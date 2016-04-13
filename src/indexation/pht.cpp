#include "indexation/pht.h"
#include "rng.h"

namespace dht {
namespace indexation {

const ValueType IndexEntry::TYPE = ValueType::USER_DATA;
constexpr std::chrono::minutes Pht::Cache::NODE_EXPIRE_TIME;

void Pht::lookupStep(Prefix p, std::shared_ptr<int> lo, std::shared_ptr<int> hi,
        std::shared_ptr<std::vector<std::shared_ptr<Value>>> vals,
        LookupCallback cb, Dht::DoneCallbackSimple done_cb,
        std::shared_ptr<unsigned> max_common_prefix_len, int start, bool all_values)
{
    struct node_lookup_result {
        bool done {false};
        bool is_pht {false};
    };

    /* start could be under 0 but after the compare it to 0 it always will be unsigned, so we can cast it*/
    auto mid = (start >= 0) ? (unsigned) start : (*lo + *hi)/2;
    auto first_res = std::make_shared<node_lookup_result>();
    auto second_res = std::make_shared<node_lookup_result>();
    auto on_done = [=](bool ok) {
        bool is_leaf = first_res->is_pht and not second_res->is_pht;
        if (not ok) {
            if (done_cb)
                done_cb(false);
        }
        else if (is_leaf or *lo > *hi) {
            // leaf node
            auto to_insert = p.getPrefix(mid);
            cache_.insert(to_insert);

            if (cb) {
                if (vals->size() == 0 and max_common_prefix_len and mid > 0) {
                    auto p_ = (p.getPrefix(mid)).getSibling().getFullSize();
                    *lo = mid;
                    *hi = p_.size_;
                    lookupStep(p_, lo, hi, vals, cb, done_cb, max_common_prefix_len, -1, all_values);
                }

                cb(*vals, to_insert);
            }

            if (done_cb)
                done_cb(true);
        } else if (first_res->is_pht) {
            // internal node
            *lo = mid+1;
            lookupStep(p, lo, hi, vals, cb, done_cb, max_common_prefix_len, -1, all_values);
        } else {
            // first get failed before second.
            if (done_cb)
                done_cb(false);
        }
    };
    if (*lo <= *hi) {
        auto pht_filter = [&](const dht::Value& v) {
            return v.user_type.compare(0, name_.size(), name_) == 0;
        };

        auto on_get = [=](const std::shared_ptr<dht::Value>& value, std::shared_ptr<node_lookup_result> res) {
            if (value->user_type == canary_)
                res->is_pht = true;
            else {
                IndexEntry entry;
                entry.unpackValue(*value);

                auto add_value = [&](bool better = true) {
                    vals->emplace_back(std::make_shared<Value>(entry.value));
                    if (better and max_common_prefix_len)
                        *max_common_prefix_len = Prefix::commonBits(p, vals->front()->first);
                };
                if (max_common_prefix_len) {
                    if (vals->empty()) {
                        add_value();
                    } else {
                        auto common_bits = Prefix::commonBits(vals->front()->first, p.getPrefix(mid));
                        if (common_bits == *max_common_prefix_len)
                            add_value(false);
                        else if (common_bits > *max_common_prefix_len) {
                            vals->clear();
                            add_value();
                        }
                    }
                }
                else if (all_values or entry.prefix == p.content_)
                    add_value(false);
            }
            return true;
        };

        dht_->get(p.getPrefix(mid).hash(),
                std::bind(on_get, std::placeholders::_1, first_res),
                [=](bool ok) {
                    if (not ok) {
                        // DHT failed
                        first_res->done = true;
                        if (done_cb and second_res->done)
                            on_done(false);
                    }
                    else {
                        if (not first_res->is_pht) {
                            // Not a PHT node.
                            *hi = mid-1;
                            lookupStep(p, lo, hi, vals, cb, done_cb, max_common_prefix_len, -1, all_values);
                        } else {
                            first_res->done = true;
                            if (second_res->done)
                                on_done(true);
                        }
                    }
                }, pht_filter);

        if (mid < p.size_)
           dht_->get(p.getPrefix(mid+1).hash(),
                    std::bind(on_get, std::placeholders::_1, second_res),
                    [=](bool ok) {
                        if (not ok) {
                            // DHT failed
                            second_res->done = true;
                            if (done_cb and first_res->done)
                                on_done(false);
                        }
                        else {
                            second_res->done = true;
                            if (first_res->done)
                                on_done(true);
                        }
                    }, pht_filter);

    } else {
        on_done(true);
    }
}

void Pht::lookup(Key k, Pht::LookupCallback cb, Dht::DoneCallbackSimple done_cb, bool exact_match) {
    auto values = std::make_shared<std::vector<std::shared_ptr<Value>>>();
    auto prefix = linearize(k);
    auto lo = std::make_shared<int>(0);
    auto hi = std::make_shared<int>(prefix.size_);
    std::shared_ptr<unsigned> max_common_prefix_len = not exact_match ? std::make_shared<unsigned>(0) : nullptr;

    lookupStep(prefix, lo, hi, values, cb, done_cb, max_common_prefix_len, cache_.lookup(prefix));
}

void Pht::updateCanary(Prefix p) {
    // TODO: change this... copy value
    dht::Value canary_value;
    canary_value.user_type = canary_;
    dht_->put(p.hash(), std::move(canary_value),
        [=](bool){
            static std::bernoulli_distribution d(0.5);
            crypto::random_device rd;
            if (p.size_ && d(rd))
                updateCanary(p.getPrefix(-1));
        }
    );

    if (p.size_) {
        dht::Value canary_second_value;
        canary_second_value.user_type = canary_;
        dht_->put(p.getSibling().hash(), std::move(canary_second_value));
    }
}

void Pht::insert(Key k, Value v, Dht::DoneCallbackSimple done_cb) {
    Prefix kp = linearize(k);

    auto lo = std::make_shared<int>(0);
    auto hi = std::make_shared<int>(kp.size_);
    auto vals = std::make_shared<std::vector<std::shared_ptr<Value>>>();
    auto final_prefix = std::make_shared<Prefix>();

    lookupStep(kp, lo, hi, vals,
        [=](std::vector<std::shared_ptr<Value>>&, Prefix p) {
            *final_prefix = Prefix(p);
        },
        [=](bool ok){
            if (not ok) {
                if (done_cb)
                    done_cb(false);
            } else {
                if (vals->size() >= MAX_NODE_ENTRY_COUNT)
                    *final_prefix = kp.getPrefix(final_prefix->size_+1);

                IndexEntry entry;
                entry.value = v;
                entry.prefix = kp.content_;
                entry.name = name_;

                updateCanary(*final_prefix);
                dht_->put(final_prefix->hash(), std::move(entry), done_cb);
            }
        }, nullptr, cache_.lookup(kp), true
    );
}

} /* indexation  */
} /* dht */
