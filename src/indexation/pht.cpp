#include "indexation/pht.h"
#include "rng.h"

namespace dht {
namespace indexation {

void Pht::lookupStep(Prefix p, std::shared_ptr<int> lo,
                       std::shared_ptr<int> hi,
                       std::shared_ptr<std::vector<std::shared_ptr<Value>>> vals,
                       LookupCallback cb, Dht::DoneCallbackSimple done_cb)
{
    struct node_lookup_result {
        bool done {false};
        bool is_pht {false};
    };

    auto mid = (*lo + *hi)/2;
    auto first_res = std::make_shared<node_lookup_result>();
    auto second_res = std::make_shared<node_lookup_result>();
    auto on_done = [=](){
        bool is_leaf = first_res->is_pht and not second_res->is_pht;
        if (is_leaf or *lo > *hi) {
            // leaf node
            if (cb)
                cb(*vals, p.getPrefix(mid));
            if (done_cb)
                done_cb(true);
        } else {
            // internal node
            *lo = mid+1;
            lookupStep(p, lo, hi, vals, cb, done_cb);
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
                if (entry.prefix == p.content_)
                    vals->emplace_back(std::make_shared<Value>(entry.value));
            }
            return true;
        };
        dht_->get(p.getPrefix(mid).hash(),
                std::bind(on_get, std::placeholders::_1, first_res),
                [=](bool ok) {
                    if (not ok) {
                        // DHT failed
                        if (done_cb)
                            done_cb(false);
                    }
                    else {
                        if (not first_res->is_pht) {
                            // Not a PHT node.
                            *hi = mid-1;
                            lookupStep(p, lo, hi, vals, cb, done_cb);
                        } else {
                            first_res->done = true;
                            if (second_res->done)
                                on_done();
                        }
                    }
                }, pht_filter);
        if (mid < p.size_)
           dht_->get(p.getPrefix(mid+1).hash(),
                    std::bind(on_get, std::placeholders::_1, second_res),
                    [=](bool ok) {
                        if (not ok) {
                            // DHT failed
                            if (done_cb)
                                done_cb(false);
                        }
                        else {
                            second_res->done = true;
                            if (first_res->done)
                                on_done();
                        }
                    }, pht_filter);

    } else {
        on_done();
    }
}

void Pht::lookup(Key k, Pht::LookupCallback cb, Dht::DoneCallbackSimple done_cb) {
    auto values = std::make_shared<std::vector<std::shared_ptr<Value>>>();
    auto prefix = linearize(k);
    auto lo = std::make_shared<int>(0);
    auto hi = std::make_shared<int>(prefix.size_);
    lookupStep(prefix, lo, hi, values, cb, done_cb);
}

void Pht::updateCanary(Prefix p) {
    // TODO: change this... copy value
    dht::Value canary_value;
    canary_value.user_type = canary_;
    dht_->put(p.hash(), std::move(canary_value),
        [=](bool ok){
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
        [=](std::vector<std::shared_ptr<Value>>& values, Prefix p) {
            *final_prefix = Prefix(p);
            return true;
        },
        [=](bool ok){
            if (not ok) {
                if (done_cb)
                    done_cb(false);
            } else {
                if (vals->size() > MAX_NODE_ENTRY_COUNT)
                    *final_prefix = kp.getPrefix(final_prefix->size_+1);

                IndexEntry entry;
                entry.value = v;
                entry.prefix = kp.content_;
                entry.name = name_;

                updateCanary(*final_prefix);
                dht_->put(final_prefix->hash(), std::move(entry), done_cb);
            }
        }
    );
}

} /* indexation  */
} /* dht */
