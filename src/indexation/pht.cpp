/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
 *              Nicolas Reynaud <nicolas.reynaud@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "indexation/pht.h"
#include "rng.h"

namespace dht {
namespace indexation {

/**
 * Output the blob into string and readable way
 *
 * @param bl   : Blob to print
 *
 * @return string that represent the blob into a readable way
 */
static std::string blobToString(const Blob &bl) {
    std::stringstream ss;
    auto bn = bl.size() % 8;
    auto n = bl.size() / 8;

    for (size_t i = 0; i < bl.size(); i++)
        ss << std::bitset<8>(bl[i]) << " ";
    if (bn)
        for (unsigned b=0; b < bn; b++)
            ss << (char)((bl[n] & (1 << (7 - b))) ? '1':'0');

    return ss.str();
}

std::string Prefix::toString() const {
    std::stringstream ss;

    ss << "Prefix : " << std::endl << "\tContent_ : \"";
    ss << blobToString(content_);
    ss << "\"" << std::endl;

    ss << "\tFlags_   : \"";
    ss << blobToString(flags_);
    ss << "\"" << std::endl;

    return ss.str();
}

void Pht::Cache::insert(const Prefix& p) {
    size_t i = 0;
    auto now = clock::now();

    std::shared_ptr<Node> curr_node;

    while ((leaves_.size() > 0
        and leaves_.begin()->first + NODE_EXPIRE_TIME < now)
        or  leaves_.size() > MAX_ELEMENT) {

        leaves_.erase(leaves_.begin());
    }

    if (not (curr_node = root_.lock()) ) {
        /* Root does not exist, need to create one*/
        curr_node = std::make_shared<Node>();
        root_ = curr_node;
    }

    curr_node->last_reply = now;

    /* Iterate through all bit of the Blob */
    for ( i = 0; i < p.size_; i++ ) {

        /* According to the bit define which node is the next one */
        auto& next = ( p.isContentBitActive(i) ) ? curr_node->right_child : curr_node->left_child;

        /**
         * If lock, node exists
         * else create it
         */
        if (auto n = next.lock()) {
            curr_node = std::move(n);
        } else {
            /* Create the next node if doesn't exist*/
            auto tmp_curr_node = std::make_shared<Node>();
            tmp_curr_node->parent = curr_node;
            next = tmp_curr_node;
            curr_node = std::move(tmp_curr_node);
        }

        curr_node->last_reply = now;
    }

    /* Insert the leaf (curr_node) into the multimap */
    leaves_.emplace(std::move(now), std::move(curr_node) );
}

int Pht::Cache::lookup(const Prefix& p) {
    int pos = -1;
    auto now = clock::now(), last_node_time = now;

    /* Before lookup remove the useless one [i.e. too old] */
    while ( leaves_.size() > 0
        and leaves_.begin()->first + NODE_EXPIRE_TIME < now ) {

        leaves_.erase(leaves_.begin());
    }

    auto next = root_;
    std::shared_ptr<Node> curr_node;

    while ( auto n = next.lock() ) {
        ++pos;
        /* Safe since pos is equal to 0 until here */
        if ( (unsigned) pos >= p.content_.size() * 8) break;

        curr_node = n;
        last_node_time = curr_node->last_reply;
        curr_node->last_reply = now;

        /* Get the Prefix bit by bit, starting from left */
        next = ( p.isContentBitActive(pos) ) ? curr_node->right_child : curr_node->left_child;
    }

    if ( pos >= 0 ) {
        auto to_erase = leaves_.find(last_node_time);
        if ( to_erase != leaves_.end() )
            leaves_.erase( to_erase );

        leaves_.emplace( std::move(now), std::move(curr_node) );
    }

    return pos;
}

const ValueType IndexEntry::TYPE = ValueType::USER_DATA;
constexpr std::chrono::minutes Pht::Cache::NODE_EXPIRE_TIME;

void Pht::lookupStep(Prefix p, std::shared_ptr<int> lo, std::shared_ptr<int> hi,
        std::shared_ptr<std::vector<std::shared_ptr<IndexEntry>>> vals,
        LookupCallbackWrapper cb, DoneCallbackSimple done_cb,
        std::shared_ptr<unsigned> max_common_prefix_len,
        int start, bool all_values)
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
            Prefix to_insert = p.getPrefix(mid);
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
            if (value->user_type == canary_) {
                res->is_pht = true;
            }
            else {
                IndexEntry entry;
                entry.unpackValue(*value);

                auto it = std::find_if(vals->cbegin(), vals->cend(), [&](const std::shared_ptr<IndexEntry>& ie) {
                    return ie->value == entry.value;
                });

                /* If we already got the value then get the next one */
                if (it != vals->cend())
                    return true;

                if (max_common_prefix_len) { /* inexact match case */
                    auto common_bits = Prefix::commonBits(p, entry.prefix);

                    if (vals->empty()) {
                        vals->emplace_back(std::make_shared<IndexEntry>(entry));
                        *max_common_prefix_len = common_bits;
                    }
                    else {
                        if (common_bits == *max_common_prefix_len) /* this is the max so far */
                            vals->emplace_back(std::make_shared<IndexEntry>(entry));
                        else if (common_bits > *max_common_prefix_len) { /* new max found! */
                            vals->clear();
                            vals->emplace_back(std::make_shared<IndexEntry>(entry));
                            *max_common_prefix_len = common_bits;
                        }
                    }
                } else if (all_values or entry.prefix == p.content_) /* exact match case */
                    vals->emplace_back(std::make_shared<IndexEntry>(entry));
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
                            if (second_res->done or mid >= p.size_ - 1)
                                on_done(true);
                        }
                    }
                }, pht_filter);

        if (mid < p.size_ - 1)
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

void Pht::lookup(Key k, Pht::LookupCallback cb, DoneCallbackSimple done_cb, bool exact_match) {
    auto prefix = linearize(k);
    auto values = std::make_shared<std::vector<std::shared_ptr<IndexEntry>>>();

    auto lo = std::make_shared<int>(0);
    auto hi = std::make_shared<int>(prefix.size_);
    std::shared_ptr<unsigned> max_common_prefix_len = not exact_match ? std::make_shared<unsigned>(0) : nullptr;

    lookupStep(prefix, lo, hi, values,
        [=](std::vector<std::shared_ptr<IndexEntry>>& entries, const Prefix& p) {
            std::vector<std::shared_ptr<Value>> vals(entries.size());

            std::transform(entries.begin(), entries.end(), vals.begin(),
                [](const std::shared_ptr<IndexEntry>& ie) {
                    return std::make_shared<Value>(ie->value);
            });

            cb(vals, p);
        }, done_cb, max_common_prefix_len, cache_.lookup(prefix));
}

void Pht::updateCanary(Prefix p) {
    // TODO: change this... copy value
    dht::Value canary_value;
    canary_value.user_type = canary_;

    dht_->put(p.hash(), std::move(canary_value),
        [=](bool){
            static std::bernoulli_distribution d(0.5);
            crypto::random_device rd;
            if (p.size_ and d(rd))
                updateCanary(p.getPrefix(-1));
        }
    );

    if (p.size_) {
        dht::Value canary_second_value;
        canary_second_value.user_type = canary_;
        dht_->put(p.getSibling().hash(), std::move(canary_second_value));
    }
}

void Pht::insert(const Prefix& kp, IndexEntry entry, std::shared_ptr<int> lo, std::shared_ptr<int> hi, time_point time_p,
                 bool check_split, DoneCallbackSimple done_cb) {

    if (time_p + ValueType::USER_DATA.expiration < clock::now()) return;

    auto vals = std::make_shared<std::vector<std::shared_ptr<IndexEntry>>>();
    auto final_prefix = std::make_shared<Prefix>();

    lookupStep(kp, lo, hi, vals,
        [=](std::vector<std::shared_ptr<IndexEntry>>&, Prefix p) {
            *final_prefix = Prefix(p);
        },
        [=](bool ok){
            if (not ok) {
                if (done_cb)
                    done_cb(false);
            } else {

                RealInsertCallback real_insert = [=](const Prefix& p, IndexEntry entry) {
                    updateCanary(p);
                    checkPhtUpdate(p, entry, time_p);
                    cache_.insert(p);
                    dht_->put(p.hash(), std::move(entry), done_cb , time_p);
                };

                if ( not check_split or final_prefix->size_ == kp.size_ ) {
                    real_insert(*final_prefix, std::move(entry));
                } else {
                    if ( vals->size() < MAX_NODE_ENTRY_COUNT ) {
                        getRealPrefix(final_prefix, std::move(entry), real_insert);
                    }
                    else {
                        split(*final_prefix, *vals, entry, real_insert);
                    }
                }
            }
        }, nullptr, cache_.lookup(kp), true);
}

Prefix Pht::zcurve(const std::vector<Prefix>& all_prefix) const {
    Prefix p;

    if ( all_prefix.size() == 1 )
        return all_prefix[0];

    /* All prefix got the same size (thanks to padding) */
    size_t prefix_size = all_prefix[0].content_.size();

    /* Loop on all uint8_t of the input prefix */
    for ( size_t j = 0, bit = 0; j < prefix_size; j++) {

        uint8_t mask = 0x80;
        /* For each of the 8 bits of the input uint8_t */
        for ( int i = 0; i < 8; ) {

            uint8_t flags = 0;
            uint8_t content = 0;

            /* For each bit of the output uint8_t */
            for ( int k = 0 ; k < 8; k++ ) {

                auto diff = k - i;

                /*get the content 'c', and the flag 'f' of the input prefix */
                auto c = all_prefix[bit].content_[j] & mask;
                auto f = all_prefix[bit].flags_[j] & mask;

                /* Move this bit at the right position according to the diff
                   and merge it into content and flags in the same way */
                content |= ( diff >= 0 ) ? c >> diff : c << std::abs(diff);
                flags   |= ( diff >= 0 ) ? f >> diff : f << std::abs(diff);

                /* If we are on the last prefix of the vector get back to the first and
                ,move the mask in order to get the n + 1nth bit */
                if ( ++bit == all_prefix.size() ) { bit = 0; ++i; mask >>= 1; }
            }

            /* Add the next flags + content to the output prefix */
            p.content_.push_back(content);
            p.flags_.push_back(flags);
            p.size_ += 8;
        }
    }

    return p;
}

Prefix Pht::linearize(Key k) const {
    if (not validKey(k)) { throw std::invalid_argument(INVALID_KEY); }

    std::vector<Prefix> all_prefix;
    all_prefix.reserve(k.size());

    /* Get the max size of the keyspec and take it for size limit (for padding) */
    auto max = std::max_element(keySpec_.begin(), keySpec_.end(),
        [](const std::pair<std::string, size_t>& a, const std::pair<std::string, size_t>& b) {
            return a.second < b.second;
        })->second + 1;

    for ( auto const& it : k ) {
        Prefix p = Blob {it.second.begin(), it.second.end()};
        p.addPaddingContent(max);
        p.updateFlags();

        all_prefix.emplace_back(std::move(p));
    }

    return zcurve(all_prefix);
}

void Pht::getRealPrefix(const std::shared_ptr<Prefix>& p, IndexEntry entry, RealInsertCallback end_cb )
{
    if ( p->size_ == 0 ) {
        end_cb(*p, std::move(entry));
        return;
    }

    struct OpState {
        unsigned entry_count {0}; /* Total number of data on 3 nodes */
        unsigned ended {0};      /* How many ops have ended */
        Prefix parent;
        OpState(Prefix p) : parent(p) {}
    };
    auto op_state = std::make_shared<OpState>(p->getPrefix(-1));

    auto pht_filter = [&](const dht::Value& v) {
        return v.user_type.compare(0, name_.size(), name_) == 0;
    };

    /* Lambda will count total number of data node */
    auto count = [=]( const std::shared_ptr<dht::Value>& value ) {
        if (value->user_type != canary_)
            op_state->entry_count++;
        return true;
    };

    auto on_done = [=] ( bool ) {
        op_state->ended++;
        /* Only the last one do the CallBack*/
        if  (op_state->ended == 3) {
            if (op_state->entry_count < MAX_NODE_ENTRY_COUNT)
                end_cb(op_state->parent, std::move(entry));
            else
                end_cb(*p, std::move(entry));
        }
    };

    dht_->get(op_state->parent.hash(),
        count,
        on_done,
        pht_filter
    );

    dht_->get(p->hash(),
        count,
        on_done,
        pht_filter
    );

    dht_->get(p->getSibling().hash(),
        count,
        on_done,
        pht_filter
    );
}

void Pht::checkPhtUpdate(Prefix p, IndexEntry entry, time_point time_p) {

    Prefix full = entry.prefix;
    if ( p.content_.size() * 8 >= full.content_.size() * 8 ) return;

    auto next_prefix = full.getPrefix( p.size_ + 1 );

    dht_->listen(next_prefix.hash(),
        [=](const std::shared_ptr<dht::Value> &value) {
            if (value->user_type == canary_) {
                insert(full, entry, std::make_shared<int>(0), std::make_shared<int>(full.size_), time_p, false, nullptr);

                /* Cancel listen since we found where we need to update*/
                return false;
            }

            return true;
        },
        [=](const dht::Value& v) {
            /* Filter value v thats start with the same name as ours */
            return v.user_type.compare(0, name_.size(), name_) == 0;
        }
    );
}

void Pht::split(const Prefix& insert, const std::vector<std::shared_ptr<IndexEntry>>& vals, IndexEntry entry, RealInsertCallback end_cb ) {
    const auto full = Prefix(entry.prefix);

    auto loc = findSplitLocation(full, vals);
    const auto prefix_to_insert = full.getPrefix(loc);

    for(;loc != insert.size_ - 1; loc--) {
        updateCanary(full.getPrefix(loc));
    }

    end_cb(prefix_to_insert, entry);
}

} /* indexation  */

} /* dht */
