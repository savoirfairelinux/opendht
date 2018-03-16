/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#pragma once

#include "infohash.h"
#include "value.h"
#include "listener.h"

#include <map>
#include <utility>

namespace dht {

/**
 * Tracks storage usage per IP or IP range
 */
class StorageBucket {
public:
    void insert(const InfoHash& id, const Value& value, time_point expiration) {
        totalSize_ += value.size();
        storedValues_.emplace(expiration, std::pair<InfoHash, Value::Id>(id, value.id));
    }
    void erase(const InfoHash& id, const Value& value, time_point expiration) {
        auto size = value.size();
        totalSize_ -= size;
        auto range = storedValues_.equal_range(expiration);
        for (auto rit = range.first; rit != range.second;) {
            if (rit->second.first == id && rit->second.second == value.id) {
                storedValues_.erase(rit);
                break;
            } else
                ++rit;
        }
    }
    size_t size() const { return totalSize_; }
    std::pair<InfoHash, Value::Id> getOldest() const { return storedValues_.begin()->second; }
private:
    std::multimap<time_point, std::pair<InfoHash, Value::Id>> storedValues_;
    size_t totalSize_ {0};
};

struct ValueStorage {
    Sp<Value> data {};
    time_point created {};
    time_point expiration {};
    StorageBucket* store_bucket {nullptr};

    ValueStorage() {}
    ValueStorage(const Sp<Value>& v, time_point t, time_point e)
     : data(v), created(t), expiration(e) {}
};


struct Storage {
    time_point maintenance_time {};
    std::map<Sp<Node>, std::map<size_t, Listener>> listeners;
    std::map<size_t, LocalListener> local_listeners {};
    size_t listener_token {1};

    /* The maximum number of values we store for a given hash. */
    static constexpr unsigned MAX_VALUES {1024};

    /**
     * Changes caused by an operation on the storage.
     */
    struct StoreDiff {
        /** Difference in stored size caused by the op */
        ssize_t size_diff;
        /** Difference in number of values */
        ssize_t values_diff;
        /** Difference in number of listeners */
        ssize_t listeners_diff;
    };

    Storage() {}
    Storage(time_point t) : maintenance_time(t) {}

#if defined(__GNUC__) && __GNUC__ == 4 && __GNUC_MINOR__ <= 9 || defined(_WIN32)
    // GCC-bug: remove me when support of GCC < 4.9.2 is abandoned
    Storage(Storage&& o) noexcept
        : maintenance_time(std::move(o.maintenance_time))
        , listeners(std::move(o.listeners))
        , local_listeners(std::move(o.local_listeners))
        , listener_token(std::move(o.listener_token))
        , values(std::move(o.values))
        , total_size(std::move(o.total_size)) {}
#else
    Storage(Storage&& o) noexcept = default;
#endif

    Storage& operator=(Storage&& o) = default;

    bool empty() const {
        return values.empty();
    }

    StoreDiff clear();

    size_t valueCount() const {
        return values.size();
    }

    size_t totalSize() const {
        return total_size;
    }

    const std::vector<ValueStorage>& getValues() const { return values; }

    Sp<Value> getById(Value::Id vid) const {
        for (auto& v : values)
            if (v.data->id == vid) return v.data;
        return {};
    }

    std::vector<Sp<Value>> get(Value::Filter f = {}) const {
        std::vector<Sp<Value>> newvals {};
        if (not f) newvals.reserve(values.size());
        for (auto& v : values) {
            if (not f || f(*v.data))
                newvals.push_back(v.data);
        }
        return newvals;
    }

    /**
     * Stores a new value in this storage, or replace a previous value
     *
     * @return <storage, change_size, change_value_num>
     *      storage: set if a change happened
     *      change_size: size difference
     *      change_value_num: change of value number (0 or 1)
     */
    std::pair<ValueStorage*, StoreDiff>
    store(const InfoHash& id, const Sp<Value>&, time_point created, time_point expiration, StorageBucket*);

    /**
     * Refreshes the time point of the value's lifetime begining.
     *
     * @param now  The reference to now
     * @param vid  The value id
     * @return true if a value storage was updated, false otherwise
     */
    bool refresh(const time_point& now, const Value::Id& vid) {
        for (auto& vs : values)
            if (vs.data->id == vid) {
                vs.created = now;
                return true;
            }
        return false;
    }

    StoreDiff remove(const InfoHash& id, Value::Id);

    std::pair<ssize_t, std::vector<Sp<Value>>> expire(const InfoHash& id, time_point now);

private:
    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;

    std::vector<ValueStorage> values {};
    size_t total_size {};
};


std::pair<ValueStorage*, Storage::StoreDiff>
Storage::store(const InfoHash& id, const Sp<Value>& value, time_point created, time_point expiration, StorageBucket* sb)
{
    auto it = std::find_if (values.begin(), values.end(), [&](const ValueStorage& vr) {
        return vr.data == value || vr.data->id == value->id;
    });
    ssize_t size_new = value->size();
    if (it != values.end()) {
        /* Already there, only need to refresh */
        it->created = created;
        size_t size_old = it->data->size();
        ssize_t size_diff = size_new - (ssize_t)size_old;
        if (it->data != value) {
            //DHT_LOG.DEBUG("Updating %s -> %s", id.toString().c_str(), value->toString().c_str());
            // clear quota for previous value
            if (it->store_bucket)
                it->store_bucket->erase(id, *value, it->expiration);
            it->expiration = expiration;
            // update quota for new value
            it->store_bucket = sb;
            if (sb)
                sb->insert(id, *value, expiration);
            it->data = value;
            total_size += size_diff;
            return std::make_pair(&(*it), StoreDiff{size_diff, 0, 0});
        }
        return std::make_pair(nullptr, StoreDiff{});
    } else {
        //DHT_LOG.DEBUG("Storing %s -> %s", id.toString().c_str(), value->toString().c_str());
        if (values.size() < MAX_VALUES) {
            total_size += size_new;
            values.emplace_back(value, created, expiration);
            values.back().store_bucket = sb;
            if (sb)
                sb->insert(id, *value, expiration);
            return std::make_pair(&values.back(), StoreDiff{size_new, 1, 0});
        }
        return std::make_pair(nullptr, StoreDiff{});
    }
}

Storage::StoreDiff
Storage::remove(const InfoHash& id, Value::Id vid)
{
    auto it = std::find_if (values.begin(), values.end(), [&](const ValueStorage& vr) {
        return vr.data->id == vid;
    });
    if (it == values.end())
        return {};
    ssize_t size = it->data->size();
    if (it->store_bucket)
        it->store_bucket->erase(id, *it->data, it->expiration);
    total_size -= size;
    values.erase(it);
    return {-size, -1, 0};
}

Storage::StoreDiff
Storage::clear()
{
    ssize_t num_values = values.size();
    ssize_t tot_size = total_size;
    values.clear();
    total_size = 0;
    return {-tot_size, -num_values, 0};
}

std::pair<ssize_t, std::vector<Sp<Value>>>
Storage::expire(const InfoHash& id, time_point now)
{
    // expire listeners
    ssize_t del_listen {0};
    for (auto nl_it = listeners.begin(); nl_it != listeners.end();) {
        auto& node_listeners = nl_it->second;
        for (auto l = node_listeners.cbegin(); l != node_listeners.cend();) {
            bool expired = l->second.time + Node::NODE_EXPIRE_TIME < now;
            if (expired)
                l = node_listeners.erase(l);
            else
                ++l;
        }
        if (node_listeners.empty()) {
            nl_it = listeners.erase(nl_it);
            del_listen--;
        }
        else
            ++nl_it;
    }

    // expire values
    auto r = std::partition(values.begin(), values.end(), [&](const ValueStorage& v) {
        return v.expiration > now;
    });
    std::vector<Sp<Value>> ret;
    ret.reserve(std::distance(r, values.end()));
    ssize_t size_diff {};
    std::for_each(r, values.end(), [&](const ValueStorage& v) {
        size_diff -= v.data->size();
        if (v.store_bucket)
            v.store_bucket->erase(id, *v.data, v.expiration);
        ret.emplace_back(std::move(v.data));
    });
    total_size += size_diff;
    values.erase(r, values.end());
    return {size_diff, std::move(ret)};
}

}
