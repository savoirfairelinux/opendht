/*
 *  Copyright (C) 2018 Savoir-faire Linux Inc.
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

#include "value.h"

namespace dht {

using ValueStateCallback = std::function<void(const std::vector<Sp<Value>>&, bool)>;
enum class ListenSyncStatus { ADDED, SYNCED, UNSYNCED, REMOVED };
using SyncCallback = std::function<void(ListenSyncStatus)>;
using CallbackQueue = std::list<std::function<void()>>;

class ValueCache {
public:
    ValueCache(ValueStateCallback&& cb, SyncCallback&& scb = {})
        : callback(std::forward<ValueStateCallback>(cb)), syncCallback(std::move(scb))
    {
        if (syncCallback)
            syncCallback(ListenSyncStatus::ADDED);
    }
    ValueCache(ValueCache&& o) : values(std::move(o.values)), callback(std::move(o.callback)), syncCallback(std::move(o.syncCallback)) {
        o.callback = {};
        o.syncCallback = {};
    }

    ~ValueCache() {
        auto q = clear();
        for (auto& cb: q)
            cb();
        if (syncCallback) {
            if (status == ListenSyncStatus::SYNCED)
                syncCallback(ListenSyncStatus::UNSYNCED);
            syncCallback(ListenSyncStatus::REMOVED);
        }
    }

    CallbackQueue clear() {
        std::vector<Sp<Value>> expired_values;
        expired_values.reserve(values.size());
        for (const auto& v : values)
            expired_values.emplace_back(std::move(v.second.data));
        values.clear();
        CallbackQueue ret;
        if (not expired_values.empty() and callback) {
            auto cb = callback;
            ret.emplace_back([expired_values, cb]{
                cb(expired_values, true);
            });
        }
        return ret;
    }

    time_point expireValues(const time_point& now) {
        time_point ret = time_point::max();
        auto cbs = expireValues(now, ret);
        while (not cbs.empty()) {
            cbs.front()();
            cbs.pop_front();
        }
        return ret;
    }

    CallbackQueue expireValues(const time_point& now, time_point& next) {
        std::vector<Sp<Value>> expired_values;
        for (auto it = values.begin(); it != values.end();) {
            if (it->second.expiration <= now) {
                expired_values.emplace_back(std::move(it->second.data));
                it = values.erase(it);
            } else {
                next = std::min(next, it->second.expiration);
                ++it;
            }
        }
        while (values.size() > MAX_VALUES) {
            // too many values, remove oldest values
            time_point oldest_creation = time_point::max();
            auto oldest_value = values.end();
            for (auto it = values.begin(); it != values.end(); ++it)
                if (it->second.created < oldest_creation) {
                    oldest_value = it;
                    oldest_creation = it->second.created;
                }
            if (oldest_value != values.end()) {
                expired_values.emplace_back(std::move(oldest_value->second.data));
                values.erase(oldest_value);
            }
        }
        CallbackQueue ret;
        if (not expired_values.empty() and callback) {
            auto cb = callback;
            ret.emplace_back([cb, expired_values]{
                if (cb) cb(expired_values, true);
            });
        }
        return ret;
    }

    time_point onValues
        (const std::vector<Sp<Value>>& values,
        const std::vector<Value::Id>& refreshed_values,
        const std::vector<Value::Id>& expired_values,
        const TypeStore& types, const time_point& now)
    {
        CallbackQueue cbs;
        time_point ret = time_point::max();
        if (not values.empty())
            cbs.splice(cbs.end(), addValues(values, types, now));
        for (const auto& vid : refreshed_values)
            refreshValue(vid, types, now);
        for (const auto& vid : expired_values)
            cbs.splice(cbs.end(), expireValue(vid));
        cbs.splice(cbs.end(), expireValues(now, ret));
        while (not cbs.empty()) {
            cbs.front()();
            cbs.pop_front();
        }
        return ret;
    }

    void onSynced(bool synced) {
        auto newStatus = synced ? ListenSyncStatus::SYNCED : ListenSyncStatus::UNSYNCED;
        if (status != newStatus) {
            status = newStatus;
            if (syncCallback)
                syncCallback(newStatus);
        }
    }

private:
    // prevent copy
    ValueCache(const ValueCache&) = delete;
    ValueCache& operator=(const ValueCache&) = delete;
    ValueCache& operator=(ValueCache&&) = delete;

    /* The maximum number of values we store in the cache. */
    static constexpr unsigned MAX_VALUES {4096};

    struct CacheValueStorage {
        Sp<Value> data {};
        time_point created {};
        time_point expiration {};

        CacheValueStorage() {}
        CacheValueStorage(const Sp<Value>& v, time_point t, time_point e)
         : data(v), created(t), expiration(e) {}
    };

    std::map<Value::Id, CacheValueStorage> values;
    ValueStateCallback callback;
    SyncCallback syncCallback;
    ListenSyncStatus status {ListenSyncStatus::UNSYNCED};

    CallbackQueue addValues(const std::vector<Sp<Value>>& new_values, const TypeStore& types, const time_point& now) {
        std::vector<Sp<Value>> nvals;
        for (const auto& value : new_values) {
            auto v = values.find(value->id);
            if (v == values.end()) {
                // new value
                nvals.emplace_back(value);
                values.emplace(value->id, CacheValueStorage(value, now, now + types.getType(value->type).expiration));
            } else {
                // refreshed value
                v->second.created = now;
                v->second.expiration = now + types.getType(v->second.data->type).expiration;
            }
        }
        auto cb = callback;
        CallbackQueue ret;
        if (not nvals.empty())
            ret.emplace_back([cb, nvals]{
                if (cb) cb(nvals, false);
            });
        return ret;
    }
    CallbackQueue expireValue(Value::Id vid) {
        auto v = values.find(vid);
        if (v == values.end())
            return {};
        const std::vector<Sp<Value>> val {std::move(v->second.data)};
        values.erase(v);
        auto cb = callback;
        CallbackQueue ret;
        ret.emplace_back([cb, val]{
            if (cb) cb(val, true);
        });
        return ret;
    }
    void refreshValue(Value::Id vid, const TypeStore& types, const time_point& now) {
        auto v = values.find(vid);
        if (v == values.end())
            return;
        v->second.created = now;
        v->second.expiration = now + types.getType(v->second.data->type).expiration;
    }
};

}
