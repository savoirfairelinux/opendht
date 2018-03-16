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
using CallbackQueue = std::list<std::function<void()>>;

class ValueCache {
public:
    ValueCache(ValueStateCallback&& cb) {
        callbacks.emplace_back(std::forward<ValueStateCallback>(cb));
    }
    ValueCache(ValueCache&&) = default;

    ~ValueCache() {
        auto q = clear();
        for (auto& cb: q)
            cb();
    }

    CallbackQueue clear() {
        std::vector<Sp<Value>> expired_values;
        expired_values.reserve(values.size());
        for (const auto& v : values)
            expired_values.emplace_back(std::move(v.second.data));
        values.clear();
        CallbackQueue ret;
        if (not expired_values.empty() and not callbacks.empty()) {
            auto cbs = callbacks;
            ret.emplace_back([expired_values, cbs]{
                for (auto& cb : cbs)
                    cb(expired_values, true);
            });
        }
        return ret;
    }

    CallbackQueue expireValues(const time_point& now) {
        std::vector<Sp<Value>> expired_values;
        for (auto it = values.begin(); it != values.end();) {
            if (it->second.expiration < now) {
                expired_values.emplace_back(std::move(it->second.data));
                it = values.erase(it);
            } else
                ++it;
        }
        while (values.size() >= MAX_VALUES) {
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
        if (not expired_values.empty()) {
            auto cbs = callbacks;
            ret.emplace_back([cbs, expired_values]{
                for (auto& cb : cbs)
                    if (cb) cb(expired_values, true);
            });
        }
        return ret;
    }

    void onValues
        (const std::vector<Sp<Value>>& values,
        const std::vector<Value::Id>& refreshed_values,
        const std::vector<Value::Id>& expired_values,
        const TypeStore& types, const time_point& now)
    {
        CallbackQueue cbs;
        if (not values.empty())
            cbs.splice(cbs.end(), addValues(values, types, now));
        for (const auto& vid : refreshed_values)
            refreshValue(vid, types, now);
        for (const auto& vid : expired_values)
            cbs.splice(cbs.end(), expireValue(vid));
        cbs.splice(cbs.end(), expireValues(now));
        while (not cbs.empty()) {
            cbs.front()();
            cbs.pop_front();
        }
    }

private:
    // prevent copy
    ValueCache(const ValueCache&) = delete;
    ValueCache& operator=(const ValueCache&) = delete;

    /* The maximum number of values we store in the cache. */
    static constexpr unsigned MAX_VALUES {1024};

    struct CacheValueStorage {
        Sp<Value> data {};
        time_point created {};
        time_point expiration {};

        CacheValueStorage() {}
        CacheValueStorage(const Sp<Value>& v, time_point t, time_point e)
         : data(v), created(t), expiration(e) {}
    };

    std::map<Value::Id, CacheValueStorage> values;
    std::vector<ValueStateCallback> callbacks;

    CallbackQueue addValues(const std::vector<Sp<Value>>& new_values, const TypeStore& types, const time_point& now) {
        std::vector<Sp<Value>> nvals;
        for (const auto& value : new_values) {
            auto v = values.find(value->id);
            if (v == values.end()) {
                nvals.emplace_back(value);
                // new value
                values.emplace(value->id, CacheValueStorage(value, now, now + types.getType(value->type).expiration));
            } else {
                v->second.created = now;
                v->second.expiration = now + types.getType(v->second.data->type).expiration;
            }
        }
        auto cbs = callbacks;
        CallbackQueue ret;
        if (not nvals.empty())
            ret.emplace_back([cbs, nvals]{
                for (auto& cb : cbs)
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
        auto cbs = callbacks;
        CallbackQueue ret;
        ret.emplace_back([cbs, val]{
            for (auto& cb : cbs)
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
