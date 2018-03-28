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
#include "value_cache.h"
#include "listener.h"

namespace dht {

struct OpCacheValueStorage
{
    Sp<Value> data {};
    unsigned refCount {1};
    OpCacheValueStorage(Sp<Value> val = {}) : data(val) {}
};

class OpValueCache {
public:
    OpValueCache(ValueCallback&& cb) : callback(std::forward<ValueCallback>(cb)) {}

    static ValueCallback cacheCallback(ValueCallback&& cb) {
        auto cache = std::make_shared<OpValueCache>(std::forward<ValueCallback>(cb));
        return [cache](const std::vector<Sp<Value>>& vals, bool expired){
            return cache->onValue(vals, expired);
        };
    }

    bool onValue(const std::vector<Sp<Value>>& vals, bool expired) {
        if (expired)
            return onValuesExpired(vals);
        else
            return onValuesAdded(vals);
    }

    bool onValuesAdded(const std::vector<Sp<Value>>& vals) {
        std::vector<Sp<Value>> newValues;
        for (const auto& v : vals) {
            auto viop = values.emplace(v->id, OpCacheValueStorage{v});
            if (viop.second) {
                newValues.emplace_back(v);
            } else {
                viop.first->second.refCount++;
            }
        }
        return newValues.empty() ? true : callback(newValues, false);
    }
    bool onValuesExpired(const std::vector<Sp<Value>>& vals) {
        std::vector<Sp<Value>> expiredValues;
        for (const auto& v : vals) {
            auto vit = values.find(v->id);
            if (vit != values.end()) {
                vit->second.refCount--;
                if (not vit->second.refCount) {
                    expiredValues.emplace_back(std::move(vit->second.data));
                    values.erase(vit);
                }
            }
        }
        return expiredValues.empty() ? true : callback(expiredValues, true);
    }
    std::vector<Sp<Value>> get(Value::Filter& filter) const {
        std::vector<Sp<Value>> ret;
        if (not filter)
            ret.reserve(values.size());
        for (const auto& v : values)
            if (not filter or filter(*v.second.data))
                ret.emplace_back(v.second.data);
        return ret;
    }

    Sp<Value> get(Value::Id id) const {
        auto v = values.find(id);
        if (v == values.end())
            return {};
        return v->second.data;
    }

    std::vector<Sp<Value>> getValues() const {
        std::vector<Sp<Value>> ret;
        ret.reserve(values.size());
        for (const auto& v : values)
            ret.emplace_back(v.second.data);
        return ret;
    }

private:
    std::map<Value::Id, OpCacheValueStorage> values {};
    ValueCallback callback;
};

class OpCache {
public:
    OpCache() : cache([this](const std::vector<Sp<Value>>& vals, bool expired){
        if (expired)
            onValuesExpired(vals);
        else
            onValuesAdded(vals);
        return true;
    }) {}

    bool onValue(const std::vector<Sp<Value>>& vals, bool expired) {
        cache.onValue(vals, expired);
        return not listeners.empty();
    }

    void onValuesAdded(const std::vector<Sp<Value>>& vals) {
        if (not listeners.empty()) {
            std::vector<LocalListener> list;
            list.reserve(listeners.size());
            for (const auto& l : listeners)
                list.emplace_back(l.second);
            for (auto& l : list)
                l.get_cb(l.filter.filter(vals), false);
        }
    }
    void onValuesExpired(const std::vector<Sp<Value>>& vals) {
        if (not listeners.empty()) {
            std::vector<LocalListener> list;
            list.reserve(listeners.size());
            for (const auto& l : listeners)
                list.emplace_back(l.second);
            for (auto& l : list)
                l.get_cb(l.filter.filter(vals), true);
        }
    }

    void addListener(size_t token, ValueCallback cb, Sp<Query> q, Value::Filter filter) {
        listeners.emplace(token, LocalListener{q, filter, cb});
        cb(cache.get(filter), false);
    }

    bool removeListener(size_t token) {
        return listeners.erase(token) > 0;
    }

    bool isDone() {
        return listeners.empty();
    }

    std::vector<Sp<Value>> get(Value::Filter& filter) const {
        return cache.get(filter);
    }

    Sp<Value> get(Value::Id id) const {
        return cache.get(id);
    }

    size_t searchToken;
private:
    OpValueCache cache;
    std::map<size_t, LocalListener> listeners;
};

class SearchCache {
public:
    size_t listen(ValueCallback get_cb, Sp<Query> q, Value::Filter filter, std::function<size_t(Sp<Query>, ValueCallback)> onListen) {
        // find exact match
        auto op = ops.find(q);
        if (op == ops.end()) {
            // find satisfying query
            for (auto it = ops.begin(); it != ops.end(); it++) {
                if (q->isSatisfiedBy(*it->first)) {
                    op = it;
                    break;
                }
            }
        }
        if (op == ops.end()) {
            // New query
            op = ops.emplace(q, std::unique_ptr<OpCache>(new OpCache)).first;
            auto& cache = *op->second;
            cache.searchToken = onListen(q, [&](const std::vector<Sp<Value>>& values, bool expired){
                return cache.onValue(values, expired);
            });
        }
        auto token = nextToken_++;
        if (nextToken_ == 0)
            nextToken_++;
        op->second->addListener(token, get_cb, q, filter);
        return token;
    }

    bool cancelListen(size_t gtoken, std::function<void(size_t)> onCancel) {
        for (auto it = ops.begin(); it != ops.end(); it++) {
            if (it->second->removeListener(gtoken)) {
                if (it->second->isDone()) {
                    auto cache = std::move(it->second);
                    ops.erase(it);
                    onCancel(cache->searchToken);
                }
                return true;
            }
        }
        return false;
    }

    std::vector<Sp<Value>> get(Value::Filter& filter) const {
        if (ops.size() == 1)
            return ops.begin()->second->get(filter);
        std::map<Value::Id, Sp<Value>> c;
        for (const auto& op : ops) {
            for (const auto& v : op.second->get(filter))
                c.emplace(v->id, v);
        }
        std::vector<Sp<Value>> ret;
        ret.reserve(c.size());
        for (auto& v : c)
            ret.emplace_back(std::move(v.second));
        return ret;
    }

    Sp<Value> get(Value::Id id) const {
        for (const auto& op : ops)
            if (auto v = op.second->get(id))
                return v;
        return {};
    }

private:
    std::map<Sp<Query>, std::unique_ptr<OpCache>> ops {};
    size_t nextToken_ {1};
};

}
