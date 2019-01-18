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
    OpValueCache(OpValueCache&& o) : values(std::move(o.values)), callback(std::move(o.callback)) {
        o.callback = {};
    }

    static ValueCallback cacheCallback(ValueCallback&& cb, std::function<void()>&& onCancel) {
        auto cache = std::make_shared<OpValueCache>(std::forward<ValueCallback>(cb));
        return [cache, onCancel](const std::vector<Sp<Value>>& vals, bool expired){
            auto ret = cache->onValue(vals, expired);
            if (not ret)
                onCancel();
            return ret;
        };
    }

    bool onValue(const std::vector<Sp<Value>>& vals, bool expired) {
        if (expired)
            return onValuesExpired(vals);
        else
            return onValuesAdded(vals);
    }

    bool onValuesAdded(const std::vector<Sp<Value>>& vals);
    bool onValuesExpired(const std::vector<Sp<Value>>& vals);

    void onNodeChanged(ListenSyncStatus status) {
        switch (status) {
            case ListenSyncStatus::ADDED: nodes++; break;
            case ListenSyncStatus::REMOVED: nodes--; break;
            case ListenSyncStatus::SYNCED : syncedNodes++; break;
            case ListenSyncStatus::UNSYNCED: syncedNodes--; break;
        }
    }

    bool isSynced() const { return nodes > 0 and syncedNodes == nodes; }

    std::vector<Sp<Value>> get(const Value::Filter& filter) const;
    Sp<Value> get(Value::Id id) const;
    std::vector<Sp<Value>> getValues() const;

private:
    OpValueCache(const OpValueCache&) = delete;
    OpValueCache& operator=(const OpValueCache&) = delete;

    size_t nodes {0};
    size_t syncedNodes {0};
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
    void onNodeChanged(ListenSyncStatus status) {
        cache.onNodeChanged(status);
    }

    void onValuesAdded(const std::vector<Sp<Value>>& vals);
    void onValuesExpired(const std::vector<Sp<Value>>& vals);

    bool addListener(size_t token, ValueCallback cb, Sp<Query> q, Value::Filter filter) {
        listeners.emplace(token, LocalListener{q, filter, cb});
        auto cached = cache.get(filter);
        if (not cached.empty()) {
            auto ret = cb(cached, false);
            if (not ret)
                listeners.erase(token);
            return ret;
        }
        return true;
    }

    bool removeListener(size_t token, const time_point& now) {
        lastRemoved = now;
        return listeners.erase(token) > 0;
    }

    void removeAll() {
        listeners.clear();
    }

    bool isDone() {
        return listeners.empty();
    }

    std::vector<Sp<Value>> get(const Value::Filter& filter) const {
        return cache.get(filter);
    }

    Sp<Value> get(Value::Id id) const {
        return cache.get(id);
    }

    bool isSynced() const {
        return cache.isSynced();
    }

    bool isExpired(const time_point& now) const {
        return listeners.empty() and (lastRemoved + EXPIRATION < now);
    }
    time_point getExpiration() const;

    size_t searchToken;
private:
    constexpr static const std::chrono::seconds EXPIRATION {60};
    OpCache(const OpCache&) = delete;
    OpCache& operator=(const OpCache&) = delete;

    OpValueCache cache;
    std::map<size_t, LocalListener> listeners;
    time_point lastRemoved {clock::now()};
};

class SearchCache {
public:
    SearchCache() {}
    SearchCache(SearchCache&&) = default;
    size_t listen(ValueCallback get_cb, Sp<Query> q, Value::Filter filter, std::function<size_t(Sp<Query>, ValueCallback, SyncCallback)> onListen);

    bool cancelListen(size_t gtoken, const time_point& now);
    void cancelAll(std::function<void(size_t)> onCancel);

    time_point expire(const time_point& now, std::function<void(size_t)> onCancel);
    time_point getExpiration() const {
        return nextExpiration_;
    }

    std::vector<Sp<Value>> get(const Value::Filter& filter) const;
    Sp<Value> get(Value::Id id) const;

private:
    SearchCache(const SearchCache&) = delete;
    SearchCache& operator=(const SearchCache&) = delete;

    std::map<Sp<Query>, std::unique_ptr<OpCache>> ops {};
    size_t nextToken_ {1};
    time_point nextExpiration_ {time_point::max()};
};

}
