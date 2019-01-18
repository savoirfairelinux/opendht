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
#include "op_cache.h"

namespace dht {

constexpr const std::chrono::seconds OpCache::EXPIRATION;

bool
OpValueCache::onValuesAdded(const std::vector<Sp<Value>>& vals) {
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
bool
OpValueCache::onValuesExpired(const std::vector<Sp<Value>>& vals) {
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
std::vector<Sp<Value>>
OpValueCache::get(const Value::Filter& filter) const {
    std::vector<Sp<Value>> ret;
    if (not filter)
        ret.reserve(values.size());
    for (const auto& v : values)
        if (not filter or filter(*v.second.data))
            ret.emplace_back(v.second.data);
    return ret;
}

Sp<Value>
OpValueCache::get(Value::Id id) const {
    auto v = values.find(id);
    if (v == values.end())
        return {};
    return v->second.data;
}

std::vector<Sp<Value>>
OpValueCache::getValues() const {
    std::vector<Sp<Value>> ret;
    ret.reserve(values.size());
    for (const auto& v : values)
        ret.emplace_back(v.second.data);
    return ret;
}

void
OpCache::onValuesAdded(const std::vector<Sp<Value>>& vals) {
    if (not listeners.empty()) {
        std::vector<LocalListener> list;
        list.reserve(listeners.size());
        for (const auto& l : listeners)
            list.emplace_back(l.second);
        for (auto& l : list)
            l.get_cb(l.filter.filter(vals), false);
    }
}

void
OpCache::onValuesExpired(const std::vector<Sp<Value>>& vals) {
    if (not listeners.empty()) {
        std::vector<LocalListener> list;
        list.reserve(listeners.size());
        for (const auto& l : listeners)
            list.emplace_back(l.second);
        for (auto& l : list)
            l.get_cb(l.filter.filter(vals), true);
    }
}

time_point
OpCache::getExpiration() const {
    if (not listeners.empty())
        return time_point::max();
    return lastRemoved + EXPIRATION;
}

SearchCache::OpMap::iterator
SearchCache::getOp(const Sp<Query>& q)
{
    // find exact match
    auto op = ops.find(q);
    if (op != ops.end())
        return op;
    // find satisfying query
    for (auto it = ops.begin(); it != ops.end(); it++) {
        if (q->isSatisfiedBy(*it->first)) {
            return it;
        }
    }
    return ops.end();
}

SearchCache::OpMap::const_iterator
SearchCache::getOp(const Sp<Query>& q) const
{
    // find exact match
    auto op = ops.find(q);
    if (op != ops.cend())
        return op;
    // find satisfying query
    for (auto it = ops.begin(); it != ops.end(); it++) {
        if (q->isSatisfiedBy(*it->first)) {
            return it;
        }
    }
    return ops.cend();
}

size_t
SearchCache::listen(ValueCallback get_cb, Sp<Query> q, Value::Filter filter, OnListen onListen)
{
    // find exact match
    auto op = getOp(q);
    if (op == ops.end()) {
        // New query
        op = ops.emplace(q, std::unique_ptr<OpCache>(new OpCache)).first;
        auto& cache = *op->second;
        cache.searchToken = onListen(q, [&](const std::vector<Sp<Value>>& values, bool expired){
            return cache.onValue(values, expired);
        }, [&](ListenSyncStatus status) {
            cache.onNodeChanged(status);
        });
    }
    auto token = nextToken_++;
    if (nextToken_ == 0)
        nextToken_++;
    return op->second->addListener(token, get_cb, q, filter) ? token : 0;
}

bool
SearchCache::cancelListen(size_t gtoken, const time_point& now) {
    for (auto& op : ops) {
        if (op.second->removeListener(gtoken, now)) {
            nextExpiration_ = std::min(nextExpiration_, op.second->getExpiration());
            return true;
        }
    }
    return false;
}

void
SearchCache::cancelAll(std::function<void(size_t)> onCancel) {
    for (auto& op : ops) {
        auto cache = std::move(op.second);
        cache->removeAll();
        onCancel(cache->searchToken);
    }
    ops.clear();
}

time_point
SearchCache::expire(const time_point& now, std::function<void(size_t)> onCancel) {
    nextExpiration_ = time_point::max();
    auto ret = nextExpiration_;
    for (auto it = ops.begin(); it != ops.end();) {
        auto expiration = it->second->getExpiration();
        if (expiration < now) {
            auto cache = std::move(it->second);
            it = ops.erase(it);
            onCancel(cache->searchToken);
        } else {
            nextExpiration_ = std::min(nextExpiration_, expiration);
            ret = nextExpiration_;
            ++it;
        }
    }
    return ret;
}

bool
SearchCache::get(const Value::Filter& f, const Sp<Query>& q, const GetCallback& gcb, const DoneCallback& dcb) const
{
    auto op = getOp(q);
    if (op != ops.end()) {
        auto vals = op->second->get(f);
        if ((not vals.empty() and not gcb(vals)) or op->second->isSynced()) {
            dcb(true, {});
            return true;
        }
    }
    return false;
}

std::vector<Sp<Value>>
SearchCache::get(const Value::Filter& filter) const {
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

Sp<Value>
SearchCache::get(Value::Id id) const {
    for (const auto& op : ops)
        if (auto v = op.second->get(id))
            return v;
    return {};
}

}
