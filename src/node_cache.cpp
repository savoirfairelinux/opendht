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

#include "node_cache.h"

namespace dht {

Sp<Node>
NodeCache::getNode(const InfoHash& id, sa_family_t family) {
    return cache(family).getNode(id);
}

Sp<Node>
NodeCache::getNode(const InfoHash& id, const SockAddr& addr, time_point now, bool confirm, bool client) {
    if (id == zeroes)
        return std::make_shared<Node>(id, addr);
    return cache(addr.getFamily()).getNode(id, addr, now, confirm, client);
}

std::vector<Sp<Node>>
NodeCache::getCachedNodes(const InfoHash& id, sa_family_t sa_f, size_t count) const
{
    const auto& c = cache(sa_f);

    std::vector<Sp<Node>> nodes;
    nodes.reserve(std::min(c.size(), count));
    NodeMap::const_iterator it;
    auto dec_it = [&c](NodeMap::const_iterator& it) {
        auto ret = it;
        it = (it == c.cbegin()) ? c.cend() : std::prev(it);
        return ret;
    };

    auto it_p = c.lower_bound(id),
        it_n = it_p;
    if (it_p != c.cend())
        dec_it(it_p); /* Create 2 separate iterator if we could */

    while (nodes.size() < count and (it_n != c.cend() or it_p != c.cend())) {
        /* If one of the iterator is at the end, then take the other one
           If they are both in middle of somewhere comapre both and take
           the closest to the id. */
        if (it_p == c.cend())       it = it_n++;
        else if (it_n == c.cend())  it = dec_it(it_p);
        else                        it = id.xorCmp(it_p->first, it_n->first) < 0 ? dec_it(it_p) : it_n++;

        if (auto n = it->second.lock())
            if ( not n->isExpired() and not n->isClient() )
                nodes.emplace_back(std::move(n));
    }

    return nodes;
}

void
NodeCache::clearBadNodes(sa_family_t family)
{
    if (family == 0) {
        clearBadNodes(AF_INET);
        clearBadNodes(AF_INET6);
    } else {
        cache(family).clearBadNodes();
    }
}

Sp<Node>
NodeCache::NodeMap::getNode(const InfoHash& id)
{
    auto wn = find(id);
    if (wn == end())
        return {};
    if (auto n = wn->second.lock())
        return n;
    erase(wn);
    return {};
}

Sp<Node>
NodeCache::NodeMap::getNode(const InfoHash& id, const SockAddr& addr, time_point now, bool confirm, bool client)
{
    auto it = emplace(id, std::weak_ptr<Node>{});
    auto node = it.first->second.lock();
    if (not node) {
        node = std::make_shared<Node>(id, addr, client);
        it.first->second = node;
    } else if (confirm or node->isOld(now)) {
        node->update(addr);
    }
    return node;
}

void
NodeCache::NodeMap::clearBadNodes() {
    for (auto it = cbegin(); it != cend();) {
        if (auto n = it->second.lock()) {
            n->reset();
            ++it;
        } else {
            erase(it++);
        }
    }
}

}
