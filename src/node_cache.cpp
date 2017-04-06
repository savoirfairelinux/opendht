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

std::shared_ptr<Node>
NodeCache::getNode(const InfoHash& id, sa_family_t family) {
    return (family == AF_INET ? cache_4 : cache_6).getNode(id);
}

std::shared_ptr<Node>
NodeCache::getNode(const InfoHash& id, const SockAddr& addr, const Sp<TcpSocket>& sock, time_point now, bool confirm) {
    if (id == zeroes)
        return std::make_shared<Node>(id, addr, sock);
    return (addr.getFamily() == AF_INET ? cache_4 : cache_6).getNode(id, addr, sock, now, confirm);
}

std::vector<std::shared_ptr<Node>>
NodeCache::getCachedNodes(const InfoHash& id, sa_family_t sa_f, size_t count) {
    const auto& c = (sa_f == AF_INET ? cache_4 : cache_6);

    std::vector<std::shared_ptr<Node>> nodes;
    nodes.reserve(std::min(c.size(), count));
    NodeMap::const_iterator it;

    auto it_p = c.lower_bound(id),
         it_n = it_p;
    if (it_p != c.begin()) /* Create 2 separate iterator if we could */
        --it_p;

    while (nodes.size() < count and (it_n != c.end() or it_p != c.end())) {
        /* If one of the iterator is at the end, then take the other one
           If they are both in middle of somewhere comapre both and take
           the closest to the id. */
        if (it_p == c.end())       it = it_n++;
        else if (it_n == c.end())  it = it_p--;
        else                       it = id.xorCmp(it_p->first, it_n->first) < 0 ? it_p-- : it_n++;

        if (it == c.begin())
            it_p = c.end();

        if (auto n = it->second.lock())
            if ( not n->isExpired() )
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
        (family == AF_INET ? cache_4 : cache_6).clearBadNodes();
    }
}

void
NodeCache::closeAll(sa_family_t family)
{
    if (family == 0) {
        closeAll(AF_INET);
        closeAll(AF_INET6);
    } else {
        (family == AF_INET ? cache_4 : cache_6).closeAll();
    }
}

std::shared_ptr<Node>
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

std::shared_ptr<Node>
NodeCache::NodeMap::getNode(const InfoHash& id, const SockAddr& addr, const Sp<TcpSocket>& sock, time_point now, bool confirm)
{
    auto it = emplace(id, std::weak_ptr<Node>{});
    auto node = it.first->second.lock();
    if (not node) {
        node = std::make_shared<Node>(id, addr, sock);
        it.first->second = node;
    } else if (confirm || node->time < now - Node::NODE_EXPIRE_TIME) {
        node->update(addr, sock);
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

void
NodeCache::NodeMap::closeAll()
{
    for (auto it = cbegin(); it != cend();) {
        if (auto n = it->second.lock()) {
            if (n->sock) {
                n->sock->close();
                n->sock.reset();
            }
            ++it;
        } else {
            erase(it++);
        }
    }
}


}
