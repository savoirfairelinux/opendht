/*
 *  Copyright (C) 2014-2016 Savoir-faire Linux Inc.
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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.
 */

#include "node_cache.h"

namespace dht {

std::shared_ptr<Node>
NodeCache::getNode(const InfoHash& id, sa_family_t family) {
    return (family == AF_INET ? cache_4 : cache_6).getNode(id);
}

std::shared_ptr<Node>
NodeCache::getNode(const InfoHash& id, const sockaddr* sa, socklen_t sa_len, time_point now, int confirm) {
    if (id == zeroes)
        return std::make_shared<Node>(id, sa, sa_len);
    return (sa->sa_family == AF_INET ? cache_4 : cache_6).getNode(id, sa, sa_len, now, confirm);
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
NodeCache::NodeMap::getNode(const InfoHash& id, const sockaddr* sa, socklen_t sa_len, time_point now, int confirm)
{
    auto it = emplace(id, std::weak_ptr<Node>{});
    auto node = it.first->second.lock();
    if (not node) {
        node = std::make_shared<Node>(id, sa, sa_len);
        it.first->second = node;
    } else if (confirm || node->time < now - Node::NODE_EXPIRE_TIME) {
        node->update(sa, sa_len);
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
