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
    return (family == AF_INET ? cache_4 : cache_6).get(id);
}

std::shared_ptr<Node>
NodeCache::getNode(const InfoHash& id, const sockaddr* sa, socklen_t sa_len, time_point now, int confirm) {
    return (sa->sa_family == AF_INET ? cache_4 : cache_6).get(id, sa, sa_len, now, confirm);
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
NodeCache::NodeTree::getLocal(const InfoHash& id)
{
    for (auto it = nodes.begin(); it != nodes.end();) {
        if (auto n = it->lock()) {
            if (n->id == id) return n;
            ++it;
        } else {
            it = nodes.erase(it);
        }
    }
    return {};
}

std::shared_ptr<Node>
NodeCache::NodeTree::get(const InfoHash& id)
{
    NodeTree* t = this;
    for (auto b : id) {
        if (t->childs.empty())
            return t->getLocal(id);
        else
            t = &t->childs[b];
    }
    return {};
}

std::shared_ptr<Node>
NodeCache::NodeTree::get(const InfoHash& id, const sockaddr* sa, socklen_t sa_len, time_point now, int confirm)
{
    // find the bucket
    NodeTree* t = this;
    size_t offset = 0;
    while (not t->childs.empty() and offset < 4)
        t = &t->childs[id[offset++]];

    // find node in bucket
    auto node = t->getLocal(id);
    if (not node) {
        node = std::make_shared<Node>(id, sa, sa_len);

        // insert node in bucket
        if (t->nodes.size() >= 8 && offset < 4) {
            offset++;
            t->childs.resize(256);
            for (auto& w : t->nodes) {
                if (auto tn = w.lock()) {
                    t->childs[tn->id[offset]].nodes.emplace_back(std::move(w));
                }
            }
            t->nodes = {};
            t->childs[id[offset]].nodes.emplace_back(node);
        } else {
            t->nodes.emplace_back(node);
        }
    } else if (confirm || node->time < now - Node::NODE_EXPIRE_TIME) {
        node->update(sa, sa_len);
    }
    /*if (confirm)
        node->received(now, confirm >= 2);*/
    return node;
}

void
NodeCache::NodeTree::clearBadNodes() {
    if (childs.empty()) {
        for (auto it = nodes.begin(); it != nodes.end();) {
            if (auto n = it->lock()) {
                n->reset();
                ++it;
            } else {
                it = nodes.erase(it);
            }
        }
    } else {
        for (auto& c : childs)
            c.clearBadNodes();
    }
}

}
