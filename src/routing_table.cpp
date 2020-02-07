/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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

#include "routing_table.h"

#include "network_engine.h"
#include "rng.h"

#include <memory>

namespace dht {

Sp<Node>
Bucket::randomNode(std::mt19937_64& rd)
{
    if (nodes.empty())
        return nullptr;
    unsigned expired_node_count = std::count_if(nodes.cbegin(), nodes.cend(), [](const decltype(nodes)::value_type& node) {
        return node->isExpired();
    });
    auto prioritize_not_expired = expired_node_count < nodes.size();

    std::uniform_int_distribution<unsigned> rand_node(0, prioritize_not_expired
            ? nodes.size() - expired_node_count - 1
            : nodes.size()-1);
    unsigned nn = rand_node(rd);
    for (auto& n : nodes) {
        if (not (prioritize_not_expired and n->isExpired())) {
            if (not nn--)
                return n;
        }
    }
    return nodes.back();
}

void Bucket::sendCachedPing(net::NetworkEngine& ne)
{
    if (not cached)
        return;
    //DHT_LOG.d(b.cached->id, "[node %s] sending ping to cached node", cached->toString().c_str());
    ne.sendPing(cached, nullptr, nullptr);
    cached = {};
}

InfoHash
RoutingTable::randomId(const RoutingTable::const_iterator& it, std::mt19937_64& rd) const
{
    int bit1 = it->first.lowbit();
    int bit2 = std::next(it) != end() ? std::next(it)->first.lowbit() : -1;
    int bit = std::max(bit1, bit2) + 1;

    if (bit >= 8*(int)HASH_LEN)
        return it->first;

#ifdef _WIN32
    std::uniform_int_distribution<int> rand_byte{ 0, std::numeric_limits<uint8_t>::max() };
#else
    std::uniform_int_distribution<uint8_t> rand_byte;
#endif

    int b = bit/8;
    InfoHash id_return;
    std::copy_n(it->first.cbegin(), b, id_return.begin());
    id_return[b] = it->first[b] & (0xFF00 >> (bit % 8));
    id_return[b] |= rand_byte(rd) >> (bit % 8);
    for (unsigned i = b + 1; i < HASH_LEN; i++)
        id_return[i] = rand_byte(rd);
    return id_return;
}

InfoHash
RoutingTable::middle(const RoutingTable::const_iterator& it) const
{
    unsigned bit = depth(it);
    if (bit >= 8*HASH_LEN)
        throw std::out_of_range("End of table");

    InfoHash id = it->first;
    id.setBit(bit, true);
    return id;
}

unsigned
RoutingTable::depth(const RoutingTable::const_iterator& it) const
{
    if (it == end())
        return 0;
    int bit1 = it->first.lowbit();
    int bit2 = std::next(it) != end() ? std::next(it)->first.lowbit() : -1;
    return std::max(bit1, bit2)+1;
}

std::vector<Sp<Node>>
RoutingTable::findClosestNodes(const InfoHash id, time_point now, size_t count) const
{
    std::vector<Sp<Node>> nodes;
    nodes.reserve(count);
    auto bucket = findBucket(id);

    if (bucket == end()) { return nodes; }

    auto sortedBucketInsert = [&](const Bucket &b) {
        for (auto n : b.nodes) {
            if (not n->isGood(now))
                continue;

            auto here = std::find_if(nodes.begin(), nodes.end(),
                [&id,&n](Sp<Node> &node) {
                    return id.xorCmp(n->id, node->id) < 0;
                }
            );
            nodes.insert(here, n);
        }
    };

    auto itn = bucket;
    auto itp = (bucket == begin()) ? end() : std::prev(bucket);
    while (nodes.size() < count && (itn != end() || itp != end())) {
        if (itn != end()) {
            sortedBucketInsert(*itn);
            itn = std::next(itn);
        }
        if (itp != end()) {
            sortedBucketInsert(*itp);
            itp = (itp == begin()) ? end() : std::prev(itp);
        }
    }

    // shrink to the count closest nodes.
    if (nodes.size() > count) {
        nodes.resize(count);
    }
    return nodes;
}

RoutingTable::iterator
RoutingTable::findBucket(const InfoHash& id)
{
    if (empty())
        return end();
    auto b = begin();
    while (true) {
        auto next = std::next(b);
        if (next == end())
            return b;
        if (InfoHash::cmp(id, next->first) < 0)
            return b;
        b = next;
    }
}

RoutingTable::const_iterator
RoutingTable::findBucket(const InfoHash& id) const
{
    /* Avoid code duplication for the const version */
    const_iterator it = const_cast<RoutingTable*>(this)->findBucket(id);
    return it;
}

/* Split a bucket into two equal parts. */
bool
RoutingTable::split(const RoutingTable::iterator& b)
{
    InfoHash new_id;
    try {
        new_id = middle(b);
    } catch (const std::out_of_range& e) {
        return false;
    }

    // Insert new bucket
    insert(std::next(b), Bucket {b->af, new_id, b->time});

    // Re-assign nodes
    std::list<Sp<Node>> nodes {};
    nodes.splice(nodes.begin(), b->nodes);
    while (!nodes.empty()) {
        auto n = nodes.begin();
        auto b = findBucket((*n)->id);
        if (b == end())
            nodes.erase(n);
        else
            b->nodes.splice(b->nodes.begin(), nodes, n);
    }
    return true;
}

bool
RoutingTable::onNewNode(const Sp<Node>& node, int confirm, const time_point& now, const InfoHash& myid, net::NetworkEngine& ne) {
    auto b = findBucket(node->id);
    if (b == end()) return false;

    if (confirm == 2)
        b->time = now;

    for (auto& n : b->nodes) {
        if (n == node)
            return false;
    }

    bool mybucket = contains(b, myid);
    if (mybucket) {
        grow_time = now;
        //scheduler.edit(nextNodesConfirmation, now);
    }

    if (b->nodes.size() >= TARGET_NODES) {
        /* Try to get rid of an expired node. */
        for (auto& n : b->nodes)
            if (n->isExpired()) {
                n = node;
                return true;
            }
        /* Bucket full.  Ping a dubious node */
        bool dubious = false;
        for (auto& n : b->nodes) {
            /* Pick the first dubious node that we haven't pinged in the
               last 9 seconds.  This gives nodes the time to reply, but
               tends to concentrate on the same nodes, so that we get rid
               of bad nodes fast. */
            if (not n->isGood(now)) {
                dubious = true;
                if (not n->isPendingMessage()) {
                    //DHT_LOG.d(n->id, "[node %s] sending ping to dubious node", n->toString().c_str());
                    ne.sendPing(n, nullptr, nullptr);
                    break;
                }
            }
        }

        if ((mybucket || (is_client and depth(b) < 6)) && (!dubious || size() == 1)) {
            //DHT_LOG.d("Splitting from depth %u", depth(b));
            b->sendCachedPing(ne);
            split(b);
            return onNewNode(node, confirm, now, myid, ne);
        }

        /* No space for this node.  Cache it away for later. */
        if (confirm or not b->cached)
            b->cached = node;
    } else {
        /* Create a new node. */
        b->nodes.emplace_front(node);
    }
    return true;
}



}
