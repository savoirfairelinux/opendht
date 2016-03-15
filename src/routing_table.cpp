#include "routing_table.h"
#include "rng.h"

#include <memory>

namespace dht {

static std::mt19937 rd{ dht::crypto::random_device{}() };
#ifdef _WIN32
static std::uniform_int_distribution<int> rand_byte{ 0, std::numeric_limits<uint8_t>::max() };
#else
static std::uniform_int_distribution<uint8_t> rand_byte;
#endif

std::shared_ptr<Node>
Bucket::randomNode()
{
    if (nodes.empty())
        return nullptr;
    std::uniform_int_distribution<unsigned> rand_node(0, nodes.size()-1);
    unsigned nn = rand_node(rd);
    for (auto& n : nodes)
        if (not nn--) return n;
    return nodes.back();
}

InfoHash
RoutingTable::randomId(const RoutingTable::const_iterator& it) const
{
    int bit1 = it->first.lowbit();
    int bit2 = std::next(it) != end() ? std::next(it)->first.lowbit() : -1;
    int bit = std::max(bit1, bit2) + 1;

    if (bit >= 8*(int)HASH_LEN)
        return it->first;

    int b = bit/8;
    InfoHash id_return;
    std::copy_n(it->first.begin(), b, id_return.begin());
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
    id.setBit(bit, 1);
    return id;
}

unsigned
RoutingTable::depth(const RoutingTable::const_iterator& it) const
{
    int bit1 = it->first.lowbit();
    int bit2 = std::next(it) != end() ? std::next(it)->first.lowbit() : -1;
    return std::max(bit1, bit2)+1;
}

std::vector<std::shared_ptr<Node>>
RoutingTable::findClosestNodes(const InfoHash id, time_point now, size_t count) const
{
    std::vector<std::shared_ptr<Node>> nodes {};
    auto bucket = findBucket(id);

    if (bucket == end()) { return nodes; }

    auto sortedBucketInsert = [&](const Bucket &b) {
        for (auto n : b.nodes) {
            if (not n->isGood(now))
                continue;

            auto here = std::find_if(nodes.begin(), nodes.end(),
                [&id,&n](std::shared_ptr<Node> &node) {
                    return id.xorCmp(n->id, node->id) < 0;
                }
            );
            nodes.insert(here, n);
        }
    };

    auto itn = bucket;
    auto itp = std::prev(bucket);
    while (nodes.size() < count && (itn != end() || itp != end())) {
        if (itn != end()) {
            sortedBucketInsert(*itn);
            itn = std::next(itn);
        }
        if (itp != end()) {
            sortedBucketInsert(*itp);
            if (itp == begin()) {
                itp = end();
                continue;
            }
            itp = std::prev(itp);
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
    std::list<std::shared_ptr<Node>> nodes {};
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

}
