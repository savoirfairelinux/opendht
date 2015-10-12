/*
Copyright (c) 2009-2014 Juliusz Chroboczek
Copyright (c) 2014-2015 Savoir-Faire Linux Inc.

Authors : Adrien Béraud <adrien.beraud@savoirfairelinux.com>,
          Juliusz Chroboczek <jch@pps.univ–paris–diderot.fr>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "dht.h"
#include "rng.h"

#include <msgpack.hpp>
extern "C" {
#include <gnutls/gnutls.h>
}

#ifndef _WIN32
#include <arpa/inet.h>
#else
#include <ws2tcpip.h>
#endif

#include <algorithm>
#include <random>
#include <sstream>

#include <unistd.h>
#include <fcntl.h>
#include <cstring>

#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

#ifdef _WIN32

static bool
set_nonblocking(int fd, int nonblocking)
{
    unsigned long mode = !!nonblocking;
    int rc = ioctlsocket(fd, FIONBIO, &mode);
    return rc == 0;
}

extern const char *inet_ntop(int, const void *, char *, socklen_t);

#else

static bool
set_nonblocking(int fd, int nonblocking)
{
    int rc = fcntl(fd, F_GETFL, 0);
    if (rc < 0)
        return false;
    rc = fcntl(fd, F_SETFL, nonblocking?(rc | O_NONBLOCK):(rc & ~O_NONBLOCK));
    return !(rc < 0);
}

#endif

#define WANT4 1
#define WANT6 2

static std::mt19937 rd {dht::crypto::random_device{}()};
static std::uniform_int_distribution<uint8_t> rand_byte;

static const uint8_t v4prefix[16] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
};

static std::string
to_hex(const uint8_t *buf, size_t buflen)
{
    std::stringstream s;
    s << std::hex;
    for (size_t i = 0; i < buflen; i++)
        s << std::setfill('0') << std::setw(2) << (unsigned)buf[i];
    s << std::dec;
    return s.str();
}

std::string
dht::print_addr(const sockaddr* sa, socklen_t slen)
{
    char hbuf[NI_MAXHOST];
    char sbuf[NI_MAXSERV];
    std::stringstream out;
    if (!getnameinfo(sa, slen, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) {
        if (sa->sa_family == AF_INET6)
            out << "[" << hbuf << "]";
        else
            out << hbuf;
        if (strcmp(sbuf, "0"))
            out << ":" << sbuf;
    } else
        out << "[invalid address]";
    return out.str();
}

std::string
dht::print_addr(const sockaddr_storage& ss, socklen_t sslen)
{
    return print_addr((const sockaddr*)&ss, sslen);
}

std::string
dht::printAddr(const Address& addr) {
    return print_addr((const sockaddr*)&addr.first, addr.second);
}

template <class DT>
static double
print_dt(DT d) {
    return std::chrono::duration_cast<std::chrono::duration<double>>(d).count();
}

namespace dht {

const Dht::TransPrefix Dht::TransPrefix::PING = {"pn"};
const Dht::TransPrefix Dht::TransPrefix::FIND_NODE  = {"fn"};
const Dht::TransPrefix Dht::TransPrefix::GET_VALUES  = {"gt"};
const Dht::TransPrefix Dht::TransPrefix::ANNOUNCE_VALUES  = {"pt"};
const Dht::TransPrefix Dht::TransPrefix::LISTEN  = {"lt"};

const std::string Dht::my_v = "RNG1";

static constexpr InfoHash zeroes {};
static constexpr InfoHash ones = {std::array<uint8_t, HASH_LEN>{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
}};

constexpr std::chrono::minutes Node::NODE_EXPIRE_TIME;
constexpr std::chrono::minutes Node::NODE_GOOD_TIME;
constexpr std::chrono::seconds Node::MAX_RESPONSE_TIME;

constexpr std::chrono::seconds Dht::SEARCH_GET_STEP;
constexpr std::chrono::minutes Dht::SEARCH_EXPIRE_TIME;
constexpr std::chrono::seconds Dht::LISTEN_EXPIRE_TIME;
constexpr std::chrono::seconds Dht::REANNOUNCE_MARGIN;
constexpr std::chrono::seconds Dht::UDP_REPLY_TIME;
constexpr long unsigned Dht::MAX_REQUESTS_PER_SEC;

void
Dht::setLoggers(LogMethod&& error, LogMethod&& warn, LogMethod&& debug)
{
    DHT_DEBUG = std::move(debug);
    DHT_WARN = std::move(warn);
    DHT_ERROR = std::move(error);
}

Dht::Status
Dht::getStatus(sa_family_t af) const
{
    unsigned good = 0, dubious = 0, cached = 0, incoming = 0;
    int tot = getNodesStats(af, &good, &dubious, &cached, &incoming);
    if (tot < 1)
        return Status::Disconnected;
    else if (good < 1)
        return Status::Connecting;
    return Status::Connected;
}

bool
Dht::isRunning(sa_family_t af) const
{
    switch (af) {
    case 0:
        return dht_socket  >= 0 ||  dht_socket6 >= 0;
    case AF_INET:
        return dht_socket  >= 0;
    case AF_INET6:
        return dht_socket6 >= 0;
    default:
        return false;
    }
}

bool
Dht::isMartian(const sockaddr *sa, socklen_t len)
{
    // Check that sa_family can be accessed safely
    if (!sa || len < sizeof(sockaddr_in))
        return true;

    switch(sa->sa_family) {
    case AF_INET: {
        sockaddr_in *sin = (sockaddr_in*)sa;
        const uint8_t *address = (const uint8_t*)&sin->sin_addr;
        return sin->sin_port == 0 ||
            (address[0] == 0) ||
            (address[0] == 127) ||
            ((address[0] & 0xE0) == 0xE0);
    }
    case AF_INET6: {
        if (len < sizeof(sockaddr_in6))
            return true;
        sockaddr_in6 *sin6 = (sockaddr_in6*)sa;
        const uint8_t *address = (const uint8_t*)&sin6->sin6_addr;
        return sin6->sin6_port == 0 ||
            (address[0] == 0xFF) ||
            (address[0] == 0xFE && (address[1] & 0xC0) == 0x80) ||
            (memcmp(address, zeroes.data(), 15) == 0 &&
             (address[15] == 0 || address[15] == 1)) ||
            (memcmp(address, v4prefix, 12) == 0);
    }

    default:
        return true;
    }
}

std::shared_ptr<Node>
Dht::Bucket::randomNode()
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
Dht::RoutingTable::randomId(const Dht::RoutingTable::const_iterator& it) const
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
Dht::RoutingTable::middle(const RoutingTable::const_iterator& it) const
{
    unsigned bit = depth(it);
    if (bit >= 8*HASH_LEN)
        throw std::out_of_range("End of table");

    InfoHash id = it->first;
    id.setBit(bit, 1);
    return id;
}

unsigned
Dht::RoutingTable::depth(const RoutingTable::const_iterator& it) const
{
    int bit1 = it->first.lowbit();
    int bit2 = std::next(it) != end() ? std::next(it)->first.lowbit() : -1;
    return std::max(bit1, bit2)+1;
}

Dht::RoutingTable::iterator
Dht::RoutingTable::findBucket(const InfoHash& id)
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

Dht::RoutingTable::const_iterator
Dht::RoutingTable::findBucket(const InfoHash& id) const
{
    /* Avoid code duplication for the const version */
    const_iterator it = const_cast<RoutingTable*>(this)->findBucket(id);
    return it;
}

/* Every bucket contains an unordered list of nodes. */
std::shared_ptr<Node>
Dht::findNode(const InfoHash& id, sa_family_t af)
{
    Bucket* b = findBucket(id, af);
    if (!b)
        return {};
    for (auto& n : b->nodes)
        if (n->id == id) return n;
    return {};
}

const std::shared_ptr<Node>
Dht::findNode(const InfoHash& id, sa_family_t af) const
{
    const Bucket* b = findBucket(id, af);
    if (!b)
        return {};
    for (const auto& n : b->nodes)
        if (n->id == id) return n;
    return {};
}

/* This is our definition of a known-good node. */
bool
Node::isGood(time_point now) const
{
    return
        not isExpired(now) &&
        reply_time >= now - NODE_GOOD_TIME &&
        time >= now - NODE_EXPIRE_TIME;
}

bool
Node::isExpired(time_point now) const
{
    return pinged >= 3 && reply_time < pinged_time && pinged_time + MAX_RESPONSE_TIME < now;
}

bool
Node::isMessagePending(time_point now) const
{
    return reply_time < pinged_time && pinged_time + MAX_RESPONSE_TIME > now;
}

void
Node::update(const sockaddr* sa, socklen_t salen)
{
    std::copy_n((const uint8_t*)sa, salen, (uint8_t*)&ss);
    sslen = salen;
}

/** To be called when a message was sent to the node */
void
Node::requested(time_point now)
{
    pinged++;
    if (reply_time > pinged_time || pinged_time + MAX_RESPONSE_TIME < now)
        pinged_time = now;
}

/** To be called when a message was received from the node.
 Answer should be true if the message was an aswer to a request we made*/
void
Node::received(time_point now, bool answer)
{
    time = now;
    if (answer) {
        pinged = 0;
        reply_time = now;
    }
}

std::ostream& operator<< (std::ostream& s, const Node& h)
{
    s << h.id << " " << print_addr(h.ss, h.sslen);
    return s;
}


std::shared_ptr<Node>
Dht::NodeCache::getNode(const InfoHash& id, sa_family_t family) {
    auto& list = family == AF_INET ? cache_4 : cache_6;
    for (auto n = list.begin(); n != list.end();) {
        if (auto ln = n->lock()) {
            if (ln->id == id)
                return ln;
            ++n;
        } else {
            n = list.erase(n);
        }
    }
    return nullptr;
}

std::shared_ptr<Node>
Dht::NodeCache::getNode(const InfoHash& id, const sockaddr* sa, socklen_t sa_len, time_point now, int confirm) {
    auto node = getNode(id, sa->sa_family);
    if (not node) {
        node = std::make_shared<Node>(id, sa, sa_len);
        putNode(node);
    } else if (confirm || node->time < now - Node::NODE_EXPIRE_TIME) {
        node->update(sa, sa_len);
    }
    if (confirm)
        node->received(now, confirm >= 2);
    return node;
}

void
Dht::NodeCache::putNode(std::shared_ptr<Node> n) {
    if (not n) return;
    auto& list = n->ss.ss_family == AF_INET ? cache_4 : cache_6;
    list.push_back(n);
}

/* Every bucket caches the address of a likely node.  Ping it. */
int
Dht::sendCachedPing(Bucket& b)
{
    /* We set family to 0 when there's no cached node. */
    if (b.cached.ss_family == 0)
        return 0;

    DHT_DEBUG("Sending ping to cached node.");
    int rc = sendPing((sockaddr*)&b.cached, b.cachedlen, TransId{TransPrefix::PING});
    b.cached.ss_family = 0;
    b.cachedlen = 0;
    return rc;
}

/* Called whenever we send a request to a node, increases the ping count
   and, if that reaches 3, sends a ping to a new candidate. */
void
Dht::pinged(Node& n, Bucket* b)
{

    if (not n.isExpired(now)) {
        n.requested(now);
        if (n.pinged >= 3) {
            if (not b)
                b = findBucket(n.id, n.ss.ss_family);
            if (b) sendCachedPing(*b);
        }
    }
}

/* The internal blacklist is an LRU cache of nodes that have sent
   incorrect messages. */
void
Dht::blacklistNode(const InfoHash* id, const sockaddr *sa, socklen_t salen)
{
    DHT_WARN("Blacklisting broken node.");

    if (id) {
        /* Make the node easy to discard. */
        auto n = findNode(*id, sa->sa_family);
        if (n) {
            n->pinged = 3;
            pinged(*n);
        }
        /* Discard it from any searches in progress. */
        for (auto& sr : searches) {
            auto sni = std::begin(sr.nodes);
            while (sni != std::end(sr.nodes)) {
                if ((*sni).node == n)
                    sni = sr.nodes.erase(sni);
                else
                    ++sni;
            }
        }
    }
    /* And make sure we don't hear from it again. */
    memcpy(&blacklist[next_blacklisted], sa, salen);
    next_blacklisted = (next_blacklisted + 1) % BLACKLISTED_MAX;
}

bool
Dht::isNodeBlacklisted(const sockaddr *sa, socklen_t salen) const
{
    if (salen > sizeof(sockaddr_storage))
        return true;

    if (isBlacklisted(sa, salen))
        return true;

    for (unsigned i = 0; i < BLACKLISTED_MAX; i++) {
        if (memcmp(&blacklist[i], sa, salen) == 0)
            return true;
    }

    return false;
}

std::vector<Address>
Dht::getPublicAddress()
{
    std::sort(reported_addr.begin(), reported_addr.end(), [](const ReportedAddr& a, const ReportedAddr& b) {
        return a.first < b.first;
    });
    std::vector<Address> ret;
    ret.reserve(reported_addr.size());
    for (const auto& addr : reported_addr)
        ret.emplace_back(addr.second);
    return ret;
}

/* Split a bucket into two equal parts. */
bool
Dht::RoutingTable::split(const RoutingTable::iterator& b)
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

bool
Dht::trySearchInsert(const std::shared_ptr<Node>& node)
{
    bool inserted = false;
    auto family = node->getFamily();
    if (not node) return inserted;
    for (auto& s : searches) {
        if (s.af != family) continue;
        if (s.insertNode(node, now)) {
            inserted = true;
            search_time = std::min(search_time, s.getNextStepTime(types, now));
        }
    }
    return inserted;
}

void
Dht::reportedAddr(const sockaddr *sa, socklen_t sa_len)
{
    auto it = std::find_if(reported_addr.begin(), reported_addr.end(), [=](const ReportedAddr& addr){
        return (addr.second.second == sa_len) && std::equal((uint8_t*)&addr.second.first, (uint8_t*)&addr.second.first + addr.second.second, (uint8_t*)sa);
    });
    if (it == reported_addr.end()) {
        if (reported_addr.size() < 32)
            reported_addr.emplace_back(1, std::make_pair(*((sockaddr_storage*)sa), sa_len));
    } else
        it->first++;
}

/* We just learnt about a node, not necessarily a new one.  Confirm is 1 if
   the node sent a message, 2 if it sent us a reply. */
std::shared_ptr<Node>
Dht::newNode(const InfoHash& id, const sockaddr *sa, socklen_t salen, int confirm, const sockaddr* addr, socklen_t addr_length)
{
    if (id == myid || isMartian(sa, salen) || isNodeBlacklisted(sa, salen))
        return nullptr;

    auto& list = sa->sa_family == AF_INET ? buckets : buckets6;
    auto b = list.findBucket(id);
    if (b == list.end())
        return nullptr;

    bool mybucket = list.contains(b, myid);

    if (confirm == 2) {
        b->time = now;
        if (addr and addr_length)
            reportedAddr(addr, addr_length);
    }

    for (auto& n : b->nodes) {
        if (n->id != id) continue;
        /* Known node.  Update stuff. */

        if (confirm || n->time + Node::NODE_EXPIRE_TIME < now) {
            n->update(sa, salen);
            if (confirm) {
                n->received(now, confirm >= 2);
                /* If this node existed in searches but was expired, give it another chance. */
                trySearchInsert(n);
            }
        }
        return n;
    }

    /* New node. */

    if (mybucket) {
        if (sa->sa_family == AF_INET)
            mybucket_grow_time = now;
        else
            mybucket6_grow_time = now;
    }

    /* First, try to get rid of a known-bad node. */
    for (auto& n : b->nodes) {
        if (not n->isExpired(now))
            continue;
        n = cache.getNode(id, sa, salen, now, confirm);

        /* Try adding the node to searches */
        trySearchInsert(n);
        return n;
    }

    if (b->nodes.size() >= TARGET_NODES) {
        /* Bucket full.  Ping a dubious node */
        bool dubious = false;
        for (auto& n : b->nodes) {
            /* Pick the first dubious node that we haven't pinged in the
               last 9 seconds.  This gives nodes the time to reply, but
               tends to concentrate on the same nodes, so that we get rid
               of bad nodes fast. */
            if (not n->isGood(now)) {
                dubious = true;
                if (n->pinged_time + Node::MAX_RESPONSE_TIME < now) {
                    DHT_DEBUG("Sending ping to dubious node.");
                    sendPing((sockaddr*)&n->ss, n->sslen, TransId {TransPrefix::PING});
                    n->pinged++;
                    n->pinged_time = now;
                    //pinged(n, b);
                    break;
                }
            }
        }

        if ((mybucket || (is_bootstrap and list.depth(b) < 6)) && (!dubious || list.size() == 1)) {
            DHT_DEBUG("Splitting from depth %u", list.depth(b));
            sendCachedPing(*b);
            list.split(b);
            return newNode(id, sa, salen, confirm);
        }

        /* No space for this node.  Cache it away for later. */
        if (confirm || b->cached.ss_family == 0) {
            memcpy(&b->cached, sa, salen);
            b->cachedlen = salen;
        }
        auto cn = cache.getNode(id, sa, salen, now, confirm);
        trySearchInsert(cn);
        return cn;
    }

    /* Create a new node. */
    auto cn = cache.getNode(id, sa, salen, now, confirm);
    b->nodes.emplace_front(cn);
    trySearchInsert(cn);
    return cn;
}

/* Called periodically to purge known-bad nodes.  Note that we're very
   conservative here: broken nodes in the table don't do much harm, we'll
   recover as soon as we find better ones. */
void
Dht::expireBuckets(RoutingTable& list)
{
    for (auto& b : list) {
        bool changed = false;
        b.nodes.remove_if([&changed](const std::shared_ptr<Node>& n) {
            if (n->pinged >= 4) {
                changed = true;
                return true;
            }
            return false;
        });
        if (changed)
            sendCachedPing(b);
    }
    uniform_duration_distribution<> time_dis(std::chrono::minutes(2), std::chrono::minutes(6));
    expire_stuff_time = now + duration(time_dis(rd));
}

/* While a search is in progress, we don't necessarily keep the nodes being
   walked in the main bucket table.  A search in progress is identified by
   a unique transaction id, a short (and hence small enough to fit in the
   transaction id of the protocol packets). */

Dht::Search *
Dht::findSearch(unsigned short tid, sa_family_t af)
{
    auto sr = std::find_if (searches.begin(), searches.end(), [tid,af](const Search& s){
        return s.tid == tid && s.af == af;
    });
    return sr == searches.end() ? nullptr : &(*sr);
}

bool
Dht::Search::removeExpiredNode(time_point now)
{
    auto e = nodes.end();
    while (e != nodes.cbegin()) {
        e = std::prev(e);
        const Node& n = *e->node;
        if (n.isExpired(now) and n.time + Node::NODE_EXPIRE_TIME < now) {
            //std::cout << "Removing expired node " << n.id << " from IPv" << (af==AF_INET?'4':'6') << " search " << id << std::endl;
            nodes.erase(e);
            return true;
        }
    }
    return false;
}

/* A search contains a list of nodes, sorted by decreasing distance to the
   target.  We just got a new candidate, insert it at the right spot or
   discard it. */
bool
Dht::Search::insertNode(std::shared_ptr<Node> node, time_point now, const Blob& token)
{
    if (node->ss.ss_family != af) {
        //DHT_DEBUG("Attempted to insert node in the wrong family.");
        return false;
    }

    const auto& nid = node->id;

    // Fast track for the case where the node is not relevant for this search
    if (nodes.size() >= SEARCH_NODES && id.xorCmp(nid, nodes.back().node->id) > 0 && node->isExpired(now))
        return false;

    // Reset search timer if it was empty
    if (nodes.empty()) {
        step_time = TIME_INVALID;
        get_step_time = TIME_INVALID;
    }

    bool found = false;
    unsigned num_candidates = 0;
    auto n = std::find_if(nodes.begin(), nodes.end(), [&](const SearchNode& sn) {
        if (sn.candidate)
            num_candidates++;
        if (sn.node == node) {
            found = true;
            return true;
        }
        return id.xorCmp(nid, sn.node->id) < 0;
    });
    if (!found) {
        if (nodes.size()-num_candidates >= SEARCH_NODES or nodes.size() >= SEARCH_NODES+TARGET_NODES/2) {
            if (node->isExpired(now))
                return false;
            if (n == nodes.end()) {
                // search is full, try to remove an expired node
                if (not removeExpiredNode(now))
                    return false;
                n = nodes.end();
            }
        }
        //bool synced = isSynced(now);
        n = nodes.insert(n, SearchNode(node));
        node->time = now;
        /*if (synced) {
            n->candidate = true;
            //std::cout << "Adding candidate node " << node->id << " to IPv" << (af==AF_INET?'4':'6') << " synced search " << id << std::endl;
        }*//* else {
            std::cout << "Adding real node " << node->id << " to IPv" << (af==AF_INET?'4':'6') << " synced search " << id << std::endl;
        }*/
        while (nodes.size()-num_candidates > SEARCH_NODES)
            if (not removeExpiredNode(now))
                nodes.pop_back();
        expired = false;
    }
    if (not token.empty()) {
        n->getStatus.reply_time = now;
        n->getStatus.request_time = TIME_INVALID;
        if (n->candidate) {
            n->candidate = false;
            //std::cout << "Confirm candidate node " << node->id << " to synced search " << id << std::endl;
        }
        if (token.size() <= 64)
            n->token = token;
        expired = false;
    }
    return true;
}

std::vector<std::shared_ptr<Node>>
Dht::Search::getNodes() const
{
    std::vector<std::shared_ptr<Node>> ret {};
    ret.reserve(nodes.size());
    for (const auto& sn : nodes)
        ret.emplace_back(sn.node);
    return ret;
}

void
Dht::expireSearches()
{
    auto t = now - SEARCH_EXPIRE_TIME;
    searches.remove_if([t](const Search& sr) {
        return sr.callbacks.empty() && sr.announce.empty() && sr.listeners.empty() && sr.step_time < t;
    });
}

Dht::SearchNode*
Dht::searchSendGetValues(Search& sr, SearchNode* pn, bool update)
{
    const time_point up = update ? sr.getLastGetTime() : time_point::min();
    SearchNode* n = nullptr;
    if (pn) {
        if (not pn->canGet(now, up))
            return nullptr;
        n = pn;
    } else {
        for (auto& sn : sr.nodes) {
            if (sn.canGet(now, up)) {
                n = &sn;
                break;
            }
        }
        if (not n)
            return nullptr;
    }

    DHT_DEBUG("[search %s IPv%c] [node %s %s] sending 'get' (p %d last get %lf)",
        sr.id.toString().c_str(), sr.af == AF_INET ? '4' : '6',
        n->node->id.toString().c_str(),
        print_addr(n->node->ss, n->node->sslen).c_str(),
        n->node->pinged, print_dt(now-n->getStatus.request_time));

    sendGetValues((sockaddr*)&n->node->ss, n->node->sslen, TransId {TransPrefix::GET_VALUES, sr.tid}, sr.id, -1, n->node->reply_time >= now - UDP_REPLY_TIME);
    n->getStatus.request_time = now;
    pinged(*n->node);
    if (n->node->pinged > 1 and not n->candidate) {
        n->candidate = true;
    }

    return n;
}

/* When a search is in progress, we periodically call search_step to send
   further requests. */
void
Dht::searchStep(Search& sr)
{
    DHT_DEBUG("[search %s IPv%c] step", sr.id.toString().c_str(), sr.af == AF_INET ? '4' : '6');
    sr.step_time = now;

    /* Check if the first TARGET_NODES (8) live nodes have replied. */
    if (sr.isSynced(now)) {
        if (not sr.callbacks.empty()) {
            // search is synced but some (newer) get operations are not complete
            // Call callbacks when done
            for (auto b = sr.callbacks.begin(); b != sr.callbacks.end();) {
                if (sr.isDone(*b, now)) {
                    if (b->done_cb)
                        b->done_cb(true, sr.getNodes());
                    b = sr.callbacks.erase(b);
                }
                else
                    ++b;
            }
            if (sr.callbacks.empty() && sr.announce.empty() && sr.listeners.empty())
                sr.done = true;
        }

        // true if this node is part of the target nodes cluter.
        bool in = sr.id.xorCmp(myid, sr.nodes.back().node->id) < 0;

        DHT_DEBUG("[search %s IPv%c] synced%s", sr.id.toString().c_str(), sr.af == AF_INET ? '4' : '6', in ? ", in" : "");

        if (not sr.listeners.empty()) {
            unsigned i = 0, t = 0;
            for (auto& n : sr.nodes) {
                if (not n.isSynced(now) or (n.candidate and t >= LISTEN_NODES))
                    continue;
                if (n.getListenTime() <= now) {
                    DHT_WARN("[search %s IPv%c] [node %s %s] sending 'listen'",
                        sr.id.toString().c_str(), sr.af == AF_INET ? '4' : '6',
                        n.node->id.toString().c_str(),
                        print_addr(n.node->ss, n.node->sslen).c_str());
                    //std::cout << "Sending listen to " << n.node->id << " " << print_addr(n.node->ss, n.node->sslen) << std::endl;

                    sendListen((sockaddr*)&n.node->ss, n.node->sslen, TransId {TransPrefix::LISTEN, sr.tid}, sr.id, n.token, n.node->reply_time >= now - UDP_REPLY_TIME);
                    n.pending = true;
                    n.listenStatus.request_time = now;
                }
                t++;
                if (not n.candidate and ++i == LISTEN_NODES)
                    break;
            }
        }

        // Announce requests
        for (auto& a : sr.announce) {
            if (!a.value) continue;
            unsigned i = 0, t = 0;
            auto vid = a.value->id;
            const auto& type = getType(a.value->type);
            if (in) {
                DHT_WARN("[search %s IPv%c] [value %lu] storing locally",
                    sr.id.toString().c_str(), sr.af == AF_INET ? '4' : '6', vid);
                storageStore(sr.id, a.value);
            }
            for (auto& n : sr.nodes) {
                if (not n.isSynced(now) or (n.candidate and t >= TARGET_NODES))
                    continue;
                auto a_status = n.acked.find(vid);
                auto at = n.getAnnounceTime(a_status, type);
                if ( at <= now ) {
                    DHT_WARN("[search %s IPv%c] [node %s %s] sending 'put'",
                        sr.id.toString().c_str(), sr.af == AF_INET ? '4' : '6',
                        n.node->id.toString().c_str(),
                        print_addr(n.node->ss, n.node->sslen).c_str());
                    //std::cout << "Sending announce_value to " << n.node->id << " " << print_addr(n.node->ss, n.node->sslen) << std::endl;

                    sendAnnounceValue((sockaddr*)&n.node->ss, n.node->sslen,
                                       TransId {TransPrefix::ANNOUNCE_VALUES, sr.tid}, sr.id, *a.value,
                                       n.token, n.node->reply_time >= now - UDP_REPLY_TIME);
                    if (a_status == n.acked.end()) {
                        n.acked[vid] = { now };
                    } else {
                        a_status->second.request_time = now;
                    }
                    // use the "pending" flag so we update the "pinged"
                    // fields after sending the announce requests for every value to announce
                    n.pending = true;
                }
                t++;
                if (not n.candidate and ++i == TARGET_NODES)
                    break;
            }
        }
        if (sr.callbacks.empty() && sr.announce.empty() && sr.listeners.empty())
            sr.done = true;
    }

    if (sr.get_step_time + SEARCH_GET_STEP <= now) {
        unsigned i = 0;
        SearchNode* sent;
        do {
            sent = searchSendGetValues(sr);
            if (sent) {
                sent->pending = false;
                if (not sent->candidate)
                    i++;
            }
        }
        while (sent and i < 3);
        DHT_DEBUG("[search %s IPv%c] step: sent %u requests.",
            sr.id.toString().c_str(), sr.af == AF_INET ? '4' : '6', i);

        if (i > 0)
            sr.get_step_time = now;
        else if ((size_t)std::count_if(sr.nodes.begin(), sr.nodes.end(), [&](const SearchNode& sn) {
                    return sn.candidate or sn.node->isExpired(now);
                }) == sr.nodes.size())
        {
            DHT_ERROR("[search %s IPv%c] expired", sr.id.toString().c_str(), sr.af == AF_INET ? '4' : '6');
            // no nodes or all expired nodes
            sr.expired = true;
            if (sr.announce.empty() && sr.listeners.empty()) {
                // Listening or announcing requires keeping the cluster up to date.
                sr.done = true;
            }
            {
                auto get_cbs = std::move(sr.callbacks);
                for (const auto& g : get_cbs) {
                    if (g.done_cb)
                        g.done_cb(false, {});
                }
            }
            {
                std::vector<DoneCallback> a_cbs;
                a_cbs.reserve(sr.announce.size());
                for (const auto& a : sr.announce)
                    if (a.callback)
                        a_cbs.emplace_back(std::move(a.callback));
                for (const auto& a : a_cbs)
                    a(false, {});
            }
        }
    }

    for (auto& n : sr.nodes) {
        if (n.pending) {
            n.pending = false;
            pinged(*n.node);
        }
    }

}


std::list<Dht::Search>::iterator
Dht::newSearch()
{
    auto oldest = searches.begin();
    for (auto i = searches.begin(); i != searches.end(); ++i) {
        if (i->done && (oldest->step_time > i->step_time))
            oldest = i;
    }

    /* The oldest slot is expired. */
    if (oldest != searches.end() && oldest->announce.empty() && oldest->listeners.empty() && oldest->step_time < now - SEARCH_EXPIRE_TIME) {
        DHT_WARN("Reusing expired search %s", oldest->id.toString().c_str());
        return oldest;
    }

    /* Allocate a new slot. */
    if (searches.size() < MAX_SEARCHES) {
        searches.push_front(Search {});
        return searches.begin();
    }

    /* Oh, well, never mind.  Reuse the oldest slot. */
    return oldest;
}

/* Insert the contents of a bucket into a search structure. */
void
Dht::Search::insertBucket(const Bucket& b, time_point now)
{
    for (auto& n : b.nodes) {
        if (not n->isExpired(now))
            insertNode(n, now);
    }
}

bool
Dht::Search::isSynced(time_point now) const
{
    unsigned i = 0;
    for (const auto& n : nodes) {
        if (n.node->isExpired(now) or n.candidate)
            continue;
        if (not n.isSynced(now))
            return false;
        if (++i == TARGET_NODES)
            break;
    }
    return i > 0;
}

time_point
Dht::Search::getLastGetTime() const
{
    time_point last = time_point::min();
    for (const auto& g : callbacks)
        last = std::max(last, g.start);
    return last;
}

bool
Dht::Search::isDone(const Get& get, time_point now) const
{
    unsigned i = 0;
    const auto limit = std::max(get.start, now - Node::NODE_EXPIRE_TIME);
    for (const auto& sn : nodes) {
        if (sn.node->isExpired(now) or sn.candidate)
            continue;
        if (sn.getStatus.reply_time < limit)
            return false;
        if (++i == TARGET_NODES)
            break;
    }
    return true;
}

time_point
Dht::Search::getUpdateTime(time_point now) const
{
    time_point ut = time_point::max();
    const auto last_get = getLastGetTime();
    unsigned i = 0, t = 0, d = 0;
    for (const auto& sn : nodes) {
        if (sn.node->isExpired(now) or (sn.candidate and t >= TARGET_NODES))
            continue;
        if (sn.getStatus.reply_time < std::max(now - Node::NODE_EXPIRE_TIME, last_get)) {
            // not isSynced
            ut = std::min(ut, std::max(
                sn.getStatus.request_time + Node::MAX_RESPONSE_TIME,
                get_step_time + SEARCH_GET_STEP));
            if (not sn.candidate)
                d++;
        } else {
            ut = std::min(ut, std::max(
                sn.getStatus.request_time + Node::MAX_RESPONSE_TIME,
                sn.getStatus.reply_time + Node::NODE_EXPIRE_TIME));
        }
        t++;
        if (not sn.candidate and ++i == TARGET_NODES)
            break;
    }
    if (not callbacks.empty() and d == 0) {
        // If all synced/updated but some callbacks remain, step now to clear them
        return now;
    }
    return ut;
}

bool
Dht::Search::isAnnounced(Value::Id id, const ValueType& type, time_point now) const
{
    if (nodes.empty())
        return false;
    unsigned i = 0;
    for (const auto& n : nodes) {
        if (n.candidate or n.node->isExpired(now))
            continue;
        if (not n.isAnnounced(id, type, now))
            return false;
        if (++i == TARGET_NODES)
            break;
    }
    return i;
}

bool
Dht::Search::isListening(time_point now) const
{
    if (nodes.empty() or listeners.empty())
        return false;
    unsigned i = 0;
    for (const auto& n : nodes) {
        if (n.candidate or n.node->isExpired(now))
            continue;
        if (!n.isListening(now))
            return false;
        if (++i == LISTEN_NODES)
            break;
    }
    return i;
}

time_point
Dht::Search::getAnnounceTime(const std::map<ValueType::Id, ValueType>& types, time_point now) const
{
    if (nodes.empty())
        return time_point::max();
    time_point ret {time_point::max()};
    for (const auto& a : announce) {
        if (!a.value) continue;
        auto type_it = types.find(a.value->type);
        const ValueType& type = (type_it == types.end()) ? ValueType::USER_DATA : type_it->second;
        unsigned i = 0, t = 0;
        for (const auto& n : nodes) {
            if (not n.isSynced(now) or (n.candidate and t >= TARGET_NODES))
                continue;
            ret = std::min(ret, n.getAnnounceTime(a.value->id, type));
            t++;
            if (not n.candidate and ++i == TARGET_NODES)
                break;
        }
    }
    return ret;
}

time_point
Dht::Search::getListenTime(time_point now) const
{
    if (listeners.empty())
        return time_point::max();
    time_point listen_time {time_point::max()};
    unsigned i = 0, t = 0;
    for (const auto& sn : nodes) {
        if (not sn.isSynced(now) or (sn.candidate and t >= LISTEN_NODES))
            continue;
        auto lt = sn.getListenTime();
        listen_time = std::min(listen_time, lt);
        t++;
        if (not sn.candidate and ++i == LISTEN_NODES)
            break;
    }
    return listen_time;
}

time_point
Dht::Search::getNextStepTime(const std::map<ValueType::Id, ValueType>& types, time_point now) const
{
    auto next_step = time_point::max();
    if (expired or done)
        return next_step;

    auto ut = getUpdateTime(now);
    if (ut != time_point::max()) {
        //std::cout << id.toString() << " IPv" << (af==AF_INET?"4":"6") << " update time in " << print_dt(ut - now) << " s" << std::endl;
        next_step = std::min(next_step, ut);
    }

    if (isSynced(now))
    {
        auto at = getAnnounceTime(types, now);
        if (at != time_point::max()) {
            //std::cout << id.toString() << " IPv" << (af==AF_INET?"4":"6") << " announce time in " << print_dt(at - now) << " s" << std::endl;
            next_step = std::min(next_step, at);
        }

        auto lt = getListenTime(now);
        if (lt != time_point::max()) {
            //std::cout << id.toString() << " IPv" << (af==AF_INET?"4":"6") << " listen time in " << print_dt(lt - now) << " s" << std::endl;
            next_step = std::min(next_step, lt);
        }
    }


    return next_step;
}

void
Dht::bootstrapSearch(Dht::Search& sr)
{
    auto& list = (sr.af == AF_INET) ? buckets : buckets6;
    if (list.empty() || (list.size() == 1 && list.front().nodes.empty()))
        return;
    auto b = list.findBucket(sr.id);
    if (b == list.end()) {
        DHT_ERROR("No bucket");
        return;
    }

    sr.insertBucket(*b, now);
    if (sr.nodes.size() < SEARCH_NODES) {
        if (std::next(b) != list.end())
            sr.insertBucket(*std::next(b), now);
        if (b != list.begin())
            sr.insertBucket(*std::prev(b), now);
    }
    if (sr.nodes.size() < SEARCH_NODES)
        sr.insertBucket(*list.findBucket(myid), now);
}

/* Start a search. */
Dht::Search*
Dht::search(const InfoHash& id, sa_family_t af, GetCallback callback, DoneCallback done_callback, Value::Filter filter)
{
    if (!isRunning(af)) {
        DHT_ERROR("[search %s IPv%c] unsupported protocol", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
        if (done_callback)
            done_callback(false, {});
        return nullptr;
    }

    auto sr = std::find_if (searches.begin(), searches.end(), [id,af](const Search& s) {
        return s.id == id && s.af == af;
    });

    if (sr != searches.end()) {
        sr->done = false;
        sr->expired = false;
    } else {
        sr = newSearch();
        if (sr == searches.end())
            return nullptr;
        sr->af = af;
        sr->tid = search_id++;
        sr->step_time = TIME_INVALID;
        sr->get_step_time = TIME_INVALID;
        sr->id = id;
        sr->done = false;
        sr->expired = false;
        sr->nodes.clear();
        sr->nodes.reserve(SEARCH_NODES+1);
        DHT_WARN("[search %s IPv%c] new search", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
    }

    if (callback)
        sr->callbacks.push_back({.start=now, .filter=filter, .get_cb=callback, .done_cb=done_callback});

    bootstrapSearch(*sr);
    searchStep(*sr);
    search_time = now;
    return &(*sr);
}

void
Dht::announce(const InfoHash& id, sa_family_t af, std::shared_ptr<Value> value, DoneCallback callback)
{
    if (!value) {
        if (callback)
            callback(false, {});
        return;
    }
    auto sri = std::find_if (searches.begin(), searches.end(), [id,af](const Search& s) {
        return s.id == id && s.af == af;
    });
    Search* sr = (sri == searches.end()) ? search(id, af, nullptr, nullptr) : &(*sri);
    if (!sr) {
        if (callback)
            callback(false, {});
        return;
    }
    sr->done = false;
    auto a_sr = std::find_if(sr->announce.begin(), sr->announce.end(), [&](const Announce& a){
        return a.value->id == value->id;
    });
    if (a_sr == sr->announce.end())
        sr->announce.emplace_back(Announce {value, callback});
    else {
        if (a_sr->value != value) {
            a_sr->value = value;
            for (auto& n : sr->nodes)
                n.acked[value->id] = {};
        }
        if (a_sr->callback)
            a_sr->callback(false, {});
        a_sr->callback = callback;
    }
    auto tm = sr->getNextStepTime(types, now);
    if (tm < search_time) {
        DHT_ERROR("[search %s IPv%c] search_time is now in %lfs", sr->id.toString().c_str(), (sr->af == AF_INET) ? '4' : '6', print_dt(tm-clock::now()));
        search_time = tm;
    }/* else {
        DHT_DEBUG("search_time NOT changed to %ld (in %lf - actual in %lf)",
            tm.time_since_epoch().count(),
            print_dt(tm-clock::now()),
            print_dt(search_time-clock::now()));
    }*/
}

size_t
Dht::listenTo(const InfoHash& id, sa_family_t af, GetCallback cb, Value::Filter f)
{
    if (!isRunning(af))
        return 0;
       // DHT_ERROR("[search %s IPv%c] search_time is now in %lfs", sr->id.toString().c_str(), (sr->af == AF_INET) ? '4' : '6', print_dt(tm-clock::now()));

    //DHT_WARN("listenTo %s", id.toString().c_str());
    auto sri = std::find_if (searches.begin(), searches.end(), [id,af](const Search& s) {
        return s.id == id && s.af == af;
    });
    Search* sr = (sri == searches.end()) ? search(id, af, nullptr, nullptr) : &(*sri);
    if (!sr)
        throw DhtException("Can't create search");
    DHT_ERROR("[search %s IPv%c] listen", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
    sr->done = false;
    auto token = ++sr->listener_token;
    sr->listeners.emplace(token, LocalListener{f, cb});
    search_time = std::min(search_time, sr->getNextStepTime(types, now));
    return token;
}

size_t
Dht::listen(const InfoHash& id, GetCallback cb, Value::Filter f)
{
    now = clock::now();

    auto vals = std::make_shared<std::map<Value::Id, std::shared_ptr<Value>>>();
    auto token = ++listener_token;

    auto gcb = [=](const std::vector<std::shared_ptr<Value>>& values) {
        std::vector<std::shared_ptr<Value>> newvals {};
        for (const auto& v : values) {
            auto it = vals->find(v->id);
            if (it == vals->cend() || !(*it->second == *v))
                newvals.push_back(v);
        }
        if (!newvals.empty()) {
            if (!cb(newvals)) {
                cancelListen(id, token);
                return false;
            }
            for (const auto& v : newvals) {
                auto it = vals->emplace(v->id, v);
                if (not it.second)
                    it.first->second = v;
            }
        }
        return true;
    };

    Storage* st = findStorage(id);
    size_t tokenlocal = 0;
    if (!st && store.size() < MAX_HASHES) {
        store.push_back(Storage {id});
        st = &store.back();
    }
    if (st) {
        if (not st->values.empty()) {
            std::vector<std::shared_ptr<Value>> newvals {};
            newvals.reserve(st->values.size());
            for (auto& v : st->values) {
                if (not f || f(*v.data))
                    newvals.push_back(v.data);
            }
            if (not newvals.empty()) {
                if (!cb(newvals))
                    return 0;
                for (const auto& v : newvals) {
                    auto it = vals->emplace(v->id, v);
                    if (not it.second)
                        it.first->second = v;
                }
            }
        }
        tokenlocal = ++st->listener_token;
        st->local_listeners.emplace(tokenlocal, LocalListener{f, gcb});
    }

    auto token4 = Dht::listenTo(id, AF_INET, gcb, f);
    auto token6 = Dht::listenTo(id, AF_INET6, gcb, f);

    DHT_WARN("Added listen : %d -> %d %d %d", token, tokenlocal, token4, token6);
    listeners.emplace(token, std::make_tuple(tokenlocal, token4, token6));
    return token;
}

bool
Dht::cancelListen(const InfoHash& id, size_t token)
{
    now = clock::now();

    auto it = listeners.find(token);
    if (it == listeners.end()) {
        DHT_WARN("Listen token not found: %d", token);
        return false;
    }
    DHT_WARN("cancelListen %s with token %d", id.toString().c_str(), token);
    Storage* st = findStorage(id);
    auto tokenlocal = std::get<0>(it->second);
    if (st && tokenlocal)
        st->local_listeners.erase(tokenlocal);
    for (auto& s : searches) {
        if (s.id != id) continue;
        auto af_token = s.af == AF_INET ? std::get<1>(it->second) : std::get<2>(it->second);
        if (af_token == 0)
            continue;
        s.listeners.erase(af_token);
    }
    listeners.erase(it);
    return true;
}

void
Dht::put(const InfoHash& id, std::shared_ptr<Value> val, DoneCallback callback)
{
    now = clock::now();

    if (val->id == Value::INVALID_ID) {
        crypto::random_device rdev;
        std::uniform_int_distribution<Value::Id> rand_id {};
        val->id = rand_id(rdev);
    }

    DHT_DEBUG("put: adding %s -> %s", id.toString().c_str(), val->toString().c_str());

    auto ok = std::make_shared<bool>(false);
    auto done = std::make_shared<bool>(false);
    auto done4 = std::make_shared<bool>(false);
    auto done6 = std::make_shared<bool>(false);
    auto donecb = [=](const std::vector<std::shared_ptr<Node>>& nodes) {
        // Callback as soon as the value is announced on one of the available networks
        if (callback && !*done && (*ok || (*done4 && *done6))) {
            callback(*ok, nodes);
            *done = true;
        }
    };
    announce(id, AF_INET, val, [=](bool ok4, const std::vector<std::shared_ptr<Node>>& nodes) {
        DHT_DEBUG("Announce done IPv4 %d", ok4);
        *done4 = true;
        *ok |= ok4;
        donecb(nodes);
    });
    announce(id, AF_INET6, val, [=](bool ok6, const std::vector<std::shared_ptr<Node>>& nodes) {
        DHT_DEBUG("Announce done IPv6 %d", ok6);
        *done6 = true;
        *ok |= ok6;
        donecb(nodes);
    });
}

struct OpStatus {
    bool done {false};
    bool ok {false};
};

void
Dht::get(const InfoHash& id, GetCallback getcb, DoneCallback donecb, Value::Filter filter)
{
    now = clock::now();

    auto status = std::make_shared<OpStatus>();
    auto status4 = std::make_shared<OpStatus>();
    auto status6 = std::make_shared<OpStatus>();
    auto vals = std::make_shared<std::vector<std::shared_ptr<Value>>>();
    auto all_nodes = std::make_shared<std::vector<std::shared_ptr<Node>>>();

    auto done_l = [=](const std::vector<std::shared_ptr<Node>>& nodes) {
        if (status->done)
            return;
        all_nodes->insert(all_nodes->end(), nodes.begin(), nodes.end());
        if (status->ok || (status4->done && status6->done)) {
            bool ok = status->ok || status4->ok || status6->ok;
            status->done = true;
            if (donecb)
                donecb(ok, *all_nodes);
        }
    };
    auto cb = [=](const std::vector<std::shared_ptr<Value>>& values) {
        if (status->done)
            return false;
        std::vector<std::shared_ptr<Value>> newvals {};
        for (const auto& v : values) {
            auto it = std::find_if(vals->cbegin(), vals->cend(), [&](const std::shared_ptr<Value>& sv) {
                return sv == v || *sv == *v;
            });
            if (it == vals->cend()) {
                if (!filter || filter(*v))
                    newvals.push_back(v);
            }
        }
        if (!newvals.empty()) {
            status->ok = !getcb(newvals);
            vals->insert(vals->end(), newvals.begin(), newvals.end());
        }
        done_l({});
        return !status->ok;
    };

    /* Try to answer this search locally. */
    cb(getLocal(id, filter));

    Dht::search(id, AF_INET, cb, [=](bool ok, const std::vector<std::shared_ptr<Node>>& nodes) {
        //DHT_WARN("DHT done IPv4");
        status4->done = true;
        status4->ok = ok;
        done_l(nodes);
    });
    Dht::search(id, AF_INET6, cb, [=](bool ok, const std::vector<std::shared_ptr<Node>>& nodes) {
        //DHT_WARN("DHT done IPv6");
        status6->done = true;
        status6->ok = ok;
        done_l(nodes);
    });
}

std::vector<std::shared_ptr<Value>>
Dht::getLocal(const InfoHash& id, Value::Filter f) const
{
    auto s = findStorage(id);
    if (!s) return {};
    std::vector<std::shared_ptr<Value>> vals;
    vals.reserve(s->values.size());
    for (auto& v : s->values)
        if (!f || f(*v.data)) vals.push_back(v.data);
    return vals;
}

std::shared_ptr<Value>
Dht::getLocalById(const InfoHash& id, const Value::Id& vid) const
{
    if (auto s = findStorage(id)) {
        for (auto& v : s->values)
            if (v.data->id == vid) return v.data;
    }
    return {};
}

std::vector<std::shared_ptr<Value>>
Dht::getPut(const InfoHash& id)
{
    std::vector<std::shared_ptr<Value>> ret;
    for (const auto& search: searches) {
        if (search.id != id)
            continue;
        ret.reserve(ret.size() + search.announce.size());
        for (const auto& a : search.announce)
            ret.push_back(a.value);
    }
    return ret;
}

std::shared_ptr<Value>
Dht::getPut(const InfoHash& id, const Value::Id& vid)
{
    for (const auto& search : searches) {
        if (search.id != id)
            continue;
        for (const auto& a : search.announce) {
            if (a.value->id == vid)
                return a.value;
        }
    }
    return {};
}

bool
Dht::cancelPut(const InfoHash& id, const Value::Id& vid)
{
    bool canceled {false};
    for (auto& search: searches) {
        if (search.id != id)
            continue;
        for (auto it = search.announce.begin(); it != search.announce.end();) {
            if (it->value->id == vid) {
                canceled = true;
                it = search.announce.erase(it);
            }
            else
                ++it;
        }
    }
    return canceled;
}

/* A struct storage stores all the stored peer addresses for a given info
   hash. */

Dht::Storage*
Dht::findStorage(const InfoHash& id)
{
    for (auto& st : store)
        if (st.id == id)
            return &st;
    return nullptr;
}

void
Dht::storageChanged(Storage& st, ValueStorage& v)
{
    {
        std::vector<std::pair<GetCallback, std::vector<std::shared_ptr<Value>>>> cbs;
        for (const auto& l : st.local_listeners) {
            std::vector<std::shared_ptr<Value>> vals;
            if (not l.second.filter or l.second.filter(*v.data))
                vals.push_back(v.data);
            if (not vals.empty())
                cbs.emplace_back(l.second.get_cb, std::move(vals));
        }
        // listeners are copied: they may be deleted by the callback
        for (auto& cb : cbs)
            cb.first(cb.second);
    }

    for (const auto& l : st.listeners) {
        DHT_WARN("Storage changed. Sending update to %s %s.", l.id.toString().c_str(), print_addr((sockaddr*)&l.ss, l.sslen).c_str());
        std::vector<ValueStorage> vals;
        vals.push_back(v);
        Blob ntoken = makeToken((const sockaddr*)&l.ss, false);
        sendClosestNodes((const sockaddr*)&l.ss, l.sslen, TransId {TransPrefix::GET_VALUES, l.tid}, st.id, WANT4 | WANT6, ntoken, vals);
    }
}

Dht::ValueStorage*
Dht::storageStore(const InfoHash& id, const std::shared_ptr<Value>& value)
{
    Storage *st = findStorage(id);
    if (!st) {
        if (store.size() >= MAX_HASHES)
            return nullptr;
        store.push_back(Storage {id});
        st = &store.back();
    }

    auto it = std::find_if (st->values.begin(), st->values.end(), [&](const ValueStorage& vr) {
        return vr.data == value || vr.data->id == value->id;
    });
    if (it != st->values.end()) {
        /* Already there, only need to refresh */
        it->time = now;
        if (it->data != value) {
            DHT_DEBUG("Updating %s -> %s", id.toString().c_str(), value->toString().c_str());
            it->data = value;
            storageChanged(*st, *it);
        }
        return &*it;
    } else {
        DHT_DEBUG("Storing %s -> %s", id.toString().c_str(), value->toString().c_str());
        if (st->values.size() >= MAX_VALUES)
            return nullptr;
        st->values.emplace_back(value, now);
        storageChanged(*st, st->values.back());
        return &st->values.back();
    }
}

void
Dht::storageAddListener(const InfoHash& id, const InfoHash& node, const sockaddr *from, socklen_t fromlen, uint16_t tid)
{
    Storage *st = findStorage(id);
    if (!st) {
        if (store.size() >= MAX_HASHES)
            return;
        store.push_back(Storage {id});
        st = &store.back();
    }
    sa_family_t af = from->sa_family;
    auto l = std::find_if(st->listeners.begin(), st->listeners.end(), [&](const Listener& l){
        return l.ss.ss_family == af && l.id == node;
    });
    if (l == st->listeners.end()) {
        sendClosestNodes(from, fromlen, TransId {TransPrefix::GET_VALUES, tid}, st->id, WANT4 | WANT6, makeToken(from, false), st->values);
        st->listeners.emplace_back(node, from, fromlen, tid, now);
    }
    else
        l->refresh(from, fromlen, tid, now);
}

void
Dht::expireStorage()
{
    auto i = store.begin();
    while (i != store.end())
    {
        // put elements to remove at the end with std::partition,
        // and then remove them with std::vector::erase.
        i->listeners.erase(
            std::partition(i->listeners.begin(), i->listeners.end(),
                [&](const Listener& l)
                {
                    bool expired = l.time + Node::NODE_EXPIRE_TIME < now;
                    if (expired)
                        DHT_DEBUG("Discarding expired listener %s", l.id.toString().c_str());
                    // return false if the element should be removed
                    return !expired;
                }),
            i->listeners.end());

        i->values.erase(
            std::partition(i->values.begin(), i->values.end(),
                [&](const ValueStorage& v)
                {
                    if (!v.data) return false; // should not happen
                    const auto& type = getType(v.data->type);
                    bool expired = v.time + type.expiration < now;
                    if (expired)
                        DHT_DEBUG("Discarding expired value %s", v.data->toString().c_str());
                    return !expired;
                }),
            i->values.end());

        if (i->values.empty() && i->listeners.empty()) {
            DHT_DEBUG("Discarding expired value %s", i->id.toString().c_str());
            i = store.erase(i);
        }
        else
            ++i;
    }
}

void
Dht::connectivityChanged()
{
    confirm_nodes_time = now;
    mybucket_grow_time = now;
    mybucket6_grow_time = now;
    reported_addr.clear();
    for (auto& s : searches)
        for (auto& sn : s.nodes)
            sn.listenStatus = {};
}

void
Dht::rotateSecrets()
{
    uniform_duration_distribution<> time_dist(std::chrono::minutes(15), std::chrono::minutes(45));
    rotate_secrets_time = now + time_dist(rd);

    oldsecret = secret;
    {
        crypto::random_device rdev;
        std::generate_n(secret.begin(), secret.size(), std::bind(rand_byte, std::ref(rdev)));
    }
}

Blob
Dht::makeToken(const sockaddr *sa, bool old) const
{
    void *ip;
    size_t iplen;
    in_port_t port;

    if (sa->sa_family == AF_INET) {
        sockaddr_in *sin = (sockaddr_in*)sa;
        ip = &sin->sin_addr;
        iplen = 4;
        port = htons(sin->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        sockaddr_in6 *sin6 = (sockaddr_in6*)sa;
        ip = &sin6->sin6_addr;
        iplen = 16;
        port = htons(sin6->sin6_port);
    } else {
        return {};
    }

    const auto& c1 = old ? oldsecret : secret;
    Blob data;
    data.reserve(sizeof(secret)+2+iplen);
    data.insert(data.end(), c1.begin(), c1.end());
    data.insert(data.end(), (uint8_t*)ip, (uint8_t*)ip+iplen);
    data.insert(data.end(), (uint8_t*)&port, ((uint8_t*)&port)+2);

    size_t sz = TOKEN_SIZE;
    Blob ret {};
    ret.resize(sz);
    gnutls_datum_t gnudata = {data.data(), (unsigned int)data.size()};
    if (gnutls_fingerprint(GNUTLS_DIG_SHA512, &gnudata, ret.data(), &sz) != GNUTLS_E_SUCCESS)
        throw DhtException("Can't compute SHA512");
    ret.resize(sz);
    return ret;
}

bool
Dht::tokenMatch(const Blob& token, const sockaddr *sa) const
{
    if (!sa || token.size() != TOKEN_SIZE)
        return false;
    if (token == makeToken(sa, false))
        return true;
    if (token == makeToken(sa, true))
        return true;
    return false;
}

int
Dht::getNodesStats(sa_family_t af, unsigned *good_return, unsigned *dubious_return, unsigned *cached_return, unsigned *incoming_return) const
{
    unsigned good = 0, dubious = 0, cached = 0, incoming = 0;
    auto& list = (af == AF_INET) ? buckets : buckets6;

    for (const auto& b : list) {
        for (auto& n : b.nodes) {
            if (n->isGood(now)) {
                good++;
                if (n->time > n->reply_time)
                    incoming++;
            } else {
                dubious++;
            }
        }
        if (b.cached.ss_family > 0)
            cached++;
    }
    if (good_return)
        *good_return = good;
    if (dubious_return)
        *dubious_return = dubious;
    if (cached_return)
        *cached_return = cached;
    if (incoming_return)
        *incoming_return = incoming;
    return good + dubious;
}

void
Dht::dumpBucket(const Bucket& b, std::ostream& out) const
{
    using namespace std::chrono;
    out << b.first << " count " << b.nodes.size() << " age " << duration_cast<seconds>(now - b.time).count() << " sec";
    if (b.cached.ss_family)
        out << " (cached)";
    out  << std::endl;
    for (auto& n : b.nodes) {
        out << "    Node " << n->id << " " << print_addr((sockaddr*)&n->ss, n->sslen);
        if (n->time != n->reply_time)
            out << " age " << duration_cast<seconds>(now - n->time).count() << ", reply: " << duration_cast<seconds>(now - n->reply_time).count();
        else
            out << " age " << duration_cast<seconds>(now - n->time).count();
        if (n->pinged)
            out << " [p " << n->pinged << "]";
        if (n->isExpired(now))
            out << " [expired]";
        else if (n->isGood(now))
            out << " [good]";
        out << std::endl;
    }
}

void
Dht::dumpSearch(const Search& sr, std::ostream& out) const
{
    using namespace std::chrono;
    out << std::endl << "Search IPv" << (sr.af == AF_INET6 ? '6' : '4') << ' ' << sr.id << " G" << sr.callbacks.size();
    out << " age " << duration_cast<seconds>(now - sr.step_time).count() << " s tid " << sr.tid;
    if (sr.done)
        out << " [done]";
    bool synced = sr.isSynced(now);
    out << (synced ? " [synced]" : " [not synced]");
    if (synced && sr.isListening(now)) {
        auto lt = sr.getListenTime(now);
        out << " [listening, next in " << duration_cast<minutes>(lt-now).count() << " min]";
    }
    out << std::endl;

    for (const auto& n : sr.announce) {
        bool announced = sr.isAnnounced(n.value->id, getType(n.value->type), now);
        out << "Announcement: " << *n.value << (announced ? " [announced]" : "") << std::endl;
    }

    out << " Common bits    InfoHash                          Conn. Get   Put IP" << std::endl;
    unsigned i = 0;
    auto last_get = sr.getLastGetTime();
    for (const auto& n : sr.nodes) {
        i++;
        out << std::setfill (' ') << std::setw(3) << InfoHash::commonBits(sr.id, n.node->id) << ' ' << n.node->id;
        out << ' ' << (findNode(n.node->id, AF_INET) || findNode(n.node->id, AF_INET6) ? '*' : ' ');
        out << ' ' << (n.candidate ? 'c' : ' ');
        out << " ["
            << (n.node->isMessagePending(now) ? 'f':' ');
        if (n.node->pinged)
            out << n.node->pinged;
        else
            out << ' ';
        out << (n.node->isExpired(now) ? 'x' : ' ') << "]";

        out << " ["
            << (n.getStatus.pending(now) ? 'f' : (n.getStatus.expired(now) ? 'x' : ' '))
            << (n.isSynced(now) ? 's' : '-')
            << ((n.getStatus.reply_time > last_get) ? 'u' : '-') << "] ";

        if (not sr.listeners.empty()) {
            if (n.listenStatus.request_time == time_point::min())
                out << "     ";
            else
                out << "["
                    << (n.listenStatus.pending(now) ? 'f' : (n.listenStatus.expired(now) ? 'x' : ' '))
                    << (n.isListening(now) ? 'l' : '-') << "] ";
        }

        if (not sr.announce.empty()) {
            if (n.acked.empty()) {
                out << "   ";
                for (size_t a=0; a < sr.announce.size(); a++)
                    out << ' ';
            } else {
                out << "[";
                for (const auto& a : sr.announce) {
                    auto ack = n.acked.find(a.value->id);
                    if (ack == n.acked.end()) {
                        out << ' ';
                    } else {
                        auto& astatus = ack->second;
                        if (astatus.reply_time + getType(a.value->type).expiration > now)
                            out << 'a';
                        else if (astatus.pending(now))
                            out << 'f';
                        else if (astatus.expired(now))
                            out << 'x';
                        else
                            out << ' ';
                    }
                }
                out << "] ";
            }
        }
        out << print_addr(n.node->ss, n.node->sslen);
        out << std::endl;
    }
}

void
Dht::dumpTables() const
{
    std::stringstream out;
    out << "My id " << myid << std::endl;

    out << "Buckets IPv4 :" << std::endl;
    for (const auto& b : buckets)
        dumpBucket(b, out);
    out << "Buckets IPv6 :" << std::endl;
    for (const auto& b : buckets6)
        dumpBucket(b, out);

    for (const auto& sr : searches)
        dumpSearch(sr, out);
    out << std::endl;

    out << getStorageLog() << std::endl;

    DHT_DEBUG("%s", out.str().c_str());
}

std::string
Dht::getStorageLog() const
{
    using namespace std::chrono;
    std::stringstream out;
    for (const auto& st : store) {
        out << "Storage " << st.id << " " << st.listeners.size() << " list., " << st.values.size() << " values:" << std::endl;
        for (const auto& l : st.listeners) {
            out << "   " << "Listener " << l.id << " " << print_addr((sockaddr*)&l.ss, l.sslen);
            auto since = duration_cast<seconds>(now - l.time);
            auto expires = duration_cast<seconds>(l.time + Node::NODE_EXPIRE_TIME - now);
            out << " (since " << since.count() << "s, exp in " << expires.count() << "s)" << std::endl;
        }
        for (const auto& v : st.values) {
            const auto& type = getType(v.data->type);
            auto since = duration_cast<seconds>(now - v.time);
            auto expires = duration_cast<seconds>(v.time + type.expiration - now);
            out << "   " << *v.data << " (since " << since.count() << "s, exp in " << expires.count() << "s)" << std::endl;
        }
    }
    return out.str();
}


std::string
Dht::getRoutingTablesLog(sa_family_t af) const
{
    auto& list = (af == AF_INET) ? buckets : buckets6;
    std::stringstream out;
    for (const auto& b : list)
        dumpBucket(b, out);
    return out.str();
}

std::string
Dht::getSearchesLog(sa_family_t af) const
{
    std::stringstream out;
    out << "s:synched, u:updated, a:announced, c:candidate, f:cur req, x:expired, *:known" << std::endl;
    for (const auto& sr : searches)
        if (af == 0 or sr.af == af)
            dumpSearch(sr, out);
    return out.str();
}

Dht::Dht(int s, int s6, Config config)
 : dht_socket(s), dht_socket6(s6), myid(config.node_id), is_bootstrap(config.is_bootstrap),
   now(clock::now()), mybucket_grow_time(now), mybucket6_grow_time(now)
{
    if (s < 0 && s6 < 0)
        return;

    if (s >= 0) {
        buckets = {Bucket {AF_INET}};
        if (!set_nonblocking(s, 1))
            throw DhtException("Can't set socket to non-blocking mode");
    }

    if (s6 >= 0) {
        buckets6 = {Bucket {AF_INET6}};
        if (!set_nonblocking(s6, 1))
            throw DhtException("Can't set socket to non-blocking mode");
    }

    search_id = std::uniform_int_distribution<decltype(search_id)>{}(rd);

    uniform_duration_distribution<> time_dis {std::chrono::seconds(0), std::chrono::seconds(3)};
    confirm_nodes_time = now + time_dis(rd);

    // Fill old secret
    {
        crypto::random_device rdev;
        std::generate_n(secret.begin(), secret.size(), std::bind(rand_byte, std::ref(rdev)));
    }
    rotateSecrets();

    expireBuckets(buckets);
    expireBuckets(buckets6);

    DHT_DEBUG("DHT initialised with node ID %s", myid.toString().c_str());
}


Dht::~Dht()
{}

/* Rate control for requests we receive. */
bool
Dht::rateLimit()
{
    using namespace std::chrono;
    while (not rate_limit_time.empty() and duration_cast<seconds>(now - rate_limit_time.front()) > seconds(1))
        rate_limit_time.pop();

    if (rate_limit_time.size() >= MAX_REQUESTS_PER_SEC)
        return false;

    rate_limit_time.emplace(now);
    return true;
}

bool
Dht::neighbourhoodMaintenance(RoutingTable& list)
{
    //DHT_DEBUG("neighbourhoodMaintenance");
    auto b = list.findBucket(myid);
    if (b == list.end())
        return false;

    InfoHash id = myid;
    id[HASH_LEN-1] = rand_byte(rd);

    std::bernoulli_distribution rand_trial(1./8.);
    auto q = b;
    if (std::next(q) != list.end() && (q->nodes.empty() || rand_trial(rd)))
        q = std::next(q);
    if (b != list.begin() && (q->nodes.empty() || rand_trial(rd))) {
        auto r = std::prev(b);
        if (!r->nodes.empty())
            q = r;
    }

    /* Since our node-id is the same in both DHTs, it's probably
       profitable to query both families. */
    want_t want = dht_socket >= 0 && dht_socket6 >= 0 ? (WANT4 | WANT6) : -1;
    auto n = q->randomNode();
    if (n) {
        DHT_DEBUG("[find %s IPv%c] sending find for neighborhood maintenance.", id.toString().c_str(), q->af == AF_INET6 ? '6' : '4');
        sendFindNode((sockaddr*)&n->ss, n->sslen,
                       TransId {TransPrefix::FIND_NODE}, id, want,
                       n->reply_time >= now - UDP_REPLY_TIME);
        pinged(*n, &(*q));
    }

    return true;
}

bool
Dht::bucketMaintenance(RoutingTable& list)
{
    std::bernoulli_distribution rand_trial(1./8.);
    std::bernoulli_distribution rand_trial_38(1./38.);

    for (auto b = list.begin(); b != list.end(); ++b) {
        if (b->time < now - std::chrono::minutes(10) || b->nodes.empty()) {
            /* This bucket hasn't seen any positive confirmation for a long
               time.  Pick a random id in this bucket's range, and send
               a request to a random node. */
            InfoHash id = list.randomId(b);
            auto q = b;
            /* If the bucket is empty, we try to fill it from a neighbour.
               We also sometimes do it gratuitiously to recover from
               buckets full of broken nodes. */
            if (std::next(b) != list.end() && (q->nodes.empty() || rand_trial(rd)))
                q = std::next(b);
            if (b != list.begin() && (q->nodes.empty() || rand_trial(rd))) {
                auto r = std::prev(b);
                if (!r->nodes.empty())
                    q = r;
            }

            auto n = q->randomNode();
            if (n) {
                want_t want = -1;

                if (dht_socket >= 0 && dht_socket6 >= 0) {
                    auto otherbucket = findBucket(id, q->af == AF_INET ? AF_INET6 : AF_INET);
                    if (otherbucket && otherbucket->nodes.size() < TARGET_NODES)
                        /* The corresponding bucket in the other family
                           is emptyish -- querying both is useful. */
                        want = WANT4 | WANT6;
                    else if (rand_trial_38(rd))
                        /* Most of the time, this just adds overhead.
                           However, it might help stitch back one of
                           the DHTs after a network collapse, so query
                           both, but only very occasionally. */
                        want = WANT4 | WANT6;
                }

                DHT_DEBUG("[find %s IPv%c] sending for bucket maintenance.", id.toString().c_str(), q->af == AF_INET6 ? '6' : '4');
                sendFindNode((sockaddr*)&n->ss, n->sslen,
                               TransId {TransPrefix::FIND_NODE}, id, want,
                               n->reply_time >= now - UDP_REPLY_TIME);
                pinged(*n, &(*q));
                /* In order to avoid sending queries back-to-back,
                   give up for now and reschedule us soon. */
                return true;
            }
        }
    }
    return false;
}

void
Dht::processMessage(const uint8_t *buf, size_t buflen, const sockaddr *from, socklen_t fromlen)
{
    if (buflen == 0)
        return;

    if (isMartian(from, fromlen))
        return;

    if (isNodeBlacklisted(from, fromlen)) {
        DHT_DEBUG("Received packet from blacklisted node.");
        return;
    }

    //DHT_DEBUG("processMessage %p %lu %p %lu", buf, buflen, from, fromlen);

    ParsedMessage msg;
    try {
        msgpack::unpacked msg_res = msgpack::unpack((const char*)buf, buflen);
        msg.msgpack_unpack(msg_res.get());
        if (msg.type != MessageType::Error && msg.id == zeroes)
            throw DhtException("no or invalid InfoHash");
    } catch (const std::exception& e) {
        DHT_WARN("Can't process message of size %lu: %s.", buflen, e.what());
        DHT_DEBUG.logPrintable(buf, buflen);
        return;
    }

    if (msg.id == myid) {
        DHT_DEBUG("Received message from self.");
        return;
    }

    if (msg.type > MessageType::Reply) {
        /* Rate limit requests. */
        if (!rateLimit()) {
            DHT_WARN("Dropping request due to rate limiting.");
            return;
        }
    }

    //std::cout << "Message from " << id << " IPv" << (from->sa_family==AF_INET?'4':'6') << std::endl;
    uint16_t ttid = 0;

    switch (msg.type) {
    case MessageType::Error:
        if (msg.tid.length != 4) return;
        if (msg.error_code == 401 && msg.id != zeroes && (msg.tid.matches(TransPrefix::ANNOUNCE_VALUES, &ttid) || msg.tid.matches(TransPrefix::LISTEN, &ttid))) {
            auto esr = findSearch(ttid, from->sa_family);
            if (!esr) return;
            auto ne = newNode(msg.id, from, fromlen, 2);
            unsigned cleared = 0;
            for (auto& sr : searches) {
                for (auto& n : sr.nodes) {
                    if (n.node != ne) continue;
                    cleared++;
                    n.getStatus.request_time = TIME_INVALID;
                    n.getStatus.reply_time = TIME_INVALID;
                    if (searchSendGetValues(sr))
                        sr.get_step_time = now;
                    break;
                }
            }
            DHT_WARN("[node %s %s] token flush (%d searches affected)", msg.id.toString().c_str(), print_addr(from, fromlen).c_str(), cleared);
        } else {
            DHT_WARN("[node %s %s] received unknown error message %u", msg.id.toString().c_str(), print_addr(from, fromlen).c_str(), msg.error_code);
            DHT_WARN.logPrintable(buf, buflen);
        }
        break;
    case MessageType::Reply:
        if (msg.tid.length != 4) {
            DHT_ERROR("Broken node truncates transaction ids (len: %d): ", msg.tid.length);
            DHT_ERROR.logPrintable(buf, buflen);
            /* This is really annoying, as it means that we will
               time-out all our searches that go through this node.
               Kill it. */
            blacklistNode(&msg.id, from, fromlen);
            return;
        }
        if (msg.tid.matches(TransPrefix::PING)) {
            DHT_DEBUG("[node %s %s] Pong!", msg.id.toString().c_str(), print_addr(from, fromlen).c_str());
            newNode(msg.id, from, fromlen, 2, (sockaddr*)&msg.addr.first, msg.addr.second);
        } else if (msg.tid.matches(TransPrefix::FIND_NODE) or msg.tid.matches(TransPrefix::GET_VALUES)) {
            bool gp = false;
            Search *sr = nullptr;
            std::shared_ptr<Node> n;
            if (msg.tid.matches(TransPrefix::GET_VALUES, &ttid)) {
                gp = true;
                sr = findSearch(ttid, from->sa_family);
            }
            if (msg.nodes4.size() % 26 != 0 || msg.nodes6.size() % 38 != 0) {
                DHT_WARN("Unexpected length for node info!");
                blacklistNode(&msg.id, from, fromlen);
                break;
            } else if (gp && sr == nullptr) {
                DHT_WARN("Unknown search with tid %u !", ttid);
                n = newNode(msg.id, from, fromlen, 1);
            } else {
                n = newNode(msg.id, from, fromlen, 2, (sockaddr*)&msg.addr.first, msg.addr.second);
                for (unsigned i = 0; i < msg.nodes4.size() / 26; i++) {
                    uint8_t *ni = msg.nodes4.data() + i * 26;
                    const InfoHash& ni_id = *reinterpret_cast<InfoHash*>(ni);
                    if (ni_id == myid)
                        continue;
                    sockaddr_in sin;
                    std::fill_n((uint8_t*)&sin, sizeof(sockaddr_in), 0);
                    sin.sin_family = AF_INET;
                    memcpy(&sin.sin_addr, ni + ni_id.size(), 4);
                    memcpy(&sin.sin_port, ni + ni_id.size() + 4, 2);
                    auto sn = newNode(ni_id, (sockaddr*)&sin, sizeof(sin), 0);
                    if (sn && sr && sr->af == AF_INET) {
                        sr->insertNode(sn, now);
                    }
                }
                for (unsigned i = 0; i < msg.nodes6.size() / 38; i++) {
                    uint8_t *ni = msg.nodes6.data() + i * 38;
                    InfoHash* ni_id = reinterpret_cast<InfoHash*>(ni);
                    if (*ni_id == myid)
                        continue;
                    sockaddr_in6 sin6;
                    std::fill_n((uint8_t*)&sin6, sizeof(sockaddr_in6), 0);
                    sin6.sin6_family = AF_INET6;
                    memcpy(&sin6.sin6_addr, ni + HASH_LEN, 16);
                    memcpy(&sin6.sin6_port, ni + HASH_LEN + 16, 2);
                    auto sn = newNode(*ni_id, (sockaddr*)&sin6, sizeof(sin6), 0);
                    if (sn && sr && sr->af == AF_INET6) {
                        sr->insertNode(sn, now);
                    }
                }
                if (sr) {
                    /* Since we received a reply, the number of
                       requests in flight has decreased.  Let's push
                       another request. */
                   DHT_DEBUG("[search %s IPv%c] found nodes: %u IPv4, %u IPv6",
                       sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6',
                       msg.nodes4.size()/26, msg.nodes6.size()/38);
                    //std::cout << "Received reply from " << id << ", sending new message..." << std::endl;
                    if (searchSendGetValues(*sr))
                        sr->get_step_time = now;
                }
            }
            if (sr) {
                sr->insertNode(n, now, msg.token);
                if (!msg.values.empty()) {
                    DHT_DEBUG("[search %s IPv%c] found %u values",
                        sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6',
                        msg.values.size());
                    for (auto& cb : sr->callbacks) {
                        if (!cb.get_cb) continue;
                        std::vector<std::shared_ptr<Value>> tmp;
                        std::copy_if(msg.values.begin(), msg.values.end(), std::back_inserter(tmp), [&](const std::shared_ptr<Value>& v) {
                            return not static_cast<bool>(cb.filter) or cb.filter(*v);
                        });
                        if (not tmp.empty())
                            cb.get_cb(tmp);
                    }
                    std::vector<std::pair<GetCallback, std::vector<std::shared_ptr<Value>>>> tmp_lists;
                    for (auto& l : sr->listeners) {
                        if (!l.second.get_cb) continue;
                        std::vector<std::shared_ptr<Value>> tmp;
                        std::copy_if(msg.values.begin(), msg.values.end(), std::back_inserter(tmp), [&](const std::shared_ptr<Value>& v) {
                            return not static_cast<bool>(l.second.filter) or l.second.filter(*v);
                        });
                        if (not tmp.empty())
                            tmp_lists.emplace_back(l.second.get_cb, tmp);
                    }
                    for (auto& l : tmp_lists)
                        l.first(l.second);
                }
                // Force to recompute the next step time
                if (sr->isSynced(now))
                    search_time = now;
            }
        } else if (msg.tid.matches(TransPrefix::ANNOUNCE_VALUES, &ttid)) {
            Search *sr = findSearch(ttid, from->sa_family);
            if (!sr || msg.value_id == Value::INVALID_ID) {
                DHT_DEBUG("Unknown search or announce!");
                newNode(msg.id, from, fromlen, 1);
            } else {
                DHT_DEBUG("[search %s IPv%c] got reply to put!",
                    sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6',
                    msg.values.size());

                auto n = newNode(msg.id, from, fromlen, 2, (sockaddr*)&msg.addr.first, msg.addr.second);
                for (auto& sn : sr->nodes)
                    if (sn.node == n) {
                        auto it = sn.acked.emplace(msg.value_id, SearchNode::RequestStatus{});
                        it.first->second.reply_time = now;
                        break;
                    }
                /* See comment for gp above. */
                if (searchSendGetValues(*sr))
                    sr->get_step_time = now;

                // If the value was just successfully announced, call the callback
                for (auto& a : sr->announce) {
                    if (!a.callback || !a.value || a.value->id != msg.value_id)
                        continue;
                    if (sr->isAnnounced(msg.value_id, getType(a.value->type), now)) {
                        a.callback(true, sr->getNodes());
                        a.callback = nullptr;
                    }
                }
            }
        } else if (msg.tid.matches(TransPrefix::LISTEN, &ttid)) {
            DHT_DEBUG("Got reply to listen.");
            Search *sr = findSearch(ttid, from->sa_family);
            if (!sr) {
                DHT_DEBUG("Unknown search or announce!");
                newNode(msg.id, from, fromlen, 1);
            } else {
                auto n = newNode(msg.id, from, fromlen, 2, (sockaddr*)&msg.addr.first, msg.addr.second);
                for (auto& sn : sr->nodes)
                    if (sn.node == n) {
                        sn.listenStatus.reply_time = now;
                        break;
                    }
                /* See comment for gp above. */
                if (searchSendGetValues(*sr))
                    sr->get_step_time = now;
            }
        } else {
            DHT_WARN("Unexpected reply: ");
            DHT_WARN.logPrintable(buf, buflen);
        }
        break;
    case MessageType::Ping:
        newNode(msg.id, from, fromlen, 1);
        //DHT_DEBUG("Sending pong.");
        sendPong(from, fromlen, msg.tid);
        break;
    case MessageType::FindNode:
        newNode(msg.id, from, fromlen, 1);
        DHT_DEBUG("[node %s %s] got 'find' request (%d).", msg.id.toString().c_str(), print_addr(from, fromlen).c_str(), msg.want);
        sendClosestNodes(from, fromlen, msg.tid, msg.target, msg.want);
        break;
    case MessageType::GetValues:
        DHT_DEBUG("[node %s %s] got 'get' request for %s.", msg.id.toString().c_str(), print_addr(from, fromlen).c_str(), msg.info_hash.toString().c_str());
        newNode(msg.id, from, fromlen, 1);
        if (msg.info_hash == zeroes) {
            DHT_WARN("[node %s %s] Eek! Got get_values with no info_hash.", msg.id.toString().c_str(), print_addr(from, fromlen).c_str());
            sendError(from, fromlen, msg.tid, 203, "Get_values with no info_hash");
            break;
        } else {
            Storage* st = findStorage(msg.info_hash);
            Blob ntoken = makeToken(from, false);
            if (st && st->values.size() > 0) {
                 DHT_DEBUG("[node %s %s] sending %u values.", msg.id.toString().c_str(), print_addr(from, fromlen).c_str(), st->values.size());
                 sendClosestNodes(from, fromlen, msg.tid, msg.info_hash, msg.want, ntoken, st->values);
            } else {
                DHT_DEBUG("[node %s %s] sending nodes.", msg.id.toString().c_str(), print_addr(from, fromlen).c_str());
                sendClosestNodes(from, fromlen, msg.tid, msg.info_hash, msg.want, ntoken);
            }
        }
        break;
    case MessageType::AnnounceValue:
        DHT_DEBUG("[node %s %s] got 'put' request for %s.",
            msg.id.toString().c_str(), print_addr(from, fromlen).c_str(),
            msg.info_hash.toString().c_str());
        newNode(msg.id, from, fromlen, 1);
        if (msg.info_hash == zeroes) {
            DHT_WARN("Put with no info_hash.");
            sendError(from, fromlen, msg.tid, 203, "Put with no info_hash");
            break;
        }
        if (!tokenMatch(msg.token, from)) {
            DHT_WARN("[node %s %s] incorrect token %s for 'put'.",
                msg.id.toString().c_str(), print_addr(from, fromlen).c_str(),
                msg.info_hash.toString().c_str(), to_hex(msg.token.data(), msg.token.size()).c_str());
            sendError(from, fromlen, msg.tid, 401, "Put with wrong token", true);
            break;
        }
        for (const auto& v : msg.values) {
            if (v->id == Value::INVALID_ID) {
                DHT_WARN("[node %s %s] incorrect value id",
                    msg.id.toString().c_str(), print_addr(from, fromlen).c_str(),
                    msg.info_hash.toString().c_str(), to_hex(msg.token.data(), msg.token.size()).c_str());

                DHT_WARN("Incorrect value id ");
                sendError(from, fromlen, msg.tid, 203, "Put with invalid id");
                continue;
            }
            auto lv = getLocalById(msg.info_hash, v->id);
            std::shared_ptr<Value> vc = v;
            if (lv) {
                const auto& type = getType(lv->type);
                if (type.editPolicy(msg.info_hash, lv, vc, msg.id, from, fromlen)) {
                    DHT_DEBUG("Editing value of type %s belonging to %s at %s.", type.name.c_str(), v->owner.getId().toString().c_str(), msg.info_hash.toString().c_str());
                    storageStore(msg.info_hash, vc);
                } else {
                    DHT_WARN("Rejecting edition of type %s belonging to %s at %s because of storage policy.", type.name.c_str(), v->owner.getId().toString().c_str(), msg.info_hash.toString().c_str());
                }
            } else {
                // Allow the value to be edited by the storage policy
                const auto& type = getType(vc->type);
                if (type.storePolicy(msg.info_hash, vc, msg.id, from, fromlen)) {
                    DHT_DEBUG("Storing value of type %s belonging to %s at %s.", type.name.c_str(), v->owner.getId().toString().c_str(), msg.info_hash.toString().c_str());
                    storageStore(msg.info_hash, vc);
                } else {
                    DHT_WARN("Rejecting storage of type %s belonging to %s at %s because of storage policy.", type.name.c_str(), v->owner.getId().toString().c_str(), msg.info_hash.toString().c_str());
                }
            }

            /* Note that if storageStore failed, we lie to the requestor.
               This is to prevent them from backtracking, and hence
               polluting the DHT. */
            sendValueAnnounced(from, fromlen, msg.tid, v->id);
        }
        break;
    case MessageType::Listen:
        DHT_DEBUG("[node %s %s] got 'listen' request for %s.", msg.id.toString().c_str(), print_addr(from, fromlen).c_str(), msg.info_hash.toString().c_str());
        if (msg.info_hash == zeroes) {
            DHT_WARN("Listen with no info_hash.");
            sendError(from, fromlen, msg.tid, 203, "Listen with no info_hash");
            break;
        }
        if (!tokenMatch(msg.token, from)) {
            DHT_WARN("[node %s %s] incorrect token %s for 'listen'.",
                msg.id.toString().c_str(), print_addr(from, fromlen).c_str(),
                msg.info_hash.toString().c_str(), to_hex(msg.token.data(), msg.token.size()).c_str());
            sendError(from, fromlen, msg.tid, 401, "Listen with wrong token", true);
            break;
        }
        if (!msg.tid.matches(TransPrefix::LISTEN, &ttid)) {
            break;
        }
        newNode(msg.id, from, fromlen, 1);
        storageAddListener(msg.info_hash, msg.id, from, fromlen, ttid);
        sendListenConfirmation(from, fromlen, msg.tid);
        break;
    }
}

time_point
Dht::periodic(const uint8_t *buf, size_t buflen,
             const sockaddr *from, socklen_t fromlen)
{
    using namespace std::chrono;
    now = clock::now();

    processMessage(buf, buflen, from, fromlen);

    if (now >= rotate_secrets_time)
        rotateSecrets();

    if (now >= expire_stuff_time) {
        expireBuckets(buckets);
        expireBuckets(buckets6);
        expireStorage();
        expireSearches();
    }

    if (now > search_time) {
        search_time = time_point::max();
        for (auto& sr : searches) {
            auto step = sr.getNextStepTime(types, now);
            if (step <= now) {
                searchStep(sr);
                step = sr.getNextStepTime(types, now);
            }
            search_time = std::min(search_time, step);
        }
        /*if (search_time == time_point::max())
            DHT_DEBUG("next search time : (none)");
        else
            DHT_DEBUG("next search time : %lf s%s", print_dt(search_time-now), (search_time < now)?" (ASAP)":"");*/
    }

    if (now >= confirm_nodes_time) {
        bool soon = false;

        if (searches.empty() and getStatus() != Status::Disconnected) {
            get(myid, GetCallbackSimple{});
        }

        soon |= bucketMaintenance(buckets);
        soon |= bucketMaintenance(buckets6);

        if (!soon) {
            if (mybucket_grow_time >= now - seconds(150))
                soon |= neighbourhoodMaintenance(buckets);
            if (mybucket6_grow_time >= now - seconds(150))
                soon |= neighbourhoodMaintenance(buckets6);
        }

        /* In order to maintain all buckets' age within 600 seconds, worst
           case is roughly 27 seconds, assuming the table is 22 bits deep.
           We want to keep a margin for neighborhood maintenance, so keep
           this within 25 seconds. */
        auto time_dis = soon ?
               uniform_duration_distribution<> {seconds(5) , seconds(25)}
             : uniform_duration_distribution<> {seconds(60), seconds(180)};
        confirm_nodes_time = now + time_dis(rd);
    }

    return std::min(confirm_nodes_time, search_time);
}

std::vector<Dht::ValuesExport>
Dht::exportValues() const
{
    std::vector<ValuesExport> e {};
    e.reserve(store.size());
    for (const auto& h : store) {
        ValuesExport ve;
        ve.first = h.id;

        msgpack::sbuffer buffer;
        msgpack::packer<msgpack::sbuffer> pk(&buffer);
        pk.pack_array(h.values.size());
        for (const auto& v : h.values) {
            pk.pack_array(2);
            pk.pack(v.time.time_since_epoch().count());
            v.data->msgpack_pack(pk);
        }
        ve.second = {buffer.data(), buffer.data()+buffer.size()};
        e.push_back(std::move(ve));
    }
    return e;
}

void
Dht::importValues(const std::vector<ValuesExport>& import)
{
    for (const auto& h : import) {
        if (h.second.empty())
            continue;

        try {
            msgpack::unpacked msg;
            msgpack::unpack(&msg, (const char*)h.second.data(), h.second.size());
            auto valarr = msg.get();
            if (valarr.type != msgpack::type::ARRAY)
                throw msgpack::type_error();
            for (unsigned i = 0; i < valarr.via.array.size; i++) {
                auto& valel = valarr.via.array.ptr[i];
                if (valel.via.array.size < 2)
                    throw msgpack::type_error();
                time_point val_time;
                Value tmp_val;
                try {
                    val_time = time_point{time_point::duration{valel.via.array.ptr[0].as<time_point::duration::rep>()}};
                    tmp_val.msgpack_unpack(valel.via.array.ptr[1]);
                } catch (const std::exception&) {
                    DHT_ERROR("Error reading value at %s", h.first.toString().c_str());
                    continue;
                }
                if (val_time + getType(tmp_val.type).expiration < now) {
                    DHT_DEBUG("Discarding expired value at %s", h.first.toString().c_str());
                    continue;
                }
                auto st = storageStore(h.first, std::make_shared<Value>(std::move(tmp_val)));
                st->time = val_time;
            }
        } catch (const std::exception&) {
            DHT_ERROR("Error reading values at %s", h.first.toString().c_str());
            continue;
        }
    }
}


std::vector<NodeExport>
Dht::exportNodes()
{
    std::vector<NodeExport> nodes;
    const auto b4 = buckets.findBucket(myid);
    if (b4 != buckets.end()) {
        for (auto& n : b4->nodes)
            if (n->isGood(now))
                nodes.push_back(n->exportNode());
    }
    const auto b6 = buckets6.findBucket(myid);
    if (b6 != buckets6.end()) {
        for (auto& n : b6->nodes)
            if (n->isGood(now))
                nodes.push_back(n->exportNode());
    }
    for (auto b = buckets.begin(); b != buckets.end(); ++b) {
        if (b == b4) continue;
        for (auto& n : b->nodes)
            if (n->isGood(now))
                nodes.push_back(n->exportNode());
    }
    for (auto b = buckets6.begin(); b != buckets6.end(); ++b) {
        if (b == b6) continue;
        for (auto& n : b->nodes)
            if (n->isGood(now))
                nodes.push_back(n->exportNode());
    }
    return nodes;
}

bool
Dht::insertNode(const InfoHash& id, const sockaddr *sa, socklen_t salen)
{
    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
        return false;
    now = clock::now();
    auto n = newNode(id, sa, salen, 0);
    return !!n;
}

int
Dht::pingNode(const sockaddr *sa, socklen_t salen)
{
    DHT_DEBUG("Sending ping to %s", print_addr(sa, salen).c_str());
    return sendPing(sa, salen, TransId {TransPrefix::PING});
}

void
insertAddr(msgpack::packer<msgpack::sbuffer>& pk, const sockaddr *sa, socklen_t)
{
    size_t addr_len = (sa->sa_family == AF_INET) ? sizeof(in_addr) : sizeof(in6_addr);
    void* addr_ptr = (sa->sa_family == AF_INET) ? (void*)&((sockaddr_in*)sa)->sin_addr
                                                : (void*)&((sockaddr_in6*)sa)->sin6_addr;
    pk.pack("sa");
    pk.pack_bin(addr_len);
    pk.pack_bin_body((char*)addr_ptr, addr_len);
}

int
Dht::send(const char *buf, size_t len, int flags, const sockaddr *sa, socklen_t salen)
{
    if (salen == 0)
        return -1;

    if (isNodeBlacklisted(sa, salen)) {
        DHT_DEBUG("Attempting to send to blacklisted node.");
        return -1;
    }

    int s;
    if (sa->sa_family == AF_INET)
        s = dht_socket;
    else if (sa->sa_family == AF_INET6)
        s = dht_socket6;
    else
        s = -1;

    if (s < 0)
        return -1;
    return sendto(s, buf, len, flags, sa, salen);
}

int
Dht::sendPing(const sockaddr *sa, socklen_t salen, TransId tid)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5);

    pk.pack(std::string("a")); pk.pack_map(1);
      pk.pack(std::string("id")); pk.pack(myid);

    pk.pack(std::string("q")); pk.pack(std::string("ping"));
    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("q"));
    pk.pack(std::string("v")); pk.pack(my_v);

    out.ping++;

    return send(buffer.data(), buffer.size(), 0, sa, salen);
}

int
Dht::sendPong(const sockaddr *sa, socklen_t salen, TransId tid)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4);

    pk.pack(std::string("r")); pk.pack_map(2);
      pk.pack(std::string("id")); pk.pack(myid);
      insertAddr(pk, sa, salen);

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);

    return send(buffer.data(), buffer.size(), 0, sa, salen);
}

int
Dht::sendFindNode(const sockaddr *sa, socklen_t salen, TransId tid,
               const InfoHash& target, want_t want, int confirm)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5);

    pk.pack(std::string("a")); pk.pack_map(2 + (want>0?1:0));
      pk.pack(std::string("id"));     pk.pack(myid);
      pk.pack(std::string("target")); pk.pack(target);
    if (want > 0) {
      pk.pack(std::string("w"));
      pk.pack_array(((want & WANT4)?1:0) + ((want & WANT6)?1:0));
      if (want & WANT4) pk.pack(AF_INET);
      if (want & WANT6) pk.pack(AF_INET6);
    }

    pk.pack(std::string("q")); pk.pack(std::string("find"));
    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("q"));
    pk.pack(std::string("v")); pk.pack(my_v);

    out.find++;

    return send(buffer.data(), buffer.size(), confirm ? 0 : MSG_CONFIRM, sa, salen);
}

int
Dht::sendNodesValues(const sockaddr *sa, socklen_t salen, TransId tid,
                 const uint8_t *nodes, unsigned nodes_len,
                 const uint8_t *nodes6, unsigned nodes6_len,
                 const std::vector<ValueStorage>& st, const Blob& token)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4);

    pk.pack(std::string("r"));
    pk.pack_map(2 + (not st.empty()?1:0) + (nodes_len>0?1:0) + (nodes6_len>0?1:0) + (not token.empty()?1:0));
    pk.pack(std::string("id")); pk.pack(myid);
    insertAddr(pk, sa, salen);
    if (nodes_len > 0) {
        pk.pack(std::string("n4"));
        pk.pack_bin(nodes_len);
        pk.pack_bin_body((const char*)nodes, nodes_len);
    }
    if (nodes6_len > 0) {
        pk.pack(std::string("n6"));
        pk.pack_bin(nodes6_len);
        pk.pack_bin_body((const char*)nodes6, nodes6_len);
    }
    if (not token.empty()) {
        pk.pack(std::string("token")); pk.pack(token);
    }
    if (not st.empty()) {
        // We treat the storage as a circular list, and serve a randomly
        // chosen slice.  In order to make sure we fit,
        // we limit ourselves to 50 values.
        std::uniform_int_distribution<> pos_dis(0, st.size()-1);
        unsigned j0 = pos_dis(rd);
        unsigned j = j0;
        unsigned k = 0;

        pk.pack(std::string("values"));
        pk.pack_array(std::min<size_t>(st.size(), 50));
        do {
            pk.pack(*st[j].data);
            k++;
            j = (j + 1) % st.size();
        } while (j != j0 && k < 50);
    }

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);

    return send(buffer.data(), buffer.size(), 0, sa, salen);
}

unsigned
Dht::insertClosestNode(uint8_t *nodes, unsigned numnodes, const InfoHash& id, const Node& n)
{
    unsigned i, size;

    if (n.ss.ss_family == AF_INET)
        size = HASH_LEN + sizeof(in_addr) + sizeof(in_port_t); // 26
    else if (n.ss.ss_family == AF_INET6)
        size = HASH_LEN + sizeof(in6_addr) + sizeof(in_port_t); // 38
    else
        return numnodes;

    for (i = 0; i < numnodes; i++) {
        const InfoHash* nid = reinterpret_cast<const InfoHash*>(nodes + size * i);
        if (InfoHash::cmp(n.id, *nid) == 0)
            return numnodes;
        if (id.xorCmp(n.id, *nid) < 0)
            break;
    }

    if (i >= TARGET_NODES)
        return numnodes;

    if (numnodes < TARGET_NODES)
        numnodes++;

    if (i < numnodes - 1)
        memmove(nodes + size * (i + 1), nodes + size * i, size * (numnodes - i - 1));

    if (n.ss.ss_family == AF_INET) {
        sockaddr_in *sin = (sockaddr_in*)&n.ss;
        memcpy(nodes + size * i, n.id.data(), HASH_LEN);
        memcpy(nodes + size * i + HASH_LEN, &sin->sin_addr, sizeof(in_addr));
        memcpy(nodes + size * i + HASH_LEN + sizeof(in_addr), &sin->sin_port, 2);
    }
    else if (n.ss.ss_family == AF_INET6) {
        sockaddr_in6 *sin6 = (sockaddr_in6*)&n.ss;
        memcpy(nodes + size * i, n.id.data(), HASH_LEN);
        memcpy(nodes + size * i + HASH_LEN, &sin6->sin6_addr, sizeof(in6_addr));
        memcpy(nodes + size * i + HASH_LEN + sizeof(in6_addr), &sin6->sin6_port, 2);
    }

    return numnodes;
}

unsigned
Dht::bufferClosestNodes(uint8_t* nodes, unsigned numnodes, const InfoHash& id, const Bucket& b) const
{
    for (const auto& n : b.nodes) {
        if (n->isGood(now))
            numnodes = insertClosestNode(nodes, numnodes, id, *n);
    }
    return numnodes;
}

int
Dht::sendClosestNodes(const sockaddr *sa, socklen_t salen, TransId tid,
                    const InfoHash& id, want_t want, const Blob& token, const std::vector<ValueStorage>& st)
{
    uint8_t nodes[8 * 26];
    uint8_t nodes6[8 * 38];
    unsigned numnodes = 0, numnodes6 = 0;

    if (want < 0)
        want = sa->sa_family == AF_INET ? WANT4 : WANT6;

    if ((want & WANT4)) {
        auto b = buckets.findBucket(id);
        if (b != buckets.end()) {
            numnodes = bufferClosestNodes(nodes, numnodes, id, *b);
            if (std::next(b) != buckets.end())
                numnodes = bufferClosestNodes(nodes, numnodes, id, *std::next(b));
            if (b != buckets.begin())
                numnodes = bufferClosestNodes(nodes, numnodes, id, *std::prev(b));
        }
    }

    if ((want & WANT6)) {
        auto b = buckets6.findBucket(id);
        if (b != buckets6.end()) {
            numnodes6 = bufferClosestNodes(nodes6, numnodes6, id, *b);
            if (std::next(b) != buckets6.end())
                numnodes6 = bufferClosestNodes(nodes6, numnodes6, id, *std::next(b));
            if (b != buckets6.begin())
                numnodes6 = bufferClosestNodes(nodes6, numnodes6, id, *std::prev(b));
        }
    }
    //DHT_DEBUG("sending closest nodes (%d+%d nodes.)", numnodes, numnodes6);

    try {
        return sendNodesValues(sa, salen, tid,
                                nodes, numnodes * 26,
                                nodes6, numnodes6 * 38,
                                st, token);
    } catch (const std::overflow_error& e) {
        DHT_ERROR("Can't send value: buffer not large enough !");
        return -1;
    }
}

int
Dht::sendGetValues(const sockaddr *sa, socklen_t salen,
               TransId tid, const InfoHash& infohash,
               want_t want, int confirm)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5);

    pk.pack(std::string("a"));  pk.pack_map(2 + (want>0?1:0));
      pk.pack(std::string("id")); pk.pack(myid);
      pk.pack(std::string("h"));  pk.pack(infohash);
    if (want > 0) {
      pk.pack(std::string("w"));
      pk.pack_array(((want & WANT4)?1:0) + ((want & WANT6)?1:0));
      if (want & WANT4) pk.pack(AF_INET);
      if (want & WANT6) pk.pack(AF_INET6);
    }

    pk.pack(std::string("q")); pk.pack(std::string("get"));
    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("q"));
    pk.pack(std::string("v")); pk.pack(my_v);

    out.get++;

    return send(buffer.data(), buffer.size(), confirm ? 0 : MSG_CONFIRM, sa, salen);
}

int
Dht::sendListen(const sockaddr* sa, socklen_t salen, TransId tid,
                        const InfoHash& infohash, const Blob& token, int confirm)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5);

    pk.pack(std::string("a")); pk.pack_map(3);
      pk.pack(std::string("id"));    pk.pack(myid);
      pk.pack(std::string("h"));     pk.pack(infohash);
      pk.pack(std::string("token")); pk.pack(token);

    pk.pack(std::string("q")); pk.pack(std::string("listen"));
    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("q"));
    pk.pack(std::string("v")); pk.pack(my_v);

    out.listen++;

    return send(buffer.data(), buffer.size(), confirm ? 0 : MSG_CONFIRM, sa, salen);
}

int
Dht::sendListenConfirmation(const sockaddr* sa, socklen_t salen, TransId tid)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4);

    pk.pack(std::string("r")); pk.pack_map(2);
      pk.pack(std::string("id")); pk.pack(myid);
      insertAddr(pk, sa, salen);

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);

    return send(buffer.data(), buffer.size(), 0, sa, salen);
}

int
Dht::sendAnnounceValue(const sockaddr *sa, socklen_t salen, TransId tid,
                   const InfoHash& infohash, const Value& value,
                   const Blob& token, int confirm)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5);

    pk.pack(std::string("a")); pk.pack_map(4);
      pk.pack(std::string("id"));     pk.pack(myid);
      pk.pack(std::string("h"));      pk.pack(infohash);
      pk.pack(std::string("values")); pk.pack_array(1); pk.pack(value);
      pk.pack(std::string("token"));  pk.pack(token);

    pk.pack(std::string("q")); pk.pack(std::string("put"));
    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("q"));
    pk.pack(std::string("v")); pk.pack(my_v);

    out.put++;

    return send(buffer.data(), buffer.size(), confirm ? 0 : MSG_CONFIRM, sa, salen);
}

int
Dht::sendValueAnnounced(const sockaddr *sa, socklen_t salen, TransId tid, Value::Id vid)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4);

    pk.pack(std::string("r")); pk.pack_map(3);
      pk.pack(std::string("id"));  pk.pack(myid);
      pk.pack(std::string("vid")); pk.pack(vid);
      insertAddr(pk, sa, salen);

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);

    return send(buffer.data(), buffer.size(), 0, sa, salen);
}

int
Dht::sendError(const sockaddr *sa, socklen_t salen, TransId tid, uint16_t code, const char *message, bool include_id)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4 + (include_id?1:0));

    pk.pack(std::string("e")); pk.pack_array(2);
      pk.pack(code);
      pk.pack_str(strlen(message));
      pk.pack_str_body(message, strlen(message));

    if (include_id) {
        pk.pack(std::string("r")); pk.pack_map(1);
          pk.pack(std::string("id")); pk.pack(myid);
    }

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("e"));
    pk.pack(std::string("v")); pk.pack(my_v);

    return send(buffer.data(), buffer.size(), 0, sa, salen);
}

msgpack::object*
findMapValue(msgpack::object& map, const std::string& key) {
    if (map.type != msgpack::type::MAP) throw msgpack::type_error();
    for (unsigned i = 0; i < map.via.map.size; i++) {
        auto& o = map.via.map.ptr[i];
        if(o.key.type != msgpack::type::STR)
            continue;
        if (o.key.as<std::string>() == key) {
            return &o.val;
        }
    }
    return nullptr;
}

void
Dht::ParsedMessage::msgpack_unpack(msgpack::object msg)
{
    auto y = findMapValue(msg, "y");
    auto a = findMapValue(msg, "a");
    auto r = findMapValue(msg, "r");
    auto e = findMapValue(msg, "e");

    std::string query;
    if (auto q = findMapValue(msg, "q")) {
        if (q->type != msgpack::type::STR)
            throw msgpack::type_error();
        query = q->as<std::string>();
    }

    auto& req = a ? *a : (r ? *r : *e);
    if (not &req)
        throw msgpack::type_error();

    if (e) {
        if (e->type != msgpack::type::ARRAY)
            throw msgpack::type_error();
        error_code = e->via.array.ptr[0].as<uint16_t>();
    }

    if (auto rid = findMapValue(req, "id"))
        id = {*rid};

    if (auto rh = findMapValue(req, "h"))
        info_hash = {*rh};

    if (auto rtarget = findMapValue(req, "target"))
        target = {*rtarget};

    if (auto otoken = findMapValue(req, "token"))
        token = otoken->as<Blob>();

    if (auto vid = findMapValue(req, "vid"))
        value_id = vid->as<Value::Id>();

    if (auto rnodes4 = findMapValue(req, "n4")) {
        auto n4b = rnodes4->as<std::vector<char>>();
        nodes4 = {n4b.begin(), n4b.end()};
    }

    if (auto rnodes6 = findMapValue(req, "n6")) {
        auto n6b = rnodes6->as<std::vector<char>>();
        nodes6 = {n6b.begin(), n6b.end()};
    }

    if (auto sa = findMapValue(req, "sa")) {
        if (sa->type != msgpack::type::BIN)
            throw msgpack::type_error();
        auto l = sa->via.bin.size;
        if (l == sizeof(in_addr)) {
            auto a = (sockaddr_in*)&addr.first;
            std::fill_n((uint8_t*)a, sizeof(sockaddr_in), 0);
            a->sin_family = AF_INET;
            a->sin_port = 0;
            std::copy_n(sa->via.bin.ptr, l, (char*)&a->sin_addr);
            addr.second = sizeof(sockaddr_in);
        } else if (l == sizeof(in6_addr)) {
            auto a = (sockaddr_in6*)&addr.first;
            std::fill_n((uint8_t*)a, sizeof(sockaddr_in6), 0);
            a->sin6_family = AF_INET6;
            a->sin6_port = 0;
            std::copy_n(sa->via.bin.ptr, l, (char*)&a->sin6_addr);
            addr.second = sizeof(sockaddr_in6);
        }
    } else
        addr.second = 0;

    if (auto rvalues = findMapValue(req, "values")) {
        if (rvalues->type != msgpack::type::ARRAY)
            throw msgpack::type_error();
        for (size_t i = 0; i < rvalues->via.array.size; i++)
            try {
                values.emplace_back(std::make_shared<Value>(rvalues->via.array.ptr[i]));
            } catch (const std::exception& e) {
                //DHT_WARN("Error reading value: %s", e.what());
            }
    }

    if (auto w = findMapValue(req, "w")) {
        if (w->type != msgpack::type::ARRAY)
            throw msgpack::type_error();
        want = 0;
        for (unsigned i=0; i<w->via.array.size; i++) {
            auto& val = w->via.array.ptr[i];
            try {
                auto w = val.as<sa_family_t>();
                if (w == AF_INET)
                    want |= WANT4;
                else if(w == AF_INET6)
                    want |= WANT6;
            } catch (const std::exception& e) {};
        }
    } else {
        want = -1;
    }

    if (auto t = findMapValue(msg, "t"))
        tid = {t->as<std::array<char, 4>>()};

    if (auto rv = findMapValue(msg, "v"))
        ua = rv->as<std::string>();

    if (e)
        type = MessageType::Error;
    else if (r)
        type = MessageType::Reply;
    else if (y and y->as<std::string>() != "q")
        throw msgpack::type_error();
    else if (query == "ping")
        type = MessageType::Ping;
    else if (query == "find")
        type = MessageType::FindNode;
    else if (query == "get")
        type = MessageType::GetValues;
    else if (query == "listen")
        type = MessageType::Listen;
    else if (query == "put")
        type = MessageType::AnnounceValue;
    else
        throw msgpack::type_error();
}

}
