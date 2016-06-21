/*
 *  Copyright (C) 2014-2016 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <sim.desaulniers@gmail.com>
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


#include "dht.h"
#include "rng.h"
#include "request.h"

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

#ifndef _WIN32
#include <unistd.h>
#else
#include <io.h>
#endif

#include <fcntl.h>
#include <cstring>

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
    return rc >= 0;
}

#endif

static std::mt19937 rd {dht::crypto::random_device{}()};
#ifdef _WIN32
static std::uniform_int_distribution<int> rand_byte{ 0, std::numeric_limits<uint8_t>::max() };
#else
static std::uniform_int_distribution<uint8_t> rand_byte;
#endif

namespace dht {

using namespace std::placeholders;

constexpr std::chrono::minutes Dht::MAX_STORAGE_MAINTENANCE_EXPIRE_TIME;
constexpr std::chrono::minutes Dht::SEARCH_EXPIRE_TIME;
constexpr std::chrono::seconds Dht::LISTEN_EXPIRE_TIME;
constexpr std::chrono::seconds Dht::REANNOUNCE_MARGIN;

// internal structures definition

struct Dht::Storage {
    InfoHash id;
    time_point maintenance_time {};
    std::map<std::shared_ptr<Node>, Listener> listeners {};
    std::map<size_t, LocalListener> local_listeners {};
    size_t listener_token {1};

    Storage() {}
    Storage(InfoHash id, time_point now) : id(id), maintenance_time(now+MAX_STORAGE_MAINTENANCE_EXPIRE_TIME) {}

#if defined(__GNUC__) && __GNUC__ == 4 && __GNUC_MINOR__ <= 9 || defined(_WIN32)
    // GCC-bug: remove me when support of GCC < 4.9.2 is abandoned
    Storage(Storage&& o) noexcept
        : id(std::move(o.id))
        , maintenance_time(std::move(o.maintenance_time))
        , listeners(std::move(o.listeners))
        , local_listeners(std::move(o.local_listeners))
        , listener_token(std::move(o.listener_token))
        , values(std::move(o.values))
        , total_size(std::move(o.total_size)) {}
#else
    Storage(Storage&& o) noexcept = default;
#endif

    Storage& operator=(Storage&& o) = default;

    bool empty() const {
        return values.empty();
    }

    void clear();

    size_t valueCount() const {
        return values.size();
    }

    size_t totalSize() const {
        return total_size;
    }

    const std::vector<ValueStorage>& getValues() const { return values; }

    std::shared_ptr<Value> getById(Value::Id vid) const {
        for (auto& v : values)
            if (v.data->id == vid) return v.data;
        return {};
    }

    std::vector<std::shared_ptr<Value>> get(Value::Filter f = {}) const {
        std::vector<std::shared_ptr<Value>> newvals {};
        if (not f) newvals.reserve(values.size());
        for (auto& v : values) {
            if (not f || f(*v.data))
                newvals.push_back(v.data);
        }
        return newvals;
    }

    /**
     * Stores a new value in this storage, or replace a previous value
     *
     * @return <storage, change_size, change_value_num>
     *      storage: set if a change happened
     *      change_size: size difference
     *      change_value_num: change of value number (0 or 1)
     */
    std::tuple<ValueStorage*, ssize_t, ssize_t>
    store(const std::shared_ptr<Value>& value, time_point created, ssize_t size_left);

    std::pair<ssize_t, ssize_t> expire(const std::map<ValueType::Id, ValueType>& types, time_point now);

private:
    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;

    std::vector<ValueStorage> values {};
    size_t total_size {};
};


struct Dht::SearchNode {
    SearchNode() : node() {}
    SearchNode(std::shared_ptr<Node> node) : node(node) {}

    using AnnounceStatusMap = std::map<Value::Id, std::shared_ptr<Request>>;

    /**
     * Can we use this node to listen/announce now ?
     */
    bool isSynced(time_point now) const {
        return not node->isExpired() and
               not token.empty() and last_get_reply >= now - Node::NODE_EXPIRE_TIME;
    }

    /**
     * Could a "get" request be sent to this node now ?
     * update: time of the last "get" op for the search.
     */
    bool canGet(time_point now, time_point update) const {
        return not node->isExpired() and
               (now > last_get_reply + Node::NODE_EXPIRE_TIME or update > last_get_reply)
               and (not getStatus or not getStatus->pending());
    }

    bool isAnnounced(Value::Id vid, const ValueType& type, time_point now) const {
        auto ack = acked.find(vid);
        if (ack == acked.end() or not ack->second) {
            return false;
        }
        return ack->second->reply_time + type.expiration > now;
    }
    bool isListening(time_point now) const {
        if (not listenStatus)
            return false;

        return listenStatus->reply_time + LISTEN_EXPIRE_TIME > now;
    }

    /**
     * Assumng the node is synced, should a "put" request be sent to this node now ?
     */
    time_point getAnnounceTime(AnnounceStatusMap::const_iterator ack, const ValueType& type) const {
        if (ack == acked.end() or not ack->second)
            return time_point::min();
        return ack->second->pending() ? time_point::max() : ack->second->reply_time + type.expiration - REANNOUNCE_MARGIN;
    }

    time_point getAnnounceTime(Value::Id vid, const ValueType& type) const {
        return getAnnounceTime(acked.find(vid), type);
    }

    /**
     * Assumng the node is synced, should a "listen" request be sent to this node now ?
     */
    time_point getListenTime() const {
        if (not listenStatus)
            return time_point::min();

        return listenStatus->pending() ? time_point::max() : listenStatus->reply_time + LISTEN_EXPIRE_TIME - REANNOUNCE_MARGIN;
    }

    /**
     * Is this node expired or candidate
     */
    bool isBad() const {
        return !node || node->isExpired() || candidate;
    }

    std::shared_ptr<Node> node {};

    time_point last_get_reply {time_point::min()};                 /* last time received valid token */
    std::shared_ptr<Request> getStatus {};          /* get/sync status */
    std::shared_ptr<Request> listenStatus {};
    AnnounceStatusMap acked {};                                    /* announcement status for a given value id */

    Blob token {};

    /**
     * A search node is candidate if the search is/was synced and this node is a new candidate for inclusion
     *
     */
    bool candidate {false};
};

struct Dht::Search {
    InfoHash id {};
    sa_family_t af;

    uint16_t tid;
    time_point refill_time {time_point::min()};
    time_point step_time {time_point::min()};           /* the time of the last search step */
    std::shared_ptr<Scheduler::Job> nextSearchStep {};

    bool expired {false};              /* no node, or all nodes expired */
    bool done {false};                 /* search is over, cached for later */
    std::vector<SearchNode> nodes {};

    /* pending puts */
    std::vector<Announce> announce {};

    /* pending gets */
    std::vector<Get> callbacks {};

    /* listeners */
    std::map<size_t, LocalListener> listeners {};
    size_t listener_token = 1;

    /**
     * @returns true if the node was not present and added to the search
     */
    bool insertNode(const std::shared_ptr<Node>& n, time_point now, const Blob& token={});
    unsigned insertBucket(const Bucket&, time_point now);

    SearchNode* getNode(const std::shared_ptr<Node>& n) {
        auto srn = std::find_if(nodes.begin(), nodes.end(), [&](SearchNode& sn) {
            return n == sn.node;
        });
        return (srn == nodes.end()) ? nullptr : &(*srn);
    }

    /* number of concurrent sync requests */
    unsigned currentGetRequests() const {
        unsigned count = 0;
        for (const auto& n : nodes)
            if (not n.isBad() and n.getStatus and n.getStatus->pending())
                count++;
        return count;
    }

    /**
     * Can we use this search to announce ?
     */
    bool isSynced(time_point now) const;

    /**
     * Get the time of the last "get" operation performed on this search,
     * or time_point::min() if no such operation have been performed.
     */
    time_point getLastGetTime() const;

    /**
     * Is this get operation done ?
     */
    bool isDone(const Get& get, time_point now) const;

    time_point getUpdateTime(time_point now) const;

    bool isAnnounced(Value::Id id, const ValueType& type, time_point now) const;
    bool isListening(time_point now) const;

    /**
     * @return The number of non-good search nodes.
     */
    unsigned getNumberOfBadNodes() const;

    /**
     * Returns the time of the next "announce" event for this search,
     * or time_point::max() if no such event is planned.
     * Only makes sense when the search is synced.
     */
    time_point getAnnounceTime(const std::map<ValueType::Id, ValueType>& types, time_point now) const;

    /**
     * Returns the time of the next "listen" event for this search,
     * or time_point::max() if no such event is planned.
     * Only makes sense when the search is synced.
     */
    time_point getListenTime(time_point now) const;

    /**
     * Returns the time of the next event for this search,
     * or time_point::max() if no such event is planned.
     */
    time_point getNextStepTime(const std::map<ValueType::Id, ValueType>& types, time_point now) const;

    bool removeExpiredNode(time_point now);

    unsigned refill(const RoutingTable&, time_point now);

    std::vector<std::shared_ptr<Node>> getNodes() const;

    void clear() {
        announce.clear();
        callbacks.clear();
        listeners.clear();
        nodes.clear();
        nextSearchStep.reset();
    }
};

void
Dht::setLoggers(LogMethod error, LogMethod warn, LogMethod debug)
{
    DHT_LOG.DEBUG = debug;
    DHT_LOG.WARN = warn;
    DHT_LOG.ERR = error;
}

NodeStatus
Dht::getStatus(sa_family_t af) const
{
    unsigned good = 0, dubious = 0, cached = 0, incoming = 0;
    int tot = getNodesStats(af, &good, &dubious, &cached, &incoming);
    if (tot < 1)
        return NodeStatus::Disconnected;
    else if (good < 1)
        return NodeStatus::Connecting;
    return NodeStatus::Connected;
}

void
Dht::shutdown(ShutdownCallback cb) {
    /****************************
     *  Last store maintenance  *
     ****************************/

    scheduler.syncTime();
    auto remaining = std::make_shared<int>(0);
    auto str_donecb = [=](bool, const std::vector<std::shared_ptr<Node>>&) {
        --*remaining;
        if (!*remaining && cb) { cb(); }
        else DHT_LOG.WARN("Shuting down node: %u ops remaining.", *remaining);
    };

    for (const auto& str : store) {
        *remaining += maintainStorage(str.id, true, str_donecb);
    }
    DHT_LOG.WARN("Shuting down node: %u ops remaining.", *remaining);
    if (!*remaining && cb) { cb(); }
}

bool
Dht::isRunning(sa_family_t af) const { return network_engine.isRunning(af); }

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

/* Every bucket caches the address of a likely node.  Ping it. */
int
Dht::sendCachedPing(Bucket& b)
{
    /* We set family to 0 when there's no cached node. */
    if (!b.cached)
        return 0;

    DHT_LOG.DEBUG("Sending ping to cached node.");
    network_engine.sendPing(b.cached, nullptr, nullptr);
    b.cached = {};
    return 0;
}

std::vector<Address>
Dht::getPublicAddress(sa_family_t family)
{
    std::sort(reported_addr.begin(), reported_addr.end(), [](const ReportedAddr& a, const ReportedAddr& b) {
        return a.first < b.first;
    });
    std::vector<Address> ret;
    for (const auto& addr : reported_addr)
        if (!family || family == addr.second.first.ss_family)
            ret.emplace_back(addr.second);
    return ret;
}

bool
Dht::trySearchInsert(const std::shared_ptr<Node>& node)
{
    const auto& now = scheduler.time();
    if (not node) return false;

    bool inserted = false;
    auto family = node->getFamily();
    auto& srs = family == AF_INET ? searches4 : searches6;
    for (auto& srp : srs) {
        auto& s = *srp.second;
        if (s.insertNode(node, now)) {
            inserted = true;
            scheduler.edit(s.nextSearchStep, s.getNextStepTime(types, now));
        }
    }
    return inserted;
}

void
Dht::reportedAddr(const sockaddr *sa, socklen_t sa_len)
{
    auto it = std::find_if(reported_addr.begin(), reported_addr.end(), [=](const ReportedAddr& addr){
        return (addr.second.second == sa_len) &&
            std::equal((uint8_t*)&addr.second.first, (uint8_t*)&addr.second.first + addr.second.second, (uint8_t*)sa);
    });
    if (it == reported_addr.end()) {
        if (reported_addr.size() < 32)
            reported_addr.emplace_back(1, std::make_pair(*((sockaddr_storage*)sa), sa_len));
    } else
        it->first++;
}

/* We just learnt about a node, not necessarily a new one.  Confirm is 1 if
   the node sent a message, 2 if it sent us a reply. */
void
Dht::onNewNode(const std::shared_ptr<Node>& node, int confirm)
{
    auto& list = node->getFamily() == AF_INET ? buckets : buckets6;
    auto b = list.findBucket(node->id);
    if (b == list.end())
        return;

    for (auto& n : b->nodes) {
        if (n == node) {
            if (confirm)
                trySearchInsert(node);
            return;
        }
    }

    /* New node. */
    /* Try adding the node to searches */
    trySearchInsert(node);

    const auto& now = scheduler.time();
    bool mybucket = list.contains(b, myid);
    if (mybucket) {
        if (node->getFamily() == AF_INET)
            mybucket_grow_time = now;
        else
            mybucket6_grow_time = now;
        //scheduler.edit(nextNodesConfirmation, now);
    }

    /* Try to get rid of an expired node. */
    for (auto& n : b->nodes) {
        if (not n->isExpired())
            continue;
        n = node;
        return;
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
                if (not n->isPendingMessage()) {
                    DHT_LOG.DEBUG("Sending ping to dubious node %s.", n->toString().c_str());
                    network_engine.sendPing(n, nullptr, nullptr);
                    break;
                }
            }
        }

        if ((mybucket || (is_bootstrap and list.depth(b) < 6)) && (!dubious || list.size() == 1)) {
            DHT_LOG.DEBUG("Splitting from depth %u", list.depth(b));
            sendCachedPing(*b);
            list.split(b);
            onNewNode(node, 0);
            return;
        }

        /* No space for this node.  Cache it away for later. */
        if (confirm or not b->cached)
            b->cached = node;
    } else {
        /* Create a new node. */
        b->nodes.emplace_front(node);
    }
}

/* Called periodically to purge known-bad nodes.  Note that we're very
   conservative here: broken nodes in the table don't do much harm, we'll
   recover as soon as we find better ones. */
void
Dht::expireBuckets(RoutingTable& list)
{
    for (auto& b : list) {
        bool changed = false;
        b.nodes.remove_if([this,&changed](const std::shared_ptr<Node>& n) {
            if (n->isExpired()) {
                changed = true;
                return true;
            }
            return false;
        });
        if (changed)
            sendCachedPing(b);
    }
}

bool
Dht::Search::removeExpiredNode(time_point now)
{
    auto e = nodes.end();
    while (e != nodes.cbegin()) {
        e = std::prev(e);
        const Node& n = *e->node;
        if (n.isExpired() and n.time + Node::NODE_EXPIRE_TIME < now) {
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
Dht::Search::insertNode(const std::shared_ptr<Node>& snode, time_point now, const Blob& token)
{
    auto& node = *snode;
    const auto& nid = node.id;

    if (node.getFamily() != af)
        return false;

    bool found = false;
    auto n = nodes.end();
    while (n != nodes.begin()) {
        --n;
        if (n->node == snode) {
            found = true;
            break;
        }
        if (id.xorCmp(nid, n->node->id) > 0) {
            ++n;
            break;
        }
    }

    bool new_search_node = false;
    if (!found) {
        // find if and where to trim excessive nodes
        auto t = nodes.cend();
        size_t bad = 0;     // number of bad nodes (if search is not expired)
        bool full {false};  // is the search full (has the maximum nodes)
        if (expired) {
            // if the search is expired, trim to SEARCH_NODES nodes
            if (nodes.size() >= SEARCH_NODES) {
                full = true;
                t = nodes.begin() + SEARCH_NODES;
            }
        } else {
            // otherwise, trim to SEARCH_NODES nodes, not counting bad nodes
            bad = getNumberOfBadNodes();
            full = nodes.size() - bad >=  SEARCH_NODES;
            while (std::distance(nodes.cbegin(), t) - bad >  SEARCH_NODES) {
                --t;
                if (t->isBad())
                    bad--;
            }
        }

        if (full) {
            if (t != nodes.cend())
                nodes.resize(std::distance(nodes.cbegin(), t));
            if (n >= t)
                return false;
        }

        // Reset search timer if the search is empty
        if (nodes.empty()) {
            step_time = TIME_INVALID;
        }
        n = nodes.insert(n, SearchNode(snode));
        node.time = now;
        new_search_node = true;
        if (node.isExpired()) {
            if (not expired)
                bad++;
        } else if (expired) {
            bad = nodes.size() - 1;
            expired = false;
        }

        while (nodes.size() - bad >  SEARCH_NODES) {
            if (not expired and nodes.back().isBad())
                bad--;
            nodes.pop_back();
        }
    }
    if (not token.empty()) {
        n->candidate = false;
        n->last_get_reply = now;
        if (token.size() <= 64)
            n->token = token;
        expired = false;
    }
    if (new_search_node) {
        removeExpiredNode(now);
    }
    return new_search_node;
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
    auto t = scheduler.time() - SEARCH_EXPIRE_TIME;
    auto expired = [&](std::pair<const InfoHash, std::shared_ptr<Search>>& srp) {
        auto& sr = *srp.second;
        auto b = sr.callbacks.empty() && sr.announce.empty() && sr.listeners.empty() && sr.step_time < t;
        if (b) {
            DHT_LOG.DEBUG("Removing search %s", srp.first.toString().c_str());
            sr.clear();
            return b;
        } else { return false; }
    };
    erase_if(searches4, expired);
    erase_if(searches6, expired);
}

Dht::SearchNode*
Dht::searchSendGetValues(std::shared_ptr<Search> sr, SearchNode* pn, bool update)
{
    if (sr->done or sr->currentGetRequests() >= SEARCH_REQUESTS)
        return nullptr;

    const auto& now = scheduler.time();
    const time_point up = update ? sr->getLastGetTime() : time_point::min();
    SearchNode* n = nullptr;
    if (pn) {
        if (not pn->canGet(now, up))
            return nullptr;
        n = pn;
    } else {
        for (auto& sn : sr->nodes) {
            if (sn.canGet(now, up)) {
                n = &sn;
                break;
            }
        }
        if (not n)
            return nullptr;
    }

    /*DHT_LOG.DEBUG("[search %s IPv%c] [node %s] sending 'get'",
        sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6',
        n->node->toString().c_str());*/

    std::weak_ptr<Search> ws = sr;
    auto onDone =
        [this,ws](const Request& status, NetworkEngine::RequestAnswer&& answer) mutable {
            if (auto sr = ws.lock()) {
                sr->insertNode(status.node, scheduler.time(), answer.ntoken);
                onGetValuesDone(status, answer, sr);
            }
        };
    auto onExpired =
        [this,ws](const Request& status, bool over) mutable {
            if (auto sr = ws.lock()) {
                if (auto srn = sr->getNode(status.node))
                    srn->candidate = not over;
                scheduler.edit(sr->nextSearchStep, scheduler.time());
            }
        };
    std::shared_ptr<Request> rstatus;
    if (sr->callbacks.empty() and sr->listeners.empty())
        rstatus = network_engine.sendFindNode(n->node, sr->id, -1, onDone, onExpired);
    else
        rstatus = network_engine.sendGetValues(n->node, sr->id, -1, onDone, onExpired);
    n->getStatus = rstatus;
    return n;
}

/* When a search is in progress, we periodically call search_step to send
   further requests. */
void
Dht::searchStep(std::shared_ptr<Search> sr)
{
    if (not sr or sr->expired or sr->done) return;

    const auto& now = scheduler.time();
    DHT_LOG.DEBUG("[search %s IPv%c] step (%d requests)", sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6', sr->currentGetRequests());
    sr->step_time = now;

    if (sr->refill_time + Node::NODE_EXPIRE_TIME < now and sr->nodes.size()-sr->getNumberOfBadNodes() < SEARCH_NODES) {
        if (auto added = sr->refill(sr->af == AF_INET ? buckets : buckets6, now)) {
            sr->refill_time = now;
            DHT_LOG.DEBUG("[search %s IPv%c] refilled with %u nodes", sr->id.toString().c_str(), (sr->af == AF_INET) ? '4' : '6', added);
        }
    }

    /* Check if the first TARGET_NODES (8) live nodes have replied. */
    if (sr->isSynced(now)) {
        if (not sr->callbacks.empty()) {
            // search is synced but some (newer) get operations are not complete
            // Call callbacks when done
            for (auto b = sr->callbacks.begin(); b != sr->callbacks.end();) {
                if (sr->isDone(*b, now)) {
                    if (b->done_cb)
                        b->done_cb(true, sr->getNodes());
                    b = sr->callbacks.erase(b);
                }
                else
                    ++b;
            }
            if (sr->callbacks.empty() && sr->announce.empty() && sr->listeners.empty())
                sr->done = true;
        }

        // true if this node is part of the target nodes cluter.
        bool in = sr->id.xorCmp(myid, sr->nodes.back().node->id) < 0;

        DHT_LOG.DEBUG("[search %s IPv%c] synced%s", sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6', in ? ", in" : "");

        if (not sr->listeners.empty()) {
            unsigned i = 0;
            for (auto& n : sr->nodes) {
                if (not n.isSynced(now))
                    continue;
                if (n.getListenTime() <= now) {
                    DHT_LOG.WARN("[search %s IPv%c] [node %s] sending 'listen'",
                        sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6',
                        n.node->toString().c_str());
                    //std::cout << "Sending listen to " << n.node->id << " " << print_addr(n.node->ss, n.node->sslen) << std::endl;

                    //network_engine.cancelRequest(n.listenStatus);
                    auto ls = n.listenStatus;

                    std::weak_ptr<Search> ws = sr;
                    n.listenStatus = network_engine.sendListen(n.node, sr->id, n.token,
                        [this,ws,ls](const Request& status,
                                NetworkEngine::RequestAnswer&& answer) mutable
                        { /* on done */
                            // cancel previous request
                            network_engine.cancelRequest(ls);
                            if (auto sr = ws.lock()) {
                                onListenDone(status, answer, sr);
                                searchStep(sr);
                            }
                        },
                        [this,ws,ls](const Request&, bool over) mutable
                        { /* on expired */
                            if (over) {
                                network_engine.cancelRequest(ls);
                                if (auto sr = ws.lock())
                                    scheduler.edit(sr->nextSearchStep, scheduler.time());
                            }
                        }
                    );
                }
                if (not n.candidate and ++i == LISTEN_NODES)
                    break;
            }
        }

        // Announce requests
        for (auto ait = sr->announce.begin(); ait != sr->announce.end();) {
            auto& a = *ait;
            if (!a.value) continue;
            auto vid = a.value->id;
            const auto& type = getType(a.value->type);
            if (sr->isAnnounced(vid, type, now)) {
                if (a.callback) {
                    a.callback(true, sr->getNodes());
                    a.callback = nullptr;
                }
                if (not a.permanent) {
                    ait = sr->announce.erase(ait);
                    continue;
                }
            }
            if (in) storageStore(sr->id, a.value, a.created);
            unsigned i = 0;
            for (auto& n : sr->nodes) {
                if (not n.isSynced(now))
                    continue;
                if (n.getAnnounceTime(vid, type) <= now) {
                    DHT_LOG.WARN("[search %s IPv%c] [node %s] sending 'put' (vid: %d)",
                        sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6', n.node->toString().c_str(), vid);
                    std::weak_ptr<Search> ws = sr;
                    n.acked[vid] = network_engine.sendAnnounceValue(n.node, sr->id, *a.value, a.created, n.token,
                        [this,ws](const Request& status, NetworkEngine::RequestAnswer&& answer)
                        { /* on done */
                            if (auto sr = ws.lock()) {
                                onAnnounceDone(status, answer, sr);
                                searchStep(sr);
                            }
                        },
                        [this,ws](const Request&, bool over)
                        { /* on expired */
                            if (over)
                                if (auto sr = ws.lock())
                                    scheduler.edit(sr->nextSearchStep, scheduler.time());
                        }
                    );
                }
                if (not n.candidate and ++i == TARGET_NODES)
                    break;
            }
            ++ait;
        }
        if (sr->callbacks.empty() && sr->announce.empty() && sr->listeners.empty())
            sr->done = true;
    }

    if (sr->currentGetRequests() < SEARCH_REQUESTS) {
        unsigned i = 0;
        SearchNode* sent;
        do {
            sent = searchSendGetValues(sr);
            if (sent and not sent->candidate)
                i++;
        }
        while (sent and sr->currentGetRequests() < SEARCH_REQUESTS);
        /*DHT_LOG.DEBUG("[search %s IPv%c] step: sent %u requests (total %u).",
            sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6', i, sr->currentGetRequests());*/

        auto expiredn = (size_t)std::count_if(sr->nodes.begin(), sr->nodes.end(), [&](const SearchNode& sn) {
                    return sn.candidate or sn.node->isExpired();
                });
        if (i == 0 && expiredn == sr->nodes.size())
        {
            DHT_LOG.WARN("[search %s IPv%c] expired", sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6');
            // no nodes or all expired nodes
            sr->expired = true;
            if (sr->announce.empty() && sr->listeners.empty()) {
                // Listening or announcing requires keeping the cluster up to date.
                sr->done = true;
            }
            {
                auto get_cbs = std::move(sr->callbacks);
                for (const auto& g : get_cbs) {
                    if (g.done_cb)
                        g.done_cb(false, {});
                }
            }
            {
                std::vector<DoneCallback> a_cbs;
                a_cbs.reserve(sr->announce.size());
                for (auto ait = sr->announce.begin() ; ait != sr->announce.end(); ) {
                    if (ait->callback)
                        a_cbs.emplace_back(std::move(ait->callback));
                    if (not ait->permanent)
                        ait = sr->announce.erase(ait);
                    else
                        ait++;
                }
                for (const auto& a : a_cbs)
                    a(false, {});
            }
        }
    }

    //dumpSearch(*sr, std::cout);

    /* periodic searchStep scheduling. */
    if (not sr->done)
        scheduler.edit(sr->nextSearchStep, sr->getNextStepTime(types, now));
}

/* Insert the contents of a bucket into a search structure. */
unsigned
Dht::Search::insertBucket(const Bucket& b, time_point now)
{
    unsigned inserted = 0;
    for (auto& n : b.nodes) {
        if (not n->isExpired() and insertNode(n, now))
            inserted++;
    }
    return inserted;
}

bool
Dht::Search::isSynced(time_point now) const
{
    unsigned i = 0;
    for (const auto& n : nodes) {
        if (n.isBad())
            continue;
        if (not n.isSynced(now))
            return false;
        if (++i == TARGET_NODES)
            break;
    }
    return i > 0;
}

unsigned Dht::Search::getNumberOfBadNodes() const {
    return std::count_if(nodes.begin(), nodes.end(),
                [=](const SearchNode& sn) { return sn.isBad(); }
           );
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
        if (sn.isBad())
            continue;
        if (sn.last_get_reply < limit)
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
    const auto reqs = currentGetRequests();
    for (const auto& sn : nodes) {
        if (sn.node->isExpired() or (sn.candidate and t >= TARGET_NODES))
            continue;
        bool pending = sn.getStatus and sn.getStatus->pending();
        if (sn.last_get_reply < std::max(now - Node::NODE_EXPIRE_TIME, last_get) or pending) {
            // not isSynced
            if (not pending and reqs < SEARCH_REQUESTS)
                ut = std::min(ut, now);
            if (not sn.candidate)
                d++;
        } else {
            ut = std::min(ut, sn.last_get_reply + Node::NODE_EXPIRE_TIME);
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
        if (n.isBad())
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
        if (n.isBad())
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
    const auto& now = scheduler.time();
    auto& list = (sr.af == AF_INET) ? buckets : buckets6;
    if (list.empty() || (list.size() == 1 && list.front().nodes.empty()))
        return;
    auto b = list.findBucket(sr.id);
    if (b == list.end()) {
        DHT_LOG.ERR("No bucket");
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
    sr.refill_time = now;
}

unsigned
Dht::Search::refill(const RoutingTable& r, time_point now) {
    if (r.isEmpty() or r.front().af != af)
        return 0;
    unsigned added = 0;
    auto num_bad_nodes = getNumberOfBadNodes();
    auto b = r.findBucket(id);
    auto n = b;
    while (nodes.size()-num_bad_nodes < SEARCH_NODES && (std::next(n) != r.end() || b != r.begin())) {
        if (std::next(n) != r.end()) {
            added += insertBucket(*std::next(n), now);
            n = std::next(n);
        }
        if (b != r.begin()) {
            added += insertBucket(*std::prev(b), now);
            b = std::prev(b);
        }
    }

    return added;
}

/* Start a search. */
std::shared_ptr<Dht::Search>
Dht::search(const InfoHash& id, sa_family_t af, GetCallback callback, DoneCallback done_callback, Value::Filter filter)
{
    if (!isRunning(af)) {
        DHT_LOG.ERR("[search %s IPv%c] unsupported protocol", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
        if (done_callback)
            done_callback(false, {});
        return {};
    }

    auto& srs = af == AF_INET ? searches4 : searches6;
    const auto& srp = srs.find(id);
    std::shared_ptr<Search> sr {};

    if (srp != srs.end()) {
        sr = srp->second;
        sr->done = false;
        sr->expired = false;
    } else {
        if (searches4.size() + searches6.size() < MAX_SEARCHES) {
            sr = std::make_shared<Search>();
            srs.emplace(id, sr);
        } else {
            for (auto it = srs.begin(); it!=srs.end();) {
                auto& s = *it->second;
                if ((s.done or s.expired) and s.announce.empty() and s.listeners.empty()) {
                    sr = it->second;
                    break;
                }
            }
            if (not sr)
                throw DhtException("Can't create search");
        }
        sr->af = af;
        sr->tid = search_id++;
        sr->step_time = TIME_INVALID;
        sr->id = id;
        sr->done = false;
        sr->expired = false;
        sr->nodes.clear();
        sr->nodes.reserve(SEARCH_NODES+1);
        DHT_LOG.WARN("[search %s IPv%c] new search", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
        if (search_id == 0)
            search_id++;
    }

    if (callback)
        sr->callbacks.push_back({/*.start=*/scheduler.time(), /*.filter=*/filter, /*.get_cb=*/callback, /*.done_cb=*/done_callback});
    bootstrapSearch(*sr);

    if (sr->nextSearchStep)
        scheduler.edit(sr->nextSearchStep, sr->getNextStepTime(types, scheduler.time()));
    else
        sr->nextSearchStep = scheduler.add(scheduler.time(), std::bind(&Dht::searchStep, this, sr));
    return sr;
}

void
Dht::announce(const InfoHash& id, sa_family_t af, std::shared_ptr<Value> value, DoneCallback callback,
        time_point created, bool permanent)
{
    const auto& now = scheduler.time();
    if (!value) {
        if (callback)
            callback(false, {});
        return;
    }
    auto& srs = af == AF_INET ? searches4 : searches6;
    auto srp = srs.find(id);
    auto sr = srp == srs.end() ? search(id, af, nullptr, nullptr) : srp->second;
    if (!sr) {
        if (callback)
            callback(false, {});
        return;
    }
    sr->done = false;
    sr->expired = false;
    auto a_sr = std::find_if(sr->announce.begin(), sr->announce.end(), [&](const Announce& a){
        return a.value->id == value->id;
    });
    if (a_sr == sr->announce.end()) {
        sr->announce.emplace_back(Announce {permanent, value, std::min(now, created), callback});
        for (auto& n : sr->nodes)
            n.acked[value->id].reset();
    }
    else {
        if (a_sr->value != value) {
            a_sr->value = value;
            for (auto& n : sr->nodes)
                n.acked[value->id].reset();
        }
        if (sr->isAnnounced(value->id, getType(value->type), now)) {
            if (a_sr->callback)
                a_sr->callback(true, {});
            a_sr->callback = {};
            if (callback) {
                callback(true, {});
            }
            return;
        } else {
            if (a_sr->callback)
                a_sr->callback(false, {});
            a_sr->callback = callback;
        }
    }
    scheduler.edit(sr->nextSearchStep, scheduler.time());
    //TODO
    //if (tm < search_time) {
    //    DHT_LOG.ERR("[search %s IPv%c] search_time is now in %lfs", sr->id.toString().c_str(),l
    //            (sr->af == AF_INET) ? '4' : '6', print_dt(tm-clock::now()));
    //    search_time = tm;
    //}
}

size_t
Dht::listenTo(const InfoHash& id, sa_family_t af, GetCallback cb, Value::Filter f)
{
    const auto& now = scheduler.time();
    if (!isRunning(af))
        return 0;
       // DHT_LOG.ERR("[search %s IPv%c] search_time is now in %lfs", sr->id.toString().c_str(), (sr->af == AF_INET) ? '4' : '6', print_dt(tm-clock::now()));

    //DHT_LOG.WARN("listenTo %s", id.toString().c_str());
    auto& srs = af == AF_INET ? searches4 : searches6;
    auto srp = srs.find(id);
    std::shared_ptr<Search> sr = (srp == srs.end()) ? search(id, af, nullptr, nullptr) : srp->second;
    if (!sr)
        throw DhtException("Can't create search");
    DHT_LOG.ERR("[search %s IPv%c] listen", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
    sr->done = false;
    auto token = ++sr->listener_token;
    sr->listeners.emplace(token, LocalListener{f, cb});
    scheduler.edit(sr->nextSearchStep, sr->getNextStepTime(types, now));
    return token;
}

size_t
Dht::listen(const InfoHash& id, GetCallback cb, Value::Filter&& f)
{
    scheduler.syncTime();

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

    auto st = findStorage(id);
    size_t tokenlocal = 0;
    if (st == store.end() && store.size() < MAX_HASHES) {
        store.emplace_back(id, scheduler.time());
        st = std::prev(store.end());
    }
    if (st != store.end()) {
        if (not st->empty()) {
            std::vector<std::shared_ptr<Value>> newvals = st->get(f);
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

    DHT_LOG.DEBUG("Added listen : %d -> %d %d %d", token, tokenlocal, token4, token6);
    listeners.emplace(token, std::make_tuple(tokenlocal, token4, token6));
    return token;
}

bool
Dht::cancelListen(const InfoHash& id, size_t token)
{
    scheduler.syncTime();

    auto it = listeners.find(token);
    if (it == listeners.end()) {
        DHT_LOG.WARN("Listen token not found: %d", token);
        return false;
    }
    DHT_LOG.DEBUG("cancelListen %s with token %d", id.toString().c_str(), token);
    auto st = findStorage(id);
    auto tokenlocal = std::get<0>(it->second);
    if (st != store.end() && tokenlocal)
        st->local_listeners.erase(tokenlocal);

    auto searches_cancel_listen = [&](std::map<InfoHash, std::shared_ptr<Search>> srs) {
        for (auto& sp : srs) {
            auto& s = sp.second;
            if (s->id != id) continue;
            auto af_token = s->af == AF_INET ? std::get<1>(it->second) : std::get<2>(it->second);
            if (af_token == 0)
                continue;
            s->listeners.erase(af_token);
            if (s->listeners.empty()) {
                for (auto& sn : s->nodes) {
                    // also erase requests for all searchnodes.
                    network_engine.cancelRequest(sn.listenStatus);
                    sn.listenStatus.reset();
                }
            }
        }
    };
    searches_cancel_listen(searches4);
    searches_cancel_listen(searches6);
    listeners.erase(it);
    return true;
}

void
Dht::put(const InfoHash& id, std::shared_ptr<Value> val, DoneCallback callback, time_point created, bool permanent)
{
    scheduler.syncTime();

    if (val->id == Value::INVALID_ID) {
        crypto::random_device rdev;
        std::uniform_int_distribution<Value::Id> rand_id {};
        val->id = rand_id(rdev);
    }

    DHT_LOG.DEBUG("put: adding %s -> %s", id.toString().c_str(), val->toString().c_str());

    auto ok = std::make_shared<bool>(false);
    auto done = std::make_shared<bool>(false);
    auto done4 = std::make_shared<bool>(false);
    auto done6 = std::make_shared<bool>(false);
    auto donecb = [=](const std::vector<std::shared_ptr<Node>>& nodes) {
        // Callback as soon as the value is announced on one of the available networks
        if (callback && !*done && (*done4 && *done6)) {
            callback(*ok, nodes);
            *done = true;
        }
    };
    announce(id, AF_INET, val, [=](bool ok4, const std::vector<std::shared_ptr<Node>>& nodes) {
        DHT_LOG.DEBUG("Announce done IPv4 %d", ok4);
        *done4 = true;
        *ok |= ok4;
        donecb(nodes);
    }, created, permanent);
    announce(id, AF_INET6, val, [=](bool ok6, const std::vector<std::shared_ptr<Node>>& nodes) {
        DHT_LOG.DEBUG("Announce done IPv6 %d", ok6);
        *done6 = true;
        *ok |= ok6;
        donecb(nodes);
    }, created, permanent);
}

struct OpStatus {
    bool done {false};
    bool ok {false};
};

void
Dht::get(const InfoHash& id, GetCallback getcb, DoneCallback donecb, Value::Filter&& filter)
{
    scheduler.syncTime();

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
        //DHT_LOG.WARN("DHT done IPv4");
        status4->done = true;
        status4->ok = ok;
        done_l(nodes);
    });
    Dht::search(id, AF_INET6, cb, [=](bool ok, const std::vector<std::shared_ptr<Node>>& nodes) {
        //DHT_LOG.WARN("DHT done IPv6");
        status6->done = true;
        status6->ok = ok;
        done_l(nodes);
    });
}

std::vector<std::shared_ptr<Value>>
Dht::getLocal(const InfoHash& id, Value::Filter f) const
{
    auto s = findStorage(id);
    if (s == store.end()) return {};
    return s->get(f);
}

std::shared_ptr<Value>
Dht::getLocalById(const InfoHash& id, Value::Id vid) const
{
    auto s = findStorage(id);
    if (s != store.end())
        return s->getById(vid);
    return {};
}

std::vector<std::shared_ptr<Value>>
Dht::getPut(const InfoHash& id)
{
    std::vector<std::shared_ptr<Value>> ret;
    auto find_values = [&](std::map<InfoHash, std::shared_ptr<Search>> srs) {
        auto srp = srs.find(id);
        if (srp == srs.end())
            return;
        auto& search = srp->second;
        ret.reserve(ret.size() + search->announce.size());
        for (const auto& a : search->announce)
            ret.push_back(a.value);
    };
    find_values(searches4);
    find_values(searches6);
    return ret;
}

std::shared_ptr<Value>
Dht::getPut(const InfoHash& id, const Value::Id& vid)
{
    auto find_value = [&](std::map<InfoHash, std::shared_ptr<Search>> srs) {
        auto srp = srs.find(id);
        if (srp == srs.end())
            return std::shared_ptr<Value> {};
        auto& search = srp->second;
        for (auto& a : search->announce) {
            if (a.value->id == vid)
                return a.value;
        }
        return std::shared_ptr<Value> {};
    };
    auto v4 = find_value(searches4);
    if (v4) return v4;
    auto v6 = find_value(searches6);
    if (v6) return v6;
    return {};
}

bool
Dht::cancelPut(const InfoHash& id, const Value::Id& vid)
{
    bool canceled {false};
    auto sr_cancel_put = [&](std::map<InfoHash, std::shared_ptr<Search>> srs) {
        auto srp = srs.find(id);
        if (srp == srs.end())
            return;

        auto& sr = srp->second;
        for (auto it = sr->announce.begin(); it != sr->announce.end();) {
            if (it->value->id == vid) {
                canceled = true;
                it = sr->announce.erase(it);
            }
            else
                ++it;
        }
    };
    sr_cancel_put(searches4);
    sr_cancel_put(searches6);
    return canceled;
}


// Storage

decltype(Dht::store)::iterator
Dht::findStorage(const InfoHash& id)
{
    return std::find_if(store.begin(), store.end(), [&](const Storage& st) {
        return st.id == id;
    });
}
decltype(Dht::store)::const_iterator
Dht::findStorage(const InfoHash& id) const
{
    return std::find_if(store.cbegin(), store.cend(), [&](const Storage& st) {
        return st.id == id;
    });
}

void
Dht::storageChanged(Storage& st, ValueStorage& v)
{
    if (not st.local_listeners.empty()) {
        std::vector<std::pair<GetCallback, std::vector<std::shared_ptr<Value>>>> cbs;
        DHT_LOG.DEBUG("Storage changed. Sending update to %lu local listeners.", st.local_listeners.size());
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
        DHT_LOG.DEBUG("Storage changed. Sending update to %s.", l.first->toString().c_str());
        std::vector<std::shared_ptr<Value>> vals;
        vals.push_back(v.data);
        Blob ntoken = makeToken((const sockaddr*)&l.first->ss, false);
        network_engine.tellListener(l.first, l.second.rid, st.id, 0, ntoken, {}, {}, vals);
    }
}

bool
Dht::storageStore(const InfoHash& id, const std::shared_ptr<Value>& value, time_point created)
{
    const auto& now = scheduler.time();
    created = std::min(created, now);
    auto st = findStorage(id);
    if (st == store.end()) {
        if (store.size() >= MAX_HASHES)
            return false;
        store.emplace_back(id, now);
        st = std::prev(store.end());
    }

    auto store = st->store(value, created, max_store_size - total_store_size);
    if (std::get<0>(store)) {
        total_store_size += std::get<1>(store);
        total_values += std::get<2>(store);
        storageChanged(*st, *std::get<0>(store));
    }
    return std::get<0>(store);
}

std::tuple<Dht::ValueStorage*, ssize_t, ssize_t>
Dht::Storage::store(const std::shared_ptr<Value>& value, time_point created, ssize_t size_left) {

    auto it = std::find_if (values.begin(), values.end(), [&](const ValueStorage& vr) {
        return vr.data == value || vr.data->id == value->id;
    });
    if (it != values.end()) {
        /* Already there, only need to refresh */
        it->time = created;
        ssize_t size_diff = value->size() - it->data->size();
        if (size_diff <= size_left and it->data != value) {
            //DHT_LOG.DEBUG("Updating %s -> %s", id.toString().c_str(), value->toString().c_str());
            it->data = value;
            total_size += size_diff;
            return std::make_tuple(&(*it), size_diff, 0);
        }
        return std::make_tuple(nullptr, 0, 0);
    } else {
        //DHT_LOG.DEBUG("Storing %s -> %s", id.toString().c_str(), value->toString().c_str());
        ssize_t size = value->size();
        if (size <= size_left and values.size() < MAX_VALUES) {
            total_size += size;
            values.emplace_back(value, created);
            return std::make_tuple(&values.back(), size, 1);
        }
        return std::make_tuple(nullptr, 0, 0);
    }
}

void
Dht::Storage::clear()
{
    values.clear();
    total_size = 0;
}

void
Dht::storageAddListener(const InfoHash& id, const std::shared_ptr<Node>& node, size_t rid)
{
    const auto& now = scheduler.time();
    auto st = findStorage(id);
    if (st == store.end()) {
        if (store.size() >= MAX_HASHES)
            return;
        store.emplace_back(id, now);
        st = std::prev(store.end());
    }
    auto l = st->listeners.find(node);
    if (l == st->listeners.end()) {
        const auto& stvalues = st->getValues();
        if (not stvalues.empty()) {
            std::vector<std::shared_ptr<Value>> values(stvalues.size());
            std::transform(stvalues.begin(), stvalues.end(), values.begin(), [=](const ValueStorage& vs) { return vs.data; });

            network_engine.tellListener(node, rid, id, WANT4 | WANT6, makeToken((sockaddr*)&node->ss, false),
                    buckets.findClosestNodes(id, now, TARGET_NODES), buckets6.findClosestNodes(id, now, TARGET_NODES),
                    values);
        }
        st->listeners.emplace(node, Listener {rid, now});
    }
    else
        l->second.refresh(rid, now);
}

void
Dht::expireStorage()
{
    const auto& now = scheduler.time();
    auto i = store.begin();
    while (i != store.end()) {
        for (auto l = i->listeners.cbegin(); l != i->listeners.cend();){
            bool expired = l->second.time + Node::NODE_EXPIRE_TIME < now;
            if (expired) {
                DHT_LOG.DEBUG("Discarding expired listener %s", l->first->id.toString().c_str());
                i->listeners.erase(l++);
            } else
                ++l;
        }

        auto stats = i->expire(types, now);
        total_store_size += stats.first;
        total_values += stats.second;

        if (i->empty() && i->listeners.empty() && i->local_listeners.empty()) {
            DHT_LOG.DEBUG("Discarding expired value %s", i->id.toString().c_str());
            i = store.erase(i);
        }
        else
            ++i;
    }
}

std::pair<ssize_t, ssize_t>
Dht::Storage::expire(const std::map<ValueType::Id, ValueType>& types, time_point now)
{
    auto r = std::partition(values.begin(), values.end(), [&](const ValueStorage& v) {
        if (!v.data) return false; // should not happen
        auto type_it = types.find(v.data->type);
        const ValueType& type = (type_it == types.end()) ? ValueType::USER_DATA : type_it->second;
        bool expired = v.time + type.expiration < now;
        //if (expired)
        //    DHT_LOG.DEBUG("Discarding expired value %s", v.data->toString().c_str());
        return !expired;
    });
    ssize_t del_num = std::distance(r, values.end());
    ssize_t size_diff {};
    std::for_each(r, values.end(), [&](const ValueStorage& v){
        size_diff -= v.data->size();
    });
    total_size += size_diff;
    values.erase(r, values.end());
    return {size_diff, -del_num};
}

void
Dht::connectivityChanged()
{
    const auto& now = scheduler.time();
    scheduler.edit(nextNodesConfirmation, now);
    mybucket_grow_time = now;
    mybucket6_grow_time = now;
    reported_addr.clear();
    network_engine.connectivityChanged();
    auto stop_listen = [&](std::map<InfoHash, std::shared_ptr<Search>> srs) {
        for (auto& sp : srs)
            for (auto& sn : sp.second->nodes)
                sn.listenStatus.reset();
    };
    stop_listen(searches4);
    stop_listen(searches6);
}

void
Dht::rotateSecrets()
{
    const auto& now = scheduler.time();
    uniform_duration_distribution<> time_dist(std::chrono::minutes(15), std::chrono::minutes(45));
    auto rotate_secrets_time = now + time_dist(rd);

    oldsecret = secret;
    {
        crypto::random_device rdev;
        std::generate_n(secret.begin(), secret.size(), std::bind(rand_byte, std::ref(rdev)));
    }
    scheduler.add(rotate_secrets_time, std::bind(&Dht::rotateSecrets, this));
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
    const auto& now = scheduler.time();
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
        if (b.cached)
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
    const auto& now = scheduler.time();
    using namespace std::chrono;
    out << b.first << " count " << b.nodes.size() << " age " << duration_cast<seconds>(now - b.time).count() << " sec";
    if (b.cached)
        out << " (cached)";
    out  << std::endl;
    for (auto& n : b.nodes) {
        out << "    Node " << n->toString();
        if (n->time != n->reply_time)
            out << " age " << duration_cast<seconds>(now - n->time).count() << ", reply: " << duration_cast<seconds>(now - n->reply_time).count();
        else
            out << " age " << duration_cast<seconds>(now - n->time).count();
        if (n->isExpired())
            out << " [expired]";
        else if (n->isGood(now))
            out << " [good]";
        out << std::endl;
    }
}

void
Dht::dumpSearch(const Search& sr, std::ostream& out) const
{
    const auto& now = scheduler.time();
    using namespace std::chrono;
    out << std::endl << "Search IPv" << (sr.af == AF_INET6 ? '6' : '4') << ' ' << sr.id << " gets: " << sr.callbacks.size();
    out << ", age: " << duration_cast<seconds>(now - sr.step_time).count() << " s";
    if (sr.done)
        out << " [done]";
    if (sr.expired)
        out << " [expired]";
    bool synced = sr.isSynced(now);
    out << (synced ? " [synced]" : " [not synced]");
    if (synced && sr.isListening(now)) {
        auto lt = sr.getListenTime(now);
        out << " [listening, next in " << duration_cast<seconds>(lt-now).count() << " s]";
    }
    out << std::endl;

    for (const auto& n : sr.announce) {
        bool announced = sr.isAnnounced(n.value->id, getType(n.value->type), now);
        out << "Announcement: " << *n.value << (announced ? " [announced]" : "") << std::endl;
    }

    out << " Common bits    InfoHash                       Conn. Get   Ops  IP" << std::endl;
    unsigned i = 0;
    auto last_get = sr.getLastGetTime();
    for (const auto& n : sr.nodes) {
        i++;
        out << std::setfill (' ') << std::setw(3) << InfoHash::commonBits(sr.id, n.node->id) << ' ' << n.node->id;
        out << ' ' << (findNode(n.node->id, sr.af) ? '*' : ' ');
        out << " [";
        if (auto pendingCount = n.node->getPendingMessageCount())
            out << pendingCount;
        else
            out << ' ';
        out << (n.node->isExpired() ? 'x' : ' ') << "]";

        // Get status
        {
            char g_i = (n.getStatus && n.getStatus->pending()) ? (n.candidate ? 'c' : 'f') : ' ';
            char s_i = n.isSynced(now) ? (n.last_get_reply > last_get ? 'u' : 's') : '-';
            out << " [" << s_i << g_i << "] ";
        }

        // Listen status
        if (not sr.listeners.empty()) {
            if (not n.listenStatus)
                out << "    ";
            else
                out << "["
                    << (n.isListening(now) ? 'l' : (n.listenStatus->pending() ? 'f' : ' ')) << "] ";
        }

        // Announce status
        if (not sr.announce.empty()) {
            if (n.acked.empty()) {
                out << "   ";
                for (size_t a=0; a < sr.announce.size(); a++)
                    out << ' ';
            } else {
                out << "[";
                for (const auto& a : sr.announce) {
                    auto ack = n.acked.find(a.value->id);
                    if (ack == n.acked.end() or not ack->second) {
                        out << ' ';
                    } else {
                        if (ack->second->reply_time + getType(a.value->type).expiration > now)
                            out << 'a';
                        else if (ack->second->pending())
                            out << 'f';
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

    auto dump_searches = [&](std::map<InfoHash, std::shared_ptr<Search>> srs) {
        for (auto& srp : srs)
            dumpSearch(*srp.second, out);
    };
    dump_searches(searches4);
    dump_searches(searches6);
    out << std::endl;

    out << getStorageLog() << std::endl;

    DHT_LOG.DEBUG("%s", out.str().c_str());
}

std::string
Dht::getStorageLog() const
{
    const auto& now = scheduler.time();
    using namespace std::chrono;
    std::stringstream out;
    for (const auto& st : store) {
        out << "Storage " << st.id << " " << st.listeners.size() << " list., " << st.valueCount() << " values (" << st.totalSize() << " bytes)" << std::endl;
        if (not st.local_listeners.empty())
            out << "   " << st.local_listeners.size() << " local listeners" << std::endl;
        for (const auto& l : st.listeners) {
            out << "   " << "Listener " << l.first->toString();
            auto since = duration_cast<seconds>(now - l.second.time);
            auto expires = duration_cast<seconds>(l.second.time + Node::NODE_EXPIRE_TIME - now);
            out << " (since " << since.count() << "s, exp in " << expires.count() << "s)" << std::endl;
        }
    }
    out << "Total " << store.size() << " storages, " << total_values << " values (" << (total_store_size/1024) << " ĶB)" << std::endl;
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
    if (not af or af == AF_INET)
        for (const auto& sr : searches4)
            dumpSearch(*sr.second, out);
    if (not af or af == AF_INET6)
        for (const auto& sr : searches6)
            dumpSearch(*sr.second, out);
    return out.str();
}

Dht::~Dht()
{
    for (auto& s : searches4)
        s.second->clear();
    for (auto& s : searches6)
        s.second->clear();
}

Dht::Dht() : store(), network_engine(DHT_LOG, scheduler) {}

Dht::Dht(int s, int s6, Config config)
 : myid(config.node_id), is_bootstrap(config.is_bootstrap), store(),
    network_engine(myid, config.network, s, s6, DHT_LOG, scheduler,
            std::bind(&Dht::onError, this, _1, _2),
            std::bind(&Dht::onNewNode, this, _1, _2),
            std::bind(&Dht::onReportedAddr, this, _1, _2, _3),
            std::bind(&Dht::onPing, this, _1),
            std::bind(&Dht::onFindNode, this, _1, _2, _3),
            std::bind(&Dht::onGetValues, this, _1, _2, _3),
            std::bind(&Dht::onListen, this, _1, _2, _3, _4),
            std::bind(&Dht::onAnnounce, this, _1, _2, _3, _4, _5))
{
    scheduler.syncTime();
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

    uniform_duration_distribution<> time_dis {std::chrono::seconds(3), std::chrono::seconds(5)};
    auto confirm_nodes_time = scheduler.time() + time_dis(rd);
    DHT_LOG.DEBUG("Scheduling %s", myid.toString().c_str());
    nextNodesConfirmation = scheduler.add(confirm_nodes_time, std::bind(&Dht::confirmNodes, this));

    // Fill old secret
    {
        crypto::random_device rdev;
        std::generate_n(secret.begin(), secret.size(), std::bind(rand_byte, std::ref(rdev)));
    }
    rotateSecrets();

    expire();

    DHT_LOG.DEBUG("DHT initialised with node ID %s", myid.toString().c_str());
}


bool
Dht::neighbourhoodMaintenance(RoutingTable& list)
{
    //DHT_LOG.DEBUG("neighbourhoodMaintenance");
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
    auto n = q->randomNode();
    if (n) {
        DHT_LOG.DEBUG("[find %s IPv%c] sending find for neighborhood maintenance.", id.toString().c_str(), q->af == AF_INET6 ? '6' : '4');
        network_engine.sendFindNode(n, id, network_engine.want(), nullptr, nullptr);
    }

    return true;
}

bool
Dht::bucketMaintenance(RoutingTable& list)
{
    std::bernoulli_distribution rand_trial(1./8.);
    std::bernoulli_distribution rand_trial_38(1./38.);

    for (auto b = list.begin(); b != list.end(); ++b) {
        if (b->time < scheduler.time() - std::chrono::minutes(10) || b->nodes.empty()) {
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

                if (network_engine.want() != want) {
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

                DHT_LOG.DEBUG("[find %s IPv%c] sending for bucket maintenance.", id.toString().c_str(), q->af == AF_INET6 ? '6' : '4');
                network_engine.sendFindNode(n, id, want, nullptr, nullptr);
                /* In order to avoid sending queries back-to-back,
                   give up for now and reschedule us soon. */
                return true;
            }
        }
    }
    return false;
}

void
Dht::dataPersistence() {
    const auto& now = scheduler.time();
    auto storage_maintenance_time = time_point::max();
    for (auto &str : store) {
        if (now > str.maintenance_time) {
            maintainStorage(str.id);
            str.maintenance_time = now + MAX_STORAGE_MAINTENANCE_EXPIRE_TIME;
        }
        storage_maintenance_time = std::min(storage_maintenance_time, str.maintenance_time);
    }
    scheduler.add(storage_maintenance_time, std::bind(&Dht::dataPersistence, this));
}

size_t
Dht::maintainStorage(InfoHash id, bool force, DoneCallback donecb) {
    const auto& now = scheduler.time();
    size_t announce_per_af = 0;
    auto local_storage = findStorage(id);
    if (local_storage == store.end()) { return 0; }

    bool want4 = true, want6 = true;

    auto nodes = buckets.findClosestNodes(id, now);
    if (!nodes.empty()) {
        if (force || id.xorCmp(nodes.back()->id, myid) < 0) {
            for (auto &value : local_storage->getValues()) {
                const auto& vt = getType(value.data->type);
                if (force || value.time + vt.expiration > now + MAX_STORAGE_MAINTENANCE_EXPIRE_TIME) {
                    // gotta put that value there
                    announce(id, AF_INET, value.data, donecb, value.time);
                    ++announce_per_af;
                }
            }
            want4 = false;
        }
    }
    else { want4 = false; }

    auto nodes6 = buckets6.findClosestNodes(id, now);
    if (!nodes6.empty()) {
        if (force || id.xorCmp(nodes6.back()->id, myid) < 0) {
            for (auto &value : local_storage->getValues()) {
                const auto& vt = getType(value.data->type);
                if (force || value.time + vt.expiration > now + MAX_STORAGE_MAINTENANCE_EXPIRE_TIME) {
                    // gotta put that value there
                    announce(id, AF_INET6, value.data, donecb, value.time);
                    ++announce_per_af;
                }
            }
            want6 = false;
        }
    }
    else { want6 = false; }

    if (not want4 and not want6) {
        DHT_LOG.DEBUG("Discarding storage values %s", id.toString().c_str());
        local_storage->clear();
    }

    return announce_per_af;
}

void
Dht::processMessage(const uint8_t *buf, size_t buflen, const sockaddr *from, socklen_t fromlen)
{
    if (buflen == 0)
        return;

    try {
        network_engine.processMessage(buf, buflen, from, fromlen);
    } catch (const std::exception& e) {
        DHT_LOG.ERR("Can't parse message from %s: %s", print_addr(from, fromlen).c_str(), e.what());
        //auto code = e.getCode();
        //if (code == DhtProtocolException::INVALID_TID_SIZE or code == DhtProtocolException::WRONG_NODE_INFO_BUF_LEN) {
            /* This is really annoying, as it means that we will
               time-out all our searches that go through this node.
               Kill it. */
            //const auto& id = e.getNodeId();
            //blacklistNode(&id, from, fromlen);
        ///}
    }
}

time_point
Dht::periodic(const uint8_t *buf, size_t buflen, const sockaddr *from, socklen_t fromlen)
{
    scheduler.syncTime();
    processMessage(buf, buflen, from, fromlen);
    return scheduler.run();
}

void
Dht::expire()
{
    uniform_duration_distribution<> time_dis(std::chrono::minutes(2), std::chrono::minutes(6));
    auto expire_stuff_time = scheduler.time() + duration(time_dis(rd));

    expireBuckets(buckets);
    expireBuckets(buckets6);
    expireStorage();
    expireSearches();
    scheduler.add(expire_stuff_time, std::bind(&Dht::expire, this));
}

void
Dht::confirmNodes()
{
    using namespace std::chrono;
    bool soon = false;
    const auto& now = scheduler.time();

    if (searches4.empty() and getStatus(AF_INET) != NodeStatus::Disconnected) {
        DHT_LOG.DEBUG("[confirm nodes] initial IPv4 'get' for my id (%s).", myid.toString().c_str());
        search(myid, AF_INET);
    }
    if (searches6.empty() and getStatus(AF_INET6) != NodeStatus::Disconnected) {
        DHT_LOG.DEBUG("[confirm nodes] initial IPv6 'get' for my id (%s).", myid.toString().c_str());
        search(myid, AF_INET6);
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
    auto confirm_nodes_time = now + time_dis(rd);

    nextNodesConfirmation = scheduler.add(confirm_nodes_time, std::bind(&Dht::confirmNodes, this));
}

std::vector<ValuesExport>
Dht::exportValues() const
{
    std::vector<ValuesExport> e {};
    e.reserve(store.size());
    for (const auto& h : store) {
        ValuesExport ve;
        ve.first = h.id;

        msgpack::sbuffer buffer;
        msgpack::packer<msgpack::sbuffer> pk(&buffer);
        pk.pack_array(h.getValues().size());
        for (const auto& v : h.getValues()) {
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
            msgpack::unpack(msg, (const char*)h.second.data(), h.second.size());
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
                    DHT_LOG.ERR("Error reading value at %s", h.first.toString().c_str());
                    continue;
                }
                if (val_time + getType(tmp_val.type).expiration < scheduler.time()) {
                    DHT_LOG.DEBUG("Discarding expired value at %s", h.first.toString().c_str());
                    continue;
                }
                storageStore(h.first, std::make_shared<Value>(std::move(tmp_val)), val_time);
            }
        } catch (const std::exception&) {
            DHT_LOG.ERR("Error reading values at %s", h.first.toString().c_str());
            continue;
        }
    }
}


std::vector<NodeExport>
Dht::exportNodes()
{
    const auto& now = scheduler.time();
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
Dht::insertNode(const InfoHash& id, const sockaddr* sa, socklen_t salen)
{
    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
        return false;
    scheduler.syncTime();
    auto n = network_engine.insertNode(id, sa, salen);
    return !!n;
}

int
Dht::pingNode(const sockaddr *sa, socklen_t salen)
{
    scheduler.syncTime();
    DHT_LOG.DEBUG("Sending ping to %s", print_addr(sa, salen).c_str());
    network_engine.sendPing(sa, salen, nullptr, nullptr);
    return -1;
}

void
Dht::onError(std::shared_ptr<Request> req, DhtProtocolException e) {
    if (e.getCode() == DhtProtocolException::UNAUTHORIZED) {
        network_engine.cancelRequest(req);
        unsigned cleared = 0;
        for (auto& srp : req->node->getFamily() == AF_INET ? searches4 : searches6) {
            auto& sr = srp.second;
            for (auto& n : sr->nodes) {
                if (n.node != req->node) continue;
                n.token.clear();
                n.last_get_reply = time_point::min();
                cleared++;
                searchSendGetValues(sr);
                break;
            }
        }
        DHT_LOG.WARN("[node %s] token flush (%d searches affected)", req->node->toString().c_str(), cleared);
    }
}

void
Dht::onReportedAddr(const InfoHash& id, sockaddr* addr , socklen_t addr_length)
{
    const auto& b = (addr->sa_family == AF_INET ? buckets : buckets6).findBucket(id);
    b->time = scheduler.time();
    if (addr and addr_length)
        reportedAddr(addr, addr_length);
}

NetworkEngine::RequestAnswer
Dht::onPing(std::shared_ptr<Node>)
{
    return {};
}

NetworkEngine::RequestAnswer
Dht::onFindNode(std::shared_ptr<Node> node, InfoHash& target, want_t want)
{
    const auto& now = scheduler.time();
    NetworkEngine::RequestAnswer answer;
    answer.ntoken = makeToken((sockaddr*)&node->ss, false);
    if (want & WANT4)
        answer.nodes4 = buckets.findClosestNodes(target, now, TARGET_NODES);
    if (want & WANT6)
        answer.nodes6 = buckets6.findClosestNodes(target, now, TARGET_NODES);
    return answer;
}

NetworkEngine::RequestAnswer
Dht::onGetValues(std::shared_ptr<Node> node, InfoHash& hash, want_t)
{
    if (hash == zeroes) {
        DHT_LOG.WARN("[node %s] Eek! Got get_values with no info_hash.", node->toString().c_str());
        throw DhtProtocolException {DhtProtocolException::NON_AUTHORITATIVE_INFORMATION, DhtProtocolException::GET_NO_INFOHASH};
    }
    const auto& now = scheduler.time();
    NetworkEngine::RequestAnswer answer {};
    auto st = findStorage(hash);
    answer.ntoken = makeToken((sockaddr*)&node->ss, false);
    answer.nodes4 = buckets.findClosestNodes(hash, now, TARGET_NODES);
    answer.nodes6 = buckets6.findClosestNodes(hash, now, TARGET_NODES);
    if (st != store.end() && not st->empty()) {
        auto values = st->getValues();
        answer.values.resize(values.size());
        std::transform(values.begin(), values.end(), answer.values.begin(), [](const ValueStorage& vs) {
            return vs.data;
        });
        DHT_LOG.DEBUG("[node %s] sending %u values.", node->toString().c_str(), answer.values.size());
    } else {
        DHT_LOG.DEBUG("[node %s] sending nodes.", node->toString().c_str());
    }
    return answer;
}

void
Dht::onGetValuesDone(const Request& status,
        NetworkEngine::RequestAnswer& a, std::shared_ptr<Search> sr)
{
    if (not sr) {
        DHT_LOG.WARN("[search unknown] got reply to 'get'. Ignoring.");
        return;
    }

    DHT_LOG.DEBUG("[search %s IPv%c] got reply to 'get' from %s with %u nodes", sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6', status.node->toString().c_str(), a.nodes4.size());

    if (not a.ntoken.empty()) {
        if (!a.values.empty()) {
            DHT_LOG.DEBUG("[search %s IPv%c] found %u values",
                    sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6',
                    a.values.size());
            for (auto& cb : sr->callbacks) {
                if (!cb.get_cb) continue;
                std::vector<std::shared_ptr<Value>> tmp;
                std::copy_if(a.values.begin(), a.values.end(), std::back_inserter(tmp),
                    [&](const std::shared_ptr<Value>& v) {
                        return not static_cast<bool>(cb.filter) or cb.filter(*v);
                    }
                );
                if (not tmp.empty())
                    cb.get_cb(tmp);
            }
            std::vector<std::pair<GetCallback, std::vector<std::shared_ptr<Value>>>> tmp_lists;
            for (auto& l : sr->listeners) {
                if (!l.second.get_cb) continue;
                std::vector<std::shared_ptr<Value>> tmp;
                std::copy_if(a.values.begin(), a.values.end(), std::back_inserter(tmp),
                    [&](const std::shared_ptr<Value>& v) {
                        return not static_cast<bool>(l.second.filter) or l.second.filter(*v);
                    }
                );
                if (not tmp.empty())
                    tmp_lists.emplace_back(l.second.get_cb, tmp);
            }
            for (auto& l : tmp_lists)
                l.first(l.second);
        }
    } else {
        DHT_LOG.WARN("[node %s] no token provided. Ignoring response content.", status.node->toString().c_str());
        network_engine.blacklistNode(status.node);
    }

    if (not sr->done) {
        searchSendGetValues(sr);

        // Force to recompute the next step time
        scheduler.edit(sr->nextSearchStep, scheduler.time());
    }
}

NetworkEngine::RequestAnswer
Dht::onListen(std::shared_ptr<Node> node, InfoHash& hash, Blob& token, size_t rid)
{
    if (hash == zeroes) {
        DHT_LOG.WARN("Listen with no info_hash.");
        throw DhtProtocolException {
            DhtProtocolException::NON_AUTHORITATIVE_INFORMATION,
            DhtProtocolException::LISTEN_NO_INFOHASH
        };
    }
    if (!tokenMatch(token, (sockaddr*)&node->ss)) {
        DHT_LOG.WARN("[node %s] incorrect token %s for 'listen'.", node->toString().c_str(), hash.toString().c_str());
        throw DhtProtocolException {DhtProtocolException::UNAUTHORIZED, DhtProtocolException::LISTEN_WRONG_TOKEN};
    }
    storageAddListener(hash, node, rid);
    return {};
}

void
Dht::onListenDone(const Request& status, NetworkEngine::RequestAnswer& answer, std::shared_ptr<Search>& sr)
{
    DHT_LOG.DEBUG("[search %s] Got reply to listen.", sr->id.toString().c_str());
    if (sr) {
        if (not answer.values.empty()) { /* got new values from listen request */
            DHT_LOG.DEBUG("[listen %s] Got new values.", sr->id.toString().c_str());
            onGetValuesDone(status, answer, sr);
        }

        if (not sr->done) {
            const auto& now = scheduler.time();
            searchSendGetValues(sr);
            scheduler.edit(sr->nextSearchStep, sr->getNextStepTime(types, now));
        }
    } else
        DHT_LOG.DEBUG("Unknown search or announce!");
}

NetworkEngine::RequestAnswer
Dht::onAnnounce(std::shared_ptr<Node> node, InfoHash& hash, Blob& token, std::vector<std::shared_ptr<Value>> values,
        time_point created)
{
    if (hash == zeroes) {
        DHT_LOG.WARN("Put with no info_hash.");
        throw DhtProtocolException {
            DhtProtocolException::NON_AUTHORITATIVE_INFORMATION,
            DhtProtocolException::PUT_NO_INFOHASH
        };
    }
    if (!tokenMatch(token, (sockaddr*)&node->ss)) {
        DHT_LOG.WARN("[node %s] incorrect token %s for 'put'.", node->toString().c_str(), hash.toString().c_str());
        throw DhtProtocolException {DhtProtocolException::UNAUTHORIZED, DhtProtocolException::PUT_WRONG_TOKEN};
    }
    {
        // We store a value only if we think we're part of the
        // SEARCH_NODES nodes around the target id.
        auto closest_nodes = (node->getFamily() == AF_INET ? buckets : buckets6)
                                .findClosestNodes(hash, scheduler.time(), SEARCH_NODES);
        if (closest_nodes.size() >= TARGET_NODES and hash.xorCmp(closest_nodes.back()->id, myid) < 0) {
            DHT_LOG.WARN("[node %s] announce too far from the target. Dropping value.", node->toString().c_str());
            return {};
        }
    }

    for (const auto& v : values) {
        if (v->id == Value::INVALID_ID) {
            DHT_LOG.WARN("[value %s %s] incorrect value id", hash.toString().c_str(), v->id);
            throw DhtProtocolException {
                DhtProtocolException::NON_AUTHORITATIVE_INFORMATION,
                DhtProtocolException::PUT_INVALID_ID
            };
        }
        auto lv = getLocalById(hash, v->id);
        std::shared_ptr<Value> vc = v;
        if (lv) {
            if (*lv == *vc) {
                DHT_LOG.WARN("[value %s %lu] nothing to do.", hash.toString().c_str(), lv->id);
            } else {
                const auto& type = getType(lv->type);
                if (type.editPolicy(hash, lv, vc, node->id, (sockaddr*)&node->ss, node->sslen)) {
                    DHT_LOG.DEBUG("[value %s %lu] editing %s.",
                            hash.toString().c_str(), lv->id, vc->toString().c_str());
                    storageStore(hash, vc, created);
                } else {
                    DHT_LOG.DEBUG("[value %s %lu] rejecting edition of %s because of storage policy.",
                            hash.toString().c_str(), lv->id, vc->toString().c_str());
                }
            }
        } else {
            // Allow the value to be edited by the storage policy
            const auto& type = getType(vc->type);
            if (type.storePolicy(hash, vc, node->id, (sockaddr*)&node->ss, node->sslen)) {
                DHT_LOG.DEBUG("[value %s %lu] storing %s.", hash.toString().c_str(), vc->id, vc->toString().c_str());
                storageStore(hash, vc, created);
            } else {
                DHT_LOG.DEBUG("[value %s %lu] rejecting storage of %s.",
                        hash.toString().c_str(), vc->id, vc->toString().c_str());
            }
        }
    }
    return {};
}

void
Dht::onAnnounceDone(const Request&, NetworkEngine::RequestAnswer& answer,
        std::shared_ptr<Search>& sr)
{
    const auto& now = scheduler.time();
    DHT_LOG.DEBUG("[search %s IPv%c] got reply to put!",
            sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6');

    searchSendGetValues(sr);

    // If the value was just successfully announced, call the callback
    sr->announce.erase(std::remove_if(sr->announce.begin(), sr->announce.end(),
        [&](Announce& a) {
            if (!a.value || a.value->id != answer.vid)
                return false;
            auto type = getType(a.value->type);
            if (sr->isAnnounced(answer.vid, type, now)) {
                if (a.callback) {
                    a.callback(true, sr->getNodes());
                    a.callback = nullptr;
                }
                if (not a.permanent)
                    return true;
            }
            return false;
    }), sr->announce.end());
}

}
