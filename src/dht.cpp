/*
 *  Copyright (C) 2014-2018 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
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


#include "dht.h"
#include "rng.h"
#include "search.h"
#include "storage.h"
#include "request.h"

#include <msgpack.hpp>

#include <algorithm>
#include <random>
#include <sstream>

namespace dht {

using namespace std::placeholders;

constexpr std::chrono::minutes Dht::MAX_STORAGE_MAINTENANCE_EXPIRE_TIME;
constexpr std::chrono::minutes Dht::SEARCH_EXPIRE_TIME;
constexpr std::chrono::seconds Dht::LISTEN_EXPIRE_TIME;
constexpr std::chrono::seconds Dht::REANNOUNCE_MARGIN;

NodeStatus
Dht::getStatus(sa_family_t af) const
{
    const auto& stats = getNodesStats(af);
    if (stats.good_nodes)
        return NodeStatus::Connected;
    auto& ping = af == AF_INET ? pending_pings4 : pending_pings6;
    if (ping or stats.getKnownNodes())
        return NodeStatus::Connecting;
    return NodeStatus::Disconnected;
}

void
Dht::shutdown(ShutdownCallback cb)
{
    if (not maintain_storage) {
        if (cb) cb();
        return;
    }

    // Last store maintenance
    scheduler.syncTime();
    auto remaining = std::make_shared<int>(0);
    auto str_donecb = [=](bool, const std::vector<Sp<Node>>&) {
        --*remaining;
        DHT_LOG.w("shuting down node: %u ops remaining", *remaining);
        if (!*remaining && cb) { cb(); }
    };

    for (auto& str : store)
        *remaining += maintainStorage(str, true, str_donecb);

    if (!*remaining) {
        DHT_LOG.w("shuting down node: %u ops remaining", *remaining);
        if (cb)
            cb();
    }
}

bool
Dht::isRunning(sa_family_t af) const { return network_engine.isRunning(af); }

/* Every bucket contains an unordered list of nodes. */
const Sp<Node>
Dht::findNode(const InfoHash& id, sa_family_t af) const
{
    if (const Bucket* b = findBucket(id, af))
        for (const auto& n : b->nodes)
            if (n->id == id) return n;
    return {};
}

/* Every bucket caches the address of a likely node.  Ping it. */
void
Dht::sendCachedPing(Bucket& b)
{
    if (b.cached)
        DHT_LOG.d(b.cached->id, "[node %s] sending ping to cached node", b.cached->toString().c_str());
    b.sendCachedPing(network_engine);
}

std::vector<SockAddr>
Dht::getPublicAddress(sa_family_t family)
{
    std::sort(reported_addr.begin(), reported_addr.end(), [](const ReportedAddr& a, const ReportedAddr& b) {
        return a.first > b.first;
    });
    std::vector<SockAddr> ret;
    ret.reserve(!family ? reported_addr.size() : reported_addr.size()/2);
    for (const auto& addr : reported_addr)
        if (!family || family == addr.second.getFamily())
            ret.emplace_back(addr.second);
    return ret;
}

bool
Dht::trySearchInsert(const Sp<Node>& node)
{
    const auto& now = scheduler.time();
    if (not node) return false;

    auto& srs = searches(node->getFamily());
    auto closest = srs.lower_bound(node->id);
    bool inserted {false};

    // insert forward
    auto it = closest;
    while (it != srs.end()) {
        auto& s = *it->second;
        if (s.insertNode(node, now)) {
            inserted = true;
            scheduler.edit(s.nextSearchStep, now);
        } else if (not s.expired and not s.done)
            break;
        ++it;
    }
    // insert backward
    it = closest;
    while (it != srs.begin()) {
        --it;
        auto& s = *it->second;
        if (s.insertNode(node, now)) {
            inserted = true;
            scheduler.edit(s.nextSearchStep, now);
        } else if (not s.expired and not s.done)
            break;
    }
    return inserted;
}

void
Dht::reportedAddr(const SockAddr& addr)
{
    auto it = std::find_if(reported_addr.begin(), reported_addr.end(), [&](const ReportedAddr& a){
        return a.second == addr;
    });
    if (it == reported_addr.end()) {
        if (reported_addr.size() < 32)
            reported_addr.emplace_back(1, addr);
    } else
        it->first++;
}

/* We just learnt about a node, not necessarily a new one.  Confirm is 1 if
   the node sent a message, 2 if it sent us a reply. */
void
Dht::onNewNode(const Sp<Node>& node, int confirm)
{
    if (buckets(node->getFamily()).onNewNode(node, confirm, scheduler.time(), myid, network_engine) or confirm) {
        trySearchInsert(node);
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
        b.nodes.remove_if([this,&changed](const Sp<Node>& n) {
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

void
Dht::expireSearches()
{
    auto t = scheduler.time() - SEARCH_EXPIRE_TIME;
    auto expired = [&](std::pair<const InfoHash, Sp<Search>>& srp) {
        auto& sr = *srp.second;
        auto b = sr.callbacks.empty() && sr.announce.empty() && sr.listeners.empty() && sr.step_time < t;
        if (b) {
            DHT_LOG.d(srp.first, "[search %s] removing search", srp.first.toString().c_str());
            sr.clear();
            return b;
        } else { return false; }
    };
    erase_if(searches4, expired);
    erase_if(searches6, expired);
}

void
Dht::searchNodeGetDone(const net::Request& req,
        net::RequestAnswer&& answer,
        std::weak_ptr<Search> ws,
        Sp<Query> query)
{
    const auto& now = scheduler.time();
    if (auto sr = ws.lock()) {
        sr->insertNode(req.node, now, answer.ntoken);
        if (auto srn = sr->getNode(req.node)) {
            /* all other get requests which are satisfied by this answer
               should not be sent anymore */
            for (auto& g : sr->callbacks) {
                auto& q = g.second.query;
                if (q->isSatisfiedBy(*query) and q != query) {
                    auto dummy_req = std::make_shared<net::Request>();
                    dummy_req->cancel();
                    srn->getStatus[q] = std::move(dummy_req);
                }
            }
            auto syncTime = srn->getSyncTime(scheduler.time());
            if (srn->syncJob)
                scheduler.edit(srn->syncJob, syncTime);
            else
                srn->syncJob = scheduler.add(syncTime, std::bind(&Dht::searchStep, this, sr));
        }
        onGetValuesDone(req.node, answer, sr, query);
    }
}

void
Dht::searchNodeGetExpired(const net::Request& status,
        bool over,
        std::weak_ptr<Search> ws,
        Sp<Query> query)
{
    if (auto sr = ws.lock()) {
        if (auto srn = sr->getNode(status.node)) {
            srn->candidate = not over;
            if (over)
                srn->getStatus.erase(query);
        }
        scheduler.edit(sr->nextSearchStep, scheduler.time());
    }
}

void Dht::paginate(std::weak_ptr<Search> ws, Sp<Query> query, SearchNode* n) {
    auto sr = ws.lock();
    if (not sr) return;
    auto select_q = std::make_shared<Query>(Select {}.field(Value::Field::Id), query ? query->where : Where {});
    auto onSelectDone = [this,ws,query](const net::Request& status,
                                        net::RequestAnswer&& answer) mutable {
        // retreive search
        auto sr = ws.lock();
        if (not sr) return;
        const auto& id = sr->id;
        // retreive search node
        auto sn = sr->getNode(status.node);
        if (not sn) return;
        // backward compatibility
        if (answer.fields.empty()) {
            searchNodeGetDone(status, std::move(answer), ws, query);
            return;
        }
        for (const auto& fvi : answer.fields) {
            try {
                auto vid = fvi->index.at(Value::Field::Id).getInt();
                if (vid == Value::INVALID_ID) continue;
                auto query_for_vid = std::make_shared<Query>(Select {}, Where {}.id(vid));
                sn->pagination_queries[query].push_back(query_for_vid);
                DHT_LOG.w(id, sn->node->id, "[search %s] [node %s] sending %s",
                        id.toString().c_str(), sn->node->toString().c_str(), query_for_vid->toString().c_str());
                sn->getStatus[query_for_vid] = network_engine.sendGetValues(status.node,
                        id,
                        *query_for_vid,
                        -1,
                        std::bind(&Dht::searchNodeGetDone, this, _1, _2, ws, query),
                        std::bind(&Dht::searchNodeGetExpired, this, _1, _2, ws, query_for_vid)
                        );
            } catch (const std::out_of_range&) {
                DHT_LOG.e(id, sn->node->id, "[search %s] [node %s] received non-id field in response to "\
                        "'SELECT id' request...",
                        id.toString().c_str(), sn->node->toString().c_str());
            }
        }
    };
    /* add pagination query key for tracking ongoing requests. */
    n->pagination_queries[query].push_back(select_q);

    DHT_LOG.w(sr->id, n->node->id, "[search %s] [node %s] sending %s",
            sr->id.toString().c_str(), n->node->toString().c_str(), select_q->toString().c_str());
    n->getStatus[select_q] = network_engine.sendGetValues(n->node,
            sr->id,
            *select_q,
            -1,
            onSelectDone,
            std::bind(&Dht::searchNodeGetExpired, this, _1, _2, ws, select_q)
            );
}

Dht::SearchNode*
Dht::searchSendGetValues(Sp<Search> sr, SearchNode* pn, bool update)
{
    if (sr->done or sr->currentlySolicitedNodeCount() >= MAX_REQUESTED_SEARCH_NODES)
        return nullptr;

    const auto& now = scheduler.time();

    std::weak_ptr<Search> ws = sr;
    auto cb = sr->callbacks.begin();
    do { /* for all requests to send */
        SearchNode* n = nullptr;
        auto query = not sr->callbacks.empty() ? cb->second.query : std::make_shared<Query>(Select {}, Where {}, true);
        const time_point up = not sr->callbacks.empty() and update
                                ? sr->getLastGetTime(query)
                                : time_point::min();

        if (pn and pn->canGet(now, up, query)) {
            n = pn;
        } else {
            for (auto& sn : sr->nodes) {
                if (sn.canGet(now, up, query)) {
                    n = &sn;
                    break;
                }
            }
        }

        if (sr->callbacks.empty()) { /* 'find_node' request */
            if (not n)
                return nullptr;

            /*DHT_LOG.d(sr->id, n->node->id, "[search %s] [node %s] sending 'find_node'",
                    sr->id.toString().c_str(), n->node->toString().c_str());*/
            n->getStatus[query] = network_engine.sendFindNode(n->node,
                    sr->id,
                    -1,
                    std::bind(&Dht::searchNodeGetDone, this, _1, _2, ws, query),
                    std::bind(&Dht::searchNodeGetExpired, this, _1, _2, ws, query));

        } else { /* 'get' request */
            if (not n)
                continue;

            if (query and not query->select.getSelection().empty()) {
                /* The request contains a select. No need to paginate... */
                /*DHT_LOG.d(sr->id, n->node->id, "[search %s] [node %s] sending 'get'",
                        sr->id.toString().c_str(), n->node->toString().c_str());*/
                n->getStatus[query] = network_engine.sendGetValues(n->node,
                        sr->id,
                        *query,
                        -1,
                        std::bind(&Dht::searchNodeGetDone, this, _1, _2, ws, query),
                        std::bind(&Dht::searchNodeGetExpired, this, _1, _2, ws, query));
            } else
                paginate(ws, query, n);
        }

        /* We only try to send one request. return. */
        return n;

    } while (++cb != sr->callbacks.end());

    /* no request were sent */
    return nullptr;
}

void Dht::searchSendAnnounceValue(const Sp<Search>& sr) {
    if (sr->announce.empty())
        return;
    unsigned i = 0;
    auto probe_query = std::make_shared<Query>(Select {}.field(Value::Field::Id).field(Value::Field::SeqNum));
    std::weak_ptr<Search> ws = sr;
    const auto& now = scheduler.time();
    for (auto& n : sr->nodes) {
        if (not n.isSynced(now))
            continue;
        if (std::find_if(sr->announce.cbegin(), sr->announce.cend(),
            [this,&now,&n](const Announce& a) {
                return n.getAnnounceTime(a.value->id) <= now;
            }) == sr->announce.cend())
            continue;

        auto onDone = [this,ws](const net::Request& req, net::RequestAnswer&& answer)
        { /* when put done */
            if (auto sr = ws.lock()) {
                onAnnounceDone(req.node, answer, sr);
                searchStep(sr);
            }
        };
        auto onExpired = [this,ws](const net::Request&, bool over)
        { /* when put expired */
            if (over)
                if (auto sr = ws.lock())
                    scheduler.edit(sr->nextSearchStep, scheduler.time());
        };
        auto onSelectDone =
            [this,ws,onDone,onExpired](const net::Request& req, net::RequestAnswer&& answer) mutable
            { /* on probing done */
                auto sr = ws.lock();
                if (not sr) return;
                auto sn = sr->getNode(req.node);
                if (not sn) return;

                const auto& now = scheduler.time();
                if (not sn->isSynced(now)) {
                    /* Search is now unsynced. Let's call searchStep to sync again. */
                    scheduler.edit(sr->nextSearchStep, now);
                    return;
                }
                for (auto& a : sr->announce) {
                    if (sn->getAnnounceTime(a.value->id) > now)
                        continue;
                    bool hasValue {false};
                    uint16_t seq_no = 0;
                    try {
                        const auto& f = std::find_if(answer.fields.cbegin(), answer.fields.cend(),
                                [&a](const Sp<FieldValueIndex>& i){
                                    return i->index.at(Value::Field::Id).getInt() == a.value->id;
                                });
                        if (f != answer.fields.cend() and *f) {
                            hasValue = true;
                            seq_no = static_cast<uint16_t>((*f)->index.at(Value::Field::SeqNum).getInt());
                        }
                    } catch (std::out_of_range&) { }

                    auto next_refresh_time = now + getType(a.value->type).expiration;
                    /* only put the value if the node doesn't already have it */
                    if (not hasValue or seq_no < a.value->seq) {
                        DHT_LOG.w(sr->id, sn->node->id, "[search %s] [node %s] sending 'put' (vid: %d)",
                                sr->id.toString().c_str(), sn->node->toString().c_str(), a.value->id);
                        sn->acked[a.value->id] = std::make_pair(network_engine.sendAnnounceValue(sn->node,
                                                        sr->id,
                                                        a.value,
                                                        a.permanent ? time_point::max() : a.created,
                                                        sn->token,
                                                        onDone,
                                                        onExpired), next_refresh_time);
                    } else if (hasValue and a.permanent) {
                        DHT_LOG.w(sr->id, sn->node->id, "[search %s] [node %s] sending 'refresh' (vid: %d)",
                                sr->id.toString().c_str(), sn->node->toString().c_str(), a.value->id);
                        sn->acked[a.value->id] = std::make_pair(network_engine.sendRefreshValue(sn->node,
                                                        sr->id,
                                                        a.value->id,
                                                        sn->token,
                                                        onDone,
                                                        onExpired), next_refresh_time);
                    } else {
                        DHT_LOG.w(sr->id, sn->node->id, "[search %s] [node %s] already has value (vid: %d). Aborting.",
                                sr->id.toString().c_str(), sn->node->toString().c_str(), a.value->id);
                        auto ack_req = std::make_shared<net::Request>(net::Request::State::COMPLETED);
                        ack_req->reply_time = now;
                        sn->acked[a.value->id] = std::make_pair(std::move(ack_req), next_refresh_time);

                        /* step to clear announces */
                        scheduler.edit(sr->nextSearchStep, now);
                    }
                }
            };
        DHT_LOG.w(sr->id, n.node->id, "[search %s] [node %s] sending %s",
                sr->id.toString().c_str(), n.node->toString().c_str(), probe_query->toString().c_str());
        n.probe_query = probe_query;
        n.getStatus[probe_query] = network_engine.sendGetValues(n.node,
                sr->id,
                *probe_query,
                -1,
                onSelectDone,
                std::bind(&Dht::searchNodeGetExpired, this, _1, _2, ws, probe_query));
        if (not n.candidate and ++i == TARGET_NODES)
            break;
    }
}

/* When a search is in progress, we periodically call search_step to send
   further requests. */
void
Dht::searchStep(Sp<Search> sr)
{
    if (not sr or sr->expired or sr->done) return;

    const auto& now = scheduler.time();
    if (auto req_count = sr->currentlySolicitedNodeCount())
        DHT_LOG.d(sr->id, "[search %s IPv%c] step (%d requests)",
                sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6', req_count);
    sr->step_time = now;

    if (sr->refill_time + Node::NODE_EXPIRE_TIME < now and sr->nodes.size()-sr->getNumberOfBadNodes() < SEARCH_NODES)
        refill(*sr);

    /* Check if the first TARGET_NODES (8) live nodes have replied. */
    if (sr->isSynced(now)) {
        if (not (sr->callbacks.empty() and sr->announce.empty())) {
            // search is synced but some (newer) get operations are not complete
            // Call callbacks when done
            std::vector<Get> completed_gets;
            for (auto b = sr->callbacks.begin(); b != sr->callbacks.end();) {
                if (sr->isDone(b->second)) {
                    sr->setDone(b->second);
                    completed_gets.emplace_back(std::move(b->second));
                    b = sr->callbacks.erase(b);
                }
                else
                    ++b;
            }
            // clear corresponding queries
            for (const auto& get : completed_gets)
                for (auto& sn : sr->nodes) {
                    sn.getStatus.erase(get.query);
                    sn.pagination_queries.erase(get.query);
                }

            /* clearing callbacks for announced values */
            sr->checkAnnounced();

            if (sr->callbacks.empty() && sr->announce.empty() && sr->listeners.empty())
                sr->setDone();
        }

        // true if this node is part of the target nodes cluter.
        /*bool in = sr->id.xorCmp(myid, sr->nodes.back().node->id) < 0;

        DHT_LOG_DEBUG("[search %s IPv%c] synced%s",
                sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6', in ? ", in" : "");*/

        if (not sr->listeners.empty()) {
            unsigned i = 0;
            for (auto& n : sr->nodes) {
                if (not n.isSynced(now))
                    continue;
                for (const auto& l : sr->listeners) {
                    const auto& query = l.second.query;
                    if (n.getListenTime(query) > now)
                        continue;
                    DHT_LOG.w(sr->id, n.node->id, "[search %s] [node %s] sending 'listen'",
                            sr->id.toString().c_str(), n.node->toString().c_str());

                    const auto& r = n.listenStatus.find(query);
                    auto prev_req = r != n.listenStatus.end() ? r->second : nullptr;

                    std::weak_ptr<Search> ws = sr;
                    n.listenStatus[query] = network_engine.sendListen(n.node, sr->id, *query, n.token, prev_req,
                        [this,ws,query](const net::Request& req, net::RequestAnswer&& answer) mutable
                        { /* on done */
                            if (auto sr = ws.lock()) {
                                scheduler.edit(sr->nextSearchStep, scheduler.time());
                                if (auto sn = sr->getNode(req.node))
                                    scheduler.add(sn->getListenTime(query), std::bind(&Dht::searchStep, this, sr));
                                onListenDone(req.node, answer, sr);
                            }
                        },
                        [this,ws,query](const net::Request& req, bool over) mutable
                        { /* on expired */
                            if (auto sr = ws.lock()) {
                                scheduler.edit(sr->nextSearchStep, scheduler.time());
                                if (over)
                                    if (auto sn = sr->getNode(req.node))
                                        sn->listenStatus.erase(query);
                            }
                        },
                        [this,ws,query](const Sp<Node>& node, net::RequestAnswer&& answer) mutable
                        { /* on new values */
                            if (auto sr = ws.lock()) {
                                scheduler.edit(sr->nextSearchStep, scheduler.time());
                                onGetValuesDone(node, answer, sr, query);
                            }
                        }
                    );
                }
                if (not n.candidate and ++i == LISTEN_NODES)
                    break;
            }
        }

        // Announce requests
        searchSendAnnounceValue(sr);

        if (sr->callbacks.empty() && sr->announce.empty() && sr->listeners.empty())
            sr->setDone();
    }

    if (sr->currentlySolicitedNodeCount() < MAX_REQUESTED_SEARCH_NODES) {
        unsigned i = 0;
        SearchNode* sent;
        do {
            sent = searchSendGetValues(sr);
            if (sent and not sent->candidate)
                i++;
        }
        while (sent and sr->currentlySolicitedNodeCount() < MAX_REQUESTED_SEARCH_NODES);
        /*DHT_LOG_DEBUG("[search %s IPv%c] step: sent %u requests (total %u).",
            sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6', i, sr->currentlySolicitedNodeCount());*/
    }

    if (sr->getNumberOfConsecutiveBadNodes() >= std::min(sr->nodes.size(),
                                                             static_cast<size_t>(SEARCH_MAX_BAD_NODES)))
    {
        DHT_LOG.w(sr->id, "[search %s IPv%c] expired", sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6');
        sr->expire();
        connectivityChanged(sr->af);
    }

    /* dumpSearch(*sr, std::cout); */

    /* periodic searchStep scheduling. */
    //if (not sr->done)
    //    scheduler.edit(sr->nextSearchStep, now);
}

unsigned Dht::refill(Dht::Search& sr) {
    const auto& now = scheduler.time();
    sr.refill_time = now;
    /* we search for up to SEARCH_NODES good nodes. */
    auto cached_nodes = network_engine.getCachedNodes(sr.id, sr.af, SEARCH_NODES);

    if (cached_nodes.empty()) {
        DHT_LOG.e(sr.id, "[search %s IPv%c] no nodes from cache while refilling search",
                sr.id.toString().c_str(), (sr.af == AF_INET) ? '4' : '6');
        return 0;
    }

    unsigned inserted = 0;
    for (auto& i : cached_nodes) {
        /* try to insert the nodes. Search::insertNode will know how many to insert. */
        if (sr.insertNode(i, now))
            ++inserted;
    }
    DHT_LOG.d(sr.id, "[search %s IPv%c] refilled search with %u nodes from node cache",
            sr.id.toString().c_str(), (sr.af == AF_INET) ? '4' : '6', inserted);
    return inserted;
}


/* Start a search. */
Sp<Dht::Search>
Dht::search(const InfoHash& id, sa_family_t af, GetCallback gcb, QueryCallback qcb, DoneCallback dcb, Value::Filter f, Query q)
{
    if (!isRunning(af)) {
        DHT_LOG.e(id, "[search %s IPv%c] unsupported protocol", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
        if (dcb)
            dcb(false, {});
        return {};
    }

    auto& srs = searches(af);
    const auto& srp = srs.find(id);
    Sp<Search> sr {};

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
            if (not sr) {
                DHT_LOG.e(id, "[search %s IPv%c] maximum number of searches reached !", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
                return {};
            }
        }
        sr->af = af;
        sr->tid = search_id++;
        sr->step_time = time_point::min();
        sr->id = id;
        sr->done = false;
        sr->expired = false;
        sr->nodes.clear();
        sr->nodes.reserve(SEARCH_NODES+1);
        DHT_LOG.w(id, "[search %s IPv%c] new search", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
        if (search_id == 0)
            search_id++;
    }

    if (gcb or qcb) {
        auto now = scheduler.time();
        sr->callbacks.insert(std::make_pair<time_point, Get>(
            std::move(now),
            Get { scheduler.time(), f, std::make_shared<Query>(q),
                qcb ? qcb : QueryCallback {}, gcb ? gcb : GetCallback {}, dcb
            }
        ));
    }

    refill(*sr);
    if (sr->nextSearchStep)
        scheduler.edit(sr->nextSearchStep, scheduler.time());
    else
        sr->nextSearchStep = scheduler.add(scheduler.time(), std::bind(&Dht::searchStep, this, sr));

    return sr;
}

void
Dht::announce(const InfoHash& id,
        sa_family_t af,
        Sp<Value> value,
        DoneCallback callback,
        time_point created,
        bool permanent)
{
    const auto& now = scheduler.time();
    if (!value) {
        if (callback)
            callback(false, {});
        return;
    }
    created = std::min(now, created);
    storageStore(id, value, created);

    auto& srs = searches(af);
    auto srp = srs.find(id);
    auto sr = srp == srs.end() ? search(id, af) : srp->second;
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
        sr->announce.emplace_back(Announce {permanent, value, created, callback});
        for (auto& n : sr->nodes) {
            n.probe_query.reset();
            n.acked[value->id].first.reset();
        }
    } else {
        a_sr->permanent = permanent;
        a_sr->created = created;
        if (a_sr->value != value) {
            a_sr->value = value;
            for (auto& n : sr->nodes) {
                n.acked[value->id].first.reset();
                n.probe_query.reset();
            }
        }
        if (sr->isAnnounced(value->id)) {
            if (a_sr->callback)
                a_sr->callback(true, {});
            a_sr->callback = {};
            if (callback)
                callback(true, {});
            return;
        } else {
            if (a_sr->callback)
                a_sr->callback(false, {});
            a_sr->callback = callback;
        }
    }
    scheduler.edit(sr->nextSearchStep, scheduler.time());
}

size_t
Dht::listenTo(const InfoHash& id, sa_family_t af, GetCallback cb, Value::Filter f, const Sp<Query>& q)
{
    const auto& now = scheduler.time();
    if (!isRunning(af))
        return 0;
       // DHT_LOG_ERR("[search %s IPv%c] search_time is now in %lfs", sr->id.toString().c_str(), (sr->af == AF_INET) ? '4' : '6', print_dt(tm-clock::now()));

    //DHT_LOG_WARN("listenTo %s", id.toString().c_str());
    auto& srs = searches(af);
    auto srp = srs.find(id);
    Sp<Search> sr = (srp == srs.end()) ? search(id, af) : srp->second;
    if (!sr)
        throw DhtException("Can't create search");
    DHT_LOG.e(id, "[search %s IPv%c] listen", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
    sr->done = false;
    auto token = ++sr->listener_token;
    sr->listeners.emplace(token, LocalListener{q, f, cb});
    scheduler.edit(sr->nextSearchStep, now);
    return token;
}

size_t
Dht::listen(const InfoHash& id, GetCallback cb, Value::Filter f, Where where)
{
    scheduler.syncTime();

    Query q {{}, where};
    auto vals = std::make_shared<std::map<Value::Id, Sp<Value>>>();
    auto token = ++listener_token;

    auto gcb = [=](const std::vector<Sp<Value>>& values) {
        std::vector<Sp<Value>> newvals;
        for (const auto& v : values) {
            auto it = vals->find(v->id);
            if (it == vals->cend() || !(*it->second == *v))
                newvals.push_back(v);
        }
        if (!newvals.empty()) {
            if (!cb(newvals)) {
                // cancelListen is useful here, because we need to cancel on IPv4 and 6
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

    auto query = std::make_shared<Query>(q);
    auto filter = f.chain(q.where.getFilter());
    size_t tokenlocal = 0;
    auto st = store.find(id);
    if (st == store.end() && store.size() < MAX_HASHES)
        st = store.emplace(id, Storage(scheduler.time() + MAX_STORAGE_MAINTENANCE_EXPIRE_TIME)).first;
    if (st != store.end()) {
        if (not st->second.empty()) {
            std::vector<Sp<Value>> newvals = st->second.get(filter);
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
        tokenlocal = ++st->second.listener_token;
        st->second.local_listeners.emplace(tokenlocal, LocalListener{query, filter, gcb});
    }

    auto token4 = Dht::listenTo(id, AF_INET, gcb, filter, query);
    auto token6 = Dht::listenTo(id, AF_INET6, gcb, filter, query);

    DHT_LOG.d(id, "Added listen : %d -> %d %d %d", token, tokenlocal, token4, token6);
    listeners.emplace(token, std::make_tuple(tokenlocal, token4, token6));
    return token;
}

bool
Dht::cancelListen(const InfoHash& id, size_t token)
{
    scheduler.syncTime();

    auto it = listeners.find(token);
    if (it == listeners.end()) {
        DHT_LOG.w(id, "Listen token not found: %d", token);
        return false;
    }
    DHT_LOG.d(id, "cancelListen %s with token %d", id.toString().c_str(), token);
    auto st = store.find(id);
    auto tokenlocal = std::get<0>(it->second);
    if (st != store.end() && tokenlocal)
        st->second.local_listeners.erase(tokenlocal);

    auto searches_cancel_listen = [&id](std::map<InfoHash, Sp<Search>>& srs, size_t token) {
        auto srp = srs.find(id);
        if (srp != srs.end() and token)
            srp->second->cancelListen(token);
    };
    searches_cancel_listen(searches4, std::get<1>(it->second));
    searches_cancel_listen(searches6, std::get<2>(it->second));
    listeners.erase(it);
    return true;
}

struct OpStatus {
    struct Status {
        bool done {false};
        bool ok {false};
        Status(bool done=false, bool ok=false) : done(done), ok(ok) {}
    };
    Status status;
    Status status4;
    Status status6;
};

template <typename T>
struct GetStatus : public OpStatus {
    std::vector<Sp<T>> values;
    std::vector<Sp<Node>> nodes;
};

void
Dht::put(const InfoHash& id, Sp<Value> val, DoneCallback callback, time_point created, bool permanent)
{
    scheduler.syncTime();

    if (val->id == Value::INVALID_ID) {
        crypto::random_device rdev;
        std::uniform_int_distribution<Value::Id> rand_id {};
        val->id = rand_id(rdev);
    }

    DHT_LOG.d(id, "put: adding %s -> %s", id.toString().c_str(), val->toString().c_str());

    auto op = std::make_shared<OpStatus>();
    auto donecb = [callback](const std::vector<Sp<Node>>& nodes, OpStatus& op) {
        // Callback as soon as the value is announced on one of the available networks
        if (callback and not op.status.done and (op.status4.done && op.status6.done)) {
            callback(op.status4.ok or op.status6.ok, nodes);
            op.status.done = true;
        }
    };
    announce(id, AF_INET, val, [=](bool ok4, const std::vector<Sp<Node>>& nodes) {
        DHT_LOG.d(id, "Announce done IPv4 %d", ok4);
        auto& o = *op;
        o.status4 = {true, ok4};
        donecb(nodes, o);
    }, created, permanent);
    announce(id, AF_INET6, val, [=](bool ok6, const std::vector<Sp<Node>>& nodes) {
        DHT_LOG.d(id, "Announce done IPv6 %d", ok6);
        auto& o = *op;
        o.status6 = {true, ok6};
        donecb(nodes, o);
    }, created, permanent);
}

template <typename T>
void doneCallbackWrapper(DoneCallback dcb, const std::vector<Sp<Node>>& nodes, GetStatus<T>& op) {
    if (op.status.done)
        return;
    op.nodes.insert(op.nodes.end(), nodes.begin(), nodes.end());
    if (op.status.ok or (op.status4.done and op.status6.done)) {
        bool ok = op.status.ok or op.status4.ok or op.status6.ok;
        op.status.done = true;
        if (dcb)
            dcb(ok, op.nodes);
    }
}

template <typename T, typename Cb>
bool callbackWrapper(Cb get_cb,
        DoneCallback done_cb,
        const std::vector<Sp<T>>& values,
        std::function<std::vector<Sp<T>>(const std::vector<Sp<T>>&)> add_values,
        Sp<GetStatus<T>> o)
{
    auto& op = *o;
    if (op.status.done)
        return false;
    auto newvals = add_values(values);
    if (not newvals.empty()) {
        op.status.ok = !get_cb(newvals);
        op.values.insert(op.values.end(), newvals.begin(), newvals.end());
    }
    doneCallbackWrapper(done_cb, {}, op);
    return !op.status.ok;
}

void
Dht::get(const InfoHash& id, GetCallback getcb, DoneCallback donecb, Value::Filter&& filter, Where&& where)
{
    scheduler.syncTime();

    Query q {{}, where};
    auto op = std::make_shared<GetStatus<Value>>();

    auto f = filter.chain(q.where.getFilter());
    auto add_values = [op,f](const std::vector<Sp<Value>>& values) {
        std::vector<Sp<Value>> newvals {};
        for (const auto& v : values) {
            auto it = std::find_if(op->values.cbegin(), op->values.cend(), [&](const Sp<Value>& sv) {
                return sv == v or *sv == *v;
            });
            if (it == op->values.cend()) {
               if (not f or f(*v))
                   newvals.push_back(v);
            }
        }
        return newvals;
    };
    auto gcb = std::bind(callbackWrapper<Value, GetCallback>, getcb, donecb, _1, add_values, op);

    /* Try to answer this search locally. */
    gcb(getLocal(id, f));

    Dht::search(id, AF_INET, gcb, {}, [=](bool ok, const std::vector<Sp<Node>>& nodes) {
        //DHT_LOG_WARN("DHT done IPv4");
        op->status4 = {true, ok};
        doneCallbackWrapper(donecb, nodes, *op);
    }, f, q);
    Dht::search(id, AF_INET6, gcb, {}, [=](bool ok, const std::vector<Sp<Node>>& nodes) {
        //DHT_LOG_WARN("DHT done IPv6");
        op->status6 = {true, ok};
        doneCallbackWrapper(donecb, nodes, *op);
    }, f, q);
}

void Dht::query(const InfoHash& id, QueryCallback cb, DoneCallback done_cb, Query&& q)
{
    scheduler.syncTime();
    auto op = std::make_shared<GetStatus<FieldValueIndex>>();

    auto f = q.where.getFilter();
    auto values = getLocal(id, f);
    auto add_fields = [=](const std::vector<Sp<FieldValueIndex>>& fields) {
        std::vector<Sp<FieldValueIndex>> newvals {};
        for (const auto& f : fields) {
            auto it = std::find_if(op->values.cbegin(), op->values.cend(),
                [&](const Sp<FieldValueIndex>& sf) {
                    return sf == f or f->containedIn(*sf);
                });
            if (it == op->values.cend()) {
                auto lesser = std::find_if(op->values.begin(), op->values.end(),
                    [&](const Sp<FieldValueIndex>& sf) {
                        return sf->containedIn(*f);
                    });
                if (lesser != op->values.end())
                    op->values.erase(lesser);
                newvals.push_back(f);
            }
        }
        return newvals;
    };
    std::vector<Sp<FieldValueIndex>> local_fields(values.size());
    std::transform(values.begin(), values.end(), local_fields.begin(), [&q](const Sp<Value>& v) {
        return std::make_shared<FieldValueIndex>(*v, q.select);
    });
    auto qcb = std::bind(callbackWrapper<FieldValueIndex, QueryCallback>, cb, done_cb, _1, add_fields, op);

    /* Try to answer this search locally. */
    qcb(local_fields);

    Dht::search(id, AF_INET, {}, qcb, [=](bool ok, const std::vector<Sp<Node>>& nodes) {
        //DHT_LOG_WARN("DHT done IPv4");
        op->status4 = {true, ok};
        doneCallbackWrapper(done_cb, nodes, *op);
    }, f, q);
    Dht::search(id, AF_INET6, {}, qcb, [=](bool ok, const std::vector<Sp<Node>>& nodes) {
        //DHT_LOG_WARN("DHT done IPv6");
        op->status6 = {true, ok};
        doneCallbackWrapper(done_cb, nodes, *op);
    }, f, q);
}

std::vector<Sp<Value>>
Dht::getLocal(const InfoHash& id, Value::Filter f) const
{
    auto s = store.find(id);
    if (s == store.end()) return {};
    return s->second.get(f);
}

Sp<Value>
Dht::getLocalById(const InfoHash& id, Value::Id vid) const
{
    auto s = store.find(id);
    if (s != store.end())
        return s->second.getById(vid);
    return {};
}

std::vector<Sp<Value>>
Dht::getPut(const InfoHash& id)
{
    std::vector<Sp<Value>> ret;
    auto find_values = [&](std::map<InfoHash, Sp<Search>> srs) {
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

Sp<Value>
Dht::getPut(const InfoHash& id, const Value::Id& vid)
{
    auto find_value = [&](std::map<InfoHash, Sp<Search>> srs) {
        auto srp = srs.find(id);
        if (srp == srs.end())
            return Sp<Value> {};
        auto& search = srp->second;
        for (auto& a : search->announce) {
            if (a.value->id == vid)
                return a.value;
        }
        return Sp<Value> {};
    };
    if (auto v4 = find_value(searches4))
        return v4;
    if (auto v6 = find_value(searches6))
        return v6;
    return {};
}

bool
Dht::cancelPut(const InfoHash& id, const Value::Id& vid)
{
    bool canceled {false};
    auto sr_cancel_put = [&](std::map<InfoHash, Sp<Search>> srs) {
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

void
Dht::storageChanged(const InfoHash& id, Storage& st, ValueStorage& v)
{
    if (not st.local_listeners.empty()) {
        DHT_LOG.d(id, "[store %s] %lu local listeners", id.toString().c_str(), st.local_listeners.size());
        std::vector<std::pair<GetCallback, std::vector<Sp<Value>>>> cbs;
        for (const auto& l : st.local_listeners) {
            std::vector<Sp<Value>> vals;
            if (not l.second.filter or l.second.filter(*v.data))
                vals.push_back(v.data);
            if (not vals.empty()) {
                DHT_LOG.d(id, "[store %s] sending update local listener with token %lu",
                        id.toString().c_str(),
                        l.first);
                cbs.emplace_back(l.second.get_cb, std::move(vals));
            }
        }
        // listeners are copied: they may be deleted by the callback
        for (auto& cb : cbs)
            cb.first(cb.second);
    }

    if (not st.listeners.empty()) {
        DHT_LOG.d(id, "[store %s] %lu remote listeners", id.toString().c_str(), st.listeners.size());
        for (const auto& node_listeners : st.listeners) {
            for (const auto& l : node_listeners.second) {
                auto f = l.second.query.where.getFilter();
                if (f and not f(*v.data))
                    continue;
                DHT_LOG.w(id, node_listeners.first->id, "[store %s] [node %s] sending update",
                        id.toString().c_str(),
                        node_listeners.first->toString().c_str());
                std::vector<Sp<Value>> vals {};
                vals.push_back(v.data);
                Blob ntoken = makeToken(node_listeners.first->getAddr(), false);
                network_engine.tellListener(node_listeners.first, l.first, id, 0, ntoken, {}, {},
                        std::move(vals), l.second.query);
            }
        }
    }
}

bool
Dht::storageStore(const InfoHash& id, const Sp<Value>& value, time_point created, const SockAddr& sa)
{
    const auto& now = scheduler.time();
    created = std::min(created, now);
    auto expiration = created + getType(value->type).expiration;
    if (expiration < now)
        return false;

    auto st = store.find(id);
    if (st == store.end()) {
        if (store.size() >= MAX_HASHES)
            return false;
        auto st_i = store.emplace(id, Storage(now));
        st = st_i.first;
        if (maintain_storage and st_i.second)
            scheduler.add(st->second.maintenance_time, std::bind(&Dht::dataPersistence, this, id));
    }

    StorageBucket* store_bucket {nullptr};
    if (sa)
        store_bucket = &store_quota.emplace(sa, StorageBucket{}).first->second;

    auto store = st->second.store(id, value, created, expiration, store_bucket);
    if (auto vs = store.first) {
        total_store_size += store.second.size_diff;
        total_values += store.second.values_diff;
        scheduler.add(expiration, std::bind(&Dht::expireStorage, this, id));
        if (total_store_size > max_store_size) {
            expireStore();
        }
        storageChanged(id, st->second, *vs);
    }

    return std::get<0>(store);
}

void
Dht::storageAddListener(const InfoHash& id, const Sp<Node>& node, size_t socket_id, Query&& query)
{
    const auto& now = scheduler.time();
    auto st = store.find(id);
    if (st == store.end()) {
        if (store.size() >= MAX_HASHES)
            return;
        st = store.emplace(id, Storage(now)).first;
    }
    auto node_listeners = st->second.listeners.emplace(node, std::map<size_t, Listener> {}).first;
    auto l = node_listeners->second.find(socket_id);
    if (l == node_listeners->second.end()) {
        auto vals = st->second.get(query.where.getFilter());
        if (not vals.empty()) {
            network_engine.tellListener(node, socket_id, id, WANT4 | WANT6, makeToken(node->getAddr(), false),
                    buckets4.findClosestNodes(id, now, TARGET_NODES), buckets6.findClosestNodes(id, now, TARGET_NODES),
                    std::move(vals), query);
        }
        node_listeners->second.emplace(socket_id, Listener {now, std::forward<Query>(query)});
    }
    else
        l->second.refresh(now, std::forward<Query>(query));
}

void
Dht::expireStore(decltype(store)::iterator i)
{
    const auto& id = i->first;
    auto& st = i->second;
    auto stats = st.expire(id, scheduler.time());
    total_store_size += stats.first;
    total_values -= stats.second.size();
    if (not stats.second.empty()) {
        DHT_LOG.d(id, "[store %s] discarded %ld expired values (%ld bytes)",
            id.toString().c_str(), stats.second.size(), -stats.first);

        if (not st.listeners.empty()) {
            DHT_LOG.d(id, "[store %s] %lu remote listeners", id.toString().c_str(), st.listeners.size());

            std::vector<Value::Id> ids;
            ids.reserve(stats.second.size());
            for (const auto& v : stats.second)
                ids.emplace_back(v->id);

            for (const auto& node_listeners : st.listeners) {
                for (const auto& l : node_listeners.second) {
                    DHT_LOG.w(id, node_listeners.first->id, "[store %s] [node %s] sending expired",
                            id.toString().c_str(),
                            node_listeners.first->toString().c_str());
                    Blob ntoken = makeToken(node_listeners.first->getAddr(), false);
                    network_engine.tellListenerExpired(node_listeners.first, l.first, id, ntoken, ids);
                }
            }
        }
    }
}

void
Dht::expireStorage(InfoHash h)
{
    auto i = store.find(h);
    if (i != store.end())
        expireStore(i);
}

void
Dht::expireStore()
{
    // removing expired values
    for (auto i = store.begin(); i != store.end();) {
        expireStore(i);

        if (i->second.empty() && i->second.listeners.empty() && i->second.local_listeners.empty()) {
            DHT_LOG.d(i->first, "[store %s] discarding empty storage", i->first.toString().c_str());
            i = store.erase(i);
        }
        else
            ++i;
    }

    // remove more values if storage limit is exceeded
    while (total_store_size > max_store_size) {
        // find IP using the most storage
        if (store_quota.empty()) {
            DHT_LOG.w("No space left: local data consumes all the quota!");
            break;
        }
        auto largest = store_quota.begin();
        for (auto it = ++largest; it != store_quota.end(); ++it) {
            if (it->second.size() > largest->second.size())
                largest = it;
        }
        DHT_LOG.w("No space left: discarding value of largest consumer %s", largest->first.toString().c_str());
        while (true) {
            auto exp_value = largest->second.getOldest();
            auto storage = store.find(exp_value.first);
            if (storage != store.end()) {
                auto ret = storage->second.remove(exp_value.first, exp_value.second);
                total_store_size += ret.size_diff;
                total_values += ret.values_diff;
                DHT_LOG.w("Discarded %ld bytes, still %ld used", largest->first.toString().c_str(), total_store_size);
                if (ret.values_diff)
                    break;
            }
        }
    }

    // remove unused quota entires
    for (auto i = store_quota.begin(); i != store_quota.end();) {
        if (i->second.size() == 0)
            i = store_quota.erase(i);
        else
            ++i;
    }
}

void
Dht::connectivityChanged(sa_family_t af)
{
    const auto& now = scheduler.time();
    scheduler.edit(nextNodesConfirmation, now);
    buckets(af).connectivityChanged(now);
    network_engine.connectivityChanged(af);
    for (auto& sp : searches(af))
        for (auto& sn : sp.second->nodes) {
            for (auto& ls : sn.listenStatus)
                sn.node->cancelRequest(ls.second);
            sn.listenStatus.clear();
        }
    reported_addr.erase(std::remove_if(reported_addr.begin(), reported_addr.end(), [&](const ReportedAddr& addr){
        return addr.second.getFamily() == af;
    }), reported_addr.end());
}

void
Dht::rotateSecrets()
{
    oldsecret = secret;
    {
        crypto::random_device rdev;
        secret = std::uniform_int_distribution<uint64_t>{}(rdev);
    }
    uniform_duration_distribution<> time_dist(std::chrono::minutes(15), std::chrono::minutes(45));
    auto rotate_secrets_time = scheduler.time() + time_dist(rd);
    scheduler.add(rotate_secrets_time, std::bind(&Dht::rotateSecrets, this));
}

Blob
Dht::makeToken(const SockAddr& addr, bool old) const
{
    const void *ip;
    size_t iplen;
    in_port_t port;

    auto family = addr.getFamily();
    if (family == AF_INET) {
        const auto& sin = addr.getIPv4();
        ip = &sin.sin_addr;
        iplen = 4;
        port = sin.sin_port;
    } else if (family == AF_INET6) {
        const auto& sin6 = addr.getIPv6();
        ip = &sin6.sin6_addr;
        iplen = 16;
        port = sin6.sin6_port;
    } else {
        return {};
    }

    const auto& c1 = old ? oldsecret : secret;
    Blob data;
    data.reserve(sizeof(secret)+sizeof(in_port_t)+iplen);
    data.insert(data.end(), (uint8_t*)&c1, ((uint8_t*)&c1) + sizeof(c1));
    data.insert(data.end(), (uint8_t*)ip, (uint8_t*)ip+iplen);
    data.insert(data.end(), (uint8_t*)&port, ((uint8_t*)&port)+sizeof(in_port_t));
    return crypto::hash(data, TOKEN_SIZE);
}

bool
Dht::tokenMatch(const Blob& token, const SockAddr& addr) const
{
    if (not addr or token.size() != TOKEN_SIZE)
        return false;
    if (token == makeToken(addr, false))
        return true;
    if (token == makeToken(addr, true))
        return true;
    return false;
}

NodeStats
Dht::getNodesStats(sa_family_t af) const
{
    NodeStats stats {};
    const auto& now = scheduler.time();
    const auto& bcks = buckets(af);
    for (const auto& b : bcks) {
        for (auto& n : b.nodes) {
            if (n->isGood(now)) {
                stats.good_nodes++;
                if (n->isIncoming())
                    stats.incoming_nodes++;
            } else if (not n->isExpired())
                stats.dubious_nodes++;
        }
        if (b.cached)
            stats.cached_nodes++;
    }
    stats.table_depth = bcks.depth(bcks.findBucket(myid));
    return stats;
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
        const auto& t = n->getTime();
        const auto& r = n->getReplyTime();
        if (t != r)
            out << " age " << duration_cast<seconds>(now - t).count() << ", reply: " << duration_cast<seconds>(now - r).count();
        else
            out << " age " << duration_cast<seconds>(now - t).count();
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
    if (synced && sr.isListening(now))
        out << " [listening]";
    out << std::endl;

    /*printing the queries*/
    if (sr.callbacks.size() + sr.listeners.size() > 0)
        out << "Queries:" << std::endl;
    for (const auto& cb : sr.callbacks) {
        out << *cb.second.query << std::endl;
    }
    for (const auto& l : sr.listeners) {
        out << *l.second.query << std::endl;
    }

    for (const auto& a : sr.announce) {
        bool announced = sr.isAnnounced(a.value->id);
        out << "Announcement: " << *a.value << (announced ? " [announced]" : "") << std::endl;
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
            char g_i = n.pending(n.getStatus) ? (n.candidate ? 'c' : 'f') : ' ';
            char s_i = n.isSynced(now) ? (n.last_get_reply > last_get ? 'u' : 's') : '-';
            out << " [" << s_i << g_i << "] ";
        }

        // Listen status
        if (not sr.listeners.empty()) {
            if (n.listenStatus.empty())
                out << "    ";
            else
                out << "["
                    << (n.isListening(now) ? 'l' : (n.pending(n.listenStatus) ? 'f' : ' ')) << "] ";
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
                    if (ack == n.acked.end() or not ack->second.first) {
                        out << ' ';
                    } else {
                        if (ack->second.first->completed())
                            out << 'a';
                        else if (ack->second.first->pending())
                            out << 'f';
                    }
                }
                out << "] ";
            }
        }
        out << n.node->getAddrStr() << std::endl;
    }
}

void
Dht::dumpTables() const
{
    std::stringstream out;
    out << "My id " << myid << std::endl;

    out << "Buckets IPv4 :" << std::endl;
    for (const auto& b : buckets4)
        dumpBucket(b, out);
    out << "Buckets IPv6 :" << std::endl;
    for (const auto& b : buckets6)
        dumpBucket(b, out);

    auto dump_searches = [&](std::map<InfoHash, Sp<Search>> srs) {
        for (auto& srp : srs)
            dumpSearch(*srp.second, out);
    };
    dump_searches(searches4);
    dump_searches(searches6);
    out << std::endl;

    out << getStorageLog() << std::endl;

    DHT_LOG.d("%s", out.str().c_str());
}

std::string
Dht::getStorageLog() const
{
    std::stringstream out;
    for (const auto& s : store)
        out << printStorageLog(s);
    out << "Total " << store.size() << " storages, " << total_values << " values (";
    if (total_store_size < 1024)
        out << total_store_size << " bytes)";
    else
        out << (total_store_size/1024) << " KB)";
    out << std::endl << std::endl;
    std::multimap<size_t, const SockAddr*> q_map;
    for (const auto& ip : store_quota)
        if (ip.second.size())
            q_map.emplace(ip.second.size(), &ip.first);
    for (auto ip = q_map.rbegin(); ip != q_map.rend(); ++ip)
        out << "IP " << ip->second->toString() << " uses " << ip->first << " bytes" << std::endl;
    out << std::endl;
    return out.str();
}

std::string
Dht::getStorageLog(const InfoHash& h) const
{
    auto s = store.find(h);
    if (s == store.end()) {
        std::stringstream out;
        out << "Storage " << h << " empty" << std::endl;
        return out.str();
    }
    return printStorageLog(*s);
}

std::string
Dht::printStorageLog(const decltype(store)::value_type& s) const
{
    std::stringstream out;
    using namespace std::chrono;
    const auto& st = s.second;
    out << "Storage " << s.first << " "
                      << st.listeners.size() << " list., "
                      << st.valueCount() << " values ("
                      << st.totalSize() << " bytes)" << std::endl;
    if (not st.local_listeners.empty())
        out << "   " << st.local_listeners.size() << " local listeners" << std::endl;
    for (const auto& node_listeners : st.listeners) {
        const auto& node = node_listeners.first;
        out << "   " << "Listener " << node->toString() << " : " << node_listeners.second.size() << " entries" << std::endl;
    }
    return out.str();
}

std::string
Dht::getRoutingTablesLog(sa_family_t af) const
{
    std::stringstream out;
    for (const auto& b : buckets(af))
        dumpBucket(b, out);
    return out.str();
}

std::string
Dht::getSearchesLog(sa_family_t af) const
{
    std::stringstream out;
    auto num_searches = searches4.size() + searches6.size();
    if (num_searches > 8) {
        if (not af or af == AF_INET)
            for (const auto& sr : searches4)
                out << "[search " << sr.first << " IPv4]" << std::endl;
        if (not af or af == AF_INET6)
            for (const auto& sr : searches6)
                out << "[search " << sr.first << " IPv6]" << std::endl;
    } else {
        out << "s:synched, u:updated, a:announced, c:candidate, f:cur req, x:expired, *:known" << std::endl;
        if (not af or af == AF_INET)
            for (const auto& sr : searches4)
                dumpSearch(*sr.second, out);
        if (not af or af == AF_INET6)
            for (const auto& sr : searches6)
                dumpSearch(*sr.second, out);
    }
    out << "Total: " << num_searches << " searches (" << searches4.size() << " IPv4, " << searches6.size() << " IPv6)." << std::endl;
    return out.str();
}

std::string
Dht::getSearchLog(const InfoHash& id, sa_family_t af) const
{
    std::stringstream out;
    if (af == AF_UNSPEC) {
        out << getSearchLog(id, AF_INET) << getSearchLog(id, AF_INET6);
    } else {
        auto& srs = searches(af);
        auto sr = srs.find(id);
        if (sr != srs.end())
            dumpSearch(*sr->second, out);
    }
    return out.str();
}

Dht::~Dht()
{
    for (auto& s : searches4)
        s.second->clear();
    for (auto& s : searches6)
        s.second->clear();
}

Dht::Dht() : store(), scheduler(DHT_LOG), network_engine(DHT_LOG, scheduler) {}

Dht::Dht(const int& s, const int& s6, Config config)
    : myid(config.node_id ? config.node_id : InfoHash::getRandom()),
    is_bootstrap(config.is_bootstrap),
    maintain_storage(config.maintain_storage), store(), store_quota(),
    scheduler(DHT_LOG),
    network_engine(myid, config.network, s, s6, DHT_LOG, scheduler,
            std::bind(&Dht::onError, this, _1, _2),
            std::bind(&Dht::onNewNode, this, _1, _2),
            std::bind(&Dht::onReportedAddr, this, _1, _2),
            std::bind(&Dht::onPing, this, _1),
            std::bind(&Dht::onFindNode, this, _1, _2, _3),
            std::bind(&Dht::onGetValues, this, _1, _2, _3, _4),
            std::bind(&Dht::onListen, this, _1, _2, _3, _4, _5),
            std::bind(&Dht::onAnnounce, this, _1, _2, _3, _4, _5),
            std::bind(&Dht::onRefresh, this, _1, _2, _3, _4))
{
    scheduler.syncTime();
    if (s < 0 && s6 < 0)
        return;
    if (s >= 0) {
        buckets4 = {Bucket {AF_INET}};
        buckets4.is_client = config.is_bootstrap;
    }
    if (s6 >= 0) {
        buckets6 = {Bucket {AF_INET6}};
        buckets6.is_client = config.is_bootstrap;
    }

    search_id = std::uniform_int_distribution<decltype(search_id)>{}(rd);

    uniform_duration_distribution<> time_dis {std::chrono::seconds(3), std::chrono::seconds(5)};
    auto confirm_nodes_time = scheduler.time() + time_dis(rd);
    DHT_LOG.d(myid, "Scheduling %s", myid.toString().c_str());
    nextNodesConfirmation = scheduler.add(confirm_nodes_time, std::bind(&Dht::confirmNodes, this));

    // Fill old secret
    {
        crypto::random_device rdev;
        secret = std::uniform_int_distribution<uint64_t>{}(rdev);
    }
    rotateSecrets();

    expire();

    DHT_LOG.d("DHT initialised with node ID %s", myid.toString().c_str());
}


bool
Dht::neighbourhoodMaintenance(RoutingTable& list)
{
    //DHT_LOG_DEBUG("neighbourhoodMaintenance");
    auto b = list.findBucket(myid);
    if (b == list.end())
        return false;

    InfoHash id = myid;
#ifdef _WIN32
    std::uniform_int_distribution<int> rand_byte{ 0, std::numeric_limits<uint8_t>::max() };
#else
    std::uniform_int_distribution<uint8_t> rand_byte;
#endif
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

    auto n = q->randomNode();
    if (n) {
        DHT_LOG.d(id, n->id, "[node %s] sending [find %s] for neighborhood maintenance",
                n->toString().c_str(), id.toString().c_str());
        /* Since our node-id is the same in both DHTs, it's probably
           profitable to query both families. */
        network_engine.sendFindNode(n, id, network_engine.want(), nullptr, nullptr);
    }

    return true;
}

bool
Dht::bucketMaintenance(RoutingTable& list)
{
    std::bernoulli_distribution rand_trial(1./8.);
    std::bernoulli_distribution rand_trial_38(1./38.);

    bool sent {false};
    for (auto b = list.begin(); b != list.end(); ++b) {
        if (b->time < scheduler.time() - std::chrono::minutes(10) || b->nodes.empty()) {
            /* This bucket hasn't seen any positive confirmation for a long
               time. Pick a random id in this bucket's range, and send a request
               to a random node. */
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
            if (n and not n->isPendingMessage()) {
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

                DHT_LOG.d(id, n->id, "[node %s] sending find %s for bucket maintenance", n->toString().c_str(), id.toString().c_str());
                auto start = scheduler.time();
                network_engine.sendFindNode(n, id, want, nullptr, [this,start,n](const net::Request&, bool over) {
                    if (over) {
                        const auto& end = scheduler.time();
                        using namespace std::chrono;
                        DHT_LOG.d(n->id, "[node %s] bucket maintenance op expired after %llu ms", n->toString().c_str(), duration_cast<milliseconds>(end-start).count());
                        scheduler.edit(nextNodesConfirmation, end + Node::MAX_RESPONSE_TIME);
                    }
                });
                sent = true;
            }
        }
    }
    return sent;
}

void
Dht::dataPersistence(InfoHash id)
{
    const auto& now = scheduler.time();
    auto str = store.find(id);
    if (str != store.end() and now > str->second.maintenance_time) {
        DHT_LOG.d(id, "[storage %s] maintenance (%u values, %u bytes)",
                id.toString().c_str(), str->second.valueCount(), str->second.totalSize());
        maintainStorage(*str);
        str->second.maintenance_time = now + MAX_STORAGE_MAINTENANCE_EXPIRE_TIME;
        scheduler.add(str->second.maintenance_time, std::bind(&Dht::dataPersistence, this, id));
    }
}

size_t
Dht::maintainStorage(decltype(store)::value_type& storage, bool force, DoneCallback donecb)
{
    const auto& now = scheduler.time();
    size_t announce_per_af = 0;

    bool want4 = true, want6 = true;

    auto nodes = buckets4.findClosestNodes(storage.first, now);
    if (!nodes.empty()) {
        if (force || storage.first.xorCmp(nodes.back()->id, myid) < 0) {
            for (auto &value : storage.second.getValues()) {
                const auto& vt = getType(value.data->type);
                if (force || value.created + vt.expiration > now + MAX_STORAGE_MAINTENANCE_EXPIRE_TIME) {
                    // gotta put that value there
                    announce(storage.first, AF_INET, value.data, donecb, value.created);
                    ++announce_per_af;
                }
            }
            want4 = false;
        }
    }

    auto nodes6 = buckets6.findClosestNodes(storage.first, now);
    if (!nodes6.empty()) {
        if (force || storage.first.xorCmp(nodes6.back()->id, myid) < 0) {
            for (auto &value : storage.second.getValues()) {
                const auto& vt = getType(value.data->type);
                if (force || value.created + vt.expiration > now + MAX_STORAGE_MAINTENANCE_EXPIRE_TIME) {
                    // gotta put that value there
                    announce(storage.first, AF_INET6, value.data, donecb, value.created);
                    ++announce_per_af;
                }
            }
            want6 = false;
        }
    }

    if (not want4 and not want6) {
        DHT_LOG.d(storage.first, "Discarding storage values %s", storage.first.toString().c_str());
        auto diff = storage.second.clear();
        total_store_size += diff.size_diff;
        total_values += diff.values_diff;
    }

    return announce_per_af;
}

time_point
Dht::periodic(const uint8_t *buf, size_t buflen, const SockAddr& from)
{
    scheduler.syncTime();
    if (buflen) {
        try {
            network_engine.processMessage(buf, buflen, from);
        } catch (const std::exception& e) {
            DHT_LOG.e("Can't process message from %s: %s", from.toString().c_str(), e.what());
        }
    }
    return scheduler.run();
}

void
Dht::expire()
{
    uniform_duration_distribution<> time_dis(std::chrono::minutes(2), std::chrono::minutes(6));
    auto expire_stuff_time = scheduler.time() + duration(time_dis(rd));

    expireBuckets(buckets4);
    expireBuckets(buckets6);
    expireStore();
    expireSearches();
    scheduler.add(expire_stuff_time, std::bind(&Dht::expire, this));
}

void
Dht::confirmNodes()
{
    using namespace std::chrono;
    bool soon = false;
    const auto& now = scheduler.time();

    if (searches4.empty() and getStatus(AF_INET) == NodeStatus::Connected) {
        DHT_LOG.d(myid, "[confirm nodes] initial IPv4 'get' for my id (%s)", myid.toString().c_str());
        search(myid, AF_INET);
    }
    if (searches6.empty() and getStatus(AF_INET6) == NodeStatus::Connected) {
        DHT_LOG.d(myid, "[confirm nodes] initial IPv6 'get' for my id (%s)", myid.toString().c_str());
        search(myid, AF_INET6);
    }

    soon |= bucketMaintenance(buckets4);
    soon |= bucketMaintenance(buckets6);

    if (!soon) {
        if (buckets4.grow_time >= now - seconds(150))
            soon |= neighbourhoodMaintenance(buckets4);
        if (buckets6.grow_time >= now - seconds(150))
            soon |= neighbourhoodMaintenance(buckets6);
    }

    /* In order to maintain all buckets' age within 600 seconds, worst
       case is roughly 27 seconds, assuming the table is 22 bits deep.
       We want to keep a margin for neighborhood maintenance, so keep
       this within 25 seconds. */
    auto time_dis = soon
        ? uniform_duration_distribution<> {seconds(5) , seconds(25)}
        : uniform_duration_distribution<> {seconds(60), seconds(180)};
    auto confirm_nodes_time = now + time_dis(rd);

    scheduler.edit(nextNodesConfirmation, confirm_nodes_time);
}

std::vector<ValuesExport>
Dht::exportValues() const
{
    std::vector<ValuesExport> e {};
    e.reserve(store.size());
    for (const auto& h : store) {
        ValuesExport ve;
        ve.first = h.first;

        msgpack::sbuffer buffer;
        msgpack::packer<msgpack::sbuffer> pk(&buffer);
        const auto& vals = h.second.getValues();
        pk.pack_array(vals.size());
        for (const auto& v : vals) {
            pk.pack_array(2);
            pk.pack(v.created.time_since_epoch().count());
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

        const auto& now = scheduler.time();
        try {
            msgpack::unpacked msg;
            msgpack::unpack(msg, (const char*)h.second.data(), h.second.size());
            auto valarr = msg.get();
            if (valarr.type != msgpack::type::ARRAY)
                throw msgpack::type_error();
            for (unsigned i = 0; i < valarr.via.array.size; i++) {
                auto& valel = valarr.via.array.ptr[i];
                if (valel.type != msgpack::type::ARRAY or valel.via.array.size < 2)
                    throw msgpack::type_error();
                time_point val_time;
                Value tmp_val;
                try {
                    val_time = time_point{time_point::duration{valel.via.array.ptr[0].as<time_point::duration::rep>()}};
                    tmp_val.msgpack_unpack(valel.via.array.ptr[1]);
                } catch (const std::exception&) {
                    DHT_LOG.e(h.first, "Error reading value at %s", h.first.toString().c_str());
                    continue;
                }
                val_time = std::min(val_time, now);
                storageStore(h.first, std::make_shared<Value>(std::move(tmp_val)), val_time);
            }
        } catch (const std::exception&) {
            DHT_LOG.e(h.first, "Error reading values at %s", h.first.toString().c_str());
            continue;
        }
    }
}


std::vector<NodeExport>
Dht::exportNodes()
{
    const auto& now = scheduler.time();
    std::vector<NodeExport> nodes;
    const auto b4 = buckets4.findBucket(myid);
    if (b4 != buckets4.end()) {
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
    for (auto b = buckets4.begin(); b != buckets4.end(); ++b) {
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

void
Dht::insertNode(const InfoHash& id, const SockAddr& addr)
{
    if (addr.getFamily() != AF_INET && addr.getFamily() != AF_INET6)
        return;
    scheduler.syncTime();
    network_engine.insertNode(id, addr);
}

void
Dht::pingNode(const sockaddr* sa, socklen_t salen, DoneCallbackSimple&& cb)
{
    scheduler.syncTime();
    DHT_LOG.d("Sending ping to %s", print_addr(sa, salen).c_str());
    auto& count = sa->sa_family == AF_INET ? pending_pings4 : pending_pings6;
    count++;
    network_engine.sendPing(sa, salen, [&count,cb](const net::Request&, net::RequestAnswer&&) {
        count--;
        if (cb)
            cb(true);
    }, [&count,cb](const net::Request&, bool last){
        if (last) {
            count--;
            if (cb)
                cb(false);
        }
    });
}

void
Dht::onError(Sp<net::Request> req, net::DhtProtocolException e) {
    const auto& node = req->node;
    if (e.getCode() == net::DhtProtocolException::UNAUTHORIZED) {
        DHT_LOG.e(node->id, "[node %s] token flush", node->toString().c_str());
        node->authError();
        node->cancelRequest(req);
        for (auto& srp : searches(node->getFamily())) {
            auto& sr = srp.second;
            for (auto& n : sr->nodes) {
                if (n.node != node) continue;
                n.token.clear();
                n.last_get_reply = time_point::min();
                searchSendGetValues(sr);
                scheduler.edit(sr->nextSearchStep, scheduler.time());
                break;
            }
        }
    } else if (e.getCode() == net::DhtProtocolException::NOT_FOUND) {
        DHT_LOG.e(node->id, "[node %s] returned error 404: storage not found", node->toString().c_str());
        node->cancelRequest(req);
    }
}

void
Dht::onReportedAddr(const InfoHash& /*id*/, const SockAddr& addr)
{
    if (addr)
        reportedAddr(addr);
}

net::RequestAnswer
Dht::onPing(Sp<Node>)
{
    return {};
}

net::RequestAnswer
Dht::onFindNode(Sp<Node> node, const InfoHash& target, want_t want)
{
    const auto& now = scheduler.time();
    net::RequestAnswer answer;
    answer.ntoken = makeToken(node->getAddr(), false);
    if (want & WANT4)
        answer.nodes4 = buckets4.findClosestNodes(target, now, TARGET_NODES);
    if (want & WANT6)
        answer.nodes6 = buckets6.findClosestNodes(target, now, TARGET_NODES);
    return answer;
}

net::RequestAnswer
Dht::onGetValues(Sp<Node> node, const InfoHash& hash, want_t, const Query& query)
{
    if (not hash) {
        DHT_LOG.w("[node %s] Eek! Got get_values with no info_hash", node->toString().c_str());
        throw net::DhtProtocolException {
            net::DhtProtocolException::NON_AUTHORITATIVE_INFORMATION,
            net::DhtProtocolException::GET_NO_INFOHASH
        };
    }
    const auto& now = scheduler.time();
    net::RequestAnswer answer {};
    auto st = store.find(hash);
    answer.ntoken = makeToken(node->getAddr(), false);
    answer.nodes4 = buckets4.findClosestNodes(hash, now, TARGET_NODES);
    answer.nodes6 = buckets6.findClosestNodes(hash, now, TARGET_NODES);
    if (st != store.end() && not st->second.empty()) {
        answer.values = st->second.get(query.where.getFilter());
        DHT_LOG.d(hash, "[node %s] sending %u values", node->toString().c_str(), answer.values.size());
    }
    return answer;
}

void Dht::onGetValuesDone(const Sp<Node>& node,
        net::RequestAnswer& a,
        Sp<Search>& sr,
        const Sp<Query>& orig_query)
{
    if (not sr) {
        DHT_LOG.w("[search unknown] got reply to 'get'. Ignoring.");
        return;
    }

    /*DHT_LOG.d(sr->id, "[search %s] [node %s] got reply to 'get' with %u nodes",
            sr->id.toString().c_str(), node->toString().c_str(), a.nodes4.size()+a.nodes6.size());*/

    if (not a.ntoken.empty()) {
        if (not a.values.empty() or not a.fields.empty()) {
            DHT_LOG.d(sr->id, node->id, "[search %s] [node %s] found %u values",
                      sr->id.toString().c_str(), node->toString().c_str(), a.values.size());
            for (auto& getp : sr->callbacks) { /* call all callbacks for this search */
                auto& get = getp.second;
                if (not (get.get_cb or get.query_cb) or
                        (orig_query and get.query and not get.query->isSatisfiedBy(*orig_query)))
                    continue;

                if (get.query_cb) { /* in case of a request with query */
                    if (not a.fields.empty()) {
                        get.query_cb(a.fields);
                    } else if (not a.values.empty()) {
                        std::vector<Sp<FieldValueIndex>> fields;
                        fields.reserve(a.values.size());
                        for (const auto& v : a.values)
                            fields.emplace_back(std::make_shared<FieldValueIndex>(*v, orig_query ? orig_query->select : Select {}));
                        get.query_cb(fields);
                    }
                } else if (get.get_cb) { /* in case of a vanilla get request */
                    std::vector<Sp<Value>> tmp;
                    for (const auto& v : a.values)
                        if (not get.filter or get.filter(*v))
                            tmp.emplace_back(v);
                    if (not tmp.empty())
                        get.get_cb(tmp);
                }
            }

            /* callbacks for local search listeners */
            std::vector<std::pair<GetCallback, std::vector<Sp<Value>>>> tmp_lists;
            for (auto& l : sr->listeners) {
                if (!l.second.get_cb or (orig_query and l.second.query and not l.second.query->isSatisfiedBy(*orig_query)))
                    continue;
                std::vector<Sp<Value>> tmp;
                for (const auto& v : a.values)
                    if (not l.second.filter or l.second.filter(*v))
                        tmp.emplace_back(v);
                if (not tmp.empty())
                    tmp_lists.emplace_back(l.second.get_cb, std::move(tmp));
            }
            for (auto& l : tmp_lists)
                l.first(l.second);
        } else if (not a.expired_values.empty()) {
            DHT_LOG.w(sr->id, node->id, "[search %s] [node %s] %u expired values",
                      sr->id.toString().c_str(), node->toString().c_str(), a.expired_values.size());
        }
    } else {
        DHT_LOG.w(sr->id, "[node %s] no token provided. Ignoring response content.", node->toString().c_str());
        network_engine.blacklistNode(node);
    }

    if (not sr->done) {
        searchSendGetValues(sr);

        // Force to recompute the next step time
        scheduler.edit(sr->nextSearchStep, scheduler.time());
    }
}

net::RequestAnswer
Dht::onListen(Sp<Node> node, const InfoHash& hash, const Blob& token, size_t socket_id, const Query& query)
{
    if (not hash) {
        DHT_LOG.w(node->id, "[node %s] listen with no info_hash", node->toString().c_str());
        throw net::DhtProtocolException {
            net::DhtProtocolException::NON_AUTHORITATIVE_INFORMATION,
            net::DhtProtocolException::LISTEN_NO_INFOHASH
        };
    }
    if (not tokenMatch(token, node->getAddr())) {
        DHT_LOG.w(hash, node->id, "[node %s] incorrect token %s for 'listen'", node->toString().c_str(), hash.toString().c_str());
        throw net::DhtProtocolException {net::DhtProtocolException::UNAUTHORIZED, net::DhtProtocolException::LISTEN_WRONG_TOKEN};
    }
    Query q = query;
    storageAddListener(hash, node, socket_id, std::move(q));
    return {};
}

void
Dht::onListenDone(const Sp<Node>& node,
        net::RequestAnswer& answer,
        Sp<Search>& sr)
{
    DHT_LOG.d(sr->id, node->id, "[search %s] [node %s] got listen confirmation",
                sr->id.toString().c_str(), node->toString().c_str(), answer.values.size());

    if (not sr->done) {
        const auto& now = scheduler.time();
        searchSendGetValues(sr);
        scheduler.edit(sr->nextSearchStep, now);
    }
}

net::RequestAnswer
Dht::onAnnounce(Sp<Node> n,
        const InfoHash& hash,
        const Blob& token,
        const std::vector<Sp<Value>>& values,
        const time_point& creation_date)
{
    auto& node = *n;
    if (not hash) {
        DHT_LOG.w(node.id, "put with no info_hash");
        throw net::DhtProtocolException {
            net::DhtProtocolException::NON_AUTHORITATIVE_INFORMATION,
            net::DhtProtocolException::PUT_NO_INFOHASH
        };
    }
    if (!tokenMatch(token, node.getAddr())) {
        DHT_LOG.w(hash, node.id, "[node %s] incorrect token %s for 'put'", node.toString().c_str(), hash.toString().c_str());
        throw net::DhtProtocolException {net::DhtProtocolException::UNAUTHORIZED, net::DhtProtocolException::PUT_WRONG_TOKEN};
    }
    {
        // We store a value only if we think we're part of the
        // SEARCH_NODES nodes around the target id.
        auto closest_nodes = buckets(node.getFamily()).findClosestNodes(hash, scheduler.time(), SEARCH_NODES);
        if (closest_nodes.size() >= TARGET_NODES and hash.xorCmp(closest_nodes.back()->id, myid) < 0) {
            DHT_LOG.w(hash, node.id, "[node %s] announce too far from the target. Dropping value.", node.toString().c_str());
            return {};
        }
    }

    auto created = std::min(creation_date, scheduler.time());
    for (const auto& v : values) {
        if (v->id == Value::INVALID_ID) {
            DHT_LOG.w(hash, node.id, "[value %s] incorrect value id", hash.toString().c_str());
            throw net::DhtProtocolException {
                net::DhtProtocolException::NON_AUTHORITATIVE_INFORMATION,
                net::DhtProtocolException::PUT_INVALID_ID
            };
        }
        auto lv = getLocalById(hash, v->id);
        Sp<Value> vc = v;
        if (lv) {
            if (*lv == *vc) {
                DHT_LOG.d(hash, node.id, "[store %s] nothing to do for %s", hash.toString().c_str(), lv->toString().c_str());
            } else {
                const auto& type = getType(lv->type);
                if (type.editPolicy(hash, lv, vc, node.id, node.getAddr())) {
                    DHT_LOG.d(hash, node.id, "[store %s] editing %s",
                            hash.toString().c_str(), vc->toString().c_str());
                    storageStore(hash, vc, created, node.getAddr());
                } else {
                    DHT_LOG.d(hash, node.id, "[store %s] rejecting edition of %s because of storage policy",
                            hash.toString().c_str(), vc->toString().c_str());
                }
            }
        } else {
            // Allow the value to be edited by the storage policy
            const auto& type = getType(vc->type);
            if (type.storePolicy(hash, vc, node.id, node.getAddr())) {
                DHT_LOG.d(hash, node.id, "[store %s] storing %s", hash.toString().c_str(), vc->toString().c_str());
                storageStore(hash, vc, created, node.getAddr());
            } else {
                DHT_LOG.d(hash, node.id, "[store %s] rejecting storage of %s",
                        hash.toString().c_str(), vc->toString().c_str());
            }
        }
    }
    return {};
}

net::RequestAnswer
Dht::onRefresh(Sp<Node> node, const InfoHash& hash, const Blob& token, const Value::Id& vid)
{
    using namespace net;

    const auto& now = scheduler.time();
    if (not tokenMatch(token, node->getAddr())) {
        DHT_LOG.w(hash, node->id, "[node %s] incorrect token %s for 'put'", node->toString().c_str(), hash.toString().c_str());
        throw DhtProtocolException {DhtProtocolException::UNAUTHORIZED, DhtProtocolException::PUT_WRONG_TOKEN};
    }

    auto s = store.find(hash);
    if (s != store.end() and s->second.refresh(now, vid)) {
        DHT_LOG.d(hash, node->id, "[store %s] [node %s] refreshed value %s", hash.toString().c_str(), node->toString().c_str(), std::to_string(vid).c_str());
    } else {
        DHT_LOG.d(hash, node->id, "[store %s] [node %s] got refresh for unknown value",
                hash.toString().c_str(), node->toString().c_str());
        throw DhtProtocolException {DhtProtocolException::NOT_FOUND, DhtProtocolException::STORAGE_NOT_FOUND};
    }
    return {};
}

void
Dht::onAnnounceDone(const Sp<Node>& node, net::RequestAnswer& answer, Sp<Search>& sr)
{
    DHT_LOG.d(sr->id, node->id, "[search %s] [node %s] got reply to put!",
            sr->id.toString().c_str(), node->toString().c_str());
    searchSendGetValues(sr);
    /* if (auto sn = sr->getNode(req->node)) { */
    /*     sn->setRefreshTime(answer.vid, now + answer) */
    /* } */
    sr->checkAnnounced(answer.vid);
}

}
