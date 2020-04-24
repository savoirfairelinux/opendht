/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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
#include <fstream>

namespace dht {

using namespace std::placeholders;

constexpr std::chrono::minutes Dht::MAX_STORAGE_MAINTENANCE_EXPIRE_TIME;
constexpr std::chrono::minutes Dht::SEARCH_EXPIRE_TIME;
constexpr duration Dht::LISTEN_EXPIRE_TIME;
constexpr duration Dht::LISTEN_EXPIRE_TIME_PUBLIC;
constexpr duration Dht::REANNOUNCE_MARGIN;
static constexpr size_t MAX_REQUESTS_PER_SEC {8 * 1024};

NodeStatus
Dht::updateStatus(sa_family_t af)
{
    auto& d = dht(af);
    auto old = d.status;
    d.status = d.getStatus(scheduler.time());
    if (d.status != old) {
        auto& other = dht(af == AF_INET ? AF_INET6 : AF_INET);
        if (other.status == NodeStatus::Disconnected && d.status == NodeStatus::Disconnected)
            onDisconnected();
        else if (other.status == NodeStatus::Connected || d.status == NodeStatus::Connected) {
            // On connected
            if (bootstrapJob) {
                bootstrapJob->cancel();
                bootstrapJob.reset();
            }
            bootstrap_period = std::chrono::seconds(10);
        }
    }
    return d.status;
}

NodeStatus
Dht::Kad::getStatus(time_point now) const
{
    unsigned dubious = 0;
    for (const auto& b : buckets) {
        for (auto& n : b.nodes) {
            if (n->isGood(now)) {
                return NodeStatus::Connected;
            } else if (not n->isExpired())
                dubious++;
        }
    }
    auto& ping = pending_pings;
    if (dubious or ping)
        return NodeStatus::Connecting;
    return NodeStatus::Disconnected;
}

void
Dht::shutdown(ShutdownCallback cb)
{
    if (not persistPath.empty())
        saveState(persistPath);

    if (not maintain_storage) {
        if (cb) cb();
        return;
    }

    // Last store maintenance
    scheduler.syncTime();
    auto remaining = std::make_shared<int>(0);
    auto str_donecb = [=](bool, const std::vector<Sp<Node>>&) {
        --*remaining;
        if (logger_)
            logger_->w("shuting down node: %u ops remaining", *remaining);
        if (!*remaining && cb) { cb(); }
    };

    for (auto& str : store)
        *remaining += maintainStorage(str, true, str_donecb);

    if (logger_)
        logger_->w("shuting down node: after storage, %u ops", *remaining);

    if (!*remaining) {
        if (cb) cb();
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
        if (logger_)
            logger_->d(b.cached->id, "[node %s] sending ping to cached node", b.cached->toString().c_str());
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
    for (auto it = closest; it != srs.end(); it++) {
        auto& s = *it->second;
        if (s.insertNode(node, now)) {
            inserted = true;
            scheduler.edit(s.nextSearchStep, now);
        } else if (not s.expired and not s.done)
            break;
    }
    // insert backward
    for (auto it = closest; it != srs.begin();) {
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
    const auto& now = scheduler.time();
    auto& b = buckets(node->getFamily());
    auto wasEmpty = confirm < 2 && b.grow_time < now - std::chrono::minutes(5);
    if (b.onNewNode(node, confirm, now, myid, network_engine) or confirm) {
        trySearchInsert(node);
        if (wasEmpty) {
            scheduler.edit(nextNodesConfirmation, now + std::chrono::seconds(1));
        }
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
        b.nodes.remove_if([&changed](const Sp<Node>& n) {
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
            if (logger_)
                logger_->d(srp.first, "[search %s] removing search", srp.first.toString().c_str());
            sr.clear();
            return b;
        } else { return false; }
    };
    erase_if(dht4.searches, expired);
    erase_if(dht6.searches, expired);
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
        // Retrieve search
        auto sr = ws.lock();
        if (not sr) return;
        const auto& id = sr->id;
        // Retrieve search node
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
                if (logger_)
                    logger_->d(id, sn->node->id, "[search %s] [node %s] sending %s",
                        id.toString().c_str(), sn->node->toString().c_str(), query_for_vid->toString().c_str());
                sn->getStatus[query_for_vid] = network_engine.sendGetValues(status.node,
                        id,
                        *query_for_vid,
                        -1,
                        std::bind(&Dht::searchNodeGetDone, this, _1, _2, ws, query),
                        std::bind(&Dht::searchNodeGetExpired, this, _1, _2, ws, query_for_vid)
                        );
            } catch (const std::out_of_range&) {
                if (logger_)
                    logger_->e(id, sn->node->id, "[search %s] [node %s] received non-id field in response to "\
                        "'SELECT id' request...",
                        id.toString().c_str(), sn->node->toString().c_str());
            }
        }
    };
    /* add pagination query key for tracking ongoing requests. */
    n->pagination_queries[query].push_back(select_q);

    if (logger_)
        logger_->d(sr->id, n->node->id, "[search %s] [node %s] sending %s",
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
    static const auto ANY_QUERY = std::make_shared<Query>(Select {}, Where {}, true);
    do { /* for all requests to send */
        SearchNode* n = nullptr;
        auto& query = sr->callbacks.empty() ? ANY_QUERY : cb->second.query;
        const time_point up = (not sr->callbacks.empty() and update)
                                ? sr->getLastGetTime(*query)
                                : time_point::min();

        if (pn and pn->canGet(now, up, query)) {
            n = pn;
        } else {
            for (auto& sn : sr->nodes) {
                if (sn->canGet(now, up, query)) {
                    n = sn.get();
                    break;
                }
            }
        }

        if (sr->callbacks.empty()) { /* 'find_node' request */
            if (not n)
                return nullptr;

            /* if (logger_)
                   logger_->d(sr->id, n->node->id, "[search %s] [node %s] sending 'find_node'",
                        sr->id.toString().c_str(), n->node->toString().c_str());*/
            n->getStatus[query] = network_engine.sendFindNode(n->node,
                    sr->id,
                    -1,
                    std::bind(&Dht::searchNodeGetDone, this, _1, _2, ws, query),
                    std::bind(&Dht::searchNodeGetExpired, this, _1, _2, ws, query));

        } else { /* 'get' request */
            if (not n)
                continue;

            if (query and not query->select.empty()) {
                /* The request contains a select. No need to paginate... */
                /* if (logger_)
                       logger_->d(sr->id, n->node->id, "[search %s] [node %s] sending 'get'",
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
    std::weak_ptr<Search> ws = sr;

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
        const auto& now = scheduler.time();
        sr->insertNode(req.node, scheduler.time(), answer.ntoken);
        auto sn = sr->getNode(req.node);
        if (not sn) return;

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
                if (logger_)
                    logger_->d(sr->id, sn->node->id, "[search %s] [node %s] sending 'put' (vid: %d)",
                        sr->id.toString().c_str(), sn->node->toString().c_str(), a.value->id);
                auto created = a.permanent ? time_point::max() : a.created;
                sn->acked[a.value->id] = {
                    network_engine.sendAnnounceValue(sn->node, sr->id, a.value, created, sn->token, onDone, onExpired),
                    next_refresh_time
                };
            } else if (hasValue and a.permanent) {
                if (logger_)
                    logger_->w(sr->id, sn->node->id, "[search %s] [node %s] sending 'refresh' (vid: %d)",
                        sr->id.toString().c_str(), sn->node->toString().c_str(), a.value->id);
                sn->acked[a.value->id] = {
                    network_engine.sendRefreshValue(sn->node, sr->id, a.value->id, sn->token, onDone, onExpired),
                    next_refresh_time
                };
            } else {
                if (logger_)
                    logger_->w(sr->id, sn->node->id, "[search %s] [node %s] already has value (vid: %d). Aborting.",
                        sr->id.toString().c_str(), sn->node->toString().c_str(), a.value->id);
                auto ack_req = std::make_shared<net::Request>(net::Request::State::COMPLETED);
                ack_req->reply_time = now;
                sn->acked[a.value->id] = std::make_pair(std::move(ack_req), next_refresh_time);

                /* step to clear announces */
                scheduler.edit(sr->nextSearchStep, now);
            }
            if (a.permanent) {
                scheduler.add(next_refresh_time - REANNOUNCE_MARGIN, [this,ws] {
                    if (auto sr = ws.lock()) {
                        searchStep(sr);
                    }
                });
            }
        }
    };

    static const auto PROBE_QUERY = std::make_shared<Query>(Select {}.field(Value::Field::Id).field(Value::Field::SeqNum));

    const auto& now = scheduler.time();
    for (auto& np : sr->nodes) {
        auto& n = *np;
        if (not n.isSynced(now))
            continue;

        auto gs = n.probe_query ? n.getStatus.find(n.probe_query) : n.getStatus.end();
        if (gs != n.getStatus.end() and gs->second and gs->second->pending()) {
            continue;
        }

        bool sendQuery = false;
        for (auto& a : sr->announce) {
            if (n.getAnnounceTime(a.value->id) <= now) {
                if (a.permanent) {
                    sendQuery = true;
                } else {
                    if (logger_)
                        logger_->w(sr->id, n.node->id, "[search %s] [node %s] sending 'put' (vid: %d)",
                            sr->id.toString().c_str(), n.node->toString().c_str(), a.value->id);
                    n.acked[a.value->id] = {
                        network_engine.sendAnnounceValue(n.node, sr->id, a.value, a.created, n.token, onDone, onExpired),
                        now + getType(a.value->type).expiration
                    };
                }
            }
        }

        if (sendQuery) {
            n.probe_query = PROBE_QUERY;
            if (logger_)
                logger_->d(sr->id, n.node->id, "[search %s] [node %s] sending %s",
                    sr->id.toString().c_str(), n.node->toString().c_str(), n.probe_query->toString().c_str());
            auto req = network_engine.sendGetValues(n.node,
                    sr->id,
                    *PROBE_QUERY,
                    -1,
                    onSelectDone,
                    std::bind(&Dht::searchNodeGetExpired, this, _1, _2, ws, PROBE_QUERY));
            n.getStatus[PROBE_QUERY] = std::move(req);
        }
        if (not n.candidate and ++i == TARGET_NODES)
            break;
    }
}

void
Dht::searchSynchedNodeListen(const Sp<Search>& sr, SearchNode& n)
{
    const auto& listenExp = getListenExpiration();
    std::weak_ptr<Search> ws = sr;
    for (const auto& l : sr->listeners) {
        const auto& query = l.second.query;
        auto list_token = l.first;
        if (n.getListenTime(query, listenExp) > scheduler.time())
            continue;
        // if (logger_)
        //     logger_->d(sr->id, n.node->id, "[search %s] [node %s] sending 'listen'",
        //        sr->id.toString().c_str(), n.node->toString().c_str());

        auto r = n.listenStatus.find(query);
        if (r == n.listenStatus.end()) {
            r = n.listenStatus.emplace(std::piecewise_construct,
                std::forward_as_tuple(query),
                std::forward_as_tuple(
                [ws,list_token](const std::vector<Sp<Value>>& values, bool expired){
                    if (auto sr = ws.lock()) {
                        auto l = sr->listeners.find(list_token);
                        if (l != sr->listeners.end()) {
                            l->second.get_cb(values, expired);
                        }
                    }
                }, [ws,list_token] (ListenSyncStatus status) {
                    if (auto sr = ws.lock()) {
                        auto l = sr->listeners.find(list_token);
                        if (l != sr->listeners.end()) {
                            l->second.sync_cb(status);
                        }
                    }
                })).first;
            r->second.cacheExpirationJob = scheduler.add(time_point::max(), [this,ws,query,node=n.node]{
                if (auto sr = ws.lock()) {
                    if (auto sn = sr->getNode(node)) {
                        sn->expireValues(query, scheduler);
                    }
                }
            });
        }
        auto prev_req = r != n.listenStatus.end() ? r->second.req : nullptr;
        auto new_req = network_engine.sendListen(n.node, sr->id, *query, n.token, prev_req,
            [this,ws,query](const net::Request& req, net::RequestAnswer&& answer) mutable
            { /* on done */
                if (auto sr = ws.lock()) {
                    scheduler.edit(sr->nextSearchStep, scheduler.time());
                    if (auto sn = sr->getNode(req.node)) {
                        scheduler.add(sn->getListenTime(query, getListenExpiration()), std::bind(&Dht::searchStep, this, sr));
                        sn->onListenSynced(query);
                    }
                    onListenDone(req.node, answer, sr);
                }
            },
            [this,ws,query](const net::Request& req, bool over) mutable
            { /* on request expired */
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
                    sr->insertNode(node, scheduler.time(), answer.ntoken);
                    if (auto sn = sr->getNode(node)) {
                        sn->onValues(query, std::move(answer), types, scheduler);
                    }
                }
            }
        );
        // Here the request may have failed and the CachedListenStatus removed
        r = n.listenStatus.find(query);
        if (r != n.listenStatus.end()) {
            r->second.req = new_req;
        }
    }
}

/* When a search is in progress, we periodically call search_step to send
   further requests. */
void
Dht::searchStep(Sp<Search> sr)
{
    if (not sr or sr->expired or sr->done) return;

    const auto& now = scheduler.time();
    /*if (auto req_count = sr->currentlySolicitedNodeCount())
        if (logger_)
            logger_->d(sr->id, "[search %s IPv%c] step (%d requests)",
                sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6', req_count);*/
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
                    sn->getStatus.erase(get.query);
                    sn->pagination_queries.erase(get.query);
                }

            /* clearing callbacks for announced values */
            sr->checkAnnounced();

            if (sr->callbacks.empty() && sr->announce.empty() && sr->listeners.empty())
                sr->setDone();
        }

        // true if this node is part of the target nodes cluter.
        /*bool in = sr->id.xorCmp(myid, sr->nodes.back().node->id) < 0;

        logger__DBG("[search %s IPv%c] synced%s",
                sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6', in ? ", in" : "");*/

        if (not sr->listeners.empty()) {
            unsigned i = 0;
            for (auto& n : sr->nodes) {
                if (not n->isSynced(now))
                    continue;
                searchSynchedNodeListen(sr, *n);
                if (not n->candidate and ++i == LISTEN_NODES)
                    break;
            }
        }

        // Announce requests
        searchSendAnnounceValue(sr);

        if (sr->callbacks.empty() && sr->announce.empty() && sr->listeners.empty())
            sr->setDone();
    }

    while (sr->currentlySolicitedNodeCount() < MAX_REQUESTED_SEARCH_NODES and searchSendGetValues(sr));

    
    if (sr->getNumberOfConsecutiveBadNodes() >= std::min<size_t>(sr->nodes.size(), SEARCH_MAX_BAD_NODES))
    {
        if (logger_)
            logger_->w(sr->id, "[search %s IPv%c] expired", sr->id.toString().c_str(), sr->af == AF_INET ? '4' : '6');
        sr->expire();
        if (not public_stable)
            connectivityChanged(sr->af);
    }

    /* dumpSearch(*sr, std::cout); */
}

unsigned Dht::refill(Dht::Search& sr) {
    const auto& now = scheduler.time();
    sr.refill_time = now;
    /* we search for up to SEARCH_NODES good nodes. */
    auto cached_nodes = network_engine.getCachedNodes(sr.id, sr.af, SEARCH_NODES);

    if (cached_nodes.empty()) {
        if (logger_)
            logger_->e(sr.id, "[search %s IPv%c] no nodes from cache while refilling search",
                sr.id.toString().c_str(), (sr.af == AF_INET) ? '4' : '6');
        return 0;
    }

    unsigned inserted = 0;
    for (auto& i : cached_nodes) {
        /* try to insert the nodes. Search::insertNode will know how many to insert. */
        if (sr.insertNode(i, now))
            ++inserted;
    }
    if (logger_)
        logger_->d(sr.id, "[search %s IPv%c] refilled search with %u nodes from node cache",
            sr.id.toString().c_str(), (sr.af == AF_INET) ? '4' : '6', inserted);
    return inserted;
}


/* Start a search. */
Sp<Dht::Search>
Dht::search(const InfoHash& id, sa_family_t af, GetCallback gcb, QueryCallback qcb, DoneCallback dcb, Value::Filter f, const Sp<Query>& q)
{
    if (!isRunning(af)) {
        if (logger_)
            logger_->e(id, "[search %s IPv%c] unsupported protocol", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
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
        if (srs.size() < max_searches) {
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
                if (logger_)
                    logger_->e(id, "[search %s IPv%c] maximum number of searches reached !", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
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
        sr->nextSearchStep = scheduler.add(time_point::max(), std::bind(&Dht::searchStep, this, sr));
        if (logger_)
            logger_->w(id, "[search %s IPv%c] new search", id.toString().c_str(), (af == AF_INET) ? '4' : '6');
        if (search_id == 0)
            search_id++;
    }

    sr->get(f, q, qcb, gcb, dcb, scheduler);
    refill(*sr);

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
    auto& srs = searches(af);
    auto srp = srs.find(id);
    if (auto sr = srp == srs.end() ? search(id, af) : srp->second) {
        sr->put(value, callback, created, permanent);
        scheduler.edit(sr->nextSearchStep, scheduler.time());
    } else if (callback) {
        callback(false, {});
    }
}

size_t
Dht::listenTo(const InfoHash& id, sa_family_t af, ValueCallback cb, Value::Filter f, const Sp<Query>& q)
{
    if (!isRunning(af))
        return 0;
       // logger__ERR("[search %s IPv%c] search_time is now in %lfs", sr->id.toString().c_str(), (sr->af == AF_INET) ? '4' : '6', print_dt(tm-clock::now()));

    //logger__WARN("listenTo %s", id.toString().c_str());
    auto& srs = searches(af);
    auto srp = srs.find(id);
    Sp<Search> sr = (srp == srs.end()) ? search(id, af) : srp->second;
    if (!sr)
        throw DhtException("Can't create search");
    if (logger_)
        logger_->w(id, "[search %s IPv%c] listen", id.to_c_str(), (af == AF_INET) ? '4' : '6');
    return sr->listen(cb, f, q, scheduler);
}

size_t
Dht::listen(const InfoHash& id, ValueCallback cb, Value::Filter f, Where where)
{
    scheduler.syncTime();

    auto token = ++listener_token;
    auto gcb = OpValueCache::cacheCallback(std::move(cb), [this, id, token]{
        cancelListen(id, token);
    });

    auto query = std::make_shared<Query>(Select{}, std::move(where));
    auto filter = f.chain(query->where.getFilter());
    auto st = store.find(id);
    if (st == store.end() && store.size() < max_store_keys)
        st = store.emplace(id, scheduler.time() + MAX_STORAGE_MAINTENANCE_EXPIRE_TIME).first;

    size_t tokenlocal = 0;
    if (st != store.end()) {
        tokenlocal = st->second.listen(gcb, filter, query);
        if (tokenlocal == 0)
            return 0;
    }

    auto token4 = Dht::listenTo(id, AF_INET, gcb, filter, query);
    auto token6 = token4 == 0 ? 0 : Dht::listenTo(id, AF_INET6, gcb, filter, query);
    if (token6 == 0 && st != store.end()) {
        st->second.cancelListen(tokenlocal);
        return 0;
    }

    listeners.emplace(token, std::make_tuple(tokenlocal, token4, token6));
    return token;
}

bool
Dht::cancelListen(const InfoHash& id, size_t token)
{
    scheduler.syncTime();

    auto it = listeners.find(token);
    if (it == listeners.end()) {
        if (logger_)
            logger_->w(id, "Listen token not found: %d", token);
        return false;
    }
    if (logger_)
        logger_->d(id, "cancelListen %s with token %d", id.toString().c_str(), token);
    if (auto tokenlocal = std::get<0>(it->second)) {
        auto st = store.find(id);
        if (st != store.end())
            st->second.cancelListen(tokenlocal);
    }
    auto searches_cancel_listen = [this,&id](std::map<InfoHash, Sp<Search>>& srs, size_t token) {
        if (token) {
            auto srp = srs.find(id);
            if (srp != srs.end())
                srp->second->cancelListen(token, scheduler);
        }
    };
    searches_cancel_listen(dht4.searches, std::get<1>(it->second));
    searches_cancel_listen(dht6.searches, std::get<2>(it->second));
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
    T values;
    std::vector<Sp<Node>> nodes;
};

void
Dht::put(const InfoHash& id, Sp<Value> val, DoneCallback callback, time_point created, bool permanent)
{
    if (not val) {
        if (callback)
            callback(false, {});
        return;
    }
    if (val->id == Value::INVALID_ID)
        val->id = std::uniform_int_distribution<Value::Id>{1}(rd);
    scheduler.syncTime();
    const auto& now = scheduler.time();
    created = std::min(now, created);
    storageStore(id, val, created, {}, permanent);

    if (logger_)
        logger_->d(id, "put: adding %s -> %s", id.toString().c_str(), val->toString().c_str());

    auto op = std::make_shared<OpStatus>();
    auto donecb = [callback](const std::vector<Sp<Node>>& nodes, OpStatus& op) {
        // Callback as soon as the value is announced on one of the available networks
        if (callback and not op.status.done and (op.status4.done && op.status6.done)) {
            callback(op.status4.ok or op.status6.ok, nodes);
            op.status.done = true;
        }
    };
    announce(id, AF_INET, val, [=](bool ok4, const std::vector<Sp<Node>>& nodes) {
        if (logger_)
            logger_->d(id, "Announce done IPv4 %d", ok4);
        auto& o = *op;
        o.status4 = {true, ok4};
        donecb(nodes, o);
    }, created, permanent);
    announce(id, AF_INET6, val, [=](bool ok6, const std::vector<Sp<Node>>& nodes) {
        if (logger_)
            logger_->d(id, "Announce done IPv6 %d", ok6);
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

template <typename T, typename St, typename Cb, typename Av, typename Cv>
bool callbackWrapper(Cb get_cb, DoneCallback done_cb, const std::vector<Sp<T>>& values,
    Av add_values, Cv cache_values, GetStatus<St>& op)
{
    if (op.status.done)
        return false;
    auto newvals = add_values(values);
    if (not newvals.empty()) {
        op.status.ok = !get_cb(newvals);
        cache_values(newvals);
    }
    doneCallbackWrapper(done_cb, {}, op);
    return !op.status.ok;
}

void
Dht::get(const InfoHash& id, GetCallback getcb, DoneCallback donecb, Value::Filter&& filter, Where&& where)
{
    scheduler.syncTime();

    auto op = std::make_shared<GetStatus<std::map<Value::Id, Sp<Value>>>>();
    auto gcb = [getcb, donecb, op](const std::vector<Sp<Value>>& vals) {
        auto& o = *op;
        return callbackWrapper(getcb, donecb, vals, [&o](const std::vector<Sp<Value>>& values) {
            std::vector<Sp<Value>> newvals {};
            for (const auto& v : values) {
                auto it = o.values.find(v->id);
                if (it == o.values.cend() or (it->second != v && !(*it->second == *v))) {
                    newvals.push_back(v);
                }
            }
            return newvals;
        }, [&o](const std::vector<Sp<Value>>& newvals) {
            for (const auto& v : newvals)
                o.values[v->id] = v;
        }, o);
    };

    auto q = std::make_shared<Query>(Select {}, std::move(where));
    auto f = filter.chain(q->where.getFilter());

    /* Try to answer this search locally. */
    gcb(getLocal(id, f));

    Dht::search(id, AF_INET, gcb, {}, [=](bool ok, const std::vector<Sp<Node>>& nodes) {
        //logger__WARN("DHT done IPv4");
        op->status4 = {true, ok};
        doneCallbackWrapper(donecb, nodes, *op);
    }, f, q);
    Dht::search(id, AF_INET6, gcb, {}, [=](bool ok, const std::vector<Sp<Node>>& nodes) {
        //logger__WARN("DHT done IPv6");
        op->status6 = {true, ok};
        doneCallbackWrapper(donecb, nodes, *op);
    }, f, q);
}

void Dht::query(const InfoHash& id, QueryCallback cb, DoneCallback done_cb, Query&& q)
{
    scheduler.syncTime();
    auto op = std::make_shared<GetStatus<std::vector<Sp<FieldValueIndex>>>>();
    auto f = q.where.getFilter();
    auto qcb = [cb, done_cb, op](const std::vector<Sp<FieldValueIndex>>& fields){
        auto& o = *op;
        return callbackWrapper(cb, done_cb, fields, [&](const std::vector<Sp<FieldValueIndex>>& fields) {
            std::vector<Sp<FieldValueIndex>> newvals {};
            for (const auto& f : fields) {
                auto it = std::find_if(o.values.cbegin(), o.values.cend(),
                    [&](const Sp<FieldValueIndex>& sf) {
                        return sf == f or f->containedIn(*sf);
                    });
                if (it == o.values.cend()) {
                    auto lesser = std::find_if(o.values.begin(), o.values.end(),
                        [&](const Sp<FieldValueIndex>& sf) {
                            return sf->containedIn(*f);
                        });
                    if (lesser != o.values.end())
                        o.values.erase(lesser);
                    newvals.push_back(f);
                }
            }
            return newvals;
        }, [&](const std::vector<Sp<FieldValueIndex>>& fields){
            o.values.insert(o.values.end(), fields.begin(), fields.end());
        }, o);
    };

    /* Try to answer this search locally. */
    auto values = getLocal(id, f);
    std::vector<Sp<FieldValueIndex>> local_fields(values.size());
    std::transform(values.begin(), values.end(), local_fields.begin(), [&q](const Sp<Value>& v) {
        return std::make_shared<FieldValueIndex>(*v, q.select);
    });
    qcb(local_fields);

    auto sq = std::make_shared<Query>(std::move(q));
    Dht::search(id, AF_INET, {}, qcb, [=](bool ok, const std::vector<Sp<Node>>& nodes) {
        //logger__WARN("DHT done IPv4");
        op->status4 = {true, ok};
        doneCallbackWrapper(done_cb, nodes, *op);
    }, f, sq);
    Dht::search(id, AF_INET6, {}, qcb, [=](bool ok, const std::vector<Sp<Node>>& nodes) {
        //logger__WARN("DHT done IPv6");
        op->status6 = {true, ok};
        doneCallbackWrapper(done_cb, nodes, *op);
    }, f, sq);
}

std::vector<Sp<Value>>
Dht::getLocal(const InfoHash& id, const Value::Filter& f) const
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
Dht::getPut(const InfoHash& id) const
{
    std::vector<Sp<Value>> ret;
    auto find_values = [&](const std::map<InfoHash, Sp<Search>>& srs) {
        auto srp = srs.find(id);
        if (srp == srs.end()) return;
        auto vals = srp->second->getPut();
        ret.insert(ret.end(), vals.begin(), vals.end());
    };
    find_values(dht4.searches);
    find_values(dht6.searches);
    return ret;
}

Sp<Value>
Dht::getPut(const InfoHash& id, const Value::Id& vid) const
{
    auto find_value = [&](const std::map<InfoHash, Sp<Search>>& srs) {
        auto srp = srs.find(id);
        return (srp != srs.end()) ? srp->second->getPut(vid) : Sp<Value> {};
    };
    if (auto v4 = find_value(dht4.searches))
        return v4;
    if (auto v6 = find_value(dht6.searches))
        return v6;
    return {};
}

bool
Dht::cancelPut(const InfoHash& id, const Value::Id& vid)
{
    bool canceled {false};
    auto sr_cancel_put = [&](std::map<InfoHash, Sp<Search>>& srs) {
        auto srp = srs.find(id);
        return (srp != srs.end()) ? srp->second->cancelPut(vid) : false;
    };
    canceled |= sr_cancel_put(dht4.searches);
    canceled |= sr_cancel_put(dht6.searches);
    if (canceled)
        storageErase(id, vid);
    return canceled;
}

// Storage

void
Dht::storageChanged(const InfoHash& id, Storage& st, ValueStorage& v, bool newValue)
{
    if (newValue) {
        if (not st.local_listeners.empty()) {
            if (logger_)
                logger_->d(id, "[store %s] %lu local listeners", id.toString().c_str(), st.local_listeners.size());
            std::vector<std::pair<ValueCallback, std::vector<Sp<Value>>>> cbs;
            cbs.reserve(st.local_listeners.size());
            for (const auto& l : st.local_listeners) {
                std::vector<Sp<Value>> vals;
                if (not l.second.filter or l.second.filter(*v.data))
                    vals.push_back(v.data);
                if (not vals.empty()) {
                    if (logger_)
                        logger_->d(id, "[store %s] sending update local listener with token %lu",
                            id.toString().c_str(),
                            l.first);
                    cbs.emplace_back(l.second.get_cb, std::move(vals));
                }
            }
            // listeners are copied: they may be deleted by the callback
            for (auto& cb : cbs)
                cb.first(cb.second, false);
        }
    }

    if (not st.listeners.empty()) {
        if (logger_)
            logger_->d(id, "[store %s] %lu remote listeners", id.toString().c_str(), st.listeners.size());
        for (const auto& node_listeners : st.listeners) {
            for (const auto& l : node_listeners.second) {
                auto f = l.second.query.where.getFilter();
                if (f and not f(*v.data))
                    continue;
                if (logger_)
                    logger_->w(id, node_listeners.first->id, "[store %s] [node %s] sending update",
                        id.toString().c_str(),
                        node_listeners.first->toString().c_str());
                std::vector<Sp<Value>> vals {};
                vals.push_back(v.data);
                Blob ntoken = makeToken(node_listeners.first->getAddr(), false);
                network_engine.tellListener(node_listeners.first, l.first, id, 0, ntoken, {}, {},
                        std::move(vals), l.second.query, l.second.version);
            }
        }
    }
}

bool
Dht::storageStore(const InfoHash& id, const Sp<Value>& value, time_point created, const SockAddr& sa, bool permanent)
{
    const auto& now = scheduler.time();
    created = std::min(created, now);
    auto expiration = permanent ? time_point::max() : created + getType(value->type).expiration;
    if (expiration < now)
        return false;

    auto st = store.find(id);
    if (st == store.end()) {
        if (store.size() >= max_store_keys)
            return false;
        auto st_i = store.emplace(id, now);
        st = st_i.first;
        if (maintain_storage and st_i.second)
            scheduler.add(st->second.maintenance_time, std::bind(&Dht::dataPersistence, this, id));
    }

    StorageBucket* store_bucket {nullptr};
    if (sa)
        store_bucket = &store_quota[sa];

    auto store = st->second.store(id, value, created, expiration, store_bucket);
    if (auto vs = store.first) {
        total_store_size += store.second.size_diff;
        total_values += store.second.values_diff;
        if (not permanent) {
            scheduler.add(expiration, std::bind(&Dht::expireStorage, this, id));
        }
        if (total_store_size > max_store_size) {
            expireStore();
        }
        storageChanged(id, st->second, *vs, store.second.values_diff > 0);
    }

    return std::get<0>(store);
}

bool
Dht::storageErase(const InfoHash& id, Value::Id vid)
{
    auto st = store.find(id);
    if (st == store.end())
        return false;
    auto ret = st->second.remove(id, vid);
    total_store_size += ret.size_diff;
    total_values += ret.values_diff;
    return ret.values_diff;
}

void
Dht::storageAddListener(const InfoHash& id, const Sp<Node>& node, size_t socket_id, Query&& query, int version)
{
    const auto& now = scheduler.time();
    auto st = store.find(id);
    if (st == store.end()) {
        if (store.size() >= max_store_keys)
            return;
        st = store.emplace(id, now).first;
    }
    auto& node_listeners = st->second.listeners[node];
    auto l = node_listeners.find(socket_id);
    if (l == node_listeners.end()) {
        auto vals = st->second.get(query.where.getFilter());
        if (not vals.empty()) {
            network_engine.tellListener(node, socket_id, id, WANT4 | WANT6, makeToken(node->getAddr(), false),
                    dht4.buckets.findClosestNodes(id, now, TARGET_NODES), dht6.buckets.findClosestNodes(id, now, TARGET_NODES),
                    std::move(vals), query, version);
        }
        node_listeners.emplace(socket_id, Listener {now, std::forward<Query>(query), version});
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
        if (logger_)
            logger_->d(id, "[store %s] discarded %ld expired values (%ld bytes)",
            id.toString().c_str(), stats.second.size(), -stats.first);

        if (not st.listeners.empty()) {
            if (logger_)
                logger_->d(id, "[store %s] %lu remote listeners", id.toString().c_str(), st.listeners.size());

            std::vector<Value::Id> ids;
            ids.reserve(stats.second.size());
            for (const auto& v : stats.second)
                ids.emplace_back(v->id);

            for (const auto& node_listeners : st.listeners) {
                for (const auto& l : node_listeners.second) {
                    if (logger_)
                        logger_->w(id, node_listeners.first->id, "[store %s] [node %s] sending expired",
                            id.toString().c_str(),
                            node_listeners.first->toString().c_str());
                    Blob ntoken = makeToken(node_listeners.first->getAddr(), false);
                    network_engine.tellListenerExpired(node_listeners.first, l.first, id, ntoken, ids);
                }
            }
        }
        for (const auto& local_listeners : st.local_listeners) {
            local_listeners.second.get_cb(stats.second, true);
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
            if (logger_)
                logger_->d(i->first, "[store %s] discarding empty storage", i->first.toString().c_str());
            i = store.erase(i);
        }
        else
            ++i;
    }

    // remove more values if storage limit is exceeded
    while (total_store_size > max_store_size) {
        // find IP using the most storage
        if (store_quota.empty()) {
            if (logger_)
                logger_->w("No space left: local data consumes all the quota!");
            break;
        }
        auto largest = store_quota.begin();
        for (auto it = ++largest; it != store_quota.end(); ++it) {
            if (it->second.size() > largest->second.size())
                largest = it;
        }
        if (logger_)
            logger_->w("No space left: discarding value of largest consumer %s", largest->first.toString().c_str());
        while (true) {
            auto exp_value = largest->second.getOldest();
            auto storage = store.find(exp_value.first);
            if (storage != store.end()) {
                auto ret = storage->second.remove(exp_value.first, exp_value.second);
                total_store_size += ret.size_diff;
                total_values += ret.values_diff;
                if (logger_)
                    logger_->w("Discarded %ld bytes, still %ld used", largest->first.toString().c_str(), total_store_size);
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
    reported_addr.erase(std::remove_if(reported_addr.begin(), reported_addr.end(), [&](const ReportedAddr& addr){
        return addr.second.getFamily() == af;
    }), reported_addr.end());
}

void
Dht::rotateSecrets()
{
    oldsecret = secret;
    secret = std::uniform_int_distribution<uint64_t>{}(rd);
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
    NodeStats stats = dht(af).getNodesStats(scheduler.time(), myid);
    stats.node_cache_size = network_engine.getNodeCacheSize(af);
    return stats;
}

NodeStats
Dht::Kad::getNodesStats(time_point now, const InfoHash& myid) const
{
    NodeStats stats {};
    for (const auto& b : buckets) {
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
    stats.table_depth = buckets.depth(buckets.findBucket(myid));
    stats.searches = searches.size();
    return stats;
}

void
Dht::dumpBucket(const Bucket& b, std::ostream& out) const
{
    const auto& now = scheduler.time();
    using namespace std::chrono;
    out << b.first << " count: " << b.nodes.size() << " updated: " << print_time_relative(now, b.time);
    if (b.cached)
        out << " (cached)";
    out  << std::endl;
    for (auto& n : b.nodes) {
        out << "    Node " << n->toString();
        const auto& t = n->getTime();
        const auto& r = n->getReplyTime();
        if (t != r)
            out << " updated: " << print_time_relative(now, t) << ", replied: " << print_time_relative(now, r);
        else
            out << " updated: " << print_time_relative(now, t);
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
    const auto& listen_expire = getListenExpiration();
    using namespace std::chrono;
    out << std::endl << "Search IPv" << (sr.af == AF_INET6 ? '6' : '4') << ' ' << sr.id << " gets: " << sr.callbacks.size();
    out << ", last step: " << print_time_relative(now, sr.step_time);
    if (sr.done)
        out << " [done]";
    if (sr.expired)
        out << " [expired]";
    bool synced = sr.isSynced(now);
    out << (synced ? " [synced]" : " [not synced]");
    if (synced && sr.isListening(now, listen_expire))
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
    auto last_get = sr.getLastGetTime();
    for (const auto& np : sr.nodes) {
        auto& n = *np;
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
                    << (n.isListening(now,listen_expire) ? 'l' : (n.pending(n.listenStatus) ? 'f' : ' ')) << "] ";
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
                        out << ack->second.first->getStateChar();
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
    for (const auto& b : dht4.buckets)
        dumpBucket(b, out);
    out << "Buckets IPv6 :" << std::endl;
    for (const auto& b : dht6.buckets)
        dumpBucket(b, out);

    auto dump_searches = [&](std::map<InfoHash, Sp<Search>> srs) {
        for (auto& srp : srs)
            dumpSearch(*srp.second, out);
    };
    dump_searches(dht4.searches);
    dump_searches(dht6.searches);
    out << std::endl;

    out << getStorageLog() << std::endl;

    if (logger_)
        logger_->d("%s", out.str().c_str());
}

std::string
Dht::getStorageLog() const
{
    std::stringstream out;
    for (const auto& s : store)
        out << printStorageLog(s);
    out << std::endl << std::endl;
    std::multimap<size_t, const SockAddr*> q_map;
    for (const auto& ip : store_quota)
        if (ip.second.size())
            q_map.emplace(ip.second.size(), &ip.first);
    for (auto ip = q_map.rbegin(); ip != q_map.rend(); ++ip)
        out << "IP " << ip->second->toString() << " uses " << ip->first << " bytes" << std::endl;
    out << std::endl;
    out << "Total " << store.size() << " storages, " << total_values << " values (";
    if (total_store_size < 1024)
        out << total_store_size << " bytes)";
    else
        out << (total_store_size/1024) << " / " << (max_store_size/1024) << " KB)";
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
    auto num_searches = dht4.searches.size() + dht6.searches.size();
    if (num_searches > 8) {
        if (not af or af == AF_INET)
            for (const auto& sr : dht4.searches)
                out << "[search " << sr.first << " IPv4]" << std::endl;
        if (not af or af == AF_INET6)
            for (const auto& sr : dht6.searches)
                out << "[search " << sr.first << " IPv6]" << std::endl;
    } else {
        out << "s:synched, u:updated, a:announced, c:candidate, f:cur req, x:expired, *:known" << std::endl;
        if (not af or af == AF_INET)
            for (const auto& sr : dht4.searches)
                dumpSearch(*sr.second, out);
        if (not af or af == AF_INET6)
            for (const auto& sr : dht6.searches)
                dumpSearch(*sr.second, out);
    }
    out << "Total: " << num_searches << " searches (" << dht4.searches.size() << " IPv4, " << dht6.searches.size() << " IPv6)." << std::endl;
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
    for (auto& s : dht4.searches)
        s.second->clear();
    for (auto& s : dht6.searches)
        s.second->clear();
}

net::NetworkConfig
fromDhtConfig(const Config& config)
{
    net::NetworkConfig netConf;
    netConf.network = config.network;
    netConf.max_req_per_sec = config.max_req_per_sec ? config.max_req_per_sec : MAX_REQUESTS_PER_SEC;
    netConf.max_peer_req_per_sec = config.max_peer_req_per_sec
        ? config.max_peer_req_per_sec
        : netConf.max_req_per_sec/8;
    return netConf;
}

Dht::Dht() : store(), network_engine(logger_, rd, scheduler, {}) {}

Dht::Dht(std::unique_ptr<net::DatagramSocket>&& sock, const Config& config, const Sp<Logger>& l)
    : DhtInterface(l),
    myid(config.node_id ? config.node_id : InfoHash::getRandom()),
    store(),
    store_quota(),
    max_store_keys(config.max_store_size ? (int)config.max_store_size : MAX_HASHES),
    max_searches(config.max_searches ? (int)config.max_searches : MAX_SEARCHES),
    network_engine(myid, fromDhtConfig(config), std::move(sock), logger_, rd, scheduler,
            std::bind(&Dht::onError, this, _1, _2),
            std::bind(&Dht::onNewNode, this, _1, _2),
            std::bind(&Dht::onReportedAddr, this, _1, _2),
            std::bind(&Dht::onPing, this, _1),
            std::bind(&Dht::onFindNode, this, _1, _2, _3),
            std::bind(&Dht::onGetValues, this, _1, _2, _3, _4),
            std::bind(&Dht::onListen, this, _1, _2, _3, _4, _5, _6),
            std::bind(&Dht::onAnnounce, this, _1, _2, _3, _4, _5),
            std::bind(&Dht::onRefresh, this, _1, _2, _3, _4)),
    persistPath(config.persist_path),
    is_bootstrap(config.is_bootstrap),
    maintain_storage(config.maintain_storage),
    public_stable(config.public_stable)
{
    scheduler.syncTime();
    auto s = network_engine.getSocket();
    if (not s or (not s->hasIPv4() and not s->hasIPv6()))
        throw DhtException("Opened socket required");
    if (s->hasIPv4()) {
        dht4.buckets = {Bucket {AF_INET}};
        dht4.buckets.is_client = config.is_bootstrap;
    }
    if (s->hasIPv6()) {
        dht6.buckets = {Bucket {AF_INET6}};
        dht6.buckets.is_client = config.is_bootstrap;
    }

    search_id = std::uniform_int_distribution<decltype(search_id)>{}(rd);

    uniform_duration_distribution<> time_dis {std::chrono::seconds(3), std::chrono::seconds(5)};
    nextNodesConfirmation = scheduler.add(scheduler.time() + time_dis(rd), std::bind(&Dht::confirmNodes, this));

    // Fill old secret
    secret = std::uniform_int_distribution<uint64_t>{}(rd);
    rotateSecrets();

    expire();

    if (logger_)
        logger_->d("DHT node initialised with ID %s", myid.toString().c_str());

    if (not persistPath.empty())
        loadState(persistPath);
}

bool
Dht::neighbourhoodMaintenance(RoutingTable& list)
{
    //logger__DBG("neighbourhoodMaintenance");
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

    auto n = q->randomNode(rd);
    if (n) {
        if (logger_)
            logger_->d(id, n->id, "[node %s] sending [find %s] for neighborhood maintenance",
                n->toString().c_str(), id.toString().c_str());
        /* Since our node-id is the same in both DHTs, it's probably
           profitable to query both families. */
        network_engine.sendFindNode(n, id, network_engine.want());
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
            InfoHash id = list.randomId(b, rd);
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

            auto n = q->randomNode(rd);
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

                if (logger_)
                    logger_->d(id, n->id, "[node %s] sending find %s for bucket maintenance", n->toString().c_str(), id.toString().c_str());
                //auto start = scheduler.time();
                network_engine.sendFindNode(n, id, want, nullptr, [this,n](const net::Request&, bool over) {
                    if (over) {
                        const auto& end = scheduler.time();
                        // using namespace std::chrono;
                        // if (logger_)
                        //     logger_->d(n->id, "[node %s] bucket maintenance op expired after %s", n->toString().c_str(), print_duration(end-start).c_str());
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
        if (logger_)
            logger_->d(id, "[storage %s] maintenance (%u values, %u bytes)",
                id.toString().c_str(), str->second.valueCount(), str->second.totalSize());
        maintainStorage(*str);
        str->second.maintenance_time = now + MAX_STORAGE_MAINTENANCE_EXPIRE_TIME;
        scheduler.add(str->second.maintenance_time, std::bind(&Dht::dataPersistence, this, id));
    }
}

size_t
Dht::maintainStorage(decltype(store)::value_type& storage, bool force, const DoneCallback& donecb)
{
    const auto& now = scheduler.time();
    size_t announce_per_af = 0;

    auto maintain = [&](sa_family_t af){
        bool want = true;
        auto nodes = buckets(af).findClosestNodes(storage.first, now);
        if (!nodes.empty()) {
            if (force || storage.first.xorCmp(nodes.back()->id, myid) < 0) {
                for (auto &value : storage.second.getValues()) {
                    const auto& vt = getType(value.data->type);
                    if (force || value.created + vt.expiration > now + MAX_STORAGE_MAINTENANCE_EXPIRE_TIME) {
                        // gotta put that value there
                        announce(storage.first, af, value.data, donecb, value.created);
                        ++announce_per_af;
                    }
                }
                want = false;
            }
        }
        return want;
    };
    bool want4 = maintain(AF_INET), want6 = maintain(AF_INET6);

    if (not want4 and not want6) {
        if (logger_)
            logger_->d(storage.first, "Discarding storage values %s", storage.first.toString().c_str());
        auto diff = storage.second.clear();
        total_store_size += diff.size_diff;
        total_values += diff.values_diff;
    }

    return announce_per_af;
}

time_point
Dht::periodic(const uint8_t *buf, size_t buflen, SockAddr from, const time_point& now)
{
    scheduler.syncTime(now);
    if (buflen) {
        try {
            network_engine.processMessage(buf, buflen, std::move(from));
        } catch (const std::exception& e) {
            if (logger_)
                logger_->w("Can't process message: %s", e.what());
        }
    }
    return scheduler.run();
}

void
Dht::expire()
{
    uniform_duration_distribution<> time_dis(std::chrono::minutes(2), std::chrono::minutes(6));
    auto expire_stuff_time = scheduler.time() + duration(time_dis(rd));

    expireBuckets(dht4.buckets);
    expireBuckets(dht6.buckets);
    expireStore();
    expireSearches();
    scheduler.add(expire_stuff_time, std::bind(&Dht::expire, this));
}

void
Dht::onDisconnected()
{
    if (dht4.status != NodeStatus::Disconnected || dht6.status != NodeStatus::Disconnected)
        return;
    if (logger_)
        logger_->d(myid, "Bootstraping");
    for (const auto& boootstrap : bootstrap_nodes) {
        try {
            auto ips = network_engine.getSocket()->resolve(boootstrap.first, boootstrap.second);
            for (auto& ip : ips) {
                if (ip.getPort() == 0)
                    ip.setPort(net::DHT_DEFAULT_PORT);
                pingNode(ip);
            }
        } catch (const std::exception& e) {
            if (logger_)
                logger_->e(myid, "Can't resolve %s:%s: %s", boootstrap.first.c_str(), boootstrap.second.c_str(), e.what());
        }
    }
    if (bootstrapJob)
        bootstrapJob->cancel();
    bootstrapJob = scheduler.add(scheduler.time() + bootstrap_period, std::bind(&Dht::onDisconnected, this));
    bootstrap_period *= 2;
}

void
Dht::confirmNodes()
{
    using namespace std::chrono;
    bool soon = false;
    const auto& now = scheduler.time();

    if (dht4.searches.empty() and dht4.status == NodeStatus::Connected) {
        if (logger_)
            logger_->d(myid, "[confirm nodes] initial IPv4 'get' for my id (%s)", myid.toString().c_str());
        search(myid, AF_INET);
    }
    if (dht6.searches.empty() and dht6.status == NodeStatus::Connected) {
        if (logger_)
            logger_->d(myid, "[confirm nodes] initial IPv6 'get' for my id (%s)", myid.toString().c_str());
        search(myid, AF_INET6);
    }

    soon |= bucketMaintenance(dht4.buckets);
    soon |= bucketMaintenance(dht6.buckets);

    if (!soon) {
        if (dht4.buckets.grow_time >= now - seconds(150))
            soon |= neighbourhoodMaintenance(dht4.buckets);
        if (dht6.buckets.grow_time >= now - seconds(150))
            soon |= neighbourhoodMaintenance(dht6.buckets);
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
    const auto& now = scheduler.time();

    for (const auto& node : import) {
        if (node.second.empty())
            continue;

        try {
            msgpack::unpacked msg;
            msgpack::unpack(msg, (const char*)node.second.data(), node.second.size());
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
                    if (logger_)
                        logger_->e(node.first, "Error reading value at %s", node.first.toString().c_str());
                    continue;
                }
                val_time = std::min(val_time, now);
                storageStore(node.first, std::make_shared<Value>(std::move(tmp_val)), val_time);
            }
        } catch (const std::exception&) {
            if (logger_)
                logger_->e(node.first, "Error reading values at %s", node.first.toString().c_str());
            continue;
        }
    }
}


std::vector<NodeExport>
Dht::exportNodes() const
{
    const auto& now = scheduler.time();
    std::vector<NodeExport> nodes;
    const auto b4 = dht4.buckets.findBucket(myid);
    if (b4 != dht4.buckets.end()) {
        for (auto& n : b4->nodes)
            if (n->isGood(now))
                nodes.push_back(n->exportNode());
    }
    const auto b6 = dht6.buckets.findBucket(myid);
    if (b6 != dht6.buckets.end()) {
        for (auto& n : b6->nodes)
            if (n->isGood(now))
                nodes.push_back(n->exportNode());
    }
    for (auto b = dht4.buckets.begin(); b != dht4.buckets.end(); ++b) {
        if (b == b4) continue;
        for (auto& n : b->nodes)
            if (n->isGood(now))
                nodes.push_back(n->exportNode());
    }
    for (auto b = dht6.buckets.begin(); b != dht6.buckets.end(); ++b) {
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
Dht::pingNode(SockAddr sa, DoneCallbackSimple&& cb)
{
    scheduler.syncTime();
    if (logger_)
        logger_->d("Sending ping to %s", sa.toString().c_str());
    auto& count = dht(sa.getFamily()).pending_pings;
    count++;
    network_engine.sendPing(std::move(sa), [&count,cb](const net::Request&, net::RequestAnswer&&) {
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
        if (logger_)
            logger_->e(node->id, "[node %s] token flush", node->toString().c_str());
        node->authError();
        node->cancelRequest(req);
        for (auto& srp : searches(node->getFamily())) {
            auto& sr = srp.second;
            for (auto& n : sr->nodes) {
                if (n->node != node) continue;
                n->token.clear();
                n->last_get_reply = time_point::min();
                searchSendGetValues(sr);
                scheduler.edit(sr->nextSearchStep, scheduler.time());
                break;
            }
        }
    } else if (e.getCode() == net::DhtProtocolException::NOT_FOUND) {
        if (logger_)
            logger_->e(node->id, "[node %s] returned error 404: storage not found", node->toString().c_str());
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
        answer.nodes4 = dht4.buckets.findClosestNodes(target, now, TARGET_NODES);
    if (want & WANT6)
        answer.nodes6 = dht6.buckets.findClosestNodes(target, now, TARGET_NODES);
    return answer;
}

net::RequestAnswer
Dht::onGetValues(Sp<Node> node, const InfoHash& hash, want_t, const Query& query)
{
    if (not hash) {
        if (logger_)
            logger_->w("[node %s] Eek! Got get_values with no info_hash", node->toString().c_str());
        throw net::DhtProtocolException {
            net::DhtProtocolException::NON_AUTHORITATIVE_INFORMATION,
            net::DhtProtocolException::GET_NO_INFOHASH
        };
    }
    const auto& now = scheduler.time();
    net::RequestAnswer answer {};
    auto st = store.find(hash);
    answer.ntoken = makeToken(node->getAddr(), false);
    answer.nodes4 = dht4.buckets.findClosestNodes(hash, now, TARGET_NODES);
    answer.nodes6 = dht6.buckets.findClosestNodes(hash, now, TARGET_NODES);
    if (st != store.end() && not st->second.empty()) {
        answer.values = st->second.get(query.where.getFilter());
        if (logger_)
            logger_->d(hash, "[node %s] sending %u values", node->toString().c_str(), answer.values.size());
    }
    return answer;
}

void Dht::onGetValuesDone(const Sp<Node>& node,
        net::RequestAnswer& a,
        Sp<Search>& sr,
        const Sp<Query>& orig_query)
{
    if (not sr) {
        if (logger_)
            logger_->w("[search unknown] got reply to 'get'. Ignoring.");
        return;
    }

    /* if (logger_)
           logger_->d(sr->id, "[search %s] [node %s] got reply to 'get' with %u nodes",
            sr->id.toString().c_str(), node->toString().c_str(), a.nodes4.size()+a.nodes6.size());*/

    if (not a.ntoken.empty()) {
        if (not a.values.empty() or not a.fields.empty()) {
            if (logger_)
                logger_->d(sr->id, node->id, "[search %s] [node %s] found %u values",
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
            /*std::vector<std::pair<ValueCallback, std::vector<Sp<Value>>>> tmp_lists;
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
                l.first(l.second, false);*/
        } else if (not a.expired_values.empty()) {
            if (logger_)
                logger_->w(sr->id, node->id, "[search %s] [node %s] %u expired values",
                      sr->id.toString().c_str(), node->toString().c_str(), a.expired_values.size());
        }
    } else {
        if (logger_)
            logger_->w(sr->id, "[node %s] no token provided. Ignoring response content.", node->toString().c_str());
        network_engine.blacklistNode(node);
    }

    if (not sr->done) {
        searchSendGetValues(sr);

        // Force to recompute the next step time
        scheduler.edit(sr->nextSearchStep, scheduler.time());
    }
}

net::RequestAnswer
Dht::onListen(Sp<Node> node, const InfoHash& hash, const Blob& token, size_t socket_id, const Query& query, int version)
{
    if (not hash) {
        if (logger_)
            logger_->w(node->id, "[node %s] listen with no info_hash", node->toString().c_str());
        throw net::DhtProtocolException {
            net::DhtProtocolException::NON_AUTHORITATIVE_INFORMATION,
            net::DhtProtocolException::LISTEN_NO_INFOHASH
        };
    }
    if (not tokenMatch(token, node->getAddr())) {
        if (logger_)
            logger_->w(hash, node->id, "[node %s] incorrect token %s for 'listen'", node->toString().c_str(), hash.toString().c_str());
        throw net::DhtProtocolException {net::DhtProtocolException::UNAUTHORIZED, net::DhtProtocolException::LISTEN_WRONG_TOKEN};
    }
    Query q = query;
    storageAddListener(hash, node, socket_id, std::move(q), version);
    return {};
}

void
Dht::onListenDone(const Sp<Node>& /* node */, net::RequestAnswer& /* answer */, Sp<Search>& sr)
{
    // if (logger_)
    //     logger_->d(sr->id, node->id, "[search %s] [node %s] got listen confirmation",
    //            sr->id.toString().c_str(), node->toString().c_str(), answer.values.size());

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
        if (logger_)
            logger_->w(node.id, "put with no info_hash");
        throw net::DhtProtocolException {
            net::DhtProtocolException::NON_AUTHORITATIVE_INFORMATION,
            net::DhtProtocolException::PUT_NO_INFOHASH
        };
    }
    if (!tokenMatch(token, node.getAddr())) {
        if (logger_)
            logger_->w(hash, node.id, "[node %s] incorrect token %s for 'put'", node.toString().c_str(), hash.toString().c_str());
        throw net::DhtProtocolException {net::DhtProtocolException::UNAUTHORIZED, net::DhtProtocolException::PUT_WRONG_TOKEN};
    }
    {
        // We store a value only if we think we're part of the
        // SEARCH_NODES nodes around the target id.
        auto closest_nodes = buckets(node.getFamily()).findClosestNodes(hash, scheduler.time(), SEARCH_NODES);
        if (closest_nodes.size() >= TARGET_NODES and hash.xorCmp(closest_nodes.back()->id, myid) < 0) {
            if (logger_)
                logger_->w(hash, node.id, "[node %s] announce too far from the target. Dropping value.", node.toString().c_str());
            return {};
        }
    }

    auto created = std::min(creation_date, scheduler.time());
    for (const auto& v : values) {
        if (v->id == Value::INVALID_ID) {
            if (logger_)
                logger_->w(hash, node.id, "[value %s] incorrect value id", hash.toString().c_str());
            throw net::DhtProtocolException {
                net::DhtProtocolException::NON_AUTHORITATIVE_INFORMATION,
                net::DhtProtocolException::PUT_INVALID_ID
            };
        }
        auto lv = getLocalById(hash, v->id);
        Sp<Value> vc = v;
        if (lv) {
            if (*lv == *vc) {
                storageRefresh(hash, v->id);
                if (logger_)
                    logger_->d(hash, node.id, "[store %s] [node %s] refreshed value %s", hash.toString().c_str(), node.toString().c_str(), std::to_string(v->id).c_str());
            } else {
                const auto& type = getType(lv->type);
                if (type.editPolicy(hash, lv, vc, node.id, node.getAddr())) {
                    if (logger_)
                        logger_->d(hash, node.id, "[store %s] editing %s",
                            hash.toString().c_str(), vc->toString().c_str());
                    storageStore(hash, vc, created, node.getAddr());
                } else {
                    if (logger_)
                        logger_->d(hash, node.id, "[store %s] rejecting edition of %s because of storage policy",
                            hash.toString().c_str(), vc->toString().c_str());
                }
            }
        } else {
            // Allow the value to be edited by the storage policy
            const auto& type = getType(vc->type);
            if (type.storePolicy(hash, vc, node.id, node.getAddr())) {
                // if (logger_)
                //     logger_->d(hash, node.id, "[store %s] storing %s", hash.toString().c_str(), std::to_string(vc->id).c_str());
                storageStore(hash, vc, created, node.getAddr());
            } else {
                if (logger_)
                    logger_->d(hash, node.id, "[store %s] rejecting storage of %s",
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

    if (not tokenMatch(token, node->getAddr())) {
        if (logger_)
            logger_->w(hash, node->id, "[node %s] incorrect token %s for 'put'", node->toString().c_str(), hash.toString().c_str());
        throw DhtProtocolException {DhtProtocolException::UNAUTHORIZED, DhtProtocolException::PUT_WRONG_TOKEN};
    }
    if (storageRefresh(hash, vid)) {
        if (logger_)
            logger_->d(hash, node->id, "[store %s] [node %s] refreshed value %s", hash.toString().c_str(), node->toString().c_str(), std::to_string(vid).c_str());
    } else {
        if (logger_)
            logger_->d(hash, node->id, "[store %s] [node %s] got refresh for unknown value",
                hash.toString().c_str(), node->toString().c_str());
        throw DhtProtocolException {DhtProtocolException::NOT_FOUND, DhtProtocolException::STORAGE_NOT_FOUND};
    }
    return {};
}

bool
Dht::storageRefresh(const InfoHash& id, Value::Id vid)
{
    const auto& now = scheduler.time();
    auto s = store.find(id);
    if (s != store.end()) {
        // Values like for a permanent put can be refreshed. So, inform remote listeners that the value
        // need to be refreshed
        auto& st = s->second;
        if (not st.listeners.empty()) {
            if (logger_)
                logger_->d(id, "[store %s] %lu remote listeners", id.toString().c_str(), st.listeners.size());
            std::vector<Value::Id> ids = {vid};
            for (const auto& node_listeners : st.listeners) {
                for (const auto& l : node_listeners.second) {
                    if (logger_)
                        logger_->w(id, node_listeners.first->id, "[store %s] [node %s] sending refresh",
                            id.toString().c_str(),
                            node_listeners.first->toString().c_str());
                    Blob ntoken = makeToken(node_listeners.first->getAddr(), false);
                    network_engine.tellListenerRefreshed(node_listeners.first, l.first, id, ntoken, ids);
                }
            }
        }

        auto expiration = s->second.refresh(now, vid, types);
        if (expiration != time_point::max())
            scheduler.add(expiration, std::bind(&Dht::expireStorage, this, id));
        return true;
    }
    return false;
}

void
Dht::onAnnounceDone(const Sp<Node>& node, net::RequestAnswer& answer, Sp<Search>& sr)
{
    if (logger_)
        logger_->d(sr->id, node->id, "[search %s] [node %s] got reply to put!",
            sr->id.toString().c_str(), node->toString().c_str());
    searchSendGetValues(sr);
    sr->checkAnnounced(answer.vid);
}


void
Dht::saveState(const std::string& path) const
{
    std::ofstream file(path);
    msgpack::pack(file, exportNodes());
    msgpack::pack(file, exportValues());
}

void
Dht::loadState(const std::string& path)
{
    if (logger_)
        logger_->d("Importing state from %s", path.c_str());
    try {
        // Import nodes from binary file
        msgpack::unpacker pac;
        {
            // Read whole file
            std::ifstream file(path, std::ios::binary|std::ios::ate);
            if (!file.is_open()) {
                return;
            }
            auto size = file.tellg();
            file.seekg (0, std::ios::beg);
            pac.reserve_buffer(size);
            file.read (pac.buffer(), size);
            pac.buffer_consumed(size);
        }
        // Import nodes
        msgpack::object_handle oh;
        if (pac.next(oh)) {
            {
                auto imported_nodes = oh.get().as<std::vector<NodeExport>>();
                if (logger_)
                    logger_->d("Importing %zu nodes", imported_nodes.size());
                for (const auto& node : imported_nodes)
                    insertNode(node);
            }
            if (pac.next(oh)) {
                auto imported_values = oh.get().as<std::vector<ValuesExport>>();
                if (logger_)
                    logger_->d("Importing %zu values", imported_values.size());
                importValues(imported_values);
            }
        }
    } catch (const std::exception& e) {
        if (logger_)
            logger_->w("Error importing state from %s: %s", path.c_str(), e.what());
    }
}

}
