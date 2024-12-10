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

#include "network_engine.h"
#include "request.h"
#include "default_types.h"
#include "log_enable.h"
#include "parsed_message.h"

#include <msgpack.hpp>

namespace dht {
namespace net {
using namespace std::chrono_literals;

const std::string DhtProtocolException::GET_NO_INFOHASH {"Get_values with no info_hash"};
const std::string DhtProtocolException::LISTEN_NO_INFOHASH {"Listen with no info_hash"};
const std::string DhtProtocolException::LISTEN_WRONG_TOKEN {"Listen with wrong token"};
const std::string DhtProtocolException::PUT_NO_INFOHASH {"Put with no info_hash"};
const std::string DhtProtocolException::PUT_WRONG_TOKEN {"Put with wrong token"};
const std::string DhtProtocolException::PUT_INVALID_ID {"Put with invalid id"};
const std::string DhtProtocolException::STORAGE_NOT_FOUND {"Access operation for unknown storage"};

constexpr std::chrono::seconds NetworkEngine::UDP_REPLY_TIME;
constexpr std::chrono::seconds NetworkEngine::RX_MAX_PACKET_TIME;
constexpr std::chrono::seconds NetworkEngine::RX_TIMEOUT;

const std::string NetworkEngine::my_v {"RNG1"};

static constexpr uint8_t v4prefix[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0};

constexpr unsigned SEND_NODES {8};


struct NetworkEngine::PartialMessage {
    SockAddr from;
    time_point start;
    time_point last_part;
    std::unique_ptr<ParsedMessage> msg;
};

std::vector<Blob>
serializeValues(const std::vector<Sp<Value>>& st)
{
    std::vector<Blob> svals;
    svals.reserve(st.size());
    for (const auto& v : st)
        svals.emplace_back(packMsg(v));
    return svals;
}

void
packToken(msgpack::packer<msgpack::sbuffer>& pk, const Blob& token)
{
    pk.pack_bin(token.size());
    pk.pack_bin_body((char*)token.data(), token.size());
}

RequestAnswer::RequestAnswer(ParsedMessage&& msg)
 : ntoken(std::move(msg.token)),
   values(std::move(msg.values)),
   refreshed_values(std::move(msg.refreshed_values)),
   expired_values(std::move(msg.expired_values)),
   fields(std::move(msg.fields)),
   nodes4(std::move(msg.nodes4)),
   nodes6(std::move(msg.nodes6))
{}

NetworkEngine::NetworkEngine(const Sp<Logger>& log, std::mt19937_64& rand, Scheduler& scheduler, std::unique_ptr<DatagramSocket>&& sock)
    : myid(zeroes), dht_socket(std::move(sock)), logger_(log), rd(rand), cache(rd), rate_limiter((size_t)-1), scheduler(scheduler)
{}

NetworkEngine::NetworkEngine(InfoHash& myid, NetworkConfig c,
        std::unique_ptr<DatagramSocket>&& sock,
        const Sp<Logger>& log,
        std::mt19937_64& rand,
        Scheduler& scheduler,
        decltype(NetworkEngine::onError)&& onError,
        decltype(NetworkEngine::onNewNode)&& onNewNode,
        decltype(NetworkEngine::onReportedAddr)&& onReportedAddr,
        decltype(NetworkEngine::onPing)&& onPing,
        decltype(NetworkEngine::onFindNode)&& onFindNode,
        decltype(NetworkEngine::onGetValues)&& onGetValues,
        decltype(NetworkEngine::onListen)&& onListen,
        decltype(NetworkEngine::onAnnounce)&& onAnnounce,
        decltype(NetworkEngine::onRefresh)&& onRefresh) :
    onError(std::move(onError)),
    onNewNode(std::move(onNewNode)),
    onReportedAddr(std::move(onReportedAddr)),
    onPing(std::move(onPing)),
    onFindNode(std::move(onFindNode)),
    onGetValues(std::move(onGetValues)),
    onListen(std::move(onListen)),
    onAnnounce(std::move(onAnnounce)),
    onRefresh(std::move(onRefresh)),
    myid(myid), config(c), dht_socket(std::move(sock)), logger_(log), rd(rand),
    cache(rd),
    rate_limiter(config.max_req_per_sec),
    scheduler(scheduler)
{}

NetworkEngine::~NetworkEngine() {
    clear();
}

void
NetworkEngine::tellListener(Sp<Node> node, Tid socket_id, const InfoHash& hash, want_t want,
        const Blob& ntoken, std::vector<Sp<Node>>&& nodes,
        std::vector<Sp<Node>>&& nodes6, std::vector<Sp<Value>>&& values,
        const Query& query, int version)
{
    auto nnodes = bufferNodes(node->getFamily(), hash, want, nodes, nodes6);
    try {
        if (version >= 1) {
            sendUpdateValues(node, hash, values, scheduler.time(), ntoken, socket_id);
        } else {
            sendNodesValues(node->getAddr(), socket_id, nnodes.first, nnodes.second, values, query, ntoken);
        }
    } catch (const std::overflow_error& e) {
        if (logger_)
            logger_->e("Can't send value: buffer not large enough !");
    }
}

void
NetworkEngine::tellListenerRefreshed(Sp<Node> n, Tid socket_id, const InfoHash&, const Blob& token, const std::vector<Value::Id>& values, int version)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);

    pk.pack_map(4 + (version >= 1 ? 1 : 0) + (config.network?1:0));

    pk.pack(version >= 1 ? KEY_A : KEY_U);
        pk.pack_map(1 + (version >= 1 ? 1 : 0) + (not values.empty()?1:0) + (not token.empty()?1:0));
        pk.pack(KEY_REQ_ID); pk.pack(myid);
        if (version >= 1) {
            pk.pack(KEY_REQ_SID);   pk.pack(socket_id);
        }
        if (not token.empty()) {
            pk.pack(KEY_REQ_TOKEN); packToken(pk, token);
        }
        if (not values.empty()) {
            pk.pack(KEY_REQ_REFRESHED);
            pk.pack(values);
            if (logger_)
                logger_->d(n->id, "[node %s] sending %zu refreshed values", n->toString().c_str(), values.size());
        }

    pk.pack(KEY_Y); pk.pack(version >= 1 ? KEY_Q : KEY_R);
    pk.pack(KEY_UA); pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    if (version >= 1) {
        Tid tid (n->getNewTid());

        pk.pack(KEY_Q);   pk.pack(QUERY_UPDATE);
        pk.pack(KEY_TID); pk.pack(tid);

        auto req = std::make_shared<Request>(MessageType::UpdateValue, tid, n,
            Blob(buffer.data(), buffer.data() + buffer.size()),
            [=](const Request&, ParsedMessage&&) { /* on done */ },
            [=](const Request&, bool) { /* on expired */ }
        );
        sendRequest(req);
        ++out_stats.updateValue;
        return;
    }
    pk.pack(KEY_TID); pk.pack(socket_id);

    // send response
    send(n->getAddr(), buffer.data(), buffer.size());
}

void
NetworkEngine::tellListenerExpired(Sp<Node> n, Tid socket_id, const InfoHash&, const Blob& token, const std::vector<Value::Id>& values, int version)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);

    pk.pack_map(4 + (version >= 1 ? 1 : 0) + (config.network?1:0));

    pk.pack(version >= 1 ? KEY_A : KEY_U);
        pk.pack_map(1 + (version >= 1 ? 1 : 0) + (not values.empty()?1:0) + (not token.empty()?1:0));
        pk.pack(KEY_REQ_ID); pk.pack(myid);
        if (version >= 1) {
            pk.pack(KEY_REQ_SID);   pk.pack(socket_id);
        }
        if (not token.empty()) {
            pk.pack(KEY_REQ_TOKEN); packToken(pk, token);
        }
        if (not values.empty()) {
            pk.pack(KEY_REQ_EXPIRED);
            pk.pack(values);
            if (logger_)
                logger_->d(n->id, "[node %s] sending %zu expired values", n->toString().c_str(), values.size());
        }

    pk.pack(KEY_Y); pk.pack(version >= 1 ? KEY_Q : KEY_R);
    pk.pack(KEY_UA); pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    if (version >= 1) {
        Tid tid (n->getNewTid());

        pk.pack(KEY_Q);   pk.pack(QUERY_UPDATE);
        pk.pack(KEY_TID);     pk.pack(tid);

        auto req = std::make_shared<Request>(MessageType::UpdateValue, tid, n,
            Blob(buffer.data(), buffer.data() + buffer.size()),
            [=](const Request&, ParsedMessage&&) { /* on done */ },
            [=](const Request&, bool) { /* on expired */ }
        );
        sendRequest(req);
        ++out_stats.updateValue;
        return;
    }
    pk.pack(KEY_TID); pk.pack(socket_id);

    // send response
    send(n->getAddr(), buffer.data(), buffer.size());
}


bool
NetworkEngine::isRunning(sa_family_t af) const
{
    switch (af) {
    case 0:
        return dht_socket->hasIPv4() or dht_socket->hasIPv6();
    case AF_INET:
        return dht_socket->hasIPv4();
    case AF_INET6:
        return dht_socket->hasIPv6();
    default:
        return false;
    }
}

void
NetworkEngine::clear()
{
    for (auto& request : requests) {
        request.second->cancel();
        request.second->node->setExpired();
    }
    requests.clear();
}

void
NetworkEngine::connectivityChanged(sa_family_t af)
{
    cache.clearBadNodes(af);
}

void
NetworkEngine::requestStep(Sp<Request> sreq)
{
    auto& req = *sreq;
    if (not req.pending())
        return;

    auto now = scheduler.time();
    auto& node = *req.node;
    if (req.isExpired(now)) {
        // if (logger_)
        //     logger_->d(node.id, "[node %s] expired !", node.toString().c_str());
        node.setExpired();
        if (not node.id)
            requests.erase(req.tid);
        return;
    } else if (req.attempt_count == 1) {
        req.on_expired(req, false);
    }

    auto err = send(node.getAddr(), (char*)req.msg.data(), req.msg.size(), node.getReplyTime() < now - UDP_REPLY_TIME);
    if (err == ENETUNREACH  ||
        err == EHOSTUNREACH ||
        err == EAFNOSUPPORT ||
        err == EPIPE        ||
        err == EPERM)
    {
        node.setExpired();
        if (not node.id)
            requests.erase(req.tid);
    } else {
        req.last_try = now;
        if (err != EAGAIN) {
            ++req.attempt_count;
            req.attempt_duration +=
                req.attempt_duration + uniform_duration_distribution<>(0ms, ((duration)Node::MAX_RESPONSE_TIME)/4)(rd);
            if (not req.parts.empty()){
                sendValueParts(req.tid, req.parts, node.getAddr());
            }
        }
        std::weak_ptr<Request> wreq = sreq;
        scheduler.add(req.last_try + req.attempt_duration, [this,wreq] {
            if (auto req = wreq.lock())
                requestStep(req);
        });
    }
}

/**
 * Sends a request to a node. Request::MAX_ATTEMPT_COUNT attempts will
 * be made before the request expires.
 */
void
NetworkEngine::sendRequest(const Sp<Request>& request)
{
    auto& node = *request->node;
    if (not node.id)
        requests.emplace(request->tid, request);
    request->start = scheduler.time();
    node.requested(request);
    requestStep(request);
}


/* Rate control for requests we receive. */
bool
NetworkEngine::rateLimit(const SockAddr& addr)
{
    const auto& now = scheduler.time();

    // occasional IP limiter maintenance (a few times every second at max rate)
    if (limiter_maintenance++ == config.max_peer_req_per_sec) {
        for (auto it = address_rate_limiter.begin(); it != address_rate_limiter.end();) {
            if (it->second.maintain(now) == 0)
                address_rate_limiter.erase(it++);
            else
                ++it;
        }
        limiter_maintenance = 0;
    }

    // invoke per IP, then global rate limiter
    return (config.max_peer_req_per_sec < 0
            or address_rate_limiter
                .emplace(addr, config.max_peer_req_per_sec).first->second
                .limit(now))
            and rate_limiter.limit(now);
}

bool
NetworkEngine::isMartian(const SockAddr& addr)
{
    if (addr.getPort() == 0)
        return true;
    switch(addr.getFamily()) {
    case AF_INET: {
        const auto& sin = addr.getIPv4();
        const uint8_t* address = (const uint8_t*)&sin.sin_addr;
        return (address[0] == 0) ||
              ((address[0] & 0xE0) == 0xE0);
    }
    case AF_INET6: {
        if (addr.getLength() < sizeof(sockaddr_in6))
            return true;
        const auto& sin6 = addr.getIPv6();
        const uint8_t* address = (const uint8_t*)&sin6.sin6_addr;
        return address[0] == 0xFF ||
              (address[0] == 0xFE && (address[1] & 0xC0) == 0x80) ||
               memcmp(address, zeroes.data(), 16) == 0 ||
               memcmp(address, v4prefix,      12) == 0;
    }
    default:
        return true;
    }
}

/* The internal blacklist is an LRU cache of nodes that have sent
   incorrect messages. */
void
NetworkEngine::blacklistNode(const Sp<Node>& n)
{
    n->setExpired();
    blacklist.emplace(n->getAddr());
}

bool
NetworkEngine::isNodeBlacklisted(const SockAddr& addr) const
{
    return blacklist.find(addr) != blacklist.end();
}

void
NetworkEngine::processMessage(const uint8_t *buf, size_t buflen, SockAddr f)
{
    auto from = f.getMappedIPv4();
    if (isMartian(from)) {
        if (logger_)
            logger_->w("Received packet from martian node %s", from.toString().c_str());
        return;
    }

    if (isNodeBlacklisted(from)) {
        if (logger_)
            logger_->w("Received packet from blacklisted node %s", from.toString().c_str());
        return;
    }

    std::unique_ptr<ParsedMessage> msg {new ParsedMessage};
    try {
        msgpack::unpacked msg_res = msgpack::unpack((const char*)buf, buflen);
        msg->msgpack_unpack(msg_res.get());
    } catch (const std::exception& e) {
        if (logger_)
            logger_->w("Can't parse message of size %lu: %s", buflen, e.what());
        // if (logger_)
        //     logger_->DBG.logPrintable(buf, buflen);
        return;
    }

    if (msg->network != config.network) {
        if (logger_)
            logger_->d("Received message from other config.network %u", msg->network);
        return;
    }

    const auto& now = scheduler.time();

    // partial value data
    if (msg->type == MessageType::ValueData) {
        auto pmsg_it = partial_messages.find(msg->tid);
        if (pmsg_it == partial_messages.end()) {
            if (logIncoming_)
                if (logger_)
                    logger_->d("Can't find partial message");
            rateLimit(from);
            return;
        }
        if (!pmsg_it->second.from.equals(from)) {
            if (logger_)
                logger_->d("Received partial message data from unexpected IP address");
            rateLimit(from);
            return;
        }
        // append data block
        if (pmsg_it->second.msg->append(*msg)) {
            pmsg_it->second.last_part = now;
            // check data completion
            if (pmsg_it->second.msg->complete()) {
                // process the full message
                process(std::move(pmsg_it->second.msg), from);
                partial_messages.erase(pmsg_it);
            } else
                scheduler.add(now + RX_TIMEOUT, std::bind(&NetworkEngine::maintainRxBuffer, this, msg->tid));
        }
        return;
    }

    if (msg->id == myid or not msg->id) {
        if (logger_)
            logger_->d("Received message from self");
        return;
    }

    if (msg->type > MessageType::Reply) {
        /* Rate limit requests. */
        if (!rateLimit(from)) {
            if (logger_)
                logger_->w("Dropping request due to rate limiting");
            return;
        }
    }

    if (msg->value_parts.empty()) {
        process(std::move(msg), from);
    } else {
        // starting partial message session
        auto k = msg->tid;
        auto& pmsg = partial_messages[k];
        if (not pmsg.msg) {
            pmsg.from = from;
            pmsg.msg = std::move(msg);
            pmsg.start = now;
            pmsg.last_part = now;
            scheduler.add(now + RX_MAX_PACKET_TIME, std::bind(&NetworkEngine::maintainRxBuffer, this, k));
            scheduler.add(now + RX_TIMEOUT, std::bind(&NetworkEngine::maintainRxBuffer, this, k));
        } else
            if (logger_)
                logger_->e("Partial message with given TID already exists");
    }
}

void
NetworkEngine::process(std::unique_ptr<ParsedMessage>&& msg, const SockAddr& from)
{
    const auto& now = scheduler.time();
    auto node = cache.getNode(msg->id, from, now, true, msg->is_client);

    if (msg->type == MessageType::ValueUpdate) {
        auto rsocket = node->getSocket(msg->tid);
        if (not rsocket)
            throw DhtProtocolException {DhtProtocolException::UNKNOWN_TID, "Can't find socket", msg->id};
        node->received(now, {});
        onNewNode(node, 2);
        deserializeNodes(*msg, from);
        rsocket->on_receive(node, std::move(*msg));
    }
    else if (msg->type == MessageType::Error or msg->type == MessageType::Reply) {
        auto rsocket = node->getSocket(msg->tid);
        auto req = node->getRequest(msg->tid);

        /* either response for a request or data for an opened socket */
        if (not req and not rsocket) {
            auto req_it = requests.find(msg->tid);
            if (req_it != requests.end() and not req_it->second->node->id) {
                req = req_it->second;
                req->node = node;
                requests.erase(req_it);
            } else {
                node->received(now, req);
                if (not node->isClient())
                    onNewNode(node, 1);
                if (logger_)
                    logger_->d(node->id, "[node %s] can't find transaction with id %u", node->toString().c_str(), msg->tid);
                return;
            }
        }

        node->received(now, req);

        if (not node->isClient())
            onNewNode(node, 2);
        onReportedAddr(msg->id, msg->addr);

        if (req and (req->cancelled() or req->expired() or req->completed())) {
            if (logger_)
                logger_->w(node->id, "[node %s] response to expired, cancelled or completed request", node->toString().c_str());
            return;
        }

        switch (msg->type) {
        case MessageType::Error: {
            if (msg->id and req and (
                (msg->error_code == DhtProtocolException::NOT_FOUND    and req->getType() == MessageType::Refresh) or
                (msg->error_code == DhtProtocolException::UNAUTHORIZED and (req->getType() == MessageType::AnnounceValue
                                                                         or req->getType() == MessageType::Listen))))
            {
                req->last_try = time_point::min();
                req->reply_time = time_point::min();
                if (not req->setError(DhtProtocolException {msg->error_code}))
                    onError(req, DhtProtocolException {msg->error_code});
            } else {
                if (logIncoming_)
                    if (logger_)
                        logger_->w(msg->id, "[node %s %s] received unknown error message %u",
                        msg->id.toString().c_str(), from.toString().c_str(), msg->error_code);
            }
            break;
        }
        case MessageType::Reply:
            if (req) { /* request reply */
                auto& r = *req;
                if (r.getType() == MessageType::AnnounceValue
                 or r.getType() == MessageType::Listen
                 or r.getType() == MessageType::Refresh) {
                    r.node->authSuccess();
                }
                r.reply_time = scheduler.time();

                deserializeNodes(*msg, from);
                r.setDone(std::move(*msg));
                break;
            } else { /* request socket data */
                deserializeNodes(*msg, from);
                rsocket->on_receive(node, std::move(*msg));
            }
            break;
        default:
            break;
        }
    } else {
        node->received(now, {});
        if (not node->isClient())
            onNewNode(node, 1);
        try {
            switch (msg->type) {
            case MessageType::Ping:
                ++in_stats.ping;
                if (logIncoming_)
                    if (logger_)
                        logger_->d(node->id, "[node %s] sending pong", node->toString().c_str());
                onPing(node);
                sendPong(from, msg->tid);
                break;
            case MessageType::FindNode: {
                // if (logger_)
                //     logger_->d(msg->target, node->id, "[node %s] got 'find' request for %s (%d)", node->toString().c_str(), msg->target.toString().c_str(), msg->want);
                ++in_stats.find;
                RequestAnswer answer = onFindNode(node, msg->target, msg->want);
                auto nnodes = bufferNodes(from.getFamily(), msg->target, msg->want, answer.nodes4, answer.nodes6);
                sendNodesValues(from, msg->tid, nnodes.first, nnodes.second, {}, {}, answer.ntoken);
                break;
            }
            case MessageType::GetValues: {
                // if (logger_)
                //     logger_->d(msg->info_hash, node->id, "[node %s] got 'get' request for %s", node->toString().c_str(), msg->info_hash.toString().c_str());
                ++in_stats.get;
                RequestAnswer answer = onGetValues(node, msg->info_hash, msg->want, msg->query);
                auto nnodes = bufferNodes(from.getFamily(), msg->info_hash, msg->want, answer.nodes4, answer.nodes6);
                sendNodesValues(from, msg->tid, nnodes.first, nnodes.second, answer.values, msg->query, answer.ntoken);
                break;
            }
            case MessageType::AnnounceValue: {
                if (logIncoming_ and logger_)
                    logger_->d(msg->info_hash, node->id, "[node %s] got 'put' request for %s", node->toString().c_str(), msg->info_hash.toString().c_str());
                ++in_stats.put;
                onAnnounce(node, msg->info_hash, msg->token, msg->values, msg->created);

                /* Note that if storageStore failed, we lie to the requestor.
                   This is to prevent them from backtracking, and hence
                   polluting the DHT. */
                for (auto& v : msg->values) {
                   sendValueAnnounced(from, msg->tid, v->id);
                }
                break;
            }
            case MessageType::Refresh:
                if (logIncoming_ and logger_)
                    logger_->d(msg->info_hash, node->id, "[node %s] got 'refresh' request for %s", node->toString().c_str(), msg->info_hash.toString().c_str());
                onRefresh(node, msg->info_hash, msg->token, msg->value_id);
                /* Same note as above in MessageType::AnnounceValue applies. */
                sendValueAnnounced(from, msg->tid, msg->value_id);
                break;
            case MessageType::Listen: {
                if (logIncoming_ and logger_)
                    logger_->d(msg->info_hash, node->id, "[node %s] got 'listen' request for %s", node->toString().c_str(), msg->info_hash.toString().c_str());
                ++in_stats.listen;
                RequestAnswer answer = onListen(node, msg->info_hash, msg->token, msg->socket_id, std::move(msg->query), msg->version);
                auto nnodes = bufferNodes(from.getFamily(), msg->info_hash, msg->want, answer.nodes4, answer.nodes6);
                sendListenConfirmation(from, msg->tid);
                break;
            }
            case MessageType::UpdateValue: {
                if (logIncoming_ and logger_)
                    logger_->d(msg->info_hash, node->id, "[node %s] got 'update' request for %s", node->toString().c_str(), msg->info_hash.toString().c_str());
                ++in_stats.updateValue;
                if (auto rsocket = node->getSocket(msg->socket_id))
                    rsocket->on_receive(node, std::move(*msg));
                else if (logger_)
                    logger_->e(msg->info_hash, node->id, "[node %s] 'update' request without socket for %s", node->toString().c_str(), msg->info_hash.toString().c_str());
                sendListenConfirmation(from, msg->tid);
                break;
            }
            default:
                break;
            }
        } catch (const std::overflow_error& e) {
            if (logger_)
                logger_->e("Can't send value: buffer not large enough !");
        } catch (const DhtProtocolException& e) {
            sendError(from, msg->tid, e.getCode(), e.getMsg().c_str(), true);
        }
    }
}

void
insertAddr(msgpack::packer<msgpack::sbuffer>& pk, const SockAddr& addr)
{
    size_t addr_len = std::min<size_t>(addr.getLength(),
                     (addr.getFamily() == AF_INET) ? sizeof(in_addr) : sizeof(in6_addr));
    void* addr_ptr = (addr.getFamily() == AF_INET) ? (void*)&addr.getIPv4().sin_addr
                                                : (void*)&addr.getIPv6().sin6_addr;
    pk.pack("sa");
    pk.pack_bin(addr_len);
    pk.pack_bin_body((char*)addr_ptr, addr_len);
}

int
NetworkEngine::send(const SockAddr& addr, const char *buf, size_t len, bool confirmed)
{
    return dht_socket ? dht_socket->sendTo(addr, (const uint8_t*)buf, len, confirmed) : ENOTCONN;
}

Sp<Request>
NetworkEngine::sendPing(Sp<Node> node, RequestCb&& on_done, RequestExpiredCb&& on_expired) {
    Tid tid (node->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(config.network?1:0));

    pk.pack(KEY_A); pk.pack_map(1);
     pk.pack(KEY_REQ_ID); pk.pack(myid);

    pk.pack(KEY_Q); pk.pack(QUERY_PING);
    pk.pack(KEY_TID); pk.pack(tid);
    pk.pack(KEY_Y); pk.pack(KEY_Q);
    pk.pack(KEY_UA); pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    auto req = std::make_shared<Request>(MessageType::Ping, tid, node,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&&) {
            if (logger_)
                logger_->d(req_status.node->id, "[node %s] got pong !", req_status.node->toString().c_str());
            if (on_done) {
                on_done(req_status, {});
            }
        },
        [=](const Request& req_status, bool done) { /* on expired */
            if (on_expired) {
                on_expired(req_status, done);
            }
        }
    );
    sendRequest(req);
    ++out_stats.ping;
    return req;
}

void
NetworkEngine::sendPong(const SockAddr& addr, Tid tid) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(config.network?1:0));

    pk.pack(KEY_R); pk.pack_map(2);
      pk.pack(KEY_REQ_ID); pk.pack(myid);
      insertAddr(pk, addr);

    pk.pack(KEY_TID); pk.pack(tid);
    pk.pack(KEY_Y); pk.pack(KEY_R);
    pk.pack(KEY_UA); pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    send(addr, buffer.data(), buffer.size());
}

Sp<Request>
NetworkEngine::sendFindNode(Sp<Node> n, const InfoHash& target, want_t want,
        RequestCb&& on_done, RequestExpiredCb&& on_expired) {
    Tid tid (n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(config.network?1:0));

    pk.pack(KEY_A); pk.pack_map(2 + (want>0?1:0));
      pk.pack(KEY_REQ_ID);     pk.pack(myid);
      pk.pack(KEY_REQ_TARGET); pk.pack(target);
    if (want > 0) {
      pk.pack(KEY_REQ_WANT);
      pk.pack_array(((want & WANT4)?1:0) + ((want & WANT6)?1:0));
      if (want & WANT4) pk.pack(AF_INET);
      if (want & WANT6) pk.pack(AF_INET6);
    }

    pk.pack(KEY_Q); pk.pack(QUERY_FIND);
    pk.pack(KEY_TID); pk.pack(tid);
    pk.pack(KEY_Y); pk.pack(KEY_Q);
    pk.pack(KEY_UA); pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    auto req = std::make_shared<Request>(MessageType::FindNode, tid, n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
            if (on_done) {
                on_done(req_status, {std::forward<ParsedMessage>(msg)});
            }
        },
        [=](const Request& req_status, bool done) { /* on expired */
            if (on_expired) {
                on_expired(req_status, done);
            }
        }
    );
    sendRequest(req);
    ++out_stats.find;
    return req;
}


Sp<Request>
NetworkEngine::sendGetValues(Sp<Node> n, const InfoHash& info_hash, const Query& query, want_t want,
        RequestCb&& on_done, RequestExpiredCb&& on_expired) {
    Tid tid (n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(config.network?1:0));

    unsigned sendQuery = (not query.where.empty() or not query.select.empty()) ? 1 : 0;
    unsigned sendWant = (want > 0) ? 1 : 0;

    pk.pack(KEY_A);  pk.pack_map(2 + sendQuery + sendWant);
      pk.pack(KEY_REQ_ID); pk.pack(myid);
      pk.pack(KEY_REQ_H);  pk.pack(info_hash);
      if (sendQuery) {
        pk.pack(KEY_Q); pk.pack(query);
      }
      if (sendWant) {
        pk.pack(KEY_REQ_WANT);
        unsigned sendWant4 = (want & WANT4) ? 1 : 0;
        unsigned sendWant6 = (want & WANT6) ? 1 : 0;
        pk.pack_array(sendWant4 + sendWant6);
        if (sendWant4) pk.pack(AF_INET);
        if (sendWant6) pk.pack(AF_INET6);
      }

    pk.pack(KEY_Q); pk.pack(QUERY_GET);
    pk.pack(KEY_TID); pk.pack(tid);
    pk.pack(KEY_Y); pk.pack(KEY_Q);
    pk.pack(KEY_UA); pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    auto req = std::make_shared<Request>(MessageType::GetValues, tid, n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
            if (on_done) {
                on_done(req_status, {std::forward<ParsedMessage>(msg)});
            }
        },
        [=](const Request& req_status, bool done) { /* on expired */
            if (on_expired) {
                on_expired(req_status, done);
            }
        }
    );
    sendRequest(req);
    ++out_stats.get;
    return req;
}

SockAddr deserializeIPv4(const uint8_t* ni) {
    SockAddr addr;
    addr.setFamily(AF_INET);
    auto& sin = addr.getIPv4();
    std::memcpy(&sin.sin_addr, ni, 4);
    std::memcpy(&sin.sin_port, ni + 4, 2);
    return addr;
}
SockAddr deserializeIPv6(const uint8_t* ni) {
    SockAddr addr;
    addr.setFamily(AF_INET6);
    auto& sin6 = addr.getIPv6();
    std::memcpy(&sin6.sin6_addr, ni, 16);
    std::memcpy(&sin6.sin6_port, ni + 16, 2);
    return addr;
}

void
NetworkEngine::deserializeNodes(ParsedMessage& msg, const SockAddr& from) {
    if (msg.nodes4_raw.size() % NODE4_INFO_BUF_LEN != 0 || msg.nodes6_raw.size() % NODE6_INFO_BUF_LEN != 0) {
        throw DhtProtocolException {DhtProtocolException::WRONG_NODE_INFO_BUF_LEN};
    }
    // deserialize nodes
    const auto& now = scheduler.time();
    for (unsigned i = 0, n = msg.nodes4_raw.size() / NODE4_INFO_BUF_LEN; i < n; i++) {
        const uint8_t* ni = msg.nodes4_raw.data() + i * NODE4_INFO_BUF_LEN;
        const auto& ni_id = *reinterpret_cast<const InfoHash*>(ni);
        if (ni_id == myid)
            continue;
        SockAddr addr = deserializeIPv4(ni + ni_id.size());
        if (addr.isLoopback() and from.getFamily() == AF_INET) {
            auto port = addr.getPort();
            addr = from;
            addr.setPort(port);
        }
        if (isMartian(addr) || isNodeBlacklisted(addr))
            continue;
        msg.nodes4.emplace_back(cache.getNode(ni_id, addr, now, false));
        onNewNode(msg.nodes4.back(), 0);
    }
    for (unsigned i = 0, n = msg.nodes6_raw.size() / NODE6_INFO_BUF_LEN; i < n; i++) {
        const uint8_t* ni = msg.nodes6_raw.data() + i * NODE6_INFO_BUF_LEN;
        const auto& ni_id = *reinterpret_cast<const InfoHash*>(ni);
        if (ni_id == myid)
            continue;
        SockAddr addr = deserializeIPv6(ni + ni_id.size());
        if (addr.isLoopback() and from.getFamily() == AF_INET6) {
            auto port = addr.getPort();
            addr = from;
            addr.setPort(port);
        }
        if (isMartian(addr) || isNodeBlacklisted(addr))
            continue;
        msg.nodes6.emplace_back(cache.getNode(ni_id, addr, now, false));
        onNewNode(msg.nodes6.back(), 0);
    }
}

std::vector<Blob>
NetworkEngine::packValueHeader(msgpack::sbuffer& buffer, const std::vector<Sp<Value>>& st)
{
    auto svals = serializeValues(st);
    size_t total_size = 0;
    for (const auto& v : svals)
        total_size += v.size();

    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack(KEY_REQ_VALUES);
    pk.pack_array(svals.size());
    // try to put everything in a single UDP packet
    if (svals.size() < 50 && total_size < MAX_PACKET_VALUE_SIZE) {
        for (const auto& b : svals)
            buffer.write((const char*)b.data(), b.size());
        // if (logger_)
        //     logger_->d("sending %lu bytes of values", total_size);
        svals.clear();
    } else {
        for (const auto& b : svals)
            pk.pack(b.size());
    }
    return svals;
}

void
NetworkEngine::sendValueParts(Tid tid, const std::vector<Blob>& svals, const SockAddr& addr)
{
    msgpack::sbuffer buffer;
    unsigned i=0;
    for (const auto& v: svals) {
        size_t start {0}, end;
        do {
            end = std::min(start + MTU, v.size());
            buffer.clear();
            msgpack::packer<msgpack::sbuffer> pk(&buffer);
            pk.pack_map(3+(config.network?1:0));
            if (config.network) {
                pk.pack(KEY_NETID); pk.pack(config.network);
            }
            pk.pack(KEY_Y); pk.pack(KEY_V);
            pk.pack(KEY_TID); pk.pack(tid);
            pk.pack(KEY_V); pk.pack_map(1);
                pk.pack(i); pk.pack_map(2);
                    pk.pack(std::string("o")); pk.pack(start);
                    pk.pack(std::string("d")); pk.pack_bin(end-start);
                                               pk.pack_bin_body((const char*)v.data()+start, end-start);
            send(addr, buffer.data(), buffer.size());
            start = end;
        } while (start != v.size());
        i++;
    }
}

void
NetworkEngine::sendNodesValues(const SockAddr& addr, Tid tid, const Blob& nodes, const Blob& nodes6,
        const std::vector<Sp<Value>>& st, const Query& query, const Blob& token)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(config.network?1:0));

    pk.pack(KEY_R);
    pk.pack_map(2 + (not st.empty()?1:0) + (nodes.size()>0?1:0) + (nodes6.size()>0?1:0) + (not token.empty()?1:0));
    pk.pack(KEY_REQ_ID); pk.pack(myid);
    insertAddr(pk, addr);
    if (nodes.size() > 0) {
        pk.pack(KEY_REQ_NODES4);
        pk.pack_bin(nodes.size());
        pk.pack_bin_body((const char*)nodes.data(), nodes.size());
    }
    if (nodes6.size() > 0) {
        pk.pack(KEY_REQ_NODES6);
        pk.pack_bin(nodes6.size());
        pk.pack_bin_body((const char*)nodes6.data(), nodes6.size());
    }
    if (not token.empty()) {
        pk.pack(KEY_REQ_TOKEN); packToken(pk, token);
    }
    std::vector<Blob> svals {};
    if (not st.empty()) { /* pack complete values */
        if (query.select.empty()) {
            svals = packValueHeader(buffer, st);
        } else { /* pack fields */
            auto fields = query.select.getSelection();
            pk.pack(KEY_REQ_FIELDS);
            pk.pack_map(2);
            pk.pack(std::string("f")); pk.pack(fields);
            pk.pack(std::string("v")); pk.pack_array(st.size()*fields.size());
            for (const auto& v : st)
                v->msgpack_pack_fields(fields, pk);
            //DHT_LOG_DBG("sending closest nodes (%d+%d nodes.), %u value headers containing %u fields",
            //        nodes.size(), nodes6.size(), st.size(), fields.size());
        }
    }

    pk.pack(KEY_TID); pk.pack(tid);
    pk.pack(KEY_Y); pk.pack(KEY_R);
    pk.pack(KEY_UA); pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    // send response
    send(addr, buffer.data(), buffer.size());

    // send parts
    if (not svals.empty())
        sendValueParts(tid, svals, addr);
}

Blob
NetworkEngine::bufferNodes(sa_family_t af, const InfoHash& id, std::vector<Sp<Node>>& nodes)
{
    std::sort(nodes.begin(), nodes.end(), [&](const Sp<Node>& a, const Sp<Node>& b){
        return id.xorCmp(a->id, b->id) < 0;
    });
    size_t nnode = std::min<size_t>(SEND_NODES, nodes.size());
    Blob bnodes;
    if (af == AF_INET) {
        bnodes.resize(NODE4_INFO_BUF_LEN * nnode);
        for (size_t i=0; i<nnode; i++) {
            const Node& n = *nodes[i];
            const auto& sin = n.getAddr().getIPv4();
            auto dest = bnodes.data() + NODE4_INFO_BUF_LEN * i;
            memcpy(dest, n.id.data(), HASH_LEN);
            memcpy(dest + HASH_LEN, &sin.sin_addr, sizeof(in_addr));
            memcpy(dest + HASH_LEN + sizeof(in_addr), &sin.sin_port, sizeof(in_port_t));
        }
    } else if (af == AF_INET6) {
        bnodes.resize(NODE6_INFO_BUF_LEN * nnode);
        for (size_t i=0; i<nnode; i++) {
            const Node& n = *nodes[i];
            const auto& sin6 = n.getAddr().getIPv6();
            auto dest = bnodes.data() + NODE6_INFO_BUF_LEN * i;
            memcpy(dest, n.id.data(), HASH_LEN);
            memcpy(dest + HASH_LEN, &sin6.sin6_addr, sizeof(in6_addr));
            memcpy(dest + HASH_LEN + sizeof(in6_addr), &sin6.sin6_port, sizeof(in_port_t));
        }
    }
    return bnodes;
}

std::pair<Blob, Blob>
NetworkEngine::bufferNodes(sa_family_t af, const InfoHash& id, want_t want,
        std::vector<Sp<Node>>& nodes4, std::vector<Sp<Node>>& nodes6)
{
    if (want < 0)
        want = af == AF_INET ? WANT4 : WANT6;

    Blob bnodes4;
    if (want & WANT4)
        bnodes4 = bufferNodes(AF_INET, id, nodes4);

    Blob bnodes6;
    if (want & WANT6)
        bnodes6 = bufferNodes(AF_INET6, id, nodes6);

    return {std::move(bnodes4), std::move(bnodes6)};
}

Sp<Request>
NetworkEngine::sendListen(Sp<Node> n,
        const InfoHash& hash,
        const Query& query,
        const Blob& token,
        Tid socketId,
        RequestCb&& on_done,
        RequestExpiredCb&& on_expired)
{
    Tid tid (n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(config.network?1:0));

    auto has_query = not query.where.empty() or not query.select.empty();
    pk.pack(KEY_A); pk.pack_map(5 + has_query);
      pk.pack(KEY_REQ_ID);    pk.pack(myid);
      pk.pack(KEY_VERSION);   pk.pack(1);
      pk.pack(KEY_REQ_H);     pk.pack(hash);
      pk.pack(KEY_REQ_TOKEN); packToken(pk, token);
      pk.pack(KEY_REQ_SID);   pk.pack(socketId);
      if (has_query) {
          pk.pack(KEY_REQ_QUERY); pk.pack(query);
      }

    pk.pack(KEY_Q); pk.pack(QUERY_LISTEN);
    pk.pack(KEY_TID); pk.pack(tid);
    pk.pack(KEY_Y); pk.pack(KEY_Q);
    pk.pack(KEY_UA); pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    auto req = std::make_shared<Request>(MessageType::Listen, tid, n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
            if (on_done)
                on_done(req_status, {std::forward<ParsedMessage>(msg)});
        },
        [=](const Request& req_status, bool done) { /* on expired */
            if (on_expired)
                on_expired(req_status, done);
        }
    );
    sendRequest(req);
    ++out_stats.listen;
    return req;
}

void
NetworkEngine::sendListenConfirmation(const SockAddr& addr, Tid tid) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(config.network?1:0));

    pk.pack(KEY_R); pk.pack_map(2);
      pk.pack(KEY_REQ_ID); pk.pack(myid);
      insertAddr(pk, addr);

    pk.pack(KEY_TID); pk.pack(tid);
    pk.pack(KEY_Y); pk.pack(KEY_R);
    pk.pack(KEY_UA); pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    send(addr, buffer.data(), buffer.size());
}

Sp<Request>
NetworkEngine::sendAnnounceValue(Sp<Node> n,
        const InfoHash& infohash,
        const Sp<Value>& value,
        time_point created,
        const Blob& token,
        RequestCb&& on_done,
        RequestExpiredCb&& on_expired)
{
    Tid tid (n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(config.network?1:0));

    pk.pack(KEY_A); pk.pack_map((created < scheduler.time() ? 5 : 4));
      pk.pack(KEY_REQ_ID);     pk.pack(myid);
      pk.pack(KEY_REQ_H);      pk.pack(infohash);
      auto v = packValueHeader(buffer, {value});
      if (created < scheduler.time()) {
          pk.pack(KEY_REQ_CREATION);
          pk.pack(to_time_t(created));
      }
      pk.pack(KEY_REQ_TOKEN);  pk.pack(token);

    pk.pack(KEY_Q);   pk.pack(QUERY_PUT);
    pk.pack(KEY_TID); pk.pack(tid);
    pk.pack(KEY_Y);   pk.pack(KEY_Q);
    pk.pack(KEY_UA);  pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    auto req = std::make_shared<Request>(MessageType::AnnounceValue, tid, n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
            if (msg.value_id == Value::INVALID_ID) {
                if (logger_)
                    logger_->d(infohash, "Unknown search or announce!");
            } else {
                if (on_done) {
                    RequestAnswer answer {};
                    answer.vid = msg.value_id;
                    on_done(req_status, std::move(answer));
                }
            }
        },
        [=](const Request& req_status, bool done) { /* on expired */
            if (on_expired) {
                on_expired(req_status, done);
            }
        }
    );
    req->parts = std::move(v);
    sendRequest(req);
    ++out_stats.put;
    return req;
}

Sp<Request>
NetworkEngine::sendUpdateValues(Sp<Node> n,
                                const InfoHash& infohash,
                                const std::vector<Sp<Value>>& values,
                                time_point created,
                                const Blob& token,
                                const size_t& socket_id)
{
    Tid tid (n->getNewTid());
    Tid sid (socket_id);

    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(config.network?1:0));

    pk.pack(KEY_A); pk.pack_map((created < scheduler.time() ? 7 : 6));
      pk.pack(KEY_REQ_ID);     pk.pack(myid);
      pk.pack(KEY_VERSION);    pk.pack(1);
      pk.pack(KEY_REQ_H);      pk.pack(infohash);
      pk.pack(KEY_REQ_SID);   pk.pack(sid);
      auto v = packValueHeader(buffer, values);
      if (created < scheduler.time()) {
          pk.pack(KEY_REQ_CREATION);
          pk.pack(to_time_t(created));
      }
      pk.pack(KEY_REQ_TOKEN);  pk.pack(token);

    pk.pack(KEY_Q);   pk.pack(QUERY_UPDATE);
    pk.pack(KEY_TID); pk.pack(tid);
    pk.pack(KEY_Y);   pk.pack(KEY_Q);
    pk.pack(KEY_UA);  pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    auto req = std::make_shared<Request>(MessageType::UpdateValue, tid, n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request&, ParsedMessage&&) { /* on done */ },
        [=](const Request&, bool) { /* on expired */ }
    );
    req->parts = std::move(v);
    sendRequest(req);
    ++out_stats.updateValue;
    return req;
}

Sp<Request>
NetworkEngine::sendRefreshValue(Sp<Node> n,
                const InfoHash& infohash,
                const Value::Id& vid,
                const Blob& token,
                RequestCb&& on_done,
                RequestErrorCb&& on_error,
                RequestExpiredCb&& on_expired)
{
    Tid tid (n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(config.network?1:0));

    pk.pack(KEY_A); pk.pack_map(4);
      pk.pack(KEY_REQ_ID);       pk.pack(myid);
      pk.pack(KEY_REQ_H);        pk.pack(infohash);
      pk.pack(KEY_REQ_VALUE_ID); pk.pack(vid);
      pk.pack(KEY_REQ_TOKEN);    pk.pack(token);

    pk.pack(KEY_Q); pk.pack(QUERY_REFRESH);
    pk.pack(KEY_TID); pk.pack(tid);
    pk.pack(KEY_Y); pk.pack(KEY_Q);
    pk.pack(KEY_UA); pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    auto req = std::make_shared<Request>(MessageType::Refresh, tid, n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
            if (msg.value_id == Value::INVALID_ID) {
                if (logger_)
                    logger_->d(infohash, "Unknown search or announce!");
            } else {
                if (on_done) {
                    RequestAnswer answer {};
                    answer.vid = msg.value_id;
                    on_done(req_status, std::move(answer));
                }
            }
        },
        on_error,
        [=](const Request& req_status, bool done) { /* on expired */
            if (on_expired) {
                on_expired(req_status, done);
            }
        }
    );
    sendRequest(req);
    ++out_stats.refresh;
    return req;
}

void
NetworkEngine::sendValueAnnounced(const SockAddr& addr, Tid tid, Value::Id vid) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(config.network?1:0));

    pk.pack(KEY_R); pk.pack_map(3);
      pk.pack(KEY_REQ_ID);  pk.pack(myid);
      pk.pack(KEY_REQ_VALUE_ID); pk.pack(vid);
      insertAddr(pk, addr);

    pk.pack(KEY_TID); pk.pack(tid);
    pk.pack(KEY_Y); pk.pack(KEY_R);
    pk.pack(KEY_UA); pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    send(addr, buffer.data(), buffer.size());
}

void
NetworkEngine::sendError(const SockAddr& addr,
        Tid tid,
        uint16_t code,
        const std::string& message,
        bool include_id)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4 + (include_id?1:0) + (config.network?1:0));

    pk.pack(KEY_E); pk.pack_array(2);
      pk.pack(code);
      pk.pack(message);

    if (include_id) {
        pk.pack(KEY_R); pk.pack_map(1);
          pk.pack(KEY_REQ_ID); pk.pack(myid);
    }

    pk.pack(KEY_TID); pk.pack(tid);
    pk.pack(KEY_Y); pk.pack(KEY_E);
    pk.pack(KEY_UA); pk.pack(my_v);
    if (config.network) {
        pk.pack(KEY_NETID); pk.pack(config.network);
    }

    send(addr, buffer.data(), buffer.size());
}

void
NetworkEngine::maintainRxBuffer(Tid tid)
{
    auto msg = partial_messages.find(tid);
    if (msg != partial_messages.end()) {
        const auto& now = scheduler.time();
        if (msg->second.start + RX_MAX_PACKET_TIME < now
         || msg->second.last_part + RX_TIMEOUT < now) {
            if (logger_)
                logger_->w("Dropping expired partial message from %s", msg->second.from.toString().c_str());
            partial_messages.erase(msg);
        }
    }
}


} /* namespace net  */
} /* namespace dht */
