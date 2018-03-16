/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
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

#ifndef _WIN32
#include <arpa/inet.h>
#include <unistd.h>
#else
#include <ws2tcpip.h>
#include <io.h>
#endif
#include <fcntl.h>

#include <cstring>

namespace dht {
namespace net {

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
constexpr size_t NetworkEngine::MAX_REQUESTS_PER_SEC;

static const uint8_t v4prefix[16] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
};

constexpr unsigned SEND_NODES {8};

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


/* Transaction-ids are 4-bytes long, with the first two bytes identifying
 * the kind of request, and the remaining two a sequence number in
 * host order.
 */
struct TransId final : public std::array<uint8_t, 4> {
    TransId() { std::fill(begin(), end(), 0); }
    TransId(const std::array<char, 4>& o) { std::copy(o.begin(), o.end(), begin()); }
    TransId(uint32_t id) {
        *reinterpret_cast<uint32_t*>(data()) = htonl(id);
    }

    uint32_t toInt() const {
        return ntohl(*reinterpret_cast<const uint32_t*>(&(*this)[0]));
    }
};


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

NetworkEngine::NetworkEngine(Logger& log, Scheduler& scheduler, const int& s, const int& s6)
    : myid(zeroes), DHT_LOG(log), scheduler(scheduler), dht_socket(s), dht_socket6(s6)
{}
NetworkEngine::NetworkEngine(InfoHash& myid, NetId net, const int& s, const int& s6, Logger& log, Scheduler& scheduler,
        decltype(NetworkEngine::onError) onError,
        decltype(NetworkEngine::onNewNode) onNewNode,
        decltype(NetworkEngine::onReportedAddr) onReportedAddr,
        decltype(NetworkEngine::onPing) onPing,
        decltype(NetworkEngine::onFindNode) onFindNode,
        decltype(NetworkEngine::onGetValues) onGetValues,
        decltype(NetworkEngine::onListen) onListen,
        decltype(NetworkEngine::onAnnounce) onAnnounce,
        decltype(NetworkEngine::onRefresh) onRefresh) :
    onError(onError), onNewNode(onNewNode), onReportedAddr(onReportedAddr), onPing(onPing), onFindNode(onFindNode),
    onGetValues(onGetValues), onListen(onListen), onAnnounce(onAnnounce), onRefresh(onRefresh), myid(myid),
    network(net), dht_socket(s), dht_socket6(s6), DHT_LOG(log), scheduler(scheduler)
{
    if (dht_socket >= 0) {
        if (!set_nonblocking(dht_socket, 1))
            throw DhtException("Can't set socket to non-blocking mode");
    }
    if (dht_socket6 >= 0) {
        if (!set_nonblocking(dht_socket6, 1))
            throw DhtException("Can't set socket to non-blocking mode");
    }
}

NetworkEngine::~NetworkEngine() {
    clear();
}

void
NetworkEngine::tellListener(Sp<Node> node, Tid socket_id, const InfoHash& hash, want_t want,
        const Blob& ntoken, std::vector<Sp<Node>>&& nodes,
        std::vector<Sp<Node>>&& nodes6, std::vector<Sp<Value>>&& values,
        const Query& query)
{
    auto nnodes = bufferNodes(node->getFamily(), hash, want, nodes, nodes6);
    try {
        sendNodesValues(node->getAddr(), socket_id, nnodes.first, nnodes.second, values, query, ntoken);
    } catch (const std::overflow_error& e) {
        DHT_LOG.e("Can't send value: buffer not large enough !");
    }
}

void
NetworkEngine::tellListenerRefreshed(Sp<Node> n, Tid socket_id, const InfoHash& hash, const Blob& token, const std::vector<Value::Id>& values)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("u"));
    pk.pack_map(1 + (not values.empty()?1:0) + (not token.empty()?1:0));
    pk.pack(std::string("id")); pk.pack(myid);
    if (not token.empty()) {
        pk.pack(std::string("token")); packToken(pk, token);
    }
    if (not values.empty()) {
        pk.pack(std::string("re"));
        pk.pack(values);
        DHT_LOG.d(n->id, "[node %s] sending %zu refreshed values", n->toString().c_str(), values.size());
    }

    pk.pack(std::string("t")); pk.pack(socket_id);
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    // send response
    send(buffer.data(), buffer.size(), 0, n->getAddr());
}

void
NetworkEngine::tellListenerExpired(Sp<Node> n, Tid socket_id, const InfoHash& hash, const Blob& token, const std::vector<Value::Id>& values)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("u"));
    pk.pack_map(1 + (not values.empty()?1:0) + (not token.empty()?1:0));
    pk.pack(std::string("id")); pk.pack(myid);
    if (not token.empty()) {
        pk.pack(std::string("token")); packToken(pk, token);
    }
    if (not values.empty()) {
        pk.pack(std::string("exp"));
        pk.pack(values);
        DHT_LOG.d(n->id, "[node %s] sending %zu expired values", n->toString().c_str(), values.size());
    }

    pk.pack(std::string("t")); pk.pack(socket_id);
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    // send response
    send(buffer.data(), buffer.size(), 0, n->getAddr());
}


bool
NetworkEngine::isRunning(sa_family_t af) const
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

void
NetworkEngine::clear()
{}

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
        DHT_LOG.e(node.id, "[node %s] expired !", node.toString().c_str());
        node.setExpired();
        if (not node.id)
            requests.erase(req.tid);
        return;
    } else if (req.attempt_count == 1) {
        req.on_expired(req, false);
    }

    auto err = send((char*)req.msg.data(), req.msg.size(),
            (node.getReplyTime() >= now - UDP_REPLY_TIME) ? 0 : MSG_CONFIRM,
            node.getAddr());
    if (err == ENETUNREACH  ||
        err == EHOSTUNREACH ||
        err == EAFNOSUPPORT ||
        err == EPIPE)
    {
        node.setExpired();
        if (not node.id)
            requests.erase(req.tid);
    } else {
        if (err != EAGAIN) {
            ++req.attempt_count;
        }
        req.last_try = now;
        std::weak_ptr<Request> wreq = sreq;
        scheduler.add(req.last_try + Node::MAX_RESPONSE_TIME, [this,wreq] {
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
    auto& node = request->node;
    if (not node->id)
        requests.emplace(request->tid, request);
    request->start = scheduler.time();
    node->requested(request);
    requestStep(request);
}


/* Rate control for requests we receive. */
bool
NetworkEngine::rateLimit(const SockAddr& addr)
{
    const auto& now = scheduler.time();

    // occasional IP limiter maintenance (a few times every second at max rate)
    if (limiter_maintenance++ == MAX_REQUESTS_PER_SEC/8) {
        for (auto it = address_rate_limiter.begin(); it != address_rate_limiter.end();) {
            if (it->second.maintain(now) == 0)
                address_rate_limiter.erase(it++);
            else
                ++it;
        }
        limiter_maintenance = 0;
    }

    auto it = address_rate_limiter.emplace(addr, IpLimiter{});
    // invoke per IP, then global rate limiter
    return it.first->second.limit(now) and rate_limiter.limit(now);
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
NetworkEngine::processMessage(const uint8_t *buf, size_t buflen, const SockAddr& from)
{
    if (isMartian(from)) {
        DHT_LOG.w("Received packet from martian node %s", from.toString().c_str());
        return;
    }

    if (isNodeBlacklisted(from)) {
        DHT_LOG.w("Received packet from blacklisted node %s", from.toString().c_str());
        return;
    }

    std::unique_ptr<ParsedMessage> msg {new ParsedMessage};
    try {
        msgpack::unpacked msg_res = msgpack::unpack((const char*)buf, buflen);
        msg->msgpack_unpack(msg_res.get());
    } catch (const std::exception& e) {
        DHT_LOG.w("Can't parse message of size %lu: %s", buflen, e.what());
        DHT_LOG.DEBUG.logPrintable(buf, buflen);
        return;
    }

    if (msg->network != network) {
        DHT_LOG.d("Received message from other network %u", msg->network);
        return;
    }

    const auto& now = scheduler.time();

    // partial value data
    if (msg->type == MessageType::ValueData) {
        auto pmsg_it = partial_messages.find(msg->tid);
        if (pmsg_it == partial_messages.end()) {
            DHT_LOG.d("Can't find partial message");
            rateLimit(from);
            return;
        }
        if (!pmsg_it->second.from.equals(from)) {
            DHT_LOG.d("Received partial message data from unexpected IP address");
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
        DHT_LOG.d("Received message from self");
        return;
    }

    if (msg->type > MessageType::Reply) {
        /* Rate limit requests. */
        if (!rateLimit(from)) {
            DHT_LOG.w("Dropping request due to rate limiting");
            return;
        }
    }

    if (msg->value_parts.empty()) {
        process(std::move(msg), from);
    } else {
        // starting partial message session
        PartialMessage pmsg;
        pmsg.from = from;
        pmsg.msg = std::move(msg);
        pmsg.start = now;
        pmsg.last_part = now;
        auto wmsg = partial_messages.emplace(pmsg.msg->tid, std::move(pmsg));
        if (wmsg.second) {
            scheduler.add(now + RX_MAX_PACKET_TIME, std::bind(&NetworkEngine::maintainRxBuffer, this, wmsg.first->first));
            scheduler.add(now + RX_TIMEOUT, std::bind(&NetworkEngine::maintainRxBuffer, this, wmsg.first->first));
        } else
            DHT_LOG.e("Partial message with given TID already exists");
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
                throw DhtProtocolException {DhtProtocolException::UNKNOWN_TID, "Can't find transaction", msg->id};
            }
        }

        node->received(now, req);

        if (not node->isClient())
            onNewNode(node, 2);
        onReportedAddr(msg->id, msg->addr);

        if (req and (req->cancelled() or req->expired() or req->completed())) {
            DHT_LOG.w(node->id, "[node %s] response to expired, cancelled or completed request", node->toString().c_str());
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
                onError(req, DhtProtocolException {msg->error_code});
            } else {
                DHT_LOG.w(msg->id, "[node %s %s] received unknown error message %u",
                        msg->id.toString().c_str(), from.toString().c_str(), msg->error_code);
            }
            break;
        }
        case MessageType::Reply:
            if (req) { /* request reply */
                if (msg->type == MessageType::AnnounceValue or msg->type == MessageType::Listen)
                    req->node->authSuccess();
                req->reply_time = scheduler.time();

                deserializeNodes(*msg, from);
                req->setDone(std::move(*msg));
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
                DHT_LOG.d(node->id, "[node %s] sending pong", node->toString().c_str());
                onPing(node);
                sendPong(from, msg->tid);
                break;
            case MessageType::FindNode: {
                //DHT_LOG.d(msg->target, node->id, "[node %s] got 'find' request for %s (%d)", node->toString().c_str(), msg->target.toString().c_str(), msg->want);
                ++in_stats.find;
                RequestAnswer answer = onFindNode(node, msg->target, msg->want);
                auto nnodes = bufferNodes(from.getFamily(), msg->target, msg->want, answer.nodes4, answer.nodes6);
                sendNodesValues(from, msg->tid, nnodes.first, nnodes.second, {}, {}, answer.ntoken);
                break;
            }
            case MessageType::GetValues: {
                //DHT_LOG.d(msg->info_hash, node->id, "[node %s] got 'get' request for %s", node->toString().c_str(), msg->info_hash.toString().c_str());
                ++in_stats.get;
                RequestAnswer answer = onGetValues(node, msg->info_hash, msg->want, msg->query);
                auto nnodes = bufferNodes(from.getFamily(), msg->info_hash, msg->want, answer.nodes4, answer.nodes6);
                sendNodesValues(from, msg->tid, nnodes.first, nnodes.second, answer.values, msg->query, answer.ntoken);
                break;
            }
            case MessageType::AnnounceValue: {
                DHT_LOG.d(msg->info_hash, node->id, "[node %s] got 'put' request for %s", node->toString().c_str(), msg->info_hash.toString().c_str());
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
                DHT_LOG.d(msg->info_hash, node->id, "[node %s] got 'refresh' request for %s", node->toString().c_str(), msg->info_hash.toString().c_str());
                onRefresh(node, msg->info_hash, msg->token, msg->value_id);
                /* Same note as above in MessageType::AnnounceValue applies. */
                sendValueAnnounced(from, msg->tid, msg->value_id);
                break;
            case MessageType::Listen: {
                DHT_LOG.d(msg->info_hash, node->id, "[node %s] got 'listen' request for %s", node->toString().c_str(), msg->info_hash.toString().c_str());
                ++in_stats.listen;
                RequestAnswer answer = onListen(node, msg->info_hash, msg->token, msg->socket_id, std::move(msg->query));
                sendListenConfirmation(from, msg->tid);
                break;
            }
            default:
                break;
            }
        } catch (const std::overflow_error& e) {
            DHT_LOG.e("Can't send value: buffer not large enough !");
        } catch (DhtProtocolException& e) {
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
NetworkEngine::send(const char *buf, size_t len, int flags, const SockAddr& addr)
{
    if (not addr)
        return EFAULT;

    int s;
    if (addr.getFamily() == AF_INET)
        s = dht_socket;
    else if (addr.getFamily() == AF_INET6)
        s = dht_socket6;
    else
        s = -1;

    if (s < 0)
        return EAFNOSUPPORT;
#ifdef MSG_NOSIGNAL
    flags &= MSG_NOSIGNAL;
#endif
    if (sendto(s, buf, len, flags, addr.get(), addr.getLength()) == -1) {
        int err = errno;
        DHT_LOG.e("Can't send message to %s: %s", addr.toString().c_str(), strerror(err));
        if (err == EPIPE) {
            throw SocketException(EPIPE);
        }
        return err;
    }
    return 0;
}

Sp<Request>
NetworkEngine::sendPing(Sp<Node> node, RequestCb&& on_done, RequestExpiredCb&& on_expired) {
    TransId tid (node->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(network?1:0));

    pk.pack(std::string("a")); pk.pack_map(1);
     pk.pack(std::string("id")); pk.pack(myid);

    pk.pack(std::string("q")); pk.pack(std::string("ping"));
    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                              pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("q"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    auto req = std::make_shared<Request>(MessageType::Ping, tid.toInt(), node,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&&) {
            DHT_LOG.d(req_status.node->id, "[node %s] got pong !", req_status.node->toString().c_str());
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
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("r")); pk.pack_map(2);
      pk.pack(std::string("id")); pk.pack(myid);
      insertAddr(pk, addr);

    TransId t (tid);
    pk.pack(std::string("t")); pk.pack_bin(t.size());
                               pk.pack_bin_body((const char*)t.data(), t.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    send(buffer.data(), buffer.size(), 0, addr);
}

Sp<Request>
NetworkEngine::sendFindNode(Sp<Node> n, const InfoHash& target, want_t want,
        RequestCb&& on_done, RequestExpiredCb&& on_expired) {
    TransId tid (n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(network?1:0));

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
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    auto req = std::make_shared<Request>(MessageType::FindNode, tid.toInt(), n,
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
    TransId tid (n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(network?1:0));

    pk.pack(std::string("a"));  pk.pack_map(2 +
                                (query.where.getFilter() or not query.select.getSelection().empty() ? 1:0) +
                                (want>0?1:0));
      pk.pack(std::string("id")); pk.pack(myid);
      pk.pack(std::string("h"));  pk.pack(info_hash);
      pk.pack(std::string("q")); pk.pack(query);
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
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    auto req = std::make_shared<Request>(MessageType::GetValues, tid.toInt(), n,
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
    pk.pack(std::string("values"));
    pk.pack_array(svals.size());
    // try to put everything in a single UDP packet
    if (svals.size() < 50 && total_size < MAX_PACKET_VALUE_SIZE) {
        for (const auto& b : svals)
            buffer.write((const char*)b.data(), b.size());
        DHT_LOG.d("sending %lu bytes of values", total_size);
        svals.clear();
    } else {
        for (const auto& b : svals)
            pk.pack(b.size());
    }
    return svals;
}

void
NetworkEngine::sendValueParts(const TransId& tid, const std::vector<Blob>& svals, const SockAddr& addr)
{
    msgpack::sbuffer buffer;
    unsigned i=0;
    for (const auto& v: svals) {
        size_t start {0}, end;
        do {
            end = std::min(start + MTU, v.size());
            buffer.clear();
            msgpack::packer<msgpack::sbuffer> pk(&buffer);
            pk.pack_map(3+(network?1:0));
            if (network) {
                pk.pack(std::string("n")); pk.pack(network);
            }
            pk.pack(std::string("y")); pk.pack(std::string("v"));
            pk.pack(std::string("t")); pk.pack_bin(tid.size());
                                       pk.pack_bin_body((const char*)tid.data(), tid.size());
            pk.pack(std::string("p")); pk.pack_map(1);
                pk.pack(i); pk.pack_map(2);
                    pk.pack(std::string("o")); pk.pack(start);
                    pk.pack(std::string("d")); pk.pack_bin(end-start);
                                               pk.pack_bin_body((const char*)v.data()+start, end-start);
            send(buffer.data(), buffer.size(), 0, addr);
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
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("r"));
    pk.pack_map(2 + (not st.empty()?1:0) + (nodes.size()>0?1:0) + (nodes6.size()>0?1:0) + (not token.empty()?1:0));
    pk.pack(std::string("id")); pk.pack(myid);
    insertAddr(pk, addr);
    if (nodes.size() > 0) {
        pk.pack(std::string("n4"));
        pk.pack_bin(nodes.size());
        pk.pack_bin_body((const char*)nodes.data(), nodes.size());
    }
    if (nodes6.size() > 0) {
        pk.pack(std::string("n6"));
        pk.pack_bin(nodes6.size());
        pk.pack_bin_body((const char*)nodes6.data(), nodes6.size());
    }
    if (not token.empty()) {
        pk.pack(std::string("token")); packToken(pk, token);
    }
    std::vector<Blob> svals {};
    if (not st.empty()) { /* pack complete values */
        auto fields = query.select.getSelection();
        if (fields.empty()) {
            svals = packValueHeader(buffer, st);
        } else { /* pack fields */
            pk.pack(std::string("fields"));
            pk.pack_map(2);
            pk.pack(std::string("f")); pk.pack(fields);
            pk.pack(std::string("v")); pk.pack_array(st.size()*fields.size());
            for (const auto& v : st)
                v->msgpack_pack_fields(fields, pk);
            //DHT_LOG_DEBUG("sending closest nodes (%d+%d nodes.), %u value headers containing %u fields",
            //        nodes.size(), nodes6.size(), st.size(), fields.size());
        }
    }

    TransId t (tid);
    pk.pack(std::string("t")); pk.pack_bin(t.size());
                               pk.pack_bin_body((const char*)t.data(), t.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    // send response
    send(buffer.data(), buffer.size(), 0, addr);

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
        Sp<Request> previous,
        RequestCb&& on_done,
        RequestExpiredCb&& on_expired,
        SocketCb&& socket_cb)
{
    Tid socket;
    TransId tid (n->getNewTid());
    if (previous and previous->node == n) {
        socket = previous->getSocket();
    } else {
        if (previous)
            DHT_LOG.e(hash, "[node %s] trying refresh listen contract with wrong node", previous->node->toString().c_str());
        socket = n->openSocket(std::move(socket_cb));
    }

    if (not socket) {
        DHT_LOG.e(hash, "[node %s] unable to get a valid socket for listen. Aborting listen", n->toString().c_str());
        return {};
    }
    TransId sid(socket);

    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(network?1:0));

    auto has_query = query.where.getFilter() or not query.select.getSelection().empty();
    pk.pack(std::string("a")); pk.pack_map(4 + has_query);
      pk.pack(std::string("id"));    pk.pack(myid);
      pk.pack(std::string("h"));     pk.pack(hash);
      pk.pack(std::string("token")); packToken(pk, token);
      pk.pack(std::string("sid"));  pk.pack_bin(sid.size());
                                     pk.pack_bin_body((const char*)sid.data(), sid.size());
      if (has_query) {
          pk.pack(std::string("q")); pk.pack(query);
      }

    pk.pack(std::string("q")); pk.pack(std::string("listen"));
    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("q"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    auto req = std::make_shared<Request>(MessageType::Listen, tid.toInt(), n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
            if (on_done)
                on_done(req_status, {std::forward<ParsedMessage>(msg)});
        },
        [=](const Request& req_status, bool done) { /* on expired */
            if (on_expired)
                on_expired(req_status, done);
        },
        socket
    );
    sendRequest(req);
    ++out_stats.listen;
    return req;
}

void
NetworkEngine::sendListenConfirmation(const SockAddr& addr, Tid tid) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("r")); pk.pack_map(2);
      pk.pack(std::string("id")); pk.pack(myid);
      insertAddr(pk, addr);

    TransId t (tid);
    pk.pack(std::string("t")); pk.pack_bin(t.size());
                               pk.pack_bin_body((const char*)t.data(), t.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    send(buffer.data(), buffer.size(), 0, addr);
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
    TransId tid (n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(network?1:0));

    pk.pack(std::string("a")); pk.pack_map((created < scheduler.time() ? 5 : 4));
      pk.pack(std::string("id"));     pk.pack(myid);
      pk.pack(std::string("h"));      pk.pack(infohash);
      auto v = packValueHeader(buffer, {value});
      if (created < scheduler.time()) {
          pk.pack(std::string("c"));
          pk.pack(to_time_t(created));
      }
      pk.pack(std::string("token"));  pk.pack(token);

    pk.pack(std::string("q")); pk.pack(std::string("put"));
    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("q"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    auto req = std::make_shared<Request>(MessageType::AnnounceValue, tid.toInt(), n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
            if (msg.value_id == Value::INVALID_ID) {
                DHT_LOG.d(infohash, "Unknown search or announce!");
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
    sendRequest(req);
    if (not v.empty())
        sendValueParts(tid, v, n->getAddr());
    ++out_stats.put;
    return req;
}

Sp<Request>
NetworkEngine::sendRefreshValue(Sp<Node> n,
                const InfoHash& infohash,
                const Value::Id& vid,
                const Blob& token,
                RequestCb&& on_done,
                RequestExpiredCb&& on_expired)
{
    TransId tid (n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(network?1:0));

    pk.pack(std::string("a")); pk.pack_map(4);
      pk.pack(std::string("id"));  pk.pack(myid);
      pk.pack(std::string("h"));  pk.pack(infohash);
      pk.pack(std::string("vid")); pk.pack(vid);
      pk.pack(std::string("token"));  pk.pack(token);

    pk.pack(std::string("q")); pk.pack(std::string("refresh"));
    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("q"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    auto req = std::make_shared<Request>(MessageType::Refresh, tid.toInt(), n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
            if (msg.value_id == Value::INVALID_ID) {
                DHT_LOG.d(infohash, "Unknown search or announce!");
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
    sendRequest(req);
    ++out_stats.refresh;
    return req;
}

void
NetworkEngine::sendValueAnnounced(const SockAddr& addr, Tid tid, Value::Id vid) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("r")); pk.pack_map(3);
      pk.pack(std::string("id"));  pk.pack(myid);
      pk.pack(std::string("vid")); pk.pack(vid);
      insertAddr(pk, addr);

    TransId t(tid);
    pk.pack(std::string("t")); pk.pack_bin(t.size());
                               pk.pack_bin_body((const char*)t.data(), t.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    send(buffer.data(), buffer.size(), 0, addr);
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
    pk.pack_map(4 + (include_id?1:0));

    pk.pack(std::string("e")); pk.pack_array(2);
      pk.pack(code);
      pk.pack(message);

    if (include_id) {
        pk.pack(std::string("r")); pk.pack_map(1);
          pk.pack(std::string("id")); pk.pack(myid);
    }

    TransId t(tid);
    pk.pack(std::string("t")); pk.pack_bin(t.size());
                               pk.pack_bin_body((const char*)t.data(), t.size());
    pk.pack(std::string("y")); pk.pack(std::string("e"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    send(buffer.data(), buffer.size(), 0, addr);
}

void
NetworkEngine::maintainRxBuffer(Tid tid)
{
    auto msg = partial_messages.find(tid);
    if (msg != partial_messages.end()) {
        const auto& now = scheduler.time();
        if (msg->second.start + RX_MAX_PACKET_TIME < now
         || msg->second.last_part + RX_TIMEOUT < now) {
            DHT_LOG.w("Dropping expired partial message from %s", msg->second.from.toString().c_str());
            partial_messages.erase(msg);
        }
    }
}


} /* namespace net  */
} /* namespace dht */
