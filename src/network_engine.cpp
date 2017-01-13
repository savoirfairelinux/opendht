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
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


#include "network_engine.h"
#include "request.h"
#include "default_types.h"
#include "log_enable.h"

#include <msgpack.hpp>

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
const constexpr uint16_t TransId::INVALID;
std::mt19937 NetworkEngine::rd_device {dht::crypto::random_device{}()};

const TransPrefix TransPrefix::PING = {"pn"};
const TransPrefix TransPrefix::FIND_NODE = {"fn"};
const TransPrefix TransPrefix::GET_VALUES = {"gt"};
const TransPrefix TransPrefix::ANNOUNCE_VALUES = {"pt"};
const TransPrefix TransPrefix::REFRESH = {"rf"};
const TransPrefix TransPrefix::LISTEN = {"lt"};
constexpr long unsigned NetworkEngine::MAX_REQUESTS_PER_SEC;

static const uint8_t v4prefix[16] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
};

constexpr unsigned SEND_NODES {8};

enum class MessageType {
    Error = 0,
    Reply,
    Ping,
    FindNode,
    GetValues,
    AnnounceValue,
    Refresh,
    Listen,
    ValueData
};

struct ParsedMessage {
    MessageType type;
    /* Node ID of the sender */
    InfoHash id;
    /* Network id */
    NetId network {0};
    /* hash for which values are requested */
    InfoHash info_hash;
    /* target id around which to find nodes */
    InfoHash target;
    /* transaction id */
    TransId tid;
    /* tid for packets going through request socket */
    TransId socket_id;
    /* security token */
    Blob token;
    /* the value id (announce confirmation) */
    Value::Id value_id;
    /* time when value was first created */
    time_point created { time_point::max() };
    /* IPv4 nodes in response to a 'find' request */
    Blob nodes4_raw, nodes6_raw;
    std::vector<std::shared_ptr<Node>> nodes4, nodes6;
    /* values to store or retreive request */
    std::vector<std::shared_ptr<Value>> values;
    /* index for fields values */
    std::vector<std::shared_ptr<FieldValueIndex>> fields;
    /** When part of the message header: {index -> (total size, {})}
     *  When part of partial value data: {index -> (offset, part_data)} */
    std::map<unsigned, std::pair<unsigned, Blob>> value_parts;
    /* query describing a filter to apply on values. */
    Query query;
    /* states if ipv4 or ipv6 request */
    want_t want;
    /* error code in case of error */
    uint16_t error_code;
    /* reported address by the distant node */
    std::string ua;
    SockAddr addr;
    void msgpack_unpack(msgpack::object o);

    bool append(const ParsedMessage& block);
    bool complete();
};

struct NetworkEngine::PartialMessage {
    SockAddr from;
    time_point start;
    time_point last_part;
    std::unique_ptr<ParsedMessage> msg;
};

std::vector<Blob>
serializeValues(const std::vector<std::shared_ptr<Value>>& st)
{
    std::vector<Blob> svals;
    svals.reserve(st.size());
    for (const auto& v : st)
        svals.emplace_back(packMsg(v));
    return svals;
}

NetworkEngine::RequestAnswer::RequestAnswer(ParsedMessage&& msg)
 : ntoken(std::move(msg.token)), values(std::move(msg.values)), fields(std::move(msg.fields)),
    nodes4(std::move(msg.nodes4)), nodes6(std::move(msg.nodes6)) {}

NetworkEngine::NetworkEngine(Logger& log, Scheduler& scheduler) : myid(zeroes), DHT_LOG(log), scheduler(scheduler) {}
NetworkEngine::NetworkEngine(InfoHash& myid, NetId net, int s, int s6, Logger& log, Scheduler& scheduler,
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
    transaction_id = std::uniform_int_distribution<decltype(transaction_id)>{1}(rd_device);
}

NetworkEngine::~NetworkEngine() {
    clear();
}

void
NetworkEngine::tellListener(std::shared_ptr<Node> node, uint32_t socket_id, const InfoHash& hash, want_t want,
        const Blob& ntoken, std::vector<std::shared_ptr<Node>>&& nodes,
        std::vector<std::shared_ptr<Node>>&& nodes6, std::vector<std::shared_ptr<Value>>&& values,
        const Query& query)
{
    auto nnodes = bufferNodes(node->getFamily(), hash, want, nodes, nodes6);
    try {
        sendNodesValues(node->addr, TransId((char*)&socket_id, 4), nnodes.first, nnodes.second, values, query, ntoken);
    } catch (const std::overflow_error& e) {
        DHT_LOG.e("Can't send value: buffer not large enough !");
    }
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

std::shared_ptr<Socket>
NetworkEngine::openSocket(const std::shared_ptr<Node>& node, TransPrefix tp, SocketCb&& cb)
{
    auto tid = TransId {tp, getNewTid()};
    auto s = opened_sockets.emplace(tid, std::make_shared<Socket>(node, tid, cb));
    if (not s.second)
        DHT_LOG.e(node->id, "[node %s] socket (tid: %d) already opened!", node->id.toString().c_str(), tid.toInt());
    return s.first->second;
}

void
NetworkEngine::closeSocket(std::shared_ptr<Socket> socket)
{
    if (socket)
        opened_sockets.erase(socket->id);
}

void
NetworkEngine::cancelRequest(std::shared_ptr<Request>& req)
{
    if (req) {
        req->cancel();
        closeSocket(req->socket);
        requests.erase(req->tid);
    }
}

void
NetworkEngine::clear()
{
    for (auto& req : requests)
        req.second->setExpired();
    requests.clear();
}

void
NetworkEngine::connectivityChanged(sa_family_t af)
{
    cache.clearBadNodes(af);
}

void
NetworkEngine::requestStep(std::shared_ptr<Request> sreq)
{
    auto& req = *sreq;
    if (not req.pending()) {
        if (req.cancelled())
            requests.erase(req.tid);
        return;
    }

    auto now = scheduler.time();
    auto& node = *req.node;
    if (req.isExpired(now)) {
        DHT_LOG.e(node.id, "[node %s] expired !", node.toString().c_str());
        node.setExpired();
        requests.erase(req.tid);
        return;
    } else if (req.attempt_count == 1) {
        req.on_expired(req, false);
    }

    send((char*)req.msg.data(), req.msg.size(),
            (node.reply_time >= now - UDP_REPLY_TIME) ? 0 : MSG_CONFIRM,
            node.addr);
    ++req.attempt_count;
    req.last_try = now;
    std::weak_ptr<Request> wreq = sreq;
    scheduler.add(req.last_try + Node::MAX_RESPONSE_TIME, [this,wreq] {
        if (auto req = wreq.lock())
            requestStep(req);
    });
}

/**
 * Sends a request to a node. Request::MAX_ATTEMPT_COUNT attempts will
 * be made before the request expires.
 */
void
NetworkEngine::sendRequest(std::shared_ptr<Request>& request)
{
    request->start = scheduler.time();
    auto e = requests.emplace(request->tid, request);
    if (not e.second) {
        // Should not happen !
        // Try to handle this scenario as well as we can
        e.first->second->setExpired();
        e.first->second = request;
        DHT_LOG.e(request->node->id, "Request already existed (tid: %d)!", request->tid.getTid());
    }
    request->node->requested(request);
    requestStep(request);
}


/* Rate control for requests we receive. */
bool
NetworkEngine::rateLimit(const SockAddr& addr)
{
    const auto& now = scheduler.time();

    // occasional IP limiter maintenance
    std::bernoulli_distribution rand_trial(1./128.);
    if (rand_trial(rd_device)) {
        for (auto it = address_rate_limiter.begin(); it != address_rate_limiter.end();) {
            if (it->second.maintain(now) == 0)
                address_rate_limiter.erase(it++);
            else
                ++it;
        }
    }

    auto it = address_rate_limiter.emplace(addr, IpLimiter{});
    // invoke per IP, then global rate limiter
    return it.first->second.limit(now) and rate_limiter.limit(now);
}

bool
NetworkEngine::isMartian(const SockAddr& addr)
{
    // Check that sa_family can be accessed safely
    if (addr.second < sizeof(sockaddr_in))
        return true;

    switch(addr.first.ss_family) {
    case AF_INET: {
        sockaddr_in *sin = (sockaddr_in*)&addr.first;
        const uint8_t *address = (const uint8_t*)&sin->sin_addr;
        return sin->sin_port == 0 ||
            (address[0] == 0) ||
            (address[0] == 127) ||
            ((address[0] & 0xE0) == 0xE0);
    }
    case AF_INET6: {
        if (addr.second < sizeof(sockaddr_in6))
            return true;
        sockaddr_in6 *sin6 = (sockaddr_in6*)&addr.first;
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

/* The internal blacklist is an LRU cache of nodes that have sent
   incorrect messages. */
void
NetworkEngine::blacklistNode(const std::shared_ptr<Node>& n)
{
    n->setExpired();
    for (auto rit = requests.begin(); rit != requests.end();) {
        if (rit->second->node == n) {
            //rit->second->cancel();
            requests.erase(rit++);
        } else {
            ++rit;
        }
    }
    blacklist.emplace(n->addr);
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
        DHT_LOG.w("Can't process message of size %lu: %s", buflen, e.what());
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

    if (msg->id == myid || msg->id == zeroes) {
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

    if (msg->type == MessageType::Error or msg->type == MessageType::Reply) {
        /* either response for a request or data for an opened socket */
        auto req_it = requests.find(msg->tid);
        auto rsocket_it = opened_sockets.end();
        if (req_it == requests.end())
            rsocket_it = opened_sockets.find(msg->tid);
        if (req_it == requests.end() and rsocket_it == opened_sockets.end())
            throw DhtProtocolException {DhtProtocolException::UNKNOWN_TID, "Can't find transaction", msg->id};

        auto req = req_it != requests.end() ? req_it->second : nullptr;
        auto rsocket = rsocket_it != opened_sockets.end() ? rsocket_it->second : nullptr;

        auto& node = req ? req->node : rsocket->node;
        if (node->id != msg->id) {
            if (node->id == zeroes) // received reply to a message sent when we didn't know the node ID.
                node = cache.getNode(msg->id, from, now, true);
            else {
                // received reply from unexpected node
                node->received(now, req);
                onNewNode(node, 2);
                DHT_LOG.w(node->id, "[node %s] message received from unexpected node", node->toString().c_str());
                return;
            }
        } else
            node->update(from);

        node->received(now, req);

        onNewNode(node, 2);
        onReportedAddr(msg->id, msg->addr);

        if (req and (req->cancelled() or req->expired() or req->completed())) {
            DHT_LOG.w(node->id, "[node %s] response to expired, cancelled or completed request", node->toString().c_str());
            requests.erase(req_it);
            return;
        }

        switch (msg->type) {
        case MessageType::Error: {
            if (msg->id != zeroes and (
                (msg->error_code == DhtProtocolException::NOT_FOUND    and  msg->tid.matches(TransPrefix::REFRESH)) or
                (msg->error_code == DhtProtocolException::UNAUTHORIZED and (msg->tid.matches(TransPrefix::ANNOUNCE_VALUES)
                                                                         or msg->tid.matches(TransPrefix::LISTEN)))))
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

             // erase before calling callback to make sure iterator is still valid
             requests.erase(req_it);
             req->reply_time = scheduler.time();

             deserializeNodes(*msg);
             req->setDone(std::move(*msg));
             break;
         } else { /* request socket data */
             deserializeNodes(*msg);
             rsocket->on_receive(rsocket->node, std::move(*msg));
         }
        default:
            break;
        }
    } else {
        auto node = cache.getNode(msg->id, from, now, true);
        node->received(now, {});
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
                DHT_LOG.d(msg->target, node->id, "[node %s] got 'find' request for %s (%d)", node->toString().c_str(), msg->target.toString().c_str(), msg->want);
                ++in_stats.find;
                RequestAnswer answer = onFindNode(node, msg->target, msg->want);
                auto nnodes = bufferNodes(from.getFamily(), msg->target, msg->want, answer.nodes4, answer.nodes6);
                sendNodesValues(from, msg->tid, nnodes.first, nnodes.second, {}, {}, answer.ntoken);
                break;
            }
            case MessageType::GetValues: {
                DHT_LOG.d(msg->info_hash, node->id, "[node %s] got 'get' request for %s", node->toString().c_str(), msg->info_hash.toString().c_str());
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
                /* TODO: backward compatibility check to remove in a few versions (see ::sendListen doc) */
                auto socket_id = msg->socket_id.getTid() ? msg->socket_id : TransId { TransPrefix::GET_VALUES, msg->tid.getTid() };
                RequestAnswer answer = onListen(node, msg->info_hash, msg->token, socket_id.toInt(), std::move(msg->query));
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
packToken(msgpack::packer<msgpack::sbuffer>& pk, const Blob& token)
{
    pk.pack_bin(token.size());
    pk.pack_bin_body((char*)token.data(), token.size());
}

void
insertAddr(msgpack::packer<msgpack::sbuffer>& pk, const SockAddr& addr)
{
    size_t addr_len = std::min<size_t>(addr.second,
                     (addr.getFamily() == AF_INET) ? sizeof(in_addr) : sizeof(in6_addr));
    void* addr_ptr = (addr.getFamily() == AF_INET) ? (void*)&((sockaddr_in*)&addr.first)->sin_addr
                                                : (void*)&((sockaddr_in6*)&addr.first)->sin6_addr;
    pk.pack("sa");
    pk.pack_bin(addr_len);
    pk.pack_bin_body((char*)addr_ptr, addr_len);
}

int
NetworkEngine::send(const char *buf, size_t len, int flags, const SockAddr& addr)
{
    if (addr.second == 0)
        return -1;

    int s;
    if (addr.getFamily() == AF_INET)
        s = dht_socket;
    else if (addr.getFamily() == AF_INET6)
        s = dht_socket6;
    else
        s = -1;

    if (s < 0)
        return -1;
    return sendto(s, buf, len, flags, (const sockaddr*)&addr.first, addr.second);
}

std::shared_ptr<Request>
NetworkEngine::sendPing(std::shared_ptr<Node> node, RequestCb&& on_done, RequestExpiredCb&& on_expired) {
    auto tid = TransId {TransPrefix::PING, getNewTid()};
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

    Blob b {buffer.data(), buffer.data() + buffer.size()};
    std::shared_ptr<Request> req(new Request {tid, node, std::move(b),
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
    });
    sendRequest(req);
    ++out_stats.ping;
    return req;
}

void
NetworkEngine::sendPong(const SockAddr& addr, TransId tid) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("r")); pk.pack_map(2);
      pk.pack(std::string("id")); pk.pack(myid);
      insertAddr(pk, addr);

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    send(buffer.data(), buffer.size(), 0, addr);
}

std::shared_ptr<Request>
NetworkEngine::sendFindNode(std::shared_ptr<Node> n, const InfoHash& target, want_t want,
        RequestCb&& on_done, RequestExpiredCb&& on_expired) {
    auto tid = TransId {TransPrefix::FIND_NODE, getNewTid()};
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

    Blob b {buffer.data(), buffer.data() + buffer.size()};
    std::shared_ptr<Request> req(new Request {tid, n, std::move(b),
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
    });
    sendRequest(req);
    ++out_stats.find;
    return req;
}


std::shared_ptr<Request>
NetworkEngine::sendGetValues(std::shared_ptr<Node> n, const InfoHash& info_hash, const Query& query, want_t want,
        RequestCb&& on_done, RequestExpiredCb&& on_expired) {
    auto tid = TransId {TransPrefix::GET_VALUES, getNewTid()};
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

    Blob b {buffer.data(), buffer.data() + buffer.size()};
    std::shared_ptr<Request> req(new Request {tid, n, std::move(b),
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
    });
    sendRequest(req);
    ++out_stats.get;
    return req;
}

void
NetworkEngine::deserializeNodes(ParsedMessage& msg) {
    if (msg.nodes4_raw.size() % NODE4_INFO_BUF_LEN != 0 || msg.nodes6_raw.size() % NODE6_INFO_BUF_LEN != 0) {
        throw DhtProtocolException {DhtProtocolException::WRONG_NODE_INFO_BUF_LEN};
    } else {
        // deserialize nodes
        const auto& now = scheduler.time();
        SockAddr addr;
        for (unsigned i = 0; i < msg.nodes4_raw.size() / NODE4_INFO_BUF_LEN; i++) {
            uint8_t *ni = msg.nodes4_raw.data() + i * NODE4_INFO_BUF_LEN;
            const InfoHash& ni_id = *reinterpret_cast<InfoHash*>(ni);
            if (ni_id == myid)
                continue;
            auto sin = (sockaddr_in*)&addr.first;
            std::fill_n((uint8_t*)sin, sizeof(sockaddr_in), 0);
            sin->sin_family = AF_INET;
            memcpy(&sin->sin_addr, ni + ni_id.size(), 4);
            memcpy(&sin->sin_port, ni + ni_id.size() + 4, 2);
            addr.second = sizeof(sockaddr_in);
            if (isMartian(addr) || isNodeBlacklisted(addr))
                continue;
            msg.nodes4.emplace_back(cache.getNode(ni_id, addr, now, false));
            onNewNode(msg.nodes4.back(), 0);
        }
        for (unsigned i = 0; i < msg.nodes6_raw.size() / NODE6_INFO_BUF_LEN; i++) {
            uint8_t *ni = msg.nodes6_raw.data() + i * NODE6_INFO_BUF_LEN;
            const InfoHash& ni_id = *reinterpret_cast<InfoHash*>(ni);
            if (ni_id == myid)
                continue;
            auto sin6 = (sockaddr_in6*)&addr.first;
            std::fill_n((uint8_t*)sin6, sizeof(sockaddr_in6), 0);
            sin6->sin6_family = AF_INET6;
            memcpy(&sin6->sin6_addr, ni + HASH_LEN, 16);
            memcpy(&sin6->sin6_port, ni + HASH_LEN + 16, 2);
            addr.second = sizeof(sockaddr_in6);
            if (isMartian(addr) || isNodeBlacklisted(addr))
                continue;
            msg.nodes6.emplace_back(cache.getNode(ni_id, addr, now, false));
            onNewNode(msg.nodes6.back(), 0);
        }
    }
}

std::vector<Blob>
NetworkEngine::packValueHeader(msgpack::sbuffer& buffer, const std::vector<std::shared_ptr<Value>>& st)
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
NetworkEngine::sendValueParts(TransId tid, const std::vector<Blob>& svals, const SockAddr& addr)
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
NetworkEngine::sendNodesValues(const SockAddr& addr, TransId tid, const Blob& nodes, const Blob& nodes6,
        const std::vector<std::shared_ptr<Value>>& st, const Query& query, const Blob& token)
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

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
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
NetworkEngine::bufferNodes(sa_family_t af, const InfoHash& id, std::vector<std::shared_ptr<Node>>& nodes)
{
    std::sort(nodes.begin(), nodes.end(), [&](const std::shared_ptr<Node>& a, const std::shared_ptr<Node>& b){
        return id.xorCmp(a->id, b->id) < 0;
    });
    size_t nnode = std::min<size_t>(SEND_NODES, nodes.size());
    Blob bnodes;
    if (af == AF_INET) {
        bnodes.resize(NODE4_INFO_BUF_LEN * nnode);
        const constexpr size_t size = HASH_LEN + sizeof(in_addr) + sizeof(in_port_t); // 26
        for (size_t i=0; i<nnode; i++) {
            const Node& n = *nodes[i];
            sockaddr_in *sin = (sockaddr_in*)&n.addr.first;
            auto dest = bnodes.data() + size * i;
            memcpy(dest, n.id.data(), HASH_LEN);
            memcpy(dest + HASH_LEN, &sin->sin_addr, sizeof(in_addr));
            memcpy(dest + HASH_LEN + sizeof(in_addr), &sin->sin_port, 2);
        }
    } else if (af == AF_INET6) {
        bnodes.resize(NODE6_INFO_BUF_LEN * nnode);
        const constexpr size_t size = HASH_LEN + sizeof(in6_addr) + sizeof(in_port_t); // 38
        for (size_t i=0; i<nnode; i++) {
            const Node& n = *nodes[i];
            sockaddr_in6 *sin6 = (sockaddr_in6*)&n.addr.first;
            auto dest = bnodes.data() + size * i;
            memcpy(dest, n.id.data(), HASH_LEN);
            memcpy(dest + HASH_LEN, &sin6->sin6_addr, sizeof(in6_addr));
            memcpy(dest + HASH_LEN + sizeof(in6_addr), &sin6->sin6_port, 2);
        }
    }
    return bnodes;
}

std::pair<Blob, Blob>
NetworkEngine::bufferNodes(sa_family_t af, const InfoHash& id, want_t want,
        std::vector<std::shared_ptr<Node>>& nodes4, std::vector<std::shared_ptr<Node>>& nodes6)
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

std::shared_ptr<Request>
NetworkEngine::sendListen(std::shared_ptr<Node> n,
        const InfoHash& hash,
        const Query& query,
        const Blob& token,
        std::shared_ptr<Request> previous,
        RequestCb&& on_done,
        RequestExpiredCb&& on_expired,
        SocketCb&& socket_cb)
{
    std::shared_ptr<Socket> socket;
    auto tid = TransId { TransPrefix::LISTEN, previous ? previous->tid.getTid() : getNewTid() };
    if (previous and previous->node == n) {
        socket = previous->socket;
    } else {
        if (previous)
            DHT_LOG.e(hash, "[node %s] trying refresh listen contract with wrong node", previous->node->toString().c_str());
        /* TODO: Manually creating a socket for "listen" backward compatibility.
         * As soon as this is not an issue anymore, switch to using
         * ::createSocket function! */
        auto sid = TransId {TransPrefix::GET_VALUES, tid.getTid()};
        socket = std::make_shared<Socket>(n, sid, socket_cb);
        opened_sockets.emplace(sid, socket);
    }

    if (not socket) {
        DHT_LOG.e(hash, "[node %s] unable to get a valid socket for listen. Aborting listen", n->toString().c_str());
        return {};
    }

    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(network?1:0));

    auto has_query = query.where.getFilter() or not query.select.getSelection().empty();
    pk.pack(std::string("a")); pk.pack_map(4 + has_query);
      pk.pack(std::string("id"));    pk.pack(myid);
      pk.pack(std::string("h"));     pk.pack(hash);
      pk.pack(std::string("token")); packToken(pk, token);
      pk.pack(std::string("sid"));  pk.pack_bin(socket->id.size());
                                     pk.pack_bin_body((const char*)socket->id.data(), socket->id.size());
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

    Blob b {buffer.data(), buffer.data() + buffer.size()};
    std::shared_ptr<Request> req(new Request {tid, n, std::move(b),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
            if (on_done)
                on_done(req_status, {std::forward<ParsedMessage>(msg)});
        },
        [=](const Request& req_status, bool done) { /* on expired */
            if (on_expired)
                on_expired(req_status, done);
        },
        socket
    });
    sendRequest(req);
    ++out_stats.listen;
    return req;
}

void
NetworkEngine::sendListenConfirmation(const SockAddr& addr, TransId tid) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("r")); pk.pack_map(2);
      pk.pack(std::string("id")); pk.pack(myid);
      insertAddr(pk, addr);

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    send(buffer.data(), buffer.size(), 0, addr);
}

std::shared_ptr<Request>
NetworkEngine::sendAnnounceValue(std::shared_ptr<Node> n,
        const InfoHash& infohash,
        const std::shared_ptr<Value>& value,
        time_point created,
        const Blob& token,
        RequestCb&& on_done,
        RequestExpiredCb&& on_expired)
{
    auto tid = TransId {TransPrefix::ANNOUNCE_VALUES, getNewTid()};
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

    Blob b {buffer.data(), buffer.data() + buffer.size()};
    std::shared_ptr<Request> req(new Request {tid, n, std::move(b),
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
    });
    sendRequest(req);
    if (not v.empty())
        sendValueParts(tid, v, n->addr);
    ++out_stats.put;
    return req;
}

std::shared_ptr<Request>
NetworkEngine::sendRefreshValue(std::shared_ptr<Node> n,
                const InfoHash& infohash,
                const Value::Id& vid,
                const Blob& token,
                RequestCb&& on_done,
                RequestExpiredCb&& on_expired)
{
    auto tid = TransId {TransPrefix::REFRESH, getNewTid()};
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

    Blob b {buffer.data(), buffer.data() + buffer.size()};
    std::shared_ptr<Request> req(new Request {tid, n, std::move(b),
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
    });
    sendRequest(req);
    ++out_stats.refresh;
    return req;

}

void
NetworkEngine::sendValueAnnounced(const SockAddr& addr, TransId tid, Value::Id vid) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("r")); pk.pack_map(3);
      pk.pack(std::string("id"));  pk.pack(myid);
      pk.pack(std::string("vid")); pk.pack(vid);
      insertAddr(pk, addr);

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    send(buffer.data(), buffer.size(), 0, addr);
}

void
NetworkEngine::sendError(const SockAddr& addr,
        TransId tid,
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

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("e"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    send(buffer.data(), buffer.size(), 0, addr);
}

void
ParsedMessage::msgpack_unpack(msgpack::object msg)
{
    auto y = findMapValue(msg, "y");
    auto r = findMapValue(msg, "r");
    auto e = findMapValue(msg, "e");
    auto v = findMapValue(msg, "p");

    if (auto t = findMapValue(msg, "t"))
        tid = {t->as<std::array<char, 4>>()};

    if (auto rv = findMapValue(msg, "v"))
        ua = rv->as<std::string>();

    if (auto netid = findMapValue(msg, "n"))
        network = netid->as<NetId>();

    std::string q;
    if (auto rq = findMapValue(msg, "q")) {
        if (rq->type != msgpack::type::STR)
            throw msgpack::type_error();
        q = rq->as<std::string>();
    }

    if (e)
        type = MessageType::Error;
    else if (r)
        type = MessageType::Reply;
    else if (v)
        type = MessageType::ValueData;
    else if (y and y->as<std::string>() != "q")
        throw msgpack::type_error();
    else if (q == "ping")
        type = MessageType::Ping;
    else if (q == "find")
        type = MessageType::FindNode;
    else if (q == "get")
        type = MessageType::GetValues;
    else if (q == "listen")
        type = MessageType::Listen;
    else if (q == "put")
        type = MessageType::AnnounceValue;
    else if (q == "refresh")
        type = MessageType::Refresh;
    else
        throw msgpack::type_error();

    if (type == MessageType::ValueData) {
        if (v->type != msgpack::type::MAP)
            throw msgpack::type_error();
        for (size_t i = 0; i < v->via.map.size; ++i) {
            auto& vdat = v->via.map.ptr[i];
            auto o = findMapValue(vdat.val, "o");
            auto d = findMapValue(vdat.val, "d");
            if (not o or not d)
                continue;
            value_parts.emplace(vdat.key.as<unsigned>(), std::pair<size_t, Blob>(o->as<size_t>(), unpackBlob(*d)));
        }
        return;
    }

    auto a = findMapValue(msg, "a");
    if (!a && !r && !e)
        throw msgpack::type_error();
    auto& req = a ? *a : (r ? *r : *e);

    if (e) {
        if (e->type != msgpack::type::ARRAY)
            throw msgpack::type_error();
        error_code = e->via.array.ptr[0].as<uint16_t>();
    }

    if (auto t = findMapValue(req, "sid"))
        socket_id = {t->as<std::array<char, 4>>()};

    if (auto rid = findMapValue(req, "id"))
        id = {*rid};

    if (auto rh = findMapValue(req, "h"))
        info_hash = {*rh};

    if (auto rtarget = findMapValue(req, "target"))
        target = {*rtarget};

    if (auto rquery = findMapValue(req, "q"))
        query.msgpack_unpack(*rquery);

    if (auto otoken = findMapValue(req, "token"))
        token = unpackBlob(*otoken);

    if (auto vid = findMapValue(req, "vid"))
        value_id = vid->as<Value::Id>();

    if (auto rnodes4 = findMapValue(req, "n4"))
        nodes4_raw = unpackBlob(*rnodes4);

    if (auto rnodes6 = findMapValue(req, "n6"))
        nodes6_raw = unpackBlob(*rnodes6);

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

    if (auto rcreated = findMapValue(req, "c"))
        created = from_time_t(rcreated->as<std::time_t>());

    if (auto rvalues = findMapValue(req, "values")) {
        if (rvalues->type != msgpack::type::ARRAY)
            throw msgpack::type_error();
        for (size_t i = 0; i < rvalues->via.array.size; i++) {
            auto& packed_v = rvalues->via.array.ptr[i];
            if (packed_v.type == msgpack::type::POSITIVE_INTEGER) {
                // Skip oversize values with a small margin for header overhead
                if (packed_v.via.u64 > MAX_VALUE_SIZE + 32)
                    continue;
                value_parts.emplace(i, std::make_pair(packed_v.via.u64, Blob{}));
            } else {
                try {
                    values.emplace_back(std::make_shared<Value>(rvalues->via.array.ptr[i]));
                } catch (const std::exception& e) {
                    //DHT_LOG_WARN("Error reading value: %s", e.what());
                }
            }
        }
    } else if (auto raw_fields = findMapValue(req, "fields")) {
        if (auto rfields = findMapValue(*raw_fields, "f")) {
            auto vfields = rfields->as<std::set<Value::Field>>();
            if (auto rvalues = findMapValue(*raw_fields, "v")) {
                if (rvalues->type != msgpack::type::ARRAY)
                    throw msgpack::type_error();
                size_t val_num = rvalues->via.array.size / vfields.size();
                for (size_t i = 0; i < val_num; ++i) {
                    try {
                        auto v = std::make_shared<FieldValueIndex>();
                        v->msgpack_unpack_fields(vfields, *rvalues, i*vfields.size());
                        fields.emplace_back(std::move(v));
                    } catch (const std::exception& e) { }
                }
            }
        } else {
            throw msgpack::type_error();
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
}

void
NetworkEngine::maintainRxBuffer(const TransId& tid)
{
    const auto& now = scheduler.time();
    auto msg = partial_messages.find(tid);
    if (msg != partial_messages.end()) {
        if (msg->second.start + RX_MAX_PACKET_TIME < now
         || msg->second.last_part + RX_TIMEOUT < now) {
            DHT_LOG.w("Dropping expired partial message from %s", msg->second.from.toString().c_str());
            partial_messages.erase(msg);
        }
    }
}

bool
ParsedMessage::append(const ParsedMessage& block)
{
    bool ret(false);
    for (const auto& ve : block.value_parts) {
        auto part_val = value_parts.find(ve.first);
        if (part_val == value_parts.end()
            || part_val->second.second.size() >= part_val->second.first)
            continue;
        // TODO: handle out-of-order packets
        if (ve.second.first != part_val->second.second.size()) {
            //std::cout << "skipping out-of-order packet" << std::endl;
            continue;
        }
        ret = true;
        part_val->second.second.insert(part_val->second.second.end(),
                                       ve.second.second.begin(),
                                       ve.second.second.end());
    }
    return ret;
}

bool
ParsedMessage::complete()
{
    for (auto& e : value_parts) {
        //std::cout << "part " << e.first << ": " << e.second.second.size() << "/" << e.second.first << std::endl;
        if (e.second.first > e.second.second.size())
            return false;
    }
    for (auto& e : value_parts) {
        msgpack::unpacked msg;
        msgpack::unpack(msg, (const char*)e.second.second.data(), e.second.second.size());
        values.emplace_back(std::make_shared<Value>(msg.get()));
    }
    return true;
}


} /* namespace net  */
} /* namespace dht */
