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


#include "network_engine.h"
#include "request.h"

#include <msgpack.hpp>

namespace dht {

const std::string DhtProtocolException::GET_NO_INFOHASH {"Get_values with no info_hash"};
const std::string DhtProtocolException::LISTEN_NO_INFOHASH {"Listen with no info_hash"};
const std::string DhtProtocolException::LISTEN_WRONG_TOKEN {"Listen with wrong token"};
const std::string DhtProtocolException::PUT_NO_INFOHASH {"Put with no info_hash"};
const std::string DhtProtocolException::PUT_WRONG_TOKEN {"Put with wrong token"};
const std::string DhtProtocolException::PUT_INVALID_ID {"Put with invalid id"};

constexpr std::chrono::seconds NetworkEngine::UDP_REPLY_TIME;
const std::string NetworkEngine::my_v {"RNG1"};
const constexpr uint16_t NetworkEngine::TransId::INVALID;
std::mt19937 NetworkEngine::rd_device {dht::crypto::random_device{}()};

const NetworkEngine::TransPrefix NetworkEngine::TransPrefix::PING = {"pn"};
const NetworkEngine::TransPrefix NetworkEngine::TransPrefix::FIND_NODE  = {"fn"};
const NetworkEngine::TransPrefix NetworkEngine::TransPrefix::GET_VALUES  = {"gt"};
const NetworkEngine::TransPrefix NetworkEngine::TransPrefix::ANNOUNCE_VALUES  = {"pt"};
const NetworkEngine::TransPrefix NetworkEngine::TransPrefix::LISTEN  = {"lt"};
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
    Listen
};

struct ParsedMessage {
    MessageType type;
    InfoHash id;                                /* the id of the sender */
    NetId network {0};                          /* network id */
    InfoHash info_hash;                         /* hash for which values are requested */
    InfoHash target;                            /* target id around which to find nodes */
    NetworkEngine::TransId tid;                                /* transaction id */
    Blob token;                                 /* security token */
    Value::Id value_id;                         /* the value id */
    time_point created { time_point::max() };   /* time when value was first created */
    Blob nodes4_raw, nodes6_raw;                /* IPv4 nodes in response to a 'find' request */
    std::vector<std::shared_ptr<Node>> nodes4, nodes6;
    std::vector<std::shared_ptr<Value>> values; /* values for a 'get' request */
    want_t want;                                /* states if ipv4 or ipv6 request */
    uint16_t error_code;                        /* error code in case of error */
    std::string ua;
    Address addr;                               /* reported address by the distant node */
    void msgpack_unpack(msgpack::object o);
};

NetworkEngine::RequestAnswer::RequestAnswer(ParsedMessage&& msg)
 : ntoken(std::move(msg.token)), values(std::move(msg.values)), nodes4(std::move(msg.nodes4)), nodes6(std::move(msg.nodes6)) {}

void
NetworkEngine::tellListener(std::shared_ptr<Node> node, uint16_t rid, InfoHash hash, want_t want,
        Blob ntoken, std::vector<std::shared_ptr<Node>> nodes, std::vector<std::shared_ptr<Node>> nodes6,
        std::vector<std::shared_ptr<Value>> values)
{
    auto nnodes = bufferNodes(node->getFamily(), hash, want, nodes, nodes6);
    try {
        sendNodesValues((const sockaddr*)&node->ss, node->sslen, TransId {TransPrefix::GET_VALUES, (uint16_t)rid}, nnodes.first, nnodes.second,
                values, ntoken);
    } catch (const std::overflow_error& e) {
        DHT_LOG.ERR("Can't send value: buffer not large enough !");
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

void
NetworkEngine::cancelRequest(std::shared_ptr<Request>& req)
{
    if (req) {
        req->cancel();
        requests.erase(req->tid);
    }
}

void
NetworkEngine::clear()
{
    for (auto& req : requests)
        req.second->cancel();
    requests.clear();
}

void
NetworkEngine::connectivityChanged()
{
    cache.clearBadNodes();
}

void
NetworkEngine::requestStep(std::shared_ptr<Request> req)
{
    if (not req->pending()) {
        if (req->cancelled())
            requests.erase(req->tid);
        return;
    }

    auto now = scheduler.time();
    if (req->isExpired(now)) {
        DHT_LOG.ERR("[node %s] expired !", req->node->toString().c_str());
        req->node->setExpired();
        requests.erase(req->tid);
        return;
    } else if (req->attempt_count == 1) {
        req->on_expired(*req, false);
    }

    send((char*)req->msg.data(), req->msg.size(),
            (req->node->reply_time >= now - UDP_REPLY_TIME) ? 0 : MSG_CONFIRM,
            (sockaddr*)&req->node->ss, req->node->sslen);
    ++req->attempt_count;
    req->last_try = now;
    std::weak_ptr<Request> wreq = req;
    scheduler.add(req->last_try + Node::MAX_RESPONSE_TIME, [this,wreq]() {
        if (auto req = wreq.lock()) {
            requestStep(req);
        }
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
    if (!e.second) {
        DHT_LOG.ERR("Request already existed !");
    }
    request->node->requested(request);
    requestStep(request);
}


/* Rate control for requests we receive. */
bool
NetworkEngine::rateLimit()
{
    using namespace std::chrono;
    const auto& now = scheduler.time();
    while (not rate_limit_time.empty() and duration_cast<seconds>(now - rate_limit_time.front()) > seconds(1))
        rate_limit_time.pop();

    if (rate_limit_time.size() >= MAX_REQUESTS_PER_SEC)
        return false;

    rate_limit_time.emplace(now);
    return true;
}

bool
NetworkEngine::isMartian(const sockaddr* sa, socklen_t len)
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
    memcpy(&blacklist[next_blacklisted], &n->ss, n->sslen);
    next_blacklisted = (next_blacklisted + 1) % BLACKLISTED_MAX;
}

bool
NetworkEngine::isNodeBlacklisted(const sockaddr *sa, socklen_t salen) const
{
    if (salen > sizeof(sockaddr_storage))
        return true;

    /*if (isBlacklisted(sa, salen))
        return true;*/

    for (unsigned i = 0; i < BLACKLISTED_MAX; i++) {
        if (memcmp(&blacklist[i], sa, salen) == 0)
            return true;
    }

    return false;
}

void
NetworkEngine::processMessage(const uint8_t *buf, size_t buflen, const sockaddr* from, socklen_t fromlen)
{
    if (isMartian(from, fromlen)) {
        DHT_LOG.WARN("Received packet from martian node %s", print_addr(from, fromlen).c_str());
        return;
    }

    if (isNodeBlacklisted(from, fromlen)) {
        DHT_LOG.WARN("Received packet from blacklisted node %s", print_addr(from, fromlen).c_str());
        return;
    }

    ParsedMessage msg;
    try {
        msgpack::unpacked msg_res = msgpack::unpack((const char*)buf, buflen);
        msg.msgpack_unpack(msg_res.get());
        if (msg.type != MessageType::Error && msg.id == zeroes)
            throw DhtException("no or invalid InfoHash");
    } catch (const std::exception& e) {
        DHT_LOG.WARN("Can't process message of size %lu: %s.", buflen, e.what());
        DHT_LOG.DEBUG.logPrintable(buf, buflen);
        return;
    }

    if (msg.network != network) {
        DHT_LOG.DEBUG("Received message from other network %u.", msg.network);
        return;
    }

    if (msg.id == myid || msg.id == zeroes) {
        DHT_LOG.DEBUG("Received message from self.");
        return;
    }

    if (msg.type > MessageType::Reply) {
        /* Rate limit requests. */
        if (!rateLimit()) {
            DHT_LOG.WARN("Dropping request due to rate limiting.");
            return;
        }
    }

    const auto& now = scheduler.time();

    if (msg.tid.length != 4) {
        DHT_LOG.ERR("Broken node truncates transaction ids (len: %d): ", msg.tid.length);
        DHT_LOG.ERR.logPrintable(buf, buflen);
        blacklistNode(cache.getNode(msg.id, from, fromlen, now, 1));
        return;
    }

    uint16_t ttid = 0;
    if (msg.type == MessageType::Error or msg.type == MessageType::Reply) {
        auto reqp = requests.find(msg.tid.getTid());
        if (reqp == requests.end()) {
            throw DhtProtocolException {DhtProtocolException::UNKNOWN_TID, "Can't find transaction", msg.id};
        }
        auto req = reqp->second;

        auto node = req->node;
        if (node->id != msg.id) {
            bool unknown_node = node->id == zeroes;
            node = cache.getNode(msg.id, from, fromlen, now, 2);
            if (unknown_node) {
                // received reply to a message sent when we didn't know the node ID.
                req->node = node;
            } else {
                // received reply from unexpected node
                node->received(now, req);
                onNewNode(node, 2);
                DHT_LOG.WARN("Message received from unexpected ndoe %s", node->toString().c_str());
                return;
            }
        } else
            node->update(from, fromlen);
        node->received(now, req);

        onNewNode(node, 2);
        onReportedAddr(msg.id, (sockaddr*)&msg.addr.first, msg.addr.second);

        if (req->cancelled() or req->expired() or (req->completed() and not req->persistent)) {
            DHT_LOG.WARN("[node %s] response to expired, cancelled or completed request", node->toString().c_str());
            requests.erase(reqp);
            return;
        }

        switch (msg.type) {
        case MessageType::Error: {
            if (msg.error_code == DhtProtocolException::UNAUTHORIZED
                    && msg.id != zeroes
                    && (msg.tid.matches(TransPrefix::ANNOUNCE_VALUES, &ttid)
                    || msg.tid.matches(TransPrefix::LISTEN, &ttid)))
            {
                req->last_try = TIME_INVALID;
                req->reply_time = TIME_INVALID;
                onError(req, DhtProtocolException {DhtProtocolException::UNAUTHORIZED});
            } else {
                DHT_LOG.WARN("[node %s %s] received unknown error message %u",
                        msg.id.toString().c_str(), print_addr(from, fromlen).c_str(), msg.error_code);
                DHT_LOG.WARN.logPrintable(buf, buflen);
            }
            break;
        }
        case MessageType::Reply:
            // erase before calling callback to make sure iterator is still valid
            if (not req->persistent)
                requests.erase(reqp);
            req->reply_time = scheduler.time();

            deserializeNodesValues(msg);
            req->setDone(std::move(msg));
            break;
        default:
            break;
        }
    } else {
        auto node = cache.getNode(msg.id, from, fromlen, now, 1);
        node->received(now, {});
        onNewNode(node, 1);
        try {
            switch (msg.type) {
            case MessageType::Ping:
                ++in_stats.ping;
                DHT_LOG.DEBUG("Sending pong.");
                onPing(node);
                sendPong(from, fromlen, msg.tid);
                break;
            case MessageType::FindNode: {
                DHT_LOG.DEBUG("[node %s %s] got 'find' request (%d).",
                        msg.id.toString().c_str(), print_addr(from, fromlen).c_str(), msg.want);
                ++in_stats.find;
                RequestAnswer answer = onFindNode(node, msg.target, msg.want);
                auto nnodes = bufferNodes(from->sa_family, msg.target, msg.want, answer.nodes4, answer.nodes6);
                sendNodesValues(from, fromlen, msg.tid, nnodes.first, nnodes.second, {}, answer.ntoken);
                break;
            }
            case MessageType::GetValues: {
                DHT_LOG.DEBUG("[node %s %s] got 'get' request for %s.",
                        msg.id.toString().c_str(), print_addr(from, fromlen).c_str(), msg.info_hash.toString().c_str());
                ++in_stats.get;
                RequestAnswer answer = onGetValues(node, msg.info_hash, msg.want);
                auto nnodes = bufferNodes(from->sa_family, msg.info_hash, msg.want, answer.nodes4, answer.nodes6);
                sendNodesValues(from, fromlen, msg.tid, nnodes.first, nnodes.second, answer.values, answer.ntoken);
                break;
            }
            case MessageType::AnnounceValue: {
                DHT_LOG.DEBUG("[node %s %s] got 'put' request for %s.",
                    msg.id.toString().c_str(), print_addr(from, fromlen).c_str(),
                    msg.info_hash.toString().c_str());
                ++in_stats.put;
                onAnnounce(node, msg.info_hash, msg.token, msg.values, msg.created);

                /* Note that if storageStore failed, we lie to the requestor.
                   This is to prevent them from backtracking, and hence
                   polluting the DHT. */
                for (auto& v : msg.values) {
                   sendValueAnnounced(from, fromlen, msg.tid, v->id);
                }
                break;
            }
            case MessageType::Listen: {
                DHT_LOG.DEBUG("[node %s %s] got 'listen' request for %s.",
                        msg.id.toString().c_str(), print_addr(from, fromlen).c_str(), msg.info_hash.toString().c_str());
                ++in_stats.listen;
                RequestAnswer answer = onListen(node, msg.info_hash, msg.token, msg.tid.getTid());
                sendListenConfirmation(from, fromlen, msg.tid);
                break;
            }
            default:
                break;
            }
        } catch (const std::overflow_error& e) {
            DHT_LOG.ERR("Can't send value: buffer not large enough !");
        } catch (DhtProtocolException& e) {
            sendError(from, fromlen, msg.tid, e.getCode(), e.getMsg().c_str(), true);
        }
    }
}

void
packToken(msgpack::packer<msgpack::sbuffer>& pk, Blob token)
{
    pk.pack_bin(token.size());
    pk.pack_bin_body((char*)token.data(), token.size());
}

void
insertAddr(msgpack::packer<msgpack::sbuffer>& pk, const sockaddr *sa, socklen_t sa_len)
{
    size_t addr_len = std::min<size_t>(sa_len,
                     (sa->sa_family == AF_INET) ? sizeof(in_addr) : sizeof(in6_addr));
    void* addr_ptr = (sa->sa_family == AF_INET) ? (void*)&((sockaddr_in*)sa)->sin_addr
                                                : (void*)&((sockaddr_in6*)sa)->sin6_addr;
    pk.pack("sa");
    pk.pack_bin(addr_len);
    pk.pack_bin_body((char*)addr_ptr, addr_len);
}

int
NetworkEngine::send(const char *buf, size_t len, int flags, const sockaddr *sa, socklen_t salen)
{
    if (salen == 0)
        return -1;

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

std::shared_ptr<Request>
NetworkEngine::sendPing(std::shared_ptr<Node> node, RequestCb on_done, RequestExpiredCb on_expired) {
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
    std::shared_ptr<Request> req(new Request {tid.getTid(), node, std::move(b),
        [=](const Request& req_status, ParsedMessage&&) {
            DHT_LOG.DEBUG("Got pong from %s", req_status.node->toString().c_str());
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
NetworkEngine::sendPong(const sockaddr* sa, socklen_t salen, TransId tid) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("r")); pk.pack_map(2);
      pk.pack(std::string("id")); pk.pack(myid);
      insertAddr(pk, sa, salen);

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    send(buffer.data(), buffer.size(), 0, sa, salen);
}

std::shared_ptr<Request>
NetworkEngine::sendFindNode(std::shared_ptr<Node> n, const InfoHash& target, want_t want,
        RequestCb on_done, RequestExpiredCb on_expired) {
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
    std::shared_ptr<Request> req(new Request {tid.getTid(), n, std::move(b),
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
NetworkEngine::sendGetValues(std::shared_ptr<Node> n, const InfoHash& info_hash, want_t want,
        RequestCb on_done, RequestExpiredCb on_expired) {
    auto tid = TransId {TransPrefix::GET_VALUES, getNewTid()};
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(network?1:0));

    pk.pack(std::string("a"));  pk.pack_map(2 + (want>0?1:0));
      pk.pack(std::string("id")); pk.pack(myid);
      pk.pack(std::string("h"));  pk.pack(info_hash);
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
    std::shared_ptr<Request> req(new Request {tid.getTid(), n, std::move(b),
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
NetworkEngine::deserializeNodesValues(ParsedMessage& msg) {
    if (msg.nodes4_raw.size() % NODE4_INFO_BUF_LEN != 0 || msg.nodes6_raw.size() % NODE6_INFO_BUF_LEN != 0) {
        throw DhtProtocolException {DhtProtocolException::WRONG_NODE_INFO_BUF_LEN};
    } else {
        // deserialize nodes
        const auto& now = scheduler.time();
        for (unsigned i = 0; i < msg.nodes4_raw.size() / NODE4_INFO_BUF_LEN; i++) {
            uint8_t *ni = msg.nodes4_raw.data() + i * NODE4_INFO_BUF_LEN;
            const InfoHash& ni_id = *reinterpret_cast<InfoHash*>(ni);
            if (ni_id == myid)
                continue;
            sockaddr_in sin;
            std::fill_n((uint8_t*)&sin, sizeof(sockaddr_in), 0);
            sin.sin_family = AF_INET;
            memcpy(&sin.sin_addr, ni + ni_id.size(), 4);
            memcpy(&sin.sin_port, ni + ni_id.size() + 4, 2);
            if (isMartian((sockaddr*)&sin, sizeof(sin)) || isNodeBlacklisted((sockaddr*)&sin, sizeof(sin)))
                continue;
            msg.nodes4.emplace_back(cache.getNode(ni_id, (sockaddr*)&sin, sizeof(sin), now, 0));
            onNewNode(msg.nodes4.back(), 0);
        }
        for (unsigned i = 0; i < msg.nodes6_raw.size() / NODE6_INFO_BUF_LEN; i++) {
            uint8_t *ni = msg.nodes6_raw.data() + i * NODE6_INFO_BUF_LEN;
            const InfoHash& ni_id = *reinterpret_cast<InfoHash*>(ni);
            if (ni_id == myid)
                continue;
            sockaddr_in6 sin6;
            std::fill_n((uint8_t*)&sin6, sizeof(sockaddr_in6), 0);
            sin6.sin6_family = AF_INET6;
            memcpy(&sin6.sin6_addr, ni + HASH_LEN, 16);
            memcpy(&sin6.sin6_port, ni + HASH_LEN + 16, 2);
            if (isMartian((sockaddr*)&sin6, sizeof(sin6)) || isNodeBlacklisted((sockaddr*)&sin6, sizeof(sin6)))
                continue;
            msg.nodes6.emplace_back(cache.getNode(ni_id, (sockaddr*)&sin6, sizeof(sin6), now, 0));
            onNewNode(msg.nodes6.back(), 0);
        }
    }
}

void
NetworkEngine::sendNodesValues(const sockaddr* sa, socklen_t salen, TransId tid, const Blob& nodes, const Blob& nodes6,
        const std::vector<std::shared_ptr<Value>>& st, const Blob& token) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("r"));
    pk.pack_map(2 + (not st.empty()?1:0) + (nodes.size()>0?1:0) + (nodes6.size()>0?1:0) + (not token.empty()?1:0));
    pk.pack(std::string("id")); pk.pack(myid);
    insertAddr(pk, sa, salen);
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
    if (not st.empty()) {
        // We treat the storage as a circular list, and serve a randomly
        // chosen slice.  In order to make sure we fit,
        // we limit ourselves to 50 values.
        std::uniform_int_distribution<> pos_dis(0, st.size()-1);
        std::vector<Blob> subset {};
        subset.reserve(std::min<size_t>(st.size(), 50));

        size_t total_size = 0;
        unsigned j0 = pos_dis(rd_device);
        unsigned j = j0;
        unsigned k = 0;

        do {
            subset.emplace_back(packMsg(st[j]));
            total_size += subset.back().size();
            ++k;
            j = (j + 1) % st.size();
        } while (j != j0 && k < 50 && total_size < MAX_VALUE_SIZE);

        pk.pack(std::string("values"));
        pk.pack_array(subset.size());
        for (const auto& b : subset)
            buffer.write((const char*)b.data(), b.size());
        DHT_LOG.DEBUG("sending closest nodes (%d+%d nodes.), %lu bytes of values", nodes.size(), nodes6.size(), total_size);
    } else
        DHT_LOG.DEBUG("sending closest nodes (%d+%d nodes.)", nodes.size(), nodes6.size());

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    send(buffer.data(), buffer.size(), 0, sa, salen);
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
            sockaddr_in *sin = (sockaddr_in*)&n.ss;
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
            sockaddr_in6 *sin6 = (sockaddr_in6*)&n.ss;
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
NetworkEngine::sendListen(std::shared_ptr<Node> n, const InfoHash& infohash, const Blob& token,
        RequestCb on_done, RequestExpiredCb on_expired) {
    auto tid = TransId {TransPrefix::LISTEN, getNewTid()};
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(network?1:0));

    pk.pack(std::string("a")); pk.pack_map(3);
      pk.pack(std::string("id"));    pk.pack(myid);
      pk.pack(std::string("h"));     pk.pack(infohash);
      pk.pack(std::string("token")); packToken(pk, token);

    pk.pack(std::string("q")); pk.pack(std::string("listen"));
    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("q"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    Blob b {buffer.data(), buffer.data() + buffer.size()};
    std::shared_ptr<Request> req(new Request {tid.getTid(), n, std::move(b),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
            if (on_done)
                on_done(req_status, {std::forward<ParsedMessage>(msg)});
        },
        [=](const Request& req_status, bool done) { /* on expired */
            if (on_expired)
                on_expired(req_status, done);
        },
        true
    });
    sendRequest(req);
    ++out_stats.listen;
    return req;
}

void
NetworkEngine::sendListenConfirmation(const sockaddr* sa, socklen_t salen, TransId tid) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("r")); pk.pack_map(2);
      pk.pack(std::string("id")); pk.pack(myid);
      insertAddr(pk, sa, salen);

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    send(buffer.data(), buffer.size(), 0, sa, salen);
}

std::shared_ptr<Request>
NetworkEngine::sendAnnounceValue(std::shared_ptr<Node> n, const InfoHash& infohash, const Value& value, time_point created,
        const Blob& token, RequestCb on_done, RequestExpiredCb on_expired) {
    auto tid = TransId {TransPrefix::ANNOUNCE_VALUES, getNewTid()};
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5+(network?1:0));

    pk.pack(std::string("a")); pk.pack_map((created < scheduler.time() ? 5 : 4));
      pk.pack(std::string("id"));     pk.pack(myid);
      pk.pack(std::string("h"));      pk.pack(infohash);
      pk.pack(std::string("values")); pk.pack_array(1); pk.pack(value);
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
    std::shared_ptr<Request> req(new Request {tid.getTid(), n, std::move(b),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
            if (msg.value_id == Value::INVALID_ID) {
                DHT_LOG.DEBUG("Unknown search or announce!");
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
    ++out_stats.put;
    return req;
}

void
NetworkEngine::sendValueAnnounced(const sockaddr* sa, socklen_t salen, TransId tid, Value::Id vid) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4+(network?1:0));

    pk.pack(std::string("r")); pk.pack_map(3);
      pk.pack(std::string("id"));  pk.pack(myid);
      pk.pack(std::string("vid")); pk.pack(vid);
      insertAddr(pk, sa, salen);

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);
    if (network) {
        pk.pack(std::string("n")); pk.pack(network);
    }

    send(buffer.data(), buffer.size(), 0, sa, salen);
}

void
NetworkEngine::sendError(const sockaddr* sa,
        socklen_t salen,
        TransId tid,
        uint16_t code,
        const std::string& message,
        bool include_id) {
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

    send(buffer.data(), buffer.size(), 0, sa, salen);
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
ParsedMessage::msgpack_unpack(msgpack::object msg)
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

    if (!a && !r && !e)
        throw msgpack::type_error();
    auto& req = a ? *a : (r ? *r : *e);

    if (e) {
        if (e->type != msgpack::type::ARRAY)
            throw msgpack::type_error();
        error_code = e->via.array.ptr[0].as<uint16_t>();
    }

    if (auto netid = findMapValue(msg, "n"))
        network = netid->as<NetId>();

    if (auto rid = findMapValue(req, "id"))
        id = {*rid};

    if (auto rh = findMapValue(req, "h"))
        info_hash = {*rh};

    if (auto rtarget = findMapValue(req, "target"))
        target = {*rtarget};

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
        for (size_t i = 0; i < rvalues->via.array.size; i++)
            try {
                values.emplace_back(std::make_shared<Value>(rvalues->via.array.ptr[i]));
            } catch (const std::exception& e) {
                //DHT_LOG.WARN("Error reading value: %s", e.what());
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
