// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "network_engine.h"
#include "request.h"
#include "default_types.h"
#include "logger.h"
#include "parsed_message.h"

#include <msgpack.hpp>
#include <chrono>
#include <string_view>

namespace dht {
namespace net {
using namespace std::chrono_literals;

const std::string DhtProtocolException::GET_NO_INFOHASH {"Get_values with no info_hash"};
const std::string DhtProtocolException::LISTEN_NO_INFOHASH {"Listen with no info_hash"};
const std::string DhtProtocolException::LISTEN_WRONG_TOKEN {"Listen with incorrect token"};
const std::string DhtProtocolException::PUT_NO_INFOHASH {"Put with no info_hash"};
const std::string DhtProtocolException::PUT_WRONG_TOKEN {"Put with incorrect token"};
const std::string DhtProtocolException::PUT_INVALID_ID {"Put with invalid ID"};
const std::string DhtProtocolException::STORAGE_NOT_FOUND {"Access operation for unknown storage"};

constexpr std::chrono::seconds NetworkEngine::UDP_REPLY_TIME;
constexpr std::chrono::seconds NetworkEngine::RX_MAX_PACKET_TIME;
constexpr std::chrono::seconds NetworkEngine::RX_TIMEOUT;

/* OpenDHT User Agent (UA) */
constexpr std::string_view OPENDHT_UA {"o2"};

static constexpr uint8_t v4prefix[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0};

constexpr unsigned SEND_NODES {8};

struct NetworkEngine::PartialMessage
{
    SockAddr from;
    time_point start;
    time_point last_part;
    std::unique_ptr<ParsedMessage> msg;
    std::vector<std::unique_ptr<ParsedMessage>> early_parts;
    size_t early_bytes {};
    bool request_quota_consumed {};
    /* parts are all plaintext, or all in envelopes from this sender key */
    bool encrypted {};
    transport::Key key {};

    void bind(const ParsedMessage& part)
    {
        encrypted = part.encrypted;
        if (encrypted)
            key = part.peer->key;
    }
    bool accepts(const ParsedMessage& part) const
    {
        return encrypted == part.encrypted and (not encrypted or (part.peer and key == part.peer->key));
    }
};

/* Value data fragments carry no node ID: parts are bound to the envelope state of the first one.
 * Plaintext from a spoofed address can be forged by anyone, so an encrypted part replaces it. */
bool
NetworkEngine::acceptsPart(std::map<PartialMessageKey, PartialMessage>::iterator& it, const ParsedMessage& part)
{
    if (it == partial_messages.end() or it->second.accepts(part))
        return true;
    if (not part.encrypted or it->second.encrypted)
        return false;
    partial_messages.erase(it);
    it = partial_messages.end();
    return true;
}

bool
NetworkEngine::isExpectedReply(const ParsedMessage& msg, const SockAddr& from)
{
    auto request = requests.find(msg.tid);
    if (request != requests.end() && request->second->pending() && !request->second->node->id
        && request->second->node->getAddr() == from)
        return true;

    auto node = cache.getNode(msg.id, from.getFamily());
    if (!node || node->getAddr() != from)
        return false;

    auto pending = node->getRequest(msg.tid);
    return (pending && pending->pending()) || node->getSocket(msg.tid);
}

bool
NetworkEngine::tryCompleteMessage(PartialMessage& partial, const SockAddr& from)
{
    try {
        if (!partial.msg->complete())
            return false;
        process(std::move(partial.msg), from);
    } catch (const std::exception& e) {
        if (logger_)
            logger_->warn("Error while processing partial message: {}", e.what());
    } catch (...) {
        if (logger_)
            logger_->warn("Unknown error while processing partial message");
    }
    return true;
}

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
    pk.pack_bin_body((char*) token.data(), token.size());
}

RequestAnswer::RequestAnswer(ParsedMessage&& msg)
    : values(std::move(msg.values))
    , refreshed_values(std::move(msg.refreshed_values))
    , expired_values(std::move(msg.expired_values))
    , fields(std::move(msg.fields))
    , nodes4(std::move(msg.nodes4))
    , nodes6(std::move(msg.nodes6))
{
    if (msg.encrypted)
        ntoken.emplace();
    else if (not msg.token.empty())
        ntoken = std::move(msg.token);
}

NetworkEngine::NetworkEngine(InfoHash& myid,
                             NetworkConfig c,
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
                             decltype(NetworkEngine::onRefresh)&& onRefresh)
    : onError(std::move(onError))
    , onNewNode(std::move(onNewNode))
    , onReportedAddr(std::move(onReportedAddr))
    , onPing(std::move(onPing))
    , onFindNode(std::move(onFindNode))
    , onGetValues(std::move(onGetValues))
    , onListen(std::move(onListen))
    , onAnnounce(std::move(onAnnounce))
    , onRefresh(std::move(onRefresh))
    , myid(myid)
    , config(c)
    , transport_(config.transport.enabled and config.transport.key)
    , credential_(transport_ and config.transport.isPrivate() ? config.transport.credential.pack() : Blob {})
    , dht_socket(std::move(sock))
    , logger_(log)
    , rd(rand)
    , cache(rd)
    , rate_limiter(config.max_req_per_sec)
    , scheduler(scheduler)
{
    epoch_.secret = transport::randomSecret();
    epochRotation_ = scheduler.add(scheduler.time() + EPOCH_DURATION, std::bind(&NetworkEngine::rotateEpoch, this));
}

NetworkEngine::~NetworkEngine()
{
    clear();
    scheduler.cancel(epochRotation_);
    epoch_.wipe();
    previousEpoch_.wipe();
}

void
NetworkEngine::tellListener(const Sp<Node>& node,
                            Tid socket_id,
                            const InfoHash& hash,
                            want_t want,
                            std::vector<Sp<Node>>&& nodes,
                            std::vector<Sp<Node>>&& nodes6,
                            std::vector<Sp<Value>>&& values,
                            const Query& query,
                            int version)
{
    auto nnodes = bufferNodes(node->getFamily(), hash, want, nodes, nodes6);
    auto ntoken = writeToken(*node);
    try {
        if (version >= 1) {
            sendUpdateValues(node, hash, std::move(values), scheduler.time(), ntoken, socket_id);
        } else {
            sendNodesValues(*node, node->getAddr(), socket_id, nnodes, std::move(values), query, ntoken);
        }
    } catch (const std::overflow_error& e) {
        if (logger_)
            logger_->error("Unable to send value: buffer not large enough.");
    }
}

void
NetworkEngine::tellListenerRefreshed(const Sp<Node>& n,
                                     Tid socket_id,
                                     const InfoHash&,
                                     const std::vector<Value::Id>& values,
                                     int version)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(*n);
    auto token = writeToken(*n);

    pk.pack_map(4 + (version >= 1 ? 1 : 0) + optionalFields(advertise));

    pk.pack(version >= 1 ? KEY_A : KEY_U);
    pk.pack_map(1 + (version >= 1 ? 1 : 0) + (not values.empty() ? 1 : 0) + (not token.empty() ? 1 : 0));
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);
    if (version >= 1) {
        pk.pack(KEY_REQ_SID);
        pk.pack(socket_id);
    }
    if (not token.empty()) {
        pk.pack(KEY_REQ_TOKEN);
        packToken(pk, token);
    }
    if (not values.empty()) {
        pk.pack(KEY_REQ_REFRESHED);
        pk.pack(values);
        if (logger_)
            logger_->debug("[node {}] sending {} refreshed values", n->toString(), values.size());
    }

    pk.pack(KEY_Y);
    pk.pack(version >= 1 ? KEY_Q : KEY_R);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    if (version >= 1) {
        Tid tid(n->getNewTid());

        pk.pack(KEY_Q);
        pk.pack(QUERY_UPDATE);
        pk.pack(KEY_TID);
        pk.pack(tid);

        auto req = std::make_shared<Request>(
            MessageType::UpdateValue,
            tid,
            n,
            Blob(buffer.data(), buffer.data() + buffer.size()),
            [=](const Request&, ParsedMessage&&) { /* on done */ },
            [=](const Request&, bool) { /* on expired */ });
        sendRequest(req);
        ++out_stats.updateValue;
        return;
    }
    pk.pack(KEY_TID);
    pk.pack(socket_id);

    // send response
    send(*n, n->getAddr(), buffer.data(), buffer.size());
}

void
NetworkEngine::tellListenerExpired(const Sp<Node>& n,
                                   Tid socket_id,
                                   const InfoHash&,
                                   const std::vector<Value::Id>& values,
                                   int version)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(*n);
    auto token = writeToken(*n);

    pk.pack_map(4 + (version >= 1 ? 1 : 0) + optionalFields(advertise));

    pk.pack(version >= 1 ? KEY_A : KEY_U);
    pk.pack_map(1 + (version >= 1 ? 1 : 0) + (not values.empty() ? 1 : 0) + (not token.empty() ? 1 : 0));
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);
    if (version >= 1) {
        pk.pack(KEY_REQ_SID);
        pk.pack(socket_id);
    }
    if (not token.empty()) {
        pk.pack(KEY_REQ_TOKEN);
        packToken(pk, token);
    }
    if (not values.empty()) {
        pk.pack(KEY_REQ_EXPIRED);
        pk.pack(values);
        if (logger_)
            logger_->debug("[node {}] sending {} expired values", n->toString(), values.size());
    }

    pk.pack(KEY_Y);
    pk.pack(version >= 1 ? KEY_Q : KEY_R);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    if (version >= 1) {
        Tid tid(n->getNewTid());

        pk.pack(KEY_Q);
        pk.pack(QUERY_UPDATE);
        pk.pack(KEY_TID);
        pk.pack(tid);

        auto req = std::make_shared<Request>(
            MessageType::UpdateValue,
            tid,
            n,
            Blob(buffer.data(), buffer.data() + buffer.size()),
            [=](const Request&, ParsedMessage&&) { /* on done */ },
            [=](const Request&, bool) { /* on expired */ });
        sendRequest(req);
        ++out_stats.updateValue;
        return;
    }
    pk.pack(KEY_TID);
    pk.pack(socket_id);

    // send response
    send(*n, n->getAddr(), buffer.data(), buffer.size());
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
    partial_messages.clear();
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
        //     logger_->d(node.id, "[node %s] expired.", node.toString().c_str());
        node.setExpired();
        if (not node.id)
            requests.erase(req.tid);
        return;
    } else if (req.attempt_count == 1) {
        if (req.on_expired)
            req.on_expired(req, false);
        // The peer may have lost our session or credential: start a new one
        if (const auto& peer = node.getTransport(); peer and peer->ephemeral) {
            peer->resetEphemeral();
            peer->recovering = true;
        }
    }
    const auto& peer = node.getTransport();
    req.initial = peer and not peer->ephemeral;
    // After the first contact, payloads stay out of Initial envelopes: a later compromise of the receiver key reveals them
    req.withheld = peer and peer->recovering and req.type != MessageType::Ping;
    if (req.withheld)
        recoverSession(req.node);

    auto err = req.withheld ? 0
                            : send(node,
                                   node.getAddr(),
                                   (char*) req.msg.data(),
                                   req.msg.size(),
                                   node.getReplyTime() < now - UDP_REPLY_TIME);
    if (err == ENETUNREACH || err == EHOSTUNREACH || err == EAFNOSUPPORT || err == EPIPE || err == EPERM) {
        node.setExpired();
        if (not node.id)
            requests.erase(req.tid);
    } else {
        req.last_try = now;
        if (err != EAGAIN) {
            ++req.attempt_count;
            req.attempt_duration += req.attempt_duration
                                    + uniform_duration_distribution<>(0ms, ((duration) Node::MAX_RESPONSE_TIME) / 4)(rd);
            if (not req.withheld and not req.parts.empty()) {
                sendValueParts(req.tid, req.parts, node, node.getAddr());
            }
        }
        std::weak_ptr<Request> wreq = sreq;
        scheduler.add(req.last_try + req.attempt_duration, [this, wreq] {
            if (auto req = wreq.lock())
                requestStep(req);
        });
    }
}

void
NetworkEngine::recoverSession(const Sp<Node>& node)
{
    for (const auto& [tid, req] : node->getRequests())
        if (req->type == MessageType::Ping and req->pending())
            return;
    sendPing(node, {}, {});
}

void
NetworkEngine::resumeRequests(Node& node)
{
    for (const auto& [tid, req] : node.getRequests()) {
        if (not req->withheld or not req->pending())
            continue;
        req->withheld = false;
        req->initial = false;
        if (send(node, node.getAddr(), (char*) req->msg.data(), req->msg.size()) == 0 and not req->parts.empty())
            sendValueParts(req->tid, req->parts, node, node.getAddr());
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
            or address_rate_limiter.emplace(addr, config.max_peer_req_per_sec).first->second.limit(now))
           and rate_limiter.limit(now);
}

bool
NetworkEngine::isMartian(const SockAddr& addr)
{
    if (addr.getPort() == 0)
        return true;
    switch (addr.getFamily()) {
    case AF_INET: {
        const auto& sin = addr.getIPv4();
        const uint8_t* address = (const uint8_t*) &sin.sin_addr;
        return (address[0] == 0) || ((address[0] & 0xE0) == 0xE0);
    }
    case AF_INET6: {
        if (addr.getLength() < sizeof(sockaddr_in6))
            return true;
        const auto& sin6 = addr.getIPv6();
        const uint8_t* address = (const uint8_t*) &sin6.sin6_addr;
        return address[0] == 0xFF || memcmp(address, InfoHash::zero().data(), 16) == 0
               || memcmp(address, v4prefix, 12) == 0;
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
NetworkEngine::processMessage(const uint8_t* buf, size_t buflen, SockAddr f)
{
    auto from = f.getMappedIPv4();
    if (isMartian(from)) {
        if (logger_)
            logger_->warn("Received packet from martian node {}", from.toString());
        return;
    }

    if (isNodeBlacklisted(from)) {
        if (logger_)
            logger_->warn("Received packet from blacklisted node {}", from.toString());
        return;
    }

    std::optional<OpenedEnvelope> envelope;
    if (transport::isEnvelope(buf, buflen)) {
        if (not transport_)
            return;
        envelope = openEnvelope(buf, buflen, from);
        if (not envelope)
            return;
        buf = envelope->payload.data();
        buflen = envelope->payload.size();
    } else if (transport_ and config.transport.isPrivate()) {
        return;
    }

    auto msg = std::make_unique<ParsedMessage>();
    try {
        msgpack::unpacked msg_res = msgpack::unpack((const char*) buf, buflen);
        msg->msgpack_unpack(msg_res.get());
    } catch (const std::exception& e) {
        if (logger_)
            logger_->warn("Unable to parse message of size {}: {}", buflen, e.what());
        // if (logger_)
        //     logger_->DBG.logPrintable(buf, buflen);
        return;
    }

    if (msg->network != config.network) {
        if (logger_)
            logger_->debug("Received message from other config.network {}", msg->network);
        return;
    }

    if (envelope) {
        // value fragments carry no node ID
        if (msg->type != MessageType::ValueData and msg->id != transport::nodeId(envelope->peer->key)) {
            if (logger_)
                logger_->warn("Dropping encrypted message from {}: node ID doesn't match its key", from.toString());
            return;
        }
        if (envelope->hello) {
            processHello(*msg, envelope->peer, from);
            return;
        }
        msg->peer = std::move(envelope->peer);
        msg->encrypted = true;
        msg->session = envelope->session;
    } else if (transport_ and msg->transport_key) {
        msg->peer = makePeer(msg->id, *msg->transport_key);
    }

    const auto& now = scheduler.time();

    // partial value data
    if (msg->type == MessageType::ValueData) {
        if (msg->fragment_parts.empty()
            || std::any_of(msg->fragment_parts.begin(), msg->fragment_parts.end(), [](const auto& fragment) {
                   return fragment.second.second.empty();
               })) {
            rateLimit(from);
            return;
        }
        PartialMessageKey key {from, msg->tid};
        auto pmsg_it = partial_messages.find(key);
        if (not acceptsPart(pmsg_it, *msg))
            return;
        if (pmsg_it == partial_messages.end()) {
            if (!rateLimit(from))
                return;
            auto inserted = partial_messages.emplace(key, PartialMessage {});
            pmsg_it = inserted.first;
            pmsg_it->second.from = from;
            pmsg_it->second.start = now;
            pmsg_it->second.last_part = now;
            pmsg_it->second.request_quota_consumed = true;
            pmsg_it->second.bind(*msg);
            scheduler.add(now + RX_MAX_PACKET_TIME, std::bind(&NetworkEngine::maintainRxBuffer, this, key));
        }
        auto& pmsg = pmsg_it->second;
        if (!pmsg.msg) {
            if (pmsg.early_parts.size() >= RX_MAX_EARLY_PARTS) {
                partial_messages.erase(pmsg_it);
                return;
            }
            size_t fragment_bytes {};
            for (const auto& [index, fragment] : msg->fragment_parts) {
                (void) index;
                if (fragment.second.size() > RX_MAX_EARLY_BYTES - fragment_bytes) {
                    partial_messages.erase(pmsg_it);
                    return;
                }
                fragment_bytes += fragment.second.size();
            }
            if (fragment_bytes > RX_MAX_EARLY_BYTES - pmsg.early_bytes) {
                partial_messages.erase(pmsg_it);
                return;
            }
            pmsg.early_bytes += fragment_bytes;
            pmsg.early_parts.emplace_back(std::move(msg));
            pmsg.last_part = now;
            scheduler.add(now + RX_TIMEOUT, std::bind(&NetworkEngine::maintainRxBuffer, this, key));
            return;
        }
        // append data block
        if (pmsg.msg->append(*msg)) {
            pmsg.last_part = now;
            if (tryCompleteMessage(pmsg, from)) {
                partial_messages.erase(pmsg_it);
            } else
                scheduler.add(now + RX_TIMEOUT, std::bind(&NetworkEngine::maintainRxBuffer, this, key));
        }
        return;
    }

    if (msg->id == myid or not msg->id) {
        if (logger_)
            logger_->debug("Received message from self");
        return;
    }

    if (msg->value_parts.empty()) {
        if (msg->type > MessageType::Reply) {
            /* Rate limit requests. */
            if (!rateLimit(from)) {
                if (logger_)
                    logger_->warn("Dropping request due to rate limiting");
                return;
            }
        }
        try {
            process(std::move(msg), from);
        } catch (const std::exception& e) {
            if (logger_)
                logger_->warn("Error while processing message: {}", e.what());
        }
        return;
    }

    PartialMessageKey partial_key {from, msg->tid};
    if (msg->type == MessageType::Reply && !isExpectedReply(*msg, from))
        return;

    auto partial = partial_messages.find(partial_key);
    if (not acceptsPart(partial, *msg))
        return;
    const bool request_quota_consumed = partial != partial_messages.end() && !partial->second.msg
                                        && partial->second.request_quota_consumed;
    if (msg->type > MessageType::Reply && !request_quota_consumed) {
        /* Rate limit requests. */
        if (!rateLimit(from)) {
            if (logger_)
                logger_->warn("Dropping request due to rate limiting");
            return;
        }
    }

    // starting partial message session
    auto inserted = partial_messages.emplace(partial_key, PartialMessage {});
    auto& pmsg = inserted.first->second;
    if (not pmsg.msg) {
        if (inserted.second) {
            pmsg.from = from;
            pmsg.start = now;
            pmsg.bind(*msg);
            scheduler.add(now + RX_MAX_PACKET_TIME, std::bind(&NetworkEngine::maintainRxBuffer, this, partial_key));
        }
        pmsg.msg = std::move(msg);
        pmsg.last_part = now;
        for (const auto& part : pmsg.early_parts)
            pmsg.msg->append(*part);
        pmsg.early_parts.clear();
        pmsg.early_bytes = 0;
        if (tryCompleteMessage(pmsg, from)) {
            partial_messages.erase(inserted.first);
        } else {
            scheduler.add(now + RX_TIMEOUT, std::bind(&NetworkEngine::maintainRxBuffer, this, partial_key));
        }
    } else if (logger_)
        logger_->error("Partial message from {} with given TID {} already exists", from.toString(), msg->tid);
}

void
NetworkEngine::process(std::unique_ptr<ParsedMessage>&& msg, const SockAddr& from)
{
    const auto& now = scheduler.time();
    auto node = cache.getNode(msg->id, from.getFamily());
    const bool keyed = transport_ and node and node->getTransport();
    bool trusted = msg->session or (not msg->encrypted and not keyed);
    if (msg->encrypted and not msg->session
        and (msg->type == MessageType::Reply or msg->type == MessageType::Error)) {
        if (keyed and node->getAddr() != from)
            return;
        auto request = node and node->getAddr() == from ? node->getRequest(msg->tid) : nullptr;
        if (not request) {
            auto pending = requests.find(msg->tid);
            if (pending != requests.end() and not pending->second->node->id
                and pending->second->node->getAddr() == from)
                request = pending->second;
        }
        if (not request or not request->pending())
            return;
        trusted = true;
    }

    if (trusted) {
        node = cache.getNode(msg->id, from, now, true, msg->is_client);
        if (msg->peer)
            attachPeer(*node, msg->peer);
    } else {
        switch (msg->type) {
        case MessageType::Ping:
        case MessageType::FindNode:
        case MessageType::GetValues:
            break;
        case MessageType::AnnounceValue:
        case MessageType::Refresh:
        case MessageType::Listen:
            if (msg->encrypted)
                break;
            return;
        default:
            return;
        }
        auto peer = msg->peer;
        if (not peer and keyed)
            peer = std::make_shared<transport::Peer>(node->getTransport()->key);
        node = std::make_shared<Node>(msg->id, from, rd, msg->is_client);
        node->setTransport(std::move(peer));
    }

    if (msg->type == MessageType::ValueUpdate) {
        auto rsocket = node->getSocket(msg->tid);
        if (not rsocket)
            throw DhtProtocolException {DhtProtocolException::UNKNOWN_TID, "Unable to find socket", msg->id};
        node->received(now, {});
        onNewNode(node, 2);
        try {
            deserializeNodes(*msg, from);
            rsocket->on_receive(node, std::move(*msg));
        } catch (const DhtProtocolException& e) {
            if (logger_)
                logger_->warn("Unable to deserialize nodes {}", e.what());
        }
    } else if (msg->type == MessageType::Error or msg->type == MessageType::Reply) {
        auto rsocket = node->getSocket(msg->tid);
        auto req = node->getRequest(msg->tid);
        // Our request reached the peer in a Session envelope, so it cached the keys it answered with
        if (msg->session and req and not req->initial) {
            const auto& peer = node->getTransport();
            if (auto s = peer and peer->ephemeral ? epoch_.find(from, peer->key, *peer->ephemeral) : nullptr)
                s->confirmed = true;
        }

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
                    logger_->debug("[node {}] Unable to find transaction with id {}", node->toString(), msg->tid);
                return;
            }
        }

        node->received(now, req);

        if (not node->isClient())
            onNewNode(node, 2);
        onReportedAddr(msg->id, msg->addr);

        if (req and (req->cancelled() or req->expired() or req->completed())) {
            if (logger_)
                logger_->warn("[node {}] response to expired, cancelled or completed request", node->toString());
            return;
        }

        switch (msg->type) {
        case MessageType::Error: {
            if (msg->id and req
                and ((msg->error_code == DhtProtocolException::NOT_FOUND and req->getType() == MessageType::Refresh)
                     or (msg->error_code == DhtProtocolException::UNAUTHORIZED
                         and (req->getType() == MessageType::AnnounceValue or req->getType() == MessageType::Listen)))) {
                req->last_try = time_point::min();
                req->reply_time = time_point::min();
                if (not req->setError(DhtProtocolException {msg->error_code}))
                    onError(req, DhtProtocolException {msg->error_code});
            } else {
                if (logIncoming_)
                    if (logger_)
                        logger_->warn("[node {} {}] received unknown error message {}",
                                      msg->id.toString(),
                                      from.toString(),
                                      msg->error_code);
            }
            break;
        }
        case MessageType::Reply:
            if (req) { /* request reply */
                auto& r = *req;
                if (r.getType() == MessageType::AnnounceValue or r.getType() == MessageType::Listen
                    or r.getType() == MessageType::Refresh) {
                    r.node->authSuccess();
                }
                r.reply_time = scheduler.time();
                try {
                    deserializeNodes(*msg, from);
                    r.setDone(std::move(*msg));
                } catch (const DhtProtocolException& e) {
                    if (logger_)
                        logger_->warn("Unable to deserialize nodes {}", e.what());
                }
                break;
            } else { /* request socket data */
                try {
                    deserializeNodes(*msg, from);
                    rsocket->on_receive(node, std::move(*msg));
                } catch (const DhtProtocolException& e) {
                    if (logger_)
                        logger_->warn("Unable to deserialize nodes {}", e.what());
                }
            }
            break;
        default:
            break;
        }
    } else {
        if (trusted) {
            node->received(now, {});
            if (not node->isClient())
                onNewNode(node, 1);
        }
        try {
            switch (msg->type) {
            case MessageType::Ping:
                ++in_stats.ping;
                if (logIncoming_)
                    if (logger_)
                        logger_->debug("[node {}] sending pong", node->toString());
                onPing(node);
                sendPong(*node, from, msg->tid);
                break;
            case MessageType::FindNode: {
                // if (logger_)
                //     logger_->d("[node %s] got 'find' request for %s (%d)",
                //     node->toString().c_str(), msg->target.toString().c_str(), msg->want);
                ++in_stats.find;
                RequestAnswer answer = onFindNode(node, msg->target, msg->want);
                auto nnodes = bufferNodes(from.getFamily(), msg->target, msg->want, answer.nodes4, answer.nodes6);
                sendNodesValues(*node, from, msg->tid, nnodes, {}, {}, writeToken(*node));
                break;
            }
            case MessageType::GetValues: {
                // if (logger_)
                //     logger_->d("[node %s] got 'get' request for %s",
                //     node->toString().c_str(), msg->info_hash.toString().c_str());
                ++in_stats.get;
                RequestAnswer answer = onGetValues(node, msg->info_hash, msg->want, msg->query);
                auto nnodes = bufferNodes(from.getFamily(), msg->info_hash, msg->want, answer.nodes4, answer.nodes6);
                sendNodesValues(*node, from, msg->tid, nnodes, answer.values, msg->query, writeToken(*node));
                break;
            }
            case MessageType::AnnounceValue: {
                if (logIncoming_ and logger_)
                    logger_->debug("[node {}] got 'put' request for {}", node->toString(), msg->info_hash.toString());
                ++in_stats.put;
                authorizeWrite(*msg, *node, DhtProtocolException::PUT_WRONG_TOKEN);
                onAnnounce(node, msg->info_hash, msg->values, msg->created);

                /* Note that if storageStore failed, we lie to the requestor.
                   This is to prevent them from backtracking, and hence
                   polluting the DHT. */
                for (auto& v : msg->values) {
                    sendValueAnnounced(*node, from, msg->tid, v->id);
                }
                break;
            }
            case MessageType::Refresh:
                if (logIncoming_ and logger_)
                    logger_->debug("[node {}] got 'refresh' request for {}",
                                   node->toString(),
                                   msg->info_hash.toString());
                authorizeWrite(*msg, *node, DhtProtocolException::PUT_WRONG_TOKEN);
                onRefresh(node, msg->info_hash, msg->value_id);
                /* Same note as above in MessageType::AnnounceValue applies. */
                sendValueAnnounced(*node, from, msg->tid, msg->value_id);
                break;
            case MessageType::Listen: {
                if (logIncoming_ and logger_)
                    logger_->debug("[node {}] got 'listen' request for {}", node->toString(), msg->info_hash.toString());
                ++in_stats.listen;
                authorizeWrite(*msg, *node, DhtProtocolException::LISTEN_WRONG_TOKEN);
                RequestAnswer answer = onListen(node,
                                                msg->info_hash,
                                                msg->socket_id,
                                                std::move(msg->query),
                                                msg->version);
                auto nnodes = bufferNodes(from.getFamily(), msg->info_hash, msg->want, answer.nodes4, answer.nodes6);
                sendListenConfirmation(*node, from, msg->tid, writeToken(*node));
                break;
            }
            case MessageType::UpdateValue: {
                if (logIncoming_ and logger_)
                    logger_->debug("[node {}] got 'update' request for {}", node->toString(), msg->info_hash.toString());
                ++in_stats.updateValue;
                if (auto rsocket = node->getSocket(msg->socket_id))
                    rsocket->on_receive(node, std::move(*msg));
                else if (logger_)
                    logger_->error("[node {}] 'update' request without socket for {}",
                                   node->toString(),
                                   msg->info_hash.toString());
                sendListenConfirmation(*node, from, msg->tid);
                break;
            }
            default:
                break;
            }
        } catch (const std::overflow_error& e) {
            if (logger_)
                logger_->e("Unable to send value: buffer not large enough.");
        } catch (const DhtProtocolException& e) {
            sendError(*node, from, msg->tid, e.getCode(), e.getMsg().c_str(), true);
        }
    }
}

void
insertAddr(msgpack::packer<msgpack::sbuffer>& pk, const SockAddr& addr)
{
    size_t addr_len = std::min<size_t>(addr.getLength(),
                                       (addr.getFamily() == AF_INET) ? sizeof(in_addr) : sizeof(in6_addr));
    void* addr_ptr = (addr.getFamily() == AF_INET) ? (void*) &addr.getIPv4().sin_addr
                                                   : (void*) &addr.getIPv6().sin6_addr;
    pk.pack("sa");
    pk.pack_bin(addr_len);
    pk.pack_bin_body((char*) addr_ptr, addr_len);
}

void
NetworkEngine::packOptionalFields(msgpack::packer<msgpack::sbuffer>& pk, bool key) const
{
    if (config.network) {
        pk.pack(KEY_NETID);
        pk.pack(config.network);
    }
    if (config.is_client) {
        pk.pack(KEY_ISCLIENT);
        pk.pack(config.is_client);
    }
    if (key) {
        const auto& pub = config.transport.key.pub;
        pk.pack(KEY_TRANSPORT);
        pk.pack_bin(pub.size());
        pk.pack_bin_body((const char*) pub.data(), pub.size());
    }
}

/* IP and port: what ephemeral keys and tokens are bound to */
static Blob
addressBytes(const SockAddr& sa)
{
    auto addr = SockAddr(sa).getMappedIPv4();
    Blob b;
    in_port_t port;
    if (addr.getFamily() == AF_INET) {
        const auto& sin = addr.getIPv4();
        b.assign((const uint8_t*) &sin.sin_addr, (const uint8_t*) &sin.sin_addr + sizeof(in_addr));
        port = sin.sin_port;
    } else if (addr.getFamily() == AF_INET6) {
        const auto& sin6 = addr.getIPv6();
        b.assign((const uint8_t*) &sin6.sin6_addr, (const uint8_t*) &sin6.sin6_addr + sizeof(in6_addr));
        port = sin6.sin6_port;
    } else {
        return b;
    }
    b.insert(b.end(), (const uint8_t*) &port, (const uint8_t*) &port + sizeof(port));
    return b;
}

transport::KeyPair
NetworkEngine::Epoch::ephemeral(const SockAddr& addr) const
{
    auto a = addressBytes(addr);
    return transport::addressKey(secret, a.data(), a.size());
}

Blob
NetworkEngine::Epoch::token(const SockAddr& addr) const
{
    auto a = addressBytes(addr);
    if (a.empty())
        return {};
    auto t = transport::addressToken(secret, a.data(), a.size());
    return {t.begin(), t.end()};
}

NetworkEngine::Session*
NetworkEngine::Epoch::find(const SockAddr& addr)
{
    auto it = sessions.find(addr);
    if (it == sessions.end())
        return nullptr;
    used.splice(used.begin(), used, it->second.used);
    return &it->second.session;
}

NetworkEngine::Session*
NetworkEngine::Epoch::find(const SockAddr& addr, const transport::Key& peer, const transport::Key& peerEphemeral)
{
    auto s = find(addr);
    return s and s->peer == peer and s->peerEphemeral == peerEphemeral ? s : nullptr;
}

void
NetworkEngine::Epoch::store(const SockAddr& addr, const Session& session)
{
    auto it = sessions.find(addr);
    if (it == sessions.end()) {
        if (sessions.size() >= MAX_SESSIONS) {
            auto evicted = sessions.find(used.back());
            transport::wipe(evicted->second.session.keys.tx);
            transport::wipe(evicted->second.session.keys.rx);
            sessions.erase(evicted);
            used.pop_back();
        }
        used.push_front(addr);
        sessions.emplace(addr, Entry {session, used.begin()});
        return;
    }
    transport::wipe(it->second.session.keys.tx);
    transport::wipe(it->second.session.keys.rx);
    it->second.session = session;
    used.splice(used.begin(), used, it->second.used);
}

void
NetworkEngine::Epoch::wipe()
{
    for (auto& [addr, entry] : sessions) {
        (void) addr;
        transport::wipe(entry.session.keys.tx);
        transport::wipe(entry.session.keys.rx);
    }
    sessions.clear();
    used.clear();
    transport::wipe(secret);
}

void
NetworkEngine::rotateEpoch()
{
    previousEpoch_.wipe();
    previousEpoch_.secret = epoch_.secret;
    previousEpoch_.sessions = std::move(epoch_.sessions);
    previousEpoch_.used = std::move(epoch_.used);
    epoch_.sessions.clear();
    epoch_.used.clear();
    epoch_.secret = transport::randomSecret();
    epochRotation_ = scheduler.add(scheduler.time() + EPOCH_DURATION, std::bind(&NetworkEngine::rotateEpoch, this));
}

std::optional<NetworkEngine::Session>
NetworkEngine::session(const transport::Peer& peer, const SockAddr& addr)
{
    const auto& peerEphemeral = *peer.ephemeral;
    const bool validated = peer.validatedAddress and peer.validatedAddress == addr;
    if (validated)
        if (auto s = epoch_.find(addr, peer.key, peerEphemeral))
            return *s;
    auto ephemeral = epoch_.ephemeral(addr);
    std::optional<Session> s;
    if (auto keys = transport::sessionKeys(config.transport.key, ephemeral, peer.key, peerEphemeral, config.network)) {
        s = Session {ephemeral.pub, peer.key, peerEphemeral, *keys};
        if (validated)
            epoch_.store(addr, *s);
    }
    transport::wipe(ephemeral.secret);
    return s;
}

std::optional<Blob>
NetworkEngine::openSession(const transport::Header& header, const uint8_t* buf, size_t buflen, const SockAddr& from)
{
    // The sender uses the last ephemeral key we sent to its address
    const std::array<Epoch*, 2> epochs {&epoch_, &previousEpoch_};
    for (auto* epoch : epochs)
        if (auto cached = epoch->find(from, header.sender, header.ephemeral))
            if (auto payload = transport::open(cached->keys.rx, buf, buflen))
                return payload;
    for (auto* epoch : epochs) {
        if (not *epoch or epoch->find(from, header.sender, header.ephemeral))
            continue;
        // Key agreement is the costly part of an unknown sender
        if (not rateLimit(from))
            return std::nullopt;
        auto ephemeral = epoch->ephemeral(from);
        auto keys = transport::sessionKeys(config.transport.key,
                                           ephemeral,
                                           header.sender,
                                           header.ephemeral,
                                           config.network);
        transport::wipe(ephemeral.secret);
        if (not keys)
            return std::nullopt;
        if (auto payload = transport::open(keys->rx, buf, buflen)) {
            epoch->store(from, Session {ephemeral.pub, header.sender, header.ephemeral, *keys});
            return payload;
        }
        transport::wipe(keys->tx);
        transport::wipe(keys->rx);
    }
    return std::nullopt;
}

std::optional<Blob>
NetworkEngine::openData(transport::Header& header, const uint8_t* buf, size_t buflen, const SockAddr& from)
{
    for (auto* epoch : {&epoch_, &previousEpoch_}) {
        auto s = epoch->find(from);
        if (not s)
            continue;
        if (auto payload = transport::open(s->keys.rx, buf, buflen)) {
            // The peer only sends Data once it got our answer: it has the keys and accepted us
            if (epoch == &epoch_)
                s->confirmed = true;
            header.sender = s->peer;
            header.ephemeral = s->peerEphemeral;
            return payload;
        }
    }
    return std::nullopt;
}

bool
NetworkEngine::tokenMatch(const Blob& token, const SockAddr& addr) const
{
    if (not addr or token.size() != TOKEN_SIZE)
        return false;
    return token == epoch_.token(addr) or (previousEpoch_ and token == previousEpoch_.token(addr));
}

void
NetworkEngine::authorizeWrite(const ParsedMessage& msg, const Node& node, const std::string& error) const
{
    if (msg.encrypted ? msg.session : tokenMatch(msg.token, node.getAddr()))
        return;
    if (logger_)
        logger_->warn("[node {}] {}", node.toString(), error);
    throw DhtProtocolException {DhtProtocolException::UNAUTHORIZED, error};
}

Sp<transport::Peer>
NetworkEngine::makePeer(const InfoHash& id, const transport::Key& key) const
{
    if (key == transport::Key {} or transport::nodeId(key) != id)
        return {};
    return std::make_shared<transport::Peer>(key);
}

void
NetworkEngine::attachPeer(Node& node, const Sp<transport::Peer>& peer)
{
    const auto& current = node.getTransport();
    if (not current) {
        node.setTransport(peer);
    } else if (current != peer) {
        // Both keys match the node ID, so they are the same
        current->authorizedUntil = std::max(current->authorizedUntil, peer->authorizedUntil);
        if (peer->ephemeral) {
            current->setEphemeral(*peer->ephemeral, peer->validatedAddress);
            if (std::exchange(current->recovering, false))
                resumeRequests(node);
        }
    }
}

bool
NetworkEngine::authorize(transport::Peer& peer, const uint8_t* data, size_t size) const
{
    if (peer.isAuthorized(std::chrono::system_clock::now()))
        return true;
    try {
        auto credential = transport::Credential::unpack(data, size);
        if (credential.key != peer.key or not credential.verify(config.transport.authorities))
            return false;
        peer.authorizedUntil = credential.expiration;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::optional<NetworkEngine::OpenedEnvelope>
NetworkEngine::openEnvelope(const uint8_t* buf, size_t buflen, const SockAddr& from)
{
    using transport::EnvelopeType;
    constexpr size_t CREDENTIAL_SIZE = transport::Credential::PACKED_SIZE;
    auto header = transport::parseHeader(buf, buflen);
    if (not header or header->sender == config.transport.key.pub)
        return std::nullopt;
    const bool isPrivate = config.transport.isPrivate();

    if (header->type == EnvelopeType::Hello) {
        // Unauthenticated: its state is only used to answer, never kept
        constexpr size_t credentialEnd = transport::HEADER_SIZE + CREDENTIAL_SIZE;
        auto peer = std::make_shared<transport::Peer>(header->sender);
        if (not isPrivate or buflen <= credentialEnd or not rateLimit(from)
            or not authorize(*peer, buf + transport::HEADER_SIZE, CREDENTIAL_SIZE))
            return std::nullopt;
        peer->setEphemeral(header->ephemeral);
        return OpenedEnvelope {std::move(peer), Blob(buf + credentialEnd, buf + buflen), true};
    }

    std::optional<Blob> payload;
    if (header->type == EnvelopeType::Initial) {
        if (not rateLimit(from))
            return std::nullopt;
        if (auto key = transport::initialReceiveKey(config.transport.key,
                                                    header->sender,
                                                    header->ephemeral,
                                                    config.network))
            payload = transport::open(*key, buf, buflen);
    } else if (header->type == EnvelopeType::Data) {
        payload = openData(*header, buf, buflen, from);
    } else {
        payload = openSession(*header, buf, buflen, from);
    }
    if (not payload) {
        if (logger_)
            logger_->debug("Unable to decrypt message from {}", from.toString());
        return std::nullopt;
    }

    auto peer = std::make_shared<transport::Peer>(header->sender);
    if (auto node = cache.getNode(transport::nodeId(header->sender), from.getFamily()))
        if (const auto& current = node->getTransport())
            peer->authorizedUntil = current->authorizedUntil;
    if (header->credential) {
        if (payload->size() < CREDENTIAL_SIZE or (isPrivate and not authorize(*peer, payload->data(), CREDENTIAL_SIZE)))
            return std::nullopt;
        payload->erase(payload->begin(), payload->begin() + CREDENTIAL_SIZE);
    } else if (isPrivate and not peer->isAuthorized(std::chrono::system_clock::now())) {
        return std::nullopt;
    }
    // Session and Data envelopes were opened with our key for the source address: the sender receives there
    const bool session = header->type != EnvelopeType::Initial;
    peer->setEphemeral(header->ephemeral, session ? from : SockAddr {});
    return OpenedEnvelope {std::move(peer), std::move(*payload), false, session};
}

void
NetworkEngine::processHello(const ParsedMessage& msg, const Sp<transport::Peer>& peer, const SockAddr& from)
{
    if (msg.type != MessageType::Ping)
        return;
    ++in_stats.ping;
    // Answer without adding the claimed node: only the owner of its key can read the answer
    Node node(msg.id, from, rd);
    node.setTransport(peer);
    sendPong(node, from, msg.tid);
}

int
NetworkEngine::sendRaw(const SockAddr& addr, const uint8_t* buf, size_t len, bool confirmed)
{
    return dht_socket ? dht_socket->sendTo(addr, buf, len, confirmed) : ENOTCONN;
}

int
NetworkEngine::send(const Node& node, const SockAddr& addr, const char* buf, size_t len, bool confirmed)
{
    using transport::EnvelopeType;
    const auto data = (const uint8_t*) buf;
    if (not transport_)
        return sendRaw(addr, data, len, confirmed);
    const bool isPrivate = config.transport.isPrivate();
    const auto& own = config.transport.key;
    if (const auto& peer = node.getTransport()) {
        // Keys travel until the peer confirms the session, and the credential with them
        Blob packet;
        if (not peer->ephemeral) {
            auto e = epoch_.ephemeral(addr);
            if (auto key = transport::initialSendKey(own, e, peer->key, config.network)) {
                packet = transport::seal(*key,
                                         EnvelopeType::Initial,
                                         own.pub,
                                         e.pub,
                                         data,
                                         len,
                                         isPrivate ? credential_ : Blob {});
                transport::wipe(*key);
            }
            transport::wipe(e.secret);
        } else if (auto s = session(*peer, addr)) {
            packet = s->confirmed ? transport::sealData(s->keys.tx, data, len)
                                  : transport::seal(s->keys.tx,
                                                    EnvelopeType::Session,
                                                    own.pub,
                                                    s->ephemeral,
                                                    data,
                                                    len,
                                                    isPrivate ? credential_ : Blob {});
            transport::wipe(s->keys.tx);
            transport::wipe(s->keys.rx);
        }
        if (not packet.empty())
            return sendRaw(addr, packet.data(), packet.size(), confirmed);
        return EPERM;
    } else if (isPrivate and not node.id) {
        // ping to an address: introduce ourselves
        auto e = epoch_.ephemeral(addr);
        transport::wipe(e.secret);
        auto packet = transport::hello(own.pub, e.pub, credential_, data, len);
        return sendRaw(addr, packet.data(), packet.size(), confirmed);
    }
    if (isPrivate)
        return EPERM;
    return sendRaw(addr, data, len, confirmed);
}

size_t
NetworkEngine::envelopeOverhead(const Node& node, const SockAddr& addr)
{
    if (not transport_)
        return 0;
    const size_t credential = config.transport.isPrivate() ? credential_.size() : 0;
    if (const auto& peer = node.getTransport()) {
        if (peer->ephemeral and peer->validatedAddress and peer->validatedAddress == addr)
            if (auto s = epoch_.find(addr, peer->key, *peer->ephemeral); s and s->confirmed)
                return transport::DATA_ENVELOPE_OVERHEAD;
        return transport::ENVELOPE_OVERHEAD + credential;
    }
    if (config.transport.isPrivate() and not node.id)
        return transport::HEADER_SIZE + credential;
    return 0;
}

Sp<Request>
NetworkEngine::sendPing(const Sp<Node>& node, RequestCb&& on_done, RequestExpiredCb&& on_expired)
{
    Tid tid(node->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(*node);
    pk.pack_map(5 + optionalFields(advertise));

    pk.pack(KEY_A);
    pk.pack_map(1);
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);

    pk.pack(KEY_Q);
    pk.pack(QUERY_PING);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_Q);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    auto req = std::make_shared<Request>(
        MessageType::Ping,
        tid,
        node,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [this, on_done = std::move(on_done)](const Request& req_status, ParsedMessage&&) {
            if (logger_)
                logger_->debug("[node {}] got pong.", req_status.node->toString());
            if (on_done) {
                on_done(req_status, {});
            }
        },
        std::move(on_expired));
    sendRequest(req);
    ++out_stats.ping;
    return req;
}

void
NetworkEngine::sendPong(const Node& node, const SockAddr& addr, Tid tid)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(node);
    pk.pack_map(4 + optionalFields(advertise));

    pk.pack(KEY_R);
    pk.pack_map(2);
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);
    insertAddr(pk, addr);

    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_R);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    send(node, addr, buffer.data(), buffer.size());
}

Sp<Request>
NetworkEngine::sendFindNode(
    const Sp<Node>& n, const InfoHash& target, want_t want, RequestCb&& on_done, RequestExpiredCb&& on_expired)
{
    Tid tid(n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(*n);
    pk.pack_map(5 + optionalFields(advertise));

    pk.pack(KEY_A);
    pk.pack_map(2 + (want > 0 ? 1 : 0));
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);
    pk.pack(KEY_REQ_TARGET);
    pk.pack(target);
    if (want > 0) {
        pk.pack(KEY_REQ_WANT);
        pk.pack_array(((want & WANT4) ? 1 : 0) + ((want & WANT6) ? 1 : 0));
        if (want & WANT4)
            pk.pack(AF_INET);
        if (want & WANT6)
            pk.pack(AF_INET6);
    }

    pk.pack(KEY_Q);
    pk.pack(QUERY_FIND);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_Q);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    auto req = std::make_shared<Request>(
        MessageType::FindNode,
        tid,
        n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
                                                              if (on_done) {
                                                                  on_done(req_status,
                                                                          {std::forward<ParsedMessage>(msg)});
                                                              }
        },
        std::move(on_expired));
    sendRequest(req);
    ++out_stats.find;
    return req;
}

Sp<Request>
NetworkEngine::sendGetValues(const Sp<Node>& n,
                             const InfoHash& info_hash,
                             const Query& query,
                             want_t want,
                             RequestCb&& on_done,
                             RequestExpiredCb&& on_expired)
{
    Tid tid(n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(*n);
    pk.pack_map(5 + optionalFields(advertise));

    unsigned sendQuery = (not query.where.empty() or not query.select.empty()) ? 1 : 0;
    unsigned sendWant = (want > 0) ? 1 : 0;

    pk.pack(KEY_A);
    pk.pack_map(2 + sendQuery + sendWant);
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);
    pk.pack(KEY_REQ_H);
    pk.pack(info_hash);
    if (sendQuery) {
        pk.pack(KEY_Q);
        pk.pack(query);
    }
    if (sendWant) {
        pk.pack(KEY_REQ_WANT);
        unsigned sendWant4 = (want & WANT4) ? 1 : 0;
        unsigned sendWant6 = (want & WANT6) ? 1 : 0;
        pk.pack_array(sendWant4 + sendWant6);
        if (sendWant4)
            pk.pack(AF_INET);
        if (sendWant6)
            pk.pack(AF_INET6);
    }

    pk.pack(KEY_Q);
    pk.pack(QUERY_GET);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_Q);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    auto req = std::make_shared<Request>(
        MessageType::GetValues,
        tid,
        n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
                                                              if (on_done) {
                                                                  on_done(req_status,
                                                                          {std::forward<ParsedMessage>(msg)});
                                                              }
        },
        std::move(on_expired));
    sendRequest(req);
    ++out_stats.get;
    return req;
}

SockAddr
deserializeIPv4(const uint8_t* ni)
{
    SockAddr addr;
    addr.setFamily(AF_INET);
    auto& sin = addr.getIPv4();
    std::memcpy(&sin.sin_addr, ni, 4);
    std::memcpy(&sin.sin_port, ni + 4, 2);
    return addr;
}
SockAddr
deserializeIPv6(const uint8_t* ni)
{
    SockAddr addr;
    addr.setFamily(AF_INET6);
    auto& sin6 = addr.getIPv6();
    std::memcpy(&sin6.sin6_addr, ni, 16);
    std::memcpy(&sin6.sin6_port, ni + 16, 2);
    return addr;
}

void
NetworkEngine::deserializeNodes(ParsedMessage& msg, const SockAddr& from)
{
    if (msg.nodes4_raw.size() % NODE4_INFO_BUF_LEN != 0 || msg.nodes6_raw.size() % NODE6_INFO_BUF_LEN != 0) {
        throw DhtProtocolException {DhtProtocolException::WRONG_NODE_INFO_BUF_LEN};
    }
    // deserialize nodes
    const auto& now = scheduler.time();
    const bool isPrivate = transport_ and config.transport.isPrivate();
    auto listedPeer = [&](const Blob& keys, size_t count, size_t i, const InfoHash& id) -> Sp<transport::Peer> {
        if (not transport_ or keys.size() != count * transport::KEY_SIZE)
            return {};
        transport::Key key;
        std::copy_n(keys.data() + i * transport::KEY_SIZE, key.size(), key.begin());
        return makePeer(id, key);
    };
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
        auto peer = listedPeer(msg.nodes4_keys, n, i, ni_id);
        if (isPrivate and not peer)
            continue;
        msg.nodes4.emplace_back(cache.getNode(ni_id, addr, now, false));
        if (peer)
            attachPeer(*msg.nodes4.back(), peer);
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
        auto peer = listedPeer(msg.nodes6_keys, n, i, ni_id);
        if (isPrivate and not peer)
            continue;
        msg.nodes6.emplace_back(cache.getNode(ni_id, addr, now, false));
        if (peer)
            attachPeer(*msg.nodes6.back(), peer);
        onNewNode(msg.nodes6.back(), 0);
    }
}

std::vector<Blob>
NetworkEngine::packValueHeader(msgpack::sbuffer& buffer,
                               std::vector<Sp<Value>>::const_iterator b,
                               std::vector<Sp<Value>>::const_iterator e) const
{
    std::vector<Blob> svals;
    size_t total_size = 0;

    svals.reserve(std::distance(b, e));
    for (; b != e; ++b) {
        svals.emplace_back(packMsg(*b));
        total_size += svals.back().size();
    }

    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack(KEY_REQ_VALUES);
    pk.pack_array(svals.size());
    // try to put everything in a single UDP packet
    if (svals.size() < 50 && total_size < MAX_PACKET_VALUE_SIZE) {
        for (const auto& b : svals)
            buffer.write((const char*) b.data(), b.size());
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
NetworkEngine::sendValueParts(Tid tid, const std::vector<Blob>& svals, const Node& node, const SockAddr& addr)
{
    const size_t fragmentSize = FRAGMENT_SIZE - envelopeOverhead(node, addr);
    msgpack::sbuffer buffer;
    unsigned i = 0;
    for (const auto& v : svals) {
        size_t start {0}, end;
        do {
            end = std::min(start + fragmentSize, v.size());
            buffer.clear();
            msgpack::packer<msgpack::sbuffer> pk(&buffer);
            pk.pack_map(3 + optionalFields(false));
            packOptionalFields(pk, false);
            pk.pack(KEY_Y);
            pk.pack(KEY_V);
            pk.pack(KEY_TID);
            pk.pack(tid);
            pk.pack(KEY_V);
            pk.pack_map(1);
            pk.pack(i);
            pk.pack_map(2);
            pk.pack("o"sv);
            pk.pack(start);
            pk.pack("d"sv);
            pk.pack_bin(end - start);
            pk.pack_bin_body((const char*) v.data() + start, end - start);
            send(node, addr, buffer.data(), buffer.size());
            start = end;
        } while (start != v.size());
        i++;
    }
}

void
NetworkEngine::sendNodesValues(const Node& node,
                               const SockAddr& addr,
                               Tid tid,
                               const BufferedNodes& nodes,
                               const std::vector<Sp<Value>>& st,
                               const Query& query,
                               const Blob& token)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(node);
    pk.pack_map(4 + optionalFields(advertise));

    auto packBlob = [&](std::string_view key, const Blob& b) {
        if (b.empty())
            return;
        pk.pack(key);
        pk.pack_bin(b.size());
        pk.pack_bin_body((const char*) b.data(), b.size());
    };
    pk.pack(KEY_R);
    pk.pack_map(2 + (not st.empty() ? 1 : 0) + (not nodes.nodes4.empty() ? 1 : 0) + (not nodes.nodes6.empty() ? 1 : 0)
                + (not nodes.keys4.empty() ? 1 : 0) + (not nodes.keys6.empty() ? 1 : 0) + (not token.empty() ? 1 : 0));
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);
    insertAddr(pk, addr);
    packBlob(KEY_REQ_NODES4, nodes.nodes4);
    packBlob(KEY_REQ_NODES6, nodes.nodes6);
    packBlob(KEY_REQ_KEYS4, nodes.keys4);
    packBlob(KEY_REQ_KEYS6, nodes.keys6);
    if (not token.empty()) {
        pk.pack(KEY_REQ_TOKEN);
        packToken(pk, token);
    }
    std::vector<Blob> svals {};
    if (not st.empty()) { /* pack complete values */
        if (query.select.empty()) {
            svals = packValueHeader(buffer, st);
        } else { /* pack fields */
            auto fields = query.select.getSelection();
            pk.pack(KEY_REQ_FIELDS);
            pk.pack_map(2);
            pk.pack("f"sv);
            pk.pack(fields);
            pk.pack("v"sv);
            pk.pack_array(st.size() * fields.size());
            for (const auto& v : st)
                v->msgpack_pack_fields(fields, pk);
            // DHT_LOG_DBG("sending closest nodes (%d+%d nodes.), %u value headers containing %u fields",
            //         nodes.size(), nodes6.size(), st.size(), fields.size());
        }
    }

    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_R);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    // send response
    send(node, addr, buffer.data(), buffer.size());

    // send parts
    if (not svals.empty())
        sendValueParts(tid, svals, node, addr);
}

std::pair<Blob, Blob>
NetworkEngine::bufferNodes(sa_family_t af, const InfoHash& id, std::vector<Sp<Node>>& nodes)
{
    std::sort(nodes.begin(), nodes.end(), [&](const Sp<Node>& a, const Sp<Node>& b) {
        return id.xorCmp(a->id, b->id) < 0;
    });
    size_t nnode = std::min<size_t>(SEND_NODES, nodes.size());
    Blob bnodes;
    if (af == AF_INET) {
        bnodes.resize(NODE4_INFO_BUF_LEN * nnode);
        for (size_t i = 0; i < nnode; i++) {
            const Node& n = *nodes[i];
            const auto& sin = n.getAddr().getIPv4();
            auto dest = bnodes.data() + NODE4_INFO_BUF_LEN * i;
            memcpy(dest, n.id.data(), HASH_LEN);
            memcpy(dest + HASH_LEN, &sin.sin_addr, sizeof(in_addr));
            memcpy(dest + HASH_LEN + sizeof(in_addr), &sin.sin_port, sizeof(in_port_t));
        }
    } else if (af == AF_INET6) {
        bnodes.resize(NODE6_INFO_BUF_LEN * nnode);
        for (size_t i = 0; i < nnode; i++) {
            const Node& n = *nodes[i];
            const auto& sin6 = n.getAddr().getIPv6();
            auto dest = bnodes.data() + NODE6_INFO_BUF_LEN * i;
            memcpy(dest, n.id.data(), HASH_LEN);
            memcpy(dest + HASH_LEN, &sin6.sin6_addr, sizeof(in6_addr));
            memcpy(dest + HASH_LEN + sizeof(in6_addr), &sin6.sin6_port, sizeof(in_port_t));
        }
    } else {
        return {};
    }

    Blob bkeys;
    if (transport_) {
        bool hasKey = false;
        bkeys.resize(transport::KEY_SIZE * nnode);
        for (size_t i = 0; i < nnode; i++) {
            if (const auto& peer = nodes[i]->getTransport()) {
                std::copy(peer->key.begin(), peer->key.end(), bkeys.begin() + transport::KEY_SIZE * i);
                hasKey = true;
            }
        }
        if (not hasKey)
            bkeys.clear();
    }
    return {std::move(bnodes), std::move(bkeys)};
}

NetworkEngine::BufferedNodes
NetworkEngine::bufferNodes(
    sa_family_t af, const InfoHash& id, want_t want, std::vector<Sp<Node>>& nodes4, std::vector<Sp<Node>>& nodes6)
{
    if (want < 0)
        want = af == AF_INET ? WANT4 : WANT6;

    BufferedNodes buffered;
    if (want & WANT4)
        std::tie(buffered.nodes4, buffered.keys4) = bufferNodes(AF_INET, id, nodes4);
    if (want & WANT6)
        std::tie(buffered.nodes6, buffered.keys6) = bufferNodes(AF_INET6, id, nodes6);
    return buffered;
}

Sp<Request>
NetworkEngine::sendListen(const Sp<Node>& n,
                          const InfoHash& hash,
                          const Query& query,
                          const Blob& token,
                          Tid socketId,
                          RequestCb&& on_done,
                          RequestExpiredCb&& on_expired)
{
    Tid tid(n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(*n);
    pk.pack_map(5 + optionalFields(advertise));

    auto has_query = not query.where.empty() or not query.select.empty();
    pk.pack(KEY_A);
    pk.pack_map(4 + has_query + (not token.empty() ? 1 : 0));
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);
    pk.pack(KEY_VERSION);
    pk.pack(1);
    pk.pack(KEY_REQ_H);
    pk.pack(hash);
    if (not token.empty()) {
        pk.pack(KEY_REQ_TOKEN);
        packToken(pk, token);
    }
    pk.pack(KEY_REQ_SID);
    pk.pack(socketId);
    if (has_query) {
        pk.pack(KEY_REQ_QUERY);
        pk.pack(query);
    }

    pk.pack(KEY_Q);
    pk.pack(QUERY_LISTEN);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_Q);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    auto req = std::make_shared<Request>(
        MessageType::Listen,
        tid,
        n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request& req_status, ParsedMessage&& msg) { /* on done */
                                                              if (on_done)
                                                                  on_done(req_status,
                                                                          {std::forward<ParsedMessage>(msg)});
        },
        std::move(on_expired));
    sendRequest(req);
    ++out_stats.listen;
    return req;
}

void
NetworkEngine::sendListenConfirmation(const Node& node, const SockAddr& addr, Tid tid, const Blob& token)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(node);
    pk.pack_map(4 + optionalFields(advertise));

    pk.pack(KEY_R);
    pk.pack_map(2 + (not token.empty() ? 1 : 0));
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);
    insertAddr(pk, addr);
    if (not token.empty()) {
        pk.pack(KEY_REQ_TOKEN);
        packToken(pk, token);
    }

    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_R);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    send(node, addr, buffer.data(), buffer.size());
}

Sp<Request>
NetworkEngine::sendAnnounceValue(const Sp<Node>& n,
                                 const InfoHash& infohash,
                                 const Sp<Value>& value,
                                 time_point created,
                                 const Blob& token,
                                 RequestCb&& on_done,
                                 RequestExpiredCb&& on_expired)
{
    Tid tid(n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(*n);
    pk.pack_map(5 + optionalFields(advertise));

    bool add_created = created < scheduler.time();
    pk.pack(KEY_A);
    pk.pack_map(3 + (add_created ? 1 : 0) + (not token.empty() ? 1 : 0));
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);
    pk.pack(KEY_REQ_H);
    pk.pack(infohash);
    auto v = packValueHeader(buffer, {value});
    if (add_created) {
        pk.pack(KEY_REQ_CREATION);
        pk.pack(to_time_t(created));
    }
    if (not token.empty()) {
        pk.pack(KEY_REQ_TOKEN);
        pk.pack(token);
    }

    pk.pack(KEY_Q);
    pk.pack(QUERY_PUT);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_Q);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    auto req = std::make_shared<Request>(
        MessageType::AnnounceValue,
        tid,
        n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [this, on_done = std::move(on_done)](const Request& req_status, ParsedMessage&& msg) {
            /* on done */
            if (msg.value_id == Value::INVALID_ID) {
                if (logger_)
                    logger_->debug("[node {}] Unknown search or announce!", req_status.node->toString());
            } else {
                if (on_done) {
                    RequestAnswer answer {};
                    answer.vid = msg.value_id;
                    on_done(req_status, std::move(answer));
                }
            }
        },
        std::move(on_expired));
    req->parts = std::move(v);
    sendRequest(req);
    ++out_stats.put;
    return req;
}

void
NetworkEngine::sendUpdateValues(const Sp<Node>& n,
                                const InfoHash& infohash,
                                std::vector<Sp<Value>>&& values,
                                time_point created,
                                const Blob& token,
                                size_t socket_id)
{
    size_t total_size = 0;

    auto b = values.begin(), e = values.begin();
    while (e != values.end()) {
        if (total_size >= MAX_MESSAGE_VALUE_SIZE) {
            sendUpdateValues(n, infohash, b, e, created, token, socket_id);
            b = e;
            total_size = 0;
        }
        total_size += (*e)->size();
        ++e;
    }
    if (b != e) {
        sendUpdateValues(n, infohash, b, e, created, token, socket_id);
    }
}

Sp<Request>
NetworkEngine::sendUpdateValues(const Sp<Node>& n,
                                const InfoHash& infohash,
                                std::vector<Sp<Value>>::iterator begin,
                                std::vector<Sp<Value>>::iterator end,
                                time_point created,
                                const Blob& token,
                                size_t socket_id)
{
    Tid tid(n->getNewTid());
    Tid sid(socket_id);

    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(*n);
    pk.pack_map(5 + optionalFields(advertise));

    pk.pack(KEY_A);
    pk.pack_map(5 + (created < scheduler.time() ? 1 : 0) + (not token.empty() ? 1 : 0));
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);
    pk.pack(KEY_VERSION);
    pk.pack(1);
    pk.pack(KEY_REQ_H);
    pk.pack(infohash);
    pk.pack(KEY_REQ_SID);
    pk.pack(sid);
    auto v = packValueHeader(buffer, begin, end);
    if (created < scheduler.time()) {
        pk.pack(KEY_REQ_CREATION);
        pk.pack(to_time_t(created));
    }
    if (not token.empty()) {
        pk.pack(KEY_REQ_TOKEN);
        pk.pack(token);
    }

    pk.pack(KEY_Q);
    pk.pack(QUERY_UPDATE);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_Q);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    auto req = std::make_shared<Request>(
        MessageType::UpdateValue,
        tid,
        n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [=](const Request&, ParsedMessage&&) { /* on done */ },
        [=](const Request&, bool) { /* on expired */ });
    req->parts = std::move(v);
    sendRequest(req);
    ++out_stats.updateValue;
    return req;
}

Sp<Request>
NetworkEngine::sendRefreshValue(const Sp<Node>& n,
                                const InfoHash& infohash,
                                const Value::Id& vid,
                                const Blob& token,
                                RequestCb&& on_done,
                                RequestErrorCb&& on_error,
                                RequestExpiredCb&& on_expired)
{
    Tid tid(n->getNewTid());
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(*n);
    pk.pack_map(5 + optionalFields(advertise));

    pk.pack(KEY_A);
    pk.pack_map(3 + (not token.empty() ? 1 : 0));
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);
    pk.pack(KEY_REQ_H);
    pk.pack(infohash);
    pk.pack(KEY_REQ_VALUE_ID);
    pk.pack(vid);
    if (not token.empty()) {
        pk.pack(KEY_REQ_TOKEN);
        pk.pack(token);
    }

    pk.pack(KEY_Q);
    pk.pack(QUERY_REFRESH);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_Q);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    auto req = std::make_shared<Request>(
        MessageType::Refresh,
        tid,
        n,
        Blob(buffer.data(), buffer.data() + buffer.size()),
        [this, on_done = std::move(on_done)](const Request& req_status, ParsedMessage&& msg) {
            /* on done */
            if (msg.value_id == Value::INVALID_ID) {
                if (logger_)
                    logger_->debug("[node {}] Unknown search or announce!", req_status.node->toString());
            } else {
                if (on_done) {
                    RequestAnswer answer {};
                    answer.vid = msg.value_id;
                    on_done(req_status, std::move(answer));
                }
            }
        },
        std::move(on_error),
        std::move(on_expired));
    sendRequest(req);
    ++out_stats.refresh;
    return req;
}

void
NetworkEngine::sendValueAnnounced(const Node& node, const SockAddr& addr, Tid tid, Value::Id vid)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(node);
    pk.pack_map(4 + optionalFields(advertise));

    pk.pack(KEY_R);
    pk.pack_map(3);
    pk.pack(KEY_REQ_ID);
    pk.pack(myid);
    pk.pack(KEY_REQ_VALUE_ID);
    pk.pack(vid);
    insertAddr(pk, addr);

    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_R);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    send(node, addr, buffer.data(), buffer.size());
}

void
NetworkEngine::sendError(
    const Node& node, const SockAddr& addr, Tid tid, uint16_t code, const std::string& message, bool include_id)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    bool advertise = advertiseKey(node);
    pk.pack_map(4 + (include_id ? 1 : 0) + optionalFields(advertise));

    pk.pack(KEY_E);
    pk.pack_array(2);
    pk.pack(code);
    pk.pack(message);

    if (include_id) {
        pk.pack(KEY_R);
        pk.pack_map(1);
        pk.pack(KEY_REQ_ID);
        pk.pack(myid);
    }

    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_E);
    pk.pack(KEY_UA);
    pk.pack(OPENDHT_UA);
    packOptionalFields(pk, advertise);

    send(node, addr, buffer.data(), buffer.size());
}

void
NetworkEngine::maintainRxBuffer(const PartialMessageKey& key)
{
    auto msg = partial_messages.find(key);
    if (msg != partial_messages.end()) {
        const auto& now = scheduler.time();
        if (msg->second.start + RX_MAX_PACKET_TIME < now || msg->second.last_part + RX_TIMEOUT < now) {
            if (logger_)
                logger_->warn("Dropping expired partial message from {}", msg->second.from.toString());
            partial_messages.erase(msg);
        }
    }
}

} /* namespace net  */
} /* namespace dht */
