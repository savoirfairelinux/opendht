/*
Copyright (C) 2009-2014 Juliusz Chroboczek
Copyright (C) 2014-2016 Savoir-faire Linux Inc.

Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>,
            Simon Désaulniers <sim.desaulniers@gmail.com>

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

#include "network_engine.h"

#include <msgpack.hpp>

namespace dht {

const std::string DhtProtocolException::GET_NO_INFOHASH {"Get_values with no info_hash"};
const std::string DhtProtocolException::LISTEN_NO_INFOHASH {"Listen with no info_hash"};
const std::string DhtProtocolException::LISTEN_WRONG_TOKEN {"Listen with wrong token"};
const std::string DhtProtocolException::PUT_NO_INFOHASH {"Put with no info_hash"};
const std::string DhtProtocolException::PUT_WRONG_TOKEN {"Put with wrong token"};
const std::string DhtProtocolException::PUT_INVALID_ID {"Put with invalid id"};

const std::string NetworkEngine::my_v {"RNG1"};
const constexpr uint32_t NetworkEngine::Request::INVALID_ID;
static std::mt19937 rd_device {dht::crypto::random_device{}()};

const NetworkEngine::TransPrefix NetworkEngine::TransPrefix::PING = {"pn"};
const NetworkEngine::TransPrefix NetworkEngine::TransPrefix::FIND_NODE  = {"fn"};
const NetworkEngine::TransPrefix NetworkEngine::TransPrefix::GET_VALUES  = {"gt"};
const NetworkEngine::TransPrefix NetworkEngine::TransPrefix::ANNOUNCE_VALUES  = {"pt"};
const NetworkEngine::TransPrefix NetworkEngine::TransPrefix::LISTEN  = {"lt"};
constexpr long unsigned NetworkEngine::MAX_REQUESTS_PER_SEC;

void
NetworkEngine::tellListener(const sockaddr *sa, socklen_t salen, size_t rid, InfoHash hash, want_t want,
        Blob ntoken, std::vector<std::shared_ptr<Node>> nodes, std::vector<std::shared_ptr<Node>> nodes6,
        std::vector<std::shared_ptr<Value>> values)
{
    auto nnodes = bufferNodes(sa->sa_family, hash, want, nodes, nodes6);
    try {
        sendNodesValues(sa, salen, TransId {TransPrefix::GET_VALUES, (uint16_t)rid}, nnodes.first, nnodes.second,
                values, ntoken);
    } catch (const std::overflow_error& e) {
        DHT_LOG.ERROR("Can't send value: buffer not large enough !");
    }
}

/* Rate control for requests we receive. */
bool
NetworkEngine::rateLimit()
{
    using namespace std::chrono;
    while (not rate_limit_time.empty() and duration_cast<seconds>(now - rate_limit_time.front()) > seconds(1))
        rate_limit_time.pop();

    if (rate_limit_time.size() >= MAX_REQUESTS_PER_SEC)
        return false;

    rate_limit_time.emplace(now);
    return true;
}

void
NetworkEngine::processMessage(const uint8_t *buf, size_t buflen, const sockaddr *from, socklen_t fromlen, time_point now) {
    this->now = now;
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

    if (msg.id == myid) {
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

    if (msg.tid.length != 4) {
        DHT_LOG.ERROR("Broken node truncates transaction ids (len: %d): ", msg.tid.length);
        DHT_LOG.ERROR.logPrintable(buf, buflen);
        throw DhtProtocolException {DhtProtocolException::INVALID_REPLY_TID};
    }

    uint16_t ttid = 0;
    if (msg.type == MessageType::Error or msg.type == MessageType::Reply) {
        auto node = onNewNode(msg.id, from, fromlen, 2);
        switch (msg.type) {
        case MessageType::Error: {
            if (msg.error_code == DhtProtocolException::UNAUTHORIZED
                    && msg.id != zeroes
                    && (msg.tid.matches(TransPrefix::ANNOUNCE_VALUES, &ttid)
                        || msg.tid.matches(TransPrefix::LISTEN, &ttid))) {
                onError(node, DhtProtocolException {DhtProtocolException::UNAUTHORIZED});
            } else {
                DHT_LOG.WARN("[node %s %s] received unknown error message %u",
                        msg.id.toString().c_str(), print_addr(from, fromlen).c_str(), msg.error_code);
                DHT_LOG.WARN.logPrintable(buf, buflen);
            }
            break;
        }
        case MessageType::Reply:
            const auto& reqp = requests.find(msg.tid[2]);
            Request* req = nullptr;
            if (reqp != requests.end())
                req = &(*reqp->second);

            if (not req)
                throw DhtProtocolException {DhtProtocolException::INVALID_REPLY_TID, "", msg.id};

            req->on_done(req->id, std::move(msg));
            break;
        }
    } else {
        auto node = onNewNode(msg.id, from, fromlen, 1);
        try {
            switch (msg.type) {
            case MessageType::Ping:
                in_stats.ping++;
                DHT_LOG.DEBUG("Sending pong.");
                onPing(node);
                sendPong(from, fromlen, msg.tid);
                break;
            case MessageType::FindNode: {
                in_stats.find++;
                DHT_LOG.DEBUG("[node %s %s] got 'find' request (%d).",
                        msg.id.toString().c_str(), print_addr(from, fromlen).c_str(), msg.want);
                RequestAnswer answer = onFindNode(node, msg.info_hash, msg.want);
                auto nnodes = bufferNodes(from->sa_family, msg.target, msg.want, answer.nodes, answer.nodes6);
                sendNodesValues(from, fromlen, msg.tid, nnodes.first, nnodes.second, {}, answer.ntoken);
                break;
            }
            case MessageType::GetValues: {
                in_stats.get++;
                RequestAnswer answer = onGetValues(node, msg.info_hash, msg.want);
                auto nnodes = bufferNodes(from->sa_family, msg.target, msg.want, answer.nodes, answer.nodes6);
                sendNodesValues(from, fromlen, msg.tid, nnodes.first, nnodes.second, answer.values, answer.ntoken);
                break;
            }
            case MessageType::AnnounceValue: {
                in_stats.put++;
                onAnnounce(node, msg.info_hash, msg.token, msg.values, msg.created);

                /* Note that if storageStore failed, we lie to the requestor.
                   This is to prevent them from backtracking, and hence
                   polluting the DHT. */
                for (auto& v : msg.values) {
                   sendValueAnnounced(from, fromlen, msg.tid, v->id);
                }
                break;
            }
            case MessageType::Listen:
                if (!msg.tid.matches(TransPrefix::LISTEN, &ttid)) {
                   break;
                }
                in_stats.listen++;
                RequestAnswer answer = onListen(node, msg.info_hash, msg.token, msg.tid[2]);
                sendListenConfirmation(from, fromlen, msg.tid);
                break;
            }
        } catch (const std::overflow_error& e) {
            DHT_LOG.ERROR("Can't send value: buffer not large enough !");
        } catch (DhtProtocolException& e) {
            sendError(from, fromlen, msg.tid, e.getCode(), e.getMsg().c_str());
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

bool
NetworkEngine::cancelRequest(size_t rid) {
    // ids are at most 32bit.
    if ((rid >> 32) != 0) {
        //TODO: utiliser exception?
        return false;
    } else {
        auto rit = requests.find(rid);
        if (rit == requests.end()) {
            return false;
        } else {
            requests.erase(rit);
            return true;
        }
    }
}

void
NetworkEngine::clearExpiredRequests(size_t rid) {
    auto reqp = requests.find(rid);
    if (reqp != requests.end() and reqp->second->expired()) {
        auto& req = reqp->second;
        erase_if(requests, [=,&req](std::pair<const size_t, std::shared_ptr<Request>>& rp) {
            auto& r = rp.second;
            if (r->node->id == req->node->id && r->expired()) {
                return true;
            } else { return false; }
        });
    }
}

size_t
NetworkEngine::sendPing(std::shared_ptr<Node> n, RequestCb on_done, RequestCb on_expired) {
    auto tid = TransId {TransPrefix::PING};
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

    Blob b {buffer.data(), buffer.data() + buffer.size()};
    Request req {getNewRequestId(), n, std::move(b), nullptr,
        [=](size_t rid, bool s) { /* on expired */
            on_expired(n, rid, {});
            clearExpiredRequests(rid);
        }
    };
    requests.emplace(std::move(req));
    send(buffer.data(), buffer.size(), 0, (sockaddr*)&n->ss, n->sslen);
    out_stats.ping++;
    return tid[2];
}

void
NetworkEngine::sendPong(const sockaddr* sa, socklen_t salen, TransId tid) {
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

    send(buffer.data(), buffer.size(), 0, sa, salen);
}

size_t
NetworkEngine::sendFindNode(std::shared_ptr<Node> n, const InfoHash& target, want_t want, int confirm,
        RequestCb on_done, RequestCb on_expired) {
    auto tid = TransId {TransPrefix::FIND_NODE};
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


    Blob b {buffer.data(), buffer.data() + buffer.size()};
    Request req {getNewRequestId(), n, std::move(b),
        [=](size_t rid, ParsedMessage&& msg) { /* on done */
            on_done(n, rid, deserializeNodesValues(msg));
        },
        [=](size_t rid, bool s) { /* on expired */
            on_expired(n, rid, {});
            clearExpiredRequests(rid);
        }
    };
    requests.emplace(std::move(req));
    send(buffer.data(), buffer.size(), confirm ? 0 : MSG_CONFIRM, (sockaddr*)&n->ss, n->sslen);
    out_stats.find++;
    return tid[2];
}


size_t
NetworkEngine::sendGetValues(std::shared_ptr<Node> n, const InfoHash& target, want_t want, int confirm,
        RequestCb on_done, RequestCb on_expired) {
    auto tid = TransId {TransPrefix::GET_VALUES};
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5);

    pk.pack(std::string("a"));  pk.pack_map(2 + (want>0?1:0));
      pk.pack(std::string("id")); pk.pack(myid);
      pk.pack(std::string("h"));  pk.pack(target);
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

    Blob b {buffer.data(), buffer.data() + buffer.size()};
    Request req {getNewRequestId(), n, std::move(b),
        [=](size_t rid, ParsedMessage&& msg) { /* on done */
            on_done(n, rid, deserializeNodesValues(msg));
        },
        [=](size_t rid, bool s) { /* on expired */
            on_expired(n, rid, {});
            clearExpiredRequests(rid);
        }
    };
    requests.emplace(std::move(req));
    send(buffer.data(), buffer.size(), confirm ? 0 : MSG_CONFIRM, (sockaddr*)&n->ss, n->sslen);
    out_stats.get++;
    return tid[2];
}

NetworkEngine::RequestAnswer
NetworkEngine::deserializeNodesValues(ParsedMessage& msg) {
    RequestAnswer req_a {msg.token, std::move(msg.values)};
    if (msg.nodes4.size() % NODE4_INFO_BUF_LEN != 0 || msg.nodes6.size() % NODE6_INFO_BUF_LEN != 0) {
        throw DhtProtocolException {DhtProtocolException::WRONG_NODE_INFO_BUF_LEN};
    } else {
        // deserialize nodes
        for (unsigned i = 0; i < msg.nodes4.size() / NODE4_INFO_BUF_LEN; i++) {
            uint8_t *ni = msg.nodes4.data() + i * NODE4_INFO_BUF_LEN;
            const InfoHash& ni_id = *reinterpret_cast<InfoHash*>(ni);
            if (ni_id == myid)
                continue;
            sockaddr_in sin;
            std::fill_n((uint8_t*)&sin, sizeof(sockaddr_in), 0);
            sin.sin_family = AF_INET;
            memcpy(&sin.sin_addr, ni + ni_id.size(), 4);
            memcpy(&sin.sin_port, ni + ni_id.size() + 4, 2);
            req_a.nodes.emplace_back(Node {ni_id, (sockaddr*)&sin, sizeof(sin)});
        }
        for (unsigned i = 0; i < msg.nodes6.size() / NODE6_INFO_BUF_LEN; i++) {
            uint8_t *ni = msg.nodes6.data() + i * NODE6_INFO_BUF_LEN;
            const InfoHash& ni_id = *reinterpret_cast<InfoHash*>(ni);
            if (ni_id == myid)
                continue;
            sockaddr_in6 sin6;
            std::fill_n((uint8_t*)&sin6, sizeof(sockaddr_in6), 0);
            sin6.sin6_family = AF_INET6;
            memcpy(&sin6.sin6_addr, ni + HASH_LEN, 16);
            memcpy(&sin6.sin6_port, ni + HASH_LEN + 16, 2);
            req_a.nodes.emplace_back(Node {ni_id, (sockaddr*)&sin6, sizeof(sin6)});
        }
    }
    return std::move(req_a);
}

void
NetworkEngine::sendNodesValues(const sockaddr* sa, socklen_t salen, TransId tid, const Blob nodes, const Blob nodes6,
        const std::vector<std::shared_ptr<Value>>& st, const Blob& token) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4);

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
            subset.emplace_back(packMsg(st[j]->data));
            total_size += subset.back().size();
            k++;
            j = (j + 1) % st.size();
        } while (j != j0 && k < 50 && total_size < MAX_VALUE_SIZE);

        pk.pack(std::string("values"));
        pk.pack_array(subset.size());
        for (const auto& b : subset)
            buffer.write((const char*)b.data(), b.size());
    }

    DHT_LOG.DEBUG("sending closest nodes (%d+%d nodes.)", nodes.size(), nodes6.size());

    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("r"));
    pk.pack(std::string("v")); pk.pack(my_v);

    send(buffer.data(), buffer.size(), 0, sa, salen);
}

unsigned
NetworkEngine::insertClosestNode(uint8_t *nodes, unsigned numnodes, const InfoHash& id, const Node& n)
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

std::pair<Blob, Blob>
NetworkEngine::bufferNodes(sa_family_t af, const InfoHash& id, want_t want,
        const std::vector<std::shared_ptr<Node>>& nodes, const std::vector<std::shared_ptr<Node>>& nodes6)
{
    uint8_t bnodes[8 * NODE4_INFO_BUF_LEN];
    uint8_t bnodes6[8 * NODE6_INFO_BUF_LEN];
    size_t numnodes, numnodes6 = 0;

    if (want < 0)
        want = af == AF_INET ? WANT4 : WANT6;

    auto buff = [=](uint8_t* nodes, const InfoHash& id, const std::vector<std::shared_ptr<Node>>& closest_nodes) {
        size_t numnodes = 0;
        for (const auto& n : closest_nodes) {
            numnodes = insertClosestNode(nodes, numnodes, id, *n);
        }
        return numnodes;
    };

    if ((want & WANT4)) {
        numnodes = buff(bnodes, id, nodes);
    }

    if ((want & WANT6)) {
        numnodes6 = buff(bnodes6, id, nodes6);
    }

    Blob bn4(8 * NODE4_INFO_BUF_LEN), bn6(8 * NODE6_INFO_BUF_LEN);
    bn4.insert(bn4.begin(), bnodes, bnodes + (8*NODE4_INFO_BUF_LEN));
    bn6.insert(bn6.begin(), bnodes6, bnodes6 + (8*NODE6_INFO_BUF_LEN));
    return {std::move(bn4), std::move(bn6)};
}

size_t
NetworkEngine::sendListen(std::shared_ptr<Node> n, const InfoHash& infohash, const Blob& token, int confirm,
        RequestCb on_done, RequestCb on_expired) {
    auto tid = TransId {TransPrefix::LISTEN};
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5);

    pk.pack(std::string("a")); pk.pack_map(3);
      pk.pack(std::string("id"));    pk.pack(myid);
      pk.pack(std::string("h"));     pk.pack(infohash);
      pk.pack(std::string("token")); packToken(pk, token);

    pk.pack(std::string("q")); pk.pack(std::string("listen"));
    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("q"));
    pk.pack(std::string("v")); pk.pack(my_v);


    Blob b {buffer.data(), buffer.data() + buffer.size()};
    Request req {getNewRequestId(), n, std::move(b),
        [=](size_t rid, ParsedMessage&& msg) { /* on done */
            on_done(n, rid, {});
        },
        [=](size_t rid, bool s) { /* on expired */
            on_expired(n, rid, {});
            clearExpiredRequests(rid);
        }
    };
    requests.emplace(std::move(req));
    send(buffer.data(), buffer.size(), confirm ? 0 : MSG_CONFIRM, (sockaddr*)&n->ss, n->sslen);
    out_stats.listen++;
    return tid[2];
}

void
NetworkEngine::sendListenConfirmation(const sockaddr* sa, socklen_t salen, TransId tid) {
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

    send(buffer.data(), buffer.size(), 0, sa, salen);
}

size_t
NetworkEngine::sendAnnounceValue(std::shared_ptr<Node> n, const InfoHash& infohash, const Value& value, time_point created,
        const Blob& token, int confirm, RequestCb on_done, RequestCb on_expired) {
    auto tid = TransId {TransPrefix::ANNOUNCE_VALUES};
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(5);

    pk.pack(std::string("a")); pk.pack_map((created < now ? 5 : 4));
      pk.pack(std::string("id"));     pk.pack(myid);
      pk.pack(std::string("h"));      pk.pack(infohash);
      pk.pack(std::string("values")); pk.pack_array(1); pk.pack(value);
      if (created < now) {
          pk.pack(std::string("c"));
          pk.pack(to_time_t(created));
      }
      pk.pack(std::string("token"));  pk.pack(token);

    pk.pack(std::string("q")); pk.pack(std::string("put"));
    pk.pack(std::string("t")); pk.pack_bin(tid.size());
                               pk.pack_bin_body((const char*)tid.data(), tid.size());
    pk.pack(std::string("y")); pk.pack(std::string("q"));
    pk.pack(std::string("v")); pk.pack(my_v);

    Blob b {buffer.data(), buffer.data() + buffer.size()};
    Request req {getNewRequestId(), n, std::move(b),
        [=](size_t rid, ParsedMessage&& msg) { /* on done */
            on_done(n, rid, {});
        },
        [=](size_t rid, bool s) { /* on expired */
            on_expired(n, rid, {});
            clearExpiredRequests(rid);
        }
    };
    requests.emplace(std::move(req));
    send(buffer.data(), buffer.size(), confirm ? 0 : MSG_CONFIRM, (sockaddr*)&n->ss, n->sslen);
    out_stats.put++;
    return tid[2];
}

void
NetworkEngine::sendValueAnnounced(const sockaddr* sa, socklen_t salen, TransId tid, Value::Id vid) {
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

    send(buffer.data(), buffer.size(), 0, sa, salen);
}

void
NetworkEngine::sendError(const sockaddr* sa,
        socklen_t salen,
        TransId tid,
        uint16_t code,
        const char *message,
        bool include_id) {
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
NetworkEngine::ParsedMessage::msgpack_unpack(msgpack::object msg)
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
        nodes4 = unpackBlob(*rnodes4);

    if (auto rnodes6 = findMapValue(req, "n6"))
        nodes6 = unpackBlob(*rnodes6);

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
