/*
 *  Copyright (C) 2014-2019 Savoir-faire Linux Inc.
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

#pragma once

#include "node_cache.h"
#include "value.h"
#include "infohash.h"
#include "node.h"
#include "scheduler.h"
#include "utils.h"
#include "rng.h"
#include "rate_limiter.h"
#include "log_enable.h"
#include "network_utils.h"

#include <vector>
#include <string>
#include <functional>
#include <algorithm>
#include <memory>
#include <queue>

namespace dht {
namespace net {

struct Request;
struct Socket;
struct TransId;

#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

class DhtProtocolException : public DhtException {
public:
    // sent to another peer (http-like).
    static const constexpr uint16_t NON_AUTHORITATIVE_INFORMATION {203}; /* incomplete request packet. */
    static const constexpr uint16_t UNAUTHORIZED {401};                  /* wrong tokens. */
    static const constexpr uint16_t NOT_FOUND {404};                     /* storage not found */
    // for internal use (custom).
    static const constexpr uint16_t INVALID_TID_SIZE {421};              /* id was truncated. */
    static const constexpr uint16_t UNKNOWN_TID {422};                   /* unknown tid */
    static const constexpr uint16_t WRONG_NODE_INFO_BUF_LEN {423};       /* node info length is wrong */

    static const std::string GET_NO_INFOHASH;    /* received "get" request with no infohash */
    static const std::string LISTEN_NO_INFOHASH; /* got "listen" request without infohash */
    static const std::string LISTEN_WRONG_TOKEN; /* wrong token in "listen" request */
    static const std::string PUT_NO_INFOHASH;    /* no infohash in "put" request */
    static const std::string PUT_WRONG_TOKEN;    /* got "put" request with wrong token */
    static const std::string STORAGE_NOT_FOUND;  /* got access request for an unknown storage */
    static const std::string PUT_INVALID_ID;     /* invalid id in "put" request */

    DhtProtocolException(uint16_t code, const std::string& msg="", InfoHash failing_node_id={})
        : DhtException(msg), msg(msg), code(code), failing_node_id(failing_node_id) {}

    const std::string& getMsg() const { return msg; }
    uint16_t getCode() const { return code; }
    const InfoHash& getNodeId() const { return failing_node_id; }

private:
    std::string msg;
    uint16_t code;
    InfoHash failing_node_id;
};

struct ParsedMessage;

/**
 * Answer for a request.
 */
struct RequestAnswer {
    Blob ntoken {};
    Value::Id vid {};
    std::vector<Sp<Value>> values {};
    std::vector<Value::Id> refreshed_values {};
    std::vector<Value::Id> expired_values {};
    std::vector<Sp<FieldValueIndex>> fields {};
    std::vector<Sp<Node>> nodes4 {};
    std::vector<Sp<Node>> nodes6 {};
    RequestAnswer() {}
    RequestAnswer(ParsedMessage&& msg);
};

/*!
 * @class   NetworkEngine
 * @brief   An abstraction of communication protocol on the network.
 * @details
 * The NetworkEngine processes all requests to nodes by offering a public
 * interface for handling sending and receiving packets. The following
 * parameters specify callbacks for DHT work:
 *
 * @param onError        callback for handling error messages.
 * @param onNewNode      callback for handling new nodes.
 * @param onReportedAddr callback for reporting an our address as seen from the other peer.
 * @param onPing         callback for ping request.
 * @param onFindNode     callback for "find node" request.
 * @param onGetValues    callback for "get values" request.
 * @param onListen       callback for "listen" request.
 * @param onAnnounce     callback for "announce" request.
 * @param onRefresh      callback for "refresh" request.
 */
class NetworkEngine final
{
private:
    /**
     * Called when we receive an error message.
     */
    std::function<void(Sp<Request>, DhtProtocolException)> onError;

    /**
     * Called for every packets received for handling new nodes contacting us.
     *
     * @param node: the node
     * @param confirm: 1 if the node sent a message, 2 if it sent us a reply.
     */
    std::function<void(const Sp<Node>&, int)> onNewNode;
    /**
     * Called when an addres is reported from a requested node.
     *
     * @param h: id
     * @param saddr_len (type: socklen_t) lenght of the sockaddr struct.
     */
    std::function<void(const InfoHash&, const SockAddr&)> onReportedAddr;
    /**
     * Called on ping reception.
     *
     * @param node (type: Sp<Node>) the requesting node.
     */
    std::function<RequestAnswer(Sp<Node>)> onPing {};
    /**
     * Called on find node request.
     *
     * @param node (type: Sp<Node>) the requesting node.
     * @param h (type: InfoHash) hash of the value of interest.
     * @param want (type: want_t) states if nodes sent in the response are ipv4
     *             or ipv6.
     */
    std::function<RequestAnswer(Sp<Node>, const InfoHash&, want_t)> onFindNode {};
    /**
     * Called on "get values" request.
     *
     * @param node (type: Sp<Node>) the requesting node.
     * @param h (type: InfoHash) hash of the value of interest.
     * @param want (type: want_t) states if nodes sent in the response are ipv4
     *             or ipv6.
     */
    std::function<RequestAnswer(Sp<Node>, const InfoHash&, want_t, const Query&)> onGetValues {};
    /**
     * Called on listen request.
     *
     * @param node (type: Sp<Node>) the requesting node.
     * @param h (type: InfoHash) hash of the value of interest.
     * @param token (type: Blob) security token.
     * @param rid (type: uint16_t) request id.
     */
    std::function<RequestAnswer(Sp<Node>,
            const InfoHash&,
            const Blob&,
            Tid,
            const Query&)> onListen {};
    /**
     * Called on announce request.
     *
     * @param node (type: Sp<Node>) the requesting node.
     * @param h (type: InfoHash) hash of the value of interest.
     * @param token (type: Blob) security token.
     * @param values (type: std::vector<Sp<Value>>) values to store.
     * @param created (type: time_point) time when the value was created.
     */
    std::function<RequestAnswer(Sp<Node>,
            const InfoHash&,
            const Blob&,
            const std::vector<Sp<Value>>&,
            const time_point&)> onAnnounce {};
    /**
     * Called on refresh request.
     *
     * @param node (type: Sp<Node>) the requesting node.
     * @param h (type: InfoHash) hash of the value of interest.
     * @param token (type: Blob) security token.
     * @param vid (type: Value::id) the value id.
     */
    std::function<RequestAnswer(Sp<Node>,
            const InfoHash&,
            const Blob&,
            const Value::Id&)> onRefresh {};

public:
    using RequestCb = std::function<void(const Request&, RequestAnswer&&)>;
    using RequestExpiredCb = std::function<void(const Request&, bool)>;

    NetworkEngine(Logger& log, Scheduler& scheduler, std::unique_ptr<DatagramSocket>&& sock);
    NetworkEngine(InfoHash& myid, NetId net, std::unique_ptr<DatagramSocket>&& sock, Logger& log, Scheduler& scheduler,
            decltype(NetworkEngine::onError)&& onError,
            decltype(NetworkEngine::onNewNode)&& onNewNode,
            decltype(NetworkEngine::onReportedAddr)&& onReportedAddr,
            decltype(NetworkEngine::onPing)&& onPing,
            decltype(NetworkEngine::onFindNode)&& onFindNode,
            decltype(NetworkEngine::onGetValues)&& onGetValues,
            decltype(NetworkEngine::onListen)&& onListen,
            decltype(NetworkEngine::onAnnounce)&& onAnnounce,
            decltype(NetworkEngine::onRefresh)&& onRefresh);

    ~NetworkEngine();

    net::DatagramSocket* getSocket() const { return dht_socket.get(); };

    void clear();

    /**
     * Sends values (with closest nodes) to a listenner.
     *
     * @param sa          The address of the listenner.
     * @param sslen       The length of the sockaddr structure.
     * @param socket_id  The tid to use to write to the request socket.
     * @param hash        The hash key of the value.
     * @param want        Wether to send ipv4 and/or ipv6 nodes.
     * @param ntoken      Listen security token.
     * @param nodes       The ipv4 closest nodes.
     * @param nodes6      The ipv6 closest nodes.
     * @param values      The values to send.
     */
    void tellListener(Sp<Node> n, Tid socket_id, const InfoHash& hash, want_t want, const Blob& ntoken,
            std::vector<Sp<Node>>&& nodes, std::vector<Sp<Node>>&& nodes6,
            std::vector<Sp<Value>>&& values, const Query& q);

    void tellListenerRefreshed(Sp<Node> n, Tid socket_id, const InfoHash& hash, const Blob& ntoken, const std::vector<Value::Id>& values);
    void tellListenerExpired(Sp<Node> n, Tid socket_id, const InfoHash& hash, const Blob& ntoken, const std::vector<Value::Id>& values);

    bool isRunning(sa_family_t af) const;
    inline want_t want () const { return dht_socket->hasIPv4() and dht_socket->hasIPv6() ? (WANT4 | WANT6) : -1; }

    void connectivityChanged(sa_family_t);

    /**************
     *  Requests  *
     **************/

    /**
     * Send a "ping" request to a given node.
     *
     * @param n           The node.
     * @param on_done     Request callback when the request is completed.
     * @param on_expired  Request callback when the request expires.
     *
     * @return the request with information concerning its success.
     */
    Sp<Request>
        sendPing(Sp<Node> n, RequestCb&& on_done, RequestExpiredCb&& on_expired);
    /**
     * Send a "ping" request to a given node.
     *
     * @param sa          The node's ip sockaddr info.
     * @param salen       The associated sockaddr struct length.
     * @param on_done     Request callback when the request is completed.
     * @param on_expired  Request callback when the request expires.
     *
     * @return the request with information concerning its success.
     */
    Sp<Request>
        sendPing(const sockaddr* sa, socklen_t salen, RequestCb&& on_done, RequestExpiredCb&& on_expired) {
            return sendPing(std::make_shared<Node>(zeroes, sa, salen),
                    std::forward<RequestCb>(on_done),
                    std::forward<RequestExpiredCb>(on_expired));
        }
    /**
     * Send a "find node" request to a given node.
     *
     * @param n           The node.
     * @param target      The target hash.
     * @param want        Indicating wether IPv4 or IPv6 are wanted in response.
     *                    Use NetworkEngine::want()
     * @param on_done     Request callback when the request is completed.
     * @param on_expired  Request callback when the request expires.
     *
     * @return the request with information concerning its success.
     */
    Sp<Request> sendFindNode(Sp<Node> n,
                             const InfoHash& hash,
                             want_t want = -1,
                             RequestCb&& on_done = {},
                             RequestExpiredCb&& on_expired = {});
    /**
     * Send a "get" request to a given node.
     *
     * @param n           The node.
     * @param hash        The target hash.
     * @param query       The query describing filters.
     * @param token       A security token.
     * @param want        Indicating wether IPv4 or IPv6 are wanted in response.
     *                    Use NetworkEngine::want()
     * @param on_done     Request callback when the request is completed.
     * @param on_expired  Request callback when the request expires.
     *
     * @return the request with information concerning its success.
     */
    Sp<Request> sendGetValues(Sp<Node> n,
                              const InfoHash& hash,
                              const Query& query,
                              want_t want,
                              RequestCb&& on_done,
                              RequestExpiredCb&& on_expired);
    /**
     * Send a "listen" request to a given node.
     *
     * @param n           The node.
     * @param hash        The storage's hash.
     * @param query       The query describing filters.
     * @param token       A security token.
     * @param previous    The previous request "listen" sent to this node.
     * @param socket      **UNUSED** The socket for further response.
     *
     *                    For backward compatibility purpose, sendListen has to
     *                    handle creation of the socket. Therefor, you cannot
     *                    use openSocket yourself. TODO: Once we don't support
     *                    the old "listen" negociation, sendListen shall not
     *                    create the socket itself.
     *
     * @param on_done     Request callback when the request is completed.
     * @param on_expired  Request callback when the request expires.
     * @param socket_cb   Callback to execute each time new updates arrive on
     *                    the socket.
     *
     * @return the request with information concerning its success.
     */
    Sp<Request> sendListen(Sp<Node> n,
                           const InfoHash& hash,
                           const Query& query,
                           const Blob& token,
                           Sp<Request> previous,
                           RequestCb&& on_done,
                           RequestExpiredCb&& on_expired,
                           SocketCb&& socket_cb);
    /**
     * Send a "announce" request to a given node.
     *
     * @param n           The node.
     * @param hash        The target hash.
     * @param created     The time when the value was created (avoiding extended
     *                    value lifetime)
     * @param token       A security token.
     * @param on_done     Request callback when the request is completed.
     * @param on_expired  Request callback when the request expires.
     *
     * @return the request with information concerning its success.
     */
    Sp<Request> sendAnnounceValue(Sp<Node> n,
                                  const InfoHash& hash,
                                  const Sp<Value>& v,
                                  time_point created,
                                  const Blob& token,
                                  RequestCb&& on_done,
                                  RequestExpiredCb&& on_expired);
    /**
     * Send a "refresh" request to a given node. Asks a node to keep the
     * associated value Value.type.expiration more minutes in its storage.
     *
     * @param n           The node.
     * @param hash        The target hash.
     * @param vid         The value id.
     * @param token       A security token.
     * @param on_done     Request callback when the request is completed.
     * @param on_expired  Request callback when the request expires.
     *
     * @return the request with information concerning its success.
     */
    Sp<Request> sendRefreshValue(Sp<Node> n,
                                 const InfoHash& hash,
                                 const Value::Id& vid,
                                 const Blob& token,
                                 RequestCb&& on_done,
                                 RequestExpiredCb&& on_expired);

    /**
     * Parses a message and calls appropriate callbacks.
     *
     * @param buf  The buffer containing the binary message.
     * @param buflen  The length of the buffer.
     * @param from  The address info of the sender.
     * @param fromlen  The length of the corresponding sockaddr structure.
     * @param now  The time to adjust the clock in the network engine.
     */
    void processMessage(const uint8_t *buf, size_t buflen, const SockAddr& addr);

    Sp<Node> insertNode(const InfoHash& myid, const SockAddr& addr) {
        auto n = cache.getNode(myid, addr, scheduler.time(), 0);
        onNewNode(n, 0);
        return n;
    }

    std::vector<unsigned> getNodeMessageStats(bool in) {
        auto& st = in ? in_stats : out_stats;
        std::vector<unsigned> stats {st.ping,  st.find,  st.get,  st.listen,  st.put};
        st = {};
        return stats;
    }

    void blacklistNode(const Sp<Node>& n);

    std::vector<Sp<Node>> getCachedNodes(const InfoHash& id, sa_family_t sa_f, size_t count) {
        return cache.getCachedNodes(id, sa_f, count);
    }

private:

    struct PartialMessage;

    /***************
     *  Constants  *
     ***************/
    static constexpr size_t MAX_REQUESTS_PER_SEC {1600};
    /* the length of a node info buffer in ipv4 format */
    static const constexpr size_t NODE4_INFO_BUF_LEN {HASH_LEN + sizeof(in_addr) + sizeof(in_port_t)};
    /* the length of a node info buffer in ipv6 format */
    static const constexpr size_t NODE6_INFO_BUF_LEN {HASH_LEN + sizeof(in6_addr) + sizeof(in_port_t)};
    /* after a UDP reply, the period during which we tell the link layer about it */
    static constexpr std::chrono::seconds UDP_REPLY_TIME {15};

    /* Max. time to receive a full fragmented packet */
    static constexpr std::chrono::seconds RX_MAX_PACKET_TIME {10};
    /* Max. time between packet fragments */
    static constexpr std::chrono::seconds RX_TIMEOUT {3};
    /* The maximum number of nodes that we snub.  There is probably little
        reason to increase this value. */
    static constexpr unsigned BLACKLISTED_MAX {10};

    static constexpr size_t MTU {1280};
    static constexpr size_t MAX_PACKET_VALUE_SIZE {600};

    static const std::string my_v;

    void process(std::unique_ptr<ParsedMessage>&&, const SockAddr& from);

    bool rateLimit(const SockAddr& addr);

    static bool isMartian(const SockAddr& addr);
    bool isNodeBlacklisted(const SockAddr& addr) const;

    void requestStep(Sp<Request> req);

    /**
     * Sends a request to a node. Request::MAX_ATTEMPT_COUNT attempts will
     * be made before the request expires.
     */
    void sendRequest(const Sp<Request>& request);

    struct MessageStats {
        unsigned ping    {0};
        unsigned find    {0};
        unsigned get     {0};
        unsigned put     {0};
        unsigned listen  {0};
        unsigned refresh {0};
    };


    // basic wrapper for socket sendto function
    int send(const SockAddr& addr, const char *buf, size_t len, bool confirmed = false);

    void sendValueParts(const TransId& tid, const std::vector<Blob>& svals, const SockAddr& addr);
    std::vector<Blob> packValueHeader(msgpack::sbuffer&, const std::vector<Sp<Value>>&);
    void maintainRxBuffer(Tid tid);

    /*************
     *  Answers  *
     *************/
    /* answer to a ping  request */
    void sendPong(const SockAddr& addr, Tid tid);
    /* answer to findnodes/getvalues request */
    void sendNodesValues(const SockAddr& addr,
            Tid tid,
            const Blob& nodes,
            const Blob& nodes6,
            const std::vector<Sp<Value>>& st,
            const Query& query,
            const Blob& token);
    Blob bufferNodes(sa_family_t af, const InfoHash& id, std::vector<Sp<Node>>& nodes);

    std::pair<Blob, Blob> bufferNodes(sa_family_t af,
            const InfoHash& id,
            want_t want,
            std::vector<Sp<Node>>& nodes,
            std::vector<Sp<Node>>& nodes6);
    /* answer to a listen request */
    void sendListenConfirmation(const SockAddr& addr, Tid tid);
    /* answer to put request */
    void sendValueAnnounced(const SockAddr& addr, Tid, Value::Id);
    /* answer in case of error */
    void sendError(const SockAddr& addr,
            Tid tid,
            uint16_t code,
            const std::string& message,
            bool include_id=false);

    void deserializeNodes(ParsedMessage& msg, const SockAddr& from);

    /* DHT info */
    const InfoHash& myid;
    const NetId network {0};
    const std::unique_ptr<DatagramSocket> dht_socket;
    const Logger& DHT_LOG;

    NodeCache cache {};

    // global limiting should be triggered by at least 8 different IPs
    using IpLimiter = RateLimiter<MAX_REQUESTS_PER_SEC/8>;
    using IpLimiterMap = std::map<SockAddr, IpLimiter, SockAddr::ipCmp>;
    IpLimiterMap address_rate_limiter {};
    RateLimiter<MAX_REQUESTS_PER_SEC> rate_limiter {};
    size_t limiter_maintenance {0};

    // requests handling
    std::map<Tid, Sp<Request>> requests {};
    std::map<Tid, PartialMessage> partial_messages;

    MessageStats in_stats {}, out_stats {};
    std::set<SockAddr> blacklist {};

    Scheduler& scheduler;

    bool logIncoming_ {false};
};

} /* namespace net  */
} /* namespace dht */
