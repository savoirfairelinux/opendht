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


#pragma once

#include "node_cache.h"
#include "value.h"
#include "infohash.h"
#include "node.h"
#include "scheduler.h"
#include "utils.h"
#include "rng.h"
#include "rate_limiter.h"

#include <vector>
#include <string>
#include <functional>
#include <algorithm>
#include <memory>
#include <random>
#include <queue>

namespace dht {

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

    std::string getMsg() const { return msg; }
    uint16_t getCode() const { return code; }
    const InfoHash getNodeId() const { return failing_node_id; }

private:
    std::string msg;
    uint16_t code;
    const InfoHash failing_node_id;
};

struct ParsedMessage;

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
    struct TransPrefix : public  std::array<uint8_t, 2>  {
        TransPrefix(const std::string& str) : std::array<uint8_t, 2>({{(uint8_t)str[0], (uint8_t)str[1]}}) {}
        static const TransPrefix PING;
        static const TransPrefix FIND_NODE;
        static const TransPrefix GET_VALUES;
        static const TransPrefix ANNOUNCE_VALUES;
        static const TransPrefix REFRESH;
        static const TransPrefix LISTEN;
    };
public:

    /* Transaction-ids are 4-bytes long, with the first two bytes identifying
     * the kind of request, and the remaining two a sequence number in
     * host order.
     */
    struct TransId final : public std::array<uint8_t, 4> {
        static const constexpr uint16_t INVALID {0};

        TransId() {}
        TransId(const std::array<char, 4>& o) { std::copy(o.begin(), o.end(), begin()); }
        TransId(const TransPrefix prefix, uint16_t seqno = 0) {
            std::copy_n(prefix.begin(), prefix.size(), begin());
            *reinterpret_cast<uint16_t*>(data()+prefix.size()) = seqno;
        }

        TransId(const char* q, size_t l) : array<uint8_t, 4>() {
            if (l > 4) {
                length = 0;
            } else {
                std::copy_n(q, l, begin());
                length = l;
            }
        }

        uint16_t getTid() const {
            return *reinterpret_cast<const uint16_t*>(&(*this)[2]);
        }

        bool matches(const TransPrefix prefix, uint16_t* tid = nullptr) const {
            if (std::equal(begin(), begin()+2, prefix.begin())) {
                if (tid)
                    *tid = getTid();
                return true;
            } else
                return false;
        }

        unsigned length {4};
    };

    /*!
     * @class   RequestAnswer
     * @brief   Answer for a request.
     * @details
     * Answer for a request to be (de)serialized. Used for reponding to a node
     * and looking up the response from a node.
     */
    struct RequestAnswer {
        Blob ntoken {};
        Value::Id vid {};
        std::vector<std::shared_ptr<Value>> values {};
        std::vector<std::shared_ptr<FieldValueIndex>> fields {};
        std::vector<std::shared_ptr<Node>> nodes4 {};
        std::vector<std::shared_ptr<Node>> nodes6 {};
        RequestAnswer() {}
        RequestAnswer(ParsedMessage&& msg);
    };


    /**
     * Cancel a request. Setting req->cancelled = true is not enough in the case
     * a request is "persistent".
     */
    void cancelRequest(std::shared_ptr<Request>& req);

    void connectivityChanged();

private:

    /**
     * @brief when we receive an error message.
     *
     * @param node (type: std::shared_ptr<Request>) the associated request for
     *             which we got an error;
     */
    std::function<void(std::shared_ptr<Request>, DhtProtocolException)> onError;
    /**
     * @brief when a new node happens.
     *
     * Called for every packets received for handling new nodes contacting us.
     *
     * @param id (type: InfoHash) id of the node.
     * @param saddr (type: sockaddr*) sockaddr* pointer containing address ip information.
     * @param saddr_len (type: socklen_t) lenght of the sockaddr struct.
     * @param confirm (type: int) 1 if the node sent a message, 2 if it sent us a reply.
     */
    std::function<void(const std::shared_ptr<Node>&, int)> onNewNode;
    /**
     * @brief when an addres is reported from a distant node.
     *
     * @param id (type: InfoHash) id of the node.
     * @param saddr (type: sockaddr*) sockaddr* pointer containing address ip information.
     * @param saddr_len (type: socklen_t) lenght of the sockaddr struct.
     */
    std::function<void(const InfoHash&, const SockAddr&)> onReportedAddr;
    /**
     * @brief on ping request callback.
     *
     * @param node (type: std::shared_ptr<Node>) the requesting node.
     */
    std::function<RequestAnswer(std::shared_ptr<Node>)> onPing {};
    /**
     * @brief on find node request callback.
     *
     * @param node (type: std::shared_ptr<Node>) the requesting node.
     * @param vhash (type: InfoHash) hash of the value of interest.
     * @param want (type: want_t) states if nodes sent in the response are ipv4
     *             or ipv6.
     */
    std::function<RequestAnswer(std::shared_ptr<Node>,
            const InfoHash&,
            want_t)> onFindNode {};
    /**
     * @brief on "get values" request callback.
     *
     * @param node (type: std::shared_ptr<Node>) the requesting node.
     * @param vhash (type: InfoHash) hash of the value of interest.
     * @param want (type: want_t) states if nodes sent in the response are ipv4
     *             or ipv6.
     */
    std::function<RequestAnswer(std::shared_ptr<Node>,
            const InfoHash&,
            want_t,
            const Query&)> onGetValues {};
    /**
     * @brief on listen request callback.
     *
     * @param node (type: std::shared_ptr<Node>) the requesting node.
     * @param vhash (type: InfoHash) hash of the value of interest.
     * @param token (type: Blob) security token.
     * @param rid (type: uint16_t) request id.
     */
    std::function<RequestAnswer(std::shared_ptr<Node>,
            const InfoHash&,
            const Blob&,
            uint16_t,
            const Query&)> onListen {};
    /**
     * @brief on announce request callback.
     *
     * @param node (type: std::shared_ptr<Node>) the requesting node.
     * @param vhash (type: InfoHash) hash of the value of interest.
     * @param token (type: Blob) security token.
     * @param values (type: std::vector<std::shared_ptr<Value>>) values to store.
     * @param created (type: time_point) time when the value was created.
     */
    std::function<RequestAnswer(std::shared_ptr<Node>,
            const InfoHash&,
            const Blob&,
            const std::vector<std::shared_ptr<Value>>&,
            const time_point&)> onAnnounce {};
    /**
     * @brief on refresh request callback.
     *
     * @param node (type: std::shared_ptr<Node>) the requesting node.
     * @param vhash (type: InfoHash) hash of the value of interest.
     * @param token (type: Blob) security token.
     * @param vid (type: Value::id) the value id.
     */
    std::function<RequestAnswer(std::shared_ptr<Node>,
            const InfoHash&,
            const Blob&,
            const Value::Id&)> onRefresh {};

public:
    using RequestCb = std::function<void(const Request&, RequestAnswer&&)>;
    using RequestExpiredCb = std::function<void(const Request&, bool)>;

    NetworkEngine(Logger& log, Scheduler& scheduler);
    NetworkEngine(InfoHash& myid, NetId net, int s, int s6, Logger& log, Scheduler& scheduler,
            decltype(NetworkEngine::onError) onError,
            decltype(NetworkEngine::onNewNode) onNewNode,
            decltype(NetworkEngine::onReportedAddr) onReportedAddr,
            decltype(NetworkEngine::onPing) onPing,
            decltype(NetworkEngine::onFindNode) onFindNode,
            decltype(NetworkEngine::onGetValues) onGetValues,
            decltype(NetworkEngine::onListen) onListen,
            decltype(NetworkEngine::onAnnounce) onAnnounce,
            decltype(NetworkEngine::onRefresh) onRefresh);

    virtual ~NetworkEngine();

    void clear();

    /**
     * Sends values (with closest nodes) to a listenner.
     *
     * @param sa  The address of the listenner.
     * @param sslen  The length of the sockaddr structure.
     * @param rid  The request id of the initial listen request.
     * @param hash  The hash key of the value.
     * @param want  Wether to send ipv4 and/or ipv6 nodes.
     * @param ntoken  Listen security token.
     * @param nodes  The ipv4 closest nodes.
     * @param nodes6  The ipv6 closest nodes.
     * @param values  The values to send.
     */
    void tellListener(std::shared_ptr<Node> n, uint16_t rid, const InfoHash& hash, want_t want, const Blob& ntoken,
            std::vector<std::shared_ptr<Node>>&& nodes, std::vector<std::shared_ptr<Node>>&& nodes6,
            std::vector<std::shared_ptr<Value>>&& values, const Query& q);

    bool isRunning(sa_family_t af) const;
    inline want_t want () const { return dht_socket >= 0 && dht_socket6 >= 0 ? (WANT4 | WANT6) : -1; }

    /**************
     *  Requests  *
     **************/
    std::shared_ptr<Request>
        sendPing(std::shared_ptr<Node> n, RequestCb on_done, RequestExpiredCb on_expired);
    std::shared_ptr<Request>
        sendPing(const sockaddr* sa, socklen_t salen, RequestCb on_done, RequestExpiredCb on_expired) {
            return sendPing(std::make_shared<Node>(zeroes, sa, salen), on_done, on_expired);
        }
    std::shared_ptr<Request>
        sendFindNode(std::shared_ptr<Node> n,
                const InfoHash& target,
                want_t want,
                RequestCb on_done,
                RequestExpiredCb on_expired);
    std::shared_ptr<Request>
        sendGetValues(std::shared_ptr<Node> n,
                const InfoHash& info_hash,
                const Query& query,
                want_t want,
                RequestCb on_done,
                RequestExpiredCb on_expired);
    std::shared_ptr<Request>
        sendListen(std::shared_ptr<Node> n,
                const InfoHash& infohash,
                const Query& query,
                const Blob& token,
                RequestCb on_done,
                RequestExpiredCb on_expired);
    std::shared_ptr<Request>
        sendAnnounceValue(std::shared_ptr<Node> n,
                const InfoHash& infohash,
                const std::shared_ptr<Value>& v,
                time_point created,
                const Blob& token,
                RequestCb on_done,
                RequestExpiredCb on_expired);
    std::shared_ptr<Request>
        sendRefreshValue(std::shared_ptr<Node> n,
                const InfoHash& infohash,
                const Value::Id& vid,
                const Blob& token,
                RequestCb on_done,
                RequestExpiredCb on_expired);

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

    std::shared_ptr<Node> insertNode(const InfoHash& myid, const SockAddr& addr) {
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

    void blacklistNode(const std::shared_ptr<Node>& n);

    std::vector<std::shared_ptr<Node>> getCachedNodes(const InfoHash& id, sa_family_t sa_f, size_t count) {
        return cache.getCachedNodes(id, sa_f, count);
    }

private:

    struct PartialMessage;

    /***************
     *  Constants  *
     ***************/
    static constexpr long unsigned MAX_REQUESTS_PER_SEC {1600};
    /* the length of a node info buffer in ipv4 format */
    static const constexpr size_t NODE4_INFO_BUF_LEN {26};
    /* the length of a node info buffer in ipv6 format */
    static const constexpr size_t NODE6_INFO_BUF_LEN {38};
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
    static constexpr size_t MAX_PACKET_VALUE_SIZE {8 * 1024};

    static const std::string my_v;
    static std::mt19937 rd_device;

    void process(std::unique_ptr<ParsedMessage>&&, const SockAddr& from);

    bool rateLimit(const SockAddr& addr);

    static bool isMartian(const SockAddr& addr);
    bool isNodeBlacklisted(const SockAddr& addr) const;

    void requestStep(std::shared_ptr<Request> req);

    /**
     * Sends a request to a node. Request::MAX_ATTEMPT_COUNT attempts will
     * be made before the request expires.
     */
    void sendRequest(std::shared_ptr<Request>& request);

    /**
     * Generates a new request id, skipping the invalid id.
     *
     * @return the new id.
     */
    uint16_t getNewTid() {
        ++transaction_id;
        return transaction_id == TransId::INVALID ? ++transaction_id : transaction_id;
    }

    struct MessageStats {
        unsigned ping {0};
        unsigned find {0};
        unsigned get {0};
        unsigned put {0};
        unsigned listen {0};
        unsigned refresh {0};
    };


    // basic wrapper for socket sendto function
    int send(const char *buf, size_t len, int flags, const SockAddr& addr);

    void sendValueParts(TransId tid, const std::vector<Blob>& svals, const SockAddr& addr);
    std::vector<Blob> packValueHeader(msgpack::sbuffer&, const std::vector<std::shared_ptr<Value>>&);
    void maintainRxBuffer(const TransId& tid);

    /*************
     *  Answers  *
     *************/
    /* answer to a ping  request */
    void sendPong(const SockAddr& addr, TransId tid);
    /* answer to findnodes/getvalues request */
    void sendNodesValues(const SockAddr& addr,
            TransId tid,
            const Blob& nodes,
            const Blob& nodes6,
            const std::vector<std::shared_ptr<Value>>& st,
            const Query& query,
            const Blob& token);
    Blob bufferNodes(sa_family_t af, const InfoHash& id, std::vector<std::shared_ptr<Node>>& nodes);

    std::pair<Blob, Blob> bufferNodes(sa_family_t af,
            const InfoHash& id,
            want_t want,
            std::vector<std::shared_ptr<Node>>& nodes,
            std::vector<std::shared_ptr<Node>>& nodes6);
    /* answer to a listen request */
    void sendListenConfirmation(const SockAddr& addr, TransId tid);
    /* answer to put request */
    void sendValueAnnounced(const SockAddr& addr, TransId, Value::Id);
    /* answer in case of error */
    void sendError(const SockAddr& addr,
            TransId tid,
            uint16_t code,
            const std::string& message,
            bool include_id=false);

    void deserializeNodes(ParsedMessage& msg);

    /* DHT info */
    const InfoHash& myid;
    const NetId network {0};
    const int dht_socket {-1};
    const int dht_socket6 {-1};
    const Logger& DHT_LOG;

    NodeCache cache {};

    /**
     * A comparator to classify IP addresses, only considering the
     * first 64 bits in IPv6.
     */
    struct cmpSockAddr {
        bool operator()(const SockAddr& a, const SockAddr& b) const {
            if (a.second != b.second)
                return a.second < b.second;
            socklen_t start, len;
            switch(a.getFamily()) {
                case AF_INET:
                    start = offsetof(sockaddr_in, sin_addr);
                    len = sizeof(in_addr);
                    break;
                case AF_INET6:
                    start = offsetof(sockaddr_in6, sin6_addr);
                    // don't consider more than 64 bits (IPv6)
                    len = 8;
                    break;
                default:
                    start = 0;
                    len = a.second;
                    break;
            }

            return std::memcmp((uint8_t*)&a.first+start, (uint8_t*)&b.first+start, len) < 0;
        }
    };
    // global limiting should be triggered by at least 8 different IPs
    using IpLimiter = RateLimiter<MAX_REQUESTS_PER_SEC/8>;
    using IpLimiterMap = std::map<SockAddr, IpLimiter, cmpSockAddr>;
    IpLimiterMap address_rate_limiter {};
    RateLimiter<MAX_REQUESTS_PER_SEC> rate_limiter {};

    // requests handling
    uint16_t transaction_id {1};
    std::map<uint16_t, std::shared_ptr<Request>> requests {};
    std::map<TransId, PartialMessage> partial_messages;
    MessageStats in_stats {}, out_stats {};
    std::set<SockAddr> blacklist {};

    Scheduler& scheduler;
};

}
