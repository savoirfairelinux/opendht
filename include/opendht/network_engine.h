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

#include "value.h"
#include "infohash.h"
#include "node.h"
#include "scheduler.h"
#include "utils.h"
#include "rng.h"

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
    // for internal use (custom).
    static const constexpr uint16_t INVALID_TID_SIZE {421};              /* id was truncated. */
    static const constexpr uint16_t UNKNOWN_TID {422};                   /* unknown tid */
    static const constexpr uint16_t WRONG_NODE_INFO_BUF_LEN {423};       /* node info length is wrong */

    static const std::string GET_NO_INFOHASH;    /* received "get" request with no infohash */
    static const std::string LISTEN_NO_INFOHASH; /* got "listen" request without infohash */
    static const std::string LISTEN_WRONG_TOKEN; /* wrong token in "listen" request */
    static const std::string PUT_NO_INFOHASH;    /* no infohash in "put" request */
    static const std::string PUT_WRONG_TOKEN;    /* got "put" request with wrong token */
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
 */
class NetworkEngine final {
    struct TransPrefix : public  std::array<uint8_t, 2>  {
        TransPrefix(const std::string& str) : std::array<uint8_t, 2>({{(uint8_t)str[0], (uint8_t)str[1]}}) {}
        static const TransPrefix PING;
        static const TransPrefix FIND_NODE;
        static const TransPrefix GET_VALUES;
        static const TransPrefix ANNOUNCE_VALUES;
        static const TransPrefix LISTEN;
    };

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
        InfoHash info_hash;                         /* hash for which values are requested */
        InfoHash target;                            /* target id around which to find nodes */
        TransId tid;                                /* transaction id */
        Blob token;                                 /* security token */
        Value::Id value_id;                         /* the value id */
        time_point created { time_point::max() };   /* time when value was first created */
        Blob nodes4;                                /* IPv4 nodes in response to a 'find' request */
        Blob nodes6;                                /* IPv6 nodes in response to a 'find' request */
        std::vector<std::shared_ptr<Value>> values; /* values for a 'get' request */
        want_t want;                                /* states if ipv4 or ipv6 request */
        uint16_t error_code;                        /* error code in case of error */
        std::string ua;
        Address addr;                               /* reported address by the distant node */
        void msgpack_unpack(msgpack::object o);
    };

public:
    /*!
     * @class   RequestAnswer
     * @brief   Answer for a request.
     * @details
     * Answer for a request to be (de)serialized. Used for reponding to a node
     * and looking up the response from a node.
     */
    struct RequestAnswer {
        Blob ntoken;
        Value::Id vid;
        std::vector<std::shared_ptr<Value>> values;
        std::vector<std::shared_ptr<Node>> nodes;
        std::vector<std::shared_ptr<Node>> nodes6;
    };


    /*!
     * @class   Request
     * @brief   An atomic request destined to a node.
     * @details
     * A request contains data used by the NetworkEngine to process a request
     * desitned to specific node and std::function callbacks to execute when the
     * request is done.
     */
    struct Request {
        friend class dht::NetworkEngine;

        static const constexpr size_t MAX_ATTEMPT_COUNT {3};

        std::shared_ptr<Node> node {};             /* the node to whom the request is destined. */
        bool cancelled {false};                    /* whether the request is canceled before done. */
        bool completed {false};                    /* whether the request is completed. */
        unsigned attempt_count {0};                /* number of attempt to process the request. */
        time_point start {time_point::min()};      /* time when the request is created. */
        time_point last_try {time_point::min()};   /* time of the last attempt to process the request. */
        time_point reply_time {time_point::min()}; /* time when we received the response to the request. */

        bool expired(time_point now) const {
            return now > last_try + Node::MAX_RESPONSE_TIME and attempt_count >= Request::MAX_ATTEMPT_COUNT
                and not completed;
        }

        bool pending(time_point now) const {
            return not cancelled  
               and not completed 
               and reply_time < last_try
               and now - last_try <= Node::MAX_RESPONSE_TIME;
        }

        Request() {}

    private:
        Request(uint16_t tid,
                std::shared_ptr<Node> node,
                Blob &&msg,
                std::function<void(std::shared_ptr<Request> req_status, ParsedMessage&&)> on_done,
                std::function<void(std::shared_ptr<Request> req_status, bool)> on_expired, bool persistent = false) :
            node(node), on_done(on_done), on_expired(on_expired), tid(tid), msg(std::move(msg)), persistent(persistent) { }

        std::function<void(std::shared_ptr<Request> req_status, ParsedMessage&&)> on_done {};
        std::function<void(std::shared_ptr<Request> req_status, bool)> on_expired {};

        const uint16_t tid {0};                   /* the request id. */
        const Blob msg {};                              /* the serialized message. */
        const bool persistent {false};            /* the request is not erased upon completion. */
    };

    /**
     * Cancel a request. Setting req->cancelled = true is not enough in the case
     * a request is "persistent".
     */
    void cancelRequest(std::shared_ptr<Request>& req) {
        if (req) {
            req->cancelled = true;
            req->on_done = {};
            req->on_expired = {};
            requests.erase(req->tid);
        }
    }

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
    std::function<std::shared_ptr<Node>(const InfoHash&, const sockaddr*, socklen_t, int)> onNewNode;
    /**
     * @brief when an addres is reported from a distant node.
     *
     * @param id (type: InfoHash) id of the node.
     * @param saddr (type: sockaddr*) sockaddr* pointer containing address ip information.
     * @param saddr_len (type: socklen_t) lenght of the sockaddr struct.
     */
    std::function<void(const InfoHash&, sockaddr*, socklen_t)> onReportedAddr;
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
            InfoHash&,
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
            InfoHash&,
            want_t)> onGetValues {};
    /**
     * @brief on listen request callback.
     *
     * @param node (type: std::shared_ptr<Node>) the requesting node.
     * @param vhash (type: InfoHash) hash of the value of interest.
     * @param token (type: Blob) security token.
     * @param rid (type: uint16_t) request id.
     */
    std::function<RequestAnswer(std::shared_ptr<Node>,
            InfoHash&,
            Blob&,
            uint16_t)> onListen {};
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
            InfoHash&,
            Blob&,
            std::vector<std::shared_ptr<Value>>,
            time_point)> onAnnounce {};

public:
    using RequestCb = std::function<void(std::shared_ptr<Request>, RequestAnswer&&)>;
    using RequestExpiredCb = std::function<void(std::shared_ptr<Request>, bool)>;

    NetworkEngine(Logger& log, Scheduler& scheduler) : myid(zeroes), DHT_LOG(log), scheduler(scheduler) {}
    NetworkEngine(InfoHash& myid, int s, int s6, Logger& log, Scheduler& scheduler,
            decltype(NetworkEngine::onError) onError,
            decltype(NetworkEngine::onNewNode) onNewNode,
            decltype(NetworkEngine::onReportedAddr) onReportedAddr,
            decltype(NetworkEngine::onPing) onPing,
            decltype(NetworkEngine::onFindNode) onFindNode,
            decltype(NetworkEngine::onGetValues) onGetValues,
            decltype(NetworkEngine::onListen) onListen,
            decltype(NetworkEngine::onAnnounce) onAnnounce) :
        onError(onError), onNewNode(onNewNode), onReportedAddr(onReportedAddr), onPing(onPing), onFindNode(onFindNode),
        onGetValues(onGetValues), onListen(onListen), onAnnounce(onAnnounce), myid(myid),
        dht_socket(s), dht_socket6(s6), DHT_LOG(log), scheduler(scheduler)
    {
        transaction_id = std::uniform_int_distribution<decltype(transaction_id)>{1}(rd_device);
    }
    virtual ~NetworkEngine() {
        clear();
    };

    void clear() {
        for (auto& req : requests) {
            req.second->on_expired = {};
            req.second->on_done = {};
        }
        requests.clear();
    }

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
    void tellListener(const sockaddr* sa, socklen_t salen, uint16_t rid, InfoHash hash, want_t want, Blob ntoken,
            std::vector<std::shared_ptr<Node>> nodes, std::vector<std::shared_ptr<Node>> nodes6,
            std::vector<std::shared_ptr<Value>> values);

    bool isRunning(sa_family_t af) const;
    inline want_t want () const { return dht_socket >= 0 && dht_socket6 >= 0 ? (WANT4 | WANT6) : -1; }

    /**************
     *  Requests  *
     **************/
    std::shared_ptr<Request>
        sendPing(std::shared_ptr<Node> n, RequestCb on_done, RequestExpiredCb on_expired) {
            return sendPing((sockaddr*)&n->ss, n->sslen, on_done, on_expired);
        }
    std::shared_ptr<Request>
        sendPing(const sockaddr* sa, socklen_t salen, RequestCb on_done, RequestExpiredCb on_expired);
    std::shared_ptr<Request>
        sendFindNode(std::shared_ptr<Node> n,
                const InfoHash& target,
                want_t want,
                RequestCb on_done,
                RequestExpiredCb on_expired);
    std::shared_ptr<Request>
        sendGetValues(std::shared_ptr<Node> n,
                const InfoHash& target,
                want_t want,
                RequestCb on_done,
                RequestExpiredCb on_expired);
    std::shared_ptr<Request>
        sendListen(std::shared_ptr<Node> n,
                const InfoHash& infohash,
                const Blob& token,
                RequestCb on_done,
                RequestExpiredCb on_expired);
    std::shared_ptr<Request>
        sendAnnounceValue(std::shared_ptr<Node> n,
                const InfoHash& infohash,
                const Value& v,
                time_point created,
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
    void processMessage(const uint8_t *buf, size_t buflen, const sockaddr *from, socklen_t fromlen);

    std::vector<unsigned> getNodeMessageStats(bool in) {
        auto stats = in ? std::vector<unsigned>{in_stats.ping,  in_stats.find,  in_stats.get,  in_stats.listen,  in_stats.put}
        : std::vector<unsigned>{out_stats.ping, out_stats.find, out_stats.get, out_stats.listen, out_stats.put};
        if (in) { in_stats = {}; }
        else { out_stats = {}; }

        return stats;
    }

private:
    /***************
     *  Constants  *
     ***************/
    static constexpr long unsigned MAX_REQUESTS_PER_SEC {1600};
    /* the length of a node info buffer in ipv4 format */
    static const constexpr size_t NODE4_INFO_BUF_LEN {26};
    /* the length of a node info buffer in ipv6 format */
    static const constexpr size_t NODE6_INFO_BUF_LEN {38};
    /* TODO */
    static constexpr std::chrono::seconds UDP_REPLY_TIME {15};
    /* TODO */
    static const std::string my_v;

    /* DHT info */
    const InfoHash& myid;
    const int dht_socket {-1};
    const int dht_socket6 {-1};
    const Logger& DHT_LOG;

    bool rateLimit();

    void pinged(Node&);

    void requestStep(std::shared_ptr<Request> req) {
        if (req->completed or req->cancelled)
            return;

        auto now = scheduler.time();
        if (req->expired(now)) {
            req->on_expired(req, true);
            req->on_expired = {};
            req->on_done = {};
            requests.erase(req->tid);
            return;
        } else if (req->attempt_count == 1) {
            req->on_expired(req, false);
        }

        send((char*)req->msg.data(), req->msg.size(),
                (req->node->reply_time >= now - UDP_REPLY_TIME) ? 0 : MSG_CONFIRM,
                (sockaddr*)&req->node->ss, req->node->sslen);
        pinged(*req->node);
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
    void sendRequest(std::shared_ptr<Request>& request) {
        request->start = scheduler.time();
        auto e = requests.emplace(request->tid, request);
        if (!e.second) {
            DHT_LOG.ERROR("Request already existed !");
        }
        requestStep(request);
    }

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
    };


    // basic wrapper for socket sendto function
    int send(const char *buf, size_t len, int flags, const sockaddr *sa, socklen_t salen);

    /*************
     *  Answers  *
     *************/
    /* answer to a ping  request */
    void sendPong(const sockaddr* sa, socklen_t salen, TransId tid);
    /* answer to findnodes/getvalues request */
    void sendNodesValues(const sockaddr* sa,
            socklen_t salen,
            TransId tid,
            const Blob& nodes,
            const Blob& nodes6,
            const std::vector<std::shared_ptr<Value>>& st,
            const Blob& token);
    unsigned insertClosestNode(uint8_t *nodes, unsigned numnodes, const InfoHash& id, const Node& n);
    std::pair<Blob, Blob> bufferNodes(sa_family_t af,
            const InfoHash& id,
            want_t want,
            const std::vector<std::shared_ptr<Node>>& nodes,
            const std::vector<std::shared_ptr<Node>>& nodes6);
    /* answer to a listen request */
    void sendListenConfirmation(const sockaddr* sa, socklen_t salen, TransId tid);
    /* answer to put request */
    void sendValueAnnounced(const sockaddr* sa, socklen_t salen, TransId, Value::Id);
    /* answer in case of error */
    void sendError(const sockaddr* sa,
            socklen_t salen,
            TransId tid,
            uint16_t code,
            const char *message,
            bool include_id=false);

    RequestAnswer deserializeNodesValues(ParsedMessage& msg);

    std::queue<time_point> rate_limit_time {};
    static std::mt19937 rd_device;

    // requests handling
    uint16_t transaction_id {1};
    std::map<uint16_t, std::shared_ptr<Request>> requests {};
    MessageStats in_stats {}, out_stats {};

    Scheduler& scheduler;
};

}
