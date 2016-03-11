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
     * @class   RequestStatus
     * @brief   Request info for DHT layer.
     * @details
     * Request info associated to a NetworkEngine request. This enables
     * interracting with the NetworkEngine by cancelling a request or extracting
     * information like the reply time for that request.
     */
    struct RequestStatus {
        static const constexpr size_t MAX_ATTEMPT_COUNT {3};

        std::shared_ptr<Node> node {};             /* the node to whom the request is destined. */
        bool cancelled {false};                    /* whether the request is canceled before done. */
        bool completed {false};                    /* whether the request is completed. */
        unsigned attempt_count {0};                /* number of attempt to process the request. */
        time_point start {time_point::min()};      /* time when the request is created. */
        time_point last_try {time_point::min()};   /* time of the last attempt to process the request. */
        time_point reply_time {time_point::min()}; /* time when we received the response from the node. */

        RequestStatus() {}
        RequestStatus(time_point start, time_point reply_time = time_point::min())
            : start(start), last_try(start), reply_time(reply_time) {}

        bool expired(time_point now) const {
            return now > last_try + Node::MAX_RESPONSE_TIME and attempt_count >= RequestStatus::MAX_ATTEMPT_COUNT
                and not completed;
        }
        bool pending(time_point now) const {
            return reply_time < last_try && now - last_try <= Node::MAX_RESPONSE_TIME;
        }
    };

private:

    /**
     * @brief when we receive an error message.
     *
     * @param node (type: std::shared_ptr<Request>) the associated request for
     *             which we got an error;
     */
    std::function<void(std::shared_ptr<RequestStatus>, DhtProtocolException)> onError;
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
    /**
     * @brief callback after the processing of a request is over.
     *
     * @param success (type: bool) true if no error occured, else false.
     */
    using RequestCb = std::function<void(std::shared_ptr<RequestStatus>, RequestAnswer&&)>;

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
    virtual ~NetworkEngine() {};

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
    std::shared_ptr<RequestStatus>
        sendPing(std::shared_ptr<Node> n, RequestCb on_done, RequestCb on_expired) {
            return sendPing((sockaddr*)&n->ss, n->sslen, on_done, on_expired);
        }
    std::shared_ptr<RequestStatus>
        sendPing(const sockaddr* sa, socklen_t salen, RequestCb on_done, RequestCb on_expired);
    std::shared_ptr<RequestStatus>
        sendFindNode(std::shared_ptr<Node> n,
                const InfoHash& target,
                want_t want,
                RequestCb on_done,
                RequestCb on_expired);
    std::shared_ptr<RequestStatus>
        sendGetValues(std::shared_ptr<Node> n,
                const InfoHash& target,
                want_t want,
                RequestCb on_done,
                RequestCb on_expired);
    std::shared_ptr<RequestStatus>
        sendListen(std::shared_ptr<Node> n,
                const InfoHash& infohash,
                const Blob& token,
                RequestCb on_done,
                RequestCb on_expired);
    std::shared_ptr<RequestStatus>
        sendAnnounceValue(std::shared_ptr<Node> n,
                const InfoHash& infohash,
                const Value& v,
                time_point created,
                const Blob& token,
                RequestCb on_done,
                RequestCb on_expired);

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

        bool matches(const TransPrefix prefix, uint16_t *seqno_return = nullptr) const {
            if (std::equal(begin(), begin()+2, prefix.begin())) {
                if (seqno_return)
                    *seqno_return = *reinterpret_cast<const uint16_t*>(&(*this)[2]);
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
        InfoHash id;
        InfoHash info_hash;
        InfoHash target;
        TransId tid;
        Blob token;
        Value::Id value_id;
        time_point created { time_point::max() };
        Blob nodes4;
        Blob nodes6;
        std::vector<std::shared_ptr<Value>> values;
        want_t want;
        uint16_t error_code;
        std::string ua;
        Address addr;
        void msgpack_unpack(msgpack::object o);
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
        Request(uint16_t tid,
                std::shared_ptr<Node> node,
                Blob &&msg,
                std::function<void(std::shared_ptr<RequestStatus> req_status, ParsedMessage&&)> on_done,
                std::function<void(std::shared_ptr<RequestStatus> req_status, bool)> on_expired) :
            on_done(on_done), on_expired(on_expired), tid(tid), msg(msg), status(std::make_shared<RequestStatus>()) {
                status->node = node;
            }

        std::function<void(std::shared_ptr<RequestStatus> req_status, ParsedMessage&&)> on_done {};
        std::function<void(std::shared_ptr<RequestStatus> req_status, bool)> on_expired {};

        const uint16_t tid {0};                   /* the request id. */
        Blob msg {};                              /* the serialized message. */
        std::shared_ptr<RequestStatus> status {}; /* the request info for DHT layer. */
    };

    void requestStep(std::shared_ptr<Request> req) {
        if (req->status->completed or req->status->cancelled)
            return;
        auto now = scheduler.time();
        if (req->status->expired(now)) {
            req->on_expired(req->status, false);
            requests.erase(req->tid);
            return;
        }

        send((char*)req->msg.data(), req->msg.size(),
                (req->status->node->reply_time >= now - UDP_REPLY_TIME) ? 0 : MSG_CONFIRM,
                (sockaddr*)&req->status->node->ss, req->status->node->sslen);
        ++req->status->attempt_count;
        req->status->last_try = now;
        std::weak_ptr<Request> wreq = req;
        scheduler.add(req->status->last_try + Node::MAX_RESPONSE_TIME, [this,wreq]() {
            if (auto req = wreq.lock()) {
                requestStep(req);
            }
        });
    }

    /**
     * Sends a request to a node. RequestStatus::MAX_ATTEMPT_COUNT attempts will
     * be made before the request expires.
     */
    void sendRequest(Request&& request) {
        auto sreq = std::make_shared<Request>(std::move(request));
        sreq->status->start = scheduler.time();
        requests.emplace(request.tid, sreq);
        requestStep(sreq);
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
    time_point now;

    // requests handling
    uint16_t transaction_id {1};
    std::map<uint16_t, std::shared_ptr<Request>> requests;
    MessageStats in_stats {}, out_stats {};

    Scheduler& scheduler;
};

}
