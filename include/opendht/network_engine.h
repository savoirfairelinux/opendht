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
#include "utils.h"
#include "rng.h"

#include <vector>
#include <string>
#include <functional>
#include <algorithm>
#include <memory>
#include <random>

namespace dht {

class DhtProtocolException : public DhtException {
public:
    // sent to another peer (http-like).
    static const constexpr uint16_t NON_AUTHORITATIVE_INFORMATION {203}; /* incomplete request packet. */
    static const constexpr uint16_t UNAUTHORIZED {401};                  /* wrong tokens. */
    // for internal use (custom).
    static const constexpr uint16_t TRUNCATED_ID {421};                  /* id was truncated. */
    static const constexpr uint16_t WRONG_NODE_INFO_BUF_LEN {422};       /* node info length is wrong */

    static const std::string GET_NO_INFOHASH; /* received get request with no infohash */
    static const std::string LISTEN_NO_INFOHASH;     /* got listen request without infohash */
    static const std::string LISTEN_WRONG_TOKEN;     /* wrong token in listen request */
    static const std::string PUT_NO_INFOHASH;        /* no infohash in put request */
    static const std::string PUT_WRONG_TOKEN;        /* got put request with wrong token */
    static const std::string PUT_INVALID_ID;         /* invalid id in put request */

    DhtProtocolException(uint16_t code, const std::string& msg="") : DhtException(msg), code(code), msg(msg) {}

    std::string getMsg() { return msg; }
    uint16_t getCode() { return code; }

private:
    uint16_t code;
    std::string msg;
};

/*!
 * @class   NetworkEngine
 * @brief   A protocol abstraction of communication on the network.
 * @details
 * The NetworkEngine processes all requests to nodes by offering a public
 * interface for handling sending and receiving packets. The following
 * parameters specify callbacks for DHT work:
 *
 * @param onPing       callback for ping request.
 * @param onFindNode   callback for "find node" request.
 * @param onGetValues  callback for "get values" request.
 * @param onListen     callback for "listen" request.
 * @param onAnnounce   callback for "announce" request.
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
        std::vector<std::shared_ptr<Value>> values;
        std::vector<std::shared_ptr<Node>> nodes;
        std::vector<std::shared_ptr<Node>> nodes6;
    };

private:
    /**
     * @brief when a new node happens.
     *
     * Called for every packets received for handling new nodes contacting us.
     *
     * @param id (type: InfoHash) id of the node.
     * @param saddr (type: sockaddr*) sockaddr* pointer containing address ip information.
     * @param saddr_len (type: socklen_t) lenght of the sockaddr struct.
     */
    std::function<std::shared_ptr<Node>(const InfoHash&, const sockaddr*, socklen_t, int)> onNewNode;
    /**
     * @brief when an addres is reported from a distant node.
     *
     * @param arg1  Arg description
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
     * @param rid (type: size_t) request id.
     */
    std::function<RequestAnswer(std::shared_ptr<Node>,
            InfoHash&,
            Blob&,
            size_t)> onListen {};
    /**
     * @brief on announce request callback.
     *
     * @param node (type: std::shared_ptr<Node>) the requesting node.
     * @param vhash (type: InfoHash) hash of the value of interest.
     * @param token (type: Blob) security token.
     * @param value (type: std::shared_ptr<Value>) value to send.
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
    using RequestCb = std::function<void(std::shared_ptr<Node>, size_t rid, RequestAnswer&&)>;

    // Config from Dht.
    struct DhtInfo {
        const InfoHash& myid;
        const int& dht_socket;
        const int& dht_socket6;
        const Logger& DHT_LOG;
    };

    NetworkEngine(DhtInfo info,
            decltype(NetworkEngine::onNewNode) onNewNode,
            decltype(NetworkEngine::onReportedAddr) onReportedAddr,
            decltype(NetworkEngine::onPing) onPing,
            decltype(NetworkEngine::onFindNode) onFindNode,
            decltype(NetworkEngine::onGetValues) onGetValues,
            decltype(NetworkEngine::onListen) onListen,
            decltype(NetworkEngine::onAnnounce) onAnnounce) :
        onNewNode(onNewNode), onReportedAddr(onReportedAddr), onPing(onPing), onFindNode(onFindNode),
        onGetValues(onGetValues), onListen(onListen), onAnnounce(onAnnounce), myid(info.myid),
        dht_socket(info.dht_socket), dht_socket6(info.dht_socket6), DHT_LOG(info.DHT_LOG)
    {
        req_ids = std::uniform_int_distribution<decltype(req_ids)>{1}(rd_device);
    }
    virtual ~NetworkEngine() {};


    /**
     * Cancel an ongoing request before it's processed.
     *
     * @param rid  The request id.
     *
     * @return true if it can be canceled, false otherwise.
     */
    bool cancelRequest(size_t rid);

    /**************
     *  Requests  *
     **************/
    size_t sendPing(std::shared_ptr<Node> n, RequestCb on_done, RequestCb on_expired);
    size_t sendFindNode(std::shared_ptr<Node> n,
            const InfoHash& target,
            want_t want,
            int confirm,
            RequestCb on_done,
            RequestCb on_expired);
    size_t sendGetValues(std::shared_ptr<Node> n,
            const InfoHash& target,
            want_t want,
            int confirm,
            RequestCb on_done,
            RequestCb on_expired);
    size_t sendListen(std::shared_ptr<Node> n,
            const InfoHash& infohash,
            const Blob& token,
            int confirm,
            RequestCb on_done,
            RequestCb on_expired);
    size_t sendAnnounceValue(std::shared_ptr<Node> n,
            const InfoHash& infohash,
            const Value& v,
            time_point created,
            const Blob& token,
            int confirm,
            RequestCb on_done,
            RequestCb on_expired);

    time_point processMessage(const uint8_t *buf, size_t buflen, const sockaddr *from, socklen_t fromlen, time_point now);

private:
    /***************
     *  Constants  *
     ***************/
    /* the length of a node info buffer in ipv4 format */
    static const constexpr size_t NODE4_INFO_BUF_LEN {26};
    /* the length of a node info buffer in ipv6 format */
    static const constexpr size_t NODE6_INFO_BUF_LEN {38};
    /* TODO: ???? */
    static const std::string my_v;

    /* DHT info */
    const InfoHash& myid;
    const int& dht_socket;
    const int& dht_socket6;
    const Logger& DHT_LOG;



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

    //TODO: balancer ce code dans NetworkEngine::processMessage
    //void onReply(ParsedMessage& msg) {
    //    if (msg.tid.length != 4)
    //        throw DhtProtocolException {DhtProtocolException::TRUNCATED_ID};
    //    onNewNode(msg.id, msg.);
    //}

    /**
     * When a request has expired, i.e when Request::MAX_ATTEMPT_COUNT attempts
     * of processing the request have been made, we consider a node expired.
     * Therefor, the requests for this node can be cancelled.
     *
     * @param rid  The request id.
     */
    void clearExpiredRequests(size_t rid);

    /*!
     * @class   Request
     * @brief   An atomic request destined to a node.
     * @details
     * A request contains data used by the NetworkEngine to process a request
     * desitned to specific node and std::function callbacks to execute when the
     * request is done.
     */
    struct Request {
        static const constexpr size_t MAX_ATTEMPT_COUNT {3};
        static const constexpr uint32_t INVALID_ID {0};

        Request(uint32_t id,
                std::shared_ptr<Node> node,
                Blob &&msg,
                std::function<void(size_t, ParsedMessage&&)> on_done,
                std::function<void(size_t, bool)> on_expired) :
            id(id), node(node), msg(msg), on_done(on_done), on_expired(on_expired) {}

        bool expired() { return attempt_count >= Request::MAX_ATTEMPT_COUNT; }

        std::function<void(size_t, ParsedMessage&&)> on_done {};
        std::function<void(size_t, bool)> on_expired {};

        uint32_t id {INVALID_ID};
        unsigned attempt_count {0};              /* number of attempt to process the request. */
        time_point start {clock::now()};         /* time when the request is created. */
        time_point last_try {time_point::min()}; /* time of the last attempt to process the request. */
        std::shared_ptr<Node> node {};           /* the node to whom the request is destined. */
        Blob msg {};                             /* the serialized message. */
    };

    /**
     * Generates a new request id, skipping the invalid id.
     *
     * @return the new id.
     */
    uint32_t getNewRequestId() {
        ++req_ids;
        return req_ids == Request::INVALID_ID ? ++req_ids : req_ids;
    }


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
            const uint8_t *nodes,
            unsigned nodes_len,
            const uint8_t *nodes6,
            unsigned nodes6_len,
            const std::vector<std::shared_ptr<Value>>& st,
            const Blob& token);
    unsigned insertClosestNode(uint8_t *nodes, unsigned numnodes, const InfoHash& id, const Node& n);
    std::pair<uint8_t*, uint8_t*>
        bufferNodes(const sockaddr *sa,
            socklen_t salen,
            TransId tid,
            const InfoHash& id,
            want_t want,
            const Blob& token,
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

    static std::mt19937 rd_device;
    time_point now;

    // requests handling
    uint32_t req_ids {1};
    std::map<size_t, std::shared_ptr<Request>> requests;
    std::map<time_point, std::function<void()>> timers; /** callbacks in case of expired requests. */
};

}
