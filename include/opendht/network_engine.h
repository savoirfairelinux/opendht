// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "node_cache.h"
#include "value.h"
#include "infohash.h"
#include "node.h"
#include "scheduler.h"
#include "utils.h"
#include "rng.h"
#include "rate_limiter.h"
#include "logger.h"
#include "network_utils.h"
#include "transport.h"

#include <vector>
#include <string>
#include <functional>
#include <algorithm>
#include <list>
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

struct NetworkConfig
{
    NetId network {0};
    ssize_t max_req_per_sec {0};
    ssize_t max_peer_req_per_sec {0};
    bool is_client {false};
    /** Transport encryption is used only if enabled and a key is set */
    TransportConfig transport {};
};

class DhtProtocolException : public DhtException
{
public:
    // sent to another peer (http-like).
    static const constexpr uint16_t NON_AUTHORITATIVE_INFORMATION {203}; /* incomplete request packet. */
    static const constexpr uint16_t UNAUTHORIZED {401};                  /* incorrect tokens. */
    static const constexpr uint16_t NOT_FOUND {404};                     /* storage not found */
    // for internal use (custom).
    static const constexpr uint16_t INVALID_TID_SIZE {421};        /* id was truncated. */
    static const constexpr uint16_t UNKNOWN_TID {422};             /* unknown tid */
    static const constexpr uint16_t WRONG_NODE_INFO_BUF_LEN {423}; /* node info length is incorrect */

    static const std::string GET_NO_INFOHASH;    /* received "get" request with no infohash */
    static const std::string LISTEN_NO_INFOHASH; /* got "listen" request without infohash */
    static const std::string LISTEN_WRONG_TOKEN; /* incorrect token in "listen" request */
    static const std::string PUT_NO_INFOHASH;    /* no infohash in "put" request */
    static const std::string PUT_WRONG_TOKEN;    /* got "put" request with incorrect token */
    static const std::string STORAGE_NOT_FOUND;  /* got access request for an unknown storage */
    static const std::string PUT_INVALID_ID;     /* invalid id in "put" request */

    DhtProtocolException(uint16_t code, const std::string& msg = "", InfoHash failing_node_id = {})
        : DhtException(msg)
        , msg(msg)
        , code(code)
        , failing_node_id(failing_node_id)
    {}

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
struct RequestAnswer
{
    /* Write token of the node; empty if it needs none (encrypted), nullopt if not granted. */
    std::optional<Blob> ntoken {};
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
     * Called on listen request, from a node proven to receive at its address.
     *
     * @param node (type: Sp<Node>) the requesting node.
     * @param h (type: InfoHash) hash of the value of interest.
     * @param rid (type: uint16_t) request id.
     */
    std::function<RequestAnswer(Sp<Node>, const InfoHash&, Tid, const Query&, int)> onListen {};
    /**
     * Called on announce request, from a node proven to receive at its address.
     *
     * @param node (type: Sp<Node>) the requesting node.
     * @param h (type: InfoHash) hash of the value of interest.
     * @param values (type: std::vector<Sp<Value>>) values to store.
     * @param created (type: time_point) time when the value was created.
     */
    std::function<RequestAnswer(Sp<Node>, const InfoHash&, const std::vector<Sp<Value>>&, const time_point&)>
        onAnnounce {};
    /**
     * Called on refresh request, from a node proven to receive at its address.
     *
     * @param node (type: Sp<Node>) the requesting node.
     * @param h (type: InfoHash) hash of the value of interest.
     * @param vid (type: Value::id) the value id.
     */
    std::function<RequestAnswer(Sp<Node>, const InfoHash&, const Value::Id&)> onRefresh {};

public:
    using RequestCb = std::function<void(const Request&, RequestAnswer&&)>;
    using RequestErrorCb = std::function<bool(const Request&, DhtProtocolException&&)>;
    using RequestExpiredCb = std::function<void(const Request&, bool)>;

    NetworkEngine(InfoHash& myid,
                  NetworkConfig config,
                  std::unique_ptr<DatagramSocket>&& sock,
                  const Sp<Logger>& log,
                  std::mt19937_64& rd,
                  Scheduler& scheduler,
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

    /** Our transport key, or nullptr if transport encryption is disabled */
    const transport::KeyPair* getTransportKey() const { return transport_ ? &config.transport.key : nullptr; }
    /** Replaces our transport key. Only valid before any message is exchanged. */
    void setTransportKey(const transport::KeyPair& key)
    {
        if (transport_)
            config.transport.key = key;
    }

    void clear();

    /**
     * Sends values (with closest nodes) to a listener.
     *
     * @deprecated
     * @param sa          The address of the listener.
     * @param sslen       The length of the sockaddr structure.
     * @param socket_id  The tid to use to write to the request socket.
     * @param hash        The hash key of the value.
     * @param want        Wether to send ipv4 and/or ipv6 nodes.
     * @param nodes       The ipv4 closest nodes.
     * @param nodes6      The ipv6 closest nodes.
     * @param values      The values to send.
     * @param version     If version = 1, a request will be used to answer to the listener
     */
    void tellListener(const Sp<Node>& n,
                      Tid socket_id,
                      const InfoHash& hash,
                      want_t want,
                      std::vector<Sp<Node>>&& nodes,
                      std::vector<Sp<Node>>&& nodes6,
                      std::vector<Sp<Value>>&& values,
                      const Query& q,
                      int version);

    void tellListenerRefreshed(const Sp<Node>& n,
                               Tid socket_id,
                               const InfoHash& hash,
                               const std::vector<Value::Id>& values,
                               int version);
    void tellListenerExpired(const Sp<Node>& n,
                             Tid socket_id,
                             const InfoHash& hash,
                             const std::vector<Value::Id>& values,
                             int version);

    bool isRunning(sa_family_t af) const;
    inline want_t want() const { return dht_socket->hasIPv4() and dht_socket->hasIPv6() ? (WANT4 | WANT6) : -1; }

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
    Sp<Request> sendPing(const Sp<Node>& n, RequestCb&& on_done, RequestExpiredCb&& on_expired);

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
    Sp<Request> sendPing(SockAddr&& sa, RequestCb&& on_done, RequestExpiredCb&& on_expired)
    {
        return sendPing(std::make_shared<Node>(InfoHash::zero(), std::move(sa), rd),
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
    Sp<Request> sendFindNode(const Sp<Node>& n,
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
    Sp<Request> sendGetValues(const Sp<Node>& n,
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
     *                    For backward compatibility purposes, sendListen has to
     *                    handle creation of the socket. Therefore, you are unable to
     *                    use openSocket yourself.
     *                    TODO: Once we don't support the old "listen" negotiation,
     *                    sendListen shall not create the socket itself.
     *
     * @param on_done     Request callback when the request is completed.
     * @param on_expired  Request callback when the request expires.
     * @param socket_cb   Callback to execute each time new updates arrive on
     *                    the socket.
     *
     * @return the request with information concerning its success.
     */
    Sp<Request> sendListen(const Sp<Node>& n,
                           const InfoHash& hash,
                           const Query& query,
                           const Blob& token,
                           Tid socketId,
                           RequestCb&& on_done,
                           RequestExpiredCb&& on_expired);
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
    Sp<Request> sendAnnounceValue(const Sp<Node>& n,
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
    Sp<Request> sendRefreshValue(const Sp<Node>& n,
                                 const InfoHash& hash,
                                 const Value::Id& vid,
                                 const Blob& token,
                                 RequestCb&& on_done,
                                 RequestErrorCb&& on_error,
                                 RequestExpiredCb&& on_expired);
    /**
     * Send a "update" request to a given node. Used for Listen operations
     *
     * @param n           The node.
     * @param hash        The target hash.
     * @param values      The values.
     * @param created     Time id.
     * @param token       A security token.
     * @param sid         The socket id.
     *
     * @return the request with information concerning its success.
     */
    void sendUpdateValues(const Sp<Node>& n,
                          const InfoHash& infohash,
                          std::vector<Sp<Value>>&& values,
                          time_point created,
                          const Blob& token,
                          size_t sid);
    Sp<Request> sendUpdateValues(const Sp<Node>& n,
                                 const InfoHash& infohash,
                                 std::vector<Sp<Value>>::iterator begin,
                                 std::vector<Sp<Value>>::iterator end,
                                 time_point created,
                                 const Blob& token,
                                 size_t sid);

    /**
     * Parses a message and calls appropriate callbacks.
     *
     * @param buf  The buffer containing the binary message.
     * @param buflen  The length of the buffer.
     * @param from  The address info of the sender.
     * @param fromlen  The length of the corresponding sockaddr structure.
     * @param now  The time to adjust the clock in the network engine.
     */
    void processMessage(const uint8_t* buf, size_t buflen, SockAddr addr);

    Sp<Node> insertNode(const InfoHash& id, const SockAddr& addr)
    {
        auto n = cache.getNode(id, addr, scheduler.time(), 0);
        onNewNode(n, 0);
        return n;
    }

    std::vector<unsigned> getNodeMessageStats(bool in)
    {
        auto& st = in ? in_stats : out_stats;
        std::vector<unsigned> stats {st.ping, st.find, st.get, st.listen, st.put};
        st = {};
        return stats;
    }

    void blacklistNode(const Sp<Node>& n);

    std::vector<Sp<Node>> getCachedNodes(const InfoHash& id, sa_family_t sa_f, size_t count)
    {
        return cache.getCachedNodes(id, sa_f, count);
    }

    size_t getNodeCacheSize() const { return cache.size(); }
    size_t getNodeCacheSize(sa_family_t af) const { return cache.size(af); }

    size_t getRateLimiterSize() const { return address_rate_limiter.size(); }

    size_t getPartialCount() const { return partial_messages.size(); }

private:
    struct PartialMessage;

    /***************
     *  Constants  *
     ***************/
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

    /* IPv6 minimum MTU, less the IPv6 and UDP headers */
    static constexpr size_t MAX_PACKET_SIZE {1280 - 40 - 8};
    /* Upper bound of the msgpack framing around a value fragment */
    static constexpr size_t FRAGMENT_HEADER_SIZE {48};
    /* Value fragment sizes keeping each packet within the minimum MTU, less the envelope */
    static constexpr size_t FRAGMENT_SIZE {MAX_PACKET_SIZE - FRAGMENT_HEADER_SIZE};
    static constexpr size_t ENCRYPTED_FRAGMENT_SIZE {FRAGMENT_SIZE - transport::MAX_ENVELOPE_OVERHEAD};
    static constexpr size_t MAX_PACKET_VALUE_SIZE {600};
    static constexpr size_t MAX_MESSAGE_VALUE_SIZE {56 * 1024};
    static constexpr size_t RX_MAX_EARLY_BYTES {MAX_MESSAGE_VALUE_SIZE + MAX_VALUE_SIZE + 32};
    static constexpr size_t RX_MAX_EARLY_PARTS {RX_MAX_EARLY_BYTES / ENCRYPTED_FRAGMENT_SIZE + 2};
    /* Lifetime of ephemeral transport keys and write tokens: in use for one period, then accepted for another */
    static constexpr std::chrono::minutes EPOCH_DURATION {30};
    /* Cached session keys per epoch */
    static constexpr size_t MAX_SESSIONS {16 * 1024};
    static constexpr size_t TOKEN_SIZE {transport::KEY_SIZE};

    struct Session
    {
        /* our ephemeral key for the peer address */
        transport::Key ephemeral;
        transport::Key peer;
        transport::Key peerEphemeral;
        transport::SessionKeys keys;
        /* the peer has these keys and accepted us: send Data envelopes */
        bool confirmed {false};
    };
    /* The secret from which ephemeral keys and tokens derive, and session keys, all erased together.
     * A session is cached for an address only once its peer proved to receive there: it opened an envelope
     * encrypted with our key for that address. Replies to Initial and Hello envelopes never cache one,
     * since their source address can be spoofed. */
    struct Epoch
    {
        struct Entry
        {
            Session session;
            std::list<SockAddr>::iterator used;
        };
        transport::Key secret {};
        std::map<SockAddr, Entry> sessions {};
        /* most recently used first */
        std::list<SockAddr> used {};

        explicit operator bool() const { return secret != transport::Key {}; }
        transport::KeyPair ephemeral(const SockAddr& addr) const;
        Blob token(const SockAddr& addr) const;
        /* Marks the session as used */
        Session* find(const SockAddr& addr);
        Session* find(const SockAddr& addr, const transport::Key& peer, const transport::Key& peerEphemeral);
        /* Evicts the least recently used session when full */
        void store(const SockAddr& addr, const Session& session);
        void wipe();
    };
    void rotateEpoch();
    /* Session with the peer at `addr`, or nullopt for an invalid peer key. Cached if the peer ephemeral key is validated. */
    std::optional<Session> session(const transport::Peer& peer, const SockAddr& addr);
    std::optional<Blob> openSession(const transport::Header& header,
                                    const uint8_t* buf,
                                    size_t buflen,
                                    const SockAddr& from);
    /* Fills the sender keys of `header` from the session */
    std::optional<Blob> openData(transport::Header& header, const uint8_t* buf, size_t buflen, const SockAddr& from);

    struct OpenedEnvelope
    {
        Sp<transport::Peer> peer;
        Blob payload;
        /* unauthenticated */
        bool hello {false};
        /* Session or Data envelope: the sender got our ephemeral key for its address */
        bool session {false};
    };
    std::optional<OpenedEnvelope> openEnvelope(const uint8_t* buf, size_t buflen, const SockAddr& from);
    bool authorize(transport::Peer& peer, const uint8_t* credential, size_t size) const;
    void attachPeer(Node& node, const Sp<transport::Peer>& peer);
    Sp<transport::Peer> makePeer(const InfoHash& id, const transport::Key& key) const;
    void processHello(const ParsedMessage& msg, const Sp<transport::Peer>& peer, const SockAddr& from);

    /* Advertise our transport key in plaintext messages to nodes not known to support encryption */
    bool advertiseKey(const Node& node) const
    {
        return transport_ and not config.transport.isPrivate() and not node.getTransport();
    }
    /* Messages to the node are encrypted */
    bool encrypts(const Node& node) const { return transport_ and node.getTransport(); }
    /* Token granting writes to a plaintext node. Encrypted nodes need none. */
    Blob writeToken(const Node& node) const { return encrypts(node) ? Blob {} : epoch_.token(node.getAddr()); }
    bool tokenMatch(const Blob& token, const SockAddr& addr) const;
    /* Writes need proof that the sender receives at its address: a Session envelope, or else a token */
    void authorizeWrite(const ParsedMessage& msg, const Node& node, const std::string& error) const;
    /* Number of optional top-level fields packed by packOptionalFields */
    unsigned optionalFields(bool key) const
    {
        return (config.network ? 1 : 0) + (config.is_client ? 1 : 0) + (key ? 1 : 0);
    }
    void packOptionalFields(msgpack::packer<msgpack::sbuffer>& pk, bool key) const;

    void process(std::unique_ptr<ParsedMessage>&&, const SockAddr& from);
    bool isExpectedReply(const ParsedMessage&, const SockAddr& from);
    bool tryCompleteMessage(PartialMessage&, const SockAddr& from);

    bool rateLimit(const SockAddr& addr);

    static bool isMartian(const SockAddr& addr);
    bool isNodeBlacklisted(const SockAddr& addr) const;

    void requestStep(Sp<Request> req);
    /* Re-establishes the session with a ping in an Initial envelope, then resends `req` under it */
    void recoverSession(const Sp<Request>& req);

    /**
     * Sends a request to a node. Request::MAX_ATTEMPT_COUNT attempts will
     * be made before the request expires.
     */
    void sendRequest(const Sp<Request>& request);

    struct MessageStats
    {
        unsigned ping {0};
        unsigned find {0};
        unsigned get {0};
        unsigned put {0};
        unsigned listen {0};
        unsigned refresh {0};
        unsigned updateValue {0};
    };

    // basic wrapper for socket sendto function
    int sendRaw(const SockAddr& addr, const uint8_t* buf, size_t len, bool confirmed = false);
    // send to a node, encrypted if supported
    int send(const Node& node, const SockAddr& addr, const char* buf, size_t len, bool confirmed = false);
    /* Bytes added by the envelope that send() uses for the node at `addr` */
    size_t envelopeOverhead(const Node& node, const SockAddr& addr);

    void sendValueParts(Tid tid, const std::vector<Blob>& svals, const Node& node, const SockAddr& addr);
    std::vector<Blob> packValueHeader(msgpack::sbuffer&,
                                      std::vector<Sp<Value>>::const_iterator,
                                      std::vector<Sp<Value>>::const_iterator) const;
    std::vector<Blob> packValueHeader(msgpack::sbuffer& buf, const std::vector<Sp<Value>>& values) const
    {
        return packValueHeader(buf, values.begin(), values.end());
    }
    using PartialMessageKey = std::pair<SockAddr, Tid>;
    void maintainRxBuffer(const PartialMessageKey& key);
    /* Whether `part` may join the partial message at `it`, end() if none. Parts of a message are all
     * plaintext, or all in envelopes from one sender key: an encrypted part replaces plaintext state. */
    bool acceptsPart(std::map<PartialMessageKey, PartialMessage>::iterator& it, const ParsedMessage& part);

    /*************
     *  Answers  *
     *************/
    /* answer to a ping  request */
    void sendPong(const Node& node, const SockAddr& addr, Tid tid);
    struct BufferedNodes
    {
        Blob nodes4, nodes6;
        /* transport keys, aligned with nodes, zeros if unknown. Empty if none is known. */
        Blob keys4, keys6;
    };
    /* answer to findnodes/getvalues request */
    void sendNodesValues(const Node& node,
                         const SockAddr& addr,
                         Tid tid,
                         const BufferedNodes& nodes,
                         const std::vector<Sp<Value>>& st,
                         const Query& query,
                         const Blob& token);
    std::pair<Blob, Blob> bufferNodes(sa_family_t af, const InfoHash& id, std::vector<Sp<Node>>& nodes);

    BufferedNodes bufferNodes(
        sa_family_t af, const InfoHash& id, want_t want, std::vector<Sp<Node>>& nodes, std::vector<Sp<Node>>& nodes6);
    /* answer to a listen request */
    void sendListenConfirmation(const Node& node, const SockAddr& addr, Tid tid, const Blob& token = {});
    /* answer to put request */
    void sendValueAnnounced(const Node& node, const SockAddr& addr, Tid, Value::Id);
    /* answer in case of error */
    void sendError(const Node& node,
                   const SockAddr& addr,
                   Tid tid,
                   uint16_t code,
                   const std::string& message,
                   bool include_id = false);

    void deserializeNodes(ParsedMessage& msg, const SockAddr& from);

    /* DHT info */
    const InfoHash& myid;
    NetworkConfig config {};
    const bool transport_ {false};
    const Blob credential_ {};
    Epoch epoch_ {};
    Epoch previousEpoch_ {};
    Sp<Scheduler::Job> epochRotation_ {};
    const std::unique_ptr<DatagramSocket> dht_socket;
    Sp<Logger> logger_;
    std::mt19937_64& rd;

    NodeCache cache;

    // global limiting should be triggered by at least 8 different IPs
    using IpLimiter = RateLimiter;
    using IpLimiterMap = std::map<SockAddr, IpLimiter, SockAddr::ipCmp>;
    IpLimiterMap address_rate_limiter;
    RateLimiter rate_limiter;
    ssize_t limiter_maintenance {0};

    // requests handling
    std::map<Tid, Sp<Request>> requests {};
    std::map<PartialMessageKey, PartialMessage> partial_messages;

    MessageStats in_stats {}, out_stats {};
    std::set<SockAddr> blacklist {};

    Scheduler& scheduler;

    bool logIncoming_ {false};
};

} /* namespace net  */
} /* namespace dht */
