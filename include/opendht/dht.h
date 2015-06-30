/*
Copyright (c) 2009-2014 Juliusz Chroboczek
Copyright (c) 2014 Savoir-Faire Linux Inc.

Authors : Adrien Béraud <adrien.beraud@savoirfairelinux.com>,
          Juliusz Chroboczek <jch@pps.univ–paris–diderot.fr>

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

#include "infohash.h"
#include "value.h"

#include <string>
#include <array>
#include <vector>
#include <map>
#include <list>
#include <queue>
#include <functional>
#include <algorithm>
#include <memory>

namespace dht {

struct NodeExport {
    InfoHash id;
    sockaddr_storage ss;
    socklen_t sslen;
};

struct Node {
    InfoHash id {};
    sockaddr_storage ss;
    socklen_t sslen {0};
    time_point time {};            /* last time eared about */
    time_point reply_time {};      /* time of last correct reply received */
    time_point pinged_time {};     /* time of last message sent */
    unsigned pinged {0};           /* how many requests we sent since last reply */

    Node() : ss() {
        std::fill_n((uint8_t*)&ss, sizeof(ss), 0);
    }
    Node(const InfoHash& id, const sockaddr* sa, socklen_t salen)
        : id(id), ss(), sslen(salen) {
        std::copy_n((const uint8_t*)sa, salen, (uint8_t*)&ss);
    }
    InfoHash getId() const {
        return id;
    }
    bool isExpired(time_point now) const;
    bool isGood(time_point now) const;
    NodeExport exportNode() const { return NodeExport {id, ss, sslen}; }
    sa_family_t getFamily() const { return ss.ss_family; }

    void update(const sockaddr* sa, socklen_t salen);

    /** To be called when a message was sent to the noe */
    void requested(time_point now);

    /** To be called when a message was received from the node.
     Answer should be true if the message was an aswer to a request we made*/
    void received(time_point now, bool answer);

    friend std::ostream& operator<< (std::ostream& s, const Node& h);

    static constexpr const std::chrono::minutes NODE_GOOD_TIME {120};

    /* The time after which we consider a node to be expirable. */
    static constexpr const std::chrono::minutes NODE_EXPIRE_TIME {10};

    /* Time for a request to timeout */
    static constexpr const std::chrono::seconds MAX_RESPONSE_TIME {3};
};

/**
 * Main Dht class.
 * Provides a Distributed Hash Table node.
 *
 * Must be given open UDP sockets and ::periodic must be
 * called regularly.
 */
class Dht {
public:

    enum class Status {
        Disconnected, // 0 nodes
        Connecting,   // 1+ nodes
        Connected     // 1+ good nodes
    };

    // [[deprecated]]
    using NodeExport = dht::NodeExport;

    //typedef std::function<bool(const std::vector<std::shared_ptr<Value>>& values)> GetCallback;
    struct GetCallback : public std::function<bool(const std::vector<std::shared_ptr<Value>>& values)>
    {
        typedef bool (*GetCallbackRaw)(std::vector<std::shared_ptr<Value>>*, void *user_data);

        using std::function<bool(const std::vector<std::shared_ptr<Value>>& values)>::function;
        GetCallback(GetCallbackRaw raw_cb, void *user_data)
            : GetCallback([=](const std::vector<std::shared_ptr<Value>>& values){
                return raw_cb((std::vector<std::shared_ptr<Value>>*)&values, user_data);
            }) {}
        GetCallback() : GetCallback(nullptr) {}
    };
    struct DoneCallback : public std::function<void(bool success, const std::vector<std::shared_ptr<Node>>& nodes)>
    {
        typedef void (*DoneCallbackRaw)(bool, std::vector<std::shared_ptr<Node>>*, void *user_data);

        using std::function<void(bool success, const std::vector<std::shared_ptr<Node>>& nodes)>::function;
        DoneCallback(DoneCallbackRaw raw_cb, void *user_data)
            : DoneCallback([=](bool success, const std::vector<std::shared_ptr<Node>>& nodes) {
                return raw_cb(success, (std::vector<std::shared_ptr<Node>>*)&nodes, user_data);
            }) {}
        DoneCallback() : DoneCallback(nullptr) {}
    };

    //typedef std::function<void(bool success, const std::vector<std::shared_ptr<Node>>& nodes)> DoneCallback;
    typedef std::function<void(bool success)> DoneCallbackSimple;

    static DoneCallback
    bindDoneCb(DoneCallbackSimple donecb) {
        using namespace std::placeholders;
        return std::bind(donecb, _1);
    }


    using want_t = int_fast8_t;

    Dht() {}

    /**
     * Initialise the Dht with two open sockets (for IPv4 and IP6)
     * and an ID for the node.
     */
    Dht(int s, int s6, const InfoHash& id);
    virtual ~Dht();

    /**
     * Get the ID of the node.
     */
    inline const InfoHash& getNodeId() const { return myid; }

    /**
     * Get the current status of the node for the given family.
     */
    Status getStatus(sa_family_t af) const;

    /**
     * Returns true if the node is running (have access to an open socket).
     *
     *  af: address family. If non-zero, will return true if the node
     *      is running for the provided family.
     */
    bool isRunning(sa_family_t af = 0) const;

    /**
     * Enable or disable logging of DHT internal messages
     */
    void setLoggers(LogMethod&& error = NOLOG, LogMethod&& warn = NOLOG, LogMethod&& debug = NOLOG);

    virtual void registerType(const ValueType& type) {
        types[type.id] = type;
    }
    const ValueType& getType(ValueType::Id type_id) const {
        const auto& t_it = types.find(type_id);
        return (t_it == types.end()) ? ValueType::USER_DATA : t_it->second;
    }

    /**
     * Insert a node in the main routing table.
     * The node is not pinged, so this should be
     * used to bootstrap efficiently from previously known nodes.
     */
    bool insertNode(const InfoHash& id, const sockaddr*, socklen_t);
    bool insertNode(const NodeExport& n) {
        return insertNode(n.id, reinterpret_cast<const sockaddr*>(&n.ss), n.sslen);
    }

    int pingNode(const sockaddr*, socklen_t);

    time_point periodic(const uint8_t *buf, size_t buflen, const sockaddr *from, socklen_t fromlen);

    /**
     * Get a value by searching on all available protocols (IPv4, IPv6),
     * and call the callback when some values are found.
     * The operation will start as soon as the node is connected to the network.
     * GetCallback will be called every time new values are found, until
     * GetCallback returns false or the search completes.
     * Then, DoneCallback is called.
     */
    void get(const InfoHash& id, GetCallback cb, DoneCallback donecb=nullptr, Value::Filter = Value::AllFilter());
    void get(const InfoHash& id, GetCallback cb, DoneCallbackSimple donecb=nullptr, Value::Filter f = Value::AllFilter()) {
        get(id, cb, bindDoneCb(donecb), f);
    }

    /**
     * Get locally stored data for the given hash.
     */
    std::vector<std::shared_ptr<Value>> getLocal(const InfoHash& id, Value::Filter f = Value::AllFilter()) const;

    /**
     * Get locally stored data for the given hash and value id.
     */
    std::shared_ptr<Value> getLocalById(const InfoHash& id, const Value::Id& vid) const;

    /**
     * Announce a value on all available protocols (IPv4, IPv6), and
     * automatically re-announce when it's about to expire.
     * The operation will start as soon as the node is connected to the network.
     * The done callback will be called once, when the first announce succeeds, or fails.
     *
     * A "put" operation will never end by itself because the value will need to be
     * reannounced on a regular basis.
     * User can call #cancelPut(InfoHash, Value::Id) to cancel a put operation.
     */
    void put(const InfoHash&, const std::shared_ptr<Value>&, DoneCallback cb=nullptr);
    void put(const InfoHash& id, const std::shared_ptr<Value>& v, DoneCallbackSimple cb) {
        put(id, v, bindDoneCb(cb));
    }

    void put(const InfoHash& h, Value&& v, DoneCallback cb=nullptr) {
        put(h, std::make_shared<Value>(std::move(v)), cb);
    }
    void put(const InfoHash& id, Value&& v, DoneCallbackSimple cb) {
        put(id, std::forward<Value>(v), bindDoneCb(cb));
    }

    /**
     * Get data currently being put at the given hash.
     */
    std::vector<std::shared_ptr<Value>> getPut(const InfoHash&);

    /**
     * Get data currently being put at the given hash with the given id.
     */
    std::shared_ptr<Value> getPut(const InfoHash&, const Value::Id&);

    /**
     * Stop any put/announce operation at the given location,
     * for values with the given id.
     */
    bool cancelPut(const InfoHash&, const Value::Id&);

    /**
     * Listen for any changes involving a specified hash.
     * The node will register to receive updates from relevent nodes when
     * new values are added or removed.
     *
     * @return a token to cancel the listener later.
     */
    size_t listen(const InfoHash&, GetCallback, Value::Filter = Value::AllFilter());
    bool cancelListen(const InfoHash&, size_t token);

    /**
     * Get the list of good nodes for local storage saving purposes
     * The list is ordered to minimize the back-to-work delay.
     */
    std::vector<NodeExport> exportNodes();

    typedef std::pair<InfoHash, Blob> ValuesExport;
    std::vector<ValuesExport> exportValues() const;
    void importValues(const std::vector<ValuesExport>&);

    int getNodesStats(sa_family_t af, unsigned *good_return, unsigned *dubious_return, unsigned *cached_return, unsigned *incoming_return) const;
    std::string getStorageLog() const;
    std::string getRoutingTablesLog(sa_family_t) const;
    std::string getSearchesLog(sa_family_t) const;

    void dumpTables() const;

    /* This must be provided by the user. */
    static bool isBlacklisted(const sockaddr*, socklen_t) { return false; }

protected:
    LogMethod DHT_DEBUG = NOLOG;
    LogMethod DHT_WARN = NOLOG;
    LogMethod DHT_ERROR = NOLOG;

private:

    static constexpr unsigned TARGET_NODES {8};

    /* When performing a search, we search for up to SEARCH_NODES closest nodes
       to the destination, and use the additional ones to backtrack if any of
       the target 8 turn out to be dead. */
    static constexpr unsigned SEARCH_NODES {14};
    static constexpr unsigned LISTEN_NODES {3};

    /* The maximum number of values we store for a given hash. */
    static constexpr unsigned MAX_VALUES {2048};

    /* The maximum number of hashes we're willing to track. */
    static constexpr unsigned MAX_HASHES {16384};

    /* The maximum number of searches we keep data about. */
    static constexpr unsigned MAX_SEARCHES {1024};

    /* The time after which we can send get requests for
       a search in case of no answers. */
    static constexpr std::chrono::seconds SEARCH_GET_STEP {3};

    /* The time after which we consider a search to be expirable. */
    static constexpr std::chrono::minutes SEARCH_EXPIRE_TIME {62};

    /* Timeout for listen */
    static constexpr std::chrono::minutes LISTEN_EXPIRE_TIME {3};

    static constexpr std::chrono::seconds REANNOUNCE_MARGIN {5};

    static constexpr std::chrono::seconds UDP_REPLY_TIME {15};

    /* The maximum number of nodes that we snub.  There is probably little
        reason to increase this value. */
    static constexpr unsigned BLACKLISTED_MAX {10};

    static constexpr long unsigned MAX_REQUESTS_PER_SEC {400};

    static constexpr std::chrono::seconds TOKEN_EXPIRE_TIME {10 * 60};

    static constexpr unsigned TOKEN_SIZE {64};


    struct NodeCache {
        std::shared_ptr<Node> getNode(const InfoHash& id, sa_family_t family);
        std::shared_ptr<Node> getNode(const InfoHash& id, const sockaddr* sa, socklen_t sa_len, time_point now, int confirmed);
        void putNode(std::shared_ptr<Node> n);
    private:
        std::list<std::weak_ptr<Node>> cache_4;
        std::list<std::weak_ptr<Node>> cache_6;
    };

    struct Bucket {
        Bucket() : cached() {}
        Bucket(sa_family_t af, const InfoHash& f = {}, time_point t = {})
            : af(af), first(f), time(t), cached() {}
        sa_family_t af {0};
        InfoHash first {};
        time_point time {};             /* time of last reply in this bucket */
        std::list<std::shared_ptr<Node>> nodes {};
        sockaddr_storage cached;  /* the address of a likely candidate */
        socklen_t cachedlen {0};

        /** Return a random node in a bucket. */
        std::shared_ptr<Node> randomNode();
    };

    class RoutingTable : public std::list<Bucket> {
    public:
        using std::list<Bucket>::list;

        InfoHash middle(const RoutingTable::const_iterator&) const;

        RoutingTable::iterator findBucket(const InfoHash& id);
        RoutingTable::const_iterator findBucket(const InfoHash& id) const;

        /**
         * Returns true if the id is in the bucket's range.
         */
        inline bool contains(const RoutingTable::const_iterator& bucket, const InfoHash& id) const {
            return InfoHash::cmp(bucket->first, id) <= 0
                && (std::next(bucket) == end() || InfoHash::cmp(id, std::next(bucket)->first) < 0);
        }

        /**
         * Returns a random id in the bucket's range.
         */
        InfoHash randomId(const RoutingTable::const_iterator& bucket) const;

        /**
         * Split a bucket in two equal parts.
         */
        bool split(const RoutingTable::iterator& b);
    };

    struct SearchNode {
        SearchNode(std::shared_ptr<Node> node) : node(node) {}

        struct RequestStatus {
            time_point request_time {};    /* the time of the last unanswered request */
            time_point reply_time {};      /* the time of the last confirmation */
            RequestStatus() {};
            RequestStatus(time_point q, time_point a = {}) : request_time(q), reply_time(a) {};
            bool expired(time_point now) {
                return (reply_time < request_time && now - request_time <= Node::MAX_RESPONSE_TIME);
            }
        };
        typedef std::map<Value::Id, RequestStatus> AnnounceStatusMap;

        /**
         * Can we use this node to listen/announce now ?
         */
        bool isSynced(time_point now) const {
            return not node->isExpired(now) and
                   getStatus.reply_time >= now - Node::NODE_EXPIRE_TIME;
        }
        bool canGet(time_point now, time_point update) const {
            return not node->isExpired(now) and
                   (now > getStatus.reply_time + Node::NODE_EXPIRE_TIME or update > getStatus.reply_time) and
                   now > getStatus.request_time + Node::MAX_RESPONSE_TIME;
        }

        bool isAnnounced(Value::Id vid, const ValueType& type, time_point now) const {
            auto ack = acked.find(vid);
            if (ack == acked.end()) {
                return false;
            }
            return ack->second.reply_time + type.expiration > now;
        }
        bool isListening(time_point now) const {
            return listenStatus.reply_time + LISTEN_EXPIRE_TIME > now;
        }

        time_point getAnnounceTime(AnnounceStatusMap::const_iterator ack, const ValueType& type) const {
            if (ack == acked.end())
                return getStatus.request_time + Node::MAX_RESPONSE_TIME;
            return std::max<time_point>({
                ack->second.reply_time + type.expiration - REANNOUNCE_MARGIN, 
                ack->second.request_time + Node::MAX_RESPONSE_TIME, 
                getStatus.request_time + Node::MAX_RESPONSE_TIME
            });
        }
        time_point getAnnounceTime(Value::Id vid, const ValueType& type) const {
            return getAnnounceTime(acked.find(vid), type);
        }
        time_point getListenTime() const {
            if (listenStatus.reply_time > listenStatus.request_time)
                return listenStatus.reply_time + LISTEN_EXPIRE_TIME - REANNOUNCE_MARGIN;
            return listenStatus.request_time + Node::MAX_RESPONSE_TIME;
            //time_point min_t = listenStatus.request_time + MAX_RESPONSE_TIME;
            //return listenStatus.reply_time.time_since_epoch().count() ? std::max(listenStatus.reply_time + NODE_EXPIRE_TIME - REANNOUNCE_MARGIN, min_t) : min_t;
        }

        std::shared_ptr<Node> node {};

        RequestStatus getStatus {};    /* get/sync status */
        RequestStatus listenStatus {};
        AnnounceStatusMap acked {};    /* announcement status for a given value id */

        Blob token {};

        // Generic temporary flag.
        // Must be reset to false after use by the algorithm.
        bool pending {false};
    };

    struct Get {
        time_point start;
        Value::Filter filter;
        GetCallback get_cb;
        DoneCallback done_cb;
    };

    struct Announce {
        std::shared_ptr<Value> value;
        DoneCallback callback;
    };

    struct LocalListener {
        Value::Filter filter;
        GetCallback get_cb;
    };

    /**
     * A search is a pointer to the nodes we think are responsible
     * for storing values for a given hash.
     *
     * A Search has 3 states:
     * - Idle (nothing to do)
     * - Syncing (Some nodes not synced)
     * - Announcing (Some announces not performed on all nodes)
     */
    struct Search {
        InfoHash id {};
        sa_family_t af;

        uint16_t tid;
        time_point step_time {};           /* the time of the last search_step */
        time_point get_step_time {};       /* the time of the last get time */

        bool expired {false};              /* no node, or all nodes expired */
        bool done {false};                 /* search is over, cached for later */
        std::vector<SearchNode> nodes {};
        std::vector<Announce> announce {};
        std::vector<Get> callbacks {};

        std::map<size_t, LocalListener> listeners {};
        size_t listener_token = 1;

        bool insertNode(std::shared_ptr<Node> n, time_point now, const Blob& token={});
        void insertBucket(const Bucket&, time_point now);

        /**
         * Can we use this search to announce ?
         */
        bool isSynced(time_point now) const;

        time_point getLastGetTime() const;

        /**
         * Is this get operation done ?
         */
        bool isDone(const Get& get, time_point now) const;

        time_point getUpdateTime(time_point now) const;

        bool isAnnounced(Value::Id id, const ValueType& type, time_point now) const;
        bool isListening(time_point now) const;

        /**
         * ret = 0 : no announce required.
         * ret > 0 : (re-)announce required at time ret.
         */
        time_point getAnnounceTime(const std::map<ValueType::Id, ValueType>& types, time_point now) const;

        /**
         * ret = 0 : no listen required.
         * ret > 0 : (re-)announce required at time ret.
         */
        time_point getListenTime(time_point now) const;

        time_point getNextStepTime(const std::map<ValueType::Id, ValueType>& types, time_point now) const;

        bool removeExpiredNode(time_point now);

        std::vector<std::shared_ptr<Node>> getNodes(time_point now) const;
    };

    struct ValueStorage {
        std::shared_ptr<Value> data {};
        time_point time {};

        ValueStorage() {}
        ValueStorage(const std::shared_ptr<Value>& v, time_point t) : data(v), time(t) {}
    };

    /**
     * Foreign nodes asking for updates about an InfoHash.
     */
    struct Listener {
        InfoHash id {};
        sockaddr_storage ss;
        socklen_t sslen {};
        uint16_t tid {};
        time_point time {};

        /*constexpr*/ Listener() : ss() {}
        Listener(const InfoHash& id, const sockaddr *from, socklen_t fromlen, uint16_t ttid, time_point t) : id(id), ss(), sslen(fromlen), tid(ttid), time(t) {
            memcpy(&ss, from, fromlen);
        }
        void refresh(const sockaddr *from, socklen_t fromlen, uint16_t ttid, time_point t) {
            memcpy(&ss, from, fromlen);
            sslen = fromlen;
            tid = ttid;
            time = t;
        }
    };

    struct Storage {
        InfoHash id;
        std::vector<ValueStorage> values {};
        std::vector<Listener> listeners {};
        std::map<size_t, LocalListener> local_listeners {};
        size_t listener_token {1};

        Storage() {}
        Storage(InfoHash id) : id(id) {}
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

    struct TransPrefix : public  std::array<uint8_t, 2>  {
        TransPrefix(const std::string& str) : std::array<uint8_t, 2>({(uint8_t)str[0], (uint8_t)str[1]}) {}
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
            if (std::equal(begin(), begin()+1, prefix.begin())) {
                if (seqno_return)
                    *seqno_return = *reinterpret_cast<const uint16_t*>(&(*this)[2]);
                return true;
            } else
                return false;
        }

        unsigned length {4};
    };

    // prevent copy
    Dht(const Dht&) = delete;
    Dht& operator=(const Dht&) = delete;

    // socket descriptors
    int dht_socket {-1};
    int dht_socket6 {-1};

    InfoHash myid {};
    static const uint8_t my_v[9];
    std::array<uint8_t, 8> secret {{}};
    std::array<uint8_t, 8> oldsecret {{}};

    // registred types
    std::map<ValueType::Id, ValueType> types;

    // cache of nodes not in the main routing table but used for searches
    NodeCache cache;

    // the stuff
    RoutingTable buckets {};
    RoutingTable buckets6 {};
    std::vector<Storage> store {};
    std::list<Search> searches {};
    uint16_t search_id {0};

    // map a global listen token to IPv4, IPv6 specific listen tokens.
    // 0 is the invalid token.
    std::map<size_t, std::tuple<size_t, size_t, size_t>> listeners {};
    size_t listener_token {1};

    sockaddr_storage blacklist[BLACKLISTED_MAX] {};
    unsigned next_blacklisted = 0;

    time_point now;
    time_point mybucket_grow_time {}, mybucket6_grow_time {};
    time_point expire_stuff_time {};
    time_point search_time {};
    time_point confirm_nodes_time {};
    time_point rotate_secrets_time {};
    std::queue<time_point> rate_limit_time {};

    // Networking & packet handling
    int send(const char* buf, size_t len, int flags, const sockaddr*, socklen_t);
    int sendPing(const sockaddr*, socklen_t, TransId tid);
    int sendPong(const sockaddr*, socklen_t, TransId tid);

    int sendFindNode(const sockaddr*, socklen_t, TransId tid,
                        const InfoHash& target, want_t want, int confirm);

    int sendNodesValues(const sockaddr*, socklen_t, TransId tid,
                              const uint8_t *nodes, unsigned nodes_len,
                              const uint8_t *nodes6, unsigned nodes6_len,
                              const std::vector<ValueStorage>& st, const Blob& token);

    int sendClosestNodes(const sockaddr*, socklen_t, TransId tid,
                               const InfoHash& id, want_t want, const Blob& token={},
                               const std::vector<ValueStorage>& st = {});

    int sendGetValues(const sockaddr*, socklen_t, TransId tid,
                            const InfoHash& infohash, want_t want, int confirm);

    int sendListen(const sockaddr*, socklen_t, TransId,
                            const InfoHash&, const Blob& token, int confirm);

    int sendListenConfirmation(const sockaddr*, socklen_t, TransId);

    int sendAnnounceValue(const sockaddr*, socklen_t, TransId,
                            const InfoHash&, const Value&,
                            const Blob& token, int confirm);

    int sendValueAnnounced(const sockaddr*, socklen_t, TransId, Value::Id);

    int sendError(const sockaddr*, socklen_t, TransId tid, uint16_t code, const char *message, bool include_id=false);

    void processMessage(const uint8_t *buf, size_t buflen, const sockaddr *from, socklen_t fromlen);
    MessageType parseMessage(const uint8_t *buf, size_t buflen,
                  TransId& tid,
                  InfoHash& id_return, InfoHash& info_hash_return,
                  InfoHash& target_return, in_port_t& port_return,
                  Blob& token, Value::Id& value_id,
                  uint8_t *nodes_return, unsigned *nodes_len,
                  uint8_t *nodes6_return, unsigned *nodes6_len,
                  std::vector<std::shared_ptr<Value>>& values_return,
                             want_t* want_return, uint16_t& error_code, bool& ring);

    void rotateSecrets();

    Blob makeToken(const sockaddr *sa, bool old) const;
    bool tokenMatch(const Blob& token, const sockaddr *sa) const;

    // Storage
    Storage* findStorage(const InfoHash& id);
    const Storage* findStorage(const InfoHash& id) const {
        return const_cast<Dht*>(this)->findStorage(id);
    }

    void storageAddListener(const InfoHash& id, const InfoHash& node, const sockaddr *from, socklen_t fromlen, uint16_t tid);
    ValueStorage* storageStore(const InfoHash& id, const std::shared_ptr<Value>& value);
    void expireStorage();
    void storageChanged(Storage& st, ValueStorage&);

    // Buckets
    Bucket* findBucket(const InfoHash& id, sa_family_t af) {
        RoutingTable::iterator b;
        switch (af) {
        case AF_INET:
            b = buckets.findBucket(id);
            return b == buckets.end() ? nullptr : &(*b);
        case AF_INET6:
            b = buckets6.findBucket(id);
            return b == buckets6.end() ? nullptr : &(*b);
        default:
            return nullptr;
        }
    }
    const Bucket* findBucket(const InfoHash& id, sa_family_t af) const {
        return const_cast<Dht*>(this)->findBucket(id, af);
    }

    void expireBuckets(RoutingTable&);
    int sendCachedPing(Bucket& b);
    bool bucketMaintenance(RoutingTable&);
    static unsigned insertClosestNode(uint8_t *nodes, unsigned numnodes, const InfoHash& id, const Node& n);
    unsigned bufferClosestNodes(uint8_t *nodes, unsigned numnodes, const InfoHash& id, const Bucket& b) const;
    void dumpBucket(const Bucket& b, std::ostream& out) const;

    // Nodes
    std::shared_ptr<Node> newNode(const InfoHash& id, const sockaddr*, socklen_t, int confirm);
    std::shared_ptr<Node> findNode(const InfoHash& id, sa_family_t af);
    const std::shared_ptr<Node> findNode(const InfoHash& id, sa_family_t af) const;
    bool trySearchInsert(const std::shared_ptr<Node>& node);

    void pinged(Node& n, Bucket *b = nullptr);

    void blacklistNode(const InfoHash* id, const sockaddr*, socklen_t);
    bool isNodeBlacklisted(const sockaddr*, socklen_t) const;
    static bool isMartian(const sockaddr*, socklen_t);

    // Searches

    /**
     * Low-level method that will perform a search on the DHT for the
     * specified infohash (id), using the specified IP version (IPv4 or IPv6).
     * The values can be filtered by an arbitrary provided filter.
     */
    Search* search(const InfoHash& id, sa_family_t af, GetCallback = nullptr, DoneCallback = nullptr, Value::Filter = Value::AllFilter());
    void announce(const InfoHash& id, sa_family_t af, const std::shared_ptr<Value>& value, DoneCallback callback);
    size_t listenTo(const InfoHash& id, sa_family_t af, GetCallback cb, Value::Filter f = Value::AllFilter());

    std::list<Search>::iterator newSearch();
    void bootstrapSearch(Search& sr);
    Search *findSearch(unsigned short tid, sa_family_t af);
    void expireSearches();

    /**
     * If update is true, this method will also send message to synced but non-updated search nodes.
     */
    bool searchSendGetValues(Search& sr, SearchNode *n = nullptr, bool update = false);

    void searchStep(Search& sr);
    void dumpSearch(const Search& sr, std::ostream& out) const;

    bool rateLimit();
    bool neighbourhoodMaintenance(RoutingTable&);

    static void *dht_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);

};

}
