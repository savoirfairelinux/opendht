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
#include <functional>
#include <algorithm>
#include <memory>

namespace dht {

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
        Connected     // 4+ good nodes
    };

    typedef std::function<bool(const std::vector<std::shared_ptr<Value>>& values)> GetCallback;
    typedef std::function<void(bool success)> DoneCallback;

    struct NodeExport {
        InfoHash id;
        sockaddr_storage ss;
        socklen_t sslen;
    };

    typedef int_fast8_t want_t;

    Dht() {}

    /**
     * Initialise the Dht with two open sockets (for IPv4 and IP6)
     * and an ID for the node.
     */
    Dht(int s, int s6, const InfoHash& id);
    virtual ~Dht();

    /**
     * Get the ID of the node, which was provided in the constructor.
     */
    inline const InfoHash& getId() const { return myid; }

    /**
     * Get the current status of the node for the given family.
     */
    Status getStatus(sa_family_t af) const;

    /**
     * Returns true if the node have access to an open socket
     * for the provided family.
     */
    bool isRunning(sa_family_t af) const;

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

    void periodic(const uint8_t *buf, size_t buflen, const sockaddr *from, socklen_t fromlen, time_t *tosleep);

    /**
     * Get a value by searching on all available protocols (IPv4, IPv6),
     * and call the callback when some values are found.
     * The operation will start as soon as the node is connected to the network.
     * GetCallback will be called every time new values are found, until
     * GetCallback returns false or the search completes.
     * Then, DoneCallback is called.
     */
    void get(const InfoHash& id, GetCallback cb, DoneCallback donecb=nullptr, Value::Filter = Value::AllFilter());

    /**
     * Get locally stored data for the given hash.
     */
    std::vector<std::shared_ptr<Value>> getLocal(const InfoHash& id, Value::Filter f = Value::AllFilter()) const;

    /**
     * Get locally stored data for the given hash and value id.
     */
    std::shared_ptr<Value> getLocal(const InfoHash& id, const Value::Id& vid) const;

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
    void put(const InfoHash&, Value&&, DoneCallback cb=nullptr);

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
    std::string getRoutingTablesLog(sa_family_t af) const;
    std::string getSearchesLog(sa_family_t af) const;

    void dumpTables() const;

    /* This must be provided by the user. */
    static bool isBlacklisted(const sockaddr*, socklen_t) { return false; }

protected:
    LogMethod DHT_DEBUG = NOLOG;
    LogMethod DHT_WARN = NOLOG;
    LogMethod DHT_ERROR = NOLOG;

private:

    /* When performing a search, we search for up to SEARCH_NODES closest nodes
       to the destination, and use the additional ones to backtrack if any of
       the target 8 turn out to be dead. */
    static const unsigned SEARCH_NODES {14};

    /* The maximum number of values we store for a given hash. */
    static const unsigned MAX_VALUES {2048};

    /* The maximum number of hashes we're willing to track. */
    static const unsigned MAX_HASHES {16384};

    /* The maximum number of searches we keep data about. */
    static const unsigned MAX_SEARCHES {1024};

    /* Time for a request to timeout */
    static const time_t MAX_RESPONSE_TIME {6};

    /* A search with no nodes will timeout after this time. */
    static const time_t SEARCH_TIMEOUT {10};

    /* The time after which we can send get requests for
       a search in case of no answers. */
    static const time_t SEARCH_GET_STEP {6};

    /* The time after which we consider a search to be expirable. */
    static const time_t SEARCH_EXPIRE_TIME {62 * 60};

    /* The time after which we consider a node to be expirable. */
    static const time_t NODE_EXPIRE_TIME {15 * 60};

    /* The maximum number of nodes that we snub.  There is probably little
        reason to increase this value. */
    static const unsigned BLACKLISTED_MAX {10};

    static const long unsigned MAX_REQUESTS_PER_SEC;

    static const time_t TOKEN_EXPIRE_TIME {10 * 60};

    static const unsigned TOKEN_SIZE {64};

    struct Node {
        InfoHash id {};
        sockaddr_storage ss;
        socklen_t sslen {0};
        time_t time {0};            /* time of last message received */
        time_t reply_time {0};      /* time of last correct reply received */
        time_t pinged_time {0};     /* time of last request */
        unsigned pinged {0};        /* how many requests we sent since last reply */

        Node() {
            std::fill_n((uint8_t*)&ss, sizeof(ss), 0);
        }
        Node(const InfoHash& id, const sockaddr* sa, socklen_t salen, time_t t, time_t reply_time)
            : id(id), sslen(salen), time(t), reply_time(reply_time) {
            std::copy_n((const uint8_t*)sa, salen, (uint8_t*)&ss);
        }
        bool isGood(time_t now) const;
        NodeExport exportNode() const { return NodeExport {id, ss, sslen}; }
    };

    struct Bucket {
        Bucket() : cached() {}
        Bucket(sa_family_t af, const InfoHash& f = {}, time_t t = 0)
            : af(af), first(f), time(t), cached() {}
        sa_family_t af {0};
        InfoHash first {};
        time_t time {0};             /* time of last reply in this bucket */
        std::list<Node> nodes {};
        sockaddr_storage cached;  /* the address of a likely candidate */
        socklen_t cachedlen {0};

        /** Return a random node in a bucket. */
        Node* randomNode();
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
        SearchNode() : ss() {}
        SearchNode(const InfoHash& id) : id(id), ss() {}

        struct RequestStatus {
            time_t request_time;    /* the time of the last unanswered announce request */
            time_t reply_time;      /* the time of the last announce confirmation */
        };
        typedef std::map<Value::Id, RequestStatus> AnnounceStatusMap;

        /**
         * Can we use this node to listen/announce ?
         */
        bool isSynced(time_t now) const {
            return /*pinged < 3 && replied &&*/ reply_time >= now - NODE_EXPIRE_TIME;
        }

        bool isAnnounced(Value::Id vid, const ValueType& type, time_t now) const {
            auto ack = acked.find(vid);
            if (ack == acked.end()) {

                return false;
            }
            return ack->second.reply_time + type.expiration > now;
        }
        time_t getAnnounceTime(AnnounceStatusMap::const_iterator ack, const ValueType& type) const {
            if (ack == acked.end())
                return request_time + 5;
            return std::max<time_t>({ack->second.reply_time + type.expiration - 3, ack->second.request_time + 5, request_time + 5});
        }
        time_t getAnnounceTime(Value::Id vid, const ValueType& type) const {
            return getAnnounceTime(acked.find(vid), type);
        }
        time_t getListenTime() const {
            time_t min_t = listenStatus.request_time + MAX_RESPONSE_TIME;
            return listenStatus.reply_time ? std::max(listenStatus.reply_time + NODE_EXPIRE_TIME - 5, min_t) : min_t;
        }

        InfoHash id {};
        sockaddr_storage ss;
        socklen_t sslen {0};
        time_t request_time {0};    /* the time of the last unanswered request */
        time_t reply_time {0};      /* the time of the last reply with a token */
        unsigned pinged {0};

        RequestStatus listenStatus {0, 0};

        Blob token {};

        AnnounceStatusMap acked {};  /* announcement status for a given value id */

        // Generic temporary flag.
        // Must be reset to false after use by the algorithm.
        bool pending {false};
    };

    struct Get {
        time_t start;
        Value::Filter filter;
        GetCallback get_cb;
        DoneCallback done_cb;
    };

    struct Announce {
        std::shared_ptr<Value> value;
        DoneCallback callback;
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
        time_t step_time {0};           /* the time of the last search_step */

        bool done {false};
        std::vector<SearchNode> nodes {SEARCH_NODES+1};
        std::vector<Announce> announce {};
        std::vector<Get> callbacks {};

        std::map<size_t, std::pair<Value::Filter, GetCallback>> listeners {};
        size_t listener_token = 1;

        bool insertNode(const InfoHash& id, const sockaddr*, socklen_t, time_t now, bool confirmed=false, const Blob& token={});
        void insertBucket(const Bucket&, time_t now);

        /**
         * Can we use this search to announce ?
         */
        bool isSynced(time_t now) const;

        time_t getLastGetTime() const;

        bool isUpdated(const SearchNode& sn) const;

        /**
         * Is this get operation done ?
         */
        bool isDone(const Get& get, time_t now) const;

        time_t getUpdateTime(time_t now) const;

        bool isAnnounced(Value::Id id, const ValueType& type, time_t now) const;

        /**
         * ret = 0 : no announce required.
         * ret > 0 : (re-)announce required at time ret.
         */
        time_t getAnnounceTime(const std::map<ValueType::Id, ValueType>& types) const;

        /**
         * ret = 0 : no listen required.
         * ret > 0 : (re-)announce required at time ret.
         */
        time_t getListenTime(time_t now) const;

        /**
         * ret = 0 : no expiration
         * ret > 0 : search will expire at time ret
         */
        time_t getExpireTime() const;

        time_t getNextStepTime(const std::map<ValueType::Id, ValueType>& types, time_t now) const;
    };

    struct ValueStorage {
        std::shared_ptr<Value> data {};
        time_t time {0};

        ValueStorage() {}
        ValueStorage(const std::shared_ptr<Value>& v, time_t t) : data(v), time(t) {}
    };

    /**
     * Foreign nodes asking for updates about an InfoHash.
     */
    struct Listener {
        InfoHash id {};
        sockaddr_storage ss;
        socklen_t sslen {};
        uint16_t tid {};
        time_t time {};

        constexpr Listener() : ss() {}
        Listener(const InfoHash& id, const sockaddr *from, socklen_t fromlen, uint16_t ttid, time_t t) : id(id), ss(), sslen(fromlen), tid(ttid), time(t) {
            memcpy(&ss, from, fromlen);
        }
        void refresh(const sockaddr *from, socklen_t fromlen, uint16_t ttid, time_t t) {
            memcpy(&ss, from, fromlen);
            sslen = fromlen;
            tid = ttid;
            time = t;
        }
    };

    struct Storage {
        InfoHash id;
        std::vector<ValueStorage> values;
        std::vector<Listener> listeners;
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

    // the stuff
    RoutingTable buckets {};
    RoutingTable buckets6 {};
    std::vector<Storage> store {};
    std::list<Search> searches {};
    uint16_t search_id {0};

    // map a global listen token to IPv4, IPv6 specific listen tokens.
    // 0 is the invalid token.
    std::map<size_t, std::pair<size_t, size_t>> listeners {};
    size_t listener_token {1};

    sockaddr_storage blacklist[BLACKLISTED_MAX] {};
    unsigned next_blacklisted = 0;

    struct timeval now {0, 0};
    time_t mybucket_grow_time {0}, mybucket6_grow_time {0};
    time_t expire_stuff_time {0};
    time_t search_time {0};
    time_t confirm_nodes_time {0};
    time_t rotate_secrets_time {0};
    time_t rate_limit_time {0};

    // remaining requests for this second
    long unsigned rate_limit_tokens {MAX_REQUESTS_PER_SEC};

    // Networking & packet handling
    int send(const char* buf, size_t len, int flags, const sockaddr*, socklen_t);
    int sendPing(const sockaddr*, socklen_t, TransId tid);
    int sendPong(const sockaddr*, socklen_t, TransId tid);

    int sendFindNode(const sockaddr*, socklen_t, TransId tid,
                        const InfoHash& target, want_t want, int confirm);

    int sendNodesValues(const sockaddr*, socklen_t, TransId tid,
                              const uint8_t *nodes, unsigned nodes_len,
                              const uint8_t *nodes6, unsigned nodes6_len,
                              Storage *st, const Blob& token);

    int sendClosestNodes(const sockaddr*, socklen_t, TransId tid,
                               const InfoHash& id, want_t want, const Blob& token={},
                               Storage *st=nullptr);

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
                  want_t* want_return, uint16_t& error_code);

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
    void storageChanged(Storage& st);

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
    Node* newNode(const InfoHash& id, const sockaddr*, socklen_t, int confirm);
    Node* findNode(const InfoHash& id, sa_family_t af);
    const Node* findNode(const InfoHash& id, sa_family_t af) const;

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
