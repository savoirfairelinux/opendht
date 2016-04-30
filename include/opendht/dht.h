/*
Copyright (C) 2009-2014 Juliusz Chroboczek
Copyright (C) 2014-2016 Savoir-faire Linux Inc.

Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>,
            Juliusz Chroboczek <jch@pps.univ–paris–diderot.fr>
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

#define WANT4 1
#define WANT6 2

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

using want_t = int_fast8_t;
using Address = std::pair<sockaddr_storage, socklen_t>;

std::string print_addr(const sockaddr* sa, socklen_t slen);
std::string print_addr(const sockaddr_storage& ss, socklen_t sslen);
std::string printAddr(const Address& addr);

struct NodeExport {
    InfoHash id;
    sockaddr_storage ss;
    socklen_t sslen;
};

struct Node {
    InfoHash id {};
    sockaddr_storage ss;
    socklen_t sslen {0};
    time_point time {time_point::min()};            /* last time eared about */
    time_point reply_time {time_point::min()};      /* time of last correct reply received */
    time_point pinged_time {time_point::min()};     /* time of last message sent */
    unsigned pinged {0};           /* how many requests we sent since last reply */

    Node() : ss() {
        std::fill_n((uint8_t*)&ss, sizeof(ss), 0);
    }
    Node(const InfoHash& id, const sockaddr* sa, socklen_t salen)
        : id(id), ss(), sslen(salen) {
        std::copy_n((const uint8_t*)sa, salen, (uint8_t*)&ss);
        if ((unsigned)salen < sizeof(ss))
            std::fill_n((uint8_t*)&ss+salen, sizeof(ss)-salen, 0);
    }
    InfoHash getId() const {
        return id;
    }
    std::pair<const sockaddr*, socklen_t> getAddr() const {
        return {(const sockaddr*)&ss, sslen};
    }
    std::string getAddrStr() const {
        return print_addr(ss, sslen);
    }
    bool isExpired(time_point now) const;
    bool isExpired() const { return isExpired(clock::now()); }
    bool isGood(time_point now) const;
    bool isMessagePending(time_point now) const;
    NodeExport exportNode() const { return NodeExport {id, ss, sslen}; }
    sa_family_t getFamily() const { return ss.ss_family; }

    void update(const sockaddr* sa, socklen_t salen);

    /** To be called when a message was sent to the node */
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

    struct Config {
        InfoHash node_id;
        bool is_bootstrap;
    };

    // [[deprecated]]
    using NodeExport = dht::NodeExport;

    typedef std::function<bool(const std::vector<std::shared_ptr<Value>>& values)> GetCallback;
    typedef std::function<bool(std::shared_ptr<Value> value)> GetCallbackSimple;
    typedef std::function<void()> ShutdownCallback;

    typedef bool (*GetCallbackRaw)(std::shared_ptr<Value>, void *user_data);

    static constexpr size_t DEFAULT_STORAGE_LIMIT {1024 * 1024 * 64};

    static GetCallbackSimple
    bindGetCb(GetCallbackRaw raw_cb, void* user_data) {
        if (not raw_cb) return {};
        return [=](const std::shared_ptr<Value>& value) {
            return raw_cb(value, user_data);
        };
    }
    static GetCallback
    bindGetCb(GetCallbackSimple cb) {
        if (not cb) return {};
        return [=](const std::vector<std::shared_ptr<Value>>& values) {
            for (const auto& v : values)
                if (not cb(v))
                    return false;
            return true;
        };
    }

    typedef std::function<void(bool success, const std::vector<std::shared_ptr<Node>>& nodes)> DoneCallback;
    typedef void (*DoneCallbackRaw)(bool, std::vector<std::shared_ptr<Node>>*, void *user_data);
    typedef void (*ShutdownCallbackRaw)(void *user_data);

    typedef std::function<void(bool success)> DoneCallbackSimple;

    static ShutdownCallback
    bindShutdownCb(ShutdownCallbackRaw shutdown_cb_raw, void* user_data) {
        return [=]() { shutdown_cb_raw(user_data); };
    }
    static DoneCallback
    bindDoneCb(DoneCallbackSimple donecb) {
        if (not donecb) return {};
        using namespace std::placeholders;
        return std::bind(donecb, _1);
    }
    static DoneCallback
    bindDoneCb(DoneCallbackRaw raw_cb, void* user_data) {
        if (not raw_cb) return {};
        return [=](bool success, const std::vector<std::shared_ptr<Node>>& nodes) {
            raw_cb(success, (std::vector<std::shared_ptr<Node>>*)&nodes, user_data);
        };
    }

    Dht() {}

    /**
     * Initialise the Dht with two open sockets (for IPv4 and IP6)
     * and an ID for the node.
     */
    Dht(int s, int s6, Config config);
    virtual ~Dht();

    /**
     * Get the ID of the node.
     */
    inline const InfoHash& getNodeId() const { return myid; }

    /**
     * Get the current status of the node for the given family.
     */
    Status getStatus(sa_family_t af) const;

    Status getStatus() const {
        return std::max(getStatus(AF_INET), getStatus(AF_INET6));
    }

    /**
     * Performs final operations before quitting.
     */
    void shutdown(ShutdownCallback cb);

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
     * and call the provided get callback when values are found at key.
     * The operation will start as soon as the node is connected to the network.
     * @param cb a function called when new values are found on the network.
     *           It should return false to stop the operation.
     * @param donecb a function called when the operation is complete.
                        cb and donecb won't be called again afterward.
     * @param f a filter function used to prefilter values.
     */
    void get(const InfoHash& key, GetCallback cb, DoneCallback donecb=nullptr, Value::Filter f = Value::AllFilter());
    void get(const InfoHash& key, GetCallback cb, DoneCallbackSimple donecb, Value::Filter f = Value::AllFilter()) {
        get(key, cb, bindDoneCb(donecb), f);
    }
    void get(const InfoHash& key, GetCallbackSimple cb, DoneCallback donecb=nullptr, Value::Filter f = Value::AllFilter()) {
        get(key, bindGetCb(cb), donecb, f);
    }
    void get(const InfoHash& key, GetCallbackSimple cb, DoneCallbackSimple donecb, Value::Filter f = Value::AllFilter()) {
        get(key, bindGetCb(cb), bindDoneCb(donecb), f);
    }

    /**
     * Get locally stored data for the given hash.
     */
    std::vector<std::shared_ptr<Value>> getLocal(const InfoHash& key, Value::Filter f = Value::AllFilter()) const;

    /**
     * Get locally stored data for the given key and value id.
     */
    std::shared_ptr<Value> getLocalById(const InfoHash& key, Value::Id vid) const;

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
    void put(const InfoHash& key, std::shared_ptr<Value>, DoneCallback cb=nullptr, time_point created=time_point::max());
    void put(const InfoHash& key, const std::shared_ptr<Value>& v, DoneCallbackSimple cb, time_point created=time_point::max()) {
        put(key, v, bindDoneCb(cb), created);
    }

    void put(const InfoHash& key, Value&& v, DoneCallback cb=nullptr, time_point created=time_point::max()) {
        put(key, std::make_shared<Value>(std::move(v)), cb, created);
    }
    void put(const InfoHash& key, Value&& v, DoneCallbackSimple cb, time_point created=time_point::max()) {
        put(key, std::forward<Value>(v), bindDoneCb(cb), created);
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
     * for the value with the given id.
     */
    bool cancelPut(const InfoHash&, const Value::Id&);

    /**
     * Listen on the network for any changes involving a specified hash.
     * The node will register to receive updates from relevent nodes when
     * new values are added or removed.
     *
     * @return a token to cancel the listener later.
     */
    size_t listen(const InfoHash&, GetCallback, Value::Filter = Value::AllFilter());
    size_t listen(const InfoHash& key, GetCallbackSimple cb, Value::Filter f = Value::AllFilter()) {
        return listen(key, bindGetCb(cb), f);
    }

    bool cancelListen(const InfoHash&, size_t token);

    /**
     * Inform the DHT of lower-layer connectivity changes.
     * This will cause the DHT to assume a public IP address change.
     * The DHT will recontact neighbor nodes, re-register for listen ops etc.
     */
    void connectivityChanged();

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
    std::vector<unsigned> getNodeMessageStats(bool in = false) {
        auto stats = in ? std::vector<unsigned>{in_stats.ping,  in_stats.find,  in_stats.get,  in_stats.listen,  in_stats.put}
                  : std::vector<unsigned>{out_stats.ping, out_stats.find, out_stats.get, out_stats.listen, out_stats.put};
        if (in) { in_stats = {}; }
        else { out_stats = {}; }

        return stats;
    }

    /**
     * Set the in-memory storage limit in bytes
     */
    void setStorageLimit(size_t limit = DEFAULT_STORAGE_LIMIT) {
        max_store_size = limit;
    }

    /**
     * Returns the total memory usage of stored values and the number
     * of stored values.
     */
    std::pair<size_t, size_t> getStoreSize() const {
        return {total_store_size, total_values};
    }

    /* This must be provided by the user. */
    static bool isBlacklisted(const sockaddr*, socklen_t) { return false; }

    std::vector<Address> getPublicAddress(sa_family_t family = 0);

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
    static constexpr unsigned MAX_SEARCHES {128};

    /* The time after which we can send get requests for
       a search in case of no answers. */
    static constexpr std::chrono::seconds SEARCH_GET_STEP {3};

    static constexpr std::chrono::minutes MAX_STORAGE_MAINTENANCE_EXPIRE_TIME {10};

    /* The time after which we consider a search to be expirable. */
    static constexpr std::chrono::minutes SEARCH_EXPIRE_TIME {62};

    /* Timeout for listen */
    static constexpr std::chrono::seconds LISTEN_EXPIRE_TIME {30};

    static constexpr std::chrono::seconds REANNOUNCE_MARGIN {5};

    static constexpr std::chrono::seconds UDP_REPLY_TIME {15};

    /* The maximum number of nodes that we snub.  There is probably little
        reason to increase this value. */
    static constexpr unsigned BLACKLISTED_MAX {10};

    static constexpr long unsigned MAX_REQUESTS_PER_SEC {1600};

    static constexpr size_t TOKEN_SIZE {64};

    struct NodeCache {
        std::shared_ptr<Node> getNode(const InfoHash& id, sa_family_t family);
        std::shared_ptr<Node> getNode(const InfoHash& id, const sockaddr* sa, socklen_t sa_len, time_point now, int confirmed);
        void putNode(std::shared_ptr<Node> n);

        /**
         * Reset the connectivity state of every node,
         * Giving them a new chance if they where expired.
         * To use in case of connectivity change etc.
         */
        void clearBadNodes(sa_family_t family = 0);
    private:
        std::list<std::weak_ptr<Node>> cache_4;
        std::list<std::weak_ptr<Node>> cache_6;
    };

    struct Bucket {
        Bucket() : cached() {}
        Bucket(sa_family_t af, const InfoHash& f = {}, time_point t = time_point::min())
            : af(af), first(f), time(t), cached() {}
        sa_family_t af {0};
        InfoHash first {};
        time_point time {time_point::min()};             /* time of last reply in this bucket */
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

        std::vector<std::shared_ptr<Node>> findClosestNodes(const InfoHash id, size_t count = TARGET_NODES) const;

        RoutingTable::iterator findBucket(const InfoHash& id);
        RoutingTable::const_iterator findBucket(const InfoHash& id) const;

        /**
         * Return true if the id is in the bucket's range.
         */
        inline bool contains(const RoutingTable::const_iterator& bucket, const InfoHash& id) const {
            return InfoHash::cmp(bucket->first, id) <= 0
                && (std::next(bucket) == end() || InfoHash::cmp(id, std::next(bucket)->first) < 0);
        }

        /**
         * Return true if the table has no bucket ore one empty buket.
         */
        inline bool isEmpty() const {
            return empty() || (size() == 1 && front().nodes.empty());
        }

        /**
         * Return a random id in the bucket's range.
         */
        InfoHash randomId(const RoutingTable::const_iterator& bucket) const;

        unsigned depth(const RoutingTable::const_iterator& bucket) const;

        /**
         * Split a bucket in two equal parts.
         */
        bool split(const RoutingTable::iterator& b);
    };

    struct SearchNode {
        SearchNode(std::shared_ptr<Node> node) : node(node) {}

        struct RequestStatus {
            time_point request_time {time_point::min()};    /* the time of the last unanswered request */
            time_point reply_time {time_point::min()};      /* the time of the last confirmation */
            RequestStatus() {};
            RequestStatus(time_point q, time_point a = time_point::min()) : request_time(q), reply_time(a) {};
            bool expired(time_point now) const {
                return reply_time < request_time && now > request_time + Node::MAX_RESPONSE_TIME;
            }
            bool pending(time_point now) const {
                return reply_time < request_time && now - request_time <= Node::MAX_RESPONSE_TIME;
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
                return time_point::min();
            return std::max(
                ack->second.reply_time + type.expiration - REANNOUNCE_MARGIN,
                ack->second.request_time + Node::MAX_RESPONSE_TIME
            );
        }
        time_point getAnnounceTime(Value::Id vid, const ValueType& type) const {
            return getAnnounceTime(acked.find(vid), type);
        }
        time_point getListenTime() const {
            return std::max(
                listenStatus.reply_time + LISTEN_EXPIRE_TIME - REANNOUNCE_MARGIN,
                listenStatus.request_time + Node::MAX_RESPONSE_TIME
            );
        }
        bool isBad(const time_point& now) const {
            return !node || node->isExpired(now) || candidate;
        }

        std::shared_ptr<Node> node {};

        RequestStatus getStatus {};    /* get/sync status */
        RequestStatus listenStatus {};
        AnnounceStatusMap acked {};    /* announcement status for a given value id */

        Blob token {};

        /**
         * A search node is candidate if the search is/was synced and this node is a new candidate for inclusion
         *
         */
        bool candidate {false};

        // Generic temporary flag.
        // Must be reset to false after use by the algorithm.
        bool pending {false};
    };

    /**
     * A single "get" operation data
     */
    struct Get {
        time_point start;
        Value::Filter filter;
        GetCallback get_cb;
        DoneCallback done_cb;
    };

    /**
     * A single "put" operation data
     */
    struct Announce {
        std::shared_ptr<Value> value;
        time_point created;
        DoneCallback callback;
    };

    /**
     * A single "listen" operation data
     */
    struct LocalListener {
        Value::Filter filter;
        GetCallback get_cb;
    };

    /**
     * A search is a pointer to the nodes we think are responsible
     * for storing values for a given hash.
     */
    struct Search {
        InfoHash id {};
        sa_family_t af;

        uint16_t tid;
        time_point refill_time {time_point::min()};
        time_point step_time {time_point::min()};           /* the time of the last search step */
        time_point get_step_time {time_point::min()};       /* the time of the last get step */

        bool expired {false};              /* no node, or all nodes expired */
        bool done {false};                 /* search is over, cached for later */
        std::vector<SearchNode> nodes {};

        /* pending puts */
        std::vector<Announce> announce {};

        /* pending gets */
        std::vector<Get> callbacks {};

        /* listeners */
        std::map<size_t, LocalListener> listeners {};
        size_t listener_token = 1;

        /**
         * @returns true if the node was not present and added to the search
         */
        bool insertNode(std::shared_ptr<Node> n, time_point now, const Blob& token={});
        unsigned insertBucket(const Bucket&, time_point now);

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
         * @return The number of non-good search nodes.
         */
        unsigned getNumberOfBadNodes(time_point now);

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

        unsigned refill(const RoutingTable&, time_point now);

        std::vector<std::shared_ptr<Node>> getNodes() const;
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
        time_point maintenance_time {};
        std::vector<Listener> listeners {};
        std::map<size_t, LocalListener> local_listeners {};
        size_t listener_token {1};

        Storage() {}
        Storage(InfoHash id, time_point now) : id(id), maintenance_time(now+MAX_STORAGE_MAINTENANCE_EXPIRE_TIME) {}

#if defined(__GNUC__) && __GNUC__ == 4 && __GNUC_MINOR__ <= 9
        // GCC-bug: remove me when support of GCC < 4.9.2 is abandoned
        Storage(Storage&& o) noexcept
			: id(std::move(o.id))
            , maintenance_time(std::move(o.maintenance_time))
            , listeners(std::move(o.listeners))
            , local_listeners(std::move(o.local_listeners))
            , listener_token(std::move(o.listener_token))
            , values(std::move(o.values))
            , total_size(std::move(o.total_size)) {}
#else
        Storage(Storage&& o) noexcept = default;
#endif

        Storage& operator=(Storage&& o) = default;

        bool empty() const {
            return values.empty();
        }

        void clear();

        size_t valueCount() const {
            return values.size();
        }

        size_t totalSize() const {
            return total_size;
        }

        const std::vector<ValueStorage>& getValues() const { return values; }

        std::shared_ptr<Value> getById(Value::Id vid) const {
            for (auto& v : values)
                if (v.data->id == vid) return v.data;
            return {};
        }

        std::vector<std::shared_ptr<Value>> get(Value::Filter f = {}) const {
            std::vector<std::shared_ptr<Value>> newvals {};
            if (not f) newvals.reserve(values.size());
            for (auto& v : values) {
                if (not f || f(*v.data))
                    newvals.push_back(v.data);
            }
            return newvals;
        }

        /**
         * Stores a new value in this storage, or replace a previous value
         *
         * @return <storage, change_size, change_value_num>
         *      storage: set if a change happened
         *      change_size: size difference
         *      change_value_num: change of value number (0 or 1)
         */
        std::tuple<ValueStorage*, ssize_t, ssize_t>
        store(const std::shared_ptr<Value>& value, time_point created, ssize_t size_left);

        std::pair<ssize_t, ssize_t> expire(const std::map<ValueType::Id, ValueType>& types, time_point now);

    private:
        Storage(const Storage&) = delete;
        Storage& operator=(const Storage&) = delete;

        std::vector<ValueStorage> values {};
        size_t total_size {};
    };

    // prevent copy
    Dht(const Dht&) = delete;
    Dht& operator=(const Dht&) = delete;

    // socket descriptors
    int dht_socket {-1};
    int dht_socket6 {-1};

    InfoHash myid {};

    std::array<uint8_t, 8> secret {{}};
    std::array<uint8_t, 8> oldsecret {{}};

    // registred types
    std::map<ValueType::Id, ValueType> types;

    // cache of nodes not in the main routing table but used for searches
    NodeCache cache;

    // are we a bootstrap node ?
    // note: Any running node can be used as a bootstrap node.
    //       Only nodes running only as bootstrap nodes should
    //       be put in bootstrap mode.
    const bool is_bootstrap {false};

    // the stuff
    RoutingTable buckets {};
    RoutingTable buckets6 {};

    std::vector<Storage> store {};
    size_t total_values {0};
    size_t total_store_size {0};
    size_t max_store_size {DEFAULT_STORAGE_LIMIT};

    std::list<Search> searches {};
    uint16_t search_id {0};

    // map a global listen token to IPv4, IPv6 specific listen tokens.
    // 0 is the invalid token.
    std::map<size_t, std::tuple<size_t, size_t, size_t>> listeners {};
    size_t listener_token {1};

    sockaddr_storage blacklist[BLACKLISTED_MAX] {};
    unsigned next_blacklisted = 0;

    // timing
    time_point now;
    time_point mybucket_grow_time {time_point::min()}, mybucket6_grow_time {time_point::min()};
    time_point expire_stuff_time {time_point::min()};
    time_point search_time {time_point::max()};
    time_point confirm_nodes_time {time_point::min()};
    time_point rotate_secrets_time {time_point::min()};
    std::queue<time_point> rate_limit_time {};

    using ReportedAddr = std::pair<unsigned, Address>;
    std::vector<ReportedAddr> reported_addr;

    void rotateSecrets();

    Blob makeToken(const sockaddr *sa, bool old) const;
    bool tokenMatch(const Blob& token, const sockaddr *sa) const;

    void reportedAddr(const sockaddr *sa, socklen_t sa_len);

    // Storage
    decltype(Dht::store)::iterator findStorage(const InfoHash& id) {
        return std::find_if(store.begin(), store.end(), [&](const Storage& st) {
            return st.id == id;
        });
    }
    decltype(Dht::store)::const_iterator findStorage(const InfoHash& id) const {
        return std::find_if(store.cbegin(), store.cend(), [&](const Storage& st) {
            return st.id == id;
        });
    }

    void storageAddListener(const InfoHash& id, const InfoHash& node, const sockaddr *from, socklen_t fromlen, uint16_t tid);
    bool storageStore(const InfoHash& id, const std::shared_ptr<Value>& value, time_point created);
    void expireStorage();
    void storageChanged(Storage& st, ValueStorage&);

    /**
     * For a given storage, if values don't belong there anymore because this
     * node is too far from the target, values are sent to the appropriate
     * nodes.
     */
    size_t maintainStorage(InfoHash id, bool force=false, DoneCallback donecb=nullptr);

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
    std::shared_ptr<Node> newNode(const InfoHash& id, const sockaddr*, socklen_t, int confirm, const sockaddr* addr=nullptr, socklen_t addr_length=0);
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
    void announce(const InfoHash& id, sa_family_t af, std::shared_ptr<Value> value, DoneCallback callback, time_point created=time_point::max());
    size_t listenTo(const InfoHash& id, sa_family_t af, GetCallback cb, Value::Filter f = Value::AllFilter());

    std::list<Search>::iterator newSearch();
    void bootstrapSearch(Search& sr);
    Search *findSearch(unsigned short tid, sa_family_t af);
    void expireSearches();

    /**
     * If update is true, this method will also send message to synced but non-updated search nodes.
     */
    SearchNode* searchSendGetValues(Search& sr, SearchNode *n = nullptr, bool update = true);

    void searchStep(Search& sr);
    void dumpSearch(const Search& sr, std::ostream& out) const;

    bool rateLimit();
    bool neighbourhoodMaintenance(RoutingTable&);

    struct MessageStats {
        unsigned ping {0};
        unsigned find {0};
        unsigned get {0};
        unsigned put {0};
        unsigned listen {0};
    };

    MessageStats in_stats {}, out_stats {};

};

}
