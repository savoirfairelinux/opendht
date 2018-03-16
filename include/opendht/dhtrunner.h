/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
 *  Authors: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *           Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
 *           Sébastien Blin <sebastien.blin@savoirfairelinux.com>
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

#include "infohash.h"
#include "value.h"
#include "callbacks.h"
#include "sockaddr.h"
#include "log_enable.h"
#include "def.h"

#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <future>
#include <exception>
#include <queue>
#include <chrono>

namespace dht {

struct Node;
class SecureDht;
struct SecureDhtConfig;

/**
 * Provides a thread-safe interface to run the (secure) DHT.
 * The class will open sockets on the provided port and will
 * either wait for (expectedly frequent) calls to ::loop() or start an internal
 * thread that will update the DHT when appropriate.
 */
class OPENDHT_PUBLIC DhtRunner {

public:
    typedef std::function<void(NodeStatus, NodeStatus)> StatusCallback;

    struct Config {
        SecureDhtConfig dht_config;
        bool threaded;
        std::string proxy_server;
        std::string push_node_id;
    };

    DhtRunner();
    virtual ~DhtRunner();

    void get(InfoHash id, GetCallbackSimple cb, DoneCallback donecb={}, Value::Filter f = Value::AllFilter(), Where w = {}) {
        get(id, bindGetCb(cb), donecb, f, w);
    }

    void get(InfoHash id, GetCallbackSimple cb, DoneCallbackSimple donecb={}, Value::Filter f = Value::AllFilter(), Where w = {}) {
        get(id, bindGetCb(cb), donecb, f, w);
    }

    void get(InfoHash hash, GetCallback vcb, DoneCallback dcb, Value::Filter f={}, Where w = {});

    void get(InfoHash id, GetCallback cb, DoneCallbackSimple donecb={}, Value::Filter f = Value::AllFilter(), Where w = {}) {
        get(id, cb, bindDoneCb(donecb), f, w);
    }
    void get(const std::string& key, GetCallback vcb, DoneCallbackSimple dcb={}, Value::Filter f = Value::AllFilter(), Where w = {});

    template <class T>
    void get(InfoHash hash, std::function<bool(std::vector<T>&&)> cb, DoneCallbackSimple dcb={})
    {
        get(hash, [=](const std::vector<std::shared_ptr<Value>>& vals) {
            return cb(unpackVector<T>(vals));
        },
        dcb,
        getFilterSet<T>());
    }
    template <class T>
    void get(InfoHash hash, std::function<bool(T&&)> cb, DoneCallbackSimple dcb={})
    {
        get(hash, [=](const std::vector<std::shared_ptr<Value>>& vals) {
            for (const auto& v : vals) {
                try {
                    if (not cb(Value::unpack<T>(*v)))
                        return false;
                } catch (const std::exception&) {
                    continue;
                }
            }
            return true;
        },
        dcb,
        getFilterSet<T>());
    }

    std::future<std::vector<std::shared_ptr<dht::Value>>> get(InfoHash key, Value::Filter f = Value::AllFilter(), Where w = {}) {
        auto p = std::make_shared<std::promise<std::vector<std::shared_ptr< dht::Value >>>>();
        auto values = std::make_shared<std::vector<std::shared_ptr< dht::Value >>>();
        get(key, [=](const std::vector<std::shared_ptr<dht::Value>>& vlist) {
            values->insert(values->end(), vlist.begin(), vlist.end());
            return true;
        }, [=](bool) {
            p->set_value(std::move(*values));
        },
        f, w);
        return p->get_future();
    }

    template <class T>
    std::future<std::vector<T>> get(InfoHash key) {
        auto p = std::make_shared<std::promise<std::vector<T>>>();
        auto values = std::make_shared<std::vector<T>>();
        get<T>(key, [=](T&& v) {
            values->emplace_back(std::move(v));
            return true;
        }, [=](bool) {
            p->set_value(std::move(*values));
        });
        return p->get_future();
    }

    void query(const InfoHash& hash, QueryCallback cb, DoneCallback done_cb = {}, Query q = {});
    void query(const InfoHash& hash, QueryCallback cb, DoneCallbackSimple done_cb = {}, Query q = {}) {
        query(hash, cb, bindDoneCb(done_cb), q);
    }

    std::future<size_t> listen(InfoHash key, GetCallback vcb, Value::Filter f = Value::AllFilter(), Where w = {});
    std::future<size_t> listen(const std::string& key, GetCallback vcb, Value::Filter f = Value::AllFilter(), Where w = {});
    std::future<size_t> listen(InfoHash key, GetCallbackSimple cb, Value::Filter f = Value::AllFilter(), Where w = {}) {
        return listen(key, bindGetCb(cb), f, w);
    }

    template <class T>
    std::future<size_t> listen(InfoHash hash, std::function<bool(std::vector<T>&&)> cb)
    {
        return listen(hash, [=](const std::vector<std::shared_ptr<Value>>& vals) {
            return cb(unpackVector<T>(vals));
        },
        getFilterSet<T>());
    }
    template <typename T>
    std::future<size_t> listen(InfoHash hash, std::function<bool(T&&)> cb, Value::Filter f = Value::AllFilter(), Where w = {})
    {
        return listen(hash, [=](const std::vector<std::shared_ptr<Value>>& vals) {
            for (const auto& v : vals) {
                try {
                    if (not cb(Value::unpack<T>(*v)))
                        return false;
                } catch (const std::exception&) {
                    continue;
                }
            }
            return true;
        },
        getFilterSet<T>(f), w);
    }

    void cancelListen(InfoHash h, size_t token);
    void cancelListen(InfoHash h, std::shared_future<size_t> token);

    void put(InfoHash hash, std::shared_ptr<Value> value, DoneCallback cb={}, time_point created=time_point::max(), bool permanent = false);
    void put(InfoHash hash, std::shared_ptr<Value> value, DoneCallbackSimple cb, time_point created=time_point::max(), bool permanent = false) {
        put(hash, value, bindDoneCb(cb), created, permanent);
    }

    void put(InfoHash hash, Value&& value, DoneCallback cb={}, time_point created=time_point::max(), bool permanent = false);
    void put(InfoHash hash, Value&& value, DoneCallbackSimple cb, time_point created=time_point::max(), bool permanent = false) {
        put(hash, std::forward<Value>(value), bindDoneCb(cb), created, permanent);
    }
    void put(const std::string& key, Value&& value, DoneCallbackSimple cb={}, time_point created=time_point::max(), bool permanent = false);

    void cancelPut(const InfoHash& h, const Value::Id& id);

    void putSigned(InfoHash hash, std::shared_ptr<Value> value, DoneCallback cb={});
    void putSigned(InfoHash hash, std::shared_ptr<Value> value, DoneCallbackSimple cb) {
        putSigned(hash, value, bindDoneCb(cb));
    }

    void putSigned(InfoHash hash, Value&& value, DoneCallback cb={});
    void putSigned(InfoHash hash, Value&& value, DoneCallbackSimple cb) {
        putSigned(hash, std::forward<Value>(value), bindDoneCb(cb));
    }
    void putSigned(const std::string& key, Value&& value, DoneCallbackSimple cb={});

    void putEncrypted(InfoHash hash, InfoHash to, std::shared_ptr<Value> value, DoneCallback cb={});
    void putEncrypted(InfoHash hash, InfoHash to, std::shared_ptr<Value> value, DoneCallbackSimple cb) {
        putEncrypted(hash, to, value, bindDoneCb(cb));
    }

    void putEncrypted(InfoHash hash, InfoHash to, Value&& value, DoneCallback cb={});
    void putEncrypted(InfoHash hash, InfoHash to, Value&& value, DoneCallbackSimple cb) {
        putEncrypted(hash, to, std::forward<Value>(value), bindDoneCb(cb));
    }
    void putEncrypted(const std::string& key, InfoHash to, Value&& value, DoneCallback cb={});

    /**
     * Insert known nodes to the routing table, without necessarly ping them.
     * Usefull to restart a node and get things running fast without putting load on the network.
     */
    void bootstrap(const std::vector<SockAddr>& nodes, DoneCallbackSimple&& cb={});
    void bootstrap(const SockAddr& addr, DoneCallbackSimple&& cb={});

    /**
     * Insert known nodes to the routing table, without necessarly ping them.
     * Usefull to restart a node and get things running fast without putting load on the network.
     */
    void bootstrap(const std::vector<NodeExport>& nodes);

    /**
     * Add host:service to bootstrap nodes, and ping this node.
     * DNS resolution is performed asynchronously.
     * When disconnected, all bootstrap nodes added with this method will be tried regularly until connection
     * to the DHT network is established.
     */
    void bootstrap(const std::string& host, const std::string& service);

    /**
     * Clear the list of bootstrap added using bootstrap(const std::string&, const std::string&).
     */
    void clearBootstrap();

    /**
     * Inform the DHT of lower-layer connectivity changes.
     * This will cause the DHT to assume an IP address change.
     * The DHT will recontact neighbor nodes, re-register for listen ops etc.
     */
    void connectivityChanged();

    void dumpTables() const;

    InfoHash getId() const;

    InfoHash getNodeId() const;

    /**
     * Returns the currently bound address.
     * @param f: address family of the bound address to retreive.
     */
    const SockAddr& getBound(sa_family_t f = AF_INET) const {
        return (f == AF_INET) ? bound4 : bound6;
    }

    /**
     * Returns the currently bound port, in host byte order.
     * @param f: address family of the bound port to retreive.
     */
    in_port_t getBoundPort(sa_family_t f = AF_INET) const {
        return getBound(f).getPort();
    }

    std::pair<size_t, size_t> getStoreSize() const;

    void setStorageLimit(size_t limit = DEFAULT_STORAGE_LIMIT);

    std::vector<NodeExport> exportNodes() const;

    std::vector<ValuesExport> exportValues() const;

    void setLoggers(LogMethod err = NOLOG, LogMethod warn = NOLOG, LogMethod debug = NOLOG);

    /**
     * Only print logs related to the given InfoHash (if given), or disable filter (if zeroes).
     */
    void setLogFilter(const InfoHash& f = {});

    void registerType(const ValueType& type);

    void importValues(const std::vector<ValuesExport>& values);

    bool isRunning() const {
        return running;
    }

    NodeStats getNodesStats(sa_family_t af) const;
    unsigned getNodesStats(sa_family_t af, unsigned *good_return, unsigned *dubious_return, unsigned *cached_return, unsigned *incoming_return) const;

    std::vector<unsigned> getNodeMessageStats(bool in = false) const;
    std::string getStorageLog() const;
    std::string getStorageLog(const InfoHash&) const;
    std::string getRoutingTablesLog(sa_family_t af) const;
    std::string getSearchesLog(sa_family_t af = AF_UNSPEC) const;
    std::string getSearchLog(const InfoHash&, sa_family_t af = AF_UNSPEC) const;
    std::vector<SockAddr> getPublicAddress(sa_family_t af = AF_UNSPEC);
    std::vector<std::string> getPublicAddressStr(sa_family_t af = AF_UNSPEC);

    // securedht methods

    void findCertificate(InfoHash hash, std::function<void(const std::shared_ptr<crypto::Certificate>)>);
    void registerCertificate(std::shared_ptr<crypto::Certificate> cert);
    void setLocalCertificateStore(CertificateStoreQuery&& query_method);

    /**
     * @param port: Local port to bind. Both IPv4 and IPv6 will be tried (ANY).
     * @param identity: RSA key pair to use for cryptographic operations.
     * @param threaded: If false, ::loop() must be called periodically. Otherwise a thread is launched.
     * @param cb: Optional callback to receive general state information.
     */
    void run(in_port_t port = 4222, const crypto::Identity identity = {}, bool threaded = false, NetId network = 0) {
        run(port, {
            /*.dht_config = */{
                /*.node_config = */{
                    /*.node_id = */{},
                    /*.network = */network,
                    /*.is_bootstrap = */false,
                    /*.maintain_storage*/false
                },
                /*.id = */identity
            },
            /*.threaded = */threaded,
            /*.proxy_server = */"",
            /*.push_node_id = */""
        });
    }
    void run(in_port_t port, Config config);

    /**
     * @param local4: Local IPv4 address and port to bind. Can be null.
     * @param local6: Local IPv6 address and port to bind. Can be null.
     *         You should allways bind to a global IPv6 address.
     * @param identity: RSA key pair to use for cryptographic operations.
     * @param threaded: If false, loop() must be called periodically. Otherwise a thread is launched.
     * @param cb: Optional callback to receive general state information.
     */
    void run(const SockAddr& local4, const SockAddr& local6, Config config);

    /**
     * Same as @run(sockaddr_in, sockaddr_in6, Identity, bool, StatusCallback), but with string IP addresses and service (port).
     */
    void run(const char* ip4, const char* ip6, const char* service, Config config);

    void setOnStatusChanged(StatusCallback&& cb) {
        statusCb = std::move(cb);
    }

    /**
     * In non-threaded mode, the user should call this method
     * regularly and everytime a new packet is received.
     * @return the next op
     */
    time_point loop() {
        std::lock_guard<std::mutex> lck(dht_mtx);
        time_point wakeup = time_point::min();
        try {
            wakeup = loop_();
        } catch (const dht::SocketException& e) {
            startNetwork(bound4, bound6);
        }
        return wakeup;
    }

    /**
     * Gracefuly disconnect from network.
     */
    void shutdown(ShutdownCallback cb);

    /**
     * Quit and wait for all threads to terminate.
     * No callbacks will be called after this method returns.
     * All internal state will be lost. The DHT can then be run again with @run().
     */
    void join();

    void setProxyServer(const std::string& proxy, const std::string& pushNodeId = "") {
#if OPENDHT_PROXY_CLIENT
        if (config_.proxy_server == proxy and config_.push_node_id == pushNodeId)
            return;
        config_.proxy_server = proxy;
        config_.push_node_id = pushNodeId;
        enableProxy(use_proxy and not config_.proxy_server.empty());
#endif
    }

    /**
     * Start or stop the proxy
     * @param proxify if we want to use the proxy
     * @param deviceKey non empty to enable push notifications
     */
    void enableProxy(bool proxify);

    /* Push notification methods */

    /**
     * Updates the push notification device token
     */
    void setPushNotificationToken(const std::string& token);

    /**
     * Insert a push notification to process for OpenDHT
     */
    void pushNotificationReceived(const std::map<std::string, std::string>& data) const;
    /**
     * Refresh a listen via a token
     * @param token
     */
    void resubscribe(unsigned token);

    /* Proxy server mothods */
    void forwardAllMessages(bool forward);

private:
    static constexpr std::chrono::seconds BOOTSTRAP_PERIOD {10};

    /**
     * Will try to resolve the list of hostnames `bootstrap_nodes` on seperate
     * thread and then queue ping requests. This list should contain reliable
     * nodes so that the DHT node can recover quickly from losing connection
     * with the network.
     */
    void tryBootstrapContinuously();

    void startNetwork(const SockAddr sin4, const SockAddr sin6);
    time_point loop_();

    NodeStatus getStatus() const {
        return std::max(status4, status6);
    }

    /** Local DHT instance */
    std::unique_ptr<SecureDht> dht_;

    /** Proxy client instance */
    std::unique_ptr<SecureDht> dht_via_proxy_;

    /** true if we are currently using a proxy */
    std::atomic_bool use_proxy {false};

    /** Current configuration */
    Config config_;

    /**
     * reset dht clients
     */
    void resetDht();
    /**
     * @return the current active DHT
     */
    SecureDht* activeDht() const;

    /**
     * Store current listeners and translates global tokens for each client.
     */
    struct Listener {
        size_t tokenClassicDht;
        size_t tokenProxyDht;
        GetCallback gcb;
        InfoHash hash;
        Value::Filter f;
        Where w;
    };
    std::map<size_t, Listener> listeners_ {};
    size_t listener_token_ {1};

    mutable std::mutex dht_mtx {};
    std::thread dht_thread {};
    std::condition_variable cv {};

    std::thread rcv_thread {};
    std::mutex sock_mtx {};
    std::vector<std::pair<Blob, SockAddr>> rcv {};

    /** true if currently actively boostraping */
    std::atomic_bool bootstraping {false};
    /* bootstrap nodes given as (host, service) pairs */
    std::vector<std::pair<std::string,std::string>> bootstrap_nodes_all {};
    std::vector<std::pair<std::string,std::string>> bootstrap_nodes {};
    std::thread bootstrap_thread {};
    /** protects bootstrap_nodes, bootstrap_thread */
    std::mutex bootstrap_mtx {};
    std::condition_variable bootstrap_cv {};

    std::queue<std::function<void(SecureDht&)>> pending_ops_prio {};
    std::queue<std::function<void(SecureDht&)>> pending_ops {};
    std::mutex storage_mtx {};

    std::atomic_bool running {false};
    std::atomic_bool running_network {false};

    NodeStatus status4 {NodeStatus::Disconnected},
               status6 {NodeStatus::Disconnected};
    StatusCallback statusCb {nullptr};

    int s4 {-1}, s6 {-1};
    SockAddr bound4 {};
    SockAddr bound6 {};

    /** Push notification token */
    std::string pushToken_;
};

}
