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

//#include "securedht.h"
#include "infohash.h"
#include "value.h"
#include "callbacks.h"

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
class DhtRunner {

public:
    typedef std::function<void(NodeStatus, NodeStatus)> StatusCallback;

    DhtRunner();
    virtual ~DhtRunner();

    void get(InfoHash id, GetCallbackSimple cb, DoneCallback donecb={}, Value::Filter f = Value::AllFilter()) {
        get(id, bindGetCb(cb), donecb, f);
    }

    void get(InfoHash id, GetCallbackSimple cb, DoneCallbackSimple donecb={}, Value::Filter f = Value::AllFilter()) {
        get(id, bindGetCb(cb), donecb, f);
    }

    void get(InfoHash hash, GetCallback vcb, DoneCallback dcb, Value::Filter f={});

    void get(InfoHash id, GetCallback cb, DoneCallbackSimple donecb={}, Value::Filter f = Value::AllFilter()) {
        get(id, cb, bindDoneCb(donecb), f);
    }
    void get(const std::string& key, GetCallback vcb, DoneCallbackSimple dcb={}, Value::Filter f = Value::AllFilter());

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

    std::future<std::vector<std::shared_ptr<dht::Value>>> get(InfoHash key, Value::Filter f = Value::AllFilter()) {
        auto p = std::make_shared<std::promise<std::vector<std::shared_ptr< dht::Value >>>>();
        auto values = std::make_shared<std::vector<std::shared_ptr< dht::Value >>>();
        get(key, [=](const std::vector<std::shared_ptr<dht::Value>>& vlist) {
            values->insert(values->end(), vlist.begin(), vlist.end());
            return true;
        }, [=](bool) {
            p->set_value(std::move(*values));
        },
        f);
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

    std::future<size_t> listen(InfoHash key, GetCallback vcb, Value::Filter f = Value::AllFilter());
    std::future<size_t> listen(const std::string& key, GetCallback vcb, Value::Filter f = Value::AllFilter());
    std::future<size_t> listen(InfoHash key, GetCallbackSimple cb, Value::Filter f = Value::AllFilter()) {
        return listen(key, bindGetCb(cb), f);
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
    std::future<size_t> listen(InfoHash hash, std::function<bool(T&&)> cb, Value::Filter f = Value::AllFilter())
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
        getFilterSet<T>(f));
    }

    void cancelListen(InfoHash h, size_t token);
    void cancelListen(InfoHash h, std::shared_future<size_t> token);

    void put(InfoHash hash, std::shared_ptr<Value> value, DoneCallback cb={}, bool permanent = false);
    void put(InfoHash hash, std::shared_ptr<Value> value, DoneCallbackSimple cb, bool permanent = false) {
        put(hash, value, bindDoneCb(cb), permanent);
    }

    void put(InfoHash hash, Value&& value, DoneCallback cb={}, bool permanent = false);
    void put(InfoHash hash, Value&& value, DoneCallbackSimple cb, bool permanent = false) {
        put(hash, std::forward<Value>(value), bindDoneCb(cb), permanent);
    }
    void put(const std::string& key, Value&& value, DoneCallbackSimple cb={}, bool permanent = false);

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

    void bootstrap(const char* host, const char* service);
    void bootstrap(const std::vector<std::pair<sockaddr_storage, socklen_t>>& nodes);
    void bootstrap(const std::vector<NodeExport>& nodes);

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
    const Address& getBound(sa_family_t f = AF_INET) const {
        return (f == AF_INET) ? bound4 : bound6;
    }

    /**
     * Returns the currently bound port, in host byte order.
     * @param f: address family of the bound port to retreive.
     */
    in_port_t getBoundPort(sa_family_t f = AF_INET) const {
        return ntohs(((sockaddr_in*)&getBound(f).first)->sin_port);
    }

    std::pair<size_t, size_t> getStoreSize() const;

    void setStorageLimit(size_t limit = DEFAULT_STORAGE_LIMIT);

    std::vector<NodeExport> exportNodes() const;

    std::vector<ValuesExport> exportValues() const;

    void setLoggers(LogMethod err = NOLOG, LogMethod warn = NOLOG, LogMethod debug = NOLOG);

    void registerType(const ValueType& type);

    void importValues(const std::vector<ValuesExport>& values);

    bool isRunning() const {
        return running;
    }

    int getNodesStats(sa_family_t af, unsigned *good_return, unsigned *dubious_return, unsigned *cached_return, unsigned *incoming_return) const;

    std::vector<unsigned> getNodeMessageStats(bool in = false) const;
    std::string getStorageLog() const;
    std::string getRoutingTablesLog(sa_family_t af) const;
    std::string getSearchesLog(sa_family_t af = 0) const;
    std::vector<Address> getPublicAddress(sa_family_t af = 0);
    std::vector<std::string> getPublicAddressStr(sa_family_t af = 0);

    // securedht methods

    void findCertificate(InfoHash hash, std::function<void(const std::shared_ptr<crypto::Certificate>)>);
    void registerCertificate(std::shared_ptr<crypto::Certificate> cert);
    void setLocalCertificateStore(CertificateStoreQuery&& query_method);

    struct Config {
        SecureDhtConfig dht_config;
        bool threaded;
    };

    /**
     * @param port: Local port to bind. Both IPv4 and IPv6 will be tried (ANY).
     * @param identity: RSA key pair to use for cryptographic operations.
     * @param threaded: If false, ::loop() must be called periodically. Otherwise a thread is launched.
     * @param cb: Optional callback to receive general state information.
     */
    void run(in_port_t port, const crypto::Identity identity, bool threaded = false, NetId network = 0) {
        run(port, {
            /*.dht_config = */{
                /*.node_config = */{
                    /*.node_id = */{},
                    /*.network = */network,
                    /*.is_bootstrap = */false
                },
                /*.id = */identity
            },
            /*.threaded = */threaded
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
    void run(const sockaddr_in* local4, const sockaddr_in6* local6, Config config);

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
        return loop_();
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

private:

    void doRun(const sockaddr_in* sin4, const sockaddr_in6* sin6, SecureDhtConfig config);
    time_point loop_();

    static std::vector<std::pair<sockaddr_storage, socklen_t>> getAddrInfo(const char* host, const char* service);

    NodeStatus getStatus() const {
        return std::max(status4, status6);
    }

    std::unique_ptr<SecureDht> dht_;
    mutable std::mutex dht_mtx {};
    std::thread dht_thread {};
    std::condition_variable cv {};

    std::thread rcv_thread {};
    std::mutex sock_mtx {};
    std::vector<std::pair<Blob, std::pair<sockaddr_storage, socklen_t>>> rcv {};

    std::queue<std::function<void(SecureDht&)>> pending_ops_prio {};
    std::queue<std::function<void(SecureDht&)>> pending_ops {};
    std::mutex storage_mtx {};

    std::atomic<bool> running {false};

    NodeStatus status4 {NodeStatus::Disconnected},
               status6 {NodeStatus::Disconnected};
    StatusCallback statusCb {nullptr};

    Address bound4 {};
    Address bound6 {};
};

}
