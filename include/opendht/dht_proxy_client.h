/*
 *  Copyright (C) 2016-2018 Savoir-faire Linux Inc.
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
 *          Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#if OPENDHT_PROXY_CLIENT

#pragma once

#include <functional>
#include <thread>
#include <mutex>

#include "callbacks.h"
#include "def.h"
#include "dht_interface.h"
#include "scheduler.h"
#include "proxy.h"

namespace restbed {
    class Request;
}

namespace Json {
    class Value;
}

namespace dht {

class SearchCache;

class OPENDHT_PUBLIC DhtProxyClient final : public DhtInterface {
public:

    DhtProxyClient();

    explicit DhtProxyClient(std::function<void()> loopSignal, const std::string& serverHost, const std::string& pushClientId = "");

    virtual void setPushNotificationToken(const std::string& token) {
#if OPENDHT_PUSH_NOTIFICATIONS
        deviceKey_ = token;
#endif
    }

    virtual ~DhtProxyClient();

    /**
     * Get the ID of the node.
     */
    inline const InfoHash& getNodeId() const { return myid; }

    /**
     * Get the current status of the node for the given family.
     */
    NodeStatus getStatus(sa_family_t af) const;
    NodeStatus getStatus() const {
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
     * Get a value by asking the proxy and call the provided get callback when
     * values are found at key.
     * The operation will start as soon as the node is connected to the network.
     * @param cb a function called when new values are found on the network.
     *           It should return false to stop the operation.
     * @param donecb a function called when the operation is complete.
                     cb and donecb won't be called again afterward.
     * @param f a filter function used to prefilter values.
     */
    virtual void get(const InfoHash& key, GetCallback cb, DoneCallback donecb={}, Value::Filter&& f={}, Where&& w = {});
    virtual void get(const InfoHash& key, GetCallback cb, DoneCallbackSimple donecb={}, Value::Filter&& f={}, Where&& w = {}) {
        get(key, cb, bindDoneCb(donecb), std::forward<Value::Filter>(f), std::forward<Where>(w));
    }
    virtual void get(const InfoHash& key, GetCallbackSimple cb, DoneCallback donecb={}, Value::Filter&& f={}, Where&& w = {}) {
        get(key, bindGetCb(cb), donecb, std::forward<Value::Filter>(f), std::forward<Where>(w));
    }
    virtual void get(const InfoHash& key, GetCallbackSimple cb, DoneCallbackSimple donecb, Value::Filter&& f={}, Where&& w = {}) {
        get(key, bindGetCb(cb), bindDoneCb(donecb), std::forward<Value::Filter>(f), std::forward<Where>(w));
    }

    /**
     * Announce a value on all available protocols (IPv4, IPv6).
     *
     * The operation will start as soon as the node is connected to the network.
     * The done callback will be called once, when the first announce succeeds, or fails.
     * NOTE: For now, created parameter is ignored.
     */
    void put(const InfoHash& key,
            Sp<Value>,
            DoneCallback cb=nullptr,
            time_point created=time_point::max(),
            bool permanent = false);
    void put(const InfoHash& key,
            const Sp<Value>& v,
            DoneCallbackSimple cb,
            time_point created=time_point::max(),
            bool permanent = false)
    {
        put(key, v, bindDoneCb(cb), created, permanent);
    }

    void put(const InfoHash& key,
            Value&& v,
            DoneCallback cb=nullptr,
            time_point created=time_point::max(),
            bool permanent = false)
    {
        put(key, std::make_shared<Value>(std::move(v)), cb, created, permanent);
    }
    void put(const InfoHash& key,
            Value&& v,
            DoneCallbackSimple cb,
            time_point created=time_point::max(),
            bool permanent = false)
    {
        put(key, std::forward<Value>(v), bindDoneCb(cb), created, permanent);
    }

    /**
     * @param  af the socket family
     * @return node stats from the proxy
     */
    NodeStats getNodesStats(sa_family_t af) const;

    /**
     * @param  family the socket family
     * @return public address
     */
    std::vector<SockAddr> getPublicAddress(sa_family_t family = 0);

    /**
     * Listen on the network for any changes involving a specified hash.
     * The node will register to receive updates from relevent nodes when
     * new values are added or removed.
     *
     * @return a token to cancel the listener later.
     */
    virtual size_t listen(const InfoHash&, ValueCallback, Value::Filter={}, Where={});

    virtual size_t listen(const InfoHash& key, GetCallback cb, Value::Filter f={}, Where w={}) {
        return listen(key, [cb](const std::vector<Sp<Value>>& vals, bool expired){
            if (not expired)
                return cb(vals);
            return true;
        }, std::forward<Value::Filter>(f), std::forward<Where>(w));
    }
    virtual size_t listen(const InfoHash& key, GetCallbackSimple cb, Value::Filter f={}, Where w={}) {
        return listen(key, bindGetCb(cb), std::forward<Value::Filter>(f), std::forward<Where>(w));
    }
    virtual bool cancelListen(const InfoHash& key, size_t token);

    /**
     * Call linked callback with a push notification
     * @param notification to process
     */
    void pushNotificationReceived(const std::map<std::string, std::string>& notification);

    time_point periodic(const uint8_t*, size_t, const SockAddr&);
    time_point periodic(const uint8_t *buf, size_t buflen, const sockaddr* from, socklen_t fromlen) {
        return periodic(buf, buflen, SockAddr(from, fromlen));
    }


    /**
     * Similar to Dht::get, but sends a Query to filter data remotely.
     * @param key the key for which to query data for.
     * @param cb a function called when new values are found on the network.
     *           It should return false to stop the operation.
     * @param done_cb a function called when the operation is complete.
               cb and done_cb won't be called again afterward.
     * @param q a query used to filter values on the remotes before they send a
     *          response.
     */
    virtual void query(const InfoHash& /*key*/, QueryCallback /*cb*/, DoneCallback /*done_cb*/ = {}, Query&& /*q*/ = {}) { }
    virtual void query(const InfoHash& key, QueryCallback cb, DoneCallbackSimple done_cb = {}, Query&& q = {}) {
        query(key, cb, bindDoneCb(done_cb), std::forward<Query>(q));
    }

    /**
     * Get data currently being put at the given hash.
     */
    std::vector<Sp<Value>> getPut(const InfoHash&);

    /**
     * Get data currently being put at the given hash with the given id.
     */
    Sp<Value> getPut(const InfoHash&, const Value::Id&);

    /**
     * Stop any put/announce operation at the given location,
     * for the value with the given id.
     */
    bool cancelPut(const InfoHash&, const Value::Id&);

    void pingNode(const sockaddr*, socklen_t, DoneCallbackSimple&& /*cb*/={}) { }

    virtual void registerType(const ValueType& type) {
        types.registerType(type);
    }
    const ValueType& getType(ValueType::Id type_id) const {
        return types.getType(type_id);
    }

    std::vector<Sp<Value>> getLocal(const InfoHash& k, Value::Filter filter) const;
    Sp<Value> getLocalById(const InfoHash& k, Value::Id id) const;

    /**
     * NOTE: The following methods will not be implemented because the
     * DhtProxyClient doesn't have any storage nor synchronization process
     */
    void insertNode(const InfoHash&, const SockAddr&) { }
    void insertNode(const InfoHash&, const sockaddr*, socklen_t) { }
    void insertNode(const NodeExport&) { }
    std::pair<size_t, size_t> getStoreSize() const { return {}; }
    std::vector<NodeExport> exportNodes() { return {}; }
    std::vector<ValuesExport> exportValues() const { return {}; }
    void importValues(const std::vector<ValuesExport>&) {}
    std::string getStorageLog() const { return {}; }
    std::string getStorageLog(const InfoHash&) const { return {}; }
    std::string getRoutingTablesLog(sa_family_t) const { return {}; }
    std::string getSearchesLog(sa_family_t) const { return {}; }
    std::string getSearchLog(const InfoHash&, sa_family_t) const { return {}; }
    void dumpTables() const {}
    std::vector<unsigned> getNodeMessageStats(bool) { return {}; }
    void setStorageLimit(size_t) {}
    void connectivityChanged(sa_family_t) {
        restartListeners();
    }
    void connectivityChanged() {
        getProxyInfos();
        restartListeners();
        loopSignal_();
    }

private:
    /**
     * Start the connection with a server.
     */
    void startProxy();

    /**
     * Get informations from the proxy node
     * @return the JSON returned by the proxy
     */
    struct InfoState;
    void getProxyInfos();
    void onProxyInfos(const Json::Value& val, sa_family_t family);
    SockAddr parsePublicAddress(const Json::Value& val);

    void opFailed();

    size_t doListen(const InfoHash& key, ValueCallback, Value::Filter);
    bool doCancelListen(const InfoHash& key, size_t token);

    struct ListenState;
    void sendListen(const std::shared_ptr<restbed::Request>& request, const ValueCallback&, const Value::Filter& filter, const Sp<ListenState>& state);
    void sendSubscribe(const std::shared_ptr<restbed::Request>& request, const ValueCallback&, const Value::Filter& filter, const Sp<ListenState>& state);

    void doPut(const InfoHash&, Sp<Value>, DoneCallback, time_point created, bool permanent);

    /**
     * Initialize statusIpvX_
     */
    void getConnectivityStatus();
    /**
     * cancel all Listeners
     */
    void cancelAllListeners();
    /**
     * cancel all Operations
     */
    void cancelAllOperations();

    std::string serverHost_;
    std::string pushClientId_;

    mutable std::mutex lockCurrentProxyInfos_;
    NodeStatus statusIpv4_ {NodeStatus::Disconnected};
    NodeStatus statusIpv6_ {NodeStatus::Disconnected};
    NodeStats stats4_ {};
    NodeStats stats6_ {};
    SockAddr publicAddressV4_;
    SockAddr publicAddressV6_;

    InfoHash myid {};

    // registred types
    TypeStore types;

    /**
     * Store listen requests.
     */
    struct Listener;
    struct ProxySearch;

    size_t listenerToken_ {0};
    std::map<InfoHash, ProxySearch> searches_;
    mutable std::mutex searchLock_;

    /**
     * Store current put and get requests.
     */
    struct Operation
    {
        std::shared_ptr<restbed::Request> req;
        std::thread thread;
        std::shared_ptr<std::atomic_bool> finished;
    };
    std::vector<Operation> operations_;
    std::mutex lockOperations_;
    /**
     * Callbacks should be executed in the main thread.
     */
    std::vector<std::function<void()>> callbacks_;
    std::mutex lockCallbacks;

    Sp<InfoState> infoState_;
    std::thread statusThread_;
    mutable std::mutex statusLock_;

    Scheduler scheduler;
    /**
     * Retrieve if we can connect to the proxy (update statusIpvX_)
     */
    void confirmProxy();
    Sp<Scheduler::Job> nextProxyConfirmation {};
    Sp<Scheduler::Job> listenerRestart {};

    /**
     * Relaunch LISTEN requests if the client disconnect/reconnect.
     */
    void restartListeners();

    /**
     * Refresh a listen via a token
     * @param token
     */
    void resubscribe(const InfoHash& key, Listener& listener);

    /**
     * If we want to use push notifications by default.
     * NOTE: empty by default to avoid to use services like FCM or APN.
     */
    std::string deviceKey_ {};

    const std::function<void()> loopSignal_;

#if OPENDHT_PUSH_NOTIFICATIONS
    void fillBody(std::shared_ptr<restbed::Request> request);
    void getPushRequest(Json::Value&) const;
#endif // OPENDHT_PUSH_NOTIFICATIONS

    std::atomic_bool isDestroying_ {false};
};

}

#endif // OPENDHT_PROXY_CLIENT
