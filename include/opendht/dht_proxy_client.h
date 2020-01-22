/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
 *          Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *          Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
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

#include <functional>
#include <mutex>

#include "callbacks.h"
#include "def.h"
#include "dht_interface.h"
#include "proxy.h"
#include "http.h"

#include <restinio/all.hpp>
#include <json/json.h>

#include <chrono>
#include <vector>
#include <functional>

namespace Json {
class Value;
}

namespace http {
class Resolver;
class Request;
}

namespace dht {

class OPENDHT_PUBLIC DhtProxyClient final : public DhtInterface {
public:

    DhtProxyClient();

    explicit DhtProxyClient(
        std::shared_ptr<crypto::Certificate> serverCA, crypto::Identity clientIdentity,
        std::function<void()> loopSignal, const std::string& serverHost,
        const std::string& pushClientId = "", std::shared_ptr<Logger> logger = {});

    void setHeaderFields(http::Request& request);

    virtual void setPushNotificationToken(const std::string& token) override {
#ifdef OPENDHT_PUSH_NOTIFICATIONS
        deviceKey_ = token;
#else
        (void) token;
#endif
    }

    virtual ~DhtProxyClient();

    /**
     * Get the ID of the node.
     */
    inline const InfoHash& getNodeId() const override { return myid; }

    /**
     * Get the current status of the node for the given family.
     */
    NodeStatus getStatus(sa_family_t af) const override;
    NodeStatus getStatus() const override {
        return std::max(getStatus(AF_INET), getStatus(AF_INET6));
    }

    /**
     * Performs final operations before quitting.
     */
    void shutdown(ShutdownCallback cb) override;

    /**
     * Returns true if the node is running (have access to an open socket).
     *
     *  af: address family. If non-zero, will return true if the node
     *      is running for the provided family.
     */
    bool isRunning(sa_family_t af = 0) const override;

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
    virtual void get(const InfoHash& key, GetCallback cb, DoneCallback donecb={}, Value::Filter&& f={}, Where&& w = {}) override;
    virtual void get(const InfoHash& key, GetCallback cb, DoneCallbackSimple donecb={}, Value::Filter&& f={}, Where&& w = {}) override {
        get(key, cb, bindDoneCb(donecb), std::forward<Value::Filter>(f), std::forward<Where>(w));
    }
    virtual void get(const InfoHash& key, GetCallbackSimple cb, DoneCallback donecb={}, Value::Filter&& f={}, Where&& w = {}) override {
        get(key, bindGetCb(cb), donecb, std::forward<Value::Filter>(f), std::forward<Where>(w));
    }
    virtual void get(const InfoHash& key, GetCallbackSimple cb, DoneCallbackSimple donecb, Value::Filter&& f={}, Where&& w = {}) override {
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
            bool permanent = false) override;
    void put(const InfoHash& key,
            const Sp<Value>& v,
            DoneCallbackSimple cb,
            time_point created=time_point::max(),
            bool permanent = false) override
    {
        put(key, v, bindDoneCb(cb), created, permanent);
    }

    void put(const InfoHash& key,
            Value&& v,
            DoneCallback cb=nullptr,
            time_point created=time_point::max(),
            bool permanent = false) override
    {
        put(key, std::make_shared<Value>(std::move(v)), cb, created, permanent);
    }
    void put(const InfoHash& key,
            Value&& v,
            DoneCallbackSimple cb,
            time_point created=time_point::max(),
            bool permanent = false) override
    {
        put(key, std::forward<Value>(v), bindDoneCb(cb), created, permanent);
    }

    /**
     * @param  af the socket family
     * @return node stats from the proxy
     */
    NodeStats getNodesStats(sa_family_t af) const override;

    /**
     * @param  family the socket family
     * @return public address
     */
    std::vector<SockAddr> getPublicAddress(sa_family_t family = 0) override;

    /**
     * Listen on the network for any changes involving a specified hash.
     * The node will register to receive updates from relevent nodes when
     * new values are added or removed.
     *
     * @return a token to cancel the listener later.
     */
    virtual size_t listen(const InfoHash&, ValueCallback, Value::Filter={}, Where={}) override;

    virtual size_t listen(const InfoHash& key, GetCallback cb, Value::Filter f={}, Where w={}) override {
        return listen(key, [cb](const std::vector<Sp<Value>>& vals, bool expired){
            if (not expired)
                return cb(vals);
            return true;
        }, std::forward<Value::Filter>(f), std::forward<Where>(w));
    }
    virtual size_t listen(const InfoHash& key, GetCallbackSimple cb, Value::Filter f={}, Where w={}) override {
        return listen(key, bindGetCb(cb), std::forward<Value::Filter>(f), std::forward<Where>(w));
    }
    /*
     * This function relies on the cache implementation.
     * It means that there are no true cancel here, it keeps the caching in higher priority.
     */
    virtual bool cancelListen(const InfoHash& key, size_t token) override;

    /**
     * Call linked callback with a push notification
     * @param notification to process
     */
    void pushNotificationReceived(const std::map<std::string, std::string>& notification) override;

    time_point periodic(const uint8_t*, size_t, SockAddr, const time_point& now) override;
    time_point periodic(const uint8_t* buf, size_t buflen, const sockaddr* from, socklen_t fromlen, const time_point& now) override {
        return periodic(buf, buflen, SockAddr(from, fromlen), now);
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
    virtual void query(const InfoHash& /*key*/, QueryCallback /*cb*/, DoneCallback /*done_cb*/ = {}, Query&& /*q*/ = {}) override { }
    virtual void query(const InfoHash& key, QueryCallback cb, DoneCallbackSimple done_cb = {}, Query&& q = {}) override {
        query(key, cb, bindDoneCb(done_cb), std::forward<Query>(q));
    }

    /**
     * Get data currently being put at the given hash.
     */
    std::vector<Sp<Value>> getPut(const InfoHash&) const override;

    /**
     * Get data currently being put at the given hash with the given id.
     */
    Sp<Value> getPut(const InfoHash&, const Value::Id&) const override;

    /**
     * Stop any put/announce operation at the given location,
     * for the value with the given id.
     */
    bool cancelPut(const InfoHash&, const Value::Id&) override;

    void pingNode(SockAddr, DoneCallbackSimple&& /*cb*/={}) override { }

    virtual void registerType(const ValueType& type) override {
        types.registerType(type);
    }
    const ValueType& getType(ValueType::Id type_id) const override {
        return types.getType(type_id);
    }

    std::vector<Sp<Value>> getLocal(const InfoHash& k, const Value::Filter& filter) const override;
    Sp<Value> getLocalById(const InfoHash& k, Value::Id id) const override;

    /**
     * NOTE: The following methods will not be implemented because the
     * DhtProxyClient doesn't have any storage nor synchronization process
     */
    void insertNode(const InfoHash&, const SockAddr&) override { }
    void insertNode(const NodeExport&) override { }
    std::pair<size_t, size_t> getStoreSize() const override { return {}; }
    std::vector<NodeExport> exportNodes() const override { return {}; }
    std::vector<ValuesExport> exportValues() const override { return {}; }
    void importValues(const std::vector<ValuesExport>&) override {}
    std::string getStorageLog() const override { return {}; }
    std::string getStorageLog(const InfoHash&) const override { return {}; }
    std::string getRoutingTablesLog(sa_family_t) const override { return {}; }
    std::string getSearchesLog(sa_family_t) const override { return {}; }
    std::string getSearchLog(const InfoHash&, sa_family_t) const override { return {}; }
    void dumpTables() const override {}
    std::vector<unsigned> getNodeMessageStats(bool) override { return {}; }
    void setStorageLimit(size_t) override {}
    void connectivityChanged(sa_family_t) override {
        restartListeners();
    }
    void connectivityChanged() override {
        getProxyInfos();
        restartListeners();
        loopSignal_();
    }

private:
    /**
     * Start the connection with a server.
     */
    void startProxy();
    void stop();

    /**
     * Get informations from the proxy node
     * @return the JSON returned by the proxy
     */
    struct InfoState;
    void getProxyInfos();
    void queryProxyInfo(const std::shared_ptr<InfoState>& infoState, const std::shared_ptr<http::Resolver>& resolver, sa_family_t family);
    void onProxyInfos(const Json::Value& val, const sa_family_t family);
    SockAddr parsePublicAddress(const Json::Value& val);

    void opFailed();

    void handleExpireListener(const asio::error_code &ec, const InfoHash& key);

    struct Listener;
    struct OperationState;
    enum class ListenMethod {
        LISTEN,
        SUBSCRIBE,
        RESUBSCRIBE,
    };
    using CacheValueCallback = std::function<bool(const std::vector<std::shared_ptr<Value>>& values, bool expired, system_clock::time_point)>;

    /**
     * Send Listen with httpClient_
     */
    void sendListen(const restinio::http_request_header_t& header, const CacheValueCallback& cb,
                    const Sp<OperationState>& opstate, Listener& listener, ListenMethod method = ListenMethod::LISTEN);
    void handleResubscribe(const asio::error_code& ec, const InfoHash& key,
                           const size_t token, std::shared_ptr<OperationState> opstate);

    void doPut(const InfoHash&, Sp<Value>, DoneCallbackSimple, time_point created, bool permanent);
    void handleRefreshPut(const asio::error_code& ec, InfoHash key, Value::Id id);

    /**
     * Initialize statusIpvX_
     */
    void getConnectivityStatus();
    /**
     * cancel all Listeners
     */
    void cancelAllListeners();

    std::atomic_bool isDestroying_ {false};

    std::string proxyUrl_;
    dht::crypto::Identity clientIdentity_;
    std::shared_ptr<dht::crypto::Certificate> serverCertificate_;
    //std::pair<std::string, std::string> serverHostService_;
    std::string pushClientId_;
    std::string pushSessionId_;

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

    /*
     * ASIO I/O Context for sockets in httpClient_
     * Note: Each context is used in one thread only
     */
    asio::io_context httpContext_;
    std::shared_ptr<http::Resolver> resolver_;

    mutable std::mutex requestLock_;
    std::map<unsigned, std::shared_ptr<http::Request>> requests_;
    /*
     * Thread for executing the http io_context.run() blocking call
     */
    std::thread httpClientThread_;

    /**
     * Store listen requests.
     */
    struct ProxySearch;

    mutable std::mutex searchLock_;
    size_t listenerToken_ {0};
    std::map<InfoHash, ProxySearch> searches_;

    /**
     * Callbacks should be executed in the main thread.
     */
    std::mutex lockCallbacks_;
    std::vector<std::function<void()>> callbacks_;

    Sp<InfoState> infoState_;

    /**
     * Retrieve if we can connect to the proxy (update statusIpvX_)
     */
    void handleProxyConfirm(const asio::error_code &ec);
    Sp<asio::steady_timer> nextProxyConfirmationTimer_;
    Sp<asio::steady_timer> listenerRestartTimer_;

    /**
     * Relaunch LISTEN requests if the client disconnect/reconnect.
     */
    void restartListeners();

    /**
     * Refresh a listen via a token
     * @param token
     */
    void resubscribe(const InfoHash& key, const size_t token, Listener& listener);

    /**
     * If we want to use push notifications by default.
     * NOTE: empty by default to avoid to use services like FCM or APN.
     */
    std::string deviceKey_ {};

    const std::function<void()> loopSignal_;

#ifdef OPENDHT_PUSH_NOTIFICATIONS
    std::string fillBody(bool resubscribe);
    void getPushRequest(Json::Value&) const;
#endif // OPENDHT_PUSH_NOTIFICATIONS

    Json::StreamWriterBuilder jsonBuilder_;
    std::unique_ptr<Json::CharReader> jsonReader_;

    std::shared_ptr<http::Request> buildRequest(const std::string& target = {});
};

}
