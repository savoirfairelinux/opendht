/*
 *  Copyright (C) 2016 Savoir-faire Linux Inc.
 *  Author : Sébastien Blin <sebastien.blin@savoirfairelinux.com>
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

#if OPENDHT_PROXY_SERVER

#pragma once

#include <thread>

#include "callbacks.h"
#include "def.h"
#include "dht_interface.h"
#include "scheduler.h"

namespace restbed
{
    class Request;
}

namespace dht {

class OPENDHT_PUBLIC DhtProxyClient : public DhtInterface {
public:

    DhtProxyClient() : scheduler(DHT_LOG) {}

    /**
     * Initialise the DhtProxyClient with two open sockets (for IPv4 and IP6)
     * and an ID for the node.
     */
    explicit DhtProxyClient(const std::string& serverHost);
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
    virtual size_t listen(const InfoHash&, GetCallback, Value::Filter&&={}, Where&&={});
    virtual size_t listen(const InfoHash& key, GetCallbackSimple cb, Value::Filter f={}, Where w = {}) {
        return listen(key, bindGetCb(cb), std::forward<Value::Filter>(f), std::forward<Where>(w));
    }


    /**
     * TODO
     * NOTE: For now, there is no endpoint in the DhtProxyServer to do the following methods.
     * It will come in another version. (with push_notifications support)
     */
    virtual bool cancelListen(const InfoHash&, size_t token);

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
    std::vector<Sp<Value>> getPut(const InfoHash&) { return {}; }

    /**
     * Get data currently being put at the given hash with the given id.
     */
    Sp<Value> getPut(const InfoHash&, const Value::Id&) { return {}; }

    /**
     * Stop any put/announce operation at the given location,
     * for the value with the given id.
     */
    bool cancelPut(const InfoHash&, const Value::Id&) { return false; }

    void pingNode(const sockaddr*, socklen_t, DoneCallbackSimple&& /*cb*/={}) { }

    /**
     * NOTE: The following methods will not be implemented because the
     * DhtProxyClient doesn't have any storage nor synchronization process
     */

    /**
     * Insert a node in the main routing table.
     * The node is not pinged, so this should be
     * used to bootstrap efficiently from previously known nodes.
     */
    void insertNode(const InfoHash&, const SockAddr&) { }
    void insertNode(const InfoHash&, const sockaddr*, socklen_t) { }
    void insertNode(const NodeExport&) { }

    /**
     * Returns the total memory usage of stored values and the number
     * of stored values.
     */
    std::pair<size_t, size_t> getStoreSize() const { return {}; }

    virtual void registerType(const ValueType&) { }
    const ValueType& getType(ValueType::Id) const { }

    /**
     * Get locally stored data for the given hash.
     */
    std::vector<Sp<Value>> getLocal(const InfoHash&, Value::Filter) const { return {}; }

    /**
     * Get locally stored data for the given key and value id.
     */
    Sp<Value> getLocalById(const InfoHash&, Value::Id) const { return {}; }

    /**
     * Get the list of good nodes for local storage saving purposes
     * The list is ordered to minimize the back-to-work delay.
     */
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

    /**
     * Set the in-memory storage limit in bytes
     */
    void setStorageLimit(size_t) {}

    /**
     * Inform the DHT of lower-layer connectivity changes.
     * This will cause the DHT to assume a public IP address change.
     * The DHT will recontact neighbor nodes, re-register for listen ops etc.
     */
    void connectivityChanged(sa_family_t) {}
    void connectivityChanged() {
        connectivityChanged(AF_INET);
        connectivityChanged(AF_INET6);
    }

    time_point periodic(const uint8_t*, size_t, const SockAddr&) {
        // The DhtProxyClient doesn't use NetworkEngine, so here, we have nothing to do for now.
        scheduler.syncTime();
        return scheduler.run();
    }
    time_point periodic(const uint8_t *buf, size_t buflen, const sockaddr* from, socklen_t fromlen) {
        return periodic(buf, buflen, SockAddr(from, fromlen));
    }

private:
    /**
     * Get informations from the proxy node
     * @return the JSON returned by the proxy
     */
    Json::Value getProxyInfos() const;
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
    NodeStatus statusIpv4_ {NodeStatus::Disconnected};
    NodeStatus statusIpv6_ {NodeStatus::Disconnected};

    InfoHash myid {};

    /**
     * Store listen requests.
     */
    struct Listener
    {
        size_t token;
        std::shared_ptr<restbed::Request> req;
        std::string key;
        GetCallback cb;
        Value::Filter filterChain;
        std::unique_ptr<std::thread> thread;
    };
    std::vector<Listener> listeners_;
    size_t listener_token_ {0};
    /**
     * Store current put and get requests.
     */
    struct Operation
    {
        std::shared_ptr<restbed::Request> req;
        std::thread thread;
    };
    std::vector<Operation> operations_;

    Scheduler scheduler;
    /**
     * Retrieve if we can connect to the proxy (update statusIpvX_)
     */
    void confirmProxy();
    Sp<Scheduler::Job> nextProxyConfirmation {};
    /**
     * Verify if we are still connected.
     */
    void confirmConnectivity();
    Sp<Scheduler::Job> nextConnectivityConfirmation {};
    /**
     * Relaunch LISTEN requests if the client disconnect/reconnect.
     */
    void restartListeners();

    std::shared_ptr<Json::Value> currentProxyInfos_;
};

}

#endif // OPENDHT_PROXY_CLIENT
