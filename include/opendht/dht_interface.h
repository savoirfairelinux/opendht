/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
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
#include "log_enable.h"

namespace dht {

namespace net {
    class DatagramSocket;
}

class OPENDHT_PUBLIC DhtInterface {
public:
    DhtInterface() = default;
    DhtInterface(const Logger& l) : logger_(std::make_shared<Logger>(l)) {};
    DhtInterface(const std::shared_ptr<Logger>& l) : logger_(l) {};
    virtual ~DhtInterface() = default;

    // [[deprecated]]
    using Status = NodeStatus;
    // [[deprecated]]
    using NodeExport = dht::NodeExport;

    /**
     * Get the current status of the node for the given family.
     */
    virtual NodeStatus updateStatus(sa_family_t af) { return getStatus(af); };
    virtual NodeStatus getStatus(sa_family_t af) const = 0;
    virtual NodeStatus getStatus() const = 0;

    virtual net::DatagramSocket* getSocket() const { return {}; };

    /**
     * Get the ID of the DHT node.
     */
    virtual const InfoHash& getNodeId() const = 0;

    /**
     * Performs final operations before quitting.
     */
    virtual void shutdown(ShutdownCallback cb) = 0;

    /**
     * Returns true if the node is running (have access to an open socket).
     *
     *  af: address family. If non-zero, will return true if the node
     *     is running for the provided family.
     */
    virtual bool isRunning(sa_family_t af = 0) const = 0;

    virtual void registerType(const ValueType& type) = 0;

    virtual const ValueType& getType(ValueType::Id type_id) const = 0;

    virtual void addBootstrap(const std::string& /*host*/, const std::string& /*service*/) {};
    virtual void clearBootstrap() {};

    /**
     * Insert a node in the main routing table.
     * The node is not pinged, so this should be
     * used to bootstrap efficiently from previously known nodes.
     */
    virtual void insertNode(const InfoHash& id, const SockAddr&) = 0;
    virtual void insertNode(const NodeExport& n) = 0;

    virtual void pingNode(SockAddr, DoneCallbackSimple&& cb={}) = 0;

    virtual time_point periodic(const uint8_t *buf, size_t buflen, SockAddr, const time_point& now) = 0;
    virtual time_point periodic(const uint8_t *buf, size_t buflen, const sockaddr* from, socklen_t fromlen, const time_point& now) = 0;

    /**
     * Get a value by searching on all available protocols (IPv4, IPv6),
     * and call the provided get callback when values are found at key.
     * The operation will start as soon as the node is connected to the network.
     * @param cb a function called when new values are found on the network.
     *         It should return false to stop the operation.
     * @param donecb a function called when the operation is complete.
                  cb and donecb won't be called again afterward.
     * @param f a filter function used to prefilter values.
     */
    virtual void get(const InfoHash& key, GetCallback cb, DoneCallback donecb={}, Value::Filter&& f={}, Where&& w = {}) = 0;
    virtual void get(const InfoHash& key, GetCallback cb, DoneCallbackSimple donecb={}, Value::Filter&& f={}, Where&& w = {}) = 0;
    virtual void get(const InfoHash& key, GetCallbackSimple cb, DoneCallback donecb={}, Value::Filter&& f={}, Where&& w = {}) = 0;
    virtual void get(const InfoHash& key, GetCallbackSimple cb, DoneCallbackSimple donecb, Value::Filter&& f={}, Where&& w = {}) = 0;

    /**
      * Similar to Dht::get, but sends a Query to filter data remotely.
      * @param key the key for which to query data for.
      * @param cb a function called when new values are found on the network.
      *         It should return false to stop the operation.
      * @param done_cb a function called when the operation is complete.
                      cb and done_cb won't be called again afterward.
      * @param q a query used to filter values on the remotes before they send a
      *        response.
      */
    virtual void query(const InfoHash& key, QueryCallback cb, DoneCallback done_cb = {}, Query&& q = {}) = 0;
    virtual void query(const InfoHash& key, QueryCallback cb, DoneCallbackSimple done_cb = {}, Query&& q = {}) = 0;

    /**
     * Get locally stored data for the given hash.
     */
    virtual std::vector<Sp<Value>> getLocal(const InfoHash& key, const Value::Filter& f = {}) const = 0;

    /**
     * Get locally stored data for the given key and value id.
     */
    virtual Sp<Value> getLocalById(const InfoHash& key, Value::Id vid) const = 0;

    /**
     * Announce a value on all available protocols (IPv4, IPv6).
     *
     * The operation will start as soon as the node is connected to the network.
     * The done callback will be called once, when the first announce succeeds, or fails.
     */
    virtual void put(const InfoHash& key,
           Sp<Value>,
           DoneCallback cb=nullptr,
           time_point created=time_point::max(),
           bool permanent = false) = 0;
    virtual void put(const InfoHash& key,
           const Sp<Value>& v,
           DoneCallbackSimple cb,
           time_point created=time_point::max(),
           bool permanent = false) = 0;
    virtual void put(const InfoHash& key,
           Value&& v,
           DoneCallback cb=nullptr,
           time_point created=time_point::max(),
           bool permanent = false) = 0;
    virtual void put(const InfoHash& key,
           Value&& v,
           DoneCallbackSimple cb,
           time_point created=time_point::max(),
           bool permanent = false) = 0;

    /**
     * Get data currently being put at the given hash.
     */
    virtual std::vector<Sp<Value>> getPut(const InfoHash&) const = 0;

    /**
     * Get data currently being put at the given hash with the given id.
     */
    virtual Sp<Value> getPut(const InfoHash&, const Value::Id&) const = 0;

    /**
     * Stop any put/announce operation at the given location,
     * for the value with the given id.
     */
    virtual bool cancelPut(const InfoHash&, const Value::Id&) = 0;

    /**
     * Listen on the network for any changes involving a specified hash.
     * The node will register to receive updates from relevent nodes when
     * new values are added or removed.
     *
     * @return a token to cancel the listener later.
     */
    virtual size_t listen(const InfoHash&, GetCallback, Value::Filter={}, Where w = {}) = 0;
    virtual size_t listen(const InfoHash& key, GetCallbackSimple cb, Value::Filter f={}, Where w = {}) = 0;
    virtual size_t listen(const InfoHash&, ValueCallback, Value::Filter={}, Where w = {}) = 0;

    virtual bool cancelListen(const InfoHash&, size_t token) = 0;

    /**
     * Inform the DHT of lower-layer connectivity changes.
     * This will cause the DHT to assume a public IP address change.
     * The DHT will recontact neighbor nodes, re-register for listen ops etc.
     */
    virtual void connectivityChanged(sa_family_t) = 0;
    virtual void connectivityChanged() = 0;

    /**
     * Get the list of good nodes for local storage saving purposes
     * The list is ordered to minimize the back-to-work delay.
     */
    virtual std::vector<NodeExport> exportNodes() const = 0;

    virtual std::vector<ValuesExport> exportValues() const = 0;
    virtual void importValues(const std::vector<ValuesExport>&) = 0;

    virtual NodeStats getNodesStats(sa_family_t af) const = 0;

    virtual std::string getStorageLog() const = 0;
    virtual std::string getStorageLog(const InfoHash&) const = 0;

    virtual std::string getRoutingTablesLog(sa_family_t) const = 0;
    virtual std::string getSearchesLog(sa_family_t) const = 0;
    virtual std::string getSearchLog(const InfoHash&, sa_family_t af = AF_UNSPEC) const = 0;

    virtual void dumpTables() const = 0;
    virtual std::vector<unsigned> getNodeMessageStats(bool in = false) = 0;

    /**
     * Set the in-memory storage limit in bytes
     */
    virtual void setStorageLimit(size_t limit = DEFAULT_STORAGE_LIMIT) = 0;

    /**
     * Returns the total memory usage of stored values and the number
     * of stored values.
     */
    virtual std::pair<size_t, size_t> getStoreSize() const = 0;

    virtual std::vector<SockAddr> getPublicAddress(sa_family_t family = 0) = 0;

    /**
     * Enable or disable logging of DHT internal messages
     */
    virtual void setLoggers(LogMethod error = {}, LogMethod warn = {}, LogMethod debug = {}) {
        if (logger_) {
            logger_->DBG = std::move(debug);
            logger_->WARN = std::move(warn);
            logger_->ERR = std::move(error);
        } else
            logger_= std::make_shared<Logger>(std::move(error), std::move(warn), std::move(debug));
    }

    virtual void setLogger(const Logger& l) {
        if (logger_)
            *logger_ = l;
        else
            logger_= std::make_shared<Logger>(l);
    }

    virtual void setLogger(const std::shared_ptr<Logger>& l) {
        logger_ = l;
    }

    /**
     * Only print logs related to the given InfoHash (if given), or disable filter (if zeroes).
     */
    virtual void setLogFilter(const InfoHash& f)
    {
        if (logger_)
            logger_->setFilter(f);
    }

    virtual void setPushNotificationToken(const std::string&) {};

    /**
     * Call linked callback with a push notification
     * @param notification to process
     */
    virtual void pushNotificationReceived(const std::map<std::string, std::string>& data) = 0;

protected:
    std::shared_ptr<Logger> logger_ {};
};

} // namespace dht
