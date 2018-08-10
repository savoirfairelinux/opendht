/*
 *  Copyright (C) 2017-2018 Savoir-faire Linux Inc.
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

#if OPENDHT_PROXY_SERVER

#pragma once

#include "callbacks.h"
#include "def.h"
#include "infohash.h"
#include "proxy.h"
#include "scheduler.h"
#include "sockaddr.h"
#include "value.h"

#include <thread>
#include <memory>
#include <mutex>
#include <restbed>

#ifdef OPENDHT_JSONCPP
#include <json/json.h>
#endif

namespace Json {
    class Value;
}

namespace dht {

class DhtRunner;

/**
 * Describes the REST API
 */
class OPENDHT_PUBLIC DhtProxyServer
{
public:
    /**
     * Start the Http server for OpenDHT
     * @param dht the DhtRunner linked to this proxy server
     * @param port to listen
     * @param pushServer where to push notifications
     * @note if the server fails to start (if port is already used or reserved),
     * it will fails silently
     */
    DhtProxyServer(std::shared_ptr<DhtRunner> dht, in_port_t port = 8000, const std::string& pushServer = "");
    virtual ~DhtProxyServer();

    DhtProxyServer(const DhtProxyServer& other) = delete;
    DhtProxyServer(DhtProxyServer&& other) = delete;
    DhtProxyServer& operator=(const DhtProxyServer& other) = delete;
    DhtProxyServer& operator=(DhtProxyServer&& other) = delete;

    struct ServerStats {
        /** Current number of listen operations */
        size_t listenCount;
        /** Current number of permanent put operations */
        size_t putCount;
        /** Current number of push tokens with at least one listen operation */
        size_t pushListenersCount;
        /** Average requests per second */
        double requestRate;
        /** Node Info **/
        NodeInfo nodeInfo;

        std::string toString() const {
            std::ostringstream ss;
            ss << "Listens: " << listenCount << " Puts: " << putCount << " PushListeners: " << pushListenersCount << std::endl;
            ss << "Requests: " << requestRate << " per second." << std::endl;
            auto& ni = nodeInfo;
            auto& ipv4 = ni.ipv4;
            if (ipv4.table_depth > 1) {
                ss << "IPv4 Network estimation: " << ipv4.getNetworkSizeEstimation() << std::endl;;
            }
            auto& ipv6 = ni.ipv6;
            if (ipv6.table_depth > 1) {
                ss << "IPv6 Network estimation: " << ipv6.getNetworkSizeEstimation() << std::endl;;
            }
            return ss.str();
        }

#ifdef OPENDHT_JSONCPP
        /**
         * Build a json object from a NodeStats
         */
        Json::Value toJson() const {
            Json::Value result;
            result["listenCount"] = static_cast<Json::UInt64>(listenCount);
            result["putCount"] = static_cast<Json::UInt64>(putCount);
            result["pushListenersCount"] = static_cast<Json::UInt64>(pushListenersCount);
            result["requestRate"] = requestRate;
            result["nodeInfo"] = nodeInfo.toJson();
            return result;
        }
#endif
    };

    ServerStats stats() const { return stats_; }

    void updateStats() const;

    std::shared_ptr<DhtRunner> getNode() const { return dht_; }

    /**
     * Stop the DhtProxyServer
     */
    void stop();

private:
    /**
     * Return the PublicKey id, the node id and node stats
     * Method: GET "/"
     * Result: HTTP 200, body: Node infos in JSON format
     * On error: HTTP 503, body: {"err":"xxxx"}
     * @param session
     */
    void getNodeInfo(const std::shared_ptr<restbed::Session>& session) const;

    /**
     * Return ServerStats in JSON format
     * Method: STATS "/"
     * Result: HTTP 200, body: Node infos in JSON format
     * @param session
     */
    void getStats(const std::shared_ptr<restbed::Session>& session) const;

    /**
     * Return Values of an infoHash
     * Method: GET "/{InfoHash: .*}"
     * Return: Multiple JSON object in parts. Example:
     * Value in JSON format\n
     * Value in JSON format
     *
     * On error: HTTP 503, body: {"err":"xxxx"}
     * @param session
     */
    void get(const std::shared_ptr<restbed::Session>& session) const;

    /**
     * Listen incoming Values of an infoHash.
     * Method: LISTEN "/{InfoHash: .*}"
     * Return: Multiple JSON object in parts. Example:
     * Value in JSON format\n
     * Value in JSON format
     *
     * On error: HTTP 503, body: {"err":"xxxx"}
     * @param session
     */
    void listen(const std::shared_ptr<restbed::Session>& session);

    /**
     * Put a value on the DHT
     * Method: POST "/{InfoHash: .*}"
     * body = Value to put in JSON
     * Return: HTTP 200 if success and the value put in JSON
     * On error: HTTP 503, body: {"err":"xxxx"} if no dht
     * HTTP 400, body: {"err":"xxxx"} if bad json or HTTP 502 if put fails
     * @param session
     */
    void put(const std::shared_ptr<restbed::Session>& session);

    void cancelPut(const InfoHash& key, Value::Id vid);

#if OPENDHT_PROXY_SERVER_IDENTITY
    /**
     * Put a value to sign by the proxy on the DHT
     * Method: SIGN "/{InfoHash: .*}"
     * body = Value to put in JSON
     * Return: HTTP 200 if success and the value put in JSON
     * On error: HTTP 503, body: {"err":"xxxx"} if no dht
     * HTTP 400, body: {"err":"xxxx"} if bad json
     * @param session
     */
    void putSigned(const std::shared_ptr<restbed::Session>& session) const;

    /**
     * Put a value to encrypt by the proxy on the DHT
     * Method: ENCRYPT "/{hash: .*}"
     * body = Value to put in JSON + "to":"infoHash"
     * Return: HTTP 200 if success and the value put in JSON
     * On error: HTTP 503, body: {"err":"xxxx"} if no dht
     * HTTP 400, body: {"err":"xxxx"} if bad json
     * @param session
     */
    void putEncrypted(const std::shared_ptr<restbed::Session>& session) const;
#endif // OPENDHT_PROXY_SERVER_IDENTITY

    /**
     * Return Values of an infoHash filtered by a value id
     * Method: GET "/{InfoHash: .*}/{ValueId: .*}"
     * Return: Multiple JSON object in parts. Example:
     * Value in JSON format\n
     * Value in JSON format
     *
     * On error: HTTP 503, body: {"err":"xxxx"}
     * @param session
     */
    void getFiltered(const std::shared_ptr<restbed::Session>& session) const;

    /**
     * Respond allowed Methods
     * Method: OPTIONS "/{hash: .*}"
     * Return: HTTP 200 + Allow: allowed methods
     * See https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS
     * @param session
     */
    void handleOptionsMethod(const std::shared_ptr<restbed::Session>& session) const;

    /**
     * Remove finished listeners
     * @param testSession if we remove the listener only if the session is closed
     */
    void removeClosedListeners(bool testSession = true);

#if OPENDHT_PUSH_NOTIFICATIONS
    /**
     * Subscribe to push notifications for an iOS or Android device.
     * Method: SUBSCRIBE "/{InfoHash: .*}"
     * Body: {"key": "device_key", (optional)"isAndroid":false (default true)}"
     * Return: {"token": x}" where x if a token to save
     * @note: the listen will timeout after six hours (and send a push notification).
     * so you need to refresh the operation each six hours.
     * @param session
     */
    void subscribe(const std::shared_ptr<restbed::Session>& session);
    /**
     * Unsubscribe to push notifications for an iOS or Android device.
     * Method: UNSUBSCRIBE "/{InfoHash: .*}"
     * Body: {"key": "device_key", "token": x} where x if the token to cancel
     * Return: nothing
     * @param session
     */
    void unsubscribe(const std::shared_ptr<restbed::Session>& session);
    /**
     * Send a push notification via a gorush push gateway
     * @param key of the device
     * @param json, the content to send
     */
    void sendPushNotification(const std::string& key, const Json::Value& json, bool isAndroid) const;

    /**
     * Remove a push listener between a client and a hash
     * @param pushToken
     * @param key
     * @param clientId
     */
    void cancelPushListen(const std::string& pushToken, const InfoHash& key, const std::string& clientId);


#endif //OPENDHT_PUSH_NOTIFICATIONS

    using clock = std::chrono::steady_clock;
    using time_point = clock::time_point;

    std::thread server_thread {};
    std::unique_ptr<restbed::Service> service_;
    std::shared_ptr<DhtRunner> dht_;

    std::mutex schedulerLock_;
    std::condition_variable schedulerCv_;
    Scheduler scheduler_;
    std::thread schedulerThread_;

    Sp<Scheduler::Job> printStatsJob_;
    mutable std::mutex statsMutex_;
    mutable NodeInfo nodeInfo_ {};

    // Handle client quit for listen.
    // NOTE: can be simplified when we will supports restbed 5.0
    std::thread listenThread_;
    struct SessionToHashToken {
        std::shared_ptr<restbed::Session> session;
        InfoHash hash;
        std::future<size_t> token;
    };
    std::vector<SessionToHashToken> currentListeners_;
    std::mutex lockListener_;
    std::atomic_bool stopListeners {false};

    struct PermanentPut;
    struct SearchPuts;
    std::map<InfoHash, SearchPuts> puts_;

    mutable std::atomic<size_t> requestNum_ {0};
    mutable std::atomic<time_point> lastStatsReset_ {time_point::min()};

    const std::string pushServer_;

    mutable ServerStats stats_;

#if OPENDHT_PUSH_NOTIFICATIONS
    struct Listener;
    struct PushListener;
    std::mutex lockPushListeners_;
    std::map<std::string, PushListener> pushListeners_;
    proxy::ListenToken tokenPushNotif_ {0};
#endif //OPENDHT_PUSH_NOTIFICATIONS
};

}

#endif //OPENDHT_PROXY_SERVER
