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

#include "callbacks.h"
#include "def.h"
#include "infohash.h"
#include "proxy.h"
#include "scheduler.h"
#include "sockaddr.h"
#include "value.h"
#include "http.h"

#include <restinio/all.hpp>
#include <restinio/tls.hpp>
#include <json/json.h>

#include <memory>
#include <mutex>

namespace http {
class Request;
struct ListenerSession;
}

namespace Json {
class Value;
}

namespace dht {

class DhtRunner;

using RestRouter = restinio::router::express_router_t<>;
using RequestStatus = restinio::request_handling_status_t;

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
    DhtProxyServer(
       dht::crypto::Identity identity,
       std::shared_ptr<DhtRunner> dht, in_port_t port = 8000, const std::string& pushServer = "",
       std::shared_ptr<dht::Logger> logger = {});

    virtual ~DhtProxyServer();

    DhtProxyServer(const DhtProxyServer& other) = delete;
    DhtProxyServer(DhtProxyServer&& other) = delete;
    DhtProxyServer& operator=(const DhtProxyServer& other) = delete;
    DhtProxyServer& operator=(DhtProxyServer&& other) = delete;

    asio::io_context& io_context() const;

    struct ServerStats {
        /** Current number of listen operations */
        size_t listenCount {0};
        /** Current number of permanent put operations */
        size_t putCount {0};
        /** Current number of push tokens with at least one listen operation */
        size_t pushListenersCount {0};
        /** Average requests per second */
        double requestRate {0};
        /** Node Info **/
        std::shared_ptr<NodeInfo> nodeInfo {};

        std::string toString() const {
            std::ostringstream ss;
            ss << "Listens: " << listenCount << " Puts: " << putCount << " PushListeners: " << pushListenersCount << std::endl;
            ss << "Requests: " << requestRate << " per second." << std::endl;
            if (nodeInfo) {
                auto& ipv4 = nodeInfo->ipv4;
                if (ipv4.table_depth > 1)
                    ss << "IPv4 Network estimation: " << ipv4.getNetworkSizeEstimation() << std::endl;;
                auto& ipv6 = nodeInfo->ipv6;
                if (ipv6.table_depth > 1)
                    ss << "IPv6 Network estimation: " << ipv6.getNetworkSizeEstimation() << std::endl;;
            }
            return ss.str();
        }

        /**
         * Build a json object from a NodeStats
         */
        Json::Value toJson() const {
            Json::Value result;
            result["listenCount"] = static_cast<Json::UInt64>(listenCount);
            result["putCount"] = static_cast<Json::UInt64>(putCount);
            result["pushListenersCount"] = static_cast<Json::UInt64>(pushListenersCount);
            result["requestRate"] = requestRate;
            if (nodeInfo)
                result["nodeInfo"] = nodeInfo->toJson();
            return result;
        }
    };

    std::shared_ptr<ServerStats> stats() const { return stats_; }

    std::shared_ptr<ServerStats> updateStats(std::shared_ptr<NodeInfo> info) const;

    std::shared_ptr<DhtRunner> getNode() const { return dht_; }

private:
    class ConnectionListener;
    struct RestRouterTraitsTls;
    struct RestRouterTraits;

    template <typename HttpResponse>
    static HttpResponse initHttpResponse(HttpResponse response);
    static restinio::request_handling_status_t serverError(restinio::request_t& request);

    template< typename ServerSettings >
    void addServerSettings(ServerSettings& serverSettings,
                           const unsigned int max_pipelined_requests = 16);

    std::unique_ptr<RestRouter> createRestRouter();

    void onConnectionClosed(restinio::connection_id_t);

    /**
     * Return the PublicKey id, the node id and node stats
     * Method: GET "/"
     * Result: HTTP 200, body: Node infos in JSON format
     * On error: HTTP 503, body: {"err":"xxxx"}
     * @param session
     */
    RequestStatus getNodeInfo(restinio::request_handle_t request,
                               restinio::router::route_params_t params) const;

    /**
     * Return ServerStats in JSON format
     * Method: STATS "/"
     * Result: HTTP 200, body: Node infos in JSON format
     * @param session
     */
    RequestStatus getStats(restinio::request_handle_t request,
                           restinio::router::route_params_t params);

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
    RequestStatus get(restinio::request_handle_t request,
                       restinio::router::route_params_t params);

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
    RequestStatus listen(restinio::request_handle_t request,
                         restinio::router::route_params_t params);

    /**
     * Put a value on the DHT
     * Method: POST "/{InfoHash: .*}"
     * body = Value to put in JSON
     * Return: HTTP 200 if success and the value put in JSON
     * On error: HTTP 503, body: {"err":"xxxx"} if no dht
     * HTTP 400, body: {"err":"xxxx"} if bad json or HTTP 502 if put fails
     * @param session
     */
    RequestStatus put(restinio::request_handle_t request,
                      restinio::router::route_params_t params);

    void handleCancelPermamentPut(const asio::error_code &ec, const InfoHash& key, Value::Id vid);

#ifdef OPENDHT_PROXY_SERVER_IDENTITY
    /**
     * Put a value to sign by the proxy on the DHT
     * Method: SIGN "/{InfoHash: .*}"
     * body = Value to put in JSON
     * Return: HTTP 200 if success and the value put in JSON
     * On error: HTTP 503, body: {"err":"xxxx"} if no dht
     * HTTP 400, body: {"err":"xxxx"} if bad json
     * @param session
     */
    RequestStatus putSigned(restinio::request_handle_t request,
                            restinio::router::route_params_t params) const;

    /**
     * Put a value to encrypt by the proxy on the DHT
     * Method: ENCRYPT "/{hash: .*}"
     * body = Value to put in JSON + "to":"infoHash"
     * Return: HTTP 200 if success and the value put in JSON
     * On error: HTTP 503, body: {"err":"xxxx"} if no dht
     * HTTP 400, body: {"err":"xxxx"} if bad json
     * @param session
     */
    RequestStatus putEncrypted(restinio::request_handle_t request,
                               restinio::router::route_params_t params);

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
    RequestStatus getFiltered(restinio::request_handle_t request,
                              restinio::router::route_params_t params);

    /**
     * Respond allowed Methods
     * Method: OPTIONS "/{hash: .*}"
     * Return: HTTP 200 + Allow: allowed methods
     * See https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS
     * @param session
     */
    RequestStatus options(restinio::request_handle_t request,
                           restinio::router::route_params_t params);

#ifdef OPENDHT_PUSH_NOTIFICATIONS
    /**
     * Subscribe to push notifications for an iOS or Android device.
     * Method: SUBSCRIBE "/{InfoHash: .*}"
     * Body: {"key": "device_key", (optional)"isAndroid":false (default true)}"
     * Return: {"token": x}" where x if a token to save
     * @note: the listen will timeout after six hours (and send a push notification).
     * so you need to refresh the operation each six hours.
     * @param session
     */
    RequestStatus subscribe(restinio::request_handle_t request,
                            restinio::router::route_params_t params);

    /**
     * Unsubscribe to push notifications for an iOS or Android device.
     * Method: UNSUBSCRIBE "/{InfoHash: .*}"
     * Body: {"key": "device_key", "token": x} where x if the token to cancel
     * Return: nothing
     * @param session
     */
    RequestStatus unsubscribe(restinio::request_handle_t request,
                              restinio::router::route_params_t params);

    /**
     * Send a push notification via a gorush push gateway
     * @param key of the device
     * @param json, the content to send
     */
    void sendPushNotification(const std::string& key, Json::Value&& json, bool isAndroid, bool highPriority);

    /**
     * Send push notification with an expire timeout.
     * @param ec
     * @param pushToken
     * @param json
     * @param isAndroid
     */
    void handleNotifyPushListenExpire(const asio::error_code &ec, const std::string pushToken,
                                      std::function<Json::Value()> json, const bool isAndroid);

    /**
     * Remove a push listener between a client and a hash
     * @param ec
     * @param pushToken
     * @param key
     * @param clientId
     */
    void handleCancelPushListen(const asio::error_code &ec, const std::string pushToken,
                                const InfoHash key, const std::string clientId);

#endif //OPENDHT_PUSH_NOTIFICATIONS

    void handlePrintStats(const asio::error_code &ec);
    void updateStats();

    using clock = std::chrono::steady_clock;
    using time_point = clock::time_point;

    std::shared_ptr<asio::io_context> ioContext_;
    std::shared_ptr<DhtRunner> dht_;
    Json::StreamWriterBuilder jsonBuilder_;
    Json::CharReaderBuilder jsonReaderBuilder_;

    // http server
    std::thread serverThread_;
    std::unique_ptr<restinio::http_server_t<RestRouterTraitsTls>> httpsServer_;
    std::unique_ptr<restinio::http_server_t<RestRouterTraits>> httpServer_;

    // http client
    std::pair<std::string, std::string> pushHostPort_;

    mutable std::mutex requestLock_;
    std::map<unsigned int /*id*/, std::shared_ptr<http::Request>> requests_;

    std::shared_ptr<dht::Logger> logger_;

    std::shared_ptr<ServerStats> stats_;
    std::shared_ptr<NodeInfo> nodeInfo_ {};
    std::unique_ptr<asio::steady_timer> printStatsTimer_;

    // Thread-safe access to listeners map.
    std::mutex lockListener_;
    // Shared with connection listener.
    std::map<restinio::connection_id_t, http::ListenerSession> listeners_;
    // Connection Listener observing conn state changes.
    std::shared_ptr<ConnectionListener> connListener_;

    struct PushSessionContext {
        std::mutex lock;
        std::string sessionId;
    };
    struct PermanentPut {
        time_point expiration;
        std::string pushToken;
        std::string clientId;
        std::shared_ptr<PushSessionContext> sessionCtx;
        std::unique_ptr<asio::steady_timer> expireTimer;
        std::unique_ptr<asio::steady_timer> expireNotifyTimer;
        Sp<Value> value;
    };
    struct SearchPuts {
        std::map<dht::Value::Id, PermanentPut> puts;
    };
    std::mutex lockSearchPuts_;
    std::map<InfoHash, SearchPuts> puts_;

    mutable std::atomic<size_t> requestNum_ {0};
    mutable std::atomic<time_point> lastStatsReset_ {time_point::min()};

    std::string pushServer_;

#ifdef OPENDHT_PUSH_NOTIFICATIONS
    struct Listener {
        std::string clientId;
        std::shared_ptr<PushSessionContext> sessionCtx;
        std::future<size_t> internalToken;
        std::unique_ptr<asio::steady_timer> expireTimer;
        std::unique_ptr<asio::steady_timer> expireNotifyTimer;
    };
    struct PushListener {
        std::map<InfoHash, std::vector<Listener>> listeners;
    };
    std::mutex lockPushListeners_;
    std::map<std::string, PushListener> pushListeners_;
    proxy::ListenToken tokenPushNotif_ {0};
#endif //OPENDHT_PUSH_NOTIFICATIONS
};

}
