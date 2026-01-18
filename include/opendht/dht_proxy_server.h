// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
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

namespace dht {
enum class PushType { None = 0, Android, iOS, UnifiedPush };
}
MSGPACK_ADD_ENUM(dht::PushType)

namespace Json {
class Value;
}

namespace dht {

namespace http {
class Request;
struct ListenerSession;
} // namespace http

class DhtRunner;

using RestRouter = restinio::router::express_router_t<>;
using RequestStatus = restinio::request_handling_status_t;

struct OPENDHT_PUBLIC ProxyServerConfig
{
    std::string address {};
    in_port_t port {8000};
    std::string pushServer {};
    std::string persistStatePath {};
    dht::crypto::Identity identity {};
    std::string bundleId {};
};

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
    DhtProxyServer(const std::shared_ptr<DhtRunner>& dht,
                   const ProxyServerConfig& config = {},
                   const std::shared_ptr<log::Logger>& logger = {});

    virtual ~DhtProxyServer();

    DhtProxyServer(const DhtProxyServer& other) = delete;
    DhtProxyServer(DhtProxyServer&& other) = delete;
    DhtProxyServer& operator=(const DhtProxyServer& other) = delete;
    DhtProxyServer& operator=(DhtProxyServer&& other) = delete;

    asio::io_context& io_context() const;

    using clock = std::chrono::steady_clock;
    using time_point = clock::time_point;

    struct PushStats
    {
        uint64_t highPriorityCount {0};
        uint64_t normalPriorityCount {0};

        void increment(bool highPriority)
        {
            if (highPriority)
                highPriorityCount++;
            else
                normalPriorityCount++;
        }

        Json::Value toJson() const
        {
            Json::Value val;
            val["highPriorityCount"] = static_cast<Json::UInt64>(highPriorityCount);
            val["normalPriorityCount"] = static_cast<Json::UInt64>(normalPriorityCount);
            return val;
        }

        std::string toString() const
        {
            return fmt::format("{} high priority, {} normal priority", highPriorityCount, normalPriorityCount);
        }
    };

    struct OPENDHT_PUBLIC ServerStats
    {
        /** Current number of listen operations */
        size_t listenCount {0};
        /** Current number of permanent put operations (hash used) */
        size_t putCount {0};
        /** Current number of permanent put values */
        size_t totalPermanentPuts {0};
        /** Current number of push tokens with at least one listen operation */
        size_t pushListenersCount {0};

        /** Time at which the server was started */
        time_point serverStartTime;
        /** Last time at which the stats were updated */
        time_point lastUpdated;
        /** Total number of push notification requests that the server attempted to
         * send since being started, broken down by type and priority level */
        PushStats androidPush;
        PushStats iosPush;
        PushStats unifiedPush;

        /** Average requests per second */
        double requestRate {0};
        /** Node Info **/
        std::shared_ptr<NodeInfo> nodeInfo {};

        std::string toString() const;

        /**
         * Build a json object from a NodeStats
         */
        Json::Value toJson() const;
    };

    std::shared_ptr<ServerStats> stats() const { return stats_; }

    std::shared_ptr<ServerStats> updateStats(std::shared_ptr<NodeInfo> info) const;

    std::shared_ptr<DhtRunner> getNode() const { return dht_; }

private:
    class ConnectionListener;
    struct RestRouterTraitsTls;
    struct RestRouterTraits;

    template<typename HttpResponse>
    static HttpResponse initHttpResponse(HttpResponse response);
    static restinio::request_handling_status_t serverError(restinio::request_t& request);

    template<typename ServerSettings>
    void addServerSettings(ServerSettings& serverSettings, const unsigned int max_pipelined_requests = 16);

    std::unique_ptr<RestRouter> createRestRouter();

    void onConnectionClosed(restinio::connection_id_t);

    /**
     * Return the PublicKey id, the node id and node stats
     * Method: GET "/"
     * Result: HTTP 200, body: Node infos in JSON format
     * On error: HTTP 503, body: {"err":"xxxx"}
     * @param session
     */
    RequestStatus getNodeInfo(restinio::request_handle_t request, restinio::router::route_params_t params) const;

    /**
     * Return ServerStats in JSON format
     * Method: STATS "/"
     * Result: HTTP 200, body: Node infos in JSON format
     * @param session
     */
    RequestStatus getStats(restinio::request_handle_t request, restinio::router::route_params_t params);

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
    RequestStatus get(restinio::request_handle_t request, restinio::router::route_params_t params);

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
    RequestStatus listen(restinio::request_handle_t request, restinio::router::route_params_t params);

    /**
     * Put a value on the DHT
     * Method: POST "/{InfoHash: .*}"
     * body = Value to put in JSON
     * Return: HTTP 200 if success and the value put in JSON
     * On error: HTTP 503, body: {"err":"xxxx"} if no dht
     * HTTP 400, body: {"err":"xxxx"} if bad json or HTTP 502 if put fails
     * @param session
     */
    RequestStatus put(restinio::request_handle_t request, restinio::router::route_params_t params);

    void handleCancelPermamentPut(const asio::error_code& ec, const InfoHash& key, Value::Id vid);

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
    RequestStatus putSigned(restinio::request_handle_t request, restinio::router::route_params_t params) const;

    /**
     * Put a value to encrypt by the proxy on the DHT
     * Method: ENCRYPT "/{hash: .*}"
     * body = Value to put in JSON + "to":"infoHash"
     * Return: HTTP 200 if success and the value put in JSON
     * On error: HTTP 503, body: {"err":"xxxx"} if no dht
     * HTTP 400, body: {"err":"xxxx"} if bad json
     * @param session
     */
    RequestStatus putEncrypted(restinio::request_handle_t request, restinio::router::route_params_t params);

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
    RequestStatus getFiltered(restinio::request_handle_t request, restinio::router::route_params_t params);

    /**
     * Respond allowed Methods
     * Method: OPTIONS "/{hash: .*}"
     * Return: HTTP 200 + Allow: allowed methods
     * See https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS
     * @param session
     */
    RequestStatus options(restinio::request_handle_t request, restinio::router::route_params_t params);

    struct PushSessionContext
    {
        std::mutex lock;
        std::string sessionId;
        PushSessionContext(const std::string& id)
            : sessionId(id)
        {}
    };

#ifdef OPENDHT_PUSH_NOTIFICATIONS
    PushType getTypeFromString(const std::string& type);
    std::string getDefaultTopic(PushType type);

    RequestStatus pingPush(restinio::request_handle_t request, restinio::router::route_params_t /*params*/);
    /**
     * Subscribe to push notifications for an iOS or Android device.
     * Method: SUBSCRIBE "/{InfoHash: .*}"
     * Body: {"key": "device_key", (optional)"isAndroid":false (default true)}"
     * Return: {"token": x}" where x if a token to save
     * @note: the listen will timeout after six hours (and send a push notification).
     * so you need to refresh the operation each six hours.
     * @param session
     */
    RequestStatus subscribe(restinio::request_handle_t request, restinio::router::route_params_t params);

    /**
     * Unsubscribe to push notifications for an iOS or Android device.
     * Method: UNSUBSCRIBE "/{InfoHash: .*}"
     * Body: {"key": "device_key", "token": x} where x if the token to cancel
     * Return: nothing
     * @param session
     */
    RequestStatus unsubscribe(restinio::request_handle_t request, restinio::router::route_params_t params);

    /**
     * Send a push notification via a gorush push gateway
     * @param key of the device
     * @param json, the content to send
     */
    void sendPushNotification(
        const std::string& key, Json::Value&& json, PushType type, bool highPriority, const std::string& topic);

    /**
     * Send push notification with an expire timeout.
     * @param ec
     * @param pushToken
     * @param json
     * @param type
     * @param topic
     */
    void handleNotifyPushListenExpire(const asio::error_code& ec,
                                      const std::string pushToken,
                                      std::function<Json::Value()> json,
                                      PushType type,
                                      const std::string& topic);

    /**
     * Remove a push listener between a client and a hash
     * @param ec
     * @param pushToken
     * @param key
     * @param clientId
     */
    void handleCancelPushListen(const asio::error_code& ec,
                                const std::string pushToken,
                                const InfoHash key,
                                const std::string clientId);

    /**
     * Handles a push listen request.
     *
     * @param infoHash The information hash associated with the push listen request.
     * @param pushToken The push token associated with the push listen request.
     * @param type The type of the push listen request.
     * @param clientId The client ID associated with the push listen request.
     * @param sessionCtx The shared pointer to the push session context associated with the push listen request.
     * @param topic The topic associated with the push listen request.
     * @param values The vector of shared pointers to values associated with the push listen request.
     * @param expired A boolean indicating whether the push listen request has expired.
     * @return true.
     */
    bool handlePushListen(const InfoHash& infoHash,
                          const std::string& pushToken,
                          PushType type,
                          const std::string& clientId,
                          const std::shared_ptr<DhtProxyServer::PushSessionContext>& sessionCtx,
                          const std::string& topic,
                          const std::vector<std::shared_ptr<Value>>& values,
                          bool expired);

#endif // OPENDHT_PUSH_NOTIFICATIONS

    void handlePrintStats(const asio::error_code& ec);
    void updateStats();

    template<typename Os>
    void saveState(Os& stream);

    template<typename Is>
    void loadState(Is& is, size_t size);

    std::shared_ptr<asio::io_context> ioContext_;
    std::shared_ptr<DhtRunner> dht_;
    Json::StreamWriterBuilder jsonBuilder_;
    Json::CharReaderBuilder jsonReaderBuilder_;
    std::mt19937_64 rd {crypto::getSeededRandomEngine<std::mt19937_64>()};

    std::string persistPath_;

    // http server
    std::thread serverThread_;
    std::unique_ptr<restinio::http_server_t<RestRouterTraitsTls>> httpsServer_;
    std::unique_ptr<restinio::http_server_t<RestRouterTraits>> httpServer_;

    // http client
    std::pair<std::string, std::string> pushHostPort_;

    mutable std::mutex requestLock_;
    std::map<unsigned int /*id*/, std::shared_ptr<http::Request>> requests_;

    std::shared_ptr<log::Logger> logger_;

    std::shared_ptr<ServerStats> stats_;
    std::shared_ptr<NodeInfo> nodeInfo_ {};
    std::unique_ptr<asio::steady_timer> printStatsTimer_;
    const time_point serverStartTime_;
    mutable std::mutex pushStatsMutex_;
    PushStats androidPush_;
    PushStats iosPush_;
    PushStats unifiedPush_;

    // Thread-safe access to listeners map.
    std::mutex lockListener_;
    // Shared with connection listener.
    std::map<restinio::connection_id_t, http::ListenerSession> listeners_;
    // Connection Listener observing conn state changes.
    std::shared_ptr<ConnectionListener> connListener_;
    struct PermanentPut
    {
        time_point expiration;
        std::string pushToken;
        std::string clientId;
        std::shared_ptr<PushSessionContext> sessionCtx;
        std::unique_ptr<asio::steady_timer> expireTimer;
        std::unique_ptr<asio::steady_timer> expireNotifyTimer;
        Sp<Value> value;
        PushType type;
        std::string topic;

        template<typename Packer>
        void msgpack_pack(Packer& p) const
        {
            p.pack_map(2 + (sessionCtx ? 1 : 0) + (clientId.empty() ? 0 : 1) + (type == PushType::None ? 0 : 2)
                       + (topic.empty() ? 0 : 1));
            p.pack("value");
            p.pack(value);
            p.pack("exp");
            p.pack(to_time_t(expiration));
            if (not clientId.empty()) {
                p.pack("cid");
                p.pack(clientId);
            }
            if (sessionCtx) {
                std::lock_guard<std::mutex> l(sessionCtx->lock);
                p.pack("sid");
                p.pack(sessionCtx->sessionId);
            }
            if (type != PushType::None) {
                p.pack("t");
                p.pack(type);
                p.pack("token");
                p.pack(pushToken);
            }
            if (not topic.empty()) {
                p.pack("top");
                p.pack(topic);
            }
        }

        void msgpack_unpack(const msgpack::object& o);
    };
    struct SearchPuts
    {
        std::map<dht::Value::Id, PermanentPut> puts;
        MSGPACK_DEFINE_ARRAY(puts)
    };
    std::mutex lockSearchPuts_;
    std::map<InfoHash, SearchPuts> puts_;

    mutable std::atomic<size_t> requestNum_ {0};
    mutable std::atomic<time_point> lastStatsReset_ {time_point::min()};

    std::string pushServer_;
    std::string bundleId_;

#ifdef OPENDHT_PUSH_NOTIFICATIONS
    struct Listener
    {
        time_point expiration;
        std::string clientId;
        std::shared_ptr<PushSessionContext> sessionCtx;
        std::future<size_t> internalToken;
        std::unique_ptr<asio::steady_timer> expireTimer;
        std::unique_ptr<asio::steady_timer> expireNotifyTimer;
        PushType type;
        std::string topic;

        template<typename Packer>
        void msgpack_pack(Packer& p) const
        {
            p.pack_map(3 + (sessionCtx ? 1 : 0) + (topic.empty() ? 0 : 1));
            p.pack("cid");
            p.pack(clientId);
            p.pack("exp");
            p.pack(to_time_t(expiration));
            if (sessionCtx) {
                std::lock_guard<std::mutex> l(sessionCtx->lock);
                p.pack("sid");
                p.pack(sessionCtx->sessionId);
            }
            p.pack("t");
            p.pack(type);
            if (!topic.empty()) {
                p.pack("top");
                p.pack(topic);
            }
        }

        void msgpack_unpack(const msgpack::object& o);
    };
    struct PushListener
    {
        std::map<InfoHash, std::vector<Listener>> listeners;
        MSGPACK_DEFINE_ARRAY(listeners)
    };
    std::map<std::string, PushListener> pushListeners_;
#endif // OPENDHT_PUSH_NOTIFICATIONS
};

} // namespace dht
