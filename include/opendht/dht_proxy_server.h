/*
 *  Copyright (C) 2017-2018 Savoir-faire Linux Inc.
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

#if OPENDHT_PROXY_SERVER

#pragma once

#include "def.h"
#include "sockaddr.h"
#include "infohash.h"

#include <thread>
#include <memory>
#include <mutex>
#include <restbed>

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
    void listen(const std::shared_ptr<restbed::Session>& session) const;

    /**
     * Put a value on the DHT
     * Method: POST "/{InfoHash: .*}"
     * body = Value to put in JSON
     * Return: HTTP 200 if success and the value put in JSON
     * On error: HTTP 503, body: {"err":"xxxx"} if no dht
     * HTTP 400, body: {"err":"xxxx"} if bad json or HTTP 502 if put fails
     * @param session
     */
    void put(const std::shared_ptr<restbed::Session>& session) const;

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

#if OPENDHT_PUSH_NOTIFICATIONS
    /**
     * Subscribe to push notifications for an iOS or Android device.
     * Method: SUBSCRIBE "/{InfoHash: .*}"
     * Body: {"key": "device_key", (optional)"callback_id":y,
     * (optional)"isAndroid":false (default true)}"
     * Return: {"token": x}" where x if a token to save
     * @note: the listen will timeout after six hours (and send a push notification).
     * so you need to refresh the operation each six hours.
     * @note: callback_id is used to add the possibility to have multiple listen
     * on same hash for same device and must be > 0
     * @param session
     */
    void subscribe(const std::shared_ptr<restbed::Session>& session) const;
    /**
     * Unsubscribe to push notifications for an iOS or Android device.
     * Method: UNSUBSCRIBE "/{InfoHash: .*}"
     * Body: {"key": "device_key", "token": x, (optional)"callback_id":y"
     * where x if the token to cancel
     * Return: nothing
     * @note: callback id is used to add the possibility to have multiple listen
     * on same hash for same device
     * @param session
     */
    void unsubscribe(const std::shared_ptr<restbed::Session>& session) const;
    /**
     * Send a push notification via a gorush push gateway
     * @param key of the device
     * @param json, the content to send
     */
    void sendPushNotification(const std::string& key, const Json::Value& json, bool isAndroid) const;
#endif //OPENDHT_PUSH_NOTIFICATIONS

    std::thread server_thread {};
    std::unique_ptr<restbed::Service> service_;
    std::shared_ptr<DhtRunner> dht_;

    // Handle client quit for listen.
    // NOTE: can be simplified when we will supports restbed 5.0
    std::thread listenThread_;
    struct SessionToHashToken {
        std::shared_ptr<restbed::Session> session;
        InfoHash hash;
        std::future<size_t> token;
    };
    mutable std::vector<SessionToHashToken> currentListeners_;
    mutable std::mutex lockListener_;
    std::atomic_bool stopListeners {false};

#if OPENDHT_PUSH_NOTIFICATIONS
    struct PushListener {
        std::string pushToken;
        InfoHash hash;
        unsigned token;
        std::future<size_t> internalToken;
        std::chrono::steady_clock::time_point deadline;
        bool started {false};
        unsigned callbackId {0};
        std::string clientId {};
        bool isAndroid {true};
    };
    mutable std::mutex lockPushListeners_;
    mutable std::vector<PushListener> pushListeners_;
    mutable unsigned tokenPushNotif_ {0};
    const std::string pushServer_;
#endif //OPENDHT_PUSH_NOTIFICATIONS

    /**
     * Remove finished listeners
     * @param testSession if we remove the listener only if the session is closed
     */
    void removeClosedListeners(bool testSession = true);
    /**
     * Launch or remove push listeners if needed
     */
    void handlePushListeners();
};

}

#endif //OPENDHT_PROXY_SERVER
