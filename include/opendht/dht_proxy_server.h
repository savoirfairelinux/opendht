/*
 *  Copyright (C) 2017 Savoir-faire Linux Inc.
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

#include "def.h"
#include "sockaddr.h"
#include "infohash.h"

#include <thread>
#include <memory>
#include <restbed>

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
     * @note if the server fails to start (if port is already used or reserved),
     * it will fails silently
     */
    DhtProxyServer(std::shared_ptr<DhtRunner> dht, in_port_t port = 8000);
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
     * Return Values of a InfoHash
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
     * Listen incoming Values of a InfoHash.
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
     * Return Values of a InfoHash filtered by a value id
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
     */
    void handleOptionsMethod(const std::shared_ptr<restbed::Session>& session) const;

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
    std::atomic_bool stopListeners {false};
};

}

#endif //OPENDHT_PROXY_SERVER
