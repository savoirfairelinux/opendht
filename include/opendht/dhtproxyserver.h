// TODO gpl

#if OPENDHT_PROXY_SERVER

#pragma once

#include "def.h"

#include <thread>
#include <memory>
#include <restbed>

namespace dht {

class DhtRunner;

class OPENDHT_PUBLIC DhtProxyServer
{
public:
    DhtProxyServer(DhtRunner* dht, unsigned int port = 8000);
    virtual ~DhtProxyServer();

    DhtProxyServer(const DhtProxyServer& other) = default;
    DhtProxyServer(DhtProxyServer&& other) = default;
    DhtProxyServer& operator=(const DhtProxyServer& other) = default;
    DhtProxyServer& operator=(DhtProxyServer&& other) = default;

    void stop();

private:
    /**
     * Return the PublicKey id, the node id and node stats
     * Method: GET "/"
     * Result: HTTP 200, body: {"id":"xxxx", "node_id":"xxxx", "ipv4":"xxxxxx", "ipv6": "xxxxx"}
     * On error: HTTP 404, body: {"err":"xxxx"}
     */
    void getNodeInfo(const std::shared_ptr<restbed::Session>& session) const;

    /**
     * Return Values of a InfoHash
     * Method: GET "/{InfoHash: .*}"
     * Return: Multiple JSON object in parts. For 2 values, you will have 3 parts:
     * {"data":"xxxx" (...) "type":3} (HTTP/1.1 200 OK Content-Type: application/json)
     * {"data":"xxxx" (...) "type":3} (HTTP/1.1 200 OK Content-Type: application/json)
     * {"ok": 1}
     *
     * On error: HTTP 404, body: {"err":"xxxx"}
     */
    void get(const std::shared_ptr<restbed::Session>& session) const;

    /**
     * Listen incoming Values of a InfoHash.
     * Method: LISTEN "/{InfoHash: .*}"
     * Return: Multiple JSON object in parts. For 2 values, you will have 2 parts:
     * {"data":"xxxx" (...) "type":3} (HTTP/1.1 200 OK Content-Type: application/json)
     * {"data":"xxxx" (...) "type":3} (HTTP/1.1 200 OK Content-Type: application/json)
     *
     * On error: HTTP 404, body: {"err":"xxxx"}
     */
    void listen(const std::shared_ptr<restbed::Session>& session) const;

    /**
     * Put a value on the DHT
     * Method: POST "/{InfoHash: .*}"
     * body = Value to put in JSON
     * Return: {"ok":"1"}
     * On error: HTTP 404, body: {"err":"xxxx"} if no dht
     * HTTP 400, body: {"err":"xxxx"} if bad json
     */
    void put(const std::shared_ptr<restbed::Session>& session) const;

#if OPENDHT_PROXY_SERVER_OPTIONAL
    /**
     * Put a value to sign by the proxy on the DHT
     * Method: SIGN "/{InfoHash: .*}"
     * body = Value to put in JSON
     * Return: {"ok":"1"}
     * On error: HTTP 404, body: {"err":"xxxx"} if no dht
     * HTTP 400, body: {"err":"xxxx"} if bad json
     */
    void putSigned(const std::shared_ptr<restbed::Session>& session) const;

    /**
     * Put a value to encrypt by the proxy on the DHT
     * Method: ENCRYPT "/{hash: .*}"
     * body = Value to put in JSON + "to":"infoHash"
     * Return: {"ok":"1"}
     * On error: HTTP 404, body: {"err":"xxxx"} if no dht
     * HTTP 400, body: {"err":"xxxx"} if bad json
     */
    void putEncrypted(const std::shared_ptr<restbed::Session>& session) const;
#endif // OPENDHT_PROXY_SERVER_OPTIONAL

    /**
     * Return Values of a InfoHash filtered by a value id
     * Method: GET "/{InfoHash: .*}/{ValueId: .*}"
     * Return: Multiple JSON object in parts. For 2 values, you will have 3 parts:
     * {"data":"xxxx" (...) "type":3} (HTTP/1.1 200 OK Content-Type: application/json)
     * {"data":"xxxx" (...) "type":3} (HTTP/1.1 200 OK Content-Type: application/json)
     * {"ok": 1}
     *
     * On error: HTTP 404, body: {"err":"xxxx"}
     */
    void getFiltered(const std::shared_ptr<restbed::Session>& session) const;

    std::thread server_thread {};
    std::unique_ptr<restbed::Service> service_;
    DhtRunner* dht_;
    mutable std::vector<std::shared_ptr<std::thread>> listenThreads_;
};

}

#endif //OPENDHT_PROXY_SERVER
