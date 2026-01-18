// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "def.h"
#include "sockaddr.h"
#include "infohash.h"
#include "logger.h"
#include "utils.h"

#include <asio/steady_timer.hpp>
#include <thread>

namespace asio {
class io_context;
}

namespace dht {

class OPENDHT_PUBLIC PeerDiscovery
{
public:
    static constexpr in_port_t DEFAULT_PORT = 8888;
    using ServiceDiscoveredCallback = std::function<void(msgpack::object&&, SockAddr&&)>;

    PeerDiscovery(in_port_t port = DEFAULT_PORT,
                  std::shared_ptr<asio::io_context> ioContext = {},
                  std::shared_ptr<Logger> logger = {});
    ~PeerDiscovery();

    /**
     * startDiscovery - Keep Listening data from the sender until node is joinned
     * or stop is called
     */
    void startDiscovery(std::string_view type, ServiceDiscoveredCallback callback);

    template<typename T>
    void startDiscovery(std::string_view type, std::function<void(T&&, SockAddr&&)> cb)
    {
        startDiscovery(type, [cb](msgpack::object&& ob, SockAddr&& addr) { cb(ob.as<T>(), std::move(addr)); });
    }

    /**
     * startPublish - Keeping sending data until node is joinned or stop is called
     */
    void startPublish(std::string_view type, const msgpack::sbuffer& pack_buf);
    void startPublish(sa_family_t domain, std::string_view type, const msgpack::sbuffer& pack_buf);

    template<typename T>
    void startPublish(std::string_view type, const T& object)
    {
        msgpack::sbuffer buf;
        msgpack::pack(buf, object);
        startPublish(type, buf);
    }

    /**
     * Thread Stopper
     */
    void stop();

    /**
     * Remove possible callBack to discovery
     */
    bool stopDiscovery(std::string_view type);

    /**
     * Remove different serivce message to send
     */
    bool stopPublish(std::string_view type);
    bool stopPublish(sa_family_t domain, std::string_view type);

    void connectivityChanged();

    void stopConnectivityChanged();

private:
    class DomainPeerDiscovery;
    std::unique_ptr<DomainPeerDiscovery> peerDiscovery4_;
    std::unique_ptr<DomainPeerDiscovery> peerDiscovery6_;
    std::shared_ptr<asio::io_context> ioContext_;
    std::thread ioRunnner_;
};

} // namespace dht
