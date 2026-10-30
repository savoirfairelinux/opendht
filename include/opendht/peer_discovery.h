// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "def.h"
#include "infohash.h"
#include "logger.h"
#include "sockaddr.h"
#include "utils.h"

#include <functional>
#include <memory>
#include <thread>

namespace asio {
class io_context;
}

namespace dht {

class OPENDHT_PUBLIC PeerDiscovery
{
public:
    using PeerDiscoveredCallback = std::function<void(const InfoHash&, SockAddr&&)>;

    PeerDiscovery(std::shared_ptr<asio::io_context> ioContext = {}, std::shared_ptr<Logger> logger = {});
    ~PeerDiscovery();

    void startDiscovery(NetId network, PeerDiscoveredCallback callback);
    void startPublish(const InfoHash& nodeId, NetId network, in_port_t port);

    bool stopDiscovery();
    bool stopPublish();
    void stop();

    void connectivityChanged();
    void stopConnectivityChanged();

private:
    class Impl;
    std::shared_ptr<Impl> impl_;
    std::shared_ptr<asio::io_context> ioContext_;
    std::thread ioRunner_;
};

} // namespace dht