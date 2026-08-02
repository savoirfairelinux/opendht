// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "dns_sd.h"
#include "logger.h"

#include <asio/ip/udp.hpp>
#include <functional>
#include <memory>

namespace asio {
class io_context;
}

namespace dht::mdns {

class MdnsTransport
{
public:
    using ReceiveCallback = std::function<void(const Packet&, const asio::ip::udp::endpoint&)>;

    MdnsTransport(std::shared_ptr<asio::io_context> ioContext, std::shared_ptr<Logger> logger = {});
    ~MdnsTransport();

    void start(ReceiveCallback callback);
    void send(Packet packet);
    void send(Packet packet, const asio::ip::udp::endpoint& destination);
    void sendAndWait(Packet packet);
    void refresh();
    void stop();

    std::vector<dns_sd::AddressData> addresses() const;

private:
    class Impl;
    std::shared_ptr<Impl> impl_;
};

} // namespace dht::mdns