// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "dns_sd.h"

#include "opendht/logger.h"

#include <asio/ip/address.hpp>
#include <asio/ip/udp.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace asio {
class io_context;
}

namespace dht::mdns {

using InterfaceId = uint64_t;

struct InterfaceAddress
{
    InterfaceId id {};
    unsigned index {};
    asio::ip::address address;
    bool multicast {true};
    bool loopback {false};
};

struct NetworkInterface
{
    InterfaceId id {};
    unsigned ipv4Index {};
    unsigned ipv6Index {};
    std::optional<asio::ip::address_v4> ipv4Outbound;
    std::vector<dns_sd::AddressData> addresses;
};

OPENDHT_PUBLIC std::vector<NetworkInterface> groupInterfaces(const std::vector<InterfaceAddress>& addresses);

struct ReceiveContext
{
    asio::ip::udp::endpoint source;
    InterfaceId interface {};
    unsigned ipv6Index {};
};

class MdnsTransport
{
public:
    using ReceiveCallback = std::function<void(const Packet&, const ReceiveContext&)>;

    MdnsTransport(std::shared_ptr<asio::io_context> ioContext, std::shared_ptr<Logger> logger = {});
    ~MdnsTransport();

    void start(ReceiveCallback callback);
    void send(Packet packet);
    void send(Packet packet, InterfaceId interface);
    void send(Packet packet, const asio::ip::udp::endpoint& destination, InterfaceId interface);
    void sendAndWait(Packet packet, InterfaceId interface);
    void refresh();
    void stop();

    std::vector<NetworkInterface> interfaces() const;

private:
    class Impl;
    std::shared_ptr<Impl> impl_;
};

} // namespace dht::mdns