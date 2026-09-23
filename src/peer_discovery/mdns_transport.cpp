// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "mdns_transport.h"

#include <asio.hpp>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <future>
#include <mutex>

#ifdef _WIN32
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#endif

namespace dht::mdns {
namespace {

constexpr in_port_t MDNS_PORT = 5353;
constexpr std::string_view MDNS_IPV4 = "224.0.0.251";
constexpr std::string_view MDNS_IPV6 = "ff02::fb";

std::vector<InterfaceAddress>
interfaceAddresses([[maybe_unused]] asio::io_context& ioContext)
{
    std::vector<InterfaceAddress> result;
#ifdef _WIN32
    ULONG size = 15000;
    std::vector<uint8_t> buffer(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    auto status = GetAdaptersAddresses(AF_UNSPEC,
                                       GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                       nullptr,
                                       adapters,
                                       &size);
    if (status == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        status = GetAdaptersAddresses(AF_UNSPEC,
                                      GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                      nullptr,
                                      adapters,
                                      &size);
    }
    if (status == NO_ERROR) {
        InterfaceId id = 0;
        for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
            if (adapter->OperStatus != IfOperStatusUp)
                continue;
            ++id;
            const auto multicast = not(adapter->Flags & IP_ADAPTER_NO_MULTICAST);
            const auto loopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
            for (auto* current = adapter->FirstUnicastAddress; current; current = current->Next) {
                const auto* socketAddress = current->Address.lpSockaddr;
                if (socketAddress->sa_family == AF_INET) {
                    const auto* address = reinterpret_cast<const sockaddr_in*>(socketAddress);
                    asio::ip::address_v4::bytes_type bytes;
                    std::memcpy(bytes.data(), &address->sin_addr, bytes.size());
                    result.push_back({id, adapter->IfIndex, asio::ip::address_v4(bytes), multicast, loopback});
                } else if (socketAddress->sa_family == AF_INET6) {
                    const auto* address = reinterpret_cast<const sockaddr_in6*>(socketAddress);
                    asio::ip::address_v6::bytes_type bytes;
                    std::memcpy(bytes.data(), &address->sin6_addr, bytes.size());
                    result.push_back({id,
                                      adapter->Ipv6IfIndex,
                                      asio::ip::address_v6(bytes, address->sin6_scope_id),
                                      multicast,
                                      loopback});
                }
            }
        }
    }
#else
    ifaddrs* addresses = nullptr;
    if (getifaddrs(&addresses) != 0)
        return result;
    for (auto* current = addresses; current; current = current->ifa_next) {
        if (not current->ifa_addr or not(current->ifa_flags & IFF_UP))
            continue;
        const auto family = current->ifa_addr->sa_family;
        if (family == AF_INET) {
            const auto* address = reinterpret_cast<const sockaddr_in*>(current->ifa_addr);
            asio::ip::address_v4::bytes_type bytes;
            std::memcpy(bytes.data(), &address->sin_addr, bytes.size());
            const auto index = if_nametoindex(current->ifa_name);
            result.push_back({index,
                              index,
                              asio::ip::address_v4(bytes),
                              bool(current->ifa_flags & IFF_MULTICAST),
                              bool(current->ifa_flags & IFF_LOOPBACK)});
        } else if (family == AF_INET6) {
            const auto* address = reinterpret_cast<const sockaddr_in6*>(current->ifa_addr);
            asio::ip::address_v6::bytes_type bytes;
            std::memcpy(bytes.data(), &address->sin6_addr, bytes.size());
            const auto index = if_nametoindex(current->ifa_name);
            result.push_back({index,
                              index,
                              asio::ip::address_v6(bytes, address->sin6_scope_id),
                              bool(current->ifa_flags & IFF_MULTICAST),
                              bool(current->ifa_flags & IFF_LOOPBACK)});
        }
    }
    freeifaddrs(addresses);
#endif
    return result;
}

} // namespace

std::vector<NetworkInterface>
groupInterfaces(const std::vector<InterfaceAddress>& addresses)
{
    std::vector<NetworkInterface> result;
    const auto hasNonLoopback = std::any_of(addresses.begin(), addresses.end(), [](const InterfaceAddress& address) {
        return address.multicast and not address.loopback and not address.address.is_unspecified()
               and not address.address.is_multicast();
    });

    for (const auto& address : addresses) {
        if (address.id == 0 or not address.multicast or (hasNonLoopback and address.loopback)
            or address.address.is_unspecified() or address.address.is_multicast())
            continue;

        auto scope = std::find_if(result.begin(), result.end(), [&](const NetworkInterface& interface) {
            return interface.id == address.id;
        });
        if (scope == result.end()) {
            NetworkInterface interface;
            interface.id = address.id;
            result.push_back(std::move(interface));
            scope = std::prev(result.end());
        }

        dns_sd::AddressData record;
        if (address.address.is_v4()) {
            scope->ipv4Index = address.index;
            if (not scope->ipv4Outbound)
                scope->ipv4Outbound = address.address.to_v4();
            record = AData {address.address.to_v4().to_bytes()};
        } else {
            const auto bytes = address.address.to_v6().to_bytes();
            const auto mapped = std::all_of(bytes.begin(), bytes.begin() + 10, [](uint8_t byte) { return byte == 0; })
                                and bytes[10] == 0xff and bytes[11] == 0xff;
            if (mapped)
                continue;
            scope->ipv6Index = address.index;
            record = AaaaData {bytes};
        }
        if (std::find(scope->addresses.begin(), scope->addresses.end(), record) == scope->addresses.end())
            scope->addresses.emplace_back(std::move(record));
    }
    result.erase(std::remove_if(result.begin(),
                                result.end(),
                                [](const NetworkInterface& interface) { return interface.addresses.empty(); }),
                 result.end());
    return result;
}

class MdnsTransport::Impl : public std::enable_shared_from_this<MdnsTransport::Impl>
{
public:
    Impl(std::shared_ptr<asio::io_context> ioContext, std::shared_ptr<Logger> logger)
        : ioContext_(std::move(ioContext))
        , logger_(std::move(logger))
        , interfaces_(groupInterfaces(interfaceAddresses(*ioContext_)))
    {}

    struct Socket
    {
        explicit Socket(asio::io_context& ioContext)
            : socket(ioContext)
        {}

        asio::ip::udp::socket socket;
        std::array<uint8_t, MAX_PACKET_SIZE> receiveBuffer {};
        asio::ip::udp::endpoint sender;
        asio::ip::udp::endpoint multicast;
        InterfaceId interface {};
        unsigned ipv6Index {};
    };

    void start(ReceiveCallback callback)
    {
        callback_ = std::move(callback);
        configure();
    }

    void send(Packet packet) { send(std::move(packet), {}, {}); }

    void send(Packet packet, std::optional<asio::ip::udp::endpoint> destination, std::optional<InterfaceId> interface)
    {
        auto sharedPacket = std::make_shared<Packet>(std::move(packet));
        asio::post(*ioContext_, [weak = weak_from_this(), sharedPacket, destination, interface] {
            const auto self = weak.lock();
            if (not self)
                return;
            for (const auto& state : self->sockets_) {
                if (interface and state->interface != *interface)
                    continue;
                const auto target = destination.value_or(state->multicast);
                if (target.address().is_v4() != state->multicast.address().is_v4())
                    continue;
                state->socket.async_send_to(asio::buffer(*sharedPacket),
                                            target,
                                            [logger = self->logger_, sharedPacket](const asio::error_code& error,
                                                                                   size_t) {
                                                if (error and error != asio::error::operation_aborted and logger)
                                                    logger->warn("Unable to send mDNS packet: {}", error.message());
                                            });
            }
        });
    }

    void sendAndWait(Packet packet, InterfaceId interface)
    {
        if (ioContext_->get_executor().running_in_this_thread()) {
            sendNow(packet, interface);
            return;
        }
        auto completed = std::make_shared<std::promise<void>>();
        auto future = completed->get_future();
        asio::post(*ioContext_, [weak = weak_from_this(), packet = std::move(packet), interface, completed] {
            if (const auto self = weak.lock())
                self->sendNow(packet, interface);
            completed->set_value();
        });
        future.wait_for(std::chrono::milliseconds(250));
    }

    void refresh()
    {
        {
            std::lock_guard lock(interfacesMutex_);
            interfaces_ = groupInterfaces(interfaceAddresses(*ioContext_));
        }
        asio::post(*ioContext_, [weak = weak_from_this()] {
            if (const auto self = weak.lock())
                self->configure();
        });
    }

    void stop()
    {
        if (ioContext_->get_executor().running_in_this_thread()) {
            stopNow();
            return;
        }
        auto completed = std::make_shared<std::promise<void>>();
        auto future = completed->get_future();
        asio::post(*ioContext_, [weak = weak_from_this(), completed] {
            if (const auto self = weak.lock())
                self->stopNow();
            completed->set_value();
        });
        future.wait_for(std::chrono::milliseconds(250));
    }

    std::vector<NetworkInterface> interfaces() const
    {
        std::lock_guard lock(interfacesMutex_);
        return interfaces_;
    }

private:
    void sendNow(const Packet& packet, InterfaceId interface)
    {
        for (const auto& state : sockets_) {
            if (state->interface != interface)
                continue;
            asio::error_code error;
            state->socket.send_to(asio::buffer(packet), state->multicast, 0, error);
            if (error and logger_)
                logger_->warn("Unable to send final mDNS packet: {}", error.message());
        }
    }

    void stopNow()
    {
        callback_ = {};
        stopSockets();
    }

    void configure()
    {
        stopSockets();
        std::vector<NetworkInterface> currentInterfaces;
        {
            std::lock_guard lock(interfacesMutex_);
            currentInterfaces = interfaces_;
        }
        for (const auto& interface : currentInterfaces) {
            if (interface.ipv4Outbound)
                configure(interface, asio::ip::udp::v4(), asio::ip::make_address(MDNS_IPV4));
            if (interface.ipv6Index)
                configure(interface, asio::ip::udp::v6(), asio::ip::make_address(MDNS_IPV6));
        }
    }

    void configure(const NetworkInterface& interface, asio::ip::udp protocol, const asio::ip::address& multicast)
    {
        auto state = std::make_shared<Socket>(*ioContext_);
        asio::error_code error;
        state->socket.open(protocol, error);
        if (error)
            return logSocketError(protocol, error);
        state->socket.set_option(asio::ip::udp::socket::reuse_address(true), error);
#if defined(SO_REUSEPORT) && !defined(_WIN32)
        if (not error) {
            const int enabled = 1;
            if (::setsockopt(state->socket.native_handle(), SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)) != 0)
                error.assign(errno, asio::error::get_system_category());
        }
#endif
        if (error)
            return logSocketError(protocol, error);
        if (protocol == asio::ip::udp::v6())
            state->socket.set_option(asio::ip::v6_only(true), error);
        state->socket.bind({protocol, MDNS_PORT}, error);
        if (error)
            return logSocketError(protocol, error);
        state->socket.set_option(asio::ip::multicast::hops(255), error);
        if (error)
            return logSocketError(protocol, error);
        state->socket.set_option(asio::ip::multicast::enable_loopback(true), error);
        if (protocol == asio::ip::udp::v4()) {
            state->socket.set_option(asio::ip::multicast::join_group(multicast.to_v4(), *interface.ipv4Outbound), error);
            if (not error)
                state->socket.set_option(asio::ip::multicast::outbound_interface(*interface.ipv4Outbound), error);
        } else {
            state->socket.set_option(asio::ip::multicast::join_group(multicast.to_v6(), interface.ipv6Index), error);
            if (not error)
                state->socket.set_option(asio::ip::multicast::outbound_interface(interface.ipv6Index), error);
        }
        if (error)
            return logSocketError(protocol, error);

        if (protocol == asio::ip::udp::v6())
            state->multicast = {asio::ip::address_v6(multicast.to_v6().to_bytes(), interface.ipv6Index), MDNS_PORT};
        else
            state->multicast = {multicast, MDNS_PORT};
        state->interface = interface.id;
        state->ipv6Index = interface.ipv6Index;
        sockets_.push_back(state);
        receive(state);
    }

    void receive(const std::shared_ptr<Socket>& state)
    {
        state->socket.async_receive_from(asio::buffer(state->receiveBuffer),
                                         state->sender,
                                         [weak = weak_from_this(), state](const asio::error_code& error, size_t size) {
                                             const auto self = weak.lock();
                                             if (not self)
                                                 return;
                                             if (not error and self->callback_) {
                                                 Packet packet(state->receiveBuffer.begin(),
                                                               state->receiveBuffer.begin() + size);
                                                 self->callback_(packet,
                                                                 {state->sender, state->interface, state->ipv6Index});
                                             } else if (error != asio::error::operation_aborted and self->logger_) {
                                                 self->logger_->warn("Unable to receive mDNS packet: {}",
                                                                     error.message());
                                             }
                                             if (state->socket.is_open())
                                                 self->receive(state);
                                         });
    }

    void stopSockets()
    {
        for (const auto& state : sockets_) {
            asio::error_code error;
            state->socket.cancel(error);
            state->socket.close(error);
        }
        sockets_.clear();
    }

    void logSocketError(asio::ip::udp protocol, const asio::error_code& error)
    {
        if (logger_)
            logger_->warn("Unable to start {} mDNS transport: {}",
                          protocol == asio::ip::udp::v4() ? "IPv4" : "IPv6",
                          error.message());
    }

    std::shared_ptr<asio::io_context> ioContext_;
    std::shared_ptr<Logger> logger_;
    mutable std::mutex interfacesMutex_;
    std::vector<NetworkInterface> interfaces_;
    std::vector<std::shared_ptr<Socket>> sockets_;
    ReceiveCallback callback_;
};

MdnsTransport::MdnsTransport(std::shared_ptr<asio::io_context> ioContext, std::shared_ptr<Logger> logger)
    : impl_(std::make_shared<Impl>(std::move(ioContext), std::move(logger)))
{}

MdnsTransport::~MdnsTransport() = default;

void
MdnsTransport::start(ReceiveCallback callback)
{
    impl_->start(std::move(callback));
}

void
MdnsTransport::send(Packet packet)
{
    impl_->send(std::move(packet));
}

void
MdnsTransport::send(Packet packet, InterfaceId interface)
{
    impl_->send(std::move(packet), {}, interface);
}

void
MdnsTransport::send(Packet packet, const asio::ip::udp::endpoint& destination, InterfaceId interface)
{
    impl_->send(std::move(packet), destination, interface);
}

void
MdnsTransport::sendAndWait(Packet packet, InterfaceId interface)
{
    impl_->sendAndWait(std::move(packet), interface);
}

void
MdnsTransport::refresh()
{
    impl_->refresh();
}

void
MdnsTransport::stop()
{
    if (impl_)
        impl_->stop();
}

std::vector<NetworkInterface>
MdnsTransport::interfaces() const
{
    return impl_->interfaces();
}

} // namespace dht::mdns