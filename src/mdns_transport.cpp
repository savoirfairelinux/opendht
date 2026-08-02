// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "mdns_transport.h"

#include <asio.hpp>
#include <algorithm>
#include <array>
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

struct Interface
{
    asio::ip::address address;
    unsigned index {};
    bool multicast {true};
    bool loopback {false};
};

std::vector<Interface>
interfaces([[maybe_unused]] asio::io_context& ioContext)
{
    std::vector<Interface> result;
#ifdef _WIN32
    ULONG size = 15000;
    std::vector<uint8_t> buffer(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    auto status = GetAdaptersAddresses(AF_UNSPEC,
                                       GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
                                           | GAA_FLAG_SKIP_DNS_SERVER,
                                       nullptr,
                                       adapters,
                                       &size);
    if (status == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        status = GetAdaptersAddresses(AF_UNSPEC,
                                      GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
                                          | GAA_FLAG_SKIP_DNS_SERVER,
                                      nullptr,
                                      adapters,
                                      &size);
    }
    if (status == NO_ERROR) {
        for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
            if (adapter->OperStatus != IfOperStatusUp)
                continue;
            const auto multicast = not(adapter->Flags & IP_ADAPTER_NO_MULTICAST);
            const auto loopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
            for (auto* current = adapter->FirstUnicastAddress; current; current = current->Next) {
                const auto* socketAddress = current->Address.lpSockaddr;
                if (socketAddress->sa_family == AF_INET) {
                    const auto* address = reinterpret_cast<const sockaddr_in*>(socketAddress);
                    asio::ip::address_v4::bytes_type bytes;
                    std::memcpy(bytes.data(), &address->sin_addr, bytes.size());
                    result.push_back({asio::ip::address_v4(bytes), adapter->IfIndex, multicast, loopback});
                } else if (socketAddress->sa_family == AF_INET6) {
                    const auto* address = reinterpret_cast<const sockaddr_in6*>(socketAddress);
                    asio::ip::address_v6::bytes_type bytes;
                    std::memcpy(bytes.data(), &address->sin6_addr, bytes.size());
                    result.push_back(
                        {asio::ip::address_v6(bytes, address->sin6_scope_id), adapter->Ipv6IfIndex, multicast, loopback});
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
            result.push_back({asio::ip::address_v4(bytes),
                              if_nametoindex(current->ifa_name),
                              bool(current->ifa_flags & IFF_MULTICAST),
                              bool(current->ifa_flags & IFF_LOOPBACK)});
        } else if (family == AF_INET6) {
            const auto* address = reinterpret_cast<const sockaddr_in6*>(current->ifa_addr);
            asio::ip::address_v6::bytes_type bytes;
            std::memcpy(bytes.data(), &address->sin6_addr, bytes.size());
            result.push_back({asio::ip::address_v6(bytes, address->sin6_scope_id),
                              if_nametoindex(current->ifa_name),
                              bool(current->ifa_flags & IFF_MULTICAST),
                              bool(current->ifa_flags & IFF_LOOPBACK)});
        }
    }
    freeifaddrs(addresses);
#endif
    result.erase(std::remove_if(result.begin(), result.end(), [](const Interface& interface) {
                     return interface.address.is_unspecified() or interface.address.is_multicast();
                 }),
                 result.end());
    std::stable_sort(result.begin(), result.end(), [](const Interface& lhs, const Interface& rhs) {
        return lhs.loopback < rhs.loopback;
    });
    return result;
}

} // namespace

class MdnsTransport::Impl : public std::enable_shared_from_this<MdnsTransport::Impl>
{
public:
    Impl(std::shared_ptr<asio::io_context> ioContext, std::shared_ptr<Logger> logger)
        : ioContext_(std::move(ioContext))
        , logger_(std::move(logger))
        , interfaces_(interfaces(*ioContext_))
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
    };

    void start(ReceiveCallback callback)
    {
        callback_ = std::move(callback);
        configure();
    }

    void send(Packet packet)
    {
        send(std::move(packet), {});
    }

    void send(Packet packet, std::optional<asio::ip::udp::endpoint> destination)
    {
        auto sharedPacket = std::make_shared<Packet>(std::move(packet));
        asio::post(*ioContext_, [weak = weak_from_this(), sharedPacket, destination] {
            const auto self = weak.lock();
            if (not self)
                return;
            for (const auto& state : self->sockets_) {
                const auto target = destination.value_or(state->multicast);
                if (target.address().is_v4() != state->multicast.address().is_v4())
                    continue;
                state->socket.async_send_to(
                    asio::buffer(*sharedPacket),
                    target,
                    [logger = self->logger_, sharedPacket](const asio::error_code& error, size_t) {
                        if (error and error != asio::error::operation_aborted and logger)
                            logger->warn("Unable to send mDNS packet: {}", error.message());
                    });
            }
        });
    }

    void sendAndWait(Packet packet)
    {
        if (ioContext_->get_executor().running_in_this_thread()) {
            sendNow(packet);
            return;
        }
        auto completed = std::make_shared<std::promise<void>>();
        auto future = completed->get_future();
        asio::post(*ioContext_, [weak = weak_from_this(), packet = std::move(packet), completed] {
            if (const auto self = weak.lock())
                self->sendNow(packet);
            completed->set_value();
        });
        future.wait_for(std::chrono::milliseconds(250));
    }

    void refresh()
    {
        {
            std::lock_guard lock(interfacesMutex_);
            interfaces_ = interfaces(*ioContext_);
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

    std::vector<dns_sd::AddressData> addresses() const
    {
        std::lock_guard lock(interfacesMutex_);
        std::vector<dns_sd::AddressData> result;
        const auto hasNonLoopback = std::any_of(interfaces_.begin(), interfaces_.end(), [](const Interface& interface) {
            return not interface.loopback;
        });
        for (const auto& interface : interfaces_) {
            if (hasNonLoopback and interface.loopback)
                continue;
            if (interface.address.is_v4()) {
                result.emplace_back(AData {interface.address.to_v4().to_bytes()});
            } else {
                const auto bytes = interface.address.to_v6().to_bytes();
                const auto mapped = std::all_of(bytes.begin(), bytes.begin() + 10, [](uint8_t byte) {
                    return byte == 0;
                }) and bytes[10] == 0xff and bytes[11] == 0xff;
                if (not mapped)
                    result.emplace_back(AaaaData {bytes});
            }
        }
        return result;
    }

private:
    void sendNow(const Packet& packet)
    {
        for (const auto& state : sockets_) {
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
        configure(asio::ip::udp::v4(), asio::ip::make_address(MDNS_IPV4));
        configure(asio::ip::udp::v6(), asio::ip::make_address(MDNS_IPV6));
    }

    void configure(asio::ip::udp protocol, const asio::ip::address& multicast)
    {
        auto state = std::make_shared<Socket>(*ioContext_);
        asio::error_code error;
        state->socket.open(protocol, error);
        if (error)
            return logSocketError(protocol, error);
        state->socket.set_option(asio::ip::udp::socket::reuse_address(true), error);
        if (protocol == asio::ip::udp::v6())
            state->socket.set_option(asio::ip::v6_only(true), error);
        state->socket.bind({protocol, MDNS_PORT}, error);
        if (error)
            return logSocketError(protocol, error);
        state->socket.set_option(asio::ip::multicast::hops(255), error);
        if (error)
            return logSocketError(protocol, error);
        state->socket.set_option(asio::ip::multicast::enable_loopback(true), error);

        std::vector<Interface> currentInterfaces;
        {
            std::lock_guard lock(interfacesMutex_);
            currentInterfaces = interfaces_;
        }
        size_t joined = 0;
        for (const auto& interface : currentInterfaces) {
            if (not interface.multicast or interface.address.is_v4() != (protocol == asio::ip::udp::v4()))
                continue;
            if (protocol == asio::ip::udp::v4())
                state->socket.set_option(asio::ip::multicast::join_group(multicast.to_v4(),
                                                                         interface.address.to_v4()),
                                         error);
            else
                state->socket.set_option(asio::ip::multicast::join_group(multicast.to_v6(), interface.index), error);
            if (not error)
                joined++;
        }
        if (joined == 0) {
            state->socket.set_option(asio::ip::multicast::join_group(multicast), error);
            if (error)
                return logSocketError(protocol, error);
        }

        const auto outbound = std::find_if(currentInterfaces.begin(), currentInterfaces.end(), [&](const Interface& interface) {
            return interface.multicast and not interface.loopback
                and interface.address.is_v4() == (protocol == asio::ip::udp::v4());
        });
        if (outbound != currentInterfaces.end()) {
            if (protocol == asio::ip::udp::v4())
                state->socket.set_option(asio::ip::multicast::outbound_interface(outbound->address.to_v4()), error);
            else
                state->socket.set_option(asio::ip::multicast::outbound_interface(outbound->index), error);
        }
        state->multicast = {multicast, MDNS_PORT};
        sockets_.push_back(state);
        receive(state);
    }

    void receive(const std::shared_ptr<Socket>& state)
    {
        state->socket.async_receive_from(
            asio::buffer(state->receiveBuffer),
            state->sender,
            [weak = weak_from_this(), state](const asio::error_code& error, size_t size) {
                const auto self = weak.lock();
                if (not self)
                    return;
                if (not error and self->callback_) {
                    Packet packet(state->receiveBuffer.begin(), state->receiveBuffer.begin() + size);
                    self->callback_(packet, state->sender);
                } else if (error != asio::error::operation_aborted and self->logger_) {
                    self->logger_->warn("Unable to receive mDNS packet: {}", error.message());
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
    std::vector<Interface> interfaces_;
    std::vector<std::shared_ptr<Socket>> sockets_;
    ReceiveCallback callback_;
};

MdnsTransport::MdnsTransport(std::shared_ptr<asio::io_context> ioContext, std::shared_ptr<Logger> logger)
    : impl_(std::make_shared<Impl>(std::move(ioContext), std::move(logger)))
{}

MdnsTransport::~MdnsTransport()
= default;

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
MdnsTransport::send(Packet packet, const asio::ip::udp::endpoint& destination)
{
    impl_->send(std::move(packet), destination);
}

void
MdnsTransport::sendAndWait(Packet packet)
{
    impl_->sendAndWait(std::move(packet));
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

std::vector<dns_sd::AddressData>
MdnsTransport::addresses() const
{
    return impl_->addresses();
}

} // namespace dht::mdns