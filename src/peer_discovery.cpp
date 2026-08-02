// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "peer_discovery.h"

#include "dns_sd.h"
#include "mdns_transport.h"

#include <asio.hpp>
#include <chrono>
#include <cstring>
#include <mutex>
#include <optional>
#include <random>

namespace dht {
namespace {

constexpr auto BROWSE_INTERVAL = std::chrono::seconds(60);
constexpr auto CONNECTIVITY_RETRY = std::chrono::seconds(10);
constexpr auto CONNECTIVITY_RETRY_MAX = std::chrono::minutes(1);

SockAddr
socketAddress(const mdns::dns_sd::AddressData& data,
              in_port_t port,
              const asio::ip::udp::endpoint& source)
{
    SockAddr address;
    std::visit(
        [&](const auto& record) {
            using Record = std::decay_t<decltype(record)>;
            if constexpr (std::is_same_v<Record, mdns::AData>) {
                address.setFamily(AF_INET);
                std::memcpy(&address.getIPv4().sin_addr, record.address.data(), record.address.size());
            } else {
                address.setFamily(AF_INET6);
                std::memcpy(&address.getIPv6().sin6_addr, record.address.data(), record.address.size());
                const asio::ip::address_v6 parsed(record.address);
                if (parsed.is_link_local() and source.address().is_v6())
                    address.getIPv6().sin6_scope_id = source.address().to_v6().scope_id();
            }
        },
        data);
    address.setPort(port);
    return address;
}

bool
isGoodbye(const mdns::Message& message)
{
    return std::any_of(message.answers.begin(), message.answers.end(), [](const mdns::ResourceRecord& record) {
        return record.type == mdns::Type::PTR and record.name == mdns::dns_sd::serviceName() and record.ttl == 0;
    });
}

} // namespace

class PeerDiscovery::Impl : public std::enable_shared_from_this<PeerDiscovery::Impl>
{
public:
    Impl(std::shared_ptr<asio::io_context> ioContext, std::shared_ptr<Logger> logger)
        : ioContext_(std::move(ioContext))
        , logger_(std::move(logger))
        , transport_(ioContext_, logger_)
        , browseTimer_(*ioContext_)
        , announceTimer_(*ioContext_)
        , connectivityTimer_(*ioContext_)
    {}

    void start()
    {
        transport_.start([weak = weak_from_this()](const mdns::Packet& packet,
                                                   const asio::ip::udp::endpoint& source) {
            if (const auto self = weak.lock())
                self->receive(packet, source);
        });
    }

    void startDiscovery(NetId network, PeerDiscoveredCallback callback)
    {
        {
            std::lock_guard lock(mutex_);
            discoveryNetwork_ = network;
            discoveryCallback_ = std::move(callback);
        }
        asio::post(*ioContext_, [weak = weak_from_this()] {
            if (const auto self = weak.lock())
                self->browse();
        });
    }

    void startPublish(const InfoHash& nodeId, NetId network, in_port_t port)
    {
        mdns::dns_sd::Service service {nodeId, network, port, transport_.addresses()};
        const auto message = mdns::dns_sd::announcement(service);
        {
            std::lock_guard lock(mutex_);
            published_ = std::move(service);
        }
        transport_.send(mdns::encode(message));
        asio::post(*ioContext_, [weak = weak_from_this()] {
            const auto self = weak.lock();
            if (not self)
                return;
            self->announceTimer_.expires_after(std::chrono::seconds(1));
            self->announceTimer_.async_wait([weak](const asio::error_code& error) {
                if (not error) {
                    if (const auto locked = weak.lock())
                        locked->announce();
                }
            });
        });
    }

    bool stopDiscovery()
    {
        std::lock_guard lock(mutex_);
        const auto stopped = bool(discoveryCallback_);
        discoveryCallback_ = {};
        discoveryNetwork_.reset();
        asio::post(*ioContext_, [weak = weak_from_this()] {
            if (const auto self = weak.lock())
                self->browseTimer_.cancel();
        });
        return stopped;
    }

    bool stopPublish()
    {
        std::optional<mdns::dns_sd::Service> service;
        {
            std::lock_guard lock(mutex_);
            service = std::exchange(published_, {});
        }
        asio::post(*ioContext_, [weak = weak_from_this()] {
            if (const auto self = weak.lock())
                self->announceTimer_.cancel();
        });
        if (service)
            transport_.send(mdns::encode(mdns::dns_sd::goodbye(*service)));
        return bool(service);
    }

    void stop()
    {
        stopConnectivityChanged();
        stopDiscovery();
        std::optional<mdns::dns_sd::Service> service;
        {
            std::lock_guard lock(mutex_);
            service = std::exchange(published_, {});
        }
        asio::post(*ioContext_, [weak = weak_from_this()] {
            if (const auto self = weak.lock())
                self->announceTimer_.cancel();
        });
        if (service)
            transport_.sendAndWait(mdns::encode(mdns::dns_sd::goodbye(*service)));
        transport_.stop();
    }

    void connectivityChanged()
    {
        asio::post(*ioContext_, [weak = weak_from_this()] {
            if (const auto self = weak.lock())
                self->handleConnectivityChanged();
        });
    }

    void stopConnectivityChanged()
    {
        asio::post(*ioContext_, [weak = weak_from_this()] {
            if (const auto self = weak.lock()) {
                self->connectivityTimer_.cancel();
                self->connectivityRetry_ = CONNECTIVITY_RETRY;
            }
        });
    }

private:
    void handleConnectivityChanged()
    {
        transport_.refresh();
        refreshPublication();
        browse();

        connectivityTimer_.expires_after(connectivityRetry_);
        connectivityTimer_.async_wait([weak = weak_from_this()](const asio::error_code& error) {
            if (not error) {
                if (const auto self = weak.lock())
                    self->handleConnectivityChanged();
            }
        });
        connectivityRetry_ = std::min(
            connectivityRetry_ * 2,
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(CONNECTIVITY_RETRY_MAX));
    }

    void browse()
    {
        bool active;
        {
            std::lock_guard lock(mutex_);
            active = bool(discoveryCallback_);
        }
        if (not active)
            return;
        transport_.send(mdns::encode(mdns::dns_sd::browseQuery()));
        browseTimer_.expires_after(BROWSE_INTERVAL);
        browseTimer_.async_wait([weak = weak_from_this()](const asio::error_code& error) {
            if (not error) {
                if (const auto self = weak.lock())
                    self->browse();
            }
        });
    }

    void announce()
    {
        std::optional<mdns::dns_sd::Service> service;
        {
            std::lock_guard lock(mutex_);
            service = published_;
        }
        if (service)
            transport_.send(mdns::encode(mdns::dns_sd::announcement(*service)));
    }

    void refreshPublication()
    {
        std::optional<mdns::dns_sd::Service> service;
        {
            std::lock_guard lock(mutex_);
            if (published_) {
                published_->addresses = transport_.addresses();
                service = published_;
            }
        }
        if (service)
            transport_.send(mdns::encode(mdns::dns_sd::announcement(*service)));
    }

    void receive(const mdns::Packet& packet, const asio::ip::udp::endpoint& source)
    {
        try {
            const auto message = mdns::decode(packet.data(), packet.size());
            if (message.response)
                discover(message, source);
            else
                answer(message, source);
        } catch (const std::exception& error) {
            if (logger_)
                logger_->warn("Ignoring invalid mDNS packet: {}", error.what());
        }
    }

    void answer(const mdns::Message& query, const asio::ip::udp::endpoint& source)
    {
        std::optional<mdns::dns_sd::Service> service;
        {
            std::lock_guard lock(mutex_);
            service = published_;
        }
        if (service) {
            if (auto response = mdns::dns_sd::respond(query, *service)) {
                const auto unicast = source.port() != 5353
                    or std::any_of(query.questions.begin(), query.questions.end(), [](const mdns::Question& question) {
                           return question.unicastResponse;
                       });
                if (source.port() != 5353)
                    response->questions = query.questions;
                auto packet = mdns::encode(*response);
                const auto sharedAnswer = std::any_of(
                    response->answers.begin(), response->answers.end(), [](const mdns::ResourceRecord& record) {
                        return not record.cacheFlush;
                    });
                if (not sharedAnswer) {
                    if (unicast)
                        transport_.send(std::move(packet), source);
                    else
                        transport_.send(std::move(packet));
                    return;
                }

                static thread_local std::mt19937 random {std::random_device {}()};
                const auto delay = std::chrono::milliseconds(std::uniform_int_distribution<int> {20, 120}(random));
                auto timer = std::make_shared<asio::steady_timer>(*ioContext_, delay);
                timer->async_wait([weak = weak_from_this(), timer, packet = std::move(packet), source, unicast](
                                      const asio::error_code& error) mutable {
                    if (error)
                        return;
                    const auto self = weak.lock();
                    if (not self)
                        return;
                    if (unicast)
                        self->transport_.send(std::move(packet), source);
                    else
                        self->transport_.send(std::move(packet));
                });
            }
        }
    }

    void discover(const mdns::Message& message, const asio::ip::udp::endpoint& source)
    {
        if (isGoodbye(message))
            return;
        const auto service = mdns::dns_sd::resolve(message);
        if (not service)
            return;

        PeerDiscoveredCallback callback;
        std::optional<NetId> network;
        std::optional<InfoHash> localNode;
        {
            std::lock_guard lock(mutex_);
            callback = discoveryCallback_;
            network = discoveryNetwork_;
            if (published_)
                localNode = published_->nodeId;
        }
        if (not callback or not network or service->network != *network
            or (localNode and service->nodeId == *localNode))
            return;

        for (const auto& address : service->addresses)
            callback(service->nodeId, socketAddress(address, service->port, source));
    }

    std::shared_ptr<asio::io_context> ioContext_;
    std::shared_ptr<Logger> logger_;
    mdns::MdnsTransport transport_;
    asio::steady_timer browseTimer_;
    asio::steady_timer announceTimer_;
    asio::steady_timer connectivityTimer_;
    std::chrono::steady_clock::duration connectivityRetry_ {CONNECTIVITY_RETRY};
    std::mutex mutex_;
    std::optional<NetId> discoveryNetwork_;
    PeerDiscoveredCallback discoveryCallback_;
    std::optional<mdns::dns_sd::Service> published_;
};

PeerDiscovery::PeerDiscovery(std::shared_ptr<asio::io_context> ioContext, std::shared_ptr<Logger> logger)
{
    if (not ioContext) {
        ioContext = std::make_shared<asio::io_context>();
        ioContext_ = ioContext;
    }
    impl_ = std::make_shared<Impl>(ioContext, logger);
    impl_->start();

    if (ioContext_) {
        ioRunner_ = std::thread([logger = std::move(logger), ioContext = std::move(ioContext)] {
            try {
                auto work = asio::make_work_guard(*ioContext);
                ioContext->run();
            } catch (const std::exception& error) {
                if (logger)
                    logger->error("Peer discovery event loop failed: {}", error.what());
            }
        });
    }
}

PeerDiscovery::~PeerDiscovery()
{
    stop();
    impl_.reset();
    if (ioContext_)
        ioContext_->stop();
    if (ioRunner_.joinable())
        ioRunner_.join();
}

void
PeerDiscovery::startDiscovery(NetId network, PeerDiscoveredCallback callback)
{
    impl_->startDiscovery(network, std::move(callback));
}

void
PeerDiscovery::startPublish(const InfoHash& nodeId, NetId network, in_port_t port)
{
    impl_->startPublish(nodeId, network, port);
}

bool
PeerDiscovery::stopDiscovery()
{
    return impl_->stopDiscovery();
}

bool
PeerDiscovery::stopPublish()
{
    return impl_->stopPublish();
}

void
PeerDiscovery::stop()
{
    if (impl_)
        impl_->stop();
}

void
PeerDiscovery::connectivityChanged()
{
    impl_->connectivityChanged();
}

void
PeerDiscovery::stopConnectivityChanged()
{
    impl_->stopConnectivityChanged();
}

} // namespace dht