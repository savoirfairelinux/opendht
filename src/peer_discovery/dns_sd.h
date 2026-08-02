// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "mdns.h"

#include "opendht/infohash.h"
#include "opendht/utils.h"

#include <chrono>
#include <functional>
#include <memory>
#include <optional>

namespace dht::mdns::dns_sd {

constexpr uint32_t HOST_RECORD_TTL = 120;
constexpr uint32_t SERVICE_RECORD_TTL = 4500;

using AddressData = std::variant<AData, AaaaData>;

struct Service
{
    InfoHash nodeId;
    NetId network {};
    in_port_t port {};
    std::vector<AddressData> addresses;
};

class OPENDHT_PUBLIC Cache
{
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;

    explicit Cache(Now now = [] { return Clock::now(); });
    ~Cache();

    Cache(Cache&&) noexcept;
    Cache& operator=(Cache&&) noexcept;

    std::vector<Service> update(const Message& message);
    std::vector<Service> services();
    void clear();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

OPENDHT_PUBLIC Name serviceName();
OPENDHT_PUBLIC Name instanceName(const InfoHash& nodeId);
OPENDHT_PUBLIC Name hostName(const InfoHash& nodeId);

OPENDHT_PUBLIC Message announcement(const Service& service);
OPENDHT_PUBLIC Message goodbye(const Service& service);
OPENDHT_PUBLIC Message browseQuery();
OPENDHT_PUBLIC std::optional<Message> respond(const Message& query, const Service& service);
OPENDHT_PUBLIC std::optional<Service> resolve(const Message& message);

} // namespace dht::mdns::dns_sd