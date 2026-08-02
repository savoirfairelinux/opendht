// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "mdns.h"

#include "opendht/infohash.h"
#include "opendht/utils.h"

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

OPENDHT_PUBLIC Name serviceName();
OPENDHT_PUBLIC Name instanceName(const InfoHash& nodeId);
OPENDHT_PUBLIC Name hostName(const InfoHash& nodeId);

OPENDHT_PUBLIC Message announcement(const Service& service);
OPENDHT_PUBLIC Message goodbye(const Service& service);
OPENDHT_PUBLIC std::optional<Service> resolve(const Message& message);

} // namespace dht::mdns::dns_sd