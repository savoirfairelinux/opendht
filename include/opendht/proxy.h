// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include <chrono>

namespace dht {
namespace proxy {

constexpr const std::chrono::hours OP_TIMEOUT {24}; // one day
constexpr const std::chrono::hours OP_MARGIN {8};   // eight hours

/**
 * Deadline for a subscribe request to complete. Unlike a listen, a subscribe is a short
 * request: the server answers immediately and the device then relies on push notifications.
 * Nothing else observes it, so without a deadline a subscribe stalled in name resolution,
 * connection or TLS handshake would never complete nor fail.
 */
constexpr const std::chrono::seconds SUBSCRIBE_TIMEOUT {20};

using ListenToken = uint64_t;

} // namespace proxy
} // namespace dht
