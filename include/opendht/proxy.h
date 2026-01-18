// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include <chrono>

namespace dht {
namespace proxy {

constexpr const std::chrono::hours OP_TIMEOUT {24}; // one day
constexpr const std::chrono::hours OP_MARGIN {2};   // two hours

using ListenToken = uint64_t;

} // namespace proxy
} // namespace dht
