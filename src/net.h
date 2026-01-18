// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

namespace dht {
namespace net {

enum class MessageType {
    Error = 0,
    Reply,
    Ping,
    FindNode,
    GetValues,
    AnnounceValue,
    Refresh,
    Listen,
    ValueData,
    ValueUpdate,
    UpdateValue
};

} /* namespace net */
} // namespace dht
