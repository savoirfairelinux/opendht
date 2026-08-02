// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#if __has_include("def.h")
#include "def.h"
#else
#include "opendht/def.h"
#endif

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace dht::mdns {

constexpr size_t MAX_PACKET_SIZE = 9000;
constexpr size_t MAX_RECORD_COUNT = 1024;
constexpr uint16_t CLASS_IN = 1;
constexpr uint16_t CLASS_ANY = 255;

enum class Type : uint16_t {
    A = 1,
    PTR = 12,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    NSEC = 47,
    ANY = 255,
};

class OPENDHT_PUBLIC ParseError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

class OPENDHT_PUBLIC Name
{
public:
    Name() = default;
    explicit Name(std::vector<std::string> labels);

    static Name fromString(std::string_view name);

    const std::vector<std::string>& labels() const noexcept { return labels_; }
    std::string toString() const;

    friend bool operator==(const Name& lhs, const Name& rhs) noexcept;
    friend bool operator!=(const Name& lhs, const Name& rhs) noexcept { return not(lhs == rhs); }

private:
    std::vector<std::string> labels_;
};

OPENDHT_PUBLIC bool operator==(const Name& lhs, const Name& rhs) noexcept;

struct Question
{
    Name name;
    Type type {Type::ANY};
    uint16_t classCode {CLASS_IN};
    bool unicastResponse {false};
};

struct AData
{
    std::array<uint8_t, 4> address {};
};

struct AaaaData
{
    std::array<uint8_t, 16> address {};
};

struct PtrData
{
    Name name;
};

struct TxtData
{
    std::vector<std::vector<uint8_t>> strings;
};

struct SrvData
{
    uint16_t priority {};
    uint16_t weight {};
    uint16_t port {};
    Name target;
};

struct NsecData
{
    Name nextDomain;
    std::vector<Type> types;
};

struct UnknownData
{
    std::vector<uint8_t> bytes;
};

using RData = std::variant<AData, AaaaData, PtrData, TxtData, SrvData, NsecData, UnknownData>;

struct ResourceRecord
{
    Name name;
    Type type {Type::ANY};
    uint16_t classCode {CLASS_IN};
    bool cacheFlush {false};
    uint32_t ttl {};
    RData data {UnknownData {}};
};

struct Message
{
    uint16_t id {};
    bool response {false};
    bool authoritative {false};
    bool truncated {false};
    std::vector<Question> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authorities;
    std::vector<ResourceRecord> additionals;
};

using Packet = std::vector<uint8_t>;

OPENDHT_PUBLIC Packet encode(const Message& message);
OPENDHT_PUBLIC Message decode(const uint8_t* packet, size_t size);

inline bool operator==(const Question& lhs, const Question& rhs)
{
    return lhs.name == rhs.name and lhs.type == rhs.type and lhs.classCode == rhs.classCode
        and lhs.unicastResponse == rhs.unicastResponse;
}

inline bool operator==(const AData& lhs, const AData& rhs) { return lhs.address == rhs.address; }
inline bool operator==(const AaaaData& lhs, const AaaaData& rhs) { return lhs.address == rhs.address; }
inline bool operator==(const PtrData& lhs, const PtrData& rhs) { return lhs.name == rhs.name; }
inline bool operator==(const TxtData& lhs, const TxtData& rhs) { return lhs.strings == rhs.strings; }
inline bool operator==(const SrvData& lhs, const SrvData& rhs)
{
    return lhs.priority == rhs.priority and lhs.weight == rhs.weight and lhs.port == rhs.port
        and lhs.target == rhs.target;
}
inline bool operator==(const NsecData& lhs, const NsecData& rhs)
{
    return lhs.nextDomain == rhs.nextDomain and lhs.types == rhs.types;
}
inline bool operator==(const UnknownData& lhs, const UnknownData& rhs) { return lhs.bytes == rhs.bytes; }

inline bool operator==(const ResourceRecord& lhs, const ResourceRecord& rhs)
{
    return lhs.name == rhs.name and lhs.type == rhs.type and lhs.classCode == rhs.classCode
        and lhs.cacheFlush == rhs.cacheFlush and lhs.ttl == rhs.ttl and lhs.data == rhs.data;
}

inline bool operator==(const Message& lhs, const Message& rhs)
{
    return lhs.id == rhs.id and lhs.response == rhs.response and lhs.authoritative == rhs.authoritative
        and lhs.truncated == rhs.truncated and lhs.questions == rhs.questions and lhs.answers == rhs.answers
        and lhs.authorities == rhs.authorities and lhs.additionals == rhs.additionals;
}

} // namespace dht::mdns