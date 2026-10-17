// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "def.h"
#include "infohash.h"
#include "utils.h"

#include <array>
#include <chrono>
#include <optional>
#include <vector>

namespace dht {
namespace transport {

constexpr size_t KEY_SIZE {32};
constexpr size_t SIGNATURE_SIZE {64};
using Key = std::array<uint8_t, KEY_SIZE>;
using Signature = std::array<uint8_t, SIGNATURE_SIZE>;
using SystemTime = std::chrono::system_clock::time_point;

/**
 * X25519 key pair used to encrypt the DHT protocol.
 * The node ID of a node using transport encryption derives from its public key.
 */
struct OPENDHT_PUBLIC KeyPair
{
    Key secret {};
    Key pub {};

    static KeyPair generate();
    static KeyPair fromSecret(const Key& secret);
    explicit operator bool() const { return pub != Key {}; }
};

/** Node ID of a node using the transport public key `pub`. */
OPENDHT_PUBLIC InfoHash nodeId(const Key& pub);

/** Authority-signed binding of a transport public key to a private network. */
struct OPENDHT_PUBLIC Credential
{
    static constexpr size_t PACKED_SIZE {1 + KEY_SIZE + 8 + SIGNATURE_SIZE};

    Key key {};
    SystemTime expiration {};
    Signature signature {};

    Blob pack() const;
    /** @throws std::invalid_argument if the data is not a packed credential */
    static Credential unpack(const uint8_t* data, size_t size);
    static Credential unpack(const Blob& b) { return unpack(b.data(), b.size()); }

    /** True if signed by one of the authorities and not expired at `now`. */
    bool verify(const std::vector<Key>& authorities, SystemTime now = std::chrono::system_clock::now()) const;
    explicit operator bool() const { return key != Key {}; }
};

/** Ed25519 key of a private network authority, issuing node credentials. */
struct OPENDHT_PUBLIC Authority
{
    Key secret {};
    Key pub {};

    static Authority generate();
    static Authority fromSecret(const Key& secret);
    Credential issue(const Key& transportKey, SystemTime expiration) const;
};

/** Transport state of a remote node, attached to its Node. */
struct Peer
{
    explicit Peer(const Key& k)
        : key(k)
    {}
    const Key key;
    std::optional<Key> shared {};
    /** Private networks: expiration of the verified peer credential */
    SystemTime authorizedUntil {};
    /** Private networks: the peer accepted our credential */
    bool acked {false};

    bool isAuthorized(SystemTime now) const { return now < authorizedUntil; }
};

/*
 * Envelope: marker | type | sender public key | nonce | ChaCha20-Poly1305(payload) | tag
 * The marker is never a valid msgpack first byte, so legacy nodes drop envelopes.
 * Hello (private networks only, plaintext): marker | type | sender public key | credential | message
 */
constexpr uint8_t ENVELOPE_MARKER {0xC1};
enum class EnvelopeType : uint8_t { Data = 1, DataCredential = 2, Hello = 3 };
constexpr size_t NONCE_SIZE {12};
constexpr size_t TAG_SIZE {16};
constexpr size_t HEADER_SIZE {2 + KEY_SIZE};
constexpr size_t ENVELOPE_OVERHEAD {HEADER_SIZE + NONCE_SIZE + TAG_SIZE};
constexpr size_t MAX_ENVELOPE_OVERHEAD {ENVELOPE_OVERHEAD + Credential::PACKED_SIZE};

inline bool
isEnvelope(const uint8_t* data, size_t size)
{
    return size >= HEADER_SIZE and data[0] == ENVELOPE_MARKER;
}

/** Symmetric key shared with `peer`, or nullopt for an invalid peer key. */
OPENDHT_PUBLIC std::optional<Key> deriveSharedKey(const KeyPair& own, const Key& peer, NetId network);

/** Encrypts `prefix || data`, authenticating the envelope header. */
OPENDHT_PUBLIC Blob seal(
    const Key& shared, const Key& sender, EnvelopeType type, const uint8_t* data, size_t size, const Blob& prefix = {});

/** Decrypted payload, or nullopt if the envelope is not authentic. */
OPENDHT_PUBLIC std::optional<Blob> open(const Key& shared, const uint8_t* data, size_t size);

OPENDHT_PUBLIC Blob hello(const Key& sender, const Blob& credential, const uint8_t* data, size_t size);

} // namespace transport

/**
 * Encryption of the DHT protocol. Peers that don't support it keep talking in plaintext,
 * unless the node is part of a private network.
 */
struct TransportConfig
{
    /** Advertise our key and encrypt traffic with nodes supporting it. Disabling uses a legacy random node ID. */
    bool enabled {true};
    /** Transport key, generated on start if empty. The node ID derives from it. */
    transport::KeyPair key {};
    /** Network authorities. If set, only nodes with a credential issued by one of them are accepted. */
    std::vector<transport::Key> authorities {};
    /** Credential of `key`, required for private networks. */
    transport::Credential credential {};

    bool isPrivate() const { return not authorities.empty(); }
};

} // namespace dht
