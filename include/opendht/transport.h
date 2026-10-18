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
 * X25519 key pair used to encrypt the DHT protocol: the static key of a node, from which its node ID derives,
 * or a periodically rotated ephemeral key.
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

/** Secret from the system CSPRNG. */
OPENDHT_PUBLIC Key randomSecret();

/** Ephemeral key pair used with the peer at `address` (IP and port), derived from an epoch secret. */
OPENDHT_PUBLIC KeyPair addressKey(const Key& epochSecret, const uint8_t* address, size_t size);

/** Write token of the plaintext peer at `address` (IP and port), derived from an epoch secret. */
OPENDHT_PUBLIC Key addressToken(const Key& epochSecret, const uint8_t* address, size_t size);

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
    /** Last authenticated ephemeral key of the peer */
    std::optional<Key> ephemeral {};
    /** The ephemeral key came in an envelope opened with our key for the peer address: the peer receives there */
    bool ephemeralValidated {false};
    /** Private networks: expiration of the verified peer credential */
    SystemTime authorizedUntil {};

    bool isAuthorized(SystemTime now) const { return now < authorizedUntil; }
    void setEphemeral(const Key& k, bool validated)
    {
        ephemeral = k;
        ephemeralValidated = validated;
    }
    void resetEphemeral()
    {
        ephemeral.reset();
        ephemeralValidated = false;
    }
};

/*
 * Envelope: marker | type | sender static key | sender ephemeral key | nonce | ChaCha20-Poly1305(payload) | tag
 * Data envelope: marker | type | nonce | ChaCha20-Poly1305(payload) | tag, keys found from the source address.
 * The marker is never a valid msgpack first byte, so legacy nodes drop envelopes.
 * Hello (private networks only, plaintext): marker | type | sender static key | sender ephemeral key | credential | message
 */
constexpr uint8_t ENVELOPE_MARKER {0xC1};
/** Initial: the sender doesn't know the receiver ephemeral key. Session: it does. Data: the receiver has the session. */
enum class EnvelopeType : uint8_t { Initial = 1, Session = 2, Hello = 3, Data = 4 };
/** Type flag: the payload starts with the sender credential */
constexpr uint8_t CREDENTIAL_FLAG {0x80};
constexpr size_t NONCE_SIZE {12};
constexpr size_t TAG_SIZE {16};
constexpr size_t HEADER_SIZE {2 + 2 * KEY_SIZE};
constexpr size_t DATA_HEADER_SIZE {2};
constexpr size_t ENVELOPE_OVERHEAD {HEADER_SIZE + NONCE_SIZE + TAG_SIZE};
constexpr size_t DATA_ENVELOPE_OVERHEAD {DATA_HEADER_SIZE + NONCE_SIZE + TAG_SIZE};
constexpr size_t MAX_ENVELOPE_OVERHEAD {ENVELOPE_OVERHEAD + Credential::PACKED_SIZE};

inline bool
isEnvelope(const uint8_t* data, size_t size)
{
    return size >= DATA_HEADER_SIZE and data[0] == ENVELOPE_MARKER;
}

struct Header
{
    EnvelopeType type;
    bool credential;
    /* not in Data envelopes */
    Key sender;
    Key ephemeral;
};

/** Envelope header, or nullopt if not an envelope of a known type. */
OPENDHT_PUBLIC std::optional<Header> parseHeader(const uint8_t* data, size_t size);

/** Keys to send to and receive from a peer. */
struct SessionKeys
{
    Key tx;
    Key rx;
};

/** Session keys with a peer whose ephemeral key is known, or nullopt for an invalid peer key. */
OPENDHT_PUBLIC std::optional<SessionKeys> sessionKeys(
    const KeyPair& own, const KeyPair& ephemeral, const Key& peer, const Key& peerEphemeral, NetId network);

/** Key of an Initial envelope to `peer`, or nullopt for an invalid peer key. */
OPENDHT_PUBLIC std::optional<Key> initialSendKey(const KeyPair& own,
                                                 const KeyPair& ephemeral,
                                                 const Key& peer,
                                                 NetId network);

/** Key of an Initial envelope from `peer`, or nullopt for an invalid peer key. */
OPENDHT_PUBLIC std::optional<Key> initialReceiveKey(const KeyPair& own,
                                                    const Key& peer,
                                                    const Key& peerEphemeral,
                                                    NetId network);

/** Encrypts `credential || data`, authenticating the envelope header. */
OPENDHT_PUBLIC Blob seal(const Key& key,
                         EnvelopeType type,
                         const Key& sender,
                         const Key& ephemeral,
                         const uint8_t* data,
                         size_t size,
                         const Blob& credential = {});

/** Encrypts `data` in a Data envelope. */
OPENDHT_PUBLIC Blob sealData(const Key& key, const uint8_t* data, size_t size);

/** Decrypted payload, or nullopt if the envelope is not authentic. */
OPENDHT_PUBLIC std::optional<Blob> open(const Key& key, const uint8_t* data, size_t size);

OPENDHT_PUBLIC Blob
hello(const Key& sender, const Key& ephemeral, const Blob& credential, const uint8_t* data, size_t size);

/** Erases secret key material. */
OPENDHT_PUBLIC void wipe(Key& key);

} // namespace transport

/**
 * Encryption of the DHT protocol. Peers that don't support it keep talking in plaintext,
 * unless the node is part of a private network.
 */
struct TransportConfig
{
    /** Advertise our key and encrypt traffic with nodes supporting it. Disabling uses a legacy random node ID. */
    bool enabled {true};
    /** Transport key. If empty, generated on start, and kept in the persisted state if Config::persist_path is set. */
    transport::KeyPair key {};
    /** Network authorities. If set, only nodes with a credential issued by one of them are accepted. */
    std::vector<transport::Key> authorities {};
    /** Credential of `key`, required for private networks. */
    transport::Credential credential {};

    bool isPrivate() const { return not authorities.empty(); }
};

} // namespace dht
