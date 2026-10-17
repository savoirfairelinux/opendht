// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "transport.h"

#include <gnutls/crypto.h>
#include <nettle/chacha-poly1305.h>
#include <nettle/curve25519.h>
#include <nettle/eddsa.h>
#include <nettle/hmac.h>
#include <nettle/memops.h>
#include <nettle/sha2.h>
#include <nettle/version.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string_view>

namespace dht {
namespace transport {

using namespace std::literals;

namespace {

constexpr auto NODE_ID_CONTEXT = "opendht-node-id-v1"sv;
constexpr auto KDF_SALT = "opendht-transport-v1"sv;
constexpr auto CREDENTIAL_CONTEXT = "opendht-credential-v1"sv;
constexpr uint8_t CREDENTIAL_VERSION {1};

void
randomBytes(uint8_t* data, size_t size, gnutls_rnd_level_t level)
{
    if (gnutls_rnd(level, data, size) != 0)
        throw std::runtime_error("Unable to generate random data");
}

Key
hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen)
{
    struct hmac_sha256_ctx ctx;
    hmac_sha256_set_key(&ctx, keyLen, key);
    hmac_sha256_update(&ctx, dataLen, data);
    Key out;
#if NETTLE_VERSION_MAJOR >= 4
    hmac_sha256_digest(&ctx, out.data());
#else
    hmac_sha256_digest(&ctx, out.size(), out.data());
#endif
    return out;
}

void
chachaDigest(struct chacha_poly1305_ctx* ctx, uint8_t* tag)
{
#if NETTLE_VERSION_MAJOR >= 4
    chacha_poly1305_digest(ctx, tag);
#else
    chacha_poly1305_digest(ctx, TAG_SIZE, tag);
#endif
}

void
writeU64(uint8_t* p, uint64_t v)
{
    for (int i = 7; i >= 0; --i, v >>= 8)
        p[i] = v & 0xFF;
}

uint64_t
readU64(const uint8_t* p)
{
    uint64_t v {0};
    for (int i = 0; i < 8; ++i)
        v = (v << 8) | p[i];
    return v;
}

constexpr size_t SIGNED_SIZE {CREDENTIAL_CONTEXT.size() + 1 + KEY_SIZE + 8};

std::array<uint8_t, SIGNED_SIZE>
signedData(const Key& key, uint64_t expiration)
{
    std::array<uint8_t, SIGNED_SIZE> data;
    auto p = std::copy(CREDENTIAL_CONTEXT.begin(), CREDENTIAL_CONTEXT.end(), data.begin());
    *p++ = CREDENTIAL_VERSION;
    p = std::copy(key.begin(), key.end(), p);
    writeU64(&*p, expiration);
    return data;
}

uint64_t
toSeconds(SystemTime t)
{
    auto s = std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
    return s > 0 ? static_cast<uint64_t>(s) : 0;
}

} // namespace

KeyPair
KeyPair::generate()
{
    Key secret;
    randomBytes(secret.data(), secret.size(), GNUTLS_RND_KEY);
    return fromSecret(secret);
}

KeyPair
KeyPair::fromSecret(const Key& secret)
{
    KeyPair kp;
    kp.secret = secret;
    curve25519_mul_g(kp.pub.data(), secret.data());
    return kp;
}

InfoHash
nodeId(const Key& pub)
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, NODE_ID_CONTEXT.size(), (const uint8_t*) NODE_ID_CONTEXT.data());
    sha256_update(&ctx, pub.size(), pub.data());
    std::array<uint8_t, SHA256_DIGEST_SIZE> digest;
#if NETTLE_VERSION_MAJOR >= 4
    sha256_digest(&ctx, digest.data());
#else
    sha256_digest(&ctx, digest.size(), digest.data());
#endif
    return InfoHash(digest.data(), HASH_LEN);
}

Blob
Credential::pack() const
{
    Blob b(PACKED_SIZE);
    b[0] = CREDENTIAL_VERSION;
    std::copy(key.begin(), key.end(), b.begin() + 1);
    writeU64(b.data() + 1 + KEY_SIZE, toSeconds(expiration));
    std::copy(signature.begin(), signature.end(), b.begin() + 1 + KEY_SIZE + 8);
    return b;
}

Credential
Credential::unpack(const uint8_t* data, size_t size)
{
    if (size != PACKED_SIZE or data[0] != CREDENTIAL_VERSION)
        throw std::invalid_argument("Invalid transport credential");
    Credential c;
    std::copy_n(data + 1, KEY_SIZE, c.key.begin());
    c.expiration = SystemTime(std::chrono::seconds(readU64(data + 1 + KEY_SIZE)));
    std::copy_n(data + 1 + KEY_SIZE + 8, SIGNATURE_SIZE, c.signature.begin());
    return c;
}

bool
Credential::verify(const std::vector<Key>& authorities, SystemTime now) const
{
    if (now >= expiration)
        return false;
    auto data = signedData(key, toSeconds(expiration));
    return std::any_of(authorities.begin(), authorities.end(), [&](const Key& authority) {
        return ed25519_sha512_verify(authority.data(), data.size(), data.data(), signature.data()) == 1;
    });
}

Authority
Authority::generate()
{
    Key secret;
    randomBytes(secret.data(), secret.size(), GNUTLS_RND_KEY);
    return fromSecret(secret);
}

Authority
Authority::fromSecret(const Key& secret)
{
    Authority a;
    a.secret = secret;
    ed25519_sha512_public_key(a.pub.data(), secret.data());
    return a;
}

Credential
Authority::issue(const Key& transportKey, SystemTime expiration) const
{
    Credential c;
    c.key = transportKey;
    c.expiration = SystemTime(std::chrono::seconds(toSeconds(expiration)));
    auto data = signedData(c.key, toSeconds(c.expiration));
    ed25519_sha512_sign(pub.data(), secret.data(), data.size(), data.data(), c.signature.data());
    return c;
}

std::optional<Key>
deriveSharedKey(const KeyPair& own, const Key& peer, NetId network)
{
    Key dh;
    curve25519_mul(dh.data(), own.secret.data(), peer.data());
    if (dh == Key {})
        return std::nullopt;

    auto prk = hmacSha256((const uint8_t*) KDF_SALT.data(), KDF_SALT.size(), dh.data(), dh.size());
    std::array<uint8_t, 4 + 2 * KEY_SIZE + 1> info;
    for (int i = 0; i < 4; ++i)
        info[i] = (network >> (24 - 8 * i)) & 0xFF;
    const auto& lo = std::min(own.pub, peer);
    const auto& hi = std::max(own.pub, peer);
    std::copy(lo.begin(), lo.end(), info.begin() + 4);
    std::copy(hi.begin(), hi.end(), info.begin() + 4 + KEY_SIZE);
    info.back() = 1;
    return hmacSha256(prk.data(), prk.size(), info.data(), info.size());
}

Blob
seal(const Key& shared, const Key& sender, EnvelopeType type, const uint8_t* data, size_t size, const Blob& prefix)
{
    const size_t len = prefix.size() + size;
    Blob out(ENVELOPE_OVERHEAD + len);
    out[0] = ENVELOPE_MARKER;
    out[1] = static_cast<uint8_t>(type);
    std::copy(sender.begin(), sender.end(), out.begin() + 2);
    auto nonce = out.data() + HEADER_SIZE;
    randomBytes(nonce, NONCE_SIZE, GNUTLS_RND_NONCE);
    auto payload = nonce + NONCE_SIZE;
    std::copy(prefix.begin(), prefix.end(), payload);
    if (size)
        std::memcpy(payload + prefix.size(), data, size);

    struct chacha_poly1305_ctx ctx;
    chacha_poly1305_set_key(&ctx, shared.data());
    chacha_poly1305_set_nonce(&ctx, nonce);
    chacha_poly1305_update(&ctx, HEADER_SIZE, out.data());
    chacha_poly1305_encrypt(&ctx, len, payload, payload);
    chachaDigest(&ctx, payload + len);
    return out;
}

std::optional<Blob>
open(const Key& shared, const uint8_t* data, size_t size)
{
    if (size < ENVELOPE_OVERHEAD or data[0] != ENVELOPE_MARKER)
        return std::nullopt;
    const size_t len = size - ENVELOPE_OVERHEAD;
    const auto nonce = data + HEADER_SIZE;

    struct chacha_poly1305_ctx ctx;
    chacha_poly1305_set_key(&ctx, shared.data());
    chacha_poly1305_set_nonce(&ctx, nonce);
    chacha_poly1305_update(&ctx, HEADER_SIZE, data);
    Blob out(len);
    chacha_poly1305_decrypt(&ctx, len, out.data(), nonce + NONCE_SIZE);
    std::array<uint8_t, TAG_SIZE> tag;
    chachaDigest(&ctx, tag.data());
    if (not memeql_sec(tag.data(), data + size - TAG_SIZE, TAG_SIZE))
        return std::nullopt;
    return out;
}

Blob
hello(const Key& sender, const Blob& credential, const uint8_t* data, size_t size)
{
    Blob out;
    out.reserve(HEADER_SIZE + credential.size() + size);
    out.push_back(ENVELOPE_MARKER);
    out.push_back(static_cast<uint8_t>(EnvelopeType::Hello));
    out.insert(out.end(), sender.begin(), sender.end());
    out.insert(out.end(), credential.begin(), credential.end());
    out.insert(out.end(), data, data + size);
    return out;
}

} // namespace transport
} // namespace dht
