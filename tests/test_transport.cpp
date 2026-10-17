// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_transport.h"

#include <opendht/transport.h>
#include <opendht/value.h>

#include <msgpack.hpp>

using namespace std::chrono_literals;

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(TransportTester);

using namespace dht;
using namespace dht::transport;

static Key
keyFromHex(std::string_view hex)
{
    Key k;
    for (size_t i = 0; i < k.size(); i++)
        k[i] = std::stoi(std::string(hex.substr(2 * i, 2)), nullptr, 16);
    return k;
}

static Blob
message()
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(2);
    pk.pack("y");
    pk.pack("q");
    pk.pack("q");
    pk.pack("ping");
    return {buffer.data(), buffer.data() + buffer.size()};
}

void
TransportTester::testX25519Rfc7748()
{
    auto alice = KeyPair::fromSecret(keyFromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    auto bob = KeyPair::fromSecret(keyFromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    CPPUNIT_ASSERT(alice.pub == keyFromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    CPPUNIT_ASSERT(bob.pub == keyFromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
}

void
TransportTester::testSharedKey()
{
    auto a = KeyPair::generate();
    auto b = KeyPair::generate();
    CPPUNIT_ASSERT(a);
    CPPUNIT_ASSERT(a.pub != b.pub);

    auto ab = deriveSharedKey(a, b.pub, 0);
    auto ba = deriveSharedKey(b, a.pub, 0);
    CPPUNIT_ASSERT(ab and ba);
    CPPUNIT_ASSERT(*ab == *ba);

    auto otherNetwork = deriveSharedKey(a, b.pub, 42);
    CPPUNIT_ASSERT(otherNetwork);
    CPPUNIT_ASSERT(*otherNetwork != *ab);

    auto c = KeyPair::generate();
    CPPUNIT_ASSERT(*deriveSharedKey(a, c.pub, 0) != *ab);
}

void
TransportTester::testRejectsLowOrderKey()
{
    auto a = KeyPair::generate();
    CPPUNIT_ASSERT(not deriveSharedKey(a, Key {}, 0));
    Key one {};
    one[0] = 1;
    CPPUNIT_ASSERT(not deriveSharedKey(a, one, 0));
}

void
TransportTester::testNodeId()
{
    auto a = KeyPair::generate();
    auto b = KeyPair::generate();
    CPPUNIT_ASSERT(nodeId(a.pub));
    CPPUNIT_ASSERT_EQUAL(nodeId(a.pub), nodeId(KeyPair::fromSecret(a.secret).pub));
    CPPUNIT_ASSERT(nodeId(a.pub) != nodeId(b.pub));
}

void
TransportTester::testSealOpen()
{
    auto a = KeyPair::generate();
    auto b = KeyPair::generate();
    auto shared = *deriveSharedKey(a, b.pub, 0);
    auto msg = message();

    auto envelope = seal(shared, a.pub, EnvelopeType::Data, msg.data(), msg.size());
    CPPUNIT_ASSERT_EQUAL(msg.size() + ENVELOPE_OVERHEAD, envelope.size());
    CPPUNIT_ASSERT(isEnvelope(envelope.data(), envelope.size()));
    CPPUNIT_ASSERT_EQUAL((uint8_t) EnvelopeType::Data, envelope[1]);
    CPPUNIT_ASSERT(std::equal(a.pub.begin(), a.pub.end(), envelope.begin() + 2));

    auto opened = open(*deriveSharedKey(b, a.pub, 0), envelope.data(), envelope.size());
    CPPUNIT_ASSERT(opened);
    CPPUNIT_ASSERT(*opened == msg);

    // Random nonces: sealing twice gives different envelopes
    CPPUNIT_ASSERT(seal(shared, a.pub, EnvelopeType::Data, msg.data(), msg.size()) != envelope);

    Blob prefix {1, 2, 3};
    auto withPrefix = seal(shared, a.pub, EnvelopeType::DataCredential, msg.data(), msg.size(), prefix);
    auto openedPrefix = open(shared, withPrefix.data(), withPrefix.size());
    CPPUNIT_ASSERT(openedPrefix);
    CPPUNIT_ASSERT(std::equal(prefix.begin(), prefix.end(), openedPrefix->begin()));
    CPPUNIT_ASSERT(std::equal(msg.begin(), msg.end(), openedPrefix->begin() + prefix.size()));
}

void
TransportTester::testOpenRejectsTampering()
{
    auto a = KeyPair::generate();
    auto b = KeyPair::generate();
    auto shared = *deriveSharedKey(a, b.pub, 0);
    auto msg = message();
    auto envelope = seal(shared, a.pub, EnvelopeType::Data, msg.data(), msg.size());

    for (size_t i : {(size_t) 1, (size_t) 2, HEADER_SIZE, HEADER_SIZE + NONCE_SIZE, envelope.size() - 1}) {
        auto tampered = envelope;
        tampered[i] ^= 0x01;
        CPPUNIT_ASSERT(not open(shared, tampered.data(), tampered.size()));
    }
    CPPUNIT_ASSERT(not open(shared, envelope.data(), envelope.size() - 1));
    CPPUNIT_ASSERT(not open(shared, envelope.data(), ENVELOPE_OVERHEAD - 1));

    auto c = KeyPair::generate();
    CPPUNIT_ASSERT(not open(*deriveSharedKey(c, a.pub, 0), envelope.data(), envelope.size()));
    CPPUNIT_ASSERT(not open(*deriveSharedKey(b, a.pub, 1), envelope.data(), envelope.size()));
}

void
TransportTester::testEnvelopeIsNotMsgpack()
{
    auto a = KeyPair::generate();
    auto shared = *deriveSharedKey(a, KeyPair::generate().pub, 0);
    auto msg = message();
    auto envelope = seal(shared, a.pub, EnvelopeType::Data, msg.data(), msg.size());
    CPPUNIT_ASSERT_THROW(msgpack::unpack((const char*) envelope.data(), envelope.size()), std::exception);
    auto h = hello(a.pub, Blob(Credential::PACKED_SIZE), msg.data(), msg.size());
    CPPUNIT_ASSERT_THROW(msgpack::unpack((const char*) h.data(), h.size()), std::exception);
}

void
TransportTester::testHello()
{
    auto a = KeyPair::generate();
    auto credential = Authority::generate().issue(a.pub, std::chrono::system_clock::now() + 1h).pack();
    auto msg = message();
    auto h = hello(a.pub, credential, msg.data(), msg.size());
    CPPUNIT_ASSERT_EQUAL(HEADER_SIZE + Credential::PACKED_SIZE + msg.size(), h.size());
    CPPUNIT_ASSERT(isEnvelope(h.data(), h.size()));
    CPPUNIT_ASSERT_EQUAL((uint8_t) EnvelopeType::Hello, h[1]);
    CPPUNIT_ASSERT(std::equal(credential.begin(), credential.end(), h.begin() + HEADER_SIZE));
    CPPUNIT_ASSERT(std::equal(msg.begin(), msg.end(), h.begin() + HEADER_SIZE + credential.size()));
}

void
TransportTester::testCredential()
{
    auto authority = Authority::generate();
    CPPUNIT_ASSERT(Authority::fromSecret(authority.secret).pub == authority.pub);
    auto key = KeyPair::generate();
    auto expiration = std::chrono::system_clock::now() + 24h;

    auto credential = authority.issue(key.pub, expiration);
    CPPUNIT_ASSERT(credential);
    CPPUNIT_ASSERT(credential.key == key.pub);
    CPPUNIT_ASSERT(credential.verify({authority.pub}));
    CPPUNIT_ASSERT(credential.verify({Authority::generate().pub, authority.pub}));

    auto packed = credential.pack();
    CPPUNIT_ASSERT_EQUAL(Credential::PACKED_SIZE, packed.size());
    auto unpacked = Credential::unpack(packed);
    CPPUNIT_ASSERT(unpacked.key == credential.key);
    CPPUNIT_ASSERT(unpacked.expiration == credential.expiration);
    CPPUNIT_ASSERT(unpacked.signature == credential.signature);
    CPPUNIT_ASSERT(unpacked.verify({authority.pub}));
}

void
TransportTester::testCredentialRejections()
{
    auto authority = Authority::generate();
    auto key = KeyPair::generate();
    auto now = std::chrono::system_clock::now();
    auto credential = authority.issue(key.pub, now + 1h);

    CPPUNIT_ASSERT(not credential.verify({}));
    CPPUNIT_ASSERT(not credential.verify({Authority::generate().pub}));
    CPPUNIT_ASSERT(not credential.verify({authority.pub}, now + 2h));
    CPPUNIT_ASSERT(not authority.issue(key.pub, now - 1s).verify({authority.pub}));

    auto otherKey = credential;
    otherKey.key = KeyPair::generate().pub;
    CPPUNIT_ASSERT(not otherKey.verify({authority.pub}));

    auto extended = credential;
    extended.expiration += 24h;
    CPPUNIT_ASSERT(not extended.verify({authority.pub}));

    auto packed = credential.pack();
    CPPUNIT_ASSERT_THROW(Credential::unpack(packed.data(), packed.size() - 1), std::invalid_argument);
    packed[0] = 2;
    CPPUNIT_ASSERT_THROW(Credential::unpack(packed), std::invalid_argument);
}

} // namespace test
