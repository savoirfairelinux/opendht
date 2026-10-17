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
TransportTester::testSessionKeys()
{
    auto a = KeyPair::generate(), ea = KeyPair::generate();
    auto b = KeyPair::generate(), eb = KeyPair::generate();
    CPPUNIT_ASSERT(a);
    CPPUNIT_ASSERT(a.pub != b.pub);

    auto ab = sessionKeys(a, ea, b.pub, eb.pub, 0);
    auto ba = sessionKeys(b, eb, a.pub, ea.pub, 0);
    CPPUNIT_ASSERT(ab and ba);
    CPPUNIT_ASSERT(ab->tx == ba->rx);
    CPPUNIT_ASSERT(ab->rx == ba->tx);
    CPPUNIT_ASSERT(ab->tx != ab->rx);

    auto c = KeyPair::generate();
    for (const auto& other : {sessionKeys(a, ea, b.pub, eb.pub, 42),
                              sessionKeys(a, c, b.pub, eb.pub, 0),
                              sessionKeys(a, ea, b.pub, c.pub, 0),
                              sessionKeys(a, ea, c.pub, eb.pub, 0),
                              sessionKeys(c, ea, b.pub, eb.pub, 0)}) {
        CPPUNIT_ASSERT(other);
        CPPUNIT_ASSERT(other->tx != ab->tx and other->rx != ab->rx);
    }
}

void
TransportTester::testInitialKey()
{
    auto a = KeyPair::generate(), ea = KeyPair::generate();
    auto b = KeyPair::generate(), eb = KeyPair::generate();

    auto sent = initialSendKey(a, ea, b.pub, 0);
    auto received = initialReceiveKey(b, a.pub, ea.pub, 0);
    CPPUNIT_ASSERT(sent and received);
    CPPUNIT_ASSERT(*sent == *received);

    auto session = sessionKeys(a, ea, b.pub, eb.pub, 0);
    CPPUNIT_ASSERT(*sent != session->tx and *sent != session->rx);
    CPPUNIT_ASSERT(*initialSendKey(a, ea, b.pub, 42) != *sent);
    CPPUNIT_ASSERT(*initialSendKey(a, eb, b.pub, 0) != *sent);
    // directional
    CPPUNIT_ASSERT(*initialSendKey(b, ea, a.pub, 0) != *sent);
}

void
TransportTester::testRejectsLowOrderKey()
{
    auto a = KeyPair::generate(), ea = KeyPair::generate();
    auto b = KeyPair::generate();
    Key one {};
    one[0] = 1;
    for (const auto& bad : {Key {}, one}) {
        CPPUNIT_ASSERT(not sessionKeys(a, ea, bad, b.pub, 0));
        CPPUNIT_ASSERT(not sessionKeys(a, ea, b.pub, bad, 0));
        CPPUNIT_ASSERT(not initialSendKey(a, ea, bad, 0));
        CPPUNIT_ASSERT(not initialReceiveKey(a, bad, b.pub, 0));
        CPPUNIT_ASSERT(not initialReceiveKey(a, b.pub, bad, 0));
    }
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
TransportTester::testAddressKey()
{
    auto secret = randomSecret(), other = randomSecret();
    CPPUNIT_ASSERT(secret != other);
    const uint8_t x[] = {127, 0, 0, 2, 0x10, 0x7e};
    const uint8_t y[] = {127, 0, 0, 2, 0x10, 0x7f};

    auto key = addressKey(secret, x, sizeof(x));
    CPPUNIT_ASSERT(key);
    CPPUNIT_ASSERT(key.pub == KeyPair::fromSecret(key.secret).pub);
    CPPUNIT_ASSERT(key.secret == addressKey(secret, x, sizeof(x)).secret);
    CPPUNIT_ASSERT(key.secret != addressKey(secret, y, sizeof(y)).secret);
    CPPUNIT_ASSERT(key.secret != addressKey(other, x, sizeof(x)).secret);

    auto token = addressToken(secret, x, sizeof(x));
    CPPUNIT_ASSERT(token == addressToken(secret, x, sizeof(x)));
    CPPUNIT_ASSERT(token != addressToken(secret, y, sizeof(y)));
    CPPUNIT_ASSERT(token != addressToken(other, x, sizeof(x)));
    CPPUNIT_ASSERT(token != key.secret and token != key.pub);
}

void
TransportTester::testSealOpen()
{
    auto a = KeyPair::generate(), ea = KeyPair::generate();
    auto b = KeyPair::generate(), eb = KeyPair::generate();
    auto keys = *sessionKeys(a, ea, b.pub, eb.pub, 0);
    auto msg = message();

    auto envelope = seal(keys.tx, EnvelopeType::Session, a.pub, ea.pub, msg.data(), msg.size());
    CPPUNIT_ASSERT_EQUAL(msg.size() + ENVELOPE_OVERHEAD, envelope.size());
    CPPUNIT_ASSERT(isEnvelope(envelope.data(), envelope.size()));
    auto header = parseHeader(envelope.data(), envelope.size());
    CPPUNIT_ASSERT(header);
    CPPUNIT_ASSERT(header->type == EnvelopeType::Session);
    CPPUNIT_ASSERT(not header->credential);
    CPPUNIT_ASSERT(header->sender == a.pub);
    CPPUNIT_ASSERT(header->ephemeral == ea.pub);

    auto opened = open(sessionKeys(b, eb, a.pub, ea.pub, 0)->rx, envelope.data(), envelope.size());
    CPPUNIT_ASSERT(opened);
    CPPUNIT_ASSERT(*opened == msg);

    // Random nonces: sealing twice gives different envelopes
    CPPUNIT_ASSERT(seal(keys.tx, EnvelopeType::Session, a.pub, ea.pub, msg.data(), msg.size()) != envelope);

    Blob credential {1, 2, 3};
    auto withCredential = seal(keys.tx, EnvelopeType::Initial, a.pub, ea.pub, msg.data(), msg.size(), credential);
    header = parseHeader(withCredential.data(), withCredential.size());
    CPPUNIT_ASSERT(header and header->type == EnvelopeType::Initial and header->credential);
    auto openedCredential = open(keys.tx, withCredential.data(), withCredential.size());
    CPPUNIT_ASSERT(openedCredential);
    CPPUNIT_ASSERT(std::equal(credential.begin(), credential.end(), openedCredential->begin()));
    CPPUNIT_ASSERT(std::equal(msg.begin(), msg.end(), openedCredential->begin() + credential.size()));
}

void
TransportTester::testOpenRejectsTampering()
{
    auto a = KeyPair::generate(), ea = KeyPair::generate();
    auto b = KeyPair::generate(), eb = KeyPair::generate();
    auto keys = *sessionKeys(a, ea, b.pub, eb.pub, 0);
    auto msg = message();
    auto envelope = seal(keys.tx, EnvelopeType::Session, a.pub, ea.pub, msg.data(), msg.size());

    for (size_t i : {(size_t) 1, (size_t) 2, 2 + KEY_SIZE, HEADER_SIZE, HEADER_SIZE + NONCE_SIZE, envelope.size() - 1}) {
        auto tampered = envelope;
        tampered[i] ^= 0x01;
        CPPUNIT_ASSERT(not open(keys.tx, tampered.data(), tampered.size()));
    }
    CPPUNIT_ASSERT(not open(keys.tx, envelope.data(), envelope.size() - 1));
    CPPUNIT_ASSERT(not open(keys.tx, envelope.data(), ENVELOPE_OVERHEAD - 1));
    CPPUNIT_ASSERT(not open(keys.rx, envelope.data(), envelope.size()));
    CPPUNIT_ASSERT(not open(sessionKeys(b, eb, a.pub, ea.pub, 1)->rx, envelope.data(), envelope.size()));
}

void
TransportTester::testDataEnvelope()
{
    auto a = KeyPair::generate(), ea = KeyPair::generate();
    auto b = KeyPair::generate(), eb = KeyPair::generate();
    auto keys = *sessionKeys(a, ea, b.pub, eb.pub, 0);
    auto msg = message();

    auto envelope = sealData(keys.tx, msg.data(), msg.size());
    CPPUNIT_ASSERT_EQUAL(msg.size() + DATA_ENVELOPE_OVERHEAD, envelope.size());
    CPPUNIT_ASSERT_EQUAL((size_t) 30, DATA_ENVELOPE_OVERHEAD);
    CPPUNIT_ASSERT(isEnvelope(envelope.data(), envelope.size()));
    CPPUNIT_ASSERT_THROW(msgpack::unpack((const char*) envelope.data(), envelope.size()), std::exception);
    auto header = parseHeader(envelope.data(), envelope.size());
    CPPUNIT_ASSERT(header and header->type == EnvelopeType::Data and not header->credential);

    auto opened = open(sessionKeys(b, eb, a.pub, ea.pub, 0)->rx, envelope.data(), envelope.size());
    CPPUNIT_ASSERT(opened and *opened == msg);

    for (size_t i : {(size_t) 1, DATA_HEADER_SIZE, DATA_HEADER_SIZE + NONCE_SIZE, envelope.size() - 1}) {
        auto tampered = envelope;
        tampered[i] ^= 0x01;
        CPPUNIT_ASSERT(not open(keys.tx, tampered.data(), tampered.size()));
    }
    CPPUNIT_ASSERT(not open(keys.tx, envelope.data(), DATA_ENVELOPE_OVERHEAD - 1));
    CPPUNIT_ASSERT(not open(keys.rx, envelope.data(), envelope.size()));

    // Same key, other type: the type is authenticated
    auto session = seal(keys.tx, EnvelopeType::Session, a.pub, ea.pub, msg.data(), msg.size());
    Blob relabeled {ENVELOPE_MARKER, static_cast<uint8_t>(EnvelopeType::Data)};
    relabeled.insert(relabeled.end(), session.begin() + HEADER_SIZE, session.end());
    CPPUNIT_ASSERT(not open(keys.tx, relabeled.data(), relabeled.size()));

    // Data never carries a credential
    auto flagged = envelope;
    flagged[1] |= CREDENTIAL_FLAG;
    CPPUNIT_ASSERT(not parseHeader(flagged.data(), flagged.size()));
    CPPUNIT_ASSERT(not open(keys.tx, flagged.data(), flagged.size()));
}

void
TransportTester::testParseHeader()
{
    auto a = KeyPair::generate(), ea = KeyPair::generate();
    auto msg = message();
    auto envelope = seal(Key {}, EnvelopeType::Session, a.pub, ea.pub, msg.data(), msg.size());
    CPPUNIT_ASSERT(parseHeader(envelope.data(), HEADER_SIZE));
    CPPUNIT_ASSERT(not parseHeader(envelope.data(), HEADER_SIZE - 1));
    for (uint8_t type : {0, 5, 0x80, 0x84, 0x85}) {
        auto unknown = envelope;
        unknown[1] = type;
        CPPUNIT_ASSERT(not parseHeader(unknown.data(), unknown.size()));
    }
    CPPUNIT_ASSERT(not parseHeader(msg.data(), msg.size()));
}

void
TransportTester::testEnvelopeIsNotMsgpack()
{
    auto a = KeyPair::generate(), ea = KeyPair::generate();
    auto msg = message();
    auto envelope = seal(Key {}, EnvelopeType::Session, a.pub, ea.pub, msg.data(), msg.size());
    CPPUNIT_ASSERT_THROW(msgpack::unpack((const char*) envelope.data(), envelope.size()), std::exception);
    auto h = hello(a.pub, ea.pub, Blob(Credential::PACKED_SIZE), msg.data(), msg.size());
    CPPUNIT_ASSERT_THROW(msgpack::unpack((const char*) h.data(), h.size()), std::exception);
}

void
TransportTester::testHello()
{
    auto a = KeyPair::generate(), ea = KeyPair::generate();
    auto credential = Authority::generate().issue(a.pub, std::chrono::system_clock::now() + 1h).pack();
    auto msg = message();
    auto h = hello(a.pub, ea.pub, credential, msg.data(), msg.size());
    CPPUNIT_ASSERT_EQUAL(HEADER_SIZE + Credential::PACKED_SIZE + msg.size(), h.size());
    auto header = parseHeader(h.data(), h.size());
    CPPUNIT_ASSERT(header);
    CPPUNIT_ASSERT(header->type == EnvelopeType::Hello);
    CPPUNIT_ASSERT(header->sender == a.pub);
    CPPUNIT_ASSERT(header->ephemeral == ea.pub);
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
