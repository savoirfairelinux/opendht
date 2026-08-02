// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_mdns.h"

#include "../src/mdns.h"

#include <array>
#include <string>

namespace test {

using namespace dht::mdns;

CPPUNIT_TEST_SUITE_REGISTRATION(MdnsTester);

void
MdnsTester::testName()
{
    const auto name = Name::fromString("Node._opendht._udp.local.");
    CPPUNIT_ASSERT_EQUAL(std::string("Node._opendht._udp.local."), name.toString());
    CPPUNIT_ASSERT(name == Name::fromString("node._OpenDHT._UDP.LOCAL"));
    CPPUNIT_ASSERT_THROW(Name::fromString("bad..local."), ParseError);
    CPPUNIT_ASSERT_THROW(Name::fromString(std::string(64, 'a') + ".local."), ParseError);
}

void
MdnsTester::testRecordRoundTrip()
{
    const auto service = Name::fromString("_opendht._udp.local.");
    const auto instance = Name::fromString("0123456789abcdef0123456789abcdef01234567._opendht._udp.local.");
    const auto host = Name::fromString("0123456789abcdef0123456789abcdef01234567.local.");

    Message message;
    message.response = true;
    message.authoritative = true;
    message.answers.push_back({service, Type::PTR, CLASS_IN, false, 4500, PtrData {instance}});
    message.additionals.push_back({instance, Type::SRV, CLASS_IN, true, 120, SrvData {0, 0, 4222, host}});
    message.additionals.push_back({instance,
                                   Type::TXT,
                                   CLASS_IN,
                                   true,
                                   4500,
                                   TxtData {{{'t', 'x', 't', 'v', 'e', 'r', 's', '=', '1'},
                                             {'n', 'e', 't', '=', '0'}}}});
    message.additionals.push_back({host, Type::A, CLASS_IN, true, 120, AData {{192, 0, 2, 1}}});
    message.additionals.push_back({host,
                                   Type::AAAA,
                                   CLASS_IN,
                                   true,
                                   120,
                                   AaaaData {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}});
    message.additionals.push_back(
        {host, Type::NSEC, CLASS_IN, true, 120, NsecData {host, {Type::A, Type::AAAA}}});

    const auto packet = encode(message);
    const auto decoded = decode(packet.data(), packet.size());

    CPPUNIT_ASSERT(decoded.response);
    CPPUNIT_ASSERT(decoded.authoritative);
    CPPUNIT_ASSERT_EQUAL(size_t(1), decoded.answers.size());
    CPPUNIT_ASSERT_EQUAL(size_t(5), decoded.additionals.size());
    CPPUNIT_ASSERT(decoded == message);
}

void
MdnsTester::testCompression()
{
    Message message;
    message.questions.push_back({Name::fromString("_opendht._udp.local."), Type::PTR, CLASS_IN, false});
    message.questions.push_back(
        {Name::fromString("node._opendht._udp.local."), Type::SRV, CLASS_IN, false});

    const auto packet = encode(message);
    CPPUNIT_ASSERT(std::find(packet.begin(), packet.end(), uint8_t {0xc0}) != packet.end());
    CPPUNIT_ASSERT(decode(packet.data(), packet.size()) == message);
}

void
MdnsTester::testMalformedPackets()
{
    const std::array<uint8_t, 3> truncated {{0, 0, 0}};
    CPPUNIT_ASSERT_THROW(decode(truncated.data(), truncated.size()), ParseError);

    const std::array<uint8_t, 18> compressionLoop {{
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0xc0, 0x0c, 0, static_cast<uint8_t>(Type::PTR), 0, CLASS_IN,
    }};
    CPPUNIT_ASSERT_THROW(decode(compressionLoop.data(), compressionLoop.size()), ParseError);
}

void
MdnsTester::testPacketSizeLimit()
{
    std::array<uint8_t, MAX_PACKET_SIZE + 1> oversized {};
    CPPUNIT_ASSERT_THROW(decode(oversized.data(), oversized.size()), ParseError);
}

} // namespace test