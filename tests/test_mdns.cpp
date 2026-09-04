// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_mdns.h"

#include "../src/peer_discovery/dns_sd.h"
#include "../src/peer_discovery/mdns.h"
#include "../src/peer_discovery/mdns_transport.h"

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
    message.additionals.push_back({
        instance, Type::SRV, CLASS_IN, true, 120, SrvData {0, 0, 4222, host}
    });
    message.additionals.push_back(
        {instance,
         Type::TXT,
         CLASS_IN,
         true,
         4500,
         TxtData {{{'t', 'x', 't', 'v', 'e', 'r', 's', '=', '1'}, {'n', 'e', 't', '=', '0'}}}});
    message.additionals.push_back({host, Type::A, CLASS_IN, true, 120, AData {{192, 0, 2, 1}}});
    message.additionals.push_back(
        {host, Type::AAAA, CLASS_IN, true, 120, AaaaData {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}});
    message.additionals.push_back({
        host, Type::NSEC, CLASS_IN, true, 120, NsecData {host, {Type::A, Type::AAAA}}
    });

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
    message.questions.push_back({Name::fromString("node._opendht._udp.local."), Type::SRV, CLASS_IN, false});

    const auto packet = encode(message);
    CPPUNIT_ASSERT(std::find(packet.begin(), packet.end(), uint8_t {0xc0}) != packet.end());
    CPPUNIT_ASSERT(decode(packet.data(), packet.size()) == message);
}

void
MdnsTester::testMalformedPackets()
{
    const std::array<uint8_t, 3> truncated {
        {0, 0, 0}
    };
    CPPUNIT_ASSERT_THROW(decode(truncated.data(), truncated.size()), ParseError);

    const std::array<uint8_t, 18> compressionLoop {
        {
         0, 0,
         0, 0,
         0, 1,
         0, 0,
         0, 0,
         0, 0,
         0xc0, 0x0c,
         0, static_cast<uint8_t>(Type::PTR),
         0, CLASS_IN,
         }
    };
    CPPUNIT_ASSERT_THROW(decode(compressionLoop.data(), compressionLoop.size()), ParseError);
}

void
MdnsTester::testPacketSizeLimit()
{
    std::array<uint8_t, MAX_PACKET_SIZE + 1> oversized {};
    CPPUNIT_ASSERT_THROW(decode(oversized.data(), oversized.size()), ParseError);
}

void
MdnsTester::testDnsSdAdvertisement()
{
    dns_sd::Service service;
    service.nodeId = dht::InfoHash("0123456789abcdef0123456789abcdef01234567");
    service.network = 42;
    service.port = 4222;
    service.addresses.emplace_back(AData {
        {192, 0, 2, 1}
    });
    service.addresses.emplace_back(AaaaData {
        {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
    });

    const auto message = dns_sd::announcement(service);
    CPPUNIT_ASSERT(message.response);
    CPPUNIT_ASSERT(message.authoritative);
    CPPUNIT_ASSERT_EQUAL(size_t(1), message.answers.size());
    CPPUNIT_ASSERT_EQUAL(size_t(4), message.additionals.size());
    CPPUNIT_ASSERT_EQUAL(std::string("_opendht._udp.local."), message.answers.front().name.toString());

    const auto resolved = dns_sd::resolve(message);
    CPPUNIT_ASSERT(resolved);
    CPPUNIT_ASSERT_EQUAL(service.nodeId, resolved->nodeId);
    CPPUNIT_ASSERT_EQUAL(service.network, resolved->network);
    CPPUNIT_ASSERT_EQUAL(service.port, resolved->port);
    CPPUNIT_ASSERT_EQUAL(service.addresses.size(), resolved->addresses.size());
}

void
MdnsTester::testDnsSdGoodbye()
{
    dns_sd::Service service;
    service.nodeId = dht::InfoHash("0123456789abcdef0123456789abcdef01234567");
    service.port = 4222;
    service.addresses.emplace_back(AData {
        {192, 0, 2, 1}
    });

    const auto message = dns_sd::goodbye(service);
    CPPUNIT_ASSERT(std::all_of(message.answers.begin(), message.answers.end(), [](const auto& record) {
        return record.ttl == 0;
    }));
    CPPUNIT_ASSERT(std::all_of(message.additionals.begin(), message.additionals.end(), [](const auto& record) {
        return record.ttl == 0;
    }));
}

void
MdnsTester::testDnsSdValidation()
{
    dns_sd::Service service;
    service.nodeId = dht::InfoHash("0123456789abcdef0123456789abcdef01234567");
    service.network = 42;
    service.port = 4222;
    service.addresses.emplace_back(AData {
        {192, 0, 2, 1}
    });

    auto message = dns_sd::announcement(service);
    auto& txt = std::get<TxtData>(message.additionals[1].data);
    txt.strings.push_back({'n', 'e', 't', '=', '4', '3'});
    CPPUNIT_ASSERT(not dns_sd::resolve(message));

    message = dns_sd::announcement(service);
    auto& srv = std::get<SrvData>(message.additionals[0].data);
    srv.target = Name::fromString("other.local.");
    CPPUNIT_ASSERT(not dns_sd::resolve(message));

    CPPUNIT_ASSERT_THROW(dns_sd::announcement({}), ParseError);
}

void
MdnsTester::testDnsSdQueryResponse()
{
    dns_sd::Service service;
    service.nodeId = dht::InfoHash("0123456789abcdef0123456789abcdef01234567");
    service.network = 42;
    service.port = 4222;
    service.addresses.emplace_back(AData {
        {192, 0, 2, 1}
    });

    const auto query = dns_sd::browseQuery();
    CPPUNIT_ASSERT(not query.response);
    CPPUNIT_ASSERT_EQUAL(size_t(1), query.questions.size());
    CPPUNIT_ASSERT(query.questions.front().name == dns_sd::serviceName());
    CPPUNIT_ASSERT(query.questions.front().type == Type::PTR);

    const auto response = dns_sd::respond(query, service);
    CPPUNIT_ASSERT(response);
    CPPUNIT_ASSERT(dns_sd::resolve(*response));

    auto knownAnswerQuery = query;
    knownAnswerQuery.answers = response->answers;
    CPPUNIT_ASSERT(not dns_sd::respond(knownAnswerQuery, service));

    knownAnswerQuery.answers.front().ttl = dns_sd::SERVICE_RECORD_TTL / 2;
    CPPUNIT_ASSERT(dns_sd::respond(knownAnswerQuery, service));

    Message metaQuery;
    const auto metaName = Name::fromString("_services._dns-sd._udp.local.");
    metaQuery.questions.push_back({metaName, Type::PTR, CLASS_IN, false});
    const auto metaResponse = dns_sd::respond(metaQuery, service);
    CPPUNIT_ASSERT(metaResponse);
    CPPUNIT_ASSERT_EQUAL(size_t(1), metaResponse->answers.size());
    CPPUNIT_ASSERT(metaResponse->answers.front().name == metaName);
    CPPUNIT_ASSERT(std::get<PtrData>(metaResponse->answers.front().data).name == dns_sd::serviceName());
    CPPUNIT_ASSERT(metaResponse->additionals.empty());

    metaQuery.answers = metaResponse->answers;
    CPPUNIT_ASSERT(not dns_sd::respond(metaQuery, service));
}

void
MdnsTester::testDnsSdCache()
{
    dns_sd::Service service;
    service.nodeId = dht::InfoHash("0123456789abcdef0123456789abcdef01234567");
    service.network = 42;
    service.port = 4222;
    service.addresses.emplace_back(AData {
        {192, 0, 2, 1}
    });

    auto now = dns_sd::Cache::Clock::now();
    dns_sd::Cache cache([&] { return now; });
    auto ptr = dns_sd::announcement(service);
    auto details = ptr;
    ptr.additionals.clear();
    details.answers.clear();

    CPPUNIT_ASSERT(cache.update(ptr).empty());
    const auto discovered = cache.update(details);
    CPPUNIT_ASSERT_EQUAL(size_t(1), discovered.size());
    CPPUNIT_ASSERT_EQUAL(service.nodeId, discovered.front().nodeId);
    CPPUNIT_ASSERT_EQUAL(size_t(1), cache.services().size());

    now += std::chrono::seconds(dns_sd::HOST_RECORD_TTL + 1);
    CPPUNIT_ASSERT(cache.services().empty());
}

void
MdnsTester::testInterfaceScoping()
{
    const std::vector<InterfaceAddress> addresses {
        {1, 1, asio::ip::make_address("192.0.2.1"), true,  false},
        {1, 1, asio::ip::make_address("fe80::1"),   true,  false},
        {2, 2, asio::ip::make_address("fe80::2"),   true,  false},
        {3, 3, asio::ip::make_address("fe80::3"),   false, false},
        {4, 4, asio::ip::make_address("::1"),       true,  true },
    };

    const auto interfaces = groupInterfaces(addresses);
    CPPUNIT_ASSERT_EQUAL(size_t(2), interfaces.size());
    CPPUNIT_ASSERT_EQUAL(InterfaceId {1}, interfaces[0].id);
    CPPUNIT_ASSERT_EQUAL(size_t(2), interfaces[0].addresses.size());
    CPPUNIT_ASSERT_EQUAL(InterfaceId {2}, interfaces[1].id);
    CPPUNIT_ASSERT_EQUAL(size_t(1), interfaces[1].addresses.size());

    dns_sd::Service service;
    service.nodeId = dht::InfoHash("0123456789abcdef0123456789abcdef01234567");
    service.port = 4222;
    service.addresses = interfaces[0].addresses;
    const auto announcement = dns_sd::announcement(service);
    const auto resolved = dns_sd::resolve(announcement);
    CPPUNIT_ASSERT(resolved);
    CPPUNIT_ASSERT(resolved->addresses == interfaces[0].addresses);
}

} // namespace test