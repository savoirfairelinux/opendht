// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_networkengine.h"

#ifdef _MSC_VER

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(NetworkEngineTester);

void
NetworkEngineTester::setUp()
{}

void
NetworkEngineTester::tearDown()
{}

void
NetworkEngineTester::testDisabledOnMsvc()
{
    CPPUNIT_ASSERT(true);
}

} // namespace test

#else

#include <any>
#include <mutex>

#ifdef _WIN32
#ifdef opendht_EXPORTS
#undef opendht_EXPORTS
#endif
#endif

#include "opendht/node.h"
#include "opendht/network_engine.h"
#include "opendht/network_utils.h"
#include "opendht/utils.h"
#include "opendht/value.h"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wkeyword-macro"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#define private public
#include "opendht/dht.h"
#undef private
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include "../src/parsed_message.h"
#include "../src/search.h"

// Hack to test internal classes
#include "../src/op_cache.cpp"
#include "../src/routing_table.cpp"
#include "../src/dht.cpp"
#include "../src/node.cpp"
#include "../src/node_cache.cpp"
#include "../src/network_engine.cpp"

#include <string>

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(NetworkEngineTester);

using namespace dht;
using namespace dht::net;

static constexpr size_t TEST_MTU {1280};

class TestDatagramSocket : public net::DatagramSocket
{
public:
    TestDatagramSocket()
    {
        bound_.setFamily(AF_INET);
        bound_.setLoopback();
        bound_.setPort(4222);
    }

    int sendTo(const SockAddr& dest, const uint8_t* data, size_t size, bool replied) override
    {
        sends.emplace_back(SentPacket {dest, Blob(data, data + size), replied});
        return 0;
    }

    bool hasIPv4() const override { return true; }
    bool hasIPv6() const override { return false; }
    const SockAddr& getBoundRef(sa_family_t family = AF_UNSPEC) const override
    {
        (void) family;
        return bound_;
    }
    void stop() override {}

    struct SentPacket
    {
        SockAddr dest;
        Blob data;
        bool replied;
    };

    SockAddr bound_;
    std::vector<SentPacket> sends {};
};

static Blob
serializeValue(const std::string& data)
{
    auto val = std::make_shared<Value>((const uint8_t*) data.data(), data.size());
    return packMsg(val);
}

static Blob
makeReplyHeaderPacketBlob(const InfoHash& id, Tid tid, const std::vector<size_t>& valueSizes)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);

    pk.pack_map(3);
    pk.pack(KEY_R);
    pk.pack_map(2);
    pk.pack(KEY_REQ_ID);
    pk.pack(id);
    pk.pack(KEY_REQ_VALUES);
    pk.pack_array(valueSizes.size());
    for (const auto& size : valueSizes)
        pk.pack(size);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_R);

    return {buffer.data(), buffer.data() + buffer.size()};
}

static Blob
makeValueDataPacketBlob(Tid tid, unsigned index, size_t offset, const Blob& data)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);

    pk.pack_map(3);
    pk.pack(KEY_Y);
    pk.pack(KEY_V);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_V);
    pk.pack_map(1);
    pk.pack(index);
    pk.pack_map(2);
    pk.pack("o");
    pk.pack(offset);
    pk.pack("d");
    pk.pack_bin(data.size());
    pk.pack_bin_body((const char*) data.data(), data.size());

    return {buffer.data(), buffer.data() + buffer.size()};
}

static Blob
makeListenPacketBlob(const InfoHash& id, const InfoHash& hash, Tid tid, Tid socketId, const Blob& token)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);

    pk.pack_map(4);
    pk.pack(KEY_A);
    pk.pack_map(5);
    pk.pack(KEY_REQ_ID);
    pk.pack(id);
    pk.pack(KEY_VERSION);
    pk.pack(1);
    pk.pack(KEY_REQ_H);
    pk.pack(hash);
    pk.pack(KEY_REQ_TOKEN);
    packToken(pk, token);
    pk.pack(KEY_REQ_SID);
    pk.pack(socketId);
    pk.pack(KEY_Q);
    pk.pack(QUERY_LISTEN);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_Q);

    return {buffer.data(), buffer.data() + buffer.size()};
}

static SockAddr
makeIPv4(const char* ip, in_port_t port)
{
    SockAddr addr;
    addr.setFamily(AF_INET);
    addr.setAddress(ip);
    addr.setPort(port);
    return addr;
}

static net::NetworkEngine
makeEngine(std::unique_ptr<TestDatagramSocket>&& socket,
           Scheduler& scheduler,
           InfoHash& myid,
           std::mt19937_64& rd,
           int& onNewNodeCalls)
{
    return net::NetworkEngine(
        myid,
        {},
        std::move(socket),
        {},
        rd,
        scheduler,
        [](Sp<net::Request>, net::DhtProtocolException) {},
        [&onNewNodeCalls](const Sp<Node>&, int) { ++onNewNodeCalls; },
        [](const InfoHash&, const SockAddr&) {},
        [](Sp<Node>) { return net::RequestAnswer {}; },
        [](Sp<Node>, const InfoHash&, want_t) { return net::RequestAnswer {}; },
        [](Sp<Node>, const InfoHash&, want_t, const Query&) { return net::RequestAnswer {}; },
        [](Sp<Node>, const InfoHash&, const Blob&, Tid, const Query&, int) { return net::RequestAnswer {}; },
        [](Sp<Node>, const InfoHash&, const Blob&, const std::vector<Sp<Value>>&, const time_point&) {
            return net::RequestAnswer {};
        },
        [](Sp<Node>, const InfoHash&, const Blob&, const Value::Id&) { return net::RequestAnswer {}; });
}

void
NetworkEngineTester::setUp()
{}

void
NetworkEngineTester::tearDown()
{}

void
NetworkEngineTester::testIgnoresUnknownPartialData()
{
    Scheduler scheduler;
    std::mt19937_64 rd(0);
    InfoHash myid = InfoHash::getRandom(rd);
    int onNewNodeCalls = 0;
    auto engine = makeEngine(std::make_unique<TestDatagramSocket>(), scheduler, myid, rd, onNewNodeCalls);

    Blob fragment = {1, 2, 3};
    auto packet = makeValueDataPacketBlob(99, 0, 0, fragment);
    auto from = makeIPv4("127.0.0.2", 5000);

    engine.processMessage(packet.data(), packet.size(), from);

    CPPUNIT_ASSERT_EQUAL((size_t) 0, engine.getPartialCount());
    CPPUNIT_ASSERT_EQUAL(0, onNewNodeCalls);
}

void
NetworkEngineTester::testCompletesPartialSessionFromSameSource()
{
    Scheduler scheduler;
    std::mt19937_64 rd(1);
    InfoHash myid = InfoHash::getRandom(rd);
    InfoHash remoteId = InfoHash::getRandom(rd);
    int onNewNodeCalls = 0;
    auto engine = makeEngine(std::make_unique<TestDatagramSocket>(), scheduler, myid, rd, onNewNodeCalls);

    std::string data(TEST_MTU * 2 + 64, 'z');
    auto serialized = serializeValue(data);
    auto from = makeIPv4("127.0.0.2", 5001);
    auto header = makeReplyHeaderPacketBlob(remoteId, 7, {serialized.size()});

    engine.processMessage(header.data(), header.size(), from);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, engine.getPartialCount());

    for (size_t offset = 0; offset < serialized.size(); offset += TEST_MTU) {
        auto end = std::min(offset + TEST_MTU, serialized.size());
        Blob fragment(serialized.begin() + offset, serialized.begin() + end);
        auto packet = makeValueDataPacketBlob(7, 0, offset, fragment);
        engine.processMessage(packet.data(), packet.size(), from);
    }

    CPPUNIT_ASSERT_EQUAL((size_t) 0, engine.getPartialCount());
    CPPUNIT_ASSERT(onNewNodeCalls > 0);
}

void
NetworkEngineTester::testKeepsSessionForWrongSourceFragment()
{
    Scheduler scheduler;
    std::mt19937_64 rd(2);
    InfoHash myid = InfoHash::getRandom(rd);
    InfoHash remoteId = InfoHash::getRandom(rd);
    int onNewNodeCalls = 0;
    auto engine = makeEngine(std::make_unique<TestDatagramSocket>(), scheduler, myid, rd, onNewNodeCalls);

    std::string data(TEST_MTU + 32, 'w');
    auto serialized = serializeValue(data);
    auto goodFrom = makeIPv4("127.0.0.2", 5002);
    auto badFrom = makeIPv4("127.0.0.3", 5002);
    auto header = makeReplyHeaderPacketBlob(remoteId, 11, {serialized.size()});

    engine.processMessage(header.data(), header.size(), goodFrom);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, engine.getPartialCount());

    auto firstEnd = std::min(TEST_MTU, serialized.size());
    Blob firstFragment(serialized.begin(), serialized.begin() + firstEnd);
    auto firstPacket = makeValueDataPacketBlob(11, 0, 0, firstFragment);
    engine.processMessage(firstPacket.data(), firstPacket.size(), badFrom);

    CPPUNIT_ASSERT_EQUAL((size_t) 1, engine.getPartialCount());
    CPPUNIT_ASSERT_EQUAL(0, onNewNodeCalls);

    engine.processMessage(firstPacket.data(), firstPacket.size(), goodFrom);
    if (firstEnd < serialized.size()) {
        Blob tail(serialized.begin() + firstEnd, serialized.end());
        auto tailPacket = makeValueDataPacketBlob(11, 0, firstEnd, tail);
        engine.processMessage(tailPacket.data(), tailPacket.size(), goodFrom);
    }

    CPPUNIT_ASSERT_EQUAL((size_t) 0, engine.getPartialCount());
    CPPUNIT_ASSERT(onNewNodeCalls > 0);
}

void
NetworkEngineTester::testListenConfirmationCarriesToken()
{
    Scheduler scheduler;
    std::mt19937_64 rd(3);
    InfoHash myid = InfoHash::getRandom(rd);
    InfoHash remoteId = InfoHash::getRandom(rd);
    InfoHash hash = InfoHash::getRandom(rd);
    Blob requestToken {0x01, 0x02, 0x03, 0x04};
    Blob responseToken {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    int onNewNodeCalls = 0;
    net::NetworkConfig config {};
    config.max_req_per_sec = -1;
    config.max_peer_req_per_sec = -1;

    auto socket = std::make_unique<TestDatagramSocket>();
    auto* socketPtr = socket.get();
    auto engine = net::NetworkEngine(
        myid,
        config,
        std::move(socket),
        {},
        rd,
        scheduler,
        [](Sp<net::Request>, net::DhtProtocolException) {},
        [&onNewNodeCalls](const Sp<Node>&, int) { ++onNewNodeCalls; },
        [](const InfoHash&, const SockAddr&) {},
        [](Sp<Node>) { return net::RequestAnswer {}; },
        [](Sp<Node>, const InfoHash&, want_t) { return net::RequestAnswer {}; },
        [](Sp<Node>, const InfoHash&, want_t, const Query&) { return net::RequestAnswer {}; },
        [responseToken](Sp<Node>, const InfoHash&, const Blob&, Tid, const Query&, int) {
            net::RequestAnswer answer {};
            answer.ntoken = responseToken;
            return answer;
        },
        [](Sp<Node>, const InfoHash&, const Blob&, const std::vector<Sp<Value>>&, const time_point&) {
            return net::RequestAnswer {};
        },
        [](Sp<Node>, const InfoHash&, const Blob&, const Value::Id&) { return net::RequestAnswer {}; });

    auto from = makeIPv4("127.0.0.2", 5003);
    auto packet = makeListenPacketBlob(remoteId, hash, 17, 23, requestToken);

    engine.processMessage(packet.data(), packet.size(), from);

    CPPUNIT_ASSERT_EQUAL((size_t) 1, socketPtr->sends.size());

    const auto& sent = socketPtr->sends.front();
    CPPUNIT_ASSERT(sent.dest == from);

    auto replyObject = msgpack::unpack((const char*) sent.data.data(), sent.data.size());
    ParsedMessage reply;
    reply.msgpack_unpack(replyObject.get());

    CPPUNIT_ASSERT(reply.type == MessageType::Reply);
    CPPUNIT_ASSERT_EQUAL(myid, reply.id);
    CPPUNIT_ASSERT(reply.token == responseToken);
}

void
NetworkEngineTester::testListenConfirmationUpdatesSearchNodeToken()
{
    Config config {};
    config.max_req_per_sec = -1;
    config.max_peer_req_per_sec = -1;

    auto rd = std::make_unique<std::mt19937_64>(6);
    Dht localDht(std::make_unique<TestDatagramSocket>(), config, {}, std::move(rd));

    auto node = std::make_shared<Node>(InfoHash::getRandom(localDht.rd),
                                       makeIPv4("127.0.0.2", 5006),
                                       localDht.rd,
                                       false);
    auto sr = std::make_shared<Dht::Search>();
    auto query = std::make_shared<Query>();
    ValueCallback valueCallback = [](const std::vector<std::shared_ptr<Value>>&, bool) {
        return true;
    };

    sr->id = InfoHash::getRandom(localDht.rd);
    sr->af = AF_INET;
    sr->nextSearchStep = localDht.scheduler.add(time_point::max(), [] {});
    sr->listeners.emplace(1, Dht::Search::SearchListener {query, valueCallback, {}});

    auto searchNode = std::make_unique<Dht::SearchNode>(node);
    auto socketId = node->openSocket([](const Sp<Node>&, net::RequestAnswer&&) {});
    searchNode->listenStatus.emplace(std::piecewise_construct,
                                     std::forward_as_tuple(query),
                                     std::forward_as_tuple(valueCallback, dht::SyncCallback {}, socketId));
    auto* searchNodePtr = sr->nodes.emplace_back(std::move(searchNode)).get();

    CPPUNIT_ASSERT(searchNodePtr->token.empty());
    CPPUNIT_ASSERT(!searchNodePtr->isSynced(localDht.scheduler.time()));

    net::RequestAnswer answer {};
    answer.ntoken = Blob {0xaa, 0xbb, 0xcc, 0xdd};

    localDht.onListenDone(node, answer, sr);

    CPPUNIT_ASSERT(searchNodePtr->token == answer.ntoken);
    /* last_get_reply should NOT be updated by listen confirmation,
       so that periodic find_node requests still refresh the search table. */
    CPPUNIT_ASSERT(searchNodePtr->last_get_reply == time_point::min());
    CPPUNIT_ASSERT(!searchNodePtr->isSynced(localDht.scheduler.time()));
}

void
NetworkEngineTester::testListenReopensSocketAfterNodeExpiration()
{
    Config config {};
    config.max_req_per_sec = -1;
    config.max_peer_req_per_sec = -1;

    auto rd = std::make_unique<std::mt19937_64>(4);
    Dht localDht(std::make_unique<TestDatagramSocket>(), config, {}, std::move(rd));

    auto node = std::make_shared<Node>(InfoHash::getRandom(localDht.rd),
                                       makeIPv4("127.0.0.2", 5004),
                                       localDht.rd,
                                       false);
    auto sr = std::make_shared<Dht::Search>();
    auto query = std::make_shared<Query>();
    ValueCallback valueCallback = [](const std::vector<std::shared_ptr<Value>>&, bool) {
        return true;
    };
    dht::SyncCallback syncCallback {};

    sr->id = InfoHash::getRandom(localDht.rd);
    sr->af = AF_INET;
    sr->listeners.emplace(1, Dht::Search::SearchListener {query, valueCallback, {}});

    auto searchNode = std::make_unique<Dht::SearchNode>(node);
    auto staleSocketId = node->openSocket([](const Sp<Node>&, net::RequestAnswer&&) {});
    auto status = searchNode->listenStatus
                      .emplace(std::piecewise_construct,
                               std::forward_as_tuple(query),
                               std::forward_as_tuple(valueCallback, syncCallback, staleSocketId))
                      .first;
    status->second.req = std::make_shared<net::Request>(net::Request::State::COMPLETED);
    status->second.req->reply_time = time_point::min();

    node->setExpired();
    CPPUNIT_ASSERT(!node->getSocket(staleSocketId));

    auto* searchNodePtr = sr->nodes.emplace_back(std::move(searchNode)).get();
    searchNodePtr->token = Blob {0x42};
    searchNodePtr->last_get_reply = localDht.scheduler.time();

    localDht.searchSynchedNodeListen(sr, *searchNodePtr);

    auto listenIt = searchNodePtr->listenStatus.find(query);
    CPPUNIT_ASSERT(listenIt != searchNodePtr->listenStatus.end());
    CPPUNIT_ASSERT(listenIt->second.req);
    CPPUNIT_ASSERT(listenIt->second.socketId);
    CPPUNIT_ASSERT(listenIt->second.socketId != staleSocketId);
    CPPUNIT_ASSERT(node->getSocket(listenIt->second.socketId));
}

void
NetworkEngineTester::testUnauthorizedListenFlushClearsListenState()
{
    Config config {};
    config.max_req_per_sec = -1;
    config.max_peer_req_per_sec = -1;

    auto rd = std::make_unique<std::mt19937_64>(5);
    Dht localDht(std::make_unique<TestDatagramSocket>(), config, {}, std::move(rd));

    auto node = std::make_shared<Node>(InfoHash::getRandom(localDht.rd),
                                       makeIPv4("127.0.0.2", 5005),
                                       localDht.rd,
                                       false);
    auto sr = std::make_shared<Dht::Search>();
    auto query = std::make_shared<Query>();
    ValueCallback valueCallback = [](const std::vector<std::shared_ptr<Value>>&, bool) {
        return true;
    };
    dht::SyncCallback syncCallback {};

    sr->id = InfoHash::getRandom(localDht.rd);
    sr->af = AF_INET;

    auto searchNode = std::make_unique<Dht::SearchNode>(node);
    auto socketId = node->openSocket([](const Sp<Node>&, net::RequestAnswer&&) {});
    auto listenIt = searchNode->listenStatus
                        .emplace(std::piecewise_construct,
                                 std::forward_as_tuple(query),
                                 std::forward_as_tuple(valueCallback, syncCallback, socketId))
                        .first;
    listenIt->second.req = std::make_shared<net::Request>();
    listenIt->second.refresh = localDht.scheduler.add(localDht.scheduler.time() + std::chrono::seconds(1), [] {});
    searchNode->token = Blob {0x10, 0x11, 0x12};
    searchNode->last_get_reply = localDht.scheduler.time();
    auto* searchNodePtr = sr->nodes.emplace_back(std::move(searchNode)).get();

    localDht.searches(AF_INET).emplace(sr->id, sr);

    auto failingReq = std::make_shared<net::Request>(
        MessageType::Listen,
        node->getNewTid(),
        node,
        Blob {},
        [](const net::Request&, ParsedMessage&&) {},
        [](const net::Request&, bool) {});

    localDht.onError(failingReq,
                     net::DhtProtocolException {net::DhtProtocolException::UNAUTHORIZED,
                                                net::DhtProtocolException::LISTEN_WRONG_TOKEN});

    CPPUNIT_ASSERT(searchNodePtr->token.empty());
    CPPUNIT_ASSERT(searchNodePtr->last_get_reply == time_point::min());

    auto listenStatusIt = searchNodePtr->listenStatus.find(query);
    CPPUNIT_ASSERT(listenStatusIt != searchNodePtr->listenStatus.end());
    CPPUNIT_ASSERT(!listenStatusIt->second.req);
    CPPUNIT_ASSERT(!listenStatusIt->second.refresh);
}

} // namespace test

#endif