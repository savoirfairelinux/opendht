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
#include "opendht/network_utils.h"
#include "opendht/transport.h"
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
#include "opendht/network_engine.h"
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

#include <sstream>
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

static Blob
makeFindPacketBlob(const InfoHash& id, const InfoHash& target, Tid tid)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);

    pk.pack_map(4);
    pk.pack(KEY_A);
    pk.pack_map(2);
    pk.pack(KEY_REQ_ID);
    pk.pack(id);
    pk.pack(KEY_REQ_TARGET);
    pk.pack(target);
    pk.pack(KEY_Q);
    pk.pack(QUERY_FIND);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_Q);

    return {buffer.data(), buffer.data() + buffer.size()};
}

static void
parseMessage(ParsedMessage& msg, const Blob& data)
{
    auto object = msgpack::unpack((const char*) data.data(), data.size());
    msg.msgpack_unpack(object.get());
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
    net::NetworkConfig config {};
    config.max_req_per_sec = -1;
    config.max_peer_req_per_sec = -1;
    return net::NetworkEngine(
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
        [](Sp<Node>, const InfoHash&, Tid, const Query&, int) { return net::RequestAnswer {}; },
        [](Sp<Node>, const InfoHash&, const std::vector<Sp<Value>>&, const time_point&) {
            return net::RequestAnswer {};
        },
        [](Sp<Node>, const InfoHash&, const Value::Id&) { return net::RequestAnswer {}; });
}

static Sp<Node>
addPendingGetRequest(net::NetworkEngine& engine, const InfoHash& id, const SockAddr& addr, Tid tid)
{
    auto node = engine.insertNode(id, addr);
    auto request = std::make_shared<net::Request>(
        MessageType::GetValues,
        tid,
        node,
        Blob {},
        [](const net::Request&, ParsedMessage&&) {},
        [](const net::Request&, bool) {});
    node->requested(request);
    return node;
}

void
NetworkEngineTester::setUp()
{}

void
NetworkEngineTester::tearDown()
{}

void
NetworkEngineTester::testNodeTransportState()
{
    std::mt19937_64 rd(0);
    const auto id = InfoHash::getRandom(rd);
    const auto address = makeIPv4("127.0.0.2", 5000);
    Node node(id, address, rd);
    const auto prefix = fmt::format("{} {:<21}", id, address.toString());
    auto check = [&](const std::string& state) {
        CPPUNIT_ASSERT_EQUAL(prefix + " " + state, node.toString());
        CPPUNIT_ASSERT_EQUAL(prefix.size() + size_t {5}, node.toString().size());
        std::ostringstream out;
        out << node;
        CPPUNIT_ASSERT_EQUAL(node.toString(), out.str());
    };

    check("[P-]");
    auto peer = std::make_shared<transport::Peer>(transport::KeyPair::generate().pub);
    node.setTransport(peer);
    check("[K-]");

    const auto ephemeral = transport::KeyPair::generate().pub;
    peer->setEphemeral(ephemeral);
    check("[K-]");
    peer->setEphemeral(ephemeral, makeIPv4("127.0.0.3", 5000));
    check("[K-]");
    peer->setEphemeral(ephemeral, address);
    check("[A-]");

    peer->authorizedUntil = std::chrono::system_clock::now() + std::chrono::hours(1);
    check("[A+]");
    peer->authorizedUntil = std::chrono::system_clock::now() - std::chrono::hours(1);
    check("[A!]");

    peer->authorizedUntil = {};
    peer->resetEphemeral();
    check("[K-]");
    node.setTransport({});
    check("[P-]");
}

void
NetworkEngineTester::testCompletesPartialSessionWithDataBeforeHeader()
{
    Scheduler scheduler;
    std::mt19937_64 rd(0);
    InfoHash myid = InfoHash::getRandom(rd);
    InfoHash remoteId = InfoHash::getRandom(rd);
    int onNewNodeCalls = 0;
    auto engine = makeEngine(std::make_unique<TestDatagramSocket>(), scheduler, myid, rd, onNewNodeCalls);

    auto serialized = serializeValue("fragment before header");
    auto from = makeIPv4("127.0.0.2", 5000);
    addPendingGetRequest(engine, remoteId, from, 99);
    auto initialOnNewNodeCalls = onNewNodeCalls;
    auto fragment = makeValueDataPacketBlob(99, 0, 0, serialized);
    auto header = makeReplyHeaderPacketBlob(remoteId, 99, {serialized.size()});

    engine.processMessage(fragment.data(), fragment.size(), from);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, engine.getPartialCount());
    CPPUNIT_ASSERT_EQUAL(initialOnNewNodeCalls, onNewNodeCalls);

    engine.processMessage(header.data(), header.size(), from);

    CPPUNIT_ASSERT_EQUAL((size_t) 0, engine.getPartialCount());
    CPPUNIT_ASSERT(onNewNodeCalls > initialOnNewNodeCalls);
}

void
NetworkEngineTester::testBuffersLargeValueBeforeHeader()
{
    Scheduler scheduler;
    std::mt19937_64 rd(8);
    InfoHash myid = InfoHash::getRandom(rd);
    InfoHash remoteId = InfoHash::getRandom(rd);
    int onNewNodeCalls = 0;
    auto engine = makeEngine(std::make_unique<TestDatagramSocket>(), scheduler, myid, rd, onNewNodeCalls);

    auto serialized = serializeValue(std::string(57 * 1024, 'l'));
    auto from = makeIPv4("127.0.0.2", 5008);
    addPendingGetRequest(engine, remoteId, from, 101);
    auto initialOnNewNodeCalls = onNewNodeCalls;
    for (size_t offset = 0; offset < serialized.size(); offset += TEST_MTU) {
        auto end = std::min(offset + TEST_MTU, serialized.size());
        Blob data(serialized.begin() + offset, serialized.begin() + end);
        auto fragment = makeValueDataPacketBlob(101, 0, offset, data);
        engine.processMessage(fragment.data(), fragment.size(), from);
    }
    CPPUNIT_ASSERT_EQUAL((size_t) 1, engine.getPartialCount());

    auto header = makeReplyHeaderPacketBlob(remoteId, 101, {serialized.size()});
    engine.processMessage(header.data(), header.size(), from);

    CPPUNIT_ASSERT_EQUAL((size_t) 0, engine.getPartialCount());
    CPPUNIT_ASSERT(onNewNodeCalls > initialOnNewNodeCalls);
}

void
NetworkEngineTester::testIgnoresEmptyPartialData()
{
    Scheduler scheduler;
    std::mt19937_64 rd(7);
    InfoHash myid = InfoHash::getRandom(rd);
    int onNewNodeCalls = 0;
    auto engine = makeEngine(std::make_unique<TestDatagramSocket>(), scheduler, myid, rd, onNewNodeCalls);

    auto packet = makeValueDataPacketBlob(100, 0, 0, {});
    auto from = makeIPv4("127.0.0.2", 5007);
    engine.processMessage(packet.data(), packet.size(), from);

    CPPUNIT_ASSERT_EQUAL((size_t) 0, engine.getPartialCount());
    CPPUNIT_ASSERT_EQUAL(0, onNewNodeCalls);
}

void
NetworkEngineTester::testRejectsUnsolicitedPartialReply()
{
    Scheduler scheduler;
    std::mt19937_64 rd(9);
    InfoHash myid = InfoHash::getRandom(rd);
    InfoHash remoteId = InfoHash::getRandom(rd);
    int onNewNodeCalls = 0;
    auto engine = makeEngine(std::make_unique<TestDatagramSocket>(), scheduler, myid, rd, onNewNodeCalls);

    auto from = makeIPv4("127.0.0.2", 5009);
    auto header = makeReplyHeaderPacketBlob(remoteId, 102, {TEST_MTU});
    engine.processMessage(header.data(), header.size(), from);

    CPPUNIT_ASSERT_EQUAL((size_t) 0, engine.getPartialCount());
    CPPUNIT_ASSERT_EQUAL((size_t) 0, engine.getNodeCacheSize());
}

void
NetworkEngineTester::testDropsMalformedCompletedPartialMessage()
{
    Scheduler scheduler;
    std::mt19937_64 rd(10);
    InfoHash myid = InfoHash::getRandom(rd);
    InfoHash remoteId = InfoHash::getRandom(rd);
    int onNewNodeCalls = 0;
    auto engine = makeEngine(std::make_unique<TestDatagramSocket>(), scheduler, myid, rd, onNewNodeCalls);

    auto from = makeIPv4("127.0.0.2", 5010);
    addPendingGetRequest(engine, remoteId, from, 103);
    Blob malformed {0xc1};
    auto header = makeReplyHeaderPacketBlob(remoteId, 103, {malformed.size()});
    auto fragment = makeValueDataPacketBlob(103, 0, 0, malformed);

    engine.processMessage(header.data(), header.size(), from);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, engine.getPartialCount());
    engine.processMessage(fragment.data(), fragment.size(), from);

    CPPUNIT_ASSERT_EQUAL((size_t) 0, engine.getPartialCount());

    auto earlyFrom = makeIPv4("127.0.0.2", 5011);
    addPendingGetRequest(engine, remoteId, earlyFrom, 104);
    auto earlyHeader = makeReplyHeaderPacketBlob(remoteId, 104, {malformed.size()});
    auto earlyFragment = makeValueDataPacketBlob(104, 0, 0, malformed);

    engine.processMessage(earlyFragment.data(), earlyFragment.size(), earlyFrom);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, engine.getPartialCount());
    engine.processMessage(earlyHeader.data(), earlyHeader.size(), earlyFrom);

    CPPUNIT_ASSERT_EQUAL((size_t) 0, engine.getPartialCount());
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
    addPendingGetRequest(engine, remoteId, from, 7);
    auto initialOnNewNodeCalls = onNewNodeCalls;
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
    CPPUNIT_ASSERT(onNewNodeCalls > initialOnNewNodeCalls);
}

void
NetworkEngineTester::testSeparatesPartialSessionsBySource()
{
    Scheduler scheduler;
    std::mt19937_64 rd(2);
    InfoHash myid = InfoHash::getRandom(rd);
    InfoHash firstRemoteId = InfoHash::getRandom(rd);
    InfoHash secondRemoteId = InfoHash::getRandom(rd);
    int onNewNodeCalls = 0;
    auto engine = makeEngine(std::make_unique<TestDatagramSocket>(), scheduler, myid, rd, onNewNodeCalls);

    auto serialized = serializeValue("same transaction, different peers");
    auto firstFrom = makeIPv4("127.0.0.2", 5002);
    auto secondFrom = makeIPv4("127.0.0.3", 5002);
    addPendingGetRequest(engine, firstRemoteId, firstFrom, 11);
    addPendingGetRequest(engine, secondRemoteId, secondFrom, 11);
    auto initialOnNewNodeCalls = onNewNodeCalls;
    auto firstHeader = makeReplyHeaderPacketBlob(firstRemoteId, 11, {serialized.size()});
    auto secondHeader = makeReplyHeaderPacketBlob(secondRemoteId, 11, {serialized.size()});

    engine.processMessage(firstHeader.data(), firstHeader.size(), firstFrom);
    engine.processMessage(secondHeader.data(), secondHeader.size(), secondFrom);
    CPPUNIT_ASSERT_EQUAL((size_t) 2, engine.getPartialCount());

    auto fragment = makeValueDataPacketBlob(11, 0, 0, serialized);
    engine.processMessage(fragment.data(), fragment.size(), firstFrom);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, engine.getPartialCount());
    engine.processMessage(fragment.data(), fragment.size(), secondFrom);

    CPPUNIT_ASSERT_EQUAL((size_t) 0, engine.getPartialCount());
    CPPUNIT_ASSERT(onNewNodeCalls > initialOnNewNodeCalls);
}

void
NetworkEngineTester::testPlaintextListenRequiresToken()
{
    Scheduler scheduler;
    std::mt19937_64 rd(3);
    InfoHash myid = InfoHash::getRandom(rd);
    InfoHash remoteId = InfoHash::getRandom(rd);
    InfoHash hash = InfoHash::getRandom(rd);
    int listens = 0;
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
        [](const Sp<Node>&, int) {},
        [](const InfoHash&, const SockAddr&) {},
        [](Sp<Node>) { return net::RequestAnswer {}; },
        [](Sp<Node>, const InfoHash&, want_t) { return net::RequestAnswer {}; },
        [](Sp<Node>, const InfoHash&, want_t, const Query&) { return net::RequestAnswer {}; },
        [&listens](Sp<Node>, const InfoHash&, Tid, const Query&, int) {
            ++listens;
            return net::RequestAnswer {};
        },
        [](Sp<Node>, const InfoHash&, const std::vector<Sp<Value>>&, const time_point&) {
            return net::RequestAnswer {};
        },
        [](Sp<Node>, const InfoHash&, const Value::Id&) { return net::RequestAnswer {}; });

    auto from = makeIPv4("127.0.0.2", 5003);
    auto forged = makeListenPacketBlob(remoteId, hash, 17, 23, Blob(32, 0x42));
    engine.processMessage(forged.data(), forged.size(), from);
    CPPUNIT_ASSERT_EQUAL(0, listens);
    ParsedMessage error;
    parseMessage(error, socketPtr->sends.at(0).data);
    CPPUNIT_ASSERT(error.type == MessageType::Error);
    CPPUNIT_ASSERT_EQUAL(DhtProtocolException::UNAUTHORIZED, error.error_code);

    // Answers carry a token for the address they are sent to
    auto find = makeFindPacketBlob(remoteId, hash, 18);
    engine.processMessage(find.data(), find.size(), from);
    ParsedMessage answer;
    parseMessage(answer, socketPtr->sends.at(1).data);
    CPPUNIT_ASSERT_EQUAL((size_t) 32, answer.token.size());

    auto other = makeIPv4("127.0.0.3", 5003);
    auto stolen = makeListenPacketBlob(InfoHash::getRandom(rd), hash, 19, 23, answer.token);
    engine.processMessage(stolen.data(), stolen.size(), other);
    CPPUNIT_ASSERT_EQUAL(0, listens);

    auto listen = makeListenPacketBlob(remoteId, hash, 20, 23, answer.token);
    engine.processMessage(listen.data(), listen.size(), from);
    CPPUNIT_ASSERT_EQUAL(1, listens);
    const auto& sent = socketPtr->sends.back();
    CPPUNIT_ASSERT(sent.dest == from);
    ParsedMessage reply;
    parseMessage(reply, sent.data);
    CPPUNIT_ASSERT(reply.type == MessageType::Reply);
    CPPUNIT_ASSERT_EQUAL(myid, reply.id);
    CPPUNIT_ASSERT(reply.token == answer.token);
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

    CPPUNIT_ASSERT(not searchNodePtr->token);
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

    CPPUNIT_ASSERT(not searchNodePtr->token);
    CPPUNIT_ASSERT(searchNodePtr->last_get_reply == time_point::min());

    auto listenStatusIt = searchNodePtr->listenStatus.find(query);
    CPPUNIT_ASSERT(listenStatusIt != searchNodePtr->listenStatus.end());
    CPPUNIT_ASSERT(!listenStatusIt->second.req);
    CPPUNIT_ASSERT(!listenStatusIt->second.refresh);
}

/* A NetworkEngine with its own socket, delivering its packets to other engines */
struct TransportTestNode
{
    TransportTestNode(const char* ip,
                      TransportConfig transport,
                      uint64_t seed,
                      NetId network = 0,
                      const std::function<void(net::NetworkConfig&)>& configure = {})
        : rd(seed)
        , addr(makeIPv4(ip, 4222))
    {
        net::NetworkConfig config {};
        config.network = network;
        config.max_req_per_sec = -1;
        config.max_peer_req_per_sec = -1;
        if (configure)
            configure(config);
        if (transport.enabled and not transport.key)
            transport.key = transport::KeyPair::generate();
        config.transport = transport;
        key = transport.key;
        id = transport.enabled ? transport::nodeId(key.pub) : InfoHash::getRandom(rd);
        auto s = std::make_unique<TestDatagramSocket>();
        socket = s.get();
        engine = std::make_unique<net::NetworkEngine>(
            id,
            config,
            std::move(s),
            Sp<Logger> {},
            rd,
            scheduler,
            [](Sp<net::Request>, net::DhtProtocolException) {},
            [this](const Sp<Node>& n, int) {
                ++newNodes;
                known.emplace_back(n);
            },
            [](const InfoHash&, const SockAddr&) {},
            [](Sp<Node>) { return net::RequestAnswer {}; },
            [this](Sp<Node>, const InfoHash&, want_t) {
                ++finds;
                return routing;
            },
            [this](Sp<Node>, const InfoHash&, want_t, const Query&) {
                ++gets;
                net::RequestAnswer answer {};
                answer.values = values;
                return answer;
            },
            [this](Sp<Node>, const InfoHash&, Tid, const Query&, int) {
                ++listens;
                return net::RequestAnswer {};
            },
            [](Sp<Node>, const InfoHash&, const std::vector<Sp<Value>>&, const time_point&) {
                return net::RequestAnswer {};
            },
            [](Sp<Node>, const InfoHash&, const Value::Id&) { return net::RequestAnswer {}; });
    }

    std::vector<TestDatagramSocket::SentPacket> takeSent() { return std::exchange(socket->sends, {}); }

    size_t deliverTo(TransportTestNode& to, const SockAddr& from)
    {
        auto sent = takeSent();
        for (const auto& p : sent)
            to.engine->processMessage(p.data.data(), p.data.size(), from);
        return sent.size();
    }
    size_t deliverTo(TransportTestNode& to) { return deliverTo(to, addr); }

    Sp<Request> ping(const SockAddr& dest, bool& done)
    {
        return engine->sendPing(SockAddr(dest), [&done](const net::Request&, net::RequestAnswer&&) { done = true; }, {});
    }
    Sp<Request> ping(const Sp<Node>& dest, bool& done)
    {
        return engine->sendPing(dest, [&done](const net::Request&, net::RequestAnswer&&) { done = true; }, {});
    }
    Sp<Request> get(const Sp<Node>& dest, std::optional<std::vector<Sp<Value>>>& got)
    {
        return engine->sendGetValues(dest,
                                     InfoHash::getRandom(rd),
                                     {},
                                     -1,
                                     [&got](const net::Request&, net::RequestAnswer&& answer) {
                                         got = std::move(answer.values);
                                     },
                                     {});
    }

    Sp<Node> node(const TransportTestNode& other) { return engine->insertNode(other.id, other.addr); }

    Scheduler scheduler;
    std::mt19937_64 rd;
    SockAddr addr;
    InfoHash id;
    transport::KeyPair key;
    TestDatagramSocket* socket;
    std::unique_ptr<net::NetworkEngine> engine;
    int newNodes {0};
    int listens {0};
    int gets {0};
    int finds {0};
    net::RequestAnswer routing;
    /* answered to get requests */
    std::vector<Sp<Value>> values;
    /* held by the routing table in a Dht */
    std::vector<Sp<Node>> known;
};

static TransportConfig
legacyTransport()
{
    TransportConfig c;
    c.enabled = false;
    return c;
}

static TransportConfig
privateTransport(const transport::Authority& authority,
                 std::chrono::system_clock::duration validity = std::chrono::hours(1))
{
    TransportConfig c;
    c.key = transport::KeyPair::generate();
    c.authorities = {authority.pub};
    c.credential = authority.issue(c.key.pub, std::chrono::system_clock::now() + validity);
    return c;
}

static bool
isEnvelope(const TestDatagramSocket::SentPacket& p, transport::EnvelopeType type, bool credential = false)
{
    auto header = transport::parseHeader(p.data.data(), p.data.size());
    return header and header->type == type and header->credential == credential;
}

static transport::Key
ephemeralKey(const TestDatagramSocket::SentPacket& p)
{
    return transport::parseHeader(p.data.data(), p.data.size())->ephemeral;
}

static std::optional<transport::Key>
advertisedKey(const TestDatagramSocket::SentPacket& p)
{
    ParsedMessage msg;
    msgpack::unpacked res = msgpack::unpack((const char*) p.data.data(), p.data.size());
    msg.msgpack_unpack(res.get());
    return msg.transport_key;
}

static Blob
makePingPacketBlob(const InfoHash& id, Tid tid, const std::optional<transport::Key>& key = {})
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4 + (key ? 1 : 0));
    pk.pack(KEY_A);
    pk.pack_map(1);
    pk.pack(KEY_REQ_ID);
    pk.pack(id);
    pk.pack(KEY_Q);
    pk.pack(QUERY_PING);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_Q);
    if (key) {
        pk.pack(KEY_TRANSPORT);
        pk.pack_bin(key->size());
        pk.pack_bin_body((const char*) key->data(), key->size());
    }
    return {buffer.data(), buffer.data() + buffer.size()};
}

void
NetworkEngineTester::testTransportDisabledKeepsLegacyWire()
{
    TransportTestNode legacy("127.0.0.2", legacyTransport(), 1);
    TransportTestNode other("127.0.0.3", legacyTransport(), 2);
    CPPUNIT_ASSERT(not legacy.engine->getTransportKey());

    bool done = false;
    legacy.ping(other.addr, done);
    auto sent = legacy.takeSent();
    CPPUNIT_ASSERT_EQUAL((size_t) 1, sent.size());
    CPPUNIT_ASSERT(not transport::isEnvelope(sent[0].data.data(), sent[0].data.size()));
    CPPUNIT_ASSERT(not advertisedKey(sent[0]));
}

void
NetworkEngineTester::testTransportEncryptsAfterKeyExchange()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    CPPUNIT_ASSERT_EQUAL(transport::nodeId(a.engine->getTransportKey()->pub), a.id);

    // First contact: plaintext advertising our key
    bool done = false;
    a.ping(b.addr, done);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, a.socket->sends.size());
    auto key = advertisedKey(a.socket->sends[0]);
    CPPUNIT_ASSERT(key and *key == a.key.pub);
    a.deliverTo(b);

    // The reply is encrypted, before b knows our ephemeral key
    CPPUNIT_ASSERT_EQUAL((size_t) 1, b.socket->sends.size());
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends[0], transport::EnvelopeType::Initial));
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);
    CPPUNIT_ASSERT(a.node(b)->getTransport());
    CPPUNIT_ASSERT(b.node(a)->getTransport());

    // Following requests use ephemeral keys both ways
    done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Session));
    a.deliverTo(b);
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends.at(0), transport::EnvelopeType::Session));
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);

    // b answered our request: both have the session, keys are left out
    done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Data));
    a.deliverTo(b);
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends.at(0), transport::EnvelopeType::Data));
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);
}

void
NetworkEngineTester::testTransportLegacyPeerStaysPlaintext()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode legacy("127.0.0.3", legacyTransport(), 2);

    bool done = false;
    a.ping(legacy.addr, done);
    a.deliverTo(legacy);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, legacy.socket->sends.size());
    CPPUNIT_ASSERT(not transport::isEnvelope(legacy.socket->sends[0].data.data(), legacy.socket->sends[0].data.size()));
    legacy.deliverTo(a);
    CPPUNIT_ASSERT(done);
    CPPUNIT_ASSERT(not a.node(legacy)->getTransport());

    // Requests from the legacy node are answered in plaintext
    done = false;
    legacy.ping(legacy.node(a), done);
    legacy.deliverTo(a);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, a.socket->sends.size());
    CPPUNIT_ASSERT(not transport::isEnvelope(a.socket->sends[0].data.data(), a.socket->sends[0].data.size()));
    a.deliverTo(legacy);
    CPPUNIT_ASSERT(done);
}

void
NetworkEngineTester::testTransportRejectsMismatchedNodeId()
{
    TransportTestNode b("127.0.0.3", {}, 2);
    auto from = makeIPv4("127.0.0.4", 4222);
    auto sender = transport::KeyPair::generate();
    auto ephemeral = transport::KeyPair::generate();
    auto key = *transport::initialSendKey(sender, ephemeral, b.key.pub, 0);
    auto seal = [&](const Blob& msg) {
        return transport::seal(key, transport::EnvelopeType::Initial, sender.pub, ephemeral.pub, msg.data(), msg.size());
    };

    std::mt19937_64 rd(3);
    auto spoofed = makePingPacketBlob(InfoHash::getRandom(rd), 1);
    auto envelope = seal(spoofed);
    b.engine->processMessage(envelope.data(), envelope.size(), from);
    CPPUNIT_ASSERT(b.socket->sends.empty());
    CPPUNIT_ASSERT_EQUAL(0, b.newNodes);

    auto genuine = makePingPacketBlob(transport::nodeId(sender.pub), 2);
    envelope = seal(genuine);
    b.engine->processMessage(envelope.data(), envelope.size(), from);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, b.socket->sends.size());

    // A plaintext key that doesn't match the node ID is ignored: the reply stays plaintext
    auto other = makeIPv4("127.0.0.5", 4222);
    auto fake = makePingPacketBlob(InfoHash::getRandom(rd), 3, sender.pub);
    b.takeSent();
    b.engine->processMessage(fake.data(), fake.size(), other);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, b.socket->sends.size());
    CPPUNIT_ASSERT(not transport::isEnvelope(b.socket->sends[0].data.data(), b.socket->sends[0].data.size()));
}

void
NetworkEngineTester::testTransportIgnoresForgedNodeListKey()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    auto remote = makeIPv4("127.0.0.3", 4222);
    std::mt19937_64 rd(5);
    auto remoteId = InfoHash::getRandom(rd);
    auto remoteNode = a.engine->insertNode(remoteId, remote);

    std::vector<Sp<Node>> answerNodes;
    auto req = a.engine->sendFindNode(remoteNode,
                                      InfoHash::getRandom(rd),
                                      -1,
                                      [&](const net::Request&, net::RequestAnswer&& answer) {
                                          answerNodes = std::move(answer.nodes4);
                                      });
    a.takeSent();

    auto forgedKey = transport::KeyPair::generate().pub;
    auto forgedId = InfoHash::getRandom(rd);
    auto validKey = transport::KeyPair::generate().pub;
    auto validId = transport::nodeId(validKey);

    struct Listed
    {
        InfoHash id;
        transport::Key key;
        const char* ip;
    };
    Blob nodes4, keys4;
    for (const auto& listed : {
             Listed {forgedId, forgedKey, "127.0.0.6"},
              Listed {validId,  validKey,  "127.0.0.7"}
    }) {
        auto addr = makeIPv4(listed.ip, 5000);
        nodes4.insert(nodes4.end(), listed.id.data(), listed.id.data() + listed.id.size());
        auto sin = addr.getIPv4();
        nodes4.insert(nodes4.end(), (uint8_t*) &sin.sin_addr, (uint8_t*) &sin.sin_addr + sizeof(in_addr));
        nodes4.insert(nodes4.end(), (uint8_t*) &sin.sin_port, (uint8_t*) &sin.sin_port + sizeof(in_port_t));
        keys4.insert(keys4.end(), listed.key.begin(), listed.key.end());
    }

    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(3);
    pk.pack(KEY_R);
    pk.pack_map(3);
    pk.pack(KEY_REQ_ID);
    pk.pack(remoteId);
    pk.pack(KEY_REQ_NODES4);
    pk.pack_bin(nodes4.size());
    pk.pack_bin_body((const char*) nodes4.data(), nodes4.size());
    pk.pack(KEY_REQ_KEYS4);
    pk.pack_bin(keys4.size());
    pk.pack_bin_body((const char*) keys4.data(), keys4.size());
    pk.pack(KEY_TID);
    pk.pack(req->getTid());
    pk.pack(KEY_Y);
    pk.pack(KEY_R);
    a.engine->processMessage((const uint8_t*) buffer.data(), buffer.size(), remote);

    CPPUNIT_ASSERT_EQUAL((size_t) 2, answerNodes.size());
    for (const auto& n : answerNodes) {
        if (n->id == forgedId)
            CPPUNIT_ASSERT(not n->getTransport());
        else
            CPPUNIT_ASSERT(n->getTransport() and n->getTransport()->key == validKey);
    }
}

void
NetworkEngineTester::testTransportPlaintextDoesNotMoveKeyedNode()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    bool done = false;
    a.ping(b.addr, done);
    a.deliverTo(b);
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);
    auto nodeB = a.node(b);
    CPPUNIT_ASSERT(nodeB->getTransport());
    auto newNodes = a.newNodes;

    auto attacker = makeIPv4("127.0.0.66", 4222);
    auto spoofed = makePingPacketBlob(b.id, 7);
    a.engine->processMessage(spoofed.data(), spoofed.size(), attacker);

    CPPUNIT_ASSERT(nodeB->getAddr() == b.addr);
    CPPUNIT_ASSERT_EQUAL(newNodes, a.newNodes);
    // Answered, but only readable by the owner of the key
    CPPUNIT_ASSERT_EQUAL((size_t) 1, a.socket->sends.size());
    CPPUNIT_ASSERT(a.socket->sends[0].dest == attacker);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends[0], transport::EnvelopeType::Initial));
}

void
NetworkEngineTester::testTransportPrivateNetwork()
{
    auto authority = transport::Authority::generate();
    TransportTestNode a("127.0.0.2", privateTransport(authority), 1);
    TransportTestNode b("127.0.0.3", privateTransport(authority), 2);

    // Ping to an address: plaintext hello with our credential, never a plaintext message
    bool done = false;
    a.ping(b.addr, done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Hello));
    a.deliverTo(b);
    // the hello gave b our ephemeral key
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends.at(0), transport::EnvelopeType::Session, true));
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);
    auto peerB = a.node(b)->getTransport();
    CPPUNIT_ASSERT(peerB and peerB->isAuthorized(std::chrono::system_clock::now()));

    // b only saw our credential in the unauthenticated hello
    done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Session, true));
    a.deliverTo(b);
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends.at(0), transport::EnvelopeType::Session, true));
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);

    // b accepted our request: Data envelopes, without credential
    done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Data));
    a.deliverTo(b);
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends.at(0), transport::EnvelopeType::Data));
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);
}

void
NetworkEngineTester::testTransportPrivateNetworkRejectsOutsiders()
{
    auto authority = transport::Authority::generate();
    TransportTestNode member("127.0.0.2", privateTransport(authority), 1);

    // plaintext
    TransportTestNode open("127.0.0.3", {}, 2);
    bool done = false;
    open.ping(member.addr, done);
    open.deliverTo(member);
    CPPUNIT_ASSERT(member.socket->sends.empty());

    // credential from another authority
    auto rogue = privateTransport(transport::Authority::generate());
    rogue.authorities = {authority.pub};
    TransportTestNode outsider("127.0.0.4", rogue, 3);
    outsider.ping(member.addr, done);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, outsider.deliverTo(member));
    CPPUNIT_ASSERT(member.socket->sends.empty());

    // expired credential
    TransportTestNode expired("127.0.0.5", privateTransport(authority, -std::chrono::seconds(1)), 4);
    expired.ping(member.addr, done);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, expired.deliverTo(member));
    CPPUNIT_ASSERT(member.socket->sends.empty());

    // encrypted, without credential
    auto sender = transport::KeyPair::generate();
    auto ephemeral = transport::KeyPair::generate();
    auto ping = makePingPacketBlob(transport::nodeId(sender.pub), 1);
    auto envelope = transport::seal(*transport::initialSendKey(sender, ephemeral, member.key.pub, 0),
                                    transport::EnvelopeType::Initial,
                                    sender.pub,
                                    ephemeral.pub,
                                    ping.data(),
                                    ping.size());
    member.engine->processMessage(envelope.data(), envelope.size(), makeIPv4("127.0.0.6", 4222));
    CPPUNIT_ASSERT(member.socket->sends.empty());

    // members don't talk to open nodes, nor accept their hello
    member.ping(open.addr, done);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, member.deliverTo(open));
    CPPUNIT_ASSERT(open.socket->sends.empty());
    CPPUNIT_ASSERT(not done);
    CPPUNIT_ASSERT_EQUAL(0, member.newNodes);
}

static void
advanceTime(TransportTestNode& n, std::chrono::steady_clock::duration d)
{
    n.scheduler.syncTime(n.scheduler.time() + d);
    n.scheduler.run();
}

void
NetworkEngineTester::testTransportEpochRotation()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    bool done = false;
    a.ping(b.addr, done);
    a.deliverTo(b);
    b.deliverTo(a);
    a.ping(a.node(b), done);
    auto captured = a.socket->sends.at(0);
    CPPUNIT_ASSERT(isEnvelope(captured, transport::EnvelopeType::Session));
    a.deliverTo(b);
    auto oldReply = b.socket->sends.at(0);
    b.deliverTo(a);
    a.ping(a.node(b), done);
    auto capturedData = a.socket->sends.at(0);
    CPPUNIT_ASSERT(isEnvelope(capturedData, transport::EnvelopeType::Data));
    a.deliverTo(b);
    b.deliverTo(a);

    // b rotates: a's Data envelopes still open with b's previous epoch
    advanceTime(b, std::chrono::minutes(30));
    b.takeSent();
    done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Data));
    a.deliverTo(b);
    // b answers with its new ephemeral key, until a confirms the new session
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends.at(0), transport::EnvelopeType::Session));
    CPPUNIT_ASSERT(ephemeralKey(b.socket->sends.at(0)) != ephemeralKey(oldReply));
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);
    done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Data));
    a.deliverTo(b);
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends.at(0), transport::EnvelopeType::Data));
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);

    // a rotates: new ephemeral key
    advanceTime(a, std::chrono::minutes(30));
    a.takeSent();
    done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Session));
    CPPUNIT_ASSERT(ephemeralKey(a.socket->sends.at(0)) != ephemeralKey(captured));
    a.deliverTo(b);
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);

    // Keys of the previous epoch are accepted for one period, then erased
    b.engine->processMessage(captured.data.data(), captured.data.size(), a.addr);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, b.takeSent().size());
    advanceTime(b, std::chrono::minutes(30));
    b.takeSent();
    b.engine->processMessage(captured.data.data(), captured.data.size(), a.addr);
    b.engine->processMessage(capturedData.data.data(), capturedData.data.size(), a.addr);
    CPPUNIT_ASSERT(b.socket->sends.empty());
}

void
NetworkEngineTester::testTransportPeerRestart()
{
    auto authority = transport::Authority::generate();
    auto configB = privateTransport(authority);
    TransportTestNode a("127.0.0.2", privateTransport(authority), 1);
    auto b = std::make_unique<TransportTestNode>("127.0.0.3", configB, 2);
    bool done = false;
    a.ping(b->addr, done);
    a.deliverTo(*b);
    b->deliverTo(a);
    for (int i = 0; i < 2; i++) {
        done = false;
        a.ping(a.node(*b), done);
        a.deliverTo(*b);
        b->deliverTo(a);
        CPPUNIT_ASSERT(done);
    }

    // b restarts with the same key: it lost the session and our credential
    b = std::make_unique<TransportTestNode>("127.0.0.3", configB, 3);
    done = false;
    a.ping(a.node(*b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Data));
    a.deliverTo(*b);
    CPPUNIT_ASSERT(b->socket->sends.empty());

    // The retry starts over
    advanceTime(a, std::chrono::seconds(2));
    CPPUNIT_ASSERT_EQUAL((size_t) 1, a.socket->sends.size());
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Initial, true));
    a.deliverTo(*b);
    CPPUNIT_ASSERT(isEnvelope(b->socket->sends.at(0), transport::EnvelopeType::Session, true));
    b->deliverTo(a);
    CPPUNIT_ASSERT(done);
}

void
NetworkEngineTester::testTransportHelloIsUnauthenticated()
{
    auto authority = transport::Authority::generate();
    auto configA = privateTransport(authority);
    TransportTestNode a("127.0.0.2", configA, 1);
    TransportTestNode b("127.0.0.3", privateTransport(authority), 2);
    bool done = false;
    a.ping(b.addr, done);
    a.deliverTo(b);
    b.deliverTo(a);
    a.ping(a.node(b), done);
    a.deliverTo(b);
    b.deliverTo(a);
    auto nodeA = b.node(a);
    auto newNodes = b.newNodes;

    // Anyone can replay a's credential in a hello
    auto attacker = makeIPv4("127.0.0.66", 4222);
    auto ephemeral = transport::KeyPair::generate();
    auto credential = configA.credential.pack();
    auto forge = [&](const Blob& msg) {
        auto hello = transport::hello(a.key.pub, ephemeral.pub, credential, msg.data(), msg.size());
        b.engine->processMessage(hello.data(), hello.size(), attacker);
    };
    forge(makePingPacketBlob(a.id, 9));

    // Answered, but only readable by the owner of the key
    CPPUNIT_ASSERT_EQUAL((size_t) 1, b.socket->sends.size());
    CPPUNIT_ASSERT(b.socket->sends[0].dest == attacker);
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends[0], transport::EnvelopeType::Session, true));
    b.takeSent();
    // without changing what b knows about a
    CPPUNIT_ASSERT(nodeA->getAddr() == a.addr);
    CPPUNIT_ASSERT_EQUAL(newNodes, b.newNodes);
    done = false;
    a.ping(a.node(b), done);
    a.deliverTo(b);
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);

    // Only pings are answered
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_map(4);
    pk.pack(KEY_A);
    pk.pack_map(2);
    pk.pack(KEY_REQ_ID);
    pk.pack(a.id);
    pk.pack(KEY_REQ_TARGET);
    pk.pack(b.id);
    pk.pack(KEY_Q);
    pk.pack(QUERY_FIND);
    pk.pack(KEY_TID);
    pk.pack(10);
    pk.pack(KEY_Y);
    pk.pack(KEY_Q);
    forge({buffer.data(), buffer.data() + buffer.size()});
    CPPUNIT_ASSERT(b.socket->sends.empty());
}

void
NetworkEngineTester::testTransportSessionAuthorizesWrites()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    bool done = false;
    a.ping(b.addr, done);
    a.deliverTo(b);
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);

    // No token: a got b's ephemeral key for its address
    std::mt19937_64 rd(4);
    std::optional<Blob> token;
    a.engine->sendListen(a.node(b),
                         InfoHash::getRandom(rd),
                         {},
                         {},
                         1,
                         [&token](const net::Request&, net::RequestAnswer&& answer) {
                             token = std::move(answer.ntoken);
                         },
                         {});
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Session));
    a.deliverTo(b);
    CPPUNIT_ASSERT_EQUAL(1, b.listens);
    b.deliverTo(a);
    CPPUNIT_ASSERT(token and token->empty());

    // Data envelopes also come from the address that got b's ephemeral key
    token.reset();
    a.engine->sendListen(a.node(b),
                         InfoHash::getRandom(rd),
                         {},
                         {},
                         2,
                         [&token](const net::Request&, net::RequestAnswer&& answer) {
                             token = std::move(answer.ntoken);
                         },
                         {});
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Data));
    a.deliverTo(b);
    CPPUNIT_ASSERT_EQUAL(2, b.listens);
    b.deliverTo(a);
    CPPUNIT_ASSERT(token and token->empty());
}

void
NetworkEngineTester::testTransportInitialWriteIsUnauthorized()
{
    TransportTestNode b("127.0.0.3", {}, 2);
    auto from = makeIPv4("127.0.0.4", 4222);
    auto sender = transport::KeyPair::generate();
    auto ephemeral = transport::KeyPair::generate();
    std::mt19937_64 rd(5);
    auto listen = makeListenPacketBlob(transport::nodeId(sender.pub), InfoHash::getRandom(rd), 1, 2, {});

    // Anyone can send an Initial envelope from any address
    auto initial = transport::seal(*transport::initialSendKey(sender, ephemeral, b.key.pub, 0),
                                   transport::EnvelopeType::Initial,
                                   sender.pub,
                                   ephemeral.pub,
                                   listen.data(),
                                   listen.size());
    b.engine->processMessage(initial.data(), initial.size(), from);
    CPPUNIT_ASSERT_EQUAL(0, b.listens);

    auto reply = b.takeSent().at(0);
    CPPUNIT_ASSERT(reply.dest == from);
    CPPUNIT_ASSERT(isEnvelope(reply, transport::EnvelopeType::Session));
    auto keys = *transport::sessionKeys(sender, ephemeral, b.key.pub, ephemeralKey(reply), 0);
    auto payload = transport::open(keys.rx, reply.data.data(), reply.data.size());
    CPPUNIT_ASSERT(payload);
    ParsedMessage error;
    parseMessage(error, *payload);
    CPPUNIT_ASSERT(error.type == MessageType::Error);
    CPPUNIT_ASSERT_EQUAL(DhtProtocolException::UNAUTHORIZED, error.error_code);

    // The error reached the sender's address: the retry is accepted
    auto session = transport::seal(keys.tx,
                                   transport::EnvelopeType::Session,
                                   sender.pub,
                                   ephemeral.pub,
                                   listen.data(),
                                   listen.size());
    b.engine->processMessage(session.data(), session.size(), from);
    CPPUNIT_ASSERT_EQUAL(1, b.listens);
}

void
NetworkEngineTester::testTransportUnvalidatedGetIsUnauthorized()
{
    auto authority = transport::Authority::generate();
    for (bool privateNetwork : {false, true}) {
        TransportTestNode receiver("127.0.0.3", privateNetwork ? privateTransport(authority) : TransportConfig {}, 2);
        auto from = makeIPv4("127.0.0.4", 4222);
        auto senderConfig = privateTransport(authority);
        auto sender = senderConfig.key;
        auto ephemeral = transport::KeyPair::generate();
        receiver.values = {std::make_shared<Value>(Blob(65536, 'x'))};
        std::optional<transport::Key> receiverEphemeral;
        for (bool select : {false, true}) {
            for (bool advertise : {true, false}) {
                msgpack::sbuffer buffer;
                msgpack::packer<msgpack::sbuffer> pk(&buffer);
                pk.pack_map(advertise ? 5 : 4);
                pk.pack(KEY_A);
                pk.pack_map(select ? 3 : 2);
                pk.pack(KEY_REQ_ID);
                pk.pack(transport::nodeId(sender.pub));
                pk.pack(KEY_REQ_H);
                pk.pack(receiver.id);
                if (select) {
                    Query query;
                    query.select.field(Value::Field::Id);
                    pk.pack(KEY_Q);
                    pk.pack(query);
                }
                pk.pack(KEY_Q);
                pk.pack(QUERY_GET);
                pk.pack(KEY_TID);
                pk.pack(Tid(42));
                pk.pack(KEY_Y);
                pk.pack(KEY_Q);
                if (advertise) {
                    pk.pack(KEY_TRANSPORT);
                    pk.pack_bin(sender.pub.size());
                    pk.pack_bin_body((const char*) sender.pub.data(), sender.pub.size());
                } else {
                    auto node = receiver.engine->insertNode(transport::nodeId(sender.pub), from);
                    node->setTransport(std::make_shared<transport::Peer>(sender.pub));
                }
                auto initial = transport::seal(*transport::initialSendKey(sender, ephemeral, receiver.key.pub, 0),
                                               transport::EnvelopeType::Initial,
                                               sender.pub,
                                               ephemeral.pub,
                                               (const uint8_t*) buffer.data(),
                                               buffer.size(),
                                               privateNetwork ? senderConfig.credential.pack() : Blob {});
                for (bool encrypted : {true, false}) {
                    if (encrypted)
                        receiver.engine->processMessage(initial.data(), initial.size(), from);
                    else
                        receiver.engine->processMessage((const uint8_t*) buffer.data(), buffer.size(), from);
                    CPPUNIT_ASSERT_EQUAL(0, receiver.gets);
                    auto replies = receiver.takeSent();
                    if (privateNetwork and not encrypted) {
                        CPPUNIT_ASSERT(replies.empty());
                        continue;
                    }
                    CPPUNIT_ASSERT_EQUAL(size_t(1), replies.size());
                    CPPUNIT_ASSERT(replies[0].data.size() < 512);
                    receiverEphemeral = ephemeralKey(replies[0]);
                    auto key = encrypted
                                   ? transport::sessionKeys(sender, ephemeral, receiver.key.pub, *receiverEphemeral, 0)
                                         ->rx
                                   : *transport::initialReceiveKey(sender, receiver.key.pub, *receiverEphemeral, 0);
                    auto payload = transport::open(key, replies[0].data.data(), replies[0].data.size());
                    CPPUNIT_ASSERT(payload);
                    if (privateNetwork)
                        payload->erase(payload->begin(), payload->begin() + transport::Credential::PACKED_SIZE);
                    ParsedMessage error;
                    parseMessage(error, *payload);
                    CPPUNIT_ASSERT(error.type == MessageType::Error);
                    CPPUNIT_ASSERT_EQUAL(DhtProtocolException::UNAUTHORIZED, error.error_code);
                    CPPUNIT_ASSERT_EQUAL(Tid(42), error.tid);
                    CPPUNIT_ASSERT(error.id == receiver.id);
                }
            }
        }
        TransportTestNode senderNode("127.0.0.4", privateNetwork ? senderConfig : TransportConfig {}, 5);
        bool done = false;
        senderNode.ping(receiver.addr, done);
        senderNode.deliverTo(receiver);
        receiver.deliverTo(senderNode);
        std::optional<std::vector<Sp<Value>>> got;
        senderNode.get(senderNode.node(receiver), got);
        senderNode.deliverTo(receiver);
        receiver.deliverTo(senderNode);
        CPPUNIT_ASSERT_EQUAL(1, receiver.gets);
        CPPUNIT_ASSERT(got and got->size() == 1 and got->front()->data == receiver.values.front()->data);
    }
}

void
NetworkEngineTester::testTransportEphemeralBoundToAddress()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    TransportTestNode c("127.0.0.66", {}, 3);
    bool done = false;
    a.ping(b.addr, done);
    a.deliverTo(b);
    auto toA = b.socket->sends.at(0);
    b.deliverTo(a);
    c.ping(b.addr, done);
    c.deliverTo(b);
    CPPUNIT_ASSERT(ephemeralKey(b.socket->sends.at(0)) != ephemeralKey(toA));
    b.deliverTo(c);

    a.ping(a.node(b), done);
    auto fromA = a.socket->sends.at(0);
    c.ping(c.node(b), done);
    auto fromC = c.socket->sends.at(0);
    CPPUNIT_ASSERT(isEnvelope(fromA, transport::EnvelopeType::Session));
    CPPUNIT_ASSERT(isEnvelope(fromC, transport::EnvelopeType::Session));

    // A Session envelope only opens from the address that received b's ephemeral key
    b.engine->processMessage(fromC.data.data(), fromC.data.size(), a.addr);
    b.engine->processMessage(fromA.data.data(), fromA.data.size(), c.addr);
    CPPUNIT_ASSERT(b.socket->sends.empty());
    b.engine->processMessage(fromA.data.data(), fromA.data.size(), a.addr);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, b.socket->sends.size());

    // So does a Data envelope, without any key derivation
    a.takeSent();
    b.deliverTo(a);
    a.ping(a.node(b), done);
    auto data = a.socket->sends.at(0);
    CPPUNIT_ASSERT(isEnvelope(data, transport::EnvelopeType::Data));
    b.engine->processMessage(data.data.data(), data.data.size(), c.addr);
    CPPUNIT_ASSERT(b.socket->sends.empty());
    b.engine->processMessage(data.data.data(), data.data.size(), a.addr);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, b.socket->sends.size());
}

void
NetworkEngineTester::testTransportRestartedPeerReconnects()
{
    TransportConfig configA;
    configA.key = transport::KeyPair::generate();
    auto a = std::make_unique<TransportTestNode>("127.0.0.2", configA, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    bool done = false;
    a->ping(b.addr, done);
    a->deliverTo(b);
    b.deliverTo(*a);
    for (int i = 0; i < 2; i++) {
        a->ping(a->node(b), done);
        a->deliverTo(b);
        b.deliverTo(*a);
    }

    // a restarts with the same key, and contacts b by address: b must forget a's ephemeral key
    a = std::make_unique<TransportTestNode>("127.0.0.2", configA, 3);
    done = false;
    a->ping(b.addr, done);
    a->deliverTo(b);
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends.at(0), transport::EnvelopeType::Initial));
    b.deliverTo(*a);
    CPPUNIT_ASSERT(done);
}

/* Brings a and b to confirmed sessions both ways: their next packets are Data envelopes */
static void
establishSession(TransportTestNode& a, TransportTestNode& b)
{
    bool done = false;
    a.ping(b.addr, done);
    a.deliverTo(b);
    b.deliverTo(a);
    for (int i = 0; i < 2; i++) {
        done = false;
        a.ping(a.node(b), done);
        a.deliverTo(b);
        b.deliverTo(a);
        CPPUNIT_ASSERT(done);
    }
    done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Data));
    a.deliverTo(b);
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends.at(0), transport::EnvelopeType::Data));
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);
}

void
NetworkEngineTester::testTransportPrivateClientKeepsAuthorization()
{
    auto authority = transport::Authority::generate();
    TransportTestNode client("127.0.0.2", privateTransport(authority), 1, 0, [](net::NetworkConfig& config) {
        config.is_client = true;
    });
    TransportTestNode server("127.0.0.3", privateTransport(authority), 2);
    establishSession(client, server);
    CPPUNIT_ASSERT(server.known.empty());
    CPPUNIT_ASSERT(not server.engine->cache.getNode(client.id, AF_INET));

    advanceTime(server, std::chrono::minutes(30));
    for (int attempt = 0; attempt < 3; ++attempt) {
        bool done = false;
        client.ping(client.node(server), done);
        CPPUNIT_ASSERT(isEnvelope(client.socket->sends.at(0), transport::EnvelopeType::Data));
        client.deliverTo(server);
        server.deliverTo(client);
        CPPUNIT_ASSERT(done);
        CPPUNIT_ASSERT(server.known.empty());
        CPPUNIT_ASSERT(not server.engine->cache.getNode(client.id, AF_INET));
    }
}

/* Initial envelope from a fresh identity, as anyone can send from any address */
static Blob
makeInitialPing(const transport::KeyPair& receiver, Tid tid)
{
    auto sender = transport::KeyPair::generate();
    auto ephemeral = transport::KeyPair::generate();
    auto ping = makePingPacketBlob(transport::nodeId(sender.pub), tid);
    return transport::seal(*transport::initialSendKey(sender, ephemeral, receiver.pub, 0),
                           transport::EnvelopeType::Initial,
                           sender.pub,
                           ephemeral.pub,
                           ping.data(),
                           ping.size());
}

void
NetworkEngineTester::testTransportSpoofedInitialKeepsSession()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    establishSession(a, b);

    // An Initial envelope with a's source address, from an identity that never received anything at it
    auto initial = makeInitialPing(b.key, 77);
    b.engine->processMessage(initial.data(), initial.size(), a.addr);
    auto sent = b.takeSent();
    CPPUNIT_ASSERT_EQUAL((size_t) 1, sent.size());
    CPPUNIT_ASSERT(sent[0].dest == a.addr);
    CPPUNIT_ASSERT(isEnvelope(sent[0], transport::EnvelopeType::Session));

    // a's session with b is untouched: its Data envelopes still open
    bool done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Data));
    a.deliverTo(b);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, b.socket->sends.size());
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);
}

void
NetworkEngineTester::testTransportSpoofedHelloKeepsSession()
{
    auto authority = transport::Authority::generate();
    auto configA = privateTransport(authority);
    TransportTestNode a("127.0.0.2", configA, 1);
    TransportTestNode b("127.0.0.3", privateTransport(authority), 2);
    establishSession(a, b);

    // A hello with a copied credential and a's source address
    auto ephemeral = transport::KeyPair::generate();
    auto credential = configA.credential.pack();
    auto ping = makePingPacketBlob(a.id, 78);
    auto hello = transport::hello(a.key.pub, ephemeral.pub, credential, ping.data(), ping.size());
    b.engine->processMessage(hello.data(), hello.size(), a.addr);
    auto sent = b.takeSent();
    CPPUNIT_ASSERT_EQUAL((size_t) 1, sent.size());
    CPPUNIT_ASSERT(sent[0].dest == a.addr);

    bool done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Data));
    a.deliverTo(b);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, b.socket->sends.size());
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);
}

void
NetworkEngineTester::testTransportSpoofedInitialsDoNotFillSessionCache()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    establishSession(a, b);
    const auto cached = b.engine->epoch_.sessions.size();
    CPPUNIT_ASSERT(b.engine->epoch_.find(a.addr));

    // Answering unvalidated senders must not take a cache slot per source address
    for (unsigned i = 0; i < 64; i++) {
        auto initial = makeInitialPing(b.key, 100 + i);
        b.engine->processMessage(initial.data(), initial.size(), makeIPv4("203.0.113.7", 10000 + i));
    }
    CPPUNIT_ASSERT_EQUAL((size_t) 64, b.takeSent().size());
    CPPUNIT_ASSERT_EQUAL(cached, b.engine->epoch_.sessions.size());

    // The sender takes a slot once it answers with our key for its address
    auto sender = transport::KeyPair::generate();
    auto ephemeral = transport::KeyPair::generate();
    auto from = makeIPv4("203.0.113.8", 4222);
    auto ping = makePingPacketBlob(transport::nodeId(sender.pub), 200);
    auto initial = transport::seal(*transport::initialSendKey(sender, ephemeral, b.key.pub, 0),
                                   transport::EnvelopeType::Initial,
                                   sender.pub,
                                   ephemeral.pub,
                                   ping.data(),
                                   ping.size());
    b.engine->processMessage(initial.data(), initial.size(), from);
    auto reply = b.takeSent().at(0);
    CPPUNIT_ASSERT_EQUAL(cached, b.engine->epoch_.sessions.size());
    auto keys = *transport::sessionKeys(sender, ephemeral, b.key.pub, ephemeralKey(reply), 0);
    auto session = transport::seal(keys.tx,
                                   transport::EnvelopeType::Session,
                                   sender.pub,
                                   ephemeral.pub,
                                   ping.data(),
                                   ping.size());
    b.engine->processMessage(session.data(), session.size(), from);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, b.takeSent().size());
    CPPUNIT_ASSERT_EQUAL(cached + 1, b.engine->epoch_.sessions.size());
    CPPUNIT_ASSERT(b.engine->epoch_.find(from));
}

void
NetworkEngineTester::testTransportSessionCacheEvictsLeastRecentlyUsed()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    establishSession(a, b);
    auto& epoch = b.engine->epoch_;
    CPPUNIT_ASSERT(epoch.find(a.addr));

    // Fill the cache around a's session, with addresses sorting after it
    auto filler = [](unsigned i) {
        return makeIPv4(i % 2 ? "10.0.0.1" : "250.0.0.1", 5000 + i);
    };
    const auto max = net::NetworkEngine::MAX_SESSIONS;
    for (unsigned i = 0; epoch.sessions.size() < max; i++)
        epoch.store(filler(i), {});

    // a is the least recently used until it talks to b again
    bool done = false;
    a.ping(a.node(b), done);
    a.deliverTo(b);
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);

    epoch.store(makeIPv4("192.0.2.1", 4222), {});
    CPPUNIT_ASSERT_EQUAL(max, epoch.sessions.size());
    CPPUNIT_ASSERT(epoch.find(a.addr));
    CPPUNIT_ASSERT(not epoch.find(filler(0)));
    CPPUNIT_ASSERT(epoch.find(filler(1)));
}

void
NetworkEngineTester::testTransportRejectedSessionsKeepCache()
{
    auto authority = transport::Authority::generate();
    TransportTestNode a("127.0.0.2", privateTransport(authority), 1);
    TransportTestNode b("127.0.0.3", privateTransport(authority), 2);
    establishSession(a, b);
    auto sender = transport::KeyPair::generate();
    auto ephemeral = transport::KeyPair::generate();
    auto receiver = b.engine->epoch_.ephemeral(a.addr);
    auto keys = *transport::sessionKeys(sender, ephemeral, b.key.pub, receiver.pub, 0);
    auto expiration = std::chrono::system_clock::now() + std::chrono::hours(1);
    auto credential = authority.issue(sender.pub, expiration).pack();
    auto ping = makePingPacketBlob(transport::nodeId(sender.pub), 77);
    std::vector<std::pair<Blob, Blob>> rejected {
        {ping, {}},
        {ping, transport::Authority::generate().issue(sender.pub, expiration).pack()},
        {Blob {0xC1}, credential},
        {makePingPacketBlob(a.id, 77), credential},
        {makeReplyHeaderPacketBlob(transport::nodeId(sender.pub), 77, {}), credential},
        {makeValueDataPacketBlob(77, 0, 0, {}), credential}};
    for (const auto& [payload, proof] : rejected) {
        auto packet = transport::seal(keys.tx,
                                      transport::EnvelopeType::Session,
                                      sender.pub,
                                      ephemeral.pub,
                                      payload.data(),
                                      payload.size(),
                                      proof);
        b.engine->processMessage(packet.data(), packet.size(), a.addr);
        auto cached = b.engine->epoch_.find(a.addr);
        CPPUNIT_ASSERT(cached and cached->peer == a.key.pub and cached->confirmed);
        CPPUNIT_ASSERT(b.socket->sends.empty());
    }
    bool done = false;
    a.ping(a.node(b), done);
    a.deliverTo(b);
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);
}

void
NetworkEngineTester::testTransportInitialSenderConfirmsAfterSessionEnvelope()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    // a learned b's key from a node list: its first packet is an Initial envelope
    a.engine->insertNode(b.id, b.addr)->setTransport(std::make_shared<transport::Peer>(b.key.pub));
    bool done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Initial));
    a.deliverTo(b);
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends.at(0), transport::EnvelopeType::Session));
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);

    // b answered without caching a session for a's address: a must not send Data yet
    done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Session));
    a.deliverTo(b);
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends.at(0), transport::EnvelopeType::Session));
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);

    // b opened a Session envelope from a, so it cached the session
    done = false;
    a.ping(a.node(b), done);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Data));
    a.deliverTo(b);
    CPPUNIT_ASSERT(isEnvelope(b.socket->sends.at(0), transport::EnvelopeType::Data));
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);
}

/* a requests a value from b that b answers in a header and two encrypted fragments, kept in `reply` */
struct FragmentedReply
{
    static constexpr size_t FRAGMENT {net::NetworkEngine::ENCRYPTED_FRAGMENT_SIZE};

    FragmentedReply(TransportTestNode& a, TransportTestNode& b)
        : data(FRAGMENT + FRAGMENT / 2, 'x')
    {
        b.values = {std::make_shared<Value>((const uint8_t*) data.data(), data.size())};
        request = a.get(a.node(b), got);
        a.deliverTo(b);
        reply = b.takeSent();
        CPPUNIT_ASSERT_EQUAL((size_t) 3, reply.size());
        for (const auto& p : reply)
            CPPUNIT_ASSERT(isEnvelope(p, transport::EnvelopeType::Data));
    }
    void deliver(TransportTestNode& a, const SockAddr& from, size_t index)
    {
        a.engine->processMessage(reply[index].data.data(), reply[index].data.size(), from);
    }
    bool received() const { return got and got->size() == 1 and (*got)[0]->data == data; }

    Blob data;
    std::optional<std::vector<Sp<Value>>> got;
    Sp<Request> request;
    std::vector<TestDatagramSocket::SentPacket> reply;
};

void
NetworkEngineTester::testTransportEncryptedFragmentsIgnorePlaintextParts()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    establishSession(a, b);
    FragmentedReply r(a, b);
    const auto tid = r.request->getTid();
    const Blob forged(r.FRAGMENT, 'z');

    // Plaintext fragments spoofed from b's address, before and after the header, must not be merged
    auto early = makeValueDataPacketBlob(tid, 0, 0, forged);
    a.engine->processMessage(early.data(), early.size(), b.addr);
    r.deliver(a, b.addr, 0);
    auto late = makeValueDataPacketBlob(tid, 0, r.FRAGMENT, Blob(r.data.size() - r.FRAGMENT, 'z'));
    a.engine->processMessage(late.data(), late.size(), b.addr);
    r.deliver(a, b.addr, 1);
    r.deliver(a, b.addr, 2);
    CPPUNIT_ASSERT(r.received());
}

void
NetworkEngineTester::testTransportEncryptedFragmentsIgnorePlaintextHeader()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    establishSession(a, b);
    FragmentedReply r(a, b);
    const auto tid = r.request->getTid();

    // A plaintext header spoofed from b's address must not claim the transaction
    auto header = makeReplyHeaderPacketBlob(b.id, tid, {r.data.size()});
    a.engine->processMessage(header.data(), header.size(), b.addr);
    for (size_t i = 0; i < 3; i++)
        r.deliver(a, b.addr, i);
    CPPUNIT_ASSERT(r.received());
}

void
NetworkEngineTester::testTransportEncryptedFragmentsRequireSenderKey()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    establishSession(a, b);
    auto sender = transport::KeyPair::generate();
    auto ephemeral = transport::KeyPair::generate();
    for (auto type : {transport::EnvelopeType::Initial, transport::EnvelopeType::Session}) {
        FragmentedReply r(a, b);
        auto replySession = b.engine->session(*b.node(a)->getTransport(), a.addr);
        for (auto& packet : r.reply) {
            auto payload = transport::open(replySession->keys.tx, packet.data.data(), packet.data.size());
            CPPUNIT_ASSERT(payload);
            packet.data = transport::seal(replySession->keys.tx,
                                          transport::EnvelopeType::Session,
                                          b.key.pub,
                                          replySession->ephemeral,
                                          payload->data(),
                                          payload->size());
        }
        auto receiver = a.engine->epoch_.ephemeral(b.addr);
        auto key = type == transport::EnvelopeType::Initial
                       ? *transport::initialSendKey(sender, ephemeral, a.key.pub, 0)
                       : transport::sessionKeys(sender, ephemeral, a.key.pub, receiver.pub, 0)->tx;
        auto fragment = makeValueDataPacketBlob(r.request->getTid(), 0, 0, Blob(r.FRAGMENT, 'z'));
        auto packet = transport::seal(key, type, sender.pub, ephemeral.pub, fragment.data(), fragment.size());
        a.engine->processMessage(packet.data(), packet.size(), b.addr);
        if (type == transport::EnvelopeType::Initial)
            CPPUNIT_ASSERT_EQUAL(size_t(0), a.engine->getPartialCount());
        r.deliver(a, b.addr, 1);
        a.engine->processMessage(packet.data(), packet.size(), b.addr);
        r.deliver(a, b.addr, 0);
        r.deliver(a, b.addr, 2);
        CPPUNIT_ASSERT(r.received());
        a.engine->partial_messages.clear();
    }
}

/* every packet of a fragmented value fits the IPv6 minimum MTU, less the IPv6 and UDP headers,
 * with fragments as large as the envelope `overhead` allows */
static void
checkFragmentsFitMinimumMtu(TransportTestNode& a, TransportTestNode& b, size_t overhead)
{
    constexpr size_t MAX_PAYLOAD {1280 - 40 - 8};
    const Blob data(5000, 'x');
    const size_t fragment = net::NetworkEngine::FRAGMENT_SIZE - overhead;
    b.values = {std::make_shared<Value>(data.data(), data.size())};
    std::optional<std::vector<Sp<Value>>> got;
    a.get(a.node(b), got);
    a.deliverTo(b);
    auto reply = b.takeSent();
    CPPUNIT_ASSERT_EQUAL(1 + (data.size() + fragment - 1) / fragment, reply.size());
    for (const auto& p : reply)
        CPPUNIT_ASSERT_LESSEQUAL(MAX_PAYLOAD, p.data.size());
    for (const auto& p : reply)
        a.engine->processMessage(p.data.data(), p.data.size(), b.addr);
    CPPUNIT_ASSERT(got and got->size() == 1 and (*got)[0]->data == data);
}

void
NetworkEngineTester::testValueFragmentsFitMinimumMtu()
{
    constexpr NetId network = 0x7fffffff;
    {
        TransportTestNode a("127.0.0.2", legacyTransport(), 1, network);
        TransportTestNode b("127.0.0.3", legacyTransport(), 2, network);
        checkFragmentsFitMinimumMtu(a, b, 0);
    }
    {
        // Smallest overhead: Data envelopes, once the session is confirmed
        TransportTestNode a("127.0.0.2", {}, 1, network);
        TransportTestNode b("127.0.0.3", {}, 2, network);
        establishSession(a, b);
        checkFragmentsFitMinimumMtu(a, b, transport::DATA_ENVELOPE_OVERHEAD);
    }
    {
        // Largest overhead: Session envelopes with a credential, until a confirms b's session
        auto authority = transport::Authority::generate();
        TransportTestNode a("127.0.0.2", privateTransport(authority), 1, network);
        TransportTestNode b("127.0.0.3", privateTransport(authority), 2, network);
        bool done = false;
        a.ping(b.addr, done);
        a.deliverTo(b);
        b.deliverTo(a);
        CPPUNIT_ASSERT(done);
        checkFragmentsFitMinimumMtu(a, b, transport::MAX_ENVELOPE_OVERHEAD);
    }
}

/* Type of the message in an Initial envelope, opened by its receiver */
static MessageType
initialMessageType(const TestDatagramSocket::SentPacket& p, const transport::KeyPair& receiver)
{
    auto header = transport::parseHeader(p.data.data(), p.data.size());
    CPPUNIT_ASSERT(header and header->type == transport::EnvelopeType::Initial);
    auto key = transport::initialReceiveKey(receiver, header->sender, header->ephemeral, 0);
    CPPUNIT_ASSERT(key);
    auto payload = transport::open(*key, p.data.data(), p.data.size());
    CPPUNIT_ASSERT(payload);
    if (header->credential)
        payload->erase(payload->begin(), payload->begin() + transport::Credential::PACKED_SIZE);
    ParsedMessage msg;
    parseMessage(msg, *payload);
    return msg.type;
}

static Sp<Request>
sendTestListen(TransportTestNode& a, const Sp<Node>& dest, std::optional<Blob>& token)
{
    return a.engine->sendListen(dest,
                                InfoHash::getRandom(a.rd),
                                {},
                                {},
                                1,
                                [&token](const net::Request&, net::RequestAnswer&& answer) {
                                    token = std::move(answer.ntoken);
                                },
                                {});
}

void
NetworkEngineTester::testTransportRetryRecoversSessionBeforePayload()
{
    TransportConfig configB;
    configB.key = transport::KeyPair::generate();
    TransportTestNode a("127.0.0.2", {}, 1);
    auto b = std::make_unique<TransportTestNode>("127.0.0.3", configB, 2);
    establishSession(a, *b);

    // b restarts with the same key: it lost the session and drops a's Data envelope
    b = std::make_unique<TransportTestNode>("127.0.0.3", configB, 3);
    std::optional<Blob> token;
    sendTestListen(a, a.node(*b), token);
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Data));
    a.deliverTo(*b);
    CPPUNIT_ASSERT(b->socket->sends.empty());

    // The retry recovers the session with a ping in an Initial envelope, without the listen
    advanceTime(a, std::chrono::milliseconds(1500));
    CPPUNIT_ASSERT_EQUAL((size_t) 1, a.socket->sends.size());
    CPPUNIT_ASSERT(initialMessageType(a.socket->sends[0], b->key) == MessageType::Ping);
    a.deliverTo(*b);
    CPPUNIT_ASSERT(isEnvelope(b->socket->sends.at(0), transport::EnvelopeType::Session));
    b->deliverTo(a);

    // The pong carries b's ephemeral key: the listen follows at once, in a Session envelope b accepts
    CPPUNIT_ASSERT_EQUAL((size_t) 1, a.socket->sends.size());
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends[0], transport::EnvelopeType::Session));
    a.deliverTo(*b);
    CPPUNIT_ASSERT_EQUAL(1, b->listens);
    b->deliverTo(a);
    CPPUNIT_ASSERT(token and token->empty());
}

void
NetworkEngineTester::testTransportRetryNeverResendsPayloadInInitial()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    establishSession(a, b);

    // Nothing reaches b: until the listen expires, Initial envelopes only carry pings
    std::optional<Blob> token;
    auto req = sendTestListen(a, a.node(b), token);
    a.takeSent();
    size_t initials = 0;
    for (int i = 0; i < 60; i++) {
        advanceTime(a, std::chrono::milliseconds(250));
        for (const auto& p : a.takeSent()) {
            CPPUNIT_ASSERT(initialMessageType(p, b.key) == MessageType::Ping);
            ++initials;
        }
    }
    CPPUNIT_ASSERT(initials > 0);
    CPPUNIT_ASSERT(req->expired());
    CPPUNIT_ASSERT(not token);
}

void
NetworkEngineTester::testTransportRecoveryWithholdsAllRequests()
{
    TransportConfig configB;
    configB.key = transport::KeyPair::generate();
    TransportTestNode a("127.0.0.2", {}, 1);
    auto b = std::make_unique<TransportTestNode>("127.0.0.3", configB, 2);
    establishSession(a, *b);

    // b restarts: both listens are lost, and their retries share one recovery ping
    b = std::make_unique<TransportTestNode>("127.0.0.3", configB, 3);
    std::optional<Blob> token1, token2, token3;
    sendTestListen(a, a.node(*b), token1);
    sendTestListen(a, a.node(*b), token2);
    a.deliverTo(*b);
    advanceTime(a, std::chrono::milliseconds(1500));
    CPPUNIT_ASSERT_EQUAL((size_t) 1, a.socket->sends.size());
    CPPUNIT_ASSERT(initialMessageType(a.socket->sends[0], b->key) == MessageType::Ping);

    // A new request waits for the recovery too
    sendTestListen(a, a.node(*b), token3);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, a.socket->sends.size());
    a.deliverTo(*b);
    b->deliverTo(a);

    // The pong releases all of them in Session envelopes
    CPPUNIT_ASSERT_EQUAL((size_t) 3, a.socket->sends.size());
    for (const auto& p : a.socket->sends)
        CPPUNIT_ASSERT(isEnvelope(p, transport::EnvelopeType::Session));
    a.deliverTo(*b);
    CPPUNIT_ASSERT_EQUAL(3, b->listens);
    b->deliverTo(a);
    CPPUNIT_ASSERT(token1 and token2 and token3);
}

void
NetworkEngineTester::testTransportColdRequestsShareProbe()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    bool callerDone = false;
    auto caller = a.ping(a.node(b), callerDone);
    caller->cancel();
    std::optional<std::vector<Sp<Value>>> first, second;
    auto req = a.get(a.node(b), first);
    auto cancelled = a.get(a.node(b), second);
    cancelled->cancel();
    auto packets = a.takeSent();
    CPPUNIT_ASSERT_EQUAL(size_t(2), packets.size());
    for (const auto& packet : packets) {
        ParsedMessage msg;
        parseMessage(msg, packet.data);
        CPPUNIT_ASSERT(msg.type == MessageType::Ping);
    }
    b.engine->processMessage(packets.back().data.data(), packets.back().data.size(), a.addr);
    b.deliverTo(a);
    CPPUNIT_ASSERT_EQUAL(size_t(1), a.socket->sends.size());
    CPPUNIT_ASSERT(isEnvelope(a.socket->sends.front(), transport::EnvelopeType::Session));
    a.deliverTo(b);
    b.deliverTo(a);
    CPPUNIT_ASSERT(req->completed());
    CPPUNIT_ASSERT(first and first->empty());
    CPPUNIT_ASSERT(not second);
    CPPUNIT_ASSERT(not callerDone);
}

void
NetworkEngineTester::testTransportDelayedReplyDoesNotResend()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    establishSession(a, b);
    std::optional<std::vector<Sp<Value>>> got;
    auto req = a.get(a.node(b), got);
    a.deliverTo(b);
    auto reply = b.takeSent();
    advanceTime(a, std::chrono::milliseconds(1500));
    a.takeSent();
    for (const auto& packet : reply)
        a.engine->processMessage(packet.data.data(), packet.data.size(), b.addr);
    CPPUNIT_ASSERT(req->completed());
    CPPUNIT_ASSERT(got);
    CPPUNIT_ASSERT(a.socket->sends.empty());
}

void
NetworkEngineTester::testTransportAuthenticatedReplyCanMoveNode()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    establishSession(a, b);
    auto node = a.node(b);
    std::optional<std::vector<Sp<Value>>> got;
    auto req = a.get(node, got);
    a.takeSent();
    auto moved = makeIPv4("127.0.0.4", 4222);
    auto reply = std::make_unique<ParsedMessage>();
    reply->type = MessageType::Reply;
    reply->id = b.id;
    reply->tid = req->getTid();
    reply->session = reply->encrypted = true;
    reply->peer = std::make_shared<transport::Peer>(b.key.pub);
    reply->peer->setEphemeral(*node->getTransport()->ephemeral, moved);
    a.engine->process(std::move(reply), moved);
    CPPUNIT_ASSERT(req->completed());
    CPPUNIT_ASSERT(node->getAddr() == moved);
    CPPUNIT_ASSERT(got);
}

void
NetworkEngineTester::testTransportRecoveryRefreshesDeadline()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    establishSession(a, b);
    std::optional<std::vector<Sp<Value>>> got;
    auto req = a.get(a.node(b), got);
    a.takeSent();
    advanceTime(a, std::chrono::milliseconds(1500));
    a.deliverTo(b);
    advanceTime(a, std::chrono::milliseconds(3000));
    a.takeSent();
    b.deliverTo(a);
    CPPUNIT_ASSERT_EQUAL(size_t(1), a.takeSent().size());
    advanceTime(a, std::chrono::milliseconds(250));
    CPPUNIT_ASSERT(a.socket->sends.empty());
    CPPUNIT_ASSERT(req->pending());
    a.engine->clear();
    advanceTime(a, std::chrono::seconds(30));
    CPPUNIT_ASSERT(a.socket->sends.empty());
}

void
NetworkEngineTester::testTransportSearchRoutesBeforeFetching()
{
    auto authority = transport::Authority::generate();
    for (int mode = 0; mode < 3; ++mode) {
        bool privateNetwork = mode == 2;
        TransportTestNode b("192.0.2.3", privateNetwork ? privateTransport(authority) : TransportConfig {}, 2);
        TransportTestNode c("192.0.2.4", privateNetwork ? privateTransport(authority) : TransportConfig {}, 3);
        Config config {};
        if (privateNetwork)
            config.transport = privateTransport(authority);
        config.max_req_per_sec = config.max_peer_req_per_sec = -1;
        auto socket = std::make_unique<TestDatagramSocket>();
        auto* packets = socket.get();
        Dht local(std::move(socket), config, {}, std::make_unique<std::mt19937_64>(1));
        auto sr = std::make_shared<Dht::Search>();
        sr->id = c.id;
        sr->af = AF_INET;
        sr->refill_time = local.scheduler.time();
        sr->nextSearchStep = local.scheduler.add(time_point::max(), [&] { local.searchStep(sr); });
        auto query = std::make_shared<Query>();
        size_t received = 0;
        sr->get(
            {},
            query,
            {},
            [&](const auto& values) {
                received += values.size();
                return true;
            },
            [](bool, const auto&) {},
            local.scheduler);
        local.searches(AF_INET).emplace(sr->id, sr);
        auto node = local.network_engine.insertNode(b.id, b.addr);
        if (mode != 0)
            node->setTransport(std::make_shared<transport::Peer>(b.key.pub));
        auto closer = b.node(c);
        closer->setTransport(std::make_shared<transport::Peer>(c.key.pub));
        b.routing.nodes4.emplace_back(closer);
        c.values = {std::make_shared<Value>(Blob(4096, 'v'))};
        c.values.front()->id = 42;
        local.searchSendGetValues(sr);
        CPPUNIT_ASSERT_EQUAL(size_t(1), packets->sends.size());
        if (mode == 0) {
            ParsedMessage msg;
            parseMessage(msg, packets->sends.front().data);
            CPPUNIT_ASSERT(msg.type == MessageType::FindNode);
        } else
            CPPUNIT_ASSERT(initialMessageType(packets->sends.front(), b.key) == MessageType::FindNode);
        auto deliver = [&](TransportTestNode& peer) {
            auto sent = std::exchange(packets->sends, {});
            for (const auto& packet : sent)
                if (packet.dest == peer.addr)
                    peer.engine->processMessage(packet.data.data(), packet.data.size(), packets->bound_);
            for (const auto& packet : peer.takeSent())
                local.network_engine.processMessage(packet.data.data(), packet.data.size(), peer.addr);
        };
        deliver(b);
        CPPUNIT_ASSERT_EQUAL(size_t(1), sr->callbacks.size());
        CPPUNIT_ASSERT_EQUAL(size_t(0), received);
        CPPUNIT_ASSERT(sr->getNode(node)->getStatus.empty());
        local.scheduler.run();
        CPPUNIT_ASSERT(not packets->sends.empty());
        CPPUNIT_ASSERT(packets->sends.front().dest == c.addr);
        CPPUNIT_ASSERT(initialMessageType(packets->sends.front(), c.key) == MessageType::FindNode);
        deliver(c);
        CPPUNIT_ASSERT_EQUAL(1, c.finds);
        CPPUNIT_ASSERT_EQUAL(0, c.gets);
        CPPUNIT_ASSERT_EQUAL(size_t(0), received);
        local.scheduler.run();
        CPPUNIT_ASSERT(not packets->sends.empty());
        CPPUNIT_ASSERT(isEnvelope(packets->sends.front(), transport::EnvelopeType::Session, privateNetwork));
        deliver(c);
        CPPUNIT_ASSERT_EQUAL(1, c.gets);
        deliver(c);
        CPPUNIT_ASSERT_EQUAL(2, c.gets);
        CPPUNIT_ASSERT_EQUAL(size_t(1), received);
    }
}

void
NetworkEngineTester::testTransportSearchProbeSlots()
{
    Config config {};
    config.max_req_per_sec = config.max_peer_req_per_sec = -1;
    auto socket = std::make_unique<TestDatagramSocket>();
    auto* packets = socket.get();
    Dht local(std::move(socket), config, {}, std::make_unique<std::mt19937_64>(1));
    auto sr = std::make_shared<Dht::Search>();
    sr->id = InfoHash::getRandom(local.rd);
    sr->af = AF_INET;
    sr->refill_time = local.scheduler.time();
    sr->nextSearchStep = local.scheduler.add(time_point::max(), [&] { local.searchStep(sr); });
    auto query = std::make_shared<Query>();
    sr->get({}, query, {}, [](const auto&) { return true; }, [](bool, const auto&) {}, local.scheduler);
    local.searches(AF_INET).emplace(sr->id, sr);
    for (int index = 0; index < 8; ++index) {
        auto key = transport::KeyPair::generate();
        auto node = local.network_engine.insertNode(transport::nodeId(key.pub), makeIPv4("127.0.0.3", 4200 + index));
        node->setTransport(std::make_shared<transport::Peer>(key.pub));
    }
    local.scheduler.run();
    CPPUNIT_ASSERT_EQUAL(size_t(4), packets->sends.size());
    CPPUNIT_ASSERT_EQUAL(4u, sr->currentlySolicitedNodeCount());
    CPPUNIT_ASSERT(not local.searchSendGetValues(sr));
    local.scheduler.syncTime(local.scheduler.time() + std::chrono::milliseconds(1500));
    local.scheduler.run();
    CPPUNIT_ASSERT_EQUAL(4u, sr->currentlySolicitedNodeCount());
    size_t candidates = 0;
    for (const auto& node : sr->nodes)
        candidates += node->candidate;
    CPPUNIT_ASSERT_EQUAL(size_t(4), candidates);
    CPPUNIT_ASSERT_EQUAL(size_t(1), sr->callbacks.size());
    CPPUNIT_ASSERT(not sr->isDone(sr->callbacks.begin()->second));
    std::vector<Sp<Request>> probes;
    for (const auto& node : sr->nodes)
        if (node->routingProbe)
            probes.emplace_back(node->routingProbe);
    sr->nodes.clear();
    for (const auto& probe : probes)
        CPPUNIT_ASSERT(probe->cancelled());
}

void
NetworkEngineTester::testTransportSearchHalfUnreachable()
{
    Config config {};
    config.max_req_per_sec = config.max_peer_req_per_sec = -1;
    auto socket = std::make_unique<TestDatagramSocket>();
    auto* packets = socket.get();
    Dht local(std::move(socket), config, {}, std::make_unique<std::mt19937_64>(1));
    auto sr = std::make_shared<Dht::Search>();
    sr->id = InfoHash::getRandom(local.rd);
    sr->af = AF_INET;
    sr->refill_time = local.scheduler.time();
    sr->nextSearchStep = local.scheduler.add(time_point::max(), [&] { local.searchStep(sr); });
    auto query = std::make_shared<Query>();
    bool done = false;
    sr->get({}, query, {}, [](const auto&) { return true; }, [&](bool ok, const auto&) { done = ok; }, local.scheduler);
    local.searches(AF_INET).emplace(sr->id, sr);
    std::vector<std::unique_ptr<TransportTestNode>> peers;
    for (int index = 0; index < 8; ++index) {
        auto peer = std::make_unique<TransportTestNode>("192.0.2.3", TransportConfig {}, index + 2);
        peer->addr.setPort(4200 + index);
        auto node = local.network_engine.insertNode(peer->id, peer->addr);
        node->setTransport(std::make_shared<transport::Peer>(peer->key.pub));
        peers.emplace_back(std::move(peer));
    }
    std::set<uint16_t> contacted;
    for (int step = 0; step < 24 and not done; ++step) {
        local.scheduler.run();
        CPPUNIT_ASSERT(sr->currentlySolicitedNodeCount() <= 4);
        for (const auto& packet : std::exchange(packets->sends, {})) {
            for (size_t index = 0; index < peers.size(); ++index) {
                auto& peer = *peers[index];
                if (packet.dest != peer.addr)
                    continue;
                contacted.insert(peer.addr.getPort());
                if (index % 2 == 0) {
                    peer.engine->processMessage(packet.data.data(), packet.data.size(), packets->bound_);
                    for (const auto& reply : peer.takeSent())
                        local.network_engine.processMessage(reply.data.data(), reply.data.size(), peer.addr);
                }
            }
        }
        local.scheduler.syncTime(local.scheduler.time() + std::chrono::milliseconds(250));
    }
    CPPUNIT_ASSERT(done);
    CPPUNIT_ASSERT_EQUAL(size_t(8), contacted.size());
    for (size_t index = 0; index < peers.size(); ++index) {
        if (index % 2 == 0)
            CPPUNIT_ASSERT(peers[index]->gets > 0);
        else
            CPPUNIT_ASSERT_EQUAL(0, peers[index]->gets);
    }
}

void
NetworkEngineTester::testTransportProbeFailureNotifiesWaiters()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    auto node = a.node(b);
    node->setTransport(std::make_shared<transport::Peer>(b.key.pub));
    size_t stalled = 0, expired = 0;
    auto req = a.engine->sendGetValues(node, b.id, {}, -1, {}, [&](const Request&, bool over) {
        if (over)
            ++expired;
        else
            ++stalled;
    });
    for (int step = 0; step < 60; ++step) {
        for (const auto& packet : a.takeSent())
            CPPUNIT_ASSERT(initialMessageType(packet, b.key) == MessageType::Ping);
        advanceTime(a, std::chrono::milliseconds(250));
    }
    CPPUNIT_ASSERT_EQUAL(size_t(1), stalled);
    CPPUNIT_ASSERT_EQUAL(size_t(1), expired);
    CPPUNIT_ASSERT(req->expired());
    CPPUNIT_ASSERT(node->isExpired());
}

void
NetworkEngineTester::testTransportProbeErrorExpiresWaiters()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2);
    b.engine->onPing = [](Sp<Node>) -> RequestAnswer {
        throw DhtProtocolException {DhtProtocolException::UNAUTHORIZED, "Rejected"};
    };
    std::optional<std::vector<Sp<Value>>> got;
    auto req = a.get(a.node(b), got);
    a.deliverTo(b);
    b.deliverTo(a);
    CPPUNIT_ASSERT(req->expired());
    CPPUNIT_ASSERT(not got);
    advanceTime(a, std::chrono::seconds(15));
    CPPUNIT_ASSERT(a.socket->sends.empty());
}

void
NetworkEngineTester::testTransportFindReleasesWaiters()
{
    auto authority = transport::Authority::generate();
    for (bool privateNetwork : {false, true}) {
        TransportTestNode a("127.0.0.2", privateNetwork ? privateTransport(authority) : TransportConfig {}, 1);
        TransportTestNode b("127.0.0.3", privateNetwork ? privateTransport(authority) : TransportConfig {}, 2);
        auto node = a.node(b);
        node->setTransport(std::make_shared<transport::Peer>(b.key.pub));
        std::optional<std::vector<Sp<Value>>> got;
        auto req = a.get(node, got);
        a.takeSent();
        bool found = false;
        a.engine->sendFindNode(node, b.id, -1, [&](const Request&, RequestAnswer&&) { found = true; }, {});
        a.deliverTo(b);
        b.deliverTo(a);
        CPPUNIT_ASSERT(found);
        CPPUNIT_ASSERT_EQUAL(size_t(1), a.socket->sends.size());
        CPPUNIT_ASSERT(isEnvelope(a.socket->sends.front(), transport::EnvelopeType::Session, privateNetwork));
        a.deliverTo(b);
        b.deliverTo(a);
        CPPUNIT_ASSERT(req->completed());
        CPPUNIT_ASSERT(got);
        advanceTime(a, std::chrono::seconds(15));
        CPPUNIT_ASSERT(a.socket->sends.empty());
        CPPUNIT_ASSERT(not node->isExpired());
    }
}

void
NetworkEngineTester::testTransportColdLegacyGet()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode legacy("127.0.0.3", legacyTransport(), 2);
    legacy.values = {std::make_shared<Value>(Blob(4096, 'x'))};
    std::optional<std::vector<Sp<Value>>> got;
    auto req = a.get(a.node(legacy), got);
    a.deliverTo(legacy);
    CPPUNIT_ASSERT_EQUAL(0, legacy.gets);
    legacy.deliverTo(a);
    CPPUNIT_ASSERT_EQUAL(size_t(1), a.socket->sends.size());
    CPPUNIT_ASSERT(not transport::parseHeader(a.socket->sends.front().data.data(), a.socket->sends.front().data.size()));
    a.deliverTo(legacy);
    legacy.deliverTo(a);
    CPPUNIT_ASSERT(req->completed());
    CPPUNIT_ASSERT(got and got->size() == 1);
    CPPUNIT_ASSERT(got->front()->data == legacy.values.front()->data);
}

void
NetworkEngineTester::testTransportPlaintextCannotPoisonSessionCache()
{
    TransportTestNode receiver("127.0.0.2", {}, 1);
    TransportTestNode peer("127.0.0.3", {}, 2);
    TransportTestNode victim("127.0.0.4", {}, 3);
    establishSession(receiver, peer);
    establishSession(receiver, victim);
    const auto cached = receiver.engine->epoch_.sessions.size();
    const auto ephemeral = receiver.node(peer)->getTransport()->ephemeral;
    CPPUNIT_ASSERT(receiver.engine->session(*receiver.node(peer)->getTransport(), victim.addr));
    CPPUNIT_ASSERT(receiver.engine->epoch_.find(victim.addr)->peer == victim.key.pub);
    auto ping = makePingPacketBlob(peer.id, 77);
    receiver.engine->processMessage(ping.data(), ping.size(), victim.addr);
    receiver.takeSent();
    CPPUNIT_ASSERT(receiver.engine->epoch_.find(victim.addr)->peer == victim.key.pub);

    for (unsigned index = 0; index < 64; ++index) {
        auto from = makeIPv4("203.0.113.7", 10000 + index);
        receiver.engine->processMessage(ping.data(), ping.size(), from);
    }
    CPPUNIT_ASSERT_EQUAL(cached, receiver.engine->epoch_.sessions.size());
    CPPUNIT_ASSERT(receiver.node(peer)->getTransport()->ephemeral == ephemeral);
    receiver.takeSent();

    bool done = false;
    victim.ping(victim.node(receiver), done);
    victim.deliverTo(receiver);
    CPPUNIT_ASSERT(isEnvelope(receiver.socket->sends.at(0), transport::EnvelopeType::Data));
    receiver.deliverTo(victim);
    CPPUNIT_ASSERT(done);
}

void
NetworkEngineTester::testTransportPlaintextCannotUpdateKeyedNode()
{
    TransportTestNode receiver("127.0.0.2", {}, 1);
    TransportTestNode peer("127.0.0.3", {}, 2);
    establishSession(receiver, peer);
    size_t expired = 0;
    auto socketId = receiver.node(peer)->openSocket([&](const Sp<Node>&, net::RequestAnswer&& answer) {
        expired += answer.expired_values.size();
    });
    for (bool legacy : {false, true}) {
        msgpack::sbuffer buffer;
        msgpack::packer<msgpack::sbuffer> pk(&buffer);
        pk.pack_map(legacy ? 3 : 4);
        pk.pack(legacy ? KEY_U : KEY_A);
        pk.pack_map(legacy ? 2 : 3);
        pk.pack(KEY_REQ_ID);
        pk.pack(peer.id);
        if (not legacy) {
            pk.pack(KEY_REQ_SID);
            pk.pack(socketId);
        }
        pk.pack(KEY_REQ_EXPIRED);
        pk.pack(std::vector<Value::Id> {42});
        if (not legacy) {
            pk.pack(KEY_Q);
            pk.pack(QUERY_UPDATE);
        }
        pk.pack(KEY_TID);
        pk.pack(legacy ? socketId : 77);
        pk.pack(KEY_Y);
        pk.pack(legacy ? KEY_R : KEY_Q);
        for (const auto& from : {peer.addr, makeIPv4("127.0.0.66", 4222)}) {
            receiver.engine->processMessage((const uint8_t*) buffer.data(), buffer.size(), from);
            CPPUNIT_ASSERT_EQUAL((size_t) 0, expired);
            CPPUNIT_ASSERT(receiver.socket->sends.empty());
        }
    }
    peer.engine->tellListenerExpired(peer.node(receiver), socketId, {}, {42}, 1);
    peer.deliverTo(receiver);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, expired);
}

void
NetworkEngineTester::testTransportPlaintextCannotCompleteEncryptedRequest()
{
    TransportTestNode receiver("127.0.0.2", {}, 1);
    TransportTestNode peer("127.0.0.3", {}, 2);
    establishSession(receiver, peer);
    auto node = receiver.node(peer);
    const auto ephemeral = node->getTransport()->ephemeral;
    bool done = false;
    auto request = receiver.ping(node, done);
    auto reply = makeReplyHeaderPacketBlob(peer.id, request->getTid(), {});
    receiver.engine->processMessage(reply.data(), reply.size(), peer.addr);
    CPPUNIT_ASSERT(not done);
    CPPUNIT_ASSERT(request->pending());

    auto advertisement = makePingPacketBlob(peer.id, 78, peer.key.pub);
    receiver.engine->processMessage(advertisement.data(), advertisement.size(), peer.addr);
    CPPUNIT_ASSERT(node->getTransport()->ephemeral == ephemeral);
    CPPUNIT_ASSERT(receiver.engine->epoch_.find(peer.addr)->confirmed);
    receiver.deliverTo(peer);
    peer.deliverTo(receiver);
    CPPUNIT_ASSERT(done);
}

void
NetworkEngineTester::testTransportInitialReplayKeepsPeerState()
{
    TransportTestNode receiver("127.0.0.2", {}, 1);
    TransportTestNode peer("127.0.0.3", {}, 2);
    bool done = false;
    receiver.ping(peer.addr, done);
    receiver.deliverTo(peer);
    auto initial = peer.socket->sends.at(0);
    CPPUNIT_ASSERT(isEnvelope(initial, transport::EnvelopeType::Initial));
    peer.deliverTo(receiver);
    establishSession(receiver, peer);
    auto node = receiver.node(peer);
    const auto ephemeral = node->getTransport()->ephemeral;
    const auto newNodes = receiver.newNodes;
    auto oldEphemeral = transport::KeyPair::generate();
    auto ping = makePingPacketBlob(peer.id, 79);
    auto initialPing = transport::seal(*transport::initialSendKey(peer.key, oldEphemeral, receiver.key.pub, 0),
                                       transport::EnvelopeType::Initial,
                                       peer.key.pub,
                                       oldEphemeral.pub,
                                       ping.data(),
                                       ping.size());
    for (const auto& from : {peer.addr, makeIPv4("127.0.0.66", 4222)}) {
        for (const auto& packet : {initial.data, initialPing}) {
            receiver.engine->processMessage(packet.data(), packet.size(), from);
            CPPUNIT_ASSERT(node->getAddr() == peer.addr);
            CPPUNIT_ASSERT(node->getTransport()->ephemeral == ephemeral);
            CPPUNIT_ASSERT_EQUAL(newNodes, receiver.newNodes);
            CPPUNIT_ASSERT(receiver.engine->epoch_.find(peer.addr)->confirmed);
        }
    }
    receiver.takeSent();
    done = false;
    receiver.ping(node, done);
    CPPUNIT_ASSERT(isEnvelope(receiver.socket->sends.at(0), transport::EnvelopeType::Data));
    receiver.deliverTo(peer);
    peer.deliverTo(receiver);
    CPPUNIT_ASSERT(done);
}

void
NetworkEngineTester::testTransportInitialAddressChangeNeedsSession()
{
    auto authority = transport::Authority::generate();
    for (bool isPrivate : {false, true}) {
        auto config = isPrivate ? privateTransport(authority) : TransportConfig {};
        if (not config.key)
            config.key = transport::KeyPair::generate();
        TransportTestNode peer("127.0.0.3", config, 2);
        TransportTestNode receiver("127.0.0.2", isPrivate ? privateTransport(authority) : TransportConfig {}, 1);
        establishSession(receiver, peer);
        auto node = receiver.node(peer);
        TransportTestNode moved("127.0.0.4", config, 3);
        auto remote = moved.node(receiver);
        remote->setTransport(std::make_shared<transport::Peer>(receiver.key.pub));
        bool done = false;
        moved.ping(remote, done);
        moved.deliverTo(receiver);
        CPPUNIT_ASSERT(node->getAddr() == peer.addr);
        receiver.deliverTo(moved);
        CPPUNIT_ASSERT(done);

        done = false;
        moved.ping(remote, done);
        CPPUNIT_ASSERT(isEnvelope(moved.socket->sends.at(0), transport::EnvelopeType::Session, isPrivate));
        moved.deliverTo(receiver);
        CPPUNIT_ASSERT(node->getAddr() == moved.addr);
        receiver.deliverTo(moved);
        CPPUNIT_ASSERT(done);
    }
}

void
NetworkEngineTester::testTransportEncryptionFailureDoesNotSendPlaintext()
{
    TransportTestNode receiver("127.0.0.2", {}, 1);
    auto from = makeIPv4("127.0.0.3", 4222);
    transport::Key lowOrder {};
    lowOrder[0] = 1;
    auto ping = makePingPacketBlob(transport::nodeId(lowOrder), 80, lowOrder);
    receiver.engine->processMessage(ping.data(), ping.size(), from);
    CPPUNIT_ASSERT(receiver.socket->sends.empty());

    auto peer = std::make_shared<transport::Peer>(transport::KeyPair::generate().pub);
    peer->ephemeral = lowOrder;
    auto node = receiver.engine->insertNode(transport::nodeId(peer->key), from);
    node->setTransport(peer);
    CPPUNIT_ASSERT_EQUAL(EPERM, receiver.engine->send(*node, from, "payload", 7));
    CPPUNIT_ASSERT(receiver.socket->sends.empty());
}

/* Limits of a test node: global quotas, without per-address quotas unless given */
static std::function<void(net::NetworkConfig&)>
rateLimits(ssize_t requests, ssize_t unauthenticated, ssize_t crypto, ssize_t peerCrypto = -1)
{
    return [=](net::NetworkConfig& c) {
        c.max_req_per_sec = requests;
        c.max_unauth_req_per_sec = unauthenticated;
        c.max_crypto_per_sec = crypto;
        c.max_peer_req_per_sec = c.max_peer_unauth_req_per_sec = -1;
        c.max_peer_crypto_per_sec = peerCrypto;
    };
}

/* A distinct source address per index, as a spoofing attacker can use */
static SockAddr
spoofedAddress(unsigned i)
{
    return makeIPv4(("10.1." + std::to_string(i / 256) + "." + std::to_string(i % 256)).c_str(), 4222);
}

static SockAddr
makeIPv6(const char* ip, in_port_t port)
{
    SockAddr addr;
    addr.setFamily(AF_INET6);
    addr.setAddress(ip);
    addr.setPort(port);
    return addr;
}

/* Number of packets sent in answer to an Initial ping from each address */
static size_t
floodInitialPings(TransportTestNode& n, const std::vector<SockAddr>& sources)
{
    for (size_t i = 0; i < sources.size(); i++) {
        auto initial = makeInitialPing(n.key, 1000 + i);
        n.engine->processMessage(initial.data(), initial.size(), sources[i]);
    }
    return n.takeSent().size();
}

static std::vector<SockAddr>
spoofedAddresses(unsigned count, unsigned first = 0)
{
    std::vector<SockAddr> sources;
    for (unsigned i = first; i < first + count; i++)
        sources.emplace_back(spoofedAddress(i));
    return sources;
}

void
NetworkEngineTester::testRateLimitSeparatesSessionRequests()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2, 0, rateLimits(4, 4, -1));
    establishSession(a, b);
    advanceTime(b, std::chrono::seconds(2));

    // A plaintext flood uses up the budget of senders without a session
    std::mt19937_64 rd(3);
    for (unsigned i = 0; i < 10; i++) {
        auto ping = makePingPacketBlob(InfoHash::getRandom(rd), 100 + i);
        b.engine->processMessage(ping.data(), ping.size(), spoofedAddress(i));
    }
    CPPUNIT_ASSERT_EQUAL((size_t) 4, b.takeSent().size());

    // Requests from a validated address have their own
    for (unsigned i = 0; i < 5; i++) {
        bool done = false;
        a.ping(a.node(b), done);
        CPPUNIT_ASSERT(isEnvelope(a.socket->sends.at(0), transport::EnvelopeType::Data));
        a.deliverTo(b);
        CPPUNIT_ASSERT_EQUAL((size_t) (i < 4 ? 1 : 0), b.takeSent().size());
    }
}

void
NetworkEngineTester::testRateLimitCryptoAdmission()
{
    TransportTestNode a("127.0.0.2", {}, 1);
    TransportTestNode b("127.0.0.3", {}, 2, 0, rateLimits(-1, 6, 4));
    establishSession(a, b);
    advanceTime(b, std::chrono::seconds(2));

    // Each Initial request is charged once to each budget
    CPPUNIT_ASSERT_EQUAL((size_t) 4, floodInitialPings(b, spoofedAddresses(10)));

    // Answering a plaintext request advertising a key takes an Initial envelope
    std::mt19937_64 rd(3);
    auto key = transport::KeyPair::generate().pub;
    auto keyed = makePingPacketBlob(transport::nodeId(key), 200, key);
    b.engine->processMessage(keyed.data(), keyed.size(), spoofedAddress(20));
    CPPUNIT_ASSERT(b.takeSent().empty());
    auto legacy = makePingPacketBlob(InfoHash::getRandom(rd), 201);
    b.engine->processMessage(legacy.data(), legacy.size(), spoofedAddress(21));
    CPPUNIT_ASSERT_EQUAL((size_t) 1, b.takeSent().size());
    // The 4 Initial requests, the keyed and the legacy one used the unauthenticated budget
    legacy = makePingPacketBlob(InfoHash::getRandom(rd), 202);
    b.engine->processMessage(legacy.data(), legacy.size(), spoofedAddress(22));
    CPPUNIT_ASSERT(b.takeSent().empty());

    // Established sessions need no key agreement
    bool done = false;
    a.ping(a.node(b), done);
    a.deliverTo(b);
    b.deliverTo(a);
    CPPUNIT_ASSERT(done);
}

void
NetworkEngineTester::testRateLimitCachedSessionCredentials()
{
    auto authority = transport::Authority::generate();
    for (bool cached : {false, true}) {
        auto sender = privateTransport(authority);
        auto ephemeral = transport::KeyPair::generate();
        auto from = makeIPv4("127.0.0.2", 4222);
        TransportTestNode receiver("127.0.0.3", privateTransport(authority), 2, 0, rateLimits(-1, -1, 1));
        auto local = receiver.engine->epoch_.ephemeral(from);
        auto keys = *transport::sessionKeys(receiver.key, local, sender.key.pub, ephemeral.pub, 0);
        if (cached)
            receiver.engine->epoch_.store(from, {local.pub, sender.key.pub, ephemeral.pub, keys});
        auto ping = makePingPacketBlob(transport::nodeId(sender.key.pub), 200);
        auto send = [&](const Blob& credential) {
            auto packet = transport::seal(keys.rx,
                                          transport::EnvelopeType::Session,
                                          sender.key.pub,
                                          ephemeral.pub,
                                          ping.data(),
                                          ping.size(),
                                          credential);
            receiver.engine->processMessage(packet.data(), packet.size(), from);
        };
        auto data = transport::sealData(keys.rx, ping.data(), ping.size());
        receiver.engine->processMessage(data.data(), data.size(), from);
        CPPUNIT_ASSERT(receiver.takeSent().empty());

        auto invalid = sender.credential;
        invalid.signature[0] ^= 1;
        for (int attempt = 0; attempt < 3; ++attempt)
            send(invalid.pack());
        CPPUNIT_ASSERT(receiver.takeSent().empty());
        send(sender.credential.pack());
        CPPUNIT_ASSERT(receiver.takeSent().empty());

        advanceTime(receiver, std::chrono::seconds(2));
        send(sender.credential.pack());
        CPPUNIT_ASSERT_EQUAL(size_t {1}, receiver.takeSent().size());
        CPPUNIT_ASSERT(not receiver.engine->cryptoLimiter_.limit(from, receiver.scheduler.time()));

        send(sender.credential.pack());
        CPPUNIT_ASSERT_EQUAL(size_t {1}, receiver.takeSent().size());
    }
}

void
NetworkEngineTester::testRateLimitCryptoPerPrefix()
{
    TransportTestNode b("127.0.0.3", {}, 2, 0, rateLimits(-1, -1, 100, 2));
    // IPv6 addresses share the budget of their /64 prefix
    CPPUNIT_ASSERT_EQUAL((size_t) 2,
                         floodInitialPings(b,
                                           {makeIPv6("2001:db8::1", 4222),
                                            makeIPv6("2001:db8::2", 4223),
                                            makeIPv6("2001:db8::3:4", 4224)}));
    CPPUNIT_ASSERT_EQUAL((size_t) 1, floodInitialPings(b, {makeIPv6("2001:db8:0:1::1", 4222)}));
    auto v4 = makeIPv4("192.0.2.1", 4222);
    CPPUNIT_ASSERT_EQUAL((size_t) 2, floodInitialPings(b, {v4, v4, v4}));

    // Spoofed sources take no more per-address records than the global budget allows
    TransportTestNode c("127.0.0.4", {}, 3, 0, rateLimits(-1, -1, 4, 1));
    CPPUNIT_ASSERT_EQUAL((size_t) 4, floodInitialPings(c, spoofedAddresses(50)));
    CPPUNIT_ASSERT(c.engine->cryptoLimiter_.size() <= 4);
}

void
NetworkEngineTester::testRateLimitReservesExpectedReplies()
{
    TransportTestNode b("127.0.0.3", {}, 2, 0, rateLimits(-1, -1, 2));
    TransportTestNode c("127.0.0.4", {}, 3);
    CPPUNIT_ASSERT_EQUAL((size_t) 2, floodInitialPings(b, spoofedAddresses(5)));

    // Our own handshakes still complete: c answers in an Initial, then in a Session envelope
    bool done = false;
    b.ping(c.addr, done);
    b.deliverTo(c);
    CPPUNIT_ASSERT(isEnvelope(c.socket->sends.at(0), transport::EnvelopeType::Initial));
    c.deliverTo(b);
    CPPUNIT_ASSERT(done);
    done = false;
    b.ping(b.node(c), done);
    b.deliverTo(c);
    CPPUNIT_ASSERT(isEnvelope(c.socket->sends.at(0), transport::EnvelopeType::Session));
    c.deliverTo(b);
    CPPUNIT_ASSERT(done);

    // Unexpected senders don't get that reserve
    CPPUNIT_ASSERT_EQUAL((size_t) 0, floodInitialPings(b, spoofedAddresses(5, 10)));
}

} // namespace test

#endif