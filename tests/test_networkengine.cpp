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
    TransportTestNode(const char* ip, TransportConfig transport, uint64_t seed, NetId network = 0)
        : rd(seed)
        , addr(makeIPv4(ip, 4222))
    {
        net::NetworkConfig config {};
        config.network = network;
        config.max_req_per_sec = -1;
        config.max_peer_req_per_sec = -1;
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
            [](Sp<Node>, const InfoHash&, want_t) { return net::RequestAnswer {}; },
            [this](Sp<Node>, const InfoHash&, want_t, const Query&) {
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
advance(TransportTestNode& n, std::chrono::steady_clock::duration d)
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
    advance(b, std::chrono::minutes(30));
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
    advance(a, std::chrono::minutes(30));
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
    advance(b, std::chrono::minutes(30));
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
    advance(a, std::chrono::seconds(2));
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
    FragmentedReply r(a, b);
    const auto tid = r.request->getTid();

    // A fragment under another key, in an Initial envelope spoofed from b's address, must not be merged
    auto sender = transport::KeyPair::generate();
    auto ephemeral = transport::KeyPair::generate();
    auto fragment = makeValueDataPacketBlob(tid, 0, 0, Blob(r.FRAGMENT, 'z'));
    auto initial = transport::seal(*transport::initialSendKey(sender, ephemeral, a.key.pub, 0),
                                   transport::EnvelopeType::Initial,
                                   sender.pub,
                                   ephemeral.pub,
                                   fragment.data(),
                                   fragment.size());
    r.deliver(a, b.addr, 0);
    a.engine->processMessage(initial.data(), initial.size(), b.addr);
    r.deliver(a, b.addr, 1);
    r.deliver(a, b.addr, 2);
    CPPUNIT_ASSERT(r.received());
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
    advance(a, std::chrono::milliseconds(1500));
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
        advance(a, std::chrono::milliseconds(250));
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
    advance(a, std::chrono::milliseconds(1500));
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

} // namespace test

#endif