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

    bool hasIPv4() const override { return ipv4; }
    bool hasIPv6() const override { return ipv6; }
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
    bool ipv4 {true};
    bool ipv6 {false};
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
        [](Sp<Node>, const InfoHash&, const Blob&, Tid, const Query&, int, const std::optional<net::ListenSync>&) {
            return net::RequestAnswer {};
        },
        [](Sp<Node>, const InfoHash&, const Blob&, const std::vector<Sp<Value>>&, const time_point&) {
            return net::RequestAnswer {};
        },
        [](Sp<Node>, const InfoHash&, const Blob&, const Value::Id&) { return net::RequestAnswer {}; });
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

struct ListenSnapshotTransport
{
    InfoHash key {InfoHash::get("initial-listen-snapshot")};
    std::vector<Value::Id> received;
    std::vector<bool> results;
    std::vector<size_t> snapshots;
    std::vector<TestDatagramSocket::SentPacket> delayedUpdates;
    TestDatagramSocket* clientPackets;
    TestDatagramSocket* serverPackets;
    SockAddr clientAddr;
    SockAddr serverAddr;
    std::unique_ptr<Dht> client;
    std::unique_ptr<Dht> server;
    size_t token {0};

    ListenSnapshotTransport()
    {
        Config config {};
        config.max_req_per_sec = -1;
        config.max_peer_req_per_sec = -1;
        auto clientSocket = std::make_unique<TestDatagramSocket>();
        clientPackets = clientSocket.get();
        clientAddr = clientPackets->bound_;
        client = std::make_unique<Dht>(std::move(clientSocket),
                                       config,
                                       Sp<Logger> {},
                                       std::make_unique<std::mt19937_64>(30));
        auto serverSocket = std::make_unique<TestDatagramSocket>();
        serverPackets = serverSocket.get();
        serverPackets->bound_.setPort(5031);
        serverAddr = serverPackets->bound_;
        server = std::make_unique<Dht>(std::move(serverSocket),
                                       config,
                                       Sp<Logger> {},
                                       std::make_unique<std::mt19937_64>(31));
    }

    ~ListenSnapshotTransport()
    {
        if (token)
            client->cancelListen(key, token);
    }

    static ParsedMessage parse(const TestDatagramSocket::SentPacket& packet)
    {
        ParsedMessage message;
        message.msgpack_unpack(msgpack::unpack((const char*) packet.data.data(), packet.data.size()).get());
        return message;
    }

    void store(size_t count, size_t payloadSize = 20)
    {
        for (size_t index = 0; index < count; ++index) {
            auto value = std::make_shared<Value>(std::string(payloadSize, 'x'));
            value->id = index + 1;
            CPPUNIT_ASSERT(server->storageStore(key, value, server->scheduler.time()));
        }
    }

    void listen()
    {
        token = client->listen(
            key,
            [this](const std::vector<Sp<Value>>& values, bool expired) {
                if (!expired)
                    for (const auto& value : values)
                        received.emplace_back(value->id);
                return true;
            },
            {},
            {},
            [this](bool ok) {
                results.push_back(ok);
                snapshots.emplace_back(received.size());
            });
        CPPUNIT_ASSERT(token != 0);
    }

    void start(bool confirm = true)
    {
        listen();
        auto search = client->searches(AF_INET).at(key);
        auto node = client->network_engine.insertNode(server->getNodeId(), serverAddr);
        auto* searchNode = search->getNode(node);
        CPPUNIT_ASSERT(searchNode);
        searchNode->token = server->makeToken(clientAddr, false);
        searchNode->last_get_reply = client->scheduler.time();
        client->searchStep(search);
        if (confirm)
            acknowledge();
    }

    void acknowledge()
    {
        auto requests = std::move(clientPackets->sends);
        clientPackets->sends.clear();
        unsigned registrations = 0;
        for (const auto& packet : requests) {
            if (parse(packet).type == MessageType::Listen) {
                ++registrations;
                server->network_engine.processMessage(packet.data.data(), packet.data.size(), clientAddr);
            }
        }
        CPPUNIT_ASSERT_EQUAL(1u, registrations);
        auto replies = std::move(serverPackets->sends);
        serverPackets->sends.clear();
        for (const auto& packet : replies) {
            if (parse(packet).type == MessageType::Reply)
                client->network_engine.processMessage(packet.data.data(), packet.data.size(), serverAddr);
            else
                delayedUpdates.emplace_back(packet);
        }
    }

    void getRound(bool reversed = false)
    {
        for (const auto& packet : clientPackets->sends)
            CPPUNIT_ASSERT(parse(packet).type != MessageType::GetValues);
        if (reversed)
            std::reverse(delayedUpdates.begin(), delayedUpdates.end());
        deliverUpdates();
    }

    void deliverUpdates()
    {
        for (const auto& packet : delayedUpdates)
            client->network_engine.processMessage(packet.data.data(), packet.data.size(), serverAddr);
        delayedUpdates.clear();
    }

    Sp<net::Request> initialRequest() const
    {
        auto search = client->searches(AF_INET).at(key);
        auto& status = search->nodes.front()->listenStatus.begin()->second;
        CPPUNIT_ASSERT(status.req);
        return status.req;
    }
};

void
NetworkEngineTester::setUp()
{}

void
NetworkEngineTester::tearDown()
{}

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
        [responseToken](
            Sp<Node>, const InfoHash&, const Blob&, Tid, const Query&, int, const std::optional<net::ListenSync>&) {
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
NetworkEngineTester::testListenReadinessWaitsForInitialUpdate()
{
    Config config {};
    config.max_req_per_sec = -1;
    config.max_peer_req_per_sec = -1;
    auto clientSocket = std::make_unique<TestDatagramSocket>();
    auto* clientPackets = clientSocket.get();
    auto clientAddr = clientPackets->bound_;
    Dht client(std::move(clientSocket), config, {}, std::make_unique<std::mt19937_64>(20));
    auto serverSocket = std::make_unique<TestDatagramSocket>();
    auto* serverPackets = serverSocket.get();
    serverPackets->bound_.setPort(5020);
    auto serverAddr = serverPackets->bound_;
    Dht server(std::move(serverSocket), config, {}, std::make_unique<std::mt19937_64>(21));
    auto key = InfoHash::get("readiness-reordered-update");
    auto value = std::make_shared<Value>("initial-value");
    value->id = 42;
    CPPUNIT_ASSERT(server.storageStore(key, value, server.scheduler.time()));

    std::vector<Value::Id> received;
    std::vector<size_t> snapshots;
    auto token = client.listen(
        key,
        [&](const std::vector<Sp<Value>>& values, bool expired) {
            if (!expired)
                for (const auto& current : values)
                    received.emplace_back(current->id);
            return true;
        },
        {},
        {},
        [&](bool ok) {
            CPPUNIT_ASSERT(ok);
            snapshots.emplace_back(received.size());
        });
    CPPUNIT_ASSERT(token != 0);
    auto search = client.searches(AF_INET).at(key);
    auto node = client.network_engine.insertNode(server.getNodeId(), serverAddr);
    auto* searchNode = search->getNode(node);
    CPPUNIT_ASSERT(searchNode);
    searchNode->token = server.makeToken(clientAddr, false);
    searchNode->last_get_reply = client.scheduler.time();
    CPPUNIT_ASSERT(search->isSynced(client.scheduler.time()));
    client.searchStep(search);
    CPPUNIT_ASSERT(snapshots.empty());

    auto listen = std::find_if(clientPackets->sends.begin(), clientPackets->sends.end(), [](const auto& packet) {
        ParsedMessage message;
        message.msgpack_unpack(msgpack::unpack((const char*) packet.data.data(), packet.data.size()).get());
        return message.type == MessageType::Listen;
    });
    CPPUNIT_ASSERT(listen != clientPackets->sends.end());
    server.network_engine.processMessage(listen->data.data(), listen->data.size(), clientAddr);
    CPPUNIT_ASSERT(serverPackets->sends.size() >= 2);

    std::vector<TestDatagramSocket::SentPacket> updates;
    std::vector<TestDatagramSocket::SentPacket> confirmations;
    for (const auto& packet : serverPackets->sends) {
        ParsedMessage message;
        message.msgpack_unpack(msgpack::unpack((const char*) packet.data.data(), packet.data.size()).get());
        if (message.type == MessageType::Reply)
            confirmations.emplace_back(packet);
        else if (message.type == MessageType::UpdateValue)
            updates.emplace_back(packet);
    }
    CPPUNIT_ASSERT_EQUAL(size_t(1), confirmations.size());
    CPPUNIT_ASSERT(!updates.empty());
    for (const auto& packet : confirmations)
        client.network_engine.processMessage(packet.data.data(), packet.data.size(), serverAddr);
    CPPUNIT_ASSERT(snapshots.empty());
    serverPackets->sends.clear();
    for (const auto& packet : clientPackets->sends)
        CPPUNIT_ASSERT(ListenSnapshotTransport::parse(packet).type != MessageType::GetValues);
    for (const auto& packet : updates)
        client.network_engine.processMessage(packet.data.data(), packet.data.size(), serverAddr);
    CPPUNIT_ASSERT(client.cancelListen(key, token));
    CPPUNIT_ASSERT(received == std::vector<Value::Id>({42}));
    CPPUNIT_ASSERT_EQUAL(size_t(1), snapshots.size());
    CPPUNIT_ASSERT_EQUAL(size_t(1), snapshots.front());
}

void
NetworkEngineTester::testListenReadinessSnapshotVariants()
{
    for (size_t count : {size_t(0), size_t(3)}) {
        ListenSnapshotTransport transport;
        transport.store(count, 6000);
        transport.start();
        if (count != 0)
            CPPUNIT_ASSERT(transport.results.empty());
        transport.getRound(true);
        CPPUNIT_ASSERT(transport.results == std::vector<bool>({true}));
        CPPUNIT_ASSERT(transport.snapshots == std::vector<size_t>({count}));
        transport.deliverUpdates();
        CPPUNIT_ASSERT_EQUAL(count, transport.received.size());
        CPPUNIT_ASSERT_EQUAL(size_t(1), transport.results.size());
    }
}

void
NetworkEngineTester::testListenReadinessSnapshotLegacy()
{
    for (size_t count : {size_t(0), size_t(3)}) {
        ListenSnapshotTransport transport;
        transport.store(count);
        transport.start(false);
        auto request = transport.initialRequest();
        ParsedMessage answer;
        answer.type = MessageType::Reply;
        answer.token = transport.server->makeToken(transport.clientAddr, false);
        request->setDone(std::move(answer));
        CPPUNIT_ASSERT(transport.results == std::vector<bool>({false}));
        CPPUNIT_ASSERT(transport.received.empty());
    }
}

void
NetworkEngineTester::testListenReadinessSnapshotFailure()
{
    for (unsigned failure = 0; failure < 3; ++failure) {
        ListenSnapshotTransport transport;
        transport.store(1);
        transport.start(false);
        auto request = transport.initialRequest();
        if (failure == 0) {
            request->setExpired();
        } else {
            ParsedMessage answer;
            answer.type = MessageType::Reply;
            if (failure == 2) {
                answer.token = transport.server->makeToken(transport.clientAddr, false);
                answer.fields.emplace_back(std::make_shared<FieldValueIndex>());
            }
            request->setDone(std::move(answer));
        }
        CPPUNIT_ASSERT(transport.results == std::vector<bool>({false}));
        transport.deliverUpdates();
        CPPUNIT_ASSERT_EQUAL(size_t(1), transport.results.size());
    }
}

void
NetworkEngineTester::testListenReadinessSnapshotCancellation()
{
    ListenSnapshotTransport transport;
    transport.store(1);
    transport.start();
    CPPUNIT_ASSERT(transport.client->cancelListen(transport.key, transport.token));
    transport.token = 0;
    transport.getRound();
    transport.getRound();
    CPPUNIT_ASSERT(transport.results.empty());
    transport.listen();
    CPPUNIT_ASSERT(transport.results == std::vector<bool>({true}));
    CPPUNIT_ASSERT(transport.snapshots == std::vector<size_t>({1}));
}

void
NetworkEngineTester::testListenReadinessSnapshotReplacement()
{
    ListenSnapshotTransport transport;
    transport.store(1);
    transport.start();
    auto previous = transport.initialRequest();
    auto search = transport.client->searches(AF_INET).at(transport.key);
    auto* node = search->nodes.front().get();
    auto oldUpdates = std::move(transport.delayedUpdates);
    node->listenStatus.clear();
    transport.clientPackets->sends.clear();
    transport.client->searchSynchedNodeListen(search, *node);
    transport.acknowledge();
    CPPUNIT_ASSERT(transport.results.empty());
    ParsedMessage answer;
    answer.token = transport.server->makeToken(transport.clientAddr, false);
    answer.values = transport.server->getLocal(transport.key);
    previous->setDone(std::move(answer));
    for (const auto& packet : oldUpdates)
        transport.client->network_engine.processMessage(packet.data.data(), packet.data.size(), transport.serverAddr);
    CPPUNIT_ASSERT(transport.results.empty());
    transport.getRound();
    transport.getRound();
    CPPUNIT_ASSERT(transport.results == std::vector<bool>({true}));
    CPPUNIT_ASSERT(transport.snapshots == std::vector<size_t>({1}));
}

void
NetworkEngineTester::testListenReadinessSnapshotRenewal()
{
    ListenSnapshotTransport transport;
    transport.store(1);
    transport.start();
    transport.getRound();
    transport.getRound();
    CPPUNIT_ASSERT(transport.results == std::vector<bool>({true}));
    transport.deliverUpdates();
    transport.clientPackets->sends.clear();
    auto search = transport.client->searches(AF_INET).at(transport.key);
    auto* node = search->nodes.front().get();
    node->listenStatus.begin()->second.req->reply_time = transport.client->scheduler.time()
                                                         - transport.client->getListenExpiration();
    transport.client->searchSynchedNodeListen(search, *node);
    transport.acknowledge();
    CPPUNIT_ASSERT(transport.delayedUpdates.empty());
    for (const auto& packet : transport.clientPackets->sends)
        CPPUNIT_ASSERT(ListenSnapshotTransport::parse(packet).type != MessageType::GetValues);
    CPPUNIT_ASSERT_EQUAL(size_t(1), transport.results.size());
}

void
NetworkEngineTester::testListenUpdatesBeforeConfirmation()
{
    ListenSnapshotTransport transport;
    transport.store(40, 6000);
    transport.start(false);
    auto request = transport.initialRequest();
    auto listen = std::find_if(transport.clientPackets->sends.begin(),
                               transport.clientPackets->sends.end(),
                               [](const auto& packet) {
                                   return ListenSnapshotTransport::parse(packet).type == MessageType::Listen;
                               });
    CPPUNIT_ASSERT(listen != transport.clientPackets->sends.end());
    transport.server->network_engine.processMessage(listen->data.data(), listen->data.size(), transport.clientAddr);
    auto replies = std::move(transport.serverPackets->sends);
    std::vector<TestDatagramSocket::SentPacket> confirmations;
    std::reverse(replies.begin(), replies.end());
    for (const auto& packet : replies) {
        if (ListenSnapshotTransport::parse(packet).type == MessageType::Reply)
            confirmations.emplace_back(packet);
        else
            transport.client->network_engine.processMessage(packet.data.data(),
                                                            packet.data.size(),
                                                            transport.serverAddr);
    }
    CPPUNIT_ASSERT(transport.results.empty());
    CPPUNIT_ASSERT(transport.received.empty());
    CPPUNIT_ASSERT_EQUAL(size_t(1), confirmations.size());
    auto& confirmation = confirmations.front();
    transport.client->network_engine.processMessage(confirmation.data.data(),
                                                    confirmation.data.size(),
                                                    transport.serverAddr);
    CPPUNIT_ASSERT(transport.results == std::vector<bool>({true}));
    CPPUNIT_ASSERT_EQUAL(size_t(40), transport.received.size());
    for (const auto& packet : replies)
        transport.client->network_engine.processMessage(packet.data.data(), packet.data.size(), transport.serverAddr);
    CPPUNIT_ASSERT_EQUAL(size_t(40), transport.received.size());
}

void
NetworkEngineTester::testListenLiveChangesBeforeSnapshot()
{
    ListenSnapshotTransport transport;
    transport.store(1);
    transport.start();
    auto& storage = transport.server->store.at(transport.key);
    auto removed = storage.remove(transport.key, 1);
    CPPUNIT_ASSERT(removed);
    transport.server->storageRemoved(transport.key, storage, {removed}, removed->size());
    auto value = std::make_shared<Value>("new-live-value");
    value->id = 99;
    CPPUNIT_ASSERT(transport.server->storageStore(transport.key, value, transport.server->scheduler.time()));
    CPPUNIT_ASSERT_EQUAL(size_t(2), transport.serverPackets->sends.size());
    for (const auto& packet : transport.serverPackets->sends)
        transport.client->network_engine.processMessage(packet.data.data(), packet.data.size(), transport.serverAddr);
    CPPUNIT_ASSERT(transport.received.empty());
    CPPUNIT_ASSERT(transport.results.empty());
    transport.deliverUpdates();
    auto search = transport.client->searches(AF_INET).at(transport.key);
    CPPUNIT_ASSERT(!search->cache.get(1));
    CPPUNIT_ASSERT(search->cache.get(99));
    CPPUNIT_ASSERT(transport.results == std::vector<bool>({true}));
    for (const auto& packet : transport.serverPackets->sends)
        transport.client->network_engine.processMessage(packet.data.data(), packet.data.size(), transport.serverAddr);
    CPPUNIT_ASSERT(!search->cache.get(1));
    CPPUNIT_ASSERT_EQUAL(size_t(2), transport.received.size());
}

void
NetworkEngineTester::testListenDuplicateRegistration()
{
    ListenSnapshotTransport transport;
    transport.store(40);
    transport.start(false);
    auto listen = std::find_if(transport.clientPackets->sends.begin(),
                               transport.clientPackets->sends.end(),
                               [](const auto& packet) {
                                   return ListenSnapshotTransport::parse(packet).type == MessageType::Listen;
                               });
    CPPUNIT_ASSERT(listen != transport.clientPackets->sends.end());
    auto packet = *listen;
    transport.acknowledge();
    CPPUNIT_ASSERT_EQUAL(size_t(2),
                         size_t(std::count_if(transport.delayedUpdates.begin(),
                                              transport.delayedUpdates.end(),
                                              [](const auto& update) {
                                                  return ListenSnapshotTransport::parse(update).type
                                                         == MessageType::UpdateValue;
                                              })));
    transport.server->network_engine.processMessage(packet.data.data(), packet.data.size(), transport.clientAddr);
    CPPUNIT_ASSERT_EQUAL(size_t(1), transport.serverPackets->sends.size());
    auto confirmation = ListenSnapshotTransport::parse(transport.serverPackets->sends.front());
    CPPUNIT_ASSERT(confirmation.type == MessageType::Reply);
    CPPUNIT_ASSERT(confirmation.listenSync);
    CPPUNIT_ASSERT_EQUAL(uint64_t(2), confirmation.listenSync->snapshotEnd);
    transport.deliverUpdates();
    CPPUNIT_ASSERT(transport.results == std::vector<bool>({true}));
    CPPUNIT_ASSERT_EQUAL(size_t(40), transport.received.size());
}

void
NetworkEngineTester::testListenLargeSnapshotDefaultLimits()
{
    ListenSnapshotTransport transport;
    auto socket = std::make_unique<TestDatagramSocket>();
    socket->bound_.setPort(5031);
    transport.serverPackets = socket.get();
    transport.serverAddr = socket->bound_;
    transport.server = std::make_unique<Dht>(std::move(socket),
                                             Config {},
                                             Sp<Logger> {},
                                             std::make_unique<std::mt19937_64>(31));
    transport.store(4096);
    transport.start();
    CPPUNIT_ASSERT(transport.results.empty());
    size_t batches = 0;
    size_t payloads = 0;
    for (const auto& packet : transport.delayedUpdates) {
        auto message = ListenSnapshotTransport::parse(packet);
        if (message.type == MessageType::UpdateValue) {
            ++batches;
            payloads += message.values.size() + message.value_parts.size();
        }
    }
    CPPUNIT_ASSERT_EQUAL(size_t(128), batches);
    CPPUNIT_ASSERT_EQUAL(size_t(4096), payloads);
    transport.getRound(true);
    CPPUNIT_ASSERT(transport.results == std::vector<bool>({true}));
    CPPUNIT_ASSERT_EQUAL(size_t(4096), transport.received.size());
    auto search = transport.client->searches(AF_INET).at(transport.key);
    CPPUNIT_ASSERT_EQUAL(size_t(4096), search->cache.get(Value::Filter {}).size());
    for (const auto& packet : transport.clientPackets->sends)
        CPPUNIT_ASSERT(ListenSnapshotTransport::parse(packet).type != MessageType::GetValues);
}

void
NetworkEngineTester::testListenLiveUpdateOrdering()
{
    ListenSnapshotTransport transport;
    transport.store(1);
    transport.start();
    transport.deliverUpdates();
    for (Value::Id id : {2, 3}) {
        auto value = std::make_shared<Value>("live");
        value->id = id;
        CPPUNIT_ASSERT(transport.server->storageStore(transport.key, value, transport.server->scheduler.time()));
    }
    CPPUNIT_ASSERT_EQUAL(size_t(2), transport.serverPackets->sends.size());
    auto search = transport.client->searches(AF_INET).at(transport.key);
    auto& later = transport.serverPackets->sends.back();
    transport.client->network_engine.processMessage(later.data.data(), later.data.size(), transport.serverAddr);
    CPPUNIT_ASSERT(!search->cache.get(3));
    auto& earlier = transport.serverPackets->sends.front();
    transport.client->network_engine.processMessage(earlier.data.data(), earlier.data.size(), transport.serverAddr);
    CPPUNIT_ASSERT(search->cache.get(2));
    CPPUNIT_ASSERT(search->cache.get(3));
    CPPUNIT_ASSERT(transport.results == std::vector<bool>({true}));
}

void
NetworkEngineTester::testListenInitializationTimeout()
{
    ListenSnapshotTransport transport;
    transport.store(1);
    transport.start();
    CPPUNIT_ASSERT(transport.results.empty());
    transport.client->scheduler.syncTime(transport.client->scheduler.time() + std::chrono::seconds(31));
    transport.client->scheduler.run();
    CPPUNIT_ASSERT(transport.results == std::vector<bool>({false}));
    transport.deliverUpdates();
    CPPUNIT_ASSERT_EQUAL(size_t(1), transport.results.size());
}

void
NetworkEngineTester::testListenRegistrationFailure()
{
    ListenSnapshotTransport transport;
    transport.store(1);
    transport.start(false);
    auto search = transport.client->searches(AF_INET).at(transport.key);
    auto* node = search->nodes.front().get();
    auto request = node->listenStatus.begin()->second.req;
    CPPUNIT_ASSERT(request->pending());
    CPPUNIT_ASSERT(!node->node->isExpired());
    request->setExpired();
    CPPUNIT_ASSERT(transport.results == std::vector<bool>({false}));
    CPPUNIT_ASSERT(!node->node->isExpired());
    transport.clientPackets->sends.clear();
    transport.client->searchStep(search);
    transport.acknowledge();
    transport.getRound();
    transport.getRound();
    CPPUNIT_ASSERT(transport.results == std::vector<bool>({false}));
}

void
NetworkEngineTester::testListenRegistrationCapacity()
{
    for (bool dualStack : {false, true}) {
        auto socket = std::make_unique<TestDatagramSocket>();
        socket->ipv6 = dualStack;
        Config config;
        config.max_searches = 1;
        Dht localDht(std::move(socket), config, {}, std::make_unique<std::mt19937_64>(40));
        auto occupiedKey = InfoHash::get("occupied-search");
        auto rejectedKey = InfoHash::get("rejected-search");
        auto values = [](const std::vector<Sp<Value>>&, bool) {
            return true;
        };
        if (dualStack)
            CPPUNIT_ASSERT(localDht.search(occupiedKey, AF_INET6));
        else
            CPPUNIT_ASSERT(localDht.listen(occupiedKey, values) != 0);
        std::vector<bool> results;
        CPPUNIT_ASSERT_EQUAL(size_t(0),
                             localDht.listen(rejectedKey, values, {}, {}, [&](bool ok) { results.push_back(ok); }));
        CPPUNIT_ASSERT(results == std::vector<bool>({false}));
        CPPUNIT_ASSERT(localDht.store.at(rejectedKey).local_listeners.empty());
        if (dualStack) {
            auto partial = localDht.searches(AF_INET).at(rejectedKey);
            CPPUNIT_ASSERT(!partial->cache.cancelListen(1, localDht.scheduler.time()));
            partial->cache.onReady();
            CPPUNIT_ASSERT_EQUAL(size_t(1), results.size());
        }
    }
}

void
NetworkEngineTester::testListenReadinessAddressFamilies()
{
    auto key = InfoHash::get("readiness-address-families");
    for (unsigned families = 1; families <= 3; ++families) {
        auto socket = std::make_unique<TestDatagramSocket>();
        socket->ipv4 = families & 1;
        socket->ipv6 = families & 2;
        Dht localDht(std::move(socket), Config {}, {}, std::make_unique<std::mt19937_64>(families));
        std::vector<bool> results;
        auto token = localDht.listen(
            key,
            [](const std::vector<Sp<Value>>&, bool) { return true; },
            {},
            {},
            [&](bool ok) { results.push_back(ok); });
        CPPUNIT_ASSERT(token != 0);
        CPPUNIT_ASSERT(results.empty());
        if (families & 1) {
            localDht.searchStep(localDht.searches(AF_INET).at(key));
            if (families & 2)
                CPPUNIT_ASSERT(results.empty());
        }
        if (families & 2)
            localDht.searchStep(localDht.searches(AF_INET6).at(key));
        CPPUNIT_ASSERT(results == std::vector<bool>({true}));
        CPPUNIT_ASSERT(localDht.cancelListen(key, token));

        results.clear();
        CPPUNIT_ASSERT_EQUAL(size_t(0),
                             localDht.listen(
                                 InfoHash {},
                                 [](const std::vector<Sp<Value>>&, bool) { return true; },
                                 {},
                                 {},
                                 [&](bool ok) { results.push_back(ok); }));
        CPPUNIT_ASSERT(results == std::vector<bool>({false}));
    }
}

void
NetworkEngineTester::testListenReadinessFailedSearch()
{
    Dht localDht(std::make_unique<TestDatagramSocket>(), Config {}, {}, std::make_unique<std::mt19937_64>(22));
    auto key = InfoHash::get("readiness-failed-search");
    std::vector<bool> results;
    auto token = localDht.listen(
        key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {}, [&](bool ok) { results.push_back(ok); });
    auto search = localDht.searches(AF_INET).at(key);
    auto node = std::make_shared<Node>(InfoHash::getRandom(localDht.rd),
                                       makeIPv4("127.0.0.2", 5022),
                                       localDht.rd,
                                       false);
    node->setExpired();
    search->nodes.emplace_back(std::make_unique<Dht::SearchNode>(node));
    localDht.searchStep(search);
    CPPUNIT_ASSERT(search->expired);
    CPPUNIT_ASSERT(results == std::vector<bool>({false}));
    search->cache.onReady();
    CPPUNIT_ASSERT_EQUAL(size_t(1), results.size());
    CPPUNIT_ASSERT(localDht.cancelListen(key, token));
}

void
NetworkEngineTester::testListenReadinessReusesExpiredSearch()
{
    Dht localDht(std::make_unique<TestDatagramSocket>(), Config {}, {}, std::make_unique<std::mt19937_64>(23));
    auto key = InfoHash::get("readiness-reused-search");
    auto values = [](const std::vector<Sp<Value>>&, bool) {
        return true;
    };
    std::vector<bool> results;
    auto ready = [&](bool ok) {
        results.push_back(ok);
    };
    auto first = localDht.listen(key, values, {}, {}, ready);
    auto search = localDht.searches(AF_INET).at(key);
    search->expire();
    CPPUNIT_ASSERT(results == std::vector<bool>({false}));
    CPPUNIT_ASSERT(localDht.cancelListen(key, first));
    auto second = localDht.listen(key, values, {}, {}, ready);
    CPPUNIT_ASSERT(second != 0);
    CPPUNIT_ASSERT(search == localDht.searches(AF_INET).at(key));
    CPPUNIT_ASSERT(!search->expired);
    CPPUNIT_ASSERT(!search->done);
    CPPUNIT_ASSERT(localDht.scheduler.time() == search->nextSearchStep->t_);
    localDht.searchStep(search);
    CPPUNIT_ASSERT(results == std::vector<bool>({false, true}));
    CPPUNIT_ASSERT(localDht.cancelListen(key, second));
}

void
NetworkEngineTester::testListenReadinessShutdown()
{
    for (bool stop : {false, true}) {
        std::vector<bool> results;
        auto localDht = std::make_unique<Dht>(std::make_unique<TestDatagramSocket>(),
                                              Config {},
                                              Sp<Logger> {},
                                              std::make_unique<std::mt19937_64>(24));
        CPPUNIT_ASSERT(localDht->listen(
                           InfoHash::get("readiness-shutdown"),
                           [](const std::vector<Sp<Value>>&, bool) { return true; },
                           {},
                           {},
                           [&](bool ok) { results.push_back(ok); })
                       != 0);
        CPPUNIT_ASSERT(results.empty());
        if (stop) {
            localDht->shutdown({}, true);
            CPPUNIT_ASSERT_EQUAL(size_t(1), results.size());
            CPPUNIT_ASSERT(!results.front());
        }
        localDht.reset();
        CPPUNIT_ASSERT_EQUAL(size_t(1), results.size());
        CPPUNIT_ASSERT(!results.front());
    }
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