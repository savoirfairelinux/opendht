// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_dhtproxy.h"

// std
#include <iostream>
#include <string>

#include <chrono>
#include <condition_variable>
#include <asio.hpp>

using namespace std::chrono_literals;

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(DhtProxyTester);

void
DhtProxyTester::setUp()
{
    clientConfig.dht_config.node_config.max_peer_req_per_sec = -1;
    clientConfig.dht_config.node_config.max_req_per_sec = -1;
    clientConfig.push_token.clear();

    nodePeer.run(0, clientConfig);

    nodeProxy = std::make_shared<dht::DhtRunner>();
    nodeProxy->run(0, clientConfig);

    auto bound = nodePeer.getBound();
    if (bound.isUnspecified())
        bound.setLoopback();
    nodeProxy->bootstrap(bound);

    // auto serverCAIdentity = dht::crypto::generateEcIdentity("DHT Node CA");

    uint16_t port = 1024 + (std::rand() % (65535 - 1024));

    dht::ProxyServerConfig serverConfig;
    // serverConfig.identity = dht::crypto::generateIdentity("DHT Node", serverCAIdentity);
    serverConfig.port = port;
    // serverConfig.pushServer = "127.0.0.1:8090";
    serverProxy = std::make_unique<dht::DhtProxyServer>(nodeProxy, serverConfig);

    /*clientConfig.server_ca = serverCAIdentity.second;
    clientConfig.client_identity = dht::crypto::generateIdentity("DhtProxyTester");
    clientConfig.push_node_id = "dhtnode";*/
    clientConfig.proxy_server = "http://127.0.0.1:" + std::to_string(port); //"https://127.0.0.1:8080";
}

void
DhtProxyTester::tearDown()
{
    nodePeer.join();
    nodeClient.join();

    bool done = false;
    std::condition_variable cv;
    std::mutex cv_m;
    nodeProxy->shutdown([&] {
        std::lock_guard lk(cv_m);
        done = true;
        cv.notify_all();
    });
    std::unique_lock lk(cv_m);
    CPPUNIT_ASSERT(cv.wait_for(lk, 15s, [&] { return done; }));
    // Join nodeProxy to ensure all DHT threads are done before
    // destroying the proxy server (whose callbacks may still be
    // pending on the DHT thread).
    nodeProxy->join();
    serverProxy.reset();
    nodeProxy.reset();
}

void
DhtProxyTester::testGetPut()
{
    nodeClient.run(0, clientConfig);

    bool done = false;
    std::condition_variable cv;
    std::mutex cv_m;

    auto key = dht::InfoHash::get("GLaDOs");
    dht::Value val {"Hey! It's been a long time. How have you been?"};
    auto val_data = val.data;
    {
        nodePeer.put(key, std::move(val), [&](bool) {
            std::lock_guard lk(cv_m);
            done = true;
            cv.notify_all();
        });
        std::unique_lock lk(cv_m);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    }

    auto vals = nodeClient.get(key).get();
    CPPUNIT_ASSERT(not vals.empty());
    CPPUNIT_ASSERT(vals.front()->data == val_data);
}

void
DhtProxyTester::testListen()
{
    nodeClient.run(0, clientConfig);

    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock lk(cv_m);
    auto key = dht::InfoHash::get("GLaDOs");
    bool done = false;

    // If a peer send a value, the listen operation from the client
    // should retrieve this value
    dht::Value firstVal {"Hey! It's been a long time. How have you been?"};
    auto firstVal_data = firstVal.data;
    nodePeer.put(key, std::move(firstVal), [&](bool ok) {
        CPPUNIT_ASSERT(ok);
        std::lock_guard lk(cv_m);
        done = true;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    done = false;

    std::vector<dht::Blob> values;
    auto token = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& v, bool expired) {
        if (not expired) {
            std::lock_guard lk(cv_m);
            for (const auto& value : v)
                values.emplace_back(value->data);
            done = true;
            cv.notify_all();
        }
        return true;
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    done = false;
    // Here values should contains 1 values
    CPPUNIT_ASSERT_EQUAL(static_cast<int>(values.size()), 1);
    CPPUNIT_ASSERT(values.front() == firstVal_data);

    // And the listen should retrieve futures values
    // All values
    dht::Value secondVal {"You're a monster"};
    auto secondVal_data = secondVal.data;
    nodePeer.put(key, std::move(secondVal));
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    nodeClient.cancelListen(key, std::move(token));
    // Here values should contains 2 values
    CPPUNIT_ASSERT_EQUAL(static_cast<int>(values.size()), 2);
    CPPUNIT_ASSERT(values.back() == secondVal_data);
}

void
DhtProxyTester::testListenValueEdit()
{
    static constexpr dht::ValueType::Id EDITABLE_TYPE_ID = 5555;
    const dht::ValueType editableType {EDITABLE_TYPE_ID,
                                       "proxy-editable",
                                       std::chrono::seconds(2),
                                       dht::ValueType::DEFAULT_STORE_POLICY,
                                       [](dht::InfoHash,
                                          const std::shared_ptr<dht::Value>&,
                                          std::shared_ptr<dht::Value>&,
                                          const dht::InfoHash&,
                                          const dht::SockAddr&) { return true; }};
    nodePeer.registerType(editableType);
    nodeProxy->registerType(editableType);

    nodeClient.run(0, clientConfig);
    nodeClient.registerType(editableType);

    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock<std::mutex> lk(cv_m);
    auto key = dht::InfoHash::get("ProxyListenEdit");
    auto identity = dht::crypto::generateIdentity("ProxyEditAuthor");

    std::vector<std::pair<dht::Value::Id, bool>> events;
    auto ftoken = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& v, bool expired) {
        std::lock_guard<std::mutex> lk(cv_m);
        for (const auto& val : v)
            events.emplace_back(val->id, expired);
        cv.notify_all();
        return true;
    });

    // Wait for listen to be established
    cv.wait_for(lk, 1s);

    // Peer puts first version
    dht::Value firstVal {"version1"};
    firstVal.type = EDITABLE_TYPE_ID;
    firstVal.id = 42;
    firstVal.seq = 1;
    firstVal.sign(*identity.first);
    bool putDone = false;
    nodePeer.put(key, std::move(firstVal), [&](bool ok) {
        std::lock_guard<std::mutex> lk(cv_m);
        CPPUNIT_ASSERT(ok);
        putDone = true;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return putDone; }));
    putDone = false;

    // Wait for the first value to arrive via proxy listen
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
        return std::any_of(events.begin(), events.end(), [](const auto& e) { return !e.second; });
    }));

    // Peer edits the value (same id, higher seq)
    dht::Value secondVal {"version2"};
    secondVal.type = EDITABLE_TYPE_ID;
    secondVal.id = 42;
    secondVal.seq = 2;
    secondVal.sign(*identity.first);
    nodePeer.put(key, std::move(secondVal), [&](bool ok) {
        std::lock_guard<std::mutex> lk(cv_m);
        CPPUNIT_ASSERT(ok);
        putDone = true;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return putDone; }));

    // Wait for the edited value to arrive
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
        int adds = 0;
        for (const auto& e : events)
            if (!e.second)
                adds++;
        return adds >= 2;
    }));

    // Allow stray callbacks
    cv.wait_for(lk, 500ms);

    // Verify: 2 adds, 0 expires (no phantom expiry on edit)
    {
        int addCount = 0, expireCount = 0;
        for (const auto& e : events) {
            if (e.second)
                expireCount++;
            else
                addCount++;
        }
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Should receive 2 add callbacks (original + edit)", 2, addCount);
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Should receive no expire callbacks on edit", 0, expireCount);
    }

    // Now wait for the edited value to actually expire (type expiration is 2s,
    // the cache adds a grace period when synced, so effective expiry is ~4s).
    CPPUNIT_ASSERT_MESSAGE("Edited value should eventually expire", cv.wait_for(lk, 30s, [&] {
        return std::any_of(events.begin(), events.end(), [](const auto& e) { return e.second; });
    }));

    // Verify we got at least one expiration
    {
        int expireCount = 0;
        for (const auto& e : events)
            if (e.second)
                expireCount++;
        CPPUNIT_ASSERT_MESSAGE("Should receive at least one expire callback after real expiration", expireCount >= 1);
    }

    nodeClient.cancelListen(key, ftoken.get());
}

void
DhtProxyTester::testPushListenValueEdit()
{
#ifndef OPENDHT_PUSH_NOTIFICATIONS
    fmt::print(stderr, "Push notifications are not supported in this build, skipping test\n");
    return;
#else
    static constexpr dht::ValueType::Id PUSH_EDIT_TYPE_ID = 6666;
    const dht::ValueType pushEditType {PUSH_EDIT_TYPE_ID,
                                       "push-edit",
                                       std::chrono::seconds(2),
                                       dht::ValueType::DEFAULT_STORE_POLICY,
                                       [](dht::InfoHash,
                                          const std::shared_ptr<dht::Value>&,
                                          std::shared_ptr<dht::Value>&,
                                          const dht::InfoHash&,
                                          const dht::SockAddr&) { return true; }};
    nodePeer.registerType(pushEditType);
    nodeProxy->registerType(pushEditType);

    clientConfig.push_token = "push-edit-token";
    nodeClient.run(0, clientConfig);
    nodeClient.registerType(pushEditType);

    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock<std::mutex> lk(cv_m);
    auto key = dht::InfoHash::get("PushListenEdit");
    auto identity = dht::crypto::generateIdentity("PushEditAuthor");

    std::vector<std::pair<dht::Value::Id, bool>> events;
    auto ftoken = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& v, bool expired) {
        std::lock_guard<std::mutex> lk(cv_m);
        for (const auto& val : v)
            events.emplace_back(val->id, expired);
        cv.notify_all();
        return true;
    });

    // Wait for SUBSCRIBE to reach the proxy
    cv.wait_for(lk, 1s);

    // Peer puts first version
    dht::Value firstVal {"push-v1"};
    firstVal.type = PUSH_EDIT_TYPE_ID;
    firstVal.id = 77;
    firstVal.seq = 1;
    firstVal.sign(*identity.first);
    bool putDone = false;
    nodePeer.put(key, std::move(firstVal), [&](bool ok) {
        std::lock_guard<std::mutex> lk(cv_m);
        CPPUNIT_ASSERT(ok);
        putDone = true;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return putDone; }));
    putDone = false;

    // Simulate push notification to trigger value fetch
    std::map<std::string, std::string> push_data;
    push_data["key"] = key.toString();
    push_data["t"] = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    nodeClient.pushNotificationReceived(push_data).get();

    // Wait for first add callback
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
        return std::any_of(events.begin(), events.end(), [](const auto& e) { return !e.second; });
    }));

    // Peer edits the value (same id, higher seq)
    dht::Value secondVal {"push-v2"};
    secondVal.type = PUSH_EDIT_TYPE_ID;
    secondVal.id = 77;
    secondVal.seq = 2;
    secondVal.sign(*identity.first);
    nodePeer.put(key, std::move(secondVal), [&](bool ok) {
        std::lock_guard<std::mutex> lk(cv_m);
        CPPUNIT_ASSERT(ok);
        putDone = true;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return putDone; }));

    // Simulate push notification for the edit
    push_data["t"] = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    nodeClient.pushNotificationReceived(push_data).get();

    // Wait for the second add
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
        int adds = 0;
        for (const auto& e : events)
            if (!e.second)
                adds++;
        return adds >= 2;
    }));

    // Allow stray callbacks
    cv.wait_for(lk, 500ms);

    // Verify: 2 adds, 0 expires (no phantom expiry on edit via push)
    {
        int addCount = 0, expireCount = 0;
        for (const auto& e : events) {
            if (e.second)
                expireCount++;
            else
                addCount++;
        }
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Should receive 2 add callbacks (original + edit) via push", 2, addCount);
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Should receive no expire callbacks on edit via push", 0, expireCount);
    }

    // Simulate expiration push notification
    push_data["exp"] = std::to_string((dht::Value::Id) 77);
    push_data["t"] = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    CPPUNIT_ASSERT(nodeClient.pushNotificationReceived(push_data).get() == dht::PushNotificationResult::ValuesExpired);

    // Wait for the expire callback
    CPPUNIT_ASSERT_MESSAGE("Should receive expire callback via push", cv.wait_for(lk, 10s, [&] {
        return std::any_of(events.begin(), events.end(), [](const auto& e) { return e.second; });
    }));

    // Verify we got at least one expiration
    {
        int expireCount = 0;
        for (const auto& e : events)
            if (e.second)
                expireCount++;
        CPPUNIT_ASSERT_MESSAGE("Should receive at least one expire callback after push expiration", expireCount >= 1);
    }

    nodeClient.cancelListen(key, ftoken.get());
#endif
}

void
DhtProxyTester::testResubscribeGetValues()
{
    clientConfig.push_token = "atlas";
    nodeClient.run(0, clientConfig);

    bool done = false;
    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock lk(cv_m);
    auto key = dht::InfoHash::get("GLaDOs");

    // If a peer sent a value, the listen operation from the client
    // should retrieve this value
    dht::Value firstVal {"Hey! It's been a long time. How have you been?"};
    auto firstVal_data = firstVal.data;
    nodePeer.put(key, std::move(firstVal), [&](bool ok) {
        std::lock_guard lk(cv_m);
        CPPUNIT_ASSERT(ok);
        done = true;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    done = false;

    // Send a first subscribe, the value is sent via a push notification
    // So ignore values here.
    auto firstToken = nodeClient.listen(key,
                                        [&](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; });
    cv.wait_for(lk, std::chrono::seconds(1));

    // Cancel the push listen before rebooting the node
    nodeClient.cancelListen(key, firstToken.get());

    // Reboot node (to avoid cache)
    nodeClient.join();
    clientConfig.push_token = "";
    nodeClient.run(0, clientConfig);

    // For the second subscribe, the proxy will return the value in the body
    std::vector<std::shared_ptr<dht::Value>> values;
    auto ftoken = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& v, bool expired) {
        if (not expired) {
            std::lock_guard lk(cv_m);
            values.insert(values.end(), v.begin(), v.end());
            done = true;
            cv.notify_all();
        }
        return true;
    });

    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    auto token = ftoken.get();
    CPPUNIT_ASSERT(token);
    nodeClient.cancelListen(key, token);
    // Here values should still contains 1 values
    CPPUNIT_ASSERT_EQUAL((size_t) 1u, values.size());
    CPPUNIT_ASSERT(firstVal_data == values.front()->data);
}

void
DhtProxyTester::testPushNotification()
{
#ifndef OPENDHT_PUSH_NOTIFICATIONS
    fmt::print(stderr, "Push notifications are not supported in this build, skipping test\n");
    return;
#else
    static constexpr dht::ValueType::Id PUSH_EDITABLE_TYPE_ID = 4242;
    const dht::ValueType pushEditableType {PUSH_EDITABLE_TYPE_ID,
                                           "push-editable",
                                           std::chrono::seconds(1),
                                           dht::ValueType::DEFAULT_STORE_POLICY,
                                           [](dht::InfoHash,
                                              const std::shared_ptr<dht::Value>&,
                                              std::shared_ptr<dht::Value>&,
                                              const dht::InfoHash&,
                                              const dht::SockAddr&) { return true; }};
    nodePeer.registerType(pushEditableType);
    nodeProxy->registerType(pushEditableType);

    clientConfig.push_token = "atlas";
    nodeClient.run(0, clientConfig);
    nodeClient.registerType(pushEditableType);

    bool gotValues = false;
    bool gotExpiredValues = false;
    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock<std::mutex> lk(cv_m);
    auto key = dht::InfoHash::get("GLaDOs");
    auto valueAuthor = dht::crypto::generateIdentity("PushNotificationAuthor");

    std::vector<std::shared_ptr<dht::Value>> values;
    std::vector<std::shared_ptr<dht::Value>> expiredValues;
    auto ftoken = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& v, bool expired) {
        std::lock_guard<std::mutex> lk(cv_m);
        if (expired) {
            expiredValues.insert(expiredValues.end(), v.begin(), v.end());
            gotExpiredValues = true;
        } else {
            values.insert(values.end(), v.begin(), v.end());
            gotValues = true;
        }
        cv.notify_all();
        return true;
    });

    // Wait for listen to be sent to proxy
    cv.wait_for(lk, std::chrono::seconds(1));

    // Peer puts a value
    dht::Value firstVal {"Hey! It's been a long time. How have you been?"};
    firstVal.type = PUSH_EDITABLE_TYPE_ID;
    firstVal.id = 1337;
    firstVal.seq = 1;
    firstVal.sign(*valueAuthor.first);
    auto firstVal_data = firstVal.data;
    nodePeer.put(key, std::move(firstVal), [&](bool ok) {
        std::lock_guard<std::mutex> lk(cv_m);
        CPPUNIT_ASSERT(ok);
        gotValues = true;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return gotValues; }));
    gotValues = false;

    // Simulate push notification
    std::map<std::string, std::string> push_data;
    push_data["key"] = key.toString();
    push_data["t"] = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    CPPUNIT_ASSERT(nodeClient.pushNotificationReceived(push_data).get() == dht::PushNotificationResult::Values);

    // Wait for client to receive the value
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return gotValues; }));
    gotValues = false;

    CPPUNIT_ASSERT_EQUAL((size_t) 1u, values.size());
    CPPUNIT_ASSERT(firstVal_data == values.front()->data);

    // Peer edits the existing value (same id, higher seq)
    dht::Value secondVal {"You're a monster"};
    secondVal.type = PUSH_EDITABLE_TYPE_ID;
    secondVal.id = 1337;
    secondVal.seq = 2;
    secondVal.sign(*valueAuthor.first);
    auto secondVal_data = secondVal.data;
    nodePeer.put(key, std::move(secondVal), [&](bool ok) {
        std::lock_guard<std::mutex> lk(cv_m);
        CPPUNIT_ASSERT(ok);
        gotValues = true;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return gotValues; }));
    gotValues = false;

    // Simulate push notification again
    push_data["t"] = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    CPPUNIT_ASSERT(nodeClient.pushNotificationReceived(push_data).get() == dht::PushNotificationResult::Values);

    // Wait for client to receive the edited value
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return gotValues; }));
    gotValues = false;

    // OpValueCache should update the existing id with the new sequence/data
    CPPUNIT_ASSERT_EQUAL((size_t) 2u, values.size());
    CPPUNIT_ASSERT_EQUAL((dht::Value::Id) 1337, values.back()->id);
    CPPUNIT_ASSERT_EQUAL((uint16_t) 2, values.back()->seq);
    CPPUNIT_ASSERT(secondVal_data == values.back()->data);

    // Simulate expiration push notification for the edited value
    push_data["exp"] = std::to_string((dht::Value::Id) 1337);
    push_data["t"] = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    CPPUNIT_ASSERT(nodeClient.pushNotificationReceived(push_data).get() == dht::PushNotificationResult::ValuesExpired);

    cv.wait_for(lk, 500ms, [&] { return gotExpiredValues; });

    auto token = ftoken.get();
    CPPUNIT_ASSERT(token);
    nodeClient.cancelListen(key, token);
#endif
}

void
DhtProxyTester::testProxyServerClientFullChain()
{
#ifndef OPENDHT_PUSH_NOTIFICATIONS
    fmt::print(stderr, "Push notifications are not supported in this build, skipping test\n");
    return;
#else
    static constexpr dht::ValueType::Id CHAIN_EDITABLE_TYPE_ID = 4343;
    const dht::ValueType chainEditableType {CHAIN_EDITABLE_TYPE_ID,
                                            "chain-editable",
                                            std::chrono::seconds(30),
                                            dht::ValueType::DEFAULT_STORE_POLICY,
                                            [](dht::InfoHash,
                                               const std::shared_ptr<dht::Value>&,
                                               std::shared_ptr<dht::Value>&,
                                               const dht::InfoHash&,
                                               const dht::SockAddr&) { return true; }};

    uint16_t pushPort = 1024 + (std::rand() % (65535 - 1024));
    uint16_t proxyPort = 1024 + (std::rand() % (65535 - 1024));

    std::atomic_bool relayStop {false};
    std::atomic_size_t relayedPushCount {0};
    std::thread pushRelay([&] {
        try {
            asio::io_context io;
            asio::ip::tcp::acceptor acceptor(io, asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), pushPort));
            acceptor.non_blocking(true);

            while (not relayStop.load()) {
                asio::ip::tcp::socket socket(io);
                std::error_code ec;
                acceptor.accept(socket, ec);
                if (ec == asio::error::would_block || ec == asio::error::try_again) {
                    std::this_thread::sleep_for(5ms);
                    continue;
                }
                if (ec)
                    continue;

                socket.non_blocking(true);

                std::string raw;
                raw.reserve(4096);
                auto deadline = std::chrono::steady_clock::now() + 2s;
                while (raw.find("\r\n\r\n") == std::string::npos && std::chrono::steady_clock::now() < deadline
                       && not relayStop.load()) {
                    std::array<char, 2048> chunk {};
                    size_t n = socket.read_some(asio::buffer(chunk), ec);
                    if (!ec) {
                        raw.append(chunk.data(), n);
                    } else if (ec == asio::error::would_block || ec == asio::error::try_again) {
                        std::this_thread::sleep_for(2ms);
                    } else {
                        break;
                    }
                }
                if (raw.find("\r\n\r\n") == std::string::npos)
                    continue;

                auto sep = raw.find("\r\n\r\n");
                std::string head = raw.substr(0, sep + 4);
                auto clPos = head.find("Content-Length:");
                size_t contentLength = 0;
                if (clPos != std::string::npos) {
                    clPos += std::string("Content-Length:").size();
                    while (clPos < head.size() && (head[clPos] == ' ' || head[clPos] == '\t'))
                        ++clPos;
                    size_t clEnd = head.find("\r\n", clPos);
                    contentLength = std::stoul(head.substr(clPos, clEnd - clPos));
                }

                std::string body = raw.substr(sep + 4);
                while (body.size() < contentLength && std::chrono::steady_clock::now() < deadline
                       && not relayStop.load()) {
                    std::array<char, 2048> chunk {};
                    size_t n = socket.read_some(asio::buffer(chunk), ec);
                    if (!ec) {
                        body.append(chunk.data(), n);
                    } else if (ec == asio::error::would_block || ec == asio::error::try_again) {
                        std::this_thread::sleep_for(2ms);
                    } else {
                        break;
                    }
                }
                if (body.size() > contentLength)
                    body.resize(contentLength);

                Json::Value payload;
                std::string err;
                auto reader = std::unique_ptr<Json::CharReader>(Json::CharReaderBuilder().newCharReader());
                if (reader->parse(body.data(), body.data() + body.size(), &payload, &err)
                    && payload.isMember("notifications") && payload["notifications"].isArray()
                    && !payload["notifications"].empty() && payload["notifications"][0].isMember("data")) {
                    const auto& data = payload["notifications"][0]["data"];
                    std::map<std::string, std::string> notif;
                    for (const auto& name : data.getMemberNames()) {
                        const auto& value = data[name];
                        if (value.isString())
                            notif[name] = value.asString();
                        else if (value.isBool())
                            notif[name] = value.asBool() ? "true" : "false";
                        else if (value.isUInt64())
                            notif[name] = std::to_string(value.asUInt64());
                        else if (value.isInt64())
                            notif[name] = std::to_string(value.asInt64());
                    }
                    nodeClient.pushNotificationReceived(notif);
                    relayedPushCount++;
                }

                static const std::string okResp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                asio::write(socket, asio::buffer(okResp), ec);
            }
        } catch (...) {
        }
    });
    struct RelayGuard
    {
        std::atomic_bool& stop;
        std::thread& th;
        ~RelayGuard()
        {
            stop = true;
            if (th.joinable())
                th.join();
        }
    } relayGuard {relayStop, pushRelay};

    serverProxy.reset();
    dht::ProxyServerConfig serverConfig;
    serverConfig.port = proxyPort;
    serverConfig.pushServer = "127.0.0.1:" + std::to_string(pushPort);
    serverProxy = std::make_unique<dht::DhtProxyServer>(nodeProxy, serverConfig);

    clientConfig.proxy_server = "http://127.0.0.1:" + std::to_string(proxyPort);
    clientConfig.push_token = "relay-token";
    clientConfig.push_platform = "android";

    nodePeer.registerType(chainEditableType);
    nodeProxy->registerType(chainEditableType);

    nodeClient.run(0, clientConfig);
    nodeClient.registerType(chainEditableType);

    bool done = false;
    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock<std::mutex> lk(cv_m);

    auto key = dht::InfoHash::get("proxy-full-chain");
    auto valueAuthor = dht::crypto::generateIdentity("ProxyChainAuthor");

    std::vector<std::shared_ptr<dht::Value>> values;
    auto token = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& incoming, bool expired) {
        if (expired)
            return true;
        std::lock_guard<std::mutex> lk(cv_m);
        values.insert(values.end(), incoming.begin(), incoming.end());
        done = true;
        cv.notify_all();
        return true;
    });

    dht::Value firstVal {"first-version"};
    firstVal.type = CHAIN_EDITABLE_TYPE_ID;
    firstVal.id = 424242;
    firstVal.seq = 1;
    firstVal.sign(*valueAuthor.first);
    auto firstData = firstVal.data;
    nodePeer.put(key, std::move(firstVal), [&](bool ok) {
        std::lock_guard<std::mutex> lk(cv_m);
        CPPUNIT_ASSERT(ok);
        cv.notify_all();
    });

    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    done = false;
    CPPUNIT_ASSERT_EQUAL((size_t) 1u, values.size());
    CPPUNIT_ASSERT_EQUAL((dht::Value::Id) 424242, values.back()->id);
    CPPUNIT_ASSERT_EQUAL((uint16_t) 1, values.back()->seq);
    CPPUNIT_ASSERT(firstData == values.back()->data);

    dht::Value secondVal {"second-version"};
    secondVal.type = CHAIN_EDITABLE_TYPE_ID;
    secondVal.id = 424242;
    secondVal.seq = 2;
    secondVal.sign(*valueAuthor.first);
    auto secondData = secondVal.data;
    nodePeer.put(key, std::move(secondVal), [&](bool ok) {
        std::lock_guard<std::mutex> lk(cv_m);
        CPPUNIT_ASSERT(ok);
        cv.notify_all();
    });

    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    done = false;
    CPPUNIT_ASSERT_EQUAL((size_t) 2u, values.size());
    CPPUNIT_ASSERT_EQUAL((dht::Value::Id) 424242, values.back()->id);
    CPPUNIT_ASSERT_EQUAL((uint16_t) 2, values.back()->seq);
    CPPUNIT_ASSERT(secondData == values.back()->data);
    CPPUNIT_ASSERT(relayedPushCount.load() >= 2);

    // Older sequence should not update current cached value
    dht::Value staleVal {"stale-version"};
    staleVal.type = CHAIN_EDITABLE_TYPE_ID;
    staleVal.id = 424242;
    staleVal.seq = 1;
    staleVal.sign(*valueAuthor.first);
    nodePeer.put(key, std::move(staleVal), [&](bool ok) {
        std::lock_guard<std::mutex> lk(cv_m);
        CPPUNIT_ASSERT(ok);
        cv.notify_all();
    });
    CPPUNIT_ASSERT(not cv.wait_for(lk, 1s, [&] { return done; }));
    CPPUNIT_ASSERT_EQUAL((size_t) 2u, values.size());
    CPPUNIT_ASSERT_EQUAL((uint16_t) 2, values.back()->seq);
    CPPUNIT_ASSERT(secondData == values.back()->data);

    // New id should be delivered as an additional value
    dht::Value thirdVal {"third-value"};
    thirdVal.type = CHAIN_EDITABLE_TYPE_ID;
    thirdVal.id = 424243;
    thirdVal.seq = 1;
    thirdVal.sign(*valueAuthor.first);
    auto thirdData = thirdVal.data;
    nodePeer.put(key, std::move(thirdVal), [&](bool ok) {
        std::lock_guard<std::mutex> lk(cv_m);
        CPPUNIT_ASSERT(ok);
        cv.notify_all();
    });

    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    done = false;
    CPPUNIT_ASSERT_EQUAL((size_t) 3u, values.size());
    CPPUNIT_ASSERT_EQUAL((dht::Value::Id) 424243, values.back()->id);
    CPPUNIT_ASSERT_EQUAL((uint16_t) 1, values.back()->seq);
    CPPUNIT_ASSERT(thirdData == values.back()->data);
    CPPUNIT_ASSERT(relayedPushCount.load() >= 3);

    nodeClient.cancelListen(key, std::move(token));
#endif
}

void
DhtProxyTester::testPutGet40KChars()
{
    nodeClient.run(0, clientConfig);
    constexpr size_t N = 40000;

    // Arrange
    auto key = dht::InfoHash::get("testPutGet40KChars");
    std::vector<std::shared_ptr<dht::Value>> values;
    std::vector<uint8_t> mtu;
    mtu.reserve(N);
    for (size_t i = 0; i < N; i++)
        mtu.emplace_back((i % 2) ? 'T' : 'M');
    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock lk(cv_m);
    bool done_put = false;
    bool done_get = false;

    // Act
    dht::Value val {mtu};
    nodePeer.put(key, std::move(val), [&](bool ok) {
        std::lock_guard lk(cv_m);
        done_put = ok;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done_put; }));

    nodeClient.get(
        key,
        [&](const std::vector<std::shared_ptr<dht::Value>>& vals) {
            values.insert(values.end(), vals.begin(), vals.end());
            return true;
        },
        [&](bool ok) {
            std::lock_guard lk(cv_m);
            done_get = ok;
            cv.notify_all();
        });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done_get; }));

    // Assert
    CPPUNIT_ASSERT_EQUAL((size_t) 1u, values.size());
    for (const auto& value : values)
        CPPUNIT_ASSERT(value->data == mtu);
}

void
DhtProxyTester::testFuzzy()
{
    constexpr size_t N = 40000;

    // Arrange
    auto key = dht::InfoHash::get("testFuzzy");
    std::vector<std::shared_ptr<dht::Value>> values;
    std::vector<uint8_t> mtu;
    mtu.reserve(N);
    for (size_t i = 0; i < N; i++)
        mtu.emplace_back((i % 2) ? 'T' : 'M');

    // Act
    for (size_t i = 0; i < 100; i++) {
        auto nodeTest = std::make_shared<dht::DhtRunner>();
        nodeTest->run(0, clientConfig);
        nodeTest->put(key, dht::Value(mtu), [&](bool ok) { CPPUNIT_ASSERT(ok); });
        nodeTest->get(
            key,
            [&](const std::vector<std::shared_ptr<dht::Value>>& vals) {
                values.insert(values.end(), vals.begin(), vals.end());
                return true;
            },
            [&](bool ok) { CPPUNIT_ASSERT(ok); });
        std::this_thread::sleep_for(5ms);
    }

    // Assert
    for (const auto& value : values)
        CPPUNIT_ASSERT(value->data == mtu);
}

void
DhtProxyTester::testShutdownStop()
{
    constexpr size_t N = 40000;
    constexpr unsigned C = 100;

    // Arrange
    auto key = dht::InfoHash::get("testShutdownStop");
    std::vector<std::shared_ptr<dht::Value>> values;
    std::vector<uint8_t> mtu;
    mtu.reserve(N);
    for (size_t i = 0; i < N; i++)
        mtu.emplace_back((i % 2) ? 'T' : 'M');

    std::atomic_uint callback_count {0};

    // Act
    for (size_t i = 0; i < C; i++) {
        auto nodeTest = std::make_shared<dht::DhtRunner>();
        nodeTest->run(0, clientConfig);
        nodeTest->put(key, dht::Value(mtu), [&](bool /*ok*/) { callback_count++; });
        nodeTest->get(
            key,
            [&](const std::vector<std::shared_ptr<dht::Value>>& vals) {
                values.insert(values.end(), vals.begin(), vals.end());
                return true;
            },
            [&](bool /*ok*/) { callback_count++; });
        bool done = false;
        std::condition_variable cv;
        std::mutex cv_m;
        nodeTest->shutdown(
            [&] {
                std::lock_guard lk(cv_m);
                done = true;
                cv.notify_all();
            },
            true);
        std::unique_lock lk(cv_m);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    }
    CPPUNIT_ASSERT_EQUAL(2 * C, callback_count.load());
}

void
DhtProxyTester::testGetAfterListen()
{
    // Test that get() through proxy returns cached values after listen is synced,
    // without double delivery.
    nodeClient.run(0, clientConfig);

    std::condition_variable cv;
    std::mutex cv_m;
    auto key = dht::InfoHash::get("proxyGetAfterListen");

    // Peer puts a value
    dht::Value val {"proxy_cached_val"};
    auto val_data = val.data;
    {
        bool putDone = false;
        nodePeer.put(key, std::move(val), [&](bool ok) {
            std::lock_guard lk(cv_m);
            CPPUNIT_ASSERT(ok);
            putDone = true;
            cv.notify_all();
        });
        std::unique_lock lk(cv_m);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return putDone; }));
    }

    // Start listen on the proxy client
    std::atomic_int listenAddCount {0};
    auto ftoken = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (!expired)
            listenAddCount += vals.size();
        cv.notify_all();
        return true;
    });

    // Wait for listen to receive the value
    {
        std::unique_lock lk(cv_m);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return listenAddCount.load() >= 1; }));
    }

    // Now do a get — should be served from the synced proxy cache
    auto vals = nodeClient.get(key).get();
    CPPUNIT_ASSERT_MESSAGE("get() through proxy should return values", not vals.empty());
    CPPUNIT_ASSERT(val_data == vals.front()->data);

    // Listen should not fire extra callbacks
    std::this_thread::sleep_for(200ms);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Listen should not fire extra callbacks from proxy get()", 1, listenAddCount.load());

    nodeClient.cancelListen(key, ftoken.get());
}

void
DhtProxyTester::testListenDuplicatePut()
{
    // Test that putting the same value multiple times through proxy only
    // triggers a single add callback in the listener.
    nodeClient.run(0, clientConfig);

    std::condition_variable cv;
    std::mutex cv_m;
    auto key = dht::InfoHash::get("proxyListenDupPut");

    std::vector<std::pair<dht::Value::Id, bool>> events;
    auto ftoken = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        std::lock_guard lk(cv_m);
        for (const auto& v : vals)
            events.emplace_back(v->id, expired);
        cv.notify_all();
        return true;
    });

    // Wait for listen to be established
    std::this_thread::sleep_for(500ms);

    // Peer puts same value 3 times
    auto val = std::make_shared<dht::Value>("proxy_dup_test");
    val->id = 456;
    for (int i = 0; i < 3; i++) {
        bool putDone = false;
        nodePeer.put(key, val, [&](bool ok) {
            std::lock_guard lk(cv_m);
            CPPUNIT_ASSERT(ok);
            putDone = true;
            cv.notify_all();
        });
        std::unique_lock lk(cv_m);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return putDone; }));
    }

    // Wait for at least 1 add to arrive
    {
        std::unique_lock lk(cv_m);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
            return std::any_of(events.begin(), events.end(), [](const auto& e) { return !e.second; });
        }));
    }

    // Allow stray callbacks
    std::this_thread::sleep_for(500ms);

    // Should have exactly 1 add, 0 expires
    {
        std::lock_guard lk(cv_m);
        int addCount = 0, expireCount = 0;
        for (const auto& e : events) {
            if (e.second)
                expireCount++;
            else
                addCount++;
        }
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Duplicate puts through proxy should produce only 1 add callback", 1, addCount);
        CPPUNIT_ASSERT_EQUAL_MESSAGE("No expire callbacks expected", 0, expireCount);
    }

    nodeClient.cancelListen(key, ftoken.get());
}

void
DhtProxyTester::testPushMultiValueEditExpire()
{
#ifndef OPENDHT_PUSH_NOTIFICATIONS
    fmt::print(stderr, "Push notifications are not supported in this build, skipping test\n");
    return;
#else
    // Test with multiple values: edit one via push, expire another via push.
    // Verify that editing value A does not affect value B, and that expiring
    // value B does not affect value A.
    static constexpr dht::ValueType::Id MULTI_TYPE_ID = 7777;
    const dht::ValueType multiType {MULTI_TYPE_ID,
                                    "multi-push",
                                    std::chrono::seconds(30),
                                    dht::ValueType::DEFAULT_STORE_POLICY,
                                    [](dht::InfoHash,
                                       const std::shared_ptr<dht::Value>&,
                                       std::shared_ptr<dht::Value>&,
                                       const dht::InfoHash&,
                                       const dht::SockAddr&) { return true; }};
    nodePeer.registerType(multiType);
    nodeProxy->registerType(multiType);

    clientConfig.push_token = "multi-push-token";
    nodeClient.run(0, clientConfig);
    nodeClient.registerType(multiType);

    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock<std::mutex> lk(cv_m);

    auto key = dht::InfoHash::get("pushMultiEditExpire");
    auto identity = dht::crypto::generateIdentity("MultiEditAuthor");

    struct Event {
        dht::Value::Id id;
        uint16_t seq;
        bool expired;
    };
    std::vector<Event> events;

    auto ftoken = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        std::lock_guard<std::mutex> lk(cv_m);
        for (const auto& v : vals)
            events.push_back({v->id, v->seq, expired});
        cv.notify_all();
        return true;
    });

    // Wait for listen to be established
    cv.wait_for(lk, 1s);

    // Put value A (id=100)
    dht::Value valA {"value-A"};
    valA.type = MULTI_TYPE_ID;
    valA.id = 100;
    valA.seq = 1;
    valA.sign(*identity.first);
    {
        bool done = false;
        nodePeer.put(key, std::make_shared<dht::Value>(std::move(valA)), [&](bool ok) {
            std::lock_guard<std::mutex> lk(cv_m);
            CPPUNIT_ASSERT(ok);
            done = true;
            cv.notify_all();
        });
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    }

    // Put value B (id=200)
    dht::Value valB {"value-B"};
    valB.type = MULTI_TYPE_ID;
    valB.id = 200;
    valB.seq = 1;
    valB.sign(*identity.first);
    {
        bool done = false;
        nodePeer.put(key, std::make_shared<dht::Value>(std::move(valB)), [&](bool ok) {
            std::lock_guard<std::mutex> lk(cv_m);
            CPPUNIT_ASSERT(ok);
            done = true;
            cv.notify_all();
        });
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    }

    // Simulate push notification to fetch both values
    std::map<std::string, std::string> push_data;
    push_data["key"] = key.toString();
    push_data["t"] = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    nodeClient.pushNotificationReceived(push_data).get();

    // Wait for both values to arrive
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
        int adds = 0;
        for (const auto& e : events)
            if (!e.expired)
                adds++;
        return adds >= 2;
    }));

    // Edit value A (higher seq)
    dht::Value valA2 {"value-A-v2"};
    valA2.type = MULTI_TYPE_ID;
    valA2.id = 100;
    valA2.seq = 2;
    valA2.sign(*identity.first);
    {
        bool done = false;
        nodePeer.put(key, std::make_shared<dht::Value>(std::move(valA2)), [&](bool ok) {
            std::lock_guard<std::mutex> lk(cv_m);
            CPPUNIT_ASSERT(ok);
            done = true;
            cv.notify_all();
        });
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    }

    // Simulate push notification for the edit
    push_data["t"] = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    push_data.erase("exp");
    nodeClient.pushNotificationReceived(push_data).get();

    // Wait for the edited value (id=100, seq=2) to arrive
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
        return std::any_of(events.begin(), events.end(), [](const Event& e) {
            return e.id == 100 && e.seq == 2 && !e.expired;
        });
    }));

    // No phantom expire should have been generated for value A or B
    {
        int expireCount = 0;
        for (const auto& e : events)
            if (e.expired)
                expireCount++;
        CPPUNIT_ASSERT_EQUAL_MESSAGE("No expire should happen during edit", 0, expireCount);
    }

    // Expire value B via push notification
    push_data["exp"] = std::to_string((dht::Value::Id) 200);
    push_data["t"] = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    CPPUNIT_ASSERT(nodeClient.pushNotificationReceived(push_data).get() == dht::PushNotificationResult::ValuesExpired);

    // Wait for expire callback for value B
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
        return std::any_of(events.begin(), events.end(), [](const Event& e) {
            return e.id == 200 && e.expired;
        });
    }));

    // Verify: value A (edited) should NOT have been expired
    {
        bool aExpired = std::any_of(events.begin(), events.end(), [](const Event& e) {
            return e.id == 100 && e.expired;
        });
        CPPUNIT_ASSERT_MESSAGE("Value A should not be expired when only B is expired", !aExpired);
    }

    nodeClient.cancelListen(key, ftoken.get());
#endif
}

void
DhtProxyTester::testPushRefreshNoSpuriousExpire()
{
#ifndef OPENDHT_PUSH_NOTIFICATIONS
    fmt::print(stderr, "Push notifications are not supported in this build, skipping test\n");
    return;
#else
    // Test that a push refresh (ListenRefresh) that re-fetches values does not
    // produce phantom expires for values that are still present on the DHT.
    // This verifies the fix in dht_proxy_client.cpp where the completion callback
    // only expires values when ok==true and they are genuinely missing.
    static constexpr dht::ValueType::Id REFRESH_TYPE_ID = 8787;
    const dht::ValueType refreshType {REFRESH_TYPE_ID,
                                      "refresh-test",
                                      std::chrono::seconds(30),
                                      dht::ValueType::DEFAULT_STORE_POLICY,
                                      [](dht::InfoHash,
                                         const std::shared_ptr<dht::Value>&,
                                         std::shared_ptr<dht::Value>&,
                                         const dht::InfoHash&,
                                         const dht::SockAddr&) { return true; }};
    nodePeer.registerType(refreshType);
    nodeProxy->registerType(refreshType);

    clientConfig.push_token = "refresh-push-token";
    nodeClient.run(0, clientConfig);
    nodeClient.registerType(refreshType);

    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock<std::mutex> lk(cv_m);

    auto key = dht::InfoHash::get("pushRefreshNoExpire");
    auto identity = dht::crypto::generateIdentity("RefreshAuthor");

    struct Event {
        dht::Value::Id id;
        bool expired;
    };
    std::vector<Event> events;

    auto ftoken = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        std::lock_guard<std::mutex> lk(cv_m);
        for (const auto& v : vals)
            events.push_back({v->id, expired});
        cv.notify_all();
        return true;
    });

    // Wait for listen to be established
    cv.wait_for(lk, 1s);

    // Put 3 values
    for (dht::Value::Id id : {10, 20, 30}) {
        auto v = std::make_shared<dht::Value>("val-" + std::to_string(id));
        v->type = REFRESH_TYPE_ID;
        v->id = id;
        v->seq = 1;
        v->sign(*identity.first);
        bool done = false;
        nodePeer.put(key, v, [&](bool ok) {
            std::lock_guard<std::mutex> lk(cv_m);
            CPPUNIT_ASSERT(ok);
            done = true;
            cv.notify_all();
        });
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    }

    // Simulate initial push notification to fetch all values
    std::map<std::string, std::string> push_data;
    push_data["key"] = key.toString();
    push_data["t"] = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    nodeClient.pushNotificationReceived(push_data).get();

    // Wait for all 3 values to arrive
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
        int adds = 0;
        for (const auto& e : events)
            if (!e.expired)
                adds++;
        return adds >= 3;
    }));

    // Verify no expires yet
    {
        int expireCount = 0;
        for (const auto& e : events)
            if (e.expired)
                expireCount++;
        CPPUNIT_ASSERT_EQUAL_MESSAGE("No expires after initial fetch", 0, expireCount);
    }

    // Simulate a refresh push notification (same values still present)
    // This should re-fetch the same 3 values, with none expiring.
    push_data["t"] = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    push_data.erase("exp");
    nodeClient.pushNotificationReceived(push_data).get();

    // Wait a bit for any callbacks
    cv.wait_for(lk, 1s);

    // Still no expires — all values are still present on DHT
    {
        int expireCount = 0;
        for (const auto& e : events)
            if (e.expired)
                expireCount++;
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Refresh with same values should not produce expires", 0, expireCount);
    }

    // Now remove value 20 from the DHT (simulate by not re-publishing),
    // then trigger another refresh. The removed value should be expired.
    // We'll use the "exp" field to explicitly expire value 20.
    push_data["exp"] = "20";
    push_data["t"] = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    nodeClient.pushNotificationReceived(push_data).get();

    // Wait for expire callback
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
        return std::any_of(events.begin(), events.end(), [](const Event& e) {
            return e.id == 20 && e.expired;
        });
    }));

    // Verify only value 20 expired, not 10 or 30
    {
        bool id10Expired = std::any_of(events.begin(), events.end(), [](const Event& e) {
            return e.id == 10 && e.expired;
        });
        bool id30Expired = std::any_of(events.begin(), events.end(), [](const Event& e) {
            return e.id == 30 && e.expired;
        });
        CPPUNIT_ASSERT_MESSAGE("Value 10 should not be expired", !id10Expired);
        CPPUNIT_ASSERT_MESSAGE("Value 30 should not be expired", !id30Expired);
    }

    nodeClient.cancelListen(key, ftoken.get());
#endif
}

void
DhtProxyTester::testProxyListenEditChain()
{
    // Chain of rapid edits through proxy (no push). Each edit should appear as
    // an add, no phantom expires during the chain, then natural expiration.
    static constexpr dht::ValueType::Id CHAIN_TYPE_ID = 8181;
    const dht::ValueType chainType {CHAIN_TYPE_ID,
                                    "proxy-chain-edit",
                                    std::chrono::seconds(2),
                                    dht::ValueType::DEFAULT_STORE_POLICY,
                                    [](dht::InfoHash,
                                       const std::shared_ptr<dht::Value>&,
                                       std::shared_ptr<dht::Value>&,
                                       const dht::InfoHash&,
                                       const dht::SockAddr&) { return true; }};
    nodePeer.registerType(chainType);
    nodeProxy->registerType(chainType);

    nodeClient.run(0, clientConfig);
    nodeClient.registerType(chainType);

    std::condition_variable cv;
    std::mutex cv_m;
    auto key = dht::InfoHash::get("proxyEditChain");
    auto identity = dht::crypto::generateIdentity("ProxyChainEditTester");

    struct Event { dht::Value::Id id; uint16_t seq; bool expired; };
    std::vector<Event> events;

    auto ftoken = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        std::lock_guard<std::mutex> lk(cv_m);
        for (const auto& v : vals)
            events.push_back({v->id, v->seq, expired});
        cv.notify_all();
        return true;
    });

    // Wait for listen to be established
    std::this_thread::sleep_for(500ms);

    // Rapid chain of 4 edits
    constexpr int NUM_EDITS = 4;
    for (int seq = 1; seq <= NUM_EDITS; seq++) {
        auto v = std::make_shared<dht::Value>("proxy-v" + std::to_string(seq));
        v->type = CHAIN_TYPE_ID;
        v->id = 77;
        v->seq = seq;
        v->sign(*identity.first);
        bool done = false;
        nodePeer.put(key, v, [&](bool ok) {
            std::lock_guard<std::mutex> lk(cv_m);
            CPPUNIT_ASSERT(ok);
            done = true;
            cv.notify_all();
        });
        std::unique_lock lk(cv_m);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    }

    // Wait for edits to arrive (at least 2: initial + one or more updates)
    // Note: rapid edits may coalesce in the DHT — only the latest is stored.
    {
        std::unique_lock lk(cv_m);
        CPPUNIT_ASSERT(cv.wait_for(lk, 15s, [&] {
            int adds = 0;
            for (const auto& e : events)
                if (!e.expired)
                    adds++;
            return adds >= 2;
        }));
    }

    // Allow stray callbacks
    std::this_thread::sleep_for(500ms);

    // Verify: at least 2 adds, 0 expires during edits
    {
        std::lock_guard<std::mutex> lk(cv_m);
        int addCount = 0, expireCount = 0;
        for (const auto& e : events) {
            if (e.expired)
                expireCount++;
            else
                addCount++;
        }
        CPPUNIT_ASSERT_MESSAGE("Should receive at least 2 add callbacks via proxy", addCount >= 2);
        CPPUNIT_ASSERT_EQUAL_MESSAGE("No expires during edit chain via proxy", 0, expireCount);

        // Verify final seq is NUM_EDITS
        uint16_t maxSeq = 0;
        for (const auto& e : events)
            if (!e.expired && e.seq > maxSeq)
                maxSeq = e.seq;
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Latest add should be the final version",
                                     (uint16_t) NUM_EDITS, maxSeq);
    }

    // Wait for natural expiration
    {
        std::unique_lock lk(cv_m);
        CPPUNIT_ASSERT_MESSAGE("Value should eventually expire via proxy", cv.wait_for(lk, 60s, [&] {
            return std::any_of(events.begin(), events.end(), [](const Event& e) { return e.expired; });
        }));
    }

    // Only 1 expire, with the latest seq
    {
        std::lock_guard<std::mutex> lk(cv_m);
        int expireCount = 0;
        uint16_t expiredSeq = 0;
        for (const auto& e : events) {
            if (e.expired) {
                expireCount++;
                if (e.seq > expiredSeq)
                    expiredSeq = e.seq;
            }
        }
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Should have exactly 1 expire via proxy", 1, expireCount);
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Expired value should be the latest",
                                     (uint16_t) NUM_EDITS, expiredSeq);
    }

    nodeClient.cancelListen(key, ftoken.get());
}

void
DhtProxyTester::testPushRapidEditsNoPhantom()
{
#ifndef OPENDHT_PUSH_NOTIFICATIONS
    fmt::print(stderr, "Push notifications are not supported in this build, skipping test\n");
    return;
#else
    // Rapid fire edits with push notifications between each.
    // No phantom expires should appear at any point.
    static constexpr dht::ValueType::Id RAPID_TYPE_ID = 9191;
    const dht::ValueType rapidType {RAPID_TYPE_ID,
                                    "rapid-push-edit",
                                    std::chrono::seconds(30),
                                    dht::ValueType::DEFAULT_STORE_POLICY,
                                    [](dht::InfoHash,
                                       const std::shared_ptr<dht::Value>&,
                                       std::shared_ptr<dht::Value>&,
                                       const dht::InfoHash&,
                                       const dht::SockAddr&) { return true; }};
    nodePeer.registerType(rapidType);
    nodeProxy->registerType(rapidType);

    clientConfig.push_token = "rapid-edit-token";
    nodeClient.run(0, clientConfig);
    nodeClient.registerType(rapidType);

    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock<std::mutex> lk(cv_m);
    auto key = dht::InfoHash::get("pushRapidEdits");
    auto identity = dht::crypto::generateIdentity("RapidEditAuthor");

    struct Event { dht::Value::Id id; uint16_t seq; bool expired; };
    std::vector<Event> events;

    auto ftoken = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        std::lock_guard<std::mutex> lk(cv_m);
        for (const auto& v : vals)
            events.push_back({v->id, v->seq, expired});
        cv.notify_all();
        return true;
    });

    // Wait for listen to be established
    cv.wait_for(lk, 1s);

    // Perform 6 rapid edits, each followed by a push notification
    constexpr int NUM_EDITS = 6;
    for (int seq = 1; seq <= NUM_EDITS; seq++) {
        auto v = std::make_shared<dht::Value>("rapid-v" + std::to_string(seq));
        v->type = RAPID_TYPE_ID;
        v->id = 500;
        v->seq = seq;
        v->sign(*identity.first);

        bool done = false;
        nodePeer.put(key, v, [&](bool ok) {
            std::lock_guard<std::mutex> lk(cv_m);
            CPPUNIT_ASSERT(ok);
            done = true;
            cv.notify_all();
        });
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));

        // Simulate push notification
        std::map<std::string, std::string> push_data;
        push_data["key"] = key.toString();
        push_data["t"] = std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        lk.unlock();
        nodeClient.pushNotificationReceived(push_data).get();
        lk.lock();
    }

    // Wait for edits to arrive (at least 2: initial + latest)
    CPPUNIT_ASSERT(cv.wait_for(lk, 15s, [&] {
        int adds = 0;
        for (const auto& e : events)
            if (!e.expired)
                adds++;
        return adds >= 2;
    }));

    // Allow stray callbacks
    cv.wait_for(lk, 1s);

    // Verify: at least 2 adds, ZERO expires
    {
        int addCount = 0, expireCount = 0;
        for (const auto& e : events) {
            if (e.expired)
                expireCount++;
            else
                addCount++;
        }
        CPPUNIT_ASSERT_MESSAGE("Should receive at least 2 add callbacks via push edits", addCount >= 2);
        CPPUNIT_ASSERT_EQUAL_MESSAGE("No phantom expires during rapid push edits", 0, expireCount);

        // Verify final seq is NUM_EDITS
        uint16_t maxSeq = 0;
        for (const auto& e : events)
            if (!e.expired && e.seq > maxSeq)
                maxSeq = e.seq;
        CPPUNIT_ASSERT_EQUAL((uint16_t) NUM_EDITS, maxSeq);
    }

    nodeClient.cancelListen(key, ftoken.get());
#endif
}

void
DhtProxyTester::testPushRefreshAfterEditKeepsLatest()
{
#ifndef OPENDHT_PUSH_NOTIFICATIONS
    fmt::print(stderr, "Push notifications are not supported in this build, skipping test\n");
    return;
#else
    // After editing a value, a refresh push re-fetches all values.
    // The latest version should stay current, no expire/re-add cycle.
    static constexpr dht::ValueType::Id REFRESH_EDIT_TYPE_ID = 9292;
    const dht::ValueType refreshEditType {REFRESH_EDIT_TYPE_ID,
                                          "refresh-after-edit",
                                          std::chrono::seconds(30),
                                          dht::ValueType::DEFAULT_STORE_POLICY,
                                          [](dht::InfoHash,
                                             const std::shared_ptr<dht::Value>&,
                                             std::shared_ptr<dht::Value>&,
                                             const dht::InfoHash&,
                                             const dht::SockAddr&) { return true; }};
    nodePeer.registerType(refreshEditType);
    nodeProxy->registerType(refreshEditType);

    clientConfig.push_token = "refresh-edit-token";
    nodeClient.run(0, clientConfig);
    nodeClient.registerType(refreshEditType);

    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock<std::mutex> lk(cv_m);
    auto key = dht::InfoHash::get("pushRefreshAfterEdit");
    auto identity = dht::crypto::generateIdentity("RefreshEditAuthor");

    struct Event { dht::Value::Id id; uint16_t seq; bool expired; };
    std::vector<Event> events;

    auto ftoken = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        std::lock_guard<std::mutex> lk(cv_m);
        for (const auto& v : vals)
            events.push_back({v->id, v->seq, expired});
        cv.notify_all();
        return true;
    });

    // Wait for listen to be established
    cv.wait_for(lk, 1s);

    // Put initial value
    auto v1 = std::make_shared<dht::Value>("original");
    v1->type = REFRESH_EDIT_TYPE_ID;
    v1->id = 600;
    v1->seq = 1;
    v1->sign(*identity.first);
    {
        bool done = false;
        nodePeer.put(key, v1, [&](bool ok) {
            std::lock_guard<std::mutex> lk(cv_m);
            CPPUNIT_ASSERT(ok);
            done = true;
            cv.notify_all();
        });
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    }

    // First push notification to receive it
    {
        std::map<std::string, std::string> push_data;
        push_data["key"] = key.toString();
        push_data["t"] = std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        lk.unlock();
        nodeClient.pushNotificationReceived(push_data).get();
        lk.lock();
    }

    // Wait for initial add
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
        return std::any_of(events.begin(), events.end(), [](const Event& e) {
            return e.id == 600 && e.seq == 1 && !e.expired;
        });
    }));

    // Edit to seq 3
    auto v2 = std::make_shared<dht::Value>("edited");
    v2->type = REFRESH_EDIT_TYPE_ID;
    v2->id = 600;
    v2->seq = 3;
    v2->sign(*identity.first);
    {
        bool done = false;
        nodePeer.put(key, v2, [&](bool ok) {
            std::lock_guard<std::mutex> lk(cv_m);
            CPPUNIT_ASSERT(ok);
            done = true;
            cv.notify_all();
        });
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    }

    // Push notification for the edit
    {
        std::map<std::string, std::string> push_data;
        push_data["key"] = key.toString();
        push_data["t"] = std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        lk.unlock();
        nodeClient.pushNotificationReceived(push_data).get();
        lk.lock();
    }

    // Wait for the edit add (seq=3)
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
        return std::any_of(events.begin(), events.end(), [](const Event& e) {
            return e.id == 600 && e.seq == 3 && !e.expired;
        });
    }));

    // Record event count before refresh
    size_t eventsBeforeRefresh = events.size();

    // Simulate another refresh push (same value still present on DHT with seq=3)
    {
        std::map<std::string, std::string> push_data;
        push_data["key"] = key.toString();
        push_data["t"] = std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        lk.unlock();
        nodeClient.pushNotificationReceived(push_data).get();
        lk.lock();
    }

    // Wait a bit for any callbacks
    cv.wait_for(lk, 1s);

    // After refresh: no new adds, no expires. The value is already at seq=3
    // and the refresh should not produce any events (duplicate is filtered).
    {
        int expiresAfterRefresh = 0;
        int addsAfterRefresh = 0;
        for (size_t i = eventsBeforeRefresh; i < events.size(); i++) {
            if (events[i].expired)
                expiresAfterRefresh++;
            else
                addsAfterRefresh++;
        }
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Refresh should not produce phantom expires", 0, expiresAfterRefresh);
        // No new adds either (same value, same seq)
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Refresh should not re-add same value", 0, addsAfterRefresh);
    }

    // Global verification: exactly 2 adds (initial + edit), 0 expires
    {
        int totalAdds = 0, totalExpires = 0;
        for (const auto& e : events) {
            if (e.expired)
                totalExpires++;
            else
                totalAdds++;
        }
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Total adds should be 2 (initial + edit)", 2, totalAdds);
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Total expires should be 0", 0, totalExpires);
    }

    nodeClient.cancelListen(key, ftoken.get());
#endif
}

} // namespace test
