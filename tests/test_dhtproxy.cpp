// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_dhtproxy.h"

// std
#include <iostream>
#include <string>

#include <chrono>
#include <condition_variable>
#include <asio.hpp>
#include <sys/socket.h>
#include <sys/time.h>

using namespace std::chrono_literals;

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(DhtProxyTester);

void
DhtProxyTester::setUp()
{
    clientConfig.dht_config.node_config.max_peer_req_per_sec = -1;
    clientConfig.dht_config.node_config.max_req_per_sec = -1;

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
        std::lock_guard<std::mutex> lk(cv_m);
        done = true;
        cv.notify_all();
    });
    std::unique_lock<std::mutex> lk(cv_m);
    CPPUNIT_ASSERT(cv.wait_for(lk, 15s, [&] { return done; }));
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
            std::lock_guard<std::mutex> lk(cv_m);
            done = true;
            cv.notify_all();
        });
        std::unique_lock<std::mutex> lk(cv_m);
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
    std::unique_lock<std::mutex> lk(cv_m);
    auto key = dht::InfoHash::get("GLaDOs");
    bool done = false;

    // If a peer send a value, the listen operation from the client
    // should retrieve this value
    dht::Value firstVal {"Hey! It's been a long time. How have you been?"};
    auto firstVal_data = firstVal.data;
    nodePeer.put(key, std::move(firstVal), [&](bool ok) {
        CPPUNIT_ASSERT(ok);
        std::lock_guard<std::mutex> lk(cv_m);
        done = true;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    done = false;

    std::vector<dht::Blob> values;
    auto token = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& v, bool expired) {
        if (not expired) {
            std::lock_guard<std::mutex> lk(cv_m);
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
DhtProxyTester::testResubscribeGetValues()
{
    clientConfig.push_token = "atlas";
    nodeClient.run(0, clientConfig);

    bool done = false;
    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock<std::mutex> lk(cv_m);
    auto key = dht::InfoHash::get("GLaDOs");

    // If a peer sent a value, the listen operation from the client
    // should retrieve this value
    dht::Value firstVal {"Hey! It's been a long time. How have you been?"};
    auto firstVal_data = firstVal.data;
    nodePeer.put(key, std::move(firstVal), [&](bool ok) {
        std::lock_guard<std::mutex> lk(cv_m);
        CPPUNIT_ASSERT(ok);
        done = true;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    done = false;

    // Send a first subscribe, the value is sent via a push notification
    // So ignore values here.
    nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; });
    cv.wait_for(lk, std::chrono::seconds(1));

    // Reboot node (to avoid cache)
    nodeClient.join();
    clientConfig.push_token = "";
    nodeClient.run(0, clientConfig);

    // For the second subscribe, the proxy will return the value in the body
    std::vector<std::shared_ptr<dht::Value>> values;
    auto ftoken = nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& v, bool expired) {
        if (not expired) {
            std::lock_guard<std::mutex> lk(cv_m);
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
    std::unique_lock<std::mutex> lk(cv_m);
    bool done_put = false;
    bool done_get = false;

    // Act
    dht::Value val {mtu};
    nodePeer.put(key, std::move(val), [&](bool ok) {
        std::lock_guard<std::mutex> lk(cv_m);
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
            std::lock_guard<std::mutex> lk(cv_m);
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
                std::lock_guard<std::mutex> lk(cv_m);
                done = true;
                cv.notify_all();
            },
            true);
        std::unique_lock<std::mutex> lk(cv_m);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    }
    CPPUNIT_ASSERT_EQUAL(2 * C, callback_count.load());
}

} // namespace test
