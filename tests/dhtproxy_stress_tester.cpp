// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "dhtproxy_stress_tester.h"

#include <iostream>
#include <string>
#include <chrono>
#include <condition_variable>

using namespace std::chrono_literals;

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(DhtProxyStressTester);

void
DhtProxyStressTester::setUp()
{
    logger = dht::log::getStdLogger();

    dht::DhtRunner::Context ctx;
    ctx.logger = logger;

    clientConfig.dht_config.node_config.max_peer_req_per_sec = -1;
    clientConfig.dht_config.node_config.max_req_per_sec = -1;

    nodePeer.run(0, clientConfig, std::move(ctx));

    ctx.logger = logger;

    nodeProxy = std::make_shared<dht::DhtRunner>();
    nodeProxy->run(0, clientConfig, std::move(ctx));
    auto bound = nodePeer.getBound();
    if (bound.isUnspecified())
        bound.setLoopback();
    nodeProxy->bootstrap(bound);

    dht::ProxyServerConfig serverConfig;
    serverConfig.port = 8084;
    serverProxy = std::make_unique<dht::DhtProxyServer>(nodeProxy, serverConfig, logger);
    clientConfig.proxy_server = "http://127.0.0.1:8084";
}

void
DhtProxyStressTester::tearDown()
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
DhtProxyStressTester::testRepeatValues()
{
    dht::DhtRunner::Context ctx;
    ctx.logger = logger;
    nodeClient.run(0, clientConfig, std::move(ctx));

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
    dht::Value secondVal {"You're a monster"};
    auto secondVal_data = secondVal.data;
    nodePeer.put(key, std::move(secondVal));
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return done; }));
    nodeClient.cancelListen(key, std::move(token));
    CPPUNIT_ASSERT_EQUAL(static_cast<int>(values.size()), 2);
    CPPUNIT_ASSERT(values.back() == secondVal_data);
    done = false;

    clientConfig.proxy_server = {};
    constexpr auto DELAY = 60s;
    dht::Value::Id id = 42;
    for (auto now = std::chrono::steady_clock::now(), end = now + 12min; now < end; now += DELAY) {
        auto tmpNode = std::make_shared<dht::DhtRunner>();
        dht::DhtRunner::Context ctx;
        ctx.logger = logger;
        tmpNode->run(0, clientConfig, std::move(ctx));
        auto bound = nodePeer.getBound();
        if (bound.isUnspecified())
            bound.setLoopback();
        tmpNode->bootstrap(nodePeer.getBound());
        // 1 minute
        std::this_thread::sleep_until(now + DELAY);
        auto val = std::make_shared<dht::Value>("I'm doing science and I'm still alive");
        val->id = id++;
        nodePeer.put(key, val, [&](bool ok) {
            CPPUNIT_ASSERT(ok);
            std::lock_guard<std::mutex> lk(cv_m);
            done = true;
            cv.notify_all();
        });
        CPPUNIT_ASSERT(cv.wait_for(lk, 20s, [&] { return done; }));
        done = false;
        // temporary node to make sure the value is retrieved
        auto tmpValues = tmpNode->get(key);

        auto token = nodeClient.listen(key, [&, val](const std::vector<std::shared_ptr<dht::Value>>& v, bool expired) {
            if (not expired) {
                for (const auto& value : v) {
                    if (value->id == val->id) {
                        std::lock_guard<std::mutex> lk(cv_m);
                        done = true;
                        cv.notify_all();
                        break;
                    }
                }
            }
            return true;
        });
        CPPUNIT_ASSERT(cv.wait_for(lk, 25s, [&] { return done; }));
        done = false;

        bool found_value = false;
        for (const auto& value : tmpValues.get()) {
            if (value->data == val->data) {
                found_value = true;
                break;
            }
        }
        CPPUNIT_ASSERT(found_value);

        nodeClient.cancelListen(key, std::move(token));
        tmpNode->shutdown();
    }
}

} // namespace test
