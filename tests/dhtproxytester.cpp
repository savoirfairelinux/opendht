/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
 *          Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "dhtproxytester.h"

// std
#include <iostream>
#include <string>

#include <chrono>
#include <condition_variable>

using namespace std::chrono_literals;

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(DhtProxyTester);

void
DhtProxyTester::setUp() {
    clientConfig.dht_config.node_config.max_peer_req_per_sec = -1;
    clientConfig.dht_config.node_config.max_req_per_sec = -1;

    nodePeer.run(0, clientConfig);

    nodeProxy = std::make_shared<dht::DhtRunner>();
    nodeProxy->run(0, clientConfig);
    nodeProxy->bootstrap(nodePeer.getBound());

    auto serverCAIdentity = dht::crypto::generateEcIdentity("DHT Node CA");
    auto serverIdentity = dht::crypto::generateIdentity("DHT Node", serverCAIdentity);

    serverProxy = std::make_unique<dht::DhtProxyServer>(
            //dht::crypto::Identity{}, // http
            serverIdentity,            // https
            nodeProxy, 8080, /*pushServer*/"127.0.0.1:8090");

    clientConfig.server_ca = serverCAIdentity.second;
    clientConfig.client_identity = dht::crypto::generateIdentity("DhtProxyTester");
    clientConfig.push_node_id = "dhtnode";
    clientConfig.proxy_server = "https://127.0.0.1:8080";
}

void
DhtProxyTester::tearDown() {
    nodePeer.join();
    nodeClient.join();

    bool done = false;
    std::condition_variable cv;
    std::mutex cv_m;
    nodeProxy->shutdown([&]{
        std::lock_guard<std::mutex> lk(cv_m);
        done = true;
        cv.notify_all();
    });
    std::unique_lock<std::mutex> lk(cv_m);
    CPPUNIT_ASSERT(cv.wait_for(lk, 5s, [&]{ return done; }));
    serverProxy.reset();
    nodeProxy.reset();
}

void
DhtProxyTester::testGetPut() {
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
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&]{ return done; }));
    }

    auto vals = nodeClient.get(key).get();
    CPPUNIT_ASSERT(not vals.empty());
    CPPUNIT_ASSERT(vals.front()->data == val_data);
}

void
DhtProxyTester::testListen() {
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
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&]{ return done; }));
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
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&]{ return done; }));
    done = false;
    // Here values should contains 1 values
    CPPUNIT_ASSERT_EQUAL(static_cast<int>(values.size()), 1);
    CPPUNIT_ASSERT(values.front() == firstVal_data);

    // And the listen should retrieve futures values
    // All values
    dht::Value secondVal {"You're a monster"};
    auto secondVal_data = secondVal.data;
    nodePeer.put(key, std::move(secondVal));
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&]{ return done; }));
    nodeClient.cancelListen(key, std::move(token));
    // Here values should contains 2 values
    CPPUNIT_ASSERT_EQUAL(static_cast<int>(values.size()), 2);
    CPPUNIT_ASSERT(values.back() == secondVal_data);
}

void
DhtProxyTester::testResubscribeGetValues() {
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
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&]{ return done; }));
    done = false;

    // Send a first subscribe, the value is sent via a push notification
    // So ignore values here.
    nodeClient.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>&, bool) {
        return true;
    });
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

    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&]{ return done; }));
    auto token = ftoken.get();
    CPPUNIT_ASSERT(token);
    nodeClient.cancelListen(key, token);
    // Here values should still contains 1 values
    CPPUNIT_ASSERT_EQUAL((size_t)1u, values.size());
    CPPUNIT_ASSERT(firstVal_data == values.front()->data);
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
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&]{ return done_put; }));

    nodeClient.get(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals){
        values.insert(values.end(), vals.begin(), vals.end());
        return true;
    },[&](bool ok){
        std::lock_guard<std::mutex> lk(cv_m);
        done_get = ok;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&]{ return done_get; }));

    // Assert
    CPPUNIT_ASSERT_EQUAL((size_t)1u, values.size());
    for (const auto &value: values)
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
        nodeTest->put(key, dht::Value(mtu), [&](bool ok) {
            CPPUNIT_ASSERT(ok);
        });
        nodeTest->get(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals){
            values.insert(values.end(), vals.begin(), vals.end());
            return true;
        },[&](bool ok){
            CPPUNIT_ASSERT(ok);
        });
        std::this_thread::sleep_for(5ms);
    }

    // Assert
    for (const auto &value: values)
        CPPUNIT_ASSERT(value->data == mtu);
}

}  // namespace test
