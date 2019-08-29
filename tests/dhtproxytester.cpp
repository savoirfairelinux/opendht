/*
 *  Copyright (C) 2019 Savoir-faire Linux Inc.
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


namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(DhtProxyTester);

void
DhtProxyTester::setUp() {
    logger = dht::log::getStdLogger();

    nodePeer.run(0, /*identity*/{}, /*threaded*/true);

    nodeProxy = std::make_shared<dht::DhtRunner>();
    nodeProxy->run(0, /*identity*/{}, /*threaded*/true);
    nodeProxy->bootstrap(nodePeer.getBound());

    auto serverCAIdentity = dht::crypto::generateEcIdentity("DHT Node CA");
    auto serverIdentity = dht::crypto::generateIdentity("DHT Node", serverCAIdentity);

    serverProxy = std::unique_ptr<dht::DhtProxyServer>(
        new dht::DhtProxyServer(
            ///*http*/nullptr,
            /*https*/serverIdentity,
            nodeProxy, 8080, /*pushServer*/"127.0.0.1:8090", logger));

    clientConfig.client_cert = serverIdentity.second;
    clientConfig.dht_config.node_config.maintain_storage = false;
    clientConfig.threaded = true;
    clientConfig.push_node_id = "dhtnode";
    clientContext.logger = logger;

    nodeClient = std::make_shared<dht::DhtRunner>();
    nodeClient->run(0, clientConfig, std::move(clientContext));
    nodeClient->bootstrap(nodePeer.getBound());
    nodeClient->setProxyServer("https://127.0.0.1:8080");
    nodeClient->enableProxy(true); // creates DhtProxyClient
}

void
DhtProxyTester::tearDown() {
    logger->d("[tester:proxy] stopping peer node");
    nodePeer.join();
    nodeClient->join();
    logger->d("[tester:proxy] stopping proxy server");
    serverProxy.reset(nullptr);
    logger->d("[tester:proxy] stopping proxy node");
    nodeProxy->join();
}

void
DhtProxyTester::testGetPut() {
    bool done = false;
    std::condition_variable cv;
    std::mutex cv_m;

    auto key = dht::InfoHash::get("GLaDOs");
    dht::Value val {"Hey! It's been a long time. How have you been?"};
    auto val_data = val.data;
    {
        std::unique_lock<std::mutex> lk(cv_m);
        nodePeer.put(key, std::move(val), [&](bool) {
            std::lock_guard<std::mutex> lk(cv_m);
            done = true;
            cv.notify_all();
        });
        CPPUNIT_ASSERT(cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; }));
    }

    auto vals = nodeClient->get(key).get();
    CPPUNIT_ASSERT(not vals.empty());
    CPPUNIT_ASSERT(vals.front()->data == val_data);
}

void
DhtProxyTester::testListen() {
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
    CPPUNIT_ASSERT(cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; }));
    done = false;

    std::vector<dht::Blob> values;
    auto token = nodeClient->listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& v, bool expired) {
        if (not expired) {
            std::lock_guard<std::mutex> lk(cv_m);
            for (const auto& value : v)
                values.emplace_back(value->data);
            done = true;
            cv.notify_all();
        }
        return true;
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; }));
    done = false;
    // Here values should contains 1 values
    CPPUNIT_ASSERT_EQUAL(static_cast<int>(values.size()), 1);
    CPPUNIT_ASSERT(values.front() == firstVal_data);

    // And the listen should retrieve futures values
    // All values
    dht::Value secondVal {"You're a monster"};
    auto secondVal_data = secondVal.data;
    nodePeer.put(key, std::move(secondVal));
    CPPUNIT_ASSERT(cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; }));
    nodeClient->cancelListen(key, std::move(token));
    // Here values should contains 2 values
    CPPUNIT_ASSERT_EQUAL(static_cast<int>(values.size()), 2);
    CPPUNIT_ASSERT(values.back() == secondVal_data);
}

void
DhtProxyTester::testResubscribeGetValues() {
    nodeClient->setPushNotificationToken("atlas");

    bool done = false;
    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock<std::mutex> lk(cv_m);
    auto key = dht::InfoHash::get("GLaDOs");

    // If a peer send a value, the listen operation from the client
    // should retrieve this value
    dht::Value firstVal {"Hey! It's been a long time. How have you been?"};
    auto firstVal_data = firstVal.data;
    nodePeer.put(key, std::move(firstVal), [&](bool) {
        std::lock_guard<std::mutex> lk(cv_m);
        done = true;
        cv.notify_all();
    });
    CPPUNIT_ASSERT(cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; }));
    done = false;

    // Send a first subscribe, the value is sent via a push notification
    // So ignore values here.
    nodeClient->listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>&, bool) {
        return true;
    });
    cv.wait_for(lk, std::chrono::seconds(1));

    // Reboot node (to avoid cache)
    nodeClient->join();
    nodeClient->run(0, clientConfig, std::move(clientContext));
    nodeClient->bootstrap(nodePeer.getBound());
    nodeClient->setProxyServer("https://127.0.0.1:8080");
    nodeClient->enableProxy(true);
    nodeClient->setPushNotificationToken("atlas");

    // For the second subscribe, the proxy will return the value in the body
    auto values = std::vector<dht::Blob>();
    auto ftoken = nodeClient->listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& v, bool expired) {
        if (not expired) {
            std::lock_guard<std::mutex> lk(cv_m);
            for (const auto& value : v)
                values.emplace_back(value->data);
            done = true;
            cv.notify_all();
        }
        return true;
    });

    CPPUNIT_ASSERT(cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; }));
    auto token = ftoken.get();
    CPPUNIT_ASSERT(token);
    nodeClient->cancelListen(key, token);
    // Here values should still contains 1 values
    CPPUNIT_ASSERT_EQUAL((size_t)1u, values.size());
    CPPUNIT_ASSERT(firstVal_data == values.front());
}

}  // namespace test
