/*
 *  Copyright (C) 2018 Savoir-faire Linux Inc.
 *
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
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
    nodePeer.run(42222, {}, true);
    nodeProxy = std::make_shared<dht::DhtRunner>();
    nodeClient = std::make_shared<dht::DhtRunner>();

    nodeProxy->run(42232, {}, true);
    nodeProxy->bootstrap(nodePeer.getBound());
    server = std::unique_ptr<dht::DhtProxyServer>(new dht::DhtProxyServer(nodeProxy, 8080));

    nodeClient->run(42242, {}, true);
    nodeClient->bootstrap(nodePeer.getBound());
    nodeClient->setProxyServer("127.0.0.1:8080");
    nodeClient->enableProxy(true);
}

void
DhtProxyTester::tearDown() {
    nodePeer.join();
    nodeClient->join();
    server->stop();
    server = nullptr;
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

    nodePeer.put(key, std::move(val), [&](bool) {
        done = true;
        cv.notify_all();
    });
    std::unique_lock<std::mutex> lk(cv_m);
    cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; });

    auto vals = nodeClient->get(key).get();
    CPPUNIT_ASSERT(not vals.empty());
    CPPUNIT_ASSERT(vals.front()->data == val_data);
}

void
DhtProxyTester::testListen() {
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
        done = true;
        cv.notify_all();
    });
    cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; });
    done = false;

    auto values = std::vector<dht::Blob>();
    nodeClient->listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& v, bool) {
        for (const auto& value : v)
            values.emplace_back(value->data);
        done = true;
        cv.notify_all();
        return true;
    });

    cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; });
    done = false;
    // Here values should contains 1 values
    CPPUNIT_ASSERT_EQUAL(static_cast<int>(values.size()), 1);
    CPPUNIT_ASSERT(values.front() == firstVal_data);

    // And the listen should retrieve futures values
    // All values
    dht::Value secondVal {"You're a monster"};
    auto secondVal_data = secondVal.data;
    nodePeer.put(key, std::move(secondVal));
    cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; });
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
        done = true;
        cv.notify_all();
    });
    cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; });
    done = false;

    // Send a first subscribe, the value is sent via a push notification
    // So ignore values here.
    nodeClient->listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>&, bool) {
        return true;
    });
    cv.wait_for(lk, std::chrono::seconds(1));

    // Reboot node (to avoid cache)
    nodeClient->join();
    nodeClient->run(42242, {}, true);
    nodeClient->bootstrap(nodePeer.getBound());
    nodeClient->setProxyServer("127.0.0.1:8080");
    nodeClient->enableProxy(true);
    nodeClient->setPushNotificationToken("atlas");

    // For the second subscribe, the proxy will return the value in the body
    auto values = std::vector<dht::Blob>();
    nodeClient->listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& v, bool) {
        for (const auto& value : v)
            values.emplace_back(value->data);
        done = true;
        cv.notify_all();
        return true;
    });

    cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; });
    done = false;
    // Here values should still contains 1 values
    CPPUNIT_ASSERT_EQUAL(static_cast<int>(values.size()), 1);
    CPPUNIT_ASSERT(values.front() == firstVal_data);

}

}  // namespace test
