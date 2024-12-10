/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *
 *  Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include "dhtrunnertester.h"

#include <chrono>
#include <mutex>
#include <condition_variable>
using namespace std::chrono_literals;

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(DhtRunnerTester);

void
DhtRunnerTester::setUp() {
    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;

    node1.run(42222, config);
    node2.run(42232, config);
    node2.bootstrap(node1.getBound());
}

void
DhtRunnerTester::tearDown() {
    unsigned done {0};
    std::condition_variable cv;
    std::mutex cv_m;
    auto shutdown = [&]{
        std::lock_guard<std::mutex> lk(cv_m);
        done++;
        cv.notify_all();
    };
    node1.shutdown(shutdown);
    node2.shutdown(shutdown);
    std::unique_lock<std::mutex> lk(cv_m);
    CPPUNIT_ASSERT(cv.wait_for(lk, 5s, [&]{ return done == 2; }));
    node1.join();
    node2.join();
}

void
DhtRunnerTester::testConstructors() {
    CPPUNIT_ASSERT(node1.getBoundPort() == 42222);
    CPPUNIT_ASSERT(node2.getBoundPort() == 42232);
}

void
DhtRunnerTester::testGetPut() {
    auto key = dht::InfoHash::get("123");
    dht::Value val {"hey"};
    auto val_data = val.data;
    std::promise<bool> p;
    node2.put(key, std::move(val), [&](bool ok){
        p.set_value(ok);
    });
    CPPUNIT_ASSERT(p.get_future().get());
    auto vals = node1.get(key).get();
    CPPUNIT_ASSERT(not vals.empty());
    CPPUNIT_ASSERT(vals.front()->data == val_data);
}

void
DhtRunnerTester::testListen() {
    std::mutex mutex;
    std::condition_variable cv;
    std::atomic_uint valueCount(0);
    unsigned putCount(0);
    unsigned putOkCount(0);

    auto a = dht::InfoHash::get("234");
    auto b = dht::InfoHash::get("2345");
    auto c = dht::InfoHash::get("23456");
    auto d = dht::InfoHash::get("234567");
    constexpr unsigned N = 256;
    constexpr unsigned SZ = 56 * 1024;

    auto ftokena = node1.listen(a, [&](const std::shared_ptr<dht::Value>&) {
        valueCount++;
        return true;
    });

    auto ftokenb = node1.listen(b, [&](const std::shared_ptr<dht::Value>&) {
        valueCount++;
        return false;
    });

    auto ftokenc = node1.listen(c, [&](const std::shared_ptr<dht::Value>&) {
        valueCount++;
        return true;
    });

    auto ftokend = node1.listen(d, [&](const std::shared_ptr<dht::Value>&) {
        valueCount++;
        return true;
    });

    std::vector<uint8_t> mtu;
    mtu.reserve(SZ);
    for (size_t i = 0; i < SZ; i++)
        mtu.emplace_back((i % 2) ? 'T' : 'M');

    for (unsigned i=0; i<N; i++) {
        node2.put(a, dht::Value("v1"), [&](bool ok) {
            std::lock_guard<std::mutex> lock(mutex);
            putCount++;
            if (ok) putOkCount++;
            cv.notify_all();
        });
        node2.put(b, dht::Value("v2"), [&](bool ok) {
            std::lock_guard<std::mutex> lock(mutex);
            putCount++;
            if (ok) putOkCount++;
            cv.notify_all();
        });
        auto bigVal = std::make_shared<dht::Value>();
        bigVal->data = mtu;
        node2.put(c, bigVal, [&](bool ok) {
            std::lock_guard<std::mutex> lock(mutex);
            putCount++;
            if (ok) putOkCount++;
            cv.notify_all();
        });
    }

    {
        std::unique_lock<std::mutex> lk(mutex);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&]{ return putCount == N * 3u; }));
        CPPUNIT_ASSERT_EQUAL(N * 3u, putOkCount);
    }

    CPPUNIT_ASSERT(ftokena.valid());
    CPPUNIT_ASSERT(ftokenb.valid());
    CPPUNIT_ASSERT(ftokenc.valid());
    CPPUNIT_ASSERT(ftokend.valid());

    auto tokena = ftokena.get();
    auto tokenc = ftokenc.get();
    auto tokend = ftokend.get();
    // tokenb might be 0 since the callback returns false.

    CPPUNIT_ASSERT(tokena);
    CPPUNIT_ASSERT(tokenc);
    CPPUNIT_ASSERT(tokend);
    CPPUNIT_ASSERT_EQUAL(N * 2u + 1u, valueCount.load());

    node1.cancelListen(a, tokena);
    node1.cancelListen(b, std::move(ftokenb));
    node1.cancelListen(c, tokenc);
    node1.cancelListen(d, tokend);
}

void
DhtRunnerTester::testListenLotOfBytes() {
    std::mutex mutex;
    std::condition_variable cv;
    std::atomic_uint valueCount(0);
    unsigned putCount(0);
    unsigned putOkCount(0);

    std::string data(10000, 'a');

    auto foo = dht::InfoHash::get("foo");
    constexpr unsigned N = 50;

    for (unsigned i=0; i<N; i++) {
        node2.put(foo, data, [&](bool ok) {
            std::lock_guard<std::mutex> lock(mutex);
            putCount++;
            if (ok) putOkCount++;
            cv.notify_all();
        });
    }
    {
        std::unique_lock<std::mutex> lk(mutex);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&]{ return putCount == N; }));
    }

    dht::DhtRunner node3 {};
    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;
    node3.run(42242, config);
    node3.bootstrap(node1.getBound());

    auto ftokenfoo = node3.listen(foo, [&](const std::shared_ptr<dht::Value>&) {
        valueCount++;
        cv.notify_all();
        return true;
    });

    {
        std::unique_lock<std::mutex> lk(mutex);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&]{ return valueCount == N; }));
    }

    node3.cancelListen(foo, ftokenfoo.get());
}

}  // namespace test
