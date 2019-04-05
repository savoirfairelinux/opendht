/*
 *  Copyright (C) 2019 Savoir-faire Linux Inc.
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

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(DhtRunnerTester);

void
DhtRunnerTester::setUp() {
    node1.run(42222, {}, true);
    node2.run(42232, {}, true);
    node2.bootstrap(node1.getBound());
}

void
DhtRunnerTester::tearDown() {
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
    constexpr unsigned N = 64;

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

    for (unsigned i=0; i<N; i++) {
        node2.put(a, dht::Value("v1"), [&](bool ok) {
            {
                std::lock_guard<std::mutex> lock(mutex);
                putCount++;
                if (ok) putOkCount++;
            }
            cv.notify_all();
        });
        node2.put(b, dht::Value("v2"), [&](bool ok) {
            {
                std::lock_guard<std::mutex> lock(mutex);
                putCount++;
                if (ok) putOkCount++;
            }
            cv.notify_all();
        });
    }

    {
        std::unique_lock<std::mutex> lk(mutex);
        cv.wait_for(lk, std::chrono::seconds(30), [&]{ return putCount == N * 2u; });
        CPPUNIT_ASSERT_EQUAL(N * 2u, putCount);
        CPPUNIT_ASSERT_EQUAL(N * 2u, putOkCount);
    }

    auto tokena = ftokena.get();
    auto tokenb = ftokenb.get();
    auto tokenc = ftokenc.get();

    CPPUNIT_ASSERT(tokena);
    CPPUNIT_ASSERT(tokenb);
    CPPUNIT_ASSERT(tokenc);
    CPPUNIT_ASSERT_EQUAL(N + 1u, valueCount.load());

    node1.cancelListen(a, tokena);
    node1.cancelListen(b, tokena);
    node1.cancelListen(c, tokena);
}

}  // namespace test
