/*
 *  Copyright (C) 2018 Savoir-faire Linux Inc.
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

// std
#include <iostream>
#include <string>

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
    node1.put(key, std::move(val));
    auto vals = node2.get(key).get();
    CPPUNIT_ASSERT(not vals.empty());
    CPPUNIT_ASSERT(vals.front()->data == val_data);
}

void
DhtRunnerTester::testListen() {
    // TODO
}

}  // namespace test
