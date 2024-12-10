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

#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <opendht/dhtrunner.h>

namespace test {

class DhtRunnerTester : public CppUnit::TestFixture {
    CPPUNIT_TEST_SUITE(DhtRunnerTester);
    CPPUNIT_TEST(testConstructors);
    CPPUNIT_TEST(testGetPut);
    CPPUNIT_TEST(testListen);
    CPPUNIT_TEST(testListenLotOfBytes);
    CPPUNIT_TEST_SUITE_END();

    dht::DhtRunner node1 {};
    dht::DhtRunner node2 {};
 public:
    /**
     * Method automatically called before each test by CppUnit
     */
    void setUp();
    /**
     * Method automatically called after each test CppUnit
     */
    void tearDown();
    /**
     * Test the differents behaviors of constructors
     */
    void testConstructors();
    /**
     * Test get and put methods
     */
    void testGetPut();
    /**
     * Test listen method
     */
    void testListen();
    /**
     * Test listen method with lot of datas
     */
    void testListenLotOfBytes();
};

}  // namespace test
