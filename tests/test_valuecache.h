/*
 *  Copyright (C) 2025 Savoir-faire Linux Inc.
 *
 *  Author: GitHub Copilot
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

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class ValueCacheTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(ValueCacheTester);
    CPPUNIT_TEST(testUpdate);
    CPPUNIT_TEST(testUpdateExpiration);
    CPPUNIT_TEST(testExpiration);
    CPPUNIT_TEST(testRefresh);
    CPPUNIT_TEST(testExplicitExpiration);
    CPPUNIT_TEST(testClear);
    CPPUNIT_TEST(testSyncStatus);
    CPPUNIT_TEST(testMaxValues);
    CPPUNIT_TEST(testUpdateTypeExpiration);
    CPPUNIT_TEST(testShortExpirationRefreshLost);
    CPPUNIT_TEST(testShortExpirationHighChurn);
    CPPUNIT_TEST(testNoTimeExpirationWhileSynced);
    CPPUNIT_TEST(testUnsyncExpiresImmediately);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();
    void tearDown();

    void testUpdate();
    void testUpdateExpiration();
    void testExpiration();
    void testRefresh();
    void testExplicitExpiration();
    void testClear();
    void testSyncStatus();
    void testMaxValues();
    void testUpdateTypeExpiration();
    void testShortExpirationRefreshLost();
    void testShortExpirationHighChurn();
    void testNoTimeExpirationWhileSynced();
    void testUnsyncExpiresImmediately();
};

} // namespace test
