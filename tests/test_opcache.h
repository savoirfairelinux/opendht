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

class OpCacheTester : public CppUnit::TestFixture {
    CPPUNIT_TEST_SUITE(OpCacheTester);
    CPPUNIT_TEST(testUpdateRefCount);
    CPPUNIT_TEST(testBasicAddExpire);
    CPPUNIT_TEST(testMultipleSources);
    CPPUNIT_TEST(testUpdateSequence);
    CPPUNIT_TEST(testCallbacks);
    CPPUNIT_TEST(testFilters);
    CPPUNIT_TEST(testSyncStatus);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();
    void tearDown();

    void testUpdateRefCount();
    void testBasicAddExpire();
    void testMultipleSources();
    void testUpdateSequence();
    void testCallbacks();
    void testFilters();
    void testSyncStatus();
};

}  // namespace test
