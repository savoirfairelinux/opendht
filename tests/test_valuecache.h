// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
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
    CPPUNIT_TEST(testSameSeqEditIgnored);
    CPPUNIT_TEST(testShortExpirationRefreshLost);
    CPPUNIT_TEST(testShortExpirationHighChurn);
    CPPUNIT_TEST(testGracePeriodWhileSynced);
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
    void testSameSeqEditIgnored();
    void testShortExpirationRefreshLost();
    void testShortExpirationHighChurn();
    void testGracePeriodWhileSynced();
    void testUnsyncExpiresImmediately();
};

} // namespace test
