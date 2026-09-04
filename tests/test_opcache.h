// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class OpCacheTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(OpCacheTester);
    CPPUNIT_TEST(testBasicAddExpire);
    CPPUNIT_TEST(testMultipleSources);
    CPPUNIT_TEST(testEditResetsRefCount);
    CPPUNIT_TEST(testEditChainMultiSource);
    CPPUNIT_TEST(testStaleAddIgnored);
    CPPUNIT_TEST(testStaleExpireIgnored);
    CPPUNIT_TEST(testCallbacks);
    CPPUNIT_TEST(testFilters);
    CPPUNIT_TEST(testSyncStatus);
    CPPUNIT_TEST(testGetWhileSynced);
    CPPUNIT_TEST(testGetWhileNotSynced);
    CPPUNIT_TEST(testGetEmptySynced);
    CPPUNIT_TEST(testGetWithoutCallback);
    CPPUNIT_TEST(testGetCallbackReturnsFalse);
    CPPUNIT_TEST(testTimestampOrdering);
    CPPUNIT_TEST(testSourceDropKeepsValue);
    CPPUNIT_TEST(testHighChurnRefCountConsistency);
    CPPUNIT_TEST(testValueUpdateSingleSourcePhantom);
    CPPUNIT_TEST(testExpireAfterUpdate);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();
    void tearDown();

    void testBasicAddExpire();
    void testMultipleSources();
    void testEditResetsRefCount();
    void testEditChainMultiSource();
    void testStaleAddIgnored();
    void testStaleExpireIgnored();
    void testCallbacks();
    void testFilters();
    void testSyncStatus();
    void testGetWhileSynced();
    void testGetWhileNotSynced();
    void testGetEmptySynced();
    void testGetWithoutCallback();
    void testGetCallbackReturnsFalse();
    void testTimestampOrdering();
    void testSourceDropKeepsValue();
    void testHighChurnRefCountConsistency();
    void testValueUpdateSingleSourcePhantom();
    void testExpireAfterUpdate();
};

} // namespace test
