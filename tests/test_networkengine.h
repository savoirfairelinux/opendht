// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class NetworkEngineTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(NetworkEngineTester);
#ifdef _MSC_VER
    CPPUNIT_TEST(testDisabledOnMsvc);
#else
    CPPUNIT_TEST(testCompletesPartialSessionWithDataBeforeHeader);
    CPPUNIT_TEST(testBuffersLargeValueBeforeHeader);
    CPPUNIT_TEST(testIgnoresEmptyPartialData);
    CPPUNIT_TEST(testRejectsUnsolicitedPartialReply);
    CPPUNIT_TEST(testDropsMalformedCompletedPartialMessage);
    CPPUNIT_TEST(testCompletesPartialSessionFromSameSource);
    CPPUNIT_TEST(testSeparatesPartialSessionsBySource);
    CPPUNIT_TEST(testListenConfirmationCarriesToken);
    CPPUNIT_TEST(testListenConfirmationUpdatesSearchNodeToken);
    CPPUNIT_TEST(testListenReopensSocketAfterNodeExpiration);
    CPPUNIT_TEST(testUnauthorizedListenFlushClearsListenState);
#endif
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();
    void tearDown();

#ifdef _MSC_VER
    void testDisabledOnMsvc();
#else
    void testCompletesPartialSessionWithDataBeforeHeader();
    void testBuffersLargeValueBeforeHeader();
    void testIgnoresEmptyPartialData();
    void testRejectsUnsolicitedPartialReply();
    void testDropsMalformedCompletedPartialMessage();
    void testCompletesPartialSessionFromSameSource();
    void testSeparatesPartialSessionsBySource();
    void testListenConfirmationCarriesToken();
    void testListenConfirmationUpdatesSearchNodeToken();
    void testListenReopensSocketAfterNodeExpiration();
    void testUnauthorizedListenFlushClearsListenState();
#endif
};

} // namespace test