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
    CPPUNIT_TEST(testIgnoresUnknownPartialData);
    CPPUNIT_TEST(testCompletesPartialSessionFromSameSource);
    CPPUNIT_TEST(testKeepsSessionForWrongSourceFragment);
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
    void testIgnoresUnknownPartialData();
    void testCompletesPartialSessionFromSameSource();
    void testKeepsSessionForWrongSourceFragment();
    void testListenConfirmationCarriesToken();
    void testListenConfirmationUpdatesSearchNodeToken();
    void testListenReopensSocketAfterNodeExpiration();
    void testUnauthorizedListenFlushClearsListenState();
#endif
};

} // namespace test