// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class NetworkEngineTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(NetworkEngineTester);
    CPPUNIT_TEST(testIgnoresUnknownPartialData);
    CPPUNIT_TEST(testCompletesPartialSessionFromSameSource);
    CPPUNIT_TEST(testKeepsSessionForWrongSourceFragment);
    CPPUNIT_TEST(testListenConfirmationCarriesToken);
    CPPUNIT_TEST(testListenReopensSocketAfterNodeExpiration);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();
    void tearDown();

    void testIgnoresUnknownPartialData();
    void testCompletesPartialSessionFromSameSource();
    void testKeepsSessionForWrongSourceFragment();
    void testListenConfirmationCarriesToken();
    void testListenReopensSocketAfterNodeExpiration();
};

} // namespace test