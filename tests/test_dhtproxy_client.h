// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class DhtProxyClientTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(DhtProxyClientTester);
    CPPUNIT_TEST(testResubscribeUsesKeyRoute);
    CPPUNIT_TEST(testSetPushNotificationTokenResubscribesWithNewToken);
    CPPUNIT_TEST_SUITE_END();

public:
    void testResubscribeUsesKeyRoute();
    void testSetPushNotificationTokenResubscribesWithNewToken();
};

} // namespace test