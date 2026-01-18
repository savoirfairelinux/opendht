// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "opendht/peer_discovery.h"

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class PeerDiscoveryTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(PeerDiscoveryTester);
    CPPUNIT_TEST(testMulticastToTwoNodes);
    CPPUNIT_TEST_SUITE_END();

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
     * Test Multicast on two nodes
     */
    void testMulticastToTwoNodes();
};

} // namespace test
