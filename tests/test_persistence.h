// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <opendht/dhtrunner.h>

namespace test {

class PersistenceTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(PersistenceTester);
    CPPUNIT_TEST(testRestartKeepsValues);
    CPPUNIT_TEST(testRebootExpiresValues);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();
    void tearDown();

    /**
     * A node restarted right away keeps the values it had stored.
     */
    void testRestartKeepsValues();
    /**
     * Values saved before a reboot are dated on a steady clock that starts
     * over, so they must be aged by the wall-clock time the node was down
     * instead of surviving it.
     */
    void testRebootExpiresValues();
};

} // namespace test
