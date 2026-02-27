// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class ValueTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(ValueTester);
    CPPUNIT_TEST(testConstructors);
    CPPUNIT_TEST(testFilter);
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
     * Test the differents behaviors of constructors
     */
    void testConstructors();
    /**
     * Test compare operators
     */
    void testFilter();
};

} // namespace test
