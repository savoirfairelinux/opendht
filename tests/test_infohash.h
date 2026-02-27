// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class InfoHashTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(InfoHashTester);
    CPPUNIT_TEST(testConstructors);
    CPPUNIT_TEST(testComparators);
    CPPUNIT_TEST(testLowBit);
    CPPUNIT_TEST(testCommonBits);
    CPPUNIT_TEST(testXorCmp);
    CPPUNIT_TEST(testHex);
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
    void testComparators();
    /**
     * Test lowbit method
     */
    void testLowBit();
    /**
     * Test commonBits method
     */
    void testCommonBits();
    /**
     * Test xorCmp operators
     */
    void testXorCmp();

    /**
     * Test hex conversion
     */
    void testHex();
};

} // namespace test
