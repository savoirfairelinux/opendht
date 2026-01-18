// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class ThreadPoolTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(ThreadPoolTester);
    CPPUNIT_TEST(testThreadPool);
    CPPUNIT_TEST(testExecutor);
    CPPUNIT_TEST(testContext);
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

    void testThreadPool();
    void testExecutor();
    void testContext();
};

} // namespace test
