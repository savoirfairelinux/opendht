// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <opendht/dhtrunner.h>

namespace test {

class DhtRunnerTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(DhtRunnerTester);
    CPPUNIT_TEST(testConstructors);
    CPPUNIT_TEST(testGetPut);
    CPPUNIT_TEST(testPutDuplicate);
    CPPUNIT_TEST(testPutOverride);
    CPPUNIT_TEST(testListen);
    CPPUNIT_TEST(testListenLotOfBytes);
    CPPUNIT_TEST(testIdOps);
    CPPUNIT_TEST_SUITE_END();

    dht::DhtRunner node1 {};
    dht::DhtRunner node2 {};

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
     * Test get and put methods
     */
    void testGetPut();
    /**
     * Test get and multiple put
     */
    void testPutDuplicate();
    /**
     * Test get and multiple put with changing value
     */
    void testPutOverride();
    /**
     * Test listen method
     */
    void testListen();
    /**
     * Test methods requiring a node identity
     */
    void testIdOps();
    /**
     * Test listen method with lot of datas
     */
    void testListenLotOfBytes();
    /**
     * Test multithread
     */
    void testMultithread();
};

} // namespace test
