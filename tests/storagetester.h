// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <opendht/dhtrunner.h>

namespace test {

class StorageTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(StorageTester);
    CPPUNIT_TEST(testRemoteStorageLimit);
    CPPUNIT_TEST(testLocalStorageLimit);
    CPPUNIT_TEST(testIndependentLimits);
    CPPUNIT_TEST(testLocalPutNotAffectedByRemoteLimit);
    CPPUNIT_TEST(testRemotePutNotAffectedByLocalLimit);
    CPPUNIT_TEST_SUITE_END();

    dht::DhtRunner node1 {};
    dht::DhtRunner node2 {};

    /**
     * Start both nodes with given configs, bootstrap node2 to node1
     */
    void startNodes(dht::DhtRunner::Config config1, dht::DhtRunner::Config config2);

public:
    void setUp();
    void tearDown();

    /**
     * Test that remote values (received from other nodes) are limited by max_store_size
     */
    void testRemoteStorageLimit();
    /**
     * Test that locally put values are limited by max_local_store_size
     */
    void testLocalStorageLimit();
    /**
     * Test that remote and local limits work independently
     */
    void testIndependentLimits();
    /**
     * Test that local puts are not blocked when remote storage is full
     */
    void testLocalPutNotAffectedByRemoteLimit();
    /**
     * Test that remote puts are not blocked when local storage is full
     */
    void testRemotePutNotAffectedByLocalLimit();
};

} // namespace test
