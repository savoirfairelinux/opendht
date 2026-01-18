// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <opendht/dhtrunner.h>
#include <opendht/dht_proxy_server.h>
#include <opendht/log.h>

namespace test {

class DhtProxyStressTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(DhtProxyStressTester);
    CPPUNIT_TEST(testRepeatValues);
    CPPUNIT_TEST_SUITE_END();

public:
    /**
     * Method automatically called before each test by CppUnit
     * Init nodes
     */
    void setUp();
    /**
     * Method automatically called after each test CppUnit
     */
    void tearDown();
    /**
     * Test get and put methods
     */
    void testRepeatValues();

private:
    std::shared_ptr<dht::log::Logger> logger;
    dht::DhtRunner::Config clientConfig {};
    dht::DhtRunner nodePeer;
    dht::DhtRunner nodeClient;
    std::shared_ptr<dht::DhtRunner> nodeProxy;
    std::unique_ptr<dht::DhtProxyServer> serverProxy;
};

} // namespace test
