// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <opendht/dhtrunner.h>
#include <opendht/dht_proxy_server.h>

namespace test {

class DhtProxyTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(DhtProxyTester);
    CPPUNIT_TEST(testGetPut);
    CPPUNIT_TEST(testListen);
    CPPUNIT_TEST(testListenValueEdit);
    CPPUNIT_TEST(testPushListenValueEdit);
    CPPUNIT_TEST(testResubscribeGetValues);
    CPPUNIT_TEST(testPushNotification);
    CPPUNIT_TEST(testProxyServerClientFullChain);
    CPPUNIT_TEST(testPutGet40KChars);
    CPPUNIT_TEST(testFuzzy);
    CPPUNIT_TEST(testShutdownStop);
    CPPUNIT_TEST(testGetAfterListen);
    CPPUNIT_TEST(testListenDuplicatePut);
    CPPUNIT_TEST(testPushMultiValueEditExpire);
    CPPUNIT_TEST(testPushRefreshNoSpuriousExpire);
    CPPUNIT_TEST(testProxyListenEditChain);
    CPPUNIT_TEST(testPushRapidEditsNoPhantom);
    CPPUNIT_TEST(testPushRefreshAfterEditKeepsLatest);
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
    void testGetPut();
    /**
     * Test listen
     */
    void testListen();
    /**
     * Test that editing a value only triggers an add callback via proxy, no expire
     */
    void testListenValueEdit();
    /**
     * Test that editing a value only triggers an add callback via push,
     * no phantom expire, and that real expiration is received.
     */
    void testPushListenValueEdit();
    /**
     * When a proxy redo a subscribe on the proxy
     * it should retrieve existant values
     */
    void testResubscribeGetValues();
    /**
     * Test push notification mechanism and OpValueCache
     */
    void testPushNotification();
    /**
     * Test end-to-end chain through proxy server and proxy client
     */
    void testProxyServerClientFullChain();
    /**
     * Test MTU put/get on dht
     */
    void testPutGet40KChars();

    void testFuzzy();

    void testShutdownStop();
    void testGetAfterListen();
    void testListenDuplicatePut();
    void testPushMultiValueEditExpire();
    void testPushRefreshNoSpuriousExpire();
    void testProxyListenEditChain();
    void testPushRapidEditsNoPhantom();
    void testPushRefreshAfterEditKeepsLatest();

private:
    dht::DhtRunner::Config clientConfig {};
    dht::DhtRunner nodePeer;
    dht::DhtRunner nodeClient;
    std::shared_ptr<dht::DhtRunner> nodeProxy;
    std::unique_ptr<dht::DhtProxyServer> serverProxy;
};

} // namespace test
