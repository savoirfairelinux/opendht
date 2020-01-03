/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <opendht/dhtrunner.h>
#include <opendht/dht_proxy_server.h>
#include <opendht/log.h>

namespace test {

class DhtProxyTester : public CppUnit::TestFixture {
    CPPUNIT_TEST_SUITE(DhtProxyTester);
    CPPUNIT_TEST(testGetPut);
    CPPUNIT_TEST(testListen);
    CPPUNIT_TEST(testResubscribeGetValues);
    CPPUNIT_TEST(testPutGet40KChars);
    CPPUNIT_TEST(testFuzzy);
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
    * When a proxy redo a subscribe on the proxy
    * it should retrieve existant values
    */
   void testResubscribeGetValues();
   /**
    * Test MTU put/get on dht
    */
   void testPutGet40KChars();

   void testFuzzy();

 private:
    dht::DhtRunner::Config clientConfig {};
    dht::DhtRunner nodePeer;
    dht::DhtRunner nodeClient;
    std::shared_ptr<dht::DhtRunner> nodeProxy;
    std::unique_ptr<dht::DhtProxyServer> serverProxy;
};

}  // namespace test
