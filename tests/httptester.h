/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *
 *  Author: Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
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

#include <opendht/http.h>
#include <opendht/dht_proxy_server.h>
#include <asio.hpp>

#include <thread>
#include <memory>

namespace test {

class HttpTester : public CppUnit::TestFixture {
    CPPUNIT_TEST_SUITE(HttpTester);
    // parse_url
    CPPUNIT_TEST(test_parse_url);
    CPPUNIT_TEST(test_parse_https_url_no_service);
    CPPUNIT_TEST(test_parse_url_no_prefix_no_target);
    CPPUNIT_TEST(test_parse_url_target);
    CPPUNIT_TEST(test_parse_url_query);
    CPPUNIT_TEST(test_parse_url_fragment);
    CPPUNIT_TEST(test_parse_url_ipv4);
    CPPUNIT_TEST(test_parse_url_no_prefix_no_target_ipv4);
    CPPUNIT_TEST(test_parse_url_target_ipv4);
    CPPUNIT_TEST(test_parse_url_ipv6);
    CPPUNIT_TEST(test_parse_url_no_prefix_no_target_ipv6);
    CPPUNIT_TEST(test_parse_url_target_ipv6);
    // send
    CPPUNIT_TEST(test_send_json);
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
     * Test parse urls
     */
   void test_parse_url();
   void test_parse_https_url_no_service();
   void test_parse_url_no_prefix_no_target();
   void test_parse_url_target();
   void test_parse_url_query();
   void test_parse_url_fragment();
    /**
     * Test parse urls (ipv4)
     */
   void test_parse_url_ipv4();
   void test_parse_url_no_prefix_no_target_ipv4();
   void test_parse_url_target_ipv4();
    /**
     * Test parse urls (ipv6)
     */
   void test_parse_url_ipv6();
   void test_parse_url_no_prefix_no_target_ipv6();
   void test_parse_url_target_ipv6();
    /**
     * Test send(json)
     */
   void test_send_json();

 private:
    std::shared_ptr<dht::DhtRunner> nodePeer;
    std::unique_ptr<dht::DhtProxyServer> serverProxy;
};

}  // namespace test
