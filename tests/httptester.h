// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
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

class HttpTester : public CppUnit::TestFixture
{
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
    CPPUNIT_TEST(test_parse_url_user_pass);
    CPPUNIT_TEST(test_parse_url_user_only);
    CPPUNIT_TEST(test_parse_url_ipv6_brackets);
    CPPUNIT_TEST(test_parse_url_ipv6_brackets_port);
    CPPUNIT_TEST(test_parse_url_mixed_case_protocol);
    CPPUNIT_TEST(test_parse_url_complex_path_query_fragment);
    CPPUNIT_TEST(test_parse_url_empty);
    CPPUNIT_TEST(test_parse_url_just_slash);
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
    void test_parse_url_user_pass();
    void test_parse_url_user_only();
    void test_parse_url_ipv6_brackets();
    void test_parse_url_ipv6_brackets_port();
    void test_parse_url_mixed_case_protocol();
    void test_parse_url_complex_path_query_fragment();
    void test_parse_url_empty();
    void test_parse_url_just_slash();
    /**
     * Test send(json)
     */
    void test_send_json();

private:
    std::shared_ptr<dht::DhtRunner> nodePeer;
    std::unique_ptr<dht::DhtProxyServer> serverProxy;
};

} // namespace test
