/*
 *  Copyright (C) 2019 Savoir-faire Linux Inc.
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

#include "httptester.h"

// std
#include <iostream>
#include <string>

#include <chrono>
#include <condition_variable>


namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(HttpTester);

void
HttpTester::setUp() {
    logger = dht::log::getStdLogger();
}

void
HttpTester::tearDown() {
}

void
HttpTester::test_parse_url() {
    // Arrange
    std::string url = "http://google.com/";
    // Act
    dht::http::Url parsed (url);
    // Assert
    CPPUNIT_ASSERT(parsed.url == url);
    CPPUNIT_ASSERT(parsed.protocol == "http");
    CPPUNIT_ASSERT(parsed.host == "google.com");
    CPPUNIT_ASSERT(parsed.service == "80");
    CPPUNIT_ASSERT(parsed.target == "/");
}

void
HttpTester::test_parse_url_no_prefix_no_target() {
    // Arrange
    std::string url = "google.com";
    // Act
    dht::http::Url parsed (url);
    // Assert
    CPPUNIT_ASSERT(parsed.url == url);
    CPPUNIT_ASSERT(parsed.protocol == "http");
    CPPUNIT_ASSERT(parsed.host == "google.com");
    CPPUNIT_ASSERT(parsed.service == "80");
    CPPUNIT_ASSERT(parsed.target == "/");
}

void
HttpTester::test_parse_url_target() {
    // Arrange
    std::string url = "https://www.google.com:666/going/under";
    // Act
    dht::http::Url parsed (url);
    // Assert
    CPPUNIT_ASSERT(parsed.url == url);
    CPPUNIT_ASSERT(parsed.protocol == "https");
    CPPUNIT_ASSERT(parsed.host == "www.google.com");
    CPPUNIT_ASSERT(parsed.service == "666");
    CPPUNIT_ASSERT(parsed.target == "/going/under");
}

void
HttpTester::test_parse_url_query() {
    // Arrange
    std::string url = "http://google.com/?key=1";
    // Act
    dht::http::Url parsed (url);
    // Assert
    CPPUNIT_ASSERT(parsed.url == url);
    CPPUNIT_ASSERT(parsed.protocol == "http");
    CPPUNIT_ASSERT(parsed.host == "google.com");
    CPPUNIT_ASSERT(parsed.service == "80");
    CPPUNIT_ASSERT(parsed.target == "/");
    CPPUNIT_ASSERT(parsed.query == "key=1");
}

void
HttpTester::test_parse_url_ipv4() {
    // Arrange
    std::string url = "http://172.217.13.132/";
    // Act
    dht::http::Url parsed (url);
    // Assert
    CPPUNIT_ASSERT(parsed.url == url);
    CPPUNIT_ASSERT(parsed.protocol == "http");
    CPPUNIT_ASSERT(parsed.host == "172.217.13.132");
    CPPUNIT_ASSERT(parsed.service == "80");
    CPPUNIT_ASSERT(parsed.target == "/");
}

void
HttpTester::test_parse_url_no_prefix_no_target_ipv4() {
    // Arrange
    std::string url = "172.217.13.132";
    // Act
    dht::http::Url parsed (url);
    // Assert
    CPPUNIT_ASSERT(parsed.url == url);
    CPPUNIT_ASSERT(parsed.protocol == "http");
    CPPUNIT_ASSERT(parsed.host == "172.217.13.132");
    CPPUNIT_ASSERT(parsed.service == "80");
    CPPUNIT_ASSERT(parsed.target == "/");
}

void
HttpTester::test_parse_url_target_ipv4() {
    // Arrange
    std::string url = "https://172.217.13.132:666/going/under";
    // Act
    dht::http::Url parsed (url);
    // Assert
    CPPUNIT_ASSERT(parsed.url == url);
    CPPUNIT_ASSERT(parsed.protocol == "https");
    CPPUNIT_ASSERT(parsed.host == "172.217.13.132");
    CPPUNIT_ASSERT(parsed.service == "666");
    CPPUNIT_ASSERT(parsed.target == "/going/under");
}

void
HttpTester::test_parse_url_ipv6() {
    // Arrange
    std::string url = "http://[2607:f8b0:4006:804::2004]/";
    // Act
    dht::http::Url parsed (url);
    // Assert
    CPPUNIT_ASSERT(parsed.url == url);
    CPPUNIT_ASSERT(parsed.protocol == "http");
    CPPUNIT_ASSERT(parsed.host == "2607:f8b0:4006:804::2004");
    CPPUNIT_ASSERT(parsed.service == "80");
    CPPUNIT_ASSERT(parsed.target == "/");
}

void
HttpTester::test_parse_url_no_prefix_no_target_ipv6() {
    // Arrange
    std::string url = "2607:f8b0:4006:804::2004";
    // Act
    dht::http::Url parsed (url);
    // Assert
    CPPUNIT_ASSERT(parsed.url == url);
    CPPUNIT_ASSERT(parsed.protocol == "http");
    CPPUNIT_ASSERT(parsed.host == "2607:f8b0:4006:804::2004");
    CPPUNIT_ASSERT(parsed.service == "80");
    CPPUNIT_ASSERT(parsed.target == "/");
}

void
HttpTester::test_parse_url_target_ipv6() {
    // Arrange
    std::string url = "https://[2607:f8b0:4006:804::2004]:666/going/under";
    // Act
    dht::http::Url parsed (url);
    // Assert
    CPPUNIT_ASSERT(parsed.url == url);
    CPPUNIT_ASSERT(parsed.protocol == "https");
    CPPUNIT_ASSERT(parsed.host == "2607:f8b0:4006:804::2004");
    CPPUNIT_ASSERT(parsed.service == "666");
    CPPUNIT_ASSERT(parsed.target == "/going/under");
}

}  // namespace test
