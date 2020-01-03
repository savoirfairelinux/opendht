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

#include "httptester.h"

#include <opendht/value.h>
#include <opendht/dhtrunner.h>

#include <iostream>
#include <string>
#include <chrono>
#include <condition_variable>

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(HttpTester);

void
HttpTester::setUp() {
    nodePeer = std::make_shared<dht::DhtRunner>();
    nodePeer->run(0);

    auto nodeProxy = std::make_shared<dht::DhtRunner>();
    nodeProxy->run(0, /*identity*/{}, /*threaded*/true);
    nodeProxy->bootstrap(nodePeer->getBound());

    serverProxy = std::unique_ptr<dht::DhtProxyServer>(
        new dht::DhtProxyServer(
            /*http*/dht::crypto::Identity{}, nodeProxy, 8080, /*pushServer*/"127.0.0.1:8090"));
}

void
HttpTester::tearDown() {
    serverProxy.reset();
    nodePeer->join();
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
HttpTester::test_parse_https_url_no_service() {
    // Arrange
    std::string url = "https://jami.net/";
    // Act
    dht::http::Url parsed (url);
    // Assert
    CPPUNIT_ASSERT(parsed.url == url);
    CPPUNIT_ASSERT(parsed.protocol == "https");
    CPPUNIT_ASSERT(parsed.host == "jami.net");
    CPPUNIT_ASSERT(parsed.service == "https");
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
    CPPUNIT_ASSERT(parsed.target == "/?key=1");
    CPPUNIT_ASSERT(parsed.query == "key=1");
}

void
HttpTester::test_parse_url_fragment() {
    // Arrange
    std::string url = "http://google.com/?key=1#some-important-id";
    // Act
    dht::http::Url parsed (url);
    // Assert
    CPPUNIT_ASSERT(parsed.url == url);
    CPPUNIT_ASSERT(parsed.protocol == "http");
    CPPUNIT_ASSERT(parsed.host == "google.com");
    CPPUNIT_ASSERT(parsed.service == "80");
    CPPUNIT_ASSERT(parsed.target == "/?key=1");
    CPPUNIT_ASSERT(parsed.query == "key=1");
    CPPUNIT_ASSERT(parsed.fragment == "#some-important-id");
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

void
HttpTester::test_send_json() {
    // Arrange
    std::condition_variable cv;
    std::mutex cv_m;
    std::unique_lock<std::mutex> lk(cv_m);
    bool done = false;
    unsigned int status = 0;

    auto json = dht::Value("hey").toJson();
    Json::Value resp_val;

    // Act
    auto request = std::make_shared<dht::http::Request>(serverProxy->io_context(), 
        "http://127.0.0.1:8080/key",
        json,
        [&](Json::Value value, unsigned int status_code) {
            std::lock_guard<std::mutex> lk(cv_m);
            resp_val = std::move(value);
            status = status_code;
            done = true;
            cv.notify_all();
        });
    request->send();

    // Assert
    CPPUNIT_ASSERT(cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; }));
    CPPUNIT_ASSERT_EQUAL(200u, status);
    CPPUNIT_ASSERT_EQUAL(json["data"].asString(), resp_val["data"].asString());
    done = false;

#if 0
    request = std::make_shared<dht::http::Request>(serverProxy->io_context(),
        "http://google.ca",
        [&](const dht::http::Response& response) {
            std::lock_guard<std::mutex> lk(cv_m);
            status = response.status_code;
            done = true;
            cv.notify_all();
        });
    request->send();

    CPPUNIT_ASSERT(cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; }));
    CPPUNIT_ASSERT(status != 0);
    done = false;

    request = std::make_shared<dht::http::Request>(serverProxy->io_context(),
        "https://google.ca",
        [&](const dht::http::Response& response) {
            std::lock_guard<std::mutex> lk(cv_m);
            status = response.status_code;
            done = true;
            cv.notify_all();
        });
    request->send();

    CPPUNIT_ASSERT(cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; }));
    CPPUNIT_ASSERT(status != 0);
    done = false;

    request = std::make_shared<dht::http::Request>(serverProxy->io_context(),
        "https://google.ca/sdbjklwGBIP",
        [&](const dht::http::Response& response) {
            std::lock_guard<std::mutex> lk(cv_m);
            status = response.status_code;
            done = true;
            cv.notify_all();
        });
    request->send();

    CPPUNIT_ASSERT(cv.wait_for(lk, std::chrono::seconds(10), [&]{ return done; }));
    CPPUNIT_ASSERT_EQUAL(404u, status);
#endif
}

}  // namespace test
