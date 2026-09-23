// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_peerdiscovery.h"

#include <mutex>
#include <condition_variable>

namespace test {

using namespace std::literals;

constexpr dht::NetId NETWORK_ID = 10;
constexpr in_port_t NODE_PORT = 50000;

CPPUNIT_TEST_SUITE_REGISTRATION(PeerDiscoveryTester);

void
PeerDiscoveryTester::setUp()
{}

void
PeerDiscoveryTester::testMulticastToTwoNodes()
{
    const auto nodeId = dht::InfoHash::get("opendht01");

    std::mutex lock;
    std::condition_variable cv;
    unsigned discovered {0};
    unsigned wrongNetwork {0};
    {
        std::unique_lock l(lock);
        dht::PeerDiscovery publisher;
        dht::PeerDiscovery browser;
        dht::PeerDiscovery otherNetworkBrowser;

        browser.startDiscovery(NETWORK_ID, [&](const dht::InfoHash& peerId, dht::SockAddr&& address) {
            CPPUNIT_ASSERT_EQUAL(nodeId, peerId);
            CPPUNIT_ASSERT_EQUAL(NODE_PORT, address.getPort());
            {
                std::lock_guard l(lock);
                discovered++;
            }
            cv.notify_all();
        });
        otherNetworkBrowser.startDiscovery(NETWORK_ID + 1, [&](const dht::InfoHash&, dht::SockAddr&&) {
            std::lock_guard l(lock);
            wrongNetwork++;
        });

        publisher.startPublish(nodeId, NETWORK_ID, NODE_PORT);
        CPPUNIT_ASSERT(cv.wait_for(l, std::chrono::seconds(5), [&] { return discovered > 0; }));
        CPPUNIT_ASSERT_EQUAL(0u, wrongNetwork);

        l.unlock();
        publisher.stopPublish();
        browser.stopDiscovery();
        otherNetworkBrowser.stopDiscovery();
    }
}

void
PeerDiscoveryTester::tearDown()
{}

} // namespace test
