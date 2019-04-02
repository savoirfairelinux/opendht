/*
 *  Copyright (C) 2019 Savoir-faire Linux Inc.
 *
 *  Author: Mingrui Zhang <mingrui.zhang@savoirfairelinux.com>
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

#include "peerDiscoverytester.h"

namespace test {

CPPUNIT_TEST_SUITE_REGISTRATION(PeerDiscoveryTester);

void PeerDiscoveryTester::setUp(){}

void PeerDiscoveryTester::testTransmission_ipv4(){

    // Node for getnode id
    uint8_t *data_n = dht::InfoHash::get("something").data();

    char address_ipv4[10] = "224.0.0.1";
    const int delay_secs = 1;
    int port = 8080;
    char *add = address_ipv4;
    int port_node = 9999;

    dht::PeerDiscovery test_Sender(AF_INET,8080);
    dht::PeerDiscovery test_Listener(AF_INET,8080);

    std::thread t([&]{

        int received = test_Listener.listener_oneTimeShoot();
        CPPUNIT_ASSERT_MESSAGE("Port Receive Incorrect", received == port_node);

    });

    sleep(delay_secs);
    test_Sender.sender_oneTimeShoot(data_n,9999);

    sleep(5);
    t.join();

}

void PeerDiscoveryTester::testTransmission_ipv6(){

    // Node for getnode id
    uint8_t *data_n = dht::InfoHash::get("something").data();
    
    char address_ipv6[11] = "ff12::1234";
    const int delay_secs = 1;
    const int port = 8081;
    char *add = address_ipv6;
    int port_node = 10000;

    dht::PeerDiscovery test_Sender(AF_INET6,8080);
    dht::PeerDiscovery test_Listener(AF_INET6,8080);

    std::thread t([&]{

        int received = test_Listener.listener_oneTimeShoot();
        CPPUNIT_ASSERT_MESSAGE("Port Receive Incorrect", received == port_node);

    });

    sleep(delay_secs);
    test_Sender.sender_oneTimeShoot(data_n,10000);

    sleep(5);
    t.join();

}

void PeerDiscoveryTester::tearDown(){}

}  // namespace test