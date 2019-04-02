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

#include "peerdiscoverytester.h"

namespace test {

CPPUNIT_TEST_SUITE_REGISTRATION(PeerDiscoveryTester);

void PeerDiscoveryTester::setUp(){}

void PeerDiscoveryTester::testTransmission_ipv4(){

    // Node for getnode id
    dht::InfoHash data_n = dht::InfoHash::get("something");
    int port = 2222;
    int port_node = 50000;

    dht::PeerDiscovery test(AF_INET,port);

    std::thread t([&]{

        int received = test.discoveryOnce();
        CPPUNIT_ASSERT_MESSAGE("Port Receive Incorrect", received == port_node);

    });

    sleep(1);
    test.publishOnce(data_n,port_node);

    sleep(5);
    t.join();

}

void PeerDiscoveryTester::testTransmission_ipv6(){

    // Node for getnode id
    dht::InfoHash data_n = dht::InfoHash::get("something");
    const int port = 2223;
    int port_node = 50001;

    dht::PeerDiscovery test(AF_INET6,port);

    std::thread t([&]{

        int received = test.discoveryOnce();
        CPPUNIT_ASSERT_MESSAGE("Port Receive Incorrect", received == port_node);

    });

    sleep(1);
    test.publishOnce(data_n,port_node);

    sleep(5);
    t.join();

}

void PeerDiscoveryTester::tearDown(){}

}  // namespace test