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
    dht::InfoHash data_n = dht::InfoHash::get("applepin");
    int port = 2222;
    in_port_t port_n = 50000;

    dht::PeerDiscovery test_n(AF_INET, port);
    dht::PeerDiscovery test_s(AF_INET, port);

    test_s.startDiscovery([&](const dht::InfoHash& node, const dht::SockAddr& addr){
        CPPUNIT_ASSERT_EQUAL(data_n, node);
        CPPUNIT_ASSERT_EQUAL(port_n, addr.getPort());
    });

    test_n.startPublish(data_n, port_n);

    sleep(5);
    test_n.stop();
    test_s.stop();
    test_n.join();
    test_s.join();
}

void PeerDiscoveryTester::testTransmission_ipv6(){

    // Node for getnode id
    dht::InfoHash data_n = dht::InfoHash::get("applepin");
    int port = 3333;
    in_port_t port_n = 50001;

    dht::PeerDiscovery test_n(AF_INET6,port);
    dht::PeerDiscovery test_s(AF_INET6,port);

    test_s.startDiscovery([&](const dht::InfoHash& node, const dht::SockAddr& addr){
        CPPUNIT_ASSERT_EQUAL(data_n, node);
        CPPUNIT_ASSERT_EQUAL(port_n, addr.getPort());
    });

    test_n.startPublish(data_n,port_n);

    sleep(5);
    test_n.stop();
    test_s.stop();
    test_n.join();
    test_s.join();

}

void PeerDiscoveryTester::tearDown(){}

}  // namespace test