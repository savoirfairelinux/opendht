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
#include "opendht/dhtrunner.h"

namespace test {

class NodeInsertion{
public:
    dht::InfoHash nodeid_;
    in_port_t node_port_;
    dht::NetId nid_;
    MSGPACK_DEFINE(nodeid_, node_port_, nid_)
};

CPPUNIT_TEST_SUITE_REGISTRATION(PeerDiscoveryTester);

void PeerDiscoveryTester::setUp(){}

void PeerDiscoveryTester::testTransmission_ipv4(){

    // Node for getnode id
    const std::string type {"dht"};
    dht::InfoHash data_n = dht::InfoHash::get("applepin");
    int port = 2222;
    in_port_t port_n = 50000;
    dht::NetId netid = 10;
    msgpack::sbuffer sbuf;
    NodeInsertion adc;
    adc.nid_ = 10;
    adc.node_port_ = port_n;
    adc.nodeid_ = data_n;
    msgpack::pack(sbuf,adc);
    try{
        dht::PeerDiscovery test_n(AF_INET, port);
        dht::PeerDiscovery test_s(AF_INET, port);
        try{
            test_s.startDiscovery(type,[&](msgpack::object&& obj, dht::SockAddr& add){
                auto v = obj.as<NodeInsertion>();
                CPPUNIT_ASSERT_EQUAL(v.node_port_, port_n);
                CPPUNIT_ASSERT_EQUAL(v.nodeid_, data_n);
            });

            test_n.startPublish(type, sbuf);

            std::this_thread::sleep_for(std::chrono::seconds(5));
            test_n.stop();
            test_s.stop();
            test_n.join();
            test_s.join();
        } catch(std::exception &exception){
            perror(exception.what());
            CPPUNIT_ASSERT(false);
        }
    } catch(std::exception &exception){
            perror(exception.what());
    }
}

void PeerDiscoveryTester::testTransmission_ipv6(){

    // Node for getnode id
    const std::string type {"dht"};
    dht::InfoHash data_n = dht::InfoHash::get("applepin");
    int port = 2222;
    in_port_t port_n = 50000;
    dht::NetId netid = 10;
    msgpack::sbuffer sbuf;
    NodeInsertion adc;
    adc.nid_ = 10;
    adc.node_port_ = port_n;
    adc.nodeid_ = data_n;
    msgpack::pack(sbuf,adc);
    try{
        dht::PeerDiscovery test_n(AF_INET6, port);
        dht::PeerDiscovery test_s(AF_INET6, port);
        try{
            test_s.startDiscovery(type,[&](msgpack::object&& obj, dht::SockAddr& add){
                auto v = obj.as<NodeInsertion>();
                CPPUNIT_ASSERT_EQUAL(v.node_port_, port_n);
                CPPUNIT_ASSERT_EQUAL(v.nodeid_, data_n);
            });

            test_n.startPublish(type, sbuf);

            std::this_thread::sleep_for(std::chrono::seconds(5));
            test_n.stop();
            test_s.stop();
            test_n.join();
            test_s.join();
        } catch(std::exception &exception){
            perror(exception.what());
            CPPUNIT_ASSERT(false);
        }
    } catch(std::exception &exception){
            perror(exception.what());
    }
}

void PeerDiscoveryTester::tearDown(){}

}  // namespace test