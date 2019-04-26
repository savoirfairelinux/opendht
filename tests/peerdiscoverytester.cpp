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
#include "opendht/value.h"

namespace test {

struct NodeInsertion {
    dht::InfoHash nodeid;
    in_port_t node_port;
    dht::NetId nid;
    MSGPACK_DEFINE(nodeid, node_port, nid)
};

struct TestPack {
    int num;
    char cha;
    std::string str;
    MSGPACK_DEFINE(num, cha, str)
};

CPPUNIT_TEST_SUITE_REGISTRATION(PeerDiscoveryTester);

void PeerDiscoveryTester::setUp(){}

void PeerDiscoveryTester::testTransmission()
{
    // Node for getnode id
    const std::string type {"dht"};
    const std::string test_type {"pdd"};
    constexpr int MULTICAST_PORT = 2222;

    NodeInsertion adc;
    adc.nid = 10;
    adc.node_port = 50000;
    adc.nodeid = dht::InfoHash::get("applepin");

    TestPack pdd;
    pdd.num = 100;
    pdd.cha = 'a';
    pdd.str = "apple";

    dht::PeerDiscovery test_n(MULTICAST_PORT);
    dht::PeerDiscovery test_s(MULTICAST_PORT);

    std::mutex lock;
    std::condition_variable cv;
    std::unique_lock<std::mutex> l(lock);
    unsigned count_node {0};
    unsigned count_test {0};

    test_s.startDiscovery<NodeInsertion>(type,[&](NodeInsertion&& v, dht::SockAddr&& add){
        CPPUNIT_ASSERT_EQUAL(v.node_port, adc.node_port);
        CPPUNIT_ASSERT_EQUAL(v.nodeid, adc.nodeid);
        CPPUNIT_ASSERT_EQUAL(v.nid, adc.nid);
        {
            std::lock_guard<std::mutex> l(lock);
            count_node++;
        }
        cv.notify_all();
    });

    test_s.startDiscovery(test_type,[&](msgpack::object&& obj, dht::SockAddr&& add){
        auto v = obj.as<TestPack>();
        CPPUNIT_ASSERT_EQUAL(v.num, pdd.num);
        CPPUNIT_ASSERT_EQUAL(v.cha, pdd.cha);
        CPPUNIT_ASSERT_EQUAL(v.str, pdd.str);
        {
            std::lock_guard<std::mutex> l(lock);
            count_test++;
        }
        cv.notify_all();
    });

    test_n.startPublish(type, adc);
    CPPUNIT_ASSERT(cv.wait_for(l, std::chrono::seconds(5), [&]{
        return count_node > 0;
    }));

    test_n.startPublish(test_type, pdd);
    CPPUNIT_ASSERT(cv.wait_for(l, std::chrono::seconds(5), [&]{
        return count_node > 1 and count_test > 0;
    }));
    l.unlock();

    test_n.stopPublish(type);
    test_n.stopPublish(test_type);
    test_n.stopDiscovery(type);
    test_n.stopDiscovery(test_type);
}

void PeerDiscoveryTester::tearDown(){}

}  // namespace test