/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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

#include <mutex>
#include <condition_variable>

namespace test {

constexpr unsigned MULTICAST_PORT = 2222;
const std::string DHT_NODE_NAME {"dht"};
const std::string JAMI_NODE_NAME {"jami"};

struct DhtNode {
    dht::InfoHash nodeid;
    in_port_t node_port;
    dht::NetId nid;
    MSGPACK_DEFINE(nodeid, node_port, nid)
};
struct JamiNode {
    int num;
    char cha;
    std::string str;
    MSGPACK_DEFINE(num, cha, str)
};

CPPUNIT_TEST_SUITE_REGISTRATION(PeerDiscoveryTester);

void PeerDiscoveryTester::setUp(){}

void PeerDiscoveryTester::testMulticastToTwoNodes()
{
    DhtNode dhtNode;
    dhtNode.nid = 10;
    dhtNode.node_port = 50000;
    dhtNode.nodeid = dht::InfoHash::get("opendht01");

    JamiNode jamiNode;
    jamiNode.num = 100;
    jamiNode.cha = 'a';
    jamiNode.str = "jami01";

    std::mutex lock;
    std::condition_variable cv;
    unsigned countDht {0};
    unsigned countJami {0};
    {
        std::unique_lock<std::mutex> l(lock);
        dht::PeerDiscovery testDht(MULTICAST_PORT);
        dht::PeerDiscovery testJami(MULTICAST_PORT);

        testJami.startDiscovery<DhtNode>(DHT_NODE_NAME,[&](DhtNode&& v, dht::SockAddr&&){
            CPPUNIT_ASSERT_EQUAL(dhtNode.node_port, v.node_port);
            CPPUNIT_ASSERT_EQUAL(dhtNode.nodeid, v.nodeid);
            CPPUNIT_ASSERT_EQUAL(dhtNode.nid, v.nid);
            {
                std::lock_guard<std::mutex> l(lock);
                countDht++;
            }
            cv.notify_all();
        });

        testJami.startDiscovery(JAMI_NODE_NAME,[&](msgpack::object&& obj, dht::SockAddr&&){
            auto v = obj.as<JamiNode>();
            CPPUNIT_ASSERT_EQUAL(jamiNode.num, v.num);
            CPPUNIT_ASSERT_EQUAL(jamiNode.cha, v.cha);
            CPPUNIT_ASSERT_EQUAL(jamiNode.str, v.str);
            {
                std::lock_guard<std::mutex> l(lock);
                countJami++;
            }
            cv.notify_all();
        });

        testDht.startPublish(DHT_NODE_NAME, dhtNode);
        CPPUNIT_ASSERT(cv.wait_for(l, std::chrono::seconds(5), [&]{
            return countDht > 0;
        }));

        testDht.startPublish(JAMI_NODE_NAME, jamiNode);
        CPPUNIT_ASSERT(cv.wait_for(l, std::chrono::seconds(5), [&]{
            return countDht > 1 and countJami > 0;
        }));
        // we don't verify count values since its a continious multicasting

        l.unlock();
        testDht.stopPublish(DHT_NODE_NAME);
        testDht.stopPublish(JAMI_NODE_NAME);
        testJami.stopDiscovery(DHT_NODE_NAME);
        testJami.stopDiscovery(JAMI_NODE_NAME);
    }
}

void PeerDiscoveryTester::tearDown(){}

}  // namespace test
