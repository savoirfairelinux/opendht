/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *
 *  Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tools_common.h"
#include <opendht/node.h>

extern "C" {
#include <gnutls/gnutls.h>
}
#include <set>
#include <condition_variable>
#include <mutex>

using namespace dht;

void print_usage() {
    std::cout << "Usage: dhtscanner [-n network_id] [-p local_port] [-b bootstrap_host[:port]]" << std::endl << std::endl;
    std::cout << "dhtscanner, a simple OpenDHT command line utility generating scan result the network." << std::endl;
    std::cout << "Report bugs to: https://opendht.net" << std::endl;
}

struct snode_compare {
    bool operator() (const std::shared_ptr<Node>& lhs, const std::shared_ptr<Node>& rhs) const{
        return (lhs->id < rhs->id) ||
            (lhs->id == rhs->id && lhs->getFamily() == AF_INET && rhs->getFamily() == AF_INET6);
    }
};

using NodeSet = std::set<std::shared_ptr<Node>, snode_compare>;
std::condition_variable cv;

void
step(DhtRunner& dht, std::atomic_uint& done, std::shared_ptr<NodeSet> all_nodes, dht::InfoHash cur_h, unsigned cur_depth)
{
    std::cout << "step at " << cur_h << ", depth " << cur_depth << std::endl;
    done++;
    dht.get(cur_h, [all_nodes](const std::vector<std::shared_ptr<Value>>& /*values*/) {
        return true;
    }, [&,all_nodes,cur_h,cur_depth](bool, const std::vector<std::shared_ptr<Node>>& nodes) {
        all_nodes->insert(nodes.begin(), nodes.end());
        NodeSet sbuck {nodes.begin(), nodes.end()};
        if (not sbuck.empty()) {
            unsigned bdepth = sbuck.size()==1 ? 0u : InfoHash::commonBits((*sbuck.begin())->id, (*sbuck.rbegin())->id);
            unsigned target_depth = std::min(8u, bdepth+6u);
            std::cout << cur_h << " : " << nodes.size() << " nodes; target is " << target_depth << " bits deep (cur " << cur_depth << ")" << std::endl;
            for (unsigned b = cur_depth ; b < target_depth; b++) {
                auto new_h = cur_h;
                new_h.setBit(b, 1);
                step(dht, done, all_nodes, new_h, b+1);
            }
        }
        done--;
        std::cout << done.load() << " operations left, " << all_nodes->size() << " nodes found." << std::endl;
        cv.notify_one();
    });
}

int
main(int argc, char **argv)
{
#ifdef WIN32_NATIVE
    gnutls_global_init();
#endif
    auto params = parseArgs(argc, argv);
    if (params.help) {
        print_usage();
        return 0;
    }

    DhtRunner dht;
    try {
        auto dhtConf = getDhtConfig(params);
        dht.run(params.port, dhtConf.first, std::move(dhtConf.second));

        if (not params.bootstrap.empty())
            dht.bootstrap(params.bootstrap);

        print_node_info(dht.getNodeInfo());
        std::cout << "Scanning network..." << std::endl;
        auto all_nodes = std::make_shared<NodeSet>();

        // Set hash to 1 because 0 is the null hash
        dht::InfoHash cur_h {};
        cur_h.setBit(8*HASH_LEN-1, 1);

        std::this_thread::sleep_for(std::chrono::seconds(2));

        std::atomic_uint done {0};
        step(dht, done, all_nodes, cur_h, 0);

        {
            std::mutex m;
            std::unique_lock<std::mutex> lk(m);
            cv.wait(lk, [&](){
                return done.load() == 0;
            });
        }

        std::cout << std::endl << "Scan ended: " << all_nodes->size() << " nodes found." << std::endl;
        for (const auto& n : *all_nodes)
            std::cout << "Node " << *n << std::endl;
    } catch(const std::exception&e) {
        std::cerr << std::endl <<  e.what() << std::endl;
    }

    dht.join();
#ifdef WIN32_NATIVE
    gnutls_global_deinit();
#endif
    return 0;
}
