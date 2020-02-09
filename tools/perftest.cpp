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
#include <condition_variable>
#include <mutex>
#include <atomic>

void print_usage() {
    std::cout << "Usage: perftest" << std::endl << std::endl;
    std::cout << "perftest, a simple OpenDHT basic performance tester." << std::endl;
    std::cout << "Report bugs to: https://opendht.net" << std::endl;
}
constexpr unsigned PINGPONG_MAX = 2048;
using namespace dht;

namespace tests {

using clock = std::chrono::high_resolution_clock;
using duration = clock::duration;

duration
benchPingPong(unsigned netSize, unsigned n_parallel) {
    DhtRunner::Config config {};
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;

    DhtRunner ping_node, pong_node;

    std::vector<std::pair<InfoHash, InfoHash>> locs;
    locs.reserve(n_parallel);
    for (unsigned i=0; i<n_parallel; i++) {
        auto loc_ping = InfoHash::get("toto" + std::to_string(i));
        locs.emplace_back(loc_ping, InfoHash::get(loc_ping.toString()));
    }

    ping_node.run(0, config);
    pong_node.run(0, config);
    auto bindAddr = ping_node.getBound();
    pong_node.bootstrap(bindAddr);

    std::vector<std::unique_ptr<DhtRunner>> nodes;
    nodes.reserve(netSize);
    for (unsigned i=0; i<netSize; i++) {
        auto node = std::make_unique<DhtRunner>();
        node->run(0, config);
        node->bootstrap(bindAddr);
        nodes.emplace_back(std::move(node));
    }

    // std::this_thread::sleep_for(std::chrono::seconds(1));

    std::condition_variable cv;
    unsigned i {0};
    std::mutex m;

    unsigned max = PINGPONG_MAX * n_parallel;

    auto ping = [&](DhtRunner& node, InfoHash h) {
        std::lock_guard<std::mutex> lk(m);
        if (i < max)  {
            i++;
            node.put(h, Value("hey"));
        }
        cv.notify_one();
    };

    for (unsigned i=0; i<n_parallel; i++)  {
        ping_node.listen(locs[i].first, [&,i](const std::shared_ptr<Value>&){
            ping(pong_node, locs[i].second);
            return true;
        });
        pong_node.listen(locs[i].second, [&,i](const std::shared_ptr<Value>&){
            ping(ping_node, locs[i].first);
            return true;
        });
    }

    auto start = clock::now();

    for (unsigned i=0; i<n_parallel; i++) 
        ping(pong_node, locs[i].first);

    {
        std::unique_lock<std::mutex> lk(m);
        if (not cv.wait_for(lk, std::chrono::minutes(1), [&](){ return i == max; })) {
            throw std::runtime_error(std::string("Timeout: ") + std::to_string(i));
        }
    }

    auto end = clock::now();

    for (auto& node : nodes)
        node->shutdown();
    ping_node.shutdown();
    pong_node.shutdown();

    for (auto& node : nodes)
        node->join();
    ping_node.join();
    pong_node.join();

    return end-start;
}

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

    duration totalTime {0};
    unsigned totalOps {0};

    for (unsigned nparallel = 1; nparallel <= 32; nparallel *= 2)  {
        unsigned max = PINGPONG_MAX * nparallel;
        std::vector<duration> results {};
        results.reserve(8);
        duration total {0};
        for (unsigned i=2; i<32; i *= 2) {
            auto dt = tests::benchPingPong(i - 2, nparallel);
            std::cout << "Network size: " << i << std::endl;
            std::cout << max << " ping-pong done, took " << print_duration(dt) << std::endl;
            std::cout << print_duration(dt/max) << " per rt, "
                    << max/std::chrono::duration<double>(dt).count() << " ping per s" << std::endl << std::endl;
            total += dt;
            totalOps += max;
            results.emplace_back(dt);
        }

        totalTime += total;

        std::cout << "Total for " << nparallel << std::endl;
        auto totNum = max*results.size();
        std::cout << totNum << " ping-pong done, took " << print_duration(total) << std::endl;
        std::cout << print_duration(total/totNum) << " per rt, "
                << totNum/std::chrono::duration<double>(total).count() << " ping per s" << std::endl << std::endl;
    }

    std::cout << std::endl << "Grand total: " << print_duration(totalTime) << " for " << totalOps << std::endl;
    std::cout << print_duration(totalTime/totalOps) << " per rt, "
            << totalOps/std::chrono::duration<double>(totalTime).count() << " ping per s" << std::endl << std::endl;

#ifdef WIN32_NATIVE
    gnutls_global_deinit();
#endif
    return 0;
}
