// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tools_common.h"
#include <opendht/node.h>
#include <fmt/format.h>

extern "C" {
#include <gnutls/gnutls.h>
}
#include <set>
#include <condition_variable>
#include <mutex>

using namespace dht;

void
print_usage()
{
    fmt::print("Usage: dhtscanner [-n network_id] [-p local_port] [-b bootstrap_host[:port]]\n"
               "dhtscanner: a simple OpenDHT command line utility generating scan result the network.\n"
               "Report bugs to: https://opendht.net\n");
}

struct snode_compare
{
    bool operator()(const std::shared_ptr<Node>& lhs, const std::shared_ptr<Node>& rhs) const
    {
        return (lhs->id < rhs->id)
               || (lhs->id == rhs->id && lhs->getFamily() == AF_INET && rhs->getFamily() == AF_INET6);
    }
};

using NodeSet = std::set<std::shared_ptr<Node>, snode_compare>;
std::condition_variable cv;

void
step(DhtRunner& dht, std::atomic_uint& done, std::shared_ptr<NodeSet> all_nodes, dht::InfoHash cur_h, unsigned cur_depth)
{
    fmt::print("step at {}, depth {}\n", cur_h.to_view(), cur_depth);
    done++;
    dht.get(
        cur_h,
        [](const std::vector<std::shared_ptr<Value>>& /*values*/) { return true; },
        [&,
         all_nodes,
         cur_h,
         cur_depth,
         start_time = std::chrono::steady_clock::now()](bool ok, const std::vector<std::shared_ptr<Node>>& nodes) {
            auto took = std::chrono::steady_clock::now() - start_time;
            if (not ok) {
                fmt::print("Error while getting nodes for hash {} after {}\n",
                           cur_h.to_view(),
                           dht::print_duration(took));
            }
            all_nodes->insert(nodes.begin(), nodes.end());
            NodeSet sbuck {nodes.begin(), nodes.end()};
            if (not sbuck.empty()) {
                unsigned bdepth = sbuck.size() == 1 ? 0u
                                                    : InfoHash::commonBits((*sbuck.begin())->id, (*sbuck.rbegin())->id);
                unsigned target_depth = std::min(8u, bdepth + 6u);
                fmt::print("Found {} nodes for hash {}, target depth is {}\n",
                           nodes.size(),
                           cur_h.to_view(),
                           target_depth);
                for (unsigned b = cur_depth; b < target_depth; b++) {
                    auto new_h = cur_h;
                    new_h.setBit(b, 1);
                    step(dht, done, all_nodes, new_h, b + 1);
                }
            }
            done--;
            fmt::print("Step for {} ended after {}. Ongoing operations: {}. Total nodes: {}\n",
                       cur_h.to_view(),
                       dht::print_duration(took),
                       done.load(),
                       all_nodes->size());
            cv.notify_one();
        });
}

int
main(int argc, char** argv)
{
#ifdef _MSC_VER
    if (auto err = gnutls_global_init()) {
        fmt::print(stderr, "Failed to initialize GnuTLS: {}\n", gnutls_strerror(err));
        return EXIT_FAILURE;
    }
#endif
    auto params = parseArgs(argc, argv);
    if (params.help) {
        print_usage();
        return EXIT_SUCCESS;
    }

    DhtRunner dht;
    try {
        auto [config, context] = getDhtConfig(params);
        config.dht_config.node_config.client_mode = true;
        dht.run(params.port, config, std::move(context));

        if (not params.bootstrap.empty())
            dht.bootstrap(params.bootstrap);

        print_node_info(dht.getNodeInfo());
        fmt::print("Scanning network {} on port {}\n", params.network, dht.getBoundPort());
        auto all_nodes = std::make_shared<NodeSet>();

        // Set hash to 1 because 0 is the null hash
        dht::InfoHash cur_h {};
        cur_h.setBit(8 * HASH_LEN - 1, 1);

        std::this_thread::sleep_for(std::chrono::seconds(2));

        std::atomic_uint done {0};
        step(dht, done, all_nodes, cur_h, 0);

        {
            std::mutex m;
            std::unique_lock<std::mutex> lk(m);
            cv.wait(lk, [&]() { return done.load() == 0; });
        }

        fmt::print("Scan ended: {} nodes found.\n", all_nodes->size());
        for (const auto& n : *all_nodes)
            fmt::print("Node {}: {}\n", n->id.to_view(), n->getAddrStr());
    } catch (const std::exception& e) {
        fmt::print(stderr, "\n{}\n", e.what());
    }

    dht.join();
#ifdef _MSC_VER
    gnutls_global_deinit();
#endif
    return EXIT_SUCCESS;
}
