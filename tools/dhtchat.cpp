// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tools_common.h"
#include <opendht/rng.h>

extern "C" {
#include <gnutls/gnutls.h>
}
#include <ctime>

namespace dht {
namespace tools {

static std::mt19937_64 rd {dht::crypto::getSeededRandomEngine<std::mt19937_64>()};

const std::string
printTime(const std::time_t& now)
{
    struct tm tstruct = *localtime(&now);
    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return buf;
}

void
print_usage()
{
    std::cout << "Usage: dhtchat [-n network_id] [-p local_port] [-b bootstrap_host[:port]]" << std::endl << std::endl;
    std::cout << "dhtchat, a simple OpenDHT command line chat client." << std::endl;
    std::cout << "Report bugs to: https://opendht.net" << std::endl;
}

} // namespace tools
} // namespace dht

int
main(int argc, char** argv)
{
    using namespace dht;
    using IdDist = std::uniform_int_distribution<dht::Value::Id>;

    auto params = tools::parseArgs(argc, argv);
    if (params.help) {
        tools::print_usage();
        return 0;
    }
#ifdef _MSC_VER
    if (auto err = gnutls_global_init()) {
        std::cerr << "Failed to initialize GnuTLS: " << gnutls_strerror(err) << std::endl;
        return EXIT_FAILURE;
    }
#endif

    DhtRunner dht;
    try {
        params.generate_identity = true;
        auto dhtConf = getDhtConfig(params);
        dht.run(params.port, dhtConf.first, std::move(dhtConf.second));

        if (not params.bootstrap.empty())
            dht.bootstrap(params.bootstrap);

        tools::print_node_info(dht.getNodeInfo());
        std::cout << "  type 'c {hash}' to join a channel" << std::endl << std::endl;

        bool connected {false};
        InfoHash room;
        std::future<size_t> token;

        const auto mypk = dht.getPublicKey();

#ifndef _MSC_VER
        // using the GNU History API
        using_history();
#endif

        while (true) {
            // using the GNU Readline API
            std::string line = tools::readLine(connected ? tools::PROMPT : "> ");
            if (!line.empty() && line[0] == '\0')
                break;
            if (line.empty())
                continue;

            std::istringstream iss(line);
            std::string op, idstr;
            iss >> op;
            if (not connected) {
                if (op == "x" || op == "q" || op == "exit" || op == "quit")
                    break;
                else if (op == "c") {
                    iss >> idstr;
                    room = InfoHash(idstr);
                    if (not room) {
                        room = InfoHash::get(idstr);
                        std::cout << "Joining h(" << idstr << ") = " << room << std::endl;
                    }

                    token = dht.listen<dht::ImMessage>(room, [&](dht::ImMessage&& msg) {
                        if (msg.owner && msg.owner->getLongId() != mypk->getLongId())
                            std::cout << msg.from.toString() << " at " << tools::printTime(msg.date) << " (took "
                                      << print_duration(std::chrono::system_clock::now()
                                                        - std::chrono::system_clock::from_time_t(msg.date))
                                      << ") " << (msg.to == mypk->getId() ? "ENCRYPTED " : "") << ": " << msg.id
                                      << " - " << msg.msg << std::endl;
                        return true;
                    });
                    connected = true;
                } else {
                    std::cout << "Unknown command. Type 'c {hash}' to join a channel" << std::endl << std::endl;
                }
            } else {
                auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                if (op == "d") {
                    dht.cancelListen(room, std::move(token));
                    connected = false;
                    continue;
                } else if (op == "e") {
                    iss >> idstr;
                    std::getline(iss, line);
                    dht.putEncrypted(room,
                                     InfoHash(idstr),
                                     dht::ImMessage(IdDist()(tools::rd), std::move(line), now),
                                     [](bool ok) {
                                         // dht.cancelPut(room, id);
                                         if (not ok)
                                             std::cout << "Message publishing failed !" << std::endl;
                                     });
                } else {
                    dht.putSigned(room, dht::ImMessage(IdDist()(tools::rd), std::move(line), now), [](bool ok) {
                        // dht.cancelPut(room, id);
                        if (not ok)
                            std::cout << "Message publishing failed !" << std::endl;
                    });
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << std::endl << e.what() << std::endl;
    }

    std::cout << std::endl << "Stopping node..." << std::endl;
    dht.join();
#ifdef _MSC_VER
    gnutls_global_deinit();
#endif
    return 0;
}
