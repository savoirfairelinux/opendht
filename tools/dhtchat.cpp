/*
 *  Copyright (C) 2014-2019 Savoir-faire Linux Inc.
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

#include "tools_common.h"
#include <opendht/rng.h>

extern "C" {
#include <gnutls/gnutls.h>
}
#include <ctime>

using namespace dht;

static std::mt19937_64 rd {dht::crypto::random_device{}()};
static std::uniform_int_distribution<dht::Value::Id> rand_id;

const std::string printTime(const std::time_t& now) {
    struct tm tstruct = *localtime(&now);
    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return buf;
}

void print_node_info(const DhtRunner& dht, const dht_params&) {
    std::cout << "OpenDht node " << dht.getNodeId() << " running on port " <<  dht.getBoundPort() << std::endl;
    std::cout << "Public key ID " << dht.getId() << std::endl;
}

void print_usage() {
    std::cout << "Usage: dhtchat [-n network_id] [-p local_port] [-b bootstrap_host[:port]]" << std::endl << std::endl;
    std::cout << "dhtchat, a simple OpenDHT command line chat client." << std::endl;
    std::cout << "Report bugs to: https://opendht.net" << std::endl;
}

int
main(int argc, char **argv)
{
    auto params = parseArgs(argc, argv);
    if (params.help) {
        print_usage();
        return 0;
    }
#ifdef WIN32_NATIVE
    gnutls_global_init();
#endif

    DhtRunner dht;
    try {
        if (not params.id.first) {
            auto node_ca = std::make_unique<dht::crypto::Identity>(dht::crypto::generateEcIdentity("DHT Node CA"));
            params.id = dht::crypto::generateIdentity("DHT Chat Node", *node_ca);
            if (not params.save_identity.empty()) {
                dht::crypto::saveIdentity(*node_ca, params.save_identity + "_ca", params.privkey_pwd);
                dht::crypto::saveIdentity(params.id, params.save_identity, params.privkey_pwd);
            }
        }

        dht::DhtRunner::Config config {};
        config.dht_config.node_config.network = params.network;
        config.dht_config.node_config.maintain_storage = false;
        config.dht_config.node_config.persist_path = params.persist_path;
        config.dht_config.id = params.id;
        config.threaded = true;
        config.proxy_server = params.proxyclient;
        config.push_node_id = "dhtnode";
        config.push_token = params.devicekey;
        config.peer_discovery = params.peer_discovery;
        config.peer_publish = params.peer_discovery;

        dht::DhtRunner::Context context {};
        if (params.log) {
            if (params.syslog or (params.daemonize and params.logfile.empty()))
                context.logger = log::getSyslogLogger("dhtnode");
            else if (not params.logfile.empty())
                context.logger = log::getFileLogger(params.logfile);
            else
                context.logger = log::getStdLogger();
        }
        dht.run(params.port, config, std::move(context));

        if (not params.bootstrap.first.empty())
            dht.bootstrap(params.bootstrap.first.c_str(), params.bootstrap.second.c_str());

#ifdef OPENDHT_PROXY_CLIENT
    if (!params.proxyclient.empty()) {
        dht.setProxyServer(params.proxyclient);
        dht.enableProxy(true);
    }
#endif //OPENDHT_PROXY_CLIENT

        print_node_info(dht, params);
        std::cout << "  type 'c {hash}' to join a channel" << std::endl << std::endl;

        bool connected {false};
        InfoHash room;
        const InfoHash myid = dht.getId();

#ifndef WIN32_NATIVE
        // using the GNU History API
        using_history();
#endif

        while (true)
        {
            // using the GNU Readline API
            std::string line = readLine(connected ? PROMPT : "> ");
            if (!line.empty() && line[0] == '\0')
                break;
            if (line.empty())
                continue;

            std::istringstream iss(line);
            std::string op, idstr;
            iss >> op;
            if (not connected) {
                if (op  == "x" || op == "q" || op == "exit" || op == "quit")
                    break;
                else if (op == "c") {
                    iss >> idstr;
                    room = InfoHash(idstr);
                    if (not room) {
                        room = InfoHash::get(idstr);
                        std::cout << "Joining h(" << idstr << ") = " << room << std::endl;
                    }

                    dht.listen<dht::ImMessage>(room, [&](dht::ImMessage&& msg) {
                        if (msg.from != myid)
                            std::cout << msg.from.toString() << " at " << printTime(msg.date)
                                      << " (took " << print_dt(std::chrono::system_clock::now() - std::chrono::system_clock::from_time_t(msg.date))
                                      << "s) " << (msg.to == myid ? "ENCRYPTED ":"") << ": " << msg.id << " - " << msg.msg << std::endl;
                        return true;
                    });
                    connected = true;
                } else {
                    std::cout << "Unknown command. Type 'c {hash}' to join a channel" << std::endl << std::endl;
                }
            } else {
                auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                if (op == "d") {
                    connected = false;
                    continue;
                } else if (op == "e") {
                    iss >> idstr;
                    std::getline(iss, line);
                    dht.putEncrypted(room, InfoHash(idstr), dht::ImMessage(rand_id(rd), std::move(line), now), [](bool ok) {
                        //dht.cancelPut(room, id);
                        if (not ok)
                            std::cout << "Message publishing failed !" << std::endl;
                    });
                } else {
                    dht.putSigned(room, dht::ImMessage(rand_id(rd), std::move(line), now), [](bool ok) {
                        //dht.cancelPut(room, id);
                        if (not ok)
                            std::cout << "Message publishing failed !" << std::endl;
                    });
                }
            }
        }
    } catch(const std::exception&e) {
        std::cerr << std::endl <<  e.what() << std::endl;
    }

    std::cout << std::endl <<  "Stopping node..." << std::endl;
    dht.join();
#ifdef WIN32_NATIVE
    gnutls_global_deinit();
#endif
    return 0;
}
