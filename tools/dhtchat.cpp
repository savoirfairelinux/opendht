/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
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

#include <iostream>

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
    std::cout << "Report bugs to: http://opendht.net" << std::endl;
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
        dht.run(params.port, dht::crypto::generateIdentity("DHT Chat Node"), true, params.network);

        if (not params.bootstrap.first.empty())
            dht.bootstrap(params.bootstrap.first.c_str(), params.bootstrap.second.c_str());

        dht.startProxyInterface();

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

            static constexpr dht::InfoHash INVALID_ID {};

            std::istringstream iss(line);
            std::string op, idstr;
            iss >> op;
            if (not connected) {
                if (op  == "x" || op == "q" || op == "exit" || op == "quit")
                    break;
                else if (op == "c") {
                    iss >> idstr;
                    room = InfoHash(idstr);
                    if (room == INVALID_ID) {
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
                    auto value = std::make_shared<Value>( dht::ImMessage(rand_id(rd), std::move(line), now));

                    // TODO TEMP
                    auto valueStr = packMsg(value);
                    std::cout << std::endl;
                    for (const auto& v: valueStr) {
                        std::cout << "\\x" << std::hex << static_cast<int>(v);
                    }
                    std::cout << std::endl;

                    dht.putSigned(room, value, [](bool ok) {
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
