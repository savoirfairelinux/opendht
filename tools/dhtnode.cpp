/*
 *  Copyright (C) 2014-2016 Savoir-faire Linux Inc.
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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.
 */

#include "tools_common.h"
extern "C" {
#include <gnutls/gnutls.h>
}

#include <set>
#include <thread> // std::this_thread::sleep_for

using namespace dht;

void print_usage() {
    std::cout << "Usage: dhtnode [-v[logfile]] [-i] [-d] [-n network_id] [-p local_port] [-b[bootstrap_host[:port]]]" << std::endl << std::endl;
    std::cout << "dhtnode, a simple OpenDHT command line node runner." << std::endl;
    std::cout << "Report bugs to: http://opendht.net" << std::endl;
}

void print_id_req() {
    std::cout << "An identity is required to perform this operation (run with -i)" << std::endl;
}

void print_node_info(const DhtRunner& dht, const dht_params& params) {
    std::cout << "OpenDht node " << dht.getNodeId() << " running on port " <<  dht.getBoundPort() << std::endl;
    if (params.is_bootstrap_node)
        std::cout << "Running in bootstrap mode (discouraged)." << std::endl;
    if (params.generate_identity)
        std::cout << "Public key ID " << dht.getId() << std::endl;
}

void print_help() {
    std::cout << "OpenDht command line interface (CLI)" << std::endl;
    std::cout << "Possible commands:" << std::endl
              << "  h, help    Print this help message." << std::endl
              << "  q, quit    Quit the program." << std::endl
              << "  log        Start/stop printing DHT logs." << std::endl;

    std::cout << std::endl << "Node information:" << std::endl
              << "  ll         Print basic information and stats about the current node." << std::endl
              << "  ls         Print basic information about current searches." << std::endl
              << "  ld         Print basic information about currenty stored values on this node." << std::endl
              << "  lr         Print the full current routing table of this node" << std::endl;

    std::cout << std::endl << "Operations on the DHT:" << std::endl
              << "  b ip:port             Ping potential node at given IP address/port." << std::endl
              << "  g [key]               Get values at [key]." << std::endl
              << "  l [key]               Listen for value changes at [key]." << std::endl
              << "  p [key] [str]         Put string value at [key]." << std::endl
              << "  s [key] [str]         Put string value at [key], signed with our generated private key." << std::endl
              << "  e [key] [dest] [str]  Put string value at [key], encrypted for [dest] with its public key (if found)." << std::endl
              << std::endl;
}

void cmd_loop(DhtRunner& dht, dht_params& params)
{
    print_node_info(dht, params);
    std::cout << " (type 'h' or 'help' for a list of possible commands)" << std::endl << std::endl;

    // using the GNU History API
    using_history();

    while (true)
    {
        // using the GNU Readline API
        std::string line = readLine();
        if (!line.empty() && line[0] == '\0')
            break;

        std::istringstream iss(line);
        std::string op, idstr, value;
        iss >> op >> idstr;

        if (op == "x" || op == "q" || op == "exit" || op == "quit") {
            break;
        } else if (op == "h" || op == "help") {
            print_help();
            continue;
        } else if (op == "ll") {
            print_node_info(dht, params);
            unsigned good4, dubious4, cached4, incoming4;
            unsigned good6, dubious6, cached6, incoming6;
            dht.getNodesStats(AF_INET, &good4, &dubious4, &cached4, &incoming4);
            dht.getNodesStats(AF_INET6, &good6, &dubious6, &cached6, &incoming6);
            std::cout << "IPv4 nodes : " << good4 << " good, " << dubious4 << " dubious, " << incoming4 << " incoming." << std::endl;
            std::cout << "IPv6 nodes : " << good6 << " good, " << dubious6 << " dubious, " << incoming6 << " incoming." << std::endl;
            continue;
        } else if (op == "lr") {
            std::cout << "IPv4 routing table:" << std::endl;
            std::cout << dht.getRoutingTablesLog(AF_INET) << std::endl;
            std::cout << "IPv6 routing table:" << std::endl;
            std::cout << dht.getRoutingTablesLog(AF_INET6) << std::endl;
            continue;
        } else if (op == "ld") {
            std::cout << dht.getStorageLog() << std::endl;
            continue;
        } else if (op == "ls") {
            std::cout << "Searches:" << std::endl;
            std::cout << dht.getSearchesLog() << std::endl;
            continue;
        } else if (op == "la")  {
            std::cout << "Reported public addresses:" << std::endl;
            auto addrs = dht.getPublicAddressStr();
            for (const auto& addr : addrs)
                std::cout << addr << std::endl;
            continue;
        } else if (op == "b") {
            try {
                auto addr = splitPort(idstr);
                if (not addr.first.empty() and addr.second.empty()){
                    std::stringstream ss;
                    ss << DHT_DEFAULT_PORT;
                    addr.second = ss.str();
                }
                dht.bootstrap(addr.first.c_str(), addr.second.c_str());
            } catch (const std::exception& e) {
                std::cerr << e.what() << std::endl;
            }
            continue;
        } else if (op == "log") {
            params.log = !params.log;
            if (params.log)
                log::enableLogging(dht);
            else
                log::disableLogging(dht);
            continue;
        }

        if (op.empty())
            continue;

        dht::InfoHash id {idstr};
        static const std::set<std::string> VALID_OPS {"g", "l", "p", "s", "e", "a"};
        if (VALID_OPS.find(op) == VALID_OPS.cend()) {
            std::cout << "Unknown command: " << op << std::endl;
            std::cout << " (type 'h' or 'help' for a list of possible commands)" << std::endl;
            continue;
        }
        static constexpr dht::InfoHash INVALID_ID {};
        if (id == INVALID_ID) {
            std::cout << "Syntax error: invalid InfoHash." << std::endl;
            continue;
        }

        auto start = std::chrono::high_resolution_clock::now();
        if (op == "g") {
            dht.get(id, [start](std::shared_ptr<Value> value) {
                auto now = std::chrono::high_resolution_clock::now();
                std::cout << "Get: found value (after " << print_dt(now-start) << "s)" << std::endl;
                std::cout << "\t" << *value << std::endl;
                return true;
            }, [start](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                std::cout << "Get: " << (ok ? "completed" : "failure") << " (took " << print_dt(end-start) << "s)" << std::endl;
            });
        }
        else if (op == "l") {
            dht.listen(id, [](std::shared_ptr<Value> value) {
                std::cout << "Listen: found value:" << std::endl;
                std::cout << "\t" << *value << std::endl;
                return true;
            });
        }
        else if (op == "p") {
            std::string v;
            iss >> v;
            dht.put(id, dht::Value {
                dht::ValueType::USER_DATA.id,
                std::vector<uint8_t> {v.begin(), v.end()}
            }, [start](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                std::cout << "Put: " << (ok ? "success" : "failure") << " (took " << print_dt(end-start) << "s)" << std::endl;
            });
        }
        else if (op == "s") {
            if (not params.generate_identity) {
                print_id_req();
                continue;
            }
            std::string v;
            iss >> v;
            dht.putSigned(id, dht::Value {
                dht::ValueType::USER_DATA.id,
                std::vector<uint8_t> {v.begin(), v.end()}
            }, [start](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                std::cout << "Put signed: " << (ok ? "success" : "failure") << " (took " << print_dt(end-start) << "s)" << std::endl;
            });
        }
        else if (op == "e") {
            if (not params.generate_identity) {
                print_id_req();
                continue;
            }
            std::string tostr;
            std::string v;
            iss >> tostr >> v;
            dht.putEncrypted(id, InfoHash(tostr), dht::Value {
                dht::ValueType::USER_DATA.id,
                std::vector<uint8_t> {v.begin(), v.end()}
            }, [start](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                std::cout << "Put encrypted: " << (ok ? "success" : "failure") << " (took " << print_dt(end-start) << "s)" << std::endl;
            });
        }
        else if (op == "a") {
            in_port_t port;
            iss >> port;
            dht.put(id, dht::Value {dht::IpServiceAnnouncement::TYPE.id, dht::IpServiceAnnouncement(port)}, [start](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                std::cout << "Announce: " << (ok ? "success" : "failure") << " (took " << print_dt(end-start) << "s)" << std::endl;
            });
        }
    }

    std::cout << std::endl <<  "Stopping node..." << std::endl;
}

int
main(int argc, char **argv)
{
    if (int rc = gnutls_global_init())  // TODO: remove with GnuTLS >= 3.3
        throw std::runtime_error(std::string("Error initializing GnuTLS: ")+gnutls_strerror(rc));

    DhtRunner dht;
    try {
        auto params = parseArgs(argc, argv);
        if (params.help) {
            print_usage();
            return 0;
        }
        if (params.daemonize) {
            daemonize();
        }

        dht::crypto::Identity crt {};
        if (params.generate_identity) {
            auto ca_tmp = dht::crypto::generateIdentity("DHT Node CA");
            crt = dht::crypto::generateIdentity("DHT Node", ca_tmp);
        }

        dht.run(params.port, crt, true, params.network);

        if (params.log) {
            if (not params.logfile.empty())
                log::enableFileLogging(dht, params.logfile);
            else
                log::enableLogging(dht);
        }

        if (not params.bootstrap.first.empty()) {
            //std::cout << "Bootstrap: " << params.bootstrap.first << ":" << params.bootstrap.second << std::endl;
            dht.bootstrap(params.bootstrap.first.c_str(), params.bootstrap.second.c_str());
        }

        if (params.daemonize) {
            while (true)
                std::this_thread::sleep_for(std::chrono::seconds(30));
        } else {
            cmd_loop(dht, params);
        }

    } catch(const std::exception&e) {
        std::cerr << std::endl <<  e.what() << std::endl;
    }

    std::condition_variable cv;
    std::mutex m;
    std::atomic_bool done {false};

    dht.shutdown([&]()
    {
        std::lock_guard<std::mutex> lk(m);
        done = true;
        cv.notify_all();
    });

    // wait for shutdown
    std::unique_lock<std::mutex> lk(m);
    cv.wait(lk, [&](){ return done.load(); });

    dht.join();
    gnutls_global_deinit();

    return 0;
}
