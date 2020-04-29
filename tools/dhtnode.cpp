/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *
 *  Authors: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *           Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
 *           Sébastien Blin <sebastien.blin@savoirfairelinux.com>
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
extern "C" {
#include <gnutls/gnutls.h>
}

#include <set>
#include <thread> // std::this_thread::sleep_for

using namespace dht;

void print_info() {
    std::cout << "dhtnode, a simple OpenDHT command line node runner." << std::endl;
    std::cout << "Report bugs to: https://opendht.net" << std::endl;
}

void print_version() {
    std::cout << "OpenDHT version " << dht::version() << std::endl;
    print_info();
}

void print_usage() {
    std::cout << "Usage: dhtnode [-v [-l logfile]] [-i] [-d] [-n network_id] [-p local_port] [-b bootstrap_host[:port]] [--proxyserver local_port] [--proxyserverssl local_port]" << std::endl << std::endl;
    print_info();
}

void print_id_req() {
    std::cout << "An identity is required to perform this operation (run with -i)" << std::endl;
}

void print_help() {
    std::cout << "OpenDHT command line interface (CLI)" << std::endl;
    std::cout << "Possible commands:" << std::endl
              << "  h, help    Print this help message." << std::endl
              << "  x, quit    Quit the program." << std::endl
              << "  log        Start/stop printing DHT logs." << std::endl;

    std::cout << std::endl << "Node information:" << std::endl
              << "  ll         Print basic information and stats about the current node." << std::endl
              << "  ls [key]   Print basic information about current search(es)." << std::endl
              << "  ld [key]   Print basic information about currenty stored values on this node (or key)." << std::endl
              << "  lr         Print the full current routing table of this node." << std::endl;

#ifdef OPENDHT_PROXY_SERVER
    std::cout << std::endl << "Operations with the proxy:" << std::endl
#ifdef OPENDHT_PUSH_NOTIFICATIONS
              << "  pst [port] <pushServer> Start the proxy interface on port." << std::endl
#else
              << "  pst [port]              Start the proxy interface on port." << std::endl
              << "  psx [port]              Start the proxy ssl interface on port." << std::endl
#endif // OPENDHT_PUSH_NOTIFICATIONS
              << "  psp [port]              Stop the proxy interface on port." << std::endl;
#endif //OPENDHT_PROXY_SERVER

#ifdef OPENDHT_PROXY_CLIENT
    std::cout << std::endl << "Operations with the proxy:" << std::endl
#ifdef OPENDHT_PUSH_NOTIFICATIONS
              << "  stt [server_address] <device_key> Start the proxy client." << std::endl
              << "  rs  [token]                       Resubscribe to opendht." << std::endl
              << "  rp  [token]                       Inject a push notification in Opendht." << std::endl
#else
              << "  stt [server_address]              Start the proxy client." << std::endl
#endif // OPENDHT_PUSH_NOTIFICATIONS
              << "  stp                               Stop the proxy client." << std::endl;
#endif //OPENDHT_PROXY_CLIENT

    std::cout << std::endl << "Operations on the DHT:" << std::endl
              << "  b <ip:port>           Ping potential node at given IP address/port." << std::endl
              << "  g <key>               Get values at <key>." << std::endl
              << "  l <key>               Listen for value changes at <key>." << std::endl
              << "  cl <key> <token>      Cancel listen for <token> and <key>." << std::endl
              << "  p <key> <str>         Put string value at <key>." << std::endl
              << "  pp <key> <str>        Put string value at <key> (persistent version)." << std::endl
              << "  cpp <key> <id>        Cancel persistent put operation for <key> and value <id>." << std::endl
              << "  s <key> <str>         Put string value at <key>, signed with our generated private key." << std::endl
              << "  e <key> <dest> <str>  Put string value at <key>, encrypted for <dest> with its public key (if found)." << std::endl
              << "  cc                    Trigger connectivity changed signal." << std::endl;

#ifdef OPENDHT_INDEXATION
    std::cout << std::endl << "Indexation operations on the DHT:" << std::endl
              << "  il <name> <key> [exact match]   Lookup the index named <name> with the key <key>." << std::endl
              << "                                  Set [exact match] to 'false' for inexact match lookup." << std::endl
              << "  ii <name> <key> <value>         Inserts the value <value> under the key <key> in the index named <name>." << std::endl
              << std::endl;
#endif
}

void cmd_loop(std::shared_ptr<DhtRunner>& node, dht_params& params
#ifdef OPENDHT_PROXY_SERVER
    , std::map<in_port_t, std::unique_ptr<DhtProxyServer>>& proxies
#endif
)
{
    print_node_info(node->getNodeInfo());
    std::cout << " (type 'h' or 'help' for a list of possible commands)" << std::endl << std::endl;

#ifndef WIN32_NATIVE
    // using the GNU History API
    using_history();
#endif

#ifdef OPENDHT_INDEXATION
    std::map<std::string, indexation::Pht> indexes;
#endif

    while (true)
    {
        // using the GNU Readline API
        std::string line = readLine();
        if (!line.empty() && line[0] == '\0')
            break;

        std::istringstream iss(line);
        std::string op, idstr, value, index, keystr, pushServer, deviceKey;
        iss >> op;

        if (op == "x" || op == "exit" || op == "quit") {
            break;
        } else if (op == "h" || op == "help") {
            print_help();
            continue;
        } else if (op == "ll") {
            node->getNodeInfo([&](const std::shared_ptr<dht::NodeInfo>& nodeInfo) {
                print_node_info(*nodeInfo);
                std::cout << nodeInfo->ongoing_ops << " ongoing operations" << std::endl;
                std::cout << "IPv4 stats:" << std::endl;
                std::cout << nodeInfo->ipv4.toString() << std::endl;
                std::cout << "IPv6 stats:" << std::endl;
                std::cout << nodeInfo->ipv6.toString() << std::endl;
#ifdef OPENDHT_PROXY_SERVER
                for (const auto& proxy : proxies) {
                    std::cout << "Stats for proxy server on port " << proxy.first << std::endl;
                    if (auto stats = proxy.second->stats())
                        std::cout << "  " << stats->toString() << std::endl;
                    else
                        std::cout << "  (stats not available yet)" << std::endl;                
                }
#endif
            });
            continue;
        } else if (op == "lr") {
            std::cout << "IPv4 routing table:" << std::endl;
            std::cout << node->getRoutingTablesLog(AF_INET) << std::endl;
            std::cout << "IPv6 routing table:" << std::endl;
            std::cout << node->getRoutingTablesLog(AF_INET6) << std::endl;
            continue;
        } else if (op == "ld") {
            iss >> idstr;
            InfoHash filter(idstr);
            if (filter)
                std::cout << node->getStorageLog(filter) << std::endl;
            else
                std::cout << node->getStorageLog() << std::endl;
            continue;
        } else if (op == "ls") {
            iss >> idstr;
            InfoHash filter(idstr);
            if (filter)
                std::cout << node->getSearchLog(filter) << std::endl;
            else
                std::cout << node->getSearchesLog() << std::endl;
            continue;
        } else if (op == "la")  {
            std::cout << "Reported public addresses:" << std::endl;
            auto addrs = node->getPublicAddressStr();
            for (const auto& addr : addrs)
                std::cout << addr << std::endl;
            continue;
        } else if (op == "b") {
            iss >> idstr;
            if (not idstr.empty())
                node->bootstrap(idstr);
            else
                std::cerr << "No service provided. Syntax: b hostname:port" << std::endl;
            continue;
        } else if (op == "log") {
            iss >> idstr;
            InfoHash filter(idstr);
            params.log = filter ? true : !params.log;
            if (params.log)
                log::enableLogging(*node);
            else
                log::disableLogging(*node);
            node->setLogFilter(filter);
            continue;
        } else if (op == "cc") {
            node->connectivityChanged();
            continue;
        }
#ifdef OPENDHT_PROXY_SERVER
        else if (op == "pst") {
#ifdef OPENDHT_PUSH_NOTIFICATIONS
                iss >> idstr >> pushServer;
#else
                iss >> idstr;
#endif // OPENDHT_PUSH_NOTIFICATIONS
            try {
                unsigned int port = std::stoi(idstr);
                proxies.emplace(port, std::unique_ptr<DhtProxyServer>(
                    new DhtProxyServer(
                        dht::crypto::Identity{}, node, port
#ifdef OPENDHT_PUSH_NOTIFICATIONS
                        ,pushServer
#endif
                )));
            } catch (...) { }
            continue;
        } else if (op == "psx") {
#ifdef OPENDHT_PUSH_NOTIFICATIONS
                iss >> idstr >> pushServer;
#else
                iss >> idstr;
#endif // OPENDHT_PUSH_NOTIFICATIONS
            try {
                if (params.proxy_id.first and params.proxy_id.second){
                    unsigned int port = std::stoi(idstr);
                    proxies.emplace(port, std::unique_ptr<DhtProxyServer>(
                        new DhtProxyServer(params.proxy_id, node, port
#ifdef OPENDHT_PUSH_NOTIFICATIONS
                                           ,pushServer
#endif
                    )));
                }
                else {
                    std::cerr << "Missing Identity private key or certificate" << std::endl;
                }
            } catch (...) { }
            continue;
        } else if (op == "psp") {
            iss >> idstr;
            try {
                auto it = proxies.find(std::stoi(idstr));
                if (it != proxies.end())
                    proxies.erase(it);
            } catch (...) { }
            continue;
        }
#endif //OPENDHT_PROXY_SERVER
#ifdef OPENDHT_PROXY_CLIENT
        else if (op == "stt") {
            node->enableProxy(true);
            continue;
        } else if (op == "stp") {
            node->enableProxy(false);
            continue;
        }
#ifdef OPENDHT_PUSH_NOTIFICATIONS
        else if (op == "rp") {
            iss >> value;
            node->pushNotificationReceived({{"to", "dhtnode"}, {"token", value}});
            continue;
        }
#endif // OPENDHT_PUSH_NOTIFICATIONS
#endif //OPENDHT_PROXY_CLIENT

        if (op.empty())
            continue;

        static const std::set<std::string> VALID_OPS {"g", "l", "cl", "il", "ii", "p", "pp", "cpp", "s", "e", "a",  "q"};
        if (VALID_OPS.find(op) == VALID_OPS.cend()) {
            std::cout << "Unknown command: " << op << std::endl;
            std::cout << " (type 'h' or 'help' for a list of possible commands)" << std::endl;
            continue;
        }
        dht::InfoHash id;

        if (false) {}
#ifdef OPENDHT_INDEXATION
        else if (op == "il" or op == "ii") {
            // Pht syntax
            iss >> index >> keystr;
            auto new_index = std::find_if(indexes.begin(), indexes.end(),
                    [&](std::pair<const std::string, indexation::Pht>& i) {
                        return i.first == index;
                    }) == indexes.end();
            if (not index.size()) {
                std::cerr << "You must enter the index name." << std::endl;
                continue;
            } else if (new_index) {
                using namespace dht::indexation;
                try {
                    auto key = createPhtKey(parseStringMap(keystr));
                    Pht::KeySpec ks;
                    std::transform(key.begin(), key.end(), std::inserter(ks, ks.end()), [](Pht::Key::value_type& f) {
                        return std::make_pair(f.first, f.second.size());
                    });
                    indexes.emplace(index, Pht {index, std::move(ks), node});
                } catch (std::invalid_argument& e) { std::cout << e.what() << std::endl; }
            }
        }
#endif
        else {
            // Dht syntax
            iss >> idstr;
            id = dht::InfoHash(idstr);
            if (not id) {
                if (idstr.empty()) {
                    std::cerr << "Syntax error: invalid InfoHash." << std::endl;
                    continue;
                }
                id = InfoHash::get(idstr);
                std::cout << "Using h(" << idstr << ") = " << id << std::endl;
            }
        }

        // Dht
        auto start = std::chrono::high_resolution_clock::now();
        if (op == "g") {
            std::string rem;
            std::getline(iss, rem);
            node->get(id, [start](const std::vector<std::shared_ptr<Value>>& values) {
                auto now = std::chrono::high_resolution_clock::now();
                std::cout << "Get: found " << values.size() << " value(s) after " << print_duration(now-start) << std::endl;
                for (const auto& value : values)
                    std::cout << "\t" << *value << std::endl;
                return true;
            }, [start](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                std::cout << "Get: " << (ok ? "completed" : "failure") << ", took " << print_duration(end-start) << std::endl;
            }, {}, dht::Where {rem});
        }
        else if (op == "q") {
            std::string rem;
            std::getline(iss, rem);
            node->query(id, [start](const std::vector<std::shared_ptr<FieldValueIndex>>& field_value_indexes) {
                auto now = std::chrono::high_resolution_clock::now();
                for (auto& index : field_value_indexes) {
                    std::cout << "Query: found field value index after " << print_duration(now-start) << std::endl;
                    std::cout << "\t" << *index << std::endl;
                }
                return true;
            }, [start](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                std::cout << "Query: " << (ok ? "completed" : "failure") << ", took " << print_duration(end-start) << std::endl;
            }, dht::Query {rem});
        }
        else if (op == "l") {
            std::string rem;
            std::getline(iss, rem);
            auto token = node->listen(id, [](const std::vector<std::shared_ptr<Value>>& values, bool expired) {
                std::cout << "Listen: found " << values.size() << " values" << (expired ? " expired" : "") << std::endl;
                for (const auto& value : values)
                    std::cout << "\t" << *value << std::endl;
                return true;
            }, {}, dht::Where {rem});
            auto t = token.get();
            std::cout << "Listening, token: " << t << std::endl;
        }
        if (op == "cl") {
            std::string rem;
            iss >> rem;
            size_t token;
            try {
                token = std::stoul(rem);
            } catch(...) {
                std::cerr << "Syntax: cl [key] [token]" << std::endl;
                continue;
            }
            node->cancelListen(id, token);
        }
        else if (op == "p") {
            std::string v;
            iss >> v;
            auto value = std::make_shared<dht::Value>(
                dht::ValueType::USER_DATA.id,
                std::vector<uint8_t> {v.begin(), v.end()});
            value->user_type = "text/plain";
            node->put(id, value, [start, value](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                auto flags(std::cout.flags());
                std::cout << "Put: " << (ok ? "success" : "failure") << ", took " << print_duration(end-start) << ". Value ID: " << std::hex << value->id << std::endl;
                std::cout.flags(flags);
            });
        }
        else if (op == "pp") {
            std::string v;
            iss >> v;
            auto value = std::make_shared<dht::Value>(
                dht::ValueType::USER_DATA.id,
                std::vector<uint8_t> {v.begin(), v.end()}
            );
            value->user_type = "text/plain";
            node->put(id, value, [start, value](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                auto flags(std::cout.flags());
                std::cout << "Put: " << (ok ? "success" : "failure") << ", took " << print_duration(end-start) << ". Value ID: " << std::hex << value->id << std::endl;
                std::cout.flags(flags);
            }, time_point::max(), true);
        }
        else if (op == "cpp") {
            std::string rem;
            iss >> rem;
            node->cancelPut(id, std::stoul(rem, nullptr, 16));
        }
        else if (op == "s") {
            if (not params.id.first) {
                print_id_req();
                continue;
            }
            std::string v;
            iss >> v;
            auto value = std::make_shared<dht::Value>();
            value->data = {v.begin(), v.end()};
            value->user_type = "text/plain";
            node->putSigned(id, std::move(value), [start](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                std::cout << "Put signed: " << (ok ? "success" : "failure") << " (took " << print_duration(end-start) << "s)" << std::endl;
            });
        }
        else if (op == "e") {
            if (not params.id.first) {
                print_id_req();
                continue;
            }
            std::string tostr;
            std::string v;
            iss >> tostr >> v;
            auto value = std::make_shared<dht::Value>(
                dht::ValueType::USER_DATA.id,
                std::vector<uint8_t> {v.begin(), v.end()}
            );
            value->user_type = "text/plain";
            node->putEncrypted(id, InfoHash(tostr), std::move(value), [start](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                std::cout << "Put encrypted: " << (ok ? "success" : "failure") << " (took " << print_duration(end-start) << std::endl;
            });
        }
        else if (op == "a") {
            in_port_t port;
            iss >> port;
            node->put(id, dht::Value {dht::IpServiceAnnouncement::TYPE.id, dht::IpServiceAnnouncement(port)}, [start](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                std::cout << "Announce: " << (ok ? "success" : "failure") << " (took " << print_duration(end-start) << std::endl;
            });
        }
#ifdef OPENDHT_INDEXATION
        else if (op == "il") {
            std::string exact_match;
            iss >> exact_match;
            try {
                auto key = createPhtKey(parseStringMap(keystr));
                indexes.at(index).lookup(key,
                    [=](std::vector<std::shared_ptr<indexation::Value>>& vals, indexation::Prefix p) {
                        if (vals.empty())
                            return;
                        std::cout << "Pht::lookup: found entries!" << std::endl
                                  << p.toString() << std::endl
                                  << "   hash: " << p.hash() << std::endl;
                        std::cout << "   entries:" << std::endl;
                        for (const auto& v : vals)
                             std::cout << "      " << v->first.toString() << "[vid: " << v->second << "]" << std::endl;
                    },
                    [start](bool ok) {
                        auto end = std::chrono::high_resolution_clock::now();
                        std::cout << "Pht::lookup: " << (ok ? "done." : "failed.")
                                  << " took " << print_duration(end-start) << std::endl;

                    }, exact_match.size() != 0 and exact_match == "false" ? false : true
                );
            }
            catch (std::invalid_argument& e) { std::cout << e.what() << std::endl; }
            catch (std::out_of_range& e) { }
        }
        else if (op == "ii") {
            iss >> idstr;
            InfoHash h {idstr};
            if (not isInfoHash(h))
                continue;

            indexation::Value v {h, 0};
            try {
                auto key = createPhtKey(parseStringMap(keystr));
                indexes.at(index).insert(key, v,
                    [=](bool ok) {
                        std::cout << "Pht::insert: " << (ok ? "done." : "failed.") << std::endl;
                    }
                );
            }
            catch (std::invalid_argument& e) { std::cout << e.what() << std::endl; }
            catch (std::out_of_range& e) { }
        }
#endif
    }

    std::cout << std::endl <<  "Stopping node..." << std::endl;
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
    if (params.version) {
        print_version();
        return 0;
    }

    if (params.daemonize) {
        daemonize();
    }
    setupSignals();

    auto node = std::make_shared<DhtRunner>();
    try {
        auto dhtConf = getDhtConfig(params);
        node->run(params.port, dhtConf.first, std::move(dhtConf.second));

        if (not params.bootstrap.empty()) {
            std::cout << "Bootstrap: " << params.bootstrap << std::endl;
            node->bootstrap(params.bootstrap);
        }

#ifdef OPENDHT_PROXY_SERVER
        std::map<in_port_t, std::unique_ptr<DhtProxyServer>> proxies;
#endif
        if (params.proxyserverssl and params.proxy_id.first and params.proxy_id.second){
#ifdef OPENDHT_PROXY_SERVER
            proxies.emplace(params.proxyserverssl, std::unique_ptr<DhtProxyServer>(
                new DhtProxyServer(params.proxy_id,
                                   node, params.proxyserverssl, params.pushserver, dhtConf.second.logger)));
        }
        if (params.proxyserver) {
            proxies.emplace(params.proxyserver, std::unique_ptr<DhtProxyServer>(
                new DhtProxyServer(
                    dht::crypto::Identity{},
                    node, params.proxyserver, params.pushserver, dhtConf.second.logger)));
#else
            std::cerr << "DHT proxy server requested but OpenDHT built without proxy server support." << std::endl;
            exit(EXIT_FAILURE);
#endif
        }

        if (params.daemonize or params.service)
            while (runner.wait());
        else
            cmd_loop(node, params
#ifdef OPENDHT_PROXY_SERVER
                , proxies
#endif
            );

    } catch(const std::exception&e) {
        std::cerr << std::endl <<  e.what() << std::endl;
    }

    std::condition_variable cv;
    std::mutex m;
    bool done {false};

    node->shutdown([&]()
    {
        done = true;
        cv.notify_all();
    });

    // wait for shutdown
    std::unique_lock<std::mutex> lk(m);
    cv.wait(lk, [&](){ return done; });

    node->join();
#ifdef WIN32_NATIVE
    gnutls_global_deinit();
#endif
    return 0;
}
