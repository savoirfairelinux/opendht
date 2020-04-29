/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *
 *  Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
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

// Common utility methods used by C++ OpenDHT tools.
#pragma once

#include <opendht.h>
#include <opendht/log.h>
#include <opendht/crypto.h>
#include <opendht/network_utils.h>
#ifdef OPENDHT_INDEXATION
#include <opendht/indexation/pht.h>
#endif
#ifdef OPENDHT_PROXY_SERVER
#include <opendht/dht_proxy_server.h>
#endif

#ifndef WIN32_NATIVE
#include <getopt.h>
#include <readline/readline.h>
#include <readline/history.h>
#else
#define SIGHUP 0
#include "wingetopt.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>

#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <iostream>
#include <sstream>
#include <fstream>

/*
 * The mapString shall have the following format:
 *
 *      k1:v1[,k2:v2[,...]]
 */
std::map<std::string, std::string> parseStringMap(std::string mapString) {
    std::istringstream keySs(mapString);
    std::string mapStr;
    std::map<std::string, std::string> map;

    while (std::getline(keySs, mapStr, ',')) {
        std::istringstream mapSs(mapStr);
        std::string key, value;

        while (std::getline(mapSs, key, ':')) {
            std::getline(mapSs, value, ':');
            map[key] = { value };
        }
    }
    return map;
}

#ifdef OPENDHT_INDEXATION
dht::indexation::Pht::Key createPhtKey(std::map<std::string, std::string> pht_key_str_map) {
    dht::indexation::Pht::Key pht_key;
    for (auto f : pht_key_str_map) {
        dht::Blob prefix {f.second.begin(), f.second.end()};
        pht_key.emplace(f.first, std::move(prefix));
    }
    return pht_key;
}
#endif

bool isInfoHash(const dht::InfoHash& h) {
    if (not h) {
        std::cout << "Syntax error: invalid InfoHash." << std::endl;
        return false;
    }
    return true;
}

std::vector<uint8_t>
loadFile(const std::string& path)
{
    std::vector<uint8_t> buffer;
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("Can't read file: "+path);
    file.seekg(0, std::ios::end);
    auto size = file.tellg();
    if (size > std::numeric_limits<unsigned>::max())
        throw std::runtime_error("File is too big: "+path);
    buffer.resize(size);
    file.seekg(0, std::ios::beg);
    if (!file.read((char*)buffer.data(), size))
        throw std::runtime_error("Can't load file: "+path);
    return buffer;
}

struct dht_params {
    bool help {false}; // print help and exit
    bool version {false};
    bool generate_identity {false};
    bool daemonize {false};
    bool service {false};
    bool peer_discovery {false};
    bool log {false};
    bool syslog {false};
    std::string logfile {};
    std::string bootstrap {};
    dht::NetId network {0};
    in_port_t port {0};
    in_port_t proxyserver {0};
    in_port_t proxyserverssl {0};
    std::string proxyclient {};
    std::string pushserver {};
    std::string devicekey {};
    std::string persist_path {};
    dht::crypto::Identity id {};
    dht::crypto::Identity proxy_id {};
    std::string privkey_pwd {};
    std::string proxy_privkey_pwd {};
    std::string save_identity {};
    bool no_rate_limit {false};
    bool public_stable {false};
};

std::pair<dht::DhtRunner::Config, dht::DhtRunner::Context>
getDhtConfig(dht_params& params)
{
    if (not params.id.first and params.generate_identity) {
        auto node_ca = std::make_unique<dht::crypto::Identity>(dht::crypto::generateEcIdentity("DHT Node CA"));
        params.id = dht::crypto::generateIdentity("DHT Node", *node_ca);
        if (not params.save_identity.empty()) {
            dht::crypto::saveIdentity(*node_ca, params.save_identity + "_ca", params.privkey_pwd);
            dht::crypto::saveIdentity(params.id, params.save_identity, params.privkey_pwd);
        }
    }

    dht::DhtRunner::Config config {};
    config.dht_config.node_config.network = params.network;
    config.dht_config.node_config.maintain_storage = false;
    config.dht_config.node_config.persist_path = params.persist_path;
    config.dht_config.node_config.public_stable = params.public_stable;
    config.dht_config.id = params.id;
    config.dht_config.cert_cache_all = static_cast<bool>(params.id.first);
    config.threaded = true;
    config.proxy_server = params.proxyclient;
    config.push_node_id = "dhtnode";
    config.push_token = params.devicekey;
    config.peer_discovery = params.peer_discovery;
    config.peer_publish = params.peer_discovery;
    if (params.no_rate_limit) {
        config.dht_config.node_config.max_req_per_sec = -1;
        config.dht_config.node_config.max_peer_req_per_sec = -1;
        config.dht_config.node_config.max_searches = -1;
        config.dht_config.node_config.max_store_size = -1;
    }

    dht::DhtRunner::Context context {};
    if (params.log) {
        if (params.syslog or (params.daemonize and params.logfile.empty()))
            context.logger = dht::log::getSyslogLogger("dhtnode");
        else if (not params.logfile.empty())
            context.logger = dht::log::getFileLogger(params.logfile);
        else
            context.logger = dht::log::getStdLogger();
    }
    if (context.logger) {
        context.statusChangedCallback = [logger = *context.logger](dht::NodeStatus status4, dht::NodeStatus status6) {
            logger.WARN("Connectivity changed: IPv4: %s, IPv6: %s", dht::statusToStr(status4), dht::statusToStr(status6));
        };
    }
    return {std::move(config), std::move(context)};
}

void print_node_info(const dht::NodeInfo& info) {
    std::cout << "OpenDHT node " << info.node_id << " running on ";
    if (info.bound4 == info.bound6)
        std::cout << "port " << info.bound4 << std::endl;
    else
        std::cout << "IPv4 port " << info.bound4 << ", IPv6 port " << info.bound6 << std::endl;
    if (info.id)
        std::cout << "Public key ID " << info.id << std::endl;
}

static const constexpr struct option long_options[] = {
    {"help",                    no_argument      , nullptr, 'h'},
    {"port",                    required_argument, nullptr, 'p'},
    {"net",                     required_argument, nullptr, 'n'},
    {"bootstrap",               required_argument, nullptr, 'b'},
    {"identity",                no_argument      , nullptr, 'i'},
    {"save-identity",           required_argument, nullptr, 'I'},
    {"certificate",             required_argument, nullptr, 'c'},
    {"privkey",                 required_argument, nullptr, 'k'},
    {"privkey-password",        required_argument, nullptr, 'm'},
    {"verbose",                 no_argument      , nullptr, 'v'},
    {"daemonize",               no_argument      , nullptr, 'd'},
    {"service",                 no_argument      , nullptr, 's'},
    {"peer-discovery",          no_argument      , nullptr, 'D'},
    {"no-rate-limit",           no_argument      , nullptr, 'U'},
    {"public-stable",           no_argument      , nullptr, 'P'},
    {"persist",                 required_argument, nullptr, 'f'},
    {"logfile",                 required_argument, nullptr, 'l'},
    {"syslog",                  no_argument      , nullptr, 'L'},
    {"proxyserver",             required_argument, nullptr, 'S'},
    {"proxyserverssl",          required_argument, nullptr, 'e'},
    {"proxy-certificate",       required_argument, nullptr, 'w'},
    {"proxy-privkey",           required_argument, nullptr, 'K'},
    {"proxy-privkey-password",  required_argument, nullptr, 'M'},
    {"proxyclient",             required_argument, nullptr, 'C'},
    {"pushserver",              required_argument, nullptr, 'y'},
    {"devicekey",               required_argument, nullptr, 'z'},
    {"version",                 no_argument      , nullptr, 'V'},
    {nullptr,                   0                , nullptr,  0}
};

dht_params
parseArgs(int argc, char **argv) {
    dht_params params;
    int opt;
    std::string privkey;
    std::string proxy_privkey;
    while ((opt = getopt_long(argc, argv, "hidsvDUPp:n:b:f:l:", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'p': {
                int port_arg = atoi(optarg);
                if (port_arg >= 0 && port_arg < 0x10000)
                    params.port = port_arg;
                else
                    std::cout << "Invalid port: " << port_arg << std::endl;
            }
            break;
        case 'S': {
                int port_arg = atoi(optarg);
                if (port_arg >= 0 && port_arg < 0x10000)
                    params.proxyserver = port_arg;
                else
                    std::cout << "Invalid port: " << port_arg << std::endl;
            }
            break;
        case 'e': {
                int port_arg = atoi(optarg);
                if (port_arg >= 0 && port_arg < 0x10000)
                    params.proxyserverssl = port_arg;
                else
                    std::cout << "Invalid port: " << port_arg << std::endl;
            }
            break;
        case 'D':
            params.peer_discovery = true;
            break;
        case 'y':
            params.pushserver = optarg;
            break;
        case 'C':
            params.proxyclient = optarg;
            break;
        case 'z':
            params.devicekey = optarg;
            break;
        case 'f':
            params.persist_path = optarg;
            break;
        case 'n':
            params.network = strtoul(optarg, nullptr, 0);
            break;
        case 'U':
            params.no_rate_limit = true;
            break;
        case 'P':
            params.public_stable = true;
            break;
        case 'b':
            params.bootstrap = (optarg[0] == '=') ? optarg+1 : optarg;
            break;
        case 'V':
            params.version = true;
            break;
        case 'h':
            params.help = true;
            break;
        case 'l':
            params.logfile = optarg;
            break;
        case 'L':
            params.log = true;
            params.syslog = true;
            break;
        case 'v':
            params.log = true;
            break;
        case 'i':
            params.generate_identity = true;
            break;
        case 'd':
            params.daemonize = true;
            break;
        case 's':
            params.service = true;
            break;
        case 'c': {
            try {
                params.id.second = std::make_shared<dht::crypto::Certificate>(loadFile(optarg));
            } catch (const std::exception& e) {
                throw std::runtime_error(std::string("Error loading certificate: ") + e.what());
            }
            break;
        }
        case 'w': {
            try {
                params.proxy_id.second = std::make_shared<dht::crypto::Certificate>(loadFile(optarg));
            } catch (const std::exception& e) {
                throw std::runtime_error(std::string("Error loading proxy certificate: ") + e.what());
            }
            break;
        }
        case 'k':
            privkey = optarg;
            break;
        case 'K':
            proxy_privkey = optarg;
            break;
        case 'm':
            params.privkey_pwd = optarg;
            break;
        case 'M':
            params.proxy_privkey_pwd = optarg;
            break;
        case 'I':
            params.save_identity = optarg;
            break;
        default:
            break;
        }
    }
    if (not privkey.empty()) {
        try {
            params.id.first = std::make_shared<dht::crypto::PrivateKey>(loadFile(privkey),
                                                                        params.privkey_pwd);
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("Error loading private key: ") + e.what());
        }
    }
    if (not proxy_privkey.empty()) {
        try {
            params.proxy_id.first = std::make_shared<dht::crypto::PrivateKey>(loadFile(proxy_privkey),
                                                                              params.proxy_privkey_pwd);
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("Error loading proxy private key: ") + e.what());
        }
    }
    if (params.save_identity.empty())
        params.privkey_pwd.clear();
    return params;
}

static const constexpr char* PROMPT = ">> ";

std::string
readLine(const char* prefix = PROMPT)
{
#ifndef WIN32_NATIVE
    const char* line_read = readline(prefix);
    if (line_read && *line_read)
        add_history(line_read);

#else
    char line_read[512];
    std::cout << PROMPT;
    fgets(line_read, 512 , stdin);
#endif
    return line_read ? std::string(line_read) : std::string("\0", 1);
}

struct ServiceRunner {
    bool wait() {
        std::unique_lock<std::mutex> lock(m);
        cv.wait(lock, [&]{return terminate.load();});
        return !terminate;
    }
    void kill() {
        terminate = true;
        cv.notify_all();
    }
private:
    std::condition_variable cv;
    std::mutex m;
    std::atomic_bool terminate {false};
};

ServiceRunner runner;

void signal_handler(int sig)
{
    switch(sig) {
    case SIGHUP:
        break;
    case SIGINT:
        close(STDIN_FILENO);
        // fall through
    case SIGTERM:
        runner.kill();
        break;
    }
}

void setupSignals()
{
#ifndef WIN32_NATIVE
    signal(SIGCHLD,SIG_IGN); /* ignore child */
    signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGHUP,signal_handler); /* catch hangup signal */
    signal(SIGINT,signal_handler); /* catch interrupt signal */
    signal(SIGTERM,signal_handler); /* catch kill signal */
#endif
}

void daemonize()
{
#ifndef WIN32_NATIVE
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);

    pid_t sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
#endif
}
