// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

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

#include <fmt/ranges.h>

#ifndef _WIN32
#include <getopt.h>
#include <readline/readline.h>
#include <readline/history.h>
#else
#ifdef _MSC_VER
#pragma message("Building on WIN32 platform using MSVC, linking wingetopt")
#include "wingetopt.h"
#endif
#if defined(__MINGW32__) || defined(__MINGW64__)
#pragma message "Building on MinGW, linking system-wide getopt"
#include <getopt.h>
#include <readline/readline.h>
#include <readline/history.h>
#endif
#endif

#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
#define SIGHUP 0
#include <io.h>
#define DISABLE_SIGNALS
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
#include <filesystem>

namespace dht {
namespace tools {

/*
 * The mapString shall have the following format:
 *
 *      k1:v1[,k2:v2[,...]]
 */
std::map<std::string, std::string>
parseStringMap(std::string mapString)
{
    std::istringstream keySs(mapString);
    std::string mapStr;
    std::map<std::string, std::string> map;

    while (std::getline(keySs, mapStr, ',')) {
        std::istringstream mapSs(mapStr);
        std::string key, value;

        while (std::getline(mapSs, key, ':')) {
            std::getline(mapSs, value, ':');
            map[key] = {value};
        }
    }
    return map;
}

#ifdef OPENDHT_INDEXATION
dht::indexation::Pht::Key
createPhtKey(std::map<std::string, std::string> pht_key_str_map)
{
    dht::indexation::Pht::Key pht_key;
    for (auto f : pht_key_str_map) {
        dht::Blob prefix {f.second.begin(), f.second.end()};
        pht_key.emplace(f.first, std::move(prefix));
    }
    return pht_key;
}
#endif

bool
isInfoHash(const dht::InfoHash& h)
{
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
        throw std::runtime_error("Can't read file: " + path);
    file.seekg(0, std::ios::end);
    auto size = file.tellg();
    if (size > std::numeric_limits<unsigned>::max())
        throw std::runtime_error("File is too big: " + path);
    buffer.resize(size);
    file.seekg(0, std::ios::beg);
    if (!file.read((char*) buffer.data(), size))
        throw std::runtime_error("Can't load file: " + path);
    return buffer;
}

void
saveFile(const std::string& path, const uint8_t* data, size_t size, bool secret)
{
    auto temporary = path + "." + dht::InfoHash::getRandom().toString() + ".tmp";
    try {
        std::ofstream file;
        file.exceptions(std::ios::failbit | std::ios::badbit);
        file.open(temporary, std::ios::binary | std::ios::trunc);
        if (secret)
            std::filesystem::permissions(temporary,
                                         std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
        file.write((const char*) data, size);
        file.close();
        std::filesystem::rename(temporary, path);
    } catch (...) {
        std::error_code ec;
        std::filesystem::remove(temporary, ec);
        throw;
    }
}

dht::transport::Key
loadTransportKey(const std::string& path)
{
    auto data = loadFile(path);
    dht::transport::Key key;
    if (data.size() != key.size())
        throw std::runtime_error("Invalid key file: " + path);
    std::copy(data.begin(), data.end(), key.begin());
    return key;
}

/* Loads the transport key from path, or generates and saves it if the file doesn't exist */
dht::transport::KeyPair
loadOrCreateTransportKey(const std::string& path)
{
    if (std::filesystem::exists(std::filesystem::symlink_status(path)))
        return dht::transport::KeyPair::fromSecret(loadTransportKey(path));
    auto key = dht::transport::KeyPair::generate();
    saveFile(path, key.secret.data(), key.secret.size(), true);
    return key;
}

dht::transport::Key
keyFromHex(const std::string& hex)
{
    dht::transport::Key key;
    if (hex.size() != 2 * key.size())
        throw std::runtime_error("Invalid key: " + hex);
    for (size_t i = 0; i < key.size(); i++)
        key[i] = std::stoul(hex.substr(2 * i, 2), nullptr, 16);
    return key;
}

struct dht_params
{
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
    std::string proxy_address {};
    std::string pushserver {};
    std::string devicekey {};
    std::string bundle_id {};
    std::string persist_path {};
    dht::crypto::Identity id {};
    dht::crypto::Identity proxy_id {};
    std::string privkey_pwd {};
    std::string proxy_privkey_pwd {};
    std::string save_identity {};
    bool no_rate_limit {false};
    bool public_stable {false};
    bool no_encryption {false};
    std::string transport_key {};
    std::vector<dht::transport::Key> authorities {};
    std::string credential {};
    std::string gen_authority {};
    std::string issue_credential {};
    std::string authority_key {};
    unsigned validity_days {365};
};

/* Runs private network management commands. Returns true if one was run. */
bool
runNetworkAuthorityCommands(const dht_params& params)
{
    if (not params.gen_authority.empty()) {
        for (const auto& suffix : {".key", ".pub"}) {
            auto path = params.gen_authority + suffix;
            if (std::filesystem::exists(std::filesystem::symlink_status(path)))
                throw std::runtime_error("Refusing to overwrite network authority file: " + path);
        }
        auto authority = dht::transport::Authority::generate();
        auto pub = dht::toHex(authority.pub.data(), authority.pub.size());
        saveFile(params.gen_authority + ".key", authority.secret.data(), authority.secret.size(), true);
        saveFile(params.gen_authority + ".pub", (const uint8_t*) pub.data(), pub.size(), false);
        std::cout << "Network authority saved to " << params.gen_authority << ".key" << std::endl
                  << "Public key (--network-authority): " << pub << std::endl;
        return true;
    }
    if (not params.issue_credential.empty()) {
        if (params.authority_key.empty() or params.transport_key.empty())
            throw std::runtime_error("--issue-credential requires --authority-key and --transport-key");
        auto authority = dht::transport::Authority::fromSecret(loadTransportKey(params.authority_key));
        auto key = loadOrCreateTransportKey(params.transport_key);
        auto expiration = std::chrono::system_clock::now() + std::chrono::hours(24) * params.validity_days;
        auto credential = authority.issue(key.pub, expiration).pack();
        saveFile(params.issue_credential, credential.data(), credential.size(), false);
        std::cout << "Credential for node " << dht::transport::nodeId(key.pub) << " saved to "
                  << params.issue_credential << ", valid for " << params.validity_days << " days" << std::endl;
        return true;
    }
    return false;
}

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
    auto& transport = config.dht_config.node_config.transport;
    transport.enabled = not params.no_encryption;
    if (not params.transport_key.empty())
        transport.key = loadOrCreateTransportKey(params.transport_key);
    transport.authorities = params.authorities;
    if (not params.credential.empty())
        transport.credential = dht::transport::Credential::unpack(loadFile(params.credential));

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
        context.statusChangedCallback = [logger = context.logger](dht::NodeStatus status4, dht::NodeStatus status6) {
            logger->warn("Connectivity changed: IPv4: {}, IPv6: {}",
                         dht::statusToStr(status4),
                         dht::statusToStr(status6));
        };
        context.publicAddressChangedCb = [logger = context.logger](std::vector<dht::SockAddr> addrs) {
            logger->warn("Public address changed: {}", addrs);
        };
    }
    return {std::move(config), std::move(context)};
}

void
print_node_info(const dht::NodeInfo& info)
{
    std::cout << "OpenDHT node " << info.node_id << " running on ";
    if (info.bound4 == info.bound6)
        std::cout << "port " << info.bound4 << std::endl;
    else
        std::cout << "IPv4 port " << info.bound4 << ", IPv6 port " << info.bound6 << std::endl;
    if (info.id)
        std::cout << "Public key ID " << info.id << std::endl;
    std::cout << "Storage: " << info.storage_values << " values, " << printByteCount(info.storage_size) << std::endl;
    std::cout << "Local storage: " << info.local_storage_values << " values, "
              << printByteCount(info.local_storage_size) << std::endl;
    std::cout << "Ongoing operations: " << info.ongoing_ops << std::endl;
}

static const constexpr struct option long_options[] = {
    {"help",                   no_argument,       nullptr, 'h'},
    {"port",                   required_argument, nullptr, 'p'},
    {"net",                    required_argument, nullptr, 'n'},
    {"bootstrap",              required_argument, nullptr, 'b'},
    {"identity",               no_argument,       nullptr, 'i'},
    {"save-identity",          required_argument, nullptr, 'I'},
    {"certificate",            required_argument, nullptr, 'c'},
    {"privkey",                required_argument, nullptr, 'k'},
    {"privkey-password",       required_argument, nullptr, 'm'},
    {"verbose",                no_argument,       nullptr, 'v'},
    {"daemonize",              no_argument,       nullptr, 'd'},
    {"service",                no_argument,       nullptr, 's'},
    {"peer-discovery",         no_argument,       nullptr, 'D'},
    {"no-rate-limit",          no_argument,       nullptr, 'U'},
    {"public-stable",          no_argument,       nullptr, 'P'},
    {"persist",                required_argument, nullptr, 'f'},
    {"logfile",                required_argument, nullptr, 'l'},
    {"syslog",                 no_argument,       nullptr, 'L'},
    {"proxyserver",            required_argument, nullptr, 'S'},
    {"proxyserverssl",         required_argument, nullptr, 'e'},
    {"proxy-addr",             required_argument, nullptr, 'a'},
    {"proxy-certificate",      required_argument, nullptr, 'w'},
    {"proxy-privkey",          required_argument, nullptr, 'K'},
    {"proxy-privkey-password", required_argument, nullptr, 'M'},
    {"proxyclient",            required_argument, nullptr, 'C'},
    {"pushserver",             required_argument, nullptr, 'y'},
    {"devicekey",              required_argument, nullptr, 'z'},
    {"bundleid",               required_argument, nullptr, 'u'},
    {"version",                no_argument,       nullptr, 'V'},
    {"no-encryption",          no_argument,       nullptr, 'N'},
    {"transport-key",          required_argument, nullptr, 'T'},
    {"network-authority",      required_argument, nullptr, 'A'},
    {"network-credential",     required_argument, nullptr, 'R'},
    {"gen-network-authority",  required_argument, nullptr, 'G'},
    {"issue-credential",       required_argument, nullptr, 'Y'},
    {"authority-key",          required_argument, nullptr, 'X'},
    {"validity",               required_argument, nullptr, 'W'},
    {nullptr,                  0,                 nullptr, 0  }
};

dht_params
parseArgs(int argc, char** argv)
{
    dht_params params;
    int opt;
    std::string privkey;
    std::string proxy_privkey;
    while ((opt = getopt_long(argc, argv, "hidsvODUPp:n:b:f:l:", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'p': {
            int port_arg = atoi(optarg);
            if (port_arg >= 0 && port_arg < 0x10000)
                params.port = port_arg;
            else
                std::cout << "Invalid port: " << port_arg << std::endl;
        } break;
        case 'S': {
            int port_arg = atoi(optarg);
            if (port_arg >= 0 && port_arg < 0x10000)
                params.proxyserver = port_arg;
            else
                std::cout << "Invalid port: " << port_arg << std::endl;
        } break;
        case 'e': {
            int port_arg = atoi(optarg);
            if (port_arg >= 0 && port_arg < 0x10000)
                params.proxyserverssl = port_arg;
            else
                std::cout << "Invalid port: " << port_arg << std::endl;
        } break;
        case 'D':
            params.peer_discovery = true;
            break;
        case 'a':
            params.proxy_address = optarg;
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
            params.bootstrap = (optarg[0] == '=') ? optarg + 1 : optarg;
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
        case 'u':
            params.bundle_id = optarg;
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
        case 'N':
            params.no_encryption = true;
            break;
        case 'T':
            params.transport_key = optarg;
            break;
        case 'A':
            params.authorities.emplace_back(keyFromHex(optarg));
            break;
        case 'R':
            params.credential = optarg;
            break;
        case 'G':
            params.gen_authority = optarg;
            break;
        case 'Y':
            params.issue_credential = optarg;
            break;
        case 'X':
            params.authority_key = optarg;
            break;
        case 'W':
            params.validity_days = std::stoul(optarg);
            break;
        default:
            break;
        }
    }
    if (not privkey.empty()) {
        try {
            params.id.first = std::make_shared<dht::crypto::PrivateKey>(loadFile(privkey), params.privkey_pwd);
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
#ifndef _MSC_VER
    const char* line_read = readline(prefix);
    if (line_read && *line_read)
        add_history(line_read);

#else
    char line_read[512];
    std::cout << PROMPT;
    fgets(line_read, 512, stdin);
#endif
    return line_read ? std::string(line_read) : std::string("\0", 1);
}

struct ServiceRunner
{
    bool wait()
    {
        std::unique_lock lock(m);
        cv.wait(lock, [&] { return terminate.load(); });
        return !terminate;
    }
    void kill()
    {
        terminate = true;
        cv.notify_all();
    }

private:
    std::condition_variable cv;
    std::mutex m;
    std::atomic_bool terminate {false};
};

ServiceRunner runner;

#ifndef DISABLE_SIGNALS
void
signal_handler(int sig)
{
    switch (sig) {
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
#endif

void
setupSignals()
{
#ifndef DISABLE_SIGNALS
    signal(SIGCHLD, SIG_IGN); /* ignore child */
    signal(SIGTSTP, SIG_IGN); /* ignore tty signals */
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGHUP, signal_handler);  /* catch hangup signal */
    signal(SIGINT, signal_handler);  /* catch interrupt signal */
    signal(SIGTERM, signal_handler); /* catch kill signal */
#endif
}

void
daemonize()
{
#ifndef DISABLE_SIGNALS
    pid_t pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);

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

} // namespace tools
} // namespace dht