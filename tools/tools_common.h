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

// Common utility methods used by C++ OpenDHT tools.

#include <opendht.h>
#include <getopt.h>
#include <readline/readline.h>
#include <readline/history.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>

#include <string>
#include <vector>
#include <chrono>
#include <iostream>
#include <sstream>
#include <fstream>

/**
 * Terminal colors for logging
 */
namespace Color {
    enum Code {
        FG_RED      = 31,
        FG_GREEN    = 32,
        FG_YELLOW   = 33,
        FG_BLUE     = 34,
        FG_DEFAULT  = 39,
        BG_RED      = 41,
        BG_GREEN    = 42,
        BG_BLUE     = 44,
        BG_DEFAULT  = 49
    };
    class Modifier {
        const Code code;
    public:
        constexpr Modifier(Code pCode) : code(pCode) {}
        friend std::ostream&
        operator<<(std::ostream& os, const Modifier& mod) {
            return os << "\033[" << mod.code << 'm';
        }
    };
}

constexpr const Color::Modifier def(Color::FG_DEFAULT);
constexpr const Color::Modifier red(Color::FG_RED);
constexpr const Color::Modifier yellow(Color::FG_YELLOW);

/**
 * Print va_list to std::ostream (used for logging).
 */
void
printLog(std::ostream& s, char const* m, va_list args) {
    static constexpr int BUF_SZ = 8192;
    char buffer[BUF_SZ];
    int ret = vsnprintf(buffer, sizeof(buffer), m, args);
    if (ret < 0)
        return;
    s.write(buffer, std::min(ret, BUF_SZ));
    if (ret >= BUF_SZ)
        s << "[[TRUNCATED]]";
    s.put('\n');
}

void
enableLogging(dht::DhtRunner& dht)
{
    dht.setLoggers(
        [](char const* m, va_list args){ std::cerr << red; printLog(std::cerr, m, args); std::cerr << def; },
        [](char const* m, va_list args){ std::cout << yellow; printLog(std::cout, m, args); std::cout << def; },
        [](char const* m, va_list args){ printLog(std::cout, m, args); }
    );
}

void
enableFileLogging(dht::DhtRunner& dht, const std::string& path)
{
    auto logfile = std::make_shared<std::fstream>();
    logfile->open(path, std::ios::out);

    dht.setLoggers(
        [=](char const* m, va_list args){ printLog(*logfile, m, args); },
        [=](char const* m, va_list args){ printLog(*logfile, m, args); },
        [=](char const* m, va_list args){ printLog(*logfile, m, args); }
    );
}

void
disableLogging(dht::DhtRunner& dht)
{
    dht.setLoggers(dht::NOLOG, dht::NOLOG, dht::NOLOG);
}

/**
 * Split "[host]:port" or "host:port" to pair<"host", "port">.
 */
std::pair<std::string, std::string>
splitPort(const std::string& s) {
    if (s.empty())
        return {};
    if (s[0] == '[') {
        std::size_t closure = s.find_first_of(']');
        std::size_t found = s.find_last_of(':');
        if (closure == std::string::npos)
            return {s, ""};
        if (found == std::string::npos or found < closure)
            return {s.substr(1,closure-1), ""};
        return {s.substr(1,closure-1), s.substr(found+1)};
    }
    std::size_t found = s.find_last_of(':');
    std::size_t first = s.find_first_of(':');
    if (found == std::string::npos or found != first)
        return {s, ""};
    return {s.substr(0,found), s.substr(found+1)};
}

static const constexpr in_port_t DHT_DEFAULT_PORT = 4222;

struct dht_params {
    bool help {false}; // print help and exit
    bool log {false};
    std::string logfile {};
    in_port_t port {0};
    dht::NetId network {0};
    bool is_bootstrap_node {false};
    bool generate_identity {false};
    bool daemonize {false};
    std::pair<std::string, std::string> bootstrap {};
};

static const constexpr struct option long_options[] = {
   {"help",       no_argument,       nullptr, 'h'},
   {"port",       required_argument, nullptr, 'p'},
   {"net",        required_argument, nullptr, 'n'},
   {"bootstrap",  optional_argument, nullptr, 'b'},
   {"identity",   no_argument      , nullptr, 'i'},
   {"verbose",    optional_argument, nullptr, 'v'},
   {"daemonize",  no_argument      , nullptr, 'd'},
   {nullptr,      0,                 nullptr,  0}
};

dht_params
parseArgs(int argc, char **argv) {
    dht_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hidv::p:n:b::", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'p': {
                int port_arg = atoi(optarg);
                if (port_arg >= 0 && port_arg < 0x10000)
                    params.port = port_arg;
                else
                    std::cerr << "Invalid port: " << port_arg << std::endl;
            }
            break;
        case 'n':
            params.network = strtoul(optarg, nullptr, 0);
            break;
        case 'b':
            if (optarg) {
                params.bootstrap = splitPort((optarg[0] == '=') ? optarg+1 : optarg);
                if (not params.bootstrap.first.empty() and params.bootstrap.second.empty()) {
                    std::stringstream ss;
                    ss << DHT_DEFAULT_PORT;
                    params.bootstrap.second = ss.str();
                }
            } else
                params.is_bootstrap_node = true;
            break;
        case 'h':
            params.help = true;
            break;
        case 'v':
            if (optarg)
                params.logfile = optarg;
            params.log = true;
            break;
        case 'i':
            params.generate_identity = true;
            break;
        case 'd':
            params.daemonize = true;
            break;
        case '?':
            std::cerr << "unrecognized option -- '" << static_cast<char>(optopt) << '\'' << std::endl;
            exit(EXIT_FAILURE);
        default:
            break;
        }
    }
    return params;
}

static const constexpr char* PROMPT = ">> ";

std::string
readLine(const char* prefix = PROMPT)
{
    const char* line_read = readline(prefix);
    if (line_read && *line_read)
        add_history(line_read);

    return line_read ? std::string(line_read) : std::string("\0", 1);
}

void signal_handler(int sig)
{
    switch(sig) {
    case SIGHUP:
        break;
    case SIGTERM:
        exit(EXIT_SUCCESS);
        break;
    }
}

void daemonize()
{
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);

    pid_t sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    signal(SIGCHLD,SIG_IGN); /* ignore child */
    signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGHUP,signal_handler); /* catch hangup signal */
    signal(SIGTERM,signal_handler); /* catch kill signal */
}
