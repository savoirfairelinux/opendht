/*
 *  Copyright (C) 2014-2015 Savoir-Faire Linux Inc.
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
 *
 *  Additional permission under GNU GPL version 3 section 7:
 *
 *  If you modify this program, or any covered work, by linking or
 *  combining it with the OpenSSL project's OpenSSL library (or a
 *  modified version of that library), containing parts covered by the
 *  terms of the OpenSSL or SSLeay licenses, Savoir-Faire Linux Inc.
 *  grants you additional permission to convey the resulting work.
 *  Corresponding Source for a non-source form of such a combination
 *  shall include the source code for the parts of OpenSSL used as well
 *  as that of the covered work.
 */

// Common utility methods used by C++ OpenDHT tools.

#include <string>
#include <vector>
#include <sstream>
#include <chrono>

#include <opendht/value.h> // in_port_t
#include <getopt.h>

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
        Code code;
    public:
        Modifier(Code pCode) : code(pCode) {}
        friend std::ostream&
        operator<<(std::ostream& os, const Modifier& mod) {
            return os << "\033[" << mod.code << "m";
        }
    };
}

const Color::Modifier def(Color::FG_DEFAULT);
const Color::Modifier red(Color::FG_RED);
const Color::Modifier yellow(Color::FG_YELLOW);

/**
 * Print va_list to std::ostream (used for logging)
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

/**
 * Converts std::chrono::duration to floating-point seconds.
 */
template <class DT>
static double
print_dt(DT d) {
    return std::chrono::duration_cast<std::chrono::duration<double>>(d).count();
}

/**
 * Split string with delimiter
 */
std::vector<std::string>
split(const std::string& s, char delim) {
    std::vector<std::string> elems;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim))
        elems.emplace_back(std::move(item));
    return elems;
}

static const constexpr in_port_t DHT_DEFAULT_PORT = 4222;

struct dht_params {
    in_port_t port {DHT_DEFAULT_PORT};
    bool is_bootstrap_node {false};
    std::vector<std::string> bootstrap {};
};

static const struct option long_options[] = {
   {"port",       required_argument, nullptr, 'p'},
   {"bootstrap",  optional_argument, nullptr, 'b'},
   {nullptr,      0,                 nullptr,  0}
};

dht_params
parseArgs(int argc, char **argv) {
    dht_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "p:b:", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'p': {
                int port_arg = atoi(optarg);
                if (port_arg > 0 && port_arg < 0x10000)
                    params.port = port_arg;
                else
                    std::cout << "Invalid port: " << port_arg << std::endl;
            }
            break;
        case 'b':
            if (optarg) {
                params.bootstrap = split((optarg[0] == '=') ? optarg+1 : optarg, ':');
                if (params.bootstrap.size() == 1)
                    params.bootstrap.emplace_back(std::to_string(DHT_DEFAULT_PORT));
            }
            else
                params.is_bootstrap_node = true;
            break;
        default:
            break;
        }
    }
    return params;
}
