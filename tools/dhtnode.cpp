/*
 *  Copyright (C) 2014 Savoir-Faire Linux Inc.
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

#include <opendht.h>

extern "C" {
#include <gnutls/gnutls.h>
}

#include <iostream>
#include <string>
#include <sstream>
#include <chrono>
#include <set>

using namespace dht;

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

void printLog(std::ostream& s, char const* m, va_list args) {
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

template <class DT>
static double
print_dt(DT d) {
    return std::chrono::duration_cast<std::chrono::duration<double>>(d).count();
}

int
main(int argc, char **argv)
{
    int i = 1;
    in_port_t port = 0;
    if (argc >= 2) {
        int p = atoi(argv[i]);
        if (p > 0 && p < 0x10000) {
            port = p;
            i++;
        }
    }
    if (!port)
        port = 4222;

    int rc = gnutls_global_init();
    if (rc != GNUTLS_E_SUCCESS)
        throw std::runtime_error(std::string("Error initializing GnuTLS: ")+gnutls_strerror(rc));

    auto ca_tmp = dht::crypto::generateIdentity("DHT Node CA");
    auto crt_tmp = dht::crypto::generateIdentity("DHT Node", ca_tmp);

    DhtRunner dht;
    dht.run(port, crt_tmp, true, [](dht::Dht::Status /* ipv4 */, dht::Dht::Status /* ipv6 */) {
    });

    while (i+1 < argc) {
        dht.bootstrap(argv[i], argv[i + 1]);
        i += 2;
    }

    std::cout << "OpenDht node " << dht.getNodeId() << " running on port " <<  port<<  std::endl;
    std::cout << "Public key ID " << dht.getId() << std::endl;
    std::cout << " (type 'h' or 'help' for a list of possible commands)" << std::endl << std::endl;

    while (true)
    {
        std::cout << ">> ";
        std::string line;
        std::getline(std::cin, line);
        std::istringstream iss(line);
        std::string op, idstr, value;
        iss >> op >> idstr;

        if (std::cin.eof() || op == "x" || op == "q" || op == "exit" || op == "quit") {
            break;
        } else if (op == "h" || op == "help") {
            std::cout << "OpenDht command line interface (CLI)" << std::endl;
            std::cout << "Possible commands:" << std::endl;
            std::cout << "  h, help    Print this help message." << std::endl;
            std::cout << "  q, quit    Quit the program." << std::endl;
            std::cout << "  log        Print the full DHT log." << std::endl;

            std::cout << std::endl << "Node information:" << std::endl;
            std::cout << "  ll         Print basic information and stats about the current node." << std::endl;
            std::cout << "  ls         Print basic information about current searches." << std::endl;
            std::cout << "  ld         Print basic information about currenty stored values on this node." << std::endl;
            std::cout << "  lr         Print the full current routing table of this node" << std::endl;

            std::cout << std::endl << "Operations on the DHT:" << std::endl;
            std::cout << "  g [key]               Get values at [key]." << std::endl;
            std::cout << "  l [key]               Listen for value changes at [key]." << std::endl;
            std::cout << "  p [key] [str]         Put string value at [key]." << std::endl;
            std::cout << "  s [key] [str]         Put string value at [key], signed with our generated private key." << std::endl;
            std::cout << "  e [key] [dest] [str]  Put string value at [key], encrypted for [dest] with its public key (if found)." << std::endl;
            std::cout << std::endl;
            continue;
        } else if (op == "ll") {
            unsigned good4, dubious4, cached4, incoming4;
            unsigned good6, dubious6, cached6, incoming6;
            dht.getNodesStats(AF_INET, &good4, &dubious4, &cached4, &incoming4);
            dht.getNodesStats(AF_INET6, &good6, &dubious6, &cached6, &incoming6);
            std::cout << "OpenDht node " << dht.getRoutingId() << " running on port " <<  port<<  std::endl;
            std::cout << "Public key ID " << dht.getId() << std::endl;
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
            std::cout << dht.getSearchesLog(AF_INET) << std::endl;
            continue;
        } else if (op == "log") {
            dht.setLoggers(
                [](char const* m, va_list args){ std::cerr << red; printLog(std::cerr, m, args); std::cerr << def; },
                [](char const* m, va_list args){ std::cout << yellow; printLog(std::cout, m, args); std::cout << def; },
                [](char const* m, va_list args){ printLog(std::cout, m, args); }
            );
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
            dht.get(id, [start](const std::vector<std::shared_ptr<Value>>& values) {
                auto now = std::chrono::high_resolution_clock::now();
                std::cout << "Get: found values (after " << print_dt(now-start) << "s)" << std::endl;
                for (const auto& a : values)
                    std::cout << "\t" << *a << std::endl;
                return true;
            }, [start](bool ok) {
                auto end = std::chrono::high_resolution_clock::now();
                std::cout << "Get: " << (ok ? "completed" : "failure") << " (took " << print_dt(end-start) << "s)" << std::endl;
            });
        }
        else if (op == "l") {
            std::cout << id << std::endl;
            dht.listen(id, [](const std::vector<std::shared_ptr<Value>>& values) {
                std::cout << "Listen: found values:" << std::endl;
                for (const auto& a : values)
                    std::cout << "\t" << *a << std::endl;
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
    dht.join();

    gnutls_global_deinit();

    return 0;
}
