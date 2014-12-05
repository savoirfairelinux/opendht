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

#include <sys/socket.h>

#include <iostream>
#include <string>
#include <sstream>
#include <chrono>

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

int
main(int argc, char **argv)
{
    if (argc < 2)
        throw std::invalid_argument("Entrez un port");

    int i = 1;
    int p = atoi(argv[i++]);
    if (p <= 0 || p >= 0x10000)
        throw std::invalid_argument("Port invalide: " + std::to_string(p));
    in_port_t port = p;

    std::vector<sockaddr_storage> bootstrap_nodes {};
    while (i < argc) {
        addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        addrinfo *info = nullptr, *infop = nullptr;
        hints.ai_socktype = SOCK_DGRAM;
        int rc = getaddrinfo(argv[i], argv[i + 1], &hints, &info);
        if(rc != 0)
            throw std::invalid_argument(std::string("getaddrinfo: ") + gai_strerror(rc));

        i++;
        if(i >= argc)
            break;

        infop = info;
        while (infop) {
            sockaddr_storage tmp;
            memcpy(&tmp, infop->ai_addr, infop->ai_addrlen);
            bootstrap_nodes.push_back(tmp);
            infop = infop->ai_next;
        }
        freeaddrinfo(info);
        i++;
    }

    int rc = gnutls_global_init();
    if (rc != GNUTLS_E_SUCCESS)
        throw std::runtime_error(std::string("Error initializing GnuTLS: ")+gnutls_strerror(rc));

    auto ca_tmp = dht::crypto::generateIdentity("DHT Node CA");
    auto crt_tmp = dht::crypto::generateIdentity("DHT Node", ca_tmp);

    DhtRunner dht;
    dht.run(port, crt_tmp, true, [](dht::Dht::Status ipv4, dht::Dht::Status ipv6) {
        std::cout << (int)ipv4 << (int)ipv6 << std::endl;
    });

    dht.setLoggers(
        [](char const* m, va_list args){ std::cerr << red; printLog(std::cerr, m, args); std::cerr << def; },
        [](char const* m, va_list args){ std::cout << yellow; printLog(std::cout, m, args); std::cout << def; },
        [](char const* m, va_list args){ printLog(std::cout, m, args); }
    );

    dht.bootstrap(bootstrap_nodes);

    while (true)
    {
        std::string line;
        std::getline(std::cin, line);
        std::istringstream iss(line);
        std::string op, idstr, value;
        iss >> op >> idstr;

        if (op == "x" || op == "q" || op == "exit" || op == "quit") {
            break;
        }

        dht::InfoHash id {idstr};

        if (op == "g") {
            dht.get(id, [](const std::vector<std::shared_ptr<Value>>& values) {
                std::cout << "Get - found values : " << std::endl;
                for (const auto& a : values) {
                    std::cout << "\t" << *a << std::endl;
                }
                return true;
            }, [](bool ok) {
                std::cout << "Get - done : " << (ok ? "success" : "failure") << std::endl;
            });
        }
        else if (op == "l") {
            dht.listen(id, [](const std::vector<std::shared_ptr<Value>>& values) {
                std::cout << "Listen - found values : " << std::endl;
                for (const auto& a : values) {
                    std::cout << "\t" << *a << std::endl;
                }
                return true;
            });
        }
        else if (op == "p") {
            std::string v;
            iss >> v;
            dht.put(id, dht::Value {
                dht::ValueType::USER_DATA.id,
                std::vector<uint8_t> {v.begin(), v.end()}
            }, [](bool ok) {
                std::cout << "Put done !" << ok << std::endl;
            });
        }
        else if (op == "s") {
            std::string v;
            iss >> v;
            dht.putSigned(id, dht::Value {
                dht::ValueType::USER_DATA.id,
                std::vector<uint8_t> {v.begin(), v.end()}
            }, [](bool ok) {
                std::cout << "Put signed done !" << ok << std::endl;
            });
        }
        else if (op == "e") {
            std::string tostr;
            std::string v;
            iss >> tostr >> v;
            dht.putEncrypted(id, tostr, dht::Value {
                dht::ValueType::USER_DATA.id,
                std::vector<uint8_t> {v.begin(), v.end()}
            }, [](bool ok) {
                std::cout << "Put encrypted done !" << ok << std::endl;
            });
        }
        else if (op == "a") {
            in_port_t port;
            iss >> port;
            dht.put(id, dht::Value {dht::ServiceAnnouncement::TYPE.id, dht::ServiceAnnouncement(port)}, [](bool ok) {
                std::cout << "Announce done !" << ok << std::endl;
            });
        }
    }

    std::cout <<  "Stopping node..." << std::endl;
    dht.join();

    gnutls_global_deinit();

    return 0;
}
