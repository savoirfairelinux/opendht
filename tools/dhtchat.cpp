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

#ifndef _WIN32
#include <sys/socket.h>
#else
#include <ws2tcpip.h>
#endif

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <chrono>
#include <set>

#include <ctime>

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

const std::string getDateTime(const std::chrono::system_clock::time_point& t) {
    auto now = std::chrono::system_clock::to_time_t(t);
    struct tm tstruct = *localtime(&now);
    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return buf;
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

    std::vector<std::pair<sockaddr_storage, socklen_t>> bootstrap_nodes {};
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
            std::copy_n((uint8_t*)infop->ai_addr, infop->ai_addrlen, (uint8_t*)&tmp);
            bootstrap_nodes.emplace_back(tmp, infop->ai_addrlen);
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
    dht.run(port, crt_tmp, true, [](dht::Dht::Status /* ipv4 */, dht::Dht::Status /* ipv6 */) {
    });
    /*dht.setLoggers(
        [](char const* m, va_list args){ std::cerr << red; printLog(std::cerr, m, args); std::cerr << def; },
        [](char const* m, va_list args){ std::cout << yellow; printLog(std::cout, m, args); std::cout << def; },
        [](char const* m, va_list args){ printLog(std::cout, m, args); }
    );
*/
    dht.bootstrap(bootstrap_nodes);

    std::cout << "OpenDht node " << dht.getRoutingId() << " running on port " <<  port<<  std::endl;
    std::cout << "Public key ID " << dht.getId() << std::endl;
    std::cout << "  type 'c {hash}' to join a channel" << std::endl << std::endl;

    bool connected {false};
    InfoHash room;
    const InfoHash myid = dht.getId();

    std::random_device rdev;
    std::uniform_int_distribution<Value::Id> rand_id {};

    auto rcv_msg = [&](const std::vector<std::shared_ptr<Value>>& values) {
            for (const auto& a : values) {
                try {
                    if (a->owner.getId() == myid)
                        continue;
                    if (a->isEncrypted())
                        std::cout << a->owner.getId().toString() << " : [encrypted]" << std::endl;
                    else {
                        Blob msg_raw = dht::DhtMessage(a->data).getMessage();
                        auto b = msg_raw.cbegin();
                        auto e = msg_raw.cend();
                        auto date = deserialize<std::chrono::system_clock::time_point>(b, e);
                        auto dt = std::chrono::system_clock::now() - date;
                        std::string msg {b, e};
                        std::cout << a->owner.getId().toString() << " at " << getDateTime(date) << " (took " << std::chrono::duration_cast<std::chrono::duration<double>>(dt).count() << "s) : " << msg << std::endl;
                    }
                } catch (const std::exception& e) {}
            }
            return true;
        };

    while (true)
    {
        std::cout << ">> ";
        std::string line;
        std::getline(std::cin, line);
        static constexpr dht::InfoHash INVALID_ID {};

        if (std::cin.eof()) {
            break;
        }

        if (not connected) {
            std::istringstream iss(line);
            std::string op, idstr, p;
            iss >> op >> idstr;
            if (op  == "x" || op == "q" || op == "exit" || op == "quit")
                break;
            else if (op == "c") {
                room = idstr;
                if (room == INVALID_ID) {
                    std::cout << "Syntax error: invalid InfoHash." << std::endl;
                    continue;
                }
                dht.listen(room, rcv_msg, dht::DhtMessage::ServiceFilter(dht::DhtMessage::Service::IM_MESSAGE));
                connected = true;
            } else if (op == "p") {
                iss >> p;
                room = idstr;
                InfoHash peer {p};
                std::vector<uint8_t> data;
                
            }
        } else {
            auto id = rand_id(rdev);
            std::vector<uint8_t> data;
            serialize<std::chrono::system_clock::time_point>(std::chrono::system_clock::now(), data);
            data.insert(data.end(), line.begin(), line.end());
            dht.putSigned(room, dht::Value {
                dht::DhtMessage::TYPE,
                dht::DhtMessage(
                    dht::DhtMessage::Service::IM_MESSAGE,
                    data
                ),
                id
            }, [id](bool /*ok*/) {
                //dht.cancelPut(room, id);
                //std::cout << "Put signed done !" << ok << std::endl;
            });
        }
    }

    std::cout << std::endl <<  "Stopping node..." << std::endl;
    dht.join();

    gnutls_global_deinit();

    return 0;
}
