/*
 *  Copyright (C) 2016 Savoir-faire Linux Inc.
 *  Author : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#ifndef _WIN32
#include <sys/socket.h>
#else
#include <ws2def.h>
#include <ws2tcpip.h>
#endif

namespace dht {

std::string print_addr(const sockaddr* sa, socklen_t slen);
std::string print_addr(const sockaddr_storage& ss, socklen_t sslen);

struct SockAddr : public std::pair<sockaddr_storage, socklen_t> {
public:
    using std::pair<sockaddr_storage, socklen_t>::pair;

    SockAddr() : pair<sockaddr_storage, socklen_t>::pair({},0) {}
    SockAddr(const SockAddr& o) : pair<sockaddr_storage, socklen_t>::pair({},o.second) {
        std::copy_n((uint8_t*)&o.first, o.second, (uint8_t*)&first);
    }
    SockAddr(const sockaddr* sa, socklen_t len) : pair<sockaddr_storage, socklen_t>::pair({},len) {
        if (len > sizeof(sockaddr_storage))
            throw std::runtime_error("Socket address length is too large");
        std::copy_n((uint8_t*)sa, len, (uint8_t*)&first);
    }

    bool operator<(const SockAddr& o) const {
        if (second != o.second)
            return second < o.second;
        return std::memcmp((uint8_t*)&first, (uint8_t*)&o.first, second) < 0;
    }

    bool equals(const SockAddr& o) const {
        return second == o.second
            && std::memcmp((uint8_t*)&first, (uint8_t*)&o.first, second) == 0;
    }
    SockAddr& operator=(const SockAddr& o) {
        std::copy_n((const uint8_t*)&o.first, o.second, (uint8_t*)&first);
        second = o.second;
        return *this;
    }

    std::string toString() const {
        return print_addr(first, second);
    }
    sa_family_t getFamily() const { return second > sizeof(sa_family_t) ? first.ss_family : AF_UNSPEC; }
};

bool operator==(const SockAddr& a, const SockAddr& b);

std::string printAddr(const SockAddr& addr);

}
