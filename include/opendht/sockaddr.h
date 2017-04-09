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
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "def.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef __ANDROID__
typedef uint16_t in_port_t;
#endif
#else
#include <iso646.h>
#include <ws2def.h>
#include <ws2tcpip.h>
typedef uint16_t sa_family_t;
typedef uint16_t in_port_t;
#endif

namespace dht {

OPENDHT_PUBLIC std::string print_addr(const sockaddr* sa, socklen_t slen);
OPENDHT_PUBLIC std::string print_addr(const sockaddr_storage& ss, socklen_t sslen);

struct OPENDHT_PUBLIC SockAddr : public std::pair<sockaddr_storage, socklen_t> {
public:
    SockAddr() : pair<sockaddr_storage, socklen_t>::pair({},0) {}
    SockAddr(const SockAddr& o) : pair<sockaddr_storage, socklen_t>::pair({},o.second) {
        std::copy_n((uint8_t*)&o.first, o.second, (uint8_t*)&first);
    }
    SockAddr(const sockaddr* sa, socklen_t len) : pair<sockaddr_storage, socklen_t>::pair({},len) {
        if (len > sizeof(sockaddr_storage))
            throw std::runtime_error("Socket address length is too large");
        std::copy_n((uint8_t*)sa, len, (uint8_t*)&first);
    }
    SockAddr(const sockaddr_storage& ss, socklen_t len) : SockAddr((const sockaddr*)&ss, len) {}

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
    void setFamily(sa_family_t af) {
        first.ss_family = af;
        switch(af) {
        case AF_INET:
            second = sizeof(sockaddr_in);
            break;
        case AF_INET6:
            second = sizeof(sockaddr_in6);
            break;
        }
    }

    in_port_t getPort() const {
        switch(getFamily()) {
        case AF_INET:
            return ntohs(getIPv4().sin_port);
        case AF_INET6:
            return ntohs(getIPv6().sin6_port);
        default:
            return 0;
        }
    }
    void setPort(in_port_t p) {
        switch(getFamily()) {
        case AF_INET:
            getIPv4().sin_port = htons(p);
            break;
        case AF_INET6:
            getIPv6().sin6_port = htons(p);
            break;
        }
    }

    const sockaddr_in& getIPv4() const {
        return *reinterpret_cast<const sockaddr_in*>(&first);
    }
    const sockaddr_in6& getIPv6() const {
        return *reinterpret_cast<const sockaddr_in6*>(&first);
    }
    sockaddr_in& getIPv4() {
        return *reinterpret_cast<sockaddr_in*>(&first);
    }
    sockaddr_in6& getIPv6() {
        return *reinterpret_cast<sockaddr_in6*>(&first);
    }

    /**
     * Return true if address is a loopback IP address.
     */
    bool isLoopback() const;

    /**
     * Return true if address is not a public IP address.
     */
    bool isPrivate() const;

    bool isUnspecified() const;

    /**
     * A comparator to classify IP addresses, only considering the
     * first 64 bits in IPv6.
     */
    struct ipCmp {
        bool operator()(const SockAddr& a, const SockAddr& b) const {
            if (a.second != b.second)
                return a.second < b.second;
            socklen_t start, len;
            switch(a.getFamily()) {
                case AF_INET:
                    start = offsetof(sockaddr_in, sin_addr);
                    len = sizeof(in_addr);
                    break;
                case AF_INET6:
                    start = offsetof(sockaddr_in6, sin6_addr);
                    // don't consider more than 64 bits (IPv6)
                    len = 8;
                    break;
                default:
                    start = 0;
                    len = a.second;
                    break;
            }

            return std::memcmp((uint8_t*)&a.first+start, (uint8_t*)&b.first+start, len) < 0;
        }
    };

};

OPENDHT_PUBLIC bool operator==(const SockAddr& a, const SockAddr& b);

OPENDHT_PUBLIC std::string printAddr(const SockAddr& addr);

}
