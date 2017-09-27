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

#include <string>
#include <memory>

#include <cstring>
#include <cstddef>

namespace dht {

OPENDHT_PUBLIC std::string print_addr(const sockaddr* sa, socklen_t slen);
OPENDHT_PUBLIC std::string print_addr(const sockaddr_storage& ss, socklen_t sslen);

class OPENDHT_PUBLIC SockAddr {
public:
    SockAddr() {}
    SockAddr(const SockAddr& o) {
        len = o.len;
        if (len) {
            addr.reset((sockaddr*)std::malloc(len));
            std::memcpy((uint8_t*)addr.get(), (const uint8_t*)o.get(), len);
        } else
            addr.reset();
    }
    SockAddr(SockAddr&& o) : len(o.len), addr(std::move(o.addr)) {
        o.len = 0;
    }
    SockAddr(const sockaddr* sa, socklen_t length) {
        if (length > sizeof(sockaddr_storage))
            throw std::runtime_error("Socket address length is too large");
        len = length;
        addr.reset((sockaddr*)std::malloc(len));
        std::memcpy((uint8_t*)get(), (const uint8_t*)sa, len);
    }
    SockAddr(const sockaddr_storage& ss, socklen_t len) : SockAddr((const sockaddr*)&ss, len) {}

    bool operator<(const SockAddr& o) const {
        if (len != o.len)
            return len < o.len;
        return std::memcmp((uint8_t*)get(), (uint8_t*)o.get(), len) < 0;
    }

    bool equals(const SockAddr& o) const {
        return len == o.len
            && std::memcmp((uint8_t*)get(), (uint8_t*)o.get(), len) == 0;
    }
    SockAddr& operator=(const SockAddr& o) {
        if (len != o.len) {
            len = o.len;
            addr.reset((sockaddr*)std::realloc(addr.release(), len));
        }
        std::memcpy((uint8_t*)get(), (const uint8_t*)o.get(), len);
        return *this;
    }
    SockAddr& operator=(SockAddr&& o) {
        len = o.len;
        o.len = 0;
        addr = std::move(o.addr);
        return *this;
    }

    std::string toString() const {
        return print_addr(get(), getLength());
    }
    sa_family_t getFamily() const { return len > sizeof(sa_family_t) ? addr->sa_family : AF_UNSPEC; }
    void setFamily(sa_family_t af) {
        socklen_t new_length;
        switch(af) {
        case AF_INET:
            new_length = sizeof(sockaddr_in);
            break;
        case AF_INET6:
            new_length = sizeof(sockaddr_in6);
            break;
        default:
            new_length = 0;
        }
        if (new_length != len) {
            len = new_length;
            if (len) addr.reset((sockaddr*)std::calloc(len, 1));
            else     addr.reset();
        }
        if (len > sizeof(sa_family_t))
            addr->sa_family = af;
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

    socklen_t getLength() const { return len; }
    explicit operator bool() const noexcept {
        return len;
    }

    const sockaddr* get() const { return addr.get(); }
    sockaddr* get() { return addr.get(); }

    const sockaddr_in& getIPv4() const {
        return *reinterpret_cast<const sockaddr_in*>(get());
    }
    const sockaddr_in6& getIPv6() const {
        return *reinterpret_cast<const sockaddr_in6*>(get());
    }
    sockaddr_in& getIPv4() {
        return *reinterpret_cast<sockaddr_in*>(get());
    }
    sockaddr_in6& getIPv6() {
        return *reinterpret_cast<sockaddr_in6*>(get());
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
            if (a.len != b.len)
                return a.len < b.len;
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
                    len = a.len;
                    break;
            }
            return std::memcmp((uint8_t*)a.get()+start,
                               (uint8_t*)b.get()+start, len) < 0;
        }
    };
private:
    socklen_t len {0};
    struct free_delete { void operator()(void* p) { std::free(p); } };
    std::unique_ptr<sockaddr, free_delete> addr {};
};

OPENDHT_PUBLIC bool operator==(const SockAddr& a, const SockAddr& b);

}
