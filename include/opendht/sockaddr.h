/*
 *  Copyright (C) 2016-2019 Savoir-faire Linux Inc.
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
#include <arpa/inet.h>
#ifdef __ANDROID__
typedef uint16_t in_port_t;
#endif
#else
#include <iso646.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2def.h>
#include <ws2tcpip.h>
typedef uint16_t sa_family_t;
typedef uint16_t in_port_t;
#endif

#include <string>
#include <memory>
#include <vector>
#include <stdlib.h>

#include <cstring>
#include <cstddef>

namespace dht {

OPENDHT_PUBLIC std::string print_addr(const sockaddr* sa, socklen_t slen);
OPENDHT_PUBLIC std::string print_addr(const sockaddr_storage& ss, socklen_t sslen);

/**
 * A Socket Address (sockaddr*), with abstraction for IPv4, IPv6 address families.
 */
class OPENDHT_PUBLIC SockAddr {
public:
    SockAddr() {}
    SockAddr(const SockAddr& o) {
        set(o.get(), o.getLength());
    }
    SockAddr(SockAddr&& o) noexcept : len(o.len), addr(std::move(o.addr)) {
        o.len = 0;
    }

    /**
     * Build from existing address.
     */
    SockAddr(const sockaddr* sa, socklen_t length) {
        if (length > sizeof(sockaddr_storage))
            throw std::runtime_error("Socket address length is too large");
        set(sa, length);
    }
    SockAddr(const sockaddr* sa) {
        socklen_t len = 0;
        if (sa) {
            if (sa->sa_family == AF_INET)
                len = sizeof(sockaddr_in);
            else if(sa->sa_family == AF_INET6)
                len = sizeof(sockaddr_in6);
            else
                throw std::runtime_error("Unknown address family");
        }
        set(sa, len);
    }

    /**
     * Build from an existing sockaddr_storage structure.
     */
    SockAddr(const sockaddr_storage& ss, socklen_t len) : SockAddr((const sockaddr*)&ss, len) {}

    static std::vector<SockAddr> resolve(const std::string& host, const std::string& service = {});

    bool operator<(const SockAddr& o) const {
        if (len != o.len)
            return len < o.len;
        return std::memcmp((const uint8_t*)get(), (const uint8_t*)o.get(), len) < 0;
    }

    bool equals(const SockAddr& o) const {
        return len == o.len
            && std::memcmp((const uint8_t*)get(), (const uint8_t*)o.get(), len) == 0;
    }
    SockAddr& operator=(const SockAddr& o) {
        set(o.get(), o.getLength());
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

    /**
     * Returns the address family or AF_UNSPEC if the address is not set.
     */
    sa_family_t getFamily() const { return len ? addr->sa_family : AF_UNSPEC; }

    /**
     * Resize the managed structure to the appropriate size (if needed),
     * in which case the sockaddr structure is cleared to zero,
     * and set the address family field (sa_family).
     */
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
            if (len) addr.reset((sockaddr*)::calloc(len, 1));
            else     addr.reset();
        }
        if (len > sizeof(sa_family_t))
            addr->sa_family = af;
    }

    /**
     * Set Network Interface to any
     */
    void setAny() {
        auto family = getFamily();
        switch(family) {
        case AF_INET:
            getIPv4().sin_addr.s_addr = htonl(INADDR_ANY);
            break;
        case AF_INET6:
            getIPv6().sin6_addr = in6addr_any;
            break;
        }
    }

    /**
     * Retreive the port (in host byte order) or 0 if the address is not
     * of a supported family.
     */
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
    /**
     * Set the port. The address must be of a supported family.
     * @param p The port in host byte order.
     */
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

    /**
     * Set the address part of the socket address from a numeric IP address (string representation).
     * Family must be already set. Throws in case of parse failue.
     */
    void setAddress(const char* address);

    /**
     * Returns the accessible byte length at the pointer returned by #get().
     * If zero, #get() returns null.
     */
    socklen_t getLength() const { return len; }

    /**
     * An address is defined to be true if its length is not zero.
     */
    explicit operator bool() const noexcept {
        return len;
    }

    /**
     * Returns the address to the managed sockaddr structure.
     * The accessible length is returned by #getLength().
     */
    const sockaddr* get() const { return addr.get(); }

    /**
     * Returns the address to the managed sockaddr structure.
     * The accessible length is returned by #getLength().
     */
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

    bool isMappedIPv4() const;
    SockAddr getMappedIPv4() const;

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
    struct free_delete { void operator()(void* p) { ::free(p); } };
    std::unique_ptr<sockaddr, free_delete> addr {};

    void set(const sockaddr* sa, socklen_t length) {
        if (len != length) {
            len = length;
            if (len) addr.reset((sockaddr*)::malloc(len));
            else     addr.reset();
        }
        if (len)
            std::memcpy((uint8_t*)get(), (const uint8_t*)sa, len);
    }

};

OPENDHT_PUBLIC bool operator==(const SockAddr& a, const SockAddr& b);

}
