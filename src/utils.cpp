/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
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

#include "utils.h"
#include "sockaddr.h"
#include "default_types.h"

/* An IPv4 equivalent to IN6_IS_ADDR_UNSPECIFIED */
#ifndef IN_IS_ADDR_UNSPECIFIED
#define IN_IS_ADDR_UNSPECIFIED(a) (((long int) (a)->s_addr) == 0x00000000)
#endif /* IN_IS_ADDR_UNSPECIFIED */

namespace dht {

std::vector<SockAddr>
SockAddr::resolve(const std::string& host, const std::string& service)
{
    std::vector<SockAddr> ips {};
    if (host.empty())
        return ips;

    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* info = nullptr;
    int rc = getaddrinfo(host.c_str(), service.empty() ? nullptr : service.c_str(), &hints, &info);
    if(rc != 0)
        throw std::invalid_argument(std::string("Error: `") + host + ":" + service + "`: " + gai_strerror(rc));

    addrinfo* infop = info;
    while (infop) {
        ips.emplace_back(infop->ai_addr, infop->ai_addrlen);
        infop = infop->ai_next;
    }
    freeaddrinfo(info);
    return ips;
}


std::string
print_addr(const sockaddr* sa, socklen_t slen)
{
    char hbuf[NI_MAXHOST];
    char sbuf[NI_MAXSERV];
    std::stringstream out;
    if (!getnameinfo(sa, slen, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV)) {
        if (sa->sa_family == AF_INET6)
            out << "[" << hbuf << "]";
        else
            out << hbuf;
        if (std::strcmp(sbuf, "0"))
            out << ":" << sbuf;
    } else
        out << "[invalid address]";
    return out.str();
}

std::string
print_addr(const sockaddr_storage& ss, socklen_t sslen)
{
    return print_addr((const sockaddr*)&ss, sslen);
}

bool
SockAddr::isUnspecified() const
{
    switch (getFamily()) {
    case AF_INET:
        return IN_IS_ADDR_UNSPECIFIED(&getIPv4().sin_addr);
    case AF_INET6:
        return IN6_IS_ADDR_UNSPECIFIED(reinterpret_cast<const in6_addr*>(&getIPv6().sin6_addr));
    default:
        return true;
    }
}

bool
SockAddr::isLoopback() const
{
    switch (getFamily()) {
    case AF_INET: {
        auto addr_host = ntohl(getIPv4().sin_addr.s_addr);
        uint8_t b1 = (uint8_t)(addr_host >> 24);
        return b1 == 127;
    }
    case AF_INET6:
        return IN6_IS_ADDR_LOOPBACK(reinterpret_cast<const in6_addr*>(&getIPv6().sin6_addr));
    default:
        return false;
    }
}

bool
SockAddr::isPrivate() const
{
    if (isLoopback()) {
        return true;
    }
    switch (getFamily()) {
    case AF_INET: {
        auto addr_host = ntohl(getIPv4().sin_addr.s_addr);
        uint8_t b1, b2;
        b1 = (uint8_t)(addr_host >> 24);
        b2 = (uint8_t)((addr_host >> 16) & 0x0ff);
        // 10.x.y.z
        if (b1 == 10)
            return true;
        // 172.16.0.0 - 172.31.255.255
        if ((b1 == 172) && (b2 >= 16) && (b2 <= 31))
            return true;
        // 192.168.0.0 - 192.168.255.255
        if ((b1 == 192) && (b2 == 168))
            return true;
        return false;
    }
    case AF_INET6: {
        const uint8_t* addr6 = reinterpret_cast<const uint8_t*>(&getIPv6().sin6_addr);
        if (addr6[0] == 0xfc)
            return true;
        return false;
    }
    default:
        return false;
    }
}

bool operator==(const SockAddr& a, const SockAddr& b) {
    return a.equals(b);
}

time_point from_time_t(std::time_t t) {
    return clock::now() + (std::chrono::system_clock::from_time_t(t) - std::chrono::system_clock::now());
}

std::time_t to_time_t(time_point t) {
    return std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now() +
            std::chrono::duration_cast<std::chrono::system_clock::duration>(t - clock::now()));
}

Blob
unpackBlob(msgpack::object& o) {
    switch (o.type) {
    case msgpack::type::BIN:
        return {o.via.bin.ptr, o.via.bin.ptr+o.via.bin.size};
    case msgpack::type::STR:
        return {o.via.str.ptr, o.via.str.ptr+o.via.str.size};
    case msgpack::type::ARRAY: {
        Blob ret(o.via.array.size);
        std::transform(o.via.array.ptr, o.via.array.ptr+o.via.array.size, ret.begin(), [](const msgpack::object& b) {
            return b.as<uint8_t>();
        });
        return ret;
    }
    default:
        throw msgpack::type_error();
    }
}

msgpack::unpacked
unpackMsg(Blob b) {
    return msgpack::unpack((const char*)b.data(), b.size());
}

msgpack::object*
findMapValue(msgpack::object& map, const std::string& key) {
    if (map.type != msgpack::type::MAP) throw msgpack::type_error();
    for (unsigned i = 0; i < map.via.map.size; i++) {
        auto& o = map.via.map.ptr[i];
        if (o.key.type == msgpack::type::STR && o.key.as<std::string>() == key)
            return &o.val;
    }
    return nullptr;
}

}
