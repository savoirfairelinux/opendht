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
#include "net.h"
#include "uv_utils.h"

/* An IPv4 equivalent to IN6_IS_ADDR_UNSPECIFIED */
#ifndef IN_IS_ADDR_UNSPECIFIED
#define IN_IS_ADDR_UNSPECIFIED(a) (((long int) (a)->s_addr) == 0x00000000)
#endif /* IN_IS_ADDR_UNSPECIFIED */

static constexpr std::array<uint8_t, 12> MAPPED_IPV4_PREFIX {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}};

namespace dht {

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
        uint8_t b1 = (uint8_t)(getIPv4().sin_addr.s_addr >> 24);
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
    case AF_INET:
        uint8_t b1, b2;
        b1 = (uint8_t)(getIPv4().sin_addr.s_addr >> 24);
        b2 = (uint8_t)((getIPv4().sin_addr.s_addr >> 16) & 0x0ff);
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

bool
SockAddr::isMappedIPv4() const
{
    if (getFamily() != AF_INET6)
        return false;
    const uint8_t* addr6 = reinterpret_cast<const uint8_t*>(&getIPv6().sin6_addr);
    return std::equal(MAPPED_IPV4_PREFIX.begin(), MAPPED_IPV4_PREFIX.end(), addr6);
}

SockAddr
SockAddr::getMappedIPv4() const
{
    if (getFamily() != AF_INET6)
        return *this;
    SockAddr ret;
    ret.setFamily(AF_INET);
    ret.setPort(getPort());
    auto addr6 = reinterpret_cast<const uint8_t*>(&getIPv6().sin6_addr);
    auto addr4 = reinterpret_cast<uint8_t*>(&ret.getIPv4().sin_addr);
    addr6 += MAPPED_IPV4_PREFIX.size();
    std::copy_n(addr6, sizeof(in_addr), addr4);
    return ret;
}

void get_addr_info_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    if (auto cb = static_cast<GetAddrInfoCb*>(req->data)) {
        size_t count {0};
        for (auto addr = res; addr; addr = addr->ai_next)
            count++;
        std::vector<SockAddr> ret;
        ret.reserve(count);
        for (auto addr = res; addr; addr = addr->ai_next)
            ret.emplace_back(addr->ai_addr, addr->ai_addrlen);
        (*cb)(std::move(ret));
        delete cb;
    }
    delete req;
    uv_freeaddrinfo(res);
}

void getAddrInfo(uv_loop_t* loop, const char* node, const char* service, GetAddrInfoCb&& cb)
{
    auto req = new uv_getaddrinfo_t;
    req->data = new GetAddrInfoCb(std::move(cb));
    addrinfo hints {};
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    uv_getaddrinfo(loop, req, get_addr_info_cb, node, service, &hints);
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

namespace net {

TransId
unpackTid(msgpack::object& o) {
    switch (o.type) {
    case msgpack::type::POSITIVE_INTEGER:
        return o.as<uint32_t>();
    default:
        return o.as<std::array<char, 4>>();
    }
}

}

}
