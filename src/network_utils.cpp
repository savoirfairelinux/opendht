/*
 *  Copyright (C) 2014-2022 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include "network_utils.h"

#ifdef _WIN32
#include "utils.h"
#include <io.h>
#include <string>
#include <cstring>
#define close(x) closesocket(x)
#define write(s, b, f) send(s, b, (int)strlen(b), 0)
#else
#include <sys/select.h>
#include <fcntl.h>
#endif

#include <iostream>

namespace dht {
namespace net {
/*

UdpSocket::UdpSocket(in_port_t port, const std::shared_ptr<Logger>& l)
    : logger(l)
{
    asio::io_service io_service;
    asio::ip::udp::endpoint endpoint(asio::ip::udp::v4(), port);
    s4.open(endpoint.protocol());
    s4.set_option(asio::ip::udp::socket::reuse_address(true));
    s4.bind(endpoint);
    s4.non_blocking(true);

    try {
        asio::ip::udp::endpoint endpoint(asio::ip::udp::v6(), port);
        s6.open(endpoint.protocol());
        s6.set_option(asio::ip::udp::socket::reuse_address(true));
        s6.bind(endpoint);
        s6.non_blocking(true);
    } catch (...) {
    }
}

UdpSocket::UdpSocket(const SockAddr& bind4, const SockAddr& bind6, const std::shared_ptr<Logger>& l)
    : logger(l)
{
    if (bind4.isSet()) {
        asio::io_service io_service;
        asio::ip::udp::endpoint endpoint(asio::ip::udp::v4(), bind4.getPort());
        s4.open(endpoint.protocol());
        s4.set_option(asio::ip::udp::socket::reuse_address(true));
        s4.bind(endpoint);
        s4.non_blocking(true);
    }

    if (bind6.isSet()) {
        try {
            asio::io_service io_service;
            asio::ip::udp::endpoint endpoint(asio::ip::udp::v6(), bind6.getPort());
            s6.open(endpoint.protocol());
            s6.set_option(asio::ip::udp::socket::reuse_address(true));
            s6.bind(endpoint);
            s6.non_blocking(true);
        } catch (...) {
        }
    }
}

UdpSocket::~UdpSocket()
{
    stop();
}

int UdpSocket::sendTo(const SockAddr& dest, const uint8_t* data, size_t size, bool replied)
{
    asio::ip::udp::socket* sock = nullptr;
    if (dest.isV4())
        sock = &s4;
    else if (dest.isV6())
        sock = &s6;
    else
        return -1;

    try {
        asio::ip::udp::endpoint endpoint(dest.toAsio());
        return sock->send_to(asio::buffer(data, size), endpoint);
    } catch (...) {
        return -1;
    }
}

void UdpSocket::stop()
{
    s4.cancel();
    s4.close();
    s6.cancel();
    s6.close();
}
*/

}
}
