/*
 *  Copyright (C) 2019 Savoir-faire Linux Inc.
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
#pragma once

#include "def.h"

#include "sockaddr.h"
#include "utils.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include <functional>
#include <thread>
#include <atomic>
#include <iostream>

namespace dht {
namespace net {

int bindSocket(const SockAddr& addr, SockAddr& bound);

bool setNonblocking(int fd, bool nonblocking = true);

#ifdef _WIN32
void udpPipe(int fds[2]);
#endif
struct ReceivedPacket {
    Blob data;
    SockAddr from;
    time_point received;
};

class OPENDHT_PUBLIC DatagramSocket {
public:
    using OnReceive = std::function<void(std::unique_ptr<ReceivedPacket>&& packet)>;
    virtual ~DatagramSocket() {};

    virtual int sendTo(const SockAddr& dest, const uint8_t* data, size_t size, bool replied) = 0;

    inline void setOnReceive(OnReceive&& cb) {
        rx_callback = std::move(cb);
    }

    virtual const SockAddr& getBound(sa_family_t family = AF_UNSPEC) const = 0;
    virtual bool hasIPv4() const = 0;
    virtual bool hasIPv6() const = 0;

    in_port_t getPort(sa_family_t family = AF_UNSPEC) const {
        return getBound(family).getPort();
    }

    virtual void stop() = 0;
protected:

    inline void onReceived(std::unique_ptr<ReceivedPacket>&& packet) {
        if (rx_callback)
            rx_callback(std::move(packet));
    }
private:
    OnReceive rx_callback;
};

class OPENDHT_PUBLIC UdpSocket : public DatagramSocket {
public:
    UdpSocket(in_port_t port);
    UdpSocket(const SockAddr& bind4, const SockAddr& bind6);
    ~UdpSocket();

    int sendTo(const SockAddr& dest, const uint8_t* data, size_t size, bool replied) override;

    const SockAddr& getBound(sa_family_t family = AF_UNSPEC) const override {
        return (family == AF_INET6) ? bound6 : bound4; 
    }

    bool hasIPv4() const override { return s4 != -1; }
    bool hasIPv6() const override { return s6 != -1; }

    void stop() override;
private:
    int s4 {-1};
    int s6 {-1};
    int stopfd {-1};
    SockAddr bound4, bound6;
    std::thread rcv_thread {};
    std::atomic_bool running {false};

    void openSockets(const SockAddr& bind4, const SockAddr& bind6);
};

}
}
