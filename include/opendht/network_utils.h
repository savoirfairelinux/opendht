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
#include "log_enable.h"

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
#include <mutex>

namespace dht {
namespace net {

static const constexpr in_port_t DHT_DEFAULT_PORT = 4222;

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
        std::lock_guard<std::mutex> lk(lock);
        rx_callback = std::move(cb);
    }

    virtual bool hasIPv4() const = 0;
    virtual bool hasIPv6() const = 0;

    SockAddr getBound(sa_family_t family = AF_UNSPEC) const {
        std::lock_guard<std::mutex> lk(lock);
        return getBoundRef(family);
    }
    in_port_t getPort(sa_family_t family = AF_UNSPEC) const {
        std::lock_guard<std::mutex> lk(lock);
        return getBoundRef(family).getPort();
    }

    virtual const SockAddr& getBoundRef(sa_family_t family = AF_UNSPEC) const = 0;

    virtual void stop() = 0;
protected:

    inline void onReceived(std::unique_ptr<ReceivedPacket>&& packet) {
        std::lock_guard<std::mutex> lk(lock);
        if (rx_callback)
            rx_callback(std::move(packet));
    }
protected:
    mutable std::mutex lock;
private:
    OnReceive rx_callback;
};

class OPENDHT_PUBLIC UdpSocket : public DatagramSocket {
public:
    UdpSocket(in_port_t port, const Logger& l = {});
    UdpSocket(const SockAddr& bind4, const SockAddr& bind6, const Logger& l = {});
    ~UdpSocket();

    int sendTo(const SockAddr& dest, const uint8_t* data, size_t size, bool replied) override;

    const SockAddr& getBoundRef(sa_family_t family = AF_UNSPEC) const override {
        return (family == AF_INET6) ? bound6 : bound4;
    }

    bool hasIPv4() const override {
        std::lock_guard<std::mutex> lk(lock);
        return s4 != -1;
    }
    bool hasIPv6() const override {
        std::lock_guard<std::mutex> lk(lock);
        return s6 != -1;
    }

    void stop() override;
private:
    Logger logger;
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
