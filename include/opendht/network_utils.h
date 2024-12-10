/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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
#include <list>

namespace dht {
namespace net {

static const constexpr in_port_t DHT_DEFAULT_PORT = 4222;
static const constexpr size_t RX_QUEUE_MAX_SIZE = 1024 * 16;
static const constexpr std::chrono::milliseconds RX_QUEUE_MAX_DELAY(650);

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
using PacketList = std::list<ReceivedPacket>;

class OPENDHT_PUBLIC DatagramSocket {
public:
    /** A function that takes a list of new received packets and
     *  optionally returns consumed packets for recycling.
     **/
    using OnReceive = std::function<PacketList(PacketList&& packets)>;
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

    /** Virtual resolver mothod allows to implement custom resolver */
    virtual std::vector<SockAddr> resolve(const std::string& host, const std::string& service = {}) {
        return SockAddr::resolve(host, service);
    }

    virtual void stop() = 0;
protected:

    PacketList getNewPacket() {
        PacketList pkts;
        if (toRecycle_.empty()) {
            pkts.emplace_back();
        } else {
            auto begIt = toRecycle_.begin();
            auto begItNext = std::next(begIt);
            pkts.splice(pkts.end(), toRecycle_, begIt, begItNext);
        }
        return pkts;
    }

    inline void onReceived(PacketList&& packets) {
        std::lock_guard<std::mutex> lk(lock);
        if (rx_callback) {
            auto r = rx_callback(std::move(packets));
            if (not r.empty() and toRecycle_.size() < RX_QUEUE_MAX_SIZE)
                toRecycle_.splice(toRecycle_.end(), std::move(r));
        }
    }
protected:
    mutable std::mutex lock;
private:
    OnReceive rx_callback;
    PacketList toRecycle_;
};

class OPENDHT_PUBLIC UdpSocket : public DatagramSocket {
public:
    UdpSocket(in_port_t port, const std::shared_ptr<Logger>& l = {});
    UdpSocket(const SockAddr& bind4, const SockAddr& bind6, const std::shared_ptr<Logger>& l = {});
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
    std::shared_ptr<Logger> logger;
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
