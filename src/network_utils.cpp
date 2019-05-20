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

#include "network_utils.h"

#ifdef _WIN32
#include "utils.h"
#include <io.h>
#include <string>
#include <cstring>
#define close(x) closesocket(x)
#define write(s, b, f) send(s, b, (int)strlen(b), 0)
#else
#include <fcntl.h>
#endif

#include <iostream>

namespace dht {
namespace net {

int
bindSocket(const SockAddr& addr, SockAddr& bound)
{
    bool is_ipv6 = addr.getFamily() == AF_INET6;
    int sock = socket(is_ipv6 ? PF_INET6 : PF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        throw DhtException(std::string("Can't open socket: ") + strerror(sock));
    int set = 1;
#ifdef SO_NOSIGPIPE
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (const char*)&set, sizeof(set));
#endif
    if (is_ipv6)
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&set, sizeof(set));
    net::setNonblocking(sock);
    int rc = bind(sock, addr.get(), addr.getLength());
    if (rc < 0) {
        rc = errno;
        close(sock);
        throw DhtException("Can't bind socket on " + addr.toString() + " " + strerror(rc));
    }
    sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    getsockname(sock, (sockaddr*)&ss, &ss_len);
    bound = {ss, ss_len};
    return sock;
}

bool
setNonblocking(int fd, bool nonblocking)
{
#ifdef _WIN32
    unsigned long mode = !!nonblocking;
    int rc = ioctlsocket(fd, FIONBIO, &mode);
    return rc == 0;
#else
    int rc = fcntl(fd, F_GETFL, 0);
    if (rc < 0)
        return false;
    rc = fcntl(fd, F_SETFL, nonblocking ? (rc | O_NONBLOCK) : (rc & ~O_NONBLOCK));
    return rc >= 0;
#endif
}

#ifdef _WIN32
void udpPipe(int fds[2])
{
    int lst = socket(AF_INET, SOCK_DGRAM, 0);
    if (lst < 0)
        throw DhtException(std::string("Can't open socket: ") + strerror(WSAGetLastError()));
    sockaddr_in inaddr;
    sockaddr addr;
    memset(&inaddr, 0, sizeof(inaddr));
    memset(&addr, 0, sizeof(addr));
    inaddr.sin_family = AF_INET;
    inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    inaddr.sin_port = 0;
    int yes = 1;
    setsockopt(lst, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
    int rc = bind(lst, (sockaddr*)&inaddr, sizeof(inaddr));
    if (rc < 0) {
        close(lst);
        throw DhtException("Can't bind socket on " + print_addr((sockaddr*)&inaddr, sizeof(inaddr)) + " " + strerror(rc));
    }
    socklen_t len = sizeof(addr);
    getsockname(lst, &addr, &len);
    fds[0] = lst;
    fds[1] = socket(AF_INET, SOCK_DGRAM, 0);
    connect(fds[1], &addr, len);
}
#endif

UdpSocket::UdpSocket(in_port_t port) {
    SockAddr bind4;
    bind4.setFamily(AF_INET);
    bind4.setPort(port);
    SockAddr bind6;
    bind6.setFamily(AF_INET6);
    bind6.setPort(port);
    openSockets(bind4, bind6);
}

UdpSocket::UdpSocket(const SockAddr& bind4, const SockAddr& bind6) {
    openSockets(bind4, bind6);
}

UdpSocket::~UdpSocket() {
    stop();
    if (rcv_thread.joinable())
        rcv_thread.join();
}

int
UdpSocket::sendTo(const SockAddr& dest, const uint8_t* data, size_t size, bool replied) {
    if (not dest)
        return EFAULT;

    int s;
    switch (dest.getFamily()) {
    case AF_INET:  s = s4; break;
    case AF_INET6: s = s6; break;
    default:       s = -1; break;
    }

    if (s < 0)
        return EAFNOSUPPORT;

    int flags = 0;
#ifdef MSG_CONFIRM
    if (replied)
        flags |= MSG_CONFIRM;
#endif
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif

    if (sendto(s, data, size, flags, dest.get(), dest.getLength()) == -1) {
        int err = errno;
        std::cerr << "Can't send message to " << dest.toString() << ": " << strerror(err) << std::endl;
        if (err == EPIPE) {
            auto bind4 = std::move(bound4), bind6 = std::move(bound6); 
            openSockets(bind4, bind6);
            return sendTo(dest, data, size, false);
        }
        return err;
    }
    return 0;
}

void
UdpSocket::openSockets(const SockAddr& bind4, const SockAddr& bind6)
{
    stop();
    if (rcv_thread.joinable())
        rcv_thread.join();

    int stopfds[2];
#ifndef _WIN32
    auto status = pipe(stopfds);
    if (status == -1) {
        throw DhtException(std::string("Can't open pipe: ") + strerror(errno));
    }
#else
    udpPipe(stopfds);
#endif
    int stop_readfd = stopfds[0];
    stopfd = stopfds[1];

    s4 = -1;
    s6 = -1;

    bound4 = {};
    if (bind4) {
        try {
            s4 = bindSocket(bind4, bound4);
        } catch (const DhtException& e) {
            std::cerr << "Can't bind inet socket: " << e.what() << std::endl;
        }
    }

#if 1
    bound6 = {};
    if (bind6) {
        try {
            s6 = bindSocket(bind6, bound6);
        } catch (const DhtException& e) {
            std::cerr << "Can't bind inet6 socket: " << e.what() << std::endl;
        }
    }
#endif

    if (s4 == -1 && s6 == -1) {
        throw DhtException("Can't bind socket");
    }

    running = true;
    rcv_thread = std::thread([this, stop_readfd]() {
        try {
            while (running) {
                fd_set readfds;

                FD_ZERO(&readfds);
                FD_SET(stop_readfd, &readfds);
                if(s4 >= 0)
                    FD_SET(s4, &readfds);
                if(s6 >= 0)
                    FD_SET(s6, &readfds);

                int selectFd = std::max({s4, s6, stop_readfd}) + 1;
                int rc = select(selectFd, &readfds, nullptr, nullptr, nullptr);
                if (rc < 0) {
                    if (errno != EINTR) {
                        perror("select");
                        std::this_thread::sleep_for( std::chrono::seconds(1) );
                    }
                }

                if (not running)
                    break;

                if (rc > 0) {
                    std::array<uint8_t, 1024 * 64> buf;
                    sockaddr_storage from;
                    socklen_t from_len = sizeof(from);

                    if (FD_ISSET(stop_readfd, &readfds)) {
                        if (recv(stop_readfd, (char*)buf.data(), buf.size(), 0) < 0) {
                            std::cerr << "Got stop packet error: " << strerror(errno) << std::endl;
                            break;
                        }
                    }
                    else if (s4 >= 0 && FD_ISSET(s4, &readfds))
                        rc = recvfrom(s4, (char*)buf.data(), buf.size(), 0, (sockaddr*)&from, &from_len);
                    else if (s6 >= 0 && FD_ISSET(s6, &readfds))
                        rc = recvfrom(s6, (char*)buf.data(), buf.size(), 0, (sockaddr*)&from, &from_len);
                    else
                        continue;

                    if (rc > 0) {
                        auto pkt = std::unique_ptr<ReceivedPacket>(new ReceivedPacket);
                        pkt->data = {buf.begin(), buf.begin()+rc};
                        pkt->from = {from, from_len};
                        pkt->received = clock::now();
                        onReceived(std::move(pkt));
                    } else if (rc == -1) {
                        std::cerr << "Error receiving packet: " << strerror(errno) << std::endl;
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in DHT networking thread: " << e.what() << std::endl;
        }
        if (s4 >= 0)
            close(s4);
        if (s6 >= 0)
            close(s6);
        s4 = -1;
        s6 = -1;
        bound4 = {};
        bound6 = {};
        if (stop_readfd != -1)
            close(stop_readfd);
        if (stopfd != -1)
            close(stopfd);
        stopfd = -1;
    });
}

void
UdpSocket::stop()
{
    if (running.exchange(false)) {
        auto sfd = stopfd;
        if (sfd != -1 && write(sfd, "\0", 1) == -1) {
            std::cerr << "can't write to stop fd" << std::endl;
        }
    }
}

}
}
