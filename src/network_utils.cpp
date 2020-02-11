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

UdpSocket::UdpSocket(in_port_t port, const std::shared_ptr<Logger>& l) : logger(l) {
    SockAddr bind4;
    bind4.setFamily(AF_INET);
    bind4.setPort(port);
    SockAddr bind6;
    bind6.setFamily(AF_INET6);
    bind6.setPort(port);
    std::lock_guard<std::mutex> lk(lock);
    openSockets(bind4, bind6);
}

UdpSocket::UdpSocket(const SockAddr& bind4, const SockAddr& bind6, const std::shared_ptr<Logger>& l) : logger(l)
{
    std::lock_guard<std::mutex> lk(lock);
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

    if (sendto(s, (const char*)data, size, flags, dest.get(), dest.getLength()) == -1) {
        int err = errno;
        if (logger)
            logger->d("Can't send message to %s: %s", dest.toString().c_str(), strerror(err));
        if (err == EPIPE || err == ENOTCONN || err == ECONNRESET) {
            std::lock_guard<std::mutex> lk(lock);
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
            if (logger)
                logger->e("Can't bind inet socket: %s", e.what());
        }
    }

#if 1
    bound6 = {};
    if (bind6) {
        if (bind6.getPort() == 0) {
            // Attempt to use the same port as IPv4 with IPv6
            if (auto p4 = bound4.getPort()) {
                auto b6 = bind6;
                b6.setPort(p4);
                try {
                    s6 = bindSocket(b6, bound6);
                } catch (const DhtException& e) {
                    if (logger)
                        logger->e("Can't bind inet6 socket: %s", e.what());
                }
            }
        }
        if (s6 == -1) {
            try {
                s6 = bindSocket(bind6, bound6);
            } catch (const DhtException& e) {
                if (logger)
                    logger->e("Can't bind inet6 socket: %s", e.what());
            }
        }
    }
#endif

    if (s4 == -1 && s6 == -1) {
        throw DhtException("Can't bind socket");
    }

    running = true;
    rcv_thread = std::thread([this, stop_readfd, ls4=s4, ls6=s6]() mutable {
        int selectFd = std::max({ls4, ls6, stop_readfd}) + 1;
        try {
            while (running) {
                fd_set readfds;

                FD_ZERO(&readfds);
                FD_SET(stop_readfd, &readfds);
                if(ls4 >= 0)
                    FD_SET(ls4, &readfds);
                if(ls6 >= 0)
                    FD_SET(ls6, &readfds);

                int rc = select(selectFd, &readfds, nullptr, nullptr, nullptr);
                if (rc < 0) {
                    if (errno != EINTR) {
                        if (logger)
                            logger->e("Select error: %s", strerror(errno));
                        std::this_thread::sleep_for(std::chrono::seconds(1));
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
                            if (logger)
                                logger->e("Got stop packet error: %s", strerror(errno));
                            break;
                        }
                    }
                    else if (ls4 >= 0 && FD_ISSET(ls4, &readfds))
                        rc = recvfrom(ls4, (char*)buf.data(), buf.size(), 0, (sockaddr*)&from, &from_len);
                    else if (ls6 >= 0 && FD_ISSET(ls6, &readfds))
                        rc = recvfrom(ls6, (char*)buf.data(), buf.size(), 0, (sockaddr*)&from, &from_len);
                    else
                        continue;

                    if (rc > 0) {
                        auto pkts = getNewPacket();
                        auto& pkt = pkts.front();
                        pkt.data.insert(pkt.data.end(), buf.begin(), buf.begin()+rc);
                        pkt.from = {from, from_len};
                        pkt.received = clock::now();
                        onReceived(std::move(pkts));
                    } else if (rc == -1) {
                        if (logger)
                            logger->e("Error receiving packet: %s", strerror(errno));
                        int err = errno;
                        if (err == EPIPE || err == ENOTCONN || err == ECONNRESET) {
                            if (not running) break;
                            std::unique_lock<std::mutex> lk(lock, std::try_to_lock);
                            if (lk.owns_lock()) {
                                if (not running) break;
                                if (ls4 >= 0) {
                                    close(ls4);
                                    try {
                                        ls4 = bindSocket(bound4, bound4);
                                    } catch (const DhtException& e) {
                                        if (logger)
                                            logger->e("Can't bind inet socket: %s", e.what());
                                    }
                                }
                                if (ls6 >= 0) {
                                    close(ls6);
                                    try {
                                        ls6 = bindSocket(bound6, bound6);
                                    } catch (const DhtException& e) {
                                        if (logger)
                                            logger->e("Can't bind inet6 socket: %s", e.what());
                                    }
                                }
                                if (ls4 < 0 && ls6 < 0)
                                    break;
                                s4 = ls4;
                                s6 = ls6;
                                selectFd = std::max({ls4, ls6, stop_readfd}) + 1;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            if (logger)
                logger->e("Error in UdpSocket rx thread: %s", e.what());
        }
        if (ls4 >= 0)
            close(ls4);
        if (ls6 >= 0)
            close(ls6);
        if (stop_readfd != -1)
            close(stop_readfd);
        if (stopfd != -1)
            close(stopfd);
        std::unique_lock<std::mutex> lk(lock, std::try_to_lock);
        if (lk.owns_lock()) {
            s4 = -1;
            s6 = -1;
            bound4 = {};
            bound6 = {};
            stopfd = -1;
        }
    });
}

void
UdpSocket::stop()
{
    if (running.exchange(false)) {
        auto sfd = stopfd;
        if (sfd != -1 && write(sfd, "\0", 1) == -1) {
            if (logger)
                logger->e("Can't write to stop fd");
        }
    }
}

}
}
