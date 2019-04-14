/*
 *  Copyright (C) 2014-2019 Savoir-faire Linux Inc.
 *  Author(s) : Mingrui Zhang <mingrui.zhang@savoirfairelinux.com>
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

#include "peer_discovery.h"
#include "network_utils.h"

#ifdef _WIN32
#include <Ws2tcpip.h> // needed for ip_mreq definition for multicast
#include <Windows.h>
#else
#include <sys/types.h>
#endif
#include <fcntl.h>

namespace dht {

constexpr char MULTICAST_ADDRESS_IPV4[10] = "224.0.0.1";
constexpr char MULTICAST_ADDRESS_IPV6[8] = "ff05::2"; // Site-local multicast

PeerDiscovery::PeerDiscovery(sa_family_t domain, in_port_t port)
    : domain_(domain), port_(port), sockfd_(initialize_socket(domain))
{
    socketJoinMulticast(sockfd_, domain);
}

PeerDiscovery::~PeerDiscovery()
{
    if (sockfd_ != -1)
        close(sockfd_);

#ifdef _WIN32
    WSACleanup();
#endif
}

int
PeerDiscovery::initialize_socket(sa_family_t domain)
{
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(0x0101, &wsaData)) {
        throw std::runtime_error(std::string("Can't initialize Winsock2 ") + strerror(errno));
    }
#endif

    int sockfd = socket(domain, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        throw std::runtime_error(std::string("Socket Creation Error: ") + strerror(errno));
    }
    net::set_nonblocking(sockfd);
    return sockfd;
}

void
PeerDiscovery::listener_setup()
{
    SockAddr sockAddrListen_;
    sockAddrListen_.setFamily(domain_);
    sockAddrListen_.setPort(port_);
    sockAddrListen_.setAny();

    unsigned int opt = 1;
    if (setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
       std::cerr << "setsockopt SO_REUSEADDR failed: " << strerror(errno) << std::endl;
    }
    if (setsockopt(sockfd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
       std::cerr << "setsockopt SO_REUSEPORT failed: " << strerror(errno) << std::endl;
    }

    // bind to receive address
    if (bind(sockfd_, sockAddrListen_.get(), sockAddrListen_.getLength()) < 0){
        throw std::runtime_error(std::string("Error binding socket: ") + strerror(errno));
    }
}

void
PeerDiscovery::socketJoinMulticast(int sockfd, sa_family_t family)
{
    switch (family)
    {
    case AF_INET:{
        ip_mreq config_ipv4;

        //This option can be used to set the interface for sending outbound
        //multicast datagrams from the sockets application.
        config_ipv4.imr_interface.s_addr = htonl(INADDR_ANY);
        if( setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, &config_ipv4.imr_interface, sizeof( struct in_addr )) < 0 ) {
            throw std::runtime_error(std::string("Bound Network Interface IPv4 Error: ") + strerror(errno));
        }

        //The IP_MULTICAST_TTL socket option allows the application to primarily
        //limit the lifetime of the packet in the Internet and prevent it from circulating indefinitely
        unsigned char ttl4 = 20;
        if( setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl4, sizeof( ttl4 )) < 0 ) {
            throw std::runtime_error(std::string("TTL Sockopt Error: ") + strerror(errno));
        }

        // config the listener to be interested in joining in the multicast group
        config_ipv4.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDRESS_IPV4);
        config_ipv4.imr_interface.s_addr = htonl(INADDR_ANY);
        if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&config_ipv4, sizeof(config_ipv4)) < 0){
            throw std::runtime_error(std::string(" Member Addition IPv4 Error: ") + strerror(errno));
        }
        break;
    }
    case AF_INET6: {
        ipv6_mreq config_ipv6;

        /* unsigned int outif = 0;
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &outif, sizeof(outif)) < 0) {
            std::cerr << "Can't assign multicast interface: " << strerror(errno) << std::endl;
        } */

        unsigned int ttl6 = 20;
        if( setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl6, sizeof( ttl6 )) < 0 ) {
            throw std::runtime_error(std::string("Hop Count Set Error: ") + strerror(errno));
        }

        config_ipv6.ipv6mr_interface = 0;
        inet_pton(AF_INET6, MULTICAST_ADDRESS_IPV6, &config_ipv6.ipv6mr_multiaddr);
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &config_ipv6, sizeof(config_ipv6)) < 0){
            throw std::runtime_error(std::string("Member Addition IPv6 Error: ") + strerror(errno));
        }
        break;
    }
    }
}

void
PeerDiscovery::sendTo(uint8_t *buf, size_t buf_size)
{
    ssize_t nbytes = sendto(
        sockfd_,
        buf,
        buf_size,
        0,
        sockAddrSend_.get(),
        sockAddrSend_.getLength()
    );
    if (nbytes < 0) {
        throw std::runtime_error(std::string("Error sending packet: ") + strerror(errno));
    }
}

SockAddr
PeerDiscovery::recvFrom(uint8_t *buf, size_t& buf_size)
{
    sockaddr_storage storeage_recv;
    socklen_t sa_len = sizeof(storeage_recv);

    ssize_t nbytes = recvfrom(
        sockfd_,
        buf,
        buf_size,
        0,
        (sockaddr*)&storeage_recv,
        &sa_len
    );
    if (nbytes < 0) {
        throw std::runtime_error(std::string("Error receiving packet: ") + strerror(errno));
    }

    buf_size = nbytes;
    SockAddr ret {storeage_recv, sa_len};
    return ret;
}

void
PeerDiscovery::sender_setup(const dht::InfoHash& nodeId, in_port_t port_to_send)
{
    nodeId_ = nodeId;
    // Setup sender address
    sockAddrSend_.setFamily(domain_);
    sockAddrSend_.setAddress(domain_ == AF_INET ? MULTICAST_ADDRESS_IPV4 : MULTICAST_ADDRESS_IPV6);
    sockAddrSend_.setPort(port_);

    // Setup sent data
    std::copy_n(nodeId.cbegin(), nodeId.size(), data_send_.begin());
    auto portAddr = reinterpret_cast<in_port_t*>(data_send_.data() + dht::InfoHash::size());
    *portAddr = htons(port_to_send);
}

void
PeerDiscovery::sender_thread()
{
    while(true) {
        try {
            sendTo(data_send_.data(), data_send_.size());
        } catch (const std::exception& e) {
            std::cerr << e.what() << std::endl;
        }
        {
            std::unique_lock<std::mutex> lck(mtx_);
            if (cv_.wait_for(lck,std::chrono::seconds(3),[&]{ return !running_; }))
                break;
        }
    }
}

void
PeerDiscovery::listener_thread(PeerDiscoveredCallback callback)
{
    int stopfds_pipe[2];
#ifndef _WIN32
    if (pipe(stopfds_pipe) == -1)
        throw std::runtime_error(std::string("Can't open pipe: ") + strerror(errno));
#else
    net::udpPipe(stopfds_pipe);
#endif
    int stop_readfd = stopfds_pipe[0];
    stop_writefd_ = stopfds_pipe[1];

    while(true) {
        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(stop_readfd, &readfds);
        FD_SET(sockfd_, &readfds);

        int data_coming = select(sockfd_ > stop_readfd ? sockfd_ + 1 : stop_readfd + 1, &readfds, nullptr, nullptr, nullptr);

        {
            std::unique_lock<std::mutex> lck(mtx_);
            if (not running_)
                break;
        }

        if (data_coming < 0) {
            if(errno != EINTR) {
                perror("Select Error");
                std::this_thread::sleep_for( std::chrono::seconds(1) );
            }
        }

        if (data_coming > 0) {
            if (FD_ISSET(stop_readfd, &readfds)) {
                std::array<uint8_t, 64 * 1024> buf;
                recv(stop_readfd, buf.data(), buf.size(), 0);
            }

            std::array<uint8_t,dht::InfoHash::size() + sizeof(in_port_t)> data_receive;
            size_t data_receive_size = data_receive.size();
            auto from = recvFrom(data_receive.data(), data_receive_size);

            // Data_receive_size as a value-result member will hlep to filter packs
            if(data_receive_size != data_receive.size()){
                // std::cerr << "Received invalid peer discovery packet" << std::endl;
                continue;
            }

            dht::InfoHash nodeId;
            std::copy_n(data_receive.begin(), dht::InfoHash::size(), nodeId.begin());
            auto portAddr = reinterpret_cast<in_port_t*>(data_receive.data() + dht::InfoHash::size());
            auto port = ntohs(*portAddr);
            if (nodeId != nodeId_){
                from.setPort(port);
                callback(nodeId, from);
            }
        }
    }
    if (stop_readfd != -1)
        close(stop_readfd);
    if (stop_writefd_ != -1) {
        close(stop_writefd_);
        stop_writefd_ = -1;
    }
}

void
PeerDiscovery::startDiscovery(PeerDiscoveredCallback callback)
{
    listener_setup();
    running_listen = std::thread(&PeerDiscovery::listener_thread, this, callback);
}

void
PeerDiscovery::startPublish(const dht::InfoHash& nodeId, in_port_t port_to_send)
{
    sender_setup(nodeId, port_to_send);
    running_send = std::thread(&PeerDiscovery::sender_thread, this);
}

void
PeerDiscovery::stop()
{
    {
        std::unique_lock<std::mutex> lck(mtx_);
        running_ = false;
    }
    cv_.notify_all();
    if (stop_writefd_ != -1) {
        if (write(stop_writefd_, "\0", 1) == -1) {
            perror("write");
        }
    }
}

}
