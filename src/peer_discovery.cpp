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

#ifdef _WIN32
#include <Ws2tcpip.h> // needed for ip_mreq definition for multicast
#include <Windows.h>
#else
#include <sys/types.h>
#endif
#include <fcntl.h>

namespace dht {

constexpr char MULTICAST_ADDRESS_IPV4[10] = "224.0.0.1";
constexpr char MULTICAST_ADDRESS_IPV6[8] = "ff02::1";

#ifdef _WIN32

static bool
set_nonblocking(int fd, int nonblocking)
{
    unsigned long mode = !!nonblocking;
    int rc = ioctlsocket(fd, FIONBIO, &mode);
    return rc == 0;
}

extern const char *inet_ntop(int, const void *, char *, socklen_t);

#else

static bool
set_nonblocking(int fd, int nonblocking)
{
    int rc = fcntl(fd, F_GETFL, 0);
    if (rc < 0)
        return false;
    rc = fcntl(fd, F_SETFL, nonblocking?(rc | O_NONBLOCK):(rc & ~O_NONBLOCK));
    return rc >= 0;
}

#endif

PeerDiscovery::PeerDiscovery(sa_family_t domain, in_port_t port)
    : domain_(domain), port_(port), sockfd_(initialize_socket(domain))
{
    socketJoinMulticast(sockfd_, domain);
}

int
PeerDiscovery::initialize_socket(sa_family_t domain)
{

#ifdef _WIN32
    // Initialize Windows Socket API with given VERSION.
    if (WSAStartup(0x0101, &wsaData)) {
        perror("WSAStartup");
        throw std::runtime_error(std::string("Socket Creation Error_initialize_socket ") + strerror(errno));
    }
#endif

    int sockfd = socket(domain, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        throw std::runtime_error(std::string("Socket Creation Error: ") + strerror(errno));
    }
    set_nonblocking(sockfd, 1);
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
    if (setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, (char*) &opt, sizeof(opt)) < 0){
       throw std::runtime_error(std::string("Reusing ADDR failed: ") + strerror(errno));
    }

    // bind to receive address
    if (bind(sockfd_, sockAddrListen_.get(), sockAddrListen_.getLength()) < 0){
        throw std::runtime_error(std::string("Bind Socket For Listener Error: ") + strerror(errno));
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
                throw std::runtime_error(std::string("Bound Network Interface IPV4 Error: ") + strerror(errno));
            }

            //The IP_MULTICAST_TTL socket option allows the application to primarily 
            //limit the lifetime of the packet in the Internet and prevent it from circulating indefinitely
            unsigned char ttl4 = 20;
            if( setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl4, sizeof( ttl4 )) < 0 ) {
                throw std::runtime_error(std::string(" TTL Sockopt Error: ") + strerror(errno));
            }
            
            // config the listener to be interested in joining in the multicast group
            config_ipv4.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDRESS_IPV4);
            config_ipv4.imr_interface.s_addr = htonl(INADDR_ANY);
            if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&config_ipv4, sizeof(config_ipv4)) < 0){
                throw std::runtime_error(std::string(" Member Addition IPV4 Error: ") + strerror(errno));
            }

            break;
        }
    
        case AF_INET6:{

            ipv6_mreq config_ipv6;

            unsigned int outif = 0;
            if( setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &outif, sizeof( outif )) < 0 ) {
                throw std::runtime_error(std::string("Bound Network Interface IPV6 Error: ") + strerror(errno));
            }

            unsigned int ttl6 = 20;
            if( setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl6, sizeof( ttl6 )) < 0 ) {
                throw std::runtime_error(std::string("Hop Count Set Error: ") + strerror(errno));
            }

            config_ipv6.ipv6mr_interface = 0;
            inet_pton(AF_INET6, MULTICAST_ADDRESS_IPV6, &config_ipv6.ipv6mr_multiaddr);
            if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &config_ipv6, sizeof(config_ipv6)) < 0){
                throw std::runtime_error(std::string("Member Addition IPV6 Error: ") + strerror(errno));
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
    //Set up for Sender
    sockAddrSend_ = SockAddr::parse(domain_, domain_ == AF_INET ? MULTICAST_ADDRESS_IPV4 : MULTICAST_ADDRESS_IPV6);
    sockAddrSend_.setPort(port_);

    //Setup for send data
    int port_node = port_to_send;
    uint8_t port_node_binary[2];
    PeerDiscovery::inttolitend(port_node,port_node_binary);

    //Copy Node id and node port
    memcpy (data_send_.data(), nodeId.data(), nodeId.size());
    data_send_[InfoHash::size()] = port_node_binary[0];
    data_send_[InfoHash::size() + 1] = port_node_binary[1];
}

void
PeerDiscovery::sender_thread()
{
    while(true) {
        sendTo(data_send_.data(), data_send_.size());
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
    auto status = pipe(stopfds_pipe);
    if (status == -1) {
        throw std::runtime_error(std::string("Can't open pipe: ") + strerror(errno));
    }
#else
    udpPipe(stopfds_pipe);
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

            if(FD_ISSET(stop_readfd, &readfds)){ break; }

            std::array<uint8_t,dht::InfoHash::size() + sizeof(in_port_t)> data_receive;
            size_t data_receive_size = data_receive.size();
            auto from = recvFrom(data_receive.data(), data_receive_size);

            //Data_receive_size as a value-result member will hlep to filter packs 
            if(data_receive_size != data_receive.size()){ 
                perror("Data Received Unmatch");
                continue; 
            }

            std::array<uint8_t,dht::InfoHash::size()> data_infohash;
            uint8_t data_port[2];

            memcpy (data_infohash.data(), data_receive.data(), dht::InfoHash::size());
            data_port[0] = data_receive[dht::InfoHash::size()];
            data_port[1] = data_receive[dht::InfoHash::size() + 1];

            auto port = PeerDiscovery::litendtoint(data_port);
            auto nodeId = dht::InfoHash(data_infohash.data(), dht::InfoHash::size());

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
PeerDiscovery::startPublish(const dht::InfoHash &nodeId, in_port_t port_to_send)
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
    cv_.notify_one();
    if (stop_writefd_ != -1) {

        if (write(stop_writefd_, "\0", 1) == -1) {
            perror("write");
        }
    }
}

PeerDiscovery::~PeerDiscovery()
{
    if (sockfd_ != -1)
        close(sockfd_);

#ifdef _WIN32
    WSACleanup();
#endif
}

}
