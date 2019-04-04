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

constexpr char Multicast_address_ipv4[10] = "224.0.0.1";
constexpr char Multicast_address_ipv6[11] = "ff12::1234";

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

PeerDiscovery::PeerDiscovery(sa_family_t domain, in_port_t port){

    domain_ = domain;
    port_ = port;
    initialize_socket();

}

void
PeerDiscovery::initialize_socket(){

#ifdef _WIN32
    // Initialize Windows Socket API with given VERSION.
    if (WSAStartup(0x0101, &wsaData)) {
        perror("WSAStartup");
        throw std::runtime_error(std::string("Socket Creation Error_initialize_socket ") + strerror(errno));
    }
#endif

    sockfd_ = socket(domain_, SOCK_DGRAM, 0);
    if (sockfd_ < 0) {
        throw std::runtime_error(std::string("Socket Creation Error_initialize_socket ") + strerror(errno));
    }

}

void
PeerDiscovery::initialize_socketopt(){

    unsigned int opt = 1;
    if (setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, (char*) &opt, sizeof(opt)) < 0){
       throw std::runtime_error(std::string("Reusing ADDR failed_initialize_socketopt ") + strerror(errno));
    }
}

void
PeerDiscovery::initialize_sockaddr_Listener(){   

    SockAddr sockAddrListen_;
    sockAddrListen_.setFamily(domain_);
    sockAddrListen_.setPort(port_);
    sockAddrListen_.setAny();

    // bind to receive address
    if (bind(sockfd_, sockAddrListen_.get(), sockAddrListen_.getLength()) < 0){
        throw std::runtime_error(std::string("bind_Listener ") + strerror(errno));
    }

}

void
PeerDiscovery::mcast_join(){

    switch (domain_)
    {
        case AF_INET:

            struct ip_mreq config_ipv4;
            // config the listener to be interested in joining in the multicast group
            config_ipv4.imr_multiaddr.s_addr = inet_addr(Multicast_address_ipv4);
            config_ipv4.imr_interface.s_addr = htonl(INADDR_ANY);

            if (setsockopt(sockfd_, 
                           IPPROTO_IP, 
                           IP_ADD_MEMBERSHIP, 
                           (char*)&config_ipv4, 
                           sizeof(config_ipv4)) < 0
            ){
                throw std::runtime_error(strerror(errno) + std::string("Setsockopt_mcast_join error "));
            }

            break;
    
        case AF_INET6:

            struct ipv6_mreq config_ipv6;
            config_ipv6.ipv6mr_interface = 0;
            inet_pton(AF_INET6, Multicast_address_ipv6, &config_ipv6.ipv6mr_multiaddr);
            if (setsockopt(sockfd_, 
                           IPPROTO_IPV6, 
                           IPV6_ADD_MEMBERSHIP, 
                           &config_ipv6, 
                           sizeof(config_ipv6)) < 0
            ){
                throw std::runtime_error(strerror(errno) + std::string("setsockopt_mcast_join "));
            }

            break;

    }       

}

void
PeerDiscovery::m_sendto(uint8_t *buf,const size_t &buf_size){

    int nbytes = sendto(
        sockfd_,
        buf,
        buf_size,
        0,
        sockAddrSend_.get(),
        sockAddrSend_.getLength()
    );
    if (nbytes < 0) {

        throw std::runtime_error(std::string("sendto_m_sendto ") + strerror(errno));

    }

}

SockAddr
PeerDiscovery::m_recvfrom(uint8_t *buf,const size_t &buf_size)
{
    sockaddr_storage storeage_recv;
    socklen_t sa_len = sizeof(storeage_recv);

    int nbytes = recvfrom(
        sockfd_,
        buf,
        buf_size,
        0,
        (sockaddr*)&storeage_recv,
        &sa_len
    );
    //Check if received data is in a not required length
    if (nbytes != static_cast<int>(data_size_) + 2) {
        throw std::runtime_error(std::string("recvfrom_m_recvfrom ") + strerror(errno));
    }

    SockAddr ret {storeage_recv, sa_len};
    return ret;

}

void
PeerDiscovery::publishOnce(const dht::InfoHash &nodeId, in_port_t port_to_send){

    data_size_ = nodeId.size();
    data_send_.reset(new uint8_t[data_size_ + 2]);
    sender_setup(nodeId.data(),port_to_send);
    m_sendto(data_send_.get(),data_size_ + 2);

}

uint32_t
PeerDiscovery::discoveryOnce(const size_t &nodeId_data_size){

    listener_setup();
    data_size_ = nodeId_data_size;
    data_receive_.reset(new uint8_t[data_size_ + 2]);

    m_recvfrom(data_receive_.get(),data_size_ + 2);

    uint8_t data_port[2];
    data_port[0] = data_receive_.get()[data_size_];
    data_port[1] = data_receive_.get()[data_size_ + 1];

    return PeerDiscovery::litendtoint(data_port);

}

void
PeerDiscovery::sender_setup(const uint8_t * data_n, in_port_t port_to_send){

    //Set up for Sender
    sockAddrSend_ = SockAddr::parse(domain_, domain_ == AF_INET ? Multicast_address_ipv4 : Multicast_address_ipv6);
    sockAddrSend_.setPort(port_);

    //This option can be used to set the interface for sending outbound 
    //multicast datagrams from the sockets application.
    struct in_addr ifaddr;
    ifaddr.s_addr = INADDR_ANY;
    int optres_one = setsockopt(sockfd_, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr, sizeof( ifaddr ));
    if( optres_one == -1 ) {
        throw std::runtime_error(strerror(errno) + std::string("sender_setup  setsockopt_IP_MULTICAST_IF "));
    }

    //The IP_MULTICAST_TTL socket option allows the application to primarily 
    //limit the lifetime of the packet in the Internet and prevent it from circulating indefinitely
    unsigned char ttl = 32;
    int optres_two = setsockopt(sockfd_, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof( ttl ));
    if( optres_two == -1 ) {
        throw std::runtime_error(strerror(errno) + std::string("sender_setup  setsockopt_IP_MULTICAST_TTL "));
    }

    //Setup for send data
    int port_node = port_to_send;
    uint8_t port_node_binary[2];
    PeerDiscovery::inttolitend(port_node,port_node_binary);

    //Copy Node id and node port
    memcpy (data_send_.get(), data_n, data_size_);
    data_send_.get()[data_size_] = port_node_binary[0];
    data_send_.get()[data_size_ + 1] = port_node_binary[1];

}

void
PeerDiscovery::sender_thread(){

    size_t data_send_size = data_size_ + 2; 
    while(true) {
        m_sendto(data_send_.get(),data_send_size);
        {
            std::unique_lock<std::mutex> lck(mtx_);
            if (cv_.wait_for(lck,std::chrono::seconds(3),[&]{ return !running_; }))
                break;
        }
    }
}

void
PeerDiscovery::listener_setup(){

    initialize_socketopt();
    initialize_sockaddr_Listener();
    mcast_join();

}

void
PeerDiscovery::listener_thread(PeerDiscoveredCallback callback){

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

    while(true){
        
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


        if(data_coming < 0) {
            if(errno != EINTR) {
                perror("select");
                std::this_thread::sleep_for( std::chrono::seconds(1) );
            }
        }

        if(data_coming > 0){
            
            if(FD_ISSET(stop_readfd, &readfds)){ break; }

            size_t data_receive_size = data_size_ + 2;
            auto from = m_recvfrom(data_receive_.get(),data_receive_size);

            std::unique_ptr<uint8_t> data_infohash;
            data_infohash.reset(new uint8_t[data_size_]);
            uint8_t data_port[2];

            memcpy (data_infohash.get(), data_receive_.get(), data_size_);
            data_port[0] = data_receive_.get()[data_size_];
            data_port[1] = data_receive_.get()[data_size_ + 1];

            auto port = PeerDiscovery::litendtoint(data_port);
            auto nodeId = dht::InfoHash(data_infohash.get(), data_size_);

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
PeerDiscovery::startDiscovery(PeerDiscoveredCallback callback, const dht::InfoHash &nodeId){

    data_size_ = nodeId.size();
    data_receive_.reset(new uint8_t[data_size_ + 2]);
    nodeId_ = nodeId;
    listener_setup();
    set_nonblocking(sockfd_, 1);
    running_listen = std::thread(&PeerDiscovery::listener_thread, this, callback);

}

void
PeerDiscovery::startPublish(const dht::InfoHash &nodeId, in_port_t port_to_send){

    data_size_ = nodeId.size();
    data_send_.reset(new uint8_t[data_size_ + 2]);
    sender_setup(nodeId.data(),port_to_send);
    set_nonblocking(sockfd_, 1);
    running_send = std::thread(&PeerDiscovery::sender_thread, this);

}

void
PeerDiscovery::stop(){

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
