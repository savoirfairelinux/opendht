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

namespace dht {

constexpr char multicast_address_ipv4[10] = "224.0.0.1";
constexpr char multicast_address_ipv6[11] = "ff12::1234";

PeerDiscovery::PeerDiscovery(sa_family_t domain, in_port_t port){

    domain_ = domain;
    port_ = port;
    continue_to_run_ = true;

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

    uint opt = 1;

    if (setsockopt(sockfd_, 
                   SOL_SOCKET, 
                   SO_REUSEADDR|SO_REUSEPORT, 
                   (char*) &opt, 
                   sizeof(opt)) < 0
    ){
       throw std::runtime_error(std::string("Reusing ADDR failed_initialize_socketopt ") + strerror(errno));
    }

}

void
PeerDiscovery::initialize_sockaddr_Listener(){   

    sockaddr_.setFamily(domain_);
    sockaddr_.setPort(port_);
    sockaddr_.setAny();

    // bind to receive address
    if (bind(sockfd_, 
             sockaddr_.get(), 
             sockaddr_.getLength()) < 0
    ){

        throw std::runtime_error(std::string("bind_Listener ") + strerror(errno));

    }

}

void
PeerDiscovery::initialize_sockaddr_Sender(){   

    sockaddr_ = SockAddr::parse(domain_, domain_ == AF_INET ? multicast_address_ipv4 : multicast_address_ipv6);
    sockaddr_.setPort(port_);

}

void
PeerDiscovery::mcast_join(){

    switch (domain_)
    {
        case AF_INET:

            struct ip_mreq config_ipv4;
            // config the listener to be interested in joining in the multicast group
            config_ipv4.imr_multiaddr.s_addr = inet_addr(multicast_address_ipv4);
            config_ipv4.imr_interface.s_addr = htonl(INADDR_ANY);

            if (setsockopt(sockfd_, 
                           IPPROTO_IP, 
                           IP_ADD_MEMBERSHIP, 
                           (char*)&config_ipv4, 
                           sizeof(config_ipv4)) < 0
            ){
                throw std::runtime_error(std::string("Setsockopt_mcast_join error ") + strerror(errno));
            }

            break;
    
        case AF_INET6:

            struct ipv6_mreq config_ipv6;
            config_ipv6.ipv6mr_interface = 0;
            inet_pton(AF_INET6, multicast_address_ipv6, &config_ipv6.ipv6mr_multiaddr);
            if (setsockopt(sockfd_, 
                           IPPROTO_IPV6, 
                           IPV6_ADD_MEMBERSHIP, 
                           &config_ipv6, 
                           sizeof(config_ipv6)) < 0
            ){
                throw std::runtime_error(std::string("setsockopt_mcast_join ") + strerror(errno));
            }

            break;

    }       

}

void
PeerDiscovery::m_sendto(uint8_t *buf,size_t &buf_size){

    int nbytes = sendto(
        sockfd_,
        buf,
        buf_size,
        0,
        sockaddr_.get(),
        sockaddr_.getLength()
    );
    if (nbytes < 0) {

        throw std::runtime_error(std::string("sendto_m_sendto ") + strerror(errno));

    }

}

void
PeerDiscovery::m_recvfrom(uint8_t *buf,size_t &buf_size)
{
    struct sockaddr_storage storeage_recv;
    memcpy (&storeage_recv, sockaddr_.get(), sizeof (sockaddr_));
    socklen_t sa_len = sizeof(storeage_recv);
    int nbytes = recvfrom(
        sockfd_,
        buf,
        buf_size,
        0,
        (sockaddr*)&storeage_recv,
        &sa_len
    );
    if (nbytes < 0) {
        throw std::runtime_error(std::string("recvfrom_m_recvfrom ") + strerror(errno));
    }

    SockAddr received_addrr (storeage_recv,sizeof(storeage_recv));
    sockaddr_ = std::move(received_addrr);

}

void
PeerDiscovery::sender_oneTimeShoot(uint8_t * data_n, in_port_t port_to_send){

    //Set up for Sender
    initialize_socket();
    initialize_sockaddr_Sender();

    //Setup for send data
    uint8_t data_send[22];

    size_t data_send_size = 22;
    int port_node = port_to_send;
    uint8_t port_node_binary[2];
    PeerDiscovery::inttolitend(port_node,port_node_binary);

    //Copy Node id and node port
    memcpy (data_send, data_n, 20);
    data_send[20] = port_node_binary[0];
    data_send[21] = port_node_binary[1];

    m_sendto(data_send,data_send_size);

}

uint32_t
PeerDiscovery::listener_oneTimeShoot(){

    initialize_socket();
    initialize_socketopt();
    initialize_sockaddr_Listener();
    mcast_join();

    size_t data_receive_size = 22;
    uint8_t data_receive[22];
    m_recvfrom(data_receive,data_receive_size);

    uint8_t data_infohash[20];
    uint8_t data_port[2];

    memcpy (data_infohash, data_receive, 20);
    data_port[0] = data_receive[20];
    data_port[1] = data_receive[21];

    return PeerDiscovery::litendtoint(data_port);

}

void
PeerDiscovery::sender_setup(dht::InfoHash nodeId, in_port_t port_to_send){

    //Set up for Sender
    initialize_socket();
    initialize_sockaddr_Sender();

    //Setup for send data
    uint8_t *x = nodeId.data();
    int port_node = port_to_send;
    uint8_t port_node_binary[2];
    PeerDiscovery::inttolitend(port_node,port_node_binary);

    //Copy Node id and node port
    memcpy (data_send_, x, 20);
    data_send_[20] = port_node_binary[0];
    data_send_[21] = port_node_binary[1];
    
}

void
PeerDiscovery::sender_thread(bool &continues){

    std::mutex mtx;
    std::unique_lock<std::mutex> lck(mtx);
    while(continues){
        
        m_sendto(data_send_,data_size_);
        cv_.wait_for(lck,std::chrono::seconds(3));

    }

}

void
PeerDiscovery::listener_setup(){

    initialize_socket();
    initialize_socketopt();
    initialize_sockaddr_Listener();
    mcast_join();

}

void
PeerDiscovery::listener_thread(PeerDiscoveredCallback callback, bool &continues){

#ifndef _WIN32
    auto status = pipe(stopfds_pipe_);
    if (status == -1) {
        throw std::runtime_error(std::string("Can't open pipe: ") + strerror(errno));
    }
#else
    udpPipe(stopfds);
#endif
    stop_readfd_ = stopfds_pipe_[0];
    stop_writefd_ = stopfds_pipe_[1];

    while(continues){
        
        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(stop_readfd_, &readfds);
        FD_SET(sockfd_, &readfds);

        int data_coming = select(sockfd_ + 1, &readfds, nullptr, nullptr, nullptr);
        if(data_coming < 0) {
            if(errno != EINTR) {
                perror("select");
                std::this_thread::sleep_for( std::chrono::seconds(1) );
            }
        }

        if(data_coming > 0){
            
            if(FD_ISSET(stop_readfd_,&readfds)){ break; }

            size_t data_receive_size = 22;
            uint8_t data_receive[22];

            m_recvfrom(data_receive,data_receive_size);

            uint8_t data_infohash[20];
            uint8_t data_port[2];

            memcpy (data_infohash, data_receive, 20);
            data_port[0] = data_receive[20];
            data_port[1] = data_receive[21];

            auto port = PeerDiscovery::litendtoint(data_port);
            auto nodeId = dht::InfoHash(data_infohash, 20);

            if(port_self_ != port){

                sockaddr_.setPort(port);
                callback(nodeId, sockaddr_);

            }

        }

    }
    if (stop_readfd_ != -1)
        close(stop_readfd_);
    if (stop_writefd_ != -1)
        close(stop_writefd_);

}

void
PeerDiscovery::startDiscovery(PeerDiscoveredCallback callback, in_port_t port_to_avoid){

    port_self_ = port_to_avoid;
    listener_setup();
    running_ = std::thread(&PeerDiscovery::listener_thread, this, callback,std::ref(continue_to_run_));

}

void
PeerDiscovery::startPublish(dht::InfoHash nodeId, in_port_t port_to_send){

    sender_setup(nodeId,port_to_send);
    running_ = std::thread(&PeerDiscovery::sender_thread, this, std::ref(continue_to_run_));

}

PeerDiscovery::~PeerDiscovery()
{

#ifdef _WIN32
    WSACleanup();
#endif
    close(sockfd_);

}

}
