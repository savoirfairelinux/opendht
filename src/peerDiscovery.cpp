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

#include "peerDiscovery.h"

namespace dht {

constexpr char multicast_address_ipv4[10] = "224.0.0.1";
constexpr char multicast_address_ipv6[11] = "ff12::1234";

PeerDiscovery::PeerDiscovery(int domain, in_port_t port){

    m_domain = domain;
    m_port = port;
    m_continue_to_run = true;

}

void
PeerDiscovery::initialize_socket(){

#ifdef _WIN32
    // Initialize Windows Socket API with given VERSION.
    if (WSAStartup(0x0101, &wsaData)) {
        perror("WSAStartup");
        exit(EXIT_FAILURE);
    }
#endif

    m_sockfd = socket(m_domain, SOCK_DGRAM, 0);
    if (m_sockfd < 0) {
        throw std::runtime_error(std::string("Socket Creation Error_initialize_socket") + strerror(errno));
    }

}

void
PeerDiscovery::initialize_socketopt(){

    uint opt = 1;

    if (setsockopt(m_sockfd, 
                   SOL_SOCKET, 
                   SO_REUSEADDR|SO_REUSEPORT, 
                   (char*) &opt, 
                   sizeof(opt)) < 0
    ){
       throw std::runtime_error(std::string("Reusing ADDR failed_initialize_socketopt") + strerror(errno));
    }

}

void
PeerDiscovery::initialize_sockaddr_Listener()
{   
    bzero(&m_sockaddr,sizeof(m_sockaddr));
    m_sockaddr.setFamily(m_domain);
    m_sockaddr.setPort(m_port);
    m_sockaddr.setAny();

    // bind to receive address
    if (bind(m_sockfd, 
             m_sockaddr.get(), 
             m_sockaddr.getLength()) < 0
    ){

        throw std::runtime_error(std::string("bind_mcast_join") + strerror(errno));

    }

}

void
PeerDiscovery::initialize_sockaddr_Sender(){

    bzero(&m_sockaddr,sizeof(m_sockaddr));
    m_sockaddr.setFamily(m_domain);
    m_sockaddr.setPort(m_port);
    m_sockaddr.setAddress(multicast_address_ipv4,multicast_address_ipv6);

}

void
PeerDiscovery::mcast_join(){

    switch (m_domain)
    {
        case AF_INET:

            struct ip_mreq config_ipv4;
            // config the listener to be interested in joining in the multicast group
            config_ipv4.imr_multiaddr.s_addr = inet_addr(multicast_address_ipv4);
            config_ipv4.imr_interface.s_addr = htonl(INADDR_ANY);

            if (setsockopt(m_sockfd, 
                           IPPROTO_IP, 
                           IP_ADD_MEMBERSHIP, 
                           (char*)&config_ipv4, 
                           sizeof(config_ipv4)) < 0
            ){
                throw std::runtime_error(std::string("Setsockopt_mcast_join error:") + strerror(errno));
            }

            break;
    
        case AF_INET6:

            struct ipv6_mreq config_ipv6;
            config_ipv6.ipv6mr_interface = 0;
            inet_pton(AF_INET6, multicast_address_ipv6, &config_ipv6.ipv6mr_multiaddr);
            if (setsockopt(m_sockfd, 
                           IPPROTO_IPV6, 
                           IPV6_ADD_MEMBERSHIP, 
                           &config_ipv6, 
                           sizeof(config_ipv6)) < 0
            ){
                throw std::runtime_error(std::string("setsockopt_mcast_join") + strerror(errno));
            }

            break;

    }       

}

void
PeerDiscovery::m_sendto(uint8_t *buf,size_t &buf_size){

    int nbytes = sendto(
        m_sockfd,
        buf,
        buf_size,
        0,
        m_sockaddr.get(),
        m_sockaddr.getLength()
    );
    if (nbytes < 0) {

        throw std::runtime_error(std::string("sendto_m_sendto") + strerror(errno));

    }

}

void
PeerDiscovery::m_recvfrom(uint8_t *buf,size_t &buf_size)
{
    socklen_t sa_len = sizeof(m_sockaddr);
    int nbytes = recvfrom(
        m_sockfd,
        buf,
        buf_size,
        0,
        m_sockaddr.get(),
        &sa_len
    );
    if (nbytes < 0) {
        throw std::runtime_error(std::string("recvfrom_m_recvfrom") + strerror(errno));
    }

}

void
PeerDiscovery::Sender_oneTimeShoot(dht::InfoHash nodeId, in_port_t port_to_send){

    //Set up for Sender
    initialize_socket();
    initialize_sockaddr_Sender();

    //Setup for send data
    uint8_t data_send[22];
    uint8_t *x = nodeId.data();

    size_t data_send_size = 22;
    int port_node = port_to_send;
    uint8_t port_node_binary[2];
    PeerDiscovery::inttolitend(port_node,port_node_binary);

    //Copy Node id and node port
    memcpy (data_send, x, 20);
    data_send[20] = port_node_binary[0];
    data_send[21] = port_node_binary[1];

    m_sendto(data_send,data_send_size);

}

void
PeerDiscovery::Listener_oneTimeShoot(){

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

    m_port_received = PeerDiscovery::litendtoint(data_port);
    m_node_id_received = dht::InfoHash(data_infohash, 20);

}

void
PeerDiscovery::Sender_Setup(dht::InfoHash nodeId, in_port_t port_to_send){

    //Set up for Sender
    initialize_socket();
    initialize_sockaddr_Sender();

    //Setup for send data
    uint8_t *x = nodeId.data();
    int port_node = port_to_send;
    uint8_t port_node_binary[2];
    PeerDiscovery::inttolitend(port_node,port_node_binary);

    //Copy Node id and node port
    memcpy (m_data_send, x, 20);
    m_data_send[20] = port_node_binary[0];
    m_data_send[21] = port_node_binary[1];
    
}

void
PeerDiscovery::SenderThread(bool &continues){

    while(continues){
        
        m_sendto(m_data_send,m_data_size);
        sleep(5);

    }

}

void
PeerDiscovery::Sender_Loop(){

    m_running = std::thread(&PeerDiscovery::SenderThread, this, std::ref(m_continue_to_run));

}

void
PeerDiscovery::Listener_Setup(){

    initialize_socket();
    initialize_socketopt();
    initialize_sockaddr_Listener();
    mcast_join();

}

void
PeerDiscovery::Listener_Thread(PeerDiscoveredCallback callback, bool &continues){

#ifndef _WIN32
    auto status = pipe(m_stopfds_pipe);
    if (status == -1) {
        throw DhtException(std::string("Can't open pipe: ") + strerror(errno));
    }
#else
    udpPipe(stopfds);
#endif
    m_stop_readfd = m_stopfds_pipe[0];
    m_stop_writefd = m_stopfds_pipe[1];

    while(continues){
        
        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(m_stop_readfd, &readfds);
        FD_SET(m_sockfd, &readfds);

        int data_coming = select(m_sockfd + 1, &readfds, nullptr, nullptr, nullptr);
        if(data_coming < 0) {
            if(errno != EINTR) {
                perror("select");
                std::this_thread::sleep_for( std::chrono::seconds(1) );
            }
        }

        if(data_coming > 0){
            
            if(FD_ISSET(m_stop_readfd,&readfds)){ break; }

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

            if(m_port_self != port){

                m_sockaddr.setPort(port);
                callback(nodeId, m_sockaddr);

            }
            sleep(1);

        }

    }
    if (m_stop_readfd != -1)
        close(m_stop_readfd);
    if (m_stop_writefd != -1)
        close(m_stop_writefd);

}

void 
PeerDiscovery::Listener_Loop(PeerDiscoveredCallback callback)
{

    m_running = std::thread(&PeerDiscovery::Listener_Thread, this, callback,std::ref(m_continue_to_run));

}

void
PeerDiscovery::startDiscovery(PeerDiscoveredCallback callback, in_port_t port_to_avoid){

    m_port_self = port_to_avoid;
    Listener_Setup();
    Listener_Loop(callback);

}

void
PeerDiscovery::startPublish(dht::InfoHash nodeId, in_port_t port_to_send){

    Sender_Setup(nodeId,port_to_send);
    Sender_Loop();

}

PeerDiscovery::~PeerDiscovery()
{

#ifdef _WIN32
    WSACleanup();
#endif
    close(m_sockfd);

}

}
