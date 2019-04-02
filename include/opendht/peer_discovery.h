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

#pragma once

#include "sockaddr.h"
#include "infohash.h"

#ifdef _WIN32
#include <Winsock2.h> // before Windows.h, else Winsock 1 conflict
#include <Ws2tcpip.h> // needed for ip_mreq definition for multicast
#include <Windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 

#include <thread>
#include <string>
#include <mutex>
#include <condition_variable>

namespace dht {

class OPENDHT_PUBLIC PeerDiscovery
{
public:

    using PeerDiscoveredCallback = std::function<void(const InfoHash&, const SockAddr&)>;

    PeerDiscovery(sa_family_t domain, in_port_t port);
    ~PeerDiscovery();
    
    /**
     * startDiscovery - Listen
    */
    void startDiscovery(PeerDiscoveredCallback callback, in_port_t port_to_avoid);

    /**
     * startPublish - Send
    */
    void startPublish(dht::InfoHash nodeId, in_port_t port_to_send);

    /**
     * Send socket procudure start - one time sender
    */
    void sender_oneTimeShoot(uint8_t * data_n, in_port_t port_to_send);

    /**
     * Listener socket procudure start - one time Listen
    */
    uint32_t listener_oneTimeShoot();

    /**
     * Thread Stopper
    */
    void stop(bool listenorsend){ 
        
        continue_to_run_setter(false);
        cv_.notify_one();
        if(listenorsend) {

            close(stop_readfd_);
            if (stop_writefd_ != -1) {
                if (write(stop_writefd_, "\0", 1) == -1) {
                    perror("write");
                }
            }

        }

    }

    /**
     * Getter and Setters
    */
    void continue_to_run_setter(bool continue_to_run){

        continue_to_run_ = continue_to_run;

    }
    bool is_thread_joinable(){

        return running_.joinable();

    }
    void join_thread(){

        running_.join();

    }
    
private:
    
    sa_family_t domain_;
    int sockfd_;
    SockAddr sockaddr_;
    int port_;
    in_port_t port_self_;
    uint8_t data_send_[22];
    size_t data_size_ = 22;

    bool continue_to_run_;
    int stopfds_pipe_[2];
    int stop_readfd_;
    int stop_writefd_;
    std::condition_variable cv_;
    //Thread export to be joined 
    std::thread running_;

    /**
     * Multicast Socket Initialization, accept IPV4, IPV6 
    */
    void initialize_socket();

    /**
     * Multicast Socket Option Initialization, aim to allow multiple sockets to use the same PORT number 
     * listen used only
    */
    void initialize_socketopt();

    /**
     * Socket Address Structure Initialization for both Listener
    */
    void initialize_sockaddr_Listener();

    /**
     * Socket Address Structure Initialization for both Sender 
    */
    void initialize_sockaddr_Sender();

    /**
     * Configure the listener to be insterested in joining the IP multicast group
    */
    void mcast_join();

    /**
     * Send messages
    */
    void m_sendto(uint8_t *buf,size_t &buf_size);

    /**
     * Receive messages
    */
    void m_recvfrom(uint8_t *buf,size_t &buf_size);

    /**
     * Send thread loop
    */
    void sender_thread(bool &continues);

    /**
     * Listener thread loop
    */
    void listener_thread(PeerDiscoveredCallback callback,bool &continues);

    /**
     * Listener Parameters Setup
    */
    void listener_setup();

    /**
     * Sender Parameters Setup
    */
    void sender_setup(dht::InfoHash nodeId, in_port_t port_to_send);

    /**
     * Binary Converters
    */
    static void inttolitend(uint32_t x, uint8_t *lit_int) {
        lit_int[0] = (uint8_t)(x >>  0);
        lit_int[1] = (uint8_t)(x >>  8);
    }

    static uint32_t litendtoint(uint8_t *lit_int) {
        return (uint32_t)lit_int[0] <<  0
            |  (uint32_t)lit_int[1] <<  8;
    }

#ifdef _WIN32
    WSADATA wsaData;
#endif

};

}
