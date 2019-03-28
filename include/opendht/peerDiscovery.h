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

#include "dhtrunner.h"

#ifdef _WIN32
#include <Winsock2.h> // before Windows.h, else Winsock 1 conflict
#include <Ws2tcpip.h> // needed for ip_mreq definition for multicast
#include <Windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 

#include <string>

namespace dht {

class OPENDHT_PUBLIC PeerDiscovery
{
public:

    using PeerDiscoveredCallback = std::function<void(const InfoHash&, const SockAddr&)>;

    PeerDiscovery(int domain, in_port_t port);
    ~PeerDiscovery();
    
    /**
     * startDiscovery - Listen
    */
    void startDiscovery(PeerDiscoveredCallback callback, in_port_t port_to_avoid);

    /**
     * startPublish - Listen
    */
    void startPublish(dht::InfoHash nodeId, in_port_t port_to_send);

    /**
     * Send socket procudure start - one time sender
    */
    void Sender_oneTimeShoot(dht::InfoHash nodeId, in_port_t port_to_send);

    /**
     * Listener socket procudure start - one time Listen
    */
    void Listener_oneTimeShoot();

    /**
     * Thread Stopper
    */
    void stop(bool listenorsend){ 
        
        continue_to_run_setter(false);
        if(listenorsend) {

            close(m_stop_readfd);
            if (m_stop_writefd != -1) {
                if (write(m_stop_writefd, "\0", 1) == -1) {
                    perror("write");
                }
            }

        }

    }

    /**
     * Getter and Setters
    */
    std::thread::id running_threadid_get(){

        return m_running.get_id();

    }
    SockAddr get_sockAddr(){

        return m_sockaddr;

    }
    dht::InfoHash get_node_id_received(){

        return m_node_id_received;

    }
    int get_port_received(){

        return m_port_received;

    }
    void continue_to_run_setter(bool continue_to_run){

        m_continue_to_run = continue_to_run;

    }
    //Thread export to be joined 
    std::thread m_running;
    
private:
    
    int m_domain;
    int m_sockfd;
    SockAddr m_sockaddr;
    int m_port;
    in_port_t m_port_self;
    uint8_t m_data_send[22];
    size_t m_data_size = 22;

    bool m_continue_to_run;
    int m_stopfds_pipe[2];
    int m_stop_readfd;
    int m_stop_writefd;

    //Data to export - Listener Socket Test Only
    dht::InfoHash m_node_id_received;
    int m_port_received;

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
     * send messages
    */
    void m_sendto(uint8_t *buf,size_t &buf_size);

    /**
     * send messages
    */
    void m_recvfrom(uint8_t *buf,size_t &buf_size);

    /**
     * Send thread loop
    */
    void SenderThread(bool &continues);

    /**
     * Listener thread loop
    */
    void Listener_Thread(PeerDiscoveredCallback callback,bool &continues);

    /**
     * Listener Parameters Setup
    */
    void Listener_Setup();

    /**
     * Listener socket procudure start - Loop Listen
    */
    void Listener_Loop(PeerDiscoveredCallback callback);

    /**
     * Sender Parameters Setup
    */
    void Sender_Setup(dht::InfoHash nodeId, in_port_t port_to_send);

    /**
     * Send socket procudure start - Loop send
    */
    void Sender_Loop();

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
