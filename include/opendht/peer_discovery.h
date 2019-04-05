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

#include <string.h>
#include <stdio.h>
#include <unistd.h> 

#include <thread>
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
     * startDiscovery - Keep Listening data from the sender until node is joinned or stop is called
    */
    void startDiscovery(PeerDiscoveredCallback callback);

    /**
     * startPublish - Keeping sending data until node is joinned or stop is called
    */
    void startPublish(const dht::InfoHash &nodeId, in_port_t port_to_send);

    /**
     * Thread Stopper
    */
    void stop();

    /**
     * Configure the sockopt to be able to listen multicast group
    */
    static void socketJoinMulticast(int sockfd, sa_family_t family);

    /**
     * Join the threads
    */
    void join(){

        if(running_listen.joinable()){ running_listen.join(); };
        if(running_send.joinable()){ running_send.join(); };

    }
    
private:
    std::mutex mtx_;
    std::condition_variable cv_;
    bool running_ {true};
    sa_family_t domain_ {AF_UNSPEC};
    int port_;
    int sockfd_ {-1};
    int stop_writefd_ {-1};

    SockAddr sockAddrSend_;
    std::array<uint8_t,dht::InfoHash::size() + sizeof(in_port_t)> data_send_;

    //Thread export to be joined 
    std::thread running_listen;
    std::thread running_send;
    dht::InfoHash nodeId_;

    /**
     * Multicast Socket Initialization, accept IPV4, IPV6 
    */
    static int initialize_socket(sa_family_t domain);

    /**
     * Send messages
    */
    void sendTo(uint8_t *buf,size_t buf_size);

    /**
     * Receive messages
    */
    SockAddr recvFrom(uint8_t *buf, size_t &buf_size);

    /**
     * Send thread loop
    */
    void sender_thread();

    /**
     * Listener thread loop
    */
    void listener_thread(PeerDiscoveredCallback callback);

    /**
     * Listener Parameters Setup
    */
    void listener_setup();

    /**
     * Sender Parameters Setup
    */
    void sender_setup(const dht::InfoHash& nodeId, in_port_t port_to_send);

    /**
     * Binary Converters
    */
    static void inttolitend(uint32_t x, uint8_t *lit_int) {
        lit_int[0] = (uint8_t)(x >>  0);
        lit_int[1] = (uint8_t)(x >>  8);
    }

    static uint16_t litendtoint(uint8_t *lit_int) {
        return (uint32_t)lit_int[0] <<  0
            |  (uint32_t)lit_int[1] <<  8;
    }

#ifdef _WIN32
    WSADATA wsaData;
#endif

};

}
