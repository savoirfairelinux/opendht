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

#include "def.h"
#include "sockaddr.h"
#include "infohash.h"

#include <thread>
#include <mutex>
#include <condition_variable>

namespace dht {

class OPENDHT_PUBLIC PeerDiscovery
{
public:

    using PeerDiscoveredPackCallback = std::function<void(std::string&, msgpack::object&&, SockAddr&)>;
    PeerDiscovery(sa_family_t domain, in_port_t port);
    ~PeerDiscovery();

    /**
     * startDiscovery - Keep Listening data from the sender until node is joinned or stop is called
    */
    void startDiscovery(PeerDiscoveredPackCallback callback);

    /**
     * startPublish - Keeping sending data until node is joinned or stop is called - msgpack
    */
    void startPublish(const std::string &type, msgpack::sbuffer && pack_buf, const dht::InfoHash &nodeId);

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
    void join() {
        if(running_listen_.joinable()) running_listen_.join();
        if(running_send_.joinable()) running_send_.join();
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

    //Thread export to be joined
    std::thread running_listen_;
    std::thread running_send_;
    dht::InfoHash nodeId_;

    msgpack::sbuffer sbuf_;
    msgpack::sbuffer rbuf_;

    /**
     * Multicast Socket Initialization, accept IPV4, IPV6
    */
    static int initialize_socket(sa_family_t domain);

    /**
     * Send pack messages
    */
    void sendTo();

    /**
     * Receive messages
    */
    SockAddr recvFrom(size_t &buf_size);

    /**
     * Send pack thread loop
    */
    void senderpack_thread();

    /**
     * Listener pack thread loop
    */
    void listenerpack_thread(PeerDiscoveredPackCallback callback);

    /**
     * Listener Parameters Setup
    */
    void listener_setup();

    /**
     * Sender Parameters Setup
    */
    void sender_setup(const std::string &type, msgpack::sbuffer && pack_buf, const dht::InfoHash &nodeId);
};

}
