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

    using ServiceDiscoveredCallback = std::function<void(msgpack::object&&, SockAddr&&)>;
    PeerDiscovery(in_port_t port);
    ~PeerDiscovery();

    /**
     * startDiscovery - Keep Listening data from the sender until node is joinned or stop is called
    */
    void startDiscovery(const std::string &type, ServiceDiscoveredCallback callback);

    /**
     * startPublish - Keeping sending data until node is joinned or stop is called - msgpack
    */
    void startPublish(const std::string &type, const msgpack::sbuffer &pack_buf);

    /**
     * Thread Stopper
    */
    void stop();

    /**
     * Remove possible callBack to discovery
    */
    void stopDiscovery(const std::string &type);

    /**
     * Remove different serivce message to send
    */
    void stopPublish(const std::string &type);

    /**
     * Configure the sockopt to be able to listen multicast group
    */
    static void socketJoinMulticast(int sockfd, sa_family_t family);

    /**
     * Join the threads
    */
    void join();

private:
    class DomainPeerDiscovery;
    std::unique_ptr<DomainPeerDiscovery> peerDiscovery4_;
    std::unique_ptr<DomainPeerDiscovery> peerDiscovery6_;
};

}
