/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author(s) : Mingrui Zhang <mingrui.zhang@savoirfairelinux.com>
 *              Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
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
#include "log_enable.h"

#include <thread>

namespace asio {
class io_context;
}

namespace dht {

class OPENDHT_PUBLIC PeerDiscovery
{
public:
    static constexpr in_port_t DEFAULT_PORT = 8888;
    using ServiceDiscoveredCallback = std::function<void(msgpack::object&&, SockAddr&&)>;

    PeerDiscovery(in_port_t port = DEFAULT_PORT, std::shared_ptr<asio::io_context> ioContext = {}, std::shared_ptr<Logger> logger = {});
    ~PeerDiscovery();

    /**
     * startDiscovery - Keep Listening data from the sender until node is joinned or stop is called
    */
    void startDiscovery(const std::string &type, ServiceDiscoveredCallback callback);

    template<typename T>
    void startDiscovery(const std::string &type, std::function<void(T&&, SockAddr&&)> cb) {
        startDiscovery(type, [cb](msgpack::object&& ob, SockAddr&& addr) {
            cb(ob.as<T>(), std::move(addr));
        });
    }

    /**
     * startPublish - Keeping sending data until node is joinned or stop is called
    */
    void startPublish(const std::string &type, const msgpack::sbuffer &pack_buf);
    void startPublish(sa_family_t domain, const std::string &type, const msgpack::sbuffer &pack_buf);

    template<typename T>
    void startPublish(const std::string &type, const T& object) {
        msgpack::sbuffer buf;
        msgpack::pack(buf, object);
        startPublish(type, buf);
    }

    /**
     * Thread Stopper
    */
    void stop();

    /**
     * Remove possible callBack to discovery
    */
    bool stopDiscovery(const std::string &type);

    /**
     * Remove different serivce message to send
    */
    bool stopPublish(const std::string &type);
    bool stopPublish(sa_family_t domain, const std::string &type);

    void connectivityChanged();

private:
    class DomainPeerDiscovery;
    std::unique_ptr<DomainPeerDiscovery> peerDiscovery4_;
    std::unique_ptr<DomainPeerDiscovery> peerDiscovery6_;
    std::shared_ptr<asio::io_context> ioContext_;
    std::thread ioRunnner_;
};

}
