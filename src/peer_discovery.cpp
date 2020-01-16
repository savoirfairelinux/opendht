/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author(s) : Mingrui Zhang <mingrui.zhang@savoirfairelinux.com>
 *              Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
 *              Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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
#include "network_utils.h"
#include "utils.h"

#include <asio.hpp>

namespace dht {

// Organization-local Scope multicast
constexpr char MULTICAST_ADDRESS_IPV4[] = "239.192.0.1";
constexpr char MULTICAST_ADDRESS_IPV6[] = "ff08::101";

class PeerDiscovery::DomainPeerDiscovery
{
public:
    DomainPeerDiscovery(asio::ip::udp domain, in_port_t port, Sp<asio::io_context> ioContext = {}, Sp<Logger> logger = {});
    ~DomainPeerDiscovery();

    void startDiscovery(const std::string &type, ServiceDiscoveredCallback callback);
    void startPublish(const std::string &type, const msgpack::sbuffer &pack_buf);

    void stop();

    bool stopDiscovery(const std::string &type);
    bool stopPublish(const std::string &type);

    void connectivityChanged();

private:
    Sp<Logger> logger_;
    //dmtx_ for callbackmap_ and drunning_ (write)
    std::mutex dmtx_;
    //mtx_ for messages_ and lrunning (listen)
    std::mutex mtx_;
    std::shared_ptr<asio::io_context> ioContext_;
    asio::ip::udp::socket sockFd_;
    asio::ip::udp::endpoint sockAddrSend_;

    std::array<char, 64 * 1024> receiveBuf_;
    asio::ip::udp::endpoint receiveFrom_;

    msgpack::sbuffer sbuf_;
    std::map<std::string, msgpack::sbuffer> messages_;
    std::map<std::string, ServiceDiscoveredCallback> callbackmap_;
    bool lrunning_ {false};
    bool drunning_ {false};

    void loopListener();
    void query(const asio::ip::udp::endpoint& peer);
    void reloadMessages();

    void stopDiscovery();
    void stopPublish();

    void publish(const asio::ip::udp::endpoint& peer);

    void reDiscover();
};

PeerDiscovery::DomainPeerDiscovery::DomainPeerDiscovery(asio::ip::udp domain, in_port_t port, Sp<asio::io_context> ioContext, Sp<Logger> logger)
    : logger_(logger)
    , ioContext_(ioContext)
    , sockFd_(*ioContext_, domain)
    , sockAddrSend_(asio::ip::address::from_string(domain.family() == AF_INET ? MULTICAST_ADDRESS_IPV4
                                                                              : MULTICAST_ADDRESS_IPV6), port)
{
    try {
        sockFd_.set_option(asio::ip::multicast::join_group(sockAddrSend_.address()));
        sockFd_.set_option(asio::ip::udp::socket::reuse_address(true));
        sockFd_.bind({domain, port});
    } catch (const std::exception& e) {
        if (logger_)
            logger_->e("Can't start peer discovery for %s: %s",
                    domain.family() == AF_INET ? "IPv4" : "IPv6", e.what());
    }
}

PeerDiscovery::DomainPeerDiscovery::~DomainPeerDiscovery()
{
    stop();
    sockFd_.close();
}

void
PeerDiscovery::DomainPeerDiscovery::startDiscovery(const std::string &type, ServiceDiscoveredCallback callback)
{
    std::lock_guard<std::mutex> lck(dmtx_);
    callbackmap_[type] = callback;
    if (not drunning_) {
        drunning_ = true;
        ioContext_->post([this] () {
                    loopListener();
                    query(sockAddrSend_);
                });
    }
}

void
PeerDiscovery::DomainPeerDiscovery::loopListener()
{
    std::lock_guard<std::mutex> lck(dmtx_);
    if (not drunning_)
        return;
    sockFd_.async_receive_from(asio::buffer(receiveBuf_), receiveFrom_, [this](const asio::error_code& error, size_t bytes) {
        if (error == asio::error::operation_aborted)
            return;
        if (error) {
            if (logger_)
                logger_->e("Error receiving message: %s", error.message().c_str());
        }
        try {
            auto rcv = msgpack::unpack(receiveBuf_.data(), bytes);
            msgpack::object obj = rcv.get();

            if (obj.type == msgpack::type::STR) {
                if (lrunning_ and obj.as<std::string>() == "q")
                    publish(receiveFrom_);
            } else if (obj.type == msgpack::type::MAP) {
                for (unsigned i = 0; i < obj.via.map.size; i++) {
                    auto& o = obj.via.map.ptr[i];
                    if (o.key.type != msgpack::type::STR)
                        continue;
                    auto key = o.key.as<std::string>();
                    ServiceDiscoveredCallback cb;
                    {
                        std::lock_guard<std::mutex> lck(dmtx_);
                        if (drunning_) {
                            auto callback = callbackmap_.find(key);
                            if (callback != callbackmap_.end())
                                cb = callback->second;
                        } else
                            return;
                    }
                    if (cb)
                        cb(std::move(o.val), SockAddr{ receiveFrom_.data(), (socklen_t)receiveFrom_.size() });
                }
            } else {
                throw msgpack::type_error{};
            }
        } catch (const std::exception& e) {
            if (logger_)
                logger_->e("Error receiving packet: %s", e.what());
        }
        loopListener();
    });
}

void
PeerDiscovery::DomainPeerDiscovery::query(const asio::ip::udp::endpoint& peer)
{
    std::lock_guard<std::mutex> lck(dmtx_);
    if (not drunning_)
        return;

    msgpack::sbuffer pbuf_request;
    msgpack::pack(pbuf_request, "q");

    sockFd_.async_send_to(asio::buffer(pbuf_request.data(), pbuf_request.size()), peer,
            [logger=logger_, peer] (const asio::error_code& ec, size_t)
            {
                if (ec and (ec != asio::error::operation_aborted) and logger)
                    logger->w("Error sending packet to: %s with err: %s",
				    peer.address().to_string().c_str(),
				    ec.message().c_str());
            }
    );
}

void
PeerDiscovery::DomainPeerDiscovery::publish(const asio::ip::udp::endpoint& peer)
{
    std::lock_guard<std::mutex> lck(mtx_);
    if (not lrunning_)
        return;

    sockFd_.async_send_to(asio::buffer(sbuf_.data(), sbuf_.size()), peer,
            [logger=logger_, peer] (const asio::error_code& ec, size_t)
            {
                if (ec and (ec != asio::error::operation_aborted) and logger)
                    logger->w("Error sending packet to: %s with err: %s",
				    peer.address().to_string().c_str(),
				    ec.message().c_str());
            }
    );
}


void
PeerDiscovery::DomainPeerDiscovery::startPublish(const std::string &type, const msgpack::sbuffer &pack_buf)
{
    msgpack::sbuffer pack_buf_c;
    pack_buf_c.write(pack_buf.data(),pack_buf.size());

    std::lock_guard<std::mutex> lck(mtx_);
    messages_[type] = std::move(pack_buf_c);
    reloadMessages();
    lrunning_ = true;
    ioContext_->post([this] () { publish(sockAddrSend_); });
}

bool
PeerDiscovery::DomainPeerDiscovery::stopDiscovery(const std::string& type)
{
    std::lock_guard<std::mutex> lck(dmtx_);
    if (callbackmap_.erase(type) > 0) {
        if (callbackmap_.empty())
            stopDiscovery();
        return true;
    }
    return false;
}

bool
PeerDiscovery::DomainPeerDiscovery::stopPublish(const std::string& type)
{
    std::lock_guard<std::mutex> lck(mtx_);
    if (messages_.erase(type) > 0) {
        if (messages_.empty())
            stopPublish();
        else
            reloadMessages();
        return true;
    }
    return false;
}

void
PeerDiscovery::DomainPeerDiscovery::stopDiscovery()
{
    drunning_ = false;
}

void
PeerDiscovery::DomainPeerDiscovery::stopPublish()
{
    lrunning_ = false;
}

void
PeerDiscovery::DomainPeerDiscovery::stop()
{
    {
        std::lock_guard<std::mutex> lck(dmtx_);
        stopDiscovery();
    }
    {
        std::lock_guard<std::mutex> lck(mtx_);
        stopPublish();
    }
}

void
PeerDiscovery::DomainPeerDiscovery::reloadMessages()
{
    sbuf_.clear();
    msgpack::packer<msgpack::sbuffer> pk(&sbuf_);
    pk.pack_map(messages_.size());
    for (const auto& m : messages_) {
        pk.pack(m.first);
        sbuf_.write(m.second.data(), m.second.size());
    }
}

void
PeerDiscovery::DomainPeerDiscovery::reDiscover()
{
    asio::error_code ec;

    sockFd_.set_option(asio::ip::multicast::join_group(sockAddrSend_.address()), ec);
    if (ec and logger_)
        logger_->w("can't multicast on %s: %s",
                sockAddrSend_.address().to_string().c_str(),
                ec.message().c_str());
    query(sockAddrSend_);
}

void
PeerDiscovery::DomainPeerDiscovery::connectivityChanged()
{
    reDiscover();
    publish(sockAddrSend_);
}

PeerDiscovery::PeerDiscovery(in_port_t port, Sp<asio::io_context> ioContext, Sp<Logger> logger)
{
    if (not ioContext) {
        ioContext = std::make_shared<asio::io_context>();
        ioContext_ = ioContext;
        ioRunnner_ = std::thread([logger, ioContext] {
            try {
                if (logger)
                    logger->d("[peerdiscovery] starting io_context");
                auto work = asio::make_work_guard(*ioContext);
                ioContext->run();
                if (logger)
                    logger->d("[peerdiscovery] io_context stopped");
            }
            catch (const std::exception& ex){
                if (logger)
                    logger->e("[peerdiscovery] run error: %s", ex.what());
            }
        });
    }

    try {
        peerDiscovery4_.reset(new DomainPeerDiscovery(asio::ip::udp::v4(), port, ioContext, logger));
    } catch(const std::exception& e){
        if (logger)
            logger->e("[peerdiscovery] can't start IPv4: %s", e.what());
    }
    try {
        peerDiscovery6_.reset(new DomainPeerDiscovery(asio::ip::udp::v6(), port, ioContext, logger));
    } catch(const std::exception& e) {
        if (logger)
            logger->e("[peerdiscovery] can't start IPv6: %s", e.what());
    }
}

PeerDiscovery::~PeerDiscovery() {
    stop();
    if (ioContext_)
        ioContext_->stop();
    if (ioRunnner_.joinable())
        ioRunnner_.join();
}

void
PeerDiscovery::startDiscovery(const std::string& type, ServiceDiscoveredCallback callback)
{
    if (peerDiscovery4_) peerDiscovery4_->startDiscovery(type, callback);
    if (peerDiscovery6_) peerDiscovery6_->startDiscovery(type, callback);
}

void
PeerDiscovery::startPublish(const std::string& type, const msgpack::sbuffer& pack_buf)
{
    if (peerDiscovery4_) peerDiscovery4_->startPublish(type, pack_buf);
    if (peerDiscovery6_) peerDiscovery6_->startPublish(type, pack_buf);
}

void
PeerDiscovery::startPublish(sa_family_t domain, const std::string& type, const msgpack::sbuffer& pack_buf)
{
    if (domain == AF_INET) {
        if (peerDiscovery4_) peerDiscovery4_->startPublish(type, pack_buf);
    } else if (domain == AF_INET6) {
        if (peerDiscovery6_) peerDiscovery6_->startPublish(type, pack_buf);
    }
}

void
PeerDiscovery::stop()
{
    if (peerDiscovery4_) peerDiscovery4_->stop();
    if (peerDiscovery6_) peerDiscovery6_->stop();
}

bool
PeerDiscovery::stopDiscovery(const std::string &type)
{
    bool stopped4 = peerDiscovery4_ and peerDiscovery4_->stopDiscovery(type);
    bool stopped6 = peerDiscovery6_ and peerDiscovery6_->stopDiscovery(type);
    return stopped4 or stopped6;
}

bool
PeerDiscovery::stopPublish(const std::string &type)
{
    bool stopped4 = peerDiscovery4_ and peerDiscovery4_->stopPublish(type);
    bool stopped6 = peerDiscovery6_ and peerDiscovery6_->stopPublish(type);
    return stopped4 or stopped6;
}

bool
PeerDiscovery::stopPublish(sa_family_t domain, const std::string& type)
{
    if (domain == AF_INET) {
        return peerDiscovery4_ and peerDiscovery4_->stopPublish(type);
    } else if (domain == AF_INET6) {
        return peerDiscovery6_ and peerDiscovery6_->stopPublish(type);
    }
    return false;
}

void
PeerDiscovery::connectivityChanged()
{
    if (peerDiscovery4_)
        peerDiscovery4_->connectivityChanged();
    if (peerDiscovery6_)
        peerDiscovery6_->connectivityChanged();
}

} /* namespace dht */
