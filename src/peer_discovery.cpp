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
#include "network_utils.h"
#include "utils.h"

#ifdef _WIN32
#include <Ws2tcpip.h> // needed for ip_mreq definition for multicast
#include <Windows.h>
#include <cstring>
#define close(x) closesocket(x)
#define write(s, b, f) send(s, b, (int)strlen(b), 0)
#else
#include <sys/types.h>
#include <unistd.h>
#endif
#include <fcntl.h>

namespace dht {

constexpr char MULTICAST_ADDRESS_IPV4[10] = "224.0.0.1";
constexpr char MULTICAST_ADDRESS_IPV6[8] = "ff05::2"; // Site-local multicast


class PeerDiscovery::DomainPeerDiscovery
{
public:
    DomainPeerDiscovery(sa_family_t domain, in_port_t port);
    ~DomainPeerDiscovery();

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
    void join() {
        if(running_listen_.joinable()) running_listen_.join();
        if(running_send_.joinable()) running_send_.join();
    }
private:
    //dmtx_ for callbackmap_ and drunning_ (write)
    std::mutex dmtx_;
    //mtx_ for messages_ and lrunning (listen)
    std::mutex mtx_;
    std::condition_variable cv_;
    bool lrunning_ {false};
    bool drunning_ {false};
    sa_family_t domain_ {AF_UNSPEC};
    int port_;
    int sockfd_ {-1};
    int stop_writefd_ {-1};

    SockAddr sockAddrSend_;

    //Thread export to be joined
    std::thread running_listen_;
    std::thread running_send_;

    msgpack::sbuffer sbuf_;
    msgpack::sbuffer rbuf_;
    std::map<std::string, msgpack::sbuffer> messages_;
    std::map<std::string, ServiceDiscoveredCallback> callbackmap_;

    /**
     * Multicast Socket Initialization, accept IPV4, IPV6
    */
    static int initialize_socket(sa_family_t domain);

    /**
     * Receive messages
    */
    std::pair<SockAddr, Blob> recvFrom();
    
    /**
     * Listener pack thread loop
    */
    void listenerpack_thread();

    /**
     * Listener Parameters Setup
    */
    void listener_setup();

    /**
     * Sender Parameters Setup
    */
    void sender_setup();
    /**
     * Sender Parameters Setup
    */
    void messages_reload();
};

PeerDiscovery::DomainPeerDiscovery::DomainPeerDiscovery(sa_family_t domain, in_port_t port)
    : domain_(domain), port_(port), sockfd_(initialize_socket(domain))
{
    socketJoinMulticast(sockfd_, domain);
}

PeerDiscovery::DomainPeerDiscovery::~DomainPeerDiscovery()
{
    if (sockfd_ != -1)
        close(sockfd_);

#ifdef _WIN32
    WSACleanup();
#endif
}

int
PeerDiscovery::DomainPeerDiscovery::initialize_socket(sa_family_t domain)
{
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(0x0101, &wsaData)) {
        throw std::runtime_error(std::string("Can't initialize Winsock2 ") + strerror(errno));
    }
#endif

    int sockfd = socket(domain, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        throw std::runtime_error(std::string("Socket Creation Error: ") + strerror(errno));
    }
    net::set_nonblocking(sockfd);
    return sockfd;
}

void
PeerDiscovery::DomainPeerDiscovery::listener_setup()
{
    SockAddr sockAddrListen_;
    sockAddrListen_.setFamily(domain_);
    sockAddrListen_.setPort(port_);
    sockAddrListen_.setAny();

    unsigned int opt = 1;
    if (setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
       std::cerr << "setsockopt SO_REUSEADDR failed: " << strerror(errno) << std::endl;
    }
    if (setsockopt(sockfd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
       std::cerr << "setsockopt SO_REUSEPORT failed: " << strerror(errno) << std::endl;
    }

    // bind to receive address
    if (bind(sockfd_, sockAddrListen_.get(), sockAddrListen_.getLength()) < 0){
        throw std::runtime_error(std::string("Error binding socket: ") + strerror(errno));
    }
}

void
PeerDiscovery::DomainPeerDiscovery::socketJoinMulticast(int sockfd, sa_family_t family)
{
    switch (family)
    {
    case AF_INET:{
        ip_mreq config_ipv4;

        //This option can be used to set the interface for sending outbound
        //multicast datagrams from the sockets application.
        config_ipv4.imr_interface.s_addr = htonl(INADDR_ANY);
        if( setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, &config_ipv4.imr_interface, sizeof( struct in_addr )) < 0 ) {
            throw std::runtime_error(std::string("Bound Network Interface IPv4 Error: ") + strerror(errno));
        }

        //The IP_MULTICAST_TTL socket option allows the application to primarily
        //limit the lifetime of the packet in the Internet and prevent it from circulating indefinitely
        unsigned char ttl4 = 20;
        if( setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl4, sizeof( ttl4 )) < 0 ) {
            throw std::runtime_error(std::string("TTL Sockopt Error: ") + strerror(errno));
        }

        // config the listener to be interested in joining in the multicast group
        config_ipv4.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDRESS_IPV4);
        config_ipv4.imr_interface.s_addr = htonl(INADDR_ANY);
        if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&config_ipv4, sizeof(config_ipv4)) < 0){
            throw std::runtime_error(std::string(" Member Addition IPv4 Error: ") + strerror(errno));
        }
        break;
    }
    case AF_INET6: {
        ipv6_mreq config_ipv6;

        /* unsigned int outif = 0;
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &outif, sizeof(outif)) < 0) {
            std::cerr << "Can't assign multicast interface: " << strerror(errno) << std::endl;
        } */

        unsigned int ttl6 = 20;
        if( setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl6, sizeof( ttl6 )) < 0 ) {
            throw std::runtime_error(std::string("Hop Count Set Error: ") + strerror(errno));
        }

        config_ipv6.ipv6mr_interface = 0;
        inet_pton(AF_INET6, MULTICAST_ADDRESS_IPV6, &config_ipv6.ipv6mr_multiaddr);
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &config_ipv6, sizeof(config_ipv6)) < 0){
            throw std::runtime_error(std::string("Member Addition IPv6 Error: ") + strerror(errno));
        }
        break;
    }
    }
}

void
PeerDiscovery::DomainPeerDiscovery::startDiscovery(const std::string &type, ServiceDiscoveredCallback callback)
{
    std::unique_lock<std::mutex> lck(dmtx_);
    callbackmap_[type] = callback;
    if (not drunning_){
        drunning_ = true;
        listener_setup();
        running_listen_ = std::thread(&DomainPeerDiscovery::listenerpack_thread, this);
    }
}

std::pair<SockAddr, Blob>
PeerDiscovery::DomainPeerDiscovery::recvFrom()
{
    sockaddr_storage storeage_recv;
    socklen_t sa_len = sizeof(storeage_recv);
    std::array<uint8_t, 64 * 1024> recv;

    ssize_t nbytes = recvfrom(
        sockfd_,
        recv.data(),
        recv.size(),
        0,
        (sockaddr*)&storeage_recv,
        &sa_len
    );
    if (nbytes < 0) {
        throw std::runtime_error(std::string("Error receiving packet: ") + strerror(errno));
    }
    
    SockAddr ret {storeage_recv, sa_len};
    return {ret, Blob(recv.begin(), recv.end())};
}

void 
PeerDiscovery::DomainPeerDiscovery::listenerpack_thread()
{
    int stopfds_pipe[2];
#ifndef _WIN32
    if (pipe(stopfds_pipe) == -1)
        throw std::runtime_error(std::string("Can't open pipe: ") + strerror(errno));
#else
    net::udpPipe(stopfds_pipe);
#endif
    int stop_readfd = stopfds_pipe[0];
    stop_writefd_ = stopfds_pipe[1];

    while (true) {
        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(stop_readfd, &readfds);
        FD_SET(sockfd_, &readfds);

        int data_coming = select(sockfd_ > stop_readfd ? sockfd_ + 1 : stop_readfd + 1, &readfds, nullptr, nullptr, nullptr);

        {
            std::unique_lock<std::mutex> lck(dmtx_);
            if (not drunning_)
                break;
        }

        if (data_coming < 0) {
            if(errno != EINTR) {
                perror("Select Error");
                std::this_thread::sleep_for( std::chrono::seconds(1) );
            }
        }

        if (data_coming > 0) {
            if (FD_ISSET(stop_readfd, &readfds)) {
                std::array<uint8_t, 64 * 1024> buf;
                recv(stop_readfd, buf.data(), buf.size(), 0);
            }

            auto rcv = recvFrom();
            msgpack::object_handle oh = msgpack::unpack(reinterpret_cast<char*>(rcv.second.data()), rcv.second.size());
            msgpack::object obj = oh.get();

            if (obj.type != msgpack::type::MAP)
                continue;
            for (unsigned i = 0; i < obj.via.map.size; i++) {
                auto& o = obj.via.map.ptr[i];
                if (o.key.type != msgpack::type::STR)
                    continue;
                auto key = o.key.as<std::string>();
                std::unique_lock<std::mutex> lck(dmtx_);
                auto callback = callbackmap_.find(key);
                if (callback != callbackmap_.end()){
                    callback->second(std::move(o.val), std::move(rcv.first));
                }
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
PeerDiscovery::DomainPeerDiscovery::sender_setup()
{
    // Setup sender address
    sockAddrSend_.setFamily(domain_);
    sockAddrSend_.setAddress(domain_ == AF_INET ? MULTICAST_ADDRESS_IPV4 : MULTICAST_ADDRESS_IPV6);
    sockAddrSend_.setPort(port_);
}

void 
PeerDiscovery::DomainPeerDiscovery::startPublish(const std::string &type, const msgpack::sbuffer &pack_buf)
{
    //Set up New Sending pack
    msgpack::sbuffer pack_buf_c;
    pack_buf_c.write(pack_buf.data(),pack_buf.size());

    std::unique_lock<std::mutex> lck(mtx_);
    messages_[type] = std::move(pack_buf_c);
    messages_reload();
    if (not lrunning_) {
        lrunning_ = true;
        sender_setup();
        running_send_ = std::thread([this](){
            std::unique_lock<std::mutex> lck(mtx_);
            while (lrunning_) {
                ssize_t nbytes = sendto(
                    sockfd_,
                    sbuf_.data(),
                    sbuf_.size(),
                    0,
                    sockAddrSend_.get(),
                    sockAddrSend_.getLength()
                );
                if (nbytes < 0) {
                    std::cerr << "Error sending packet: " << strerror(errno) << std::endl;
                }
                if (cv_.wait_for(lck,std::chrono::seconds(3),[&]{ return !lrunning_; }))
                    break;
            }
        });
    }
}

void 
PeerDiscovery::DomainPeerDiscovery::stopDiscovery(const std::string &type)
{   
    {   
        std::unique_lock<std::mutex> lck(dmtx_);
        auto it  = callbackmap_.find(type);
        if(it != callbackmap_.end()){
            callbackmap_.erase(it);
        }
    }
}

void 
PeerDiscovery::DomainPeerDiscovery::stopPublish(const std::string &type)
{
    std::unique_lock<std::mutex> lck(mtx_);
    auto it = messages_.find(type);
    if(it != messages_.end()){
        messages_.erase(it);
    }
    messages_reload();
}

void
PeerDiscovery::DomainPeerDiscovery::stop()
{
    {
        std::unique_lock<std::mutex> lck(mtx_);
        lrunning_ = false;
    }
    {
        std::unique_lock<std::mutex> lck(dmtx_);
        drunning_ = false;
    }
    cv_.notify_all();
    if (stop_writefd_ != -1) {
        if (write(stop_writefd_, "\0", 1) == -1) {
            perror("write");
        }
    }
}

void
PeerDiscovery::DomainPeerDiscovery::messages_reload()
{
    sbuf_.clear();
    msgpack::packer<msgpack::sbuffer> pk(&sbuf_);
    pk.pack_map(messages_.size());
    for (const auto& m : messages_) {
        pk.pack(m.first);
        sbuf_.write(m.second.data(), m.second.size());
    }
}

PeerDiscovery::PeerDiscovery(in_port_t port) 
{
    try {
        peerDiscovery4_.reset(new DomainPeerDiscovery(AF_INET, port));
    } catch(const std::exception& e){
        peerDiscovery4_.reset(nullptr);
        std::cerr << "Can't start peer discovery (IPv4): " << e.what() << std::endl;
    }
    try {
        peerDiscovery6_.reset(new DomainPeerDiscovery(AF_INET6, port));
    } catch(const std::exception& e) {
        peerDiscovery6_.reset(nullptr);
        std::cerr << "Can't start peer discovery (IPv6): " << e.what() << std::endl;
    }

}

PeerDiscovery::~PeerDiscovery(){}

/**
 * startDiscovery - Keep Listening data from the sender until node is joinned or stop is called
*/
void 
PeerDiscovery::startDiscovery(const std::string &type, ServiceDiscoveredCallback callback)
{
    if(peerDiscovery4_) peerDiscovery4_->startDiscovery(type, callback);
    if(peerDiscovery6_) peerDiscovery6_->startDiscovery(type, callback);
}

/**
 * startPublish - Keeping sending data until node is joinned or stop is called - msgpack
*/
void 
PeerDiscovery::startPublish(const std::string &type, const msgpack::sbuffer &pack_buf)
{
    if(peerDiscovery4_) peerDiscovery4_->startPublish(type, pack_buf);
    if(peerDiscovery6_) peerDiscovery6_->startPublish(type, pack_buf);
}

/**
 * Thread Stopper
*/
void 
PeerDiscovery::stop()
{
    if(peerDiscovery4_) peerDiscovery4_->stop();
    if(peerDiscovery6_) peerDiscovery6_->stop();
}

/**
 * Remove possible callBack to discovery
*/
void 
PeerDiscovery::stopDiscovery(const std::string &type)
{
    if(peerDiscovery4_) peerDiscovery4_->stopDiscovery(type);
    if(peerDiscovery6_) peerDiscovery6_->stopDiscovery(type);
}

/**
 * Remove different serivce message to send
*/
void 
PeerDiscovery::stopPublish(const std::string &type)
{
    if(peerDiscovery4_) peerDiscovery4_->stopPublish(type);
    if(peerDiscovery6_) peerDiscovery6_->stopPublish(type);
}

/**
 * Join the threads
*/
void 
PeerDiscovery::join() {
    if(peerDiscovery4_) peerDiscovery4_->join();
    if(peerDiscovery6_) peerDiscovery6_->join();
}

}
