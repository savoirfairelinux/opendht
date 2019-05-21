/*
 *  Copyright (C) 2014-2019 Savoir-faire Linux Inc.
 *  Authors: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *           Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
 *           Sébastien Blin <sebastien.blin@savoirfairelinux.com>
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

#include "dhtrunner.h"
#include "securedht.h"
#include "peer_discovery.h"
#include "network_utils.h"

#ifdef OPENDHT_PROXY_CLIENT
#include "dht_proxy_client.h"
#endif

#ifdef _WIN32
#include <cstring>
#define close(x) closesocket(x)
#define write(s, b, f) send(s, b, (int)strlen(b), 0)
#endif

namespace dht {

constexpr std::chrono::seconds DhtRunner::BOOTSTRAP_PERIOD;
static constexpr size_t RX_QUEUE_MAX_SIZE = 1024 * 16;
static constexpr std::chrono::milliseconds RX_QUEUE_MAX_DELAY(500);
static constexpr in_port_t PEER_DISCOVERY_PORT = 8888;
static const std::string PEER_DISCOVERY_DHT_SERVICE = "dht";

struct DhtRunner::Listener {
    size_t tokenClassicDht {0};
    size_t tokenProxyDht {0};
    ValueCallback gcb;
    InfoHash hash {};
    Value::Filter f;
    Where w;
};

class OPENDHT_PUBLIC NodeInsertionPack{
public:
    dht::InfoHash nodeid_;
    in_port_t node_port_;
    dht::NetId nid_;
    MSGPACK_DEFINE(nodeid_, node_port_, nid_)
};

DhtRunner::DhtRunner() : dht_()
#ifdef OPENDHT_PROXY_CLIENT
, dht_via_proxy_()
#endif //OPENDHT_PROXY_CLIENT
{
#ifdef _WIN32
    WSADATA wsd;
    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
        throw DhtException("Can't initialize Winsock2");
#endif
}

DhtRunner::~DhtRunner()
{
    join();
#ifdef _WIN32
    WSACleanup();
#endif
}

void
DhtRunner::run(in_port_t port, const DhtRunner::Config& config, Context&& context)
{
    SockAddr sin4;
    sin4.setFamily(AF_INET);
    sin4.setPort(port);
    SockAddr sin6;
    sin6.setFamily(AF_INET6);
    sin6.setPort(port);
    run(sin4, sin6, config, std::move(context));
}

void
DhtRunner::run(const char* ip4, const char* ip6, const char* service, const DhtRunner::Config& config, Context&& context)
{
    auto res4 = SockAddr::resolve(ip4, service);
    auto res6 = SockAddr::resolve(ip6, service);
    run(res4.empty() ? SockAddr() : res4.front(),
        res6.empty() ? SockAddr() : res6.front(), config, std::move(context));
}

void
DhtRunner::run(const SockAddr& local4, const SockAddr& local6, const DhtRunner::Config& config, Context&& context)
{
    if (running)
        return;
    startNetwork(local4, local6);

    auto dht = std::unique_ptr<DhtInterface>(new Dht(s4, s6, SecureDht::getConfig(config.dht_config)));
    dht_ = std::unique_ptr<SecureDht>(new SecureDht(std::move(dht), config.dht_config));

#ifdef OPENDHT_PROXY_CLIENT
    config_ = config;
#endif
    enableProxy(not config.proxy_server.empty());

    if (context.logger) {
        if (dht_)
            dht_->setLoggers(context.logger->ERR, context.logger->WARN, context.logger->DBG);
        if (dht_via_proxy_)
            dht_via_proxy_->setLoggers(context.logger->ERR, context.logger->WARN, context.logger->DBG);
    }

    running = true;
    if (not config.threaded)
        return;
    dht_thread = std::thread([this, local4, local6]() {
        while (running) {
            std::unique_lock<std::mutex> lk(dht_mtx);
            time_point wakeup;
            try {
                wakeup = loop_();
            } catch (const dht::SocketException& e) {
                startNetwork(local4, local6);
            }

            auto hasJobToDo = [this]() {
                if (not running)
                    return true;
                {
                    std::lock_guard<std::mutex> lck(sock_mtx);
                    if (not rcv.empty())
                        return true;
                }
                {
                    std::lock_guard<std::mutex> lck(storage_mtx);
                    if (not pending_ops_prio.empty())
                        return true;
                    auto s = getStatus();
                    if (not pending_ops.empty() and (s == NodeStatus::Connected or (s == NodeStatus::Disconnected and not bootstraping)))
                        return true;
                }
                return false;
            };
            if (wakeup == time_point::max())
                cv.wait(lk, hasJobToDo);
            else
                cv.wait_until(lk, wakeup, hasJobToDo);
        }
    });

    if (config.peer_discovery or config.peer_publish) {
        if (context.peerDiscovery)
            peerDiscovery_ = std::move(context.peerDiscovery);
        else
            peerDiscovery_.reset(new PeerDiscovery(PEER_DISCOVERY_PORT));
    }

    auto netId = config.dht_config.node_config.network;
    if (config.peer_discovery) {
        peerDiscovery_->startDiscovery(PEER_DISCOVERY_DHT_SERVICE, [this, netId](msgpack::object&& obj, SockAddr&& add){
            try {
                auto v = obj.as<NodeInsertionPack>();
                add.setPort(v.node_port_);
                if(v.nodeid_ != dht_->getNodeId() && netId == v.nid_){
                    bootstrap(v.nodeid_, add);
                }
            } catch(const msgpack::type_error &e){
                std::cerr << "Msgpack Info Invalid: " << e.what() << '\n';
            }
        });
    }
    if (config.peer_publish) {
        msgpack::sbuffer sbuf_node;
        // IPv4
        NodeInsertionPack adc;
        adc.nid_ = netId;
        adc.node_port_ = getBoundPort(AF_INET);
        adc.nodeid_ = dht_->getNodeId();
        msgpack::pack(sbuf_node, adc);
        peerDiscovery_->startPublish(AF_INET, PEER_DISCOVERY_DHT_SERVICE, sbuf_node);
        // IPv6
        adc.node_port_ = getBoundPort(AF_INET6);
        sbuf_node.clear();
        msgpack::pack(sbuf_node, adc);
        peerDiscovery_->startPublish(AF_INET6, PEER_DISCOVERY_DHT_SERVICE, sbuf_node);
    }
}

void
DhtRunner::shutdown(ShutdownCallback cb) {
    if (not running) {
        cb();
        return;
    }
#ifdef OPENDHT_PROXY_CLIENT
    if (dht_via_proxy_)
        dht_via_proxy_->shutdown(cb);
#endif
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([=](SecureDht& dht) mutable {
        dht.shutdown(cb);
    });
    cv.notify_all();
}

void
DhtRunner::join()
{
    stopNetwork();
    running = false;
    cv.notify_all();
    bootstrap_cv.notify_all();
    if (peerDiscovery_) peerDiscovery_->stop();

    if (dht_thread.joinable())
        dht_thread.join();
    if (bootstrap_thread.joinable())
        bootstrap_thread.join();
    if (rcv_thread.joinable())
        rcv_thread.join();

    if (peerDiscovery_) {
        peerDiscovery_->join();
    }

    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops = decltype(pending_ops)();
        pending_ops_prio = decltype(pending_ops_prio)();
    }
    {
        std::lock_guard<std::mutex> lck(dht_mtx);
        resetDht();
        status4 = NodeStatus::Disconnected;
        status6 = NodeStatus::Disconnected;
    }
}

void
DhtRunner::dumpTables() const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    activeDht()->dumpTables();
}

InfoHash
DhtRunner::getId() const
{
    if (auto dht = activeDht())
        return dht->getId();
    return {};
}

InfoHash
DhtRunner::getNodeId() const
{
    if (auto dht = activeDht())
        return dht->getNodeId();
    return {};
}


std::pair<size_t, size_t>
DhtRunner::getStoreSize() const {
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (!dht_)
        return {};
    return dht_->getStoreSize();
}

void
DhtRunner::setStorageLimit(size_t limit) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (!dht_)
        throw std::runtime_error("dht is not running");
    return dht_->setStorageLimit(limit);
}

std::vector<NodeExport>
DhtRunner::exportNodes() const {
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (!dht_)
        return {};
    return dht_->exportNodes();
}

std::vector<ValuesExport>
DhtRunner::exportValues() const {
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (!dht_)
        return {};
    return dht_->exportValues();
}

void
DhtRunner::setLoggers(LogMethod error, LogMethod warn, LogMethod debug) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (dht_)
        dht_->setLoggers(error, warn, debug);
#ifdef OPENDHT_PROXY_CLIENT
    if (dht_via_proxy_)
        dht_via_proxy_->setLoggers(error, warn, debug);
#endif
}

void
DhtRunner::setLogFilter(const InfoHash& f) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    activeDht()->setLogFilter(f);
    if (dht_)
        dht_->setLogFilter(f);
#ifdef OPENDHT_PROXY_CLIENT
    if (dht_via_proxy_)
        dht_via_proxy_->setLogFilter(f);
#endif
}

void
DhtRunner::registerType(const ValueType& type) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    activeDht()->registerType(type);
}

void
DhtRunner::importValues(const std::vector<ValuesExport>& values) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    dht_->importValues(values);
}

unsigned
DhtRunner::getNodesStats(sa_family_t af, unsigned *good_return, unsigned *dubious_return, unsigned *cached_return, unsigned *incoming_return) const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    const auto stats = activeDht()->getNodesStats(af);
    if (good_return)
        *good_return = stats.good_nodes;
    if (dubious_return)
        *dubious_return = stats.dubious_nodes;
    if (cached_return)
        *cached_return = stats.cached_nodes;
    if (incoming_return)
        *incoming_return = stats.incoming_nodes;
    return stats.good_nodes + stats.dubious_nodes;
}

NodeStats
DhtRunner::getNodesStats(sa_family_t af) const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return activeDht()->getNodesStats(af);
}

NodeInfo
DhtRunner::getNodeInfo() const {
    std::lock_guard<std::mutex> lck(dht_mtx);
    NodeInfo info;
    info.id = getId();
    info.node_id = getNodeId();
    info.ipv4 = dht_->getNodesStats(AF_INET);
    info.ipv6 = dht_->getNodesStats(AF_INET6);
    return info;
}

std::vector<unsigned>
DhtRunner::getNodeMessageStats(bool in) const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return activeDht()->getNodeMessageStats(in);
}

std::string
DhtRunner::getStorageLog() const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return activeDht()->getStorageLog();
}
std::string
DhtRunner::getStorageLog(const InfoHash& f) const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return activeDht()->getStorageLog(f);
}
std::string
DhtRunner::getRoutingTablesLog(sa_family_t af) const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return activeDht()->getRoutingTablesLog(af);
}
std::string
DhtRunner::getSearchesLog(sa_family_t af) const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return activeDht()->getSearchesLog(af);
}
std::string
DhtRunner::getSearchLog(const InfoHash& f, sa_family_t af) const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return activeDht()->getSearchLog(f, af);
}
std::vector<SockAddr>
DhtRunner::getPublicAddress(sa_family_t af)
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (auto dht = activeDht())
        return dht->getPublicAddress(af);
    return {};
}
std::vector<std::string>
DhtRunner::getPublicAddressStr(sa_family_t af)
{
    auto addrs = getPublicAddress(af);
    std::vector<std::string> ret(addrs.size());
    std::transform(addrs.begin(), addrs.end(), ret.begin(), [](const SockAddr& a) { return a.toString(); });
    return ret;
}

void
DhtRunner::registerCertificate(std::shared_ptr<crypto::Certificate> cert) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    activeDht()->registerCertificate(cert);
}
void
DhtRunner::setLocalCertificateStore(CertificateStoreQuery&& query_method) {
    std::lock_guard<std::mutex> lck(dht_mtx);
#ifdef OPENDHT_PROXY_CLIENT
    if (dht_via_proxy_)
        dht_via_proxy_->setLocalCertificateStore(std::forward<CertificateStoreQuery>(query_method));
#endif
    if (dht_)
        dht_->setLocalCertificateStore(std::forward<CertificateStoreQuery>(query_method));
}

time_point
DhtRunner::loop_()
{
    auto dht = activeDht();
    if (not dht)
        return {};

    decltype(pending_ops) ops {};
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        auto s = getStatus();
        ops = (pending_ops_prio.empty() && (s == NodeStatus::Connected or (s == NodeStatus::Disconnected and not bootstraping))) ?
               std::move(pending_ops) : std::move(pending_ops_prio);
    }
    while (not ops.empty()) {
        ops.front()(*dht);
        ops.pop();
    }

    time_point wakeup {};
    decltype(rcv) received {};
    {
        std::lock_guard<std::mutex> lck(sock_mtx);
        // move to stack
        received = std::move(rcv);
    }

    // Discard old packets
    size_t dropped {0};
    if (not received.empty()) {
        auto now = clock::now();
        while (not received.empty() and now - received.front().received > RX_QUEUE_MAX_DELAY) {
            received.pop();
            dropped++;
        }
    }

    // Handle packets
    if (not received.empty()) {
        while (not received.empty()) {
            auto& pck = received.front();
            if (clock::now() - pck.received > RX_QUEUE_MAX_DELAY)
                dropped++;
            else
                wakeup = dht->periodic(pck.data.data(), pck.data.size(), pck.from);
            received.pop();
        }
    } else {
        // Or just run the scheduler
        wakeup = dht->periodic(nullptr, 0, nullptr, 0);
    }

    if (dropped)
        std::cerr << "Dropped %zu packets with high delay" << dropped << std::endl;

    NodeStatus nstatus4 = dht->getStatus(AF_INET);
    NodeStatus nstatus6 = dht->getStatus(AF_INET6);
    if (nstatus4 != status4 || nstatus6 != status6) {
        status4 = nstatus4;
        status6 = nstatus6;
        if (status4 == NodeStatus::Disconnected and status6 == NodeStatus::Disconnected) {
            // We have lost connection with the DHT.  Try to recover using bootstrap nodes.
            std::unique_lock<std::mutex> lck(bootstrap_mtx);
            bootstrap_nodes = bootstrap_nodes_all;
            tryBootstrapContinuously();
        } else {
            std::unique_lock<std::mutex> lck(bootstrap_mtx);
            bootstrap_nodes.clear();
        }
        if (statusCb)
            statusCb(status4, status6);
    }

    return wakeup;
}


int bindSocket(const SockAddr& addr, SockAddr& bound)
{
    bool is_ipv6 = addr.getFamily() == AF_INET6;
    int sock = socket(is_ipv6 ? PF_INET6 : PF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        throw DhtException(std::string("Can't open socket: ") + strerror(sock));
    int set = 1;
#ifdef SO_NOSIGPIPE
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (const char*)&set, sizeof(set));
#endif
    if (is_ipv6)
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&set, sizeof(set));
    net::set_nonblocking(sock);
    int rc = bind(sock, addr.get(), addr.getLength());
    if(rc < 0) {
        rc = errno;
        close(sock);
        throw DhtException("Can't bind socket on " + addr.toString() + " " + strerror(rc));
    }
    sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    getsockname(sock, (sockaddr*)&ss, &ss_len);
    bound = {ss, ss_len};
    return sock;
}

void
DhtRunner::stopNetwork()
{
    running_network = false;
    if (stop_writefd != -1) {
        if (write(stop_writefd, "\0", 1) == -1) {
            perror("write");
        }
    }
}

void
DhtRunner::startNetwork(const SockAddr sin4, const SockAddr sin6)
{
    stopNetwork();
    if (rcv_thread.joinable())
        rcv_thread.join();

    int stopfds[2];
#ifndef _WIN32
    auto status = pipe(stopfds);
    if (status == -1) {
        throw DhtException(std::string("Can't open pipe: ") + strerror(errno));
    }
#else
    net::udpPipe(stopfds);
#endif
    int stop_readfd = stopfds[0];
    stop_writefd = stopfds[1];

    s4 = -1;
    s6 = -1;

    bound4 = {};
    if (sin4) {
        try {
            s4 = bindSocket(sin4, bound4);
        } catch (const DhtException& e) {
            std::cerr << "Can't bind inet socket: " << e.what() << std::endl;
        }
    }

#if 1
    bound6 = {};
    if (sin6) {
        try {
            s6 = bindSocket(sin6, bound6);
        } catch (const DhtException& e) {
            std::cerr << "Can't bind inet6 socket: " << e.what() << std::endl;
        }
    }
#endif

    if (s4 == -1 && s6 == -1) {
        throw DhtException("Can't bind socket");
    }

    running_network = true;
    rcv_thread = std::thread([this, stop_readfd]() {
        try {
            while (running_network) {
                fd_set readfds;

                FD_ZERO(&readfds);
                FD_SET(stop_readfd, &readfds);
                if(s4 >= 0)
                    FD_SET(s4, &readfds);
                if(s6 >= 0)
                    FD_SET(s6, &readfds);

                int selectFd = std::max({s4, s6, stop_readfd}) + 1;
                int rc = select(selectFd, &readfds, nullptr, nullptr, nullptr);
                if(rc < 0) {
                    if(errno != EINTR) {
                        perror("select");
                        std::this_thread::sleep_for( std::chrono::seconds(1) );
                    }
                }

                if (not running_network)
                    break;

                if (rc > 0) {
                    std::array<uint8_t, 1024 * 64> buf;
                    sockaddr_storage from;
                    socklen_t from_len = sizeof(from);

                    if (FD_ISSET(stop_readfd, &readfds)) {
                        if (recv(stop_readfd, (char*)buf.data(), buf.size(), 0) < 0) {
                            std::cerr << "Got stop packet error: " << strerror(errno) << std::endl;
                            break;
                        }
                    }
                    else if (s4 >= 0 && FD_ISSET(s4, &readfds))
                        rc = recvfrom(s4, (char*)buf.data(), buf.size(), 0, (sockaddr*)&from, &from_len);
                    else if (s6 >= 0 && FD_ISSET(s6, &readfds))
                        rc = recvfrom(s6, (char*)buf.data(), buf.size(), 0, (sockaddr*)&from, &from_len);
                    else
                        continue;

                    if (rc > 0) {
                        {
                            std::lock_guard<std::mutex> lck(sock_mtx);
                            if (rcv.size() >= RX_QUEUE_MAX_SIZE) {
                                std::cerr << "Dropping packet: queue is full!" << std::endl;
                                rcv.pop();
                            }
                            rcv.emplace(ReceivedPacket {Blob {buf.begin(), buf.begin()+rc}, SockAddr(from, from_len), clock::now()});
                        }
                        cv.notify_all();
                    } else if (rc == -1) {
                        std::cerr << "Error receiving packet: " << strerror(errno) << std::endl;
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in DHT networking thread: " << e.what() << std::endl;
        }
        if (s4 >= 0)
            close(s4);
        if (s6 >= 0)
            close(s6);
        s4 = -1;
        s6 = -1;
        bound4 = {};
        bound6 = {};
        if (stop_readfd != -1)
            close(stop_readfd);
        if (stop_writefd != -1)
            close(stop_writefd);
        stop_writefd = -1;
    });
}

void
DhtRunner::get(InfoHash hash, GetCallback vcb, DoneCallback dcb, Value::Filter f, Where w)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) mutable {
            dht.get(hash, std::move(vcb), std::move(dcb), std::move(f), std::move(w));
        });
    }
    cv.notify_all();
}

void
DhtRunner::get(const std::string& key, GetCallback vcb, DoneCallbackSimple dcb, Value::Filter f, Where w)
{
    get(InfoHash::get(key), std::move(vcb), std::move(dcb), std::move(f), std::move(w));
}
void
DhtRunner::query(const InfoHash& hash, QueryCallback cb, DoneCallback done_cb, Query q) {
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) mutable {
            dht.query(hash, std::move(cb), std::move(done_cb), std::move(q));
        });
    }
    cv.notify_all();
}

std::future<size_t>
DhtRunner::listen(InfoHash hash, ValueCallback vcb, Value::Filter f, Where w)
{
    auto ret_token = std::make_shared<std::promise<size_t>>();
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) mutable {
#ifdef OPENDHT_PROXY_CLIENT
            auto tokenbGlobal = listener_token_++;
            auto& listener = listeners_[tokenbGlobal];
            listener.hash = hash;
            listener.f = std::move(f);
            listener.w = std::move(w);
            listener.gcb = [hash,vcb,tokenbGlobal,this](const std::vector<Sp<Value>>& vals, bool expired) {
                if (not vcb(vals, expired)) {
                    cancelListen(hash, tokenbGlobal);
                    return false;
                }
                return true;
            };
            if (auto token = dht.listen(hash, listener.gcb, listener.f, listener.w)) {
                if (use_proxy)  listener.tokenProxyDht = token;
                else            listener.tokenClassicDht = token;
            }
            ret_token->set_value(tokenbGlobal);
#else
            ret_token->set_value(dht.listen(hash, std::move(vcb), std::move(f), std::move(w)));
#endif
        });
    }
    cv.notify_all();
    return ret_token->get_future();
}

std::future<size_t>
DhtRunner::listen(const std::string& key, GetCallback vcb, Value::Filter f, Where w)
{
    return listen(InfoHash::get(key), std::move(vcb), std::move(f), std::move(w));
}

void
DhtRunner::cancelListen(InfoHash h, size_t token)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
#ifdef OPENDHT_PROXY_CLIENT
        pending_ops.emplace([=](SecureDht&) {
            auto it = listeners_.find(token);
            if (it == listeners_.end()) return;
            if (it->second.tokenClassicDht)
                dht_->cancelListen(h, it->second.tokenClassicDht);
            if (it->second.tokenProxyDht and dht_via_proxy_)
                dht_via_proxy_->cancelListen(h, it->second.tokenProxyDht);
            listeners_.erase(it);
        });
#else
        pending_ops.emplace([=](SecureDht& dht) {
            dht.cancelListen(h, token);
        });
#endif // OPENDHT_PROXY_CLIENT
    }
    cv.notify_all();
}

void
DhtRunner::cancelListen(InfoHash h, std::shared_future<size_t> ftoken)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
#ifdef OPENDHT_PROXY_CLIENT
        pending_ops.emplace([=](SecureDht&) {
            auto it = listeners_.find(ftoken.get());
            if (it == listeners_.end()) return;
            if (it->second.tokenClassicDht)
                dht_->cancelListen(h, it->second.tokenClassicDht);
            if (it->second.tokenProxyDht and dht_via_proxy_)
                dht_via_proxy_->cancelListen(h, it->second.tokenProxyDht);
            listeners_.erase(it);
        });
#else
        pending_ops.emplace([=](SecureDht& dht) {
            dht.cancelListen(h, ftoken.get());
        });
#endif // OPENDHT_PROXY_CLIENT
    }
    cv.notify_all();
}

void
DhtRunner::put(InfoHash hash, Value&& value, DoneCallback cb, time_point created, bool permanent)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        auto sv = std::make_shared<Value>(std::move(value));
        pending_ops.emplace([=](SecureDht& dht) {
            dht.put(hash, sv, cb, created, permanent);
        });
    }
    cv.notify_all();
}

void
DhtRunner::put(InfoHash hash, std::shared_ptr<Value> value, DoneCallback cb, time_point created, bool permanent)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) {
            dht.put(hash, value, cb, created, permanent);
        });
    }
    cv.notify_all();
}

void
DhtRunner::put(const std::string& key, Value&& value, DoneCallbackSimple cb, time_point created, bool permanent)
{
    put(InfoHash::get(key), std::forward<Value>(value), std::move(cb), created, permanent);
}

void
DhtRunner::cancelPut(const InfoHash& h , const Value::Id& id)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) {
            dht.cancelPut(h, id);
        });
    }
    cv.notify_all();
}

void
DhtRunner::putSigned(InfoHash hash, std::shared_ptr<Value> value, DoneCallback cb)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) {
            dht.putSigned(hash, value, cb);
        });
    }
    cv.notify_all();
}

void
DhtRunner::putSigned(InfoHash hash, Value&& value, DoneCallback cb)
{
    putSigned(hash, std::make_shared<Value>(std::move(value)), std::move(cb));
}

void
DhtRunner::putSigned(const std::string& key, Value&& value, DoneCallbackSimple cb)
{
    putSigned(InfoHash::get(key), std::forward<Value>(value), std::move(cb));
}

void
DhtRunner::putEncrypted(InfoHash hash, InfoHash to, std::shared_ptr<Value> value, DoneCallback cb)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) {
            dht.putEncrypted(hash, to, value, cb);
        });
    }
    cv.notify_all();
}

void
DhtRunner::putEncrypted(InfoHash hash, InfoHash to, Value&& value, DoneCallback cb)
{
    putEncrypted(hash, to, std::make_shared<Value>(std::move(value)), std::move(cb));
}

void
DhtRunner::putEncrypted(const std::string& key, InfoHash to, Value&& value, DoneCallback cb)
{
    putEncrypted(InfoHash::get(key), to, std::forward<Value>(value), std::move(cb));
}

void
DhtRunner::tryBootstrapContinuously()
{
    if (bootstrap_thread.joinable()) {
        if (bootstraping)
            return; // already running
        else
            bootstrap_thread.join();
    }
    bootstraping = true;
    bootstrap_thread = std::thread([this]() {
        auto next = clock::now();
        do {
            decltype(bootstrap_nodes) nodes;
            {
                std::lock_guard<std::mutex> lck(bootstrap_mtx);
                nodes = bootstrap_nodes;
            }

            next += BOOTSTRAP_PERIOD;
            {
                std::mutex mtx;
                std::unique_lock<std::mutex> blck(mtx);
                unsigned ping_count(0);
                // Reverse: try last inserted bootstrap nodes first
                for (auto it = nodes.rbegin(); it != nodes.rend(); it++) {
                    ++ping_count;
                    try {
                        bootstrap(SockAddr::resolve(it->first, it->second), [&](bool) {
                            if (not running)
                                return;
                            {
                                std::unique_lock<std::mutex> blck(mtx);
                                --ping_count;
                            }
                            bootstrap_cv.notify_all();
                        });
                    } catch (std::invalid_argument& e) {
                        --ping_count;
                        std::cerr << e.what() << std::endl;
                    }
                }
                // wait at least until the next BOOTSTRAP_PERIOD
                bootstrap_cv.wait_until(blck, next, [&]() { return not running; });
                // wait for bootstrap requests to end.
                if (running)
                   bootstrap_cv.wait(blck, [&]() { return not running or ping_count == 0; });
            }
            // update state
            {
                std::lock_guard<std::mutex> lck(dht_mtx);
                bootstraping = running and
                               status4 == NodeStatus::Disconnected and
                               status6 == NodeStatus::Disconnected;
            }
        } while (bootstraping);
    });
}

void
DhtRunner::bootstrap(const std::string& host, const std::string& service)
{
    std::lock_guard<std::mutex> lck(bootstrap_mtx);
    bootstrap_nodes_all.emplace_back(host, service);
    bootstrap_nodes.emplace_back(host, service);
    tryBootstrapContinuously();
}

void
DhtRunner::clearBootstrap()
{
    std::lock_guard<std::mutex> lck(bootstrap_mtx);
    bootstrap_nodes_all.clear();
}

void
DhtRunner::bootstrap(const std::vector<SockAddr>& nodes, DoneCallbackSimple&& cb)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([=](SecureDht& dht) mutable {
        auto rem = cb ? std::make_shared<std::pair<size_t, bool>>(nodes.size(), false) : nullptr;
        for (const auto& node : nodes)
            dht.pingNode(node.get(), node.getLength(), cb ? [rem,cb](bool ok) {
                auto& r = *rem;
                r.first--;
                r.second |= ok;
                if (not r.first)
                    cb(r.second);
            } : DoneCallbackSimple{});
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(const SockAddr& addr, DoneCallbackSimple&& cb)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([addr,cb](SecureDht& dht) mutable {
        dht.pingNode(addr.get(), addr.getLength(), std::move(cb));
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(const InfoHash& id, const SockAddr& address)
{
    {
        std::unique_lock<std::mutex> lck(storage_mtx);
        pending_ops_prio.emplace([id, address](SecureDht& dht) mutable {
            dht.insertNode(id, address);
        });
    }
    cv.notify_all();
}

void
DhtRunner::bootstrap(const std::vector<NodeExport>& nodes)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops_prio.emplace([=](SecureDht& dht) {
            for (auto& node : nodes)
                dht.insertNode(node);
        });
    }
    cv.notify_all();
}

void
DhtRunner::connectivityChanged()
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops_prio.emplace([=](SecureDht& dht) {
            dht.connectivityChanged();
        });
    }
    cv.notify_all();
}

void
DhtRunner::findCertificate(InfoHash hash, std::function<void(const std::shared_ptr<crypto::Certificate>)> cb) {
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) {
            dht.findCertificate(hash, cb);
        });
    }
    cv.notify_all();
}

void
DhtRunner::resetDht()
{
    peerDiscovery_.reset();
#ifdef OPENDHT_PROXY_CLIENT
    listeners_.clear();
    dht_via_proxy_.reset();
#endif // OPENDHT_PROXY_CLIENT
    dht_.reset();
}

SecureDht*
DhtRunner::activeDht() const
{
#ifdef OPENDHT_PROXY_CLIENT
    return use_proxy? dht_via_proxy_.get() : dht_.get();
#else
    return dht_.get();
#endif // OPENDHT_PROXY_CLIENT
}

void
DhtRunner::setProxyServer(const std::string& proxy, const std::string& pushNodeId)
{
#ifdef OPENDHT_PROXY_CLIENT
    if (config_.proxy_server == proxy and config_.push_node_id == pushNodeId)
        return;
    config_.proxy_server = proxy;
    config_.push_node_id = pushNodeId;
    enableProxy(use_proxy and not config_.proxy_server.empty());
#else
    if (not proxy.empty())
        std::cerr << "DHT proxy requested but OpenDHT built without proxy support." << std::endl;
#endif
}

void
DhtRunner::enableProxy(bool proxify)
{
#ifdef OPENDHT_PROXY_CLIENT
    if (dht_via_proxy_) {
        dht_via_proxy_->shutdown({});
    }
    if (proxify) {
        // Init the proxy client
        auto dht_via_proxy = std::unique_ptr<DhtInterface>(
            new DhtProxyClient([this]{
                if (config_.threaded) {
                    {
                        std::lock_guard<std::mutex> lck(storage_mtx);
                        pending_ops_prio.emplace([=](SecureDht&) mutable {});
                    }
                    cv.notify_all();
                }
            }, config_.proxy_server, config_.push_node_id)
        );
        dht_via_proxy_ = std::unique_ptr<SecureDht>(new SecureDht(std::move(dht_via_proxy), config_.dht_config));
#ifdef OPENDHT_PUSH_NOTIFICATIONS
        if (not pushToken_.empty())
            dht_via_proxy_->setPushNotificationToken(pushToken_);
#endif
        // add current listeners
        for (auto& l: listeners_)
            l.second.tokenProxyDht = dht_via_proxy_->listen(l.second.hash, l.second.gcb, l.second.f, l.second.w);
        // and use it
        use_proxy = proxify;
    } else {
        use_proxy = proxify;
        std::lock_guard<std::mutex> lck(storage_mtx);
        if (not listeners_.empty()) {
            pending_ops.emplace([this](SecureDht& /*dht*/) mutable {
                if (not dht_)
                    return;
                for (auto& l : listeners_) {
                    if (not l.second.tokenClassicDht) {
                        l.second.tokenClassicDht = dht_->listen(l.second.hash, l.second.gcb, l.second.f, l.second.w);
                    }
                }
            });
        }
    }
#else
    if (proxify)
        std::cerr << "DHT proxy requested but OpenDHT built without proxy support." << std::endl;
#endif
}

void
DhtRunner::forwardAllMessages(bool forward)
{
#ifdef OPENDHT_PROXY_SERVER
#ifdef OPENDHT_PROXY_CLIENT
    if (dht_via_proxy_)
        dht_via_proxy_->forwardAllMessages(forward);
#endif // OPENDHT_PROXY_CLIENT
    if (dht_)
        dht_->forwardAllMessages(forward);
#else
    (void) forward;
#endif // OPENDHT_PROXY_SERVER
}

/**
 * Updates the push notification device token
 */
void
DhtRunner::setPushNotificationToken(const std::string& token) {
#if defined(OPENDHT_PROXY_CLIENT) && defined(OPENDHT_PUSH_NOTIFICATIONS)
    pushToken_ = token;
    if (dht_via_proxy_)
        dht_via_proxy_->setPushNotificationToken(token);
#else
    (void) token;
#endif
}

void
DhtRunner::pushNotificationReceived(const std::map<std::string, std::string>& data)
{
#if defined(OPENDHT_PROXY_CLIENT) && defined(OPENDHT_PUSH_NOTIFICATIONS)
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops_prio.emplace([=](SecureDht&) {
            if (dht_via_proxy_)
                dht_via_proxy_->pushNotificationReceived(data);
        });
    }
    cv.notify_all();
#else
    (void) data;
#endif
}

}
