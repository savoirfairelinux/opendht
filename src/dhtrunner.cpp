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
static const std::string PEER_DISCOVERY_DHT_SERVICE = "dht";

struct DhtRunner::Listener {
    size_t tokenClassicDht {0};
    size_t tokenProxyDht {0};
    ValueCallback gcb;
    InfoHash hash {};
    Value::Filter f;
    Where w;
};

struct NodeInsertionPack {
    dht::InfoHash nodeId;
    in_port_t port;
    dht::NetId net;
    MSGPACK_DEFINE(nodeId, port, net)
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
DhtRunner::run(in_port_t port, const Config& config, Context&& context)
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
DhtRunner::run(const char* ip4, const char* ip6, const char* service, const Config& config, Context&& context)
{
    auto res4 = SockAddr::resolve(ip4, service);
    auto res6 = SockAddr::resolve(ip6, service);
    run(res4.empty() ? SockAddr() : res4.front(),
        res6.empty() ? SockAddr() : res6.front(), config, std::move(context));
}

void
DhtRunner::run(const SockAddr& local4, const SockAddr& local6, const Config& config, Context&& context)
{
    if (not running) {
        if (not context.sock)
            context.sock.reset(new net::UdpSocket(local4, local6, context.logger ? *context.logger : Logger{}));
        run(config, std::move(context));
    }
}

void
DhtRunner::run(const Config& config, Context&& context)
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (running)
        return;

    if (context.logger)
        logger_ = context.logger;

    context.sock->setOnReceive([&] (std::unique_ptr<net::ReceivedPacket>&& pkt) {
        {
            std::lock_guard<std::mutex> lck(sock_mtx);
            if (rcv.size() >= RX_QUEUE_MAX_SIZE) {
                std::cerr << "Dropping packet: queue is full!" << std::endl;
                rcv.pop();
            }
            rcv.emplace(std::move(pkt));
        }
        cv.notify_all();
    });

    auto dht = std::unique_ptr<DhtInterface>(new Dht(std::move(context.sock), SecureDht::getConfig(config.dht_config), context.logger ? *context.logger : Logger{}));
    dht_ = std::unique_ptr<SecureDht>(new SecureDht(std::move(dht), config.dht_config));

#ifdef OPENDHT_PROXY_CLIENT
    config_ = config;
#endif
    enableProxy(not config.proxy_server.empty());
    if (context.logger and dht_via_proxy_) {
        dht_via_proxy_->setLogger(*context.logger);
    }
    if (context.statusChangedCallback) {
        statusCb = std::move(context.statusChangedCallback);
    }
    if (context.certificateStore) {
        dht_->setLocalCertificateStore(std::move(context.certificateStore));
        if (dht_via_proxy_)
            dht_via_proxy_->setLocalCertificateStore(std::move(context.certificateStore));
    }

    running = true;
    if (not config.threaded)
        return;
    dht_thread = std::thread([this]() {
        while (running) {
            std::unique_lock<std::mutex> lk(dht_mtx);
            time_point wakeup = loop_();

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
        peerDiscovery_ = context.peerDiscovery ?
            std::move(context.peerDiscovery) :
            std::make_shared<PeerDiscovery>();
    }

    auto netId = config.dht_config.node_config.network;
    if (config.peer_discovery) {
        peerDiscovery_->startDiscovery<NodeInsertionPack>(PEER_DISCOVERY_DHT_SERVICE, [this, netId](NodeInsertionPack&& v, SockAddr&& addr){
            addr.setPort(v.port);
            if (v.nodeId != dht_->getNodeId() && netId == v.net){
                bootstrap(v.nodeId, addr);
            }
        });
    }
    if (config.peer_publish) {
        msgpack::sbuffer sbuf_node;
        NodeInsertionPack adc;
        adc.net = netId;
        adc.nodeId = dht_->getNodeId();
        // IPv4
        if (auto bound4 = dht_->getSocket()->getBound(AF_INET)) {
            adc.port = bound4.getPort();
            msgpack::pack(sbuf_node, adc);
            peerDiscovery_->startPublish(AF_INET, PEER_DISCOVERY_DHT_SERVICE, sbuf_node);
        }
        // IPv6
        if (auto bound6 = dht_->getSocket()->getBound(AF_INET6)) {
            adc.port = bound6.getPort();
            sbuf_node.clear();
            msgpack::pack(sbuf_node, adc);
            peerDiscovery_->startPublish(AF_INET6, PEER_DISCOVERY_DHT_SERVICE, sbuf_node);
        }
    }
}

void
DhtRunner::shutdown(ShutdownCallback cb) {
    if (not running) {
        cb();
        return;
    }
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([=](SecureDht&) mutable {
#ifdef OPENDHT_PROXY_CLIENT
        if (dht_via_proxy_)
            dht_via_proxy_->shutdown(cb);
#endif
        if (dht_)
            dht_->shutdown(cb);
    });
    cv.notify_all();
}

void
DhtRunner::join()
{
    if (peerDiscovery_)
        peerDiscovery_->stop();

    {
        std::lock_guard<std::mutex> lck(dht_mtx);
        running = false;
        cv.notify_all();
        bootstrap_cv.notify_all();
        if (dht_)
            if (auto sock = dht_->getSocket())
                sock->stop();
    }

    if (dht_thread.joinable())
        dht_thread.join();

    if (bootstrap_thread.joinable())
        bootstrap_thread.join();

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

SockAddr
DhtRunner::getBound(sa_family_t af) const {
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (dht_)
        if (auto sock = dht_->getSocket())
            return sock->getBound(af);
    return SockAddr{};
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
DhtRunner::setLogger(const Logger& logger) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (dht_)
        dht_->setLogger(logger);
#ifdef OPENDHT_PROXY_CLIENT
    if (dht_via_proxy_)
        dht_via_proxy_->setLogger(logger);
#endif
}

void
DhtRunner::setLoggers(LogMethod error, LogMethod warn, LogMethod debug) {
    Logger logger {std::move(error), std::move(warn), std::move(debug)};
    setLogger(logger);
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
        while (not received.empty() and now - received.front()->received > RX_QUEUE_MAX_DELAY) {
            received.pop();
            dropped++;
        }
    }

    // Handle packets
    if (not received.empty()) {
        while (not received.empty()) {
            auto& pck = received.front();
            if (clock::now() - pck->received > RX_QUEUE_MAX_DELAY)
                dropped++;
            else
                wakeup = dht->periodic(pck->data.data(), pck->data.size(), std::move(pck->from));
            received.pop();
        }
    } else {
        // Or just run the scheduler
        wakeup = dht->periodic(nullptr, 0, nullptr, 0);
    }

    if (dropped)
        std::cerr << "Dropped " << dropped << " packets with high delay" << std::endl;

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
DhtRunner::bootstrap(const std::string& hostService)
{
    std::lock_guard<std::mutex> lck(bootstrap_mtx);
    auto host_service = splitPort(hostService);
    bootstrap_nodes_all.emplace_back(host_service.first, host_service.second);
    bootstrap_nodes.emplace_back(std::move(host_service.first), std::move(host_service.second));
    tryBootstrapContinuously();
}

void
DhtRunner::clearBootstrap()
{
    std::lock_guard<std::mutex> lck(bootstrap_mtx);
    bootstrap_nodes_all.clear();
}

void
DhtRunner::bootstrap(std::vector<SockAddr> nodes, DoneCallbackSimple&& cb)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([=](SecureDht& dht) mutable {
        auto rem = cb ? std::make_shared<std::pair<size_t, bool>>(nodes.size(), false) : nullptr;
        for (auto& node : nodes) {
            if (node.getPort() == 0)
                node.setPort(net::DHT_DEFAULT_PORT);
            dht.pingNode(std::move(node), cb ? [rem,cb](bool ok) {
                auto& r = *rem;
                r.first--;
                r.second |= ok;
                if (not r.first)
                    cb(r.second);
            } : DoneCallbackSimple{});
        }
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(const SockAddr& addr, DoneCallbackSimple&& cb)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([addr, cb](SecureDht& dht) mutable {
        dht.pingNode(std::move(addr), std::move(cb));
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
    std::lock_guard<std::mutex> lck(dht_mtx);
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
            new DhtProxyClient(
                config_.server_ca,
                config_.client_identity,
                [this]{
                    if (config_.threaded) {
                        {
                            std::lock_guard<std::mutex> lck(storage_mtx);
                            pending_ops_prio.emplace([=](SecureDht&) mutable {});
                        }
                        cv.notify_all();
                    }
                },
                config_.proxy_server, config_.push_node_id, logger_)
        );
        dht_via_proxy_ = std::unique_ptr<SecureDht>(new SecureDht(std::move(dht_via_proxy), config_.dht_config));
#ifdef OPENDHT_PUSH_NOTIFICATIONS
        if (not config_.push_token.empty())
            dht_via_proxy_->setPushNotificationToken(config_.push_token);
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
    std::lock_guard<std::mutex> lck(dht_mtx);
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
    std::lock_guard<std::mutex> lck(dht_mtx);
#if defined(OPENDHT_PROXY_CLIENT) && defined(OPENDHT_PUSH_NOTIFICATIONS)
    config_.push_token = token;
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
