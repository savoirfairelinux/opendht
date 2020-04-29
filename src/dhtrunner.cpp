/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dhtrunner.h"
#include "securedht.h"
#include "network_utils.h"
#ifdef OPENDHT_PEER_DISCOVERY
#include "peer_discovery.h"
#endif
#ifdef OPENDHT_PROXY_CLIENT
#include "dht_proxy_client.h"
#endif

namespace dht {

constexpr std::chrono::seconds DhtRunner::BOOTSTRAP_PERIOD;
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
    if (running == State::Idle) {
        if (not context.sock)
            context.sock.reset(new net::UdpSocket(local4, local6, context.logger));
        run(config, std::move(context));
    }
}

void
DhtRunner::run(const Config& config, Context&& context)
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    auto expected = State::Idle;
    if (not running.compare_exchange_strong(expected, State::Running))
        return;

    if (context.logger) {
        logger_ = context.logger;
        logger_->d("[runner %p] state changed to Running", this);
    }

    context.sock->setOnReceive([&] (net::PacketList&& pkts) {
        net::PacketList ret;
        {
            std::lock_guard<std::mutex> lck(sock_mtx);
            auto maxSize = net::RX_QUEUE_MAX_SIZE - pkts.size();
            while (rcv.size() > maxSize) {
                if (logger_)
                    logger_->e("Dropping packet: queue is full!");
                rcv.pop_front();
            }

            rcv.splice(rcv.end(), std::move(pkts));
            ret = std::move(rcv_free);
        }
        cv.notify_all();
        return ret;
    });

    auto dht = std::unique_ptr<DhtInterface>(new Dht(std::move(context.sock), SecureDht::getConfig(config.dht_config), context.logger));
    dht_ = std::unique_ptr<SecureDht>(new SecureDht(std::move(dht), config.dht_config));

#ifdef OPENDHT_PROXY_CLIENT
    config_ = config;
#endif
    enableProxy(not config.proxy_server.empty());
    if (context.logger and dht_via_proxy_) {
        dht_via_proxy_->setLogger(context.logger);
    }
    if (context.statusChangedCallback) {
        statusCb = std::move(context.statusChangedCallback);
    }
    if (context.certificateStore) {
        dht_->setLocalCertificateStore(std::move(context.certificateStore));
        if (dht_via_proxy_)
            dht_via_proxy_->setLocalCertificateStore(std::move(context.certificateStore));
    }

    if (not config.threaded)
        return;
    dht_thread = std::thread([this]() {
        while (running != State::Idle) {
            std::unique_lock<std::mutex> lk(dht_mtx);
            time_point wakeup = loop_();

            auto hasJobToDo = [this]() {
                if (running == State::Idle)
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
                    if (not pending_ops.empty() and (s == NodeStatus::Connected or s == NodeStatus::Disconnected))
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
#ifdef OPENDHT_PEER_DISCOVERY
        peerDiscovery_ = context.peerDiscovery ?
            std::move(context.peerDiscovery) :
            std::make_shared<PeerDiscovery>();
#else
        std::cerr << "Peer discovery requested but OpenDHT built without peer discovery support." << std::endl;
#endif
    }

#ifdef OPENDHT_PEER_DISCOVERY
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
        if (const auto& bound4 = dht_->getSocket()->getBoundRef(AF_INET)) {
            adc.port = bound4.getPort();
            msgpack::pack(sbuf_node, adc);
            peerDiscovery_->startPublish(AF_INET, PEER_DISCOVERY_DHT_SERVICE, sbuf_node);
        }
        // IPv6
        if (const auto& bound6 = dht_->getSocket()->getBoundRef(AF_INET6)) {
            adc.port = bound6.getPort();
            sbuf_node.clear();
            msgpack::pack(sbuf_node, adc);
            peerDiscovery_->startPublish(AF_INET6, PEER_DISCOVERY_DHT_SERVICE, sbuf_node);
        }
    }
#endif
}

void
DhtRunner::shutdown(ShutdownCallback cb) {
    auto expected = State::Running;
    if (not running.compare_exchange_strong(expected, State::Stopping)) {
        if (expected == State::Stopping and ongoing_ops) {
            std::lock_guard<std::mutex> lck(storage_mtx);
            shutdownCallbacks_.emplace_back(std::move(cb));
        }
        else if (cb) cb();
        return;
    }
    if (logger_)
        logger_->d("[runner %p] state changed to Stopping, %zu ongoing ops", this, ongoing_ops.load());
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    shutdownCallbacks_.emplace_back(std::move(cb));
    pending_ops_prio.emplace([=](SecureDht&) mutable {
        auto onShutdown = [this]{ opEnded(); };
#ifdef OPENDHT_PROXY_CLIENT
        if (dht_via_proxy_)
            dht_via_proxy_->shutdown(onShutdown);
#endif
        if (dht_)
            dht_->shutdown(onShutdown);
    });
    cv.notify_all();
}

void
DhtRunner::opEnded() {
    if (--ongoing_ops == 0)
        checkShutdown();
}

DoneCallback
DhtRunner::bindOpDoneCallback(DoneCallback&& cb) {
    return [this, cb = std::move(cb)](bool ok, const std::vector<std::shared_ptr<Node>>& nodes){
        if (cb) cb(ok, nodes);
        opEnded();
    };
}

DoneCallbackSimple
DhtRunner::bindOpDoneCallback(DoneCallbackSimple&& cb) {
    return [this, cb = std::move(cb)](bool ok){
        if (cb) cb(ok);
        opEnded();
    };
}

bool
DhtRunner::checkShutdown() {
    if (running != State::Stopping or ongoing_ops)
        return false;
    decltype(shutdownCallbacks_) cbs;
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        cbs = std::move(shutdownCallbacks_);
    }
    for (auto& cb : cbs)
        if (cb) cb();
    return true;
}

void
DhtRunner::join()
{
    {
        std::lock_guard<std::mutex> lck(dht_mtx);
        if (running.exchange(State::Idle) == State::Idle)
            return;
        cv.notify_all();
#ifdef OPENDHT_PEER_DISCOVERY
        if (peerDiscovery_)
            peerDiscovery_->stop();
#endif
        if (dht_)
            if (auto sock = dht_->getSocket())
                sock->stop();
        if (logger_)
            logger_->d("[runner %p] state changed to Idle", this);
    }

    if (dht_thread.joinable())
        dht_thread.join();

    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops = decltype(pending_ops)();
        pending_ops_prio = decltype(pending_ops_prio)();
        ongoing_ops = 0;
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

in_port_t
DhtRunner::getBoundPort(sa_family_t af) const {
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (dht_)
        if (auto sock = dht_->getSocket())
            return sock->getPort(af);
    return 0;
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
DhtRunner::setLogger(const Sp<Logger>& logger) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    logger_ = logger;
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
    NodeInfo info {};
    if (auto dht = activeDht()) {
        info.id = dht->getId();
        info.node_id = dht->getNodeId();
        info.ipv4 = dht->getNodesStats(AF_INET);
        info.ipv6 = dht->getNodesStats(AF_INET6);
        if (auto sock = dht->getSocket()) {
            info.bound4 = sock->getBoundRef(AF_INET).getPort();
            info.bound6 = sock->getBoundRef(AF_INET6).getPort();
        }
    }
    info.ongoing_ops = ongoing_ops;
    return info;
}

void
DhtRunner::getNodeInfo(std::function<void(std::shared_ptr<NodeInfo>)> cb)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    pending_ops_prio.emplace([cb = std::move(cb), this](SecureDht& dht){
        auto sinfo = std::make_shared<NodeInfo>();
        auto& info = *sinfo;
        info.id = dht.getId();
        info.node_id = dht.getNodeId();
        info.ipv4 = dht.getNodesStats(AF_INET);
        info.ipv6 = dht.getNodesStats(AF_INET6);
        if (auto sock = dht.getSocket()) {
            info.bound4 = sock->getBoundRef(AF_INET).getPort();
            info.bound6 = sock->getBoundRef(AF_INET6).getPort();
        }
        info.ongoing_ops = ongoing_ops;
        cb(std::move(sinfo));
        opEnded();
    });
    cv.notify_all();
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
        ops = (pending_ops_prio.empty() && (s == NodeStatus::Connected or s == NodeStatus::Disconnected)) ?
               std::move(pending_ops) : std::move(pending_ops_prio);
    }
    while (not ops.empty()) {
        ops.front()(*dht);
        ops.pop();
    }

    time_point wakeup {};
    decltype(rcv) received {};
    decltype(rcv) received_treated {};
    {
        std::lock_guard<std::mutex> lck(sock_mtx);
        // move to stack
        received = std::move(rcv);
    }

    // Discard old packets
    size_t dropped {0};
    if (not received.empty()) {
        auto limit = clock::now() - net::RX_QUEUE_MAX_DELAY;
        auto it = received.begin();
        while (it != received.end() and it->received < limit) {
            it->data.clear();
            ++it;
            dropped++;
        }
        received_treated.splice(received_treated.end(), received, received.begin(), it);
    }

    // Handle packets
    if (not received.empty()) {
        for (auto& pkt : received) {
            auto now = clock::now();
            if (now - pkt.received > net::RX_QUEUE_MAX_DELAY)
                dropped++;
            else
                wakeup = dht->periodic(pkt.data.data(), pkt.data.size(), std::move(pkt.from), now);
            pkt.data.clear();
        }
        received_treated.splice(received_treated.end(), std::move(received));
    } else {
        // Or just run the scheduler
        wakeup = dht->periodic(nullptr, 0, nullptr, 0, clock::now());
    }

    if (not received_treated.empty()) {
        std::lock_guard<std::mutex> lck(sock_mtx);
        if (rcv_free.size() < net::RX_QUEUE_MAX_SIZE)
            rcv_free.splice(rcv_free.end(), std::move(received_treated));
    }

    if (dropped)
        std::cerr << "Dropped " << dropped << " packets with high delay" << std::endl;

    NodeStatus nstatus4 = dht->updateStatus(AF_INET);
    NodeStatus nstatus6 = dht->updateStatus(AF_INET6);
    if (nstatus4 != status4 || nstatus6 != status6) {
        status4 = nstatus4;
        status6 = nstatus6;
        if (statusCb)
            statusCb(status4, status6);
    }

    return wakeup;
}

void
DhtRunner::get(InfoHash hash, GetCallback vcb, DoneCallback dcb, Value::Filter f, Where w)
{
    if (running != State::Running) {
        if (dcb) dcb(false, {});
        return;
    }
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    pending_ops.emplace([=](SecureDht& dht) mutable {
        dht.get(hash, std::move(vcb), bindOpDoneCallback(std::move(dcb)), std::move(f), std::move(w));
    });
    cv.notify_all();
}

void
DhtRunner::get(const std::string& key, GetCallback vcb, DoneCallbackSimple dcb, Value::Filter f, Where w)
{
    get(InfoHash::get(key), std::move(vcb), std::move(dcb), std::move(f), std::move(w));
}
void
DhtRunner::query(const InfoHash& hash, QueryCallback cb, DoneCallback done_cb, Query q) {
    if (running != State::Running) {
        if (done_cb) done_cb(false, {});
        return;
    }
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    pending_ops.emplace([=](SecureDht& dht) mutable {
        dht.query(hash, std::move(cb), bindOpDoneCallback(std::move(done_cb)), std::move(q));
    });
    cv.notify_all();
}

std::future<size_t>
DhtRunner::listen(InfoHash hash, ValueCallback vcb, Value::Filter f, Where w)
{
    auto ret_token = std::make_shared<std::promise<size_t>>();
    if (running != State::Running) {
        ret_token->set_value(0);
        return ret_token->get_future();
    }
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
    cv.notify_all();
}

void
DhtRunner::cancelListen(InfoHash h, std::shared_future<size_t> ftoken)
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
    cv.notify_all();
}

void
DhtRunner::put(InfoHash hash, Value&& value, DoneCallback cb, time_point created, bool permanent)
{
    if (running != State::Running) {
        if (cb) cb(false, {});
        return;
    }
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    pending_ops.emplace([=,
        cb = std::move(cb),
        sv = std::make_shared<Value>(std::move(value))
    ] (SecureDht& dht) mutable {
        dht.put(hash, sv, bindOpDoneCallback(std::move(cb)), created, permanent);
    });
    cv.notify_all();
}

void
DhtRunner::put(InfoHash hash, std::shared_ptr<Value> value, DoneCallback cb, time_point created, bool permanent)
{
    if (running != State::Running) {
        if (cb) cb(false, {});
        return;
    }
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    pending_ops.emplace([=, cb = std::move(cb)](SecureDht& dht) mutable {
        dht.put(hash, value, bindOpDoneCallback(std::move(cb)), created, permanent);
    });
    cv.notify_all();
}

void
DhtRunner::put(const std::string& key, Value&& value, DoneCallbackSimple cb, time_point created, bool permanent)
{
    put(InfoHash::get(key), std::forward<Value>(value), std::move(cb), created, permanent);
}

void
DhtRunner::cancelPut(const InfoHash& h, Value::Id id)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops.emplace([=](SecureDht& dht) {
        dht.cancelPut(h, id);
    });
    cv.notify_all();
}

void
DhtRunner::cancelPut(const InfoHash& h, const std::shared_ptr<Value>& value)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops.emplace([=](SecureDht& dht) {
        dht.cancelPut(h, value->id);
    });
    cv.notify_all();
}

void
DhtRunner::putSigned(InfoHash hash, std::shared_ptr<Value> value, DoneCallback cb, bool permanent)
{
    if (running != State::Running) {
        if (cb) cb(false, {});
        return;
    }
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    pending_ops.emplace([=,
        cb = std::move(cb),
        value = std::move(value)
    ](SecureDht& dht) mutable {
        dht.putSigned(hash, value, bindOpDoneCallback(std::move(cb)), permanent);
    });
    cv.notify_all();
}

void
DhtRunner::putSigned(InfoHash hash, Value&& value, DoneCallback cb, bool permanent)
{
    putSigned(hash, std::make_shared<Value>(std::move(value)), std::move(cb), permanent);
}

void
DhtRunner::putSigned(const std::string& key, Value&& value, DoneCallbackSimple cb, bool permanent)
{
    putSigned(InfoHash::get(key), std::forward<Value>(value), std::move(cb), permanent);
}

void
DhtRunner::putEncrypted(InfoHash hash, InfoHash to, std::shared_ptr<Value> value, DoneCallback cb, bool permanent)
{
    if (running != State::Running) {
        if (cb) cb(false, {});
        return;
    }
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    pending_ops.emplace([=,
        cb = std::move(cb),
        value = std::move(value)
    ] (SecureDht& dht) mutable {
        dht.putEncrypted(hash, to, value, bindOpDoneCallback(std::move(cb)), permanent);
    });
    cv.notify_all();
}

void
DhtRunner::putEncrypted(InfoHash hash, InfoHash to, Value&& value, DoneCallback cb, bool permanent)
{
    putEncrypted(hash, to, std::make_shared<Value>(std::move(value)), std::move(cb), permanent);
}

void
DhtRunner::putEncrypted(const std::string& key, InfoHash to, Value&& value, DoneCallback cb, bool permanent)
{
    putEncrypted(InfoHash::get(key), to, std::forward<Value>(value), std::move(cb), permanent);
}

void
DhtRunner::bootstrap(const std::string& host, const std::string& service)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([host, service] (SecureDht& dht) mutable {
        dht.addBootstrap(host, service);
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(const std::string& hostService)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([host_service = splitPort(hostService)] (SecureDht& dht) mutable {
        dht.addBootstrap(host_service.first, host_service.second);
    });
    cv.notify_all();
}

void
DhtRunner::clearBootstrap()
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([] (SecureDht& dht) mutable {
        dht.clearBootstrap();
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(std::vector<SockAddr> nodes, DoneCallbackSimple&& cb)
{
    if (running != State::Running) {
        cb(false);
        return;
    }
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    pending_ops_prio.emplace([
        cb = bindOpDoneCallback(std::move(cb)),
        nodes = std::move(nodes)
    ] (SecureDht& dht) mutable {
        auto rem = cb ? std::make_shared<std::pair<size_t, bool>>(nodes.size(), false) : nullptr;
        for (auto& node : nodes) {
            if (node.getPort() == 0)
                node.setPort(net::DHT_DEFAULT_PORT);
            dht.pingNode(std::move(node), [rem,cb](bool ok) {
                auto& r = *rem;
                r.first--;
                r.second |= ok;
                if (r.first == 0) {
                    cb(r.second);
                }
            });
        }
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(const SockAddr& addr, DoneCallbackSimple&& cb)
{
    if (running != State::Running) {
        if (cb) cb(false);
        return;
    }
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    pending_ops_prio.emplace([addr, cb = bindOpDoneCallback(std::move(cb))](SecureDht& dht) mutable {
        dht.pingNode(std::move(addr), std::move(cb));
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(const InfoHash& id, const SockAddr& address)
{
    if (running != State::Running)
        return;
    std::unique_lock<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([id, address](SecureDht& dht) mutable {
        dht.insertNode(id, address);
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(const std::vector<NodeExport>& nodes)
{
    if (running != State::Running)
        return;
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([=](SecureDht& dht) {
        for (auto& node : nodes)
            dht.insertNode(node);
    });
    cv.notify_all();
}

void
DhtRunner::connectivityChanged()
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([=](SecureDht& dht) {
        dht.connectivityChanged();
#ifdef OPENDHT_PEER_DISCOVERY
        if (peerDiscovery_)
            peerDiscovery_->connectivityChanged();
#endif
    });
    cv.notify_all();
}

void
DhtRunner::findCertificate(InfoHash hash, std::function<void(const Sp<crypto::Certificate>&)> cb) {
    if (running != State::Running) {
        cb({});
        return;
    }
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    pending_ops.emplace([this, hash, cb = std::move(cb)] (SecureDht& dht) {
        dht.findCertificate(hash, [this, cb = std::move(cb)](const Sp<crypto::Certificate>& crt){
            cb(crt);
            opEnded();
        });
    });
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
#ifdef OPENDHT_PUSH_NOTIFICATIONS
        if (not config_.push_token.empty())
            dht_via_proxy->setPushNotificationToken(config_.push_token);
#endif
        dht_via_proxy_ = std::unique_ptr<SecureDht>(new SecureDht(std::move(dht_via_proxy), config_.dht_config));
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
