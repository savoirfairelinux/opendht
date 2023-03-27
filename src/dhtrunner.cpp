/*
 *  Copyright (C) 2014-2022 Savoir-faire Linux Inc.
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
#ifdef OPENDHT_PEER_DISCOVERY
#include "peer_discovery.h"
#endif
#ifdef OPENDHT_PROXY_CLIENT
#include "dht_proxy_client.h"
#endif

#include <fstream>

namespace dht {

static const std::string PEER_DISCOVERY_DHT_SERVICE = "dht";

struct NodeInsertionPack {
    dht::InfoHash nodeId;
    in_port_t port;
    dht::NetId net;
    MSGPACK_DEFINE(nodeId, port, net)
};

DhtRunner::DhtRunner() : dht_()
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
DhtRunner::run(in_port_t port, Config& config, Context&& context)
{
    config.bind4 = {asio::ip::address_v4::any(), port};
    config.bind6 = {asio::ip::address_v6::any(), port};
    run(config, std::move(context));
}

void
DhtRunner::run(const char* ip4, const char* ip6, const char* service, Config& config, Context&& context)
{
    auto s = asio::ip::udp::resolver::query(service);
    asio::ip::udp::resolver resolver(*context.ioContext);
    auto res4 = resolver.resolve(ip4, service);
    auto res6 = resolver.resolve(ip6, service);
    if (not res4.empty())
        config.bind4 = std::move(*res4.begin());
    if (not res6.empty())
        config.bind6 = std::move(*res6.begin());
    run(config, std::move(context));
}

void
DhtRunner::run(const Config& config, Context&& context)
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    auto expected = State::Idle;
    if (not running.compare_exchange_strong(expected, State::Running)) {
        if (context.logger)
            context.logger->w("[runner %p] Node is already running. Call join() first before calling run() again.", this);
        return;
    }

    try {
        auto local4 = config.bind4;
        auto local6 = config.bind6;
        auto state_path = config.dht_config.node_config.persist_path;
        if (not state_path.empty())
            state_path += "_port.txt";
        if (not state_path.empty() && (local4.port() == 0 || local6.port() == 0)) {
            std::ifstream inConfig(state_path);
            if (inConfig.is_open()) {
                in_port_t port;
                if (inConfig >> port) {
                    if (local4.port() == 0) {
                        if (context.logger)
                            context.logger->d("[runner %p] Using IPv4 port %hu from saved configuration", this, port);
                        local4.port(port);
                    }
                }
                if (inConfig >> port) {
                    if (local6.port() == 0) {
                        if (context.logger)
                            context.logger->d("[runner %p] Using IPv6 port %hu from saved configuration", this, port);
                        local6.port(port);
                    }
                }
            }
        }

        if (context.logger) {
            logger_ = context.logger;
            logger_->d("[runner %p] state changed to Running", this);
        }

#ifdef OPENDHT_PROXY_CLIENT
        config_ = config;
        identityAnnouncedCb_ = context.identityAnnouncedCb;
#endif

        if (not context.ioContext)
            context.ioContext.reset(new asio::io_context);

        ioContext_ = context.ioContext;
        strand_ = std::make_shared<asio::io_context::strand>(asio::io_context::strand(*ioContext_));

        if (config.proxy_server.empty()) {
            if (not context.sock) {
                //if (context.logger)
                //    context.logger->d("[runner %p] Creating new socket with local addresses %s and %s", this, local4.toString().c_str(), local6.toString().c_str());
                context.sock.reset(new net::UdpSocket(strand_, local4, local6/*, context.logger*/));
            }
            if (not state_path.empty()) {
                std::ofstream outConfig(state_path);
                outConfig << context.sock->getPort(AF_INET) << std::endl;
                outConfig << context.sock->getPort(AF_INET6) << std::endl;
            }
            auto dht = std::make_unique<Dht>(strand_, std::move(context.sock), SecureDht::getConfig(config.dht_config), context.logger);
            dht_ = std::make_unique<SecureDht>(std::move(dht), config.dht_config, std::move(context.identityAnnouncedCb), context.logger);
        } else {
            enableProxy(true);
        }
    } catch(const std::exception& e) {
        config_ = {};
        identityAnnouncedCb_ = {};
        dht_.reset();
        running = State::Idle;
        throw;
    }

    dht_->addOnStateChangeCallback([this](const DhtNodeStatus& status){
        if (status.get() != NodeStatus::Connecting) {
            auto pending = std::move(pending_ops);
            while (not pending.empty()) {
                pending.front()(*dht_);
                pending.pop();
            }
        }
    });

    if (context.statusChangedCallback) {
        if (logger_)
            logger_->d("[dhtrunner] starting io_context");
        dht_->addOnStateChangeCallback(std::move(context.statusChangedCallback));
    }
    if (context.certificateStore) {
        dht_->setLocalCertificateStore(std::move(context.certificateStore));
    }

    if (not config.threaded)
        return;
    dht_thread = std::thread([this]() {
        try {
            if (logger_)
                logger_->d("[dhtrunner] starting io_context");
            // Ensures the context won't run out of work
            auto work = asio::make_work_guard(*ioContext_);
            ioContext_->run();
            if (logger_)
                logger_->d("[dhtrunner] io_context stopped");
        }
        catch(const std::exception& ex){
            if (logger_)
                logger_->e("[dhtrunner] run error: %s", ex.what());
        }
    });

    if (config.proxy_server.empty()) {
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
                addr.port(v.port);
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
            if (auto socket = dht_->getSocket()) {
                // IPv4
                const auto& bound4 = socket->getBound(AF_INET);
                if (bound4 != asio::ip::udp::endpoint{}) {
                    adc.port = bound4.port();
                    msgpack::pack(sbuf_node, adc);
                    peerDiscovery_->startPublish(AF_INET, PEER_DISCOVERY_DHT_SERVICE, sbuf_node);
                }
                // IPv6
                const auto& bound6 = socket->getBound(AF_INET6);
                if (bound6 != asio::ip::udp::endpoint{}) {
                    adc.port = bound6.port();
                    sbuf_node.clear();
                    msgpack::pack(sbuf_node, adc);
                    peerDiscovery_->startPublish(AF_INET6, PEER_DISCOVERY_DHT_SERVICE, sbuf_node);
                }
            }
        }
#endif
    }
}

void
DhtRunner::shutdown(ShutdownCallback cb, bool stop) {
    //std::unique_lock<std::mutex> lck(storage_mtx);
    auto expected = State::Running;
    if (not running.compare_exchange_strong(expected, State::Stopping)) {
        if (expected == State::Stopping and ongoing_ops) {
            if (cb)
                shutdownCallbacks_.emplace_back(std::move(cb));
                //asio::post(*ioContext_, [cb] { cb(); });
                // ioContext_->post([cb] { cb(); });
        }
        else if (cb) {
            cb();
        }
        return;
    }
    if (logger_)
        logger_->d("[runner %p] state changed to Stopping, %zu ongoing ops", this, ongoing_ops.load());
    ongoing_ops++;
    shutdownCallbacks_.emplace_back(std::move(cb));
    post([=]() mutable {
        auto onShutdown = [this]{ opEnded(); };
        if (dht_)
            dht_->shutdown(onShutdown, stop);
        else
            opEnded();
    });
    //cv.notify_all();
}

void
DhtRunner::postOp(std::function<void(SecureDht&)>&& op, bool prio) {
    ongoing_ops++;
    /*if (prio)
        ioContext_->post(asio::bind_executor(*strand_, std::move(op)));
    else*/
        ioContext_->post(asio::bind_executor(*strand_, [this, prio, op=std::move(op)]{
            if (dht_ && (prio || dht_->getStatus() != NodeStatus::Connecting))
                op(*dht_);
            else
                pending_ops.emplace(std::move(op));
        }));
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
    decltype(shutdownCallbacks_) cbs;
    {
        if (running != State::Stopping or ongoing_ops)
            return false;
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
        /*if (dht_)
            if (auto sock = dht_->getSocket())
                sock->stop();*/
        if (logger_)
            logger_->d("[runner %p] state changed to Idle", this);
    }

    if (dht_thread.joinable()) {
        ioContext_->stop();
        dht_thread.join();
    }

    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        if (ongoing_ops and logger_) {
            logger_->w("[runner %p] stopping with %zu remaining ops", this, ongoing_ops.load());
        }
        ongoing_ops = 0;
        shutdownCallbacks_.clear();
    }
    {
        std::lock_guard<std::mutex> lck(dht_mtx);
        resetDht();
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
            return sock->getBound(af).port();
    return 0;
}

void
DhtRunner::dumpTables() const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    dht_->dumpTables();
}

InfoHash
DhtRunner::getId() const
{
    return dht_ ? dht_->getId() : InfoHash{};
}

std::shared_ptr<crypto::PublicKey>
DhtRunner::getPublicKey() const
{
    return dht_ ? dht_->getPublicKey() : std::shared_ptr<crypto::PublicKey>{};
}

InfoHash
DhtRunner::getNodeId() const
{
    return dht_ ? dht_->getNodeId() : InfoHash{};
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
}

void
DhtRunner::registerType(const ValueType& type) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    dht_->registerType(type);
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
    const auto stats = dht_->getNodesStats(af);
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
    return dht_->getNodesStats(af);
}

NodeInfo
DhtRunner::getNodeInfo() const {
    std::lock_guard<std::mutex> lck(dht_mtx);
    NodeInfo info {};
    if (dht_) {
        info.id = dht_->getId();
        info.node_id = dht_->getNodeId();
        info.ipv4 = dht_->getNodesStats(AF_INET);
        info.ipv6 = dht_->getNodesStats(AF_INET6);
        if (auto sock = dht_->getSocket()) {
            info.bound4 = sock->getBound(AF_INET).port();
            info.bound6 = sock->getBound(AF_INET6).port();
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
    post([cb = std::move(cb), this](){
        auto sinfo = std::make_shared<NodeInfo>();
        auto& info = *sinfo;
        info.id = dht_->getId();
        info.node_id = dht_->getNodeId();
        info.ipv4 = dht_->getNodesStats(AF_INET);
        info.ipv6 = dht_->getNodesStats(AF_INET6);
        std::tie(info.storage_size, info.storage_values) = dht_->getStoreSize();
        if (auto sock = dht_->getSocket()) {
            info.bound4 = sock->getBound(AF_INET).port();
            info.bound6 = sock->getBound(AF_INET6).port();
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
    return dht_->getNodeMessageStats(in);
}

std::string
DhtRunner::getStorageLog() const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return dht_->getStorageLog();
}
std::string
DhtRunner::getStorageLog(const InfoHash& f) const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return dht_->getStorageLog(f);
}
std::string
DhtRunner::getRoutingTablesLog(sa_family_t af) const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return dht_->getRoutingTablesLog(af);
}
std::string
DhtRunner::getSearchesLog(sa_family_t af) const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return dht_->getSearchesLog(af);
}
std::string
DhtRunner::getSearchLog(const InfoHash& f, sa_family_t af) const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return dht_->getSearchLog(f, af);
}
std::vector<SockAddr>
DhtRunner::getPublicAddress(sa_family_t af) const
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (dht_)
        return dht_->getPublicAddress(af);
    return {};
}
std::vector<std::string>
DhtRunner::getPublicAddressStr(sa_family_t af) const
{
    auto addrs = getPublicAddress(af);
    std::vector<std::string> ret(addrs.size());
    std::transform(addrs.begin(), addrs.end(), ret.begin(), [](const SockAddr& a) {
        return asio::ip::detail::endpoint(a.address(), a.port()).to_string();
        /*std::ostringstream ss;
        ss << a;
        return ss.str();*/
    });
    return ret;
}

void
DhtRunner::getPublicAddress(std::function<void(std::vector<SockAddr>&&)> cb, sa_family_t af)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    post([cb = std::move(cb), this, af](){
        cb(dht_->getPublicAddress(af));
        opEnded();
    });
    cv.notify_all();
}

void
DhtRunner::registerCertificate(std::shared_ptr<crypto::Certificate> cert) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    dht_->registerCertificate(cert);
}

void
DhtRunner::setLocalCertificateStore(CertificateStoreQuery&& query_method) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (dht_)
        dht_->setLocalCertificateStore(std::forward<CertificateStoreQuery>(query_method));
}
/*
time_point
DhtRunner::loop_()
{
    if (not dht_)
        return {};

    decltype(pending_ops) ops {};
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        auto s = getStatus();
        ops = (pending_ops_prio.empty() && (s == NodeStatus::Connected or s == NodeStatus::Disconnected)) ?
               std::move(pending_ops) : std::move(pending_ops_prio);
    }
    while (not ops.empty()) {
        ops.front()(*dht_);
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
                wakeup = dht_->periodic(pkt.data.data(), pkt.data.size(), std::move(pkt.from), now);
            pkt.data.clear();
        }
        received_treated.splice(received_treated.end(), std::move(received));
    } else {
        // Or just run the scheduler
        wakeup = dht_->periodic(nullptr, 0, nullptr, 0, clock::now());
    }

    if (not received_treated.empty()) {
        std::lock_guard<std::mutex> lck(sock_mtx);
        if (rcv_free.size() < net::RX_QUEUE_MAX_SIZE)
            rcv_free.splice(rcv_free.end(), std::move(received_treated));
    }

    if (dropped && logger_)
        logger_->e("[runner %p] Dropped %zu packets with high delay.", this, dropped);

    NodeStatus nstatus4 = dht_->updateStatus(AF_INET);
    NodeStatus nstatus6 = dht_->updateStatus(AF_INET6);
    if (nstatus4 != status4 || nstatus6 != status6) {
        status4 = nstatus4;
        status6 = nstatus6;
        if (statusCb)
            statusCb(status4, status6);
    }

    return wakeup;
}*/

void
DhtRunner::get(InfoHash hash, GetCallback vcb, DoneCallback dcb, Value::Filter f, Where w)
{
    if (running != State::Running) {
        if (dcb) dcb(false, {});
        return;
    }
    postOp([
        hash,
        vcb = std::move(vcb),
        dcb=bindOpDoneCallback(std::move(dcb)),
        f = std::move(f),
        w = std::move(w)
    ](SecureDht& dht) mutable {
        dht.get(hash, std::move(vcb), std::move(dcb), std::move(f), std::move(w));
    });
}

void
DhtRunner::get(const std::string& key, GetCallback vcb, DoneCallbackSimple dcb, Value::Filter f, Where w)
{
    get(InfoHash::get(key), std::move(vcb), std::move(dcb), std::move(f), std::move(w));
}
void
DhtRunner::query(const InfoHash& hash, QueryCallback cb, DoneCallback done_cb, Query q) {
    std::unique_lock<std::mutex> lck(storage_mtx);
    if (running != State::Running) {
        lck.unlock();
        if (done_cb) done_cb(false, {});
        return;
    }
    postOp([=](SecureDht& dht) mutable {
        dht.query(hash, std::move(cb), bindOpDoneCallback(std::move(done_cb)), std::move(q));
    });
}

std::future<size_t>
DhtRunner::listen(InfoHash hash, ValueCallback vcb, Value::Filter f, Where w)
{
    auto ret_token = std::make_shared<std::promise<size_t>>();
    std::unique_lock<std::mutex> lck(storage_mtx);
    if (running != State::Running) {
        lck.unlock();
        ret_token->set_value(0);
        return ret_token->get_future();
    }
    post([=]() mutable {
        ret_token->set_value(dht_->listen(hash, std::move(vcb), std::move(f), std::move(w)));
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
    if (running != State::Running)
        return;
    postOp([=](SecureDht& dht) {
        dht.cancelListen(h, token);
        opEnded();
    });
}

void
DhtRunner::cancelListen(InfoHash h, std::shared_future<size_t> ftoken)
{
    if (running != State::Running)
        return;
    postOp([this, h, ftoken = std::move(ftoken)](SecureDht& dht) {
        dht.cancelListen(h, ftoken.get());
        opEnded();
    });
}

void
DhtRunner::put(InfoHash hash, Value&& value, DoneCallback cb, time_point created, bool permanent)
{
    std::unique_lock<std::mutex> lck(storage_mtx);
    if (running != State::Running) {
        lck.unlock();
        if (cb) cb(false, {});
        return;
    }
    postOp([=,
        cb = std::move(cb),
        sv = std::make_shared<Value>(std::move(value))
    ] (SecureDht& dht) mutable {
        dht.put(hash, sv, bindOpDoneCallback(std::move(cb)), created, permanent);
    });
}

void
DhtRunner::put(InfoHash hash, std::shared_ptr<Value> value, DoneCallback cb, time_point created, bool permanent)
{
    std::unique_lock<std::mutex> lck(storage_mtx);
    if (running != State::Running) {
        lck.unlock();
        if (cb) cb(false, {});
        return;
    }
    postOp([=, value = std::move(value), cb = std::move(cb)](SecureDht& dht) mutable {
        dht.put(hash, value, bindOpDoneCallback(std::move(cb)), created, permanent);
    });
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
    post([=]() {
        dht_->cancelPut(h, id);
    });
}

void
DhtRunner::cancelPut(const InfoHash& h, const std::shared_ptr<Value>& value)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    post([=]() {
        dht_->cancelPut(h, value->id);
    });
}

void
DhtRunner::putSigned(InfoHash hash, std::shared_ptr<Value> value, DoneCallback cb, bool permanent)
{
    std::unique_lock<std::mutex> lck(storage_mtx);
    if (running != State::Running) {
        lck.unlock();
        if (cb) cb(false, {});
        return;
    }
    postOp([=,
        cb = std::move(cb),
        value = std::move(value)
    ](SecureDht& dht) mutable {
        dht.putSigned(hash, value, bindOpDoneCallback(std::move(cb)), permanent);
    });
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
    std::unique_lock<std::mutex> lck(storage_mtx);
    if (running != State::Running) {
        lck.unlock();
        if (cb) cb(false, {});
        return;
    }
    postOp([=,
        cb = std::move(cb),
        value = std::move(value)
    ] (SecureDht& dht) mutable {
        dht.putEncrypted(hash, to, value, bindOpDoneCallback(std::move(cb)), permanent);
    });
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
DhtRunner::putEncrypted(InfoHash hash, const std::shared_ptr<crypto::PublicKey>& to, std::shared_ptr<Value> value, DoneCallback cb, bool permanent)
{
    std::unique_lock<std::mutex> lck(storage_mtx);
    if (running != State::Running) {
        lck.unlock();
        if (cb) cb(false, {});
        return;
    }
    ongoing_ops++;
    postOp([=,
        cb = std::move(cb),
        value = std::move(value)
    ] (SecureDht& dht) mutable {
        dht.putEncrypted(hash, *to, value, bindOpDoneCallback(std::move(cb)), permanent);
    });
    cv.notify_all();
}

void
DhtRunner::putEncrypted(InfoHash hash, const std::shared_ptr<crypto::PublicKey>& to, Value&& value, DoneCallback cb, bool permanent)
{
    putEncrypted(hash, to, std::make_shared<Value>(std::move(value)), std::move(cb), permanent);
}

void
DhtRunner::bootstrap(const std::string& host, const std::string& service)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    post([this, host, service] () mutable {
        dht_->addBootstrap(host, service);
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(const std::string& hostService)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    post([this, host_service = splitPort(hostService)] () mutable {
        dht_->addBootstrap(host_service.first, host_service.second);
    });
    cv.notify_all();
}

void
DhtRunner::clearBootstrap()
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    post([this] () mutable {
        dht_->clearBootstrap();
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(std::vector<SockAddr> nodes, DoneCallbackSimple cb)
{
    if (running != State::Running) {
        cb(false);
        return;
    }
    std::lock_guard<std::mutex> lck(storage_mtx);
    ongoing_ops++;
    post([this,
        cb = bindOpDoneCallback(std::move(cb)),
        nodes = std::move(nodes)
    ] () mutable {
        auto rem = cb ? std::make_shared<std::pair<size_t, bool>>(nodes.size(), false) : nullptr;
        for (auto& node : nodes) {
            if (node.port() == 0)
                node.port(net::DHT_DEFAULT_PORT);
            dht_->pingNode(std::move(node), [rem,cb](bool ok) {
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
DhtRunner::bootstrap(SockAddr addr, DoneCallbackSimple cb)
{
    std::unique_lock<std::mutex> lck(storage_mtx);
    if (running != State::Running) {
        lck.unlock();
        if (cb) cb(false);
        return;
    }
    ongoing_ops++;
    if (addr.address().is_unspecified())
        addr.address(addr.address().is_v4() ? asio::ip::address(asio::ip::address_v4::loopback()) : asio::ip::address(asio::ip::address_v6::loopback()));
    post([this, addr = std::move(addr), cb = bindOpDoneCallback(std::move(cb))]() mutable {
        dht_->pingNode(std::move(addr), std::move(cb));
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(const InfoHash& id, const SockAddr& address)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    if (running != State::Running)
        return;
    post([this, id, address]() mutable {
        dht_->insertNode(id, address);
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(std::vector<NodeExport> nodes)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    if (running != State::Running)
        return;
    post([this, nodes = std::move(nodes)]() {
        for (auto& node : nodes)
            dht_->insertNode(node);
    });
    cv.notify_all();
}

void
DhtRunner::connectivityChanged()
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    post([=]() {
        dht_->connectivityChanged();
#ifdef OPENDHT_PEER_DISCOVERY
        if (peerDiscovery_)
            peerDiscovery_->connectivityChanged();
#endif
    });
    cv.notify_all();
}

void
DhtRunner::findCertificate(InfoHash hash, std::function<void(const Sp<crypto::Certificate>&)> cb) {
    std::unique_lock<std::mutex> lck(storage_mtx);
    if (running != State::Running) {
        lck.unlock();
        cb({});
        return;
    }
    postOp([this, hash, cb = std::move(cb)] (SecureDht& dht) {
        dht.findCertificate(hash, [this, cb = std::move(cb)](const Sp<crypto::Certificate>& crt){
            cb(crt);
            opEnded();
        });
    });
}

void
DhtRunner::resetDht()
{
    peerDiscovery_.reset();
    dht_.reset();
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
        throw std::runtime_error("DHT proxy requested but OpenDHT built without proxy support.");
    (void) pushNodeId;
#endif
}

void
DhtRunner::enableProxy(bool proxify)
{
#ifdef OPENDHT_PROXY_CLIENT
    if (dht_) {
        dht_->shutdown({});
    }
    if (proxify) {
        // Init the proxy client
        auto dht_via_proxy = std::make_unique<DhtProxyClient>(
                config_.server_ca,
                config_.client_identity,
                strand_,
                config_.proxy_server, config_.push_node_id, logger_);
        if (not config_.push_token.empty())
            dht_via_proxy->setPushNotificationToken(config_.push_token);
        if (not config_.push_topic.empty())
            dht_via_proxy->setPushNotificationTopic(config_.push_topic);
        if (not config_.push_platform.empty())
            dht_via_proxy->setPushNotificationPlatform(config_.push_platform);
        dht_ = std::make_unique<SecureDht>(std::move(dht_via_proxy), config_.dht_config, identityAnnouncedCb_, logger_);
        // and use it
        use_proxy = proxify;
    } else {
        use_proxy = proxify;
    }
#else
    if (proxify)
        throw std::runtime_error("DHT proxy requested but OpenDHT built without proxy support.");
#endif
}

void
DhtRunner::forwardAllMessages(bool forward)
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (dht_)
        dht_->forwardAllMessages(forward);
}

/**
 * Updates the push notification device token
 */
void
DhtRunner::setPushNotificationToken(const std::string& token) {
    std::lock_guard<std::mutex> lck(dht_mtx);
#if defined(OPENDHT_PROXY_CLIENT) && defined(OPENDHT_PUSH_NOTIFICATIONS)
    config_.push_token = token;
    if (dht_)
        dht_->setPushNotificationToken(token);
#else
    (void) token;
#endif
}

void
DhtRunner::setPushNotificationTopic(const std::string& topic) {
    std::lock_guard<std::mutex> lck(dht_mtx);
#if defined(OPENDHT_PROXY_CLIENT) && defined(OPENDHT_PUSH_NOTIFICATIONS)
    config_.push_topic = topic;
    if (dht_)
        dht_->setPushNotificationTopic(topic);
#else
    (void) topic;
#endif
}

void
DhtRunner::setPushNotificationPlatform(const std::string& platform) {
    std::lock_guard<std::mutex> lck(dht_mtx);
#if defined(OPENDHT_PROXY_CLIENT) && defined(OPENDHT_PUSH_NOTIFICATIONS)
    config_.push_platform = platform;
    if (dht_)
        dht_->setPushNotificationPlatform(platform);
#else
    (void) platform;
#endif
}

void
DhtRunner::pushNotificationReceived(const std::map<std::string, std::string>& data)
{
#if defined(OPENDHT_PROXY_CLIENT) && defined(OPENDHT_PUSH_NOTIFICATIONS)
    std::lock_guard<std::mutex> lck(storage_mtx);
    post([=]() {
        if (dht_)
            dht_->pushNotificationReceived(data);
    });
    cv.notify_all();
#else
    (void) data;
#endif
}

}
