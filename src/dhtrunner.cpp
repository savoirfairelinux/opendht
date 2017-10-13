/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
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

namespace dht {

constexpr std::chrono::seconds DhtRunner::BOOTSTRAP_PERIOD;

DhtRunner::DhtRunner() : dht_()
{
    uv_async_.data = this;
    uv_async_init(uv_loop_.get(), &uv_async_, &DhtRunner::loop_callback);
}

DhtRunner::~DhtRunner()
{
    join();
}

void
DhtRunner::run(DhtRunner::Config config)
{
    if (running)
        return;
    running = true;
    doRun(config.dht_config);
    if (not config.threaded)
        return;
    dht_thread = std::thread([this]() {
        uv_loop_.run();
    });
}

void
DhtRunner::shutdown(ShutdownCallback cb) {
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([=](SecureDht& dht) mutable {
        dht.shutdown(cb);
    });
    uv_async_send(&uv_async_);
}

void
DhtRunner::join()
{
    running = false;
    uv_async_send(&uv_async_);
    //bootstrap_cv.notify_all();
    if (dht_thread.joinable())
        dht_thread.join();
    /*if (bootstrap_thread.joinable())
        bootstrap_thread.join();*/

    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops = decltype(pending_ops)();
        pending_ops_prio = decltype(pending_ops_prio)();
    }
    {
        std::lock_guard<std::mutex> lck(dht_mtx);
        dht_.reset();
        /*status4 = NodeStatus::Disconnected;
        status6 = NodeStatus::Disconnected;
        bound4 = {};
        bound6 = {};*/
    }
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
    if (!dht_)
        return {};
    return dht_->getId();
}

InfoHash
DhtRunner::getNodeId() const
{
    if (!dht_)
        return {};
    return dht_->getNodeId();
}

void
DhtRunner::setOnStatusChanged(StatusCallback&& cb)
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    if (not dht_)
        throw std::runtime_error("dht is not running");
    dht_->setOnStatusChanged(std::move(cb));
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
    dht_->setLoggers(std::forward<LogMethod>(error), std::forward<LogMethod>(warn), std::forward<LogMethod>(debug));
}

void
DhtRunner::setLogFilter(const InfoHash& f) {
    std::lock_guard<std::mutex> lck(dht_mtx);
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
DhtRunner::getPublicAddress(sa_family_t af)
{
    std::lock_guard<std::mutex> lck(dht_mtx);
    return dht_->getPublicAddress(af);
}
std::vector<std::string>
DhtRunner::getPublicAddressStr(sa_family_t af)
{
    auto addrs = getPublicAddress(af);
    std::vector<std::string> ret(addrs.size());
    std::transform(addrs.begin(), addrs.end(), ret.begin(), [](const SockAddr& a) { return a.toString(); });
    return ret;
}

SockAddr 
DhtRunner::getBound() const {
    return dht_->getBoundAddr();
}

void
DhtRunner::registerCertificate(std::shared_ptr<crypto::Certificate> cert) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    dht_->registerCertificate(cert);
}
void
DhtRunner::setLocalCertificateStore(CertificateStoreQuery&& query_method) {
    std::lock_guard<std::mutex> lck(dht_mtx);
    dht_->setLocalCertificateStore(std::forward<CertificateStoreQuery>(query_method));
}

void
DhtRunner::loop_()
{
    if (!dht_)
        return;
/*
    NodeStatus nstatus4 = dht_->getStatus(AF_INET);
    NodeStatus nstatus6 = dht_->getStatus(AF_INET6);
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
*/
    decltype(pending_ops) ops {};
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        auto s = dht_->getStatus();
        ops = (pending_ops_prio.empty() && (s == NodeStatus::Connected or (s == NodeStatus::Disconnected and not bootstraping))) ?
               std::move(pending_ops) : std::move(pending_ops_prio);
    }
    while (not ops.empty()) {
        ops.front()(*dht_);
        ops.pop();
    }
}

void
DhtRunner::doRun(SecureDht::Config config)
{
    dht_ = std::unique_ptr<SecureDht>(new SecureDht {uv_loop_.get(), config});
}

void
DhtRunner::get(InfoHash hash, GetCallback vcb, DoneCallback dcb, Value::Filter f, Where w)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) mutable {
            std::cout << "DhtRunner dht.get " << hash << std::endl;
            dht.get(hash, vcb, dcb, std::move(f), std::move(w));
        });
    }
    uv_async_send(&uv_async_);
}

void
DhtRunner::get(const std::string& key, GetCallback vcb, DoneCallbackSimple dcb, Value::Filter f, Where w)
{
    get(InfoHash::get(key), vcb, dcb, f, w);
}
void DhtRunner::query(const InfoHash& hash, QueryCallback cb, DoneCallback done_cb, Query q) {
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) mutable {
            dht.query(hash, cb, done_cb, std::move(q));
        });
    }
    uv_async_send(&uv_async_);
}

std::future<size_t>
DhtRunner::listen(InfoHash hash, GetCallback vcb, Value::Filter f, Where w)
{
    auto ret_token = std::make_shared<std::promise<size_t>>();
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) mutable {
            ret_token->set_value(dht.listen(hash, vcb, std::move(f), std::move(w)));
        });
    }
    uv_async_send(&uv_async_);
    return ret_token->get_future();
}

std::future<size_t>
DhtRunner::listen(const std::string& key, GetCallback vcb, Value::Filter f, Where w)
{
    return listen(InfoHash::get(key), vcb, f, w);
}

void
DhtRunner::cancelListen(InfoHash h, size_t token)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) {
            dht.cancelListen(h, token);
        });
    }
    uv_async_send(&uv_async_);
}

void
DhtRunner::cancelListen(InfoHash h, std::shared_future<size_t> token)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) {
            auto tk = token.get();
            dht.cancelListen(h, tk);
        });
    }
    uv_async_send(&uv_async_);
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
    uv_async_send(&uv_async_);
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
    uv_async_send(&uv_async_);
}

void
DhtRunner::put(const std::string& key, Value&& value, DoneCallbackSimple cb, time_point created, bool permanent)
{
    put(InfoHash::get(key), std::forward<Value>(value), cb, created, permanent);
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
    uv_async_send(&uv_async_);
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
    uv_async_send(&uv_async_);
}

void
DhtRunner::putSigned(InfoHash hash, Value&& value, DoneCallback cb)
{
    putSigned(hash, std::make_shared<Value>(std::move(value)), cb);
}

void
DhtRunner::putSigned(const std::string& key, Value&& value, DoneCallbackSimple cb)
{
    putSigned(InfoHash::get(key), std::forward<Value>(value), cb);
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
    uv_async_send(&uv_async_);
}

void
DhtRunner::putEncrypted(InfoHash hash, InfoHash to, Value&& value, DoneCallback cb)
{
    putEncrypted(hash, to, std::make_shared<Value>(std::move(value)), cb);
}

void
DhtRunner::putEncrypted(const std::string& key, InfoHash to, Value&& value, DoneCallback cb)
{
    putEncrypted(InfoHash::get(key), to, std::forward<Value>(value), cb);
}

/*
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
                        bootstrap(getAddrInfo(it->first, it->second), [&](bool) {
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
}*/

std::vector<std::pair<sockaddr_storage, socklen_t>>
DhtRunner::getAddrInfo(const std::string& host, const std::string& service)
{
    std::vector<std::pair<sockaddr_storage, socklen_t>> ips {};
    if (host.empty())
        return ips;

    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* info = nullptr;
    int rc = getaddrinfo(host.c_str(), service.c_str(), &hints, &info);
    if(rc != 0)
        throw std::invalid_argument(std::string("Error: `") + host + ":" + service + "`: " + gai_strerror(rc));

    addrinfo* infop = info;
    while (infop) {
        ips.emplace_back(sockaddr_storage(), infop->ai_addrlen);
        std::copy_n((uint8_t*)infop->ai_addr, infop->ai_addrlen, (uint8_t*)&ips.back().first);
        infop = infop->ai_next;
    }
    freeaddrinfo(info);
    return ips;
}

void
DhtRunner::bootstrap(const std::string& host, const std::string& service)
{
    /*std::lock_guard<std::mutex> lck(bootstrap_mtx);
    bootstrap_nodes_all.emplace_back(host, service);
    bootstrap_nodes.emplace_back(host, service);
    tryBootstrapContinuously();*/
    pending_ops_prio.emplace([=](SecureDht& dht) mutable {
        dht.bootstrap(host, service);
    });
    uv_async_send(&uv_async_);
}

void
DhtRunner::clearBootstrap()
{
    //std::lock_guard<std::mutex> lck(bootstrap_mtx);
    //bootstrap_nodes_all.clear();
    pending_ops_prio.emplace([=](SecureDht& dht) mutable {
        dht.clearBootstrap();
    });
    uv_async_send(&uv_async_);
}

void
DhtRunner::ping(const std::vector<std::pair<sockaddr_storage, socklen_t>>& nodes, DoneCallback&& cb)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([=](SecureDht& dht) mutable {
        struct GroupPing {
            size_t remaining {0};
            bool ok {false};
            std::vector<Sp<Node>> nodes;
            GroupPing(size_t s) : remaining(s) {}
        };
        Sp<GroupPing> rem = cb ? std::make_shared<GroupPing>(nodes.size()) : nullptr;
        for (auto& node : nodes)
            dht.pingNode(SockAddr((sockaddr*)&node.first, node.second), cb ? [rem,cb](bool ok, std::vector<Sp<Node>>&& nodes) {
                auto& r = *rem;
                r.remaining--;
                r.ok |= ok;
                r.nodes.insert(r.nodes.end(), nodes.begin(), nodes.end());
                if (r.remaining == 0)
                    cb(r.ok, std::move(r.nodes));
            } : DoneCallback{});
    });
    uv_async_send(&uv_async_);
}

void
DhtRunner::ping(const SockAddr& addr, DoneCallback&& cb)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([addr,cb](SecureDht& dht) mutable {
        dht.pingNode(addr, std::move(cb));
    });
    uv_async_send(&uv_async_);
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
    uv_async_send(&uv_async_);
}

void
DhtRunner::connectivityChanged()
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) {
            dht.connectivityChanged();
        });
    }
    uv_async_send(&uv_async_);
}

void
DhtRunner::findCertificate(InfoHash hash, std::function<void(const std::shared_ptr<crypto::Certificate>)> cb) {
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) {
            dht.findCertificate(hash, cb);
        });
    }
    uv_async_send(&uv_async_);
}

}
