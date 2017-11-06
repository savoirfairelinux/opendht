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

#ifndef _WIN32
#include <unistd.h>
#else
#include <io.h>
#endif

#ifndef _WIN32
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#define close(x) closesocket(x)
#endif

namespace dht {

constexpr std::chrono::seconds DhtRunner::BOOTSTRAP_PERIOD;

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
DhtRunner::run(in_port_t port, DhtRunner::Config config)
{
    SockAddr sin4;
    sin4.setFamily(AF_INET);
    sin4.setPort(port);
    SockAddr sin6;
    sin6.setFamily(AF_INET6);
    sin6.setPort(port);
    run(sin4, sin6, config);
}

void
DhtRunner::run(const char* ip4, const char* ip6, const char* service, DhtRunner::Config config)
{
    auto res4 = getAddrInfo(ip4, service);
    auto res6 = getAddrInfo(ip6, service);
    run(res4.empty() ? SockAddr() : res4.front(),
        res6.empty() ? SockAddr() : res6.front(), config);
}

void
DhtRunner::run(const SockAddr& local4, const SockAddr& local6, DhtRunner::Config config)
{
    if (running)
        return;
    if (rcv_thread.joinable())
        rcv_thread.join();
    running = true;
    doRun(local4, local6, config.dht_config);
    if (not config.threaded)
        return;
    dht_thread = std::thread([this]() {
        while (running) {
            std::unique_lock<std::mutex> lk(dht_mtx);
            auto wakeup = loop_();
            cv.wait_until(lk, wakeup, [this]() {
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
            });
        }
    });
}

void
DhtRunner::shutdown(ShutdownCallback cb) {
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([=](SecureDht& dht) mutable {
        dht.shutdown(cb);
    });
    cv.notify_all();
}

void
DhtRunner::join()
{
    running = false;
    cv.notify_all();
    bootstrap_cv.notify_all();
    if (dht_thread.joinable())
        dht_thread.join();
    if (rcv_thread.joinable())
        rcv_thread.join();
    if (bootstrap_thread.joinable())
        bootstrap_thread.join();

    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops = decltype(pending_ops)();
        pending_ops_prio = decltype(pending_ops_prio)();
    }
    {
        std::lock_guard<std::mutex> lck(dht_mtx);
        dht_.reset();
        status4 = NodeStatus::Disconnected;
        status6 = NodeStatus::Disconnected;
        bound4 = {};
        bound6 = {};
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

time_point
DhtRunner::loop_()
{
    if (!dht_)
        return {};

    decltype(pending_ops) ops {};
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        auto s = getStatus();
        ops = (pending_ops_prio.empty() && (s == NodeStatus::Connected or (s == NodeStatus::Disconnected and not bootstraping))) ?
               std::move(pending_ops) : std::move(pending_ops_prio);
    }
    while (not ops.empty()) {
        ops.front()(*dht_);
        ops.pop();
    }

    time_point wakeup {};
    decltype(rcv) received {};
    {
        std::lock_guard<std::mutex> lck(sock_mtx);
        // move to stack
        received = std::move(rcv);
    }
    if (not received.empty()) {
        for (const auto& pck : received) {
            auto& buf = pck.first;
            auto& from = pck.second;
            wakeup = dht_->periodic(buf.data(), buf.size()-1, from);
        }
        received.clear();
    } else {
        wakeup = dht_->periodic(nullptr, 0, nullptr, 0);
    }

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

    return wakeup;
}


int bindSocket(const SockAddr& addr, SockAddr& bound)
{
    bool is_ipv6 = addr.getFamily() == AF_INET6;
    int sock = socket(is_ipv6 ? PF_INET6 : PF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        int set = 1;
#ifdef SO_NOSIGPIPE
        setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(set));
#endif
        if (is_ipv6)
            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&set, sizeof(set));
        int rc = bind(sock, addr.get(), addr.getLength());
        if(rc < 0)
            throw DhtException("Can't bind socket on " + addr.toString() + " " + strerror(rc));
        sockaddr_storage ss;
        socklen_t ss_len = sizeof(ss);
        getsockname(sock, (sockaddr*)&ss, &ss_len);
        bound = {ss, ss_len};
        return sock;
    } else {
        throw DhtException(std::string("Can't open socket: ") + strerror(sock));
    }
    return -1;
}

void
DhtRunner::doRun(const SockAddr& sin4, const SockAddr& sin6, SecureDht::Config config)
{
    dht_.reset();

    int s4 = -1,
        s6 = -1;

    bound4 = {};
    if (sin4)
        s4 = bindSocket(sin4, bound4);

#if 1
    bound6 = {};
    if (sin6)
        s6 = bindSocket(sin6, bound6);
#endif

    std::cerr << "s4: " << s4 << " bound on " << bound4.toString() << std::endl;
    std::cerr << "s6: " << s6 << " bound on " << bound6.toString() << std::endl;


    dht_ = std::unique_ptr<SecureDht>(new SecureDht {s4, s6, config});

    rcv_thread = std::thread([this,s4,s6]() {
        try {
            while (true) {
                struct timeval tv {/*.tv_sec = */0, /*.tv_usec = */250000};
                fd_set readfds;

                FD_ZERO(&readfds);
                if(s4 >= 0)
                    FD_SET(s4, &readfds);
                if(s6 >= 0)
                    FD_SET(s6, &readfds);

                int rc = select(s4 > s6 ? s4 + 1 : s6 + 1, &readfds, nullptr, nullptr, &tv);
                if(rc < 0) {
                    if(errno != EINTR) {
                        perror("select");
                        std::this_thread::sleep_for( std::chrono::seconds(1) );
                    }
                }

                if(!running)
                    break;

                if(rc > 0) {
                    std::array<uint8_t, 1024 * 64> buf;
                    sockaddr_storage from;
                    socklen_t from_len = sizeof(from);

                    if(s4 >= 0 && FD_ISSET(s4, &readfds))
                        rc = recvfrom(s4, (char*)buf.data(), buf.size(), 0, (sockaddr*)&from, &from_len);
                    else if(s6 >= 0 && FD_ISSET(s6, &readfds))
                        rc = recvfrom(s6, (char*)buf.data(), buf.size(), 0, (sockaddr*)&from, &from_len);
                    else
                        break;
                    if (rc > 0) {
                        {
                            std::lock_guard<std::mutex> lck(sock_mtx);
                            rcv.emplace_back(Blob {buf.begin(), buf.begin()+rc+1}, SockAddr(from, from_len));
                        }
                        cv.notify_all();
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
    });
}

void
DhtRunner::get(InfoHash hash, GetCallback vcb, DoneCallback dcb, Value::Filter f, Where w)
{
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) mutable {
            dht.get(hash, vcb, dcb, std::move(f), std::move(w));
        });
    }
    cv.notify_all();
}

void
DhtRunner::get(const std::string& key, GetCallback vcb, DoneCallbackSimple dcb, Value::Filter f, Where w)
{
    get(InfoHash::get(key), vcb, dcb, f, w);
}
void
DhtRunner::query(const InfoHash& hash, QueryCallback cb, DoneCallback done_cb, Query q) {
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops.emplace([=](SecureDht& dht) mutable {
            dht.query(hash, cb, done_cb, std::move(q));
        });
    }
    cv.notify_all();
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
    cv.notify_all();
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
    cv.notify_all();
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
    cv.notify_all();
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
}

std::vector<SockAddr>
DhtRunner::getAddrInfo(const std::string& host, const std::string& service)
{
    std::vector<SockAddr> ips {};
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
        ips.emplace_back(infop->ai_addr, infop->ai_addrlen);
        infop = infop->ai_next;
    }
    freeaddrinfo(info);
    return ips;
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
        pending_ops.emplace([=](SecureDht& dht) {
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

}
