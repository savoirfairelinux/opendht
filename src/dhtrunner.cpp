/*
 *  Copyright (C) 2014-2015 Savoir-Faire Linux Inc.
 *  Author : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 *  Additional permission under GNU GPL version 3 section 7:
 *
 *  If you modify this program, or any covered work, by linking or
 *  combining it with the OpenSSL project's OpenSSL library (or a
 *  modified version of that library), containing parts covered by the
 *  terms of the OpenSSL or SSLeay licenses, Savoir-Faire Linux Inc.
 *  grants you additional permission to convey the resulting work.
 *  Corresponding Source for a non-source form of such a combination
 *  shall include the source code for the parts of OpenSSL used as well
 *  as that of the covered work.
 */

#include "dhtrunner.h"

#include <unistd.h> // close(fd)

#ifndef _WIN32
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#define close(x) closesocket(x)
#endif

namespace dht {

DhtRunner::DhtRunner()
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
    sockaddr_in sin4;
    std::fill_n((uint8_t*)&sin4, sizeof(sin4), 0);
    sin4.sin_family = AF_INET;
    sin4.sin_port = htons(port);
    sockaddr_in6 sin6;
    std::fill_n((uint8_t*)&sin6, sizeof(sin6), 0);
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    run(&sin4, &sin6, config);
}

void
DhtRunner::run(const char* ip4, const char* ip6, const char* service, DhtRunner::Config config)
{
    auto res4 = getAddrInfo(ip4, service);
    auto res6 = getAddrInfo(ip6, service);
    run(res4.empty() ? nullptr : (sockaddr_in*) &res4.front().first,
        res6.empty() ? nullptr : (sockaddr_in6*)&res6.front().first, config);
}

void
DhtRunner::run(const sockaddr_in* local4, const sockaddr_in6* local6, DhtRunner::Config config)
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
                    if (not pending_ops.empty() and getStatus() >= Dht::Status::Connecting)
                        return true;
                }
                return false;
            });
        }
    });
}

void
DhtRunner::shutdown(Dht::ShutdownCallback cb) {
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops.emplace([=](SecureDht& dht) mutable {
        dht.shutdown(cb);
    });
    cv.notify_all();
}

void
DhtRunner::join()
{
    running = false;
    cv.notify_all();
    if (dht_thread.joinable())
        dht_thread.join();
    if (rcv_thread.joinable())
        rcv_thread.join();
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        pending_ops = decltype(pending_ops)();
        pending_ops_prio = decltype(pending_ops_prio)();
    }
    {
        std::lock_guard<std::mutex> lck(dht_mtx);
        dht_.reset();
        status4 = Dht::Status::Disconnected;
        status6 = Dht::Status::Disconnected;
        bound4 = {};
        bound6 = {};
    }
}

time_point
DhtRunner::loop_()
{
    if (!dht_)
        return {};

    decltype(pending_ops) ops {};
    {
        std::lock_guard<std::mutex> lck(storage_mtx);
        ops = std::move(pending_ops_prio);
    }
    while (not ops.empty()) {
        ops.front()(*dht_);
        ops.pop();
    }
    if (getStatus() >= Dht::Status::Connecting) {
        {
            std::lock_guard<std::mutex> lck(storage_mtx);
            ops = std::move(pending_ops);
        }
        while (not ops.empty()) {
            ops.front()(*dht_);
            ops.pop();
        }
    }

    time_point wakeup {};
    {
        std::lock_guard<std::mutex> lck(sock_mtx);
        if (not rcv.empty()) {
            for (const auto& pck : rcv) {
                auto& buf = pck.first;
                auto& from = pck.second;
                wakeup = dht_->periodic(buf.data(), buf.size()-1, (sockaddr*)&from.first, from.second);
            }
            rcv.clear();
        } else {
            wakeup = dht_->periodic(nullptr, 0, nullptr, 0);
        }
    }

    Dht::Status nstatus4 = dht_->getStatus(AF_INET);
    Dht::Status nstatus6 = dht_->getStatus(AF_INET6);
    if (nstatus4 != status4 || nstatus6 != status6) {
        status4 = nstatus4;
        status6 = nstatus6;
        if (statusCb)
            statusCb(status4, status6);
    }

    return wakeup;
}

void
DhtRunner::doRun(const sockaddr_in* sin4, const sockaddr_in6* sin6, SecureDht::Config config)
{
    dht_.reset();

    int s4 = -1,
        s6 = -1;

    bound4 = {};
    if (sin4) {
        s4 = socket(PF_INET, SOCK_DGRAM, 0);
        if(s4 >= 0) {
            int rc = bind(s4, (sockaddr*)sin4, sizeof(sockaddr_in));
            if(rc < 0)
                throw DhtException("Can't bind IPv4 socket on " + dht::print_addr((sockaddr*)sin4, sizeof(sockaddr_in)));
            bound4.second = sizeof(bound4.first);
            getsockname(s4, (sockaddr*)&bound4.first, &bound4.second);
        }
    }

#if 1
    bound6 = {};
    if (sin6) {
        s6 = socket(PF_INET6, SOCK_DGRAM, 0);
        if(s6 >= 0) {
            int val = 1;
            int rc = setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&val, sizeof(val));
            if(rc < 0)
                throw DhtException("Can't set IPV6_V6ONLY");

            rc = bind(s6, (sockaddr*)sin6, sizeof(sockaddr_in6));
            if(rc < 0)
                throw DhtException("Can't bind IPv6 socket on " + dht::print_addr((sockaddr*)sin6, sizeof(sockaddr_in6)));
            bound6.second = sizeof(bound6.first);
            getsockname(s6, (sockaddr*)&bound6.first, &bound6.second);
        }
    }
#endif

    dht_ = std::unique_ptr<SecureDht>(new SecureDht {s4, s6, config});

    rcv_thread = std::thread([this,s4,s6]() {
        try {
            while (true) {
                uint8_t buf[4096 * 64];
                sockaddr_storage from;
                socklen_t fromlen;

                struct timeval tv {.tv_sec = 0, .tv_usec = 250000};
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
                    fromlen = sizeof(from);
                    if(s4 >= 0 && FD_ISSET(s4, &readfds))
                        rc = recvfrom(s4, (char*)buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
                    else if(s6 >= 0 && FD_ISSET(s6, &readfds))
                        rc = recvfrom(s6, (char*)buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
                    else
                        break;
                    if (rc > 0) {
                        {
                            std::lock_guard<std::mutex> lck(sock_mtx);
                            rcv.emplace_back(Blob {buf, buf+rc+1}, std::make_pair(from, fromlen));
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
DhtRunner::get(InfoHash hash, Dht::GetCallback vcb, Dht::DoneCallback dcb, Value::Filter f)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops.emplace([=](SecureDht& dht) mutable {
        dht.get(hash, vcb, dcb, std::move(f));
    });
    cv.notify_all();
}

void
DhtRunner::get(const std::string& key, Dht::GetCallback vcb, Dht::DoneCallbackSimple dcb, Value::Filter f)
{
    get(InfoHash::get(key), vcb, dcb, f);
}

std::future<size_t>
DhtRunner::listen(InfoHash hash, Dht::GetCallback vcb, Value::Filter f)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    auto ret_token = std::make_shared<std::promise<size_t>>();
    pending_ops.emplace([=](SecureDht& dht) mutable {
        ret_token->set_value(dht.listen(hash, vcb, std::move(f)));
    });
    cv.notify_all();
    return ret_token->get_future();
}

std::future<size_t>
DhtRunner::listen(const std::string& key, Dht::GetCallback vcb, Value::Filter f)
{
    return listen(InfoHash::get(key), vcb, f);
}

void
DhtRunner::cancelListen(InfoHash h, size_t token)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops.emplace([=](SecureDht& dht) {
        dht.cancelListen(h, token);
    });
    cv.notify_all();
}

void
DhtRunner::cancelListen(InfoHash h, std::shared_future<size_t> token)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops.emplace([=](SecureDht& dht) {
        auto tk = token.get();
        dht.cancelListen(h, tk);
    });
    cv.notify_all();
}

void
DhtRunner::put(InfoHash hash, Value&& value, Dht::DoneCallback cb)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    auto sv = std::make_shared<Value>(std::move(value));
    pending_ops.emplace([=](SecureDht& dht) {
        dht.put(hash, sv, cb);
    });
    cv.notify_all();
}

void
DhtRunner::put(InfoHash hash, const std::shared_ptr<Value>& value, Dht::DoneCallback cb)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops.emplace([=](SecureDht& dht) {
        dht.put(hash, value, cb);
    });
    cv.notify_all();
}

void
DhtRunner::put(const std::string& key, Value&& value, Dht::DoneCallbackSimple cb)
{
    put(InfoHash::get(key), std::forward<Value>(value), cb);
}

void
DhtRunner::cancelPut(const InfoHash& h , const Value::Id& id)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops.emplace([=](SecureDht& dht) {
        dht.cancelPut(h, id);
    });
    cv.notify_all();
}

void
DhtRunner::putSigned(InfoHash hash, Value&& value, Dht::DoneCallback cb)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    auto sv = std::make_shared<Value>(std::move(value));
    pending_ops.emplace([=](SecureDht& dht) {
        dht.putSigned(hash, sv, cb);
    });
    cv.notify_all();
}

void
DhtRunner::putSigned(const std::string& key, Value&& value, Dht::DoneCallbackSimple cb)
{
    putSigned(InfoHash::get(key), std::forward<Value>(value), cb);
}

void
DhtRunner::putEncrypted(InfoHash hash, InfoHash to, Value&& value, Dht::DoneCallback cb)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    auto sv = std::make_shared<Value>(std::move(value));
    pending_ops.emplace([=](SecureDht& dht) {
        dht.putEncrypted(hash, to, sv, cb);
    });
    cv.notify_all();
}

void
DhtRunner::putEncrypted(const std::string& key, InfoHash to, Value&& value, Dht::DoneCallback cb)
{
    putEncrypted(InfoHash::get(key), to, std::forward<Value>(value), cb);
}

std::vector<std::pair<sockaddr_storage, socklen_t>>
DhtRunner::getAddrInfo(const char* host, const char* service)
{
    std::vector<std::pair<sockaddr_storage, socklen_t>> ips {};
    if (not host or not service or strlen(host) == 0)
        return ips;

    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* info = nullptr;
    int rc = getaddrinfo(host, service, &hints, &info);
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
DhtRunner::bootstrap(const char* host, const char* service)
{
    bootstrap(getAddrInfo(host, service));
}

void
DhtRunner::bootstrap(const std::vector<std::pair<sockaddr_storage, socklen_t>>& nodes)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops_prio.emplace([=](SecureDht& dht) {
        for (auto& node : nodes)
            dht.pingNode((sockaddr*)&node.first, node.second);
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(const std::vector<NodeExport>& nodes)
{
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
    pending_ops.emplace([=](SecureDht& dht) {
        dht.connectivityChanged();
    });
    cv.notify_all();
}

void
DhtRunner::findCertificate(InfoHash hash, std::function<void(const std::shared_ptr<crypto::Certificate>)> cb) {
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops.emplace([=](SecureDht& dht) {
        dht.findCertificate(hash, cb);
    });
    cv.notify_all();
}

}
