/*
 *  Copyright (C) 2014 Savoir-Faire Linux Inc.
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
DhtRunner::run(in_port_t port, const crypto::Identity identity, bool threaded, StatusCallback cb)
{
    if (running)
        return;
    if (rcv_thread.joinable())
        rcv_thread.join();
    statusCb = cb;
    running = true;
    doRun(port, identity);
    if (not threaded)
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
                    if (not pending_ops.empty())
                        return true;
                }
                return false;
            });
        }
    });
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
        std::lock_guard<std::mutex> lck(dht_mtx);
        dht_.reset();
        status4 = Dht::Status::Disconnected;
        status6 = Dht::Status::Disconnected;
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
        ops = std::move(pending_ops);
    }
    while (not ops.empty()) {
        ops.front()(*dht_);
        ops.pop();
    }

    time_point wakeup {};
    {
        std::lock_guard<std::mutex> lck(sock_mtx);
        if (not rcv.empty()) {
            for (const auto& pck : rcv) {
                auto& buf = pck.first;
                auto& from = pck.second;
                wakeup = dht_->periodic(buf.data(), buf.size()-1, (sockaddr*)&from, from.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
            }
            rcv.clear();
        } else {
            wakeup = dht_->periodic(nullptr, 0, nullptr, 0);
        }
    }

    if (statusCb) {
        Dht::Status nstatus4 = dht_->getStatus(AF_INET);
        Dht::Status nstatus6 = dht_->getStatus(AF_INET6);
        if (nstatus4 != status4 || nstatus6 != status6) {
            status4 = nstatus4;
            status6 = nstatus6;
            statusCb(status4, status6);
        }
    }

    return wakeup;
}

void
DhtRunner::doRun(in_port_t port, const crypto::Identity identity)
{
    dht_.reset();

    int s = socket(PF_INET, SOCK_DGRAM, 0);
    int s6 = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s >= 0) {
        sockaddr_in sin {};
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        int rc = bind(s, (sockaddr*)&sin, sizeof(sin));
        if(rc < 0)
            throw DhtException("Can't bind IPv4 socket");
    }
    if(s6 >= 0) {
        int val = 1;
        int rc = setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&val, sizeof(val));
        if(rc < 0) {
            throw DhtException("setsockopt(IPV6_V6ONLY)");
        }

        /* BEP-32 mandates that we should bind this socket to one of our
           global IPv6 addresses. */
        sockaddr_in6 sin6 {};
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(port);
        rc = bind(s6, (sockaddr*)&sin6, sizeof(sin6));
        if(rc < 0)
            throw DhtException("Can't bind IPv6 socket");
    }

    dht_ = std::unique_ptr<SecureDht>(new SecureDht {s, s6, identity});

    rcv_thread = std::thread([this,s,s6]() {
        try {
            while (true) {
                uint8_t buf[4096 * 64];
                sockaddr_storage from;
                socklen_t fromlen;

                struct timeval tv {.tv_sec = 0, .tv_usec = 250000};
                fd_set readfds;

                FD_ZERO(&readfds);
                if(s >= 0)
                    FD_SET(s, &readfds);
                if(s6 >= 0)
                    FD_SET(s6, &readfds);

                int rc = select(s > s6 ? s + 1 : s6 + 1, &readfds, nullptr, nullptr, &tv);
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
                    if(s >= 0 && FD_ISSET(s, &readfds))
                        rc = recvfrom(s, (char*)buf, sizeof(buf) - 1, 0, (struct sockaddr*)&from, &fromlen);
                    else if(s6 >= 0 && FD_ISSET(s6, &readfds))
                        rc = recvfrom(s6, (char*)buf, sizeof(buf) - 1, 0, (struct sockaddr*)&from, &fromlen);
                    else
                        break;
                    if (rc > 0) {
                        buf[rc] = 0;
                        {
                            std::lock_guard<std::mutex> lck(sock_mtx);
                            rcv.emplace_back(Blob {buf, buf+rc+1}, from);
                        }
                        cv.notify_all();
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error int DHT networking thread: " << e.what() << std::endl;
        }
        if (s >= 0)
            close(s);
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
DhtRunner::get(const std::string& key, Dht::GetCallback vcb, Dht::DoneCallback dcb, Value::Filter f)
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
DhtRunner::put(const std::string& key, Value&& value, Dht::DoneCallback cb)
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
DhtRunner::putSigned(const std::string& key, Value&& value, Dht::DoneCallback cb)
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

void
DhtRunner::bootstrap(const char* host, const char* service)
{
    std::vector<std::pair<sockaddr_storage, socklen_t>> bootstrap_nodes {};

    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* info = nullptr;
    int rc = getaddrinfo(host, service, &hints, &info);
    if(rc != 0)
        throw std::invalid_argument(std::string("Error: `") + host + ":" + service + "`: " + gai_strerror(rc));

    addrinfo* infop = info;
    while (infop) {
        bootstrap_nodes.emplace_back(sockaddr_storage(), infop->ai_addrlen);
        std::copy_n((uint8_t*)infop->ai_addr, infop->ai_addrlen, (uint8_t*)&bootstrap_nodes.back().first);
        infop = infop->ai_next;
    }
    freeaddrinfo(info);
    bootstrap(bootstrap_nodes);
}

void
DhtRunner::bootstrap(const std::vector<std::pair<sockaddr_storage, socklen_t>>& nodes)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops.emplace([=](SecureDht& dht) {
        for (auto& node : nodes)
            dht.pingNode((sockaddr*)&node.first, node.second);
    });
    cv.notify_all();
}

void
DhtRunner::bootstrap(const std::vector<NodeExport>& nodes)
{
    std::lock_guard<std::mutex> lck(storage_mtx);
    pending_ops.emplace([=](SecureDht& dht) {
        for (auto& node : nodes)
            dht.insertNode(node);
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
