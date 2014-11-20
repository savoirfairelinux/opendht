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

namespace dht {

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
    if (!threaded)
        return;
    dht_thread = std::thread([this]() {
        while (running) {
            std::unique_lock<std::mutex> lk(dht_mtx);
            loop_();
            cv.wait_for(lk, std::chrono::seconds( tosleep ), [this]() {
                if (!running) return true;
                {
                    std::unique_lock<std::mutex> lck(sock_mtx);
                    if (!rcv.empty()) return true;
                }
                {
                    std::unique_lock<std::mutex> lck(storage_mtx);
                    if (!dht_gets.empty() || !dht_puts.empty() || !bootstrap_nodes.empty())
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
        std::unique_lock<std::mutex> lck(dht_mtx);
        dht.reset();
        status4 = Dht::Status::Disconnected;
        status6 = Dht::Status::Disconnected;
    }
}

void
DhtRunner::loop_()
{
    if (!dht) return;
    time_t tosl;
    {
        std::unique_lock<std::mutex> lck(sock_mtx);
        if (!dht) return;
        if (rcv.size()) {
            for (const auto& pck : rcv) {
                auto& buf = pck.first;
                auto& from = pck.second;
                dht->periodic(buf.data(), buf.size()-1, (sockaddr*)&from, from.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6), &tosl);
            }
            rcv.clear();
        } else {
            dht->periodic(nullptr, 0, nullptr, 0, &tosl);
        }
    }
    tosleep = tosl;
    {
        std::unique_lock<std::mutex> lck(storage_mtx);

        for (auto& get : dht_gets) {
            std::cout << "Processing get (" <<  std::get<0>(get) << ")" << std::endl;
            dht->get(std::get<0>(get), std::get<1>(get), std::get<2>(get), std::move(std::get<3>(get)));
        }
        dht_gets.clear();

        for (auto& put : dht_eputs) {
            auto& id = std::get<0>(put);
            auto& val = std::get<2>(put);
            std::cout << "Processing encrypted put at " << id << " for " << std::get<1>(put) << " -> " << val << std::endl;
            dht->putEncrypted(id, std::get<1>(put), std::move(val), std::get<3>(put));
        }
        dht_eputs.clear();

        for (auto& put : dht_puts) {
            auto& id = std::get<0>(put);
            auto& val = std::get<1>(put);
            std::cout << "Processing put " << id << " -> " << val << std::endl;
            dht->put(id, std::move(val), std::get<2>(put));
        }
        dht_puts.clear();

        for (auto& put : dht_sputs) {
            auto& id = std::get<0>(put);
            auto& val = std::get<1>(put);
            std::cout << "Processing signed put " << id << " -> " << val << std::endl;
            dht->putSigned(id, std::move(val), std::get<2>(put));
        }
        dht_sputs.clear();

        for (auto& node : bootstrap_nodes)
            dht->insertNode(node);
        bootstrap_nodes.clear();

        for (auto& node : bootstrap_ips) {
            dht->pingNode((sockaddr*)&node, sizeof(node));
            //std::this_thread::sleep_for( std::chrono::microseconds(/*rand_delay()*/ 10) );
        }
        bootstrap_ips.clear();
    }

    if (statusCb) {
        Dht::Status nstatus4 = dht->getStatus(AF_INET);
        Dht::Status nstatus6 = dht->getStatus(AF_INET6);
        if (nstatus4 != status4 || nstatus6 != status6) {
            status4 = nstatus4;
            status6 = nstatus6;
            statusCb(status4, status6);
        }
    }
}

void
DhtRunner::doRun(in_port_t port, const crypto::Identity identity)
{
    dht.reset();

    int s = socket(PF_INET, SOCK_DGRAM, 0);
    int s6 = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s >= 0) {
        sockaddr_in sin {
            .sin_family = AF_INET,
            .sin_port = htons(port)
        };
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
           global IPv6 addresses.  In this simple example, this only
           happens if the user used the -b flag. */
        sockaddr_in6 sin6 {
            .sin6_family = AF_INET6,
            .sin6_port = htons(port)
        };
        rc = bind(s6, (sockaddr*)&sin6, sizeof(sin6));
        if(rc < 0)
            throw DhtException("Can't bind IPv6 socket");
    }

    dht = std::unique_ptr<SecureDht>(new SecureDht {s, s6, identity});

    rcv_thread = std::thread([this,s,s6]() {
        std::mt19937 engine(std::random_device{}());
        auto rand_delay = std::bind(std::uniform_int_distribution<uint32_t>(0, 1000000), engine);
        try {
            while (true) {
                uint8_t buf[4096 * 64];
                sockaddr_storage from;
                socklen_t fromlen;

                struct timeval tv;
                fd_set readfds;
                tv.tv_sec = tosleep / 5;
                tv.tv_usec = rand_delay();
                //std::cout << "Dht::rcv_thread loop " << tv.tv_sec << "." << tv.tv_usec << std::endl;

                FD_ZERO(&readfds);
                if(s >= 0)
                    FD_SET(s, &readfds);
                if(s6 >= 0)
                    FD_SET(s6, &readfds);
                int rc = select(s > s6 ? s + 1 : s6 + 1, &readfds, NULL, NULL, &tv);
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
                        rc = recvfrom(s, buf, sizeof(buf) - 1, 0, (struct sockaddr*)&from, &fromlen);
                    else if(s6 >= 0 && FD_ISSET(s6, &readfds))
                        rc = recvfrom(s6, buf, sizeof(buf) - 1, 0, (struct sockaddr*)&from, &fromlen);
                    else
                        break;
                    if (rc > 0) {
                        buf[rc] = 0;
                        {
                            std::unique_lock<std::mutex> lck(sock_mtx);
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
    std::unique_lock<std::mutex> lck(storage_mtx);
    dht_gets.emplace_back(hash, vcb, dcb, f);
    cv.notify_all();
}

void
DhtRunner::get(const std::string& key, Dht::GetCallback vcb, Dht::DoneCallback dcb, Value::Filter f)
{
    get(InfoHash::get(key), vcb, dcb, f);
}

void
DhtRunner::put(InfoHash hash, Value&& value, Dht::DoneCallback cb)
{
    std::unique_lock<std::mutex> lck(storage_mtx);
    dht_puts.emplace_back(hash, std::move(value), cb);
    cv.notify_all();
}

void
DhtRunner::put(const std::string& key, Value&& value, Dht::DoneCallback cb)
{
    put(InfoHash::get(key), std::forward<Value>(value), cb);
}

void
DhtRunner::putSigned(InfoHash hash, Value&& value, Dht::DoneCallback cb)
{
    std::unique_lock<std::mutex> lck(storage_mtx);
    dht_sputs.emplace_back(hash, std::move(value), cb);
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
    std::unique_lock<std::mutex> lck(storage_mtx);
    dht_eputs.emplace_back(hash, to, std::move(value), cb);
    cv.notify_all();
}

void
DhtRunner::putEncrypted(const std::string& key, InfoHash to, Value&& value, Dht::DoneCallback cb)
{
    putEncrypted(key, to, std::forward<Value>(value), cb);
}

void
DhtRunner::bootstrap(const std::vector<sockaddr_storage>& nodes)
{
    std::unique_lock<std::mutex> lck(storage_mtx);
    bootstrap_ips.insert(bootstrap_ips.end(), nodes.begin(), nodes.end());
    cv.notify_all();
}

void
DhtRunner::bootstrap(const std::vector<Dht::NodeExport>& nodes)
{
    std::unique_lock<std::mutex> lck(storage_mtx);
    bootstrap_nodes.insert(bootstrap_nodes.end(), nodes.begin(), nodes.end());
    cv.notify_all();
}


}
