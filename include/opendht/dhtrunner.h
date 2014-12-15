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

#pragma once

#include "securedht.h"

#include <thread>
#include <random>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <future>
#include <exception>
#include <queue>

#include <unistd.h> // close(fd)

namespace dht {

/**
 * Provides a thread-safe interface to run the (secure) DHT.
 * The class will open sockets on the provided port and will
 * either wait for (expectedly frequent) calls to loop() or start an internal
 * thread that will update the DHT when appropriate.
 */
class DhtRunner {

public:
    typedef std::function<void(Dht::Status, Dht::Status)> StatusCallback;

    DhtRunner() {}
    virtual ~DhtRunner() {
        join();
    }

    void get(InfoHash hash, Dht::GetCallback vcb, Dht::DoneCallback dcb=nullptr, Value::Filter f = Value::AllFilter());
    void get(const std::string& key, Dht::GetCallback vcb, Dht::DoneCallback dcb=nullptr, Value::Filter f = Value::AllFilter());

    std::future<size_t> listen(InfoHash hash, Dht::GetCallback vcb, Value::Filter f = Value::AllFilter());
    std::future<size_t> listen(const std::string& key, Dht::GetCallback vcb, Value::Filter f = Value::AllFilter());
    void cancelListen(InfoHash h, size_t token);
    void cancelListen(InfoHash h, std::shared_future<size_t> token);

    void put(InfoHash hash, Value&& value, Dht::DoneCallback cb=nullptr);
    void put(const std::string& key, Value&& value, Dht::DoneCallback cb=nullptr);
    void cancelPut(const InfoHash& h , const Value::Id& id);

    void putSigned(InfoHash hash, Value&& value, Dht::DoneCallback cb=nullptr);
    void putSigned(const std::string& key, Value&& value, Dht::DoneCallback cb=nullptr);

    void putEncrypted(InfoHash hash, InfoHash to, Value&& value, Dht::DoneCallback cb=nullptr);
    void putEncrypted(const std::string& key, InfoHash to, Value&& value, Dht::DoneCallback cb=nullptr);

    void bootstrap(const std::vector<sockaddr_storage>& nodes);
    void bootstrap(const std::vector<Dht::NodeExport>& nodes);

    void dumpTables() const
    {
        std::unique_lock<std::mutex> lck(dht_mtx);
        dht->dumpTables();
    }

    InfoHash getId() const {
        if (!dht)
            return {};
        return dht->getId();
    }

    InfoHash getRoutingId() const {
        if (!dht)
            return {};
        return dht->getRoutingId();
    }

    std::vector<Dht::NodeExport> exportNodes() const {
        std::unique_lock<std::mutex> lck(dht_mtx);
        if (!dht)
            return {};
        return dht->exportNodes();
    }

    std::vector<Dht::ValuesExport> exportValues() const {
        std::unique_lock<std::mutex> lck(dht_mtx);
        if (!dht)
            return {};
        return dht->exportValues();
    }

    void setLoggers(LogMethod&& error = NOLOG, LogMethod&& warn = NOLOG, LogMethod&& debug = NOLOG) {
        std::unique_lock<std::mutex> lck(dht_mtx);
        dht->setLoggers(std::forward<LogMethod>(error), std::forward<LogMethod>(warn), std::forward<LogMethod>(debug));
    }

    void registerType(const ValueType& type) {
        std::unique_lock<std::mutex> lck(dht_mtx);
        dht->registerType(type);
    }

    void importValues(const std::vector<Dht::ValuesExport>& values) {
        std::unique_lock<std::mutex> lck(dht_mtx);
        dht->importValues(values);
    }

    bool isRunning() const {
        return running;
    }

    int getNodesStats(sa_family_t af, unsigned *good_return, unsigned *dubious_return, unsigned *cached_return, unsigned *incoming_return) const
    {
        std::unique_lock<std::mutex> lck(dht_mtx);
        return dht->getNodesStats(af, good_return, dubious_return, cached_return, incoming_return);
    }

    std::string getStorageLog() const
    {
        std::unique_lock<std::mutex> lck(dht_mtx);
        return dht->getStorageLog();
    }
    std::string getRoutingTablesLog(sa_family_t af) const
    {
        std::unique_lock<std::mutex> lck(dht_mtx);
        return dht->getRoutingTablesLog(af);
    }
    std::string getSearchesLog(sa_family_t af) const
    {
        std::unique_lock<std::mutex> lck(dht_mtx);
        return dht->getSearchesLog(af);
    }

    /**
     * If threaded is false, loop() must be called periodically.
     */
    void run(in_port_t port, const crypto::Identity identity, bool threaded = false, StatusCallback cb = nullptr);

    void loop() {
        std::unique_lock<std::mutex> lck(dht_mtx);
        loop_();
    }

    void join();

private:

    void doRun(in_port_t port, const crypto::Identity identity);
    void loop_();

    std::unique_ptr<SecureDht> dht {};
    mutable std::mutex dht_mtx {};
    std::thread dht_thread {};
    std::condition_variable cv {};

    std::thread rcv_thread {};
    std::mutex sock_mtx {};
    std::vector<std::pair<Blob, sockaddr_storage>> rcv {};
    std::atomic<time_t> tosleep {0};

    std::queue<std::function<void(SecureDht&)>> pending_ops {};
    std::mutex storage_mtx {};

    std::atomic<bool> running {false};

    Dht::Status status4 {Dht::Status::Disconnected},
                status6 {Dht::Status::Disconnected};
    StatusCallback statusCb {nullptr};
};

}
