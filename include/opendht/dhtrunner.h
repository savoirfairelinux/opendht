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
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <future>
#include <exception>
#include <queue>
#include <chrono>

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

    DhtRunner();
    virtual ~DhtRunner();

    void get(InfoHash hash, Dht::GetCallback vcb, Dht::DoneCallback dcb, Value::Filter f={});
    void get(InfoHash hash, Dht::GetCallback vcb, Dht::DoneCallbackSimple cb) {
        get(hash, vcb, Dht::bindDoneCb(cb));
    }
    void get(const std::string& key, Dht::GetCallback vcb, Dht::DoneCallback dcb=nullptr, Value::Filter f = Value::AllFilter());

    template <class T>
    void get(InfoHash hash, std::function<bool(std::vector<T>&&)> cb)
    {
        get(hash, [=](const std::vector<std::shared_ptr<Value>>& vals) {
            return cb(unpackVector<T>(vals));
        },
        T::getFilter());
    }
    template <class T>
    void get(InfoHash hash, std::function<bool(T&&)> cb)
    {
        get(hash, [=](const std::vector<std::shared_ptr<Value>>& vals) {
            for (const auto& v : vals) {
                T msg;
                try {
                    msg.unpackValue(*v);
                } catch (const std::exception&) {
                    continue;
                }
                if (not cb(std::move(msg)))
                    return false;
            }
            return true;
        },
        T::getFilter());
    }

    std::future<size_t> listen(InfoHash hash, Dht::GetCallback vcb, Value::Filter f = Value::AllFilter());
    std::future<size_t> listen(const std::string& key, Dht::GetCallback vcb, Value::Filter f = Value::AllFilter());

    template <class T>
    std::future<size_t> listen(InfoHash hash, std::function<bool(std::vector<T>&&)> cb)
    {
        return listen(hash, [=](const std::vector<std::shared_ptr<Value>>& vals) {
            return cb(unpackVector<T>(vals));
        },
        T::getFilter());
    }
    template <class T>
    std::future<size_t> listen(InfoHash hash, std::function<bool(T&&)> cb, Value::Filter f = Value::AllFilter())
    {
        return listen(hash, [=](const std::vector<std::shared_ptr<Value>>& vals) {
            for (const auto& v : vals) {
                T msg;
                try {
                    msg.unpackValue(*v);
                } catch (const std::exception&) {
                    continue;
                }
                if (not cb(std::move(msg)))
                    return false;
            }
            return true;
        },
        Value::Filter::chain({
            Value::TypeFilter(T::TYPE),
            T::getFilter(),
            f
        }));
    }

    void cancelListen(InfoHash h, size_t token);
    void cancelListen(InfoHash h, std::shared_future<size_t> token);

    void put(InfoHash hash, Value&& value, Dht::DoneCallback cb=nullptr);
    void put(InfoHash hash, const std::shared_ptr<Value>&, Dht::DoneCallback cb=nullptr);
    void put(InfoHash hash, Value&& value, Dht::DoneCallbackSimple cb) {
        put(hash, std::forward<Value>(value), Dht::bindDoneCb(cb));
    }
    void put(const std::string& key, Value&& value, Dht::DoneCallback cb=nullptr);

    void cancelPut(const InfoHash& h , const Value::Id& id);

    void putSigned(InfoHash hash, Value&& value, Dht::DoneCallback cb=nullptr);
    void putSigned(const std::string& key, Value&& value, Dht::DoneCallback cb=nullptr);
    void putSigned(InfoHash hash, Value&& value, Dht::DoneCallbackSimple cb) {
        putSigned(hash, std::forward<Value>(value), Dht::bindDoneCb(cb));
    }

    void putEncrypted(InfoHash hash, InfoHash to, Value&& value, Dht::DoneCallback cb=nullptr);
    void putEncrypted(InfoHash hash, InfoHash to, Value&& value, Dht::DoneCallbackSimple cb) {
        putEncrypted(hash, to, std::forward<Value>(value), Dht::bindDoneCb(cb));
    }
    void putEncrypted(const std::string& key, InfoHash to, Value&& value, Dht::DoneCallback cb=nullptr);

    void bootstrap(const char* host, const char* service);
    void bootstrap(const std::vector<std::pair<sockaddr_storage, socklen_t>>& nodes);
    void bootstrap(const std::vector<NodeExport>& nodes);

    void dumpTables() const
    {
        std::lock_guard<std::mutex> lck(dht_mtx);
        dht_->dumpTables();
    }

    InfoHash getId() const {
        if (!dht_)
            return {};
        return dht_->getId();
    }

    InfoHash getNodeId() const {
        if (!dht_)
            return {};
        return dht_->getNodeId();
    }

    /**
     * @deprecated
     */
    //[[deprecated]]
    InfoHash getRoutingId() const {
        return getNodeId();
    }

    std::vector<NodeExport> exportNodes() const {
        std::lock_guard<std::mutex> lck(dht_mtx);
        if (!dht_)
            return {};
        return dht_->exportNodes();
    }

    std::vector<Dht::ValuesExport> exportValues() const {
        std::lock_guard<std::mutex> lck(dht_mtx);
        if (!dht_)
            return {};
        return dht_->exportValues();
    }

    void setLoggers(LogMethod&& error = NOLOG, LogMethod&& warn = NOLOG, LogMethod&& debug = NOLOG) {
        std::lock_guard<std::mutex> lck(dht_mtx);
        dht_->setLoggers(std::forward<LogMethod>(error), std::forward<LogMethod>(warn), std::forward<LogMethod>(debug));
    }

    void registerType(const ValueType& type) {
        std::lock_guard<std::mutex> lck(dht_mtx);
        dht_->registerType(type);
    }

    void importValues(const std::vector<Dht::ValuesExport>& values) {
        std::lock_guard<std::mutex> lck(dht_mtx);
        dht_->importValues(values);
    }

    bool isRunning() const {
        return running;
    }

    int getNodesStats(sa_family_t af, unsigned *good_return, unsigned *dubious_return, unsigned *cached_return, unsigned *incoming_return) const
    {
        std::lock_guard<std::mutex> lck(dht_mtx);
        return dht_->getNodesStats(af, good_return, dubious_return, cached_return, incoming_return);
    }

    std::string getStorageLog() const
    {
        std::lock_guard<std::mutex> lck(dht_mtx);
        return dht_->getStorageLog();
    }
    std::string getRoutingTablesLog(sa_family_t af) const
    {
        std::lock_guard<std::mutex> lck(dht_mtx);
        return dht_->getRoutingTablesLog(af);
    }
    std::string getSearchesLog(sa_family_t af) const
    {
        std::lock_guard<std::mutex> lck(dht_mtx);
        return dht_->getSearchesLog(af);
    }

    // securedht methods

    void findCertificate(InfoHash hash, std::function<void(const std::shared_ptr<crypto::Certificate>)>);
    void registerCertificate(std::shared_ptr<crypto::Certificate> cert) {
        std::lock_guard<std::mutex> lck(dht_mtx);
        dht_->registerCertificate(cert);
    }
    void setLocalCertificateStore(SecureDht::CertificateStoreQuery&& query_method) {
        std::lock_guard<std::mutex> lck(dht_mtx);
        dht_->setLocalCertificateStore(std::move(query_method));
    }

    /**
     * If threaded is false, loop() must be called periodically.
     */
    void run(in_port_t port, const crypto::Identity identity, bool threaded = false, StatusCallback cb = nullptr);

    time_point loop() {
        std::lock_guard<std::mutex> lck(dht_mtx);
        return loop_();
    }

    void join();

private:

    void doRun(in_port_t port, const crypto::Identity identity);
    time_point loop_();

    std::unique_ptr<SecureDht> dht_ {};
    mutable std::mutex dht_mtx {};
    std::thread dht_thread {};
    std::condition_variable cv {};

    std::thread rcv_thread {};
    std::mutex sock_mtx {};
    std::vector<std::pair<Blob, sockaddr_storage>> rcv {};

    std::queue<std::function<void(SecureDht&)>> pending_ops {};
    std::mutex storage_mtx {};

    std::atomic<bool> running {false};

    Dht::Status status4 {Dht::Status::Disconnected},
                status6 {Dht::Status::Disconnected};
    StatusCallback statusCb {nullptr};
};

}
