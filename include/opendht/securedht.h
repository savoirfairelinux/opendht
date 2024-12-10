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

#pragma once

#include "dht.h"
#include "crypto.h"

#include <map>
#include <vector>
#include <memory>
#include <random>

namespace dht {

class OPENDHT_PUBLIC SecureDht final : public DhtInterface {
public:

    typedef std::function<void(bool)> SignatureCheckCallback;

    using Config = SecureDhtConfig;

    static dht::Config getConfig(const SecureDht::Config& conf)
    {
        auto c = conf.node_config;
        if (not c.node_id and conf.id.second)
            c.node_id = InfoHash::get("node:"+conf.id.second->getId().toString());
        return c;
    }

    SecureDht() {}

    /**
     * s, s6: bound socket descriptors for IPv4 and IPv6, respectively.
     *        For the Dht to be initialised, at least one of them must be >= 0.
     * id:    the identity to use for the crypto layer and to compute
     *        our own hash on the Dht.
     */
    SecureDht(std::unique_ptr<DhtInterface> dht, Config config);

    virtual ~SecureDht();

    InfoHash getId() const {
        return key_ ? key_->getPublicKey().getId() : InfoHash();
    }
    PkId getLongId() const {
        return key_ ? key_->getPublicKey().getLongId() : PkId();
    }

    ValueType secureType(ValueType&& type);

    ValueType secureType(const ValueType& type) {
        ValueType tmp_type = type;
        return secureType(std::move(tmp_type));
    }

    void registerType(const ValueType& type) override {
        if (dht_)
            dht_->registerType(secureType(type));
    }
    void registerType(ValueType&& type) {
        if (dht_)
            dht_->registerType(secureType(std::forward<ValueType>(type)));
    }
    void registerInsecureType(const ValueType& type) {
        if (dht_)
            dht_->registerType(type);
    }

    /**
     * "Secure" get(), that will check the signature of signed data, and decrypt encrypted data.
     * If the signature can't be checked, or if the data can't be decrypted, it is not returned.
     * Public, non-signed & non-encrypted data is retransmitted as-is.
     */
    void get(const InfoHash& id, GetCallback cb, DoneCallback donecb={}, Value::Filter&& = {}, Where&& w = {}) override;
    void get(const InfoHash& id, GetCallback cb, DoneCallbackSimple donecb={}, Value::Filter&& f = {}, Where&& w = {}) override {
        get(id, cb, bindDoneCb(donecb), std::forward<Value::Filter>(f), std::forward<Where>(w));
    }
    void get(const InfoHash& key, GetCallbackSimple cb, DoneCallback donecb={}, Value::Filter&& f={}, Where&& w = {}) override {
        get(key, bindGetCb(cb), donecb, std::forward<Value::Filter>(f), std::forward<Where>(w));
    }
    void get(const InfoHash& key, GetCallbackSimple cb, DoneCallbackSimple donecb, Value::Filter&& f={}, Where&& w = {}) override {
        get(key, bindGetCb(cb), bindDoneCb(donecb), std::forward<Value::Filter>(f), std::forward<Where>(w));
    }

    /**
     * Will take ownership of the value, sign it using our private key and put it in the DHT.
     */
    void putSigned(const InfoHash& hash, Sp<Value> val, DoneCallback callback, bool permanent = false);
    void putSigned(const InfoHash& hash, Value&& v, DoneCallback callback, bool permanent = false) {
        putSigned(hash, std::make_shared<Value>(std::move(v)), callback, permanent);
    }

    /**
     * Will sign the data using our private key, encrypt it using the recipient' public key,
     * and put it in the DHT.
     * The operation will be immediate if the recipient' public key is known (otherwise it will be retrived first).
     */
    void putEncrypted(const InfoHash& hash, const InfoHash& to, Sp<Value> val, DoneCallback callback, bool permanent = false);
    void putEncrypted(const InfoHash& hash, const InfoHash& to, Value&& v, DoneCallback callback, bool permanent = false) {
        putEncrypted(hash, to, std::make_shared<Value>(std::move(v)), callback, permanent);
    }

    /**
     * Take ownership of the value and sign it using our private key.
     */
    void sign(Value& v) const;

    Value encrypt(Value& v, const crypto::PublicKey& to) const;

    Value decrypt(const Value& v);

    void findCertificate(const InfoHash& node, const std::function<void(const Sp<crypto::Certificate>)>& cb);
    void findPublicKey(const InfoHash& node, const std::function<void(const Sp<const crypto::PublicKey>)>& cb);

    const Sp<crypto::Certificate> registerCertificate(const InfoHash& node, const Blob& cert);
    void registerCertificate(Sp<crypto::Certificate>& cert);

    const Sp<crypto::Certificate> getCertificate(const InfoHash& node) const;
    const Sp<const crypto::PublicKey> getPublicKey(const InfoHash& node) const;

    /**
     * Allows to set a custom callback called by the library to find a locally-stored certificate.
     * The search key used is the public key ID, so there may be multiple certificates retured, signed with
     * the same private key.
     */
    void setLocalCertificateStore(CertificateStoreQuery&& query_method) {
        localQueryMethod_ = std::move(query_method);
    }

    /**
     * SecureDht to Dht proxy
     */
    void shutdown(ShutdownCallback cb) override {
        dht_->shutdown(cb);
    }
    void dumpTables() const override {
        dht_->dumpTables();
    }
    inline const InfoHash& getNodeId() const override { return dht_->getNodeId(); }

    std::pair<size_t, size_t> getStoreSize() const override {
        return dht_->getStoreSize();
    }
    std::string getStorageLog() const override {
        return dht_->getStorageLog();
    }
    std::string getStorageLog(const InfoHash& h) const override {
        return dht_->getStorageLog(h);
    }
    void setStorageLimit(size_t limit = DEFAULT_STORAGE_LIMIT) override {
        dht_->setStorageLimit(limit);
    }
    std::vector<NodeExport> exportNodes() const override {
        return dht_->exportNodes();
    }
    std::vector<ValuesExport> exportValues() const override {
        return dht_->exportValues();
    }
    void importValues(const std::vector<ValuesExport>& v) override {
        dht_->importValues(v);
    }
    NodeStats getNodesStats(sa_family_t af) const override {
        return dht_->getNodesStats(af);
    }
    std::vector<unsigned> getNodeMessageStats(bool in = false) override {
        return dht_->getNodeMessageStats(in);
    }
    std::string getRoutingTablesLog(sa_family_t af) const override {
        return dht_->getRoutingTablesLog(af);
    }
    std::string getSearchesLog(sa_family_t af) const override {
        return dht_->getSearchesLog(af);
    }
    std::string getSearchLog(const InfoHash& h, sa_family_t af = AF_UNSPEC) const override {
        return dht_->getSearchLog(h, af);
    }
    std::vector<SockAddr> getPublicAddress(sa_family_t family = 0) override {
        return dht_->getPublicAddress(family);
    }
    time_point periodic(const uint8_t *buf, size_t buflen, SockAddr sa, const time_point& now) override {
        return dht_->periodic(buf, buflen, std::move(sa), now);
    }
    time_point periodic(const uint8_t *buf, size_t buflen, const sockaddr* from, socklen_t fromlen, const time_point& now) override {
        return dht_->periodic(buf, buflen, from, fromlen, now);
    }
    NodeStatus updateStatus(sa_family_t af) override  {
        return dht_->updateStatus(af);
    }
    NodeStatus getStatus(sa_family_t af) const override {
        return dht_->getStatus(af);
    }
    NodeStatus getStatus() const override {
        return dht_->getStatus();
    }
    net::DatagramSocket* getSocket() const override {
        return dht_->getSocket();
    };
    bool isRunning(sa_family_t af = 0) const override {
        return dht_->isRunning(af);
    }
    const ValueType& getType(ValueType::Id type_id) const override {
        return dht_->getType(type_id);
    }
    void addBootstrap(const std::string& host, const std::string& service) override {
        dht_->addBootstrap(host, service);
    }
    void clearBootstrap() override {
        dht_->clearBootstrap();
    }
    void insertNode(const InfoHash& id, const SockAddr& sa) override {
        dht_->insertNode(id, sa);
    }
    void insertNode(const NodeExport& n) override {
        dht_->insertNode(n);
    }
    void pingNode(SockAddr sa, DoneCallbackSimple&& cb={}) override {
        dht_->pingNode(std::move(sa), std::move(cb));
    }
    void query(const InfoHash& key, QueryCallback cb, DoneCallback done_cb = {}, Query&& q = {}) override {
        dht_->query(key, cb, done_cb, std::move(q));
    }
    void query(const InfoHash& key, QueryCallback cb, DoneCallbackSimple done_cb = {}, Query&& q = {}) override {
        dht_->query(key, cb, done_cb, std::move(q));
    }
    std::vector<Sp<Value>> getLocal(const InfoHash& key, const Value::Filter& f = {}) const override {
        return dht_->getLocal(key, f);
    }
    Sp<Value> getLocalById(const InfoHash& key, Value::Id vid) const override {
        return dht_->getLocalById(key, vid);
    }
    void put(const InfoHash& key,
            Sp<Value> v,
            DoneCallback cb=nullptr,
            time_point created=time_point::max(),
            bool permanent = false) override
    {
        dht_->put(key, v, cb, created, permanent);
    }
    void put(const InfoHash& key,
            const Sp<Value>& v,
            DoneCallbackSimple cb,
            time_point created=time_point::max(),
            bool permanent = false) override
    {
        dht_->put(key, v, cb, created, permanent);
    }

    void put(const InfoHash& key,
            Value&& v,
            DoneCallback cb=nullptr,
            time_point created=time_point::max(),
            bool permanent = false) override
    {
        dht_->put(key, std::move(v), cb, created, permanent);
    }
    void put(const InfoHash& key,
            Value&& v,
            DoneCallbackSimple cb,
            time_point created=time_point::max(),
            bool permanent = false) override
    {
        dht_->put(key, std::move(v), cb, created, permanent);
    }
    std::vector<Sp<Value>> getPut(const InfoHash& h) const override {
        return dht_->getPut(h);
    }
    Sp<Value> getPut(const InfoHash& h, const Value::Id& vid) const override {
        return dht_->getPut(h, vid);
    }
    bool cancelPut(const InfoHash& h, const Value::Id& vid) override {
        return dht_->cancelPut(h, vid);
    }

    size_t listen(const InfoHash& key, ValueCallback, Value::Filter={}, Where={}) override;
    size_t listen(const InfoHash& key, GetCallback cb, Value::Filter = {}, Where w = {}) override;
    size_t listen(const InfoHash& key, GetCallbackSimple cb, Value::Filter f={}, Where w = {}) override {
        return listen(key, bindGetCb(cb), f, w);
    }
    bool cancelListen(const InfoHash& h, size_t token) override {
        return dht_->cancelListen(h, token);
    }
    void connectivityChanged(sa_family_t af) override {
        dht_->connectivityChanged(af);
    }
    void connectivityChanged() override {
        dht_->connectivityChanged();
    }

    void forwardAllMessages(bool forward) {
        forward_all_ = forward;
    }

    void setPushNotificationToken(const std::string& token = "") override {
        dht_->setPushNotificationToken(token);
    }

    /**
     * Call linked callback with push_notification
     * @param notification to process
     */
    void pushNotificationReceived(const std::map<std::string, std::string>& notification) override {
        dht_->pushNotificationReceived(notification);
    }

    void setLogger(const Logger& logger) override {
        DhtInterface::setLogger(logger);
        dht_->setLogger(logger);
    }

    void setLogger(const std::shared_ptr<Logger>& logger) override {
        DhtInterface::setLogger(logger);
        dht_->setLogger(logger);
    }

    /**
     * Only print logs related to the given InfoHash (if given), or disable filter (if zeroes).
     */
    void setLogFilter(const InfoHash& f) override {
        DhtInterface::setLogFilter(f);
        dht_->setLogFilter(f);
    }

private:
    std::unique_ptr<DhtInterface> dht_;
    // prevent copy
    SecureDht(const SecureDht&) = delete;
    SecureDht& operator=(const SecureDht&) = delete;

    Sp<Value> checkValue(const Sp<Value>& v);
    ValueCallback getCallbackFilter(const ValueCallback&, Value::Filter&&);
    GetCallback getCallbackFilter(const GetCallback&, Value::Filter&&);

    Sp<crypto::PrivateKey> key_ {};
    Sp<crypto::Certificate> certificate_ {};

    // method to query the local certificate store
    CertificateStoreQuery localQueryMethod_ {};

    // our certificate cache
    std::map<InfoHash, Sp<crypto::Certificate>> nodesCertificates_ {};
    std::map<InfoHash, Sp<const crypto::PublicKey>> nodesPubKeys_ {};

    std::atomic_bool forward_all_ {false};
    bool enableCache_ {false};
};

const ValueType CERTIFICATE_TYPE = {
    8, "Certificate", std::chrono::hours(24 * 7),
    // A certificate can only be stored at its public key ID.
    [](InfoHash id, Sp<Value>& v, const InfoHash&, const SockAddr&) {
        try {
            crypto::Certificate crt(v->data);
            // TODO check certificate signature
            return crt.getPublicKey().getId() == id;
        } catch (const std::exception& e) {}
        return false;
    },
    [](InfoHash, const Sp<Value>& o, Sp<Value>& n, const InfoHash&, const SockAddr&) {
        try {
            return crypto::Certificate(o->data).getPublicKey().getId() == crypto::Certificate(n->data).getPublicKey().getId();
        } catch (const std::exception& e) {}
        return false;
    }
};

}
