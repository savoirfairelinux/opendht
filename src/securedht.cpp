/*
 *  Copyright (C) 2014-2025 Savoir-faire Linux Inc.
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

#include "securedht.h"
#include "rng.h"

#include "default_types.h"

extern "C" {
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
}

#include <random>

namespace dht {

SecureDht::SecureDht(std::unique_ptr<DhtInterface> dht, SecureDht::Config conf, IdentityAnnouncedCb iacb, const std::shared_ptr<Logger>& l)
: DhtInterface(l), dht_(std::move(dht)), key_(conf.id.first), certificate_(conf.id.second), enableCache_(conf.cert_cache_all)
{
    if (!dht_) return;
    for (const auto& type : DEFAULT_TYPES)
        registerType(type);

    for (const auto& type : DEFAULT_INSECURE_TYPES)
        registerInsecureType(type);

    registerInsecureType(CERTIFICATE_TYPE);

    if (certificate_) {
        auto certId = certificate_->getId();
        auto certLongId = certificate_->getLongId();
        if (key_ and (certId != key_->getPublicKey().getId() or certLongId != key_->getPublicKey().getLongId()))
            throw DhtException("SecureDht: provided certificate doesn't match private key.");
        dht_->addOnConnectedCallback([this, certId, certLongId, cb=std::move(iacb)]{
            dht_->put(certId, Value {
                CERTIFICATE_TYPE,
                *certificate_,
                1
            }, [this, certId, cb=std::move(cb)](bool ok) {
                if (cb) cb(ok);
                if (logger_)
                    logger_->d(certId, "SecureDht: certificate announcement %s", ok ? "succeeded" : "failed");
            }, {}, true);
            dht_->put(InfoHash::get(certLongId), Value {
                CERTIFICATE_TYPE,
                *certificate_,
                1
            }, [this, cb=std::move(cb)](bool ok) {
                if (cb) cb(ok);
                if (logger_)
                    logger_->debug("SecureDht: certificate announcement {}", ok ? "succeeded" : "failed");
            }, {}, true);
        });
    }
}

SecureDht::~SecureDht(){
    dht_.reset();
}

ValueType
SecureDht::secureType(ValueType&& type)
{
    type.storePolicy = [type](InfoHash id, Sp<Value>& v, const InfoHash& nid, const SockAddr& a) {
        if (v->isSigned())
            return v->checkSignature();
        return type.storePolicy(id, v, nid, a);
    };
    type.editPolicy = [this,type](InfoHash id, const Sp<Value>& o, Sp<Value>& n, const InfoHash& nid, const SockAddr& a) {
        if (not o->isSigned())
            return type.editPolicy(id, o, n, nid, a);
        if (*o->owner != *n->owner or not n->isSigned()) {
            if (logger_)
                logger_->w("Edition forbidden: not signed or wrong owner.");
            return false;
        }
        if (not n->checkSignature()) {
            if (logger_)
                logger_->w("Edition forbidden: signature verification failed.");
            return false;
        }
        if (o->seq == n->seq) {
            // If the data is exactly the same,
            // it can be reannounced, possibly by someone else.
            if (o->getToSign() != n->getToSign()) {
                if (logger_)
                    logger_->w("Edition forbidden: sequence number must be increasing.");
                return false;
            }
        }
        else if (n->seq < o->seq)
            return false;
        return true;
    };
    return type;
}

Sp<crypto::Certificate>
SecureDht::getCertificate(const InfoHash& node) const
{
    if (node == getId())
        return certificate_;
    auto it = nodesCertificates_.find(node);
    if (it == nodesCertificates_.end())
        return nullptr;
    else
        return it->second;
}

Sp<crypto::PublicKey>
SecureDht::getPublicKey(const InfoHash& node) const
{
    if (node == getId())
        return certificate_->getSharedPublicKey();
    auto it = nodesPubKeys_.find(node);
    if (it == nodesPubKeys_.end())
        return nullptr;
    else
        return it->second;
}

Sp<crypto::Certificate>
SecureDht::getCertificate(const PkId& node) const
{
    if (node == getLongId())
        return certificate_;
    auto it = nodesCertificatesLong_.find(node);
    if (it == nodesCertificatesLong_.end())
        return nullptr;
    else
        return it->second;
}

Sp<crypto::PublicKey>
SecureDht::getPublicKey(const PkId& node) const
{
    if (node == getLongId())
        return certificate_->getSharedPublicKey();
    auto it = nodesPubKeysLong_.find(node);
    if (it == nodesPubKeysLong_.end())
        return nullptr;
    else
        return it->second;
}

Sp<crypto::Certificate>
SecureDht::registerCertificate(const InfoHash& node, const Blob& data)
{
    Sp<crypto::Certificate> crt;
    try {
        crt = std::make_shared<crypto::Certificate>(data);
    } catch (const std::exception& e) {
        return nullptr;
    }
    InfoHash h = crt->getPublicKey().getId();
    if (node == h) {
        if (logger_)
            logger_->debug("Registering certificate for {}", h.toString());
        registerCertificate(crt);
        return crt;
    } else {
        if (logger_)
            logger_->w("Certificate {} for node {} does not match node id !", h.toString(), node.toString());
        return nullptr;
    }
}
Sp<crypto::Certificate>
SecureDht::registerCertificate(const PkId& node, const Blob& data)
{
    Sp<crypto::Certificate> crt;
    try {
        crt = std::make_shared<crypto::Certificate>(data);
    } catch (const std::exception& e) {
        return nullptr;
    }
    auto h = crt->getPublicKey().getLongId();
    if (node == h) {
        if (logger_)
            logger_->debug("Registering certificate for {}", h.toString());
        registerCertificate(crt);
        return crt;
    } else {
        if (logger_)
            logger_->w("Certificate {} for node {} does not match node id !", h.toString(), node.toString());
        return nullptr;
    }
}

void
SecureDht::registerCertificate(const Sp<crypto::Certificate>& cert)
{
    if (cert) {
        nodesCertificates_[cert->getId()] = cert;
        nodesCertificatesLong_[cert->getLongId()] = cert;
    }
}

void
SecureDht::findCertificate(const InfoHash& node, const std::function<void(const Sp<crypto::Certificate>)>& cb)
{
    Sp<crypto::Certificate> b = getCertificate(node);
    if (b && *b) {
        if (logger_)
            logger_->d("Using certificate from cache for %s", node.to_c_str());
        if (cb)
            cb(b);
        return;
    }
    if (localQueryMethod_) {
        auto res = localQueryMethod_(node);
        if (not res.empty()) {
            if (logger_)
                logger_->d("Registering certificate from local store for %s", node.to_c_str());
            nodesCertificates_.emplace(node, res.front());
            if (cb)
                cb(res.front());
            return;
        }
    }

    auto found = std::make_shared<bool>(false);
    dht_->get(node, [cb,node,found,this](const std::vector<Sp<Value>>& vals) {
        for (const auto& v : vals) {
            if (auto cert = registerCertificate(node, v->data)) {
                *found = true;
                if (logger_)
                    logger_->d(node, "Found certificate for %s", node.to_c_str());
                if (cb)
                    cb(cert);
                return false;
            }
        }
        return !*found;
    }, [cb,found](bool) {
        if (!*found and cb)
            cb(nullptr);
    }, Value::TypeFilter(CERTIFICATE_TYPE));
}

void
SecureDht::findPublicKey(const InfoHash& node, const std::function<void(const Sp<crypto::PublicKey>)>& cb)
{
    auto pk = getPublicKey(node);
    if (pk && *pk) {
        if (logger_)
            logger_->d(node, "Found public key from cache for %s", node.to_c_str());
        if (cb)
            cb(pk);
        return;
    }
    findCertificate(node, [=](const Sp<crypto::Certificate>& crt) {
        if (crt && *crt) {
            auto pk = crt->getSharedPublicKey();
            if (*pk) {
                nodesPubKeys_[pk->getId()] = pk;
                nodesPubKeysLong_[pk->getLongId()] = pk;
                if (cb) cb(pk);
                return;
            }
        }
        if (cb) cb(nullptr);
    });
}

void
SecureDht::findCertificate(const PkId& node, const std::function<void(const Sp<crypto::Certificate>)>& cb)
{
    Sp<crypto::Certificate> b = getCertificate(node);
    if (b && *b) {
        if (logger_)
            logger_->debug("Using certificate from cache for {}", node.to_c_str());
        if (cb)
            cb(b);
        return;
    }

    auto found = std::make_shared<bool>(false);
    dht_->get(InfoHash::get(node), [cb,node,found,this](const std::vector<Sp<Value>>& vals) {
        for (const auto& v : vals) {
            if (auto cert = registerCertificate(node, v->data)) {
                *found = true;
                if (logger_)
                    logger_->debug("Found certificate for {}", node.to_c_str());
                if (cb)
                    cb(cert);
                return false;
            }
        }
        return !*found;
    }, [cb,found](bool) {
        if (!*found and cb)
            cb(nullptr);
    }, Value::TypeFilter(CERTIFICATE_TYPE));
}

void
SecureDht::findPublicKey(const PkId& node, const std::function<void(const Sp<crypto::PublicKey>)>& cb)
{
    auto pk = getPublicKey(node);
    if (pk && *pk) {
        if (logger_)
            logger_->debug("Found public key from cache for {}", node.to_c_str());
        if (cb)
            cb(pk);
        return;
    }
    findCertificate(node, [=](const Sp<crypto::Certificate>& crt) {
        if (crt && *crt) {
            auto pk = crt->getSharedPublicKey();
            if (*pk) {
                nodesPubKeys_[pk->getId()] = pk;
                nodesPubKeysLong_[pk->getLongId()] = pk;
                if (cb) cb(pk);
                return;
            }
        }
        if (cb) cb(nullptr);
    });
}

Sp<Value>
SecureDht::checkValue(const Sp<Value>& v)
{
    // Decrypt encrypted values
    if (v->isEncrypted()) {
        if (not key_) {
#ifdef OPENDHT_PROXY_SERVER
            if (forward_all_) // We are currently a proxy, send messages to clients.
                return v;
#endif
            return {};
        }
        try {
            auto isDecrypted = v->isDecrypted();
            if (auto decrypted_val = v->decrypt(*key_)) {
                auto cacheValue = not isDecrypted and decrypted_val->owner;
                if (cacheValue) {
                    nodesPubKeys_[decrypted_val->owner->getId()] = decrypted_val->owner;
                    nodesPubKeysLong_[decrypted_val->owner->getLongId()] = decrypted_val->owner;
                }
                return decrypted_val;
            }
        } catch (const std::exception& e) {
            if (logger_)
                logger_->w("Could not decrypt value %s : %s", v->toString().c_str(), e.what());
        }
    }
    // Check signed values
    else if (v->isSigned()) {
        auto cacheValue = not v->isSignatureChecked() and enableCache_ and v->owner;
        if (v->checkSignature()) {
            if (cacheValue) {
                nodesPubKeys_[v->owner->getId()] = v->owner;
                nodesPubKeysLong_[v->owner->getLongId()] = v->owner;
            }
            return v;
        } else if (logger_)
            logger_->w("Signature verification failed for %s", v->toString().c_str());
    }
    // Forward normal values
    else {
        return v;
    }
    return {};
}

ValueCallback
SecureDht::getCallbackFilter(const ValueCallback& cb, Value::Filter&& filter)
{
    return [=](const std::vector<Sp<Value>>& values, bool expired) {
        std::vector<Sp<Value>> tmpvals {};
        if (not filter)
            tmpvals.reserve(values.size());
        for (const auto& v : values) {
            if (auto nv = checkValue(v))
                if (not filter or filter(*nv))
                    tmpvals.emplace_back(std::move(nv));
        }
        if (cb and not tmpvals.empty())
            return cb(tmpvals, expired);
        return true;
    };
}


GetCallback
SecureDht::getCallbackFilter(const GetCallback& cb, Value::Filter&& filter)
{
    return [=](const std::vector<Sp<Value>>& values) {
        std::vector<Sp<Value>> tmpvals {};
        if (not filter)
            tmpvals.reserve(values.size());
        for (const auto& v : values) {
            if (auto nv = checkValue(v))
                if (not filter or filter(*nv))
                    tmpvals.emplace_back(std::move(nv));
        }
        if (cb and not tmpvals.empty())
            return cb(tmpvals);
        return true;
    };
}

void
SecureDht::get(const InfoHash& id, GetCallback cb, DoneCallback donecb, Value::Filter&& f, Where&& w)
{
    dht_->get(id, getCallbackFilter(cb, std::forward<Value::Filter>(f)), donecb, {}, std::forward<Where>(w));
}

size_t
SecureDht::listen(const InfoHash& id, ValueCallback cb, Value::Filter f, Where w)
{
    return dht_->listen(id, getCallbackFilter(cb, std::forward<Value::Filter>(f)), {}, std::forward<Where>(w));
}


size_t
SecureDht::listen(const InfoHash& id, GetCallback cb, Value::Filter f, Where w)
{
    return dht_->listen(id, getCallbackFilter(cb, std::forward<Value::Filter>(f)), {}, std::forward<Where>(w));
}

void
SecureDht::putSigned(const InfoHash& hash, Sp<Value> val, DoneCallback callback, bool permanent)
{
    if (not key_ or not hash or not val)  {
        if (callback)
            callback(false, {});
        return;
    }
    if (val->id == Value::INVALID_ID) {
        std::random_device rdev;
        std::uniform_int_distribution<Value::Id> rand_id;
        val->id = rand_id(rdev);
    }

    // Check if we are already announcing a value
    auto p = dht_->getPut(hash, val->id);
    if (p && val->seq <= p->seq) {
        val->seq = p->seq + 1;
    }

    // Check if data already exists on the dht
    get(hash,
        [val,this] (const std::vector<Sp<Value>>& vals) {
            if (logger_)
                logger_->d("Found online previous value being announced.");
            for (const auto& v : vals) {
                if (!v->isSigned()) {
                    if (logger_)
                        logger_->e("Existing non-signed value seems to exists at this location.");
                } else if (not v->owner or v->owner->getId() != getId()) {
                    if (logger_)
                        logger_->e("Existing signed value belonging to someone else seems to exists at this location.");
                } else if (val->seq <= v->seq)
                    val->seq = v->seq + 1;
            }
            return true;
        },
        [hash,val,this,callback,permanent] (bool /* ok */) {
            sign(*val);
            dht_->put(hash, val, callback, time_point::max(), permanent);
        },
        Value::IdFilter(val->id),
        Where().id(val->id)
    );
}

void
SecureDht::putEncrypted(const InfoHash& hash, const InfoHash& to, Sp<Value> val, DoneCallback callback, bool permanent)
{
    if (not key_)  {
        if (callback)
            callback(false, {});
        return;
    }
    findPublicKey(to, [this, hash, val = std::move(val), callback = std::move(callback), permanent](const Sp<crypto::PublicKey>& pk) {
        if(!pk || !*pk) {
            if (callback)
                callback(false, {});
            return;
        }
        if (logger_)
            logger_->w("Encrypting data for PK: %s", pk->getId().toString().c_str());
        try {
            dht_->put(hash, encrypt(*val, *pk), callback, time_point::max(), permanent);
        } catch (const std::exception& e) {
            if (logger_)
                logger_->e("Error putting encrypted data: %s", e.what());
            if (callback)
                callback(false, {});
        }
    });
}

void
SecureDht::putEncrypted(const InfoHash& hash, const PkId& to, Sp<Value> val, DoneCallback callback, bool permanent)
{
    if (not key_)  {
        if (callback)
            callback(false, {});
        return;
    }
    findPublicKey(to, [this, hash, val = std::move(val), callback = std::move(callback), permanent](const Sp<crypto::PublicKey>& pk) {
        if(!pk || !*pk) {
            if (callback)
                callback(false, {});
            return;
        }
        if (logger_)
            logger_->warn("Encrypting data for PK: {}", pk->getLongId());
        try {
            dht_->put(hash, encrypt(*val, *pk), callback, time_point::max(), permanent);
        } catch (const std::exception& e) {
            if (logger_)
                logger_->e("Error putting encrypted data: %s", e.what());
            if (callback)
                callback(false, {});
        }
    });
}

void
SecureDht::putEncrypted(const InfoHash& hash, const crypto::PublicKey& pk, Sp<Value> val, DoneCallback callback, bool permanent)
{
    if (not key_)  {
        if (callback)
            callback(false, {});
        return;
    }
    if (logger_)
        logger_->warn("Encrypting data for PK: {}", pk.getLongId());
    try {
        dht_->put(hash, encrypt(*val, pk), callback, time_point::max(), permanent);
    } catch (const std::exception& e) {
        if (logger_)
            logger_->e("Error putting encrypted data: %s", e.what());
        if (callback)
            callback(false, {});
    }
}

void
SecureDht::sign(Value& v) const
{
    v.sign(*key_);
}

Value
SecureDht::encrypt(Value& v, const crypto::PublicKey& to) const
{
    return v.encrypt(*key_, to);
}

Value
SecureDht::decrypt(const Value& v)
{
    if (not v.isEncrypted())
        throw DhtException("Data is not encrypted.");

    auto decrypted = key_->decrypt(v.cypher);

    Value ret {v.id};
    auto msg = msgpack::unpack((const char*)decrypted.data(), decrypted.size());
    ret.msgpack_unpack_body(msg.get());

    if (ret.recipient != getId())
        throw crypto::DecryptError("Recipient mismatch");
    if (not ret.owner or not ret.owner->checkSignature(ret.getToSign(), ret.signature))
        throw crypto::DecryptError("Signature mismatch");

    return ret;
}

}
