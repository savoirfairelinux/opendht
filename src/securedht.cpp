/*
 *  Copyright (C) 2014-2016 Savoir-faire Linux Inc.
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
 */

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

Config& getConfig(SecureDht::Config& conf)
{
    auto& c = conf.node_config;
    if (c.node_id == InfoHash()) {
          if (conf.id.second)
            c.node_id = InfoHash::get("node:"+conf.id.second->getId().toString());
        else
            c.node_id = InfoHash::getRandom();
    }
    return c;
}

SecureDht::SecureDht(int s, int s6, SecureDht::Config conf)
: Dht(s, s6, getConfig(conf)), key_(conf.id.first), certificate_(conf.id.second)
{
    if (s < 0 && s6 < 0)
        return;

#if GNUTLS_VERSION_NUMBER < 0x030300
    int rc = gnutls_global_init();
    if (rc != GNUTLS_E_SUCCESS)
        throw DhtException(std::string("Error initializing GnuTLS: ")+gnutls_strerror(rc));
#endif

    for (const auto& type : DEFAULT_TYPES)
        registerType(type);

    for (const auto& type : DEFAULT_INSECURE_TYPES)
        registerInsecureType(type);

    registerInsecureType(CERTIFICATE_TYPE);

    if (certificate_) {
        auto certId = certificate_->getPublicKey().getId();
        if (key_ and certId != key_->getPublicKey().getId())
            throw DhtException("SecureDht: provided certificate doesn't match private key.");

        Dht::put(certId, Value {
            CERTIFICATE_TYPE,
            *certificate_,
            1
        }, [this](bool ok) {
            if (ok)
                DHT_LOG.DEBUG("SecureDht: public key announced successfully");
            else
                DHT_LOG.ERR("SecureDht: error while announcing public key!");
        }, {}, true);
    }
}

SecureDht::~SecureDht()
{
#if GNUTLS_VERSION_NUMBER < 0x030300
    gnutls_global_deinit();
#endif
}

ValueType
SecureDht::secureType(ValueType&& type)
{
    type.storePolicy = [this,type](InfoHash id, std::shared_ptr<Value>& v, InfoHash nid, const sockaddr* a, socklen_t al) {
        if (v->isSigned()) {
            if (!v->owner or !v->owner->checkSignature(v->getToSign(), v->signature)) {
                DHT_LOG.WARN("Signature verification failed");
                return false;
            }
            else
                DHT_LOG.WARN("Signature verification succeeded");
        }
        return type.storePolicy(id, v, nid, a, al);
    };
    type.editPolicy = [this,type](InfoHash id, const std::shared_ptr<Value>& o, std::shared_ptr<Value>& n, InfoHash nid, const sockaddr* a, socklen_t al) {
        if (!o->isSigned())
            return type.editPolicy(id, o, n, nid, a, al);
        if (o->owner != n->owner) {
            DHT_LOG.WARN("Edition forbidden: owner changed.");
            return false;
        }
        if (!o->owner or !o->owner->checkSignature(n->getToSign(), n->signature)) {
            DHT_LOG.WARN("Edition forbidden: signature verification failed.");
            return false;
        }
        if (o->seq == n->seq) {
            // If the data is exactly the same,
            // it can be reannounced, possibly by someone else.
            if (o->getToSign() != n->getToSign()) {
                DHT_LOG.WARN("Edition forbidden: sequence number must be increasing.");
                return false;
            }
        }
        else if (n->seq < o->seq)
            return false;
        return true;
    };
    return type;
}

const std::shared_ptr<crypto::Certificate>
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

const std::shared_ptr<const crypto::PublicKey>
SecureDht::getPublicKey(const InfoHash& node) const
{
    if (node == getId())
        return std::make_shared<crypto::PublicKey>(certificate_->getPublicKey());
    auto it = nodesPubKeys_.find(node);
    if (it == nodesPubKeys_.end())
        return nullptr;
    else
        return it->second;
}

const std::shared_ptr<crypto::Certificate>
SecureDht::registerCertificate(const InfoHash& node, const Blob& data)
{
    std::shared_ptr<crypto::Certificate> crt;
    try {
        crt = std::make_shared<crypto::Certificate>(data);
    } catch (const std::exception& e) {
        return nullptr;
    }
    InfoHash h = crt->getPublicKey().getId();
    if (node == h) {
        DHT_LOG.DEBUG("Registering certificate for %s", h.toString().c_str());
        auto it = nodesCertificates_.find(h);
        if (it == nodesCertificates_.end())
            std::tie(it, std::ignore) = nodesCertificates_.emplace(h, std::move(crt));
        else
            it->second = std::move(crt);
        return it->second;
    } else {
        DHT_LOG.DEBUG("Certificate %s for node %s does not match node id !", h.toString().c_str(), node.toString().c_str());
        return nullptr;
    }
}

void
SecureDht::registerCertificate(std::shared_ptr<crypto::Certificate>& cert)
{
    if (cert)
        nodesCertificates_[cert->getId()] = cert;
}

void
SecureDht::findCertificate(const InfoHash& node, std::function<void(const std::shared_ptr<crypto::Certificate>)> cb)
{
    std::shared_ptr<crypto::Certificate> b = getCertificate(node);
    if (b && *b) {
        DHT_LOG.DEBUG("Using certificate from cache for %s", node.toString().c_str());
        if (cb)
            cb(b);
        return;
    }
    if (localQueryMethod_) {
        auto res = localQueryMethod_(node);
        if (not res.empty()) {
            DHT_LOG.DEBUG("Registering certificate from local store for %s", node.toString().c_str());
            nodesCertificates_.emplace(node, res.front());
            if (cb)
                cb(res.front());
            return;
        }
    }

    auto found = std::make_shared<bool>(false);
    Dht::get(node, [cb,node,found,this](const std::vector<std::shared_ptr<Value>>& vals) {
        if (*found)
            return false;
        for (const auto& v : vals) {
            if (auto cert = registerCertificate(node, v->data)) {
                *found = true;
                DHT_LOG.DEBUG("Found certificate for %s", node.toString().c_str());
                if (cb)
                    cb(cert);
                return false;
            }
        }
        return true;
    }, [cb,found](bool) {
        if (!*found and cb)
            cb(nullptr);
    }, Value::TypeFilter(CERTIFICATE_TYPE));
}

void
SecureDht::findPublicKey(const InfoHash& node, std::function<void(const std::shared_ptr<const crypto::PublicKey>)> cb)
{
    auto pk = getPublicKey(node);
    if (pk && *pk) {
        DHT_LOG.DEBUG("Found public key from cache for %s", node.toString().c_str());
        if (cb)
            cb(pk);
        return;
    }
    findCertificate(node, [=](const std::shared_ptr<crypto::Certificate> crt) {
        if (crt && *crt) {
            auto pk = std::make_shared<crypto::PublicKey>(crt->getPublicKey());
            nodesPubKeys_[pk->getId()] = pk;
            if (cb) cb(pk);
        } else {
            if (cb) cb(nullptr);
        }
    });
}

GetCallback
SecureDht::getCallbackFilter(GetCallback cb, Value::Filter&& filter)
{
    return [=](const std::vector<std::shared_ptr<Value>>& values) {
        std::vector<std::shared_ptr<Value>> tmpvals {};
        for (const auto& v : values) {
            // Decrypt encrypted values
            if (v->isEncrypted()) {
                if (not key_)
                    continue;
                try {
                    Value decrypted_val (decrypt(*v));
                    if (decrypted_val.recipient == getId()) {
                        nodesPubKeys_[decrypted_val.owner->getId()] = decrypted_val.owner;
                        if (not filter or filter(decrypted_val))
                            tmpvals.push_back(std::make_shared<Value>(std::move(decrypted_val)));
                    }
                    // Ignore values belonging to other people
                } catch (const std::exception& e) {
                    DHT_LOG.WARN("Could not decrypt value %s : %s", v->toString().c_str(), e.what());
                }
            }
            // Check signed values
            else if (v->isSigned()) {
                if (v->owner and v->owner->checkSignature(v->getToSign(), v->signature)) {
                    nodesPubKeys_[v->owner->getId()] = v->owner;
                    if (not filter  or filter(*v))
                        tmpvals.push_back(v);
                }
                else
                    DHT_LOG.WARN("Signature verification failed for %s", v->toString().c_str());
            }
            // Forward normal values
            else {
                if (not filter or filter(*v))
                    tmpvals.push_back(v);
            }
        }
        if (cb && not tmpvals.empty())
            return cb(tmpvals);
        return true;
    };
}

void
SecureDht::get(const InfoHash& id, GetCallback cb, DoneCallback donecb, Value::Filter&& f)
{
    Dht::get(id, getCallbackFilter(cb, std::forward<Value::Filter>(f)), donecb);
}

size_t
SecureDht::listen(const InfoHash& id, GetCallback cb, Value::Filter&& f)
{
    return Dht::listen(id, getCallbackFilter(cb, std::forward<Value::Filter>(f)));
}

void
SecureDht::putSigned(const InfoHash& hash, std::shared_ptr<Value> val, DoneCallback callback, bool permanent)
{
    if (val->id == Value::INVALID_ID) {
        crypto::random_device rdev;
        val->id = rand_id(rdev);
    }

    // Check if we are already announcing a value
    auto p = getPut(hash, val->id);
    if (p && val->seq <= p->seq) {
        DHT_LOG.DEBUG("Found previous value being announced.");
        val->seq = p->seq + 1;
    }

    // Check if data already exists on the dht
    get(hash,
        [val,this] (const std::vector<std::shared_ptr<Value>>& vals) {
            DHT_LOG.DEBUG("Found online previous value being announced.");
            for (const auto& v : vals) {
                if (!v->isSigned())
                    DHT_LOG.ERR("Existing non-signed value seems to exists at this location.");
                else if (not v->owner or v->owner->getId() != getId())
                    DHT_LOG.ERR("Existing signed value belonging to someone else seems to exists at this location.");
                else if (val->seq <= v->seq)
                    val->seq = v->seq + 1;
            }
            return true;
        },
        [hash,val,this,callback,permanent] (bool /* ok */) {
            sign(*val);
            put(hash, val, callback, {}, permanent);
        },
        Value::IdFilter(val->id)
    );
}

void
SecureDht::putEncrypted(const InfoHash& hash, const InfoHash& to, std::shared_ptr<Value> val, DoneCallback callback, bool permanent)
{
    findPublicKey(to, [=](const std::shared_ptr<const crypto::PublicKey> pk) {
        if(!pk || !*pk) {
            if (callback)
                callback(false, {});
            return;
        }
        DHT_LOG.WARN("Encrypting data for PK: %s", pk->getId().toString().c_str());
        try {
            put(hash, encrypt(*val, *pk), callback, {}, permanent);
        } catch (const std::exception& e) {
            DHT_LOG.ERR("Error putting encrypted data: %s", e.what());
            if (callback)
                callback(false, {});
        }
    });
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
