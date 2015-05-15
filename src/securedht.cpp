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

#include "securedht.h"

#include "default_types.h"

extern "C" {
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
}

#include <random>

namespace dht {

SecureDht::SecureDht(int s, int s6, crypto::Identity id)
: Dht(s, s6, InfoHash::get("node:"+id.second->getPublicKey().getId().toString())), key_(id.first), certificate_(id.second)
{
    if (s < 0 && s6 < 0)
        return;

    int rc = gnutls_global_init();
    if (rc != GNUTLS_E_SUCCESS)
        throw DhtException(std::string("Error initializing GnuTLS: ")+gnutls_strerror(rc));

    auto certId = certificate_->getPublicKey().getId();
    if (certId != key_->getPublicKey().getId())
        throw DhtException("SecureDht: provided certificate doesn't match private key.");

    for (const auto& type : DEFAULT_TYPES)
        registerType(type);
    for (const auto& type : DEFAULT_INSECURE_TYPES)
        registerInsecureType(type);
    registerInsecureType(CERTIFICATE_TYPE);

    Dht::put(certId, Value {
        CERTIFICATE_TYPE,
        *certificate_,
        1
    }, [this](bool ok) {
        if (ok)
            DHT_DEBUG("SecureDht: public key announced successfully");
        else
            DHT_ERROR("SecureDht: error while announcing public key!");
    });
}

SecureDht::~SecureDht()
{
    gnutls_global_deinit();
}

ValueType
SecureDht::secureType(ValueType&& type)
{
    type.storePolicy = [this,type](InfoHash id, std::shared_ptr<Value>& v, InfoHash nid, const sockaddr* a, socklen_t al) {
        if (v->isSigned() && !v->isEncrypted()) {
            if (!v->owner.checkSignature(v->getToSign(), v->signature)) {
                DHT_WARN("Signature verification failed");
                return false;
            }
            else
                DHT_WARN("Signature verification succeded");
        }
        return type.storePolicy(id, v, nid, a, al);
    };
    type.editPolicy = [this,type](InfoHash id, const std::shared_ptr<Value>& o, std::shared_ptr<Value>& n, InfoHash nid, const sockaddr* a, socklen_t al) {
        if (!o->isSigned() || o->isEncrypted())
            return type.editPolicy(id, o, n, nid, a, al);
        if (o->owner != n->owner) {
            DHT_WARN("Edition forbidden: owner changed.");
            return false;
        }
        if (!o->owner.checkSignature(n->getToSign(), n->signature)) {
            DHT_WARN("Edition forbidden: signature verification failed.");
            return false;
        }
        if (o->seq == n->seq) {
            // If the data is exactly the same,
            // it can be reannounced, possibly by someone else.
            if (o->getToSign() != n->getToSign()) {
                DHT_WARN("Edition forbidden: sequence number must be increasing.");
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
        DHT_DEBUG("Registering public key for %s", h.toString().c_str());
        nodesCertificates_[h] = crt;
    } else {
        DHT_DEBUG("Certificate %s for node %s does not match node id !", h.toString().c_str(), node.toString().c_str());
        return nullptr;
    }
    auto it = nodesCertificates_.find(h);
    if (it == nodesCertificates_.end())
        return nullptr;
    return it->second;
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
        DHT_DEBUG("Using public key from cache for %s", node.toString().c_str());
        if (cb)
            cb(b);
        return;
    }
    auto found = std::make_shared<bool>(false);
    Dht::get(node, [cb,node,found,this](const std::vector<std::shared_ptr<Value>>& vals) {
        if (*found)
            return false;
        for (const auto& v : vals) {
            if (auto cert = registerCertificate(node, v->data)) {
                *found = true;
                DHT_DEBUG("Found public key for %s", node.toString().c_str());
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


Dht::GetCallback
SecureDht::getCallbackFilter(GetCallback cb, Value::Filter&& filter)
{
    return [=](const std::vector<std::shared_ptr<Value>>& values) {
        std::vector<std::shared_ptr<Value>> tmpvals {};
        for (const auto& v : values) {
            // Decrypt encrypted values
            if (v->isEncrypted()) {
                try {
                    Value decrypted_val (decrypt(*v));
                    if (decrypted_val.recipient == getId()) {
                        if (decrypted_val.owner.checkSignature(decrypted_val.getToSign(), decrypted_val.signature)) {
                            if (not filter or filter(decrypted_val))
                                tmpvals.push_back(std::make_shared<Value>(std::move(decrypted_val)));
                        }
                        else
                            DHT_WARN("Signature verification failed for %s", v->toString().c_str());
                    }
                    // Ignore values belonging to other people
                } catch (const std::exception& e) {
                    DHT_WARN("Could not decrypt value %s : %s", v->toString().c_str(), e.what());
                }
            }
            // Check signed values
            else if (v->isSigned()) {
                if (v->owner.checkSignature(v->getToSign(), v->signature)) {
                    if (not filter  or filter(*v))
                        tmpvals.push_back(v);
                }
                else
                    DHT_WARN("Signature verification failed for %s", v->toString().c_str());
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
SecureDht::putSigned(const InfoHash& hash, const std::shared_ptr<Value>& val, DoneCallback callback)
{
    if (val->id == Value::INVALID_ID) {
#ifndef _WIN32
        std::random_device rdev;
#else
        std::default_random_engine rdev(std::chrono::system_clock::now().time_since_epoch().count());
#endif
        val->id = rand_id(rdev);
    }

    // Check if we are already announcing a value
    auto p = getPut(hash, val->id);
    if (p && val->seq <= p->seq) {
        DHT_DEBUG("Found previous value being announced.");
        val->seq = p->seq + 1;
    }

    // Check if data already exists on the dht
    get(hash,
        [val,this] (const std::vector<std::shared_ptr<Value>>& vals) {
            DHT_DEBUG("Found online previous value being announced.");
            for (const auto& v : vals) {
                if (!v->isSigned())
                    DHT_ERROR("Existing non-signed value seems to exists at this location.");
                else if (v->owner.getId() != getId())
                    DHT_ERROR("Existing signed value belonging to someone else seems to exists at this location.");
                else if (val->seq <= v->seq)
                    val->seq = v->seq + 1;
            }
            return true;
        },
        [hash,val,this,callback] (bool /* ok */) {
            sign(*val);
            put(hash, val, callback);
        },
        Value::IdFilter(val->id)
    );
}

void
SecureDht::putEncrypted(const InfoHash& hash, const InfoHash& to, std::shared_ptr<Value> val, DoneCallback callback)
{
    findCertificate(to, [=](const std::shared_ptr<crypto::Certificate> crt) {
        if(!crt || !*crt) {
            if (callback)
                callback(false);
            return;
        }
        DHT_WARN("Encrypting data for PK: %s", crt->getPublicKey().getId().toString().c_str());
        try {
            put(hash, encrypt(*val, crt->getPublicKey()), callback);
        } catch (const std::exception& e) {
            DHT_ERROR("Error putting encrypted data: %s", e.what());
            if (callback)
                callback(false);
        }
    });
}

void
SecureDht::sign(Value& v) const
{
    if (v.flags.isEncrypted())
        throw DhtException("Can't sign encrypted data.");
    v.owner = key_->getPublicKey();
    v.flags = Value::ValueFlags(true, false, v.flags[2]);
    v.signature = key_->sign(v.getToSign());
}

Value
SecureDht::encrypt(Value& v, const crypto::PublicKey& to) const
{
    if (v.flags.isEncrypted())
        throw DhtException("Data is already encrypted.");
    v.setRecipient(to.getId());
    sign(v);
    Value nv {v.id};
    nv.setCypher(to.encrypt(v.getToEncrypt()));
    return nv;
}

Value
SecureDht::decrypt(const Value& v)
{
    if (not v.flags.isEncrypted())
        throw DhtException("Data is not encrypted.");
    auto decrypted = key_->decrypt(v.cypher);
    Value ret {v.id};
    auto pb = decrypted.cbegin(), pe = decrypted.cend();
    ret.unpackBody(pb, pe);
    return ret;
}

}
