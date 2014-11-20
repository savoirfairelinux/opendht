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

extern "C" {
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
}

#include <random>
#include <sstream>
#include <random>

static gnutls_digest_algorithm_t get_dig_for_pub(gnutls_pubkey_t pubkey)
{
    gnutls_digest_algorithm_t dig;
    int result = gnutls_pubkey_get_preferred_hash_algorithm(pubkey, &dig, nullptr);
    if (result < 0)
        return GNUTLS_DIG_UNKNOWN;
    return dig;
}

static gnutls_digest_algorithm_t get_dig(gnutls_x509_crt_t crt)
{
    gnutls_pubkey_t pubkey;
    gnutls_pubkey_init(&pubkey);

    int result = gnutls_pubkey_import_x509(pubkey, crt, 0);
    if (result < 0) {
        gnutls_pubkey_deinit(pubkey);
        return GNUTLS_DIG_UNKNOWN;
    }

    gnutls_digest_algorithm_t dig = get_dig_for_pub(pubkey);
    gnutls_pubkey_deinit(pubkey);
    return dig;
}

namespace dht {
namespace crypto {

PrivateKey::PrivateKey(gnutls_x509_privkey_t k) : x509_key(k)
{
    gnutls_privkey_init(&key);
    if (gnutls_privkey_import_x509(key, k, GNUTLS_PRIVKEY_IMPORT_COPY) != GNUTLS_E_SUCCESS) {
        key = nullptr;
        throw DhtException("Can't load private key !");
    }
}

PrivateKey::PrivateKey(const Blob& import)
{
    const gnutls_datum_t dt {(unsigned char*)import.data(), static_cast<unsigned>(import.size())};
    gnutls_x509_privkey_init(&x509_key);
    int err = gnutls_x509_privkey_import(x509_key, &dt, GNUTLS_X509_FMT_PEM);
    if (err != GNUTLS_E_SUCCESS) {
        err = gnutls_x509_privkey_import(x509_key, &dt, GNUTLS_X509_FMT_DER);
    }
    if (err != GNUTLS_E_SUCCESS) {
        gnutls_x509_privkey_deinit(x509_key);
        throw DhtException("Can't load private key !");
    }
    gnutls_privkey_init(&key);
    if (gnutls_privkey_import_x509(key, x509_key, GNUTLS_PRIVKEY_IMPORT_COPY) != GNUTLS_E_SUCCESS) {
        throw DhtException("Can't load private key !");
    }
}

PrivateKey::~PrivateKey()
{
    if (key) {
        gnutls_privkey_deinit(key);
        key = nullptr;
    }
    if (x509_key) {
        gnutls_x509_privkey_deinit(x509_key);
        x509_key = nullptr;
    }
}

PrivateKey&
PrivateKey::operator=(PrivateKey&& o) noexcept
{
    if (key) {
        gnutls_privkey_deinit(key);
        key = nullptr;
    }
    if (x509_key) {
        gnutls_x509_privkey_deinit(x509_key);
        x509_key = nullptr;
    }
    key = o.key; x509_key = o.x509_key;
    o.key = nullptr; o.x509_key = nullptr;
    return *this;
}

Blob
PrivateKey::sign(const Blob& data) const
{
    if (!key)
        throw DhtException("Can't sign data: no private key set !");
    gnutls_datum_t sig;
    const gnutls_datum_t dat {(unsigned char*)data.data(), (unsigned)data.size()};
    if (gnutls_privkey_sign_data(key, GNUTLS_DIG_SHA512, 0, &dat, &sig) != GNUTLS_E_SUCCESS)
        throw DhtException("Can't sign data !");
    Blob ret(sig.data, sig.data+sig.size);
    gnutls_free(sig.data);
    return ret;
}

Blob
PrivateKey::decrypt(const Blob& cipher) const
{
    if (!key)
        throw DhtException("Can't decrypt data without private key !");
    const gnutls_datum_t dat {(uint8_t*)cipher.data(), (unsigned)cipher.size()};
    gnutls_datum_t out;
    if (gnutls_privkey_decrypt_data(key, 0, &dat, &out) != GNUTLS_E_SUCCESS)
        throw DhtException("Can't decrypt data !");
    Blob ret {out.data, out.data+out.size};
    gnutls_free(out.data);
    return ret;
}

Blob
PrivateKey::serialize() const
{
    if (!x509_key)
        return {};
    size_t buf_sz = 8192;
    Blob buffer;
    buffer.resize(buf_sz);
    int err = gnutls_x509_privkey_export_pkcs8(x509_key, GNUTLS_X509_FMT_PEM, nullptr, GNUTLS_PKCS_PLAIN, buffer.data(), &buf_sz);
    if (err != GNUTLS_E_SUCCESS) {
        std::cerr << "Could not export certificate - " << gnutls_strerror(err) << std::endl;
        return {};
    }
    buffer.resize(buf_sz);
    return buffer;
}

PublicKey
PrivateKey::getPublicKey() const
{
    gnutls_pubkey_t pk;
    gnutls_pubkey_init(&pk);
    PublicKey pk_ret {pk};
    if (gnutls_pubkey_import_privkey(pk, key, GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN, 0) != GNUTLS_E_SUCCESS)
        return {};
    return pk_ret;
}

PublicKey::PublicKey(const Blob& dat) : pk(nullptr)
{
    unpackBlob(dat);
}

PublicKey::~PublicKey()
{
    if (pk) {
        gnutls_pubkey_deinit(pk);
        pk = nullptr;
    }
}

PublicKey&
PublicKey::operator=(PublicKey&& o) noexcept
{
    if (pk)
        gnutls_pubkey_deinit(pk);
    pk = o.pk;
    o.pk = nullptr;
    return *this;
}

void
PublicKey::pack(Blob& b) const
{
    std::vector<uint8_t> tmp(2048);
    size_t sz = tmp.size();
    int err = gnutls_pubkey_export(pk, GNUTLS_X509_FMT_DER, tmp.data(), &sz);
    if (err != GNUTLS_E_SUCCESS)
        throw std::invalid_argument(std::string("Could not export public key: ") + gnutls_strerror(err));
    tmp.resize(sz);
    serialize<Blob>(tmp, b);
}

void
PublicKey::unpack(Blob::const_iterator& begin, Blob::const_iterator& end)
{
    Blob tmp = deserialize<Blob>(begin, end);
    if (pk)
        gnutls_pubkey_deinit(pk);
    gnutls_pubkey_init(&pk);
    const gnutls_datum_t dat {(uint8_t*)tmp.data(), (unsigned)tmp.size()};
    int err = gnutls_pubkey_import(pk, &dat, GNUTLS_X509_FMT_DER);
    if (err != GNUTLS_E_SUCCESS)
        throw std::invalid_argument(std::string("Could not read public key: ") + gnutls_strerror(err));
}

bool
PublicKey::checkSignature(const Blob& data, const Blob& signature) const {
    if (!pk)
        return false;
    const gnutls_datum_t sig {(uint8_t*)signature.data(), (unsigned)signature.size()};
    const gnutls_datum_t dat {(uint8_t*)data.data(), (unsigned)data.size()};
    int rc = gnutls_pubkey_verify_data2(pk, GNUTLS_SIGN_RSA_SHA512, 0, &dat, &sig);
    return rc >= 0;
}

Blob
PublicKey::encrypt(const Blob& data) const
{
    if (!pk)
        throw DhtException("Can't read public key !");
    const gnutls_datum_t dat {(uint8_t*)data.data(), (unsigned)data.size()};
    gnutls_datum_t encrypted;
    int err = gnutls_pubkey_encrypt_data(pk, 0, &dat, &encrypted);
    if (err != GNUTLS_E_SUCCESS)
        throw DhtException(std::string("Can't encrypt data: ") + gnutls_strerror(err));
    Blob ret {encrypted.data, encrypted.data+encrypted.size};
    gnutls_free(encrypted.data);
    return ret;
}

InfoHash
PublicKey::getId() const
{
    InfoHash id;
    size_t sz = id.size();
    gnutls_pubkey_get_key_id(pk, 0, id.data(), &sz);
    return id;
}

Certificate::Certificate(const Blob& certData) : cert(nullptr)
{
    unpackBlob(certData);
}

Certificate&
Certificate::operator=(Certificate&& o) noexcept
{
    if (cert)
        gnutls_x509_crt_deinit(cert);
    cert = o.cert;
    o.cert = nullptr;
    return *this;
}

void
Certificate::unpack(Blob::const_iterator& begin, Blob::const_iterator& end)
{
    if (cert)
        gnutls_x509_crt_deinit(cert);
    gnutls_x509_crt_init(&cert);
    const gnutls_datum_t crt_dt {(uint8_t*)&(*begin), (unsigned)(end-begin)};
    int err = gnutls_x509_crt_import(cert, &crt_dt, GNUTLS_X509_FMT_PEM);
    if (err != GNUTLS_E_SUCCESS) {
        cert = nullptr;
        throw std::invalid_argument(std::string("Could not read certificate - ") + gnutls_strerror(err));
    }
}

void
Certificate::pack(Blob& b) const
{
    auto b_size = b.size();
    size_t buf_sz = 8192;
    b.resize(b_size + buf_sz);
    int err = gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_PEM, b.data()+b_size, &buf_sz);
    if (err != GNUTLS_E_SUCCESS) {
        std::cerr << "Could not export certificate - " << gnutls_strerror(err) << std::endl;
        b.resize(b_size);
    }
    b.resize(b_size + buf_sz);
}

Certificate::~Certificate()
{
    if (cert) {
        gnutls_x509_crt_deinit(cert);
        cert = nullptr;
    }
}

PublicKey
Certificate::getPublicKey() const
{
    gnutls_pubkey_t pk;
    gnutls_pubkey_init(&pk);
    PublicKey pk_ret(pk);
    if (gnutls_pubkey_import_x509(pk, cert, 0) != GNUTLS_E_SUCCESS)
        return {};
    return pk_ret;
}

PrivateKey
PrivateKey::generate()
{
    gnutls_x509_privkey_t key;
    if (gnutls_x509_privkey_init(&key) != GNUTLS_E_SUCCESS)
        throw std::runtime_error("Can't initialize private key.");
    if (gnutls_x509_privkey_generate(key, GNUTLS_PK_RSA, 2048, 0) != GNUTLS_E_SUCCESS) {
        gnutls_x509_privkey_deinit(key);
        throw std::runtime_error("Can't initialize RSA key pair.");
    }
    return PrivateKey{key};
}

crypto::Identity
generateIdentity(const std::string& name, crypto::Identity ca)
{
    int rc = gnutls_global_init();
    if (rc != GNUTLS_E_SUCCESS)
        return {};

    auto shared_key = std::make_shared<PrivateKey>(PrivateKey::generate());

    gnutls_x509_crt_t cert;
    if (gnutls_x509_crt_init(&cert) != GNUTLS_E_SUCCESS)
        return {};
    auto shared_crt = std::make_shared<Certificate>(cert);

    gnutls_x509_crt_set_activation_time(cert, time(NULL));
    gnutls_x509_crt_set_expiration_time(cert, time(NULL) + (700 * 24 * 60 * 60));
    if (gnutls_x509_crt_set_key(cert, shared_key->x509_key) != GNUTLS_E_SUCCESS) {
        std::cerr << "Error when setting certificate key" << std::endl;
        return {};
    }
    if (gnutls_x509_crt_set_version(cert, 3) != GNUTLS_E_SUCCESS) {
        std::cerr << "Error when setting certificate version" << std::endl;
        return {};
    }

    // TODO: compute the subject key using the recommended RFC method
    auto pk_id = shared_key->getPublicKey().getId();
    gnutls_x509_crt_set_subject_key_id(cert, &pk_id, sizeof(pk_id));

    gnutls_x509_crt_set_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 0, name.data(), name.length());

    const std::string& uid_str = shared_key->getPublicKey().getId().toString();
    gnutls_x509_crt_set_dn_by_oid(cert, GNUTLS_OID_LDAP_UID, 0, uid_str.data(), uid_str.length());

    {
        std::random_device rdev;
        std::uniform_int_distribution<uint64_t> dist{};
        uint64_t cert_serial = dist(rdev);
        gnutls_x509_crt_set_serial(cert, &cert_serial, sizeof(cert_serial));
    }

    if (ca.first && ca.second) {
        gnutls_x509_crt_set_key_usage (cert, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_DATA_ENCIPHERMENT);
        //if (gnutls_x509_crt_sign2(cert, ca.second->cert, ca.first->x509_key, get_dig(cert), 0) != GNUTLS_E_SUCCESS) {
        if (gnutls_x509_crt_privkey_sign(cert, ca.second->cert, ca.first->key, get_dig(cert), 0) != GNUTLS_E_SUCCESS) {
            std::cerr << "Error when signing certificate" << std::endl;
            return {};
        }
    } else {
        gnutls_x509_crt_set_ca_status(cert, 1);
        gnutls_x509_crt_set_key_usage (cert, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_CERT_SIGN);
        //if (gnutls_x509_crt_sign2(cert, cert, key, get_dig(cert), 0) != GNUTLS_E_SUCCESS) {
        if (gnutls_x509_crt_privkey_sign(cert, cert, shared_key->key, get_dig(cert), 0) != GNUTLS_E_SUCCESS) {
            std::cerr << "Error when signing certificate" << std::endl;
            return {};
        }
    }

    gnutls_global_deinit();

    return {shared_key, shared_crt};
}

}

}
