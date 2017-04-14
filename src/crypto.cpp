/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
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
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "crypto.h"
#include "rng.h"

extern "C" {
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <nettle/gcm.h>
#include <nettle/aes.h>

#include <argon2.h>
}

#include <random>
#include <sstream>
#include <stdexcept>
#include <cassert>

#ifdef _WIN32
static std::uniform_int_distribution<int> rand_byte{ 0, std::numeric_limits<uint8_t>::max() };
#else
static std::uniform_int_distribution<uint8_t> rand_byte;
#endif

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

// support for GnuTLS < 3.4.
#if GNUTLS_VERSION_NUMBER < 0x030400
#define GNUTLS_PKCS_PKCS12_3DES GNUTLS_PKCS_USE_PKCS12_3DES
#define GNUTLS_PKCS_PKCS12_ARCFOUR GNUTLS_PKCS_USE_PKCS12_ARCFOUR
#define GNUTLS_PKCS_PKCS12_RC2_40 GNUTLS_PKCS_USE_PKCS12_RC2_40
#define GNUTLS_PKCS_PBES2_3DES GNUTLS_PKCS_USE_PBES2_3DES
#define GNUTLS_PKCS_PBES2_AES_128 GNUTLS_PKCS_USE_PBES2_AES_128
#define GNUTLS_PKCS_PBES2_AES_192 GNUTLS_PKCS_USE_PBES2_AES_192
#define GNUTLS_PKCS_PBES2_AES_256 GNUTLS_PKCS_USE_PBES2_AES_256
#endif

namespace dht {
namespace crypto {

static constexpr std::array<size_t, 3> AES_LENGTHS {{128/8, 192/8, 256/8}};
static constexpr size_t PASSWORD_SALT_LENGTH {16};

constexpr gnutls_digest_algorithm_t gnutlsHashAlgo(size_t min_res) {
    return (min_res > 256/8) ? GNUTLS_DIG_SHA512 : (
           (min_res > 128/8) ? GNUTLS_DIG_SHA256 : (
                               GNUTLS_DIG_SHA1));
}

constexpr size_t gnutlsHashSize(int algo) {
    return (algo == GNUTLS_DIG_SHA512) ? 512/8 : (
           (algo == GNUTLS_DIG_SHA256) ? 256/8 : (
           (algo == GNUTLS_DIG_SHA1)   ? 160/8 : 0 ));
}

size_t aesKeySize(size_t max)
{
    size_t aes_key_len = 0;
    for (size_t s : AES_LENGTHS) {
        if (s <= max) aes_key_len = s;
        else break;
    }
    return aes_key_len;
}

bool aesKeySizeGood(size_t key_size)
{
    for (auto& i : AES_LENGTHS)
        if (key_size == i)
            return true;
    return false;
}

#ifndef GCM_DIGEST_SIZE
#define GCM_DIGEST_SIZE GCM_BLOCK_SIZE
#endif

Blob aesEncrypt(const Blob& data, const Blob& key)
{
    if (not aesKeySizeGood(key.size()))
        throw DecryptError("Wrong key size");

    Blob ret(data.size() + GCM_IV_SIZE + GCM_DIGEST_SIZE);
    {
        crypto::random_device rdev;
        std::generate_n(ret.begin(), GCM_IV_SIZE, std::bind(rand_byte, std::ref(rdev)));
    }
    struct gcm_aes_ctx aes;
    gcm_aes_set_key(&aes, key.size(), key.data());
    gcm_aes_set_iv(&aes, GCM_IV_SIZE, ret.data());
    gcm_aes_update(&aes, data.size(), data.data());

    gcm_aes_encrypt(&aes, data.size(), ret.data() + GCM_IV_SIZE, data.data());
    gcm_aes_digest(&aes, GCM_DIGEST_SIZE, ret.data() + GCM_IV_SIZE + data.size());
    return ret;
}

Blob aesEncrypt(const Blob& data, const std::string& password)
{
    Blob salt;
    Blob key = stretchKey(password, salt, 256 / 8);
    Blob encrypted = aesEncrypt(data, key);
    encrypted.insert(encrypted.begin(), salt.begin(), salt.end());
    return encrypted;
}

Blob aesDecrypt(const Blob& data, const Blob& key)
{
    if (not aesKeySizeGood(key.size()))
        throw DecryptError("Wrong key size");

    if (data.size() <= GCM_IV_SIZE + GCM_DIGEST_SIZE)
        throw DecryptError("Wrong data size");

    std::array<uint8_t, GCM_DIGEST_SIZE> digest;

    struct gcm_aes_ctx aes;
    gcm_aes_set_key(&aes, key.size(), key.data());
    gcm_aes_set_iv(&aes, GCM_IV_SIZE, data.data());

    size_t data_sz = data.size() - GCM_IV_SIZE - GCM_DIGEST_SIZE;
    Blob ret(data_sz);
    //gcm_aes_update(&aes, data_sz, data.data() + GCM_IV_SIZE);
    gcm_aes_decrypt(&aes, data_sz, ret.data(), data.data() + GCM_IV_SIZE);
    //gcm_aes_digest(aes, GCM_DIGEST_SIZE, digest.data());

    // TODO compute the proper digest directly from the decryption pass
    Blob ret_tmp(data_sz);
    struct gcm_aes_ctx aes_d;
    gcm_aes_set_key(&aes_d, key.size(), key.data());
    gcm_aes_set_iv(&aes_d, GCM_IV_SIZE, data.data());
    gcm_aes_update(&aes_d, ret.size(), ret.data());
    gcm_aes_encrypt(&aes_d, ret.size(), ret_tmp.data(), ret.data());
    gcm_aes_digest(&aes_d, GCM_DIGEST_SIZE, digest.data());

    if (not std::equal(digest.begin(), digest.end(), data.end() - GCM_DIGEST_SIZE))
        throw DecryptError("Can't decrypt data");

    return ret;
}

Blob aesDecrypt(const Blob& data, const std::string& password)
{
    if (data.size() <= PASSWORD_SALT_LENGTH)
        throw DecryptError("Wrong data size");
    Blob salt {data.begin(), data.begin()+PASSWORD_SALT_LENGTH};
    Blob key = stretchKey(password, salt, 256/8);
    Blob encrypted {data.begin()+PASSWORD_SALT_LENGTH, data.end()};
    return aesDecrypt(encrypted, key);
}

Blob stretchKey(const std::string& password, Blob& salt, size_t key_length)
{
    if (salt.empty()) {
        salt.resize(PASSWORD_SALT_LENGTH);
        crypto::random_device rdev;
        std::generate_n(salt.begin(), salt.size(), std::bind(rand_byte, std::ref(rdev)));
    }
    Blob res;
    res.resize(32);
    auto ret = argon2i_hash_raw(16, 64*1024, 1, password.data(), password.size(), salt.data(), salt.size(), res.data(), res.size());
    if (ret != ARGON2_OK)
        throw CryptoException("Can't compute argon2i !");
    return hash(res, key_length);
}

Blob hash(const Blob& data, size_t hash_len)
{
    auto algo = gnutlsHashAlgo(hash_len);
    size_t res_size = gnutlsHashSize(algo);
    Blob res;
    res.resize(res_size);
    const gnutls_datum_t gdat {(uint8_t*)data.data(), (unsigned)data.size()};
    if (gnutls_fingerprint(algo, &gdat, res.data(), &res_size))
        throw CryptoException("Can't compute hash !");
    res.resize(std::min(hash_len, res_size));
    return res;
}

PrivateKey::PrivateKey()
{}

PrivateKey::PrivateKey(gnutls_x509_privkey_t k) : x509_key(k)
{
    gnutls_privkey_init(&key);
    if (gnutls_privkey_import_x509(key, k, GNUTLS_PRIVKEY_IMPORT_COPY) != GNUTLS_E_SUCCESS) {
        key = nullptr;
        throw CryptoException("Can't load generic private key !");
    }
}

PrivateKey::PrivateKey(const Blob& import, const std::string& password)
{
    int err = gnutls_x509_privkey_init(&x509_key);
    if (err != GNUTLS_E_SUCCESS)
        throw CryptoException("Can't initialize private key !");

    const gnutls_datum_t dt {(uint8_t*)import.data(), static_cast<unsigned>(import.size())};
    const char* password_ptr = password.empty() ? nullptr : password.c_str();
    int flags = password.empty() ? GNUTLS_PKCS_PLAIN
                : ( GNUTLS_PKCS_PBES2_AES_128 | GNUTLS_PKCS_PBES2_AES_192  | GNUTLS_PKCS_PBES2_AES_256
                  | GNUTLS_PKCS_PKCS12_3DES   | GNUTLS_PKCS_PKCS12_ARCFOUR | GNUTLS_PKCS_PKCS12_RC2_40);

    err = gnutls_x509_privkey_import2(x509_key, &dt, GNUTLS_X509_FMT_PEM, password_ptr, flags);
    if (err != GNUTLS_E_SUCCESS) {
        int err_der = gnutls_x509_privkey_import2(x509_key, &dt, GNUTLS_X509_FMT_DER, password_ptr, flags);
        if (err_der != GNUTLS_E_SUCCESS) {
            gnutls_x509_privkey_deinit(x509_key);
            if (err == GNUTLS_E_DECRYPTION_FAILED or err_der == GNUTLS_E_DECRYPTION_FAILED)
                throw DecryptError("Can't decrypt private key");
            else
                throw CryptoException(std::string("Can't load private key: PEM: ") + gnutls_strerror(err)
                                                                       + " DER: "  + gnutls_strerror(err_der));
        }
    }

    gnutls_privkey_init(&key);
    if (gnutls_privkey_import_x509(key, x509_key, GNUTLS_PRIVKEY_IMPORT_COPY) != GNUTLS_E_SUCCESS) {
        throw CryptoException("Can't load generic private key !");
    }
}

PrivateKey::PrivateKey(PrivateKey&& o) noexcept : key(o.key), x509_key(o.x509_key)
{
    o.key = nullptr;
    o.x509_key = nullptr;
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
        throw CryptoException("Can't sign data: no private key set !");
    if (std::numeric_limits<unsigned>::max() < data.size())
        throw CryptoException("Can't sign data: too large !");
    gnutls_datum_t sig;
    const gnutls_datum_t dat {(unsigned char*)data.data(), (unsigned)data.size()};
    if (gnutls_privkey_sign_data(key, GNUTLS_DIG_SHA512, 0, &dat, &sig) != GNUTLS_E_SUCCESS)
        throw CryptoException("Can't sign data !");
    Blob ret(sig.data, sig.data+sig.size);
    gnutls_free(sig.data);
    return ret;
}

Blob
PrivateKey::decryptBloc(const uint8_t* src, size_t src_size) const
{
    const gnutls_datum_t dat {(uint8_t*)src, (unsigned)src_size};
    gnutls_datum_t out;
    int err = gnutls_privkey_decrypt_data(key, 0, &dat, &out);
    if (err != GNUTLS_E_SUCCESS)
        throw DecryptError(std::string("Can't decrypt data: ") + gnutls_strerror(err));
    Blob ret {out.data, out.data+out.size};
    gnutls_free(out.data);
    return ret;
}

Blob
PrivateKey::decrypt(const Blob& cipher) const
{
    if (!key)
        throw CryptoException("Can't decrypt data without private key !");

    unsigned key_len = 0;
    int err = gnutls_privkey_get_pk_algorithm(key, &key_len);
    if (err < 0)
        throw CryptoException("Can't read public key length !");
    if (err != GNUTLS_PK_RSA)
        throw CryptoException("Must be an RSA key");

    unsigned cypher_block_sz = key_len / 8;
    if (cipher.size() < cypher_block_sz)
        throw DecryptError("Unexpected cipher length");
    else if (cipher.size() == cypher_block_sz)
        return decryptBloc(cipher.data(), cypher_block_sz);

    return aesDecrypt(Blob {cipher.begin() + cypher_block_sz, cipher.end()}, decryptBloc(cipher.data(), cypher_block_sz));
}

Blob
PrivateKey::serialize(const std::string& password) const
{
    if (!x509_key)
        return {};
    size_t buf_sz = 8192;
    Blob buffer;
    buffer.resize(buf_sz);
    int err = password.empty()
        ? gnutls_x509_privkey_export_pkcs8(x509_key, GNUTLS_X509_FMT_PEM, nullptr,          GNUTLS_PKCS_PLAIN,         buffer.data(), &buf_sz)
        : gnutls_x509_privkey_export_pkcs8(x509_key, GNUTLS_X509_FMT_PEM, password.c_str(), GNUTLS_PKCS_PBES2_AES_256, buffer.data(), &buf_sz);
    if (err != GNUTLS_E_SUCCESS) {
        std::cerr << "Could not export private key - " << gnutls_strerror(err) << std::endl;
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
    unpack(dat.data(), dat.size());
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
        throw CryptoException(std::string("Could not export public key: ") + gnutls_strerror(err));
    tmp.resize(sz);
    b.insert(b.end(), tmp.begin(), tmp.end());
}

void
PublicKey::unpack(const uint8_t* data, size_t data_size)
{
    if (pk)
        gnutls_pubkey_deinit(pk);
    gnutls_pubkey_init(&pk);
    const gnutls_datum_t dat {(uint8_t*)data, (unsigned)data_size};
    int err = gnutls_pubkey_import(pk, &dat, GNUTLS_X509_FMT_PEM);
    if (err != GNUTLS_E_SUCCESS)
        err = gnutls_pubkey_import(pk, &dat, GNUTLS_X509_FMT_DER);
    if (err != GNUTLS_E_SUCCESS)
        throw CryptoException(std::string("Could not read public key: ") + gnutls_strerror(err));
}

std::string
PublicKey::toString() const
{
    std::string ret;
    size_t sz = ret.size();
    int err = gnutls_pubkey_export(pk, GNUTLS_X509_FMT_PEM, (void*)ret.data(), &sz);
    if (err ==  GNUTLS_E_SHORT_MEMORY_BUFFER) {
        ret.resize(sz);
        int err = gnutls_pubkey_export(pk, GNUTLS_X509_FMT_PEM, (void*)ret.data(), &sz);
        if (err != GNUTLS_E_SUCCESS)
            throw CryptoException(std::string("Could not print public key: ") + gnutls_strerror(err));
    } else if (err != GNUTLS_E_SUCCESS)
        throw CryptoException(std::string("Could not print public key: ") + gnutls_strerror(err));
    return ret;
}

void
PublicKey::msgpack_unpack(msgpack::object o)
{
    if (o.type == msgpack::type::BIN)
        unpack((const uint8_t*)o.via.bin.ptr, o.via.bin.size);
    else {
        Blob dat = unpackBlob(o);
        unpack(dat.data(), dat.size());
    }
}

bool
PublicKey::checkSignature(const Blob& data, const Blob& signature) const
{
    if (!pk)
        return false;
    const gnutls_datum_t sig {(uint8_t*)signature.data(), (unsigned)signature.size()};
    const gnutls_datum_t dat {(uint8_t*)data.data(), (unsigned)data.size()};
    int rc = gnutls_pubkey_verify_data2(pk, GNUTLS_SIGN_RSA_SHA512, 0, &dat, &sig);
    return rc >= 0;
}

void
PublicKey::encryptBloc(const uint8_t* src, size_t src_size, uint8_t* dst, size_t dst_size) const
{
    const gnutls_datum_t key_dat {(uint8_t*)src, (unsigned)src_size};
    gnutls_datum_t encrypted;
    auto err = gnutls_pubkey_encrypt_data(pk, 0, &key_dat, &encrypted);
    if (err != GNUTLS_E_SUCCESS)
        throw CryptoException(std::string("Can't encrypt data: ") + gnutls_strerror(err));
    if (encrypted.size != dst_size)
        throw CryptoException("Unexpected cypherblock size");
    std::copy_n(encrypted.data, encrypted.size, dst);
    gnutls_free(encrypted.data);
}

Blob
PublicKey::encrypt(const Blob& data) const
{
    if (!pk)
        throw CryptoException("Can't read public key !");

    unsigned key_len = 0;
    int err = gnutls_pubkey_get_pk_algorithm(pk, &key_len);
    if (err < 0)
        throw CryptoException("Can't read public key length !");
    if (err != GNUTLS_PK_RSA)
        throw CryptoException("Must be an RSA key");

    const unsigned max_block_sz = key_len / 8 - 11;
    const unsigned cypher_block_sz = key_len / 8;

    /* Use plain RSA if the data is small enough */
    if (data.size() <= max_block_sz) {
        Blob ret(cypher_block_sz);
        encryptBloc(data.data(), data.size(), ret.data(), cypher_block_sz);
        return ret;
    }

    /* Otherwise use RSA+AES-GCM,
       using the max. AES key size that can fit
       in a single RSA packet () */
    unsigned aes_key_sz = aesKeySize(max_block_sz);
    if (aes_key_sz == 0)
        throw CryptoException("Key is not long enough for AES128");
    Blob key(aes_key_sz);
    {
        crypto::random_device rdev;
        std::generate_n(key.begin(), key.size(), std::bind(rand_byte, std::ref(rdev)));
    }
    auto data_encrypted = aesEncrypt(data, key);

    Blob ret;
    ret.reserve(cypher_block_sz + data_encrypted.size());

    ret.resize(cypher_block_sz);
    encryptBloc(key.data(), key.size(), ret.data(), cypher_block_sz);
    ret.insert(ret.end(), data_encrypted.begin(), data_encrypted.end());
    return ret;
}

InfoHash
PublicKey::getId() const
{
    InfoHash id;
    size_t sz = id.size();
    if (gnutls_pubkey_get_key_id(pk, 0, id.data(), &sz) != GNUTLS_E_SUCCESS || sz != id.size())
        return {};
    return id;
}

#if GNUTLS_VERSION_NUMBER >= 0x030401
PkId
PublicKey::getLongId() const
{
    PkId h;
    size_t sz = h.size();
    if (gnutls_pubkey_get_key_id(pk, GNUTLS_KEYID_USE_SHA256, h.data(), &sz) != GNUTLS_E_SUCCESS || sz != h.size())
        return {};
    return h;
}
#endif

Certificate::Certificate(const Blob& certData) : cert(nullptr)
{
    unpack(certData.data(), certData.size());
}

Certificate&
Certificate::operator=(Certificate&& o) noexcept
{
    if (cert)
        gnutls_x509_crt_deinit(cert);
    cert = o.cert;
    o.cert = nullptr;
    issuer = std::move(o.issuer);
    return *this;
}

void
Certificate::unpack(const uint8_t* dat, size_t dat_size)
{
    if (cert) {
        gnutls_x509_crt_deinit(cert);
        cert = nullptr;
    }
    gnutls_x509_crt_t* cert_list;
    unsigned cert_num;
    const gnutls_datum_t crt_dt {(uint8_t*)dat, (unsigned)dat_size};
    int err = gnutls_x509_crt_list_import2(&cert_list, &cert_num, &crt_dt, GNUTLS_X509_FMT_PEM, GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED);
    if (err != GNUTLS_E_SUCCESS)
        err = gnutls_x509_crt_list_import2(&cert_list, &cert_num, &crt_dt, GNUTLS_X509_FMT_DER, GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED);
    if (err != GNUTLS_E_SUCCESS || cert_num == 0) {
        cert = nullptr;
        throw CryptoException(std::string("Could not read certificate - ") + gnutls_strerror(err));
    }

    cert = cert_list[0];
    Certificate* crt = this;
    size_t i = 1;
    while (crt and i < cert_num) {
        crt->issuer = std::make_shared<Certificate>(cert_list[i++]);
        crt = crt->issuer.get();
    }
    gnutls_free(cert_list);
}

void
Certificate::msgpack_unpack(msgpack::object o)
{
    if (o.type == msgpack::type::BIN)
        unpack((const uint8_t*)o.via.bin.ptr, o.via.bin.size);
    else {
        Blob dat = unpackBlob(o);
        unpack(dat.data(), dat.size());
    }
}

void
Certificate::pack(Blob& b) const
{
    const Certificate* crt = this;
    while (crt) {
        std::string str;
        size_t buf_sz = 8192;
        str.resize(buf_sz);
        if (int err = gnutls_x509_crt_export(crt->cert, GNUTLS_X509_FMT_PEM, &(*str.begin()), &buf_sz)) {
            std::cerr << "Could not export certificate - " << gnutls_strerror(err) << std::endl;
            return;
        }
        str.resize(buf_sz);
        b.insert(b.end(), str.begin(), str.end());
        crt = crt->issuer.get();
    }
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

InfoHash
Certificate::getId() const
{
    if (not cert)
        return {};
    InfoHash id;
    size_t sz = id.size();
    if (gnutls_x509_crt_get_key_id(cert, 0, id.data(), &sz) != GNUTLS_E_SUCCESS || sz != id.size())
        throw CryptoException("Can't get certificate public key ID.");
    return id;
}

#if GNUTLS_VERSION_NUMBER >= 0x030401
PkId
Certificate::getLongId() const
{
    if (not cert)
        return {};
    PkId id;
    size_t sz = id.size();
    if (gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA256, id.data(), &sz) != GNUTLS_E_SUCCESS || sz != id.size())
        throw CryptoException("Can't get certificate public key ID.");
    return id;
}
#endif

static std::string
getDN(gnutls_x509_crt_t cert, const char* oid, bool issuer = false)
{
    std::string dn;
    dn.resize(512);
    size_t dn_sz = dn.size();
    int ret = issuer
            ? gnutls_x509_crt_get_issuer_dn_by_oid(cert, oid, 0, 0, &(*dn.begin()), &dn_sz)
            : gnutls_x509_crt_get_dn_by_oid(       cert, oid, 0, 0, &(*dn.begin()), &dn_sz);
    if (ret != GNUTLS_E_SUCCESS)
        return {};
    dn.resize(dn_sz);
    return dn;
}

std::string
Certificate::getName() const
{
    return getDN(cert, GNUTLS_OID_X520_COMMON_NAME);
}

std::string
Certificate::getUID() const
{
    return getDN(cert, GNUTLS_OID_LDAP_UID);
}

std::string
Certificate::getIssuerName() const
{
    return getDN(cert, GNUTLS_OID_X520_COMMON_NAME, true);
}

std::string
Certificate::getIssuerUID() const
{
    return getDN(cert, GNUTLS_OID_LDAP_UID, true);
}

static Certificate::NameType
typeFromGnuTLS(gnutls_x509_subject_alt_name_t type)
{
    switch(type) {
    case GNUTLS_SAN_DNSNAME:
        return Certificate::NameType::DNS;
    case GNUTLS_SAN_RFC822NAME:
        return Certificate::NameType::RFC822;
    case GNUTLS_SAN_URI:
        return Certificate::NameType::URI;
    case GNUTLS_SAN_IPADDRESS:
        return Certificate::NameType::IP;
    default:
        return Certificate::NameType::UNKNOWN;
    }
}

std::vector<std::pair<Certificate::NameType, std::string>>
Certificate::getAltNames() const
{
    std::vector<std::pair<NameType, std::string>> names;
    unsigned i = 0;
    std::string name;
    while (true) {
        name.resize(512);
        size_t name_sz = name.size();
        unsigned type;
        int ret = gnutls_x509_crt_get_subject_alt_name2(cert, i++, &(*name.begin()), &name_sz, &type, nullptr);
        if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
            break;
        name.resize(name_sz);
        names.emplace_back(typeFromGnuTLS((gnutls_x509_subject_alt_name_t)type), name);
    }
    return names;
}

bool
Certificate::isCA() const
{
    unsigned critical;
    bool ca_flag = gnutls_x509_crt_get_ca_status(cert, &critical) > 0;
    if (ca_flag) {
        unsigned usage;
        auto ret = gnutls_x509_crt_get_key_usage(cert, &usage, &critical);
        /* Conforming CAs MUST include this extension in certificates that
           contain public keys that are used to validate digital signatures on
           other public key certificates or CRLs. */
        if (ret < 0)
            return false;
        if (not critical)
            return true;
        return usage & GNUTLS_KEY_KEY_CERT_SIGN;
    }
    return false;
}

std::string
Certificate::toString(bool chain) const
{
    std::ostringstream ss;
    const Certificate* crt = this;
    while (crt) {
        std::string str;
        size_t buf_sz = 8192;
        str.resize(buf_sz);
        if (int err = gnutls_x509_crt_export(crt->cert, GNUTLS_X509_FMT_PEM, &(*str.begin()), &buf_sz)) {
            std::cerr << "Could not export certificate - " << gnutls_strerror(err) << std::endl;
            return {};
        }
        str.resize(buf_sz);
        ss << str;
        if (not chain)
            break;
        crt = crt->issuer.get();
    }
    return ss.str();
}

std::string
Certificate::print() const
{
    gnutls_datum_t out;
    gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_FULL, &out);
    std::string ret(out.data, out.data+out.size);
    gnutls_free(out.data);
    return ret;
}

void
Certificate::revoke(const PrivateKey& key, const Certificate& to_revoke)
{
    if (revocation_lists.empty())
        revocation_lists.emplace(std::make_shared<RevocationList>());
    auto& list = *(*revocation_lists.begin());
    list.revoke(to_revoke);
    list.sign(key, *this);
}

void
Certificate::addRevocationList(RevocationList&& list)
{
    addRevocationList(std::make_shared<RevocationList>(std::forward<RevocationList>(list)));
}

void
Certificate::addRevocationList(std::shared_ptr<RevocationList> list)
{
    if (revocation_lists.find(list) != revocation_lists.end())
        return; // Already in the list
    if (not list->isSignedBy(*this))
        throw CryptoException("CRL is not signed by this certificate");
    revocation_lists.emplace(std::move(list));
}

std::chrono::system_clock::time_point
Certificate::getExpiration() const
{
    auto t = gnutls_x509_crt_get_expiration_time(cert);
    if (t == (time_t)-1)
        return std::chrono::system_clock::time_point::min();
    return std::chrono::system_clock::from_time_t(t);
}

PrivateKey
PrivateKey::generate(unsigned key_length)
{
    gnutls_x509_privkey_t key;
    if (gnutls_x509_privkey_init(&key) != GNUTLS_E_SUCCESS)
        throw CryptoException("Can't initialize private key.");
    int err = gnutls_x509_privkey_generate(key, GNUTLS_PK_RSA, key_length, 0);
    if (err != GNUTLS_E_SUCCESS) {
        gnutls_x509_privkey_deinit(key);
        throw CryptoException(std::string("Can't generate RSA key pair: ") + gnutls_strerror(err));
    }
    return PrivateKey{key};
}

PrivateKey
PrivateKey::generateEC()
{
    gnutls_x509_privkey_t key;
    if (gnutls_x509_privkey_init(&key) != GNUTLS_E_SUCCESS)
        throw CryptoException("Can't initialize private key.");
    int err = gnutls_x509_privkey_generate(key, GNUTLS_PK_EC, gnutls_sec_param_to_pk_bits(GNUTLS_PK_EC, GNUTLS_SEC_PARAM_ULTRA), 0);
    if (err != GNUTLS_E_SUCCESS) {
        gnutls_x509_privkey_deinit(key);
        throw CryptoException(std::string("Can't generate EC key pair: ") + gnutls_strerror(err));
    }
    return PrivateKey{key};
}

Identity
generateIdentity(const std::string& name, crypto::Identity ca, unsigned key_length, bool is_ca)
{
    auto key = std::make_shared<PrivateKey>(PrivateKey::generate(key_length));
    auto cert = std::make_shared<Certificate>(Certificate::generate(*key, name, ca, is_ca));
    return {std::move(key), std::move(cert)};
}


Identity
generateIdentity(const std::string& name, Identity ca, unsigned key_length) {
    return generateIdentity(name, ca, key_length, !ca.first || !ca.second);
}

Certificate
Certificate::generate(const PrivateKey& key, const std::string& name, Identity ca, bool is_ca)
{
    gnutls_x509_crt_t cert;
    if (not key.x509_key or gnutls_x509_crt_init(&cert) != GNUTLS_E_SUCCESS)
        return {};
    Certificate ret {cert};

    gnutls_x509_crt_set_activation_time(cert, time(NULL));
    gnutls_x509_crt_set_expiration_time(cert, time(NULL) + (20 * 365 * 24 * 60 * 60));
    if (gnutls_x509_crt_set_key(cert, key.x509_key) != GNUTLS_E_SUCCESS) {
        std::cerr << "Error when setting certificate key" << std::endl;
        return {};
    }
    if (gnutls_x509_crt_set_version(cert, 3) != GNUTLS_E_SUCCESS) {
        std::cerr << "Error when setting certificate version" << std::endl;
        return {};
    }

    // TODO: compute the subject key using the recommended RFC method
    auto pk_id = key.getPublicKey().getId();
    const std::string uid_str = pk_id.toString();

    gnutls_x509_crt_set_subject_key_id(cert, &pk_id, sizeof(pk_id));
    gnutls_x509_crt_set_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 0, name.data(), name.length());
    gnutls_x509_crt_set_dn_by_oid(cert, GNUTLS_OID_LDAP_UID, 0, uid_str.data(), uid_str.length());

    {
        random_device rdev;
        std::uniform_int_distribution<uint64_t> dist{};
        uint64_t cert_serial = dist(rdev);
        gnutls_x509_crt_set_serial(cert, &cert_serial, sizeof(cert_serial));
    }

    unsigned key_usage = GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_DATA_ENCIPHERMENT;
    if (is_ca) {
        gnutls_x509_crt_set_ca_status(cert, 1);
        key_usage |= GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN;
    }
    gnutls_x509_crt_set_key_usage(cert, key_usage);

    if (ca.first && ca.second) {
        if (not ca.second->isCA()) {
            // Signing certificate must be CA.
            return {};
        }
        //if (gnutls_x509_crt_sign2(cert, ca.second->cert, ca.first->x509_key, get_dig(cert), 0) != GNUTLS_E_SUCCESS) {
        if (gnutls_x509_crt_privkey_sign(cert, ca.second->cert, ca.first->key, get_dig(cert), 0) != GNUTLS_E_SUCCESS) {
            std::cerr << "Error when signing certificate" << std::endl;
            return {};
        }
        ret.issuer = ca.second;
    } else {
        //if (gnutls_x509_crt_sign2(cert, cert, key, get_dig(cert), 0) != GNUTLS_E_SUCCESS) {
        if (gnutls_x509_crt_privkey_sign(cert, cert, key.key, get_dig(cert), 0) != GNUTLS_E_SUCCESS) {
            std::cerr << "Error when signing certificate" << std::endl;
            return {};
        }
    }

    return ret.getPacked();
}

std::vector<std::shared_ptr<RevocationList>>
Certificate::getRevocationLists() const
{
    std::vector<std::shared_ptr<RevocationList>> ret;
    ret.reserve(revocation_lists.size());
    for (const auto& crl : revocation_lists)
        ret.emplace_back(crl);
    return ret;
}

RevocationList::RevocationList()
{
    gnutls_x509_crl_init(&crl);
}

RevocationList::RevocationList(const Blob& b)
{
    gnutls_x509_crl_init(&crl);
    try {
        unpack(b.data(), b.size());
    } catch (const std::exception& e) {
        gnutls_x509_crl_deinit(crl);
        crl = nullptr;
        throw e;
    }
}

RevocationList::~RevocationList()
{
    if (crl) {
        gnutls_x509_crl_deinit(crl);
        crl = nullptr;
    }
}

void
RevocationList::pack(Blob& b) const
{
    gnutls_datum_t gdat {nullptr, 0};
    if (auto err = gnutls_x509_crl_export2(crl, GNUTLS_X509_FMT_DER, &gdat)) {
        throw CryptoException(std::string("Can't export CRL: ") + gnutls_strerror(err));
    }
    b.insert(b.end(), gdat.data, gdat.data + gdat.size);
}

void
RevocationList::unpack(const uint8_t* dat, size_t dat_size)
{
    if (std::numeric_limits<unsigned>::max() < dat_size)
        throw CryptoException("Can't load CRL: too large!");
    const gnutls_datum_t gdat {(uint8_t*)dat, (unsigned)dat_size};
    if (auto err_pem = gnutls_x509_crl_import(crl, &gdat, GNUTLS_X509_FMT_PEM))
        if (auto err_der = gnutls_x509_crl_import(crl, &gdat, GNUTLS_X509_FMT_DER)) {
            throw CryptoException(std::string("Can't load CRL: PEM: ") + gnutls_strerror(err_pem)
                                                           + " DER: "  + gnutls_strerror(err_der));
        }
}

void
RevocationList::msgpack_unpack(msgpack::object o)
{
    try {
        if (o.type == msgpack::type::BIN)
            unpack((const uint8_t*)o.via.bin.ptr, o.via.bin.size);
        else {
            Blob dat = unpackBlob(o);
            unpack(dat.data(), dat.size());
        }
    } catch (...) {
        throw msgpack::type_error();
    }
}

bool
RevocationList::isRevoked(const Certificate& crt) const
{
    auto ret = gnutls_x509_crt_check_revocation(crt.cert, &crl, 1);
    if (ret < 0)
        throw CryptoException(std::string("Can't check certificate revocation status: ") + gnutls_strerror(ret));
    return ret != 0;
}

void
RevocationList::revoke(const Certificate& crt, std::chrono::system_clock::time_point t)
{
    if (t == time_point::min())
        t = clock::now();
    if (auto err = gnutls_x509_crl_set_crt(crl, crt.cert, std::chrono::system_clock::to_time_t(t)))
        throw CryptoException(std::string("Can't revoke certificate: ") + gnutls_strerror(err));
}

static std::string
getCRLIssuerDN(gnutls_x509_crl_t cert, const char* oid)
{
    std::string dn;
    dn.resize(512);
    size_t dn_sz = dn.size();
    int ret = gnutls_x509_crl_get_issuer_dn_by_oid(cert, oid, 0, 0, &(*dn.begin()), &dn_sz);
    if (ret != GNUTLS_E_SUCCESS)
        return {};
    dn.resize(dn_sz);
    return dn;
}

std::string
RevocationList::getIssuerName() const
{
    return getCRLIssuerDN(crl, GNUTLS_OID_X520_COMMON_NAME);
}

/** Read CRL issuer User ID (UID) */
std::string
RevocationList::getIssuerUID() const
{
    return getCRLIssuerDN(crl, GNUTLS_OID_LDAP_UID);
}

RevocationList::time_point
RevocationList::getNextUpdateTime() const
{
    auto t = gnutls_x509_crl_get_next_update(crl);
    if (t == (time_t)-1)
        return std::chrono::system_clock::time_point::min();
    return std::chrono::system_clock::from_time_t(t);
}

RevocationList::time_point
RevocationList::getUpdateTime() const
{
    auto t = gnutls_x509_crl_get_this_update(crl);
    if (t == (time_t)-1)
        return std::chrono::system_clock::time_point::min();
    return std::chrono::system_clock::from_time_t(t);
}

enum class Endian : uint32_t
{
    LITTLE = 0,
    BIG = 1
};

template <typename T>
T endian(T w, Endian endian = Endian::BIG)
{
    // this gets optimized out into if (endian == host_endian) return w;
    union { uint64_t quad; uint32_t islittle; } t;
    t.quad = 1;
    if (t.islittle ^ (uint32_t)endian) return w;
    T r = 0;

    // decent compilers will unroll this (gcc)
    // or even convert straight into single bswap (clang)
    for (size_t i = 0; i < sizeof(r); i++) {
        r <<= 8;
        r |= w & 0xff;
        w >>= 8;
    }
    return r;
}

void
RevocationList::sign(const PrivateKey& key, const Certificate& ca, duration validity)
{
    if (auto err = gnutls_x509_crl_set_version(crl, 2))
        throw CryptoException(std::string("Can't set CRL version: ") + gnutls_strerror(err));
    auto now = std::chrono::system_clock::now();
    auto next_update = (validity == duration{}) ? ca.getExpiration() : now + validity;
    if (auto err = gnutls_x509_crl_set_this_update(crl, std::chrono::system_clock::to_time_t(now)))
        throw CryptoException(std::string("Can't set CRL update time: ") + gnutls_strerror(err));
    if (auto err = gnutls_x509_crl_set_next_update(crl, std::chrono::system_clock::to_time_t(next_update)))
        throw CryptoException(std::string("Can't set CRL next update time: ") + gnutls_strerror(err));
    uint64_t number {0};
    size_t number_sz {sizeof(number)};
    unsigned critical {0};
    gnutls_x509_crl_get_number(crl, &number, &number_sz, &critical);
    if (number == 0) {
        // initialize to a random number
        number_sz = sizeof(number);
        random_device rdev;
        std::generate_n((uint8_t*)&number, sizeof(number), std::bind(rand_byte, std::ref(rdev)));
    } else
        number = endian(endian(number) + 1);
    if (auto err = gnutls_x509_crl_set_number(crl, &number, sizeof(number)))
        throw CryptoException(std::string("Can't set CRL update time: ") + gnutls_strerror(err));
    if (auto err = gnutls_x509_crl_sign2(crl, ca.cert, key.x509_key, GNUTLS_DIG_SHA512, 0))
        throw CryptoException(std::string("Can't sign certificate revocation list: ") + gnutls_strerror(err));
    // to be able to actually use the CRL we need to serialize/deserialize it
    auto packed = getPacked();
    unpack(packed.data(), packed.size());
}

bool
RevocationList::isSignedBy(const Certificate& issuer) const
{
    unsigned result {0};
    auto err = gnutls_x509_crl_verify(crl, &issuer.cert, 1, 0, &result);
    if (err < 0) {
        //std::cout << "Can't verify CRL: " << err << " " << result << " " << gnutls_strerror(err) << std::endl;
        return false;
    }
    return result == 0;
}


Blob
RevocationList::getNumber() const
{
    Blob number(20);
    size_t number_sz {number.size()};
    unsigned critical {0};
    gnutls_x509_crl_get_number(crl, number.data(), &number_sz, &critical);
    if (number_sz != number.size())
        number.resize(number_sz);
    return number;
}

std::string
RevocationList::toString() const
{
    gnutls_datum_t out;
    gnutls_x509_crl_print(crl, GNUTLS_CRT_PRINT_FULL, &out);
    std::string ret(out.data, out.data+out.size);
    gnutls_free(out.data);
    return ret;
}

}
}
