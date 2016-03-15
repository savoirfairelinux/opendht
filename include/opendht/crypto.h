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

#pragma once

#include "infohash.h"
#include "utils.h"

extern "C" {
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
}

#include <vector>
#include <memory>

#ifdef _WIN32
#include <iso646.h>
#endif

namespace dht {
namespace crypto {

class CryptoException : public std::runtime_error {
    public:
        CryptoException(const std::string& str) : std::runtime_error(str) {};
};

/**
 * Exception thrown when a decryption error happened.
 */
class DecryptError : public CryptoException {
    public:
        DecryptError(const std::string& str = "") : CryptoException(str) {};
};

struct PrivateKey;
struct Certificate;

using Identity = std::pair<std::shared_ptr<PrivateKey>, std::shared_ptr<Certificate>>;

/**
 * A public key.
 */
struct PublicKey
{
    PublicKey() {}

    /**
     * Takes ownership of an existing gnutls_pubkey.
     */
    PublicKey(gnutls_pubkey_t k) : pk(k) {}
    PublicKey(const Blob& pk);
    PublicKey(PublicKey&& o) noexcept : pk(o.pk) { o.pk = nullptr; };

    ~PublicKey();
    explicit operator bool() const { return pk; }
    bool operator ==(const PublicKey& o) const {
        return pk == o.pk || getId() == o.getId();
    }
    bool operator !=(const PublicKey& o) const {
        return !(*this == o);
    }

    PublicKey& operator=(PublicKey&& o) noexcept;

    InfoHash getId() const;
    bool checkSignature(const Blob& data, const Blob& signature) const;
    Blob encrypt(const Blob&) const;

    void pack(Blob& b) const;
    void unpack(const uint8_t* dat, size_t dat_size);

    template <typename Packer>
    void msgpack_pack(Packer& p) const
    {
        Blob b;
        pack(b);
        p.pack_bin(b.size());
        p.pack_bin_body((const char*)b.data(), b.size());
    }

    void msgpack_unpack(msgpack::object o);

    gnutls_pubkey_t pk {};
private:
    PublicKey(const PublicKey&) = delete;
    PublicKey& operator=(const PublicKey&) = delete;
    void encryptBloc(const uint8_t* src, size_t src_size, uint8_t* dst, size_t dst_size) const;
};

/**
 * A private key, including the corresponding public key.
 */
struct PrivateKey
{
    PrivateKey();
    //PrivateKey(gnutls_privkey_t k) : key(k) {}

    /**
     * Takes ownership of an existing gnutls_x509_privkey.
     */
    PrivateKey(gnutls_x509_privkey_t k);

    PrivateKey(PrivateKey&& o) noexcept;
    PrivateKey& operator=(PrivateKey&& o) noexcept;

    PrivateKey(const Blob& import, const std::string& password = {});
    ~PrivateKey();
    explicit operator bool() const { return key; }
    PublicKey getPublicKey() const;
    Blob serialize(const std::string& password = {}) const;

    /**
     * Sign the provided binary object.
     * @returns the signature data.
     */
    Blob sign(const Blob&) const;

    /**
     * Try to decrypt the provided cypher text.
     * In case of failure a CryptoException is thrown.
     * @returns the decrypted data.
     */
    Blob decrypt(const Blob& cypher) const;

    /**
     * Generate a new RSA key pair
     * @param key_length : size of the modulus in bits
     *      Minimim value: 2048
     *      Recommended values: 4096, 8192
     */
    static PrivateKey generate(unsigned key_length = 4096);

    gnutls_privkey_t key {};
    gnutls_x509_privkey_t x509_key {};
private:
    PrivateKey(const PrivateKey&) = delete;
    PrivateKey& operator=(const PrivateKey&) = delete;
    Blob decryptBloc(const uint8_t* src, size_t src_size) const;

    //friend dht::crypto::Identity dht::crypto::generateIdentity(const std::string&, dht::crypto::Identity, unsigned key_length);
};

struct Certificate {
    Certificate() {}

    /**
     * Take ownership of existing gnutls structure
     */
    Certificate(gnutls_x509_crt_t crt) : cert(crt) {}

    Certificate(Certificate&& o) noexcept : cert(o.cert), issuer(std::move(o.issuer)) { o.cert = nullptr; };

    /**
     * Import certificate (PEM or DER) or certificate chain (PEM),
     * ordered from subject to issuer
     */
    Certificate(const Blob& crt);
    Certificate(const uint8_t* dat, size_t dat_size) {
        unpack(dat, dat_size);
    }

    /**
     * Import certificate chain (PEM or DER),
     * ordered from subject to issuer
     */
    template<typename Iterator>
    Certificate(const Iterator& begin, const Iterator& end) {
        unpack(begin, end);
    }

    /**
     * Import certificate chain (PEM or DER),
     * ordered from subject to issuer
     */
    template<typename Iterator>
    Certificate(const std::vector<std::pair<Iterator, Iterator>>& certs) {
        unpack(certs);
    }

    Certificate& operator=(Certificate&& o) noexcept;
    ~Certificate();

    void pack(Blob& b) const;
    void unpack(const uint8_t* dat, size_t dat_size);
    Blob getPacked() const {
        Blob b;
        pack(b);
        return b;
    }

    /**
     * Import certificate chain (PEM or DER).
     * Certificates are not checked during import.
     *
     * Iterator is the type of an iterator or pointer to
     * gnutls_x509_crt_t or Blob instances to import, that should be
     * ordered from subject to issuer.
     */
    template<typename Iterator>
    void unpack(const Iterator& begin, const Iterator& end)
    {
        std::shared_ptr<Certificate> tmp_subject {};
        std::shared_ptr<Certificate> first {};
        for (Iterator icrt = begin; icrt < end; ++icrt) {
            auto tmp_crt = std::make_shared<Certificate>(*icrt);
            if (tmp_subject)
                tmp_subject->issuer = tmp_crt;
            tmp_subject = std::move(tmp_crt);
            if (!first)
                first = tmp_subject;
        }
        *this = first ? std::move(*first) : Certificate();
    }

    /**
     * Import certificate chain (PEM or DER).
     * Certificates are not checked during import.
     *
     * Iterator is the type of an iterator or pointer to the bytes of
     * the certificates to import.
     *
     * @param certs list of (begin, end) iterator pairs, pointing to the
     *              PEM or DER certificate data to import, that should be
     *              ordered from subject to issuer.
     */
    template<typename Iterator>
    void unpack(const std::vector<std::pair<Iterator, Iterator>>& certs)
    {
        std::shared_ptr<Certificate> tmp_issuer;
        // reverse iteration
        for (auto li = certs.rbegin(); li != certs.rend(); ++li) {
            Certificate tmp_crt;
            gnutls_x509_crt_init(&tmp_crt.cert);
            const gnutls_datum_t crt_dt {(uint8_t*)&(*li->first), (unsigned)(li->second-li->first)};
            int err = gnutls_x509_crt_import(tmp_crt.cert, &crt_dt, GNUTLS_X509_FMT_PEM);
            if (err != GNUTLS_E_SUCCESS)
                err = gnutls_x509_crt_import(tmp_crt.cert, &crt_dt, GNUTLS_X509_FMT_DER);
            if (err != GNUTLS_E_SUCCESS)
                throw CryptoException(std::string("Could not read certificate - ") + gnutls_strerror(err));
            tmp_crt.issuer = tmp_issuer;
            tmp_issuer = std::make_shared<Certificate>(std::move(tmp_crt));
        }
        *this = tmp_issuer ? std::move(*tmp_issuer) : Certificate();
    }

    template <typename Packer>
    void msgpack_pack(Packer& p) const
    {
        Blob b;
        pack(b);
        p.pack_bin(b.size());
        p.pack_bin_body((const char*)b.data(), b.size());
    }

    void msgpack_unpack(msgpack::object o);

    explicit operator bool() const { return cert; }
    PublicKey getPublicKey() const;

    /** Same as getPublicKey().getId() */
    InfoHash getId() const;

    /** Read certificate Common Name (CN) */
    std::string getName() const;

    /** Read certificate User ID (UID) */
    std::string getUID() const;

    /** Read certificate issuer Common Name (CN) */
    std::string getIssuerName() const;

    /** Read certificate issuer User ID (UID) */
    std::string getIssuerUID() const;

    enum class NameType { UNKNOWN = 0, RFC822, DNS, URI, IP };

    /** Read certificate alternative names */
    std::vector<std::pair<NameType, std::string>> getAltNames() const;

    /**
     * Returns true if the certificate is marked as a Certificate Authority.
     */
    bool isCA() const;

    /**
     * PEM encoded certificate.
     * If chain is true, the issuer chain will be included (default).
     */
    std::string toString(bool chain = true) const;

    static Certificate generate(const PrivateKey& key, const std::string& name = "dhtnode", Identity ca = {}, bool is_ca = false);

    gnutls_x509_crt_t cert {};
    std::shared_ptr<Certificate> issuer {};
private:
    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;
};


/**
 * Generate an RSA key pair (4096 bits) and a certificate.
 * @param name the name used in the generated certificate
 * @param ca if set, the certificate authority that will sign the generated certificate.
 *           If not set, the generated certificate will be a self-signed CA.
 * @param key_length stength of the generated private key (bits).
 */
Identity generateIdentity(const std::string& name, Identity ca, unsigned key_length, bool is_ca);
Identity generateIdentity(const std::string& name = "dhtnode", Identity ca = {}, unsigned key_length = 4096);


/**
 * SHA512
 */
Blob hash(const Blob& data);

/**
 * Generates an encryption key from a text password,
 * making the key longer to bruteforce.
 * The generated key also depends on a unique salt value of any size,
 * that can be transmitted in clear, and will be generated if
 * not provided (32 bytes).
 */
Blob stretchKey(const std::string& password, Blob& salt);

/**
 * AES-GCM encryption. Key must be 128, 192 or 256 bits long (16, 24 or 32 bytes).
 */
Blob aesEncrypt(const Blob& data, const Blob& key);
Blob aesEncrypt(const Blob& data, const std::string& password);

/**
 * AES-GCM decryption.
 */
Blob aesDecrypt(const Blob& data, const Blob& key);
Blob aesDecrypt(const Blob& data, const std::string& password);

}
}
