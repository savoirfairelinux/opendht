/*
 *  Copyright (C) 2014-2025 Savoir-faire Linux Inc.
 *  Author : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *           Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
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

#include "infohash.h"
#include "utils.h"
#include "rng.h"

extern "C" {
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <gnutls/ocsp.h>
}

#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <string_view>

#ifdef _WIN32
#include <iso646.h>
#endif

namespace dht {

/**
 * Contains all crypto primitives
 */
namespace crypto {

class OPENDHT_PUBLIC CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& str) : std::runtime_error(str) {};
    explicit CryptoException(const char* str) : std::runtime_error(str) {};
    CryptoException(const CryptoException& e) noexcept = default;
    CryptoException& operator=(const CryptoException&) noexcept = default;
};

/**
 * Exception thrown when a decryption error happened.
 */
class OPENDHT_PUBLIC DecryptError : public CryptoException {
public:
    explicit DecryptError(const std::string& str) : CryptoException(str) {};
    explicit DecryptError(const char* str) : CryptoException(str) {};
    DecryptError(const DecryptError& e) noexcept = default;
    DecryptError& operator=(const DecryptError&) noexcept = default;
};

struct PrivateKey;
struct Certificate;
class RevocationList;

using Identity = std::pair<std::shared_ptr<PrivateKey>, std::shared_ptr<Certificate>>;

/**
 * A public key.
 */
struct OPENDHT_PUBLIC PublicKey
{
    PublicKey();

    /**
     * Takes ownership of an existing gnutls_pubkey.
     */
    PublicKey(gnutls_pubkey_t k) : pk(k) {}

    /** Import public key from serialized data */
    PublicKey(const uint8_t* dat, size_t dat_size);
    PublicKey(const Blob& pk) : PublicKey(pk.data(), pk.size()) {}
    PublicKey(std::string_view pk) : PublicKey((const uint8_t*)pk.data(), pk.size()) {}
    PublicKey(PublicKey&& o) noexcept : pk(o.pk) { o.pk = nullptr; }

    ~PublicKey();
    explicit operator bool() const { return pk; }
    bool operator ==(const PublicKey& o) const {
        return pk == o.pk || getLongId() == o.getLongId();
    }
    bool operator !=(const PublicKey& o) const {
        return !(*this == o);
    }

    PublicKey& operator=(PublicKey&& o) noexcept;

    /**
     * Get public key fingerprint
     */
   const InfoHash& getId() const;

    /**
     * Get public key long fingerprint
     */
    const PkId& getLongId() const;

    bool checkSignature(const uint8_t* data, size_t data_len, const uint8_t* signature, size_t signature_len) const;
    inline bool checkSignature(const Blob& data, const Blob& signature) const {
        return checkSignature(data.data(), data.size(), signature.data(), signature.size());
    }

    Blob encrypt(const uint8_t* data, size_t data_len) const;
    inline Blob encrypt(const Blob& data) const {
        return encrypt(data.data(), data.size());
    }
    inline Blob encrypt(std::string_view data) const {
        return encrypt((const uint8_t*)data.data(), data.size());
    }
    void pack(Blob& b) const;
    int pack(uint8_t* out, size_t* out_len) const;
    void unpack(const uint8_t* dat, size_t dat_size);

    std::string toString() const;

    template <typename Packer>
    void msgpack_pack(Packer& p) const
    {
        Blob b;
        pack(b);
        p.pack_bin(b.size());
        p.pack_bin_body((const char*)b.data(), b.size());
    }

    void msgpack_unpack(const msgpack::object& o);

    gnutls_digest_algorithm_t getPreferredDigest() const;

    gnutls_pubkey_t pk {nullptr};
private:
    mutable InfoHash cachedId_ {};
    mutable PkId cachedLongId_ {};
    mutable std::atomic_bool idCached_ {false};
    mutable std::atomic_bool longIdCached_ {false};

    PublicKey(const PublicKey&) = delete;
    PublicKey& operator=(const PublicKey&) = delete;
    void encryptBloc(const uint8_t* src, size_t src_size, uint8_t* dst, size_t dst_size) const;
};

/**
 * A private key, including the corresponding public key.
 */
struct OPENDHT_PUBLIC PrivateKey
{
    PrivateKey();
    //PrivateKey(gnutls_privkey_t k) : key(k) {}

    /**
     * Takes ownership of an existing gnutls_x509_privkey.
     */
    PrivateKey(gnutls_x509_privkey_t k);

    PrivateKey(PrivateKey&& o) noexcept;
    PrivateKey& operator=(PrivateKey&& o) noexcept;

    PrivateKey(const uint8_t* src, size_t src_size, const char* password = nullptr);
    PrivateKey(const Blob& src, const std::string& password = {}) : PrivateKey(src.data(), src.size(), password.c_str()) {}
    PrivateKey(std::string_view src, const std::string& password = {}) : PrivateKey((const uint8_t*)src.data(), src.size(), password.c_str()) {}

    ~PrivateKey();
    explicit operator bool() const { return key; }

    const PublicKey& getPublicKey() const;
    const std::shared_ptr<PublicKey>& getSharedPublicKey() const;

    int serialize(uint8_t* out, size_t* out_len, const std::string& password = {}) const;
    Blob serialize(const std::string& password = {}) const;

    /**
     * Sign the provided binary object.
     * @returns the signature data.
     */
    Blob sign(const uint8_t* data, size_t data_len) const;
    inline Blob sign(std::string_view dat) const { return sign((const uint8_t*)dat.data(), dat.size()); }
    inline Blob sign(const Blob& dat) const { return sign(dat.data(), dat.size()); }

    /**
     * Try to decrypt the provided cypher text.
     * In case of failure a CryptoException is thrown.
     * @returns the decrypted data.
     */
    Blob decrypt(const uint8_t* cypher, size_t cypher_len) const;
    Blob decrypt(const Blob& cypher) const { return decrypt(cypher.data(), cypher.size()); }

    /**
     * Generate a new RSA key pair
     * @param key_length : size of the modulus in bits
     *      Minimim value: 2048
     *      Recommended values: 4096, 8192
     */
    static PrivateKey generate(unsigned key_length = 4096);
    static PrivateKey generateEC();

    gnutls_privkey_t key {};
    gnutls_x509_privkey_t x509_key {};
private:
    PrivateKey(const PrivateKey&) = delete;
    PrivateKey& operator=(const PrivateKey&) = delete;
    Blob decryptBloc(const uint8_t* src, size_t src_size) const;

    mutable std::mutex publicKeyMutex_ {};
    mutable std::shared_ptr<PublicKey> publicKey_ {};
};

class OPENDHT_PUBLIC RevocationList
{
    using clock = std::chrono::system_clock;
    using time_point = clock::time_point;
    using duration = clock::duration;
public:
    RevocationList();
    RevocationList(const Blob& b);
    RevocationList(RevocationList&& o) noexcept : crl(o.crl) { o.crl = nullptr; }
    ~RevocationList();

    RevocationList& operator=(RevocationList&& o) { crl = o.crl; o.crl = nullptr; return *this; }

    void pack(Blob& b) const;
    void unpack(const uint8_t* dat, size_t dat_size);
    Blob getPacked() const {
        Blob b;
        pack(b);
        return b;
    }

    template <typename Packer>
    void msgpack_pack(Packer& p) const
    {
        Blob b = getPacked();
        p.pack_bin(b.size());
        p.pack_bin_body((const char*)b.data(), b.size());
    }

    void msgpack_unpack(const msgpack::object& o);

    void revoke(const Certificate& crt, time_point t = time_point::min());

    bool isRevoked(const Certificate& crt) const;

    /**
     * Sign this revocation list using provided key and certificate.
     * Validity_period sets the duration until next update (default to no next update).
     */
    void sign(const PrivateKey&, const Certificate&, duration validity_period = {});
    void sign(const Identity& id) { sign(*id.first, *id.second); }

    bool isSignedBy(const Certificate& issuer) const;

    std::string toString() const;

    /**
     * Read the CRL number extension field.
     */
    Blob getNumber() const;

    /** Read CRL issuer Common Name (CN) */
    std::string getIssuerName() const;

    /** Read CRL issuer User ID (UID) */
    std::string getIssuerUID() const;

    time_point getUpdateTime() const;
    time_point getNextUpdateTime() const;

    gnutls_x509_crl_t get() { return crl; }
    gnutls_x509_crl_t getCopy() const {
        if (not crl)
            return nullptr;
        auto copy = RevocationList(getPacked());
        gnutls_x509_crl_t ret = copy.crl;
        copy.crl = nullptr;
        return ret;
    }

private:
    gnutls_x509_crl_t crl {};
    RevocationList(const RevocationList&) = delete;
    RevocationList& operator=(const RevocationList&) = delete;
};

enum class NameType { UNKNOWN = 0, RFC822, DNS, URI, IP };

class OPENDHT_PUBLIC CertificateRequest {
public:
    CertificateRequest();
    CertificateRequest(const uint8_t* data, size_t size);
    CertificateRequest(std::string_view src) : CertificateRequest((const uint8_t*)src.data(), src.size()) {}
    CertificateRequest(const Blob& data) : CertificateRequest(data.data(), data.size()) {}

    CertificateRequest(CertificateRequest&& o) noexcept : request(std::move(o.request)) {
        o.request = nullptr;
    }
    CertificateRequest& operator=(CertificateRequest&& o) noexcept;

    ~CertificateRequest();

    void setName(const std::string& name);
    void setUID(const std::string& name);
    void setAltName(NameType type, const std::string& name);

    std::string getName() const;
    std::string getUID() const;

    void sign(const PrivateKey& key, const std::string& password = {});

    bool verify() const;

    Blob pack() const;
    std::string toString() const;

    gnutls_x509_crq_t get() const { return request; }
private:
    CertificateRequest(const CertificateRequest& o) = delete;
    CertificateRequest& operator=(const CertificateRequest& o) = delete;
    gnutls_x509_crq_t request {nullptr};
};

class OPENDHT_PUBLIC OcspRequest
{
public:
    OcspRequest(gnutls_ocsp_req_t r) : request(r) {}
    OcspRequest(const uint8_t* dat_ptr, size_t dat_size);
    OcspRequest(std::string_view dat): OcspRequest((const uint8_t*)dat.data(), dat.size()) {}
    ~OcspRequest();

    /*
     * Get OCSP Request in readable format.
     */
    std::string toString(const bool compact = true) const;

    Blob pack() const;
    Blob getNonce() const;
private:
    gnutls_ocsp_req_t request;
};

class OPENDHT_PUBLIC OcspResponse
{
public:
    OcspResponse(const uint8_t* dat_ptr, size_t dat_size);
    OcspResponse(std::string_view response) : OcspResponse((const uint8_t*)response.data(), response.size()) {}
    ~OcspResponse();

    Blob pack() const;
    /*
     * Get OCSP Response in readable format.
     */
    std::string toString(const bool compact = true) const;

    /*
     * Get OCSP response certificate status.
     * Return certificate status.
     * http://www.gnu.org/software/gnutls/reference/gnutls-ocsp.html#gnutls-ocsp-cert-status-t
     */
    gnutls_ocsp_cert_status_t getCertificateStatus() const;

    /*
     * Verify OCSP response and return OCSP status.
     * Throws CryptoException in case of error in the response.
     * http://www.gnu.org/software/gnutls/reference/gnutls-ocsp.html#gnutls-ocsp-verify-reason-t
     */
    gnutls_ocsp_cert_status_t verifyDirect(const Certificate& crt, const Blob& nonce);

private:
    gnutls_ocsp_resp_t response;
};

struct OPENDHT_PUBLIC Certificate {
    Certificate() noexcept {}

    /**
     * Take ownership of existing gnutls structure
     */
    Certificate(gnutls_x509_crt_t crt) noexcept : cert(crt) {}

    Certificate(Certificate&& o) noexcept
        : cert(o.cert)
        , issuer(std::move(o.issuer))
        , publicKey_(std::move(o.publicKey_))
        { o.cert = nullptr; };

    /**
     * Import certificate (PEM or DER) or certificate chain (PEM),
     * ordered from subject to issuer
     */
    Certificate(const Blob& crt);
    Certificate(const uint8_t* dat, size_t dat_size) : cert(nullptr) {
        unpack(dat, dat_size);
    }
    Certificate(std::string_view pem) : Certificate((const uint8_t*)pem.data(), pem.size()) {}

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

    void msgpack_unpack(const msgpack::object& o);

    explicit operator bool() const { return cert; }
    const PublicKey& getPublicKey() const;
    const std::shared_ptr<PublicKey>& getSharedPublicKey() const;

    /** Same as getPublicKey().getId() */
    const InfoHash& getId() const;
    /** Same as getPublicKey().getLongId() */
    const PkId& getLongId() const;

    Blob getSerialNumber() const;

    /** Read certificate full DN as described in RFC4514 */ 
    std::string getDN() const;

    /** Read certificate Common Name (CN) */
    std::string getName() const;

    /** Read certificate User ID (UID) */
    std::string getUID() const;

    /** Read certificate issuer DN as described in RFC4514 */
    std::string getIssuerDN() const;

    /** Read certificate issuer Common Name (CN) */
    std::string getIssuerName() const;

    /** Read certificate issuer User ID (UID) */
    std::string getIssuerUID() const;

    /** Read certificate alternative names */
    std::vector<std::pair<NameType, std::string>> getAltNames() const;

    std::chrono::system_clock::time_point getActivation() const;
    std::chrono::system_clock::time_point getExpiration() const;

    /**
     * Returns true if the certificate is marked as a Certificate Authority
     * and has necessary key usage flags to sign certificates.
     */
    bool isCA() const;

    /**
     * PEM encoded certificate.
     * If chain is true, the issuer chain will be included (default).
     */
    std::string toString(bool chain = true) const;

    std::string print() const;

    /**
     * As a CA, revoke a certificate, adding it to
     * the attached Certificate Revocation List (CRL)
     */
    void revoke(const PrivateKey&, const Certificate&);

    /**
     * Get the list of certificates revoked as as CA.
     */
    std::vector<std::shared_ptr<RevocationList>> getRevocationLists() const;

    /**
     * Attach existing revocation list.
     */
    void addRevocationList(RevocationList&&);
    void addRevocationList(std::shared_ptr<RevocationList>);

    static Certificate generate(const PrivateKey& key, const std::string& name = "dhtnode", const Identity& ca = {}, bool is_ca = false, int64_t validity = 0);
    static Certificate generate(const CertificateRequest& request, const Identity& ca, int64_t validity = 0);

    gnutls_x509_crt_t getCopy() const {
        if (not cert)
            return nullptr;
        auto copy = Certificate(getPacked());
        gnutls_x509_crt_t ret = copy.cert;
        copy.cert = nullptr;
        return ret;
    }

    std::vector<gnutls_x509_crt_t>
    getChain(bool copy = false) const
    {
        if (not cert)
            return {};
        std::vector<gnutls_x509_crt_t> crts;
        for (auto c = this; c; c = c->issuer.get())
            crts.emplace_back(copy ? c->getCopy() : c->cert);
        return crts;
    }

    std::pair<
        std::vector<gnutls_x509_crt_t>,
        std::vector<gnutls_x509_crl_t>
    >
    getChainWithRevocations(bool copy = false) const
    {
        if (not cert)
            return {};
        std::vector<gnutls_x509_crt_t> crts;
        std::vector<gnutls_x509_crl_t> crls;
        for (auto c = this; c; c = c->issuer.get()) {
            crts.emplace_back(copy ? c->getCopy() : c->cert);
            crls.reserve(crls.size() + c->revocation_lists.size());
            for (const auto& crl : c->revocation_lists)
                crls.emplace_back(copy ? crl->getCopy() : crl->get());
        }
        return {crts, crls};
    }

    gnutls_digest_algorithm_t getPreferredDigest() const;

    /*
     * Generate OCSP request.
     * Return GnuTLS error code.
     * https://www.gnutls.org/manual/html_node/Error-codes.html
     */
    std::pair<std::string, Blob> generateOcspRequest(gnutls_x509_crt_t& issuer);

    /**
     * Change certificate's expiration
     */
    void setValidity(const Identity& ca, int64_t validity);
    void setValidity(const PrivateKey& key, int64_t validity);

    gnutls_x509_crt_t cert {nullptr};
    std::shared_ptr<Certificate> issuer {};
    std::shared_ptr<OcspResponse> ocspResponse;
private:
    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;
    mutable InfoHash cachedId_ {};
    mutable PkId cachedLongId_ {};
    mutable std::atomic_bool idCached_ {false};
    mutable std::atomic_bool longIdCached_ {false};

    struct crlNumberCmp {
        bool operator() (const std::shared_ptr<RevocationList>& lhs, const std::shared_ptr<RevocationList>& rhs) const {
            return lhs->getNumber() < rhs->getNumber();
        }
    };

    std::set<std::shared_ptr<RevocationList>, crlNumberCmp> revocation_lists;

    mutable std::mutex publicKeyMutex_ {};
    mutable std::shared_ptr<PublicKey> publicKey_ {};
};

struct OPENDHT_PUBLIC TrustList
{
    struct VerifyResult {
        int ret;
        unsigned result;
        bool hasError() const { return ret < 0; }
        bool isValid() const { return !hasError() and !(result & GNUTLS_CERT_INVALID); }
        explicit operator bool() const { return isValid(); }
        OPENDHT_PUBLIC std::string toString() const;
        OPENDHT_PUBLIC friend std::ostream& operator<< (std::ostream& s, const VerifyResult& h);
    };

    TrustList();
    TrustList(TrustList&& o) noexcept : trust(std::move(o.trust)) {
        o.trust = nullptr;
    }
    TrustList& operator=(TrustList&& o) noexcept;
    ~TrustList();
    void add(const Certificate& crt);
    void add(const RevocationList& crl);
    void remove(const Certificate& crt, bool parents = true);
    VerifyResult verify(const Certificate& crt) const;

private:
    TrustList(const TrustList& o) = delete;
    TrustList& operator=(const TrustList& o) = delete;
    gnutls_x509_trust_list_t trust {nullptr};
};

/**
 * Generate an RSA key pair (4096 bits) and a certificate.
 * @param name the name used in the generated certificate
 * @param ca if set, the certificate authority that will sign the generated certificate.
 *           If not set, the generated certificate will be a self-signed CA.
 * @param key_length stength of the generated private key (bits).
 */
OPENDHT_PUBLIC Identity generateIdentity(const std::string& name, const Identity& ca, unsigned key_length, bool is_ca);
OPENDHT_PUBLIC Identity generateIdentity(const std::string& name = "dhtnode", const Identity& ca = {}, unsigned key_length = 4096);

OPENDHT_PUBLIC Identity generateEcIdentity(const std::string& name, const Identity& ca, bool is_ca);
OPENDHT_PUBLIC Identity generateEcIdentity(const std::string& name = "dhtnode", const Identity& ca = {});

OPENDHT_PUBLIC void saveIdentity(const Identity& id, const std::string& path, const std::string& privkey_password = {});
OPENDHT_PUBLIC Identity loadIdentity(const std::string &path,const std::string &privkey_password = {});

/**
 * Performs SHA512, SHA256 or SHA1, depending on hash_length.
 * Attempts to choose an hash function with
 * output size of at least hash_length bytes, Current implementation
 * will use SHA1 for hash_length up to 20 bytes,
 * will use SHA256 for hash_length up to 32 bytes,
 * will use SHA512 for hash_length of 33 bytes and more.
 */
OPENDHT_PUBLIC Blob hash(const Blob& data, size_t hash_length = 512/8);

OPENDHT_PUBLIC void hash(const uint8_t* data, size_t data_length, uint8_t* hash, size_t hash_length);

/**
 * Generates an encryption key from a text password,
 * making the key longer to bruteforce.
 * The generated key also depends on a unique salt value of any size,
 * that can be transmitted in clear, and will be generated if
 * not provided (32 bytes).
 */
OPENDHT_PUBLIC Blob stretchKey(std::string_view password, Blob& salt, size_t key_length = 512/8);

/**
 * AES-GCM encryption. Key must be 128, 192 or 256 bits long (16, 24 or 32 bytes).
 */
OPENDHT_PUBLIC Blob aesEncrypt(const uint8_t* data, size_t data_length, const Blob& key);
OPENDHT_PUBLIC inline Blob aesEncrypt(const Blob& data, const Blob& key) {
    return aesEncrypt(data.data(), data.size(), key);
}
/**
 * AES-GCM encryption with argon2 key derivation.
 * This function uses `stretchKey` to generate an AES key from the password and a random salt.
 * The result is a bundle including the salt that can be decrypted with `aesDecrypt(data, password)`.
 * If needed, the salt or encrypted data can be individually extracted from the bundle with `aesGetSalt` and `aesGetEncrypted`.
 * @param data: data to encrypt
 * @param password: password to encrypt the data with
 * @param salt: optional salt to use for key derivation. If not provided, a random salt will be generated.
 */
OPENDHT_PUBLIC Blob aesEncrypt(const Blob& data, std::string_view password, const Blob& salt = {});

/**
 * AES-GCM decryption.
 */
OPENDHT_PUBLIC Blob aesDecrypt(const uint8_t* data, size_t data_length, const Blob& key);
OPENDHT_PUBLIC inline Blob aesDecrypt(const Blob& data, const Blob& key) { return aesDecrypt(data.data(), data.size(), key); }
OPENDHT_PUBLIC inline Blob aesDecrypt(std::string_view data, const Blob& key) { return aesDecrypt((uint8_t*)data.data(), data.size(), key); }

OPENDHT_PUBLIC Blob aesDecrypt(const uint8_t* data, size_t data_length, std::string_view password);
OPENDHT_PUBLIC inline Blob aesDecrypt(const Blob& data, std::string_view password) { return aesDecrypt(data.data(), data.size(), password); }
OPENDHT_PUBLIC inline Blob aesDecrypt(std::string_view data, std::string_view password) { return aesDecrypt((uint8_t*)data.data(), data.size(), password); }

/**
 * Get raw AES key from password and salt stored with the encrypted data.
 */
OPENDHT_PUBLIC Blob aesGetKey(const uint8_t* data, size_t data_length, std::string_view password);
OPENDHT_PUBLIC Blob inline aesGetKey(const Blob& data, std::string_view password) {
    return aesGetKey(data.data(), data.size(), password);
}
/** Get the salt part of data password-encrypted with `aesEncrypt(data, password)` */
OPENDHT_PUBLIC Blob aesGetSalt(const uint8_t* data, size_t data_length);
OPENDHT_PUBLIC Blob inline aesGetSalt(const Blob& data) {
    return aesGetSalt(data.data(), data.size());
}
/** Get the encrypted data (ciphertext) part of data password-encrypted with `aesEncrypt(data, password)` */
OPENDHT_PUBLIC std::string_view aesGetEncrypted(const uint8_t* data, size_t data_length);
OPENDHT_PUBLIC std::string_view inline aesGetEncrypted(const Blob& data) {
    return aesGetEncrypted(data.data(), data.size());
}

/** Build an encrypted bundle that can be decrypted with aesDecrypt(data, password).
 *  @param encryptedData: result of `aesEncrypt(data, key)` or `aesGetEncrypted`
 *  @param salt: should match the encryption key and password so that `stretchKey(password, salk) == key`.
 *  Can be obtained from an existing bundle with `aesGetSalt`.
 **/
OPENDHT_PUBLIC Blob aesBuildEncrypted(const uint8_t* encryptedData, size_t data_length, const Blob& salt);
OPENDHT_PUBLIC Blob inline aesBuildEncrypted(const Blob& encryptedData, const Blob& salt) {
    return aesBuildEncrypted(encryptedData.data(), encryptedData.size(), salt);
}
OPENDHT_PUBLIC Blob inline aesBuildEncrypted(std::string_view encryptedData, const Blob& salt) {
    return aesBuildEncrypted((const uint8_t*)encryptedData.data(), encryptedData.size(), salt);
}

}
}
