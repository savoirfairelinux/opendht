/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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

#pragma once

#include "infohash.h"
#include "utils.h"
#include "rng.h"

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
    PublicKey(const uint8_t* dat, size_t dat_size);
    PublicKey(const Blob& pk) : PublicKey(pk.data(), pk.size()) {}
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

    /**
     * Get public key fingerprint
     */
    InfoHash getId() const;

    /**
     * Get public key long fingerprint
     */
    PkId getLongId() const;

    bool checkSignature(const uint8_t* data, size_t data_len, const uint8_t* signature, size_t signature_len) const;
    bool checkSignature(const Blob& data, const Blob& signature) const {
        return checkSignature(data.data(), data.size(), signature.data(), signature.size());
    }

    Blob encrypt(const uint8_t* data, size_t data_len) const;
    Blob encrypt(const Blob& data) const {
        return encrypt(data.data(), data.size());
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
    PrivateKey(const Blob& src, const std::string& password = {}) : PrivateKey(src.data(), src.size(), password.data()) {}
    ~PrivateKey();
    explicit operator bool() const { return key; }

    PublicKey getPublicKey() const;
    int serialize(uint8_t* out, size_t* out_len, const std::string& password = {}) const;
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
    static PrivateKey generateEC();

    gnutls_privkey_t key {};
    gnutls_x509_privkey_t x509_key {};
private:
    PrivateKey(const PrivateKey&) = delete;
    PrivateKey& operator=(const PrivateKey&) = delete;
    Blob decryptBloc(const uint8_t* src, size_t src_size) const;

    //friend dht::crypto::Identity dht::crypto::generateIdentity(const std::string&, dht::crypto::Identity, unsigned key_length);
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

struct OPENDHT_PUBLIC Certificate {
    Certificate() noexcept {}

    /**
     * Take ownership of existing gnutls structure
     */
    Certificate(gnutls_x509_crt_t crt) noexcept : cert(crt) {}

    Certificate(Certificate&& o) noexcept : cert(o.cert), issuer(std::move(o.issuer)) { o.cert = nullptr; };

    /**
     * Import certificate (PEM or DER) or certificate chain (PEM),
     * ordered from subject to issuer
     */
    Certificate(const Blob& crt);
    Certificate(const std::string& pem) : cert(nullptr) {
        unpack((const uint8_t*)pem.data(), pem.size());
    }
    Certificate(const uint8_t* dat, size_t dat_size) : cert(nullptr) {
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

    void msgpack_unpack(const msgpack::object& o);

    explicit operator bool() const { return cert; }
    PublicKey getPublicKey() const;

    /** Same as getPublicKey().getId() */
    InfoHash getId() const;
    /** Same as getPublicKey().getLongId() */
    PkId getLongId() const;

    /** Read certificate Common Name (CN) */
    std::string getName() const;

    /** Read certificate User ID (UID) */
    std::string getUID() const;

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

    static Certificate generate(const PrivateKey& key, const std::string& name = "dhtnode", const Identity& ca = {}, bool is_ca = false);
    static Certificate generate(const CertificateRequest& request, const Identity& ca);

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

    gnutls_x509_crt_t cert {nullptr};
    std::shared_ptr<Certificate> issuer {};
private:
    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;

    struct crlNumberCmp {
        bool operator() (const std::shared_ptr<RevocationList>& lhs, const std::shared_ptr<RevocationList>& rhs) const {
            return lhs->getNumber() < rhs->getNumber();
        }
    };

    std::set<std::shared_ptr<RevocationList>, crlNumberCmp> revocation_lists;
};

struct OPENDHT_PUBLIC TrustList
{
    struct VerifyResult {
        int ret;
        unsigned result;
        bool hasError() const { return ret < 0; }
        bool isValid() const { return !hasError() and !(result & GNUTLS_CERT_INVALID); }
        explicit operator bool() const { return isValid(); }
        std::string toString() const;
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

template <class T>
class OPENDHT_PUBLIC secure_vector
{
public:
    secure_vector() {}
    secure_vector(secure_vector<T> const&) = default;
    secure_vector(secure_vector<T> &&) = default;
    explicit secure_vector(unsigned size): data_(size) {}
    explicit secure_vector(unsigned size, T _item): data_(size, _item) {}
    explicit secure_vector(const std::vector<T>& c): data_(c) {}
    secure_vector(std::vector<T>&& c): data_(std::move(c)) {}
    ~secure_vector() { clean(); }

    static secure_vector<T> getRandom(size_t size) {
        secure_vector<T> ret(size);
        crypto::random_device rdev;
#ifdef _WIN32
        std::uniform_int_distribution<int> rand_byte{ 0, std::numeric_limits<uint8_t>::max() };
#else
        std::uniform_int_distribution<uint8_t> rand_byte;
#endif
        std::generate_n((uint8_t*)ret.data_.data(), ret.size()*sizeof(T), std::bind(rand_byte, std::ref(rdev)));
        return ret;
    }
    secure_vector<T>& operator=(const secure_vector<T>& c) {
        if (&c == this)
            return *this;
        clean();
        data_ = c.data_;
        return *this;
    }
    secure_vector<T>& operator=(secure_vector<T>&& c) {
        if (&c == this)
            return *this;
        clean();
        data_ = std::move(c.data_);
        return *this;
    }
    secure_vector<T>& operator=(std::vector<T>&& c) {
        clean();
        data_ = std::move(c);
        return *this;
    }
    std::vector<T>& writable() { clean(); return data_; }
    const std::vector<T>& makeInsecure() const { return data_; }
    const uint8_t* data() const { return data_.data(); }

    void clean() {
        clean(data_.begin(), data_.end());
    }

    void clear() { clean(); data_.clear(); }

    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    void swap(secure_vector<T>& other) { data_.swap(other.data_); }
    void resize(size_t s) {
        if (s == data_.size()) return;
        if (s < data_.size()) {
            //shrink
            clean(data_.begin()+s, data_.end());
            data_.resize(s);
        } else {
            //grow
            auto data = std::move(data_); // move protected data
            clear();
            data_.resize(s);
            std::copy(data.begin(), data.end(), data_.begin());
            clean(data.begin(), data.end());
        }
    }

private:
    /**
     * Securely wipe memory
     */
    static void clean(const typename std::vector<T>::iterator& i, const typename std::vector<T>::iterator& j) {
        volatile uint8_t* b = reinterpret_cast<uint8_t*>(&*i);
        volatile uint8_t* e = reinterpret_cast<uint8_t*>(&*j);
        std::fill(b, e, 0);
    }

    std::vector<T> data_;
};

using SecureBlob = secure_vector<uint8_t>;

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
OPENDHT_PUBLIC Blob stretchKey(const std::string& password, Blob& salt, size_t key_length = 512/8);

/**
 * AES-GCM encryption. Key must be 128, 192 or 256 bits long (16, 24 or 32 bytes).
 */
OPENDHT_PUBLIC Blob aesEncrypt(const uint8_t* data, size_t data_length, const Blob& key);
OPENDHT_PUBLIC inline Blob aesEncrypt(const Blob& data, const Blob& key) {
    return aesEncrypt(data.data(), data.size(), key);
}
OPENDHT_PUBLIC Blob aesEncrypt(const Blob& data, const std::string& password);

/**
 * AES-GCM decryption.
 */
OPENDHT_PUBLIC Blob aesDecrypt(const Blob& data, const Blob& key);
OPENDHT_PUBLIC Blob aesDecrypt(const Blob& data, const std::string& password);

}
}
