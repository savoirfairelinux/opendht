/*
 *  Copyright (C) 2014-2025 Savoir-faire Linux Inc.
 *
 *  Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *          Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
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

#include "cryptotester.h"

#include <opendht/crypto.h>

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(CryptoTester);

void
CryptoTester::setUp()
{}

void
CryptoTester::testSignatureEncryption()
{
    auto key = dht::crypto::PrivateKey::generate();
    const auto& public_key = key.getPublicKey();

    std::vector<uint8_t> data1 {5, 10};
    std::vector<uint8_t> data2(64 * 1024, 10);

    std::vector<uint8_t> signature1 = key.sign(data1);
    std::vector<uint8_t> signature2 = key.sign(data2);

    // check signature
    CPPUNIT_ASSERT(public_key.checkSignature(data1, signature1));
    CPPUNIT_ASSERT(public_key.checkSignature(data2, signature2));
    signature1[7]++;
    signature2[8]--;
    CPPUNIT_ASSERT(!public_key.checkSignature(data1, signature1));
    CPPUNIT_ASSERT(!public_key.checkSignature(data2, signature2));

    // encrypt data
    {
        std::vector<uint8_t> encrypted = public_key.encrypt(data1);
        std::vector<uint8_t> decrypted = key.decrypt(encrypted);
        CPPUNIT_ASSERT(data1 == decrypted);
    }

    {
        std::vector<uint8_t> encrypted = public_key.encrypt(data2);
        std::vector<uint8_t> decrypted = key.decrypt(encrypted);
        CPPUNIT_ASSERT(data2 == decrypted);
    }

    // encrypt data (invalid)
    {
        std::vector<uint8_t> encrypted = public_key.encrypt(data1);
        encrypted[1]++;
        CPPUNIT_ASSERT_THROW(key.decrypt(encrypted), std::runtime_error);
    }

    {
        std::vector<uint8_t> encrypted = public_key.encrypt(data2);
        encrypted[2]++;
        CPPUNIT_ASSERT_THROW(key.decrypt(encrypted), std::runtime_error);
    }
}

void
CryptoTester::testCertificateRevocation()
{
    auto ca1 = dht::crypto::generateIdentity("ca1");
    auto account1 = dht::crypto::generateIdentity("acc1", ca1, 4096, true);
    auto device11 = dht::crypto::generateIdentity("dev11", account1);
    auto device12 = dht::crypto::generateIdentity("dev12", account1);

    dht::crypto::TrustList list;
    list.add(*ca1.second);
    auto v = list.verify(*account1.second);
    CPPUNIT_ASSERT_MESSAGE(v.toString(), v);

    list.add(*account1.second);
    v = list.verify(*device11.second);
    CPPUNIT_ASSERT_MESSAGE(v.toString(), v);
    v = list.verify(*device12.second);
    CPPUNIT_ASSERT_MESSAGE(v.toString(), v);

    auto ca2 = dht::crypto::generateIdentity("ca2");
    auto account2 = dht::crypto::generateIdentity("acc2", ca2, 4096, true);
    auto device2 = dht::crypto::generateIdentity("dev2", account2);

    v = list.verify(*device2.second);
    CPPUNIT_ASSERT_MESSAGE(v.toString(), !v);

    account1.second->revoke(*account1.first, *device11.second);
    dht::crypto::TrustList list2;
    list2.add(*account1.second);

    v = list2.verify(*device11.second);
    CPPUNIT_ASSERT_MESSAGE(v.toString(), !v);
    v = list2.verify(*device12.second);
    CPPUNIT_ASSERT_MESSAGE(v.toString(), v);
}

void
CryptoTester::testCertificateRequest()
{
    // Generate CA
    auto ca = dht::crypto::generateIdentity("Test CA");

    // Generate signed request
    auto deviceKey = dht::crypto::PrivateKey::generate();
    auto request = dht::crypto::CertificateRequest();
    request.setName("Test Device");
    request.sign(deviceKey);

    // Export/import request
    auto importedRequest = dht::crypto::CertificateRequest(request.pack());
    CPPUNIT_ASSERT(importedRequest.verify());

    // Generate/sign certificate from request
    auto signedCert = dht::crypto::Certificate::generate(request, ca);
    CPPUNIT_ASSERT_EQUAL(ca.second->getName(), signedCert.getIssuerName());
    CPPUNIT_ASSERT_EQUAL(request.getName(), signedCert.getName());

    // Check generated certificate
    dht::crypto::TrustList list;
    list.add(*ca.second);
    auto v = list.verify(signedCert);
    CPPUNIT_ASSERT_MESSAGE(v.toString(), v);
}

void
CryptoTester::testCertificateSerialNumber()
{
    static const std::string cert_pem = "-----BEGIN CERTIFICATE-----"
                                        "MIICDjCCAZSgAwIBAgIIS90uAKp+u/swCgYIKoZIzj0EAwMwTDEQMA4GA1UEAxMH"
                                        "ZGh0bm9kZTE4MDYGCgmSJomT8ixkAQETKDBlNDQxZTA4YWJmYTQzYTc3ZTVjZDBm"
                                        "Y2QzMzAzMTc4MjYxMTk0MzIwHhcNMTkxMTA3MDA0MTMwWhcNMjkxMTA0MDA0MTMw"
                                        "WjBMMRAwDgYDVQQDEwdkaHRub2RlMTgwNgYKCZImiZPyLGQBARMoMGU0NDFlMDhh"
                                        "YmZhNDNhNzdlNWNkMGZjZDMzMDMxNzgyNjExOTQzMjB2MBAGByqGSM49AgEGBSuB"
                                        "BAAiA2IABCZ7sBp0Pu+b5yIifoNXchU9crv9won0in++COWynvM4GCLF2Gk6QGhh"
                                        "YLDxNGsyQjGR7z5AGibvYhNLU0JA4RbmxYWHw4g3wBrPA1jm9hGZ8y5Y8R97d0Hl"
                                        "VpyreEMjRKNDMEEwHQYDVR0OBBYEFA5EHgir+kOnflzQ/NMwMXgmEZQyMA8GA1Ud"
                                        "EwEB/wQFMAMBAf8wDwYDVR0PAQH/BAUDAwcGADAKBggqhkjOPQQDAwNoADBlAjEA"
                                        "kKF/6WReNytwSrJ8JSTToc7xWS5SvAa23Fnla4mywZUxUFS4VSxCMQTjQCknO3iZ"
                                        "AjBgxXyXYqn0d7vz7S6oAY5TdaD5YFT5MD2c1MAAp8pxQSwdPa9k0ZSoGIEn31Z0"
                                        "GxU="
                                        "-----END CERTIFICATE-----";
    /*
     * $ openssl x509 -in cert.pem  -noout -serial
     * serial=4BDD2E00AA7EBBFB
     */
    static constexpr std::array<uint8_t, 8> SERIAL {
        {0x4b, 0xdd, 0x2e, 0x00, 0xaa, 0x7e, 0xbb, 0xfb}
    };
    auto serial = dht::crypto::Certificate(cert_pem).getSerialNumber();
    CPPUNIT_ASSERT(std::equal(SERIAL.begin(), SERIAL.end(), serial.begin(), serial.end()));
}

void
CryptoTester::testOcsp()
{
    auto ca = dht::crypto::generateIdentity("Test CA");
    auto device = dht::crypto::generateIdentity("Test Device", ca);
    auto ocspRequest = device.second->generateOcspRequest(ca.second->cert);
    auto req = dht::crypto::OcspRequest((const uint8_t*) ocspRequest.first.data(), ocspRequest.first.size());
    CPPUNIT_ASSERT(ocspRequest.second == req.getNonce());
}

void
CryptoTester::testAesEncryption()
{
    auto password = "this is a password 123414!@#%@#$?" + std::to_string(rand());

    std::vector<uint8_t> data1 {5, 10};
    std::vector<uint8_t> data2(128 * 1024 + 13, 10);

    auto encrypted1 = dht::crypto::aesEncrypt(data1, password);
    auto encrypted2 = dht::crypto::aesEncrypt(data2, password);

    auto decrypted1 = dht::crypto::aesDecrypt(encrypted1, password);
    auto decrypted2 = dht::crypto::aesDecrypt(encrypted2, password);

    CPPUNIT_ASSERT(data1 != encrypted1);
    CPPUNIT_ASSERT(data2 != encrypted2);
    CPPUNIT_ASSERT(data1 == decrypted1);
    CPPUNIT_ASSERT(data2 == decrypted2);

    auto key1 = dht::crypto::aesGetKey(encrypted1, password);
    auto key2 = dht::crypto::aesGetKey(encrypted2, password);
    auto encrypted1_data = dht::crypto::aesGetEncrypted(encrypted1);
    auto encrypted2_data = dht::crypto::aesGetEncrypted(encrypted2);

    CPPUNIT_ASSERT(key1 != key2);

    decrypted1 = dht::crypto::aesDecrypt(encrypted1_data, key1);
    decrypted2 = dht::crypto::aesDecrypt(encrypted2_data, key2);

    CPPUNIT_ASSERT(data1 == decrypted1);
    CPPUNIT_ASSERT(data2 == decrypted2);

    auto salt1 = dht::crypto::aesGetSalt(encrypted1);
    auto salt2 = dht::crypto::aesGetSalt(encrypted2);

    CPPUNIT_ASSERT(salt1 != salt2);

    auto encrypted11 = dht::crypto::aesBuildEncrypted(encrypted1_data, salt1);
    auto encrypted22 = dht::crypto::aesBuildEncrypted(encrypted2_data, salt2);

    CPPUNIT_ASSERT(encrypted11 == encrypted1);
    CPPUNIT_ASSERT(encrypted22 == encrypted2);

    auto key12 = dht::crypto::stretchKey(password, salt1, 256 / 8);
    auto key22 = dht::crypto::stretchKey(password, salt2, 256 / 8);

    CPPUNIT_ASSERT(key1 == key12);
    CPPUNIT_ASSERT(key2 == key22);

    decrypted1 = dht::crypto::aesDecrypt(encrypted1_data, key12);
    decrypted2 = dht::crypto::aesDecrypt(encrypted2_data, key22);

    CPPUNIT_ASSERT(data1 == decrypted1);
    CPPUNIT_ASSERT(data2 == decrypted2);

    auto encrypted12_data = dht::crypto::aesEncrypt(data1, key12);
    auto encrypted22_data = dht::crypto::aesEncrypt(data2, key22);

    encrypted11 = dht::crypto::aesBuildEncrypted(encrypted12_data, salt1);
    encrypted22 = dht::crypto::aesBuildEncrypted(encrypted22_data, salt2);

    decrypted1 = dht::crypto::aesDecrypt(encrypted11, password);
    decrypted2 = dht::crypto::aesDecrypt(encrypted22, password);

    CPPUNIT_ASSERT(data1 == decrypted1);
    CPPUNIT_ASSERT(data2 == decrypted2);
}

void
CryptoTester::testAesEncryptionWithMultipleKeySizes()
{
    auto data = std::vector<uint8_t>(rand(), rand());

    // Valid key sizes
    for (auto key_length : {16, 24, 32}) {
        auto key = std::vector<uint8_t>(key_length, rand());

        auto encrypted_data = dht::crypto::aesEncrypt(data, key);
        auto decrypted_data = dht::crypto::aesDecrypt(encrypted_data, key);

        CPPUNIT_ASSERT(data == decrypted_data);
    }

    // Invalid key sizes
    for (auto key_length : {12, 28, 36}) {
        auto key = std::vector<uint8_t>(key_length, rand());

        CPPUNIT_ASSERT_THROW(dht::crypto::aesEncrypt(data, key), dht::crypto::DecryptError);
    }
}

void
CryptoTester::testOaep()
{
#if GNUTLS_VERSION_NUMBER >= 0x030804 && !defined(_WIN32)
    auto data = std::vector<uint8_t>(446, 10);
    auto ca = dht::crypto::generateIdentity("n1");

    auto key = dht::crypto::PrivateKey::generate(4096, GNUTLS_PK_RSA_OAEP);

    auto pk = key.getSharedPublicKey();
    auto encrypted = pk->encrypt(data);

    auto decrypted = key.decrypt(encrypted);
    CPPUNIT_ASSERT(data == decrypted);

    auto crt = dht::crypto::Certificate::generate(key, "dhtnode", ca);
    auto pk2 = crt.getSharedPublicKey();

    auto encrypted2 = pk2->encrypt(data);
    auto decrypted2 = key.decrypt(encrypted2);
    CPPUNIT_ASSERT(data == decrypted2);

    auto exported = crt.getPacked();
    dht::crypto::Certificate imported(exported);
    auto pk3 = imported.getSharedPublicKey();
    auto encrypted3 = pk3->encrypt(data);
    auto decrypted3 = key.decrypt(encrypted3);
    CPPUNIT_ASSERT(data == decrypted3);

    auto exportedPk = pk->toString();
    dht::crypto::PublicKey importedPk(exportedPk);
    auto encrypted4 = importedPk.encrypt(data);
    auto decrypted4 = key.decrypt(encrypted4);
    CPPUNIT_ASSERT(data == decrypted4);

    auto exportedKey = key.serialize();
    dht::crypto::PrivateKey importedKey(exportedKey);
    auto decrypted5 = importedKey.decrypt(encrypted);
    CPPUNIT_ASSERT(data == decrypted5);
#else
    std::cerr << "Skipping OAEP test, not supported by the current GnuTLS version" << std::endl;
#endif
}

void
CryptoTester::testWebPushEncryption()
{
    // 1. Generate Receiver P-256 Key Pair
    gnutls_privkey_t receiver_key;
    CPPUNIT_ASSERT_EQUAL(GNUTLS_E_SUCCESS, gnutls_privkey_init(&receiver_key));
    CPPUNIT_ASSERT_EQUAL(GNUTLS_E_SUCCESS,
                         gnutls_privkey_generate(receiver_key,
                                                 GNUTLS_PK_ECC,
                                                 GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1),
                                                 0));

    gnutls_datum_t x, y, k;
    CPPUNIT_ASSERT_EQUAL(GNUTLS_E_SUCCESS, gnutls_privkey_export_ecc_raw(receiver_key, NULL, &x, &y, &k));

    // Construct receiver public key (uncompressed)
    std::vector<uint8_t> p256dh(65);
    p256dh[0] = 0x04;

    auto copy_coord = [](uint8_t* dest, const gnutls_datum_t& src) {
        if (src.size > 32 && (src.size != 33 || src.data[0] != 0))
            throw std::runtime_error("Invalid key coordinate size: " + std::to_string(src.size));
        size_t offset = src.size > 32 ? 1 : 0;
        size_t len = src.size - offset;
        std::memset(dest, 0, 32 - len);
        std::memcpy(dest + (32 - len), src.data + offset, len);
    };

    copy_coord(p256dh.data() + 1, x);
    copy_coord(p256dh.data() + 33, y);

    gnutls_free(x.data);
    gnutls_free(y.data);
    gnutls_free(k.data);
    gnutls_privkey_deinit(receiver_key);

    // 2. Generate Auth Secret
    std::vector<uint8_t> auth(16, 'a'); // Dummy auth

    // 3. Payload
    std::string payloadStr = "{\"test\":\"data\"}";
    std::vector<uint8_t> payload(payloadStr.begin(), payloadStr.end());

    std::vector<uint8_t> longPayload(3 * 4096 + 17, 'b');

    // 4. Encrypt
    auto encrypted = dht::crypto::webPushEncrypt(p256dh, auth, payload.data(), payload.size());
    auto encryptedLong = dht::crypto::webPushEncrypt(p256dh, auth, longPayload.data(), longPayload.size());

    // 5. Verify Structure
    // Salt (16) + RS (4) + IDLEN (1) + Key (65) + Ciphertext (payload + 1 + 16)
    size_t expectedSize = 16 + 4 + 1 + 65 + payload.size() + 1 + 16;
    CPPUNIT_ASSERT_EQUAL(expectedSize, encrypted.size());

    expectedSize = 16 + 4 + 1 + 65 + longPayload.size() + 1 + 16;
    CPPUNIT_ASSERT_EQUAL(expectedSize, encryptedLong.size());

    // Check IDLEN
    CPPUNIT_ASSERT_EQUAL((uint8_t) 65, encrypted[20]);
    CPPUNIT_ASSERT_EQUAL((uint8_t) 65, encryptedLong[20]);

    // Check Key Header
    CPPUNIT_ASSERT_EQUAL((uint8_t) 0x04, encrypted[21]);
    CPPUNIT_ASSERT_EQUAL((uint8_t) 0x04, encryptedLong[21]);
}

void
CryptoTester::testWebPushRFC8291()
{
    // RFC 8291 Example
    // https://www.rfc-editor.org/rfc/rfc8291.html#section-5

    // Plaintext
    std::string plaintextStr = "When I grow up, I want to be a watermelon";
    dht::Blob payload(plaintextStr.begin(), plaintextStr.end());

    // Receiver (UA) Public Key (P-256 uncompressed)
    // Base64URL: BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4
    dht::Blob uaPub = {0x04, 0x25, 0x71, 0xb2, 0xbe, 0xcd, 0xfd, 0xe3, 0x60, 0x55, 0x1a, 0xaf, 0x1e,
                       0xd0, 0xf4, 0xcd, 0x36, 0x6c, 0x11, 0xce, 0xbe, 0x55, 0x5f, 0x89, 0xbc, 0xb7,
                       0xb1, 0x86, 0xa5, 0x33, 0x39, 0x17, 0x31, 0x68, 0xec, 0xe2, 0xeb, 0xe0, 0x18,
                       0x59, 0x7b, 0xd3, 0x04, 0x79, 0xb8, 0x6e, 0x3c, 0x8f, 0x8e, 0xce, 0xd5, 0x77,
                       0xca, 0x59, 0x18, 0x7e, 0x92, 0x46, 0x99, 0x0d, 0xb6, 0x82, 0x00, 0x8b, 0x0e};

    // Auth Secret
    // BTBZMqHH6r4Tts7J_aSIgg
    dht::Blob auth = {0x05, 0x30, 0x59, 0x32, 0xa1, 0xc7, 0xea, 0xbe, 0x13, 0xb6, 0xce, 0xc9, 0xfd, 0xa4, 0x88, 0x82};

    // Salt
    // DGv6ra1nlYgDCS1FRnbzlw
    dht::Blob salt = {0x0c, 0x6b, 0xfa, 0xad, 0xad, 0x67, 0x95, 0x88, 0x03, 0x09, 0x2d, 0x45, 0x46, 0x76, 0xf3, 0x97};

    // AS Private Key (Sender)
    // yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw
    dht::Blob asPrivRaw = {0xc9, 0xf5, 0x8f, 0x89, 0x81, 0x3e, 0x9f, 0x8e, 0x87, 0x2e, 0x71,
                           0xf4, 0x2a, 0xa6, 0x4e, 0x17, 0x57, 0xc9, 0x25, 0x4d, 0xcc, 0x62,
                           0xb7, 0x2d, 0xdc, 0x01, 0x0b, 0xb4, 0x04, 0x3e, 0xa1, 0x1c};

    // AS Public Key (Sender) - for verification
    // BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8
    dht::Blob asPubRaw = {0x04, 0xfe, 0x33, 0xf4, 0xab, 0x0d, 0xea, 0x71, 0x91, 0x4d, 0xb5, 0x58, 0x23,
                          0xf7, 0x3b, 0x54, 0x94, 0x8f, 0x41, 0x30, 0x6d, 0x92, 0x07, 0x32, 0xdb, 0xb9,
                          0xa5, 0x9a, 0x53, 0x28, 0x64, 0x82, 0x20, 0x0e, 0x59, 0x7a, 0x7b, 0x7b, 0xc2,
                          0x60, 0xba, 0x1c, 0x22, 0x79, 0x98, 0x58, 0x09, 0x92, 0xe9, 0x39, 0x73, 0x00,
                          0x2f, 0x30, 0x12, 0xa2, 0x8a, 0xe8, 0xf0, 0x6b, 0xbb, 0x78, 0xe5, 0xec, 0x0f};

    gnutls_privkey_t asPrivKeyGnutls;
    gnutls_privkey_init(&asPrivKeyGnutls);
    gnutls_datum_t k = {(unsigned char*) asPrivRaw.data(), (unsigned int) asPrivRaw.size()};
    gnutls_datum_t x = {(unsigned char*) asPubRaw.data() + 1, 32};
    gnutls_datum_t y = {(unsigned char*) asPubRaw.data() + 33, 32};

    int ret = gnutls_privkey_import_ecc_raw(asPrivKeyGnutls, GNUTLS_ECC_CURVE_SECP256R1, &x, &y, &k);
    CPPUNIT_ASSERT_EQUAL(0, ret);

    dht::crypto::PrivateKey asPrivKey;
    asPrivKey.key = asPrivKeyGnutls;

    // Expected Ciphertext (from RFC)
    // 8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ
    dht::Blob expectedCiphertext = {0xf2, 0x97, 0xde, 0x5b, 0x42, 0x9b, 0xba, 0x71, 0x53, 0xd3, 0xa4, 0xae,
                                    0x0c, 0xaa, 0x09, 0x1f, 0xd4, 0x25, 0xf3, 0xb4, 0xb5, 0x41, 0x4a, 0xdd,
                                    0x8a, 0xb3, 0x7a, 0x19, 0xc1, 0xbb, 0xb0, 0x5c, 0xf5, 0xcb, 0x5b, 0x2a,
                                    0x2e, 0x05, 0x62, 0xd5, 0x58, 0x63, 0x56, 0x41, 0xec, 0x52, 0x81, 0x2c,
                                    0x6c, 0x8f, 0xf4, 0x2e, 0x95, 0xcc, 0xb8, 0x6b, 0xe7, 0xcd};

    // Perform Encryption
    auto output = dht::crypto::webPushEncrypt(uaPub, auth, payload.data(), payload.size(), asPrivKey, salt);

    // Verify Output
    size_t headerSize = 16 + 4 + 1 + 65;
    CPPUNIT_ASSERT(output.size() == headerSize + expectedCiphertext.size());

    // Check Salt
    dht::Blob outSalt(output.begin(), output.begin() + 16);
    CPPUNIT_ASSERT(outSalt == salt);

    // Check Ciphertext
    dht::Blob outCiphertext(output.begin() + headerSize, output.end());
    CPPUNIT_ASSERT(outCiphertext == expectedCiphertext);

    // Check AS Public Key in header
    dht::Blob outASPub(output.begin() + 16 + 4 + 1, output.begin() + 16 + 4 + 1 + 65);
    CPPUNIT_ASSERT(outASPub == asPubRaw);
}

void
CryptoTester::tearDown()
{}
} // namespace test
