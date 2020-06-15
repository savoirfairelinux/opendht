/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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
CryptoTester::setUp() {

}

void
CryptoTester::testSignatureEncryption() {
    auto key = dht::crypto::PrivateKey::generate();
    auto public_key = key.getPublicKey();

    std::vector<uint8_t> data1 {5, 10};
    std::vector<uint8_t> data2(64 * 1024, 10);

    std::vector<uint8_t> signature1 = key.sign(data1);
    std::vector<uint8_t> signature2 = key.sign(data2);

    // check signature
    CPPUNIT_ASSERT(public_key.checkSignature(data1, signature1));
    CPPUNIT_ASSERT(public_key.checkSignature(data2, signature2));

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

void CryptoTester::testCertificateSerialNumber()
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
    static constexpr std::array<uint8_t, 8> SERIAL {{0x4b,0xdd,0x2e,0x00,0xaa,0x7e,0xbb,0xfb}};
    auto serial = dht::crypto::Certificate(cert_pem).getSerialNumber();
    CPPUNIT_ASSERT(std::equal(SERIAL.begin(), SERIAL.end(), serial.begin(), serial.end()));
}

void
CryptoTester::tearDown() {

}
}  // namespace test
