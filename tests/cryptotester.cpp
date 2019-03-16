/*
 *  Copyright (C) 2019 Savoir-faire Linux Inc.
 *
 *  Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include "opendht/crypto.h"

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(CryptoTester);

void
CryptoTester::setUp() {

}

void
CryptoTester::testSignatureEncryption() {
    auto key = dht::crypto::PrivateKey::generate();
    auto public_key = key.getPublicKey();

    std::vector<uint8_t> data {5, 10};
    std::vector<uint8_t> signature = key.sign(data);

    // check signature
    CPPUNIT_ASSERT(public_key.checkSignature(data, signature));

    // encrypt data
    std::vector<uint8_t> encrypted = public_key.encrypt(data);
    std::vector<uint8_t> decrypted = key.decrypt(encrypted);
    CPPUNIT_ASSERT(data == decrypted);
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
CryptoTester::tearDown() {

}
}  // namespace test
