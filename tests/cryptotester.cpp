/*
 *  Copyright (C) 2018 Savoir-faire Linux Inc.
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
CryptoTester::tearDown() {

}
}  // namespace test
