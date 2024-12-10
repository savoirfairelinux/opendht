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

#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class CryptoTester : public CppUnit::TestFixture {
    CPPUNIT_TEST_SUITE(CryptoTester);
    CPPUNIT_TEST(testSignatureEncryption);
    CPPUNIT_TEST(testCertificateRevocation);
    CPPUNIT_TEST(testCertificateRequest);
    CPPUNIT_TEST(testCertificateSerialNumber);
    CPPUNIT_TEST_SUITE_END();

 public:
    /**
     * Method automatically called before each test by CppUnit
     */
    void setUp();
    /**
     * Method automatically called after each test CppUnit
     */
    void tearDown();
    /**
     * Test data signature, encryption and decryption
     */
    void testSignatureEncryption();
    /**
     * Test certificate generation, validation and revocation
     */
    void testCertificateRevocation();
    /**
     * Test certificate requests
     */
    void testCertificateRequest();
    /**
     * Test certificate serial number extraction
     */
    void testCertificateSerialNumber();
};

}  // namespace test
