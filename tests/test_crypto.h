// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class CryptoTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(CryptoTester);
    CPPUNIT_TEST(testSignatureEncryption);
    CPPUNIT_TEST(testCertificateRevocation);
    CPPUNIT_TEST(testCertificateRequest);
    CPPUNIT_TEST(testCertificateSerialNumber);
    CPPUNIT_TEST(testOcsp);
    CPPUNIT_TEST(testAesEncryption);
    CPPUNIT_TEST(testAesEncryptionWithMultipleKeySizes);
    CPPUNIT_TEST(testOaep);
    CPPUNIT_TEST(testWebPushEncryption);
    CPPUNIT_TEST(testWebPushRFC8291);
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
    /**
     * Test OCSP
     */
    void testOcsp();
    /**
     * Test key streching and aes encryption/decryption
     */
    void testAesEncryption();
    void testAesEncryptionWithMultipleKeySizes();

    void testOaep();
    void testWebPushEncryption();
    void testWebPushRFC8291();
};

} // namespace test
