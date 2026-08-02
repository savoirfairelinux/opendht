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
    CPPUNIT_TEST(testPublicKeyPemIsPlainText);
    CPPUNIT_TEST(testCertificateRevocation);
    CPPUNIT_TEST(testRevocationListNumber);
    CPPUNIT_TEST(testRevocationListExplicitNumber);
    CPPUNIT_TEST(testRevocationListPartitionedNumber);
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
     * Test that an exported public key is text only, with no embedded null byte
     */
    void testPublicKeyPemIsPlainText();
    /**
     * Test certificate generation, validation and revocation
     */
    void testCertificateRevocation();
    /**
     * Test the default CRL Number behavior: random on first signature, incremented after
     */
    void testRevocationListNumber();
    /**
     * Test signing a revocation list with a caller-provided CRL Number
     */
    void testRevocationListExplicitNumber();
    /**
     * Test that issuers sharing an authority can partition the CRL Number space
     */
    void testRevocationListPartitionedNumber();
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
