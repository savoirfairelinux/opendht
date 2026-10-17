// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class TransportTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(TransportTester);
    CPPUNIT_TEST(testX25519Rfc7748);
    CPPUNIT_TEST(testSessionKeys);
    CPPUNIT_TEST(testInitialKey);
    CPPUNIT_TEST(testRejectsLowOrderKey);
    CPPUNIT_TEST(testNodeId);
    CPPUNIT_TEST(testAddressKey);
    CPPUNIT_TEST(testSealOpen);
    CPPUNIT_TEST(testOpenRejectsTampering);
    CPPUNIT_TEST(testDataEnvelope);
    CPPUNIT_TEST(testParseHeader);
    CPPUNIT_TEST(testEnvelopeIsNotMsgpack);
    CPPUNIT_TEST(testHello);
    CPPUNIT_TEST(testCredential);
    CPPUNIT_TEST(testCredentialRejections);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() {}
    void tearDown() {}

    void testX25519Rfc7748();
    void testSessionKeys();
    void testInitialKey();
    void testRejectsLowOrderKey();
    void testNodeId();
    void testAddressKey();
    void testSealOpen();
    void testOpenRejectsTampering();
    void testDataEnvelope();
    void testParseHeader();
    void testEnvelopeIsNotMsgpack();
    void testHello();
    void testCredential();
    void testCredentialRejections();
};

} // namespace test
