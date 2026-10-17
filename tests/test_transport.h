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
    CPPUNIT_TEST(testSharedKey);
    CPPUNIT_TEST(testRejectsLowOrderKey);
    CPPUNIT_TEST(testNodeId);
    CPPUNIT_TEST(testSealOpen);
    CPPUNIT_TEST(testOpenRejectsTampering);
    CPPUNIT_TEST(testEnvelopeIsNotMsgpack);
    CPPUNIT_TEST(testHello);
    CPPUNIT_TEST(testCredential);
    CPPUNIT_TEST(testCredentialRejections);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() {}
    void tearDown() {}

    void testX25519Rfc7748();
    void testSharedKey();
    void testRejectsLowOrderKey();
    void testNodeId();
    void testSealOpen();
    void testOpenRejectsTampering();
    void testEnvelopeIsNotMsgpack();
    void testHello();
    void testCredential();
    void testCredentialRejections();
};

} // namespace test
