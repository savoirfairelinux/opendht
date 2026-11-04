// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class MdnsTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(MdnsTester);
    CPPUNIT_TEST(testName);
    CPPUNIT_TEST(testRecordRoundTrip);
    CPPUNIT_TEST(testCompression);
    CPPUNIT_TEST(testMalformedPackets);
    CPPUNIT_TEST(testPacketSizeLimit);
    CPPUNIT_TEST(testDnsSdAdvertisement);
    CPPUNIT_TEST(testDnsSdGoodbye);
    CPPUNIT_TEST(testDnsSdValidation);
    CPPUNIT_TEST(testDnsSdQueryResponse);
    CPPUNIT_TEST(testDnsSdCache);
    CPPUNIT_TEST(testInterfaceScoping);
    CPPUNIT_TEST_SUITE_END();

public:
    void testName();
    void testRecordRoundTrip();
    void testCompression();
    void testMalformedPackets();
    void testPacketSizeLimit();
    void testDnsSdAdvertisement();
    void testDnsSdGoodbye();
    void testDnsSdValidation();
    void testDnsSdQueryResponse();
    void testDnsSdCache();
    void testInterfaceScoping();
};

} // namespace test