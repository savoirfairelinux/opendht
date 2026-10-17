// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class NetworkEngineTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(NetworkEngineTester);
#ifdef _MSC_VER
    CPPUNIT_TEST(testDisabledOnMsvc);
#else
    CPPUNIT_TEST(testCompletesPartialSessionWithDataBeforeHeader);
    CPPUNIT_TEST(testBuffersLargeValueBeforeHeader);
    CPPUNIT_TEST(testIgnoresEmptyPartialData);
    CPPUNIT_TEST(testRejectsUnsolicitedPartialReply);
    CPPUNIT_TEST(testDropsMalformedCompletedPartialMessage);
    CPPUNIT_TEST(testCompletesPartialSessionFromSameSource);
    CPPUNIT_TEST(testSeparatesPartialSessionsBySource);
    CPPUNIT_TEST(testPlaintextListenRequiresToken);
    CPPUNIT_TEST(testListenConfirmationUpdatesSearchNodeToken);
    CPPUNIT_TEST(testListenReopensSocketAfterNodeExpiration);
    CPPUNIT_TEST(testUnauthorizedListenFlushClearsListenState);
    CPPUNIT_TEST(testTransportDisabledKeepsLegacyWire);
    CPPUNIT_TEST(testTransportEncryptsAfterKeyExchange);
    CPPUNIT_TEST(testTransportLegacyPeerStaysPlaintext);
    CPPUNIT_TEST(testTransportRejectsMismatchedNodeId);
    CPPUNIT_TEST(testTransportIgnoresForgedNodeListKey);
    CPPUNIT_TEST(testTransportPlaintextDoesNotMoveKeyedNode);
    CPPUNIT_TEST(testTransportPrivateNetwork);
    CPPUNIT_TEST(testTransportPrivateNetworkRejectsOutsiders);
    CPPUNIT_TEST(testTransportEpochRotation);
    CPPUNIT_TEST(testTransportPeerRestart);
    CPPUNIT_TEST(testTransportHelloIsUnauthenticated);
    CPPUNIT_TEST(testTransportSessionAuthorizesWrites);
    CPPUNIT_TEST(testTransportInitialWriteIsUnauthorized);
    CPPUNIT_TEST(testTransportEphemeralBoundToAddress);
    CPPUNIT_TEST(testTransportRestartedPeerReconnects);
#endif
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();
    void tearDown();

#ifdef _MSC_VER
    void testDisabledOnMsvc();
#else
    void testCompletesPartialSessionWithDataBeforeHeader();
    void testBuffersLargeValueBeforeHeader();
    void testIgnoresEmptyPartialData();
    void testRejectsUnsolicitedPartialReply();
    void testDropsMalformedCompletedPartialMessage();
    void testCompletesPartialSessionFromSameSource();
    void testSeparatesPartialSessionsBySource();
    void testPlaintextListenRequiresToken();
    void testListenConfirmationUpdatesSearchNodeToken();
    void testListenReopensSocketAfterNodeExpiration();
    void testUnauthorizedListenFlushClearsListenState();
    void testTransportDisabledKeepsLegacyWire();
    void testTransportEncryptsAfterKeyExchange();
    void testTransportLegacyPeerStaysPlaintext();
    void testTransportRejectsMismatchedNodeId();
    void testTransportIgnoresForgedNodeListKey();
    void testTransportPlaintextDoesNotMoveKeyedNode();
    void testTransportPrivateNetwork();
    void testTransportPrivateNetworkRejectsOutsiders();
    void testTransportEpochRotation();
    void testTransportPeerRestart();
    void testTransportHelloIsUnauthenticated();
    void testTransportSessionAuthorizesWrites();
    void testTransportInitialWriteIsUnauthorized();
    void testTransportEphemeralBoundToAddress();
    void testTransportRestartedPeerReconnects();
#endif
};

} // namespace test