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
    CPPUNIT_TEST(testListenConfirmationCarriesToken);
    CPPUNIT_TEST(testListenConfirmationUpdatesSearchNodeToken);
    CPPUNIT_TEST(testListenReadinessWaitsForInitialUpdate);
    CPPUNIT_TEST(testListenReadinessSnapshotVariants);
    CPPUNIT_TEST(testListenReadinessSnapshotLegacy);
    CPPUNIT_TEST(testListenLegacyLateValuesAndRenewal);
    CPPUNIT_TEST(testListenReadinessMixedPeers);
    CPPUNIT_TEST(testListenReadinessSnapshotFailure);
    CPPUNIT_TEST(testListenReadinessSnapshotCancellation);
    CPPUNIT_TEST(testListenReadinessSnapshotReplacement);
    CPPUNIT_TEST(testListenReadinessSnapshotRenewal);
    CPPUNIT_TEST(testListenUpdatesBeforeConfirmation);
    CPPUNIT_TEST(testListenLiveChangesBeforeSnapshot);
    CPPUNIT_TEST(testListenDuplicateRegistration);
    CPPUNIT_TEST(testListenLargeSnapshotDefaultLimits);
    CPPUNIT_TEST(testListenLiveUpdateOrdering);
    CPPUNIT_TEST(testListenInitializationTimeout);
    CPPUNIT_TEST(testListenRegistrationFailure);
    CPPUNIT_TEST(testListenRegistrationCapacity);
    CPPUNIT_TEST(testListenReadinessAddressFamilies);
    CPPUNIT_TEST(testListenReadinessFailedSearch);
    CPPUNIT_TEST(testListenReadinessReusesExpiredSearch);
    CPPUNIT_TEST(testListenReadinessShutdown);
    CPPUNIT_TEST(testListenReopensSocketAfterNodeExpiration);
    CPPUNIT_TEST(testUnauthorizedListenFlushClearsListenState);
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
    void testListenConfirmationCarriesToken();
    void testListenConfirmationUpdatesSearchNodeToken();
    void testListenReadinessWaitsForInitialUpdate();
    void testListenReadinessSnapshotVariants();
    void testListenReadinessSnapshotLegacy();
    void testListenLegacyLateValuesAndRenewal();
    void testListenReadinessMixedPeers();
    void testListenReadinessSnapshotFailure();
    void testListenReadinessSnapshotCancellation();
    void testListenReadinessSnapshotReplacement();
    void testListenReadinessSnapshotRenewal();
    void testListenUpdatesBeforeConfirmation();
    void testListenLiveChangesBeforeSnapshot();
    void testListenDuplicateRegistration();
    void testListenLargeSnapshotDefaultLimits();
    void testListenLiveUpdateOrdering();
    void testListenInitializationTimeout();
    void testListenRegistrationFailure();
    void testListenRegistrationCapacity();
    void testListenReadinessAddressFamilies();
    void testListenReadinessFailedSearch();
    void testListenReadinessReusesExpiredSearch();
    void testListenReadinessShutdown();
    void testListenReopensSocketAfterNodeExpiration();
    void testUnauthorizedListenFlushClearsListenState();
#endif
};

} // namespace test