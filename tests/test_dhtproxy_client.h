// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class DhtProxyClientTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(DhtProxyClientTester);
    CPPUNIT_TEST(testResubscribeUsesKeyRoute);
    CPPUNIT_TEST(testSetPushNotificationTokenResubscribesWithNewToken);
    CPPUNIT_TEST(testRestartListenersFetchesValuesAfterFailedSubscribe);
    CPPUNIT_TEST(testReadinessShutdown);
    CPPUNIT_TEST(testReadinessReentrancy);
    CPPUNIT_TEST(testReadinessCancelsAnotherListener);
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    CPPUNIT_TEST(testInitialReadinessFailures);
    CPPUNIT_TEST(testReadinessRecoveryIsOneShot);
    CPPUNIT_TEST(testWrongSessionPushDoesNotTouchSubscriptions);
    CPPUNIT_TEST(testNewSessionSynchronizesIndependently);
    CPPUNIT_TEST(testFailedTimerRetryFetchesValues);
    CPPUNIT_TEST(testFullRetryRemovesAbsentValues);
    CPPUNIT_TEST(testStreamingFallbackExpiresSnapshot);
    CPPUNIT_TEST(testLateRetryResponseDoesNotResurrectExpiredValue);
    CPPUNIT_TEST(testTruncatedRecoveryRemainsFailed);
    CPPUNIT_TEST(testTruncatedRecoveryAtEofFails);
    CPPUNIT_TEST(testMissingCompletionDoesNotReconcile);
    CPPUNIT_TEST(testSnapshotExpirationIgnoresClockRollback);
    CPPUNIT_TEST(testSupersededFailureDoesNotPoisonSuccessfulRetry);
    CPPUNIT_TEST(testSyncCoalescesConnectivityChanges);
    CPPUNIT_TEST(testTokenRotationDuringRecovery);
    CPPUNIT_TEST(testTokenRotationBackToPreviousEpoch);
    CPPUNIT_TEST(testAuthoritativeEpochAfterStalePush);
    CPPUNIT_TEST(testSyncEditsAndDuplicateValues);
    CPPUNIT_TEST(testIncompleteSnapshotDoesNotReconcile);
    CPPUNIT_TEST(testSubscriptionDeadline);
    CPPUNIT_TEST(testInvalidPushRevision);
    CPPUNIT_TEST(testRecoveryBackoff);
    CPPUNIT_TEST(testContiguousExpiration);
    CPPUNIT_TEST(testLegacyPushValidatesRevisions);
#endif
    CPPUNIT_TEST_SUITE_END();

public:
    void testResubscribeUsesKeyRoute();
    void testSetPushNotificationTokenResubscribesWithNewToken();
    void testRestartListenersFetchesValuesAfterFailedSubscribe();
    void testReadinessShutdown();
    void testReadinessReentrancy();
    void testReadinessCancelsAnotherListener();
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    void testInitialReadinessFailures();
    void testReadinessRecoveryIsOneShot();
    void testWrongSessionPushDoesNotTouchSubscriptions();
    void testNewSessionSynchronizesIndependently();
    void testFailedTimerRetryFetchesValues();
    void testFullRetryRemovesAbsentValues();
    void testStreamingFallbackExpiresSnapshot();
    void testLateRetryResponseDoesNotResurrectExpiredValue();
    void testTruncatedRecoveryRemainsFailed();
    void testTruncatedRecoveryAtEofFails();
    void testMissingCompletionDoesNotReconcile();
    void testSnapshotExpirationIgnoresClockRollback();
    void testSupersededFailureDoesNotPoisonSuccessfulRetry();
    void testSyncCoalescesConnectivityChanges();
    void testTokenRotationDuringRecovery();
    void testTokenRotationBackToPreviousEpoch();
    void testAuthoritativeEpochAfterStalePush();
    void testSyncEditsAndDuplicateValues();
    void testIncompleteSnapshotDoesNotReconcile();
    void testSubscriptionDeadline();
    void testInvalidPushRevision();
    void testRecoveryBackoff();
    void testContiguousExpiration();
    void testLegacyPushValidatesRevisions();
#endif
};

} // namespace test