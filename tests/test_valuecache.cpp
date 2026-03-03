/*
 *  Copyright (C) 2025 Savoir-faire Linux Inc.
 *
 *  Author: GitHub Copilot
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

#include "test_valuecache.h"
#include "../src/value_cache.h"

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(ValueCacheTester);

void
ValueCacheTester::setUp()
{}

void
ValueCacheTester::tearDown()
{}

void
ValueCacheTester::testUpdate()
{
    int addCount = 0;
    dht::ValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (!expired)
            addCount += vals.size();
    });

    dht::TypeStore types;

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 1;
    v1->seq = 1;
    v1->data = {'A'};

    auto v2 = std::make_shared<dht::Value>();
    v2->id = 1;
    v2->seq = 2;
    v2->data = {'B'};

    auto now = std::chrono::steady_clock::now();

    // Add v1
    cache.onValues({v1}, {}, {}, types, now);
    CPPUNIT_ASSERT_EQUAL(1, addCount);

    // Update v1 -> v2
    cache.onValues({v2}, {}, {}, types, now);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Callback should be called for update", 2, addCount);
}

void
ValueCacheTester::testUpdateExpiration()
{
    int addCount = 0;
    int expireCount = 0;
    dht::ValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (expired)
            expireCount += vals.size();
        else
            addCount += vals.size();
    });

    dht::TypeStore types;

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 1;
    v1->seq = 1;
    v1->data = {'A'};

    auto v2 = std::make_shared<dht::Value>();
    v2->id = 1;
    v2->seq = 2;
    v2->data = {'B'};

    auto now = std::chrono::steady_clock::now();

    // Add v1
    cache.onValues({v1}, {}, {}, types, now);
    CPPUNIT_ASSERT_EQUAL(1, addCount);
    CPPUNIT_ASSERT_EQUAL(0, expireCount);

    // Update v1 -> v2
    cache.onValues({v2}, {}, {}, types, now);
    CPPUNIT_ASSERT_EQUAL(2, addCount);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Old value should be expired on update", 1, expireCount);
}

void
ValueCacheTester::testExpiration()
{
    int expireCount = 0;
    dht::ValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (expired)
            expireCount += vals.size();
    });

    dht::TypeStore types;
    auto v1 = std::make_shared<dht::Value>();
    v1->id = 10;
    v1->data = {'A'};

    // Default expiration is 10 minutes
    auto now = std::chrono::steady_clock::now();
    cache.onValues({v1}, {}, {}, types, now);

    // Advance time past expiration
    auto future = now + std::chrono::minutes(11);

    // expireValues returns next expiration time
    cache.expireValues(future);

    CPPUNIT_ASSERT_EQUAL(1, expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

void
ValueCacheTester::testRefresh()
{
    int expireCount = 0;
    dht::ValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (expired)
            expireCount += vals.size();
    });

    dht::TypeStore types;
    auto v1 = std::make_shared<dht::Value>();
    v1->id = 20;
    v1->data = {'B'};

    auto now = std::chrono::steady_clock::now();
    cache.onValues({v1}, {}, {}, types, now);

    // Refresh at +5 mins
    auto later = now + std::chrono::minutes(5);
    cache.onValues({}, {v1->id}, {}, types, later);

    // Should not expire at +11 mins (original expiration was +10, so +10 from start)
    // But refresh should extend it to +10 from 'later' = +15 from start.

    auto checkTime = now + std::chrono::minutes(11);
    cache.expireValues(checkTime);

    CPPUNIT_ASSERT_EQUAL(0, expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());

    // Should expire at +16 mins
    auto future = now + std::chrono::minutes(16);
    cache.expireValues(future);
    CPPUNIT_ASSERT_EQUAL(1, expireCount);
}

void
ValueCacheTester::testExplicitExpiration()
{
    int expireCount = 0;
    dht::ValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (expired)
            expireCount += vals.size();
    });

    dht::TypeStore types;
    auto v1 = std::make_shared<dht::Value>();
    v1->id = 30;
    v1->data = {'C'};

    auto now = std::chrono::steady_clock::now();
    cache.onValues({v1}, {}, {}, types, now);

    cache.onValues({}, {}, {v1->id}, types, now);

    CPPUNIT_ASSERT_EQUAL(1, expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

void
ValueCacheTester::testClear()
{
    dht::ValueCache cache([](const std::vector<std::shared_ptr<dht::Value>>&, bool) {});
    dht::TypeStore types;
    auto now = std::chrono::steady_clock::now();

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 1;
    auto v2 = std::make_shared<dht::Value>();
    v2->id = 2;

    cache.onValues({v1, v2}, {}, {}, types, now);
    CPPUNIT_ASSERT_EQUAL((size_t) 2, cache.size());

    auto cbs = cache.clear();
    // Execute callbacks
    for (auto& cb : cbs)
        cb();

    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

void
ValueCacheTester::testSyncStatus()
{
    std::vector<dht::ListenSyncStatus> statuses;
    {
        dht::ValueCache cache([](const std::vector<std::shared_ptr<dht::Value>>&, bool) {},
                              [&](dht::ListenSyncStatus status) { statuses.push_back(status); });

        CPPUNIT_ASSERT_EQUAL((size_t) 1, statuses.size());
        CPPUNIT_ASSERT(statuses.back() == dht::ListenSyncStatus::ADDED);

        cache.onSynced(true);
        CPPUNIT_ASSERT_EQUAL((size_t) 2, statuses.size());
        CPPUNIT_ASSERT(statuses.back() == dht::ListenSyncStatus::SYNCED);

        // Calling onSynced(true) again should not trigger the callback
        cache.onSynced(true);
        CPPUNIT_ASSERT_EQUAL((size_t) 2, statuses.size());

        cache.onSynced(false);
        CPPUNIT_ASSERT_EQUAL((size_t) 3, statuses.size());
        CPPUNIT_ASSERT(statuses.back() == dht::ListenSyncStatus::UNSYNCED);

        // Calling onSynced(false) again should not trigger the callback
        cache.onSynced(false);
        CPPUNIT_ASSERT_EQUAL((size_t) 3, statuses.size());

        // Set to synced before destruction to test UNSYNCED on destruction
        cache.onSynced(true);
        CPPUNIT_ASSERT_EQUAL((size_t) 4, statuses.size());
        CPPUNIT_ASSERT(statuses.back() == dht::ListenSyncStatus::SYNCED);
    }

    // Destructor should have been called
    CPPUNIT_ASSERT_EQUAL((size_t) 6, statuses.size());
    CPPUNIT_ASSERT(statuses[4] == dht::ListenSyncStatus::UNSYNCED);
    CPPUNIT_ASSERT(statuses[5] == dht::ListenSyncStatus::REMOVED);
}

void
ValueCacheTester::testMaxValues()
{
    dht::ValueCache cache([](const std::vector<std::shared_ptr<dht::Value>>&, bool) {});
    dht::TypeStore types;
    auto now = std::chrono::steady_clock::now();

    // MAX_VALUES is 4096
    for (int i = 0; i < 4100; ++i) {
        auto v = std::make_shared<dht::Value>();
        v->id = (dht::Value::Id) i + 1;
        cache.onValues({v}, {}, {}, types, now + std::chrono::milliseconds(i));
    }

    // Should be capped at 4096
    CPPUNIT_ASSERT_EQUAL((size_t) 4096, cache.size());
}

void
ValueCacheTester::testUpdateTypeExpiration()
{
    // Test that when a value is updated with a different type, the expiration
    // uses the new type's expiration period, not the old one.
    int addCount = 0;
    int expireCount = 0;
    dht::ValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (expired)
            expireCount += vals.size();
        else
            addCount += vals.size();
    });

    // Register a custom type with a short expiration (2 minutes)
    dht::TypeStore types;
    dht::ValueType shortType(42, "short", std::chrono::minutes(2));
    types.registerType(shortType);

    // Register a custom type with a long expiration (30 minutes)
    dht::ValueType longType(99, "long", std::chrono::minutes(30));
    types.registerType(longType);

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 1;
    v1->type = 42; // short type: 2 min expiration
    v1->data = {'A'};

    auto now = std::chrono::steady_clock::now();

    // Add v1 with short type
    cache.onValues({v1}, {}, {}, types, now);
    CPPUNIT_ASSERT_EQUAL(1, addCount);

    // Update with new type (long expiration)
    auto v2 = std::make_shared<dht::Value>();
    v2->id = 1;
    v2->type = 99; // long type: 30 min expiration
    v2->data = {'B'};

    cache.onValues({v2}, {}, {}, types, now);
    CPPUNIT_ASSERT_EQUAL(2, addCount);

    // At +3 minutes: should NOT be expired (long type has 30 min expiration)
    // Before the fix, the old type (2 min) would be used, causing expiration here
    expireCount = 0;
    auto at3min = now + std::chrono::minutes(3);
    cache.expireValues(at3min);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Value updated to long-expiry type should NOT expire at 3 min", 0, expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());

    // At +31 minutes: should be expired
    auto at31min = now + std::chrono::minutes(31);
    cache.expireValues(at31min);
    CPPUNIT_ASSERT_EQUAL(1, expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

void
ValueCacheTester::testShortExpirationRefreshLost()
{
    // Demonstrates that a value with a short expiration type survives
    // past its nominal expiration when the listen is synced, thanks to
    // a proportional grace period (= typeExpiration).
    //
    // For a 5s type:  effective expiration when synced = expiration + 5s = 10s
    //
    // Scenario:
    //   t=0 : Value V added → nominal expiration t+5s, effective t+10s
    //   t=6 : Past nominal but within grace → alive
    //   t=8 : Refresh arrives → V refreshed → expiration reset to t8+5s, effective t8+10s=t18s
    //   t=14: Still alive (within refreshed effective range)
    //   t=20: No more refreshes → past t8+10s=t18s → expired

    int addCount = 0;
    int expireCount = 0;
    dht::ValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (expired)
            expireCount += vals.size();
        else
            addCount += vals.size();
    });

    // Register a type with a very short expiration (5 seconds)
    dht::TypeStore types;
    dht::ValueType shortType(100, "short_lived", std::chrono::seconds(5));
    types.registerType(shortType);

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 1;
    v1->type = 100;
    v1->data = {'V'};

    auto t0 = std::chrono::steady_clock::now();

    // t=0: Listen response arrives with V
    cache.onValues({v1}, {}, {}, types, t0);
    CPPUNIT_ASSERT_EQUAL(1, addCount);
    CPPUNIT_ASSERT_EQUAL(0, expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());

    // Mark cache as synced (listen is active)
    cache.onSynced(true);

    // t=6: Past nominal 5s expiration, but grace (5s) gives effective 10s
    auto t6 = t0 + std::chrono::seconds(6);
    cache.expireValues(t6);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Value should survive past nominal expiration thanks to proportional grace",
                                 0,
                                 expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());

    // t=8: Value refresh arrives → expiration reset to t8+5s=t13s, effective t8+10s=t18s
    auto t8 = t0 + std::chrono::seconds(8);
    cache.onValues({}, {v1->id}, {}, types, t8);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());

    // t=14: Within refreshed effective range (t18s) → alive
    auto t14 = t0 + std::chrono::seconds(14);
    cache.expireValues(t14);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Value should survive past short expiration after refresh", 0, expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());

    // t=20: No more refreshes → past effective t18s → must expire
    auto t20 = t0 + std::chrono::seconds(20);
    cache.expireValues(t20);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Value must eventually expire even while synced if server stops refreshing",
                                 1,
                                 expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

void
ValueCacheTester::testShortExpirationHighChurn()
{
    // Simulates high churn: multiple rapid add/expire/refresh cycles with
    // short-lived values, verifying the cache stays consistent.

    int addCount = 0;
    int expireCount = 0;
    dht::ValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (expired)
            expireCount += vals.size();
        else
            addCount += vals.size();
    });

    dht::TypeStore types;
    dht::ValueType shortType(101, "fast_churn", std::chrono::seconds(3));
    types.registerType(shortType);

    auto now = std::chrono::steady_clock::now();

    // Simulate 10 churn cycles: add value, advance time, refresh, advance, expire
    for (int cycle = 0; cycle < 10; cycle++) {
        auto v = std::make_shared<dht::Value>();
        v->id = static_cast<dht::Value::Id>(500 + cycle);
        v->type = 101;
        v->data = {static_cast<uint8_t>('A' + cycle)};

        auto t = now + std::chrono::seconds(cycle * 10);

        // Add the value
        cache.onValues({v}, {}, {}, types, t);

        // Refresh halfway through
        auto tRefresh = t + std::chrono::seconds(2);
        cache.onValues({}, {v->id}, {}, types, tRefresh);

        // Explicit expire from server
        auto tExpire = t + std::chrono::seconds(8);
        cache.onValues({}, {}, {v->id}, types, tExpire);
    }

    // All 10 values were added and explicitly expired
    CPPUNIT_ASSERT_EQUAL(10, addCount);
    CPPUNIT_ASSERT_EQUAL(10, expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

void
ValueCacheTester::testNoTimeExpirationWhileSynced()
{
    // Verify that when the listen is synced, the proportional grace period
    // (= typeExpiration) delays time-based expiration but doesn't prevent
    // it entirely.  For a 2s type: effective expiration = 2s + 2s = 4s.

    int expireCount = 0;
    dht::ValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (expired)
            expireCount += vals.size();
    });

    dht::TypeStore types;
    dht::ValueType shortType(110, "short", std::chrono::seconds(2));
    types.registerType(shortType);

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 1;
    v1->type = 110;
    v1->data = {'X'};

    auto t0 = std::chrono::steady_clock::now();
    cache.onValues({v1}, {}, {}, types, t0);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());

    // Mark as synced
    cache.onSynced(true);

    // t=3: Past nominal 2s, within effective 4s → grace protects
    auto t3 = t0 + std::chrono::seconds(3);
    cache.expireValues(t3);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Synced cache: grace period should prevent early expiry", 0, expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());

    // t=5: Past effective 4s (2s + 2s grace) → must expire
    auto t5 = t0 + std::chrono::seconds(5);
    cache.expireValues(t5);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Synced cache: value must eventually expire after grace period", 1, expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

void
ValueCacheTester::testUnsyncExpiresImmediately()
{
    // When the cache goes from synced to unsynced, the grace period is
    // removed and already-past-due values expire on the next check.
    // Type expiration = 5s. Grace when synced = 5s → effective = 10s.

    int expireCount = 0;
    dht::ValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (expired)
            expireCount += vals.size();
    });

    dht::TypeStore types;
    dht::ValueType shortType(120, "short", std::chrono::seconds(5));
    types.registerType(shortType);

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 1;
    v1->type = 120;
    v1->data = {'U'};

    auto t0 = std::chrono::steady_clock::now();
    cache.onValues({v1}, {}, {}, types, t0);
    cache.onSynced(true);

    // t=7: past nominal 5s, within effective 10s while synced → alive
    auto t7 = t0 + std::chrono::seconds(7);
    cache.expireValues(t7);
    CPPUNIT_ASSERT_EQUAL(0, expireCount);

    // Now unsync (node went away / connectivity loss)
    cache.onSynced(false);

    // Same time point t=7: past nominal 5s, no grace → expires
    cache.expireValues(t7);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Unsynced cache should immediately expire past-due values", 1, expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

} // namespace test
