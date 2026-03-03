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

} // namespace test
