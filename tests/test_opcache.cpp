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

#include "test_opcache.h"

// Hack to test internal class
#include "../src/op_cache.cpp"

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(OpCacheTester);

void
OpCacheTester::setUp()
{}

void
OpCacheTester::tearDown()
{}

void
OpCacheTester::testUpdateRefCount()
{
    dht::OpValueCache cache([](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; });

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 1;
    v1->seq = 1;
    std::string data1 = "data1";
    v1->data = {data1.begin(), data1.end()};

    auto v2 = std::make_shared<dht::Value>();
    v2->id = 1;
    v2->seq = 2;
    std::string data2 = "data2";
    v2->data = {data2.begin(), data2.end()};

    // Add v1
    cache.onValuesAdded({v1});
    // Should have 1 value
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());
    auto stored = cache.get(1);
    CPPUNIT_ASSERT(stored);
    CPPUNIT_ASSERT_EQUAL(v1->seq, stored->seq);

    // Add v2 (update)
    cache.onValuesAdded({v2});
    // Should still have 1 value (updated)
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());
    stored = cache.get(1);
    CPPUNIT_ASSERT(stored);
    CPPUNIT_ASSERT_EQUAL(v2->seq, stored->seq);

    // Now expire v1
    // Note: onValuesExpired uses ID to find value.
    cache.onValuesExpired({v1});

    // If refCount was incremented on update, we should still have the value (refCount=1).
    // If not, it will be removed (refCount=0).

    // Check if value exists
    stored = cache.get(1);

    // This assertion will fail if the bug exists
    CPPUNIT_ASSERT_MESSAGE("Value should still exist after expiring one source", stored != nullptr);

    if (stored) {
        CPPUNIT_ASSERT_EQUAL(v2->seq, stored->seq);
    }

    // Expire v2
    cache.onValuesExpired({v2});
    stored = cache.get(1);
    CPPUNIT_ASSERT_MESSAGE("Value should be removed after expiring all sources", stored == nullptr);
}

void
OpCacheTester::testBasicAddExpire()
{
    dht::OpValueCache cache([](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; });

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 10;
    v1->data = {'A'};

    cache.onValuesAdded({v1});
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());
    CPPUNIT_ASSERT(cache.get(10));

    std::vector<dht::Value::Id> ids = {v1->id};
    cache.onValuesExpired(ids);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
    CPPUNIT_ASSERT(!cache.get(10));
}

void
OpCacheTester::testMultipleSources()
{
    dht::OpValueCache cache([](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; });

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 20;
    v1->data = {'B'};

    // Add same value twice (simulating two sources)
    cache.onValuesAdded({v1});
    cache.onValuesAdded({v1});

    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());

    // Expire once
    cache.onValuesExpired({v1});
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());
    CPPUNIT_ASSERT(cache.get(20));

    // Expire twice
    cache.onValuesExpired({v1});
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

void
OpCacheTester::testUpdateSequence()
{
    dht::OpValueCache cache([](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; });

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 30;
    v1->seq = 10;
    v1->data = {'C'};

    auto v2 = std::make_shared<dht::Value>();
    v2->id = 30;
    v2->seq = 20;
    v2->data = {'D'};

    auto v3 = std::make_shared<dht::Value>();
    v3->id = 30;
    v3->seq = 5;
    v3->data = {'E'};

    // Add seq 10
    cache.onValuesAdded({v1});
    auto stored = cache.get(30);
    CPPUNIT_ASSERT_EQUAL((uint16_t) 10, stored->seq);

    // Add seq 20 (update)
    cache.onValuesAdded({v2});
    stored = cache.get(30);
    CPPUNIT_ASSERT_EQUAL((uint16_t) 20, stored->seq);

    // Add seq 5 (older, should not update content but increment refCount)
    cache.onValuesAdded({v3});
    stored = cache.get(30);
    CPPUNIT_ASSERT_EQUAL((uint16_t) 20, stored->seq);

    // We added 3 times. Should need 3 expires to remove.
    cache.onValuesExpired({v1}); // 2 left
    CPPUNIT_ASSERT(cache.get(30));
    cache.onValuesExpired({v2}); // 1 left
    CPPUNIT_ASSERT(cache.get(30));
    cache.onValuesExpired({v3}); // 0 left
    CPPUNIT_ASSERT(!cache.get(30));
}

void
OpCacheTester::testCallbacks()
{
    int addCount = 0;
    int expireCount = 0;
    dht::OpValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (expired)
            expireCount += vals.size();
        else
            addCount += vals.size();
        return true;
    });

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 40;

    cache.onValuesAdded({v1});
    CPPUNIT_ASSERT_EQUAL(1, addCount);
    CPPUNIT_ASSERT_EQUAL(0, expireCount);

    // Adding same value again should NOT trigger callback (no new value added)
    // Wait, looking at code:
    // if (viop.second) { newValues.emplace_back(v); } ...
    // return newValues.empty() ? true : callback(newValues, false);
    // So if it's a duplicate or update, does it callback?
    // If update: newValues.emplace_back(v) IS called.
    // If duplicate (refCount++ only): newValues is NOT added.

    cache.onValuesAdded({v1});
    CPPUNIT_ASSERT_EQUAL(1, addCount); // Should still be 1

    auto v2 = std::make_shared<dht::Value>();
    v2->id = 40;
    v2->seq = 100;              // Update
    v2->data = {'M', 'O', 'D'}; // Change data to ensure inequality

    cache.onValuesAdded({v2});
    CPPUNIT_ASSERT_EQUAL(2, addCount); // Should be 2 now (update triggers callback)

    cache.onValuesExpired({v1});
    CPPUNIT_ASSERT_EQUAL(0, expireCount); // RefCount dec, not removed yet

    cache.onValuesExpired({v1});
    CPPUNIT_ASSERT_EQUAL(0, expireCount); // RefCount dec, not removed yet

    cache.onValuesExpired({v1});
    CPPUNIT_ASSERT_EQUAL(1, expireCount); // Removed now
}

void
OpCacheTester::testFilters()
{
    dht::OpValueCache cache([](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; });

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 50;
    v1->type = 1;

    auto v2 = std::make_shared<dht::Value>();
    v2->id = 51;
    v2->type = 2;

    cache.onValuesAdded({v1, v2});

    auto f1 = dht::Value::TypeFilter(1);
    auto res1 = cache.get(f1);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, res1.size());
    CPPUNIT_ASSERT_EQUAL(v1->id, res1[0]->id);

    auto f2 = dht::Value::TypeFilter(2);
    auto res2 = cache.get(f2);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, res2.size());
    CPPUNIT_ASSERT_EQUAL(v2->id, res2[0]->id);

    auto all = cache.getValues();
    CPPUNIT_ASSERT_EQUAL((size_t) 2, all.size());
}

void
OpCacheTester::testSyncStatus()
{
    dht::OpValueCache cache([](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; });

    // Initial state
    CPPUNIT_ASSERT(!cache.isSynced());

    // Add a node
    cache.onNodeChanged(dht::ListenSyncStatus::ADDED);
    // 1 node, 0 synced -> not synced
    CPPUNIT_ASSERT(!cache.isSynced());

    // Sync the node
    cache.onNodeChanged(dht::ListenSyncStatus::SYNCED);
    // 1 node, 1 synced -> synced
    CPPUNIT_ASSERT(cache.isSynced());

    // Add another node
    cache.onNodeChanged(dht::ListenSyncStatus::ADDED);
    // 2 nodes, 1 synced -> not synced
    CPPUNIT_ASSERT(!cache.isSynced());

    // Sync second node
    cache.onNodeChanged(dht::ListenSyncStatus::SYNCED);
    // 2 nodes, 2 synced -> synced
    CPPUNIT_ASSERT(cache.isSynced());

    // Unsync one
    cache.onNodeChanged(dht::ListenSyncStatus::UNSYNCED);
    CPPUNIT_ASSERT(!cache.isSynced());

    // Remove one (the unsynced one)
    cache.onNodeChanged(dht::ListenSyncStatus::REMOVED);
    // 1 node, 1 synced -> synced
    CPPUNIT_ASSERT(cache.isSynced());
}

void
OpCacheTester::testGetWhileSynced()
{
    // Test that get() on a SearchCache with a synced listen returns cached values
    // and completes the get (returns true) without causing duplicate delivery.
    dht::SearchCache searchCache;

    int getCallCount = 0;
    bool doneCalled = false;
    bool doneSuccess = false;

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 100;
    v1->data = {'X'};
    auto v2 = std::make_shared<dht::Value>();
    v2->id = 101;
    v2->data = {'Y'};

    auto query = std::make_shared<dht::Query>();

    // Start a listen
    size_t listenToken = searchCache.listen([](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; },
                                            query,
                                            {},
                                            [&](const std::shared_ptr<dht::Query>& q,
                                                dht::ValueCallback vcb,
                                                dht::SyncCallback scb) -> size_t {
                                                // Simulate node added and synced
                                                scb(dht::ListenSyncStatus::ADDED);
                                                // Inject values
                                                vcb({v1, v2}, false);
                                                // Mark as synced
                                                scb(dht::ListenSyncStatus::SYNCED);
                                                return 1;
                                            });
    CPPUNIT_ASSERT(listenToken != 0);

    // Now perform a get on the synced cache
    bool result = searchCache.get(
        {},
        query,
        [&](const std::vector<std::shared_ptr<dht::Value>>& vals) {
            getCallCount++;
            CPPUNIT_ASSERT_EQUAL((size_t) 2, vals.size());
            return true;
        },
        [&](bool success, const std::vector<std::shared_ptr<dht::Node>>&) {
            doneCalled = true;
            doneSuccess = success;
        });

    // get should be served from cache
    CPPUNIT_ASSERT_MESSAGE("get() should return true when cache is synced", result);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("get callback should be called exactly once", 1, getCallCount);
    CPPUNIT_ASSERT_MESSAGE("done callback should be called", doneCalled);
    CPPUNIT_ASSERT_MESSAGE("done callback should indicate success", doneSuccess);
}

void
OpCacheTester::testGetWhileNotSynced()
{
    // Test that get() on a SearchCache with a non-synced listen does NOT call gcb
    // (to prevent duplicate delivery when the network get completes later).
    dht::SearchCache searchCache;

    int getCallCount = 0;
    bool doneCalled = false;

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 200;
    v1->data = {'A'};

    auto query = std::make_shared<dht::Query>();

    // Start a listen but DON'T mark as synced
    size_t listenToken = searchCache.listen([](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; },
                                            query,
                                            {},
                                            [&](const std::shared_ptr<dht::Query>& q,
                                                dht::ValueCallback vcb,
                                                dht::SyncCallback scb) -> size_t {
                                                // Node added but NOT synced
                                                scb(dht::ListenSyncStatus::ADDED);
                                                // Inject a value
                                                vcb({v1}, false);
                                                // NOT calling scb(SYNCED) — listen is not synced
                                                return 1;
                                            });
    CPPUNIT_ASSERT(listenToken != 0);

    // Now perform a get on the non-synced cache
    bool result = searchCache.get(
        {},
        query,
        [&](const std::vector<std::shared_ptr<dht::Value>>& vals) {
            getCallCount++;
            return true;
        },
        [&](bool success, const std::vector<std::shared_ptr<dht::Node>>&) { doneCalled = true; });

    // get should NOT be served from cache (not synced)
    CPPUNIT_ASSERT_MESSAGE("get() should return false when cache is not synced", !result);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("get callback should NOT be called (would cause duplicates)", 0, getCallCount);
    CPPUNIT_ASSERT_MESSAGE("done callback should NOT be called", !doneCalled);
}

void
OpCacheTester::testGetEmptySynced()
{
    // Test that get() on a synced but empty cache calls dcb but not gcb.
    dht::SearchCache searchCache;

    int getCallCount = 0;
    bool doneCalled = false;
    bool doneSuccess = false;

    auto query = std::make_shared<dht::Query>();

    // Start a listen, inject no values, mark as synced
    size_t listenToken = searchCache.listen([](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; },
                                            query,
                                            {},
                                            [&](const std::shared_ptr<dht::Query>& q,
                                                dht::ValueCallback vcb,
                                                dht::SyncCallback scb) -> size_t {
                                                scb(dht::ListenSyncStatus::ADDED);
                                                scb(dht::ListenSyncStatus::SYNCED);
                                                return 1;
                                            });
    CPPUNIT_ASSERT(listenToken != 0);

    bool result = searchCache.get(
        {},
        query,
        [&](const std::vector<std::shared_ptr<dht::Value>>& vals) {
            getCallCount++;
            return true;
        },
        [&](bool success, const std::vector<std::shared_ptr<dht::Node>>&) {
            doneCalled = true;
            doneSuccess = success;
        });

    // Synced + empty: get should succeed but gcb should not be called
    CPPUNIT_ASSERT_MESSAGE("get() should return true when cache is synced (even if empty)", result);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("get callback should NOT be called (no values)", 0, getCallCount);
    CPPUNIT_ASSERT_MESSAGE("done callback should be called", doneCalled);
    CPPUNIT_ASSERT_MESSAGE("done callback should indicate success", doneSuccess);
}

void
OpCacheTester::testValueExpirationDuringListen()
{
    // Test that values correctly expire via refCount during listen with multiple sources.
    dht::OpValueCache cache([](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; });

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 300;
    v1->data = {'D'};

    // Simulate two nodes reporting the same value
    cache.onNodeChanged(dht::ListenSyncStatus::ADDED);
    cache.onNodeChanged(dht::ListenSyncStatus::ADDED);

    cache.onValuesAdded({v1}); // source 1
    cache.onValuesAdded({v1}); // source 2

    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());
    CPPUNIT_ASSERT(cache.get(300) != nullptr);

    // Expire from source 1 — value should stay (refCount = 1)
    cache.onValuesExpired({v1});
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());
    CPPUNIT_ASSERT(cache.get(300) != nullptr);

    // Expire from source 2 — value should be removed (refCount = 0)
    cache.onValuesExpired({v1});
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
    CPPUNIT_ASSERT(cache.get(300) == nullptr);
}

void
OpCacheTester::testTimestampOrdering()
{
    // Test that expired values with timestamps older than the last update are ignored.
    dht::OpValueCache cache([](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; });

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 400;
    v1->data = {'T'};

    auto t1 = std::chrono::system_clock::now();
    auto t2 = t1 + std::chrono::seconds(10);

    // Add value at time t2
    cache.onValue({v1}, false, t2);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());

    // Try to expire at time t1 (older) — should be ignored
    cache.onValue({v1}, true, t1);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Stale expiration should be ignored", (size_t) 1, cache.size());
    CPPUNIT_ASSERT(cache.get(400) != nullptr);

    // Expire at time t2 — should succeed
    cache.onValue({v1}, true, t2);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

} // namespace test
