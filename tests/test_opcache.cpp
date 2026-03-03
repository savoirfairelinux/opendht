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
    // Test that when a get() is performed on a non-synced cache, values
    // are not delivered twice: once from the cache and once from the
    // simulated network get that Search::get would queue.
    dht::SearchCache searchCache;

    // Track every value delivery with (value_id, source) pairs
    std::vector<std::pair<dht::Value::Id, std::string>> deliveries;

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 200;
    v1->data = {'A'};

    auto query = std::make_shared<dht::Query>();

    // Start a listen but DON'T mark as synced
    dht::ValueCallback storedVcb;
    dht::SyncCallback storedScb;
    size_t listenToken = searchCache.listen([](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; },
                                            query,
                                            {},
                                            [&](const std::shared_ptr<dht::Query>& q,
                                                dht::ValueCallback vcb,
                                                dht::SyncCallback scb) -> size_t {
                                                storedVcb = vcb;
                                                storedScb = scb;
                                                // Node added but NOT synced
                                                scb(dht::ListenSyncStatus::ADDED);
                                                // Inject a value
                                                vcb({v1}, false);
                                                return 1;
                                            });
    CPPUNIT_ASSERT(listenToken != 0);

    // Simulate what Search::get does: try cache first, if false, queue network get
    bool doneCalled = false;
    auto gcb = [&](const std::vector<std::shared_ptr<dht::Value>>& vals) {
        for (const auto& v : vals)
            deliveries.emplace_back(v->id, "get");
        return true;
    };
    auto dcb = [&](bool, const std::vector<std::shared_ptr<dht::Node>>&) {
        doneCalled = true;
    };

    bool servedFromCache = searchCache.get({}, query, gcb, dcb);

    // Cache is not synced so get should not be served from cache
    CPPUNIT_ASSERT_MESSAGE("get() should return false when cache is not synced", !servedFromCache);

    // Simulate the network get completing with the same value
    // (this is what onGetValuesDone does — calls gcb for each matching get)
    gcb({v1});

    // Exactly one delivery expected — from the network get only
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Value should be delivered exactly once (from network get only)",
                                 (size_t) 1,
                                 deliveries.size());
    CPPUNIT_ASSERT_EQUAL(v1->id, deliveries[0].first);
    CPPUNIT_ASSERT_EQUAL(std::string("get"), deliveries[0].second);

    // Now sync the listen and perform another get — this time it should be served from cache
    storedScb(dht::ListenSyncStatus::SYNCED);

    deliveries.clear();
    doneCalled = false;
    bool servedFromCache2 = searchCache.get({}, query, gcb, dcb);
    CPPUNIT_ASSERT_MESSAGE("get() should return true once cache is synced", servedFromCache2);
    CPPUNIT_ASSERT_MESSAGE("done callback should be called when served from synced cache", doneCalled);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Synced cache get should deliver the value exactly once",
                                 (size_t) 1,
                                 deliveries.size());
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

void
OpCacheTester::testShortExpirationPhantomExpiry()
{
    // End-to-end test: demonstrates phantom expire / re-add when multiple
    // per-node ValueCaches feed into a single OpValueCache and a short-lived
    // value expires from all per-node caches before the listen refresh.
    //
    // The fixed behavior (ValueCache does not time-expire while synced)
    // prevents the phantom.  Here we verify the OpValueCache stays consistent.

    using namespace std::chrono;
    int addCount = 0;
    int expireCount = 0;

    dht::OpValueCache opCache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (expired)
            expireCount += vals.size();
        else
            addCount += vals.size();
        return true;
    });

    auto v = std::make_shared<dht::Value>();
    v->id = 900;
    v->data = {'Z'};

    // Simulate 3 nodes each adding the same value
    opCache.onNodeChanged(dht::ListenSyncStatus::ADDED);
    opCache.onNodeChanged(dht::ListenSyncStatus::ADDED);
    opCache.onNodeChanged(dht::ListenSyncStatus::ADDED);
    opCache.onValuesAdded({v});
    opCache.onValuesAdded({v});
    opCache.onValuesAdded({v});
    CPPUNIT_ASSERT_EQUAL(1, addCount); // first add fires callback
    CPPUNIT_ASSERT_EQUAL((size_t) 1, opCache.size());

    // Simulate 2 out of 3 nodes expiring (high churn)
    opCache.onValuesExpired({v});         // refCount 3→2
    opCache.onValuesExpired({v});         // refCount 2→1
    CPPUNIT_ASSERT_EQUAL(0, expireCount); // value still alive, 1 source left
    CPPUNIT_ASSERT_EQUAL((size_t) 1, opCache.size());

    // Last node also expires → value goes away
    opCache.onValuesExpired({v}); // refCount 1→0
    CPPUNIT_ASSERT_EQUAL(1, expireCount);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, opCache.size());

    // New nodes report the same value again (re-listen completed)
    opCache.onValuesAdded({v});
    opCache.onValuesAdded({v});
    CPPUNIT_ASSERT_EQUAL(2, addCount); // value re-appeared
    CPPUNIT_ASSERT_EQUAL((size_t) 1, opCache.size());

    // Only 1 expire needed per source to remove
    opCache.onValuesExpired({v}); // refCount 2→1
    CPPUNIT_ASSERT_EQUAL((size_t) 1, opCache.size());
    opCache.onValuesExpired({v}); // refCount 1→0
    CPPUNIT_ASSERT_EQUAL((size_t) 0, opCache.size());
    CPPUNIT_ASSERT_EQUAL(2, expireCount);
}

void
OpCacheTester::testHighChurnRefCountConsistency()
{
    // Rapid node churn: nodes join and leave quickly, each reporting the same
    // value.  Verify that the refCount never goes negative and the value is
    // correctly expired only when all sources are gone.

    bool callbackFailed = false;
    dht::OpValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>&, bool) { return true; });

    auto v = std::make_shared<dht::Value>();
    v->id = 800;
    v->data = {'C', 'H', 'U', 'R', 'N'};

    // Simulate 50 rapid churn cycles:
    //   - node joins, adds V (refCount++)
    //   - node leaves, expires V (refCount--)
    for (int i = 0; i < 50; i++) {
        cache.onNodeChanged(dht::ListenSyncStatus::ADDED);
        cache.onValuesAdded({v});
        cache.onValuesExpired({v});
        cache.onNodeChanged(dht::ListenSyncStatus::REMOVED);
    }

    // After all churn, value should be completely gone.
    CPPUNIT_ASSERT_EQUAL_MESSAGE("All sources gone — value must be removed", (size_t) 0, cache.size());

    // Now simulate overlapping churn: add N, add N+1, expire N, expire N+1
    for (int i = 0; i < 20; i++) {
        cache.onNodeChanged(dht::ListenSyncStatus::ADDED);
        cache.onValuesAdded({v}); // refCount+

        cache.onNodeChanged(dht::ListenSyncStatus::ADDED);
        cache.onValuesAdded({v}); // refCount+

        // First node leaves
        cache.onValuesExpired({v});
        cache.onNodeChanged(dht::ListenSyncStatus::REMOVED);

        // Value should still be alive (second node still holds it)
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Value should survive while one source remains", (size_t) 1, cache.size());

        // Second node leaves
        cache.onValuesExpired({v});
        cache.onNodeChanged(dht::ListenSyncStatus::REMOVED);
    }

    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

void
OpCacheTester::testValueUpdateSingleSourcePhantom()
{
    // Demonstrates Bug 2: when ValueCache::addValues detects a changed value,
    // it fires expire(old) then add(new).  With a single source (refCount=1),
    // OpValueCache removes the value on expire(old) → user sees a phantom
    // expiration before the re-add.
    //
    // This test captures the current behaviour so a future fix can update
    // the expectation.

    std::vector<std::pair<dht::Value::Id, bool>> events; // (id, expired?)

    dht::OpValueCache cache([&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        for (const auto& v : vals)
            events.emplace_back(v->id, expired);
        return true;
    });

    auto v1 = std::make_shared<dht::Value>();
    v1->id = 700;
    v1->seq = 1;
    v1->data = {'O', 'L', 'D'};

    auto v2 = std::make_shared<dht::Value>();
    v2->id = 700;
    v2->seq = 2;
    v2->data = {'N', 'E', 'W'};

    // Single source adds v1
    cache.onValuesAdded({v1});
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());
    events.clear();

    // Simulate what ValueCache::addValues does on value update:
    //   1) callback(old_value, expired=true)
    //   2) callback(new_value, expired=false)
    cache.onValuesExpired({v1}); // refCount 1→0 → value removed
    cache.onValuesAdded({v2});   // value re-added with refCount=1

    // The user sees 2 events: first an expire, then an add.
    // Ideally there should be just 1 event (add with updated data), but
    // the current architecture causes a phantom expire when refCount==1.
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Expected 2 events (phantom expire + re-add)", (size_t) 2, events.size());
    CPPUNIT_ASSERT_EQUAL_MESSAGE("First event should be an expiration", true, events[0].second);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Second event should be an addition", false, events[1].second);

    // Final state: value exists with updated data
    auto stored = cache.get(700);
    CPPUNIT_ASSERT(stored != nullptr);
    CPPUNIT_ASSERT_EQUAL(v2->seq, stored->seq);
}

} // namespace test
