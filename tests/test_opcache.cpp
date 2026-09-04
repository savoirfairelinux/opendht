// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_opcache.h"

// Hack to test internal class
#include "../src/op_cache.cpp"

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(OpCacheTester);

namespace {

using Values = std::vector<std::shared_ptr<dht::Value>>;

struct Event
{
    dht::Value::Id id;
    uint16_t seq;
    bool expired;
};

std::shared_ptr<dht::Value>
makeValue(dht::Value::Id id, uint16_t seq, std::string data)
{
    auto v = std::make_shared<dht::Value>();
    v->id = id;
    v->seq = seq;
    v->data = {data.begin(), data.end()};
    return v;
}

dht::ValueCallback
recordEvents(std::vector<Event>& events)
{
    return [&events](const Values& vals, bool expired) {
        for (const auto& v : vals)
            events.push_back({v->id, v->seq, expired});
        return true;
    };
}

unsigned
count(const std::vector<Event>& events, bool expired)
{
    unsigned n = 0;
    for (const auto& e : events)
        if (e.expired == expired)
            n++;
    return n;
}

} // namespace

void
OpCacheTester::setUp()
{}

void
OpCacheTester::tearDown()
{}

void
OpCacheTester::testBasicAddExpire()
{
    dht::OpValueCache cache([](const Values&, bool) { return true; });

    auto v1 = makeValue(10, 0, "A");
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
    // Two sources report the same value: it must survive until both have
    // expired it, and the user must see exactly one add and one expire.
    std::vector<Event> events;
    dht::OpValueCache cache(recordEvents(events));

    auto v = makeValue(20, 0, "B");
    cache.onValuesAdded({v}); // source A
    cache.onValuesAdded({v}); // source B
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());
    CPPUNIT_ASSERT_EQUAL(1u, count(events, false));

    cache.onValuesExpired({v}); // source A goes away
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Value still held by source B", (size_t) 1, cache.size());
    CPPUNIT_ASSERT_EQUAL(0u, count(events, true));

    cache.onValuesExpired({v}); // source B goes away
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
    CPPUNIT_ASSERT_EQUAL(1u, count(events, true));
}

void
OpCacheTester::testEditResetsRefCount()
{
    // A and B hold v1. A reports the edit v2: only A is known to hold v2, so
    // the refcount restarts at 1. B then confirms v2 (refcount 2).
    std::vector<Event> events;
    dht::OpValueCache cache(recordEvents(events));

    auto v1 = makeValue(1, 1, "data1");
    auto v2 = makeValue(1, 2, "data2");

    cache.onValuesAdded({v1}); // A
    cache.onValuesAdded({v1}); // B
    cache.onValuesAdded({v2}); // A edits
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());
    CPPUNIT_ASSERT_EQUAL(v2->seq, cache.get(1)->seq);
    CPPUNIT_ASSERT_EQUAL(2u, count(events, false));

    cache.onValuesExpired({v2}); // A expires v2 -> nobody known to hold it
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Edit reset the refcount to the editing source", (size_t) 0, cache.size());
    CPPUNIT_ASSERT_EQUAL(1u, count(events, true));

    // Same scenario, but B confirms v2 before A expires it.
    events.clear();
    cache.onValuesAdded({v1}); // A
    cache.onValuesAdded({v1}); // B
    cache.onValuesAdded({v2}); // A edits
    cache.onValuesAdded({v2}); // B confirms
    cache.onValuesExpired({v2});
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Still held by B", (size_t) 1, cache.size());
    cache.onValuesExpired({v2});
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
    CPPUNIT_ASSERT_EQUAL(2u, count(events, false));
    CPPUNIT_ASSERT_EQUAL(1u, count(events, true));
}

void
OpCacheTester::testEditChainMultiSource()
{
    // Rapid edit chain seen from two sources with interleaving: the user
    // must see each version once as an add and a single final expire.
    std::vector<Event> events;
    dht::OpValueCache cache(recordEvents(events));

    auto v1 = makeValue(7, 1, "v1");
    auto v2 = makeValue(7, 2, "v2");
    auto v3 = makeValue(7, 3, "v3");

    cache.onValuesAdded({v1}); // A
    cache.onValuesAdded({v1}); // B
    cache.onValuesAdded({v2}); // A
    cache.onValuesAdded({v3}); // A (B skipped v2)
    cache.onValuesAdded({v2}); // B, late and stale: ignored
    cache.onValuesAdded({v3}); // B
    CPPUNIT_ASSERT_EQUAL(3u, count(events, false));
    CPPUNIT_ASSERT_EQUAL((uint16_t) 3, cache.get(7)->seq);

    cache.onValuesExpired({v3}); // A
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());
    cache.onValuesExpired({v3}); // B
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
    CPPUNIT_ASSERT_EQUAL(1u, count(events, true));
    CPPUNIT_ASSERT_EQUAL((uint16_t) 3, events.back().seq);
}

void
OpCacheTester::testStaleAddIgnored()
{
    dht::OpValueCache cache([](const Values&, bool) { return true; });

    auto v1 = makeValue(30, 10, "C");
    auto v2 = makeValue(30, 20, "D");
    auto v3 = makeValue(30, 5, "E");

    cache.onValuesAdded({v1});
    CPPUNIT_ASSERT_EQUAL((uint16_t) 10, cache.get(30)->seq);
    cache.onValuesAdded({v2});
    CPPUNIT_ASSERT_EQUAL((uint16_t) 20, cache.get(30)->seq);

    // Older version from a lagging source: neither stored nor counted
    cache.onValuesAdded({v3});
    CPPUNIT_ASSERT_EQUAL((uint16_t) 20, cache.get(30)->seq);
    cache.onValuesExpired({v2});
    CPPUNIT_ASSERT_MESSAGE("Stale add must not have incremented the refcount", !cache.get(30));
}

void
OpCacheTester::testStaleExpireIgnored()
{
    // A source that still holds an older version expiring it must not
    // affect the newer version held by others.
    std::vector<Event> events;
    dht::OpValueCache cache(recordEvents(events));

    auto v1 = makeValue(31, 1, "old");
    auto v2 = makeValue(31, 2, "new");

    cache.onValuesAdded({v1}); // A
    cache.onValuesAdded({v1}); // B
    cache.onValuesAdded({v2}); // A edits; B never receives v2

    cache.onValuesExpired({v1}); // B expires its stale copy
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());
    CPPUNIT_ASSERT_EQUAL(0u, count(events, true));

    cache.onValuesExpired({v2}); // A
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
    CPPUNIT_ASSERT_EQUAL(1u, count(events, true));
    CPPUNIT_ASSERT_EQUAL((uint16_t) 2, events.back().seq);
}

void
OpCacheTester::testSameSeqConflictExpireIgnored()
{
    // A different payload with the same seq (e.g. the same signed content
    // re-signed with a randomized signature) is ignored on add and not
    // counted: its expiration must be ignored too.
    std::vector<Event> events;
    dht::OpValueCache cache(recordEvents(events));

    auto x = makeValue(60, 0, "x");
    auto y = makeValue(60, 0, "y");

    cache.onValuesAdded({x}); // A
    cache.onValuesAdded({y}); // B: same seq, different content
    CPPUNIT_ASSERT_EQUAL(1u, count(events, false));
    CPPUNIT_ASSERT(cache.get(60)->data == x->data);

    cache.onValuesExpired({y}); // B
    CPPUNIT_ASSERT_EQUAL_MESSAGE("An uncounted version must not expire the value", (size_t) 1, cache.size());
    CPPUNIT_ASSERT_EQUAL(0u, count(events, true));

    cache.onValuesExpired({x}); // A
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
    CPPUNIT_ASSERT_EQUAL(1u, count(events, true));
}

void
OpCacheTester::testCallbacks()
{
    std::vector<Event> events;
    dht::OpValueCache cache(recordEvents(events));

    auto v1 = makeValue(40, 0, "");
    cache.onValuesAdded({v1});
    CPPUNIT_ASSERT_EQUAL(1u, count(events, false));

    // Duplicate from another source: counted, but not re-delivered
    cache.onValuesAdded({v1});
    CPPUNIT_ASSERT_EQUAL(1u, count(events, false));

    auto v2 = makeValue(40, 100, "MOD");
    cache.onValuesAdded({v2});
    CPPUNIT_ASSERT_EQUAL(2u, count(events, false));

    // The edit reset the refcount: one expire removes it
    cache.onValuesExpired({v2});
    CPPUNIT_ASSERT_EQUAL(1u, count(events, true));
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

void
OpCacheTester::testFilters()
{
    dht::OpValueCache cache([](const Values&, bool) { return true; });

    auto v1 = makeValue(50, 0, "");
    v1->type = 1;
    auto v2 = makeValue(51, 0, "");
    v2->type = 2;
    cache.onValuesAdded({v1, v2});

    auto res1 = cache.get(dht::Value::TypeFilter(1));
    CPPUNIT_ASSERT_EQUAL((size_t) 1, res1.size());
    CPPUNIT_ASSERT_EQUAL(v1->id, res1[0]->id);

    auto res2 = cache.get(dht::Value::TypeFilter(2));
    CPPUNIT_ASSERT_EQUAL((size_t) 1, res2.size());
    CPPUNIT_ASSERT_EQUAL(v2->id, res2[0]->id);

    CPPUNIT_ASSERT_EQUAL((size_t) 2, cache.getValues().size());
}

void
OpCacheTester::testSyncStatus()
{
    dht::OpValueCache cache([](const Values&, bool) { return true; });

    CPPUNIT_ASSERT(!cache.isSynced());
    cache.onNodeChanged(dht::ListenSyncStatus::ADDED);
    CPPUNIT_ASSERT(!cache.isSynced());
    cache.onNodeChanged(dht::ListenSyncStatus::SYNCED);
    CPPUNIT_ASSERT(cache.isSynced());
    cache.onNodeChanged(dht::ListenSyncStatus::ADDED);
    CPPUNIT_ASSERT(!cache.isSynced());
    cache.onNodeChanged(dht::ListenSyncStatus::SYNCED);
    CPPUNIT_ASSERT(cache.isSynced());
    cache.onNodeChanged(dht::ListenSyncStatus::UNSYNCED);
    CPPUNIT_ASSERT(!cache.isSynced());
    cache.onNodeChanged(dht::ListenSyncStatus::REMOVED);
    CPPUNIT_ASSERT(cache.isSynced());
}

void
OpCacheTester::testGetWhileSynced()
{
    dht::SearchCache searchCache;
    int getCallCount = 0;
    bool doneCalled = false;
    bool doneSuccess = false;

    auto v1 = makeValue(100, 0, "X");
    auto v2 = makeValue(101, 0, "Y");
    auto query = std::make_shared<dht::Query>();

    auto token = searchCache.listen([](const Values&, bool) { return true; },
                                    query,
                                    {},
                                    [&](const std::shared_ptr<dht::Query>&,
                                        dht::ValueCallback vcb,
                                        dht::SyncCallback scb) -> size_t {
                                        scb(dht::ListenSyncStatus::ADDED);
                                        vcb({v1, v2}, false);
                                        scb(dht::ListenSyncStatus::SYNCED);
                                        return 1;
                                    });
    CPPUNIT_ASSERT(token != 0);

    bool result = searchCache.get(
        {},
        query,
        [&](const Values& vals) {
            getCallCount++;
            CPPUNIT_ASSERT_EQUAL((size_t) 2, vals.size());
            return true;
        },
        [&](bool success, const std::vector<std::shared_ptr<dht::Node>>&) {
            doneCalled = true;
            doneSuccess = success;
        });

    CPPUNIT_ASSERT_MESSAGE("get() should be served from a synced cache", result);
    CPPUNIT_ASSERT_EQUAL(1, getCallCount);
    CPPUNIT_ASSERT(doneCalled);
    CPPUNIT_ASSERT(doneSuccess);
}

void
OpCacheTester::testGetWhileNotSynced()
{
    // An unsynced cache must not answer a get: the caller falls back to the
    // network and values are delivered once, from the network only.
    dht::SearchCache searchCache;
    std::vector<dht::Value::Id> deliveries;

    auto v1 = makeValue(200, 0, "A");
    auto query = std::make_shared<dht::Query>();
    dht::SyncCallback storedScb;

    auto token = searchCache.listen([](const Values&, bool) { return true; },
                                    query,
                                    {},
                                    [&](const std::shared_ptr<dht::Query>&,
                                        dht::ValueCallback vcb,
                                        dht::SyncCallback scb) -> size_t {
                                        storedScb = scb;
                                        scb(dht::ListenSyncStatus::ADDED);
                                        vcb({v1}, false);
                                        return 1;
                                    });
    CPPUNIT_ASSERT(token != 0);

    bool doneCalled = false;
    auto gcb = [&](const Values& vals) {
        for (const auto& v : vals)
            deliveries.emplace_back(v->id);
        return true;
    };
    auto dcb = [&](bool, const std::vector<std::shared_ptr<dht::Node>>&) {
        doneCalled = true;
    };

    CPPUNIT_ASSERT(!searchCache.get({}, query, gcb, dcb));
    CPPUNIT_ASSERT(deliveries.empty());
    CPPUNIT_ASSERT(!doneCalled);

    // Simulated network reply
    gcb({v1});
    CPPUNIT_ASSERT_EQUAL((size_t) 1, deliveries.size());

    storedScb(dht::ListenSyncStatus::SYNCED);
    deliveries.clear();
    CPPUNIT_ASSERT(searchCache.get({}, query, gcb, dcb));
    CPPUNIT_ASSERT(doneCalled);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, deliveries.size());
}

void
OpCacheTester::testGetEmptySynced()
{
    dht::SearchCache searchCache;
    int getCallCount = 0;
    bool doneCalled = false;
    bool doneSuccess = false;
    auto query = std::make_shared<dht::Query>();

    auto token = searchCache.listen([](const Values&, bool) { return true; },
                                    query,
                                    {},
                                    [&](const std::shared_ptr<dht::Query>&,
                                        dht::ValueCallback,
                                        dht::SyncCallback scb) -> size_t {
                                        scb(dht::ListenSyncStatus::ADDED);
                                        scb(dht::ListenSyncStatus::SYNCED);
                                        return 1;
                                    });
    CPPUNIT_ASSERT(token != 0);

    bool result = searchCache.get(
        {},
        query,
        [&](const Values&) {
            getCallCount++;
            return true;
        },
        [&](bool success, const std::vector<std::shared_ptr<dht::Node>>&) {
            doneCalled = true;
            doneSuccess = success;
        });

    CPPUNIT_ASSERT(result);
    CPPUNIT_ASSERT_EQUAL(0, getCallCount);
    CPPUNIT_ASSERT(doneCalled);
    CPPUNIT_ASSERT(doneSuccess);
}

void
OpCacheTester::testGetWithoutCallback()
{
    // Dht::query() passes no GetCallback: the cache cannot answer it and
    // must let the network path run instead of calling an empty function.
    dht::SearchCache searchCache;
    auto v1 = makeValue(300, 0, "Q");
    auto query = std::make_shared<dht::Query>();

    searchCache.listen([](const Values&, bool) { return true; },
                       query,
                       {},
                       [&](const std::shared_ptr<dht::Query>&, dht::ValueCallback vcb, dht::SyncCallback scb) -> size_t {
                           scb(dht::ListenSyncStatus::ADDED);
                           vcb({v1}, false);
                           scb(dht::ListenSyncStatus::SYNCED);
                           return 1;
                       });

    bool doneCalled = false;
    CPPUNIT_ASSERT(!searchCache.get({}, query, {}, [&](bool, const std::vector<std::shared_ptr<dht::Node>>&) {
        doneCalled = true;
    }));
    CPPUNIT_ASSERT(!doneCalled);
}

void
OpCacheTester::testGetCallbackReturnsFalse()
{
    // A consumer returning false means "I have enough", not a failure.
    dht::SearchCache searchCache;
    auto v1 = makeValue(1000, 0, "X");
    auto query = std::make_shared<dht::Query>();

    searchCache.listen([](const Values&, bool) { return true; },
                       query,
                       {},
                       [&](const std::shared_ptr<dht::Query>&, dht::ValueCallback vcb, dht::SyncCallback scb) -> size_t {
                           scb(dht::ListenSyncStatus::ADDED);
                           vcb({v1}, false);
                           scb(dht::ListenSyncStatus::SYNCED);
                           return 1;
                       });

    bool doneCalled = false;
    bool doneSuccess = false;
    int gcbCallCount = 0;
    bool result = searchCache.get(
        {},
        query,
        [&](const Values&) {
            gcbCallCount++;
            return false;
        },
        [&](bool success, const std::vector<std::shared_ptr<dht::Node>>&) {
            doneCalled = true;
            doneSuccess = success;
        });

    CPPUNIT_ASSERT(result);
    CPPUNIT_ASSERT_EQUAL(1, gcbCallCount);
    CPPUNIT_ASSERT(doneCalled);
    CPPUNIT_ASSERT_MESSAGE("Stopping early is reported as success, like the network path", doneSuccess);
}

void
OpCacheTester::testTimestampOrdering()
{
    dht::OpValueCache cache([](const Values&, bool) { return true; });

    auto v1 = makeValue(400, 0, "T");
    auto t1 = std::chrono::system_clock::now();
    auto t2 = t1 + std::chrono::seconds(10);

    cache.onValue({v1}, false, t2);
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());

    cache.onValue({v1}, true, t1);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Stale expiration should be ignored", (size_t) 1, cache.size());

    cache.onValue({v1}, true, t2);
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

void
OpCacheTester::testSourceDropKeepsValue()
{
    // Two per-node ValueCaches feed one Search-level OpCache. When one node
    // leaves the search (its ValueCache is destroyed, expiring everything it
    // held) the value must stay visible as long as the other node holds it.
    std::vector<Event> events;
    dht::SearchCache searchCache;
    auto query = std::make_shared<dht::Query>();
    dht::ValueCallback toOpCache;
    dht::SyncCallback toOpCacheSync;

    searchCache.listen(recordEvents(events),
                       query,
                       {},
                       [&](const std::shared_ptr<dht::Query>&, dht::ValueCallback vcb, dht::SyncCallback scb) -> size_t {
                           toOpCache = std::move(vcb);
                           toOpCacheSync = std::move(scb);
                           return 1;
                       });

    dht::TypeStore types;
    auto now = dht::clock::now();
    auto v = makeValue(42, 0, "hello");

    auto makeNodeCache = [&] {
        return std::make_unique<dht::ValueCache>([&](const Values& vals, bool expired) { toOpCache(vals, expired); },
                                                 [&](dht::ListenSyncStatus s) { toOpCacheSync(s); });
    };
    auto nodeA = makeNodeCache();
    auto nodeB = makeNodeCache();
    nodeA->onValues({v}, {}, {}, types, now);
    nodeA->onSynced(true);
    nodeB->onValues({v}, {}, {}, types, now);
    nodeB->onSynced(true);
    CPPUNIT_ASSERT_EQUAL(1u, count(events, false));
    CPPUNIT_ASSERT_EQUAL((size_t) 1, searchCache.get(dht::Value::Filter {}).size());

    nodeA.reset();
    CPPUNIT_ASSERT_EQUAL_MESSAGE("No expire while another node holds the value", 0u, count(events, true));
    CPPUNIT_ASSERT_EQUAL((size_t) 1, searchCache.get(dht::Value::Filter {}).size());

    nodeB->onValues({v}, {}, {}, types, now + std::chrono::seconds(1));
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Refresh from the remaining node is not re-delivered", 1u, count(events, false));

    nodeB.reset();
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Last holder gone: expire once", 1u, count(events, true));
    CPPUNIT_ASSERT_EQUAL((size_t) 0, searchCache.get(dht::Value::Filter {}).size());
}

void
OpCacheTester::testSeqOnlyRefreshNotCounted()
{
    // A node re-announcing the same content with a bumped seq must not be
    // counted as an additional source by the OpValueCache above it, or the
    // value would survive the node's departure.
    std::vector<Event> events;
    dht::OpValueCache parent(recordEvents(events));
    dht::TypeStore types;
    auto now = dht::clock::now();

    auto v = makeValue(42, 0, "same");
    auto vBumped = makeValue(42, 1, "same");
    {
        dht::ValueCache node([&](const Values& vals, bool expired) { parent.onValue(vals, expired); });
        node.onValues({v}, {}, {}, types, now);
        node.onValues({vBumped}, {}, {}, types, now);
        CPPUNIT_ASSERT_EQUAL(1u, count(events, false));
    }
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Node gone: its value must be expired once", 1u, count(events, true));
    CPPUNIT_ASSERT_EQUAL((size_t) 0, parent.size());
}

void
OpCacheTester::testHighChurnRefCountConsistency()
{
    dht::OpValueCache cache([](const Values&, bool) { return true; });
    auto v = makeValue(800, 0, "CHURN");

    for (int i = 0; i < 50; i++) {
        cache.onNodeChanged(dht::ListenSyncStatus::ADDED);
        cache.onValuesAdded({v});
        cache.onValuesExpired({v});
        cache.onNodeChanged(dht::ListenSyncStatus::REMOVED);
    }
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());

    // Overlapping churn: add A, add B, expire A, expire B
    for (int i = 0; i < 20; i++) {
        cache.onNodeChanged(dht::ListenSyncStatus::ADDED);
        cache.onValuesAdded({v});
        cache.onNodeChanged(dht::ListenSyncStatus::ADDED);
        cache.onValuesAdded({v});

        cache.onValuesExpired({v});
        cache.onNodeChanged(dht::ListenSyncStatus::REMOVED);
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Value kept while one source remains", (size_t) 1, cache.size());

        cache.onValuesExpired({v});
        cache.onNodeChanged(dht::ListenSyncStatus::REMOVED);
        CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
    }

    // Extra expirations from sources that never added must be no-ops
    cache.onValuesExpired({v});
    cache.onValuesExpired({v});
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
}

void
OpCacheTester::testValueUpdateSingleSourcePhantom()
{
    // Editing a value (same id, higher seq) is delivered as a single add of
    // the new version, without a phantom expiration of the old one.
    std::vector<Event> events;
    dht::OpValueCache cache(recordEvents(events));

    auto v1 = makeValue(700, 1, "OLD");
    auto v2 = makeValue(700, 2, "NEW");

    cache.onValuesAdded({v1});
    events.clear();
    cache.onValuesAdded({v2});

    CPPUNIT_ASSERT_EQUAL((size_t) 1, events.size());
    CPPUNIT_ASSERT(!events[0].expired);
    CPPUNIT_ASSERT_EQUAL(v2->id, events[0].id);
    CPPUNIT_ASSERT_EQUAL(v2->seq, cache.get(700)->seq);
}

void
OpCacheTester::testExpireAfterUpdate()
{
    std::vector<Event> events;
    dht::OpValueCache cache(recordEvents(events));

    auto v1 = makeValue(1200, 1, "V1");
    auto v2 = makeValue(1200, 5, "V2");

    cache.onValuesAdded({v1});
    cache.onValuesAdded({v2});
    CPPUNIT_ASSERT_EQUAL(v2->seq, cache.get(1200)->seq);

    cache.onValuesExpired({v2});
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());
    CPPUNIT_ASSERT_EQUAL(1u, count(events, true));
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Expired value should be the updated one", v2->seq, events.back().seq);

    // Once gone, an older version is accepted again
    cache.onValuesAdded({v1});
    CPPUNIT_ASSERT_EQUAL(v1->seq, cache.get(1200)->seq);
}

void
OpCacheTester::testSingleSourceMode()
{
    // Single-source caches (proxy client) get the same values re-delivered
    // on refresh: duplicates must not be counted, one expire removes.
    std::vector<Event> events;
    dht::OpValueCache cache(recordEvents(events), false);
    auto v = makeValue(1100, 0, "DUP");

    for (int i = 0; i < 10; i++)
        cache.onValuesAdded({v});
    CPPUNIT_ASSERT_EQUAL(1u, count(events, false));
    CPPUNIT_ASSERT_EQUAL((size_t) 1, cache.size());

    cache.onValuesExpired({v});
    CPPUNIT_ASSERT_EQUAL(1u, count(events, true));
    CPPUNIT_ASSERT_EQUAL((size_t) 0, cache.size());

    cache.onValuesExpired({v});
    CPPUNIT_ASSERT_EQUAL(1u, count(events, true));
}

void
OpCacheTester::testSingleSourceModeSearchCache()
{
    std::vector<Event> events;
    dht::SearchCache searchCache(false);
    auto query = std::make_shared<dht::Query>();
    dht::ValueCallback vcbStored;

    searchCache.listen(recordEvents(events),
                       query,
                       {},
                       [&](const std::shared_ptr<dht::Query>&, dht::ValueCallback vcb, dht::SyncCallback) -> size_t {
                           vcbStored = std::move(vcb);
                           return 1;
                       });

    auto v = makeValue(1300, 0, "S");
    vcbStored({v}, false);
    vcbStored({v}, false); // re-delivery after listen restart
    CPPUNIT_ASSERT_EQUAL(1u, count(events, false));

    vcbStored({v}, true);
    CPPUNIT_ASSERT_EQUAL(1u, count(events, true));
    CPPUNIT_ASSERT_EQUAL((size_t) 0, searchCache.get(dht::Value::Filter {}).size());
}

} // namespace test
