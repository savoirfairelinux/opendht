// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_storage.h"

#include <opendht/thread_pool.h>

#include <chrono>
#include <mutex>
#include <condition_variable>
using namespace std::chrono_literals;
using namespace std::literals;

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(StorageTester);

static constexpr unsigned VAL_SIZE = 1024;

static dht::DhtRunner::Config
makeConfig(ssize_t maxStore = -1, ssize_t maxLocalStore = -1, ssize_t maxKeys = -1)
{
    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;
    config.dht_config.node_config.max_store_size = maxStore;
    config.dht_config.node_config.max_local_store_size = maxLocalStore;
    config.dht_config.node_config.max_store_keys = maxKeys;
    return config;
}

static std::shared_ptr<dht::Value>
makeValue(size_t size = VAL_SIZE)
{
    return std::make_shared<dht::Value>(std::string(size, 'x'));
}

void
StorageTester::setUp()
{
    // Tests configure and start nodes with specific limits as needed.
}

void
StorageTester::tearDown()
{
    node1.shutdown();
    node2.shutdown();
    node1.join();
    node2.join();
}

void
StorageTester::startNodes(dht::DhtRunner::Config config1, dht::DhtRunner::Config config2)
{
    node1.run(0, config1);
    node2.run(0, config2);
    auto bound = node1.getBound();
    if (bound.isUnspecified())
        bound.setLoopback();
    node2.bootstrap(bound);
    std::this_thread::sleep_for(1s);
}

void
StorageTester::testRemoteStorageLimit()
{
    constexpr ssize_t REMOTE_LIMIT = 10 * 1024; // 10 KB remote limit
    startNodes(makeConfig(REMOTE_LIMIT, -1 /* unlimited local */), makeConfig());

    // Put many values from node2 -> they are stored remotely on node1
    auto key = dht::InfoHash::get("remote_test");
    constexpr unsigned N = 20; // 20 * ~1KB = ~20KB, more than 10KB limit
    std::mutex mtx;
    std::condition_variable cv;
    unsigned putCount = 0;

    for (unsigned i = 0; i < N; i++) {
        auto val = makeValue();
        node2.put(key, val, [&](bool) {
            std::lock_guard lk(mtx);
            putCount++;
            cv.notify_all();
        });
    }

    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return putCount == N; }));
    }

    // Wait for values to propagate
    std::this_thread::sleep_for(2s);

    // The combined store size on node1 should be under or near the remote limit
    auto [storeSize, storeValues] = node1.getStoreSize();
    CPPUNIT_ASSERT_MESSAGE("Remote store size (" + std::to_string(storeSize)
                               + ") should be limited (limit: " + std::to_string(REMOTE_LIMIT) + ")",
                           storeSize <= static_cast<size_t>(REMOTE_LIMIT) * 2 // allow some margin for timing
    );
    // We should have fewer values than N since eviction happened
    CPPUNIT_ASSERT_MESSAGE("Should have fewer than " + std::to_string(N) + " values stored, got "
                               + std::to_string(storeValues),
                           storeValues < N);
}

void
StorageTester::testLocalStorageLimit()
{
    constexpr ssize_t LOCAL_LIMIT = 10 * 1024; // 10 KB local limit
    // Only node1 is needed - testing local puts
    auto config = makeConfig(-1 /* unlimited remote */, LOCAL_LIMIT);
    node1.run(0, config);

    // With 1KB values and 10KB limit, ~10 should fit, rest should be rejected
    constexpr unsigned N = 20; // 20 * ~1KB = ~20KB, more than 10KB limit
    std::mutex mtx;
    std::condition_variable cv;
    unsigned putCount = 0;

    for (unsigned i = 0; i < N; i++) {
        auto key = dht::InfoHash::get("local_test_" + std::to_string(i));
        auto val = makeValue();
        node1.put(key, val, [&](bool) {
            std::lock_guard lk(mtx);
            putCount++;
            cv.notify_all();
        });
    }

    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return putCount == N; }));
    }

    auto [storeSize, storeValues] = node1.getStoreSize();
    CPPUNIT_ASSERT_MESSAGE("Local store size (" + std::to_string(storeSize) + ") should not exceed "
                               + std::to_string(LOCAL_LIMIT),
                           storeSize <= static_cast<size_t>(LOCAL_LIMIT));
    CPPUNIT_ASSERT_MESSAGE("Some values should be stored (got " + std::to_string(storeValues) + ")", storeValues > 0);
    CPPUNIT_ASSERT_MESSAGE("Not all values should fit (stored " + std::to_string(storeValues) + "/" + std::to_string(N)
                               + ")",
                           storeValues < N);
}

void
StorageTester::testIndependentLimits()
{
    constexpr ssize_t REMOTE_LIMIT = 10 * 1024;
    constexpr ssize_t LOCAL_LIMIT = 10 * 1024;
    startNodes(makeConfig(REMOTE_LIMIT, LOCAL_LIMIT), makeConfig());

    // Put local values on node1 — some will be rejected when limit is hit
    constexpr unsigned N_LOCAL = 20;
    std::mutex mtx;
    std::condition_variable cv;
    unsigned putCount = 0;

    for (unsigned i = 0; i < N_LOCAL; i++) {
        auto key = dht::InfoHash::get("local_indep_" + std::to_string(i));
        auto val = makeValue();
        node1.put(key, val, [&](bool) {
            std::lock_guard lk(mtx);
            putCount++;
            cv.notify_all();
        });
    }

    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return putCount == N_LOCAL; }));
    }

    // Now put remote values from node2
    constexpr unsigned N_REMOTE = 20;
    unsigned remotePutCount = 0;
    for (unsigned i = 0; i < N_REMOTE; i++) {
        auto key = dht::InfoHash::get("remote_indep_" + std::to_string(i));
        auto val = makeValue();
        node2.put(key, val, [&](bool) {
            std::lock_guard lk(mtx);
            remotePutCount++;
            cv.notify_all();
        });
    }

    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return remotePutCount == N_REMOTE; }));
    }

    // Wait for values to propagate
    std::this_thread::sleep_for(2s);

    auto [storeSize, storeValues] = node1.getStoreSize();
    // Combined should be bounded by remote + local limits (with some margin for timing)
    CPPUNIT_ASSERT_MESSAGE("Combined store size (" + std::to_string(storeSize) + ") should be limited",
                           storeSize <= static_cast<size_t>(REMOTE_LIMIT + LOCAL_LIMIT) * 2);
    // Not all values should be stored (both limits should reject/evict some)
    CPPUNIT_ASSERT_MESSAGE("Should have fewer than " + std::to_string(N_LOCAL + N_REMOTE) + " values, got "
                               + std::to_string(storeValues),
                           storeValues < N_LOCAL + N_REMOTE);
}

void
StorageTester::testLocalPutNotAffectedByRemoteLimit()
{
    constexpr ssize_t REMOTE_LIMIT = 1024; // 1 KB - very small
    startNodes(makeConfig(REMOTE_LIMIT, -1 /* unlimited local */), makeConfig());

    // Fill up remote storage from node2
    auto remoteKey = dht::InfoHash::get("fill_remote");
    constexpr unsigned N_REMOTE = 5;
    std::mutex mtx;
    std::condition_variable cv;
    unsigned putCount = 0;

    for (unsigned i = 0; i < N_REMOTE; i++) {
        auto val = makeValue();
        node2.put(remoteKey, val, [&](bool) {
            std::lock_guard lk(mtx);
            putCount++;
            cv.notify_all();
        });
    }

    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return putCount == N_REMOTE; }));
    }
    std::this_thread::sleep_for(2s);

    // Local puts on node1 should all succeed regardless of remote limit
    constexpr unsigned N_LOCAL = 10;
    unsigned localPutCount = 0;
    unsigned localPutOk = 0;
    for (unsigned i = 0; i < N_LOCAL; i++) {
        auto key = dht::InfoHash::get("local_separate_" + std::to_string(i));
        auto val = makeValue();
        node1.put(key, val, [&](bool ok) {
            std::lock_guard lk(mtx);
            localPutCount++;
            if (ok)
                localPutOk++;
            cv.notify_all();
        });
    }

    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return localPutCount == N_LOCAL; }));
    }

    // All local puts should succeed
    CPPUNIT_ASSERT_EQUAL(N_LOCAL, localPutOk);

    // Verify local values can be retrieved
    for (unsigned i = 0; i < N_LOCAL; i++) {
        auto key = dht::InfoHash::get("local_separate_" + std::to_string(i));
        auto vals = node1.get(key).get();
        CPPUNIT_ASSERT_MESSAGE("Local value " + std::to_string(i) + " should be retrievable", !vals.empty());
    }
}

void
StorageTester::testRemotePutNotAffectedByLocalLimit()
{
    constexpr ssize_t LOCAL_LIMIT = 1024; // 1 KB - very small
    startNodes(makeConfig(-1 /* unlimited remote */, LOCAL_LIMIT), makeConfig());

    // Fill up local storage on node1
    constexpr unsigned N_LOCAL = 5;
    std::mutex mtx;
    std::condition_variable cv;
    unsigned localPutCount = 0;

    for (unsigned i = 0; i < N_LOCAL; i++) {
        auto key = dht::InfoHash::get("fill_local_" + std::to_string(i));
        auto val = makeValue();
        node1.put(key, val, [&](bool) {
            std::lock_guard lk(mtx);
            localPutCount++;
            cv.notify_all();
        });
    }

    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return localPutCount == N_LOCAL; }));
    }

    // Remote puts from node2 should all succeed despite full local storage
    auto remoteKey = dht::InfoHash::get("remote_separate");
    constexpr unsigned N_REMOTE = 10;
    unsigned remotePutCount = 0;
    unsigned remotePutOk = 0;

    for (unsigned i = 0; i < N_REMOTE; i++) {
        auto val = makeValue();
        node2.put(remoteKey, val, [&](bool ok) {
            std::lock_guard lk(mtx);
            remotePutCount++;
            if (ok)
                remotePutOk++;
            cv.notify_all();
        });
    }

    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return remotePutCount == N_REMOTE; }));
    }

    // All remote puts should succeed
    CPPUNIT_ASSERT_EQUAL(N_REMOTE, remotePutOk);

    std::this_thread::sleep_for(2s);
    auto vals = node1.get(remoteKey).get();
    CPPUNIT_ASSERT_MESSAGE("Remote values should be stored on node1 despite full local storage, got "
                               + std::to_string(vals.size()),
                           !vals.empty());
}

} // namespace test
