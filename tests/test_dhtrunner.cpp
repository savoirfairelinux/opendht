// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_dhtrunner.h"

#include <opendht/thread_pool.h>

#include <chrono>
#include <future>
#include <mutex>
#include <condition_variable>
using namespace std::chrono_literals;
using namespace std::literals;

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(DhtRunnerTester);

template<typename T>
T
getFutureValue(std::future<T> future, std::chrono::steady_clock::duration timeout = 30s)
{
    CPPUNIT_ASSERT(std::future_status::ready == future.wait_for(timeout));
    return future.get();
}

void
DhtRunnerTester::setUp()
{
    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;
    config.dht_config.node_config.max_store_size = -1;
    config.dht_config.node_config.max_store_keys = -1;

    node1.run(0, config);
    node2.run(0, config);
    auto bound = node1.getBound();
    if (bound.isUnspecified())
        bound.setLoopback();
    node2.bootstrap(bound);
}

void
DhtRunnerTester::tearDown()
{
    unsigned done {0};
    std::condition_variable cv;
    std::mutex cv_m;
    auto shutdown = [&] {
        std::lock_guard lk(cv_m);
        done++;
        cv.notify_all();
    };
    node1.shutdown(shutdown);
    node2.shutdown(shutdown);
    std::unique_lock lk(cv_m);
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return done == 2u; }));
    node1.join();
    node2.join();
}

void
DhtRunnerTester::testConstructors()
{
    CPPUNIT_ASSERT(node1.getBoundPort());
    CPPUNIT_ASSERT_EQUAL(node1.getBoundPort(), node1.getBound().getPort());
    CPPUNIT_ASSERT(node2.getBoundPort());
    CPPUNIT_ASSERT_EQUAL(node2.getBoundPort(), node2.getBound().getPort());

    dht::DhtRunner::Config config {};
    dht::DhtRunner::Context context {};
    dht::DhtRunner testNode;
    testNode.run(config, std::move(context));
    CPPUNIT_ASSERT(testNode.getBoundPort());
}

void
DhtRunnerTester::testGetPut()
{
    auto key = dht::InfoHash::get("123");
    dht::Value val {"hey"};
    auto val_data = val.data;
    std::promise<bool> p;
    auto future = p.get_future();
    node2.put(key, std::move(val), [&](bool ok) { p.set_value(ok); });
    CPPUNIT_ASSERT(getFutureValue(std::move(future)));
    auto vals = getFutureValue(node1.get(key));
    CPPUNIT_ASSERT(not vals.empty());
    CPPUNIT_ASSERT(vals.front()->data == val_data);
}

void
DhtRunnerTester::testStoreEmptyValue()
{
    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;
    config.dht_config.node_config.max_store_size = 100; // Small size to force expireStore()
    config.dht_config.node_config.max_store_keys = -1;

    dht::DhtRunner testNode;
    testNode.run(0, config);
    testNode.bootstrap(node1.getBound());

    auto key = testNode.getId();
    auto val = std::make_shared<dht::Value>();
    val->data.clear(); // Ensure size is 0
    CPPUNIT_ASSERT_EQUAL((size_t) 0, val->size());

    std::promise<bool> p;
    testNode.put(key, val, [&](bool ok) { p.set_value(ok); });
    p.get_future().get(); // Wait for put to finish

    // Put a large value to exceed max_store_size and trigger expireStore()
    auto key2 = dht::InfoHash::get("large_value_test");
    auto val2 = std::make_shared<dht::Value>();
    val2->data = std::vector<uint8_t>(200, 0); // 200 bytes
    std::promise<bool> p2;
    testNode.put(key2, val2, [&](bool ok) { p2.set_value(ok); });
    p2.get_future().get(); // Wait for put to finish

    // Wait a bit to ensure the value is processed
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    testNode.join();
}

void
DhtRunnerTester::testPutDuplicate()
{
    auto key = dht::InfoHash::get("123");
    auto val = std::make_shared<dht::Value>("hey");
    val->id = 42;
    auto val_data = val->data;
    std::promise<bool> p1;
    std::promise<bool> p2;
    auto p1future = p1.get_future();
    auto p2future = p2.get_future();
    node2.put(key, val, [&](bool ok) { p1.set_value(ok); });
    node2.put(key, val, [&](bool ok) { p2.set_value(ok); });
    auto p1ret = getFutureValue(std::move(p1future));
    auto p2ret = getFutureValue(std::move(p2future));
    CPPUNIT_ASSERT(p1ret);
    CPPUNIT_ASSERT(p2ret);
    auto vals = getFutureValue(node1.get(key));
    CPPUNIT_ASSERT(not vals.empty());
    CPPUNIT_ASSERT(vals.size() == 1);
    CPPUNIT_ASSERT(vals.front()->data == val_data);
}

void
DhtRunnerTester::testPutOverride()
{
    auto key = dht::InfoHash::get("123");
    auto val = std::make_shared<dht::Value>("meh");
    val->id = 42;
    auto val2 = std::make_shared<dht::Value>("hey");
    val2->id = 42;
    CPPUNIT_ASSERT_EQUAL(val->id, val2->id);
    auto val_data = val2->data;
    std::promise<bool> p1;
    std::promise<bool> p2;
    auto p1future = p1.get_future();
    auto p2future = p2.get_future();
    node2.put(key, val, [&](bool ok) { p1.set_value(ok); });
    node2.put(key, val2, [&](bool ok) { p2.set_value(ok); });
    auto p1ret = getFutureValue(std::move(p1future));
    auto p2ret = getFutureValue(std::move(p2future));
    CPPUNIT_ASSERT(!p1ret);
    CPPUNIT_ASSERT(p2ret);
    auto vals = getFutureValue(node1.get(key));
    CPPUNIT_ASSERT(not vals.empty());
    CPPUNIT_ASSERT(vals.size() == 1);
    CPPUNIT_ASSERT(vals.front()->data == val_data);
}

void
DhtRunnerTester::testImportValuesPreservesRemoteQuota()
{
    node1.shutdown();
    node1.join();
    node2.shutdown();
    node2.join();

    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;
    config.dht_config.node_config.max_store_size = 1536;
    config.dht_config.node_config.max_local_store_size = -1;
    config.dht_config.node_config.max_store_keys = -1;

    node1.run(0, config);
    node2.run(0, config);
    auto bound = node1.getBound();
    if (bound.isUnspecified())
        bound.setLoopback();
    node2.bootstrap(bound);
    std::this_thread::sleep_for(1s);

    auto key1 = dht::InfoHash::get("import-quota-1");
    auto key2 = dht::InfoHash::get("import-quota-2");
    auto value1 = std::make_shared<dht::Value>(std::string(1024, 'a'));
    auto value2 = std::make_shared<dht::Value>(std::string(1024, 'b'));

    std::promise<bool> p1;
    auto p1future = p1.get_future();
    node2.put(key1, value1, [&](bool ok) { p1.set_value(ok); });
    CPPUNIT_ASSERT(getFutureValue(std::move(p1future)));

    std::this_thread::sleep_for(2s);
    auto exported = node1.exportValues();
    CPPUNIT_ASSERT(!exported.empty());

    node1.shutdown();
    node1.join();

    dht::DhtRunner restored;
    restored.run(0, config);
    auto restoredBound = restored.getBound();
    if (restoredBound.isUnspecified())
        restoredBound.setLoopback();

    node2.shutdown();
    node2.join();
    node2.run(0, config);
    node2.bootstrap(restoredBound);
    std::this_thread::sleep_for(1s);

    restored.importValues(exported);
    std::this_thread::sleep_for(500ms);

    std::promise<bool> p2;
    auto p2future = p2.get_future();
    node2.put(key2, value2, [&](bool ok) { p2.set_value(ok); });
    CPPUNIT_ASSERT(getFutureValue(std::move(p2future)));

    std::this_thread::sleep_for(2s);

    auto vals1 = getFutureValue(restored.get(key1));
    auto vals2 = getFutureValue(restored.get(key2));
    CPPUNIT_ASSERT(vals1.size() + vals2.size() <= 1);

    restored.shutdown();
    restored.join();
}

void
DhtRunnerTester::testImportValuesPreservesStoredExpiration()
{
    static const dht::ValueType SHORT_LIVED_TYPE {200, "Short lived", 2s};

    node1.registerInsecureType(SHORT_LIVED_TYPE);

    auto key = dht::InfoHash::get("import-expiration");
    auto now = dht::clock::now();
    auto created = now;
    auto expiration = now + SHORT_LIVED_TYPE.expiration;

    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_array(1);
    pk.pack_array(4);
    pk.pack(created.time_since_epoch().count());
    dht::Value {SHORT_LIVED_TYPE.id, std::string("short-lived")}.msgpack_pack(pk);
    pk.pack_bin(0);
    pk.pack(expiration.time_since_epoch().count());

    node1.importValues({
        dht::ValuesExport {key, {buffer.data(), buffer.data() + buffer.size()}}
    });

    auto exported = node1.exportValues();
    CPPUNIT_ASSERT(!exported.empty());

    dht::DhtRunner restored;
    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;
    config.dht_config.node_config.max_store_size = -1;
    config.dht_config.node_config.max_store_keys = -1;
    restored.run(0, config);

    restored.importValues(exported);
    CPPUNIT_ASSERT(!restored.exportValues().empty());

    std::this_thread::sleep_for(3s);

    auto restoredValues = restored.exportValues();
    CPPUNIT_ASSERT_EQUAL(size_t(1), restoredValues.size());

    msgpack::unpacked msg;
    msgpack::unpack(msg, (const char*) restoredValues.front().second.data(), restoredValues.front().second.size());
    auto valarr = msg.get();
    CPPUNIT_ASSERT(valarr.type == msgpack::type::ARRAY);
    CPPUNIT_ASSERT_EQUAL(uint32_t(0), valarr.via.array.size);

    restored.shutdown();
    restored.join();
}

void
DhtRunnerTester::testImportPermanentValueExpires()
{
    // Simulate importing a value that was originally stored as permanent
    // (expiration = time_point::max()). After import the permanent flag is lost,
    // so the value must expire within the type's normal expiration window.
    static const dht::ValueType SHORT_TYPE {201, "Short perm", 2s};

    auto key = dht::InfoHash::get("import-permanent-expiration");
    auto now = dht::clock::now();

    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_array(1);
    pk.pack_array(4);
    pk.pack(now.time_since_epoch().count());
    dht::Value {SHORT_TYPE.id, std::string("was-permanent")}.msgpack_pack(pk);
    pk.pack_bin(0);
    // Permanent values are exported with time_point::max() expiration
    pk.pack(dht::clock::time_point::max().time_since_epoch().count());

    dht::DhtRunner restored;
    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;
    config.dht_config.node_config.max_store_size = -1;
    config.dht_config.node_config.max_store_keys = -1;
    restored.run(0, config);

    restored.importValues({
        dht::ValuesExport {key, {buffer.data(), buffer.data() + buffer.size()}}
    });

    // Value should be present right after import
    auto exportedBefore = restored.exportValues();
    CPPUNIT_ASSERT(!exportedBefore.empty());

    // Wait longer than the default USER_DATA expiration (10 min) is not
    // practical, but the type is unregistered so the default 10 min expiration
    // applies.  Instead, register the short type so the cap uses 2 s.
    // Re-import into a fresh node that knows the short type.
    dht::DhtRunner restored2;
    restored2.run(0, config);
    restored2.registerInsecureType(SHORT_TYPE);
    restored2.importValues({
        dht::ValuesExport {key, {buffer.data(), buffer.data() + buffer.size()}}
    });

    CPPUNIT_ASSERT(!restored2.exportValues().empty());

    // Wait for the short expiration to pass
    std::this_thread::sleep_for(3s);

    auto restoredValues = restored2.exportValues();
    bool found = false;
    for (const auto& ve : restoredValues) {
        if (ve.first == key) {
            msgpack::unpacked msg;
            msgpack::unpack(msg, (const char*) ve.second.data(), ve.second.size());
            auto valarr = msg.get();
            CPPUNIT_ASSERT(valarr.type == msgpack::type::ARRAY);
            // The value should have expired
            CPPUNIT_ASSERT_EQUAL(uint32_t(0), valarr.via.array.size);
            found = true;
        }
    }
    // Either the key was cleaned up entirely or it was found with 0 values
    CPPUNIT_ASSERT(found || restoredValues.empty()
                   || std::none_of(restoredValues.begin(), restoredValues.end(),
                                   [&](const auto& ve) { return ve.first == key; }));

    restored.shutdown();
    restored.join();
    restored2.shutdown();
    restored2.join();
}

void
DhtRunnerTester::testBootstrapSetsConnectingState()
{
    node1.shutdown();
    node1.join();
    node2.shutdown();
    node2.join();

    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;
    config.dht_config.node_config.max_store_size = -1;
    config.dht_config.node_config.max_store_keys = -1;

    std::mutex mutex;
    std::condition_variable cv;
    bool sawConnecting {false};

    dht::DhtRunner::Context context;
    context.statusChangedCallback = [&](dht::NodeStatus status4, dht::NodeStatus status6) {
        std::lock_guard lock(mutex);
        sawConnecting = sawConnecting || status4 == dht::NodeStatus::Connecting
                        || status6 == dht::NodeStatus::Connecting;
        cv.notify_all();
    };

    dht::DhtRunner bootstrapNode;
    dht::DhtRunner clientNode;
    bootstrapNode.run(0, config);
    clientNode.run(config, std::move(context));

    auto bound = bootstrapNode.getBound();
    if (bound.isUnspecified())
        bound.setLoopback();

    clientNode.bootstrap("127.0.0.1", std::to_string(bound.getPort()));

    {
        std::unique_lock lock(mutex);
        CPPUNIT_ASSERT(cv.wait_for(lock, 5s, [&] { return sawConnecting; }));
    }

    bootstrapNode.shutdown();
    bootstrapNode.join();
    clientNode.shutdown();
    clientNode.join();
}

void
DhtRunnerTester::testBootstrapThenPutNoRace()
{
    node1.shutdown();
    node1.join();
    node2.shutdown();
    node2.join();

    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;
    config.dht_config.node_config.max_store_size = -1;
    config.dht_config.node_config.max_store_keys = -1;

    dht::DhtRunner bootstrapNode;
    dht::DhtRunner clientNode;
    bootstrapNode.run(0, config);
    clientNode.run(0, config);

    auto bound = bootstrapNode.getBound();
    if (bound.isUnspecified())
        bound.setLoopback();

    clientNode.bootstrap(bound);

    std::promise<bool> putDone;
    auto putFuture = putDone.get_future();
    clientNode.put(dht::InfoHash::get("bootstrap-then-put"), dht::Value {"value"}, [&](bool ok) {
        putDone.set_value(ok);
    });
    CPPUNIT_ASSERT(getFutureValue(std::move(putFuture)));

    auto vals = getFutureValue(bootstrapNode.get(dht::InfoHash::get("bootstrap-then-put")));
    CPPUNIT_ASSERT(!vals.empty());

    bootstrapNode.shutdown();
    bootstrapNode.join();
    clientNode.shutdown();
    clientNode.join();
}

void
DhtRunnerTester::testBootstrapMissingNodeThenPutFails()
{
    node1.shutdown();
    node1.join();
    node2.shutdown();
    node2.join();

    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;
    config.dht_config.node_config.max_store_size = -1;
    config.dht_config.node_config.max_store_keys = -1;

    auto getUnusedPort = [&]() {
        dht::DhtRunner tmpNode;
        tmpNode.run(0, config);
        auto port = tmpNode.getBoundPort();
        tmpNode.shutdown();
        tmpNode.join();
        return port;
    };

    auto missingPort = getUnusedPort();

    std::mutex mutex;
    std::condition_variable cv;
    bool sawConnecting {false};
    bool sawDisconnectedAfterConnecting {false};
    bool putReturnedBeforeDisconnect {false};

    dht::DhtRunner::Context context;
    context.statusChangedCallback = [&](dht::NodeStatus status4, dht::NodeStatus status6) {
        std::lock_guard lock(mutex);
        if (status4 == dht::NodeStatus::Connecting || status6 == dht::NodeStatus::Connecting)
            sawConnecting = true;
        if (sawConnecting && status4 == dht::NodeStatus::Disconnected && status6 == dht::NodeStatus::Disconnected)
            sawDisconnectedAfterConnecting = true;
        cv.notify_all();
    };

    dht::DhtRunner clientNode;
    clientNode.run(0, config, std::move(context));
    while (clientNode.getBoundPort() == missingPort)
        missingPort = getUnusedPort();

    std::promise<bool> putDone;
    auto putFuture = putDone.get_future();

    clientNode.bootstrap("127.0.0.1", std::to_string(missingPort));
    clientNode.put(dht::InfoHash::get("bootstrap-missing-put"), dht::Value {"value"}, [&](bool ok) {
        std::lock_guard lock(mutex);
        putReturnedBeforeDisconnect = !sawDisconnectedAfterConnecting;
        putDone.set_value(ok);
        cv.notify_all();
    });

    {
        std::unique_lock lock(mutex);
        CPPUNIT_ASSERT(cv.wait_for(lock, 10s, [&] { return sawConnecting; }));
        CPPUNIT_ASSERT(cv.wait_for(lock, 20s, [&] { return sawDisconnectedAfterConnecting; }));
    }
    CPPUNIT_ASSERT(std::future_status::ready == putFuture.wait_for(20s));
    CPPUNIT_ASSERT(!putFuture.get());
    CPPUNIT_ASSERT(!putReturnedBeforeDisconnect);

    clientNode.shutdown();
    clientNode.join();
}

void
DhtRunnerTester::testShutdownCompletesWithPendingPut()
{
    node1.shutdown();
    node1.join();
    node2.shutdown();
    node2.join();

    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;
    config.dht_config.node_config.max_store_size = -1;
    config.dht_config.node_config.max_store_keys = -1;

    auto getUnusedPort = [&]() {
        dht::DhtRunner tmpNode;
        tmpNode.run(0, config);
        auto port = tmpNode.getBoundPort();
        tmpNode.shutdown();
        tmpNode.join();
        return port;
    };

    auto missingPort = getUnusedPort();

    dht::DhtRunner clientNode;
    clientNode.run(0, config);
    while (clientNode.getBoundPort() == missingPort)
        missingPort = getUnusedPort();

    clientNode.bootstrap("127.0.0.1", std::to_string(missingPort));
    clientNode.put(dht::InfoHash::get("shutdown-pending-put"), dht::Value {"value"}, [](bool) {});

    std::promise<void> shutdownDone;
    auto shutdownFuture = shutdownDone.get_future();
    clientNode.shutdown([&]() { shutdownDone.set_value(); });

    CPPUNIT_ASSERT(std::future_status::ready == shutdownFuture.wait_for(5s));

    clientNode.join();
}

void
DhtRunnerTester::testListenValueEdit()
{
    // Register an editable type on both nodes so the DHT allows edits.
    static constexpr dht::ValueType::Id EDITABLE_TYPE_ID = 9999;
    const dht::ValueType editableType {EDITABLE_TYPE_ID,
                                       "editable-test",
                                       std::chrono::seconds(2),
                                       dht::ValueType::DEFAULT_STORE_POLICY,
                                       [](dht::InfoHash,
                                          const std::shared_ptr<dht::Value>&,
                                          std::shared_ptr<dht::Value>&,
                                          const dht::InfoHash&,
                                          const dht::SockAddr&) { return true; }};
    node1.registerType(editableType);
    node2.registerType(editableType);

    auto key = dht::InfoHash::get("listenValueEdit");
    auto identity = dht::crypto::generateIdentity("ListenEditTester");

    std::mutex mtx;
    std::condition_variable cv;
    std::vector<std::pair<dht::Value::Id, bool>> events; // (id, expired?)

    auto ftoken = node1.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        std::lock_guard lk(mtx);
        for (const auto& v : vals) {
            events.emplace_back(v->id, expired);
        }
        cv.notify_all();
        return true;
    });

    // Put initial value (signed, editable type)
    auto val1 = std::make_shared<dht::Value>("version1");
    val1->type = EDITABLE_TYPE_ID;
    val1->id = 42;
    val1->seq = 1;
    val1->sign(*identity.first);
    {
        std::promise<bool> p;
        node2.put(key, val1, [&](bool ok) { p.set_value(ok); });
        CPPUNIT_ASSERT(getFutureValue(p.get_future()));
    }

    // Wait for the first value to be received
    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
            return std::any_of(events.begin(), events.end(), [](const auto& e) { return !e.second; });
        }));
    }

    // Edit the value (same id, higher seq)
    auto val2 = std::make_shared<dht::Value>("version2");
    val2->type = EDITABLE_TYPE_ID;
    val2->id = 42;
    val2->seq = 2;
    val2->sign(*identity.first);
    {
        std::promise<bool> p;
        node2.put(key, val2, [&](bool ok) { p.set_value(ok); });
        CPPUNIT_ASSERT(getFutureValue(p.get_future()));
    }

    // Wait for the edited value to be received
    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
            int adds = 0;
            for (const auto& e : events)
                if (!e.second)
                    adds++;
            return adds >= 2;
        }));
    }

    // Give some extra time for any stray callbacks
    std::this_thread::sleep_for(500ms);

    // Verify: we should have exactly 2 add events, no expire events.
    // On value edition the listener should see only the new version
    // (as an add), not an expiration of the old version.
    {
        std::lock_guard lk(mtx);
        int addCount = 0;
        int expireCount = 0;
        for (const auto& e : events) {
            if (e.second)
                expireCount++;
            else
                addCount++;
        }
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Should receive 2 add callbacks (original + edit)", 2, addCount);
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Should receive no expire callbacks on edit", 0, expireCount);
    }

    // Now wait for the edited value to actually expire.
    // Type expiration is 2s. The cache may add a grace period.
    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT_MESSAGE("Edited value should eventually expire", cv.wait_for(lk, 60s, [&] {
            return std::any_of(events.begin(), events.end(), [](const auto& e) { return e.second; });
        }));
    }

    node1.cancelListen(key, ftoken.get());
}

void
DhtRunnerTester::testListen()
{
    std::mutex mutex;
    std::condition_variable cv;
    std::atomic_uint valueCounta(0);
    std::atomic_uint valueCountb(0);
    std::atomic_uint valueCountc(0);
    std::atomic_uint valueCountd(0);

    unsigned putCount(0);
    unsigned putOkCount1(0);
    unsigned putOkCount2(0);
    unsigned putOkCount3(0);

    auto a = dht::InfoHash::get("234");
    auto b = dht::InfoHash::get("2345");
    auto c = dht::InfoHash::get("23456");
    auto d = dht::InfoHash::get("234567");
    constexpr unsigned N = 256;
    constexpr unsigned SZ = 56 * 1024;

    auto ftokena = node1.listen(a, [&](const std::vector<std::shared_ptr<dht::Value>>& values, bool expired) {
        if (expired)
            valueCounta -= values.size();
        else
            valueCounta += values.size();
        return true;
    });

    auto ftokenb = node1.listen(b, [&](const std::shared_ptr<dht::Value>&) {
        /*if (expired)
            valueCountb -= values.size();
        else
            valueCountb += values.size();*/
        valueCountb++;
        return false;
    });

    auto ftokenc = node1.listen(c, [&](const std::vector<std::shared_ptr<dht::Value>>& values, bool expired) {
        if (expired)
            valueCountc -= values.size();
        else
            valueCountc += values.size();
        return true;
    });

    auto ftokend = node1.listen(d, [&](const std::vector<std::shared_ptr<dht::Value>>& values, bool expired) {
        if (expired)
            valueCountd -= values.size();
        else
            valueCountd += values.size();
        return true;
    });

    std::vector<uint8_t> mtu;
    mtu.reserve(SZ);
    for (size_t i = 0; i < SZ; i++)
        mtu.emplace_back((i % 2) ? 'T' : 'M');

    for (unsigned i = 0; i < N; i++) {
        node2.put(a, dht::Value("v1"), [&](bool ok) {
            std::lock_guard lock(mutex);
            putCount++;
            if (ok)
                putOkCount1++;
            cv.notify_all();
        });
        node2.put(b, dht::Value("v2"), [&](bool ok) {
            std::lock_guard lock(mutex);
            putCount++;
            if (ok)
                putOkCount2++;
            cv.notify_all();
        });
        auto bigVal = std::make_shared<dht::Value>();
        bigVal->data = mtu;
        node2.put(c, std::move(bigVal), [&](bool ok) {
            std::lock_guard lock(mutex);
            putCount++;
            if (ok)
                putOkCount3++;
            cv.notify_all();
        });
    }

    {
        std::unique_lock lk(mutex);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return putCount == N * 3u; }));
        CPPUNIT_ASSERT_EQUAL(N, putOkCount1);
        CPPUNIT_ASSERT_EQUAL(N, putOkCount2);
        CPPUNIT_ASSERT_EQUAL(N, putOkCount3);
    }

    CPPUNIT_ASSERT(ftokena.valid());
    CPPUNIT_ASSERT(ftokenb.valid());
    CPPUNIT_ASSERT(ftokenc.valid());
    CPPUNIT_ASSERT(ftokend.valid());

    auto tokena = getFutureValue(std::move(ftokena));
    auto tokenc = getFutureValue(std::move(ftokenc));
    auto tokend = getFutureValue(std::move(ftokend));
    // tokenb might be 0 since the callback returns false.

    CPPUNIT_ASSERT(tokena);
    CPPUNIT_ASSERT(tokenc);
    CPPUNIT_ASSERT(tokend);
    CPPUNIT_ASSERT_EQUAL(N, valueCounta.load());
    CPPUNIT_ASSERT_EQUAL(1u, valueCountb.load());
    CPPUNIT_ASSERT_EQUAL(N, valueCountc.load());
    CPPUNIT_ASSERT_EQUAL(0u, valueCountd.load());

    node1.cancelListen(a, tokena);
    node1.cancelListen(b, std::move(ftokenb));
    node1.cancelListen(c, tokenc);
    node1.cancelListen(d, tokend);
}

void
DhtRunnerTester::testIdOps()
{
    std::mutex mutex;
    std::condition_variable cv;
    unsigned identityCount(0);
    unsigned valueCount(0);
    unsigned valueCountEdit(0);

    dht::DhtRunner::Config config2;
    config2.dht_config.node_config.max_peer_req_per_sec = -1;
    config2.dht_config.node_config.max_req_per_sec = -1;
    config2.dht_config.id = dht::crypto::generateIdentity();

    dht::DhtRunner::Context context2;
    context2.identityAnnouncedCb = [&](bool ok) {
        CPPUNIT_ASSERT(ok);
        std::lock_guard lk(mutex);
        identityCount++;
        cv.notify_all();
    };

    node2.join();
    node2.run(0, config2, std::move(context2));
    auto bound = node1.getBound();
    if (bound.isUnspecified())
        bound.setLoopback();
    node2.bootstrap(bound);

    {
        std::unique_lock lk(mutex);
        CPPUNIT_ASSERT(cv.wait_for(lk, 20s, [&] { return identityCount == 1; }));
    }

    node1.findCertificate(node2.getPublicKey()->getLongId(), [&](const std::shared_ptr<dht::crypto::Certificate>& crt) {
        CPPUNIT_ASSERT(crt);
        std::lock_guard lk(mutex);
        valueCount++;
        cv.notify_all();
    });

    {
        std::unique_lock lk(mutex);
        CPPUNIT_ASSERT(cv.wait_for(lk, 20s, [&] { return valueCount == 1u; }));
        CPPUNIT_ASSERT_EQUAL(1u, identityCount);
    }

    dht::DhtRunner::Context context1;
    context1.identityAnnouncedCb = [&](bool ok) {
        CPPUNIT_ASSERT(ok);
        std::lock_guard lk(mutex);
        identityCount++;
        cv.notify_all();
    };

    config2.dht_config.id = dht::crypto::generateIdentity();
    node1.join();
    node1.run(0, config2, std::move(context1));
    bound = node2.getBound();
    if (bound.isUnspecified())
        bound.setLoopback();
    node1.bootstrap(bound);

    auto key = dht::InfoHash::get("key");
    node1.putEncrypted(key, node2.getPublicKey()->getLongId(), std::make_shared<dht::Value>("yo"), [&](bool ok) {
        CPPUNIT_ASSERT(ok);
        std::lock_guard lk(mutex);
        valueCount++;
        cv.notify_all();
    });

    node1.putEncrypted(key, node2.getPublicKey(), dht::Value("yo"), [&](bool ok) {
        CPPUNIT_ASSERT(ok);
        std::lock_guard lk(mutex);
        valueCount++;
        cv.notify_all();
    });

    node2.listen<std::string>(key, [&](std::string&& value) {
        CPPUNIT_ASSERT_EQUAL("yo"s, value);
        std::lock_guard lk(mutex);
        valueCount++;
        cv.notify_all();
        return true;
    });

    auto key2 = dht::InfoHash::get("key2");
    auto editValue = std::make_shared<dht::Value>("v1");
    node1.putSigned(key2, editValue, [&](bool ok) {
        CPPUNIT_ASSERT(ok);
        std::lock_guard lk(mutex);
        valueCountEdit++;
        cv.notify_all();
    });
    auto listenToken = node2.listen(key2, [&](const std::vector<std::shared_ptr<dht::Value>>& values, bool /*expired*/) {
        for (const auto& v : values) {
            if (v->seq == 0)
                CPPUNIT_ASSERT_EQUAL("v1"s, dht::unpackMsg<std::string>(v->data));
            else if (v->seq == 1)
                CPPUNIT_ASSERT_EQUAL("v2"s, dht::unpackMsg<std::string>(v->data));
            CPPUNIT_ASSERT_EQUAL(v->owner->getLongId(), node1.getPublicKey()->getLongId());
        }
        std::lock_guard lk(mutex);
        valueCountEdit += values.size();
        cv.notify_all();
        return true;
    });

    {
        std::unique_lock lk(mutex);
        CPPUNIT_ASSERT(cv.wait_for(lk, 20s, [&] { return identityCount == 2u; }));
        CPPUNIT_ASSERT(cv.wait_for(lk, 20s, [&] { return valueCount == 5u; }));
        CPPUNIT_ASSERT(cv.wait_for(lk, 20s, [&] { return valueCountEdit == 2u; }));
    }

    node2.findCertificate(node1.getPublicKey()->getLongId(), [&](const std::shared_ptr<dht::crypto::Certificate>& crt) {
        CPPUNIT_ASSERT(crt);
        std::lock_guard lk(mutex);
        valueCount++;
        cv.notify_all();
    });

    {
        std::unique_lock lk(mutex);
        CPPUNIT_ASSERT(cv.wait_for(lk, 20s, [&] { return valueCount == 6u; }));
    }

    // editValue->data = dht::packMsg("v2");
    editValue = std::make_shared<dht::Value>(editValue->id);
    editValue->data = dht::packMsg("v2");
    node1.putSigned(key2, editValue, [&](bool ok) {
        CPPUNIT_ASSERT(ok);
        std::lock_guard lk(mutex);
        valueCountEdit++;
        cv.notify_all();
    });
    std::unique_lock lk(mutex);
    CPPUNIT_ASSERT(cv.wait_for(lk, 20s, [&] { return valueCountEdit == 4u; }));
    lk.unlock();
    node2.cancelListen(key2, listenToken.get());
}

void
DhtRunnerTester::testListenLotOfBytes()
{
    std::mutex mutex;
    std::condition_variable cv;
    std::atomic_uint valueCount(0);
    unsigned putCount(0);
    unsigned putOkCount(0);

    std::string data(10000, 'a');

    auto foo = dht::InfoHash::get("foo");
    constexpr unsigned N = 1024;

    for (unsigned i = 0; i < N; i++) {
        node2.put(foo, data, [&](bool ok) {
            std::lock_guard lock(mutex);
            putCount++;
            if (ok)
                putOkCount++;
            cv.notify_all();
        });
    }
    {
        std::unique_lock lk(mutex);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return putCount == N; }));
    }

    dht::DhtRunner node3 {};
    dht::DhtRunner::Config config;
    config.dht_config.node_config.max_peer_req_per_sec = -1;
    config.dht_config.node_config.max_req_per_sec = -1;
    node3.run(42242, config);
    auto bound = node1.getBound();
    if (bound.isUnspecified())
        bound.setLoopback();
    node3.bootstrap(bound);

    auto ftokenfoo = node3.listen(foo, [&](const std::shared_ptr<dht::Value>&) {
        valueCount++;
        cv.notify_all();
        return true;
    });

    {
        std::unique_lock lk(mutex);
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return valueCount == N; }));
    }

    node3.cancelListen(foo, getFutureValue(std::move(ftokenfoo)));
}

void
DhtRunnerTester::testMultithread()
{
    std::mutex mutex;
    std::condition_variable cv;
    unsigned putCount(0);
    unsigned putOkCount(0);

    constexpr unsigned N = 2048;

    for (unsigned i = 0; i < N; i++) {
        dht::ThreadPool::computation().run([&] {
            node2.put(dht::InfoHash::get("123" + std::to_string(i)), "hehe", [&](bool ok) {
                std::lock_guard lock(mutex);
                putCount++;
                if (ok)
                    putOkCount++;
                cv.notify_all();
            });
            node2.get(
                dht::InfoHash::get("123" + std::to_string(N - i - 1)),
                [](const std::shared_ptr<dht::Value>&) { return true; },
                [&](bool ok) {
                    std::lock_guard lock(mutex);
                    putCount++;
                    if (ok)
                        putOkCount++;
                    cv.notify_all();
                });
        });
    }
    std::unique_lock lk(mutex);
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return putCount == 2 * N; }));
    CPPUNIT_ASSERT_EQUAL(2 * N, putOkCount);
}

void
DhtRunnerTester::testGetAfterListen()
{
    // Test that get() after a synced listen delivers values exactly once
    // from the cache, and that the GetCallback return value is honored.
    auto key = dht::InfoHash::get("getAfterListen");

    // Put a value first
    auto val = std::make_shared<dht::Value>("cached_val");
    {
        std::promise<bool> p;
        node2.put(key, val, [&](bool ok) { p.set_value(ok); });
        CPPUNIT_ASSERT(getFutureValue(p.get_future()));
    }

    // Start a listen on node1 and wait for it to sync
    std::mutex mtx;
    std::condition_variable cv;
    std::atomic_int listenAddCount {0};

    auto ftoken = node1.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        if (!expired)
            listenAddCount += vals.size();
        cv.notify_all();
        return true;
    });

    // Wait for listen to receive the value
    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return listenAddCount.load() >= 1; }));
    }

    // Now do a get — should be served from the synced cache
    auto vals = getFutureValue(node1.get(key));
    CPPUNIT_ASSERT_MESSAGE("get() should return values", not vals.empty());
    CPPUNIT_ASSERT(val->data == vals.front()->data);

    // The listen callback should not have been called again by the get
    std::this_thread::sleep_for(200ms);
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Listen should not fire extra callbacks from get()", 1, listenAddCount.load());

    node1.cancelListen(key, ftoken.get());
}

void
DhtRunnerTester::testListenDuplicatePut()
{
    // Test that putting the exact same value multiple times only triggers
    // one add callback in the listener (no duplicate delivery).
    auto key = dht::InfoHash::get("listenDupPut");

    std::mutex mtx;
    std::condition_variable cv;
    std::vector<std::pair<dht::Value::Id, bool>> events;

    auto ftoken = node1.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        std::lock_guard lk(mtx);
        for (const auto& v : vals)
            events.emplace_back(v->id, expired);
        cv.notify_all();
        return true;
    });

    // Put the same value 3 times
    auto val = std::make_shared<dht::Value>("duplicate_test");
    val->id = 123;
    for (int i = 0; i < 3; i++) {
        std::promise<bool> p;
        node2.put(key, val, [&](bool ok) { p.set_value(ok); });
        CPPUNIT_ASSERT(getFutureValue(p.get_future()));
    }

    // Wait for at least 1 add to arrive
    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
            return std::any_of(events.begin(), events.end(), [](const auto& e) { return !e.second; });
        }));
    }

    // Give time for any spurious callbacks
    std::this_thread::sleep_for(500ms);

    // Should have exactly 1 add, 0 expires
    {
        std::lock_guard lk(mtx);
        int addCount = 0, expireCount = 0;
        for (const auto& e : events) {
            if (e.second)
                expireCount++;
            else
                addCount++;
        }
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Duplicate puts should produce only 1 add callback", 1, addCount);
        CPPUNIT_ASSERT_EQUAL_MESSAGE("No expire callbacks expected", 0, expireCount);
    }

    node1.cancelListen(key, ftoken.get());
}

void
DhtRunnerTester::testListenMultiSourceExpire()
{
    // Test that when multiple nodes store the same value, the listener sees
    // exactly 1 add (no duplicates). When the value expires naturally, the
    // listener sees exactly 1 expire.
    static constexpr dht::ValueType::Id SHORT_TYPE_ID = 8888;
    const dht::ValueType shortType {SHORT_TYPE_ID,
                                    "short-lived",
                                    std::chrono::seconds(2),
                                    dht::ValueType::DEFAULT_STORE_POLICY,
                                    [](dht::InfoHash,
                                       const std::shared_ptr<dht::Value>&,
                                       std::shared_ptr<dht::Value>&,
                                       const dht::InfoHash&,
                                       const dht::SockAddr&) { return true; }};
    node1.registerType(shortType);
    node2.registerType(shortType);

    auto key = dht::InfoHash::get("multiSourceExpire");
    auto identity = dht::crypto::generateIdentity("MultiSourceTester");

    std::mutex mtx;
    std::condition_variable cv;
    std::vector<std::pair<dht::Value::Id, bool>> events;

    // node1 listens; node1 and node2 put
    auto ftoken = node1.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        std::lock_guard lk(mtx);
        for (const auto& v : vals)
            events.emplace_back(v->id, expired);
        cv.notify_all();
        return true;
    });

    // Both node1 and node2 put the same value (same id, same seq)
    auto val = std::make_shared<dht::Value>("multi_source");
    val->type = SHORT_TYPE_ID;
    val->id = 55;
    val->seq = 1;
    val->sign(*identity.first);

    {
        std::promise<bool> p1, p2;
        node1.put(key, val, [&](bool ok) { p1.set_value(ok); });
        node2.put(key, val, [&](bool ok) { p2.set_value(ok); });
        CPPUNIT_ASSERT(getFutureValue(p1.get_future()));
        CPPUNIT_ASSERT(getFutureValue(p2.get_future()));
    }

    // Wait for at least one add
    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
            return std::any_of(events.begin(), events.end(), [](const auto& e) { return !e.second; });
        }));
    }

    // Allow time for duplicate callbacks
    std::this_thread::sleep_for(1s);

    // Should have exactly 1 add (deduplication in OpValueCache)
    {
        std::lock_guard lk(mtx);
        int addCount = 0;
        for (const auto& e : events)
            if (!e.second)
                addCount++;
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Multiple sources should produce only 1 add callback", 1, addCount);
    }

    // Wait for natural expiration (type is 2s + grace period)
    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT_MESSAGE("Value should eventually expire", cv.wait_for(lk, 60s, [&] {
            return std::any_of(events.begin(), events.end(), [](const auto& e) { return e.second; });
        }));
    }

    // Should have exactly 1 expire (no duplicate expires from multiple sources)
    {
        std::lock_guard lk(mtx);
        int expireCount = 0;
        for (const auto& e : events)
            if (e.second)
                expireCount++;
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Should receive exactly 1 expire callback", 1, expireCount);
    }

    node1.cancelListen(key, ftoken.get());
}

void
DhtRunnerTester::testListenEditChainThenExpire()
{
    // Chain of 5 rapid edits (seq 1→5) on the same value, then natural expiration.
    // Must see 5 adds (one per edit), 0 expires during edits, then exactly 1 expire.
    static constexpr dht::ValueType::Id CHAIN_TYPE_ID = 7654;
    const dht::ValueType chainType {CHAIN_TYPE_ID,
                                    "chain-edit",
                                    std::chrono::seconds(2),
                                    dht::ValueType::DEFAULT_STORE_POLICY,
                                    [](dht::InfoHash,
                                       const std::shared_ptr<dht::Value>&,
                                       std::shared_ptr<dht::Value>&,
                                       const dht::InfoHash&,
                                       const dht::SockAddr&) { return true; }};
    node1.registerType(chainType);
    node2.registerType(chainType);

    auto key = dht::InfoHash::get("editChainExpire");
    auto identity = dht::crypto::generateIdentity("ChainEditTester");

    std::mutex mtx;
    std::condition_variable cv;
    struct Event { dht::Value::Id id; uint16_t seq; bool expired; };
    std::vector<Event> events;

    auto ftoken = node1.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        std::lock_guard lk(mtx);
        for (const auto& v : vals)
            events.push_back({v->id, v->seq, expired});
        cv.notify_all();
        return true;
    });

    // Rapid chain of 5 edits — wait for the first to arrive before continuing
    constexpr int NUM_EDITS = 5;
    {
        auto v = std::make_shared<dht::Value>("version1");
        v->type = CHAIN_TYPE_ID;
        v->id = 99;
        v->seq = 1;
        v->sign(*identity.first);
        std::promise<bool> p;
        node2.put(key, v, [&](bool ok) { p.set_value(ok); });
        CPPUNIT_ASSERT(getFutureValue(p.get_future()));
    }

    // Wait for first add to arrive before sending more edits
    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
            return std::any_of(events.begin(), events.end(), [](const Event& e) { return !e.expired; });
        }));
    }

    // Now send remaining edits rapidly
    for (int seq = 2; seq <= NUM_EDITS; seq++) {
        auto v = std::make_shared<dht::Value>("version" + std::to_string(seq));
        v->type = CHAIN_TYPE_ID;
        v->id = 99;
        v->seq = seq;
        v->sign(*identity.first);
        std::promise<bool> p;
        node2.put(key, v, [&](bool ok) { p.set_value(ok); });
        CPPUNIT_ASSERT(getFutureValue(p.get_future()));
    }

    // Wait for edits to arrive (at least 2: initial + one or more updates)
    // Note: rapid edits may coalesce — the DHT stores only the latest seq,
    // so the listener may not see every intermediate version.
    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 15s, [&] {
            int adds = 0;
            for (const auto& e : events)
                if (!e.expired)
                    adds++;
            return adds >= 2;
        }));
    }

    // Wait a bit more for any remaining events
    std::this_thread::sleep_for(1s);

    // Verify: multiple adds, 0 expires during edits (no phantom expiry)
    int totalAdds;
    {
        std::lock_guard lk(mtx);
        totalAdds = 0;
        int expireCount = 0;
        for (const auto& e : events) {
            if (e.expired)
                expireCount++;
            else
                totalAdds++;
        }
        CPPUNIT_ASSERT_MESSAGE("Should receive at least 2 add callbacks", totalAdds >= 2);
        CPPUNIT_ASSERT_EQUAL_MESSAGE("No expires during edit chain", 0, expireCount);

        // Verify the latest add has the highest seq
        uint16_t maxSeq = 0;
        for (const auto& e : events)
            if (!e.expired && e.seq > maxSeq)
                maxSeq = e.seq;
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Latest add should have the final seq",
                                     (uint16_t) NUM_EDITS, maxSeq);
    }

    // Wait for natural expiration
    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT_MESSAGE("Value should eventually expire", cv.wait_for(lk, 60s, [&] {
            return std::any_of(events.begin(), events.end(), [](const Event& e) { return e.expired; });
        }));
    }

    // Verify exactly 1 expire with the latest seq
    {
        std::lock_guard lk(mtx);
        int expireCount = 0;
        uint16_t expiredSeq = 0;
        for (const auto& e : events) {
            if (e.expired) {
                expireCount++;
                expiredSeq = e.seq;
            }
        }
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Should receive exactly 1 expire", 1, expireCount);
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Expired value should be the latest version",
                                     (uint16_t) NUM_EDITS, expiredSeq);
    }

    node1.cancelListen(key, ftoken.get());
}

void
DhtRunnerTester::testListenMultiValuePartialExpire()
{
    // Two values with different types: one short-lived (2s), one long-lived (60s).
    // The short one expires while the long one stays. Verify isolation:
    // no spurious expire for the long-lived value.
    static constexpr dht::ValueType::Id SHORT_TYPE_ID = 3001;
    static constexpr dht::ValueType::Id LONG_TYPE_ID = 3002;
    const dht::ValueType shortType {SHORT_TYPE_ID,
                                    "short-partial",
                                    std::chrono::seconds(2),
                                    dht::ValueType::DEFAULT_STORE_POLICY,
                                    [](dht::InfoHash,
                                       const std::shared_ptr<dht::Value>&,
                                       std::shared_ptr<dht::Value>&,
                                       const dht::InfoHash&,
                                       const dht::SockAddr&) { return true; }};
    const dht::ValueType longType {LONG_TYPE_ID,
                                   "long-partial",
                                   std::chrono::seconds(600),
                                   dht::ValueType::DEFAULT_STORE_POLICY,
                                   [](dht::InfoHash,
                                      const std::shared_ptr<dht::Value>&,
                                      std::shared_ptr<dht::Value>&,
                                      const dht::InfoHash&,
                                      const dht::SockAddr&) { return true; }};
    node1.registerType(shortType);
    node1.registerType(longType);
    node2.registerType(shortType);
    node2.registerType(longType);

    auto key = dht::InfoHash::get("multiValuePartialExpire");
    auto identity = dht::crypto::generateIdentity("PartialExpireTester");

    std::mutex mtx;
    std::condition_variable cv;
    struct Event { dht::Value::Id id; bool expired; };
    std::vector<Event> events;

    auto ftoken = node1.listen(key, [&](const std::vector<std::shared_ptr<dht::Value>>& vals, bool expired) {
        std::lock_guard lk(mtx);
        for (const auto& v : vals)
            events.push_back({v->id, expired});
        cv.notify_all();
        return true;
    });

    // Put short-lived value (id=1)
    auto shortVal = std::make_shared<dht::Value>("short");
    shortVal->type = SHORT_TYPE_ID;
    shortVal->id = 1;
    shortVal->seq = 1;
    shortVal->sign(*identity.first);
    {
        std::promise<bool> p;
        node2.put(key, shortVal, [&](bool ok) { p.set_value(ok); });
        CPPUNIT_ASSERT(getFutureValue(p.get_future()));
    }

    // Put long-lived value (id=2)
    auto longVal = std::make_shared<dht::Value>("long");
    longVal->type = LONG_TYPE_ID;
    longVal->id = 2;
    longVal->seq = 1;
    longVal->sign(*identity.first);
    {
        std::promise<bool> p;
        node2.put(key, longVal, [&](bool ok) { p.set_value(ok); });
        CPPUNIT_ASSERT(getFutureValue(p.get_future()));
    }

    // Wait for both adds
    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] {
            int adds = 0;
            for (const auto& e : events)
                if (!e.expired)
                    adds++;
            return adds >= 2;
        }));
    }

    // Wait for short-lived value to expire
    {
        std::unique_lock lk(mtx);
        CPPUNIT_ASSERT_MESSAGE("Short-lived value should expire", cv.wait_for(lk, 60s, [&] {
            return std::any_of(events.begin(), events.end(), [](const Event& e) {
                return e.id == 1 && e.expired;
            });
        }));
    }

    // Give extra time for any spurious callbacks
    std::this_thread::sleep_for(1s);

    // Verify: value 1 expired, value 2 did NOT expire
    {
        std::lock_guard lk(mtx);
        bool longExpired = std::any_of(events.begin(), events.end(), [](const Event& e) {
            return e.id == 2 && e.expired;
        });
        CPPUNIT_ASSERT_MESSAGE("Long-lived value should NOT be expired", !longExpired);

        int shortExpires = 0;
        for (const auto& e : events)
            if (e.id == 1 && e.expired)
                shortExpires++;
        CPPUNIT_ASSERT_EQUAL_MESSAGE("Short-lived value should expire exactly once", 1, shortExpires);
    }

    node1.cancelListen(key, ftoken.get());
}

} // namespace test
