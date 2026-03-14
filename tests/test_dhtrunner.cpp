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
    node2.listen(key2, [&](const std::vector<std::shared_ptr<dht::Value>>& values, bool /*expired*/) {
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

} // namespace test
