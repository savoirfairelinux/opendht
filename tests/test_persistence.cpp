// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#include "test_persistence.h"

#include <opendht.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(PersistenceTester);

namespace {

constexpr const char* STATE_PATH = "test_persistence_state";

/** The saved state, as Dht writes it. */
struct SavedState
{
    unsigned v {1};
    dht::InfoHash id;
    std::vector<dht::NodeExport> nodes;
    std::vector<dht::ValuesExport> values;
    int64_t saved_steady {0};
    int64_t saved_wall {0};

    MSGPACK_DEFINE_MAP(v, id, nodes, values, saved_steady, saved_wall)
};

SavedState readState(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    CPPUNIT_ASSERT(file.is_open());
    const std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    CPPUNIT_ASSERT(not data.empty());
    msgpack::object_handle oh = msgpack::unpack(data.data(), data.size());
    return oh.get().as<SavedState>();
}

void writeState(const std::string& path, const SavedState& state)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    msgpack::pack(file, state);
}

/** Saves a node holding one value under @p key, and returns its state. */
SavedState saveOneValue(const dht::InfoHash& key)
{
    std::remove(STATE_PATH);
    dht::DhtRunner node;
    dht::DhtRunner::Config config;
    config.dht_config.node_config.persist_path = STATE_PATH;
    node.run(0, config);
    node.put(key, dht::Value(reinterpret_cast<const uint8_t*>("kept"), 4));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    node.shutdown();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    node.join();
    return readState(STATE_PATH);
}

/** Counts the values a node loads back from the saved state. */
size_t loadValueCount()
{
    dht::DhtRunner node;
    dht::DhtRunner::Config config;
    config.dht_config.node_config.persist_path = STATE_PATH;
    node.run(0, config);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto count = node.exportValues().size();
    node.join();
    return count;
}

} // namespace

void
PersistenceTester::setUp()
{}

void
PersistenceTester::tearDown()
{
    std::remove(STATE_PATH);
    std::remove((std::string(STATE_PATH) + "_port.txt").c_str());
}

void
PersistenceTester::testRestartKeepsValues()
{
    const auto key = dht::InfoHash::get("persisted key");
    const auto state = saveOneValue(key);
    CPPUNIT_ASSERT_EQUAL(size_t(1), state.values.size());

    CPPUNIT_ASSERT_EQUAL(size_t(1), loadValueCount());
}

void
PersistenceTester::testRebootExpiresValues()
{
    const auto key = dht::InfoHash::get("persisted key");
    auto state = saveOneValue(key);
    CPPUNIT_ASSERT_EQUAL(size_t(1), state.values.size());

    /* A reboot leaves the steady clock where the saved timestamps point, while
       the wall clock records the hour the node spent down. The value's ten
       minute lifetime ran out during that hour. */
    state.saved_wall -= std::chrono::nanoseconds(std::chrono::hours(1)).count();
    writeState(STATE_PATH, state);

    CPPUNIT_ASSERT_EQUAL(size_t(0), loadValueCount());
}

} // namespace test
