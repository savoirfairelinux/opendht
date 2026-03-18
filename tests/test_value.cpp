// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_value.h"

#include <iostream>
#include <string>

// opendht
#include "opendht/value.h"
#include "opendht/crypto.h"
#include <msgpack.hpp>

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(ValueTester);

void
ValueTester::setUp()
{}

void
ValueTester::testConstructors()
{
    std::string the_data {"42 cats"};
    dht::Value the_dht_value {(const uint8_t*) the_data.data(), the_data.size()};
    std::string from_value {the_dht_value.data.begin(), the_dht_value.data.end()};
    CPPUNIT_ASSERT_EQUAL(the_data, from_value);
}

void
ValueTester::testFilter()
{
    dht::Value::Filter defaultFiler {};

    auto isPairSize = dht::Value::Filter([](const dht::Value& v) { return v.data.size() % 2 == 0; });

    auto isUserTypeTest = dht::Value::Filter([](const dht::Value& v) { return v.user_type == "test"; });

    std::string data1 {"42 cats"};
    dht::Value value1 {(const uint8_t*) data1.data(), data1.size()};
    value1.user_type = "test";

    std::string data2 {"420 cats"};
    dht::Value value2 {(const uint8_t*) data2.data(), data2.size()};
    dht::Value value3 {(const uint8_t*) data2.data(), data2.size()};
    value3.user_type = "test";

    CPPUNIT_ASSERT(!isPairSize(value1));
    CPPUNIT_ASSERT(isUserTypeTest(value1));

    auto isBoth = dht::Value::Filter::chain(isPairSize, isUserTypeTest);
    auto isUserTypeTest2 = dht::Value::Filter::chain(defaultFiler, isUserTypeTest);

    CPPUNIT_ASSERT(isUserTypeTest2(value1));
    CPPUNIT_ASSERT(!isUserTypeTest2(value2));
    CPPUNIT_ASSERT(!isBoth(value1));
    CPPUNIT_ASSERT(!isBoth(value2));
    CPPUNIT_ASSERT(isBoth(value3));
}

void
ValueTester::tearDown()
{}

void
ValueTester::testPushTypeMsgpackRoundTrip()
{
    dht::Value original {(const uint8_t*) "hello", 5};
    original.id = 42;
    original.priority = 3;
    original.pushType = "audioCall";

    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    original.msgpack_pack(pk);

    msgpack::unpacked msg;
    msgpack::unpack(msg, buffer.data(), buffer.size());
    dht::Value restored(msg.get());

    CPPUNIT_ASSERT_EQUAL(original.id, restored.id);
    CPPUNIT_ASSERT_EQUAL(original.priority, restored.priority);
    CPPUNIT_ASSERT_EQUAL(original.pushType, restored.pushType);
}

void
ValueTester::testPushTypeAbsentAfterUnpack()
{
    dht::Value withPt {(const uint8_t*) "data", 4};
    withPt.id = 1;
    withPt.pushType = "videoCall";
    withPt.priority = 2;

    msgpack::sbuffer buf1;
    msgpack::packer<msgpack::sbuffer> pk1(&buf1);
    withPt.msgpack_pack(pk1);

    msgpack::unpacked msg1;
    msgpack::unpack(msg1, buf1.data(), buf1.size());

    dht::Value reused;
    reused.msgpack_unpack(msg1.get());
    CPPUNIT_ASSERT_EQUAL(std::string("videoCall"), reused.pushType);
    CPPUNIT_ASSERT_EQUAL(2u, reused.priority);

    dht::Value plain {(const uint8_t*) "data", 4};
    plain.id = 2;

    msgpack::sbuffer buf2;
    msgpack::packer<msgpack::sbuffer> pk2(&buf2);
    plain.msgpack_pack(pk2);

    msgpack::unpacked msg2;
    msgpack::unpack(msg2, buf2.data(), buf2.size());

    reused.msgpack_unpack(msg2.get());
    CPPUNIT_ASSERT_EQUAL(std::string(), reused.pushType);
    CPPUNIT_ASSERT_EQUAL(0u, reused.priority);
}

void
ValueTester::testPushTypePreservedAfterEncrypt()
{
    auto key = dht::crypto::PrivateKey::generate();
    const auto& pubkey = key.getPublicKey();

    dht::Value original {(const uint8_t*) "secret", 6};
    original.id = 99;
    original.priority = 1;
    original.pushType = "audioCall";

    auto encrypted = original.encrypt(key, pubkey);

    CPPUNIT_ASSERT_EQUAL(original.pushType, encrypted.pushType);
    CPPUNIT_ASSERT_EQUAL(original.priority, encrypted.priority);
    CPPUNIT_ASSERT_EQUAL(original.id, encrypted.id);
    CPPUNIT_ASSERT(encrypted.isEncrypted());
}

} // namespace test
