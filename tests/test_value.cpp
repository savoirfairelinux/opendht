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
ValueTester::testFieldValueIndexContainedIn()
{
    dht::Value first {(const uint8_t*) "a", 1};
    first.id = 1;
    dht::Value second {(const uint8_t*) "b", 1};
    second.id = 2;

    const dht::Select select {dht::Select {}.field(dht::Value::Field::Id)};
    dht::FieldValueIndex first_index {first, select};
    dht::FieldValueIndex second_index {second, select};

    // Same projected field, different values: neither index contains the other.
    CPPUNIT_ASSERT(not first_index.containedIn(second_index));
    CPPUNIT_ASSERT(not second_index.containedIn(first_index));

    // An index is always contained in an equal one.
    dht::FieldValueIndex first_copy {first, select};
    CPPUNIT_ASSERT(first_index.containedIn(first_copy));
    CPPUNIT_ASSERT(first_copy.containedIn(first_index));

    // A narrower projection with a matching value stays contained in a wider one.
    const dht::Select wider {dht::Select {}.field(dht::Value::Field::Id).field(dht::Value::Field::ValueType)};
    dht::FieldValueIndex first_wide {first, wider};
    CPPUNIT_ASSERT(first_index.containedIn(first_wide));
    CPPUNIT_ASSERT(not second_index.containedIn(first_wide));
}

void
ValueTester::testProjectionSatisfiedBy()
{
    const dht::Query broad {dht::Select {}.field(dht::Value::Field::Id)};
    const dht::Query filtered {dht::Select {}.field(dht::Value::Field::Id),
                               dht::Where {}.valueType(1)};

    // The unfiltered answer contains every value the filtered query asks for,
    // so it satisfies it, but it also contains values it must not report.
    CPPUNIT_ASSERT(filtered.isSatisfiedBy(broad));
    CPPUNIT_ASSERT(not filtered.isProjectionSatisfiedBy(broad));

    // The filtered answer is incomplete for the broad query either way.
    CPPUNIT_ASSERT(not broad.isSatisfiedBy(filtered));
    CPPUNIT_ASSERT(not broad.isProjectionSatisfiedBy(filtered));

    // Identical filters stay reusable, including for a wider projection.
    const dht::Query same {dht::Select {}.field(dht::Value::Field::Id),
                           dht::Where {}.valueType(1)};
    const dht::Query wider {dht::Select {}.field(dht::Value::Field::Id).field(dht::Value::Field::ValueType),
                            dht::Where {}.valueType(1)};
    CPPUNIT_ASSERT(filtered.isProjectionSatisfiedBy(same));
    CPPUNIT_ASSERT(filtered.isProjectionSatisfiedBy(wider));
    CPPUNIT_ASSERT(not wider.isProjectionSatisfiedBy(filtered));
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

void
ValueTester::testPushTypeJsonRoundTrip()
{
#ifdef OPENDHT_JSONCPP
    dht::Value original {(const uint8_t*) "hello", 5};
    original.id = 42;
    original.priority = 1;
    original.pushType = "videoCall";

    dht::Value restored(original.toJson());

    CPPUNIT_ASSERT_EQUAL(original.id, restored.id);
    CPPUNIT_ASSERT_EQUAL(original.priority, restored.priority);
    CPPUNIT_ASSERT_EQUAL(original.pushType, restored.pushType);

    // No pushType: the field must stay absent from the JSON and empty after parse.
    dht::Value plain {(const uint8_t*) "data", 4};
    plain.id = 7;
    auto json = plain.toJson();
    CPPUNIT_ASSERT(!json.isMember("pt"));
    dht::Value plainRestored(json);
    CPPUNIT_ASSERT_EQUAL(std::string(), plainRestored.pushType);
#endif
}

} // namespace test
