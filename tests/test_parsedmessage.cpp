// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_parsedmessage.h"

#include "opendht/value.h"
#include "opendht/node.h"
#include "opendht/utils.h"

#include "../src/parsed_message.h"

#include <iostream>
#include <limits>
#include <string>

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(ParsedMessageTester);

using namespace dht;
using namespace dht::net;

static constexpr size_t TEST_MTU {1280};

// Helper: create a ParsedMessage with a single value_parts entry of given total_size
static ParsedMessage
makeHeader(unsigned index, size_t total_size)
{
    ParsedMessage msg;
    msg.value_parts[index].total_size = total_size;
    return msg;
}

// Helper: create a ParsedMessage fragment (as if parsed from ValueData)
static ParsedMessage
makeFragment(unsigned index, size_t offset, const Blob& data)
{
    ParsedMessage frag;
    frag.fragment_parts[index] = {offset, data};
    return frag;
}

// Helper: serialize a Value to a Blob
static Blob
serializeValue(const std::string& data)
{
    auto val = std::make_shared<Value>((const uint8_t*) data.data(), data.size());
    return packMsg(val);
}

static ParsedMessage
parsePackedMessage(msgpack::sbuffer& buffer)
{
    auto msg = msgpack::unpack(buffer.data(), buffer.size());
    ParsedMessage parsed;
    parsed.msgpack_unpack(msg.get());
    return parsed;
}

static ParsedMessage
makeReplyHeaderPacket(Tid tid, const std::vector<size_t>& valueSizes)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);

    pk.pack_map(3);
    pk.pack(KEY_R);
    pk.pack_map(1);
    pk.pack(KEY_REQ_VALUES);
    pk.pack_array(valueSizes.size());
    for (const auto& size : valueSizes)
        pk.pack(size);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_Y);
    pk.pack(KEY_R);

    return parsePackedMessage(buffer);
}

static ParsedMessage
makeValueDataPacket(Tid tid, unsigned index, size_t offset, const Blob& data)
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);

    pk.pack_map(3);
    pk.pack(KEY_Y);
    pk.pack(KEY_V);
    pk.pack(KEY_TID);
    pk.pack(tid);
    pk.pack(KEY_V);
    pk.pack_map(1);
    pk.pack(index);
    pk.pack_map(2);
    pk.pack("o");
    pk.pack(offset);
    pk.pack("d");
    pk.pack_bin(data.size());
    pk.pack_bin_body((const char*) data.data(), data.size());

    return parsePackedMessage(buffer);
}

void
ParsedMessageTester::setUp()
{}

void
ParsedMessageTester::tearDown()
{}

// --- append tests ---

void
ParsedMessageTester::testAppendInOrder()
{
    Blob full = {1, 2, 3, 4, 5, 6};
    auto msg = makeHeader(0, full.size());

    // Send first half, then second half
    Blob part1(full.begin(), full.begin() + 3);
    Blob part2(full.begin() + 3, full.end());

    auto frag1 = makeFragment(0, 0, part1);
    auto frag2 = makeFragment(0, 3, part2);

    CPPUNIT_ASSERT(msg.append(frag1));
    CPPUNIT_ASSERT(msg.append(frag2));

    auto& pv = msg.value_parts[0];
    CPPUNIT_ASSERT(pv.isComplete());
    CPPUNIT_ASSERT_EQUAL(full.size(), pv.received_bytes);

    auto reassembled = pv.reassemble();
    CPPUNIT_ASSERT(reassembled == full);
}

void
ParsedMessageTester::testAppendOutOfOrder()
{
    Blob full = {10, 20, 30, 40, 50, 60};
    auto msg = makeHeader(0, full.size());

    Blob part1(full.begin(), full.begin() + 2);     // [0..2)
    Blob part2(full.begin() + 2, full.begin() + 4); // [2..4)
    Blob part3(full.begin() + 4, full.end());       // [4..6)

    // Send in order: part3, part1, part2
    CPPUNIT_ASSERT(msg.append(makeFragment(0, 4, part3)));
    CPPUNIT_ASSERT(!msg.value_parts[0].isComplete());

    CPPUNIT_ASSERT(msg.append(makeFragment(0, 0, part1)));
    CPPUNIT_ASSERT(!msg.value_parts[0].isComplete());

    CPPUNIT_ASSERT(msg.append(makeFragment(0, 2, part2)));
    CPPUNIT_ASSERT(msg.value_parts[0].isComplete());

    auto reassembled = msg.value_parts[0].reassemble();
    CPPUNIT_ASSERT(reassembled == full);
}

void
ParsedMessageTester::testAppendReverseOrder()
{
    Blob full = {1, 2, 3, 4, 5, 6, 7, 8};
    auto msg = makeHeader(0, full.size());

    // 4 fragments of 2 bytes each, sent in reverse
    for (int i = 3; i >= 0; --i) {
        size_t offset = i * 2;
        Blob part(full.begin() + offset, full.begin() + offset + 2);
        CPPUNIT_ASSERT(msg.append(makeFragment(0, offset, part)));
    }

    CPPUNIT_ASSERT(msg.value_parts[0].isComplete());
    CPPUNIT_ASSERT(msg.value_parts[0].reassemble() == full);
}

void
ParsedMessageTester::testAppendDuplicateFragment()
{
    Blob full = {1, 2, 3, 4};
    auto msg = makeHeader(0, full.size());

    Blob part1(full.begin(), full.begin() + 2);
    Blob part2(full.begin() + 2, full.end());

    CPPUNIT_ASSERT(msg.append(makeFragment(0, 0, part1)));
    // Duplicate of first fragment should be rejected
    CPPUNIT_ASSERT(!msg.append(makeFragment(0, 0, part1)));

    CPPUNIT_ASSERT(msg.append(makeFragment(0, 2, part2)));
    CPPUNIT_ASSERT(msg.value_parts[0].isComplete());
    CPPUNIT_ASSERT_EQUAL((size_t) 4, msg.value_parts[0].received_bytes);
}

void
ParsedMessageTester::testAppendOverlappingFragments()
{
    Blob full = {1, 2, 3, 4, 5, 6};
    auto msg = makeHeader(0, full.size());

    // Fragment [0..3)
    Blob part1(full.begin(), full.begin() + 3);
    CPPUNIT_ASSERT(msg.append(makeFragment(0, 0, part1)));

    // Overlapping fragment [2..5) should be rejected
    Blob overlap(full.begin() + 2, full.begin() + 5);
    CPPUNIT_ASSERT(!msg.append(makeFragment(0, 2, overlap)));

    // Non-overlapping fragment [3..6) should succeed
    Blob part2(full.begin() + 3, full.end());
    CPPUNIT_ASSERT(msg.append(makeFragment(0, 3, part2)));

    CPPUNIT_ASSERT(msg.value_parts[0].isComplete());
    CPPUNIT_ASSERT(msg.value_parts[0].reassemble() == full);
}

void
ParsedMessageTester::testAppendFragmentBeyondTotal()
{
    auto msg = makeHeader(0, 4);

    // Fragment at offset 3 with 2 bytes goes beyond total_size of 4
    Blob data = {1, 2};
    CPPUNIT_ASSERT(!msg.append(makeFragment(0, 3, data)));
    CPPUNIT_ASSERT_EQUAL((size_t) 0, msg.value_parts[0].received_bytes);
}

void
ParsedMessageTester::testAppendEmptyFragment()
{
    auto msg = makeHeader(0, 4);

    Blob empty;
    CPPUNIT_ASSERT(!msg.append(makeFragment(0, 0, empty)));
    CPPUNIT_ASSERT_EQUAL((size_t) 0, msg.value_parts[0].received_bytes);
}

void
ParsedMessageTester::testAppendUnknownIndex()
{
    auto msg = makeHeader(0, 10);

    // Fragment for index 1 which doesn't exist in value_parts
    Blob data = {1, 2, 3};
    CPPUNIT_ASSERT(!msg.append(makeFragment(1, 0, data)));
    // Index 0 should be untouched
    CPPUNIT_ASSERT_EQUAL((size_t) 0, msg.value_parts[0].received_bytes);
}

void
ParsedMessageTester::testAppendAlreadyComplete()
{
    Blob full = {1, 2, 3, 4};
    auto msg = makeHeader(0, full.size());

    // Complete the value
    CPPUNIT_ASSERT(msg.append(makeFragment(0, 0, full)));
    CPPUNIT_ASSERT(msg.value_parts[0].isComplete());

    // Further fragment should be rejected
    Blob extra = {5, 6};
    CPPUNIT_ASSERT(!msg.append(makeFragment(0, 0, extra)));
}

void
ParsedMessageTester::testAppendOverflowingOffset()
{
    auto msg = makeHeader(0, 4);

    Blob data = {1};
    CPPUNIT_ASSERT(!msg.append(makeFragment(0, std::numeric_limits<size_t>::max(), data)));
    CPPUNIT_ASSERT_EQUAL((size_t) 0, msg.value_parts[0].received_bytes);
}

void
ParsedMessageTester::testParseRejectsNonMapPacket()
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_array(1);
    pk.pack(42);

    auto msg = msgpack::unpack(buffer.data(), buffer.size());
    ParsedMessage parsed;
    CPPUNIT_ASSERT_THROW(parsed.msgpack_unpack(msg.get()), msgpack::type_error);
}

void
ParsedMessageTester::testParseRejectsInvalidValueDataPayload()
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);

    pk.pack_map(3);
    pk.pack(KEY_Y);
    pk.pack(KEY_V);
    pk.pack(KEY_TID);
    pk.pack(1u);
    pk.pack(KEY_V);
    pk.pack_array(1);
    pk.pack(42);

    auto msg = msgpack::unpack(buffer.data(), buffer.size());
    ParsedMessage parsed;
    CPPUNIT_ASSERT_THROW(parsed.msgpack_unpack(msg.get()), msgpack::type_error);
}

void
ParsedMessageTester::testParseRejectsInvalidValuesField()
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);

    pk.pack_map(3);
    pk.pack(KEY_R);
    pk.pack_map(1);
    pk.pack(KEY_REQ_VALUES);
    pk.pack("invalid");
    pk.pack(KEY_TID);
    pk.pack(1u);
    pk.pack(KEY_Y);
    pk.pack(KEY_R);

    auto msg = msgpack::unpack(buffer.data(), buffer.size());
    ParsedMessage parsed;
    CPPUNIT_ASSERT_THROW(parsed.msgpack_unpack(msg.get()), msgpack::type_error);
}

void
ParsedMessageTester::testParseIgnoresIncompleteValueDataEntry()
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);

    pk.pack_map(3);
    pk.pack(KEY_Y);
    pk.pack(KEY_V);
    pk.pack(KEY_TID);
    pk.pack(1u);
    pk.pack(KEY_V);
    pk.pack_map(1);
    pk.pack(0u);
    pk.pack_map(1);
    pk.pack("o");
    pk.pack(0u);

    auto msg = msgpack::unpack(buffer.data(), buffer.size());
    ParsedMessage parsed;
    parsed.msgpack_unpack(msg.get());

    CPPUNIT_ASSERT(parsed.fragment_parts.empty());
}

// --- complete tests ---

void
ParsedMessageTester::testCompleteEmpty()
{
    // No value_parts at all — should be trivially complete
    ParsedMessage msg;
    CPPUNIT_ASSERT(msg.complete());
    CPPUNIT_ASSERT(msg.values.empty());
}

void
ParsedMessageTester::testCompleteIncomplete()
{
    auto msg = makeHeader(0, 100);
    Blob partial = {1, 2, 3};
    msg.append(makeFragment(0, 0, partial));

    CPPUNIT_ASSERT(!msg.complete());
    CPPUNIT_ASSERT(msg.values.empty());
}

void
ParsedMessageTester::testCompleteZeroSizedValue()
{
    auto msg = makeHeader(0, 0);

    CPPUNIT_ASSERT(!msg.value_parts[0].isComplete());
    CPPUNIT_ASSERT(!msg.complete());
    CPPUNIT_ASSERT(msg.values.empty());
}

void
ParsedMessageTester::testCompleteSingleValue()
{
    std::string data = "hello world";
    auto serialized = serializeValue(data);

    auto msg = makeHeader(0, serialized.size());
    msg.append(makeFragment(0, 0, serialized));
    CPPUNIT_ASSERT(msg.value_parts[0].isComplete());

    CPPUNIT_ASSERT(msg.complete());
    CPPUNIT_ASSERT_EQUAL((size_t) 1, msg.values.size());

    std::string recovered(msg.values[0]->data.begin(), msg.values[0]->data.end());
    CPPUNIT_ASSERT_EQUAL(data, recovered);
}

void
ParsedMessageTester::testCompleteMultipleValues()
{
    std::string data1 = "first value";
    std::string data2 = "second value";
    auto ser1 = serializeValue(data1);
    auto ser2 = serializeValue(data2);

    ParsedMessage msg;
    msg.value_parts[0].total_size = ser1.size();
    msg.value_parts[1].total_size = ser2.size();

    msg.append(makeFragment(0, 0, ser1));
    msg.append(makeFragment(1, 0, ser2));

    CPPUNIT_ASSERT(msg.complete());
    CPPUNIT_ASSERT_EQUAL((size_t) 2, msg.values.size());

    std::string r1(msg.values[0]->data.begin(), msg.values[0]->data.end());
    std::string r2(msg.values[1]->data.begin(), msg.values[1]->data.end());
    CPPUNIT_ASSERT_EQUAL(data1, r1);
    CPPUNIT_ASSERT_EQUAL(data2, r2);
}

void
ParsedMessageTester::testCompleteReassemblyOrder()
{
    // Verify that out-of-order fragments produce correct reassembly
    std::string data = "test data for fragmentation";
    auto serialized = serializeValue(data);

    auto msg = makeHeader(0, serialized.size());

    // Split into 3 fragments and send out of order
    size_t chunk = serialized.size() / 3;
    Blob frag1(serialized.begin(), serialized.begin() + chunk);
    Blob frag2(serialized.begin() + chunk, serialized.begin() + 2 * chunk);
    Blob frag3(serialized.begin() + 2 * chunk, serialized.end());

    // Send: third, first, second
    CPPUNIT_ASSERT(msg.append(makeFragment(0, 2 * chunk, frag3)));
    CPPUNIT_ASSERT(msg.append(makeFragment(0, 0, frag1)));
    CPPUNIT_ASSERT(msg.append(makeFragment(0, chunk, frag2)));

    CPPUNIT_ASSERT(msg.value_parts[0].isComplete());
    CPPUNIT_ASSERT(msg.complete());
    CPPUNIT_ASSERT_EQUAL((size_t) 1, msg.values.size());

    std::string recovered(msg.values[0]->data.begin(), msg.values[0]->data.end());
    CPPUNIT_ASSERT_EQUAL(data, recovered);
}

void
ParsedMessageTester::testAppendMultipleValuesOutOfOrder()
{
    // Two values, both fragmented, fragments interleaved and out of order
    Blob val1 = {1, 2, 3, 4, 5, 6};
    Blob val2 = {10, 20, 30, 40};

    ParsedMessage msg;
    msg.value_parts[0].total_size = val1.size();
    msg.value_parts[1].total_size = val2.size();

    // val2 second half
    CPPUNIT_ASSERT(msg.append(makeFragment(1, 2, Blob {30, 40})));
    // val1 last third
    CPPUNIT_ASSERT(msg.append(makeFragment(0, 4, Blob {5, 6})));
    // val2 first half
    CPPUNIT_ASSERT(msg.append(makeFragment(1, 0, Blob {10, 20})));
    // val1 first third
    CPPUNIT_ASSERT(msg.append(makeFragment(0, 0, Blob {1, 2})));
    // val1 middle third
    CPPUNIT_ASSERT(msg.append(makeFragment(0, 2, Blob {3, 4})));

    CPPUNIT_ASSERT(msg.value_parts[0].isComplete());
    CPPUNIT_ASSERT(msg.value_parts[1].isComplete());
    CPPUNIT_ASSERT(msg.value_parts[0].reassemble() == val1);
    CPPUNIT_ASSERT(msg.value_parts[1].reassemble() == val2);
}

void
ParsedMessageTester::testReceiveLargeFragmentedValue()
{
    std::string data(TEST_MTU * 3, 'x');
    auto serialized = serializeValue(data);
    CPPUNIT_ASSERT(serialized.size() > TEST_MTU);

    auto msg = makeReplyHeaderPacket(1, {serialized.size()});
    CPPUNIT_ASSERT_EQUAL((size_t) 1, msg.value_parts.size());
    CPPUNIT_ASSERT_EQUAL(serialized.size(), msg.value_parts[0].total_size);

    for (size_t offset = 0; offset < serialized.size(); offset += TEST_MTU) {
        auto end = std::min(offset + TEST_MTU, serialized.size());
        Blob fragment(serialized.begin() + offset, serialized.begin() + end);
        auto packet = makeValueDataPacket(1, 0, offset, fragment);
        CPPUNIT_ASSERT(msg.append(packet));
    }

    CPPUNIT_ASSERT(msg.value_parts[0].isComplete());
    CPPUNIT_ASSERT(msg.complete());
    CPPUNIT_ASSERT_EQUAL((size_t) 1, msg.values.size());

    std::string recovered(msg.values[0]->data.begin(), msg.values[0]->data.end());
    CPPUNIT_ASSERT_EQUAL(data, recovered);
}

void
ParsedMessageTester::testReceiveLargeFragmentedValueOutOfOrder()
{
    std::string data(TEST_MTU * 3 + 117, 'y');
    auto serialized = serializeValue(data);
    CPPUNIT_ASSERT(serialized.size() > TEST_MTU);

    auto msg = makeReplyHeaderPacket(7, {serialized.size()});
    std::vector<ParsedMessage> packets;
    for (size_t offset = 0; offset < serialized.size(); offset += TEST_MTU) {
        auto end = std::min(offset + TEST_MTU, serialized.size());
        Blob fragment(serialized.begin() + offset, serialized.begin() + end);
        packets.emplace_back(makeValueDataPacket(7, 0, offset, fragment));
    }

    CPPUNIT_ASSERT(packets.size() >= 3);
    CPPUNIT_ASSERT(msg.append(packets.back()));
    CPPUNIT_ASSERT(msg.append(packets.front()));
    for (size_t i = 1; i + 1 < packets.size(); ++i)
        CPPUNIT_ASSERT(msg.append(packets[i]));

    CPPUNIT_ASSERT(msg.value_parts[0].isComplete());
    CPPUNIT_ASSERT(msg.complete());
    CPPUNIT_ASSERT_EQUAL((size_t) 1, msg.values.size());

    std::string recovered(msg.values[0]->data.begin(), msg.values[0]->data.end());
    CPPUNIT_ASSERT_EQUAL(data, recovered);
}

} // namespace test
