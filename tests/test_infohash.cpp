// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_infohash.h"

// std
#include <iostream>
#include <string>
#include <string_view>

// opendht
#include "opendht/infohash.h"

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(InfoHashTester);

void
InfoHashTester::setUp()
{}

void
InfoHashTester::testConstructors()
{
    // Default constructor creates a null infohash
    constexpr auto nullHash = dht::InfoHash();
    CPPUNIT_ASSERT_EQUAL((size_t) 20u, nullHash.size());
    CPPUNIT_ASSERT(!nullHash);
    // Build from a uint8_t. if length to short, should get a null infohash
    constexpr uint8_t too_short[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
    auto infohash = dht::InfoHash(too_short, 8);
    CPPUNIT_ASSERT_EQUAL((size_t) 20u, infohash.size());
    CPPUNIT_ASSERT_EQUAL(std::string("0000000000000000000000000000000000000000"), infohash.toString());
    // Build from a uint8_t. if length is enough, data should contains the uint8_t
    constexpr uint8_t enough[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa,
                                  0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa};
    infohash = dht::InfoHash(enough, 20);
    static_assert(dht::InfoHash(enough, 20) != nullHash);
    CPPUNIT_ASSERT_EQUAL((size_t) 20u, infohash.size());
    const auto* data = infohash.data();
    for (auto i = 0; i < 20; ++i) {
        CPPUNIT_ASSERT_EQUAL(enough[i], data[i]);
    }
    // if too long, should be cutted to 20
    constexpr uint8_t tooLong[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0x1,
                                   0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb0};
    infohash = dht::InfoHash(tooLong, 21);
    const auto* data2 = infohash.data();
    for (auto i = 0; i < 20; ++i) {
        CPPUNIT_ASSERT_EQUAL(enough[i], data2[i]);
    }
    // Build from string
    constexpr auto infohashFromStr = dht::InfoHash("0102030405060708090A0102030405060708090A");
    CPPUNIT_ASSERT_EQUAL((size_t) 20u, infohashFromStr.size());
    const auto* dataStr = infohashFromStr.data();
    for (auto i = 0; i < 20; ++i) {
        CPPUNIT_ASSERT_EQUAL((int) dataStr[i], (int) data[i]);
    }

    // invalid strings
    constexpr auto invalidHash = dht::InfoHash("invalid_string0102030405060708090A010203");
    CPPUNIT_ASSERT_EQUAL((size_t) 20u, invalidHash.size());
    CPPUNIT_ASSERT(!invalidHash);
    CPPUNIT_ASSERT_EQUAL(nullHash, invalidHash);
    static_assert(invalidHash == nullHash, "Invalid hash string should result in null hash");

    constexpr auto tooShortHash = dht::InfoHash("0123456789abcdef0123456789abcdef012345");
    CPPUNIT_ASSERT_EQUAL((size_t) 20u, tooShortHash.size());
    CPPUNIT_ASSERT(!tooShortHash);
    CPPUNIT_ASSERT_EQUAL(nullHash, tooShortHash);
    static_assert(tooShortHash == nullHash, "Too short hash string should result in null hash");
}

void
InfoHashTester::testComparators()
{
    constexpr auto nullHash = dht::InfoHash();
    constexpr auto minHash = dht::InfoHash("0000000000000000000000000000000000111110");
    constexpr auto maxHash = dht::InfoHash("0111110000000000000000000000000000000000");
    // operator ==
    CPPUNIT_ASSERT_EQUAL(minHash, minHash);
    CPPUNIT_ASSERT_EQUAL(minHash, dht::InfoHash("0000000000000000000000000000000000111110"));
    CPPUNIT_ASSERT(!(minHash == maxHash));
    // operator !=
    CPPUNIT_ASSERT(!(minHash != minHash));
    CPPUNIT_ASSERT(!(minHash != dht::InfoHash("0000000000000000000000000000000000111110")));
    CPPUNIT_ASSERT(minHash != maxHash);
    // operator<
    CPPUNIT_ASSERT(nullHash < minHash);
    CPPUNIT_ASSERT(nullHash < maxHash);
    CPPUNIT_ASSERT(minHash < maxHash);
    CPPUNIT_ASSERT(!(minHash < nullHash));
    CPPUNIT_ASSERT(!(maxHash < nullHash));
    CPPUNIT_ASSERT(!(maxHash < minHash));
    CPPUNIT_ASSERT(!(minHash < minHash));
    // bool()
    CPPUNIT_ASSERT(maxHash);
    CPPUNIT_ASSERT(!nullHash);
}

void
InfoHashTester::testLowBit()
{
    auto nullHash = dht::InfoHash();
    auto minHash = dht::InfoHash("0000000000000000000000000000000000000010");
    auto maxHash = dht::InfoHash("0100000000000000000000000000000000000000");
    CPPUNIT_ASSERT_EQUAL(nullHash.lowbit(), -1);
    CPPUNIT_ASSERT_EQUAL(minHash.lowbit(), 155);
    CPPUNIT_ASSERT_EQUAL(maxHash.lowbit(), 7);
}

void
InfoHashTester::testCommonBits()
{
    auto nullHash = dht::InfoHash();
    auto minHash = dht::InfoHash("0000000000000000000000000000000000000010");
    auto maxHash = dht::InfoHash("0100000000000000000000000000000000000000");
    CPPUNIT_ASSERT_EQUAL(dht::InfoHash::commonBits(nullHash, nullHash), (unsigned) 160);
    CPPUNIT_ASSERT_EQUAL(dht::InfoHash::commonBits(nullHash, minHash), (unsigned) 155);
    CPPUNIT_ASSERT_EQUAL(dht::InfoHash::commonBits(nullHash, maxHash), (unsigned) 7);
    CPPUNIT_ASSERT_EQUAL(dht::InfoHash::commonBits(minHash, maxHash), (unsigned) 7);
}

void
InfoHashTester::testXorCmp()
{
    auto nullHash = dht::InfoHash();
    auto minHash = dht::InfoHash("0000000000000000000000000000000000000010");
    auto maxHash = dht::InfoHash("0100000000000000000000000000000000000000");
    CPPUNIT_ASSERT_EQUAL(minHash.xorCmp(nullHash, maxHash), -1);
    CPPUNIT_ASSERT_EQUAL(minHash.xorCmp(maxHash, nullHash), 1);
    CPPUNIT_ASSERT_EQUAL(minHash.xorCmp(minHash, maxHash), -1);
    CPPUNIT_ASSERT_EQUAL(minHash.xorCmp(maxHash, minHash), 1);
    CPPUNIT_ASSERT_EQUAL(nullHash.xorCmp(minHash, maxHash), -1);
    CPPUNIT_ASSERT_EQUAL(nullHash.xorCmp(maxHash, minHash), 1);
    // Because hashes are circular in distance.
    CPPUNIT_ASSERT_EQUAL(maxHash.xorCmp(nullHash, minHash), -1);
    CPPUNIT_ASSERT_EQUAL(maxHash.xorCmp(minHash, nullHash), 1);
}

void
InfoHashTester::testHex()
{
    using namespace std::literals;
    static constexpr auto H = "0123456789abcdef0123456789abcdef01234567"sv;
    const std::string TEST_HASH_STR(H);
    dht::InfoHash TEST_HASH(TEST_HASH_STR);
    static constexpr dht::InfoHash TEST_HASH_CONST(H);
    CPPUNIT_ASSERT_EQUAL(TEST_HASH_STR, TEST_HASH.toString());
    CPPUNIT_ASSERT_EQUAL(H, TEST_HASH.to_view());
    CPPUNIT_ASSERT_EQUAL(TEST_HASH_STR, dht::toHex(TEST_HASH.data(), TEST_HASH.size()));
    CPPUNIT_ASSERT_EQUAL(TEST_HASH_CONST.to_view(), H);

    static constexpr auto hexArray = dht::toHexArray(TEST_HASH_CONST);
    static constexpr auto hexArrayView = std::string_view(hexArray.data(), hexArray.size());
    static_assert(hexArrayView == H, "Hex array does not match");

    CPPUNIT_ASSERT_EQUAL(std::string_view(TEST_HASH_STR), hexArrayView);
}

void
InfoHashTester::tearDown()
{}
} // namespace test
