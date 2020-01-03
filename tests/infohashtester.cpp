/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
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

#include "infohashtester.h"

// std
#include <iostream>
#include <string>

// opendht
#include "opendht/infohash.h"

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(InfoHashTester);

void
InfoHashTester::setUp() {

}

void
InfoHashTester::testConstructors() {
    // Default constructor creates a null infohash
    auto nullHash = dht::InfoHash();
    CPPUNIT_ASSERT_EQUAL((size_t)20u, nullHash.size());
    CPPUNIT_ASSERT(!nullHash);
    // Build from a uint8_t. if length to short, should get a null infohash
    uint8_t to_short[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
    auto infohash = dht::InfoHash(to_short, 8);
    CPPUNIT_ASSERT_EQUAL((size_t)20u, infohash.size());
    CPPUNIT_ASSERT_EQUAL(std::string("0000000000000000000000000000000000000000"), infohash.toString());
    // Build from a uint8_t. if length is enough, data should contains the uint8_t
    uint8_t enough[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa,
                        0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa};
    infohash = dht::InfoHash(enough, 20);
    CPPUNIT_ASSERT(infohash.size() == 20);
    const auto* data = infohash.data();
    for (auto i = 0; i < 20; ++i) {
        CPPUNIT_ASSERT_EQUAL(enough[i], data[i]);
    }
    // if too long, should be cutted to 20
    uint8_t tooLong[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa,
                        0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb0};
    infohash = dht::InfoHash(tooLong, 21);
    CPPUNIT_ASSERT(infohash.size() == 20);
    const auto* data2 = infohash.data();
    for (auto i = 0; i < 20; ++i) {
        CPPUNIT_ASSERT_EQUAL(enough[i], data2[i]);
    }
    // Build from string
    auto infohashFromStr = dht::InfoHash("0102030405060708090A0102030405060708090A");
    CPPUNIT_ASSERT_EQUAL((size_t)20u, infohashFromStr.size());
    const auto* dataStr = infohashFromStr.data();
    for (auto i = 0; i < 20; ++i) {
        CPPUNIT_ASSERT_EQUAL((int)dataStr[i], (int)data[i]);
    }
}

void
InfoHashTester::testComperators() {
    auto nullHash = dht::InfoHash();
    auto minHash = dht::InfoHash("0000000000000000000000000000000000111110");
    auto maxHash = dht::InfoHash("0111110000000000000000000000000000000000");
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
InfoHashTester::testLowBit() {
    auto nullHash = dht::InfoHash();
    auto minHash = dht::InfoHash("0000000000000000000000000000000000000010");
    auto maxHash = dht::InfoHash("0100000000000000000000000000000000000000");
    CPPUNIT_ASSERT_EQUAL(nullHash.lowbit(), -1);
    CPPUNIT_ASSERT_EQUAL(minHash.lowbit(), 155);
    CPPUNIT_ASSERT_EQUAL(maxHash.lowbit(), 7);
}

void
InfoHashTester::testCommonBits() {
    auto nullHash = dht::InfoHash();
    auto minHash = dht::InfoHash("0000000000000000000000000000000000000010");
    auto maxHash = dht::InfoHash("0100000000000000000000000000000000000000");
    CPPUNIT_ASSERT_EQUAL(dht::InfoHash::commonBits(nullHash, nullHash), (unsigned)160);
    CPPUNIT_ASSERT_EQUAL(dht::InfoHash::commonBits(nullHash, minHash), (unsigned)155);
    CPPUNIT_ASSERT_EQUAL(dht::InfoHash::commonBits(nullHash, maxHash), (unsigned)7);
    CPPUNIT_ASSERT_EQUAL(dht::InfoHash::commonBits(minHash, maxHash), (unsigned)7);
}

void
InfoHashTester::testXorCmp() {
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
InfoHashTester::tearDown() {

}
}  // namespace test
