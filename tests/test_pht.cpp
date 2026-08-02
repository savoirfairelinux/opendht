// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_pht.h"

// opendht
#include "opendht/indexation/pht.h"

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(PhtTester);

using dht::indexation::Prefix;

void
PhtTester::testCommonBits()
{
    // Prefix::size_ counts bits, so two prefixes that agree everywhere have
    // as many bits in common as they are long, and no more.
    const Prefix same {dht::Blob(20, 0xAB)};
    CPPUNIT_ASSERT_EQUAL((unsigned) 160, Prefix::commonBits(same, Prefix {dht::Blob(20, 0xAB)}));

    // A difference in the very last bit leaves every other bit in common.
    dht::Blob other(20, 0xAB);
    other[19] = 0xAA;
    CPPUNIT_ASSERT_EQUAL((unsigned) 159, Prefix::commonBits(same, Prefix {other}));

    // A difference in the very first bit leaves nothing in common.
    dht::Blob first(20, 0xAB);
    first[0] = 0x2B;
    CPPUNIT_ASSERT_EQUAL((unsigned) 0, Prefix::commonBits(same, Prefix {first}));

    // Bits beyond the shorter prefix are not compared, whatever the content
    // they are cut from holds.
    const Prefix shorter = same.getPrefix(3);
    CPPUNIT_ASSERT_EQUAL((size_t) 3, shorter.size_);
    CPPUNIT_ASSERT_EQUAL((unsigned) 3, Prefix::commonBits(shorter, same));
    CPPUNIT_ASSERT_EQUAL((unsigned) 3, Prefix::commonBits(same, shorter));
}

void
PhtTester::testSibling()
{
    // The sibling of a node in the trie is the prefix that differs from it in
    // its last bit, and in that bit only.
    for (size_t length : {1, 7, 8, 9, 15, 16, 159}) {
        const Prefix prefix = Prefix {dht::Blob(20, 0xAB)}.getPrefix(length);
        const Prefix sibling = prefix.getSibling();

        CPPUNIT_ASSERT_EQUAL(prefix.size_, sibling.size_);
        CPPUNIT_ASSERT_EQUAL((unsigned) (length - 1), Prefix::commonBits(prefix, sibling));
        CPPUNIT_ASSERT(prefix.isContentBitActive(length - 1) != sibling.isContentBitActive(length - 1));

        // Being siblings is symmetric.
        CPPUNIT_ASSERT(sibling.getSibling().content_ == prefix.content_);
    }
}

} // namespace test
