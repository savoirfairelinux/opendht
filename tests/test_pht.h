// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class PhtTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(PhtTester);
    CPPUNIT_TEST(testCommonBits);
    CPPUNIT_TEST(testSibling);
    CPPUNIT_TEST_SUITE_END();

public:
    /**
     * Test how many bits two prefixes have in common
     */
    void testCommonBits();
    /**
     * Test the prefix of the sibling node in the trie
     */
    void testSibling();
};

} // namespace test
