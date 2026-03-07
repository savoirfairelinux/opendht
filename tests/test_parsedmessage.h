// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class ParsedMessageTester : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(ParsedMessageTester);
    CPPUNIT_TEST(testAppendInOrder);
    CPPUNIT_TEST(testAppendOutOfOrder);
    CPPUNIT_TEST(testAppendReverseOrder);
    CPPUNIT_TEST(testAppendDuplicateFragment);
    CPPUNIT_TEST(testAppendOverlappingFragments);
    CPPUNIT_TEST(testAppendFragmentBeyondTotal);
    CPPUNIT_TEST(testAppendEmptyFragment);
    CPPUNIT_TEST(testAppendUnknownIndex);
    CPPUNIT_TEST(testAppendAlreadyComplete);
    CPPUNIT_TEST(testCompleteEmpty);
    CPPUNIT_TEST(testCompleteIncomplete);
    CPPUNIT_TEST(testCompleteSingleValue);
    CPPUNIT_TEST(testCompleteMultipleValues);
    CPPUNIT_TEST(testCompleteReassemblyOrder);
    CPPUNIT_TEST(testAppendMultipleValuesOutOfOrder);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();
    void tearDown();

    void testAppendInOrder();
    void testAppendOutOfOrder();
    void testAppendReverseOrder();
    void testAppendDuplicateFragment();
    void testAppendOverlappingFragments();
    void testAppendFragmentBeyondTotal();
    void testAppendEmptyFragment();
    void testAppendUnknownIndex();
    void testAppendAlreadyComplete();
    void testCompleteEmpty();
    void testCompleteIncomplete();
    void testCompleteSingleValue();
    void testCompleteMultipleValues();
    void testCompleteReassemblyOrder();
    void testAppendMultipleValuesOutOfOrder();
};

} // namespace test
