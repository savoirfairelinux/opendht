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
    CPPUNIT_TEST(testAppendOverflowingOffset);
    CPPUNIT_TEST(testParseRejectsNonMapPacket);
    CPPUNIT_TEST(testParseRejectsInvalidValueDataPayload);
    CPPUNIT_TEST(testParseRejectsInvalidValuesField);
    CPPUNIT_TEST(testParseIgnoresIncompleteValueDataEntry);
    CPPUNIT_TEST(testCompleteEmpty);
    CPPUNIT_TEST(testCompleteIncomplete);
    CPPUNIT_TEST(testCompleteZeroSizedValue);
    CPPUNIT_TEST(testCompleteSingleValue);
    CPPUNIT_TEST(testCompleteMultipleValues);
    CPPUNIT_TEST(testCompleteReassemblyOrder);
    CPPUNIT_TEST(testAppendMultipleValuesOutOfOrder);
    CPPUNIT_TEST(testReceiveLargeFragmentedValue);
    CPPUNIT_TEST(testReceiveLargeFragmentedValueOutOfOrder);
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
    void testAppendOverflowingOffset();
    void testParseRejectsNonMapPacket();
    void testParseRejectsInvalidValueDataPayload();
    void testParseRejectsInvalidValuesField();
    void testParseIgnoresIncompleteValueDataEntry();
    void testCompleteEmpty();
    void testCompleteIncomplete();
    void testCompleteZeroSizedValue();
    void testCompleteSingleValue();
    void testCompleteMultipleValues();
    void testCompleteReassemblyOrder();
    void testAppendMultipleValuesOutOfOrder();
    void testReceiveLargeFragmentedValue();
    void testReceiveLargeFragmentedValueOutOfOrder();
};

} // namespace test
