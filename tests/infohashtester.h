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

#pragma once

// cppunit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

namespace test {

class InfoHashTester : public CppUnit::TestFixture {
    CPPUNIT_TEST_SUITE(InfoHashTester);
    CPPUNIT_TEST(testConstructors);
    CPPUNIT_TEST(testComperators);
    CPPUNIT_TEST(testLowBit);
    CPPUNIT_TEST(testCommonBits);
    CPPUNIT_TEST(testXorCmp);
    CPPUNIT_TEST_SUITE_END();

 public:
    /**
     * Method automatically called before each test by CppUnit
     */
    void setUp();
    /**
     * Method automatically called after each test CppUnit
     */
    void tearDown();
    /**
     * Test the differents behaviors of constructors
     */
    void testConstructors();
    /**
     * Test compare operators
     */
    void testComperators();
    /**
     * Test lowbit method
     */
    void testLowBit();
    /**
     * Test commonBits method
     */
    void testCommonBits();
    /**
     * Test xorCmp operators
     */
    void testXorCmp();

};

}  // namespace test
