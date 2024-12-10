/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *
 *  Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include "valuetester.h"

#include <iostream>
#include <string>

// opendht
#include "opendht/value.h"

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(ValueTester);

void
ValueTester::setUp() {

}

void
ValueTester::testConstructors() {
    std::string the_data {"42 cats"};
    dht::Value the_dht_value {(const uint8_t*)the_data.data(), the_data.size()};
    std::string from_value {the_dht_value.data.begin(), the_dht_value.data.end()};
    CPPUNIT_ASSERT_EQUAL(the_data, from_value);
}

void
ValueTester::testFilter()
{
    dht::Value::Filter defaultFiler {};

    auto isPairSize = dht::Value::Filter([](const dht::Value& v) {
        return v.data.size() % 2 == 0;
    });

    auto isUserTypeTest = dht::Value::Filter([](const dht::Value& v) {
        return v.user_type == "test";
    });

    std::string data1 {"42 cats"};
    dht::Value value1 {(const uint8_t*)data1.data(), data1.size()};
    value1.user_type = "test";

    std::string data2 {"420 cats"};
    dht::Value value2 {(const uint8_t*)data2.data(), data2.size()};
    dht::Value value3 {(const uint8_t*)data2.data(), data2.size()};
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
ValueTester::tearDown() {

}
}  // namespace test
