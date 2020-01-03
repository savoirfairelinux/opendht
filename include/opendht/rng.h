/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include <random>
#include <algorithm>
#include <functional>

namespace dht {
namespace crypto {

#ifndef _MSC_VER
#ifdef _WIN32

/**
 * Hardware random number generator using Intel RDRAND/RDSEED,
 * API-compatible with std::random_device.
 */
class random_device {
public:
    using result_type = std::random_device::result_type;
    using pseudo_engine = std::mt19937_64;

    /**
     * Current implementation assumption : result_type must be of a size
     * supported by Intel RDRAND/RDSEED.
     * result_type is unsigned int so this is currently safe.
     */
    static_assert(
        sizeof(result_type) == 2 ||
        sizeof(result_type) == 4 ||
        sizeof(result_type) == 8,
        "result_type must be 16, 32 or 64 bits");

    random_device();

    result_type operator()();

    static constexpr result_type min() {
        return std::numeric_limits<result_type>::lowest();
    }

    static constexpr result_type max() {
        return std::numeric_limits<result_type>::max();
    }

    double entropy() const {
        if (hasRdrand() or hasRdseed())
            return 1.;
        return 0.;
    }

    static bool hasRdrand() {
        static const bool hasrdrand = _hasRdrand();
        return hasrdrand;
    }

    static bool hasRdseed() {
        static const bool hasrdseed = _hasRdseed();
        return hasrdseed;
    }

private:
    random_device& operator=(random_device&) = delete;

    pseudo_engine gen;
    std::uniform_int_distribution<result_type> dis {};

    static bool hasIntelCpu();
    static bool _hasRdrand();
    static bool _hasRdseed();

    struct CPUIDinfo {
        unsigned int EAX;
        unsigned int EBX;
        unsigned int ECX;
        unsigned int EDX;
        CPUIDinfo(const unsigned int func, const unsigned int subfunc);
    };
    bool rdrandStep(result_type* r);
    bool rdrand(result_type* r);
    bool rdseedStep(result_type* r);
    bool rdseed(result_type* r);
};

#else

using random_device = std::random_device;

#endif
#else
using random_device = std::random_device;
#endif

template<class T = std::mt19937, std::size_t N = T::state_size>
auto getSeededRandomEngine () -> typename std::enable_if<!!N, T>::type {
    typename T::result_type random_data[N];
    random_device source;
    std::generate(std::begin(random_data), std::end(random_data), std::ref(source));
    std::seed_seq seeds(std::begin(random_data), std::end(random_data));
    T seededEngine (seeds);
    return seededEngine;
}

}} // dht::crypto
