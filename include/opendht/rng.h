/*
 *  Copyright (C) 2014-2023 Savoir-faire Linux Inc.
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
#include <thread>
#include <stdexcept>

namespace dht {
namespace crypto {

/** 
 * Generate a seeded random engine.
 */
template<class T = std::mt19937, std::size_t N = T::state_size+1>
auto getSeededRandomEngine() -> typename std::enable_if<!!N, T>::type {
    std::array<typename T::result_type, N> random_data;
    constexpr auto gen = [](std::random_device& source) -> typename T::result_type {
        for (unsigned j=0; j<64; j++) {
            try {
                return source();
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::microseconds(500));
            }
        }
        throw std::runtime_error("Can't generate random number");
    };
    for (unsigned i=0; i<8; i++) {
        try {
            std::random_device source;
            for (auto& r : random_data)
                r = gen(source);
            std::seed_seq seed(
                (std::seed_seq::result_type*)random_data.data(),
                (std::seed_seq::result_type*)(random_data.data() + random_data.size()));
            return T(seed);
        } catch (...) {
            std::this_thread::sleep_for(std::chrono::microseconds(500));
        }
    }
    throw std::runtime_error("Can't seed random seed");
}

/**
 * Generate a random engine from another source.
 */
template<class T = std::mt19937, std::size_t N = T::state_size+1>
auto getDerivedRandomEngine(T& source) -> typename std::enable_if<!!N, T>::type {
    std::array<typename T::result_type, N> random_data;
    std::generate(random_data.begin(), random_data.end(), std::ref(source));
    std::seed_seq seed(
        (std::seed_seq::result_type*)random_data.data(),
        (std::seed_seq::result_type*)(random_data.data() + random_data.size()));
    return T(seed);
}

}} // dht::crypto
