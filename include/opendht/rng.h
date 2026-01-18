// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
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
template<class T = std::mt19937, std::size_t N = T::state_size + 1>
auto
getSeededRandomEngine() -> typename std::enable_if<!!N, T>::type
{
    std::array<typename T::result_type, N> random_data;
    constexpr auto gen = [](std::random_device& source) -> typename T::result_type {
        for (unsigned j = 0; j < 64; j++) {
            try {
                return source();
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::microseconds(500));
            }
        }
        throw std::runtime_error("Can't generate random number");
    };
    for (unsigned i = 0; i < 8; i++) {
        try {
            std::random_device source;
            for (auto& r : random_data)
                r = gen(source);
            std::seed_seq seed((std::seed_seq::result_type*) random_data.data(),
                               (std::seed_seq::result_type*) (random_data.data() + random_data.size()));
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
template<class T = std::mt19937, std::size_t N = T::state_size + 1>
auto
getDerivedRandomEngine(T& source) -> typename std::enable_if<!!N, T>::type
{
    std::array<typename T::result_type, N> random_data;
    std::generate(random_data.begin(), random_data.end(), std::ref(source));
    std::seed_seq seed((std::seed_seq::result_type*) random_data.data(),
                       (std::seed_seq::result_type*) (random_data.data() + random_data.size()));
    return T(seed);
}

} // namespace crypto
} // namespace dht
