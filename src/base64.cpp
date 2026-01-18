// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "base64.h"
#include "utils.h"

#include <simdutf.h>

#include <vector>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>

namespace dht {

using namespace std::literals;

std::string
base64_encode(const std::vector<unsigned char>& str)
{
    std::string buffer(simdutf::base64_length_from_binary(str.size()), '\0');
    simdutf::binary_to_base64((const char*) str.data(), str.size(), buffer.data());
    return buffer;
}

std::vector<unsigned char>
base64_decode(std::string_view str)
{
    std::vector<unsigned char> buffer(simdutf::maximal_binary_length_from_base64(str.data(), str.size()));
    simdutf::result r = simdutf::base64_to_binary(str.data(), str.size(), (char*) buffer.data());
    if (r.error) {
        throw std::invalid_argument(concat("Invalid base64 input: "sv, simdutf::error_to_string(r.error)));
    } else {
        buffer.resize(r.count);
    }
    return buffer;
}

} // namespace dht
