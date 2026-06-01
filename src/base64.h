// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include <string>
#include <vector>

namespace dht {

/**
 * Encode a buffer in base64.
 *
 * @param str the input buffer
 * @return a base64-encoded buffer
 */
std::string base64_encode(const std::vector<unsigned char>& str);
/**
 * Decode a buffer in base64.
 *
 * @param str the input buffer
 * @return a base64-decoded buffer
 */
std::vector<unsigned char> base64_decode(std::string_view str);
/**
 * Decode a buffer in base64 or url style base64 (including '-' '_' ).
 *
 * @param str the input buffer
 * @return a base64-decoded buffer
 */
std::vector<unsigned char> base64_default_or_url_decode(std::string_view str);

} // namespace dht
