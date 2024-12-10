/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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

#include <string>
#include <vector>

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
std::vector<unsigned char> base64_decode(const std::string& str);
