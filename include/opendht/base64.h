/*
 *  Copyright (C) 2004-2017 Savoir-faire Linux Inc.
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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.
 */

#if OPENDHT_PROXY_SERVER
#pragma once

#include <string>
#include <vector>

/**
 * Encode a string into base64
 * @param begin
 * @param end
 * @return the encoded vector in a string
 */
std::string base64_encode(const std::vector<unsigned char>& str);
/**
 * Decode a base64 encoded string
 * @param str to decode
 * @return the decoded string
 */
std::string base64_decode(std::string const& str);

#endif // OPENDHT_PROXY_SERVER
