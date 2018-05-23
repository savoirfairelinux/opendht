/*
 *  Copyright (C) 2017-2018 Savoir-faire Linux Inc.
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
#pragma once

#include <chrono>

namespace dht {
namespace proxy {

constexpr const std::chrono::seconds OP_TIMEOUT {10 * 60}; // onw hour
constexpr const std::chrono::seconds OP_MARGIN {5 * 60}; // 5 minutes
constexpr const char* const HTTP_PROTO {"http://"};
using ListenToken = uint64_t;

}
}
