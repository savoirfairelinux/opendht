/*
 *  Copyright (C) 2014-2022 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include "def.h"

#include <asio.hpp>
#include <chrono>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <vector>

namespace dht {
namespace net {

using asio::ip::udp;
//using time_point = std::chrono::high_resolution_clock::time_point;

static const constexpr in_port_t DHT_DEFAULT_PORT = 4222;

}
}
