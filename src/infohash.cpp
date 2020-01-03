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

#include "infohash.h"

#include <functional>
#include <sstream>
#include <cstdio>

namespace dht {

const HexMap hex_map = {};

void
NodeExport::msgpack_unpack(msgpack::object o)
{
    if (o.type != msgpack::type::MAP)
        throw msgpack::type_error();
    if (o.via.map.size < 2)
        throw msgpack::type_error();
    if (o.via.map.ptr[0].key.as<std::string>() != "id")
        throw msgpack::type_error();
    if (o.via.map.ptr[1].key.as<std::string>() != "addr")
        throw msgpack::type_error();
    const auto& addr = o.via.map.ptr[1].val;
    if (addr.type != msgpack::type::BIN)
        throw msgpack::type_error();
    if (addr.via.bin.size > sizeof(sockaddr_storage))
        throw msgpack::type_error();
    id.msgpack_unpack(o.via.map.ptr[0].val);
    sslen = addr.via.bin.size;
    std::copy_n(addr.via.bin.ptr, addr.via.bin.size, (char*)&ss);
}

std::ostream& operator<< (std::ostream& s, const NodeExport& h)
{
    msgpack::pack(s, h);
    return s;
}

}
