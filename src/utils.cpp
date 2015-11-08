/*
 *  Copyright (C) 2014-2015 Savoir-faire Linux Inc.
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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.
 */

#include "utils.h"

namespace dht {

time_point from_time_t(std::time_t t) {
    return clock::now() + (std::chrono::system_clock::from_time_t(t) - std::chrono::system_clock::now());
}

std::time_t to_time_t(time_point t) {
    return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + 
            (t - clock::now()));
}

Blob
unpackBlob(msgpack::object& o) {
    switch (o.type) {
    case msgpack::type::BIN:
        return {o.via.bin.ptr, o.via.bin.ptr+o.via.bin.size};
    case msgpack::type::STR:
        return {o.via.str.ptr, o.via.str.ptr+o.via.str.size};
    case msgpack::type::ARRAY: {
        Blob ret(o.via.array.size);
        std::transform(o.via.array.ptr, o.via.array.ptr+o.via.array.size, ret.begin(), [](const msgpack::object& b) {
            return b.as<uint8_t>();
        });
        return ret;
    }
    default:
        throw msgpack::type_error();
    }
}

msgpack::unpacked
unpackMsg(Blob b) {
    return msgpack::unpack((const char*)b.data(), b.size());
}

}
