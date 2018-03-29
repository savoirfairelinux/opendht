/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
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

#include "def.h"

#include <msgpack.hpp>

#include <chrono>
#include <random>
#include <functional>
#include <map>

#include <cstdarg>

#define WANT4 1
#define WANT6 2

/**
 * OpenDHT C++ namespace
 */
namespace dht {

using NetId = uint32_t;
using want_t = int_fast8_t;

// shortcut for std::shared_ptr
template<class T>
using Sp = std::shared_ptr<T>;

template <typename Key, typename Item, typename Condition>
void erase_if(std::map<Key, Item>& map, const Condition& condition)
{
    for (auto it = map.begin(); it != map.end(); ) {
        if (condition(*it)) {
            it = map.erase(it);
        } else { ++it; }
    }
}

/**
 * Split "[host]:port" or "host:port" to pair<"host", "port">.
 */
OPENDHT_PUBLIC std::pair<std::string, std::string>
splitPort(const std::string& s);

class OPENDHT_PUBLIC DhtException : public std::runtime_error {
public:
    DhtException(const std::string &str = "") :
        std::runtime_error("DhtException occurred: " + str) {}
};

class OPENDHT_PUBLIC SocketException : public DhtException {
public:
    SocketException(int err) :
        DhtException(strerror(err)) {}
};

// Time related definitions and utility functions

using clock = std::chrono::steady_clock;
using time_point = clock::time_point;
using duration = clock::duration;

time_point from_time_t(std::time_t t);
std::time_t to_time_t(time_point t);

/**
 * Converts std::chrono::duration to floating-point seconds.
 */
template <class DT>
static double
print_dt(DT d) {
    return std::chrono::duration_cast<std::chrono::duration<double>>(d).count();
}

template <typename Duration = duration>
class uniform_duration_distribution : public std::uniform_int_distribution<typename Duration::rep> {
    using Base = std::uniform_int_distribution<typename Duration::rep>;
    using param_type = typename Base::param_type;
public:
    uniform_duration_distribution(Duration min, Duration max) : Base(min.count(), max.count()) {}
    template <class Generator>
    Duration operator()(Generator && g) {
        return Duration(Base::operator()(g));
    }
    template< class Generator >
    Duration operator()( Generator && g, const param_type& params ) {
        return Duration(Base::operator()(g, params));
    }
};

// Serialization related definitions and utility functions

/**
 * Arbitrary binary data.
 */
using Blob = std::vector<uint8_t>;

/**
 * Provides backward compatibility with msgpack 1.0
 */
OPENDHT_PUBLIC Blob unpackBlob(msgpack::object& o);

template <typename Type>
Blob
packMsg(const Type& t) {
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack(t);
    return {buffer.data(), buffer.data()+buffer.size()};
}

template <typename Type>
Type
unpackMsg(Blob b) {
    msgpack::unpacked msg_res = msgpack::unpack((const char*)b.data(), b.size());
    return msg_res.get().as<Type>();
}

msgpack::unpacked unpackMsg(Blob b);

msgpack::object* findMapValue(msgpack::object& map, const std::string& key);

} // namespace dht
