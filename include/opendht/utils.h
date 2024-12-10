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

OPENDHT_PUBLIC const char* version();

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
using system_clock = std::chrono::system_clock;
using time_point = clock::time_point;
using duration = clock::duration;

time_point from_time_t(std::time_t t);
std::time_t to_time_t(time_point t);

inline std::string
to_str(double d) {
    char buf[16];
    auto ret = snprintf(buf, sizeof(buf), "%.3g", d);
    return (ret < 0) ? std::to_string(d) : std::string(buf, ret);
}

/**
 * Converts std::chrono::duration to floating-point seconds.
 */
template <class DT>
static double
print_dt(DT d) {
    return std::chrono::duration_cast<std::chrono::duration<double>>(d).count();
}

template <class DT>
static std::string
print_duration(DT d) {
    if (d < std::chrono::seconds(0)) {
        return "-" + print_duration(-d);
    } else if (d < std::chrono::milliseconds(1)) {
        return to_str(std::chrono::duration_cast<std::chrono::duration<double, std::micro>>(d).count()) +  " us";
    } else if (d < std::chrono::seconds(1)) {
        return to_str(std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(d).count()) +  " ms";
    } else if (d < std::chrono::minutes(1)) {
        return to_str(std::chrono::duration_cast<std::chrono::duration<double>>(d).count()) +  " s";
    } else if (d < std::chrono::hours(1)) {
        return to_str(std::chrono::duration_cast<std::chrono::duration<double, std::ratio<60>>>(d).count()) +  " min";
    } else {
        return to_str(std::chrono::duration_cast<std::chrono::duration<double, std::ratio<3600>>>(d).count()) +  " h";
    }
}

template <class TimePoint>
static std::string
print_time_relative(TimePoint now, TimePoint d) {
    if (d == TimePoint::min()) return "never";
    if (d == now)              return "now";
    return (d > now) ? std::string("in ") + print_duration(d - now)
                     : print_duration(now - d) + std::string(" ago");
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
OPENDHT_PUBLIC Blob unpackBlob(const msgpack::object& o);

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

msgpack::object* findMapValue(const msgpack::object& map, const char* key, size_t length);

inline msgpack::object* findMapValue(const msgpack::object& map, const char* key) {
    return findMapValue(map, key, strlen(key));
}
inline msgpack::object* findMapValue(const msgpack::object& map, const std::string& key) {
    return findMapValue(map, key.c_str(), key.size());
}

} // namespace dht
