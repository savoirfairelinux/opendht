/*
 *  Copyright (C) 2014-2016 Savoir-faire Linux Inc.
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

#pragma once

#define WANT4 1
#define WANT6 2

#include <msgpack.hpp>

#ifndef _WIN32
#include <sys/socket.h>
#else
#include <ws2def.h>
#include <ws2tcpip.h>
#endif

#include <chrono>
#include <random>
#include <functional>
#include <map>

#include <cstdarg>

namespace dht {

using Address = std::pair<sockaddr_storage, socklen_t>;
using NetId = uint32_t;
using want_t = int_fast8_t;

std::string print_addr(const sockaddr* sa, socklen_t slen);
std::string print_addr(const sockaddr_storage& ss, socklen_t sslen);
std::string printAddr(const Address& addr);

template <typename Key, typename Item, typename Condition>
void erase_if(std::map<Key, Item>& map, const Condition& condition)
{
    for (auto it = map.begin(); it != map.end(); ) {
        if (condition(*it)) {
            it = map.erase(it);
        } else { ++it; }
    }
}

class DhtException : public std::runtime_error {
    public:
        DhtException(const std::string &str = "") :
            std::runtime_error("DhtException occurred: " + str) {}
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

static /*constexpr*/ const time_point TIME_INVALID = {time_point::min()};
static /*constexpr*/ const time_point TIME_MAX {time_point::max()};

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

// Logging related utility functions

/**
 * Dummy function used to disable logging
 */
inline void NOLOG(char const*, va_list) {}

/**
 * Wrapper for logging methods
 */
struct LogMethod {
    LogMethod() = default;

    template<typename T>
    LogMethod(T&& t) : func(std::forward<T>(t)) {}

    void operator()(char const* format, ...) const {
        va_list args;
        va_start(args, format);
        func(format, args);
        va_end(args);
    }

    void logPrintable(const uint8_t *buf, size_t buflen) const {
        std::string buf_clean(buflen, '\0');
        for (size_t i=0; i<buflen; i++)
            buf_clean[i] = isprint(buf[i]) ? buf[i] : '.';
        (*this)("%s", buf_clean.c_str());
    }
private:
    std::function<void(char const*, va_list)> func;
};

struct Logger {
    LogMethod DEBUG = NOLOG;
    LogMethod WARN = NOLOG;
    LogMethod ERR = NOLOG;
};

// Serialization related definitions and utility functions

using Blob = std::vector<uint8_t>;

/**
 * Provides backward compatibility with msgpack 1.0
 */
Blob unpackBlob(msgpack::object& o);

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

} // namespace dht
