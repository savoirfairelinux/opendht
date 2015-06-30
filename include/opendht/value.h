/*
 *  Copyright (C) 2014 Savoir-Faire Linux Inc.
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
 *
 *  Additional permission under GNU GPL version 3 section 7:
 *
 *  If you modify this program, or any covered work, by linking or
 *  combining it with the OpenSSL project's OpenSSL library (or a
 *  modified version of that library), containing parts covered by the
 *  terms of the OpenSSL or SSLeay licenses, Savoir-Faire Linux Inc.
 *  grants you additional permission to convey the resulting work.
 *  Corresponding Source for a non-source form of such a combination
 *  shall include the source code for the parts of OpenSSL used as well
 *  as that of the covered work.
 */

#pragma once

#include "infohash.h"
#include "crypto.h"
#include "serialize.h"

#ifndef _WIN32
#include <netinet/in.h>
#include <netdb.h>
#ifdef __ANDROID__
typedef uint16_t in_port_t;
#endif
#else
#include <ws2tcpip.h>
typedef uint16_t sa_family_t;
typedef uint16_t in_port_t;
#endif

#include <string>
#include <sstream>
#include <bitset>
#include <vector>
#include <iostream>
#include <algorithm>
#include <functional>
#include <memory>
#include <chrono>

#include <cstdarg>

namespace dht {

using clock = std::chrono::steady_clock;
using time_point = clock::time_point;
using duration = clock::duration;

static /*constexpr*/const time_point TIME_INVALID = {};
static /*constexpr*/const time_point TIME_MAX {time_point::max()};

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

/**
 * Wrapper for logging methods
 */
struct LogMethod {
    LogMethod() = default;

    template<typename T>
    LogMethod( T&& t) : func(std::forward<T>(t)) {}

    void operator()(char const* format, ...) const {
        va_list args;
        va_start(args, format);
        func(format, args);
        va_end(args);
    }

    void logPrintable(const uint8_t *buf, size_t buflen) const {
        std::string buf_clean(buflen, '\0');
        for (size_t i=0; i<buflen; i++)
            buf_clean[i] = buf[i] >= 32 && buf[i] <= 126 ? buf[i] : '.';
        (*this)("%s", buf_clean.c_str());
    }
private:
    std::function<void(char const*, va_list)> func;
};

/**
 * Dummy function used to disable logging
 */
inline void NOLOG(char const*, va_list) {}


struct Value;

typedef std::function<bool(InfoHash, std::shared_ptr<Value>&, InfoHash, const sockaddr*, socklen_t)> StorePolicy;
typedef std::function<bool(InfoHash, const std::shared_ptr<Value>&, std::shared_ptr<Value>&, InfoHash, const sockaddr*, socklen_t)> EditPolicy;

struct ValueType {
    typedef uint16_t Id;
    ValueType () {}

    ValueType (Id id, std::string name, duration e = std::chrono::hours(1))
    : id(id), name(name), expiration(e) {}

    ValueType (Id id, std::string name, duration e, StorePolicy&& sp, EditPolicy&& ep)
     : id(id), name(name), expiration(e), storePolicy(std::move(sp)), editPolicy(std::move(ep)) {}

    virtual ~ValueType() {}

    bool operator==(const ValueType& o) {
       return id == o.id;
    }

    // Generic value type
    static const ValueType USER_DATA;

    static bool DEFAULT_STORE_POLICY(InfoHash, std::shared_ptr<Value>&, InfoHash, const sockaddr*, socklen_t) {
        return true;
    }
    static bool DEFAULT_EDIT_POLICY(InfoHash, const std::shared_ptr<Value>&, std::shared_ptr<Value>&, InfoHash, const sockaddr*, socklen_t) {
        return false;
    }

    Id id {0};
    std::string name {};
    duration expiration {60 * 60};
    StorePolicy storePolicy {DEFAULT_STORE_POLICY};
    EditPolicy editPolicy {DEFAULT_EDIT_POLICY};
};

struct ValueSerializable : public Serializable
{
    virtual const ValueType& getType() const = 0;
    virtual void unpackValue(const Value& v);
    virtual Value packValue() const;
};

/**
 * A "value" is data potentially stored on the Dht, with some metadata.
 *
 * It can be an IP:port announced for a service, a public key, or any kind of
 * light user-defined data (recommended: less than 512 bytes).
 *
 * Values are stored at a given InfoHash in the Dht, but also have a
 * unique ID to distinguish between values stored at the same location.
 */
struct Value : public Serializable
{
    typedef uint64_t Id;
    static const Id INVALID_ID {0};

    class Filter : public std::function<bool(const Value&)> {
        using std::function<bool(const Value&)>::function;
    public:
        static Filter chain(Filter&& f1, Filter&& f2) {
            return [f1,f2](const Value& v){
                return f1(v) && f2(v);
            };
        }
        static Filter chain(std::initializer_list<Filter> l) {
            const std::vector<Filter> list(l.begin(), l.end());
            return [list](const Value& v){
                for (const auto& f : list)
                    if (f and not f(v))
                        return false;
                return true;
            };
        }
        Filter chain(Filter&& f2) {
            Filter f1 = std::move(*this);
            return [f1,f2](const Value& v){
                return f1(v) && f2(v);
            };
        }
    };

    static const Filter AllFilter() {
        return [](const Value&){return true;};
    }

    static Filter TypeFilter(const ValueType& t) {
        const auto tid = t.id;
        return [tid](const Value& v) {
            return v.type == tid;
        };
    }

    static Filter IdFilter(const Id id) {
        return [id](const Value& v) {
            return v.id == id;
        };
    }

    static Filter recipientFilter(const InfoHash& r) {
        return [r](const Value& v) {
            return v.recipient == r;
        };
    }

    /**
     * Hold information about how the data is signed/encrypted.
     * Class is final because bitset have no virtual destructor.
     */
    class ValueFlags final : public std::bitset<3> {
    public:
        using std::bitset<3>::bitset;
        ValueFlags() {}
        ValueFlags(bool sign, bool encrypted, bool have_recipient = false) : bitset<3>((sign ? 1:0) | (encrypted ? 2:0) | (have_recipient ? 4:0)) {}
        bool isSigned() const {
            return (*this)[0];
        }
        bool isEncrypted() const {
            return (*this)[1];
        }
        bool haveRecipient() const {
            return (*this)[2];
        }
    };

    bool isEncrypted() const {
        return flags.isEncrypted();
    }
    bool isSigned() const {
        return flags.isSigned();
    }

    Value() {}

    Value (Id id) : id(id) {}

    /** Generic constructor */
    Value(ValueType::Id t, const Blob& data, Id id = INVALID_ID)
     : id(id), type(t), data(data) {}
    Value(ValueType::Id t, Blob&& data, Id id = INVALID_ID)
     : id(id), type(t), data(std::move(data)) {}
    Value(ValueType::Id t, const uint8_t* dat_ptr, size_t dat_len, Id id = INVALID_ID)
     : id(id), type(t), data(dat_ptr, dat_ptr+dat_len) {}
    Value(ValueType::Id t, const Serializable& d, Id id = INVALID_ID)
     : id(id), type(t), data(d.getPacked()) {}
    Value(const ValueType& t, const Serializable& d, Id id = INVALID_ID)
     : id(id), type(t.id), data(d.getPacked()) {}
    Value(const ValueSerializable& d, Id id = INVALID_ID)
     : id(id), type(d.getType().id), data(d.getPacked()) {}

    /** Custom user data constructor */
    Value(const Blob& userdata) : data(userdata) {}
    Value(Blob&& userdata) : data(std::move(userdata)) {}
    Value(const uint8_t* dat_ptr, size_t dat_len) : data(dat_ptr, dat_ptr+dat_len) {}

    Value(Value&& o) noexcept
     : id(o.id), flags(o.flags), owner(std::move(o.owner)), recipient(o.recipient),
     type(o.type), data(std::move(o.data)), seq(o.seq), signature(std::move(o.signature)), cypher(std::move(o.cypher)) {}

    inline bool operator== (const Value& o) {
        return id == o.id &&
        (flags.isEncrypted() ? cypher == o.cypher :
        (owner == o.owner && type == o.type && data == o.data && signature == o.signature));
    }

    void setRecipient(const InfoHash& r) {
        recipient = r;
        flags[2] = true;
    }

    void setCypher(Blob&& c) {
        cypher = std::move(c);
        flags = {true, true, true};
    }

    /**
     * Pack part of the data to be signed
     */
    void packToSign(Blob& res) const;
    Blob getToSign() const;

    /**
     * Pack part of the data to be encrypted
     */
    void packToEncrypt(Blob& res) const;
    Blob getToEncrypt() const;

    void pack(Blob& res) const;

    void unpackBody(Blob::const_iterator& begin, Blob::const_iterator& end);
    virtual void unpack(Blob::const_iterator& begin, Blob::const_iterator& end);

    /** print value for debugging */
    friend std::ostream& operator<< (std::ostream& s, const Value& v);

    std::string toString() const {
        std::stringstream ss;
        ss << *this;
        return ss.str();
    }

    Id id {INVALID_ID};

    // data (part that is signed / encrypted)

    ValueFlags flags {};

    /**
     * Public key of the signer.
     */
    crypto::PublicKey owner {};

    /**
     * Hash of the recipient (optional).
     * Should only be present for encrypted values.
     * Can optionally be present for signed values.
     */
    InfoHash recipient {};

    /**
     * Type of data.
     */
    ValueType::Id type {ValueType::USER_DATA.id};
    Blob data {};

    /**
     * Sequence number to avoid replay attacks
     */
    uint16_t seq {0};

    /**
     * Optional signature.
     */
    Blob signature {};

    /**
     * Hold encrypted version of the data.
     */
    Blob cypher {};
};

template <class T>
std::vector<T>
unpackVector(const std::vector<std::shared_ptr<Value>>& vals) {
    std::vector<T> ret;
    ret.reserve(vals.size());
    for (const auto& v : vals) {
        try {
            T msg;
            msg.unpackValue(*v);
            ret.emplace_back(std::move(msg));
        } catch (const std::exception&) {}
    }
    return ret;
}

}
