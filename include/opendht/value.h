/*
 *  Copyright (C) 2014-2016 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <sim.desaulniers@gmail.com>
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

#include "infohash.h"
#include "crypto.h"
#include "utils.h"

#include <msgpack.hpp>

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

namespace dht {

struct Value;

/**
 * A storage policy is applied once to every incoming value storage requests.
 * If the policy returns false, the value is dropped.
 *
 * @param key: the key where the storage is requested.
 * @param value: the value to be stored. The value can be edited by the storage policy.
 * @param from: id of the requesting node.
 * @param form_addr: network address of the incoming request.
 * @param from_len: network address lendth of the incoming request.
 */
using StorePolicy = std::function<bool(InfoHash key, std::shared_ptr<Value>& value, InfoHash from, const sockaddr* from_addr, socklen_t from_len)>;

/**
 * An edition policy is applied once to every incoming value storage requests,
 * if a value already exists for this key and value id.
 * If the policy returns false, the edition request is ignored.
 * The default behavior is to deny edition (see {ValueType::DEFAULT_EDIT_POLICY}).
 * Some {ValueType}s may override this behavior (e.g. SignedValue).
 *
 * @param key: the key where the value is stored.
 * @param old_val: the previously stored value.
 * @param new_val: the new value to be stored. The value can be edited by the edit policy.
 * @param from: id of the requesting node.
 * @param form_addr: network address of the incoming request.
 * @param from_len: network address lendth of the incoming request.
 */
using EditPolicy = std::function<bool(InfoHash key, const std::shared_ptr<Value>& old_val, std::shared_ptr<Value>& new_val, InfoHash from, const sockaddr* from_addr, socklen_t from_len)>;

static constexpr const size_t MAX_VALUE_SIZE {1024 * 56};

struct ValueType {
    typedef uint16_t Id;
    ValueType () {}

    ValueType (Id id, std::string name, duration e = std::chrono::minutes(10))
    : id(id), name(name), expiration(e) {}

    ValueType (Id id, std::string name, duration e, StorePolicy&& sp, EditPolicy&& ep)
     : id(id), name(name), expiration(e), storePolicy(std::move(sp)), editPolicy(std::move(ep)) {}

    virtual ~ValueType() {}

    bool operator==(const ValueType& o) {
       return id == o.id;
    }

    // Generic value type
    static const ValueType USER_DATA;

    static bool DEFAULT_STORE_POLICY(InfoHash, std::shared_ptr<Value>& v, InfoHash, const sockaddr*, socklen_t);
    static bool DEFAULT_EDIT_POLICY(InfoHash, const std::shared_ptr<Value>&, std::shared_ptr<Value>&, InfoHash, const sockaddr*, socklen_t) {
        return false;
    }

    Id id {0};
    std::string name {};
    duration expiration {60 * 10};
    StorePolicy storePolicy {DEFAULT_STORE_POLICY};
    EditPolicy editPolicy {DEFAULT_EDIT_POLICY};
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
struct Value
{
    typedef uint64_t Id;
    static const Id INVALID_ID {0};

    class Filter : public std::function<bool(const Value&)> {
        using std::function<bool(const Value&)>::function;
    public:
        static Filter chain(Filter&& f1, Filter&& f2) {
            if (not f1) return f2;
            if (not f2) return f1;
            return [f1,f2](const Value& v) {
                return f1(v) and f2(v);
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
        static Filter chainOr(Filter&& f1, Filter&& f2) {
            if (not f1 or not f2) return AllFilter();
            return [f1,f2](const Value& v) {
                return f1(v) or f2(v);
            };
        }
        Filter chain(Filter&& f2) {
            return chain(std::move(*this), std::move(f2));
        }
        Filter chainOr(Filter&& f2) {
            return chainOr(std::move(*this), std::move(f2));
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

    class SerializableBase
    {
    public:
        SerializableBase() {}
        virtual ~SerializableBase() {};
        virtual const ValueType& getType() const = 0;
        virtual void unpackValue(const Value& v) = 0;
        virtual Value packValue() const = 0;
    };

    template <typename Derived, typename Base=SerializableBase>
    class Serializable : public Base
    {
    public:
        using Base::Base;

        virtual const ValueType& getType() const {
            return Derived::TYPE;
        }

        virtual void unpackValue(const Value& v) {
            auto msg = msgpack::unpack((const char*)v.data.data(), v.data.size());
            msg.get().convert(*static_cast<Derived*>(this));
        }

        virtual Value packValue() const {
            return Value {getType(), static_cast<const Derived&>(*this)};
        }
    };

    template <typename T,
              typename std::enable_if<std::is_base_of<SerializableBase, T>::value, T>::type* = nullptr>
    static Value pack(const T& obj)
    {
        return obj.packValue();
    }

    template <typename T,
              typename std::enable_if<!std::is_base_of<SerializableBase, T>::value, T>::type* = nullptr>
    static Value pack(const T& obj)
    {
        return {ValueType::USER_DATA.id, packMsg<T>(obj)};
    }

    template <typename T,
              typename std::enable_if<std::is_base_of<SerializableBase, T>::value, T>::type* = nullptr>
    static T unpack(const Value& v)
    {
        T msg;
        msg.unpackValue(v);
        return msg;
    }

    template <typename T,
              typename std::enable_if<!std::is_base_of<SerializableBase, T>::value, T>::type* = nullptr>
    static T unpack(const Value& v)
    {
        return unpackMsg<T>(v.data);
    }

    template <typename T>
    T unpack()
    {
        return unpack<T>(*this);
    }

    bool isEncrypted() const {
        return not cypher.empty();
    }
    bool isSigned() const {
        return not signature.empty();
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

    template <typename Type>
    Value(ValueType::Id t, const Type& d, Id id = INVALID_ID)
     : id(id), type(t), data(packMsg(d)) {}

    template <typename Type>
    Value(const ValueType& t, const Type& d, Id id = INVALID_ID)
     : id(id), type(t.id), data(packMsg(d)) {}

    /** Custom user data constructor */
    Value(const Blob& userdata) : data(userdata) {}
    Value(Blob&& userdata) : data(std::move(userdata)) {}
    Value(const uint8_t* dat_ptr, size_t dat_len) : data(dat_ptr, dat_ptr+dat_len) {}

    Value(Value&& o) noexcept
     : id(o.id), owner(std::move(o.owner)), recipient(o.recipient),
     type(o.type), data(std::move(o.data)), user_type(std::move(o.user_type)), seq(o.seq), signature(std::move(o.signature)), cypher(std::move(o.cypher)) {}

    template <typename Type>
    Value(const Type& vs)
     : Value(pack<Type>(vs)) {}

    /**
     * Unpack a serialized value
     */
    Value(const msgpack::object& o) {
        msgpack_unpack(o);
    }

    inline bool operator== (const Value& o) {
        return id == o.id &&
        (isEncrypted() ? cypher == o.cypher :
        (owner == o.owner && type == o.type && data == o.data && user_type == o.user_type && signature == o.signature));
    }

    void setRecipient(const InfoHash& r) {
        recipient = r;
    }

    void setCypher(Blob&& c) {
        cypher = std::move(c);
    }

    /**
     * Pack part of the data to be signed (must always be done the same way)
     */
    Blob getToSign() const {
        msgpack::sbuffer buffer;
        msgpack::packer<msgpack::sbuffer> pk(&buffer);
        msgpack_pack_to_sign(pk);
        return {buffer.data(), buffer.data()+buffer.size()};
    }

    /**
     * Pack part of the data to be encrypted
     */
    Blob getToEncrypt() const {
        msgpack::sbuffer buffer;
        msgpack::packer<msgpack::sbuffer> pk(&buffer);
        msgpack_pack_to_encrypt(pk);
        return {buffer.data(), buffer.data()+buffer.size()};
    }

    /** print value for debugging */
    friend std::ostream& operator<< (std::ostream& s, const Value& v);

    std::string toString() const {
        std::stringstream ss;
        ss << *this;
        return ss.str();
    }

    /** Return the size in bytes used by this value in memory (minimum). */
    size_t size() const;

    template <typename Packer>
    void msgpack_pack_to_sign(Packer& pk) const
    {
        pk.pack_map((user_type.empty()?0:1) + (owner?(recipient == InfoHash() ? 4 : 5):2));
        if (owner) { // isSigned
            pk.pack(std::string("seq"));   pk.pack(seq);
            pk.pack(std::string("owner")); owner.msgpack_pack(pk);
            if (recipient != InfoHash()) {
                pk.pack(std::string("to")); pk.pack(recipient);
            }
        }
        pk.pack(std::string("type"));  pk.pack(type);
        pk.pack(std::string("data"));  pk.pack_bin(data.size());
                                       pk.pack_bin_body((const char*)data.data(), data.size());
        if (not user_type.empty()) {
            pk.pack(std::string("utype")); pk.pack(user_type);
        }
    }

    template <typename Packer>
    void msgpack_pack_to_encrypt(Packer& pk) const
    {
        if (isEncrypted()) {
            pk.pack_bin(cypher.size());
            pk.pack_bin_body((const char*)cypher.data(), cypher.size());
        } else {
            pk.pack_map(isSigned() ? 2 : 1);
            pk.pack(std::string("body")); msgpack_pack_to_sign(pk);
            if (isSigned()) {
                pk.pack(std::string("sig")); pk.pack_bin(signature.size());
                                             pk.pack_bin_body((const char*)signature.data(), signature.size());
            }
        }
    }

    template <typename Packer>
    void msgpack_pack(Packer& pk) const
    {
        pk.pack_map(2);
        pk.pack(std::string("id"));  pk.pack(id);
        pk.pack(std::string("dat")); msgpack_pack_to_encrypt(pk);
    }

    void msgpack_unpack(msgpack::object o);
    void msgpack_unpack_body(const msgpack::object& o);

    Id id {INVALID_ID};

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
     * Custom user-defined type
     */
    std::string user_type {};

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

template <typename T,
          typename std::enable_if<std::is_base_of<Value::SerializableBase, T>::value, T>::type* = nullptr>
Value::Filter
getFilterSet(Value::Filter f)
{
    return Value::Filter::chain({
        Value::TypeFilter(T::TYPE),
        T::getFilter(),
        f
    });
}

template <typename T,
          typename std::enable_if<!std::is_base_of<Value::SerializableBase, T>::value, T>::type* = nullptr>
Value::Filter
getFilterSet(Value::Filter f)
{
    return f;
}

template <typename T,
          typename std::enable_if<std::is_base_of<Value::SerializableBase, T>::value, T>::type* = nullptr>
Value::Filter
getFilterSet()
{
    return Value::Filter::chain({
        Value::TypeFilter(T::TYPE),
        T::getFilter()
    });
}

template <typename T,
          typename std::enable_if<!std::is_base_of<Value::SerializableBase, T>::value, T>::type* = nullptr>
Value::Filter
getFilterSet()
{
    return Value::AllFilter();
}

template <class T>
std::vector<T>
unpackVector(const std::vector<std::shared_ptr<Value>>& vals) {
    std::vector<T> ret;
    ret.reserve(vals.size());
    for (const auto& v : vals) {
        try {
            ret.emplace_back(Value::unpack<T>(*v));
        } catch (const std::exception&) {}
    }
    return ret;
}

}
