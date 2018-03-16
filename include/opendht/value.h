/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
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

#include "infohash.h"
#include "crypto.h"
#include "utils.h"
#include "sockaddr.h"

#include <msgpack.hpp>

#include <string>
#include <sstream>
#include <bitset>
#include <vector>
#include <iostream>
#include <algorithm>
#include <functional>
#include <memory>
#include <chrono>
#include <set>

#if OPENDHT_PROXY_SERVER || OPENDHT_PROXY_CLIENT
#include <json/json.h>
#endif //OPENDHT_PROXY_SERVER

namespace dht {

struct Value;
struct Query;

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
using StorePolicy = std::function<bool(InfoHash key, std::shared_ptr<Value>& value, const InfoHash& from, const SockAddr& addr)>;

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
using EditPolicy = std::function<bool(InfoHash key, const std::shared_ptr<Value>& old_val, std::shared_ptr<Value>& new_val, const InfoHash& from, const SockAddr& addr)>;

static constexpr const size_t MAX_VALUE_SIZE {1024 * 64};

struct OPENDHT_PUBLIC ValueType {
    typedef uint16_t Id;

    static bool DEFAULT_STORE_POLICY(InfoHash, std::shared_ptr<Value>& v, const InfoHash&, const SockAddr&);
    static bool DEFAULT_EDIT_POLICY(InfoHash, const std::shared_ptr<Value>&, std::shared_ptr<Value>&, const InfoHash&, const SockAddr&) {
        return false;
    }

    ValueType () {}

    ValueType (Id id, std::string name, duration e = std::chrono::minutes(10))
    : id(id), name(name), expiration(e) {}

    ValueType (Id id, std::string name, duration e, StorePolicy sp, EditPolicy ep = DEFAULT_EDIT_POLICY)
     : id(id), name(name), expiration(e), storePolicy(sp), editPolicy(ep) {}

    virtual ~ValueType() {}

    bool operator==(const ValueType& o) {
       return id == o.id;
    }

    // Generic value type
    static const ValueType USER_DATA;


    Id id {0};
    std::string name {};
    duration expiration {60 * 10};
    StorePolicy storePolicy {DEFAULT_STORE_POLICY};
    EditPolicy editPolicy {DEFAULT_EDIT_POLICY};
};

class TypeStore {
public:
    void registerType(const ValueType& type) {
        types[type.id] = type;
    }
    const ValueType& getType(ValueType::Id type_id) const {
        const auto& t_it = types.find(type_id);
        return (t_it == types.end()) ? ValueType::USER_DATA : t_it->second;
    }
private:
    std::map<ValueType::Id, ValueType> types {};
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
struct OPENDHT_PUBLIC Value
{
    enum class Field : int {
        None = 0,
        Id,        /* Value::id */
        ValueType, /* Value::type */
        OwnerPk,   /* Value::owner */
        SeqNum,    /* Value::seq */
        UserType,  /* Value::user_type */

        COUNT      /* the total number of fields */
    };

    typedef uint64_t Id;
    static const constexpr Id INVALID_ID {0};

    class Filter : public std::function<bool(const Value&)> {
    public:
        Filter() {}

        template<typename Functor>
        Filter(Functor f) : std::function<bool(const Value&)>::function(f) {}

        Filter chain(Filter&& f2) {
            auto f1 = *this;
            return chain(std::move(f1), std::move(f2));
        }
        Filter chainOr(Filter&& f2) {
            auto f1 = *this;
            return chainOr(std::move(f1), std::move(f2));
        }
        static Filter chain(Filter&& f1, Filter&& f2) {
            if (not f1) return f2;
            if (not f2) return f1;
            return [f1,f2](const Value& v) {
                return f1(v) and f2(v);
            };
        }
        static Filter chainAll(std::vector<Filter>&& set) {
            if (set.empty()) return {};
            return std::bind([](const Value& v, std::vector<Filter>& s) {
                for (const auto& f : s)
                    if (f and not f(v))
                        return false;
                return true;
            }, std::placeholders::_1, std::move(set));
        }
        static Filter chain(std::initializer_list<Filter> l) {
            return chainAll(std::vector<Filter>(l.begin(), l.end()));
        }
        static Filter chainOr(Filter&& f1, Filter&& f2) {
            if (not f1 or not f2) return AllFilter();
            return [f1,f2](const Value& v) {
                return f1(v) or f2(v);
            };
        }
        std::vector<Sp<Value>> filter(const std::vector<Sp<Value>>& values) {
            if (not (*this))
                return values;
            std::vector<Sp<Value>> ret;
            for (const auto& v : values)
                if ((*this)(v))
                    ret.emplace_back(v);
            return ret;
        }
    };

    /* Sneaky functions disguised in classes */

    static const Filter AllFilter() {
        return {};
    }

    static Filter TypeFilter(const ValueType& t) {
        const auto tid = t.id;
        return [tid](const Value& v) {
            return v.type == tid;
        };
    }
    static Filter TypeFilter(const ValueType::Id& tid) {
        return [tid](const Value& v) {
            return v.type == tid;
        };
    }

    static Filter IdFilter(const Id id) {
        return [id](const Value& v) {
            return v.id == id;
        };
    }

    static Filter RecipientFilter(const InfoHash& r) {
        return [r](const Value& v) {
            return v.recipient == r;
        };
    }

    static Filter OwnerFilter(const crypto::PublicKey& pk) {
        return OwnerFilter(pk.getId());
    }

    static Filter OwnerFilter(const InfoHash& pkh) {
        return [pkh](const Value& v) {
            return v.owner and v.owner->getId() == pkh;
        };
    }

    static Filter SeqNumFilter(uint16_t seq_no) {
        return [seq_no](const Value& v) {
            return v.seq == seq_no;
        };
    }

    static Filter UserTypeFilter(const std::string& ut) {
        return [ut](const Value& v) {
            return v.user_type == ut;
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
        return owner and not signature.empty();
    }

    /**
     * Sign the value using the provided private key.
     * Afterward, checkSignature() will return true and owner will
     * be set to the corresponding public key.
     */
    void sign(const crypto::PrivateKey& key) {
        if (isEncrypted())
            throw DhtException("Can't sign encrypted data.");
        owner = std::make_shared<const crypto::PublicKey>(key.getPublicKey());
        signature = key.sign(getToSign());
    }

    /**
     * Check that the value is signed and that the signature matches.
     * If true, the owner field will contain the signer public key.
     */
    bool checkSignature() const {
        return isSigned() and owner->checkSignature(getToSign(), signature);
    }

    std::shared_ptr<const crypto::PublicKey> getOwner() const {
        return std::static_pointer_cast<const crypto::PublicKey>(owner);
    }

    /**
     * Sign the value with from and returns the encrypted version for to.
     */
    Value encrypt(const crypto::PrivateKey& from, const crypto::PublicKey& to) {
        if (isEncrypted())
            throw DhtException("Data is already encrypted.");
        setRecipient(to.getId());
        sign(from);
        Value nv {id};
        nv.setCypher(to.encrypt(getToEncrypt()));
        return nv;
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

#if OPENDHT_PROXY_SERVER || OPENDHT_PROXY_CLIENT
    /**
     * Build a value from a json object
     * @param json
     */
    Value(Json::Value& json);
#endif //OPENDHT_PROXY_SERVER

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
        ((owner == o.owner || *owner == *o.owner) && type == o.type && data == o.data && user_type == o.user_type && signature == o.signature));
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
    OPENDHT_PUBLIC friend std::ostream& operator<< (std::ostream& s, const Value& v);

    std::string toString() const {
        std::stringstream ss;
        ss << *this;
        return ss.str();
    }

#if OPENDHT_PROXY_SERVER || OPENDHT_PROXY_CLIENT
    /**
     * Build a json object from a value
     * Example:
     * {
     *  "data":"base64ofdata",
     *   id":"0", "seq":0,"type":3
     * }
     */
    Json::Value toJson() const;
#endif //OPENDHT_PROXY_SERVER

    /** Return the size in bytes used by this value in memory (minimum). */
    size_t size() const;

    template <typename Packer>
    void msgpack_pack_to_sign(Packer& pk) const
    {
        bool has_owner = owner && *owner;
        pk.pack_map((user_type.empty()?0:1) + (has_owner?(recipient ? 5 : 4):2));
        if (has_owner) { // isSigned
            pk.pack(std::string("seq"));   pk.pack(seq);
            pk.pack(std::string("owner")); owner->msgpack_pack(pk);
            if (recipient) {
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

    template <typename Packer>
    void msgpack_pack_fields(const std::set<Value::Field>& fields, Packer& pk) const
    {
        for (const auto& field : fields)
            switch (field) {
                case Value::Field::Id:
                    pk.pack(static_cast<uint64_t>(id));
                    break;
                case Value::Field::ValueType:
                    pk.pack(static_cast<uint64_t>(type));
                    break;
                case Value::Field::OwnerPk:
                    if (owner)
                        owner->msgpack_pack(pk);
                    else
                        InfoHash().msgpack_pack(pk);
                    break;
                case Value::Field::SeqNum:
                    pk.pack(static_cast<uint64_t>(seq));
                    break;
                case Value::Field::UserType:
                    pk.pack(user_type);
                    break;
                default:
                    break;
            }
    }

    void msgpack_unpack(msgpack::object o);
    void msgpack_unpack_body(const msgpack::object& o);
    Blob getPacked() const {
        msgpack::sbuffer buffer;
        msgpack::packer<msgpack::sbuffer> pk(&buffer);
        pk.pack(*this);
        return {buffer.data(), buffer.data()+buffer.size()};
    }

    void msgpack_unpack_fields(const std::set<Value::Field>& fields, const msgpack::object& o, unsigned offset);

    Id id {INVALID_ID};

    /**
     * Public key of the signer.
     */
    std::shared_ptr<const crypto::PublicKey> owner {};

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

using ValuesExport = std::pair<InfoHash, Blob>;

/**
 * @class   FieldValue
 * @brief   Describes a value filter.
 * @details
 * This structure holds the value for a specified field. It's type can either be
 * uint64_t, InfoHash or Blob.
 */
struct OPENDHT_PUBLIC FieldValue
{
    FieldValue() {}
    FieldValue(Value::Field f, uint64_t int_value) : field(f), intValue(int_value) {}
    FieldValue(Value::Field f, InfoHash hash_value) : field(f), hashValue(hash_value) {}
    FieldValue(Value::Field f, Blob blob_value) : field(f), blobValue(blob_value) {}

    bool operator==(const FieldValue& fd) const;

    // accessors
    Value::Field getField() const { return field; }
    uint64_t getInt() const { return intValue; }
    InfoHash getHash() const { return hashValue; }
    Blob getBlob() const { return blobValue; }

    template <typename Packer>
    void msgpack_pack(Packer& p) const {
        p.pack_map(2);
        p.pack(std::string("f")); p.pack(static_cast<uint8_t>(field));

        p.pack(std::string("v"));
        switch (field) {
            case Value::Field::Id:
            case Value::Field::ValueType:
                p.pack(intValue);
                break;
            case Value::Field::OwnerPk:
                p.pack(hashValue);
                break;
            case Value::Field::UserType:
                p.pack_bin(blobValue.size());
                p.pack_bin_body((const char*)blobValue.data(), blobValue.size());
                break;
            default:
                throw msgpack::type_error();
        }
    }

    void msgpack_unpack(msgpack::object msg) {
        hashValue = {};
        blobValue.clear();

        if (auto f = findMapValue(msg, "f"))
            field = (Value::Field)f->as<unsigned>();
        else
            throw msgpack::type_error();

        auto v = findMapValue(msg, "v");
        if (not v)
            throw msgpack::type_error();
        else
            switch (field) {
                case Value::Field::Id:
                case Value::Field::ValueType:
                    intValue = v->as<decltype(intValue)>();
                    break;
                case Value::Field::OwnerPk:
                    hashValue = v->as<decltype(hashValue)>();
                    break;
                case Value::Field::UserType:
                    blobValue = unpackBlob(*v);
                    break;
                default:
                    throw msgpack::type_error();
            }
    }

    Value::Filter getLocalFilter() const;

private:
    Value::Field field {Value::Field::None};
    // three possible value types
    uint64_t intValue {};
    InfoHash hashValue {};
    Blob blobValue {};
};

/**
 * @class   Select
 * @brief   Serializable Value field selection.
 * @details
 * This is a container for a list of FieldSelectorDescription instances. It
 * describes a complete SELECT query for dht::Value.
 */
struct OPENDHT_PUBLIC Select
{
    Select() { }
    Select(const std::string& q_str);

    bool isSatisfiedBy(const Select& os) const;

    /**
     * Selects a field of type Value::Field.
     *
     * @param field  the field to require.
     *
     * @return the resulting Select instance.
     */
    Select& field(Value::Field field) {
        if (std::find(fieldSelection_.begin(), fieldSelection_.end(), field) == fieldSelection_.end())
            fieldSelection_.emplace_back(field);
        return *this;
    }

    /**
     * Computes the set of selected fields based on previous require* calls.
     *
     * @return the set of fields.
     */
    std::set<Value::Field> getSelection() const {
        return {fieldSelection_.begin(), fieldSelection_.end()};
    }

    template <typename Packer>
    void msgpack_pack(Packer& pk) const { pk.pack(fieldSelection_); }
    void msgpack_unpack(const msgpack::object& o) {
        fieldSelection_ = o.as<decltype(fieldSelection_)>();
    }

    std::string toString() const {
        std::stringstream ss;
        ss << *this;
        return ss.str();
    }

    OPENDHT_PUBLIC friend std::ostream& operator<<(std::ostream& s, const dht::Select& q);
private:
    std::vector<Value::Field> fieldSelection_ {};
};

/**
 * @class   Where
 * @brief   Serializable dht::Value filter.
 * @details
 * This is container for a list of FieldValue instances. It describes a
 * complete WHERE query for dht::Value.
 */
struct OPENDHT_PUBLIC Where
{
    Where() { }
    Where(const std::string& q_str);

    bool isSatisfiedBy(const Where& where) const;

    /**
     * Adds restriction on Value::Id based on the id argument.
     *
     * @param id  the id.
     *
     * @return the resulting Where instance.
     */
    Where& id(Value::Id id) {
        FieldValue fv {Value::Field::Id, id};
        if (std::find(filters_.begin(), filters_.end(), fv) == filters_.end())
            filters_.emplace_back(std::move(fv));
        return *this;
    }

    /**
     * Adds restriction on Value::ValueType based on the type argument.
     *
     * @param type  the value type.
     *
     * @return the resulting Where instance.
     */
    Where& valueType(ValueType::Id type) {
        FieldValue fv {Value::Field::ValueType, type};
        if (std::find(filters_.begin(), filters_.end(), fv) == filters_.end())
            filters_.emplace_back(std::move(fv));
        return *this;
    }

    /**
     * Adds restriction on Value::OwnerPk based on the owner_pk_hash argument.
     *
     * @param owner_pk_hash  the owner public key fingerprint.
     *
     * @return the resulting Where instance.
     */
    Where& owner(InfoHash owner_pk_hash) {
        FieldValue fv {Value::Field::OwnerPk, owner_pk_hash};
        if (std::find(filters_.begin(), filters_.end(), fv) == filters_.end())
            filters_.emplace_back(std::move(fv));
        return *this;
    }

    /**
     * Adds restriction on Value::OwnerPk based on the owner_pk_hash argument.
     *
     * @param owner_pk_hash  the owner public key fingerprint.
     *
     * @return the resulting Where instance.
     */
    Where& seq(uint16_t seq_no) {
        FieldValue fv {Value::Field::SeqNum, seq_no};
        if (std::find(filters_.begin(), filters_.end(), fv) == filters_.end())
            filters_.emplace_back(std::move(fv));
        return *this;
    }

    /**
     * Adds restriction on Value::UserType based on the user_type argument.
     *
     * @param user_type  the user type.
     *
     * @return the resulting Where instance.
     */
    Where& userType(std::string user_type) {
        FieldValue fv {Value::Field::UserType, Blob {user_type.begin(), user_type.end()}};
        if (std::find(filters_.begin(), filters_.end(), fv) == filters_.end())
            filters_.emplace_back(std::move(fv));
        return *this;
    }

    /**
     * Computes the Value::Filter based on the list of field value set.
     *
     * @return the resulting Value::Filter.
     */
    Value::Filter getFilter() const {
        if (filters_.empty()) return {};
        std::vector<Value::Filter> fset;
        fset.reserve(filters_.size());
        for (const auto& f : filters_) {
            if (auto lf = f.getLocalFilter())
                fset.emplace_back(std::move(lf));
        }
        return Value::Filter::chainAll(std::move(fset));
    }

    template <typename Packer>
    void msgpack_pack(Packer& pk) const { pk.pack(filters_); }
    void msgpack_unpack(const msgpack::object& o) {
        filters_.clear();
        filters_ = o.as<decltype(filters_)>();
    }

    std::string toString() const {
        std::stringstream ss;
        ss << *this;
        return ss.str();
    }

    bool empty() const {
        return filters_.empty();
    }

    OPENDHT_PUBLIC friend std::ostream& operator<<(std::ostream& s, const dht::Where& q);

private:
    std::vector<FieldValue> filters_;
};

/**
 * @class   Query
 * @brief   Describes a query destined to another peer.
 * @details
 * This class describes the list of filters on field values and the field
 * itselves to include in the peer response to a GET operation. See
 * FieldValue.
 */
struct OPENDHT_PUBLIC Query
{
    static const std::string QUERY_PARSE_ERROR;

    Query(Select s = {}, Where w = {}, bool none = false) : select(s), where(w), none(none) { };

    /**
     * Initializes a query based on a SQL-ish formatted string. The abstract
     * form of such a string is the following:
     *
     *  [SELECT $field$ [WHERE $field$=$value$]]
     *
     *  where
     *
     *  - $field$ = *|id|value_type|owner_pk|user_type
     *  - $value$ = $string$|$integer$
     *  - $string$: a simple string WITHOUT SPACES.
     *  - $integer$: a simple integer.
     */
    Query(std::string q_str) {
        auto pos_W = q_str.find("WHERE");
        auto pos_w = q_str.find("where");
        auto pos = std::min(pos_W != std::string::npos ? pos_W : q_str.size(),
                            pos_w != std::string::npos ? pos_w : q_str.size());
        select = q_str.substr(0, pos);
        where = q_str.substr(pos, q_str.size()-pos);
    }

    /**
     * Tell if the query is satisfied by another query.
     */
    bool isSatisfiedBy(const Query& q) const;

    template <typename Packer>
    void msgpack_pack(Packer& pk) const {
        pk.pack_map(2);
        pk.pack(std::string("s")); pk.pack(select); /* packing field selectors */
        pk.pack(std::string("w")); pk.pack(where);  /* packing filters */
    }

    void msgpack_unpack(const msgpack::object& o);

    std::string toString() const {
        std::stringstream ss;
        ss << *this;
        return ss.str();
    }

    OPENDHT_PUBLIC friend std::ostream& operator<<(std::ostream& s, const dht::Query& q) {
        return s << "Query[" << q.select << " " << q.where << "]";
    }

    Select select {};
    Where where {};
    bool none {false}; /* When true, any query satisfies this. */
};

/*!
 * @class   FieldValueIndex
 * @brief   An index for field values.
 * @details
 * This structures is meant to manipulate a subset of fields normally contained
 * in Value.
 */
struct OPENDHT_PUBLIC FieldValueIndex {
    FieldValueIndex() {}
    FieldValueIndex(const Value& v, Select s = {});
    /**
     * Tells if all the fields of this are contained in the other
     * FieldValueIndex with the same value.
     *
     * @param other  The other FieldValueIndex instance.
     */
    bool containedIn(const FieldValueIndex& other) const;

    OPENDHT_PUBLIC friend std::ostream& operator<<(std::ostream& os, const FieldValueIndex& fvi);

    void msgpack_unpack_fields(const std::set<Value::Field>& fields,
            const msgpack::object& o,
            unsigned offset);

    std::map<Value::Field, FieldValue> index {};
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

MSGPACK_ADD_ENUM(dht::Value::Field)
