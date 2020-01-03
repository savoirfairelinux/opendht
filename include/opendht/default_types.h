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

#include "value.h"
#include "sockaddr.h"

namespace dht {
enum class ImStatus : uint8_t {
    NONE = 0,
    TYPING,
    RECEIVED,
    READ
};
}
MSGPACK_ADD_ENUM(dht::ImStatus)

namespace dht {

class OPENDHT_PUBLIC DhtMessage : public Value::Serializable<DhtMessage>
{
public:
    static const ValueType TYPE;

    DhtMessage(const std::string& s = {}, const Blob& msg = {}) : service(s), data(msg) {}

    std::string getService() const {
        return service;
    }

    static Value::Filter getFilter() { return {}; }

    static bool storePolicy(InfoHash key, std::shared_ptr<Value>& value, const InfoHash& from, const SockAddr&);

    static Value::Filter ServiceFilter(const std::string& s);

    /** print value for debugging */
    friend std::ostream& operator<< (std::ostream&, const DhtMessage&);

    std::string service;
    Blob data;
    MSGPACK_DEFINE(service, data)
};

template <typename T>
class OPENDHT_PUBLIC SignedValue : public Value::Serializable<T>
{
private:
    using BaseClass = Value::Serializable<T>;

public:
    virtual void unpackValue(const Value& v) override {
        if (v.owner)
            from = v.owner->getId();
        BaseClass::unpackValue(v);
    }

    static Value::Filter getFilter() {
        return [](const Value& v){ return v.isSigned(); };
    }

    dht::InfoHash from;
};

template <typename T>
class OPENDHT_PUBLIC EncryptedValue : public SignedValue<T>
{
public:
    using BaseClass = SignedValue<T>;

public:
    virtual void unpackValue(const Value& v) override {
        to = v.recipient;
        BaseClass::unpackValue(v);
    }

    static Value::Filter getFilter() {
        return Value::Filter::chain(
            BaseClass::getFilter(),
            [](const Value& v) { return static_cast<bool>(v.recipient); }
        );
    }

    dht::InfoHash to;
};




class OPENDHT_PUBLIC ImMessage : public SignedValue<ImMessage>
{
private:
    using BaseClass = SignedValue<ImMessage>;

public:
    static const ValueType TYPE;

    ImMessage() {}
    ImMessage(dht::Value::Id id, std::string&& m, long d = 0)
        : id(id), msg(std::move(m)), date(d) {}
    ImMessage(dht::Value::Id id, std::string &&dt, std::string &&m, long d = 0)
        : id(id), msg(std::move(m)), datatype(std::move(dt)), date(d) {}
    ImMessage(dht::Value::Id id, std::string &&dt, std::string &&m, std::map<std::string, std::string> &&md, long d = 0)
        : id(id), msg(std::move(m)), datatype(std::move(dt)), metadatas(std::move(md)), date(d) {}

    virtual void unpackValue(const Value& v) override {
        to = v.recipient;
        SignedValue::unpackValue(v);
    }

    dht::InfoHash to;
    dht::Value::Id id {0};
    std::string msg;
    std::string datatype;
    std::map<std::string, std::string> metadatas;
    long date {0};
    ImStatus status {ImStatus::NONE};

    MSGPACK_DEFINE_MAP(id, msg, date, status, datatype, metadatas)
};

class OPENDHT_PUBLIC TrustRequest : public EncryptedValue<TrustRequest>
{
private:
    using BaseClass = EncryptedValue<TrustRequest>;

public:
    static const ValueType TYPE;

    TrustRequest() {}
    TrustRequest(std::string s) : service(s) {}
    TrustRequest(std::string s, const Blob& d) : service(s), payload(d) {}

    static Value::Filter getFilter() {
        return EncryptedValue::getFilter();
    }

    std::string service;
    Blob payload;
    bool confirm {false};
    MSGPACK_DEFINE_MAP(service, payload, confirm)
};

class OPENDHT_PUBLIC IceCandidates : public EncryptedValue<IceCandidates>
{
private:
    using BaseClass = EncryptedValue<IceCandidates>;

public:
    static const ValueType TYPE;

    IceCandidates() {}
    IceCandidates(Value::Id msg_id, Blob ice) : id(msg_id), ice_data(ice) {}

    static Value::Filter getFilter() {
        return EncryptedValue::getFilter();
    }

    template <typename Packer>
    void msgpack_pack(Packer& pk) const
    {
        pk.pack_array(2);
        pk.pack(id);
#if 1
        pk.pack_bin(ice_data.size());
        pk.pack_bin_body((const char*)ice_data.data(), ice_data.size());
#else
        // hack for backward compatibility with old opendht compiled with msgpack 1.0
        // remove when enough people have moved to new versions
        pk.pack_array(ice_data.size());
        for (uint8_t b : ice_data)
            pk.pack(b);
#endif
    }

    virtual void msgpack_unpack(const msgpack::object& o)
    {
        if (o.type != msgpack::type::ARRAY) throw msgpack::type_error();
        if (o.via.array.size < 2) throw msgpack::type_error();
        id = o.via.array.ptr[0].as<Value::Id>();
        ice_data = unpackBlob(o.via.array.ptr[1]);
    }

    Value::Id id {0};
    Blob ice_data;
};

/* "Peer" announcement
 */
class OPENDHT_PUBLIC IpServiceAnnouncement : public Value::Serializable<IpServiceAnnouncement>
{
private:
    using BaseClass = Value::Serializable<IpServiceAnnouncement>;

public:
    static const ValueType TYPE;

    IpServiceAnnouncement(sa_family_t family = AF_UNSPEC, in_port_t p = 0) {
        addr.setFamily(family);
        addr.setPort(p);
    }

    IpServiceAnnouncement(const SockAddr& sa) : addr(sa) {}

    IpServiceAnnouncement(const Blob& b) {
        msgpack_unpack(unpackMsg(b).get());
    }

    template <typename Packer>
    void msgpack_pack(Packer& pk) const
    {
        pk.pack_bin(addr.getLength());
        pk.pack_bin_body((const char*)addr.get(), addr.getLength());
    }

    virtual void msgpack_unpack(const msgpack::object& o)
    {
        if (o.type == msgpack::type::BIN)
            addr = {(sockaddr*)o.via.bin.ptr, (socklen_t)o.via.bin.size};
        else
            throw msgpack::type_error();
    }

    in_port_t getPort() const {
        return addr.getPort();
    }
    void setPort(in_port_t p) {
        addr.setPort(p);
    }

    const SockAddr& getPeerAddr() const {
        return addr;
    }

    virtual const ValueType& getType() const {
        return TYPE;
    }

    static bool storePolicy(InfoHash, std::shared_ptr<Value>&, const InfoHash&, const SockAddr&);

    /** print value for debugging */
    friend std::ostream& operator<< (std::ostream&, const IpServiceAnnouncement&);

private:
    SockAddr addr;
};


OPENDHT_PUBLIC extern const std::array<std::reference_wrapper<const ValueType>, 5> DEFAULT_TYPES;

OPENDHT_PUBLIC extern const std::array<std::reference_wrapper<const ValueType>, 1> DEFAULT_INSECURE_TYPES;

}
