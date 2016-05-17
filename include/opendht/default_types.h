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

#include "value.h"

namespace dht {
enum class ImStatus : uint8_t {
    NONE = 0,
    TYPING,
    RECEIVED,
    READ
};
}
MSGPACK_ADD_ENUM(dht::ImStatus);

namespace dht {

class DhtMessage : public Value::Serializable<DhtMessage>
{
public:
    static const ValueType TYPE;

    DhtMessage(std::string s = {}, Blob msg = {}) : service(s), data(msg) {}

    std::string getService() const {
        return service;
    }

    static Value::Filter getFilter() { return {}; }

    static bool storePolicy(InfoHash key, std::shared_ptr<Value>& value, InfoHash from, const sockaddr* from_addr, socklen_t from_len);

    static Value::Filter ServiceFilter(std::string s);

    /** print value for debugging */
    friend std::ostream& operator<< (std::ostream&, const DhtMessage&);

    std::string service;
    Blob data;
    MSGPACK_DEFINE(service, data);
};

template <typename T>
class SignedValue : public Value::Serializable<T>
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
class EncryptedValue : public SignedValue<T>
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
            [](const Value& v){ return v.recipient != InfoHash(); }
        );
    }

    dht::InfoHash to;
};




class ImMessage : public SignedValue<ImMessage>
{
private:
    using BaseClass = SignedValue<ImMessage>;

public:
    static const ValueType TYPE;

    ImMessage() {}
    ImMessage(dht::Value::Id id, std::string&& m, long d = 0)
        : id(id), msg(std::move(m)), date(d) {}

    virtual void unpackValue(const Value& v) override {
        to = v.recipient;
        SignedValue::unpackValue(v);
    }

    dht::InfoHash to;
    dht::Value::Id id;
    std::string msg;
    long date {0};
    ImStatus status {ImStatus::NONE};

    MSGPACK_DEFINE_MAP(id, msg, date, status);
};

class TrustRequest : public EncryptedValue<TrustRequest>
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
    MSGPACK_DEFINE(service, payload);
};

class IceCandidates : public EncryptedValue<IceCandidates>
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

    virtual void msgpack_unpack(msgpack::object o)
    {
        if (o.type != msgpack::type::ARRAY) throw msgpack::type_error();
        if (o.via.array.size < 2) throw msgpack::type_error();
        id = o.via.array.ptr[0].as<Value::Id>();
        ice_data = unpackBlob(o.via.array.ptr[1]);
    }

    Value::Id id;
    Blob ice_data;
};

/* "Peer" announcement
 */
class IpServiceAnnouncement : public Value::Serializable<IpServiceAnnouncement>
{
private:
    using BaseClass = Value::Serializable<IpServiceAnnouncement>;

public:
    static const ValueType TYPE;

    IpServiceAnnouncement(in_port_t p = 0) {
        ss.ss_family = 0;
        setPort(p);
    }

    IpServiceAnnouncement(const sockaddr* sa, socklen_t sa_len) {
        if (sa)
            std::copy_n((const uint8_t*)sa, sa_len, (uint8_t*)&ss);
    }

    IpServiceAnnouncement(const Blob& b) {
        msgpack_unpack(unpackMsg(b).get());
    }

    template <typename Packer>
    void msgpack_pack(Packer& pk) const
    {
        pk.pack_array(2);
        pk.pack(getPort());
        if (ss.ss_family == AF_INET) {
            pk.pack_bin(sizeof(in_addr));
            pk.pack_bin_body((const char*)&reinterpret_cast<const sockaddr_in*>(&ss)->sin_addr, sizeof(in_addr));
        } else if (ss.ss_family == AF_INET6) {
            pk.pack_bin(sizeof(in6_addr));
            pk.pack_bin_body((const char*)&reinterpret_cast<const sockaddr_in6*>(&ss)->sin6_addr, sizeof(in6_addr));
        }
    }

    virtual void msgpack_unpack(msgpack::object o)
    {
        if (o.type != msgpack::type::ARRAY) throw msgpack::type_error();
        if (o.via.array.size < 2) throw msgpack::type_error();
        setPort(o.via.array.ptr[0].as<in_port_t>());
        auto ip_dat = o.via.array.ptr[1].as<Blob>();
        if (ip_dat.size() == sizeof(in_addr))
            std::copy(ip_dat.begin(), ip_dat.end(), (char*)&reinterpret_cast<sockaddr_in*>(&ss)->sin_addr);
        else if (ip_dat.size() == sizeof(in6_addr))
            std::copy(ip_dat.begin(), ip_dat.end(), (char*)&reinterpret_cast<sockaddr_in6*>(&ss)->sin6_addr);
        else
            throw msgpack::type_error();
    }

    in_port_t getPort() const {
        return ntohs(reinterpret_cast<const sockaddr_in*>(&ss)->sin_port);
    }
    void setPort(in_port_t p) {
        reinterpret_cast<sockaddr_in*>(&ss)->sin_port = htons(p);
    }

    sockaddr_storage getPeerAddr() const {
        return ss;
    }

    virtual const ValueType& getType() const {
        return TYPE;
    }

    static bool storePolicy(InfoHash, std::shared_ptr<Value>&, InfoHash, const sockaddr*, socklen_t);

    /** print value for debugging */
    friend std::ostream& operator<< (std::ostream&, const IpServiceAnnouncement&);

private:
    sockaddr_storage ss;
};


extern const std::array<std::reference_wrapper<const ValueType>, 5> DEFAULT_TYPES;

extern const std::array<std::reference_wrapper<const ValueType>, 1> DEFAULT_INSECURE_TYPES;

}
