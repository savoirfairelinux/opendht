/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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
#include "sockaddr.h"
#include "net.h"

#include <map>

namespace dht {
namespace net {

static const std::string KEY_Y {"y"};
static const std::string KEY_R {"r"};
static const std::string KEY_U {"u"};
static const std::string KEY_E {"e"};
static const std::string KEY_V {"p"};
static const std::string KEY_TID {"t"};
static const std::string KEY_UA {"v"};
static const std::string KEY_NETID {"n"};
static const std::string KEY_ISCLIENT {"s"};
static const std::string KEY_Q {"q"};
static const std::string KEY_A {"a"};

static const std::string KEY_REQ_SID {"sid"};
static const std::string KEY_REQ_ID {"id"};
static const std::string KEY_REQ_H {"h"};
static const std::string KEY_REQ_TARGET {"target"};
static const std::string KEY_REQ_QUERY {"q"};
static const std::string KEY_REQ_TOKEN {"token"};
static const std::string KEY_REQ_VALUE_ID {"vid"};
static const std::string KEY_REQ_NODES4 {"n4"};
static const std::string KEY_REQ_NODES6 {"n6"};
static const std::string KEY_REQ_CREATION {"c"};
static const std::string KEY_REQ_ADDRESS {"sa"};
static const std::string KEY_REQ_VALUES {"values"};
static const std::string KEY_REQ_EXPIRED {"exp"};
static const std::string KEY_REQ_REFRESHED {"re"};
static const std::string KEY_REQ_FIELDS {"fileds"};
static const std::string KEY_REQ_WANT {"w"};
static const std::string KEY_VERSION {"ve"};

static const std::string QUERY_PING {"ping"};
static const std::string QUERY_FIND {"find"};
static const std::string QUERY_GET {"get"};
static const std::string QUERY_UPDATE {"update"};
static const std::string QUERY_PUT {"put"};
static const std::string QUERY_LISTEN {"listen"};
static const std::string QUERY_REFRESH {"refresh"};

Tid unpackTid(const msgpack::object& o) {
    switch (o.type) {
    case msgpack::type::POSITIVE_INTEGER:
        return o.as<Tid>();
    default:
        return ntohl(*reinterpret_cast<const uint32_t*>(o.as<std::array<char, 4>>().data()));
    }
}

struct ParsedMessage {
    MessageType type;
    /* Node ID of the sender */
    InfoHash id;
    /* Network id */
    NetId network {0};
    /** Is a client node */
    bool is_client {false};
    /* hash for which values are requested */
    InfoHash info_hash;
    /* target id around which to find nodes */
    InfoHash target;
    /* transaction id */
    Tid tid {0};
    /* tid for packets going through request socket */
    Tid socket_id {0};
    /* security token */
    Blob token;
    /* the value id (announce confirmation) */
    Value::Id value_id {0};
    /* time when value was first created */
    time_point created { time_point::max() };
    /* IPv4 nodes in response to a 'find' request */
    Blob nodes4_raw, nodes6_raw;
    std::vector<Sp<Node>> nodes4, nodes6;
    /* values to store or retreive request */
    std::vector<Sp<Value>> values;
    std::vector<Value::Id> refreshed_values {};
    std::vector<Value::Id> expired_values {};
    /* index for fields values */
    std::vector<Sp<FieldValueIndex>> fields;
    /** When part of the message header: {index -> (total size, {})}
     *  When part of partial value data: {index -> (offset, part_data)} */
    std::map<unsigned, std::pair<unsigned, Blob>> value_parts;
    /* query describing a filter to apply on values. */
    Query query;
    /* states if ipv4 or ipv6 request */
    want_t want;
    /* error code in case of error */
    uint16_t error_code;
    /* reported address by the distant node */
    std::string ua;
    int version {0};
    SockAddr addr;
    void msgpack_unpack(const msgpack::object& o);

    bool append(const ParsedMessage& block);
    bool complete();
};

bool
ParsedMessage::append(const ParsedMessage& block)
{
    bool ret(false);
    for (const auto& ve : block.value_parts) {
        auto part_val = value_parts.find(ve.first);
        if (part_val == value_parts.end()
            || part_val->second.second.size() >= part_val->second.first)
            continue;
        // TODO: handle out-of-order packets
        if (ve.second.first != part_val->second.second.size()) {
            //std::cout << "skipping out-of-order packet" << std::endl;
            continue;
        }
        ret = true;
        part_val->second.second.insert(part_val->second.second.end(),
                                       ve.second.second.begin(),
                                       ve.second.second.end());
    }
    return ret;
}

bool
ParsedMessage::complete()
{
    for (auto& e : value_parts) {
        //std::cout << "part " << e.first << ": " << e.second.second.size() << "/" << e.second.first << std::endl;
        if (e.second.first > e.second.second.size())
            return false;
    }
    for (auto& e : value_parts) {
        msgpack::unpacked msg;
        msgpack::unpack(msg, (const char*)e.second.second.data(), e.second.second.size());
        values.emplace_back(std::make_shared<Value>(msg.get()));
    }
    return true;
}

void
ParsedMessage::msgpack_unpack(const msgpack::object& msg)
{
    if (msg.type != msgpack::type::MAP) throw msgpack::type_error();

    struct ParsedMsg {
        msgpack::object* y;
        msgpack::object* r;
        msgpack::object* u;
        msgpack::object* e;
        msgpack::object* v;
        msgpack::object* a;
        std::string q;
    } parsed {};

    for (unsigned i = 0; i < msg.via.map.size; i++) {
        auto& o = msg.via.map.ptr[i];
        if (o.key.type != msgpack::type::STR)
            continue;
        auto key = o.key.as<std::string>();
        if (key == KEY_Y)
            parsed.y = &o.val;
        else if (key == KEY_R)
            parsed.r = &o.val;
        else if (key == KEY_U)
            parsed.u = &o.val;
        else if (key == KEY_E)
            parsed.e = &o.val;
        else if (key == KEY_V)
            parsed.v = &o.val;
        else if (key == KEY_TID)
            tid = unpackTid(o.val);
        else if (key == KEY_UA)
            ua = o.val.as<std::string>();
        else if (key == KEY_NETID)
            network = o.val.as<NetId>();
        else if (key == KEY_ISCLIENT)
            is_client = o.val.as<bool>();
        else if (key == KEY_Q)
            parsed.q = o.val.as<std::string>();
        else if (key == KEY_A)
            parsed.a = &o.val;
    }

    if (parsed.e)
        type = MessageType::Error;
    else if (parsed.r)
        type = MessageType::Reply;
    else if (parsed.v)
        type = MessageType::ValueData;
    else if (parsed.u)
        type = MessageType::ValueUpdate;
    else if (parsed.y and parsed.y->as<std::string>() != "q")
        throw msgpack::type_error();
    else if (parsed.q == QUERY_PING)
        type = MessageType::Ping;
    else if (parsed.q == QUERY_FIND)
        type = MessageType::FindNode;
    else if (parsed.q == QUERY_GET)
        type = MessageType::GetValues;
    else if (parsed.q == QUERY_LISTEN)
        type = MessageType::Listen;
    else if (parsed.q == QUERY_PUT)
        type = MessageType::AnnounceValue;
    else if (parsed.q == QUERY_REFRESH)
        type = MessageType::Refresh;
    else if (parsed.q == QUERY_UPDATE)
        type = MessageType::UpdateValue;
    else
        throw msgpack::type_error();

    if (type == MessageType::ValueData) {
        if (parsed.v->type != msgpack::type::MAP)
            throw msgpack::type_error();
        for (size_t i = 0; i < parsed.v->via.map.size; ++i) {
            auto& vdat = parsed.v->via.map.ptr[i];
            auto o = findMapValue(vdat.val, "o");
            auto d = findMapValue(vdat.val, "d");
            if (not o or not d)
                continue;
            value_parts.emplace(vdat.key.as<unsigned>(), std::pair<size_t, Blob>(o->as<size_t>(), unpackBlob(*d)));
        }
        return;
    }

    if (!parsed.a && !parsed.r && !parsed.e && !parsed.u)
        throw msgpack::type_error();
    auto& req = parsed.a ? *parsed.a : (parsed.r ? *parsed.r : (parsed.u ? *parsed.u : *parsed.e));

    if (parsed.e) {
        if (parsed.e->type != msgpack::type::ARRAY)
            throw msgpack::type_error();
        error_code = parsed.e->via.array.ptr[0].as<uint16_t>();
    }

    struct ParsedReq {
        msgpack::object* values;
        msgpack::object* fields;
        msgpack::object* sa;
        msgpack::object* want;
    } parsedReq {};

    for (unsigned i = 0; i < req.via.map.size; i++) {
        auto& o = req.via.map.ptr[i];
        if (o.key.type != msgpack::type::STR)
            continue;
        auto key = o.key.as<std::string>();
        if (key == KEY_REQ_SID)
            socket_id = unpackTid(o.val);
        else if (key == KEY_REQ_ID)
            id = {o.val};
        else if (key == KEY_REQ_H)
            info_hash = {o.val};
        else if (key == KEY_REQ_TARGET)
            target = {o.val};
        else if (key == KEY_REQ_QUERY)
            query.msgpack_unpack(o.val);
        else if (key == KEY_REQ_TOKEN)
            token = unpackBlob(o.val);
        else if (key == KEY_REQ_VALUE_ID)
            value_id = o.val.as<Value::Id>();
        else if (key == KEY_REQ_NODES4)
            nodes4_raw = unpackBlob(o.val);
        else if (key == KEY_REQ_NODES6)
            nodes6_raw = unpackBlob(o.val);
        else if (key == KEY_REQ_ADDRESS)
            parsedReq.sa = &o.val;
        else if (key == KEY_REQ_CREATION)
            created = from_time_t(o.val.as<std::time_t>());
        else if (key == KEY_REQ_VALUES)
            parsedReq.values = &o.val;
        else if (key == KEY_REQ_EXPIRED)
            expired_values = o.val.as<decltype(expired_values)>();
        else if (key == KEY_REQ_REFRESHED)
            refreshed_values = o.val.as<decltype(refreshed_values)>();
        else if (key == KEY_REQ_FIELDS)
            parsedReq.fields = &o.val;
        else if (key == KEY_REQ_WANT)
            parsedReq.want = &o.val;
        else if (key == KEY_VERSION)
            version = o.val.as<int>();
    }

    if (parsedReq.sa) {
        if (parsedReq.sa->type != msgpack::type::BIN)
            throw msgpack::type_error();
        auto l = parsedReq.sa->via.bin.size;
        if (l == sizeof(in_addr)) {
            addr.setFamily(AF_INET);
            auto& a = addr.getIPv4();
            a.sin_port = 0;
            std::copy_n(parsedReq.sa->via.bin.ptr, l, (char*)&a.sin_addr);
        } else if (l == sizeof(in6_addr)) {
            addr.setFamily(AF_INET6);
            auto& a = addr.getIPv6();
            a.sin6_port = 0;
            std::copy_n(parsedReq.sa->via.bin.ptr, l, (char*)&a.sin6_addr);
        }
    } else
        addr = {};

    if (parsedReq.values) {
        if (parsedReq.values->type != msgpack::type::ARRAY)
            throw msgpack::type_error();
        for (size_t i = 0; i < parsedReq.values->via.array.size; i++) {
            auto& packed_v = parsedReq.values->via.array.ptr[i];
            if (packed_v.type == msgpack::type::POSITIVE_INTEGER) {
                // Skip oversize values with a small margin for header overhead
                if (packed_v.via.u64 > MAX_VALUE_SIZE + 32)
                    continue;
                value_parts.emplace(i, std::make_pair(packed_v.via.u64, Blob{}));
            } else {
                try {
                    values.emplace_back(std::make_shared<Value>(parsedReq.values->via.array.ptr[i]));
                } catch (const std::exception& e) {
                     //DHT_LOG_WARN("Error reading value: %s", e.what());
                }
            }
        }
    } else if (parsedReq.fields) {
        if (auto rfields = findMapValue(*parsedReq.fields, "f")) {
            auto vfields = rfields->as<std::set<Value::Field>>();
            if (auto rvalues = findMapValue(*parsedReq.fields, "v")) {
                if (rvalues->type != msgpack::type::ARRAY)
                    throw msgpack::type_error();
                size_t val_num = rvalues->via.array.size / vfields.size();
                for (size_t i = 0; i < val_num; ++i) {
                    try {
                        auto v = std::make_shared<FieldValueIndex>();
                        v->msgpack_unpack_fields(vfields, *rvalues, i*vfields.size());
                        fields.emplace_back(std::move(v));
                    } catch (const std::exception& e) { }
                }
            }
        } else {
            throw msgpack::type_error();
        }
    }

    if (parsedReq.want) {
        if (parsedReq.want->type != msgpack::type::ARRAY)
            throw msgpack::type_error();
        want = 0;
        for (unsigned i=0; i<parsedReq.want->via.array.size; i++) {
            auto& val = parsedReq.want->via.array.ptr[i];
            try {
                auto w = val.as<sa_family_t>();
                if (w == AF_INET)
                    want |= WANT4;
                else if(w == AF_INET6)
                    want |= WANT6;
            } catch (const std::exception& e) {};
        }
    } else {
        want = -1;
    }
}

} /* namespace net  */
} /* namespace dht */
