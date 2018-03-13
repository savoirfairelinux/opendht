/*
 *  Copyright (C) 2017 Savoir-faire Linux Inc.
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
    Tid tid;
    /* tid for packets going through request socket */
    Tid socket_id;
    /* security token */
    Blob token;
    /* the value id (announce confirmation) */
    Value::Id value_id;
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
    SockAddr addr;
    void msgpack_unpack(msgpack::object o);

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
ParsedMessage::msgpack_unpack(msgpack::object msg)
{
    auto y = findMapValue(msg, "y");
    auto r = findMapValue(msg, "r");
    auto u = findMapValue(msg, "u");
    auto e = findMapValue(msg, "e");
    auto v = findMapValue(msg, "p");

    if (auto t = findMapValue(msg, "t"))
        tid = unpackTid(*t);

    if (auto rv = findMapValue(msg, "v"))
        ua = rv->as<std::string>();

    if (auto netid = findMapValue(msg, "n"))
        network = netid->as<NetId>();

    if (auto is_client_v = findMapValue(msg, "s"))
        is_client = is_client_v->as<bool>();

    std::string q;
    if (auto rq = findMapValue(msg, "q")) {
        if (rq->type != msgpack::type::STR)
            throw msgpack::type_error();
        q = rq->as<std::string>();
    }

    if (e)
        type = MessageType::Error;
    else if (r)
        type = MessageType::Reply;
    else if (v)
        type = MessageType::ValueData;
    else if (u)
        type = MessageType::ValueUpdate;
    else if (y and y->as<std::string>() != "q")
        throw msgpack::type_error();
    else if (q == "ping")
        type = MessageType::Ping;
    else if (q == "find")
        type = MessageType::FindNode;
    else if (q == "get")
        type = MessageType::GetValues;
    else if (q == "listen")
        type = MessageType::Listen;
    else if (q == "put")
        type = MessageType::AnnounceValue;
    else if (q == "refresh")
        type = MessageType::Refresh;
    else
        throw msgpack::type_error();

    if (type == MessageType::ValueData) {
        if (v->type != msgpack::type::MAP)
            throw msgpack::type_error();
        for (size_t i = 0; i < v->via.map.size; ++i) {
            auto& vdat = v->via.map.ptr[i];
            auto o = findMapValue(vdat.val, "o");
            auto d = findMapValue(vdat.val, "d");
            if (not o or not d)
                continue;
            value_parts.emplace(vdat.key.as<unsigned>(), std::pair<size_t, Blob>(o->as<size_t>(), unpackBlob(*d)));
        }
        return;
    }

    auto a = findMapValue(msg, "a");
    if (!a && !r && !e && !u)
        throw msgpack::type_error();
    auto& req = a ? *a : (r ? *r : (u ? *u : *e));

    if (e) {
        if (e->type != msgpack::type::ARRAY)
            throw msgpack::type_error();
        error_code = e->via.array.ptr[0].as<uint16_t>();
    }

    if (auto t = findMapValue(req, "sid"))
        socket_id = unpackTid(*t);

    if (auto rid = findMapValue(req, "id"))
        id = {*rid};

    if (auto rh = findMapValue(req, "h"))
        info_hash = {*rh};

    if (auto rtarget = findMapValue(req, "target"))
        target = {*rtarget};

    if (auto rquery = findMapValue(req, "q"))
        query.msgpack_unpack(*rquery);

    if (auto otoken = findMapValue(req, "token"))
        token = unpackBlob(*otoken);

    if (auto vid = findMapValue(req, "vid"))
        value_id = vid->as<Value::Id>();

    if (auto rnodes4 = findMapValue(req, "n4"))
        nodes4_raw = unpackBlob(*rnodes4);

    if (auto rnodes6 = findMapValue(req, "n6"))
        nodes6_raw = unpackBlob(*rnodes6);

    if (auto sa = findMapValue(req, "sa")) {
        if (sa->type != msgpack::type::BIN)
            throw msgpack::type_error();
        auto l = sa->via.bin.size;
        if (l == sizeof(in_addr)) {
            addr.setFamily(AF_INET);
            auto& a = addr.getIPv4();
            a.sin_port = 0;
            std::copy_n(sa->via.bin.ptr, l, (char*)&a.sin_addr);
        } else if (l == sizeof(in6_addr)) {
            addr.setFamily(AF_INET6);
            auto& a = addr.getIPv6();
            a.sin6_port = 0;
            std::copy_n(sa->via.bin.ptr, l, (char*)&a.sin6_addr);
        }
    } else
        addr = {};

    if (auto rcreated = findMapValue(req, "c"))
        created = from_time_t(rcreated->as<std::time_t>());

    if (auto rvalues = findMapValue(req, "values")) {
        if (rvalues->type != msgpack::type::ARRAY)
            throw msgpack::type_error();
        for (size_t i = 0; i < rvalues->via.array.size; i++) {
            auto& packed_v = rvalues->via.array.ptr[i];
            if (packed_v.type == msgpack::type::POSITIVE_INTEGER) {
                // Skip oversize values with a small margin for header overhead
                if (packed_v.via.u64 > MAX_VALUE_SIZE + 32)
                    continue;
                value_parts.emplace(i, std::make_pair(packed_v.via.u64, Blob{}));
            } else {
                try {
                    values.emplace_back(std::make_shared<Value>(rvalues->via.array.ptr[i]));
                } catch (const std::exception& e) {
                     //DHT_LOG_WARN("Error reading value: %s", e.what());
                }
            }
        }
    } else if (auto raw_fields = findMapValue(req, "fields")) {
        if (auto rfields = findMapValue(*raw_fields, "f")) {
            auto vfields = rfields->as<std::set<Value::Field>>();
            if (auto rvalues = findMapValue(*raw_fields, "v")) {
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
    } else if (auto raw_fields = findMapValue(req, "exp")) {
        expired_values = raw_fields->as<decltype(expired_values)>();
    } else if (auto raw_fields = findMapValue(req, "re")) {
        refreshed_values = raw_fields->as<decltype(refreshed_values)>();
    }

    if (auto w = findMapValue(req, "w")) {
        if (w->type != msgpack::type::ARRAY)
            throw msgpack::type_error();
        want = 0;
        for (unsigned i=0; i<w->via.array.size; i++) {
            auto& val = w->via.array.ptr[i];
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
