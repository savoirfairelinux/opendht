/*
 *  Copyright (C) 2014-2015 Savoir-Faire Linux Inc.
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

#include "value.h"

#include "default_types.h"
#include "securedht.h" // print certificate ID

namespace dht {

time_point from_time_t(std::time_t t) {
    return clock::now() + (std::chrono::system_clock::from_time_t(t) - std::chrono::system_clock::now());
}

std::time_t to_time_t(time_point t) {
    return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + 
            (t - clock::now()));
}


std::ostream& operator<< (std::ostream& s, const Value& v)
{
    s << "Value[id:" << std::hex << v.id << std::dec << " ";
    if (v.isEncrypted())
        s << "encrypted ";
    else if (v.isSigned()) {
        s << "signed (v" << v.seq << ") ";
        if (v.recipient != InfoHash())
            s << "decrypted ";
    }
    if (not v.isEncrypted()) {
        if (v.type == IpServiceAnnouncement::TYPE.id) {
            s << IpServiceAnnouncement(v.data);
        } else if (v.type == CERTIFICATE_TYPE.id) {
            s << "Certificate";
            try {
                InfoHash h = crypto::Certificate(v.data).getPublicKey().getId();
                s << " with ID " << h;
            } catch (const std::exception& e) {
                s << " (invalid)";
            }
        } else {
            s << "Data (type: " << v.type << " ): ";
            s << std::hex;
            for (size_t i=0; i<v.data.size(); i++)
                s << std::setfill('0') << std::setw(2) << (unsigned)v.data[i] << " ";
            s << std::dec;
        }
    }
    s << "]";
    return s;
}

const ValueType ValueType::USER_DATA = {0, "User Data"};


msgpack::unpacked
unpackMsg(Blob b) {
    return msgpack::unpack((const char*)b.data(), b.size());
}

msgpack::object*
findMapValue(const msgpack::object& map, const std::string& key) {
    if (map.type != msgpack::type::MAP) throw msgpack::type_error();
    for (unsigned i = 0; i < map.via.map.size; i++) {
        auto& o = map.via.map.ptr[i];
        if(o.key.type != msgpack::type::STR)
            continue;
        if (o.key.as<std::string>() == key) {
            return &o.val;
        }
    }
    return nullptr;
}

void
Value::msgpack_unpack(msgpack::object o)
{
    if (o.type != msgpack::type::MAP) throw msgpack::type_error();
    if (o.via.map.size < 2) throw msgpack::type_error();

    if (auto rid = findMapValue(o, "id")) {
        id = rid->as<Id>();
    } else
        throw msgpack::type_error();

    if (auto rdat = findMapValue(o, "dat")) {
        msgpack_unpack_body(*rdat);
    } else
        throw msgpack::type_error();
}

void
Value::msgpack_unpack_body(const msgpack::object& o)
{
    owner = {};
    recipient = {};
    cypher.clear();
    signature.clear();
    data.clear();
    type = 0;

    if (o.type == msgpack::type::BIN) {
        auto dat = o.as<std::vector<char>>();
        cypher = {dat.begin(), dat.end()};
    } else {
        if (o.type != msgpack::type::MAP)
            throw msgpack::type_error();
        auto rbody = findMapValue(o, "body");
        if (not rbody)
            throw msgpack::type_error();

        if (auto rdata = findMapValue(*rbody, "data")) {
            data = unpackBlob(*rdata);
        } else
            throw msgpack::type_error();

        if (auto rtype = findMapValue(*rbody, "type")) {
            type = rtype->as<ValueType::Id>();
        } else
            throw msgpack::type_error();

        if (auto rutype = findMapValue(*rbody, "utype")) {
            user_type = rutype->as<std::string>();
        }

        if (auto rowner = findMapValue(*rbody, "owner")) {
            if (auto rseq = findMapValue(*rbody, "seq"))
                seq = rseq->as<decltype(seq)>();
            else
                throw msgpack::type_error();
            owner.msgpack_unpack(*rowner);
            if (auto rrecipient = findMapValue(*rbody, "to")) {
                recipient = rrecipient->as<InfoHash>();
            }

            if (auto rsig = findMapValue(o, "sig")) {
                signature = unpackBlob(*rsig);
            } else
                throw msgpack::type_error();
        }
    }
}

Blob
unpackBlob(msgpack::object& o) {
    switch (o.type) {
    case msgpack::type::BIN:
        return {o.via.bin.ptr, o.via.bin.ptr+o.via.bin.size};
    case msgpack::type::STR:
        return {o.via.str.ptr, o.via.str.ptr+o.via.str.size};
    case msgpack::type::ARRAY: {
        Blob ret(o.via.array.size);
        std::transform(o.via.array.ptr, o.via.array.ptr+o.via.array.size, ret.begin(), [](const msgpack::object& b) {
            return b.as<uint8_t>();
        });
        return ret;
    }
    default:
        throw msgpack::type_error();
    }
}

}
