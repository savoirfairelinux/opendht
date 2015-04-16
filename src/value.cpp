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

#include "value.h"

#include "default_types.h"
#include "securedht.h" // print certificate ID

namespace dht {

std::ostream& operator<< (std::ostream& s, const Value& v)
{
    s << "Value[id:" << std::hex << v.id << std::dec << " ";
    if (v.flags.isSigned())
        s << "signed (v" << v.seq << ") ";
    if (v.flags.isEncrypted())
        s << "encrypted ";
    else {
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
                s << std::setfill('0') << std::setw(2) << (unsigned)v.data[i];
            s << std::dec;
        }
    }
    s << "]";
    return s;
}

const ValueType ValueType::USER_DATA = {0, "User Data"};


void
Value::packToSign(Blob& res) const
{
    res.push_back(flags.to_ulong());
    if (flags.isEncrypted()) {
        res.insert(res.end(), cypher.begin(), cypher.end());
    } else {
        if (flags.isSigned()) {
            serialize<decltype(seq)>(seq, res);
            owner.pack(res);
            if (flags.haveRecipient())
                res.insert(res.end(), recipient.begin(), recipient.end());
        }
        serialize<ValueType::Id>(type, res);
        serialize<Blob>(data, res);
    }
}

Blob
Value::getToSign() const
{
    Blob ret;
    packToSign(ret);
    return ret;
}

/**
 * Pack part of the data to be encrypted
 */
void
Value::packToEncrypt(Blob& res) const
{
    packToSign(res);
    if (!flags.isEncrypted() && flags.isSigned())
        serialize<Blob>(signature, res);
}

Blob
Value::getToEncrypt() const
{
    Blob ret;
    packToEncrypt(ret);
    return ret;
}

void
Value::pack(Blob& res) const
{
    serialize<Id>(id, res);
    packToEncrypt(res);
}

void
Value::unpackBody(Blob::const_iterator& begin, Blob::const_iterator& end)
{
    // clear optional fields
    owner = {};
    recipient = {};
    cypher.clear();
    signature.clear();
    data.clear();
    type = 0;

    flags = {deserialize<uint8_t>(begin, end)};
    if (flags.isEncrypted()) {
        cypher = {begin, end};
        begin = end;
    } else {
        if(flags.isSigned()) {
            seq = deserialize<decltype(seq)>(begin, end);
            owner.unpack(begin, end);
            if (flags.haveRecipient())
               recipient = deserialize<InfoHash>(begin, end);
        }
        type = deserialize<ValueType::Id>(begin, end);
        data = deserialize<Blob>(begin, end);
        if (flags.isSigned())
            signature = deserialize<Blob>(begin, end);
    }
}

void
Value::unpack(Blob::const_iterator& begin, Blob::const_iterator& end)
{
    id = deserialize<Id>(begin, end);
    unpackBody(begin, end);
}

void
ValueSerializable::unpackValue(const Value& v) {
    unpackBlob(v.data);
}

Value
ValueSerializable::packValue() const {
    return Value {getType(), *this};
}

}
