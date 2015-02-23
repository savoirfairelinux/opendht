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

std::ostream& operator<< (std::ostream& s, const IpServiceAnnouncement& v)
{
    s << "Peer: ";
    s << "port " << v.getPort();

    if (v.ss.ss_family == AF_INET || v.ss.ss_family == AF_INET6) {
        char hbuf[NI_MAXHOST];
        if (getnameinfo((sockaddr*)&v.ss, sizeof(v.ss), hbuf, sizeof(hbuf), nullptr, 0, NI_NUMERICHOST) == 0) {
            s << " addr " << std::string(hbuf, strlen(hbuf));
        }
    }
    return s;
}

void
IpServiceAnnouncement::pack(Blob& res) const
{
    serialize<in_port_t>(getPort(), res);
    if (ss.ss_family == AF_INET) {
        auto sa4 = reinterpret_cast<const sockaddr_in*>(&ss);
        serialize<in_addr>(sa4->sin_addr, res);
    } else if (ss.ss_family == AF_INET6) {
        auto sa6 = reinterpret_cast<const sockaddr_in6*>(&ss);
        serialize<in6_addr>(sa6->sin6_addr, res);
    }
}

void
IpServiceAnnouncement::unpack(Blob::const_iterator& begin, Blob::const_iterator& end)
{
    setPort(deserialize<in_port_t>(begin, end));
    size_t addr_size = end - begin;
    if (addr_size < sizeof(in_addr)) {
        ss.ss_family = 0;
    } else if (addr_size == sizeof(in_addr)) {
        auto sa4 = reinterpret_cast<sockaddr_in*>(&ss);
        sa4->sin_family = AF_INET;
        sa4->sin_addr = deserialize<in_addr>(begin, end);
    } else if (addr_size == sizeof(in6_addr)) {
        auto sa6 = reinterpret_cast<sockaddr_in6*>(&ss);
        sa6->sin6_family = AF_INET6;
        sa6->sin6_addr = deserialize<in6_addr>(begin, end);
    } else {
        throw std::runtime_error("ServiceAnnouncement parse error.");
    }
}

bool
IpServiceAnnouncement::storePolicy(InfoHash, std::shared_ptr<Value>& v, InfoHash, const sockaddr* from, socklen_t fromlen)
{
    IpServiceAnnouncement request {};
    request.unpackBlob(v->data);
    if (request.getPort() == 0)
        return false;
    IpServiceAnnouncement sa_addr {from, fromlen};
    sa_addr.setPort(request.getPort());
    // argument v is modified (not the value).
    v = std::make_shared<Value>(IpServiceAnnouncement::TYPE, sa_addr, v->id);
    return true;
}

const ValueType IpServiceAnnouncement::TYPE = {2, "Internet Service Announcement", std::chrono::minutes(15), IpServiceAnnouncement::storePolicy, ValueType::DEFAULT_EDIT_POLICY};

std::ostream& operator<< (std::ostream& s, const DhtMessage& v)
{
    s << "DhtMessage: service " << v.service << std::endl;
    s.write((const char*)v.message.data(), v.message.size());
    return s;
}

void
DhtMessage::pack(Blob& res) const
{
    serialize<int16_t>(service, res);
    serialize<Blob>(message, res);
}

void
DhtMessage::unpack(Blob::const_iterator& begin, Blob::const_iterator& end)
{
    service = deserialize<int16_t>(begin, end);
    message = deserialize<Blob>(begin, end);
}

bool
DhtMessage::storePolicy(InfoHash, std::shared_ptr<Value>& v, InfoHash, const sockaddr* from, socklen_t fromlen)
{
    DhtMessage request {v->data};
    if (request.service == 0)
        return false;
    return true;
}

const ValueType DhtMessage::TYPE = {1, "DHT message", std::chrono::minutes(5), DhtMessage::storePolicy, ValueType::DEFAULT_EDIT_POLICY};

}
