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

#include "default_types.h"

namespace dht {

std::ostream& operator<< (std::ostream& s, const DhtMessage& v)
{
    s << "DhtMessage: service " << v.service << std::endl;
    return s;
}

void
DhtMessage::pack(Blob& res) const
{
    serialize<std::string>(service, res);
    serialize<Blob>(data, res);
}

void
DhtMessage::unpack(Blob::const_iterator& begin, Blob::const_iterator& end)
{
    service = deserialize<std::string>(begin, end);
    data = deserialize<Blob>(begin, end);
}

bool
DhtMessage::storePolicy(InfoHash, std::shared_ptr<Value>& v, InfoHash, const sockaddr*, socklen_t)
{
    DhtMessage request;
    try {
    	request.unpackBlob(v->data);
    } catch (const std::exception& e) {}
    if (request.service.empty())
        return false;
    return true;
}

Value::Filter
DhtMessage::ServiceFilter(std::string s)
{
    return Value::Filter::chain(
        Value::TypeFilter(TYPE),
        [s](const Value& v) {
            try {
                auto b = v.data.cbegin(), e = v.data.cend();
                auto service = deserialize<std::string>(b, e);
                return service == s;
            } catch (const std::exception& e) {
                return false;
            }
        }
    );
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

const ValueType DhtMessage::TYPE = {1, "DHT message", std::chrono::minutes(5), DhtMessage::storePolicy, ValueType::DEFAULT_EDIT_POLICY};
const ValueType IpServiceAnnouncement::TYPE = {2, "Internet Service Announcement", std::chrono::minutes(15), IpServiceAnnouncement::storePolicy, ValueType::DEFAULT_EDIT_POLICY};
const ValueType ImMessage::TYPE = {3, "IM message", std::chrono::minutes(5)};
const ValueType ContactInvite::TYPE = {4, "Service contact invitation", std::chrono::hours(24*7)};
const ValueType IceCandidates::TYPE = {5, "ICE candidates", std::chrono::minutes(5)};

}
