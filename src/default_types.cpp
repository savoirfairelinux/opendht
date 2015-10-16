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

#include "default_types.h"

namespace dht {

std::ostream& operator<< (std::ostream& s, const DhtMessage& v)
{
    s << "DhtMessage: service " << v.service << std::endl;
    return s;
}

bool
DhtMessage::storePolicy(InfoHash, std::shared_ptr<Value>& v, InfoHash, const sockaddr*, socklen_t)
{
    try {
        auto msg = unpackMsg<DhtMessage>(v->data);
        if (msg.service.empty())
            return false;
    } catch (const std::exception& e) {}
    return true;
}

Value::Filter
DhtMessage::ServiceFilter(std::string s)
{
    return Value::Filter::chain(
        Value::TypeFilter(TYPE),
        [s](const Value& v) {
            try {
                return unpackMsg<DhtMessage>(v.data).service == s;
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

bool
IpServiceAnnouncement::storePolicy(InfoHash, std::shared_ptr<Value>& v, InfoHash, const sockaddr* from, socklen_t fromlen)
{
    try {
        auto msg = unpackMsg<IpServiceAnnouncement>(v->data);
        if (msg.getPort() == 0)
            return false;
        IpServiceAnnouncement sa_addr {from, fromlen};
        sa_addr.setPort(msg.getPort());
        // argument v is modified (not the value).
        v = std::make_shared<Value>(IpServiceAnnouncement::TYPE, sa_addr, v->id);
        return true;
    } catch (const std::exception& e) {}
    return false;
}

const ValueType DhtMessage::TYPE = {1, "DHT message", std::chrono::minutes(5), DhtMessage::storePolicy, ValueType::DEFAULT_EDIT_POLICY};
const ValueType IpServiceAnnouncement::TYPE = {2, "Internet Service Announcement", std::chrono::minutes(15), IpServiceAnnouncement::storePolicy, ValueType::DEFAULT_EDIT_POLICY};
const ValueType ImMessage::TYPE = {3, "IM message", std::chrono::minutes(5)};
const ValueType TrustRequest::TYPE = {4, "Certificate trust request", std::chrono::hours(24*7)};
const ValueType IceCandidates::TYPE = {5, "ICE candidates", std::chrono::minutes(5)};


const std::array<std::reference_wrapper<const ValueType>, 5>
DEFAULT_TYPES
{
    ValueType::USER_DATA,
    DhtMessage::TYPE,
    ImMessage::TYPE,
    IceCandidates::TYPE,
    TrustRequest::TYPE
};

const std::array<std::reference_wrapper<const ValueType>, 1>
DEFAULT_INSECURE_TYPES
{
    IpServiceAnnouncement::TYPE
};

}
