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

#include "default_types.h"

namespace dht {

std::ostream& operator<< (std::ostream& s, const DhtMessage& v)
{
    s << "DhtMessage: service " << v.service << std::endl;
    return s;
}

bool
DhtMessage::storePolicy(InfoHash h, std::shared_ptr<Value>& v, const InfoHash& f, const SockAddr& sa)
{
    try {
        auto msg = unpackMsg<DhtMessage>(v->data);
        if (msg.service.empty())
            return false;
    } catch (const std::exception& e) {}
    return ValueType::DEFAULT_STORE_POLICY(h, v, f, sa);
}

Value::Filter
DhtMessage::ServiceFilter(const std::string& s)
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
    if (v.addr) {
        s << "Peer: ";
        s << "port " << v.getPort();
        char hbuf[NI_MAXHOST];
        if (getnameinfo(v.addr.get(), v.addr.getLength(), hbuf, sizeof(hbuf), nullptr, 0, NI_NUMERICHOST) == 0) {
            s << " addr " << std::string(hbuf, strlen(hbuf));
        }
    }
    return s;
}

bool
IpServiceAnnouncement::storePolicy(InfoHash h, std::shared_ptr<Value>& v, const InfoHash& f, const SockAddr& sa)
{
    try {
        auto msg = unpackMsg<IpServiceAnnouncement>(v->data);
        if (msg.getPort() == 0)
            return false;
        IpServiceAnnouncement sa_addr {sa};
        sa_addr.setPort(msg.getPort());
        // argument v is modified (not the value).
        v = std::make_shared<Value>(IpServiceAnnouncement::TYPE, sa_addr, v->id);
        return ValueType::DEFAULT_STORE_POLICY(h, v, f, sa);
    } catch (const std::exception& e) {}
    return false;
}

const ValueType DhtMessage::TYPE(1, "DHT message", std::chrono::minutes(5), DhtMessage::storePolicy);
const ValueType IpServiceAnnouncement::TYPE(2, "Internet Service Announcement", std::chrono::minutes(15), IpServiceAnnouncement::storePolicy);
const ValueType ImMessage::TYPE = {3, "IM message", std::chrono::minutes(5)};
const ValueType TrustRequest::TYPE = {4, "Certificate trust request", std::chrono::hours(24*7)};
const ValueType IceCandidates::TYPE = {5, "ICE candidates", std::chrono::minutes(1)};

const std::array<std::reference_wrapper<const ValueType>, 5>
DEFAULT_TYPES
{{
    ValueType::USER_DATA,
    DhtMessage::TYPE,
    ImMessage::TYPE,
    IceCandidates::TYPE,
    TrustRequest::TYPE
}};

const std::array<std::reference_wrapper<const ValueType>, 1>
DEFAULT_INSECURE_TYPES
{{
    IpServiceAnnouncement::TYPE
}};

}
