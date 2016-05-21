/*
 *  Copyright (C) 2014-2016 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <sim.desaulniers@gmail.com>
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

#include "value.h"

#include "default_types.h"
#include "securedht.h" // print certificate ID

namespace dht {

const std::string Query::QUERY_PARSE_ERROR {"Error parsing query."};

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

bool
ValueType::DEFAULT_STORE_POLICY(InfoHash, std::shared_ptr<Value>& v, InfoHash, const sockaddr*, socklen_t)
{
    return v->data.size() <= MAX_VALUE_SIZE;
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

size_t
Value::size() const
{
    return cypher.size() + data.size() + signature.size()  + user_type.size();
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
            owner = std::make_shared<crypto::PublicKey>();
            owner->msgpack_unpack(*rowner);
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

void
Value::msgpack_unpack_fields(const std::set<Value::Field>& fields, const msgpack::object& o, unsigned offset)
{
    owner = {};
    recipient = {};
    cypher.clear();
    signature.clear();
    data.clear();
    type = 0;

    unsigned j = 0;
    for (const auto& field : fields) {
        auto& field_value = o.via.array.ptr[offset+(j++)];
        switch (field) {
            case Value::Field::Id:
                id = field_value.as<decltype(id)>();
                break;
            case Value::Field::ValueType:
                type = field_value.as<decltype(type)>();
                break;
            case Value::Field::OwnerPk:
                owner = field_value.as<decltype(owner)>();
                break;
            case Value::Field::UserType:
                user_type = field_value.as<decltype(user_type)>();
                break;
            default:
                throw msgpack::type_error();
        }
    }
}

bool
FilterDescription::operator==(const FilterDescription& vfd) const
{
    if (field != vfd.field)
        return false;
    switch (field) {
        case Value::Field::Id:
        case Value::Field::ValueType:
            return intValue == vfd.intValue;
        case Value::Field::OwnerPk:
            return hashValue == vfd.hashValue;
        case Value::Field::UserType:
            return blobValue == vfd.blobValue;
        case Value::Field::None:
            return true;
        default:
            return false;
    }
}

Value::Filter
FilterDescription::getLocalFilter() const
{
    switch (field) {
        case Value::Field::Id:
            return Value::IdFilter(intValue);
        case Value::Field::ValueType:
            return Value::TypeFilter(intValue);
        case Value::Field::OwnerPk:
            return Value::ownerFilter(hashValue);
        case Value::Field::UserType:
            return Value::userTypeFilter(std::string {blobValue.begin(), blobValue.end()});
        default:
            return Value::AllFilter();
    }
}

Query::Query(std::string&& q_str) {
    auto trim_str = [](std::string& str) {
        auto first = std::min(str.size(), str.find_first_not_of(" "));
        auto last = std::min(str.size(), str.find_last_not_of(" "));
        str = str.substr(first, last - first + 1);
    };

    std::istringstream q_iss {q_str};
    std::string token {};
    q_iss >> token;

    if (token == "SELECT" or token == "select") {
        q_iss >> token;
        std::istringstream fields {token};

        while (std::getline(fields, token, ',')) {
            trim_str(token);
            if (token == "id")
                requireField(Value::Field::Id);
            else if (token == "value_type")
                requireField(Value::Field::ValueType);
            else if (token == "owner_pk")
                requireField(Value::Field::OwnerPk);
            else if (token == "user_type")
                requireField(Value::Field::UserType);
        }
    }

    q_iss >> token;
    if (token == "WHERE" or token == "where") {
        std::getline(q_iss, token);
        std::istringstream restrictions {token};
        while (std::getline(restrictions, token, ',')) {
            trim_str(token);
            std::istringstream eq_ss {token};
            std::string field_str, value_str;
            std::getline(eq_ss, field_str, '=');
            trim_str(field_str);
            std::getline(eq_ss, value_str, '=');
            trim_str(value_str);

            if (not value_str.empty()) {
                uint64_t v = 0;
                std::string s {};
                std::istringstream convert {value_str};
                convert >> v;
                if (value_str.size() > 1 and value_str[0] == '\"' and value_str[value_str.size()-1] == '\"')
                    s = value_str.substr(1, value_str.size()-2);
                else
                    s = value_str;
                if (field_str == "id")
                    setValueId(v);
                else if (field_str == "value_type")
                    setValueType(v);
                else if (field_str == "owner_pk")
                    setOwnerPk(InfoHash(s));
                else if (field_str == "user_type")
                    setUserType(s);
                else
                    throw std::invalid_argument(QUERY_PARSE_ERROR + " (WHERE) wrong token near: " + field_str);
            }
        }
    }
}

void
Query::msgpack_unpack(const msgpack::object& o)
{
	filters_.clear();
	fieldSelectors_.clear();

	if (o.type != msgpack::type::MAP)
		throw msgpack::type_error();

	auto rfilters = findMapValue(o, "w"); /* unpacking filters */
	if (rfilters)
        filters_ = rfilters->as<decltype(filters_)>();
	else
		throw msgpack::type_error();

	auto rfield_selector = findMapValue(o, "s"); /* unpacking field selectors */
	if (rfield_selector)
        fieldSelectors_ = rfield_selector->as<decltype(fieldSelectors_)>();
	else
		throw msgpack::type_error();
}

template <typename T>
bool satisfied(std::vector<T> fds, std::vector<T> qfds)
{
    for (auto& fd : fds) {
        auto correspondance = std::find_if(qfds.begin(), qfds.end(), [&fd](T& _vfd) { return fd == _vfd; });
        if (correspondance == qfds.end())
            return false; /* the query is not satisfied */
    }
    return true;
};

bool
Query::isSatisfiedBy(const Query& q) const
{
    /* empty, means all values are selected. */
    if (fieldSelectors_.empty() and not q.fieldSelectors_.empty())
        return false;
    else
        return satisfied(filters_, q.filters_) and satisfied(fieldSelectors_, q.fieldSelectors_);
}

std::ostream& operator<<(std::ostream& s, const dht::Query& q)
{
    s << "Query[SELECT " << (q.fieldSelectors_.empty() ? "*" : "");
    for (auto fs = q.fieldSelectors_.begin() ; fs != q.fieldSelectors_.end() ; ++fs) {
        switch (fs->getField()) {
            case Value::Field::Id:
                s << "id";
                break;
            case Value::Field::ValueType:
                s << "value_type";
                break;
            case Value::Field::UserType:
                s << "user_type";
                break;
            case Value::Field::OwnerPk:
                s << "owner_public_key";
                break;
            default:
                break;
        }
        s << (std::next(fs) != q.fieldSelectors_.end() ? "," : "");
    }

    if (not q.filters_.empty()){
        s << " WHERE ";
        for (auto f = q.filters_.begin() ; f != q.filters_.end() ; ++f) {
            switch (f->getField()) {
                case Value::Field::Id:
                    s << "id=" << f->getInt();
                    break;
                case Value::Field::ValueType:
                    s << "value_type=" << f->getInt();
                    break;
                case Value::Field::OwnerPk:
                    s << "owner_pk_hash=" << f->getHash().toString();
                    break;
                case Value::Field::UserType: {
                    auto b = f->getBlob();
                    s << "user_type=" << std::string {b.begin(), b.end()};
                    break;
                }
                default:
                    break;
            }
            s << (std::next(f) != q.filters_.end() ? "," : "");
        }
    }
    s << "]";
    return s;
}

}

