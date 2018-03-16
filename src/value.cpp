/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
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

#include "value.h"

#include "default_types.h"
#include "securedht.h" // print certificate ID

#if OPENDHT_PROXY_SERVER || OPENDHT_PROXY_CLIENT
#include "base64.h"
#endif //OPENDHT_PROXY_SERVER


namespace dht {

const std::string Query::QUERY_PARSE_ERROR {"Error parsing query."};

Value::Filter bindFilterRaw(FilterRaw raw_filter, void* user_data) {
    if (not raw_filter) return {};
    return [=](const Value& value) {
        return raw_filter(value, user_data);
    };
}

std::ostream& operator<< (std::ostream& s, const Value& v)
{
    auto flags(s.flags());
    s << "Value[id:" << std::hex << v.id << std::dec << " ";
    if (v.isEncrypted())
        s << "encrypted ";
    else if (v.isSigned()) {
        s << "signed (v" << v.seq << ") ";
        if (v.recipient)
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
                s << std::setfill('0') << std::setw(2) << (unsigned)v.data[i];
            s << std::dec;
        }
    }
    s << "]";
    s.flags(flags);
    return s;
}

const ValueType ValueType::USER_DATA = {0, "User Data"};

bool
ValueType::DEFAULT_STORE_POLICY(InfoHash, std::shared_ptr<Value>& v, const InfoHash&, const SockAddr&)
{
    return v->size() <= MAX_VALUE_SIZE;
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
            crypto::PublicKey new_owner;
            new_owner.msgpack_unpack(*rowner);
            owner = std::make_shared<const crypto::PublicKey>(std::move(new_owner));
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

#if OPENDHT_PROXY_SERVER || OPENDHT_PROXY_CLIENT
Value::Value(Json::Value& json)
{
   try {
       if (json.isMember("id")) {
           if (json["id"].isString()) {
               id = Value::Id(std::stoull(json["id"].asString()));
           } else {
               id = Value::Id(json["id"].asLargestUInt());
           }
       }
   } catch (...) { }
   if (json.isMember("cypher")) {
       auto cypherStr = json["cypher"].asString();
       cypherStr = base64_decode(cypherStr);
       cypher = std::vector<unsigned char>(cypherStr.begin(), cypherStr.end());
   }
   if (json.isMember("sig")) {
       auto sigStr = json["sig"].asString();
       sigStr = base64_decode(sigStr);
       signature = std::vector<unsigned char>(sigStr.begin(), sigStr.end());
   }
   if (json.isMember("seq"))
       seq = json["seq"].asInt();
   if (json.isMember("owner")) {
       auto ownerStr = json["owner"].asString();
       auto ownerBlob = std::vector<unsigned char>(ownerStr.begin(), ownerStr.end());
       owner = std::make_shared<const crypto::PublicKey>(ownerBlob);
   }
   if (json.isMember("to")) {
       auto toStr = json["to"].asString();
       recipient = InfoHash(toStr);
   }
   if (json.isMember("type"))
       type = json["type"].asInt();
   if (json.isMember("data")){
       auto dataStr = json["data"].asString();
       dataStr = base64_decode(dataStr);
       data = std::vector<unsigned char>(dataStr.begin(), dataStr.end());
   }
   if (json.isMember("utype"))
       user_type = json["utype"].asString();
}

Json::Value
Value::toJson() const
{
    Json::Value val;
    val["id"] = std::to_string(id);
    if (isEncrypted()) {
        val["cypher"] = base64_encode(cypher);
    } else {
        if (isSigned())
            val["sig"] = base64_encode(signature);
        bool has_owner = owner && *owner;
        if (has_owner) { // isSigned
            val["seq"] = seq;
            val["owner"] = owner->toString();
            if (recipient)
                val["to"] = recipient.toString();
        }
        val["type"] = type;
        val["data"] = base64_encode(data);
        if (not user_type.empty())
            val["utype"] = user_type;
    }
    return val;
}
#endif //OPENDHT_PROXY_SERVER

bool
FieldValue::operator==(const FieldValue& vfd) const
{
    if (field != vfd.field)
        return false;
    switch (field) {
        case Value::Field::Id:
        case Value::Field::ValueType:
        case Value::Field::SeqNum:
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
FieldValue::getLocalFilter() const
{
    switch (field) {
        case Value::Field::Id:
            return Value::IdFilter(intValue);
        case Value::Field::ValueType:
            return Value::TypeFilter(intValue);
        case Value::Field::OwnerPk:
            return Value::OwnerFilter(hashValue);
        case Value::Field::SeqNum:
            return Value::SeqNumFilter(intValue);
        case Value::Field::UserType:
            return Value::UserTypeFilter(std::string {blobValue.begin(), blobValue.end()});
        default:
            return Value::AllFilter();
    }
}

FieldValueIndex::FieldValueIndex(const Value& v, Select s)
{
    auto selection = s.getSelection();
    if (not selection.empty()) {
        std::transform(selection.begin(), selection.end(), std::inserter(index, index.end()),
            [](const std::set<Value::Field>::value_type& f) {
                return std::make_pair(f, FieldValue {});
        });
    } else {
        index.clear();
        for (size_t f = 1 ; f < static_cast<int>(Value::Field::COUNT) ; ++f)
            index[static_cast<Value::Field>(f)] = {};
    }
    for (const auto& fvp : index) {
        const auto& f = fvp.first;
        switch (f) {
            case Value::Field::Id:
                index[f] = {f, v.id};
                break;
            case Value::Field::ValueType:
                index[f] = {f, v.type};
                break;
            case Value::Field::OwnerPk:
                index[f] = {f, v.owner ? v.owner->getId() : InfoHash() };
                break;
            case Value::Field::SeqNum:
                index[f] = {f, v.seq};
                break;
            case Value::Field::UserType:
                index[f] = {f, Blob {v.user_type.begin(), v.user_type.end()}};
                break;
            default:
                break;
        }
    }
}

bool FieldValueIndex::containedIn(const FieldValueIndex& other) const {
    if (index.size() > other.index.size())
        return false;
    for (const auto& field : index) {
        auto other_field = other.index.find(field.first);
        if (other_field == other.index.end())
            return false;
    }
    return true;
}

std::ostream& operator<<(std::ostream& os, const FieldValueIndex& fvi) {
    os << "Index[";
    for (auto v = fvi.index.begin(); v != fvi.index.end(); ++v) {
        switch (v->first) {
            case Value::Field::Id: {
                auto flags(os.flags());
                os << "Id:" << std::hex << v->second.getInt();
                os.flags(flags);
                break;
            }
            case Value::Field::ValueType:
                os << "ValueType:" << v->second.getInt();
                break;
            case Value::Field::OwnerPk:
                os << "Owner:" << v->second.getHash().toString();
                break;
            case Value::Field::SeqNum:
                os << "Seq:" << v->second.getInt();
                break;
            case Value::Field::UserType: {
                auto ut = v->second.getBlob();
                os << "UserType:" << std::string(ut.begin(), ut.end());
                break;
            }
            default:
                break;
        }
        os << (std::next(v) != fvi.index.end() ? "," : "");
    }
    return os << "]";
}

void
FieldValueIndex::msgpack_unpack_fields(const std::set<Value::Field>& fields, const msgpack::object& o, unsigned offset)
{
    index.clear();

    unsigned j = 0;
    for (const auto& field : fields) {
        auto& field_value = o.via.array.ptr[offset+(j++)];
        switch (field) {
            case Value::Field::Id:
            case Value::Field::ValueType:
            case Value::Field::SeqNum:
                index[field] = FieldValue(field, field_value.as<uint64_t>());
                break;
            case Value::Field::OwnerPk:
                index[field] = FieldValue(field, field_value.as<InfoHash>());
                break;
            case Value::Field::UserType:
                index[field] = FieldValue(field, field_value.as<Blob>());
                break;
            default:
                throw msgpack::type_error();
        }
    }
}

void trim_str(std::string& str) {
    auto first = std::min(str.size(), str.find_first_not_of(" "));
    auto last = std::min(str.size(), str.find_last_not_of(" "));
    str = str.substr(first, last - first + 1);
}

Select::Select(const std::string& q_str) {
    std::istringstream q_iss {q_str};
    std::string token {};
    q_iss >> token;

    if (token == "SELECT" or token == "select") {
        q_iss >> token;
        std::istringstream fields {token};

        while (std::getline(fields, token, ',')) {
            trim_str(token);
            if (token == "id")
                field(Value::Field::Id);
            else if (token == "value_type")
                field(Value::Field::ValueType);
            else if (token == "owner_pk")
                field(Value::Field::OwnerPk);
            if (token == "seq")
                field(Value::Field::SeqNum);
            else if (token == "user_type")
                field(Value::Field::UserType);
        }
    }
}

Where::Where(const std::string& q_str) {
    std::istringstream q_iss {q_str};
    std::string token {};
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
                if (not convert
                        and value_str.size() > 1
                        and value_str[0] == '"'
                        and value_str[value_str.size()-1] == '"')
                    s = value_str.substr(1, value_str.size()-2);
                else
                    s = value_str;
                if (field_str == "id")
                    id(v);
                else if (field_str == "value_type")
                    valueType(v);
                else if (field_str == "owner_pk")
                    owner(InfoHash(s));
                else if (field_str == "seq")
                    seq(v);
                else if (field_str == "user_type")
                    userType(s);
                else
                    throw std::invalid_argument(Query::QUERY_PARSE_ERROR + " (WHERE) wrong token near: " + field_str);
            }
        }
    }
}

void
Query::msgpack_unpack(const msgpack::object& o)
{
	if (o.type != msgpack::type::MAP)
		throw msgpack::type_error();

	auto rfilters = findMapValue(o, "w"); /* unpacking filters */
	if (rfilters)
        where.msgpack_unpack(*rfilters);
	else
		throw msgpack::type_error();

	auto rfield_selector = findMapValue(o, "s"); /* unpacking field selectors */
	if (rfield_selector)
        select.msgpack_unpack(*rfield_selector);
	else
		throw msgpack::type_error();
}

template <typename T>
bool subset(std::vector<T> fds, std::vector<T> qfds)
{
    for (auto& fd : fds) {
        auto correspondance = std::find_if(qfds.begin(), qfds.end(), [&fd](T& _vfd) { return fd == _vfd; });
        if (correspondance == qfds.end())
            return false;
    }
    return true;
}

bool Select::isSatisfiedBy(const Select& os) const {
    /* empty, means all values are selected. */
    if (fieldSelection_.empty() and not os.fieldSelection_.empty())
        return false;
    else
        return subset(fieldSelection_, os.fieldSelection_);
}

bool Where::isSatisfiedBy(const Where& ow) const {
    return subset(ow.filters_, filters_);
}

bool Query::isSatisfiedBy(const Query& q) const {
    return none or (where.isSatisfiedBy(q.where) and select.isSatisfiedBy(q.select));
}

std::ostream& operator<<(std::ostream& s, const dht::Select& select) {
    s << "SELECT " << (select.fieldSelection_.empty() ? "*" : "");
    for (auto fs = select.fieldSelection_.begin() ; fs != select.fieldSelection_.end() ; ++fs) {
        switch (*fs) {
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
            case Value::Field::SeqNum:
                s << "seq";
                break;
            default:
                break;
        }
        s << (std::next(fs) != select.fieldSelection_.end() ? "," : "");
    }
    return s;
}

std::ostream& operator<<(std::ostream& s, const dht::Where& where) {
    if (not where.filters_.empty()) {
        s << "WHERE ";
        for (auto f = where.filters_.begin() ; f != where.filters_.end() ; ++f) {
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
                case Value::Field::SeqNum:
                    s << "seq=" << f->getInt();
                    break;
                case Value::Field::UserType: {
                    auto b = f->getBlob();
                    s << "user_type=" << std::string {b.begin(), b.end()};
                    break;
                }
                default:
                    break;
            }
            s << (std::next(f) != where.filters_.end() ? "," : "");
        }
    }
    return s;
}


}
