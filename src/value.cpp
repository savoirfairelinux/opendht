/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "value.h"

#include "default_types.h"
#include "securedht.h" // print certificate ID

#ifdef OPENDHT_JSONCPP
#include "base64.h"
#endif


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
    s << "Value[id:" << std::hex << v.id << std::dec << ' ';
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
#ifdef OPENDHT_LOG_CRT_ID
            try {
                auto h = crypto::Certificate(v.data).getPublicKey().getLongId();
                s << " with ID " << h;
            } catch (const std::exception& e) {
                s << " (invalid)";
            }
#endif
        } else {
            if (v.user_type.empty())
                s << "data:";
            else
                s << "data(" << v.user_type << "):";
            if (v.user_type == "text/plain") {
                s << '"';
                s.write((const char*)v.data.data(), v.data.size());
                s << '"';
            } else if (v.data.size() < 1024) {
                s << std::hex;
                for (auto i : v.data)
                    s << std::setfill('0') << std::setw(2) << (unsigned)i;
                s << std::dec;
            } else {
                s << v.data.size() << " bytes";
            }
        }
    }
    s << ']';
    s.flags(flags);
    return s;
}

const ValueType ValueType::USER_DATA = {0, "User Data"};

bool
ValueType::DEFAULT_STORE_POLICY(InfoHash, const std::shared_ptr<Value>& v, const InfoHash&, const SockAddr&)
{
    return v->size() <= MAX_VALUE_SIZE;
}

size_t
Value::size() const
{
    return cypher.size() + data.size() + signature.size()  + user_type.size();
}

void
Value::msgpack_unpack(const msgpack::object& o)
{
    if (o.type != msgpack::type::MAP or o.via.map.size < 2)
        throw msgpack::type_error();

    if (auto rid = findMapValue(o, VALUE_KEY_ID)) {
        id = rid->as<Id>();
    } else
        throw msgpack::type_error();

    if (auto rdat = findMapValue(o, VALUE_KEY_DAT)) {
        msgpack_unpack_body(*rdat);
    } else
        throw msgpack::type_error();

    if (auto rprio = findMapValue(o, VALUE_KEY_PRIO)) {
        priority = rprio->as<unsigned>();
    }
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
        auto rbody = findMapValue(o, VALUE_KEY_BODY);
        if (not rbody)
            throw msgpack::type_error();

        if (auto rdata = findMapValue(*rbody, VALUE_KEY_DATA)) {
            data = unpackBlob(*rdata);
        } else
            throw msgpack::type_error();

        if (auto rtype = findMapValue(*rbody, VALUE_KEY_TYPE)) {
            type = rtype->as<ValueType::Id>();
        } else
            throw msgpack::type_error();

        if (auto rutype = findMapValue(*rbody, VALUE_KEY_USERTYPE)) {
            user_type = rutype->as<std::string>();
        }

        if (auto rowner = findMapValue(*rbody, VALUE_KEY_OWNER)) {
            if (auto rseq = findMapValue(*rbody, VALUE_KEY_SEQ))
                seq = rseq->as<decltype(seq)>();
            else
                throw msgpack::type_error();
            crypto::PublicKey new_owner;
            new_owner.msgpack_unpack(*rowner);
            owner = std::make_shared<const crypto::PublicKey>(std::move(new_owner));
            if (auto rrecipient = findMapValue(*rbody, VALUE_KEY_TO)) {
                recipient = rrecipient->as<InfoHash>();
            }

            if (auto rsig = findMapValue(o, VALUE_KEY_SIGNATURE)) {
                signature = unpackBlob(*rsig);
            } else
                throw msgpack::type_error();
        }
    }
}

#ifdef OPENDHT_JSONCPP
Value::Value(const Json::Value& json)
{
    id = Value::Id(unpackId(json, VALUE_KEY_ID));
    const auto& jcypher = json["cypher"];
    if (jcypher.isString())
        cypher = base64_decode(jcypher.asString());
    const auto& jsig = json[VALUE_KEY_SIGNATURE];
    if (jsig.isString())
        signature = base64_decode(jsig.asString());
    const auto& jseq = json[VALUE_KEY_SEQ];
    if (!jseq.isNull())
        seq = jseq.asInt();
    const auto& jowner = json[VALUE_KEY_OWNER];
    if (jowner.isString()) {
        auto ownerStr = jowner.asString();
        auto ownerBlob = std::vector<unsigned char>(ownerStr.begin(), ownerStr.end());
        owner = std::make_shared<const crypto::PublicKey>(ownerBlob);
    }
    const auto& jto = json[VALUE_KEY_TO];
    if (jto.isString())
        recipient = InfoHash(jto.asString());
    const auto& jtype = json[VALUE_KEY_TYPE];
    if (!jtype.isNull())
        type = jtype.asInt();
    const auto& jdata = json[VALUE_KEY_DATA];
    if (jdata.isString())
        data = base64_decode(jdata.asString());
    const auto& jutype = json[VALUE_KEY_USERTYPE];
    if (jutype.isString())
        user_type = jutype.asString();
    const auto& jprio = json["prio"];
    if (jprio.isIntegral())
        priority = jprio.asUInt();
}

Json::Value
Value::toJson() const
{
    Json::Value val;
    val[VALUE_KEY_ID] = std::to_string(id);
    if (isEncrypted()) {
        val["cypher"] = base64_encode(cypher);
    } else {
        if (isSigned())
            val[VALUE_KEY_SIGNATURE] = base64_encode(signature);
        bool has_owner = owner && *owner;
        if (has_owner) { // isSigned
            val[VALUE_KEY_SEQ] = seq;
            val[VALUE_KEY_OWNER] = owner->toString();
            if (recipient)
                val[VALUE_KEY_TO] = recipient.toString();
        }
        val[VALUE_KEY_TYPE] = type;
        val[VALUE_KEY_DATA] = base64_encode(data);
        if (not user_type.empty())
            val[VALUE_KEY_USERTYPE] = user_type;
    }
    if (priority)
        val["prio"] = priority;
    return val;
}

uint64_t
unpackId(const Json::Value& json, const std::string& key) {
    uint64_t ret = 0;
    try {
        const auto& t = json[key];
        if (t.isString()) {
            ret = std::stoull(t.asString());
        } else {
            ret = t.asLargestUInt();
        }
    } catch (...) {}
    return ret;
}
#endif

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
        return {};
    }
}

FieldValueIndex::FieldValueIndex(const Value& v, const Select& s)
{
    if (not s.empty()) {
        auto selection = s.getSelection();
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
            os << "Owner:" << v->second.getHash();
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
    auto first = std::min(str.size(), str.find_first_not_of(' '));
    auto last = std::min(str.size(), str.find_last_not_of(' '));
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
            if (token == VALUE_KEY_ID)
                field(Value::Field::Id);
            else if (token == "value_type")
                field(Value::Field::ValueType);
            else if (token == "owner_pk")
                field(Value::Field::OwnerPk);
            if (token == VALUE_KEY_SEQ)
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
                if (field_str == VALUE_KEY_ID)
                    id(v);
                else if (field_str == "value_type")
                    valueType(v);
                else if (field_str == "owner_pk")
                    owner(InfoHash(s));
                else if (field_str == VALUE_KEY_SEQ)
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
        if (std::find_if(qfds.begin(), qfds.end(), [&fd](T& _vfd) { return fd == _vfd; }) == qfds.end())
            return false;
    }
    return true;
}

bool Select::isSatisfiedBy(const Select& os) const {
    /* empty, means all values are selected. */
    return fieldSelection_.empty() ?
        os.fieldSelection_.empty() :
        subset(fieldSelection_, os.fieldSelection_);
}

bool Where::isSatisfiedBy(const Where& ow) const {
    return subset(ow.filters_, filters_);
}

bool Query::isSatisfiedBy(const Query& q) const {
    return none or (where.isSatisfiedBy(q.where) and select.isSatisfiedBy(q.select));
}

std::ostream& operator<<(std::ostream& s, const dht::Select& select) {
    s << "SELECT ";
    if (select.fieldSelection_.empty())
        s << '*';
    else
        for (auto fs = select.fieldSelection_.begin(); fs != select.fieldSelection_.end();) {
            switch (*fs) {
            case Value::Field::Id:
                s << VALUE_KEY_ID;
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
                s << VALUE_KEY_SEQ;
                break;
            default:
                break;
            }
            if (++fs != select.fieldSelection_.end())
                s << ',';
        }
    return s;
}

std::ostream& operator<<(std::ostream& s, const dht::Where& where) {
    if (not where.filters_.empty()) {
        s << "WHERE ";
        for (auto f = where.filters_.begin() ; f != where.filters_.end() ; ++f) {
            switch (f->getField()) {
            case Value::Field::Id:
                s << VALUE_KEY_ID << '=' << f->getInt();
                break;
            case Value::Field::ValueType:
                s << "value_type=" << f->getInt();
                break;
            case Value::Field::OwnerPk:
                s << "owner_pk_hash=" << f->getHash();
                break;
            case Value::Field::SeqNum:
                s << VALUE_KEY_SEQ << '=' << f->getInt();
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
