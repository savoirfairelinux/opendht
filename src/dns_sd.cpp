// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "dns_sd.h"

#include <algorithm>
#include <charconv>
#include <map>

namespace dht::mdns::dns_sd {
namespace {

constexpr std::string_view SERVICE_NAME = "_opendht._udp.local.";
constexpr std::string_view SERVICE_SUFFIX = "._opendht._udp.local.";
constexpr std::string_view HOST_SUFFIX = ".local.";

std::vector<uint8_t>
txtString(std::string value)
{
    return {value.begin(), value.end()};
}

std::string
asciiLower(std::string_view value)
{
    std::string lower;
    lower.reserve(value.size());
    for (const auto character : value) {
        if (character >= 'A' and character <= 'Z')
            lower.push_back(static_cast<char>(character + ('a' - 'A')));
        else
            lower.push_back(character);
    }
    return lower;
}

void
validateService(const Service& service)
{
    if (not service.nodeId)
        throw ParseError("DNS-SD service requires a node ID");
    if (service.port == 0)
        throw ParseError("DNS-SD service requires a port");
    if (service.addresses.empty())
        throw ParseError("DNS-SD service requires an address");
}

Message
makeAdvertisement(const Service& service, uint32_t serviceTtl, uint32_t hostTtl)
{
    validateService(service);
    const auto instance = instanceName(service.nodeId);
    const auto host = hostName(service.nodeId);

    Message message;
    message.response = true;
    message.authoritative = true;
    message.answers.push_back(
        {serviceName(), Type::PTR, CLASS_IN, false, serviceTtl, PtrData {instance}});
    message.additionals.push_back(
        {instance, Type::SRV, CLASS_IN, true, hostTtl, SrvData {0, 0, service.port, host}});

    TxtData txt;
    txt.strings.emplace_back(txtString("txtvers=1"));
    txt.strings.emplace_back(txtString("id=" + service.nodeId.toString()));
    txt.strings.emplace_back(txtString("net=" + std::to_string(service.network)));
    message.additionals.push_back({instance, Type::TXT, CLASS_IN, true, serviceTtl, std::move(txt)});

    for (const auto& address : service.addresses) {
        std::visit(
            [&](const auto& data) {
                using Data = std::decay_t<decltype(data)>;
                constexpr auto type = std::is_same_v<Data, AData> ? Type::A : Type::AAAA;
                message.additionals.push_back({host, type, CLASS_IN, true, hostTtl, data});
            },
            address);
    }
    return message;
}

std::optional<InfoHash>
nodeIdFromInstance(const Name& instance)
{
    const auto& labels = instance.labels();
    const auto service = serviceName();
    const auto& serviceLabels = service.labels();
    if (labels.size() != serviceLabels.size() + 1
        or not std::equal(labels.begin() + 1, labels.end(), serviceLabels.begin(), serviceLabels.end()))
        return {};
    if (labels.front().size() != 40)
        return {};
    const InfoHash nodeId {labels.front()};
    if (not nodeId)
        return {};
    return nodeId;
}

struct TxtValues
{
    InfoHash nodeId;
    NetId network {};
};

std::optional<TxtValues>
parseTxt(const TxtData& txt)
{
    std::map<std::string, std::string> values;
    for (const auto& raw : txt.strings) {
        const std::string_view string {reinterpret_cast<const char*>(raw.data()), raw.size()};
        const auto separator = string.find('=');
        if (separator == std::string_view::npos or separator == 0)
            continue;
        const auto keyView = string.substr(0, separator);
        if (std::any_of(keyView.begin(), keyView.end(), [](char value) {
                return value < 0x20 or value > 0x7e or value == '=';
            }))
            continue;
        const auto key = asciiLower(keyView);
        if ((key == "txtvers" or key == "id" or key == "net") and values.count(key))
            return {};
        values.emplace(key, std::string(string.substr(separator + 1)));
    }

    if (values.size() < 3 or values["txtvers"] != "1" or values["id"].size() != 40)
        return {};
    TxtValues parsed;
    parsed.nodeId = InfoHash {values["id"]};
    if (not parsed.nodeId)
        return {};
    const auto& network = values["net"];
    const auto result = std::from_chars(network.data(), network.data() + network.size(), parsed.network);
    if (result.ec != std::errc {} or result.ptr != network.data() + network.size())
        return {};
    return parsed;
}

template<typename Callback>
void
forEachRecord(const Message& message, Callback&& callback)
{
    for (const auto& record : message.answers)
        callback(record);
    for (const auto& record : message.authorities)
        callback(record);
    for (const auto& record : message.additionals)
        callback(record);
}

bool
matches(const Question& question, const ResourceRecord& record)
{
    return question.name == record.name and (question.type == Type::ANY or question.type == record.type)
        and (question.classCode == CLASS_ANY or question.classCode == record.classCode);
}

bool
sameRecord(const ResourceRecord& lhs, const ResourceRecord& rhs)
{
    return lhs.name == rhs.name and lhs.type == rhs.type and lhs.classCode == rhs.classCode
        and lhs.data == rhs.data;
}

bool
isKnownAnswer(const Message& query, const ResourceRecord& record)
{
    return std::any_of(query.answers.begin(), query.answers.end(), [&](const ResourceRecord& known) {
        return sameRecord(known, record) and known.ttl > record.ttl / 2;
    });
}

} // namespace

class Cache::Impl
{
public:
    explicit Impl(Now now)
        : now_(std::move(now))
    {}

    struct Entry
    {
        ResourceRecord record;
        Clock::time_point expires;
    };

    std::vector<Service> update(const Message& message)
    {
        expire();
        std::vector<const ResourceRecord*> records;
        forEachRecord(message, [&](const ResourceRecord& record) { records.push_back(&record); });

        std::vector<const ResourceRecord*> flushed;
        for (const auto* record : records) {
            if (not record->cacheFlush)
                continue;
            const auto alreadyFlushed = std::any_of(flushed.begin(), flushed.end(), [&](const ResourceRecord* other) {
                return other->name == record->name
                    and other->type == record->type and other->classCode == record->classCode;
            });
            if (not alreadyFlushed) {
                flushed.push_back(record);
                entries_.erase(
                    std::remove_if(entries_.begin(), entries_.end(), [&](const Entry& entry) {
                        return entry.record.name == record->name and entry.record.type == record->type
                            and entry.record.classCode == record->classCode;
                    }),
                    entries_.end());
            }
        }

        for (const auto* record : records) {
            if (record->ttl == 0) {
                entries_.erase(
                    std::remove_if(entries_.begin(), entries_.end(), [&](const Entry& entry) {
                        return sameRecord(entry.record, *record);
                    }),
                    entries_.end());
                continue;
            }
            const auto expires = now_() + std::chrono::seconds(record->ttl);
            const auto existing = std::find_if(entries_.begin(), entries_.end(), [&](const Entry& entry) {
                return sameRecord(entry.record, *record);
            });
            if (existing == entries_.end())
                entries_.push_back({*record, expires});
            else {
                existing->record = *record;
                existing->expires = expires;
            }
        }

        auto current = collect();
        std::vector<Service> discovered;
        for (const auto& service : current) {
            if (std::find_if(emitted_.begin(), emitted_.end(), [&](const Service& previous) {
                    return equal(previous, service);
                }) == emitted_.end())
                discovered.push_back(service);
        }
        emitted_ = std::move(current);
        return discovered;
    }

    std::vector<Service> services()
    {
        expire();
        auto current = collect();
        emitted_ = current;
        return current;
    }

    void clear()
    {
        entries_.clear();
        emitted_.clear();
    }

private:
    static bool equal(const Service& lhs, const Service& rhs)
    {
        return lhs.nodeId == rhs.nodeId and lhs.network == rhs.network and lhs.port == rhs.port
            and lhs.addresses == rhs.addresses;
    }

    void expire()
    {
        const auto now = now_();
        entries_.erase(std::remove_if(entries_.begin(), entries_.end(), [&](const Entry& entry) {
                           return entry.expires <= now;
                       }),
                       entries_.end());
    }

    std::vector<Service> collect() const
    {
        std::vector<Service> result;
        for (const auto& entry : entries_) {
            if (entry.record.type != Type::PTR or entry.record.classCode != CLASS_IN
                or entry.record.name != serviceName())
                continue;
            const auto* ptr = std::get_if<PtrData>(&entry.record.data);
            if (not ptr)
                continue;

            Message message;
            message.response = true;
            message.answers.push_back(entry.record);
            for (const auto& additional : entries_) {
                if (&additional != &entry and additional.record.type != Type::PTR)
                    message.additionals.push_back(additional.record);
            }
            const auto service = resolve(message);
            if (service and std::none_of(result.begin(), result.end(), [&](const Service& existing) {
                    return equal(existing, *service);
                }))
                result.push_back(*service);
        }
        return result;
    }

    Now now_;
    std::vector<Entry> entries_;
    std::vector<Service> emitted_;
};

Cache::Cache(Now now)
    : impl_(std::make_unique<Impl>(std::move(now)))
{}

Cache::~Cache() = default;
Cache::Cache(Cache&&) noexcept = default;
Cache& Cache::operator=(Cache&&) noexcept = default;

std::vector<Service>
Cache::update(const Message& message)
{
    return impl_->update(message);
}

std::vector<Service>
Cache::services()
{
    return impl_->services();
}

void
Cache::clear()
{
    impl_->clear();
}

Name
serviceName()
{
    return Name::fromString(SERVICE_NAME);
}

Name
instanceName(const InfoHash& nodeId)
{
    if (not nodeId)
        throw ParseError("DNS-SD instance requires a node ID");
    return Name::fromString(nodeId.toString() + std::string(SERVICE_SUFFIX));
}

Name
hostName(const InfoHash& nodeId)
{
    if (not nodeId)
        throw ParseError("mDNS host requires a node ID");
    return Name::fromString(nodeId.toString() + std::string(HOST_SUFFIX));
}

Message
announcement(const Service& service)
{
    return makeAdvertisement(service, SERVICE_RECORD_TTL, HOST_RECORD_TTL);
}

Message
goodbye(const Service& service)
{
    return makeAdvertisement(service, 0, 0);
}

Message
browseQuery()
{
    Message query;
    query.questions.push_back({serviceName(), Type::PTR, CLASS_IN, false});
    return query;
}

std::optional<Message>
respond(const Message& query, const Service& service)
{
    if (query.response)
        return {};

    const auto advertisement = announcement(service);
    Message response;
    response.id = query.id;
    response.response = true;
    response.authoritative = true;

    auto addMatching = [&](const ResourceRecord& record) {
        const auto question = std::find_if(query.questions.begin(), query.questions.end(), [&](const Question& q) {
            return matches(q, record);
        });
        if (question == query.questions.end() or (not question->unicastResponse and isKnownAnswer(query, record)))
            return;
        if (std::find_if(response.answers.begin(), response.answers.end(), [&](const ResourceRecord& answer) {
                return sameRecord(answer, record);
            }) == response.answers.end())
            response.answers.push_back(record);
    };

    for (const auto& record : advertisement.answers)
        addMatching(record);
    for (const auto& record : advertisement.additionals)
        addMatching(record);
    if (response.answers.empty())
        return {};

    response.additionals = advertisement.additionals;
    response.additionals.erase(
        std::remove_if(response.additionals.begin(), response.additionals.end(), [&](const ResourceRecord& record) {
            return std::any_of(response.answers.begin(), response.answers.end(), [&](const ResourceRecord& answer) {
                return sameRecord(answer, record);
            });
        }),
        response.additionals.end());
    return response;
}

std::optional<Service>
resolve(const Message& message)
{
    std::vector<Name> instances;
    forEachRecord(message, [&](const ResourceRecord& record) {
        if (record.type == Type::PTR and record.classCode == CLASS_IN and record.name == serviceName()) {
            if (const auto ptr = std::get_if<PtrData>(&record.data))
                instances.push_back(ptr->name);
        }
    });
    if (instances.size() != 1)
        return {};

    const auto nodeId = nodeIdFromInstance(instances.front());
    if (not nodeId)
        return {};
    const auto expectedHost = hostName(*nodeId);
    const SrvData* srv = nullptr;
    const TxtData* txt = nullptr;
    std::vector<AddressData> addresses;
    auto duplicate = false;

    forEachRecord(message, [&](const ResourceRecord& record) {
        if (record.classCode != CLASS_IN)
            return;
        if (record.name == instances.front()) {
            if (record.type == Type::SRV) {
                if (srv)
                    duplicate = true;
                else
                    srv = std::get_if<SrvData>(&record.data);
            } else if (record.type == Type::TXT) {
                if (txt)
                    duplicate = true;
                else
                    txt = std::get_if<TxtData>(&record.data);
            }
        } else if (record.name == expectedHost) {
            if (record.type == Type::A) {
                if (const auto data = std::get_if<AData>(&record.data))
                    addresses.emplace_back(*data);
            } else if (record.type == Type::AAAA) {
                if (const auto data = std::get_if<AaaaData>(&record.data))
                    addresses.emplace_back(*data);
            }
        }
    });

    if (duplicate or not srv or not txt or srv->priority != 0 or srv->weight != 0 or srv->port == 0
        or srv->target != expectedHost or addresses.empty())
        return {};
    const auto txtValues = parseTxt(*txt);
    if (not txtValues or txtValues->nodeId != *nodeId)
        return {};

    Service service;
    service.nodeId = *nodeId;
    service.network = txtValues->network;
    service.port = srv->port;
    for (auto& address : addresses) {
        if (std::find(service.addresses.begin(), service.addresses.end(), address) == service.addresses.end())
            service.addresses.emplace_back(std::move(address));
    }
    return service;
}

} // namespace dht::mdns::dns_sd