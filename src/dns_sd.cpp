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

} // namespace

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