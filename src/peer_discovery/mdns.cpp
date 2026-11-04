// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "mdns.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <map>
#include <unordered_map>

namespace dht::mdns {
namespace {

constexpr uint16_t FLAG_RESPONSE = 0x8000;
constexpr uint16_t FLAG_AUTHORITATIVE = 0x0400;
constexpr uint16_t FLAG_TRUNCATED = 0x0200;
constexpr uint16_t CLASS_TOP_BIT = 0x8000;
constexpr uint16_t CLASS_MASK = 0x7fff;

char
asciiLower(char value)
{
    const auto byte = static_cast<unsigned char>(value);
    return static_cast<char>(std::tolower(byte));
}

void
validateLabels(const std::vector<std::string>& labels)
{
    size_t wireSize = 0;
    for (const auto& label : labels) {
        if (label.empty() or label.size() > 63)
            throw ParseError("invalid DNS label length");
        wireSize += label.size() + 1;
        if (wireSize > 255)
            throw ParseError("DNS name is too long");
    }
}

std::string
suffixKey(const std::vector<std::string>& labels, size_t first)
{
    std::string key;
    for (auto index = first; index < labels.size(); ++index) {
        key.push_back(static_cast<char>(labels[index].size()));
        key.append(labels[index]);
    }
    key.push_back('\0');
    return key;
}

class Writer
{
public:
    void write8(uint8_t value)
    {
        ensure(1);
        packet_.push_back(value);
    }

    void write16(uint16_t value)
    {
        ensure(2);
        packet_.push_back(static_cast<uint8_t>(value >> 8));
        packet_.push_back(static_cast<uint8_t>(value));
    }

    void write32(uint32_t value)
    {
        write16(static_cast<uint16_t>(value >> 16));
        write16(static_cast<uint16_t>(value));
    }

    template<size_t Size>
    void write(const std::array<uint8_t, Size>& bytes)
    {
        write(bytes.data(), bytes.size());
    }

    void write(const uint8_t* bytes, size_t size)
    {
        ensure(size);
        packet_.insert(packet_.end(), bytes, bytes + size);
    }

    void writeName(const Name& name)
    {
        const auto& labels = name.labels();
        for (size_t index = 0; index < labels.size(); ++index) {
            const auto key = suffixKey(labels, index);
            if (const auto found = suffixes_.find(key); found != suffixes_.end()) {
                write16(static_cast<uint16_t>(0xc000 | found->second));
                return;
            }
            if (packet_.size() < 0x4000)
                suffixes_.emplace(key, static_cast<uint16_t>(packet_.size()));
            write8(static_cast<uint8_t>(labels[index].size()));
            write(reinterpret_cast<const uint8_t*>(labels[index].data()), labels[index].size());
        }
        write8(0);
    }

    size_t size() const noexcept { return packet_.size(); }

    void patch16(size_t offset, uint16_t value)
    {
        if (offset + 2 > packet_.size())
            throw ParseError("invalid DNS packet patch offset");
        packet_[offset] = static_cast<uint8_t>(value >> 8);
        packet_[offset + 1] = static_cast<uint8_t>(value);
    }

    Packet take() { return std::move(packet_); }

private:
    void ensure(size_t additional) const
    {
        if (additional > MAX_PACKET_SIZE - packet_.size())
            throw ParseError("mDNS packet exceeds maximum size");
    }

    Packet packet_;
    std::unordered_map<std::string, uint16_t> suffixes_;
};

class Reader
{
public:
    Reader(const uint8_t* packet, size_t size)
        : packet_(packet)
        , size_(size)
    {}

    uint8_t read8()
    {
        require(1);
        return packet_[position_++];
    }

    uint16_t read16()
    {
        const auto high = read8();
        const auto low = read8();
        return static_cast<uint16_t>((high << 8) | low);
    }

    uint32_t read32() { return (static_cast<uint32_t>(read16()) << 16) | read16(); }

    Name readName()
    {
        std::vector<std::string> labels;
        std::vector<size_t> visited;
        auto cursor = position_;
        auto jumped = false;
        size_t wireSize = 0;

        while (true) {
            if (cursor >= size_)
                throw ParseError("truncated DNS name");
            if (std::find(visited.begin(), visited.end(), cursor) != visited.end())
                throw ParseError("DNS compression pointer loop");
            visited.push_back(cursor);

            const auto length = packet_[cursor];
            if ((length & 0xc0) == 0xc0) {
                if (cursor + 1 >= size_)
                    throw ParseError("truncated DNS compression pointer");
                const auto pointer = static_cast<size_t>(((length & 0x3f) << 8) | packet_[cursor + 1]);
                if (pointer >= cursor)
                    throw ParseError("DNS compression pointer does not point backwards");
                if (not jumped)
                    position_ = cursor + 2;
                cursor = pointer;
                jumped = true;
                continue;
            }
            if (length & 0xc0)
                throw ParseError("invalid DNS label prefix");

            ++cursor;
            if (length == 0) {
                if (not jumped)
                    position_ = cursor;
                break;
            }
            if (length > 63 or length > size_ - cursor)
                throw ParseError("invalid or truncated DNS label");
            wireSize += length + 1;
            if (wireSize > 255)
                throw ParseError("DNS name is too long");
            labels.emplace_back(reinterpret_cast<const char*>(packet_ + cursor), length);
            cursor += length;
            if (not jumped)
                position_ = cursor;
        }
        return Name {std::move(labels)};
    }

    std::vector<uint8_t> readBytes(size_t size)
    {
        require(size);
        std::vector<uint8_t> bytes(packet_ + position_, packet_ + position_ + size);
        position_ += size;
        return bytes;
    }

    size_t position() const noexcept { return position_; }
    void setPosition(size_t position)
    {
        if (position > size_)
            throw ParseError("invalid DNS packet position");
        position_ = position;
    }

private:
    void require(size_t count) const
    {
        if (count > size_ - position_)
            throw ParseError("truncated DNS packet");
    }

    const uint8_t* packet_;
    size_t size_;
    size_t position_ {};
};

uint16_t
checkedCount(size_t count)
{
    if (count > std::numeric_limits<uint16_t>::max())
        throw ParseError("too many DNS records");
    return static_cast<uint16_t>(count);
}

void
encodeQuestion(Writer& writer, const Question& question)
{
    writer.writeName(question.name);
    writer.write16(static_cast<uint16_t>(question.type));
    writer.write16(static_cast<uint16_t>(question.classCode | (question.unicastResponse ? CLASS_TOP_BIT : 0)));
}

void
encodeNsec(Writer& writer, const NsecData& nsec)
{
    writer.writeName(nsec.nextDomain);
    std::map<uint8_t, std::array<uint8_t, 32>> windows;
    std::map<uint8_t, uint8_t> lengths;
    for (const auto type : nsec.types) {
        const auto value = static_cast<uint16_t>(type);
        const auto window = static_cast<uint8_t>(value >> 8);
        const auto low = static_cast<uint8_t>(value);
        const auto byte = static_cast<uint8_t>(low / 8);
        const auto bit = static_cast<uint8_t>(low % 8);
        windows[window][byte] |= static_cast<uint8_t>(1u << (7 - bit));
        lengths[window] = std::max<uint8_t>(lengths[window], byte + 1);
    }
    for (const auto& [window, bitmap] : windows) {
        writer.write8(window);
        writer.write8(lengths[window]);
        writer.write(bitmap.data(), lengths[window]);
    }
}

void
encodeRecord(Writer& writer, const ResourceRecord& record)
{
    writer.writeName(record.name);
    writer.write16(static_cast<uint16_t>(record.type));
    writer.write16(static_cast<uint16_t>(record.classCode | (record.cacheFlush ? CLASS_TOP_BIT : 0)));
    writer.write32(record.ttl);
    const auto lengthOffset = writer.size();
    writer.write16(0);
    const auto dataOffset = writer.size();

    switch (record.type) {
    case Type::A:
        writer.write(std::get<AData>(record.data).address);
        break;
    case Type::AAAA:
        writer.write(std::get<AaaaData>(record.data).address);
        break;
    case Type::PTR:
        writer.writeName(std::get<PtrData>(record.data).name);
        break;
    case Type::TXT:
        for (const auto& string : std::get<TxtData>(record.data).strings) {
            if (string.size() > 255)
                throw ParseError("DNS TXT string is too long");
            writer.write8(static_cast<uint8_t>(string.size()));
            writer.write(string.data(), string.size());
        }
        break;
    case Type::SRV: {
        const auto& srv = std::get<SrvData>(record.data);
        writer.write16(srv.priority);
        writer.write16(srv.weight);
        writer.write16(srv.port);
        writer.writeName(srv.target);
        break;
    }
    case Type::NSEC:
        encodeNsec(writer, std::get<NsecData>(record.data));
        break;
    default: {
        const auto& bytes = std::get<UnknownData>(record.data).bytes;
        writer.write(bytes.data(), bytes.size());
        break;
    }
    }

    const auto dataSize = writer.size() - dataOffset;
    if (dataSize > std::numeric_limits<uint16_t>::max())
        throw ParseError("DNS record data is too large");
    writer.patch16(lengthOffset, static_cast<uint16_t>(dataSize));
}

Question
decodeQuestion(Reader& reader)
{
    Question question;
    question.name = reader.readName();
    question.type = static_cast<Type>(reader.read16());
    const auto classField = reader.read16();
    question.classCode = classField & CLASS_MASK;
    question.unicastResponse = classField & CLASS_TOP_BIT;
    return question;
}

NsecData
decodeNsec(Reader& reader, size_t end)
{
    NsecData nsec;
    nsec.nextDomain = reader.readName();
    while (reader.position() < end) {
        const auto window = reader.read8();
        const auto length = reader.read8();
        if (length == 0 or length > 32 or length > end - reader.position())
            throw ParseError("invalid DNS NSEC bitmap");
        const auto bitmap = reader.readBytes(length);
        for (size_t byte = 0; byte < bitmap.size(); ++byte) {
            for (uint8_t bit = 0; bit < 8; ++bit) {
                if (bitmap[byte] & (1u << (7 - bit))) {
                    const auto value = static_cast<uint16_t>((window << 8) | (byte * 8 + bit));
                    nsec.types.push_back(static_cast<Type>(value));
                }
            }
        }
    }
    return nsec;
}

ResourceRecord
decodeRecord(Reader& reader)
{
    ResourceRecord record;
    record.name = reader.readName();
    record.type = static_cast<Type>(reader.read16());
    const auto classField = reader.read16();
    record.classCode = classField & CLASS_MASK;
    record.cacheFlush = classField & CLASS_TOP_BIT;
    record.ttl = reader.read32();
    const auto dataLength = reader.read16();
    const auto dataStart = reader.position();
    const auto dataEnd = dataStart + dataLength;
    if (dataEnd < dataStart)
        throw ParseError("invalid DNS record length");

    switch (record.type) {
    case Type::A: {
        if (dataLength != 4)
            throw ParseError("invalid DNS A record length");
        AData data;
        const auto bytes = reader.readBytes(data.address.size());
        std::copy(bytes.begin(), bytes.end(), data.address.begin());
        record.data = data;
        break;
    }
    case Type::AAAA: {
        if (dataLength != 16)
            throw ParseError("invalid DNS AAAA record length");
        AaaaData data;
        const auto bytes = reader.readBytes(data.address.size());
        std::copy(bytes.begin(), bytes.end(), data.address.begin());
        record.data = data;
        break;
    }
    case Type::PTR:
        record.data = PtrData {reader.readName()};
        break;
    case Type::TXT: {
        TxtData data;
        while (reader.position() < dataEnd) {
            const auto length = reader.read8();
            if (length > dataEnd - reader.position())
                throw ParseError("truncated DNS TXT string");
            data.strings.push_back(reader.readBytes(length));
        }
        record.data = std::move(data);
        break;
    }
    case Type::SRV: {
        if (dataLength < 7)
            throw ParseError("invalid DNS SRV record length");
        SrvData data;
        data.priority = reader.read16();
        data.weight = reader.read16();
        data.port = reader.read16();
        data.target = reader.readName();
        record.data = std::move(data);
        break;
    }
    case Type::NSEC:
        record.data = decodeNsec(reader, dataEnd);
        break;
    default:
        record.data = UnknownData {reader.readBytes(dataLength)};
        break;
    }

    if (reader.position() != dataEnd)
        throw ParseError("DNS record data length mismatch");
    return record;
}

} // namespace

Name::Name(std::vector<std::string> labels)
    : labels_(std::move(labels))
{
    validateLabels(labels_);
}

Name
Name::fromString(std::string_view name)
{
    if (name.empty() or name == ".")
        return {};
    if (name.back() == '.')
        name.remove_suffix(1);

    std::vector<std::string> labels;
    size_t start = 0;
    while (start <= name.size()) {
        const auto end = name.find('.', start);
        const auto length = (end == std::string_view::npos ? name.size() : end) - start;
        if (length == 0)
            throw ParseError("empty DNS label");
        labels.emplace_back(name.substr(start, length));
        if (end == std::string_view::npos)
            break;
        start = end + 1;
    }
    return Name {std::move(labels)};
}

std::string
Name::toString() const
{
    if (labels_.empty())
        return ".";
    std::string name;
    for (const auto& label : labels_) {
        name.append(label);
        name.push_back('.');
    }
    return name;
}

bool
operator==(const Name& lhs, const Name& rhs) noexcept
{
    if (lhs.labels_.size() != rhs.labels_.size())
        return false;
    for (size_t index = 0; index < lhs.labels_.size(); ++index) {
        const auto& left = lhs.labels_[index];
        const auto& right = rhs.labels_[index];
        if (left.size() != right.size())
            return false;
        if (not std::equal(left.begin(), left.end(), right.begin(), [](char a, char b) {
                return asciiLower(a) == asciiLower(b);
            }))
            return false;
    }
    return true;
}

Packet
encode(const Message& message)
{
    const auto recordCount = message.questions.size() + message.answers.size() + message.authorities.size()
                             + message.additionals.size();
    if (recordCount > MAX_RECORD_COUNT)
        throw ParseError("too many DNS records");

    Writer writer;
    writer.write16(message.id);
    uint16_t flags = 0;
    if (message.response)
        flags |= FLAG_RESPONSE;
    if (message.authoritative)
        flags |= FLAG_AUTHORITATIVE;
    if (message.truncated)
        flags |= FLAG_TRUNCATED;
    writer.write16(flags);
    writer.write16(checkedCount(message.questions.size()));
    writer.write16(checkedCount(message.answers.size()));
    writer.write16(checkedCount(message.authorities.size()));
    writer.write16(checkedCount(message.additionals.size()));

    for (const auto& question : message.questions)
        encodeQuestion(writer, question);
    for (const auto& record : message.answers)
        encodeRecord(writer, record);
    for (const auto& record : message.authorities)
        encodeRecord(writer, record);
    for (const auto& record : message.additionals)
        encodeRecord(writer, record);
    return writer.take();
}

Message
decode(const uint8_t* packet, size_t size)
{
    if (packet == nullptr)
        throw ParseError("null DNS packet");
    if (size > MAX_PACKET_SIZE)
        throw ParseError("mDNS packet exceeds maximum size");

    Reader reader(packet, size);
    Message message;
    message.id = reader.read16();
    const auto flags = reader.read16();
    message.response = flags & FLAG_RESPONSE;
    message.authoritative = flags & FLAG_AUTHORITATIVE;
    message.truncated = flags & FLAG_TRUNCATED;
    const auto questionCount = reader.read16();
    const auto answerCount = reader.read16();
    const auto authorityCount = reader.read16();
    const auto additionalCount = reader.read16();
    const auto recordCount = static_cast<size_t>(questionCount) + answerCount + authorityCount + additionalCount;
    if (recordCount > MAX_RECORD_COUNT)
        throw ParseError("too many DNS records");

    message.questions.reserve(questionCount);
    message.answers.reserve(answerCount);
    message.authorities.reserve(authorityCount);
    message.additionals.reserve(additionalCount);
    for (size_t index = 0; index < questionCount; ++index)
        message.questions.push_back(decodeQuestion(reader));
    for (size_t index = 0; index < answerCount; ++index)
        message.answers.push_back(decodeRecord(reader));
    for (size_t index = 0; index < authorityCount; ++index)
        message.authorities.push_back(decodeRecord(reader));
    for (size_t index = 0; index < additionalCount; ++index)
        message.additionals.push_back(decodeRecord(reader));
    if (reader.position() != size)
        throw ParseError("trailing bytes in DNS packet");
    return message;
}

} // namespace dht::mdns