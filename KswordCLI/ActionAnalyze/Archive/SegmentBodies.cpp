#include "SegmentBodies.h"

#include "SegmentWire.h"
#include "../../../shared/evidence/EvidenceJson.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <iterator>
#include <windows.h>

namespace ks::cli::action_analyze::archive {
namespace {

namespace evidence = Ksword::Evidence;
constexpr std::uint16_t kRawRecord = 3;
constexpr std::uint16_t kCanonicalEvent = 4;
constexpr auto kRawPrefixBytes = static_cast<std::uint32_t>(kRawRecordV1PrefixBytes);
constexpr std::uint32_t kEventCoreBytes = 128;
constexpr std::uint32_t kEventValidityMask = 2047;
constexpr std::size_t kMaxJsonBytes = 4u * 1024u * 1024u;
constexpr std::size_t kMaxJsonDepth = 32;
constexpr std::size_t kMaxJsonStringBytes = 64u * 1024u;

bool IsDigit(char ch) noexcept
{
    return ch >= '0' && ch <= '9';
}

// EvidenceJson 解析重复键和转义。此处补 A0 的容器深度及整数词法和数值范围。
bool ValidJsonTokens(std::string_view json) noexcept
{
    std::size_t depth = 0;
    bool inString = false;
    for (std::size_t pos = 0; pos < json.size(); ++pos) {
        const char ch = json[pos];
        if (inString) {
            if (ch == '\\') {
                ++pos;
            } else if (ch == '"') {
                inString = false;
            }
        } else if (ch == '"') {
            inString = true;
        } else if (ch == '{' || ch == '[') {
            if (++depth > kMaxJsonDepth) {
                return false;
            }
        } else if (ch == '}' || ch == ']') {
            if (depth == 0) {
                return false;
            }
            --depth;
        } else if (ch == '-' || IsDigit(ch)) {
            const auto start = pos;
            const auto digits = pos + (ch == '-' ? 1u : 0u);
            auto end = digits;
            while (end < json.size() && IsDigit(json[end])) {
                ++end;
            }
            if (end == digits || (end - digits > 1 && json[digits] == '0') || end - start > 11) {
                return false;
            }
            std::int64_t value = 0;
            const auto converted = std::from_chars(json.data() + start, json.data() + end, value);
            if (converted.ec != std::errc{} || value < -2147483648LL || value > 4294967295LL) {
                return false;
            }
            pos = end - 1;
        }
    }
    return true;
}

BodyIssue CheckJson(std::string_view json)
{
    if (json.empty() || json.size() > kMaxJsonBytes || json.substr(0, 3) == "\xef\xbb\xbf" ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, json.data(), static_cast<int>(json.size()), nullptr, 0) == 0 ||
        !ValidJsonTokens(json)) {
        return BodyIssue::Json;
    }
    evidence::JsonLimits limits;
    limits.maxTotalBytes = kMaxJsonBytes;
    limits.maxDepth = kMaxJsonDepth;
    limits.maxStringBytes = kMaxJsonStringBytes;
    limits.maxTotalNodes = std::min(limits.maxTotalNodes, limits.maxEstimatedNodeBytes / sizeof(evidence::JsonValue));
    const auto parsed = evidence::ParseJson(json, limits);
    if (parsed.status == evidence::JsonParseStatus::NodeLimit) {
        return BodyIssue::JsonBudget;
    }
    return parsed.ok() && parsed.value.asObject() ? BodyIssue::None : BodyIssue::Json;
}

std::string_view JsonView(const std::uint8_t* data, std::size_t size) noexcept
{
    return {reinterpret_cast<const char*>(data), size};
}

BodyIssue DecodeRaw(const RecordView& record, RecordBody& body)
{
    if (record.payloadBytes < kRawPrefixBytes) {
        return BodyIssue::Length;
    }
    const auto jsonBytes = wire::Get<std::uint32_t>(record.payload, 0);
    if (jsonBytes > record.payloadBytes - kRawPrefixBytes) {
        return BodyIssue::Length;
    }
    const auto json = JsonView(record.payload + kRawPrefixBytes, jsonBytes);
    if (const auto issue = CheckJson(json); issue != BodyIssue::None) {
        return issue;
    }
    const auto inlineOffset = kRawPrefixBytes + jsonBytes; // 正文内联原始字节的起点。
    const auto inlineBytes = record.payloadBytes - inlineOffset; // 已验证的实存字节数。
    // 交给读者的原始二进制视图与当前块缓冲区共用生命周期。
    const std::string_view inlineData(reinterpret_cast<const char*>(record.payload + inlineOffset), inlineBytes);
    body = RawRecordV1{json, inlineOffset, inlineBytes, inlineData};
    return BodyIssue::None;
}

struct OptionalEventField {
    std::size_t offset;
    bool requirePositive;
    std::optional<std::uint64_t> CanonicalEventV1::*member;
};

constexpr OptionalEventField kOptionalFields[] = {
    {8, false, &CanonicalEventV1::primaryRawRecordSequence},
    {32, false, &CanonicalEventV1::producerSequence},
    {40, false, &CanonicalEventV1::sourceTimestamp},
    {48, false, &CanonicalEventV1::receiveQpc},
    {56, true, &CanonicalEventV1::actorProcessObjectId},
    {64, true, &CanonicalEventV1::targetProcessObjectId},
    {72, true, &CanonicalEventV1::observedThreadObjectId},
    {80, true, &CanonicalEventV1::operationDictionaryId},
    {88, true, &CanonicalEventV1::captureRevisionDictionaryId},
    {96, true, &CanonicalEventV1::effectiveRevisionDictionaryId},
    {104, true, &CanonicalEventV1::coverageDictionaryId},
};

BodyIssue DecodeEvent(const RecordView& record, RecordBody& body)
{
    if (record.payloadBytes < kEventCoreBytes) {
        return BodyIssue::Length;
    }
    const auto* data = record.payload;
    CanonicalEventV1 event;
    event.validityBits = wire::Get<std::uint32_t>(data, 120);
    if ((event.validityBits & ~kEventValidityMask) != 0) {
        return BodyIssue::ValidityBits;
    }
    const auto jsonBytes = wire::Get<std::uint32_t>(data, 124);
    if (jsonBytes != record.payloadBytes - kEventCoreBytes) {
        return BodyIssue::Length;
    }
    event.eventOrdinal = wire::Get<std::uint64_t>(data, 0);
    event.sourceInstanceDictionaryId = wire::Get<std::uint64_t>(data, 16);
    event.sourceEpochDictionaryId = wire::Get<std::uint64_t>(data, 24);
    if (event.sourceInstanceDictionaryId == 0 || event.sourceEpochDictionaryId == 0) {
        return BodyIssue::RequiredRef;
    }
    for (std::size_t bit = 0; bit < std::size(kOptionalFields); ++bit) {
        const auto& field = kOptionalFields[bit];
        const auto value = wire::Get<std::uint64_t>(data, field.offset);
        const auto valid = (event.validityBits & (1u << bit)) != 0;
        if (valid ? (field.requirePositive && value == 0) : (value != 0)) {
            return BodyIssue::ValidityValue;
        }
        if (valid) {
            event.*field.member = value;
        }
    }
    event.eventKind = wire::Get<std::uint32_t>(data, 112);
    event.category = wire::Get<std::uint16_t>(data, 116);
    event.phase = data[118];
    event.clockDomain = data[119];
    event.fieldJson = JsonView(data + kEventCoreBytes, jsonBytes);
    if (const auto issue = CheckJson(event.fieldJson); issue != BodyIssue::None) {
        return issue;
    }
    body = event;
    return BodyIssue::None;
}

BodyIssue Decode(const RecordView& record, RecordBody& body)
{
    if (record.schemaVersion == 1) {
        if (record.type == kRawRecord) {
            return DecodeRaw(record, body);
        }
        if (record.type == kCanonicalEvent) {
            return DecodeEvent(record, body);
        }
    }
    return BodyIssue::None;
}

} // namespace

BodyIssue EncodeRawRecordV1(std::string_view metadataJson, std::string_view inlineRawData,
                          std::vector<std::uint8_t>& out)
{
    // 检查两段长度后才分配。封装和解码共享 JSON 校验规则。
    constexpr auto maxBody = kMaxDecodedBlockBytes - kRecordHeaderBytes - kRawPrefixBytes;
    if (metadataJson.size() > maxBody || inlineRawData.size() > maxBody - metadataJson.size()) {
        return BodyIssue::Length;
    }
    if (const auto issue = CheckJson(metadataJson); issue != BodyIssue::None) {
        return issue;
    }

    // 保留输入的 UTF-8 和原始二进制字节，包括原始证据中的 NUL。
    std::vector<std::uint8_t> payload(kRawPrefixBytes + metadataJson.size() + inlineRawData.size());
    wire::Put(payload.data(), 0, static_cast<std::uint32_t>(metadataJson.size()));
    auto* const metadata = payload.data() + kRawPrefixBytes;
    std::memcpy(metadata, metadataJson.data(), metadataJson.size());
    if (!inlineRawData.empty()) {
        std::memcpy(metadata + metadataJson.size(), inlineRawData.data(), inlineRawData.size());
    }
    out.swap(payload);
    return BodyIssue::None;
}

SegmentBodyScanResult ScanOpenSegmentBodies(void* fileHandle, const SegmentIdentity& expectedIdentity,
                                            std::optional<std::uint64_t> endOffset, const SegmentBodyVisitor& visitor)
{
    SegmentBodyScanResult result;
    SegmentScanOptions options;
    options.expectedIdentity = expectedIdentity;
    options.endOffset = endOffset;
    std::vector<DecodedRecord> decoded;
    result.framing = ScanOpenSegment(fileHandle, options, [&](const BlockInfo& block, const std::vector<RecordView>& records) {
        if (result.bodyFailure.issue != BodyIssue::None) {
            return true;
        }
        decoded.clear();
        std::uint64_t optional = 0;
        std::uint64_t required = 0;
        for (const auto& record : records) {
            const bool isRequired = (record.flags & kRequiredRecord) != 0;
            RecordBody body;
            if (const auto issue = Decode(record, body); issue != BodyIssue::None) {
                result.bodyFailure = {issue, record.type, record.offset};
                return true;
            }
            if (std::holds_alternative<std::monostate>(body)) {
                if (isRequired) {
                    ++required;
                } else {
                    ++optional;
                }
            }
            if (visitor) {
                decoded.push_back({record.sequence, record.offset, record.type, record.schemaVersion, record.flags, body});
            }
        }
        result.bodyCheckedBytes = block.endOffset;
        ++result.bodyCheckedBlocks;
        result.opaqueOptionalRecords += optional;
        result.opaqueRequiredRecords += required;
        return !visitor || visitor(expectedIdentity, block, decoded);
    });
    if (result.bodyCheckedBlocks == 0 && result.framing.header) {
        result.bodyCheckedBytes = kSegmentHeaderBytes;
    }
    return result;
}

} // namespace ks::cli::action_analyze::archive
