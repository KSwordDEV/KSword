#include "NetworkEvidenceArchive.h"

#include "SegmentBodies.h"
#include "SegmentInspection.h"
#include "SegmentWire.h"
#include "../../../shared/evidence/EvidenceJson.h"

#include <algorithm>
#include <charconv>
#include <limits>
#include <string_view>
#include <utility>

namespace ks::cli::action_analyze::archive {
namespace {

using Ksword::Evidence::JsonObject;
using Ksword::Evidence::JsonValue;
constexpr auto kMaxSequence = (std::numeric_limits<std::uint64_t>::max)();
constexpr std::string_view kMetadataKind = "ksword.actionAnalyze.network.v1";
constexpr std::uint16_t kRawRecord = 3;
constexpr std::size_t kRawPrefixBytes = 4;
static_assert(kNetworkBatchRecords * (kRecordHeaderBytes + kRawPrefixBytes + kNetworkMaxMetadataBytes +
    kNetworkMaxInlineBytes) <= kMaxDecodedBlockBytes);

bool HasId(const ArchiveUuid& id) noexcept
{
    return std::any_of(id.begin(), id.end(), [](auto byte) { return byte != 0; });
}

bool ValidLabel(std::string_view value) noexcept
{
    return !value.empty() && value.size() <= 64 && std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
            ch == '-' || ch == '_' || ch == '.' || ch == ':' || ch == '/';
    });
}

bool ValidBinding(const NetworkEvidenceBinding& value) noexcept
{
    if (!HasId(value.project) || !HasId(value.sample) || !HasId(value.sourceEpoch) ||
        !ValidLabel(value.sourceId) || !ValidLabel(value.clockId) || !ValidLabel(value.bootId)) return false;
    return (value.clockDomain == NetworkTimeDomain::Qpc && value.frequencyHz.value_or(0) != 0) ||
        (value.clockDomain == NetworkTimeDomain::FileTime && !value.frequencyHz);
}

bool Matches(const NetworkEvidenceBinding& a, const NetworkEvidenceBinding& b) noexcept
{
    return a.project == b.project && a.sample == b.sample && a.sourceId == b.sourceId && a.sourceEpoch == b.sourceEpoch &&
        a.clockId == b.clockId && a.bootId == b.bootId && a.clockDomain == b.clockDomain && a.frequencyHz == b.frequencyHz;
}

SegmentIdentity ForSegment(const NetworkEvidenceBinding& binding, std::uint64_t ordinal) noexcept
{
    return {StreamKind::Raw, ordinal, binding.project, binding.sample};
}

std::filesystem::path SegmentPath(const std::filesystem::path& directory, const SegmentIdentity& identity)
{
    const auto name = NameInspectionSegment(identity);
    return name ? directory / name->fileName : std::filesystem::path{};
}

bool ValidFlow(const NetworkFlowMetadata& flow) noexcept
{
    if (flow.family != NetworkFamily::IPv4 && flow.family != NetworkFamily::IPv6) return false;
    if (flow.transport != NetworkTransport::Tcp && flow.transport != NetworkTransport::Udp) return false;
    if (flow.direction != NetworkDirection::Inbound && flow.direction != NetworkDirection::Outbound) return false;
    if (flow.processId == 0 || flow.processCreatedUtc100ns == 0 || flow.processObjectId == 0) return false;
    if (flow.family == NetworkFamily::IPv4) {
        const auto zero = [](auto byte) { return byte == 0; };
        return std::all_of(flow.sourceField.address.begin() + 4, flow.sourceField.address.end(), zero) &&
            std::all_of(flow.destinationField.address.begin() + 4, flow.destinationField.address.end(), zero);
    }
    return true;
}

constexpr std::array<std::string_view, 4> kCaptureLayers{
    "flow-metadata", "transport-payload", "ip-packet", "link-frame"
};
constexpr std::array<std::string_view, 5> kPayloadStates{
    "metadata-only", "no-payload", "complete", "truncated", "captured"
};

NetworkPayloadState CaptureState(const NetworkCaptureSummary& value) noexcept
{
    if (value.layer == NetworkCaptureLayer::FlowMetadata) return NetworkPayloadState::MetadataOnly;
    if (value.sourceTruncated || value.capturedLength < value.producerCapturedLength ||
        (value.originalLength && value.capturedLength < *value.originalLength)) return NetworkPayloadState::Truncated;
    if (value.originalLength == 0) return NetworkPayloadState::NoPayload;
    return value.originalLength ? NetworkPayloadState::Complete : NetworkPayloadState::Captured;
}

bool ValidCapture(const NetworkCaptureSummary& value) noexcept
{
    if (static_cast<std::size_t>(value.layer) >= kCaptureLayers.size()) return false;
    if (value.layer == NetworkCaptureLayer::FlowMetadata) {
        return !value.originalLength && value.producerCapturedLength == 0 && value.capturedLength == 0 &&
            !value.sourceTruncated && value.state == NetworkPayloadState::MetadataOnly;
    }
    if ((value.originalLength && value.producerCapturedLength > *value.originalLength) ||
        (value.sourceTruncated && value.originalLength == value.producerCapturedLength)) return false;
    return value.capturedLength == std::min<std::uint64_t>(value.producerCapturedLength, kNetworkMaxInlineBytes) &&
        value.state == CaptureState(value);
}

bool ValidEnd(NetworkArchiveEnd end) noexcept
{
    return end == NetworkArchiveEnd::Stopped || end == NetworkArchiveEnd::SourceUnavailable ||
        end == NetworkArchiveEnd::SourceFailed;
}

void AddCount(std::uint64_t& total, bool& saturated, std::uint64_t delta, bool deltaSaturated = false) noexcept
{
    if (deltaSaturated || delta > kMaxSequence - total) {
        total = kMaxSequence;
        saturated = true;
    } else {
        total += delta;
    }
}

void AddLoss(NetworkLoss& total, const NetworkLoss& delta) noexcept
{
    AddCount(total.queueDropped, total.queueCounterSaturated, delta.queueDropped, delta.queueCounterSaturated);
    AddCount(total.sourceLost, total.sourceCounterSaturated, delta.sourceLost, delta.sourceCounterSaturated);
    total.sourceLossUnquantified |= delta.sourceLossUnquantified;
}

bool HasLoss(const NetworkLoss& loss) noexcept
{
    return loss.queueDropped != 0 || loss.sourceLost != 0 || loss.sourceLossUnquantified;
}

void AddQpc(std::optional<QpcRange>& range, std::optional<std::uint64_t> timestamp) noexcept
{
    if (!timestamp) return;
    if (!range) {
        range = QpcRange{*timestamp, *timestamp};
    } else {
        range->minimum = std::min(range->minimum, *timestamp);
        range->maximum = std::max(range->maximum, *timestamp);
    }
}

bool SameQpc(const std::optional<QpcRange>& a, const std::optional<QpcRange>& b) noexcept
{
    if (!a || !b) return !a && !b;
    return a->minimum == b->minimum && a->maximum == b->maximum;
}

std::string Hex(const std::array<std::uint8_t, 16>& bytes, std::size_t count = 16, bool uuid = false)
{
    constexpr char digits[] = "0123456789abcdef";
    std::string text;
    text.reserve(36);
    for (std::size_t i = 0; i < count; ++i) {
        if (uuid && (i == 4 || i == 6 || i == 8 || i == 10)) text.push_back('-');
        text.push_back(digits[bytes[i] >> 4]);
        text.push_back(digits[bytes[i] & 15]);
    }
    return text;
}

JsonValue Number(std::optional<std::uint64_t> value)
{
    return value ? JsonValue::makeString(std::to_string(*value)) : JsonValue::makeNull();
}

JsonObject Metadata(const NetworkEvidenceBinding& binding, const char* kind)
{
    return {{"kind", JsonValue::makeString(std::string(kMetadataKind))}, {"record", JsonValue::makeString(kind)},
            {"sourceId", JsonValue::makeString(binding.sourceId)},
            {"sourceEpoch", JsonValue::makeString(Hex(binding.sourceEpoch, 16, true))},
            {"clockId", JsonValue::makeString(binding.clockId)}, {"bootId", JsonValue::makeString(binding.bootId)},
            {"clockDomain", Number(static_cast<std::uint8_t>(binding.clockDomain))},
            {"frequencyHz", Number(binding.frequencyHz)}};
}

JsonValue FlowMetadata(const NetworkEvidenceBinding& binding, const NetworkFlowMetadata& flow,
    const NetworkCaptureSummary& capture)
{
    auto obj = Metadata(binding, "flow");
    const auto addressBytes = flow.family == NetworkFamily::IPv4 ? 4u : 16u;
    obj.insert(obj.end(), {
        {"family", Number(static_cast<std::uint8_t>(flow.family))},
        {"protocol", Number(static_cast<std::uint8_t>(flow.transport))},
        {"direction", Number(static_cast<std::uint8_t>(flow.direction))},
        {"sourceAddress", JsonValue::makeString(Hex(flow.sourceField.address, addressBytes))},
        {"sourcePort", Number(flow.sourceField.port)},
        {"destinationAddress", JsonValue::makeString(Hex(flow.destinationField.address, addressBytes))},
        {"destinationPort", Number(flow.destinationField.port)},
        {"payloadPid", Number(flow.processId)},
        {"createTime100ns", Number(flow.processCreatedUtc100ns)},
        {"processObjectId", Number(flow.processObjectId)},
        {"sourceTick", Number(flow.sourceTimestamp)},
        {"producerSequence", Number(flow.producerSequence)},
        {"receiveQpc", Number(flow.receiveQpc)},
        {"observedBytes", Number(flow.observedBytes)},
        {"eventId", Number(flow.etw ? std::optional<std::uint64_t>(flow.etw->eventId) : std::nullopt)},
        {"version", Number(flow.etw ? std::optional<std::uint64_t>(flow.etw->version) : std::nullopt)},
        {"opcode", Number(flow.etw ? std::optional<std::uint64_t>(flow.etw->opcode) : std::nullopt)},
        {"captureLayer", JsonValue::makeString(std::string(kCaptureLayers[static_cast<std::size_t>(capture.layer)]))},
        {"payloadState", JsonValue::makeString(std::string(kPayloadStates[static_cast<std::size_t>(capture.state)]))},
        {"encoding", capture.layer == NetworkCaptureLayer::FlowMetadata ? JsonValue::makeNull() : JsonValue::makeString("bytes")},
        {"originalLength", Number(capture.originalLength)},
        {"producerCapturedLength", Number(capture.producerCapturedLength)},
        {"capturedLength", Number(capture.capturedLength)},
        {"sourceTruncated", JsonValue::makeBool(capture.sourceTruncated)},
    });
    return JsonValue::makeObject(std::move(obj));
}

JsonValue LossMetadata(const NetworkEvidenceBinding& binding, const NetworkLoss& loss)
{
    auto obj = Metadata(binding, "loss");
    obj.insert(obj.end(), {
        {"queueDropped", Number(loss.queueDropped)}, {"sourceLost", Number(loss.sourceLost)},
        {"sourceLossUnquantified", JsonValue::makeBool(loss.sourceLossUnquantified)},
        {"queueCounterSaturated", JsonValue::makeBool(loss.queueCounterSaturated)},
        {"sourceCounterSaturated", JsonValue::makeBool(loss.sourceCounterSaturated)},
    });
    return JsonValue::makeObject(std::move(obj));
}

JsonValue EndMetadata(const NetworkEvidenceBinding& binding, NetworkArchiveEnd end)
{
    auto obj = Metadata(binding, "eof");
    obj.emplace_back("reason", Number(static_cast<std::uint8_t>(end)));
    return JsonValue::makeObject(std::move(obj));
}

StoredRecord Pack(std::uint64_t sequence, const JsonValue& metadata,
    std::span<const std::uint8_t> first = {}, std::span<const std::uint8_t> second = {})
{
    const auto json = Ksword::Evidence::WriteJson(metadata);
    StoredRecord record{kRawRecord, 1, 0, sequence, {}};
    record.payload.resize(kRawPrefixBytes + json.size() + first.size() + second.size());
    wire::Put(record.payload.data(), 0, static_cast<std::uint32_t>(json.size()));
    std::copy(json.begin(), json.end(), record.payload.begin() + kRawPrefixBytes);
    auto* raw = record.payload.data() + kRawPrefixBytes + json.size();
    if (!first.empty()) std::copy(first.begin(), first.end(), raw);
    if (!second.empty()) std::copy(second.begin(), second.end(), raw + first.size());
    return record;
}

template<typename Unsigned>
bool ReadNumber(const JsonValue& object, const char* field, Unsigned& value)
{
    const auto* member = object.find(field);
    std::string text;
    if (!member || !member->tryGetString(text) || text.empty()) return false;
    const auto end = text.data() + text.size();
    const auto parsed = std::from_chars(text.data(), end, value);
    return parsed.ec == std::errc{} && parsed.ptr == end;
}

template<typename Unsigned>
bool ReadNumber(const JsonValue& object, const char* field, std::optional<Unsigned>& value)
{
    const auto* member = object.find(field);
    if (!member) return false;
    if (member->isNull()) { value.reset(); return true; }
    Unsigned parsed = 0;
    if (!ReadNumber(object, field, parsed)) return false;
    value = parsed;
    return true;
}

bool ReadBool(const JsonValue& obj, const char* field, bool& value)
{
    const auto* member = obj.find(field);
    return member && member->tryGetBool(value);
}

// 读取已解析的字符串字段。不存在或类型不符时拒绝该元数据。
bool ReadText(const JsonValue& obj, const char* field, std::string& value)
{
    const auto* member = obj.find(field);
    return member && member->tryGetString(value);
}

// 来源代次采用 RFC 字节顺序。文本与反向编码比对，以保证小写规范形式。
bool ReadSourceEpoch(const JsonValue& obj, ArchiveUuid& epoch)
{
    std::string text; // 元数据声明的规范 UUID。
    if (!ReadText(obj, "sourceEpoch", text) || text.size() != 36) {
        return false;
    }
    std::size_t offset = 0; // 当前十六进制字节的文本起点。
    for (auto& byte : epoch) {
        if (offset < text.size() && text[offset] == '-') {
            ++offset;
        }
        if (text.size() - offset < 2) {
            return false;
        }
        const auto* digit = text.data() + offset;
        const auto parsed = std::from_chars(digit, digit + 2, byte, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != digit + 2) {
            return false;
        }
        offset += 2;
    }
    return Hex(epoch, 16, true) == text;
}

// 将段内来源声明和已校验段头组合为绑定值。此步骤仅核对格式。
bool ReadDeclaredBinding(const SegmentIdentity& segment, const JsonValue& obj, NetworkEvidenceBinding& binding)
{
    binding.project = segment.project;
    binding.sample = segment.sample;
    std::uint8_t domain = 0; // 原始时钟域编号。
    if (!ReadText(obj, "sourceId", binding.sourceId) || !ReadSourceEpoch(obj, binding.sourceEpoch) ||
        !ReadText(obj, "clockId", binding.clockId) || !ReadText(obj, "bootId", binding.bootId) ||
        !ReadNumber(obj, "clockDomain", domain) || !ReadNumber(obj, "frequencyHz", binding.frequencyHz)) {
        return false;
    }
    binding.clockDomain = static_cast<NetworkTimeDomain>(domain);
    return ValidBinding(binding);
}

bool ReadAddress(const JsonValue& obj, const char* field, std::array<std::uint8_t, 16>& value, std::size_t count)
{
    const auto* member = obj.find(field);
    std::string text;
    if (!member || !member->tryGetString(text) || text.size() != count * 2) return false;
    for (std::size_t i = 0; i < count; ++i) {
        const auto* begin = text.data() + 2 * i;
        const auto parsed = std::from_chars(begin, begin + 2, value[i], 16);
        if (parsed.ec != std::errc{} || parsed.ptr != begin + 2) return false;
    }
    return true;
}

bool ReadFlow(const JsonValue& obj, NetworkFlowMetadata& value)
{
    std::uint8_t family = 0, transport = 0, direction = 0;
    if (!ReadNumber(obj, "family", family) || !ReadNumber(obj, "protocol", transport) ||
        !ReadNumber(obj, "direction", direction)) return false;
    value.family = static_cast<NetworkFamily>(family);
    value.transport = static_cast<NetworkTransport>(transport);
    value.direction = static_cast<NetworkDirection>(direction);
    std::optional<std::uint16_t> eventId;
    std::optional<std::uint8_t> version, opcode;
    if (!ReadNumber(obj, "eventId", eventId) || !ReadNumber(obj, "version", version) || !ReadNumber(obj, "opcode", opcode) ||
        eventId.has_value() != version.has_value() || eventId.has_value() != opcode.has_value()) return false;
    if (eventId) value.etw = NetworkFlowMetadata::EtwDescriptor{*eventId, *version, *opcode};
    const auto addressBytes = value.family == NetworkFamily::IPv4 ? 4u : 16u;
    return ReadAddress(obj, "sourceAddress", value.sourceField.address, addressBytes) &&
        ReadAddress(obj, "destinationAddress", value.destinationField.address, addressBytes) &&
        ReadNumber(obj, "sourcePort", value.sourceField.port) && ReadNumber(obj, "destinationPort", value.destinationField.port) &&
        ReadNumber(obj, "payloadPid", value.processId) && ReadNumber(obj, "createTime100ns", value.processCreatedUtc100ns) &&
        ReadNumber(obj, "processObjectId", value.processObjectId) && ReadNumber(obj, "sourceTick", value.sourceTimestamp) &&
        ReadNumber(obj, "producerSequence", value.producerSequence) && ReadNumber(obj, "receiveQpc", value.receiveQpc) &&
        ReadNumber(obj, "observedBytes", value.observedBytes) && ValidFlow(value);
}

bool ReadCapture(const JsonValue& obj, std::uint32_t bytes, NetworkCaptureSummary& value)
{
    std::string layer;
    const auto* member = obj.find("captureLayer");
    if (!member || !member->tryGetString(layer)) return false;
    const auto found = std::find(kCaptureLayers.begin(), kCaptureLayers.end(), layer);
    if (found == kCaptureLayers.end()) return false;
    value.layer = static_cast<NetworkCaptureLayer>(found - kCaptureLayers.begin());
    if (!ReadNumber(obj, "originalLength", value.originalLength) ||
        !ReadNumber(obj, "producerCapturedLength", value.producerCapturedLength) ||
        !ReadNumber(obj, "capturedLength", value.capturedLength) || value.capturedLength != bytes ||
        !ReadBool(obj, "sourceTruncated", value.sourceTruncated)) return false;
    value.state = CaptureState(value);
    return ValidCapture(value);
}

bool ReadLoss(const JsonValue& obj, NetworkLoss& loss)
{
    return ReadNumber(obj, "queueDropped", loss.queueDropped) && ReadNumber(obj, "sourceLost", loss.sourceLost) &&
        ReadBool(obj, "sourceLossUnquantified", loss.sourceLossUnquantified) &&
        ReadBool(obj, "queueCounterSaturated", loss.queueCounterSaturated) &&
        ReadBool(obj, "sourceCounterSaturated", loss.sourceCounterSaturated) &&
        (!loss.queueCounterSaturated || loss.queueDropped == kMaxSequence) &&
        (!loss.sourceCounterSaturated || loss.sourceLost == kMaxSequence) && HasLoss(loss);
}

// Compare the closed metadata object independent of JSON field order and spacing.
bool SameMetadata(const JsonValue& actual, const JsonValue& expected)
{
    const auto* actualObject = actual.asObject();
    const auto* expectedObject = expected.asObject();
    if (!actualObject || actualObject->size() != expectedObject->size()) return false;
    for (const auto& [name, value] : *expectedObject) {
        const auto* member = actual.find(name);
        if (!member || Ksword::Evidence::WriteJson(*member) != Ksword::Evidence::WriteJson(value)) return false;
    }
    return true;
}

// 统一限制独立投影及归档扫描的 JSON 读取预算。
Ksword::Evidence::JsonParseResult ParseMetadata(std::string_view text)
{
    Ksword::Evidence::JsonLimits limits; // 网络元数据只有一层标量字段。
    limits.maxDepth = 2;
    limits.maxTotalBytes = kNetworkMaxMetadataBytes;
    limits.maxStringBytes = 64;
    limits.maxContainerItems = 40;
    limits.maxTotalNodes = 41;
    return Ksword::Evidence::ParseJson(text, limits);
}

// 验证完整网络流字段及通信字节范围，供两条读取入口共用。
bool DecodeFlow(const JsonValue& obj, const NetworkEvidenceBinding& binding, std::uint32_t inlineBytes,
    NetworkArchivedFlow& row)
{
    return ReadFlow(obj, row.observation) && ReadCapture(obj, inlineBytes, row.capture) &&
        SameMetadata(obj, FlowMetadata(binding, row.observation, row.capture));
}

// 从已验证封装的记录提取借用的网络正文视图。这里只检查类型及长度，尚未验证 JSON 字段。
std::optional<RawRecordV1> ReadNetworkRawBody(const RecordView& record)
{
    if (record.type != kRawRecord || record.schemaVersion != 1 || record.flags != 0 || !record.payload ||
        record.payloadBytes <= kRawPrefixBytes ||
        record.payloadBytes > kRawPrefixBytes + kNetworkMaxMetadataBytes + kNetworkMaxInlineBytes) {
        return std::nullopt;
    }
    const auto metadataBytes = wire::Get<std::uint32_t>(record.payload, 0); // 线上小端 JSON 字节数。
    if (metadataBytes > kNetworkMaxMetadataBytes || metadataBytes > record.payloadBytes - kRawPrefixBytes) {
        return std::nullopt;
    }
    const auto inlineOffset = static_cast<std::uint32_t>(kRawPrefixBytes) + metadataBytes; // 正文内字节起点。
    const auto inlineBytes = record.payloadBytes - inlineOffset; // 实际保留的字节数。
    if (inlineBytes > kNetworkMaxInlineBytes) {
        return std::nullopt;
    }
    const auto* payload = reinterpret_cast<const char*>(record.payload); // 视图共享原正文缓冲区。
    return RawRecordV1{{payload + kRawPrefixBytes, metadataBytes}, inlineOffset, inlineBytes,
        {payload + inlineOffset, inlineBytes}};
}

// 验证绑定到独占段的记录，并填入当前块的流、丢失或终态信息。
bool Decode(const RecordView& record, const NetworkEvidenceBinding& binding,
            std::vector<NetworkArchivedFlow>& rows, NetworkLoss& loss, std::optional<NetworkArchiveEnd>& eof)
{
    const auto raw = ReadNetworkRawBody(record); // 与通用 Stored 回读入口共用的正文范围。
    if (!raw) {
        return false;
    }
    const auto parsed = ParseMetadata(raw->metadataJson);
    const auto* type = parsed.value.find("record");
    std::string kind;
    if (!parsed.ok() || !type || !type->tryGetString(kind)) return false;
    if (kind == "flow") {
        NetworkArchivedFlow row{record.sequence, record.offset, {}, {}};
        if (!DecodeFlow(parsed.value, binding, raw->inlineRawBytes, row)) return false;
        rows.push_back(row);
        return true;
    }
    if (raw->inlineRawBytes != 0) return false;
    if (kind == "loss") {
        return !HasLoss(loss) && ReadLoss(parsed.value, loss) &&
            SameMetadata(parsed.value, LossMetadata(binding, loss));
    }
    if (kind == "eof") {
        std::uint8_t reason = 0;
        if (!ReadNumber(parsed.value, "reason", reason)) return false;
        const auto end = static_cast<NetworkArchiveEnd>(reason);
        if (!ValidEnd(end) || !SameMetadata(parsed.value, EndMetadata(binding, end))) return false;
        eof = end;
        return true;
    }
    return false;
}

} // namespace

// Standalone 段中的身份和字节来自公共解码器。额外来源凭证须由项目所有者提供。
std::optional<NetworkFlowRecordProjection> ProjectNetworkFlowRecord(const SegmentIdentity& segment,
    const DecodedRecord& record, const NetworkEvidenceBinding* verifiedBinding)
{
    const auto* raw = std::get_if<RawRecordV1>(&record.body); // 仅投影现有 RawRecord v1 正文。
    if (segment.stream != StreamKind::Raw || segment.ordinal == 0 || record.recordSequence == 0 ||
        record.recordType != kRawRecord || record.recordSchemaVersion != 1 || record.flags != 0 || !raw ||
        raw->metadataJson.size() > kNetworkMaxMetadataBytes || raw->inlineRawBytes > kNetworkMaxInlineBytes ||
        raw->inlineRawData.size() != raw->inlineRawBytes ||
        raw->inlineRawOffsetInPayload != kRawPrefixBytes + raw->metadataJson.size()) {
        return std::nullopt;
    }

    const auto parsed = ParseMetadata(raw->metadataJson); // 共享网络记录的封闭字段契约。
    NetworkFlowRecordProjection projection; // 此值保留范围和来源可信度，正文仍借用回调内存。
    std::string recordKind; // 网络流与同类型的丢失、结束记录分开处理。
    if (!parsed.ok() || !ReadText(parsed.value, "record", recordKind) || recordKind != "flow" ||
        !ReadDeclaredBinding(segment, parsed.value, projection.source) ||
        (verifiedBinding && !Matches(projection.source, *verifiedBinding)) ||
        !DecodeFlow(parsed.value, projection.source, raw->inlineRawBytes, projection.flow)) {
        return std::nullopt;
    }

    projection.flow.recordSequence = record.recordSequence;
    projection.flow.recordOffset = record.recordOffset;
    if (verifiedBinding) {
        projection.sourceTrust = NetworkSourceTrust::MatchedVerifiedBinding;
    }
    projection.inlineOffsetInPayload = raw->inlineRawOffsetInPayload;
    projection.inlineBytes = raw->inlineRawData;
    return projection;
}

// 从 CRC 已验证的 RawRecord 正文提取有限视图，再交给共用网络字段解码器。
std::optional<NetworkFlowRecordProjection> ProjectNetworkFlowRecord(const SegmentIdentity& segment,
    const RecordView& record, const NetworkEvidenceBinding* verifiedBinding)
{
    if (segment.stream != StreamKind::Raw) {
        return std::nullopt;
    }
    const auto raw = ReadNetworkRawBody(record); // 仅在 Raw 流中解释网络正文。
    if (!raw) {
        return std::nullopt;
    }
    const DecodedRecord decoded{record.sequence, record.offset, record.type, record.schemaVersion,
        record.flags, *raw}; // 封装与共同正文解码器产出的值一致。
    return ProjectNetworkFlowRecord(segment, decoded, verifiedBinding);
}

// 将线上状态和实际保留量合并为供读侧使用的材料分类。
NetworkCommunicationEvidence NetworkCaptureSummary::CommunicationEvidence() const noexcept
{
    if (state == NetworkPayloadState::MetadataOnly) {
        return NetworkCommunicationEvidence::MetadataOnly;
    }
    if (capturedLength != 0) {
        return NetworkCommunicationEvidence::RetainedBytes;
    }
    if (state == NetworkPayloadState::NoPayload) {
        return NetworkCommunicationEvidence::ConfirmedEmpty;
    }
    return state == NetworkPayloadState::Truncated ? NetworkCommunicationEvidence::MissingBytes
        : NetworkCommunicationEvidence::UnknownPresence;
}

// 复制有界正文预览并保留完整归档锚点，使界面行脱离输入块的生命周期。
std::optional<NetworkStoredFlowPreview> PreviewStoredNetworkFlow(const SegmentIdentity& segment,
    const RecordView& record, const NetworkEvidenceBinding* verifiedBinding)
{
    if (record.offset < kSegmentHeaderBytes + kBlockHeaderBytes || record.offset > kMaxSegmentBytes ||
        std::uint64_t{kRecordHeaderBytes} + record.payloadBytes > kMaxSegmentBytes - record.offset) {
        return std::nullopt;
    }
    auto decoded = ProjectNetworkFlowRecord(segment, record, verifiedBinding); // 校验完整正文，随后只复制前缀。
    if (!decoded) {
        return std::nullopt;
    }
    NetworkStoredFlowPreview preview; // 结果拥有来源和字节内容。
    preview.segmentOrdinal = segment.ordinal;
    preview.flow = decoded->flow;
    preview.source = std::move(decoded->source);
    preview.sourceTrust = decoded->sourceTrust;

    if (!decoded->inlineBytes.empty()) {
        preview.inlineFileOffset = record.offset + kRecordHeaderBytes + decoded->inlineOffsetInPayload;
        const auto* begin = reinterpret_cast<const std::uint8_t*>(decoded->inlineBytes.data()); // 保持字节位值。
        const auto size = std::min(decoded->inlineBytes.size(), kNetworkStoredPreviewBytes); // 只限预览。
        preview.bytes.assign(begin, begin + size);
    }
    return preview;
}

const NetworkEndpointMetadata* NetworkFlowMetadata::OutboundDestination() const noexcept
{
    if (direction != NetworkDirection::Outbound || !processObjectId || !ValidFlow(*this) ||
        destinationField.port.value_or(0) == 0 ||
        std::all_of(destinationField.address.begin(), destinationField.address.end(), [](auto byte) { return byte == 0; })) {
        return nullptr;
    }
    return &destinationField;
}

NetworkEvidenceArchive::NetworkEvidenceArchive(const std::filesystem::path& resolvedRawDirectory,
    NetworkEvidenceBinding binding, std::uint64_t segmentOrdinal, std::uint64_t createdUtc100ns,
    std::optional<std::uint64_t> previousSequence)
    : binding_(std::move(binding)), identity_(ForSegment(binding_, segmentOrdinal)),
      writer_(SegmentPath(resolvedRawDirectory, identity_), {identity_, createdUtc100ns}, previousSequence),
      previousSequence_(previousSequence.value_or(0)), payloadRing_(kNetworkQueuedPayloadBudget)
{
    state_.segment = identity_;
    if (!ValidBinding(binding_) || segmentOrdinal == 0 || resolvedRawDirectory.empty()) {
        state_.result = {SegmentWriteStatus::InvalidInput, {SegmentIssue::Identity}};
    }
}

NetworkSubmitStatus NetworkEvidenceArchive::Submit(const NetworkEvidenceBinding& binding,
    const NetworkFlowMetadata& observation, const NetworkCapturedBytes& capture, NetworkInlinePolicy policy) noexcept
{
    if (closed_ || state_.result.status != SegmentWriteStatus::Ok) return NetworkSubmitStatus::Closed;
    if (!Matches(binding_, binding)) return NetworkSubmitStatus::WrongBinding;
    if (!ValidFlow(observation)) return NetworkSubmitStatus::InvalidObservation;
    if (policy != NetworkInlinePolicy::RequireInline && policy != NetworkInlinePolicy::RetainPrefix) {
        return NetworkSubmitStatus::InvalidObservation;
    }
    NetworkCaptureSummary summary;
    summary.layer = capture.layer;
    summary.originalLength = capture.originalLength;
    summary.producerCapturedLength = capture.bytes.size();
    summary.capturedLength = static_cast<std::uint32_t>(std::min(capture.bytes.size(), kNetworkMaxInlineBytes));
    summary.sourceTruncated = capture.sourceTruncated;
    summary.state = CaptureState(summary);
    if (!ValidCapture(summary)) return NetworkSubmitStatus::InvalidObservation;
    if (capture.bytes.size() > kNetworkMaxInlineBytes && policy == NetworkInlinePolicy::RequireInline) {
        return NetworkSubmitStatus::NeedsBlob;
    }
    if (queued_ == queue_.size() || summary.capturedLength > payloadRing_.size() - queuedPayloadBytes_) {
        AddCount(pendingLoss_.queueDropped, pendingLoss_.queueCounterSaturated, 1);
        return NetworkSubmitStatus::QueueFull;
    }
    auto& slot = queue_[(head_ + queued_) % queue_.size()];
    slot.flow = observation;
    slot.capture = summary;
    if (summary.capturedLength != 0) {
        const auto start = (payloadHead_ + queuedPayloadBytes_) % payloadRing_.size();
        const auto first = std::min<std::size_t>(summary.capturedLength, payloadRing_.size() - start);
        std::copy_n(capture.bytes.begin(), first, payloadRing_.data() + start);
        const auto second = summary.capturedLength - first;
        if (second != 0) std::copy_n(capture.bytes.data() + first, second, payloadRing_.data());
        queuedPayloadBytes_ += summary.capturedLength;
    }
    ++queued_;
    return NetworkSubmitStatus::Queued;
}

bool NetworkEvidenceArchive::ReportSourceLoss(const NetworkEvidenceBinding& binding,
    std::optional<std::uint64_t> delta) noexcept
{
    if (closed_ || state_.result.status != SegmentWriteStatus::Ok || !Matches(binding_, binding)) return false;
    if (delta) {
        AddCount(pendingLoss_.sourceLost, pendingLoss_.sourceCounterSaturated, *delta);
    } else {
        pendingLoss_.sourceLossUnquantified = true;
    }
    return true;
}

NetworkArchiveReceipt NetworkEvidenceArchive::Receipt() const noexcept
{
    auto receipt = state_;
    receipt.queuedObservations = queued_;
    receipt.queuedPayloadBytes = queuedPayloadBytes_;
    receipt.pendingLoss = pendingLoss_;
    return receipt;
}

NetworkArchiveReceipt NetworkEvidenceArchive::Append(const std::vector<StoredRecord>& records,
    std::optional<QpcRange> qpc)
{
    state_.result = writer_.AppendBlock(records, qpc);
    state_.writtenBytes = writer_.WrittenBytes();
    if (state_.result.status == SegmentWriteStatus::Ok) {
        previousSequence_ = records.back().sequence;
        state_.lastWrittenSequence = previousSequence_;
    }
    return Receipt();
}

NetworkArchiveReceipt NetworkEvidenceArchive::Drain()
{
    if (closed_ || state_.result.status != SegmentWriteStatus::Ok) return Receipt();
    const bool hasLoss = HasLoss(pendingLoss_);
    const auto count = std::min(queued_, kNetworkBatchRecords - (hasLoss ? 1u : 0u));
    const auto recordCount = count + (hasLoss ? 1u : 0u);
    if (recordCount == 0) return Receipt();
    if (recordCount > kMaxSequence - previousSequence_) {
        state_.result = {SegmentWriteStatus::InvalidInput, {SegmentIssue::Sequence, state_.writtenBytes}};
        return Receipt();
    }
    std::vector<StoredRecord> records;
    records.reserve(recordCount);
    std::optional<QpcRange> qpc;
    std::size_t batchPayloadBytes = 0;
    for (std::size_t i = 0; i < count; ++i) {
        const auto& slot = queue_[(head_ + i) % queue_.size()];
        const auto start = (payloadHead_ + batchPayloadBytes) % payloadRing_.size();
        const auto first = std::min<std::size_t>(slot.capture.capturedLength, payloadRing_.size() - start);
        records.push_back(Pack(previousSequence_ + i + 1, FlowMetadata(binding_, slot.flow, slot.capture),
            {payloadRing_.data() + start, first}, {payloadRing_.data(), slot.capture.capturedLength - first}));
        batchPayloadBytes += slot.capture.capturedLength;
        AddQpc(qpc, slot.flow.receiveQpc);
    }
    if (hasLoss) records.push_back(Pack(previousSequence_ + recordCount, LossMetadata(binding_, pendingLoss_)));
    if (Append(records, qpc).result.status == SegmentWriteStatus::Ok) {
        head_ = (head_ + count) % queue_.size();
        queued_ -= count;
        payloadHead_ = (payloadHead_ + batchPayloadBytes) % payloadRing_.size();
        queuedPayloadBytes_ -= batchPayloadBytes;
        pendingLoss_ = {};
    }
    return Receipt();
}

NetworkArchiveReceipt NetworkEvidenceArchive::Flush() noexcept
{
    if (closed_ || state_.result.status != SegmentWriteStatus::Ok) return Receipt();
    state_.result = writer_.Flush();
    if (state_.result.status == SegmentWriteStatus::Ok) {
        state_.flushedBytes = writer_.FlushedBytes();
        state_.lastFlushedSequence = state_.lastWrittenSequence;
        state_.eofFlushed = state_.eofWritten;
    }
    return Receipt();
}

NetworkArchiveReceipt NetworkEvidenceArchive::Finish(NetworkArchiveEnd end)
{
    if (closed_ || state_.result.status != SegmentWriteStatus::Ok) return Receipt();
    if (!ValidEnd(end)) {
        auto result = Receipt();
        result.result = {SegmentWriteStatus::InvalidInput, {SegmentIssue::RecordSchema, result.writtenBytes}};
        return result;
    }
    while (queued_ != 0 || HasLoss(pendingLoss_)) {
        if (Drain().result.status != SegmentWriteStatus::Ok) return Receipt();
    }
    if (previousSequence_ == kMaxSequence) {
        state_.result = {SegmentWriteStatus::InvalidInput, {SegmentIssue::Sequence, state_.writtenBytes}};
        return Receipt();
    }
    if (Append({Pack(previousSequence_ + 1, EndMetadata(binding_, end))}, {}).result.status != SegmentWriteStatus::Ok) {
        return Receipt();
    }
    state_.eofWritten = true;
    Flush();
    state_.result = writer_.Close();
    closed_ = true;
    return Receipt();
}

NetworkArchiveRecovery ScanOpenNetworkEvidence(void* file, const NetworkEvidenceBinding& binding,
    std::uint64_t segmentOrdinal, std::optional<std::uint64_t> endOffset, const NetworkFlowBlockVisitor& visitor)
{
    NetworkArchiveRecovery result;
    if (!ValidBinding(binding) || segmentOrdinal == 0) {
        result.framing.status = SegmentScanStatus::Corrupt;
        result.framing.error = {SegmentIssue::Identity};
        return result;
    }
    const SegmentScanOptions options{ForSegment(binding, segmentOrdinal), endOffset, std::nullopt};
    result.framing = ScanOpenSegment(file, options, [&](const BlockInfo& block, const std::vector<RecordView>& records) {
        if (result.eof || records.size() > kNetworkBatchRecords) {
            result.invalidMetadataOffset = block.offset;
            return false;
        }
        std::vector<NetworkArchivedFlow> rows;
        rows.reserve(records.size());
        NetworkLoss loss;
        std::optional<NetworkArchiveEnd> eof;
        std::optional<QpcRange> qpc;
        for (std::size_t i = 0; i < records.size(); ++i) {
            const auto& record = records[i];
            const auto before = rows.size();
            if (!Decode(record, binding, rows, loss, eof) || (eof && records.size() != 1) ||
                (HasLoss(loss) && i + 1 != records.size())) {
                result.invalidMetadataOffset = record.offset;
                return false;
            }
            if (rows.size() != before) AddQpc(qpc, rows.back().observation.receiveQpc);
        }
        if (!SameQpc(qpc, block.receiveQpc)) {
            result.invalidMetadataOffset = block.offset;
            return false;
        }
        result.checkedBytes = block.endOffset;
        AddLoss(result.loss, loss);
        result.eof = eof;
        if (visitor && !rows.empty()) visitor(block, rows);
        return true;
    });
    if (result.checkedBytes == 0 && result.framing.header) result.checkedBytes = kSegmentHeaderBytes;
    return result;
}

} // namespace ks::cli::action_analyze::archive
