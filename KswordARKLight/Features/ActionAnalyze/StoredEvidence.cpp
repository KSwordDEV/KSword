#include "StoredEvidence.h"

#include "../../Core/Win32Lean.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectApiCheckpoint.h"
#include "../../../shared/evidence/EvidenceJson.h"

#include <algorithm>
#include <array>
#include <deque>
#include <iterator>
#include <string_view>

namespace Ksword::Features::ActionAnalyze {
namespace {

using Bytes = std::span<const std::uint8_t>;
using namespace Ksword::Evidence;
namespace Archive = ks::cli::action_analyze::archive;

constexpr std::size_t kSegmentHeaderBytes = 96;
constexpr std::size_t kBlockHeaderBytes = 80;
constexpr std::size_t kRecordHeaderBytes = 32;
constexpr std::size_t kEventCoreBytes = 128;
constexpr std::size_t kJsonPreviewBytes = 4096;
constexpr std::size_t kHexPreviewBytes = 128;

std::uint64_t Little(Bytes bytes, std::size_t offset, unsigned width) {
    std::uint64_t value = 0;
    for (unsigned index = 0; index < width; ++index) {
        value |= static_cast<std::uint64_t>(bytes[offset + index]) << (8 * index);
    }
    return value;
}

bool StartsWith(Bytes bytes, std::string_view text) {
    return std::equal(text.begin(), text.end(), bytes.begin());
}

std::uint32_t Crc32c(Bytes bytes) {
    static constexpr auto table = [] {
        std::array<std::uint32_t, 256> values{};
        for (std::size_t index = 0; index < values.size(); ++index) {
            auto value = static_cast<std::uint32_t>(index);
            for (unsigned bit = 0; bit < 8; ++bit) {
                value = (value >> 1) ^ ((value & 1) ? 0x82F63B78U : 0U);
            }
            values[index] = value;
        }
        return values;
    }();
    std::uint32_t crc = 0xffffffffU;
    for (const auto byte : bytes) crc = table[(crc ^ byte) & 0xffU] ^ (crc >> 8);
    return crc ^ 0xffffffffU;
}

std::string Uuid(Bytes bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index == 4 || index == 6 || index == 8 || index == 10) out += '-';
        out += digits[bytes[index] >> 4];
        out += digits[bytes[index] & 0xf];
    }
    return out;
}

bool SupportedJsonValues(const JsonValue& value, unsigned containerDepth) {
    if (const auto* object = value.asObject()) {
        return containerDepth < 32 && std::all_of(object->begin(), object->end(),
            [=](const auto& item) { return SupportedJsonValues(item.second, containerDepth + 1); });
    }
    if (const auto* array = value.asArray()) {
        return containerDepth < 32 && std::all_of(array->begin(), array->end(),
            [=](const auto& item) { return SupportedJsonValues(item, containerDepth + 1); });
    }
    if (value.type() == JsonType::UInt) {
        std::uint64_t number = 0;
        return value.tryGetU64(number) && number <= UINT32_MAX;
    }
    if (value.type() == JsonType::Int) {
        std::int64_t number = 0;
        return value.tryGetI64(number) && number >= INT32_MIN;
    }
    return true;
}

bool HasLeadingZero(std::string_view text) {
    bool inString = false;
    for (std::size_t index = 0; index < text.size(); ++index) {
        const auto current = text[index];
        if (current == '"') inString = !inString;
        else if (inString && current == '\\' && index + 1 < text.size()) ++index;
        else if (!inString && current == '0' && index + 1 < text.size() &&
            text[index + 1] >= '0' && text[index + 1] <= '9' &&
            (index == 0 || text[index - 1] < '0' || text[index - 1] > '9')) return true;
    }
    return false;
}

// 把已通过 UTF-8 校验的正文转换成有界预览，保留原始 JSON 拼写。
void AppendJsonPreview(Bytes bytes, std::wstring& preview) {
    auto end = bytes.size(); // 显示的末端必须位于完整 UTF-8 字符边界。
    if (end > kJsonPreviewBytes) {
        end = kJsonPreviewBytes;
        while ((bytes[end] & 0xc0) == 0x80) {
            --end;
        }
    }
    const auto* data = reinterpret_cast<const char*>(bytes.data()); // 已验证的 UTF-8 字节。
    const auto length = static_cast<int>(end); // Win32 转码输入长度。
    const int units = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data, length, nullptr, 0);
    std::wstring text(static_cast<std::size_t>(units), L'\0'); // 本次转码后的宽字符正文。
    ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data, length, text.data(), units);
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == L'\n' && (i == 0 || text[i - 1] != L'\r')) {
            preview += L'\r';
        }
        preview += text[i];
    }
    if (end < bytes.size()) {
        preview += L"\r\n[JSON 预览截断]";
    }
}

bool ReadJsonObject(Bytes bytes, std::wstring* preview, EvidenceRecord* event = nullptr,
    JsonValue* metadata = nullptr) {
    constexpr unsigned kMaxJson = 4 * 1024 * 1024;
    if (bytes.empty() || bytes.size() > kMaxJson) return false;
    const auto* data = reinterpret_cast<const char*>(bytes.data());
    const int length = static_cast<int>(bytes.size());
    if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data, length, nullptr, 0) == 0) return false;
    JsonLimits limits;
    limits.maxTotalBytes = kMaxJson;
    limits.maxDepth = 32;
    limits.maxStringBytes = 65536;
    const std::string_view input(data, bytes.size());
    if (input.starts_with("\xef\xbb\xbf") || HasLeadingZero(input)) return false;
    auto parsed = ParseJson(input, limits);
    if (!parsed.ok() || !parsed.value.asObject() || !SupportedJsonValues(parsed.value, 0)) return false;
    if (event) {
        const auto headerId = [&](std::string_view key) -> std::optional<std::uint32_t> {
            const auto* field = parsed.value.find(key);
            if (!field) return {};
            const auto* type = field->find("type");
            const auto* state = field->find("state");
            const auto* value = field->find("value");
            std::string typeName, stateName;
            std::uint64_t number = 0;
            if (type && type->tryGetString(typeName) && typeName == "u32" &&
                state && state->tryGetString(stateName) && stateName == "known" &&
                value && (value->type() == JsonType::UInt || value->type() == JsonType::Int) &&
                value->tryGetU64(number) && number <= UINT32_MAX) return static_cast<std::uint32_t>(number);
            return {};
        };
        event->headerPid = headerId("source.headerPid");
        event->headerTid = headerId("source.headerTid");
    }
    if (metadata) {
        *metadata = std::move(parsed.value); // 将本次已校验的同一正文交给 ETW 投影。
    }
    if (preview) {
        AppendJsonPreview(bytes, *preview);
    }
    return true;
}

std::wstring HexPreview(Bytes bytes) {
    static constexpr wchar_t digits[] = L"0123456789abcdef";
    const auto count = (std::min)(bytes.size(), kHexPreviewBytes);
    std::wstring result;
    for (const auto byte : bytes.first(count)) {
        if (!result.empty()) result += L' ';
        result += digits[byte >> 4];
        result += digits[byte & 0xf];
    }
    if (count == 0) result = L"（空）";
    if (count < bytes.size()) result += L" … [字节预览截断]";
    return result;
}

// 把已解封的线索和原包写入待发布行；序号的显示口径由核验完成的读侧补齐。
void SetApiCluePreview(EvidenceRecord& row, const ArchivedApiMonitorClue& clue, Bytes bytes) {
    row.apiClue = clue.clue->api;
    row.apiFamily.assign(clue.clue->family.begin(), clue.clue->family.end());
    row.apiSourceSequence = clue.sourceSequence;
    row.headerPid = clue.packet.pid;
    row.headerTid = clue.packet.tid;
    row.memoryWriteReturn = ReadApiMonitorMemoryWriteReturn(clue.packet);
    row.behaviorObservation = Ksword::ActionAnalyze::Rules::ReadApiBehaviorObservation(clue.packet);
    row.apiTransfer = Ksword::Evidence::ReadApiInjectionFields(clue.packet);
    if (row.apiTransfer) {
        row.apiTransferOutcome = Ksword::Evidence::ApiInjectionCallOutcome(clue.packet, *row.apiTransfer);
    }
    row.apiApc = Ksword::Evidence::ReadApiApcFields(clue.packet); // AAAP1 与写入／创建参数分别解码。
    if (row.apiApc)
    {
        row.apcOutcome = Ksword::Evidence::ApiApcCallOutcome(clue.packet);
    }
    // 只投影当前包的独立协议，不扩展关联器或目标控制资格。
    row.apiContext = Ksword::Evidence::ReadApiContextFields(clue.packet);
    if (row.apiContext)
    {
        row.contextOutcome = Ksword::Evidence::ApiContextCallOutcome(clue.packet);
    }
    row.apiSectionMap = Ksword::Evidence::ReadApiSectionMapFields(clue.packet);
    row.apiMemoryLifecycle = Ksword::Evidence::ReadApiMemoryLifecycleFields(clue.packet);
    if (row.apiMemoryLifecycle)
    {
        row.memorySourceSession = clue.packet.sessionIdentity; // 来源会话与目标强实例分开显示。
    }
    if (row.apiSectionMap)
    {
        row.sectionMapOutcome = Ksword::Evidence::ApiSectionMapCallOutcome(clue.packet);
    }
    // 内联区是 Stored raw 负载的末尾。原包偏移相对于这条记录实际所属的段文件。
    const auto packetOffset = row.offset + kRecordHeaderBytes + row.payloadBytes - bytes.size();
    row.preview = L"FILETIME：" +
        std::to_wstring(clue.packet.timestamp100ns) + L"\r\n内联原包字节偏移：" + std::to_wstring(packetOffset) +
        L"    原包长度：" + std::to_wstring(bytes.size()) + L" B\r\n";
    // 新版包的已采字段在同一详情中单独显示，旧摘要不能把这些字段重新标成未知。
    if (row.apiMemoryLifecycle)
    {
        row.preview += L"内存生命周期仅记录原请求及返回；释放全区、分配代次、后续执行与因果未知。\r\n";
    }
    else if (row.apiContext || row.apiSectionMap)
    {
        row.preview += L"请求与返回字段见本次 API 详情；未证明后续生效、写入、别名传播或执行。\r\n";
    }
    else if (row.apiApc)
    {
        row.preview += L"APC 参数见本次 API 字段；接受入队不证明投递或执行。\r\n";
    }
    else if (row.apiTransfer)
    {
        row.preview += L"目标身份与写入范围见本次 API 字段；实际执行和跨事件归因未知。\r\n";
    }
    else
    {
        row.preview += L"目标身份、实际写入范围、执行和归因未知。\r\n";
    }
    row.preview += HexPreview(bytes);
}

// 将已核验的输入类型和序号写入原生详情，尾记声明只在旧导入段上显示。
void SetApiClueSourcePreview(EvidenceRecord& row, std::optional<ApiMonitorArchiveSource> source, bool importTail) {
    row.apiArchiveSource = source;
    std::wstring fields; // 详情首部与原包预览共用同一个可复制文本。
    if (importTail && source && *source != ApiMonitorArchiveSource::LegacyUnspecified) {
        const auto name = ApiMonitorArchiveSourceName(*source); // 与 CLI 共用的 ASCII 来源标识。
        fields = L"归档输入类型（尾记声明）：" + std::wstring(name.begin(), name.end()) + L"\r\n";
    }
    fields += source == ApiMonitorArchiveSource::CooperativePipe ? L"合作流水号（非 JSONL 行号）：" : L"源归档行号：";
    row.preview.insert(0, fields + std::to_wstring(row.apiSourceSequence) + L"\r\n");
}

// 普通原始行保留有界 JSON 与原包预览，不附加分类或关系。
std::wstring RawPreview(Bytes metadata, Bytes inlineData) {
    std::wstring preview = L"原始记录元数据（归档 JSON）\r\n";
    AppendJsonPreview(metadata, preview);
    preview += L"\r\n\r\n内联原始字节（" + std::to_wstring(inlineData.size()) + L" 字节）\r\n" + HexPreview(inlineData);
    return preview;
}

// 解码一个已通过封装检查的记录，并按需要构造独立预览。
std::string_view DecodeRecord(Bytes payload, EvidenceRecord& row, bool show, bool rawStream,
    const Archive::SegmentIdentity& identity, bool& apiImport, ApiMonitorClueReadback& api,
    bool& showRow, SegmentEvidence& out, bool legacyFirstRecord,
    Ksword::Evidence::ApiTransferCandidateWindow<EvidenceRecord>& transfers) {
    if (row.schemaVersion != 1 || (row.type != 3 && row.type != 4)) {
        if (apiImport) return "raw.apiImportRecord";
        if (show) row.preview = L"不透明负载（十六进制）\r\n" + HexPreview(payload);
        return {};
    }
    if (row.type == 3) {
        if (payload.size() < 4) return "raw.length";
        const auto jsonBytes = static_cast<std::size_t>(Little(payload, 0, 4));
        if (jsonBytes > payload.size() - 4) return "raw.length";
        JsonValue metadata; // 识别 API、ETW 和网络记录的原始元数据。
        const auto jsonData = payload.subspan(4, jsonBytes); // 已验证的归档 JSON 子范围。
        if (!ReadJsonObject(jsonData, nullptr, nullptr, rawStream ? &metadata : nullptr)) return "raw.json";
        const auto inlineData = payload.subspan(4 + jsonBytes); // 已由正文边界验证的内联数据。
        std::string kindName;
        if (rawStream) {
            if (const auto* kind = metadata.find("kind")) kind->tryGetString(kindName);
            // 已停用的历史来源不得降级为普通原始记录。
            if (kindName == "sysmon-retained-plan-v1" || kindName == "sysmon-event8-v2-observation" ||
                kindName == "sysmon-retained-end-v1") return kUnsupportedRawSource;
            // 这里只分派段首计划。任何回调行都不得由通用预览发布，独立段也不能替代采样绑定校验。
            if (kindName == "kswordark-callback-thread-create-plan-v1") {
                return legacyFirstRecord ? kCallbackProjectRequired : kCallbackProjectOnly;
            }
            if (kindName == "kswordark-callback-thread-create-observation-v1" ||
                kindName == "kswordark-callback-thread-create-end-v1") return "raw.callbackPlanMissing";
        }
        if (rawStream && (row.sequence == 1 || legacyFirstRecord)) {
            if (legacyFirstRecord && kindName == Ksword::ActionAnalyze::kApiFollowPlanKind) {
                out.apiFollowRequiresCheckpoint = metadata.find("checkpointRequired") != nullptr;
                return {}; // 只识别段首跟随计划，直接退出，不投影此块或后续块。
            }
            if (row.sequence == 1) {
                apiImport = apiImport || IsApiMonitorClueImport(metadata);
                const auto* duration = metadata.find("durationMs"); // 零表示无预设时限。
                std::uint64_t milliseconds = 0; // 只接受非负整数型时长。
                out.continuousEtwPlan = kindName == "etw-capture-plan-v1" && duration && duration->type() == JsonType::UInt &&
                    duration->tryGetU64(milliseconds) && milliseconds == 0;
            }
        }
        if (apiImport) {
            std::optional<ArchivedApiMonitorClue> clue; // 尾记只更新回读状态，省略 UI 行。
            const std::string_view original(reinterpret_cast<const char*>(inlineData.data()), inlineData.size());
            if (row.sequence != api.clues + 1 || !api.Accept(metadata, original, clue)) return "raw.apiImportRecord";
            showRow = show && clue.has_value();
            if (showRow) {
                SetApiCluePreview(row, *clue, inlineData);
                transfers.Accept(*clue, row, row.segmentOrdinal, row.sequence); // 独立文件只在本段串链。
            }
            return {};
        }
        if (rawStream) {
            const auto* record = metadata.find("record"); // 丢失摘要与尾记保留普通原始行。
            std::string recordName;
            if (kindName == "ksword.actionAnalyze.network.v1" &&
                record && record->tryGetString(recordName) && recordName == "flow") {
                const Archive::RecordView view{row.type, row.schemaVersion, row.flags, row.sequence,
                    row.offset, payload.data(), row.payloadBytes, true}; // 本条的封装、边界与 CRC 已通过。
                if (!show) {
                    return Archive::ProjectNetworkFlowRecord(identity, view) ? "" : "raw.networkFlow";
                }
                row.network = Archive::PreviewStoredNetworkFlow(identity, view);
                if (!row.network) {
                    return "raw.networkFlow";
                }
                row.receiveQpc = row.network->flow.observation.receiveQpc;
                return {};
            }
        }
        if (show && rawStream) {
            row.etw = ReadArchivedEtwObservation(metadata, inlineData.size());
            if (row.etw) {
                row.headerPid = row.etw->headerPid;
                row.headerTid = row.etw->headerTid;
                row.receiveQpc = row.etw->receiveQpc;
            }
        }
        if (show) row.preview = RawPreview(jsonData, inlineData);
        return {};
    }

    if (apiImport) return "raw.apiImportRecord";
    if (payload.size() < kEventCoreBytes || Little(payload, 124, 4) != payload.size() - kEventCoreBytes) {
        return "event.length";
    }
    const auto bits = Little(payload, 120, 4);
    if (bits & ~2047ULL) return "event.validityBits";
    const auto source = Little(payload, 16, 8);
    const auto epoch = Little(payload, 24, 8);
    if (source == 0 || epoch == 0) return "event.requiredId";
    constexpr std::array<std::size_t, 11> offsets{ 8, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104 };
    constexpr std::array<const wchar_t*, 11> labels{ L"主原始记录序号", L"生产者序号", L"来源原始时间戳",
        L"接收 QPC", L"执行者进程对象 ID", L"目标进程对象 ID", L"观察线程对象 ID", L"操作字典 ID",
        L"采集修订字典 ID", L"生效修订字典 ID", L"覆盖字典 ID" };
    for (std::size_t index = 0; index < offsets.size(); ++index) {
        const auto value = Little(payload, offsets[index], 8);
        const bool present = (bits & (1ULL << index)) != 0;
        if ((!present && value != 0) || (present && index >= 4 && value == 0)) return "event.validityValue";
        if (show) row.preview += std::wstring(labels[index]) + L" = " +
            (present ? std::to_wstring(value) : L"无有效值") + L"\r\n";
    }
    std::wstring json;
    if (!ReadJsonObject(payload.subspan(kEventCoreBytes), show ? &json : nullptr, show ? &row : nullptr)) return "event.json";
    row.eventOrdinal = Little(payload, 0, 8);
    row.sourceDictionaryId = source;
    row.epochDictionaryId = epoch;
    if (bits & (1 << 0)) row.rawSequence = Little(payload, 8, 8);
    if (bits & (1 << 3)) row.receiveQpc = Little(payload, 48, 8);
    if (bits & (1 << 4)) row.actorObjectId = Little(payload, 56, 8);
    if (bits & (1 << 5)) row.targetObjectId = Little(payload, 64, 8);
    if (bits & (1 << 6)) row.threadObjectId = Little(payload, 72, 8);
    row.eventKind = static_cast<std::uint32_t>(Little(payload, 112, 4));
    row.category = static_cast<std::uint16_t>(Little(payload, 116, 2));
    if (show) row.preview += L"事件种类编号 = " + std::to_wstring(Little(payload, 112, 4)) +
        L"\r\n类别编号 = " + std::to_wstring(Little(payload, 116, 2)) +
        L"\r\n阶段编号 = " + std::to_wstring(Little(payload, 118, 1)) +
        L"\r\n时钟域编号 = " + std::to_wstring(Little(payload, 119, 1)) +
        L"\r\n\r\n事件字段（归档 JSON）\r\n" + json;
    return {};
}

} // namespace

// 从只读输入流投影行。项目已提交段可要求最近窗口，诊断用独立段保留早期行。
SegmentEvidence ReadStoredEvidence(std::uint64_t size, const ReadExact& read, const SegmentIdentity* expected,
    StoredReadMode mode) {
    const bool keepLatest = mode == StoredReadMode::KeepLatest;
    SegmentEvidence out;
    out.fileBytes = size;
    const auto fail = [&](std::string_view diagnostic, std::uint64_t offset) {
        out.diagnostic = diagnostic;
        out.failureOffset = offset;
    };
    const auto readAt = [&](std::span<std::uint8_t> bytes, std::uint64_t offset) {
        out.systemError = read(bytes);
        if (out.systemError) fail("file.read", offset);
        return out.systemError == 0;
    };
    if (size < kSegmentHeaderBytes) fail("truncated", 0);
    else if (size > 1024ULL * 1024 * 1024) fail("segment.size", 0);
    if (!out.diagnostic.empty()) return out;

    std::array<std::uint8_t, kSegmentHeaderBytes> segment{};
    if (!readAt(segment, 0)) return out;
    const Bytes header(segment);
    if (!StartsWith(header, std::string_view("KSAASEG\0", 8))) fail("segment.magic", 0);
    else if (Little(header, 92, 4) != Crc32c(header.first(92))) fail("segment.headerCrc", 92);
    else if (Little(header, 8, 2) != 1) fail("segment.major", 8);
    else if (Little(header, 10, 2) != 0) fail("segment.minor", 10);
    else if (Little(header, 12, 4) != kSegmentHeaderBytes) fail("segment.headerBytes", 12);
    else if (Little(header, 16, 4) != 0) fail("segment.requiredFlags", 16);
    else if (std::any_of(header.begin() + 72, header.begin() + 92, [](auto b) { return b != 0; })) {
        fail("segment.reserved", 72);
    }
    if (!out.diagnostic.empty()) return out;

    const SegmentIdentity identity{ Uuid(header.subspan(32, 16)), Uuid(header.subspan(48, 16)),
        static_cast<std::uint32_t>(Little(header, 20, 4)), Little(header, 24, 8) };
    if (identity.streamKind < 1 || identity.streamKind > 4 || identity.ordinal == 0 ||
        (expected && identity != *expected)) {
        fail("segment.identity", 20);
        return out;
    }
    out.identity = identity;
    Archive::SegmentIdentity archiveIdentity{static_cast<Archive::StreamKind>(identity.streamKind),
        identity.ordinal}; // 使用同一已验证段头的 RFC 顺序身份，直接交给共用正文投影。
    std::copy_n(header.begin() + 32, archiveIdentity.project.size(), archiveIdentity.project.begin());
    std::copy_n(header.begin() + 48, archiveIdentity.sample.size(), archiveIdentity.sample.begin());
    out.createdUtc100ns = Little(header, 64, 8);
    out.framedBytes = out.decodedPrefixBytes = kSegmentHeaderBytes;
    std::optional<std::uint64_t> previousBlock, previousSequence;
    std::string_view firstDecodeError;
    std::uint64_t firstDecodeErrorOffset = 0;
    bool apiImport = false; // 由首条原始记录明确声明的 API 导入格式。
    ApiMonitorClueReadback api; // 共享尾记和来源序号校验状态。
    Ksword::Evidence::ApiTransferCandidateWindow<EvidenceRecord> transfers(
        {identity.projectId, identity.sampleId, {}, {}}); // 发布必须等待整段和尾记通过。
    std::deque<EvidenceRecord> recentRows; // 最近窗口仅在整段核验完成后交付。

    while (out.framedBytes < size) {
        const auto start = out.framedBytes;
        if (size - start < kBlockHeaderBytes) { fail("truncated", start); break; }
        if (start + kBlockHeaderBytes > kEvidenceScanBytes) { fail("view.scanLimit", start); break; }
        std::array<std::uint8_t, kBlockHeaderBytes> block{};
        if (!readAt(block, start)) break;
        const auto count = Little(block, 12, 4);
        const auto blockOrdinal = Little(block, 16, 8);
        const auto stored = Little(block, 44, 4);
        const auto decoded = Little(block, 40, 4);
        const auto flags = Little(block, 10, 2);
        if (!StartsWith(block, "AAB1")) fail("block.magic", start);
        else if (Little(block, 76, 4) != Crc32c(Bytes(block).first(76))) fail("block.headerCrc", start + 76);
        else if (Little(block, 4, 2) != kBlockHeaderBytes || Little(block, 6, 2) != 1) fail("block.layout", start + 4);
        else if (Little(block, 8, 2) != 0) fail("block.codec", start + 8);
        else if ((flags & ~1ULL) || Little(block, 72, 4)) fail("block.flags", start + 10);
        else if (count < 1 || count > 32768) fail("block.recordCount", start + 12);
        else if (previousBlock && blockOrdinal <= *previousBlock) fail("block.ordinal", start + 16);
        else if (decoded > 8388608 || stored > 9437184 || stored != decoded) fail("block.length", start + 40);
        else if ((flags & 1) && Little(block, 48, 8) > Little(block, 56, 8)) fail("block.qpcRange", start + 48);
        const auto bodyOffset = start + kBlockHeaderBytes;
        if (!out.diagnostic.empty()) break;
        if (stored > size - bodyOffset) { fail("truncated", bodyOffset); break; }
        if (bodyOffset + stored > kEvidenceScanBytes) { fail("view.scanLimit", start); break; }

        std::vector<std::uint8_t> body(static_cast<std::size_t>(stored));
        if (!body.empty() && !readAt(body, bodyOffset)) break;
        const auto crc = Crc32c(body);
        if (crc != Little(block, 68, 4)) { fail("block.storedCrc", bodyOffset); break; }
        if (crc != Little(block, 64, 4)) { fail("block.decodedCrc", bodyOffset); break; }

        std::size_t position = 0, opaqueRequired = 0, opaqueOptional = 0;
        std::vector<EvidenceRecord> rows;
        auto sequence = previousSequence;
        std::string_view decodeError;
        std::uint64_t decodeOffset = 0;
        for (std::uint64_t index = 0; index < count; ++index) {
            const auto recordOffset = bodyOffset + position;
            if (body.size() - position < kRecordHeaderBytes) { fail("record.length", recordOffset); break; }
            const auto record = Bytes(body).subspan(position, kRecordHeaderBytes);
            EvidenceRecord row;
            row.segmentOrdinal = identity.ordinal;
            row.offset = recordOffset;
            row.blockOrdinal = blockOrdinal;
            row.type = static_cast<std::uint16_t>(Little(record, 4, 2));
            row.schemaVersion = static_cast<std::uint16_t>(Little(record, 6, 2));
            row.flags = static_cast<std::uint32_t>(Little(record, 8, 4));
            row.payloadBytes = static_cast<std::uint32_t>(Little(record, 12, 4));
            row.sequence = Little(record, 16, 8);
            const auto total = Little(record, 0, 4);
            if (Little(record, 28, 4) != Crc32c(record.first(28))) fail("record.headerCrc", recordOffset + 28);
            else if (total != kRecordHeaderBytes + static_cast<std::uint64_t>(row.payloadBytes) ||
                total > body.size() - position) fail("record.length", recordOffset);
            else if (row.flags & ~1U) fail("record.flags", recordOffset + 8);
            else if ((sequence && row.sequence <= *sequence) || (index == 0 && row.sequence != Little(block, 24, 8)) ||
                (index + 1 == count && row.sequence != Little(block, 32, 8))) fail("record.sequence", recordOffset + 16);
            if (!out.diagnostic.empty()) break;
            const auto payload = Bytes(body).subspan(position + kRecordHeaderBytes, row.payloadBytes);
            if (Little(record, 24, 4) != Crc32c(payload)) { fail("record.payloadCrc", recordOffset + 32); break; }

            const bool show = firstDecodeError.empty() && decodeError.empty() &&
                (keepLatest || apiImport || out.rows.size() + rows.size() < kEvidenceRows);
            bool showRow = show; // API 导入尾记不进入结果列表。
            const bool legacyFirstRecord = mode == StoredReadMode::LegacyProject && !previousBlock && index == 0;
            const auto error = DecodeRecord(payload, row, show, identity.streamKind == 1, archiveIdentity, apiImport, api, showRow, out,
                legacyFirstRecord, transfers);
            if (out.apiFollowRequiresCheckpoint.has_value()) return out;
            if (error == kUnsupportedRawSource || error == kCallbackProjectRequired ||
                error == kCallbackProjectOnly || error == "raw.callbackPlanMissing") {
                SegmentEvidence unsupported;
                unsupported.diagnostic = error;
                unsupported.failureOffset = recordOffset;
                return unsupported;
            }
            if (!error.empty() && decodeError.empty()) { decodeError = error; decodeOffset = recordOffset; }
            if (row.schemaVersion != 1 || (row.type != 3 && row.type != 4)) {
                if (row.flags & 1) ++opaqueRequired;
                else ++opaqueOptional;
            }
            if (showRow && error.empty()) {
                if (keepLatest || apiImport) {
                    if (recentRows.size() == kEvidenceRows) {
                        recentRows.pop_front();
                    }
                    recentRows.push_back(std::move(row));
                } else {
                    rows.push_back(std::move(row));
                }
            }
            sequence = Little(record, 16, 8);
            position += static_cast<std::size_t>(total);
        }
        if (!out.diagnostic.empty()) break;
        if (position != body.size()) { fail("block.trailingBytes", bodyOffset + position); break; }

        out.framedBytes = bodyOffset + stored;
        if (firstDecodeError.empty()) {
            if (decodeError.empty()) {
                out.decodedPrefixBytes = out.framedBytes;
                out.lastBlockOrdinal = blockOrdinal;
                out.lastSequence = sequence;
                out.rows.insert(out.rows.end(), std::make_move_iterator(rows.begin()), std::make_move_iterator(rows.end()));
            } else {
                firstDecodeError = decodeError;
                firstDecodeErrorOffset = decodeOffset;
            }
        }
        ++out.blocks;
        out.records += static_cast<std::size_t>(count);
        out.opaqueOptionalRecords += opaqueOptional;
        out.opaqueRequiredRecords += opaqueRequired;
        previousBlock = blockOrdinal;
        previousSequence = sequence;
    }

    // Keep the first payload failure even when later framing has its own failure.
    if (!firstDecodeError.empty()) {
        if (out.diagnostic.empty()) fail(firstDecodeError, firstDecodeErrorOffset);
        else out.diagnostic = std::string(firstDecodeError) + " @ " + std::to_string(firstDecodeErrorOffset) +
            " / " + out.diagnostic;
    }
    if (apiImport) {
        // 文件前缀可用于诊断，线索详情只在导入收尾及文件都有效时发布。
        if (out.diagnostic.empty() && !api.ended) fail("raw.apiImportEnd", out.decodedPrefixBytes);
        if (out.diagnostic.empty()) {
            out.apiClues = api.clues;
            // 只给通过整段核验的最近线索补上尾记声明和确切的序号口径。
            for (auto& row : recentRows) {
                SetApiClueSourcePreview(row, api.source, true);
            }
            out.transferCandidates.assign(transfers.Candidates().begin(), transfers.Candidates().end());
            out.transferCandidateCount = transfers.CandidateCount();
            out.apcTransferCandidates.assign(transfers.ApcCandidates().begin(), transfers.ApcCandidates().end());
            out.apcTransferCandidateCount = transfers.ApcCandidateCount();
            out.contextTransferCandidates.assign(transfers.ContextCandidates().begin(), transfers.ContextCandidates().end());
            out.contextTransferCandidateCount = transfers.ContextCandidateCount();
            out.sectionMapRequests.assign(transfers.Maps().begin(), transfers.Maps().end());
            out.evictedSectionMaps = transfers.EvictedMaps();
            for (auto& mapping : out.sectionMapRequests)
            {
                SetApiClueSourcePreview(mapping.row, api.source, true);
            }
            for (auto& candidate : out.contextTransferCandidates) // candidate 为完整导入通过后发布的双方原行。
            {
                SetApiClueSourcePreview(candidate.write, api.source, true);
                SetApiClueSourcePreview(candidate.context, api.source, true);
            }
            out.evictedTransferWrites = transfers.EvictedWrites();
            for (auto& candidate : out.apcTransferCandidates) // 导入尾记通过后同步双方来源。
            {
                SetApiClueSourcePreview(candidate.write, api.source, true);
                SetApiClueSourcePreview(candidate.queue, api.source, true);
            }
            for (auto& candidate : out.transferCandidates) {
                SetApiClueSourcePreview(candidate.write, api.source, true);
                SetApiClueSourcePreview(candidate.threadCreate, api.source, true);
            }
        } else {
            out.rows.clear();
        }
    }
    if ((keepLatest || apiImport) && out.diagnostic.empty()) {
        out.rows.assign(std::make_move_iterator(recentRows.begin()), std::make_move_iterator(recentRows.end()));
    }
    return out;
}

EvidenceRecord PreviewCommittedApiRecord(const Archive::BlockInfo& block, const Archive::DecodedRecord& record,
    const Archive::RawRecordV1& raw, std::uint64_t segmentOrdinal) {
    EvidenceRecord row; // 原始坐标来自正在验证的块和记录头。
    row.segmentOrdinal = segmentOrdinal;
    row.offset = record.recordOffset;
    row.blockOrdinal = block.ordinal;
    row.sequence = record.recordSequence;
    row.type = record.recordType;
    row.schemaVersion = record.recordSchemaVersion;
    row.flags = record.flags;
    row.payloadBytes = raw.inlineRawOffsetInPayload + raw.inlineRawBytes;
    const Bytes inlineData(reinterpret_cast<const std::uint8_t*>(raw.inlineRawData.data()), raw.inlineRawData.size());
    if (const auto clue = Ksword::ActionAnalyze::ReadCommittedApiClue(raw)) {
        SetApiCluePreview(row, *clue, inlineData);
    } else {
        const Bytes metadata(reinterpret_cast<const std::uint8_t*>(raw.metadataJson.data()), raw.metadataJson.size());
        row.preview = RawPreview(metadata, inlineData);
    }
    return row;
}

// 仅对已归类观测标注来源。旧检查点继续显示 JSONL 行号。
void ApplyCommittedApiClueSource(EvidenceRecord& row, ApiMonitorArchiveSource source) {
    if (!row.apiClue.empty()) {
        SetApiClueSourcePreview(row, source == ApiMonitorArchiveSource::LegacyUnspecified ? std::nullopt :
            std::optional{source}, false);
    }
}

SegmentEvidence OpenStoredEvidence(const std::wstring& path) {
    struct File {
        HANDLE handle;
        ~File() { if (handle != INVALID_HANDLE_VALUE) ::CloseHandle(handle); }
    } file{ ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN, nullptr) };
    if (file.handle == INVALID_HANDLE_VALUE) {
        SegmentEvidence error; // 单段入口的原生打开错误。
        error.systemError = ::GetLastError();
        error.diagnostic = "file.open";
        return error;
    }
    return ReadOpenStoredEvidence(file.handle, std::nullopt);
}

// 单段和项目回放复用投影。项目端点只在实际文件包含整个范围时才可用。
SegmentEvidence ReadOpenStoredEvidence(HANDLE file, std::optional<std::uint64_t> endOffset,
    const SegmentIdentity* expected, StoredReadMode mode) {
    SegmentEvidence error; // 无法取得文件范围时的只读回执。
    LARGE_INTEGER size{}; // 本次句柄的物理长度。
    if (::GetFileType(file) != FILE_TYPE_DISK) {
        error.diagnostic = "file.notDisk";
        return error;
    }
    if (!::GetFileSizeEx(file, &size)) {
        error.systemError = ::GetLastError();
        error.diagnostic = "file.size";
        return error;
    }
    const auto physicalBytes = static_cast<std::uint64_t>(size.QuadPart); // 包括未提交尾部。
    if (endOffset && *endOffset > physicalBytes) {
        error.fileBytes = physicalBytes;
        error.failureOffset = physicalBytes;
        error.diagnostic = "truncated";
        return error;
    }

    // 散列复核移动过游标，投影从同一文件的段头重新读取。
    if (!::SetFilePointerEx(file, LARGE_INTEGER{}, nullptr, FILE_BEGIN)) {
        error.systemError = ::GetLastError();
        error.diagnostic = "file.seek";
        return error;
    }
    auto result = ReadStoredEvidence(endOffset.value_or(physicalBytes), [&](std::span<std::uint8_t> buffer) {
        DWORD received = 0; // 此次 Win32 实读字节数。
        const auto count = static_cast<DWORD>(buffer.size()); // 已受段和块格式限额约束。
        if (!::ReadFile(file, buffer.data(), count, &received, nullptr)) return ::GetLastError();
        return received == count ? DWORD{0} : DWORD{ERROR_HANDLE_EOF};
    }, expected, mode);
    result.fileBytes = physicalBytes;
    BY_HANDLE_FILE_INFORMATION identity{}; // 详情显示的本地卷、文件和修改身份。
    if (::GetFileInformationByHandle(file, &identity)) {
        const auto combine = [](DWORD high, DWORD low) { return (static_cast<std::uint64_t>(high) << 32) | low; };
        result.fileIdentity = std::to_wstring(identity.dwVolumeSerialNumber) + L" / " +
            std::to_wstring(combine(identity.nFileIndexHigh, identity.nFileIndexLow)) + L" / " +
            std::to_wstring(combine(identity.ftLastWriteTime.dwHighDateTime, identity.ftLastWriteTime.dwLowDateTime));
    }
    return result;
}

} // namespace Ksword::Features::ActionAnalyze
