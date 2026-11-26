#include "ProjectApiCheckpoint.h"

#include "ProjectStorage.h"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <utility>

namespace Ksword::ActionAnalyze {

// 仅为本文件的检查点操作借用项目已经固定的目录链。
struct ProjectApiCheckpointAccess {
    // 借用已打开项目的根目录，项目关闭前有效。
    static const ProjectStorage::Directory* Root(const ProjectDocument& project)
    {
        return project.RootForRead();
    }
};

namespace {

namespace Archive = ks::cli::action_analyze::archive;
namespace Monitor = ks::winapi_monitor;
using namespace ProjectStorage;

constexpr char kMarkerKind[] = "api-archive-checkpoint-v1"; // raw-only 检查点类型。
constexpr char kIdentity[] = "archive-consistency-only"; // 限于存档内身份一致性。
constexpr std::uint64_t kMaxRawBytes = 512u << 10; // 256 个定长包及有限元数据。
constexpr std::uint64_t kMaxPackets = 256; // 与 CLI 分段积压上限一致。

// 从已校验的段号构造统一的 20 位文件名。
std::wstring MarkerName(std::uint64_t ordinal)
{
    const auto digits = std::to_wstring(ordinal); // 无符号 64 位最多 20 个十进制位。
    return std::wstring(20 - digits.size(), L'0') + digits + L".json";
}

// 读取严格的 JSON 无符号数，用于原计划里并非十进制字符串的有限字段。
bool ReadUInt(const JsonValue& value, std::string_view key, std::uint64_t& out)
{
    const auto* field = value.find(key); // 借用现有节点。
    return field && field->type() == JsonType::UInt && field->tryGetU64(out);
}

// 核对调用方传入的前序水位归属，拒绝跨段跳读及终段后追加。
bool NextSegment(std::string_view sampleId, std::uint64_t ordinal, const ProjectApiCheckpoint* previous)
{
    if (!previous) {
        return ordinal == 1;
    }
    return ordinal > 1 && previous->sampleId == sampleId && previous->ordinal == ordinal - 1 &&
        previous->rawEnd.lastSequence && previous->rawEnd.lastSequence < UINT64_MAX &&
        IsHash(previous->rawSha256) && !previous->planJson.empty() && !previous->finalSegment;
}

// 从同一项目快照读已登记的冻结描述。描述缺失与标记缺失分别返回。
ProjectResult ReadBoundSample(const ProjectDocument& project, std::string_view sampleId, SampleRecord& sample)
{
    const auto result = project.ReadSample(sampleId, sample); // 目录、描述与配置快照校验回执。
    return result.error == ProjectError::NotFound ? Failure(ProjectError::Corrupt, "apiCheckpointSampleMissing") : result;
}

// 冻结的单一源文件声明。重开从项目 raw 读取，不访问原 JSONL。
struct ApiSource {
    std::uint64_t pid = 0; // 文件与包头声明的调用者 PID。
    std::uint64_t creation = 0; // 声明的调用者创建 FILETIME。
    std::uint64_t sessionIdentity = 0; // 声明的 WinAPI 归档会话。
};

// 核对计划版本、冻结样本配置及来源字段，给逐包校验提供声明身份。
bool ReadPlan(const JsonValue& plan, const ProjectInfo& project, const SampleRecord& sample, ApiSource& source)
{
    const auto* session = plan.find("session"); // 跟随会话只作为历史档案身份。
    const auto* file = plan.find("file"); // 已授权文件的历史标识。
    const auto* required = plan.find(kApiFollowCheckpointField); // 旧跟随档没有此字段。
    bool checkpointRequired = false; // 此版的已提交段必须声明该要求。
    std::string epoch; // 计划和会话使用同一个代次。
    std::string fileId; // 文件 ID 的固定长度小写十六进制。
    std::uint64_t number = 0; // 检查归档文件和持续时间字段类型。
    return IsString(plan, "kind", kApiFollowPlanKind) && required && required->tryGetBool(checkpointRequired) &&
        checkpointRequired && IsString(plan, "identity", kIdentity) && IsString(plan, "projectId", project.projectId) &&
        IsString(plan, "revisionId", sample.info.revisionId) && IsString(plan, "snapshotId", sample.info.snapshotId) &&
        IsString(plan, "revisionHash", sample.revisionHash) && IsString(plan, "configSemanticHash", sample.configSemanticHash) &&
        GetUuid(plan, "sourceEpoch", epoch) && session && IsString(*session, "id", sample.info.sampleId) &&
        IsString(*session, "epoch", epoch) && file && GetString(*file, "fileId", fileId) && fileId.size() == 32 &&
        fileId.find_first_not_of("0123456789abcdef") == fileId.npos && GetNumber(*file, "volumeSerial", number) &&
        GetNumber(*file, "initialVisibleBytes", number) && ReadUInt(plan, "durationMs", number) &&
        ReadUInt(plan, "readerPid", source.pid) && source.pid && source.pid <= UINT32_MAX &&
        GetNumber(plan, "readerCreation100ns", source.creation) && source.creation &&
        GetNumber(plan, "sessionIdentity", source.sessionIdentity) && source.sessionIdentity;
}

// 核对下一行及原包。控制、覆盖和未分类包都计入连续的源行范围。
bool ReadPacket(const JsonValue& metadata, std::string_view bytes, const ApiSource& source, std::uint64_t previousSequence)
{
    Monitor::ApiMonitorEventPacket packet; // 从无对齐保证的字节复制协议包。
    std::uint64_t sequence = 0; // 源 JSONL 的一基行号。
    std::uint64_t creation = 0; // 每行保留的声明创建时间。
    if (!IsString(metadata, "kind", kApiFollowPacketKind) || bytes.size() != sizeof(packet) ||
        previousSequence == UINT64_MAX || !GetNumber(metadata, "sourceSequence", sequence) ||
        sequence != previousSequence + 1 || !GetNumber(metadata, "readerCreation100ns", creation) ||
        creation != source.creation) {
        return false;
    }
    std::memcpy(&packet, bytes.data(), sizeof(packet));
    return packet.size == sizeof(packet) && packet.version == Monitor::kProtocolVersion &&
        packet.pid == source.pid && packet.sessionIdentity == source.sessionIdentity &&
        (packet.eventKind <= static_cast<std::uint32_t>(Monitor::EventKind::IoCancel) || Monitor::isCoverageEvent(packet.eventKind)) &&
        packet.category <= static_cast<std::uint32_t>(Monitor::EventCategory::Gui) &&
        packet.resultKind <= static_cast<std::uint32_t>(Monitor::EventResultKind::StatusUnknown);
}

// 核对终段的源计数和身份，保留本端截止状态供读端展示。
bool ReadEnd(const JsonValue& end, const ApiSource& source, ProjectApiCheckpoint& draft)
{
    const auto* report = end.find("source"); // 跟随结束时归档的来源回执。
    std::uint64_t value = 0; // 逐项读取回执中的身份和计数。
    if (!report || !IsString(*report, "kind", "passive-api-archive") || !IsString(*report, "identity", kIdentity) ||
        !IsString(*report, "coverage", "unknown") || !IsNull(*report, "writerReceipt") ||
        !ReadUInt(*report, "readerPid", value) || value != source.pid ||
        !GetNumber(*report, "readerCreation100ns", value) || value != source.creation ||
        !GetNumber(*report, "sessionIdentity", value) || value != source.sessionIdentity ||
        !GetNumber(*report, "validatedRows", value) || value != draft.lastSourceSequence ||
        !GetString(end, "stopReason", draft.stopReason) || !IsText(draft.stopReason, 64) ||
        !GetString(*report, "state", draft.sourceState) || !IsText(draft.sourceState, 32)) {
        return false;
    }
    constexpr std::string_view states[]{"unopened", "reading", "at-tail", "partial-line", "sealed", "unconfirmed-end",
        "truncated-tail", "writer-failed", "receipt-mismatch", "source-changed", "identity-mismatch", "invalid-record",
        "read-failed", "cutoff", "unknown"}; // 与 CLI 跟随报告的来源状态枚举一致。
    const auto* reached = report->find("cutoffReached"); // 来源回执中的截止状态。
    std::uint64_t partial = 0; // 截止位置可能落在半行中间。
    if (std::find(std::begin(states), std::end(states), draft.sourceState) == std::end(states) ||
        !reached || !reached->tryGetBool(draft.sourceCutoffReached) ||
        draft.sourceCutoffReached != (draft.sourceState == "cutoff") || !GetNumber(*report, "partialLineBytes", partial)) {
        return false;
    }
    draft.partialLineBytes = partial;
    return true;
}

// 扫描限界前缀并读回散列。写端传入预期字节，读端可以同时暂存投影。
ProjectResult VerifyRaw(const ProjectDocument& project, const SampleRecord& sample, const ProjectApiCheckpoint* previous,
    std::span<const Archive::RawEvidenceInput> expected, const Archive::SegmentBodyVisitor& visitor,
    ProjectApiCheckpoint& draft)
{
    if (draft.rawEnd.byteOffset <= Archive::kSegmentHeaderBytes || draft.rawEnd.byteOffset > kMaxRawBytes ||
        !draft.rawEnd.blockOrdinal || !draft.rawEnd.lastSequence) {
        return Failure(ProjectError::Corrupt, "apiCheckpointRawRange");
    }

    const auto previousRaw = previous ? previous->rawEnd.lastSequence : 0; // 上一段 Stored 末序号。
    draft.previousSourceSequence = previous ? previous->lastSourceSequence : 0;
    draft.lastSourceSequence = draft.previousSourceSequence;
    draft.planRawSequence = previousRaw + 1;
    ApiSource source; // 从本段首条计划提取的完整来源声明。
    std::size_t count = 0; // 逐包比对时计入首尾元数据。
    bool seenPlan = false; // 中途失败不允许构造已提交的首段。
    Archive::RawEvidenceScanResult scan; // 同句柄的封装和正文检查结果。
    const ProjectRawEvidenceRead request{project.Info()->projectId, sample.info.sampleId, draft.ordinal,
        draft.rawEnd.byteOffset, previousRaw,
        [&](const auto& identity, const auto& block, const auto& records) {
            for (const auto& record : records) {
                const auto& raw = std::get<Archive::RawRecordV1>(record.body); // 已封装验证的本条记录。
                if (!expected.empty() && (count >= expected.size() || raw.metadataJson != expected[count].metadataJson ||
                        raw.inlineRawData != expected[count].inlineRawData)) {
                    return false;
                }
                ++count;
                const auto doc = Evidence::ParseJson(raw.metadataJson); // 定界元数据经二次解析用于语义回读。
                if (!doc.ok() || draft.finalSegment) {
                    return false;
                }
                if (!seenPlan) {
                    if (raw.inlineRawBytes || (previous && raw.metadataJson != previous->planJson) ||
                        !ReadPlan(doc.value, *project.Info(), sample, source)) {
                        return false;
                    }
                    if (const auto* mixed = doc.value.find("mixedEtw");
                        mixed && (!mixed->tryGetBool(draft.mixedEtw) || !draft.mixedEtw)) return false;
                    draft.planJson = raw.metadataJson;
                    seenPlan = true;
                } else if (IsString(doc.value, "kind", kApiFollowEndKind)) {
                    if (raw.inlineRawBytes || !ReadEnd(doc.value, source, draft)) {
                        return false;
                    }
                    draft.finalSegment = true;
                } else {
                    if (draft.lastSourceSequence - draft.previousSourceSequence >= kMaxPackets ||
                        !ReadPacket(doc.value, raw.inlineRawData, source, draft.lastSourceSequence)) {
                        return false;
                    }
                    ++draft.lastSourceSequence;
                }
            }
            // 调用方在整个段通过端点、摘要验证后才发布暂存的记录。
            return !visitor || visitor(identity, block, records);
        }, kMaxRawBytes};
    const auto result = project.ReadRawEvidenceSegment(request, scan, &draft.rawSha256); // 固定同一文件身份。
    if (result.error == ProjectError::NotFound) {
        return Failure(ProjectError::Corrupt, "apiCheckpointRawMissing");
    }
    if (!result) {
        return result;
    }
    if (!seenPlan || !scan.VerifiedBoundary(draft.rawEnd) || draft.rawSha256.empty() ||
        (!expected.empty() && count != expected.size()) ||
        (!draft.finalSegment && draft.previousSourceSequence == draft.lastSourceSequence)) {
        return Failure(ProjectError::Corrupt, "apiCheckpointRawPrefix");
    }
    draft.rawFileBytes = scan.segment.framing.fileBytes;
    return {};
}

// 读取一个已命名标记，缺失时保留 NotFound 让上层报告中断水位。
ProjectResult ReadMarker(const Directory& root, std::string_view sampleId, std::uint64_t ordinal, JsonValue& marker)
{
    return Read(root, {L"samples", WideAscii(sampleId), L"checkpoints"}, MarkerName(ordinal), {}, marker);
}

} // namespace

ProjectResult ProbeApiFollowArchive(const ProjectDocument& project, std::string_view sampleId, ApiFollowArchiveKind& out)
{
    out = ApiFollowArchiveKind::Other;
    const auto* root = ProjectApiCheckpointAccess::Root(project); // 由当前项目固定的安全根目录。
    if (!root || !IsUuid(sampleId)) {
        return Failure(root ? ProjectError::InvalidArgument : ProjectError::NotOpen, "apiCheckpointSample");
    }
    JsonValue marker; // 只检查已命名的第一代类型，不产生提交水位。
    const auto first = ReadMarker(*root, sampleId, 1, marker); // ETW 标记由现有入口完整核对。
    if (first && IsString(marker, "kind", kMarkerKind)) {
        out = ApiFollowArchiveKind::Checkpointed;
        return {};
    }
    // 旧档与首标记缺失的新档，只检查首个完整块。错误类型的标记不能让跟随档降级。
    Archive::RawEvidenceScanResult ignored; // 探测有意在首个回调返回后停止。
    const ProjectRawEvidenceRead input{project.Info()->projectId, sampleId, 1, kMaxRawBytes, 0,
        [&](const auto&, const auto&, const auto& records) {
            if (!records.empty()) {
                const auto& raw = std::get<Archive::RawRecordV1>(records.front().body); // 已验证封装的首条正文。
                const auto doc = Evidence::ParseJson(raw.metadataJson); // 仅读版本字段以区分两类无标记档。
                if (doc.ok() && IsString(doc.value, "kind", kApiFollowPlanKind)) {
                    out = first.error != ProjectError::NotFound || doc.value.find(kApiFollowCheckpointField)
                        ? ApiFollowArchiveKind::Checkpointed : ApiFollowArchiveKind::Legacy;
                }
            }
            return false;
        }, kMaxRawBytes};
    const auto scan = project.ReadRawEvidenceSegment(input, ignored); // 各格式的严格验证由各自入口处理。
    if (out != ApiFollowArchiveKind::Other) {
        return {};
    }
    if (!first && first.error != ProjectError::NotFound) {
        return first;
    }
    if (scan.error == ProjectError::NotFound ||
        (scan.error == ProjectError::IoError && scan.nativeError == ERROR_SHARING_VIOLATION)) {
        return {};
    }
    return scan;
}

ProjectResult PublishApiCheckpoint(ProjectDocument& project, std::string_view sampleId, std::uint64_t ordinal,
    const Archive::RawEvidenceReceipt& receipt, std::span<const Archive::RawEvidenceInput> expected,
    const ProjectApiCheckpoint* previous, ProjectApiCheckpoint& out)
{
    const auto* root = ProjectApiCheckpointAccess::Root(project); // 只在当前写项目的目录链内发布。
    if (!root) {
        return Failure(ProjectError::NotOpen, "apiCheckpointProject");
    }
    if (project.Info()->access != ProjectAccess::ReadWrite) {
        return Failure(ProjectError::ReadOnly, "apiCheckpointProject");
    }
    if (!NextSegment(sampleId, ordinal, previous) || !receipt.flushed || expected.empty() ||
        receipt.result.status != Archive::SegmentWriteStatus::Ok) {
        return Failure(ProjectError::InvalidArgument, "apiCheckpointReceipt");
    }
    SampleRecord sample; // 从当前项目冻结的采样目录绑定描述散列。
    if (const auto result = ReadBoundSample(project, sampleId, sample); !result) {
        return result;
    }
    ProjectApiCheckpoint draft; // 发布成功前保持调用方的上一段水位。
    draft.sampleId = sample.info.sampleId;
    draft.ordinal = ordinal;
    draft.rawEnd = *receipt.flushed;
    if (const auto result = VerifyRaw(project, sample, previous, expected, {}, draft); !result) {
        return result;
    }

    const auto sampleDir = WideAscii(sample.info.sampleId); // 仅使用已登记采样的安全目录名。
    const auto dirs = {std::wstring_view(L"samples"), std::wstring_view(sampleDir), std::wstring_view(L"checkpoints")};
    Directory markers; // 固定标记目录，必要时由当前写租约创建。
    auto status = OpenDirectory(*root, dirs, markers);
    if (status.error == ProjectError::NotFound) {
        status = OpenDirectory(*root, dirs, markers, true);
    }
    if (!status) {
        return status;
    }
    const auto raw = Object({{"block", Number(draft.rawEnd.blockOrdinal)}, {"endOffset", Number(draft.rawEnd.byteOffset)},
        {"lastSequence", Number(draft.rawEnd.lastSequence)}, {"sha256", Text(draft.rawSha256)}}); // 完整块及原字节摘要。
    const auto marker = Object({{"kind", Text(kMarkerKind)}, {"generation", Number(ordinal)},
        {"projectId", Text(project.Info()->projectId)}, {"sampleId", Text(sample.info.sampleId)},
        {"descriptionHash", Text(sample.info.descriptionHash)}, {"raw", raw},
        {"previousRawSha256", previous ? Text(previous->rawSha256) : JsonValue::makeNull()},
        {"planRawSequence", Number(draft.planRawSequence)}, {"previousSourceSequence", Number(draft.previousSourceSequence)},
        {"lastSourceSequence", Number(draft.lastSourceSequence)}, {"finalSegment", JsonValue::makeBool(draft.finalSegment)}});
    if (const auto result = Publish(*root, dirs, MarkerName(ordinal), marker, false); !result) {
        return result;
    }
    out = std::move(draft);
    return {};
}

ProjectResult ReadApiCheckpoint(const ProjectDocument& project, std::string_view sampleId, std::uint64_t ordinal,
    const ProjectApiCheckpoint* previous, ProjectApiCheckpoint& out, const Archive::SegmentBodyVisitor& visitor)
{
    const auto* root = ProjectApiCheckpointAccess::Root(project); // 当前只读快照固定的目录句柄。
    if (!root) {
        return Failure(ProjectError::NotOpen, "apiCheckpointProject");
    }
    if (!NextSegment(sampleId, ordinal, previous)) {
        return Failure(ProjectError::Corrupt, "apiCheckpointChain");
    }
    SampleRecord sample; // 复核同一个已登记的冻结描述和配置。
    if (const auto result = ReadBoundSample(project, sampleId, sample); !result) {
        return result;
    }
    JsonValue marker; // 只认精确编号的已发布文件。
    if (const auto result = ReadMarker(*root, sample.info.sampleId, ordinal, marker); !result) {
        return result;
    }

    ProjectApiCheckpoint draft; // 与前次水位分开核对，失败时仍可使用前次结果。
    draft.sampleId = sample.info.sampleId;
    draft.ordinal = ordinal;
    const auto* raw = marker.find("raw"); // 已提交 raw 依赖的端点和摘要。
    const auto* terminal = marker.find("finalSegment"); // 当前标记是否发布本端终段。
    std::uint64_t generation = 0; // 只接受与请求段号一致的代次。
    std::uint64_t planSequence = 0; // 标记声明的首条 Stored 序号。
    std::uint64_t previousSource = 0; // 标记声明的段前已交付源行序号。
    std::uint64_t lastSource = 0; // 标记声明的累计包数。
    std::string hash; // 标记中预期的前缀摘要。
    bool final = false; // 从标记解析的终段标记。
    const bool chained = previous ? IsString(marker, "previousRawSha256", previous->rawSha256)
                                  : IsNull(marker, "previousRawSha256"); // 绑定上一段实际验证的原始字节。
    if (!chained || !Fields(marker, {"kind", "generation", "projectId", "sampleId", "descriptionHash", "raw",
            "previousRawSha256", "planRawSequence", "previousSourceSequence", "lastSourceSequence", "finalSegment"}) ||
        !IsString(marker, "kind", kMarkerKind) || !GetNumber(marker, "generation", generation) || generation != ordinal ||
        !IsString(marker, "projectId", project.Info()->projectId) || !IsString(marker, "sampleId", sample.info.sampleId) ||
        !IsString(marker, "descriptionHash", sample.info.descriptionHash) ||
        !raw || !Fields(*raw, {"block", "endOffset", "lastSequence", "sha256"}) ||
        !GetNumber(*raw, "block", draft.rawEnd.blockOrdinal) || !GetNumber(*raw, "endOffset", draft.rawEnd.byteOffset) ||
        !GetNumber(*raw, "lastSequence", draft.rawEnd.lastSequence) || !GetHash(*raw, "sha256", hash) ||
        !GetNumber(marker, "planRawSequence", planSequence) || !GetNumber(marker, "previousSourceSequence", previousSource) ||
        !GetNumber(marker, "lastSourceSequence", lastSource) || !terminal || !terminal->tryGetBool(final)) {
        return Failure(ProjectError::Corrupt, "apiCheckpointDocument");
    }
    if (const auto result = VerifyRaw(project, sample, previous, {}, visitor, draft); !result) {
        // 标记已存在：缺少其声明的 raw 文件属于断链，不能按等待发布处理。
        if (result.error == ProjectError::NotFound) {
            return Failure(ProjectError::Corrupt, "apiCheckpointRawMissing");
        }
        return result;
    }
    if (draft.rawSha256 != hash || draft.planRawSequence != planSequence || draft.previousSourceSequence != previousSource ||
        draft.lastSourceSequence != lastSource || draft.finalSegment != final) {
        return Failure(ProjectError::Corrupt, "apiCheckpointMismatch");
    }
    out = std::move(draft);
    return {};
}

std::optional<Evidence::ArchivedApiMonitorClue> ReadCommittedApiClue(const Archive::RawRecordV1& raw)
{
    const auto doc = Evidence::ParseJson(raw.metadataJson); // 本条已核验 raw 的元数据。
    Evidence::ArchivedApiMonitorClue row; // 从已验证包独立复制的桌面线索投影。
    if (!doc.ok() || !IsString(doc.value, "kind", kApiFollowPacketKind) || raw.inlineRawData.size() != sizeof(row.packet) ||
        !GetNumber(doc.value, "sourceSequence", row.sourceSequence) || !row.sourceSequence ||
        !GetNumber(doc.value, "readerCreation100ns", row.readerCreation) || !row.readerCreation) {
        return std::nullopt;
    }
    std::memcpy(&row.packet, raw.inlineRawData.data(), sizeof(row.packet));
    row.clue = Evidence::ClassifyApiMonitorClue(row.packet);
    if (!row.clue) {
        return std::nullopt;
    }
    return row;
}

} // namespace Ksword::ActionAnalyze
