#include "ArchivedEvidenceGraph.h"

#include "../Project/ProjectEtwCheckpoint.h"
#include "../Project/ProjectStorage.h"
#include "../../../shared/evidence/ApiMonitorClue.h"
#include "../../../shared/evidence/ArchivedEtwObservation.h"

#include <utility>

namespace Ksword::ActionAnalyze::Detection {
namespace {

namespace Archive = ks::cli::action_analyze::archive;
using ProjectStorage::Failure;

constexpr std::uint64_t kApiReadBytes = 32u << 20; // 与旧 API 导入回读使用相同的段大小上限。
constexpr std::uint64_t kEtwReadBytes = 4u << 20; // 已提交 ETW 段的核验上限。

// 在 Stored 扫描回调中取得真实 raw 坐标。帧与正文边界已由读取器核验。
ArchivedGraphRecord Location(const Archive::SegmentIdentity& identity, const Archive::BlockInfo& block,
    const Archive::DecodedRecord& record, const Archive::RawRecordV1& raw)
{
    ArchivedGraphRecord result; // 实际 Stored 块中的坐标，不从来源元数据回填。
    result.segmentOrdinal = identity.ordinal;
    result.recordSequence = record.recordSequence;
    result.recordOffset = record.recordOffset;
    result.blockOrdinal = block.ordinal;
    result.inlineOffset = record.recordOffset + Archive::kRecordHeaderBytes + raw.inlineRawOffsetInPayload;
    result.inlineBytes = raw.inlineRawBytes;
    return result;
}

// 已验证的位置与来源声明各自保存。当前 raw 行没有规范事件序号。
GraphEventInput Context(const SampleScope& scope, const ArchivedGraphRecord& coordinate,
    std::string sourceId, std::string sourceEpoch, std::string sourceGroup,
    std::optional<std::uint64_t> sourceSequence, std::vector<Issue> gaps)
{
    EvidenceRef evidence; // 目标为本段经核验的同一原始记录。
    evidence.projectId = scope.projectId;
    evidence.sampleId = scope.sampleId;
    evidence.sourceId = std::move(sourceId);
    evidence.sourceEpoch = std::move(sourceEpoch);
    evidence.raw = RawLocator{coordinate.segmentOrdinal, coordinate.recordSequence};
    evidence.sourceSequence = sourceSequence;
    evidence.sourceGroup = std::move(sourceGroup);

    EventProjection projection; // 缺原生强角色的来源只贡献位置和可解释的缺口。
    projection.gaps = std::move(gaps);
    return {std::move(projection), std::move(evidence)};
}

// 返回一个 API 上下文。包内模块及 API 已通过共用精确分类器校验。
GraphEventInput ApiContext(const SampleScope& scope, const Evidence::ArchivedApiMonitorClue& clue,
    ArchivedGraphRecord& coordinate)
{
    const auto api = clue.clue->api; // 分类器静态表中的 ASCII 导出名。
    coordinate.operation.reserve(api.size());
    for (const auto character : api) {
        coordinate.operation.push_back(static_cast<char>(character));
    }
    coordinate.headerPid = clue.packet.pid;
    coordinate.headerTid = clue.packet.tid;
    coordinate.apiFamily = clue.clue->family;
    // 线索目录只接受这两类。公开值用于筛选，与本地化分类名称独立。
    coordinate.apiCategory = clue.clue->category == ks::winapi_monitor::EventCategory::Memory ? "memory" : "thread";

    const auto session = std::to_string(clue.packet.sessionIdentity); // 保留文件声明的采集会话。
    auto input = Context(scope, coordinate, "api-monitor-import:" + session, "api-import:" + scope.sampleId, "api-monitor",
        clue.sourceSequence, {Issue::SourceUnverified, Issue::LegacySummaryOnly, Issue::ActorInstanceUnknown,
            Issue::TargetInstanceUnknown});
    if (coordinate.apiFamily == "memory-write") {
        input.event.gaps.push_back(Issue::ActualWriteRangeUnknown);
    }
    if (coordinate.apiFamily == "thread-create") {
        input.event.gaps.push_back(Issue::ThreadInstanceUnknown);
        input.event.gaps.push_back(Issue::ExecutionUnknown);
    }
    return input;
}

// ETW 的头字段只是事件上下文。源时间和载荷可按 raw 坐标回查。
GraphEventInput EtwContext(const SampleScope& scope, const Evidence::ArchivedEtwObservation& observation,
    ArchivedGraphRecord& coordinate)
{
    coordinate.operation = "etw-observation-v1";
    coordinate.headerPid = observation.headerPid;
    coordinate.headerTid = observation.headerTid;

    std::vector<Issue> gaps{Issue::EtwContextOnly}; // 头部上下文与载荷错误分别保存。
    if (observation.malformedPayload) {
        gaps.push_back(Issue::InvalidNativeRecord);
    }
    if (coordinate.inlineBytes < observation.originalPayloadBytes) {
        gaps.push_back(Issue::SourcePayloadTruncated);
    }
    return Context(scope, coordinate, "etw:" + observation.providerId, observation.sourceEpoch,
        "etw:" + observation.providerId, std::nullopt, std::move(gaps));
}

} // namespace

ProjectResult ReadArchivedEvidenceGraph(const ProjectDocument& project, const ArchivedGraphRequest& request,
    ArchivedGraphPage& out)
{
    const auto* projectInfo = project.Info(); // 当前项目只读视图的冻结索引。
    if (!projectInfo) {
        return Failure(ProjectError::NotOpen, "project");
    }
    if (!request.segmentOrdinal || !request.limit || request.limit > kArchivedGraphMaxRows ||
        !ProjectStorage::IsUuid(request.sampleId) ||
        (!request.expectedSha256.empty() && !ProjectStorage::IsHash(request.expectedSha256))) {
        return Failure(ProjectError::InvalidArgument, "graphReadRequest");
    }

    SampleRecord sample; // 从已登记目录读回并核验实际采样描述。
    if (const auto status = project.ReadSample(request.sampleId, sample); !status) {
        return status;
    }

    ProjectEtwCheckpoint checkpoint; // 已提交的同编号 raw 与 records 端点。
    const auto checkpointStatus = project.ReadEtwCheckpoint(request.sampleId, checkpoint, request.segmentOrdinal); // 双流回读结果。
    if (!checkpointStatus && (checkpointStatus.error != ProjectError::NotFound || request.segmentOrdinal != 1)) {
        return checkpointStatus;
    }
    const bool committedEtw = static_cast<bool>(checkpointStatus); // 无首检查点时只接纳严格的 API 导入档。
    const auto endOffset = committedEtw ? std::optional{checkpoint.raw.end.byteOffset} : std::nullopt; // ETW 只读取已提交的前缀。
    const auto previousSequence = committedEtw ? checkpoint.planRawSequence - 1 : 0; // 首条记录必须接续此序号。

    // 当前两种归档的冻结采样描述都没有可信的机器和启动期字段。
    const SampleScope scope{projectInfo->projectId, sample.info.sampleId, {}, {}};
    ArchivedGraphPage page; // 完整性验证通过后再替换调用方结果。
    page.source = committedEtw ? ArchivedGraphSource::CommittedEtw : ArchivedGraphSource::ImportedApi;
    page.descriptionHash = sample.info.descriptionHash;
    if (committedEtw) {
        page.etwFinalSegment = checkpoint.finalSegment;
    }
    std::vector<GraphInput> inputs; // 只保留本页可寻址的上下文。
    inputs.reserve(request.limit);
    page.records.reserve(request.limit);
    Evidence::ApiMonitorClueReadback api; // 核对整个导入段，含本页之外的行和尾记。
    ProjectResult visitorStatus; // 保存回调拒绝原因，区分未支持格式和已识别格式损坏。
    bool more = false; // 已见本页之外的另一条有效观察。

    const ProjectRawEvidenceRead read{scope.projectId, scope.sampleId, request.segmentOrdinal, // 冻结此次只读的段身份。
        endOffset, previousSequence,
        [&](const Archive::SegmentIdentity& identity, const Archive::BlockInfo& block,
            const std::vector<Archive::DecodedRecord>& records) {
            for (const auto& record : records) {
                const auto& raw = std::get<Archive::RawRecordV1>(record.body); // 读取器已核对流和正文类型。
                if (committedEtw && (record.recordSequence == checkpoint.planRawSequence ||
                        record.recordSequence == checkpoint.raw.end.lastSequence)) {
                    continue; // 计划和终态已由检查点的散列覆盖。
                }

                const auto parsed = Evidence::ParseJson(raw.metadataJson); // 当前已核验块的原始元数据。
                if (!parsed.ok()) {
                    visitorStatus = Failure(ProjectError::Corrupt, "graphRecordMetadata");
                    return false;
                }
                std::optional<Evidence::ArchivedEtwObservation> etw; // ETW 头部及长度回执。
                std::optional<Evidence::ArchivedApiMonitorClue> clue; // 本条完整 API 包，尾记时为空。
                if (committedEtw) {
                    etw = Evidence::ReadArchivedEtwObservation(parsed.value, raw.inlineRawBytes);
                    if (!etw) {
                        visitorStatus = Failure(ProjectError::Corrupt, "graphEtwObservation");
                        return false;
                    }
                } else {
                    if (record.recordSequence == 1 && !Evidence::IsApiMonitorClueImport(parsed.value)) {
                        visitorStatus = ProjectStorage::IsString(parsed.value, "kind", "etw-capture-plan-v1")
                            ? Failure(ProjectError::NotFound, "graphEtwCheckpointNotPublished")
                            : Failure(ProjectError::Unsupported, "graphArchiveSource");
                        return false;
                    }
                    if (!api.Accept(parsed.value, raw.inlineRawData, clue)) {
                        visitorStatus = Failure(ProjectError::Corrupt, "graphApiImportTailOrRecord");
                        return false;
                    }
                    if (!clue) {
                        continue; // 导入尾记只参与整段校验。
                    }
                }

                ++page.observationCount;
                if (record.recordSequence <= request.afterSequence) {
                    continue;
                }
                if (page.records.size() == request.limit) {
                    more = true;
                    continue; // 继续核对整段与尾记。
                }

                auto coordinate = Location(identity, block, record, raw); // 实际片段和文件偏移。
                inputs.push_back(etw ? EtwContext(scope, *etw, coordinate) : ApiContext(scope, *clue, coordinate));
                page.records.push_back(std::move(coordinate));
            }
            return true;
        }, committedEtw ? kEtwReadBytes : kApiReadBytes};

    Archive::RawEvidenceScanResult scan; // 只在扫描和散列一致后公布图与坐标。
    if (const auto status = project.ReadRawEvidenceSegment(read, scan, &page.sha256); !status) {
        return status;
    }
    if (!visitorStatus) {
        return visitorStatus;
    }
    const auto& framing = scan.segment.framing; // 保留读取失败和封装不支持的原始分类。
    if (framing.status == Archive::SegmentScanStatus::IoError) {
        return ProjectStorage::WinFailure("graphArchiveRead", framing.error.win32Error);
    }
    if (framing.status == Archive::SegmentScanStatus::Unsupported) {
        return Failure(ProjectError::Unsupported, "graphArchiveFraming");
    }
    if (!scan.checked || !scan.VerifiedBoundary(committedEtw ? checkpoint.raw.end : *scan.checked) ||
        page.sha256.empty() || (committedEtw ? page.sha256 != checkpoint.raw.sha256 : !api.ended)) {
        return Failure(ProjectError::Corrupt, "graphArchivePrefix");
    }
    if (!request.expectedSha256.empty() && request.expectedSha256 != page.sha256) {
        return Failure(ProjectError::StaleRevision, "graphArchiveSha256");
    }

    page.segmentOrdinal = request.segmentOrdinal;
    page.end = *scan.checked;
    if (more) {
        page.nextAfterSequence = page.records.back().recordSequence;
    }
    page.graph = BuildCrossProcessEvidenceGraph(scope, inputs);
    out = std::move(page);
    return {};
}

} // namespace Ksword::ActionAnalyze::Detection
