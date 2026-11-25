#include "ArchivedEvidenceGraph.h"

#include "../Project/ProjectApiCheckpoint.h"
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

// 只留一页投影，观察计数覆盖整个已核验段。
struct GraphPageDraft {
    ArchivedGraphPage page; // 归档读侧回执与本页原始坐标。
    std::vector<GraphInput> inputs; // 与原始坐标同序的证据图输入。
    bool more = false; // 本页之后还有已核验的观察。

    template<class Projection>
    void AddObservation(const ArchivedGraphRequest& request, const Archive::SegmentIdentity& identity,
        const Archive::BlockInfo& block, const Archive::DecodedRecord& record, const Archive::RawRecordV1& raw,
        Projection makeContext)
    {
        ++page.observationCount;
        if (record.recordSequence <= request.afterSequence) {
            return;
        }
        if (page.records.size() == request.limit) {
            more = true;
            return;
        }
        auto coordinate = Location(identity, block, record, raw); // 使用扫描到的文件坐标。
        inputs.push_back(makeContext(coordinate));
        page.records.push_back(std::move(coordinate));
    }
};

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
    return {std::move(projection), std::move(evidence), GraphArchiveContext{
        coordinate.headerPid, coordinate.headerTid, GraphApiClueFromFamily(coordinate.apiFamily)}};
}

// 返回一个 API 上下文。包内模块及 API 已通过共用精确分类器校验。
GraphEventInput ApiContext(const SampleScope& scope, const Evidence::ArchivedApiMonitorClue& clue,
    ArchivedGraphRecord& coordinate, const std::string& followEpoch = {})
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
    const bool imported = followEpoch.empty(); // 旧导入档使用采样派生的来源代次。
    std::vector<Issue> gaps{Issue::SourceUnverified}; // 完整性核对只认证存档内的一致性。
    if (imported) {
        gaps.push_back(Issue::LegacySummaryOnly);
    }
    gaps.push_back(Issue::ActorInstanceUnknown);
    gaps.push_back(Issue::TargetInstanceUnknown);
    auto input = Context(scope, coordinate, (imported ? "api-monitor-import:" : "api-monitor-follow:") + session,
        imported ? "api-import:" + scope.sampleId : followEpoch, "api-monitor", clue.sourceSequence, std::move(gaps));
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

// 复用项目层的连续链和同句柄核验。前段只验证水位，请求段的观察与坐标在核验回调中暂存。
ProjectResult ReadCommittedApiGraph(const ProjectDocument& project, const SampleScope& scope,
    const ArchivedGraphRequest& request, GraphPageDraft& draft)
{
    if (request.segmentOrdinal > kArchivedGraphMaxApiSegments) {
        return Failure(ProjectError::LimitExceeded, "graphApiCheckpointLimit");
    }

    std::string sourceEpoch; // 请求段计划记录中的已验证来源代次。
    const Archive::SegmentBodyVisitor collect = [&](const Archive::SegmentIdentity& identity,
        const Archive::BlockInfo& block, const std::vector<Archive::DecodedRecord>& records) {
        if (sourceEpoch.empty()) {
            if (records.empty()) {
                return false;
            }
            const auto& rawPlan = std::get<Archive::RawRecordV1>(records.front().body); // 项目校验器先核验本段首条计划。
            const auto plan = Evidence::ParseJson(rawPlan.metadataJson);
            if (!plan.ok() || !ProjectStorage::GetUuid(plan.value, "sourceEpoch", sourceEpoch)) {
                return false;
            }
        }
        for (const auto& record : records) {
            const auto& raw = std::get<Archive::RawRecordV1>(record.body);
            if (const auto clue = ReadCommittedApiClue(raw)) {
                draft.AddObservation(request, identity, block, record, raw, [&](auto& coordinate) {
                    return ApiContext(scope, *clue, coordinate, sourceEpoch);
                });
            }
        }
        return true;
    };

    ProjectApiCheckpoint committed; // 仅成功验证后才会替换上一段水位。
    const Archive::SegmentBodyVisitor skipProjection; // 前序段无需收集候选观察。
    for (std::uint64_t ordinal = 1; ordinal <= request.segmentOrdinal; ++ordinal) {
        if (committed.finalSegment) {
            return Failure(ProjectError::NotFound, "graphApiAfterFinalSegment");
        }
        const auto status = ReadApiCheckpoint(project, scope.sampleId, ordinal, ordinal == 1 ? nullptr : &committed,
            committed, ordinal == request.segmentOrdinal ? collect : skipProjection);
        if (!status) {
            return status;
        }
    }
    draft.page.source = ArchivedGraphSource::CommittedApiFollow;
    draft.page.end = committed.rawEnd;
    draft.page.sha256 = std::move(committed.rawSha256);
    draft.page.apiFinalSegment = committed.finalSegment;
    draft.page.apiCheckpoint = ArchivedApiGraphCheckpoint{
        committed.previousSourceSequence, committed.lastSourceSequence};
    return {};
}

ProjectResult ReadImportedApiOrEtwGraph(const ProjectDocument& project, const SampleScope& scope,
    const ArchivedGraphRequest& request, GraphPageDraft& draft)
{
    ProjectEtwCheckpoint checkpoint; // 已提交的同编号 raw 与 records 端点。
    const auto checkpointStatus = project.ReadEtwCheckpoint(scope.sampleId, checkpoint, request.segmentOrdinal);
    if (!checkpointStatus && (checkpointStatus.error != ProjectError::NotFound || request.segmentOrdinal != 1)) {
        return checkpointStatus;
    }
    const bool committedEtw = static_cast<bool>(checkpointStatus); // 无首检查点时只接纳严格的 API 导入档。
    const auto endOffset = committedEtw ? std::optional{checkpoint.raw.end.byteOffset} : std::nullopt; // ETW 只读取已提交的前缀。
    const auto previousSequence = committedEtw ? checkpoint.planRawSequence - 1 : 0; // 首条记录必须接续此序号。

    auto& page = draft.page;
    page.source = committedEtw ? ArchivedGraphSource::CommittedEtw : ArchivedGraphSource::ImportedApi;
    if (committedEtw) {
        page.etwFinalSegment = checkpoint.finalSegment;
    }
    Evidence::ApiMonitorClueReadback api; // 核对整个导入段，含本页之外的行和尾记。
    ProjectResult visitorStatus; // 保存回调拒绝原因，区分未支持格式和已识别格式损坏。

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
                        if (ProjectStorage::IsString(parsed.value, "kind", "etw-capture-plan-v1")) {
                            visitorStatus = Failure(ProjectError::NotFound, "graphEtwCheckpointNotPublished");
                        } else if (ProjectStorage::IsString(parsed.value, "kind", kApiFollowPlanKind) &&
                            parsed.value.find(kApiFollowCheckpointField)) {
                            visitorStatus = Failure(ProjectError::NotFound, "graphApiCheckpointNotPublished");
                        } else {
                            visitorStatus = Failure(ProjectError::Unsupported, "graphArchiveSource");
                        }
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

                draft.AddObservation(request, identity, block, record, raw, [&](auto& coordinate) {
                    return etw ? EtwContext(scope, *etw, coordinate) : ApiContext(scope, *clue, coordinate);
                });
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
    page.end = *scan.checked;
    return {};
}

} // namespace

ProjectResult ReadArchivedEvidenceGraph(const ProjectDocument& project, const ArchivedGraphRequest& request,
    ArchivedGraphPage& out)
{
    const auto* projectInfo = project.Info();
    if (!projectInfo) {
        return Failure(ProjectError::NotOpen, "project");
    }
    if (!request.segmentOrdinal || !request.limit || request.limit > kArchivedGraphMaxRows ||
        !ProjectStorage::IsUuid(request.sampleId) ||
        (!request.expectedSha256.empty() && !ProjectStorage::IsHash(request.expectedSha256))) {
        return Failure(ProjectError::InvalidArgument, "graphReadRequest");
    }

    SampleRecord sample; // 从已登记目录取得冻结采样身份与描述散列。
    if (const auto status = project.ReadSample(request.sampleId, sample); !status) {
        return status;
    }
    const SampleScope scope{projectInfo->projectId, sample.info.sampleId, {}, {}}; // 当前归档只支持来源内身份。

    ApiFollowArchiveKind apiKind = ApiFollowArchiveKind::Other; // 探测结果只用于选择读路径。
    if (const auto status = ProbeApiFollowArchive(project, scope.sampleId, apiKind); !status) {
        return status;
    }
    if (apiKind == ApiFollowArchiveKind::Legacy) {
        return Failure(ProjectError::Unsupported, "graphApiLegacyUnpublished");
    }

    GraphPageDraft draft; // 完整性和续页摘要均通过后再替换调用方结果。
    draft.inputs.reserve(request.limit);
    auto& page = draft.page;
    page.records.reserve(request.limit);
    const auto status = apiKind == ApiFollowArchiveKind::Checkpointed
        ? ReadCommittedApiGraph(project, scope, request, draft)
        : ReadImportedApiOrEtwGraph(project, scope, request, draft);
    if (!status) {
        return status;
    }
    if (!request.expectedSha256.empty() && request.expectedSha256 != page.sha256) {
        return Failure(ProjectError::StaleRevision, "graphArchiveSha256");
    }

    page.descriptionHash = sample.info.descriptionHash;
    page.segmentOrdinal = request.segmentOrdinal;
    if (draft.more) {
        page.nextAfterSequence = page.records.back().recordSequence;
    }
    page.graph = BuildCrossProcessEvidenceGraph(scope, draft.inputs);
    out = std::move(page);
    return {};
}

} // namespace Ksword::ActionAnalyze::Detection
