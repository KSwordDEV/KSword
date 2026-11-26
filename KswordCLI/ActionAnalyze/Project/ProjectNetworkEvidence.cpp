#include "ProjectNetworkEvidence.h"

#include "ProjectStorage.h"
#include "../Archive/SegmentInspection.h"

#include <algorithm>
#include <utility>

namespace Ksword::ActionAnalyze {

struct ProjectNetworkEvidenceAccess {
    static const ProjectStorage::Directory* Root(const ProjectDocument& project) { return project.RootForRead(); }
};

namespace {

// 归档器使用 RequireInline。核对已通过格式校验的原记录是否完整往返了这次提交的流和正文。
bool MatchesObservation(const ProjectNetworkObservation& expected,
    const ks::cli::action_analyze::archive::NetworkArchivedFlow& decoded,
    const ks::cli::action_analyze::archive::RecordView& stored)
{
    const auto& capture = decoded.capture; // 正文长度及语义由完整块回读先行验证。
    return decoded.observation == expected.flow && capture.layer == expected.capture.layer &&
        capture.originalLength == expected.capture.originalLength && capture.sourceTruncated == expected.capture.sourceTruncated &&
        capture.producerCapturedLength == expected.capture.bytes.size() && capture.capturedLength == expected.capture.bytes.size() &&
        std::equal(expected.capture.bytes.begin(), expected.capture.bytes.end(),
            stored.payload + (stored.payloadBytes - capture.capturedLength));
}

} // namespace

// 共享段写入入口；旧首段与新网络附属流共用同一个正文归档器及逐字节回读。
static ProjectResult WriteNetworkSegment(ProjectDocument& project, std::string_view sampleId,
    const ks::cli::action_analyze::archive::NetworkEvidenceBinding& source,
    std::span<const ProjectNetworkObservation> observations,
    const ks::cli::action_analyze::archive::NetworkLoss& sourceLoss,
    ks::cli::action_analyze::archive::NetworkArchiveEnd end, ProjectNetworkEvidenceReceipt& out,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence, bool networkLane)
{
    namespace Archive = ks::cli::action_analyze::archive;
    using namespace ProjectStorage;
    out = {};
    const auto* root = ProjectNetworkEvidenceAccess::Root(project);
    const auto* info = project.Info();
    if (!root || !info) return Failure(ProjectError::NotOpen, "project");
    if (info->access != ProjectAccess::ReadWrite) return Failure(ProjectError::ReadOnly, "project");
    SampleRecord sample;
    if (const auto status = project.ReadSample(sampleId, sample); !status) return status;

    const Archive::SegmentIdentity identity{Archive::StreamKind::Raw, ordinal, UuidBytes(info->projectId),
        UuidBytes(sample.info.sampleId)};
    const auto name = Archive::NameInspectionSegment(identity);
    if (!name || identity.project != source.project || identity.sample != source.sample ||
        observations.size() > Archive::kNetworkQueueCapacity || sourceLoss.queueDropped ||
        sourceLoss.queueCounterSaturated || sourceLoss.sourceCounterSaturated) {
        return Failure(ProjectError::InvalidArgument, "networkWriterBinding");
    }

    const auto sampleDirectory = WideAscii(sample.info.sampleId);
    const Parts parts{L"samples", sampleDirectory, networkLane ? L"raw-network" : name->streamDirectory};
    Directory raw;
    auto status = OpenDirectory(*root, parts, raw);
    if (status.error == ProjectError::NotFound) status = OpenDirectory(*root, parts, raw, true);
    if (!status) return status;

    // 目录句柄的租约持续到回读结束。归档器仅以 CREATE_NEW 打开目标文件。
    Archive::NetworkEvidenceArchive writer(std::filesystem::path(raw.path), source, identity.ordinal, UtcNow(), previousSequence);
    for (const auto& row : observations) {
        const auto queued = writer.Submit(source, row.flow, row.capture); // 每条正文按原捕获层提交，不自动截断。
        if (queued == Archive::NetworkSubmitStatus::QueueFull || queued == Archive::NetworkSubmitStatus::NeedsBlob) {
            return Failure(ProjectError::LimitExceeded, "networkWriterPayloadBudget");
        }
        if (queued != Archive::NetworkSubmitStatus::Queued) {
            return Failure(ProjectError::InvalidArgument, "networkWriterObservation");
        }
    }
    if ((sourceLoss.sourceLost && !writer.ReportSourceLoss(source, sourceLoss.sourceLost)) ||
        (sourceLoss.sourceLossUnquantified && !writer.ReportSourceLoss(source, std::nullopt))) {
        return Failure(ProjectError::InvalidArgument, "networkWriterLoss");
    }
    out.raw = writer.Finish(end);
    if (out.raw.result.status != Archive::SegmentWriteStatus::Ok || !out.raw.eofFlushed ||
        out.raw.writtenBytes != out.raw.flushedBytes) {
        return out.raw.result.error.win32Error ? WinFailure("networkWriterFinish", out.raw.result.error.win32Error) :
            Failure(ProjectError::IoError, "networkWriterFinish");
    }

    Handle file;
    if (const auto opened = OpenFile(raw, name->fileName, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, file); !opened) {
        return opened;
    }
    std::vector<ProjectNetworkRecordLocation> locations; // 仅在整段与输入逐条一致后发布。
    locations.reserve(observations.size());
    bool matches = true; // 已验证块是否与本次输入顺序及内容一致。
    const auto checked = Archive::ScanOpenNetworkEvidence(file.get(), source, identity.ordinal, std::nullopt,
        [&](const auto&, const auto& records, std::span<const Archive::RecordView> stored) {
            for (std::size_t index = 0; matches && index < records.size(); ++index) {
                const auto& row = records[index]; // 本条观测与同索引的原记录来自同一个已验证块。
                const auto position = locations.size(); // 下一条输入在本段中的顺序。
                if (position == observations.size() || !MatchesObservation(observations[position], row, stored[index])) {
                    matches = false;
                    break;
                }
                locations.push_back({row.recordSequence, row.recordOffset});
            }
        });
    if (checked.framing.status == Archive::SegmentScanStatus::IoError) {
        return WinFailure("networkWriterReadback", checked.framing.error.win32Error);
    }
    if (checked.framing.status != Archive::SegmentScanStatus::FramingComplete ||
        checked.checkedBytes != out.raw.flushedBytes || checked.framing.lastSequence != out.raw.lastFlushedSequence ||
        checked.eof != end || checked.loss.sourceLost != sourceLoss.sourceLost ||
        checked.loss.sourceLossUnquantified != sourceLoss.sourceLossUnquantified || checked.loss.queueDropped ||
        checked.loss.sourceCounterSaturated || checked.loss.queueCounterSaturated || !matches || locations.size() != observations.size()) {
        return Failure(ProjectError::Corrupt, "networkWriterReadback");
    }
    out.locations = std::move(locations);
    return {};
}

// 兼容既有回环元数据命令；其 raw/1 行为保持原样。
ProjectResult WriteInitialNetworkEvidence(ProjectDocument& project, std::string_view sampleId,
    const ks::cli::action_analyze::archive::NetworkEvidenceBinding& source,
    std::span<const ProjectNetworkObservation> observations,
    const ks::cli::action_analyze::archive::NetworkLoss& sourceLoss,
    ks::cli::action_analyze::archive::NetworkArchiveEnd end, ProjectNetworkEvidenceReceipt& out)
{
    return WriteNetworkSegment(project, sampleId, source, observations, sourceLoss, end, out, 1, std::nullopt, false);
}

// 在调用方已持有的项目写租约内续写网络附属流，最后原子发布可供三端读取的检查点。
ProjectResult CommitNetworkEvidence(ProjectDocument& project, std::string_view sampleId,
    const ks::cli::action_analyze::archive::NetworkEvidenceBinding& source,
    std::span<const ProjectNetworkObservation> observations,
    const ks::cli::action_analyze::archive::NetworkLoss& loss,
    ks::cli::action_analyze::archive::NetworkArchiveEnd end,
    std::uint32_t requestedPid, std::uint64_t requestedCreation, std::string_view stopReason,
    ProjectNetworkCheckpoint& checkpoint, ProjectNetworkEvidenceReceipt& out)
{
    namespace Archive = ks::cli::action_analyze::archive;
    using namespace ProjectStorage;
    out = {};
    const auto* root = ProjectNetworkEvidenceAccess::Root(project); // 项目所有者固定的根目录。
    if (!root || !project.Info()) return Failure(ProjectError::NotOpen, "networkProject");
    if (project.Info()->access != ProjectAccess::ReadWrite) return Failure(ProjectError::ReadOnly, "networkProject");
    if (!requestedPid || !requestedCreation || !IsText(stopReason, 64) || checkpoint.ordinal >= 4096) {
        return Failure(ProjectError::InvalidArgument, "networkCheckpointInput");
    }
    SampleRecord sample; // 检查点绑定原 sample 的冻结描述，绝不另建采样。
    if (const auto status = project.ReadSample(sampleId, sample); !status) return status;
    if (checkpoint.ordinal) {
        ProjectNetworkCheckpoint checked; // 不信任调用方传入的上一段水位。
        if (const auto status = ReadNetworkEvidence(project, sampleId, checkpoint.ordinal, checked); !status) return status;
        if (checked.sha256 != checkpoint.sha256 || checked.lastSequence != checkpoint.lastSequence) {
            return Failure(ProjectError::StaleRevision, "networkCheckpointTail");
        }
    }
    const auto ordinal = checkpoint.ordinal + 1; // 下一段网络专属序号。
    const auto previous = checkpoint.ordinal ? std::optional(checkpoint.lastSequence) : std::nullopt;
    if (const auto status = WriteNetworkSegment(project, sampleId, source, observations, loss, end, out,
        ordinal, previous, true); !status) return status;

    // 整段正文已逐条核对，再以同一固定目录读回完整字节摘要。
    const auto sampleDir = WideAscii(sample.info.sampleId);
    Directory raw;
    if (const auto status = OpenDirectory(*root, {L"samples", sampleDir, L"raw-network"}, raw); !status) return status;
    const auto name = Archive::NameInspectionSegment(out.raw.segment);
    Handle file;
    if (!name) return Failure(ProjectError::InvalidArgument, "networkSegmentName");
    if (const auto status = OpenFile(raw, name->fileName, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, file); !status) return status;
    std::string hash; // 对已刷盘的完整段生成检查点摘要。
    if (const auto status = HashArchivePrefix(file.get(), out.raw.flushedBytes, hash); !status) return status;
    Directory markers;
    const Parts dirs{L"samples", sampleDir, L"checkpoints-network"};
    auto status = OpenDirectory(*root, dirs, markers);
    if (status.error == ProjectError::NotFound) status = OpenDirectory(*root, dirs, markers, true);
    if (!status) return status;

    // 来源 UUID 保存为标准文本，读端恢复到 NetworkEvidenceBinding 的 RFC 字节序。
    constexpr char hex[] = "0123456789abcdef";
    std::string epoch;
    for (std::size_t index = 0; index < source.sourceEpoch.size(); ++index) {
        if (index == 4 || index == 6 || index == 8 || index == 10) epoch.push_back('-');
        epoch.push_back(hex[source.sourceEpoch[index] >> 4]);
        epoch.push_back(hex[source.sourceEpoch[index] & 15]);
    }
    const auto marker = Object({{"kind", Text("network-archive-checkpoint-v1")},
        {"projectId", Text(project.Info()->projectId)}, {"sampleId", Text(sample.info.sampleId)},
        {"descriptionHash", Text(sample.info.descriptionHash)}, {"ordinal", Number(ordinal)},
        {"endOffset", Number(out.raw.flushedBytes)}, {"lastSequence", Number(*out.raw.lastFlushedSequence)},
        {"sha256", Text(hash)}, {"previousSha256", checkpoint.ordinal ? Text(checkpoint.sha256) : JsonValue::makeNull()},
        {"sourceId", Text(source.sourceId)}, {"sourceEpoch", Text(epoch)},
        {"clockId", Text(source.clockId)}, {"bootId", Text(source.bootId)},
        {"clockDomain", Number(static_cast<std::uint8_t>(source.clockDomain))},
        {"frequencyHz", source.frequencyHz ? Number(*source.frequencyHz) : JsonValue::makeNull()},
        {"requestedPid", Number(requestedPid)}, {"requestedCreation", Number(requestedCreation)},
        {"stopReason", Text(stopReason)}});
    if (const auto published = Publish(*root, dirs, NumberFile(ordinal), marker, false); !published) return published;
    checkpoint = {ordinal, out.raw.flushedBytes, *out.raw.lastFlushedSequence, std::move(hash), source,
        requestedPid, requestedCreation, std::string(stopReason)};
    return {};
}

} // namespace Ksword::ActionAnalyze
