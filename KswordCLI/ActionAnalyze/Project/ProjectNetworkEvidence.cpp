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

ProjectResult WriteInitialNetworkEvidence(ProjectDocument& project, std::string_view sampleId,
    const ks::cli::action_analyze::archive::NetworkEvidenceBinding& source,
    std::span<const ProjectNetworkObservation> observations,
    const ks::cli::action_analyze::archive::NetworkLoss& sourceLoss,
    ks::cli::action_analyze::archive::NetworkArchiveEnd end, ProjectNetworkEvidenceReceipt& out)
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

    const Archive::SegmentIdentity identity{Archive::StreamKind::Raw, 1, UuidBytes(info->projectId),
        UuidBytes(sample.info.sampleId)};
    const auto name = Archive::NameInspectionSegment(identity);
    if (!name || identity.project != source.project || identity.sample != source.sample ||
        observations.size() > Archive::kNetworkQueueCapacity || sourceLoss.queueDropped ||
        sourceLoss.queueCounterSaturated || sourceLoss.sourceCounterSaturated) {
        return Failure(ProjectError::InvalidArgument, "networkWriterBinding");
    }

    const auto sampleDirectory = WideAscii(sample.info.sampleId);
    const Parts parts{L"samples", sampleDirectory, name->streamDirectory};
    Directory raw;
    auto status = OpenDirectory(*root, parts, raw);
    if (status.error == ProjectError::NotFound) status = OpenDirectory(*root, parts, raw, true);
    if (!status) return status;

    // 目录句柄的租约持续到回读结束。归档器仅以 CREATE_NEW 打开目标文件。
    Archive::NetworkEvidenceArchive writer(std::filesystem::path(raw.path), source, identity.ordinal, UtcNow());
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

} // namespace Ksword::ActionAnalyze
