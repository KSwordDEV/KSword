#include "ProjectEtwStream.h"
#include "ProjectEtwCheckpoint.h"
#include "ProjectStorage.h"

#include <algorithm>
#include <utility>

namespace Ksword::ActionAnalyze {
namespace {
namespace Archive = ks::cli::action_analyze::archive;
using namespace ProjectStorage;

// 输入原writer的追加回执；返回项目层错误，保留实际Win32失败码。
ProjectResult Appended(const Archive::RawEvidenceReceipt& receipt)
{
    if (receipt.result.status == Archive::SegmentWriteStatus::Ok)
    {
        return {};
    }
    if (receipt.result.status == Archive::SegmentWriteStatus::IoError)
    {
        return WinFailure("archiveRawWrite", receipt.result.error.win32Error);
    }
    return Failure(ProjectError::InvalidArgument, "archiveRawInput");
}
} // namespace

// 连续ETW与API配套ETW使用同一定位投影，不把主流和附属流的序号空间混在一起。
Evidence::JsonValue ProjectEtwStream::PublishedJson(ProjectEvidenceLane lane) const
{
    if (!ordinal || !raw.flushed)
    {
        return Evidence::JsonValue::makeNull();
    }
    return Object({{"stream", Text(lane == ProjectEvidenceLane::MixedEtw ? "raw-etw" : "raw")},
        {"segmentOrdinal", Number(ordinal)}, {"firstRawSequence", Number(planRawSequence)},
        {"lastRawSequence", Number(raw.flushed->lastSequence)},
        {"endOffset", Number(raw.flushed->byteOffset)}, {"sha256", Text(rawSha256)},
        {"finalSegment", Evidence::JsonValue::makeBool(finalized)}});
}

// 由原worker传入冻结计划及同一来源；返回本批写入/发布是否成功，游标只在发布后推进。
bool ProjectEtwStream::Flush(ProjectDocument& project, std::string_view sampleId,
    ProjectEvidenceLane lane, const Evidence::JsonValue& plan, std::string_view reason,
    ks::r3::monitor::PassiveEtwSource& source, bool final)
{
    if (finalized)
    {
        return true;
    }
    if (!archiveStatus || !checkpointStatus)
    {
        return false;
    }
    const auto* info = project.Info(); // 原写租约对应的项目身份。
    std::string provider; // 与计划、正文及覆盖记录一致的Provider。
    if (!info || !GetUuid(plan, "providerId", provider))
    {
        archiveStatus = Failure(ProjectError::InvalidArgument, "archiveEtwPlan");
        return false;
    }
    if (final && source.status().state != ks::r3::monitor::PassiveEtwState::Stopped)
    {
        archiveStatus = Failure(ProjectError::InvalidArgument, "archiveEtwSourceNotStopped");
        return false;
    }
    do
    {
        auto rows = source.drain(512); // 一段与现有持续ETW读取上限一致。
        if (rows.empty() && !final)
        {
            return true;
        }
        const auto status = source.status(); // 本worker串行追加PID；排空后冻结本段目录及计数。
        const bool last = final && status.queued == 0; // 只有来源停止后的末批可以封终段。
        const auto previous = raw.flushed ? raw.flushed->lastSequence : 0; // 紧邻已发布前缀。
        Archive::RawEvidenceReceipt next; // 本次候选端点，不覆盖旧的已发布回执。
        archiveStatus = project.WriteRawEvidenceSegment({info->projectId, sampleId, ordinal + 1, previous,
            [&](auto& writer) -> ProjectResult
            {
                const auto planText = Evidence::WriteJson(plan); // 本段实际PID目录及冻结采样身份。
                const Archive::RawEvidenceInput head{planText, {}}; // 沿旧格式保留无载荷计划记录。
                if (const auto result = Appended(writer.Append(std::span(&head, 1))); !result)
                {
                    return result;
                }
                const std::span observations(rows); // 借用本次移出的原始观察，不复制来源队列。
                for (std::size_t index = 0; index < observations.size(); index += 32)
                {
                    // 与原ETW路径相同的小批追加，限制单块的元数据及载荷大小。
                    if (const auto result = AppendEtwObservations(writer, observations.subspan(index,
                        (std::min)(std::size_t{32}, observations.size() - index))); !result)
                    {
                        return result;
                    }
                }
                // 非终段计数仅覆盖本批；原生及队列累计丢失仍保留自己的含义。
                const auto endText = Evidence::WriteJson(Object({{"kind", Text("etw-capture-end-v1")},
                    {"stopReason", Text(last ? reason : "segment-rotated")},
                    {"finalSegment", Evidence::JsonValue::makeBool(last)},
                    {"segmentObservations", Number(rows.size())}, {"source", EtwSourceReceipt(status)}}));
                const Archive::RawEvidenceInput tail{endText, {}}; // 尾记录不携带伪造事件字节。
                return Appended(writer.Append(std::span(&tail, 1)));
            }, lane}, next);
        if (!archiveStatus)
        {
            return false;
        }
        if (!next.flushed || next.flushed->lastSequence <= previous ||
            next.flushed->lastSequence - previous != rows.size() + 2)
        {
            archiveStatus = Failure(ProjectError::Corrupt, "archiveRawVerification");
            return false;
        }
        // 未取得统计时保留null；不能把未知丢失情况写成零。
        const auto statistic = [known = status.native.statisticsKnown](ULONG value) -> std::optional<std::uint32_t>
        {
            return known ? std::optional<std::uint32_t>(value) : std::nullopt;
        };
        const Archive::EtwCoverageV1 coverage{provider, status.sourceEpoch, ordinal + 1, previous + 1,
            next.flushed->lastSequence, rows.size(), statistic(status.native.eventsLost),
            statistic(status.native.logBuffersLost), statistic(status.native.realTimeBuffersLost),
            status.queueDropped, status.payloadTruncated, status.malformedPayload};
        ProjectEtwCheckpoint checkpoint; // 原发布函数完成字节/散列与覆盖核对。
        checkpointStatus = project.PublishEtwCheckpoint(sampleId, *next.flushed, coverage, checkpoint, lane);
        if (!checkpointStatus)
        {
            return false;
        }
        // 成功发布之后才更新对外游标；失败不能消耗段号后继续跳段。
        raw = std::move(next);
        planRawSequence = checkpoint.planRawSequence;
        rawSha256 = std::move(checkpoint.raw.sha256);
        ++ordinal;
        observations += rows.size();
        finalized = last;
    } while (final && !finalized);
    return true;
}

} // namespace Ksword::ActionAnalyze
