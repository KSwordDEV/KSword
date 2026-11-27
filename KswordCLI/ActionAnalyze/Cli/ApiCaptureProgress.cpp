#include "ApiCaptureProgress.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <utility>

namespace ks::cli::action_analyze {
namespace {
using Value = Ksword::Evidence::JsonValue;
using namespace Ksword::ActionAnalyze;

// 64位序号与计数使用十进制字符串，JSON消费者不会因双精度数值丢失低位。
Value Number(std::uint64_t value)
{
    return Value::makeString(std::to_string(value));
}

// 输入累计规则回执，输出最近命中的原坐标与原释义；本段无命中不把旧命中改挂到新段。
Value LatestRule(const CooperativeApiRuleReceipt& rules)
{
    if (!rules.latest)
    {
        return Value::makeNull();
    }
    const auto& match = *rules.latest; // 已提交原包的唯一规则匹配，不重新执行表达式。
    const auto behavior = match.behavior ? Value::makeObject({
        {"ruleId", Value::makeString(match.behavior->ruleId)},
        {"evidence", Value::makeString(match.behavior->evidence)},
        {"summary", Value::makeString(match.behavior->summary)},
        {"summaryZh", Value::makeString(match.behavior->summaryZh)}}) : Value::makeNull(); // 缺释义保持null。
    return Value::makeObject({{"segmentOrdinal", Number(rules.latestSegment)},
        {"rawSequence", Number(match.rawSequence)}, {"sourceSequence", Number(match.sourceSequence)},
        {"api", Value::makeString(match.api)}, {"ruleId", Value::makeString(match.ruleId)},
        {"behavior", behavior}});
}
} // namespace

ApiCaptureProgress::ApiCaptureProgress(bool requested, std::string projectId)
    : projectId_(std::move(projectId)), requested_(requested)
{
    if (requested_)
    {
        started_ = !output_.StartOutputOnly(STD_ERROR_HANDLE);
    }
}

void ApiCaptureProgress::Publish(const Value& value)
{
    if (!requested_)
    {
        return;
    }
    auto frame = Ksword::Evidence::WriteJson(value); // 复制本次通知值，不把借用字段留给异步writer。
    frame.push_back('\n');
    if (started_ && output_.TrySend(std::move(frame)))
    {
        ++enqueued_;
    }
    else
    {
        ++dropped_; // 进度交付不反向阻塞控制线程；最终摘要保留丢失事实。
    }
}

void ApiCaptureProgress::Emit(std::string_view kind, const SampleInfo& sample, Value payload)
{
    ++sequence_;
    Publish(Value::makeObject({{"schemaVersion", Value::makeUInt(1)},
        {"type", Value::makeString("api-capture-progress")}, {"kind", Value::makeString(std::string(kind))},
        {"progressSequence", Number(sequence_)}, {"projectId", Value::makeString(projectId_)},
        {"sampleId", Value::makeString(sample.sampleId)}, {"revisionId", Value::makeString(sample.revisionId)},
        {"payload", std::move(payload)}}));
}

void ApiCaptureProgress::Committed(const SampleInfo& sample, const ProjectApiCheckpoint& checkpoint,
    const CooperativeApiRuleReceipt& rules)
{
    if (!requested_)
    {
        return;
    }
    // 原writer已发布并回读检查点才调用；所有字段沿本次快照，之后草稿变化不影响它。
    committedSample_ = sample;
    Emit("api-checkpoint", sample, Value::makeObject({{"segmentOrdinal", Number(checkpoint.ordinal)},
        {"rawSequence", Number(checkpoint.rawEnd.lastSequence)}, {"sourceSequence", Number(checkpoint.lastSourceSequence)},
        {"sha256", Value::makeString(checkpoint.rawSha256)}, {"finalSegment", Value::makeBool(checkpoint.finalSegment)},
        {"ruleMatchedRows", Number(rules.matchedRows)}, {"ruleSourceSha256", Value::makeString(rules.sourceSha256)},
        {"rulesFailed", Value::makeBool(rules.failed)}, {"ruleConfigError", Value::makeString(rules.configError)},
        {"latestRule", LatestRule(rules)},
        {"candidateCount", Number(candidateCount_)}, {"apcCandidateCount", Number(apcCandidateCount_)},
        {"contextCandidateCount", Number(contextCandidateCount_)}}));
}

void ApiCaptureProgress::Transfers(const CooperativeApiTransferReceipt& transfers)
{
    if (!requested_)
    {
        return;
    }
    // 首个候选回调早于首个检查点通知；先保存累计值，后者才能完整报告首批数据。
    candidateCount_ = transfers.candidateCount;
    apcCandidateCount_ = transfers.apcCandidateCount;
    contextCandidateCount_ = transfers.contextCandidateCount;
    const auto& sample = transfers.handoffSample ? transfers.handoffSample : committedSample_; // 优先取控制器自己绑定的身份。
    if (!sample)
    {
        return; // 尚无真实采样身份时不生成一个来自命令参数的虚构活动实例。
    }
    Emit(transfers.handoff.isNull() ? "api-transfer-candidates" : "transfer-handoff", *sample, Value::makeObject({
        {"candidateCount", Number(transfers.candidateCount)}, {"apcCandidateCount", Number(transfers.apcCandidateCount)},
        {"contextCandidateCount", Number(transfers.contextCandidateCount)}, {"evictedWrites", Number(transfers.evictedWrites)},
        {"transferHandoff", transfers.handoff}}));
}

Value ApiCaptureProgress::Finish()
{
    if (!requested_)
    {
        return Value::makeNull();
    }
    const bool drained = started_ && output_.Finish(); // 此时原采集和恢复已结束，排空仍沿传输层五秒上限。
    return Value::makeObject({{"requested", Value::makeBool(true)}, {"started", Value::makeBool(started_)},
        {"lastProgressSequence", Number(sequence_)}, {"enqueuedFrames", Number(enqueued_)},
        {"droppedFrames", Number(dropped_)}, {"outputDrained", Value::makeBool(drained)}});
}

} // namespace ks::cli::action_analyze
