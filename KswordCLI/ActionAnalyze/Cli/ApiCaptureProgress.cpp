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
Value RuleMatch(std::uint64_t segment, const Rules::ApiPresetMatch& match)
{
    const auto behavior = match.behavior ? Value::makeObject({
        {"ruleId", Value::makeString(match.behavior->ruleId)},
        {"evidence", Value::makeString(match.behavior->evidence)},
        {"summary", Value::makeString(match.behavior->summary)},
        {"summaryZh", Value::makeString(match.behavior->summaryZh)}}) : Value::makeNull(); // 缺释义保持null。
    return Value::makeObject({{"segmentOrdinal", Number(segment)},
        {"rawSequence", Number(match.rawSequence)}, {"sourceSequence", Number(match.sourceSequence)},
        {"api", Value::makeString(match.api)}, {"ruleId", Value::makeString(match.ruleId)},
        {"behavior", behavior}});
}

// 最近普通分类仍保持原兼容字段；行为窗口单独保留，不能从最新一次命中倒推出历史释义。
Value LatestRule(const CooperativeApiRuleReceipt& rules)
{
    return rules.latest ? RuleMatch(rules.latestSegment, *rules.latest) : Value::makeNull();
}

// 输入已提交原包引用，输出段号、原序号及独立来源序号；不采用UI行号或当前PID补值。
Value CandidateCoordinate(const Detection::EvidenceRef& reference)
{
    if (!reference.raw)
    {
        return Value::makeNull();
    }
    return Value::makeObject({{"segmentOrdinal", Number(reference.raw->segmentOrdinal)},
        {"rawSequence", Number(reference.raw->sequence)},
        {"sourceSequence", reference.sourceSequence ? Number(*reference.sourceSequence) : Value::makeNull()}});
}

// 输入任一候选及双方原包引用，输出共同身份和实际写入范围；返回文档不包含执行推断。
template<class Link>
Ksword::Evidence::JsonObject CandidateFields(const Link& link, const char* requestKey,
    const Detection::EvidenceRef& request)
{
    return {{"write", CandidateCoordinate(link.write)}, {requestKey, CandidateCoordinate(request)},
        {"actorPid", Value::makeUInt(link.actorPid)}, {"actorCreationFileTime", Number(link.actorCreationFileTime)},
        {"targetPid", Value::makeUInt(link.targetPid)}, {"targetCreationFileTime", Number(link.targetCreationFileTime)},
        {"writtenAddress", Number(link.writtenAddress)}, {"writtenBytes", Number(link.writtenBytes)}};
}
} // namespace

// 只投影原writer已匹配的规则；失败仍保留此前命中，不在CLI再次运行谓词或读规则文件。
Value ApiCaptureRulesJson(const CooperativeApiRuleReceipt& rules)
{
    Ksword::Evidence::JsonArray behaviors; // 原writer的有界行为窗口，不重跑规则或从UI文本反解析。
    for (const auto& behavior : rules.recentBehaviors)
    {
        behaviors.push_back(RuleMatch(behavior.segmentOrdinal, behavior.match));
    }
    return Value::makeObject({{"presetSet", Value::makeString(rules.presetSet)},
        {"sourceSha256", rules.sourceSha256.empty() ? Value::makeNull() : Value::makeString(rules.sourceSha256)},
        {"configError", rules.configError.empty() ? Value::makeNull() : Value::makeString(rules.configError)},
        {"failed", Value::makeBool(rules.failed)}, {"matchedRows", Number(rules.matchedRows)},
        {"latestSegment", Number(rules.latestSegment)}, {"latest", LatestRule(rules)},
        {"behaviorMatches", Number(rules.behaviorMatches)},
        {"behaviorWindowTruncated", Value::makeBool(rules.behaviorMatches > rules.recentBehaviors.size())},
        {"recentBehaviors", Value::makeArray(std::move(behaviors))}});
}

// 三类候选各自保留原窗口和累计数量；JSON消费者可在运行期间按坐标回读，而非只有一个计数。
Value ApiCaptureTransferCandidatesJson(const CooperativeApiTransferReceipt& transfers)
{
    Ksword::Evidence::JsonArray recent; // 写入到线程创建的原候选窗口。
    for (const auto& link : transfers.recent)
    {
        auto fields = CandidateFields(link, "threadCreate", link.threadCreate); // 本候选两端的真实归档引用。
        fields.emplace_back("requestedStartAddress", Number(link.requestedStartAddress));
        fields.emplace_back("execution", Value::makeNull());
        recent.push_back(Value::makeObject(std::move(fields)));
    }

    Ksword::Evidence::JsonArray recentApc; // APC接受不等于投递或执行；与线程创建窗口独立。
    for (const auto& link : transfers.recentApc)
    {
        auto fields = CandidateFields(link, "apcQueue", link.queue); // 原写入和排队返回包坐标。
        fields.emplace_back("targetTid", Value::makeUInt(link.targetTid));
        fields.emplace_back("targetThreadCreationFileTime", Number(link.targetThreadCreationFileTime));
        fields.emplace_back("requestedRoutineAddress", Number(link.requestedRoutineAddress));
        fields.emplace_back("queueOutcome", Value::makeString("accepted"));
        fields.emplace_back("delivery", Value::makeNull());
        fields.emplace_back("execution", Value::makeNull());
        recentApc.push_back(Value::makeObject(std::move(fields)));
    }

    Ksword::Evidence::JsonArray recentContext; // 上下文IP保留请求含义，不等同于目标线程采用该IP。
    for (const auto& link : transfers.recentContext)
    {
        auto fields = CandidateFields(link, "context", link.context); // 原写入和上下文请求坐标。
        fields.emplace_back("targetTid", Value::makeUInt(link.targetTid));
        fields.emplace_back("targetThreadCreationFileTime", Number(link.targetThreadCreationFileTime));
        fields.emplace_back("requestedIp", Number(link.requestedIp));
        fields.emplace_back("requestedSp", Number(link.requestedSp));
        fields.emplace_back("contextArchitecture", Number(link.contextArchitecture));
        fields.emplace_back("requestOutcome", Value::makeString("accepted"));
        fields.emplace_back("contextApplied", Value::makeNull());
        fields.emplace_back("execution", Value::makeNull());
        recentContext.push_back(Value::makeObject(std::move(fields)));
    }

    // 窗口淘汰与累计数分别呈现，三类记录不混用同一个截断标志。
    return Value::makeObject({{"candidateCount", Number(transfers.candidateCount)},
        {"apcCandidateCount", Number(transfers.apcCandidateCount)},
        {"contextCandidateCount", Number(transfers.contextCandidateCount)},
        {"evictedWrites", Number(transfers.evictedWrites)},
        {"windowTruncated", Value::makeBool(transfers.candidateCount > transfers.recent.size())},
        {"apcWindowTruncated", Value::makeBool(transfers.apcCandidateCount > transfers.recentApc.size())},
        {"contextWindowTruncated", Value::makeBool(transfers.contextCandidateCount > transfers.recentContext.size())},
        {"recent", Value::makeArray(std::move(recent))}, {"recentApc", Value::makeArray(std::move(recentApc))},
        {"recentContext", Value::makeArray(std::move(recentContext))}});
}

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
        {"rules", ApiCaptureRulesJson(rules)},
        {"candidateCount", Number(candidateCount_)}, {"apcCandidateCount", Number(apcCandidateCount_)},
         {"contextCandidateCount", Number(contextCandidateCount_)}}));
    if (pendingTransfers_)
    {
        // 首段前未能发出的候选现在取得真实sample；只补最近快照，不重放历史通知。
        const auto pending = std::move(*pendingTransfers_); // 独立拥有回执，避免Transfers覆盖同一optional。
        pendingTransfers_.reset();
        Transfers(pending);
    }
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
        pendingTransfers_ = transfers; // 保留原有界候选；不用命令参数虚构采样身份，也不丢掉首段唯一候选。
        return;
    }
    pendingTransfers_.reset(); // 新快照已有真实身份时取代尚未发送的旧窗口，不在下一检查点倒退展示。
    const char* kind = !transfers.handoff.isNull() ? "transfer-handoff" :
        !transfers.networkTraffic.isNull() || !transfers.agentEtw.isNull() ? "api-source-progress" :
        "api-transfer-candidates"; // 来源快照不冒充转移候选或执行准入。
    Emit(kind, *sample, Value::makeObject({
        {"candidateCount", Number(transfers.candidateCount)}, {"apcCandidateCount", Number(transfers.apcCandidateCount)},
        {"contextCandidateCount", Number(transfers.contextCandidateCount)}, {"evictedWrites", Number(transfers.evictedWrites)},
        {"candidates", ApiCaptureTransferCandidatesJson(transfers)},
        {"transferHandoff", transfers.handoff}, {"networkTraffic", transfers.networkTraffic},
        {"agentEtw", transfers.agentEtw}}));
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

Value ApiCaptureProgress::AttachDelivery(Value result)
{
    if (!requested_ || !result.asObject())
    {
        return result;
    }
    auto fields = *result.asObject(); // 原响应保序复制，仅补本次输出通道事实，不重建控制回执。
    fields.emplace_back("captureProgress", Finish());
    return Value::makeObject(std::move(fields));
}

} // namespace ks::cli::action_analyze
