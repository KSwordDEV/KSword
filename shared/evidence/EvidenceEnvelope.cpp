#include "EvidenceEnvelope.h"

#include <algorithm>
#include <limits>

namespace Ksword::Evidence {

const char* CollectionStatusName(CollectionStatus status) noexcept {
    switch (status) {
    case CollectionStatus::NotCollected: return "NotCollected";
    case CollectionStatus::Success:      return "Success";
    case CollectionStatus::Partial:      return "Partial";
    case CollectionStatus::Unsupported:  return "Unsupported";
    case CollectionStatus::AccessDenied: return "AccessDenied";
    case CollectionStatus::Timeout:      return "Timeout";
    case CollectionStatus::Error:        return "Error";
    }
    return "NotCollected";
}

bool StatusCarriesObservation(CollectionStatus status) noexcept {
    return status == CollectionStatus::Success || status == CollectionStatus::Partial;
}

CollectionOutcome CollectionOutcome::success() noexcept {
    CollectionOutcome outcome;
    outcome.status = CollectionStatus::Success;
    return outcome;
}

CollectionOutcome CollectionOutcome::notCollected() noexcept {
    CollectionOutcome outcome;
    outcome.status = CollectionStatus::NotCollected;
    return outcome;
}

CollectionOutcome CollectionOutcome::failure(CollectionStatus status,
                                             std::string domain,
                                             std::uint64_t code,
                                             std::string message) {
    CollectionOutcome outcome;
    outcome.status = status;
    outcome.nativeCodeDomain = std::move(domain);
    outcome.nativeCode = OptionalU64::of(code);
    outcome.message = std::move(message);
    return outcome;
}

const char* AnalysisConclusionName(AnalysisConclusion conclusion) noexcept {
    switch (conclusion) {
    case AnalysisConclusion::NoEvidence:           return "NoEvidence";
    case AnalysisConclusion::NoDifferenceObserved: return "NoDifferenceObserved";
    case AnalysisConclusion::DifferenceObserved:   return "DifferenceObserved";
    case AnalysisConclusion::Indeterminate:        return "Indeterminate";
    }
    return "NoEvidence";
}

namespace {

// 账目计数是 u64 且来自不同的采集方，相加必须饱和，绝不回绕成一个更小的"已完成数"。
std::uint64_t SaturatingAdd(std::uint64_t a, std::uint64_t b) noexcept {
    constexpr std::uint64_t kMax = (std::numeric_limits<std::uint64_t>::max)();
    return (a > kMax - b) ? kMax : (a + b);
}

// 范围口径是否成立：四个端点必须**同时**在场。
// 只填了 begin 而没填 end 时，末尾边界根本无从校验，早先的实现会去读两个未设
// OptionalU64 的 .value（都是 0），"0 < 0" 恒假，于是末端完全不被检查（F-06）。
bool RangeStated(const CoverageAccount& coverage) noexcept {
    return coverage.requestedBegin.present && coverage.requestedEnd.present &&
           coverage.processedBegin.present && coverage.processedEnd.present;
}

bool AnyRangeEndpoint(const CoverageAccount& coverage) noexcept {
    return coverage.requestedBegin.present || coverage.requestedEnd.present ||
           coverage.processedBegin.present || coverage.processedEnd.present;
}

} // namespace

bool CoverageAccount::fullyCovered() const noexcept {
    // 否定项：任意一条成立就不可能是完整覆盖。
    // countsIncomplete 也在其中：某一项计数来源未知时，failed/skipped 里的 0 只是
    // "没数到"，不是"没发生"，据此判完整覆盖就是拿未知冒充完整。
    if (limitHit || cancelled || countsIncomplete ||
        failed != 0U || skipped != 0U || truncated != 0U) {
        return false;
    }

    // 正面证据 (a)：范围口径。四个端点齐全才认，且处理范围必须完全盖住请求范围。
    bool rangeComplete = false;
    if (RangeStated(*this)) {
        if (processedBegin.value > requestedBegin.value || processedEnd.value < requestedEnd.value) {
            return false;
        }
        rangeComplete = true;
    } else if (AnyRangeEndpoint(*this)) {
        // 端点残缺：说不清边界，宁可判不完整。
        return false;
    }

    // 正面证据 (b)：数量口径。声称了总数就必须处理完。
    bool countComplete = false;
    if (totalKnown.present) {
        if (succeeded < totalKnown.value) {
            return false;
        }
        countComplete = true;
    }

    // F-06：两条正面证据都没有 —— 例如默认构造的空账目 —— 是"覆盖未知"，
    // 不是"100% 完整扫描"。任何忘记填账目的采集方都不该白得一个完整覆盖。
    return rangeComplete || countComplete;
}

std::string CoverageAccount::describeRemaining() const {
    // F-06：停止原因优先。取消不是"命中上限"，两者在报告里不能混为一谈。
    if (cancelled) {
        return std::string("cancelled");
    }
    if (limitHit) {
        return std::string("limit-hit:") +
               (limit.present ? FormatU64(limit.value, U64Format::Decimal) : std::string("unknown"));
    }
    if (countsIncomplete) {
        // 至少有一项计数来源未知：数字只是下界。绝不能落到下面的 "remaining:N"
        // 分支去报一个看似精确的剩余量。
        return std::string("counts-incomplete");
    }
    if (truncated != 0U) {
        // 数量口径可能刚好"算平"，但截断本身就是没看全，必须先报出来，
        // 否则会和 fullyCovered() 给出互相矛盾的两句话。
        return std::string("truncated:") + FormatU64(truncated, U64Format::Decimal);
    }
    if (totalKnown.present) {
        const std::uint64_t done =
            SaturatingAdd(SaturatingAdd(succeeded, failed), SaturatingAdd(skipped, truncated));
        if (done < totalKnown.value) {
            return std::string("remaining:") + FormatU64(totalKnown.value - done, U64Format::Decimal);
        }
        if (failed != 0U || skipped != 0U) {
            // 条数对上了但其中有失败/跳过：剩余量为 0 不等于看全了。
            return std::string("incomplete:failed=") + FormatU64(failed, U64Format::Decimal) +
                   ",skipped=" + FormatU64(skipped, U64Format::Decimal);
        }
        return std::string("remaining:0");
    }
    if (RangeStated(*this)) {
        const std::uint64_t head = processedBegin.value > requestedBegin.value
                                       ? processedBegin.value - requestedBegin.value
                                       : 0ULL;
        const std::uint64_t tail = requestedEnd.value > processedEnd.value
                                       ? requestedEnd.value - processedEnd.value
                                       : 0ULL;
        return std::string("remaining-range:") + FormatU64(SaturatingAdd(head, tail), U64Format::Decimal);
    }
    if (requestedEnd.present && processedEnd.present && requestedEnd.value > processedEnd.value) {
        return std::string("remaining-range:") +
               FormatU64(requestedEnd.value - processedEnd.value, U64Format::Decimal);
    }
    // F-06：总数未知就明确说未知，不能用已返回数量冒充总量。
    return std::string("remaining:unknown");
}

const char* SourceOriginName(SourceOrigin origin) noexcept {
    switch (origin) {
    case SourceOrigin::Unknown:       return "Unknown";
    case SourceOrigin::LiveKernel:    return "LiveKernel";
    case SourceOrigin::LiveUserMode:  return "LiveUserMode";
    case SourceOrigin::ExternalFile:  return "ExternalFile";
    case SourceOrigin::OfflineSample: return "OfflineSample";
    }
    return "Unknown";
}

const char* CaptureModeName(CaptureMode mode) noexcept {
    switch (mode) {
    case CaptureMode::Unknown:   return "Unknown";
    case CaptureMode::Snapshot:  return "Snapshot";
    case CaptureMode::Streaming: return "Streaming";
    case CaptureMode::Replay:    return "Replay";
    }
    return "Unknown";
}

bool MonotonicComparable(const CaptureWindow& a, const CaptureWindow& b) noexcept {
    if (a.bootId.empty() || b.bootId.empty()) {
        return false;
    }
    if (a.bootId != b.bootId) {
        return false;
    }
    return a.machineId == b.machineId;
}

bool MonotonicDeltaNanos(const CaptureWindow& window,
                         std::uint64_t earlierTicks,
                         std::uint64_t laterTicks,
                         std::int64_t& outNanos) noexcept {
    if (window.bootId.empty() || !window.monotonicFrequency.present) {
        return false;
    }
    const std::uint64_t frequency = window.monotonicFrequency.value;
    if (frequency == 0U) {
        return false;
    }
    const bool forward = laterTicks >= earlierTicks;
    const std::uint64_t delta = forward ? (laterTicks - earlierTicks) : (earlierTicks - laterTicks);

    // delta / freq 秒 -> 纳秒，先整除再乘余数，避免 delta * 1e9 溢出。
    constexpr std::uint64_t kNanosPerSecond = 1000000000ULL;
    const std::uint64_t whole = delta / frequency;
    const std::uint64_t remainder = delta % frequency;
    constexpr std::uint64_t kMax = static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
    if (whole > kMax / kNanosPerSecond) {
        return false;
    }
    const std::uint64_t nanos = whole * kNanosPerSecond + (remainder * kNanosPerSecond) / frequency;
    if (nanos > kMax) {
        return false;
    }
    outNanos = forward ? static_cast<std::int64_t>(nanos) : -static_cast<std::int64_t>(nanos);
    return true;
}

AnalysisConclusion EvidenceEnvelope::deriveConclusion(bool differenceFound) const noexcept {
    if (!StatusCarriesObservation(outcome.status)) {
        // 采集失败/未采集/不支持：没有证据，不是"正常"。
        return AnalysisConclusion::NoEvidence;
    }
    if (differenceFound) {
        return AnalysisConclusion::DifferenceObserved;
    }
    if (outcome.status == CollectionStatus::Partial || !coverage.fullyCovered()) {
        // 覆盖不足时"没看到差异"不能升级成"未发现差异"。
        return AnalysisConclusion::Indeterminate;
    }
    return AnalysisConclusion::NoDifferenceObserved;
}

std::size_t TrustStatement::originViewCount(SourceOrigin origin) const noexcept {
    switch (origin) {
    case SourceOrigin::Unknown:       return unknownOriginViewCount;
    case SourceOrigin::LiveKernel:    return liveKernelViewCount;
    case SourceOrigin::LiveUserMode:  return liveUserModeViewCount;
    case SourceOrigin::ExternalFile:  return externalFileViewCount;
    case SourceOrigin::OfflineSample: return offlineSampleViewCount;
    }
    return 0U;
}

TrustStatement BuildTrustStatement(const std::vector<EvidenceEnvelope>& envelopes) {
    TrustStatement statement;
    statement.viewCount = envelopes.size();

    std::vector<std::string> groups;
    groups.reserve(envelopes.size());
    bool sawAny = false;
    bool allLiveKernel = true;

    for (const EvidenceEnvelope& envelope : envelopes) {
        // F-11：来源类别逐类计数，"这份结论有一半来自离线样本"必须能被看见。
        switch (envelope.source.origin) {
        case SourceOrigin::Unknown:       ++statement.unknownOriginViewCount; break;
        case SourceOrigin::LiveKernel:    ++statement.liveKernelViewCount; break;
        case SourceOrigin::LiveUserMode:  ++statement.liveUserModeViewCount; break;
        case SourceOrigin::ExternalFile:  ++statement.externalFileViewCount; break;
        case SourceOrigin::OfflineSample: ++statement.offlineSampleViewCount; break;
        }
        // X-01：同一个 sourceGroup 的多个视图只算一个独立来源。
        const std::string& group =
            envelope.source.sourceGroup.empty() ? envelope.source.collectorId : envelope.source.sourceGroup;
        if (std::find(groups.begin(), groups.end(), group) == groups.end()) {
            groups.push_back(group);
        }
        sawAny = true;
        if (envelope.source.origin != SourceOrigin::LiveKernel) {
            allLiveKernel = false;
        }
        // Partial 本身就说明没覆盖全请求范围，即使账目字段还没填也算覆盖不完整。
        if (envelope.outcome.status == CollectionStatus::Partial ||
            !StatusCarriesObservation(envelope.outcome.status) ||
            !envelope.coverage.fullyCovered()) {
            statement.anyIncompleteCoverage = true;
        }
    }

    statement.independentSourceGroupCount = groups.size();
    statement.allFromSameLiveKernel = sawAny && allLiveKernel;
    statement.distinctOriginCount =
        (statement.unknownOriginViewCount != 0U ? 1U : 0U) +
        (statement.liveKernelViewCount != 0U ? 1U : 0U) +
        (statement.liveUserModeViewCount != 0U ? 1U : 0U) +
        (statement.externalFileViewCount != 0U ? 1U : 0U) +
        (statement.offlineSampleViewCount != 0U ? 1U : 0U);

    // F-11：结论永远表述为限制，不表述为保证。
    if (statement.allFromSameLiveKernel) {
        statement.limitationKeys.emplace_back("trust.limitation.sameLiveKernel");
    }
    if (statement.independentSourceGroupCount <= 1U && statement.viewCount > 1U) {
        statement.limitationKeys.emplace_back("trust.limitation.singleSourceGroup");
    }
    // F-11：外部文件与离线样本描述的都不是"当前正在运行的内核"，混进结论时必须
    // 单独声明 —— 否则读者会把一份半离线的判断当成对现场的判断。
    if (statement.externalFileViewCount != 0U) {
        statement.limitationKeys.emplace_back("trust.limitation.externalFile");
    }
    if (statement.offlineSampleViewCount != 0U) {
        statement.limitationKeys.emplace_back("trust.limitation.offlineSample");
    }
    if (statement.anyIncompleteCoverage) {
        statement.limitationKeys.emplace_back("trust.limitation.incompleteCoverage");
    }
    statement.limitationKeys.emplace_back("trust.limitation.noAbsenceProof");
    return statement;
}

} // namespace Ksword::Evidence
