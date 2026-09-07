#include "MemoryRegionEvidence.h"

#include <algorithm>
#include <limits>

namespace Ksword::Evidence {
namespace {

constexpr std::uint64_t kU64Max = (std::numeric_limits<std::uint64_t>::max)();

std::string Fact(const char* key, const std::string& value) {
    return std::string(key) + "=" + value;
}

std::string FactBool(const char* key, bool value) {
    return Fact(key, value ? "true" : "false");
}

std::string FactCount(const char* key, std::uint64_t value) {
    return Fact(key, FormatU64(value, U64Format::Decimal));
}

std::string FactAddress(const char* key, const OptionalU64& value) {
    // 未知就写 unknown。写 0x0000000000000000 会被下游当成"地址是 0"。
    if (!value.present) {
        return Fact(key, "unknown");
    }
    return Fact(key, FormatU64(value.value, U64Format::HexAddress));
}

std::string FactText(const char* key, const std::string& value) {
    return Fact(key, value.empty() ? std::string("unknown") : value);
}

std::string DescribeRange(const AddressRange& range) {
    return FormatU64(range.begin, U64Format::HexAddress) + "+" +
           FormatU64(range.length, U64Format::Decimal);
}

// M-07/M-09：区域归属只有三种结果。没有映射路径就是未知，绝不写"系统"。
OwnerAttribution RegionAttribution(const RegionRecord& region, bool ownerKnown) noexcept {
    if (region.mappedPath.empty()) {
        return OwnerAttribution::Unknown;
    }
    return ownerKnown ? OwnerAttribution::DirectEvidence : OwnerAttribution::Candidate;
}

void AppendRegionFacts(const RegionRecord& region, std::vector<std::string>& facts) {
    facts.push_back(FactAddress("region.base", region.base));
    facts.push_back(Fact("region.size",
                         region.size.present ? FormatU64(region.size.value, U64Format::Decimal)
                                             : std::string("unknown")));
    facts.push_back(Fact("region.state", RegionStateName(region.state)));
    facts.push_back(Fact("region.type", RegionTypeName(region.type)));
    facts.push_back(Fact("region.source", RegionEvidenceSourceName(region.source)));
    facts.push_back(FactAddress("region.allocationBase", region.allocationBase));
    facts.push_back(FactText("region.mappedPath", region.mappedPath));
    facts.push_back(FactBool("protection.readable", region.protection.readable));
    facts.push_back(FactBool("protection.writable", region.protection.writable));
    facts.push_back(FactBool("protection.executable", region.protection.executable));
    facts.push_back(FactBool("vadVerified", VadVerified(region)));
}

// 从一组"是否命中"的位图里抽出极大连续段。孔洞与冲突范围共用这段逻辑。
std::vector<AddressRange> CollectRuns(std::uint64_t begin,
                                      const std::vector<bool>& flags,
                                      bool wanted) {
    std::vector<AddressRange> runs;
    std::size_t i = 0;
    const std::size_t count = flags.size();
    while (i < count) {
        if (flags[i] != wanted) {
            ++i;
            continue;
        }
        const std::size_t start = i;
        while (i < count && flags[i] == wanted) {
            ++i;
        }
        AddressRange run;
        run.begin = begin + static_cast<std::uint64_t>(start);
        run.length = static_cast<std::uint64_t>(i - start);
        runs.push_back(run);
    }
    return runs;
}

// 合并时的准入条件。MergeReadSpans 的两趟循环必须调用**同一个**判据：第一趟
// 排除掉、第二趟却放进来的 span（例如 begin+length 溢出 64 位的那种）会让
// base = begin - lowest 算出一个巨大值，随后 present[target] / bytes[target]
// 就是越界读写。把条件收成一个函数，正是为了让两趟不可能再走偏（M-02）。
bool MergeAdmits(const ReadSpan& span, std::uint64_t& end) noexcept {
    return span.consistent() && span.range.length != 0ULL && span.range.endAddress(end);
}

// 拒绝一次有界读取：一个字节都不读，但请求范围照实记账（F-06），
// 拒绝档位写进 rejection，绝不伪装成"正常跑完"（M-10）。
BoundedReadResult RejectBoundedRead(const BoundedReadRequest& request,
                                    RangeValidation validation,
                                    BoundedReadRejection rejection,
                                    std::uint64_t nativeCode,
                                    std::string message) {
    BoundedReadResult result;
    result.validation = validation;
    result.rejection = rejection;
    result.span.range = request.requested;
    result.span.range.length = 0ULL;
    result.span.observedUtc100ns = request.observedUtc100ns;
    result.span.outcome = CollectionOutcome::failure(CollectionStatus::Error,
                                                     "KSWORD",
                                                     nativeCode,
                                                     std::move(message));
    result.coverage.requestedBegin = OptionalU64::of(request.requested.begin);
    std::uint64_t end = 0ULL;
    if (request.requested.endAddress(end)) {
        result.coverage.requestedEnd = OptionalU64::of(end);
    }
    // 被拒的整段都没处理，全部记进 truncated —— coverage 全零会被读成"没什么可做"。
    result.coverage.truncated = request.requested.length;
    return result;
}

} // namespace

// ---------------------------------------------------------------------------
// M-01
// ---------------------------------------------------------------------------

const char* RegionStateName(RegionState state) noexcept {
    switch (state) {
    case RegionState::Unknown:  return "Unknown";
    case RegionState::Free:     return "Free";
    case RegionState::Reserved: return "Reserved";
    case RegionState::Commit:   return "Commit";
    }
    return "Unknown";
}

const char* RegionTypeName(RegionType type) noexcept {
    switch (type) {
    case RegionType::Unknown: return "Unknown";
    case RegionType::Private: return "Private";
    case RegionType::Mapped:  return "Mapped";
    case RegionType::Image:   return "Image";
    }
    return "Unknown";
}

const char* RegionEvidenceSourceName(RegionEvidenceSource source) noexcept {
    switch (source) {
    case RegionEvidenceSource::R3VirtualQuery:  return "R3VirtualQuery";
    case RegionEvidenceSource::R0VadWalk:       return "R0VadWalk";
    case RegionEvidenceSource::OfflineSnapshot: return "OfflineSnapshot";
    }
    return "R3VirtualQuery";
}

bool VadEvidence::complete() const noexcept {
    if (!profileVerified || profileId.empty()) {
        return false;
    }
    if (!vadNodeAddress.present || !startingVpn.present || !endingVpn.present) {
        return false;
    }
    // 反向区间说明链结构异常，按 M-06 停下，不当成可用证据。
    return endingVpn.value >= startingVpn.value;
}

bool VadVerified(const RegionRecord& record) noexcept {
    // 硬规则：只有真的走了 VAD（R0VadWalk）且字段齐全，才允许说"VAD 已验证"。
    // R3 的 VirtualQuery 结果哪怕被人手工填上 vad 字段，也不算。
    return record.source == RegionEvidenceSource::R0VadWalk && record.vad.complete();
}

bool RegionRange(const RegionRecord& record, AddressRange& out) noexcept {
    if (!record.base.present || !record.size.present || record.size.value == 0ULL) {
        return false;
    }
    if (record.size.value > kU64Max - record.base.value) {
        return false;
    }
    out.begin = record.base.value;
    out.length = record.size.value;
    return true;
}

// ---------------------------------------------------------------------------
// M-02
// ---------------------------------------------------------------------------

bool ReadSpan::consistent() const noexcept {
    if (bytes.size() != present.size()) {
        return false;
    }
    return static_cast<std::uint64_t>(bytes.size()) == range.length;
}

std::uint64_t ReadSpan::presentCount() const noexcept {
    std::uint64_t count = 0ULL;
    for (std::size_t i = 0; i < present.size(); ++i) {
        if (present[i]) {
            ++count;
        }
    }
    return count;
}

bool ReadSpan::hasHole() const noexcept {
    for (std::size_t i = 0; i < present.size(); ++i) {
        if (!present[i]) {
            return true;
        }
    }
    return false;
}

ReadSpan MakeEmptyReadSpan(const AddressRange& range) {
    ReadSpan span;
    span.range = range;
    std::uint64_t end = 0ULL;
    if (range.length == 0ULL || !range.endAddress(end) || range.length > kMaxReadSpanBytes) {
        // 非法或超限的范围一个字节都不分配，也不返回"空但成功"。
        span.range.length = 0ULL;
        span.outcome = CollectionOutcome::failure(CollectionStatus::Error,
                                                  "KSWORD",
                                                  static_cast<std::uint64_t>(RangeValidation::Overflow),
                                                  "read span range rejected");
        return span;
    }
    const std::size_t count = static_cast<std::size_t>(range.length);
    span.bytes.assign(count, 0U);
    span.present.assign(count, false);
    span.outcome = CollectionOutcome::notCollected();
    return span;
}

bool ApplyReadChunk(ReadSpan& span,
                    std::uint64_t address,
                    const std::uint8_t* data,
                    std::size_t length) {
    if (length == 0U) {
        return true;
    }
    if (data == nullptr || !span.consistent()) {
        return false;
    }
    if (address < span.range.begin) {
        return false;
    }
    const std::uint64_t offset = address - span.range.begin;
    if (offset > span.range.length || static_cast<std::uint64_t>(length) > span.range.length - offset) {
        return false;
    }
    const std::size_t base = static_cast<std::size_t>(offset);
    for (std::size_t i = 0; i < length; ++i) {
        span.bytes[base + i] = data[i];
        span.present[base + i] = true;
    }
    return true;
}

bool ByteAt(const ReadSpan& span, std::uint64_t address, std::uint8_t& out) noexcept {
    if (!span.consistent() || address < span.range.begin) {
        return false;
    }
    const std::uint64_t offset = address - span.range.begin;
    if (offset >= span.range.length) {
        return false;
    }
    const std::size_t index = static_cast<std::size_t>(offset);
    if (!span.present[index]) {
        // 孔洞：调用方拿不到值，因此不可能把补零当成真实数据（M-02）。
        return false;
    }
    out = span.bytes[index];
    return true;
}

std::vector<AddressRange> DescribeHoles(const ReadSpan& span) {
    if (!span.consistent()) {
        return {};
    }
    return CollectRuns(span.range.begin, span.present, false);
}

CollectionStatus ClassifyReadSpan(const ReadSpan& span) noexcept {
    if (!span.consistent() || span.range.length == 0ULL) {
        return CollectionStatus::Error;
    }
    const std::uint64_t got = span.presentCount();
    if (got == span.range.length) {
        return CollectionStatus::Success;
    }
    if (got == 0ULL) {
        // 一个字节都没读到不是"部分成功"。具体原因保留在 span.outcome 里。
        return CollectionStatus::Error;
    }
    return CollectionStatus::Partial;
}

CoverageAccount BuildReadCoverage(const ReadSpan& span) {
    CoverageAccount coverage;
    std::uint64_t end = 0ULL;
    if (!span.range.endAddress(end)) {
        return coverage;
    }
    coverage.requestedBegin = OptionalU64::of(span.range.begin);
    coverage.requestedEnd = OptionalU64::of(end);
    if (!span.consistent()) {
        return coverage;
    }
    const std::uint64_t got = span.presentCount();
    coverage.succeeded = got;
    coverage.failed = span.range.length - got;
    coverage.totalKnown = OptionalU64::of(span.range.length);
    // 处理到的范围就是请求范围：我们确实逐块尝试过，只是有些块没读到。
    coverage.processedBegin = coverage.requestedBegin;
    coverage.processedEnd = coverage.requestedEnd;
    return coverage;
}

const char* MergeObservationTimingName(MergeObservationTiming timing) noexcept {
    switch (timing) {
    case MergeObservationTiming::SingleObservation:      return "SingleObservation";
    case MergeObservationTiming::MultipleObservations:   return "MultipleObservations";
    case MergeObservationTiming::ObservationTimeUnknown: return "ObservationTimeUnknown";
    }
    return "ObservationTimeUnknown";
}

MergedReadSpan MergeReadSpans(const std::vector<ReadSpan>& spans) {
    MergedReadSpan merged;
    bool any = false;
    std::uint64_t lowest = 0ULL;
    std::uint64_t highest = 0ULL;
    std::size_t admitted = 0U;
    bool timeMissing = false;
    bool timeDiffers = false;
    OptionalU64 firstTime;

    for (const ReadSpan& span : spans) {
        std::uint64_t end = 0ULL;
        if (!MergeAdmits(span, end)) {
            continue;
        }
        ++admitted;
        // M-05：时刻关系只看被真正合并进来的那些段。
        if (!span.observedUtc100ns.present) {
            timeMissing = true;
        } else if (!firstTime.present) {
            firstTime = span.observedUtc100ns;
        } else if (firstTime.value != span.observedUtc100ns.value) {
            timeDiffers = true;
        }
        if (!any) {
            lowest = span.range.begin;
            highest = end;
            any = true;
            continue;
        }
        lowest = (std::min)(lowest, span.range.begin);
        highest = (std::max)(highest, end);
    }

    // 判据是采集时刻，不是字节值。两次观测字节恰好一样，只说明这段内存没被改过，
    // 不说明它们是同一时刻的快照 —— 拿字节相等当"同时"的证据正是 M-05 禁止的。
    if (timeDiffers) {
        merged.timing = MergeObservationTiming::MultipleObservations;
    } else if (admitted > 1U && timeMissing) {
        // 多段输入里有段没记时刻：无法证明同时，宁可降级也不冒充原子快照。
        merged.timing = MergeObservationTiming::ObservationTimeUnknown;
    } else {
        merged.timing = MergeObservationTiming::SingleObservation;
    }

    if (!any) {
        merged.span.outcome = CollectionOutcome::notCollected();
        return merged;
    }

    AddressRange full;
    full.begin = lowest;
    full.length = highest - lowest;
    merged.span = MakeEmptyReadSpan(full);
    if (merged.span.range.length == 0ULL) {
        return merged;  // MakeEmptyReadSpan 已经把拒绝原因写进 outcome
    }
    if (merged.timing == MergeObservationTiming::SingleObservation) {
        merged.span.observedUtc100ns = firstTime;
    }
    merged.byteObservedUtc100ns.assign(merged.span.bytes.size(), OptionalU64::unset());

    std::vector<bool> conflicts(merged.span.bytes.size(), false);
    for (const ReadSpan& span : spans) {
        std::uint64_t end = 0ULL;
        // 与第一趟**完全相同**的准入条件，一个字都不能少（见 MergeAdmits 的注释）。
        if (!MergeAdmits(span, end)) {
            continue;
        }
        // 再确认它确实落在第一趟算出的 [lowest, highest] 之内。lowest/highest 就是
        // 由这批 span 算出来的，多这一道确认是为了让 base 与 target 的界内性不依赖
        // 上面那趟循环的正确性 —— 越界读写是 BLOCKER，判据要能自证。
        if (span.range.begin < lowest || end > highest) {
            continue;
        }
        const std::size_t base = static_cast<std::size_t>(span.range.begin - lowest);
        for (std::size_t i = 0; i < span.present.size(); ++i) {
            if (!span.present[i]) {
                continue;
            }
            const std::size_t target = base + i;
            if (merged.span.present[target] && merged.span.bytes[target] != span.bytes[i]) {
                // 同一地址两次读到不同值：保留较新的值，并把冲突范围单列出来。
                conflicts[target] = true;
            }
            merged.span.bytes[target] = span.bytes[i];
            merged.span.present[target] = true;
            merged.byteObservedUtc100ns[target] = span.observedUtc100ns;
        }
    }
    merged.conflictingRanges = CollectRuns(lowest, conflicts, true);

    CollectionStatus status = ClassifyReadSpan(merged.span);
    if (status == CollectionStatus::Success &&
        (!merged.conflictingRanges.empty() ||
         merged.timing != MergeObservationTiming::SingleObservation)) {
        // 只有"覆盖完整 + 没有冲突 + 能证明来自同一次观测"才配叫 Success。
        status = CollectionStatus::Partial;
    }
    merged.span.outcome.status = status;
    if (!merged.conflictingRanges.empty()) {
        merged.span.outcome.message = "conflicting-observations";
    } else if (merged.timing == MergeObservationTiming::MultipleObservations) {
        merged.span.outcome.message = "observations-at-different-times";
    } else if (merged.timing == MergeObservationTiming::ObservationTimeUnknown) {
        merged.span.outcome.message = "observation-time-unrecorded";
    }
    return merged;
}

const char* BoundedReadRejectionName(BoundedReadRejection rejection) noexcept {
    switch (rejection) {
    case BoundedReadRejection::None:           return "None";
    case BoundedReadRejection::InvalidRange:   return "InvalidRange";
    case BoundedReadRejection::ReversedRange:  return "ReversedRange";
    case BoundedReadRejection::ExceedsMaxSpan: return "ExceedsMaxSpan";
    case BoundedReadRejection::NoBudget:       return "NoBudget";
    }
    return "InvalidRange";
}

BoundedReadResult ReadRangeBounded(const BoundedReadRequest& request, const ChunkReader& reader) {
    // 拒绝顺序：先看范围本身合不合法，再看跨度上限，最后看预算。三档都必须在返回
    // 结构上如实标出来 —— 任何一档伪装成"合法范围、没命中预算、正常跑完"都是
    // M-10 / F-06 的直接违反。
    const RangeValidation validation = ValidateRange(request.requested, request.approved);
    if (validation != RangeValidation::Ok) {
        // M-10：非法或越权范围一个字节都不读，也不留下"部分结果"的假象。
        return RejectBoundedRead(request,
                                 validation,
                                 BoundedReadRejection::InvalidRange,
                                 static_cast<std::uint64_t>(validation),
                                 RangeValidationName(validation));
    }
    if (request.requested.length > kMaxReadSpanBytes) {
        // 超过单次跨度上限。以前这里 validation=Ok、stop=Continue、coverage 全零，
        // 调用方会以为这次扫描正常跑完了什么都没有 —— 那是把拒绝伪装成成功。
        return RejectBoundedRead(request,
                                 RangeValidation::Ok,
                                 BoundedReadRejection::ExceedsMaxSpan,
                                 kMaxReadSpanBytes,
                                 "requested span exceeds kMaxReadSpanBytes");
    }
    if (!request.budget.bounded()) {
        // M-10：忘了设预算的调用点不该能一次读走 64 MiB 内核内存。无界即拒绝。
        return RejectBoundedRead(request,
                                 RangeValidation::Ok,
                                 BoundedReadRejection::NoBudget,
                                 0ULL,
                                 "scan budget is unbounded");
    }

    BoundedReadResult result;
    result.validation = RangeValidation::Ok;
    result.span = MakeEmptyReadSpan(request.requested);
    result.span.observedUtc100ns = request.observedUtc100ns;
    if (result.span.range.length == 0ULL) {
        // 上面三道判据理论上已经把所有拒绝理由拦完；真到这里说明 MakeEmptyReadSpan
        // 还有自己的兜底判据生效了，同样按明确拒绝返回，不返回"空但成功"。
        result.rejection = BoundedReadRejection::ExceedsMaxSpan;
        result.coverage.requestedBegin = OptionalU64::of(request.requested.begin);
        result.coverage.truncated = request.requested.length;
        return result;
    }

    const std::uint64_t chunkSize = (request.chunkSize == 0ULL) ? 0x1000ULL : request.chunkSize;
    std::uint64_t end = 0ULL;
    (void)request.requested.endAddress(end);  // ValidateRange 已保证不溢出

    ScanProgress progress;
    std::vector<std::uint8_t> buffer;
    std::uint64_t cursor = request.requested.begin;

    // F-05：第一条失败的原始码原样留下来。没有它，STATUS_ACCESS_DENIED、目标进程
    // 已退出、页不可读三种失败在结果里长得一模一样。
    bool failureCaptured = false;
    CollectionStatus failureStatus = CollectionStatus::Error;
    OptionalU64 failureCode;
    std::string failureDomain;
    std::string failureMessage;

    while (cursor < end) {
        progress.cancelRequested = request.cancelRequested ? request.cancelRequested() : false;
        if (request.elapsedNanos) {
            progress.elapsedNanos = request.elapsedNanos();
        }
        result.stop = EvaluateBudget(request.budget, progress);
        if (result.stop != BudgetStop::Continue) {
            break;
        }

        // 按 chunkSize 边界切块，页边界因此必然落在块边界上。
        std::uint64_t chunkEnd = end;
        const std::uint64_t aligned = cursor - (cursor % chunkSize);
        if (aligned <= kU64Max - chunkSize) {
            const std::uint64_t boundary = aligned + chunkSize;
            if (boundary < chunkEnd) {
                chunkEnd = boundary;
            }
        }
        std::uint64_t length = chunkEnd - cursor;
        if (request.budget.maxBytes.present) {
            // 字节预算精确到字节：不允许为了凑整块而超出用户批准的上限。
            const std::uint64_t remaining = (request.budget.maxBytes.value > progress.bytesDone)
                                                ? (request.budget.maxBytes.value - progress.bytesDone)
                                                : 0ULL;
            length = (std::min)(length, remaining);
            if (length == 0ULL) {
                result.stop = BudgetStop::BytesExhausted;
                break;
            }
        }

        buffer.assign(static_cast<std::size_t>(length), 0U);
        ChunkReadResult chunk;
        if (reader) {
            reader(cursor, buffer.data(), buffer.size(), chunk);
        } else {
            chunk.status = CollectionStatus::Error;
            chunk.message = "no chunk reader supplied";
        }
        std::size_t copied = chunk.copied;
        if (copied > buffer.size()) {
            copied = buffer.size();  // 回调撒谎时按缓冲区截断，绝不越界写入
        }
        if (copied > 0U) {
            (void)ApplyReadChunk(result.span, cursor, buffer.data(), copied);
        }
        if (!failureCaptured && copied < buffer.size()) {
            // 只记第一条：它是"为什么这次读不全"的直接原因，后面的多半是它的连锁。
            failureCaptured = true;
            // 回调没给具体状态（或声称成功却没拷满）时才退到通用 Error；
            // 给了 AccessDenied / Unsupported / Timeout 就原样保留。
            failureStatus = (chunk.status == CollectionStatus::NotCollected ||
                             chunk.status == CollectionStatus::Success ||
                             chunk.status == CollectionStatus::Partial)
                                ? CollectionStatus::Error
                                : chunk.status;
            failureCode = chunk.nativeCode;
            failureDomain = chunk.nativeCodeDomain;
            failureMessage = chunk.message;
        }

        progress.bytesDone += length;
        progress.pagesDone += 1ULL;
        progress.itemsDone += 1ULL;
        // 按实际尝试的长度前进：字节预算把块截短时，游标不能跳到整块末尾，
        // 否则被跳过的字节会既没读到也没记进截断账目。
        cursor += length;
    }

    // 账目分三笔，互不重复计数：读到的、试过但读不到的、根本没试到的。
    const std::uint64_t processed = cursor - request.requested.begin;
    const std::uint64_t got = result.span.presentCount();
    result.coverage = BuildReadCoverage(result.span);
    result.coverage.succeeded = got;
    result.coverage.failed = (processed > got) ? (processed - got) : 0ULL;
    result.coverage.truncated = request.requested.length - processed;
    result.coverage.processedEnd = OptionalU64::of(cursor);

    if (result.stop == BudgetStop::Continue) {
        const CollectionStatus coverageStatus = ClassifyReadSpan(result.span);
        result.span.outcome.status = coverageStatus;
        if (coverageStatus == CollectionStatus::Partial) {
            result.span.outcome.message = "unreadable-holes";
        }
        if (coverageStatus == CollectionStatus::Error && failureCaptured) {
            // 一个字节都没读到时，到底是哪一种失败必须留下来（F-05）。
            result.span.outcome.status = failureStatus;
        }
    } else {
        // 命中上限或被取消：整体是 Partial，理由由 OutcomeForStop 给出。
        result.span.outcome = OutcomeForStop(result.stop);
        ApplyStopToCoverage(result.stop, request.budget, result.coverage);
    }
    if (failureCaptured) {
        // 原始码与来源原文原样带回，绝不用默认 0 / 空串补齐（F-05）。
        result.span.outcome.nativeCode = failureCode;
        result.span.outcome.nativeCodeDomain = failureDomain;
        // 停止理由（budget:* / cancelled）本身就是这次不完整的主因，不被读取失败
        // 的文案覆盖；只有跑完整段时才把来源原文摆到最前面。
        if (!failureMessage.empty() && result.stop == BudgetStop::Continue) {
            result.span.outcome.message = failureMessage;
        }
    }
    return result;
}

BoundedReadResult ReadRangeBoundedFromEndpoints(std::uint64_t begin,
                                                std::uint64_t end,
                                                const BoundedReadRequest& request,
                                                const ChunkReader& reader) {
    BoundedReadRequest adjusted = request;
    adjusted.requested.begin = begin;
    adjusted.requested.length = 0ULL;
    if (end < begin) {
        // M-10：逆序范围。AddressRange 用 (begin,length) 表达，endAddress() 成功后
        // end 必然 >= begin，所以这条判据在那种表示里根本不可达 —— 只有在这个接受
        // end 的入口里才能真正生效。这里判，并且一个字节都不读。
        BoundedReadResult rejected = RejectBoundedRead(adjusted,
                                                       RangeValidation::Reversed,
                                                       BoundedReadRejection::ReversedRange,
                                                       static_cast<std::uint64_t>(
                                                           RangeValidation::Reversed),
                                                       RangeValidationName(
                                                           RangeValidation::Reversed));
        // 调用方给的 end 照实记下来，UI 才能说清"你要的是哪一段"。
        rejected.coverage.requestedEnd = OptionalU64::of(end);
        return rejected;
    }
    adjusted.requested.length = end - begin;
    return ReadRangeBounded(adjusted, reader);
}

// ---------------------------------------------------------------------------
// M-09
// ---------------------------------------------------------------------------

const char* OwnerAttributionName(OwnerAttribution attribution) noexcept {
    switch (attribution) {
    case OwnerAttribution::DirectEvidence: return "DirectEvidence";
    case OwnerAttribution::Candidate:      return "Candidate";
    case OwnerAttribution::Unknown:        return "Unknown";
    }
    return "Unknown";
}

PoolAttributionResult AttributeByTag(const std::string& tag,
                                     const std::vector<PoolTagOwnerEntry>& knownTagOwners) {
    PoolAttributionResult result;
    result.allocationStackAvailable = false;  // 本函数只看标签，永远没有分配栈
    if (tag.empty()) {
        result.attribution = OwnerAttribution::Unknown;
        result.facts.push_back(Fact("pool.tag", "absent"));
        return result;
    }
    result.facts.push_back(Fact("pool.tag", tag));

    for (const PoolTagOwnerEntry& entry : knownTagOwners) {
        if (entry.tag != tag || entry.ownerId.empty()) {
            continue;
        }
        if (std::find(result.candidateOwners.begin(), result.candidateOwners.end(), entry.ownerId) !=
            result.candidateOwners.end()) {
            continue;
        }
        result.candidateOwners.push_back(entry.ownerId);
        result.facts.push_back(Fact("pool.tagOwner", entry.ownerId));
        if (!entry.sourceNote.empty()) {
            result.facts.push_back(Fact("pool.tagOwnerSource", entry.sourceNote));
        }
    }

    result.facts.push_back(FactCount("pool.tagOwnerCount",
                                     static_cast<std::uint64_t>(result.candidateOwners.size())));
    if (result.candidateOwners.empty()) {
        result.attribution = OwnerAttribution::Unknown;
        return result;
    }
    // M-09 硬规则：标签不是所有者证明。哪怕表里只有一个 owner，也只能是候选 ——
    // 多组件共用同一个 tag 是常态，表不全更是常态。
    result.attribution = OwnerAttribution::Candidate;
    return result;
}

PoolAttributionResult AttributeByAllocationEvent(const PoolAllocationEvent& event,
                                                 const PoolAttributionResult& tagFallback) {
    if (!event.captured) {
        // 没有事先采集的分配事件就退回标签那一档，不编造。
        PoolAttributionResult result = tagFallback;
        result.allocationStackAvailable = false;
        result.facts.push_back(Fact("pool.allocationEvent", "not-captured"));
        return result;
    }
    PoolAttributionResult result;
    result.allocationStackAvailable = true;
    result.attribution = OwnerAttribution::DirectEvidence;
    const std::string key = event.allocator.crossSessionKey();
    if (key.empty()) {
        // 事件在，但分配者身份不足以跨会话确认：降级为候选，不硬升成直接证据。
        result.attribution = OwnerAttribution::Candidate;
        result.facts.push_back(Fact("pool.allocatorIdentity", "insufficient"));
    }
    if (!event.allocator.imagePath.empty()) {
        result.candidateOwners.push_back(event.allocator.imagePath);
        result.facts.push_back(Fact("pool.allocator", event.allocator.imagePath));
    }
    result.facts.push_back(FactText("pool.allocationEventSource", event.eventSourceId));
    result.facts.push_back(FactAddress("pool.allocationEventUtc100ns", event.eventUtc100ns));
    return result;
}

// ---------------------------------------------------------------------------
// M-07
// ---------------------------------------------------------------------------

const char* const kRuleIdPrivateExecutable = "mem.exec.private";
const char* const kRuleIdImageBytesDiffer = "mem.exec.image-bytes-differ";
const char* const kRuleIdThreadOriginMismatch = "mem.exec.thread-origin-mismatch";
const char* const kRuleIdThreadOriginUnknown = "mem.exec.thread-origin-unknown";

ExecutableRegionReport EvaluateExecutableRegion(const ExecutableRegionInput& input) {
    ExecutableRegionReport report;
    report.attribution = RegionAttribution(input.region, input.regionOwnerKnown);

    // 规则一：private executable。这只是一个特征，JIT / .NET / 打包器都会命中，
    // 因此它只交事实，不给结论 —— 归属未知就保持未知。
    if (input.region.protection.executable && input.region.type == RegionType::Private) {
        ExecutableRegionFinding finding;
        finding.ruleId = kRuleIdPrivateExecutable;
        finding.ruleVersion = 1U;
        AppendRegionFacts(input.region, finding.facts);
        finding.facts.push_back(FactBool("region.privateExecutable", true));
        finding.attribution = report.attribution;
        if (!input.region.mappedPath.empty()) {
            finding.candidateOwners.push_back(input.region.mappedPath);
        }
        finding.inputOutcome = CollectionOutcome::success();
        report.findings.push_back(finding);
    }

    // 规则二：image 区域字节与磁盘不一致。
    bool comparedClean = false;
    bool differenceConfirmed = false;
    const ImageBytesComparison& comparison = input.imageComparison;
    const bool comparisonAttempted =
        comparison.compared || comparison.outcome.status != CollectionStatus::NotCollected;
    if (input.region.type == RegionType::Image && comparisonAttempted) {
        ExecutableRegionFinding finding;
        finding.ruleId = kRuleIdImageBytesDiffer;
        finding.ruleVersion = 1U;
        AppendRegionFacts(input.region, finding.facts);
        finding.facts.push_back(FactText("image.onDiskPath", comparison.onDiskPath));
        finding.facts.push_back(FactBool("image.compared", comparison.compared));
        finding.facts.push_back(
            Fact("image.compareStatus", CollectionStatusName(comparison.outcome.status)));
        finding.facts.push_back(FactBool("image.relocationsApplied", comparison.relocationsApplied));
        finding.facts.push_back(
            FactCount("image.differingRangeCount",
                      static_cast<std::uint64_t>(comparison.differingRanges.size())));
        for (const AddressRange& range : comparison.differingRanges) {
            finding.facts.push_back(Fact("image.differingRange", DescribeRange(range)));
        }
        finding.attribution = report.attribution;
        if (!comparison.onDiskPath.empty()) {
            finding.candidateOwners.push_back(comparison.onDiskPath);
        }
        finding.inputOutcome = comparison.outcome;
        report.findings.push_back(finding);

        const bool usable =
            comparison.compared && comparison.outcome.status == CollectionStatus::Success;
        comparedClean = usable && comparison.differingRanges.empty();
        // 没做重定位/热补丁归一化时，差异里混着正常改动，只能算线索不能算结论。
        differenceConfirmed =
            usable && !comparison.differingRanges.empty() && comparison.relocationsApplied;
    }

    // 规则三：线程起始地址与映射归属不一致。
    for (const ThreadStartFact& thread : input.threads) {
        if (!thread.startAddress.present) {
            // 起始地址拿不到就是拿不到，不拿区域基址顶替。而且这是"没有观测"，
            // 不是"归属不一致" —— 两者共用一个 ruleId 会让 UI 与导出读成同一条
            // 线索，也会让一条零观测的 finding 把结论抬高（F-05）。所以单独一条。
            ExecutableRegionFinding unknownStart;
            unknownStart.ruleId = kRuleIdThreadOriginUnknown;
            unknownStart.ruleVersion = 1U;
            unknownStart.facts.push_back(FactAddress("thread.startAddress", thread.startAddress));
            unknownStart.facts.push_back(FactText("thread.key", thread.thread.crossSessionKey()));
            unknownStart.facts.push_back(
                Fact("thread.identityStrength", IdentityStrengthName(thread.thread.strength())));
            unknownStart.attribution = OwnerAttribution::Unknown;
            unknownStart.inputOutcome = CollectionOutcome::notCollected();
            report.findings.push_back(unknownStart);
            continue;
        }
        if (!thread.startAddressInsideRegion) {
            continue;
        }
        const bool pathUnknown = thread.startAddressMappedPath.empty();
        if (!pathUnknown && thread.startAddressMappedPath == input.region.mappedPath) {
            continue;  // 归属一致，没有可报的事实
        }

        ExecutableRegionFinding finding;
        finding.ruleId = kRuleIdThreadOriginMismatch;
        finding.ruleVersion = 1U;
        finding.facts.push_back(FactAddress("thread.startAddress", thread.startAddress));
        finding.facts.push_back(FactText("thread.key", thread.thread.crossSessionKey()));
        finding.facts.push_back(
            Fact("thread.identityStrength", IdentityStrengthName(thread.thread.strength())));
        finding.facts.push_back(FactText("thread.startMappedPath", thread.startAddressMappedPath));
        finding.facts.push_back(FactText("region.mappedPath", input.region.mappedPath));
        finding.facts.push_back(FactBool("thread.startInsideRegion", true));
        if (pathUnknown) {
            finding.attribution = OwnerAttribution::Unknown;
        } else {
            // 两条路径都非空且不同：哪一边是"真正的归属"没有证据可判，
            // 所以两边都只是候选，全列出来，不挑一个当结论（M-09）。
            finding.attribution = OwnerAttribution::Candidate;
            finding.candidateOwners.push_back(thread.startAddressMappedPath);
            if (!input.region.mappedPath.empty()) {
                finding.candidateOwners.push_back(input.region.mappedPath);
            }
        }
        finding.inputOutcome = CollectionOutcome::success();
        report.findings.push_back(finding);
    }

    // F-05：Indeterminate 是"有观测但不足以判断"，NoEvidence 才是"没有可用观测"。
    // 所以只有真的携带观测的 finding 才能把结论从 NoEvidence 抬到 Indeterminate ——
    // 一条 inputOutcome=NotCollected 的 finding 抬不动任何结论。
    std::size_t observedFindings = 0U;
    for (const ExecutableRegionFinding& finding : report.findings) {
        if (StatusCarriesObservation(finding.inputOutcome.status)) {
            ++observedFindings;
        }
    }

    if (differenceConfirmed) {
        report.conclusion = AnalysisConclusion::DifferenceObserved;
    } else if (comparedClean) {
        report.conclusion = AnalysisConclusion::NoDifferenceObserved;
    } else if (observedFindings != 0U) {
        // 有线索但不足以判定。private RX 单独一条永远停在这里 ——
        // 把它升级成"恶意"正是 M-07 明令禁止的。
        report.conclusion = AnalysisConclusion::Indeterminate;
    } else {
        report.conclusion = AnalysisConclusion::NoEvidence;
    }
    return report;
}

} // namespace Ksword::Evidence
