#include "PrivateExecutionCandidates.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace Ksword::ActionAnalyze::Detection {
namespace {
using namespace Evidence;
constexpr std::uint64_t kPageBytes = 4096; // 既有AddPrivateExecutionRange的明确整页约束。
constexpr auto kOutputFlags = ApiMemoryOutputBase | ApiMemoryOutputBytes; // 两项实际输出均须有效。

// 输入原保护值，输出基础保护是否包含execute；忽略修饰位但保留原值在调用中。
bool ExecutableProtection(std::uint64_t value)
{
    const auto protection = value & 0xff; // 原新保护的低字节基础值。
    return protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
        protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
}

// 原值半开范围必须非空且不溢出；不能用请求范围代替成功输出。
bool ActualRange(const ApiMemoryLifecycleFieldsV1& fields)
{
    return fields.returnValid && fields.status >= 0 && (fields.flags & kOutputFlags) == kOutputFlags &&
        fields.outputBase && fields.outputBytes && fields.outputBytes <=
        (std::numeric_limits<std::uint64_t>::max)() - fields.outputBase;
}

// 目标稳定强实例只来自AAIM1原查询，source/target同PID时还须创建代次一致。
bool StrongTarget(const PrivateMemoryCall& call)
{
    const auto& fields = *call.record.apiMemoryLifecycle; // 本模块只构造已解码调用。
    constexpr auto required = ApiMemoryTargetIdentity | ApiMemoryTargetStable;
    if ((fields.flags & required) != required || !fields.targetPid || !fields.targetCreationFileTime)
    {
        return false;
    }
    return !call.record.headerPid || fields.targetPid != *call.record.headerPid ||
        !(fields.flags & ApiMemoryActorIdentity) || fields.targetCreationFileTime == fields.actorCreationFileTime;
}

// 输入独立原调用，输出范围候选语义；Allocate不要求初始execute，但不宣称MEM_PRIVATE。
PrivateExecutionCandidate Candidate(PrivateMemoryCall call)
{
    PrivateExecutionCandidate row; // 失败及Free也保留完整调用，只是不产生范围草稿。
    row.origin = std::move(call);
    const auto& fields = *row.origin.record.apiMemoryLifecycle; // 原严格AAIM1解析输出。
    row.executableProtection = (fields.operation == ApiMemoryOperation::Allocate || fields.operation == ApiMemoryOperation::Protect) &&
        ExecutableProtection(fields.newProtection);
    row.strongTarget = StrongTarget(row.origin);
    if (fields.operation == ApiMemoryOperation::Free)
    {
        row.reason = "free-request-actual-release-unknown";
        return row;
    }
    if (fields.operation == ApiMemoryOperation::Unmap)
    {
        row.reason = "unmap-request-actual-range-unknown";
        return row; // 直接地址属于原请求，不能转成私有执行范围或使旧候选失活。
    }
    if (!ActualRange(fields))
    {
        row.reason = "successful-actual-output-unavailable";
        return row;
    }
    if (fields.operation == ApiMemoryOperation::Protect && !row.executableProtection)
    {
        row.reason = "protection-is-not-executable";
        return row;
    }
    row.rangeCandidate = true;
    row.reason = row.strongTarget ? "explicit-held-owner-verification-required" : "strong-target-unavailable";
    PrivateExecutionRangeDraft draft; // 不裁剪、不自动扩页；整段不适合则由用户明确选子范围。
    if (PreparePrivateExecutionRangeDraft(row, fields.outputBase, fields.outputBytes, draft))
    {
        row.wholeRangeDraft = std::move(draft);
    }
    return row;
}

// 只关联同一来源强实例/会话/代次中的严格先后原调用，不比较跨来源QPC。
bool RelatedFree(const PrivateExecutionCandidate& candidate, const PrivateMemoryCall& call,
    PrivateFreeRequestLink& link)
{
    const auto& origin = candidate.origin; // 原Allocate或Protect调用，单独保留其身份。
    const auto& prior = *origin.record.apiMemoryLifecycle;
    const auto& free = *call.record.apiMemoryLifecycle;
    if (!candidate.rangeCandidate || !candidate.strongTarget || !StrongTarget(call) ||
        free.operation != ApiMemoryOperation::Free || !(prior.flags & ApiMemoryActorIdentity) ||
        !(free.flags & ApiMemoryActorIdentity) || !origin.record.headerPid ||
        origin.record.headerPid != call.record.headerPid || prior.actorCreationFileTime != free.actorCreationFileTime ||
        prior.targetPid != free.targetPid || prior.targetCreationFileTime != free.targetCreationFileTime ||
        !origin.record.apiSourceSession || origin.record.apiSourceSession != call.record.apiSourceSession ||
        origin.evidence.sourceId != call.evidence.sourceId || origin.evidence.sourceEpoch != call.evidence.sourceEpoch ||
        !origin.evidence.sourceSequence || !call.evidence.sourceSequence ||
        *origin.evidence.sourceSequence >= *call.evidence.sourceSequence ||
        !prior.enterQpc || !prior.returnQpc || !free.enterQpc || !free.returnQpc || prior.returnQpc >= free.enterQpc ||
        !(free.flags & ApiMemoryRequestedBase))
    {
        return false;
    }
    const auto end = prior.outputBase + prior.outputBytes; // 已由ActualRange证明不溢出。
    const bool baseInside = free.requestedBase >= prior.outputBase && free.requestedBase < end;
    const bool overlap = (free.flags & ApiMemoryRequestedBytes) && free.requestedBytes &&
        free.requestedBytes <= (std::numeric_limits<std::uint64_t>::max)() - free.requestedBase &&
        free.requestedBase < end && prior.outputBase < free.requestedBase + free.requestedBytes;
    if (!baseInside && !overlap)
    {
        return false;
    }
    link = {call, overlap, baseInside}; // 即使返回成功也只标请求相关，不失活候选。
    return true;
}
} // namespace

ProjectResult PreparePrivateExecutionRangeDraft(const PrivateExecutionCandidate& candidate,
    std::uint64_t address, std::uint64_t bytes, PrivateExecutionRangeDraft& out)
{
    const auto& call = candidate.origin; // 选择必须保留真实原坐标及已核验AAIM1。
    if (!candidate.rangeCandidate || !call.record.apiMemoryLifecycle || !StrongTarget(call) ||
        !HasArchivedApiLocation({call.evidence.projectId, call.evidence.sampleId, {}, {}}, call.evidence))
    {
        return {ProjectError::InvalidArgument, 0, "privateCandidateStrongTarget"};
    }
    const auto& fields = *call.record.apiMemoryLifecycle; // 输入实际半开范围，绝不向外对齐。
    if (!ActualRange(fields) || fields.operation == ApiMemoryOperation::Free ||
        (fields.operation != ApiMemoryOperation::Allocate && fields.operation != ApiMemoryOperation::Protect) ||
        (fields.operation == ApiMemoryOperation::Protect && !ExecutableProtection(fields.newProtection)) ||
        !address || !bytes || address % kPageBytes || bytes % kPageBytes || bytes > 64 * kPageBytes ||
        address < fields.outputBase || address - fields.outputBase > fields.outputBytes ||
        bytes > fields.outputBytes - (address - fields.outputBase))
    {
        return {ProjectError::InvalidArgument, 0, "privateCandidateExplicitSubrange"};
    }
    out = {call.evidence.projectId, call.evidence.sampleId, static_cast<std::uint32_t>(fields.targetPid),
        fields.targetCreationFileTime, address, bytes, call}; // 仍是待held owner核验的纯值草稿。
    return {};
}

ProjectResult ReadPrivateExecutionCandidates(const ProjectDocument& project,
    const PrivateExecutionCandidatesRequest& request, PrivateExecutionCandidatesPage& out)
{
    if (!request.throughOrdinal || request.throughOrdinal > kArchivedGraphMaxApiSegments || !request.limit ||
        request.limit > kPrivateCandidateMaxPage || (request.after && (!request.after->segmentOrdinal ||
        request.after->segmentOrdinal > request.throughOrdinal || !request.after->sequence || request.expectedSnapshot.empty())))
    {
        return {ProjectError::InvalidArgument, 0, "privateCandidatesRequest"};
    }
    PrivateExecutionCandidatesPage page; // 只在全部选择前缀通过后替换out，失败不泄漏局部成功。
    page.throughOrdinal = request.throughOrdinal;
    std::vector<PrivateExecutionCandidate> events; // 有界全前缀状态，供Free关联与稳定页计数。
    for (std::uint64_t ordinal = 1; ordinal <= request.throughOrdinal; ++ordinal)
    {
        std::uint64_t after = 0; // 复用原读取器的当前段观察游标，不拿源序号代替。
        std::string digest; // 同段分页绑定第一次核验的实际摘要。
        do
        {
            ArchivedGraphPage archived; // 与execution correlate完全相同的来源/链/坏尾核验。
            const auto status = ReadArchivedEvidenceGraph(project,
                {request.sampleId, ordinal, after, kArchivedGraphMaxRows, digest}, archived);
            if (!status)
            {
                return status;
            }
            if (archived.source != ArchivedGraphSource::CommittedApiFollow ||
                archived.records.size() != archived.graph.observations.size())
            {
                return {ProjectError::Unsupported, 0, "privateCandidatesCommittedApiRequired"};
            }
            if (digest.empty())
            {
                page.scope = archived.graph.scope;
                if (page.snapshot.empty())
                {
                    page.snapshot = "private-candidates-v1|" + page.scope.projectId + "|" + page.scope.sampleId +
                        "|" + archived.descriptionHash;
                }
                page.snapshot += "|" + archived.sha256; // 续页比较所有段，不能只绑定最后一段。
                digest = archived.sha256;
                page.observationCount += archived.observationCount;
                if (page.observationCount > kPrivateCandidateMaxObservations)
                {
                    return {ProjectError::LimitExceeded, 0, "privateCandidatesObservationBudget"};
                }
            }
            page.finalSegment = archived.apiFinalSegment.value_or(false);
            for (std::size_t index = 0; index < archived.records.size(); ++index)
            {
                const auto& record = archived.records[index]; // 与observation同索引的真实调用坐标。
                const auto& observation = archived.graph.observations[index]; // 原包解码缺口及来源引用。
                const bool lifecycle = record.apiFamily == "memory-allocation" || record.apiFamily == "memory-protection" ||
                    record.apiFamily == "memory-free-request" || record.apiFamily == "memory-unmap-request";
                if (!lifecycle)
                {
                    continue;
                }
                if (!record.apiMemoryLifecycle)
                {
                    if (std::find(observation.gaps.begin(), observation.gaps.end(), Issue::InvalidNativeRecord) != observation.gaps.end())
                    {
                        ++page.malformedLifecycleCount;
                    }
                    else
                    {
                        ++page.legacyLifecycleCount;
                    }
                    continue; // 坏AAIM1/旧摘要不能按文本解析成范围，缺口计数不可丢。
                }
                if (!observation.evidence || !HasArchivedApiLocation(page.scope, *observation.evidence) ||
                    !record.apiSourceSession)
                {
                    return {ProjectError::Corrupt, 0, "privateCandidatesCallCoordinate"};
                }
                if (events.size() == kPrivateCandidateMaxEvents)
                {
                    return {ProjectError::LimitExceeded, 0, "privateCandidatesLifecycleBudget"};
                }
                events.push_back(Candidate({*observation.evidence, record, digest}));
                page.rangeCandidateCount += events.back().rangeCandidate;
                page.freeRequestCount += record.apiMemoryLifecycle->operation == ApiMemoryOperation::Free;
            }
            if (!archived.nextAfterSequence)
            {
                break;
            }
            if (*archived.nextAfterSequence <= after)
            {
                return {ProjectError::Corrupt, 0, "privateCandidatesCursorProgress"};
            }
            after = *archived.nextAfterSequence;
        } while (true);
    }

    page.lifecycleCount = events.size(); // 成功空目录仍有snapshot、扫描计数及格式缺口。
    if (!request.expectedSnapshot.empty() && request.expectedSnapshot != page.snapshot)
    {
        return {ProjectError::StaleRevision, 0, "privateCandidatesSnapshot"};
    }
    std::size_t first = 0; // 不允许未知游标静默跳过结果，游标必须属于本次冻结目录。
    if (request.after)
    {
        const auto cursor = std::find_if(events.begin(), events.end(), [&](const auto& row)
        {
            return row.origin.evidence.raw == request.after;
        });
        if (cursor == events.end())
        {
            return {ProjectError::NotFound, 0, "privateCandidatesCursor"};
        }
        first = static_cast<std::size_t>(cursor - events.begin()) + 1;
    }
    const auto last = (std::min)(events.size(), first + request.limit); // 只关联当前页，CPU及输出都有明确上限。
    for (auto index = first; index < last; ++index)
    {
        auto row = events[index]; // 发布独立值；与其余行/未来草稿没有共享可变状态。
        if (row.rangeCandidate)
        {
            for (const auto& event : events)
            {
                PrivateFreeRequestLink link; // 每条关联必须独立通过强实例和原调用时序门禁。
                if (RelatedFree(row, event.origin, link))
                {
                    ++row.freeRequestCount;
                    if (row.freeRequests.size() < kPrivateCandidateMaxFreeLinks)
                    {
                        row.freeRequests.push_back(std::move(link));
                    }
                }
            }
        }
        // 候选默认整段草稿和用户后续选段都沿用这些Free请求说明，不改变generation未知状态。
        // 只在最终页保留完整Free调用，避免扫描缓存为每条候选重复保存所有历史请求。
        page.rows.push_back(std::move(row));
    }
    if (last < events.size())
    {
        page.nextAfter = page.rows.back().origin.evidence.raw;
    }
    out = std::move(page);
    return {};
}

} // namespace Ksword::ActionAnalyze::Detection
