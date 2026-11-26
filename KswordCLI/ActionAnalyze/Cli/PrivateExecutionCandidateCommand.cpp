#include "PrivateExecutionCandidateCommand.h"
#include "ApiMemoryLifecycleProjection.h"
#include "../Detection/PrivateExecutionCandidates.h"
#include "../Project/ProjectStorage.h"
#include "../../CommandRegistry.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace ks::cli::action_analyze {
namespace {
namespace project = Ksword::ActionAnalyze;
namespace detection = project::Detection;
namespace storage = project::ProjectStorage;

// call为已核验AAIM1原调用，输出ASCII键/无损数值JSON；不解析原详情摘要。
Json MemoryFields(const detection::PrivateMemoryCall& call)
{
    const auto text = Ksword::Evidence::WriteJson(ApiMemoryLifecycleJson(
        *call.record.apiMemoryLifecycle, *call.record.apiSourceSession)); // 共享唯一AAIM1投影。
    return {std::wstring(text.begin(), text.end()), L"AAIM1"};
}

// source是核验后的原调用；输出Stored坐标、来源强实例及请求/实际返回完整字段。
Json Call(const detection::PrivateMemoryCall& source)
{
    const auto& evidence = source.evidence; // 原项目/采样/来源代次和源序号。
    const auto& record = source.record; // 原块与字节坐标，不能用显示行号代替。
    return Json::object({
        {L"stream", Json::string(L"raw")},
        {L"projectId", Json::string(storage::WideAscii(evidence.projectId))},
        {L"sampleId", Json::string(storage::WideAscii(evidence.sampleId))},
        {L"segmentOrdinal", Json::count(record.segmentOrdinal)},
        {L"recordSequence", Json::count(record.recordSequence)},
        {L"recordOffset", Json::count(record.recordOffset)},
        {L"blockOrdinal", Json::count(record.blockOrdinal)},
        {L"inlineOffset", Json::count(record.inlineOffset)},
        {L"inlineBytes", Json::number(record.inlineBytes)},
        // 文件定位与来源身份分别保留，不能把源序号或会话号当成Stored记录坐标。
        {L"sha256", Json::string(storage::WideAscii(source.sha256))},
        {L"sourceId", Json::string(storage::WideAscii(evidence.sourceId))},
        {L"sourceEpoch", Json::string(storage::WideAscii(evidence.sourceEpoch))},
        {L"sourceSequence", evidence.sourceSequence ? Json::count(*evidence.sourceSequence) : Json{}},
        {L"actorPid", record.headerPid ? Json::number(*record.headerPid) : Json{}},
        {L"actorTid", record.headerTid ? Json::number(*record.headerTid) : Json{}},
        {L"api", Json::string(storage::WideAscii(record.operation))},
        {L"apiMemoryLifecycle", MemoryFields(source)}
    });
}

// draft仅为用户选定的历史范围，不输出停点令牌；owner仍需当前held及真实allocation核验。
Json Draft(const detection::PrivateExecutionRangeDraft& draft)
{
    return Json::object({
        {L"targetPid", Json::number(draft.targetPid)},
        {L"targetCreationFileTime", Json::count(draft.targetCreationFileTime)},
        {L"address", Json::count(draft.address)},
        {L"bytes", Json::count(draft.bytes)},
        {L"pageBytes", Json::number(4096)},
        {L"pageCount", Json::count(draft.bytes / 4096)},
        {L"allocationGeneration", Json{}},
        {L"currentHeldRequired", Json::boolean(true)},
        {L"memPrivateVerified", Json::boolean(false)},
        {L"allocationVerified", Json::boolean(false)},
        {L"controlIssued", Json::boolean(false)}
    });
}

// row是独立原调用候选；Free链接保留完整请求及真实返回，不产生released/active结论。
Json Candidate(const detection::PrivateExecutionCandidate& row)
{
    std::vector<Json> frees; // 每条最多四个链接，累计数及截断状态另列。
    for (const auto& link : row.freeRequests)
    {
        frees.push_back(Json::object({
            {L"call", Call(link.call)},
            {L"relation", Json::string(L"same-source-ordered-request-address")},
            {L"requestedBaseInside", Json::boolean(link.requestedBaseInside)},
            {L"requestedRangeOverlaps", Json::boolean(link.requestedRangeOverlaps)},
            {L"actualReleasedRange", Json{}},
            {L"sameAllocation", Json{}},
            {L"deactivated", Json::boolean(false)}
        }));
    }
    return Json::object({
        {L"origin", Call(row.origin)},
        {L"rangeCandidate", Json::boolean(row.rangeCandidate)},
        {L"executableProtection", Json::boolean(row.executableProtection)},
        {L"strongTargetReportedStable", Json::boolean(row.strongTarget)},
        {L"reason", Json::string(storage::WideAscii(row.reason))},
        {L"wholeRangeDraft", row.wholeRangeDraft ? Draft(*row.wholeRangeDraft) : Json{}},
        {L"freeRequestCount", Json::count(row.freeRequestCount)},
        {L"freeRequestsTruncated", Json::boolean(row.freeRequestCount > row.freeRequests.size())},
        {L"freeRequests", Json::array(frees)},
        // 空值表示证据未证明，不能因原API成功或生成范围草稿而填入推断状态。
        {L"allocationGeneration", Json{}},
        {L"actualReleasedRange", Json{}},
        {L"currentlyLive", Json{}},
        {L"execution", Json{}},
        {L"causality", Json{}}
    });
}

// 输入实际ProjectResult，失败退出3，不附带未完整核验的局部候选。
Result Failed(const project::ProjectResult& status)
{
    return {3, Json::object({
        {L"error", Json::string(storage::WideAscii(project::ProjectErrorName(status.error)))},
        {L"stage", Json::string(storage::WideAscii(status.detail))},
        {L"win32Error", Json::number(status.nativeError)}
    }), {}};
}

// 输入规范UUID或快照token的宽字符；只接受本模块协议使用的ASCII，不做有损替换。
std::string Ascii(const std::wstring& text)
{
    std::string result; // 用于请求存活期间借用的UTF-8/ASCII参数值。
    for (const auto ch : text)
    {
        if (ch > 127)
        {
            throw std::invalid_argument("Candidate sample and snapshot must use ASCII");
        }
        result.push_back(static_cast<char>(ch));
    }
    return result;
}

// 正式只读入口：解析分页及可选显式子范围；打开原项目只读，不接native owner。
Result Read(const Args& args)
{
    const auto sample = Ascii(args.require(L"--sample")); // 原采样身份，不创建新采样。
    const auto snapshot = Ascii(args.get(L"--snapshot")); // 续页绑定全前缀的比较token。
    const auto ordinal = args.integer(L"--through-ordinal"); // 明确扫描截止点，不猜未知末段。
    const auto limit = args.integer(L"--limit", detection::kPrivateCandidateMaxPage); // 输出页预算。
    if (!storage::IsUuid(sample) || !limit || limit > detection::kPrivateCandidateMaxPage ||
        args.has(L"--after-ordinal") != args.has(L"--after-sequence"))
    {
        throw std::invalid_argument("Require canonical --sample, --limit 1..8 and paired --after-ordinal/--after-sequence");
    }
    detection::PrivateExecutionCandidatesRequest request; // 字符串借用本次调用局部值。
    request.sampleId = sample;
    request.throughOrdinal = ordinal;
    request.limit = static_cast<std::size_t>(limit);
    request.expectedSnapshot = snapshot;
    if (args.has(L"--after-ordinal"))
    {
        request.after = detection::RawLocator{args.integer(L"--after-ordinal"), args.integer(L"--after-sequence")};
    }
    project::ProjectDocument document; // 默认ReadOnly，无writer lease或目标句柄。
    if (const auto status = document.Open(args.require(L"--project")); !status)
    {
        return Failed(status);
    }
    detection::PrivateExecutionCandidatesPage page; // 核心只有全部成功才发布此值。
    if (const auto status = detection::ReadPrivateExecutionCandidates(document, request, page); !status)
    {
        return Failed(status);
    }
    std::vector<Json> rows; // 本页原调用，包括Free及失败线索，不假装全部可控制。
    for (const auto& row : page.rows)
    {
        rows.push_back(Candidate(row));
    }

    Json selected; // 可选按当前页真实原坐标选择明确子范围，失败不生成可用草稿。
    const bool select = args.has(L"--select-ordinal") || args.has(L"--select-sequence") ||
        args.has(L"--address") || args.has(L"--bytes");
    if (select)
    {
        if (!args.has(L"--select-ordinal") || !args.has(L"--select-sequence") ||
            !args.has(L"--address") || !args.has(L"--bytes") || snapshot.empty())
        {
            throw std::invalid_argument("Selection requires --select-ordinal, --select-sequence, --address, --bytes and the displayed --snapshot");
        }
        const detection::RawLocator location{args.integer(L"--select-ordinal"), args.integer(L"--select-sequence")}; // Stored原坐标。
        const auto found = std::find_if(page.rows.begin(), page.rows.end(), [&](const auto& row)
        {
            return row.origin.evidence.raw == std::optional<detection::RawLocator>{location};
        });
        if (found == page.rows.end())
        {
            return Failed({project::ProjectError::NotFound, 0, "privateCandidatesSelectionNotInPage"});
        }
        detection::PrivateExecutionRangeDraft draft; // 地址和长度必须显式输入，不默认向外取整。
        if (const auto status = detection::PreparePrivateExecutionRangeDraft(*found,
            args.integer(L"--address"), args.integer(L"--bytes"), draft); !status)
        {
            return Failed(status);
        }
        selected = Json::object({{L"origin", Call(draft.origin)}, {L"draft", Draft(draft)}});
    }
    return {0, Json::object({
        {L"schema", Json::string(L"private-execution-candidates-v1")},
        {L"projectId", Json::string(storage::WideAscii(page.scope.projectId))},
        {L"sampleId", Json::string(storage::WideAscii(page.scope.sampleId))},
        {L"throughOrdinal", Json::count(page.throughOrdinal)},
        {L"snapshot", Json::string(storage::WideAscii(page.snapshot))},
        {L"historical", Json::boolean(true)},
        {L"committedPrefixVerified", Json::boolean(true)},
        {L"finalSegment", Json::boolean(page.finalSegment)},
        {L"observationCount", Json::count(page.observationCount)},
        {L"lifecycleCount", Json::count(page.lifecycleCount)},
        {L"malformedLifecycleCount", Json::count(page.malformedLifecycleCount)},
        {L"legacyLifecycleCount", Json::count(page.legacyLifecycleCount)},
        {L"rangeCandidateCount", Json::count(page.rangeCandidateCount)},
        {L"freeRequestCount", Json::count(page.freeRequestCount)},
        // 只有完整前缀验证成功才发布候选、续页游标和用户明确选择的范围草稿。
        {L"rows", Json::array(rows)},
        {L"nextAfter", page.nextAfter ? Json::object({
            {L"segmentOrdinal", Json::count(page.nextAfter->segmentOrdinal)},
            {L"recordSequence", Json::count(page.nextAfter->sequence)}}) : Json{}},
        {L"selectedRangeDraft", selected},
        {L"sourceAuthenticated", Json::boolean(false)},
        {L"crossSourceMerged", Json::boolean(false)},
        {L"controlIssued", Json::boolean(false)}
    }), {}};
}
} // namespace

void RegisterPrivateExecutionCandidateCommand()
{
    Command command; // path及帮助文本是正式help唯一登记源。
    command.path = L"analyze execution candidates";
    command.syntax = L"KswordCLI.exe analyze execution candidates --project PATH --sample UUID --through-ordinal N [--limit N] [--after-ordinal N --after-sequence N --snapshot TOKEN] [--select-ordinal N --select-sequence N --address N --bytes N] [--json]";
    command.summary = L"Read AAIM1 private execution range candidates from a verified committed API archive prefix.";
    command.options = L"Requires --project, --sample and --through-ordinal 1..128. --limit is 1..8 (default 8). Continuation requires both Stored cursor fields and the previous snapshot. Optional selection requires all four select/range fields and the displayed snapshot, and must refer to a row in this page.";
    command.notes = L"Read-only; reuses the execution correlate archive reader. Keeps each original call separate with requested/actual output, source and target identities, return status, original raw coordinates and hashes. Free requests are linked only within the same source identity/session and strict QPC order; actual release and allocation generation remain unknown. Drafts require a stable reported target, exact 4KiB alignment, at most 64 pages, and containment within actual successful output. No outward rounding, process access, automatic enrollment or native control. Missing/corrupt segments and budget exhaustion fail without partial rows. See docs/cli/action-analyze-execution-candidates.md.";
    command.run = Read;
    addCommand(std::move(command));
}
} // namespace ks::cli::action_analyze
