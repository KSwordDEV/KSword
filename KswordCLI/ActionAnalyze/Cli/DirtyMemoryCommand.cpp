#include "DirtyMemoryCommand.h"

#include "../Memory/PassiveDirtyMemory.h"
#include "../Project/ProjectStorage.h"
#include "../../R3ProcessShared.h"

#include <algorithm>

namespace ks::cli::action_analyze {
namespace {
namespace mem = memory;

// 命令只导出字段和摘要，不输出远程进程字节。对旧 memory watch 保持独立。
constexpr std::uint32_t kCommandByteLimit = 65536;

const wchar_t* StateName(mem::State state)
{
    switch (state) {
    case mem::State::Idle: return L"idle";
    case mem::State::Active: return L"active";
    case mem::State::Completed: return L"completed";
    case mem::State::Stopped: return L"stopped";
    case mem::State::Canceled: return L"canceled";
    case mem::State::TargetExited: return L"target-exited";
    case mem::State::Rejected: return L"rejected";
    case mem::State::Failed: return L"failed";
    }
    return L"unknown";
}

const wchar_t* PageStatusName(mem::PageStatus status)
{
    switch (status) {
    case mem::PageStatus::NotCommitted: return L"not-committed";
    case mem::PageStatus::Guarded: return L"guarded";
    case mem::PageStatus::UnsafeReadAttributes: return L"unsafe-read-attributes";
    case mem::PageStatus::NotReadable: return L"not-readable";
    case mem::PageStatus::QueryFailed: return L"query-failed";
    case mem::PageStatus::ReadFailed: return L"read-failed";
    case mem::PageStatus::MappingUnstable: return L"mapping-unstable";
    case mem::PageStatus::HashFailed: return L"hash-failed";
    case mem::PageStatus::Sampled: return L"sampled";
    }
    return L"unknown";
}

// 保留原生返回值；阶段名稳定，不暴露 C++ 枚举下标。
Json IssueJson(const mem::Issue& issue)
{
    using mem::Stage;
    const wchar_t* name = L"unknown";
    switch (issue.stage) {
    case Stage::None: return {};
    case Stage::ValidatePlan: name = L"validate-plan"; break;
    case Stage::DuplicateProcess: name = L"duplicate-process"; break;
    case Stage::ProcessId: name = L"process-id"; break;
    case Stage::ProcessCreation: name = L"process-creation"; break;
    case Stage::ProcessMismatch: name = L"process-mismatch"; break;
    case Stage::ProcessLifetime: name = L"process-lifetime"; break;
    case Stage::OpenOwnerToken: name = L"open-owner-token"; break;
    case Stage::OpenTargetToken: name = L"open-target-token"; break;
    case Stage::ReadTokenIdentity: name = L"read-token-identity"; break;
    case Stage::TokenOwnerMismatch: name = L"token-owner-mismatch"; break;
    case Stage::CriticalProcess: name = L"critical-process"; break;
    case Stage::TargetMachine: name = L"target-machine"; break;
    case Stage::Clock: name = L"clock"; break;
    case Stage::OpenHashProvider: name = L"open-hash-provider"; break;
    case Stage::QueryBeforeRead: name = L"query-before-read"; break;
    case Stage::ReadMemory: name = L"read-memory"; break;
    case Stage::QueryAfterRead: name = L"query-after-read"; break;
    case Stage::CompareMappings: name = L"compare-mappings"; break;
    case Stage::HashContent: name = L"hash-content"; break;
    }
    return Json::object({{L"stage", Json::string(name)}, {L"win32Error", Json::number(issue.win32Error)},
        {L"ntStatus", issue.ntStatus ? Json::signedNumber(*issue.ntStatus) : Json{}}});
}

Json RangeJson(const mem::Range& range)
{
    return Json::object({{L"base", Json::hex(range.base)}, {L"length", Json::count(range.length)}});
}

Json WindowJson(const mem::QpcWindow& window)
{
    return Json::object({{L"begin", Json::count(window.begin)}, {L"end", Json::count(window.end)}});
}

Json MappingJson(const std::optional<mem::Mapping>& mapping)
{
    if (!mapping) return {};
    return Json::object({{L"region", RangeJson(mapping->region)},
        {L"allocationBase", Json::hex(mapping->allocationBase)}, {L"state", Json::number(mapping->state)},
        {L"type", Json::number(mapping->type)}, {L"protection", Json::number(mapping->protection)},
        {L"allocationProtection", Json::number(mapping->allocationProtection)}});
}

// 版本只覆盖本页实际成功读取的子范围，哈希不用于证明执行时内容。
Json ContentJson(const std::optional<mem::ContentSample>& content)
{
    if (!content) return {};
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring sha;
    sha.reserve(content->sha256.size() * 2);
    for (const auto byte : content->sha256) {
        sha.push_back(digits[byte >> 4]);
        sha.push_back(digits[byte & 15]);
    }
    const auto origin = content->origin == mem::ContentOrigin::Changed ? L"changed" :
        content->origin == mem::ContentOrigin::Unchanged ? L"unchanged" : L"baseline";
    return Json::object({{L"round", Json::number(content->roundOrdinal)},
        {L"version", Json::number(content->version)}, {L"origin", Json::string(origin)},
        {L"readQpc", WindowJson(content->readQpc)}, {L"sha256", Json::string(sha)}});
}

Json DifferenceJson(const std::optional<mem::Difference>& difference)
{
    if (!difference) return {};
    std::vector<Json> ranges; // 在绝对地址空间内定位已显示的变化。
    for (const auto& range : difference->ranges) ranges.push_back(RangeJson(range));
    return Json::object({{L"changedBytes", Json::number(difference->changedBytes)},
        {L"rangeCount", Json::number(difference->rangeCount)}, {L"ranges", Json::array(ranges)},
        {L"omittedRangeCount", Json::count(difference->rangeCount - ranges.size())}});
}

Json PageJson(const mem::PageObservation& page)
{
    const auto& change = page.changes; // 属性变化与字节差异独立。
    return Json::object({{L"pageBase", Json::hex(page.pageBase)}, {L"range", RangeJson(page.sampledRange)},
        {L"status", Json::string(PageStatusName(page.status))},
        {L"mappingGeneration", page.mappingGeneration ? Json::number(*page.mappingGeneration) : Json{}},
        {L"changes", Json::object({{L"firstMappingObservation", Json::boolean(change.firstMappingObservation)},
            {L"mappingContinuityReset", Json::boolean(change.mappingContinuityReset)},
            {L"newlyCommitted", Json::boolean(change.newlyCommitted)},
            {L"noLongerCommitted", Json::boolean(change.noLongerCommitted)},
            {L"mappingChanged", Json::boolean(change.mappingChanged)},
            {L"regionLayoutChanged", Json::boolean(change.regionLayoutChanged)},
            {L"protectionChanged", Json::boolean(change.protectionChanged)}})},
        {L"mappingBefore", MappingJson(page.before)}, {L"mappingAfter", MappingJson(page.after)},
        {L"issue", IssueJson(page.issue)}, {L"additionalIssue", page.additionalIssue ? IssueJson(*page.additionalIssue) : Json{}},
        {L"readQpc", page.readQpc ? WindowJson(*page.readQpc) : Json{}},
        {L"returnedBytes", page.returnedBytes ? Json::count(*page.returnedBytes) : Json{}},
        {L"previousContent", ContentJson(page.previousContent)}, {L"content", ContentJson(page.content)},
        {L"difference", DifferenceJson(page.difference)}});
}

Json RoundJson(const mem::Round& round)
{
    std::vector<Json> pages; // 每轮不丢弃失败页，也不因此清空先前结果。
    pages.reserve(round.pages.size());
    for (const auto& page : round.pages) pages.push_back(PageJson(page));
    return Json::object({{L"ordinal", Json::number(round.ordinal)},
        {L"beginQpc", Json::count(round.beginQpc)},
        {L"endQpc", round.endQpc ? Json::count(*round.endQpc) : Json{}},
        {L"allPagesVisited", Json::boolean(round.allPagesVisited)}, {L"pages", Json::array(pages)}});
}

// 不接受任意外部执行记录。此入口输出的执行覆盖始终为未采集。
Result Run(const Args& args)
{
    if (!args.has(L"--confirm")) throw std::invalid_argument("--confirm is required for an explicitly authorized process");
    mem::Plan plan;
    plan.target.pid = args.u32(L"--pid");
    plan.target.creationFileTime100ns = args.integer(L"--creation-time");
    plan.range = {args.integer(L"--address"), args.u32(L"--size")};
    plan.rounds = args.u32(L"--samples", 20);
    plan.intervalMs = args.u32(L"--interval-ms", 100);
    if (!plan.target.pid || !plan.target.creationFileTime100ns || !plan.range.base ||
        !plan.range.length || plan.range.length > kCommandByteLimit || plan.range.base > UINT64_MAX - plan.range.length ||
        plan.rounds < 2 || plan.rounds > mem::kMaxSampleRounds || plan.intervalMs < 10 || plan.intervalMs > 1000) {
        throw std::invalid_argument("invalid process identity, address, size, sample count or interval");
    }

    // 本命令无项目：用单次调用的 UUID 隔离身份域，不把占位值当跨采样机器或启动标识。
    if (!Ksword::ActionAnalyze::ProjectStorage::NewId(plan.sampleId) ||
        !Ksword::ActionAnalyze::ProjectStorage::NewId(plan.trackingEpoch)) {
        return {3, Json::object({}), {L"Could not allocate a tracking identity."}};
    }
    plan.target.machineId = plan.sampleId;
    plan.target.bootId = plan.sampleId;
    plan.target.processInstanceId = std::to_string(plan.target.pid) + ":" + std::to_string(plan.target.creationFileTime100ns);
    plan.authorizedOwnedProcess = true;

    const process::Lease target(args, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE);
    mem::Status status;
    std::vector<Json> rounds;
    if (target.error || !target.matches) {
        status.state = mem::State::Rejected;
        status.issue = {target.error ? mem::Stage::ProcessCreation : mem::Stage::ProcessMismatch,
            target.error ? target.error : ERROR_INVALID_PARAMETER};
    } else {
        mem::PassiveDirtyMemory tracker; // 单命令线程拥有本次追踪与节奏。
        const Cancellation cancellation;
        status = tracker.Begin(target.handle.get(), plan);
        rounds.reserve(plan.rounds);
        while (status.state == mem::State::Active) {
            auto result = tracker.Poll(cancellation.token.get());
            status = result.status;
            if (result.round) rounds.push_back(RoundJson(*result.round));
            if (status.state == mem::State::Active) {
                // 短等待保持取消响应；硬期限、时钟误差检查和到期判定由后端统一负责。
                WaitForSingleObject(target.handle.get(), (std::min)(plan.intervalMs, 10u));
            }
        }
    }

    const bool complete = status.state == mem::State::Completed && !status.unavailablePages;
    const std::wstring sampleId(plan.sampleId.begin(), plan.sampleId.end());
    const std::wstring epoch(plan.trackingEpoch.begin(), plan.trackingEpoch.end());
    return {complete ? 0 : rounds.empty() ? 3 : 6,
        Json::object({{L"captureId", Json::string(sampleId)}, {L"trackingEpoch", Json::string(epoch)},
            {L"pid", Json::number(plan.target.pid)}, {L"creationFileTime", Json::count(plan.target.creationFileTime100ns)},
            {L"observedCreationFileTime", target.creationTime ? Json::count(target.creationTime) : Json{}},
            {L"range", RangeJson(plan.range)}, {L"requestedRounds", Json::number(plan.rounds)},
            {L"intervalMs", Json::number(plan.intervalMs)}, {L"complete", Json::boolean(complete)},
            {L"state", Json::string(StateName(status.state))}, {L"issue", IssueJson(status.issue)},
            {L"pageSize", status.pageSize ? Json::number(status.pageSize) : Json{}},
            {L"pointerWidth", status.pointerWidth ? Json::number(status.pointerWidth) : Json{}},
            {L"plannedPages", Json::number(status.plannedPages)}, {L"attemptedRounds", Json::number(status.attemptedRounds)},
            {L"fullRounds", Json::number(status.fullRounds)}, {L"sampledPages", Json::number(status.sampledPages)},
            {L"unavailablePages", Json::number(status.unavailablePages)},
            {L"qpcFrequency", status.qpcFrequency ? Json::count(status.qpcFrequency) : Json{}},
            {L"executionCoverage", Json::string(L"not-collected")}, {L"writeAttribution", Json::string(L"unknown")},
            {L"rounds", Json::array(rounds)}}), {L"Changes between reads and remaps with identical attributes can be missed."}};
}
} // namespace

void RegisterDirtyMemoryCommand()
{
    addCommand({L"analyze memory track",
        L"KswordCLI.exe analyze memory track --pid PID --creation-time FILETIME --address ADDRESS --size BYTES --confirm [--samples N] [--interval-ms N] [--backend r3] [--json]",
        L"Track sampled per-page content and mapping changes in an explicitly authorized process.",
        L"Required: --pid, --creation-time, --address, --size (1..65536), --confirm. Optional: --samples (2..64, default 20), --interval-ms (10..1000, default 100), --backend r3, --json.",
        L"Read-only, same user and session. Returns page state, SHA-256, change ranges and coverage gaps. Does not collect execution or attribute writes. No project is modified.", Run});
}

} // namespace ks::cli::action_analyze
