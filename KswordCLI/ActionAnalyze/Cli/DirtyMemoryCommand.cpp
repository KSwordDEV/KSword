#include "DirtyMemoryCommand.h"
#include "ThreadObservationJson.h"
#include "Transport.h"

#include "../Memory/PassiveDirtyMemory.h"
#include "../Project/ProjectStorage.h"
#include "../../R3ProcessShared.h"

#include <algorithm>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

namespace ks::cli::action_analyze {
namespace {
namespace mem = memory;

// 命令只导出字段和摘要，不输出远程进程字节。对旧 memory watch 保持独立。
constexpr std::uint32_t kCommandByteLimit = 65536;

Json CounterJson(std::uint64_t value, bool continuous)
{
    // 有限命令保留原 JSON 数字类型；持续流的 64 位序号和计数不丢精度。
    return continuous ? Json::count(value) : Json::number(static_cast<std::uint32_t>(value));
}

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

Json InputIssueJson(const Fault& issue)
{
    if (!issue) return {};
    const auto widen = [](std::string_view text) { return std::wstring(text.begin(), text.end()); };
    return Json::object({{L"errorId", Json::string(widen(issue.id))}, {L"message", Json::string(widen(issue.message))},
        {L"source", Json::string(widen(issue.source))},
        {L"code", Json::number(issue.nativeCode ? issue.nativeCode : static_cast<unsigned>(issue.code))},
        {L"byteOffset", issue.offset ? Json::count(*issue.offset) : Json{}}});
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
Json ContentJson(const std::optional<mem::ContentSample>& content, bool continuous)
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
    return Json::object({{L"round", CounterJson(content->roundOrdinal, continuous)},
        {L"version", CounterJson(content->version, continuous)}, {L"origin", Json::string(origin)},
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

Json PageJson(const mem::PageObservation& page, bool continuous)
{
    const auto& change = page.changes; // 属性变化与字节差异独立。
    return Json::object({{L"pageBase", Json::hex(page.pageBase)}, {L"range", RangeJson(page.sampledRange)},
        {L"status", Json::string(PageStatusName(page.status))},
        {L"mappingGeneration", page.mappingGeneration ? CounterJson(*page.mappingGeneration, continuous) : Json{}},
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
        {L"previousContent", ContentJson(page.previousContent, continuous)}, {L"content", ContentJson(page.content, continuous)},
        {L"difference", DifferenceJson(page.difference)}});
}

// 观察器仅由命令持有；记录前次快照尝试所在轮，不把跳过的内存轮当作线程基准。
struct RoundThreadObservation {
    explicit RoundThreadObservation(HANDLE target, DWORD pid) : observer(target, pid) {}

    mem::PassiveThreadObservation observer; // 借用本命令已核验的目标进程句柄。
    std::optional<std::uint64_t> previousRound; // 上次实际调用观察器的内存轮号；首次为空。
};

// 将一次内存采样投影到命令输出。实际读取之后才可附加独立的线程快照。
Json ObserveAndSerializeRound(const mem::Round& round, mem::State state,
    std::optional<RoundThreadObservation>& threads, const std::atomic_bool& cancel)
{
    // 仅已通过映射和完整性检查的内容允许附加线程观察；部分或弃用字节仅作诊断。
    Json threadObservation;
    Json previousThreadObservationRound; // 与 ordinal 使用同样的编码，无对应快照时为 null。
    const bool continuous = !round.effectivePlan.rounds;
    if (threads && (state == mem::State::Active || state == mem::State::Completed) &&
        std::ranges::any_of(round.pages, [](const auto& page) { return page.content.has_value(); }) &&
        !cancel.load(std::memory_order_relaxed)) {
        threadObservation = ThreadObservationJson(threads->observer.Observe());
        if (threads->previousRound) {
            previousThreadObservationRound = CounterJson(*threads->previousRound, continuous);
        }
        threads->previousRound = round.ordinal;
    }
    std::vector<Json> pages; // 每轮不丢弃失败页，也不因此清空先前结果。
    pages.reserve(round.pages.size());
    for (const auto& page : round.pages) pages.push_back(PageJson(page, continuous));
    return Json::object({{L"ordinal", CounterJson(round.ordinal, continuous)},
        {L"beginQpc", Json::count(round.beginQpc)},
        {L"endQpc", round.endQpc ? Json::count(*round.endQpc) : Json{}},
        {L"allPagesVisited", Json::boolean(round.allPagesVisited)}, {L"pages", Json::array(pages)},
        {L"threadObservation", std::move(threadObservation)},
        {L"previousThreadObservationRound", std::move(previousThreadObservationRound)}});
}

mem::Plan ReadPlan(const Args& args, bool continuous)
{
    if (!args.has(L"--confirm")) throw std::invalid_argument("--confirm is required for an explicitly authorized process");
    mem::Plan plan;
    plan.target.pid = args.u32(L"--pid");
    plan.target.creationFileTime100ns = args.integer(L"--creation-time");
    plan.range = {args.integer(L"--address"), args.u32(L"--size")};
    if (continuous) plan.rounds.reset();
    else plan.rounds = args.u32(L"--samples", 20);
    plan.intervalMs = args.u32(L"--interval-ms", 100);
    if (!plan.target.pid || !plan.target.creationFileTime100ns || !plan.range.base ||
        !plan.range.length || plan.range.length > kCommandByteLimit || plan.range.base > UINT64_MAX - plan.range.length ||
        (plan.rounds && (*plan.rounds < 2 || *plan.rounds > mem::kMaxSampleRounds)) ||
        plan.intervalMs < 10 || plan.intervalMs > 1000) {
        throw std::invalid_argument("invalid process identity, address, size, sample count or interval");
    }
    return plan;
}

bool AssignTrackingIdentity(mem::Plan& plan)
{
    // 本命令无项目：用单次调用的 UUID 隔离身份域，不把占位值当跨采样机器或启动标识。
    if (!Ksword::ActionAnalyze::ProjectStorage::NewId(plan.sampleId) ||
        !Ksword::ActionAnalyze::ProjectStorage::NewId(plan.trackingEpoch)) return false;
    plan.target.machineId = plan.sampleId;
    plan.target.bootId = plan.sampleId;
    plan.target.processInstanceId = std::to_string(plan.target.pid) + ":" + std::to_string(plan.target.creationFileTime100ns);
    plan.authorizedOwnedProcess = true;
    return true;
}

mem::Status Begin(mem::PassiveDirtyMemory& tracker, const process::Lease& target, const mem::Plan& plan)
{
    if (!target.error && target.matches) return tracker.Begin(target.handle.get(), plan);
    mem::Status status;
    status.state = mem::State::Rejected;
    status.issue = {target.error ? mem::Stage::ProcessCreation : mem::Stage::ProcessMismatch,
        target.error ? target.error : ERROR_INVALID_PARAMETER};
    return status;
}

// 不接受任意外部执行记录。两个入口的执行覆盖始终为未采集。
Result Run(const Args& args)
{
    const bool observeThreads = args.has(L"--observe-threads");
    auto plan = ReadPlan(args, false);
    if (!AssignTrackingIdentity(plan)) return {3, Json::object({{L"threadObservationEnabled", Json::boolean(observeThreads)}}),
        {L"Could not allocate a tracking identity."}};

    const process::Lease target(args, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE);
    mem::PassiveDirtyMemory tracker;
    mem::Status status;
    std::vector<Json> rounds;
    if (target.error || !target.matches) {
        status = Begin(tracker, target, plan);
    } else {
        const Cancellation cancellation;
        status = Begin(tracker, target, plan);
        std::optional<RoundThreadObservation> threads; // 本次有界追踪的线程观察及基准轮号。
        if (observeThreads && status.state == mem::State::Active) threads.emplace(target.handle.get(), target.pid);
        rounds.reserve(*plan.rounds);
        while (status.state == mem::State::Active) {
            auto result = tracker.Poll(cancellation.token.get());
            status = result.status;
            if (result.round) rounds.push_back(ObserveAndSerializeRound(*result.round, status.state, threads, *cancellation.token));
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
            {L"range", RangeJson(plan.range)}, {L"requestedRounds", Json::number(*plan.rounds)},
            {L"intervalMs", Json::number(plan.intervalMs)}, {L"complete", Json::boolean(complete)},
            {L"state", Json::string(StateName(status.state))}, {L"issue", IssueJson(status.issue)},
            {L"pageSize", status.pageSize ? Json::number(status.pageSize) : Json{}},
            {L"pointerWidth", status.pointerWidth ? Json::number(status.pointerWidth) : Json{}},
            {L"plannedPages", Json::number(status.plannedPages)}, {L"attemptedRounds", CounterJson(status.attemptedRounds, false)},
            {L"fullRounds", CounterJson(status.fullRounds, false)}, {L"sampledPages", CounterJson(status.sampledPages, false)},
            {L"unavailablePages", CounterJson(status.unavailablePages, false)},
            {L"qpcFrequency", status.qpcFrequency ? Json::count(status.qpcFrequency) : Json{}},
            {L"threadObservationEnabled", Json::boolean(observeThreads)},
            {L"executionCoverage", Json::string(L"not-collected")}, {L"writeAttribution", Json::string(L"unknown")},
            {L"rounds", Json::array(rounds)}}), {L"Changes between reads and remaps with identical attributes can be missed."}};
}

// 独占 Transport，最多提交一帧。只让后台等待该帧写完；控制线程始终能处理 stdin。
class FrameDelivery {
public:
    enum class State { Ready, Pending, Lost };

    explicit FrameDelivery(Transport& transport) : transport_(transport),
        worker_([this](std::stop_token stop) { Drain(stop); }) {}

    State Query()
    {
        std::lock_guard lock(mutex_);
        return state_;
    }

    bool Wait()
    {
        std::unique_lock lock(mutex_);
        changed_.wait(lock, [this] { return state_ != State::Pending; });
        return state_ == State::Ready;
    }

    bool Send(std::string frame)
    {
        std::lock_guard lock(mutex_);
        if (state_ != State::Ready || !transport_.Send(std::move(frame))) return false;
        state_ = State::Pending;
        changed_.notify_all();
        return true;
    }

private:
    void Drain(std::stop_token stop)
    {
        std::unique_lock lock(mutex_);
        while (changed_.wait(lock, stop, [this] { return state_ == State::Pending; })) {
            lock.unlock();
            const bool delivered = transport_.Finish();
            lock.lock();
            state_ = delivered ? State::Ready : State::Lost;
            changed_.notify_all();
        }
    }

    Transport& transport_;
    std::mutex mutex_;
    std::condition_variable_any changed_;
    State state_ = State::Ready;
    std::jthread worker_;
};

class DirtyMemoryStream {
public:
    DirtyMemoryStream(FrameDelivery& delivery, const mem::Plan& plan, bool jsonl)
        : delivery_(delivery), jsonl_(jsonl), captureId_(plan.sampleId.begin(), plan.sampleId.end()),
        trackingEpoch_(plan.trackingEpoch.begin(), plan.trackingEpoch.end()) {}

    bool Emit(const wchar_t* kind, const Json& data)
    {
        const auto record = Json::object({{L"schemaVersion", Json::number(1)},
            {L"type", Json::string(kind)}, {L"captureId", Json::string(captureId_)},
            {L"trackingEpoch", Json::string(trackingEpoch_)}, {L"data", data}});
        const auto& wide = jsonl_ ? record.text : record.display;
        if (wide.size() > kOutputBytes) return false;
        const auto length = static_cast<int>(wide.size());
        const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), length, nullptr, 0, nullptr, nullptr);
        if (bytes <= 0 || static_cast<std::size_t>(bytes) > kOutputBytes) return false;
        std::string frame(static_cast<std::size_t>(bytes), '\0');
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), length, frame.data(), bytes, nullptr, nullptr)) return false;
        frame.push_back('\n');
        return delivery_.Send(std::move(frame));
    }

private:
    FrameDelivery& delivery_;
    bool jsonl_;
    std::wstring captureId_;
    std::wstring trackingEpoch_;
};

int RunStream(const Args& args)
{
    const auto output = args.get(L"--output", L"text");
    if (output != L"text" && output != L"jsonl") throw std::invalid_argument("--output must be text or jsonl");
    const bool jsonl = output == L"jsonl";
    const bool observeThreads = args.has(L"--observe-threads");
    auto plan = ReadPlan(args, true);
    if (!AssignTrackingIdentity(plan)) {
        std::wcerr << L"error: Could not allocate a tracking identity.\n";
        return 3;
    }
    Transport transport;
    if (const auto fault = transport.Start(jsonl)) {
        const std::string_view message(fault.message);
        std::wcerr << L"error: " << std::wstring(message.begin(), message.end()) << L'\n';
        return fault.code;
    }
    const Cancellation cancellation; // 在 Transport 之后登记，Ctrl-C / Break 请求取消本次采样。
    FrameDelivery delivery(transport);
    DirtyMemoryStream stream(delivery, plan, jsonl);
    mem::PassiveDirtyMemory tracker;
    const auto outputUnavailable = [&tracker] {
        (void)tracker.Stop();
        std::wcerr << L"error: memory-stream-output-unavailable\n";
        return 3;
    };
    process::Lease target(args, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE);
    const auto observedCreationTime = target.creationTime;
    auto status = Begin(tracker, target, plan);
    std::optional<RoundThreadObservation> threads; // 本次持续追踪的线程观察及基准轮号。
    // 仅启用时保留原进程句柄给观察器；页采样后端仍自行持有其副本。
    if (observeThreads && status.state == mem::State::Active) threads.emplace(target.handle.get(), target.pid);
    else target.handle.reset();
    if (!stream.Emit(L"start", Json::object({{L"backend", Json::string(L"r3")},
        {L"pid", Json::number(plan.target.pid)}, {L"creationFileTime", Json::count(plan.target.creationFileTime100ns)},
        {L"observedCreationFileTime", observedCreationTime ? Json::count(observedCreationTime) : Json{}},
        {L"range", RangeJson(plan.range)}, {L"intervalMs", Json::number(plan.intervalMs)},
        {L"state", Json::string(StateName(status.state))}, {L"issue", IssueJson(status.issue)},
        {L"pageSize", status.pageSize ? Json::number(status.pageSize) : Json{}},
        {L"pointerWidth", status.pointerWidth ? Json::number(status.pointerWidth) : Json{}},
        {L"plannedPages", Json::number(status.plannedPages)},
        {L"qpcFrequency", status.qpcFrequency ? Json::count(status.qpcFrequency) : Json{}},
        {L"threadObservationEnabled", Json::boolean(observeThreads)},
        {L"executionCoverage", Json::string(L"not-collected")}, {L"writeAttribution", Json::string(L"unknown")},
        {L"control", Json::string(L"Send stop followed by LF to end sampling.")}}))) return outputUnavailable();

    const wchar_t* reason = nullptr;
    Fault inputIssue;
    int code = 0;
    while (status.state == mem::State::Active) {
        const auto input = transport.Next(true);
        if (input.kind == InputKind::OutputLost) return outputUnavailable();
        if (input.kind == InputKind::Eof || (input.kind == InputKind::Line && input.line == "stop")) {
            reason = input.kind == InputKind::Eof ? L"eof" : L"stop";
        } else if (input.kind == InputKind::Fatal || (input.kind == InputKind::Line && !input.line.empty())) {
            reason = input.kind == InputKind::Fatal ? L"input-failed" : L"invalid-command";
            inputIssue = input.kind == InputKind::Fatal ? input.fault : Fault{"invalid-command", "Expected a stop line"};
            code = inputIssue.code;
        } else if (input.kind == InputKind::Break) {
            cancellation.token->store(true, std::memory_order_relaxed);
        }
        if (reason) {
            // 在处理输入时已有的退出或取消优先于正常 stop/EOF；本次检查不读取页面。
            status = tracker.Poll(cancellation.token.get(), mem::PollMode::StatusOnly).status;
            if (status.state == mem::State::Active) status = tracker.Stop();
            break;
        }

        const auto outputState = delivery.Query();
        if (outputState == FrameDelivery::State::Lost) return outputUnavailable();
        auto result = tracker.Poll(cancellation.token.get(), outputState == FrameDelivery::State::Ready
            ? mem::PollMode::SampleWhenDue : mem::PollMode::StatusOnly);
        status = result.status;
        if (result.round && !stream.Emit(L"round",
            ObserveAndSerializeRound(*result.round, status.state, threads, *cancellation.token))) return outputUnavailable();
    }

    threads.reset();
    target.handle.reset();
    if (!reason || (!inputIssue && status.state != mem::State::Stopped)) reason = StateName(status.state);
    if (!code) {
        if (status.state == mem::State::Canceled || status.unavailablePages || status.fullRounds < status.attemptedRounds) code = 6;
        else if (status.state != mem::State::Stopped) code = status.attemptedRounds ? 6 : 3;
    }
    // 原生采样已终止，最后才等待输出排空。管道失联时不保证该回执送达。
    if (!delivery.Wait() || !stream.Emit(L"summary", Json::object({{L"reason", Json::string(reason)},
        {L"state", Json::string(StateName(status.state))}, {L"issue", IssueJson(status.issue)},
        {L"inputIssue", InputIssueJson(inputIssue)},
        {L"exitCode", Json::number(static_cast<std::uint32_t>(code))},
        {L"attemptedRounds", Json::count(status.attemptedRounds)}, {L"fullRounds", Json::count(status.fullRounds)},
        {L"sampledPages", Json::count(status.sampledPages)}, {L"unavailablePages", Json::count(status.unavailablePages)},
        {L"threadObservationEnabled", Json::boolean(observeThreads)},
        {L"coverageNote", Json::string(L"Changes between reads and remaps with identical attributes can be missed. Slow output can delay reads.")}})) ||
        !delivery.Wait()) return outputUnavailable();
    return code;
}
} // namespace

void RegisterDirtyMemoryCommand()
{
    addCommand({L"analyze memory track",
        L"KswordCLI.exe analyze memory track --pid PID --creation-time FILETIME --address ADDRESS --size BYTES --confirm [--samples N] [--interval-ms N] [--observe-threads] [--backend r3] [--json]",
        L"Track sampled per-page content and mapping changes in an explicitly authorized process.",
        L"Required: --pid, --creation-time, --address, --size (1..65536), --confirm. Optional: --samples (2..64, default 20), --interval-ms (10..1000, default 100), --observe-threads, --backend r3, --json.",
        L"Read-only, same user and session. Returns page state, SHA-256, change ranges and coverage gaps. --observe-threads adds a separate thread snapshot after rounds that read bytes. Does not collect execution or attribute writes. No project is modified.", Run});

    Command stream;
    stream.path = L"analyze memory stream";
    stream.syntax = L"KswordCLI.exe analyze memory stream --pid PID --creation-time FILETIME --address ADDRESS --size BYTES --confirm [--interval-ms N] [--observe-threads] [--output text|jsonl] [--backend r3]";
    stream.summary = L"Continuously sample an explicitly authorized owned process, until stopped.";
    stream.options = L"Size: 1..65536 bytes. Interval: 10..1000 ms minimum delay, default 100; stream checks on a roughly 50 ms tick. Default output: text. Optional --observe-threads adds a separate read-only thread snapshot after rounds that read bytes.";
    stream.notes = L"Send a plain stop line on stdin. EOF stops; Ctrl-C/Break cancels. For JSONL output, redirect both stdin and stdout and read continuously. Status-only checks do not observe threads. No sample count, execution evidence, write attribution, or target changes.";
    stream.runStreaming = RunStream;
    addCommand(std::move(stream));
}

} // namespace ks::cli::action_analyze
