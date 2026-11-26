// NativeStopMemoryTests.cpp
// 最小必要真实无窗口验收：
//   A) 直接驱动 NativeDebugOwner，在真实 AMD64 执行断点与 Into 步进停点上验证
//      CaptureNativeStopMemory 的停点令牌、逐页读取、无继续与错误请求拒绝；
//   B) OwnedDataWatchSession::CaptureMemory 复用该 helper、绑定新 sampleId，
//      不触发条件自动继续，并在正常清退后回读。
// 本 EXE 同时充当控制宿主与自有良性合作子进程（--child / --datawatch-child）。

#include "../../../KswordCLI/ActionAnalyze/Control/ProcessGroupMemorySnapshot.h"
#include "../../../KswordCLI/ActionAnalyze/Control/NativeDebugOwner.h"
#include "../../../KswordCLI/ActionAnalyze/Control/NativeStep.h"
#include "../../../KswordCLI/ActionAnalyze/Control/OwnedDataWatchSession.h"
#include "../../../KswordCLI/ActionAnalyze/Control/OwnedProcessGroup.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectMemorySnapshot.h"

#include <Windows.h>

#include <filesystem>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

using namespace ks::cli::action_analyze::control;
namespace memory = ks::cli::action_analyze::memory;

// ---------------------------------------------------------------------------
// 合作目标导出与已知字节。宿主与目标为同一 EXE，RVA 一致，仅映像基址不同。
// ---------------------------------------------------------------------------
// 真实执行断点与 Into 步进的确定性站点，首指令 NOP（见 NativeStopMemoryFixture.asm）。
extern "C" void KswordStopMemoryStepSite();

extern "C" __declspec(dllexport) unsigned char KswordNativeStopMemoryBytes[16] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x5A,
};

// OwnedDataWatchSession 的合作标记与 4 字节写入关注点，必须位于可写、不可执行节。
extern "C" __declspec(dllexport) unsigned char KSwordActionAnalyzeDataWatchV1 = 0;
extern "C" __declspec(dllexport) unsigned int KswordNativeStopMemoryWatch = 0;

namespace {

constexpr DWORD kDeadlineMs = 5000;
constexpr unsigned long long kWatchValue = 0x1A2B3C4DULL;
unsigned g_checks = 0;

void Trace(const char* step)
{
    std::fprintf(stderr, "TRACE %s\n", step);
}

void Require(bool condition, const char* check)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL %s win32=%lu\n", check, GetLastError());
        std::exit(1);
    }
    ++g_checks;
}

void RequireEq(bool condition, const char* check, const char* detail)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL %s (%s)\n", check, detail ? detail : "");
        std::exit(1);
    }
    ++g_checks;
}

class Handle {
public:
    explicit Handle(HANDLE handle = nullptr) : handle_(handle) {}
    ~Handle() { if (handle_) CloseHandle(handle_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE Get() const { return handle_; }
    void Reset(HANDLE value)
    {
        if (handle_) CloseHandle(handle_);
        handle_ = value;
    }
private:
    HANDLE handle_;
};

HANDLE InheritedEvent()
{
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    const auto event = CreateEventW(&attributes, TRUE, FALSE, nullptr);
    Require(event != nullptr, "fixture-event");
    return event;
}

std::uint64_t FileTimeValue(const FILETIME& time)
{
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

std::uint64_t RvaOf(const void* address)
{
    return reinterpret_cast<std::uintptr_t>(address) -
        reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
}

std::string OwnerLabel(const char* prefix)
{
    return std::string(prefix);
}

OwnerIdentity MakeIdentity()
{
    return OwnerIdentity{OwnerLabel("20000000-0000-0000-0000-000000000001"),
        OwnerLabel("20000000-0000-0000-0000-000000000002"),
        OwnerLabel("20000000-0000-0000-0000-000000000003"),
        OwnerLabel("20000000-0000-0000-0000-000000000004")};
}

// ---------------------------------------------------------------------------
// 子进程：直接断点模式。四个继承事件 [go, hit, exit, ready]。
// ---------------------------------------------------------------------------
// 与既有步进夹具一致：真实断点与 Into 都发生在子进程主线程，另一个稳定
// 等待的对端线程由 owner 在步进时挂起/恢复。
struct DirectPeer {
    HANDLE exitEvent;
    HANDLE readyEvent;
};

DWORD WINAPI DirectPeerThread(void* context)
{
    const auto* peer = static_cast<const DirectPeer*>(context);
    SetEvent(peer->readyEvent); // 对端已进入稳定等待态，宿主可安全枚举/挂起。
    WaitForSingleObject(peer->exitEvent, INFINITE);
    return 0;
}

int DirectChild(wchar_t** args)
{
    HANDLE events[4]{};
    for (int i = 0; i < 4; ++i) {
        events[i] = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(args[i], nullptr, 10)));
    }
    DirectPeer peer{events[2], events[3]};
    const auto thread = CreateThread(nullptr, 0, DirectPeerThread, &peer, 0, nullptr);
    if (!thread) return 2;
    WaitForSingleObject(events[0], INFINITE);
    KswordStopMemoryStepSite();
    WaitForSingleObject(events[2], INFINITE);
    const auto status = WaitForSingleObject(thread, kDeadlineMs);
    CloseHandle(thread);
    return status == WAIT_OBJECT_0 ? 0 : 2;
}

// ---------------------------------------------------------------------------
// 子进程：OwnedDataWatchSession 写入模式。等待命名事件后写已知 4 字节。
// ---------------------------------------------------------------------------
int DataWatchChild()
{
    const Handle gate(OpenEventW(SYNCHRONIZE, FALSE, L"Local\\KSword.NativeStopMemory.DataWatchGate"));
    if (!gate.Get()) return 2;
    if (WaitForSingleObject(gate.Get(), kDeadlineMs * 4) != WAIT_OBJECT_0) return 2;
    KswordNativeStopMemoryWatch = static_cast<unsigned int>(kWatchValue);
    return 0;
}

// ---------------------------------------------------------------------------
// 直接模式宿主夹具
// ---------------------------------------------------------------------------
class DirectFixture {
public:
    explicit DirectFixture(const wchar_t* executable) : job_(CreateFixtureJob())
    {
        std::wstring command = L"\"" + std::wstring(executable) + L"\" --child";
        HANDLE inherited[4]{};
        for (int i = 0; i < 4; ++i) {
            inherited[i] = events_[i].Get();
            command += L" " + std::to_wstring(reinterpret_cast<std::uintptr_t>(inherited[i]));
        }
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 2, 0, &bytes);
        Require(bytes != 0, "direct-attribute-size");
        std::vector<std::uintptr_t> storage((bytes + sizeof(std::uintptr_t) - 1) / sizeof(std::uintptr_t));
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        Require(InitializeProcThreadAttributeList(startup.lpAttributeList, 2, 0, &bytes) != FALSE,
            "direct-attribute-list");
        Require(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited, sizeof(inherited), nullptr, nullptr) != FALSE, "direct-inherited-handles");
        auto job = job_.Get();
        Require(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
            &job, sizeof(job), nullptr, nullptr) != FALSE, "direct-create-time-job");
        PROCESS_INFORMATION process{};
        const auto created = CreateProcessW(executable, command.data(), nullptr, nullptr, TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
            &startup.StartupInfo, &process);
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        Require(created != FALSE, "direct-create-child");
        const Handle initialThread(process.hThread);
        process_.Reset(process.hProcess);
        pid = process.dwProcessId;
        BOOL inJob = FALSE;
        Require(IsProcessInJob(process_.Get(), job_.Get(), &inJob) && inJob, "direct-child-in-job");
        Require(ResumeThread(initialThread.Get()) == 1, "direct-resume-child");
        Require(WaitForSingleObject(events_[3].Get(), kDeadlineMs) == WAIT_OBJECT_0, "direct-child-ready");
        FILETIME creation{}, exit{}, kernel{}, user{};
        Require(GetProcessTimes(process_.Get(), &creation, &exit, &kernel, &user) != FALSE,
            "direct-creation-time");
        creationTime = FileTimeValue(creation);
        Require(creationTime != 0, "direct-creation-time-nonzero");
    }

    void Go() const { Require(SetEvent(events_[0].Get()) != FALSE, "direct-signal-go"); }
    void Hit() const { Require(WaitForSingleObject(events_[1].Get(), 0) != WAIT_TIMEOUT, "direct-child-hit"); }

    void Exit()
    {
        SetEvent(events_[2].Get());
        if (process_.Get() && WaitForSingleObject(process_.Get(), kDeadlineMs) == WAIT_OBJECT_0) {
            DWORD code = 0;
            GetExitCodeProcess(process_.Get(), &code);
            Require(code == 0, "direct-child-normal-exit");
        }
    }

    DWORD pid = 0;
    std::uint64_t creationTime = 0;

private:
    static HANDLE CreateFixtureJob()
    {
        const auto job = CreateJobObjectW(nullptr, nullptr);
        Require(job != nullptr, "direct-create-job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        Require(SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE,
            "direct-job-kill-on-close");
        return job;
    }

    Handle job_;
    Handle process_;
    Handle events_[4]{Handle(InheritedEvent()), Handle(InheritedEvent()), Handle(InheritedEvent()),
        Handle(InheritedEvent())};
};

NativeControlResult WaitForBreakpoint(NativeDebugOwner& owner, NativeBreakpointState expected)
{
    const auto deadline = GetTickCount64() + kDeadlineMs;
    NativeControlResult result;
    do {
        result = owner.Query();
        if (result.breakpoint && result.breakpoint->state == expected) break;
        if (result.breakpoint && (result.breakpoint->state == NativeBreakpointState::Rejected ||
            result.breakpoint->state == NativeBreakpointState::RecoveryRequired)) break;
        Sleep(1);
    } while (GetTickCount64() < deadline);
    if (!result.breakpoint || result.breakpoint->state != expected) {
        std::fprintf(stderr, "BP_STATE stage=%s binding=%s error=%u status=%d\n", result.stage,
            result.breakpoint ? result.breakpoint->stage : "none", result.win32Error,
            static_cast<int>(result.status));
    }
    Require(result.breakpoint && result.breakpoint->state == expected, "direct-exact-breakpoint-state");
    return result;
}

ProcessGroupStop StopOf(const NativeControlResult& state)
{
    Require(state.group && state.responsibility && state.pending, "stop-has-complete-token");
    return ProcessGroupStop{{state.pid, state.processCreationTime}, state.group->groupId,
        state.responsibility->stopId, state.pending->event, state.group->stateRevision};
}

ReleaseRequest ReleaseOf(const OwnerIdentity& owner, const NativeControlResult& stop, std::string id)
{
    Require(stop.group && stop.responsibility, "release-has-group-and-stop");
    return {owner, stop.group->groupId, stop.responsibility->stopId, stop.responsibility->event,
        std::move(id), stop.group->stateRevision};
}

const NativeFrozenThread& OriginThread(const NativeControlResult& stop)
{
    Require(stop.pending && stop.pending->tid, "step-origin-thread-present");
    for (const auto& thread : stop.frozenThreads) {
        if (thread.tid == stop.pending->tid) return thread;
    }
    std::fprintf(stderr, "step-origin-tid=%u not-in-frozen-set\n", stop.pending->tid);
    std::exit(1);
}

memory::Plan MakePlan(const OwnerIdentity& identity, DWORD pid, std::uint64_t creationTime,
    std::uint64_t base, std::uint64_t length)
{
    memory::Plan plan;
    plan.sampleId = identity.sampleId;
    plan.trackingEpoch = identity.epoch;
    plan.target.machineId = "nsm-machine";
    plan.target.bootId = "nsm-boot";
    plan.target.processInstanceId = "nsm-instance";
    plan.target.pid = pid;
    plan.target.creationFileTime100ns = creationTime;
    plan.range.base = base;
    plan.range.length = length;
    plan.rounds = 2;
    plan.intervalMs = 10;
    plan.authorizedOwnedProcess = true;
    return plan;
}

ProcessMemorySnapshotRequest MakeHeldRequest([[maybe_unused]] const OwnerIdentity& identity,
    const memory::Plan& plan, const ProcessGroupStop& stop)
{
    ProcessMemorySnapshotRequest request;
    request.plan = plan;
    request.source = ProcessMemorySource::HeldEvent;
    request.stop = stop;
    return request;
}

// 所有失败请求都必须在读取前被拒绝，且不改变 owner 持有的停点。
void CheckRejected(NativeDebugOwner& owner, const OwnerIdentity& identity,
    const ProcessMemorySnapshotRequest& request, const char* stage, const char* name)
{
    const auto result = CaptureNativeStopMemory(owner, identity, request, nullptr);
    if (result.stage != stage) {
        std::fprintf(stderr, "REJECT_STAGE name=%s got=%s want=%s error=%u\n", name,
            result.stage, stage, result.win32Error);
    }
    RequireEq(result.stage == stage && !result.snapshot.has_value(), name, result.stage);
}

// ---------------------------------------------------------------------------
// A: 直接 CaptureNativeStopMemory
// ---------------------------------------------------------------------------
void TestDirectCapture(const wchar_t* executable)
{
    Trace("direct: identity");
    const auto identity = MakeIdentity();
    Trace("direct: fixture-launch");
    DirectFixture fixture(executable);
    Trace("direct: fixture-ready");

    wchar_t module[MAX_PATH]{};
    Require(GetModuleFileNameW(nullptr, module, MAX_PATH) > 0, "direct-module-path");

    NativeBreakpointRequest request{{"nsm-direct-breakpoint", fixture.pid, fixture.creationTime, true,
        NativeTargetDisposition::ResumeAndDetach}, module,
        static_cast<std::uint32_t>(RvaOf(&KswordStopMemoryStepSite)), {}, 0, false};
    Trace("direct: owner-created");
    NativeDebugOwner owner(identity);
    Trace("direct: arm-call");
    const auto accepted = owner.ArmBreakpoint(request);
    Trace("direct: arm-returned");
    Require(accepted.status == NativeControlStatus::Accepted, "direct-breakpoint-accepted");
    const auto armed = WaitForBreakpoint(owner, NativeBreakpointState::Armed);
    Trace("direct: armed");
    Require(armed.breakpoint->enrolledThreads >= 2, "direct-two-threads-enrolled");

    const auto knownRva = RvaOf(&KswordNativeStopMemoryBytes);
    const auto knownBase = armed.breakpoint->moduleBase + knownRva;
    const auto plan = MakePlan(identity, fixture.pid, fixture.creationTime, knownBase,
        sizeof(KswordNativeStopMemoryBytes));

    fixture.Go();
    Trace("direct: go-signaled");
    const auto held = WaitForBreakpoint(owner, NativeBreakpointState::Held);
    Trace("direct: held");
    Require(held.status == NativeControlStatus::Held && held.attached && !held.clean, "direct-real-held-stop");
    Require(held.group && held.group->state == GroupState::HeldComplete && held.pending &&
        held.pending->ledgerOwned && held.responsibility, "direct-held-complete-token");
    std::fprintf(stderr, "HELD eventCode=%u exception=%u hit=%u stage=%s tid=%u\n",
        held.pending->eventCode, held.pending->exceptionCode.value_or(0),
        held.breakpointHit.has_value() ? 1U : 0U, held.stage, held.pending->tid);
    Require(held.pending->eventCode == EXCEPTION_DEBUG_EVENT && held.pending->exceptionCode &&
        *held.pending->exceptionCode == EXCEPTION_SINGLE_STEP && held.breakpointHit.has_value(),
        "direct-real-single-step-event");

    const auto stop = StopOf(held);
    const auto heldRequest = MakeHeldRequest(identity, plan, stop);

    // 正控：原 owner、同一 ia 身份、精确停点令牌，逐页读取已知字节。
    const auto captured = CaptureNativeStopMemory(owner, identity, heldRequest, nullptr);
    if (captured.stage != std::string_view("process-memory-read-observed")) {
        std::fprintf(stderr, "CAPTURE stage=%s error=%u\n", captured.stage, captured.win32Error);
    }
    RequireEq(captured.stage == std::string_view("process-memory-read-observed") &&
        captured.snapshot.has_value(), "direct-capture-observed", captured.stage);
    Require(captured.snapshot->completeRange, "direct-complete-range");
    Require(captured.snapshot->captured.size() == 1, "direct-one-captured-page");
    Require(captured.snapshot->captured[0].bytes.size() == sizeof(KswordNativeStopMemoryBytes),
        "direct-captured-byte-count");
    Require(std::memcmp(captured.snapshot->captured[0].bytes.data(), KswordNativeStopMemoryBytes,
        sizeof(KswordNativeStopMemoryBytes)) == 0, "direct-known-bytes");
    Require(captured.before.has_value() && *captured.before == stop, "direct-before-token-exact");
    Require(captured.after.has_value() && *captured.after == stop, "direct-after-token-exact");
    Require(captured.heldAtBothChecks, "direct-held-at-both-checks");
    Require(captured.request.plan.target.pid == fixture.pid, "direct-request-not-rewritten");

    // 读后原生停点不被读取动作继续或改写。
    const auto post = owner.Query(stop.groupId);
    Require(post.status == NativeControlStatus::Held && post.pending && post.pending->event == stop.event &&
        post.group && post.group->stateRevision == stop.stateRevision, "direct-stop-unchanged-after-read");
    Require(post.release == std::nullopt, "direct-no-continue-from-read");

    // 负控 1：请求形态错误。
    auto live = heldRequest;
    live.source = ProcessMemorySource::LiveRead;
    CheckRejected(owner, identity, live, "process-memory-held-request-required", "direct-live-with-stop-rejected");
    auto noStop = heldRequest;
    noStop.stop.reset();
    CheckRejected(owner, identity, noStop, "process-memory-held-request-required", "direct-no-stop-rejected");
    auto wrongSamplePlan = plan;
    wrongSamplePlan.sampleId = "20000000-0000-0000-0000-0000000000ff";
    CheckRejected(owner, identity, MakeHeldRequest(identity, wrongSamplePlan, stop),
        "process-memory-held-request-required", "direct-wrong-sample-rejected");
    auto unauthorized = plan;
    unauthorized.authorizedOwnedProcess = false;
    CheckRejected(owner, identity, MakeHeldRequest(identity, unauthorized, stop),
        "process-memory-held-request-required", "direct-unauthorized-rejected");

    // 负控 2：owner/session/epoch/后端身份错误，不能借用当前 Held 事件。
    auto wrongIdentity = identity;
    wrongIdentity.sessionId = "20000000-0000-0000-0000-0000000000f2";
    CheckRejected(owner, wrongIdentity, heldRequest, "process-memory-stale-stop", "direct-wrong-session-rejected");
    wrongIdentity = identity;
    wrongIdentity.epoch = "20000000-0000-0000-0000-0000000000f3";
    CheckRejected(owner, wrongIdentity, heldRequest, "process-memory-stale-stop", "direct-wrong-epoch-rejected");
    wrongIdentity = identity;
    wrongIdentity.backendInstanceId = "20000000-0000-0000-0000-0000000000f4";
    CheckRejected(owner, wrongIdentity, heldRequest, "process-memory-stale-stop", "direct-wrong-backend-rejected");

    // 负控 3：目标创建时间、旧 event/revision、旧 group/stopId。
    auto wrongCreation = plan;
    wrongCreation.target.creationFileTime100ns += 1;
    CheckRejected(owner, identity, MakeHeldRequest(identity, wrongCreation, stop),
        "process-memory-stale-stop", "direct-wrong-creation-time-rejected");
    auto wrongEvent = stop;
    wrongEvent.event.serial += 1;
    CheckRejected(owner, identity, MakeHeldRequest(identity, plan, wrongEvent),
        "process-memory-stale-stop", "direct-old-event-rejected");
    auto wrongRevision = stop;
    wrongRevision.stateRevision += 1;
    CheckRejected(owner, identity, MakeHeldRequest(identity, plan, wrongRevision),
        "process-memory-stale-stop", "direct-old-revision-rejected");
    auto wrongGroup = stop;
    wrongGroup.groupId = "nsm-old-group";
    CheckRejected(owner, identity, MakeHeldRequest(identity, plan, wrongGroup),
        "process-memory-stale-stop", "direct-old-group-rejected");

    // 所有负控后 owner 仍持有同一事件，没有产生继续回执。
    const auto afterRejects = owner.Query(stop.groupId);
    Require(afterRejects.status == NativeControlStatus::Held && afterRejects.pending &&
        afterRejects.pending->event == stop.event, "direct-stop-held-after-all-rejects");
    Require(afterRejects.release == std::nullopt, "direct-no-continue-from-rejects");

    // 真实 Into 步进停点上再次读取仍可用。等待对端线程进入稳定等待态。
    Sleep(60);
    const auto& origin = OriginThread(held);
    NativeStepRequest stepRequest{ReleaseOf(identity, held, "continue/1"), origin.identity, origin.tid,
        origin.creationTime, NativeStepMode::Into};
    NativeControlResult started;
    for (int attempt = 0; attempt < 8; ++attempt) {
        started = owner.Step(stepRequest);
        if (started.release && started.release->receipt &&
            started.release->receipt->result == ReleaseResult::Continued) break;
        // 对端线程刚从断点返回，偶发 SuspendThread 竞态；同一精确令牌可重试。
        if (!started.step || std::string_view(started.step->stage) != "step-suspend-peer") break;
        Sleep(30);
    }
    if (started.status == NativeControlStatus::Rejected) {
        std::fprintf(stderr, "STEP_REJECT stage=%s error=%u ledger=%d\n", started.stage, started.win32Error,
            static_cast<int>(started.ledgerResult));
    }
    Require(started.status != NativeControlStatus::Rejected, "direct-into-step-accepted");
    std::fprintf(stderr, "STEP_STARTED status=%d stage=%s error=%u release=%u receipt=%u result=%d step=%s stepError=%u\n",
        static_cast<int>(started.status), started.stage, started.win32Error,
        started.release.has_value() ? 1U : 0U,
        started.release && started.release->receipt ? 1U : 0U,
        started.release && started.release->receipt ? static_cast<int>(started.release->receipt->result) : -1,
        started.step ? started.step->stage : "none", started.step ? started.step->win32Error : 0U);
    Require(started.release && started.release->receipt &&
        started.release->receipt->result == ReleaseResult::Continued, "direct-into-step-released-event");
    const auto deadline = GetTickCount64() + kDeadlineMs;
    NativeControlResult stepDone;
    do {
        stepDone = owner.QueryStep("continue/1");
        if (stepDone.step && stepDone.step->state != NativeStepState::Running) break;
        Sleep(1);
    } while (GetTickCount64() < deadline);
    Require(stepDone.step && stepDone.step->state == NativeStepState::Completed, "direct-into-step-completed");
    Require(stepDone.step->stopGroupId.has_value(), "direct-into-step-new-group");
    const auto stepStopState = owner.Query(*stepDone.step->stopGroupId);
    Require(stepStopState.status == NativeControlStatus::Held && stepStopState.attached &&
        !stepStopState.clean && stepStopState.breakpointHit == std::nullopt, "direct-into-stop-is-fresh");
    const auto stepStop = StopOf(stepStopState);
    const auto stepCaptured = CaptureNativeStopMemory(owner, identity,
        MakeHeldRequest(identity, plan, stepStop), nullptr);
    RequireEq(stepCaptured.stage == std::string_view("process-memory-read-observed") &&
        stepCaptured.snapshot.has_value() && stepCaptured.heldAtBothChecks,
        "direct-into-stop-capture", stepCaptured.stage);
    Require(stepCaptured.snapshot->captured.size() == 1 &&
        std::memcmp(stepCaptured.snapshot->captured[0].bytes.data(), KswordNativeStopMemoryBytes,
            sizeof(KswordNativeStopMemoryBytes)) == 0, "direct-into-stop-known-bytes");

    // 正常清退：释放步进事件、目标正常退出、owner 干净关闭。
    const auto released = owner.Continue(ReleaseOf(identity, stepStopState, "continue/2"));
    Require(released.release && released.release->receipt &&
        released.release->receipt->result == ReleaseResult::Continued, "direct-final-release");
    fixture.Exit();
    const auto closed = owner.Close();
    Require(closed.clean && closed.status == NativeControlStatus::Closed, "direct-owner-closed-clean");
}

// ---------------------------------------------------------------------------
// B: OwnedDataWatchSession::CaptureMemory 与新 sampleId 绑定
// ---------------------------------------------------------------------------
void TestSessionCapture(const wchar_t* executable, const wchar_t* scratch)
{
    // Identity() 是只读引用；在编译期固定该契约。
    static_assert(std::is_same_v<decltype(std::declval<const OwnedDataWatchSession&>().Identity()),
        const OwnerIdentity&>, "session-identity-is-read-only");

    const Handle gate(CreateEventW(nullptr, TRUE, FALSE, L"Local\\KSword.NativeStopMemory.DataWatchGate"));
    Require(gate.Get() != nullptr, "session-create-gate");
    ResetEvent(gate.Get());

    // 归档样本先创建，使本会话的 sampleId 与原始写入上下文同源。
    namespace aa = Ksword::ActionAnalyze;
    const auto projectPath = std::filesystem::path(scratch) / L"native-stop-memory-project";
    aa::ProjectDocument project;
    Require(!!project.Create(projectPath.wstring(), {"Native stop memory fixture", ""}),
        "session-create-project");
    aa::SampleInfo sample;
    Require(!!project.CreateSample("native-stop-memory", sample), "session-create-sample");
    const std::string sampleId = sample.sampleId;

    OwnedDataWatchSession session;
    // Start 只接受路径与导出名；用继承环境把本 EXE 切到写入子进程模式。
    Require(SetEnvironmentVariableW(L"KSWORD_NSM_DATAWATCH_CHILD", L"1") != FALSE,
        "session-set-child-flag");
    const auto started = session.Start(executable, "KswordNativeStopMemoryWatch", 4, {}, false, sampleId);
    SetEnvironmentVariableW(L"KSWORD_NSM_DATAWATCH_CHILD", nullptr);
    if (started.status == NativeControlStatus::Rejected) {
        std::fprintf(stderr, "SESSION_START stage=%s error=%u\n", started.stage, started.win32Error);
    }
    Require(started.status == NativeControlStatus::Accepted, "session-start-accepted");
    Require(session.Identity().sampleId == sampleId, "session-sample-bound");

    const auto conditionBefore = session.ConditionReport();
    Require(conditionBefore.trueCount == 0 && conditionBefore.falseCount == 0 &&
        conditionBefore.unknownCount == 0, "session-no-condition-eval-at-start");

    // 等待原生绑定就绪，再放行目标写入，得到真实数据写入停点。
    NativeControlResult armed;
    const auto armDeadline = GetTickCount64() + kDeadlineMs;
    do {
        armed = session.Query();
        if (armed.breakpoint && armed.breakpoint->state == NativeBreakpointState::Armed) break;
        Sleep(1);
    } while (GetTickCount64() < armDeadline);
    Require(armed.breakpoint && armed.breakpoint->state == NativeBreakpointState::Armed,
        "session-breakpoint-armed");
    Require(SetEvent(gate.Get()) != FALSE, "session-release-target-write");

    NativeControlResult held;
    const auto holdDeadline = GetTickCount64() + kDeadlineMs;
    do {
        held = session.Query();
        if (held.status == NativeControlStatus::Held && held.group &&
            held.group->state == GroupState::HeldComplete && held.responsibility && held.pending) break;
        Sleep(1);
    } while (GetTickCount64() < holdDeadline);
    if (held.status != NativeControlStatus::Held) {
        std::fprintf(stderr, "SESSION_HOLD stage=%s error=%u status=%d\n", held.stage, held.win32Error,
            static_cast<int>(held.status));
    }
    Require(held.status == NativeControlStatus::Held && held.group &&
        held.group->state == GroupState::HeldComplete && held.responsibility && held.pending,
        "session-data-write-held");
    Require(held.breakpointHit && held.breakpointHit->dataChange.has_value(), "session-real-write-change");
    Require(held.group->sampleId == sampleId && held.group->sessionId == session.Identity().sessionId &&
        held.group->epoch == session.Identity().epoch, "session-token-binds-identity");

    const auto watchRva = RvaOf(&KswordNativeStopMemoryWatch);
    const auto watchBase = held.breakpoint->moduleBase + watchRva;
    const auto plan = MakePlan(session.Identity(), held.pid, held.processCreationTime, watchBase,
        sizeof(KswordNativeStopMemoryWatch));

    const auto captured = session.CaptureMemory(held, plan, nullptr);
    if (captured.stage != std::string_view("process-memory-read-observed")) {
        std::fprintf(stderr, "SESSION_CAPTURE stage=%s error=%u\n", captured.stage, captured.win32Error);
    }
    RequireEq(captured.stage == std::string_view("process-memory-read-observed") &&
        captured.snapshot.has_value() && captured.heldAtBothChecks, "session-capture-observed", captured.stage);
    Require(captured.snapshot->captured.size() == 1 &&
        captured.snapshot->captured[0].bytes.size() == sizeof(KswordNativeStopMemoryWatch),
        "session-captured-byte-count");
    unsigned int observed = 0;
    std::memcpy(&observed, captured.snapshot->captured[0].bytes.data(), sizeof(observed));
    Require(observed == static_cast<unsigned int>(kWatchValue), "session-known-written-bytes");

    // helper 输出的原请求模式与读前/读后完整令牌可直接交给归档写入器；
    // 单次写回读由写入器内部同步完成（receipt.verified）。
    aa::ProjectMemorySnapshotReceipt receipt;
    const auto wrote = aa::WriteProcessGroupMemorySnapshot(project, sampleId, 1, std::nullopt, captured, receipt);
    if (!wrote) {
        std::fprintf(stderr, "ARCHIVE detail=%s\n", wrote.detail);
    }
    Require(!!wrote, "session-archive-accepts-helper-output");
    Require(receipt.verified && receipt.completeRange && receipt.ordinal == 1 &&
        receipt.capturedBytes == sizeof(KswordNativeStopMemoryWatch), "session-archive-verified-readback");

    // 读取不触发条件自动继续：条件计数与原生停点均不变。
    const auto conditionAfter = session.ConditionReport();
    Require(conditionAfter.trueCount == 0 && conditionAfter.falseCount == 0 &&
        conditionAfter.unknownCount == 0, "session-no-auto-continue-from-read");
    const auto stillHeld = session.Query();
    Require(stillHeld.status == NativeControlStatus::Held && stillHeld.pending &&
        stillHeld.pending->event == held.pending->event, "session-stop-still-held-after-read");

    // 旧/错身份的显示快照不能借用本次读取。
    auto staleDisplayed = held;
    staleDisplayed.group->epoch = "nsm-epoch-stale";
    const auto stale = session.CaptureMemory(staleDisplayed, plan, nullptr);
    RequireEq(stale.stage == std::string_view("data-watch-memory-stale-stop"), "session-stale-displayed-rejected",
        stale.stage);
    Require(!stale.snapshot.has_value(), "session-stale-displayed-no-read");

    // 正常清退：会话释放原生事件，目标退出，owner 回读 clean。
    auto closed = session.Close();
    const auto closeDeadline = GetTickCount64() + kDeadlineMs;
    while (!closed.clean && GetTickCount64() < closeDeadline) {
        Sleep(5);
        closed = session.Close();
    }
    Require(closed.clean, "session-closed-clean");
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    wchar_t childFlag[8]{};
    if (GetEnvironmentVariableW(L"KSWORD_NSM_DATAWATCH_CHILD", childFlag, 8) > 0) return DataWatchChild();
    if (argc >= 6 && std::wcscmp(argv[1], L"--child") == 0) return DirectChild(argv + 2);
    if (argc == 2 && std::wcscmp(argv[1], L"--datawatch-child") == 0) return DataWatchChild();

    wchar_t executable[MAX_PATH]{};
    Require(GetModuleFileNameW(nullptr, executable, MAX_PATH) > 0, "host-module-path");

    const wchar_t* scratch = argc > 1 ? argv[1] : L".";
    TestDirectCapture(executable);
    std::fprintf(stderr, "DIRECT_SECTION_DONE checks=%u\n", g_checks);
    TestSessionCapture(executable, scratch);

    std::printf("RESULT=PASS checks=%u\n", g_checks);
    return 0;
}
