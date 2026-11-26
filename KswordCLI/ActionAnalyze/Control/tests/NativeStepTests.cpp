// Native single-step acceptance for the production NativeDebugOwner.
//
// The fixture is a self-created benign cooperative child of this process. It
// runs a fixed MASM sequence (NativeStepFixture.asm) whose instruction
// boundaries are known, so every step outcome is checked against a real
// instruction address, a real stack slot and a real native event.

#include "../NativeDebugOwner.h"
#include "NativeStepFixture.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace ks::cli::action_analyze::control;

namespace {

constexpr DWORD kDeadlineMs = 20000;
constexpr DWORD kChildException = 0xe115aa02;

enum ChildFlag : unsigned {
    kFlagSpawn = 1u << 0,
    kFlagBlock = 1u << 1,
    kFlagRaise = 1u << 2,
    kFlagRecurse = 1u << 3,
    kFlagExitThread = 1u << 4,
    kFlagExitProcess = 1u << 5,
};

enum EventIndex {
    kGo = 0,
    kFixtureDone = 1,
    kReady = 2,
    kExit = 3,
    kPeerPulse = 4,
    kPeerAck = 5,
    kReleaseCallee = 6,
    kSpawnedRan = 7,
    kExceptionHandled = 8,
    kPeerAlive = 9,
    kEventCount = 10,
};

unsigned checks = 0;
unsigned failures = 0;

void Require(bool condition, const char* check) {
    ++checks;
    if (!condition) {
        ++failures;
        std::fprintf(stderr, "FAIL %s win32=%lu\n", check, GetLastError());
        throw std::runtime_error(check);
    }
}

class Handle {
public:
    explicit Handle(HANDLE handle = nullptr) : handle_(handle) {}
    ~Handle() { if (handle_) { CloseHandle(handle_); } }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE Get() const { return handle_; }
    void Reset(HANDLE value = nullptr) {
        if (handle_) { CloseHandle(handle_); }
        handle_ = value;
    }
private:
    HANDLE handle_;
};

HANDLE* g_childEvents = nullptr;
unsigned g_childFlags = 0;
HANDLE g_releaseEvent = nullptr;
std::FILE* g_childLog = nullptr;
DWORD g_faultCode = 0;
std::uintptr_t g_faultAddress = 0;
std::uintptr_t g_faultRip = 0;
std::uintptr_t g_faultRsp = 0;
std::uintptr_t g_faultRbp = 0;

void ChildLog(const char* format, ...) {
    if (!g_childLog) { return; }
    va_list arguments;
    va_start(arguments, format);
    std::vfprintf(g_childLog, format, arguments);
    va_end(arguments);
    std::fputc('\n', g_childLog);
    std::fflush(g_childLog);
}

int ChildFilter(EXCEPTION_POINTERS* pointers) {
    if (pointers) {
        g_faultCode = pointers->ExceptionRecord->ExceptionCode;
        g_faultAddress = reinterpret_cast<std::uintptr_t>(pointers->ExceptionRecord->ExceptionAddress);
        if (pointers->ContextRecord) {
            g_faultRip = pointers->ContextRecord->Rip;
            g_faultRsp = pointers->ContextRecord->Rsp;
            g_faultRbp = pointers->ContextRecord->Rbp;
        }
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

// Kept out of ChildMain: a function with __try cannot need object unwinding.
void LogChildThreads() {
    const Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD | TH32CS_SNAPPROCESS, 0));
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!snapshot.Get() || !Thread32First(snapshot.Get(), &entry)) { return; }
    do {
        if (entry.th32OwnerProcessID != GetCurrentProcessId()) { continue; }
        ChildLog("CHILD_THREAD tid=%u", static_cast<unsigned int>(entry.th32ThreadID));
    } while (Thread32Next(snapshot.Get(), &entry));
}

DWORD WINAPI PeerThread(void* context) {
    auto* const events = static_cast<HANDLE*>(context);
    ChildLog("PEER_ENTER tid=%u", static_cast<unsigned int>(GetCurrentThreadId()));
    const HANDLE inputs[]{events[kPeerPulse], events[kExit]};
    for (;;) {
        const auto result = WaitForMultipleObjects(2, inputs, FALSE, 100);
        if (result == WAIT_OBJECT_0) { SetEvent(events[kPeerAck]); continue; }
        if (result != WAIT_TIMEOUT) { break; }
        SetEvent(events[kPeerAlive]);
        ChildLog("PEER_TICK tid=%u", static_cast<unsigned int>(GetCurrentThreadId()));
    }
    return 0;
}

DWORD WINAPI SpawnedThread(void* context) {
    auto* const events = static_cast<HANDLE*>(context);
    SetEvent(events[kSpawnedRan]);
    WaitForSingleObject(events[kExit], INFINITE);
    return 0;
}

int ChildMain(unsigned flags, wchar_t** args) {
    HANDLE events[kEventCount]{};
    for (int i = 0; i < kEventCount; ++i) {
        events[i] = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(args[i], nullptr, 10)));
    }
    // The child cannot inherit the parent's standard handles: the fixture uses
    // an explicit inherited handle list. Its own diagnostics go to a text file
    // in the fixed test output directory instead.
    std::FILE* log = nullptr;
    if (_wfopen_s(&log, args[kEventCount], L"a") != 0 || !log) { return 6; }
    g_childLog = log;
    g_childEvents = events;
    g_childFlags = flags;
    g_releaseEvent = events[kReleaseCallee];
    ChildLog("CHILD_BEFORE_THREAD main=%u", static_cast<unsigned int>(GetCurrentThreadId()));
    const auto peer = CreateThread(nullptr, 0, PeerThread, events, 0, nullptr);
    if (!peer) { return 2; }
    ChildLog("CHILD_START flags=0x%x peer=%u main=%u", flags, static_cast<unsigned int>(GetThreadId(peer)),
        static_cast<unsigned int>(GetCurrentThreadId()));
    LogChildThreads();
    SetEvent(events[kReady]);
    if (WaitForSingleObject(events[kGo], INFINITE) != WAIT_OBJECT_0) { return 2; }
    ChildLog("CHILD_RUN_FIXTURE");
    __try {
        FixtureStepCallRun();
    } __except (ChildFilter(GetExceptionInformation())) {
        const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
        ChildLog("CHILD_FAULT code=0x%08lx address=0x%llx rip=0x%llx rsp=0x%llx rbp=0x%llx base=0x%llx",
            g_faultCode, static_cast<unsigned long long>(g_faultAddress),
            static_cast<unsigned long long>(g_faultRip), static_cast<unsigned long long>(g_faultRsp),
            static_cast<unsigned long long>(g_faultRbp), static_cast<unsigned long long>(base));
        for (int i = 0; i < 12; ++i) {
            std::uintptr_t value = 0;
            if (ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<void*>(g_faultRsp + static_cast<std::uintptr_t>(i) * sizeof(value)),
                &value, sizeof(value), nullptr)) {
                ChildLog("CHILD_STACK slot=%d value=0x%llx", i, static_cast<unsigned long long>(value));
            }
        }
        if (log) { std::fclose(log); }
        return 5;
    }
    ChildLog("CHILD_FIXTURE_RETURNED");
    SetEvent(events[kFixtureDone]);
    if (WaitForSingleObject(events[kExit], INFINITE) != WAIT_OBJECT_0) { return 2; }
    if (WaitForSingleObject(peer, kDeadlineMs) != WAIT_OBJECT_0) { return 2; }
    CloseHandle(peer);
    if (log) { std::fclose(log); }
    return 0;
}

} // namespace

// Called from the fixed MASM callee. Its behaviour is selected by the child
// command line so every native event is produced by this own fixture only.
extern "C" __declspec(noinline) void KswordFixtureCalleeBody() {
    if (g_childFlags & kFlagSpawn) {
        const auto thread = CreateThread(nullptr, 0, SpawnedThread, g_childEvents, 0, nullptr);
        if (thread) { CloseHandle(thread); }
    }
    if (g_childFlags & kFlagBlock) {
        const auto deadline = GetTickCount64() + 30000;
        while (GetTickCount64() < deadline && WaitForSingleObject(g_releaseEvent, 0) != WAIT_OBJECT_0) {
            Sleep(5);
        }
    }
    if (g_childFlags & kFlagRaise) {
        __try {
            RaiseException(kChildException, 0, 0, nullptr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SetEvent(g_childEvents[kExceptionHandled]);
        }
    }
    if (g_childFlags & kFlagExitThread) { ExitThread(0); }
    if (g_childFlags & kFlagExitProcess) { ExitProcess(0); }
    if (g_childFlags & kFlagRecurse) {
        g_childFlags &= ~kFlagRecurse;
        FixtureStepCallRun();
    }
}

namespace {

HANDLE InheritedEvent(bool manualReset = true) {
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    const auto event = CreateEventW(&attributes, manualReset, FALSE, nullptr);
    Require(event != nullptr, "fixture-event");
    return event;
}

std::uint32_t RvaOf(const void* label) {
    const auto module = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(label) - module);
}

std::wstring g_diagDir;

// Fixed diagnostic directory for the cooperative child's own text log.
std::wstring logPath() {
    static unsigned sequence = 0;
    std::wstring path = g_diagDir;
    if (path.empty()) { path = L"."; }
    if (path.back() != L'\\') { path += L'\\'; }
    path += L"native-step-child-" + std::to_wstring(sequence++) + L".log";
    return path;
}

class ChildFixture {
public:
    ChildFixture(const wchar_t* executable, unsigned flags) : job_(CreateJobObjectW(nullptr, nullptr)) {
        Require(job_.Get() != nullptr, "create-private-job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        Require(SetInformationJobObject(job_.Get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE,
            "set-private-job");
        std::wstring command = L"\"" + std::wstring(executable) + L"\" --child " + std::to_wstring(flags);
        HANDLE inherited[kEventCount]{};
        for (std::size_t i = 0; i < kEventCount; ++i) {
            inherited[i] = events_[i].Get();
            command += L" " + std::to_wstring(reinterpret_cast<std::uintptr_t>(inherited[i]));
        }
        childLogPath_ = logPath();
        command += L" " + childLogPath_;
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 2, 0, &bytes);
        Require(bytes != 0, "fixture-attribute-list-size");
        std::vector<std::uintptr_t> storage((bytes + sizeof(std::uintptr_t) - 1) / sizeof(std::uintptr_t));
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        Require(InitializeProcThreadAttributeList(startup.lpAttributeList, 2, 0, &bytes) != FALSE, "fixture-attribute-list");
        Require(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited, sizeof(inherited), nullptr, nullptr) != FALSE, "fixture-explicit-inherited-handles");
        auto job = job_.Get();
        Require(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
            &job, sizeof(job), nullptr, nullptr) != FALSE, "fixture-create-time-job");
        PROCESS_INFORMATION process{};
        const auto created = CreateProcessW(executable, command.data(), nullptr, nullptr, TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
            &startup.StartupInfo, &process);
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        Require(created != FALSE, "create-own-fixture");
        const Handle initialThread(process.hThread);
        process_.Reset(process.hProcess);
        pid = process.dwProcessId;
        BOOL inJob = FALSE;
        Require(IsProcessInJob(process_.Get(), job_.Get(), &inJob) && inJob, "own-fixture-in-private-job");
        Require(ResumeThread(initialThread.Get()) == 1, "start-own-fixture");
        Require(WaitForSingleObject(events_[kReady].Get(), kDeadlineMs) == WAIT_OBJECT_0, "fixture-threads-ready");
        FILETIME creation{}, exited{}, kernel{}, user{};
        Require(GetProcessTimes(process_.Get(), &creation, &exited, &kernel, &user) != FALSE, "fixture-creation-time");
        creationTime = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    }

    ~ChildFixture() {
        if (process_.Get() && WaitForSingleObject(process_.Get(), 0) == WAIT_TIMEOUT) {
            TerminateProcess(process_.Get(), 99);
            WaitForSingleObject(process_.Get(), 5000);
        }
    }

    void Signal(unsigned index) const { Require(SetEvent(events_[index].Get()) != FALSE, "signal-fixture-event"); }
    HANDLE Event(unsigned index) const { return events_[index].Get(); }
    bool Wait(unsigned index, DWORD limit) const {
        return WaitForSingleObject(events_[index].Get(), limit) == WAIT_OBJECT_0;
    }
    DWORD ExitCode() const {
        DWORD code = 0;
        GetExitCodeProcess(process_.Get(), &code);
        return code;
    }
    bool Alive() const { return WaitForSingleObject(process_.Get(), 0) == WAIT_TIMEOUT; }

    // Direct readback of this own child's threads: the test may inspect the
    // cooperative target it created without any debugger side effect.
    void DumpThreads(const char* tag) const {
        const Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD | TH32CS_SNAPPROCESS, 0));
        if (!snapshot.Get()) { return; }
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (!Thread32First(snapshot.Get(), &entry)) { return; }
        do {
            if (entry.th32OwnerProcessID != pid) { continue; }
            const Handle thread(OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_GET_CONTEXT |
                THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID));
            if (!thread.Get()) { continue; }
            CONTEXT context{};
            context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
            if (!GetThreadContext(thread.Get(), &context)) { continue; }
            const auto life = WaitForSingleObject(thread.Get(), 0);
            // The suspend count is observable without changing the effective
            // state: this probe adds and removes exactly one increment.
            const auto previous = SuspendThread(thread.Get());
            if (previous != static_cast<DWORD>(-1)) { ResumeThread(thread.Get()); }
            wchar_t module[MAX_PATH]{};
            const auto moduleLength = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(context.Rip), reinterpret_cast<HMODULE*>(&module));
            std::fprintf(stderr,
                "THREAD_STATE tag=%s owner=%u tid=%u life=%u suspend=%lu rip=0x%llx rsp=0x%llx dr0=0x%llx "
                "dr1=0x%llx dr6=0x%llx dr7=0x%llx eflags=0x%llx module=%ls\n",
                tag, static_cast<unsigned int>(entry.th32OwnerProcessID),
                static_cast<unsigned int>(entry.th32ThreadID), static_cast<unsigned int>(life),
                previous == static_cast<DWORD>(-1) ? 0xFFFFFFFFUL : previous,
                static_cast<unsigned long long>(context.Rip), static_cast<unsigned long long>(context.Rsp),
                static_cast<unsigned long long>(context.Dr0), static_cast<unsigned long long>(context.Dr1),
                static_cast<unsigned long long>(context.Dr6), static_cast<unsigned long long>(context.Dr7),
                static_cast<unsigned long long>(context.EFlags),
                moduleLength ? module : L"unknown");
        } while (Thread32Next(snapshot.Get(), &entry));
    }

    DWORD pid = 0;
    std::uint64_t creationTime = 0;

    // The cooperative child's own text report. The parent reads it to learn
    // what the child itself observed without trusting cross-process listings.
    std::string ReadChildLog() const {
        std::FILE* file = nullptr;
        if (_wfopen_s(&file, childLogPath_.c_str(), L"r") != 0 || !file) { return {}; }
        std::string text;
        char buffer[512]{};
        while (std::fgets(buffer, sizeof(buffer), file)) { text += buffer; }
        std::fclose(file);
        return text;
    }

    std::size_t CountPeerTicks() const {
        const auto text = ReadChildLog();
        std::size_t count = 0;
        for (std::size_t at = text.find("PEER_TICK"); at != std::string::npos; at = text.find("PEER_TICK", at + 1)) { ++count; }
        return count;
    }

private:
    Handle job_;
    Handle process_;
    std::wstring childLogPath_;
    Handle events_[kEventCount]{Handle(InheritedEvent()), Handle(InheritedEvent()), Handle(InheritedEvent()),
        Handle(InheritedEvent()), Handle(InheritedEvent(false)), Handle(InheritedEvent()), Handle(InheritedEvent()),
        Handle(InheritedEvent()), Handle(InheritedEvent()), Handle(InheritedEvent())};
};

const OwnerIdentity kOwner{"10000000-0000-0000-0000-000000000011", "10000000-0000-0000-0000-000000000012",
    "10000000-0000-0000-0000-000000000013", "10000000-0000-0000-0000-000000000014"};

NativeControlResult WaitForBreakpoint(NativeDebugOwner& owner, NativeBreakpointState expected) {
    const auto deadline = GetTickCount64() + kDeadlineMs;
    NativeControlResult result;
    do {
        result = owner.Query();
        if (result.breakpoint && (result.breakpoint->state == expected ||
            result.breakpoint->state == NativeBreakpointState::Rejected ||
            result.breakpoint->state == NativeBreakpointState::RecoveryRequired)) { break; }
        Sleep(1);
    } while (GetTickCount64() < deadline);
    if (!result.breakpoint || result.breakpoint->state != expected) {
        std::fprintf(stderr, "breakpoint-stage=%s binding=%s error=%u status=%d address=0x%llx base=0x%llx rva=0x%x\n",
            result.stage, result.breakpoint ? result.breakpoint->stage : "none", result.win32Error,
            static_cast<int>(result.status),
            result.breakpoint ? static_cast<unsigned long long>(result.breakpoint->address) : 0ULL,
            result.breakpoint ? static_cast<unsigned long long>(result.breakpoint->moduleBase) : 0ULL,
            result.breakpoint ? result.breakpoint->rva : 0U);
    }
    Require(result.breakpoint && result.breakpoint->state == expected, "observed-exact-breakpoint-state");
    return result;
}

NativeControlResult WaitForStep(NativeDebugOwner& owner, std::string_view requestId) {
    const auto deadline = GetTickCount64() + kDeadlineMs;
    NativeControlResult result;
    do {
        result = owner.QueryStep(requestId);
        if (result.step && result.step->state != NativeStepState::Running) { break; }
        Sleep(1);
    } while (GetTickCount64() < deadline);
    if (!result.step || result.step->state == NativeStepState::Running) {
        std::fprintf(stderr, "step-request=%s stage=%s error=%u\n", std::string(requestId).c_str(),
            result.stage, result.win32Error);
    }
    Require(result.step && result.step->state != NativeStepState::Running, "step-left-the-running-state");
    return result;
}

const NativeFrozenThread& OriginThread(const NativeControlResult& stop) {
    Require(stop.pending && stop.pending->tid != 0, "stop-has-an-origin-thread");
    for (const auto& thread : stop.frozenThreads) {
        if (thread.tid == stop.pending->tid) { return thread; }
    }
    std::fprintf(stderr, "origin-tid=%u not-in-frozen-set\n", stop.pending->tid);
    throw std::runtime_error("origin-thread-missing");
}

ReleaseRequest ToRelease(const OwnerIdentity& owner, const NativeControlResult& stop, std::string id) {
    Require(stop.group && stop.responsibility, "stop-has-group-and-responsibility");
    return {owner, stop.group->groupId, stop.responsibility->stopId, stop.responsibility->event, std::move(id),
        stop.group->stateRevision};
}

// One cooperative child plus one production owner bound to it.
class StepSession {
public:
    StepSession(const wchar_t* executable, unsigned flags, std::string requestId)
        : fixture_(executable, flags), owner_(kOwner) {
        wchar_t module[MAX_PATH]{};
        const auto length = GetModuleFileNameW(nullptr, module, MAX_PATH);
        Require(length && length < MAX_PATH, "fixture-full-module-path");
        modulePath_ = module;
        request_ = {{std::move(requestId), fixture_.pid, fixture_.creationTime, true,
            NativeTargetDisposition::ResumeAndDetach}, modulePath_, std::nullopt, {}, 0};
    }

    NativeControlResult Arm(std::uint32_t rva) {
        request_.rva = rva;
        const auto accepted = owner_.ArmBreakpoint(request_);
        Require(accepted.status == NativeControlStatus::Accepted && accepted.breakpoint,
            "breakpoint-attach-accepted");
        armed_ = WaitForBreakpoint(owner_, NativeBreakpointState::Armed);
        Require(armed_.breakpoint->address == armed_.breakpoint->moduleBase + rva, "armed-site-rva");
        std::fprintf(stderr, "ARM_SITE rva=0x%x address=0x%llx base=0x%llx enrolled=%zu\n", rva,
            static_cast<unsigned long long>(armed_.breakpoint->address),
            static_cast<unsigned long long>(armed_.breakpoint->moduleBase), armed_.breakpoint->enrolledThreads);
        fixture_.DumpThreads("armed");
        Require(armed_.breakpoint->enrolledThreads >= 2, "existing-threads-enrolled");
        return armed_;
    }

    NativeControlResult WaitHeld() {
        fixture_.Signal(kGo);
        const auto held = WaitForBreakpoint(owner_, NativeBreakpointState::Held);
        Require(held.breakpointHit && held.breakpointHit->address == armed_.breakpoint->address,
            "first-stop-is-a-real-breakpoint-hit");
        Require(held.pending && held.pending->exceptionCode == EXCEPTION_SINGLE_STEP && held.responsibility,
            "first-stop-holds-the-exact-native-event");
        Require(held.group && held.group->origin && held.group->state == GroupState::HeldComplete,
            "first-stop-has-a-frozen-group");
        return held;
    }

    NativeStepRequest MakeStep(const NativeControlResult& stop, std::string id, NativeStepMode mode) const {
        const auto& origin = OriginThread(stop);
        NativeStepRequest request{ToRelease(kOwner, stop, std::move(id)), origin.identity, origin.tid,
            origin.creationTime, mode};
        return request;
    }

    NativeControlResult Step(const NativeStepRequest& request) {
        auto result = owner_.Step(request);
        if (result.status == NativeControlStatus::Rejected) {
            std::fprintf(stderr, "STEP_REJECTED id=%s stage=%s error=%u ledger=%d\n",
                request.release.requestId.c_str(), result.stage, result.win32Error,
                static_cast<int>(result.ledgerResult));
        }
        return result;
    }

    ChildFixture& fixture() { return fixture_; }
    NativeDebugOwner& owner() { return owner_; }
    const NativeControlResult& armed() const { return armed_; }

    // The peer thread must be scheduled before any debugger work begins. This
    // separates a fixture defect from a native owner defect.
    bool PeerScheduledBeforeDebugging() {
        ResetEvent(fixture_.Event(kPeerAlive));
        return fixture_.Wait(kPeerAlive, 5000);
    }

private:
    ChildFixture fixture_;
    NativeDebugOwner owner_;
    NativeBreakpointRequest request_;
    std::wstring modulePath_;
    NativeControlResult armed_;
};

// Release the current stop and let the fixture run to its end.
void ReleaseAndFinish(StepSession& session, const NativeControlResult& stop, const std::string& id) {
    const auto released = session.owner().Continue(ToRelease(kOwner, stop, id));
    Require(released.release && released.release->receipt &&
        released.release->receipt->result == ReleaseResult::Continued, "released-the-held-native-event");
}

// The peer thread proves that the step's suspend debt on existing threads was
// released: a pre-existing peer answers a pulse only when it can run again.
void RequireFixtureDone(StepSession& session, const char* check) {
    const auto finished = session.fixture().Wait(kFixtureDone, kDeadlineMs);
    if (!finished) {
        std::fprintf(stderr, "FIXTURE_STATE alive=%u exitCode=%lu\n", session.fixture().Alive() ? 1U : 0U,
            session.fixture().ExitCode());
    }
    Require(finished, check);
}

void RequirePeerResumed(StepSession& session) {
    // A scheduled peer republishes its liveness on every bounded wait. A peer
    // still frozen by an unreleased suspend debt never republishes.
    ResetEvent(session.fixture().Event(kPeerAlive));
    Require(session.fixture().Wait(kPeerAlive, 5000), "existing-peer-thread-scheduled-after-step");
    session.fixture().Signal(kPeerPulse);
    Require(session.fixture().Wait(kPeerAck, kDeadlineMs), "existing-peer-thread-resumed-after-step");
}
// Control: the same child runs the same MASM sequence with no debugger at
// all. Any failure here belongs to the fixture, not to the native owner.
void TestFixtureAlone(const wchar_t* executable) {
    ChildFixture fixture(executable, 0);
    fixture.DumpThreads("alone-before");
    fixture.Signal(kGo);
    Require(fixture.Wait(kFixtureDone, kDeadlineMs), "undebugged-fixture-ran-to-completion");
    fixture.Signal(kExit);
    const auto deadline = GetTickCount64() + kDeadlineMs;
    while (fixture.Alive() && GetTickCount64() < deadline) { Sleep(5); }
    Require(!fixture.Alive(), "undebugged-fixture-exited");
    Require(fixture.ExitCode() == 0, "undebugged-fixture-exited-with-zero");
}

void TestIntoNop(const wchar_t* executable) {
    StepSession session(executable, 0, "native-step-into-nop");
    session.Arm(RvaOf(&FixtureStepNop));
    const auto held = session.WaitHeld();
    const auto base = session.armed().breakpoint->moduleBase;
    const auto step = session.MakeStep(held, "continue/1", NativeStepMode::Into);
    const auto started = session.Step(step);
    Require(started.status != NativeControlStatus::Rejected && started.release && started.release->receipt &&
        started.release->receipt->result == ReleaseResult::Continued, "into-step-started-and-released");
    const auto done = WaitForStep(session.owner(), "continue/1");
    Require(done.step->state == NativeStepState::Completed, "into-step-completed");
    Require(done.step->observedIp && *done.step->observedIp == base + RvaOf(&FixtureStepNop) + 1,
        "into-step-stopped-at-the-next-real-instruction");
    Require(done.step->observedSp && *done.step->observedSp == done.step->startSp, "into-step-kept-the-stack");
    Require(done.step->stopGroupId && *done.step->stopGroupId != held.group->groupId, "step-created-a-new-group");
    const auto stop = session.owner().Query(*done.step->stopGroupId);
    Require(stop.status == NativeControlStatus::Held && stop.breakpointHit == std::nullopt,
        "new-step-stop-has-no-breakpoint-hit");
    Require(stop.stage == std::string_view("native-step-stop-held"), "new-step-stop-stage");
    Require(stop.group && stop.group->groupId == *done.step->stopGroupId &&
        stop.group->membershipRevision == held.group->membershipRevision + 1, "new-group-has-a-new-revision");
    Require(session.owner().Query(held.group->groupId).group != std::nullopt, "old-group-stays-queryable");
    ReleaseAndFinish(session, stop, "continue/2");
    RequireFixtureDone(session, "fixture-ran-to-completion");
    RequirePeerResumed(session);
}

void TestIntoCall(const wchar_t* executable) {
    StepSession session(executable, 0, "native-step-into-call");
    session.Arm(RvaOf(&FixtureStepCall));
    const auto held = session.WaitHeld();
    const auto base = session.armed().breakpoint->moduleBase;
    const auto step = session.MakeStep(held, "continue/1", NativeStepMode::Into);
    Require(session.Step(step).status != NativeControlStatus::Rejected, "call-into-step-accepted");
    const auto done = WaitForStep(session.owner(), "continue/1");
    Require(done.step->state == NativeStepState::Completed, "call-into-step-completed");
    Require(done.step->observedIp && *done.step->observedIp == base + RvaOf(&FixtureStepCalleeEntry),
        "call-into-stopped-at-the-real-callee-entry");
    Require(done.step->observedSp && *done.step->observedSp == done.step->startSp - 8, "call-into-pushed-one-return-slot");
    const auto stop = session.owner().Query(*done.step->stopGroupId);
    Require(stop.breakpointHit == std::nullopt, "call-into-stop-has-no-breakpoint-hit");
    ReleaseAndFinish(session, stop, "continue/2");
    RequireFixtureDone(session, "call-into-fixture-completed");
}

void TestOverCall(const wchar_t* executable) {
    StepSession session(executable, 0, "native-step-over-call");
    session.Arm(RvaOf(&FixtureStepCall));
    const auto held = session.WaitHeld();
    const auto base = session.armed().breakpoint->moduleBase;
    const auto step = session.MakeStep(held, "continue/1", NativeStepMode::OverCall);
    Require(session.Step(step).status != NativeControlStatus::Rejected, "over-call-step-accepted");
    const auto done = WaitForStep(session.owner(), "continue/1");
    Require(done.step->state == NativeStepState::Completed, "over-call-step-completed");
    Require(done.step->observedIp && *done.step->observedIp == base + RvaOf(&FixtureStepAfterCall),
        "over-call-stopped-at-the-real-return-address");
    Require(done.step->observedSp && *done.step->observedSp == done.step->startSp, "over-call-restored-the-caller-stack");
    const auto stop = session.owner().Query(*done.step->stopGroupId);
    Require(stop.breakpointHit == std::nullopt, "over-call-stop-has-no-breakpoint-hit");
    ReleaseAndFinish(session, stop, "continue/2");
    RequireFixtureDone(session, "over-call-fixture-completed");
}

void TestOutFromEntry(const wchar_t* executable) {
    StepSession session(executable, 0, "native-step-out-entry");
    session.Arm(RvaOf(&FixtureStepCall));
    const auto held = session.WaitHeld();
    const auto base = session.armed().breakpoint->moduleBase;
    Require(session.Step(session.MakeStep(held, "continue/1", NativeStepMode::Into)).status !=
        NativeControlStatus::Rejected, "entry-into-step-accepted");
    const auto entered = WaitForStep(session.owner(), "continue/1");
    Require(entered.step->state == NativeStepState::Completed, "entry-into-step-completed");
    const auto entryStop = session.owner().Query(*entered.step->stopGroupId);
    const auto out = session.MakeStep(entryStop, "continue/2", NativeStepMode::Out);
    Require(session.Step(out).status != NativeControlStatus::Rejected, "out-from-entry-accepted");
    const auto done = WaitForStep(session.owner(), "continue/2");
    Require(done.step->state == NativeStepState::Completed, "out-from-entry-completed");
    Require(done.step->observedIp && *done.step->observedIp == base + RvaOf(&FixtureStepAfterCall),
        "out-from-entry-returned-to-the-real-caller");
    Require(done.step->observedSp && *done.step->observedSp == entered.step->observedSp.value_or(0) + 8,
        "out-from-entry-popped-the-real-return-slot");
    const auto stop = session.owner().Query(*done.step->stopGroupId);
    Require(stop.breakpointHit == std::nullopt, "out-stop-has-no-breakpoint-hit");
    ReleaseAndFinish(session, stop, "continue/3");
    RequireFixtureDone(session, "out-from-entry-fixture-completed");
}

void TestOutAtReturn(const wchar_t* executable) {
    StepSession session(executable, 0, "native-step-out-return");
    session.Arm(RvaOf(&FixtureStepRet));
    const auto held = session.WaitHeld();
    const auto base = session.armed().breakpoint->moduleBase;
    const auto step = session.MakeStep(held, "continue/1", NativeStepMode::Out);
    Require(session.Step(step).status != NativeControlStatus::Rejected, "out-at-return-accepted");
    const auto done = WaitForStep(session.owner(), "continue/1");
    Require(done.step->state == NativeStepState::Completed, "out-at-return-completed");
    Require(done.step->observedIp && *done.step->observedIp == base + RvaOf(&FixtureStepCallRunAfter),
        "out-at-return-used-the-real-stack-return-address");
    Require(done.step->observedSp && *done.step->observedSp == done.step->startSp + 8,
        "out-at-return-popped-the-real-stack");
    const auto stop = session.owner().Query(*done.step->stopGroupId);
    Require(stop.breakpointHit == std::nullopt, "out-at-return-stop-has-no-breakpoint-hit");
    ReleaseAndFinish(session, stop, "continue/2");
    RequireFixtureDone(session, "out-at-return-fixture-completed");
}

void TestAuthorizations(const wchar_t* executable) {
    StepSession session(executable, 0, "native-step-authorization");
    session.Arm(RvaOf(&FixtureStepNop));
    const auto held = session.WaitHeld();
    const auto valid = session.MakeStep(held, "continue/1", NativeStepMode::Into);

    auto wrong = valid;
    wrong.thread.threadId = "10000000-0000-0000-0000-0000000000ff";
    Require(session.Step(wrong).ledgerResult == LedgerResult::InvalidEvidence, "wrong-thread-identity-rejected");

    wrong = valid;
    wrong.tid = wrong.tid + 1000;
    Require(session.Step(wrong).ledgerResult == LedgerResult::InvalidEvidence, "wrong-thread-id-rejected");

    wrong = valid;
    ++wrong.threadCreationTime;
    Require(session.Step(wrong).ledgerResult == LedgerResult::IdentityMismatch, "wrong-thread-creation-time-rejected");

    wrong = valid;
    wrong.release.owner.epoch = "20000000-0000-0000-0000-000000000013";
    Require(session.Step(wrong).ledgerResult == LedgerResult::InvalidEvidence, "wrong-owner-rejected");

    wrong = valid;
    --wrong.release.expectedStateRevision;
    Require(session.Step(wrong).ledgerResult == LedgerResult::InvalidEvidence, "stale-revision-rejected");

    wrong = valid;
    wrong.release.groupId = "10000000-0000-0000-0000-0000000000ee";
    Require(session.Step(wrong).ledgerResult == LedgerResult::InvalidEvidence, "unknown-group-rejected");

    wrong = valid;
    wrong.release.requestId = "step-1";
    Require(session.Step(wrong).ledgerResult == LedgerResult::InvalidEvidence, "unsequenced-release-id-rejected");

    wrong = valid;
    wrong.mode = static_cast<NativeStepMode>(99);
    Require(session.Step(wrong).ledgerResult == LedgerResult::InvalidEvidence, "unknown-step-mode-rejected");

    wrong = valid;
    wrong.release.event.serial = wrong.release.event.serial + 1;
    Require(session.Step(wrong).ledgerResult == LedgerResult::InvalidEvidence, "wrong-native-event-rejected");

    Require(session.owner().Query().pending && session.owner().Query().pending->event == held.pending->event,
        "rejected-steps-keep-the-held-native-event");

    const auto started = session.Step(valid);
    Require(started.status != NativeControlStatus::Rejected, "authorized-step-accepted");
    const auto duplicate = session.Step(valid);
    Require(duplicate.ledgerResult == LedgerResult::Duplicate && duplicate.step, "identical-step-replay-is-a-duplicate");
    auto conflict = valid;
    conflict.mode = NativeStepMode::OverCall;
    Require(session.Step(conflict).ledgerResult == LedgerResult::Conflict, "same-step-id-with-other-body-conflicts");
    const auto done = WaitForStep(session.owner(), "continue/1");
    Require(done.step->state == NativeStepState::Completed, "authorized-step-completed");
    const auto stop = session.owner().Query(*done.step->stopGroupId);
    ReleaseAndFinish(session, stop, "continue/2");
    RequireFixtureDone(session, "authorization-fixture-completed");
}

void TestUnknownInstruction(const wchar_t* executable) {
    StepSession session(executable, 0, "native-step-unknown-instruction");
    session.Arm(RvaOf(&FixtureStepUnknown));
    const auto held = session.WaitHeld();
    const auto step = session.MakeStep(held, "continue/1", NativeStepMode::Into);
    const auto rejected = session.Step(step);
    Require(rejected.status == NativeControlStatus::Rejected && rejected.stage == std::string_view("step-instruction-unsupported"),
        "unknown-instruction-rejected");
    Require(session.owner().Query().pending && session.owner().Query().pending->event == held.pending->event,
        "rejected-instruction-keeps-the-held-event");
    ReleaseAndFinish(session, held, "continue/2");
    RequireFixtureDone(session, "unknown-instruction-fixture-completed");
}

void TestUnknownFrame(const wchar_t* executable) {
    StepSession session(executable, 0, "native-step-unknown-frame");
    session.Arm(RvaOf(&FixtureStepNop));
    const auto held = session.WaitHeld();
    Require(session.Step(session.MakeStep(held, "continue/1", NativeStepMode::Into)).status !=
        NativeControlStatus::Rejected, "frame-probe-step-accepted");
    const auto entered = WaitForStep(session.owner(), "continue/1");
    Require(entered.step->state == NativeStepState::Completed, "frame-probe-step-completed");
    const auto entryStop = session.owner().Query(*entered.step->stopGroupId);
    const auto rejected = session.Step(session.MakeStep(entryStop, "continue/2", NativeStepMode::Out));
    Require(rejected.status == NativeControlStatus::Rejected && rejected.stage == std::string_view("step-out-frame-unproven"),
        "unproven-frame-out-rejected");
    Require(session.owner().Query(*entered.step->stopGroupId).pending.has_value(), "rejected-out-keeps-the-step-stop");
    ReleaseAndFinish(session, entryStop, "continue/3");
    RequireFixtureDone(session, "unknown-frame-fixture-completed");
}

void TestEarlyBreakpointHit(const wchar_t* executable) {
    StepSession session(executable, kFlagRecurse, "native-step-early-breakpoint");
    session.Arm(RvaOf(&FixtureStepCall));
    const auto held = session.WaitHeld();
    const auto step = session.MakeStep(held, "continue/1", NativeStepMode::OverCall);
    Require(session.Step(step).status != NativeControlStatus::Rejected, "early-breakpoint-step-accepted");
    const auto done = WaitForStep(session.owner(), "continue/1");
    Require(done.step->state == NativeStepState::Interrupted, "early-breakpoint-interrupted-the-step");
    Require(done.step->stopGroupId.has_value(), "early-breakpoint-bound-a-stop-group");
    const auto stop = session.owner().Query(*done.step->stopGroupId);
    std::fprintf(stderr, "EARLY_STOP group=%s stage=%s status=%d hit=%u origin=%u pendingCode=%u pendingTid=%u\n",
        done.step->stopGroupId->c_str(), stop.stage, static_cast<int>(stop.status),
        stop.breakpointHit.has_value() ? 1U : 0U, stop.group && stop.group->origin ? 1U : 0U,
        stop.pending && stop.pending->exceptionCode ? *stop.pending->exceptionCode : 0U,
        stop.pending ? stop.pending->tid : 0U);
    session.fixture().DumpThreads("early-stop");
    Require(stop.breakpointHit && stop.breakpointHit->address == session.armed().breakpoint->address,
        "early-breakpoint-keeps-the-breakpoint-hit");
    Require(stop.stage == std::string_view("execution-breakpoint-held"), "early-breakpoint-stage");
    ReleaseAndFinish(session, stop, "continue/2");
    RequireFixtureDone(session, "early-breakpoint-fixture-completed");
}

void TestApplicationException(const wchar_t* executable) {
    StepSession session(executable, kFlagRaise, "native-step-application-exception");
    session.Arm(RvaOf(&FixtureStepCall));
    const auto held = session.WaitHeld();
    const auto step = session.MakeStep(held, "continue/1", NativeStepMode::OverCall);
    Require(session.Step(step).status != NativeControlStatus::Rejected, "exception-step-accepted");
    const auto done = WaitForStep(session.owner(), "continue/1");
    Require(done.step->state == NativeStepState::Interrupted, "application-exception-interrupted-the-step");
    const auto stop = session.owner().Query(*done.step->stopGroupId);
    Require(stop.pending && stop.pending->exceptionCode == kChildException && stop.pending->exceptionFirstChance,
        "application-exception-is-held-as-the-exact-native-event");
    ReleaseAndFinish(session, stop, "continue/2");
    Require(session.fixture().Wait(kExceptionHandled, kDeadlineMs), "application-exception-reached-the-target-handler");
    RequireFixtureDone(session, "application-exception-fixture-completed");
}

void TestCancel(const wchar_t* executable) {
    StepSession session(executable, kFlagBlock, "native-step-cancel");
    session.Arm(RvaOf(&FixtureStepCall));
    const auto held = session.WaitHeld();
    const auto step = session.MakeStep(held, "continue/1", NativeStepMode::OverCall);
    Require(session.Step(step).status != NativeControlStatus::Rejected, "cancel-step-accepted");
    const auto cancelled = session.owner().CancelStep("continue/1");
    Require(cancelled.step.has_value(), "cancel-returns-the-step-receipt");
    const auto done = WaitForStep(session.owner(), "continue/1");
    Require(done.step->state == NativeStepState::Cancelled, "cancelled-step-reports-the-cancelled-state");
    const auto stop = session.owner().Query(*done.step->stopGroupId);
    Require(stop.pending.has_value(), "cancelled-step-holds-the-interrupt-event");
    ReleaseAndFinish(session, stop, "continue/2");
    session.fixture().Signal(kReleaseCallee);
    RequireFixtureDone(session, "cancelled-step-target-continued-and-completed");
    Require(session.fixture().Alive(), "cancelled-step-left-the-target-alive");
}

void TestCloseWhileRunning(const wchar_t* executable) {
    StepSession session(executable, kFlagBlock, "native-step-close-running");
    session.Arm(RvaOf(&FixtureStepCall));
    const auto held = session.WaitHeld();
    const auto step = session.MakeStep(held, "continue/1", NativeStepMode::OverCall);
    Require(session.Step(step).status != NativeControlStatus::Rejected, "close-running-step-accepted");
    const auto closed = session.owner().Close();
    Require(closed.status == NativeControlStatus::Closed || closed.status == NativeControlStatus::ClosePending,
        "close-while-running-accepted");
    const auto deadline = GetTickCount64() + kDeadlineMs;
    NativeControlResult state;
    do {
        state = session.owner().Query();
        if (state.clean && !state.attached) { break; }
        Sleep(5);
    } while (GetTickCount64() < deadline);
    std::fprintf(stderr, "CLOSE_STATE status=%d stage=%s clean=%u attached=%u pending=%u resp=%u bp=%s\n",
        static_cast<int>(state.status), state.stage, state.clean ? 1U : 0U, state.attached ? 1U : 0U,
        state.pending.has_value() ? 1U : 0U, state.responsibility.has_value() ? 1U : 0U,
        state.breakpoint ? state.breakpoint->stage : "none");
    Require(state.clean && !state.attached, "close-while-running-released-everything");
    session.fixture().Signal(kReleaseCallee);
    RequireFixtureDone(session, "close-while-running-target-continued");
    Require(session.fixture().Alive(), "close-while-running-left-the-target-alive");
}

void TestThreadExit(const wchar_t* executable) {
    StepSession session(executable, kFlagExitThread, "native-step-thread-exit");
    Require(session.PeerScheduledBeforeDebugging(), "peer-thread-runs-before-any-debugger-work");
    session.Arm(RvaOf(&FixtureStepCall));
    const auto held = session.WaitHeld();
    const auto step = session.MakeStep(held, "continue/1", NativeStepMode::OverCall);
    Require(session.Step(step).status != NativeControlStatus::Rejected, "thread-exit-step-accepted");
    const auto done = WaitForStep(session.owner(), "continue/1");
    Require(done.step->state == NativeStepState::Exited, "thread-exit-ends-the-step");
    const auto deadline = GetTickCount64() + kDeadlineMs;
    NativeControlResult state;
    do {
        state = session.owner().Query();
        if (!state.pending) { break; }
        Sleep(5);
    } while (GetTickCount64() < deadline);
    Require(!state.pending, "thread-exit-released-the-native-event");
    session.fixture().DumpThreads("thread-exit");
    const auto ticks = session.fixture().CountPeerTicks();
    std::fprintf(stderr, "PEER_TICKS total=%zu\n", ticks);
    RequirePeerResumed(session);
    session.fixture().Signal(kExit);
    Require(!session.fixture().Alive() || session.fixture().Wait(kFixtureDone, 200), "thread-exit-target-state-known");
}

void TestProcessExit(const wchar_t* executable) {
    StepSession session(executable, kFlagExitProcess, "native-step-process-exit");
    session.Arm(RvaOf(&FixtureStepCall));
    const auto held = session.WaitHeld();
    const auto step = session.MakeStep(held, "continue/1", NativeStepMode::OverCall);
    Require(session.Step(step).status != NativeControlStatus::Rejected, "process-exit-step-accepted");
    const auto done = WaitForStep(session.owner(), "continue/1");
    Require(done.step->state == NativeStepState::Exited, "process-exit-ends-the-step");
    const auto deadline = GetTickCount64() + kDeadlineMs;
    NativeControlResult state;
    do {
        state = session.owner().Query();
        if (!state.attached && state.clean) { break; }
        Sleep(5);
    } while (GetTickCount64() < deadline);
    Require(!state.attached && state.clean, "process-exit-detached-the-owner");
    Require(!session.fixture().Alive(), "process-exit-ended-the-target");
}

void TestNewThreadRestoration(const wchar_t* executable) {
    StepSession session(executable, kFlagSpawn, "native-step-new-thread");
    session.Arm(RvaOf(&FixtureStepCall));
    const auto held = session.WaitHeld();
    const auto step = session.MakeStep(held, "continue/1", NativeStepMode::OverCall);
    Require(session.Step(step).status != NativeControlStatus::Rejected, "new-thread-step-accepted");
    const auto done = WaitForStep(session.owner(), "continue/1");
    Require(done.step->state == NativeStepState::Completed, "new-thread-step-completed");
    const auto stop = session.owner().Query(*done.step->stopGroupId);
    Require(stop.breakpointHit == std::nullopt, "new-thread-step-stop-has-no-breakpoint-hit");
    ReleaseAndFinish(session, stop, "continue/2");
    Require(session.fixture().Wait(kSpawnedRan, kDeadlineMs), "thread-created-during-the-step-ran-after-restore");
    RequireFixtureDone(session, "new-thread-fixture-completed");
    RequirePeerResumed(session);
}

const wchar_t* g_executable = nullptr;

struct ScenarioEntry {
    const char* name;
    const wchar_t* wide;
    void (*body)(const wchar_t*);
};

const ScenarioEntry kScenarios[] = {
    {"fixture-alone", L"fixture-alone", TestFixtureAlone},
    {"into-nop", L"into-nop", TestIntoNop},
    {"into-call", L"into-call", TestIntoCall},
    {"over-call", L"over-call", TestOverCall},
    {"out-from-entry", L"out-from-entry", TestOutFromEntry},
    {"out-at-return", L"out-at-return", TestOutAtReturn},
    {"authorizations", L"authorizations", TestAuthorizations},
    {"unknown-instruction", L"unknown-instruction", TestUnknownInstruction},
    {"unknown-frame", L"unknown-frame", TestUnknownFrame},
    {"early-breakpoint", L"early-breakpoint", TestEarlyBreakpointHit},
    {"application-exception", L"application-exception", TestApplicationException},
    {"cancel", L"cancel", TestCancel},
    {"close-while-running", L"close-while-running", TestCloseWhileRunning},
    {"thread-exit", L"thread-exit", TestThreadExit},
    {"process-exit", L"process-exit", TestProcessExit},
    {"new-thread-restoration", L"new-thread-restoration", TestNewThreadRestoration},
};

// 缩减批次的四个边界场景；其余旧场景只在 --suite full 下执行，函数与断言保持不变。
bool IsFocusedScenario(const wchar_t* name) {
    return std::wcscmp(name, L"thread-exit") == 0 || std::wcscmp(name, L"process-exit") == 0 ||
        std::wcscmp(name, L"close-while-running") == 0 ||
        std::wcscmp(name, L"new-thread-restoration") == 0;
}

void Run(const char* name, void (*body)(const wchar_t*)) {
    try {
        body(g_executable);
    } catch (const std::exception& error) {
        // 场景异常必须计为失败，不能只打印后继续报 PASS。
        std::fprintf(stderr, "SCENARIO_ERROR scenario=%s detail=%s\n", name, error.what());
        ++failures;
    }
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == kEventCount + 4 && std::wcscmp(argv[1], L"--child") == 0) {
        return ChildMain(std::wcstoul(argv[2], nullptr, 10), argv + 3);
    }
    bool focused = true;
    std::vector<const wchar_t*> requested;
    int index = 1;
    while (index < argc) {
        if (std::wcscmp(argv[index], L"--diag-dir") == 0 && index + 1 < argc) {
            g_diagDir = argv[index + 1];
            index += 2;
            continue;
        }
        if (std::wcscmp(argv[index], L"--suite") == 0 && index + 1 < argc) {
            if (std::wcscmp(argv[index + 1], L"full") == 0) {
                focused = false;
            } else if (std::wcscmp(argv[index + 1], L"focused") != 0) {
                return 2;
            }
            index += 2;
            continue;
        }
        if (std::wcscmp(argv[index], L"--scenario") == 0 && index + 1 < argc) {
            requested.push_back(argv[index + 1]);
            index += 2;
            continue;
        }
        break;
    }
    if (index != argc) { return 2; }
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    g_executable = argv[0];
    std::string executed;
    for (const auto& entry : kScenarios) {
        bool selected = false;
        if (requested.empty()) {
            selected = !focused || IsFocusedScenario(entry.wide);
        } else {
            for (const auto* wanted : requested) {
                if (std::wcscmp(wanted, entry.wide) == 0) { selected = true; break; }
            }
        }
        if (!selected) { continue; }
        Run(entry.name, entry.body);
        if (!executed.empty()) { executed += ','; }
        executed += entry.name;
    }
    // 未知场景名与零实际场景都算失败，避免出现空跑即 PASS。
    for (const auto* wanted : requested) {
        bool known = false;
        for (const auto& entry : kScenarios) {
            if (std::wcscmp(wanted, entry.wide) == 0) { known = true; break; }
        }
        if (!known) {
            std::fprintf(stderr, "SCENARIO_ERROR scenario=%ls detail=unknown scenario\n", wanted);
            ++failures;
        }
    }
    if (executed.empty()) {
        std::fprintf(stderr, "SCENARIO_ERROR scenario=<none> detail=no scenario executed\n");
        ++failures;
    }
    std::printf("SCENARIOS=%s\n", executed.c_str());
    std::printf("RESULT=%s checks=%u failures=%u\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
