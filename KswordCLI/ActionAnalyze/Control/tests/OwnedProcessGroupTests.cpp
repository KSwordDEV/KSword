// 自有良性心跳目标的 OwnedProcessGroup 原生验收。
// 每个目标是当前宿主直接创建的 AMD64 子进程，带两个真实心跳线程；
// 全部停止/恢复结论来自 NativeDebugOwner 的真实原生停点，不镜像组层实现。
#include "../OwnedProcessGroup.h"
#include "../ProcessGroupMemorySnapshot.h"

#include <Windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace ks::cli::action_analyze::control;
using namespace ks::cli::action_analyze::memory;

namespace {

constexpr DWORD kDeadlineMs = 5000;
constexpr DWORD kFrozenMs = 45;
unsigned checks = 0;

void Require(bool condition, const char* check, const char* detail = nullptr) {
    if (!condition) {
        std::fprintf(stderr, "FAIL %s%s%s win32=%lu\n", check, detail ? " [" : "", detail ? detail : "",
            GetLastError());
        std::exit(1);
    }
    ++checks;
}

class Handle {
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() { if (value_) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE Get() const { return value_; }
    void Reset(HANDLE value) {
        if (value_) CloseHandle(value_);
        value_ = value;
    }
private:
    HANDLE value_ = nullptr;
};

std::uint64_t FileTimeValue(const FILETIME& time) {
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

DWORD WINAPI HeartbeatThread(void* context) {
    auto* events = static_cast<HANDLE*>(context); // stop(manual), pulse(auto), reply(auto)
    const HANDLE inputs[]{events[0], events[1]};
    for (;;) {
        const auto signaled = WaitForMultipleObjects(2, inputs, FALSE, INFINITE);
        if (signaled == WAIT_OBJECT_0) return 0;
        if (signaled != WAIT_OBJECT_0 + 1) return 3;
        if (!SetEvent(events[2])) return 4;
    }
}

// 子进程：两个线程各自响应心跳脉冲；stop 为共享的手动重置事件。
int HeartbeatChildMain(wchar_t** args) {
    HANDLE handles[6]{};
    for (unsigned i = 0; i < 6; ++i) {
        handles[i] = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(args[i], nullptr, 10)));
    }
    HANDLE first[]{handles[5], handles[1], handles[2]};
    HANDLE second[]{handles[5], handles[3], handles[4]};
    const Handle thread0(CreateThread(nullptr, 0, HeartbeatThread, first, 0, nullptr));
    const Handle thread1(CreateThread(nullptr, 0, HeartbeatThread, second, 0, nullptr));
    if (!thread0.Get() || !thread1.Get() || !SetEvent(handles[0])) return 2;
    WaitForSingleObject(handles[5], INFINITE);
    const HANDLE threads[]{thread0.Get(), thread1.Get()};
    const auto both = WaitForMultipleObjects(2, threads, TRUE, kDeadlineMs);
    return both == WAIT_OBJECT_0 ? 0 : 3;
}

class HeartbeatFixture {
public:
    explicit HeartbeatFixture(wchar_t* executable) {
        job_.Reset(CreateJobObjectW(nullptr, nullptr));
        Require(job_.Get() != nullptr, "fixture-private-job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        Require(SetInformationJobObject(job_.Get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE,
            "fixture-job-kill-on-close");

        SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
        ready_.Reset(CreateEventW(&attributes, FALSE, FALSE, nullptr));
        pulse0_.Reset(CreateEventW(&attributes, FALSE, FALSE, nullptr));
        reply0_.Reset(CreateEventW(&attributes, FALSE, FALSE, nullptr));
        pulse1_.Reset(CreateEventW(&attributes, FALSE, FALSE, nullptr));
        reply1_.Reset(CreateEventW(&attributes, FALSE, FALSE, nullptr));
        stop_.Reset(CreateEventW(&attributes, TRUE, FALSE, nullptr));
        Require(ready_.Get() && pulse0_.Get() && reply0_.Get() && pulse1_.Get() && reply1_.Get() && stop_.Get(),
            "fixture-heartbeat-events");

        HANDLE inherited[]{ready_.Get(), pulse0_.Get(), reply0_.Get(), pulse1_.Get(), reply1_.Get(), stop_.Get()};
        std::wstring command = L"\"" + std::wstring(executable) + L"\" --heartbeat";
        for (auto handle : inherited) {
            command += L" " + std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
        }
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 2, 0, &bytes);
        Require(bytes != 0, "fixture-attribute-size");
        std::vector<std::uintptr_t> storage((bytes + sizeof(std::uintptr_t) - 1) / sizeof(std::uintptr_t));
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        Require(InitializeProcThreadAttributeList(startup.lpAttributeList, 2, 0, &bytes) != FALSE,
            "fixture-attribute-list");
        auto job = job_.Get();
        Require(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited, sizeof(inherited), nullptr, nullptr) != FALSE, "fixture-inherited-handle-list");
        Require(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
            &job, sizeof(job), nullptr, nullptr) != FALSE, "fixture-create-in-job");
        PROCESS_INFORMATION process{};
        const auto created = CreateProcessW(executable, command.data(), nullptr, nullptr, TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
            &startup.StartupInfo, &process);
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        Require(created != FALSE, "fixture-created");
        const Handle initialThread(process.hThread);
        process_.Reset(process.hProcess);
        pid = process.dwProcessId;
        BOOL inJob = FALSE;
        Require(IsProcessInJob(process_.Get(), job_.Get(), &inJob) && inJob, "fixture-confined-to-private-job");
        Require(ResumeThread(initialThread.Get()) == 1, "fixture-started");
        Require(WaitForSingleObject(ready_.Get(), kDeadlineMs) == WAIT_OBJECT_0, "fixture-two-threads-ready");
        FILETIME creation{}, exitTime{}, kernel{}, user{};
        Require(GetProcessTimes(process_.Get(), &creation, &exitTime, &kernel, &user) != FALSE,
            "fixture-creation-time");
        creationTime = FileTimeValue(creation);
        Require(Heartbeat(kDeadlineMs), "fixture-heartbeat-before-test");
    }

    ProcessGroupTarget Target() const { return ProcessGroupTarget{pid, creationTime}; }

    void ClearPulses() const {
        ResetEvent(pulse0_.Get());
        ResetEvent(pulse1_.Get());
    }

    bool Heartbeat(DWORD waitMs) const {
        ClearPulses();
        ResetEvent(reply0_.Get());
        ResetEvent(reply1_.Get());
        SetEvent(pulse0_.Get());
        SetEvent(pulse1_.Get());
        const auto first = WaitForSingleObject(reply0_.Get(), waitMs);
        const auto second = WaitForSingleObject(reply1_.Get(), waitMs);
        ClearPulses();
        return first == WAIT_OBJECT_0 && second == WAIT_OBJECT_0;
    }

    void ExpectFrozen(const char* check) const { Require(!Heartbeat(kFrozenMs), check); }
    void ExpectRunning(const char* check) const { Require(Heartbeat(kDeadlineMs), check); }

    void CheckAttached(bool expected) const {
        BOOL debugging = FALSE;
        Require(CheckRemoteDebuggerPresent(process_.Get(), &debugging) && (debugging != FALSE) == expected,
            "independent-attachment-readback");
    }

    bool Alive() const { return WaitForSingleObject(process_.Get(), 0) == WAIT_TIMEOUT; }

    void ExitNaturally() const {
        SetEvent(stop_.Get());
        Require(WaitForSingleObject(process_.Get(), kDeadlineMs) == WAIT_OBJECT_0, "fixture-natural-exit");
        DWORD code = 0;
        Require(GetExitCodeProcess(process_.Get(), &code) && code == 0, "fixture-natural-exit-code");
    }

    DWORD pid = 0;
    std::uint64_t creationTime = 0;

private:
    Handle job_;
    Handle process_;
    Handle ready_;
    Handle pulse0_;
    Handle reply0_;
    Handle pulse1_;
    Handle reply1_;
    Handle stop_;
};

// 自有内存目标：子进程在继承的共享节写入自身视图基址和已知字节，父进程只读验证同一物理内存。
int MemoryChild(const wchar_t* mappingArg, const wchar_t* readyArg, const wchar_t* stopArg) {
    const Handle mapping(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(mappingArg, nullptr, 10))));
    const Handle ready(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(readyArg, nullptr, 10))));
    const Handle stopHandle(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(stopArg, nullptr, 10))));
    void* view = MapViewOfFile(mapping.Get(), FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!view) return 2;
    auto* bytes = static_cast<unsigned char*>(view);
    const std::uint64_t base = reinterpret_cast<std::uintptr_t>(view);
    std::memcpy(bytes, &base, sizeof(base));
    for (unsigned i = 0; i < 64; ++i) bytes[8 + i] = static_cast<unsigned char>(0x5A + (i % 7));
    if (!SetEvent(ready.Get())) {
        UnmapViewOfFile(view);
        return 2;
    }
    WaitForSingleObject(stopHandle.Get(), INFINITE);
    UnmapViewOfFile(view);
    return 0;
}

class MemoryFixture {
public:
    explicit MemoryFixture(wchar_t* executable) {
        Require(job_.Get() != nullptr, "memory-fixture-private-job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        Require(SetInformationJobObject(job_.Get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE,
            "memory-fixture-job-kill-on-close");
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
        mapping_.Reset(CreateFileMappingW(INVALID_HANDLE_VALUE, &attributes, PAGE_READWRITE, 0, 4096, nullptr));
        Require(mapping_.Get() != nullptr, "memory-fixture-mapping");
        view_ = MapViewOfFile(mapping_.Get(), FILE_MAP_ALL_ACCESS, 0, 0, 4096);
        Require(view_ != nullptr, "memory-fixture-parent-view");
        ready_.Reset(CreateEventW(&attributes, FALSE, FALSE, nullptr));
        stop_.Reset(CreateEventW(&attributes, TRUE, FALSE, nullptr));
        Require(ready_.Get() && stop_.Get(), "memory-fixture-events");

        HANDLE inherited[]{mapping_.Get(), ready_.Get(), stop_.Get()};
        std::wstring command = L"\"" + std::wstring(executable) + L"\" --memory";
        for (auto handle : inherited) {
            command += L" " + std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
        }
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 2, 0, &bytes);
        Require(bytes != 0, "memory-fixture-attribute-size");
        std::vector<std::uintptr_t> storage((bytes + sizeof(std::uintptr_t) - 1) / sizeof(std::uintptr_t));
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        Require(InitializeProcThreadAttributeList(startup.lpAttributeList, 2, 0, &bytes) != FALSE,
            "memory-fixture-attribute-list");
        auto job = job_.Get();
        Require(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited, sizeof(inherited), nullptr, nullptr) != FALSE, "memory-fixture-handle-list");
        Require(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
            &job, sizeof(job), nullptr, nullptr) != FALSE, "memory-fixture-job");
        PROCESS_INFORMATION process{};
        const auto created = CreateProcessW(executable, command.data(), nullptr, nullptr, TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
            &startup.StartupInfo, &process);
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        Require(created != FALSE, "memory-fixture-created");
        const Handle initialThread(process.hThread);
        process_.Reset(process.hProcess);
        pid = process.dwProcessId;
        Require(ResumeThread(initialThread.Get()) == 1, "memory-fixture-started");
        Require(WaitForSingleObject(ready_.Get(), kDeadlineMs) == WAIT_OBJECT_0, "memory-fixture-known-bytes-ready");
        std::memcpy(&childBase_, view_, sizeof(childBase_));
        Require(childBase_ != 0, "memory-fixture-child-view-base");
        const auto* probe = static_cast<const unsigned char*>(view_) + 8;
        for (unsigned i = 0; i < 64; ++i) {
            Require(probe[i] == static_cast<unsigned char>(0x5A + (i % 7)), "memory-fixture-known-byte-pattern");
        }
        FILETIME creation{}, exitTime{}, kernel{}, user{};
        Require(GetProcessTimes(process_.Get(), &creation, &exitTime, &kernel, &user) != FALSE,
            "memory-fixture-creation-time");
        creationTime = FileTimeValue(creation);
    }

    ~MemoryFixture() { if (view_) UnmapViewOfFile(view_); }
    MemoryFixture(const MemoryFixture&) = delete;
    MemoryFixture& operator=(const MemoryFixture&) = delete;

    ProcessGroupTarget Target() const { return ProcessGroupTarget{pid, creationTime}; }
    ks::cli::action_analyze::memory::Range Range() const { return ks::cli::action_analyze::memory::Range{childBase_ + 8, 64}; }
    unsigned char Byte(unsigned index) const {
        return static_cast<const unsigned char*>(view_)[8 + index];
    }

    void CheckAttached(bool expected) const {
        BOOL debugging = FALSE;
        Require(CheckRemoteDebuggerPresent(process_.Get(), &debugging) && (debugging != FALSE) == expected,
            "memory-fixture-attachment-readback");
    }

    void Exit() const {
        Require(SetEvent(stop_.Get()) != FALSE, "memory-fixture-signal-stop");
        Require(WaitForSingleObject(process_.Get(), kDeadlineMs) == WAIT_OBJECT_0, "memory-fixture-exited");
        DWORD code = 0;
        Require(GetExitCodeProcess(process_.Get(), &code) && code == 0, "memory-fixture-exit-code");
    }

    DWORD pid = 0;
    std::uint64_t creationTime = 0;

private:
    Handle job_{CreateJobObjectW(nullptr, nullptr)};
    Handle process_;
    Handle mapping_;
    Handle ready_;
    Handle stop_;
    void* view_ = nullptr;
    std::uint64_t childBase_ = 0;
};

ks::cli::action_analyze::memory::Plan MakeMemoryPlan(const MemoryFixture& fixture, const std::string& sampleId) {
    ks::cli::action_analyze::memory::Plan plan;
    plan.sampleId = sampleId;
    plan.trackingEpoch = "memory-epoch-1";
    plan.target.machineId = "machine-1";
    plan.target.bootId = "boot-1";
    plan.target.processInstanceId = "instance-memory-1";
    plan.target.pid = fixture.pid;
    plan.target.creationFileTime100ns = fixture.creationTime;
    plan.range = fixture.Range();
    plan.rounds = 2;
    plan.intervalMs = 100;
    plan.authorizedOwnedProcess = true;
    return plan;
}

using Fixtures = std::vector<std::unique_ptr<HeartbeatFixture>>;

Fixtures MakeFixtures(wchar_t* executable, std::size_t count) {
    Fixtures result;
    for (std::size_t i = 0; i < count; ++i) {
        result.push_back(std::make_unique<HeartbeatFixture>(executable));
    }
    return result;
}

std::vector<ProcessGroupTarget> Targets(const Fixtures& fixtures) {
    std::vector<ProcessGroupTarget> result;
    for (const auto& fixture : fixtures) result.push_back(fixture->Target());
    return result;
}

// MSVC 的 std::span 不接受花括号初始化列表，显式构造连续容器再传入。
std::vector<ProcessGroupTarget> Vec(const ProcessGroupTarget& value) { return {value}; }
std::vector<ProcessGroupStop> Vec(const ProcessGroupStop& value) { return {value}; }
std::vector<ProcessGroupStop> Vec(const ProcessGroupStop& first, const ProcessGroupStop& second) {
    return {first, second};
}

template<class Predicate>
ProcessGroupResult WaitForGroup(OwnedProcessGroup& group, Predicate matches, const char* check) {
    const auto deadline = GetTickCount64() + kDeadlineMs;
    ProcessGroupResult result;
    do {
        result = group.Query();
        if (matches(result)) {
            Require(true, check);
            return result;
        }
        Sleep(1);
    } while (GetTickCount64() < deadline);
    std::fprintf(stderr, "group state=%d stage=%s error=%u\n", static_cast<int>(result.state), result.stage,
        result.win32Error);
    Require(matches(result), check);
    return result;
}

ProcessGroupResult HeldGroup(OwnedProcessGroup& group, const char* check) {
    return WaitForGroup(group, [](const auto& result) {
        return result.state == ProcessGroupState::HeldComplete || result.state == ProcessGroupState::HeldPartial ||
            result.state == ProcessGroupState::RecoveryRequired;
    }, check);
}

ProcessGroupStop StopOf(const ProcessGroupResult& result, std::size_t index, const char* check) {
    Require(index < result.members.size(), check);
    Require(result.members[index].stop.has_value(), check);
    return *result.members[index].stop;
}

bool Rejected(const ProcessGroupResult& result, LedgerResult ledger, const char* stage) {
    return result.ledgerResult == ledger && std::string(result.stage) == stage;
}

OwnerIdentity Identity(unsigned last) {
    const std::string tail = std::to_string(last);
    return OwnerIdentity{"10000000-0000-0000-0000-00000000000" + tail,
        "20000000-0000-0000-0000-00000000000" + tail,
        "30000000-0000-0000-0000-00000000000" + tail,
        "40000000-0000-0000-0000-00000000000" + tail};
}

// Configure 只固定实例：16 个真实进程上限、身份与授权门禁，全程不附加、不暂停。
void TestConfigure(wchar_t* executable) {
    const auto identity = Identity(1);
    {
        OwnedProcessGroup group(identity);
        Require(Rejected(group.Configure({}, true, NativeTargetDisposition::ResumeAndDetach),
            LedgerResult::InvalidEvidence, "process-group-explicit-instances-required"), "empty-configure-rejected");
        Require(group.Query().state == ProcessGroupState::Idle, "rejected-configure-leaves-idle");
    }
    auto fixtures = MakeFixtures(executable, 17);
    const auto targets = Targets(fixtures);
    {
        OwnedProcessGroup group(identity);
        Require(Rejected(group.Configure(targets, false, NativeTargetDisposition::ResumeAndDetach),
            LedgerResult::InvalidEvidence, "process-group-explicit-instances-required"), "unauthorized-configure-rejected");
        Require(Rejected(group.Configure(targets, true, NativeTargetDisposition::Unspecified),
            LedgerResult::InvalidEvidence, "process-group-explicit-instances-required"), "wrong-disposition-rejected");
    }
    auto sixteen = targets;
    sixteen.resize(16);
    {
        OwnedProcessGroup group(identity);
        auto wrong = sixteen;
        ++wrong[0].creationFileTime;
        Require(Rejected(group.Configure(wrong, true, NativeTargetDisposition::ResumeAndDetach),
            LedgerResult::IdentityMismatch, "process-group-pin-instance"), "wrong-creation-generation-rejected");
        auto duplicate = sixteen;
        duplicate[1] = duplicate[0];
        Require(Rejected(group.Configure(duplicate, true, NativeTargetDisposition::ResumeAndDetach),
            LedgerResult::Conflict, "process-group-duplicate-pid"), "duplicate-pid-rejected");
        auto zero = sixteen;
        zero[0].pid = 0;
        Require(Rejected(group.Configure(zero, true, NativeTargetDisposition::ResumeAndDetach),
            LedgerResult::IdentityMismatch, "process-group-pin-instance"), "zero-pid-rejected");
        auto self = sixteen;
        self[0].pid = GetCurrentProcessId();
        Require(Rejected(group.Configure(self, true, NativeTargetDisposition::ResumeAndDetach),
            LedgerResult::IdentityMismatch, "process-group-pin-instance"), "self-pid-rejected");
        Require(group.Query().state == ProcessGroupState::Idle, "failed-configure-publishes-no-partial-set");
    }
    {
        OwnedProcessGroup group(identity);
        auto seventeen = targets;
        Require(Rejected(group.Configure(seventeen, true, NativeTargetDisposition::ResumeAndDetach),
            LedgerResult::InvalidEvidence, "process-group-explicit-instances-required"), "seventeen-targets-rejected");
    }
    {
        OwnedProcessGroup group(identity);
        const auto configured = group.Configure(sixteen, true, NativeTargetDisposition::ResumeAndDetach);
        Require(configured.state == ProcessGroupState::Ready && configured.clean && configured.members.size() == 16 &&
            !configured.operation, "sixteen-real-instances-configured-without-side-effect");
        for (std::size_t i = 0; i < fixtures.size() && i < 16; ++i) {
            Require(configured.members[i].target == fixtures[i]->Target() && !configured.members[i].control &&
                !configured.members[i].stop, "configure-keeps-frozen-instance-without-native-claim");
            fixtures[i]->CheckAttached(false);
            fixtures[i]->ExpectRunning("configure-does-not-pause-heartbeat");
        }
        Require(Rejected(group.Configure(sixteen, true, NativeTargetDisposition::ResumeAndDetach),
            LedgerResult::Conflict, "process-group-already-configured"), "second-configure-rejected");
        Require(Rejected(group.Pause("group/1", targets), LedgerResult::InvalidTransition,
            "process-group-pause-unavailable"), "pause-beyond-configured-set-rejected");
        Require(group.Close().state == ProcessGroupState::Closed, "configure-only-close-cleans");
    }
}

// 全组/子集 Pause、单成员继续、旧令牌、128 票据滚动与 Recover 身份。
void TestGroupLifecycle(wchar_t* executable) {
    const auto identity = Identity(2);
    auto fixtures = MakeFixtures(executable, 3);
    OwnedProcessGroup group(identity);
    const auto configured = group.Configure(Targets(fixtures), true, NativeTargetDisposition::ResumeAndDetach);
    Require(configured.state == ProcessGroupState::Ready, "lifecycle-configured");
    Require(group.Query().state == ProcessGroupState::Ready && !group.Query().operation,
        "query-before-pause-introduces-no-operation");

    const auto paused = group.Pause("group/1", Targets(fixtures));
    Require(paused.operation && paused.operation->requestId == "group/1" &&
        paused.operation->action == ProcessGroupAction::Pause && paused.operation->outcomes.size() == 3,
        "pause-issues-group-ticket");
    const auto held = HeldGroup(group, "all-three-members-reach-real-native-hold");
    Require(held.state == ProcessGroupState::HeldComplete && held.members.size() == 3,
        "group-held-complete-requires-all-members");
    for (std::size_t i = 0; i < 3; ++i) {
        Require(held.members[i].control && held.members[i].control->group &&
            held.members[i].control->group->state == GroupState::HeldComplete &&
            held.members[i].stop && !held.members[i].clean, "member-actual-held-complete");
        fixtures[i]->CheckAttached(true);
        fixtures[i]->ExpectFrozen("held-member-heartbeat-stopped");
    }
    const auto repeatPause = group.Pause("group/1", Targets(fixtures));
    Require(repeatPause.ledgerResult == LedgerResult::Duplicate && repeatPause.operation &&
        repeatPause.operation->requestId == "group/1" && repeatPause.operation->outcomes.size() == 3,
        "duplicate-pause-replays-original-ticket");
    Require(repeatPause.state == ProcessGroupState::HeldComplete, "duplicate-pause-keeps-current-state-separate");
    for (const auto& fixture : fixtures) fixture->ExpectFrozen("duplicate-pause-takes-no-second-action");
    auto subset = Targets(fixtures);
    subset.resize(2);
    Require(Rejected(group.Pause("group/1", subset), LedgerResult::Conflict, "process-group-request-conflict"),
        "same-id-different-content-conflict");

    const auto oldStop = StopOf(held, 0, "first-generation-stop");
    auto stale = oldStop;
    ++stale.stateRevision;
    const auto staleRejected = group.Continue("group/2", Vec(stale));
    Require(Rejected(staleRejected, LedgerResult::StaleRevision, "process-group-stale-stop"),
        "wrong-generation-token-rejected-before-release");
    Require(staleRejected.operation && staleRejected.operation->requestId == "group/2" &&
        staleRejected.operation->ledgerResult == LedgerResult::StaleRevision &&
        std::string(staleRejected.operation->stage) == "process-group-stale-stop" &&
        staleRejected.operation->win32Error == ERROR_INVALID_STATE &&
        staleRejected.operation->outcomes.empty(), "rejected-continue-freezes-first-receipt");
    Require(group.Query().state == ProcessGroupState::HeldComplete,
        "rejected-continue-leaves-all-stops-held");
    for (const auto& fixture : fixtures) fixture->ExpectFrozen("stale-continue-holds-every-member");
    const auto staleRecover = group.Recover("group/2");
    Require(staleRecover.ledgerResult == LedgerResult::ReadbackRequired &&
        std::string(staleRecover.stage) == "process-group-stale-stop" &&
        staleRecover.win32Error == ERROR_INVALID_STATE && staleRecover.operation &&
        staleRecover.operation->requestId == "group/2" && staleRecover.operation->outcomes.empty(),
        "rejected-continue-recover-only-reads-back");
    Require(group.Query().members[0].stop && *group.Query().members[0].stop == oldStop,
        "rejected-continue-recover-keeps-original-stop");

    auto mixedStops = Vec(oldStop, StopOf(held, 1, "second-member-stop"));
    ++mixedStops[1].stateRevision;
    Require(Rejected(group.Continue("group/3", mixedStops), LedgerResult::StaleRevision,
        "process-group-stale-stop"), "one-stale-stop-rejects-whole-multi-member-continue");
    Require(group.Query().state == ProcessGroupState::HeldComplete,
        "failed-multi-continue-keeps-every-member-held");
    for (const auto& fixture : fixtures) fixture->ExpectFrozen("no-partial-release-before-full-token-check");

    const auto one = group.Continue("group/4", Vec(oldStop));
    Require(one.operation && one.operation->action == ProcessGroupAction::Continue &&
        one.operation->outcomes.size() == 1 && one.operation->outcomes[0].control.release &&
        one.operation->outcomes[0].control.release->receipt->result == ReleaseResult::Continued,
        "single-member-continue-has-native-receipt");
    const auto partial = HeldGroup(group, "single-continue-leaves-other-members-held");
    Require(partial.state == ProcessGroupState::HeldPartial && partial.members[0].clean &&
        !partial.members[0].stop && partial.members[1].stop && partial.members[2].stop,
        "partial-group-state-distinguishes-clean-member");
    fixtures[0]->CheckAttached(false);
    fixtures[0]->ExpectRunning("continued-member-resumes");
    fixtures[1]->ExpectFrozen("untouched-member-two-still-held");
    fixtures[2]->ExpectFrozen("untouched-member-three-still-held");

    const auto repeatContinue = group.Continue("group/4", Vec(oldStop));
    Require(repeatContinue.ledgerResult == LedgerResult::Duplicate && repeatContinue.operation &&
        repeatContinue.operation->outcomes.size() == 1, "duplicate-continue-replays-original-ticket");
    fixtures[0]->ExpectRunning("duplicate-continue-does-not-release-twice");
    Require(group.Query().state == ProcessGroupState::HeldPartial, "duplicate-continue-preserves-current-state");

    // 新一代暂停为新原生 owner；旧 Recover 只回读旧票据，不触碰新停点。
    const auto regenerated = group.Pause("group/5", Vec(fixtures[0]->Target()));
    Require(regenerated.operation && regenerated.operation->outcomes.size() == 1, "new-generation-pause-ticket");
    const auto newHeld = HeldGroup(group, "new-generation-reaches-hold");
    const auto newStop = *newHeld.members[0].stop;
    Require(newStop.event.backendInstanceId != oldStop.event.backendInstanceId &&
        !(newStop.event == oldStop.event), "new-generation-has-new-native-owner-and-event");
    fixtures[0]->ExpectFrozen("new-generation-holds-member");
    const auto oldRecover = group.Recover("group/4");
    Require(oldRecover.operation && oldRecover.operation->action == ProcessGroupAction::Recover &&
        oldRecover.operation->outcomes.size() == 1 && oldRecover.operation->outcomes[0].control.release,
        "old-recover-replays-original-release-receipt");
    Require(group.Query().members[0].stop && group.Query().members[0].stop->event.serial == newStop.event.serial,
        "old-recover-does-not-touch-new-owner");
    fixtures[0]->ExpectFrozen("old-recover-keeps-new-generation-held");

    const auto finishedStops = std::vector<ProcessGroupStop>{newStop, StopOf(partial, 1, "second-member-stop"),
        StopOf(partial, 2, "third-member-stop")};
    const auto finished = group.Continue("group/6", finishedStops);
    Require(finished.operation && finished.operation->outcomes.size() == 3 &&
        finished.state == ProcessGroupState::Active, "full-set-continue-detaches-all-members");
    for (std::size_t i = 0; i < 3; ++i) {
        fixtures[i]->CheckAttached(false);
        fixtures[i]->ExpectRunning("full-set-recovery-resumes-each-target");
    }
    const auto recover = group.Recover("group/6");
    Require(recover.operation && recover.operation->action == ProcessGroupAction::Recover &&
        recover.operation->outcomes.size() == 3 && recover.clean &&
        recover.state == ProcessGroupState::Active, "recover-uses-original-continue-ticket-without-second-action");
    for (const auto& fixture : fixtures) fixture->ExpectRunning("recover-does-not-pause-running-targets");
    Require(Rejected(group.Recover("group/5"), LedgerResult::ReadbackRequired,
        "process-group-original-release-required"), "pause-ticket-is-not-a-recover-ticket");
    Require(Rejected(group.Recover("group/999"), LedgerResult::ReadbackRequired,
        "process-group-original-release-required"), "unknown-recover-ticket-rejected");
    const auto closed = group.Close();
    Require(closed.state == ProcessGroupState::Closed && closed.clean, "close-after-full-continue-is-clean");
    for (const auto& fixture : fixtures) {
        fixture->CheckAttached(false);
        Require(fixture->Alive(), "close-keeps-target-alive");
        fixture->ExpectRunning("close-leaves-target-running");
    }
    Require(Rejected(group.Pause("group/7", Targets(fixtures)), LedgerResult::InvalidTransition,
        "process-group-pause-unavailable"), "close-seals-new-pause");
    Require(group.Query().state == ProcessGroupState::Closed, "query-after-close-preserves-closed-state");
    const auto recoverAfterClose = group.Recover("group/6");
    Require(recoverAfterClose.operation && recoverAfterClose.operation->requestId == "group/6" &&
        recoverAfterClose.operation->outcomes.size() == 3 &&
        recoverAfterClose.state == ProcessGroupState::Closed, "close-retains-original-continue-ticket");
}

// 外部调试器占用形成真实的已附加冲突与部分成员失败回执。
void TestExternalConflictAndPartial(wchar_t* executable) {
    const auto identity = Identity(3);
    auto fixtures = MakeFixtures(executable, 3);
    OwnedProcessGroup group(identity);
    Require(group.Configure(Targets(fixtures), true, NativeTargetDisposition::ResumeAndDetach).state ==
        ProcessGroupState::Ready, "conflict-configured");

    auto contenderIdentity = identity;
    contenderIdentity.backendInstanceId = "50000000-0000-0000-0000-000000000001";
    NativeDebugOwner contender(contenderIdentity);
    const NativePauseRequest external{"external-attach", fixtures[1]->pid, fixtures[1]->creationTime, true,
        NativeTargetDisposition::ResumeAndDetach};
    Require(contender.Pause(external).status == NativeControlStatus::Accepted, "external-debugger-attached");
    const auto deadline = GetTickCount64() + kDeadlineMs;
    NativeControlResult externalState;
    do {
        externalState = contender.Query();
        if (externalState.status == NativeControlStatus::Held) break;
        Sleep(1);
    } while (GetTickCount64() < deadline);
    Require(externalState.status == NativeControlStatus::Held && externalState.responsibility,
        "external-debugger-holds-real-event");
    fixtures[1]->CheckAttached(true);

    const auto partial = group.Pause("group/1", Targets(fixtures));
    Require(partial.operation && partial.operation->outcomes.size() == 3, "partial-pause-has-three-member-receipts");
    const auto& out0 = partial.operation->outcomes[0].control;
    const auto& out1 = partial.operation->outcomes[1].control;
    const auto& out2 = partial.operation->outcomes[2].control;
    Require(out0.status == NativeControlStatus::Accepted && out2.status == NativeControlStatus::Accepted,
        "healthy-members-accept-attachment");
    Require(out1.status == NativeControlStatus::Rejected && out1.win32Error == ERROR_BUSY && out1.clean,
        "already-attached-member-reports-real-conflict");
    const auto partialState = HeldGroup(group, "group-reports-partial-native-hold");
    Require(partialState.state == ProcessGroupState::HeldPartial && partialState.members[1].clean &&
        !partialState.members[1].stop, "partial-native-hold-is-not-whole-set-complete");
    Require(partialState.members[0].stop && partialState.members[2].stop, "healthy-members-keep-exact-stops");
    fixtures[0]->ExpectFrozen("healthy-member-zero-frozen");
    fixtures[2]->ExpectFrozen("healthy-member-two-frozen");
    Require(fixtures[1]->Alive(), "conflicted-member-still-owned-by-external-debugger");

    const auto resumed = group.Continue("group/2", Vec(*partialState.members[0].stop, *partialState.members[2].stop));
    Require(resumed.operation && resumed.operation->outcomes.size() == 2, "partial-continue-releases-only-healthy");
    fixtures[0]->CheckAttached(false);
    fixtures[2]->CheckAttached(false);
    fixtures[0]->ExpectRunning("healthy-member-zero-resumed");
    fixtures[2]->ExpectRunning("healthy-member-two-resumed");
    const auto externalClosed = contender.Close();
    Require(externalClosed.clean && externalClosed.status == NativeControlStatus::Closed,
        "external-debugger-detaches");
    fixtures[1]->CheckAttached(false);
    fixtures[1]->ExpectRunning("conflicted-member-runs-after-external-detach");
    Require(group.Close().clean, "partial-group-closes-cleanly");
}

// 目标自然退出与配置后退出：Pin 拒绝、原生 owner 拒绝已终止实例。
void TestNaturalExit(wchar_t* executable) {
    const auto identity = Identity(4);
    auto exited = MakeFixtures(executable, 1);
    exited[0]->ExitNaturally();
    {
        OwnedProcessGroup group(identity);
        Require(Rejected(group.Configure({exited[0]->Target()}, true, NativeTargetDisposition::ResumeAndDetach),
            LedgerResult::IdentityMismatch, "process-group-pin-instance"), "naturally-exited-instance-rejected-by-pin");
    }
    auto fixtures = MakeFixtures(executable, 1);
    OwnedProcessGroup group(identity);
    Require(group.Configure({fixtures[0]->Target()}, true, NativeTargetDisposition::ResumeAndDetach).state ==
        ProcessGroupState::Ready, "exit-configured");
    fixtures[0]->ExitNaturally();
    const auto afterExit = group.Pause("group/1", Vec(fixtures[0]->Target()));
    Require(afterExit.operation && afterExit.operation->outcomes.size() == 1 &&
        afterExit.operation->outcomes[0].control.status == NativeControlStatus::Rejected,
        "pause-on-exited-instance-rejected-by-native-owner");
    Require(group.Query().state == ProcessGroupState::Active && group.Query().clean,
        "exited-instance-never-becomes-held");
    Require(group.Close().state == ProcessGroupState::Closed, "exited-instance-group-closes");
}

// Close 在仍持有时真实脱离，目标继续存活。
void TestCloseWhileHeld(wchar_t* executable) {
    const auto identity = Identity(6);
    auto fixtures = MakeFixtures(executable, 2);
    OwnedProcessGroup group(identity);
    Require(group.Configure(Targets(fixtures), true, NativeTargetDisposition::ResumeAndDetach).state ==
        ProcessGroupState::Ready, "close-held-configured");
    Require(group.Pause("group/1", Targets(fixtures)).ledgerResult == LedgerResult::Applied,
        "close-held-pause-applied");
    const auto held = HeldGroup(group, "close-held-reaches-real-stop");
    Require(held.state == ProcessGroupState::HeldComplete, "close-held-all-members-held");
    for (const auto& fixture : fixtures) {
        fixture->CheckAttached(true);
        fixture->ExpectFrozen("close-held-frozen-before-close");
    }
    const auto closed = group.Close();
    Require(closed.state == ProcessGroupState::Closed && closed.clean && closed.members.size() == 2,
        "close-while-held-detaches-every-member");
    for (const auto& fixture : fixtures) {
        fixture->CheckAttached(false);
        Require(fixture->Alive(), "close-while-held-target-still-alive");
        fixture->ExpectRunning("close-while-held-target-continues-heartbeat");
    }
    Require(Rejected(group.Pause("group/2", Targets(fixtures)), LedgerResult::InvalidTransition,
        "process-group-pause-unavailable"), "close-while-held-seals-new-pause");
    Require(group.Query().state == ProcessGroupState::Closed, "close-while-held-query-stays-closed");
}

// 格式正确的拒绝也占票据：首次错误冻结、同内容 Duplicate、异内容 Conflict、新 ID 才执行。
void TestRejectedTicketReceipts(wchar_t* executable) {
    const auto identity = Identity(8);
    auto fixtures = MakeFixtures(executable, 2);
    OwnedProcessGroup group(identity);
    Require(group.Configure(Targets(fixtures), true, NativeTargetDisposition::ResumeAndDetach).state ==
        ProcessGroupState::Ready, "rejected-tickets-configured");
    const auto target = fixtures[0]->Target();
    fixtures[0]->CheckAttached(false);

    auto bogus = target;
    ++bogus.creationFileTime;
    const auto rejectedTargets = Vec(bogus);
    const auto badPause = group.Pause("group/1", rejectedTargets);
    Require(Rejected(badPause, LedgerResult::IdentityMismatch, "process-group-selection-mismatch"),
        "unconfigured-target-pause-rejected");
    Require(badPause.operation && badPause.operation->requestId == "group/1" &&
        badPause.operation->action == ProcessGroupAction::Pause &&
        badPause.operation->ledgerResult == LedgerResult::IdentityMismatch &&
        std::string(badPause.operation->stage) == "process-group-selection-mismatch" &&
        badPause.operation->win32Error == ERROR_INVALID_PARAMETER &&
        badPause.operation->outcomes.empty(), "rejected-pause-freezes-first-receipt");
    fixtures[0]->CheckAttached(false);
    fixtures[0]->ExpectRunning("rejected-pause-has-no-native-side-effect");

    const auto repeated = group.Pause("group/1", rejectedTargets);
    Require(repeated.ledgerResult == LedgerResult::Duplicate && repeated.operation &&
        repeated.operation->ledgerResult == LedgerResult::IdentityMismatch &&
        repeated.operation->win32Error == ERROR_INVALID_PARAMETER &&
        repeated.state == ProcessGroupState::Ready, "same-rejected-content-replays-without-execution");
    fixtures[0]->ExpectRunning("duplicate-rejection-does-not-attach");
    Require(Rejected(group.Pause("group/1", Vec(target)), LedgerResult::Conflict,
        "process-group-request-conflict"), "same-id-changed-content-conflicts-after-rejection");
    fixtures[0]->ExpectRunning("conflicting-rejected-id-does-not-attach");

    const auto accepted = group.Pause("group/2", Vec(target));
    Require(accepted.ledgerResult == LedgerResult::Applied && accepted.operation,
        "fresh-ticket-after-rejection-executes");
    const auto held = HeldGroup(group, "fresh-ticket-reaches-real-hold");
    Require(held.state == ProcessGroupState::HeldPartial && held.members[0].stop,
        "one-configured-member-held");
    const auto stop = StopOf(held, 0, "fresh-stop-for-rejection");
    fixtures[0]->ExpectFrozen("fresh-ticket-holds-target");

    auto stale = stop;
    ++stale.stateRevision;
    const auto badContinue = group.Continue("group/3", Vec(stale));
    Require(Rejected(badContinue, LedgerResult::StaleRevision, "process-group-stale-stop"),
        "stale-continue-consumes-ticket");
    Require(badContinue.operation && badContinue.operation->ledgerResult == LedgerResult::StaleRevision &&
        badContinue.operation->win32Error == ERROR_INVALID_STATE &&
        badContinue.operation->outcomes.empty(), "rejected-continue-freezes-first-receipt");
    const auto readback = group.Recover("group/3");
    Require(readback.ledgerResult == LedgerResult::ReadbackRequired &&
        std::string(readback.stage) == "process-group-stale-stop" &&
        readback.win32Error == ERROR_INVALID_STATE && readback.operation &&
        readback.operation->outcomes.empty(), "rejected-continue-recover-readback-only");
    Require(group.Query().members[0].stop && *group.Query().members[0].stop == stop,
        "rejected-continue-keeps-original-stop");
    fixtures[0]->ExpectFrozen("rejected-continue-keeps-target-frozen");
    const auto repeatedContinue = group.Continue("group/3", Vec(stale));
    Require(repeatedContinue.ledgerResult == LedgerResult::Duplicate && repeatedContinue.operation &&
        repeatedContinue.operation->ledgerResult == LedgerResult::StaleRevision,
        "same-rejected-continue-replays-without-execution");
    Require(Rejected(group.Continue("group/3", Vec(stop)), LedgerResult::Conflict,
        "process-group-request-conflict"), "same-continue-id-changed-content-conflicts");
    Require(group.Query().members[0].stop && *group.Query().members[0].stop == stop,
        "conflicting-continue-does-not-release-stop");
    fixtures[0]->ExpectFrozen("conflicting-continue-keeps-target-frozen");

    const auto released = group.Continue("group/4", Vec(stop));
    Require(released.ledgerResult == LedgerResult::Applied && released.operation &&
        released.operation->outcomes.size() == 1, "fresh-continue-after-rejection-executes");
    fixtures[0]->CheckAttached(false);
    fixtures[0]->ExpectRunning("fresh-continue-resumes-target");
    Require(group.Close().clean, "rejected-tickets-group-closes-cleanly");
}

// 128 组层票据滚动：真实附加/继续各占一个序号，淘汰后拒绝重放。
void TestReceiptRolling(wchar_t* executable) {
    const auto identity = Identity(5);
    auto fixtures = MakeFixtures(executable, 1);
    OwnedProcessGroup group(identity);
    const auto target = fixtures[0]->Target();
    Require(group.Configure({target}, true, NativeTargetDisposition::ResumeAndDetach).state ==
        ProcessGroupState::Ready, "rolling-configured");
    Require(Rejected(group.Pause("not-group-1", Vec(target)), LedgerResult::InvalidEvidence,
        "process-group-require-group-sequence"), "noncanonical-id-rejected");
    Require(Rejected(group.Pause("group/0", Vec(target)), LedgerResult::InvalidEvidence,
        "process-group-require-group-sequence"), "zero-sequence-rejected");
    Require(Rejected(group.Pause("group/01", Vec(target)), LedgerResult::InvalidEvidence,
        "process-group-require-group-sequence"), "leading-zero-sequence-rejected");
    auto bogus = target;
    ++bogus.creationFileTime;
    Require(group.Pause("group/1", Vec(bogus)).ledgerResult == LedgerResult::IdentityMismatch,
        "seed-format-valid-rejected-ticket");

    DWORD handlesBefore = 0; // 首轮包含 CoCreateGuid/OLE 等一次性初始化；从第二轮起核对稳态。
    for (unsigned cycle = 0; cycle < 64; ++cycle) {
        const auto pauseId = "group/" + std::to_string(cycle * 2 + 2);
        const auto continueId = "group/" + std::to_string(cycle * 2 + 3);
        const auto pause = group.Pause(pauseId, Vec(target));
        Require(pause.ledgerResult == LedgerResult::Applied && pause.operation, "rolling-pause-applied");
        const auto held = HeldGroup(group, "rolling-pause-held");
        const auto stop = StopOf(held, 0, "rolling-stop");
        const auto continued = group.Continue(continueId, Vec(stop));
        Require(continued.ledgerResult == LedgerResult::Applied && continued.operation &&
            continued.operation->outcomes[0].control.release->receipt->result == ReleaseResult::Continued,
            "rolling-continue-has-native-receipt");
        fixtures[0]->CheckAttached(false);
        fixtures[0]->ExpectRunning("rolling-cycle-resumes-target");
        if (cycle == 1) {
            Require(GetProcessHandleCount(GetCurrentProcess(), &handlesBefore) != FALSE, "steady-handle-baseline");
        }
    }
    // 第 129 张票据写入时才淘汰最低序号：首张“拒绝票据”先出局。
    Require(Rejected(group.Pause("group/1", Vec(bogus)), LedgerResult::ReplayExpired,
        "process-group-replay-expired"), "evicted-rejected-ticket-rejected");
    const auto fresh = group.Pause("group/130", Vec(target));
    Require(fresh.ledgerResult == LedgerResult::Applied && fresh.operation->requestId == "group/130",
        "ticket-after-high-water-still-accepted");
    Require(Rejected(group.Recover("group/2"), LedgerResult::ReadbackRequired,
        "process-group-original-release-required"), "evicted-recover-ticket-rejected");
    const auto freshStop = StopOf(HeldGroup(group, "fresh-ticket-held"), 0, "fresh-stop");
    Require(group.Continue("group/131", Vec(freshStop)).ledgerResult == LedgerResult::Applied,
        "fresh-continue-applied");
    DWORD handlesAfter = 0;
    Require(GetProcessHandleCount(GetCurrentProcess(), &handlesAfter) != FALSE, "owner-handle-readback");
    if (handlesBefore != handlesAfter) {
        std::fprintf(stderr, "owner-handles-before=%lu after=%lu\n", handlesBefore, handlesAfter);
    }
    Require(handlesBefore == handlesAfter, "repeated-native-generations-release-handles");
    Require(group.Close().clean, "rolling-group-closes-cleanly");
}

// control adapter 最小集：LiveRead 显式选择与 HeldEvent 精确令牌，不重复内存核心测试。
void TestProcessGroupMemorySnapshot(wchar_t* executable) {
    const auto identity = Identity(7);
    MemoryFixture fixture(executable);
    OwnedProcessGroup group(identity);
    Require(group.Configure({fixture.Target()}, true, NativeTargetDisposition::ResumeAndDetach).state ==
        ProcessGroupState::Ready, "memory-adapter-configured");
    const auto plan = MakeMemoryPlan(fixture, identity.sampleId);

    ProcessMemorySnapshotRequest liveRequest{plan, ProcessMemorySource::LiveRead, std::nullopt};
    const auto live = CaptureProcessGroupMemory(group, liveRequest);
    Require(std::string(live.stage) == "process-memory-read-observed" && live.snapshot &&
        live.snapshot->completeRange, "live-read-captures-known-range");
    Require(live.snapshot->captured.size() == 1 && live.snapshot->captured[0].bytes.size() == 64,
        "live-read-captures-exact-page-subrange");
    for (unsigned i = 0; i < 64; ++i) {
        Require(live.snapshot->captured[0].bytes[i] == fixture.Byte(i), "live-read-byte-equals-known-value");
    }
    Require(!live.before && !live.after && !live.heldAtBothChecks, "live-read-carries-no-stop-token");
    Require(live.request.plan.sampleId == plan.sampleId && live.request.plan.range == plan.range,
        "live-read-request-frozen-to-original-choice");
    fixture.CheckAttached(false);

    ProcessMemorySnapshotRequest borrowed{plan, ProcessMemorySource::LiveRead, ProcessGroupStop{}};
    const auto refused = CaptureProcessGroupMemory(group, borrowed);
    Require(std::string(refused.stage) == "process-memory-live-read-cannot-borrow-stop" &&
        refused.win32Error == ERROR_INVALID_PARAMETER && !refused.snapshot,
        "live-read-with-stop-refused-without-downgrade");
    fixture.CheckAttached(false);

    Require(group.Pause("group/1", Vec(fixture.Target())).ledgerResult == LedgerResult::Applied,
        "memory-adapter-pause-applied");
    const auto held = HeldGroup(group, "memory-adapter-reaches-hold");
    Require(held.state == ProcessGroupState::HeldComplete && held.members[0].stop,
        "memory-adapter-member-held-complete");
    const auto stop = StopOf(held, 0, "memory-adapter-stop");
    fixture.CheckAttached(true);

    ProcessMemorySnapshotRequest heldRequest{plan, ProcessMemorySource::HeldEvent, stop};
    const auto captured = CaptureProcessGroupMemory(group, heldRequest);
    Require(std::string(captured.stage) == "process-memory-read-observed" && captured.snapshot &&
        captured.snapshot->completeRange, "held-event-reads-known-bytes");
    Require(captured.before && *captured.before == stop && captured.after && *captured.after == stop &&
        captured.heldAtBothChecks, "held-event-token-identical-before-and-after");
    Require(captured.snapshot->captured.size() == 1 && captured.snapshot->captured[0].bytes.size() == 64,
        "held-event-captures-exact-page-subrange");
    for (unsigned i = 0; i < 64; ++i) {
        Require(captured.snapshot->captured[0].bytes[i] == fixture.Byte(i), "held-event-byte-equals-known-value");
    }
    Require(group.Query().state == ProcessGroupState::HeldComplete && group.Query().members[0].stop &&
        *group.Query().members[0].stop == stop, "held-event-read-does-not-continue-target");
    fixture.CheckAttached(true);

    auto stale = stop;
    ++stale.stateRevision;
    ProcessMemorySnapshotRequest staleRequest{plan, ProcessMemorySource::HeldEvent, stale};
    const auto staleResult = CaptureProcessGroupMemory(group, staleRequest);
    Require(std::string(staleResult.stage) == "process-memory-stale-stop" &&
        staleResult.win32Error == ERROR_INVALID_STATE && !staleResult.snapshot &&
        !staleResult.before && !staleResult.after, "old-token-rejected-without-read");
    Require(group.Query().members[0].stop && *group.Query().members[0].stop == stop,
        "old-token-rejection-keeps-original-stop");
    fixture.CheckAttached(true);

    auto wrongPlan = plan;
    wrongPlan.sampleId = "wrong-sample";
    ProcessMemorySnapshotRequest wrongRequest{wrongPlan, ProcessMemorySource::HeldEvent, stop};
    const auto wrongResult = CaptureProcessGroupMemory(group, wrongRequest);
    Require(std::string(wrongResult.stage) == "process-memory-stale-stop" &&
        wrongResult.win32Error == ERROR_INVALID_STATE && !wrongResult.snapshot,
        "wrong-sample-rejected-without-read");
    Require(group.Query().members[0].stop && *group.Query().members[0].stop == stop,
        "wrong-sample-rejection-keeps-original-stop");
    fixture.CheckAttached(true);

    Require(group.Close().clean, "memory-adapter-group-closes-cleanly");
    fixture.CheckAttached(false);
    fixture.Exit();
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 8 && std::wcscmp(argv[1], L"--heartbeat") == 0) return HeartbeatChildMain(argv + 2);
    if (argc == 5 && std::wcscmp(argv[1], L"--memory") == 0) return MemoryChild(argv[2], argv[3], argv[4]);
    TestConfigure(argv[0]);
    TestGroupLifecycle(argv[0]);
    TestExternalConflictAndPartial(argv[0]);
    TestNaturalExit(argv[0]);
    TestCloseWhileHeld(argv[0]);
    TestRejectedTicketReceipts(argv[0]);
    TestReceiptRolling(argv[0]);
    TestProcessGroupMemorySnapshot(argv[0]);
    std::printf("RESULT=PASS checks=%u\n", checks);
    return 0;
}
