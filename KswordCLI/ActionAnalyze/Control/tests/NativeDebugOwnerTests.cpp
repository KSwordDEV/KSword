#include "../NativeDebugOwner.h"

#include <Windows.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

using namespace ks::cli::action_analyze::control;

extern "C" __declspec(dllexport) __declspec(noinline) BOOL WINAPI KswordFixtureBreakpoint(HANDLE event) {
    return SetEvent(event);
}

namespace {

constexpr DWORD kDeadlineMs = 5000;
unsigned checks = 0;

void Require(bool condition, const char* check) {
    if (!condition) {
        std::fprintf(stderr, "FAIL %s win32=%lu\n", check, GetLastError());
        std::exit(1);
    }
    ++checks;
}

class Handle {
public:
    explicit Handle(HANDLE handle = nullptr) : handle_(handle) {}
    ~Handle() { if (handle_) { CloseHandle(handle_); } }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE Get() const { return handle_; }
    void Reset(HANDLE value) {
        if (handle_) { CloseHandle(handle_); }
        handle_ = value;
    }
private:
    HANDLE handle_;
};

HANDLE InheritedEvent(bool broadcast = false) {
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    const auto event = CreateEventW(&attributes, broadcast, FALSE, nullptr);
    Require(event != nullptr, "fixture-event");
    return event;
}

struct WorkerEvents {
    HANDLE pulse;
    HANDLE reply;
    HANDLE stop;
};

DWORD WINAPI Worker(void* context) {
    const auto* events = static_cast<const WorkerEvents*>(context);
    const HANDLE inputs[]{events->stop, events->pulse};
    while (WaitForMultipleObjects(2, inputs, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {
        if (!KswordFixtureBreakpoint(events->reply)) { return 2; }
    }
    return 0;
}

int Child(wchar_t** args) {
    constexpr DWORD kOwnApplicationException = 0xe115aa01;
    HANDLE events[10]{};
    for (int i = 0; i < 10; ++i) {
        events[i] = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(args[i], nullptr, 10)));
    }
    WorkerEvents worker{events[2], events[3], events[4]};
    WorkerEvents newWorker{events[8], events[9], events[4]};
    HANDLE newWorkerThread = nullptr;
    const auto workerThread = CreateThread(nullptr, 0, Worker, &worker, 0, nullptr);
    if (!workerThread || !SetEvent(events[6])) { return 2; }

    const HANDLE inputs[]{events[4], events[0], events[5], events[7]};
    for (;;) {
        const auto choice = WaitForMultipleObjects(static_cast<DWORD>(std::size(inputs)), inputs, FALSE, INFINITE);
        if (choice == WAIT_OBJECT_0) { break; }
        if (choice == WAIT_OBJECT_0 + 1) {
            if (!KswordFixtureBreakpoint(events[1])) { return 2; }
        } else if (choice == WAIT_OBJECT_0 + 2) {
            bool delivered = false;
            __try {
                RaiseException(kOwnApplicationException, 0, 0, nullptr);
            } __except (GetExceptionCode() == kOwnApplicationException ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
                delivered = true;
            }
            if (!delivered || !SetEvent(events[1])) { return 2; }
        } else if (choice == WAIT_OBJECT_0 + 3) {
            newWorkerThread = CreateThread(nullptr, 0, Worker, &newWorker, 0, nullptr);
            if (!newWorkerThread) { return 2; }
        } else {
            return 2;
        }
    }
    const auto status = WaitForSingleObject(workerThread, kDeadlineMs);
    CloseHandle(workerThread);
    if (newWorkerThread) {
        const auto exited = WaitForSingleObject(newWorkerThread, kDeadlineMs);
        CloseHandle(newWorkerThread);
        if (exited != WAIT_OBJECT_0) { return 2; }
    }
    return status == WAIT_OBJECT_0 ? 0 : 2;
}

class Fixture {
public:
    Fixture(wchar_t* executable) {
        job_.Reset(CreateJobObjectW(nullptr, nullptr));
        Require(job_.Get() != nullptr, "create-private-job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        Require(SetInformationJobObject(job_.Get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE,
            "set-private-job");
        std::wstring command = L"\"" + std::wstring(executable) + L"\" --child";
        HANDLE inherited[10]{};
        for (std::size_t i = 0; i < std::size(events_); ++i) {
            inherited[i] = events_[i].Get();
            command += L" " + std::to_wstring(reinterpret_cast<std::uintptr_t>(inherited[i]));
        }
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
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &process);
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        Require(created != FALSE, "create-own-fixture");
        const Handle initialThread(process.hThread);
        process_.Reset(process.hProcess);
        pid = process.dwProcessId;
        BOOL inJob = FALSE;
        Require(IsProcessInJob(process_.Get(), job_.Get(), &inJob) && inJob, "own-fixture-in-private-job");
        Require(ResumeThread(initialThread.Get()) == 1, "start-own-fixture");
        Require(WaitForSingleObject(events_[6].Get(), kDeadlineMs) == WAIT_OBJECT_0, "both-fixture-threads-ready");
        FILETIME creation{}, exited{}, kernel{}, user{};
        Require(GetProcessTimes(process_.Get(), &creation, &exited, &kernel, &user) != FALSE, "fixture-creation-time");
        creationTime = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    }

    void SignalBoth() const {
        Require(SetEvent(events_[0].Get()) && SetEvent(events_[2].Get()), "signal-both-fixture-threads");
    }

    void BothRespond(DWORD limit, DWORD expectation) const {
        for (const int reply : {1, 3}) {
            Require(WaitForSingleObject(events_[reply].Get(), limit) == expectation, "two-thread-execution-observation");
        }
    }

    void CheckAttached(bool value) const {
        BOOL debugging = FALSE;
        Require(CheckRemoteDebuggerPresent(process_.Get(), &debugging) && (debugging != FALSE) == value,
            "independent-attachment-readback");
    }

    void ExceptionDelivered() const {
        Require(SetEvent(events_[5].Get()) && WaitForSingleObject(events_[1].Get(), kDeadlineMs) == WAIT_OBJECT_0,
            "fixture-own-exception-reaches-handler");
    }

    void SpawnWorker() const { Require(SetEvent(events_[7].Get()) != FALSE, "spawn-worker-while-armed"); }
    void Signal(unsigned index) const { Require(SetEvent(events_[index].Get()) != FALSE, "signal-fixture-thread"); }
    void Response(unsigned index, DWORD limit, DWORD expected) const {
        Require(WaitForSingleObject(events_[index].Get(), limit) == expected, "fixture-thread-response");
    }

    void Exit() const {
        Require(SetEvent(events_[4].Get()) && WaitForSingleObject(process_.Get(), kDeadlineMs) == WAIT_OBJECT_0,
            "fixture-exited");
        DWORD code = 0;
        Require(GetExitCodeProcess(process_.Get(), &code) && code == 0, "fixture-normal-exit-code");
    }

    DWORD pid = 0;
    std::uint64_t creationTime = 0;

private:
    Handle job_;
    Handle process_;
    Handle events_[10]{Handle(InheritedEvent()), Handle(InheritedEvent()), Handle(InheritedEvent()), Handle(InheritedEvent()),
        Handle(InheritedEvent(true)), Handle(InheritedEvent()), Handle(InheritedEvent()), Handle(InheritedEvent()),
        Handle(InheritedEvent()), Handle(InheritedEvent())};
};

NativeControlResult WaitForHold(NativeDebugOwner& native, const NativeControlResult& accepted) {
    if (accepted.status != NativeControlStatus::Accepted) {
        std::fprintf(stderr, "attach-stage=%s error=%u status=%d\n", accepted.stage, accepted.win32Error,
            static_cast<int>(accepted.status));
    }
    Require(accepted.status == NativeControlStatus::Accepted && accepted.attached && !accepted.clean && accepted.group &&
        accepted.group->state == GroupState::GroupBuilding && !accepted.responsibility && !accepted.pending, "attach-acceptance-not-hold");
    auto held = accepted;
    const auto start = GetTickCount64();
    do {
        held = native.Query(accepted.group->groupId);
        if (held.status != NativeControlStatus::Accepted) { break; }
        Sleep(1);
    } while (GetTickCount64() - start < kDeadlineMs);
    if (held.status != NativeControlStatus::Held) {
        std::fprintf(stderr, "hold-stage=%s error=%u\n", held.stage, held.win32Error);
    }
    Require(held.status == NativeControlStatus::Held && held.attached && !held.clean && held.responsibility && held.pending,
        "real-pending-native-event");
    Require(held.pending->ledgerOwned && held.pending->eventCode == CREATE_PROCESS_DEBUG_EVENT && !held.pending->exceptionCode &&
        held.pending->pid == held.pid && held.pending->tid != 0 && held.pending->event == held.responsibility->event,
        "exact-create-process-event");
    Require(held.group && held.group->state == GroupState::HeldComplete && !held.group->origin && held.group->members.size() >= 2 &&
        held.group->incidentalQuality == IncidentalQuality::NotCollected, "frozen-member-scope-without-a-synthetic-origin-phase");
    Require(held.frozenThreads.size() == held.group->members.size(), "frozen-handle-identities-available");
    Require(held.timing.qpcFrequency != 0 && held.timing.attachSubmittedQpc && held.timing.eventObservedQpc &&
        *held.timing.attachSubmittedQpc <= *held.timing.eventObservedQpc && !held.timing.continueReturnedQpc,
        "actual-native-event-observation-clock");
    for (std::size_t i = 0; i < held.frozenThreads.size(); ++i) {
        const auto& thread = held.frozenThreads[i];
        Require(thread.tid != 0 && thread.creationTime != 0 && thread.identity.processInstanceId == held.processInstanceId &&
            thread.identity.threadId == held.group->members[i].threadId, "frozen-member-keeps-native-identity-evidence");
    }
    return held;
}

ReleaseRequest ToRelease(const OwnerIdentity& owner, const NativeControlResult& stop, std::string id) {
    return {owner, stop.group->groupId, stop.responsibility->stopId, stop.responsibility->event, std::move(id),
        stop.group->stateRevision};
}

NativeControlResult WaitForBreakpoint(NativeDebugOwner& native, NativeBreakpointState expected) {
    const auto deadline = GetTickCount64() + kDeadlineMs;
    NativeControlResult result;
    do {
        result = native.Query();
        if (result.breakpoint && (result.breakpoint->state == expected ||
            result.breakpoint->state == NativeBreakpointState::Rejected ||
            result.breakpoint->state == NativeBreakpointState::RecoveryRequired)) { break; }
        Sleep(1);
    } while (GetTickCount64() < deadline);
    if (!result.breakpoint || result.breakpoint->state != expected) {
        std::fprintf(stderr, "breakpoint-stage=%s binding=%s error=%u status=%d\n", result.stage,
            result.breakpoint ? result.breakpoint->stage : "none", result.win32Error, static_cast<int>(result.status));
    }
    Require(result.breakpoint && result.breakpoint->state == expected, "observed-exact-breakpoint-state");
    return result;
}

void TestBreakpoints(wchar_t* executable, const OwnerIdentity& owner) {
    wchar_t module[MAX_PATH]{};
    const auto length = GetModuleFileNameW(nullptr, module, MAX_PATH);
    Require(length && length < MAX_PATH, "fixture-full-module-path");
    Fixture fixture(executable);
    NativeBreakpointRequest request{{"native-breakpoint", fixture.pid, fixture.creationTime, true,
        NativeTargetDisposition::ResumeAndDetach}, module, std::nullopt, "KswordFixtureBreakpoint"};
    NativeDebugOwner native(owner);
    auto invalid = request;
    invalid.rva = 1;
    Require(native.ArmBreakpoint(invalid).status == NativeControlStatus::Rejected, "symbol-rva-mutually-exclusive");
    invalid = request;
    ++invalid.target.processCreationTime;
    Require(native.ArmBreakpoint(invalid).ledgerResult == LedgerResult::IdentityMismatch, "breakpoint-stale-instance-rejected");
    invalid = request;
    invalid.target.explicitlyAuthorized = false;
    Require(native.ArmBreakpoint(invalid).status == NativeControlStatus::Rejected, "breakpoint-explicit-authorization-required");
    fixture.CheckAttached(false);
    const auto accepted = native.ArmBreakpoint(request);
    Require(accepted.status == NativeControlStatus::Accepted && accepted.breakpoint &&
        accepted.breakpoint->state == NativeBreakpointState::Installing && !accepted.group && !accepted.responsibility,
        "breakpoint-acceptance-is-not-armed");
    const auto armed = WaitForBreakpoint(native, NativeBreakpointState::Armed);
    Require(armed.attached && !armed.clean && armed.breakpoint->enrolledThreads >= 2 &&
        armed.breakpoint->moduleBase + armed.breakpoint->rva == armed.breakpoint->address, "live-module-address-and-enrollment");
    Require(native.ArmBreakpoint(request).ledgerResult == LedgerResult::Duplicate, "breakpoint-arm-replay");
    invalid = request;
    invalid.exportName = "different";
    Require(native.ArmBreakpoint(invalid).ledgerResult == LedgerResult::Conflict, "breakpoint-arm-replay-conflict");
    fixture.ExceptionDelivered();

    fixture.SignalBoth();
    std::optional<ReleaseRequest> old;
    DWORD lastTid = 0;
    for (unsigned i = 0; i < 2; ++i) {
        const auto held = WaitForBreakpoint(native, NativeBreakpointState::Held);
        Require(held.breakpointHit && held.breakpointHit->requestId == request.target.requestId &&
            held.breakpointHit->address == armed.breakpoint->address && held.pending && held.pending->ledgerOwned &&
            held.pending->exceptionCode == EXCEPTION_SINGLE_STEP && held.group && held.group->state == GroupState::HeldComplete &&
            held.group->origin && held.group->origin->phase == StopPhase::ExecutionEnterAttempt && held.responsibility &&
            held.pending->tid != lastTid, "concurrent-existing-threads-each-produce-an-exact-stop");
        if (!i) { fixture.BothRespond(20, WAIT_TIMEOUT); }
        if (old) {
            Require(native.Continue(*old).ledgerResult == LedgerResult::Duplicate && native.Query().pending->event == held.pending->event,
                "historical-breakpoint-replay-does-not-continue-another-event");
        }
        lastTid = held.pending->tid;
        old = ToRelease(owner, held, "continue/" + std::to_string(i + 1));
        const auto released = native.Continue(*old);
        Require(released.release && released.release->receipt && released.release->receipt->result == ReleaseResult::Continued &&
            released.attached && !released.clean && released.group && released.group->historical, "breakpoint-continue-preserves-binding");
    }
    fixture.BothRespond(kDeadlineMs, WAIT_OBJECT_0);

    const auto retiredRequest = *old;
    auto previousRevision = native.Query().group->membershipRevision;
    for (unsigned sequence = 3; sequence <= 140; ++sequence) {
        fixture.Signal(0);
        const auto next = WaitForBreakpoint(native, NativeBreakpointState::Held);
        Require(next.group && next.pending && next.responsibility && next.group->membershipRevision == ++previousRevision,
            "long-running-breakpoint-has-a-new-frozen-group");
        const auto requestId = "continue/" + std::to_string(sequence);
        auto release = ToRelease(owner, next, requestId);
        if (sequence == 140) {
            const auto expired = native.Query(retiredRequest.groupId);
            Require(expired.ledgerResult == LedgerResult::MissingGroup && !expired.group && !expired.responsibility && !expired.pending,
                "old-bounded-breakpoint-group-evicted");
            Require(native.Continue(retiredRequest).ledgerResult == LedgerResult::ReplayExpired,
                "evicted-native-replay-cannot-run-again");
            const auto older = ToRelease(owner, next, retiredRequest.requestId);
            Require(native.Continue(older).ledgerResult == LedgerResult::ReplayExpired,
                "evicted-release-id-cannot-be-rebound-to-the-live-stop");
            Require(native.Continue(*old).ledgerResult == LedgerResult::Duplicate,
                "retained-native-replay-returns-receipt");
            Require(native.Query().pending->event == next.pending->event, "replays-leave-live-native-event-held");
            fixture.Response(1, 20, WAIT_TIMEOUT);
        }
        const auto continued = native.Continue(release);
        Require(continued.attached && continued.breakpoint->state == NativeBreakpointState::Armed &&
            continued.release && continued.release->receipt && continued.release->receipt->result == ReleaseResult::Continued,
            "continue-does-not-retire-the-long-running-breakpoint");
        fixture.Response(1, kDeadlineMs, WAIT_OBJECT_0);
        old = std::move(release);
    }

    fixture.SpawnWorker();
    fixture.Signal(8);
    const auto held = WaitForBreakpoint(native, NativeBreakpointState::Held);
    Require(held.breakpoint->enrolledThreads >= 3 && held.frozenThreads.size() >= 3 && held.pending && held.pending->tid != lastTid,
        "new-thread-armed-before-entering-user-code");
    fixture.Response(9, 20, WAIT_TIMEOUT);
    const auto close = native.Close();
    Require(close.clean && close.status == NativeControlStatus::Closed && close.breakpoint &&
        close.breakpoint->state == NativeBreakpointState::Retired && !close.breakpoint->enrolledThreads && close.release &&
        close.release->receipt && close.release->receipt->result == ReleaseResult::Continued, "close-clears-slots-before-releasing-pending-hit");
    fixture.CheckAttached(false);
    fixture.Response(9, kDeadlineMs, WAIT_OBJECT_0);
    fixture.SignalBoth();
    fixture.BothRespond(kDeadlineMs, WAIT_OBJECT_0);

    const auto rva = armed.breakpoint->rva;
    request.target.requestId = "native-breakpoint-rva";
    request.exportName.clear();
    request.rva = rva;
    NativeDebugOwner running(owner);
    Require(running.ArmBreakpoint(request).status == NativeControlStatus::Accepted, "rva-attach-accepted");
    const auto rvaArmed = WaitForBreakpoint(running, NativeBreakpointState::Armed);
    Require(rvaArmed.breakpoint->address == armed.breakpoint->address, "same-rva-resolves-to-same-loaded-site");
    const auto runningClose = running.Close();
    Require(runningClose.status == NativeControlStatus::ClosePending || runningClose.clean, "close-while-running-accepted");
    const auto retired = WaitForBreakpoint(running, NativeBreakpointState::Retired);
    Require(retired.clean && !retired.attached && retired.breakpoint->enrolledThreads == 0, "running-close-restores-and-detaches");
    fixture.CheckAttached(false);
    fixture.SignalBoth();
    fixture.BothRespond(kDeadlineMs, WAIT_OBJECT_0);

    NativeDebugOwner rejected(owner);
    request.target.requestId = "native-breakpoint-invalid-rva";
    request.rva = 1;
    Require(rejected.ArmBreakpoint(request).status == NativeControlStatus::Accepted, "unmapped-site-determined-from-target-image");
    const auto badSite = WaitForBreakpoint(rejected, NativeBreakpointState::Rejected);
    Require(badSite.clean && badSite.breakpoint->win32Error == ERROR_INVALID_ADDRESS, "reject-nonexecutable-image-site-and-detach");
    fixture.CheckAttached(false);

    NativeDebugOwner exiting(owner);
    request.target.requestId = "native-breakpoint-target-exit";
    request.rva = rva;
    Require(exiting.ArmBreakpoint(request).status == NativeControlStatus::Accepted, "exit-fixture-attach-accepted");
    (void)WaitForBreakpoint(exiting, NativeBreakpointState::Armed);
    fixture.Exit();
    const auto ended = WaitForBreakpoint(exiting, NativeBreakpointState::Retired);
    Require(ended.status == NativeControlStatus::Ended && ended.clean && !ended.attached &&
        ended.breakpoint->enrolledThreads == 0 && !ended.pending, "continued-process-exit-retires-all-slot-responsibilities");
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 12 && std::wcscmp(argv[1], L"--child") == 0) { return Child(argv + 2); }
    Fixture fixture(argv[0]);
    const OwnerIdentity owner{"10000000-0000-0000-0000-000000000001", "10000000-0000-0000-0000-000000000002",
        "10000000-0000-0000-0000-000000000003", "10000000-0000-0000-0000-000000000004"};
    NativeDebugOwner native(owner);
    const NativePauseRequest good{"pause-1", fixture.pid, fixture.creationTime, true, NativeTargetDisposition::ResumeAndDetach};

    auto invalid = good;
    invalid.explicitlyAuthorized = false;
    Require(native.Pause(invalid).status == NativeControlStatus::Rejected, "unauthorized-rejected");
    invalid = good;
    ++invalid.processCreationTime;
    Require(native.Pause(invalid).ledgerResult == LedgerResult::IdentityMismatch, "stale-process-identity-rejected");
    invalid = good;
    invalid.disposition = NativeTargetDisposition::Unspecified;
    Require(native.Pause(invalid).status == NativeControlStatus::Rejected, "explicit-disposition-required");
    fixture.CheckAttached(false);
    fixture.SignalBoth();
    fixture.BothRespond(kDeadlineMs, WAIT_OBJECT_0);

    auto held = WaitForHold(native, native.Pause(good));
    fixture.CheckAttached(true);
    {
        auto contender = owner;
        contender.backendInstanceId = "10000000-0000-0000-0000-000000000005";
        NativeDebugOwner competingOwner(contender);
        const auto conflict = competingOwner.Pause(good);
        Require(conflict.status == NativeControlStatus::Rejected && conflict.win32Error == ERROR_BUSY && conflict.clean,
            "existing-debugger-not-replaced");
        Require(competingOwner.Close().clean, "contender-close-without-taking-ownership");
    }
    fixture.SignalBoth();
    fixture.BothRespond(35, WAIT_TIMEOUT);
    const auto repeated = native.Pause(good);
    Require(repeated.ledgerResult == LedgerResult::Duplicate && repeated.pending && repeated.pending->event == held.pending->event,
        "pause-replay-does-not-attach-twice");
    auto second = good;
    second.requestId = "pause-2";
    Require(native.Pause(second).status == NativeControlStatus::Rejected, "single-native-event-capacity");

    const auto release = ToRelease(owner, held, "continue-1");
    Require(native.Recover(release).status == NativeControlStatus::Rejected && native.Query().pending,
        "recovery-cannot-initiate-an-unsubmitted-release");
    auto wrong = release;
    wrong.owner.epoch = "20000000-0000-0000-0000-000000000003";
    Require(native.Continue(wrong).ledgerResult == LedgerResult::IdentityMismatch, "wrong-owner-epoch-no-release");
    wrong = release;
    ++wrong.event.serial;
    Require(native.Continue(wrong).ledgerResult == LedgerResult::IdentityMismatch, "wrong-native-event-no-release");
    wrong = release;
    --wrong.expectedStateRevision;
    Require(native.Continue(wrong).ledgerResult == LedgerResult::StaleRevision, "stale-revision-no-release");
    fixture.BothRespond(35, WAIT_TIMEOUT);

    auto done = native.Continue(release);
    if (!done.clean) { std::fprintf(stderr, "continue-stage=%s error=%u\n", done.stage, done.win32Error); }
    Require(done.clean && !done.attached && !done.pending && !done.responsibility && done.group &&
        done.group->state == GroupState::Released && done.release && done.release->receipt &&
        done.release->receipt->result == ReleaseResult::Continued, "exact-continue-receipt-and-detach");
    Require(done.timing.continueReturnedQpc && *done.timing.continueReturnedQpc >= *held.timing.eventObservedQpc,
        "exact-continue-has-a-monotonic-observation");
    fixture.CheckAttached(false);
    fixture.BothRespond(kDeadlineMs, WAIT_OBJECT_0);
    fixture.ExceptionDelivered();

    const auto again = native.Recover(release);
    Require(again.ledgerResult == LedgerResult::Duplicate && again.release && again.release->receipt == done.release->receipt,
        "duplicate-recovery-replays-the-original-receipt");
    wrong = release;
    ++wrong.event.serial;
    Require(native.Continue(wrong).ledgerResult == LedgerResult::Conflict, "release-replay-with-different-payload-rejected");
    const auto queried = native.Query(release.groupId, release.requestId);
    Require(queried.releaseRequestId == release.requestId && queried.release && queried.release->receipt == done.release->receipt,
        "release-receipt-query-without-resending");
    Require(native.Query(release.groupId, "unknown-release").status == NativeControlStatus::Rejected,
        "unknown-release-receipt-distinguished");

    {
        Fixture different(argv[0]);
        const NativePauseRequest other{"different-target", different.pid, different.creationTime, true,
            NativeTargetDisposition::ResumeAndDetach};
        const auto rejected = native.Pause(other);
        Require(rejected.status == NativeControlStatus::Rejected && rejected.ledgerResult == LedgerResult::IdentityMismatch &&
            rejected.clean, "detached-owner-still-bound-to-original-instance");
        different.CheckAttached(false);
        different.Exit();
    }

    DWORD beforeHandles = 0;
    Require(GetProcessHandleCount(GetCurrentProcess(), &beforeHandles) != FALSE, "read-owner-handle-baseline");

    for (unsigned i = 0; i < 4; ++i) {
        second.requestId = "pause-repeat-" + std::to_string(i);
        auto next = WaitForHold(native, native.Pause(second));
        Require(next.processInstanceId == held.processInstanceId && next.pending->event.serial > held.pending->event.serial,
            "same-process-instance-new-native-event");
        std::size_t sameThreads = 0;
        for (const auto& thread : next.frozenThreads) {
            for (const auto& original : held.frozenThreads) {
                if (thread.tid != original.tid || thread.creationTime != original.creationTime) { continue; }
                Require(thread.identity == original.identity, "same-native-thread-keeps-instance-id");
                ++sameThreads;
            }
        }
        Require(sameThreads >= 2, "observe-both-fixture-threads-across-stops");
        Require(native.Continue(release).ledgerResult == LedgerResult::Duplicate && native.Query().pending->event == next.pending->event,
            "old-replay-does-not-release-the-new-event");
        fixture.SignalBoth();
        fixture.BothRespond(20, WAIT_TIMEOUT);
        done = native.Continue(ToRelease(owner, next, "continue-repeat-" + std::to_string(i)));
        Require(done.clean && done.release && done.release->receipt && done.release->receipt->result == ReleaseResult::Continued,
            "repeat-exact-continue-and-detach");
        fixture.CheckAttached(false);
        fixture.BothRespond(kDeadlineMs, WAIT_OBJECT_0);
    }
    DWORD afterHandles = 0;
    Require(GetProcessHandleCount(GetCurrentProcess(), &afterHandles) != FALSE, "read-owner-handle-count-after-detach");
    if (afterHandles != beforeHandles) { std::fprintf(stderr, "owner-handles-before=%lu after=%lu\n", beforeHandles, afterHandles); }
    Require(beforeHandles == afterHandles, "consecutive-native-attachments-release-handles");

    // Check the fixture thread from the original CREATE_PROCESS event. Its explicit
    // suspend count belongs to the test and must survive the native release.
    {
        const Handle originalThread(OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, held.pending->tid));
        Require(originalThread.Get() && GetProcessIdOfThread(originalThread.Get()) == fixture.pid,
            "fixture-owned-create-event-thread");
        const auto previous = SuspendThread(originalThread.Get());
        Require(previous != static_cast<DWORD>(-1), "independent-explicit-hold-acquired");
        second.requestId = "pause-with-external-suspend";
        auto parked = WaitForHold(native, native.Pause(second));
        done = native.Continue(ToRelease(owner, parked, "continue-with-external-suspend"));
        Require(done.clean && done.release && done.release->receipt && done.release->receipt->result == ReleaseResult::Continued,
            "native-continue-with-an-external-hold");
        Require(ResumeThread(originalThread.Get()) == previous + 1, "native-release-preserves-external-suspend-count");
        fixture.SignalBoth();
        fixture.BothRespond(kDeadlineMs, WAIT_OBJECT_0);
    }

    second.requestId = "pause-before-close";
    const auto closingStop = WaitForHold(native, native.Pause(second));
    fixture.SignalBoth();
    fixture.BothRespond(35, WAIT_TIMEOUT);
    const auto concurrentRequest = ToRelease(owner, closingStop, "continue-racing-close");
    NativeControlResult concurrentResult;
    std::thread continuing([&] { concurrentResult = native.Continue(concurrentRequest); });
    done = native.Close();
    continuing.join();
    Require(done.clean && done.status == NativeControlStatus::Closed && done.release && done.release->receipt &&
        done.release->receipt->result == ReleaseResult::Continued, "close-and-continue-arbitrate-exactly-one-release");
    Require((done.releaseRequestId == concurrentRequest.requestId && concurrentResult.clean && concurrentResult.release) ||
        (done.releaseRequestId != concurrentRequest.requestId && concurrentResult.ledgerResult == LedgerResult::Historical &&
            concurrentResult.releaseRequestId == done.releaseRequestId), "one-native-receipt-across-close-race");
    Require(native.Query(closingStop.group->groupId).group->state == GroupState::Released,
        "close-leaves-historical-group-queryable");
    Require(native.Close().status == NativeControlStatus::Closed, "close-idempotent");
    second.requestId = "pause-after-close";
    Require(native.Pause(second).status == NativeControlStatus::Rejected, "close-seals-new-admission");
    fixture.CheckAttached(false);
    fixture.BothRespond(kDeadlineMs, WAIT_OBJECT_0);

    auto closingOwnerKey = owner;
    closingOwnerKey.backendInstanceId = "10000000-0000-0000-0000-000000000006";
    NativeDebugOwner closingOwner(closingOwnerKey);
    Require(closingOwner.Pause(good).status == NativeControlStatus::Accepted, "close-can-race-attach-acceptance");
    const auto startedClosing = closingOwner.Close();
    Require(startedClosing.clean && startedClosing.status == NativeControlStatus::Closed, "early-close-drains-attachment");
    fixture.CheckAttached(false);
    fixture.SignalBoth();
    fixture.BothRespond(kDeadlineMs, WAIT_OBJECT_0);

    fixture.Exit();
    NativeDebugOwner endedOwner(owner);
    Require(endedOwner.Pause(second).status == NativeControlStatus::Rejected, "exited-original-instance-rejected");
    Require(endedOwner.Close().clean, "close-with-no-owned-event");
    TestBreakpoints(argv[0], owner);
    std::printf("RESULT=PASS checks=%u\n", checks);
    return 0;
}
