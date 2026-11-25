#include "Fixture.h"

#include <Psapi.h>
#include <array>
#include <cstdio>
#include <cwchar>
#include <stdexcept>
#include <string>
#include <vector>

namespace sb02 {
namespace {

int checks = 0;

void Require(bool ok, const char* check) {
    std::printf("ASSERT %s %s\n", ok ? "PASS" : "FAIL", check);
    if (!ok) { throw std::runtime_error(check); }
    ++checks;
}

void Win(bool ok, const char* call) {
    if (ok) { return; }
    std::printf("WIN32_FAILURE call=%s error=%lu\n", call, GetLastError());
    throw std::runtime_error(call);
}

LONG64 Qpc() {
    LARGE_INTEGER value{};
    Win(QueryPerformanceCounter(&value) != FALSE, "QueryPerformanceCounter");
    return value.QuadPart;
}

class Handle {
public:
    Handle() = default;
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() { Reset(); }
    HANDLE Get() const { return value_; }
    bool Reset(HANDLE value = nullptr) {
        const bool closed = !value_ || CloseHandle(value_) != FALSE;
        value_ = value;
        return closed;
    }
private:
    HANDLE value_ = nullptr;
};

struct LaunchAttributes {
    LaunchAttributes() {
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        Win(bytes != 0, "AttributeListSize");
        storage.resize((bytes + sizeof(void*) - 1) / sizeof(void*));
        auto* raw = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        Win(InitializeProcThreadAttributeList(raw, 1, 0, &bytes) != FALSE, "InitializeAttributeList");
        list = raw;
    }
    ~LaunchAttributes() { DeleteProcThreadAttributeList(list); }
    std::vector<void*> storage;
    LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
};

class Session {
public:
    Session(bool wow, bool success, DWORD epoch)
        : wow_(wow), success_(success), epoch_(epoch), releaseCount_(success ? 1 : 2) {}
    ~Session() { CleanupFailedRun(); }

    void Run(const std::wstring& path);

private:
    void Start(const std::wstring& path);
    bool Receive(DWORD wait);
    bool Continue(DWORD disposition) noexcept;
    void HandleException();
    bool IsStartupBreakpoint(const EXCEPTION_DEBUG_INFO& info);
    void Bind(const EXCEPTION_RECORD& record);
    void HandleGate(const EXCEPTION_DEBUG_INFO& info);
    void Hold(const char* stage, std::uintptr_t site, DWORD code, const State& before);
    State Sample() const;
    void Finish(DWORD exitCode);
    void CleanupFailedRun() noexcept;

    template<class T> T Read(std::uintptr_t address) const {
        T result{};
        SIZE_T bytes = 0;
        Win(ReadProcessMemory(process_.Get(), reinterpret_cast<void*>(address), &result, sizeof(T), &bytes) != FALSE,
            "ReadOwnFixtureMemory");
        Require(bytes == sizeof(T), "complete_fixed_size_read");
        return result;
    }

    void ValidateImageRange(std::uintptr_t address, SIZE_T bytes, bool executable) const;
    std::uintptr_t StoppedPc() const;

    const bool wow_;
    const bool success_;
    const DWORD epoch_;
    const LONG releaseCount_;
    Handle job_;
    Handle process_;
    Handle mainThread_;
    DWORD pid_ = 0;
    DWORD tid_ = 0;
    DWORD workerTid_ = 0;
    bool workerExited_ = false;
    bool pending_ = false;
    bool exitContinued_ = false;
    bool startupNative_ = false;
    bool startupWow_ = false;
    DEBUG_EVENT event_{};
    LONG64 receiveQpc_ = 0;
    std::uintptr_t image_ = 0;
    std::uintptr_t state_ = 0;
    std::uintptr_t enter_ = 0;
    std::uintptr_t return_ = 0;
    std::uintptr_t foreign_ = 0;
    LONG stage_ = 0;
    LONG enterHeartbeat_ = 0;
    LONG returnHeartbeat_ = 0;
    DWORD result_ = kNoResult;
    DWORD lastError_ = kNoResult;
};

void Session::Start(const std::wstring& path) {
    job_.Reset(CreateJobObjectW(nullptr, nullptr));
    Win(job_.Get() != nullptr, "CreatePrivateJob");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    Win(SetInformationJobObject(job_.Get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE, "SetPrivateJob");
    Win(QueryInformationJobObject(job_.Get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits), nullptr) != FALSE,
        "ReadPrivateJob");
    DWORD flags = 0;
    Win(GetHandleInformation(job_.Get(), &flags) != FALSE, "GetJobHandleInformation");
    Require((flags & HANDLE_FLAG_INHERIT) == 0 &&
        (limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0,
        "private_kill_job_with_noninherited_handle");

    // 创建时原子加入私有 Job。owner 在成功返回前退出也由该 Job 管理。
    LaunchAttributes attributes;
    HANDLE job = job_.Get();
    Win(UpdateProcThreadAttribute(attributes.list, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof(job), nullptr, nullptr) != FALSE,
        "SetCreateTimeJobList");
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes.list;
    PROCESS_INFORMATION created{};
    std::wstring command = L"\"" + path + L"\" --child " + (success_ ? L"success " : L"error ") + std::to_wstring(epoch_);
    Win(CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE,
        DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT | BELOW_NORMAL_PRIORITY_CLASS,
        nullptr, nullptr, &startup.StartupInfo, &created) != FALSE, "CreatePrivateFixtureUnderDebugger");
    process_.Reset(created.hProcess);
    mainThread_.Reset(created.hThread);
    pid_ = created.dwProcessId;
    tid_ = created.dwThreadId;
    std::printf("SESSION arch=%s case=%s ownerPid=%lu ownerTid=%lu childPid=%lu originTid=%lu epoch=%lu\n",
        wow_ ? "WOW64" : "x64", success_ ? "success" : "error", GetCurrentProcessId(), GetCurrentThreadId(), pid_, tid_, epoch_);
    Win(DebugSetProcessKillOnExit(TRUE) != FALSE, "DebugSetProcessKillOnExit");

    BOOL inJob = FALSE;
    Win(IsProcessInJob(process_.Get(), job_.Get(), &inJob) != FALSE, "IsProcessInPrivateJob");
    Require(inJob != FALSE && GetPriorityClass(process_.Get()) == BELOW_NORMAL_PRIORITY_CLASS, "job_and_priority_verified_before_resume");
    Require(pid_ != GetCurrentProcessId() && GetProcessId(process_.Get()) == pid_ && GetThreadId(mainThread_.Get()) == tid_ &&
        GetProcessIdOfThread(mainThread_.Get()) == pid_, "retained_exact_child_identity_and_external_owner");
    USHORT childMachine = 0;
    USHORT nativeMachine = 0;
    Win(IsWow64Process2(process_.Get(), &childMachine, &nativeMachine) != FALSE, "IsWow64Process2");
    Require(nativeMachine == IMAGE_FILE_MACHINE_AMD64 && childMachine == (wow_ ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_UNKNOWN),
        "live_child_architecture_matches_selected_image");
    std::printf("ARCHITECTURE childPid=%lu processMachine=0x%04x nativeMachine=0x%04x\n", pid_,
        static_cast<unsigned>(childMachine), static_cast<unsigned>(nativeMachine));
    Require(ResumeThread(mainThread_.Get()) == 1, "initial_suspend_count_exactly_one");
}

bool Session::Receive(DWORD wait) {
    if (!WaitForDebugEvent(&event_, wait)) { return false; }
    pending_ = true;
    // hFile 由调试器关闭。事件中的进程和线程句柄由 Windows 在相应退出事件继续后关闭。
    HANDLE file = nullptr;
    if (event_.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) { file = event_.u.CreateProcessInfo.hFile; }
    if (event_.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) { file = event_.u.LoadDll.hFile; }
    if (file && !CloseHandle(file)) { std::printf("EVENT_FILE_CLOSE_FAILED error=%lu\n", GetLastError()); }
    return true;
}

bool Session::Continue(DWORD disposition) noexcept {
    if (!pending_ || event_.dwProcessId != pid_) { return false; }
    if (!ContinueDebugEvent(pid_, event_.dwThreadId, disposition)) { return false; }
    exitContinued_ = event_.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT;
    pending_ = false;
    return true;
}

void Session::ValidateImageRange(std::uintptr_t address, SIZE_T bytes, bool executable) const {
    MEMORY_BASIC_INFORMATION info{};
    Require(address != 0 && VirtualQueryEx(process_.Get(), reinterpret_cast<void*>(address), &info, sizeof(info)) == sizeof(info),
        "declared_address_resolves_in_own_child");
    const auto offset = address - reinterpret_cast<std::uintptr_t>(info.BaseAddress);
    const DWORD protection = executable ? PAGE_EXECUTE_READ : PAGE_READWRITE;
    Require(info.AllocationBase == reinterpret_cast<void*>(image_) && info.Type == MEM_IMAGE && info.State == MEM_COMMIT &&
        info.Protect == protection && offset < info.RegionSize && bytes <= info.RegionSize - offset,
        "declared_range_in_expected_child_image_section");
}

void Session::Bind(const EXCEPTION_RECORD& record) {
    const auto* args = record.ExceptionInformation;
    Require(image_ != 0 && !state_ && workerTid_ && !workerExited_ && record.NumberParameters == ReadyArgCount &&
        args[EpochArg] == epoch_ && args[VersionArg] == kVersion, "route_offer_matches_current_child_epoch_and_version");
    enter_ = args[EnterArg];
    return_ = args[ReturnArg];
    foreign_ = args[ForeignArg];
    const auto address = args[StateArg];
    Require(enter_ != return_ && enter_ != foreign_ && return_ != foreign_ && address % alignof(State) == 0,
        "fixture_addresses_are_distinct_and_slot_aligned");
    for (auto site : {enter_, return_, foreign_}) {
        ValidateImageRange(site, 2, true);
        Require(Read<std::array<unsigned char, 2>>(site) == std::array<unsigned char, 2>{0xcc, 0xc3}, "gate_has_int3_then_ret");
    }
    ValidateImageRange(address, sizeof(State), false);
    const auto initial = Read<State>(address);
    Require(initial.workerTid == workerTid_ && initial.heartbeat > 0 && initial.hit.sequence == 0 && initial.originalCalls == 0,
        "initial_state_and_running_worker_match_native_create_thread_event");
    state_ = address;
    std::printf("ROUTE pid=%lu originTid=%lu workerTid=%lu image=0x%llx state=0x%llx enter=0x%llx return=0x%llx foreign=0x%llx\n",
        pid_, tid_, workerTid_, image_, state_, enter_, return_, foreign_);
    Win(Continue(DBG_CONTINUE), "ConfirmRouteAndContinue");
}

bool Session::IsStartupBreakpoint(const EXCEPTION_DEBUG_INFO& info) {
    const auto& record = info.ExceptionRecord;
    const bool wowCode = record.ExceptionCode == kWow64Breakpoint;
    if (state_ || event_.dwThreadId != tid_ || info.dwFirstChance != 1 ||
        (record.ExceptionCode != EXCEPTION_BREAKPOINT && !(wow_ && wowCode))) { return false; }
    bool& seen = wowCode ? startupWow_ : startupNative_;
    wchar_t name[MAX_PATH]{};
    const DWORD length = K32GetMappedFileNameW(process_.Get(), record.ExceptionAddress, name, MAX_PATH);
    const auto* leaf = wcsrchr(name, L'\\');
    if (seen || !length || length >= MAX_PATH || !leaf || _wcsicmp(leaf, L"\\ntdll.dll") != 0) { return false; }
    seen = true;
    std::printf("LOADER pid=%lu code=0x%08lx site=%p module=%ls\n", pid_, record.ExceptionCode, record.ExceptionAddress, name);
    return true;
}

std::uintptr_t Session::StoppedPc() const {
    if (wow_) {
        WOW64_CONTEXT context{};
        context.ContextFlags = WOW64_CONTEXT_CONTROL;
        Win(Wow64GetThreadContext(mainThread_.Get(), &context) != FALSE, "Wow64GetThreadContext");
        return context.Eip;
    }
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    Win(GetThreadContext(mainThread_.Get(), &context) != FALSE, "GetThreadContext");
    return context.Rip;
}

State Session::Sample() const {
    const auto before = Read<LONG>(state_);
    const auto sample = Read<State>(state_);
    const auto after = Read<LONG>(state_);
    Require(before == sample.hit.sequence && before == after, "published_slot_stable_without_waiting_on_paused_writer");
    return sample;
}

void Session::Hold(const char* stage, std::uintptr_t site, DWORD code, const State& before) {
    Require(!workerExited_ && workerTid_ == before.workerTid, "worker_alive_when_origin_event_is_held");
    Sleep(40);
    const auto after = Sample();
    Require(after.heartbeat == before.heartbeat && after.originalCalls == before.originalCalls &&
        after.callerReached == before.callerReached && after.hit.sequence == before.hit.sequence,
        "paused_worker_and_call_boundary_stay_unchanged_until_continue");
    const LONG64 releaseQpc = Qpc();
    Require(before.hit.publishedQpc > 0 && before.hit.publishedQpc <= receiveQpc_ && receiveQpc_ < releaseQpc,
        "published_received_release_qpc_order");
    Win(Continue(DBG_CONTINUE), "ReleaseExactPendingGate");
    std::printf("STOP pid=%lu phase=%s tid=%lu code=0x%08lx site=0x%llx pc=0x%llx sequence=%ld originalCalls=%lu "
        "callerReached=%lu result=%lu lastError=%lu heartbeat=%ld/%ld publishedQpc=%lld receiveQpc=%lld "
        "continueBeginQpc=%lld continueReturnedQpc=%lld\n", pid_, stage, tid_, code, site, site + 1, before.hit.sequence,
        before.originalCalls, before.callerReached, before.hit.result, before.hit.lastError, before.heartbeat, after.heartbeat,
        before.hit.publishedQpc, receiveQpc_, releaseQpc, Qpc());
}

void Session::HandleGate(const EXCEPTION_DEBUG_INFO& info) {
    const auto code = info.ExceptionRecord.ExceptionCode;
    const auto site = reinterpret_cast<std::uintptr_t>(info.ExceptionRecord.ExceptionAddress);
    Require(info.dwFirstChance == 1 && event_.dwThreadId == tid_ &&
        (code == EXCEPTION_BREAKPOINT || (wow_ && code == kWow64Breakpoint)), "first_chance_breakpoint_on_bound_origin_thread");
    Require(StoppedPc() == site + 1, "precompiled_int3_pc_at_ret_no_context_change");
    const auto sample = Sample();
    const auto& hit = sample.hit;
    Require(hit.version == kVersion && hit.size == sizeof(Hit) && hit.tid == tid_ && hit.releaseCount == releaseCount_,
        "slot_version_size_origin_and_fixed_argument_match");

    const bool owned = hit.epoch == epoch_ &&
        ((site == enter_ && hit.phase == Phase::Enter && hit.sequence == kEnterSequence) ||
         (site == return_ && hit.phase == Phase::Return && hit.sequence == kReturnSequence));
    if (!owned && site == enter_ && stage_ == 0) {
        Require(hit.epoch == (epoch_ ^ 1) && hit.phase == Phase::Enter && hit.sequence == kStaleSequence && sample.originalCalls == 0,
            "same_site_stale_epoch_rejected");
        stage_ = 1;
        Win(Continue(DBG_EXCEPTION_NOT_HANDLED), "ForwardStaleGateToFixtureSeh");
        std::printf("FORWARD pid=%lu kind=stale_epoch code=0x%08lx site=0x%llx epoch=%lu sequence=%ld disposition=NOT_HANDLED\n",
            pid_, code, site, hit.epoch, hit.sequence);
        return;
    }
    if (!owned && site == foreign_ && stage_ == 3) {
        Require(hit.epoch == epoch_ && hit.sequence == kReturnSequence && hit.phase == Phase::Return,
            "different_site_rejected_even_with_valid_return_slot");
        Require(sample.originalCalls == 1 && sample.callerReached == 1 && sample.callerResult == result_ &&
            sample.callerError == lastError_ && sample.entryErrorSeen == kEntryError && sample.heartbeat > returnHeartbeat_ &&
            sample.foreignDelivered == 0 && sample.semaphoreProbe == (success_ ? WAIT_OBJECT_0 : WAIT_TIMEOUT),
            "caller_observed_preserved_result_error_and_actual_semaphore_state_after_continue");
        stage_ = 4;
        Win(Continue(DBG_EXCEPTION_NOT_HANDLED), "ForwardForeignGateToFixtureSeh");
        std::printf("FORWARD pid=%lu kind=foreign code=0x%08lx site=0x%llx disposition=NOT_HANDLED "
            "originalCalls=%lu callerReached=%lu callerResult=%lu callerError=%lu entryErrorSeen=%lu semaphoreProbe=%lu heartbeat=%ld\n",
            pid_, code, site, sample.originalCalls, sample.callerReached, sample.callerResult, sample.callerError,
            sample.entryErrorSeen, sample.semaphoreProbe, sample.heartbeat);
        return;
    }
    if (owned && site == enter_ && stage_ == 1) {
        Require(sample.originalCalls == 0 && sample.callerReached == 0 && sample.staleDelivered == 1 &&
            hit.result == kNoResult && hit.lastError == kEntryError, "entry_holds_before_original_call_and_stale_exception_reached_local_seh");
        enterHeartbeat_ = sample.heartbeat;
        stage_ = 2;
        Hold("call-enter", site, code, sample);
        return;
    }
    Require(owned && site == return_ && stage_ == 2, "only_expected_bound_return_gate_can_be_owned_now");
    Require(sample.originalCalls == 1 && sample.callerReached == 0 && sample.heartbeat > enterHeartbeat_ &&
        (success_ ? hit.result == TRUE : hit.result == FALSE && hit.lastError == ERROR_TOO_MANY_POSTS),
        "return_holds_real_api_outcome_after_one_call_before_caller");
    returnHeartbeat_ = sample.heartbeat;
    result_ = hit.result;
    lastError_ = hit.lastError;
    stage_ = 3;
    Hold("call-return", site, code, sample);
}

void Session::HandleException() {
    const auto& info = event_.u.Exception;
    if (IsStartupBreakpoint(info)) {
        Win(Continue(DBG_CONTINUE), "ContinueKnownLoaderBreakpoint");
    } else if (info.ExceptionRecord.ExceptionCode == kReadyException && info.dwFirstChance == 1 && event_.dwThreadId == tid_) {
        Bind(info.ExceptionRecord);
    } else if (state_ && event_.dwThreadId == tid_ && info.dwFirstChance == 1 &&
        (info.ExceptionRecord.ExceptionAddress == reinterpret_cast<void*>(enter_) ||
         info.ExceptionRecord.ExceptionAddress == reinterpret_cast<void*>(return_) ||
         info.ExceptionRecord.ExceptionAddress == reinterpret_cast<void*>(foreign_))) {
        HandleGate(info);
    } else {
        std::printf("UNEXPECTED pid=%lu tid=%lu code=0x%08lx chance=%lu site=%p\n", pid_, event_.dwThreadId,
            info.ExceptionRecord.ExceptionCode, info.dwFirstChance, info.ExceptionRecord.ExceptionAddress);
        Win(Continue(DBG_EXCEPTION_NOT_HANDLED), "ForwardUnclassifiedException");
        throw std::runtime_error("unclassified exception in fixed fixture");
    }
}

void Session::Finish(DWORD exitCode) {
    Win(Continue(DBG_CONTINUE), "ContinueExitProcessEvent");
    const DWORD wait = WaitForSingleObject(process_.Get(), 1500);
    DWORD native = STILL_ACTIVE;
    Win(GetExitCodeProcess(process_.Get(), &native) != FALSE, "ReadNativeExitCode");
    Require(wait == WAIT_OBJECT_0 && native == exitCode, "exit_event_continued_process_signaled_and_codes_match");
    const bool closed = mainThread_.Reset() & process_.Reset() & job_.Reset();
    Require(closed, "own_process_thread_and_job_handles_closed");
    std::printf("CLEANUP childPid=%lu exitEvent=%lu nativeExit=%lu signaled=1 forced=0 ownedHandles=0\n", pid_, exitCode, native);
    Require(stage_ == 4 && workerExited_ && exitCode == 0, "worker_joined_and_fixture_confirms_foreign_exception_delivered_to_seh");
}

void Session::Run(const std::wstring& path) {
    Start(path);
    const ULONGLONG deadline = GetTickCount64() + 10000;
    while (GetTickCount64() < deadline) {
        if (!Receive(50)) {
            const DWORD error = GetLastError();
            if (error == ERROR_SEM_TIMEOUT) { continue; }
            Win(false, "WaitForDebugEvent");
        }
        receiveQpc_ = Qpc();
        Require(event_.dwProcessId == pid_, "native_event_pid_matches_retained_child");
        if (event_.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            HandleException();
            continue;
        }
        switch (event_.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            Require(!image_ && event_.dwThreadId == tid_, "create_event_matches_owned_main_thread");
            image_ = reinterpret_cast<std::uintptr_t>(event_.u.CreateProcessInfo.lpBaseOfImage);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            // WOW64 启动阶段可能产生辅助线程，只有最后握手回报的线程才是心跳见证。
            if (!state_) { workerTid_ = event_.dwThreadId; workerExited_ = false; }
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            if (event_.dwThreadId == workerTid_) { workerExited_ = true; }
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            Finish(event_.u.ExitProcess.dwExitCode);
            return;
        }
        Win(Continue(DBG_CONTINUE), "ContinueNonExceptionEvent");
    }
    throw std::runtime_error("10-second owned child session deadline");
}

void Session::CleanupFailedRun() noexcept {
    if (!process_.Get()) { return; }
    // 异常路径仅终止 CreateProcess 返回的精确对象，继续并排空其退出事件。
    const bool alreadyExiting = exitContinued_ || (pending_ && event_.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT);
    const bool forced = !alreadyExiting && TerminateProcess(process_.Get(), 91) != FALSE;
    const ULONGLONG deadline = GetTickCount64() + 1800;
    while (!exitContinued_ && GetTickCount64() < deadline) {
        if (!pending_ && !Receive(50)) { continue; }
        if (!Continue(event_.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE)) { break; }
    }
    const bool jobClosed = job_.Reset();
    const bool signaled = WaitForSingleObject(process_.Get(), 1500) == WAIT_OBJECT_0;
    const bool handlesClosed = mainThread_.Reset() & process_.Reset() & jobClosed;
    std::printf("FAIL_CLEANUP childPid=%lu exitContinued=%d signaled=%d forced=%d handlesClosed=%d\n", pid_,
        exitContinued_, signaled, forced, handlesClosed);
}

}  // namespace

int RunOwner() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    try {
        wchar_t module[32768]{};
        const auto count = GetModuleFileNameW(nullptr, module, static_cast<DWORD>(std::size(module)));
        Require(count && count < std::size(module), "fixed_owner_image_path");
        const std::wstring owner(module, count);
        const auto sibling = owner.substr(0, owner.find_last_of(L'\\') + 1) + L"ActionAnalyzeSyncStopValidationX86.exe";
        LARGE_INTEGER frequency{};
        Win(QueryPerformanceFrequency(&frequency) != FALSE, "QueryPerformanceFrequency");
        std::printf("OWNER pid=%lu tid=%lu priority=0x%lx qpcFrequency=%lld\n", GetCurrentProcessId(), GetCurrentThreadId(),
            GetPriorityClass(GetCurrentProcess()), frequency.QuadPart);
        DWORD epoch = (GetCurrentProcessId() & 0x00ffffffUL) * 16 + 2;
        for (bool wow : {false, true}) {
            for (bool success : {true, false}) {
                Session(wow, success, epoch++).Run(wow ? sibling : owner);
            }
        }
        std::printf("RESULT=PASS sessions=4 assertions=%d\n", checks);
        return 0;
    } catch (const std::exception& e) {
        std::printf("RESULT=FAIL assertions=%d error=%s\n", checks, e.what());
        return 1;
    }
}

}  // namespace sb02
