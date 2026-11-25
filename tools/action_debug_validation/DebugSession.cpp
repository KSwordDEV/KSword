#include "DebugSession.h"
#include <algorithm>
#include <cstdio>
#include <stdexcept>

namespace validation {
namespace { int failures = 0; int handles = 0; }
void Require(bool condition, const char* text) {
    std::printf("ASSERT %s %s\n", condition ? "PASS" : "FAIL", text);
    if (!condition) { ++failures; throw std::runtime_error(text); }
}
void Check(BOOL success, const char* operation) {
    if (!success) {
        const DWORD error = GetLastError();
        std::printf("WIN32_FAILURE operation=%s error=%lu\n", operation, error);
        throw std::runtime_error(operation);
    }
}
int FailureCount() { return failures; }
Handle::Handle(HANDLE value) noexcept { reset(value); }
Handle::~Handle() { reset(); }
void Handle::reset(HANDLE value) noexcept {
    if (value_) { CloseHandle(value_); --handles; }
    value_ = value;
    if (value_) { ++handles; }
}
int Handle::Count() noexcept { return handles; }

DebugSession::DebugSession(const char* scenario, bool controlledException) : scenario_(scenario) {
    // Constructor failures still require precise child cleanup before members close.
    try { Launch(controlledException); }
    catch (...) { Cleanup(); throw; }
}
void DebugSession::Launch(bool controlledException) {
    deadline_ = GetTickCount64() + 12000;
    job_.reset(CreateJobObjectW(nullptr, nullptr));
    Check(job_.get() != nullptr, "CreateJobObject");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    Check(SetInformationJobObject(job_.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)), "SetJobLimits");
    wchar_t path[32768]{};
    const DWORD length = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    Check(length != 0 && length < std::size(path), "GetModuleFileName");
    std::wstring command = L"\"" + std::wstring(path) + L"\" --child ";
    command += controlledException ? L"fault" : L"normal";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION info{};
    Check(CreateProcessW(path, command.data(), nullptr, nullptr, FALSE,
        DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &info), "CreateProcessSelf");
    process_.reset(info.hProcess);
    thread_.reset(info.hThread);
    pid_ = info.dwProcessId;
    tid_ = info.dwThreadId;
    std::printf("SESSION scenario=%s pid=%lu tid=%lu\n", scenario_, pid_, tid_);
    Check(AssignProcessToJobObject(job_.get(), process_.get()), "AssignJobBeforeResume");
    BOOL inJob = FALSE;
    DWORD handleFlags = HANDLE_FLAG_INHERIT;
    Check(IsProcessInJob(process_.get(), job_.get(), &inJob), "IsProcessInJob");
    Check(GetHandleInformation(job_.get(), &handleFlags), "GetJobHandleFlags");
    Check(QueryInformationJobObject(job_.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits), nullptr), "ReadJobLimits");
    Require(inJob && !(handleFlags & HANDLE_FLAG_INHERIT) &&
        (limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE),
        "private_noninherited_kill_job_assigned_before_first_resume");
    std::printf("JOB_GUARD scenario=%s assigned=1 inherited=0 killOnClose=1\n", scenario_);
    Require(ResumeThread(thread_.get()) == 1, "initial_suspend_count_exactly_one");
    if (!NextEvent() || event_.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT) {
        throw std::runtime_error("Expected create-process event");
    }
    imageBase_ = reinterpret_cast<std::uintptr_t>(event_.u.CreateProcessInfo.lpBaseOfImage);
    CloseEventHandles();
    Require(GetProcessId(process_.get()) == pid_ && GetThreadId(thread_.get()) == tid_ &&
        GetProcessIdOfThread(thread_.get()) == pid_, "retained_self_child_process_and_main_thread_identity");
}
DebugSession::~DebugSession() { Cleanup(); }
std::uintptr_t DebugSession::Address(const unsigned char* localLabel) const {
    return imageBase_ + reinterpret_cast<std::uintptr_t>(localLabel) -
        reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
}
unsigned char DebugSession::ReadByte(std::uintptr_t address) const {
    unsigned char value = 0;
    SIZE_T bytes = 0;
    Check(ReadProcessMemory(process_.get(), reinterpret_cast<const void*>(address), &value, sizeof(value), &bytes), "ReadByte");
    if (bytes != sizeof(value)) { throw std::runtime_error("Short byte read"); }
    return value;
}
std::uintptr_t DebugSession::ReadPointer(std::uintptr_t address) const {
    std::uintptr_t value = 0;
    SIZE_T bytes = 0;
    Check(ReadProcessMemory(process_.get(), reinterpret_cast<const void*>(address), &value, sizeof(value), &bytes), "ReadKnownStackReturn");
    if (bytes != sizeof(value)) { throw std::runtime_error("Short stack read"); }
    return value;
}
void DebugSession::WriteByte(std::uintptr_t address, unsigned char value) {
    DWORD oldProtection = 0;
    auto* target = reinterpret_cast<void*>(address);
    Check(VirtualProtectEx(process_.get(), target, 1, PAGE_EXECUTE_READWRITE, &oldProtection), "ProtectOwnImageByte");
    SIZE_T bytes = 0;
    const BOOL written = WriteProcessMemory(process_.get(), target, &value, 1, &bytes);
    const DWORD writeError = GetLastError();
    DWORD discarded = 0;
    Check(VirtualProtectEx(process_.get(), target, 1, oldProtection, &discarded), "RestoreOwnImageProtection");
    if (!written || bytes != 1) { SetLastError(writeError); Check(FALSE, "WriteOwnBreakpointByte"); }
    Check(FlushInstructionCache(process_.get(), target, 1), "FlushOwnInstructionCache");
    if (ReadByte(address) != value) { throw std::runtime_error("Breakpoint write readback mismatch"); }
}
void DebugSession::Arm(std::uintptr_t address, Reason reason) {
    if (!pending_) { throw std::runtime_error("Breakpoint change requires held event"); }
    auto item = std::find_if(breakpoints_.begin(), breakpoints_.end(), [address](const auto& bp) { return bp.address == address; });
    if (item == breakpoints_.end()) {
        breakpoints_.push_back({address, ReadByte(address), reason, false});
        item = breakpoints_.end() - 1;
    }
    if (item->armed || item->original == 0xcc) { throw std::runtime_error("Refuse overlapping or original INT3"); }
    item->reason = reason;
    // Record responsibility before the first write, including its failure path.
    item->armed = true;
    WriteByte(address, 0xcc);
}
void DebugSession::Remove(std::uintptr_t address) {
    for (auto& bp : breakpoints_) {
        if (bp.address == address && bp.armed) { WriteByte(bp.address, bp.original); bp.armed = false; }
    }
}
void DebugSession::CancelTemporary() {
    for (auto& bp : breakpoints_) {
        if (bp.armed && bp.reason == Reason::TemporaryBreakpoint) { Remove(bp.address); }
    }
}
bool DebugSession::IsOriginal(std::uintptr_t address) const {
    for (const auto& bp : breakpoints_) {
        if (bp.address == address) { return !bp.armed && ReadByte(address) == bp.original; }
    }
    return false;
}
bool DebugSession::NextEvent() {
    if (pending_) { throw std::runtime_error("Previous event still held"); }
    while (GetTickCount64() < deadline_) {
        if (WaitForDebugEvent(&event_, 100)) {
            if (event_.dwProcessId != pid_) { throw std::runtime_error("Unexpected debug process"); }
            pending_ = true;
            return true;
        }
        if (GetLastError() != ERROR_SEM_TIMEOUT) { Check(FALSE, "WaitForDebugEvent"); }
    }
    throw std::runtime_error("12-second session deadline");
}
void DebugSession::CloseEventHandles() {
    if (event_.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
        const auto& info = event_.u.CreateProcessInfo;
        if (info.hFile) { CloseHandle(info.hFile); }
        // Windows owns these event process/thread handles until the corresponding
        // EXIT event is continued. Keep our separate CreateProcess handles only.
    } else if (event_.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
        if (event_.u.LoadDll.hFile) { CloseHandle(event_.u.LoadDll.hFile); }
    }
}
void DebugSession::Continue(DWORD disposition) {
    if (!pending_) { throw std::runtime_error("Continue requires held event"); }
    Check(ContinueDebugEvent(pid_, event_.dwThreadId, disposition), "ContinueDebugEvent");
    pending_ = false;
}
void DebugSession::SetContext(CONTEXT context) {
    if (!pending_ || event_.dwThreadId != tid_) { throw std::runtime_error("Context requires held main-thread event"); }
    Check(SetThreadContext(thread_.get(), &context), "SetMainThreadContext");
}
Stop DebugSession::WaitStop() {
    if (pending_) { Continue(); }
    while (NextEvent()) {
        CloseEventHandles();
        if (event_.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            exited_ = true; exitCode_ = event_.u.ExitProcess.dwExitCode;
            throw std::runtime_error("Child exited before expected stop");
        }
        if (event_.dwDebugEventCode != EXCEPTION_DEBUG_EVENT) { Continue(); continue; }
        const auto& exception = event_.u.Exception;
        const DWORD code = exception.ExceptionRecord.ExceptionCode;
        const auto address = reinterpret_cast<std::uintptr_t>(exception.ExceptionRecord.ExceptionAddress);
        auto item = std::find_if(breakpoints_.begin(), breakpoints_.end(), [address](const auto& bp) { return bp.armed && bp.address == address; });
        if (code == EXCEPTION_BREAKPOINT && item == breakpoints_.end() && !loaderBreakpointSeen_) {
            loaderBreakpointSeen_ = true;
            std::printf("LOADER_BREAKPOINT scenario=%s address=0x%llx\n", scenario_, static_cast<unsigned long long>(address));
            Continue(); continue;
        }
        Require(event_.dwThreadId == tid_, "actual_stop_belongs_to_selected_main_thread");
        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        Check(GetThreadContext(thread_.get(), &context), "GetStoppedMainContext");
        const DWORD rawFlags = context.EFlags;
        context.EFlags &= ~0x100UL;
        Reason reason = code == EXCEPTION_SINGLE_STEP ? Reason::SingleStep : Reason::Exception;
        if (code == EXCEPTION_BREAKPOINT && item != breakpoints_.end()) {
            reason = item->reason;
            Require(context.Rip == address + 1, "int3_context_is_one_byte_past_owned_breakpoint");
            Remove(address);
            context.Rip = address;
        }
        SetContext(context);
        std::printf("STOP scenario=%s reason=%u code=0x%08lx firstChance=%lu tid=%lu address=0x%llx rip=0x%llx rsp=0x%llx rawFlags=0x%lx restoredFlags=0x%lx\n",
            scenario_, static_cast<unsigned>(reason), code, exception.dwFirstChance, event_.dwThreadId,
            static_cast<unsigned long long>(address), context.Rip, context.Rsp, rawFlags, context.EFlags);
        return {reason, code, event_.dwThreadId, exception.dwFirstChance, address, context};
    }
    throw std::runtime_error("No stop");
}
void DebugSession::Step() {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    Check(GetThreadContext(thread_.get(), &context), "GetBeforeTF");
    context.EFlags |= 0x100UL;
    SetContext(context);
    Continue();
}
void DebugSession::Finish() {
    for (const auto& bp : breakpoints_) {
        Require(!bp.armed && ReadByte(bp.address) == bp.original, "original_breakpoint_byte_restored_before_final_continue");
    }
    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    Check(GetThreadContext(thread_.get(), &context), "ReadFinalFlags");
    Require(!(context.EFlags & 0x100), "no_owned_trap_flag_before_final_continue");
    Continue();
    while (NextEvent()) {
        CloseEventHandles();
        if (event_.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            exited_ = true; exitCode_ = event_.u.ExitProcess.dwExitCode; Continue(); break;
        }
        if (event_.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) { throw std::runtime_error("Unexpected exception during finish"); }
        Continue();
    }
    Require(exitCode_ == 0, "benign_child_returned_42_and_exited_zero");
}
void DebugSession::AbortForCleanupTest() { expectedAbort_ = true; }
void DebugSession::Cleanup() noexcept {
    if (!process_.get()) { return; }
    bool cleanupOk = true;
    bool forced = false;
    try {
        if (!exited_) {
            if (pending_) {
                for (auto& bp : breakpoints_) {
                    if (bp.armed) { Remove(bp.address); }
                    Require(IsOriginal(bp.address), "abort_cleanup_restores_each_owned_breakpoint_byte");
                }
                if (event_.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && event_.dwThreadId == tid_) {
                    CONTEXT context{}; context.ContextFlags = CONTEXT_FULL;
                    Check(GetThreadContext(thread_.get(), &context), "CleanupGetContext");
                    context.EFlags &= ~0x100UL; SetContext(context);
                    Check(GetThreadContext(thread_.get(), &context), "CleanupReadBackContext");
                    Require(!(context.EFlags & 0x100), "abort_cleanup_reads_back_cleared_owned_trap_flag");
                }
            }
            Check(TerminateProcess(process_.get(), 99), "TerminateExactOwnedChild");
            forced = true;
        }
        if (pending_) { Continue(); }
        const ULONGLONG cleanupDeadline = GetTickCount64() + 2500;
        while (!exited_ && GetTickCount64() < cleanupDeadline) {
            if (!WaitForDebugEvent(&event_, 50)) { continue; }
            pending_ = true;
            CloseEventHandles();
            if (event_.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                exited_ = true; exitCode_ = event_.u.ExitProcess.dwExitCode;
            }
            Continue();
        }
        const bool signaled = WaitForSingleObject(process_.get(), 500) == WAIT_OBJECT_0;
        DWORD nativeExit = STILL_ACTIVE;
        Check(GetExitCodeProcess(process_.get(), &nativeExit), "CleanupReadNativeExit");
        cleanupOk = exited_ && signaled && nativeExit == exitCode_ && !pending_;
        // ActiveProcesses is decremented only after exit AND all process
        // references are released, including references outside this fixture.
        // Read it after closing ours, but do not confuse accounting with liveness.
        thread_.reset(); process_.reset();
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
        Check(QueryInformationJobObject(job_.get(), JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), nullptr), "CleanupReadJobActiveCount");
        std::printf("CLEANUP scenario=%s pid=%lu exited=%u exit=%lu forced=%u expectedAbort=%u jobActive=%lu pending=%u signaled=%u nativeExit=%lu retainedProcessHandles=0\n",
            scenario_, pid_, exited_ ? 1U : 0U, exitCode_, forced ? 1U : 0U, expectedAbort_ ? 1U : 0U,
            accounting.ActiveProcesses, pending_ ? 1U : 0U, signaled ? 1U : 0U, nativeExit);
        Require(cleanupOk && (!forced || expectedAbort_), "owned_child_signaled_native_exit_matches_event_and_expected_policy");
    } catch (const std::exception& error) {
        cleanupOk = false;
        std::printf("CLEANUP_ERROR scenario=%s detail=%s\n", scenario_, error.what());
    }
    if (!cleanupOk) { ++failures; }
    // Last-resort Job close can kill only the exact child assigned above.
    job_.reset(); thread_.reset(); process_.reset();
}
}
