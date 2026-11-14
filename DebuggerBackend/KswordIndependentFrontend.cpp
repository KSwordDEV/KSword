#include "KswordDebuggerBackend.h"
#include "../shared/driver/KswordArkKernelNoAttachIoctl.h"

#include <TlHelp32.h>
#include <algorithm>
#include <cstring>
#include <limits>

namespace ksword::debugger
{
    namespace
    {
        constexpr DWORD transitionTimeout = 3000;
        constexpr DWORD waitInterval = 5;

        std::uint64_t fileTime(const FILETIME& value)
        { return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime; }

        DWORD win32Status(long status)
        {
            if (status >= 0) return ERROR_SUCCESS;
            using Convert = ULONG (WINAPI*)(LONG);
            const auto convert = reinterpret_cast<Convert>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
            return convert ? convert(status) : ERROR_GEN_FAILURE;
        }

        bool resultBool(DWORD error)
        { SetLastError(error); return error == ERROR_SUCCESS; }

        HANDLE duplicate(HANDLE handle)
        {
            HANDLE result = nullptr;
            return DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &result, 0, FALSE,
                DUPLICATE_SAME_ACCESS) ? result : nullptr;
        }

        bool noWindowsDebugRelationship(HANDLE process)
        {
            using Query = LONG (NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
            const auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
            ULONG_PTR port = ~ULONG_PTR{0};
            return query && query(process, 7, &port, sizeof(port), nullptr) >= 0 && port == 0;
        }

        bool nativeX64(HANDLE process)
        {
            using Query = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
            const auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
            USHORT image = 0, machine = 0;
            return query && query(process, &image, &machine) && image == IMAGE_FILE_MACHINE_UNKNOWN &&
                machine == IMAGE_FILE_MACHINE_AMD64;
        }

        KSWORD_ARK_HVM_NOATTACH_GPR registers(const CONTEXT& source)
        {
            return {source.Rax, source.Rcx, source.Rdx, source.Rbx, source.Rbp, source.Rsi, source.Rdi,
                source.R8, source.R9, source.R10, source.R11, source.R12, source.R13, source.R14, source.R15,
                source.Rip, source.Rsp};
        }

        void project(CONTEXT& destination, const KSWORD_ARK_HVM_NOATTACH_RESPONSE& source)
        {
            destination.Rax = source.rax; destination.Rcx = source.rcx; destination.Rdx = source.rdx; destination.Rbx = source.rbx;
            destination.Rbp = source.rbp; destination.Rsi = source.rsi; destination.Rdi = source.rdi;
            destination.R8 = source.r8; destination.R9 = source.r9; destination.R10 = source.r10; destination.R11 = source.r11;
            destination.R12 = source.r12; destination.R13 = source.r13; destination.R14 = source.r14; destination.R15 = source.r15;
            destination.Rip = source.rip; destination.Rsp = source.rsp; destination.EFlags = static_cast<DWORD>(source.rflags);
        }
    }

    static_assert(sizeof(KSWORD_DEBUGGER_FRONTEND_REQUEST) == 32);
    static_assert(sizeof(KSWORD_DEBUGGER_FRONTEND_STATUS) == 56);

    bool IndependentFrontend::selected() const
    { std::lock_guard lock(backend_.mutex_); return command_ != 0; }
    bool IndependentFrontend::active() const
    { std::lock_guard lock(backend_.mutex_); return reserved_; }
    bool IndependentFrontend::ownsProcess(DWORD pid) const
    { std::lock_guard lock(backend_.mutex_); return reserved_ && pid != 0 && pid_ == pid; }
    bool IndependentFrontend::ownsThread(HANDLE thread) const
    { std::lock_guard lock(backend_.mutex_); return targetThread(thread); }
    DWORD IndependentFrontend::threadId() const
    { std::lock_guard lock(backend_.mutex_); return tid_; }

    void IndependentFrontend::fillStatus(KSWORD_DEBUGGER_FRONTEND_STATUS& status) const
    {
        status = {KSWORD_DEBUGGER_FRONTEND_VERSION, sizeof(status), recovery_ ? KSWORD_DEBUGGER_FRONTEND_RECOVERY :
            reserved_ ? KSWORD_DEBUGGER_FRONTEND_ACTIVE : command_ ? KSWORD_DEBUGGER_FRONTEND_ARMED : KSWORD_DEBUGGER_FRONTEND_DISABLED,
            command_, pid_ ? pid_ : configuredPid_, tid_ ? tid_ : configuredTid_, stop_.state, stop_.capabilities,
            stop_.sessionId, stop_.state == KSWORD_ARK_HVM_NOATTACH_STOPPED ? stop_.stopId : 0,
            stop_.state == KSWORD_ARK_HVM_NOATTACH_STOPPED ? stop_.stopReason : 0U, lastError_};
    }

    DWORD IndependentFrontend::control(const KSWORD_DEBUGGER_FRONTEND_REQUEST& packet, KSWORD_DEBUGGER_FRONTEND_STATUS& status)
    {
        std::lock_guard lock(backend_.mutex_);
        if (packet.version != KSWORD_DEBUGGER_FRONTEND_VERSION || packet.size != sizeof(packet) || packet.reserved != 0)
            return ERROR_REVISION_MISMATCH;
        DWORD error = ERROR_SUCCESS;
        if (packet.operation == KSWORD_DEBUGGER_FRONTEND_SELECT)
        {
            const bool kernel = packet.command == KSWORD_DEBUGGER_KERNEL_NOATTACH;
            const DWORD allowed = KSWORD_ARK_HVM_NOATTACH_CONFIRMED | (kernel ? KSWORD_ARK_KERNEL_NOATTACH_HOOK_ACK : KSWORD_ARK_HVM_NOATTACH_ALLOW_NESTED);
            if (reserved_ || backend_.noAttachReserved_ || backend_.attachedPid_ != 0 || backend_.ownsResident_ ||
                !backend_.breakpoints_.empty() || backend_.hasShadowViews()) error = ERROR_BUSY;
            else if (packet.command != 0 && (!kernel && packet.command != KSWORD_DEBUGGER_NOATTACH)) error = ERROR_INVALID_PARAMETER;
            else if (packet.command && ((packet.flags & ~allowed) != 0 || !(packet.flags & KSWORD_ARK_HVM_NOATTACH_CONFIRMED) ||
                (kernel && !(packet.flags & KSWORD_ARK_KERNEL_NOATTACH_HOOK_ACK)))) error = ERROR_ACCESS_DENIED;
            else if (packet.command && (packet.processId <= 4 || packet.threadId == 0)) error = ERROR_INVALID_PARAMETER;
            else
            {
                command_ = packet.command;
                flags_ = packet.flags;
                configuredPid_ = packet.processId;
                configuredTid_ = packet.threadId;
            }
        }
        else if (packet.operation == KSWORD_DEBUGGER_FRONTEND_CLOSE) error = close();
        else if (packet.operation == KSWORD_DEBUGGER_FRONTEND_PAUSE) error = pause();
        else if (packet.operation == KSWORD_DEBUGGER_FRONTEND_STEP_OVER_TARGET)
        {
            const auto target = (static_cast<std::uint64_t>(packet.threadId) << 32) | packet.processId;
            if (!reserved_ || stop_.state != KSWORD_ARK_HVM_NOATTACH_STOPPED || !target || target >= 0x0000800000000000ULL)
                error = ERROR_INVALID_STATE;
            else stepOverTarget_ = target;
        }
        else if (packet.operation != KSWORD_DEBUGGER_FRONTEND_QUERY) error = ERROR_INVALID_PARAMETER;
        if (packet.operation != KSWORD_DEBUGGER_FRONTEND_QUERY) lastError_ = error;
        fillStatus(status);
        return error;
    }

    DWORD IndependentFrontend::request(ULONG operation, const KSWORD_ARK_HVM_NOATTACH_REQUEST* edits)
    {
        if (!command_) return ERROR_INVALID_STATE;
        KSWORD_ARK_HVM_NOATTACH_REQUEST packet = edits ? *edits : KSWORD_ARK_HVM_NOATTACH_REQUEST{};
        packet.version = command_ == KSWORD_DEBUGGER_KERNEL_NOATTACH ? KSWORD_ARK_KERNEL_NOATTACH_VERSION : KSWORD_ARK_HVM_NOATTACH_VERSION;
        packet.size = sizeof(packet); packet.operation = operation;
        packet.sessionId = stop_.sessionId; packet.stopId = stop_.stopId;
        if (operation == KSWORD_ARK_HVM_NOATTACH_OPEN)
        {
            FILETIME created{}, exited{}, kernel{}, user{};
            packet.processId = pid_; packet.threadId = tid_; packet.flags = flags_;
            if (!GetProcessTimes(process_.native(), &created, &exited, &kernel, &user)) return GetLastError();
            packet.processCreationTime = fileTime(created);
            if (!GetThreadTimes(thread_.native(), &created, &exited, &kernel, &user)) return GetLastError();
            packet.threadCreationTime = fileTime(created);
        }
        KSWORD_ARK_HVM_NOATTACH_RESPONSE response{};
        KSWORD_DEBUGGER_CALL call{KSWORD_DEBUGGER_API_VERSION, sizeof(call), command_, 0,
            reinterpret_cast<std::uintptr_t>(&packet), reinterpret_cast<std::uintptr_t>(&response),
            sizeof(packet), sizeof(response), 0, 0};
        struct DispatchScope
        {
            bool& flag;
            explicit DispatchScope(bool& value) : flag(value) { flag = true; }
            ~DispatchScope() { flag = false; }
        } scope(backend_.independentDispatch_);
        const DWORD transport = backend_.dispatch(call);
        if (transport != ERROR_SUCCESS || call.bytesReturned != sizeof(response))
        {
            recovery_ = reserved_;
            return transport != ERROR_SUCCESS ? transport : ERROR_INVALID_DATA;
        }
        if (response.sessionId && (response.processId != pid_ || response.threadId != tid_))
        { recovery_ = true; return ERROR_INVALID_DATA; }
        if (response.status >= 0 || response.sessionId != 0) stop_ = response;
        if (response.state == KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED) recovery_ = true;
        return win32Status(response.status);
    }

    DWORD IndependentFrontend::start(DWORD pid)
    {
        std::unique_lock lock(backend_.mutex_);
        if (!command_ || reserved_ || pid != configuredPid_ || !configuredTid_) return ERROR_INVALID_STATE;
        process_.reset(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid));
        if (!process_.isValid()) return GetLastError();
        thread_.reset(::OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
            THREAD_SUSPEND_RESUME | SYNCHRONIZE, FALSE, configuredTid_));
        if (!thread_.isValid()) { const auto error = GetLastError(); resetSession(); return error; }
        if (!nativeX64(process_.native()) || !noWindowsDebugRelationship(process_.native()) ||
            GetProcessIdOfThread(thread_.native()) != pid || WaitForSingleObject(process_.native(), 0) != WAIT_TIMEOUT ||
            WaitForSingleObject(thread_.native(), 0) != WAIT_TIMEOUT)
        { resetSession(); return ERROR_NOT_SUPPORTED; }
        pid_ = pid; tid_ = configuredTid_; reserved_ = true; ++phaseGeneration_;
        DWORD error = request(KSWORD_ARK_HVM_NOATTACH_OPEN);
        if (error == ERROR_SUCCESS && stop_.sessionId == 0) error = ERROR_INVALID_DATA;
        if (error == ERROR_SUCCESS) error = request(KSWORD_ARK_HVM_NOATTACH_PAUSE);
        if (error == ERROR_SUCCESS)
        {
            KSWORD_ARK_HVM_NOATTACH_RESPONSE initial{};
            const auto generation = phaseGeneration_;
            lock.unlock();
            error = waitForStop(transitionTimeout, 0, initial);
            lock.lock();
            if (generation != phaseGeneration_) return ERROR_OPERATION_ABORTED;
        }
        if (error != ERROR_SUCCESS)
        {
            // Do not fall through to native Windows attachment on any failure.
            const auto cleanup = close();
            if (cleanup != ERROR_SUCCESS) { recovery_ = true; return cleanup; }
            return error;
        }
        backend_.log("Independent native frontend: held single thread PID=" + std::to_string(pid_) + " TID=" + std::to_string(tid_));
        return ERROR_SUCCESS;
    }

    void IndependentFrontend::resetSession()
    {
        ++phaseGeneration_;
        process_.reset(); thread_.reset(); pid_ = tid_ = 0; stop_ = {};
        reserved_ = recovery_ = stepIntent_ = false; capturedStop_ = 0; captured_ = {};
        hardware_ = {}; software_ = {}; logicalDr6_ = 0; ceEvent_ = CeEvent::none;
        ceBootstrap_ = true; ceSoftwareRip_ = false; ceDeliveredStop_ = 0;
        stepOverTarget_ = 0;
    }

    DWORD IndependentFrontend::close()
    {
        std::lock_guard lock(backend_.mutex_);
        if (!reserved_) { command_ = flags_ = configuredPid_ = configuredTid_ = 0; return ERROR_SUCCESS; }
        if (!stop_.sessionId) (void)request(KSWORD_ARK_HVM_NOATTACH_QUERY);
        const auto error = request(KSWORD_ARK_HVM_NOATTACH_CLOSE);
        if (error != ERROR_SUCCESS || stop_.sessionId != 0 || (stop_.state != KSWORD_ARK_HVM_NOATTACH_CLOSED &&
            stop_.state != KSWORD_ARK_HVM_NOATTACH_UNSUPPORTED))
        { recovery_ = true; return error != ERROR_SUCCESS ? error : ERROR_INVALID_STATE; }
        resetSession();
        command_ = flags_ = configuredPid_ = configuredTid_ = 0;
        return ERROR_SUCCESS;
    }

    DWORD IndependentFrontend::pause()
    {
        std::lock_guard lock(backend_.mutex_);
        return reserved_ && !recovery_ ? request(KSWORD_ARK_HVM_NOATTACH_PAUSE) : ERROR_INVALID_STATE;
    }

    DWORD IndependentFrontend::snapshot(KSWORD_ARK_HVM_NOATTACH_RESPONSE& snapshot)
    {
        std::lock_guard lock(backend_.mutex_);
        if (!reserved_) return ERROR_INVALID_STATE;
        const auto error = request(KSWORD_ARK_HVM_NOATTACH_QUERY);
        snapshot = stop_;
        return error;
    }

    DWORD IndependentFrontend::waitForStop(DWORD milliseconds, std::uint64_t after, KSWORD_ARK_HVM_NOATTACH_RESPONSE& response)
    {
        std::uint64_t generation;
        { std::lock_guard lock(backend_.mutex_); generation = phaseGeneration_; }
        const auto deadline = GetTickCount64() + (std::min)(milliseconds, 30000UL);
        do
        {
            {
                std::lock_guard lock(backend_.mutex_);
                if (!reserved_ || generation != phaseGeneration_) return ERROR_OPERATION_ABORTED;
                if (WaitForSingleObject(process_.native(), 0) != WAIT_TIMEOUT || WaitForSingleObject(thread_.native(), 0) != WAIT_TIMEOUT)
                    return ERROR_PROCESS_ABORTED;
                const auto error = request(KSWORD_ARK_HVM_NOATTACH_QUERY);
                if (error != ERROR_SUCCESS) return error;
                if (recovery_ || stop_.state == KSWORD_ARK_HVM_NOATTACH_EXITED || !stop_.sessionId) return ERROR_INVALID_STATE;
                if (stop_.state == KSWORD_ARK_HVM_NOATTACH_STOPPED && stop_.stopId && stop_.stopId != after)
                { response = stop_; return ERROR_SUCCESS; }
            }
            if (GetTickCount64() >= deadline) break;
            Sleep(waitInterval);
        } while (true);
        return ERROR_SEM_TIMEOUT;
    }

    DWORD IndependentFrontend::finishContextRequest()
    {
        // A kernel-DR configuration commits in the actual stopped thread.
        // It needs no frontend callback or Windows event acknowledgement.
        const auto deadline = GetTickCount64() + transitionTimeout;
        while (stop_.state == KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING && GetTickCount64() < deadline)
        {
            Sleep(1);
            const auto error = request(KSWORD_ARK_HVM_NOATTACH_QUERY);
            if (error != ERROR_SUCCESS) return error;
        }
        return stop_.state == KSWORD_ARK_HVM_NOATTACH_STOPPED && stop_.stopId ? ERROR_SUCCESS : ERROR_INVALID_STATE;
    }

    DWORD IndependentFrontend::resume(bool step, std::uint64_t runTo, std::uint64_t minimumRsp)
    {
        std::lock_guard lock(backend_.mutex_);
        if (!reserved_ || recovery_ || stop_.state != KSWORD_ARK_HVM_NOATTACH_STOPPED || !stop_.stopId) return ERROR_INVALID_STATE;
        KSWORD_ARK_HVM_NOATTACH_REQUEST edits{};
        ULONG operation = step ? KSWORD_ARK_HVM_NOATTACH_STEP : KSWORD_ARK_HVM_NOATTACH_CONTINUE;
        if (runTo)
        {
            operation = KSWORD_ARK_HVM_NOATTACH_RUN_TO;
            edits.address = runTo;
            if (minimumRsp) { edits.breakpointFlags = KSWORD_ARK_HVM_NOATTACH_BP_STACK_FILTER; edits.minimumRsp = minimumRsp; }
        }
        const auto error = request(operation, &edits);
        if (error == ERROR_SUCCESS) { capturedStop_ = 0; stepIntent_ = false; logicalDr6_ = 0; }
        return error;
    }

    DWORD IndependentFrontend::addBreakpoint(std::uint64_t address, bool once, std::uint32_t& id)
    {
        std::lock_guard lock(backend_.mutex_);
        id = 0;
        if (!reserved_ || recovery_ || stop_.state != KSWORD_ARK_HVM_NOATTACH_STOPPED || !stop_.stopId) return ERROR_INVALID_STATE;
        KSWORD_ARK_HVM_NOATTACH_REQUEST edits{};
        edits.address = address;
        if (once) edits.breakpointFlags = KSWORD_ARK_HVM_NOATTACH_BP_ONESHOT;
        DWORD error = request(KSWORD_ARK_HVM_NOATTACH_ADD_BREAKPOINT, &edits);
        if (error == ERROR_SUCCESS) error = finishContextRequest();
        if (error != ERROR_SUCCESS) return error;
        for (ULONG i = 0; i < stop_.breakpointCount; ++i)
            if (stop_.breakpoints[i].address == address && !(stop_.breakpoints[i].flags & KSWORD_ARK_HVM_NOATTACH_BP_CONSUMED))
            { id = stop_.breakpoints[i].id; return ERROR_SUCCESS; }
        recovery_ = true;
        return ERROR_INVALID_DATA;
    }

    DWORD IndependentFrontend::removeBreakpoint(std::uint32_t id)
    {
        std::lock_guard lock(backend_.mutex_);
        if (!reserved_ || recovery_ || !id || stop_.state != KSWORD_ARK_HVM_NOATTACH_STOPPED) return ERROR_INVALID_STATE;
        KSWORD_ARK_HVM_NOATTACH_REQUEST edits{}; edits.breakpointId = id;
        const auto error = request(KSWORD_ARK_HVM_NOATTACH_REMOVE_BREAKPOINT, &edits);
        return error == ERROR_SUCCESS ? finishContextRequest() : error;
    }

    bool IndependentFrontend::targetThread(HANDLE thread) const
    {
        return reserved_ && thread && thread_.isValid() && GetThreadId(thread) == tid_ &&
            GetProcessIdOfThread(thread) == pid_ && Backend::sameObject(thread, thread_.native());
    }

    DWORD IndependentFrontend::captureContext(CONTEXT& result)
    {
        if (stop_.state != KSWORD_ARK_HVM_NOATTACH_STOPPED || !stop_.stopId) return ERROR_NOT_READY;
        if (capturedStop_ != stop_.stopId)
        {
            // Suspend one selected thread briefly to read actual FP/segment
            // state. This creates no Windows debugger relationship or code.
            const auto before = stop_;
            const DWORD old = ::SuspendThread(thread_.native());
            if (old == MAXDWORD) return GetLastError();
            CONTEXT actual{}; actual.ContextFlags = CONTEXT_ALL;
            const BOOL read = ::GetThreadContext(thread_.native(), &actual);
            const auto error = read ? ERROR_SUCCESS : GetLastError();
            const auto resumed = ::ResumeThread(thread_.native());
            if (resumed == MAXDWORD || resumed == 0) { recovery_ = true; return ERROR_INVALID_STATE; }
            if (error != ERROR_SUCCESS) return error;
            const auto queried = request(KSWORD_ARK_HVM_NOATTACH_QUERY);
            if (queried != ERROR_SUCCESS) return queried;
            if (stop_.state != KSWORD_ARK_HVM_NOATTACH_STOPPED || before.sessionId != stop_.sessionId ||
                before.stopId != stop_.stopId || actual.Rip != stop_.rip || actual.Rsp != stop_.rsp) return ERROR_RETRY;
            project(actual, stop_);
            captured_ = actual; capturedStop_ = stop_.stopId;
        }
        result = captured_;
        return ERROR_SUCCESS;
    }

    DWORD IndependentFrontend::readContext(HANDLE thread, CONTEXT& context)
    {
        std::lock_guard lock(backend_.mutex_);
        if (!targetThread(thread)) return ERROR_INVALID_HANDLE;
        const auto requested = context.ContextFlags;
        if ((requested & CONTEXT_XSTATE) == CONTEXT_XSTATE) return ERROR_NOT_SUPPORTED;
        const auto error = captureContext(context);
        if (error != ERROR_SUCCESS) return error;
        context.ContextFlags = requested;
        context.Dr0 = hardware_[0].address; context.Dr1 = hardware_[1].address;
        context.Dr2 = hardware_[2].address; context.Dr3 = hardware_[3].address;
        context.Dr6 = logicalDr6_; context.Dr7 = 0x400;
        for (std::size_t i = 0; i < hardware_.size(); ++i)
            if (hardware_[i].id) context.Dr7 |= 1ULL << (2 * i);
        // CE expects to decrement RIP in its own INT3-shaped event handler.
        if (ceSoftwareRip_ && ceEvent_ == CeEvent::stop) ++context.Rip;
        if (ceEvent_ == CeEvent::initial) ++context.Rip;
        return ERROR_SUCCESS;
    }

    DWORD IndependentFrontend::writeContext(HANDLE thread, const CONTEXT& context)
    {
        std::lock_guard lock(backend_.mutex_);
        if (!targetThread(thread)) return ERROR_INVALID_HANDLE;
        if (recovery_ || stop_.state != KSWORD_ARK_HVM_NOATTACH_STOPPED) return ERROR_NOT_READY;
        if ((context.ContextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE) return ERROR_NOT_SUPPORTED;
        CONTEXT original{};
        DWORD error = captureContext(original);
        if (error != ERROR_SUCCESS) return error;
        if ((context.ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT &&
            (std::memcmp(&context.FltSave, &original.FltSave, sizeof(context.FltSave)) != 0 || context.MxCsr != original.MxCsr))
            return ERROR_NOT_SUPPORTED;
        if ((context.ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS &&
            (context.SegDs != original.SegDs || context.SegEs != original.SegEs ||
             context.SegFs != original.SegFs || context.SegGs != original.SegGs)) return ERROR_NOT_SUPPORTED;
        const bool control = (context.ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL;
        if (control && (((context.EFlags ^ original.EFlags) & ~(0x100UL | 0x10000UL)) != 0 ||
            context.SegCs != original.SegCs || context.SegSs != original.SegSs)) return ERROR_NOT_SUPPORTED;
        if ((context.ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS)
        {
            if ((context.Dr7 & 0xFFFF0000ULL) || (context.Dr7 & 0x2000ULL)) return ERROR_NOT_SUPPORTED;
            const std::array<std::uint64_t, 4> addresses{context.Dr0, context.Dr1, context.Dr2, context.Dr3};
            for (std::size_t i = 0; i < hardware_.size(); ++i)
            {
                const auto wanted = (context.Dr7 & (3ULL << (2 * i))) ? addresses[i] : 0;
                if (hardware_[i].address == wanted) continue;
                if (hardware_[i].id)
                {
                    error = removeBreakpoint(hardware_[i].id);
                    if (error != ERROR_SUCCESS) return error;
                    hardware_[i] = {};
                }
                if (wanted)
                {
                    std::uint32_t id = 0;
                    error = addBreakpoint(wanted, false, id);
                    if (error != ERROR_SUCCESS) return error;
                    hardware_[i] = {wanted, id, 0};
                }
            }
            logicalDr6_ = context.Dr6;
        }
        KSWORD_ARK_HVM_NOATTACH_REQUEST edits{};
        edits.registers = registers(context);
        const auto was = registers(original);
        if ((context.ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER)
        {
            for (unsigned int i = 0; i < 15; ++i)
                if (std::memcmp(reinterpret_cast<const BYTE*>(&was) + i * 8,
                    reinterpret_cast<const BYTE*>(&edits.registers) + i * 8, 8) != 0) edits.registerMask |= 1ULL << i;
        }
        if (control)
        {
            if (context.Rip != original.Rip && !((ceEvent_ == CeEvent::initial || ceSoftwareRip_) && context.Rip == original.Rip + 1))
                edits.registerMask |= 1ULL << 15;
            if (context.Rsp != original.Rsp) edits.registerMask |= 1ULL << 16;
        }
        if (edits.registerMask)
        {
            error = request(KSWORD_ARK_HVM_NOATTACH_SET_GPR, &edits);
            if (error == ERROR_SUCCESS) error = finishContextRequest();
            if (error != ERROR_SUCCESS) return error;
            capturedStop_ = 0;
        }
        if (control) stepIntent_ = (context.EFlags & 0x100UL) != 0;
        if (ceSoftwareRip_ && control && context.Rip == original.Rip) ceSoftwareRip_ = false;
        return ERROR_SUCCESS;
    }

    bool IndependentFrontend::takeStepIntent()
    { std::lock_guard lock(backend_.mutex_); return stepIntent_; }

    std::uint64_t IndependentFrontend::takeStepOverTarget()
    { std::lock_guard lock(backend_.mutex_); const auto value = stepOverTarget_; stepOverTarget_ = 0; return value; }

    DWORD IndependentFrontend::processInfo(PROCESS_INFORMATION& info)
    {
        std::lock_guard lock(backend_.mutex_);
        if (!reserved_) return ERROR_INVALID_STATE;
        ark::DriverHandle process(duplicate(process_.native())), thread(duplicate(thread_.native()));
        if (!process.isValid() || !thread.isValid()) return GetLastError();
        info = {process.release(), thread.release(), pid_, tid_};
        return ERROR_SUCCESS;
    }

    DWORD IndependentFrontend::moduleInfo(std::uintptr_t& base, std::wstring& path)
    {
        std::lock_guard lock(backend_.mutex_);
        if (!reserved_) return ERROR_INVALID_STATE;
        ark::DriverHandle modules(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid_));
        MODULEENTRY32W entry{sizeof(entry)};
        if (!modules.isValid() || !Module32FirstW(modules.native(), &entry)) return GetLastError();
        base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr); path = entry.szExePath;
        return ERROR_SUCCESS;
    }

    BOOL IndependentFrontend::waitCeEvent(LPDEBUG_EVENT event, DWORD milliseconds)
    {
        if (!event) return resultBool(ERROR_INVALID_PARAMETER);
        std::unique_lock lock(backend_.mutex_);
        if (!reserved_ || ceEvent_ != CeEvent::none) return resultBool(ERROR_INVALID_STATE);
        *event = {};
        event->dwProcessId = pid_; event->dwThreadId = tid_;
        if (ceBootstrap_)
        {
            PROCESS_INFORMATION info{};
            const auto error = processInfo(info);
            if (error != ERROR_SUCCESS) return resultBool(error);
            event->dwDebugEventCode = CREATE_PROCESS_DEBUG_EVENT;
            event->u.CreateProcessInfo.hProcess = info.hProcess; event->u.CreateProcessInfo.hThread = info.hThread;
            std::uintptr_t base = 0; std::wstring path;
            if (moduleInfo(base, path) == ERROR_SUCCESS) event->u.CreateProcessInfo.lpBaseOfImage = reinterpret_cast<void*>(base);
            ceEvent_ = CeEvent::process;
            return resultBool(ERROR_SUCCESS);
        }
        const auto generation = phaseGeneration_;
        const auto after = ceDeliveredStop_;
        lock.unlock();
        KSWORD_ARK_HVM_NOATTACH_RESPONSE current{};
        const auto error = waitForStop(milliseconds, after, current);
        lock.lock();
        if (!reserved_ || generation != phaseGeneration_) return resultBool(ERROR_OPERATION_ABORTED);
        if (error == ERROR_PROCESS_ABORTED || error == ERROR_INVALID_STATE)
        {
            // Retirement notification also ends CE when only the bound thread exits.
            event->dwDebugEventCode = EXIT_PROCESS_DEBUG_EVENT;
            ceEvent_ = CeEvent::exit;
            return resultBool(ERROR_SUCCESS);
        }
        if (error != ERROR_SUCCESS) return resultBool(error);
        event->dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
        auto& record = event->u.Exception.ExceptionRecord;
        record.ExceptionAddress = reinterpret_cast<void*>(current.rip);
        event->u.Exception.dwFirstChance = 1;
        ceSoftwareRip_ = false; logicalDr6_ = 0;
        if (!ceDeliveredStop_)
        {
            record.ExceptionCode = EXCEPTION_BREAKPOINT;
            ceEvent_ = CeEvent::initial;
        }
        else
        {
            record.ExceptionCode = EXCEPTION_SINGLE_STEP;
            ceEvent_ = CeEvent::stop;
            for (std::size_t i = 0; i < hardware_.size(); ++i)
                if (hardware_[i].id && hardware_[i].id == current.breakpointId) logicalDr6_ |= 1ULL << i;
            for (const auto& bp : software_)
                if (bp.id && bp.id == current.breakpointId) { record.ExceptionCode = EXCEPTION_BREAKPOINT; ceSoftwareRip_ = true; break; }
        }
        ceDeliveredStop_ = current.stopId;
        return resultBool(ERROR_SUCCESS);
    }

    BOOL IndependentFrontend::continueCeEvent(DWORD pid, DWORD tid, DWORD status)
    {
        std::lock_guard lock(backend_.mutex_);
        if (!reserved_ || pid != pid_ || tid != tid_ || ceEvent_ == CeEvent::none) return resultBool(ERROR_INVALID_STATE);
        if (ceEvent_ == CeEvent::exit) return resultBool(close());
        if (ceEvent_ == CeEvent::process) { ceBootstrap_ = false; ceEvent_ = CeEvent::none; return resultBool(ERROR_SUCCESS); }
        if (status != DBG_CONTINUE && status != DBG_EXCEPTION_NOT_HANDLED) return resultBool(ERROR_INVALID_PARAMETER);
        const auto error = resume(stepIntent_);
        if (error == ERROR_SUCCESS) { ceEvent_ = CeEvent::none; ceSoftwareRip_ = false; }
        return resultBool(error);
    }

    DWORD IndependentFrontend::logicalCodeWrite(HANDLE process, std::uint64_t address, const void* bytes, SIZE_T length)
    {
        std::lock_guard lock(backend_.mutex_);
        if (!reserved_ || !Backend::sameObject(process, process_.native()) || length != 1 || !bytes) return ERROR_NOT_SUPPORTED;
        const auto value = *static_cast<const BYTE*>(bytes);
        for (auto& bp : software_)
        {
            if (!bp.id || bp.address != address) continue;
            if (value == 0xCC) return ERROR_SUCCESS;
            if (value != bp.original) return ERROR_NOT_SUPPORTED;
            const auto error = removeBreakpoint(bp.id);
            if (error == ERROR_SUCCESS) bp = {};
            return error;
        }
        if (value != 0xCC) return ERROR_NOT_SUPPORTED;
        const auto empty = std::find_if(software_.begin(), software_.end(), [](const Binding& bp) { return !bp.id; });
        if (empty == software_.end()) return ERROR_NO_SYSTEM_RESOURCES;
        BYTE original = 0; SIZE_T read = 0;
        if (!::ReadProcessMemory(process_.native(), reinterpret_cast<const void*>(address), &original, 1, &read) || read != 1)
            return ERROR_PARTIAL_COPY;
        if (original == 0xCC) return ERROR_NOT_SUPPORTED;
        std::uint32_t id = 0;
        const auto error = addBreakpoint(address, false, id);
        if (error == ERROR_SUCCESS) *empty = {address, id, original};
        return error;
    }

    bool IndependentFrontend::canWriteData(HANDLE process, std::uint64_t address, SIZE_T length)
    {
        std::lock_guard lock(backend_.mutex_);
        if (!reserved_ || !Backend::sameObject(process, process_.native()) || !length ||
            address > (std::numeric_limits<std::uint64_t>::max)() - length) return false;
        MEMORY_BASIC_INFORMATION info{};
        if (!VirtualQueryEx(process_.native(), reinterpret_cast<void*>(address), &info, sizeof(info))) return false;
        const auto base = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
        return info.State == MEM_COMMIT && (info.Protect & 0xF0) == 0 && address >= base &&
            address - base <= info.RegionSize && length <= info.RegionSize - (address - base);
    }
}
