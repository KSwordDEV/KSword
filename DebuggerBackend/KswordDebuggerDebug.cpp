#include "KswordDebuggerBackend.h"

#include <algorithm>
#include <cstring>
#include <TlHelp32.h>

namespace ksword::debugger
{
    namespace
    {
        DWORD ntError(LONG status)
        {
            using Convert = ULONG(WINAPI*)(LONG);
            const auto convert = reinterpret_cast<Convert>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
            return status >= 0 ? ERROR_SUCCESS : convert == nullptr ? ERROR_GEN_FAILURE : convert(status);
        }
        DWORD rejectedOperation(LONG status) { return status >= 0 ? ERROR_GEN_FAILURE : ntError(status); }
        std::uint64_t instructionPointer(const CONTEXT& context)
        {
#ifdef _WIN64
            return context.Rip;
#else
            return context.Eip;
#endif
        }
        std::array<std::uint64_t, 4> debugAddresses(const CONTEXT& context)
        {
            return {context.Dr0, context.Dr1, context.Dr2, context.Dr3};
        }
        DWORD threadOwnerFromSnapshot(DWORD tid)
        {
            // 仅在原生线程句柄无法查询所属进程时枚举 TID；R0 再次核对归属。
            ark::DriverHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
            if (!snapshot.isValid()) return 0;
            THREADENTRY32 entry{};
            entry.dwSize = sizeof(entry);
            if (!Thread32First(snapshot.native(), &entry)) return 0;
            do
            {
                if (entry.th32ThreadID == tid) return entry.th32OwnerProcessID;
                entry.dwSize = sizeof(entry);
            } while (Thread32Next(snapshot.native(), &entry));
            return 0;
        }
    }

    DWORD Backend::breakpointRequest(KSWORD_ARK_HVM_DEBUG_REQUEST& request,
        KSWORD_ARK_HVM_DEBUG_RESPONSE& response)
    {
        const auto result = client_.deviceIoControl(IOCTL_KSWORD_ARK_HVM_DEBUG,
            &request, sizeof(request), &response, sizeof(response), &driver_);
        if (!result.ok) return result.win32Error;
        if (result.bytesReturned != sizeof(response) || response.version != KSWORD_ARK_HVM_DEBUG_VERSION ||
            response.size != sizeof(response)) return ERROR_INVALID_DATA;
        return ntError(response.status);
    }

    DWORD Backend::startOwnedHvm()
    {
        if (shadowRecoveryRequired_)
        { log("HVM start refused: Shadow rollback was incomplete; restore all owned memory patches before resuming"); return ERROR_INVALID_STATE; }
        KSWORD_ARK_DEBUGGER_REQUEST query{}; KSWORD_ARK_DEBUGGER_RESPONSE shadow{};
        const DWORD validity = nativeRequest(query, shadow);
        if (validity != ERROR_SUCCESS) return validity;
        if (shadow.reserved1 != 0)
        { log("HVM start refused: an owned Shadow view is missing; restore/reinstall the affected patches or breakpoints"); return ERROR_INVALID_STATE; }
        const auto state = client_.queryHvmStatus();
        if (!state.io.ok) return state.io.win32Error;
        const auto result = client_.controlHvm(KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
            state.response.generation, true, true, true, true);
        if (!result.io.ok) return result.io.win32Error;
        if (result.response.status != KSWORD_ARK_HVM_CONTROL_STATUS_OK)
        { log(result.io.message); return rejectedOperation(result.response.lastStatus); }
        const auto verify = client_.queryHvmStatus();
        if (!verify.io.ok || (verify.response.stateFlags & KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE) == 0 ||
            verify.response.residentProcessorCount != verify.response.processorCount)
            return ERROR_INVALID_STATE;
        ownsResident_ = true;
        return ERROR_SUCCESS;
    }

    DWORD Backend::pauseOwnedHvm(bool& restart)
    {
        restart = false;
        const auto state = client_.queryHvmStatus();
        if (!state.io.ok) return state.io.win32Error;
        if (state.response.residentProcessorCount == 0) return ERROR_SUCCESS;
        if (!ownsResident_)
        {
            // Data-only fallback records contain no EPT/Shadow rule to pause.
            // Their context updates/retirement must leave another caller's
            // resident lifecycle untouched and must not claim its ownership.
            bool nativeOnly = !hasShadowViews();
            for (const auto& entry : breakpoints_) nativeOnly &= nativeDataOnlyRecord(entry.second);
            return nativeOnly ? ERROR_SUCCESS : ERROR_BUSY;
        }
        const auto result = client_.controlHvm(KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
            state.response.generation, false, false, true);
        if (!result.io.ok) return result.io.win32Error;
        if (result.response.status != KSWORD_ARK_HVM_CONTROL_STATUS_OK) return rejectedOperation(result.response.lastStatus);
        restart = true;
        return ERROR_SUCCESS;
    }

    DWORD Backend::releaseOwnedHvm()
    {
        if (hasShadowViews()) return ERROR_BUSY;
        if (!ownsResident_) return ERROR_SUCCESS;
        bool restart = false;
        DWORD error = pauseOwnedHvm(restart);
        if (error != ERROR_SUCCESS) return error;
        const auto state = client_.queryHvmStatus();
        if (!state.io.ok) return state.io.win32Error;
        const auto result = client_.controlHvm(KSWORD_ARK_HVM_CONTROL_TEARDOWN,
            state.response.generation, false, false, true);
        if (!result.io.ok) return result.io.win32Error;
        if (result.response.status != KSWORD_ARK_HVM_CONTROL_STATUS_OK) return rejectedOperation(result.response.lastStatus);
        ownsResident_ = false; shadowPrepared_ = false;
        return ERROR_SUCCESS;
    }

    bool Backend::validTargetThread(HANDLE thread) const
    {
        return attachedPid_ != 0 && attachedIdentity_.isValid() &&
            WaitForSingleObject(attachedIdentity_.native(), 0) == WAIT_TIMEOUT &&
            GetProcessIdOfThread(thread) == attachedPid_ && GetThreadId(thread) != 0;
    }

    // 身份来自固定对象，不再依赖可能已被回调削减的副本查询权限。
    bool Backend::validTargetThread(const TargetLease& lease) const
    {
        return attachedPid_ != 0 && attachedIdentity_.isValid() &&
            WaitForSingleObject(attachedIdentity_.native(), 0) == WAIT_TIMEOUT &&
            lease.pid == attachedPid_ && lease.tid != 0;
    }

    bool Backend::matchesThreadRecord(HANDLE thread, const ThreadBreakpoints& record) const
    {
        if (record.generation != sessionGeneration_ ||
            !record.identity || !record.identity->isValid()) return false;
        // 已持有同一线程对象与会话代次即可匹配，不因缺少 QUERY 误丢记录。
        if (attachedIdentity_.isValid() &&
            WaitForSingleObject(attachedIdentity_.native(), 0) == WAIT_TIMEOUT &&
            sameObject(thread, record.identity->native())) return true;
        if (!validTargetThread(thread)) return false;
        FILETIME created{}, exited{}, kernel{}, user{}, retainedCreated{};
        return GetThreadTimes(thread, &created, &exited, &kernel, &user) &&
            GetThreadTimes(record.identity->native(), &retainedCreated, &exited, &kernel, &user) &&
            created.dwLowDateTime == retainedCreated.dwLowDateTime &&
            created.dwHighDateTime == retainedCreated.dwHighDateTime;
    }

    void Backend::clearAttachment()
    {
        attachedPid_ = 0; monitorAttachment_ = false; lastEvent_ = {};
        attachmentOwner_ = AttachmentOwner::none; attachedIdentity_.reset();
        shadowStops_.clear(); shadowReferences_.clear();
        ++sessionGeneration_;
    }

    DWORD Backend::retireAttachment()
    {
        DWORD error = ERROR_SUCCESS;
        if (!breakpoints_.empty() || hasShadowViews() || ownsResident_)
        {
            bool restart = false;
            error = pauseOwnedHvm(restart);
            while (!breakpoints_.empty() && error == ERROR_SUCCESS)
                error = removeBreakpoints(breakpoints_.begin()->first);
            while (!shadowInt3_.empty() && error == ERROR_SUCCESS)
                error = removeShadowInt3(*shadowInt3_.begin());
            if (error == ERROR_SUCCESS) error = restoreShadowWrites();
            if (error == ERROR_SUCCESS) error = releaseOwnedHvm();
        }
        if (error == ERROR_SUCCESS) clearAttachment();
        else lastError_ = error;
        return error;
    }

    HANDLE Backend::openIdentityProcess(DWORD pid)
    {
        // 前端拥有调试事件；这里仅持有 PID 对应对象并验证其生命周期。
        constexpr DWORD identityAccess = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
        HANDLE identity = OpenProcess(identityAccess, FALSE, pid);
        const DWORD nativeError = identity == nullptr ? GetLastError() : ERROR_ACCESS_DENIED;
        DWORD grantedAccess = 0;
        const DWORD explicitAccess = concreteAccess(identityAccess);
        if (identity != nullptr &&
            ((queryHandleAccess(identity, grantedAccess) &&
                (grantedAccess & explicitAccess) == explicitAccess) ||
             (GetProcessId(identity) == pid && WaitForSingleObject(identity, 0) != WAIT_FAILED)))
            return identity;
        HANDLE brokered = brokerOpenHandle(pid, 0, identityAccess);
        if (brokered != nullptr)
        {
            if (identity != nullptr) CloseHandle(identity);
            recordFallback("Win32 identity open", "R0 handle broker", nativeError,
                "native target identity lacked query or wait rights");
            return brokered;
        }
        if (identity != nullptr) CloseHandle(identity);
        SetLastError(nativeError);
        return nullptr;
    }

    DWORD Backend::observeNativeSession(DWORD pid, std::uint64_t* generation)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (noAttachReserved_) return ERROR_BUSY;
        if (generation != nullptr) *generation = 0;
        if (!driver_.isValid()) return ERROR_DEVICE_NOT_CONNECTED;
        if (pid == 0) return ERROR_INVALID_PARAMETER;
        if (attachedPid_ != 0)
        {
            if (attachmentOwner_ != AttachmentOwner::native || attachedPid_ != pid)
                return ERROR_BUSY;
            if (!attachedIdentity_.isValid() ||
                WaitForSingleObject(attachedIdentity_.native(), 0) != WAIT_TIMEOUT)
                return ERROR_INVALID_STATE;
            if (generation != nullptr) *generation = sessionGeneration_;
            return ERROR_SUCCESS;
        }
        ark::DriverHandle identity(openIdentityProcess(pid));
        if (!identity.isValid()) return GetLastError();
        if (GetProcessId(identity.native()) != pid || WaitForSingleObject(identity.native(), 0) != WAIT_TIMEOUT)
            return ERROR_INVALID_STATE;
        attachedIdentity_ = std::move(identity); attachedPid_ = pid;
        attachmentOwner_ = AttachmentOwner::native; monitorAttachment_ = true;
        ++sessionGeneration_;
        if (generation != nullptr) *generation = sessionGeneration_;
        log("Observed frontend-owned native debug session for PID " + std::to_string(pid));
        return ERROR_SUCCESS;
    }

    DWORD Backend::releaseNativeSession(std::uint64_t generation)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (generation != 0 && generation != sessionGeneration_) return ERROR_INVALID_STATE;
        if (attachmentOwner_ == AttachmentOwner::none) return ERROR_SUCCESS;
        if (attachmentOwner_ != AttachmentOwner::native) return ERROR_BUSY;
        // The native frontend still owns its debug port and pending event. Only
        // rules created by this backend and its own resident preparation retire.
        return retireAttachment();
    }

    DWORD Backend::observeNativeEvent(const DEBUG_EVENT& event, std::uint64_t generation)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if ((generation != 0 && generation != sessionGeneration_) ||
            attachmentOwner_ != AttachmentOwner::native || !attachedIdentity_.isValid())
            return ERROR_INVALID_STATE;
        if (event.dwProcessId != attachedPid_ || event.dwThreadId == 0) return ERROR_INVALID_PARAMETER;
        if (event.dwDebugEventCode != EXIT_PROCESS_DEBUG_EVENT &&
            WaitForSingleObject(attachedIdentity_.native(), 0) != WAIT_TIMEOUT) return ERROR_INVALID_STATE;
        lastEvent_ = event;
        return ERROR_SUCCESS;
    }

    DWORD Backend::validateNativeContinue(DWORD pid, DWORD tid, std::uint64_t generation)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (shadowRecoveryRequired_) return ERROR_INVALID_STATE;
        if ((generation != 0 && generation != sessionGeneration_) ||
            attachmentOwner_ != AttachmentOwner::native || !attachedIdentity_.isValid())
            return ERROR_INVALID_STATE;
        if (pid != attachedPid_ || lastEvent_.dwProcessId != pid || lastEvent_.dwThreadId != tid)
            return ERROR_INVALID_PARAMETER;
        if (hasHvmBreakpointRules() || hasShadowViews())
        {
            KSWORD_ARK_DEBUGGER_REQUEST query{}; KSWORD_ARK_DEBUGGER_RESPONSE shadow{};
            const DWORD validity = nativeRequest(query, shadow);
            if (validity != ERROR_SUCCESS || shadow.reserved1 != 0) return validity == ERROR_SUCCESS ? ERROR_INVALID_STATE : validity;
            const auto state = client_.queryHvmStatus();
            if (!state.io.ok) return state.io.win32Error;
            if (!ownsResident_ || (state.response.stateFlags & KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE) == 0 ||
                state.response.residentProcessorCount != state.response.processorCount) return ERROR_INVALID_STATE;
        }
        return ERROR_SUCCESS;
    }

    DWORD Backend::retireNativeThread(DWORD tid, std::uint64_t generation)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (generation != 0 && generation != sessionGeneration_) return ERROR_INVALID_STATE;
        if (attachmentOwner_ != AttachmentOwner::native) return ERROR_INVALID_STATE;
        if (tid == 0) return ERROR_INVALID_PARAMETER;
        if (breakpoints_.find(tid) == breakpoints_.end()) return ERROR_SUCCESS;
        bool restart = false;
        DWORD error = pauseOwnedHvm(restart);
        if (error == ERROR_SUCCESS) error = removeBreakpoints(tid);
        if (error == ERROR_SUCCESS && restart) error = startOwnedHvm();
        if (error != ERROR_SUCCESS) lastError_ = error;
        return error;
    }

    void Backend::retireDetachedTarget()
    {
        if (!monitorAttachment_ || attachedPid_ == 0) return;
        // The frontend must continue its held exit event before releasing the
        // borrowed session. A concurrent status poll cannot consume that lease.
        if (attachmentOwner_ == AttachmentOwner::native && lastEvent_.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            return;
        const HANDLE process = attachedIdentity_.native();
        bool detached = !attachedIdentity_.isValid();
        if (attachedIdentity_.isValid())
        {
            BOOL present = TRUE;
            detached = WaitForSingleObject(process, 0) == WAIT_OBJECT_0 ||
                (CheckRemoteDebuggerPresent(process, &present) && !present);
        }
        if (!detached) return;
        // CE calls DebugActiveProcessStop directly, outside its SDK function table.
        // Observe that lifetime transition so stale EPT leases cannot strand the
        // HVM switch after the frontend has discarded its breakpoint list.
        const DWORD error = retireAttachment();
        if (error == ERROR_SUCCESS)
        {
            log("Debugger detached; owned EPT stops and HVM residency retired");
        }
        else { lastError_ = error; log("Detached target retirement failed: " + std::to_string(error)); }
    }

    DWORD Backend::ensureDebugHvm()
    {
        if (!useHvm_) return ERROR_INVALID_STATE;
        KSWORD_ARK_HVM_DEBUG_REQUEST query{};
        KSWORD_ARK_HVM_DEBUG_RESPONSE response{};
        query.version = KSWORD_ARK_HVM_DEBUG_VERSION; query.size = sizeof(query);
        DWORD error = breakpointRequest(query, response);
        if (error != ERROR_SUCCESS || response.supported == 0) return error == ERROR_SUCCESS ? ERROR_NOT_SUPPORTED : error;
        const auto state = client_.queryHvmStatus();
        if (!state.io.ok) return state.io.win32Error;
        if ((state.response.stateFlags & KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE) != 0)
        {
            if (ownsResident_) return ERROR_SUCCESS;
            logRepeated("EPT preparation refused: error=170; pre-existing HVM residency belongs to another caller (for example Main HVM or another debugger); stop and release it in the owning UI before retrying; no foreign HVM takeover");
            return ERROR_BUSY;
        }
        if (!ownsResident_)
        {
            // Existing KSword preparations belong to their caller; never rebuild them implicitly.
            if ((state.response.stateFlags & KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0)
            {
                logRepeated("EPT preparation refused: error=170; pre-existing HVM preparation belongs to another caller; release it in the owning UI before retrying; no foreign HVM takeover");
                return ERROR_BUSY;
            }
            const auto prepared = client_.controlHvm(KSWORD_ARK_HVM_CONTROL_PREPARE, state.response.generation,
                false, true, true, false, false, false, false, false, true);
            if (!prepared.io.ok) return prepared.io.win32Error;
            if (prepared.response.status != KSWORD_ARK_HVM_CONTROL_STATUS_OK) return rejectedOperation(prepared.response.lastStatus);
            ownsResident_ = true;
            const auto preparedState = client_.queryHvmStatus();
            if (!preparedState.io.ok) return preparedState.io.win32Error;
            const auto tested = client_.controlHvm(KSWORD_ARK_HVM_CONTROL_SELF_TEST, preparedState.response.generation,
                true, true, true);
            if (!tested.io.ok || tested.response.status != KSWORD_ARK_HVM_CONTROL_STATUS_OK)
            {
                (void)releaseOwnedHvm();
                return tested.io.ok ? rejectedOperation(tested.response.lastStatus) : tested.io.win32Error;
            }
            ownsResident_ = true;
        }
        return startOwnedHvm();
    }

    DWORD Backend::removeBreakpoints(DWORD tid)
    {
        const auto found = breakpoints_.find(tid);
        if (found == breakpoints_.end()) return ERROR_SUCCESS;
        if (found->second.shadow) return removeShadowRecord(tid);
        for (DWORD& id : found->second.ids)
        {
            if (id == 0) continue;
            KSWORD_ARK_HVM_DEBUG_REQUEST request{};
            KSWORD_ARK_HVM_DEBUG_RESPONSE response{};
            request.version = KSWORD_ARK_HVM_DEBUG_VERSION; request.size = sizeof(request);
            request.operation = KSWORD_ARK_HVM_DEBUG_REMOVE;
            request.flags = KSWORD_ARK_HVM_DEBUG_FLAG_CONFIRMED;
            request.breakpointId = id;
            const DWORD error = breakpointRequest(request, response);
            if (error != ERROR_SUCCESS && error != ERROR_NOT_FOUND) return error;
            id = 0;
        }
        breakpoints_.erase(found);
        return ERROR_SUCCESS;
    }

    DWORD Backend::installBreakpoints(DWORD tid, ThreadBreakpoints& record)
    {
        const auto addresses = debugAddresses(record.requested);
        for (DWORD index = 0; index < 4; ++index)
        {
            if (record.ids[index] != 0 || (record.requested.Dr7 & (3ULL << (index * 2))) == 0) continue;
            const DWORD kind = static_cast<DWORD>((record.requested.Dr7 >> (16 + index * 4)) & 3);
            const DWORD lengthCode = static_cast<DWORD>((record.requested.Dr7 >> (18 + index * 4)) & 3);
            KSWORD_ARK_HVM_DEBUG_REQUEST request{};
            KSWORD_ARK_HVM_DEBUG_RESPONSE response{};
            request.version = KSWORD_ARK_HVM_DEBUG_VERSION; request.size = sizeof(request);
            request.operation = KSWORD_ARK_HVM_DEBUG_ADD; request.flags = KSWORD_ARK_HVM_DEBUG_FLAG_CONFIRMED;
            request.processId = attachedPid_; request.threadId = tid; request.debugRegister = index;
            request.access = kind == 0 ? KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE : kind == 1 ? KSWORD_ARK_HVM_EPT_ACCESS_WRITE : 3U;
            static constexpr DWORD lengths[] = {1, 2, 8, 4};
            request.length = kind == 0 ? 1 : lengths[lengthCode]; request.address = addresses[index];
            const DWORD error = breakpointRequest(request, response);
            // A target-exit race may return a revoked ID that still owns a pin.
            if (response.breakpointId != 0) record.ids[index] = response.breakpointId;
            if (error != ERROR_SUCCESS) return error;
            if (response.breakpointId == 0) return ERROR_INVALID_DATA;
            record.ids[index] = response.breakpointId;
        }
        return ERROR_SUCCESS;
    }

    HANDLE Backend::openThread(DWORD access, BOOL inherit, DWORD tid)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (tid == 0) { SetLastError(ERROR_INVALID_PARAMETER); return nullptr; }
        // 真实线程句柄已固定 TID，查询权限被削减时保留其原所属进程信息。
        const auto rememberThread = [this, tid](HANDLE handle) {
            DWORD pid = GetProcessIdOfThread(handle);
            if (pid == 0) pid = threadOwnerFromSnapshot(tid);
            return rememberTarget(handle, pid, tid);
        };
        const DWORD requiredAccess = access | THREAD_QUERY_LIMITED_INFORMATION;
        HANDLE thread = OpenThread(requiredAccess, inherit, tid);
        DWORD nativeError = thread == nullptr ? GetLastError() : ERROR_ACCESS_DENIED;
        DWORD grantedAccess = 0;
        const DWORD explicitAccess = concreteAccess(requiredAccess);
        if (thread != nullptr)
        {
            // 权限查询不可用时保留原生线程句柄，避免代理结果缩小既有能力。
            if (!queryHandleAccess(thread, grantedAccess) ||
                (grantedAccess & explicitAccess) == explicitAccess)
                return rememberThread(thread);
        }
        if (thread == nullptr)
        {
            thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, inherit, tid);
            if (thread == nullptr) nativeError = GetLastError();
        }
        DWORD pid = thread == nullptr ? 0 : GetProcessIdOfThread(thread);
        if (pid == 0) pid = threadOwnerFromSnapshot(tid);
        if (pid != 0)
        {
            HANDLE brokered = brokerOpenHandle(pid, tid, requiredAccess, inherit);
            if (brokered != nullptr)
            {
                DWORD nativeGranted = 0;
                DWORD brokerGranted = 0;
                if (thread != nullptr && queryHandleAccess(thread, nativeGranted) &&
                    queryHandleAccess(brokered, brokerGranted) &&
                    ((nativeGranted & explicitAccess) & ~(brokerGranted & explicitAccess)) != 0)
                {
                    // 不用缺少既有线程权限的代理句柄取代可用原生句柄。
                    CloseHandle(brokered);
                    return rememberThread(thread);
                }
                if (thread != nullptr) CloseHandle(thread);
                recordFallback("Win32 OpenThread", "R0 handle broker", nativeError,
                    "native thread handle lacked requested rights or could not be opened");
                return rememberTarget(brokered, pid, tid);
            }
        }
        if (thread == nullptr) SetLastError(nativeError);
        return thread != nullptr ? rememberThread(thread) : nullptr;
    }

    BOOL Backend::getContext(HANDLE thread, LPCONTEXT context)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (context == nullptr) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        if (independent_.active())
        { const auto error = independent_.readContext(thread, *context); SetLastError(error); return error == ERROR_SUCCESS; }
        TargetLease lease;
        if (!pinTarget(thread, true, lease)) return FALSE;
        thread = lease.identity.native();
        if (!nativeContext(thread, context, false, &lease)) return FALSE;
        const auto found = breakpoints_.find(lease.tid);
        if ((context->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS &&
            found != breakpoints_.end() && matchesThreadRecord(thread, found->second))
        {
            const CONTEXT& virtualContext = found->second.requested;
            context->Dr0 = virtualContext.Dr0; context->Dr1 = virtualContext.Dr1;
            context->Dr2 = virtualContext.Dr2; context->Dr3 = virtualContext.Dr3;
            context->Dr7 = virtualContext.Dr7;
        }
        const auto stop = shadowStops_.find(lease.tid);
        if (stop != shadowStops_.end() && !stop->second.stepping && validTargetThread(lease))
        {
            // Windows owns an INT3 stop. Its DR6 is not a hardware-stop result:
            // SetThreadContext may discard the B0-B3 bits. Expose the verified
            // thread/slot match while this event remains held by the debugger.
            if ((context->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS)
                context->Dr6 = (context->Dr6 & ~0x400fULL) | stop->second.mask;
            if ((context->ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL)
                context->Rip = stop->second.address;
        }
        return TRUE;
    }

    BOOL Backend::overlayNativeDebugContext(HANDLE thread, CONTEXT* context, std::uint64_t generation)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (generation != 0 && generation != sessionGeneration_)
        { SetLastError(ERROR_INVALID_STATE); return FALSE; }
        if (context == nullptr ||
            (context->ContextFlags & CONTEXT_DEBUG_REGISTERS) != CONTEXT_DEBUG_REGISTERS)
        { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        TargetLease lease;
        if (!pinTarget(thread, true, lease)) return FALSE;
        thread = lease.identity.native();
        if (attachmentOwner_ != AttachmentOwner::native || !validTargetThread(lease))
        { SetLastError(ERROR_INVALID_STATE); return FALSE; }
        const auto found = breakpoints_.find(lease.tid);
        if (found == breakpoints_.end()) return TRUE;
        if (!matchesThreadRecord(thread, found->second))
        { SetLastError(ERROR_INVALID_STATE); return FALSE; }
        const auto& requested = found->second.requested;
        context->Dr0 = requested.Dr0; context->Dr1 = requested.Dr1;
        context->Dr2 = requested.Dr2; context->Dr3 = requested.Dr3;
        context->Dr7 = requested.Dr7;
        return TRUE;
    }

    BOOL Backend::applyNativeDebugContext(HANDLE thread, const CONTEXT* context,
        NativeDebugWriter writer, void* opaque, std::uint64_t generation)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (generation != 0 && generation != sessionGeneration_)
        { SetLastError(ERROR_INVALID_STATE); return FALSE; }
        if (writer == nullptr || context == nullptr ||
            (context->ContextFlags & CONTEXT_DEBUG_REGISTERS) != CONTEXT_DEBUG_REGISTERS)
        { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        TargetLease lease;
        if (!pinTarget(thread, true, lease)) return FALSE;
        thread = lease.identity.native();
        if (attachmentOwner_ != AttachmentOwner::native || !validTargetThread(lease))
        { SetLastError(ERROR_INVALID_STATE); return FALSE; }
        return applyDebugContext(thread, context, writer, opaque, &lease);
    }

    BOOL Backend::setContext(HANDLE thread, const CONTEXT* context)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (independent_.active())
        {
            const auto error = context ? independent_.writeContext(thread, *context) : ERROR_INVALID_PARAMETER;
            SetLastError(error); return error == ERROR_SUCCESS;
        }
        return applyDebugContext(thread, context, nullptr, nullptr);
    }

    BOOL Backend::applyDebugContext(HANDLE thread, const CONTEXT* context,
        NativeDebugWriter writer, void* opaque, TargetLease* bound)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (context == nullptr) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        // 读取、记录替换、实际写入和回滚共用同一对象，内部不再重复复制。
        TargetLease localLease;
        TargetLease& lease = bound != nullptr ? *bound : localLease;
        if (bound == nullptr && !pinTarget(thread, true, lease)) return FALSE;
        thread = lease.identity.native();
        const DWORD tid = lease.tid;
        if (!useHvm_ || (context->ContextFlags & CONTEXT_DEBUG_REGISTERS) != CONTEXT_DEBUG_REGISTERS)
        {
            if (options_.mode == KSWORD_DEBUGGER_MODE_STEALTH &&
                (context->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS && (context->Dr7 & 0xffU) != 0)
            { logRepeated("Stealth breakpoint refused: select HVM before arming debug registers"); SetLastError(ERROR_INVALID_STATE); return FALSE; }
            CONTEXT native = *context;
            if (writer != nullptr) native.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            return writer != nullptr ? writer(thread, &native, FALSE, opaque) : nativeContext(thread, &native, true, &lease);
        }
        // A context update with no armed slots and no owned breakpoint record
        // does not mutate HVM. Route it before Shadow preparation so a harmless
        // DR clear cannot try to pause a pre-existing Main/other-client resident.
        if ((context->Dr7 & 0xffU) == 0 && breakpoints_.find(tid) == breakpoints_.end() && validTargetThread(lease))
        {
            CONTEXT native = *context;
            if (writer != nullptr) native.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            return writer != nullptr ? writer(thread, &native, FALSE, opaque) : nativeContext(thread, &native, true, &lease);
        }
        if (writer == nullptr)
        {
            bool executionRequested = false;
            for (DWORD slot = 0; slot < 4; ++slot)
                executionRequested |= (context->Dr7 & (3ULL << (2 * slot))) != 0 &&
                    ((context->Dr7 >> (16 + 4 * slot)) & 3) == 0;
            if (preferShadowExecution())
            {
                if (options_.mode == KSWORD_DEBUGGER_MODE_NORMAL && !shadowPrepared_)
                {
                    if (options_.allowFallback == 0)
                    { logRepeated("EPT breakpoint fallback refused: fallback is disabled"); SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
                }
                const bool reportFallback = options_.mode == KSWORD_DEBUGGER_MODE_NORMAL && !shadowPrepared_;
                const BOOL completed = applyShadowContext(thread, context, &lease);
                const DWORD actualError = GetLastError();
                if (reportFallback && executionRequested) recordFallback("EPT #DB execution breakpoint", completed ? "Shadow Page hidden INT3" : "Shadow route rejected", ERROR_NOT_SUPPORTED,
                    "EPT breakpoint protocol unavailable; Shadow result error=" + std::to_string(completed ? ERROR_SUCCESS : actualError) + "; no visible native DR fallback");
                SetLastError(actualError); return completed;
            }
            KSWORD_ARK_HVM_DEBUG_REQUEST query{}; KSWORD_ARK_HVM_DEBUG_RESPONSE response{};
            query.version = KSWORD_ARK_HVM_DEBUG_VERSION; query.size = sizeof(query);
            if (breakpointRequest(query, response) == ERROR_SUCCESS && response.supported == 0)
            {
                if (options_.allowFallback == 0)
                { logRepeated("EPT breakpoint fallback refused: fallback is disabled"); SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
                const BOOL completed = applyShadowContext(thread, context, &lease);
                const DWORD actualError = GetLastError();
                if (executionRequested) recordFallback("EPT #DB execution breakpoint", completed ? "Shadow Page hidden INT3" : "Shadow route rejected", ERROR_NOT_SUPPORTED,
                    "EPT breakpoint protocol unavailable; Shadow result error=" + std::to_string(completed ? ERROR_SUCCESS : actualError) + "; no visible native DR fallback");
                SetLastError(actualError); return completed;
            }
        }
        else if (preferShadowExecution() && (context->Dr7 & 0xffU) != 0)
        {
            logRepeated("Native EPT context seam refused: this policy requires the adapter's Shadow execution breakpoint path");
            SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
        }
        if (!validTargetThread(lease))
        { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        const bool enabled = (context->Dr7 & 0xffU) != 0;
        const auto found = breakpoints_.find(tid);
        if (!enabled && found == breakpoints_.end())
        {
            CONTEXT native = *context;
            if (writer != nullptr) native.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            return writer != nullptr ? writer(thread, &native, FALSE, opaque) : nativeContext(thread, &native, true, &lease);
        }
        // Validate the complete replacement before any old rule is removed.
        const auto addresses = debugAddresses(*context);
        for (DWORD index = 0; index < 4; ++index)
            if ((context->Dr7 & (3ULL << (index * 2))) != 0 &&
                (((context->Dr7 >> (16 + index * 4)) & 3) == 2 || addresses[index] == 0))
            { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
        const bool hadPrevious = found != breakpoints_.end();
        if (hadPrevious && !matchesThreadRecord(thread, found->second))
        { SetLastError(ERROR_INVALID_STATE); return FALSE; }
        const ThreadBreakpoints previous = hadPrevious ? found->second : ThreadBreakpoints{};
        const auto identity = enabled ? std::make_shared<ark::DriverHandle>() : nullptr;
        HANDLE retained = nullptr;
        if (enabled && !DuplicateHandle(GetCurrentProcess(), thread, GetCurrentProcess(),
            &retained, 0, FALSE, DUPLICATE_SAME_ACCESS)) return FALSE;
        if (identity) identity->reset(retained);
        CONTEXT saved{}; saved.ContextFlags = writer != nullptr ? CONTEXT_DEBUG_REGISTERS : context->ContextFlags;
        if (!nativeContext(thread, &saved, false, &lease)) return FALSE;
        DWORD error = enabled ? ensureDebugHvm() : ERROR_SUCCESS;
        bool restart = false;
        if (error == ERROR_SUCCESS) error = pauseOwnedHvm(restart);
        if (error != ERROR_SUCCESS) { logRepeated("EPT breakpoint preparation failed before context/binding writes: " + std::to_string(error)); SetLastError(error); return FALSE; }
        error = removeBreakpoints(tid);
        if (error == ERROR_SUCCESS && enabled)
        {
            auto& replacement = breakpoints_[tid]; replacement.requested = *context;
            replacement.identity = identity; replacement.generation = sessionGeneration_;
            if (writer != nullptr) replacement.requested.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            error = installBreakpoints(tid, replacement);
        }
        // DR7 stays enabled in the real thread. Windows clears it on debugger detach,
        // giving VM-exit a reliable lifetime guard. Actual DR addresses are neutral.
        CONTEXT native = *context;
        native.Dr0 = 0; native.Dr1 = 0; native.Dr2 = 0; native.Dr3 = 0;
        if (writer != nullptr) native.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (error == ERROR_SUCCESS &&
            !(writer != nullptr ? writer(thread, &native, FALSE, opaque) : nativeContext(thread, &native, true, &lease)))
            error = GetLastError();
        if (error == ERROR_SUCCESS && restart) error = startOwnedHvm();
        if (error != ERROR_SUCCESS)
        {
            bool ignored = false;
            DWORD rollback = pauseOwnedHvm(ignored);
            if (rollback == ERROR_SUCCESS) rollback = removeBreakpoints(tid);
            if (rollback == ERROR_SUCCESS && hadPrevious)
            {
                auto& restored = breakpoints_[tid]; restored = previous; restored.ids = {};
                rollback = installBreakpoints(tid, restored);
            }
            if (rollback == ERROR_SUCCESS &&
                !(writer != nullptr ? writer(thread, &saved, TRUE, opaque) : nativeContext(thread, &saved, true, &lease)))
                rollback = GetLastError();
            if (rollback == ERROR_SUCCESS && restart) rollback = startOwnedHvm();
            log("EPT breakpoint transaction failed: " + std::to_string(error) +
                "; rollback " + std::to_string(rollback));
            if (rollback != ERROR_SUCCESS) lastError_ = rollback;
        }
        else lastError_ = ERROR_SUCCESS;
        SetLastError(error);
        return error == ERROR_SUCCESS ? TRUE : FALSE;
    }

    DWORD Backend::suspendThread(HANDLE thread) { return changeSuspendCount(thread, true); }
    DWORD Backend::resumeThread(HANDLE thread) { return changeSuspendCount(thread, false); }

    BOOL Backend::attach(DWORD pid)
    {
        std::unique_lock<std::recursive_mutex> lock(mutex_);
        if (independent_.selected())
        {
            lock.unlock();
            const auto error = independent_.start(pid);
            SetLastError(error); return error == ERROR_SUCCESS;
        }
        if (noAttachReserved_) { SetLastError(ERROR_BUSY); return FALSE; }
        if (attachedPid_ != 0)
        { SetLastError(ERROR_BUSY); return FALSE; }
        ark::DriverHandle identity(openIdentityProcess(pid));
        if (!identity.isValid()) return FALSE;
        // Windows 的 DebugActiveProcess 接受 PID 而非已打开句柄；身份代理
        // 不能替代操作系统建立 debug port 的权限检查。
        if (!DebugActiveProcess(pid)) return FALSE;
        // Detaching or losing the debugger must leave the target alive.
        if (!DebugSetProcessKillOnExit(FALSE))
        { const DWORD error = GetLastError(); (void)DebugActiveProcessStop(pid); SetLastError(error); return FALSE; }
        if (WaitForSingleObject(identity.native(), 0) != WAIT_TIMEOUT)
        { (void)DebugActiveProcessStop(pid); SetLastError(ERROR_INVALID_STATE); return FALSE; }
        attachedPid_ = pid; attachedIdentity_ = std::move(identity);
        attachmentOwner_ = AttachmentOwner::backend; ++sessionGeneration_;
        monitorAttachment_ = true;
        log("Attached debugger event transport to PID " + std::to_string(pid));
        return TRUE;
    }

    BOOL Backend::waitEvent(LPDEBUG_EVENT event, DWORD milliseconds)
    {
        if (independent_.selected()) return independent_.waitCeEvent(event, milliseconds);
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (attachmentOwner_ == AttachmentOwner::native)
            { SetLastError(ERROR_BUSY); return FALSE; }
        }
NextEvent:
        // Never hold the backend lock while the debugger event thread waits.
        if (!WaitForDebugEvent(event, milliseconds)) return FALSE;
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        lastEvent_ = *event;
        bool consume = false;
        const DWORD shadowError = shadowEvent(*event, consume);
        if (shadowError != ERROR_SUCCESS) { SetLastError(shadowError); return FALSE; }
        lastEvent_ = *event;
        if (consume)
        {
            if (!ContinueDebugEvent(event->dwProcessId, event->dwThreadId, DBG_CONTINUE)) return FALSE;
            goto NextEvent;
        }
        if (event->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
            log("Debug exception " + std::to_string(event->u.Exception.ExceptionRecord.ExceptionCode) +
                ", PID " + std::to_string(event->dwProcessId) + ", TID " + std::to_string(event->dwThreadId));
        if (event->dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT || event->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            bool restart = false;
            DWORD error = pauseOwnedHvm(restart);
            if (error == ERROR_SUCCESS)
            {
                if (event->dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT)
                {
                    const auto pending = shadowStops_.find(event->dwThreadId);
                    const std::uint64_t address = pending == shadowStops_.end() ? 0 : pending->second.address;
                    error = removeBreakpoints(event->dwThreadId);
                    shadowStops_.erase(event->dwThreadId);
                    // A thread can exit with an internal step pending. Restore
                    // the shared execution view for any remaining thread slots.
                    if (error == ERROR_SUCCESS && address != 0 && shadowReferences_.count(address) != 0 &&
                        shadowInt3_.count(address) == 0) error = addShadowInt3(address);
                }
                else while (!breakpoints_.empty() && error == ERROR_SUCCESS) error = removeBreakpoints(breakpoints_.begin()->first);
            }
            if (error == ERROR_SUCCESS && event->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            { error = restoreShadowWrites(); if (error == ERROR_SUCCESS) error = releaseOwnedHvm(); if (error == ERROR_SUCCESS) clearAttachment(); }
            else if (error == ERROR_SUCCESS && !hasShadowViews() && shadowPrepared_) error = releaseOwnedHvm();
            else if (error == ERROR_SUCCESS && restart) error = startOwnedHvm();
            if (error != ERROR_SUCCESS) { lastError_ = error; log("Debug target retirement failed: " + std::to_string(error)); }
        }
        return TRUE;
    }

    BOOL Backend::continueEvent(DWORD pid, DWORD tid, DWORD continueStatus)
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (independent_.selected()) return independent_.continueCeEvent(pid, tid, continueStatus);
        if (shadowRecoveryRequired_)
        { log("Continue refused: Shadow rollback requires a full restore"); SetLastError(ERROR_INVALID_STATE); return FALSE; }
        if (attachmentOwner_ == AttachmentOwner::native)
        { SetLastError(ERROR_BUSY); return FALSE; }
        if (hasShadowViews() || !shadowStops_.empty())
        {
            KSWORD_ARK_DEBUGGER_REQUEST query{}; KSWORD_ARK_DEBUGGER_RESPONSE shadow{};
            const DWORD validity = nativeRequest(query, shadow);
            if (validity != ERROR_SUCCESS || shadow.reserved1 != 0)
            { log("Shadow continue refused: a required view is missing; restore/reinstall before resuming"); SetLastError(validity == ERROR_SUCCESS ? ERROR_INVALID_STATE : validity); return FALSE; }
        }
        if (shadowStops_.find(tid) != shadowStops_.end())
        {
            log("ShadowPage continue: TID " + std::to_string(tid) + ", status " + std::to_string(continueStatus));
            const DWORD error = beginShadowStep(tid, false);
            if (error != ERROR_SUCCESS) { SetLastError(error); return FALSE; }
            return ContinueDebugEvent(pid, tid, continueStatus);
        }
        const auto found = breakpoints_.find(tid);
        if (useHvm_ && (hasHvmBreakpointRules() || hasShadowViews()))
        {
            KSWORD_ARK_DEBUGGER_REQUEST query{}; KSWORD_ARK_DEBUGGER_RESPONSE shadow{};
            const DWORD validity = nativeRequest(query, shadow);
            if (validity != ERROR_SUCCESS || shadow.reserved1 != 0)
            { log("Continue refused: a Shadow view failed validation; restore/reinstall before resuming"); SetLastError(validity == ERROR_SUCCESS ? ERROR_INVALID_STATE : validity); return FALSE; }
            const auto state = client_.queryHvmStatus();
            if (!state.io.ok || (state.response.stateFlags & KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE) == 0 ||
                state.response.residentProcessorCount != state.response.processorCount)
            {
                lastError_ = state.io.ok ? ERROR_INVALID_STATE : state.io.win32Error;
                log("Continue refused: EPT debugger residency is incomplete; remove or restore the breakpoints first");
                SetLastError(lastError_); return FALSE;
            }
        }
        if (found != breakpoints_.end() && lastEvent_.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            lastEvent_.dwThreadId == tid && lastEvent_.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
        {
            HANDLE thread = openThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
            CONTEXT context{}; context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
            if (thread == nullptr) return FALSE;
            if (nativeContext(thread, &context, false))
            {
                const auto addresses = debugAddresses(found->second.requested);
                for (DWORD index = 0; index < 4; ++index)
                    if ((context.Dr6 & (1ULL << index)) != 0 && addresses[index] == instructionPointer(context) &&
                        ((found->second.requested.Dr7 >> (16 + index * 4)) & 3) == 0)
                        context.EFlags |= 0x10000UL; // RF skips exactly the resumed execution breakpoint.
                context.ContextFlags = CONTEXT_CONTROL;
                if (!nativeContext(thread, &context, true)) { const DWORD error = GetLastError(); CloseHandle(thread); SetLastError(error); return FALSE; }
            }
            else { const DWORD error = GetLastError(); CloseHandle(thread); SetLastError(error); return FALSE; }
            CloseHandle(thread);
        }
        return ContinueDebugEvent(pid, tid, continueStatus);
    }

    bool Backend::shutdown()
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (independent_.selected() && independent_.close() != ERROR_SUCCESS) return false;
        bool restart = false;
        if ((hasHvmBreakpointRules() || hasShadowViews()) && pauseOwnedHvm(restart) != ERROR_SUCCESS) return false;
        while (!breakpoints_.empty())
        {
            const DWORD tid = breakpoints_.begin()->first;
            const auto& record = breakpoints_.begin()->second;
            CONTEXT native = record.requested;
            native.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            const HANDLE thread = record.identity && record.identity->isValid() ? record.identity->native() : nullptr;
            if (thread != nullptr && matchesThreadRecord(thread, record))
            {
                const BOOL restored = nativeContext(thread, &native, true);
                const DWORD error = GetLastError();
                if (!restored && error != ERROR_INVALID_PARAMETER && error != ERROR_INVALID_HANDLE) return false;
            }
            if (removeBreakpoints(tid) != ERROR_SUCCESS) return false;
        }
        while (!shadowInt3_.empty()) if (removeShadowInt3(*shadowInt3_.begin()) != ERROR_SUCCESS) return false;
        if (restoreShadowWrites() != ERROR_SUCCESS) return false;
        if (releaseOwnedHvm() != ERROR_SUCCESS) return false;
        ownsResident_ = false; useHvm_ = false; clearAttachment();
        processIds_.clear(); threadIds_.clear(); driver_.reset();
        return true;
    }
}
