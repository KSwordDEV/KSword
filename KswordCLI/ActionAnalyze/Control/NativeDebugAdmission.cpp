#include "NativeDebugAdmission.h"
#include "NativePrivateExecutionPage.h"
#include <TlHelp32.h>
#include <array>
#include <cstddef>
#include <algorithm>
#include <bcrypt.h>
#include <objbase.h>
#include <charconv>
#include <new>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")

namespace ks::cli::action_analyze::control::native_owner_detail {
namespace {
using Handle = NativeDebugHandle;
using NativeError = NativeDebugError;
NativeError WinError(const char* stage) {
    const auto error = GetLastError();
    return {stage, error ? error : ERROR_GEN_FAILURE};
}
NativeError CheckUser(HANDLE target) {
    Handle ours;
    Handle theirs;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return WinError("open-owner-token");
    ours.Reset(token);
    if (!OpenProcessToken(target, TOKEN_QUERY, &token)) return WinError("open-target-token");
    theirs.Reset(token);
    struct UserBuffer { TOKEN_USER user; std::array<std::byte, SECURITY_MAX_SID_SIZE> sidStorage; } ourUser{}, targetUser{};
    DWORD bytes = 0;
    if (!GetTokenInformation(ours.Get(), TokenUser, &ourUser, sizeof(ourUser), &bytes) ||
        !GetTokenInformation(theirs.Get(), TokenUser, &targetUser, sizeof(targetUser), &bytes))
        return WinError("read-user-sid");
    if (!EqualSid(ourUser.user.User.Sid, targetUser.user.User.Sid)) return {"same-user-required", ERROR_ACCESS_DENIED};
    DWORD ourSession = 0;
    DWORD targetSession = 0;
    if (!GetTokenInformation(ours.Get(), TokenSessionId, &ourSession, sizeof(ourSession), &bytes) ||
        !GetTokenInformation(theirs.Get(), TokenSessionId, &targetSession, sizeof(targetSession), &bytes))
        return WinError("read-token-session");
    return ourSession == targetSession ? NativeError{} : NativeError{"same-session-required", ERROR_ACCESS_DENIED};
}
}

std::optional<DWORD64> DebugControl(std::uint32_t dataBytes) noexcept {
    constexpr DWORD64 write = 1ull << 16;
    switch (dataBytes) {
    case 0: return 1;
    case 1: return 1 | write;
    case 2: return 1 | write | (1ull << 18);
    case 4: return 1 | write | (3ull << 18);
    case 8: return 1 | write | (2ull << 18);
    default: return std::nullopt;
    }
}

std::uintptr_t InstructionPointer(const CONTEXT& context) noexcept {
#if defined(_M_X64)
    return context.Rip;
#else
    return context.Eip; // Win32仍可编译，原准入不放行该后端。
#endif
}

std::uint64_t FileTime(FILETIME value) noexcept {
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

std::optional<std::uint64_t> ReadQpc() noexcept {
    LARGE_INTEGER counter{};
    if (!QueryPerformanceCounter(&counter) || counter.QuadPart < 0) return std::nullopt;
    return static_cast<std::uint64_t>(counter.QuadPart);
}

bool AbsoluteModulePath(std::wstring_view path) {
    return path.size() >= 4 && path.size() < MAX_PATH && path.find(L'\0') == path.npos &&
        ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' && path[2] == L'\\';
}

bool IsNativeRequestedInterrupt(HANDLE process, HANDLE thread, const DEBUG_EVENT& event,
    std::uint64_t breakpointAddress) {
    if (!thread || event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT || !event.u.Exception.dwFirstChance ||
        event.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT ||
        reinterpret_cast<std::uintptr_t>(event.u.Exception.ExceptionRecord.ExceptionAddress) != breakpointAddress ||
        GetProcessId(process) != event.dwProcessId || GetThreadId(thread) != event.dwThreadId ||
        GetProcessIdOfThread(thread) != event.dwProcessId || WaitForSingleObject(thread, 0) != WAIT_TIMEOUT) return false;
    FILETIME created{}, exited{}, kernel{}, user{};
    return GetThreadTimes(thread, &created, &exited, &kernel, &user) && FileTime(created) != 0;
}

NativeDebugError CaptureNativeInterruptThread(NativeDebugHandle& heldThread, const DEBUG_EVENT& event) {
    const auto thread = event.u.CreateThread.hThread;
    FILETIME created{}, exited{}, kernel{}, user{};
    if (GetThreadId(thread) != event.dwThreadId || GetProcessIdOfThread(thread) != event.dwProcessId ||
        !GetThreadTimes(thread, &created, &exited, &kernel, &user) || !FileTime(created))
        return {"interrupt-thread-identity-unavailable", ERROR_INVALID_DATA};
    if (heldThread && !CompareObjectHandles(heldThread.Get(), thread))
        return {"interrupt-thread-object-conflict", ERROR_INVALID_DATA};
    HANDLE duplicate = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), thread, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
        return WinError("hold-interrupt-thread");
    heldThread.Reset(duplicate);
    return {};
}

NativeDebugError EnrollNativeBreakpointThread(NativeDebugSlots& slots, DWORD pid, DWORD tid, HANDLE eventThread,
    std::uint64_t address, DWORD64 control, std::uint64_t revision, bool pageMode) {
    constexpr DWORD64 mask = 0x000f0003;
    if (const auto old = slots.find(tid); old != slots.end()) {
        if (!eventThread)
        {
            return {"breakpoint-thread-object-required", ERROR_INVALID_HANDLE};
        }
        if (CompareObjectHandles(old->second.thread.Get(), eventThread))
        {
            // 已登记不等于目前仍武装；安装失败或目标改写DR0后，不能让旧槽位掩盖覆盖缺口。
            if (pageMode)
            {
                return {}; // NX登记只保留线程对象，页保护由原owner统一核验。
            }
            CONTEXT observed{}; // 只读硬件槽位，不重写目标已有TF、RIP或其它调试槽。
            observed.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!GetThreadContext(old->second.thread.Get(), &observed))
            {
                return WinError("read-enrolled-breakpoint-thread");
            }
            if (observed.Dr0 != address || (observed.Dr7 & mask) != control)
            {
                return {"enrolled-breakpoint-thread-no-longer-armed", ERROR_INVALID_DATA};
            }
            return {}; // 同一强对象且实际槽位仍与当前绑定一致，重复登记没有写入副作用。
        }
        if (WaitForSingleObject(old->second.thread.Get(), 0) != WAIT_OBJECT_0)
            return {"breakpoint-thread-object-conflict", ERROR_INVALID_DATA};
        slots.erase(old); // 精确旧对象退出后才允许登记复用的TID。
    }
    if (slots.size() >= 1024) return {"breakpoint-thread-capacity", ERROR_BUFFER_OVERFLOW};
    NativeDebugHandle thread(OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION |
        THREAD_SUSPEND_RESUME | SYNCHRONIZE, FALSE, tid));
    if (!thread) return WinError("open-breakpoint-thread");
    if (GetProcessIdOfThread(thread.Get()) != pid || GetThreadId(thread.Get()) != tid ||
        !eventThread || !CompareObjectHandles(thread.Get(), eventThread))
        return {"breakpoint-thread-object-mismatch", ERROR_INVALID_DATA};
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetThreadTimes(thread.Get(), &created, &exited, &kernel, &user) || !FileTime(created))
        return {"breakpoint-thread-instance-unavailable", ERROR_INVALID_DATA};
    if (pageMode) {
        // NX由进程页保护触发；登记强线程身份即可，不占DR0，也不接管目标已有TF/DR状态。
        slots.emplace(tid, NativeDebugSlot{std::move(thread), 0, 0, revision,
            NativeFollowSlotState{control, std::nullopt, std::nullopt}});
        return {};
    }
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread.Get(), &context)) return WinError("read-breakpoint-thread-context");
    if ((context.Dr7 & 0xff) || (context.EFlags & 0x100)) return {"competing-thread-debug-state", ERROR_BUSY};
    HANDLE duplicate = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), thread.Get(), GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
        return WinError("hold-breakpoint-thread");
    slots.emplace(tid, NativeDebugSlot{NativeDebugHandle(duplicate), context.Dr0, context.Dr7 & mask, revision,
        NativeFollowSlotState{control, std::nullopt, std::nullopt}}); // 写入结果未知时原账也已在owner内。
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    context.Dr0 = static_cast<decltype(context.Dr0)>(address);
    context.Dr7 = static_cast<decltype(context.Dr7)>((context.Dr7 & ~mask) | control);
    if (!SetThreadContext(thread.Get(), &context)) return WinError("arm-breakpoint-thread");
    if (!GetThreadContext(thread.Get(), &context)) return WinError("read-armed-breakpoint-thread");
    if (context.Dr0 != address || (context.Dr7 & mask) != control) return {"verify-armed-breakpoint-thread", ERROR_INVALID_DATA};
    return {};
}

NativeDebugError RestoreNativeBreakpointThreads(NativeDebugSlots& slots, std::uint64_t address) {
    constexpr DWORD64 mask = 0x000f0003;
    NativeDebugError first;
    for (auto it = slots.begin(); it != slots.end();) {
        const auto& slot = it->second;
        const auto thread = slot.thread.Get();
        NativeDebugError error;
        const auto wait = WaitForSingleObject(thread, 0);
        if (wait == WAIT_FAILED) error = WinError("check-breakpoint-thread-lifetime");
        else if (wait == WAIT_TIMEOUT) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!GetThreadContext(thread, &context)) error = WinError("read-breakpoint-restore-context");
            else if (context.Dr0 != slot.originalAddress || (context.Dr7 & mask) != slot.originalControl) {
                if (context.Dr0 != address || ((context.Dr7 & mask) != slot.followState.expectedControl &&
                    (!slot.followState.alternateControl || (context.Dr7 & mask) != *slot.followState.alternateControl)))
                    error = {"breakpoint-slot-restore-conflict", ERROR_INVALID_DATA};
                else {
                    context.Dr0 = static_cast<decltype(context.Dr0)>(slot.originalAddress);
                    context.Dr7 = static_cast<decltype(context.Dr7)>((context.Dr7 & ~mask) | slot.originalControl);
                    context.Dr6 = static_cast<decltype(context.Dr6)>(context.Dr6 & ~DWORD64{1});
                    if (!SetThreadContext(thread, &context)) error = WinError("restore-breakpoint-thread");
                    else if (!GetThreadContext(thread, &context)) error = WinError("read-restored-breakpoint-thread");
                    else if (context.Dr0 != slot.originalAddress || (context.Dr7 & mask) != slot.originalControl)
                        error = {"verify-restored-breakpoint-thread", ERROR_INVALID_DATA};
                }
            }
        } else if (wait != WAIT_OBJECT_0) error = {"check-breakpoint-thread-lifetime", ERROR_INVALID_DATA};
        if (error) { if (!first) first = error; ++it; }
        else it = slots.erase(it); // 逐项确认，单项失败不丢失责任，也不跳过其它线程。
    }
    return first;
}

NativeDebugError CheckProcessIdentity(HANDLE process, const NativePauseRequest& request) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return WinError("get-process-times");
    if (GetProcessId(process) != request.pid || FileTime(created) != request.processCreationTime)
        return {"process-instance-mismatch", ERROR_INVALID_PARAMETER};
    return {};
}

NativeDebugError CheckAdmission(HANDLE process, const NativePauseRequest& request) {
    if (const auto error = CheckProcessIdentity(process, request); error) return error;
    const auto wait = WaitForSingleObject(process, 0);
    if (wait == WAIT_FAILED) return WinError("check-process-lifetime");
    if (wait != WAIT_TIMEOUT) return {"process-already-exited", ERROR_PROCESS_ABORTED};
    if (const auto error = CheckUser(process); error) return error;
    BOOL critical = FALSE;
    if (!IsProcessCritical(process, &critical)) return WinError("check-critical-process");
    if (critical) return {"critical-process-excluded", ERROR_ACCESS_DENIED};
    USHORT machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native = IMAGE_FILE_MACHINE_UNKNOWN;
    if (!IsWow64Process2(GetCurrentProcess(), &machine, &native) ||
        machine != IMAGE_FILE_MACHINE_UNKNOWN || native != IMAGE_FILE_MACHINE_AMD64)
        return {"native-amd64-owner-required", ERROR_NOT_SUPPORTED};
    if (!IsWow64Process2(process, &machine, &native)) return WinError("check-target-architecture");
    if (machine != IMAGE_FILE_MACHINE_UNKNOWN || native != IMAGE_FILE_MACHINE_AMD64)
        return {"native-amd64-target-required", ERROR_NOT_SUPPORTED};
    BOOL debugging = FALSE;
    if (!CheckRemoteDebuggerPresent(process, &debugging)) return WinError("check-existing-debugger");
    return debugging ? NativeError{"debugger-already-present", ERROR_BUSY} : NativeError{};
}

NativeDebugError CheckOwnedChild(const NativePauseRequest& request) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return WinError("get-owner-times");
    if (request.processCreationTime <= FileTime(created)) return {"direct-child-required", ERROR_ACCESS_DENIED};
    const Handle processes(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!processes) return WinError("snapshot-child-identity");
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(processes.Get(), &entry)) return WinError("enumerate-child-identity");
    do {
        if (entry.th32ProcessID == request.pid)
            return entry.th32ParentProcessID == GetCurrentProcessId() ? NativeError{} :
                NativeError{"direct-child-required", ERROR_ACCESS_DENIED};
    } while (Process32NextW(processes.Get(), &entry));
    return {"process-child-not-found", ERROR_NOT_FOUND};
}

std::string NewId() {
    GUID guid{};
    wchar_t text[39]{};
    if (FAILED(CoCreateGuid(&guid)) || StringFromGUID2(guid, text, 39) != 39) return {};
    std::string id;
    id.reserve(36);
    for (std::size_t i = 1; i <= 36; ++i) {
        const auto digit = text[i];
        id.push_back(static_cast<char>(digit >= L'A' && digit <= L'F' ? digit - L'A' + L'a' : digit));
    }
    return id;
}

// 以本次后端身份为命名空间；滚动历史淘汰后也不复用停止组/停点ID。
std::string BreakpointId(std::string_view backend, std::uint64_t revision, bool stop) {
    constexpr std::string_view hex = "0123456789abcdef";
    std::string id(backend);
    id[14] = '8';
    id[16] = hex[hex.find(id[16]) ^ static_cast<std::size_t>(stop)];
    id[19] = hex[8 | (hex.find(id[19]) & 3)];
    for (const auto i : {35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 22, 21, 20, 17}) {
        id[i] = hex[hex.find(id[i]) ^ static_cast<std::size_t>(revision & 15)];
        revision >>= 4;
    }
    return id;
}

std::string MembershipHash(const std::vector<ThreadIdentity>& ordered) {
    std::string bytes = "ksword-action-analyze-native-members-v1\n";
    for (const auto& thread : ordered) {
        bytes += thread.threadId;
        bytes += ' ';
        bytes += thread.processInstanceId;
        bytes += '\n';
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return {};
    std::array<UCHAR, 32> hash{};
    const NTSTATUS status = BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(bytes.data()),
        static_cast<ULONG>(bytes.size()), hash.data(), static_cast<ULONG>(hash.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) return {};
    constexpr std::string_view hex = "0123456789abcdef";
    std::string result;
    result.reserve(hash.size() * 2);
    for (const auto byte : hash) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 15]);
    }
    return result;
}

NativeDebugError CaptureThreads(DWORD pid, const std::string& processInstanceId, const NativeDebugThreadIds& priorIds,
    std::vector<NativeDebugFrozenThread>& threads) {
    const Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot) return WinError("snapshot-threads");
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot.Get(), &entry)) return WinError("read-threads");
    do {
        if (entry.th32OwnerProcessID != pid) continue;
        Handle thread(OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, entry.th32ThreadID));
        if (!thread) {
            const auto error = WinError("open-frozen-thread");
            if (error.code == ERROR_INVALID_PARAMETER) continue;
            return error;
        }
        const auto threadPid = GetProcessIdOfThread(thread.Get());
        if (!threadPid) return WinError("get-thread-process-id");
        if (threadPid != pid) continue;
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetThreadTimes(thread.Get(), &created, &exited, &kernel, &user)) return WinError("get-thread-times");
        const auto wait = WaitForSingleObject(thread.Get(), 0);
        if (wait == WAIT_FAILED) return WinError("check-thread-lifetime");
        if (wait == WAIT_OBJECT_0) continue;
        if (threads.size() == 1024) return {"frozen-thread-capacity", ERROR_BUFFER_OVERFLOW};
        const auto createdAt = FileTime(created);
        if (!createdAt) return {"missing-thread-creation-time", ERROR_INVALID_DATA};
        const auto prior = priorIds.find({entry.th32ThreadID, createdAt});
        auto threadId = prior == priorIds.end() ? NewId() : prior->second;
        if (threadId.empty()) return {"create-thread-id", ERROR_GEN_FAILURE};
        threads.push_back({std::move(thread), {{std::move(threadId), processInstanceId}, entry.th32ThreadID, createdAt}});
    } while (Thread32Next(snapshot.Get(), &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) return WinError("enumerate-threads");
    if (threads.empty()) return {"no-strong-live-members", ERROR_NOT_FOUND};
    std::sort(threads.begin(), threads.end(), [](const auto& a, const auto& b) {
        return a.member.identity.threadId < b.member.identity.threadId;
    });
    return {};
}

NativeControlResult NativeExecutionRangeHistory::Apply(const OwnerIdentity& owner, const NativeExecutionRangeRequest& request,
    NativeControlResult current, NativePrivateExecutionPage* page, HANDLE process) {
    const auto reject = [&](const char* stage, DWORD error, LedgerResult reason) {
        auto result = current;
        result.status = NativeControlStatus::Rejected;
        result.stage = stage;
        result.win32Error = error;
        result.ledgerResult = reason;
        result.executionRange = NativeExecutionRangeReceipt{request, current.group ? current.group->stateRevision : 0,
            false, true, stage, error};
        return result;
    };
    std::string_view id = request.stop.requestId;
    if (!id.starts_with("range/")) return reject("private-execution-range-id-required", ERROR_INVALID_PARAMETER, LedgerResult::InvalidEvidence);
    id.remove_prefix(6);
    std::uint64_t sequence = 0;
    const auto parsed = std::from_chars(id.data(), id.data() + id.size(), sequence);
    if (id.empty() || id.front() == '0' || !sequence || parsed.ec != std::errc{} || parsed.ptr != id.data() + id.size())
        return reject("private-execution-range-id-required", ERROR_INVALID_PARAMETER, LedgerResult::InvalidEvidence);
    if (const auto old = history_.find(sequence); old != history_.end()) {
        if (old->second.first != request)
            return reject("private-execution-range-request-conflict", ERROR_INVALID_PARAMETER, LedgerResult::Conflict);
        auto replay = old->second.second;
        replay.ledgerResult = LedgerResult::Duplicate;
        return replay;
    }
    if (sequence <= sequence_) return reject("private-execution-range-replay-expired", ERROR_NOT_FOUND, LedgerResult::ReplayExpired);
    auto& cached = history_.emplace(sequence, std::make_pair(request, NativeControlResult{})).first->second.second;
    sequence_ = sequence; // 失败也消费本票据，不能重用相同序号产生不同副作用。
    last_ = NativeExecutionRangeReceipt{request, current.group ? current.group->stateRevision : 0};
    const auto finish = [&](const char* stage, DWORD error, LedgerResult reason, bool rollback = true, bool recovery = false) {
        last_->stage = stage;
        last_->win32Error = error;
        last_->rollbackComplete = rollback;
        cached = error ? reject(stage, error, reason) : current;
        cached.executionRange = last_;
        if (!rollback || recovery) {
            cached.status = NativeControlStatus::RecoveryRequired;
            if (cached.breakpoint) {
                cached.breakpoint->state = NativeBreakpointState::RecoveryRequired;
                cached.breakpoint->stage = stage;
                cached.breakpoint->win32Error = error;
            }
        }
        auto result = cached;
        while (history_.size() > 128) history_.erase(history_.begin());
        return result;
    };
    const auto& stop = request.stop;
    const auto& group = current.group;
    const auto& responsibility = current.responsibility;
    if (!page || !process || !current.breakpoint || !current.breakpoint->rangeBytes ||
        current.breakpoint->state != NativeBreakpointState::Held || !current.breakpoint->explicitPrivateAddress ||
        current.breakpoint->writeWatchBytes || current.breakpoint->executePointerExport)
        return finish("private-execution-range-nx-owner-required", ERROR_INVALID_STATE, LedgerResult::InvalidTransition);
    if (stop.owner != owner || !group || group->sampleId != owner.sampleId || group->sessionId != owner.sessionId ||
        group->epoch != owner.epoch || !responsibility || !current.pending || stop.event.backendInstanceId != owner.backendInstanceId ||
        stop.groupId != group->groupId || stop.groupId != responsibility->groupId || stop.stopId != responsibility->stopId ||
        stop.event != responsibility->event || stop.event != current.pending->event || stop.expectedStateRevision != group->stateRevision)
        return finish("private-execution-range-stale-stop", ERROR_INVALID_DATA, LedgerResult::StaleRevision);
    if (current.status != NativeControlStatus::Held || !current.attached || current.clean || group->historical ||
        group->state != GroupState::HeldComplete || (group->origin && group->origin->hold != OriginHold::Held) ||
        responsibility->state != EventState::Held || !current.pending->ledgerOwned || current.pending->continuationIndeterminate ||
        current.pending->eventCode != EXCEPTION_DEBUG_EVENT || current.pending->exceptionFirstChance != true ||
        current.pending->pid != current.pid)
        return finish("private-execution-range-complete-held-stop-required", ERROR_INVALID_STATE, LedgerResult::InvalidTransition);
    const auto origin = std::find_if(current.frozenThreads.begin(), current.frozenThreads.end(), [&](const auto& member) {
        return member.tid == current.pending->tid && member.identity == responsibility->actualEventThread &&
            member.creationTime && member.identity.processInstanceId == current.processInstanceId;
    });
    if (origin == current.frozenThreads.end())
        return finish("private-execution-range-event-thread-not-frozen", ERROR_INVALID_DATA, LedgerResult::IdentityMismatch);
    const NativePauseRequest target{"", current.pid, current.processCreationTime, true, NativeTargetDisposition::ResumeAndDetach};
    if (const auto error = CheckProcessIdentity(process, target); error)
        return finish(error.stage, error.code, LedgerResult::IdentityMismatch);
    if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT)
        return finish("private-execution-range-process-not-live", ERROR_PROCESS_ABORTED, LedgerResult::IdentityMismatch);
    if (const auto error = page->Verify(process))
        return finish("private-execution-range-existing-pages-changed", error, LedgerResult::IdentityMismatch, true, true);
    // 按本次实际目录预留下一项，解除64页限制后也保证保护事务之后不再扩容。
    auto& publishedRanges = current.breakpoint->executionRanges; // 仍发布原owner的完整范围目录。
    if (page->Ranges().size() >= publishedRanges.max_size())
        return finish("private-execution-range-capacity-exhausted", ERROR_NOT_ENOUGH_MEMORY, LedgerResult::Capacity);
    try
    {
        publishedRanges.reserve(page->Ranges().size() + 1);
    }
    catch (const std::bad_alloc&)
    {
        return finish("private-execution-range-allocation-failed", ERROR_NOT_ENOUGH_MEMORY, LedgerResult::Capacity);
    }
    bool rollback = true;
    const auto error = page->AddRange(process, current.pid, request.address, request.bytes, rollback);
    if (error) return finish("private-execution-range-add-failed", error,
        error == ERROR_NOT_ENOUGH_MEMORY ? LedgerResult::Capacity : LedgerResult::InvalidTransition, rollback,
        page->Verify(process) != ERROR_SUCCESS);
    current.breakpoint->executionRanges = page->Ranges();
    current.stage = "private-execution-range-added";
    current.win32Error = ERROR_SUCCESS;
    last_->added = true;
    return finish("private-execution-range-added", ERROR_SUCCESS, LedgerResult::Applied);
}

NativeControlResult NativeArmedPauseHistory::Begin(const OwnerIdentity& owner, const OwnerIdentity& requestedOwner,
    const NativePauseRequest& request, const NativeControlResult& current, bool available, bool& issue) {
    issue = false;
    auto result = current;
    const auto reject = [&](const char* stage, DWORD error, LedgerResult reason) {
        result.status = NativeControlStatus::Rejected;
        result.stage = stage;
        result.win32Error = error;
        result.ledgerResult = reason;
        result.armedPause = NativeArmedPauseReceipt{requestedOwner, request, NativeArmedPauseState::Rejected,
            {}, {}, stage, error};
        return result;
    };
    if (requestedOwner != owner) return reject("armed-pause-owner-mismatch", ERROR_INVALID_DATA, LedgerResult::IdentityMismatch);
    std::string_view id = request.requestId;
    if (!id.starts_with("pause/")) return reject("armed-pause-id-required", ERROR_INVALID_PARAMETER, LedgerResult::InvalidEvidence);
    id.remove_prefix(6);
    std::uint64_t sequence = 0;
    const auto parsed = std::from_chars(id.data(), id.data() + id.size(), sequence);
    if (id.empty() || id.front() == '0' || !sequence || parsed.ec != std::errc{} || parsed.ptr != id.data() + id.size())
        return reject("armed-pause-id-required", ERROR_INVALID_PARAMETER, LedgerResult::InvalidEvidence);
    if (const auto old = history_.find(sequence); old != history_.end()) {
        if (old->second.request != request) return reject("armed-pause-request-conflict", ERROR_INVALID_PARAMETER, LedgerResult::Conflict);
        result.armedPause = old->second;
        result.ledgerResult = LedgerResult::Duplicate;
        return result;
    }
    if (sequence <= sequence_) return reject("armed-pause-replay-expired", ERROR_NOT_FOUND, LedgerResult::ReplayExpired);
    NativeArmedPauseReceipt receipt{owner, request};
    if (!request.explicitlyAuthorized || !request.pid || !request.processCreationTime ||
        request.disposition != NativeTargetDisposition::ResumeAndDetach || request.pid != current.pid ||
        request.processCreationTime != current.processCreationTime) {
        result = reject("armed-pause-process-authorization-mismatch", ERROR_INVALID_PARAMETER, LedgerResult::IdentityMismatch);
        receipt = *result.armedPause;
    } else if (!available || pending_) {
        result = reject("armed-pause-owner-unavailable", ERROR_BUSY, LedgerResult::InvalidTransition);
        receipt = *result.armedPause;
    } else {
        issue = true;
        pending_ = sequence;
    }
    history_.emplace(sequence, receipt);
    sequence_ = sequence;
    last_ = receipt;
    result.armedPause = receipt;
    if (issue) { result.stage = receipt.stage; result.win32Error = 0; }
    while (history_.size() > 128) {
        auto oldest = history_.begin();
        if (pending_ && oldest->first == *pending_) ++oldest;
        history_.erase(oldest);
    }
    return result;
}

std::optional<NativeArmedPauseReceipt> NativeArmedPauseHistory::Find(std::string_view id) const {
    for (const auto& [sequence, receipt] : history_) {
        (void)sequence;
        if (receipt.request.requestId == id) return receipt;
    }
    return {};
}

void NativeArmedPauseHistory::Complete(NativeArmedPauseState state, const char* stage, DWORD error,
    std::optional<std::string> group, std::optional<NativeEventKey> event) {
    if (!pending_) return;
    auto& receipt = history_.at(*pending_);
    receipt.state = state;
    receipt.stage = stage;
    receipt.win32Error = error;
    receipt.groupId = std::move(group);
    receipt.event = std::move(event);
    last_ = receipt;
    pending_.reset(); // 中断排空责任仍由原owner持有，不随请求终态消失。
}

} // namespace ks::cli::action_analyze::control::native_owner_detail
