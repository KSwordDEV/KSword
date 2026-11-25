#include "NativeDebugOwner.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>
#include <bcrypt.h>
#include <objbase.h>

#include "NativeBreakpointImage.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <thread>
#include <utility>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "onecore.lib")

namespace ks::cli::action_analyze::control {
namespace {

constexpr std::size_t kMaxGroups = 64;
constexpr std::size_t kMaxMembers = 1024;
constexpr DWORD kWaitMs = 10;
constexpr DWORD kAttachDeadlineMs = 5000;
constexpr std::string_view kClosePrefix = "native-owner-close/";
constexpr DWORD64 kDr0Control = 0x000f0003;
constexpr DWORD64 kDr0LocalExecute = 1;
constexpr DWORD64 kDr6Reasons = 0xe00f;
constexpr DWORD kTrapFlag = 0x100;
constexpr DWORD kResumeFlag = 0x10000;

std::uintptr_t InstructionPointer(const CONTEXT& context) noexcept {
#if defined(_M_X64)
    return context.Rip;
#else
    // Win32 CLI 仍需编译；CheckAdmission 不会在该构建放行本后端。
    return context.Eip;
#endif
}

class Handle {
public:
    explicit Handle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~Handle() { Reset(); }
    Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    Handle& operator=(Handle&& other) noexcept {
        Reset(std::exchange(other.value_, nullptr));
        return *this;
    }
    HANDLE Get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }
    void Reset(HANDLE value = nullptr) noexcept {
        if (*this) { CloseHandle(value_); }
        value_ = value;
    }

private:
    HANDLE value_;
};

std::uint64_t FileTime(FILETIME value) noexcept {
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

std::optional<std::uint64_t> ReadQpc() noexcept {
    LARGE_INTEGER counter{};
    if (!QueryPerformanceCounter(&counter) || counter.QuadPart < 0) { return std::nullopt; }
    return static_cast<std::uint64_t>(counter.QuadPart);
}

std::string NewId() {
    GUID guid{};
    wchar_t text[39]{};
    if (FAILED(CoCreateGuid(&guid)) || StringFromGUID2(guid, text, 39) != 39) { return {}; }
    std::string id;
    id.reserve(36);
    for (std::size_t i = 1; i <= 36; ++i) {
        const auto digit = text[i];
        id.push_back(static_cast<char>(digit >= L'A' && digit <= L'F' ? digit - L'A' + L'a' : digit));
    }
    return id;
}

std::string MembershipHash(const std::vector<ThreadIdentity>& ordered) {
    // Versioned fixed-width encoding. IDs are lowercase UUIDs sorted by threadId.
    std::string bytes = "ksword-action-analyze-native-members-v1\n";
    for (const auto& thread : ordered) {
        bytes += thread.threadId;
        bytes += ' ';
        bytes += thread.processInstanceId;
        bytes += '\n';
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) { return {}; }
    std::array<UCHAR, 32> hash{};
    const NTSTATUS status = BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(bytes.data()),
        static_cast<ULONG>(bytes.size()), hash.data(), static_cast<ULONG>(hash.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) { return {}; }
    constexpr std::string_view hex = "0123456789abcdef";
    std::string result;
    result.reserve(hash.size() * 2);
    for (const auto byte : hash) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 15]);
    }
    return result;
}

struct NativeError {
    const char* stage = "idle";
    DWORD code = ERROR_SUCCESS;
    explicit operator bool() const noexcept { return code != ERROR_SUCCESS; }
};

NativeError WinError(const char* stage) noexcept {
    const DWORD error = GetLastError();
    return {stage, error ? error : ERROR_GEN_FAILURE};
}

NativeError CheckUser(HANDLE target) {
    Handle ours;
    Handle theirs;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) { return WinError("open-owner-token"); }
    ours.Reset(token);
    if (!OpenProcessToken(target, TOKEN_QUERY, &token)) { return WinError("open-target-token"); }
    theirs.Reset(token);

    struct UserBuffer {
        TOKEN_USER user;
        std::array<std::byte, SECURITY_MAX_SID_SIZE> sidStorage;
    } ourUser{}, targetUser{};
    DWORD bytes = 0;
    if (!GetTokenInformation(ours.Get(), TokenUser, &ourUser, sizeof(ourUser), &bytes) ||
        !GetTokenInformation(theirs.Get(), TokenUser, &targetUser, sizeof(targetUser), &bytes)) {
        return WinError("read-user-sid");
    }
    if (!EqualSid(ourUser.user.User.Sid, targetUser.user.User.Sid)) { return {"same-user-required", ERROR_ACCESS_DENIED}; }
    DWORD ourSession = 0;
    DWORD targetSession = 0;
    if (!GetTokenInformation(ours.Get(), TokenSessionId, &ourSession, sizeof(ourSession), &bytes) ||
        !GetTokenInformation(theirs.Get(), TokenSessionId, &targetSession, sizeof(targetSession), &bytes)) {
        return WinError("read-token-session");
    }
    if (ourSession != targetSession) { return {"same-session-required", ERROR_ACCESS_DENIED}; }
    return {};
}

NativeError CheckProcessIdentity(HANDLE process, const NativePauseRequest& request) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) { return WinError("get-process-times"); }
    if (GetProcessId(process) != request.pid || FileTime(created) != request.processCreationTime) {
        return {"process-instance-mismatch", ERROR_INVALID_PARAMETER};
    }
    return {};
}

NativeError CheckAdmission(HANDLE process, const NativePauseRequest& request) {
    if (const auto error = CheckProcessIdentity(process, request); error) { return error; }
    const auto wait = WaitForSingleObject(process, 0);
    if (wait == WAIT_FAILED) { return WinError("check-process-lifetime"); }
    if (wait != WAIT_TIMEOUT) { return {"process-already-exited", ERROR_PROCESS_ABORTED}; }
    if (const auto error = CheckUser(process); error) { return error; }
    BOOL critical = FALSE;
    if (!IsProcessCritical(process, &critical)) { return WinError("check-critical-process"); }
    if (critical) { return {"critical-process-excluded", ERROR_ACCESS_DENIED}; }
    USHORT machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native = IMAGE_FILE_MACHINE_UNKNOWN;
    if (!IsWow64Process2(GetCurrentProcess(), &machine, &native) ||
        machine != IMAGE_FILE_MACHINE_UNKNOWN || native != IMAGE_FILE_MACHINE_AMD64) {
        return {"native-amd64-owner-required", ERROR_NOT_SUPPORTED};
    }
    if (!IsWow64Process2(process, &machine, &native)) { return WinError("check-target-architecture"); }
    if (machine != IMAGE_FILE_MACHINE_UNKNOWN || native != IMAGE_FILE_MACHINE_AMD64) {
        return {"native-amd64-target-required", ERROR_NOT_SUPPORTED};
    }
    BOOL debugging = FALSE;
    if (!CheckRemoteDebuggerPresent(process, &debugging)) { return WinError("check-existing-debugger"); }
    if (debugging) { return {"debugger-already-present", ERROR_BUSY}; }
    return {};
}

NativeError CheckOwnedChild(const NativePauseRequest& request) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) { return WinError("get-owner-times"); }
    if (request.processCreationTime <= FileTime(created)) { return {"direct-child-required", ERROR_ACCESS_DENIED}; }
    const Handle processes(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!processes) { return WinError("snapshot-child-identity"); }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(processes.Get(), &entry)) { return WinError("enumerate-child-identity"); }
    do {
        if (entry.th32ProcessID == request.pid) {
            return entry.th32ParentProcessID == GetCurrentProcessId() ? NativeError{} :
                NativeError{"direct-child-required", ERROR_ACCESS_DENIED};
        }
    } while (Process32NextW(processes.Get(), &entry));
    return {"process-child-not-found", ERROR_NOT_FOUND};
}

bool AbsoluteModulePath(std::wstring_view path) {
    return path.size() >= 4 && path.size() < MAX_PATH && path.find(L'\0') == path.npos &&
        ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' && path[2] == L'\\';
}

struct FrozenThread {
    Handle handle;
    NativeFrozenThread member;
};

using ThreadIds = std::map<std::pair<DWORD, std::uint64_t>, std::string>;

NativeError CaptureThreads(DWORD pid, const std::string& processInstanceId, const ThreadIds& priorIds,
    std::vector<FrozenThread>& threads) {
    const Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot) { return WinError("snapshot-threads"); }
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot.Get(), &entry)) { return WinError("read-threads"); }
    do {
        if (entry.th32OwnerProcessID != pid) { continue; }
        Handle thread(OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, entry.th32ThreadID));
        if (!thread) {
            // A TID that disappeared while being frozen never yields a strong member.
            const auto error = WinError("open-frozen-thread");
            if (error.code == ERROR_INVALID_PARAMETER) { continue; }
            return error;
        }
        const auto threadPid = GetProcessIdOfThread(thread.Get());
        if (!threadPid) { return WinError("get-thread-process-id"); }
        if (threadPid != pid) { continue; }
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetThreadTimes(thread.Get(), &created, &exited, &kernel, &user)) { return WinError("get-thread-times"); }
        const auto wait = WaitForSingleObject(thread.Get(), 0);
        if (wait == WAIT_FAILED) { return WinError("check-thread-lifetime"); }
        if (wait == WAIT_OBJECT_0) { continue; }
        if (threads.size() == kMaxMembers) { return {"frozen-thread-capacity", ERROR_BUFFER_OVERFLOW}; }
        const auto createdAt = FileTime(created);
        if (!createdAt) { return {"missing-thread-creation-time", ERROR_INVALID_DATA}; }
        const auto prior = priorIds.find({entry.th32ThreadID, createdAt});
        auto threadId = prior == priorIds.end() ? NewId() : prior->second;
        if (threadId.empty()) { return {"create-thread-id", ERROR_GEN_FAILURE}; }
        threads.push_back({std::move(thread), {{std::move(threadId), processInstanceId}, entry.th32ThreadID, createdAt}});
    } while (Thread32Next(snapshot.Get(), &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) { return WinError("enumerate-threads"); }
    if (threads.empty()) { return {"no-strong-live-members", ERROR_NOT_FOUND}; }
    std::sort(threads.begin(), threads.end(), [](const auto& a, const auto& b) {
        return a.member.identity.threadId < b.member.identity.threadId;
    });
    return {};
}

} // namespace

class NativeDebugOwner::Impl final {
public:
    explicit Impl(OwnerIdentity owner) : owner_(std::move(owner)), ledger_(owner_), thread_([this] { Run(); }) {}
    ~Impl() {
        Invoke([this] {
            stopWhenClean_ = true;
            return Close();
        });
        thread_.join();
    }

    template<class Function>
    NativeControlResult Invoke(Function operation) {
        const std::lock_guard callLock(caller_);
        auto job = std::make_shared<std::packaged_task<NativeControlResult()>>(std::move(operation));
        auto result = job->get_future();
        {
            const std::lock_guard lock(queueMutex_);
            queued_ = [job] { (*job)(); };
        }
        wake_.notify_one();
        return result.get();
    }

    NativeControlResult Pause(const NativePauseRequest& request);
    NativeControlResult ArmBreakpoint(const NativeBreakpointRequest& request);
    NativeControlResult Query(std::string_view groupId, std::string_view releaseRequestId = {}) const;
    NativeControlResult Release(const ReleaseRequest& request, bool recover, bool internal = false);
    NativeControlResult Close();

private:
    struct PauseRecord {
        NativePauseRequest request;
        std::string groupId;
        std::string stopId;
        std::string processInstanceId;
        NativeControlStatus status = NativeControlStatus::Accepted;
        NativeError outcome{"attach-accepted", ERROR_SUCCESS};
        std::optional<std::string> lastReleaseRequestId = std::nullopt;
        std::vector<NativeFrozenThread> frozenThreads{};
        NativeStopTiming timing{};
        std::optional<NativeBreakpointHit> hit{};
    };

    struct DebugSlot {
        Handle thread;
        DWORD64 originalAddress;
        DWORD64 originalControl;
    };

    struct ActiveBreakpoint {
        NativeBreakpointRequest request;
        NativeBreakpointBinding binding;
        NativeImageSite systemBreak;
        NativeImageSite systemBreakThread;
        std::map<DWORD, DebugSlot> slots;
        DWORD interruptTid = 0;
        bool processVerified = false;
        bool installed = false;
        bool interruptRequested = false;
        bool retire = false;
        NativeError retirement;
        std::optional<DWORD> cleanupDisposition;
        bool retryHitContext = false;
    };

    void Run();
    void Pump();
    void Receive(const DEBUG_EVENT& event);
    void ReceiveBreakpoint(const DEBUG_EVENT& event);
    NativeError ResolveBreakpointImages();
    NativeError InstallBreakpoint();
    NativeError EnrollThread(DWORD tid, HANDLE eventThread = nullptr);
    NativeError RestoreBreakpoint();
    NativeError AdoptBreakpointHit();
    NativeError PrepareBreakpointResume();
    void RetireBreakpoint(NativeError reason);
    void BreakpointRecovery(NativeError error);
    void FinishBreakpointEvent(DWORD disposition);
    void RequestBreakpointClose();
    void AdoptCreateEvent();
    bool ApplyContinue(DWORD disposition);
    void Detach();
    void Complete(NativeControlStatus status, NativeError outcome);
    NativeControlResult Snapshot(const PauseRecord* record) const;
    NativeControlResult Reject(NativeError error, LedgerResult ledgerResult, const PauseRecord* record = nullptr) const;

    const OwnerIdentity owner_;
    StopLedger ledger_;
    std::map<std::string, PauseRecord, std::less<>> pauses_;
    PauseRecord* latest_ = nullptr;
    PauseRecord* firstBound_ = nullptr;
    Handle process_;
    ThreadIds threadIds_;
    std::vector<FrozenThread> members_;
    std::optional<DEBUG_EVENT> event_;
    std::optional<ActiveBreakpoint> breakpoint_;
    std::optional<std::uint64_t> failedContinueSerial_;
    std::uint64_t eventSerial_ = 0;
    ULONGLONG attachDeadline_ = 0;
    bool attached_ = false;
    bool closing_ = false;
    bool stopWhenClean_ = false;
    NativeError killOnExitError_;

    std::mutex caller_;
    std::mutex queueMutex_;
    std::condition_variable wake_;
    std::function<void()> queued_;
    std::thread thread_;
};

NativeControlResult NativeDebugOwner::Impl::Snapshot(const PauseRecord* record) const {
    NativeControlResult result;
    result.attached = attached_;
    result.clean = !attached_ && !event_ && ledger_.CanRetireLedger();
    if (!record) { return result; }
    result.status = record->status;
    result.stage = record->outcome.stage;
    result.win32Error = record->outcome.code;
    result.pauseRequestId = record->request.requestId;
    result.pid = record->request.pid;
    result.processCreationTime = record->request.processCreationTime;
    result.processInstanceId = record->processInstanceId;
    result.group = ledger_.Query(record->groupId);
    result.frozenThreads = record->frozenThreads;
    result.timing = record->timing;
    if (breakpoint_) { result.breakpoint = breakpoint_->binding; }
    result.breakpointHit = record->hit;
    if (record->lastReleaseRequestId) {
        result.releaseRequestId = record->lastReleaseRequestId;
        result.release = ledger_.QueryRelease(*record->lastReleaseRequestId);
    }
    if (record == latest_) {
        result.responsibility = ledger_.UnresolvedNativeResponsibility();
        if (event_) {
            result.pending = NativePendingEvent{{owner_.backendInstanceId, eventSerial_}, event_->dwProcessId,
                event_->dwThreadId, event_->dwDebugEventCode, std::nullopt, std::nullopt, result.responsibility.has_value()};
            if (event_->dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                result.pending->exceptionCode = event_->u.Exception.ExceptionRecord.ExceptionCode;
                result.pending->exceptionFirstChance = event_->u.Exception.dwFirstChance != 0;
            }
        }
    }
    return result;
}

NativeControlResult NativeDebugOwner::Impl::Reject(NativeError error, LedgerResult ledgerResult, const PauseRecord* record) const {
    auto result = Snapshot(record ? record : latest_);
    result.status = NativeControlStatus::Rejected;
    result.stage = error.stage;
    result.win32Error = error.code;
    result.ledgerResult = ledgerResult;
    return result;
}

NativeControlResult NativeDebugOwner::Impl::Pause(const NativePauseRequest& request) {
    if (request.requestId.empty() || request.requestId.size() > 128 || request.requestId.starts_with(kClosePrefix) ||
        !request.pid || request.pid == GetCurrentProcessId() || !request.processCreationTime ||
        !request.explicitlyAuthorized || request.disposition != NativeTargetDisposition::ResumeAndDetach) {
        return Reject({"explicit-authorized-process-instance-and-disposition-required", ERROR_INVALID_PARAMETER},
            LedgerResult::InvalidEvidence);
    }
    if (const auto prior = pauses_.find(request.requestId); prior != pauses_.end()) {
        if (prior->second.request != request) { return Reject({"pause-request-conflict", ERROR_INVALID_PARAMETER}, LedgerResult::Conflict); }
        auto result = Snapshot(&prior->second);
        result.ledgerResult = LedgerResult::Duplicate;
        return result;
    }
    if (breakpoint_ || closing_ || attached_ || event_ || !ledger_.CanRetireLedger()) {
        return Reject({"native-owner-unavailable", ERROR_BUSY}, LedgerResult::InvalidTransition);
    }
    if (pauses_.size() == kMaxGroups) { return Reject({"stop-group-history-capacity", ERROR_BUFFER_OVERFLOW}, LedgerResult::Capacity); }

    if (firstBound_ && (firstBound_->request.pid != request.pid ||
        firstBound_->request.processCreationTime != request.processCreationTime)) {
        return Reject({"owner-bound-to-another-process-instance", ERROR_INVALID_PARAMETER}, LedgerResult::IdentityMismatch);
    }
    Handle newProcess;
    if (!firstBound_) {
        newProcess.Reset(OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, request.pid));
        if (!newProcess) { return Reject(WinError("open-original-process"), LedgerResult::IdentityMismatch); }
    }
    const auto process = firstBound_ ? process_.Get() : newProcess.Get();
    if (const auto error = CheckAdmission(process, request); error) {
        return Reject(error, LedgerResult::IdentityMismatch);
    }

    PauseRecord record{request, NewId(), NewId(), firstBound_ ? firstBound_->processInstanceId : NewId()};
    if (record.groupId.empty() || record.stopId.empty() || record.processInstanceId.empty()) {
        return Reject({"allocate-stop-identities", ERROR_GEN_FAILURE}, LedgerResult::InvalidEvidence);
    }
    std::vector<FrozenThread> members;
    if (const auto error = CaptureThreads(request.pid, record.processInstanceId, threadIds_, members); error) {
        return Reject(error, error.code == ERROR_BUFFER_OVERFLOW ? LedgerResult::Capacity : LedgerResult::InvalidEvidence);
    }
    FrozenStopGroup group{record.groupId, static_cast<std::uint64_t>(pauses_.size() + 1), {}, {}};
    group.requested.reserve(members.size());
    record.frozenThreads.reserve(members.size());
    ThreadIds newThreadIds;
    for (const auto& thread : members) {
        const auto& member = thread.member;
        group.requested.push_back(member.identity);
        record.frozenThreads.push_back(member);
        if (!threadIds_.contains({member.tid, member.creationTime})) {
            newThreadIds.emplace(std::pair<DWORD, std::uint64_t>{member.tid, member.creationTime}, member.identity.threadId);
        }
    }
    group.membershipSha256 = MembershipHash(group.requested);
    if (group.membershipSha256.empty()) {
        return Reject({"hash-frozen-membership", ERROR_GEN_FAILURE}, LedgerResult::InvalidEvidence);
    }
    if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT) {
        return Reject({"original-process-no-longer-live", ERROR_PROCESS_ABORTED}, LedgerResult::IdentityMismatch);
    }
    const auto inserted = pauses_.emplace(request.requestId, std::move(record)).first;
    const auto frozen = ledger_.Freeze(std::move(group));
    if (frozen != LedgerResult::Applied) {
        pauses_.erase(inserted);
        return Reject({"freeze-stop-group", ERROR_GEN_FAILURE}, frozen);
    }
    latest_ = &inserted->second;
    members_ = std::move(members);
    LARGE_INTEGER frequency{};
    if (QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0) {
        latest_->timing.qpcFrequency = static_cast<std::uint64_t>(frequency.QuadPart);
        latest_->timing.attachSubmittedQpc = ReadQpc();
    }
    if (!DebugActiveProcess(request.pid)) {
        const auto error = WinError("debug-active-process");
        Complete(NativeControlStatus::Rejected, error);
        return Snapshot(latest_);
    }
    if (!firstBound_) {
        firstBound_ = latest_;
        process_ = std::move(newProcess);
    }
    threadIds_.merge(newThreadIds);
    attached_ = true;
    killOnExitError_ = {};
    if (!DebugSetProcessKillOnExit(FALSE)) {
        killOnExitError_ = WinError("disable-kill-on-exit");
        latest_->status = NativeControlStatus::RecoveryRequired;
        latest_->outcome = killOnExitError_;
        Detach();
        return Snapshot(latest_);
    }
    attachDeadline_ = GetTickCount64() + kAttachDeadlineMs;
    return Snapshot(latest_);
}

NativeControlResult NativeDebugOwner::Impl::ArmBreakpoint(const NativeBreakpointRequest& request) {
    const auto& target = request.target;
    if (target.requestId.empty() || target.requestId.size() > 128 || target.requestId.starts_with(kClosePrefix) ||
        !target.pid || target.pid == GetCurrentProcessId() || !target.processCreationTime || !target.explicitlyAuthorized ||
        target.disposition != NativeTargetDisposition::ResumeAndDetach || !AbsoluteModulePath(request.modulePath) ||
        request.rva.has_value() == !request.exportName.empty() || (request.rva && !*request.rva) ||
        request.exportName.size() > 255 || request.exportName.find('\0') != std::string::npos) {
        return Reject({"explicit-child-and-exact-image-site-required", ERROR_INVALID_PARAMETER}, LedgerResult::InvalidEvidence);
    }
    if (breakpoint_ && breakpoint_->request.target.requestId == target.requestId) {
        if (breakpoint_->request != request) { return Reject({"breakpoint-request-conflict", ERROR_INVALID_PARAMETER}, LedgerResult::Conflict); }
        auto result = Snapshot(latest_);
        result.ledgerResult = LedgerResult::Duplicate;
        return result;
    }
    if (breakpoint_ || firstBound_ || !pauses_.empty() || closing_) {
        return Reject({"breakpoint-requires-unbound-owner", ERROR_BUSY}, LedgerResult::InvalidTransition);
    }
    Handle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, target.pid));
    if (!process) { return Reject(WinError("open-breakpoint-process"), LedgerResult::IdentityMismatch); }
    if (const auto error = CheckAdmission(process.Get(), target); error) { return Reject(error, LedgerResult::IdentityMismatch); }
    if (const auto error = CheckOwnedChild(target); error) { return Reject(error, LedgerResult::IdentityMismatch); }
    PauseRecord record{target, {}, {}, NewId()};
    if (record.processInstanceId.empty()) { return Reject({"allocate-process-instance", ERROR_GEN_FAILURE}, LedgerResult::InvalidEvidence); }
    latest_ = &pauses_.emplace(target.requestId, std::move(record)).first->second;
    firstBound_ = latest_;
    breakpoint_.emplace();
    breakpoint_->request = request;
    breakpoint_->binding.requestId = target.requestId;
    process_ = std::move(process);
    LARGE_INTEGER frequency{};
    if (QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0) {
        latest_->timing.qpcFrequency = static_cast<std::uint64_t>(frequency.QuadPart);
        latest_->timing.attachSubmittedQpc = ReadQpc();
    }
    if (!DebugActiveProcess(target.pid)) {
        const auto error = WinError("debug-active-process");
        RetireBreakpoint(error);
        Complete(NativeControlStatus::Rejected, error);
        return Snapshot(latest_);
    }
    attached_ = true;
    if (!DebugSetProcessKillOnExit(FALSE)) {
        killOnExitError_ = WinError("disable-kill-on-exit");
        RetireBreakpoint(killOnExitError_);
        Detach();
        return Snapshot(latest_);
    }
    attachDeadline_ = GetTickCount64() + kAttachDeadlineMs;
    return Snapshot(latest_);
}

NativeControlResult NativeDebugOwner::Impl::Query(std::string_view groupId, std::string_view releaseRequestId) const {
    if (!groupId.empty()) {
        for (const auto& [id, record] : pauses_) {
            if (record.groupId != groupId) { continue; }
            auto result = Snapshot(&record);
            if (!releaseRequestId.empty() && (!result.releaseRequestId || *result.releaseRequestId != releaseRequestId)) {
                return Reject({"release-request-not-found", ERROR_NOT_FOUND}, LedgerResult::InvalidEvidence, &record);
            }
            return result;
        }
        return Reject({"stop-group-not-found", ERROR_NOT_FOUND}, LedgerResult::MissingGroup);
    }
    if (!releaseRequestId.empty()) {
        return Reject({"release-query-requires-group", ERROR_INVALID_PARAMETER}, LedgerResult::InvalidEvidence);
    }
    auto result = Snapshot(latest_);
    if (closing_ && result.clean) {
        result.status = NativeControlStatus::Closed;
        result.stage = "owner-closed";
    } else if (closing_ && result.status != NativeControlStatus::RecoveryRequired) {
        result.status = NativeControlStatus::ClosePending;
    }
    return result;
}

void NativeDebugOwner::Impl::Run() {
    for (;;) {
        std::function<void()> work;
        {
            std::unique_lock lock(queueMutex_);
            if (!queued_ && (!attached_ || event_)) {
                wake_.wait(lock, [this] { return static_cast<bool>(queued_); });
            }
            work = std::exchange(queued_, {});
        }
        if (work) { work(); }
        if (closing_ && !attached_ && !event_ && ledger_.CanRetireLedger()) {
            process_.Reset();
            if (stopWhenClean_) { return; }
        }
        if (attached_ && !event_) { Pump(); }
    }
}

void NativeDebugOwner::Impl::Pump() {
    DEBUG_EVENT event{};
    if (WaitForDebugEvent(&event, kWaitMs)) {
        Receive(event);
        return;
    }
    if (GetLastError() != ERROR_SEM_TIMEOUT) {
        latest_->status = NativeControlStatus::RecoveryRequired;
        latest_->outcome = WinError("wait-for-debug-event");
        if (breakpoint_) { BreakpointRecovery(latest_->outcome); }
        // Unsupported/transient wait errors should neither tight-loop nor block submitted commands.
        std::unique_lock lock(queueMutex_);
        wake_.wait_for(lock, std::chrono::milliseconds(kWaitMs), [this] { return static_cast<bool>(queued_); });
        return;
    }
    if (breakpoint_) {
        if (breakpoint_->binding.state == NativeBreakpointState::Installing && GetTickCount64() >= attachDeadline_) {
            RetireBreakpoint({"breakpoint-attach-timeout", ERROR_TIMEOUT});
            Detach();
        } else if (breakpoint_->interruptRequested && GetTickCount64() >= attachDeadline_) {
            BreakpointRecovery({"breakpoint-cleanup-interrupt-timeout", ERROR_TIMEOUT});
        }
    } else if (latest_->status == NativeControlStatus::Accepted && GetTickCount64() >= attachDeadline_) {
        latest_->status = NativeControlStatus::Rejected;
        latest_->outcome = {"attach-create-event-timeout", ERROR_TIMEOUT};
        Detach();
    }
}

void NativeDebugOwner::Impl::Receive(const DEBUG_EVENT& event) {
    event_ = event;
    ++eventSerial_;
    // The debugger closes image file handles. Windows owns the event's process and thread handles.
    if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
        const Handle imageFile(event.u.CreateProcessInfo.hFile);
    } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
        const Handle imageFile(event.u.LoadDll.hFile);
    }
    if (event.dwProcessId != latest_->request.pid) {
        latest_->status = NativeControlStatus::RecoveryRequired;
        latest_->outcome = {"unexpected-native-event-process", ERROR_INVALID_DATA};
        return;
    }
    if (breakpoint_) {
        ReceiveBreakpoint(event);
        return;
    }
    if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && latest_->status == NativeControlStatus::Accepted && !closing_) {
        AdoptCreateEvent();
        if (ledger_.UnresolvedNativeResponsibility()) { return; }
    }

    // A failed detach may deliver the system's attach breakpoint. It is unsafe to
    // guess its disposition from the exception code alone. Keep the raw obligation.
    if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
        event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
        latest_->status = NativeControlStatus::RecoveryRequired;
        latest_->outcome = {"ambiguous-breakpoint-during-attach-cleanup", ERROR_NOT_SUPPORTED};
        return;
    }
    // Preserve exception dispatch for any non-owned exception. The manual stop only owns
    // the attach create-process event.
    if (!ApplyContinue(event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE)) { return; }
    if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
        Complete(NativeControlStatus::Ended, {"exit-process-event-continued", ERROR_SUCCESS});
    } else if (closing_ || latest_->status != NativeControlStatus::Accepted) {
        Detach();
    }
}

NativeError NativeDebugOwner::Impl::ResolveBreakpointImages() {
    auto& bp = *breakpoint_;
    const auto pid = bp.request.target.pid;
    wchar_t directory[MAX_PATH]{};
    const auto length = GetSystemDirectoryW(directory, MAX_PATH);
    if (!length || length >= MAX_PATH - 11) { return {"get-native-system-directory", ERROR_BAD_PATHNAME}; }
    std::wstring path(directory, length);
    path += L"\\ntdll.dll";
    const auto resolve = [&](std::string_view name, NativeImageSite& site) {
        return ResolveNativeImageSite(process_.Get(), pid, path, std::nullopt, name, site);
    };
    if (const auto error = resolve("DbgBreakPoint", bp.systemBreak)) { return {"resolve-system-breakpoint", error}; }
    if (const auto error = resolve("DbgUiRemoteBreakin", bp.systemBreakThread)) { return {"resolve-system-break-thread", error}; }
    return {};
}

NativeError NativeDebugOwner::Impl::EnrollThread(DWORD tid, HANDLE eventThread) {
    auto& bp = *breakpoint_;
    if (const auto old = bp.slots.find(tid); old != bp.slots.end()) {
        if (!eventThread || CompareObjectHandles(old->second.thread.Get(), eventThread)) { return {}; }
        // 已退出线程的 TID 可以复用，不能把旧 DR 恢复到新线程。
        if (WaitForSingleObject(old->second.thread.Get(), 0) != WAIT_OBJECT_0) {
            return {"breakpoint-thread-object-conflict", ERROR_INVALID_DATA};
        }
        bp.slots.erase(old);
    }
    if (bp.slots.size() >= kMaxMembers) { return {"breakpoint-thread-capacity", ERROR_BUFFER_OVERFLOW}; }
    const Handle current(OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION |
        SYNCHRONIZE, FALSE, tid));
    if (!current) { return WinError("open-breakpoint-thread"); }
    if (GetProcessIdOfThread(current.Get()) != bp.request.target.pid ||
        (eventThread && !CompareObjectHandles(current.Get(), eventThread))) {
        return {"breakpoint-thread-object-mismatch", ERROR_INVALID_DATA};
    }
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(current.Get(), &context)) { return WinError("read-breakpoint-thread-context"); }
    if ((context.Dr7 & 0xff) || (context.EFlags & kTrapFlag)) {
        return {"competing-thread-debug-state", ERROR_BUSY};
    }
    // 先保留句柄和原 DR 状态，再写入；连写入结果不明也不能失去清退责任。
    HANDLE duplicate = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), current.Get(), GetCurrentProcess(), &duplicate, 0, FALSE,
        DUPLICATE_SAME_ACCESS)) { return WinError("hold-breakpoint-thread"); }
    DebugSlot slot{Handle(duplicate), context.Dr0, context.Dr7 & kDr0Control};
    bp.slots.emplace(tid, std::move(slot));
    bp.binding.enrolledThreads = bp.slots.size();
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    context.Dr0 = static_cast<decltype(context.Dr0)>(bp.binding.address);
    context.Dr7 = static_cast<decltype(context.Dr7)>((context.Dr7 & ~kDr0Control) | kDr0LocalExecute);
    if (!SetThreadContext(current.Get(), &context)) { return WinError("arm-breakpoint-thread"); }
    if (!GetThreadContext(current.Get(), &context)) { return WinError("read-armed-breakpoint-thread"); }
    if (context.Dr0 != bp.binding.address || (context.Dr7 & kDr0Control) != kDr0LocalExecute) {
        return {"verify-armed-breakpoint-thread", ERROR_INVALID_DATA};
    }
    return {};
}

NativeError NativeDebugOwner::Impl::InstallBreakpoint() {
    auto& bp = *breakpoint_;
    NativeImageSite site;
    const auto pid = bp.request.target.pid;
    const auto error = ResolveNativeImageSite(process_.Get(), pid, bp.request.modulePath, bp.request.rva,
        bp.request.exportName, site);
    if (error) { return {"resolve-requested-image-site", error}; }
    bp.binding.moduleBase = site.base;
    bp.binding.address = site.address;
    bp.binding.rva = site.rva;
    std::vector<FrozenThread> threads;
    if (const auto capture = CaptureThreads(pid, latest_->processInstanceId, threadIds_, threads); capture) { return capture; }
    for (const auto& thread : threads) {
        if (const auto enroll = EnrollThread(thread.member.tid, thread.handle.Get()); enroll) { return enroll; }
    }
    bp.installed = true;
    return {};
}

NativeError NativeDebugOwner::Impl::RestoreBreakpoint() {
    auto& bp = *breakpoint_;
    NativeError firstError;
    for (auto it = bp.slots.begin(); it != bp.slots.end();) {
        const auto& slot = it->second;
        const auto thread = slot.thread.Get();
        NativeError error;
        const auto wait = WaitForSingleObject(thread, 0);
        if (wait == WAIT_FAILED) {
            error = WinError("check-breakpoint-thread-lifetime");
        } else if (wait == WAIT_TIMEOUT) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!GetThreadContext(thread, &context)) {
                error = WinError("read-breakpoint-restore-context");
            } else if (context.Dr0 != slot.originalAddress || (context.Dr7 & kDr0Control) != slot.originalControl) {
                if (context.Dr0 != bp.binding.address || (context.Dr7 & kDr0Control) != kDr0LocalExecute) {
                    error = {"breakpoint-slot-restore-conflict", ERROR_INVALID_DATA};
                } else {
                    context.Dr0 = static_cast<decltype(context.Dr0)>(slot.originalAddress);
                    context.Dr7 = static_cast<decltype(context.Dr7)>((context.Dr7 & ~kDr0Control) | slot.originalControl);
                    context.Dr6 = static_cast<decltype(context.Dr6)>(context.Dr6 & ~kDr0LocalExecute);
                    if (!SetThreadContext(thread, &context)) {
                        error = WinError("restore-breakpoint-thread");
                    } else if (!GetThreadContext(thread, &context)) {
                        error = WinError("read-restored-breakpoint-thread");
                    } else if (context.Dr0 != slot.originalAddress || (context.Dr7 & kDr0Control) != slot.originalControl) {
                        error = {"verify-restored-breakpoint-thread", ERROR_INVALID_DATA};
                    }
                }
            }
        }
        if (error) {
            if (!firstError) { firstError = error; }
            ++it;
        } else {
            it = bp.slots.erase(it);
        }
    }
    bp.binding.enrolledThreads = bp.slots.size();
    return firstError;
}

NativeError NativeDebugOwner::Impl::AdoptBreakpointHit() {
    const auto& bp = *breakpoint_;
    PauseRecord record{bp.request.target, NewId(), NewId(), latest_->processInstanceId};
    record.timing = firstBound_->timing;
    record.timing.eventObservedQpc = ReadQpc();
    record.hit = NativeBreakpointHit{bp.request.target.requestId, bp.binding.address};
    if (record.groupId.empty() || record.stopId.empty() || pauses_.size() >= kMaxGroups) {
        return {"breakpoint-stop-history-capacity", ERROR_BUFFER_OVERFLOW};
    }
    std::vector<FrozenThread> frozen;
    if (const auto error = CaptureThreads(record.request.pid, record.processInstanceId, threadIds_, frozen); error) { return error; }
    FrozenStopGroup group{record.groupId, static_cast<std::uint64_t>(pauses_.size()), {}, {}};
    ThreadIdentity origin;
    ThreadIds newIds;
    for (const auto& thread : frozen) {
        const auto& member = thread.member;
        group.requested.push_back(member.identity);
        record.frozenThreads.push_back(member);
        newIds.emplace(std::pair<DWORD, std::uint64_t>{member.tid, member.creationTime}, member.identity.threadId);
        if (member.tid == event_->dwThreadId && CompareObjectHandles(thread.handle.Get(), bp.slots.at(member.tid).thread.Get())) {
            origin = member.identity;
        }
    }
    group.membershipSha256 = MembershipHash(group.requested);
    if (origin.threadId.empty() || group.membershipSha256.empty()) { return {"verify-breakpoint-stop-members", ERROR_INVALID_DATA}; }
    auto inserted = pauses_.emplace(std::string(kClosePrefix) + record.groupId, std::move(record)).first;
    if (ledger_.Freeze(std::move(group)) != LedgerResult::Applied) {
        pauses_.erase(inserted);
        return {"freeze-breakpoint-stop-group", ERROR_INVALID_DATA};
    }
    latest_ = &inserted->second;
    const NativeEventKey key{owner_.backendInstanceId, eventSerial_};
    if (ledger_.AdoptNativeStop(latest_->groupId, {key, origin, latest_->stopId,
        StopPhase::ExecutionEnterAttempt}) != LedgerResult::Applied) {
        for (const auto& thread : frozen) {
            (void)ledger_.ObserveMember(latest_->groupId, thread.member.identity, MemberEvidence::NoOwnedHold);
        }
        (void)ledger_.SealMembership(latest_->groupId);
        (void)ledger_.ConfirmNoNativeEvent(latest_->groupId);
        return {"adopt-breakpoint-debug-event", ERROR_INVALID_DATA};
    }
    threadIds_ = std::move(newIds);
    for (const auto& thread : frozen) {
        const auto wait = WaitForSingleObject(thread.handle.Get(), 0);
        (void)ledger_.ObserveMember(latest_->groupId, thread.member.identity,
            wait == WAIT_TIMEOUT ? MemberEvidence::CoveredByEvent : wait == WAIT_OBJECT_0 ? MemberEvidence::Exited : MemberEvidence::Unknown,
            wait == WAIT_TIMEOUT ? std::optional(key) : std::nullopt);
    }
    (void)ledger_.SealMembership(latest_->groupId);
    latest_->status = NativeControlStatus::Held;
    latest_->outcome = {"execution-breakpoint-held", ERROR_SUCCESS};
    breakpoint_->binding.state = NativeBreakpointState::Held;
    breakpoint_->binding.stage = latest_->outcome.stage;
    return {};
}

NativeError NativeDebugOwner::Impl::PrepareBreakpointResume() {
    auto& bp = *breakpoint_;
    if (bp.retire) { return RestoreBreakpoint(); }
    const auto slot = bp.slots.find(event_->dwThreadId);
    if (slot == bp.slots.end()) { return {"missing-breakpoint-resume-thread", ERROR_INVALID_DATA}; }
    const auto thread = slot->second.thread.Get();
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &context)) { return WinError("read-breakpoint-resume-context"); }
    if (InstructionPointer(context) != bp.binding.address || context.Dr0 != bp.binding.address ||
        (context.Dr7 & kDr0Control) != kDr0LocalExecute) { return {"breakpoint-resume-context-changed", ERROR_INVALID_DATA}; }
    // RF 仅屏蔽本次重试的指令取指，其他线程继续保有 DR0，不需要单步或重新武装窗口。
    context.EFlags |= kResumeFlag;
    context.Dr6 = static_cast<decltype(context.Dr6)>(context.Dr6 & ~kDr0LocalExecute);
    if (!SetThreadContext(thread, &context)) { return WinError("prepare-breakpoint-resume"); }
    if (!GetThreadContext(thread, &context)) { return WinError("read-breakpoint-resume-preparation"); }
    if (!(context.EFlags & kResumeFlag)) { return {"verify-breakpoint-resume-flag", ERROR_INVALID_DATA}; }
    return {};
}

void NativeDebugOwner::Impl::RetireBreakpoint(NativeError reason) {
    auto& bp = *breakpoint_;
    bp.retire = true;
    bp.retirement = reason;
    bp.binding.state = NativeBreakpointState::Retiring;
    bp.binding.stage = reason.stage;
    bp.binding.win32Error = reason.code;
}

void NativeDebugOwner::Impl::BreakpointRecovery(NativeError error) {
    auto& binding = breakpoint_->binding;
    binding.state = NativeBreakpointState::RecoveryRequired;
    binding.stage = error.stage;
    binding.win32Error = error.code;
    latest_->status = NativeControlStatus::RecoveryRequired;
    latest_->outcome = error;
}

void NativeDebugOwner::Impl::FinishBreakpointEvent(DWORD disposition) {
    auto& bp = *breakpoint_;
    bp.cleanupDisposition = disposition;
    if (const auto error = RestoreBreakpoint(); error) { BreakpointRecovery(error); return; }
    if (!ApplyContinue(disposition)) { BreakpointRecovery(latest_->outcome); return; }
    bp.cleanupDisposition.reset();
    if (!bp.interruptRequested && !bp.interruptTid) { Detach(); }
}

void NativeDebugOwner::Impl::ReceiveBreakpoint(const DEBUG_EVENT& event) {
    auto& bp = *breakpoint_;
    if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
        if (!ApplyContinue(DBG_CONTINUE)) { BreakpointRecovery(latest_->outcome); return; }
        bp.slots.clear(); // 真实进程退出，不再存在可恢复的线程上下文。
        Complete(NativeControlStatus::Ended, {"exit-process-event-continued", ERROR_SUCCESS});
        return;
    }
    if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
        if (!CompareObjectHandles(process_.Get(), event.u.CreateProcessInfo.hProcess)) {
            RetireBreakpoint({"event-process-object-mismatch", ERROR_INVALID_DATA});
        } else if (const auto error = CheckProcessIdentity(event.u.CreateProcessInfo.hProcess, bp.request.target); error) {
            RetireBreakpoint(error);
        } else if (const auto failure = ResolveBreakpointImages(); failure) {
            RetireBreakpoint(failure);
        } else {
            bp.processVerified = true;
        }
    }
    if (event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT && bp.processVerified) {
        const auto start = reinterpret_cast<std::uintptr_t>(event.u.CreateThread.lpStartAddress);
        if ((!bp.binding.address || bp.interruptRequested) && start == bp.systemBreakThread.address) {
            bp.interruptTid = event.dwThreadId;
        }
        if (!bp.retire && bp.binding.address) {
            if (const auto error = EnrollThread(event.dwThreadId, event.u.CreateThread.hThread); error) { RetireBreakpoint(error); }
        }
    } else if (event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
        bp.slots.erase(event.dwThreadId);
        bp.binding.enrolledThreads = bp.slots.size();
        if (bp.interruptTid == event.dwThreadId) { bp.interruptTid = 0; }
    } else if (event.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT && bp.binding.address &&
        reinterpret_cast<std::uintptr_t>(event.u.UnloadDll.lpBaseOfDll) == bp.binding.moduleBase) {
        RetireBreakpoint({"breakpoint-module-unloaded", ERROR_SUCCESS});
    }

    DWORD disposition = event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
    if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && event.u.Exception.dwFirstChance) {
        const auto& exception = event.u.Exception.ExceptionRecord;
        const auto address = reinterpret_cast<std::uintptr_t>(exception.ExceptionAddress);
        if (exception.ExceptionCode == EXCEPTION_BREAKPOINT && address == bp.systemBreak.address &&
            bp.interruptTid == event.dwThreadId) {
            disposition = DBG_CONTINUE;
            bp.interruptTid = 0;
            bp.interruptRequested = false;
            if (!bp.retire && !bp.binding.address) {
                if (const auto error = InstallBreakpoint(); error) { RetireBreakpoint(error); }
            }
        } else if (exception.ExceptionCode == EXCEPTION_SINGLE_STEP && bp.binding.address && address == bp.binding.address) {
            const auto slot = bp.slots.find(event.dwThreadId);
            CONTEXT context{};
            context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
            if (slot != bp.slots.end() && !GetThreadContext(slot->second.thread.Get(), &context)) {
                bp.retryHitContext = true;
                BreakpointRecovery(WinError("read-breakpoint-hit-context"));
                return;
            }
            bp.retryHitContext = false;
            if (slot != bp.slots.end() && InstructionPointer(context) == address && context.Dr0 == address &&
                (context.Dr7 & kDr0Control) == kDr0LocalExecute && (context.Dr6 & kDr0LocalExecute)) {
                if ((context.Dr6 & kDr6Reasons) != kDr0LocalExecute) {
                    RetireBreakpoint({"breakpoint-mixed-single-step-causes", ERROR_BUSY});
                } else {
                    disposition = DBG_CONTINUE;
                }
                if (!bp.retire && disposition == DBG_CONTINUE) {
                    if (const auto error = AdoptBreakpointHit(); error) { RetireBreakpoint(error); }
                    else { return; }
                }
            }
        }
    }

    // DebugBreakProcess 排队后先等匹配的异常，不能在其辅助线程尚未经过断点时脱离。
    if (bp.retire) { FinishBreakpointEvent(disposition); return; }
    if (!ApplyContinue(disposition)) { BreakpointRecovery(latest_->outcome); return; }
    if (bp.binding.address && !bp.retire) {
        bp.binding.state = NativeBreakpointState::Armed;
        bp.binding.stage = "execution-breakpoint-armed";
        latest_->status = NativeControlStatus::Released;
        latest_->outcome = {bp.binding.stage, ERROR_SUCCESS};
    }
}

void NativeDebugOwner::Impl::RequestBreakpointClose() {
    auto& bp = *breakpoint_;
    if (!bp.retire) { RetireBreakpoint({"breakpoint-close-requested", ERROR_SUCCESS}); }
    if (event_) {
        if (bp.cleanupDisposition && failedContinueSerial_ != eventSerial_) { FinishBreakpointEvent(*bp.cleanupDisposition); }
        else if (bp.retryHitContext) { ReceiveBreakpoint(*event_); }
        return;
    }
    if (!attached_) { return; }
    if (bp.slots.empty() && !bp.interruptRequested && !bp.interruptTid) { Detach(); return; }
    if (bp.interruptRequested || bp.interruptTid) { return; }
    Handle interrupt(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_CREATE_THREAD, FALSE, bp.request.target.pid));
    if (!interrupt) { BreakpointRecovery(WinError("open-breakpoint-cleanup-process")); return; }
    if (!CompareObjectHandles(interrupt.Get(), process_.Get())) {
        BreakpointRecovery({"breakpoint-cleanup-process-mismatch", ERROR_INVALID_DATA});
        return;
    }
    if (!DebugBreakProcess(interrupt.Get())) { BreakpointRecovery(WinError("request-breakpoint-cleanup-event")); return; }
    bp.interruptRequested = true;
    attachDeadline_ = GetTickCount64() + kAttachDeadlineMs;
}

void NativeDebugOwner::Impl::AdoptCreateEvent() {
    latest_->timing.eventObservedQpc = ReadQpc();
    const auto& create = event_->u.CreateProcessInfo;
    if (!CompareObjectHandles(process_.Get(), create.hProcess)) {
        latest_->status = NativeControlStatus::Rejected;
        latest_->outcome = {"event-process-object-mismatch", ERROR_INVALID_DATA};
        return;
    }
    if (const auto error = CheckProcessIdentity(create.hProcess, latest_->request); error) {
        latest_->status = NativeControlStatus::Rejected;
        latest_->outcome = error;
        return;
    }
    FILETIME created{}, exited{}, kernel{}, user{};
    if (GetThreadId(create.hThread) != event_->dwThreadId || GetProcessIdOfThread(create.hThread) != latest_->request.pid ||
        !GetThreadTimes(create.hThread, &created, &exited, &kernel, &user) || !FileTime(created)) {
        latest_->status = NativeControlStatus::Rejected;
        latest_->outcome = {"event-thread-identity-unavailable", ERROR_INVALID_DATA};
        return;
    }
    const auto origin = std::find_if(members_.begin(), members_.end(), [&](const auto& member) {
        return member.member.tid == event_->dwThreadId && member.member.creationTime == FileTime(created);
    });
    if (origin != members_.end() && !CompareObjectHandles(origin->handle.Get(), create.hThread)) {
        latest_->status = NativeControlStatus::Rejected;
        latest_->outcome = {"event-thread-object-mismatch", ERROR_INVALID_DATA};
        return;
    }
    const auto prior = threadIds_.find({event_->dwThreadId, FileTime(created)});
    const auto identity = origin == members_.end()
        ? ThreadIdentity{prior == threadIds_.end() ? NewId() : prior->second, latest_->processInstanceId}
        : origin->member.identity;
    const NativeEventKey key{owner_.backendInstanceId, eventSerial_};
    const auto adopted = ledger_.AdoptNativeStop(latest_->groupId, {key, identity, latest_->stopId, std::nullopt});
    if (adopted != LedgerResult::Applied) {
        latest_->status = NativeControlStatus::Rejected;
        latest_->outcome = {"adopt-create-event", ERROR_INVALID_DATA};
        return;
    }
    for (const auto& member : members_) {
        const auto wait = WaitForSingleObject(member.handle.Get(), 0);
        if (wait == WAIT_OBJECT_0) {
            (void)ledger_.ObserveMember(latest_->groupId, member.member.identity, MemberEvidence::Exited);
        } else if (wait == WAIT_TIMEOUT) {
            (void)ledger_.ObserveMember(latest_->groupId, member.member.identity, MemberEvidence::CoveredByEvent, key);
        } else {
            (void)ledger_.ObserveMember(latest_->groupId, member.member.identity, MemberEvidence::Unknown);
        }
    }
    (void)ledger_.SealMembership(latest_->groupId);
    latest_->status = NativeControlStatus::Held;
    latest_->outcome = {"create-process-debug-event-held", ERROR_SUCCESS};
}

bool NativeDebugOwner::Impl::ApplyContinue(DWORD disposition) {
    if (!ContinueDebugEvent(event_->dwProcessId, event_->dwThreadId, disposition)) {
        failedContinueSerial_ = eventSerial_;
        latest_->status = NativeControlStatus::RecoveryRequired;
        latest_->outcome = WinError("continue-debug-event");
        return false;
    }
    event_.reset();
    return true;
}

NativeControlResult NativeDebugOwner::Impl::Release(const ReleaseRequest& request, bool recover, bool internal) {
    if (!internal && request.requestId.starts_with(kClosePrefix)) {
        return Reject({"reserved-release-request-id", ERROR_INVALID_PARAMETER}, LedgerResult::InvalidEvidence);
    }
    const auto old = ledger_.QueryRelease(request.requestId);
    if (recover && !old) {
        return Reject({"recover-requires-original-release-request", ERROR_NOT_FOUND}, LedgerResult::InvalidEvidence);
    }
    const auto decision = ledger_.BeginRelease(request);
    if (decision.result == LedgerResult::Duplicate) {
        auto result = Query(request.groupId);
        result.ledgerResult = decision.result;
        result.releaseRequestId = request.requestId;
        result.release = old;
        if (recover && latest_ && latest_->groupId == request.groupId && attached_ && !event_ &&
            (!breakpoint_ || breakpoint_->retire) &&
            latest_->status == NativeControlStatus::RecoveryRequired && result.release && result.release->receipt &&
            result.release->receipt->result == ReleaseResult::Continued) {
            Detach();
            result = Query(request.groupId);
            result.ledgerResult = decision.result;
            result.releaseRequestId = request.requestId;
            result.release = old;
        }
        return result;
    }
    if (!decision.effect) {
        if (decision.result == LedgerResult::ReadbackRequired) {
            auto result = Query(request.groupId);
            result.ledgerResult = decision.result;
            if (result.responsibility && result.responsibility->lastRequestId) {
                result.release = ledger_.QueryRelease(*result.responsibility->lastRequestId);
            }
            return result;
        }
        return Reject({"release-authorization-rejected", ERROR_INVALID_PARAMETER}, decision.result);
    }
    const auto& attempt = *decision.effect;
    if (latest_) { latest_->lastReleaseRequestId = request.requestId; }
    const bool isBreakpoint = latest_ && latest_->hit.has_value();
    const DWORD expectedEvent = isBreakpoint ? EXCEPTION_DEBUG_EVENT : CREATE_PROCESS_DEBUG_EVENT;
    if (!event_ || !latest_ || event_->dwDebugEventCode != expectedEvent || eventSerial_ != request.event.serial ||
        event_->dwProcessId != latest_->request.pid || failedContinueSerial_ == eventSerial_) {
        (void)ledger_.RecordReleaseReceipt(attempt, {ReleaseResult::Indeterminate, ERROR_INVALID_DATA});
        if (latest_) {
            latest_->status = NativeControlStatus::RecoveryRequired;
            latest_->outcome = {"release-native-event-unverified", ERROR_INVALID_DATA};
        }
    } else {
        if (isBreakpoint) {
            if (!breakpoint_->retire && pauses_.size() >= kMaxGroups) {
                RetireBreakpoint({"breakpoint-stop-history-capacity", ERROR_BUFFER_OVERFLOW});
            }
            if (const auto error = PrepareBreakpointResume(); error) {
                // 尚未调用 ContinueDebugEvent；确切事件仍在本线程，允许用新修订重试。
                (void)ledger_.RecordReleaseReceipt(attempt, {ReleaseResult::StillPending, error.code});
                BreakpointRecovery(error);
                auto result = Query(request.groupId);
                result.ledgerResult = decision.result;
                return result;
            }
        }
        const auto continued = ApplyContinue(DBG_CONTINUE);
        latest_->timing.continueReturnedQpc = ReadQpc();
        // A failed Win32 call supplies an error. There is no documented independent
        // readback of the exact pending event, so the same Continue cannot be resubmitted.
        const ReleaseReceipt receipt = continued ? ReleaseReceipt{ReleaseResult::Continued, std::nullopt} :
            ReleaseReceipt{ReleaseResult::Indeterminate, latest_->outcome.code};
        const auto recorded = ledger_.RecordReleaseReceipt(attempt, receipt);
        if (recorded != LedgerResult::Applied) {
            latest_->status = NativeControlStatus::RecoveryRequired;
            latest_->outcome = {"record-native-release-receipt", ERROR_INVALID_DATA};
        } else if (continued) {
            latest_->status = NativeControlStatus::Released;
            latest_->outcome = {"continue-debug-event", ERROR_SUCCESS};
            if (!isBreakpoint || breakpoint_->retire) {
                Detach();
            } else {
                breakpoint_->binding.state = NativeBreakpointState::Armed;
                breakpoint_->binding.stage = "execution-breakpoint-armed";
                breakpoint_->binding.win32Error = ERROR_SUCCESS;
            }
        } else if (isBreakpoint) {
            BreakpointRecovery(latest_->outcome);
        }
    }
    auto result = Query(request.groupId);
    result.ledgerResult = decision.result;
    return result;
}

void NativeDebugOwner::Impl::Detach() {
    if (!attached_ || event_ || ledger_.UnresolvedNativeResponsibility()) { return; }
    if (breakpoint_ && (!breakpoint_->slots.empty() || breakpoint_->interruptTid || breakpoint_->interruptRequested)) { return; }
    if (!DebugActiveProcessStop(latest_->request.pid)) {
        latest_->status = NativeControlStatus::RecoveryRequired;
        latest_->outcome = WinError("debug-active-process-stop");
        if (breakpoint_) { BreakpointRecovery(latest_->outcome); }
        return;
    }
    if (breakpoint_ && breakpoint_->retire) {
        Complete(!breakpoint_->installed && breakpoint_->retirement ? NativeControlStatus::Rejected : NativeControlStatus::Detached,
            breakpoint_->retirement);
    } else if (killOnExitError_) {
        Complete(NativeControlStatus::Rejected, killOnExitError_);
    } else if (latest_->status == NativeControlStatus::Rejected) {
        Complete(NativeControlStatus::Rejected, latest_->outcome);
    } else {
        Complete(NativeControlStatus::Detached, {"debug-active-process-stop", ERROR_SUCCESS});
    }
}

void NativeDebugOwner::Impl::Complete(NativeControlStatus status, NativeError outcome) {
    // Successful detach or a continued EXIT_PROCESS event is authoritative for the
    // attachment. Neither a signaled handle nor thread exit on its own clears it.
    attached_ = false;
    if (!ledger_.CanRetireLedger()) {
        for (const auto& member : members_) {
            const auto evidence = WaitForSingleObject(member.handle.Get(), 0) == WAIT_OBJECT_0
                ? MemberEvidence::Exited : MemberEvidence::NoOwnedHold;
            (void)ledger_.ObserveMember(latest_->groupId, member.member.identity, evidence);
        }
        (void)ledger_.SealMembership(latest_->groupId);
        (void)ledger_.ConfirmNoNativeEvent(latest_->groupId);
    }
    latest_->status = status;
    latest_->outcome = outcome;
    if (breakpoint_) {
        auto& binding = breakpoint_->binding;
        binding.state = status == NativeControlStatus::Rejected ? NativeBreakpointState::Rejected : NativeBreakpointState::Retired;
        binding.stage = outcome.stage;
        binding.win32Error = outcome.code;
        binding.enrolledThreads = 0;
    }
    members_.clear();
    if (closing_) { process_.Reset(); }
}

NativeControlResult NativeDebugOwner::Impl::Close() {
    closing_ = true;
    if (breakpoint_ && attached_ && !breakpoint_->retire) { RetireBreakpoint({"breakpoint-close-requested", ERROR_SUCCESS}); }
    if (const auto responsibility = ledger_.UnresolvedNativeResponsibility(); responsibility &&
        (responsibility->state == EventState::Held || responsibility->state == EventState::Retryable)) {
        const auto group = ledger_.Query(responsibility->groupId);
        auto result = Release({owner_, responsibility->groupId, responsibility->stopId, responsibility->event,
            std::string(kClosePrefix) + responsibility->groupId + "/" + std::to_string(group->stateRevision), group->stateRevision},
            false, true);
        if (result.clean) {
            result.status = NativeControlStatus::Closed;
            result.stage = "owner-closed";
        }
        return result;
    }
    if (breakpoint_ && attached_) { RequestBreakpointClose(); }
    else if (attached_ && !event_) { Detach(); }
    return Query({});
}

NativeDebugOwner::NativeDebugOwner(OwnerIdentity identity) : impl_(std::make_unique<Impl>(std::move(identity))) {}
NativeDebugOwner::~NativeDebugOwner() = default;

NativeControlResult NativeDebugOwner::Pause(const NativePauseRequest& request) {
    return impl_->Invoke([&] { return impl_->Pause(request); });
}

NativeControlResult NativeDebugOwner::ArmBreakpoint(const NativeBreakpointRequest& request) {
    return impl_->Invoke([&] { return impl_->ArmBreakpoint(request); });
}

NativeControlResult NativeDebugOwner::Query(std::string_view groupId, std::string_view releaseRequestId) {
    return impl_->Invoke([&] { return impl_->Query(groupId, releaseRequestId); });
}

NativeControlResult NativeDebugOwner::Continue(const ReleaseRequest& request) {
    return impl_->Invoke([&] { return impl_->Release(request, false); });
}

NativeControlResult NativeDebugOwner::Recover(const ReleaseRequest& request) {
    return impl_->Invoke([&] { return impl_->Release(request, true); });
}

NativeControlResult NativeDebugOwner::Close() {
    return impl_->Invoke([&] { return impl_->Close(); });
}

} // namespace ks::cli::action_analyze::control
