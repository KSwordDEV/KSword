#include "NativeDebugOwner.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "NativeBreakpointImage.h"
#include "NativePrivateExecutionSite.h"
#include "NativeExplicitMemorySite.h"
#include "NativePrivateExecutionPage.h"
#include "NativeDebugAdmission.h"
#include "NativeWriteExecutionTransition.h"
#include "NativeStepRuntime.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <limits>
#include <mutex>
#include <thread>
#include <utility>

#pragma comment(lib, "onecore.lib")

namespace ks::cli::action_analyze::control {
namespace {

constexpr DWORD kWaitMs = 10;
constexpr DWORD kAttachDeadlineMs = 5000;
constexpr DWORD kPageAdvanceDeadlineMs = 5000;
constexpr std::string_view kClosePrefix = "native-owner-close/";
constexpr DWORD64 kDr0Control = 0x000f0003;
constexpr DWORD64 kDr0Local = 1; // 槽位 0 的当前线程启用位及对应的命中标志。
constexpr DWORD64 kDr6Reasons = 0xe00f;
constexpr DWORD kResumeFlag = 0x10000;

using Handle = native_owner_detail::NativeDebugHandle;
using NativeError = native_owner_detail::NativeDebugError;
using native_owner_detail::CheckAdmission;
using native_owner_detail::CheckOwnedChild;
using native_owner_detail::CheckProcessIdentity;
using native_owner_detail::NewId;
using native_owner_detail::BreakpointId;
using native_owner_detail::MembershipHash;
using native_owner_detail::CaptureThreads;
using native_owner_detail::DebugControl;
using native_owner_detail::InstructionPointer;
using native_owner_detail::FileTime;
using native_owner_detail::ReadQpc;
using native_owner_detail::AbsoluteModulePath;
using FrozenThread = native_owner_detail::NativeDebugFrozenThread;
using ThreadIds = native_owner_detail::NativeDebugThreadIds;

NativeError WinError(const char* stage) noexcept {
    const DWORD error = GetLastError();
    return {stage, error ? error : ERROR_GEN_FAILURE};
}

} // namespace

class NativeDebugOwner::Impl final {
public:
    explicit Impl(OwnerIdentity owner) : owner_(std::move(owner)), ledger_(owner_), thread_([this] { Run(); }) {}
    ~Impl() {
        (void)Invoke([this] { return Close(); });
        thread_.join();
    }

    template<class Function>
    NativeControlResult Invoke(Function operation) {
        const std::lock_guard callLock(caller_);
        std::unique_lock lock(queueMutex_);
        if (threadFinished_) {
            // Closure seals admission. Historical queries and their replays no longer need the debug thread.
            lock.unlock();
            return operation();
        }
        auto job = std::make_shared<std::packaged_task<NativeControlResult()>>(std::move(operation));
        auto result = job->get_future();
        queued_ = [job] { (*job)(); };
        lock.unlock();
        wake_.notify_one();
        return result.get();
    }

    NativeControlResult Pause(const NativePauseRequest& request);
    NativeControlResult PauseArmed(const OwnerIdentity& owner, const NativePauseRequest& request);
    NativeControlResult QueryArmedPause(std::string_view requestId) const;
    NativeControlResult ArmBreakpoint(const NativeBreakpointRequest& request);
    NativeControlResult FollowPrivateExecution(const NativeExecutionFollowRequest& request); // 同owner串行转换，不释放事件。
    NativeControlResult AddPrivateExecutionRange(const NativeExecutionRangeRequest& request);
    NativeControlResult Query(std::string_view groupId, std::string_view releaseRequestId = {}) const;
    NativeControlResult Release(const ReleaseRequest& request, bool recover, bool internal = false);
    NativeControlResult Close();
    NativeControlResult Step(const NativeStepRequest& request);
    NativeControlResult QueryStep(std::string_view requestId) const;
    NativeControlResult CancelStep(std::string_view requestId);

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
        std::uint64_t hitEventSerial = 0;
        std::optional<NativeRetirementReceipt> retirement{};
        std::optional<NativeRecoveryFailure> firstRecoveryFailure{};
        bool stepStop = false;
        bool manualPause = false;
        std::optional<NativeArmedPauseReceipt> manualPauseReceipt; // 与本停止组冻结，后续拒绝票据不覆盖此授权来源。
        DWORD continuation = DBG_CONTINUE;
        std::optional<NativeStopRegisters> registers; // 只在真实事件形成时冻结，不随Query重采。
    };

    struct ActiveBreakpoint {
        NativeBreakpointRequest request;
        NativeBreakpointBinding binding;
        NativeImageSite systemBreak;
        NativeImageSite systemBreakThread;
        std::optional<NativePrivateExecutionSite> privateExecution;
        std::optional<NativeExplicitMemorySite> explicitSite; // 冻结原明确地址和映射属性，转换后仍复用此记录。
        std::optional<NativePrivateExecutionPage> executionPage; // 真实NX责任，和单地址DR0互斥。
        bool pageAdvancing = false; // 本端临时恢复X，尚须在TF/中断/退出事件中重设NX。
        bool internalPageAdvance = false; // Continue内部TF不发布用户step或执行完成证据。
        ULONGLONG pageAdvanceDeadline = 0;
        bool pageTimeoutRequested = false; // 每次开放窗口只请求一次超时中断；失败保留原责任。
        std::optional<NativePrivateExecutionSite> writeExecutionCandidate; // 初次私有RWX写绑定时冻结的同址候选。
        native_owner_detail::NativeDebugSlots slots;
        DWORD64 debugControl = kDr0Local; // 已核验的控制位，同时用于安装、识别本端事件和恢复。
        std::array<std::uint8_t, 8> dataBaseline{}; // 最后一次停住时确认的关注范围内容。
        DWORD interruptTid = 0;
        Handle interruptThread; // 原CREATE_THREAD中核验并复制的实际中断助手，防止TID复用。
        bool processVerified = false;
        bool installed = false;
        bool awaitingAttachBreak = false;
        bool interruptRequested = false;
        bool retire = false;
        NativeError retirement;
        std::optional<DWORD> cleanupDisposition;
        bool retryEventContext = false;
    };

    void Run();
    void Pump();
    void Receive(const DEBUG_EVENT& event);
    void ReceiveBreakpoint(const DEBUG_EVENT& event);
    NativeError ResolveBreakpointImages();
    NativeError InstallBreakpoint();
    NativeError VerifyBoundSite() const; // 回读当前私有绑定；明确地址按当前实际宽度验证。
    NativeError EnrollThread(DWORD tid, HANDLE eventThread = nullptr);
    NativeError CoverBreakpointThreads(const std::vector<FrozenThread>& frozen);
    NativeError RestoreBreakpoint();
    NativeError PreparePageResume();
    NativeError RequestInterrupt();
    bool IsRequestedInterrupt(const DEBUG_EVENT& event) const;
    bool ReceivePageEvent(const DEBUG_EVENT& event); // 返回真表示本页已处理/持有该事件。
    NativeError AdoptBreakpointHit(std::optional<NativeDataChange> dataChange = std::nullopt, bool stepStop = false,
        DWORD continuation = DBG_CONTINUE, std::optional<std::uint64_t> hitAddress = {}, bool manualPause = false);
    NativeError ReadWatchedData(std::array<std::uint8_t, 8>& bytes) const;
    NativeError PrepareBreakpointResume();
    void RetireBreakpoint(NativeError reason);
    void RequireRecovery(NativeError error);
    void FinishBreakpointEvent(DWORD disposition);
    void RequestBreakpointClose();
    NativeError RestoreStep(bool exited = false);
    void SaveStepReceipt();
    void AdoptCreateEvent();
    bool ApplyContinue(DWORD disposition);
    void Detach();
    void ContinueExitEvent(DWORD exitCode);
    void Complete(NativeControlStatus status, NativeError outcome);
    bool IsClean() const;
    NativeControlResult Snapshot(const PauseRecord* record) const;
    NativeControlResult Reject(NativeError error, LedgerResult ledgerResult, const PauseRecord* record = nullptr) const;

    const OwnerIdentity owner_;
    StopLedger ledger_;
    std::map<std::string, PauseRecord, std::less<>> pauses_;
    std::deque<PauseRecord> breakpointStops_;
    std::uint64_t breakpointMembershipRevision_ = 0;
    PauseRecord* latest_ = nullptr;
    PauseRecord* firstBound_ = nullptr;
    Handle process_;
    ThreadIds threadIds_;
    std::vector<FrozenThread> members_;
    std::optional<DEBUG_EVENT> event_;
    std::optional<ActiveBreakpoint> breakpoint_;
    NativeStepRuntime step_;
    std::map<std::string, NativeStepReceipt, std::less<>> stepHistory_;
    std::deque<std::string> stepOrder_;
    std::map<std::uint64_t, std::pair<NativeExecutionFollowRequest, NativeControlResult>> followHistory_; // 独立请求重放窗口。
    std::uint64_t followSequence_ = 0; // 已接受转换票据高水位；淘汰旧票据也不能重新执行。
    std::optional<NativeExecutionFollowReceipt> lastFollow_; // 转换结果不是执行观测，源写入事件保持原样。
    native_owner_detail::NativeExecutionRangeHistory rangeHistory_;
    native_owner_detail::NativeArmedPauseHistory armedPauseHistory_;
    bool stepSubmitting_ = false;
    std::optional<std::uint64_t> failedContinueSerial_;
    // Debug status register captured before the step runtime restored the
    // selected thread. Zero means no verified single-step evidence exists.
    std::uint64_t verifiedReasons_ = 0;
    std::uint64_t eventSerial_ = 0;
    ULONGLONG attachDeadline_ = 0;
    bool attached_ = false;
    bool closing_ = false;
    bool detachFailed_ = false;
    NativeError killOnExitError_;

    std::mutex caller_;
    std::mutex queueMutex_;
    std::condition_variable wake_;
    std::function<void()> queued_;
    bool threadFinished_ = false; // published under queueMutex_ once the worker runs no more owner code
    std::thread thread_;
};

bool NativeDebugOwner::Impl::IsClean() const {
    return !attached_ && !event_ && !step_.HasResources() && !step_.Running() && ledger_.CanRetireLedger() &&
        (!breakpoint_ || (breakpoint_->slots.empty() && !breakpoint_->awaitingAttachBreak &&
            !breakpoint_->interruptRequested && !breakpoint_->interruptTid && !breakpoint_->interruptThread &&
            (!breakpoint_->executionPage || !breakpoint_->executionPage->OwnsProtection())));
}

NativeControlResult NativeDebugOwner::Impl::Snapshot(const PauseRecord* record) const {
    NativeControlResult result;
    result.attached = attached_;
    result.clean = IsClean();
    if (!record) { return result; }
    result.status = record->status;
    result.stage = record->outcome.stage;
    result.win32Error = record->outcome.code;
    result.pauseRequestId = record->request.requestId;
    result.pid = record->request.pid;
    result.processCreationTime = record->request.processCreationTime;
    result.processInstanceId = record->processInstanceId;
    result.retirement = record->retirement;
    result.firstRecoveryFailure = record->firstRecoveryFailure;
    result.executionFollow = lastFollow_; // 仅附加操作回执，不修改hit或origin。
    result.executionRange = rangeHistory_.Last();
    result.armedPause = armedPauseHistory_.Last();
    if (record->manualPause && record->manualPauseReceipt) result.armedPause = record->manualPauseReceipt;
    result.stopReason = record->manualPause ? NativeStopReason::ManualPause :
        record->stepStop ? NativeStopReason::NativeStep : record->hit ? NativeStopReason::Breakpoint : NativeStopReason::None;
    result.group = ledger_.Query(record->groupId);
    result.frozenThreads = record->frozenThreads;
    result.timing = record->timing;
    if (breakpoint_) { result.breakpoint = breakpoint_->binding; }
    result.breakpointHit = record->hit;
    result.registers = record->registers;
    if (!step_.Receipt().request.release.requestId.empty()) { result.step = step_.Receipt(); }
    if (record->lastReleaseRequestId) {
        result.release = ledger_.QueryRelease(*record->lastReleaseRequestId, record->groupId);
        if (result.release) { result.releaseRequestId = record->lastReleaseRequestId; }
    }
    if (const auto responsibility = ledger_.UnresolvedNativeResponsibility();
        responsibility && responsibility->groupId == record->groupId) {
        result.responsibility = responsibility;
    }
    if (record == latest_ && event_) {
        const NativeEventKey key{owner_.backendInstanceId, eventSerial_};
        if (record->hitEventSerial != key.serial) {
            result.breakpointHit.reset(); result.registers.reset(); result.stopReason = NativeStopReason::None;
        }
        result.pending = NativePendingEvent{key, event_->dwProcessId, event_->dwThreadId, event_->dwDebugEventCode,
            std::nullopt, std::nullopt, result.responsibility && result.responsibility->event == key,
            failedContinueSerial_ == eventSerial_};
        if (event_->dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            result.pending->exceptionCode = event_->u.Exception.ExceptionRecord.ExceptionCode;
            result.pending->exceptionFirstChance = event_->u.Exception.dwFirstChance != 0;
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
    if (pauses_.size() == kStopHistoryGroups) { return Reject({"stop-group-history-capacity", ERROR_BUFFER_OVERFLOW}, LedgerResult::Capacity); }

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
        RequireRecovery(killOnExitError_);
        Detach();
        return Snapshot(latest_);
    }
    attachDeadline_ = GetTickCount64() + kAttachDeadlineMs;
    return Snapshot(latest_);
}

NativeControlResult NativeDebugOwner::Impl::ArmBreakpoint(const NativeBreakpointRequest& request) {
    const auto& target = request.target;
    const auto control = DebugControl(request.writeWatchBytes); // 校验宽度并冻结硬件访问类型。
    const bool explicitAddress = request.privateAddress != 0; // 私有地址和明确映像执行附加分别豁免direct-child。
    const bool pageMode = request.privateRangeBytes != 0;
    const bool validSite = explicitAddress
        ? request.modulePath.empty() && request.exportName.empty() && !request.rva &&
            !request.writeWatchPointerExport && !request.executePointerExport
        : AbsoluteModulePath(request.modulePath) && request.rva.has_value() != !request.exportName.empty() &&
            (!request.rva || *request.rva) && request.exportName.size() <= 255 &&
            request.exportName.find('\0') == std::string::npos;
    if (target.requestId.empty() || target.requestId.size() > 128 || target.requestId.starts_with(kClosePrefix) ||
        !target.pid || target.pid == GetCurrentProcessId() || !target.processCreationTime || !target.explicitlyAuthorized ||
        target.disposition != NativeTargetDisposition::ResumeAndDetach || !validSite ||
        (request.explicitImageAttachment && (explicitAddress || pageMode || request.writeWatchBytes ||
            request.writeWatchPointerExport || request.executePointerExport)) ||
        !control || (pageMode && (!explicitAddress || request.writeWatchBytes ||
            request.privateRangeBytes > 64 * 4096 || request.privateRangeBytes % 4096 || request.privateAddress % 4096)) ||
        (request.writeWatchBytes && request.rva) ||
        (request.writeWatchPointerExport && !request.writeWatchBytes) ||
        (request.executePointerExport && (request.writeWatchBytes || request.writeWatchPointerExport || request.rva))) {
        return Reject({explicitAddress ? "explicit-process-and-private-address-required" :
            "explicit-child-and-exact-image-site-required", ERROR_INVALID_PARAMETER}, LedgerResult::InvalidEvidence);
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
    Handle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE |
        (pageMode ? PROCESS_VM_OPERATION : 0), FALSE, target.pid));
    if (!process) { return Reject(WinError("open-breakpoint-process"), LedgerResult::IdentityMismatch); }
    if (const auto error = CheckAdmission(process.Get(), target); error) { return Reject(error, LedgerResult::IdentityMismatch); }
    if (!explicitAddress && !request.explicitImageAttachment) {
        if (const auto error = CheckOwnedChild(target); error) { return Reject(error, LedgerResult::IdentityMismatch); }
    }
    PauseRecord record{target, {}, {}, NewId()};
    if (record.processInstanceId.empty()) { return Reject({"allocate-process-instance", ERROR_GEN_FAILURE}, LedgerResult::InvalidEvidence); }
    latest_ = &pauses_.emplace(target.requestId, std::move(record)).first->second;
    firstBound_ = latest_;
    breakpoint_.emplace();
    breakpoint_->request = request;
    breakpoint_->binding.requestId = target.requestId;
    breakpoint_->binding.writeWatchBytes = request.writeWatchBytes;
    breakpoint_->binding.explicitPrivateAddress = explicitAddress;
    breakpoint_->binding.rangeBytes = request.privateRangeBytes;
    breakpoint_->debugControl = *control;
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
        RequireRecovery(killOnExitError_);
        Detach();
        return Snapshot(latest_);
    }
    breakpoint_->awaitingAttachBreak = true;
    attachDeadline_ = GetTickCount64() + kAttachDeadlineMs;
    return Snapshot(latest_);
}

// 输入独立follow票据，核对当前完整写停点，输出转换与回滚结果；全程不Continue、不重启目标。
NativeControlResult NativeDebugOwner::Impl::FollowPrivateExecution(const NativeExecutionFollowRequest& request)
{
    const auto sequence = NativeExecutionFollowSequence(request.stop.requestId); // 不占用continue/N流水。
    if (!sequence)
    {
        return Reject({"private-execution-follow-id-required", ERROR_INVALID_PARAMETER}, LedgerResult::InvalidEvidence);
    }
    if (const auto old = followHistory_.find(*sequence); old != followHistory_.end())
    {
        if (old->second.first != request)
        {
            return Reject({"private-execution-follow-request-conflict", ERROR_INVALID_PARAMETER}, LedgerResult::Conflict);
        }
        auto replay = old->second.second; // 返回首次结果快照，不拿当前状态冒充原转换结果。
        replay.ledgerResult = LedgerResult::Duplicate;
        return replay;
    }
    if (*sequence <= followSequence_)
    {
        return Reject({"private-execution-follow-replay-expired", ERROR_NOT_FOUND}, LedgerResult::ReplayExpired);
    }

    // 先分配重放记录，之后即使转换失败也不能重用同一票据产生新副作用。
    auto& cached = followHistory_.emplace(*sequence, std::make_pair(request, NativeControlResult{})).first->second.second;
    followSequence_ = *sequence;
    lastFollow_ = NativeExecutionFollowReceipt{request};
    const auto finish = [&](NativeFollowError error, LedgerResult reason) {
        lastFollow_->stage = error.stage;
        lastFollow_->win32Error = error.code;
        lastFollow_->rollbackComplete = error.rollbackComplete;
        cached = error.code ? Reject({error.stage, error.code}, reason) : Snapshot(latest_);
        if (!error.rollbackComplete)
        {
            cached.status = NativeControlStatus::RecoveryRequired;
        }
        const auto result = cached; // 返回值先复制，滚动清理只移除最旧的其他票据。
        while (followHistory_.size() > 128)
        {
            followHistory_.erase(followHistory_.begin());
        }
        return result;
    };
    if (!breakpoint_ || !attached_ || closing_ || breakpoint_->retire || breakpoint_->executionPage || !event_ || !latest_ ||
        failedContinueSerial_ == eventSerial_ || step_.Running() || step_.HasResources())
    {
        return finish({"private-execution-follow-owner-unavailable", ERROR_INVALID_STATE}, LedgerResult::InvalidTransition);
    }
    auto& bp = *breakpoint_; // 所有修改均针对原绑定，不重新解析后另造owner。
    const auto current = Snapshot(latest_); // 授权、成员和原写入命中来自同一次真实停止。
    const auto* frozen = bp.explicitSite ? &bp.explicitSite->site :
        bp.writeExecutionCandidate ? &bp.writeExecutionCandidate->site : nullptr; // 两类候选都保持原地址身份。
    if (const auto error = ValidateNativeExecutionFollow(owner_, request, current, frozen); error.code)
    {
        return finish(error, LedgerResult::InvalidEvidence);
    }
    const auto verifyFollowSite = [&] {
        return bp.explicitSite ? VerifyNativeExplicitMemorySite(process_.Get(), *bp.explicitSite, 0) :
            VerifyNativePrivateExecutionSite(process_.Get(), *bp.writeExecutionCandidate);
    }; // 明确地址验证执行资格，RWX属性仍须与原写绑定完全相同。
    if (const auto error = verifyFollowSite())
    {
        RetireBreakpoint({"private-execution-follow-selector-or-region-changed", error});
        return finish({"private-execution-follow-selector-or-region-changed", error}, LedgerResult::IdentityMismatch);
    }
    std::vector<NativeFollowThread> threads; // 借用所有已登记槽，事务模块负责全部预读及回滚。
    threads.reserve(bp.slots.size());
    for (auto& [tid, slot] : bp.slots)
    {
        (void)tid;
        threads.push_back({slot.thread.Get(), &slot.followState});
    }
    if (const auto error = ValidateNativeFollowThreads(current, threads); error.code)
    {
        return finish(error, LedgerResult::IdentityMismatch);
    }
    const auto switched = SwitchNativeWriteToExecution(threads, bp.binding.address, bp.debugControl,
        process_.Get(), bp.writeExecutionCandidate ? &*bp.writeExecutionCandidate : nullptr,
        bp.explicitSite ? &*bp.explicitSite : nullptr); // 无Continue副作用，Set前后均验证冻结映射。
    if (switched.code)
    {
        if (verifyFollowSite())
        {
            RetireBreakpoint({"private-execution-follow-selector-or-region-changed", ERROR_INVALID_ADDRESS});
        }
        if (!switched.rollbackComplete)
        {
            RetireBreakpoint({switched.stage, switched.code}); // 持有原事件，禁止再次转换或继续旧业务。
            RequireRecovery({switched.stage, switched.code}); // Close按每线程恢复预期继续清账。
        }
        return finish(switched, LedgerResult::InvalidTransition);
    }
    if (!bp.explicitSite) bp.privateExecution = bp.writeExecutionCandidate;
    bp.binding.writeWatchBytes = 0;
    bp.binding.executePointerExport = !bp.explicitSite; // 该字段只描述指针模式，明确地址不冒充selector。
    bp.binding.privateExecutionFollowAvailable = false;
    bp.debugControl = kDr0Local; // 新线程随后由原EnrollThread安装同址执行类型。
    bp.binding.stage = "private-execution-follow-converted";
    latest_->outcome = {bp.binding.stage, ERROR_SUCCESS};
    lastFollow_->converted = true; // 原hit.dataChange和origin仍然保留，不能生成执行证据。
    return finish({}, LedgerResult::Applied);
}

NativeControlResult NativeDebugOwner::Impl::AddPrivateExecutionRange(const NativeExecutionRangeRequest& request) {
    auto* page = breakpoint_ && breakpoint_->executionPage && attached_ && !closing_ && !breakpoint_->retire &&
        event_ && latest_ && !step_.Running() && !step_.HasResources() && !breakpoint_->pageAdvancing &&
        failedContinueSerial_ != eventSerial_ ? &*breakpoint_->executionPage : nullptr;
    if (page) breakpoint_->binding.executionRanges.reserve(64);
    auto result = rangeHistory_.Apply(owner_, request, Snapshot(latest_), page, process_.Get());
    if (result.ledgerResult != LedgerResult::Duplicate && result.executionRange &&
        result.status == NativeControlStatus::RecoveryRequired) {
        RetireBreakpoint({result.executionRange->stage, result.executionRange->win32Error});
        RequireRecovery({result.executionRange->stage, result.executionRange->win32Error});
    }
    if (page) breakpoint_->binding.executionRanges = page->Ranges();
    return result; // 原停止记录、账本及事件未修改；重放直接返回首次操作的快照。
}

NativeControlResult NativeDebugOwner::Impl::PauseArmed(const OwnerIdentity& owner, const NativePauseRequest& request) {
    const bool available = breakpoint_ && attached_ && breakpoint_->installed && !closing_ && !breakpoint_->retire &&
        !event_ && !step_.Running() && !step_.HasResources() && !breakpoint_->pageAdvancing &&
        !breakpoint_->awaitingAttachBreak && !breakpoint_->interruptRequested && !breakpoint_->interruptTid && !breakpoint_->interruptThread &&
        breakpoint_->binding.state == NativeBreakpointState::Armed && !ledger_.UnresolvedNativeResponsibility();
    bool issue = false;
    auto result = armedPauseHistory_.Begin(owner_, owner, request, Snapshot(latest_), available, issue);
    if (!issue) return result;
    auto error = CheckProcessIdentity(process_.Get(), request);
    if (!error) error = RequestInterrupt();
    if (error) {
        armedPauseHistory_.Complete(NativeArmedPauseState::Rejected, error.stage, error.code);
        result = Reject(error, LedgerResult::InvalidTransition);
    } else {
        result = Snapshot(latest_);
        result.status = NativeControlStatus::Accepted; result.stage = "armed-pause-requested"; result.win32Error = ERROR_SUCCESS;
    }
    result.armedPause = armedPauseHistory_.Last();
    return result;
}

NativeControlResult NativeDebugOwner::Impl::QueryArmedPause(std::string_view requestId) const {
    const auto receipt = armedPauseHistory_.Find(requestId);
    if (!receipt) return Reject({"armed-pause-request-not-found", ERROR_NOT_FOUND}, LedgerResult::ReplayExpired);
    auto result = receipt->groupId ? Query(*receipt->groupId) : Query({});
    result.armedPause = receipt;
    return result;
}

NativeControlResult NativeDebugOwner::Impl::Query(std::string_view groupId, std::string_view releaseRequestId) const {
    if (!groupId.empty()) {
        const auto report = [&](const PauseRecord& record) {
            auto result = Snapshot(&record);
            if (!releaseRequestId.empty()) {
                result.release = ledger_.QueryRelease(releaseRequestId, groupId);
                if (!result.release) {
                    result.status = NativeControlStatus::Rejected;
                    result.stage = "release-request-not-found";
                    result.win32Error = ERROR_NOT_FOUND;
                    result.ledgerResult = LedgerResult::InvalidEvidence;
                    result.releaseRequestId.reset();
                    return result;
                }
                result.releaseRequestId = releaseRequestId;
            }
            return result;
        };
        if (latest_ && latest_->groupId == groupId) { return report(*latest_); }
        for (const auto& record : breakpointStops_) {
            if (record.groupId == groupId) { return report(record); }
        }
        for (const auto& [id, record] : pauses_) {
            if (record.groupId == groupId) { return report(record); }
        }
        auto result = Snapshot(nullptr);
        result.status = NativeControlStatus::Rejected;
        result.stage = "stop-group-not-found";
        result.win32Error = ERROR_NOT_FOUND;
        result.ledgerResult = LedgerResult::MissingGroup;
        return result;
    }
    if (!releaseRequestId.empty()) {
        auto result = Reject({"release-query-requires-group", ERROR_INVALID_PARAMETER}, LedgerResult::InvalidEvidence);
        result.releaseRequestId.reset();
        result.release.reset();
        return result;
    }
    auto result = Snapshot(latest_);
    if (closing_ && result.clean) {
        result.status = NativeControlStatus::Closed;
        if (!result.win32Error) { result.stage = "owner-closed"; }
    } else if (closing_ && result.status != NativeControlStatus::RecoveryRequired) {
        result.status = NativeControlStatus::ClosePending;
    }
    return result;
}

void NativeDebugOwner::Impl::SaveStepReceipt() {
    const auto& receipt = step_.Receipt();
    const auto& id = receipt.request.release.requestId;
    if (id.empty()) return;
    if (!stepHistory_.contains(id)) stepOrder_.push_back(id);
    stepHistory_.insert_or_assign(id, receipt);
    while (stepOrder_.size() > 128) {
        stepHistory_.erase(stepOrder_.front());
        stepOrder_.pop_front();
    }
}

NativeError NativeDebugOwner::Impl::RestoreStep(bool exited) {
    if (!step_.HasResources()) return {};
    if (breakpoint_ && breakpoint_->executionPage && breakpoint_->pageAdvancing && !exited) {
        // 同伴放行之前必须先关回NX；失败继续保留TF、同伴债务与原debug事件。
        const auto error = breakpoint_->retire ? breakpoint_->executionPage->Restore(process_.Get()) :
            breakpoint_->executionPage->SetExecutable(process_.Get(), false);
        if (error)
            return {"page-rearm-before-step-restore", error};
        breakpoint_->pageAdvancing = false;
    }
    const auto error = step_.Restore(exited, event_ ? &*event_ : nullptr);
    SaveStepReceipt();
    return {error.stage, error.code};
}

NativeControlResult NativeDebugOwner::Impl::QueryStep(std::string_view requestId) const {
    const auto old = stepHistory_.find(requestId);
    if (old == stepHistory_.end()) return Reject({"step-request-not-found", ERROR_NOT_FOUND}, LedgerResult::ReplayExpired);
    auto result = old->second.stopGroupId ? Query(*old->second.stopGroupId) : Query({});
    result.step = old->second;
    return result;
}

NativeControlResult NativeDebugOwner::Impl::Step(const NativeStepRequest& request) {
    const auto& release = request.release;
    if (const auto old = stepHistory_.find(release.requestId); old != stepHistory_.end()) {
        if (old->second.request != request) return Reject({"step-request-conflict", ERROR_INVALID_PARAMETER}, LedgerResult::Conflict);
        auto result = QueryStep(release.requestId);
        result.ledgerResult = LedgerResult::Duplicate;
        return result;
    }
    if (latest_ && latest_->manualPause)
        return Reject({"step-manual-pause-helper-not-user-stop", ERROR_NOT_SUPPORTED}, LedgerResult::InvalidTransition);
    if (breakpoint_ && (breakpoint_->interruptRequested || breakpoint_->interruptTid || breakpoint_->interruptThread))
        return Reject({"step-requested-interrupt-not-drained", ERROR_BUSY}, LedgerResult::InvalidTransition);
    if (!breakpoint_ || breakpoint_->retire || closing_ || !event_ || !latest_ ||
        (!latest_->hit && !latest_->stepStop) || event_->dwDebugEventCode != EXCEPTION_DEBUG_EVENT ||
        step_.Running() || step_.HasResources()) {
        return Reject({"step-requires-live-breakpoint-owner-stop", ERROR_BUSY}, LedgerResult::InvalidTransition);
    }
    const auto group = ledger_.Query(release.groupId);
    const auto responsibility = ledger_.UnresolvedNativeResponsibility();
    if (!group || !responsibility || release.owner != owner_ || release.groupId != latest_->groupId ||
        release.stopId != responsibility->stopId || release.event != responsibility->event ||
        release.event.serial != eventSerial_ || release.expectedStateRevision != group->stateRevision ||
        (responsibility->state != EventState::Held && responsibility->state != EventState::Retryable) ||
        request.thread != responsibility->actualEventThread || request.tid != event_->dwThreadId ||
        !SequencedReleaseId(release.requestId) || ledger_.QueryRelease(release.requestId)) {
        return Reject({"step-stop-authorization-mismatch", ERROR_INVALID_PARAMETER}, LedgerResult::InvalidEvidence);
    }
    if (latest_->stepStop && latest_->continuation != DBG_CONTINUE)
        return Reject({"step-application-exception-requires-continue", ERROR_NOT_SUPPORTED}, LedgerResult::InvalidTransition);
    const auto member = std::find_if(latest_->frozenThreads.begin(), latest_->frozenThreads.end(), [&](const auto& value) {
        return value.identity == request.thread && value.tid == request.tid && value.creationTime == request.threadCreationTime;
    });
    const auto selected = breakpoint_->slots.find(request.tid);
    if (member == latest_->frozenThreads.end() || selected == breakpoint_->slots.end())
        return Reject({"step-thread-instance-not-frozen", ERROR_INVALID_DATA}, LedgerResult::IdentityMismatch);
    if (request.mode != NativeStepMode::Into && request.mode != NativeStepMode::OverCall && request.mode != NativeStepMode::Out)
        return Reject({"step-mode-unsupported", ERROR_NOT_SUPPORTED}, LedgerResult::InvalidEvidence);
    if (const auto error = VerifyBoundSite(); error) {
        RetireBreakpoint(error);
        return Reject(error, LedgerResult::IdentityMismatch);
    }
    std::vector<HANDLE> peers;
    for (const auto& [tid, slot] : breakpoint_->slots) if (tid != request.tid) peers.push_back(slot.thread.Get());
    if (breakpoint_->executionPage) {
        if (const auto error = breakpoint_->executionPage->OpenInstruction(process_.Get(), selected->second.thread.Get(), breakpoint_->pageAdvancing)) {
            RequireRecovery({"page-open-before-user-step", error});
            return Reject({"page-open-before-user-step", error}, LedgerResult::InvalidTransition);
        }
        if (breakpoint_->pageAdvancing) {
            breakpoint_->pageAdvanceDeadline = GetTickCount64() + kPageAdvanceDeadlineMs;
            breakpoint_->pageTimeoutRequested = false;
        }
    }
    if (const auto error = step_.Prepare(process_.Get(), selected->second.thread.Get(), request, peers,
        breakpoint_->executionPage ? &*breakpoint_->executionPage : nullptr); error) {
        step_.MarkFailure(error);
        if (breakpoint_->executionPage && breakpoint_->pageAdvancing) {
            if (const auto rearm = breakpoint_->executionPage->SetExecutable(process_.Get(), false)) {
                RequireRecovery({"page-rearm-after-step-rejection", rearm});
                return Reject({"page-rearm-after-step-rejection", rearm}, LedgerResult::InvalidTransition);
            }
            breakpoint_->pageAdvancing = false;
        }
        const auto restored = RestoreStep();
        SaveStepReceipt();
        if (restored) RequireRecovery(restored);
        return Reject({error.stage, error.code}, LedgerResult::InvalidEvidence);
    }
    SaveStepReceipt();
    // Release validates and records the very same authorization in StopLedger.
    // Suppress generic resume cleanup only around this serial owner operation.
    stepSubmitting_ = true;
    auto result = Release(release, false);
    stepSubmitting_ = false;
    if (!result.release || !result.release->receipt || result.release->receipt->result != ReleaseResult::Continued) {
        step_.RequestCancel();
        if (event_ && failedContinueSerial_ != eventSerial_) {
            if (const auto error = RestoreStep(); error) RequireRecovery(error);
        }
        step_.MarkFailure({"step-release-not-confirmed", result.win32Error ? result.win32Error : ERROR_INVALID_DATA});
        SaveStepReceipt();
    }
    result.step = step_.Receipt();
    return result;
}

NativeControlResult NativeDebugOwner::Impl::CancelStep(std::string_view requestId) {
    const auto old = stepHistory_.find(requestId);
    if (old == stepHistory_.end()) return Reject({"step-request-not-found", ERROR_NOT_FOUND}, LedgerResult::ReplayExpired);
    if (!step_.Running() || step_.Receipt().request.release.requestId != requestId) return QueryStep(requestId);
    step_.RequestCancel();
    if (!event_) {
        if (const auto error = RequestInterrupt(); error) RequireRecovery(error);
    }
    return QueryStep(requestId);
}

void NativeDebugOwner::Impl::Run() {
    for (;;) {
        std::function<void()> work;
        {
            std::unique_lock lock(queueMutex_);
            if (!queued_ && closing_ && IsClean()) {
                process_.Reset();
                threadFinished_ = true;
                return;
            }
            if (!queued_ && (!attached_ || event_)) {
                wake_.wait(lock, [this] { return static_cast<bool>(queued_); });
            }
            work = std::exchange(queued_, {});
        }
        if (work) { work(); }
        if (attached_ && !event_) { Pump(); }
    }
}

void NativeDebugOwner::Impl::Pump() {
    DEBUG_EVENT event{};
    if (WaitForDebugEvent(&event, kWaitMs)) {
        Receive(event);
        if (!attached_ || event_) { return; }
    } else {
        const auto error = WinError("wait-for-debug-event");
        if (error.code != ERROR_SEM_TIMEOUT) {
            if (!detachFailed_) { RequireRecovery(error); }
            // Unsupported/transient wait errors should neither tight-loop nor block submitted commands.
            std::unique_lock lock(queueMutex_);
            wake_.wait_for(lock, std::chrono::milliseconds(kWaitMs), [this] { return static_cast<bool>(queued_); });
            return;
        }
    }
    if (breakpoint_) {
        auto& bp = *breakpoint_;
        const auto now = GetTickCount64();
        if (bp.pageAdvancing && step_.Running() && !bp.pageTimeoutRequested && now >= bp.pageAdvanceDeadline) {
            bp.pageTimeoutRequested = true;
            step_.RequestTimeout(); // 缺少BS不能按时间猜测完成，必须取得真实事件后再恢复同伴。
            if (const auto error = RequestInterrupt(); error) RequireRecovery(error);
        }
        if (bp.awaitingAttachBreak && now >= attachDeadline_) {
            const NativeError timeout{"breakpoint-attach-timeout", ERROR_TIMEOUT};
            RetireBreakpoint(timeout);
            RequireRecovery(timeout);
        } else if (bp.interruptRequested && now >= attachDeadline_) {
            armedPauseHistory_.Complete(NativeArmedPauseState::RecoveryRequired, "armed-pause-interrupt-timeout", ERROR_TIMEOUT);
            RequireRecovery({"breakpoint-cleanup-interrupt-timeout", ERROR_TIMEOUT});
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
        RequireRecovery({"unexpected-native-event-process", ERROR_INVALID_DATA});
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
        RequireRecovery({"ambiguous-breakpoint-during-attach-cleanup", ERROR_NOT_SUPPORTED});
        return;
    }
    if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
        ContinueExitEvent(event.u.ExitProcess.dwExitCode);
        return;
    }
    // Preserve exception dispatch for any non-owned exception. The manual stop only owns
    // the attach create-process event.
    if (!ApplyContinue(event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE)) { return; }
    if (closing_ || latest_->status != NativeControlStatus::Accepted) {
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
    if (const auto error = VerifyBoundSite(); error) return error;
    const auto error = native_owner_detail::EnrollNativeBreakpointThread(bp.slots, bp.request.target.pid, tid,
        eventThread, bp.binding.address, bp.debugControl, breakpointMembershipRevision_, bp.executionPage.has_value());
    bp.binding.enrolledThreads = bp.slots.size();
    return error;
}

NativeError NativeDebugOwner::Impl::CoverBreakpointThreads(const std::vector<FrozenThread>& frozen) {
    auto& bp = *breakpoint_;
    if (!event_ || !bp.installed) return {"breakpoint-thread-coverage-requires-event", ERROR_INVALID_STATE};
    if (const auto error = VerifyBoundSite(); error) return error;
    for (const auto& thread : frozen) {
        const auto tid = thread.member.tid;
        const auto wait = WaitForSingleObject(thread.handle.Get(), 0);
        if (wait == WAIT_OBJECT_0) continue;
        if (wait != WAIT_TIMEOUT) return WinError("check-breakpoint-covered-thread");
        // 枚举可能先看见尚未分发CREATE_THREAD的对象；在当前事件内完成登记后才允许放行。
        const auto error = native_owner_detail::EnrollNativeBreakpointThread(bp.slots, bp.request.target.pid,
            tid, thread.handle.Get(), bp.binding.address, bp.debugControl, breakpointMembershipRevision_,
            bp.executionPage.has_value());
        bp.binding.enrolledThreads = bp.slots.size(); // 部分安装失败也保留已取得的槽位恢复责任。
        if (error) return error;
        if (step_.Running()) {
            const auto slot = bp.slots.find(tid);
            if (const auto hold = step_.Enroll(slot->second.thread.Get()); hold) return {hold.stage, hold.code};
        }
    }
    return {};
}

NativeError NativeDebugOwner::Impl::InstallBreakpoint() {
    auto& bp = *breakpoint_;
    NativeImageSite site;
    const auto pid = bp.request.target.pid;
    DWORD error = ERROR_SUCCESS;
    if (bp.request.privateRangeBytes) {
        bp.executionPage.emplace(); // Resolve无保护副作用，NX取得责任发生在全部线程登记后。
        error = bp.executionPage->Resolve(process_.Get(), pid, bp.request.privateAddress, bp.request.privateRangeBytes);
        if (!error) site = bp.executionPage->Site().site;
    } else if (bp.request.privateAddress) {
        NativeExplicitMemorySite explicitSite; // 在真实附加停止期间解析，后续不随地址重绑。
        error = ResolveNativeExplicitMemorySite(process_.Get(), pid, bp.request.privateAddress,
            bp.request.writeWatchBytes, explicitSite);
        if (!error) {
            site = explicitSite.site;
            bp.explicitSite = explicitSite;
        }
    } else if (bp.request.executePointerExport) {
        NativePrivateExecutionSite privateSite;
        error = ResolveNativePrivateExecutionSite(process_.Get(), pid, bp.request.modulePath, bp.request.exportName, privateSite);
        if (!error) {
            site = privateSite.site;
            bp.privateExecution = privateSite;
        }
    } else error = bp.request.writeWatchPointerExport
        ? ResolveNativePointerDataSite(process_.Get(), pid, bp.request.modulePath, bp.request.exportName, bp.request.writeWatchBytes, site)
        : ResolveNativeImageSite(process_.Get(), pid, bp.request.modulePath, bp.request.rva,
            bp.request.exportName, site, bp.request.writeWatchBytes);
    if (error) { return {bp.request.privateAddress ? "resolve-explicit-private-address" : "resolve-requested-image-site", error}; }
    bp.binding.moduleBase = site.base;
    bp.binding.address = site.address;
    bp.binding.rva = site.rva;
    bp.binding.pointerExportAddress = site.pointerExportAddress;
    bp.binding.allocationBase = site.allocationBase;
    bp.binding.regionBase = site.regionBase;
    bp.binding.regionBytes = site.regionBytes;
    bp.binding.regionProtection = site.regionProtection;
    bp.binding.executePointerExport = bp.request.executePointerExport;
    bp.binding.explicitPrivateAddress = bp.request.privateAddress != 0;
    if (bp.explicitSite && bp.request.writeWatchBytes && site.regionProtection == PAGE_EXECUTE_READWRITE &&
        site.address == site.regionBase) {
        bp.binding.privateExecutionFollowAvailable = true; // 原RWX区间起点，不另造指针候选。
    }
    // 仅初始RWX私有区间起点可转换；后续保护变化不能重新生成候选偷偷复活。
    if (bp.request.writeWatchPointerExport && site.regionProtection == PAGE_EXECUTE_READWRITE &&
        site.address == site.regionBase)
    {
        NativePrivateExecutionSite candidate; // 冻结selector自身映射和原私有区域属性。
        if (!ResolveNativePrivateExecutionSite(process_.Get(), pid, bp.request.modulePath, bp.request.exportName, candidate) &&
            candidate.site.address == site.address && candidate.site.regionBase == site.regionBase &&
            candidate.site.regionBytes == site.regionBytes && candidate.site.allocationBase == site.allocationBase &&
            candidate.site.regionProtection == site.regionProtection)
        {
            bp.writeExecutionCandidate = candidate;
            bp.binding.privateExecutionFollowAvailable = true;
        }
    }
    // 先在附加事件持有期间取基线。没有完整样本就不武装任何线程的数据关注点。
    if (bp.request.writeWatchBytes) {
        if (const auto baseline = ReadWatchedData(bp.dataBaseline); baseline) return baseline;
    }
    std::vector<FrozenThread> threads;
    if (const auto capture = CaptureThreads(pid, latest_->processInstanceId, threadIds_, threads); capture) { return capture; }
    for (const auto& thread : threads) {
        if (const auto enroll = EnrollThread(thread.member.tid, thread.handle.Get()); enroll) { return enroll; }
    }
    if (bp.executionPage) {
        bp.binding.executionRanges.reserve(64);
        if (const auto arm = bp.executionPage->SetExecutable(process_.Get(), false))
            return {"page-arm-non-executable", arm};
        bp.binding.executionRanges = bp.executionPage->Ranges();
    }
    if (const auto verification = VerifyBoundSite(); verification) return verification;
    bp.installed = true;
    return {};
}

NativeError NativeDebugOwner::Impl::VerifyBoundSite() const {
    if (breakpoint_ && breakpoint_->executionPage) {
        const auto error = breakpoint_->executionPage->Verify(process_.Get());
        return error ? NativeError{"private-execution-page-changed", error} : NativeError{};
    }
    if (breakpoint_ && breakpoint_->binding.explicitPrivateAddress) {
        if (!breakpoint_->explicitSite) return {"explicit-private-site-not-frozen", ERROR_INVALID_DATA};
        const auto error = VerifyNativeExplicitMemorySite(process_.Get(), *breakpoint_->explicitSite,
            breakpoint_->binding.writeWatchBytes); // 转换后零宽度走执行属性验证。
        return error ? NativeError{"explicit-private-region-changed", error} : NativeError{};
    }
    if (!breakpoint_ || !breakpoint_->binding.executePointerExport) return {};
    if (!breakpoint_->privateExecution) return {"private-execution-site-not-frozen", ERROR_INVALID_DATA};
    const auto error = VerifyNativePrivateExecutionSite(process_.Get(), *breakpoint_->privateExecution);
    return error ? NativeError{"private-execution-pointer-or-region-changed", error} : NativeError{};
}

// 只在原生停止期间读取绑定中的既有数据。成功时返回完整范围，失败时保留系统错误。
NativeError NativeDebugOwner::Impl::ReadWatchedData(std::array<std::uint8_t, 8>& bytes) const {
    const auto& binding = breakpoint_->binding; // 已解析且与当前映像实例绑定的可写数据。
    if (binding.explicitPrivateAddress) {
        if (const auto error = VerifyBoundSite(); error) return error;
    }
    if (binding.pointerExportAddress) {
        const NativeImageSite site{static_cast<std::uintptr_t>(binding.moduleBase), static_cast<std::uintptr_t>(binding.address),
            binding.rva, static_cast<std::uintptr_t>(binding.pointerExportAddress), static_cast<std::uintptr_t>(binding.allocationBase),
            static_cast<std::uintptr_t>(binding.regionBase), static_cast<std::size_t>(binding.regionBytes), binding.regionProtection};
        if (const auto error = VerifyNativePointerDataSite(process_.Get(), site, binding.writeWatchBytes)) {
            return {"write-watch-private-region-changed", error};
        }
    }
    const auto* address = reinterpret_cast<const void*>(static_cast<std::uintptr_t>(binding.address));
    SIZE_T count = 0; // 系统实际复制的大小。
    if (!ReadProcessMemory(process_.Get(), address, bytes.data(), binding.writeWatchBytes, &count)) {
        return WinError("read-write-watch-data");
    }
    return count == binding.writeWatchBytes ? NativeError{} : NativeError{"read-write-watch-data", ERROR_PARTIAL_COPY};
}

NativeError NativeDebugOwner::Impl::RestoreBreakpoint() {
    auto& bp = *breakpoint_;
    if (bp.executionPage) {
        if (const auto error = bp.executionPage->Restore(process_.Get())) return {"restore-private-execution-page", error};
        bp.pageAdvancing = false;
        bp.slots.clear(); // 此模式从未写DR0，不能把线程原寄存器当成本端修改恢复。
        bp.binding.enrolledThreads = 0;
        return {};
    }
    const auto error = native_owner_detail::RestoreNativeBreakpointThreads(bp.slots, bp.binding.address);
    bp.binding.enrolledThreads = bp.slots.size();
    return error;
}

NativeError NativeDebugOwner::Impl::AdoptBreakpointHit(std::optional<NativeDataChange> dataChange, bool stepStop,
    DWORD continuation, std::optional<std::uint64_t> hitAddress, bool manualPause) {
    if (const auto error = VerifyBoundSite(); error) {
        RetireBreakpoint(error);
        return error;
    }
    const auto& bp = *breakpoint_;
    if (breakpointMembershipRevision_ == std::numeric_limits<std::uint64_t>::max()) {
        return {"breakpoint-stop-identity-exhausted", ERROR_ARITHMETIC_OVERFLOW};
    }
    const auto revision = breakpointMembershipRevision_ + 1;
    PauseRecord record{bp.request.target, BreakpointId(owner_.backendInstanceId, revision, false),
        BreakpointId(owner_.backendInstanceId, revision, true), firstBound_->processInstanceId};
    record.timing = firstBound_->timing;
    record.timing.eventObservedQpc = ReadQpc();
    if (!stepStop && !manualPause) record.hit = NativeBreakpointHit{bp.request.target.requestId, hitAddress.value_or(bp.binding.address), dataChange};
    record.stepStop = stepStop;
    record.manualPause = manualPause;
    record.continuation = continuation;
    record.hitEventSerial = eventSerial_;
    std::vector<FrozenThread> frozen;
    if (const auto error = CaptureThreads(record.request.pid, record.processInstanceId, threadIds_, frozen); error) { return error; }
    if (const auto error = CoverBreakpointThreads(frozen); error) return error;
    FrozenStopGroup group{record.groupId, revision, {}, {}};
    ThreadIdentity origin;
    ThreadIds newIds;
    for (const auto& thread : frozen) {
        const auto& member = thread.member;
        group.requested.push_back(member.identity);
        record.frozenThreads.push_back(member);
        newIds.emplace(std::pair<DWORD, std::uint64_t>{member.tid, member.creationTime}, member.identity.threadId);
        const auto slot = bp.slots.find(member.tid);
        if (member.tid == event_->dwThreadId && slot != bp.slots.end() &&
            CompareObjectHandles(thread.handle.Get(), slot->second.thread.Get())) {
            origin = member.identity;
#if defined(_M_X64)
            if (!manualPause) {
                CONTEXT registers{}; // 只读取这次真实event的精确线程，零值不是失败标志。
                registers.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                if (GetThreadContext(slot->second.thread.Get(), &registers)) {
                    record.registers = NativeStopRegisters{origin, registers.Rip, registers.Rax, registers.Rsp,
                        registers.Rbx, registers.Rcx, registers.Rdx, registers.Rbp, registers.Rsi, registers.Rdi,
                        registers.R8, registers.R9, registers.R10, registers.R11, registers.R12, registers.R13,
                        registers.R14, registers.R15, registers.EFlags};
                }
            }
#endif
        }
    }
    group.membershipSha256 = MembershipHash(group.requested);
    if (origin.threadId.empty() || group.membershipSha256.empty()) { return {"verify-breakpoint-stop-members", ERROR_INVALID_DATA}; }
    breakpointStops_.push_back(std::move(record));
    if (ledger_.Freeze(std::move(group), HistoryRetention::Rolling) != LedgerResult::Applied) {
        breakpointStops_.pop_back();
        return {"freeze-breakpoint-stop-group", ERROR_INVALID_DATA};
    }
    breakpointMembershipRevision_ = revision;
    latest_ = &breakpointStops_.back();
    if (breakpointStops_.size() > kStopHistoryGroups) { breakpointStops_.pop_front(); }
    const NativeEventKey key{owner_.backendInstanceId, eventSerial_};
    const auto phase = stepStop || manualPause ? std::optional<StopPhase>{} : std::optional(dataChange ?
        StopPhase::DataWriteObserved : StopPhase::ExecutionEnterAttempt);
    if (ledger_.AdoptNativeStop(latest_->groupId, {key, origin, latest_->stopId, phase}) != LedgerResult::Applied) {
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
    if (manualPause) {
        const auto held = ledger_.Query(latest_->groupId);
        if (!held || held->state != GroupState::HeldComplete)
            return {"armed-pause-complete-membership-unconfirmed", ERROR_INVALID_DATA};
    }
    latest_->status = NativeControlStatus::Held;
    latest_->outcome = {manualPause ? "manual-pause-held" : stepStop ? "native-step-stop-held" : dataChange ? "data-write-breakpoint-held" :
        "execution-breakpoint-held", ERROR_SUCCESS};
    if (stepStop && bp.executionPage && step_.Receipt().win32Error == ERROR_TIMEOUT)
        latest_->outcome = {"page-advance-timeout-held", ERROR_TIMEOUT};
    breakpoint_->binding.state = NativeBreakpointState::Held;
    breakpoint_->binding.stage = latest_->outcome.stage;
    breakpoint_->binding.win32Error = latest_->outcome.code;
    armedPauseHistory_.Complete(manualPause ? NativeArmedPauseState::Held : NativeArmedPauseState::Preempted,
        manualPause ? "armed-pause-held" : "armed-pause-preempted-by-native-stop", ERROR_SUCCESS,
        latest_->groupId, NativeEventKey{owner_.backendInstanceId, eventSerial_});
    if (manualPause) latest_->manualPauseReceipt = armedPauseHistory_.Last();
    return {};
}

NativeError NativeDebugOwner::Impl::PrepareBreakpointResume() {
    auto& bp = *breakpoint_;
    if (!bp.retire) {
        std::vector<FrozenThread> current;
        if (const auto error = CaptureThreads(bp.request.target.pid, latest_->processInstanceId, threadIds_, current); error)
            return error;
        if (const auto error = CoverBreakpointThreads(current); error) return error;
        // 这里只补实际武装与同伴暂停，不改写原停止组、origin、寄存器或采样身份。
    }
    if ((bp.binding.executePointerExport || bp.binding.explicitPrivateAddress) && !bp.retire) {
        if (const auto error = VerifyBoundSite(); error) RetireBreakpoint(error);
    }
    if (bp.binding.pointerExportAddress && !bp.binding.executePointerExport && !bp.retire) {
        // 放行前再次核对固定区间；外部编辑不能把当前停止令牌转授到别的指针目标。
        std::array<std::uint8_t, 8> observed{};
        if (const auto error = ReadWatchedData(observed); error) return error;
    }
    if (bp.retire && stepSubmitting_) step_.MarkFailure({bp.retirement.stage, bp.retirement.code});
    if (!stepSubmitting_ || bp.retire) {
        if (const auto error = RestoreStep(); error) return error;
    }
    if (bp.retire) { return RestoreBreakpoint(); }
    if (latest_->manualPause && latest_->hitEventSerial == eventSerial_ && !stepSubmitting_)
        return {}; // 仅当前主动INT3事件直接放行；历史手动暂停不影响后续真实DR0事件。
    if (bp.executionPage) return PreparePageResume();
    const auto slot = bp.slots.find(event_->dwThreadId);
    if (slot == bp.slots.end()) { return {"missing-breakpoint-resume-thread", ERROR_INVALID_DATA}; }
    const auto thread = slot->second.thread.Get();
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &context)) { return WinError("read-breakpoint-resume-context"); }
    const bool writing = bp.binding.writeWatchBytes != 0; // 写入停点在指令执行后交付，不重试前一条指令。
    const bool sourceWrite = latest_->hit && latest_->hit->dataChange; // 转换不改原写入事件，RIP不必等于入口。
    if ((!writing && !sourceWrite && !latest_->stepStop && InstructionPointer(context) != bp.binding.address) || context.Dr0 != bp.binding.address ||
        (context.Dr7 & kDr0Control) != bp.debugControl) { return {"breakpoint-resume-context-changed", ERROR_INVALID_DATA}; }
    // 执行停点设置 RF 跳过本次同地址取指。数据停点只清掉本槽的已处理原因。
    const bool resumeExecution = !writing && !sourceWrite && InstructionPointer(context) == bp.binding.address;
    if (!resumeExecution && !(context.Dr6 & kDr0Local)) return {}; // 取消助手/普通step无本端DR0原因，不写上下文。
    if (resumeExecution) context.EFlags |= kResumeFlag;
    // 普通step/取消停止只清DR0原因；只有真实入口重试才写RF，避免触及无关控制现场。
    context.ContextFlags = resumeExecution ? CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS : CONTEXT_DEBUG_REGISTERS;
    context.Dr6 = static_cast<decltype(context.Dr6)>(context.Dr6 & ~kDr0Local);
    if (!SetThreadContext(thread, &context)) { return WinError("prepare-breakpoint-resume"); }
    if (!GetThreadContext(thread, &context)) { return WinError("read-breakpoint-resume-preparation"); }
    if ((context.Dr6 & kDr0Local) != 0 || (resumeExecution && !(context.EFlags & kResumeFlag))) {
        return {"verify-breakpoint-resume-flags", ERROR_INVALID_DATA};
    }
    return {};
}

NativeError NativeDebugOwner::Impl::PreparePageResume() {
    auto& bp = *breakpoint_;
    if (stepSubmitting_) {
        if (!bp.pageAdvancing) return {}; // 用户从范围外步进，不临时开放任何关注页。
        const auto error = step_.ArmPageTrap(); // Into复用原TF；Over/Out增加可独立归还的内部TF。
        return {error.stage, error.code};
    }
    if (latest_->continuation != DBG_CONTINUE) return {}; // 真正应用异常保持原分派，不添加内部TF。
    const auto slot = bp.slots.find(event_->dwThreadId);
    if (slot == bp.slots.end()) return {"page-resume-thread-not-enrolled", ERROR_INVALID_DATA};
    const auto member = std::find_if(latest_->frozenThreads.begin(), latest_->frozenThreads.end(), [&](const auto& value) {
        return value.tid == event_->dwThreadId;
    });
    if (member == latest_->frozenThreads.end()) return {"page-resume-thread-not-frozen", ERROR_INVALID_DATA};
    if (const auto error = bp.executionPage->OpenInstruction(process_.Get(), slot->second.thread.Get(), bp.pageAdvancing))
        return {"page-open-before-advance", error};
    if (!bp.pageAdvancing) return {}; // 当前指令未触及登记页，不取得临时保护或TF责任。
    bp.pageAdvanceDeadline = GetTickCount64() + kPageAdvanceDeadlineMs;
    bp.pageTimeoutRequested = false;
    NativeStepRequest advance;
    advance.thread = member->identity;
    advance.tid = member->tid;
    advance.threadCreationTime = member->creationTime;
    std::vector<HANDLE> peers;
    for (const auto& [tid, peer] : bp.slots) if (tid != advance.tid) peers.push_back(peer.thread.Get());
    const auto prepared = step_.PreparePageAdvance(process_.Get(), slot->second.thread.Get(), advance, peers, &*bp.executionPage);
    if (!prepared) { bp.internalPageAdvance = true; return {}; }
    // 尚持有原事件，失败先恢复NX再归还部分取得的TF/同伴责任；禁止直接Continue到NX。
    if (const auto error = bp.executionPage->SetExecutable(process_.Get(), false))
        return {"page-rearm-after-advance-rejection", error};
    bp.pageAdvancing = false;
    step_.MarkFailure(prepared);
    if (const auto error = RestoreStep(); error) return error;
    return {prepared.stage, prepared.code};
}

bool NativeDebugOwner::Impl::ReceivePageEvent(const DEBUG_EVENT& event) {
    auto& bp = *breakpoint_;
    if (!bp.executionPage || (!bp.executionPage->OwnsProtection() && !bp.pageAdvancing &&
        !step_.PageTrapOwned() && !bp.internalPageAdvance)) return false;
    auto& page = *bp.executionPage;
    const auto slot = bp.slots.find(event.dwThreadId);
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    const bool executeAv = event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && event.u.Exception.dwFirstChance &&
        event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        event.u.Exception.ExceptionRecord.NumberParameters >= 2 && event.u.Exception.ExceptionRecord.ExceptionInformation[0] == 8 &&
        page.Contains(event.u.Exception.ExceptionRecord.ExceptionInformation[1]);
    if (executeAv && slot != bp.slots.end()) {
        if (!GetThreadContext(slot->second.thread.Get(), &context)) {
            RequireRecovery(WinError("page-read-fault-thread-context")); return true;
        }
        if (page.IsExecuteFault(event, InstructionPointer(context))) {
            if (const auto error = page.Verify(process_.Get())) { RequireRecovery({"page-verify-execute-fault", error}); return true; }
            bp.cleanupDisposition = DBG_CONTINUE; // 已证明本端NX事件，失败也保留原事件/清退分派。
            if (bp.retire) { FinishBreakpointEvent(DBG_CONTINUE); return true; }
            if (const auto error = page.VerifyFaultSpan(process_.Get(), event, InstructionPointer(context))) {
                RequireRecovery({"page-execute-fault-instruction-unconfirmed", error}); return true;
            }
            if (step_.Running() && !bp.internalPageAdvance && !bp.pageAdvancing &&
                step_.Receipt().request.tid == event.dwThreadId && !step_.CancellationRequested()) {
                // 用户Over/Out跨页返回时继续同一step；不在每个NX重新创建用户命令或账本。
                if (const auto error = page.OpenInstruction(process_.Get(), slot->second.thread.Get(), bp.pageAdvancing)) {
                    RequireRecovery({"page-open-during-user-step", error}); return true;
                }
                if (!bp.pageAdvancing) { RequireRecovery({"page-step-fetch-window-missing", ERROR_INVALID_DATA}); return true; }
                bp.pageAdvanceDeadline = GetTickCount64() + kPageAdvanceDeadlineMs;
                bp.pageTimeoutRequested = false;
                if (const auto error = step_.ArmPageTrap(); error) { RequireRecovery({error.stage, error.code}); return true; }
                if (ApplyContinue(DBG_CONTINUE)) bp.cleanupDisposition.reset();
                return true;
            }
            const bool interrupted = step_.Running();
            if (interrupted) {
                if (bp.pageAdvancing) {
                    if (const auto error = page.SetExecutable(process_.Get(), false)) {
                        RequireRecovery({"page-rearm-before-competing-fetch", error}); return true;
                    }
                    bp.pageAdvancing = false;
                }
                (void)step_.Observe(event, false, false);
                if (const auto error = RestoreStep(); error) { RequireRecovery(error); return true; }
                if (step_.Receipt().state == NativeStepState::RecoveryRequired) {
                    RequireRecovery({step_.Receipt().stage, step_.Receipt().win32Error}); return true;
                }
            }
            bp.internalPageAdvance = false;
            if (const auto error = AdoptBreakpointHit({}, false, DBG_CONTINUE, InstructionPointer(context)); error) {
                RequireRecovery(error); return true;
            }
            if (interrupted) { step_.BindStop(latest_->groupId, {owner_.backendInstanceId, eventSerial_}); SaveStepReceipt(); }
            bp.cleanupDisposition.reset();
            return true;
        }
    }
    const bool processExit = event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT;
    const bool selectedExit = event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT && event.dwThreadId == step_.Receipt().request.tid;
    if (processExit) { page.ProcessExited(); bp.pageAdvancing = false; }
    if (!bp.pageAdvancing && !step_.PageTrapOwned() && !bp.internalPageAdvance && !processExit) return false;
    if (event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT && !processExit && !selectedExit) return false;
    if (!processExit && bp.pageAdvancing) {
        const auto error = bp.retire ? page.Restore(process_.Get()) : page.SetExecutable(process_.Get(), false);
        if (error) { RequireRecovery({"page-rearm-after-advance", error}); return true; }
        bp.pageAdvancing = false; // 必须先关NX，之后才允许Restore释放同伴。
    }
    if (step_.PageTrapOwned()) {
        bool onlyAdvance = false;
        if (const auto error = step_.FinishPageTrap(event, onlyAdvance); error) {
            if (onlyAdvance) bp.cleanupDisposition = DBG_CONTINUE;
            RequireRecovery({error.stage, error.code}); return true;
        }
        if (onlyAdvance) {
            bp.cleanupDisposition = DBG_CONTINUE; // 清掉BS后仍保留本端异常的分派责任。
            if (bp.retire) { FinishBreakpointEvent(DBG_CONTINUE); return true; }
            if (step_.CancellationRequested()) {
                // BS先于取消助手到达：BS已被独立证明属于本端，保持Cancelled而非伪造DR1完成。
                (void)step_.Observe(event, true, false);
                if (const auto error = RestoreStep(); error) { RequireRecovery(error); return true; }
                if (step_.Receipt().state == NativeStepState::RecoveryRequired) {
                    RequireRecovery({step_.Receipt().stage, step_.Receipt().win32Error}); return true;
                }
                if (const auto error = AdoptBreakpointHit({}, true, DBG_CONTINUE); error) { RequireRecovery(error); return true; }
                step_.BindStop(latest_->groupId, {owner_.backendInstanceId, eventSerial_});
                SaveStepReceipt();
                bp.cleanupDisposition.reset();
                return true;
            }
            if (ApplyContinue(DBG_CONTINUE)) bp.cleanupDisposition.reset(); // 用户DR1仍运行，内部BS不构造完成证据。
            return true;
        }
    }
    if (!bp.internalPageAdvance) return false; // 原用户Into/Over/Out按现有Observe完成回执。
    const bool cancellationBreak = bp.interruptRequested && IsRequestedInterrupt(event);
    const bool stopped = step_.Observe(event, cancellationBreak, false);
    if (!stopped) return false;
    bp.cleanupDisposition = step_.Disposition();
    if (const auto error = RestoreStep(processExit); error) { RequireRecovery(error); return true; }
    if (cancellationBreak) { bp.interruptRequested = false; bp.interruptTid = 0; bp.interruptThread.Reset(); }
    if (step_.Receipt().state == NativeStepState::RecoveryRequired) {
        RequireRecovery({step_.Receipt().stage, step_.Receipt().win32Error}); return true;
    }
    bp.internalPageAdvance = false;
    if (processExit || selectedExit) { bp.cleanupDisposition.reset(); return false; }
    if (bp.retire) { FinishBreakpointEvent(step_.Disposition()); return true; }
    if (step_.EventKind() == NativeStepEventKind::StepCompleted && step_.Receipt().state == NativeStepState::Completed) {
        if (ApplyContinue(DBG_CONTINUE)) bp.cleanupDisposition.reset();
        return true;
    }
    // 内部推进遇到真正的应用异常，保留原分派并交给用户继续；不发布内部step回执。
    if (const auto error = AdoptBreakpointHit({}, true, step_.Disposition()); error) { RequireRecovery(error); return true; }
    bp.cleanupDisposition.reset();
    return true;
}

void NativeDebugOwner::Impl::RetireBreakpoint(NativeError reason) {
    auto& bp = *breakpoint_;
    if (!bp.retire || (!bp.retirement && reason)) { bp.retirement = reason; }
    bp.retire = true;
    if (bp.binding.state == NativeBreakpointState::RecoveryRequired) { return; }
    bp.binding.state = NativeBreakpointState::Retiring;
    bp.binding.stage = bp.retirement.stage;
    bp.binding.win32Error = bp.retirement.code;
}

void NativeDebugOwner::Impl::RequireRecovery(NativeError error) {
    armedPauseHistory_.Complete(NativeArmedPauseState::RecoveryRequired, error.stage, error.code, {},
        event_ ? std::optional(NativeEventKey{owner_.backendInstanceId, eventSerial_}) : std::nullopt);
    if (!latest_->firstRecoveryFailure) {
        NativeRecoveryFailure failure{error.stage, error.code, owner_, std::nullopt, std::nullopt};
        if (event_) {
            failure.pendingEvent = NativeEventKey{owner_.backendInstanceId, eventSerial_};
            if (const auto responsibility = ledger_.UnresolvedNativeResponsibility();
                responsibility && responsibility->event == *failure.pendingEvent) {
                failure.releaseRequestId = responsibility->lastRequestId;
            }
        }
        latest_->firstRecoveryFailure = std::move(failure);
    }
    if (breakpoint_) {
        auto& binding = breakpoint_->binding;
        binding.state = NativeBreakpointState::RecoveryRequired;
        binding.stage = error.stage;
        binding.win32Error = error.code;
    }
    latest_->status = NativeControlStatus::RecoveryRequired;
    latest_->outcome = error;
}

void NativeDebugOwner::Impl::FinishBreakpointEvent(DWORD disposition) {
    auto& bp = *breakpoint_;
    bp.cleanupDisposition = disposition;
    if (bp.retire && step_.Running()) {
        step_.MarkFailure({bp.retirement.stage, bp.retirement.code ? bp.retirement.code : ERROR_CANCELLED});
        SaveStepReceipt();
    }
    if (const auto error = RestoreStep(); error) { RequireRecovery(error); return; }
    if (const auto error = RestoreBreakpoint(); error) { RequireRecovery(error); return; }
    if (!ApplyContinue(disposition)) { return; }
    bp.cleanupDisposition.reset();
    Detach();
}

void NativeDebugOwner::Impl::ReceiveBreakpoint(const DEBUG_EVENT& event) {
    auto& bp = *breakpoint_;
    if (event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT && (step_.Running() || step_.HasResources())) {
        if (const auto error = step_.RetireExitedThread(event); error) {
            RequireRecovery({error.stage, error.code}); return;
        }
    }
    if (ReceivePageEvent(event)) return;
    bool stepStopped = false;
    verifiedReasons_ = 0;
    if (step_.Running()) {
        if (event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT &&
            !(bp.interruptRequested && reinterpret_cast<std::uintptr_t>(event.u.CreateThread.lpStartAddress) ==
                bp.systemBreakThread.address)) {
            if (const auto error = step_.Enroll(event.u.CreateThread.hThread); error) {
                step_.MarkFailure(error);
                bp.cleanupDisposition = DBG_CONTINUE;
                RequireRecovery({error.stage, error.code});
                return; // leave the creation event pending; new thread has not run
            }
        }
        const bool cancelBreak = bp.interruptRequested && IsRequestedInterrupt(event);
        stepStopped = step_.Observe(event, cancelBreak, !bp.executionPage);
        if (stepStopped) {
            verifiedReasons_ = step_.ObservedDr6() & kDr6Reasons;
            bp.cleanupDisposition = step_.Disposition();
            if (const auto error = RestoreStep(event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT); error) {
                RequireRecovery(error);
                return;
            }
            if (step_.HasResources() || step_.Receipt().state == NativeStepState::RecoveryRequired) {
                RequireRecovery({step_.Receipt().stage, step_.Receipt().win32Error ?
                    step_.Receipt().win32Error : ERROR_INVALID_STATE});
                return; // 事件保持待处理，退出线程不能让仍存在的peer暂停债被静默带走。
            }
            SaveStepReceipt();
            bp.cleanupDisposition.reset();
            if (cancelBreak) {
                bp.interruptRequested = false;
                bp.interruptTid = 0;
                bp.interruptThread.Reset();
            }
            if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                // Keep competing application exceptions dispatchable. Only our
                // verified TF/DR1 event or the exact requested break is consumed.
                DWORD disposition = step_.Disposition();
                const auto slot = bp.slots.find(event.dwThreadId);
                CONTEXT context{};
                context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
                bool ownDr0 = false;
                if (!bp.executionPage && slot != bp.slots.end() && GetThreadContext(slot->second.thread.Get(), &context)) {
                    // The step runtime read the debug status register before it
                    // restored the selected thread. A later read can no longer
                    // prove that this event was the user's own DR0 hit.
                    const auto reasons = step_.ObservedDr6() & kDr6Reasons;
                    ownDr0 = event.u.Exception.dwFirstChance &&
                        event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP &&
                        context.Dr0 == bp.binding.address && (context.Dr7 & kDr0Control) == bp.debugControl &&
                        (reasons & kDr0Local) && !(reasons & ~static_cast<DWORD64>(kDr0Local));
                }
                if (!bp.executionPage && !ownDr0 && step_.EventKind() == NativeStepEventKind::CompetingBreakpoint) {
                    // The user's own DR0 breakpoint fired before the step
                    // destination. That hit stays a breakpoint hit.
                    ownDr0 = true;
                }
                if (!ownDr0) {
                    if (const auto error = AdoptBreakpointHit(std::nullopt, true, disposition); error) {
                        if (bp.retire) { FinishBreakpointEvent(disposition); return; }
                        RequireRecovery(error);
                        return;
                    }
                    step_.BindStop(latest_->groupId, {owner_.backendInstanceId, eventSerial_});
                    SaveStepReceipt();
                    if (closing_ || bp.retire) (void)Close();
                    return;
                }
                // A user DR0 breakpoint wins over step completion; let the
                // existing path retain its hit/data-change semantics below.
            }
        }
    }
    if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
        ContinueExitEvent(event.u.ExitProcess.dwExitCode);
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
        if (!bp.processVerified) { bp.awaitingAttachBreak = false; }
    }
    if (event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT && bp.processVerified) {
        const auto start = reinterpret_cast<std::uintptr_t>(event.u.CreateThread.lpStartAddress);
        if ((bp.awaitingAttachBreak || bp.interruptRequested) && start == bp.systemBreakThread.address) {
            if (const auto error = native_owner_detail::CaptureNativeInterruptThread(bp.interruptThread, event); error) {
                bp.retryEventContext = true;
                RequireRecovery(error); return;
            }
            bp.interruptTid = event.dwThreadId;
            bp.retryEventContext = false;
        }
        if (!bp.retire && bp.binding.address) {
            if (const auto error = EnrollThread(event.dwThreadId, event.u.CreateThread.hThread); error) { RetireBreakpoint(error); }
        }
    } else if (event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
        bp.slots.erase(event.dwThreadId);
        bp.binding.enrolledThreads = bp.slots.size();
        if (bp.interruptTid == event.dwThreadId) {
            bp.interruptTid = 0; bp.interruptThread.Reset();
            if (std::exchange(bp.interruptRequested, false) || bp.awaitingAttachBreak) {
                bp.awaitingAttachBreak = false;
                bp.cleanupDisposition = DBG_CONTINUE; // 精确助手已退出，无后续中断可等；保留真实退出事件清退。
                RequireRecovery({"requested-interrupt-thread-exited-before-break", ERROR_PROCESS_ABORTED}); return;
            }
        }
    } else if (event.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT && bp.binding.address &&
        reinterpret_cast<std::uintptr_t>(event.u.UnloadDll.lpBaseOfDll) == bp.binding.moduleBase) {
        RetireBreakpoint({"breakpoint-module-unloaded", ERROR_SUCCESS});
    }

    DWORD disposition = event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
    if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && event.u.Exception.dwFirstChance) {
        const auto& exception = event.u.Exception.ExceptionRecord;
        const auto address = reinterpret_cast<std::uintptr_t>(exception.ExceptionAddress);
        if (IsRequestedInterrupt(event)) {
            disposition = DBG_CONTINUE;
            const bool manualPause = armedPauseHistory_.Pending();
            bp.awaitingAttachBreak = false;
            bp.interruptTid = 0;
            bp.interruptRequested = false;
            bp.interruptThread.Reset();
            if (!bp.retire && !bp.binding.address) {
                if (const auto error = InstallBreakpoint(); error) { RetireBreakpoint(error); }
            }
            if (manualPause && !bp.retire) {
                bp.cleanupDisposition = DBG_CONTINUE;
                if (const auto error = AdoptBreakpointHit({}, false, DBG_CONTINUE, {}, true); error) {
                    RequireRecovery(error); return;
                }
                bp.cleanupDisposition.reset();
                return;
            }
        } else if (!bp.executionPage && exception.ExceptionCode == EXCEPTION_SINGLE_STEP && bp.binding.address &&
            (bp.binding.writeWatchBytes || address == bp.binding.address)) {
            const auto slot = bp.slots.find(event.dwThreadId);
            CONTEXT context{};
            context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
            if (slot != bp.slots.end() && !GetThreadContext(slot->second.thread.Get(), &context)) {
                bp.retryEventContext = true;
                RequireRecovery(WinError("read-breakpoint-hit-context"));
                return;
            }
            bp.retryEventContext = false;
            // A step already captured the debug status register before it
            // restored the thread. A later read can no longer prove the cause.
            const auto reasons = verifiedReasons_ ? verifiedReasons_ : (context.Dr6 & kDr6Reasons);
            if (slot != bp.slots.end() && InstructionPointer(context) == address && context.Dr0 == bp.binding.address &&
                (context.Dr7 & kDr0Control) == bp.debugControl && (reasons & kDr0Local)) {
                if ((reasons & ~static_cast<DWORD64>(kDr0Local)) != 0) {
                    // TF/DR1已由本轮step恢复后，仍必须使用恢复前捕获的原因分派，不能将自有单步交回目标。
                    const auto& receipt = step_.Receipt(); // 精确请求线程及本轮停止地址，旧step回执不能授权。
                    const auto extras = reasons & ~static_cast<DWORD64>(kDr0Local); // 除本端DR0以外的同时命中位。
                    const bool ownedStepReason = stepStopped && verifiedReasons_ &&
                        event.dwThreadId == receipt.request.tid &&
                        ((receipt.request.mode == NativeStepMode::Into && extras == 0x4000) ||
                            (receipt.destination && extras == 2 && address == *receipt.destination));
                    if (ownedStepReason)
                    {
                        disposition = DBG_CONTINUE; // 已确认同时来自本端TF/DR1及DR0，仅清退，不伪造单指令完成。
                    }
                    RetireBreakpoint({"breakpoint-mixed-single-step-causes", ERROR_BUSY});
                } else {
                    disposition = DBG_CONTINUE;
                }
                if (!bp.retire && disposition == DBG_CONTINUE) {
                    std::optional<NativeDataChange> change; // 写入前后的差异，仅在停止期间读取。
                    std::array<std::uint8_t, 8> observed{}; // 本次触发后读取的目标数据。
                    if (bp.binding.writeWatchBytes) {
                        if (const auto error = ReadWatchedData(observed); error) {
                            RetireBreakpoint(error);
                        } else {
                            std::uint32_t mask = 0; // 掩码标明相对起点的哪些字节发生变化。
                            for (std::uint32_t i = 0; i < bp.binding.writeWatchBytes; ++i) {
                                if (observed[i] != bp.dataBaseline[i]) mask |= 1u << i;
                            }
                            change = NativeDataChange{bp.binding.writeWatchBytes, mask, slot->second.enrolledAfterStop};
                        }
                    }
                    if (!bp.retire && change && !change->changedByteMask) {
                        // 写回相同值时消费本端事件，保留原数据基线和所有线程的关注点。
                        if (const auto error = PrepareBreakpointResume(); error) RetireBreakpoint(error);
                    } else if (!bp.retire) {
                        if (const auto error = AdoptBreakpointHit(change); error) {
                            RetireBreakpoint(error);
                        } else {
                            if (change) bp.dataBaseline = observed;
                            if (stepStopped) {
                                step_.BindStop(latest_->groupId, {owner_.backendInstanceId, eventSerial_});
                                SaveStepReceipt();
                            }
                            return;
                        }
                    }
                }
            }
        }
    }

    // 初始附加和清退中断都先排空已核验的系统断点，再脱离。
    if (!bp.retire && bp.installed) {
        if (const auto error = VerifyBoundSite(); error) RetireBreakpoint(error);
    }
    if (bp.retire) { FinishBreakpointEvent(disposition); return; }
    if (!ApplyContinue(disposition)) { return; }
    bp.cleanupDisposition.reset();
    if (bp.binding.address && !bp.retire) {
        bp.binding.state = NativeBreakpointState::Armed;
        bp.binding.stage = bp.binding.writeWatchBytes ? "data-write-breakpoint-armed" : "execution-breakpoint-armed";
        bp.binding.win32Error = ERROR_SUCCESS;
        latest_->status = NativeControlStatus::Released;
        latest_->outcome = {bp.binding.stage, ERROR_SUCCESS};
    }
}

void NativeDebugOwner::Impl::RequestBreakpointClose() {
    auto& bp = *breakpoint_;
    if (!bp.retire) { RetireBreakpoint({"breakpoint-close-requested", ERROR_SUCCESS}); }
    if (event_) {
        if (failedContinueSerial_ == eventSerial_) { return; }
        if (bp.cleanupDisposition) { FinishBreakpointEvent(*bp.cleanupDisposition); }
        else if (bp.retryEventContext) { ReceiveBreakpoint(*event_); }
        else if (bp.executionPage) { ReceiveBreakpoint(*event_); } // 页回读/重设NX失败仍持原事件，Close可重试恢复。
        return;
    }
    if (!attached_) { return; }
    if (bp.awaitingAttachBreak) { return; }
    if (bp.slots.empty() && !bp.interruptRequested && !bp.interruptTid &&
        (!bp.executionPage || !bp.executionPage->OwnsProtection())) { Detach(); return; }
    if (bp.interruptRequested || bp.interruptTid) { return; }
    if (const auto error = RequestInterrupt(); error) RequireRecovery(error);
}

NativeError NativeDebugOwner::Impl::RequestInterrupt() {
    auto& bp = *breakpoint_;
    if (event_ || bp.interruptRequested || bp.interruptTid || bp.interruptThread) return {};
    Handle interrupt(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_CREATE_THREAD, FALSE, bp.request.target.pid));
    if (!interrupt) return WinError("open-breakpoint-cleanup-process");
    if (!CompareObjectHandles(interrupt.Get(), process_.Get()))
        return {"breakpoint-cleanup-process-mismatch", ERROR_INVALID_DATA};
    if (!DebugBreakProcess(interrupt.Get())) return WinError("request-breakpoint-cleanup-event");
    bp.interruptRequested = true;
    attachDeadline_ = GetTickCount64() + kAttachDeadlineMs;
    return {};
}

bool NativeDebugOwner::Impl::IsRequestedInterrupt(const DEBUG_EVENT& event) const {
    return breakpoint_ && (breakpoint_->awaitingAttachBreak || breakpoint_->interruptRequested) &&
        event.dwThreadId == breakpoint_->interruptTid &&
        native_owner_detail::IsNativeRequestedInterrupt(process_.Get(), breakpoint_->interruptThread.Get(),
            event, breakpoint_->systemBreak.address);
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
    if (failedContinueSerial_ == eventSerial_) { return false; }
    if (!ContinueDebugEvent(event_->dwProcessId, event_->dwThreadId, disposition)) {
        const auto error = WinError("continue-debug-event");
        failedContinueSerial_ = eventSerial_;
        RequireRecovery(error);
        return false;
    }
    event_.reset();
    return true;
}

NativeControlResult NativeDebugOwner::Impl::Release(const ReleaseRequest& request, bool recover, bool internal) {
    const auto rejectRelease = [&](NativeError error, LedgerResult reason) {
        auto result = Reject(error, reason);
        result.releaseRequestId.reset();
        result.release.reset();
        return result;
    };
    if (!stepSubmitting_ && stepHistory_.contains(request.requestId)) {
        return rejectRelease({"release-id-belongs-to-step", ERROR_INVALID_PARAMETER}, LedgerResult::Conflict);
    }
    if (!internal && request.requestId.starts_with(kClosePrefix)) {
        return rejectRelease({"reserved-release-request-id", ERROR_INVALID_PARAMETER}, LedgerResult::InvalidEvidence);
    }
    const auto old = ledger_.QueryRelease(request.requestId, request.groupId);
    if (recover && !old) {
        return rejectRelease({"recover-requires-original-release-request", ERROR_NOT_FOUND}, LedgerResult::InvalidEvidence);
    }
    const auto decision = ledger_.BeginRelease(request, internal);
    if (decision.result == LedgerResult::Duplicate) {
        auto result = Query(request.groupId);
        result.ledgerResult = decision.result;
        result.releaseRequestId = request.requestId;
        result.release = old;
        if (recover && detachFailed_ && attached_ && !event_ && latest_ && latest_->groupId == request.groupId &&
            latest_->lastReleaseRequestId == request.requestId && result.release && result.release->receipt &&
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
        if (decision.result == LedgerResult::ReplayExpired) {
            return rejectRelease({"release-replay-expired", ERROR_NOT_FOUND}, decision.result);
        }
        if (decision.result == LedgerResult::ReadbackRequired) {
            auto result = Query(request.groupId);
            if (result.responsibility && result.responsibility->lastRequestId) {
                result = Query(request.groupId, *result.responsibility->lastRequestId);
            }
            result.ledgerResult = decision.result;
            return result;
        }
        if (decision.result == LedgerResult::Historical) {
            // A racing Close or Continue may have released this exact group. Read its winning receipt.
            auto result = Query(request.groupId);
            result.status = NativeControlStatus::Rejected;
            result.stage = "release-authorization-rejected";
            result.win32Error = ERROR_INVALID_PARAMETER;
            result.ledgerResult = decision.result;
            return result;
        }
        return rejectRelease({"release-authorization-rejected", ERROR_INVALID_PARAMETER}, decision.result);
    }
    const auto& attempt = *decision.effect;
    if (latest_) { latest_->lastReleaseRequestId = request.requestId; }
    const bool isBreakpoint = latest_ && (latest_->hit.has_value() || latest_->stepStop || latest_->manualPause);
    const DWORD expectedEvent = isBreakpoint ? EXCEPTION_DEBUG_EVENT : CREATE_PROCESS_DEBUG_EVENT;
    if (!event_ || !latest_ || event_->dwDebugEventCode != expectedEvent || eventSerial_ != request.event.serial ||
        event_->dwProcessId != latest_->request.pid || failedContinueSerial_ == eventSerial_) {
        const NativeError error{"release-native-event-unverified", ERROR_INVALID_DATA};
        (void)ledger_.RecordReleaseReceipt(attempt, {ReleaseResult::Indeterminate, error.code});
        if (latest_) { RequireRecovery(error); }
    } else {
        if (isBreakpoint) {
            if (const auto error = PrepareBreakpointResume(); error) {
                // 尚未调用 ContinueDebugEvent；确切事件仍在本线程，允许用新修订重试。
                const auto recorded = ledger_.RecordReleaseReceipt(attempt, {ReleaseResult::StillPending, error.code});
                RequireRecovery(recorded == LedgerResult::Applied ? error :
                    NativeError{"record-native-release-receipt", ERROR_INVALID_DATA});
                auto result = Query(request.groupId);
                result.ledgerResult = decision.result;
                return result;
            }
        }
        const auto continued = ApplyContinue(latest_->continuation);
        latest_->timing.continueReturnedQpc = ReadQpc();
        // A failed Win32 call supplies an error. There is no documented independent
        // readback of the exact pending event, so the same Continue cannot be resubmitted.
        const ReleaseReceipt receipt = continued ? ReleaseReceipt{ReleaseResult::Continued, std::nullopt} :
            ReleaseReceipt{ReleaseResult::Indeterminate, latest_->outcome.code};
        const auto recorded = ledger_.RecordReleaseReceipt(attempt, receipt);
        if (recorded != LedgerResult::Applied) {
            RequireRecovery({"record-native-release-receipt", ERROR_INVALID_DATA});
        } else if (continued) {
            latest_->status = NativeControlStatus::Released;
            latest_->outcome = {"continue-debug-event", ERROR_SUCCESS};
            if (!isBreakpoint || breakpoint_->retire) {
                Detach();
            } else {
                breakpoint_->binding.state = NativeBreakpointState::Armed;
                breakpoint_->binding.stage = breakpoint_->binding.writeWatchBytes ? "data-write-breakpoint-armed" : "execution-breakpoint-armed";
                breakpoint_->binding.win32Error = ERROR_SUCCESS;
            }
        }
    }
    auto result = Query(request.groupId);
    result.ledgerResult = decision.result;
    return result;
}

void NativeDebugOwner::Impl::Detach() {
    if (!attached_ || event_ || step_.Running() || step_.HasResources() || ledger_.UnresolvedNativeResponsibility()) { return; }
    if (breakpoint_ && (!breakpoint_->slots.empty() || breakpoint_->awaitingAttachBreak ||
        breakpoint_->interruptTid || breakpoint_->interruptRequested || breakpoint_->interruptThread ||
        (breakpoint_->executionPage && breakpoint_->executionPage->OwnsProtection()))) { return; }
    if (!DebugActiveProcessStop(latest_->request.pid)) {
        const auto error = WinError("debug-active-process-stop");
        detachFailed_ = true;
        RequireRecovery(error);
        return;
    }
    latest_->retirement = NativeRetirementReceipt{NativeRetirementKind::Detached, owner_, std::nullopt, std::nullopt};
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

void NativeDebugOwner::Impl::ContinueExitEvent(DWORD exitCode) {
    const NativeEventKey key{owner_.backendInstanceId, eventSerial_};
    if (const auto error = RestoreStep(true); error) { RequireRecovery(error); return; }
    if (!ApplyContinue(DBG_CONTINUE)) { return; }
    latest_->retirement = NativeRetirementReceipt{NativeRetirementKind::ExitEventContinued, owner_, key, exitCode};
    Complete(NativeControlStatus::Ended, {"exit-process-event-continued", ERROR_SUCCESS});
}

void NativeDebugOwner::Impl::Complete(NativeControlStatus status, NativeError outcome) {
    armedPauseHistory_.Complete(status == NativeControlStatus::Ended ? NativeArmedPauseState::Ended : NativeArmedPauseState::Cancelled,
        status == NativeControlStatus::Ended ? "armed-pause-process-ended" : "armed-pause-owner-detached", outcome.code);
    // Successful detach or a continued EXIT_PROCESS event is authoritative for the
    // attachment. Neither a signaled handle nor thread exit on its own clears it.
    attached_ = false;
    detachFailed_ = false;
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
        // Detach is gated on an empty slot and interrupt set. A continued process exit also retires them.
        if (breakpoint_->executionPage && status == NativeControlStatus::Ended) breakpoint_->executionPage->ProcessExited();
        breakpoint_->slots.clear();
        breakpoint_->awaitingAttachBreak = false;
        breakpoint_->interruptTid = 0;
        breakpoint_->interruptThread.Reset();
        breakpoint_->interruptRequested = false;
        breakpoint_->cleanupDisposition.reset();
        breakpoint_->retryEventContext = false;
        auto& binding = breakpoint_->binding;
        binding.state = status == NativeControlStatus::Rejected ? NativeBreakpointState::Rejected : NativeBreakpointState::Retired;
        binding.stage = outcome.stage;
        binding.win32Error = outcome.code;
        binding.enrolledThreads = 0;
        // A retired breakpoint binding cannot reattach. Its historical queries need no process handle.
        process_.Reset();
    }
    members_.clear();
    if (!ledger_.CanRetireLedger()) {
        RequireRecovery({"native-event-ledger-unresolved", ERROR_INVALID_DATA});
    }
}

NativeControlResult NativeDebugOwner::Impl::Close() {
    closing_ = true;
    armedPauseHistory_.Complete(NativeArmedPauseState::Cancelled, "armed-pause-owner-closing", ERROR_CANCELLED);
    if (step_.Running()) step_.RequestCancel();
    if (breakpoint_ && attached_ && !breakpoint_->retire) { RetireBreakpoint({"breakpoint-close-requested", ERROR_SUCCESS}); }
    if (const auto responsibility = ledger_.UnresolvedNativeResponsibility(); responsibility &&
        (responsibility->state == EventState::Held || responsibility->state == EventState::Retryable)) {
        const auto group = ledger_.Query(responsibility->groupId);
        if (!group) {
            RequireRecovery({"close-stop-group-unavailable", ERROR_INVALID_DATA});
            return Query({});
        }
        const auto released = Release({owner_, responsibility->groupId, responsibility->stopId, responsibility->event,
            std::string(kClosePrefix) + responsibility->groupId + "/" + std::to_string(group->stateRevision), group->stateRevision},
            false, true);
        if (released.status == NativeControlStatus::Rejected && !released.clean) {
            RequireRecovery({released.stage, released.win32Error});
        }
        auto result = Query({});
        result.ledgerResult = released.ledgerResult;
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

NativeControlResult NativeDebugOwner::PauseArmed(const OwnerIdentity& owner, const NativePauseRequest& request) {
    return impl_->Invoke([&] { return impl_->PauseArmed(owner, request); });
}

NativeControlResult NativeDebugOwner::QueryArmedPause(std::string_view requestId) {
    return impl_->Invoke([&] { return impl_->QueryArmedPause(requestId); });
}

NativeControlResult NativeDebugOwner::ArmBreakpoint(const NativeBreakpointRequest& request) {
    auto normalized = request; // Qt文件选择器和CLI都可提供正斜线；准入及幂等使用同一DOS路径表示。
    std::replace(normalized.modulePath.begin(), normalized.modulePath.end(), L'/', L'\\');
    return impl_->Invoke([&] { return impl_->ArmBreakpoint(normalized); });
}

// 输入调用方冻结的follow请求，在原调试线程串行运行；返回原转换结果或精确恢复责任。
NativeControlResult NativeDebugOwner::FollowPrivateExecution(const NativeExecutionFollowRequest& request)
{
    return impl_->Invoke([&] { return impl_->FollowPrivateExecution(request); });
}

NativeControlResult NativeDebugOwner::Query(std::string_view groupId, std::string_view releaseRequestId) {
    return impl_->Invoke([&] { return impl_->Query(groupId, releaseRequestId); });
}

NativeControlResult NativeDebugOwner::AddPrivateExecutionRange(const NativeExecutionRangeRequest& request) {
    return impl_->Invoke([&] { return impl_->AddPrivateExecutionRange(request); });
}

NativeControlResult NativeDebugOwner::Continue(const ReleaseRequest& request) {
    return impl_->Invoke([&] { return impl_->Release(request, false); });
}

NativeControlResult NativeDebugOwner::Recover(const ReleaseRequest& request) {
    return impl_->Invoke([&] { return impl_->Release(request, true); });
}

NativeControlResult NativeDebugOwner::Step(const NativeStepRequest& request) {
    return impl_->Invoke([&] { return impl_->Step(request); });
}

NativeControlResult NativeDebugOwner::QueryStep(std::string_view requestId) {
    return impl_->Invoke([&] { return impl_->QueryStep(requestId); });
}

NativeControlResult NativeDebugOwner::CancelStep(std::string_view requestId) {
    return impl_->Invoke([&] { return impl_->CancelStep(requestId); });
}

NativeControlResult NativeDebugOwner::Close() {
    return impl_->Invoke([&] { return impl_->Close(); });
}

} // namespace ks::cli::action_analyze::control
