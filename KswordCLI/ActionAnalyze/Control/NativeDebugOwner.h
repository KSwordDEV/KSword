#pragma once

#include "StopLedger.h"

#include <memory>

namespace ks::cli::action_analyze::control {

// 一个 owner 只绑定一个显式授权的原生 AMD64 进程实例；不承诺 owner 异常退出后的恢复。
enum class NativeTargetDisposition { Unspecified, ResumeAndDetach };

struct NativePauseRequest {
    std::string requestId;
    std::uint32_t pid = 0;
    std::uint64_t processCreationTime = 0; // Windows FILETIME, unsigned 100 ns ticks
    bool explicitlyAuthorized = false;
    NativeTargetDisposition disposition = NativeTargetDisposition::Unspecified;
    bool operator==(const NativePauseRequest&) const = default;
};

// 断点仅接纳当前宿主直接创建的合作子进程。模块必须已加载，路径为完整 DOS 路径。
// RVA 由调用方确认是指令边界；名称只解析区分大小写的 PE 导出，不接受转发导出。
struct NativeBreakpointRequest {
    NativePauseRequest target;
    std::wstring modulePath;
    std::optional<std::uint32_t> rva;
    std::string exportName;
    std::uint32_t writeWatchBytes = 0; // 0 为执行停点。1、2、4、8 为合作映像的对齐可写数据范围。
    bool operator==(const NativeBreakpointRequest&) const = default;
};

enum class NativeBreakpointState { Installing, Armed, Held, Retiring, Retired, Rejected, RecoveryRequired };

struct NativeBreakpointBinding {
    std::string requestId;
    NativeBreakpointState state = NativeBreakpointState::Installing;
    std::uint64_t moduleBase = 0;
    std::uint64_t address = 0;
    std::uint32_t rva = 0;
    std::size_t enrolledThreads = 0;
    const char* stage = "breakpoint-installing";
    std::uint32_t win32Error = 0;
    std::uint32_t writeWatchBytes = 0; // 当前绑定的实际关注宽度。
};

// 一次写入停点时读到的变化区间，供三端对账。掩码第 n 位对应起点后第 n 字节。
struct NativeDataChange {
    std::uint32_t watchedBytes = 0;
    std::uint32_t changedByteMask = 0;
    std::uint64_t enrolledAfterStop = 0; // 首次停点前登记为 0，之后登记使用彼时的停点序号。
};

struct NativeBreakpointHit {
    std::string requestId;
    std::uint64_t address = 0;
    std::optional<NativeDataChange> dataChange; // 执行停点为空，写入停点只在实际字节变化时发布。
};

enum class NativeControlStatus {
    Idle, Accepted, Held, Released, Detached, Ended, ClosePending, Closed,
    Rejected, RecoveryRequired
};

struct NativePendingEvent {
    NativeEventKey event;
    std::uint32_t pid = 0;
    std::uint32_t tid = 0;
    std::uint32_t eventCode = 0;
    std::optional<std::uint32_t> exceptionCode;
    std::optional<bool> exceptionFirstChance;
    bool ledgerOwned = false;
    bool continuationIndeterminate = false; // last observed event retained after a failed ContinueDebugEvent
};

struct NativeFrozenThread {
    ThreadIdentity identity;
    std::uint32_t tid = 0;
    std::uint64_t creationTime = 0; // Windows FILETIME, unsigned 100 ns ticks
};

struct NativeStopTiming {
    std::uint64_t qpcFrequency = 0;
    std::optional<std::uint64_t> attachSubmittedQpc;
    std::optional<std::uint64_t> eventObservedQpc;
    std::optional<std::uint64_t> continueReturnedQpc;
};

struct NativeControlResult {
    NativeControlStatus status = NativeControlStatus::Idle;
    LedgerResult ledgerResult = LedgerResult::Applied;
    const char* stage = "idle";
    std::uint32_t win32Error = 0;
    std::string pauseRequestId;
    std::string processInstanceId;
    std::uint32_t pid = 0;
    std::uint64_t processCreationTime = 0;
    std::optional<StopGroupSnapshot> group;
    std::vector<NativeFrozenThread> frozenThreads;
    std::optional<EventResponsibility> responsibility;
    std::optional<NativePendingEvent> pending;
    std::optional<ReleaseRecord> release;
    std::optional<std::string> releaseRequestId;
    std::optional<NativeBreakpointBinding> breakpoint;
    std::optional<NativeBreakpointHit> breakpointHit;
    NativeStopTiming timing;
    bool attached = false;
    bool clean = true; // no native obligations or attachment, not proof the target executed
};

// May be called from the CLI controller. Commands run serially on the dedicated
// debug thread with no callbacks, I/O, or target-side acknowledgments. Pause
// accepts an attachment attempt; use Query to observe an actual pending event.
// Continue validates the full ledger request. Recover requires an earlier release
// request and returns its receipt or retries a provably separate detach failure.
// An indeterminate Continue stays visible for the owner. Close stops admission
// and may return before cleanup completes. The debug thread exits after a clean
// close, and the owner still serves receipt queries. Keep an unclean owner alive
// to query or retry verified cleanup. Destruction waits for the debug thread and
// may block while an OS responsibility remains unresolved.
class NativeDebugOwner final {
public:
    explicit NativeDebugOwner(OwnerIdentity identity);
    ~NativeDebugOwner();
    NativeDebugOwner(const NativeDebugOwner&) = delete;
    NativeDebugOwner& operator=(const NativeDebugOwner&) = delete;

    [[nodiscard]] NativeControlResult Pause(const NativePauseRequest& request);
    // 仅接受一个持续绑定。命中历史滚动保留，Continue 采用递增的 continue/<序号> ID。
    // Query 确认接纳、武装或命中；Continue 不脱离；Close 清退整个绑定。
    [[nodiscard]] NativeControlResult ArmBreakpoint(const NativeBreakpointRequest& request);
    [[nodiscard]] NativeControlResult Query(std::string_view groupId = {}, std::string_view releaseRequestId = {});
    [[nodiscard]] NativeControlResult Continue(const ReleaseRequest& request);
    [[nodiscard]] NativeControlResult Recover(const ReleaseRequest& request);
    [[nodiscard]] NativeControlResult Close();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ks::cli::action_analyze::control
