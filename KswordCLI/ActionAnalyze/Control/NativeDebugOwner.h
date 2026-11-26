#pragma once

#include "StopLedger.h"
#include "NativeStep.h"

#include <memory>
#include <array>

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

// 默认映像/指针入口仅接纳当前宿主直接创建的合作子进程；显式映像附加仅用于普通执行。
// 模块必须已加载，路径为完整 DOS 路径。
// RVA 由调用方确认是指令边界；名称只解析区分大小写的 PE 导出，不接受转发导出。
// privateAddress入口允许显式授权的既有同用户AMD64进程，冻结单地址或privateRangeBytes指定的私有范围。
struct NativeBreakpointRequest {
    NativePauseRequest target;
    std::wstring modulePath;
    std::optional<std::uint32_t> rva;
    std::string exportName;
    std::uint32_t writeWatchBytes = 0; // 0 为执行停点。1、2、4、8 为合作映像的对齐可写数据范围。
    bool writeWatchPointerExport = false; // 数据导出内保存 AMD64 指针，实际关注其指向的私有区间。
    bool executePointerExport = false; // 数据导出内的 AMD64 指针选择私有可执行位置；writeWatchBytes 必须为 0。
    std::uint64_t privateAddress = 0; // 非零时与映像/导出/RVA/指针模式互斥；0宽度执行，1/2/4/8宽度写。
    std::uint64_t privateRangeBytes = 0; // 非零仅配privateAddress且writeWatchBytes=0；4096整数倍，最多64页，同私有分配。
    bool explicitImageAttachment = false; // 仅普通映像执行允许附加既有目标，仍须完整显式进程授权和准入。
    std::optional<std::string> imageSha256; // 冻结定义约束；必须核对实际装载事件文件，不能仅检查同名盘上文件。
    bool operator==(const NativeBreakpointRequest&) const = default;
};

enum class NativeBreakpointState { Installing, Armed, Held, Retiring, Retired, Rejected, RecoveryRequired };

struct NativeExecutionRange {
    std::uint64_t base = 0;
    std::uint64_t bytes = 0;
    std::uint64_t allocationBase = 0;
    bool operator==(const NativeExecutionRange&) const = default;
};

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
    std::uint64_t pointerExportAddress = 0; // 非零表示间接绑定；address为硬件关注地址或rangeBytes页起点。
    std::uint64_t allocationBase = 0; // 绑定时回读的私有分配，不代表操作系统提供分配代次。
    std::uint64_t regionBase = 0;
    std::uint64_t regionBytes = 0;
    std::uint32_t regionProtection = 0; // 初始冻结保护；页模式临时NX不改写此来源。
    bool executePointerExport = false; // 间接执行绑定；不表示数据写入关注或分配代次证明。
    bool privateExecutionFollowAvailable = false; // 初次写入绑定冻结了同址RWX候选；仍须当前停点完整验证。
    bool explicitPrivateAddress = false; // 明确私有地址入口，无映像指针选择器，不证明分配代次。
    std::uint64_t rangeBytes = 0; // 0为单地址DR0；非零为整个NX范围字节数，address是4KiB对齐起点。
    std::vector<NativeExecutionRange> executionRanges; // 初始及成功新增范围；address/rangeBytes始终保留初始值。
    std::optional<std::string> imageSha256; // 原装载事件文件核验通过后的散列，不认证运行时页内容。
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

enum class NativeStopReason { None, Breakpoint, NativeStep, ManualPause };
// Preempted保留抢先到达的真实命中；该请求发出的助手中断仍由原owner排空。
enum class NativeArmedPauseState { Pending, Held, Preempted, Rejected, Cancelled, Ended, RecoveryRequired };

struct NativeArmedPauseReceipt {
    OwnerIdentity owner;
    NativePauseRequest request;
    NativeArmedPauseState state = NativeArmedPauseState::Pending;
    std::optional<std::string> groupId;
    std::optional<NativeEventKey> event;
    const char* stage = "armed-pause-requested";
    std::uint32_t win32Error = 0;
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

// 真实命中/步进事件形成时冻结，Query不重新读取已运行线程；零寄存器值仍是有效数据。
struct NativeStopRegisters {
    ThreadIdentity thread;
    std::uint64_t rip = 0;
    std::uint64_t rax = 0;
    std::uint64_t rsp = 0;
    std::uint64_t rbx = 0;
    std::uint64_t rcx = 0;
    std::uint64_t rdx = 0;
    std::uint64_t rbp = 0;
    std::uint64_t rsi = 0;
    std::uint64_t rdi = 0;
    std::uint64_t r8 = 0;
    std::uint64_t r9 = 0;
    std::uint64_t r10 = 0;
    std::uint64_t r11 = 0;
    std::uint64_t r12 = 0;
    std::uint64_t r13 = 0;
    std::uint64_t r14 = 0;
    std::uint64_t r15 = 0;
    std::uint64_t eflags = 0; // 原CONTEXT的32位EFlags零扩展，不读写目标标志。
};

struct NativeStopRegisterField {
    const char* name; // 三端回执共用的小写寄存器名。
    const char* conditionField; // 条件编译器使用的完整稳定字段ID。
    std::uint64_t NativeStopRegisters::* value; // 只读取原冻结快照中的对应成员。
};

// 名称按ASCII排序；条件、CLI及两端字段详情消费同一份冻结寄存器目录。
inline constexpr std::array<NativeStopRegisterField, 18> NativeStopRegisterFields{{
    {"eflags", "stop.thread.eflags", &NativeStopRegisters::eflags},
    {"r10", "stop.thread.r10", &NativeStopRegisters::r10},
    {"r11", "stop.thread.r11", &NativeStopRegisters::r11},
    {"r12", "stop.thread.r12", &NativeStopRegisters::r12},
    {"r13", "stop.thread.r13", &NativeStopRegisters::r13},
    {"r14", "stop.thread.r14", &NativeStopRegisters::r14},
    {"r15", "stop.thread.r15", &NativeStopRegisters::r15},
    {"r8", "stop.thread.r8", &NativeStopRegisters::r8},
    {"r9", "stop.thread.r9", &NativeStopRegisters::r9},
    {"rax", "stop.thread.rax", &NativeStopRegisters::rax},
    {"rbp", "stop.thread.rbp", &NativeStopRegisters::rbp},
    {"rbx", "stop.thread.rbx", &NativeStopRegisters::rbx},
    {"rcx", "stop.thread.rcx", &NativeStopRegisters::rcx},
    {"rdi", "stop.thread.rdi", &NativeStopRegisters::rdi},
    {"rdx", "stop.thread.rdx", &NativeStopRegisters::rdx},
    {"rip", "stop.thread.rip", &NativeStopRegisters::rip},
    {"rsi", "stop.thread.rsi", &NativeStopRegisters::rsi},
    {"rsp", "stop.thread.rsp", &NativeStopRegisters::rsp},
}};

struct NativeStopTiming {
    std::uint64_t qpcFrequency = 0;
    std::optional<std::uint64_t> attachSubmittedQpc;
    std::optional<std::uint64_t> eventObservedQpc;
    std::optional<std::uint64_t> continueReturnedQpc;
};

enum class NativeRetirementKind { Detached, ExitEventContinued };

struct NativeRetirementReceipt {
    NativeRetirementKind kind;
    OwnerIdentity owner;
    std::optional<NativeEventKey> exitEvent;
    std::optional<std::uint32_t> exitCode;
    bool operator==(const NativeRetirementReceipt&) const = default;
};

struct NativeRecoveryFailure {
    const char* stage;
    std::uint32_t win32Error;
    OwnerIdentity owner;
    std::optional<NativeEventKey> pendingEvent;
    std::optional<std::string> releaseRequestId;
};

// 显式把当前私有写关注切换为同址执行关注；stop仅作授权，不向释放账本提交Continue。
struct NativeExecutionFollowRequest {
    ReleaseRequest stop; // 完整owner/epoch/事件/修订及独立follow/N请求ID。
    std::uint64_t address = 0; // 必须与原写入地址及冻结执行候选完全相同。
    bool operator==(const NativeExecutionFollowRequest&) const = default;
};

// 转换回执不是执行证据，也不证明线程继续过；源事件仍然是DataWriteObserved。
struct NativeExecutionFollowReceipt {
    NativeExecutionFollowRequest request; // 本次请求的原始内容，供重放冲突核对。
    bool converted = false; // 所有活线程的DR0类型均已读回确认为执行。
    bool rollbackComplete = true; // 失败后原写关注是否全部恢复确认。
    const char* stage = "private-execution-follow-idle"; // 稳定诊断，非用户可见翻译文本。
    std::uint32_t win32Error = 0; // 首次失败的原生错误码。
};

struct NativeExecutionRangeRequest {
    ReleaseRequest stop; // 当前完整Held授权；独立range/N，不提交释放账本。
    std::uint64_t address = 0;
    std::uint64_t bytes = 0;
    bool operator==(const NativeExecutionRangeRequest&) const = default;
};

struct NativeExecutionRangeReceipt {
    NativeExecutionRangeRequest request;
    std::uint64_t stateRevision = 0; // 本次操作核验的当前停止组修订；操作不改原事件/修订。
    bool added = false;
    bool rollbackComplete = true;
    const char* stage = "private-execution-range-idle";
    std::uint32_t win32Error = 0;
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
    std::optional<NativeStepReceipt> step;
    NativeStopTiming timing;
    bool attached = false;
    bool clean = true; // no native obligations or attachment, not proof the target executed
    // OS evidence for the end of this attachment; admission refusal has no such receipt.
    std::optional<NativeRetirementReceipt> retirement;
    // First unresolved native failure for this record, retained even if a later Close succeeds.
    std::optional<NativeRecoveryFailure> firstRecoveryFailure;
    std::optional<NativeExecutionFollowReceipt> executionFollow; // 原owner最近转换结果，不改写原写入命中。
    std::optional<NativeStopRegisters> registers; // 与该记录精确事件及冻结线程身份相同，读取失败为空。
    std::optional<NativeExecutionRangeReceipt> executionRange;
    NativeStopReason stopReason = NativeStopReason::None;
    std::optional<NativeArmedPauseReceipt> armedPause; // 独立请求回执；只有Held+ManualPause才是本次主动中断。
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
    // 复用本owner已武装的调试附加；pause/N独立幂等流水，提交不等于已停止。
    // ManualPause无origin phase/hit/registers，不授予Step资格；Continue/快照沿原事件责任。
    [[nodiscard]] NativeControlResult PauseArmed(const OwnerIdentity& owner, const NativePauseRequest& request);
    [[nodiscard]] NativeControlResult QueryArmedPause(std::string_view requestId);
    // 仅接受一个持续绑定。命中历史滚动保留，Continue 采用递增的 continue/<序号> ID。
    // Query 确认接纳、武装或命中；Continue 不脱离；Close 清退整个绑定。
    [[nodiscard]] NativeControlResult ArmBreakpoint(const NativeBreakpointRequest& request);
    // 仅修改原owner既有DR0类型；输入当前完整写入停点，输出转换/回滚回执，不Continue。
    [[nodiscard]] NativeControlResult FollowPrivateExecution(const NativeExecutionFollowRequest& request);
    [[nodiscard]] NativeControlResult AddPrivateExecutionRange(const NativeExecutionRangeRequest& request);
    [[nodiscard]] NativeControlResult Query(std::string_view groupId = {}, std::string_view releaseRequestId = {});
    [[nodiscard]] NativeControlResult Continue(const ReleaseRequest& request);
    [[nodiscard]] NativeControlResult Recover(const ReleaseRequest& request);
    [[nodiscard]] NativeControlResult Step(const NativeStepRequest& request);
    [[nodiscard]] NativeControlResult QueryStep(std::string_view requestId);
    [[nodiscard]] NativeControlResult CancelStep(std::string_view requestId);
    [[nodiscard]] NativeControlResult Close();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ks::cli::action_analyze::control
