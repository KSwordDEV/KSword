#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "NativeStep.h"
#include <array>

namespace ks::cli::action_analyze::control {

class NativePrivateExecutionPage;

// The verified meaning of the native event that ended a step.
enum class NativeStepEventKind {
    None,
    StepCompleted,        // our own TF/DR1 single-step reached the destination
    CompetingBreakpoint,  // the user's own DR0 breakpoint fired before that
    ApplicationException, // the target raised an unrelated exception
    SelectedThreadExit,
    ProcessExit,
};

struct NativeStepError {
    const char* stage = "step-ready";
    DWORD code = ERROR_SUCCESS;
    explicit operator bool() const noexcept { return code != ERROR_SUCCESS; }
};

// 原debug事件内读取的一条AMD64指令；长度只描述取指跨度，不预测执行后的RIP。
struct NativeInstructionFetch {
    std::uint64_t address = 0;
    std::array<std::uint8_t, 15> bytes{};
    std::size_t length = 0;
};

// Owned by NativeDebugOwner's existing debug thread. No second debug loop,
// target code patching, detached worker, or target-side cleanup dependency.
class NativeStepRuntime final {
public:
    NativeStepRuntime() = default;
    ~NativeStepRuntime();
    NativeStepRuntime(const NativeStepRuntime&) = delete;
    NativeStepRuntime& operator=(const NativeStepRuntime&) = delete;

    [[nodiscard]] NativeStepError Prepare(HANDLE process, HANDLE selected, const NativeStepRequest& request,
        const std::vector<HANDLE>& peers, const NativePrivateExecutionPage* executionRange = nullptr);
    // 页Continue只取得TF/同伴责任；页尾长度仅用于开放取指页，不预测下一IP。空ID不发布用户step回执。
    [[nodiscard]] NativeStepError PreparePageAdvance(HANDLE process, HANDLE selected, NativeStepRequest request,
        const std::vector<HANDLE>& peers, const NativePrivateExecutionPage* executionRange = nullptr);
    [[nodiscard]] static NativeStepError DecodeInstructionFetch(HANDLE process, std::uint64_t rip, NativeInstructionFetch& fetch);
    // 用户Over/Out的DR1继续有效，临时叠加一条TF供页关注重设NX。
    [[nodiscard]] NativeStepError ArmPageTrap();
    // 原owner已先重设NX；仅消费所选线程本端BS，onlyAdvance表示用户步进尚未到DR1终点。
    [[nodiscard]] NativeStepError FinishPageTrap(const DEBUG_EVENT& event, bool& onlyAdvance);
    // 原owner收到事件后、重设页保护或写回上下文前冻结所选线程现场；Observe消费同一份原值。
    [[nodiscard]] NativeStepError CaptureEventContext(const DEBUG_EVENT& event);
    [[nodiscard]] bool PageTrapOwned() const noexcept { return pageTrapOwned_; }
    // 原owner在当前持有事件中枚举冻结对象；允许早于该对象CREATE_THREAD事件分派。
    [[nodiscard]] NativeStepError Enroll(HANDLE thread);
    // 原owner当前尚未Continue的CREATE_THREAD事件，核验事件与强句柄后复用同套登记。
    [[nodiscard]] NativeStepError EnrollCreated(const DEBUG_EVENT& event);
    // eventThread为原owner按当前退出事件保留的强句柄；省略时在事件仍待处理期间解析。
    [[nodiscard]] NativeStepError RetireExitedThread(const DEBUG_EVENT& event, HANDLE eventThread = nullptr);
    [[nodiscard]] NativeStepError Restore(bool processExited = false, const DEBUG_EVENT* heldEvent = nullptr);
    // Called while the event is pending, before deciding its continuation.
    // A true return requires a new stop ledger entry (except process exit).
    [[nodiscard]] bool Observe(const DEBUG_EVENT& event, bool cancellationBreak, bool ownsDr0 = true);
    // Verified meaning of the event that ended the last observed step.
    [[nodiscard]] NativeStepEventKind EventKind() const noexcept { return eventKind_; }
    // Debug status register as read at the verified single-step event, before
    // any context rewrite. Debug status bits are lost by a later write.
    [[nodiscard]] std::uint64_t ObservedDr6() const noexcept { return observedDr6_; }
    [[nodiscard]] DWORD ObservedFlags() const noexcept { return observedFlags_; }
    [[nodiscard]] std::uint64_t ObservedDr7() const noexcept { return observedDr7_; }
    void RequestCancel() noexcept { cancelRequested_ = true; }
    void RequestTimeout() noexcept { timeoutRequested_ = true; cancelRequested_ = true; }
    [[nodiscard]] bool CancellationRequested() const noexcept { return cancelRequested_; }
    [[nodiscard]] bool Running() const noexcept { return running_; }
    [[nodiscard]] bool HasResources() const noexcept;
    [[nodiscard]] const NativeStepReceipt& Receipt() const noexcept { return receipt_; }
    [[nodiscard]] DWORD Disposition() const noexcept { return disposition_; }
    void MarkFailure(NativeStepError error);
    void BindStop(std::string groupId, NativeEventKey event);

private:
    NativeStepError PrepareImpl(HANDLE process, HANDLE selected, const NativeStepRequest& request,
        const std::vector<HANDLE>& peers, bool tfOnly, const NativePrivateExecutionPage* executionRange);
    struct ThreadObjectIdentity {
        DWORD processId = 0; // 强句柄查询的所属进程，不接受外部传入的TID作为身份。
        DWORD threadId = 0;
        std::uint64_t creationTime = 0;
        bool operator==(const ThreadObjectIdentity&) const = default;
    };
    struct Hold {
        HANDLE thread;
        bool debt;
        bool conflicted = false; // Resume返回0：本端暂停已不在可证明状态，不再盲目重减其它人的计数。
        ThreadObjectIdentity identity; // 与保留句柄绑定；TID复用不覆盖旧对象和旧债务。
    };
    static NativeStepError ReadThreadIdentity(HANDLE thread, ThreadObjectIdentity& identity);
    NativeStepError HoldPeer(HANDLE thread, bool preparing);
    NativeStepError RestoreSelectedContext();
    NativeStepError ReleaseHold(HANDLE thread, bool& debt, bool& conflicted, bool processExited, const char* stage);
    // 上下文恢复失败时的逐对象兜底：只按对象自身signaled退出证据免除债务，存活对象保留债务。
    static void DischargeExitedHold(HANDLE thread, bool& debt, bool& conflicted, NativeStepError& first);
    NativeStepError Arm(CONTEXT context, std::optional<std::uint64_t> destination);
    NativeStepError Read(std::uint64_t address, void* bytes, std::size_t count) const;
    NativeStepError Destination(const CONTEXT& context, std::optional<std::uint64_t>& destination);
    NativeStepError Executable(std::uint64_t address) const;
    NativeStepError CheckPageTrapInstruction(std::uint64_t address) const;
    NativeStepReceipt receipt_;
    HANDLE process_ = nullptr; // borrowed from owner; attachment outlives all step resources
    const NativePrivateExecutionPage* executionRange_ = nullptr; // 同owner冻结范围，寿命长于本次step。
    HANDLE selected_ = nullptr; // duplicate of the exact strong thread object
    ThreadObjectIdentity selectedIdentity_;
    std::vector<Hold> peers_;
    DWORD64 originalDr1_ = 0;
    DWORD64 originalDr7_ = 0;
    DWORD originalFlags_ = 0;
    std::uint64_t expectedSp_ = 0;
    bool contextOwned_ = false;
    bool pageTrapOwned_ = false; // DR1步进叠加TF，恢复时须额外归还该位。
    bool running_ = false;
    bool cancelRequested_ = false;
    bool timeoutRequested_ = false;
    bool selectedExited_ = false;
    bool selectedEventStopped_ = true; // false表示事件来自取消助手/其它线程，CONTROL修改须自行暂停selected。
    bool selectedSuspendDebt_ = false; // 在非所选线程的取消事件期间取得，保护控制现场读改写。
    bool selectedSuspendConflict_ = false;
    NativeStepEventKind eventKind_ = NativeStepEventKind::None;
    std::uint64_t observedDr6_ = 0;
    DWORD observedFlags_ = 0; // 异常交付时EFLAGS，区别于归档的入口取指异常现场。
    std::uint64_t observedDr7_ = 0; // 同一事件中的实际调试槽配置，不从恢复后现场推断。
    std::optional<CONTEXT> eventContext_; // 当前未Continue事件的原始线程现场，每次Receive重新冻结。
    DWORD disposition_ = DBG_CONTINUE;
    // Proof from this owner's immediately preceding CALL single-step. Valid only
    // at the observed callee entry and exact stack pointer/return-slot contents.
    struct EntryFrame { std::uint64_t ip; std::uint64_t sp; std::uint64_t returnIp; ThreadIdentity thread; };
    std::optional<EntryFrame> frame_;
    std::optional<std::uint64_t> callReturn_;
};

} // namespace ks::cli::action_analyze::control
