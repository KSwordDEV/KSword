#pragma once

#include "NativeDebugOwner.h"

#include <span>

namespace ks::cli::action_analyze::control {


// 进程集合按真实实例固定。历史图中的 PID 提示不能直接转换为本类型。
struct ProcessGroupTarget {
    std::uint32_t pid = 0; // 用户明确选择的进程号。
    std::uint64_t creationFileTime = 0; // 与 PID 一起核对原始进程对象。
    bool operator==(const ProcessGroupTarget&) const = default;
};

// 继续请求必须完整复制本次成员的令牌，不能只提供可显示的 stopId。
struct ProcessGroupStop {
    ProcessGroupTarget target; // 该停点所属的已冻结进程实例。
    std::string groupId; // 原生账本中的组标识。
    std::string stopId; // 本次原生事件的停点标识。
    NativeEventKey event; // 唯一后端事件身份。
    std::uint64_t stateRevision = 0; // 查询到的成员状态修订。
    bool operator==(const ProcessGroupStop&) const = default;
};

enum class ProcessGroupState { Idle, Ready, Active, HeldPartial, HeldComplete, Closing, Closed, RecoveryRequired };
enum class ProcessGroupAction { Pause, Continue, Recover };

struct ProcessGroupMember {
    ProcessGroupTarget target; // 始终保留加入集合时的目标身份。
    std::optional<NativeControlResult> control; // 未提交原生暂停前为空。
    std::optional<ProcessGroupStop> stop; // 仅确实持有可释放原生事件时提供。
    bool clean = true; // 该成员当前是否已无自有原生责任和附加。
};

struct ProcessGroupOutcome {
    ProcessGroupTarget target; // 请求时冻结的成员，不随当前界面选择变化。
    NativeControlResult control; // 对应操作的原始成员回执，重复请求保持此值。
};

struct ProcessGroupOperation {
    std::string requestId; // 组层独立请求 ID，最多保留最近 128 项。
    ProcessGroupAction action = ProcessGroupAction::Pause; // 票据所属操作。
    std::vector<ProcessGroupOutcome> outcomes; // 真实执行顺序的结果；部分失败保留成功成员。
    LedgerResult ledgerResult = LedgerResult::Applied; // 首次准入结论，重放后也不变。
    const char* stage = "process-group-operation-submitted"; // 首次拒绝的原始诊断。
    std::uint32_t win32Error = 0; // 首次准入错误，独立于当前集合状态。
};

struct ProcessGroupResult {
    ProcessGroupState state = ProcessGroupState::Idle; // 当前集合的真实汇总，不代表同时冻结。
    const char* stage = "process-group-idle"; // 组层准入或回读诊断。
    std::uint32_t win32Error = 0; // 最近组层操作的错误，不替代成员错误。
    LedgerResult ledgerResult = LedgerResult::Applied; // 重放、冲突、过期与正常结果分别回读。
    bool clean = true; // 全部成员无附加及未决责任才为真。
    std::vector<ProcessGroupMember> members; // 固定配置顺序的当前状态。
    std::optional<ProcessGroupOperation> operation; // 本次操作或精确重放的不可变回执。
};

// 本端串行控制器；每个目标复用唯一 NativeDebugOwner，不使用 SuspendThread 维护第二套账本。
// Configure 只固定并核对目标，不暂停。Pause/Continue 可传全集或明确子集；不自动跟随子进程。
// 普通 Pause 的 Continue 将恢复并脱离；再次暂停创建新的原生所有者，旧令牌不迁移。
class OwnedProcessGroup final {
public:
    explicit OwnedProcessGroup(OwnerIdentity identity);
    ~OwnedProcessGroup();
    OwnedProcessGroup(const OwnedProcessGroup&) = delete;
    OwnedProcessGroup& operator=(const OwnedProcessGroup&) = delete;

    // 初始化一次：全部目标通过身份核对后才发布集合；没有任何调试副作用。
    [[nodiscard]] ProcessGroupResult Configure(std::vector<ProcessGroupTarget> targets,
        bool explicitlyAuthorized, NativeTargetDisposition disposition);
    // requestId 在组层共享命名空间；格式正确的拒绝也占用票据，同 ID 换内容不能再执行。
    [[nodiscard]] ProcessGroupResult Pause(std::string requestId, std::span<const ProcessGroupTarget> targets);
    // 先核对全部精确令牌再释放；系统调用阶段部分失败按成员保留。
    [[nodiscard]] ProcessGroupResult Continue(std::string requestId, std::span<const ProcessGroupStop> stops);
    // 按原继续票据重试原生 Recover；不创建新的 ContinueDebugEvent 责任。
    [[nodiscard]] ProcessGroupResult Recover(std::string_view requestId);
    [[nodiscard]] ProcessGroupResult Query(); // 回读全部原所有者，保留恢复未决状态。
    [[nodiscard]] ProcessGroupResult Close(); // 关闭准入，逐成员清退；未完成时继续保留本对象。

private:
    class Impl;
    std::unique_ptr<Impl> impl_; // 固定集合、原生所有者与有界原操作回执。
};

} // namespace ks::cli::action_analyze::control
