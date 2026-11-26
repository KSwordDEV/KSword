#pragma once

#include "OwnedDataWatchSession.h"

#include <span>

namespace ks::cli::action_analyze::control {

inline constexpr std::size_t kOwnedExecutionGroupLimit = 16;

// 一个显式进程实例只接一份执行站点。条件与站点均在 Start 时按值冻结。
struct ExecutionGroupSite {
    std::uint32_t pid = 0;
    std::uint64_t creationFileTime = 0;
    std::wstring modulePath; // 普通模块绝对 DOS 路径，与私有地址互斥。
    std::optional<std::uint32_t> rva;
    std::string exactExport; // 与 RVA 二选一，区分大小写的 PE 导出。
    std::uint64_t address = 0; // 私有执行地址；rangeBytes=0 时使用单地址执行断点。
    std::uint64_t rangeBytes = 0; // 非零时沿原 owner 的私有 NX 范围机制。
    std::wstring conditionSource; // 冻结原文，供端侧显示，不重新编译或热替换。
    Ksword::ActionAnalyze::Rules::PreparedPredicate condition;
};

enum class ExecutionGroupState { Idle, Active, HeldPartial, HeldComplete, PartialFailure, RecoveryRequired, Closing, Closed };
enum class ExecutionGroupAction { Start, Continue, Step, CancelStep, Close, Pause, AddRange };

struct ExecutionGroupMember {
    ExecutionGroupSite site;
    OwnerIdentity owner; // 成员原生身份，绝不使用集合 ID 代替。
    NativeControlResult control; // 当前原会话回读，保留全部停止、步进和恢复字段。
    DataWatchConditionReport condition;
    bool attachAccepted = false; // 初次附加准入结果，不冒充后续 Armed 或命中。
};

struct ExecutionGroupOutcome {
    std::uint32_t pid = 0;
    std::uint64_t creationFileTime = 0;
    NativeControlResult control; // 本操作的原始回执，不被后续 Query 覆盖。
    bool actionAttempted = true; // 是否实际调用原session方法；already状态绝不冒充释放回执。
    const char* disposition = "action-attempted"; // action-attempted / already-held / already-running。
};

// 混合集合使用明确原owner与完整控制快照；运行成员无需旧stop，不允许按裸PID补票。
struct ExecutionGroupSessionEntry {
    OwnerIdentity owner; // 原成员sample/session/epoch/backend，必须与当前原session完全相同。
    NativeControlResult control; // 点击时显示值，包括活绑定或精确Held停止票据。
};

struct ExecutionGroupOperation {
    ExecutionGroupAction action = ExecutionGroupAction::Start;
    bool admitted = false; // 批次前置核对通过；不代表每个原生调用成功。
    const char* stage = "execution-group-idle";
    std::uint32_t win32Error = 0;
    std::vector<ExecutionGroupOutcome> outcomes; // 全部请求成员，分别标明实际动作与already状态。
};

struct ExecutionGroupResult {
    std::string collectionId; // 本集合身份，与各成员 stop groupId 完全独立。
    ExecutionGroupState state = ExecutionGroupState::Idle;
    bool clean = true;
    std::vector<ExecutionGroupMember> members; // Start 固定顺序，不隐式增加进程或后代。
    std::optional<ExecutionGroupOperation> operation; // 最近一次操作回执，与当前状态分别报告。
};

// 全部方法和销毁均由调用方同一串行 worker 执行。每成员一份原 OwnedDataWatchSession。
// Query 是逐成员回读，不证明同时冻结。未 clean 的 Close 必须保留对象继续 Query/Close。
class OwnedExecutionGroup final {
public:
    OwnedExecutionGroup();
    ~OwnedExecutionGroup();
    OwnedExecutionGroup(const OwnedExecutionGroup&) = delete;
    OwnedExecutionGroup& operator=(const OwnedExecutionGroup&) = delete;

    [[nodiscard]] ExecutionGroupResult Start(std::vector<ExecutionGroupSite> sites, bool explicitlyAuthorized,
        NativeTargetDisposition disposition, std::string_view sampleId = {});
    [[nodiscard]] ExecutionGroupResult Query();
    // 主动暂停仍使用各成员原执行owner；输入活会话完整显示值，不要求已有stop。
    // 全体预核对通过后逐成员Pause，接纳不等于已持有ManualPause停点。
    [[nodiscard]] ExecutionGroupResult Pause(std::span<const NativeControlResult> displayedSessions, bool all);
    [[nodiscard]] ExecutionGroupResult Pause(std::span<const ExecutionGroupSessionEntry> displayedSessions, bool all);
    // all=true提供固定全集的完整成员快照；精确Held继续，已Armed运行者明确already-running。
    // 全部成员先通过身份/事件/修订核对才调用任一 Continue，调用阶段仍可能部分失败。
    [[nodiscard]] ExecutionGroupResult Continue(std::span<const NativeControlResult> displayedStops, bool all);
    [[nodiscard]] ExecutionGroupResult Continue(std::span<const ExecutionGroupSessionEntry> displayedSessions, bool all);
    [[nodiscard]] ExecutionGroupResult Step(const NativeControlResult& displayedStop, NativeStepMode mode);
    [[nodiscard]] ExecutionGroupResult CancelStep(const NativeControlResult& displayedStep);
    // 输入唯一成员的完整Held快照及明确整页范围，沿原session追加NX页；不继续或改变初始站点。
    [[nodiscard]] ExecutionGroupResult AddRange(const NativeControlResult& displayedStop,
        std::uint64_t address, std::uint64_t bytes);
    [[nodiscard]] ExecutionGroupResult Close();

    // 端侧可用于资格显示；实际操作还会回读并再次核对，不接受单独 stopId 或历史索引。
    [[nodiscard]] static bool Matches(const NativeControlResult& displayed, const NativeControlResult& current);
    [[nodiscard]] static bool MatchesStep(const NativeControlResult& displayed, const NativeControlResult& current);
    [[nodiscard]] static bool MatchesPause(const NativeControlResult& displayed, const NativeControlResult& current);
    [[nodiscard]] static bool CanPauseMember(const ExecutionGroupMember& member); // 精确Held或可暂停运行，混合按钮按全部成员评估。
    [[nodiscard]] static bool CanContinueMember(const ExecutionGroupMember& member); // 有资格的精确Held或明确Armed运行。
    [[nodiscard]] static bool CanAddRangeMember(const ExecutionGroupMember& member); // 完整Held的NX成员；手动暂停可追加。

private:
    class Impl;
    [[nodiscard]] ExecutionGroupResult ApplySessions(std::span<const ExecutionGroupSessionEntry> sessions, bool all, bool pause); // 先核验全部owner，再走同一混合执行路径。
    std::unique_ptr<Impl> impl_;
};

} // namespace ks::cli::action_analyze::control
