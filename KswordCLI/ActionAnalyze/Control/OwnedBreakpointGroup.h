#pragma once

#include "NativeDebugOwner.h"

#include <array>

namespace ks::cli::action_analyze::control {

inline constexpr std::size_t kOwnedBreakpointGroupSize = 2;

struct OwnedBreakpointGroupToken {
    std::string stopId; // 本会话本轮停点的标识。
    std::uint64_t stateRevision = 0; // 每次发布完整停点递增。
    bool operator==(const OwnedBreakpointGroupToken&) const = default;
};

enum class OwnedBreakpointGroupState {
    Idle, Starting, Running, HeldPartial, HeldComplete, Closing, Closed, Ended, Failed, RecoveryRequired
};

struct OwnedBreakpointGroupMember {
    std::uint32_t pid = 0; // 本工具实际创建的进程 ID。
    std::uint64_t creationFileTime = 0; // 由创建句柄读取的进程创建时间。
    bool ready = false; // 该子进程已主动声明就绪。
    bool gateOpened = false; // 已交付允许进入正常工作的字节。
    bool held = false; // 当前观测中原生账本确实持有该成员的停点。
    std::optional<NativeControlResult> control; // 尝试原生准入之后才有独立状态。
};

struct OwnedBreakpointGroupRelease {
    OwnedBreakpointGroupToken stop; // 本次显式提交的停点。
    std::array<NativeControlResult, kOwnedBreakpointGroupSize> members; // 依冻结顺序保留原生回执。
    bool continued = false; // 两份精确原生回执均为 Continued；不据此判断目标已经执行。
};

struct OwnedBreakpointGroupResult {
    OwnedBreakpointGroupState state = OwnedBreakpointGroupState::Idle;
    const char* stage = "idle"; // 最近的组级诊断阶段。
    std::uint32_t win32Error = 0; // 对应阶段的系统错误。
    LedgerResult ledgerResult = LedgerResult::Applied; // 本次请求的准入或重放结果。
    std::optional<std::size_t> outcomeMember; // 成员级诊断在 members 中的下标。
    bool frozen = false; // 原生准入前已核对两个实例的身份和主动就绪声明。
    bool clean = true; // 没有未清理的启动门和原生调试责任，不表示子进程已退出。
    std::array<OwnedBreakpointGroupMember, kOwnedBreakpointGroupSize> members; // 按启动顺序分列。
    std::optional<OwnedBreakpointGroupToken> stop; // 仅两份真实停点均可继续时发布。
    std::optional<OwnedBreakpointGroupRelease> lastRelease; // 最近一次显式继续的原始回执，清退后仍保留。
};

// 一次性会话，由调用方的同一串行线程使用；调用 Start 前必须取得显式授权。
// 两个成员来自同一个本机 AMD64 控制台 EXE，执行停点使用该 EXE 的命名导出。
// 每个子进程接收 --ksword-breakpoint-ready HANDLE --ksword-breakpoint-gate HANDLE
// （十进制）。子进程先置 Ready，再从 Gate 读取一个字节：ASCII '1' 开始正常工作，EOF 则退出。
// Start 有界等待合作就绪；Query 推进原生武装，确认两侧 Armed 后才开门。
// 所有 PID 和句柄均来自本次启动，调用方没有指定现有目标的入口。
class OwnedBreakpointGroup final {
public:
    explicit OwnedBreakpointGroup(OwnerIdentity identity);
    ~OwnedBreakpointGroup();
    OwnedBreakpointGroup(const OwnedBreakpointGroup&) = delete;
    OwnedBreakpointGroup& operator=(const OwnedBreakpointGroup&) = delete;

    [[nodiscard]] OwnedBreakpointGroupResult Start(const std::wstring& exePath, const std::string& exportName); // 启动并提交武装。
    [[nodiscard]] OwnedBreakpointGroupResult Query(); // 回读当前真实状态和最近的继续回执。
    // 最近一次提交的精确重放返回 Duplicate 与原始回执；其它过期令牌不能释放事件。
    [[nodiscard]] OwnedBreakpointGroupResult Continue(const OwnedBreakpointGroupToken& stop);
    // 逐个请求清退。未完成时保留该对象，Query 观察进度，Close 可发起原生接口允许的重试。
    [[nodiscard]] OwnedBreakpointGroupResult Close();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ks::cli::action_analyze::control
