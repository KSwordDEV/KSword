#pragma once

// F-10 取消与并发、M-10 扫描预算、F-09 会话数据与现场分开。
//
// 这里只有纯策略，不含线程、Qt 或 Win32：任务 id 单调、旧结果不回填、预算命中
// 即停并保留部分结果、非法范围直接拒绝。UI 线程模型各自实现，判据共用这一份。

#include "EvidenceEnvelope.h"
#include "LosslessValue.h"

#include <cstdint>
#include <string>

namespace Ksword::Evidence {

// ---------------------------------------------------------------------------
// F-10：同一视图只接纳最新请求。
// ---------------------------------------------------------------------------
enum class TaskState {
    Pending,
    Running,
    Cancelling,   // 已请求取消，后台仍在安全边界内收尾（不得伪报已清理）
    Cancelled,
    Completed,
    Failed,
};

const char* TaskStateName(TaskState state) noexcept;

// 终态之外都表示后台仍可能持有资源。
bool TaskStateIsTerminal(TaskState state) noexcept;

// LatestRequestGate：给一个视图用。generation 单调递增；只有最新一代的结果
// 允许回填，晚到的旧结果一律丢弃（A 后完成也不覆盖 B）。
class LatestRequestGate final {
public:
    // 开新请求，返回本次的 generation。
    std::uint64_t begin() noexcept { return ++generation_; }

    std::uint64_t current() const noexcept { return generation_; }

    // 结果回来时问一次：是不是最新一代？
    bool accepts(std::uint64_t generation) const noexcept { return generation == generation_; }

    // 取消当前请求：generation 前进，任何在途结果都不再被接纳。
    void cancelCurrent() noexcept { ++generation_; }

private:
    std::uint64_t generation_ = 0;
};

// ---------------------------------------------------------------------------
// M-10：扫描范围与预算。
// ---------------------------------------------------------------------------
enum class RangeValidation {
    Ok,
    EmptyRange,        // begin == end
    Reversed,          // begin > end
    Overflow,          // begin + length 溢出 64 位
    ExceedsApproved,   // 越出用户已批准的范围
};

const char* RangeValidationName(RangeValidation validation) noexcept;

struct AddressRange final {
    std::uint64_t begin = 0;
    std::uint64_t length = 0;
    // M-10：(begin,end) 入口发现 end < begin 时置位。用 (begin,length) 表达范围时，
    // 调用方自算 length 会把逆序压成回绕（或压成一个合法的小长度），Reversed 就永远
    // 产不出来。这一位把"用户给反了"原样带到 ValidateRange。
    bool reversed = false;

    bool endAddress(std::uint64_t& out) const noexcept;  // 溢出或逆序返回 false

    // 端点构造。end < begin -> 标记 reversed（length 留 0），ValidateRange 报 Reversed。
    // end == begin -> 空范围，ValidateRange 报 EmptyRange。
    static AddressRange fromBeginEnd(std::uint64_t begin, std::uint64_t end) noexcept;
};

// approved.length == 0 表示"调用方没有限定到具体范围"。那不等于"允许扫全 64 位
// 地址空间"：无批准窗口时单次请求长度仍有硬天花板，越过即 ExceedsApproved。
inline constexpr std::uint64_t kUnapprovedScanCeilingBytes = 1ULL << 32;  // 4 GiB

// approved 为空长度表示"未限制到具体范围"，此时做自身合法性校验 + 上面的天花板。
RangeValidation ValidateRange(const AddressRange& request, const AddressRange& approved) noexcept;

// ScanBudget：字节、页和时间三条独立上限，任一命中即停止并保留已完成部分。
struct ScanBudget final {
    OptionalU64 maxBytes;
    OptionalU64 maxPages;
    OptionalU64 maxItems;
    OptionalU64 maxDurationNanos;

    // 全部未设置表示无界 —— 生产路径不应出现，构造点必须显式给上限。
    bool bounded() const noexcept;
};

enum class BudgetStop {
    Continue,
    BytesExhausted,
    PagesExhausted,
    ItemsExhausted,
    TimeExhausted,
    Cancelled,
};

const char* BudgetStopName(BudgetStop stop) noexcept;

// 扫描进度。每处理一批就更新，命中上限时 shouldStop() 给出具体原因。
struct ScanProgress final {
    std::uint64_t bytesDone = 0;
    std::uint64_t pagesDone = 0;
    std::uint64_t itemsDone = 0;
    std::uint64_t elapsedNanos = 0;
    bool cancelRequested = false;
};

BudgetStop EvaluateBudget(const ScanBudget& budget, const ScanProgress& progress) noexcept;

// 把一次有界扫描的结果翻译成 F-06 的账目：命中上限 -> Partial + limitHit。
CollectionOutcome OutcomeForStop(BudgetStop stop) noexcept;
void ApplyStopToCoverage(BudgetStop stop, const ScanBudget& budget, CoverageAccount& coverage);

// ---------------------------------------------------------------------------
// F-09：离线会话与现场数据分开。
// ---------------------------------------------------------------------------
enum class DataOrigin {
    Live,     // 当前现场采集，可被新快照替换
    Session,  // 已保存会话，禁止被后台刷新覆盖
};

// 现场刷新到达时的判定：会话数据永远拒绝被覆盖，现场数据只接受更新的快照。
enum class RefreshDecision {
    Apply,
    RejectSessionIsImmutable,
    RejectStaleSnapshot,
    RejectNotLatestRequest,
};

const char* RefreshDecisionName(RefreshDecision decision) noexcept;

RefreshDecision DecideRefresh(DataOrigin origin,
                              std::uint64_t currentSnapshotId,
                              std::uint64_t incomingSnapshotId,
                              bool isLatestRequest) noexcept;

// F-09：离线结果跳转现场必须显式重新校验对象身份。
enum class LiveNavigationDecision {
    Allow,              // 现场存在且身份确认一致
    RejectObjectExited, // 对象已退出
    RejectIdentityMismatch,  // 同 PID/地址但身份不匹配（PID 复用）
    RejectIdentityUnverifiable,  // 身份信息不足以确认
};

const char* LiveNavigationDecisionName(LiveNavigationDecision decision) noexcept;

} // namespace Ksword::Evidence
