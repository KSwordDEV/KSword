#pragma once

#include <cstdint>
#include <optional>

namespace ks::threadsettings {

enum class Field { Priority, PriorityBoost };

struct Identity
{
    std::uint32_t processId; // 线程所属的进程 ID。
    std::uint32_t threadId; // 选中的线程 ID。
    // 进程创建时间可为零；线程创建时间必须提供。均为原始 FILETIME 值。
    std::uint64_t processCreationTime100ns;
    std::uint64_t threadCreationTime100ns;
};

struct Value
{
    std::optional<int> value; // 实际回读的值；失败时为空，不用零占位。
    unsigned long error = 0; // 字段读取错误；可读但无写权限时仍为零。
    // 读取成功且已取得普通写权限；不保证实际设置一定成功。
    bool writable = false;
};

struct Snapshot
{
    Value priority; // Windows 线程相对优先级值。
    Value priorityBoost; // 1 表示允许动态优先级提升，0 表示禁用。
    unsigned long identityError = 0; // 目标无法打开、身份不符或已退出时的错误。
};

// 已回读确认、基线不符、无法提交、设置失败、设置成功但未验证。
enum class Status { Applied, Conflict, Unavailable, Failed, Unverified };

struct Edit
{
    Identity identity; // 编辑开始时冻结的目标身份。
    Field field; // 本次唯一允许修改的设置。
    int expected; // 编辑前实际读取的基线。
    int desired; // 用户显式选择的目标值。
};

struct Receipt
{
    Status status; // 本次提交结果。
    Snapshot snapshot; // 实际回读；未调用设置接口时为写前快照（如可用）。
    unsigned long error; // Win32 错误码；设置接口失败时优先保留其错误。
};

// 给定冻结身份，返回当前设置和普通写权限探测结果；不会写入。
Snapshot Query(const Identity&);
// 给定单字段编辑，返回写前比对、设置与写后回读的回执；不是原子操作。
// 允许读到 Time Critical，但不允许设为该值。
Receipt Apply(const Edit&);

} // namespace ks::threadsettings
