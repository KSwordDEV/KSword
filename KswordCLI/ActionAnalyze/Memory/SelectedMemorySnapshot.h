#pragma once

#include "PassiveDirtyMemory.h"

namespace ks::cli::action_analyze::memory {

struct CapturedMemoryPage {
    PageObservation observation; // 对应这些原字节的读前/读后区域、散列和采样时钟。
    std::vector<std::uint8_t> bytes; // 仅完整成功页的所选子范围，无缺口填零或未核验部分字节。
};

struct SelectedMemorySnapshot {
    Plan plan; // 本次执行时冻结的样本、真实进程实例与绝对范围。
    Status status; // 首次读取后真实状态；正常单轮收尾为 Stopped。
    std::optional<Round> round; // 实际访问过的页，失败页及部分结果均保留。
    std::vector<CapturedMemoryPage> captured; // 与 round 成功页一一对应，按地址顺序排列。
    bool completeRange = false; // 全范围每页完整读取成功；不表示进程级原子快照。
};

// 同步执行一次显式范围采样，借用已选进程句柄。调用方在后台串行执行，不重新按裸 PID 绑定。
// 复用 PassiveDirtyMemory 的身份、同用户、区域、读取和散列检查；只采一次，不等待计划轮数。
SelectedMemorySnapshot CaptureSelectedMemory(HANDLE selectedProcess, const Plan& plan,
    const std::atomic_bool* cancel = nullptr);

} // namespace ks::cli::action_analyze::memory
