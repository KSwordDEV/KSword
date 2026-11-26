#pragma once

#include "OwnedProcessGroup.h"
#include "../Memory/SelectedMemorySnapshot.h"

namespace ks::cli::action_analyze::control {

enum class ProcessMemorySource { LiveRead, HeldEvent };

struct ProcessMemorySnapshotRequest {
    memory::Plan plan; // 样本、范围和真实进程身份在显式执行时冻结。
    ProcessMemorySource source = ProcessMemorySource::LiveRead; // 实时读取和持有停点明确选择。
    std::optional<ProcessGroupStop> stop; // HeldEvent 必须带原界面显示的完整令牌。
};

struct ProcessMemorySnapshotResult {
    ProcessMemorySnapshotRequest request; // 原请求保留，不由读取后当前选区改写。
    const char* stage = "process-memory-not-read"; // 读取或精确停点核对结果。
    std::uint32_t win32Error = 0; // 原生错误或拒绝原因。
    std::optional<memory::SelectedMemorySnapshot> snapshot; // 实际读取后，即使停点失效也保留部分证据。
    std::optional<ProcessGroupStop> before, after; // 两次原所有者回读的停点，未取得时为空。
    bool heldAtBothChecks = false; // 不表示外部写入者也被冻结，内存仍为逐页采样。
};

// 在持有 OwnedProcessGroup 的同一串行工作线程调用；不能与 Continue/Close 并发。
// 明确 HeldEvent 失败时不回退实时模式；只按冻结实例打开只读句柄，不暂停或恢复任何线程。
ProcessMemorySnapshotResult CaptureProcessGroupMemory(OwnedProcessGroup& group,
    const ProcessMemorySnapshotRequest& request, const std::atomic_bool* cancel = nullptr);

// 断点/步进会话借用原 owner 读取同一停点；不新建集合、Pause 或 Continue。
// 只接 HeldEvent，要求调用者串行持有 owner，并传入本会话身份及显示时冻结的完整令牌。
ProcessMemorySnapshotResult CaptureNativeStopMemory(NativeDebugOwner& owner, const OwnerIdentity& identity,
    const ProcessMemorySnapshotRequest& request, const std::atomic_bool* cancel = nullptr);

} // namespace ks::cli::action_analyze::control
