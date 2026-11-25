#pragma once

#include "../../../shared/usermode/backend/Win32.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace ks::cli::action_analyze::memory {

enum class ThreadSnapshotStatus { Unknown, TargetExited, Limited, Complete };
enum class ThreadEventStatus { Unknown, Observed, NewlyObserved, Exited };

struct ThreadObservationEvent {
    DWORD tid = 0;
    std::uint64_t creationTime100ns = 0; // 0 表示未核对身份。
    ThreadEventStatus status = ThreadEventStatus::Unknown;
    DWORD win32Error = ERROR_SUCCESS;
};

struct ThreadObservation {
    ThreadSnapshotStatus status = ThreadSnapshotStatus::Unknown;
    DWORD win32Error = ERROR_SUCCESS;
    std::uint64_t snapshotStartUtc100ns = 0;
    std::uint64_t snapshotEndUtc100ns = 0;
    std::uint64_t readbackEndUtc100ns = 0;
    std::optional<std::size_t> listedThreadCount;
    std::vector<ThreadObservationEvent> events;
};

// 单所有者串行使用。借用调用方已核验且在本对象整个生存期内有效的进程句柄；
// pid 必须来自同一已核验进程。只持有线程查询句柄，析构即释放，不按 PID 重新打开进程。
class PassiveThreadObservation final {
public:
    PassiveThreadObservation(HANDLE verifiedProcess, DWORD pid);
    ~PassiveThreadObservation();
    PassiveThreadObservation(const PassiveThreadObservation&) = delete;
    PassiveThreadObservation& operator=(const PassiveThreadObservation&) = delete;

    // 每次调用只观察一次线程列表，与字节采样窗口独立；不提供写入或执行归因。
    [[nodiscard]] ThreadObservation Observe();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ks::cli::action_analyze::memory
