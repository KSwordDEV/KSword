#pragma once

// ============================================================
// ksword/network/network_process_etw_monitor.h
// 作用：
// - 通过 Microsoft-Windows-Kernel-Network ETW Provider 汇总每进程网络字节；
// - 仅处理 PID、方向与传输大小，不复制报文、不枚举连接表；
// - 使用独立实时 ETW 会话，绝不接管 NT Kernel Logger。
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace ks::network
{
    // ProcessNetworkTrafficCounters：单个 PID 的累计接收、发送字节数。
    struct ProcessNetworkTrafficCounters
    {
        std::uint64_t rxBytes = 0;
        std::uint64_t txBytes = 0;
    };

    // ProcessNetworkEtwHealth：ETW 会话运行状态与已检测到的数据丢失量。
    struct ProcessNetworkEtwHealth
    {
        bool isRunning = false;
        bool dataLossDetected = false;
        std::uint64_t eventsLost = 0;
        bool errorCodeKnown = false;
        std::uint32_t errorCode = 0;
        std::string errorText;
    };

    // ProcessNetworkEtwMonitor：
    // - Start/Stop 管理独占的私有实时 ETW Session；
    // - 回调线程直接按 PID 累计字节，UI 仅在刷新时取得快照；
    // - 不向 UI 投递逐包事件，避免网络活跃时压垮 GUI 线程。
    class ProcessNetworkEtwMonitor final
    {
    public:
        ProcessNetworkEtwMonitor() = default;
        ~ProcessNetworkEtwMonitor();

        ProcessNetworkEtwMonitor(const ProcessNetworkEtwMonitor&) = delete;
        ProcessNetworkEtwMonitor& operator=(const ProcessNetworkEtwMonitor&) = delete;

        // Start：创建私有 ETW 会话并启用 Kernel-Network Provider。
        // 返回 false 时可通过 LastErrorText 获取失败原因。
        bool Start();

        // Stop：停止本实例创建的会话并等待 ETW 消费线程退出。
        void Stop();

        bool IsRunning() const;
        std::string LastErrorText() const;
        ProcessNetworkEtwHealth SnapshotHealth() const;

        // SnapshotCounters：复制当前 PID -> 累计字节表。
        std::unordered_map<std::uint32_t, ProcessNetworkTrafficCounters> SnapshotCounters() const;

        // PruneCounters：删除不在 liveProcessIds 内的累计项，限制长期内存占用。
        void PruneCounters(const std::unordered_set<std::uint32_t>& liveProcessIds);

    private:
        static void WINAPI eventRecordCallback(PEVENT_RECORD eventRecord);
        static ULONG WINAPI bufferCallback(PEVENT_TRACE_LOGFILEW logFile);

        void consumeTrace(PROCESSTRACE_HANDLE consumerHandle, std::wstring sessionName);
        void recordNetworkEvent(const EVENT_RECORD& eventRecord);
        void setLastErrorText(std::string errorText, ULONG errorCode = ERROR_SUCCESS, bool codeKnown = false);

    private:
        mutable std::mutex m_lifecycleMutex;
        std::thread m_consumerThread;
        TRACEHANDLE m_sessionHandle = 0;
        PROCESSTRACE_HANDLE m_consumerHandle = INVALID_PROCESSTRACE_HANDLE;
        std::wstring m_sessionName;

        std::atomic_bool m_running{ false };
        std::atomic_bool m_stopRequested{ false };
        std::atomic<std::uint64_t> m_bufferEventsLost{ 0 };
        std::atomic<std::uint64_t> m_sessionEventsLost{ 0 };

        mutable std::mutex m_counterMutex;
        std::unordered_map<std::uint32_t, ProcessNetworkTrafficCounters> m_countersByPid;

        mutable std::mutex m_errorMutex;
        std::string m_lastErrorText;
        ULONG m_lastErrorCode = ERROR_SUCCESS;
        bool m_lastErrorCodeKnown = false;
    };
} // namespace ks::network
