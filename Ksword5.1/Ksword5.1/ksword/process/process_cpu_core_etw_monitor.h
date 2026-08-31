#pragma once

// ============================================================
// process_cpu_core_etw_monitor.h
// 作用：
// - 消费 Windows 内核线程 CSwitch ETW 事件；
// - 按 PID/TID 与逻辑处理器累计真实运行时间；
// - 供进程详情“CPU 核心”页展示进程及线程的逐核心占用。
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ks::process
{
    // EtwLogicalProcessorCoordinate：跨 Processor Group 的 ETW 全局逻辑处理器坐标。
    struct EtwLogicalProcessorCoordinate
    {
        std::uint32_t processorIndex = 0; // ETW 全局处理器索引。
        std::uint16_t group = 0;          // Processor Group 编号。
        std::uint16_t number = 0;         // 组内逻辑处理器编号。
    };

    // CpuCoreUsageSeries：一个进程或线程在全部逻辑处理器上的区间占用。
    struct CpuCoreUsageSeries
    {
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;       // 进程序列固定为 0；线程序列为实际 TID。
        double coreEquivalentPercent = 0.0; // 各核心占用求和；线程理论上不超过 100%。
        std::vector<double> percentByProcessor;
        std::vector<bool> sampleReadyByProcessor;
    };

    // CpuCoreUsageSnapshot：单个 UI 刷新区间的逐核心快照。
    struct CpuCoreUsageSnapshot
    {
        bool monitorRunning = false;
        bool sampleReady = false;
        bool dataLossDetected = false;
        std::uint64_t eventsLost = 0;
        std::uint64_t contextSwitchEvents = 0;
        std::string diagnosticText;
        std::vector<EtwLogicalProcessorCoordinate> processors;
        std::vector<bool> sampleReadyByProcessor;
        std::vector<std::uint64_t> liveThreadIdentities;
        std::unordered_map<std::uint32_t, CpuCoreUsageSeries> processUsageByPid;
        std::unordered_map<std::uint64_t, CpuCoreUsageSeries> threadUsageByIdentity;
    };

    // BuildCpuThreadIdentity：PID/TID 组合键，避免不同进程的线程 ID 混淆。
    std::uint64_t BuildCpuThreadIdentity(std::uint32_t processId, std::uint32_t threadId);

    // ProcessCpuCoreEtwMonitor：
    // - Start/Stop 管理本实例拥有的 System Logger 实时会话；
    // - 回调只做定长字段解析与计数，不向 UI 投递逐事件对象；
    // - SnapshotAndReset 生成一个刷新区间并清空区间累计值。
    class ProcessCpuCoreEtwMonitor final
    {
    public:
        ProcessCpuCoreEtwMonitor();
        ~ProcessCpuCoreEtwMonitor();

        ProcessCpuCoreEtwMonitor(const ProcessCpuCoreEtwMonitor&) = delete;
        ProcessCpuCoreEtwMonitor& operator=(const ProcessCpuCoreEtwMonitor&) = delete;

        bool Start();
        void Stop();
        bool IsRunning() const;
        std::string LastErrorText() const;
        CpuCoreUsageSnapshot SnapshotAndReset();

    private:
        struct RuntimeCounter
        {
            std::vector<std::uint64_t> ticksByProcessor;
        };

        static void WINAPI eventRecordCallback(PEVENT_RECORD eventRecord);
        static ULONG WINAPI bufferCallback(PEVENT_TRACE_LOGFILEW logFile);

        void consumeTrace(PROCESSTRACE_HANDLE consumerHandle, std::wstring sessionName);
        void recordEvent(const EVENT_RECORD& eventRecord);
        void recordThreadLifecycleEvent(const EVENT_RECORD& eventRecord, std::uint8_t opcode);
        void recordContextSwitchEvent(const EVENT_RECORD& eventRecord);
        void recordThreadRuntimeLocked(
            std::size_t processorIndex,
            std::uint32_t threadId,
            std::uint64_t deltaTicks);
        std::uint32_t resolveThreadOwnerLocked(std::uint32_t threadId);
        void resetProcessorBaselinesLocked();
        void setLastErrorText(std::string errorText);

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
        std::vector<EtwLogicalProcessorCoordinate> m_processors;
        std::vector<std::uint64_t> m_lastTimestampByProcessor;
        std::vector<std::uint32_t> m_currentThreadIdByProcessor;
        std::vector<bool> m_currentThreadKnownByProcessor;
        std::vector<std::uint64_t> m_observedTicksByProcessor;
        std::unordered_map<std::uint32_t, RuntimeCounter> m_processRuntimeByPid;
        std::unordered_map<std::uint64_t, RuntimeCounter> m_threadRuntimeByIdentity;
        std::unordered_map<std::uint32_t, std::uint32_t> m_processIdByThreadId;
        std::unordered_set<std::uint32_t> m_unresolvedThreadIds;
        std::uint64_t m_contextSwitchEvents = 0;
        std::uint64_t m_lastObservedBufferLoss = 0;
        std::uint64_t m_lastSnapshotEventsLost = 0;

        mutable std::mutex m_errorMutex;
        std::string m_lastErrorText;
    };
} // namespace ks::process
