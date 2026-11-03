#include "network_process_etw_monitor.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <utility>

namespace
{
    // Microsoft-Windows-Kernel-Network。
    // 该 Manifest Provider 的发送/接收事件沿用 TCPIP/UDPIP v2 布局：
    // UserData[0..3] 为 PID，UserData[4..7] 为实际传输字节数。
    constexpr GUID KernelNetworkProviderGuid{
        0x7dd42a49,
        0x5329,
        0x4832,
        { 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88 }
    };

    constexpr ULONGLONG KernelNetworkIpv4Keyword = 0x10ULL;
    constexpr ULONGLONG KernelNetworkIpv6Keyword = 0x20ULL;

    constexpr USHORT TcpIpv4SendEventId = 10;
    constexpr USHORT TcpIpv4ReceiveEventId = 11;
    constexpr USHORT TcpIpv6SendEventId = 26;
    constexpr USHORT TcpIpv6ReceiveEventId = 27;
    constexpr USHORT UdpIpv4SendEventId = 42;
    constexpr USHORT UdpIpv4ReceiveEventId = 43;
    constexpr USHORT UdpIpv6SendEventId = 58;
    constexpr USHORT UdpIpv6ReceiveEventId = 59;

    constexpr std::size_t EtwSessionNameCapacity = 128;

    struct TracePropertiesBlock
    {
        EVENT_TRACE_PROPERTIES properties{};
        wchar_t loggerName[EtwSessionNameCapacity]{};
    };

    std::atomic<std::uint32_t> g_sessionSequence{ 0 };

    void initializeTraceProperties(TracePropertiesBlock* const block, const std::wstring& sessionName)
    {
        if (block == nullptr)
        {
            return;
        }

        *block = TracePropertiesBlock{};
        block->properties.Wnode.BufferSize = sizeof(TracePropertiesBlock);
        block->properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        block->properties.Wnode.ClientContext = 1; // QPC 时间戳。
        block->properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        block->properties.BufferSize = 64;         // KiB。
        block->properties.MinimumBuffers = 4;
        block->properties.MaximumBuffers = 64;
        block->properties.FlushTimer = 1;
        block->properties.LoggerNameOffset = static_cast<ULONG>(offsetof(TracePropertiesBlock, loggerName));
        wcsncpy_s(block->loggerName, EtwSessionNameCapacity, sessionName.c_str(), _TRUNCATE);
    }

    std::wstring buildSessionName()
    {
        const std::uint32_t sequence = g_sessionSequence.fetch_add(1, std::memory_order_relaxed);
        return L"Ksword.ProcessNet." +
            std::to_wstring(::GetCurrentProcessId()) + L"." +
            std::to_wstring(::GetTickCount64()) + L"." +
            std::to_wstring(sequence);
    }

    ULONG stopOwnedTraceSession(const TRACEHANDLE sessionHandle, const std::wstring& sessionName)
    {
        if (sessionHandle == 0 || sessionName.empty())
        {
            return ERROR_SUCCESS;
        }

        TracePropertiesBlock traceProperties;
        initializeTraceProperties(&traceProperties, sessionName);
        return ::ControlTraceW(
            sessionHandle,
            sessionName.c_str(),
            &traceProperties.properties,
            EVENT_TRACE_CONTROL_STOP);
    }

    std::string makeEtwErrorText(const char* const operation, const ULONG errorCode)
    {
        std::ostringstream stream;
        stream << operation << " failed (Win32 error " << errorCode << ")";
        return stream.str();
    }

    bool resolveNetworkDirection(const USHORT eventId, bool* const isInbound)
    {
        if (isInbound == nullptr)
        {
            return false;
        }

        switch (eventId)
        {
        case TcpIpv4SendEventId:
        case TcpIpv6SendEventId:
        case UdpIpv4SendEventId:
        case UdpIpv6SendEventId:
            *isInbound = false;
            return true;

        case TcpIpv4ReceiveEventId:
        case TcpIpv6ReceiveEventId:
        case UdpIpv4ReceiveEventId:
        case UdpIpv6ReceiveEventId:
            *isInbound = true;
            return true;

        default:
            return false;
        }
    }
} // namespace

namespace ks::network
{
    ProcessNetworkEtwMonitor::~ProcessNetworkEtwMonitor()
    {
        Stop();
        // Legacy callers keep the original destructor guarantee that a live
        // callback can never outlive this object. Native retirement retains the
        // object on failed StopChecked, so this fallback is not on its UI path.
        if (m_consumerThread.joinable()) m_consumerThread.join();
    }

    bool ProcessNetworkEtwMonitor::Start()
    {
        std::lock_guard<std::mutex> lifecycleGuard(m_lifecycleMutex);
        if (m_running.load(std::memory_order_acquire))
        {
            return true;
        }

        // Never replace a failed cleanup identity with a new session. All
        // lifecycle fields are owned here; the consumer receives value handles.
        if (!stopLocked()) return false;
        setLastErrorText(std::string());
        m_bufferEventsLost.store(0, std::memory_order_relaxed);
        m_sessionEventsLost.store(0, std::memory_order_relaxed);
        m_providerEvents.store(0, std::memory_order_relaxed);
        m_acceptedEvents.store(0, std::memory_order_relaxed);
        m_stopRequested.store(false, std::memory_order_release);

        const std::wstring sessionName = buildSessionName();
        TracePropertiesBlock traceProperties;
        initializeTraceProperties(&traceProperties, sessionName);

        TRACEHANDLE sessionHandle = 0;
        const ULONG startResult = ::StartTraceW(
            &sessionHandle,
            sessionName.c_str(),
            &traceProperties.properties);
        if (startResult != ERROR_SUCCESS)
        {
            setLastErrorText(makeEtwErrorText("StartTraceW", startResult), startResult, true);
            return false;
        }

        m_sessionHandle = sessionHandle;
        m_sessionName = sessionName;
        m_sessionReleased.store(false, std::memory_order_release);
        m_cleanupPending.store(true, std::memory_order_release);
        const ULONG enableResult = ::EnableTraceEx2(
            sessionHandle,
            &KernelNetworkProviderGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            KernelNetworkIpv4Keyword | KernelNetworkIpv6Keyword,
            0,
            0,
            nullptr);
        if (enableResult != ERROR_SUCCESS)
        {
            (void)stopLocked();
            setLastErrorText(makeEtwErrorText("EnableTraceEx2(Microsoft-Windows-Kernel-Network)", enableResult), enableResult, true);
            return false;
        }

        m_sessionName = sessionName;
        EVENT_TRACE_LOGFILEW traceLog{};
        traceLog.LoggerName = const_cast<wchar_t*>(m_sessionName.c_str());
        traceLog.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        traceLog.EventRecordCallback = &ProcessNetworkEtwMonitor::eventRecordCallback;
        traceLog.BufferCallback = &ProcessNetworkEtwMonitor::bufferCallback;
        traceLog.Context = this;

        const PROCESSTRACE_HANDLE consumerHandle = ::OpenTraceW(&traceLog);
        if (consumerHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            const ULONG openTraceError = ::GetLastError();
            (void)stopLocked();
            setLastErrorText(makeEtwErrorText("OpenTraceW", openTraceError), openTraceError, true);
            return false;
        }

        m_consumerHandle.store(consumerHandle, std::memory_order_release);
        m_consumerFinished.store(false, std::memory_order_release);
        m_running.store(true, std::memory_order_release);
        try
        {
            m_consumerThread = std::thread(&ProcessNetworkEtwMonitor::consumeTrace, this, consumerHandle, sessionHandle, m_sessionName);
        }
        catch (...)
        {
            m_running.store(false, std::memory_order_release);
            m_consumerFinished.store(true, std::memory_order_release);
            (void)stopLocked();
            setLastErrorText("failed to create ETW consumer thread");
            return false;
        }

        return true;
    }

    void ProcessNetworkEtwMonitor::Stop()
    {
        (void)StopChecked();
    }

    bool ProcessNetworkEtwMonitor::StopChecked()
    {
        std::lock_guard<std::mutex> lifecycleGuard(m_lifecycleMutex);
        return stopLocked();
    }

    bool ProcessNetworkEtwMonitor::closeOwnedConsumer()
    {
        const auto handle = m_consumerHandle.exchange(INVALID_PROCESSTRACE_HANDLE, std::memory_order_acq_rel);
        if (handle == INVALID_PROCESSTRACE_HANDLE) return true;
        const ULONG result = ::CloseTrace(handle);
        if (result == ERROR_SUCCESS || result == ERROR_CTX_CLOSE_PENDING || result == ERROR_INVALID_HANDLE) return true;
        auto empty = INVALID_PROCESSTRACE_HANDLE;
        (void)m_consumerHandle.compare_exchange_strong(empty, handle, std::memory_order_acq_rel);
        setLastErrorText(makeEtwErrorText("CloseTrace", result), result, true);
        return false;
    }

    bool ProcessNetworkEtwMonitor::stopLocked()
    {
        m_stopRequested.store(true, std::memory_order_release);
        m_running.store(false, std::memory_order_release);
        if (m_sessionHandle != 0 && !m_sessionReleased.load(std::memory_order_acquire))
        {
            TracePropertiesBlock properties;
            initializeTraceProperties(&properties, m_sessionName);
            const ULONG result = ::ControlTraceW(m_sessionHandle, m_sessionName.c_str(),
                &properties.properties, EVENT_TRACE_CONTROL_STOP);
            if (result == ERROR_SUCCESS || result == ERROR_WMI_INSTANCE_NOT_FOUND)
            {
                if (result == ERROR_SUCCESS) m_sessionEventsLost.store(properties.properties.EventsLost, std::memory_order_relaxed);
                m_sessionReleased.store(true, std::memory_order_release);
                m_stopError.store(ERROR_SUCCESS, std::memory_order_release);
            }
            else
            {
                m_stopError.store(result, std::memory_order_release);
                setLastErrorText(makeEtwErrorText("ControlTraceW(STOP)", result), result, true);
            }
        }
        const bool consumerClosed = closeOwnedConsumer();
        // A failed close cannot authorize discarding a live callback owner.
        // Keep its thread and value handles for Retry instead of blocking this
        // attempt forever on join when both STOP and CloseTrace failed.
        if (!consumerClosed && !m_consumerFinished.load(std::memory_order_acquire)) return false;
        if (m_consumerThread.joinable()) m_consumerThread.join();
        const bool sessionReleased = m_sessionHandle == 0 || m_sessionReleased.load(std::memory_order_acquire);
        const bool complete = sessionReleased && m_consumerHandle.load(std::memory_order_acquire) == INVALID_PROCESSTRACE_HANDLE;
        if (complete)
        {
            m_sessionHandle = 0;
            m_sessionName.clear();
            m_cleanupPending.store(false, std::memory_order_release);
        }
        return complete;
    }

    bool ProcessNetworkEtwMonitor::IsRunning() const
    {
        return m_running.load(std::memory_order_acquire);
    }

    std::string ProcessNetworkEtwMonitor::LastErrorText() const
    {
        std::lock_guard<std::mutex> errorGuard(m_errorMutex);
        return m_lastErrorText;
    }

    ProcessNetworkEtwHealth ProcessNetworkEtwMonitor::SnapshotHealth() const
    {
        const std::uint64_t bufferEventsLost = m_bufferEventsLost.load(std::memory_order_relaxed);
        const std::uint64_t sessionEventsLost = m_sessionEventsLost.load(std::memory_order_relaxed);

        ProcessNetworkEtwHealth health;
        health.isRunning = IsRunning();
        health.cleanupPending = m_cleanupPending.load(std::memory_order_acquire);
        health.stopError = m_stopError.load(std::memory_order_acquire);
        health.stopErrorKnown = health.stopError != ERROR_SUCCESS;
        health.eventsLost = std::max(bufferEventsLost, sessionEventsLost);
        health.dataLossDetected = (health.eventsLost != 0);
        health.providerEvents = m_providerEvents.load(std::memory_order_relaxed);
        health.acceptedEvents = m_acceptedEvents.load(std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> errorGuard(m_errorMutex);
            health.errorCodeKnown = m_lastErrorCodeKnown;
            health.errorCode = m_lastErrorCode;
            health.errorText = m_lastErrorText;
        }
        return health;
    }

    std::unordered_map<std::uint32_t, ProcessNetworkTrafficCounters>
    ProcessNetworkEtwMonitor::SnapshotCounters() const
    {
        std::lock_guard<std::mutex> counterGuard(m_counterMutex);
        return m_countersByPid;
    }

    void ProcessNetworkEtwMonitor::PruneCounters(const std::unordered_set<std::uint32_t>& liveProcessIds)
    {
        std::lock_guard<std::mutex> counterGuard(m_counterMutex);
        for (auto counterIt = m_countersByPid.begin(); counterIt != m_countersByPid.end();)
        {
            if (liveProcessIds.find(counterIt->first) == liveProcessIds.end())
            {
                counterIt = m_countersByPid.erase(counterIt);
            }
            else
            {
                ++counterIt;
            }
        }
    }

    void WINAPI ProcessNetworkEtwMonitor::eventRecordCallback(PEVENT_RECORD const eventRecord)
    {
        if (eventRecord == nullptr || eventRecord->UserContext == nullptr)
        {
            return;
        }

        auto* const monitor = static_cast<ProcessNetworkEtwMonitor*>(eventRecord->UserContext);
        monitor->recordNetworkEvent(*eventRecord);
    }

    ULONG WINAPI ProcessNetworkEtwMonitor::bufferCallback(PEVENT_TRACE_LOGFILEW const logFile)
    {
        if (logFile == nullptr || logFile->Context == nullptr)
        {
            return TRUE;
        }

        auto* const monitor = static_cast<ProcessNetworkEtwMonitor*>(logFile->Context);
        if (logFile->EventsLost != 0)
        {
            monitor->m_bufferEventsLost.fetch_add(logFile->EventsLost, std::memory_order_relaxed);
        }
        return monitor->m_stopRequested.load(std::memory_order_acquire) ? FALSE : TRUE;
    }

    void ProcessNetworkEtwMonitor::consumeTrace(
        const PROCESSTRACE_HANDLE consumerHandle,
        const TRACEHANDLE sessionHandle,
        std::wstring sessionName)
    {
        PROCESSTRACE_HANDLE activeConsumerHandle = consumerHandle;
        const ULONG processResult = ::ProcessTrace(
            &activeConsumerHandle,
            1,
            nullptr,
            nullptr);
        (void)closeOwnedConsumer();

        if (!m_stopRequested.load(std::memory_order_acquire) &&
            processResult != ERROR_SUCCESS &&
            processResult != ERROR_CANCELLED)
        {
            setLastErrorText(makeEtwErrorText("ProcessTrace", processResult), processResult, true);
            const ULONG stopped = stopOwnedTraceSession(sessionHandle, sessionName);
            if (stopped == ERROR_SUCCESS || stopped == ERROR_WMI_INSTANCE_NOT_FOUND) {
                m_sessionReleased.store(true, std::memory_order_release);
            } else {
                m_stopError.store(stopped, std::memory_order_release);
            }
        }

        m_consumerFinished.store(true, std::memory_order_release);
        m_running.store(false, std::memory_order_release);
    }

    void ProcessNetworkEtwMonitor::recordNetworkEvent(const EVENT_RECORD& eventRecord)
    {
        if (::IsEqualGUID(eventRecord.EventHeader.ProviderId, KernelNetworkProviderGuid))
            m_providerEvents.fetch_add(1, std::memory_order_relaxed);
        if (!::IsEqualGUID(eventRecord.EventHeader.ProviderId, KernelNetworkProviderGuid) ||
            eventRecord.UserData == nullptr ||
            eventRecord.UserDataLength < (sizeof(std::uint32_t) * 2))
        {
            return;
        }

        bool isInbound = false;
        if (!resolveNetworkDirection(eventRecord.EventHeader.EventDescriptor.Id, &isInbound))
        {
            return;
        }

        std::uint32_t processId = 0;
        std::uint32_t transferBytes = 0;
        std::memcpy(&processId, eventRecord.UserData, sizeof(processId));
        std::memcpy(
            &transferBytes,
            static_cast<const std::uint8_t*>(eventRecord.UserData) + sizeof(processId),
            sizeof(transferBytes));
        if (processId == 0 || transferBytes == 0)
        {
            return;
        }
        m_acceptedEvents.fetch_add(1, std::memory_order_relaxed);

        std::lock_guard<std::mutex> counterGuard(m_counterMutex);
        ProcessNetworkTrafficCounters& counters = m_countersByPid[processId];
        if (isInbound)
        {
            counters.rxBytes += static_cast<std::uint64_t>(transferBytes);
        }
        else
        {
            counters.txBytes += static_cast<std::uint64_t>(transferBytes);
        }
    }

    void ProcessNetworkEtwMonitor::setLastErrorText(std::string errorText, ULONG errorCode, bool codeKnown)
    {
        std::lock_guard<std::mutex> errorGuard(m_errorMutex);
        m_lastErrorText = std::move(errorText);
        m_lastErrorCode = errorCode;
        m_lastErrorCodeKnown = codeKnown;
    }
} // namespace ks::network
