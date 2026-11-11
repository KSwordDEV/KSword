#include "pch.h"
#include "MonitorPipe.h"
#include "../hook/HookCallStack.h"
#include "MonitorCoverage.h"
#include "ApiMonitorMetadata.h"
#include "../MonitorAgent.h"
#include "../hook/HookEngine.h"
#include "MonitorDiagnostics.h"
#include <Aclapi.h>
#include <Sddl.h>

namespace apimon
{
    std::uint32_t FlushPendingMonitorEvents(const std::uint32_t maxPacketsToFlush);

    std::uint32_t FlushCoverageSnapshot(std::uint32_t budget);

    namespace
    {
        std::shared_ptr<const CoverageSnapshot> g_sendingCoverage;
        std::uint32_t g_coverageSendIndex = 0;
        std::atomic_uint64_t g_lastCoverageRevision{0};
        std::atomic_uint32_t g_eventFlushesActive{0};
        SRWLOCK g_pipeLock = SRWLOCK_INIT;              // g_pipeLock：保护 g_pipeHandle 的读写与发送序列。
        HANDLE g_pipeHandle = INVALID_HANDLE_VALUE;     // g_pipeHandle：当前已连接的命名管道句柄。
        // g_pipeHandleValue：无锁句柄快照，供 Hook 快速判断“是否监控管道句柄”，避免在 WriteFile Hook 中重入锁导致死锁。
        std::atomic_uintptr_t g_pipeHandleValue{ 0 };
        SRWLOCK g_queueLock = SRWLOCK_INIT;             // g_queueLock：保护待发送事件队列。
        constexpr std::size_t kMaxPendingPacketCount = 4096; // kMaxPendingPacketCount：固定环形队列容量，避免 Hook 热路径动态分配。
        constexpr std::uint32_t kMaxFlushBatchCount = 256;   // 单次发送上限；缓冲不占用目标程序继承的小线程栈。
        std::array<ks::winapi_monitor::ApiMonitorEventPacket, kMaxPendingPacketCount> g_pendingPacketRing{}; // 固定事件环形缓冲。
        // g_pipeLock covers both the copy and the send, including concurrent explicit drains.
        std::array<ks::winapi_monitor::ApiMonitorEventPacket, kMaxFlushBatchCount> g_flushPacketBatch{};
        std::atomic_uint64_t g_droppedPacketCount{0};
        std::uint64_t g_reportedDroppedPacketCount = 0; // sender thread only
        constexpr std::size_t kControlPacketReserve = 64;
        std::size_t g_pendingPacketHead = 0;                 // g_pendingPacketHead：下一条待发送事件所在槽位。
        std::size_t g_pendingPacketCount = 0;                // g_pendingPacketCount：当前环形队列中有效事件数量。
        std::atomic_bool g_senderStopFlag{ false };    // g_senderStopFlag：后台发送线程停止信号。
        HANDLE g_queueWakeEvent = nullptr;             // g_queueWakeEvent：待发送事件唤醒事件。
        HANDLE g_senderStopEvent = nullptr;            // g_senderStopEvent：中断挂起 OVERLAPPED WriteFile 的手动复位停止事件。
        constexpr DWORD kPipeConnectPollMs = 200;       // kPipeConnectPollMs：等待客户端连接时的轮询间隔。
        constexpr DWORD kPipeConnectTimeoutMs = 45000;  // kPipeConnectTimeoutMs：等待 UI 侧连入的最大时长。

        struct PipeSecurity
        {
            PSECURITY_DESCRIPTOR descriptor = nullptr;
            PACL acl = nullptr;
            ~PipeSecurity()
            {
                if (acl) ::LocalFree(acl);
                if (descriptor) ::LocalFree(descriptor);
            }
        };

        bool BuildPipeSecurity(const std::wstring& controllerSid, PipeSecurity& security,
            SECURITY_ATTRIBUTES& attributes, std::wstring* errorTextOut)
        {
            if (controllerSid.empty()) return true;
            PSID controller = nullptr;
            if (!::ConvertStringSidToSidW(controllerSid.c_str(), &controller))
            {
                if (errorTextOut) *errorTextOut = L"ConvertStringSidToSidW failed. error=" + std::to_wstring(::GetLastError());
                return false;
            }
            SID_IDENTIFIER_AUTHORITY systemAuthority = SECURITY_NT_AUTHORITY;
            PSID systemSid = nullptr;
            if (!::AllocateAndInitializeSid(&systemAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
                0, 0, 0, 0, 0, 0, 0, &systemSid))
            {
                const DWORD error = ::GetLastError();
                ::LocalFree(controller);
                if (errorTextOut) *errorTextOut = L"AllocateAndInitializeSid failed. error=" + std::to_wstring(error);
                return false;
            }
            EXPLICIT_ACCESSW entries[2]{};
            entries[0].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE;
            entries[0].grfAccessMode = GRANT_ACCESS;
            entries[0].grfInheritance = NO_INHERITANCE;
            entries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            entries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
            entries[0].Trustee.ptstrName = reinterpret_cast<LPWSTR>(controller);
            entries[1].grfAccessPermissions = GENERIC_ALL;
            entries[1].grfAccessMode = GRANT_ACCESS;
            entries[1].grfInheritance = NO_INHERITANCE;
            entries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            entries[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            entries[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(systemSid);
            const DWORD aclError = ::SetEntriesInAclW(2, entries, nullptr, &security.acl);
            ::FreeSid(systemSid);
            ::LocalFree(controller);
            if (aclError != ERROR_SUCCESS)
            {
                if (errorTextOut) *errorTextOut = L"SetEntriesInAclW for monitor pipe failed. error=" + std::to_wstring(aclError);
                return false;
            }
            security.descriptor = static_cast<PSECURITY_DESCRIPTOR>(::LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH));
            if (!security.descriptor || !::InitializeSecurityDescriptor(security.descriptor, SECURITY_DESCRIPTOR_REVISION)
                || !::SetSecurityDescriptorDacl(security.descriptor, TRUE, security.acl, FALSE))
            {
                const DWORD error = ::GetLastError();
                if (errorTextOut) *errorTextOut = L"build monitor pipe security descriptor failed. error=" + std::to_wstring(error);
                return false;
            }
            attributes.nLength = sizeof(attributes);
            attributes.lpSecurityDescriptor = security.descriptor;
            attributes.bInheritHandle = FALSE;
            return true;
        }

        // SenderThreadSlot 作用：
        // - 输入：无；
        // - 处理：返回后台发送线程的唯一持有槽位，槽位本身故意泄漏到进程结束；
        // - 返回：std::unique_ptr<std::thread> 引用，正常 StopMonitorPipeServer 仍会 join/reset。
        // - 原因：目标进程退出时 DLL 静态析构可能早于 worker 线程完成；若静态 std::thread 仍 joinable，
        //   MSVC CRT 会调用 std::terminate，表现为 0xC0000409。泄漏槽位让显式 Stop 负责清理，异常退出交给 OS 回收。
        std::unique_ptr<std::thread>& SenderThreadSlot()
        {
            static auto* const senderThreadPointer = new std::unique_ptr<std::thread>();
            return *senderThreadPointer;
        }

        // CopyWideTextRaw 作用：
        // - 输入：sourceText 为可空宽字符串，targetBuffer/charCount 为目标定长缓冲；
        // - 处理：按 maxChars 限制复制并始终补 NUL，不进行堆分配；
        // - 返回：无返回值，调用者直接使用 targetBuffer。
        void CopyWideTextRaw(
            const wchar_t* const sourceText,
            wchar_t* const targetBuffer,
            const std::size_t charCount,
            const std::size_t maxChars)
        {
            if (targetBuffer == nullptr || charCount == 0)
            {
                return;
            }

            const std::size_t copyLimit = std::min<std::size_t>(charCount - 1, maxChars);
            std::size_t copyLength = 0;
            if (sourceText != nullptr)
            {
                while (copyLength < copyLimit && sourceText[copyLength] != L'\0')
                {
                    targetBuffer[copyLength] = sourceText[copyLength];
                    ++copyLength;
                }
            }
            targetBuffer[copyLength] = L'\0';
        }

        // CopyWideText 作用：
        // - 输入：sourceText 为 std::wstring，targetBuffer/charCount 为协议包字段；
        // - 处理：复用 Raw 版本完成截断复制；
        // - 返回：无返回值，仅写入目标缓冲。
        void CopyWideText(const std::wstring& sourceText, wchar_t* const targetBuffer, const std::size_t charCount)
        {
            CopyWideTextRaw(sourceText.c_str(), targetBuffer, charCount, sourceText.size());
        }

        std::uint64_t QueryNow100ns()
        {
            FILETIME fileTimeValue{};
            ::GetSystemTimeAsFileTime(&fileTimeValue);

            ULARGE_INTEGER largeValue{};
            largeValue.LowPart = fileTimeValue.dwLowDateTime;
            largeValue.HighPart = fileTimeValue.dwHighDateTime;
            return static_cast<std::uint64_t>(largeValue.QuadPart);
        }

        void ClosePipeLocked(bool discardBuffered = false)
        {
            // 先清空无锁快照，确保 Hook 侧不会在关闭阶段继续把该句柄当作可用监控管道。
            g_pipeHandleValue.store(0);
            if (g_pipeHandle != INVALID_HANDLE_VALUE)
            {
                // 关闭阶段不再 FlushFileBuffers，避免 UI 已断开或停止读取时把目标线程卡死。
                (void)::CancelIoEx(g_pipeHandle, nullptr);
                APIMON_DIAG_MARK("pipe-close",g_lastCoverageRevision.load(),discardBuffered ? 1 : 0);
                // DisconnectNamedPipe discards unread bytes. Graceful close
                // leaves completed writes available to the reader until EOF.
                if(discardBuffered)(void)::DisconnectNamedPipe(g_pipeHandle);
                ::CloseHandle(g_pipeHandle);
                g_pipeHandle = INVALID_HANDLE_VALUE;
            }
        }

        // WritePendingPacketLocked 作用：
        // - 输入：packetValue 为固定大小的协议事件包，调用者已独占 g_pipeLock；
        // - 处理：使用专属 OVERLAPPED 和停止事件等待写完成，停止时由发送线程取消本次 I/O；
        // - 返回：完整写入一个包时为 true，断开、取消或任意 I/O 错误时为 false。
        bool WritePendingPacketLocked(const ks::winapi_monitor::ApiMonitorEventPacket& packetValue)
        {
            if (g_pipeHandle == INVALID_HANDLE_VALUE || g_senderStopFlag.load())
            {
                return false;
            }

            HANDLE writeEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (writeEvent == nullptr)
            {
                return false;
            }

            OVERLAPPED overlappedValue{};
            overlappedValue.hEvent = writeEvent;
            DWORD bytesWritten = 0;
            bool writeComplete = false;
            const BOOL writeStarted = ::WriteFile(
                g_pipeHandle,
                &packetValue,
                static_cast<DWORD>(sizeof(packetValue)),
                nullptr,
                &overlappedValue);
            if (writeStarted != FALSE)
            {
                writeComplete = ::GetOverlappedResult(
                    g_pipeHandle,
                    &overlappedValue,
                    &bytesWritten,
                    FALSE) != FALSE;
            }
            else if (::GetLastError() == ERROR_IO_PENDING)
            {
                HANDLE waitHandles[] = { writeEvent, g_senderStopEvent };
                const DWORD waitResult = ::WaitForMultipleObjects(
                    static_cast<DWORD>(std::size(waitHandles)),
                    waitHandles,
                    FALSE,
                    INFINITE);
                if (waitResult == WAIT_OBJECT_0)
                {
                    writeComplete = ::GetOverlappedResult(
                        g_pipeHandle,
                        &overlappedValue,
                        &bytesWritten,
                        FALSE) != FALSE;
                }
                else
                {
                    // 停止信号或等待异常时，必须先完成取消并等待实际完成，
                    // 否则栈上的 OVERLAPPED/packetValue 离开作用域后仍可能被内核访问。
                    (void)::CancelIoEx(g_pipeHandle, &overlappedValue);
                    (void)::WaitForSingleObject(writeEvent, INFINITE);
                    (void)::GetOverlappedResult(
                        g_pipeHandle,
                        &overlappedValue,
                        &bytesWritten,
                        FALSE);
                }
            }

            ::CloseHandle(writeEvent);
            if (writeComplete) APIMON_DIAG_ADD(PipeBytes,bytesWritten);
            return writeComplete && bytesWritten == sizeof(packetValue);
        }

        // EnsureSenderThreadStarted 作用：
        // - 输入：errorTextOut 接收创建停止事件或发送线程失败的诊断，可为空；
        // - 处理：准备队列唤醒/停止事件，并在当前会话没有发送线程时创建唯一发送线程；
        // - 返回：发送线程可用时为 true，创建任何必要同步对象失败时为 false。
        bool EnsureSenderThreadStarted(std::wstring* errorTextOut)
        {
            if (g_queueWakeEvent == nullptr)
            {
                g_queueWakeEvent = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
                if (g_queueWakeEvent == nullptr)
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = L"CreateEventW for monitor queue wake failed. error=" + std::to_wstring(::GetLastError());
                    }
                    return false;
                }
            }
            if (g_senderStopEvent == nullptr)
            {
                g_senderStopEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
                if (g_senderStopEvent == nullptr)
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = L"CreateEventW for monitor sender stop failed. error=" + std::to_wstring(::GetLastError());
                    }
                    return false;
                }
            }

            std::unique_ptr<std::thread>& senderThread = SenderThreadSlot();
            if (senderThread != nullptr && senderThread->joinable())
            {
                return true;
            }

            g_senderStopFlag.store(false);
            (void)::ResetEvent(g_senderStopEvent);
            senderThread = std::make_unique<std::thread>([]() {
                // senderBypassScope：
                // - 输入：无；
                // - 处理：后台 pipe 发送线程的 WaitForSingleObject/WriteFile/CloseHandle 等基础 API 不进入监控事件流；
                // - 返回：无返回值，作用域覆盖线程完整生命周期。
                // - 原因：Agent 内部发送线程若被自身 hook 监控，会形成 NtWaitForSingleObject 等事件风暴，严重时拖垮目标进程。
                ScopedInlineHookInternalBypass senderBypassScope;
                while (!g_senderStopFlag.load())
                {
                    (void)FlushCoverageSnapshot(64);
                    (void)FlushPendingMonitorEvents(256);
                    if (g_senderStopFlag.load())
                    {
                        break;
                    }

                    const auto latest=LatestCoverageSnapshot();
                    ::AcquireSRWLockShared(&g_queueLock);
                    const bool pendingEvents=g_pendingPacketCount!=0;
                    ::ReleaseSRWLockShared(&g_queueLock);
                    if(pendingEvents||g_sendingCoverage||(latest&&latest->revision!=g_lastCoverageRevision.load())) {
                        // A 12k-item snapshot must not incur a 25ms sleep after
                        // every 64 packets. Pipe backpressure already bounds us.
                        ::Sleep(0);continue;
                    }

                    const DWORD waitResult = (g_queueWakeEvent != nullptr)
                        ? ::WaitForSingleObject(g_queueWakeEvent, 25)
                        : WAIT_TIMEOUT;
                    if (waitResult != WAIT_OBJECT_0 && waitResult != WAIT_TIMEOUT)
                    {
                        ::Sleep(25);
                    }
                }
            });
            return true;
        }

        bool WaitForClientConnection(const HANDLE pipeHandle, const MonitorConfig& configValue, std::wstring* errorTextOut)
        {
            HANDLE connectEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (connectEvent == nullptr)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"CreateEventW for ConnectNamedPipe failed. error=" + std::to_wstring(::GetLastError());
                }
                return false;
            }

            OVERLAPPED overlappedValue{};
            overlappedValue.hEvent = connectEvent;

            const auto cancelAndDrainPendingConnect = [&]() {
                DWORD ignoredTransferredBytes = 0;
                (void)::CancelIoEx(pipeHandle, &overlappedValue);
                (void)::GetOverlappedResult(pipeHandle, &overlappedValue, &ignoredTransferredBytes, TRUE);
            };

            bool connected = false;
            const BOOL connectOk = ::ConnectNamedPipe(pipeHandle, &overlappedValue);
            if (connectOk != FALSE)
            {
                connected = true;
            }
            else
            {
                DWORD lastError = ::GetLastError();
                if (lastError == ERROR_PIPE_CONNECTED)
                {
                    connected = true;
                    ::SetEvent(connectEvent);
                }
                else if (lastError == ERROR_IO_PENDING)
                {
                    DWORD waitedMs = 0;
                    while (waitedMs < kPipeConnectTimeoutMs)
                    {
                        if (StopRequested() || IsStopFlagPresent(configValue))
                        {
                            cancelAndDrainPendingConnect();
                            if (errorTextOut != nullptr)
                            {
                                *errorTextOut = L"ConnectNamedPipe canceled because stop was requested before UI connected.";
                            }
                            ::CloseHandle(connectEvent);
                            return false;
                        }

                        const DWORD waitResult = ::WaitForSingleObject(connectEvent, kPipeConnectPollMs);
                        if (waitResult == WAIT_OBJECT_0)
                        {
                            DWORD transferredBytes = 0;
                            if (::GetOverlappedResult(pipeHandle, &overlappedValue, &transferredBytes, FALSE) != FALSE
                                || ::GetLastError() == ERROR_PIPE_CONNECTED)
                            {
                                connected = true;
                                break;
                            }

                            lastError = ::GetLastError();
                            if (errorTextOut != nullptr)
                            {
                                *errorTextOut = L"ConnectNamedPipe overlapped completion failed. error=" + std::to_wstring(lastError);
                            }
                            ::CloseHandle(connectEvent);
                            return false;
                        }
                        if (waitResult != WAIT_TIMEOUT)
                        {
                            cancelAndDrainPendingConnect();
                            if (errorTextOut != nullptr)
                            {
                                *errorTextOut = L"WaitForSingleObject for ConnectNamedPipe failed. error=" + std::to_wstring(::GetLastError());
                            }
                            ::CloseHandle(connectEvent);
                            return false;
                        }

                        waitedMs += kPipeConnectPollMs;
                    }

                    if (!connected)
                    {
                        cancelAndDrainPendingConnect();
                        if (errorTextOut != nullptr)
                        {
                            *errorTextOut = L"ConnectNamedPipe timed out waiting for WinAPIDock client.";
                        }
                        ::CloseHandle(connectEvent);
                        return false;
                    }
                }
                else
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = L"ConnectNamedPipe start failed. error=" + std::to_wstring(lastError);
                    }
                    ::CloseHandle(connectEvent);
                    return false;
                }
            }

            ::CloseHandle(connectEvent);
            return connected;
        }
    }

    bool StartMonitorPipeServer(const MonitorConfig& configValue, std::wstring* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        DWORD pipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT;
#ifdef PIPE_REJECT_REMOTE_CLIENTS
        pipeMode |= PIPE_REJECT_REMOTE_CLIENTS;
#endif

        PipeSecurity pipeSecurity;
        SECURITY_ATTRIBUTES pipeAttributes{};
        SECURITY_ATTRIBUTES* const securityAttributes = configValue.controllerSid.empty() ? nullptr : &pipeAttributes;
        if (securityAttributes != nullptr
            && !BuildPipeSecurity(configValue.controllerSid, pipeSecurity, pipeAttributes, errorTextOut))
        {
            return false;
        }

        HANDLE pipeHandle = ::CreateNamedPipeW(
            configValue.pipeName.c_str(),
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
            pipeMode,
            1,
            64 * 1024,
            64 * 1024,
            0,
            securityAttributes);
        if (pipeHandle == INVALID_HANDLE_VALUE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"CreateNamedPipeW failed. error=" + std::to_wstring(::GetLastError());
            }
            return false;
        }

        if (!WaitForClientConnection(pipeHandle, configValue, errorTextOut))
        {
            ::CloseHandle(pipeHandle);
            return false;
        }

        ::AcquireSRWLockExclusive(&g_pipeLock);
        ClosePipeLocked();
        g_pipeHandle = pipeHandle;
        g_pipeHandleValue.store(reinterpret_cast<std::uintptr_t>(pipeHandle));
        ::ReleaseSRWLockExclusive(&g_pipeLock);
        BeginCoverageSession(configValue);
        g_sendingCoverage.reset();
        g_lastCoverageRevision = 0;
        if (!EnsureSenderThreadStarted(errorTextOut))
        {
            ::AcquireSRWLockExclusive(&g_pipeLock);
            ClosePipeLocked();
            ::ReleaseSRWLockExclusive(&g_pipeLock);
            return false;
        }
        return true;
    }

    bool DrainMonitorPipeServer(const DWORD timeoutMs)
    {
        APIMON_DIAG_MARK("drain-begin",timeoutMs,g_lastCoverageRevision.load());
        if (g_queueWakeEvent) ::SetEvent(g_queueWakeEvent);
        const ULONGLONG deadline = ::GetTickCount64() + timeoutMs;
        while (::GetTickCount64() < deadline)
        {
            if (!g_pipeHandleValue.load()) return false;
            const auto snapshot = LatestCoverageSnapshot();
            ::AcquireSRWLockShared(&g_queueLock);
            const bool empty = g_pendingPacketCount == 0;
            ::ReleaseSRWLockShared(&g_queueLock);
            if (empty && g_eventFlushesActive.load() == 0
                && (!snapshot || g_lastCoverageRevision.load() == snapshot->revision)) {
                APIMON_DIAG_MARK("drain-complete",snapshot ? snapshot->revision : 0,g_lastCoverageRevision.load());
                return true;
            }
            ::Sleep(10);
        }
        APIMON_DIAG_MARK("drain-timeout",LatestCoverageSnapshot() ? LatestCoverageSnapshot()->revision : 0,g_lastCoverageRevision.load());
        return false;
    }

    void StopMonitorPipeServer()
    {
        g_senderStopFlag.store(true);
        if (g_senderStopEvent != nullptr)
        {
            // 发送线程正在等待异步 WriteFile 时会自行 CancelIoEx 并回收 OVERLAPPED；
            // 这里不能先关闭 g_pipeHandle，否则发送线程可能在已失效句柄上取完成状态。
            ::SetEvent(g_senderStopEvent);
        }
        if (g_queueWakeEvent != nullptr)
        {
            ::SetEvent(g_queueWakeEvent);
        }
        std::unique_ptr<std::thread>& senderThread = SenderThreadSlot();
        if (senderThread != nullptr && senderThread->joinable())
        {
            senderThread->join();
        }
        senderThread.reset();
        APIMON_DIAG_MARK("sender-stopped",g_sendingCoverage ? g_sendingCoverage->items.size() : 0,g_coverageSendIndex);
        EndCoverageSession();
        g_sendingCoverage.reset();

        ::AcquireSRWLockExclusive(&g_pipeLock);
        ClosePipeLocked();
        ::ReleaseSRWLockExclusive(&g_pipeLock);

        ::AcquireSRWLockExclusive(&g_queueLock);
        g_pendingPacketHead = 0;
        g_pendingPacketCount = 0;
        g_droppedPacketCount.store(0);
        g_reportedDroppedPacketCount = 0;
        ::ReleaseSRWLockExclusive(&g_queueLock);
    }

    bool SendMonitorEvent(
        const ks::winapi_monitor::EventCategory categoryValue,
        const wchar_t* moduleName,
        const wchar_t* apiName,
        const std::int32_t resultCode,
        const std::wstring& detailText)
    {
        return SendMonitorEventRaw(
            categoryValue,
            moduleName,
            apiName,
            resultCode,
            detailText.c_str());
    }

    static bool QueueMonitorEventRaw(
        const ks::winapi_monitor::EventCategory categoryValue,
        const wchar_t* moduleName,
        const wchar_t* apiName,
        const std::int32_t resultCode,
        const wchar_t* detailText,
        const ks::winapi_monitor::EventResultKind resultKind,
        const ks::winapi_monitor::EventKind eventKind, const std::uint64_t operationId, const std::uint32_t apiId,
        const std::uint64_t finalCoverageRevision,
        const bool hasReturnValue = false, const std::uint64_t returnBits = 0,
        const bool hasDuration = false, const std::uint64_t duration100ns = 0)
    {
        if ((StopRequested() || EventsPaused()) && categoryValue != ks::winapi_monitor::EventCategory::Internal) return false;
        ks::winapi_monitor::ApiMonitorEventPacket packetValue{};
        packetValue.pid = static_cast<std::uint32_t>(::GetCurrentProcessId());
        packetValue.tid = static_cast<std::uint32_t>(::GetCurrentThreadId());
        packetValue.timestamp100ns = QueryNow100ns();
        packetValue.category = static_cast<std::uint32_t>(categoryValue);
        packetValue.resultCode = resultCode;
        packetValue.resultKind = static_cast<std::uint32_t>(resultKind);
        packetValue.eventKind = static_cast<std::uint32_t>(eventKind);
        packetValue.apiId = apiId ? apiId : FindApiDefinitionId(moduleName, apiName);
        packetValue.operationId = operationId;
        packetValue.snapshotRevision = finalCoverageRevision;
        if (hasReturnValue && eventKind == ks::winapi_monitor::EventKind::ApiCall
            && categoryValue != ks::winapi_monitor::EventCategory::Internal)
        {
            packetValue.snapshotIndex = ks::winapi_monitor::kApiCallReturnValueMarker;
            packetValue.hookAddress = returnBits;
        }
        if (hasDuration && eventKind == ks::winapi_monitor::EventKind::ApiCall
            && categoryValue != ks::winapi_monitor::EventCategory::Internal)
        {
            packetValue.snapshotCount = ks::winapi_monitor::kApiCallDurationMarker;
            packetValue.snapshotRevision = duration100ns;
        }
        packetValue.sessionIdentity = CurrentMonitorSessionIdentity();
        std::memcpy(packetValue.definitionSha256, kDefinitionSha256, sizeof(packetValue.definitionSha256));

        const std::size_t detailLimit = std::min<std::size_t>(
            ActiveConfig().detailLimitChars,
            ks::winapi_monitor::kMaxDetailChars - 1);
        CopyWideTextRaw(moduleName, packetValue.moduleName, std::size(packetValue.moduleName), ks::winapi_monitor::kMaxModuleNameChars - 1);
        CopyWideTextRaw(apiName, packetValue.apiName, std::size(packetValue.apiName), ks::winapi_monitor::kMaxApiNameChars - 1);
        CopyWideTextRaw(detailText, packetValue.detailText, std::size(packetValue.detailText), detailLimit);
        StoreHookCallStack(packetValue);

        ::AcquireSRWLockExclusive(&g_queueLock);
        const std::size_t capacity = categoryValue == ks::winapi_monitor::EventCategory::Internal
            ? kMaxPendingPacketCount : kMaxPendingPacketCount - kControlPacketReserve;
        if (g_pendingPacketCount >= capacity)
        {
            g_droppedPacketCount.fetch_add(1);
            ::ReleaseSRWLockExclusive(&g_queueLock);
            return false;
        }

        const std::size_t tailIndex = (g_pendingPacketHead + g_pendingPacketCount) % kMaxPendingPacketCount;
        g_pendingPacketRing[tailIndex] = packetValue;
        ++g_pendingPacketCount;
        ::ReleaseSRWLockExclusive(&g_queueLock);
        if (g_queueWakeEvent != nullptr)
        {
            ::SetEvent(g_queueWakeEvent);
        }
        return true;
    }

    bool SendMonitorEventRaw(ks::winapi_monitor::EventCategory category,const wchar_t* module,const wchar_t* api,
        std::int32_t result,const wchar_t* detail,ks::winapi_monitor::EventResultKind resultKind,
        ks::winapi_monitor::EventKind kind,std::uint64_t operation,std::uint32_t id)
    {
        return QueueMonitorEventRaw(category,module,api,result,detail,resultKind,kind,operation,id,0);
    }

    bool SendMonitorEventRawWithReturn(ks::winapi_monitor::EventCategory category,
        const wchar_t* module, const wchar_t* api, std::int32_t result,
        const wchar_t* detail, std::uint64_t returnBits)
    {
        return QueueMonitorEventRaw(category, module, api, result, detail,
            ks::winapi_monitor::EventResultKind::StatusCode,
            ks::winapi_monitor::EventKind::ApiCall, 0, 0, 0, true, returnBits);
    }

    bool SendMonitorEventRawWithMetrics(ks::winapi_monitor::EventCategory category,
        const wchar_t* module, const wchar_t* api, std::int32_t result,
        const wchar_t* detail, bool hasReturnValue, std::uint64_t returnBits,
        bool hasDuration, std::uint64_t duration100ns, std::uint32_t apiId,
        ks::winapi_monitor::EventResultKind resultKind, std::uint64_t operationId)
    {
        return QueueMonitorEventRaw(category, module, api, result, detail,
            resultKind,
            ks::winapi_monitor::EventKind::ApiCall, operationId, apiId, 0,
            hasReturnValue, returnBits, hasDuration, duration100ns);
    }

    bool SendHooksRemovedEvent(const std::wstring& detail)
    {
        const auto final=LatestCoverageSnapshot();
        return QueueMonitorEventRaw(ks::winapi_monitor::EventCategory::Internal,L"Agent",L"HooksRemoved",0,detail.c_str(),
            ks::winapi_monitor::EventResultKind::StatusCode,ks::winapi_monitor::EventKind::ApiCall,0,0,final?final->revision:0);
    }

    std::uint32_t FlushCoverageSnapshot(const std::uint32_t budget)
    {
        // Only the sender thread calls this. It bypasses the ordinary event ring entirely.
        auto latest = LatestCoverageSnapshot();
        if (!g_sendingCoverage && latest && latest->revision != g_lastCoverageRevision.load())
        { g_sendingCoverage = std::move(latest); g_coverageSendIndex = 0; }
        if (!g_sendingCoverage) return 0;
        std::uint32_t sent = 0;
        ::AcquireSRWLockExclusive(&g_pipeLock);
        while (sent < budget && g_sendingCoverage)
        {
            ks::winapi_monitor::ApiMonitorEventPacket packet{};
            const auto count = static_cast<std::uint32_t>(g_sendingCoverage->items.size());
            if (g_coverageSendIndex == 0)
                packet.eventKind = static_cast<std::uint32_t>(ks::winapi_monitor::EventKind::CoverageBegin);
            else if (g_coverageSendIndex <= count)
                packet = g_sendingCoverage->items[g_coverageSendIndex - 1];
            else
            {
                packet.eventKind = static_cast<std::uint32_t>(ks::winapi_monitor::EventKind::CoverageEnd);
                packet.snapshotIndex = count;
            }
            packet.pid = ::GetCurrentProcessId();
            packet.sessionIdentity = g_sendingCoverage->session;
            packet.snapshotRevision = g_sendingCoverage->revision;
            packet.snapshotCount = count;
            std::memcpy(packet.definitionSha256, kDefinitionSha256, sizeof(packet.definitionSha256));
            if (!WritePendingPacketLocked(packet))
            {
                g_sendingCoverage.reset();
                ClosePipeLocked();
                break;
            }
            ++sent;
            if (++g_coverageSendIndex == count + 2)
            {
                g_lastCoverageRevision = g_sendingCoverage->revision;
                g_sendingCoverage.reset();
            }
        }
        ::ReleaseSRWLockExclusive(&g_pipeLock);
        return sent;
    }

    std::uint32_t FlushPendingMonitorEvents(const std::uint32_t maxPacketsToFlush)
    {
        struct FlushScope
        {
            FlushScope() { g_eventFlushesActive.fetch_add(1); }
            ~FlushScope() { g_eventFlushesActive.fetch_sub(1); }
        } activeFlush;
        if (maxPacketsToFlush == 0)
        {
            return 0;
        }

        auto& packetBatch = g_flushPacketBatch;
        std::size_t flushCount = 0;

        ::AcquireSRWLockExclusive(&g_pipeLock);
        ::AcquireSRWLockExclusive(&g_queueLock);
        flushCount = std::min<std::size_t>(
            std::min<std::size_t>(maxPacketsToFlush, kMaxFlushBatchCount),
            g_pendingPacketCount);
        for (std::size_t indexValue = 0; indexValue < flushCount; ++indexValue)
        {
            packetBatch[indexValue] = g_pendingPacketRing[g_pendingPacketHead];
            g_pendingPacketHead = (g_pendingPacketHead + 1) % kMaxPendingPacketCount;
            --g_pendingPacketCount;
        }
        ::ReleaseSRWLockExclusive(&g_queueLock);

        if (g_pipeHandle == INVALID_HANDLE_VALUE)
        {
            g_droppedPacketCount.fetch_add(flushCount);
            ::ReleaseSRWLockExclusive(&g_pipeLock);
            return 0;
        }

        const std::uint64_t dropped = g_droppedPacketCount.load();
        if (dropped != g_reportedDroppedPacketCount)
        {
            ks::winapi_monitor::ApiMonitorEventPacket notice{};
            notice.pid = ::GetCurrentProcessId();
            notice.tid = ::GetCurrentThreadId();
            notice.timestamp100ns = QueryNow100ns();
            notice.sessionIdentity = CurrentMonitorSessionIdentity();
            std::memcpy(notice.definitionSha256, kDefinitionSha256, sizeof(notice.definitionSha256));
            notice.category = static_cast<std::uint32_t>(ks::winapi_monitor::EventCategory::Internal);
            CopyWideText(L"Agent", notice.moduleName, std::size(notice.moduleName));
            CopyWideText(L"EventsDropped", notice.apiName, std::size(notice.apiName));
            CopyWideText(std::to_wstring(dropped), notice.detailText, std::size(notice.detailText));
            if (!WritePendingPacketLocked(notice))
            {
                g_droppedPacketCount.fetch_add(flushCount);
                ClosePipeLocked();
                ::ReleaseSRWLockExclusive(&g_pipeLock);
                return 0;
            }
            g_reportedDroppedPacketCount = dropped;
        }

        std::uint32_t flushedCount = 0;
        for (std::size_t indexValue = 0; indexValue < flushCount; ++indexValue)
        {
            const auto& packetValue = packetBatch[indexValue];
            if (!WritePendingPacketLocked(packetValue))
            {
                g_droppedPacketCount.fetch_add(flushCount - indexValue);
                ClosePipeLocked();
                break;
            }
            ++flushedCount;
        }

        ::ReleaseSRWLockExclusive(&g_pipeLock);
        return flushedCount;
    }

    bool IsMonitorPipeHandle(const HANDLE handleValue)
    {
        if (handleValue == nullptr || handleValue == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        const std::uintptr_t monitorPipeHandleValue = g_pipeHandleValue.load();
        if (monitorPipeHandleValue == 0)
        {
            return false;
        }

        // 通过无锁快照比较句柄值，避免 FlushPendingMonitorEvents 持有 g_pipeLock 时，
        // WriteFile Hook 再次尝试加锁造成同线程重入死锁。
        return reinterpret_cast<std::uintptr_t>(handleValue) == monitorPipeHandleValue;
    }
}
