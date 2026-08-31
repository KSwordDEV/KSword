#include "ArkDriverClient.h"

#include "ArkDriverError.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cwchar>
#include <cstring>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "../ksword/string/string.h"

namespace ksword::ark
{
    namespace
    {
        constexpr unsigned long kDefaultShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;

        // g_r0NotificationMutex：串行化全局 handler、去重时间与在途回调计数。
        std::mutex g_r0NotificationMutex;
        // g_r0NotificationIdleCondition：让窗口析构等待所有已取得租约的工作线程。
        std::condition_variable g_r0NotificationIdleCondition;
        // g_r0NotificationInvocationCount：记录已经复制 handler、尚未执行完毕的回调数量。
        std::size_t g_r0NotificationInvocationCount = 0U;
        DriverClient::R0UnavailableHandler g_r0UnavailableHandler;
        std::chrono::steady_clock::time_point g_lastR0UnavailableNotification;
        DriverClient::R0PermissionRequiredHandler g_r0PermissionRequiredHandler;
        std::chrono::steady_clock::time_point g_lastR0PermissionNotification;

        // finishR0NotificationInvocation：
        // - 在一个锁外 handler 调用结束时归还租约；
        // - 最后一个租约归还后唤醒正在析构的主窗口。
        void finishR0NotificationInvocation()
        {
            std::lock_guard<std::mutex> lock(g_r0NotificationMutex);
            if (g_r0NotificationInvocationCount > 0U)
            {
                --g_r0NotificationInvocationCount;
            }
            if (g_r0NotificationInvocationCount == 0U)
            {
                g_r0NotificationIdleCondition.notify_all();
            }
        }

        // R0NotificationInvocationLease：
        // - handler 从全局状态复制成功后取得一个在途租约；
        // - 析构自动归还，确保 handler 抛出异常时等待者也不会永久阻塞。
        class R0NotificationInvocationLease final
        {
        public:
            R0NotificationInvocationLease() = default;
            R0NotificationInvocationLease(const R0NotificationInvocationLease&) = delete;
            R0NotificationInvocationLease& operator=(const R0NotificationInvocationLease&) = delete;

            ~R0NotificationInvocationLease()
            {
                if (m_active)
                {
                    finishR0NotificationInvocation();
                }
            }

            // activate：仅在全局计数已经递增后标记本地租约，调用方无须传入参数。
            void activate() noexcept
            {
                m_active = true;
            }

        private:
            // m_active：区分提前返回路径与真正取得全局在途引用的调用。
            bool m_active = false;
        };

        bool isR0DriverNotEnabledError(const unsigned long win32Error)
        {
            // ERROR_FILE_NOT_FOUND 是 CreateFile(\\\\.\\KswordARKLog) 在服务未运行时的正常表现。
            // PATH_NOT_FOUND 覆盖异常的设备命名空间状态；其余错误仍交给调用方按权限、签名或
            // 协议问题处理，避免把“驱动已启用但操作失败”误导为“请启用 R0”。
            return win32Error == ERROR_FILE_NOT_FOUND || win32Error == ERROR_PATH_NOT_FOUND;
        }

        void notifyR0DriverUnavailable(const unsigned long win32Error)
        {
            if (!isR0DriverNotEnabledError(win32Error))
            {
                return;
            }

            DriverClient::R0UnavailableHandler handler;
            R0NotificationInvocationLease invocationLease;
            {
                std::lock_guard<std::mutex> lock(g_r0NotificationMutex);
                const auto now = std::chrono::steady_clock::now();
                if (!g_r0UnavailableHandler ||
                    (g_lastR0UnavailableNotification.time_since_epoch().count() != 0 &&
                        now - g_lastR0UnavailableNotification < std::chrono::seconds(2)))
                {
                    return;
                }
                g_lastR0UnavailableNotification = now;
                handler = g_r0UnavailableHandler;
                ++g_r0NotificationInvocationCount;
                invocationLease.activate();
            }

            // 不在锁内执行 UI 回调；租约保证清空 handler 后仍会等待本次调用结束。
            handler(win32Error);
        }

        bool isR0PermissionRequiredError(const unsigned long win32Error)
        {
            return win32Error == ERROR_ACCESS_DENIED ||
                win32Error == ERROR_PRIVILEGE_NOT_HELD ||
                win32Error == ERROR_ELEVATION_REQUIRED ||
                win32Error == ERROR_NOT_ALL_ASSIGNED;
        }

        void notifyR0PermissionRequired(const unsigned long win32Error)
        {
            if (!isR0PermissionRequiredError(win32Error))
            {
                return;
            }

            DriverClient::R0PermissionRequiredHandler handler;
            R0NotificationInvocationLease invocationLease;
            {
                std::lock_guard<std::mutex> lock(g_r0NotificationMutex);
                const auto now = std::chrono::steady_clock::now();
                if (!g_r0PermissionRequiredHandler ||
                    (g_lastR0PermissionNotification.time_since_epoch().count() != 0 &&
                        now - g_lastR0PermissionNotification < std::chrono::seconds(2)))
                {
                    return;
                }
                g_lastR0PermissionNotification = now;
                handler = g_r0PermissionRequiredHandler;
                ++g_r0NotificationInvocationCount;
                invocationLease.activate();
            }
            handler(win32Error);
        }

        std::string fixedAnsiToString(const char* textBuffer, const std::size_t maxBytes)
        {
            if (textBuffer == nullptr || maxBytes == 0U)
            {
                return {};
            }

            std::size_t length = 0U;
            while (length < maxBytes && textBuffer[length] != '\0')
            {
                ++length;
            }
            return std::string(textBuffer, textBuffer + length);
        }

        std::string fixedUtf16ToUtf8String(const unsigned short* textBuffer, const std::size_t maxChars)
        {
            // textBuffer 用途：接收共享协议中的 UTF-16 code unit 数组。
            // maxChars 用途：限定最大扫描长度，避免缺少结尾 NUL 时越界。
            if (textBuffer == nullptr || maxChars == 0U)
            {
                return {};
            }

            std::size_t length = 0U;
            while (length < maxChars && textBuffer[length] != 0U)
            {
                ++length;
            }
            if (length == 0U)
            {
                return {};
            }

            std::wstring wideText;
            wideText.reserve(length);
            for (std::size_t index = 0; index < length; ++index)
            {
                wideText.push_back(static_cast<wchar_t>(textBuffer[index]));
            }
            return ks::str::Utf16ToUtf8(wideText);
        }

        std::size_t processInjectRequestHeaderSize()
        {
            return sizeof(KSWORD_ARK_INJECT_PROCESS_REQUEST) - sizeof(unsigned char);
        }

        bool isUnsupportedIoctlError(const unsigned long win32Error)
        {
            // 输入：DeviceIoControl 失败后的 Win32 错误码。
            // 处理：匹配旧驱动未注册 IOCTL 或 KMDF 分发拒绝未知控制码时的常见返回值。
            // 返回：true 表示调用方可将其视为“驱动过旧/缺入口”，而不是 R0 语义失败。
            return win32Error == ERROR_INVALID_FUNCTION ||
                win32Error == ERROR_NOT_SUPPORTED ||
                win32Error == ERROR_INVALID_PARAMETER;
        }

        ProcessInjectResult makeProcessInjectInputFailure(
            const std::uint32_t processId,
            const std::uint32_t injectType,
            const unsigned long win32Error,
            const std::string& message)
        {
            ProcessInjectResult result{};
            result.processId = processId;
            result.injectType = injectType;
            result.io.ok = false;
            result.io.win32Error = win32Error;
            result.io.message = message;
            return result;
        }

        void copyProcessInjectResponse(
            ProcessInjectResult& result,
            const KSWORD_ARK_INJECT_PROCESS_RESPONSE& response)
        {
            result.version = static_cast<std::uint32_t>(response.version);
            result.processId = static_cast<std::uint32_t>(response.processId);
            result.injectType = static_cast<std::uint32_t>(response.injectType);
            result.status = static_cast<std::uint32_t>(response.status);
            result.flags = static_cast<std::uint32_t>(response.flags);
            result.bytesWritten = static_cast<std::uint32_t>(response.bytesWritten);
            result.lastStatus = static_cast<long>(response.lastStatus);
            result.waitStatus = static_cast<long>(response.waitStatus);
            result.entryPointAddress = static_cast<std::uint64_t>(response.entryPointAddress);
            result.parameterAddress = static_cast<std::uint64_t>(response.parameterAddress);
            result.remoteBaseAddress = static_cast<std::uint64_t>(response.remoteBaseAddress);
            result.remoteRegionSize = static_cast<std::uint64_t>(response.remoteRegionSize);
            result.io.ntStatus = result.lastStatus;
        }

        std::string buildProcessInjectMessage(const ProcessInjectResult& result)
        {
            std::ostringstream stream;
            stream << "pid=" << result.processId
                << ", type=" << result.injectType
                << ", status=" << result.status
                << ", flags=0x" << std::hex << std::uppercase << result.flags
                << ", written=" << std::dec << result.bytesWritten
                << ", remote=0x" << std::hex << result.remoteBaseAddress
                << ", region=0x" << result.remoteRegionSize
                << ", entry=0x" << result.entryPointAddress
                << ", param=0x" << result.parameterAddress
                << ", lastStatus=0x" << static_cast<unsigned long>(result.lastStatus)
                << ", waitStatus=0x" << static_cast<unsigned long>(result.waitStatus);
            return stream.str();
        }
    }

    void DriverClient::setR0UnavailableHandler(R0UnavailableHandler handler)
    {
        std::lock_guard<std::mutex> lock(g_r0NotificationMutex);
        g_r0UnavailableHandler = std::move(handler);
        g_lastR0UnavailableNotification = {};
    }

    void DriverClient::setR0PermissionRequiredHandler(R0PermissionRequiredHandler handler)
    {
        std::lock_guard<std::mutex> lock(g_r0NotificationMutex);
        g_r0PermissionRequiredHandler = std::move(handler);
        g_lastR0PermissionNotification = {};
    }

    void DriverClient::clearR0NotificationHandlersAndWait()
    {
        // 先在同一临界区撤销两个入口，后续工作线程无法再取得新租约。
        std::unique_lock<std::mutex> lock(g_r0NotificationMutex);
        g_r0UnavailableHandler = {};
        g_r0PermissionRequiredHandler = {};
        g_lastR0UnavailableNotification = {};
        g_lastR0PermissionNotification = {};

        // 已复制 handler 的线程会在锁外完成投递，并由租约析构唤醒这里。
        g_r0NotificationIdleCondition.wait(lock, []()
            {
                return g_r0NotificationInvocationCount == 0U;
            });
    }

    DriverHandle::DriverHandle(const HANDLE handleValue) noexcept
        : m_handle(handleValue)
    {
    }

    DriverHandle::~DriverHandle()
    {
        reset();
    }

    DriverHandle::DriverHandle(DriverHandle&& other) noexcept
        : m_handle(other.release())
    {
    }

    DriverHandle& DriverHandle::operator=(DriverHandle&& other) noexcept
    {
        if (this != &other)
        {
            reset(other.release());
        }
        return *this;
    }

    bool DriverHandle::isValid() const noexcept
    {
        return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
    }

    HANDLE DriverHandle::native() const noexcept
    {
        return m_handle;
    }

    HANDLE DriverHandle::release() noexcept
    {
        HANDLE detachedHandle = m_handle;
        m_handle = INVALID_HANDLE_VALUE;
        return detachedHandle;
    }

    void DriverHandle::reset(const HANDLE newHandle) noexcept
    {
        if (m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(m_handle);
        }
        m_handle = newHandle;
    }

    DriverHandle DriverClient::open(const unsigned long desiredAccess) const
    {
        DriverHandle handle(::CreateFileW(
            KSWORD_ARK_LOG_WIN32_PATH,
            desiredAccess,
            kDefaultShareMode,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));
        if (!handle.isValid())
        {
            const unsigned long openError = ::GetLastError();
            notifyR0DriverUnavailable(openError);
            notifyR0PermissionRequired(openError);
        }
        return handle;
    }

    DriverHandle DriverClient::openSilently(const unsigned long desiredAccess) const
    {
        return DriverHandle(::CreateFileW(
            KSWORD_ARK_LOG_WIN32_PATH,
            desiredAccess,
            kDefaultShareMode,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));
    }

    DriverHandle DriverClient::openOverlapped(const unsigned long desiredAccess) const
    {
        DriverHandle handle(::CreateFileW(
            KSWORD_ARK_LOG_WIN32_PATH,
            desiredAccess,
            kDefaultShareMode,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            nullptr));
        if (!handle.isValid())
        {
            const unsigned long openError = ::GetLastError();
            notifyR0DriverUnavailable(openError);
            notifyR0PermissionRequired(openError);
        }
        return handle;
    }

    IoResult DriverClient::deviceIoControl(
        const unsigned long ioControlCode,
        void* const inputBuffer,
        const unsigned long inputBytes,
        void* const outputBuffer,
        const unsigned long outputBytes,
        DriverHandle* const existingHandle) const
    {
        DriverHandle localHandle;
        DriverHandle* activeHandle = existingHandle;
        if (activeHandle == nullptr)
        {
            localHandle = open();
            activeHandle = &localHandle;
        }

        if (activeHandle == nullptr || !activeHandle->isValid())
        {
            const unsigned long openError = ::GetLastError();
            notifyR0PermissionRequired(openError);
            IoResult result = makeWin32IoResult(false, openError, 0, "CreateFileW(KswordARK)");
            return result;
        }

        DWORD bytesReturned = 0;
        const BOOL ioctlOk = ::DeviceIoControl(
            activeHandle->native(),
            ioControlCode,
            inputBuffer,
            inputBytes,
            outputBuffer,
            outputBytes,
            &bytesReturned,
            nullptr);
        const unsigned long ioctlError = ioctlOk ? ERROR_SUCCESS : ::GetLastError();
        if (ioctlOk == FALSE)
        {
            notifyR0PermissionRequired(ioctlError);
        }
        return makeWin32IoResult(ioctlOk != FALSE, ioctlError, bytesReturned, "KswordARK DeviceIoControl");
    }

    AsyncIoResult DriverClient::deviceIoControlAsync(
        DriverHandle& handle,
        const unsigned long ioControlCode,
        void* const inputBuffer,
        const unsigned long inputBytes,
        void* const outputBuffer,
        const unsigned long outputBytes,
        OVERLAPPED* const overlapped) const
    {
        AsyncIoResult result{};
        if (!handle.isValid())
        {
            result.issued = false;
            result.win32Error = ERROR_INVALID_HANDLE;
            return result;
        }

        DWORD bytesReturned = 0;
        const BOOL ioctlOk = ::DeviceIoControl(
            handle.native(),
            ioControlCode,
            inputBuffer,
            inputBytes,
            outputBuffer,
            outputBytes,
            &bytesReturned,
            overlapped);
        result.issued = (ioctlOk != FALSE);
        result.win32Error = result.issued ? ERROR_SUCCESS : ::GetLastError();
        if (!result.issued)
        {
            notifyR0PermissionRequired(result.win32Error);
        }
        result.bytesReturned = bytesReturned;
        return result;
    }

    IoResult DriverClient::terminateProcess(
        const std::uint32_t processId,
        const long exitStatus,
        const std::uint64_t expectedCreateTime100ns) const
    {
        DriverHandle handle = open();
        return terminateProcess(handle, processId, exitStatus, expectedCreateTime100ns);
    }

    IoResult DriverClient::terminateProcess(
        DriverHandle& handle,
        const std::uint32_t processId,
        const long exitStatus,
        const std::uint64_t expectedCreateTime100ns) const
    {
        KSWORD_ARK_TERMINATE_PROCESS_REQUEST request{};
        request.processId = processId;
        request.exitStatus = exitStatus;
        request.expectedCreateTime100ns = expectedCreateTime100ns;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_TERMINATE_PROCESS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0,
            &handle);

        std::ostringstream stream;
        stream << "pid=" << processId
            << ", createTime100ns=" << expectedCreateTime100ns
            << ", bytesReturned=" << result.bytesReturned;
        if (result.ok)
        {
            stream << ", ioctl=ok";
        }
        else
        {
            stream << ", ioctl=fail, error=" << result.win32Error;
            if (result.win32Error == ERROR_ACCESS_DENIED)
            {
                stream << " (driver returned failing NTSTATUS, check R0 log for status)";
            }
        }
        result.message = stream.str();
        return result;
    }

    IoResult DriverClient::terminateThread(
        const std::uint32_t threadId,
        const std::uint32_t processId,
        const long exitStatus) const
    {
        DriverHandle handle = open();
        return terminateThread(handle, threadId, processId, exitStatus);
    }

    IoResult DriverClient::terminateThread(
        DriverHandle& handle,
        const std::uint32_t threadId,
        const std::uint32_t processId,
        const long exitStatus) const
    {
        KSWORD_ARK_TERMINATE_THREAD_REQUEST request{};
        request.threadId = threadId;
        request.processId = processId;
        request.exitStatus = exitStatus;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_TERMINATE_THREAD,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0,
            &handle);

        std::ostringstream stream;
        stream << "tid=" << threadId << ", pid=" << processId << ", bytesReturned=" << result.bytesReturned;
        if (result.ok)
        {
            stream << ", ioctl=ok";
        }
        else
        {
            stream << ", ioctl=fail, error=" << result.win32Error;
            if (result.win32Error == ERROR_ACCESS_DENIED)
            {
                stream << " (driver returned failing NTSTATUS, check R0 log for status)";
            }
        }
        result.message = stream.str();
        return result;
    }

    IoResult DriverClient::setThreadSuspended(
        const std::uint32_t threadId,
        const std::uint32_t processId,
        const bool suspended) const
    {
        DriverHandle handle = open();
        return setThreadSuspended(handle, threadId, processId, suspended);
    }

    IoResult DriverClient::setThreadSuspended(
        DriverHandle& handle,
        const std::uint32_t threadId,
        const std::uint32_t processId,
        const bool suspended) const
    {
        KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST request{};
        request.threadId = threadId;
        request.processId = processId;
        request.action = suspended
            ? KSWORD_ARK_THREAD_SUSPEND_ACTION_SUSPEND
            : KSWORD_ARK_THREAD_SUSPEND_ACTION_RESUME;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0,
            &handle);

        std::ostringstream stream;
        stream << "tid=" << threadId
            << ", pid=" << processId
            << ", action=" << (suspended ? "suspend" : "resume")
            << ", bytesReturned=" << result.bytesReturned;
        if (result.ok)
        {
            stream << ", ioctl=ok";
        }
        else
        {
            stream << ", ioctl=fail, error=" << result.win32Error;
            if (result.win32Error == ERROR_ACCESS_DENIED)
            {
                stream << " (driver returned failing NTSTATUS, check R0 log for status)";
            }
        }
        result.message = stream.str();
        return result;
    }

    IoResult DriverClient::controlDriverThread(
        const std::uint32_t threadId,
        const std::uint64_t expectedStartAddress,
        const std::uint64_t expectedCreateTime100ns,
        const unsigned long action,
        const unsigned long terminateMethod,
        const bool uiConfirmed) const
    {
        DriverHandle handle = open();
        return controlDriverThread(
            handle,
            threadId,
            expectedStartAddress,
            expectedCreateTime100ns,
            action,
            terminateMethod,
            uiConfirmed);
    }

    IoResult DriverClient::controlDriverThread(
        DriverHandle& handle,
        const std::uint32_t threadId,
        const std::uint64_t expectedStartAddress,
        const std::uint64_t expectedCreateTime100ns,
        const unsigned long action,
        const unsigned long terminateMethod,
        const bool uiConfirmed) const
    {
        KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST request{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_DRIVER_THREAD_CONTROL_PROTOCOL_VERSION;
        request.threadId = threadId;
        request.action = action;
        request.flags = uiConfirmed
            ? KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_UI_CONFIRMED
            : 0UL;
        request.terminateMethod = terminateMethod;
        request.expectedStartAddress = expectedStartAddress;
        request.expectedCreateTime100ns = expectedCreateTime100ns;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_DRIVER_THREAD,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0,
            &handle);

        const char* actionText = action == KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND
            ? "suspend"
            : (action == KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME ? "resume" : "terminate");
        const char* rawApiText = "none";
        switch (terminateMethod)
        {
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER:
            rawApiText = "PspTerminateThreadByPointer";
            break;
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT:
            rawApiText = "ZwTerminateThread/NtTerminateThread";
            break;
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC:
            rawApiText = "KeInsertQueueApc(Normal Kernel APC)->PsTerminateSystemThread";
            break;
        case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC:
            rawApiText = "KeInsertQueueApc(Special Kernel APC)->KeInsertQueueApc(Normal Kernel APC)->PsTerminateSystemThread";
            break;
        default:
            break;
        }
        std::ostringstream stream;
        stream << "tid=" << threadId
            << ", pid=4"
            << ", start=0x" << std::hex << expectedStartAddress << std::dec
            << ", createTime100ns=" << expectedCreateTime100ns
            << ", action=" << actionText
            << ", terminateMethod=" << terminateMethod
            << ", rawApi=" << rawApiText
            << ", bytesReturned=" << result.bytesReturned;
        if (result.ok)
        {
            stream << ", ioctl=ok";
            if (terminateMethod == KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC ||
                terminateMethod == KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC)
            {
                stream << ", apc=queued (delivery/termination is asynchronous and not guaranteed)";
            }
        }
        else
        {
            stream << ", ioctl=fail, error=" << result.win32Error;
            if (result.win32Error == ERROR_ACCESS_DENIED)
            {
                stream << " (driver safety/module validation denied the request; check R0 log)";
            }
        }
        result.message = stream.str();
        return result;
    }

    IoResult DriverClient::experimentalReturnToFirmware() const
    {
        KSWORD_ARK_EXPERIMENTAL_RETURN_TO_FIRMWARE_REQUEST request{};
        request.action = KSWORD_ARK_FIRMWARE_RETURN_ACTION_HAL_REBOOT_ROUTINE;
        request.flags = KSWORD_ARK_FIRMWARE_RETURN_FLAG_UI_CONFIRMED;
        request.confirmationToken = KSWORD_ARK_FIRMWARE_RETURN_CONFIRMATION_TOKEN;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_EXPERIMENTAL_RETURN_TO_FIRMWARE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0);

        std::ostringstream stream;
        stream << "rawApi=HalReturnToFirmware(HalRebootRoutine)"
            << ", scope=machine"
            << ", bytesReturned=" << result.bytesReturned;
        if (result.ok)
        {
            stream << ", ioctl=returned-success";
        }
        else
        {
            stream << ", ioctl=fail-or-returned, error=" << result.win32Error;
        }
        result.message = stream.str();
        return result;
    }

    IoResult DriverClient::suspendProcess(const std::uint32_t processId) const
    {
        KSWORD_ARK_SUSPEND_PROCESS_REQUEST request{};
        request.processId = processId;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_SUSPEND_PROCESS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0);

        std::ostringstream stream;
        stream << "pid=" << processId << ", bytesReturned=" << result.bytesReturned;
        stream << (result.ok ? ", ioctl=ok" : ", ioctl=fail, error=" + std::to_string(result.win32Error));
        result.message = stream.str();
        return result;
    }

    IoResult DriverClient::setProcessProtection(const std::uint32_t processId, const std::uint8_t protectionLevel) const
    {
        KSWORD_ARK_SET_PPL_LEVEL_REQUEST request{};
        request.processId = processId;
        request.protectionLevel = protectionLevel;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_SET_PPL_LEVEL,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0);

        std::ostringstream stream;
        stream << "pid=" << processId
            << ", protectionLevel=0x" << std::hex << std::uppercase << static_cast<unsigned int>(protectionLevel)
            << std::dec << ", bytesReturned=" << result.bytesReturned;
        stream << (result.ok ? ", ioctl=ok" : ", ioctl=fail, error=" + std::to_string(result.win32Error));
        result.message = stream.str();
        return result;
    }

    ProcessIntegrityResult DriverClient::setProcessIntegrity(
        const std::uint32_t processId,
        const unsigned long integrityRid) const
    {
        // 输入：目标 PID 和 Mandatory Label RID。
        // 处理：构造固定 R0 协议包；驱动端先通过 ZwOpenProcessTokenEx/ZwSetInformationToken 写 TokenIntegrityLevel，
        // 失败时可由 R0 DynData/PDB 私有 Token 字段路径兜底。
        // 返回：ProcessIntegrityResult，io.ok 代表通信成功，status/lastStatus 代表 R0 语义结果。
        ProcessIntegrityResult integrityResult{};
        KSWORD_ARK_SET_PROCESS_INTEGRITY_REQUEST request{};
        KSWORD_ARK_SET_PROCESS_INTEGRITY_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_PROCESS_INTEGRITY_PROTOCOL_VERSION;
        request.processId = processId;
        request.integrityRid = integrityRid;
        request.flags = KSWORD_ARK_PROCESS_INTEGRITY_FLAG_UI_CONFIRMED;

        integrityResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!integrityResult.io.ok)
        {
            integrityResult.unsupported = isUnsupportedIoctlError(integrityResult.io.win32Error);
            integrityResult.io.message = integrityResult.unsupported
                ? "IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY) failed, error=" +
                    std::to_string(integrityResult.io.win32Error);
            return integrityResult;
        }
        if (integrityResult.io.bytesReturned < sizeof(response))
        {
            integrityResult.io.ok = false;
            integrityResult.io.message =
                "process-integrity response too small, bytesReturned=" +
                std::to_string(integrityResult.io.bytesReturned);
            return integrityResult;
        }

        integrityResult.version = static_cast<std::uint32_t>(response.version);
        integrityResult.processId = static_cast<std::uint32_t>(response.processId);
        integrityResult.integrityRid = static_cast<std::uint32_t>(response.integrityRid);
        integrityResult.status = static_cast<std::uint32_t>(response.status);
        integrityResult.lastStatus = static_cast<long>(response.lastStatus);
        integrityResult.io.ntStatus = integrityResult.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << integrityResult.processId
            << ", rid=0x" << std::hex << std::uppercase << integrityResult.integrityRid
            << std::dec << ", status=" << integrityResult.status
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(integrityResult.lastStatus)
            << std::dec << ", bytesReturned=" << integrityResult.io.bytesReturned;
        integrityResult.io.message = stream.str();
        return integrityResult;
    }

    ProcessTokenPrivilegeResult DriverClient::queryProcessTokenPrivileges(
        const std::uint32_t processId,
        const std::uint64_t expectedCreateTime100ns) const
    {
        // 输入：目标 PID 与可选创建时间。
        // 处理：发出 QUERY 请求并把固定 LUID/属性数组转换成 C++ 结果。
        // 返回：可区分旧驱动、通信失败、截断快照和完整快照的结果。
        ProcessTokenPrivilegeResult queryResult{};
        KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_REQUEST request{};
        KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
        request.operation = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_QUERY;
        request.processId = processId;
        request.expectedCreateTime100ns = expectedCreateTime100ns;

        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!queryResult.io.ok)
        {
            queryResult.unsupported = isUnsupportedIoctlError(queryResult.io.win32Error);
            queryResult.io.message = queryResult.unsupported
                ? "IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES query) failed, error=" +
                    std::to_string(queryResult.io.win32Error);
            return queryResult;
        }
        if (queryResult.io.bytesReturned < sizeof(response))
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "process-token privilege query response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }
        if (response.size != sizeof(response) ||
            response.version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION ||
            response.operation != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_QUERY ||
            response.processId != processId ||
            response.entryCount > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES ||
            response.status < KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ||
            response.status > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED ||
            ((response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ||
              response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL) &&
             (response.processCreateTime100ns == 0U ||
              (expectedCreateTime100ns != 0U &&
               response.processCreateTime100ns != expectedCreateTime100ns))))
        {
            queryResult.io.ok = false;
            queryResult.io.win32Error = ERROR_INVALID_DATA;
            queryResult.io.message = "process-token privilege query response header is invalid";
            return queryResult;
        }

        queryResult.version = static_cast<std::uint32_t>(response.version);
        queryResult.operation = static_cast<std::uint32_t>(response.operation);
        queryResult.processId = static_cast<std::uint32_t>(response.processId);
        queryResult.status = static_cast<std::uint32_t>(response.status);
        queryResult.lastStatus = static_cast<long>(response.lastStatus);
        queryResult.processCreateTime100ns =
            static_cast<std::uint64_t>(response.processCreateTime100ns);
        const std::uint32_t entryCount = std::min<std::uint32_t>(
            static_cast<std::uint32_t>(response.entryCount),
            KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES);
        queryResult.entries.reserve(entryCount);
        for (std::uint32_t entryIndex = 0; entryIndex < entryCount; ++entryIndex)
        {
            ProcessTokenPrivilegeEntry entry{};
            entry.luidLowPart = static_cast<std::uint32_t>(response.entries[entryIndex].luidLowPart);
            entry.luidHighPart = static_cast<std::int32_t>(response.entries[entryIndex].luidHighPart);
            entry.attributes = static_cast<std::uint32_t>(response.entries[entryIndex].attributes);
            entry.action = static_cast<std::uint32_t>(response.entries[entryIndex].action);
            queryResult.entries.push_back(entry);
        }
        queryResult.io.ntStatus = queryResult.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << queryResult.processId
            << ", operation=query, status=" << queryResult.status
            << ", entries=" << queryResult.entries.size()
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(queryResult.lastStatus)
            << std::dec << ", bytesReturned=" << queryResult.io.bytesReturned;
        queryResult.io.message = stream.str();
        return queryResult;
    }

    ProcessTokenPrivilegeResult DriverClient::adjustProcessTokenPrivileges(
        const std::uint32_t processId,
        const std::uint64_t expectedCreateTime100ns,
        const std::vector<ProcessTokenPrivilegeEntry>& edits,
        const bool allowRemove) const
    {
        // 输入：稳定进程身份、已解析 LUID 的调整项和移除许可。
        // 处理：本地约束协议上限/动作，再发出 confirmation-gated ADJUST 请求。
        // 返回：包含 appliedCount/failedIndex 的结果，调用方可明确提示部分成功。
        ProcessTokenPrivilegeResult adjustResult{};
        if (processId <= 4U || expectedCreateTime100ns == 0U
            || edits.empty()
            || edits.size() > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES)
        {
            adjustResult.io.win32Error = ERROR_INVALID_PARAMETER;
            adjustResult.io.message = "process-token privilege edit count is invalid";
            return adjustResult;
        }

        KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_REQUEST request{};
        KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
        request.operation = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_ADJUST;
        request.processId = processId;
        request.flags = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_UI_CONFIRMED |
            (allowRemove ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_ALLOW_REMOVE : 0UL);
        request.entryCount = static_cast<unsigned long>(edits.size());
        request.expectedCreateTime100ns = expectedCreateTime100ns;
        request.confirmationToken = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_CONFIRMATION_TOKEN;

        for (std::size_t entryIndex = 0; entryIndex < edits.size(); ++entryIndex)
        {
            const ProcessTokenPrivilegeEntry& sourceEntry = edits[entryIndex];
            const bool validAction =
                sourceEntry.action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE ||
                sourceEntry.action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE ||
                sourceEntry.action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE;
            if (!validAction ||
                (sourceEntry.action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE && !allowRemove))
            {
                adjustResult.io.win32Error = ERROR_INVALID_PARAMETER;
                adjustResult.io.message = "process-token privilege edit action is invalid";
                return adjustResult;
            }
            request.entries[entryIndex].luidLowPart = sourceEntry.luidLowPart;
            request.entries[entryIndex].luidHighPart = sourceEntry.luidHighPart;
            request.entries[entryIndex].attributes = sourceEntry.attributes;
            request.entries[entryIndex].action = sourceEntry.action;
        }

        adjustResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!adjustResult.io.ok)
        {
            adjustResult.unsupported = isUnsupportedIoctlError(adjustResult.io.win32Error);
            adjustResult.io.message = adjustResult.unsupported
                ? "IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES adjust) failed, error=" +
                    std::to_string(adjustResult.io.win32Error);
            return adjustResult;
        }
        if (adjustResult.io.bytesReturned < sizeof(response))
        {
            adjustResult.io.ok = false;
            adjustResult.io.message =
                "process-token privilege adjust response too small, bytesReturned=" +
                std::to_string(adjustResult.io.bytesReturned);
            return adjustResult;
        }
        if (response.size != sizeof(response) ||
            response.version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION ||
            response.operation != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_ADJUST ||
            response.processId != processId ||
            response.requestedCount != static_cast<unsigned long>(edits.size()) ||
            response.appliedCount > response.requestedCount ||
            response.status < KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ||
            response.status > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED ||
            (response.failedIndex != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FAILED_INDEX_NONE &&
             response.failedIndex >= response.requestedCount) ||
            (response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK &&
             (response.appliedCount != response.requestedCount ||
              response.failedIndex != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FAILED_INDEX_NONE)) ||
            (response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL &&
             (response.appliedCount == 0U ||
              response.appliedCount >= response.requestedCount ||
              response.failedIndex != response.appliedCount)) ||
            (response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED &&
             response.appliedCount != 0U) ||
            ((response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ||
              response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL) &&
             response.processCreateTime100ns != expectedCreateTime100ns) ||
            (response.processCreateTime100ns != 0U &&
             response.processCreateTime100ns != expectedCreateTime100ns))
        {
            adjustResult.io.ok = false;
            adjustResult.io.win32Error = ERROR_INVALID_DATA;
            adjustResult.io.message = "process-token privilege adjust response header is invalid";
            return adjustResult;
        }

        adjustResult.version = static_cast<std::uint32_t>(response.version);
        adjustResult.operation = static_cast<std::uint32_t>(response.operation);
        adjustResult.processId = static_cast<std::uint32_t>(response.processId);
        adjustResult.status = static_cast<std::uint32_t>(response.status);
        adjustResult.requestedCount = static_cast<std::uint32_t>(response.requestedCount);
        adjustResult.appliedCount = static_cast<std::uint32_t>(response.appliedCount);
        adjustResult.failedIndex = static_cast<std::uint32_t>(response.failedIndex);
        adjustResult.lastStatus = static_cast<long>(response.lastStatus);
        adjustResult.processCreateTime100ns =
            static_cast<std::uint64_t>(response.processCreateTime100ns);
        adjustResult.io.ntStatus = adjustResult.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << adjustResult.processId
            << ", operation=adjust, status=" << adjustResult.status
            << ", requested=" << adjustResult.requestedCount
            << ", applied=" << adjustResult.appliedCount
            << ", failedIndex=" << adjustResult.failedIndex
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(adjustResult.lastStatus)
            << std::dec << ", bytesReturned=" << adjustResult.io.bytesReturned;
        adjustResult.io.message = stream.str();
        return adjustResult;
    }

    ProcessTokenPrivilegeQueryResult DriverClient::queryProcessTokenPrivileges(
        const std::uint32_t processId,
        DriverHandle* const existingHandle) const
    {
        ProcessTokenPrivilegeQueryResult result{};
        KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_REQUEST request{};
        constexpr std::size_t responseHeaderSize =
            KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE_HEADER_SIZE;
        constexpr std::size_t responseCapacity =
            responseHeaderSize +
            (KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES *
             sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY));
        std::vector<std::uint8_t> responseBuffer(responseCapacity, 0U);

        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
        request.processId = processId;

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()),
            existingHandle);
        if (!result.io.ok)
        {
            result.unsupported = isUnsupportedIoctlError(result.io.win32Error);
            result.io.message = "IOCTL_KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES failed";
            return result;
        }
        if (result.io.bytesReturned < responseHeaderSize)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "process-token-privilege query response too small";
            return result;
        }

        const auto* response = reinterpret_cast<
            const KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_RESPONSE*>(
                responseBuffer.data());
        const std::size_t requiredBytes = responseHeaderSize +
            (static_cast<std::size_t>(response->returnedCount) *
             sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY));
        if (response->version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION ||
            response->entrySize != sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY) ||
            response->returnedCount > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES ||
            response->size < requiredBytes ||
            result.io.bytesReturned < requiredBytes)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "process-token-privilege query response invalid";
            return result;
        }

        result.version = static_cast<std::uint32_t>(response->version);
        result.processId = static_cast<std::uint32_t>(response->processId);
        result.status = static_cast<std::uint32_t>(response->status);
        result.totalCount = static_cast<std::uint32_t>(response->totalCount);
        result.returnedCount = static_cast<std::uint32_t>(response->returnedCount);
        result.lastStatus = static_cast<long>(response->lastStatus);
        result.io.ntStatus = result.lastStatus;
        result.entries.reserve(result.returnedCount);
        for (std::uint32_t index = 0; index < result.returnedCount; ++index)
        {
            ProcessTokenPrivilegeEntry entry{};
            entry.luidLowPart = static_cast<std::uint32_t>(response->entries[index].luidLowPart);
            entry.luidHighPart = static_cast<std::int32_t>(response->entries[index].luidHighPart);
            entry.attributes = static_cast<std::uint32_t>(response->entries[index].attributes);
            result.entries.push_back(entry);
        }

        std::ostringstream stream;
        stream << "pid=" << result.processId
            << ", status=" << result.status
            << ", count=" << result.returnedCount << "/" << result.totalCount
            << ", lastStatus=0x" << std::hex
            << static_cast<unsigned long>(result.lastStatus);
        result.io.message = stream.str();
        return result;
    }

    ProcessTokenPrivilegeAdjustResult DriverClient::adjustProcessTokenPrivilege(
        const std::uint32_t processId,
        const std::uint32_t luidLowPart,
        const std::int32_t luidHighPart,
        const bool enabled,
        DriverHandle* const existingHandle) const
    {
        ProcessTokenPrivilegeAdjustResult result{};
        KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_REQUEST request{};
        KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_RESPONSE response{};

        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
        request.processId = processId;
        request.luidLowPart = luidLowPart;
        request.luidHighPart = luidHighPart;
        request.action = enabled
            ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE
            : KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE;
        request.flags = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_UI_CONFIRMED;

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)),
            existingHandle);
        if (!result.io.ok)
        {
            result.unsupported = isUnsupportedIoctlError(result.io.win32Error);
            result.io.message = "IOCTL_KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE failed";
            return result;
        }
        if (result.io.bytesReturned < sizeof(response) ||
            response.size != sizeof(response) ||
            response.version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "process-token-privilege adjust response invalid";
            return result;
        }

        result.version = static_cast<std::uint32_t>(response.version);
        result.processId = static_cast<std::uint32_t>(response.processId);
        result.luidLowPart = static_cast<std::uint32_t>(response.luidLowPart);
        result.luidHighPart = static_cast<std::int32_t>(response.luidHighPart);
        result.action = static_cast<std::uint32_t>(response.action);
        result.status = static_cast<std::uint32_t>(response.status);
        result.lastStatus = static_cast<long>(response.lastStatus);
        result.io.ntStatus = result.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << result.processId
            << ", luid=" << result.luidHighPart << ":" << result.luidLowPart
            << ", action=" << result.action
            << ", status=" << result.status
            << ", lastStatus=0x" << std::hex
            << static_cast<unsigned long>(result.lastStatus);
        result.io.message = stream.str();
        return result;
    }

    ProcessVisibilityResult DriverClient::setProcessVisibility(
        const std::uint32_t processId,
    const unsigned long action,
    const unsigned long flags) const
    {
        // 作用：请求 R0 执行进程可见性动作（真实摘链/恢复）。
        // 返回：解析后的响应；IOCTL 失败时 io.ok=false 且 message 带 Win32 错误。
        ProcessVisibilityResult visibilityResult{};
        KSWORD_ARK_SET_PROCESS_VISIBILITY_REQUEST request{};
        KSWORD_ARK_SET_PROCESS_VISIBILITY_RESPONSE response{};
        request.processId = processId;
        request.action = action;
        request.flags = flags;

        visibilityResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!visibilityResult.io.ok)
        {
            visibilityResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY) failed, error=" +
                std::to_string(visibilityResult.io.win32Error);
            return visibilityResult;
        }
        if (visibilityResult.io.bytesReturned < sizeof(response))
        {
            visibilityResult.io.ok = false;
            visibilityResult.io.message =
                "process visibility response too small, bytesReturned=" +
                std::to_string(visibilityResult.io.bytesReturned);
            return visibilityResult;
        }

        visibilityResult.version = static_cast<std::uint32_t>(response.version);
        visibilityResult.processId = static_cast<std::uint32_t>(response.processId);
        visibilityResult.status = static_cast<std::uint32_t>(response.status);
        visibilityResult.hiddenCount = static_cast<std::uint32_t>(response.hiddenCount);
        visibilityResult.lastStatus = static_cast<long>(response.lastStatus);
        visibilityResult.io.ntStatus = visibilityResult.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << visibilityResult.processId
            << ", action=" << action
            << ", flags=0x" << std::hex << std::uppercase << flags << std::dec
            << ", status=" << visibilityResult.status
            << ", hiddenCount=" << visibilityResult.hiddenCount
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(visibilityResult.lastStatus);
        visibilityResult.io.message = stream.str();
        return visibilityResult;
    }

    ProcessEnumResult DriverClient::enumerateProcesses(const unsigned long flags) const
    {
        return enumerateProcesses(flags, nullptr);
    }

    ProcessEnumResult DriverClient::enumerateProcesses(
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        ProcessEnumResult enumResult{};
        KSWORD_ARK_ENUM_PROCESS_REQUEST request{};
        request.flags = flags;

        std::vector<std::uint8_t> responseBuffer(1024U * 1024U, 0U);
        enumResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_PROCESS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()),
            existingHandle);
        if (!enumResult.io.ok)
        {
            enumResult.io.message = "DeviceIoControl(IOCTL_KSWORD_ARK_ENUM_PROCESS) failed, error=" + std::to_string(enumResult.io.win32Error);
            return enumResult;
        }

        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_ENUM_PROCESS_RESPONSE) - sizeof(KSWORD_ARK_PROCESS_ENTRY);
        if (enumResult.io.bytesReturned < headerSize)
        {
            enumResult.io.ok = false;
            enumResult.io.message = "enum-process response too small, bytesReturned=" + std::to_string(enumResult.io.bytesReturned);
            return enumResult;
        }

        const auto* responseHeader = reinterpret_cast<const KSWORD_ARK_ENUM_PROCESS_RESPONSE*>(responseBuffer.data());
        // v1MinimumEntrySize 用途：
        // - 只要求老协议固定头字段完整，确保 protocol v1 驱动仍可被解析；
        // - imageName 长度来自协议常量，避免对空指针成员表达式产生编译器差异。
        constexpr std::size_t v1MinimumEntrySize =
            sizeof(unsigned long) * 4U + 16U;
        if (responseHeader->entrySize < v1MinimumEntrySize)
        {
            enumResult.io.ok = false;
            enumResult.io.message = "enum-process entry size invalid, entrySize=" + std::to_string(responseHeader->entrySize);
            return enumResult;
        }

        enumResult.version = responseHeader->version;
        enumResult.totalCount = responseHeader->totalCount;
        enumResult.returnedCount = responseHeader->returnedCount;
        const std::size_t availableCount = (enumResult.io.bytesReturned - headerSize) / static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t parsedCount = std::min<std::size_t>(static_cast<std::size_t>(responseHeader->returnedCount), availableCount);
        enumResult.entries.reserve(parsedCount);
        for (std::size_t index = 0; index < parsedCount; ++index)
        {
            const std::size_t entryOffset = headerSize + (index * static_cast<std::size_t>(responseHeader->entrySize));
            const auto* entry = reinterpret_cast<const KSWORD_ARK_PROCESS_ENTRY*>(responseBuffer.data() + entryOffset);
            ProcessEntry parsedEntry{};
            parsedEntry.processId = static_cast<std::uint32_t>(entry->processId);
            parsedEntry.parentProcessId = static_cast<std::uint32_t>(entry->parentProcessId);
            parsedEntry.flags = static_cast<std::uint32_t>(entry->flags);
            parsedEntry.imageName = fixedAnsiToString(entry->imageName, sizeof(entry->imageName));
            constexpr std::size_t v2EntrySize = offsetof(
                KSWORD_ARK_PROCESS_ENTRY,
                creationTime100ns);
            if (responseHeader->entrySize >= v2EntrySize)
            {
                parsedEntry.sessionId = static_cast<std::uint32_t>(entry->sessionId);
                parsedEntry.fieldFlags = static_cast<std::uint32_t>(entry->fieldFlags);
                parsedEntry.r0Status = static_cast<std::uint32_t>(entry->r0Status);
                parsedEntry.sessionSource = static_cast<std::uint32_t>(entry->sessionSource);
                parsedEntry.protection = static_cast<std::uint8_t>(entry->protection);
                parsedEntry.signatureLevel = static_cast<std::uint8_t>(entry->signatureLevel);
                parsedEntry.sectionSignatureLevel = static_cast<std::uint8_t>(entry->sectionSignatureLevel);
                parsedEntry.protectionSource = static_cast<std::uint32_t>(entry->protectionSource);
                parsedEntry.signatureLevelSource = static_cast<std::uint32_t>(entry->signatureLevelSource);
                parsedEntry.sectionSignatureLevelSource = static_cast<std::uint32_t>(entry->sectionSignatureLevelSource);
                parsedEntry.objectTableSource = static_cast<std::uint32_t>(entry->objectTableSource);
                parsedEntry.sectionObjectSource = static_cast<std::uint32_t>(entry->sectionObjectSource);
                parsedEntry.imagePathSource = static_cast<std::uint32_t>(entry->imagePathSource);
                parsedEntry.protectionOffset = static_cast<std::uint32_t>(entry->protectionOffset);
                parsedEntry.signatureLevelOffset = static_cast<std::uint32_t>(entry->signatureLevelOffset);
                parsedEntry.sectionSignatureLevelOffset = static_cast<std::uint32_t>(entry->sectionSignatureLevelOffset);
                parsedEntry.objectTableOffset = static_cast<std::uint32_t>(entry->objectTableOffset);
                parsedEntry.sectionObjectOffset = static_cast<std::uint32_t>(entry->sectionObjectOffset);
                parsedEntry.objectTableAddress = static_cast<std::uint64_t>(entry->objectTableAddress);
                parsedEntry.sectionObjectAddress = static_cast<std::uint64_t>(entry->sectionObjectAddress);
                parsedEntry.dynDataCapabilityMask = static_cast<std::uint64_t>(entry->dynDataCapabilityMask);
                parsedEntry.imagePath = fixedUtf16ToUtf8String(
                    entry->imagePath,
                    KSWORD_ARK_PROCESS_IMAGE_PATH_CHARS);
            }
            if (responseHeader->entrySize >= sizeof(KSWORD_ARK_PROCESS_ENTRY))
            {
                parsedEntry.creationTime100ns =
                    static_cast<std::uint64_t>(entry->creationTime100ns);
            }
            enumResult.entries.push_back(std::move(parsedEntry));
        }

        std::ostringstream stream;
        stream << "version=" << enumResult.version
            << ", total=" << enumResult.totalCount
            << ", returned=" << enumResult.returnedCount
            << ", parsed=" << enumResult.entries.size()
            << ", bytesReturned=" << enumResult.io.bytesReturned;
        enumResult.io.message = stream.str();
        return enumResult;
    }

    ProcessSpecialFlagsResult DriverClient::setProcessSpecialFlags(
        const std::uint32_t processId,
        const unsigned long action,
        const unsigned long flags,
        const std::uint64_t expectedCreateTime100ns) const
    {
        // 作用：请求 R0 设置 BreakOnTermination 或禁用目标进程线程 APC 插入。
        // 返回：解析后的固定响应；IOCTL 失败时 io.ok=false。
        ProcessSpecialFlagsResult specialResult{};
        KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_REQUEST request{};
        KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_RESPONSE response{};
        request.version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
        request.processId = processId;
        request.action = action;
        request.flags = flags;
        request.expectedCreateTime100ns = expectedCreateTime100ns;

        specialResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!specialResult.io.ok)
        {
            specialResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS) failed, error=" +
                std::to_string(specialResult.io.win32Error);
            return specialResult;
        }
        if (specialResult.io.bytesReturned < sizeof(response))
        {
            specialResult.io.ok = false;
            specialResult.io.message =
                "process-special response too small, bytesReturned=" +
                std::to_string(specialResult.io.bytesReturned);
            return specialResult;
        }

        specialResult.version = static_cast<std::uint32_t>(response.version);
        specialResult.processId = static_cast<std::uint32_t>(response.processId);
        specialResult.action = static_cast<std::uint32_t>(response.action);
        specialResult.status = static_cast<std::uint32_t>(response.status);
        specialResult.appliedFlags = static_cast<std::uint32_t>(response.appliedFlags);
        specialResult.touchedThreadCount = static_cast<std::uint32_t>(response.touchedThreadCount);
        specialResult.lastStatus = static_cast<long>(response.lastStatus);
        specialResult.io.ntStatus = specialResult.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << specialResult.processId
            << ", action=" << specialResult.action
            << ", createTime100ns=" << expectedCreateTime100ns
            << ", status=" << specialResult.status
            << ", applied=0x" << std::hex << specialResult.appliedFlags
            << ", touchedThreads=" << std::dec << specialResult.touchedThreadCount
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(specialResult.lastStatus);
        specialResult.io.message = stream.str();
        return specialResult;
    }

    ProcessDkomResult DriverClient::dkomProcess(
        const std::uint32_t processId,
        const unsigned long action,
        const unsigned long flags) const
    {
        // 作用：请求 R0 执行进程 DKOM 操作，当前用于从 PspCidTable 删除 PID。
        // 返回：解析后的固定响应；诊断地址只用于展示，不作为后续凭据。
        ProcessDkomResult dkomResult{};
        KSWORD_ARK_DKOM_PROCESS_REQUEST request{};
        KSWORD_ARK_DKOM_PROCESS_RESPONSE response{};
        request.version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
        request.processId = processId;
        request.action = action;
        request.flags = flags;

        dkomResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_DKOM_PROCESS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!dkomResult.io.ok)
        {
            dkomResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_DKOM_PROCESS) failed, error=" +
                std::to_string(dkomResult.io.win32Error);
            return dkomResult;
        }
        if (dkomResult.io.bytesReturned < sizeof(response))
        {
            dkomResult.io.ok = false;
            dkomResult.io.message =
                "process-dkom response too small, bytesReturned=" +
                std::to_string(dkomResult.io.bytesReturned);
            return dkomResult;
        }

        dkomResult.version = static_cast<std::uint32_t>(response.version);
        dkomResult.processId = static_cast<std::uint32_t>(response.processId);
        dkomResult.action = static_cast<std::uint32_t>(response.action);
        dkomResult.status = static_cast<std::uint32_t>(response.status);
        dkomResult.removedEntries = static_cast<std::uint32_t>(response.removedEntries);
        dkomResult.lastStatus = static_cast<long>(response.lastStatus);
        dkomResult.pspCidTableAddress = static_cast<std::uint64_t>(response.pspCidTableAddress);
        dkomResult.processObjectAddress = static_cast<std::uint64_t>(response.processObjectAddress);
        dkomResult.io.ntStatus = dkomResult.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << dkomResult.processId
            << ", action=" << dkomResult.action
            << ", status=" << dkomResult.status
            << ", removed=" << dkomResult.removedEntries
            << ", pspCidTable=0x" << std::hex << dkomResult.pspCidTableAddress
            << ", eprocess=0x" << dkomResult.processObjectAddress
            << ", lastStatus=0x" << static_cast<unsigned long>(dkomResult.lastStatus);
        dkomResult.io.message = stream.str();
        return dkomResult;
    }

    ProcessInjectResult DriverClient::injectProcessDll(
        const std::uint32_t processId,
        const std::wstring& dllPath,
        const unsigned long flags) const
    {
        if (dllPath.empty())
        {
            return makeProcessInjectInputFailure(
                processId,
                KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH,
                ERROR_INVALID_PARAMETER,
                "DLL path is empty");
        }
        if (dllPath.size() + 1U >
            KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES / sizeof(wchar_t))
        {
            return makeProcessInjectInputFailure(
                processId,
                KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH,
                ERROR_BAD_LENGTH,
                "DLL path is larger than R0 inject payload limit");
        }

        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        if (kernel32Module == nullptr)
        {
            const unsigned long lastError = ::GetLastError();
            const unsigned long win32Error = lastError != ERROR_SUCCESS
                ? lastError
                : ERROR_MOD_NOT_FOUND;
            return makeProcessInjectInputFailure(
                processId,
                KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH,
                win32Error,
                "GetModuleHandleW(kernel32.dll) failed, error=" + std::to_string(win32Error));
        }

        FARPROC loadLibraryAddress = ::GetProcAddress(kernel32Module, "LoadLibraryW");
        if (loadLibraryAddress == nullptr)
        {
            const unsigned long lastError = ::GetLastError();
            const unsigned long win32Error = lastError != ERROR_SUCCESS
                ? lastError
                : ERROR_PROC_NOT_FOUND;
            return makeProcessInjectInputFailure(
                processId,
                KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH,
                win32Error,
                "GetProcAddress(LoadLibraryW) failed, error=" + std::to_string(win32Error));
        }

        const std::size_t payloadBytes = (dllPath.size() + 1U) * sizeof(wchar_t);
        const std::size_t headerSize = processInjectRequestHeaderSize();
        std::vector<std::uint8_t> requestBuffer(headerSize + payloadBytes, 0U);
        auto* request = reinterpret_cast<KSWORD_ARK_INJECT_PROCESS_REQUEST*>(requestBuffer.data());
        request->version = KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION;
        request->processId = processId;
        request->injectType = KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH;
        request->flags = flags;
        request->payloadBytes = static_cast<unsigned long>(payloadBytes);
        request->entryPointAddress =
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(loadLibraryAddress));
        request->parameterAddress = 0ULL;
        std::memcpy(request->payload, dllPath.c_str(), payloadBytes);

        ProcessInjectResult injectResult{};
        KSWORD_ARK_INJECT_PROCESS_RESPONSE response{};
        injectResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_INJECT_PROCESS,
            requestBuffer.data(),
            static_cast<unsigned long>(requestBuffer.size()),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!injectResult.io.ok)
        {
            injectResult.processId = processId;
            injectResult.injectType = KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH;
            injectResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_INJECT_PROCESS/DLL) failed, error=" +
                std::to_string(injectResult.io.win32Error);
            return injectResult;
        }
        if (injectResult.io.bytesReturned < sizeof(response))
        {
            injectResult.io.ok = false;
            injectResult.io.message =
                "process inject DLL response too small, bytesReturned=" +
                std::to_string(injectResult.io.bytesReturned);
            return injectResult;
        }

        copyProcessInjectResponse(injectResult, response);
        injectResult.io.message = buildProcessInjectMessage(injectResult);
        return injectResult;
    }

    ProcessInjectResult DriverClient::injectProcessShellcode(
        const std::uint32_t processId,
        const std::vector<std::uint8_t>& shellcode,
        const unsigned long flags) const
    {
        if (shellcode.empty())
        {
            return makeProcessInjectInputFailure(
                processId,
                KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE,
                ERROR_INVALID_PARAMETER,
                "shellcode payload is empty");
        }
        if (shellcode.size() > KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES)
        {
            return makeProcessInjectInputFailure(
                processId,
                KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE,
                ERROR_BAD_LENGTH,
                "shellcode payload is larger than R0 inject payload limit");
        }

        const std::size_t headerSize = processInjectRequestHeaderSize();
        std::vector<std::uint8_t> requestBuffer(headerSize + shellcode.size(), 0U);
        auto* request = reinterpret_cast<KSWORD_ARK_INJECT_PROCESS_REQUEST*>(requestBuffer.data());
        request->version = KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION;
        request->processId = processId;
        request->injectType = KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE;
        request->flags = flags;
        request->payloadBytes = static_cast<unsigned long>(shellcode.size());
        request->entryPointAddress = 0ULL;
        request->parameterAddress = 0ULL;
        std::memcpy(request->payload, shellcode.data(), shellcode.size());

        ProcessInjectResult injectResult{};
        KSWORD_ARK_INJECT_PROCESS_RESPONSE response{};
        injectResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_INJECT_PROCESS,
            requestBuffer.data(),
            static_cast<unsigned long>(requestBuffer.size()),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!injectResult.io.ok)
        {
            injectResult.processId = processId;
            injectResult.injectType = KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE;
            injectResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_INJECT_PROCESS/SHELLCODE) failed, error=" +
                std::to_string(injectResult.io.win32Error);
            return injectResult;
        }
        if (injectResult.io.bytesReturned < sizeof(response))
        {
            injectResult.io.ok = false;
            injectResult.io.message =
                "process inject shellcode response too small, bytesReturned=" +
                std::to_string(injectResult.io.bytesReturned);
            return injectResult;
        }

        copyProcessInjectResponse(injectResult, response);
        injectResult.io.message = buildProcessInjectMessage(injectResult);
        return injectResult;
    }
}
