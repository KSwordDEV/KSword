#include "KswordCeBridge.h"

#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ksword::ce
{
    namespace
    {
        // BridgeState 用途：集中保存 CE 函数槽、原实现和代理句柄到 PID 的映射。
        struct BridgeState
        {
            std::mutex mutex;
            std::mutex driverIoMutex;
            ExportedFunctions* exportedFunctions = nullptr;
            int pluginId = -1;
            int pointerChangeRegistrationId = -1;
            ReadProcessMemoryFunction originalReadProcessMemory = nullptr;
            WriteProcessMemoryFunction originalWriteProcessMemory = nullptr;
            OpenProcessFunction originalOpenProcess = nullptr;
            VirtualQueryExFunction originalVirtualQueryEx = nullptr;
            ksword::ark::DriverHandle driverHandle;
            std::unordered_map<HANDLE, DWORD> proxyProcessIds;
            bool initialized = false;
            // r1WindowState 用途：R-1 私有页表窗口是否可用。
            // -1 未探测，0 不可用，1 可用。探测一次就缓存：窗口在驱动加载时
            // 建立，之后不会凭空出现或消失，而 CE 的读是高频调用，每次都先
            // 失败一次再回退等于把每次读变成两次 IOCTL。
            std::atomic<int> r1WindowState{ -1 };
        };

        BridgeState g_bridgeState; // g_bridgeState：插件进程内唯一桥接状态。

        const ksword::ark::DriverClient g_driverClient; // g_driverClient：统一 KSword R3 驱动入口。

        // r1WindowUsable：
        // - 输入：无（读缓存，必要时发起一次探测）。
        // - 处理：查询 R-1 私有页表窗口是否就绪，并把结论缓存下来。
        // - 返回：可用时 true。
        bool r1WindowUsable()
        {
            const int cached =
                g_bridgeState.r1WindowState.load(std::memory_order_relaxed);
            if (cached >= 0)
            {
                return cached != 0;
            }
            ksword::ark::HvmMemoryResult probe{};
            {
                std::lock_guard<std::mutex> driverLock(
                    g_bridgeState.driverIoMutex);
                if (!g_bridgeState.driverHandle.isValid())
                {
                    // 句柄还没建立时不缓存结论：这只说明现在不能问，
                    // 不说明窗口不存在。
                    return false;
                }
                probe = g_driverClient.hvmMemory(
                    KSWORD_ARK_HVM_MEMORY_OP_QUERY_WINDOW,
                    0ULL,
                    0ULL,
                    0UL,
                    nullptr,
                    false,
                    false,
                    0UL,
                    &g_bridgeState.driverHandle);
            }
            const bool ready = probe.io.ok &&
                probe.response.status == KSWORD_ARK_HVM_MEMORY_STATUS_OK &&
                probe.response.windowReady != 0;
            g_bridgeState.r1WindowState.store(
                ready ? 1 : 0,
                std::memory_order_relaxed);
            return ready;
        }

        // readThroughR1：
        // - 输入：目标 PID、虚拟地址、缓冲与长度。
        // - 处理：走 R-1 私有页表窗口读取；要求真正走窗口，不接受回退。
        // - 返回：完整读到 length 字节时 true。
        //
        // requireWindow 为 true 是有意的：如果 R-1 会退化成 MmCopyMemory，
        // 它相对现有 R0 路径就没有任何优势，反而多一层。那种情况下直接让
        // 调用方回退到成熟的 R0 路径。
        //
        // uiConfirmed 为 true 的依据：R-1 内存通道要求显式确认，而这个插件
        // 是用户自己安装并在 CE 里启用的，启用动作本身就是那次确认；插件也
        // 只在 CE 已经要求读某个地址时才发起请求，不会自作主张读别处。
        bool readThroughR1(
            const DWORD processId,
            const std::uint64_t address,
            void* const buffer,
            const std::uint32_t length)
        {
            ksword::ark::HvmMemoryResult result{};
            {
                std::lock_guard<std::mutex> driverLock(
                    g_bridgeState.driverIoMutex);
                if (!g_bridgeState.driverHandle.isValid())
                {
                    return false;
                }
                result = g_driverClient.hvmMemory(
                    KSWORD_ARK_HVM_MEMORY_OP_READ_VIRTUAL,
                    address,
                    0ULL,
                    length,
                    nullptr,
                    true,
                    true,
                    static_cast<unsigned long>(processId),
                    &g_bridgeState.driverHandle);
            }
            if (!result.io.ok ||
                result.response.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK ||
                result.response.usedDirectWindow == 0 ||
                result.response.bytesTransferred != length)
            {
                return false;
            }
            std::memcpy(buffer, result.response.data, length);
            return true;
        }

        // resolveProcessId：
        // - 输入：CE 传入的真实进程句柄或代理事件句柄。
        // - 处理：优先查代理映射，再查询真实句柄，最后使用 CE 当前 PID。
        // - 返回：可用于 KSword IOCTL 的 PID；无法解析时返回 0。
        DWORD resolveProcessId(const HANDLE processHandle)
        {
            ULONG* openedProcessId = nullptr;
            {
                std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
                const auto proxyIterator =
                    g_bridgeState.proxyProcessIds.find(processHandle);
                if (proxyIterator != g_bridgeState.proxyProcessIds.end())
                {
                    return proxyIterator->second;
                }
                if (g_bridgeState.exportedFunctions != nullptr)
                {
                    openedProcessId =
                        g_bridgeState.exportedFunctions->openedProcessId;
                }
            }

            // resolvedProcessId 用途：保存 GetProcessId 对真实句柄的解析结果。
            const DWORD resolvedProcessId = ::GetProcessId(processHandle);
            if (resolvedProcessId != 0U)
            {
                return resolvedProcessId;
            }
            if (openedProcessId != nullptr)
            {
                return static_cast<DWORD>(*openedProcessId);
            }
            return 0U;
        }

        // bridgeOpenProcess：
        // - 输入：CE 的 OpenProcess 参数。
        // - 处理：只申请查询/同步权限；实际内存访问始终交给 KSword R0。
        // - 返回：受限真实句柄或映射到 PID 的事件句柄。
        HANDLE bridgeOpenProcessImpl(
            const DWORD desiredAccess,
            const BOOL inheritHandle,
            const DWORD processId)
        {
            UNREFERENCED_PARAMETER(desiredAccess);
            OpenProcessFunction originalOpenProcess = nullptr;
            {
                std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
                originalOpenProcess = g_bridgeState.originalOpenProcess;
            }

            // processHandle 用途：仅给 CE 提供架构识别、退出等待等非内存能力。
            // 不得转发 desiredAccess，否则 CE 会重新获得用户态 VM_READ/VM_WRITE 通道。
            HANDLE processHandle = nullptr;
            if (originalOpenProcess != nullptr)
            {
                processHandle = originalOpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                    inheritHandle,
                    processId);
            }
            if (processHandle != nullptr)
            {
                // 即使 GetProcessId 可用也显式映射 PID，避免 CE 后续替换句柄语义。
                std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
                g_bridgeState.proxyProcessIds[processHandle] = processId;
                ::SetLastError(ERROR_SUCCESS);
                return processHandle;
            }

            // proxyHandle 用途：让 CE 的打开流程继续，同时把实际访问交给 KSword R0。
            HANDLE proxyHandle = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
            if (proxyHandle == nullptr)
            {
                return nullptr;
            }
            {
                std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
                g_bridgeState.proxyProcessIds[proxyHandle] = processId;
            }
            ::SetLastError(ERROR_SUCCESS);
            return proxyHandle;
        }

        // bridgeReadProcessMemory：
        // - 输入：CE 目标句柄、地址、输出缓冲和长度。
        // - 处理：按 R0 单次 1 MiB 上限分片，通过 DriverClient 读取。
        // - 返回：全部完成时 TRUE；部分复制时设置 ERROR_PARTIAL_COPY。
        BOOL bridgeReadProcessMemoryImpl(
            const HANDLE processHandle,
            const LPCVOID baseAddress,
            const LPVOID buffer,
            const SIZE_T bytesToRead,
            SIZE_T* const bytesRead)
        {
            if (bytesRead != nullptr)
            {
                *bytesRead = 0U;
            }
            if (buffer == nullptr || (bytesToRead > 0U && baseAddress == nullptr))
            {
                ::SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            if (bytesToRead == 0U)
            {
                ::SetLastError(ERROR_SUCCESS);
                return TRUE;
            }

            // processId/totalBytesRead 用途：标识 R0 目标并累计跨分片结果。
            const DWORD processId = resolveProcessId(processHandle);
            SIZE_T totalBytesRead = 0U;
            // R-1 通道单次只有 1 KiB，比 R0 的 1 MiB 小三个数量级。所以策略
            // 不是"尽量用 R-1"，而是按读的性质分流：
            //   - 小读（指针追踪、读一个结构体）正是需要隐蔽的场景，1 KiB 够用；
            //   - 大读（全内存扫描）本来就藏不住，用 1 KiB 分片会慢三个数量级，
            //     CE 的扫描会直接不可用。
            // 判据取整次请求长度而不是当前分片：一次 4 KiB 的读不该因为某个分片
            // 恰好不超过 1 KiB 就走 R-1，那会把它切成四次 IOCTL。
            const bool preferR1 = bytesToRead <=
                static_cast<SIZE_T>(KSWORD_ARK_HVM_MEMORY_MAX_BYTES);
            if (processId == 0U)
            {
                ::SetLastError(ERROR_INVALID_HANDLE);
                return FALSE;
            }

            while (totalBytesRead < bytesToRead)
            {
                const SIZE_T remainingBytes = bytesToRead - totalBytesRead;
                const SIZE_T chunkSize = std::min<SIZE_T>(
                    remainingBytes,
                    static_cast<SIZE_T>(KSWORD_ARK_MEMORY_READ_MAX_BYTES));
                const auto currentAddress =
                    reinterpret_cast<std::uintptr_t>(baseAddress) +
                    totalBytesRead;
                // 私有页表窗口绕开内核层 hook，读到的是页表真正指向的内容。
                // 窗口不可用或本次读失败时静默回退 R0，不把一个可选的加强
                // 路径变成失败原因。
                if (preferR1 &&
                    r1WindowUsable() &&
                    readThroughR1(
                        processId,
                        static_cast<std::uint64_t>(currentAddress),
                        static_cast<std::uint8_t*>(buffer) + totalBytesRead,
                        static_cast<std::uint32_t>(chunkSize)))
                {
                    totalBytesRead += chunkSize;
                    continue;
                }

                ksword::ark::VirtualMemoryReadResult readResult{};
                {
                    // CE 会并发查询/读取；同一同步设备句柄必须串行使用。
                    std::lock_guard<std::mutex> driverLock(
                        g_bridgeState.driverIoMutex);
                    if (!g_bridgeState.driverHandle.isValid())
                    {
                        ::SetLastError(ERROR_INVALID_HANDLE);
                        break;
                    }
                    readResult = g_driverClient.readVirtualMemory(
                        processId,
                        static_cast<std::uint64_t>(currentAddress),
                        static_cast<std::uint32_t>(chunkSize),
                        0UL,
                        &g_bridgeState.driverHandle);
                }

                // copiedBytes 用途：同时受响应计数、数据数组和当前分片长度约束。
                const SIZE_T copiedBytes = std::min<SIZE_T>(
                    chunkSize,
                    std::min<SIZE_T>(
                        static_cast<SIZE_T>(readResult.bytesRead),
                        readResult.data.size()));
                if (copiedBytes > 0U)
                {
                    std::memcpy(
                        static_cast<std::uint8_t*>(buffer) + totalBytesRead,
                        readResult.data.data(),
                        copiedBytes);
                    totalBytesRead += copiedBytes;
                }
                if (!readResult.io.ok || copiedBytes != chunkSize)
                {
                    break;
                }
            }

            if (bytesRead != nullptr)
            {
                *bytesRead = totalBytesRead;
            }
            const BOOL completed = totalBytesRead == bytesToRead ? TRUE : FALSE;
            ::SetLastError(completed != FALSE ? ERROR_SUCCESS : ERROR_PARTIAL_COPY);
            return completed;
        }

        // bridgeWriteProcessMemory：
        // - 输入：CE 目标句柄、地址、源缓冲和长度。
        // - 处理：按 R0 256 KiB 上限分片，标记为 CE 用户已确认的写操作。
        // - 返回：全部写入时 TRUE；不自动启用 FORCE，保留驱动安全边界。
        BOOL bridgeWriteProcessMemoryImpl(
            const HANDLE processHandle,
            const LPVOID baseAddress,
            const LPCVOID buffer,
            const SIZE_T bytesToWrite,
            SIZE_T* const bytesWritten)
        {
            if (bytesWritten != nullptr)
            {
                *bytesWritten = 0U;
            }
            if (buffer == nullptr || (bytesToWrite > 0U && baseAddress == nullptr))
            {
                ::SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            if (bytesToWrite == 0U)
            {
                ::SetLastError(ERROR_SUCCESS);
                return TRUE;
            }

            // processId/totalBytesWritten 用途：标识 R0 目标并累计跨分片写入量。
            const DWORD processId = resolveProcessId(processHandle);
            SIZE_T totalBytesWritten = 0U;
            if (processId == 0U)
            {
                ::SetLastError(ERROR_INVALID_HANDLE);
                return FALSE;
            }

            while (totalBytesWritten < bytesToWrite)
            {
                const SIZE_T remainingBytes = bytesToWrite - totalBytesWritten;
                const SIZE_T chunkSize = std::min<SIZE_T>(
                    remainingBytes,
                    static_cast<SIZE_T>(KSWORD_ARK_MEMORY_WRITE_MAX_BYTES));
                const auto* chunkBegin =
                    static_cast<const std::uint8_t*>(buffer) +
                    totalBytesWritten;
                std::vector<std::uint8_t> chunk(
                    chunkBegin,
                    chunkBegin + chunkSize);
                const auto currentAddress =
                    reinterpret_cast<std::uintptr_t>(baseAddress) +
                    totalBytesWritten;
                ksword::ark::VirtualMemoryWriteResult writeResult{};
                {
                    std::lock_guard<std::mutex> driverLock(
                        g_bridgeState.driverIoMutex);
                    if (!g_bridgeState.driverHandle.isValid())
                    {
                        ::SetLastError(ERROR_INVALID_HANDLE);
                        break;
                    }
                    writeResult = g_driverClient.writeVirtualMemory(
                        processId,
                        static_cast<std::uint64_t>(currentAddress),
                        chunk,
                        KSWORD_ARK_MEMORY_WRITE_FLAG_UI_CONFIRMED,
                        &g_bridgeState.driverHandle);
                }

                // currentWritten 用途：限制驱动返回值不超过本次请求长度。
                const SIZE_T currentWritten = std::min<SIZE_T>(
                    chunkSize,
                    static_cast<SIZE_T>(writeResult.bytesWritten));
                totalBytesWritten += currentWritten;
                if (!writeResult.io.ok ||
                    writeResult.writeStatus != KSWORD_ARK_MEMORY_WRITE_STATUS_OK ||
                    currentWritten != chunkSize)
                {
                    break;
                }
            }

            if (bytesWritten != nullptr)
            {
                *bytesWritten = totalBytesWritten;
            }
            const BOOL completed =
                totalBytesWritten == bytesToWrite ? TRUE : FALSE;
            ::SetLastError(completed != FALSE ? ERROR_SUCCESS : ERROR_PARTIAL_COPY);
            return completed;
        }

        // bridgeVirtualQueryEx：
        // - 输入：CE 目标句柄、查询地址和 MEMORY_BASIC_INFORMATION 缓冲。
        // - 处理：调用 KSword R0 ZwQueryVirtualMemory 路径并转换固定响应。
        // - 返回：成功时返回结构大小；失败时返回 0。
        SIZE_T bridgeVirtualQueryExImpl(
            const HANDLE processHandle,
            const LPCVOID address,
            PMEMORY_BASIC_INFORMATION const information,
            const SIZE_T informationLength)
        {
            if (information == nullptr ||
                informationLength < sizeof(MEMORY_BASIC_INFORMATION))
            {
                ::SetLastError(ERROR_BAD_LENGTH);
                return 0U;
            }

            // processId/queryResult 用途：解析目标并获取 R0 虚拟内存区域信息。
            const DWORD processId = resolveProcessId(processHandle);
            if (processId == 0U)
            {
                ::SetLastError(ERROR_INVALID_HANDLE);
                return 0U;
            }
            const std::uint64_t requestedAddress = static_cast<std::uint64_t>(
                reinterpret_cast<std::uintptr_t>(address));
            ksword::ark::VirtualMemoryQueryResult queryResult{};
            {
                std::lock_guard<std::mutex> driverLock(
                    g_bridgeState.driverIoMutex);
                if (!g_bridgeState.driverHandle.isValid())
                {
                    ::SetLastError(ERROR_INVALID_HANDLE);
                    return 0U;
                }
                queryResult = g_driverClient.queryVirtualMemory(
                    processId,
                    requestedAddress,
                    0UL,
                    &g_bridgeState.driverHandle);
            }
            if (!queryResult.io.ok ||
                (queryResult.fieldFlags & KSWORD_ARK_MEMORY_FIELD_BASIC_PRESENT) == 0U ||
                (queryResult.queryStatus != KSWORD_ARK_MEMORY_QUERY_STATUS_OK &&
                 queryResult.queryStatus != KSWORD_ARK_MEMORY_QUERY_STATUS_PARTIAL))
            {
                ::SetLastError(
                    queryResult.io.win32Error != ERROR_SUCCESS
                        ? queryResult.io.win32Error
                        : ERROR_PARTIAL_COPY);
                return 0U;
            }

            // CE 依赖 BaseAddress + RegionSize 推进枚举游标。驱动若返回空区间、
            // 越界区间或无法收窄到当前架构的地址，必须失败而不是让 CE 无限循环。
            const std::uint64_t regionEnd =
                queryResult.baseAddress + queryResult.regionSize;
            if (queryResult.regionSize == 0U ||
                queryResult.baseAddress > requestedAddress ||
                queryResult.baseAddress >
                    (std::numeric_limits<std::uint64_t>::max)() -
                        queryResult.regionSize ||
                requestedAddress >= regionEnd ||
                queryResult.baseAddress >
                    static_cast<std::uint64_t>(
                        (std::numeric_limits<std::uintptr_t>::max)()) ||
                queryResult.allocationBase >
                    static_cast<std::uint64_t>(
                        (std::numeric_limits<std::uintptr_t>::max)()) ||
                queryResult.regionSize >
                    static_cast<std::uint64_t>(
                        (std::numeric_limits<SIZE_T>::max)()))
            {
                ::SetLastError(ERROR_INVALID_DATA);
                return 0U;
            }

            // result 用途：先完整清零，再将跨位宽协议字段收窄到当前 CE 架构。
            MEMORY_BASIC_INFORMATION result{};
            result.BaseAddress = reinterpret_cast<PVOID>(
                static_cast<std::uintptr_t>(queryResult.baseAddress));
            result.AllocationBase = reinterpret_cast<PVOID>(
                static_cast<std::uintptr_t>(queryResult.allocationBase));
            result.AllocationProtect =
                static_cast<DWORD>(queryResult.allocationProtect);
            result.RegionSize = static_cast<SIZE_T>(queryResult.regionSize);
            result.State = static_cast<DWORD>(queryResult.state);
            result.Protect = static_cast<DWORD>(queryResult.protect);
            result.Type = static_cast<DWORD>(queryResult.type);
            *information = result;
            ::SetLastError(ERROR_SUCCESS);
            return sizeof(MEMORY_BASIC_INFORMATION);
        }

        // 以下 WINAPI 包装器是 CE/Lazarus 与 C++ 桥接的异常边界。
        // 任何 C++ 异常都必须在 DLL 内转换成 Win32 失败，不能穿过插件 ABI。
        HANDLE WINAPI bridgeOpenProcess(
            const DWORD desiredAccess,
            const BOOL inheritHandle,
            const DWORD processId) noexcept
        {
            try
            {
                return bridgeOpenProcessImpl(
                    desiredAccess,
                    inheritHandle,
                    processId);
            }
            catch (...)
            {
                ::SetLastError(ERROR_GEN_FAILURE);
                return nullptr;
            }
        }

        BOOL WINAPI bridgeReadProcessMemory(
            const HANDLE processHandle,
            const LPCVOID baseAddress,
            const LPVOID buffer,
            const SIZE_T bytesToRead,
            SIZE_T* const bytesRead) noexcept
        {
            try
            {
                return bridgeReadProcessMemoryImpl(
                    processHandle,
                    baseAddress,
                    buffer,
                    bytesToRead,
                    bytesRead);
            }
            catch (...)
            {
                if (bytesRead != nullptr)
                {
                    *bytesRead = 0U;
                }
                ::SetLastError(ERROR_GEN_FAILURE);
                return FALSE;
            }
        }

        BOOL WINAPI bridgeWriteProcessMemory(
            const HANDLE processHandle,
            const LPVOID baseAddress,
            const LPCVOID buffer,
            const SIZE_T bytesToWrite,
            SIZE_T* const bytesWritten) noexcept
        {
            try
            {
                return bridgeWriteProcessMemoryImpl(
                    processHandle,
                    baseAddress,
                    buffer,
                    bytesToWrite,
                    bytesWritten);
            }
            catch (...)
            {
                if (bytesWritten != nullptr)
                {
                    *bytesWritten = 0U;
                }
                ::SetLastError(ERROR_GEN_FAILURE);
                return FALSE;
            }
        }

        SIZE_T WINAPI bridgeVirtualQueryEx(
            const HANDLE processHandle,
            const LPCVOID address,
            PMEMORY_BASIC_INFORMATION const information,
            const SIZE_T informationLength) noexcept
        {
            try
            {
                return bridgeVirtualQueryExImpl(
                    processHandle,
                    address,
                    information,
                    informationLength);
            }
            catch (...)
            {
                if (information != nullptr &&
                    informationLength >= sizeof(MEMORY_BASIC_INFORMATION))
                {
                    *information = MEMORY_BASIC_INFORMATION{};
                }
                ::SetLastError(ERROR_GEN_FAILURE);
                return 0U;
            }
        }

        // installFunctionPointerHooks：保存当前实现并原子式覆盖 CE 函数槽。
        bool installFunctionPointerHooks()
        {
            ExportedFunctions* exportedFunctions =
                g_bridgeState.exportedFunctions;
            if (exportedFunctions == nullptr ||
                exportedFunctions->readProcessMemory == nullptr ||
                exportedFunctions->writeProcessMemory == nullptr ||
                exportedFunctions->openProcess == nullptr ||
                exportedFunctions->virtualQueryEx == nullptr)
            {
                return false;
            }

            // 各 slot 变量用途：CE 字段保存的是“函数指针变量的地址”，需要解引用后替换。
            auto* readSlot = exportedFunctions->readProcessMemory;
            auto* writeSlot = static_cast<WriteProcessMemoryFunction*>(
                exportedFunctions->writeProcessMemory);
            auto* openSlot = static_cast<OpenProcessFunction*>(
                exportedFunctions->openProcess);
            auto* querySlot = static_cast<VirtualQueryExFunction*>(
                exportedFunctions->virtualQueryEx);
            if (*readSlot != &bridgeReadProcessMemory)
            {
                g_bridgeState.originalReadProcessMemory = *readSlot;
                *readSlot = &bridgeReadProcessMemory;
            }
            if (*writeSlot != &bridgeWriteProcessMemory)
            {
                g_bridgeState.originalWriteProcessMemory = *writeSlot;
                *writeSlot = &bridgeWriteProcessMemory;
            }
            if (*openSlot != &bridgeOpenProcess)
            {
                g_bridgeState.originalOpenProcess = *openSlot;
                *openSlot = &bridgeOpenProcess;
            }
            if (*querySlot != &bridgeVirtualQueryEx)
            {
                g_bridgeState.originalVirtualQueryEx = *querySlot;
                *querySlot = &bridgeVirtualQueryEx;
            }
            return true;
        }
    }

    BOOL initializeBridge(
        ExportedFunctions* const exportedFunctions,
        const int pluginId)
    {
        if (exportedFunctions == nullptr ||
            exportedFunctions->sizeofExportedFunctions <
                static_cast<int>(kRequiredExportedFunctionsSize))
        {
            return FALSE;
        }

        // driverHandle 用途：初始化前验证读写控制句柄，失败时不修改 CE 函数表。
        auto driverHandle = g_driverClient.open();
        if (!driverHandle.isValid())
        {
            if (exportedFunctions->showMessage != nullptr)
            {
                char message[] =
                    "KSword CE Bridge: cannot open \\\\.\\KswordARKLog. "
                    "Load the KSword driver first.";
                exportedFunctions->showMessage(message);
            }
            return FALSE;
        }
        {
            std::lock_guard<std::mutex> driverLock(
                g_bridgeState.driverIoMutex);
            g_bridgeState.driverHandle = std::move(driverHandle);
        }

        // 初始化状态与 hook 安装在同一临界区完成，避免 CE 工作线程看到半状态。
        {
            std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
            g_bridgeState.exportedFunctions = exportedFunctions;
            g_bridgeState.pluginId = pluginId;
            if (!installFunctionPointerHooks())
            {
                g_bridgeState.exportedFunctions = nullptr;
                g_bridgeState.pluginId = -1;
                std::lock_guard<std::mutex> driverLock(
                    g_bridgeState.driverIoMutex);
                g_bridgeState.driverHandle.reset();
                return FALSE;
            }
            g_bridgeState.initialized = true;
        }

        // 回调注册可能同步进入 CE 代码，因此在桥接互斥锁外调用以避免重入死锁。
        if (exportedFunctions->registerFunction != nullptr)
        {
            FunctionPointerChangeInitialization initialization{};
            initialization.callbackRoutine = &notifyFunctionPointersChanged;
            const int registrationId = exportedFunctions->registerFunction(
                pluginId,
                PluginType::functionPointerChange,
                &initialization);
            std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
            g_bridgeState.pointerChangeRegistrationId = registrationId;
        }

        return TRUE;
    }

    BOOL disableBridge()
    {
        UnregisterFunction unregisterFunction = nullptr;
        int pluginId = -1;
        int registrationId = -1;
        {
            std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
            if (!g_bridgeState.initialized ||
                g_bridgeState.exportedFunctions == nullptr)
            {
                return TRUE;
            }

            // 恢复时只改仍指向本插件的槽，避免覆盖其他插件稍后安装的实现。
            ExportedFunctions* const exportedFunctions =
                g_bridgeState.exportedFunctions;
            auto* readSlot = exportedFunctions->readProcessMemory;
            auto* writeSlot = static_cast<WriteProcessMemoryFunction*>(
                exportedFunctions->writeProcessMemory);
            auto* openSlot = static_cast<OpenProcessFunction*>(
                exportedFunctions->openProcess);
            auto* querySlot = static_cast<VirtualQueryExFunction*>(
                exportedFunctions->virtualQueryEx);
            if (readSlot != nullptr && *readSlot == &bridgeReadProcessMemory)
            {
                *readSlot = g_bridgeState.originalReadProcessMemory;
            }
            if (writeSlot != nullptr && *writeSlot == &bridgeWriteProcessMemory)
            {
                *writeSlot = g_bridgeState.originalWriteProcessMemory;
            }
            if (openSlot != nullptr && *openSlot == &bridgeOpenProcess)
            {
                *openSlot = g_bridgeState.originalOpenProcess;
            }
            if (querySlot != nullptr && *querySlot == &bridgeVirtualQueryEx)
            {
                *querySlot = g_bridgeState.originalVirtualQueryEx;
            }

            // 保存注销参数后先清空状态，真正进入 CE 的调用放到互斥锁外。
            unregisterFunction = exportedFunctions->unregisterFunction;
            pluginId = g_bridgeState.pluginId;
            registrationId = g_bridgeState.pointerChangeRegistrationId;
            g_bridgeState.proxyProcessIds.clear();
            g_bridgeState.exportedFunctions = nullptr;
            g_bridgeState.pluginId = -1;
            g_bridgeState.pointerChangeRegistrationId = -1;
            g_bridgeState.initialized = false;
        }

        if (registrationId >= 0 && unregisterFunction != nullptr)
        {
            unregisterFunction(pluginId, registrationId);
        }
        {
            std::lock_guard<std::mutex> driverLock(
                g_bridgeState.driverIoMutex);
            g_bridgeState.driverHandle.reset();
        }
        return TRUE;
    }

    void __stdcall notifyFunctionPointersChanged(const int reserved)
    {
        UNREFERENCED_PARAMETER(reserved);
        std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
        if (g_bridgeState.initialized)
        {
            (void)installFunctionPointerHooks();
        }
    }
}
