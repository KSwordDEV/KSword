#include "ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#include <utility>

namespace ksword::ark
{
    namespace
    {
        constexpr std::size_t kSsdtResponseHeaderSize =
            sizeof(KSWORD_ARK_ENUM_SSDT_RESPONSE) - sizeof(KSWORD_ARK_SSDT_ENTRY);

        constexpr std::size_t kInlineHookResponseHeaderSize =
            sizeof(KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY);

        constexpr std::size_t kIatEatHookResponseHeaderSize =
            sizeof(KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY);

        inline constexpr unsigned long kScanKernelExecutableMemoryDefaultMaxEntries = 4096UL;

        constexpr std::size_t kKernelExecutableMemoryResponseHeaderSize =
            sizeof(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE) -
            sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY);

        std::string fixedKernelAnsiToString(const char* textBuffer, const std::size_t maxBytes)
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

        std::wstring fixedKernelWideToString(const wchar_t* textBuffer, const std::size_t maxChars)
        {
            if (textBuffer == nullptr || maxChars == 0U)
            {
                return {};
            }

            std::size_t length = 0U;
            while (length < maxChars && textBuffer[length] != L'\0')
            {
                ++length;
            }
            return std::wstring(textBuffer, textBuffer + length);
        }

        void copyWideToFixed(wchar_t* destination, const std::size_t destinationChars, const std::wstring& source)
        {
            if (destination == nullptr || destinationChars == 0U)
            {
                return;
            }

            const std::size_t copyChars = std::min<std::size_t>(source.size(), destinationChars - 1U);
            std::fill(destination, destination + destinationChars, L'\0');
            if (copyChars != 0U)
            {
                std::copy(source.data(), source.data() + copyChars, destination);
            }
            destination[copyChars] = L'\0';
        }

        bool isUnsupportedIoctlError(const unsigned long win32Error)
        {
            // 作用：判断旧驱动未注册新 IOCTL 的典型 Win32 错误码。
            // 返回：true 表示 UI 应显示“不支持/驱动版本过旧”。
            return win32Error == ERROR_INVALID_FUNCTION ||
                win32Error == ERROR_NOT_SUPPORTED ||
                win32Error == ERROR_INVALID_PARAMETER;
        }

        void copyVectorToFixedBytes(
            unsigned char* destination,
            const std::size_t destinationBytes,
            const std::vector<std::uint8_t>& sourceBytes)
        {
            // 作用：把 R3 vector 安全复制到共享协议定长字节数组。
            // 返回：无；超长部分被截断，剩余位置填 0。
            if (destination == nullptr || destinationBytes == 0U)
            {
                return;
            }

            std::fill(
                destination,
                destination + destinationBytes,
                static_cast<unsigned char>(0));
            const std::size_t copyBytes = std::min<std::size_t>(destinationBytes, sourceBytes.size());
            if (copyBytes != 0U)
            {
                std::copy(sourceBytes.begin(), sourceBytes.begin() + static_cast<std::ptrdiff_t>(copyBytes), destination);
            }
        }

        std::vector<std::uint8_t> fixedBytesToVector(const unsigned char* bytes, const std::size_t maxBytes)
        {
            // 作用：把共享协议定长字节数组转成 R3 vector，便于 UI 展示和重放比较。
            // 返回：长度固定为 maxBytes 的字节数组；空指针返回空 vector。
            if (bytes == nullptr || maxBytes == 0U)
            {
                return {};
            }

            return std::vector<std::uint8_t>(bytes, bytes + maxBytes);
        }

        SsdtEnumResult parseSsdtResponse(
            IoResult ioResult,
            const std::vector<std::uint8_t>& responseBuffer,
            const char* operationName)
        {
            // 作用：解析 SSDT/SSSDT 共用响应包。
            // 返回：填充后的 SsdtEnumResult，失败时 io.ok 被置 false。
            SsdtEnumResult enumResult{};
            enumResult.io = std::move(ioResult);
            if (!enumResult.io.ok)
            {
                enumResult.io.message = std::string("DeviceIoControl(") + operationName + ") failed, error=" + std::to_string(enumResult.io.win32Error);
                return enumResult;
            }

            if (enumResult.io.bytesReturned < kSsdtResponseHeaderSize)
            {
                enumResult.io.ok = false;
                enumResult.io.message = std::string(operationName) + " response too small, bytesReturned=" + std::to_string(enumResult.io.bytesReturned);
                return enumResult;
            }

            const auto* responseHeader = reinterpret_cast<const KSWORD_ARK_ENUM_SSDT_RESPONSE*>(responseBuffer.data());
            constexpr std::size_t minimumSsdtEntryBytes =
                offsetof(KSWORD_ARK_SSDT_ENTRY, tableEntryAddress);
            if (responseHeader->entrySize < minimumSsdtEntryBytes)
            {
                enumResult.io.ok = false;
                enumResult.io.message = std::string(operationName) + " entrySize invalid, entrySize=" + std::to_string(responseHeader->entrySize);
                return enumResult;
            }

            enumResult.version = responseHeader->version;
            enumResult.totalCount = responseHeader->totalCount;
            enumResult.returnedCount = responseHeader->returnedCount;
            enumResult.serviceTableBase = responseHeader->serviceTableBase;
            enumResult.serviceCountFromTable = responseHeader->serviceCountFromTable;

            const std::size_t availableCount =
                (enumResult.io.bytesReturned - kSsdtResponseHeaderSize) /
                static_cast<std::size_t>(responseHeader->entrySize);
            const std::size_t parsedCount = std::min<std::size_t>(
                static_cast<std::size_t>(responseHeader->returnedCount),
                availableCount);
            enumResult.entries.reserve(parsedCount);
            for (std::size_t index = 0U; index < parsedCount; ++index)
            {
                const std::size_t entryOffset =
                    kSsdtResponseHeaderSize +
                    (index * static_cast<std::size_t>(responseHeader->entrySize));
                if (entryOffset + minimumSsdtEntryBytes > responseBuffer.size())
                {
                    break;
                }

                const auto* sourceEntry =
                    reinterpret_cast<const KSWORD_ARK_SSDT_ENTRY*>(responseBuffer.data() + entryOffset);
                SsdtEntry row{};
                row.serviceIndex = static_cast<std::uint32_t>(sourceEntry->serviceIndex);
                row.flags = static_cast<std::uint32_t>(sourceEntry->flags);
                row.zwRoutineAddress = static_cast<std::uint64_t>(sourceEntry->zwRoutineAddress);
                row.serviceRoutineAddress = static_cast<std::uint64_t>(sourceEntry->serviceRoutineAddress);
                if (responseHeader->entrySize >= sizeof(KSWORD_ARK_SSDT_ENTRY)
                    && entryOffset + sizeof(KSWORD_ARK_SSDT_ENTRY)
                        <= responseBuffer.size())
                {
                    row.tableEntryAddress =
                        static_cast<std::uint64_t>(
                            sourceEntry->tableEntryAddress);
                    row.currentTableValue =
                        static_cast<std::uint64_t>(
                            sourceEntry->currentTableValue);
                    row.tableEntrySize =
                        static_cast<std::uint32_t>(
                            sourceEntry->tableEntrySize);
                }
                row.serviceName = fixedKernelAnsiToString(sourceEntry->serviceName, sizeof(sourceEntry->serviceName));
                row.moduleName = fixedKernelAnsiToString(sourceEntry->moduleName, sizeof(sourceEntry->moduleName));
                enumResult.entries.push_back(std::move(row));
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
    }

    SsdtEnumResult DriverClient::enumerateSsdt(const unsigned long flags) const
    {
        KSWORD_ARK_ENUM_SSDT_REQUEST request{};
        request.flags = flags;

        std::vector<std::uint8_t> responseBuffer(2U * 1024U * 1024U, 0U);
        IoResult ioResult = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_SSDT,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        return parseSsdtResponse(std::move(ioResult), responseBuffer, "IOCTL_KSWORD_ARK_ENUM_SSDT");
    }

    SsdtEnumResult DriverClient::enumerateShadowSsdt(const unsigned long flags) const
    {
        KSWORD_ARK_ENUM_SSDT_REQUEST request{};
        request.flags = flags;

        std::vector<std::uint8_t> responseBuffer(2U * 1024U * 1024U, 0U);
        IoResult ioResult = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        return parseSsdtResponse(std::move(ioResult), responseBuffer, "IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT");
    }

    KernelInlineHookScanResult DriverClient::scanInlineHooks(
        const unsigned long flags,
        const unsigned long maxEntries,
        const std::wstring& moduleName) const
    {
        KernelInlineHookScanResult scanResult{};
        KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST request{};
        request.flags = flags;
        request.maxEntries = maxEntries;
        if (!moduleName.empty())
        {
            request.flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_MODULE_FILTER;
            copyWideToFixed(request.moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS, moduleName);
        }

        std::vector<std::uint8_t> responseBuffer(4U * 1024U * 1024U, 0U);
        scanResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!scanResult.io.ok)
        {
            scanResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS) failed, error=" +
                std::to_string(scanResult.io.win32Error);
            return scanResult;
        }
        if (scanResult.io.bytesReturned < kInlineHookResponseHeaderSize)
        {
            scanResult.io.ok = false;
            scanResult.io.message =
                "inline hook response too small, bytesReturned=" +
                std::to_string(scanResult.io.bytesReturned);
            return scanResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE*>(responseBuffer.data());
        if (responseHeader->entrySize < sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY))
        {
            scanResult.io.ok = false;
            scanResult.io.message =
                "inline hook entrySize invalid, entrySize=" +
                std::to_string(responseHeader->entrySize);
            return scanResult;
        }

        scanResult.version = static_cast<std::uint32_t>(responseHeader->version);
        scanResult.status = static_cast<std::uint32_t>(responseHeader->status);
        scanResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        scanResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        scanResult.moduleCount = static_cast<std::uint32_t>(responseHeader->moduleCount);
        scanResult.lastStatus = static_cast<long>(responseHeader->lastStatus);

        const std::size_t availableCount =
            (scanResult.io.bytesReturned - kInlineHookResponseHeaderSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t parsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            availableCount);
        scanResult.entries.reserve(parsedCount);
        for (std::size_t index = 0U; index < parsedCount; ++index)
        {
            const std::size_t entryOffset =
                kInlineHookResponseHeaderSize +
                (index * static_cast<std::size_t>(responseHeader->entrySize));
            if (entryOffset + sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY) > responseBuffer.size())
            {
                break;
            }

            const auto* sourceEntry =
                reinterpret_cast<const KSWORD_ARK_INLINE_HOOK_ENTRY*>(responseBuffer.data() + entryOffset);
            KernelInlineHookEntry row{};
            row.status = static_cast<std::uint32_t>(sourceEntry->status);
            row.hookType = static_cast<std::uint32_t>(sourceEntry->hookType);
            row.flags = static_cast<std::uint32_t>(sourceEntry->flags);
            row.originalByteCount = static_cast<std::uint32_t>(sourceEntry->originalByteCount);
            row.currentByteCount = static_cast<std::uint32_t>(sourceEntry->currentByteCount);
            row.functionAddress = static_cast<std::uint64_t>(sourceEntry->functionAddress);
            row.targetAddress = static_cast<std::uint64_t>(sourceEntry->targetAddress);
            row.moduleBase = static_cast<std::uint64_t>(sourceEntry->moduleBase);
            row.targetModuleBase = static_cast<std::uint64_t>(sourceEntry->targetModuleBase);
            row.functionName = fixedKernelAnsiToString(sourceEntry->functionName, sizeof(sourceEntry->functionName));
            row.moduleName = fixedKernelWideToString(sourceEntry->moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
            row.targetModuleName = fixedKernelWideToString(sourceEntry->targetModuleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
            row.currentBytes = fixedBytesToVector(sourceEntry->currentBytes, KSWORD_ARK_KERNEL_HOOK_BYTES);
            row.expectedBytes = fixedBytesToVector(sourceEntry->expectedBytes, KSWORD_ARK_KERNEL_HOOK_BYTES);
            scanResult.entries.push_back(std::move(row));
        }

        std::ostringstream stream;
        stream << "version=" << scanResult.version
            << ", total=" << scanResult.totalCount
            << ", returned=" << scanResult.returnedCount
            << ", parsed=" << scanResult.entries.size()
            << ", modules=" << scanResult.moduleCount
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(scanResult.lastStatus);
        scanResult.io.message = stream.str();
        return scanResult;
    }

    KernelInlinePatchResult DriverClient::patchInlineHook(
        const std::uint64_t functionAddress,
        const unsigned long mode,
        const unsigned long patchBytes,
        const std::vector<std::uint8_t>& expectedCurrentBytes,
        const std::vector<std::uint8_t>& restoreBytes,
        const unsigned long flags) const
    {
        KernelInlinePatchResult patchResult{};
        KSWORD_ARK_PATCH_INLINE_HOOK_REQUEST request{};
        KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE response{};
        request.flags = flags;
        request.mode = mode;
        request.patchBytes = patchBytes;
        request.functionAddress = functionAddress;
        copyVectorToFixedBytes(
            request.expectedCurrentBytes,
            KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES,
            expectedCurrentBytes);
        copyVectorToFixedBytes(
            request.restoreBytes,
            KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES,
            restoreBytes);

        patchResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!patchResult.io.ok)
        {
            patchResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK) failed, error=" +
                std::to_string(patchResult.io.win32Error);
            return patchResult;
        }
        if (patchResult.io.bytesReturned < sizeof(response))
        {
            patchResult.io.ok = false;
            patchResult.io.message =
                "inline patch response too small, bytesReturned=" +
                std::to_string(patchResult.io.bytesReturned);
            return patchResult;
        }

        patchResult.version = static_cast<std::uint32_t>(response.version);
        patchResult.status = static_cast<std::uint32_t>(response.status);
        patchResult.bytesPatched = static_cast<std::uint32_t>(response.bytesPatched);
        patchResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        patchResult.lastStatus = static_cast<long>(response.lastStatus);
        patchResult.functionAddress = static_cast<std::uint64_t>(response.functionAddress);
        patchResult.beforeBytes = fixedBytesToVector(response.beforeBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES);
        patchResult.afterBytes = fixedBytesToVector(response.afterBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES);

        std::ostringstream stream;
        stream << "version=" << patchResult.version
            << ", status=" << patchResult.status
            << ", bytesPatched=" << patchResult.bytesPatched
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(patchResult.lastStatus);
        patchResult.io.message = stream.str();
        return patchResult;
    }

    KernelExecutableMemoryScanResult DriverClient::scanKernelExecutableMemory(
        const unsigned long flags,
        const unsigned long maxEntries,
        const std::wstring& modulePathFilter) const
    {
        // 作用：消费 Prompt-1 的内核可执行页扫描 IOCTL，并把变长响应解析为 R3 model。
        // 处理：R3 只做只读扫描请求；旧驱动未注册该 IOCTL 时返回 unsupported=true。
        // 返回：KernelExecutableMemoryScanResult，io.ok 表示传输和协议解析成功。
        KernelExecutableMemoryScanResult scanResult{};
        KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST request{};
        request.flags = flags;
        request.maxEntries = (maxEntries == 0UL)
            ? kScanKernelExecutableMemoryDefaultMaxEntries
            : maxEntries;
        request.startAddress = 0ULL;
        request.endAddress = 0ULL;
        (void)modulePathFilter;

        std::vector<std::uint8_t> responseBuffer(4U * 1024U * 1024U, 0U);
        scanResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!scanResult.io.ok)
        {
            scanResult.unsupported = isUnsupportedIoctlError(scanResult.io.win32Error);
            scanResult.io.message = scanResult.unsupported
                ? "IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY) failed, error=" +
                    std::to_string(scanResult.io.win32Error);
            return scanResult;
        }

        if (scanResult.io.bytesReturned < kKernelExecutableMemoryResponseHeaderSize)
        {
            scanResult.io.ok = false;
            scanResult.io.message =
                "kernel executable-memory response too small, bytesReturned=" +
                std::to_string(scanResult.io.bytesReturned);
            return scanResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE*>(responseBuffer.data());
        if (responseHeader->entrySize < sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY))
        {
            scanResult.io.ok = false;
            scanResult.io.message =
                "kernel executable-memory entrySize invalid, entrySize=" +
                std::to_string(responseHeader->entrySize);
            return scanResult;
        }

        scanResult.version = static_cast<std::uint32_t>(responseHeader->version);
        scanResult.status = static_cast<std::uint32_t>(responseHeader->status);
        scanResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        scanResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        scanResult.moduleCount = static_cast<std::uint32_t>(responseHeader->moduleCount);
        scanResult.lastStatus = static_cast<long>(responseHeader->lastStatus);
        scanResult.io.ntStatus = scanResult.lastStatus;
        if (static_cast<unsigned long>(scanResult.lastStatus) == 0xC00000BBUL ||
            static_cast<unsigned long>(scanResult.lastStatus) == 0xC0000010UL)
        {
            scanResult.unsupported = true;
            scanResult.io.ok = false;
            scanResult.io.message =
                "IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY unsupported by current driver response";
            return scanResult;
        }

        const std::size_t availableCount =
            (static_cast<std::size_t>(scanResult.io.bytesReturned) - kKernelExecutableMemoryResponseHeaderSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t parsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            availableCount);
        scanResult.entries.reserve(parsedCount);
        for (std::size_t index = 0U; index < parsedCount; ++index)
        {
            const std::size_t entryOffset =
                kKernelExecutableMemoryResponseHeaderSize +
                (index * static_cast<std::size_t>(responseHeader->entrySize));
            if (entryOffset + sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY) > responseBuffer.size())
            {
                break;
            }

            const auto* sourceEntry =
                reinterpret_cast<const KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY*>(
                    responseBuffer.data() + entryOffset);
            KernelExecutableMemoryPageEntry row{};
            row.status = scanResult.status;
            row.lastStatus = scanResult.lastStatus;
            row.riskFlags = static_cast<std::uint32_t>(sourceEntry->riskFlags);
            row.permissionFlags = static_cast<std::uint32_t>(sourceEntry->effectiveFlags);
            row.ownerKind = static_cast<std::uint32_t>(sourceEntry->ownerKind);
            row.pageCount = static_cast<std::uint32_t>(sourceEntry->pageCount);
            row.pageSize = static_cast<std::uint32_t>(sourceEntry->pageSize);
            row.virtualAddress = static_cast<std::uint64_t>(sourceEntry->virtualAddress);
            row.ownerAddress = static_cast<std::uint64_t>(sourceEntry->moduleBase);
            row.moduleBase = static_cast<std::uint64_t>(sourceEntry->moduleBase);
            row.moduleSize = static_cast<std::uint32_t>(sourceEntry->moduleSize);
            row.regionSize =
                static_cast<std::uint64_t>(sourceEntry->pageCount) *
                static_cast<std::uint64_t>(sourceEntry->pageSize);
            row.owner = fixedKernelWideToString(
                sourceEntry->modulePath,
                KSWORD_ARK_KERNEL_EXEC_MODULE_PATH_CHARS);
            row.modulePath = fixedKernelWideToString(
                sourceEntry->modulePath,
                KSWORD_ARK_KERNEL_EXEC_MODULE_PATH_CHARS);
            scanResult.entries.push_back(std::move(row));
        }

        std::ostringstream stream;
        stream << "version=" << scanResult.version
            << ", status=" << scanResult.status
            << ", total=" << scanResult.totalCount
            << ", returned=" << scanResult.returnedCount
            << ", parsed=" << scanResult.entries.size()
            << ", modules=" << scanResult.moduleCount
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(scanResult.lastStatus);
        scanResult.io.message = stream.str();
        return scanResult;
    }

    KernelIatEatHookScanResult DriverClient::enumerateIatEatHooks(
        const unsigned long flags,
        const unsigned long maxEntries,
        const std::wstring& moduleName) const
    {
        KernelIatEatHookScanResult scanResult{};
        KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST request{};
        request.flags = flags;
        request.maxEntries = maxEntries;
        if (!moduleName.empty())
        {
            request.flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_MODULE_FILTER;
            copyWideToFixed(request.moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS, moduleName);
        }

        std::vector<std::uint8_t> responseBuffer(4U * 1024U * 1024U, 0U);
        scanResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!scanResult.io.ok)
        {
            scanResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS) failed, error=" +
                std::to_string(scanResult.io.win32Error);
            return scanResult;
        }
        if (scanResult.io.bytesReturned < kIatEatHookResponseHeaderSize)
        {
            scanResult.io.ok = false;
            scanResult.io.message =
                "IAT/EAT response too small, bytesReturned=" +
                std::to_string(scanResult.io.bytesReturned);
            return scanResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE*>(responseBuffer.data());
        if (responseHeader->entrySize < sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY))
        {
            scanResult.io.ok = false;
            scanResult.io.message =
                "IAT/EAT entrySize invalid, entrySize=" +
                std::to_string(responseHeader->entrySize);
            return scanResult;
        }

        scanResult.version = static_cast<std::uint32_t>(responseHeader->version);
        scanResult.status = static_cast<std::uint32_t>(responseHeader->status);
        scanResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        scanResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        scanResult.moduleCount = static_cast<std::uint32_t>(responseHeader->moduleCount);
        scanResult.lastStatus = static_cast<long>(responseHeader->lastStatus);

        const std::size_t availableCount =
            (scanResult.io.bytesReturned - kIatEatHookResponseHeaderSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t parsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            availableCount);
        scanResult.entries.reserve(parsedCount);
        for (std::size_t index = 0U; index < parsedCount; ++index)
        {
            const std::size_t entryOffset =
                kIatEatHookResponseHeaderSize +
                (index * static_cast<std::size_t>(responseHeader->entrySize));
            if (entryOffset + sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY) > responseBuffer.size())
            {
                break;
            }

            const auto* sourceEntry =
                reinterpret_cast<const KSWORD_ARK_IAT_EAT_HOOK_ENTRY*>(responseBuffer.data() + entryOffset);
            KernelIatEatHookEntry row{};
            row.hookClass = static_cast<std::uint32_t>(sourceEntry->hookClass);
            row.status = static_cast<std::uint32_t>(sourceEntry->status);
            row.flags = static_cast<std::uint32_t>(sourceEntry->flags);
            row.ordinal = static_cast<std::uint32_t>(sourceEntry->ordinal);
            row.moduleBase = static_cast<std::uint64_t>(sourceEntry->moduleBase);
            row.thunkAddress = static_cast<std::uint64_t>(sourceEntry->thunkAddress);
            row.currentTarget = static_cast<std::uint64_t>(sourceEntry->currentTarget);
            row.expectedTarget = static_cast<std::uint64_t>(sourceEntry->expectedTarget);
            row.targetModuleBase = static_cast<std::uint64_t>(sourceEntry->targetModuleBase);
            row.functionName = fixedKernelAnsiToString(sourceEntry->functionName, sizeof(sourceEntry->functionName));
            row.moduleName = fixedKernelWideToString(sourceEntry->moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
            row.importModuleName = fixedKernelWideToString(sourceEntry->importModuleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
            row.targetModuleName = fixedKernelWideToString(sourceEntry->targetModuleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
            scanResult.entries.push_back(std::move(row));
        }

        std::ostringstream stream;
        stream << "version=" << scanResult.version
            << ", total=" << scanResult.totalCount
            << ", returned=" << scanResult.returnedCount
            << ", parsed=" << scanResult.entries.size()
            << ", modules=" << scanResult.moduleCount
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(scanResult.lastStatus);
        scanResult.io.message = stream.str();
        return scanResult;
    }

    KernelTimerDpcEnumResult DriverClient::enumerateKernelTimerDpc(
        const unsigned long maxEntries,
        const unsigned long maxEntriesPerBucket) const
    {
        KernelTimerDpcEnumResult enumResult{};
        KSWORD_ARK_ENUM_TIMER_DPC_REQUEST request{};
        request.version = KSWORD_ARK_TIMER_DPC_PROTOCOL_VERSION;
        request.maxEntries = maxEntries;
        request.maxEntriesPerBucket = maxEntriesPerBucket;

        const std::size_t requestedRows = std::min<std::size_t>(
            maxEntries == 0UL ? KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES : maxEntries,
            KSWORD_ARK_TIMER_DPC_MAX_ENTRIES);
        const std::size_t responseBytes = KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE +
            (requestedRows * sizeof(KSWORD_ARK_TIMER_DPC_ENTRY));
        std::vector<std::uint8_t> responseBuffer(responseBytes, 0U);
        enumResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_TIMER_DPC,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!enumResult.io.ok)
        {
            enumResult.unsupported = isUnsupportedIoctlError(enumResult.io.win32Error);
            enumResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_ENUM_TIMER_DPC) failed, error=" +
                std::to_string(enumResult.io.win32Error);
            return enumResult;
        }
        if (enumResult.io.bytesReturned < KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE)
        {
            enumResult.io.ok = false;
            enumResult.io.message =
                "timer/DPC response too small, bytesReturned=" +
                std::to_string(enumResult.io.bytesReturned);
            return enumResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE*>(responseBuffer.data());
        if (responseHeader->version != KSWORD_ARK_TIMER_DPC_PROTOCOL_VERSION ||
            responseHeader->entrySize < sizeof(KSWORD_ARK_TIMER_DPC_ENTRY))
        {
            enumResult.io.ok = false;
            enumResult.io.message = "timer/DPC response version or entrySize is invalid";
            return enumResult;
        }

        enumResult.version = static_cast<std::uint32_t>(responseHeader->version);
        enumResult.queryStatus = static_cast<std::uint32_t>(responseHeader->queryStatus);
        enumResult.statusFlags = static_cast<std::uint32_t>(responseHeader->statusFlags);
        enumResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        enumResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        enumResult.processorCount = static_cast<std::uint32_t>(responseHeader->processorCount);
        enumResult.bucketCount = static_cast<std::uint32_t>(responseHeader->bucketCount);
        enumResult.bucketsVisited = static_cast<std::uint32_t>(responseHeader->bucketsVisited);
        enumResult.corruptBucketCount = static_cast<std::uint32_t>(responseHeader->corruptBucketCount);
        enumResult.readFailureCount = static_cast<std::uint32_t>(responseHeader->readFailureCount);
        enumResult.duplicateCount = static_cast<std::uint32_t>(responseHeader->duplicateCount);
        enumResult.lastStatus = static_cast<long>(responseHeader->lastStatus);

        const std::size_t availableCount =
            (enumResult.io.bytesReturned - KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t parsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            availableCount);
        enumResult.entries.reserve(parsedCount);
        for (std::size_t index = 0U; index < parsedCount; ++index)
        {
            const std::size_t entryOffset = KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE +
                (index * static_cast<std::size_t>(responseHeader->entrySize));
            if (entryOffset + sizeof(KSWORD_ARK_TIMER_DPC_ENTRY) > responseBuffer.size())
            {
                break;
            }
            const auto* sourceEntry = reinterpret_cast<const KSWORD_ARK_TIMER_DPC_ENTRY*>(
                responseBuffer.data() + entryOffset);
            KernelTimerDpcEntry row{};
            row.processorGroup = sourceEntry->processorGroup;
            row.processorNumber = sourceEntry->processorNumber;
            row.bucketIndex = sourceEntry->bucketIndex;
            row.flags = sourceEntry->flags;
            row.timerType = sourceEntry->timerType;
            row.period = sourceEntry->period;
            row.dueTime = sourceEntry->dueTime;
            row.timerAddress = sourceEntry->timerAddress;
            row.dpcAddress = sourceEntry->dpcAddress;
            row.deferredRoutine = sourceEntry->deferredRoutine;
            row.deferredContext = sourceEntry->deferredContext;
            enumResult.entries.push_back(row);
        }

        std::ostringstream stream;
        stream << "version=" << enumResult.version
            << ", queryStatus=" << enumResult.queryStatus
            << ", statusFlags=0x" << std::hex << enumResult.statusFlags << std::dec
            << ", processors=" << enumResult.processorCount
            << ", buckets=" << enumResult.bucketsVisited
            << ", total=" << enumResult.totalCount
            << ", returned=" << enumResult.returnedCount
            << ", parsed=" << enumResult.entries.size()
            << ", corrupt=" << enumResult.corruptBucketCount
            << ", readFailures=" << enumResult.readFailureCount
            << ", duplicates=" << enumResult.duplicateCount;
        enumResult.io.message = stream.str();
        return enumResult;
    }

    DriverObjectQueryResult DriverClient::queryDriverObject(
        const std::wstring& driverName,
        const unsigned long flags,
        const unsigned long maxDevices,
        const unsigned long maxAttachedDevices) const
    {
        DriverObjectQueryResult queryResult{};
        KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST request{};
        request.flags = flags;
        request.maxDevices = maxDevices;
        request.maxAttachedDevices = maxAttachedDevices;
        copyWideToFixed(
            request.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
            driverName);

        std::vector<std::uint8_t> responseBuffer(2U * 1024U * 1024U, 0U);
        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!queryResult.io.ok)
        {
            queryResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT) failed, error=" +
                std::to_string(queryResult.io.win32Error);
            return queryResult;
        }

        // v3 起响应头在 devices[] 前多出 startIo；旧驱动（v2）头更短，先按 v2 长度取 version 再定头长。
        constexpr std::size_t headerSizeV2 = KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE_V2_HEADER_SIZE;
        constexpr std::size_t headerSizeV3 =
            sizeof(KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE) -
            sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY);
        if (queryResult.io.bytesReturned < headerSizeV2)
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "driver-object response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE*>(responseBuffer.data());
        const bool hasStartIo = responseHeader->version >= KSWORD_ARK_DRIVER_OBJECT_PROTOCOL_VERSION_V3;
        const std::size_t headerSize = hasStartIo ? headerSizeV3 : headerSizeV2;
        if (queryResult.io.bytesReturned < headerSize)
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "driver-object response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }
        if (responseHeader->deviceEntrySize < KSWORD_ARK_DRIVER_DEVICE_ENTRY_V1_SIZE)
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "driver-object device entry size invalid, entrySize=" +
                std::to_string(responseHeader->deviceEntrySize);
            return queryResult;
        }

        queryResult.version = static_cast<std::uint32_t>(responseHeader->version);
        queryResult.queryStatus = static_cast<std::uint32_t>(responseHeader->queryStatus);
        queryResult.fieldFlags = static_cast<std::uint32_t>(responseHeader->fieldFlags);
        queryResult.majorFunctionCount = static_cast<std::uint32_t>(responseHeader->majorFunctionCount);
        queryResult.totalDeviceCount = static_cast<std::uint32_t>(responseHeader->totalDeviceCount);
        queryResult.returnedDeviceCount = static_cast<std::uint32_t>(responseHeader->returnedDeviceCount);
        queryResult.lastStatus = static_cast<long>(responseHeader->lastStatus);
        queryResult.driverFlags = static_cast<std::uint32_t>(responseHeader->driverFlags);
        queryResult.driverSize = static_cast<std::uint32_t>(responseHeader->driverSize);
        queryResult.driverObjectAddress = static_cast<std::uint64_t>(responseHeader->driverObjectAddress);
        queryResult.driverStart = static_cast<std::uint64_t>(responseHeader->driverStart);
        queryResult.driverSection = static_cast<std::uint64_t>(responseHeader->driverSection);
        queryResult.driverUnload = static_cast<std::uint64_t>(responseHeader->driverUnload);
        queryResult.driverName = fixedKernelWideToString(responseHeader->driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
        queryResult.serviceKeyName = fixedKernelWideToString(responseHeader->serviceKeyName, KSWORD_ARK_DRIVER_SERVICE_KEY_CHARS);
        queryResult.imagePath = fixedKernelWideToString(responseHeader->imagePath, KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS);

        const std::size_t majorCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->majorFunctionCount),
            static_cast<std::size_t>(KSWORD_ARK_DRIVER_MAJOR_FUNCTION_COUNT));
        queryResult.majorFunctions.reserve(majorCount);
        for (std::size_t index = 0; index < majorCount; ++index)
        {
            const KSWORD_ARK_DRIVER_MAJOR_FUNCTION_ENTRY& sourceEntry =
                responseHeader->majorFunctions[index];
            DriverMajorFunctionEntry row{};
            row.majorFunction = static_cast<std::uint32_t>(sourceEntry.majorFunction);
            row.flags = static_cast<std::uint32_t>(sourceEntry.flags);
            row.dispatchAddress = static_cast<std::uint64_t>(sourceEntry.dispatchAddress);
            row.moduleBase = static_cast<std::uint64_t>(sourceEntry.moduleBase);
            row.moduleName = fixedKernelWideToString(sourceEntry.moduleName, KSWORD_ARK_DRIVER_MODULE_NAME_CHARS);
            queryResult.majorFunctions.push_back(std::move(row));
        }

        if (hasStartIo)
        {
            const KSWORD_ARK_DRIVER_START_IO_ENTRY& startIo = responseHeader->startIo;
            queryResult.startIo.state = static_cast<std::uint32_t>(startIo.state);
            queryResult.startIo.flags = static_cast<std::uint32_t>(startIo.flags);
            queryResult.startIo.address = static_cast<std::uint64_t>(startIo.address);
            queryResult.startIo.moduleBase = static_cast<std::uint64_t>(startIo.moduleBase);
            queryResult.startIo.moduleName = fixedKernelWideToString(startIo.moduleName, KSWORD_ARK_DRIVER_MODULE_NAME_CHARS);
        }

        const std::size_t availableDeviceCount =
            (queryResult.io.bytesReturned - headerSize) /
            static_cast<std::size_t>(responseHeader->deviceEntrySize);
        const std::size_t parsedDeviceCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedDeviceCount),
            availableDeviceCount);
        queryResult.devices.reserve(parsedDeviceCount);
        for (std::size_t index = 0; index < parsedDeviceCount; ++index)
        {
            const std::size_t entryOffset =
                headerSize + (index * static_cast<std::size_t>(responseHeader->deviceEntrySize));
            const auto* sourceEntry =
                reinterpret_cast<const KSWORD_ARK_DRIVER_DEVICE_ENTRY*>(responseBuffer.data() + entryOffset);
            DriverDeviceEntry row{};
            row.relationDepth = static_cast<std::uint32_t>(sourceEntry->relationDepth);
            row.deviceType = static_cast<std::uint32_t>(sourceEntry->deviceType);
            row.flags = static_cast<std::uint32_t>(sourceEntry->flags);
            row.characteristics = static_cast<std::uint32_t>(sourceEntry->characteristics);
            row.stackSize = static_cast<std::uint32_t>(sourceEntry->stackSize);
            row.alignmentRequirement = static_cast<std::uint32_t>(sourceEntry->alignmentRequirement);
            row.nameStatus = static_cast<long>(sourceEntry->nameStatus);
            row.rootDeviceObjectAddress = static_cast<std::uint64_t>(sourceEntry->rootDeviceObjectAddress);
            row.deviceObjectAddress = static_cast<std::uint64_t>(sourceEntry->deviceObjectAddress);
            row.nextDeviceObjectAddress = static_cast<std::uint64_t>(sourceEntry->nextDeviceObjectAddress);
            row.attachedDeviceObjectAddress = static_cast<std::uint64_t>(sourceEntry->attachedDeviceObjectAddress);
            row.driverObjectAddress = static_cast<std::uint64_t>(sourceEntry->driverObjectAddress);
            row.deviceName = fixedKernelWideToString(sourceEntry->deviceName, KSWORD_ARK_DRIVER_DEVICE_NAME_CHARS);
            // 旧驱动返回 v1 行宽时字段不存在，保持 0；新驱动 v2 才读取公开
            // DEVICE_OBJECT.Timer 快照，避免越过旧响应行边界。
            if (responseHeader->deviceEntrySize >= sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY))
            {
                row.ioTimerAddress = static_cast<std::uint64_t>(sourceEntry->ioTimerAddress);
            }
            queryResult.devices.push_back(std::move(row));
        }

        std::ostringstream stream;
        stream << "version=" << queryResult.version
            << ", status=" << queryResult.queryStatus
            << ", major=" << queryResult.majorFunctions.size()
            << ", devices=" << queryResult.devices.size()
            << "/" << queryResult.totalDeviceCount
            << ", bytesReturned=" << queryResult.io.bytesReturned;
        queryResult.io.message = stream.str();
        return queryResult;
    }

    IoTimerControlResult DriverClient::controlIoTimer(
        const unsigned long action,
        const std::wstring& driverName,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint64_t expectedDeviceObjectAddress,
        const std::uint64_t expectedTimerAddress,
        const bool uiConfirmed) const
    {
        IoTimerControlResult controlResult{};
        KSWORD_ARK_CONTROL_IO_TIMER_REQUEST request{};
        KSWORD_ARK_CONTROL_IO_TIMER_RESPONSE response{};

        request.version = KSWORD_ARK_IO_TIMER_CONTROL_PROTOCOL_VERSION;
        request.action = action;
        request.flags = uiConfirmed
            ? KSWORD_ARK_IO_TIMER_CONTROL_FLAG_UI_CONFIRMED
            : 0UL;
        request.confirmationToken = uiConfirmed
            ? KSWORD_ARK_IO_TIMER_CONTROL_CONFIRMATION_TOKEN
            : 0UL;
        request.expectedDriverObjectAddress =
            static_cast<unsigned long long>(expectedDriverObjectAddress);
        request.expectedDeviceObjectAddress =
            static_cast<unsigned long long>(expectedDeviceObjectAddress);
        request.expectedTimerAddress =
            static_cast<unsigned long long>(expectedTimerAddress);
        copyWideToFixed(
            request.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
            driverName);

        controlResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_IO_TIMER,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!controlResult.io.ok)
        {
            controlResult.unsupported =
                isUnsupportedIoctlError(controlResult.io.win32Error);
            controlResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_CONTROL_IO_TIMER) failed, error=" +
                std::to_string(controlResult.io.win32Error);
            return controlResult;
        }
        if (controlResult.io.bytesReturned < sizeof(response))
        {
            controlResult.io.ok = false;
            controlResult.io.message =
                "IoTimer control response too small, bytesReturned=" +
                std::to_string(controlResult.io.bytesReturned);
            return controlResult;
        }
        if (response.version != KSWORD_ARK_IO_TIMER_CONTROL_PROTOCOL_VERSION ||
            response.size < sizeof(response) ||
            response.action != action)
        {
            controlResult.io.ok = false;
            controlResult.io.message =
                "IoTimer control response protocol mismatch";
            return controlResult;
        }

        controlResult.version = static_cast<std::uint32_t>(response.version);
        controlResult.status = static_cast<std::uint32_t>(response.status);
        controlResult.action = static_cast<std::uint32_t>(response.action);
        controlResult.lastStatus = static_cast<long>(response.lastStatus);
        controlResult.observedDriverObjectAddress =
            static_cast<std::uint64_t>(response.observedDriverObjectAddress);
        controlResult.observedDeviceObjectAddress =
            static_cast<std::uint64_t>(response.observedDeviceObjectAddress);
        controlResult.observedTimerAddress =
            static_cast<std::uint64_t>(response.observedTimerAddress);
        controlResult.io.ntStatus = controlResult.lastStatus;

        std::ostringstream stream;
        stream << "version=" << controlResult.version
            << ", status=" << controlResult.status
            << ", action=" << controlResult.action
            << ", lastStatus=0x" << std::hex
            << static_cast<unsigned long>(controlResult.lastStatus)
            << ", driver=0x" << controlResult.observedDriverObjectAddress
            << ", device=0x" << controlResult.observedDeviceObjectAddress
            << ", timer=0x" << controlResult.observedTimerAddress;
        controlResult.io.message = stream.str();
        return controlResult;
    }

    DriverIntegrityResult DriverClient::queryDriverIntegrity(
        const std::wstring& driverName,
        const std::uint64_t targetModuleBase,
        const unsigned long flags,
        const unsigned long maxRows,
        const unsigned long maxIdtVectorsPerCpu) const
    {
        // 输入：可选 DriverObject 名称、目标模块基址、采集 flags 和预算。
        // 处理：调用只读 Driver Integrity IOCTL，解析 DriverObject/LDR/FastIo/CPU/IDT evidence rows。
        // 返回：DriverIntegrityResult；旧驱动或未注册 IOCTL 时 unsupported=true。
        DriverIntegrityResult integrityResult{};
        KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST request{};
        request.version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
        request.flags = flags;
        request.maxRows = maxRows;
        request.maxIdtVectorsPerCpu = maxIdtVectorsPerCpu;
        request.maxDevices = KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT;
        request.maxAttachedDevices = KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT;
        request.targetModuleBase = static_cast<unsigned long long>(targetModuleBase);
        copyWideToFixed(
            request.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
            driverName);

        constexpr std::size_t headerSize =
            sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE) -
            sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE);
        std::vector<std::uint8_t> responseBuffer(4U * 1024U * 1024U, 0U);
        integrityResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!integrityResult.io.ok)
        {
            integrityResult.unsupported = isUnsupportedIoctlError(integrityResult.io.win32Error);
            integrityResult.io.message = integrityResult.unsupported
                ? "IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY) failed, error=" +
                    std::to_string(integrityResult.io.win32Error);
            return integrityResult;
        }
        if (integrityResult.io.bytesReturned < headerSize)
        {
            integrityResult.io.ok = false;
            integrityResult.io.message =
                "driver integrity response too small, bytesReturned=" +
                std::to_string(integrityResult.io.bytesReturned);
            return integrityResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*>(responseBuffer.data());
        constexpr std::size_t minimumEvidenceSize =
            offsetof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE, entryStatus);
        if (responseHeader->entrySize < minimumEvidenceSize)
        {
            integrityResult.io.ok = false;
            integrityResult.io.message =
                "driver integrity entrySize invalid, entrySize=" +
                std::to_string(responseHeader->entrySize);
            return integrityResult;
        }

        integrityResult.version = static_cast<std::uint32_t>(responseHeader->version);
        integrityResult.queryStatus = static_cast<std::uint32_t>(responseHeader->queryStatus);
        integrityResult.flags = static_cast<std::uint32_t>(responseHeader->flags);
        integrityResult.sourceMask = static_cast<std::uint32_t>(responseHeader->sourceMask);
        integrityResult.fieldFlags = static_cast<std::uint32_t>(responseHeader->fieldFlags);
        integrityResult.statusFlags = static_cast<std::uint32_t>(responseHeader->statusFlags);
        integrityResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        integrityResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        integrityResult.cpuCount = static_cast<std::uint32_t>(responseHeader->cpuCount);
        integrityResult.moduleCount = static_cast<std::uint32_t>(responseHeader->moduleCount);
        integrityResult.lastStatus = static_cast<long>(responseHeader->lastStatus);
        integrityResult.io.ntStatus = integrityResult.lastStatus;
        if (static_cast<unsigned long>(integrityResult.lastStatus) == 0xC00000BBUL ||
            static_cast<unsigned long>(integrityResult.lastStatus) == 0xC0000010UL)
        {
            integrityResult.unsupported = true;
            integrityResult.io.ok = false;
            integrityResult.io.message =
                "IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY unsupported by current driver response";
            return integrityResult;
        }

        const std::size_t availableCount =
            (static_cast<std::size_t>(integrityResult.io.bytesReturned) - headerSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t parsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            availableCount);
        integrityResult.entries.reserve(parsedCount);
        for (std::size_t index = 0U; index < parsedCount; ++index)
        {
            const std::size_t entryOffset =
                headerSize + (index * static_cast<std::size_t>(responseHeader->entrySize));
            if (entryOffset + static_cast<std::size_t>(responseHeader->entrySize) > responseBuffer.size())
            {
                break;
            }

            const auto* sourceEntry =
                reinterpret_cast<const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE*>(
                    responseBuffer.data() + entryOffset);
            DriverIntegrityEvidenceEntry row{};
            row.evidenceClass = static_cast<std::uint32_t>(sourceEntry->evidenceClass);
            row.riskFlags = static_cast<std::uint32_t>(sourceEntry->riskFlags);
            row.sourceMask = static_cast<std::uint32_t>(sourceEntry->sourceMask);
            row.confidence = static_cast<std::uint32_t>(sourceEntry->confidence);
            row.processorGroup = static_cast<std::uint32_t>(sourceEntry->processorGroup);
            row.processorNumber = static_cast<std::uint32_t>(sourceEntry->processorNumber);
            row.vector = static_cast<std::uint32_t>(sourceEntry->vector);
            row.ownerModuleSize = static_cast<std::uint32_t>(sourceEntry->ownerModuleSize);
            row.objectAddress = static_cast<std::uint64_t>(sourceEntry->objectAddress);
            row.targetAddress = static_cast<std::uint64_t>(sourceEntry->targetAddress);
            row.ownerModuleBase = static_cast<std::uint64_t>(sourceEntry->ownerModuleBase);
            row.ownerModule = fixedKernelWideToString(
                sourceEntry->ownerModule,
                KSWORD_ARK_DRIVER_INTEGRITY_OWNER_CHARS);
            row.detail = fixedKernelWideToString(
                sourceEntry->detail,
                KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS);
            const auto hasTypedField = [entrySize = responseHeader->entrySize](const std::size_t fieldOffset, const std::size_t fieldBytes) -> bool
            {
                // 输入：R0 返回的单行大小、字段偏移和字段长度。
                // 处理：兼容 v1/v2 DriverIntegrityEvidence 前缀，避免旧驱动缺字段时越界读取。
                // 返回：true 表示该字段完整包含在当前 entrySize 内。
                return static_cast<std::size_t>(entrySize) >= fieldOffset + fieldBytes;
            };
            if (hasTypedField(offsetof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE, deviceFlags), sizeof(sourceEntry->deviceFlags)))
            {
                row.entryStatus = static_cast<std::uint32_t>(sourceEntry->entryStatus);
                row.statusFlags = static_cast<std::uint32_t>(sourceEntry->statusFlags);
                row.fieldMask = static_cast<std::uint32_t>(sourceEntry->fieldMask);
                row.riskScore = static_cast<std::uint32_t>(sourceEntry->riskScore);
                row.rangeState = static_cast<std::uint32_t>(sourceEntry->rangeState);
                row.ordinal = static_cast<std::uint32_t>(sourceEntry->ordinal);
                row.deviceType = static_cast<std::uint32_t>(sourceEntry->deviceType);
                row.deviceFlags = static_cast<std::uint32_t>(sourceEntry->deviceFlags);
            }
            if (hasTypedField(offsetof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE, kldrSizeOfImage), sizeof(sourceEntry->kldrSizeOfImage)))
            {
                row.driverObjectAddress = static_cast<std::uint64_t>(sourceEntry->driverObjectAddress);
                row.driverStart = static_cast<std::uint64_t>(sourceEntry->driverStart);
                row.driverSize = static_cast<std::uint64_t>(sourceEntry->driverSize);
                row.driverSection = static_cast<std::uint64_t>(sourceEntry->driverSection);
                row.driverUnload = static_cast<std::uint64_t>(sourceEntry->driverUnload);
                row.deviceObjectAddress = static_cast<std::uint64_t>(sourceEntry->deviceObjectAddress);
                row.nextDeviceObjectAddress = static_cast<std::uint64_t>(sourceEntry->nextDeviceObjectAddress);
                row.attachedDeviceObjectAddress = static_cast<std::uint64_t>(sourceEntry->attachedDeviceObjectAddress);
                row.deviceDriverObjectAddress = static_cast<std::uint64_t>(sourceEntry->deviceDriverObjectAddress);
                row.kldrEntryAddress = static_cast<std::uint64_t>(sourceEntry->kldrEntryAddress);
                row.kldrListHeadAddress = static_cast<std::uint64_t>(sourceEntry->kldrListHeadAddress);
                row.kldrDllBase = static_cast<std::uint64_t>(sourceEntry->kldrDllBase);
                row.kldrSizeOfImage = static_cast<std::uint32_t>(sourceEntry->kldrSizeOfImage);
            }
            if (hasTypedField(offsetof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE, descriptorRawHigh), sizeof(sourceEntry->descriptorRawHigh)))
            {
                row.descriptorSelector = static_cast<std::uint32_t>(sourceEntry->descriptorSelector);
                row.descriptorType = static_cast<std::uint32_t>(sourceEntry->descriptorType);
                row.descriptorDpl = static_cast<std::uint32_t>(sourceEntry->descriptorDpl);
                row.descriptorFlags = static_cast<std::uint32_t>(sourceEntry->descriptorFlags);
                row.descriptorSize = static_cast<std::uint32_t>(sourceEntry->descriptorSize);
                row.descriptorTableLimit = static_cast<std::uint32_t>(sourceEntry->descriptorTableLimit);
                row.descriptorTableBase = static_cast<std::uint64_t>(sourceEntry->descriptorTableBase);
                row.descriptorBase = static_cast<std::uint64_t>(sourceEntry->descriptorBase);
                row.descriptorLimit = static_cast<std::uint64_t>(sourceEntry->descriptorLimit);
                row.descriptorRawLow = static_cast<std::uint64_t>(sourceEntry->descriptorRawLow);
                row.descriptorRawHigh = static_cast<std::uint64_t>(sourceEntry->descriptorRawHigh);
            }
            if (hasTypedField(
                    offsetof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE, baselineDescriptorRawHigh),
                    sizeof(sourceEntry->baselineDescriptorRawHigh)))
            {
                row.descriptorBaselineFlags = static_cast<std::uint32_t>(sourceEntry->baselineDescriptorFlags);
                row.descriptorBaselineGeneration = static_cast<std::uint32_t>(sourceEntry->baselineGeneration);
                row.descriptorBaselineHandler = static_cast<std::uint64_t>(sourceEntry->baselineDescriptorBase);
                row.descriptorBaselineRawLow = static_cast<std::uint64_t>(sourceEntry->baselineDescriptorRawLow);
                row.descriptorBaselineRawHigh = static_cast<std::uint64_t>(sourceEntry->baselineDescriptorRawHigh);
            }
            integrityResult.entries.push_back(std::move(row));
        }

        std::ostringstream stream;
        stream << "version=" << integrityResult.version
            << ", status=" << integrityResult.queryStatus
            << ", total=" << integrityResult.totalCount
            << ", returned=" << integrityResult.returnedCount
            << ", parsed=" << integrityResult.entries.size()
            << ", cpu=" << integrityResult.cpuCount
            << ", modules=" << integrityResult.moduleCount
            << ", fields=0x" << std::hex << integrityResult.fieldFlags
            << ", statusFlags=0x" << integrityResult.statusFlags
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(integrityResult.lastStatus);
        integrityResult.io.message = stream.str();
        return integrityResult;
    }

    UnloadedDriverQueryResult DriverClient::queryUnloadedDrivers(
        const std::uint32_t source,
        const unsigned long maxRows) const
    {
        // 输入：三个只读来源之一和单次返回行数预算。
        // 处理：构造固定请求头，按预算分配变长响应并严格校验协议边界。
        // 返回：统一 R3 行模型；业务降级状态保留在 queryStatus/lastStatus。
        UnloadedDriverQueryResult queryResult{};
        queryResult.source = source;

        const bool sourceValid =
            source == KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS ||
            source == KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE ||
            source == KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST;
        if (!sourceValid)
        {
            queryResult.io.ok = false;
            queryResult.io.win32Error = ERROR_INVALID_PARAMETER;
            queryResult.io.message = "unloaded driver source is invalid";
            return queryResult;
        }

        const unsigned long boundedRows = std::max<unsigned long>(
            1UL,
            std::min<unsigned long>(
                maxRows == 0UL
                    ? KSWORD_ARK_UNLOADED_DRIVER_DEFAULT_ROWS
                    : maxRows,
                KSWORD_ARK_UNLOADED_DRIVER_MAX_ROWS));
        constexpr std::size_t headerSize =
            KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE;
        const std::size_t responseBytes =
            headerSize +
            (static_cast<std::size_t>(boundedRows) *
                sizeof(KSWORD_ARK_UNLOADED_DRIVER_ROW));

        KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST request{};
        request.version = KSWORD_ARK_UNLOADED_DRIVER_PROTOCOL_VERSION;
        request.size = static_cast<unsigned long>(sizeof(request));
        request.source = static_cast<unsigned long>(source);
        request.maxRows = boundedRows;

        std::vector<std::uint8_t> responseBuffer(responseBytes, 0U);
        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!queryResult.io.ok)
        {
            queryResult.unsupported =
                isUnsupportedIoctlError(queryResult.io.win32Error) ||
                queryResult.io.win32Error == ERROR_CALL_NOT_IMPLEMENTED;
            queryResult.io.message = queryResult.unsupported
                ? "IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS) failed, error=" +
                    std::to_string(queryResult.io.win32Error);
            return queryResult;
        }
        if (queryResult.io.bytesReturned < headerSize)
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "unloaded driver response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }

        const auto* response =
            reinterpret_cast<const KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE*>(
                responseBuffer.data());
        constexpr std::uint32_t knownResponseFlags =
            KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_TRUNCATED |
            KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_SKIPPED_INVALID_ROW |
            KSWORD_ARK_UNLOADED_DRIVER_RESPONSE_FLAG_SNAPSHOT_RACY;
        const bool headerValid =
            response->version == KSWORD_ARK_UNLOADED_DRIVER_PROTOCOL_VERSION &&
            response->rowSize == sizeof(KSWORD_ARK_UNLOADED_DRIVER_ROW) &&
            response->source == source &&
            response->queryStatus <= KSWORD_ARK_UNLOADED_DRIVER_STATUS_PARTIAL &&
            (response->responseFlags & ~knownResponseFlags) == 0U &&
            response->returnedRows <= boundedRows &&
            response->returnedRows <= response->totalRows &&
            response->reserved[0] == 0U &&
            response->reserved[1] == 0U &&
            response->size >= headerSize &&
            response->size == queryResult.io.bytesReturned;
        if (!headerValid)
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "unloaded driver response header is invalid";
            return queryResult;
        }

        const std::size_t returnedRows =
            static_cast<std::size_t>(response->returnedRows);
        if (returnedRows >
            (std::numeric_limits<std::size_t>::max() - headerSize) /
                sizeof(KSWORD_ARK_UNLOADED_DRIVER_ROW))
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "unloaded driver response row count overflows size";
            return queryResult;
        }
        const std::size_t requiredResponseBytes =
            headerSize +
            (returnedRows * sizeof(KSWORD_ARK_UNLOADED_DRIVER_ROW));
        if (requiredResponseBytes !=
                static_cast<std::size_t>(response->size) ||
            requiredResponseBytes >
                static_cast<std::size_t>(queryResult.io.bytesReturned) ||
            returnedRows > boundedRows)
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "unloaded driver response size contract is invalid";
            return queryResult;
        }

        queryResult.queryStatus =
            static_cast<std::uint32_t>(response->queryStatus);
        queryResult.responseFlags =
            static_cast<std::uint32_t>(response->responseFlags);
        queryResult.totalRows =
            static_cast<std::uint32_t>(response->totalRows);
        queryResult.skippedRows =
            static_cast<std::uint32_t>(response->skippedRows);
        queryResult.lastStatus = static_cast<long>(response->lastStatus);
        queryResult.io.ntStatus = queryResult.lastStatus;

        constexpr std::uint32_t knownRowFlags =
            KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_NAME |
            KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_BASE |
            KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_SIZE |
            KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_TIMESTAMP |
            KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_LOAD_STATUS |
            KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME;
        queryResult.entries.reserve(returnedRows);
        for (std::size_t rowIndex = 0U;
             rowIndex < returnedRows;
             ++rowIndex)
        {
            const KSWORD_ARK_UNLOADED_DRIVER_ROW& sourceRow =
                response->rows[rowIndex];
            const std::size_t nameBytes =
                static_cast<std::size_t>(sourceRow.nameLengthBytes);
            const bool hasName =
                (sourceRow.flags &
                    KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_NAME) != 0U;
            const bool hasBase =
                (sourceRow.flags &
                    KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_BASE) != 0U;
            const bool hasSize =
                (sourceRow.flags &
                    KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_SIZE) != 0U;
            const bool hasTimestamp =
                (sourceRow.flags &
                    KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_TIMESTAMP) != 0U;
            const bool hasLoadStatus =
                (sourceRow.flags &
                    KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_LOAD_STATUS) != 0U;
            const bool hasUnloadTime =
                (sourceRow.flags &
                    KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME) != 0U;
            const std::size_t nameChars = nameBytes / sizeof(wchar_t);
            if (sourceRow.source != source ||
                (sourceRow.flags & ~knownRowFlags) != 0U ||
                sourceRow.reserved != 0U ||
                nameBytes > sizeof(sourceRow.driverName) - sizeof(wchar_t) ||
                (nameBytes % sizeof(wchar_t)) != 0U ||
                hasName != (nameBytes != 0U) ||
                (!hasBase && sourceRow.baseAddress != 0ULL) ||
                (!hasSize && sourceRow.imageSize != 0ULL) ||
                (!hasTimestamp && sourceRow.timeDateStamp != 0UL) ||
                (!hasLoadStatus && sourceRow.loadStatus != 0L) ||
                (!hasUnloadTime && sourceRow.unloadTime != 0ULL) ||
                sourceRow.driverName[nameChars] != L'\0')
            {
                queryResult.io.ok = false;
                queryResult.io.message =
                    "unloaded driver response row is invalid";
                queryResult.entries.clear();
                return queryResult;
            }

            UnloadedDriverEntry row{};
            row.source = static_cast<std::uint32_t>(sourceRow.source);
            row.flags = static_cast<std::uint32_t>(sourceRow.flags);
            row.entryAddress =
                static_cast<std::uint64_t>(sourceRow.entryAddress);
            row.baseAddress =
                static_cast<std::uint64_t>(sourceRow.baseAddress);
            row.imageSize =
                static_cast<std::uint64_t>(sourceRow.imageSize);
            row.unloadTime =
                static_cast<std::uint64_t>(sourceRow.unloadTime);
            row.timeDateStamp =
                static_cast<std::uint32_t>(sourceRow.timeDateStamp);
            row.loadStatus = static_cast<long>(sourceRow.loadStatus);
            row.driverName.assign(
                sourceRow.driverName,
                sourceRow.driverName + nameChars);
            queryResult.entries.push_back(std::move(row));
        }

        std::ostringstream stream;
        stream << "source=" << queryResult.source
            << ", status=" << queryResult.queryStatus
            << ", total=" << queryResult.totalRows
            << ", returned=" << response->returnedRows
            << ", parsed=" << queryResult.entries.size()
            << ", skipped=" << queryResult.skippedRows
            << ", flags=0x" << std::hex << queryResult.responseFlags
            << ", lastStatus=0x"
            << static_cast<unsigned long>(queryResult.lastStatus);
        queryResult.io.message = stream.str();
        return queryResult;
    }

    DriverIntegrityResult DriverClient::queryKernelCpuIntegrity(
        const unsigned long flags,
        const unsigned long maxRows,
        const unsigned long maxIdtVectorsPerCpu) const
    {
        // 输入：CPU/IDT evidence flags 与预算。
        // 处理：复用 Driver Integrity 协议，不传 DriverObject 名称或模块基址。
        // 返回：DriverIntegrityResult，只读展示 CPU entry evidence。
        return queryDriverIntegrity(
            std::wstring(),
            0ULL,
            flags,
            maxRows,
            maxIdtVectorsPerCpu);
    }

    CpuHardwareSnapshotResult DriverClient::queryCpuHardwareSnapshot() const
    {
        // 输入：无；R0 CPUID 查询不需要筛选参数。
        // 处理：读取固定大小响应并复制到 R3 稳定模型，避免 UI 直接依赖共享 C 结构布局。
        // 返回：CpuHardwareSnapshotResult；旧驱动未注册 IOCTL 时 unsupported=true。
        CpuHardwareSnapshotResult snapshotResult{};
        KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE response{};

        snapshotResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE,
            nullptr,
            0UL,
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!snapshotResult.io.ok)
        {
            snapshotResult.unsupported = isUnsupportedIoctlError(snapshotResult.io.win32Error);
            snapshotResult.io.message = snapshotResult.unsupported
                ? "IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE) failed, error=" +
                    std::to_string(snapshotResult.io.win32Error);
            return snapshotResult;
        }
        if (snapshotResult.io.bytesReturned < sizeof(response))
        {
            snapshotResult.io.ok = false;
            snapshotResult.io.message =
                "cpu hardware response too small, bytesReturned=" +
                std::to_string(snapshotResult.io.bytesReturned);
            return snapshotResult;
        }

        snapshotResult.version = static_cast<std::uint32_t>(response.version);
        snapshotResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        snapshotResult.logicalProcessorCount = static_cast<std::uint32_t>(response.logicalProcessorCount);
        snapshotResult.activeProcessorCount = static_cast<std::uint32_t>(response.activeProcessorCount);
        snapshotResult.packageCount = static_cast<std::uint32_t>(response.packageCount);
        snapshotResult.family = static_cast<std::uint32_t>(response.family);
        snapshotResult.model = static_cast<std::uint32_t>(response.model);
        snapshotResult.stepping = static_cast<std::uint32_t>(response.stepping);
        snapshotResult.processorType = static_cast<std::uint32_t>(response.processorType);
        snapshotResult.brandIndex = static_cast<std::uint32_t>(response.brandIndex);
        snapshotResult.clflushLineSize = static_cast<std::uint32_t>(response.clflushLineSize);
        snapshotResult.initialApicId = static_cast<std::uint32_t>(response.initialApicId);
        snapshotResult.maxBasicLeaf = static_cast<std::uint32_t>(response.maxBasicLeaf);
        snapshotResult.maxExtendedLeaf = static_cast<std::uint32_t>(response.maxExtendedLeaf);
        snapshotResult.lastStatus = static_cast<long>(response.lastStatus);
        snapshotResult.io.ntStatus = snapshotResult.lastStatus;
        snapshotResult.featureMask = static_cast<std::uint64_t>(response.featureMask);
        snapshotResult.leaf1Ecx = static_cast<std::uint64_t>(response.leaf1Ecx);
        snapshotResult.leaf1Edx = static_cast<std::uint64_t>(response.leaf1Edx);
        snapshotResult.leaf7Ebx = static_cast<std::uint64_t>(response.leaf7Ebx);
        snapshotResult.leaf7Ecx = static_cast<std::uint64_t>(response.leaf7Ecx);
        snapshotResult.leaf7Edx = static_cast<std::uint64_t>(response.leaf7Edx);
        snapshotResult.leaf80000001Ecx = static_cast<std::uint64_t>(response.leaf80000001Ecx);
        snapshotResult.leaf80000001Edx = static_cast<std::uint64_t>(response.leaf80000001Edx);
        snapshotResult.vendor = fixedKernelAnsiToString(response.vendor, KSWORD_ARK_CPU_HARDWARE_VENDOR_CHARS);
        snapshotResult.brand = fixedKernelAnsiToString(response.brand, KSWORD_ARK_CPU_HARDWARE_BRAND_CHARS);

        std::ostringstream stream;
        stream << "version=" << snapshotResult.version
            << ", vendor=" << snapshotResult.vendor
            << ", brand=" << snapshotResult.brand
            << ", logical=" << snapshotResult.logicalProcessorCount
            << ", active=" << snapshotResult.activeProcessorCount
            << ", family=" << snapshotResult.family
            << ", model=" << snapshotResult.model
            << ", stepping=" << snapshotResult.stepping
            << ", features=0x" << std::hex << snapshotResult.featureMask
            << ", lastStatus=0x" << static_cast<unsigned long>(snapshotResult.lastStatus);
        snapshotResult.io.message = stream.str();
        return snapshotResult;
    }

    PhysicalMemoryLayoutResult DriverClient::queryPhysicalMemoryLayout() const
    {
        // 输入：无；R0 只返回物理内存范围聚合统计。
        // 处理：解析固定大小响应，避免 UI 直接依赖共享 C 结构。
        // 返回：PhysicalMemoryLayoutResult；不会包含任何物理内存字节内容。
        PhysicalMemoryLayoutResult layoutResult{};
        KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE response{};

        layoutResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT,
            nullptr,
            0UL,
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!layoutResult.io.ok)
        {
            layoutResult.unsupported = isUnsupportedIoctlError(layoutResult.io.win32Error);
            layoutResult.io.message = layoutResult.unsupported
                ? "IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT) failed, error=" +
                    std::to_string(layoutResult.io.win32Error);
            return layoutResult;
        }
        if (layoutResult.io.bytesReturned < sizeof(response))
        {
            layoutResult.io.ok = false;
            layoutResult.io.message =
                "physical memory layout response too small, bytesReturned=" +
                std::to_string(layoutResult.io.bytesReturned);
            return layoutResult;
        }

        layoutResult.version = static_cast<std::uint32_t>(response.version);
        layoutResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        layoutResult.rangeCount = static_cast<std::uint32_t>(response.rangeCount);
        layoutResult.zeroLengthRangeCount = static_cast<std::uint32_t>(response.zeroLengthRangeCount);
        layoutResult.truncated = static_cast<std::uint32_t>(response.truncated);
        layoutResult.lastStatus = static_cast<long>(response.lastStatus);
        layoutResult.io.ntStatus = layoutResult.lastStatus;
        layoutResult.totalPhysicalBytes = static_cast<std::uint64_t>(response.totalPhysicalBytes);
        layoutResult.highestPhysicalAddress = static_cast<std::uint64_t>(response.highestPhysicalAddress);
        layoutResult.largestRangeBytes = static_cast<std::uint64_t>(response.largestRangeBytes);
        layoutResult.smallestRangeBytes = static_cast<std::uint64_t>(response.smallestRangeBytes);
        layoutResult.firstBaseAddress = static_cast<std::uint64_t>(response.firstBaseAddress);
        layoutResult.lastEndAddress = static_cast<std::uint64_t>(response.lastEndAddress);
        layoutResult.estimatedAddressSpaceGapBytes = static_cast<std::uint64_t>(response.estimatedAddressSpaceGapBytes);

        std::ostringstream stream;
        stream << "version=" << layoutResult.version
            << ", ranges=" << layoutResult.rangeCount
            << ", total=" << layoutResult.totalPhysicalBytes
            << ", highest=0x" << std::hex << layoutResult.highestPhysicalAddress
            << ", largest=" << std::dec << layoutResult.largestRangeBytes
            << ", gap=" << layoutResult.estimatedAddressSpaceGapBytes
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(layoutResult.lastStatus);
        layoutResult.io.message = stream.str();
        return layoutResult;
    }

    DriverForceUnloadResult DriverClient::forceUnloadDriver(
        const std::wstring& driverName,
        const unsigned long flags,
        const unsigned long timeoutMilliseconds) const
    {
        // 作用：按 DriverObject 名称请求 R0 调用 DriverUnload。
        // 返回：固定响应；R0 地址仅作为诊断文本，不作为二次操作凭据。
        DriverForceUnloadResult unloadResult{};
        KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST request{};
        KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE response{};
        request.version = KSWORD_ARK_FORCE_UNLOAD_DRIVER_PROTOCOL_VERSION;
        request.flags = flags;
        request.timeoutMilliseconds = timeoutMilliseconds;
        copyWideToFixed(
            request.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
            driverName);

        unloadResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!unloadResult.io.ok)
        {
            unloadResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER) failed, error=" +
                std::to_string(unloadResult.io.win32Error);
            return unloadResult;
        }
        if (unloadResult.io.bytesReturned < sizeof(response))
        {
            unloadResult.io.ok = false;
            unloadResult.io.message =
                "driver-unload response too small, bytesReturned=" +
                std::to_string(unloadResult.io.bytesReturned);
            return unloadResult;
        }

        unloadResult.version = static_cast<std::uint32_t>(response.version);
        unloadResult.status = static_cast<std::uint32_t>(response.status);
        unloadResult.flags = static_cast<std::uint32_t>(response.flags);
        unloadResult.lastStatus = static_cast<long>(response.lastStatus);
        unloadResult.waitStatus = static_cast<long>(response.waitStatus);
        unloadResult.cleanupFlagsApplied = static_cast<std::uint32_t>(response.cleanupFlagsApplied);
        unloadResult.deletedDeviceCount = static_cast<std::uint32_t>(response.deletedDeviceCount);
        unloadResult.driverObjectAddress = static_cast<std::uint64_t>(response.driverObjectAddress);
        unloadResult.driverUnloadAddress = static_cast<std::uint64_t>(response.driverUnloadAddress);
        unloadResult.callbackCandidates = static_cast<std::uint32_t>(response.callbackCandidates);
        unloadResult.callbacksRemoved = static_cast<std::uint32_t>(response.callbacksRemoved);
        unloadResult.callbackFailures = static_cast<std::uint32_t>(response.callbackFailures);
        unloadResult.callbackLastStatus = static_cast<long>(response.callbackLastStatus);
        unloadResult.threadCandidates = static_cast<std::uint32_t>(response.threadCandidates);
        unloadResult.threadsTerminated = static_cast<std::uint32_t>(response.threadsTerminated);
        unloadResult.threadFailures = static_cast<std::uint32_t>(response.threadFailures);
        unloadResult.threadLastStatus = static_cast<long>(response.threadLastStatus);
        unloadResult.detachedDeviceCount = static_cast<std::uint32_t>(response.detachedDeviceCount);
        unloadResult.driverName = fixedKernelWideToString(
            response.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
        unloadResult.io.ntStatus = unloadResult.lastStatus;

        std::ostringstream stream;
        stream << "status=" << unloadResult.status
            << ", object=0x" << std::hex << unloadResult.driverObjectAddress
            << ", unload=0x" << unloadResult.driverUnloadAddress
            << ", flags=0x" << unloadResult.flags
            << ", applied=0x" << unloadResult.cleanupFlagsApplied
            << ", deletedDevices=" << std::dec << unloadResult.deletedDeviceCount
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(unloadResult.lastStatus)
            << ", waitStatus=0x" << static_cast<unsigned long>(unloadResult.waitStatus)
            << ", callbackCandidates=" << std::dec << unloadResult.callbackCandidates
            << ", callbacksRemoved=" << unloadResult.callbacksRemoved
            << ", callbackFailures=" << unloadResult.callbackFailures
            << ", callbackLast=0x" << std::hex << static_cast<unsigned long>(unloadResult.callbackLastStatus)
            << ", threadCandidates=" << std::dec << unloadResult.threadCandidates
            << ", threadsTerminated=" << unloadResult.threadsTerminated
            << ", threadFailures=" << unloadResult.threadFailures
            << ", threadLast=0x" << std::hex << static_cast<unsigned long>(unloadResult.threadLastStatus)
            << ", detachedDevices=" << std::dec << unloadResult.detachedDeviceCount;
        unloadResult.io.message = stream.str();
        return unloadResult;
    }

    DriverForceUnloadResult DriverClient::forceUnloadDriverByModuleBase(
        const std::uint64_t moduleBase,
        const std::wstring& fallbackDriverName,
        const unsigned long flags,
        const unsigned long timeoutMilliseconds) const
    {
        // 作用：按内核模块基址请求 R0 反查 DriverObject 并执行强制清理。
        // 返回：固定响应；如果模块基址无法匹配 DriverObject，R0 会继续按 fallbackDriverName 兜底。
        DriverForceUnloadResult unloadResult{};
        KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST request{};
        KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE response{};
        request.version = KSWORD_ARK_FORCE_UNLOAD_DRIVER_PROTOCOL_VERSION;
        request.flags = flags | KSWORD_ARK_DRIVER_UNLOAD_FLAG_TARGET_MODULE_BASE_PRESENT;
        request.timeoutMilliseconds = timeoutMilliseconds;
        request.targetModuleBase = static_cast<unsigned long long>(moduleBase);
        copyWideToFixed(
            request.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
            fallbackDriverName);

        unloadResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!unloadResult.io.ok)
        {
            unloadResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER/module-base) failed, error=" +
                std::to_string(unloadResult.io.win32Error);
            return unloadResult;
        }
        if (unloadResult.io.bytesReturned < sizeof(response))
        {
            unloadResult.io.ok = false;
            unloadResult.io.message =
                "driver-unload/module-base response too small, bytesReturned=" +
                std::to_string(unloadResult.io.bytesReturned);
            return unloadResult;
        }

        unloadResult.version = static_cast<std::uint32_t>(response.version);
        unloadResult.status = static_cast<std::uint32_t>(response.status);
        unloadResult.flags = static_cast<std::uint32_t>(response.flags);
        unloadResult.lastStatus = static_cast<long>(response.lastStatus);
        unloadResult.waitStatus = static_cast<long>(response.waitStatus);
        unloadResult.cleanupFlagsApplied = static_cast<std::uint32_t>(response.cleanupFlagsApplied);
        unloadResult.deletedDeviceCount = static_cast<std::uint32_t>(response.deletedDeviceCount);
        unloadResult.driverObjectAddress = static_cast<std::uint64_t>(response.driverObjectAddress);
        unloadResult.driverUnloadAddress = static_cast<std::uint64_t>(response.driverUnloadAddress);
        unloadResult.callbackCandidates = static_cast<std::uint32_t>(response.callbackCandidates);
        unloadResult.callbacksRemoved = static_cast<std::uint32_t>(response.callbacksRemoved);
        unloadResult.callbackFailures = static_cast<std::uint32_t>(response.callbackFailures);
        unloadResult.callbackLastStatus = static_cast<long>(response.callbackLastStatus);
        unloadResult.threadCandidates = static_cast<std::uint32_t>(response.threadCandidates);
        unloadResult.threadsTerminated = static_cast<std::uint32_t>(response.threadsTerminated);
        unloadResult.threadFailures = static_cast<std::uint32_t>(response.threadFailures);
        unloadResult.threadLastStatus = static_cast<long>(response.threadLastStatus);
        unloadResult.detachedDeviceCount = static_cast<std::uint32_t>(response.detachedDeviceCount);
        unloadResult.driverName = fixedKernelWideToString(
            response.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
        unloadResult.io.ntStatus = unloadResult.lastStatus;

        std::ostringstream stream;
        stream << "moduleBase=0x" << std::hex << moduleBase
            << ", status=" << unloadResult.status
            << ", object=0x" << unloadResult.driverObjectAddress
            << ", unload=0x" << unloadResult.driverUnloadAddress
            << ", flags=0x" << unloadResult.flags
            << ", applied=0x" << unloadResult.cleanupFlagsApplied
            << ", deletedDevices=" << std::dec << unloadResult.deletedDeviceCount
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(unloadResult.lastStatus)
            << ", waitStatus=0x" << static_cast<unsigned long>(unloadResult.waitStatus)
            << ", callbackCandidates=" << std::dec << unloadResult.callbackCandidates
            << ", callbacksRemoved=" << unloadResult.callbacksRemoved
            << ", callbackFailures=" << unloadResult.callbackFailures
            << ", callbackLast=0x" << std::hex << static_cast<unsigned long>(unloadResult.callbackLastStatus)
            << ", threadCandidates=" << std::dec << unloadResult.threadCandidates
            << ", threadsTerminated=" << unloadResult.threadsTerminated
            << ", threadFailures=" << unloadResult.threadFailures
            << ", threadLast=0x" << std::hex << static_cast<unsigned long>(unloadResult.threadLastStatus)
            << ", detachedDevices=" << std::dec << unloadResult.detachedDeviceCount;
        unloadResult.io.message = stream.str();
        return unloadResult;
    }
}
