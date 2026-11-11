#include "ArkDriverClient.h"

#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::ark
{
    namespace
    {
        constexpr long kNtStatusInvalidParameter = -1073741811L;

        std::wstring fixedWideToWString(const wchar_t* textBuffer, const std::size_t maxChars)
        {
            // textBuffer 用途：解析共享协议中的固定 UTF-16 缓冲。
            // maxChars 用途：限制扫描边界，避免驱动或旧协议缺少 NUL 时越界。
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
    }

    HandleEnumResult DriverClient::enumerateProcessHandles(
        const std::uint32_t processId,
        const unsigned long flags) const
    {
        // processId 输入：
        // - R0 HandleTable 枚举语义只支持“单个真实进程 PID”；
        // - pid 0 不是“全局枚举”，提前在 R3 拦截可避免向驱动刷无效 IOCTL 日志。
        // 返回：io.ok=false，调用方可把它当作该 PID 不可枚举而继续其它诊断路径。
        HandleEnumResult enumResult{};
        if (processId == 0U)
        {
            enumResult.io.ok = false;
            enumResult.io.win32Error = ERROR_INVALID_PARAMETER;
            enumResult.io.ntStatus = kNtStatusInvalidParameter;
            enumResult.processId = processId;
            enumResult.overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
            enumResult.lastStatus = kNtStatusInvalidParameter;
            enumResult.io.message =
                "enumerateProcessHandles requires a non-zero target pid; pid=0 is not a global enumeration request";
            return enumResult;
        }

        KSWORD_ARK_ENUM_PROCESS_HANDLES_REQUEST request{};
        request.flags = flags;
        request.processId = processId;

        constexpr std::size_t headerSize =
            sizeof(KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE) - sizeof(KSWORD_ARK_HANDLE_ENTRY);
        std::vector<std::uint8_t> responseBuffer(1024U * 1024U, 0U);
        enumResult.processId = processId;
        enumResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!enumResult.io.ok)
        {
            // The driver returns a populated response header for transient
            // failures such as STATUS_INVALID_CID. Preserve that NTSTATUS so
            // callers can distinguish normal process churn from protocol or
            // transport failures. Some Windows versions report zero output
            // bytes for a failed DeviceIoControl, so callers still need a
            // conservative process-liveness fallback.
            if (enumResult.io.bytesReturned >= headerSize)
            {
                const auto* responseHeader =
                    reinterpret_cast<const KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE*>(responseBuffer.data());
                enumResult.version = static_cast<std::uint32_t>(responseHeader->version);
                enumResult.processId = static_cast<std::uint32_t>(responseHeader->processId);
                enumResult.overallStatus = static_cast<std::uint32_t>(responseHeader->overallStatus);
                enumResult.lastStatus = static_cast<long>(responseHeader->lastStatus);
                enumResult.io.ntStatus = enumResult.lastStatus;
            }
            enumResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES) failed, error=" +
                std::to_string(enumResult.io.win32Error);
            return enumResult;
        }

        if (enumResult.io.bytesReturned < headerSize)
        {
            enumResult.io.ok = false;
            enumResult.io.message =
                "enum-process-handles response too small, bytesReturned=" +
                std::to_string(enumResult.io.bytesReturned);
            return enumResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE*>(responseBuffer.data());
        if (responseHeader->entrySize < offsetof(KSWORD_ARK_HANDLE_ENTRY, processCreationTime100ns))
        {
            enumResult.io.ok = false;
            enumResult.io.message =
                "enum-process-handles entry size invalid, entrySize=" +
                std::to_string(responseHeader->entrySize);
            return enumResult;
        }

        enumResult.version = static_cast<std::uint32_t>(responseHeader->version);
        enumResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        enumResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        enumResult.processId = static_cast<std::uint32_t>(responseHeader->processId);
        enumResult.overallStatus = static_cast<std::uint32_t>(responseHeader->overallStatus);
        enumResult.lastStatus = static_cast<long>(responseHeader->lastStatus);

        const std::size_t availableCount =
            (enumResult.io.bytesReturned - headerSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t parsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            availableCount);
        enumResult.entries.reserve(parsedCount);

        for (std::size_t index = 0; index < parsedCount; ++index)
        {
            const std::size_t entryOffset =
                headerSize + (index * static_cast<std::size_t>(responseHeader->entrySize));
            const auto* entry =
                reinterpret_cast<const KSWORD_ARK_HANDLE_ENTRY*>(responseBuffer.data() + entryOffset);
            HandleEntry parsedEntry{};

            parsedEntry.processId = static_cast<std::uint32_t>(entry->processId);
            if (responseHeader->entrySize >= sizeof(KSWORD_ARK_HANDLE_ENTRY))
            {
                parsedEntry.processCreationTime100ns = entry->processCreationTime100ns;
            }
            parsedEntry.handleValue = static_cast<std::uint32_t>(entry->handleValue);
            parsedEntry.fieldFlags = static_cast<std::uint32_t>(entry->fieldFlags);
            parsedEntry.decodeStatus = static_cast<std::uint32_t>(entry->decodeStatus);
            parsedEntry.grantedAccess = static_cast<std::uint32_t>(entry->grantedAccess);
            parsedEntry.attributes = static_cast<std::uint32_t>(entry->attributes);
            parsedEntry.objectTypeIndex = static_cast<std::uint32_t>(entry->objectTypeIndex);
            parsedEntry.objectAddress = static_cast<std::uint64_t>(entry->objectAddress);
            parsedEntry.dynDataCapabilityMask = static_cast<std::uint64_t>(entry->dynDataCapabilityMask);
            parsedEntry.epObjectTableOffset = static_cast<std::uint32_t>(entry->epObjectTableOffset);
            parsedEntry.htHandleContentionEventOffset = static_cast<std::uint32_t>(entry->htHandleContentionEventOffset);
            parsedEntry.obDecodeShift = static_cast<std::uint32_t>(entry->obDecodeShift);
            parsedEntry.obAttributesShift = static_cast<std::uint32_t>(entry->obAttributesShift);
            parsedEntry.otNameOffset = static_cast<std::uint32_t>(entry->otNameOffset);
            parsedEntry.otIndexOffset = static_cast<std::uint32_t>(entry->otIndexOffset);
            enumResult.entries.push_back(parsedEntry);
        }

        std::ostringstream stream;
        stream << "version=" << enumResult.version
            << ", pid=" << enumResult.processId
            << ", total=" << enumResult.totalCount
            << ", returned=" << enumResult.returnedCount
            << ", parsed=" << enumResult.entries.size()
            << ", overallStatus=" << enumResult.overallStatus
            << ", lastStatus=0x" << std::hex << std::uppercase << static_cast<unsigned long>(static_cast<std::uint32_t>(enumResult.lastStatus))
            << std::dec << ", bytesReturned=" << enumResult.io.bytesReturned;
        enumResult.io.message = stream.str();
        return enumResult;
    }

    HandleCloseResult DriverClient::closeHandleDetailed(
        const std::uint32_t processId,
        const std::uint64_t handleValue,
        const std::uint64_t expectedCreateTime100ns,
        const std::uint64_t expectedObjectAddress) const
    {
        HandleCloseResult receipt{};
        IoResult& result = receipt.io;
        if (processId <= 4U || processId == ::GetCurrentProcessId() ||
            handleValue == 0U || handleValue >= 0x80000000ULL ||
            expectedCreateTime100ns == 0U || expectedObjectAddress == 0U)
        {
            result.win32Error = ERROR_INVALID_PARAMETER;
            result.ntStatus = kNtStatusInvalidParameter;
            result.message = "invalid, protected, or unverifiable handle identity";
            return receipt;
        }
        KSWORD_ARK_CLOSE_HANDLE_REQUEST request{};
        KSWORD_ARK_CLOSE_HANDLE_RESPONSE response{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_CLOSE_HANDLE_VERSION;
        request.processId = processId;
        request.flags = KSWORD_ARK_CLOSE_HANDLE_FLAG_UI_CONFIRMED;
        request.handleValue = handleValue;
        request.expectedCreateTime100ns = expectedCreateTime100ns;
        request.expectedObjectAddress = expectedObjectAddress;
        result = deviceIoControl(IOCTL_KSWORD_ARK_CLOSE_HANDLE,
            &request, sizeof(request), &response, sizeof(response));
        if (!result.ok)
        {
            result.message = "R0 close transport failed, error=" + std::to_string(result.win32Error);
            return receipt;
        }
        if (result.bytesReturned != sizeof(response) || response.size != sizeof(response) ||
            response.version != KSWORD_ARK_CLOSE_HANDLE_VERSION)
        {
            result.ok = false;
            result.win32Error = ERROR_INVALID_DATA;
            result.message = "R0 close response invalid";
            return receipt;
        }
        receipt.responseValid = true;
        receipt.closeStatus = response.closeStatus;
        receipt.resumeStatus = response.resumeStatus;
        result.ntStatus = response.closeStatus;
        result.ok = response.closeStatus >= 0 && response.resumeStatus >= 0;
        std::ostringstream detail;
        detail << "R0 closeStatus=0x" << std::hex << std::uppercase
            << static_cast<std::uint32_t>(response.closeStatus)
            << ", resumeStatus=0x" << static_cast<std::uint32_t>(response.resumeStatus);
        if (response.closeStatus >= 0 && response.resumeStatus < 0)
        {
            detail << "; handle closed, but process resume failed";
        }
        result.message = detail.str();
        return receipt;
    }

    IoResult DriverClient::closeHandle(
        const std::uint32_t processId,
        const std::uint64_t handleValue,
        const std::uint64_t expectedCreateTime100ns,
        const std::uint64_t expectedObjectAddress) const
    {
        return closeHandleDetailed(processId, handleValue, expectedCreateTime100ns, expectedObjectAddress).io;
    }

    HandleObjectQueryResult DriverClient::queryHandleObject(
        const std::uint32_t processId,
        const std::uint64_t handleValue,
        const unsigned long flags,
        const unsigned long requestedAccess) const
    {
        HandleObjectQueryResult queryResult{};
        KSWORD_ARK_QUERY_HANDLE_OBJECT_REQUEST request{};
        KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE response{};
        request.flags = flags;
        request.processId = processId;
        request.handleValue = handleValue;
        request.requestedAccess = requestedAccess;

        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_HANDLE_OBJECT,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!queryResult.io.ok)
        {
            queryResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_HANDLE_OBJECT) failed, error=" +
                std::to_string(queryResult.io.win32Error);
            return queryResult;
        }
        if (queryResult.io.bytesReturned < sizeof(KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE))
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "query-handle-object response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }

        queryResult.version = static_cast<std::uint32_t>(response.version);
        queryResult.processId = static_cast<std::uint32_t>(response.processId);
        queryResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        queryResult.handleValue = static_cast<std::uint64_t>(response.handleValue);
        queryResult.objectAddress = static_cast<std::uint64_t>(response.objectAddress);
        queryResult.objectTypeIndex = static_cast<std::uint32_t>(response.objectTypeIndex);
        queryResult.queryStatus = static_cast<std::uint32_t>(response.queryStatus);
        queryResult.objectReferenceStatus = static_cast<long>(response.objectReferenceStatus);
        queryResult.typeStatus = static_cast<long>(response.typeStatus);
        queryResult.nameStatus = static_cast<long>(response.nameStatus);
        queryResult.proxyStatus = static_cast<std::uint32_t>(response.proxyStatus);
        queryResult.proxyNtStatus = static_cast<long>(response.proxyNtStatus);
        queryResult.proxyPolicyFlags = static_cast<std::uint32_t>(response.proxyPolicyFlags);
        queryResult.requestedAccess = static_cast<std::uint32_t>(response.requestedAccess);
        queryResult.actualGrantedAccess = static_cast<std::uint32_t>(response.actualGrantedAccess);
        queryResult.proxyHandle = static_cast<std::uint64_t>(response.proxyHandle);
        queryResult.dynDataCapabilityMask = static_cast<std::uint64_t>(response.dynDataCapabilityMask);
        queryResult.otNameOffset = static_cast<std::uint32_t>(response.otNameOffset);
        queryResult.otIndexOffset = static_cast<std::uint32_t>(response.otIndexOffset);
        queryResult.typeName = fixedWideToWString(response.typeName, KSWORD_ARK_OBJECT_TYPE_NAME_CHARS);
        queryResult.objectName = fixedWideToWString(response.objectName, KSWORD_ARK_OBJECT_NAME_CHARS);

        std::ostringstream stream;
        stream << "version=" << queryResult.version
            << ", pid=" << queryResult.processId
            << ", handle=0x" << std::hex << std::uppercase << queryResult.handleValue
            << ", queryStatus=" << std::dec << queryResult.queryStatus
            << ", proxyStatus=" << queryResult.proxyStatus
            << ", bytesReturned=" << queryResult.io.bytesReturned;
        queryResult.io.message = stream.str();
        return queryResult;
    }
}
