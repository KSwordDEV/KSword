#include "ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

namespace ksword::ark
{
    // enumerateProcessModules：发送进程映像枚举请求并验证单页响应。
    // 输入 PID/创建时间/游标/条数；输出仅在完整通过协议边界和身份校验后标记 responseValid。
    ProcessModuleEnumResult DriverClient::enumerateProcessModules(
        const std::uint32_t processId,
        const std::uint64_t expectedCreateTime100ns,
        const std::uint64_t cursor,
        const unsigned long maxRows,
        const unsigned long source) const
    {
        ProcessModuleEnumResult result{};
        if (processId == 0U || maxRows == 0UL || maxRows > KSWORD_ARK_MODULE_MAX_ROWS ||
            source != KSWORD_ARK_MODULE_SOURCE_PROCESS_IMAGE_MAP)
        {
            result.io.message = "enumerateProcessModules received invalid request parameters";
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            return result;
        }

        KSWORD_ARK_ENUM_MODULES_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_MODULE_PROTOCOL_VERSION;
        request.source = source;
        request.processId = processId;
        request.maxRows = maxRows;
        request.expectedCreateTime100ns = expectedCreateTime100ns;
        request.cursor = cursor;

        const std::size_t headerSize = KSWORD_ARK_ENUM_MODULES_RESPONSE_HEADER_SIZE;
        const std::size_t bufferSize = headerSize +
            static_cast<std::size_t>(maxRows) * sizeof(KSWORD_ARK_MODULE_ENTRY);
        std::vector<std::uint8_t> buffer(bufferSize, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_MODULES,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            buffer.data(),
            static_cast<unsigned long>(buffer.size()));
        if (!result.io.ok)
        {
            result.io.message = "DeviceIoControl(IOCTL_KSWORD_ARK_ENUM_MODULES) failed, error=" +
                std::to_string(result.io.win32Error);
            return result;
        }

        if (result.io.bytesReturned < headerSize)
        {
            result.io.ok = false;
            result.io.message = "enum-modules response header is truncated";
            return result;
        }

        const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_MODULES_RESPONSE*>(buffer.data());
        const std::size_t entrySize = static_cast<std::size_t>(response->entrySize);
        const std::size_t declaredSize = static_cast<std::size_t>(response->size);
        const std::size_t declaredPayloadBytes = declaredSize >= headerSize
            ? declaredSize - headerSize : 0U;
        if (declaredSize < headerSize || declaredSize > result.io.bytesReturned ||
            response->version != KSWORD_ARK_MODULE_PROTOCOL_VERSION ||
            response->source != source || response->processId != processId ||
            entrySize < sizeof(KSWORD_ARK_MODULE_ENTRY) ||
            (expectedCreateTime100ns != 0U && response->processCreateTime100ns != expectedCreateTime100ns))
        {
            result.io.ok = false;
            result.io.message = "enum-modules response metadata or process identity is invalid";
            return result;
        }

        const std::size_t payloadBytes = result.io.bytesReturned - headerSize;
        const std::size_t availableCount = payloadBytes / entrySize;
        if (response->returnedCount > maxRows || response->returnedCount > availableCount ||
            response->returnedCount > declaredPayloadBytes / entrySize)
        {
            result.io.ok = false;
            result.io.message = "enum-modules response entry bounds are invalid";
            return result;
        }

        result.processId = static_cast<std::uint32_t>(response->processId);
        result.status = static_cast<std::uint32_t>(response->status);
        result.flags = static_cast<std::uint32_t>(response->flags);
        result.visitedCount = static_cast<std::uint32_t>(response->visitedCount);
        result.processCreateTime100ns = static_cast<std::uint64_t>(response->processCreateTime100ns);
        result.nextCursor = static_cast<std::uint64_t>(response->nextCursor);
        result.entries.reserve(response->returnedCount);
        for (std::size_t index = 0; index < response->returnedCount; ++index)
        {
            const std::size_t offset = headerSize + index * entrySize;
            KSWORD_ARK_MODULE_ENTRY entry{};
            std::memcpy(&entry, buffer.data() + offset, sizeof(entry));
            if (entry.baseAddress == 0U || entry.spanBytes == 0U ||
                entry.baseAddress > UINT64_MAX - entry.spanBytes)
            {
                result.io.ok = false;
                result.io.message = "enum-modules response contains an invalid image range";
                result.entries.clear();
                return result;
            }
            result.entries.push_back(entry);
        }

        if ((result.flags & KSWORD_ARK_MODULE_FLAG_MORE) != 0U &&
            (result.nextCursor == 0U || result.nextCursor == cursor))
        {
            result.io.ok = false;
            result.io.message = "enum-modules response cursor did not advance";
            result.entries.clear();
            return result;
        }

        result.responseValid = true;
        result.io.message = "enum-modules page validated, entries=" + std::to_string(result.entries.size());
        return result;
    }
}
