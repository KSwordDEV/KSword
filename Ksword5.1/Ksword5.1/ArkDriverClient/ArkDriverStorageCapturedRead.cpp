#include "ArkDriverClient.h"
#include <algorithm>
#include <cstring>

namespace ksword::ark
{
    // 捕获读只返回驱动同一对象身份校验后的完整数据；兼容降级由宿主显式决定。
    RawDiskReadResult DriverClient::readCapturedRawDisk(unsigned long diskNumber, unsigned long backend,
        std::uint64_t offset, unsigned long length, const std::array<std::uint8_t, 16>& nativeGuid,
        unsigned long flags) const
    {
        static_assert(sizeof(KSWORD_ARK_RAW_DISK_READ_REQUEST) == 40);
        static_assert(sizeof(KSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST) == 56);
        RawDiskReadResult result{}; // 失败没有任何可被误标来源的字节。
        if (!length || length > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES
            || length - 1 > UINT64_MAX - offset || backend < KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
            || backend > KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER
            || std::all_of(nativeGuid.begin(), nativeGuid.end(), [](std::uint8_t byte) { return byte == 0; }))
        {
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "captured disk read has an invalid identity or range";
            return result;
        }
        KSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST request{};
        request.version = KSWORD_ARK_RAW_DISK_CAPTURED_READ_VERSION;
        request.size = sizeof(request);
        request.diskNumber = diskNumber;
        request.backend = backend;
        request.flags = flags;
        request.length = length;
        request.offset = offset;
        std::memcpy(request.expectedDeviceGuid, nativeGuid.data(), nativeGuid.size());
        std::vector<std::uint8_t> buffer(KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE + length, 0);
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_READ_RAW_DISK, &request, sizeof(request),
            buffer.data(), static_cast<unsigned long>(buffer.size()));
        result.unsupported = result.io.win32Error == ERROR_INVALID_FUNCTION
            || result.io.win32Error == ERROR_NOT_SUPPORTED || result.io.win32Error == ERROR_REVISION_MISMATCH;
        if (result.io.bytesReturned < KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE
            || result.io.bytesReturned > buffer.size())
        {
            result.io.ok = false;
            result.io.message = "captured disk read V2 was rejected or returned a truncated receipt";
            return result;
        }
        const auto* response = reinterpret_cast<const KSWORD_ARK_RAW_DISK_READ_RESPONSE*>(buffer.data());
        result.status = response->status;
        result.backendUsed = response->backendUsed;
        result.logicalSectorSize = response->logicalSectorSize;
        result.io.ntStatus = response->lastStatus;
        const bool headerValid = response->version == KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION
            && response->size == result.io.bytesReturned;
        // 老驱动可用完整V1错误回执拒绝未知请求版本；这里只标记，不发第二次读请求。
        if (!result.io.ok && headerValid && response->status == KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST
            && result.io.win32Error == ERROR_INVALID_PARAMETER)
            result.unsupported = true;
        if (headerValid && response->status == KSWORD_ARK_RAW_DISK_STATUS_NOT_SUPPORTED)
            result.unsupported = true;
        // GUID改变与不支持必须分开；前者禁止宿主的只读兼容回退。
        if (response->status == KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED) result.unsupported = false;
        if (!result.io.ok) return result;
        if (!headerValid || response->backendUsed != backend || response->status != KSWORD_ARK_RAW_DISK_STATUS_OK
            || response->bytesTransferred != length || response->lastStatus < 0
            || result.io.bytesReturned != KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE + length)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "captured disk read returned an incomplete or mismatched receipt";
            return result;
        }
        result.bytes.assign(response->data, response->data + length);
        return result;
    }
}
