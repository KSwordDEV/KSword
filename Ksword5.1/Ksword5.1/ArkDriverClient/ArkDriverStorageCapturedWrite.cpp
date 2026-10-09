#include "ArkDriverClient.h"
#include <algorithm>
#include <cstring>
#include <limits>

namespace ksword::ark
{
    // 捕获写仅使用 V2；查询、读取与旧写接口仍保持 V1，不进行隐式后端/版本回退。
    RawDiskWriteResult DriverClient::writeCapturedRawDisk(
        const unsigned long diskNumber, const unsigned long backend, const std::uint64_t offset,
        const std::vector<std::uint8_t>& original, const std::vector<std::uint8_t>& bytes,
        const std::array<std::uint8_t, 16>& nativeGuid, const unsigned long flags) const
    {
        static_assert(KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE == 40U);
        static_assert(KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_HEADER_SIZE == 56U);
        RawDiskWriteResult result{}; // 完整失败信息或驱动的已验证写入回执。
        if (original.empty() || original.size() != bytes.size()
            || bytes.size() > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES
            || bytes.size() - 1 > UINT64_MAX - offset
            || backend < KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
            || backend > KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER
            || std::all_of(nativeGuid.begin(), nativeGuid.end(), [](std::uint8_t byte) { return byte == 0; }))
        {
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "captured disk write has an invalid identity or range";
            return result;
        }
        const auto requestBytes = static_cast<std::size_t>(KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_HEADER_SIZE)
            + 2 * bytes.size(); // 两段长度已限制到 256 KiB，不会溢出 DWORD。
        std::vector<std::uint8_t> buffer(requestBytes, 0);
        auto* request = reinterpret_cast<KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST*>(buffer.data());
        request->version = KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_VERSION;
        request->size = static_cast<unsigned long>(requestBytes);
        request->diskNumber = diskNumber;
        request->backend = backend;
        request->flags = flags;
        request->length = static_cast<unsigned long>(bytes.size());
        request->confirmationToken = KSWORD_ARK_RAW_DISK_CONFIRMATION_TOKEN;
        request->offset = offset;
        std::memcpy(request->expectedDeviceGuid, nativeGuid.data(), nativeGuid.size());
        std::memcpy(request->data, original.data(), original.size());
        std::memcpy(request->data + original.size(), bytes.data(), bytes.size());
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_WRITE_RAW_DISK, buffer.data(),
            static_cast<unsigned long>(buffer.size()), &result.response, sizeof(result.response));
        result.io.ntStatus = result.response.lastStatus;
        result.unsupported = result.io.win32Error == ERROR_INVALID_FUNCTION || result.io.win32Error == ERROR_NOT_SUPPORTED;
        if (result.response.status == KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED
            || result.response.status == KSWORD_ARK_RAW_DISK_STATUS_ORIGINAL_CHANGED)
            result.unsupported = false;
        if (!result.io.ok)
        {
            result.io.message = "captured disk write V2 was rejected; legacy write fallback is disabled";
            return result;
        }
        // 成功必须是整份固定回执、匹配后端及完整写入长度；旧驱动或截短回执均不能算成功。
        if (result.io.bytesReturned != sizeof(result.response)
            || result.response.version != KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION
            || result.response.size != sizeof(result.response) || result.response.backendUsed != backend
            || result.response.status != KSWORD_ARK_RAW_DISK_STATUS_OK
            || result.response.bytesTransferred != bytes.size() || result.response.lastStatus < 0)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "captured disk write returned an incomplete or mismatched receipt";
        }
        return result;
    }
}
