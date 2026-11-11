#include "ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <vector>

namespace ksword::ark
{
    namespace
    {
        // kMappedFileNameChars 用途：限制共享响应中 UTF-16 路径的扫描长度。
        constexpr std::size_t kMappedFileNameChars =
            KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_CHARS;

        constexpr std::size_t kReadResponseHeaderSize =
            offsetof(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE, data);

        constexpr std::size_t kWriteRequestHeaderSize =
            offsetof(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST, data);

        // 物理读响应：驱动用 sizeof-sizeof(data)=55 计算“输出缓冲还剩多少可用”，
        // 却把负载写到 ->data（offsetof=48）。两个数字都要用，且不能互相替代。
        constexpr std::size_t kPhysicalReadResponseAllocSize =
            sizeof(KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE)
            - sizeof(((KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*)nullptr)->data);   // 55
        constexpr std::size_t kPhysicalReadDataOffset =
            offsetof(KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE, data);               // 48
        constexpr std::size_t kPhysicalWriteRequestAllocSize =
            sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST)
            - sizeof(((KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*)nullptr)->data);   // 31

        // kPhysicalAddressMax 用途：与 R0 memory_physical.c 的 52 位上限保持一致。
        constexpr std::uint64_t kPhysicalAddressMax = 0x000FFFFFFFFFFFFFULL;

        // isPhysicalRangeAcceptable 用途：复刻 R0 区间判据，长度为 0 时只校验起点，
        // 其余情况同时检查上限和回绕，避免把注定被拒绝的请求发给驱动。
        bool isPhysicalRangeAcceptable(
            const std::uint64_t physicalAddress,
            const std::uint64_t length)
        {
            if (physicalAddress > kPhysicalAddressMax)
            {
                return false;
            }
            if (length == 0ULL)
            {
                return true;
            }
            return length <= (kPhysicalAddressMax - physicalAddress + 1ULL);
        }
    }

    VirtualMemoryQueryResult DriverClient::queryVirtualMemory(
        const std::uint32_t processId,
        const std::uint64_t baseAddress,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        // request/response 用途：承载一次固定大小的 R3/R0 虚拟内存区域查询。
        VirtualMemoryQueryResult queryResult{};
        KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST request{};
        KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE response{};
        request.flags = flags;
        request.processId = processId;
        request.baseAddress = baseAddress;

        // 所有设备访问都继续走 DriverClient，外部调用方不接触 DeviceIoControl。
        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)),
            existingHandle);
        if (!queryResult.io.ok)
        {
            queryResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY) failed, error=" +
                std::to_string(queryResult.io.win32Error);
            return queryResult;
        }

        // 固定响应长度不完整时拒绝解析，避免不同协议版本之间错误解释字段。
        if (queryResult.io.bytesReturned < sizeof(response))
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "query-vm response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }

        // 下列字段逐项转换为稳定的 R3 类型，插件和主界面可共享同一结果模型。
        queryResult.version = static_cast<std::uint32_t>(response.version);
        queryResult.processId = static_cast<std::uint32_t>(response.processId);
        queryResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        queryResult.queryStatus = static_cast<std::uint32_t>(response.queryStatus);
        queryResult.openStatus = static_cast<long>(response.openStatus);
        queryResult.basicStatus = static_cast<long>(response.basicStatus);
        queryResult.mappedFileNameStatus = static_cast<long>(response.mappedFileNameStatus);
        queryResult.source = static_cast<std::uint32_t>(response.source);
        queryResult.requestedBaseAddress =
            static_cast<std::uint64_t>(response.requestedBaseAddress);
        queryResult.baseAddress = static_cast<std::uint64_t>(response.baseAddress);
        queryResult.allocationBase = static_cast<std::uint64_t>(response.allocationBase);
        queryResult.regionSize = static_cast<std::uint64_t>(response.regionSize);
        queryResult.allocationProtect =
            static_cast<std::uint32_t>(response.allocationProtect);
        queryResult.state = static_cast<std::uint32_t>(response.state);
        queryResult.protect = static_cast<std::uint32_t>(response.protect);
        queryResult.type = static_cast<std::uint32_t>(response.type);

        // mappedFileNameLength 用途：在固定数组内寻找 NUL，不依赖驱动一定写终止符。
        std::size_t mappedFileNameLength = 0U;
        while (mappedFileNameLength < kMappedFileNameChars &&
               response.mappedFileName[mappedFileNameLength] != L'\0')
        {
            ++mappedFileNameLength;
        }
        queryResult.mappedFileName.assign(
            response.mappedFileName,
            response.mappedFileName + mappedFileNameLength);

        // message 用途：保留关键状态，供非 Qt 调用方直接写入诊断日志。
        std::ostringstream stream;
        stream << "pid=" << queryResult.processId
            << ", requested=0x" << std::hex << std::uppercase
            << queryResult.requestedBaseAddress
            << ", base=0x" << queryResult.baseAddress
            << std::dec << ", size=" << queryResult.regionSize
            << ", status=" << queryResult.queryStatus
            << ", source=" << queryResult.source;
        queryResult.io.message = stream.str();
        return queryResult;
    }

    VirtualMemoryReadResult DriverClient::readVirtualMemory(
        const std::uint32_t processId,
        const std::uint64_t baseAddress,
        const std::uint32_t bytesToRead,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        // request 用途：承载 R3 对 R0 的读取参数，数据缓冲单独从响应中解析。
        VirtualMemoryReadResult readResult{};
        KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST request{};

        // bytesToRead 在 R3 先做上限保护，避免构造过大的响应缓冲。
        if (bytesToRead > KSWORD_ARK_MEMORY_READ_MAX_BYTES)
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "readVirtualMemory size exceeds driver limit";
            return readResult;
        }

        // request 字段逐项填充，保持共享协议字段含义清晰。
        request.flags = flags;
        request.processId = processId;
        request.baseAddress = baseAddress;
        request.bytesToRead = bytesToRead;

        // responseBuffer 包含固定头和 data[]，长度为请求大小加头部。
        std::vector<std::uint8_t> responseBuffer(
            kReadResponseHeaderSize + static_cast<std::size_t>(bytesToRead),
            0U);
        readResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()),
            existingHandle);
        if (!readResult.io.ok)
        {
            readResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY) failed, error=" +
                std::to_string(readResult.io.win32Error);
            return readResult;
        }

        // 固定头不足说明驱动或协议不匹配，直接标记失败。
        if (readResult.io.bytesReturned < kReadResponseHeaderSize)
        {
            readResult.io.ok = false;
            readResult.io.message =
                "read-vm response too small, bytesReturned=" +
                std::to_string(readResult.io.bytesReturned);
            return readResult;
        }

        // responseHeader 指向 METHOD_BUFFERED 响应头，只读解析。
        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*>(responseBuffer.data());
        readResult.version = static_cast<std::uint32_t>(responseHeader->version);
        readResult.headerSize = static_cast<std::uint32_t>(responseHeader->headerSize);
        readResult.processId = static_cast<std::uint32_t>(responseHeader->processId);
        readResult.fieldFlags = static_cast<std::uint32_t>(responseHeader->fieldFlags);
        readResult.readStatus = static_cast<std::uint32_t>(responseHeader->readStatus);
        readResult.lookupStatus = static_cast<long>(responseHeader->lookupStatus);
        readResult.copyStatus = static_cast<long>(responseHeader->copyStatus);
        readResult.source = static_cast<std::uint32_t>(responseHeader->source);
        readResult.requestedBaseAddress = static_cast<std::uint64_t>(responseHeader->requestedBaseAddress);
        readResult.requestedBytes = static_cast<std::uint32_t>(responseHeader->requestedBytes);
        readResult.bytesRead = static_cast<std::uint32_t>(responseHeader->bytesRead);
        readResult.maxBytesPerRequest = static_cast<std::uint32_t>(responseHeader->maxBytesPerRequest);

        // dataBytes 受 bytesReturned、bytesRead 和缓冲长度三者共同约束。
        const std::size_t bytesAvailable =
            static_cast<std::size_t>(readResult.io.bytesReturned) - kReadResponseHeaderSize;
        const std::size_t dataBytes = std::min<std::size_t>(
            bytesAvailable,
            static_cast<std::size_t>(readResult.bytesRead));
        if (dataBytes > 0U)
        {
            readResult.data.assign(
                responseBuffer.begin() + static_cast<std::ptrdiff_t>(kReadResponseHeaderSize),
                responseBuffer.begin() + static_cast<std::ptrdiff_t>(kReadResponseHeaderSize + dataBytes));
        }

        // message 汇总关键诊断字段，供 UI 状态栏直接展示。
        std::ostringstream stream;
        stream << "pid=" << readResult.processId
            << ", address=0x" << std::hex << std::uppercase << readResult.requestedBaseAddress
            << std::dec << ", requested=" << readResult.requestedBytes
            << ", read=" << readResult.bytesRead
            << ", status=" << readResult.readStatus
            << ", source=" << readResult.source
            << ", flags=0x" << std::hex << std::uppercase << flags
            << ", nt=0x" << static_cast<unsigned long>(readResult.copyStatus);
        readResult.io.message = stream.str();
        return readResult;
    }

    VirtualMemoryReadResult DriverClient::readVirtualMemoryVerified(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime100ns,
        const std::uint64_t baseAddress,
        const std::uint32_t bytesToRead,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        VirtualMemoryReadResult result{};
        if (processId <= 4U || expectedCreationTime100ns == 0ULL || bytesToRead == 0U ||
            bytesToRead > KSWORD_ARK_MEMORY_READ_MAX_BYTES ||
            (flags & ~KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE) != 0UL)
        {
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "verified read-vm requires a valid process identity, nonzero bounded length and user-address flags";
            return result;
        }
        KSWORD_ARK_READ_VIRTUAL_MEMORY_VERIFIED_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_VERIFIED_MEMORY_READ_VERSION;
        request.flags = flags;
        request.processId = processId;
        request.expectedCreationTime100ns = expectedCreationTime100ns;
        request.baseAddress = baseAddress;
        request.bytesToRead = bytesToRead;
        std::vector<std::uint8_t> buffer(kReadResponseHeaderSize + static_cast<std::size_t>(bytesToRead), 0U);
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY_VERIFIED, &request,
            static_cast<unsigned long>(sizeof(request)), buffer.data(), static_cast<unsigned long>(buffer.size()), existingHandle);
        if (!result.io.ok) return result; // 旧驱动返回不支持，绝不调用旧 PID-only IOCTL。
        if (result.io.bytesReturned < kReadResponseHeaderSize || result.io.bytesReturned > buffer.size())
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "verified read-vm response length is invalid";
            return result;
        }
        const auto* response = reinterpret_cast<const KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*>(buffer.data());
        if (response->version != KSWORD_ARK_MEMORY_PROTOCOL_VERSION || response->headerSize != kReadResponseHeaderSize ||
            response->processId != processId || response->requestedBaseAddress != baseAddress ||
            response->requestedBytes != bytesToRead || response->bytesRead > bytesToRead ||
            response->bytesRead > result.io.bytesReturned - kReadResponseHeaderSize ||
            (response->readStatus == KSWORD_ARK_MEMORY_READ_STATUS_OK && response->bytesRead != bytesToRead) ||
            (response->lookupStatus < 0 && response->bytesRead != 0U))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "verified read-vm response identity or payload is invalid";
            return result;
        }
        result.version = response->version;
        result.headerSize = response->headerSize;
        result.processId = response->processId;
        result.fieldFlags = response->fieldFlags;
        result.readStatus = response->readStatus;
        result.lookupStatus = response->lookupStatus;
        result.copyStatus = response->copyStatus;
        result.source = response->source;
        result.requestedBaseAddress = response->requestedBaseAddress;
        result.requestedBytes = response->requestedBytes;
        result.bytesRead = response->bytesRead;
        result.maxBytesPerRequest = response->maxBytesPerRequest;
        result.data.assign(buffer.begin() + static_cast<std::ptrdiff_t>(kReadResponseHeaderSize),
            buffer.begin() + static_cast<std::ptrdiff_t>(kReadResponseHeaderSize + result.bytesRead));
        result.io.message = "verified read-vm response parsed; inspect lookupStatus, copyStatus and readStatus";
        return result;
    }

    VirtualMemoryWriteResult DriverClient::writeVirtualMemory(
        const std::uint32_t processId,
        const std::uint64_t baseAddress,
        const std::vector<std::uint8_t>& bytes,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        // writeResult 用途：承载 R0 固定响应和 DeviceIoControl 状态。
        VirtualMemoryWriteResult writeResult{};

        // 空差异不应传给驱动，调用方应直接跳过。
        if (bytes.empty() || bytes.size() > KSWORD_ARK_MEMORY_WRITE_MAX_BYTES)
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "writeVirtualMemory invalid diff size";
            return writeResult;
        }

        // inputBuffer 按共享协议头 + data[] 构造，避免 UI 直接拼 IOCTL。
        std::vector<std::uint8_t> inputBuffer(kWriteRequestHeaderSize + bytes.size(), 0U);
        auto* request =
            reinterpret_cast<KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST*>(inputBuffer.data());
        request->flags = flags;
        request->processId = processId;
        request->baseAddress = baseAddress;
        request->bytesToWrite = static_cast<unsigned long>(bytes.size());
        std::copy(bytes.begin(), bytes.end(), request->data);

        // response 是固定大小结构，所有写入细节由 R0 统一填写。
        KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE response{};
        writeResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY,
            inputBuffer.data(),
            static_cast<unsigned long>(inputBuffer.size()),
            &response,
            static_cast<unsigned long>(sizeof(response)),
            existingHandle);
        if (!writeResult.io.ok)
        {
            writeResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY) failed, error=" +
                std::to_string(writeResult.io.win32Error);
            return writeResult;
        }
        if (writeResult.io.bytesReturned < sizeof(response))
        {
            writeResult.io.ok = false;
            writeResult.io.message =
                "write-vm response too small, bytesReturned=" +
                std::to_string(writeResult.io.bytesReturned);
            return writeResult;
        }

        // 解析响应字段，供 UI 判断成功、部分成功或失败。
        writeResult.version = static_cast<std::uint32_t>(response.version);
        writeResult.processId = static_cast<std::uint32_t>(response.processId);
        writeResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        writeResult.writeStatus = static_cast<std::uint32_t>(response.writeStatus);
        writeResult.lookupStatus = static_cast<long>(response.lookupStatus);
        writeResult.copyStatus = static_cast<long>(response.copyStatus);
        writeResult.source = static_cast<std::uint32_t>(response.source);
        writeResult.requestedBaseAddress = static_cast<std::uint64_t>(response.requestedBaseAddress);
        writeResult.requestedBytes = static_cast<std::uint32_t>(response.requestedBytes);
        writeResult.bytesWritten = static_cast<std::uint32_t>(response.bytesWritten);
        writeResult.maxBytesPerRequest = static_cast<std::uint32_t>(response.maxBytesPerRequest);

        // message 汇总本次差异块写入结果。
        std::ostringstream stream;
        stream << "pid=" << writeResult.processId
            << ", address=0x" << std::hex << std::uppercase << writeResult.requestedBaseAddress
            << std::dec << ", requested=" << writeResult.requestedBytes
            << ", written=" << writeResult.bytesWritten
            << ", status=" << writeResult.writeStatus
            << ", source=" << writeResult.source
            << ", flags=0x" << std::hex << std::uppercase << flags
            << ", fields=0x" << std::hex << std::uppercase << writeResult.fieldFlags
            << ", nt=0x" << std::hex << static_cast<unsigned long>(writeResult.copyStatus);
        if (writeResult.writeStatus == KSWORD_ARK_MEMORY_WRITE_STATUS_FORCE_REQUIRED)
        {
            stream << ", force-required";
        }
        writeResult.io.message = stream.str();
        return writeResult;
    }

    PhysicalMemoryReadResult DriverClient::readPhysicalMemory(
        const std::uint64_t physicalAddress,
        const std::uint32_t bytesToRead,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        // request 用途：承载物理读参数；物理协议没有 processId，只有地址和长度。
        PhysicalMemoryReadResult readResult{};
        KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST request{};

        // 驱动对物理读只接受 flags 为 0，任何保留位都会被直接判为无效参数。
        if (flags != 0UL)
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "物理内存读取不接受任何 flags，flags 必须为 0";
            return readResult;
        }

        // 长度上限先在 R3 拦截，避免构造超过驱动限制的响应缓冲。
        if (bytesToRead > KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES)
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "物理内存读取长度超出驱动单次上限 64KB";
            return readResult;
        }

        // 地址上限与回绕在 R3 复核一次，判据与 R0 完全一致。
        if (!isPhysicalRangeAcceptable(physicalAddress, static_cast<std::uint64_t>(bytesToRead)))
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "物理地址超出 52 位上限或区间回绕";
            return readResult;
        }

        // request 字段逐项填充；reserved/reserved2 保持零值，驱动会逐个校验。
        request.flags = 0UL;
        request.physicalAddress = physicalAddress;
        request.bytesToRead = bytesToRead;

        // 输出缓冲必须按驱动的可用空间判据 kPhysicalReadResponseAllocSize 打底，
        // 只给 kPhysicalReadDataOffset + N 会被驱动判成 BUFFER_TOO_SMALL。
        std::vector<std::uint8_t> responseBuffer(
            kPhysicalReadResponseAllocSize + static_cast<std::size_t>(bytesToRead),
            0U);
        readResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()),
            existingHandle);
        if (!readResult.io.ok)
        {
            readResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY) failed, error=" +
                std::to_string(readResult.io.win32Error);
            return readResult;
        }

        // 驱动即使在 IRQL/范围拒绝路径上也会回满响应头，长度不足说明协议不匹配。
        if (readResult.io.bytesReturned < kPhysicalReadResponseAllocSize)
        {
            readResult.io.ok = false;
            readResult.io.message =
                "read-physical response too small, bytesReturned=" +
                std::to_string(readResult.io.bytesReturned);
            return readResult;
        }

        // responseHeader 指向 METHOD_BUFFERED 响应头，只读解析。
        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*>(responseBuffer.data());
        readResult.version = static_cast<std::uint32_t>(responseHeader->version);
        readResult.headerSize = static_cast<std::uint32_t>(responseHeader->headerSize);
        readResult.fieldFlags = static_cast<std::uint32_t>(responseHeader->fieldFlags);
        readResult.readStatus = static_cast<std::uint32_t>(responseHeader->readStatus);
        readResult.copyStatus = static_cast<long>(responseHeader->copyStatus);
        readResult.source = static_cast<std::uint32_t>(responseHeader->source);
        readResult.requestedPhysicalAddress =
            static_cast<std::uint64_t>(responseHeader->requestedPhysicalAddress);
        readResult.requestedBytes = static_cast<std::uint32_t>(responseHeader->requestedBytes);
        readResult.bytesRead = static_cast<std::uint32_t>(responseHeader->bytesRead);
        readResult.maxBytesPerRequest = static_cast<std::uint32_t>(responseHeader->maxBytesPerRequest);

        // 负载起点只能是 data 成员的真实偏移；用 headerSize 或 55 会整体错位 7 字节。
        // 长度只用 bytesRead 与缓冲余量取小，不能由 bytesReturned 反推。
        const std::size_t dataCapacity = responseBuffer.size() - kPhysicalReadDataOffset;
        const std::size_t dataBytes = std::min<std::size_t>(
            static_cast<std::size_t>(readResult.bytesRead),
            dataCapacity);
        if (dataBytes > 0U)
        {
            readResult.data.assign(
                responseBuffer.begin() + static_cast<std::ptrdiff_t>(kPhysicalReadDataOffset),
                responseBuffer.begin() + static_cast<std::ptrdiff_t>(kPhysicalReadDataOffset + dataBytes));
        }

        // message 汇总关键诊断字段，供 UI 状态栏直接展示。
        std::ostringstream stream;
        stream << "pa=0x" << std::hex << std::uppercase << readResult.requestedPhysicalAddress
            << std::dec << ", requested=" << readResult.requestedBytes
            << ", read=" << readResult.bytesRead
            << ", parsed=" << readResult.data.size()
            << ", status=" << readResult.readStatus
            << ", source=" << readResult.source
            << ", fields=0x" << std::hex << std::uppercase << readResult.fieldFlags
            << ", nt=0x" << static_cast<unsigned long>(readResult.copyStatus);
        readResult.io.message = stream.str();
        return readResult;
    }

    PhysicalMemoryWriteResult DriverClient::writePhysicalMemory(
        const std::uint64_t physicalAddress,
        const std::vector<std::uint8_t>& bytes,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        // writeResult 用途：承载 R0 固定响应和 DeviceIoControl 状态。
        PhysicalMemoryWriteResult writeResult{};

        // 空负载和超限负载都会被驱动拒绝，这里提前挡掉。
        if (bytes.empty() || bytes.size() > KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES)
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "物理内存写入长度必须非零且不超过 4KB";
            return writeResult;
        }

        // flags 只允许 UI_CONFIRMED 与 FORCE 的组合，其余位驱动一律判无效参数。
        constexpr unsigned long allowedWriteFlags =
            KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED | KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE;
        if ((flags & ~allowedWriteFlags) != 0UL)
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "物理内存写入 flags 只接受 UI_CONFIRMED 与 FORCE 的组合";
            return writeResult;
        }

        // 地址上限与回绕在 R3 复核一次，判据与 R0 完全一致。
        if (!isPhysicalRangeAcceptable(physicalAddress, static_cast<std::uint64_t>(bytes.size())))
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "物理地址超出 52 位上限或区间回绕";
            return writeResult;
        }

        // inputBuffer 按物理写请求头 + data[] 构造，负载走 request->data 成员拷贝，
        // 不手算偏移，避免与结构体真实布局脱节。
        std::vector<std::uint8_t> inputBuffer(kPhysicalWriteRequestAllocSize + bytes.size(), 0U);
        auto* request =
            reinterpret_cast<KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*>(inputBuffer.data());
        request->flags = flags;
        request->physicalAddress = physicalAddress;
        request->bytesToWrite = static_cast<unsigned long>(bytes.size());
        std::copy(bytes.begin(), bytes.end(), request->data);

        // response 是固定大小结构，映射和拷贝两个阶段的状态由 R0 分别填写。
        KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE response{};
        writeResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY,
            inputBuffer.data(),
            static_cast<unsigned long>(inputBuffer.size()),
            &response,
            static_cast<unsigned long>(sizeof(response)),
            existingHandle);
        if (!writeResult.io.ok)
        {
            writeResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY) failed, error=" +
                std::to_string(writeResult.io.win32Error);
            return writeResult;
        }
        if (writeResult.io.bytesReturned < sizeof(response))
        {
            writeResult.io.ok = false;
            writeResult.io.message =
                "write-physical response too small, bytesReturned=" +
                std::to_string(writeResult.io.bytesReturned);
            return writeResult;
        }

        // 解析响应字段，供 UI 判断成功、需要 FORCE 还是失败。
        writeResult.version = static_cast<std::uint32_t>(response.version);
        writeResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        writeResult.writeStatus = static_cast<std::uint32_t>(response.writeStatus);
        writeResult.mapStatus = static_cast<long>(response.mapStatus);
        writeResult.copyStatus = static_cast<long>(response.copyStatus);
        writeResult.source = static_cast<std::uint32_t>(response.source);
        writeResult.requestedPhysicalAddress =
            static_cast<std::uint64_t>(response.requestedPhysicalAddress);
        writeResult.requestedBytes = static_cast<std::uint32_t>(response.requestedBytes);
        writeResult.bytesWritten = static_cast<std::uint32_t>(response.bytesWritten);
        writeResult.maxBytesPerRequest = static_cast<std::uint32_t>(response.maxBytesPerRequest);

        // message 汇总本次物理写入结果，map/copy 两个 NTSTATUS 都保留。
        std::ostringstream stream;
        stream << "pa=0x" << std::hex << std::uppercase << writeResult.requestedPhysicalAddress
            << std::dec << ", requested=" << writeResult.requestedBytes
            << ", written=" << writeResult.bytesWritten
            << ", status=" << writeResult.writeStatus
            << ", source=" << writeResult.source
            << ", flags=0x" << std::hex << std::uppercase << flags
            << ", fields=0x" << std::hex << std::uppercase << writeResult.fieldFlags
            << ", map=0x" << std::hex << static_cast<unsigned long>(writeResult.mapStatus)
            << ", nt=0x" << std::hex << static_cast<unsigned long>(writeResult.copyStatus);
        // 未带 FORCE 时 io.ok 仍为 true，但驱动一个字节都没写，必须靠 writeStatus 分辨。
        if (writeResult.writeStatus == KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_FORCE_REQUIRED)
        {
            stream << ", force-required";
        }
        writeResult.io.message = stream.str();
        return writeResult;
    }

    KernelMemoryEvidenceResult DriverClient::queryKernelMemoryEvidence(
        const unsigned long flags,
        const unsigned long maxRows,
        const std::uint64_t startAddress,
        const std::uint64_t endAddress,
        const std::uint64_t maxBytes,
        const unsigned long maxBigPoolRows,
        const unsigned long sampleBytes) const
    {
        // 输入：只读内核内存证据采集参数，包含来源 flags、地址范围和预算。
        // 处理：构造固定请求，调用 R0 证据 IOCTL，并按 rowSize 解析变长 rows[]。
        // 返回：KernelMemoryEvidenceResult；旧驱动或未注册 IOCTL 时 unsupported=true。
        KernelMemoryEvidenceResult evidenceResult{};
        KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST request{};
        request.flags = flags;
        request.maxRows = maxRows;
        request.startAddress = startAddress;
        request.endAddress = endAddress;
        request.maxBytes = maxBytes;
        request.maxBigPoolRows = maxBigPoolRows;
        request.sampleBytes = sampleBytes;

        constexpr std::size_t headerSize =
            sizeof(KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE) -
            sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW);
        std::vector<std::uint8_t> responseBuffer(4U * 1024U * 1024U, 0U);
        evidenceResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!evidenceResult.io.ok)
        {
            evidenceResult.unsupported =
                evidenceResult.io.win32Error == ERROR_INVALID_FUNCTION ||
                evidenceResult.io.win32Error == ERROR_NOT_SUPPORTED ||
                evidenceResult.io.win32Error == ERROR_INVALID_PARAMETER;
            evidenceResult.io.message = evidenceResult.unsupported
                ? "IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE) failed, error=" +
                    std::to_string(evidenceResult.io.win32Error);
            return evidenceResult;
        }
        if (evidenceResult.io.bytesReturned < headerSize)
        {
            evidenceResult.io.ok = false;
            evidenceResult.io.message =
                "kernel memory evidence response too small, bytesReturned=" +
                std::to_string(evidenceResult.io.bytesReturned);
            return evidenceResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE*>(responseBuffer.data());
        if (responseHeader->rowSize < sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW))
        {
            evidenceResult.io.ok = false;
            evidenceResult.io.message =
                "kernel memory evidence rowSize invalid, rowSize=" +
                std::to_string(responseHeader->rowSize);
            return evidenceResult;
        }

        evidenceResult.version = static_cast<std::uint32_t>(responseHeader->version);
        evidenceResult.status = static_cast<std::uint32_t>(responseHeader->status);
        evidenceResult.responseFlags = static_cast<std::uint32_t>(responseHeader->responseFlags);
        evidenceResult.sourceFlags = static_cast<std::uint32_t>(responseHeader->sourceFlags);
        evidenceResult.totalRows = static_cast<std::uint32_t>(responseHeader->totalRows);
        evidenceResult.returnedRows = static_cast<std::uint32_t>(responseHeader->returnedRows);
        evidenceResult.maxRows = static_cast<std::uint32_t>(responseHeader->maxRows);
        evidenceResult.maxBytes = static_cast<std::uint64_t>(responseHeader->maxBytes);
        evidenceResult.bytesScanned = static_cast<std::uint64_t>(responseHeader->bytesScanned);
        evidenceResult.moduleCount = static_cast<std::uint32_t>(responseHeader->moduleCount);
        evidenceResult.bigPoolRowsSeen = static_cast<std::uint32_t>(responseHeader->bigPoolRowsSeen);
        evidenceResult.lastStatus = static_cast<long>(responseHeader->lastStatus);
        evidenceResult.io.ntStatus = evidenceResult.lastStatus;
        if (static_cast<unsigned long>(evidenceResult.lastStatus) == 0xC00000BBUL ||
            static_cast<unsigned long>(evidenceResult.lastStatus) == 0xC0000010UL)
        {
            evidenceResult.unsupported = true;
            evidenceResult.io.ok = false;
            evidenceResult.io.message =
                "IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE unsupported by current driver response";
            return evidenceResult;
        }

        const std::size_t availableCount =
            (static_cast<std::size_t>(evidenceResult.io.bytesReturned) - headerSize) /
            static_cast<std::size_t>(responseHeader->rowSize);
        const std::size_t parsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedRows),
            availableCount);
        evidenceResult.entries.reserve(parsedCount);
        for (std::size_t index = 0U; index < parsedCount; ++index)
        {
            const std::size_t entryOffset =
                headerSize + (index * static_cast<std::size_t>(responseHeader->rowSize));
            if (entryOffset + sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW) > responseBuffer.size())
            {
                break;
            }

            const auto* sourceRow =
                reinterpret_cast<const KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW*>(
                    responseBuffer.data() + entryOffset);
            KernelMemoryEvidenceEntry row{};
            row.evidenceKind = static_cast<std::uint32_t>(sourceRow->evidenceKind);
            row.pageSize = static_cast<std::uint32_t>(sourceRow->pageSize);
            row.permissionFlags = static_cast<std::uint32_t>(sourceRow->permissionFlags);
            row.ownerKind = static_cast<std::uint32_t>(sourceRow->ownerKind);
            row.riskFlags = static_cast<std::uint32_t>(sourceRow->riskFlags);
            row.moduleSize = static_cast<std::uint32_t>(sourceRow->moduleSize);
            row.confidence = static_cast<std::uint32_t>(sourceRow->confidence);
            row.bigPoolTag = static_cast<std::uint32_t>(sourceRow->bigPoolTag);
            row.bigPoolFlags = static_cast<std::uint32_t>(sourceRow->bigPoolFlags);
            row.sectionRva = static_cast<std::uint32_t>(sourceRow->sectionRva);
            row.sectionSize = static_cast<std::uint32_t>(sourceRow->sectionSize);
            row.hashAlgorithm = static_cast<std::uint32_t>(sourceRow->hashAlgorithm);
            row.sampleSize = static_cast<std::uint32_t>(sourceRow->sampleSize);
            row.lastStatus = static_cast<long>(sourceRow->lastStatus);
            row.virtualAddress = static_cast<std::uint64_t>(sourceRow->virtualAddress);
            row.regionSize = static_cast<std::uint64_t>(sourceRow->regionSize);
            row.moduleBase = static_cast<std::uint64_t>(sourceRow->moduleBase);
            row.ownerAddress = static_cast<std::uint64_t>(sourceRow->ownerAddress);
            row.contentHash = static_cast<std::uint64_t>(sourceRow->contentHash);

            const std::size_t sectionNameLength = std::find(
                sourceRow->sectionName,
                sourceRow->sectionName + KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES,
                '\0') - sourceRow->sectionName;
            row.sectionName.assign(
                reinterpret_cast<const char*>(sourceRow->sectionName),
                reinterpret_cast<const char*>(sourceRow->sectionName + sectionNameLength));

            const std::size_t boundedSampleBytes = std::min<std::size_t>(
                static_cast<std::size_t>(sourceRow->sampleSize),
                KSWORD_ARK_MEMORY_EVIDENCE_SECTION_SAMPLE_BYTES);
            row.sample.assign(sourceRow->sample, sourceRow->sample + boundedSampleBytes);

            std::size_t ownerChars = 0U;
            while (ownerChars < KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NAME_CHARS &&
                sourceRow->ownerName[ownerChars] != L'\0')
            {
                ++ownerChars;
            }
            row.ownerName.assign(sourceRow->ownerName, sourceRow->ownerName + ownerChars);

            std::size_t detailChars = 0U;
            while (detailChars < KSWORD_ARK_MEMORY_EVIDENCE_DETAIL_CHARS &&
                sourceRow->detail[detailChars] != L'\0')
            {
                ++detailChars;
            }
            row.detail.assign(sourceRow->detail, sourceRow->detail + detailChars);
            evidenceResult.entries.push_back(std::move(row));
        }

        std::ostringstream stream;
        stream << "version=" << evidenceResult.version
            << ", status=" << evidenceResult.status
            << ", total=" << evidenceResult.totalRows
            << ", returned=" << evidenceResult.returnedRows
            << ", parsed=" << evidenceResult.entries.size()
            << ", bytesScanned=" << evidenceResult.bytesScanned
            << ", flags=0x" << std::hex << std::uppercase << evidenceResult.responseFlags
            << ", lastStatus=0x" << static_cast<unsigned long>(evidenceResult.lastStatus);
        evidenceResult.io.message = stream.str();
        return evidenceResult;
    }
}
