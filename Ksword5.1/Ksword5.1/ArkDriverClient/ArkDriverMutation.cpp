#include "ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <sstream>

namespace ksword::ark
{
    namespace
    {
        constexpr std::size_t kMutationResponseHeaderSize =
            sizeof(KSWORD_ARK_MUTATION_RESPONSE);
        const std::size_t kMutationAuditResponseHeaderSize =
            KSWORD_ARK_MUTATION_AUDIT_RESPONSE_HEADER_SIZE;

        bool isUnsupportedIoctlError(const unsigned long win32Error)
        {
            // 输入：DeviceIoControl 失败后的 Win32 错误。
            // 处理：判断是否属于未注册/旧驱动兼容错误。
            // 返回：true 表示 UI 应显示“未集成/等待 R0 支持”。
            return win32Error == ERROR_INVALID_FUNCTION ||
                win32Error == ERROR_NOT_SUPPORTED ||
                win32Error == ERROR_INVALID_PARAMETER;
        }

        void copyBytesToVector(
            const unsigned char* bytes,
            const std::size_t maxBytes,
            std::vector<std::uint8_t>& bytesOut)
        {
            // 输入：共享协议中的定长字节数组和长度。
            // 处理：复制到 R3 vector，保留原始顺序以便 UI/audit 展示。
            // 返回：无返回值，输出写入 bytesOut。
            if (bytes == nullptr || maxBytes == 0U)
            {
                bytesOut.clear();
                return;
            }

            bytesOut.assign(bytes, bytes + maxBytes);
        }

        void copyVectorToFixedBytes(
            unsigned char* destination,
            const std::size_t destinationBytes,
            const std::vector<std::uint8_t>& sourceBytes)
        {
            // 输入：目标定长字节数组和 R3 vector。
            // 处理：截断复制并清零剩余空间，保持共享协议字段确定性。
            // 返回：无返回值。
            if (destination == nullptr || destinationBytes == 0U)
            {
                return;
            }

            std::fill(destination, destination + destinationBytes, std::uint8_t{0});
            const std::size_t copyBytes = std::min<std::size_t>(destinationBytes, sourceBytes.size());
            if (copyBytes != 0U)
            {
                std::copy(sourceBytes.begin(), sourceBytes.begin() + static_cast<std::ptrdiff_t>(copyBytes), destination);
            }
        }
    }

    MutationResponseResult DriverClient::prepareMutation(const MutationPrepareInput& input) const
    {
        // 输入：dry-run / audit / rollback 前置准备信息。
        // 处理：封装 PREPARE IOCTL，只做协议打包与响应解析，不暴露任意写 UI。
        // 返回：MutationResponseResult；unsupported=true 时 UI 可提示驱动过旧。
        MutationResponseResult responseResult{};
        KSWORD_ARK_MUTATION_PREPARE_REQUEST request{};
        KSWORD_ARK_MUTATION_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
        request.flags = input.flags;
        request.targetKind = input.targetKind;
        request.processId = input.processId;
        request.bytes = input.bytes;
        request.targetAddress = input.targetAddress;
        request.targetContext = input.targetContext;
        copyVectorToFixedBytes(request.afterBytes, KSWORD_ARK_MUTATION_MAX_BYTES, input.afterBytes);
        copyVectorToFixedBytes(request.expectedBeforeBytes, KSWORD_ARK_MUTATION_MAX_BYTES, input.expectedBeforeBytes);

        responseResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_MUTATION_PREPARE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!responseResult.io.ok)
        {
            responseResult.unsupported = isUnsupportedIoctlError(responseResult.io.win32Error);
            responseResult.io.message = responseResult.unsupported
                ? "IOCTL_KSWORD_ARK_MUTATION_PREPARE unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_MUTATION_PREPARE) failed, error=" +
                    std::to_string(responseResult.io.win32Error);
            return responseResult;
        }
        if (responseResult.io.bytesReturned < kMutationResponseHeaderSize)
        {
            responseResult.io.ok = false;
            responseResult.io.message =
                "mutation prepare response too small, bytesReturned=" +
                std::to_string(responseResult.io.bytesReturned);
            return responseResult;
        }

        responseResult.version = static_cast<std::uint32_t>(response.version);
        responseResult.status = static_cast<std::uint32_t>(response.status);
        responseResult.targetKind = static_cast<std::uint32_t>(response.targetKind);
        responseResult.processId = static_cast<std::uint32_t>(response.processId);
        responseResult.bytes = static_cast<std::uint32_t>(response.bytes);
        responseResult.riskFlags = static_cast<std::uint32_t>(response.riskFlags);
        responseResult.lastStatus = static_cast<long>(response.lastStatus);
        responseResult.transactionId = static_cast<std::uint64_t>(response.transactionId);
        responseResult.targetAddress = static_cast<std::uint64_t>(response.targetAddress);
        responseResult.targetContext = static_cast<std::uint64_t>(response.targetContext);
        responseResult.beforeHash = static_cast<std::uint64_t>(response.beforeHash);
        responseResult.afterHash = static_cast<std::uint64_t>(response.afterHash);
        responseResult.timestampTick = static_cast<std::uint64_t>(response.timestampTick);
        copyBytesToVector(response.beforeBytes, KSWORD_ARK_MUTATION_MAX_BYTES, responseResult.beforeBytes);
        copyBytesToVector(response.afterBytes, KSWORD_ARK_MUTATION_MAX_BYTES, responseResult.afterBytes);

        std::ostringstream stream;
        stream << "tx=" << responseResult.transactionId
            << ", status=" << responseResult.status
            << ", kind=" << responseResult.targetKind
            << ", bytes=" << responseResult.bytes
            << ", risk=0x" << std::hex << std::uppercase << responseResult.riskFlags
            << ", lastStatus=0x" << static_cast<unsigned long>(responseResult.lastStatus);
        responseResult.io.message = stream.str();
        return responseResult;
    }

    MutationResponseResult DriverClient::commitMutation(
        const std::uint64_t transactionId,
        const unsigned long flags) const
    {
        // 输入：transactionId 和 commit flags。
        // 处理：封装 COMMIT IOCTL，只允许受控事务，不提供任意写参数。
        // 返回：MutationResponseResult，UI 可只展示 dry-run / rejected / committed 状态。
        MutationResponseResult responseResult{};
        KSWORD_ARK_MUTATION_TRANSACTION_REQUEST request{};
        KSWORD_ARK_MUTATION_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
        request.flags = flags;
        request.transactionId = transactionId;

        responseResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_MUTATION_COMMIT,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!responseResult.io.ok)
        {
            responseResult.unsupported = isUnsupportedIoctlError(responseResult.io.win32Error);
            responseResult.io.message = responseResult.unsupported
                ? "IOCTL_KSWORD_ARK_MUTATION_COMMIT unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_MUTATION_COMMIT) failed, error=" +
                    std::to_string(responseResult.io.win32Error);
            return responseResult;
        }
        if (responseResult.io.bytesReturned < kMutationResponseHeaderSize)
        {
            responseResult.io.ok = false;
            responseResult.io.message =
                "mutation commit response too small, bytesReturned=" +
                std::to_string(responseResult.io.bytesReturned);
            return responseResult;
        }

        responseResult.version = static_cast<std::uint32_t>(response.version);
        responseResult.status = static_cast<std::uint32_t>(response.status);
        responseResult.targetKind = static_cast<std::uint32_t>(response.targetKind);
        responseResult.processId = static_cast<std::uint32_t>(response.processId);
        responseResult.bytes = static_cast<std::uint32_t>(response.bytes);
        responseResult.riskFlags = static_cast<std::uint32_t>(response.riskFlags);
        responseResult.lastStatus = static_cast<long>(response.lastStatus);
        responseResult.transactionId = static_cast<std::uint64_t>(response.transactionId);
        responseResult.targetAddress = static_cast<std::uint64_t>(response.targetAddress);
        responseResult.targetContext = static_cast<std::uint64_t>(response.targetContext);
        responseResult.beforeHash = static_cast<std::uint64_t>(response.beforeHash);
        responseResult.afterHash = static_cast<std::uint64_t>(response.afterHash);
        responseResult.timestampTick = static_cast<std::uint64_t>(response.timestampTick);
        copyBytesToVector(response.beforeBytes, KSWORD_ARK_MUTATION_MAX_BYTES, responseResult.beforeBytes);
        copyBytesToVector(response.afterBytes, KSWORD_ARK_MUTATION_MAX_BYTES, responseResult.afterBytes);

        std::ostringstream stream;
        stream << "tx=" << responseResult.transactionId
            << ", status=" << responseResult.status
            << ", bytes=" << responseResult.bytes
            << ", risk=0x" << std::hex << std::uppercase << responseResult.riskFlags
            << ", lastStatus=0x" << static_cast<unsigned long>(responseResult.lastStatus);
        responseResult.io.message = stream.str();
        return responseResult;
    }

    MutationResponseResult DriverClient::rollbackMutation(
        const std::uint64_t transactionId,
        const unsigned long flags) const
    {
        // 输入：transactionId 和 rollback flags。
        // 处理：封装 ROLLBACK IOCTL，只返回事务状态，不提供任何直写参数。
        // 返回：MutationResponseResult；R3 仅能显示 rollback / dry-run / rejected。
        MutationResponseResult responseResult{};
        KSWORD_ARK_MUTATION_TRANSACTION_REQUEST request{};
        KSWORD_ARK_MUTATION_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
        request.flags = flags;
        request.transactionId = transactionId;

        responseResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_MUTATION_ROLLBACK,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!responseResult.io.ok)
        {
            responseResult.unsupported = isUnsupportedIoctlError(responseResult.io.win32Error);
            responseResult.io.message = responseResult.unsupported
                ? "IOCTL_KSWORD_ARK_MUTATION_ROLLBACK unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_MUTATION_ROLLBACK) failed, error=" +
                    std::to_string(responseResult.io.win32Error);
            return responseResult;
        }
        if (responseResult.io.bytesReturned < kMutationResponseHeaderSize)
        {
            responseResult.io.ok = false;
            responseResult.io.message =
                "mutation rollback response too small, bytesReturned=" +
                std::to_string(responseResult.io.bytesReturned);
            return responseResult;
        }

        responseResult.version = static_cast<std::uint32_t>(response.version);
        responseResult.status = static_cast<std::uint32_t>(response.status);
        responseResult.targetKind = static_cast<std::uint32_t>(response.targetKind);
        responseResult.processId = static_cast<std::uint32_t>(response.processId);
        responseResult.bytes = static_cast<std::uint32_t>(response.bytes);
        responseResult.riskFlags = static_cast<std::uint32_t>(response.riskFlags);
        responseResult.lastStatus = static_cast<long>(response.lastStatus);
        responseResult.transactionId = static_cast<std::uint64_t>(response.transactionId);
        responseResult.targetAddress = static_cast<std::uint64_t>(response.targetAddress);
        responseResult.targetContext = static_cast<std::uint64_t>(response.targetContext);
        responseResult.beforeHash = static_cast<std::uint64_t>(response.beforeHash);
        responseResult.afterHash = static_cast<std::uint64_t>(response.afterHash);
        responseResult.timestampTick = static_cast<std::uint64_t>(response.timestampTick);
        copyBytesToVector(response.beforeBytes, KSWORD_ARK_MUTATION_MAX_BYTES, responseResult.beforeBytes);
        copyBytesToVector(response.afterBytes, KSWORD_ARK_MUTATION_MAX_BYTES, responseResult.afterBytes);

        std::ostringstream stream;
        stream << "tx=" << responseResult.transactionId
            << ", status=" << responseResult.status
            << ", bytes=" << responseResult.bytes
            << ", risk=0x" << std::hex << std::uppercase << responseResult.riskFlags
            << ", lastStatus=0x" << static_cast<unsigned long>(responseResult.lastStatus);
        responseResult.io.message = stream.str();
        return responseResult;
    }

    MutationAuditResult DriverClient::queryMutationAudit(
        const unsigned long flags,
        const unsigned long maxEntries,
        const std::uint64_t startSequence) const
    {
        // 输入：audit flags、最大条数与起始 sequence。
        // 处理：读取 R0 mutation audit ring，只读解码事务元数据和可选字节快照。
        // 返回：MutationAuditResult；旧驱动或未注册 IOCTL 时 unsupported=true。
        MutationAuditResult auditResult{};
        KSWORD_ARK_MUTATION_QUERY_AUDIT_REQUEST request{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
        request.flags = flags;
        request.maxEntries = maxEntries;
        request.startSequence = startSequence;

        std::vector<std::uint8_t> responseBuffer(2U * 1024U * 1024U, 0U);
        auditResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!auditResult.io.ok)
        {
            auditResult.unsupported = isUnsupportedIoctlError(auditResult.io.win32Error);
            auditResult.io.message = auditResult.unsupported
                ? "IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT) failed, error=" +
                    std::to_string(auditResult.io.win32Error);
            return auditResult;
        }
        if (auditResult.io.bytesReturned < kMutationAuditResponseHeaderSize)
        {
            auditResult.io.ok = false;
            auditResult.io.message =
                "mutation audit response too small, bytesReturned=" +
                std::to_string(auditResult.io.bytesReturned);
            return auditResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE*>(responseBuffer.data());
        if (responseHeader->entrySize < sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY))
        {
            auditResult.io.ok = false;
            auditResult.io.message =
                "mutation audit entrySize invalid, entrySize=" +
                std::to_string(responseHeader->entrySize);
            return auditResult;
        }

        auditResult.version = static_cast<std::uint32_t>(responseHeader->version);
        auditResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        auditResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        auditResult.lostCount = static_cast<std::uint32_t>(responseHeader->lostCount);
        auditResult.oldestSequence = static_cast<std::uint64_t>(responseHeader->oldestSequence);
        auditResult.nextSequence = static_cast<std::uint64_t>(responseHeader->nextSequence);

        const std::size_t availableCount =
            (static_cast<std::size_t>(auditResult.io.bytesReturned) - kMutationAuditResponseHeaderSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t parsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            availableCount);
        auditResult.entries.reserve(parsedCount);
        for (std::size_t index = 0U; index < parsedCount; ++index)
        {
            const std::size_t entryOffset =
                kMutationAuditResponseHeaderSize +
                (index * static_cast<std::size_t>(responseHeader->entrySize));
            if (entryOffset + sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY) > responseBuffer.size())
            {
                break;
            }

            const auto* sourceEntry =
                reinterpret_cast<const KSWORD_ARK_MUTATION_AUDIT_ENTRY*>(responseBuffer.data() + entryOffset);
            MutationAuditEntry row{};
            row.operation = static_cast<std::uint32_t>(sourceEntry->operation);
            row.status = static_cast<std::uint32_t>(sourceEntry->status);
            row.lastStatus = static_cast<long>(sourceEntry->lastStatus);
            row.targetKind = static_cast<std::uint32_t>(sourceEntry->targetKind);
            row.riskFlags = static_cast<std::uint32_t>(sourceEntry->riskFlags);
            row.flags = static_cast<std::uint32_t>(sourceEntry->flags);
            row.processId = static_cast<std::uint32_t>(sourceEntry->processId);
            row.bytes = static_cast<std::uint32_t>(sourceEntry->bytes);
            row.transactionId = static_cast<std::uint64_t>(sourceEntry->transactionId);
            row.sequence = static_cast<std::uint64_t>(sourceEntry->sequence);
            row.targetAddress = static_cast<std::uint64_t>(sourceEntry->targetAddress);
            row.targetContext = static_cast<std::uint64_t>(sourceEntry->targetContext);
            row.beforeHash = static_cast<std::uint64_t>(sourceEntry->beforeHash);
            row.afterHash = static_cast<std::uint64_t>(sourceEntry->afterHash);
            row.timestampTick = static_cast<std::uint64_t>(sourceEntry->timestampTick);
            copyBytesToVector(sourceEntry->byteData, KSWORD_ARK_MUTATION_MAX_BYTES, row.byteData);
            auditResult.entries.push_back(std::move(row));
        }

        std::ostringstream stream;
        stream << "version=" << auditResult.version
            << ", total=" << auditResult.totalCount
            << ", returned=" << auditResult.returnedCount
            << ", parsed=" << auditResult.entries.size()
            << ", lost=" << auditResult.lostCount
            << ", nextSequence=" << auditResult.nextSequence;
        auditResult.io.message = stream.str();
        return auditResult;
    }
}
