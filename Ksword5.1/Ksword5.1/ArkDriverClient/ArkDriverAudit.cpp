#include "ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <limits>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace ksword::ark
{
    namespace
    {
        // kDefaultAuditBufferBytes 用途：为新增只读审计 IOCTL 提供统一输出缓冲。
        // 处理逻辑：多数协议都是 count-first + bounded rows，4MB 足够首版 UI 展示。
        // 返回行为：常量无返回值，调用方仍按 bytesReturned 和 entrySize 二次限界。
        constexpr std::size_t kDefaultAuditBufferBytes = 4U * 1024U * 1024U;
        constexpr std::uint32_t kStatusBufferOverflow = 0x80000005UL;
        constexpr std::uint32_t kStatusPartialCopy = 0x8000000DUL;

        // fixedAuditWideToString 作用：
        // - 输入：共享协议定长 wchar_t 数组和最大字符数；
        // - 处理：扫描到 NUL 或边界，避免旧驱动缺 NUL 时越界；
        // - 返回：安全 std::wstring。
        std::wstring fixedAuditWideToString(const wchar_t* const textBuffer, const std::size_t maxChars)
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

        // copyAuditWideToFixed 作用：
        // - 输入：目标定长宽字符数组、容量和 R3 字符串；
        // - 处理：清零、截断复制并保证 NUL 结尾；
        // - 返回：无返回值。
        void copyAuditWideToFixed(wchar_t* const destination, const std::size_t destinationChars, const std::wstring& source)
        {
            if (destination == nullptr || destinationChars == 0U)
            {
                return;
            }

            std::fill(destination, destination + destinationChars, L'\0');
            const std::size_t copyChars = std::min<std::size_t>(source.size(), destinationChars - 1U);
            if (copyChars != 0U)
            {
                std::copy(source.data(), source.data() + static_cast<std::ptrdiff_t>(copyChars), destination);
            }
        }

        // isAuditUnsupportedError 作用：
        // - 输入：DeviceIoControl 失败后的 Win32 错误；
        // - 处理：识别旧驱动未注册新 IOCTL 的常见错误；
        // - 返回：true 表示 UI 应显示 unsupported 而不是协议损坏。
        bool isAuditUnsupportedError(const unsigned long win32Error)
        {
            return win32Error == ERROR_INVALID_FUNCTION ||
                win32Error == ERROR_NOT_SUPPORTED ||
                win32Error == ERROR_INVALID_PARAMETER;
        }

        // markUnsupportedIfNeeded 作用：
        // - 输入：任意包含 io/unsupported 字段的结果和操作名；
        // - 处理：当 IOCTL 失败时补齐统一 message 和 unsupported 标志；
        // - 返回：无返回值，Result 原地更新。
        template <typename TResult>
        void markUnsupportedIfNeeded(TResult& result, const char* const operationName)
        {
            if (result.io.ok)
            {
                return;
            }

            result.unsupported = isAuditUnsupportedError(result.io.win32Error);
            std::ostringstream stream;
            stream << "DeviceIoControl(" << (operationName != nullptr ? operationName : "audit")
                << ") failed, error=" << result.io.win32Error;
            if (result.unsupported)
            {
                stream << ", unsupported=true";
            }
            result.io.message = stream.str();
        }

        // validateAuditRows 作用：
        // - 输入：返回字节数、头大小、entrySize、最小行结构大小和 returnedCount；
        // - 处理：验证变长响应边界并计算可安全解析的行数；
        // - 返回：可解析行数，失败时设置 io 并返回 0。
        std::size_t validateAuditRows(
            IoResult& io,
            const std::size_t headerSize,
            const std::uint32_t entrySize,
            const std::size_t minimumEntrySize,
            const std::uint32_t returnedCount,
            const char* const operationName)
        {
            if (io.bytesReturned < headerSize)
            {
                io.ok = false;
                io.win32Error = ERROR_INSUFFICIENT_BUFFER;
                io.message = std::string(operationName) + " response too small, bytesReturned=" + std::to_string(io.bytesReturned);
                return 0U;
            }
            if (entrySize < minimumEntrySize)
            {
                io.ok = false;
                io.win32Error = ERROR_INVALID_DATA;
                io.message = std::string(operationName) + " entrySize invalid, entrySize=" + std::to_string(entrySize);
                return 0U;
            }

            const std::size_t availableRows = (io.bytesReturned - headerSize) / static_cast<std::size_t>(entrySize);
            return std::min<std::size_t>(static_cast<std::size_t>(returnedCount), availableRows);
        }

        // validateNetworkAuditHeader 作用：
        // - 输入：R0 网络审计响应头、固定头大小和操作名；
        // - 处理：校验协议版本、头大小、状态、来源位、计数和预算关系；
        // - 返回：true 表示后续可以安全解析变长行，失败时同步写入 IoResult。
        template <typename TResponse>
        bool validateNetworkAuditHeader(
            IoResult& io,
            const TResponse& response,
            const std::size_t headerSize,
            const char* const operationName)
        {
            constexpr std::uint32_t knownSourceFlags =
                KSWORD_ARK_NETWORK_AUDIT_SOURCE_TCPIP_PDB |
                KSWORD_ARK_NETWORK_AUDIT_SOURCE_NETIO_PDB |
                KSWORD_ARK_NETWORK_AUDIT_SOURCE_NDIS_PDB |
                KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;

            auto fail = [&io, operationName](const std::string& reason)
            {
                io.ok = false;
                io.win32Error = ERROR_INVALID_DATA;
                io.message = std::string(operationName) + " invalid response: " + reason;
                return false;
            };

            if (response.version != KSWORD_ARK_NETWORK_PROTOCOL_VERSION)
            {
                return fail("version=" + std::to_string(response.version));
            }
            if (response.size != headerSize || response.size > io.bytesReturned)
            {
                return fail("size=" + std::to_string(response.size) +
                    ", bytesReturned=" + std::to_string(io.bytesReturned));
            }
            if (response.status > KSWORD_ARK_NETWORK_STATUS_AUDIT_STUB)
            {
                return fail("status=" + std::to_string(response.status));
            }
            if ((response.flags & ~KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL) != 0UL)
            {
                return fail("flags=" + std::to_string(response.flags));
            }
            if ((response.sourceFlags & ~knownSourceFlags) != 0UL)
            {
                return fail("sourceFlags=" + std::to_string(response.sourceFlags));
            }
            if (response.returnedRowCount > response.totalRowCount)
            {
                return fail("returnedRowCount exceeds totalRowCount");
            }
            if (response.budgetRows != 0UL && response.returnedRowCount > response.budgetRows)
            {
                return fail("returnedRowCount exceeds budgetRows");
            }
            return true;
        }

        // isRetainableNetworkInventoryPartial 作用：
        // - 输入：WFP/NDIS 响应的协议状态、NTSTATUS 和实际返回行数；
        // - 处理：只认可驱动约定的 PARTIAL_COPY/BUFFER_OVERFLOW 部分快照；
        // - 返回：true 表示合法行可以保留给 UI/CLI，其他 OPERATION_FAILED 不可用。
        bool isRetainableNetworkInventoryPartial(
            const std::uint32_t status,
            const long lastStatus,
            const std::uint32_t returnedCount) noexcept
        {
            const std::uint32_t normalizedStatus =
                static_cast<std::uint32_t>(lastStatus);
            return status == KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED &&
                returnedCount != 0U &&
                (normalizedStatus == kStatusPartialCopy ||
                 normalizedStatus == kStatusBufferOverflow);
        }

        // finalizeNetworkInventoryCompleteness 作用：
        // - 输入：已完成协议边界和逐行校验的 WFP/NDIS wrapper 结果；
        // - 处理：标记 complete/partial/truncated，并丢弃不符合 partial 契约的失败行；
        // - 返回：无返回值，结果原地更新。
        template <typename TResult>
        void finalizeNetworkInventoryCompleteness(TResult& result)
        {
            const bool applied =
                result.status == KSWORD_ARK_NETWORK_STATUS_APPLIED;
            const bool complete =
                applied && result.totalCount == result.returnedCount;
            const bool collectorPartial = isRetainableNetworkInventoryPartial(
                result.status,
                result.lastStatus,
                result.returnedCount);
            const bool appliedTruncated =
                applied && !complete;
            result.partial = collectorPartial || appliedTruncated;
            result.truncated =
                appliedTruncated ||
                (collectorPartial &&
                 (result.totalCount > result.returnedCount ||
                  static_cast<std::uint32_t>(result.lastStatus) ==
                      kStatusBufferOverflow));

            if (!applied && !collectorPartial)
            {
                result.entries.clear();
            }
        }

        // finalizeNetworkEndpointCompleteness 作用：
        // - 输入：已通过共享头与 endpoint 行校验的 TCP/UDP 结果；
        // - 处理：endpoint 只接受 APPLIED；失败响应中的行一律丢弃；
        // - 返回：无返回值，同时填充 truncated 供 UI 明确展示。
        void finalizeNetworkEndpointCompleteness(
            NetworkEndpointAuditResult& result)
        {
            const bool applied =
                result.status == KSWORD_ARK_NETWORK_STATUS_APPLIED;
            const bool complete =
                applied && result.totalCount == result.returnedCount;
            result.partial = applied && !complete;
            result.truncated = result.partial;
            if (!applied)
            {
                result.entries.clear();
            }
        }

        // appendNetworkAuditState 作用：
        // - 输入：已生成的解析摘要和网络响应状态字段；
        // - 处理：把协议状态、NTSTATUS、来源与 generation 附加到诊断文本；
        // - 返回：可直接交给 UI/日志的完整结构化说明。
        std::string appendNetworkAuditState(
            std::string summary,
            const std::uint32_t status,
            const long lastStatus,
            const std::uint32_t sourceFlags,
            const std::uint32_t generation)
        {
            std::ostringstream stream;
            stream << summary
                << ", protocolStatus=" << status
                << ", lastStatus=0x" << std::hex << static_cast<std::uint32_t>(lastStatus)
                << ", sourceFlags=0x" << sourceFlags
                << std::dec << ", generation=" << generation;
            return stream.str();
        }

        // appendAuditSummary 作用：
        // - 输入：操作名、总数、返回数、解析数和字节数；
        // - 处理：生成统一成功诊断字符串；
        // - 返回：std::string，可直接写入 IoResult::message。
        std::string appendAuditSummary(
            const char* const operationName,
            const std::uint32_t totalCount,
            const std::uint32_t returnedCount,
            const std::size_t parsedCount,
            const unsigned long bytesReturned)
        {
            std::ostringstream stream;
            stream << operationName
                << " total=" << totalCount
                << ", returned=" << returnedCount
                << ", parsed=" << parsedCount
                << ", bytesReturned=" << bytesReturned;
            return stream.str();
        }

        // parseVariableRows 作用：
        // - 输入：响应缓冲、头部大小、行大小和解析行数；
        // - 处理：逐行 memcpy 到 std::vector，避免直接保存悬空指针；
        // - 返回：行 vector，行类型必须是 trivially copyable 协议结构。
        template <typename TEntry>
        std::vector<TEntry> parseVariableRows(
            const std::vector<std::uint8_t>& responseBuffer,
            const std::size_t headerSize,
            const std::uint32_t entrySize,
            const std::size_t parsedCount)
        {
            static_assert(std::is_trivially_copyable_v<TEntry>, "audit protocol rows must be trivially copyable");
            std::vector<TEntry> rows;
            rows.reserve(parsedCount);
            for (std::size_t index = 0U; index < parsedCount; ++index)
            {
                const std::size_t offset = headerSize + (index * static_cast<std::size_t>(entrySize));
                if (offset + sizeof(TEntry) > responseBuffer.size())
                {
                    break;
                }

                TEntry row{};
                std::memcpy(&row, responseBuffer.data() + offset, sizeof(TEntry));
                rows.push_back(row);
            }
            return rows;
        }

        // queryFixedAudit 作用：
        // - 输入：DriverClient、IOCTL、可选输入、固定响应和操作名；
        // - 处理：调用统一 deviceIoControl 并验证固定响应字节数；
        // - 返回：IoResult，固定响应由调用方传入的 responseOut 承载。
        template <typename TRequest, typename TResponse>
        IoResult queryFixedAudit(
            const DriverClient& client,
            const unsigned long ioctlCode,
            TRequest* const request,
            TResponse& responseOut,
            const char* const operationName)
        {
            IoResult io = client.deviceIoControl(
                ioctlCode,
                request,
                request != nullptr ? static_cast<unsigned long>(sizeof(TRequest)) : 0UL,
                &responseOut,
                static_cast<unsigned long>(sizeof(TResponse)));
            if (!io.ok)
            {
                io.message = std::string("DeviceIoControl(") + operationName + ") failed, error=" + std::to_string(io.win32Error);
                return io;
            }
            if (io.bytesReturned < sizeof(TResponse))
            {
                io.ok = false;
                io.win32Error = ERROR_INSUFFICIENT_BUFFER;
                io.message = std::string(operationName) + " response too small, bytesReturned=" + std::to_string(io.bytesReturned);
            }
            return io;
        }

        // queryNoInputFixedAudit 作用：
        // - 输入：DriverClient、IOCTL、固定响应和操作名；
        // - 处理：无输入缓冲调用固定响应 IOCTL；
        // - 返回：IoResult，供 Hyper-V/AppControl 等无输入查询复用。
        template <typename TResponse>
        IoResult queryNoInputFixedAudit(
            const DriverClient& client,
            const unsigned long ioctlCode,
            TResponse& responseOut,
            const char* const operationName)
        {
            IoResult io = client.deviceIoControl(
                ioctlCode,
                nullptr,
                0UL,
                &responseOut,
                static_cast<unsigned long>(sizeof(TResponse)));
            if (!io.ok)
            {
                io.message = std::string("DeviceIoControl(") + operationName + ") failed, error=" + std::to_string(io.win32Error);
                return io;
            }
            if (io.bytesReturned < sizeof(TResponse))
            {
                io.ok = false;
                io.win32Error = ERROR_INSUFFICIENT_BUFFER;
                io.message = std::string(operationName) + " response too small, bytesReturned=" + std::to_string(io.bytesReturned);
            }
            return io;
        }

        // buildNetworkRequest 作用：
        // - 输入：网络审计 flags 和行预算；
        // - 处理：填充共享协议版本、结构大小和保守预算；
        // - 返回：KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST。
        KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST buildNetworkRequest(const unsigned long flags, const unsigned long maxRows)
        {
            KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request{};
            request.version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
            request.size = sizeof(request);
            request.flags = flags;
            request.maxRows = maxRows;
            return request;
        }

        // buildStorageRequest 作用：
        // - 输入：卷路径、flags、行预算和栈深度预算；
        // - 处理：填充共享 Storage 请求并安全复制可选卷路径；
        // - 返回：KSWORD_ARK_STORAGE_AUDIT_REQUEST。
        KSWORD_ARK_STORAGE_AUDIT_REQUEST buildStorageRequest(
            const std::wstring& volumePath,
            const unsigned long flags,
            const unsigned long maxRows,
            const unsigned long maxDepth)
        {
            KSWORD_ARK_STORAGE_AUDIT_REQUEST request{};
            request.version = KSWORD_ARK_STORAGE_PROTOCOL_VERSION;
            request.size = sizeof(request);
            request.flags = flags;
            request.maxRows = maxRows;
            request.maxDepth = maxDepth;
            if (!volumePath.empty())
            {
                copyAuditWideToFixed(request.volumePath, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS, volumePath);
                request.volumePathLengthChars = static_cast<unsigned short>(std::min<std::size_t>(volumePath.size(), KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS - 1U));
            }
            return request;
        }

        // buildWin32kRequest 作用：
        // - 输入：flags/session/pid/tid/maxEntries；
        // - 处理：归一化 Win32K 共享查询请求；
        // - 返回：KSWORD_ARK_WIN32K_QUERY_REQUEST。
        KSWORD_ARK_WIN32K_QUERY_REQUEST buildWin32kRequest(
            const unsigned long flags,
            const unsigned long sessionId,
            const unsigned long processId,
            const unsigned long threadId,
            const unsigned long maxEntries)
        {
            KSWORD_ARK_WIN32K_QUERY_REQUEST request{};
            unsigned long effectiveSessionId = sessionId;
            if (effectiveSessionId == 0UL &&
                (flags & KSWORD_ARK_WIN32K_QUERY_FLAG_CURRENT_SESSION_ONLY) != 0UL)
            {
                DWORD currentSessionId = 0U;
                if (::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId) != FALSE)
                {
                    effectiveSessionId = currentSessionId;
                }
            }
            request.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
            request.flags = flags;
            request.sessionId = effectiveSessionId;
            request.processId = processId;
            request.threadId = threadId;
            request.maxEntries = maxEntries;
            return request;
        }


        // queryNetworkEndpointAudit 作用：
        // - 输入：TCP/UDP IOCTL、flags、行预算和操作名；
        // - 处理：发送网络 endpoint 只读查询并解析变长响应；
        // - 返回：NetworkEndpointAuditResult。
        NetworkEndpointAuditResult queryNetworkEndpointAudit(
            const DriverClient& client,
            const unsigned long ioctlCode,
            const unsigned long flags,
            const unsigned long maxRows,
            const char* const operationName)
        {
            NetworkEndpointAuditResult result{};
            KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request = buildNetworkRequest(flags, maxRows);
            std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
            result.io = client.deviceIoControl(ioctlCode, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
            if (!result.io.ok)
            {
                markUnsupportedIfNeeded(result, operationName);
                return result;
            }

            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW);
            const auto* response = reinterpret_cast<const KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE*>(responseBuffer.data());
            if (!validateNetworkAuditHeader(result.io, *response, headerSize, operationName))
            {
                return result;
            }
            const std::size_t parsedCount = validateAuditRows(result.io, headerSize, response->entrySize, sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW), response->returnedRowCount, operationName);
            if (!result.io.ok)
            {
                return result;
            }
            if (parsedCount != static_cast<std::size_t>(response->returnedRowCount))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = std::string(operationName) + " returned rows exceed response bytes";
                return result;
            }

            result.version = response->version;
            result.status = response->status;
            result.flags = response->flags;
            result.totalCount = response->totalRowCount;
            result.returnedCount = response->returnedRowCount;
            result.entrySize = response->entrySize;
            result.sourceFlags = response->sourceFlags;
            result.budgetRows = response->budgetRows;
            result.generation = response->generation;
            result.lastStatus = response->lastStatus;
            result.io.ntStatus = response->lastStatus;
            result.entries = parseVariableRows<KSWORD_ARK_NETWORK_ENDPOINT_ROW>(responseBuffer, headerSize, response->entrySize, parsedCount);
            const std::uint32_t expectedProtocol =
                ioctlCode == IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS
                ? KSWORD_ARK_NETWORK_PROTOCOL_TCP
                : KSWORD_ARK_NETWORK_PROTOCOL_UDP;
            constexpr std::uint32_t knownRowFlags =
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
            constexpr std::uint32_t knownSourceFlags =
                KSWORD_ARK_NETWORK_AUDIT_SOURCE_TCPIP_PDB |
                KSWORD_ARK_NETWORK_AUDIT_SOURCE_NETIO_PDB |
                KSWORD_ARK_NETWORK_AUDIT_SOURCE_NDIS_PDB |
                KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;
            for (const KSWORD_ARK_NETWORK_ENDPOINT_ROW& entry : result.entries)
            {
                const bool knownFamily =
                    entry.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_UNKNOWN ||
                    entry.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4 ||
                    entry.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6;
                if (!knownFamily ||
                    entry.protocol != expectedProtocol ||
                    (entry.flags & ~knownRowFlags) != 0UL ||
                    (entry.sourceFlags & ~knownSourceFlags) != 0UL)
                {
                    result.io.ok = false;
                    result.io.win32Error = ERROR_INVALID_DATA;
                    result.io.message = std::string(operationName) + " contains an invalid endpoint row";
                    result.entries.clear();
                    return result;
                }
            }
            finalizeNetworkEndpointCompleteness(result);
            result.io.message = appendNetworkAuditState(
                appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned),
                result.status,
                result.lastStatus,
                result.sourceFlags,
                result.generation);
            result.io.message += result.partial || result.truncated
                ? ", completeness=partial, truncatedRowsRetained=true"
                : (result.status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                   result.totalCount == result.returnedCount
                    ? ", completeness=complete"
                    : ", completeness=unavailable, responseRowsDiscarded=true");
            return result;
        }

        // queryNetworkWfpAudit 作用：发送 WFP inventory IOCTL 并解析 owner/module 行。
        NetworkWfpInventoryResult queryNetworkWfpAudit(
            const DriverClient& client,
            const unsigned long flags,
            const unsigned long maxRows)
        {
            constexpr const char* operationName = "IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY";
            NetworkWfpInventoryResult result{};
            KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request = buildNetworkRequest(flags, maxRows);
            std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
            result.io = client.deviceIoControl(IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
            if (!result.io.ok)
            {
                markUnsupportedIfNeeded(result, operationName);
                return result;
            }

            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW);
            const auto* response = reinterpret_cast<const KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE*>(responseBuffer.data());
            if (!validateNetworkAuditHeader(result.io, *response, headerSize, operationName))
            {
                return result;
            }
            const std::size_t parsedCount = validateAuditRows(result.io, headerSize, response->entrySize, sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW), response->returnedRowCount, operationName);
            if (!result.io.ok)
            {
                return result;
            }
            if (parsedCount != static_cast<std::size_t>(response->returnedRowCount))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = std::string(operationName) + " returned rows exceed response bytes";
                return result;
            }

            result.version = response->version;
            result.status = response->status;
            result.flags = response->flags;
            result.totalCount = response->totalRowCount;
            result.returnedCount = response->returnedRowCount;
            result.entrySize = response->entrySize;
            result.sourceFlags = response->sourceFlags;
            result.budgetRows = response->budgetRows;
            result.generation = response->generation;
            result.lastStatus = response->lastStatus;
            result.io.ntStatus = response->lastStatus;
            result.entries = parseVariableRows<KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW>(responseBuffer, headerSize, response->entrySize, parsedCount);
            constexpr std::uint32_t knownRowFlags =
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
            for (const KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW& entry : result.entries)
            {
                if (entry.objectKind < KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER ||
                    entry.objectKind > KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT ||
                    (entry.flags & ~knownRowFlags) != 0UL)
                {
                    result.io.ok = false;
                    result.io.win32Error = ERROR_INVALID_DATA;
                    result.io.message = std::string(operationName) + " contains an invalid WFP row";
                    result.entries.clear();
                    return result;
                }
            }
            finalizeNetworkInventoryCompleteness(result);
            result.io.message = appendNetworkAuditState(
                appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned),
                result.status,
                result.lastStatus,
                result.sourceFlags,
                result.generation);
            result.io.message += result.partial || result.truncated
                ? ", completeness=partial, partialRowsRetained=true"
                : (result.status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                   result.totalCount == result.returnedCount
                    ? ", completeness=complete"
                    : ", completeness=unavailable, responseRowsDiscarded=true");
            return result;
        }

        // queryNetworkWfpEventAudit 作用：
        // - 输入：稳定 afterSequence cursor 和单次行预算；
        // - 处理：发送真实 WFP ALE event IOCTL，验证响应大小/乘加边界/行 ABI/序号单调性；
        // - 返回：仅含无 payload 流授权元数据的 NetworkWfpEventResult。
        NetworkWfpEventResult queryNetworkWfpEventAudit(
            const DriverClient& client,
            const std::uint64_t afterSequence,
            const unsigned long maxRows)
        {
            constexpr const char* operationName = "IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS";
            constexpr std::size_t headerSize =
                sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE) -
                sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW);
            NetworkWfpEventResult result{};
            KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST request{};
            request.version = KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION;
            request.size = sizeof(request);
            request.flags = KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_FLAG_NONE;
            request.maxRows = maxRows;
            request.afterSequence = afterSequence;

            std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
            result.io = client.deviceIoControl(
                IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS,
                &request,
                sizeof(request),
                responseBuffer.data(),
                static_cast<unsigned long>(responseBuffer.size()));
            if (!result.io.ok)
            {
                markUnsupportedIfNeeded(result, operationName);
                return result;
            }

            const auto failProtocol = [&result, operationName](const std::string& reason)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = std::string(operationName) + " protocol validation failed: " + reason;
            };

            if (result.io.bytesReturned < headerSize)
            {
                failProtocol("response header truncated, bytesReturned=" + std::to_string(result.io.bytesReturned));
                return result;
            }

            const auto* response =
                reinterpret_cast<const KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE*>(responseBuffer.data());
            if (response->version != KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION)
            {
                failProtocol("response version=" + std::to_string(response->version));
                return result;
            }
            if (response->entrySize != sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW))
            {
                failProtocol("entrySize=" + std::to_string(response->entrySize));
                return result;
            }
            if (response->size < headerSize ||
                response->size != result.io.bytesReturned)
            {
                failProtocol(
                    "response size=" + std::to_string(response->size) +
                    ", bytesReturned=" + std::to_string(result.io.bytesReturned));
                return result;
            }
            constexpr unsigned long knownResponseFlags =
                KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_GAP |
                KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_TRUNCATED |
                KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_RESET;
            if ((response->flags & ~knownResponseFlags) != 0UL ||
                response->reserved != 0UL ||
                (response->status != KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                    response->status != KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE &&
                    response->status != KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED))
            {
                failProtocol(
                    "response status/flags/reserved invalid, status=" +
                    std::to_string(response->status) +
                    ", flags=" + std::to_string(response->flags));
                return result;
            }
            if (response->returnedEventCount > response->availableEventCount)
            {
                failProtocol(
                    "returnedEventCount=" + std::to_string(response->returnedEventCount) +
                    " exceeds availableEventCount=" + std::to_string(response->availableEventCount));
                return result;
            }

            const unsigned long effectiveRequestedRows =
                maxRows == 0UL ?
                KSWORD_ARK_NETWORK_WFP_EVENT_DEFAULT_REQUESTED_ROWS :
                std::min<unsigned long>(maxRows, KSWORD_ARK_NETWORK_WFP_EVENT_MAX_REQUESTED_ROWS);
            if (response->returnedEventCount > effectiveRequestedRows)
            {
                failProtocol(
                    "returnedEventCount=" + std::to_string(response->returnedEventCount) +
                    " exceeds requested rows=" + std::to_string(effectiveRequestedRows));
                return result;
            }
            if (response->returnedEventCount >
                (std::numeric_limits<std::size_t>::max() - headerSize) /
                static_cast<std::size_t>(response->entrySize))
            {
                failProtocol("row byte multiplication overflow");
                return result;
            }

            const std::size_t requiredBytes =
                headerSize +
                (static_cast<std::size_t>(response->returnedEventCount) *
                    static_cast<std::size_t>(response->entrySize));
            if (requiredBytes > static_cast<std::size_t>(result.io.bytesReturned) ||
                requiredBytes != static_cast<std::size_t>(response->size))
            {
                failProtocol(
                    "row bytes=" + std::to_string(requiredBytes) +
                    ", response size=" + std::to_string(response->size) +
                    ", bytesReturned=" + std::to_string(result.io.bytesReturned));
                return result;
            }
            if (response->availableEventCount > response->capacity)
            {
                failProtocol(
                    "availableEventCount=" + std::to_string(response->availableEventCount) +
                    " exceeds capacity=" + std::to_string(response->capacity));
                return result;
            }
            if (response->capacity == 0UL ||
                (((response->flags &
                    KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_TRUNCATED) != 0UL) !=
                    (response->availableEventCount > response->returnedEventCount)) ||
                (((response->flags &
                    KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_GAP) != 0UL) !=
                    (response->cursorGapCount != 0ULL)))
            {
                failProtocol(
                    "capacity/flag counters inconsistent, capacity=" +
                    std::to_string(response->capacity) +
                    ", available=" + std::to_string(response->availableEventCount) +
                    ", returned=" + std::to_string(response->returnedEventCount) +
                    ", cursorGap=" + std::to_string(response->cursorGapCount));
                return result;
            }
            if ((response->oldestSequence == 0ULL) != (response->newestSequence == 0ULL) ||
                (response->oldestSequence != 0ULL &&
                    response->oldestSequence > response->newestSequence) ||
                (response->oldestSequence == 0ULL &&
                    (response->availableEventCount != 0UL ||
                        response->returnedEventCount != 0UL)))
            {
                failProtocol(
                    "invalid sequence window oldest=" + std::to_string(response->oldestSequence) +
                    ", newest=" + std::to_string(response->newestSequence));
                return result;
            }

            const bool cursorReset =
                (response->flags & KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_RESET) != 0UL;
            if (cursorReset &&
                (response->newestSequence == 0ULL ||
                    afterSequence <= response->newestSequence))
            {
                failProtocol(
                    "cursor reset is inconsistent with afterSequence=" +
                    std::to_string(afterSequence) +
                    ", newest=" + std::to_string(response->newestSequence));
                return result;
            }
            std::uint64_t previousSequence = cursorReset ? 0ULL : afterSequence;
            constexpr unsigned long knownRowFlags =
                KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_NO_PAYLOAD |
                KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_BLOCKED |
                KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ACTION_WRITE_UNAVAILABLE |
                KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_CONNECT |
                KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_RECV_ACCEPT |
                KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_IPV4;
            result.entries.reserve(response->returnedEventCount);
            for (std::uint32_t index = 0U; index < response->returnedEventCount; ++index)
            {
                const std::size_t offset =
                    headerSize +
                    (static_cast<std::size_t>(index) *
                        static_cast<std::size_t>(response->entrySize));
                KSWORD_ARK_NETWORK_WFP_EVENT_ROW row{};
                std::memcpy(&row, responseBuffer.data() + offset, sizeof(row));
                if (row.version != KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION ||
                    row.size < sizeof(row) ||
                    row.size > response->entrySize)
                {
                    failProtocol(
                        "row[" + std::to_string(index) + "] ABI invalid, version=" +
                        std::to_string(row.version) + ", size=" + std::to_string(row.size));
                    result.entries.clear();
                    return result;
                }
                if (row.sequence <= previousSequence)
                {
                    failProtocol(
                        "row[" + std::to_string(index) + "] sequence=" +
                        std::to_string(row.sequence) + " is not strictly increasing after " +
                        std::to_string(previousSequence));
                    result.entries.clear();
                    return result;
                }
                if (row.direction != KSWORD_ARK_NETWORK_DIRECTION_INBOUND &&
                    row.direction != KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND)
                {
                    failProtocol(
                        "row[" + std::to_string(index) + "] direction=" +
                        std::to_string(row.direction));
                    result.entries.clear();
                    return result;
                }
                if (row.protocol > std::numeric_limits<std::uint8_t>::max() ||
                    (row.flags & ~knownRowFlags) != 0UL ||
                    (row.flags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_NO_PAYLOAD) == 0UL ||
                    (row.flags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_IPV4) == 0UL ||
                    (((row.flags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_CONNECT) != 0UL) ==
                        ((row.flags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_RECV_ACCEPT) != 0UL)) ||
                    (((row.flags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_BLOCKED) != 0UL) &&
                        ((row.flags &
                            KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ACTION_WRITE_UNAVAILABLE) != 0UL)) ||
                    row.reserved0 != 0UL ||
                    row.reserved1 != 0UL ||
                    (response->oldestSequence != 0ULL &&
                        (row.sequence < response->oldestSequence ||
                            row.sequence > response->newestSequence)))
                {
                    failProtocol(
                        "row[" + std::to_string(index) +
                        "] protocol/flags invalid, protocol=" + std::to_string(row.protocol) +
                        ", flags=" + std::to_string(row.flags));
                    result.entries.clear();
                    return result;
                }
                previousSequence = row.sequence;
                result.entries.push_back(row);
            }

            const std::uint64_t expectedNextSequence =
                result.entries.empty() ?
                (cursorReset ? 0ULL : afterSequence) :
                result.entries.back().sequence;
            if (response->nextSequence != expectedNextSequence)
            {
                failProtocol(
                    "nextSequence=" + std::to_string(response->nextSequence) +
                    ", expected=" + std::to_string(expectedNextSequence));
                result.entries.clear();
                return result;
            }

            result.version = response->version;
            result.status = response->status;
            result.flags = response->flags;
            result.totalCount = response->availableEventCount;
            result.returnedCount = response->returnedEventCount;
            result.entrySize = response->entrySize;
            result.capacity = response->capacity;
            result.oldestSequence = response->oldestSequence;
            result.newestSequence = response->newestSequence;
            result.nextSequence = response->nextSequence;
            result.droppedEventCount = response->droppedEventCount;
            result.cursorGapCount = response->cursorGapCount;
            result.lastStatus = response->lastStatus;
            result.io.ntStatus = response->lastStatus;

            std::ostringstream summary;
            summary << appendAuditSummary(
                operationName,
                result.totalCount,
                result.returnedCount,
                result.entries.size(),
                result.io.bytesReturned)
                << ", oldest=" << result.oldestSequence
                << ", newest=" << result.newestSequence
                << ", next=" << result.nextSequence
                << ", dropped=" << result.droppedEventCount
                << ", cursorGap=" << result.cursorGapCount;
            result.io.message = summary.str();
            return result;
        }

        // queryNetworkNdisAudit 作用：发送 NDIS chain IOCTL 并解析链路行。
        NetworkNdisChainResult queryNetworkNdisAudit(
            const DriverClient& client,
            const unsigned long flags,
            const unsigned long maxRows)
        {
            constexpr const char* operationName = "IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN";
            NetworkNdisChainResult result{};
            KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request = buildNetworkRequest(flags, maxRows);
            std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
            result.io = client.deviceIoControl(IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
            if (!result.io.ok)
            {
                markUnsupportedIfNeeded(result, operationName);
                return result;
            }

            constexpr std::size_t headerSize = sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW);
            const auto* response = reinterpret_cast<const KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE*>(responseBuffer.data());
            if (!validateNetworkAuditHeader(result.io, *response, headerSize, operationName))
            {
                return result;
            }
            const std::size_t parsedCount = validateAuditRows(result.io, headerSize, response->entrySize, sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW), response->returnedRowCount, operationName);
            if (!result.io.ok)
            {
                return result;
            }
            if (parsedCount != static_cast<std::size_t>(response->returnedRowCount))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = std::string(operationName) + " returned rows exceed response bytes";
                return result;
            }

            result.version = response->version;
            result.status = response->status;
            result.flags = response->flags;
            result.totalCount = response->totalRowCount;
            result.returnedCount = response->returnedRowCount;
            result.entrySize = response->entrySize;
            result.sourceFlags = response->sourceFlags;
            result.budgetRows = response->budgetRows;
            result.generation = response->generation;
            result.lastStatus = response->lastStatus;
            result.io.ntStatus = response->lastStatus;
            result.entries = parseVariableRows<KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW>(responseBuffer, headerSize, response->entrySize, parsedCount);
            constexpr std::uint32_t knownRowFlags =
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
            for (const KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW& entry : result.entries)
            {
                if (entry.objectKind > KSWORD_ARK_NETWORK_NDIS_OBJECT_BINDING ||
                    (entry.flags & ~knownRowFlags) != 0UL)
                {
                    result.io.ok = false;
                    result.io.win32Error = ERROR_INVALID_DATA;
                    result.io.message = std::string(operationName) + " contains an invalid NDIS row";
                    result.entries.clear();
                    return result;
                }
            }
            finalizeNetworkInventoryCompleteness(result);
            result.io.message = appendNetworkAuditState(
                appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned),
                result.status,
                result.lastStatus,
                result.sourceFlags,
                result.generation);
            result.io.message += result.partial || result.truncated
                ? ", completeness=partial, partialRowsRetained=true"
                : (result.status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                   result.totalCount == result.returnedCount
                    ? ", completeness=complete"
                    : ", completeness=unavailable, responseRowsDiscarded=true");
            return result;
        }

        // queryStorageRows 作用：
        // - 输入：任意 Storage 变长响应/行类型与 IOCTL；
        // - 处理：发送请求、验证 rowSize、解析 rows；
        // - 返回：具体 Storage 结果类型。
        template <typename TResult, typename TResponse, typename TRow>
        TResult queryStorageRows(
            const DriverClient& client,
            const unsigned long ioctlCode,
            const KSWORD_ARK_STORAGE_AUDIT_REQUEST& request,
            const char* const operationName)
        {
            TResult result{};
            std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
            result.io = client.deviceIoControl(ioctlCode, const_cast<KSWORD_ARK_STORAGE_AUDIT_REQUEST*>(&request), sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
            if (!result.io.ok)
            {
                markUnsupportedIfNeeded(result, operationName);
                return result;
            }

            constexpr std::size_t headerSize = sizeof(TResponse) - sizeof(TRow);
            const auto* response = reinterpret_cast<const TResponse*>(responseBuffer.data());
            const std::size_t parsedCount = validateAuditRows(result.io, headerSize, response->rowSize, sizeof(TRow), response->returnedRows, operationName);
            if (!result.io.ok)
            {
                return result;
            }

            result.version = response->version;
            result.status = response->queryStatus;
            result.entrySize = response->rowSize;
            result.responseFlags = response->responseFlags;
            result.fieldFlags = response->fieldFlags;
            result.totalCount = response->totalRows;
            result.returnedCount = response->returnedRows;
            result.maxRows = response->maxRows;
            result.lastStatus = response->lastStatus;
            result.io.ntStatus = response->lastStatus;
            if constexpr (std::is_same_v<TResult, StorageVolumeStackAuditResult>)
            {
                result.fvevolPresent = response->fvevolPresent;
                result.fvevolPosition = response->fvevolPosition;
            }
            result.rows = parseVariableRows<TRow>(responseBuffer, headerSize, response->rowSize, parsedCount);
            result.io.message = appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.rows.size(), result.io.bytesReturned);
            return result;
        }
    }

    NetworkEndpointAuditResult DriverClient::queryNetworkTcpEndpoints(const unsigned long flags, const unsigned long maxRows) const
    {
        return queryNetworkEndpointAudit(*this, IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS, flags, maxRows, "IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS");
    }

    NetworkEndpointAuditResult DriverClient::queryNetworkUdpEndpoints(const unsigned long flags, const unsigned long maxRows) const
    {
        return queryNetworkEndpointAudit(*this, IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS, flags, maxRows, "IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS");
    }

    NetworkWfpInventoryResult DriverClient::queryNetworkWfpInventory(const unsigned long flags, const unsigned long maxRows) const
    {
        return queryNetworkWfpAudit(*this, flags, maxRows);
    }

    NetworkWfpEventResult DriverClient::queryNetworkWfpEvents(
        const std::uint64_t afterSequence,
        const unsigned long maxRows) const
    {
        return queryNetworkWfpEventAudit(*this, afterSequence, maxRows);
    }

    NetworkNdisChainResult DriverClient::queryNetworkNdisChain(const unsigned long flags, const unsigned long maxRows) const
    {
        return queryNetworkNdisAudit(*this, flags, maxRows);
    }

    MinifilterInventoryResult DriverClient::queryMinifilterInventory(const unsigned long flags, const unsigned long maxRows) const
    {
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY";
        MinifilterInventoryResult result{};
        KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_FILTER_PROTOCOL_VERSION;
        request.flags = flags;
        request.maxRows = maxRows;
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE*>(responseBuffer.data());
        const std::size_t parsedCount = validateAuditRows(result.io, headerSize, response->entrySize, sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY), response->returnedCount, operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->queryStatus;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.responseFlags = response->flags;
        result.lastStatus = response->lastStatus;
        result.io.ntStatus = response->lastStatus;
        result.entries = parseVariableRows<KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY>(responseBuffer, headerSize, response->entrySize, parsedCount);
        result.io.message = appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }

    StorageVolumeStackAuditResult DriverClient::queryVolumeStackAudit(const std::wstring& volumePath, const unsigned long flags, const unsigned long maxRows, const unsigned long maxDepth) const
    {
        const KSWORD_ARK_STORAGE_AUDIT_REQUEST request = buildStorageRequest(volumePath, flags, maxRows, maxDepth);
        return queryStorageRows<StorageVolumeStackAuditResult, KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE, KSWORD_ARK_VOLUME_STACK_ROW>(*this, IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT, request, "IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT");
    }

    StorageBitlockerFveAuditResult DriverClient::queryBitlockerFveAudit(const std::wstring& volumePath, const unsigned long flags, const unsigned long maxRows, const unsigned long maxDepth) const
    {
        const KSWORD_ARK_STORAGE_AUDIT_REQUEST request = buildStorageRequest(volumePath, flags, maxRows, maxDepth);
        return queryStorageRows<StorageBitlockerFveAuditResult, KSWORD_ARK_QUERY_BITLOCKER_FVE_RESPONSE, KSWORD_ARK_BITLOCKER_FVE_ROW>(*this, IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT, request, "IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT");
    }

    StorageMountMgrMappingAuditResult DriverClient::queryMountMgrMappingAudit(const std::wstring& volumePath, const unsigned long flags, const unsigned long maxRows, const unsigned long maxDepth) const
    {
        const KSWORD_ARK_STORAGE_AUDIT_REQUEST request = buildStorageRequest(volumePath, flags, maxRows, maxDepth);
        return queryStorageRows<StorageMountMgrMappingAuditResult, KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_RESPONSE, KSWORD_ARK_MOUNTMGR_MAPPING_ROW>(*this, IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT, request, "IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT");
    }

    StorageFilesystemIntegrityAuditResult DriverClient::queryFilesystemIntegrityAudit(const std::wstring& volumePath, const unsigned long flags, const unsigned long maxRows, const unsigned long maxDepth) const
    {
        const KSWORD_ARK_STORAGE_AUDIT_REQUEST request = buildStorageRequest(volumePath, flags, maxRows, maxDepth);
        return queryStorageRows<StorageFilesystemIntegrityAuditResult, KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_RESPONSE, KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW>(*this, IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT, request, "IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT");
    }

    SecurityStatusAuditResult DriverClient::querySecurityStatus(const unsigned long flags) const
    {
        SecurityStatusAuditResult result{};
        KSWORD_ARK_QUERY_SECURITY_STATUS_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION;
        request.flags = flags;
        result.io = queryFixedAudit(*this, IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS, &request, result.response, "IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS");
        markUnsupportedIfNeeded(result, "IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS");
        result.io.ntStatus = result.response.queryStatus;
        return result;
    }


    DriverTrustViewAuditResult DriverClient::queryDriverTrustView(const unsigned long flags, const unsigned long maxEntries) const
    {
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW";
        DriverTrustViewAuditResult result{};
        KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION;
        request.flags = flags;
        request.maxEntries = maxEntries;
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_RESPONSE*>(responseBuffer.data());
        const std::size_t parsedCount = validateAuditRows(result.io, headerSize, sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY), sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY), response->entryCount, operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = static_cast<std::uint32_t>(response->queryStatus);
        result.fieldFlags = response->fieldFlags;
        result.sourceMask = response->sourceMask;
        result.totalCount = response->totalModuleCount;
        result.returnedCount = response->entryCount;
        result.entrySize = sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY);
        result.maxEntriesAccepted = response->maxEntriesAccepted;
        result.truncated = response->truncated;
        result.moduleQueryStatus = response->moduleQueryStatus;
        result.signingResolverStatus = response->signingResolverStatus;
        result.lastStatus = response->queryStatus;
        result.io.ntStatus = response->queryStatus;
        result.entries = parseVariableRows<KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY>(responseBuffer, headerSize, sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY), parsedCount);
        result.io.message = appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }

    HyperVSummaryAuditResult DriverClient::queryHyperVSummary() const
    {
        HyperVSummaryAuditResult result{};
        result.io = queryNoInputFixedAudit(*this, IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY, result.response, "IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY");
        markUnsupportedIfNeeded(result, "IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY");
        result.io.ntStatus = result.response.queryStatus;
        return result;
    }

    AppControlStatusAuditResult DriverClient::queryAppControlStatus() const
    {
        AppControlStatusAuditResult result{};
        result.io = queryNoInputFixedAudit(*this, IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS, result.response, "IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS");
        markUnsupportedIfNeeded(result, "IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS");
        result.io.ntStatus = result.response.queryStatus;
        return result;
    }

    Win32kProfileStatusResult DriverClient::queryWin32kProfileStatus(const unsigned long flags, const unsigned long sessionId, const unsigned long maxEntries) const
    {
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS";
        Win32kProfileStatusResult result{};
        KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(flags, sessionId, 0UL, 0UL, maxEntries);
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_SESSION_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE*>(responseBuffer.data());
        const std::size_t parsedCount = validateAuditRows(result.io, headerSize, response->entrySize, sizeof(KSWORD_ARK_WIN32K_SESSION_ENTRY), response->returnedCount, operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.lastStatus = response->lastStatus;
        result.capabilityMask = response->capabilityMask;
        result.missingCapabilityMask = response->missingCapabilityMask;
        result.userGetSiloGlobals = response->userGetSiloGlobals;
        result.win32k = response->win32k;
        result.win32kbase = response->win32kbase;
        result.win32kfull = response->win32kfull;
        result.fieldOffsets = response->fieldOffsets;
        result.io.ntStatus = response->lastStatus;
        result.entries = parseVariableRows<KSWORD_ARK_WIN32K_SESSION_ENTRY>(responseBuffer, headerSize, response->entrySize, parsedCount);
        result.io.message = appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }

    // queryWin32kRows 作用：
    // - 输入：Win32K 变长响应/行类型、IOCTL 和过滤参数；
    // - 处理：发送请求并解析 capability/offset/entries；
    // - 返回：具体 Win32K 结果类型。
    template <typename TResult, typename TResponse, typename TEntry>
    TResult queryWin32kRows(
        const DriverClient& client,
        const unsigned long ioctlCode,
        const KSWORD_ARK_WIN32K_QUERY_REQUEST& request,
        const char* const operationName)
    {
        TResult result{};
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = client.deviceIoControl(ioctlCode, const_cast<KSWORD_ARK_WIN32K_QUERY_REQUEST*>(&request), sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t headerSize = sizeof(TResponse) - sizeof(TEntry);
        const auto* response = reinterpret_cast<const TResponse*>(responseBuffer.data());
        const std::size_t parsedCount = validateAuditRows(result.io, headerSize, response->entrySize, sizeof(TEntry), response->returnedCount, operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.lastStatus = response->lastStatus;
        result.capabilityMask = response->capabilityMask;
        result.missingCapabilityMask = response->missingCapabilityMask;
        result.fieldOffsets = response->fieldOffsets;
        result.io.ntStatus = response->lastStatus;
        result.entries = parseVariableRows<TEntry>(responseBuffer, headerSize, response->entrySize, parsedCount);
        result.io.message = appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }

    Win32kWindowsResult DriverClient::queryWin32kWindows(const unsigned long flags, const unsigned long sessionId, const unsigned long processId, const unsigned long threadId, const unsigned long maxEntries) const
    {
        const KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(flags, sessionId, processId, threadId, maxEntries);
        return queryWin32kRows<Win32kWindowsResult, KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE, KSWORD_ARK_WIN32K_WINDOW_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS, request, "IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS");
    }

    Win32kGuiThreadsResult DriverClient::queryWin32kGuiThreads(const unsigned long flags, const unsigned long sessionId, const unsigned long processId, const unsigned long threadId, const unsigned long maxEntries) const
    {
        const KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(flags, sessionId, processId, threadId, maxEntries);
        return queryWin32kRows<Win32kGuiThreadsResult, KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE, KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS, request, "IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS");
    }

    Win32kHotkeysPdbResult DriverClient::queryWin32kHotkeysPdb(const unsigned long flags, const unsigned long sessionId, const unsigned long processId, const unsigned long threadId, const unsigned long maxEntries) const
    {
        const KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(flags, sessionId, processId, threadId, maxEntries);
        return queryWin32kRows<Win32kHotkeysPdbResult, KSWORD_ARK_WIN32K_HOTKEY_SNAPSHOT_RESPONSE, KSWORD_ARK_WIN32K_HOTKEY_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB, request, "IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB");
    }

    Win32kHooksPdbResult DriverClient::queryWin32kHooksPdb(const unsigned long flags, const unsigned long sessionId, const unsigned long processId, const unsigned long threadId, const unsigned long maxEntries) const
    {
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB";
        Win32kHooksPdbResult result{};
        const KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(flags, sessionId, processId, threadId, maxEntries);
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB,
            const_cast<KSWORD_ARK_WIN32K_QUERY_REQUEST*>(&request),
            sizeof(request),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE*>(responseBuffer.data());
        const std::size_t parsedCount = validateAuditRows(
            result.io,
            headerSize,
            response->entrySize,
            sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY),
            response->returnedCount,
            operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.lastStatus = response->lastStatus;
        result.capabilityMask = response->capabilityMask;
        result.missingCapabilityMask = response->missingCapabilityMask;
        result.fieldOffsets = response->fieldOffsets;
        result.layout = response->layout;
        result.discoveredChainCount = response->discoveredChainCount;
        result.visitedNodeCount = response->visitedNodeCount;
        result.readFailureCount = response->readFailureCount;
        result.corruptLinkCount = response->corruptLinkCount;
        result.duplicateCount = response->duplicateCount;
        result.win32kbaseTimeDateStamp = response->win32kbaseTimeDateStamp;
        result.win32kbaseImageSize = response->win32kbaseImageSize;
        result.win32kfullTimeDateStamp = response->win32kfullTimeDateStamp;
        result.win32kfullImageSize = response->win32kfullImageSize;
        result.detail = fixedAuditWideToString(response->detail, KSWORD_ARK_WIN32K_DETAIL_CHARS);
        result.io.ntStatus = response->lastStatus;
        result.unsupported = response->status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED ||
            static_cast<unsigned long>(response->lastStatus) == 0xC0000059UL;
        result.entries = parseVariableRows<KSWORD_ARK_WIN32K_HOOK_ENTRY>(
            responseBuffer,
            headerSize,
            response->entrySize,
            parsedCount);
        result.io.message = appendAuditSummary(
            operationName,
            result.totalCount,
            result.returnedCount,
            result.entries.size(),
            result.io.bytesReturned);
        return result;
    }

    Win32kTimersResult DriverClient::queryWin32kTimers(const unsigned long flags, const unsigned long sessionId, const unsigned long processId, const unsigned long threadId, const unsigned long maxEntries) const
    {
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS";
        Win32kTimersResult result{};
        const KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(flags, sessionId, processId, threadId, maxEntries);
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS,
            const_cast<KSWORD_ARK_WIN32K_QUERY_REQUEST*>(&request),
            sizeof(request),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_WIN32K_TIMER_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_TIMER_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_TIMER_SNAPSHOT_RESPONSE*>(responseBuffer.data());
        const std::size_t parsedCount = validateAuditRows(
            result.io,
            headerSize,
            response->entrySize,
            sizeof(KSWORD_ARK_WIN32K_TIMER_ENTRY),
            response->returnedCount,
            operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.lastStatus = response->lastStatus;
        result.capabilityMask = response->capabilityMask;
        result.missingCapabilityMask = response->missingCapabilityMask;
        result.timerHashTable = response->timerHashTable;
        result.visitedNodeCount = response->visitedNodeCount;
        result.readFailureCount = response->readFailureCount;
        result.corruptBucketCount = response->corruptBucketCount;
        result.duplicateCount = response->duplicateCount;
        result.win32kbaseTimeDateStamp = response->win32kbaseTimeDateStamp;
        result.win32kbaseImageSize = response->win32kbaseImageSize;
        result.win32kfullTimeDateStamp = response->win32kfullTimeDateStamp;
        result.win32kfullImageSize = response->win32kfullImageSize;
        result.layout = response->layout;
        result.detail = std::wstring(response->detail);
        result.io.ntStatus = response->lastStatus;
        result.unsupported = response->status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED ||
            static_cast<unsigned long>(response->lastStatus) == 0xC0000059UL;
        result.entries = parseVariableRows<KSWORD_ARK_WIN32K_TIMER_ENTRY>(
            responseBuffer,
            headerSize,
            response->entrySize,
            parsedCount);
        result.io.message = appendAuditSummary(
            operationName,
            result.totalCount,
            result.returnedCount,
            result.entries.size(),
            result.io.bytesReturned);
        return result;
    }

    Win32kEventHooksResult DriverClient::queryWin32kEventHooks(const unsigned long flags, const unsigned long sessionId, const unsigned long processId, const unsigned long threadId, const unsigned long maxEntries) const
    {
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS";
        Win32kEventHooksResult result{};
        const KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(flags, sessionId, processId, threadId, maxEntries);
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS,
            const_cast<KSWORD_ARK_WIN32K_QUERY_REQUEST*>(&request),
            sizeof(request),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_EVENT_HOOK_SNAPSHOT_RESPONSE*>(responseBuffer.data());
        const std::size_t parsedCount = validateAuditRows(
            result.io,
            headerSize,
            response->entrySize,
            sizeof(KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY),
            response->returnedCount,
            operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.lastStatus = response->lastStatus;
        result.capabilityMask = response->capabilityMask;
        result.missingCapabilityMask = response->missingCapabilityMask;
        result.hookListPointer = response->hookListPointer;
        result.hookListHead = response->hookListHead;
        result.visitedNodeCount = response->visitedNodeCount;
        result.readFailureCount = response->readFailureCount;
        result.corruptLinkCount = response->corruptLinkCount;
        result.duplicateCount = response->duplicateCount;
        result.win32kbaseTimeDateStamp = response->win32kbaseTimeDateStamp;
        result.win32kbaseImageSize = response->win32kbaseImageSize;
        result.win32kfullTimeDateStamp = response->win32kfullTimeDateStamp;
        result.win32kfullImageSize = response->win32kfullImageSize;
        result.layout = response->layout;
        result.detail = std::wstring(response->detail);
        result.io.ntStatus = response->lastStatus;
        result.unsupported = response->status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED ||
            static_cast<unsigned long>(response->lastStatus) == 0xC0000059UL;
        result.entries = parseVariableRows<KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY>(
            responseBuffer,
            headerSize,
            response->entrySize,
            parsedCount);
        result.io.message = appendAuditSummary(
            operationName,
            result.totalCount,
            result.returnedCount,
            result.entries.size(),
            result.io.bytesReturned);
        return result;
    }

    Win32kWindowRuntimeDetailResult DriverClient::queryWin32kWindowDetail(
        const std::uint64_t hwnd,
        const unsigned long processId,
        const unsigned long threadId,
        const unsigned long flags) const
    {
        // 输入：HWND 以及可选 PID/TID 约束，flags 控制是否返回诊断文本。
        // 处理：调用 win32k 单窗口详情 IOCTL，R0 当前只做 profile/capability readiness。
        // 返回：固定响应；unsupported 表示旧驱动缺入口或 R0 明确未实现 tagWND 读取。
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL";
        Win32kWindowRuntimeDetailResult result{};
        KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST request{};
        request.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
        request.flags = flags;
        request.processId = processId;
        request.threadId = threadId;
        request.hwnd = hwnd;

        result.io = queryFixedAudit(
            *this,
            IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL,
            &request,
            result.response,
            operationName);
        markUnsupportedIfNeeded(result, operationName);
        result.io.ntStatus = result.response.lastStatus;
        if (result.io.ok)
        {
            result.unsupported = result.response.status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED ||
                static_cast<unsigned long>(result.response.lastStatus) == 0xC00000BBUL ||
                static_cast<unsigned long>(result.response.lastStatus) == 0xC0000010UL;
            std::ostringstream stream;
            stream << operationName
                << " status=" << result.response.status
                << ", fields=0x" << std::hex << std::uppercase << result.response.fieldFlags
                << ", missingCaps=0x" << result.response.missingCapabilityMask
                << ", lastStatus=0x" << static_cast<unsigned long>(result.response.lastStatus)
                << std::dec << ", bytesReturned=" << result.io.bytesReturned;
            result.io.message = stream.str();
        }
        return result;
    }


    // queryDeviceAuditRows 作用：封装 Device/Input/USB/GPU 四类统一设备审计 IOCTL。
    DeviceAuditResult queryDeviceAuditRows(
        const DriverClient& client,
        const unsigned long ioctlCode,
        const unsigned long profileFlags,
        const std::wstring& targetName,
        const unsigned long maxRows,
        const unsigned long maxAttachedDepth,
        const char* const operationName)
    {
        DeviceAuditResult result{};
        KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION;
        request.profileFlags = profileFlags;
        request.maxRows = maxRows;
        request.maxAttachedDepth = maxAttachedDepth;
        copyAuditWideToFixed(request.targetName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS, targetName);
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = client.deviceIoControl(ioctlCode, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE) - sizeof(KSWORD_ARK_DEVICE_AUDIT_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE*>(responseBuffer.data());
        const std::size_t parsedCount = validateAuditRows(result.io, headerSize, response->entrySize, sizeof(KSWORD_ARK_DEVICE_AUDIT_ENTRY), response->returnedCount, operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->queryStatus;
        result.profileFlags = response->profileFlags;
        result.responseFlags = response->responseFlags;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.targetCount = response->targetCount;
        result.driverCount = response->driverCount;
        result.deviceCount = response->deviceCount;
        result.lastStatus = response->lastStatus;
        result.io.ntStatus = response->lastStatus;
        result.entries = parseVariableRows<KSWORD_ARK_DEVICE_AUDIT_ENTRY>(responseBuffer, headerSize, response->entrySize, parsedCount);
        result.io.message = appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }

    DeviceAuditResult DriverClient::queryDeviceStackAudit(const std::wstring& targetName, const unsigned long maxRows, const unsigned long maxAttachedDepth) const
    {
        return queryDeviceAuditRows(*this, IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_DEVICE_STACK, targetName, maxRows, maxAttachedDepth, "IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT");
    }

    DeviceAuditResult DriverClient::queryInputStackAudit(const std::wstring& targetName, const unsigned long maxRows, const unsigned long maxAttachedDepth) const
    {
        return queryDeviceAuditRows(*this, IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_INPUT_STACK, targetName, maxRows, maxAttachedDepth, "IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT");
    }

    DeviceAuditResult DriverClient::queryUsbTopologyAudit(const std::wstring& targetName, const unsigned long maxRows, const unsigned long maxAttachedDepth) const
    {
        return queryDeviceAuditRows(*this, IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_USB_TOPOLOGY, targetName, maxRows, maxAttachedDepth, "IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT");
    }

    DeviceAuditResult DriverClient::queryGpuDisplayWatchdogAudit(const std::wstring& targetName, const unsigned long maxRows, const unsigned long maxAttachedDepth) const
    {
        return queryDeviceAuditRows(*this, IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_GPU_DISPLAY_WATCHDOG, targetName, maxRows, maxAttachedDepth, "IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT");
    }

    PlatformAuditResult DriverClient::queryPlatformAudit(const unsigned long scopeMask, const unsigned long maxRows) const
    {
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT";
        constexpr std::size_t headerSize =
            offsetof(KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE, entries);
        constexpr std::uint32_t knownResponseFlags =
            KSWORD_ARK_PLATFORM_RESPONSE_TRUNCATED |
            KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL |
            KSWORD_ARK_PLATFORM_RESPONSE_FAIL_CLOSED |
            KSWORD_ARK_PLATFORM_RESPONSE_NO_PDB;
        constexpr std::uint32_t knownFieldFlags =
            KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_ORIGINAL_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_TABLE_ADDRESS |
            KSWORD_ARK_PLATFORM_FIELD_MODULE |
            KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_FORMAT |
            KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT |
            KSWORD_ARK_PLATFORM_FIELD_EXECUTABLE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_READ_ONLY_RANGE |
            KSWORD_ARK_PLATFORM_FIELD_DETAIL_ARGS |
            KSWORD_ARK_PLATFORM_FIELD_BASELINE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED;
        constexpr std::uint32_t expectedSignaturePolicyFlags =
            KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT |
            KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_FORMAT |
            KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED;
        PlatformAuditResult result{};
        KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION;
        request.scopeMask = scopeMask;
        request.maxRows = maxRows;
        request.flags = 0UL;
        request.reserved0 = 0UL;

        constexpr std::size_t responseBufferBytes =
            headerSize +
            (static_cast<std::size_t>(KSWORD_ARK_PLATFORM_HARD_MAX_ROWS) *
             sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY));
        static_assert(
            responseBufferBytes <= std::numeric_limits<unsigned long>::max(),
            "platform audit buffer must fit DeviceIoControl");
        std::vector<std::uint8_t> responseBuffer(responseBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT,
            &request,
            sizeof(request),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        const auto failProtocol = [&result, operationName](const std::string& reason)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = std::string(operationName) + " invalid response: " + reason;
            result.entries.clear();
        };
        if (result.io.bytesReturned < headerSize ||
            result.io.bytesReturned > responseBuffer.size())
        {
            failProtocol("header/bytesReturned out of range");
            return result;
        }

        KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE response{};
        std::memcpy(&response, responseBuffer.data(), headerSize);
        const unsigned long expectedScope =
            scopeMask == 0UL ? KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL : scopeMask;
        const unsigned long requestedRows =
            maxRows == 0UL
                ? KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS
                : std::min(maxRows, KSWORD_ARK_PLATFORM_HARD_MAX_ROWS);
        const auto validStatus = [](const unsigned long value)
        {
            return value <= KSWORD_ARK_PLATFORM_AUDIT_STATUS_BUFFER_TRUNCATED;
        };
        const auto validSignature = [](const unsigned long value)
        {
            return value == KSWORD_ARK_PLATFORM_SIGNATURE_NONE ||
                value == KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V6 ||
                value == KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V4_V5 ||
                (value >= KSWORD_ARK_PLATFORM_SIGNATURE_WDF_BINDING_TABLE &&
                 value <= KSWORD_ARK_PLATFORM_SIGNATURE_MAX);
        };
        const bool headerValid =
            response.size == headerSize &&
            response.version == KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION &&
            response.reserved0 == 0UL &&
            response.scopeMask == expectedScope &&
            validStatus(response.queryStatus) &&
            (response.responseFlags & ~knownResponseFlags) == 0UL &&
            (response.responseFlags & KSWORD_ARK_PLATFORM_RESPONSE_NO_PDB) != 0UL &&
            response.totalCount >= response.returnedCount &&
            response.totalCount <= KSWORD_ARK_PLATFORM_HARD_MAX_ROWS &&
            response.returnedCount <= requestedRows &&
            response.returnedCount <= KSWORD_ARK_PLATFORM_HARD_MAX_ROWS &&
            response.entrySize == sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY) &&
            response.signaturePolicyFlags == expectedSignaturePolicyFlags &&
            (((response.responseFlags & KSWORD_ARK_PLATFORM_RESPONSE_TRUNCATED) != 0UL) ==
             (response.returnedCount < response.totalCount));
        if (!headerValid)
        {
            failProtocol("header fields rejected");
            return result;
        }
        if (response.returnedCount >
            (std::numeric_limits<std::size_t>::max() - headerSize) /
                sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY))
        {
            failProtocol("row byte count overflow");
            return result;
        }
        const std::size_t requiredBytes =
            headerSize +
            (static_cast<std::size_t>(response.returnedCount) *
             sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY));
        if (requiredBytes != result.io.bytesReturned)
        {
            failProtocol("returnedCount/bytesReturned mismatch");
            return result;
        }

        result.entries.reserve(response.returnedCount);
        for (std::size_t index = 0U; index < response.returnedCount; ++index)
        {
            KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry{};
            const std::size_t offset =
                headerSize + (index * sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY));
            std::memcpy(&entry, responseBuffer.data() + offset, sizeof(entry));

            const bool scopeValid =
                entry.scope != 0UL &&
                (entry.scope & ~KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL) == 0UL &&
                (entry.scope & ~response.scopeMask) == 0UL;
            const bool rowKindValid =
                entry.rowKind >= KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE &&
                entry.rowKind <= KSWORD_ARK_PLATFORM_AUDIT_ROW_DIAGNOSTIC;
            const bool hookValid =
                entry.hookStatus == KSWORD_ARK_PLATFORM_HOOK_UNKNOWN ||
                entry.hookStatus == KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS ||
                entry.hookStatus == KSWORD_ARK_PLATFORM_HOOK_UNSUPPORTED;
            const bool confidenceValid =
                entry.confidence == KSWORD_ARK_PLATFORM_CONFIDENCE_NONE ||
                entry.confidence == KSWORD_ARK_PLATFORM_CONFIDENCE_LOW ||
                entry.confidence == KSWORD_ARK_PLATFORM_CONFIDENCE_MEDIUM ||
                entry.confidence == KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
            const bool stringsValid =
                std::find(
                    std::begin(entry.name),
                    std::end(entry.name),
                    L'\0') != std::end(entry.name) &&
                std::find(
                    std::begin(entry.modulePath),
                    std::end(entry.modulePath),
                    L'\0') != std::end(entry.modulePath);
            const bool entryValid =
                entry.size == sizeof(entry) &&
                entry.reserved0 == 0UL &&
                entry.reserved1 == 0UL &&
                scopeValid &&
                rowKindValid &&
                validStatus(entry.status) &&
                hookValid &&
                confidenceValid &&
                (entry.fieldFlags & ~knownFieldFlags) == 0UL &&
                validSignature(entry.signatureId) &&
                entry.slotKind <= KSWORD_ARK_PLATFORM_SLOT_DUMMY &&
                entry.ownerPolicy <= KSWORD_ARK_PLATFORM_OWNER_KSWORD &&
                entry.originalAddressSource ==
                    KSWORD_ARK_PLATFORM_ORIGINAL_SOURCE_NONE &&
                entry.detailCode <=
                    KSWORD_ARK_PLATFORM_DETAIL_SUBCOMPONENT_VALIDATED &&
                entry.prologueSignatureId <= 8UL &&
                stringsValid &&
                (entry.fieldFlags &
                 (KSWORD_ARK_PLATFORM_FIELD_ORIGINAL_ADDRESS |
                  KSWORD_ARK_PLATFORM_FIELD_BASELINE_VALIDATED)) == 0UL &&
                entry.originalAddress == 0ULL &&
                (((entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_DETAIL_ARGS) != 0UL) ==
                 (entry.detailCode != KSWORD_ARK_PLATFORM_DETAIL_NONE)) &&
                (((entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS) != 0UL) ==
                 (entry.liveAddress != 0ULL)) &&
                (((entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_TABLE_ADDRESS) != 0UL) ==
                 (entry.tableAddress != 0ULL)) &&
                (((entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_MODULE) != 0UL) ==
                 (entry.moduleBase != 0ULL)) &&
                (((entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_MODULE) != 0UL) ==
                 (entry.moduleSize != 0UL)) &&
                (((entry.fieldFlags & KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_FORMAT) != 0UL) ==
                 (entry.prologueSignatureId != 0UL));
            if (!entryValid)
            {
                failProtocol("entry[" + std::to_string(index) + "] rejected");
                return result;
            }
            result.entries.push_back(entry);
        }

        result.version = response.version;
        result.status = response.queryStatus;
        result.scopeMask = response.scopeMask;
        result.responseFlags = response.responseFlags;
        result.totalCount = response.totalCount;
        result.returnedCount = response.returnedCount;
        result.entrySize = response.entrySize;
        result.buildNumber = response.buildNumber;
        result.signaturePolicyFlags = response.signaturePolicyFlags;
        result.lastStatus = response.lastStatus;
        result.io.ntStatus = response.lastStatus;
        result.io.message = appendAuditSummary(
            operationName,
            result.totalCount,
            result.returnedCount,
            result.entries.size(),
            result.io.bytesReturned);
        return result;
    }

    PlatformAuditControlResult DriverClient::editPlatformAuditEntry(
        const unsigned long scope,
        const unsigned long entryIndex,
        const std::uint64_t tableAddress,
        const std::uint64_t expectedValue,
        const std::uint64_t newValue,
        const bool uiConfirmed) const
    {
        constexpr const char* operationName =
            "IOCTL_KSWORD_ARK_CONTROL_PLATFORM_AUDIT";
        constexpr std::uint32_t knownResponseFlags =
            KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_CHANGED |
            KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_TARGET_EXECUTABLE |
            KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_TABLE_REVALIDATED |
            KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_ALIAS_WRITE;
        PlatformAuditControlResult result{};
        KSWORD_ARK_CONTROL_PLATFORM_AUDIT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION;
        request.scope = scope;
        request.entryIndex = entryIndex;
        request.flags = uiConfirmed
            ? KSWORD_ARK_PLATFORM_CONTROL_FLAG_UI_CONFIRMED
            : 0UL;
        request.confirmationToken = uiConfirmed
            ? KSWORD_ARK_PLATFORM_CONTROL_CONFIRMATION_TOKEN
            : 0UL;
        request.tableAddress = tableAddress;
        request.expectedValue = expectedValue;
        request.newValue = newValue;

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_PLATFORM_AUDIT,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        // WDF_CALLBACKS 不在此列：那些行是本驱动 .text 内的编译期地址，R0 没有
        // 对应的可写槽，请求会被 resolve 阶段拒绝。
        const bool validScope =
            result.response.scope ==
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH ||
            result.response.scope ==
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE ||
            result.response.scope ==
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI ||
            result.response.scope ==
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS ||
            result.response.scope ==
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS;
        const bool responseValid =
            result.io.bytesReturned == sizeof(result.response) &&
            result.response.size == sizeof(result.response) &&
            result.response.version ==
                KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION &&
            result.response.status <=
                KSWORD_ARK_PLATFORM_CONTROL_STATUS_SAFETY_DENIED &&
            validScope &&
            result.response.scope == scope &&
            result.response.entryIndex == entryIndex &&
            result.response.reserved0 == 0UL &&
            (result.response.responseFlags & ~knownResponseFlags) == 0UL &&
            result.response.requestedValue == newValue &&
            (((result.response.responseFlags &
               KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_CHANGED) != 0UL) ==
             (result.response.status ==
                  KSWORD_ARK_PLATFORM_CONTROL_STATUS_OK &&
              expectedValue != newValue));
        if (!responseValid)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message =
                std::string(operationName) + " invalid response";
            std::memset(&result.response, 0, sizeof(result.response));
            return result;
        }

        result.io.ntStatus = result.response.lastStatus;
        result.io.message = std::string(operationName) +
            " status=" + std::to_string(result.response.status) +
            ", ntstatus=" +
            std::to_string(
                static_cast<std::uint32_t>(result.response.lastStatus));
        return result;
    }

    I8042AuditResult DriverClient::queryI8042Audit(const unsigned long maxRows) const
    {
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT";
        constexpr std::size_t headerSize =
            offsetof(KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE, entries);
        constexpr std::uint32_t knownResponseFlags =
            KSWORD_ARK_I8042_RESPONSE_TRUNCATED |
            KSWORD_ARK_I8042_RESPONSE_PARTIAL |
            KSWORD_ARK_I8042_RESPONSE_FAIL_CLOSED |
            KSWORD_ARK_I8042_RESPONSE_IMAGE_VALIDATED |
            KSWORD_ARK_I8042_RESPONSE_DESCRIPTOR_VALIDATED;
        constexpr std::uint32_t knownFieldFlags =
            KSWORD_ARK_I8042_FIELD_DEVICE_OBJECT |
            KSWORD_ARK_I8042_FIELD_PNP_ID |
            KSWORD_ARK_I8042_FIELD_CLASS_DEVICE_OBJECT |
            KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS |
            KSWORD_ARK_I8042_FIELD_CONTEXT_ADDRESS |
            KSWORD_ARK_I8042_FIELD_OWNER_MODULE |
            KSWORD_ARK_I8042_FIELD_EXECUTABLE |
            KSWORD_ARK_I8042_FIELD_SAME_DEVICE_STACK |
            KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED |
            KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED |
            KSWORD_ARK_I8042_FIELD_DETAIL_ARGS;
        constexpr std::uint8_t expectedPdbGuid[KSWORD_ARK_I8042_PDB_GUID_BYTES] = {
            0x63U, 0x4CU, 0x70U, 0xECU,
            0x2FU, 0x3FU, 0xE7U, 0xA4U,
            0xBEU, 0xF7U, 0x86U, 0xF7U,
            0x55U, 0xDCU, 0xB5U, 0x2CU
        };
        I8042AuditResult result{};
        KSWORD_ARK_QUERY_I8042_AUDIT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_I8042_AUDIT_PROTOCOL_VERSION;
        request.maxRows = maxRows;
        request.flags = 0UL;
        request.reserved0 = 0UL;
        request.reserved1 = 0UL;

        constexpr std::size_t responseBufferBytes =
            headerSize +
            (static_cast<std::size_t>(KSWORD_ARK_I8042_HARD_MAX_ROWS) *
             sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY));
        static_assert(
            responseBufferBytes <= std::numeric_limits<unsigned long>::max(),
            "i8042 audit buffer must fit DeviceIoControl");
        std::vector<std::uint8_t> responseBuffer(responseBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT,
            &request,
            sizeof(request),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        const auto failProtocol = [&result, operationName](const std::string& reason)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = std::string(operationName) +
                " invalid response: " + reason;
            result.entries.clear();
        };
        if (result.io.bytesReturned < headerSize ||
            result.io.bytesReturned > responseBuffer.size())
        {
            failProtocol("header/bytesReturned out of range");
            return result;
        }

        KSWORD_ARK_QUERY_I8042_AUDIT_RESPONSE response{};
        std::memcpy(&response, responseBuffer.data(), headerSize);
        const unsigned long requestedRows =
            maxRows == 0UL
                ? KSWORD_ARK_I8042_DEFAULT_MAX_ROWS
                : std::min(maxRows, KSWORD_ARK_I8042_HARD_MAX_ROWS);
        const auto validStatus = [](const unsigned long value)
        {
            return value <= KSWORD_ARK_I8042_AUDIT_STATUS_BUFFER_TRUNCATED;
        };
        const bool imageValidated =
            (response.responseFlags &
             KSWORD_ARK_I8042_RESPONSE_IMAGE_VALIDATED) != 0UL;
        const bool descriptorValidated =
            (response.responseFlags &
             KSWORD_ARK_I8042_RESPONSE_DESCRIPTOR_VALIDATED) != 0UL;
        const bool truncated =
            (response.responseFlags &
             KSWORD_ARK_I8042_RESPONSE_TRUNCATED) != 0UL;
        const bool partial =
            (response.responseFlags &
             KSWORD_ARK_I8042_RESPONSE_PARTIAL) != 0UL;
        const bool failClosed =
            (response.responseFlags &
             KSWORD_ARK_I8042_RESPONSE_FAIL_CLOSED) != 0UL;
        const bool exactIdentity =
            response.imageTimeDateStamp == 0xFD7548DDUL &&
            response.imageSize == 0x00026000UL &&
            response.imageChecksum == 0x0002637EUL &&
            response.pdbAge == 1UL &&
            std::equal(
                std::begin(response.pdbGuid),
                std::end(response.pdbGuid),
                std::begin(expectedPdbGuid));
        const bool headerValid =
            response.size == headerSize &&
            response.version == KSWORD_ARK_I8042_AUDIT_PROTOCOL_VERSION &&
            response.reserved0 == 0UL &&
            validStatus(response.queryStatus) &&
            (response.responseFlags & ~knownResponseFlags) == 0UL &&
            response.totalCount >= response.returnedCount &&
            response.returnedCount <= requestedRows &&
            response.returnedCount <= KSWORD_ARK_I8042_HARD_MAX_ROWS &&
            (truncated
                ? response.totalCount > response.returnedCount
                : response.totalCount == response.returnedCount) &&
            response.entrySize == sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY) &&
            response.descriptorId ==
                KSWORD_ARK_I8042_DESCRIPTOR_WIN11_26100_7934 &&
            (partial ==
                (response.queryStatus !=
                 KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE)) &&
            (response.queryStatus !=
                    KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE ||
             response.totalCount != 0UL) &&
            (truncated ==
                (response.queryStatus ==
                 KSWORD_ARK_I8042_AUDIT_STATUS_BUFFER_TRUNCATED)) &&
            (!failClosed || (partial && !descriptorValidated)) &&
            response.queryStatus !=
                KSWORD_ARK_I8042_AUDIT_STATUS_SIGNATURE_MISMATCH &&
            (!imageValidated || (response.imageBase != 0ULL && exactIdentity)) &&
            (!descriptorValidated || imageValidated);
        if (!headerValid)
        {
            failProtocol("header fields rejected");
            return result;
        }
        if (response.returnedCount >
            (std::numeric_limits<std::size_t>::max() - headerSize) /
                sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY))
        {
            failProtocol("row byte count overflow");
            return result;
        }
        const std::size_t requiredBytes =
            headerSize +
            (static_cast<std::size_t>(response.returnedCount) *
             sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY));
        if (requiredBytes != result.io.bytesReturned)
        {
            failProtocol("returnedCount/bytesReturned mismatch");
            return result;
        }

        result.entries.reserve(response.returnedCount);
        for (std::size_t index = 0U; index < response.returnedCount; ++index)
        {
            KSWORD_ARK_I8042_AUDIT_ENTRY entry{};
            const std::size_t offset =
                headerSize + (index * sizeof(KSWORD_ARK_I8042_AUDIT_ENTRY));
            std::memcpy(
                &entry,
                responseBuffer.data() + offset,
                sizeof(entry));

            const bool stringsValid =
                std::find(
                    std::begin(entry.pnpId),
                    std::end(entry.pnpId),
                    L'\0') != std::end(entry.pnpId) &&
                std::find(
                    std::begin(entry.ownerModulePath),
                    std::end(entry.ownerModulePath),
                    L'\0') != std::end(entry.ownerModulePath);
            const bool pnpPresent =
                entry.pnpId[0] != L'\0';
            const bool ownerPathPresent =
                entry.ownerModulePath[0] != L'\0';
            const bool pnpFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_PNP_ID) != 0UL;
            const bool ownerFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_OWNER_MODULE) != 0UL;
            const bool callbackFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS) != 0UL;
            const bool classDeviceFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_CLASS_DEVICE_OBJECT) != 0UL;
            const bool executableFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_EXECUTABLE) != 0UL;
            const bool sameStackFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_SAME_DEVICE_STACK) != 0UL;
            const bool entryImageFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED) != 0UL;
            const bool entryDescriptorFlag =
                (entry.fieldFlags &
                 KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED) != 0UL;
            const bool endpointMatchesDevice =
                (entry.deviceKind == KSWORD_ARK_I8042_DEVICE_KEYBOARD &&
                 entry.endpointKind >=
                    KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_CLASS_SERVICE &&
                 entry.endpointKind <=
                    KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_ISR) ||
                (entry.deviceKind == KSWORD_ARK_I8042_DEVICE_MOUSE &&
                 entry.endpointKind >=
                    KSWORD_ARK_I8042_ENDPOINT_MOUSE_CLASS_SERVICE &&
                 entry.endpointKind <=
                    KSWORD_ARK_I8042_ENDPOINT_MOUSE_ISR);
            const bool ownerRangeValid =
                !ownerFlag ||
                (callbackFlag &&
                 entry.moduleBase != 0ULL &&
                 entry.moduleSize != 0UL &&
                 entry.callbackAddress >= entry.moduleBase &&
                 entry.callbackAddress - entry.moduleBase <
                    entry.moduleSize);
            const std::uint32_t deviceAllowedFields =
                KSWORD_ARK_I8042_FIELD_DEVICE_OBJECT |
                KSWORD_ARK_I8042_FIELD_PNP_ID |
                KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED |
                KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED |
                KSWORD_ARK_I8042_FIELD_DETAIL_ARGS;
            const bool availableDevice =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_AVAILABLE &&
                entry.deviceKind != KSWORD_ARK_I8042_DEVICE_UNKNOWN &&
                (entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DESCRIPTOR_VALIDATED ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_GENERIC_DEVICE_AVAILABLE) &&
                entry.lastStatus == 0L;
            const bool partialDevice =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_UNKNOWN &&
                entry.deviceKind == KSWORD_ARK_I8042_DEVICE_UNKNOWN &&
                entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_PNP_CLASS_UNKNOWN &&
                entry.lastStatus != 0L;
            const bool failedDevice =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_UNKNOWN &&
                entry.deviceKind == KSWORD_ARK_I8042_DEVICE_UNKNOWN &&
                entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DRIVER_LAYOUT_MISMATCH &&
                entry.lastStatus != 0L;
            const bool deviceShape =
                entry.rowKind != KSWORD_ARK_I8042_AUDIT_ROW_DEVICE ||
                (entry.endpointKind == KSWORD_ARK_I8042_ENDPOINT_NONE &&
                 (entry.fieldFlags & ~deviceAllowedFields) == 0UL &&
                 (availableDevice || partialDevice || failedDevice) &&
                 (entry.detailCode !=
                        KSWORD_ARK_I8042_DETAIL_DESCRIPTOR_VALIDATED ||
                  (entryImageFlag && entryDescriptorFlag)) &&
                 (entry.detailCode !=
                        KSWORD_ARK_I8042_DETAIL_GENERIC_DEVICE_AVAILABLE ||
                  !entryDescriptorFlag));
            const bool availableEndpoint =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_AVAILABLE &&
                entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_ENDPOINT_AVAILABLE &&
                entry.lastStatus == 0L &&
                callbackFlag &&
                classDeviceFlag &&
                ownerFlag &&
                executableFlag &&
                sameStackFlag;
            const bool nullEndpoint =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_UNAVAILABLE &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_UNKNOWN &&
                entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_ENDPOINT_NULL &&
                entry.lastStatus == 0L &&
                !callbackFlag &&
                !ownerFlag &&
                !executableFlag &&
                !sameStackFlag;
            const bool suspiciousEndpoint =
                entry.status ==
                    KSWORD_ARK_I8042_AUDIT_STATUS_SIGNATURE_MISMATCH &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_SUSPICIOUS &&
                entry.lastStatus != 0L &&
                callbackFlag &&
                (entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_OWNER_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_NON_EXECUTABLE ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_CLASS_DO_OUTSIDE_STACK);
            const bool endpointShape =
                entry.rowKind != KSWORD_ARK_I8042_AUDIT_ROW_ENDPOINT ||
                (endpointMatchesDevice &&
                 entryImageFlag &&
                 entryDescriptorFlag &&
                 (availableEndpoint ||
                  nullEndpoint ||
                  suspiciousEndpoint));
            const bool unavailableDiagnostic =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_UNAVAILABLE &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_UNKNOWN &&
                entry.detailCode == KSWORD_ARK_I8042_DETAIL_NO_DEVICES;
            const bool unsupportedDiagnostic =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_UNSUPPORTED &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_UNSUPPORTED &&
                (entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_MODULE_NOT_FOUND ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DRIVER_NOT_FOUND ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_IMAGE_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_RSDS_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_OPCODE_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DRIVER_LAYOUT_MISMATCH);
            const bool partialDiagnostic =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_PARTIAL &&
                entry.verdict == KSWORD_ARK_I8042_VERDICT_UNKNOWN &&
                (entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_MODULE_NOT_FOUND ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_IMAGE_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_RSDS_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_OPCODE_MISMATCH ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DRIVER_LAYOUT_MISMATCH);
            const bool failedDiagnostic =
                entry.status == KSWORD_ARK_I8042_AUDIT_STATUS_QUERY_FAILED &&
                (entry.verdict == KSWORD_ARK_I8042_VERDICT_UNKNOWN ||
                 (failClosed &&
                  entry.verdict ==
                    KSWORD_ARK_I8042_VERDICT_UNSUPPORTED)) &&
                (entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_MODULE_NOT_FOUND ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DRIVER_NOT_FOUND ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_DEVICE_ENUM_FAILED ||
                 entry.detailCode ==
                    KSWORD_ARK_I8042_DETAIL_EXTENSION_READ_FAILED);
            const bool diagnosticShape =
                entry.rowKind !=
                    KSWORD_ARK_I8042_AUDIT_ROW_DIAGNOSTIC ||
                (entry.deviceKind == KSWORD_ARK_I8042_DEVICE_UNKNOWN &&
                 entry.endpointKind == KSWORD_ARK_I8042_ENDPOINT_NONE &&
                 entry.fieldFlags ==
                    KSWORD_ARK_I8042_FIELD_DETAIL_ARGS &&
                 entry.lastStatus != 0L &&
                 (unavailableDiagnostic ||
                  unsupportedDiagnostic ||
                  partialDiagnostic ||
                  failedDiagnostic));
            const bool rowShapeValid =
                (entry.rowKind == KSWORD_ARK_I8042_AUDIT_ROW_DEVICE &&
                 entry.endpointKind == KSWORD_ARK_I8042_ENDPOINT_NONE) ||
                (entry.rowKind == KSWORD_ARK_I8042_AUDIT_ROW_ENDPOINT &&
                 entry.deviceKind != KSWORD_ARK_I8042_DEVICE_UNKNOWN &&
                 entry.endpointKind >=
                    KSWORD_ARK_I8042_ENDPOINT_KEYBOARD_CLASS_SERVICE &&
                 entry.endpointKind <= KSWORD_ARK_I8042_ENDPOINT_MOUSE_ISR) ||
                (entry.rowKind == KSWORD_ARK_I8042_AUDIT_ROW_DIAGNOSTIC &&
                 entry.endpointKind == KSWORD_ARK_I8042_ENDPOINT_NONE);
            const bool entryValid =
                entry.size == sizeof(entry) &&
                entry.reserved0 == 0UL &&
                entry.reserved1 == 0UL &&
                rowShapeValid &&
                entry.deviceKind <= KSWORD_ARK_I8042_DEVICE_MOUSE &&
                validStatus(entry.status) &&
                entry.verdict <= KSWORD_ARK_I8042_VERDICT_UNSUPPORTED &&
                (entry.fieldFlags & ~knownFieldFlags) == 0UL &&
                entry.detailCode <=
                    KSWORD_ARK_I8042_DETAIL_GENERIC_DEVICE_AVAILABLE &&
                stringsValid &&
                pnpFlag == pnpPresent &&
                ownerFlag == ownerPathPresent &&
                ownerRangeValid &&
                deviceShape &&
                endpointShape &&
                diagnosticShape &&
                (((entry.fieldFlags &
                   KSWORD_ARK_I8042_FIELD_DETAIL_ARGS) != 0UL) ==
                 (entry.detailCode != KSWORD_ARK_I8042_DETAIL_NONE)) &&
                (((entry.fieldFlags &
                   KSWORD_ARK_I8042_FIELD_DEVICE_OBJECT) != 0UL) ==
                 (entry.deviceObject != 0ULL)) &&
                (((entry.fieldFlags &
                   KSWORD_ARK_I8042_FIELD_CLASS_DEVICE_OBJECT) != 0UL) ==
                 (entry.classDeviceObject != 0ULL)) &&
                (((entry.fieldFlags &
                   KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS) != 0UL) ==
                 (entry.callbackAddress != 0ULL)) &&
                (((entry.fieldFlags &
                   KSWORD_ARK_I8042_FIELD_CONTEXT_ADDRESS) != 0UL) ==
                 (entry.contextAddress != 0ULL)) &&
                (((entry.fieldFlags &
                   KSWORD_ARK_I8042_FIELD_OWNER_MODULE) != 0UL) ==
                 (entry.moduleBase != 0ULL && entry.moduleSize != 0UL)) &&
                ((entry.fieldFlags &
                  KSWORD_ARK_I8042_FIELD_EXECUTABLE) == 0UL ||
                 (entry.fieldFlags &
                  (KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS |
                   KSWORD_ARK_I8042_FIELD_OWNER_MODULE)) ==
                    (KSWORD_ARK_I8042_FIELD_CALLBACK_ADDRESS |
                     KSWORD_ARK_I8042_FIELD_OWNER_MODULE)) &&
                ((entry.fieldFlags &
                  KSWORD_ARK_I8042_FIELD_SAME_DEVICE_STACK) == 0UL ||
                 (entry.fieldFlags &
                  KSWORD_ARK_I8042_FIELD_CLASS_DEVICE_OBJECT) != 0UL) &&
                ((entry.fieldFlags &
                  KSWORD_ARK_I8042_FIELD_IMAGE_VALIDATED) == 0UL ||
                 imageValidated) &&
                ((entry.fieldFlags &
                  KSWORD_ARK_I8042_FIELD_DESCRIPTOR_VALIDATED) == 0UL ||
                 descriptorValidated);
            if (!entryValid)
            {
                failProtocol(
                    "entry[" + std::to_string(index) + "] rejected");
                return result;
            }
            result.entries.push_back(entry);
        }

        const bool aggregateValid =
            (response.queryStatus != KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE ||
             std::all_of(
                 result.entries.begin(),
                 result.entries.end(),
                 [](const KSWORD_ARK_I8042_AUDIT_ENTRY& entry)
                 {
                     return entry.status ==
                         KSWORD_ARK_I8042_AUDIT_STATUS_AVAILABLE;
                 })) &&
            (!failClosed ||
             std::any_of(
                 result.entries.begin(),
                 result.entries.end(),
                 [](const KSWORD_ARK_I8042_AUDIT_ENTRY& entry)
                 {
                     return entry.rowKind ==
                            KSWORD_ARK_I8042_AUDIT_ROW_DIAGNOSTIC &&
                         entry.verdict ==
                            KSWORD_ARK_I8042_VERDICT_UNSUPPORTED;
                 }));
        if (!aggregateValid)
        {
            failProtocol("entry aggregate rejected");
            return result;
        }

        result.version = response.version;
        result.status = response.queryStatus;
        result.responseFlags = response.responseFlags;
        result.totalCount = response.totalCount;
        result.returnedCount = response.returnedCount;
        result.entrySize = response.entrySize;
        result.descriptorId = response.descriptorId;
        result.imageTimeDateStamp = response.imageTimeDateStamp;
        result.imageSize = response.imageSize;
        result.imageChecksum = response.imageChecksum;
        result.pdbAge = response.pdbAge;
        result.imageBase = response.imageBase;
        std::copy(
            std::begin(response.pdbGuid),
            std::end(response.pdbGuid),
            std::begin(result.pdbGuid));
        result.lastStatus = response.lastStatus;
        result.io.ntStatus = response.lastStatus;
        result.unsupported =
            response.queryStatus ==
                KSWORD_ARK_I8042_AUDIT_STATUS_UNSUPPORTED ||
            (response.responseFlags &
             KSWORD_ARK_I8042_RESPONSE_FAIL_CLOSED) != 0UL;
        result.io.message = appendAuditSummary(
            operationName,
            result.totalCount,
            result.returnedCount,
            result.entries.size(),
            result.io.bytesReturned);
        return result;
    }

    CidTableAuditResult DriverClient::enumCidTable(const unsigned long flags, const unsigned long maxEntries, const unsigned long maxVisitCount, const unsigned long startCid, const unsigned long endCid) const
    {
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_ENUM_CID_TABLE";
        CidTableAuditResult result{};
        KSWORD_ARK_ENUM_CID_TABLE_REQUEST request{};
        request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
        request.flags = flags;
        request.maxEntries = maxEntries;
        request.maxVisitCount = maxVisitCount;
        request.startCid = startCid;
        request.endCid = endCid;
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_ENUM_CID_TABLE, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t headerSize = sizeof(KSWORD_ARK_ENUM_CID_TABLE_RESPONSE) - sizeof(KSWORD_ARK_CID_TABLE_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_CID_TABLE_RESPONSE*>(responseBuffer.data());
        const std::size_t parsedCount = validateAuditRows(result.io, headerSize, response->entrySize, sizeof(KSWORD_ARK_CID_TABLE_ENTRY), response->returnedCount, operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.visitedCount = response->visitedCount;
        result.maxVisitCount = response->maxVisitCount;
        result.lastStatus = response->lastStatus;
        result.pspCidTableAddress = response->pspCidTableAddress;
        result.dynDataCapabilityMask = response->dynDataCapabilityMask;
        result.htTableCodeOffset = response->htTableCodeOffset;
        result.hteLowValueOffset = response->hteLowValueOffset;
        result.io.ntStatus = response->lastStatus;
        result.entries = parseVariableRows<KSWORD_ARK_CID_TABLE_ENTRY>(responseBuffer, headerSize, response->entrySize, parsedCount);
        result.io.message = appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }

    ObjectTypeTableAuditResult DriverClient::enumObjectTypeTable(const unsigned long flags, const unsigned long maxEntries, const unsigned long startIndex) const
    {
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE";
        ObjectTypeTableAuditResult result{};
        KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_REQUEST request{};
        request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
        request.flags = flags;
        request.startIndex = startIndex;
        request.maxEntries = maxEntries;

        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE,
            &request,
            sizeof(request),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t headerSize =
            sizeof(KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE) -
            sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY);
        const auto* response =
            reinterpret_cast<const KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE*>(
                responseBuffer.data());
        const std::size_t parsedCount = validateAuditRows(
            result.io,
            headerSize,
            response->entrySize,
            sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY),
            response->returnedCount,
            operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.lastStatus = response->lastStatus;
        result.nextIndex = response->nextIndex;
        result.tableAddress = response->tableAddress;
        result.dynDataCapabilityMask = response->dynDataCapabilityMask;
        result.snapshotHash = response->snapshotHash;
        result.otNameOffset = response->otNameOffset;
        result.otIndexOffset = response->otIndexOffset;
        result.io.ntStatus = response->lastStatus;
        result.entries = parseVariableRows<KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY>(
            responseBuffer,
            headerSize,
            response->entrySize,
            parsedCount);
        result.io.message = appendAuditSummary(
            operationName,
            result.totalCount,
            result.returnedCount,
            result.entries.size(),
            result.io.bytesReturned);
        return result;
    }

    ObjectTypeProceduresResult DriverClient::enumObjectTypeProcedures(const unsigned long flags, const unsigned long startIndex, const unsigned long maxEntries) const
    {
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES";
        // 翻页上限：驱动按 \ObjectTypes 命名空间枚举，最多 KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS(256)
        // 个类型，正常一页就取完，翻页只是驱动按 maxEntries 或输出缓冲截断时的续读。
        // 64 页远超实际需要，只用来挡住驱动异常时的死循环。
        constexpr unsigned long kMaxPages = 64UL;
        constexpr std::size_t headerSize =
            sizeof(KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_RESPONSE) -
            sizeof(KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY);

        ObjectTypeProceduresResult result{};
        unsigned long cursor = startIndex;
        unsigned long totalBytes = 0UL;
        bool finished = false;
        bool layoutConsistent = true;
        std::string pageNote;

        for (unsigned long page = 0UL; page < kMaxPages; ++page)
        {
            KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_REQUEST request{};
            request.version = KSWORD_ARK_OBJECT_TYPE_PROCEDURES_PROTOCOL_VERSION;
            request.flags = flags;
            request.startIndex = cursor;
            request.maxEntries = maxEntries;

            std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
            IoResult pageIo = deviceIoControl(
                IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES,
                &request,
                sizeof(request),
                responseBuffer.data(),
                static_cast<unsigned long>(responseBuffer.size()));
            if (!pageIo.ok)
            {
                if (page == 0UL)
                {
                    result.io = pageIo;
                    markUnsupportedIfNeeded(result, operationName);
                    return result;
                }
                // 后续页失败：保留已经取到的行，明确标成被截断，不把半张表当完整结果。
                result.truncated = true;
                pageNote = "page " + std::to_string(page) + " failed: " + pageIo.message;
                break;
            }

            const auto* response =
                reinterpret_cast<const KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_RESPONSE*>(
                    responseBuffer.data());
            const std::size_t parsedCount = validateAuditRows(
                pageIo,
                headerSize,
                response->entrySize,
                sizeof(KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY),
                response->returnedCount,
                operationName);
            if (pageIo.ok && response->version != KSWORD_ARK_OBJECT_TYPE_PROCEDURES_PROTOCOL_VERSION)
            {
                pageIo.ok = false;
                pageIo.win32Error = ERROR_INVALID_DATA;
                pageIo.message = std::string(operationName) + " version invalid, version=" + std::to_string(response->version);
            }
            if (!pageIo.ok)
            {
                if (page == 0UL)
                {
                    result.io = pageIo;
                    return result;
                }
                result.truncated = true;
                pageNote = "page " + std::to_string(page) + " invalid: " + pageIo.message;
                break;
            }

            totalBytes += pageIo.bytesReturned;
            ++result.pageCount;
            if (page == 0UL)
            {
                result.io = pageIo;
                result.version = response->version;
                result.status = response->status;
                result.flags = response->flags;
                result.entrySize = response->entrySize;
                result.lastStatus = response->lastStatus;
                result.layoutState = response->layoutState;
                result.procedureBlockOffset = response->procedureBlockOffset;
                result.layoutAnchorTypes = response->layoutAnchorTypes;
                result.layoutAnchorAgree = response->layoutAnchorAgree;
                result.layoutReason = static_cast<std::uint32_t>(response->reserved0 & 0xFFFFFFFFULL);
                result.tableAddress = response->tableAddress;
            }
            if ((response->flags & KSWORD_ARK_OBJTYPE_RESPONSE_FLAG_SKIPPED_TYPES) != 0UL)
            {
                result.skippedTypes = true;
            }
            // 布局结论是一次枚举内的整体属性；各页不一致就说明驱动中途重新判定过，
            // 这时任何一页的“已验证”都不可信，结尾统一降成 UNVERIFIED。
            // 这条核对与上面的 skippedTypes 无关，必须每页都做——之前写成 else 分支，
            // 一旦某页带了 SKIPPED_TYPES 标志，那一页的布局就再也不会被核对了。
            if (response->layoutState != result.layoutState ||
                response->procedureBlockOffset != result.procedureBlockOffset)
            {
                layoutConsistent = false;
            }
            // 状态只往坏的方向走：首个非 OK 状态优先保留。
            if (result.status == KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_OK &&
                response->status != KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_OK)
            {
                result.status = response->status;
                result.lastStatus = response->lastStatus;
            }
            // 每页都是驱动按 \ObjectTypes 现场重新枚举的：如果两页之间总数变了，说明
            // 命名空间在两次查询之间被改动过（有类型对象被创建/销毁），续读游标指向的
            // 序号已经对不上原来那个类型——不能装作没事地接着拼，按截断收场。
            if (page != 0UL && response->totalCount != result.totalCount)
            {
                result.truncated = true;
                pageNote += (pageNote.empty() ? "" : "; ");
                pageNote += "\\ObjectTypes changed between pages (totalCount " +
                    std::to_string(result.totalCount) + " -> " + std::to_string(response->totalCount) +
                    "); stopping to avoid a shifted ordinal";
                break;
            }
            result.totalCount = std::max<std::uint32_t>(result.totalCount, response->totalCount);
            result.returnedCount += response->returnedCount;
            result.nextIndex = response->nextIndex;

            const std::vector<KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY> rawRows =
                parseVariableRows<KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY>(
                    responseBuffer,
                    headerSize,
                    response->entrySize,
                    parsedCount);
            result.entries.reserve(result.entries.size() + rawRows.size());
            for (const KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY& raw : rawRows)
            {
                ObjectTypeProcedureEntry row{};
                row.typeIndex = raw.typeIndex;
                row.procedureKind = raw.procedureKind;
                row.riskFlags = raw.riskFlags;
                row.entryFlags = raw.entryFlags;
                row.ownerModuleSize = raw.ownerModuleSize;
                row.lastStatus = raw.lastStatus;
                row.objectTypeAddress = raw.objectTypeAddress;
                row.slotAddress = raw.slotAddress;
                row.targetAddress = raw.targetAddress;
                row.ownerModuleBase = raw.ownerModuleBase;
                row.detourTargetAddress = raw.detourTargetAddress;
                row.typeName = fixedAuditWideToString(raw.typeName, std::size(raw.typeName));
                row.ownerModule = fixedAuditWideToString(raw.ownerModule, std::size(raw.ownerModule));
                row.sectionName = fixedAuditWideToString(raw.sectionName, std::size(raw.sectionName));
                result.entries.push_back(std::move(row));
            }

            if (response->nextIndex >= KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS)
            {
                finished = true;
                break;
            }
            if (response->nextIndex <= cursor)
            {
                // 驱动说还有下一页却不前进：再请求只会原地打转，按被截断收场。
                pageNote = "nextIndex did not advance, nextIndex=" + std::to_string(response->nextIndex);
                break;
            }
            cursor = response->nextIndex;
        }

        result.truncated = result.truncated || !finished;
        if (!layoutConsistent)
        {
            result.layoutState = KSWORD_ARK_OBJTYPE_LAYOUT_UNVERIFIED;
            pageNote += (pageNote.empty() ? "" : "; ");
            pageNote += "layout state differs between pages, downgraded to UNVERIFIED";
        }
        result.io.bytesReturned = totalBytes;
        result.io.ntStatus = result.lastStatus;
        std::ostringstream stream;
        stream << appendAuditSummary(
                operationName,
                result.totalCount,
                result.returnedCount,
                result.entries.size(),
                result.io.bytesReturned)
            << ", layoutState=" << result.layoutState
            << ", blockOffset=0x" << std::hex << result.procedureBlockOffset << std::dec
            << ", anchors=" << result.layoutAnchorAgree << "/" << result.layoutAnchorTypes
            << ", pages=" << result.pageCount
            << ", truncated=" << (result.truncated ? 1 : 0);
        if (!pageNote.empty())
        {
            stream << ", note=" << pageNote;
        }
        result.io.message = stream.str();
        return result;
    }

    KernelObjectSummaryAuditResult DriverClient::queryKernelObjectSummary(const unsigned long targetKind, const unsigned long cidValue, const std::uint64_t expectedObjectAddress, const unsigned long flags) const
    {
        KernelObjectSummaryAuditResult result{};
        KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_REQUEST request{};
        request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
        request.flags = flags;
        request.targetKind = targetKind;
        request.cidValue = cidValue;
        request.expectedObjectAddress = expectedObjectAddress;
        result.io = queryFixedAudit(*this, IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY, &request, result.response, "IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY");
        markUnsupportedIfNeeded(result, "IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY");
        result.io.ntStatus = result.response.lookupStatus;
        return result;
    }

    IpcSummaryAuditResult DriverClient::queryIpcSummary(const unsigned long processId, const std::uint64_t handleValue, const unsigned long flags, const unsigned long maxEntries) const
    {
        IpcSummaryAuditResult result{};
        KSWORD_ARK_QUERY_IPC_SUMMARY_REQUEST request{};
        request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
        request.flags = flags;
        request.processId = processId;
        request.handleValue = handleValue;
        request.maxEntries = maxEntries;
        result.io = queryFixedAudit(*this, IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY, &request, result.response, "IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY");
        markUnsupportedIfNeeded(result, "IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY");
        result.io.ntStatus = result.response.lastStatus;
        return result;
    }

    DynDataV4ApplyResult DriverClient::applyDynDataProfileV4(const DynDataV4ApplyInput& profile) const
    {
        DynDataV4ApplyResult result{};
        if (profile.items.empty() || profile.items.size() > KSW_DYN_V4_MAX_ITEMS_PER_MODULE || profile.capabilityGroups.size() > KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "DynData v4 profile item/group count invalid.";
            return result;
        }

        const std::size_t requestBytes = KSW_APPLY_DYN_PROFILE_V4_REQUEST_HEADER_SIZE + (profile.items.size() * sizeof(KSW_DYN_V4_ITEM_PACKET));
        if (requestBytes > static_cast<std::size_t>(std::numeric_limits<unsigned long>::max()))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "DynData v4 profile request too large.";
            return result;
        }

        std::vector<std::uint8_t> requestBuffer(requestBytes, 0U);
        auto* request = reinterpret_cast<KSW_APPLY_DYN_PROFILE_V4_REQUEST*>(requestBuffer.data());
        request->size = static_cast<unsigned long>(requestBytes);
        request->version = KSW_DYN_V4_PROTOCOL_VERSION;
        request->flags = profile.flags;
        request->itemCount = static_cast<unsigned long>(profile.items.size());
        request->capabilityGroupCount = static_cast<unsigned long>(profile.capabilityGroups.size());
        request->module = profile.module;
        for (std::size_t index = 0U; index < profile.capabilityGroups.size(); ++index)
        {
            request->capabilityGroups[index] = profile.capabilityGroups[index];
        }
        for (std::size_t index = 0U; index < profile.items.size(); ++index)
        {
            request->items[index] = profile.items[index];
        }

        result.io = deviceIoControl(IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4, requestBuffer.data(), static_cast<unsigned long>(requestBuffer.size()), &result.response, sizeof(result.response));
        markUnsupportedIfNeeded(result, "IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4");
        if (result.io.ok && result.io.bytesReturned < sizeof(KSW_APPLY_DYN_PROFILE_V4_RESPONSE))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            result.io.message = "DynData v4 apply response too small, bytesReturned=" + std::to_string(result.io.bytesReturned);
        }
        result.io.ntStatus = result.response.status;
        return result;
    }

    template <typename TResult, typename TResponse, typename TEntry>
    TResult queryDynDataV4Rows(const DriverClient& client, const unsigned long ioctlCode, const unsigned long maxRows, const char* const operationName)
    {
        TResult result{};
        std::vector<std::uint8_t> responseBuffer(std::max<std::size_t>(64U * 1024U, sizeof(TResponse) + (static_cast<std::size_t>(maxRows) * sizeof(TEntry))), 0U);
        result.io = client.deviceIoControl(ioctlCode, nullptr, 0UL, responseBuffer.data(), static_cast<unsigned long>(std::min<std::size_t>(responseBuffer.size(), kDefaultAuditBufferBytes)));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t headerSize = sizeof(TResponse) - sizeof(TEntry);
        const auto* response = reinterpret_cast<const TResponse*>(responseBuffer.data());
        const std::size_t parsedCount = validateAuditRows(result.io, headerSize, response->entrySize, sizeof(TEntry), response->returnedCount, operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.entries = parseVariableRows<TEntry>(responseBuffer, headerSize, response->entrySize, parsedCount);
        result.io.message = appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }

    DynDataV4ModulesResult DriverClient::queryDynDataV4Modules(const unsigned long maxRows) const
    {
        return queryDynDataV4Rows<DynDataV4ModulesResult, KSW_QUERY_DYN_V4_MODULES_RESPONSE, KSW_DYN_V4_MODULE_STATUS_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES, maxRows, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES");
    }

    DynDataV4CapabilityGroupsResult DriverClient::queryDynDataV4CapabilityGroups(const unsigned long maxRows) const
    {
        return queryDynDataV4Rows<DynDataV4CapabilityGroupsResult, KSW_QUERY_DYN_V4_CAPABILITY_GROUPS_RESPONSE, KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS, maxRows, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS");
    }

    DynDataV4MissingItemsResult DriverClient::queryDynDataV4MissingItems(const unsigned long maxRows) const
    {
        return queryDynDataV4Rows<DynDataV4MissingItemsResult, KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE, KSW_DYN_V4_MISSING_ITEM_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS, maxRows, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS");
    }

    DynDataV4ItemsResult DriverClient::queryDynDataV4Items(const unsigned long maxRows) const
    {
        return queryDynDataV4Rows<DynDataV4ItemsResult, KSW_QUERY_DYN_V4_ITEMS_RESPONSE, KSW_DYN_V4_ITEM_STATUS_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS, maxRows, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS");
    }
}
