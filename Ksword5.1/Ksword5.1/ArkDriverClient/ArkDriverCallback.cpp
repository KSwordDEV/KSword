#include "ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <sstream>
#include <string>
#include <vector>
namespace ksword::ark
{
    namespace
    {
        std::wstring fixedCallbackWideToString(const wchar_t* const textBuffer, const std::size_t maxChars)
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

        struct CallbackEnumLegacyEntry
        {
            // Input: none; this mirrors the original v1 callback enum entry layout.
            // Processing: ArkDriverClient uses it only when an older driver returns
            // a smaller entrySize than the currently compiled shared header.
            // Return behavior: the struct itself has no return value; it preserves
            // old-driver parsing without requiring shared protocol changes.
            unsigned long size;
            unsigned long callbackClass;
            unsigned long source;
            unsigned long status;
            unsigned long fieldFlags;
            unsigned long operationMask;
            unsigned long objectTypeMask;
            long lastStatus;
            unsigned long long callbackAddress;
            unsigned long long contextAddress;
            unsigned long long registrationAddress;
            unsigned long long moduleBase;
            unsigned long moduleSize;
            unsigned long reserved;
            wchar_t name[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            wchar_t altitude[KSWORD_ARK_CALLBACK_ENUM_ALTITUDE_CHARS];
            wchar_t modulePath[KSWORD_ARK_CALLBACK_ENUM_MODULE_PATH_CHARS];
            wchar_t detail[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];
        };

        struct CallbackEnumV1Entry
        {
            // 输入：无；该结构固定镜像分页协议之前的完整 v1 行布局。
            // 处理：仅在旧驱动返回 v1 entrySize 时用于兼容解析。
            // 返回：无；新协议不会写入此结构。
            unsigned long size;
            unsigned long callbackClass;
            unsigned long source;
            unsigned long status;
            unsigned long fieldFlags;
            unsigned long operationMask;
            unsigned long objectTypeMask;
            long lastStatus;
            unsigned long long callbackAddress;
            unsigned long long contextAddress;
            unsigned long long registrationAddress;
            unsigned long long rawStorageValue;
            unsigned long long enumerationGeneration;
            unsigned long long identityHash;
            unsigned long trustFlags;
            unsigned long removeBehavior;
            unsigned long long moduleBase;
            unsigned long moduleSize;
            unsigned long ownerRangeState;
            wchar_t name[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            wchar_t altitude[KSWORD_ARK_CALLBACK_ENUM_ALTITUDE_CHARS];
            wchar_t modulePath[KSWORD_ARK_CALLBACK_ENUM_MODULE_PATH_CHARS];
            wchar_t detail[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];
        };

        struct CallbackEnumV3Entry
        {
            // Input: none; this mirrors the v3 prefix before stable detail
            // metadata was appended. Keeping it explicit lets a newer R3
            // consume an older v3 driver without shifting the text fields.
            unsigned long size;
            unsigned long callbackClass;
            unsigned long source;
            unsigned long status;
            unsigned long fieldFlags;
            unsigned long operationMask;
            unsigned long objectTypeMask;
            long lastStatus;
            unsigned long long callbackAddress;
            unsigned long long contextAddress;
            unsigned long long registrationAddress;
            unsigned long long rawStorageValue;
            unsigned long long enumerationGeneration;
            unsigned long long identityHash;
            unsigned long trustFlags;
            unsigned long removeBehavior;
            unsigned long long moduleBase;
            unsigned long moduleSize;
            unsigned long ownerRangeState;
            unsigned long registrationType;
            unsigned long reserved;
            wchar_t name[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
            wchar_t altitude[KSWORD_ARK_CALLBACK_ENUM_ALTITUDE_CHARS];
            wchar_t modulePath[KSWORD_ARK_CALLBACK_ENUM_MODULE_PATH_CHARS];
            wchar_t detail[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];
        };

        static_assert(sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2) == 24U);
        static_assert(sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_HEADER_V2) == 32U);
        static_assert(offsetof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_V2, entries) == 32U);
        static_assert(sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST) == 40U);
        static_assert(offsetof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE, entries) == 48U);
        static_assert(
            sizeof(CallbackEnumV3Entry) ==
            offsetof(KSWORD_ARK_CALLBACK_ENUM_ENTRY, detailCode));
    }

    AsyncIoResult DriverClient::waitCallbackEventAsync(
        DriverHandle& handle,
        KSWORD_ARK_CALLBACK_WAIT_REQUEST& request,
        KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket,
        OVERLAPPED* const overlapped) const
    {
        return deviceIoControlAsync(
            handle,
            IOCTL_KSWORD_ARK_WAIT_CALLBACK_EVENT,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &eventPacket,
            static_cast<unsigned long>(sizeof(eventPacket)),
            overlapped);
    }

    IoResult DriverClient::setCallbackRules(const void* const blobBytes, const unsigned long blobSize) const
    {
        return deviceIoControl(
            IOCTL_KSWORD_ARK_SET_CALLBACK_RULES,
            const_cast<void*>(blobBytes),
            blobSize,
            nullptr,
            0);
    }

    CallbackRuntimeResult DriverClient::queryCallbackRuntimeState() const
    {
        CallbackRuntimeResult result{};
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_GET_CALLBACK_RUNTIME_STATE,
            nullptr,
            0,
            &result.state,
            static_cast<unsigned long>(sizeof(result.state)));
        if (result.io.ok && result.io.bytesReturned < sizeof(result.state))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            result.io.message = "callback runtime response too small, bytesReturned=" + std::to_string(result.io.bytesReturned);
        }
        return result;
    }

    IoResult DriverClient::setMinifilterBypassPids(const std::vector<std::uint32_t>& processIds) const
    {
        // Input: UI-collected PID list; duplicates and zero are tolerated here
        // but normalized before crossing into R0.
        // Processing: build the shared fixed packet and send it only through the
        // central DriverClient DeviceIoControl helper.
        // Return: IoResult describes Win32 transport success/failure.
        KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;

        for (const std::uint32_t processId : processIds)
        {
            if (processId == 0U)
            {
                continue;
            }
            const auto existingIterator = std::find(
                request.processIds,
                request.processIds + request.pidCount,
                static_cast<unsigned long>(processId));
            if (existingIterator != request.processIds + request.pidCount)
            {
                continue;
            }
            if (request.pidCount >= KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT)
            {
                IoResult errorResult{};
                errorResult.ok = false;
                errorResult.win32Error = ERROR_INVALID_PARAMETER;
                errorResult.message = "too many minifilter bypass PIDs, max=" +
                    std::to_string(KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT);
                return errorResult;
            }
            request.processIds[request.pidCount] = static_cast<unsigned long>(processId);
            ++request.pidCount;
        }

        return deviceIoControl(
            IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0);
    }

    MinifilterBypassPidResult DriverClient::queryMinifilterBypassPids() const
    {
        // Input: none.
        // Processing: request the fixed whitelist response and verify the
        // kernel returned at least the full v1 response structure.
        // Return: response packet plus IoResult; io.ok is false on short reads.
        MinifilterBypassPidResult result{};
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_MINIFILTER_BYPASS_PIDS,
            nullptr,
            0,
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        if (result.io.ok && result.io.bytesReturned < sizeof(result.response))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            result.io.message = "minifilter bypass PID response too small, bytesReturned=" +
                std::to_string(result.io.bytesReturned);
        }
        if (result.io.ok &&
            (result.response.size < sizeof(result.response) ||
                result.response.version != KSWORD_ARK_CALLBACK_PROTOCOL_VERSION ||
                result.response.pidCount > KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "minifilter bypass PID response header invalid";
        }
        return result;
    }

    IoResult DriverClient::answerCallbackEvent(const KSWORD_ARK_CALLBACK_ANSWER_REQUEST& request) const
    {
        KSWORD_ARK_CALLBACK_ANSWER_REQUEST mutableRequest = request;
        return deviceIoControl(
            IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT,
            &mutableRequest,
            static_cast<unsigned long>(sizeof(mutableRequest)),
            nullptr,
            0);
    }

    IoResult DriverClient::cancelAllPendingCallbackDecisions() const
    {
        return deviceIoControl(
            IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS,
            nullptr,
            0,
            nullptr,
            0);
    }

    CallbackRemoveResult DriverClient::removeExternalCallback(const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST& request) const
    {
        CallbackRemoveResult result{};
        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST mutableRequest = request;
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK,
            &mutableRequest,
            static_cast<unsigned long>(sizeof(mutableRequest)),
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        if (result.io.ok)
        {
            result.io.ntStatus = result.response.ntstatus;
        }
        return result;
    }

    CallbackRemoveExResult DriverClient::removeExternalCallbackEx(const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST& request) const
    {
        // Input: a validated EX remove packet built from one enumeration row.
        // Processing: sends only through the central DriverClient DeviceIoControl path.
        // Return: transport status plus the fixed R0 response packet for diagnostics.
        CallbackRemoveExResult result{};
        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST mutableRequest = request;
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX,
            &mutableRequest,
            static_cast<unsigned long>(sizeof(mutableRequest)),
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        if (result.io.ok)
        {
            result.io.ntStatus = result.response.ntstatus;
        }
        return result;
    }

    bool DriverClient::supportsExternalCallbackExperimentalUnlink() const
    {
        // Input: none.
        // Processing: checks whether the shared user-mode build has an extended
        // callback-remove IOCTL contract compiled in. Older v1 headers do not
        // expose REMOVE_EXTERNAL_CALLBACK_EX, so callers must keep the UI on the
        // safe legacy path when this returns false.
        // Return: true when the compiled shared header exposes the extended
        // unlink protocol; false when only the legacy remove request is known.
#if defined(IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX)
        return true;
#else
        return false;
#endif
    }

    CallbackEnumResult DriverClient::enumerateCallbacks(const unsigned long flags) const
    {
        CallbackEnumResult enumResult{};
        constexpr std::size_t v3HeaderSize =
            sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE) -
            sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY);
        constexpr std::size_t commonHeaderSize = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_HEADER_V2);
        constexpr unsigned long pageEntryCount = 512UL;
        constexpr std::size_t maximumResultRows = 32768U;
        constexpr std::size_t maximumPageCount = 128U;
        constexpr std::uint32_t maximumSnapshotRetries = 3U;
        constexpr std::size_t legacyEntrySize = sizeof(CallbackEnumLegacyEntry);
        constexpr std::size_t v1EntrySize = sizeof(CallbackEnumV1Entry);
        constexpr std::size_t v3EntrySize = sizeof(CallbackEnumV3Entry);
        const std::size_t responseBufferBytes =
            v3HeaderSize + (static_cast<std::size_t>(pageEntryCount) * sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));
        std::vector<std::uint8_t> responseBuffer(responseBufferBytes, 0U);
        unsigned long startIndex = 0UL;
        std::size_t pageCount = 0U;
        std::uint64_t totalResponseBytes = 0U;
        std::uint64_t expectedSnapshotHash = 0U;
        std::uint32_t expectedTotalCount = 0U;
        std::uint32_t snapshotRetryCount = 0U;
        unsigned long requestedProtocolVersion = KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION;

    RestartCallbackEnumeration:
        enumResult = CallbackEnumResult{};
        enumResult.snapshotRetryCount = snapshotRetryCount;
        startIndex = 0UL;
        pageCount = 0U;
        totalResponseBytes = 0U;
        expectedSnapshotHash = 0U;
        expectedTotalCount = 0U;
        std::fill(responseBuffer.begin(), responseBuffer.end(), std::uint8_t{0});

        while (pageCount < maximumPageCount)
        {
            KSWORD_ARK_ENUM_CALLBACKS_REQUEST requestV3{};
            KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2 requestLegacy{};
            void* requestBuffer = nullptr;
            unsigned long requestBytes = 0UL;

            if (requestedProtocolVersion >= KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION)
            {
                requestV3.size = sizeof(requestV3);
                requestV3.version = requestedProtocolVersion;
                requestV3.flags = flags;
                requestV3.maxEntries = pageEntryCount;
                requestV3.startIndex = startIndex;
                if (expectedSnapshotHash != 0U)
                {
                    requestV3.expectedSnapshotHash = expectedSnapshotHash;
                    requestV3.expectedTotalCount = expectedTotalCount;
                    requestV3.snapshotPolicy = KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_REQUIRE_MATCH;
                }
                requestBuffer = &requestV3;
                requestBytes = static_cast<unsigned long>(sizeof(requestV3));
            }
            else
            {
                requestLegacy.size = sizeof(requestLegacy);
                requestLegacy.version = requestedProtocolVersion;
                requestLegacy.flags = flags;
                requestLegacy.maxEntries = pageEntryCount;
                requestLegacy.startIndex = startIndex;
                requestBuffer = &requestLegacy;
                requestBytes = static_cast<unsigned long>(sizeof(requestLegacy));
            }
            std::fill(responseBuffer.begin(), responseBuffer.end(), 0U);

            enumResult.io = deviceIoControl(
                IOCTL_KSWORD_ARK_ENUM_CALLBACKS,
                requestBuffer,
                requestBytes,
                responseBuffer.data(),
                static_cast<unsigned long>(responseBuffer.size()));
            if (!enumResult.io.ok)
            {
                // 中文说明：仅首请求按 v3 -> v2 -> v1 回退，兼容旧驱动的
                // 24 字节请求头；快照重试不会触发协议降级。
                if (pageCount == 0U &&
                    startIndex == 0UL &&
                    enumResult.io.win32Error == ERROR_INVALID_PARAMETER &&
                    requestedProtocolVersion > 1UL)
                {
                    requestedProtocolVersion =
                        (requestedProtocolVersion >= KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION)
                        ? KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION_V2
                        : 1UL;
                    goto RestartCallbackEnumeration;
                }
                enumResult.io.message =
                    "DeviceIoControl(IOCTL_KSWORD_ARK_ENUM_CALLBACKS) failed, page=" +
                    std::to_string(pageCount) +
                    ", startIndex=" + std::to_string(startIndex) +
                    ", error=" + std::to_string(enumResult.io.win32Error);
                return enumResult;
            }
            totalResponseBytes += enumResult.io.bytesReturned;
            if (enumResult.io.bytesReturned < commonHeaderSize)
            {
                enumResult.io.ok = false;
                enumResult.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
                enumResult.io.message =
                    "callback enum response too small, bytesReturned=" +
                    std::to_string(enumResult.io.bytesReturned);
                return enumResult;
            }

            const auto* responseHeader =
                reinterpret_cast<const KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_HEADER_V2*>(responseBuffer.data());
            const std::size_t headerSize =
                responseHeader->version >= KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION
                ? v3HeaderSize
                : commonHeaderSize;
            if (enumResult.io.bytesReturned < headerSize)
            {
                enumResult.io.ok = false;
                enumResult.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
                enumResult.io.message =
                    "callback enum response missing versioned header, version=" +
                    std::to_string(responseHeader->version) +
                    ", bytesReturned=" + std::to_string(enumResult.io.bytesReturned);
                return enumResult;
            }
            if (responseHeader->version != requestedProtocolVersion)
            {
                enumResult.io.ok = false;
                enumResult.io.win32Error = ERROR_INVALID_DATA;
                enumResult.io.message =
                    "callback enum response version mismatch, requested=" +
                    std::to_string(requestedProtocolVersion) +
                    ", returned=" + std::to_string(responseHeader->version);
                return enumResult;
            }
            if (responseHeader->entrySize < legacyEntrySize)
            {
                enumResult.io.ok = false;
                enumResult.io.win32Error = ERROR_INVALID_DATA;
                enumResult.io.message =
                    "callback enum entrySize invalid, entrySize=" +
                    std::to_string(responseHeader->entrySize);
                return enumResult;
            }
            if (responseHeader->version >= KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION &&
                responseHeader->entrySize < v3EntrySize)
            {
                enumResult.io.ok = false;
                enumResult.io.win32Error = ERROR_INVALID_DATA;
                enumResult.io.message =
                    "callback enum v3 entrySize omitted identity fields, entrySize=" +
                    std::to_string(responseHeader->entrySize);
                return enumResult;
            }

            enumResult.version = static_cast<std::uint32_t>(responseHeader->version);
            enumResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
            enumResult.flags |= static_cast<std::uint32_t>(responseHeader->flags);
            enumResult.lastStatus = static_cast<long>(responseHeader->lastStatus);
            enumResult.io.ntStatus = enumResult.lastStatus;

            if (responseHeader->version >= KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION)
            {
                const auto* responseV3 =
                    reinterpret_cast<const KSWORD_ARK_ENUM_CALLBACKS_RESPONSE*>(responseBuffer.data());
                const bool snapshotChanged =
                    (responseV3->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_CHANGED) != 0UL;
                const bool snapshotMetadataValid =
                    (responseV3->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_HASH_VALID) != 0UL
                    && (responseV3->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_IDENTITY_HASH_VALID) != 0UL
                    && responseV3->snapshotHash != 0ULL
                    && responseV3->enumerationGeneration == responseV3->snapshotHash;
                if (snapshotChanged)
                {
                    if (snapshotRetryCount >= maximumSnapshotRetries)
                    {
                        enumResult.io.ok = false;
                        enumResult.io.win32Error = ERROR_RETRY;
                        enumResult.io.message =
                            "callback enum snapshot changed repeatedly; retry limit reached";
                        return enumResult;
                    }
                    ++snapshotRetryCount;
                    goto RestartCallbackEnumeration;
                }
                if (!snapshotMetadataValid)
                {
                    enumResult.io.ok = false;
                    enumResult.io.win32Error = ERROR_INVALID_DATA;
                    enumResult.io.message = "callback enum v3 response omitted snapshot metadata";
                    return enumResult;
                }
                if (expectedSnapshotHash == 0U)
                {
                    expectedSnapshotHash = static_cast<std::uint64_t>(responseV3->snapshotHash);
                    expectedTotalCount = static_cast<std::uint32_t>(responseV3->totalCount);
                    enumResult.snapshotGeneration =
                        static_cast<std::uint64_t>(responseV3->enumerationGeneration);
                    enumResult.snapshotHash = expectedSnapshotHash;
                }
                else if (responseV3->snapshotHash != expectedSnapshotHash ||
                    responseV3->enumerationGeneration != enumResult.snapshotGeneration ||
                    responseV3->totalCount != expectedTotalCount)
                {
                    if (snapshotRetryCount >= maximumSnapshotRetries)
                    {
                        enumResult.io.ok = false;
                        enumResult.io.win32Error = ERROR_RETRY;
                        enumResult.io.message =
                            "callback enum snapshot metadata remained inconsistent after retries";
                        return enumResult;
                    }
                    ++snapshotRetryCount;
                    goto RestartCallbackEnumeration;
                }
            }

            const std::size_t availableCount =
                (enumResult.io.bytesReturned - headerSize) /
                static_cast<std::size_t>(responseHeader->entrySize);
            const std::size_t parsedCount = std::min<std::size_t>(
                static_cast<std::size_t>(responseHeader->returnedCount),
                availableCount);
            if (parsedCount != static_cast<std::size_t>(responseHeader->returnedCount))
            {
                enumResult.io.ok = false;
                enumResult.io.win32Error = ERROR_INVALID_DATA;
                enumResult.io.message = "callback enum page returnedCount exceeds available bytes";
                return enumResult;
            }

            if (enumResult.entries.size() + parsedCount > maximumResultRows)
            {
                enumResult.io.ok = false;
                enumResult.io.win32Error = ERROR_BUFFER_OVERFLOW;
                enumResult.io.message = "callback enum result exceeds safety row limit";
                return enumResult;
            }
            enumResult.entries.reserve(std::min<std::size_t>(
                static_cast<std::size_t>(enumResult.totalCount),
                maximumResultRows));

            for (std::size_t index = 0U; index < parsedCount; ++index)
            {
                const std::size_t entryOffset =
                    headerSize + (index * static_cast<std::size_t>(responseHeader->entrySize));
                CallbackEnumEntry row{};

                if (responseHeader->entrySize >= sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY))
                {
                    const auto* sourceEntry =
                        reinterpret_cast<const KSWORD_ARK_CALLBACK_ENUM_ENTRY*>(responseBuffer.data() + entryOffset);
                    row.callbackClass = static_cast<std::uint32_t>(sourceEntry->callbackClass);
                    row.source = static_cast<std::uint32_t>(sourceEntry->source);
                    row.status = static_cast<std::uint32_t>(sourceEntry->status);
                    row.fieldFlags = static_cast<std::uint32_t>(sourceEntry->fieldFlags);
                    row.operationMask = static_cast<std::uint32_t>(sourceEntry->operationMask);
                    row.objectTypeMask = static_cast<std::uint32_t>(sourceEntry->objectTypeMask);
                    row.registrationType = static_cast<std::uint32_t>(sourceEntry->registrationType);
                    row.lastStatus = static_cast<long>(sourceEntry->lastStatus);
                    row.callbackAddress = static_cast<std::uint64_t>(sourceEntry->callbackAddress);
                    row.contextAddress = static_cast<std::uint64_t>(sourceEntry->contextAddress);
                    row.registrationAddress = static_cast<std::uint64_t>(sourceEntry->registrationAddress);
                    row.rawStorageValue = static_cast<std::uint64_t>(sourceEntry->rawStorageValue);
                    row.generation = static_cast<std::uint64_t>(sourceEntry->enumerationGeneration);
                    row.identityHash = static_cast<std::uint64_t>(sourceEntry->identityHash);
                    row.trustFlags = static_cast<std::uint32_t>(sourceEntry->trustFlags);
                    row.removeBehavior = static_cast<std::uint32_t>(sourceEntry->removeBehavior);
                    row.removeFlags = row.removeBehavior;
                    row.moduleBase = static_cast<std::uint64_t>(sourceEntry->moduleBase);
                    row.moduleSize = static_cast<std::uint32_t>(sourceEntry->moduleSize);
                    row.detailCode = static_cast<std::uint32_t>(sourceEntry->detailCode);
                    for (std::size_t detailIndex = 0U;
                         detailIndex < KSWORD_ARK_CALLBACK_ENUM_DETAIL_ARG_COUNT;
                         ++detailIndex)
                    {
                        row.detailArgs[detailIndex] =
                            static_cast<std::uint64_t>(sourceEntry->detailArgs[detailIndex]);
                    }
                    row.name = fixedCallbackWideToString(sourceEntry->name, KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS);
                    row.altitude = fixedCallbackWideToString(sourceEntry->altitude, KSWORD_ARK_CALLBACK_ENUM_ALTITUDE_CHARS);
                    row.modulePath = fixedCallbackWideToString(sourceEntry->modulePath, KSWORD_ARK_CALLBACK_ENUM_MODULE_PATH_CHARS);
                    row.detail = fixedCallbackWideToString(sourceEntry->detail, KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS);
                }
                else if (responseHeader->entrySize >= v3EntrySize)
                {
                    const auto* sourceEntry =
                        reinterpret_cast<const CallbackEnumV3Entry*>(responseBuffer.data() + entryOffset);
                    row.callbackClass = static_cast<std::uint32_t>(sourceEntry->callbackClass);
                    row.source = static_cast<std::uint32_t>(sourceEntry->source);
                    row.status = static_cast<std::uint32_t>(sourceEntry->status);
                    row.fieldFlags = static_cast<std::uint32_t>(sourceEntry->fieldFlags);
                    row.operationMask = static_cast<std::uint32_t>(sourceEntry->operationMask);
                    row.objectTypeMask = static_cast<std::uint32_t>(sourceEntry->objectTypeMask);
                    row.registrationType = static_cast<std::uint32_t>(sourceEntry->registrationType);
                    row.lastStatus = static_cast<long>(sourceEntry->lastStatus);
                    row.callbackAddress = static_cast<std::uint64_t>(sourceEntry->callbackAddress);
                    row.contextAddress = static_cast<std::uint64_t>(sourceEntry->contextAddress);
                    row.registrationAddress = static_cast<std::uint64_t>(sourceEntry->registrationAddress);
                    row.rawStorageValue = static_cast<std::uint64_t>(sourceEntry->rawStorageValue);
                    row.generation = static_cast<std::uint64_t>(sourceEntry->enumerationGeneration);
                    row.identityHash = static_cast<std::uint64_t>(sourceEntry->identityHash);
                    row.trustFlags = static_cast<std::uint32_t>(sourceEntry->trustFlags);
                    row.removeBehavior = static_cast<std::uint32_t>(sourceEntry->removeBehavior);
                    row.removeFlags = row.removeBehavior;
                    row.moduleBase = static_cast<std::uint64_t>(sourceEntry->moduleBase);
                    row.moduleSize = static_cast<std::uint32_t>(sourceEntry->moduleSize);
                    row.name = fixedCallbackWideToString(sourceEntry->name, KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS);
                    row.altitude = fixedCallbackWideToString(sourceEntry->altitude, KSWORD_ARK_CALLBACK_ENUM_ALTITUDE_CHARS);
                    row.modulePath = fixedCallbackWideToString(sourceEntry->modulePath, KSWORD_ARK_CALLBACK_ENUM_MODULE_PATH_CHARS);
                    row.detail = fixedCallbackWideToString(sourceEntry->detail, KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS);
                }
                else if (responseHeader->entrySize >= v1EntrySize)
                {
                    const auto* sourceEntry =
                        reinterpret_cast<const CallbackEnumV1Entry*>(responseBuffer.data() + entryOffset);
                    row.callbackClass = static_cast<std::uint32_t>(sourceEntry->callbackClass);
                    row.source = static_cast<std::uint32_t>(sourceEntry->source);
                    row.status = static_cast<std::uint32_t>(sourceEntry->status);
                    row.fieldFlags = static_cast<std::uint32_t>(sourceEntry->fieldFlags);
                    row.operationMask = static_cast<std::uint32_t>(sourceEntry->operationMask);
                    row.objectTypeMask = static_cast<std::uint32_t>(sourceEntry->objectTypeMask);
                    row.lastStatus = static_cast<long>(sourceEntry->lastStatus);
                    row.callbackAddress = static_cast<std::uint64_t>(sourceEntry->callbackAddress);
                    row.contextAddress = static_cast<std::uint64_t>(sourceEntry->contextAddress);
                    row.registrationAddress = static_cast<std::uint64_t>(sourceEntry->registrationAddress);
                    row.rawStorageValue = static_cast<std::uint64_t>(sourceEntry->rawStorageValue);
                    row.generation = static_cast<std::uint64_t>(sourceEntry->enumerationGeneration);
                    row.identityHash = static_cast<std::uint64_t>(sourceEntry->identityHash);
                    row.trustFlags = static_cast<std::uint32_t>(sourceEntry->trustFlags);
                    row.removeBehavior = static_cast<std::uint32_t>(sourceEntry->removeBehavior);
                    row.removeFlags = row.removeBehavior;
                    row.moduleBase = static_cast<std::uint64_t>(sourceEntry->moduleBase);
                    row.moduleSize = static_cast<std::uint32_t>(sourceEntry->moduleSize);
                    row.name = fixedCallbackWideToString(sourceEntry->name, KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS);
                    row.altitude = fixedCallbackWideToString(sourceEntry->altitude, KSWORD_ARK_CALLBACK_ENUM_ALTITUDE_CHARS);
                    row.modulePath = fixedCallbackWideToString(sourceEntry->modulePath, KSWORD_ARK_CALLBACK_ENUM_MODULE_PATH_CHARS);
                    row.detail = fixedCallbackWideToString(sourceEntry->detail, KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS);
                }
                else
                {
                    const auto* sourceEntry =
                        reinterpret_cast<const CallbackEnumLegacyEntry*>(responseBuffer.data() + entryOffset);
                    row.callbackClass = static_cast<std::uint32_t>(sourceEntry->callbackClass);
                    row.source = static_cast<std::uint32_t>(sourceEntry->source);
                    row.status = static_cast<std::uint32_t>(sourceEntry->status);
                    row.fieldFlags = static_cast<std::uint32_t>(sourceEntry->fieldFlags);
                    row.operationMask = static_cast<std::uint32_t>(sourceEntry->operationMask);
                    row.objectTypeMask = static_cast<std::uint32_t>(sourceEntry->objectTypeMask);
                    row.lastStatus = static_cast<long>(sourceEntry->lastStatus);
                    row.callbackAddress = static_cast<std::uint64_t>(sourceEntry->callbackAddress);
                    row.contextAddress = static_cast<std::uint64_t>(sourceEntry->contextAddress);
                    row.registrationAddress = static_cast<std::uint64_t>(sourceEntry->registrationAddress);
                    row.moduleBase = static_cast<std::uint64_t>(sourceEntry->moduleBase);
                    row.moduleSize = static_cast<std::uint32_t>(sourceEntry->moduleSize);
                    row.name = fixedCallbackWideToString(sourceEntry->name, KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS);
                    row.altitude = fixedCallbackWideToString(sourceEntry->altitude, KSWORD_ARK_CALLBACK_ENUM_ALTITUDE_CHARS);
                    row.modulePath = fixedCallbackWideToString(sourceEntry->modulePath, KSWORD_ARK_CALLBACK_ENUM_MODULE_PATH_CHARS);
                    row.detail = fixedCallbackWideToString(sourceEntry->detail, KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS);
                }
                if (responseHeader->entrySize >=
                        sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY) &&
                    ((((row.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_DETAIL_ARGS) != 0U) !=
                      (row.detailCode != KSWORD_ARK_CALLBACK_ENUM_DETAIL_NONE)) ||
                     (row.detailCode != KSWORD_ARK_CALLBACK_ENUM_DETAIL_NONE &&
                      row.callbackClass !=
                          KSWORD_ARK_CALLBACK_ENUM_CLASS_LEGACY_FS_FILTER) ||
                     row.detailCode >
                         KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_PUBLIC_ENUM_FAILED))
                {
                    enumResult.io.ok = false;
                    enumResult.io.win32Error = ERROR_INVALID_DATA;
                    enumResult.io.message =
                        "callback enum row detail metadata invalid, page=" +
                        std::to_string(pageCount) +
                        ", row=" + std::to_string(index);
                    return enumResult;
                }
                if (responseHeader->version >= KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION &&
                    (((row.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH) == 0U) ||
                     ((row.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION) == 0U) ||
                     row.identityHash == 0U ||
                     row.generation != expectedSnapshotHash))
                {
                    enumResult.io.ok = false;
                    enumResult.io.win32Error = ERROR_INVALID_DATA;
                    enumResult.io.message =
                        "callback enum v3 row identity metadata invalid, page=" +
                        std::to_string(pageCount) +
                        ", row=" + std::to_string(index);
                    return enumResult;
                }
                enumResult.entries.push_back(std::move(row));
            }

            ++pageCount;
            const bool pagedProtocol = responseHeader->version >= 2UL;
            const unsigned long nextIndex = pagedProtocol
                ? responseHeader->nextIndex
                : startIndex + static_cast<unsigned long>(parsedCount);
            const bool moreData =
                pagedProtocol &&
                (((responseHeader->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_MORE_DATA) != 0UL) ||
                    nextIndex < responseHeader->totalCount);
            if (!moreData)
            {
                startIndex = nextIndex;
                break;
            }
            if (nextIndex <= startIndex)
            {
                enumResult.io.ok = false;
                enumResult.io.win32Error = ERROR_INVALID_DATA;
                enumResult.io.message = "callback enum pagination made no forward progress";
                return enumResult;
            }
            startIndex = nextIndex;
        }

        if (pageCount >= maximumPageCount && startIndex < enumResult.totalCount)
        {
            enumResult.io.ok = false;
            enumResult.io.win32Error = ERROR_BUFFER_OVERFLOW;
            enumResult.io.message = "callback enum exceeded safety page limit";
            return enumResult;
        }

        if (enumResult.version >= KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION_V2 &&
            enumResult.entries.size() != static_cast<std::size_t>(enumResult.totalCount))
        {
            enumResult.io.ok = false;
            enumResult.io.win32Error = ERROR_INVALID_DATA;
            enumResult.io.message =
                "callback enum pagination ended before the advertised total, total=" +
                std::to_string(enumResult.totalCount) +
                ", parsed=" + std::to_string(enumResult.entries.size());
            return enumResult;
        }

        enumResult.pageCount = static_cast<std::uint32_t>(pageCount);
        if (enumResult.version >= KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION)
        {
            KSWORD_ARK_ENUM_CALLBACKS_REQUEST validationRequest{};
            validationRequest.size = sizeof(validationRequest);
            validationRequest.version = KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION;
            validationRequest.flags = flags;
            validationRequest.maxEntries = 1UL;
            validationRequest.startIndex = 0UL;
            validationRequest.expectedSnapshotHash = expectedSnapshotHash;
            validationRequest.expectedTotalCount = expectedTotalCount;
            validationRequest.snapshotPolicy = KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_REQUIRE_MATCH;
            std::fill(responseBuffer.begin(), responseBuffer.end(), 0U);

            enumResult.io = deviceIoControl(
                IOCTL_KSWORD_ARK_ENUM_CALLBACKS,
                &validationRequest,
                static_cast<unsigned long>(sizeof(validationRequest)),
                responseBuffer.data(),
                static_cast<unsigned long>(v3HeaderSize));
            if (!enumResult.io.ok)
            {
                enumResult.io.message =
                    "callback enum final snapshot validation failed, error=" +
                    std::to_string(enumResult.io.win32Error);
                return enumResult;
            }
            totalResponseBytes += enumResult.io.bytesReturned;
            if (enumResult.io.bytesReturned < v3HeaderSize)
            {
                enumResult.io.ok = false;
                enumResult.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
                enumResult.io.message = "callback enum final validation response too small";
                return enumResult;
            }

            const auto* validationResponse =
                reinterpret_cast<const KSWORD_ARK_ENUM_CALLBACKS_RESPONSE*>(responseBuffer.data());
            const bool validationChanged =
                (validationResponse->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_CHANGED) != 0UL;
            const bool validationMatches =
                validationResponse->version == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION
                && validationResponse->totalCount == expectedTotalCount
                && validationResponse->snapshotHash == expectedSnapshotHash
                && validationResponse->enumerationGeneration == enumResult.snapshotGeneration
                && (validationResponse->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_HASH_VALID) != 0UL
                && (validationResponse->flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_IDENTITY_HASH_VALID) != 0UL;
            if (validationChanged || !validationMatches)
            {
                if (snapshotRetryCount >= maximumSnapshotRetries)
                {
                    enumResult.io.ok = false;
                    enumResult.io.win32Error = ERROR_RETRY;
                    enumResult.io.message =
                        "callback enum final snapshot validation remained unstable";
                    return enumResult;
                }
                ++snapshotRetryCount;
                goto RestartCallbackEnumeration;
            }
            enumResult.snapshotConsistent = true;
            enumResult.io.ntStatus = enumResult.lastStatus;
        }

        enumResult.returnedCount = static_cast<std::uint32_t>(enumResult.entries.size());
        if (enumResult.returnedCount >= enumResult.totalCount)
        {
            enumResult.flags &= ~static_cast<std::uint32_t>(
                KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_TRUNCATED |
                KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_MORE_DATA);
        }

        std::ostringstream stream;
        stream << "version=" << enumResult.version
            << ", total=" << enumResult.totalCount
            << ", returned=" << enumResult.returnedCount
            << ", parsed=" << enumResult.entries.size()
            << ", pages=" << pageCount
            << ", snapshotConsistent=" << (enumResult.snapshotConsistent ? "true" : "false")
            << ", snapshotRetries=" << enumResult.snapshotRetryCount
            << ", snapshotHash=0x" << std::hex << enumResult.snapshotHash
            << ", flags=0x" << std::hex << enumResult.flags
            << ", bytesReturned=" << std::dec << totalResponseBytes;
        enumResult.io.message = stream.str();
        return enumResult;
    }
}
