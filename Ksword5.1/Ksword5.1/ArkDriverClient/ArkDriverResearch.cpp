#include "ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::ark
{
    static_assert(
        sizeof(KSWORD_ARK_QUERY_RESEARCH_TOPIC_REQUEST) == 24U,
        "research_request_abi_drift");
    static_assert(
        sizeof(KSWORD_ARK_RESEARCH_EVIDENCE_ENTRY) == 184U,
        "research_evidence_abi_drift");
    static_assert(
        KSWORD_ARK_RESEARCH_RESPONSE_HEADER_SIZE == 168U,
        "research_response_abi_drift");

    namespace
    {
        bool isResearchUnsupported(const unsigned long error)
        {
            return error == ERROR_INVALID_FUNCTION ||
                error == ERROR_NOT_SUPPORTED ||
                error == ERROR_REVISION_MISMATCH;
        }
    }

    // queryResearchTopic：
    // - 输入：与知识目录同序的 topicId 和有界行预算；
    // - 处理：通过统一 DriverClient 发出只读 IOCTL，严格校验可变长响应；
    // - 返回：R0 请求/CPU/时间/WDF-WDM 快照以及已注册业务来源。
    ResearchTopicQueryResult DriverClient::queryResearchTopic(
        const unsigned long topicId,
        const unsigned long maxEntries) const
    {
        constexpr const char* operationName = "IOCTL_KSWORD_ARK_QUERY_RESEARCH_TOPIC";
        constexpr std::size_t headerSize = KSWORD_ARK_RESEARCH_RESPONSE_HEADER_SIZE;
        constexpr unsigned long knownResponseFlags =
            KSWORD_ARK_RESEARCH_RESPONSE_TRUNCATED |
            KSWORD_ARK_RESEARCH_RESPONSE_RUNTIME_DEPENDENT |
            KSWORD_ARK_RESEARCH_RESPONSE_DYNDATA_DEPENDENT |
            KSWORD_ARK_RESEARCH_RESPONSE_R3_CROSS_VIEW |
            KSWORD_ARK_RESEARCH_RESPONSE_PRIVATE_LAYOUT |
            KSWORD_ARK_RESEARCH_RESPONSE_FIRMWARE_EVIDENCE |
            KSWORD_ARK_RESEARCH_RESPONSE_PRIVACY_GUARDED;
        constexpr unsigned long knownSourceMask =
            KSWORD_ARK_RESEARCH_SOURCE_PUBLIC_KERNEL_API |
            KSWORD_ARK_RESEARCH_SOURCE_WDF |
            KSWORD_ARK_RESEARCH_SOURCE_IOCTL_REGISTRY |
            KSWORD_ARK_RESEARCH_SOURCE_DYNDATA_PDB |
            KSWORD_ARK_RESEARCH_SOURCE_RUNTIME_SNAPSHOT |
            KSWORD_ARK_RESEARCH_SOURCE_R3_PUBLIC_API |
            KSWORD_ARK_RESEARCH_SOURCE_FIRMWARE |
            KSWORD_ARK_RESEARCH_SOURCE_EVENT_STREAM;
        constexpr unsigned long commonLiveSources =
            KSWORD_ARK_RESEARCH_SOURCE_PUBLIC_KERNEL_API |
            KSWORD_ARK_RESEARCH_SOURCE_RUNTIME_SNAPSHOT;

        ResearchTopicQueryResult result{};
        if (topicId == 0UL || topicId > KSWORD_ARK_RESEARCH_TOPIC_COUNT)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "research topic id out of range";
            return result;
        }

        KSWORD_ARK_QUERY_RESEARCH_TOPIC_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_RESEARCH_PROTOCOL_VERSION;
        request.topicId = topicId;
        request.maxEntries = maxEntries == 0UL
            ? KSWORD_ARK_RESEARCH_DEFAULT_MAX_ENTRIES
            : std::min(maxEntries, KSWORD_ARK_RESEARCH_HARD_MAX_ENTRIES);

        const std::size_t outputSize = headerSize +
            (static_cast<std::size_t>(request.maxEntries) *
                sizeof(KSWORD_ARK_RESEARCH_EVIDENCE_ENTRY));
        static_assert(
            headerSize +
                (KSWORD_ARK_RESEARCH_HARD_MAX_ENTRIES *
                    sizeof(KSWORD_ARK_RESEARCH_EVIDENCE_ENTRY)) <=
                std::numeric_limits<unsigned long>::max(),
            "research response must fit DeviceIoControl size");
        std::vector<std::uint8_t> responseBuffer(outputSize, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_RESEARCH_TOPIC,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            result.unsupported = isResearchUnsupported(result.io.win32Error);
            result.io.message = result.unsupported
                ? std::string(operationName) + " unsupported or driver version is too old"
                : std::string(operationName) + " failed, error=" +
                    std::to_string(result.io.win32Error);
            return result;
        }

        const auto failProtocol = [&result, operationName](const char* reason)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = std::string(operationName) +
                " invalid response: " + reason;
            result.response = {};
            result.entries.clear();
        };
        if (result.io.bytesReturned < headerSize ||
            result.io.bytesReturned > responseBuffer.size())
        {
            failProtocol("bytesReturned/header out of range");
            return result;
        }

        const auto* response = reinterpret_cast<
            const KSWORD_ARK_QUERY_RESEARCH_TOPIC_RESPONSE*>(
                responseBuffer.data());
        const bool truncated =
            (response->responseFlags & KSWORD_ARK_RESEARCH_RESPONSE_TRUNCATED) != 0UL;
        const bool queryStateValid =
            (response->queryStatus == KSWORD_ARK_RESEARCH_STATUS_OK &&
                !truncated && response->lastStatus >= 0L &&
                response->duplicateIoctlCount == 0UL) ||
            (response->queryStatus == KSWORD_ARK_RESEARCH_STATUS_TRUNCATED &&
                truncated && response->lastStatus >= 0L &&
                response->duplicateIoctlCount == 0UL) ||
            (response->queryStatus == KSWORD_ARK_RESEARCH_STATUS_SOURCE_MISSING &&
                response->lastStatus < 0L);
        if (response->size != headerSize ||
            response->version != KSWORD_ARK_RESEARCH_PROTOCOL_VERSION ||
            response->topicId != topicId ||
            !queryStateValid ||
            (response->responseFlags & ~knownResponseFlags) != 0UL ||
            response->totalCount < KSWORD_ARK_RESEARCH_MIN_TOTAL_ENTRIES ||
            response->totalCount > KSWORD_ARK_RESEARCH_MAX_TOTAL_ENTRIES ||
            response->entrySize != sizeof(KSWORD_ARK_RESEARCH_EVIDENCE_ENTRY) ||
            response->returnedCount > response->totalCount ||
            response->returnedCount > request.maxEntries ||
            response->returnedCount > KSWORD_ARK_RESEARCH_HARD_MAX_ENTRIES ||
            truncated != (response->returnedCount < response->totalCount) ||
            response->registeredIoctlCount == 0UL ||
            response->duplicateIoctlCount > response->registeredIoctlCount ||
            response->requestorMode > 1UL ||
            response->requestorModeMirror != response->requestorMode ||
            response->performanceFrequency == 0ULL ||
            response->driverObjectAddress == 0ULL ||
            response->driverImageBase == 0ULL ||
            response->driverImageSize == 0ULL ||
            response->deviceObjectAddress == 0ULL ||
            response->topAttachedDeviceAddress == 0ULL ||
            response->reserved != 0UL)
        {
            failProtocol("header fields rejected");
            return result;
        }

        const std::size_t availableRows =
            (result.io.bytesReturned - headerSize) / response->entrySize;
        if (availableRows < response->returnedCount ||
            headerSize +
                (static_cast<std::size_t>(response->returnedCount) *
                    response->entrySize) != result.io.bytesReturned)
        {
            failProtocol("row byte count mismatch");
            return result;
        }

        std::memcpy(&result.response, response, headerSize);
        result.entries.reserve(response->returnedCount);
        for (std::size_t index = 0U; index < response->returnedCount; ++index)
        {
            const auto* row = reinterpret_cast<
                const KSWORD_ARK_RESEARCH_EVIDENCE_ENTRY*>(
                    responseBuffer.data() + headerSize +
                    (index * response->entrySize));
            const bool isCommonRow =
                index < KSWORD_ARK_RESEARCH_COMMON_ENTRY_COUNT;
            const unsigned long expectedKind = isCommonRow
                ? static_cast<unsigned long>(index + 1U)
                : KSWORD_ARK_RESEARCH_ENTRY_IOCTL_SOURCE;
            const unsigned long expectedFieldId = isCommonRow
                ? static_cast<unsigned long>(index + 1U)
                : static_cast<unsigned long>(0x100U +
                    index - KSWORD_ARK_RESEARCH_COMMON_ENTRY_COUNT);
            unsigned long expectedSourceMask =
                KSWORD_ARK_RESEARCH_SOURCE_IOCTL_REGISTRY;
            const char* expectedCommonName = nullptr;
            if (index == 0U)
            {
                expectedSourceMask = commonLiveSources |
                    KSWORD_ARK_RESEARCH_SOURCE_WDF;
                expectedCommonName = "request-context";
            }
            else if (index == 1U)
            {
                expectedSourceMask = commonLiveSources;
                expectedCommonName = "processor-context";
            }
            else if (index == 2U)
            {
                expectedSourceMask = commonLiveSources;
                expectedCommonName = "clock-snapshot";
            }
            else if (index == 3U)
            {
                expectedSourceMask = commonLiveSources |
                    KSWORD_ARK_RESEARCH_SOURCE_WDF;
                expectedCommonName = "wdf-wdm-chain";
            }

            const bool nameBufferTerminated =
                row->name[KSWORD_ARK_RESEARCH_ENTRY_NAME_CHARS - 1U] == '\0';
            const bool commonMetadataValid = !isCommonRow ||
                (row->ioControlCode == 0UL &&
                 row->functionNumber == 0UL &&
                 row->method == 0UL &&
                 row->access == 0UL &&
                 row->registryFlags == 0UL &&
                 row->requiredCapability == 0ULL &&
                 row->state == KSWORD_ARK_RESEARCH_EVIDENCE_AVAILABLE &&
                 row->lastStatus >= 0L &&
                 nameBufferTerminated &&
                 expectedCommonName != nullptr &&
                 std::strcmp(row->name, expectedCommonName) == 0);
            const bool ioctlMetadataValid = isCommonRow ||
                (row->ioControlCode != 0UL &&
                 row->functionNumber ==
                    ((row->ioControlCode >> 2U) & 0xFFFUL) &&
                 row->method == (row->ioControlCode & 0x3UL) &&
                 row->access == ((row->ioControlCode >> 14U) & 0x3UL) &&
                 row->value3 == 0ULL &&
                 ((row->state == KSWORD_ARK_RESEARCH_EVIDENCE_AVAILABLE &&
                    row->lastStatus >= 0L && row->value0 != 0ULL &&
                    row->value1 != 0ULL &&
                    (row->value1 & ~static_cast<unsigned long long>(
                        knownSourceMask)) == 0ULL &&
                    (row->value2 & ~static_cast<unsigned long long>(
                        knownResponseFlags)) == 0ULL &&
                    (row->value2 &
                        KSWORD_ARK_RESEARCH_RESPONSE_TRUNCATED) == 0ULL &&
                    row->value2 ==
                        (response->responseFlags &
                            ~KSWORD_ARK_RESEARCH_RESPONSE_TRUNCATED) &&
                    std::strncmp(row->name, "IOCTL_KSWORD_ARK_", 17U) == 0) ||
                  (row->state == KSWORD_ARK_RESEARCH_EVIDENCE_UNAVAILABLE &&
                    row->lastStatus < 0L && row->value0 == 0ULL &&
                    row->value1 == 0ULL && row->value2 == 0ULL)));
            const bool validRow =
                row->size == sizeof(*row) &&
                row->kind == expectedKind &&
                row->fieldId == expectedFieldId &&
                row->sourceMask == expectedSourceMask &&
                (row->sourceMask & ~knownSourceMask) == 0UL &&
                (row->state == KSWORD_ARK_RESEARCH_EVIDENCE_AVAILABLE ||
                 row->state == KSWORD_ARK_RESEARCH_EVIDENCE_UNAVAILABLE) &&
                row->confidence == KSWORD_ARK_RESEARCH_CONFIDENCE_RUNTIME &&
                commonMetadataValid &&
                ioctlMetadataValid &&
                nameBufferTerminated;
            if (!validRow)
            {
                failProtocol("evidence row rejected");
                return result;
            }

            const bool commonValuesMatch =
                (index != 0U ||
                    (row->value0 == response->requestorProcessId &&
                     row->value1 == response->requestorThreadId &&
                     row->value2 == response->requestorMode &&
                     row->value3 == response->requestorModeMirror)) &&
                (index != 1U ||
                    (row->value0 == response->currentIrql &&
                     row->value1 == response->processorGroup &&
                     row->value2 == response->processorNumber &&
                     row->value3 == response->activeProcessorCount)) &&
                (index != 2U ||
                    (row->value0 == response->systemTime100ns &&
                     row->value1 == response->interruptTime100ns &&
                     row->value2 == response->performanceCounter &&
                     row->value3 == response->performanceFrequency)) &&
                (index != 3U ||
                    (row->value0 == response->driverObjectAddress &&
                     row->value1 == response->deviceObjectAddress &&
                     row->value2 == response->topAttachedDeviceAddress &&
                     row->value3 == response->deviceObjectPhysicalAddress));
            if (!commonValuesMatch)
            {
                failProtocol("evidence row rejected");
                return result;
            }
            result.entries.push_back(*row);
        }

        result.io.ntStatus = response->lastStatus;
        std::ostringstream stream;
        stream << operationName
            << " topic=" << topicId
            << ", status=" << response->queryStatus
            << ", rows=" << result.entries.size() << "/"
            << response->totalCount
            << ", registeredIoctls=" << response->registeredIoctlCount
            << ", duplicates=" << response->duplicateIoctlCount
            << ", flags=0x" << std::hex << response->responseFlags;
        result.io.message = stream.str();
        return result;
    }
}
