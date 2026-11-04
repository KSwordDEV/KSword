#include "ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <cwchar>
#include <sstream>

namespace ksword::ark
{
    namespace
    {
        std::wstring fixedWide(
            const wchar_t* const text,
            const std::size_t capacity)
        {
            if (text == nullptr || capacity == 0U)
            {
                return {};
            }
            std::size_t length = 0U;
            while (length < capacity && text[length] != L'\0')
            {
                ++length;
            }
            return std::wstring(text, text + std::min(length, capacity));
        }

        bool unsupportedError(const unsigned long error)
        {
            return error == ERROR_INVALID_FUNCTION ||
                error == ERROR_NOT_SUPPORTED;
        }
    }

    PiDdbQueryResult DriverClient::queryPiDdb(
        const unsigned long maxRows) const
    {
        PiDdbQueryResult result{};
        KSWORD_ARK_QUERY_PIDDB_REQUEST request{};
        request.version = KSWORD_ARK_PIDDB_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.maxRows = std::min<unsigned long>(
            maxRows == 0UL ? KSWORD_ARK_PIDDB_DEFAULT_ROWS : maxRows,
            KSWORD_ARK_PIDDB_MAX_ROWS);

        const std::size_t responseBytes =
            KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE +
            static_cast<std::size_t>(request.maxRows) *
                sizeof(KSWORD_ARK_PIDDB_ROW);
        std::vector<std::uint8_t> responseBuffer(responseBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_PIDDB,
            &request,
            sizeof(request),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        result.unsupported = !result.io.ok &&
            unsupportedError(result.io.win32Error);
        if (result.io.bytesReturned < KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE ||
            result.io.bytesReturned > responseBuffer.size())
        {
            if (result.io.ok) { result.io.ok = false; result.io.win32Error = ERROR_INVALID_DATA; }
            if (result.io.message.empty())
            {
                result.io.message = "PiDDB response length is invalid";
            }
            return result;
        }

        const auto* response =
            reinterpret_cast<const KSWORD_ARK_QUERY_PIDDB_RESPONSE*>(
                responseBuffer.data());
        const std::size_t availableRows =
            (result.io.bytesReturned - KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE) /
            sizeof(KSWORD_ARK_PIDDB_ROW);
        if (response->version != KSWORD_ARK_PIDDB_PROTOCOL_VERSION ||
            response->rowSize != sizeof(KSWORD_ARK_PIDDB_ROW) ||
            response->size < KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE ||
            response->size > result.io.bytesReturned ||
            response->returnedRows > response->totalRows ||
            response->returnedRows > availableRows ||
            response->returnedRows > request.maxRows ||
            response->returnedRows > (response->size - KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_PIDDB_ROW))
        {
            if (result.io.ok) { result.io.ok = false; result.io.win32Error = ERROR_INVALID_DATA; }
            result.io.message = "PiDDB response version, stride, size or row count is invalid";
            return result;
        }
        result.queryStatus = response->queryStatus;
        result.responseFlags = response->responseFlags;
        result.totalRows = response->totalRows;
        result.lastStatus = response->lastStatus;
        result.io.ntStatus = response->lastStatus;
        const std::size_t returnedRows = std::min<std::size_t>(
            response->returnedRows,
            availableRows);
        result.entries.reserve(returnedRows);
        for (std::size_t index = 0U; index < returnedRows; ++index)
        {
            const KSWORD_ARK_PIDDB_ROW& source = response->rows[index];
            PiDdbEntry entry{};
            entry.entryAddress = source.entryAddress;
            entry.timeDateStamp = source.timeDateStamp;
            entry.loadStatus = source.loadStatus;
            entry.driverName = fixedWide(
                source.driverName,
                KSWORD_ARK_PIDDB_NAME_CHARS);
            result.entries.push_back(std::move(entry));
        }

        std::ostringstream stream;
        stream << "PiDDB query status=" << result.queryStatus
            << ", rows=" << result.entries.size()
            << "/" << result.totalRows
            << ", ntstatus=0x" << std::hex
            << static_cast<unsigned long>(result.lastStatus);
        result.io.message = stream.str();
        return result;
    }

    PiDdbDeleteResult DriverClient::deletePiDdbEntry(
        const PiDdbEntry& expectedEntry,
        const bool force,
        const bool uiConfirmed) const
    {
        PiDdbDeleteResult result{};
        KSWORD_ARK_DELETE_PIDDB_REQUEST request{};
        KSWORD_ARK_DELETE_PIDDB_RESPONSE response{};
        request.version = KSWORD_ARK_PIDDB_PROTOCOL_VERSION;
        request.size = sizeof(request);
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_PIDDB_DELETE_FLAG_UI_CONFIRMED;
        }
        if (force)
        {
            request.flags |= KSWORD_ARK_PIDDB_DELETE_FLAG_FORCE;
        }
        request.confirmationToken =
            KSWORD_ARK_PIDDB_DELETE_CONFIRMATION_TOKEN;
        request.expectedEntryAddress = expectedEntry.entryAddress;
        request.expectedTimeDateStamp = expectedEntry.timeDateStamp;
        request.expectedLoadStatus = expectedEntry.loadStatus;
        const std::size_t copyChars = std::min<std::size_t>(
            expectedEntry.driverName.size(),
            KSWORD_ARK_PIDDB_NAME_CHARS - 1U);
        std::copy_n(
            expectedEntry.driverName.data(),
            copyChars,
            request.driverName);
        request.driverName[copyChars] = L'\0';

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_DELETE_PIDDB,
            &request,
            sizeof(request),
            &response,
            sizeof(response));
        result.unsupported = !result.io.ok &&
            unsupportedError(result.io.win32Error);
        if (!result.io.ok) return result;
        if (result.io.bytesReturned < sizeof(response) ||
            result.io.bytesReturned > sizeof(response) ||
            response.version != KSWORD_ARK_PIDDB_PROTOCOL_VERSION ||
            response.size != sizeof(response))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "PiDDB delete response version or size is invalid";
            return result;
        }
        result.status = response.status;
        result.remainingRows = response.remainingRows;
        result.lastStatus = response.lastStatus;
        result.io.ntStatus = response.lastStatus;
        result.matchedEntry.entryAddress = response.matchedEntryAddress;
        result.matchedEntry.timeDateStamp =
            response.matchedTimeDateStamp;
        result.matchedEntry.loadStatus = response.matchedLoadStatus;
        result.matchedEntry.driverName = fixedWide(
            response.matchedDriverName,
            KSWORD_ARK_PIDDB_NAME_CHARS);

        std::ostringstream stream;
        stream << "PiDDB " << (force ? "delete" : "preflight")
            << ", status=" << result.status
            << ", remaining=" << result.remainingRows
            << ", ntstatus=0x" << std::hex
            << static_cast<unsigned long>(result.lastStatus);
        result.io.message = stream.str();
        return result;
    }
}
