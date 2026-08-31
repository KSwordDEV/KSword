#include "EtwEventModel.h"

#include <algorithm>
#include <cstdio>
#include <iterator>

namespace Ksword::Features::Monitor {
namespace {

std::wstring SanitizeTsvCell(std::wstring value) {
    for (wchar_t& character : value) {
        if (character == L'\t' || character == L'\r' || character == L'\n') {
            character = L' ';
        }
    }
    return value;
}

void AppendTsvCell(std::wstring& output, const std::wstring& value, const bool firstCell) {
    if (!firstCell) {
        output.push_back(L'\t');
    }
    output += SanitizeTsvCell(value);
}

void AppendTsvEventRow(std::wstring& output, const EtwEvent& eventRow) {
    AppendTsvCell(output, std::to_wstring(eventRow.processId), true);
    AppendTsvCell(output, eventRow.timeText, false);
    AppendTsvCell(output, eventRow.providerText, false);
    AppendTsvCell(output, std::to_wstring(eventRow.threadId), false);
    AppendTsvCell(output, std::to_wstring(eventRow.eventId), false);
    AppendTsvCell(output, std::to_wstring(static_cast<unsigned int>(eventRow.level)), false);
    AppendTsvCell(output, eventRow.summary, false);
    output += L"\r\n";
}

} // namespace

EtwEventModel::EtwEventModel(const std::size_t maxRows)
    : maxRows_(maxRows == 0 ? 1 : maxRows) {}

void EtwEventModel::append(const EtwEvent& eventRow) {
    std::lock_guard<std::mutex> lock(mutex_);
    rows_.push_back(eventRow);
    if (rows_.size() > maxRows_) {
        const std::size_t extraCount = rows_.size() - maxRows_;
        rows_.erase(rows_.begin(), rows_.begin() + static_cast<std::ptrdiff_t>(extraCount));
    }
}

void EtwEventModel::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    rows_.clear();
}

std::vector<EtwEvent> EtwEventModel::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rows_;
}

std::size_t EtwEventModel::rowCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rows_.size();
}

std::wstring GuidToString(const GUID& value) {
    wchar_t buffer[64] = {};
    const int written = std::swprintf(
        buffer,
        std::size(buffer),
        L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        static_cast<unsigned long>(value.Data1),
        value.Data2,
        value.Data3,
        value.Data4[0],
        value.Data4[1],
        value.Data4[2],
        value.Data4[3],
        value.Data4[4],
        value.Data4[5],
        value.Data4[6],
        value.Data4[7]);
    return written > 0 ? std::wstring(buffer, static_cast<std::size_t>(written)) : L"{}";
}

std::wstring FileTimeToLocalText(const LARGE_INTEGER& timestamp) {
    FILETIME utcTime{};
    utcTime.dwLowDateTime = timestamp.LowPart;
    utcTime.dwHighDateTime = static_cast<DWORD>(timestamp.HighPart);

    FILETIME localTime{};
    SYSTEMTIME systemTime{};
    if (::FileTimeToLocalFileTime(&utcTime, &localTime) == FALSE ||
        ::FileTimeToSystemTime(&localTime, &systemTime) == FALSE) {
        return L"-";
    }

    wchar_t buffer[64] = {};
    const int written = std::swprintf(
        buffer,
        std::size(buffer),
        L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
        systemTime.wYear,
        systemTime.wMonth,
        systemTime.wDay,
        systemTime.wHour,
        systemTime.wMinute,
        systemTime.wSecond,
        systemTime.wMilliseconds);
    return written > 0 ? std::wstring(buffer, static_cast<std::size_t>(written)) : L"-";
}

std::wstring BuildVisibleEtwEventsTsv(
    const std::vector<EtwEvent>& rows,
    const std::vector<std::size_t>& visibleIndexes) {
    std::wstring output;
    bool wroteRow = false;
    for (const std::size_t sourceIndex : visibleIndexes) {
        if (sourceIndex >= rows.size()) {
            continue;
        }
        if (!wroteRow) {
            output = L"PID\t时间\tProvider\tTID\tEventId\tLevel\t摘要\r\n";
            wroteRow = true;
        }
        AppendTsvEventRow(output, rows[sourceIndex]);
    }
    return output;
}

} // namespace Ksword::Features::Monitor
