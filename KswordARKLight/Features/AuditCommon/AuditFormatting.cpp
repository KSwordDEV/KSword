#include "AuditFormatting.h"

#include "AuditStatus.h"
#include "../../Ui/ExportUtil.h"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace Ksword::Features::AuditCommon {

std::wstring FormatHexValue(const std::uint64_t value, const int minimumDigits) {
    // The output intentionally avoids locale-specific grouping so addresses and
    // protocol bitfields remain stable across machines and exports.
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex;
    if (minimumDigits > 0) {
        stream << std::setw(minimumDigits) << std::setfill(L'0');
    }
    stream << value;
    return stream.str();
}

std::wstring FormatHexAddress(const std::uint64_t value) {
    return FormatHexValue(value, sizeof(void*) == 8 ? 16 : 8);
}

std::wstring FormatNtStatus(const LONG status) {
    const std::uint32_t raw = static_cast<std::uint32_t>(status);
    const AuditStatus auditStatus = AuditStatusFromNtStatus(status);
    const AuditStatusInfo info = DescribeAuditStatus(auditStatus);
    return FormatHexValue(raw, 8) + L" (" + info.label + L")";
}

std::wstring FormatWin32Error(const DWORD errorCode) {
    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD chars = ::FormatMessageW(
        flags,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    std::wstring message;
    if (chars != 0 && buffer) {
        message.assign(buffer, buffer + chars);
        while (!message.empty() &&
            (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ' || message.back() == L'\t')) {
            message.pop_back();
        }
        ::LocalFree(buffer);
    } else {
        message = L"Win32 error " + std::to_wstring(errorCode);
    }

    return L"Win32 " + std::to_wstring(errorCode) + L": " + message;
}

std::wstring SanitizeTsvCell(const std::wstring& text) {
    std::wstring sanitized = text;
    for (wchar_t& ch : sanitized) {
        if (ch == L'\t' || ch == L'\r' || ch == L'\n') {
            ch = L' ';
        }
    }
    return sanitized;
}

std::wstring BuildTsv(
    const std::vector<std::wstring>& headers,
    const std::vector<std::vector<std::wstring>>& rows) {
    std::wstring output;
    auto appendRow = [&output](const std::vector<std::wstring>& cells) {
        for (std::size_t index = 0; index < cells.size(); ++index) {
            if (index != 0) {
                output.push_back(L'\t');
            }
            output += SanitizeTsvCell(cells[index]);
        }
        output += L"\r\n";
    };

    if (!headers.empty()) {
        appendRow(headers);
    }
    for (const std::vector<std::wstring>& row : rows) {
        appendRow(row);
    }
    return output;
}

bool CopyTextToClipboard(HWND owner, const std::wstring& text) {
    return Ksword::Ui::CopyTextToClipboard(owner, text, L"审计结果");
}

} // namespace Ksword::Features::AuditCommon
