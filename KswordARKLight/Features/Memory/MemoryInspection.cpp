#include "MemoryInspection.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace Ksword::Features::Memory {
namespace {

bool IsPrintableAscii(const std::uint8_t value) noexcept {
    return value >= 0x20U && value <= 0x7EU;
}

wchar_t PrintableAsciiOrDot(const std::uint8_t value) noexcept {
    return IsPrintableAscii(value) ? static_cast<wchar_t>(value) : L'.';
}

std::wstring FormatAddress(const std::uint64_t value) {
    std::wostringstream output;
    output << L"0x" << std::uppercase << std::hex << std::setfill(L'0') << std::setw(16) << value;
    return output.str();
}

void AppendTextRun(std::wstring& output,
    const wchar_t* encoding,
    const std::uint64_t address,
    const std::wstring& value) {
    output += encoding;
    output += L" ";
    output += FormatAddress(address);
    output += L": ";
    output += value;
    output += L"\r\n";
}

} // namespace

std::wstring RenderMemorySnapshotHexAscii(
    const MemoryReadSnapshot& snapshot,
    std::size_t bytesPerLine) {
    if (bytesPerLine == 0U) {
        bytesPerLine = 16U;
    }

    std::wostringstream output;
    output << L"Address             Hex";
    const std::size_t padding = bytesPerLine > 1U ? bytesPerLine * 3U - 3U : 2U;
    output << std::wstring(padding > 3U ? padding - 3U : 1U, L' ') << L" ASCII\r\n";
    for (std::size_t offset = 0U; offset < snapshot.bytes.size(); offset += bytesPerLine) {
        const std::size_t lineSize = (std::min)(bytesPerLine, snapshot.bytes.size() - offset);
        output << FormatAddress(snapshot.address + offset) << L"  ";
        for (std::size_t index = 0U; index < bytesPerLine; ++index) {
            if (index < lineSize) {
                output << std::uppercase << std::hex << std::setfill(L'0') << std::setw(2)
                    << static_cast<unsigned>(snapshot.bytes[offset + index]) << L" ";
            } else {
                output << L"   ";
            }
        }
        output << std::dec << L" ";
        for (std::size_t index = 0U; index < lineSize; ++index) {
            output << PrintableAsciiOrDot(snapshot.bytes[offset + index]);
        }
        output << L"\r\n";
    }
    return output.str();
}

std::wstring ExtractMemorySnapshotText(
    const MemoryReadSnapshot& snapshot,
    std::size_t minimumRunLength) {
    minimumRunLength = (std::max)(std::size_t{ 1U }, minimumRunLength);
    std::wstring output;

    for (std::size_t offset = 0U; offset < snapshot.bytes.size();) {
        if (!IsPrintableAscii(snapshot.bytes[offset])) {
            ++offset;
            continue;
        }
        const std::size_t start = offset;
        std::wstring text;
        while (offset < snapshot.bytes.size() && IsPrintableAscii(snapshot.bytes[offset])) {
            text.push_back(static_cast<wchar_t>(snapshot.bytes[offset]));
            ++offset;
        }
        if (text.size() >= minimumRunLength) {
            AppendTextRun(output, L"ASCII", snapshot.address + start, text);
        }
    }

    for (std::size_t offset = 0U; offset + 1U < snapshot.bytes.size();) {
        if (!IsPrintableAscii(snapshot.bytes[offset]) || snapshot.bytes[offset + 1U] != 0U) {
            ++offset;
            continue;
        }
        const std::size_t start = offset;
        std::wstring text;
        while (offset + 1U < snapshot.bytes.size() && IsPrintableAscii(snapshot.bytes[offset]) &&
            snapshot.bytes[offset + 1U] == 0U) {
            text.push_back(static_cast<wchar_t>(snapshot.bytes[offset]));
            offset += 2U;
        }
        if (text.size() >= minimumRunLength) {
            AppendTextRun(output, L"UTF-16LE", snapshot.address + start, text);
        }
    }

    return output.empty() ? L"未发现长度足够的 ASCII 或 UTF-16LE 文本。\r\n" : output;
}

std::wstring BuildMemorySnapshotTextReport(const MemoryReadSnapshot& snapshot) {
    std::wostringstream output;
    output << L"[Memory Snapshot]\r\n"
           << L"Sequence: " << snapshot.sequence << L"\r\n"
           << L"PID: " << snapshot.processId << L"\r\n"
           << L"BaseAddress: " << FormatAddress(snapshot.address) << L"\r\n"
           << L"RequestedBytes: " << snapshot.requestedBytes << L"\r\n"
           << L"ReturnedBytes: " << snapshot.bytes.size() << L"\r\n"
           << L"Status: " << snapshot.statusText << L"\r\n\r\n"
           << L"[Hex ASCII]\r\n" << RenderMemorySnapshotHexAscii(snapshot) << L"\r\n"
           << L"[Text Runs]\r\n" << ExtractMemorySnapshotText(snapshot);
    return output.str();
}

} // namespace Ksword::Features::Memory
