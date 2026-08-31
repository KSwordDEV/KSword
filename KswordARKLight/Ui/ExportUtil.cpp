#include "ExportUtil.h"

#include "EvidenceSession.h"

#include <commdlg.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#pragma comment(lib, "Comdlg32.lib")

namespace Ksword::Ui {
namespace {

std::wstring SanitizeTsvCell(std::wstring cell) {
    for (wchar_t& character : cell) {
        if (character == L'\t' || character == L'\r' || character == L'\n') {
            character = L' ';
        }
    }
    return cell;
}

void AppendTsvRow(std::wstring& output, const std::vector<std::wstring>& cells) {
    for (std::size_t column = 0; column < cells.size(); ++column) {
        if (column != 0) {
            output.push_back(L'\t');
        }
        output += SanitizeTsvCell(cells[column]);
    }
    output += L"\r\n";
}

bool WriteAll(HANDLE file, const void* data, const std::size_t byteCount, std::wstring* errorOut) {
    if (byteCount == 0U) {
        return true;
    }
    if (!data) {
        if (errorOut) {
            *errorOut = L"导出数据为空。";
        }
        return false;
    }
    const auto* bytes = static_cast<const char*>(data);
    std::size_t offset = 0;
    while (offset < byteCount) {
        const std::size_t remaining = byteCount - offset;
        const DWORD chunk = static_cast<DWORD>((std::min)(
            remaining, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!::WriteFile(file, bytes + offset, chunk, &written, nullptr) || written != chunk) {
            if (errorOut) {
                *errorOut = L"WriteFile 失败，错误 " + std::to_wstring(::GetLastError()) + L"。";
            }
            return false;
        }
        offset += written;
    }
    return true;
}

SaveTextFileResult ChooseSavePath(HWND owner,
    const wchar_t* suggestedFileName,
    const wchar_t* dialogTitle,
    const wchar_t* fileFilter,
    const wchar_t* defaultExtension,
    std::array<wchar_t, MAX_PATH>& path,
    std::wstring* errorOut) {
    if (suggestedFileName) {
        ::wcsncpy_s(path.data(), path.size(), suggestedFileName, _TRUNCATE);
    }
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = owner;
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.lpstrTitle = dialogTitle;
    dialog.lpstrFilter = fileFilter;
    dialog.lpstrDefExt = defaultExtension;
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (::GetSaveFileNameW(&dialog)) {
        return SaveTextFileResult::Saved;
    }
    const DWORD error = ::CommDlgExtendedError();
    if (error != 0 && errorOut) {
        *errorOut = L"保存对话框失败，错误 " + std::to_wstring(error) + L"。";
    }
    return error == 0 ? SaveTextFileResult::Cancelled : SaveTextFileResult::Failed;
}

SaveTextFileResult WriteExportFile(const std::array<wchar_t, MAX_PATH>& path,
    const void* data,
    const std::size_t byteCount,
    std::wstring* errorOut) {
    HANDLE file = ::CreateFileW(path.data(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (errorOut) {
            *errorOut = L"无法写入文件，错误 " + std::to_wstring(::GetLastError()) + L"。";
        }
        return SaveTextFileResult::Failed;
    }
    const bool written = WriteAll(file, data, byteCount, errorOut);
    const DWORD closeError = ::CloseHandle(file) ? ERROR_SUCCESS : ::GetLastError();
    if (!written || closeError != ERROR_SUCCESS) {
        if (written && errorOut) {
            *errorOut = L"关闭导出文件失败，错误 " + std::to_wstring(closeError) + L"。";
        }
        return SaveTextFileResult::Failed;
    }
    return SaveTextFileResult::Saved;
}

std::vector<char> ToUtf8WithBom(const std::wstring& text, std::wstring* errorOut) {
    const int count = text.empty()
        ? 0
        : ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!text.empty() && count <= 0) {
        if (errorOut) {
            *errorOut = L"WideCharToMultiByte 失败，错误 " + std::to_wstring(::GetLastError()) + L"。";
        }
        return {};
    }
    std::vector<char> bytes;
    bytes.reserve(3U + static_cast<std::size_t>(count));
    bytes.insert(bytes.end(), { static_cast<char>(0xEF), static_cast<char>(0xBB), static_cast<char>(0xBF) });
    if (count > 0) {
        const std::size_t offset = bytes.size();
        bytes.resize(offset + static_cast<std::size_t>(count));
        if (::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), bytes.data() + offset,
                count, nullptr, nullptr) != count) {
            if (errorOut) {
                *errorOut = L"WideCharToMultiByte 失败，错误 " + std::to_wstring(::GetLastError()) + L"。";
            }
            return {};
        }
    }
    return bytes;
}

} // namespace

std::wstring BuildVisibleVirtualListTsv(
    const std::vector<std::wstring>& columnTitles,
    const VirtualListView& list) {
    if (columnTitles.empty() || list.visibleIndexes().empty()) {
        return {};
    }
    std::wstring output;
    AppendTsvRow(output, columnTitles);
    const auto& rows = list.rows();
    for (const std::size_t index : list.visibleIndexes()) {
        if (index < rows.size()) {
            AppendTsvRow(output, rows[index].cells);
        }
    }
    return output;
}

bool CopyTextToClipboard(HWND owner, const std::wstring& text, const std::wstring& source) {
    if (text.empty() || !::OpenClipboard(owner)) {
        return false;
    }
    if (!::EmptyClipboard()) {
        ::CloseClipboard();
        return false;
    }
    const SIZE_T bytes = (text.size() + 1U) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!memory) {
        ::CloseClipboard();
        return false;
    }
    void* target = ::GlobalLock(memory);
    if (!target) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    std::memcpy(target, text.c_str(), bytes);
    ::GlobalUnlock(memory);
    if (!::SetClipboardData(CF_UNICODETEXT, memory)) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    ::CloseClipboard();
    GlobalEvidenceSession().record(source.empty() ? L"剪贴板导出" : source, L"text", text);
    return true;
}

SaveTextFileResult SaveUtf8TextFileWithDialog(
    HWND owner,
    const wchar_t* suggestedFileName,
    const wchar_t* dialogTitle,
    const wchar_t* fileFilter,
    const wchar_t* defaultExtension,
    const std::wstring& text,
    std::wstring* errorOut) {
    if (errorOut) {
        errorOut->clear();
    }
    std::array<wchar_t, MAX_PATH> path{};
    const SaveTextFileResult selection = ChooseSavePath(owner, suggestedFileName, dialogTitle, fileFilter, defaultExtension, path, errorOut);
    if (selection != SaveTextFileResult::Saved) {
        return selection;
    }

    std::wstring conversionError;
    const std::vector<char> bytes = ToUtf8WithBom(text, &conversionError);
    if (bytes.empty()) {
        if (errorOut) {
            *errorOut = conversionError.empty() ? L"无法转换导出文本。" : conversionError;
        }
        return SaveTextFileResult::Failed;
    }
    const SaveTextFileResult writeResult = WriteExportFile(path, bytes.data(), bytes.size(), errorOut);
    if (writeResult != SaveTextFileResult::Saved) {
        return writeResult;
    }
    GlobalEvidenceSession().record(
        dialogTitle ? dialogTitle : L"文件导出",
        defaultExtension ? defaultExtension : L"text",
        text);
    return SaveTextFileResult::Saved;
}

SaveTextFileResult SaveBinaryFileWithDialog(
    HWND owner,
    const wchar_t* suggestedFileName,
    const wchar_t* dialogTitle,
    const wchar_t* fileFilter,
    const wchar_t* defaultExtension,
    const std::vector<std::uint8_t>& bytes,
    const std::wstring& evidenceSource,
    const std::wstring& evidenceText,
    std::wstring* errorOut) {
    if (errorOut) {
        errorOut->clear();
    }
    if (bytes.empty()) {
        if (errorOut) {
            *errorOut = L"没有可导出的二进制字节。";
        }
        return SaveTextFileResult::Failed;
    }
    std::array<wchar_t, MAX_PATH> path{};
    const SaveTextFileResult selection = ChooseSavePath(owner, suggestedFileName, dialogTitle, fileFilter, defaultExtension, path, errorOut);
    if (selection != SaveTextFileResult::Saved) {
        return selection;
    }
    const SaveTextFileResult writeResult = WriteExportFile(path, bytes.data(), bytes.size(), errorOut);
    if (writeResult != SaveTextFileResult::Saved) {
        return writeResult;
    }
    GlobalEvidenceSession().record(
        evidenceSource.empty() ? L"二进制文件导出" : evidenceSource,
        defaultExtension ? defaultExtension : L"binary",
        evidenceText.empty() ? L"二进制导出已完成。" : evidenceText);
    return SaveTextFileResult::Saved;
}

} // namespace Ksword::Ui
