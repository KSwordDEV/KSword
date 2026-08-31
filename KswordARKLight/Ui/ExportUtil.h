#pragma once

#include "../Core/Win32Lean.h"
#include "VirtualListView.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Ui {

// SaveTextFileResult distinguishes an intentional dialog cancellation from a
// failed write so a feature page can keep its local status text accurate.
enum class SaveTextFileResult {
    Saved,
    Cancelled,
    Failed
};

// BuildVisibleVirtualListTsv serializes the currently visible rows of a virtual
// list with the supplied column captions. It deliberately follows the active
// filter rather than exporting hidden rows.
std::wstring BuildVisibleVirtualListTsv(
    const std::vector<std::wstring>& columnTitles,
    const VirtualListView& list);

// CopyTextToClipboard centralizes CF_UNICODETEXT export and records the exact
// text in the current evidence session when the clipboard transfer succeeds.
bool CopyTextToClipboard(
    HWND owner,
    const std::wstring& text,
    const std::wstring& source = L"剪贴板导出");

// SaveUtf8TextFileWithDialog asks for a destination and writes text as UTF-8
// with a BOM. The suggested name, file filter and default extension describe
// the caller's page-specific export. errorOut is filled only for Failed.
SaveTextFileResult SaveUtf8TextFileWithDialog(
    HWND owner,
    const wchar_t* suggestedFileName,
    const wchar_t* dialogTitle,
    const wchar_t* fileFilter,
    const wchar_t* defaultExtension,
    const std::wstring& text,
    std::wstring* errorOut = nullptr);

// SaveBinaryFileWithDialog writes opaque bytes without changing their encoding.
// evidenceText is deliberately separate from the byte payload: the evidence
// session records an auditable description without duplicating arbitrary binary
// contents into a text-only investigation log.
SaveTextFileResult SaveBinaryFileWithDialog(
    HWND owner,
    const wchar_t* suggestedFileName,
    const wchar_t* dialogTitle,
    const wchar_t* fileFilter,
    const wchar_t* defaultExtension,
    const std::vector<std::uint8_t>& bytes,
    const std::wstring& evidenceSource,
    const std::wstring& evidenceText,
    std::wstring* errorOut = nullptr);

} // namespace Ksword::Ui
