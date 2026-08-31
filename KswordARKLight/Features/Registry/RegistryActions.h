#pragma once

#include "RegistryModel.h"
#include "RegistrySearchModel.h"

#include <atomic>
#include <memory>

namespace Ksword::Features::Registry {

// EnumerateRegistryKey reads subkeys and values for one registry path. Inputs
// are a display/kernel path and transport mode; processing uses WinAPI or
// ArkDriverClient; output is a snapshot for the view.
RegistrySnapshot EnumerateRegistryKey(const std::wstring& path, RegistryViewMode mode);

// EnumerateRegistrySubKeyNames reads only the direct child key names for one
// registry path. Inputs are a display/kernel path and transport mode; processing
// does not enumerate values and never recurses; output is used by the lazy
// TreeView expansion logic.
std::vector<std::wstring> EnumerateRegistrySubKeyNames(const std::wstring& path, RegistryViewMode mode, std::wstring* statusTextOut = nullptr);

// SearchRegistryWinApi walks one WinAPI registry subtree with fixed work,
// result, depth and preview bounds.  Inputs are a search request and an
// optional shared cancellation token; processing never uses the driver or the
// R0 browser mode; output is one immutable partial-or-complete snapshot.
RegistrySearchSnapshot SearchRegistryWinApi(
    const RegistrySearchRequest& request,
    const std::shared_ptr<std::atomic_bool>& cancelToken);

// ReadRegistryValue reads a single value. Inputs are key path, value name, and
// transport mode; output contains raw bytes and status text.
RegistryOperationResult ReadRegistryValue(const std::wstring& path, const std::wstring& valueName, RegistryViewMode mode);

// WriteRegistryValue writes a value. Inputs are path, value name, REG_* type,
// raw bytes and mode; output is a status object.
RegistryOperationResult WriteRegistryValue(const std::wstring& path, const std::wstring& valueName, std::uint32_t type, const std::vector<std::uint8_t>& data, RegistryViewMode mode);

// DeleteRegistryValue removes one value. Inputs are path, value name and mode;
// output describes whether deletion succeeded.
RegistryOperationResult DeleteRegistryValue(const std::wstring& path, const std::wstring& valueName, RegistryViewMode mode);

// CreateRegistryKey creates one key. Inputs are full key path and mode; output
// describes the operation result.
RegistryOperationResult CreateRegistryKey(const std::wstring& path, RegistryViewMode mode);

// DeleteRegistryKey deletes one key/subtree. Inputs are full key path and mode;
// output describes the operation result.
RegistryOperationResult DeleteRegistryKey(const std::wstring& path, RegistryViewMode mode);

// RenameRegistryValue renames one value under a key. Inputs are key path, old
// value name, new value name and mode; output describes the operation result.
RegistryOperationResult RenameRegistryValue(const std::wstring& path, const std::wstring& oldName, const std::wstring& newName, RegistryViewMode mode);

// RenameRegistryKey renames the final key component. Inputs are full key path,
// new leaf name and mode; output describes the operation result.
RegistryOperationResult RenameRegistryKey(const std::wstring& path, const std::wstring& newName, RegistryViewMode mode);

// CopyRegistryTextToClipboard writes Unicode text to the clipboard. Inputs are
// owner HWND and text; output is true when Windows accepts ownership.
bool CopyRegistryTextToClipboard(HWND owner, const std::wstring& text);

} // namespace Ksword::Features::Registry
