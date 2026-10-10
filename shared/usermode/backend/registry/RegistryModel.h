#pragma once

#include "../Win32.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ks::r3::registry {

// RegistryValueKind identifies what a displayed row represents. Inputs are set
// by R3/R0 enumeration code; processing in the view uses the value to choose
// context-menu commands; no behavior is embedded in the enum itself.
enum class RegistryRowKind {
    SubKey,
    Value
};

// RegistryViewMode chooses whether enumeration uses normal Win32 registry APIs
// or the KswordARK R0 registry IOCTL facade. Inputs come from the toolbar; output
// influences only the next refresh/read/write command.
enum class RegistryViewMode {
    WinApi,
    R0
};

// RegistryEntry is one visible row in the registry dock. Inputs are collected
// from either RegEnumKeyEx/RegEnumValue or ArkDriverClient; processing stores
// stable display fields and raw bytes for copy/read actions.
struct RegistryEntry {
    RegistryRowKind kind = RegistryRowKind::SubKey;
    std::wstring name;
    std::wstring typeText;
    std::wstring dataText;
    std::wstring detailText;
    std::uint32_t valueType = 0;
    std::vector<std::uint8_t> data;
};

// RegistrySnapshot is the result of enumerating one key. Inputs are a requested
// path and mode; processing fills rows and status; output is consumed by the
// Win32 view.
struct RegistrySnapshot {
    bool success = false;
    RegistryViewMode mode = RegistryViewMode::WinApi;
    std::wstring displayPath;
    std::wstring kernelPath;
    std::wstring statusText;
    std::vector<RegistryEntry> rows;
    bool complete = false;
    std::uint32_t win32Error = 0;
};

// RegistryOperationResult describes create/delete/rename/write/read commands.
// Inputs depend on the operation; processing is done in RegistryActions; output
// is a compact status plus optional returned data.
struct RegistryOperationResult {
    bool success = false;
    DWORD win32Error = ERROR_SUCCESS;
    long ntStatus = 0;
    std::wstring statusText;
    std::vector<std::uint8_t> data;
    std::uint32_t valueType = 0;
    bool partial = false, unchanged = false, dispositionKnown = false, created = false;
};

// RegistryPathInfo is the parsed form of a user path. Inputs are root aliases
// such as HKLM\Software or kernel paths such as \REGISTRY\MACHINE\Software;
// processing resolves Win32 and kernel paths; output is used by both transports.
struct RegistryPathInfo {
    bool valid = false;
    HKEY root = nullptr;
    std::wstring rootText;
    std::wstring subKey;
    std::wstring displayPath;
    std::wstring kernelPath;
    std::wstring errorText;
};

// ParseRegistryPath converts display/kernel registry paths into a common model.
// Input is raw user text; output contains Win32 root/subkey plus kernel path.
RegistryPathInfo ParseRegistryPath(const std::wstring& text);

// ParentRegistryPath returns the direct parent path of one registry key.
// Inputs are a display path such as HKLM\Software\Classes; output keeps the
// same root and removes one trailing segment; root keys are returned unchanged.
std::wstring ParentRegistryPath(const std::wstring& text);

// RootRegistryPath returns the canonical root path for a display path. Inputs
// are any registry path; output is HKCR/HKCU/HKLM/HKU/HKCC or empty on failure.
std::wstring RootRegistryPath(const std::wstring& text);

// RegistryTypeText converts REG_* constants into display text. Input is a value
// type from Win32 or R0; output is a stable label.
std::wstring RegistryTypeText(std::uint32_t type);

// FormatRegistryData converts raw registry value bytes to compact display text.
// Inputs are value type and byte buffer; processing decodes common string/DWORD
// forms and falls back to hex; output is safe for list controls.
std::wstring FormatRegistryData(std::uint32_t type, const std::vector<std::uint8_t>& data);

// ParseRegistryDataText converts user-entered text into raw bytes for the given
// REG_* type. Inputs are type and edit text; output is true with bytes or false
// with errorText.
bool ParseRegistryDataText(std::uint32_t type, const std::wstring& text, std::vector<std::uint8_t>& bytes, std::wstring& errorText);

} // namespace ks::r3::registry
