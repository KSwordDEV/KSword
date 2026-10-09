#include "RegistryActions.h"
#include "../../../shared/usermode/backend/registry/RegistryBackend.h"
#include "../../../shared/usermode/backend/registry/RegistrySupport.h"

#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>
#include <sstream>

namespace Ksword::Features::Registry {
namespace {
using namespace ks::r3::registry::detail;

// UniqueRegKey owns an HKEY returned by RegOpenKeyEx/RegCreateKeyEx. Input is a
// raw handle; processing closes it in the destructor; get returns the borrowed
// handle.


// A registry name is documented as substantially smaller than this bound.  A
// hard local ceiling prevents a malformed/racing enumeration response from
// requesting an unbounded allocation in the background search worker.














// QueryRegistrySearchValueInfo obtains only the value enumeration bounds for a
// handle opened with value-query access.  It keeps partial-ACL value discovery
// separate from subkey enumeration.


// NarrowToWide converts ArkDriverClient ASCII diagnostics to UTF-16. Input is
// client message text; output is displayable wide text.
std::wstring NarrowToWide(const std::string& text) {
    std::wstring wide;
    wide.reserve(text.size());
    for (unsigned char ch : text) {
        wide.push_back(static_cast<wchar_t>(ch));
    }
    return wide;
}

// MakePathError converts a parse failure into a snapshot. Inputs are original
// path, mode and parse result; output is a failed snapshot.


// MakeOperationPathError converts a parse failure into an operation result.
// Input is parse info; output is a failed operation status.


// OpenKey opens a WinAPI registry key. Inputs are parsed path and access mask;
// output is an owning key handle.


// BuildStatusLine creates a common R0 status line. Inputs are operation name,
// transport status, protocol status and NT status; output is shown in the UI.
std::wstring BuildR0StatusLine(const wchar_t* operation, const bool ok, const std::uint32_t status, const long ntStatus, const std::string& message) {
    std::wostringstream stream;
    stream << L"R0 registry " << operation
           << (ok ? L" transport OK" : L" transport failed")
           << L"; status=" << status
           << L"; nt=0x" << std::hex << std::uppercase << static_cast<unsigned long>(ntStatus)
           << L"; " << NarrowToWide(message);
    return stream.str();
}

// AppendWinApiValues enumerates values under one WinAPI key. Inputs are key and
// snapshot; processing appends value rows; no return value.


// AppendWinApiSubKeys enumerates direct child keys. Inputs are key and snapshot;
// processing appends subkey rows; no return value.


// KernelPathRequired verifies that R0 can address the requested path. Input is
// parsed path; output is true for \REGISTRY\MACHINE/USER paths.
bool KernelPathRequired(const RegistryPathInfo& path, RegistryOperationResult& result) {
    if (!path.kernelPath.empty()) {
        return true;
    }
    result.success = false;
    result.win32Error = ERROR_NOT_SUPPORTED;
    result.statusText = L"R0 registry mode currently supports HKLM/HKU or explicit \\REGISTRY\\MACHINE/USER paths.";
    return false;
}

} // namespace

RegistrySnapshot EnumerateRegistryKey(const std::wstring& path, const RegistryViewMode mode) {
    if (mode != RegistryViewMode::R0) {
        auto result = ks::r3::registry::EnumerateRegistryKey(path);
        result.mode = mode;
        return result;
    }

    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakePathError(path, mode, parsed);
    }

    RegistrySnapshot snapshot;
    snapshot.mode = mode;
    snapshot.displayPath = parsed.displayPath;
    snapshot.kernelPath = parsed.kernelPath;


        if (parsed.kernelPath.empty()) {
            snapshot.statusText = L"R0 registry mode supports HKLM/HKU or \\REGISTRY\\MACHINE/USER paths.";
            return snapshot;
        }
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryEnumResult result = client.enumerateRegistryKey(parsed.kernelPath);
        snapshot.success = result.io.ok &&
            (result.status == KSWORD_ARK_REGISTRY_ENUM_STATUS_SUCCESS ||
                result.status == KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL);
        for (const auto& subKey : result.subKeys) {
            RegistryEntry row;
            row.kind = RegistryRowKind::SubKey;
            row.name = subKey.name;
            row.typeText = L"Key";
            row.detailText = L"R0 subkey";
            snapshot.rows.push_back(std::move(row));
        }
        for (const auto& value : result.values) {
            RegistryEntry row;
            row.kind = RegistryRowKind::Value;
            row.name = value.name;
            row.valueType = value.valueType;
            row.typeText = RegistryTypeText(value.valueType);
            row.data = value.data;
            row.dataText = FormatRegistryData(value.valueType, row.data);
            row.detailText = L"R0 value; returned=" + std::to_wstring(value.dataBytes) +
                L"; required=" + std::to_wstring(value.requiredBytes);
            snapshot.rows.push_back(std::move(row));
        }
        snapshot.statusText = BuildR0StatusLine(L"enum", result.io.ok, result.status, result.lastStatus, result.io.message);
        return snapshot;

}



std::vector<std::wstring> EnumerateRegistrySubKeyNames(const std::wstring& path, const RegistryViewMode mode, std::wstring* statusTextOut) {
    if (mode != RegistryViewMode::R0) {
        return ks::r3::registry::EnumerateRegistrySubKeyNames(path, statusTextOut);
    }

    // Inputs:
    // - path: one registry key in display or kernel form.
    // - mode: WinAPI or R0 transport.
    // - statusTextOut: optional status sink for UI feedback.
    // Processing:
    // - parses only the current key;
    // - enumerates direct child key names only;
    // - never walks recursively, so TreeView expansion stays lazy.
    // Output:
    // - direct child key names only.
    std::vector<std::wstring> childNames;
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        if (statusTextOut) {
            *statusTextOut = parsed.errorText;
        }
        return childNames;
    }


        if (parsed.kernelPath.empty()) {
            if (statusTextOut) {
                *statusTextOut = L"R0 registry mode supports HKLM/HKU or \\REGISTRY\\MACHINE/USER paths.";
            }
            return childNames;
        }
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryEnumResult result = client.enumerateRegistryKey(parsed.kernelPath);
        if (statusTextOut) {
            *statusTextOut = BuildR0StatusLine(L"enum keys", result.io.ok, result.status, result.lastStatus, result.io.message);
        }
        for (const auto& subKey : result.subKeys) {
            childNames.push_back(subKey.name);
        }
        return childNames;

}

RegistryOperationResult ReadRegistryValue(const std::wstring& path, const std::wstring& valueName, const RegistryViewMode mode) {
    if (mode != RegistryViewMode::R0) {
        return ks::r3::registry::ReadRegistryValue(path, valueName);
    }

    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }
    RegistryOperationResult result;

        if (!KernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryReadResult read = client.readRegistryValue(parsed.kernelPath, valueName);
        result.success = read.io.ok && read.status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS;
        result.win32Error = read.io.win32Error;
        result.ntStatus = read.lastStatus;
        result.valueType = read.valueType;
        result.data = read.data;
        result.statusText = BuildR0StatusLine(L"read", read.io.ok, read.status, read.lastStatus, read.io.message);
        return result;

}

RegistryOperationResult WriteRegistryValue(const std::wstring& path, const std::wstring& valueName, const std::uint32_t type, const std::vector<std::uint8_t>& data, const RegistryViewMode mode) {
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }
    RegistryOperationResult result;
    if (mode == RegistryViewMode::R0) {
        if (!KernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryOperationResult write = client.setRegistryValue(parsed.kernelPath, valueName, type, data);
        result.success = write.io.ok && write.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        result.win32Error = write.io.win32Error;
        result.ntStatus = write.lastStatus;
        result.statusText = BuildR0StatusLine(L"write", write.io.ok, write.status, write.lastStatus, write.io.message);
        return result;
    }

    LONG openStatus = ERROR_SUCCESS;
    UniqueRegKey key = OpenKey(parsed, KEY_SET_VALUE, &openStatus);
    if (!key.valid()) {
        result.win32Error = static_cast<DWORD>(openStatus);
        result.statusText = L"RegOpenKeyExW failed: " + std::to_wstring(openStatus);
        return result;
    }
    const LONG rc = ::RegSetValueExW(key.get(), valueName.empty() ? nullptr : valueName.c_str(), 0, type,
        data.empty() ? nullptr : data.data(), static_cast<DWORD>(data.size()));
    result.success = rc == ERROR_SUCCESS;
    result.win32Error = static_cast<DWORD>(rc);
    result.statusText = result.success ? L"WinAPI write OK." : L"RegSetValueExW failed: " + std::to_wstring(rc);
    return result;
}

RegistryOperationResult DeleteRegistryValue(const std::wstring& path, const std::wstring& valueName, const RegistryViewMode mode) {
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }
    RegistryOperationResult result;
    if (mode == RegistryViewMode::R0) {
        if (!KernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryOperationResult del = client.deleteRegistryValue(parsed.kernelPath, valueName);
        result.success = del.io.ok && del.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        result.win32Error = del.io.win32Error;
        result.ntStatus = del.lastStatus;
        result.statusText = BuildR0StatusLine(L"delete value", del.io.ok, del.status, del.lastStatus, del.io.message);
        return result;
    }

    LONG openStatus = ERROR_SUCCESS;
    UniqueRegKey key = OpenKey(parsed, KEY_SET_VALUE, &openStatus);
    if (!key.valid()) {
        result.win32Error = static_cast<DWORD>(openStatus);
        result.statusText = L"RegOpenKeyExW failed: " + std::to_wstring(openStatus);
        return result;
    }
    const LONG rc = ::RegDeleteValueW(key.get(), valueName.empty() ? nullptr : valueName.c_str());
    result.success = rc == ERROR_SUCCESS;
    result.win32Error = static_cast<DWORD>(rc);
    result.statusText = result.success ? L"WinAPI delete value OK." : L"RegDeleteValueW failed: " + std::to_wstring(rc);
    return result;
}

RegistryOperationResult CreateRegistryKey(const std::wstring& path, const RegistryViewMode mode) {
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }
    RegistryOperationResult result;
    if (mode == RegistryViewMode::R0) {
        if (!KernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryOperationResult create = client.createRegistryKey(parsed.kernelPath);
        result.success = create.io.ok && create.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        result.win32Error = create.io.win32Error;
        result.ntStatus = create.lastStatus;
        result.statusText = BuildR0StatusLine(L"create key", create.io.ok, create.status, create.lastStatus, create.io.message);
        return result;
    }

    HKEY raw = nullptr;
    DWORD disposition = 0;
    const LONG rc = ::RegCreateKeyExW(parsed.root, parsed.subKey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE, nullptr, &raw, &disposition);
    UniqueRegKey key(raw);
    result.success = rc == ERROR_SUCCESS;
    result.win32Error = static_cast<DWORD>(rc);
    result.statusText = result.success ? L"WinAPI create/open key OK." : L"RegCreateKeyExW failed: " + std::to_wstring(rc);
    return result;
}

RegistryOperationResult DeleteRegistryKey(const std::wstring& path, const RegistryViewMode mode) {
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }
    RegistryOperationResult result;
    if (mode == RegistryViewMode::R0) {
        if (!KernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryOperationResult del = client.deleteRegistryKey(parsed.kernelPath);
        result.success = del.io.ok && del.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        result.win32Error = del.io.win32Error;
        result.ntStatus = del.lastStatus;
        result.statusText = BuildR0StatusLine(L"delete key", del.io.ok, del.status, del.lastStatus, del.io.message);
        return result;
    }

    const LONG rc = ::RegDeleteTreeW(parsed.root, parsed.subKey.c_str());
    result.success = rc == ERROR_SUCCESS;
    result.win32Error = static_cast<DWORD>(rc);
    result.statusText = result.success ? L"WinAPI delete key tree OK." : L"RegDeleteTreeW failed: " + std::to_wstring(rc);
    return result;
}

RegistryOperationResult RenameRegistryValue(const std::wstring& path, const std::wstring& oldName, const std::wstring& newName, const RegistryViewMode mode) {
    RegistryOperationResult result;
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }
    if (mode == RegistryViewMode::R0) {
        if (!KernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryOperationResult rename = client.renameRegistryValue(parsed.kernelPath, oldName, newName);
        result.success = rename.io.ok && rename.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        result.win32Error = rename.io.win32Error;
        result.ntStatus = rename.lastStatus;
        result.statusText = BuildR0StatusLine(L"rename value", rename.io.ok, rename.status, rename.lastStatus, rename.io.message);
        return result;
    }

    RegistryOperationResult read = ReadRegistryValue(path, oldName, mode);
    if (!read.success) {
        return read;
    }
    RegistryOperationResult write = WriteRegistryValue(path, newName, read.valueType, read.data, mode);
    if (!write.success) {
        return write;
    }
    return DeleteRegistryValue(path, oldName, mode);
}

RegistryOperationResult RenameRegistryKey(const std::wstring& path, const std::wstring& newName, const RegistryViewMode mode) {
    RegistryOperationResult result;
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }
    if (mode == RegistryViewMode::R0) {
        if (!KernelPathRequired(parsed, result)) {
            return result;
        }
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryOperationResult rename = client.renameRegistryKey(parsed.kernelPath, newName);
        result.success = rename.io.ok && rename.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        result.win32Error = rename.io.win32Error;
        result.ntStatus = rename.lastStatus;
        result.statusText = BuildR0StatusLine(L"rename key", rename.io.ok, rename.status, rename.lastStatus, rename.io.message);
        return result;
    }
    result.success = false;
    result.win32Error = ERROR_NOT_SUPPORTED;
    result.statusText = L"WinAPI key rename is not exposed here; use R0 mode for rename key.";
    return result;
}

bool CopyRegistryTextToClipboard(HWND owner, const std::wstring& text) {
    if (!::OpenClipboard(owner)) {
        return false;
    }
    ::EmptyClipboard();
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
    return true;
}

} // namespace Ksword::Features::Registry
