#pragma once

#include <Windows.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace ks::r3::file::metadata {
struct Identity {
    bool known = false;
    DWORD volumeSerial = 0;
    std::uint64_t fileId = 0;
};
struct Snapshot {
    bool ok = false;
    DWORD error = ERROR_SUCCESS;
    Identity identity;
    FILE_BASIC_INFO basic{};
};
struct BasicPatch {
    std::array<bool, 4> timeSelected{};
    std::array<std::uint64_t, 4> times{};
    bool attributesSelected = false;
    DWORD editableAttributes = 0;
};
struct BasicResult {
    Snapshot before, after;
    bool attempted = false;
    bool written = false;
    bool verified = false;
    DWORD error = ERROR_SUCCESS;
};
constexpr DWORD editableAttributeMask = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN |
    FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
Snapshot ReadBasic(const std::wstring& path);
BasicResult WriteBasic(const std::wstring& path, const Identity& expected, const BasicPatch& patch);
struct NamedValue { std::wstring name; std::vector<std::uint8_t> bytes; bool needEa = false; bool sizeKnown = false; std::uint64_t size = 0; };
struct NamedResult {
    bool ok = false, complete = false, attempted = false, written = false, verified = false;
    DWORD error = ERROR_SUCCESS;
    Identity identity;
    std::vector<NamedValue> entries;
};
NamedResult ListStreams(const std::wstring& path);
NamedResult ReadStream(const std::wstring& path, const std::wstring& name, std::size_t maxBytes);
NamedResult WriteStream(const std::wstring& path, const Identity& expected, const std::wstring& name,
    const std::vector<std::uint8_t>& bytes, bool remove);
NamedResult ListEa(const std::wstring& path);
NamedResult WriteEa(const std::wstring& path, const Identity& expected, const std::wstring& name,
    const std::vector<std::uint8_t>& bytes, bool remove, bool needEa);
struct SecurityResult {
    bool ok = false, attempted = false, written = false, verified = false;
    DWORD error = ERROR_SUCCESS;
    Identity identity;
    std::wstring sddl;
};
SecurityResult ReadSecurity(const std::wstring& path, SECURITY_INFORMATION parts);
SecurityResult WriteSecurity(const std::wstring& path, const Identity& expected, SECURITY_INFORMATION parts, const std::wstring& sddl);

struct ShellProperty { std::wstring name; bool available = false, empty = false; LONG hresult = 0; std::vector<std::wstring> values; };
struct ShellResult {
    bool ok = false, attempted = false, written = false, verified = false, backupCreated = false;
    bool rollbackAttempted = false, rollbackVerified = false;
    DWORD error = ERROR_SUCCESS, rollbackError = ERROR_SUCCESS; LONG hresult = 0;
    std::wstring backupPath;
    Identity identity, afterIdentity;
    std::vector<ShellProperty> properties;
};
ShellResult ReadShell(const std::wstring& path);
ShellResult WriteShell(const std::wstring& path, const Identity& expected, const std::wstring& name,
    const std::vector<std::wstring>& values, const std::wstring& backupPath);

struct ResourceResult {
    bool ok = false, present = false, attempted = false, written = false, verified = false, backupCreated = false;
    bool rollbackAttempted = false, rollbackVerified = false;
    DWORD error = ERROR_SUCCESS, rollbackError = ERROR_SUCCESS; Identity identity, afterIdentity; std::wstring backupPath;
    std::vector<std::uint8_t> bytes;
};
ResourceResult ReadPeResource(const std::wstring& path, const std::wstring& type, const std::wstring& name, WORD language);
ResourceResult WritePeResource(const std::wstring& path, const Identity& expected, const std::wstring& type,
    const std::wstring& name, WORD language, const std::vector<std::uint8_t>& bytes, bool remove, const std::wstring& backupPath);
}
