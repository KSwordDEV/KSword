#include "startup.h"

#include "startup_internal.h"

#include "../string/string.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Aclapi.h>
#include <Windows.h>
#include <KnownFolders.h>
#include <Shellapi.h>
#include <ShlObj.h>
#include <Softpub.h>
#include <WinTrust.h>
#include <sddl.h>
#include <winsvc.h>
#include <winver.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <regex>
#include <sstream>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Wintrust.lib")

// The first two helper blocks live in ks::startup::detail instead of an anonymous namespace so that
// sibling translation units (startup_hidden.cpp) can reuse the same registry/entry plumbing.
// A file-scope using-directive after the second block keeps every later unqualified call site intact.
namespace ks::startup::detail
{
    // The backend stores all public strings as UTF-8 and converts to UTF-16 only at Win32 boundaries.
    std::string FromWide(const std::wstring& text)
    {
        return ks::str::Utf16ToUtf8(text);
    }

    // Win32 APIs require UTF-16; empty conversion failures naturally produce empty Win32 strings.
    std::wstring ToWide(const std::string& text)
    {
        return ks::str::Utf8ToUtf16(text);
    }

    // TrimWide mirrors ks::str::TrimCopy for temporary UTF-16 values returned by Win32 APIs.
    std::wstring TrimWide(const std::wstring& text)
    {
        std::size_t first = 0;
        while (first < text.size() && std::iswspace(text[first]))
        {
            ++first;
        }
        std::size_t last = text.size();
        while (last > first && std::iswspace(text[last - 1]))
        {
            --last;
        }
        return text.substr(first, last - first);
    }

    // LowerWideCopy is used for case-insensitive registry and command-line tests.
    std::wstring LowerWideCopy(std::wstring text)
    {
        std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
        return text;
    }

    // LowerAsciiCopy is sufficient for registry catalog roots and de-duplication keys.
    std::string LowerAsciiCopy(std::string text)
    {
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return text;
    }

    // Case-insensitive prefix check for ASCII catalog and JSON field values.
    bool StartsWithI(const std::string& text, const std::string& prefix)
    {
        if (text.size() < prefix.size())
        {
            return false;
        }
        return LowerAsciiCopy(text.substr(0, prefix.size())) == LowerAsciiCopy(prefix);
    }

    // Case-insensitive suffix check for UTF-16 registry subkey filtering.
    bool EndsWithI(const std::wstring& text, const std::wstring& suffix)
    {
        if (text.size() < suffix.size())
        {
            return false;
        }
        return LowerWideCopy(text.substr(text.size() - suffix.size())) == LowerWideCopy(suffix);
    }

    // Replace all ASCII occurrences without changing unrelated non-ASCII display text.
    void ReplaceAll(std::string& text, const std::string& from, const std::string& to)
    {
        if (from.empty())
        {
            return;
        }
        std::size_t offset = 0;
        while ((offset = text.find(from, offset)) != std::string::npos)
        {
            text.replace(offset, from.size(), to);
            offset += to.size();
        }
    }

    // Case-insensitive replace for noisy registry catalog input lines.
    void ReplaceAllI(std::string& text, const std::string& from, const std::string& to)
    {
        if (from.empty())
        {
            return;
        }
        std::string lowerText = LowerAsciiCopy(text);
        const std::string lowerFrom = LowerAsciiCopy(from);
        std::size_t offset = 0;
        while ((offset = lowerText.find(lowerFrom, offset)) != std::string::npos)
        {
            text.replace(offset, from.size(), to);
            lowerText.replace(offset, from.size(), LowerAsciiCopy(to));
            offset += to.size();
        }
    }

    // Convert slash variants to Windows native separators for display and Explorer operations.
    std::string ToNativeSeparators(std::string text)
    {
        std::replace(text.begin(), text.end(), '/', '\\');
        return text;
    }

    // Expand environment variables while preserving the original text on failure.
    std::wstring ExpandEnvironmentWide(const std::wstring& text)
    {
        if (TrimWide(text).empty())
        {
            return std::wstring();
        }
        std::vector<wchar_t> buffer(32768U, L'\0');
        const DWORD chars = ::ExpandEnvironmentStringsW(text.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
        if (chars == 0 || chars >= buffer.size())
        {
            return TrimWide(text);
        }
        return TrimWide(buffer.data());
    }

    // Query an environment variable as UTF-16 and return an empty string when it is absent.
    std::wstring QueryEnvironmentWide(const wchar_t* name)
    {
        std::vector<wchar_t> buffer(32768U, L'\0');
        const DWORD chars = ::GetEnvironmentVariableW(name, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (chars == 0 || chars >= buffer.size())
        {
            return std::wstring();
        }
        return std::wstring(buffer.data(), chars);
    }

    // KnownFolderPath avoids trusting caller-controlled environment variables for security paths.
    std::wstring KnownFolderPath(const KNOWNFOLDERID& folderId)
    {
        PWSTR rawPath = nullptr;
        const HRESULT result = ::SHGetKnownFolderPath(folderId, KF_FLAG_DEFAULT, nullptr, &rawPath);
        if (FAILED(result) || rawPath == nullptr)
        {
            if (rawPath != nullptr)
            {
                ::CoTaskMemFree(rawPath);
            }
            return std::wstring();
        }
        std::wstring path(rawPath);
        ::CoTaskMemFree(rawPath);
        return path;
    }

    struct FileIdentitySnapshot
    {
        std::uint64_t volumeSerial = 0;
        std::uint64_t fileIndex = 0;
        std::uint64_t fileSize = 0;
        std::uint64_t lastWriteTime = 0;
    };

    // QueryFileIdentityNoReparse opens the final component itself and rejects links/directories.
    bool QueryFileIdentityNoReparse(
        const std::wstring& pathText,
        FileIdentitySnapshot& identityOut,
        DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;
        HANDLE fileHandle = ::CreateFileW(
            pathText.c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            errorCodeOut = ::GetLastError();
            return false;
        }
        BY_HANDLE_FILE_INFORMATION information{};
        const BOOL queryOk = ::GetFileInformationByHandle(fileHandle, &information);
        const DWORD queryError = queryOk == FALSE ? ::GetLastError() : ERROR_SUCCESS;
        ::CloseHandle(fileHandle);
        if (queryOk == FALSE)
        {
            errorCodeOut = queryError;
            return false;
        }
        if ((information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
            || (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            errorCodeOut = ERROR_REPARSE_TAG_INVALID;
            return false;
        }
        ULARGE_INTEGER fileIndex{};
        fileIndex.HighPart = information.nFileIndexHigh;
        fileIndex.LowPart = information.nFileIndexLow;
        ULARGE_INTEGER fileSize{};
        fileSize.HighPart = information.nFileSizeHigh;
        fileSize.LowPart = information.nFileSizeLow;
        ULARGE_INTEGER lastWriteTime{};
        lastWriteTime.HighPart = information.ftLastWriteTime.dwHighDateTime;
        lastWriteTime.LowPart = information.ftLastWriteTime.dwLowDateTime;
        identityOut.volumeSerial = information.dwVolumeSerialNumber;
        identityOut.fileIndex = fileIndex.QuadPart;
        identityOut.fileSize = fileSize.QuadPart;
        identityOut.lastWriteTime = lastWriteTime.QuadPart;
        return true;
    }

    // Append detail fragments without forcing the UI layer to know how backend details were assembled.
    void AppendDetailPart(std::string& detailText, const std::string& partText)
    {
        const std::string trimmedPart = ks::str::TrimCopy(partText);
        if (trimmedPart.empty())
        {
            return;
        }
        if (!ks::str::TrimCopy(detailText).empty())
        {
            detailText += FromWide(L"\uff1b");
        }
        detailText += trimmedPart;
    }

    // Join helper for registry value dumps and CSV-like action lists.
    std::string JoinStrings(const std::vector<std::string>& values, const std::string& separator)
    {
        std::ostringstream stream;
        for (std::size_t index = 0; index < values.size(); ++index)
        {
            if (index != 0)
            {
                stream << separator;
            }
            stream << values[index];
        }
        return stream.str();
    }

    // FileExists intentionally accepts a command-extracted path; callers decide whether absence is suspicious.
    bool FileExists(const std::string& pathText)
    {
        const std::wstring pathWide = ToWide(pathText);
        if (pathWide.empty())
        {
            return false;
        }
        const DWORD attributes = ::GetFileAttributesW(pathWide.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    // FormatBinaryText keeps binary registry values readable and bounded.
    std::string FormatBinaryText(const std::vector<std::uint8_t>& rawBuffer)
    {
        static constexpr char hexDigits[] = "0123456789ABCDEF";
        const std::size_t displayCount = std::min<std::size_t>(rawBuffer.size(), 16);
        std::string text;
        for (std::size_t index = 0; index < displayCount; ++index)
        {
            if (!text.empty())
            {
                text.push_back(' ');
            }
            text.push_back(hexDigits[(rawBuffer[index] >> 4) & 0x0F]);
            text.push_back(hexDigits[rawBuffer[index] & 0x0F]);
        }
        if (rawBuffer.size() > displayCount)
        {
            text += " ... (" + std::to_string(rawBuffer.size()) + " bytes)";
        }
        return text;
    }

    // RegistryWideStringFromBuffer safely decodes REG_SZ/REG_EXPAND_SZ data.
    // Inputs:
    // - rawBuffer: raw bytes returned by RegQueryValueExW/RegEnumValueW.
    // Processing:
    // - Interpret only complete wchar_t units and trim one trailing NUL if present.
    // - Do not call wcslen because registry strings are not guaranteed to be terminated.
    // Return:
    // - UTF-16 string content without the terminator, or empty text for invalid/empty buffers.
    std::wstring RegistryWideStringFromBuffer(const std::vector<std::uint8_t>& rawBuffer)
    {
        const std::size_t wcharCount = rawBuffer.size() / sizeof(wchar_t);
        if (wcharCount == 0)
        {
            return std::wstring();
        }

        const wchar_t* textBegin = reinterpret_cast<const wchar_t*>(rawBuffer.data());
        std::size_t visibleCount = wcharCount;
        if (visibleCount > 0 && textBegin[visibleCount - 1] == L'\0')
        {
            --visibleCount;
        }
        return std::wstring(textBegin, textBegin + visibleCount);
    }

    // RegistryWideMultiStringFromBuffer safely decodes REG_MULTI_SZ data.
    // Inputs:
    // - rawBuffer: raw bytes returned for a multi-string registry value.
    // Processing:
    // - Walk bounded wchar_t units and split at NUL separators.
    // - Stop at an empty segment, which is the conventional REG_MULTI_SZ terminator.
    // Return:
    // - Non-empty UTF-16 segments; malformed missing double-NUL data is still bounded.
    std::vector<std::wstring> RegistryWideMultiStringFromBuffer(const std::vector<std::uint8_t>& rawBuffer)
    {
        std::vector<std::wstring> values;
        const std::size_t wcharCount = rawBuffer.size() / sizeof(wchar_t);
        if (wcharCount == 0)
        {
            return values;
        }

        const wchar_t* textBegin = reinterpret_cast<const wchar_t*>(rawBuffer.data());
        std::size_t offset = 0;
        while (offset < wcharCount)
        {
            const std::size_t segmentStart = offset;
            while (offset < wcharCount && textBegin[offset] != L'\0')
            {
                ++offset;
            }

            if (offset == segmentStart)
            {
                break;
            }

            values.emplace_back(textBegin + segmentStart, textBegin + offset);
            if (offset < wcharCount)
            {
                ++offset;
            }
        }
        return values;
    }

    // Read CompanyName from VERSIONINFO as the fast publisher fallback before WinVerifyTrust text.
    std::string QueryCompanyNameByVersion(const std::string& filePathText)
    {
        const std::wstring pathWide = ToWide(filePathText);
        if (pathWide.empty())
        {
            return std::string();
        }
        DWORD handleValue = 0;
        const DWORD bytes = ::GetFileVersionInfoSizeW(pathWide.c_str(), &handleValue);
        if (bytes == 0)
        {
            return std::string();
        }
        std::vector<std::uint8_t> buffer(bytes);
        if (::GetFileVersionInfoW(pathWide.c_str(), 0, bytes, buffer.data()) == FALSE)
        {
            return std::string();
        }
        struct LangAndCodePage { WORD language = 0; WORD codePage = 0; };
        LangAndCodePage* translation = nullptr;
        UINT translationBytes = 0;
        if (::VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<LPVOID*>(&translation), &translationBytes) == FALSE ||
            translation == nullptr || translationBytes < sizeof(LangAndCodePage))
        {
            return std::string();
        }
        wchar_t queryPath[64] = {};
        _snwprintf_s(queryPath, _countof(queryPath), _TRUNCATE, L"\\StringFileInfo\\%04x%04x\\CompanyName", translation[0].language, translation[0].codePage);
        wchar_t* companyName = nullptr;
        UINT companyChars = 0;
        if (::VerQueryValueW(buffer.data(), queryPath, reinterpret_cast<LPVOID*>(&companyName), &companyChars) == FALSE || companyName == nullptr || companyChars <= 1)
        {
            return std::string();
        }
        return FromWide(TrimWide(companyName));
    }

    // WinVerifyTrust is used in cache-only mode to avoid UI/network prompts from the backend thread.
    bool IsFileTrustedByWindows(const std::string& filePathText)
    {
        const std::wstring pathWide = ToWide(filePathText);
        if (pathWide.empty())
        {
            return false;
        }
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = pathWide.c_str();
        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        trustData.pFile = &fileInfo;
        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const LONG result = ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        return result == ERROR_SUCCESS;
    }
}

namespace ks::startup::detail
{
    // RootKeyText maps the limited root keys used by StartupDock-compatible enumerators.
    std::string RootKeyText(HKEY rootKey)
    {
        if (rootKey == HKEY_CURRENT_USER)
        {
            return "HKCU";
        }
        if (rootKey == HKEY_LOCAL_MACHINE)
        {
            return "HKLM";
        }
        if (rootKey == HKEY_CLASSES_ROOT)
        {
            return "HKCR";
        }
        return "UNKNOWN";
    }

    // BuildRegistryLocationText creates the exact location syntax consumed by StartupDock actions.
    std::string BuildRegistryLocationText(HKEY rootKey, const std::wstring& subKeyText)
    {
        return RootKeyText(rootKey) + "\\" + FromWide(subKeyText);
    }

    // EqualWideI compares Win32 locator components without depending on display casing.
    bool EqualWideI(const std::wstring& left, const std::wstring& right)
    {
        return ::CompareStringOrdinal(left.c_str(), static_cast<int>(left.size()), right.c_str(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
    }

    // PublicRegistryRoot converts only the two hives accepted by reversible Run actions.
    ks::startup::StartupRegistryRoot PublicRegistryRoot(HKEY rootKey)
    {
        if (rootKey == HKEY_CURRENT_USER)
        {
            return ks::startup::StartupRegistryRoot::CurrentUser;
        }
        if (rootKey == HKEY_LOCAL_MACHINE)
        {
            return ks::startup::StartupRegistryRoot::LocalMachine;
        }
        return ks::startup::StartupRegistryRoot::None;
    }

    // NativeRegistryRoot rejects unknown public roots instead of guessing from display text.
    HKEY NativeRegistryRoot(const ks::startup::StartupRegistryRoot root)
    {
        switch (root)
        {
        case ks::startup::StartupRegistryRoot::CurrentUser:
            return HKEY_CURRENT_USER;
        case ks::startup::StartupRegistryRoot::LocalMachine:
            return HKEY_LOCAL_MACHINE;
        case ks::startup::StartupRegistryRoot::None:
            break;
        }
        return nullptr;
    }

    // Registry backup metadata lives at the same integrity scope as its restore target.
    HKEY RegistryBackupMetadataHive(const ks::startup::StartupRegistryRoot root)
    {
        return NativeRegistryRoot(root);
    }

    // IsKnownRunLocation recognizes records created by older builds so they remain visible.
    bool IsKnownRunLocation(HKEY rootKey, const std::wstring& subKeyText)
    {
        static const std::wstring runKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        static const std::wstring runOnceKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
        static const std::wstring run32Key = L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
        static const std::wstring runOnce32Key = L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
        if (rootKey == HKEY_CURRENT_USER)
        {
            return EqualWideI(subKeyText, runKey) || EqualWideI(subKeyText, runOnceKey);
        }
        if (rootKey == HKEY_LOCAL_MACHINE)
        {
            return EqualWideI(subKeyText, runKey) || EqualWideI(subKeyText, runOnceKey)
                || EqualWideI(subKeyText, run32Key) || EqualWideI(subKeyText, runOnce32Key);
        }
        return false;
    }

    // Warning-gated registry actions accept values from every enumerated HKCU/HKLM source.
    bool IsSupportedRunLocation(HKEY rootKey, const std::wstring& subKeyText)
    {
        return (rootKey == HKEY_CURRENT_USER || rootKey == HKEY_LOCAL_MACHINE)
            && !subKeyText.empty()
            && subKeyText.find(L'\0') == std::wstring::npos;
    }

    // Synthetic or corrupt diagnostic rows have no meaningful source object to mutate.
    void MarkEntryActionUnavailable(
        ks::startup::StartupEntry& entry,
        const ks::startup::StartupRiskLevel riskLevel,
        const std::string& reasonCode,
        const std::string& reasonText)
    {
        entry.actionKind = ks::startup::StartupActionKind::None;
        entry.actionLocator = ks::startup::StartupActionLocator{};
        entry.canEnable = false;
        entry.canDisable = false;
        entry.riskLevel = riskLevel;
        entry.riskReasonCode = reasonCode;
        entry.riskReasonText = reasonText;
        entry.canDelete = false;
    }

    void ConfigureRegistryValueAction(
        ks::startup::StartupEntry& entry,
        HKEY rootKey,
        const std::wstring& subKeyText,
        const RegistryValueRecord& valueRecord,
        const ks::startup::StartupRiskLevel riskLevel,
        const std::string& reasonCode,
        const std::string& reasonText)
    {
        entry.actionKind = ks::startup::StartupActionKind::RegistryRunValue;
        entry.actionLocator.registryRoot = PublicRegistryRoot(rootKey);
        entry.actionLocator.registrySubKeyText = FromWide(subKeyText);
        entry.actionLocator.registryValueNameText = valueRecord.valueNameText;
        entry.actionLocator.registryValueSnapshotValid = true;
        entry.actionLocator.registryValueType = valueRecord.valueType;
        entry.actionLocator.registryRawData = valueRecord.rawData;
        entry.canEnable = false;
        entry.canDisable = true;
        entry.riskLevel = riskLevel;
        entry.riskReasonCode = reasonCode;
        entry.riskReasonText = reasonText;
        entry.canDelete = true;
    }

    LONG QueryRegistryTreeSnapshot(
        HKEY rootKey,
        const std::wstring& subKeyText,
        ks::startup::StartupActionLocator& locator)
    {
        locator.registryTreeSnapshotValid = false;
        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            rootKey,
            subKeyText.c_str(),
            0,
            KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
            &openedKey);
        if (openResult != ERROR_SUCCESS)
        {
            return openResult;
        }
        DWORD subKeyCount = 0;
        DWORD valueCount = 0;
        FILETIME lastWriteTime{};
        const LONG queryResult = ::RegQueryInfoKeyW(
            openedKey,
            nullptr,
            nullptr,
            nullptr,
            &subKeyCount,
            nullptr,
            nullptr,
            &valueCount,
            nullptr,
            nullptr,
            nullptr,
            &lastWriteTime);
        ::RegCloseKey(openedKey);
        if (queryResult != ERROR_SUCCESS)
        {
            return queryResult;
        }
        ULARGE_INTEGER lastWriteValue{};
        lastWriteValue.HighPart = lastWriteTime.dwHighDateTime;
        lastWriteValue.LowPart = lastWriteTime.dwLowDateTime;
        locator.registryTreeSubKeyCount = subKeyCount;
        locator.registryTreeValueCount = valueCount;
        locator.registryTreeLastWriteTime = lastWriteValue.QuadPart;
        locator.registryTreeSnapshotValid = true;
        return ERROR_SUCCESS;
    }

    bool CaptureRegistryTreeSnapshot(
        HKEY rootKey,
        const std::wstring& subKeyText,
        ks::startup::StartupActionLocator& locator)
    {
        return QueryRegistryTreeSnapshot(rootKey, subKeyText, locator) == ERROR_SUCCESS;
    }

    void ConfigureRegistryTreeDeletion(
        ks::startup::StartupEntry& entry,
        HKEY rootKey,
        const std::wstring& subKeyText)
    {
        entry.actionLocator.registryRoot = PublicRegistryRoot(rootKey);
        entry.actionLocator.registrySubKeyText = FromWide(subKeyText);
        if (entry.actionKind == ks::startup::StartupActionKind::None)
        {
            entry.actionKind = ks::startup::StartupActionKind::RegistryTree;
        }
        CaptureRegistryTreeSnapshot(rootKey, subKeyText, entry.actionLocator);
        entry.canDelete = entry.actionLocator.registryRoot != ks::startup::StartupRegistryRoot::None;
        entry.deleteRegistryTree = entry.canDelete;
    }

    // RegistryDataToText converts common registry types into compact UTF-8 display strings.
    std::string RegistryDataToText(DWORD valueType, const std::vector<std::uint8_t>& rawBuffer)
    {
        if (rawBuffer.empty())
        {
            return std::string();
        }
        if (valueType == REG_SZ || valueType == REG_EXPAND_SZ)
        {
            std::wstring valueText = RegistryWideStringFromBuffer(rawBuffer);
            if (valueType == REG_EXPAND_SZ)
            {
                valueText = ExpandEnvironmentWide(valueText);
            }
            return FromWide(TrimWide(valueText));
        }
        if (valueType == REG_MULTI_SZ)
        {
            std::vector<std::string> items;
            for (const std::wstring& rawItemText : RegistryWideMultiStringFromBuffer(rawBuffer))
            {
                const std::wstring itemText = ExpandEnvironmentWide(rawItemText);
                if (!TrimWide(itemText).empty())
                {
                    items.push_back(FromWide(itemText));
                }
            }
            return JoinStrings(items, " | ");
        }
        if (valueType == REG_DWORD && rawBuffer.size() >= sizeof(DWORD))
        {
            const DWORD value = *reinterpret_cast<const DWORD*>(rawBuffer.data());
            std::ostringstream stream;
            stream << value << " (0x" << std::uppercase << std::hex;
            stream.width(8);
            stream.fill('0');
            stream << value << ")";
            return stream.str();
        }
        if (valueType == REG_QWORD && rawBuffer.size() >= sizeof(unsigned long long))
        {
            const unsigned long long value = *reinterpret_cast<const unsigned long long*>(rawBuffer.data());
            std::ostringstream stream;
            stream << value << " (0x" << std::uppercase << std::hex;
            stream.width(16);
            stream.fill('0');
            stream << value << ")";
            return stream.str();
        }
        return FormatBinaryText(rawBuffer);
    }

    // QueryRegistryValueRecord reads a named or default value and converts it to a backend value record.
    std::optional<RegistryValueRecord> QueryRegistryValueRecord(HKEY rootKey, const std::wstring& subKeyText, const std::wstring& valueNameText)
    {
        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(rootKey, subKeyText.c_str(), 0, KEY_QUERY_VALUE, &openedKey);
        if (openResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return std::nullopt;
        }
        DWORD valueType = REG_NONE;
        DWORD bufferBytes = 0;
        const wchar_t* valueNamePointer = valueNameText.empty() ? nullptr : valueNameText.c_str();
        const LONG sizeResult = ::RegQueryValueExW(openedKey, valueNamePointer, nullptr, &valueType, nullptr, &bufferBytes);
        if (sizeResult != ERROR_SUCCESS || bufferBytes == 0)
        {
            ::RegCloseKey(openedKey);
            return std::nullopt;
        }
        std::vector<std::uint8_t> rawBuffer(static_cast<std::size_t>(bufferBytes));
        const LONG dataResult = ::RegQueryValueExW(openedKey, valueNamePointer, nullptr, &valueType, rawBuffer.data(), &bufferBytes);
        ::RegCloseKey(openedKey);
        if (dataResult != ERROR_SUCCESS)
        {
            return std::nullopt;
        }
        rawBuffer.resize(bufferBytes);
        RegistryValueRecord record;
        record.valueNameText = FromWide(valueNameText);
        record.valueDataText = ks::str::TrimCopy(RegistryDataToText(valueType, rawBuffer));
        record.valueType = valueType;
        record.rawData = std::move(rawBuffer);
        return record;
    }

    // EnumerateRegistryValues returns all values under a key; inaccessible keys simply yield no rows.
    std::vector<RegistryValueRecord> EnumerateRegistryValues(HKEY rootKey, const std::wstring& subKeyText)
    {
        std::vector<RegistryValueRecord> records;
        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(rootKey, subKeyText.c_str(), 0, KEY_QUERY_VALUE, &openedKey);
        if (openResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return records;
        }
        DWORD valueIndex = 0;
        while (true)
        {
            std::array<wchar_t, 1024> valueName{};
            DWORD valueNameChars = static_cast<DWORD>(valueName.size());
            DWORD valueType = REG_NONE;
            DWORD dataBytes = 0;
            const LONG headerResult = ::RegEnumValueW(openedKey, valueIndex, valueName.data(), &valueNameChars, nullptr, &valueType, nullptr, &dataBytes);
            if (headerResult == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            if (headerResult != ERROR_SUCCESS)
            {
                ++valueIndex;
                continue;
            }
            std::vector<std::uint8_t> rawBuffer(static_cast<std::size_t>(dataBytes == 0 ? 2 : dataBytes));
            valueNameChars = static_cast<DWORD>(valueName.size());
            const LONG dataResult = ::RegEnumValueW(openedKey, valueIndex, valueName.data(), &valueNameChars, nullptr, &valueType, rawBuffer.data(), &dataBytes);
            if (dataResult == ERROR_SUCCESS)
            {
                rawBuffer.resize(dataBytes);
                RegistryValueRecord record;
                record.valueNameText = FromWide(std::wstring(valueName.data(), valueNameChars));
                record.valueDataText = ks::str::TrimCopy(RegistryDataToText(valueType, rawBuffer));
                record.valueType = valueType;
                record.rawData = std::move(rawBuffer);
                records.push_back(std::move(record));
            }
            ++valueIndex;
        }
        ::RegCloseKey(openedKey);
        return records;
    }

    // EnumerateRegistrySubKeys lists first-level subkey names for registry persistence families.
    std::vector<std::wstring> EnumerateRegistrySubKeys(HKEY rootKey, const std::wstring& subKeyText)
    {
        std::vector<std::wstring> subKeys;
        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(rootKey, subKeyText.c_str(), 0, KEY_ENUMERATE_SUB_KEYS, &openedKey);
        if (openResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return subKeys;
        }
        DWORD subKeyIndex = 0;
        while (true)
        {
            std::array<wchar_t, 1024> subKeyName{};
            DWORD subKeyChars = static_cast<DWORD>(subKeyName.size());
            const LONG enumResult = ::RegEnumKeyExW(openedKey, subKeyIndex, subKeyName.data(), &subKeyChars, nullptr, nullptr, nullptr, nullptr);
            if (enumResult == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            if (enumResult == ERROR_SUCCESS)
            {
                subKeys.emplace_back(subKeyName.data(), subKeyChars);
            }
            ++subKeyIndex;
        }
        ::RegCloseKey(openedKey);
        return subKeys;
    }

    // IsClsidText accepts the same relaxed {GUID} shape used by the previous UI-side backend.
    bool IsClsidText(const std::string& text)
    {
        const std::string trimmed = ks::str::TrimCopy(text);
        return trimmed.size() >= 38 && trimmed.front() == '{' && trimmed.back() == '}';
    }

    // QueryClsidFriendlyName gives COM rows a readable name when HKCR exposes one.
    std::string QueryClsidFriendlyName(const std::string& clsidText)
    {
        if (!IsClsidText(clsidText))
        {
            return std::string();
        }
        const auto record = QueryRegistryValueRecord(HKEY_CLASSES_ROOT, L"CLSID\\" + ToWide(ks::str::TrimCopy(clsidText)), L"");
        return record.has_value() ? record->valueDataText : std::string();
    }

    // QueryClsidServerPath resolves COM server paths from InprocServer32 or LocalServer32.
    std::string QueryClsidServerPath(const std::string& clsidText)
    {
        if (!IsClsidText(clsidText))
        {
            return std::string();
        }
        const std::wstring clsidSubKey = L"CLSID\\" + ToWide(ks::str::TrimCopy(clsidText));
        for (const std::wstring& candidate : { clsidSubKey + L"\\InprocServer32", clsidSubKey + L"\\LocalServer32" })
        {
            const auto record = QueryRegistryValueRecord(HKEY_CLASSES_ROOT, candidate, L"");
            if (record.has_value() && !ks::str::TrimCopy(record->valueDataText).empty())
            {
                return ks::startup::NormalizeFilePathText(record->valueDataText);
            }
        }
        return std::string();
    }

    // FinalizeRegistryEntry fills command, normalized path, publisher, and registry deletion metadata.
    void FinalizeRegistryEntry(
        ks::startup::StartupEntry& entry,
        const std::string& rawCommandText,
        const std::string& fallbackClsidText,
        const std::string& registryValueNameText,
        bool deleteRegistryTree,
        bool resolveClsidFromValueData)
    {
        entry.commandText = ks::str::TrimCopy(rawCommandText);
        entry.registryValueNameText = registryValueNameText;
        entry.deleteRegistryTree = deleteRegistryTree;
        entry.canOpenRegistryLocation = !ks::str::TrimCopy(entry.locationText).empty();
        entry.canDelete = false;

        std::string resolvedImagePath;
        if (resolveClsidFromValueData && IsClsidText(entry.commandText))
        {
            resolvedImagePath = QueryClsidServerPath(entry.commandText);
            AppendDetailPart(entry.detailText, "CLSID=" + entry.commandText);
        }
        if (ks::str::TrimCopy(resolvedImagePath).empty() && IsClsidText(fallbackClsidText))
        {
            resolvedImagePath = QueryClsidServerPath(fallbackClsidText);
            AppendDetailPart(entry.detailText, "CLSID=" + fallbackClsidText);
        }
        const std::string clsidFriendlyName = IsClsidText(fallbackClsidText)
            ? QueryClsidFriendlyName(fallbackClsidText)
            : (IsClsidText(entry.commandText) ? QueryClsidFriendlyName(entry.commandText) : std::string());
        if (!ks::str::TrimCopy(clsidFriendlyName).empty())
        {
            AppendDetailPart(entry.detailText, FromWide(L"\u7ec4\u4ef6=") + clsidFriendlyName);
        }
        entry.imagePathText = ks::str::TrimCopy(resolvedImagePath).empty()
            ? ks::startup::NormalizeFilePathText(entry.commandText)
            : resolvedImagePath;
        entry.publisherText = ks::startup::QueryPublisherTextByPath(entry.imagePathText);
        entry.canOpenFileLocation = !ks::str::TrimCopy(entry.imagePathText).empty();
        entry.imagePathExists = FileExists(entry.imagePathText);
        entry.enabled = true;
    }

    // ProcessOutput contains captured stdout/stderr from a hidden child process.
    struct ProcessOutput
    {
        bool started = false;
        bool finished = false;
        DWORD exitCode = 0;
        DWORD errorCode = ERROR_SUCCESS;
        std::string stdoutText;
        std::string stderrText;
    };

    // AppendPipeText drains available pipe bytes without blocking after process completion/timeout.
    void AppendPipeText(HANDLE pipeHandle, std::string& outputText)
    {
        if (pipeHandle == nullptr || pipeHandle == INVALID_HANDLE_VALUE)
        {
            return;
        }
        while (true)
        {
            DWORD availableBytes = 0;
            if (::PeekNamedPipe(pipeHandle, nullptr, 0, nullptr, &availableBytes, nullptr) == FALSE || availableBytes == 0)
            {
                break;
            }
            std::vector<char> buffer(std::min<DWORD>(availableBytes, 8192));
            DWORD readBytes = 0;
            if (::ReadFile(pipeHandle, buffer.data(), static_cast<DWORD>(buffer.size()), &readBytes, nullptr) == FALSE || readBytes == 0)
            {
                break;
            }
            outputText.append(buffer.data(), buffer.data() + readBytes);
        }
    }

    // RunHiddenProcess executes one explicitly selected executable without PATH/CWD lookup.
    ProcessOutput RunHiddenProcess(
        const std::wstring& applicationPath,
        const std::wstring& commandLine,
        DWORD timeoutMs)
    {
        ProcessOutput output;
        if (applicationPath.empty())
        {
            output.errorCode = ERROR_FILE_NOT_FOUND;
            return output;
        }
        SECURITY_ATTRIBUTES securityAttributes{};
        securityAttributes.nLength = sizeof(securityAttributes);
        securityAttributes.bInheritHandle = TRUE;

        HANDLE stdinHandle = INVALID_HANDLE_VALUE;
        HANDLE stdoutRead = nullptr;
        HANDLE stdoutWrite = nullptr;
        HANDLE stderrRead = nullptr;
        HANDLE stderrWrite = nullptr;
        if (::CreatePipe(&stdoutRead, &stdoutWrite, &securityAttributes, 0) == FALSE ||
            ::CreatePipe(&stderrRead, &stderrWrite, &securityAttributes, 0) == FALSE)
        {
            output.errorCode = ::GetLastError();
            if (stdoutRead != nullptr) ::CloseHandle(stdoutRead);
            if (stdoutWrite != nullptr) ::CloseHandle(stdoutWrite);
            if (stderrRead != nullptr) ::CloseHandle(stderrRead);
            if (stderrWrite != nullptr) ::CloseHandle(stderrWrite);
            return output;
        }
        if (::SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0) == FALSE
            || ::SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0) == FALSE)
        {
            output.errorCode = ::GetLastError();
            ::CloseHandle(stdoutRead);
            ::CloseHandle(stdoutWrite);
            ::CloseHandle(stderrRead);
            ::CloseHandle(stderrWrite);
            return output;
        }

        stdinHandle = ::CreateFileW(
            L"NUL",
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &securityAttributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (stdinHandle == INVALID_HANDLE_VALUE)
        {
            output.errorCode = ::GetLastError();
            ::CloseHandle(stdoutRead);
            ::CloseHandle(stdoutWrite);
            ::CloseHandle(stderrRead);
            ::CloseHandle(stderrWrite);
            return output;
        }

        SIZE_T attributeListSize = 0;
        ::InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListSize);
        std::vector<std::uint8_t> attributeListBuffer(attributeListSize);
        auto* attributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
            attributeListBuffer.data());
        if (attributeListSize == 0
            || ::InitializeProcThreadAttributeList(attributeList, 1, 0, &attributeListSize) == FALSE)
        {
            output.errorCode = ::GetLastError();
            ::CloseHandle(stdinHandle);
            ::CloseHandle(stdoutRead);
            ::CloseHandle(stdoutWrite);
            ::CloseHandle(stderrRead);
            ::CloseHandle(stderrWrite);
            return output;
        }
        const std::array<HANDLE, 3> inheritedHandles{
            stdinHandle,
            stdoutWrite,
            stderrWrite
        };
        if (::UpdateProcThreadAttribute(
                attributeList,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                const_cast<HANDLE*>(inheritedHandles.data()),
                sizeof(inheritedHandles),
                nullptr,
                nullptr) == FALSE)
        {
            output.errorCode = ::GetLastError();
            ::DeleteProcThreadAttributeList(attributeList);
            ::CloseHandle(stdinHandle);
            ::CloseHandle(stdoutRead);
            ::CloseHandle(stdoutWrite);
            ::CloseHandle(stderrRead);
            ::CloseHandle(stderrWrite);
            return output;
        }

        STARTUPINFOEXW startupInfo{};
        startupInfo.StartupInfo.cb = sizeof(startupInfo);
        startupInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startupInfo.StartupInfo.wShowWindow = SW_HIDE;
        startupInfo.StartupInfo.hStdOutput = stdoutWrite;
        startupInfo.StartupInfo.hStdError = stderrWrite;
        startupInfo.StartupInfo.hStdInput = stdinHandle;
        startupInfo.lpAttributeList = attributeList;

        PROCESS_INFORMATION processInfo{};
        std::vector<wchar_t> commandBuffer(commandLine.begin(), commandLine.end());
        commandBuffer.push_back(L'\0');
        const std::wstring applicationDirectory =
            std::filesystem::path(applicationPath).parent_path().wstring();
        const BOOL createOk = ::CreateProcessW(
            applicationPath.c_str(),
            commandBuffer.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            nullptr,
            applicationDirectory.empty() ? nullptr : applicationDirectory.c_str(),
            &startupInfo.StartupInfo,
            &processInfo);
        if (createOk == FALSE)
        {
            output.errorCode = ::GetLastError();
        }
        ::DeleteProcThreadAttributeList(attributeList);
        ::CloseHandle(stdinHandle);
        ::CloseHandle(stdoutWrite);
        ::CloseHandle(stderrWrite);
        stdinHandle = INVALID_HANDLE_VALUE;
        stdoutWrite = nullptr;
        stderrWrite = nullptr;
        if (createOk == FALSE)
        {
            ::CloseHandle(stdoutRead);
            ::CloseHandle(stderrRead);
            return output;
        }

        output.started = true;
        const ULONGLONG startTick = ::GetTickCount64();
        DWORD waitResult = WAIT_TIMEOUT;
        while (true)
        {
            // Drain stdout/stderr while the child is running so large JSON output cannot fill
            // the inherited pipe and deadlock the PowerShell process before it exits.
            AppendPipeText(stdoutRead, output.stdoutText);
            AppendPipeText(stderrRead, output.stderrText);
            waitResult = ::WaitForSingleObject(processInfo.hProcess, 50);
            if (waitResult == WAIT_OBJECT_0)
            {
                break;
            }
            if (waitResult == WAIT_FAILED)
            {
                output.errorCode = ::GetLastError();
                break;
            }
            const ULONGLONG elapsedMs = ::GetTickCount64() - startTick;
            if (elapsedMs >= timeoutMs)
            {
                output.errorCode = WAIT_TIMEOUT;
                break;
            }
        }
        if (waitResult != WAIT_OBJECT_0)
        {
            ::TerminateProcess(processInfo.hProcess, 1);
            ::WaitForSingleObject(processInfo.hProcess, 1500);
        }
        output.finished = waitResult == WAIT_OBJECT_0;
        DWORD exitCode = ERROR_PROCESS_ABORTED;
        if (::GetExitCodeProcess(processInfo.hProcess, &exitCode) != FALSE)
        {
            output.exitCode = exitCode;
        }
        else if (output.errorCode == ERROR_SUCCESS)
        {
            const DWORD exitCodeError = ::GetLastError();
            output.errorCode = exitCodeError == ERROR_SUCCESS
                ? ERROR_GEN_FAILURE
                : exitCodeError;
        }
        AppendPipeText(stdoutRead, output.stdoutText);
        AppendPipeText(stderrRead, output.stderrText);
        ::CloseHandle(processInfo.hThread);
        ::CloseHandle(processInfo.hProcess);
        ::CloseHandle(stdoutRead);
        ::CloseHandle(stderrRead);
        return output;
    }

    // ProcessFailureCode preserves launch/wait failures and rejects a successful exit that did
    // not produce the expected protocol marker as malformed output.
    DWORD ProcessFailureCode(const ProcessOutput& output)
    {
        if (output.errorCode != ERROR_SUCCESS)
        {
            return output.errorCode;
        }
        if (!output.started)
        {
            return ERROR_PROCESS_ABORTED;
        }
        if (!output.finished)
        {
            return WAIT_TIMEOUT;
        }
        if (output.exitCode != 0)
        {
            return output.exitCode;
        }
        return ERROR_INVALID_DATA;
    }

    // Base64EncodeWideScript avoids command-line quoting bugs for complex PowerShell scripts.
    std::wstring Base64EncodeWideScript(const std::wstring& scriptText)
    {
        static constexpr wchar_t alphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(scriptText.data());
        const std::size_t byteCount = scriptText.size() * sizeof(wchar_t);
        std::wstring encoded;
        encoded.reserve(((byteCount + 2) / 3) * 4);
        for (std::size_t index = 0; index < byteCount; index += 3)
        {
            const std::uint32_t b0 = bytes[index];
            const std::uint32_t b1 = (index + 1 < byteCount) ? bytes[index + 1] : 0;
            const std::uint32_t b2 = (index + 2 < byteCount) ? bytes[index + 2] : 0;
            encoded.push_back(alphabet[(b0 >> 2) & 0x3F]);
            encoded.push_back(alphabet[((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)]);
            encoded.push_back(index + 1 < byteCount ? alphabet[((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)] : L'=');
            encoded.push_back(index + 2 < byteCount ? alphabet[b2 & 0x3F] : L'=');
        }
        return encoded;
    }

    // TrustedPowerShellPath resolves only the inbox Windows PowerShell under System32.
    std::wstring TrustedPowerShellPath()
    {
        std::array<wchar_t, MAX_PATH + 1> systemDirectory{};
        const UINT charCount = ::GetSystemDirectoryW(
            systemDirectory.data(),
            static_cast<UINT>(systemDirectory.size()));
        if (charCount == 0 || charCount >= systemDirectory.size())
        {
            return std::wstring();
        }
        return (std::filesystem::path(systemDirectory.data())
            / L"WindowsPowerShell"
            / L"v1.0"
            / L"powershell.exe").wstring();
    }

    // RunPowerShellScript runs an EncodedCommand script through the trusted inbox executable.
    ProcessOutput RunPowerShellScript(const std::wstring& scriptText, DWORD timeoutMs)
    {
        const std::wstring powerShellPath = TrustedPowerShellPath();
        if (powerShellPath.empty())
        {
            return ProcessOutput{};
        }
        const std::wstring encodedScript = Base64EncodeWideScript(scriptText);
        const std::wstring commandLine = L"\"" + powerShellPath
            + L"\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
            + encodedScript;
        ProcessOutput output = RunHiddenProcess(powerShellPath, commandLine, timeoutMs);
        // PowerShell scripts set OutputEncoding=UTF8; fall back to raw bytes if conversion is unnecessary.
        return output;
    }
}

// Every later block in this file was written against unqualified helper names; the using-directive
// keeps those call sites unchanged now that the helpers moved into ks::startup::detail.
using namespace ks::startup::detail;

namespace
{
    // JsonValue is a small JSON DOM sufficient for PowerShell ConvertTo-Json results.
    struct JsonValue
    {
        enum class Type
        {
            Null,
            Bool,
            Number,
            String,
            Array,
            Object
        };

        Type type = Type::Null;
        bool boolValue = false;
        double numberValue = 0.0;
        std::string stringValue;
        std::vector<JsonValue> arrayValue;
        std::map<std::string, JsonValue> objectValue;
    };

    // AppendUtf8CodePoint writes one Unicode scalar to a UTF-8 string.
    void AppendUtf8CodePoint(std::string& text, std::uint32_t codePoint)
    {
        if (codePoint <= 0x7F)
        {
            text.push_back(static_cast<char>(codePoint));
        }
        else if (codePoint <= 0x7FF)
        {
            text.push_back(static_cast<char>(0xC0 | ((codePoint >> 6) & 0x1F)));
            text.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        else if (codePoint <= 0xFFFF)
        {
            text.push_back(static_cast<char>(0xE0 | ((codePoint >> 12) & 0x0F)));
            text.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            text.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        else
        {
            text.push_back(static_cast<char>(0xF0 | ((codePoint >> 18) & 0x07)));
            text.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
            text.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            text.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
    }

    // JsonParser implements the small subset of RFC 8259 needed by PowerShell JSON output.
    class JsonParser
    {
    public:
        explicit JsonParser(std::string_view text) : m_text(text) {}

        // Parse reads a single JSON value and ignores trailing whitespace.
        bool Parse(JsonValue& valueOut)
        {
            SkipWhitespace();
            if (!ParseValue(valueOut))
            {
                return false;
            }
            SkipWhitespace();
            return m_offset == m_text.size();
        }

    private:
        // SkipWhitespace advances over JSON insignificant whitespace.
        void SkipWhitespace()
        {
            while (m_offset < m_text.size())
            {
                const unsigned char ch = static_cast<unsigned char>(m_text[m_offset]);
                if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
                {
                    break;
                }
                ++m_offset;
            }
        }

        // Consume checks and advances one expected byte.
        bool Consume(char expected)
        {
            if (m_offset >= m_text.size() || m_text[m_offset] != expected)
            {
                return false;
            }
            ++m_offset;
            return true;
        }

        // ParseValue dispatches by the current leading token.
        bool ParseValue(JsonValue& valueOut)
        {
            SkipWhitespace();
            if (m_offset >= m_text.size())
            {
                return false;
            }
            const char ch = m_text[m_offset];
            if (ch == '"')
            {
                valueOut.type = JsonValue::Type::String;
                return ParseString(valueOut.stringValue);
            }
            if (ch == '{')
            {
                return ParseObject(valueOut);
            }
            if (ch == '[')
            {
                return ParseArray(valueOut);
            }
            if (ch == 't' || ch == 'f')
            {
                return ParseBool(valueOut);
            }
            if (ch == 'n')
            {
                return ParseNull(valueOut);
            }
            return ParseNumber(valueOut);
        }

        // ParseHex4 decodes a JSON \uXXXX escape sequence.
        bool ParseHex4(std::uint32_t& valueOut)
        {
            if (m_offset + 4 > m_text.size())
            {
                return false;
            }
            std::uint32_t value = 0;
            for (int index = 0; index < 4; ++index)
            {
                const char ch = m_text[m_offset++];
                value <<= 4;
                if (ch >= '0' && ch <= '9') value |= static_cast<std::uint32_t>(ch - '0');
                else if (ch >= 'a' && ch <= 'f') value |= static_cast<std::uint32_t>(ch - 'a' + 10);
                else if (ch >= 'A' && ch <= 'F') value |= static_cast<std::uint32_t>(ch - 'A' + 10);
                else return false;
            }
            valueOut = value;
            return true;
        }

        // ParseString handles ordinary JSON escapes and UTF-16 surrogate pairs.
        bool ParseString(std::string& textOut)
        {
            if (!Consume('"'))
            {
                return false;
            }
            std::string result;
            while (m_offset < m_text.size())
            {
                const char ch = m_text[m_offset++];
                if (ch == '"')
                {
                    textOut = std::move(result);
                    return true;
                }
                if (ch != '\\')
                {
                    result.push_back(ch);
                    continue;
                }
                if (m_offset >= m_text.size())
                {
                    return false;
                }
                const char esc = m_text[m_offset++];
                switch (esc)
                {
                case '"': result.push_back('"'); break;
                case '\\': result.push_back('\\'); break;
                case '/': result.push_back('/'); break;
                case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break;
                case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break;
                case 't': result.push_back('\t'); break;
                case 'u':
                {
                    std::uint32_t codePoint = 0;
                    if (!ParseHex4(codePoint))
                    {
                        return false;
                    }
                    if (codePoint >= 0xD800 && codePoint <= 0xDBFF)
                    {
                        const std::size_t savedOffset = m_offset;
                        if (m_offset + 2 <= m_text.size() && m_text[m_offset] == '\\' && m_text[m_offset + 1] == 'u')
                        {
                            m_offset += 2;
                            std::uint32_t lowSurrogate = 0;
                            if (ParseHex4(lowSurrogate) && lowSurrogate >= 0xDC00 && lowSurrogate <= 0xDFFF)
                            {
                                codePoint = 0x10000 + (((codePoint - 0xD800) << 10) | (lowSurrogate - 0xDC00));
                            }
                            else
                            {
                                m_offset = savedOffset;
                            }
                        }
                    }
                    AppendUtf8CodePoint(result, codePoint);
                    break;
                }
                default:
                    return false;
                }
            }
            return false;
        }

        // ParseObject reads a string-keyed JSON object.
        bool ParseObject(JsonValue& valueOut)
        {
            if (!Consume('{'))
            {
                return false;
            }
            valueOut = JsonValue{};
            valueOut.type = JsonValue::Type::Object;
            SkipWhitespace();
            if (Consume('}'))
            {
                return true;
            }
            while (true)
            {
                SkipWhitespace();
                std::string key;
                if (!ParseString(key))
                {
                    return false;
                }
                SkipWhitespace();
                if (!Consume(':'))
                {
                    return false;
                }
                JsonValue child;
                if (!ParseValue(child))
                {
                    return false;
                }
                valueOut.objectValue.emplace(std::move(key), std::move(child));
                SkipWhitespace();
                if (Consume('}'))
                {
                    return true;
                }
                if (!Consume(','))
                {
                    return false;
                }
            }
        }

        // ParseArray reads an ordered JSON array.
        bool ParseArray(JsonValue& valueOut)
        {
            if (!Consume('['))
            {
                return false;
            }
            valueOut = JsonValue{};
            valueOut.type = JsonValue::Type::Array;
            SkipWhitespace();
            if (Consume(']'))
            {
                return true;
            }
            while (true)
            {
                JsonValue child;
                if (!ParseValue(child))
                {
                    return false;
                }
                valueOut.arrayValue.push_back(std::move(child));
                SkipWhitespace();
                if (Consume(']'))
                {
                    return true;
                }
                if (!Consume(','))
                {
                    return false;
                }
            }
        }

        // ParseBool reads true/false literals.
        bool ParseBool(JsonValue& valueOut)
        {
            if (m_text.substr(m_offset, 4) == "true")
            {
                valueOut = JsonValue{};
                valueOut.type = JsonValue::Type::Bool;
                valueOut.boolValue = true;
                m_offset += 4;
                return true;
            }
            if (m_text.substr(m_offset, 5) == "false")
            {
                valueOut = JsonValue{};
                valueOut.type = JsonValue::Type::Bool;
                valueOut.boolValue = false;
                m_offset += 5;
                return true;
            }
            return false;
        }

        // ParseNull reads the null literal.
        bool ParseNull(JsonValue& valueOut)
        {
            if (m_text.substr(m_offset, 4) != "null")
            {
                return false;
            }
            valueOut = JsonValue{};
            valueOut.type = JsonValue::Type::Null;
            m_offset += 4;
            return true;
        }

        // ParseNumber stores the double form and keeps exact display through JsonValueToText when needed.
        bool ParseNumber(JsonValue& valueOut)
        {
            const std::size_t start = m_offset;
            if (m_offset < m_text.size() && m_text[m_offset] == '-')
            {
                ++m_offset;
            }
            while (m_offset < m_text.size() && std::isdigit(static_cast<unsigned char>(m_text[m_offset])))
            {
                ++m_offset;
            }
            if (m_offset < m_text.size() && m_text[m_offset] == '.')
            {
                ++m_offset;
                while (m_offset < m_text.size() && std::isdigit(static_cast<unsigned char>(m_text[m_offset])))
                {
                    ++m_offset;
                }
            }
            if (m_offset < m_text.size() && (m_text[m_offset] == 'e' || m_text[m_offset] == 'E'))
            {
                ++m_offset;
                if (m_offset < m_text.size() && (m_text[m_offset] == '+' || m_text[m_offset] == '-'))
                {
                    ++m_offset;
                }
                while (m_offset < m_text.size() && std::isdigit(static_cast<unsigned char>(m_text[m_offset])))
                {
                    ++m_offset;
                }
            }
            if (m_offset == start)
            {
                return false;
            }
            valueOut = JsonValue{};
            valueOut.type = JsonValue::Type::Number;
            valueOut.numberValue = std::strtod(std::string(m_text.substr(start, m_offset - start)).c_str(), nullptr);
            return true;
        }

        std::string_view m_text;
        std::size_t m_offset = 0;
    };

    // JsonValueToText produces the display string used by StartupEntry fields.
    std::string JsonValueToText(const JsonValue& value)
    {
        switch (value.type)
        {
        case JsonValue::Type::String:
            return ks::str::TrimCopy(value.stringValue);
        case JsonValue::Type::Number:
        {
            std::ostringstream stream;
            stream << value.numberValue;
            return stream.str();
        }
        case JsonValue::Type::Bool:
            return value.boolValue ? "true" : "false";
        case JsonValue::Type::Null:
            return std::string();
        case JsonValue::Type::Array:
        {
            std::vector<std::string> parts;
            for (const JsonValue& child : value.arrayValue)
            {
                parts.push_back(JsonValueToText(child));
            }
            return JoinStrings(parts, " | ");
        }
        case JsonValue::Type::Object:
            return "<object>";
        }
        return std::string();
    }

    // GetJsonField returns a named object field as display text, or empty for absent fields.
    std::string GetJsonField(const JsonValue& objectValue, const std::string& key)
    {
        if (objectValue.type != JsonValue::Type::Object)
        {
            return std::string();
        }
        const auto fieldIt = objectValue.objectValue.find(key);
        if (fieldIt == objectValue.objectValue.end())
        {
            return std::string();
        }
        return JsonValueToText(fieldIt->second);
    }

    // StripUtf8Bom removes a leading UTF-8 BOM because Windows PowerShell may emit it before JSON.
    std::string StripUtf8Bom(std::string text)
    {
        if (text.size() >= 3 &&
            static_cast<unsigned char>(text[0]) == 0xEF &&
            static_cast<unsigned char>(text[1]) == 0xBB &&
            static_cast<unsigned char>(text[2]) == 0xBF)
        {
            text.erase(0, 3);
        }
        return text;
    }

    // ParseJsonObjects normalizes a single JSON object or an array of objects into a vector.
    std::vector<JsonValue> ParseJsonObjects(const std::string& jsonText, bool* parseOkOut)
    {
        std::vector<JsonValue> objects;
        JsonValue root;
        JsonParser parser(jsonText);
        const bool parseOk = parser.Parse(root);
        if (parseOkOut != nullptr)
        {
            *parseOkOut = parseOk;
        }
        if (!parseOk)
        {
            return objects;
        }
        if (root.type == JsonValue::Type::Object)
        {
            objects.push_back(std::move(root));
        }
        else if (root.type == JsonValue::Type::Array)
        {
            for (JsonValue& value : root.arrayValue)
            {
                if (value.type == JsonValue::Type::Object)
                {
                    objects.push_back(std::move(value));
                }
            }
        }
        return objects;
    }
}

namespace
{
    // RunKeySpec describes Run/RunOnce style locations whose values are startup commands.
    struct RunKeySpec
    {
        HKEY rootKey = nullptr;
        const wchar_t* subKeyText = L"";
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
    };

    // SingleValueSpec describes a fixed key/value startup persistence source.
    struct SingleValueSpec
    {
        HKEY rootKey = nullptr;
        const wchar_t* subKeyText = L"";
        const wchar_t* valueNameText = L"";
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
        bool resolveClsidFromValueData = false;
    };

    // ValueEnumSpec describes a key where every value can represent a persistence item.
    struct ValueEnumSpec
    {
        HKEY rootKey = nullptr;
        const wchar_t* subKeyText = L"";
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
        bool resolveClsidFromValueData = false;
        bool resolveClsidFromValueName = false;
    };

    // SubKeyValueSpec describes sources where subkeys are enumerated and one value is read from each.
    struct SubKeyValueSpec
    {
        HKEY rootKey = nullptr;
        const wchar_t* subKeyText = L"";
        const wchar_t* valueNameText = L"";
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
        bool resolveClsidFromValueData = false;
        bool resolveClsidFromSubKeyName = false;
        bool deleteRegistryTree = false;
    };

    // BuildRunKeySpecList centralizes logon registry coverage.
    const std::array<RunKeySpec, 21>& BuildRunKeySpecList()
    {
        static const std::array<RunKeySpec, 21> specs{ {
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Run", L"当前用户", L"用户登录后自动运行" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce", L"当前用户", L"当前用户一次性登录项" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", "RunServices", L"当前用户", L"兼容性 RunServices 登录项" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "RunServicesOnce", L"当前用户", L"兼容性 RunServicesOnce 登录项" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "PoliciesRun", L"当前用户", L"策略控制的登录项" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "WindowsRun", L"当前用户", L"Windows 兼容 Run/Load 位置" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Command Processor", "CommandProcessorAutorun", L"当前用户", L"命令行解释器 Autorun" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Run", L"本机", L"系统级登录后自动运行" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce", L"本机", L"系统级一次性登录项" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", "RunServices", L"本机", L"兼容性 RunServices 登录项" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "RunServicesOnce", L"本机", L"兼容性 RunServicesOnce 登录项" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "PoliciesRun", L"本机", L"策略控制的登录项" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "WindowsRun", L"本机", L"Windows 兼容 Run/Load 位置" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Command Processor", "CommandProcessorAutorun", L"本机", L"命令行解释器 Autorun" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "TerminalServerRun", L"本机", L"终端服务安装模式 Run" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "TerminalServerRunOnce", L"本机", L"终端服务安装模式 RunOnce" },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Run32", L"本机(32位)", L"32 位视图 Run" },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce32", L"本机(32位)", L"32 位视图 RunOnce" },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices", "RunServices32", L"本机(32位)", L"32 位视图 RunServices" },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", "RunServicesOnce32", L"本机(32位)", L"32 位视图 RunServicesOnce" },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "PoliciesRun32", L"本机(32位)", L"32 位视图策略 Run" }
        } };
        return specs;
    }

    // BuildSingleValueSpecList centralizes fixed-value advanced registry persistence coverage.
    const std::array<SingleValueSpec, 92>& BuildSingleValueSpecList()
    {
        static const std::array<SingleValueSpec, 92> specs{ {
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", "WinlogonShell", L"本机", L"Winlogon Shell", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", "WinlogonUserinit", L"本机", L"Winlogon Userinit", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Taskman", "WinlogonTaskman", L"本机", L"Winlogon Taskman", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"VmApplet", "WinlogonVmApplet", L"本机", L"Winlogon VM Applet", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"GinaDLL", "WinlogonGinaDll", L"本机", L"旧式 GINA 登录 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"AppSetup", "WinlogonAppSetup", L"本机", L"Winlogon AppSetup", false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", "UserWinlogonShell", L"当前用户", L"用户级 Winlogon Shell", false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", "UserWinlogonUserinit", L"当前用户", L"用户级 Winlogon Userinit", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", "AppInitDlls", L"本机", L"AppInit DLL 列表", false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", "AppInitDlls32", L"本机(32位)", L"32 位 AppInit DLL 列表", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", "LsaAuthPackages", L"本机", L"LSA 认证包", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa", L"Security Packages", "LsaSecurityPackages", L"本机", L"LSA 安全包", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa", L"Notification Packages", "LsaNotificationPackages", L"本机", L"LSA 通知包", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa\\OSConfig", L"Security Packages", "LsaOsConfigSecurityPackages", L"本机", L"LSA OSConfig 安全包", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager", L"BootExecute", "BootExecute", L"本机", L"会话管理器启动前执行命令", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager", L"SetupExecute", "SetupExecute", L"本机", L"会话管理器 SetupExecute", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager", L"Execute", "SessionManagerExecute", L"本机", L"会话管理器 Execute", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"Shell", "PoliciesSystemShell", L"本机", L"策略指定系统 Shell", false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"Load", "WindowsLoad", L"当前用户", L"Windows 兼容 Load", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"Load", "MachineWindowsLoad", L"本机", L"系统级 Windows Load", false },
            // Boot and session bring-up: these run before, or instead of, the normal logon chain.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\SafeBoot", L"AlternateShell", "SafeBootAlternateShell", L"本机", L"安全模式备用 Shell", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager", L"S0InitialCommand", "S0InitialCommand", L"本机", L"会话管理器 S0InitialCommand", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\BootVerificationProgram", L"ImagePath", "BootVerificationProgram", L"本机", L"引导验证程序", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd", L"StartupPrograms", "TerminalServerStartupPrograms", L"本机", L"远程桌面会话启动程序", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", L"InitialProgram", "TerminalServerInitialProgram", L"本机", L"远程桌面初始程序", false },
            // Winlogon slots that are not Shell/Userinit and therefore easy to overlook.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"mpnotify", "WinlogonMpNotify", L"本机", L"Winlogon 多重通知程序", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"System", "WinlogonSystem", L"本机", L"Winlogon System 登录执行项", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"IconServiceLib", "IconServiceLib", L"本机", L"图标服务库", false },
            // Authentication and networking providers loaded into long-lived system processes.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\SecurityProviders", L"SecurityProviders", "SecurityProviders", L"本机", L"安全支持提供程序列表", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\WinSock2\\Parameters", L"AutodialDLL", "AutodialDll", L"本机", L"自动拨号 DLL", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\NetworkProvider\\Order", L"ProviderOrder", "NetworkProviderOrder", L"本机", L"网络提供程序顺序", false },
            // Crash and hang handlers: a debugger here is executed whenever the trigger fires.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", L"Debugger", "AeDebug", L"本机", L"崩溃即时调试器", false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", L"Debugger", "AeDebug32", L"本机(32位)", L"32 位崩溃即时调试器", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\Windows Error Reporting\\Hangs", L"Debugger", "WerHangsDebugger", L"本机", L"无响应进程调试器", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\Windows Error Reporting\\Hangs", L"ReflectDebugger", "WerReflectDebugger", L"本机", L"无响应进程镜像调试器", false },
            // Per-user logon hooks that need no administrative rights to install.
            { HKEY_CURRENT_USER, L"Environment", L"UserInitMprLogonScript", "UserInitMprLogonScript", L"当前用户", L"用户登录脚本", false },
            { HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"SCRNSAVE.EXE", "ScreenSaver", L"当前用户", L"屏幕保护程序", false },
            // The undocumented Office test key loads a DLL into every Office application.
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Office test\\Special\\Perf", L"", "OfficeTest", L"当前用户", L"Office Test 加载 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Office test\\Special\\Perf", L"", "OfficeTestMachine", L"本机", L"Office Test 加载 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Office test\\Special\\Perf", L"", "OfficeTest32", L"本机(32位)", L"32 位 Office Test 加载 DLL", false },
            // .NET profiler environment variables load an arbitrary DLL into every managed process.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"COR_ENABLE_PROFILING", "DotNetProfilerEnableMachine", L"本机", L".NET 分析器开关", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"COR_PROFILER", "DotNetProfilerClsidMachine", L"本机", L".NET 分析器 CLSID", true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"COR_PROFILER_PATH", "DotNetProfilerPathMachine", L"本机", L".NET 分析器 DLL 路径", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"CORECLR_ENABLE_PROFILING", "CoreClrProfilerEnableMachine", L"本机", L".NET Core 分析器开关", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"CORECLR_PROFILER", "CoreClrProfilerClsidMachine", L"本机", L".NET Core 分析器 CLSID", true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"CORECLR_PROFILER_PATH", "CoreClrProfilerPathMachine", L"本机", L".NET Core 分析器 DLL 路径", false },
            { HKEY_CURRENT_USER, L"Environment", L"COR_ENABLE_PROFILING", "DotNetProfilerEnableUser", L"当前用户", L".NET 分析器开关", false },
            { HKEY_CURRENT_USER, L"Environment", L"COR_PROFILER", "DotNetProfilerClsidUser", L"当前用户", L".NET 分析器 CLSID", true },
            { HKEY_CURRENT_USER, L"Environment", L"COR_PROFILER_PATH", "DotNetProfilerPathUser", L"当前用户", L".NET 分析器 DLL 路径", false },
            { HKEY_CURRENT_USER, L"Environment", L"CORECLR_ENABLE_PROFILING", "CoreClrProfilerEnableUser", L"当前用户", L".NET Core 分析器开关", false },
            { HKEY_CURRENT_USER, L"Environment", L"CORECLR_PROFILER", "CoreClrProfilerClsidUser", L"当前用户", L".NET Core 分析器 CLSID", true },
            { HKEY_CURRENT_USER, L"Environment", L"CORECLR_PROFILER_PATH", "CoreClrProfilerPathUser", L"当前用户", L".NET Core 分析器 DLL 路径", false },
            // AppDomainManager hijacking is configured through these two managed-runtime variables.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"APPDOMAIN_MANAGER_ASM", "AppDomainManagerAsmMachine", L"本机", L"AppDomainManager 程序集", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"APPDOMAIN_MANAGER_TYPE", "AppDomainManagerTypeMachine", L"本机", L"AppDomainManager 类型", false },
            { HKEY_CURRENT_USER, L"Environment", L"APPDOMAIN_MANAGER_ASM", "AppDomainManagerAsmUser", L"当前用户", L"AppDomainManager 程序集", false },
            { HKEY_CURRENT_USER, L"Environment", L"APPDOMAIN_MANAGER_TYPE", "AppDomainManagerTypeUser", L"当前用户", L"AppDomainManager 类型", false },
            // Additional debugger and DLL slots that no mainstream autostart tool inspects.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AeDebugProtected", L"Debugger", "AeDebugProtected", L"本机", L"受保护进程崩溃调试器", false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebugProtected", L"Debugger", "AeDebugProtected32", L"本机(32位)", L"32 位受保护进程崩溃调试器", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Cryptography\\Offload", L"ExpoOffload", "CryptoExpoOffload", L"本机", L"加密运算卸载 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Terminal Server Client", L"ClxDllPath", "RdpClxDll", L"本机", L"远程桌面客户端扩展 DLL", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Terminal Server\\AddIns\\TestDVCPlugin", L"Path", "RdpTestDvcPlugin", L"本机", L"远程桌面动态虚拟通道测试插件", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\SEMgr\\Wallet", L"DllName", "SeMgrWallet", L"本机", L"安全元件钱包 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\PushRouter\\Test", L"TestDllPath2", "PushRouterTestDll", L"本机", L"推送路由测试 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\WSMAN", L"NitsInjector", "WsmanNitsInjector", L"本机", L"WSMAN 注入测试 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\AirDrop", L"DllName", "AirDropDll", L"本机", L"AirDrop 组件 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Test", L"AdmParseLibrary", "GroupPolicyAdmParser", L"本机", L"组策略模板解析库", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\PeerDist\\Extension", L"PeerdistDllName", "PeerDistExtension", L"本机", L"对等分发扩展 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Test", L"EventerHookDll", "WindowsUpdateTestHook", L"本机", L"Windows 更新测试钩子 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Setup\\Pending", L"SPReviewEnabler", "SetupPendingReview", L"本机", L"安装挂起复查程序", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Console", L"ConsoleIME", "ConsoleIme", L"本机", L"控制台输入法程序", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\SideBySide", L"PreferExternalManifest", "PreferExternalManifest", L"本机", L"优先使用外部清单开关", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Direct3D", L"LoadDebugRuntime", "Direct3DDebugRuntime", L"本机", L"Direct3D 调试运行时开关", false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"RunGrpConv", "WinlogonRunGrpConv", L"当前用户", L"登录时运行组转换程序", false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\HtmlHelp Author", L"location", "HtmlHelpAuthor", L"当前用户", L"HTML 帮助作者 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\TestHooks", L"TestAggregatorDll", "DiagTrackTestHook", L"本机", L"遥测聚合器测试 DLL", false },
            { HKEY_CURRENT_USER, L"Environment", L"UserInitLogonScript", "UserInitLogonScript", L"当前用户", L"用户登录脚本变量", false },
            { HKEY_CURRENT_USER, L"Environment", L"UserInitLogonServer", "UserInitLogonServer", L"当前用户", L"用户登录脚本服务器", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Radio Support", L"SupportDLL", "BluetoothRadioSupport", L"本机", L"蓝牙无线电支持 DLL", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\ServerCore\\Shell Launcher", L"Shell", "ServerCoreShellLauncher", L"本机", L"Server Core 外壳启动器", false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer", L"MicrosoftRedirectionProgram", "EventViewerRedirection", L"本机", L"事件查看器帮助重定向程序", false },
            // Runtime injection variables honoured by managed, Java, CUDA and OpenSSL loaders.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"JAVA_TOOL_OPTIONS", "JavaToolOptionsMachine", L"本机", L"Java 工具选项注入", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"_JAVA_OPTIONS", "JavaOptionsMachine", L"本机", L"Java 选项注入", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"CUDA_INJECTION64_PATH", "CudaInjectionMachine", L"本机", L"CUDA 注入库路径", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"INTEL_LIBITTNOTIFY64", "IntelIttNotifyMachine", L"本机", L"Intel ITT 通知库", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"OPENSSL_MODULES", "OpenSslModulesMachine", L"本机", L"OpenSSL 模块目录", false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment", L"APPX_PROCESS", "AppxProcessMachine", L"本机", L"AppX 运行时加载开关", false },
            { HKEY_CURRENT_USER, L"Environment", L"JAVA_TOOL_OPTIONS", "JavaToolOptionsUser", L"当前用户", L"Java 工具选项注入", false },
            { HKEY_CURRENT_USER, L"Environment", L"_JAVA_OPTIONS", "JavaOptionsUser", L"当前用户", L"Java 选项注入", false },
            { HKEY_CURRENT_USER, L"Environment", L"CUDA_INJECTION64_PATH", "CudaInjectionUser", L"当前用户", L"CUDA 注入库路径", false },
            { HKEY_CURRENT_USER, L"Environment", L"INTEL_LIBITTNOTIFY64", "IntelIttNotifyUser", L"当前用户", L"Intel ITT 通知库", false },
            { HKEY_CURRENT_USER, L"Environment", L"OPENSSL_MODULES", "OpenSslModulesUser", L"当前用户", L"OpenSSL 模块目录", false },
            { HKEY_CURRENT_USER, L"Environment", L"APPX_PROCESS", "AppxProcessUser", L"当前用户", L"AppX 运行时加载开关", false }
        } };
        return specs;
    }

    // BuildValueEnumSpecList centralizes advanced registry keys where all values are inspected.
    const std::array<ValueEnumSpec, 35>& BuildValueEnumSpecList()
    {
        static const std::array<ValueEnumSpec, 35> specs{ {
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", "ShellExecuteHooks", L"本机", L"Explorer Shell Execute Hooks", true, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", "ShellExecuteHooksUser", L"当前用户", L"用户级 Explorer Shell Execute Hooks", true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler", "SharedTaskScheduler", L"本机", L"Explorer Shared Task Scheduler", true, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjectDelayLoad", "ShellDelayLoad", L"本机", L"Explorer 延迟加载 COM", true, false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjectDelayLoad", "ShellDelayLoadUser", L"当前用户", L"用户级 Explorer 延迟加载 COM", true, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved", "ShellExtensionsApproved", L"本机", L"Shell 扩展白名单", false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved", "ShellExtensionsApprovedUser", L"当前用户", L"用户级 Shell 扩展白名单", false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Internet Explorer\\URLSearchHooks", "IEUrlSearchHooks", L"本机", L"Internet Explorer URL Search Hooks", true, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\URLSearchHooks", "IEUrlSearchHooksUser", L"当前用户", L"用户级 URL Search Hooks", true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Internet Explorer\\Toolbar", "IEToolbar", L"本机", L"Internet Explorer Toolbar", true, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\Toolbar", "IEToolbarUser", L"当前用户", L"用户级 Internet Explorer Toolbar", true, true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls", "AppCertDlls", L"本机", L"AppCert DLL 注入点", false, false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", "KnownDlls", L"本机", L"Known DLL 列表", false, false },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs32", "KnownDlls32", L"本机", L"32 位 Known DLL 列表", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32", "Drivers32", L"本机", L"系统解码器/媒体驱动", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32", "Drivers32Wow64", L"本机(32位)", L"32 位解码器/媒体驱动", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceExRoot", L"本机", L"RunOnceEx 根键直接值", false, false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceExRootUser", L"当前用户", L"用户级 RunOnceEx 根键直接值", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceExRoot32", L"本机(32位)", L"32 位 RunOnceEx 根键直接值", false, false },
            // Font drivers and netsh helpers are DLL lists loaded by long-lived system components.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Font Drivers", "FontDrivers", L"本机", L"字体驱动列表", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Netsh", "NetshHelper", L"本机", L"netsh 助手 DLL", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Netsh", "NetshHelper32", L"本机(32位)", L"32 位 netsh 助手 DLL", false, false },
            // WER loads these modules into a crashing process before the report is produced.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\Windows Error Reporting\\RuntimeExceptionHelperModules", "WerRuntimeExceptionHelper", L"本机", L"WER 运行时异常助手模块", false, false },
            // StartupApproved records which logon items were switched off outside this tool.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run", "StartupApprovedRun", L"本机", L"登录项启用状态记录", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32", "StartupApprovedRun32", L"本机(32位)", L"32 位登录项启用状态记录", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder", "StartupApprovedFolder", L"本机", L"启动文件夹启用状态记录", false, false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run", "StartupApprovedRunUser", L"当前用户", L"登录项启用状态记录", false, false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32", "StartupApprovedRun32User", L"当前用户", L"32 位登录项启用状态记录", false, false },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder", "StartupApprovedFolderUser", L"当前用户", L"启动文件夹启用状态记录", false, false },
            // DLL substitution lists consulted by the loader, the debugger and Explorer helpers.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Wow64\\x86", "Wow64x86Layer", L"本机", L"WOW64 x86 层 DLL 替换", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\KnownManagedDebuggingDlls", "KnownManagedDebuggingDlls", L"本机", L"托管调试 DLL 列表", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\MiniDumpAuxiliaryDlls", "MiniDumpAuxiliaryDlls", L"本机", L"小型转储辅助 DLL 列表", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer", "ExplorerMyComputerTools", L"本机", L"我的电脑工具路径", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\WirelessDocking\\DockingProviderDLLs", "WirelessDockingProviders", L"本机", L"无线扩展坞提供程序 DLL", false, false },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\MSDTC\\XADLL", "MsdtcXaDll", L"本机", L"MSDTC XA 事务 DLL", false, false }
        } };
        return specs;
    }

    // BuildSubKeyValueSpecList centralizes subkey-driven advanced registry persistence coverage.
    const std::array<SubKeyValueSpec, 56>& BuildSubKeyValueSpecList()
    {
        static const std::array<SubKeyValueSpec, 56> specs{ {
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Active Setup\\Installed Components", L"StubPath", "ActiveSetup", L"本机", L"Active Setup StubPath", true, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", L"DLLName", "WinlogonNotify", L"本机", L"Winlogon Notify 包", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers", L"", "CredentialProvider", L"本机", L"Credential Provider", false, true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters", L"", "CredentialProviderFilter", L"本机", L"Credential Provider Filter", false, true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\PLAP Providers", L"", "PlapProvider", L"本机", L"PLAP Provider", false, true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", L"", "BHO", L"本机", L"Browser Helper Object", false, true, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", L"", "BHO-User", L"当前用户", L"用户级 Browser Helper Object", false, true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Internet Explorer\\Explorer Bars", L"", "IEExplorerBar", L"本机", L"Internet Explorer Explorer Bar", false, true, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\Explorer Bars", L"", "IEExplorerBar-User", L"当前用户", L"用户级 Explorer Bar", false, true, true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Print\\Monitors", L"Driver", "PrintMonitor", L"本机", L"打印监视器驱动", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers", L"", "ShellIconOverlay", L"本机", L"Shell 图标覆盖标识符", true, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Sidebar\\Gadgets", L"Path", "SidebarGadget", L"本机", L"Sidebar Gadget 注册", false, false, true },
            // Service-hosted DLL providers: each subkey names a module a system service loads.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\W32Time\\TimeProviders", L"DllName", "TimeProvider", L"本机", L"时间提供程序", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions", L"DllName", "GroupPolicyExtension", L"本机", L"组策略客户端扩展", false, false, true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Print\\Environments\\Windows x64\\Print Processors", L"Driver", "PrintProcessor", L"本机", L"打印处理器", false, false, true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Print\\Environments\\Windows NT x86\\Print Processors", L"Driver", "PrintProcessor32", L"本机(32位)", L"32 位打印处理器", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\AMSI\\Providers", L"", "AmsiProvider", L"本机", L"AMSI 提供程序", false, true, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\TelemetryController", L"Command", "TelemetryController", L"本机", L"遥测控制器命令", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB", L"DatabasePath", "AppCompatShimDatabase", L"本机", L"已安装应用兼容性补丁库", false, false, true },
            // Protocol handlers are instantiated by Explorer, Office and every WinINet consumer.
            { HKEY_LOCAL_MACHINE, L"Software\\Classes\\Protocols\\Filter", L"CLSID", "ProtocolFilter", L"本机", L"协议过滤器", true, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Classes\\Protocols\\Handler", L"CLSID", "ProtocolHandler", L"本机", L"协议处理器", true, false, true },
            { HKEY_CURRENT_USER, L"Software\\Classes\\Protocols\\Filter", L"CLSID", "ProtocolFilterUser", L"当前用户", L"用户级协议过滤器", true, false, true },
            { HKEY_CURRENT_USER, L"Software\\Classes\\Protocols\\Handler", L"CLSID", "ProtocolHandlerUser", L"当前用户", L"用户级协议处理器", true, false, true },
            // Views of already-covered families that the previous table only checked in one hive.
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Active Setup\\Installed Components", L"StubPath", "ActiveSetup32", L"本机(32位)", L"32 位 Active Setup StubPath", true, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Active Setup\\Installed Components", L"StubPath", "ActiveSetupUser", L"当前用户", L"用户级 Active Setup StubPath", true, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers", L"", "ShellIconOverlayUser", L"当前用户", L"用户级 Shell 图标覆盖标识符", true, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", L"", "BHO32", L"本机(32位)", L"32 位 Browser Helper Object", false, true, true },
            // Office add-ins load into a signed Microsoft host process on every document open.
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Office\\Word\\Addins", L"FriendlyName", "OfficeAddinWordUser", L"当前用户", L"Word 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Office\\Excel\\Addins", L"FriendlyName", "OfficeAddinExcelUser", L"当前用户", L"Excel 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Office\\PowerPoint\\Addins", L"FriendlyName", "OfficeAddinPowerPointUser", L"当前用户", L"PowerPoint 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Office\\Outlook\\Addins", L"FriendlyName", "OfficeAddinOutlookUser", L"当前用户", L"Outlook 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Office\\Word\\Addins", L"FriendlyName", "OfficeAddinWord", L"本机", L"Word 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Office\\Excel\\Addins", L"FriendlyName", "OfficeAddinExcel", L"本机", L"Excel 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Office\\PowerPoint\\Addins", L"FriendlyName", "OfficeAddinPowerPoint", L"本机", L"PowerPoint 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Office\\Outlook\\Addins", L"FriendlyName", "OfficeAddinOutlook", L"本机", L"Outlook 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Office\\Word\\Addins", L"FriendlyName", "OfficeAddinWord32", L"本机(32位)", L"32 位 Word 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Office\\Excel\\Addins", L"FriendlyName", "OfficeAddinExcel32", L"本机(32位)", L"32 位 Excel 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Office\\PowerPoint\\Addins", L"FriendlyName", "OfficeAddinPowerPoint32", L"本机(32位)", L"32 位 PowerPoint 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Office\\Outlook\\Addins", L"FriendlyName", "OfficeAddinOutlook32", L"本机(32位)", L"32 位 Outlook 加载项（子键名为 ProgID）", false, false, true },
            // Subkey-driven load points documented by persistence research but absent from Autoruns.
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches", L"", "DiskCleanupHandler", L"本机", L"磁盘清理处理程序", true, false, true },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\MUI\\CallbackDlls", L"DllPath", "MuiCallbackDll", L"本机", L"MUI 回调 DLL", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\IdentityStore\\Providers", L"ApPluginDLLPath", "IdentityStoreProvider", L"本机", L"标识存储提供程序 DLL", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs", L"StartExe", "AccessibilityTool", L"本机", L"辅助功能工具", false, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\PostBootReminders", L"ShellExecute", "PostBootReminder", L"当前用户", L"启动后提醒程序", false, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AppKey", L"ShellExecute", "AppKeyCommand", L"当前用户", L"多媒体按键命令", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Legacy CPL Map", L"ShellExecute", "LegacyCplMap", L"本机", L"旧式控制面板映射", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Active Setup\\Installed Components", L"RealStubPath", "ActiveSetupRealStubPath", L"本机", L"Active Setup 真实 StubPath", true, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Clients\\Mail", L"DLLPath", "MailClientDll", L"本机", L"邮件客户端 MAPI DLL", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\VBA\\Monitors", L"CLSID", "VbaMonitor", L"本机", L"VBA 事件监视器", true, false, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\VBA\\VBE\\6.0\\Addins", L"FriendlyName", "VbeAddin", L"当前用户", L"VBE 加载项（子键名为 ProgID）", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\ALG\\ISV", L"", "AlgIsvPlugin", L"本机", L"应用层网关 ISV 插件", false, true, true },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Terminal Server Client\\Default\\Addins", L"Name", "RdpClientAddinUser", L"当前用户", L"远程桌面客户端插件", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Terminal Server Client\\Default\\Addins", L"Name", "RdpClientAddin", L"本机", L"远程桌面客户端插件", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers\\Handlers", L"InvokeProgID", "AutoplayHandler", L"本机", L"自动播放处理程序", false, false, true },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\RunOnceEntries", L"", "InstallerRunOnceEntry", L"本机", L"Windows Installer 一次性执行项", false, false, true },
            // FailureCommand runs whenever the service crashes, which makes it a durable trigger.
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services", L"FailureCommand", "ServiceFailureCommand", L"本机", L"服务失败恢复命令", false, false, false }
        } };
        return specs;
    }

    // AppendValueBasedLogonEntry adapts a registry value under a Run-like key into StartupEntry.
    void AppendValueBasedLogonEntry(std::vector<ks::startup::StartupEntry>& entries, const RunKeySpec& spec, const RegistryValueRecord& valueRecord)
    {
        if (ks::str::TrimCopy(valueRecord.valueDataText).empty())
        {
            return;
        }
        const std::wstring subKeyText(spec.subKeyText);
        const std::string locationText = BuildRegistryLocationText(spec.rootKey, subKeyText);
        ks::startup::StartupEntry entry;
        entry.category = ks::startup::StartupCategory::Logon;
        entry.categoryText = ks::startup::CategoryToText(entry.category);
        entry.itemNameText = ks::str::TrimCopy(valueRecord.valueNameText).empty() ? FromWide(L"(\u9ed8\u8ba4\u503c)") : valueRecord.valueNameText;
        entry.locationText = locationText;
        entry.locationGroupText = locationText;
        entry.userText = FromWide(spec.userText);
        entry.sourceTypeText = spec.sourceTypeText;
        entry.detailText = FromWide(spec.detailText);
        entry.uniqueIdText = "REGLOGON|" + locationText + "|" + entry.itemNameText;
        FinalizeRegistryEntry(entry, valueRecord.valueDataText, std::string(), valueRecord.valueNameText, false, false);
        const bool policyManaged = LowerWideCopy(subKeyText).find(L"\\policies\\") != std::wstring::npos;
        const bool machineScope = spec.rootKey == HKEY_LOCAL_MACHINE;
        ConfigureRegistryValueAction(
            entry,
            spec.rootKey,
            subKeyText,
            valueRecord,
            policyManaged || machineScope
                ? ks::startup::StartupRiskLevel::Critical
                : ks::startup::StartupRiskLevel::Elevated,
            policyManaged ? "policy" : (machineScope ? "registry_machine" : "registry_user"),
            policyManaged
                ? FromWide(L"策略管理的启动值允许修改，但系统策略可能立即将其恢复；继续前请确认影响范围。")
                : (machineScope
                    ? FromWide(L"修改机器范围启动值需要管理员权限，并会影响所有用户。")
                    : FromWide(L"修改前会保存原始注册表类型和数据；其他软件仍可能并发改写该值。")));
        entries.push_back(std::move(entry));
    }

    // AppendRunOnceExEntries handles RunOnceEx subkey/value layout specially.
    void AppendRunOnceExEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        const std::array<RunKeySpec, 3> specs{ {
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceEx", L"本机", L"RunOnceEx 子键值" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceExUser", L"当前用户", L"用户级 RunOnceEx 子键值" },
            { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceEx32", L"本机(32位)", L"32 位 RunOnceEx 子键值" }
        } };
        for (const RunKeySpec& spec : specs)
        {
            const std::wstring rootSubKey(spec.subKeyText);
            const std::string groupLocationText = BuildRegistryLocationText(spec.rootKey, rootSubKey);
            for (const std::wstring& subKeyName : EnumerateRegistrySubKeys(spec.rootKey, rootSubKey))
            {
                const std::wstring itemSubKey = rootSubKey + L"\\" + subKeyName;
                for (const RegistryValueRecord& valueRecord : EnumerateRegistryValues(spec.rootKey, itemSubKey))
                {
                    const std::string valueName = ks::str::TrimCopy(valueRecord.valueNameText);
                    if (ks::str::TrimCopy(valueRecord.valueDataText).empty() || LowerAsciiCopy(valueName) == "flags" || LowerAsciiCopy(valueName) == "title")
                    {
                        continue;
                    }
                    const std::string subKeyNameText = FromWide(subKeyName);
                    ks::startup::StartupEntry entry;
                    entry.category = ks::startup::StartupCategory::Logon;
                    entry.categoryText = ks::startup::CategoryToText(entry.category);
                    entry.itemNameText = valueName.empty()
                        ? subKeyNameText + FromWide(L"\\(\u9ed8\u8ba4\u503c)")
                        : subKeyNameText + "\\" + valueName;
                    entry.locationText = BuildRegistryLocationText(spec.rootKey, itemSubKey);
                    entry.locationGroupText = groupLocationText;
                    entry.userText = FromWide(spec.userText);
                    entry.sourceTypeText = spec.sourceTypeText;
                    entry.detailText = FromWide(spec.detailText) + FromWide(L"\uff1b\u5b50\u952e=") + subKeyNameText;
                    entry.uniqueIdText = "RUNONCEEX|" + entry.locationText + "|" + entry.itemNameText;
                    FinalizeRegistryEntry(entry, valueRecord.valueDataText, std::string(), valueRecord.valueNameText, false, false);
                    ConfigureRegistryValueAction(
                        entry,
                        spec.rootKey,
                        itemSubKey,
                        valueRecord,
                        ks::startup::StartupRiskLevel::Elevated,
                        "unsupported_source",
                        FromWide(L"RunOnceEx 具有嵌套执行语义；修改单个值可能改变整组一次性启动命令的执行顺序。"));
                    entries.push_back(std::move(entry));
                }
            }
        }
    }

    // AppendStartupFolderEntries enumerates per-user and machine Startup folders.
    void AppendStartupFolderEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        const std::array<std::pair<std::wstring, const wchar_t*>, 2> folders{ {
            { KnownFolderPath(FOLDERID_Startup), L"当前用户" },
            { KnownFolderPath(FOLDERID_CommonStartup), L"本机" }
        } };
        for (const auto& folder : folders)
        {
            if (folder.first.empty())
            {
                continue;
            }
            std::error_code ec;
            if (!std::filesystem::exists(folder.first, ec) || !std::filesystem::is_directory(folder.first, ec))
            {
                continue;
            }
            std::vector<std::filesystem::directory_entry> fileEntries;
            for (const auto& dirEntry : std::filesystem::directory_iterator(folder.first, ec))
            {
                const std::filesystem::file_status linkStatus = dirEntry.symlink_status(ec);
                if (!ec && !std::filesystem::is_directory(linkStatus))
                {
                    fileEntries.push_back(dirEntry);
                }
            }
            std::sort(fileEntries.begin(), fileEntries.end(), [](const auto& left, const auto& right) {
                return LowerWideCopy(left.path().filename().wstring()) < LowerWideCopy(right.path().filename().wstring());
            });
            for (const auto& fileEntry : fileEntries)
            {
                const std::string filePathText = ToNativeSeparators(FromWide(fileEntry.path().wstring()));
                ks::startup::StartupEntry entry;
                entry.category = ks::startup::StartupCategory::Logon;
                entry.categoryText = ks::startup::CategoryToText(entry.category);
                entry.itemNameText = FromWide(fileEntry.path().filename().wstring());
                entry.commandText = filePathText;
                entry.imagePathText = filePathText;
                entry.publisherText = ks::startup::QueryPublisherTextByPath(entry.imagePathText);
                entry.locationText = ToNativeSeparators(FromWide(folder.first));
                entry.userText = FromWide(folder.second);
                entry.sourceTypeText = "StartupFolder";
                entry.detailText = FromWide(L"开始菜单启动文件夹");
                entry.enabled = true;
                FileIdentitySnapshot identity;
                DWORD identityError = ERROR_SUCCESS;
                const bool identityValid = QueryFileIdentityNoReparse(
                    fileEntry.path().wstring(),
                    identity,
                    identityError);
                entry.canOpenFileLocation = identityValid;
                entry.canDelete = false;
                entry.imagePathExists = identityValid;
                entry.uniqueIdText = "STARTUPFOLDER|" + filePathText;
                const bool machineScope = folder.second == std::wstring(L"\u672c\u673a");
                entry.actionKind = ks::startup::StartupActionKind::StartupFolderFile;
                entry.actionLocator.originalFilePathText = filePathText;
                entry.actionLocator.fileIdentitySnapshotValid = identityValid;
                entry.actionLocator.fileVolumeSerial = identity.volumeSerial;
                entry.actionLocator.fileIndex = identity.fileIndex;
                entry.actionLocator.fileSize = identity.fileSize;
                entry.actionLocator.fileLastWriteTime = identity.lastWriteTime;
                entry.canEnable = false;
                entry.canDisable = true;
                entry.riskLevel = machineScope || !identityValid
                    ? ks::startup::StartupRiskLevel::Critical
                    : ks::startup::StartupRiskLevel::Elevated;
                entry.riskReasonCode = machineScope ? "machine_scope" : "startup_folder";
                entry.riskReasonText = machineScope
                    ? FromWide(L"修改公共启动文件夹会影响所有用户，并且通常需要管理员权限。")
                    : (!identityValid
                        ? FromWide(L"无法取得不跟随重解析点的稳定文件身份；继续操作可能移动链接目标或已变化的文件。")
                        : FromWide(L"文件会移动到 KSword 暂存目录；跨卷移动或并发文件操作仍可能失败。"));
                entry.canDelete = true;
                entry.lastErrorCode = identityValid ? ERROR_SUCCESS : identityError;
                entries.push_back(std::move(entry));
            }
        }
    }

    // ScriptFileBase names the anchor a non-registry autostart path is resolved against.
    // Known folders are preferred over %ENV% so a poisoned environment cannot redirect the scan.
    enum class ScriptFileBase : int
    {
        SystemRoot = 0, // %SystemRoot%: group policy scripts and machine-wide PowerShell profiles.
        Documents,      // Documents known folder: per-user PowerShell profiles (may be OneDrive-redirected).
        RoamingAppData, // Roaming AppData: Office startup directories and VBA projects.
        ProgramFiles    // Program Files: PowerShell 7 machine-wide profiles.
    };

    // ScriptFileSpec describes one file-based autostart family that no registry key points at.
    struct ScriptFileSpec
    {
        ScriptFileBase baseKind = ScriptFileBase::SystemRoot;
        const wchar_t* relativePathText = L""; // Path under the base; directory or single file.
        bool isDirectory = false;              // true: every file inside is an autostart payload.
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
    };

    // BuildScriptFileSpecList centralizes the file-based autostart families.
    // These execute without any Run key or scheduled task, which is exactly why they get missed.
    const std::array<ScriptFileSpec, 23>& BuildScriptFileSpecList()
    {
        static const std::array<ScriptFileSpec, 23> specs{ {
            // Group policy scripts run as SYSTEM at boot and as the user at logon.
            { ScriptFileBase::SystemRoot, L"System32\\GroupPolicy\\Machine\\Scripts\\Startup", true, "GpoStartupScript", L"本机", L"组策略计算机启动脚本" },
            { ScriptFileBase::SystemRoot, L"System32\\GroupPolicy\\Machine\\Scripts\\Shutdown", true, "GpoShutdownScript", L"本机", L"组策略计算机关机脚本" },
            { ScriptFileBase::SystemRoot, L"System32\\GroupPolicy\\User\\Scripts\\Logon", true, "GpoLogonScript", L"本机", L"组策略用户登录脚本" },
            { ScriptFileBase::SystemRoot, L"System32\\GroupPolicy\\User\\Scripts\\Logoff", true, "GpoLogoffScript", L"本机", L"组策略用户注销脚本" },
            { ScriptFileBase::SystemRoot, L"System32\\GroupPolicy\\Machine\\Scripts\\scripts.ini", false, "GpoScriptManifest", L"本机", L"组策略计算机脚本清单" },
            { ScriptFileBase::SystemRoot, L"System32\\GroupPolicy\\Machine\\Scripts\\psscripts.ini", false, "GpoPowerShellScriptManifest", L"本机", L"组策略计算机 PowerShell 脚本清单" },
            { ScriptFileBase::SystemRoot, L"System32\\GroupPolicy\\User\\Scripts\\scripts.ini", false, "GpoUserScriptManifest", L"本机", L"组策略用户脚本清单" },
            { ScriptFileBase::SystemRoot, L"System32\\GroupPolicy\\User\\Scripts\\psscripts.ini", false, "GpoUserPowerShellScriptManifest", L"本机", L"组策略用户 PowerShell 脚本清单" },
            // Every PowerShell profile runs on each interactive shell start.
            { ScriptFileBase::SystemRoot, L"System32\\WindowsPowerShell\\v1.0\\profile.ps1", false, "PowerShellAllHostsProfile", L"本机", L"所有用户所有宿主 PowerShell 配置文件" },
            { ScriptFileBase::SystemRoot, L"System32\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1", false, "PowerShellConsoleProfile", L"本机", L"所有用户控制台 PowerShell 配置文件" },
            { ScriptFileBase::SystemRoot, L"SysWOW64\\WindowsPowerShell\\v1.0\\profile.ps1", false, "PowerShellAllHostsProfile32", L"本机(32位)", L"32 位所有用户 PowerShell 配置文件" },
            { ScriptFileBase::SystemRoot, L"SysWOW64\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1", false, "PowerShellConsoleProfile32", L"本机(32位)", L"32 位所有用户控制台 PowerShell 配置文件" },
            { ScriptFileBase::Documents, L"WindowsPowerShell\\profile.ps1", false, "PowerShellUserAllHostsProfile", L"当前用户", L"用户所有宿主 PowerShell 配置文件" },
            { ScriptFileBase::Documents, L"WindowsPowerShell\\Microsoft.PowerShell_profile.ps1", false, "PowerShellUserConsoleProfile", L"当前用户", L"用户控制台 PowerShell 配置文件" },
            { ScriptFileBase::Documents, L"PowerShell\\profile.ps1", false, "PwshUserAllHostsProfile", L"当前用户", L"用户 PowerShell 7 所有宿主配置文件" },
            { ScriptFileBase::Documents, L"PowerShell\\Microsoft.PowerShell_profile.ps1", false, "PwshUserConsoleProfile", L"当前用户", L"用户 PowerShell 7 控制台配置文件" },
            { ScriptFileBase::ProgramFiles, L"PowerShell\\7\\profile.ps1", false, "PwshAllHostsProfile", L"本机", L"PowerShell 7 所有用户配置文件" },
            { ScriptFileBase::ProgramFiles, L"PowerShell\\7\\Microsoft.PowerShell_profile.ps1", false, "PwshConsoleProfile", L"本机", L"PowerShell 7 所有用户控制台配置文件" },
            // Office loads these locations on every document open without any registry entry.
            { ScriptFileBase::RoamingAppData, L"Microsoft\\Word\\STARTUP", true, "OfficeWordStartup", L"当前用户", L"Word 启动目录加载项" },
            { ScriptFileBase::RoamingAppData, L"Microsoft\\Excel\\XLSTART", true, "OfficeExcelXlStart", L"当前用户", L"Excel 自动打开目录" },
            { ScriptFileBase::RoamingAppData, L"Microsoft\\AddIns", true, "OfficeUserAddIns", L"当前用户", L"Office 用户加载项目录" },
            { ScriptFileBase::RoamingAppData, L"Microsoft\\Outlook\\VbaProject.OTM", false, "OutlookVbaProject", L"当前用户", L"Outlook VBA 工程" },
            { ScriptFileBase::RoamingAppData, L"Microsoft\\Templates\\Normal.dotm", false, "WordNormalTemplate", L"当前用户", L"Word 通用模板（可携带自动宏）" }
        } };
        return specs;
    }

    // ResolveScriptFileBase turns a base kind into an absolute directory, or empty when unavailable.
    std::wstring ResolveScriptFileBase(const ScriptFileBase baseKind)
    {
        switch (baseKind)
        {
        case ScriptFileBase::SystemRoot:
            return QueryEnvironmentWide(L"SystemRoot");
        case ScriptFileBase::Documents:
            return KnownFolderPath(FOLDERID_Documents);
        case ScriptFileBase::RoamingAppData:
            return KnownFolderPath(FOLDERID_RoamingAppData);
        case ScriptFileBase::ProgramFiles:
            return KnownFolderPath(FOLDERID_ProgramFiles);
        }
        return std::wstring();
    }

    // AppendScriptFileEntry adds one report-only record for a file-based autostart payload.
    // These files have no reversible backend operation: the enable/disable and delete paths only
    // accept the two known Startup folders, so revalidating them here would be a lie.
    void AppendScriptFileEntry(
        std::vector<ks::startup::StartupEntry>& entries,
        const ScriptFileSpec& spec,
        const std::filesystem::path& filePath,
        const std::wstring& groupPathText)
    {
        const std::string filePathText = ToNativeSeparators(FromWide(filePath.wstring()));
        ks::startup::StartupEntry entry;
        entry.category = ks::startup::StartupCategory::Logon;
        entry.categoryText = ks::startup::CategoryToText(entry.category);
        entry.itemNameText = FromWide(filePath.filename().wstring());
        entry.commandText = filePathText;
        entry.imagePathText = filePathText;
        entry.publisherText = ks::startup::QueryPublisherTextByPath(entry.imagePathText);
        entry.locationText = ToNativeSeparators(FromWide(groupPathText));
        entry.userText = FromWide(spec.userText);
        entry.sourceTypeText = spec.sourceTypeText;
        entry.detailText = FromWide(spec.detailText);
        entry.imagePathExists = true;
        entry.canOpenFileLocation = true;
        entry.uniqueIdText = "SCRIPTFILE|" + filePathText;
        MarkEntryActionUnavailable(
            entry,
            ks::startup::StartupRiskLevel::Critical,
            "script_file",
            FromWide(L"脚本与加载项文件没有可逆的后端操作；请在确认内容后手工处理，删除组策略脚本还可能被策略刷新还原。"));
        entry.canOpenRegistryLocation = false;
        entries.push_back(std::move(entry));
    }

    // AppendScriptFileEntries walks every file-based autostart family in the catalog.
    void AppendScriptFileEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        for (const ScriptFileSpec& spec : BuildScriptFileSpecList())
        {
            const std::wstring baseText = ResolveScriptFileBase(spec.baseKind);
            if (baseText.empty())
            {
                continue;
            }
            const std::filesystem::path targetPath =
                std::filesystem::path(baseText) / std::filesystem::path(spec.relativePathText);
            std::error_code errorCode;
            if (!spec.isDirectory)
            {
                // Single-file families: report the file only when it actually exists.
                if (std::filesystem::is_regular_file(targetPath, errorCode) && !errorCode)
                {
                    AppendScriptFileEntry(entries, spec, targetPath, targetPath.parent_path().wstring());
                }
                continue;
            }
            if (!std::filesystem::is_directory(targetPath, errorCode) || errorCode)
            {
                continue;
            }
            // Directory families: every regular file inside is loaded, whatever its name.
            std::size_t reportedCount = 0;
            for (const auto& directoryEntry : std::filesystem::directory_iterator(targetPath, errorCode))
            {
                if (errorCode || reportedCount >= 64)
                {
                    break;
                }
                const std::filesystem::file_status linkStatus = directoryEntry.symlink_status(errorCode);
                if (errorCode || std::filesystem::is_directory(linkStatus))
                {
                    continue;
                }
                ++reportedCount;
                AppendScriptFileEntry(entries, spec, directoryEntry.path(), targetPath.wstring());
            }
        }
    }

    // GroupPolicyScriptSpec describes one policy phase whose scripts live three levels deep.
    struct GroupPolicyScriptSpec
    {
        HKEY rootKey = nullptr;
        const wchar_t* subKeyText = L"";
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
    };

    // AppendGroupPolicyScriptEntries reads the policy script index that drives GPO script execution.
    // Layout: <phase>\{GPO GUID}\{index} with Script and Parameters values, so a flat table cannot
    // express it and the generic subkey walker would stop one level too early.
    void AppendGroupPolicyScriptEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        static const std::array<GroupPolicyScriptSpec, 4> specs{ {
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Startup", "GpoScriptStartup", L"本机", L"组策略启动脚本注册" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Shutdown", "GpoScriptShutdown", L"本机", L"组策略关机脚本注册" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logon", "GpoScriptLogon", L"当前用户", L"组策略登录脚本注册" },
            { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logoff", "GpoScriptLogoff", L"当前用户", L"组策略注销脚本注册" }
        } };

        for (const GroupPolicyScriptSpec& spec : specs)
        {
            const std::wstring phaseSubKey(spec.subKeyText);
            const std::string groupLocationText = BuildRegistryLocationText(spec.rootKey, phaseSubKey);
            for (const std::wstring& policyName : EnumerateRegistrySubKeys(spec.rootKey, phaseSubKey))
            {
                const std::wstring policySubKey = phaseSubKey + L"\\" + policyName;
                for (const std::wstring& indexName : EnumerateRegistrySubKeys(spec.rootKey, policySubKey))
                {
                    const std::wstring itemSubKey = policySubKey + L"\\" + indexName;
                    const auto scriptRecord = QueryRegistryValueRecord(spec.rootKey, itemSubKey, L"Script");
                    if (!scriptRecord.has_value() || ks::str::TrimCopy(scriptRecord->valueDataText).empty())
                    {
                        continue;
                    }
                    // Parameters are part of what actually executes, so they belong in the command text.
                    const auto parameterRecord = QueryRegistryValueRecord(spec.rootKey, itemSubKey, L"Parameters");
                    std::string commandText = scriptRecord->valueDataText;
                    if (parameterRecord.has_value() && !ks::str::TrimCopy(parameterRecord->valueDataText).empty())
                    {
                        commandText += " " + parameterRecord->valueDataText;
                    }
                    ks::startup::StartupEntry entry;
                    entry.category = ks::startup::StartupCategory::Registry;
                    entry.categoryText = ks::startup::CategoryToText(entry.category);
                    entry.itemNameText = FromWide(policyName) + "\\" + FromWide(indexName);
                    entry.locationText = BuildRegistryLocationText(spec.rootKey, itemSubKey);
                    entry.locationGroupText = groupLocationText;
                    entry.userText = FromWide(spec.userText);
                    entry.sourceTypeText = spec.sourceTypeText;
                    entry.detailText = FromWide(spec.detailText);
                    entry.uniqueIdText = "GPOSCRIPT|" + entry.locationText;
                    FinalizeRegistryEntry(
                        entry,
                        commandText,
                        std::string(),
                        scriptRecord->valueNameText,
                        false,
                        false);
                    ConfigureRegistryValueAction(
                        entry,
                        spec.rootKey,
                        itemSubKey,
                        *scriptRecord,
                        ks::startup::StartupRiskLevel::Critical,
                        "policy",
                        FromWide(L"组策略脚本由策略引擎下发；本地修改会在下一次策略刷新时被还原，应从策略源头处理。"));
                    entries.push_back(std::move(entry));
                }
            }
        }
    }
}

namespace
{
    // AppendSingleValueEntries adds fixed key/value advanced registry records.
    void AppendSingleValueEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        for (const SingleValueSpec& spec : BuildSingleValueSpecList())
        {
            const std::wstring subKeyText(spec.subKeyText);
            const std::wstring valueNameText(spec.valueNameText);
            const auto valueRecord = QueryRegistryValueRecord(spec.rootKey, subKeyText, valueNameText);
            if (!valueRecord.has_value() || ks::str::TrimCopy(valueRecord->valueDataText).empty())
            {
                continue;
            }
            ks::startup::StartupEntry entry;
            entry.category = ks::startup::StartupCategory::Registry;
            entry.categoryText = ks::startup::CategoryToText(entry.category);
            entry.itemNameText = valueNameText.empty() ? FromWide(L"(\u9ed8\u8ba4\u503c)") : FromWide(valueNameText);
            entry.locationText = BuildRegistryLocationText(spec.rootKey, subKeyText);
            entry.locationGroupText = entry.locationText;
            entry.userText = FromWide(spec.userText);
            entry.sourceTypeText = spec.sourceTypeText;
            entry.detailText = FromWide(spec.detailText);
            entry.uniqueIdText = "SINGLE|" + entry.locationText + "|" + entry.itemNameText;
            FinalizeRegistryEntry(entry, valueRecord->valueDataText, std::string(), FromWide(valueNameText), false, spec.resolveClsidFromValueData);
            const bool policyManaged = LowerWideCopy(subKeyText).find(L"\\policies\\") != std::wstring::npos;
            ConfigureRegistryValueAction(
                entry,
                spec.rootKey,
                subKeyText,
                *valueRecord,
                ks::startup::StartupRiskLevel::Critical,
                policyManaged ? "policy" : "critical_registry",
                policyManaged
                    ? FromWide(L"策略管理的注册表持久化项允许修改，但系统策略可能覆盖更改。")
                    : FromWide(L"此值属于 Winlogon、LSA 或会话管理器等关键启动路径；错误修改可能导致无法登录或系统异常。"));
            entries.push_back(std::move(entry));
        }
    }

    // AppendValueEnumEntries adds one record for each non-empty value under known advanced keys.
    void AppendValueEnumEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        for (const ValueEnumSpec& spec : BuildValueEnumSpecList())
        {
            const std::wstring subKeyText(spec.subKeyText);
            const std::string locationText = BuildRegistryLocationText(spec.rootKey, subKeyText);
            for (const RegistryValueRecord& valueRecord : EnumerateRegistryValues(spec.rootKey, subKeyText))
            {
                if (ks::str::TrimCopy(valueRecord.valueDataText).empty())
                {
                    continue;
                }
                ks::startup::StartupEntry entry;
                entry.category = ks::startup::StartupCategory::Registry;
                entry.categoryText = ks::startup::CategoryToText(entry.category);
                entry.itemNameText = ks::str::TrimCopy(valueRecord.valueNameText).empty() ? FromWide(L"(\u9ed8\u8ba4\u503c)") : valueRecord.valueNameText;
                entry.locationText = locationText;
                entry.locationGroupText = locationText;
                entry.userText = FromWide(spec.userText);
                entry.sourceTypeText = spec.sourceTypeText;
                entry.detailText = FromWide(spec.detailText);
                entry.uniqueIdText = "VALUEENUM|" + locationText + "|" + entry.itemNameText;
                FinalizeRegistryEntry(
                    entry,
                    valueRecord.valueDataText,
                    spec.resolveClsidFromValueName ? valueRecord.valueNameText : std::string(),
                    valueRecord.valueNameText,
                    false,
                    spec.resolveClsidFromValueData);
                ConfigureRegistryValueAction(
                    entry,
                    spec.rootKey,
                    subKeyText,
                    valueRecord,
                    ks::startup::StartupRiskLevel::Critical,
                    "critical_registry",
                    FromWide(L"此高级注册表持久化值允许修改；禁用后相关外壳、COM 或登录组件可能无法启动。"));
                entries.push_back(std::move(entry));
            }
        }
    }

    // AppendSubKeyValueEntries adds records for subkey-driven advanced registry families.
    void AppendSubKeyValueEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        for (const SubKeyValueSpec& spec : BuildSubKeyValueSpecList())
        {
            const std::wstring rootSubKey(spec.subKeyText);
            const std::wstring valueNameText(spec.valueNameText);
            const std::string groupLocationText = BuildRegistryLocationText(spec.rootKey, rootSubKey);
            for (const std::wstring& subKeyName : EnumerateRegistrySubKeys(spec.rootKey, rootSubKey))
            {
                const std::wstring itemSubKey = rootSubKey + L"\\" + subKeyName;
                const auto valueRecord = QueryRegistryValueRecord(spec.rootKey, itemSubKey, valueNameText);
                if (!valueRecord.has_value() && !spec.resolveClsidFromSubKeyName)
                {
                    continue;
                }
                const std::string subKeyNameText = FromWide(subKeyName);
                std::string itemNameText = subKeyNameText;
                const std::string clsidFallbackText = spec.resolveClsidFromSubKeyName ? subKeyNameText : std::string();
                const std::string friendlyNameText = QueryClsidFriendlyName(clsidFallbackText);
                if (!ks::str::TrimCopy(friendlyNameText).empty())
                {
                    itemNameText = friendlyNameText;
                }
                std::string commandText = valueRecord.has_value() ? valueRecord->valueDataText : std::string();
                if (ks::str::TrimCopy(commandText).empty() && spec.resolveClsidFromSubKeyName)
                {
                    commandText = subKeyNameText;
                }
                if (ks::str::TrimCopy(commandText).empty())
                {
                    continue;
                }
                ks::startup::StartupEntry entry;
                entry.category = ks::startup::StartupCategory::Registry;
                entry.categoryText = ks::startup::CategoryToText(entry.category);
                entry.itemNameText = itemNameText;
                entry.locationText = BuildRegistryLocationText(spec.rootKey, itemSubKey);
                entry.locationGroupText = groupLocationText;
                entry.userText = FromWide(spec.userText);
                entry.sourceTypeText = spec.sourceTypeText;
                entry.detailText = FromWide(spec.detailText) + FromWide(L"\uff1b\u5b50\u952e=") + subKeyNameText;
                entry.uniqueIdText = "SUBKEY|" + entry.locationText + "|" + FromWide(valueNameText);
                FinalizeRegistryEntry(
                    entry,
                    commandText,
                    clsidFallbackText,
                    valueRecord.has_value() ? valueRecord->valueNameText : FromWide(valueNameText),
                    spec.deleteRegistryTree,
                    spec.resolveClsidFromValueData);
                if (valueRecord.has_value())
                {
                    ConfigureRegistryValueAction(
                        entry,
                        spec.rootKey,
                        itemSubKey,
                        *valueRecord,
                        ks::startup::StartupRiskLevel::Critical,
                        "critical_registry",
                        FromWide(L"此基于子键的持久化值允许修改；禁用可能破坏对应 COM、外壳或登录扩展。"));
                }
                else
                {
                    entry.riskLevel = ks::startup::StartupRiskLevel::Critical;
                    entry.riskReasonCode = "critical_registry";
                    entry.riskReasonText = FromWide(L"该持久化项由整个注册表子键表示；只能在不可恢复警告后永久删除。");
                }
                if (spec.deleteRegistryTree)
                {
                    ConfigureRegistryTreeDeletion(entry, spec.rootKey, itemSubKey);
                }
                entries.push_back(std::move(entry));
            }
        }
    }

    constexpr std::uint64_t kIfeoApplicationVerifierFlag = 0x100ULL;
    constexpr std::uint64_t kIfeoSilentProcessExitFlag = 0x200ULL;
    constexpr std::uint64_t kSilentExitLaunchMonitorProcessFlag = 0x1ULL;

    struct IfeoRegistryViewSpec
    {
        const wchar_t* rootSubKeyText = L"";
        const wchar_t* scopeText = L"";
        const char* identityText = "";
    };

    const std::array<IfeoRegistryViewSpec, 2>& BuildIfeoRegistryViewSpecList()
    {
        static const std::array<IfeoRegistryViewSpec, 2> specs{ {
            {
                L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                L"本机",
                "native"
            },
            {
                L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                L"本机(32位)",
                "wow64"
            }
        } };
        return specs;
    }

    std::optional<std::uint64_t> ParseRegistryUnsignedValue(const RegistryValueRecord& valueRecord)
    {
        if (valueRecord.valueType == REG_DWORD && valueRecord.rawData.size() >= sizeof(std::uint32_t))
        {
            std::uint32_t value = 0;
            std::memcpy(&value, valueRecord.rawData.data(), sizeof(value));
            return value;
        }
        if (valueRecord.valueType == REG_DWORD_BIG_ENDIAN && valueRecord.rawData.size() >= sizeof(std::uint32_t))
        {
            const auto* bytes = valueRecord.rawData.data();
            return (static_cast<std::uint64_t>(bytes[0]) << 24U)
                | (static_cast<std::uint64_t>(bytes[1]) << 16U)
                | (static_cast<std::uint64_t>(bytes[2]) << 8U)
                | static_cast<std::uint64_t>(bytes[3]);
        }
        if (valueRecord.valueType == REG_QWORD && valueRecord.rawData.size() >= sizeof(std::uint64_t))
        {
            std::uint64_t value = 0;
            std::memcpy(&value, valueRecord.rawData.data(), sizeof(value));
            return value;
        }

        const std::string text = ks::str::TrimCopy(valueRecord.valueDataText);
        if (text.empty())
        {
            return std::nullopt;
        }
        const bool hexadecimal = StartsWithI(text, "0x");
        const char* numberStart = text.c_str() + (hexadecimal ? 2 : 0);
        char* numberEnd = nullptr;
        errno = 0;
        const unsigned long long value = std::strtoull(numberStart, &numberEnd, hexadecimal ? 16 : 10);
        if (numberEnd == numberStart || *numberEnd != '\0' || errno == ERANGE)
        {
            return std::nullopt;
        }
        return static_cast<std::uint64_t>(value);
    }

    bool RegistryFlagEnabled(
        const std::optional<RegistryValueRecord>& valueRecord,
        const std::uint64_t flagMask)
    {
        if (!valueRecord.has_value())
        {
            return false;
        }
        const auto value = ParseRegistryUnsignedValue(*valueRecord);
        return value.has_value() && ((*value & flagMask) != 0ULL);
    }

    bool HasNonEmptyRegistryValue(const std::optional<RegistryValueRecord>& valueRecord)
    {
        return valueRecord.has_value()
            && !ks::str::TrimCopy(valueRecord->valueDataText).empty();
    }

    std::string BuildFilteredImageDisplayName(
        const std::wstring& imageName,
        const RegistryValueRecord& filterFullPathRecord)
    {
        std::string displayName = FromWide(imageName);
        const std::string filterFullPath = ks::str::TrimCopy(filterFullPathRecord.valueDataText);
        if (!filterFullPath.empty())
        {
            displayName += " [" + filterFullPath + "]";
        }
        return displayName;
    }

    void AppendImageHijackValueEntry(
        std::vector<ks::startup::StartupEntry>& entries,
        const std::wstring& itemSubKey,
        const std::wstring& groupSubKey,
        const std::string& imageDisplayName,
        const wchar_t* scopeText,
        const RegistryValueRecord& valueRecord,
        const char* sourceTypeText,
        const wchar_t* detailText,
        const bool active)
    {
        ks::startup::StartupEntry entry;
        entry.category = ks::startup::StartupCategory::ImageHijack;
        entry.categoryText = ks::startup::CategoryToText(entry.category);
        entry.itemNameText = imageDisplayName;
        entry.locationText = BuildRegistryLocationText(HKEY_LOCAL_MACHINE, itemSubKey);
        entry.locationGroupText = BuildRegistryLocationText(HKEY_LOCAL_MACHINE, groupSubKey);
        entry.userText = FromWide(scopeText);
        entry.sourceTypeText = sourceTypeText;
        entry.detailText = FromWide(detailText);
        entry.uniqueIdText = "IMAGEHIJACK|" + entry.locationText + "|" + valueRecord.valueNameText;
        FinalizeRegistryEntry(
            entry,
            valueRecord.valueDataText,
            std::string(),
            valueRecord.valueNameText,
            false,
            false);
        ConfigureRegistryValueAction(
            entry,
            HKEY_LOCAL_MACHINE,
            itemSubKey,
            valueRecord,
            active
                ? ks::startup::StartupRiskLevel::Critical
                : ks::startup::StartupRiskLevel::Elevated,
            "image_hijack",
            FromWide(L"映像劫持项能够在目标进程启动或退出时执行额外代码；禁用前请确认它不是受控调试或测试配置。"));
        entry.enabled = true;
        entries.push_back(std::move(entry));
    }

    void AppendIfeoViewEntries(
        std::vector<ks::startup::StartupEntry>& entries,
        const IfeoRegistryViewSpec& viewSpec)
    {
        const std::wstring rootSubKey(viewSpec.rootSubKeyText);
        for (const std::wstring& imageName : EnumerateRegistrySubKeys(HKEY_LOCAL_MACHINE, rootSubKey))
        {
            const std::wstring imageSubKey = rootSubKey + L"\\" + imageName;
            const auto globalFlagRecord = QueryRegistryValueRecord(
                HKEY_LOCAL_MACHINE,
                imageSubKey,
                L"GlobalFlag");

            const auto debuggerRecord = QueryRegistryValueRecord(
                HKEY_LOCAL_MACHINE,
                imageSubKey,
                L"Debugger");
            if (HasNonEmptyRegistryValue(debuggerRecord))
            {
                AppendImageHijackValueEntry(
                    entries,
                    imageSubKey,
                    rootSubKey,
                    FromWide(imageName),
                    viewSpec.scopeText,
                    *debuggerRecord,
                    viewSpec.identityText[0] == 'w' ? "IFEO-Debugger32" : "IFEO-Debugger",
                    L"检测到 IFEO Debugger；目标进程启动时会先执行该命令。",
                    true);
            }

            const bool verifierEnabled = RegistryFlagEnabled(
                globalFlagRecord,
                kIfeoApplicationVerifierFlag);
            const auto verifierDllsRecord = QueryRegistryValueRecord(
                HKEY_LOCAL_MACHINE,
                imageSubKey,
                L"VerifierDlls");
            if (HasNonEmptyRegistryValue(verifierDllsRecord))
            {
                AppendImageHijackValueEntry(
                    entries,
                    imageSubKey,
                    rootSubKey,
                    FromWide(imageName),
                    viewSpec.scopeText,
                    *verifierDllsRecord,
                    viewSpec.identityText[0] == 'w' ? "IFEO-VerifierDlls32" : "IFEO-VerifierDlls",
                    verifierEnabled
                        ? L"检测到已启用的 IFEO VerifierDlls；指定 DLL 会随目标进程加载。"
                        : L"检测到 IFEO VerifierDlls，但 GlobalFlag 未启用应用程序验证器。",
                    verifierEnabled);
            }

            const bool useFilterEnabled = RegistryFlagEnabled(
                QueryRegistryValueRecord(HKEY_LOCAL_MACHINE, imageSubKey, L"UseFilter"),
                0x1ULL);
            for (const std::wstring& filterName : EnumerateRegistrySubKeys(HKEY_LOCAL_MACHINE, imageSubKey))
            {
                const std::wstring filterSubKey = imageSubKey + L"\\" + filterName;
                const auto filterFullPathRecord = QueryRegistryValueRecord(
                    HKEY_LOCAL_MACHINE,
                    filterSubKey,
                    L"FilterFullPath");
                if (!HasNonEmptyRegistryValue(filterFullPathRecord))
                {
                    continue;
                }
                const std::string filteredDisplayName = BuildFilteredImageDisplayName(
                    imageName,
                    *filterFullPathRecord);
                const auto filteredDebuggerRecord = QueryRegistryValueRecord(
                    HKEY_LOCAL_MACHINE,
                    filterSubKey,
                    L"Debugger");
                if (HasNonEmptyRegistryValue(filteredDebuggerRecord))
                {
                    AppendImageHijackValueEntry(
                        entries,
                        filterSubKey,
                        rootSubKey,
                        filteredDisplayName,
                        viewSpec.scopeText,
                        *filteredDebuggerRecord,
                        viewSpec.identityText[0] == 'w' ? "IFEO-FilteredDebugger32" : "IFEO-FilteredDebugger",
                        useFilterEnabled
                            ? L"检测到按完整路径生效的 IFEO Debugger。"
                            : L"检测到带 FilterFullPath 的 IFEO Debugger，但 UseFilter 未启用。",
                        useFilterEnabled);
                }

                const auto filteredGlobalFlagRecord = QueryRegistryValueRecord(
                    HKEY_LOCAL_MACHINE,
                    filterSubKey,
                    L"GlobalFlag");
                const bool filteredVerifierEnabled = useFilterEnabled
                    && (RegistryFlagEnabled(filteredGlobalFlagRecord, kIfeoApplicationVerifierFlag)
                        || verifierEnabled);
                const auto filteredVerifierDllsRecord = QueryRegistryValueRecord(
                    HKEY_LOCAL_MACHINE,
                    filterSubKey,
                    L"VerifierDlls");
                if (HasNonEmptyRegistryValue(filteredVerifierDllsRecord))
                {
                    AppendImageHijackValueEntry(
                        entries,
                        filterSubKey,
                        rootSubKey,
                        filteredDisplayName,
                        viewSpec.scopeText,
                        *filteredVerifierDllsRecord,
                        viewSpec.identityText[0] == 'w' ? "IFEO-FilteredVerifierDlls32" : "IFEO-FilteredVerifierDlls",
                        filteredVerifierEnabled
                            ? L"检测到按完整路径生效的 IFEO VerifierDlls；指定 DLL 会随目标进程加载。"
                            : L"检测到带 FilterFullPath 的 IFEO VerifierDlls，但路径过滤或应用程序验证器未启用。",
                        filteredVerifierEnabled);
                }
            }
        }
    }

    bool IsIfeoFlagEnabledForImage(
        const std::wstring& imageName,
        const std::uint64_t flagMask)
    {
        for (const IfeoRegistryViewSpec& viewSpec : BuildIfeoRegistryViewSpecList())
        {
            const std::wstring imageSubKey = std::wstring(viewSpec.rootSubKeyText) + L"\\" + imageName;
            if (RegistryFlagEnabled(
                    QueryRegistryValueRecord(HKEY_LOCAL_MACHINE, imageSubKey, L"GlobalFlag"),
                    flagMask))
            {
                return true;
            }
            const bool useFilterEnabled = RegistryFlagEnabled(
                QueryRegistryValueRecord(HKEY_LOCAL_MACHINE, imageSubKey, L"UseFilter"),
                0x1ULL);
            if (!useFilterEnabled)
            {
                continue;
            }
            for (const std::wstring& filterName : EnumerateRegistrySubKeys(HKEY_LOCAL_MACHINE, imageSubKey))
            {
                const std::wstring filterSubKey = imageSubKey + L"\\" + filterName;
                if (!HasNonEmptyRegistryValue(QueryRegistryValueRecord(
                        HKEY_LOCAL_MACHINE,
                        filterSubKey,
                        L"FilterFullPath")))
                {
                    continue;
                }
                if (RegistryFlagEnabled(
                        QueryRegistryValueRecord(HKEY_LOCAL_MACHINE, filterSubKey, L"GlobalFlag"),
                        flagMask))
                {
                    return true;
                }
            }
        }
        return false;
    }

    void AppendSilentProcessExitEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        const std::wstring silentRoot =
            L"Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit";
        const auto globalMonitorProcessRecord = QueryRegistryValueRecord(
            HKEY_LOCAL_MACHINE,
            silentRoot,
            L"MonitorProcess");
        bool globalMonitorProcessActive = false;

        for (const std::wstring& imageName : EnumerateRegistrySubKeys(HKEY_LOCAL_MACHINE, silentRoot))
        {
            const std::wstring imageSubKey = silentRoot + L"\\" + imageName;
            const bool launchMonitorEnabled = RegistryFlagEnabled(
                QueryRegistryValueRecord(HKEY_LOCAL_MACHINE, imageSubKey, L"ReportingMode"),
                kSilentExitLaunchMonitorProcessFlag);
            const bool silentExitEnabled = IsIfeoFlagEnabledForImage(
                imageName,
                kIfeoSilentProcessExitFlag);
            const bool active = launchMonitorEnabled && silentExitEnabled;
            const auto monitorProcessRecord = QueryRegistryValueRecord(
                HKEY_LOCAL_MACHINE,
                imageSubKey,
                L"MonitorProcess");
            if (HasNonEmptyRegistryValue(monitorProcessRecord))
            {
                AppendImageHijackValueEntry(
                    entries,
                    imageSubKey,
                    silentRoot,
                    FromWide(imageName),
                    L"本机",
                    *monitorProcessRecord,
                    "SilentProcessExit-MonitorProcess",
                    active
                        ? L"SilentProcessExit 已启用启动监视进程；目标进程静默退出时会执行该命令。"
                        : L"检测到 SilentProcessExit MonitorProcess，但 IFEO GlobalFlag 或 ReportingMode 未形成有效启动链。",
                    active);
            }
            else if (active && HasNonEmptyRegistryValue(globalMonitorProcessRecord))
            {
                globalMonitorProcessActive = true;
            }
        }

        if (HasNonEmptyRegistryValue(globalMonitorProcessRecord))
        {
            AppendImageHijackValueEntry(
                entries,
                silentRoot,
                silentRoot,
                FromWide(L"全局 SilentProcessExit"),
                L"本机",
                *globalMonitorProcessRecord,
                "SilentProcessExit-GlobalMonitorProcess",
                globalMonitorProcessActive
                    ? L"全局 SilentProcessExit 监视进程已被至少一个目标使用。"
                    : L"检测到全局 SilentProcessExit MonitorProcess，但当前未发现完整的启动链。",
                globalMonitorProcessActive);
        }
    }

    bool IsImageHijackRegistrySubKey(const std::wstring& subKeyText)
    {
        const std::wstring lowerSubKey = LowerWideCopy(subKeyText);
        const std::array<std::wstring, 3> roots{ {
            LowerWideCopy(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
            LowerWideCopy(L"Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
            LowerWideCopy(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit")
        } };
        for (const std::wstring& root : roots)
        {
            if (lowerSubKey == root
                || (lowerSubKey.size() > root.size()
                    && lowerSubKey.starts_with(root)
                    && lowerSubKey[root.size()] == L'\\'))
            {
                return true;
            }
        }
        return false;
    }

    // QueryServiceBinaryPathText extracts the configured image path from QueryServiceConfig.
    std::string QueryServiceBinaryPathText(const QUERY_SERVICE_CONFIGW& serviceConfig)
    {
        if (serviceConfig.lpBinaryPathName == nullptr)
        {
            return std::string();
        }
        return ToNativeSeparators(FromWide(TrimWide(serviceConfig.lpBinaryPathName)));
    }

    ks::startup::StartupScmStartMode PublicScmStartMode(const DWORD startType)
    {
        switch (startType)
        {
        case SERVICE_BOOT_START:
            return ks::startup::StartupScmStartMode::Boot;
        case SERVICE_SYSTEM_START:
            return ks::startup::StartupScmStartMode::System;
        case SERVICE_AUTO_START:
            return ks::startup::StartupScmStartMode::Automatic;
        case SERVICE_DEMAND_START:
            return ks::startup::StartupScmStartMode::Manual;
        case SERVICE_DISABLED:
            return ks::startup::StartupScmStartMode::Disabled;
        default:
            return ks::startup::StartupScmStartMode::None;
        }
    }

    // EnumerateScmEntries implements the shared service/driver backend with category-specific filters.
    std::vector<ks::startup::StartupEntry> EnumerateScmEntries(bool drivers)
    {
        std::vector<ks::startup::StartupEntry> entries;
        SC_HANDLE scmHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (scmHandle == nullptr)
        {
            return entries;
        }
        DWORD requiredBytes = 0;
        DWORD serviceCount = 0;
        DWORD resumeHandle = 0;
        const DWORD serviceType = drivers ? SERVICE_DRIVER : SERVICE_WIN32;
        ::EnumServicesStatusExW(scmHandle, SC_ENUM_PROCESS_INFO, serviceType, SERVICE_STATE_ALL, nullptr, 0, &requiredBytes, &serviceCount, &resumeHandle, nullptr);
        if (requiredBytes == 0)
        {
            ::CloseServiceHandle(scmHandle);
            return entries;
        }
        std::vector<std::uint8_t> buffer(requiredBytes);
        resumeHandle = 0;
        const BOOL enumOk = ::EnumServicesStatusExW(scmHandle, SC_ENUM_PROCESS_INFO, serviceType, SERVICE_STATE_ALL, buffer.data(), static_cast<DWORD>(buffer.size()), &requiredBytes, &serviceCount, &resumeHandle, nullptr);
        if (enumOk == FALSE)
        {
            ::CloseServiceHandle(scmHandle);
            return entries;
        }
        const auto* serviceArray = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        for (DWORD index = 0; index < serviceCount; ++index)
        {
            const ENUM_SERVICE_STATUS_PROCESSW& serviceItem = serviceArray[index];
            SC_HANDLE serviceHandle = ::OpenServiceW(scmHandle, serviceItem.lpServiceName, SERVICE_QUERY_CONFIG);
            if (serviceHandle == nullptr)
            {
                continue;
            }
            DWORD configBytes = 0;
            ::QueryServiceConfigW(serviceHandle, nullptr, 0, &configBytes);
            if (configBytes == 0)
            {
                ::CloseServiceHandle(serviceHandle);
                continue;
            }
            std::vector<std::uint8_t> configBuffer(configBytes);
            auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());
            if (::QueryServiceConfigW(serviceHandle, config, configBytes, &configBytes) == FALSE)
            {
                ::CloseServiceHandle(serviceHandle);
                continue;
            }
            const DWORD startType = config->dwStartType;
            const ks::startup::StartupScmStartMode startMode =
                PublicScmStartMode(startType);
            const std::string serviceName = serviceItem.lpServiceName == nullptr ? std::string() : FromWide(serviceItem.lpServiceName);
            const std::string displayName = serviceItem.lpDisplayName == nullptr ? std::string() : FromWide(TrimWide(serviceItem.lpDisplayName));
            const std::string commandText = QueryServiceBinaryPathText(*config);
            ks::startup::StartupEntry entry;
            entry.category = drivers ? ks::startup::StartupCategory::Drivers : ks::startup::StartupCategory::Services;
            entry.categoryText = ks::startup::CategoryToText(entry.category);
            entry.itemNameText = displayName.empty() ? serviceName : displayName;
            entry.imagePathText = ks::startup::NormalizeFilePathText(commandText);
            entry.commandText = commandText;
            entry.publisherText = ks::startup::QueryPublisherTextByPath(entry.imagePathText);
            entry.locationText = std::string(drivers ? "SCM\\Driver\\" : "SCM\\Service\\") + serviceName;
            entry.userText = drivers ? FromWide(L"内核") : (config->lpServiceStartName == nullptr ? "N/A" : FromWide(config->lpServiceStartName));
            entry.enabled = startMode != ks::startup::StartupScmStartMode::Disabled;
            entry.sourceTypeText = drivers ? "Driver" : "SCM Service";
            if (drivers && startType == SERVICE_BOOT_START)
            {
                entry.detailText = FromWide(L"引导启动驱动");
            }
            else if (drivers && startType == SERVICE_SYSTEM_START)
            {
                entry.detailText = FromWide(L"系统启动驱动");
            }
            else if (startType == SERVICE_AUTO_START)
            {
                entry.detailText = drivers
                    ? FromWide(L"自动启动驱动")
                    : FromWide(L"自动启动服务");
            }
            else if (startType == SERVICE_DEMAND_START)
            {
                entry.detailText = FromWide(L"手动启动的服务控制管理器项");
            }
            else if (startType == SERVICE_DISABLED)
            {
                entry.detailText = FromWide(L"已禁用的服务控制管理器启动项");
            }
            else
            {
                entry.detailText = FromWide(L"未知的服务控制管理器启动类型");
            }
            entry.canOpenFileLocation = !entry.imagePathText.empty();
            entry.canDelete = true;
            entry.imagePathExists = FileExists(entry.imagePathText);
            entry.uniqueIdText = std::string(drivers ? "DRIVER|" : "SERVICE|") + serviceName;
            entry.actionKind = ks::startup::StartupActionKind::ScmStartType;
            entry.actionLocator.serviceNameText = serviceName;
            entry.actionLocator.serviceIsDriver = drivers;
            entry.actionLocator.serviceStartMode = startMode;
            entry.actionLocator.serviceType = config->dwServiceType;
            entry.actionLocator.serviceStartType = startType;
            entry.actionLocator.serviceBinaryPathText = commandText;
            entry.canEnable = startMode == ks::startup::StartupScmStartMode::Disabled;
            entry.canDisable = startMode != ks::startup::StartupScmStartMode::Disabled
                && startMode != ks::startup::StartupScmStartMode::None;
            entry.riskLevel = drivers
                ? ks::startup::StartupRiskLevel::Critical
                : ks::startup::StartupRiskLevel::Elevated;
            entry.riskReasonCode = drivers ? "driver" : "service";
            entry.riskReasonText = drivers
                ? FromWide(L"修改驱动启动类型可能导致设备失效、蓝屏或系统无法启动；重新启用时将使用系统启动类型。")
                : FromWide(L"修改服务启动类型会影响下次启动；重新启用时将使用自动启动类型。");
            entries.push_back(std::move(entry));
            ::CloseServiceHandle(serviceHandle);
        }
        ::CloseServiceHandle(scmHandle);
        return entries;
    }
}

namespace
{
    // WinsockKeySpec describes one Winsock catalog registry root.
    struct WinsockKeySpec
    {
        HKEY rootKey = nullptr;
        const wchar_t* subKeyText = L"";
        const char* sourceTypeText = "";
        const wchar_t* userText = L"";
        const wchar_t* detailText = L"";
    };

    // BuildWinsockKeySpecList keeps Winsock provider/catalog coverage in one place.
    const std::array<WinsockKeySpec, 4>& BuildWinsockKeySpecList()
    {
        static const std::array<WinsockKeySpec, 4> specs{ {
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries", "Winsock-ProtocolCatalog", L"本机", L"Winsock Protocol Catalog" },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64", "Winsock-ProtocolCatalog64", L"本机", L"Winsock 64 位 Protocol Catalog" },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries", "Winsock-NameSpaceCatalog", L"本机", L"Winsock NameSpace Catalog" },
            { HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64", "Winsock-NameSpaceCatalog64", L"本机", L"Winsock 64 位 NameSpace Catalog" }
        } };
        return specs;
    }

    // EnumerateRegistryValueTextList serializes every value in one registry key as name=value text.
    std::vector<std::string> EnumerateRegistryValueTextList(HKEY rootKey, const std::wstring& subKeyText)
    {
        std::vector<std::string> values;
        for (const RegistryValueRecord& record : EnumerateRegistryValues(rootKey, subKeyText))
        {
            const std::string nameText = ks::str::TrimCopy(record.valueNameText).empty() ? FromWide(L"(\u9ed8\u8ba4\u503c)") : record.valueNameText;
            values.push_back(nameText + "=" + record.valueDataText);
        }
        return values;
    }

    // AppendScheduledTaskJsonObject converts one PowerShell task object to StartupEntry.
    void AppendScheduledTaskJsonObject(std::vector<ks::startup::StartupEntry>& entries, const JsonValue& taskObject)
    {
        const std::string actionText = GetJsonField(taskObject, "Actions");
        const std::string taskPathText = GetJsonField(taskObject, "TaskPath");
        const std::string taskNameText = GetJsonField(taskObject, "TaskName");
        const std::string taskDefinitionSha256Text =
            LowerAsciiCopy(GetJsonField(taskObject, "XmlSha256"));
        if (ks::str::TrimCopy(taskNameText).empty())
        {
            return;
        }
        ks::startup::StartupEntry entry;
        entry.category = ks::startup::StartupCategory::Tasks;
        entry.categoryText = ks::startup::CategoryToText(entry.category);
        entry.itemNameText = taskNameText;
        entry.commandText = actionText;
        entry.imagePathText = ks::startup::NormalizeFilePathText(actionText);
        entry.publisherText = ks::startup::QueryPublisherTextByPath(entry.imagePathText);
        entry.locationText = taskPathText + taskNameText;
        entry.userText = GetJsonField(taskObject, "UserId");
        const std::string enabledText = LowerAsciiCopy(GetJsonField(taskObject, "Enabled"));
        entry.enabled = enabledText == "true"
            || (enabledText.empty()
                && LowerAsciiCopy(GetJsonField(taskObject, "State")).find("disabled") == std::string::npos);
        entry.sourceTypeText = "ScheduledTask";
        entry.detailText = FromWide(L"\u72b6\u6001=") + GetJsonField(taskObject, "State")
            + FromWide(L"\uff1b\u89e6\u53d1\u5668=") + GetJsonField(taskObject, "Triggers")
            + FromWide(L"\uff1b\u63cf\u8ff0=") + GetJsonField(taskObject, "Description");
        entry.canOpenFileLocation = !entry.imagePathText.empty();
        // Identity-valid tasks remain deletable after the explicit irreversible
        // warning. ProtectEntry below revokes this capability if the stable task
        // definition identity cannot be established.
        entry.canDelete = true;
        entry.imagePathExists = FileExists(entry.imagePathText);
        entry.uniqueIdText = "TASK|" + entry.locationText;
        entry.actionKind = ks::startup::StartupActionKind::ScheduledTask;
        entry.actionLocator.taskPathText = taskPathText;
        entry.actionLocator.taskNameText = taskNameText;
        entry.actionLocator.taskDefinitionSha256Text = taskDefinitionSha256Text;
        entry.canEnable = !entry.enabled;
        entry.canDisable = entry.enabled;
        entry.riskLevel = ks::startup::StartupRiskLevel::Elevated;
        entry.riskReasonCode = "scheduled_task";
        entry.riskReasonText = FromWide(L"仅列出 BootTrigger 和 LogonTrigger 任务；状态变更由 Windows 任务计划程序执行。");
        const bool validHash = taskDefinitionSha256Text.size() == 64
            && std::all_of(
                taskDefinitionSha256Text.begin(),
                taskDefinitionSha256Text.end(),
                [](const unsigned char ch) { return std::isxdigit(ch) != 0; });
        if (!validHash)
        {
            entry.riskLevel = ks::startup::StartupRiskLevel::Critical;
            entry.riskReasonCode = "scheduled_task";
            entry.riskReasonText = FromWide(L"无法取得计划任务定义 XML 的稳定 SHA-256 身份；继续时只按精确任务路径和名称修改并验证最终状态。");
        }
        entries.push_back(std::move(entry));
    }

    // AppendWmiJsonObject converts one PowerShell WMI persistence object to StartupEntry.
    void AppendWmiJsonObject(std::vector<ks::startup::StartupEntry>& entries, const JsonValue& objectValue)
    {
        const std::string typeText = GetJsonField(objectValue, "Type");
        const std::string nameText = GetJsonField(objectValue, "Name");
        const std::string commandText = GetJsonField(objectValue, "Command");
        const std::string imagePathText = ks::startup::NormalizeFilePathText(GetJsonField(objectValue, "Image"));
        const std::string locationText = GetJsonField(objectValue, "Location");
        const std::string detailText = GetJsonField(objectValue, "Detail");
        if (ks::str::TrimCopy(typeText).empty() && ks::str::TrimCopy(nameText).empty() && ks::str::TrimCopy(commandText).empty())
        {
            return;
        }
        ks::startup::StartupEntry entry;
        entry.category = ks::startup::StartupCategory::Wmi;
        entry.categoryText = ks::startup::CategoryToText(entry.category);
        entry.itemNameText = ks::str::TrimCopy(nameText).empty() ? FromWide(L"(\u672a\u547d\u540dWMI\u9879)") : nameText;
        entry.publisherText = ks::startup::QueryPublisherTextByPath(imagePathText);
        entry.imagePathText = imagePathText;
        entry.commandText = commandText;
        entry.locationText = locationText;
        entry.userText = FromWide(L"本机");
        entry.detailText = detailText;
        entry.sourceTypeText = typeText;
        entry.enabled = true;
        entry.canOpenFileLocation = !entry.imagePathText.empty();
        entry.canOpenRegistryLocation = false;
        entry.canDelete = false;
        entry.imagePathExists = FileExists(entry.imagePathText);
        entry.uniqueIdText = "WMI|" + typeText + "|" + entry.itemNameText + "|" + locationText;
        if (typeText == "WMI-CommandLineConsumer")
        {
            entry.actionLocator.wmiClassNameText = "CommandLineEventConsumer";
        }
        else if (typeText == "WMI-ActiveScriptConsumer")
        {
            entry.actionLocator.wmiClassNameText = "ActiveScriptEventConsumer";
        }
        else if (typeText == "WMI-LogFileConsumer")
        {
            entry.actionLocator.wmiClassNameText = "LogFileEventConsumer";
        }
        else if (typeText == "WMI-NTEventLogConsumer")
        {
            entry.actionLocator.wmiClassNameText = "NTEventLogEventConsumer";
        }
        else if (typeText == "WMI-EventFilter")
        {
            entry.actionLocator.wmiClassNameText = "__EventFilter";
        }
        else if (typeText == "WMI-FilterToConsumerBinding")
        {
            entry.actionLocator.wmiClassNameText = "__FilterToConsumerBinding";
            entry.actionLocator.wmiConsumerText = nameText;
            entry.actionLocator.wmiFilterText = commandText;
        }
        if (!entry.actionLocator.wmiClassNameText.empty())
        {
            entry.actionKind = ks::startup::StartupActionKind::WmiEntryRemoval;
            entry.actionLocator.wmiNameText = nameText;
            entry.canEnable = false;
            entry.canDisable = true;
            entry.riskLevel = ks::startup::StartupRiskLevel::Critical;
            entry.riskReasonCode = "wmi";
            entry.riskReasonText = FromWide(L"禁用会永久删除精确匹配的 WMI 永久事件对象，KSword 不会自动重建该对象。");
        }
        else
        {
            MarkEntryActionUnavailable(
                entry,
                ks::startup::StartupRiskLevel::Critical,
                "wmi",
                FromWide(L"无法识别该 WMI 对象类型，当前行没有可执行的修改定位器。"));
        }
        entries.push_back(std::move(entry));
    }

    // BuildTaskPowerShellScript returns JSON for scheduled tasks while staying UI-framework-free.
    std::wstring BuildTaskPowerShellScript()
    {
        return LR"PS(
$ErrorActionPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
function Get-KSwordTaskIdentityHash($task) {
  [xml]$document = [string](ScheduledTasks\Export-ScheduledTask -InputObject $task -ErrorAction Stop)
  $enabledNode = $document.SelectSingleNode("/*[local-name()='Task']/*[local-name()='Settings']/*[local-name()='Enabled']")
  if ($null -ne $enabledNode) { $null = $enabledNode.ParentNode.RemoveChild($enabledNode) }
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    return [BitConverter]::ToString(
      $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($document.OuterXml))
    ).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}
function Get-KSwordTaskEnabled($task) {
  if ($null -ne $task.Settings -and $null -ne $task.Settings.Enabled) {
    return [bool]$task.Settings.Enabled
  }
  return ([string]$task.State -ne 'Disabled')
}
$scheduledTasksModule = Join-Path $PSHOME 'Modules\ScheduledTasks\ScheduledTasks.psd1'
Microsoft.PowerShell.Core\Import-Module -Name $scheduledTasksModule -Force -ErrorAction Stop
$taskList = @(ScheduledTasks\Get-ScheduledTask | ForEach-Object {
  $actions = ($_.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments).Trim() }) -join ' | '
  $triggerKinds = @($_.Triggers | ForEach-Object { $_.CimClass.CimClassName })
  $isBootOrLogon = @($triggerKinds | Where-Object { $_ -eq 'MSFT_TaskBootTrigger' -or $_ -eq 'MSFT_TaskLogonTrigger' }).Count -gt 0
  if ($isBootOrLogon) {
    $xmlSha256 = ''
    try { $xmlSha256 = Get-KSwordTaskIdentityHash $_ } catch { $xmlSha256 = '' }
    [PSCustomObject]@{
      TaskPath = $_.TaskPath
      TaskName = $_.TaskName
      State = [string]$_.State
      Enabled = Get-KSwordTaskEnabled $_
      Author = $_.Author
      Description = $_.Description
      Actions = $actions
      Triggers = ($triggerKinds -join ' | ')
      UserId = $_.Principal.UserId
      XmlSha256 = $xmlSha256
    }
  }
})
if ($taskList.Count -eq 0) { '[]' } else { $taskList | ConvertTo-Json -Depth 5 -Compress }
)PS";
    }

    // BuildWmiPowerShellScript returns JSON for common root\subscription persistence classes.
    std::wstring BuildWmiPowerShellScript()
    {
        return LR"PS(
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$cimCmdletsModule = Join-Path $PSHOME 'Modules\CimCmdlets\CimCmdlets.psd1'
Microsoft.PowerShell.Core\Import-Module -Name $cimCmdletsModule -Force -ErrorAction Stop
$items = @()
CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object {
    $items += [PSCustomObject]@{ Type='WMI-CommandLineConsumer'; Name=$_.Name; Command=$_.CommandLineTemplate; Image=$_.ExecutablePath; Location='root\subscription\CommandLineEventConsumer'; Detail=('ExecutablePath=' + $_.ExecutablePath + '; WorkingDirectory=' + $_.WorkingDirectory) }
}
CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object {
    $items += [PSCustomObject]@{ Type='WMI-ActiveScriptConsumer'; Name=$_.Name; Command=$_.ScriptText; Image=''; Location='root\subscription\ActiveScriptEventConsumer'; Detail=('ScriptingEngine=' + $_.ScriptingEngine) }
}
CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName LogFileEventConsumer | ForEach-Object {
    $items += [PSCustomObject]@{ Type='WMI-LogFileConsumer'; Name=$_.Name; Command=$_.Filename; Image=''; Location='root\subscription\LogFileEventConsumer'; Detail=('Text=' + $_.Text) }
}
CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName NTEventLogEventConsumer | ForEach-Object {
    $items += [PSCustomObject]@{ Type='WMI-NTEventLogConsumer'; Name=$_.Name; Command=$_.SourceName; Image=''; Location='root\subscription\NTEventLogEventConsumer'; Detail=('EventId=' + $_.EventID + '; Category=' + $_.Category) }
}
CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | ForEach-Object {
    $items += [PSCustomObject]@{ Type='WMI-EventFilter'; Name=$_.Name; Command=$_.Query; Image=''; Location='root\subscription\__EventFilter'; Detail=('QueryLanguage=' + $_.QueryLanguage + '; EventNamespace=' + $_.EventNamespace) }
}
CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | ForEach-Object {
    $items += [PSCustomObject]@{ Type='WMI-FilterToConsumerBinding'; Name=$_.Consumer; Command=$_.Filter; Image=''; Location='root\subscription\__FilterToConsumerBinding'; Detail=('Consumer=' + $_.Consumer + '; Filter=' + $_.Filter + '; DeliveryQoS=' + $_.DeliveryQoS) }
}
if ($items.Count -eq 0) { '[]' } else { $items | ConvertTo-Json -Compress -Depth 4 }
)PS";
    }
}

namespace
{
    constexpr wchar_t kRegistryBackupRoot[] = L"Software\\KSword\\StartupManager\\RegistryBackups";
    constexpr wchar_t kStartupFolderBackupRoot[] = L"Software\\KSword\\StartupManager\\StartupFolderBackups";
    constexpr DWORD kBackupSchemaVersion = 1;
    constexpr DWORD kBackupStatePrepared = 0;
    constexpr DWORD kBackupStateDisabled = 1;
    constexpr DWORD kBackupStateRestored = 2;

    struct RegistryBackupRecord
    {
        std::wstring backupId;
        ks::startup::StartupRegistryRoot root = ks::startup::StartupRegistryRoot::None;
        std::wstring subKey;
        std::wstring valueName;
        std::wstring itemName;
        DWORD valueType = REG_NONE;
        std::vector<std::uint8_t> rawData;
        DWORD state = kBackupStatePrepared;
    };

    struct StartupFolderBackupRecord
    {
        std::wstring backupId;
        std::wstring originalPath;
        std::wstring parkedPath;
        std::wstring itemName;
        DWORD state = kBackupStatePrepared;
    };

    // MakeActionResult keeps all action exits explicit and uniform for UI callers.
    ks::startup::ActionResult MakeActionResult(
        const ks::startup::StartupActionStatus status,
        const bool success,
        const bool changed,
        const DWORD errorCode,
        const std::string& messageText)
    {
        ks::startup::ActionResult result;
        result.status = status;
        result.success = success;
        result.changed = changed;
        result.errorCode = errorCode;
        result.messageText = messageText;
        return result;
    }

    ks::startup::StartupActionStatus StatusFromWin32(
        const DWORD errorCode,
        const ks::startup::StartupActionStatus fallback)
    {
        if (errorCode == ERROR_ACCESS_DENIED || errorCode == ERROR_PRIVILEGE_NOT_HELD)
        {
            return ks::startup::StartupActionStatus::AccessDenied;
        }
        if (errorCode == ERROR_FILE_NOT_FOUND || errorCode == ERROR_PATH_NOT_FOUND)
        {
            return ks::startup::StartupActionStatus::NotFound;
        }
        if (errorCode == ERROR_ALREADY_EXISTS || errorCode == ERROR_FILE_EXISTS)
        {
            return ks::startup::StartupActionStatus::Conflict;
        }
        return fallback;
    }

    // IsSafeBackupId prevents a caller-provided backup locator from escaping its metadata root.
    bool IsSafeBackupId(const std::wstring& backupId)
    {
        if (backupId.empty() || backupId.size() > 128)
        {
            return false;
        }
        return std::all_of(backupId.begin(), backupId.end(), [](const wchar_t ch) {
            return (ch >= L'0' && ch <= L'9')
                || (ch >= L'A' && ch <= L'F')
                || (ch >= L'a' && ch <= L'f')
                || ch == L'-';
        });
    }

    // GenerateBackupId combines wall-clock, process, thread, and atomic sequence identifiers.
    std::wstring GenerateBackupId()
    {
        static volatile LONG sequence = 0;
        FILETIME fileTime{};
        ::GetSystemTimeAsFileTime(&fileTime);
        ULARGE_INTEGER ticks{};
        ticks.LowPart = fileTime.dwLowDateTime;
        ticks.HighPart = fileTime.dwHighDateTime;
        const ULONG serial = static_cast<ULONG>(::InterlockedIncrement(&sequence));
        std::wostringstream stream;
        stream << std::uppercase << std::hex
            << ticks.QuadPart << L"-"
            << ::GetCurrentProcessId() << L"-"
            << ::GetCurrentThreadId() << L"-"
            << serial;
        return stream.str();
    }

    std::wstring MetadataRecordPath(const wchar_t* metadataRoot, const std::wstring& backupId)
    {
        return std::wstring(metadataRoot) + L"\\" + backupId;
    }

    // QueryOpenedRegistryValueRaw preserves the exact type and byte sequence stored in a value.
    LONG QueryOpenedRegistryValueRaw(
        HKEY openedKey,
        const std::wstring& valueName,
        DWORD& valueTypeOut,
        std::vector<std::uint8_t>& rawDataOut)
    {
        const wchar_t* valueNamePointer = valueName.empty() ? nullptr : valueName.c_str();
        for (int attempt = 0; attempt < 3; ++attempt)
        {
            DWORD valueType = REG_NONE;
            DWORD dataBytes = 0;
            LONG result = ::RegQueryValueExW(openedKey, valueNamePointer, nullptr, &valueType, nullptr, &dataBytes);
            if (result != ERROR_SUCCESS)
            {
                return result;
            }
            std::vector<std::uint8_t> rawData(static_cast<std::size_t>(dataBytes));
            DWORD actualBytes = dataBytes;
            result = ::RegQueryValueExW(
                openedKey,
                valueNamePointer,
                nullptr,
                &valueType,
                rawData.empty() ? nullptr : rawData.data(),
                &actualBytes);
            if (result == ERROR_MORE_DATA)
            {
                continue;
            }
            if (result != ERROR_SUCCESS)
            {
                return result;
            }
            rawData.resize(actualBytes);
            valueTypeOut = valueType;
            rawDataOut = std::move(rawData);
            return ERROR_SUCCESS;
        }
        return ERROR_MORE_DATA;
    }

    LONG QueryRegistryValueRaw(
        HKEY rootKey,
        const std::wstring& subKey,
        const std::wstring& valueName,
        DWORD& valueTypeOut,
        std::vector<std::uint8_t>& rawDataOut)
    {
        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(rootKey, subKey.c_str(), 0, KEY_QUERY_VALUE, &openedKey);
        if (openResult != ERROR_SUCCESS)
        {
            return openResult;
        }
        const LONG queryResult = QueryOpenedRegistryValueRaw(openedKey, valueName, valueTypeOut, rawDataOut);
        ::RegCloseKey(openedKey);
        return queryResult;
    }

    LONG SetMetadataDword(HKEY openedKey, const wchar_t* name, const DWORD value)
    {
        return ::RegSetValueExW(
            openedKey,
            name,
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(&value),
            sizeof(value));
    }

    LONG SetMetadataString(HKEY openedKey, const wchar_t* name, const std::wstring& value)
    {
        const DWORD dataBytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
        return ::RegSetValueExW(
            openedKey,
            name,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(value.c_str()),
            dataBytes);
    }

    LONG SetMetadataBinary(HKEY openedKey, const wchar_t* name, const std::vector<std::uint8_t>& value)
    {
        return ::RegSetValueExW(
            openedKey,
            name,
            0,
            REG_BINARY,
            value.empty() ? nullptr : value.data(),
            static_cast<DWORD>(value.size()));
    }

    bool QueryMetadataDword(HKEY openedKey, const wchar_t* name, DWORD& valueOut)
    {
        DWORD type = REG_NONE;
        std::vector<std::uint8_t> rawData;
        if (QueryOpenedRegistryValueRaw(openedKey, name, type, rawData) != ERROR_SUCCESS
            || type != REG_DWORD
            || rawData.size() != sizeof(DWORD))
        {
            return false;
        }
        std::memcpy(&valueOut, rawData.data(), sizeof(DWORD));
        return true;
    }

    bool QueryMetadataString(HKEY openedKey, const wchar_t* name, std::wstring& valueOut)
    {
        DWORD type = REG_NONE;
        std::vector<std::uint8_t> rawData;
        if (QueryOpenedRegistryValueRaw(openedKey, name, type, rawData) != ERROR_SUCCESS
            || type != REG_SZ
            || rawData.size() < sizeof(wchar_t)
            || rawData.size() % sizeof(wchar_t) != 0)
        {
            return false;
        }
        std::size_t charCount = rawData.size() / sizeof(wchar_t);
        valueOut.resize(charCount);
        std::memcpy(valueOut.data(), rawData.data(), rawData.size());
        while (!valueOut.empty() && valueOut.back() == L'\0')
        {
            valueOut.pop_back();
        }
        return valueOut.find(L'\0') == std::wstring::npos;
    }

    bool QueryMetadataBinary(HKEY openedKey, const wchar_t* name, std::vector<std::uint8_t>& valueOut)
    {
        DWORD type = REG_NONE;
        std::vector<std::uint8_t> rawData;
        if (QueryOpenedRegistryValueRaw(openedKey, name, type, rawData) != ERROR_SUCCESS || type != REG_BINARY)
        {
            return false;
        }
        valueOut = std::move(rawData);
        return true;
    }

    LONG OpenMetadataRootForCreate(
        HKEY metadataHive,
        const wchar_t* metadataRoot,
        HKEY& rootKeyOut)
    {
        rootKeyOut = nullptr;
        if ((metadataHive != HKEY_CURRENT_USER && metadataHive != HKEY_LOCAL_MACHINE)
            || metadataRoot == nullptr
            || metadataRoot[0] == L'\0')
        {
            return ERROR_INVALID_PARAMETER;
        }

        PSECURITY_DESCRIPTOR machineDescriptor = nullptr;
        SECURITY_ATTRIBUTES machineAttributes{};
        SECURITY_ATTRIBUTES* securityAttributes = nullptr;
        REGSAM desiredAccess = KEY_CREATE_SUB_KEY;
        if (metadataHive == HKEY_LOCAL_MACHINE)
        {
            // Machine-scope journals must not be writable by the medium-integrity user.
            if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    L"D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)",
                    SDDL_REVISION_1,
                    &machineDescriptor,
                    nullptr) == FALSE)
            {
                return static_cast<LONG>(::GetLastError());
            }
            machineAttributes.nLength = sizeof(machineAttributes);
            machineAttributes.lpSecurityDescriptor = machineDescriptor;
            machineAttributes.bInheritHandle = FALSE;
            securityAttributes = &machineAttributes;
            desiredAccess |= WRITE_DAC;
        }

        LONG result = ::RegCreateKeyExW(
            metadataHive,
            metadataRoot,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            desiredAccess,
            securityAttributes,
            &rootKeyOut,
            nullptr);
        if (result == ERROR_SUCCESS && metadataHive == HKEY_LOCAL_MACHINE)
        {
            result = ::RegSetKeySecurity(
                rootKeyOut,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                machineDescriptor);
        }
        if (machineDescriptor != nullptr)
        {
            ::LocalFree(machineDescriptor);
        }
        if (result != ERROR_SUCCESS && rootKeyOut != nullptr)
        {
            ::RegCloseKey(rootKeyOut);
            rootKeyOut = nullptr;
        }
        return result;
    }

    // CreateUniqueMetadataKey never opens an existing backup record for writing.
    LONG CreateUniqueMetadataKey(
        HKEY metadataHive,
        const wchar_t* metadataRoot,
        std::wstring& backupIdOut,
        HKEY& recordKeyOut)
    {
        recordKeyOut = nullptr;
        HKEY rootKey = nullptr;
        LONG result = OpenMetadataRootForCreate(metadataHive, metadataRoot, rootKey);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        for (int attempt = 0; attempt < 64; ++attempt)
        {
            const std::wstring backupId = GenerateBackupId();
            DWORD disposition = 0;
            HKEY recordKey = nullptr;
            result = ::RegCreateKeyExW(
                rootKey,
                backupId.c_str(),
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                nullptr,
                &recordKey,
                &disposition);
            if (result == ERROR_SUCCESS && disposition == REG_CREATED_NEW_KEY)
            {
                backupIdOut = backupId;
                recordKeyOut = recordKey;
                ::RegCloseKey(rootKey);
                return ERROR_SUCCESS;
            }
            if (recordKey != nullptr)
            {
                ::RegCloseKey(recordKey);
            }
            if (result != ERROR_SUCCESS)
            {
                ::RegCloseKey(rootKey);
                return result;
            }
        }
        ::RegCloseKey(rootKey);
        return ERROR_ALREADY_EXISTS;
    }

    LONG DeleteMetadataRecord(
        HKEY metadataHive,
        const wchar_t* metadataRoot,
        const std::wstring& backupId)
    {
        if (!IsSafeBackupId(backupId))
        {
            return ERROR_INVALID_NAME;
        }
        const LONG result = ::RegDeleteTreeW(
            metadataHive,
            MetadataRecordPath(metadataRoot, backupId).c_str());
        return result == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : result;
    }

    LONG SetAndVerifyMetadataState(HKEY recordKey, const DWORD state)
    {
        const LONG setResult = SetMetadataDword(recordKey, L"State", state);
        if (setResult != ERROR_SUCCESS)
        {
            return setResult;
        }
        DWORD storedState = 0;
        return QueryMetadataDword(recordKey, L"State", storedState) && storedState == state
            ? ERROR_SUCCESS
            : ERROR_INVALID_DATA;
    }

    LONG CommitMetadataStateById(
        HKEY metadataHive,
        const wchar_t* metadataRoot,
        const std::wstring& backupId,
        const DWORD state)
    {
        if (!IsSafeBackupId(backupId))
        {
            return ERROR_INVALID_NAME;
        }
        HKEY recordKey = nullptr;
        LONG result = ::RegOpenKeyExW(
            metadataHive,
            MetadataRecordPath(metadataRoot, backupId).c_str(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &recordKey);
        if (result == ERROR_SUCCESS)
        {
            result = SetAndVerifyMetadataState(recordKey, state);
        }
        if (result == ERROR_SUCCESS)
        {
            result = ::RegFlushKey(recordKey);
        }
        if (recordKey != nullptr)
        {
            ::RegCloseKey(recordKey);
        }
        return result;
    }

    bool RawRegistryValuesEqual(
        const DWORD leftType,
        const std::vector<std::uint8_t>& leftData,
        const DWORD rightType,
        const std::vector<std::uint8_t>& rightData)
    {
        return leftType == rightType && leftData == rightData;
    }

    LONG SetRegistryValueWithoutOverwrite(
        HKEY rootKey,
        const std::wstring& subKey,
        const std::wstring& valueName,
        const DWORD valueType,
        const std::vector<std::uint8_t>& rawData)
    {
        HKEY openedKey = nullptr;
        LONG result = ::RegCreateKeyExW(
            rootKey,
            subKey.c_str(),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            nullptr,
            &openedKey,
            nullptr);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        DWORD existingType = REG_NONE;
        std::vector<std::uint8_t> existingData;
        result = QueryOpenedRegistryValueRaw(openedKey, valueName, existingType, existingData);
        if (result == ERROR_SUCCESS)
        {
            ::RegCloseKey(openedKey);
            return ERROR_ALREADY_EXISTS;
        }
        if (result != ERROR_FILE_NOT_FOUND)
        {
            ::RegCloseKey(openedKey);
            return result;
        }
        // Registry values do not have a native compare-and-set primitive. This final absence
        // check is performed on the exact write handle and RegSetValueExW follows immediately;
        // callers still verify the exact bytes after the best-effort no-overwrite write.
        const wchar_t* valueNamePointer = valueName.empty() ? nullptr : valueName.c_str();
        result = ::RegSetValueExW(
            openedKey,
            valueNamePointer,
            0,
            valueType,
            rawData.empty() ? nullptr : rawData.data(),
            static_cast<DWORD>(rawData.size()));
        ::RegCloseKey(openedKey);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        DWORD verifyType = REG_NONE;
        std::vector<std::uint8_t> verifyData;
        result = QueryRegistryValueRaw(rootKey, subKey, valueName, verifyType, verifyData);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        return RawRegistryValuesEqual(valueType, rawData, verifyType, verifyData)
            ? ERROR_SUCCESS
            : ERROR_INVALID_DATA;
    }

    LONG DeleteRegistryValueIfExact(
        HKEY rootKey,
        const std::wstring& subKey,
        const std::wstring& valueName,
        const DWORD expectedType,
        const std::vector<std::uint8_t>& expectedData)
    {
        DWORD currentType = REG_NONE;
        std::vector<std::uint8_t> currentData;
        LONG result = QueryRegistryValueRaw(rootKey, subKey, valueName, currentType, currentData);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        if (!RawRegistryValuesEqual(currentType, currentData, expectedType, expectedData))
        {
            return ERROR_ALREADY_EXISTS;
        }
        HKEY openedKey = nullptr;
        result = ::RegOpenKeyExW(rootKey, subKey.c_str(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &openedKey);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        currentType = REG_NONE;
        currentData.clear();
        result = QueryOpenedRegistryValueRaw(openedKey, valueName, currentType, currentData);
        if (result != ERROR_SUCCESS)
        {
            ::RegCloseKey(openedKey);
            return result;
        }
        if (!RawRegistryValuesEqual(currentType, currentData, expectedType, expectedData))
        {
            ::RegCloseKey(openedKey);
            return ERROR_ALREADY_EXISTS;
        }
        const wchar_t* valueNamePointer = valueName.empty() ? nullptr : valueName.c_str();
        result = ::RegDeleteValueW(openedKey, valueNamePointer);
        ::RegCloseKey(openedKey);
        if (result != ERROR_SUCCESS)
        {
            return result;
        }
        result = QueryRegistryValueRaw(rootKey, subKey, valueName, currentType, currentData);
        return result == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : (result == ERROR_SUCCESS ? ERROR_ALREADY_EXISTS : result);
    }
}

namespace
{
    LONG WriteRegistryBackupMetadata(HKEY recordKey, const RegistryBackupRecord& record)
    {
        LONG result = SetMetadataDword(recordKey, L"SchemaVersion", kBackupSchemaVersion);
        if (result == ERROR_SUCCESS) result = SetMetadataDword(recordKey, L"State", record.state);
        if (result == ERROR_SUCCESS) result = SetMetadataDword(recordKey, L"Root", static_cast<DWORD>(record.root));
        if (result == ERROR_SUCCESS) result = SetMetadataString(recordKey, L"SubKey", record.subKey);
        if (result == ERROR_SUCCESS) result = SetMetadataString(recordKey, L"ValueName", record.valueName);
        if (result == ERROR_SUCCESS) result = SetMetadataString(recordKey, L"ItemName", record.itemName);
        if (result == ERROR_SUCCESS) result = SetMetadataDword(recordKey, L"ValueType", record.valueType);
        if (result == ERROR_SUCCESS) result = SetMetadataBinary(recordKey, L"RawData", record.rawData);
        return result;
    }

    bool ReadRegistryBackupMetadata(
        HKEY recordKey,
        const std::wstring& backupId,
        RegistryBackupRecord& recordOut)
    {
        DWORD schemaVersion = 0;
        DWORD state = 0;
        DWORD rootValue = 0;
        DWORD valueType = REG_NONE;
        RegistryBackupRecord record;
        record.backupId = backupId;
        if (!QueryMetadataDword(recordKey, L"SchemaVersion", schemaVersion)
            || schemaVersion != kBackupSchemaVersion
            || !QueryMetadataDword(recordKey, L"State", state)
            || state > kBackupStateRestored
            || !QueryMetadataDword(recordKey, L"Root", rootValue)
            || !QueryMetadataString(recordKey, L"SubKey", record.subKey)
            || !QueryMetadataString(recordKey, L"ValueName", record.valueName)
            || !QueryMetadataString(recordKey, L"ItemName", record.itemName)
            || !QueryMetadataDword(recordKey, L"ValueType", valueType)
            || !QueryMetadataBinary(recordKey, L"RawData", record.rawData))
        {
            return false;
        }
        record.root = static_cast<ks::startup::StartupRegistryRoot>(rootValue);
        record.state = state;
        record.valueType = valueType;
        const HKEY nativeRoot = NativeRegistryRoot(record.root);
        if (nativeRoot == nullptr || !IsSupportedRunLocation(nativeRoot, record.subKey))
        {
            return false;
        }
        recordOut = std::move(record);
        return true;
    }

    bool ReadRegistryBackupById(
        HKEY metadataHive,
        const std::wstring& backupId,
        RegistryBackupRecord& recordOut,
        DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;
        if (!IsSafeBackupId(backupId))
        {
            errorCodeOut = ERROR_INVALID_NAME;
            return false;
        }
        HKEY recordKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            metadataHive,
            MetadataRecordPath(kRegistryBackupRoot, backupId).c_str(),
            0,
            KEY_QUERY_VALUE,
            &recordKey);
        if (openResult != ERROR_SUCCESS)
        {
            errorCodeOut = static_cast<DWORD>(openResult);
            return false;
        }
        const bool readOk = ReadRegistryBackupMetadata(recordKey, backupId, recordOut)
            && RegistryBackupMetadataHive(recordOut.root) == metadataHive;
        ::RegCloseKey(recordKey);
        if (!readOk)
        {
            errorCodeOut = ERROR_INVALID_DATA;
        }
        return readOk;
    }

    bool RegistryBackupRecordsEqual(const RegistryBackupRecord& left, const RegistryBackupRecord& right)
    {
        return left.backupId == right.backupId
            && left.root == right.root
            && EqualWideI(left.subKey, right.subKey)
            && left.valueName == right.valueName
            && left.itemName == right.itemName
            && left.valueType == right.valueType
            && left.rawData == right.rawData
            && left.state == right.state;
    }

    std::string RunSourceTypeForSubKey(const std::wstring& subKey)
    {
        const std::wstring lowerSubKey = LowerWideCopy(subKey);
        const bool is32 = lowerSubKey.find(L"\\wow6432node\\") != std::wstring::npos;
        const bool isRunOnce = EndsWithI(subKey, L"\\RunOnce");
        if (is32)
        {
            return isRunOnce ? "RunOnce32" : "Run32";
        }
        return isRunOnce ? "RunOnce" : "Run";
    }

    // RollbackDisabledRegistryValue restores only into an absent value and never overwrites a conflict.
    bool RollbackDisabledRegistryValue(const RegistryBackupRecord& record, DWORD& errorCodeOut)
    {
        const HKEY rootKey = NativeRegistryRoot(record.root);
        const LONG restoreResult = SetRegistryValueWithoutOverwrite(
            rootKey,
            record.subKey,
            record.valueName,
            record.valueType,
            record.rawData);
        errorCodeOut = static_cast<DWORD>(restoreResult);
        return restoreResult == ERROR_SUCCESS;
    }

    ks::startup::ActionResult DisableRegistryRunEntry(const ks::startup::StartupEntry& entry)
    {
        const HKEY rootKey = NativeRegistryRoot(entry.actionLocator.registryRoot);
        const std::wstring subKey = ToWide(entry.actionLocator.registrySubKeyText);
        const std::wstring valueName = ToWide(entry.actionLocator.registryValueNameText);
        if (rootKey == nullptr
            || !IsSupportedRunLocation(rootKey, subKey)
            || !entry.actionLocator.backupIdText.empty())
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"注册表操作定位器无效。"));
        }

        DWORD valueType = REG_NONE;
        std::vector<std::uint8_t> rawData;
        LONG result = QueryRegistryValueRaw(rootKey, subKey, valueName, valueType, rawData);
        if (result != ERROR_SUCCESS)
        {
            return MakeActionResult(
                StatusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                FromWide(L"无法读取源注册表值。"));
        }
        if (entry.actionLocator.registryValueSnapshotValid
            && !RawRegistryValuesEqual(
                entry.actionLocator.registryValueType,
                entry.actionLocator.registryRawData,
                valueType,
                rawData))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                FromWide(L"注册表值已在枚举后变化；请刷新后重试。"));
        }

        RegistryBackupRecord record;
        record.root = entry.actionLocator.registryRoot;
        record.subKey = subKey;
        record.valueName = valueName;
        record.itemName = ToWide(entry.itemNameText);
        record.valueType = valueType;
        record.rawData = rawData;
        record.state = kBackupStatePrepared;
        const HKEY metadataHive = RegistryBackupMetadataHive(record.root);
        if (metadataHive == nullptr)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"注册表备份的完整性范围无效。"));
        }

        HKEY recordKey = nullptr;
        result = CreateUniqueMetadataKey(
            metadataHive,
            kRegistryBackupRoot,
            record.backupId,
            recordKey);
        if (result != ERROR_SUCCESS)
        {
            return MakeActionResult(
                StatusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                FromWide(L"无法创建唯一的注册表备份记录。"));
        }

        result = WriteRegistryBackupMetadata(recordKey, record);
        if (result == ERROR_SUCCESS)
        {
            result = ::RegFlushKey(recordKey);
        }
        RegistryBackupRecord verifiedRecord;
        const bool metadataVerified = result == ERROR_SUCCESS
            && ReadRegistryBackupMetadata(recordKey, record.backupId, verifiedRecord)
            && RegistryBackupRecordsEqual(record, verifiedRecord);
        if (!metadataVerified)
        {
            const DWORD failureCode = result == ERROR_SUCCESS ? ERROR_INVALID_DATA : static_cast<DWORD>(result);
            ::RegCloseKey(recordKey);
            DeleteMetadataRecord(metadataHive, kRegistryBackupRoot, record.backupId);
            return MakeActionResult(
                StatusFromWin32(failureCode, ks::startup::StartupActionStatus::VerificationFailed),
                false,
                false,
                failureCode,
                FromWide(L"注册表备份写入或校验失败；源值未被修改。"));
        }

        DWORD currentType = REG_NONE;
        std::vector<std::uint8_t> currentData;
        result = QueryRegistryValueRaw(rootKey, subKey, valueName, currentType, currentData);
        if (result != ERROR_SUCCESS || !RawRegistryValuesEqual(valueType, rawData, currentType, currentData))
        {
            ::RegCloseKey(recordKey);
            DeleteMetadataRecord(metadataHive, kRegistryBackupRoot, record.backupId);
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                result == ERROR_SUCCESS ? ERROR_ALREADY_EXISTS : static_cast<DWORD>(result),
                FromWide(L"源注册表值在备份后发生变化；未执行删除。"));
        }

        result = DeleteRegistryValueIfExact(rootKey, subKey, valueName, valueType, rawData);
        if (result != ERROR_SUCCESS)
        {
            ::RegCloseKey(recordKey);
            DWORD observedType = REG_NONE;
            std::vector<std::uint8_t> observedData;
            const LONG observeResult = QueryRegistryValueRaw(rootKey, subKey, valueName, observedType, observedData);
            ks::startup::ActionResult failure = MakeActionResult(
                StatusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                FromWide(L"无法安全删除源注册表值。"));
            failure.rollbackAttempted = true;
            if (observeResult == ERROR_SUCCESS && RawRegistryValuesEqual(valueType, rawData, observedType, observedData))
            {
                failure.rollbackSucceeded = DeleteMetadataRecord(
                    metadataHive,
                    kRegistryBackupRoot,
                    record.backupId) == ERROR_SUCCESS;
            }
            else if (observeResult == ERROR_FILE_NOT_FOUND)
            {
                DWORD rollbackError = ERROR_SUCCESS;
                failure.rollbackSucceeded = RollbackDisabledRegistryValue(record, rollbackError);
                if (failure.rollbackSucceeded)
                {
                    DeleteMetadataRecord(metadataHive, kRegistryBackupRoot, record.backupId);
                }
                else
                {
                    failure.status = ks::startup::StartupActionStatus::RollbackFailed;
                    failure.errorCode = rollbackError;
                }
            }
            else
            {
                failure.status = ks::startup::StartupActionStatus::RollbackFailed;
                failure.errorCode = observeResult == ERROR_SUCCESS ? ERROR_ALREADY_EXISTS : static_cast<DWORD>(observeResult);
            }
            return failure;
        }

        LONG stateResult = SetAndVerifyMetadataState(recordKey, kBackupStateDisabled);
        if (stateResult == ERROR_SUCCESS)
        {
            stateResult = ::RegFlushKey(recordKey);
        }
        ::RegCloseKey(recordKey);
        if (stateResult != ERROR_SUCCESS)
        {
            DWORD rollbackError = ERROR_SUCCESS;
            const bool rollbackOk = RollbackDisabledRegistryValue(record, rollbackError);
            ks::startup::ActionResult failure = MakeActionResult(
                rollbackOk
                    ? StatusFromWin32(static_cast<DWORD>(stateResult), ks::startup::StartupActionStatus::WriteFailed)
                    : ks::startup::StartupActionStatus::RollbackFailed,
                false,
                false,
                rollbackOk ? static_cast<DWORD>(stateResult) : rollbackError,
                rollbackOk
                    ? FromWide(L"禁用状态提交失败；原注册表值已恢复。")
                    : FromWide(L"禁用状态提交失败，且自动回滚失败。"));
            failure.rollbackAttempted = true;
            failure.rollbackSucceeded = rollbackOk;
            if (rollbackOk)
            {
                DeleteMetadataRecord(metadataHive, kRegistryBackupRoot, record.backupId);
            }
            return failure;
        }

        return MakeActionResult(
            ks::startup::StartupActionStatus::Success,
            true,
            true,
            ERROR_SUCCESS,
            FromWide(L"注册表启动值已完成备份、校验并禁用。"));
    }

    ks::startup::ActionResult EnableRegistryRunEntry(const ks::startup::StartupEntry& entry)
    {
        const std::wstring backupId = ToWide(entry.actionLocator.backupIdText);
        const HKEY metadataHive = RegistryBackupMetadataHive(entry.actionLocator.registryRoot);
        if (metadataHive == nullptr)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"注册表恢复记录的完整性范围无效。"));
        }
        RegistryBackupRecord record;
        DWORD readError = ERROR_SUCCESS;
        if (!ReadRegistryBackupById(metadataHive, backupId, record, readError))
        {
            return MakeActionResult(
                StatusFromWin32(readError, ks::startup::StartupActionStatus::InvalidEntry),
                false,
                false,
                readError,
                FromWide(L"注册表备份记录缺失、格式无效，或使用了不受支持的版本。"));
        }
        if (record.state == kBackupStateRestored)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::NoChange,
                true,
                false,
                ERROR_SUCCESS,
                FromWide(L"注册表启动值已经恢复。"));
        }
        if (record.state != kBackupStateDisabled)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_STATE,
                FromWide(L"注册表备份事务尚未提交，不能通过此接口恢复。"));
        }
        if (record.root != entry.actionLocator.registryRoot
            || !EqualWideI(record.subKey, ToWide(entry.actionLocator.registrySubKeyText))
            || record.valueName != ToWide(entry.actionLocator.registryValueNameText))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_DATA,
                FromWide(L"条目定位器与不可变备份元数据不匹配。"));
        }

        const HKEY rootKey = NativeRegistryRoot(record.root);
        LONG result = SetRegistryValueWithoutOverwrite(
            rootKey,
            record.subKey,
            record.valueName,
            record.valueType,
            record.rawData);
        if (result != ERROR_SUCCESS)
        {
            return MakeActionResult(
                StatusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                result == ERROR_ALREADY_EXISTS
                    ? FromWide(L"原名称下已存在注册表值；未执行覆盖。")
                    : FromWide(L"无法恢复原注册表值。"));
        }

        HKEY recordKey = nullptr;
        result = ::RegOpenKeyExW(
            metadataHive,
            MetadataRecordPath(kRegistryBackupRoot, backupId).c_str(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &recordKey);
        LONG stateResult = result;
        if (stateResult == ERROR_SUCCESS)
        {
            stateResult = SetAndVerifyMetadataState(recordKey, kBackupStateRestored);
        }
        if (stateResult == ERROR_SUCCESS)
        {
            stateResult = ::RegFlushKey(recordKey);
        }
        if (recordKey != nullptr)
        {
            ::RegCloseKey(recordKey);
        }
        if (stateResult != ERROR_SUCCESS)
        {
            const LONG rollbackResult = DeleteRegistryValueIfExact(
                rootKey,
                record.subKey,
                record.valueName,
                record.valueType,
                record.rawData);
            ks::startup::ActionResult failure = MakeActionResult(
                rollbackResult == ERROR_SUCCESS
                    ? StatusFromWin32(static_cast<DWORD>(stateResult), ks::startup::StartupActionStatus::WriteFailed)
                    : ks::startup::StartupActionStatus::RollbackFailed,
                false,
                false,
                rollbackResult == ERROR_SUCCESS ? static_cast<DWORD>(stateResult) : static_cast<DWORD>(rollbackResult),
                rollbackResult == ERROR_SUCCESS
                    ? FromWide(L"恢复元数据提交失败；已再次移除刚恢复的值。")
                    : FromWide(L"恢复元数据提交失败，且无法回滚刚恢复的值。"));
            failure.rollbackAttempted = true;
            failure.rollbackSucceeded = rollbackResult == ERROR_SUCCESS;
            return failure;
        }

        const LONG cleanupResult = DeleteMetadataRecord(
            metadataHive,
            kRegistryBackupRoot,
            backupId);
        return MakeActionResult(
            ks::startup::StartupActionStatus::Success,
            true,
            true,
            cleanupResult == ERROR_SUCCESS ? ERROR_SUCCESS : static_cast<DWORD>(cleanupResult),
            cleanupResult == ERROR_SUCCESS
                ? FromWide(L"原注册表值已恢复，备份记录已移除。")
                : FromWide(L"原注册表值已恢复，但无法移除已退役的备份元数据。"));
    }

    // AppendDisabledRegistryRunEntries exposes valid app-owned backups as enabled=false records.
    void AppendDisabledRegistryRunEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        const std::array<HKEY, 2> metadataHives{ HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
        for (const HKEY metadataHive : metadataHives)
        {
            const std::string metadataScope = metadataHive == HKEY_LOCAL_MACHINE ? "HKLM" : "HKCU";
            for (const std::wstring& backupId : EnumerateRegistrySubKeys(metadataHive, kRegistryBackupRoot))
            {
                RegistryBackupRecord record;
                DWORD readError = ERROR_SUCCESS;
                if (!ReadRegistryBackupById(metadataHive, backupId, record, readError))
                {
                    ks::startup::StartupEntry invalidEntry;
                    invalidEntry.category = ks::startup::StartupCategory::Logon;
                    invalidEntry.categoryText = ks::startup::CategoryToText(invalidEntry.category);
                    invalidEntry.itemNameText = FromWide(L"KSword 注册表恢复记录 ") + FromWide(backupId);
                    invalidEntry.detailText =
                        metadataScope + "|" + FromWide(L"KSword 备份=") + FromWide(backupId);
                    invalidEntry.sourceTypeText = "RunBackup";
                    invalidEntry.enabled = false;
                    invalidEntry.uniqueIdText =
                        "REGLOGON-RECOVERY-INVALID|" + metadataScope + "|" + FromWide(backupId);
                    invalidEntry.lastErrorCode = readError;
                    MarkEntryActionUnavailable(
                        invalidEntry,
                        ks::startup::StartupRiskLevel::Critical,
                        "backup_record",
                        FromWide(L"注册表恢复元数据损坏、版本不受支持，或元数据完整性范围与目标不匹配。"));
                    entries.push_back(std::move(invalidEntry));
                    continue;
                }
            const HKEY rootKey = NativeRegistryRoot(record.root);
            DWORD sourceType = REG_NONE;
            std::vector<std::uint8_t> sourceData;
            const LONG sourceResult = QueryRegistryValueRaw(
                rootKey,
                record.subKey,
                record.valueName,
                sourceType,
                sourceData);
            const bool restoreConflict = sourceResult == ERROR_SUCCESS;
            const bool sourceConfirmedAbsent =
                sourceResult == ERROR_FILE_NOT_FOUND || sourceResult == ERROR_PATH_NOT_FOUND;
            const bool sourceMatchesBackup = restoreConflict
                && RawRegistryValuesEqual(
                    sourceType,
                    sourceData,
                    record.valueType,
                    record.rawData);
            DWORD reconciliationError = ERROR_SUCCESS;
            if (record.state == kBackupStatePrepared)
            {
                if (sourceMatchesBackup)
                {
                    reconciliationError = static_cast<DWORD>(
                        DeleteMetadataRecord(metadataHive, kRegistryBackupRoot, backupId));
                    if (reconciliationError == ERROR_SUCCESS)
                    {
                        continue;
                    }
                }
                else if (sourceConfirmedAbsent)
                {
                    reconciliationError = static_cast<DWORD>(
                        CommitMetadataStateById(
                            metadataHive,
                            kRegistryBackupRoot,
                            backupId,
                            kBackupStateDisabled));
                    if (reconciliationError == ERROR_SUCCESS)
                    {
                        record.state = kBackupStateDisabled;
                    }
                }
            }
            else if (record.state == kBackupStateRestored && sourceMatchesBackup)
            {
                reconciliationError = static_cast<DWORD>(
                    DeleteMetadataRecord(metadataHive, kRegistryBackupRoot, backupId));
                if (reconciliationError == ERROR_SUCCESS)
                {
                    continue;
                }
            }

            ks::startup::StartupEntry entry;
            const bool logonSource = IsKnownRunLocation(rootKey, record.subKey)
                || LowerWideCopy(record.subKey).find(L"\\runonceex") != std::wstring::npos;
            const bool imageHijackSource = IsImageHijackRegistrySubKey(record.subKey);
            entry.category = logonSource
                ? ks::startup::StartupCategory::Logon
                : (imageHijackSource
                    ? ks::startup::StartupCategory::ImageHijack
                    : ks::startup::StartupCategory::Registry);
            entry.categoryText = ks::startup::CategoryToText(entry.category);
            entry.itemNameText = record.itemName.empty()
                ? (record.valueName.empty() ? FromWide(L"(\u9ed8\u8ba4\u503c)") : FromWide(record.valueName))
                : FromWide(record.itemName);
            entry.locationText = BuildRegistryLocationText(rootKey, record.subKey);
            entry.locationGroupText = entry.locationText;
            entry.userText = record.root == ks::startup::StartupRegistryRoot::CurrentUser
                ? FromWide(L"\u5f53\u524d\u7528\u6237")
                : FromWide(L"\u672c\u673a");
            entry.sourceTypeText = logonSource
                ? RunSourceTypeForSubKey(record.subKey)
                : (imageHijackSource ? "ImageHijackBackup" : "RegistryBackup");
            entry.detailText =
                metadataScope + "|" + FromWide(L"KSword 备份=") + FromWide(backupId);
            entry.uniqueIdText =
                "REGLOGON-RECOVERY|" + metadataScope + "|" + FromWide(backupId);
            FinalizeRegistryEntry(
                entry,
                RegistryDataToText(record.valueType, record.rawData),
                std::string(),
                FromWide(record.valueName),
                false,
                false);
            entry.enabled = sourceMatchesBackup;
            entry.lastErrorCode = reconciliationError != ERROR_SUCCESS
                ? reconciliationError
                : (sourceConfirmedAbsent || restoreConflict
                    ? ERROR_SUCCESS
                    : static_cast<std::uint32_t>(sourceResult));
            std::string reasonCode = "backup_record";
            std::string reasonText;
            if (record.root == ks::startup::StartupRegistryRoot::LocalMachine)
            {
                reasonCode = "machine_scope";
                reasonText = FromWide(L"恢复机器范围注册表值需要管理员权限，并会影响所有用户。");
            }
            else if (record.state == kBackupStatePrepared && sourceMatchesBackup)
            {
                reasonText = FromWide(L"Prepared 操作尚未发生，但清理恢复元数据失败；记录保持可见。");
            }
            else if (record.state == kBackupStatePrepared && sourceConfirmedAbsent)
            {
                reasonText = FromWide(L"Prepared 记录对应的源值已缺失，但提交 Disabled 状态失败；记录保持可见。");
            }
            else if (restoreConflict && !sourceMatchesBackup)
            {
                reasonText = FromWide(L"源位置已出现不同的同名注册表值；恢复操作会拒绝覆盖该值。");
            }
            else if (!sourceConfirmedAbsent)
            {
                reasonText = FromWide(L"无法检查原注册表位置；恢复操作可能因访问错误而失败。");
            }
            else
            {
                reasonText = FromWide(L"恢复元数据已完成对账；警告确认后可以恢复原注册表值。");
            }
            if (record.state == kBackupStateDisabled)
            {
                entry.actionKind = ks::startup::StartupActionKind::RegistryRunValue;
                entry.actionLocator.registryRoot = record.root;
                entry.actionLocator.registrySubKeyText = FromWide(record.subKey);
                entry.actionLocator.registryValueNameText = FromWide(record.valueName);
                entry.actionLocator.backupIdText = FromWide(backupId);
                entry.canEnable = true;
                entry.canDisable = false;
                entry.riskLevel = record.root == ks::startup::StartupRegistryRoot::LocalMachine
                    || !logonSource
                    ? ks::startup::StartupRiskLevel::Critical
                    : ks::startup::StartupRiskLevel::Elevated;
                entry.riskReasonCode = reasonCode;
                entry.riskReasonText = reasonText;
            }
            else
            {
                MarkEntryActionUnavailable(
                    entry,
                    ks::startup::StartupRiskLevel::Critical,
                    reasonCode,
                    reasonText);
            }
            entries.push_back(std::move(entry));
            }
        }
    }
}

namespace
{
    std::wstring StartupParkingRoot(HKEY metadataHive)
    {
        if (metadataHive == HKEY_CURRENT_USER)
        {
            const std::wstring localAppData = KnownFolderPath(FOLDERID_LocalAppData);
            return localAppData.empty()
                ? std::wstring()
                : (std::filesystem::path(localAppData) / L"KSword" / L"StartupManager" / L"Parking").wstring();
        }
        if (metadataHive == HKEY_LOCAL_MACHINE)
        {
            const std::wstring programData = KnownFolderPath(FOLDERID_ProgramData);
            const std::wstring protectedDirectoryName =
                std::wstring(L"KSword") + L"StartupManager";
            return programData.empty()
                ? std::wstring()
                : (std::filesystem::path(programData) / protectedDirectoryName / L"Parking").wstring();
        }
        return std::wstring();
    }

    LONG EnsureProtectedMachineDirectory(const std::wstring& directoryPath)
    {
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)",
                SDDL_REVISION_1,
                &securityDescriptor,
                nullptr) == FALSE)
        {
            return static_cast<LONG>(::GetLastError());
        }

        SECURITY_ATTRIBUTES securityAttributes{};
        securityAttributes.nLength = sizeof(securityAttributes);
        securityAttributes.lpSecurityDescriptor = securityDescriptor;
        securityAttributes.bInheritHandle = FALSE;
        if (::CreateDirectoryW(directoryPath.c_str(), &securityAttributes) == FALSE)
        {
            const DWORD createError = ::GetLastError();
            if (createError != ERROR_ALREADY_EXISTS)
            {
                ::LocalFree(securityDescriptor);
                return static_cast<LONG>(createError);
            }
        }

        HANDLE directoryHandle = ::CreateFileW(
            directoryPath.c_str(),
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (directoryHandle == INVALID_HANDLE_VALUE)
        {
            const DWORD openError = ::GetLastError();
            ::LocalFree(securityDescriptor);
            return static_cast<LONG>(openError);
        }

        BY_HANDLE_FILE_INFORMATION fileInformation{};
        const bool informationValid =
            ::GetFileInformationByHandle(directoryHandle, &fileInformation) != FALSE;
        if (!informationValid
            || (fileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
            || (fileInformation.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            const DWORD validationError = informationValid
                ? ERROR_REPARSE_TAG_INVALID
                : ::GetLastError();
            ::CloseHandle(directoryHandle);
            ::LocalFree(securityDescriptor);
            return static_cast<LONG>(validationError);
        }

        BOOL daclPresent = FALSE;
        BOOL daclDefaulted = FALSE;
        PACL dacl = nullptr;
        const bool daclValid =
            ::GetSecurityDescriptorDacl(securityDescriptor, &daclPresent, &dacl, &daclDefaulted) != FALSE
            && daclPresent
            && dacl != nullptr;
        const DWORD securityResult = daclValid
            ? ::SetSecurityInfo(
                directoryHandle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                dacl,
                nullptr)
            : ERROR_INVALID_SECURITY_DESCR;
        ::CloseHandle(directoryHandle);
        ::LocalFree(securityDescriptor);
        return static_cast<LONG>(securityResult);
    }

    LONG EnsureMachineStartupParkingRoot()
    {
        const std::wstring parkingRoot = StartupParkingRoot(HKEY_LOCAL_MACHINE);
        if (parkingRoot.empty())
        {
            return ERROR_PATH_NOT_FOUND;
        }
        const std::wstring protectedRoot =
            std::filesystem::path(parkingRoot).parent_path().wstring();
        LONG result = EnsureProtectedMachineDirectory(protectedRoot);
        if (result == ERROR_SUCCESS)
        {
            result = EnsureProtectedMachineDirectory(parkingRoot);
        }
        return result;
    }

    std::wstring NormalizedPathText(const std::wstring& pathText)
    {
        if (pathText.empty())
        {
            return std::wstring();
        }
        return std::filesystem::path(pathText).lexically_normal().wstring();
    }

    bool EqualPathI(const std::wstring& left, const std::wstring& right)
    {
        return EqualWideI(NormalizedPathText(left), NormalizedPathText(right));
    }

    // IsKnownStartupFolderFile recognizes current and legacy machine-wide records for display.
    bool IsKnownStartupFolderFile(const std::wstring& pathText, bool* machineWideOut = nullptr)
    {
        const std::filesystem::path filePath = std::filesystem::path(pathText).lexically_normal();
        if (!filePath.is_absolute() || filePath.filename().empty())
        {
            return false;
        }
        const std::array<std::pair<std::wstring, bool>, 2> folders{ {
            { KnownFolderPath(FOLDERID_Startup), false },
            { KnownFolderPath(FOLDERID_CommonStartup), true }
        } };
        for (const auto& folder : folders)
        {
            if (!folder.first.empty() && EqualPathI(filePath.parent_path().wstring(), folder.first))
            {
                if (machineWideOut != nullptr)
                {
                    *machineWideOut = folder.second;
                }
                return true;
            }
        }
        return false;
    }

    bool IsSupportedStartupFolderFile(const std::wstring& pathText)
    {
        bool machineWide = false;
        return IsKnownStartupFolderFile(pathText, &machineWide);
    }

    HKEY StartupFolderMetadataHive(const std::wstring& originalPath)
    {
        bool machineWide = false;
        if (!IsKnownStartupFolderFile(originalPath, &machineWide))
        {
            return nullptr;
        }
        return machineWide ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    }

    bool IsRegularFileWide(const std::wstring& pathText)
    {
        const DWORD attributes = ::GetFileAttributesW(pathText.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    LONG MoveFileWithoutOverwrite(const std::wstring& sourcePath, const std::wstring& destinationPath)
    {
        if (IsRegularFileWide(destinationPath) || ::GetFileAttributesW(destinationPath.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            return ERROR_ALREADY_EXISTS;
        }
        if (::MoveFileExW(
                sourcePath.c_str(),
                destinationPath.c_str(),
                MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH) == FALSE)
        {
            return static_cast<LONG>(::GetLastError());
        }
        if (IsRegularFileWide(sourcePath) || !IsRegularFileWide(destinationPath))
        {
            return ERROR_INVALID_DATA;
        }
        return ERROR_SUCCESS;
    }

    LONG WriteStartupFolderBackupMetadata(HKEY recordKey, const StartupFolderBackupRecord& record)
    {
        LONG result = SetMetadataDword(recordKey, L"SchemaVersion", kBackupSchemaVersion);
        if (result == ERROR_SUCCESS) result = SetMetadataDword(recordKey, L"State", record.state);
        if (result == ERROR_SUCCESS) result = SetMetadataString(recordKey, L"OriginalPath", record.originalPath);
        if (result == ERROR_SUCCESS) result = SetMetadataString(recordKey, L"ParkedPath", record.parkedPath);
        if (result == ERROR_SUCCESS) result = SetMetadataString(recordKey, L"ItemName", record.itemName);
        return result;
    }

    bool ReadStartupFolderBackupMetadata(
        HKEY metadataHive,
        HKEY recordKey,
        const std::wstring& backupId,
        StartupFolderBackupRecord& recordOut)
    {
        DWORD schemaVersion = 0;
        StartupFolderBackupRecord record;
        record.backupId = backupId;
        if (!QueryMetadataDword(recordKey, L"SchemaVersion", schemaVersion)
            || schemaVersion != kBackupSchemaVersion
            || !QueryMetadataDword(recordKey, L"State", record.state)
            || record.state > kBackupStateRestored
            || !QueryMetadataString(recordKey, L"OriginalPath", record.originalPath)
            || !QueryMetadataString(recordKey, L"ParkedPath", record.parkedPath)
            || !QueryMetadataString(recordKey, L"ItemName", record.itemName)
            || StartupFolderMetadataHive(record.originalPath) != metadataHive)
        {
            return false;
        }
        const std::wstring parkingRoot = StartupParkingRoot(metadataHive);
        if (parkingRoot.empty())
        {
            return false;
        }
        const std::wstring expectedParkedPath =
            (std::filesystem::path(parkingRoot) / backupId / std::filesystem::path(record.originalPath).filename()).wstring();
        if (!EqualPathI(expectedParkedPath, record.parkedPath))
        {
            return false;
        }
        recordOut = std::move(record);
        return true;
    }

    bool ReadStartupFolderBackupById(
        HKEY metadataHive,
        const std::wstring& backupId,
        StartupFolderBackupRecord& recordOut,
        DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;
        if (!IsSafeBackupId(backupId))
        {
            errorCodeOut = ERROR_INVALID_NAME;
            return false;
        }
        HKEY recordKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            metadataHive,
            MetadataRecordPath(kStartupFolderBackupRoot, backupId).c_str(),
            0,
            KEY_QUERY_VALUE,
            &recordKey);
        if (openResult != ERROR_SUCCESS)
        {
            errorCodeOut = static_cast<DWORD>(openResult);
            return false;
        }
        const bool readOk = ReadStartupFolderBackupMetadata(
            metadataHive,
            recordKey,
            backupId,
            recordOut);
        ::RegCloseKey(recordKey);
        if (!readOk)
        {
            errorCodeOut = ERROR_INVALID_DATA;
        }
        return readOk;
    }

    bool StartupFolderBackupRecordsEqual(
        const StartupFolderBackupRecord& left,
        const StartupFolderBackupRecord& right)
    {
        return left.backupId == right.backupId
            && EqualPathI(left.originalPath, right.originalPath)
            && EqualPathI(left.parkedPath, right.parkedPath)
            && left.itemName == right.itemName
            && left.state == right.state;
    }

    LONG CreateUniqueStartupFolderBackup(
        const std::wstring& originalPath,
        StartupFolderBackupRecord& recordOut,
        HKEY& recordKeyOut)
    {
        const HKEY metadataHive = StartupFolderMetadataHive(originalPath);
        const std::wstring parkingRoot = StartupParkingRoot(metadataHive);
        if (parkingRoot.empty())
        {
            return ERROR_PATH_NOT_FOUND;
        }
        if (metadataHive == HKEY_LOCAL_MACHINE)
        {
            const LONG directoryResult = EnsureMachineStartupParkingRoot();
            if (directoryResult != ERROR_SUCCESS)
            {
                return directoryResult;
            }
        }
        else
        {
            std::error_code directoryError;
            std::filesystem::create_directories(parkingRoot, directoryError);
            if (directoryError)
            {
                return static_cast<LONG>(directoryError.value());
            }
        }
        for (int attempt = 0; attempt < 64; ++attempt)
        {
            StartupFolderBackupRecord record;
            record.originalPath = NormalizedPathText(originalPath);
            record.itemName = std::filesystem::path(record.originalPath).filename().wstring();
            record.state = kBackupStatePrepared;
            HKEY recordKey = nullptr;
            LONG result = CreateUniqueMetadataKey(
                metadataHive,
                kStartupFolderBackupRoot,
                record.backupId,
                recordKey);
            if (result != ERROR_SUCCESS)
            {
                return result;
            }
            const std::wstring parkingDirectory =
                (std::filesystem::path(parkingRoot) / record.backupId).wstring();
            record.parkedPath =
                (std::filesystem::path(parkingDirectory) / record.itemName).wstring();
            if (::CreateDirectoryW(parkingDirectory.c_str(), nullptr) != FALSE)
            {
                recordOut = std::move(record);
                recordKeyOut = recordKey;
                return ERROR_SUCCESS;
            }
            result = static_cast<LONG>(::GetLastError());
            ::RegCloseKey(recordKey);
            DeleteMetadataRecord(metadataHive, kStartupFolderBackupRoot, record.backupId);
            if (result != ERROR_ALREADY_EXISTS)
            {
                return result;
            }
        }
        return ERROR_ALREADY_EXISTS;
    }

    void CleanupStartupFolderBackupArtifacts(const StartupFolderBackupRecord& record)
    {
        const HKEY metadataHive = StartupFolderMetadataHive(record.originalPath);
        const std::wstring parkingRoot = StartupParkingRoot(metadataHive);
        if (metadataHive == nullptr || !IsSafeBackupId(record.backupId) || parkingRoot.empty())
        {
            return;
        }
        const std::wstring expectedDirectory =
            (std::filesystem::path(parkingRoot) / record.backupId).wstring();
        const std::wstring actualDirectory =
            std::filesystem::path(record.parkedPath).parent_path().wstring();
        const std::wstring expectedParkedPath =
            (std::filesystem::path(expectedDirectory) / record.itemName).wstring();
        if (!EqualPathI(expectedDirectory, actualDirectory)
            || !EqualPathI(expectedParkedPath, record.parkedPath))
        {
            return;
        }
        const DWORD attributes = ::GetFileAttributesW(expectedDirectory.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            const DWORD errorCode = ::GetLastError();
            if (errorCode == ERROR_FILE_NOT_FOUND || errorCode == ERROR_PATH_NOT_FOUND)
            {
                DeleteMetadataRecord(metadataHive, kStartupFolderBackupRoot, record.backupId);
            }
            return;
        }
        if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0
            || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            return;
        }
        if (::RemoveDirectoryW(expectedDirectory.c_str()) != FALSE)
        {
            DeleteMetadataRecord(metadataHive, kStartupFolderBackupRoot, record.backupId);
        }
    }

    ks::startup::ActionResult DisableStartupFolderEntry(const ks::startup::StartupEntry& entry)
    {
        const std::wstring originalPath = ToWide(entry.actionLocator.originalFilePathText);
        const HKEY metadataHive = StartupFolderMetadataHive(originalPath);
        if (!entry.actionLocator.backupIdText.empty()
            || !entry.actionLocator.parkedFilePathText.empty()
            || metadataHive == nullptr)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"启动文件夹操作定位器无效，或目标不在 Windows 启动文件夹内。"));
        }
        if (!IsRegularFileWide(originalPath))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::NotFound,
                false,
                false,
                ERROR_FILE_NOT_FOUND,
                FromWide(L"启动文件夹中的文件已不存在。"));
        }
        if (entry.actionLocator.fileIdentitySnapshotValid)
        {
            FileIdentitySnapshot observedIdentity;
            DWORD identityError = ERROR_SUCCESS;
            const bool identityValid = QueryFileIdentityNoReparse(
                originalPath,
                observedIdentity,
                identityError);
            const bool identityMatches = identityValid
                && observedIdentity.volumeSerial == entry.actionLocator.fileVolumeSerial
                && observedIdentity.fileIndex == entry.actionLocator.fileIndex
                && observedIdentity.fileSize == entry.actionLocator.fileSize
                && observedIdentity.lastWriteTime == entry.actionLocator.fileLastWriteTime;
            if (!identityMatches)
            {
                return MakeActionResult(
                    ks::startup::StartupActionStatus::Conflict,
                    false,
                    false,
                    identityValid ? ERROR_REVISION_MISMATCH : identityError,
                    FromWide(L"启动文件已在枚举后变化；请刷新后重试。"));
            }
        }

        StartupFolderBackupRecord record;
        HKEY recordKey = nullptr;
        LONG result = CreateUniqueStartupFolderBackup(originalPath, record, recordKey);
        if (result != ERROR_SUCCESS)
        {
            return MakeActionResult(
                StatusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                FromWide(L"无法创建唯一的应用专用暂存位置。"));
        }

        result = WriteStartupFolderBackupMetadata(recordKey, record);
        if (result == ERROR_SUCCESS)
        {
            result = ::RegFlushKey(recordKey);
        }
        StartupFolderBackupRecord verifiedRecord;
        const bool metadataVerified = result == ERROR_SUCCESS
            && ReadStartupFolderBackupMetadata(
                metadataHive,
                recordKey,
                record.backupId,
                verifiedRecord)
            && StartupFolderBackupRecordsEqual(record, verifiedRecord);
        if (!metadataVerified)
        {
            const DWORD failureCode = result == ERROR_SUCCESS ? ERROR_INVALID_DATA : static_cast<DWORD>(result);
            ::RegCloseKey(recordKey);
            CleanupStartupFolderBackupArtifacts(record);
            return MakeActionResult(
                StatusFromWin32(failureCode, ks::startup::StartupActionStatus::VerificationFailed),
                false,
                false,
                failureCode,
                FromWide(L"暂存元数据写入或校验失败；源文件未被移动。"));
        }

        result = MoveFileWithoutOverwrite(record.originalPath, record.parkedPath);
        if (result != ERROR_SUCCESS)
        {
            ::RegCloseKey(recordKey);
            ks::startup::ActionResult failure = MakeActionResult(
                StatusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                FromWide(L"无法将启动文件夹文件移动到暂存位置。"));
            failure.rollbackAttempted = true;
            if (IsRegularFileWide(record.originalPath) && !IsRegularFileWide(record.parkedPath))
            {
                failure.rollbackSucceeded = true;
                CleanupStartupFolderBackupArtifacts(record);
            }
            else if (!IsRegularFileWide(record.originalPath) && IsRegularFileWide(record.parkedPath))
            {
                const LONG rollbackResult = MoveFileWithoutOverwrite(record.parkedPath, record.originalPath);
                failure.rollbackSucceeded = rollbackResult == ERROR_SUCCESS;
                if (failure.rollbackSucceeded)
                {
                    CleanupStartupFolderBackupArtifacts(record);
                }
                else
                {
                    failure.status = ks::startup::StartupActionStatus::RollbackFailed;
                    failure.errorCode = static_cast<DWORD>(rollbackResult);
                }
            }
            else
            {
                failure.status = ks::startup::StartupActionStatus::RollbackFailed;
                failure.errorCode = ERROR_ALREADY_EXISTS;
            }
            return failure;
        }

        LONG stateResult = SetAndVerifyMetadataState(recordKey, kBackupStateDisabled);
        if (stateResult == ERROR_SUCCESS)
        {
            stateResult = ::RegFlushKey(recordKey);
        }
        ::RegCloseKey(recordKey);
        if (stateResult != ERROR_SUCCESS)
        {
            const LONG rollbackResult = MoveFileWithoutOverwrite(record.parkedPath, record.originalPath);
            ks::startup::ActionResult failure = MakeActionResult(
                rollbackResult == ERROR_SUCCESS
                    ? StatusFromWin32(static_cast<DWORD>(stateResult), ks::startup::StartupActionStatus::WriteFailed)
                    : ks::startup::StartupActionStatus::RollbackFailed,
                false,
                false,
                rollbackResult == ERROR_SUCCESS ? static_cast<DWORD>(stateResult) : static_cast<DWORD>(rollbackResult),
                rollbackResult == ERROR_SUCCESS
                    ? FromWide(L"暂存状态提交失败；启动文件夹文件已恢复。")
                    : FromWide(L"暂存状态提交失败，且文件自动回滚失败。"));
            failure.rollbackAttempted = true;
            failure.rollbackSucceeded = rollbackResult == ERROR_SUCCESS;
            if (failure.rollbackSucceeded)
            {
                CleanupStartupFolderBackupArtifacts(record);
            }
            return failure;
        }

        return MakeActionResult(
            ks::startup::StartupActionStatus::Success,
            true,
            true,
            ERROR_SUCCESS,
            FromWide(L"启动文件夹文件已移动到唯一的应用专用暂存位置。"));
    }

    ks::startup::ActionResult EnableStartupFolderEntry(const ks::startup::StartupEntry& entry)
    {
        const std::wstring backupId = ToWide(entry.actionLocator.backupIdText);
        const HKEY metadataHive =
            StartupFolderMetadataHive(ToWide(entry.actionLocator.originalFilePathText));
        if (metadataHive == nullptr)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"启动文件夹恢复记录的完整性范围无效。"));
        }
        StartupFolderBackupRecord record;
        DWORD readError = ERROR_SUCCESS;
        if (!ReadStartupFolderBackupById(metadataHive, backupId, record, readError))
        {
            return MakeActionResult(
                StatusFromWin32(readError, ks::startup::StartupActionStatus::InvalidEntry),
                false,
                false,
                readError,
                FromWide(L"启动文件夹备份记录缺失、格式无效，或使用了不受支持的版本。"));
        }
        if (record.state == kBackupStateRestored)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::NoChange,
                true,
                false,
                ERROR_SUCCESS,
                FromWide(L"启动文件夹文件已经恢复。"));
        }
        if (record.state != kBackupStateDisabled)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_STATE,
                FromWide(L"暂存事务尚未提交，不能通过此接口恢复。"));
        }
        if (!EqualPathI(record.originalPath, ToWide(entry.actionLocator.originalFilePathText))
            || !EqualPathI(record.parkedPath, ToWide(entry.actionLocator.parkedFilePathText)))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_DATA,
                FromWide(L"条目定位器与不可变暂存元数据不匹配。"));
        }
        if (IsRegularFileWide(record.originalPath))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_ALREADY_EXISTS,
                FromWide(L"原位置已存在同名文件；未执行覆盖。"));
        }
        if (!IsRegularFileWide(record.parkedPath))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::NotFound,
                false,
                false,
                ERROR_FILE_NOT_FOUND,
                FromWide(L"暂存的启动文件夹文件缺失。"));
        }

        LONG result = MoveFileWithoutOverwrite(record.parkedPath, record.originalPath);
        if (result != ERROR_SUCCESS)
        {
            return MakeActionResult(
                StatusFromWin32(static_cast<DWORD>(result), ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                static_cast<DWORD>(result),
                FromWide(L"无法恢复暂存的启动文件夹文件。"));
        }

        HKEY recordKey = nullptr;
        result = ::RegOpenKeyExW(
            metadataHive,
            MetadataRecordPath(kStartupFolderBackupRoot, backupId).c_str(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &recordKey);
        LONG stateResult = result;
        if (stateResult == ERROR_SUCCESS)
        {
            stateResult = SetAndVerifyMetadataState(recordKey, kBackupStateRestored);
        }
        if (stateResult == ERROR_SUCCESS)
        {
            stateResult = ::RegFlushKey(recordKey);
        }
        if (recordKey != nullptr)
        {
            ::RegCloseKey(recordKey);
        }
        if (stateResult != ERROR_SUCCESS)
        {
            const LONG rollbackResult = MoveFileWithoutOverwrite(record.originalPath, record.parkedPath);
            ks::startup::ActionResult failure = MakeActionResult(
                rollbackResult == ERROR_SUCCESS
                    ? StatusFromWin32(static_cast<DWORD>(stateResult), ks::startup::StartupActionStatus::WriteFailed)
                    : ks::startup::StartupActionStatus::RollbackFailed,
                false,
                false,
                rollbackResult == ERROR_SUCCESS ? static_cast<DWORD>(stateResult) : static_cast<DWORD>(rollbackResult),
                rollbackResult == ERROR_SUCCESS
                    ? FromWide(L"恢复元数据提交失败；文件已移回暂存位置。")
                    : FromWide(L"恢复元数据提交失败，且文件回滚失败。"));
            failure.rollbackAttempted = true;
            failure.rollbackSucceeded = rollbackResult == ERROR_SUCCESS;
            return failure;
        }

        const LONG cleanupResult = DeleteMetadataRecord(
            metadataHive,
            kStartupFolderBackupRoot,
            backupId);
        ::RemoveDirectoryW(std::filesystem::path(record.parkedPath).parent_path().c_str());
        return MakeActionResult(
            ks::startup::StartupActionStatus::Success,
            true,
            true,
            cleanupResult == ERROR_SUCCESS ? ERROR_SUCCESS : static_cast<DWORD>(cleanupResult),
            cleanupResult == ERROR_SUCCESS
                ? FromWide(L"启动文件夹文件已恢复，暂存元数据已移除。")
                : FromWide(L"启动文件夹文件已恢复，但无法移除已退役的暂存元数据。"));
    }

    void AppendDisabledStartupFolderEntries(std::vector<ks::startup::StartupEntry>& entries)
    {
        const std::array<HKEY, 2> metadataHives{ HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
        for (const HKEY metadataHive : metadataHives)
        {
            const std::string metadataScope = metadataHive == HKEY_LOCAL_MACHINE ? "HKLM" : "HKCU";
            for (const std::wstring& backupId : EnumerateRegistrySubKeys(metadataHive, kStartupFolderBackupRoot))
            {
                StartupFolderBackupRecord record;
                DWORD readError = ERROR_SUCCESS;
                if (!ReadStartupFolderBackupById(metadataHive, backupId, record, readError))
                {
                    ks::startup::StartupEntry invalidEntry;
                    invalidEntry.category = ks::startup::StartupCategory::Logon;
                    invalidEntry.categoryText = ks::startup::CategoryToText(invalidEntry.category);
                    invalidEntry.itemNameText = FromWide(L"KSword 启动文件恢复记录 ") + FromWide(backupId);
                    invalidEntry.detailText =
                        metadataScope + "|" + FromWide(L"KSword 暂存记录=") + FromWide(backupId);
                    invalidEntry.sourceTypeText = "StartupFolderBackup";
                    invalidEntry.enabled = false;
                    invalidEntry.uniqueIdText =
                        "STARTUPFOLDER-RECOVERY-INVALID|" + metadataScope + "|" + FromWide(backupId);
                    invalidEntry.lastErrorCode = readError;
                    MarkEntryActionUnavailable(
                        invalidEntry,
                        ks::startup::StartupRiskLevel::Critical,
                        "backup_record",
                        FromWide(L"启动文件夹恢复元数据损坏、版本不受支持，或元数据完整性范围与目标不匹配。"));
                    entries.push_back(std::move(invalidEntry));
                    continue;
                }
            FileIdentitySnapshot originalIdentity;
            FileIdentitySnapshot parkedIdentity;
            DWORD originalError = ERROR_SUCCESS;
            DWORD parkedError = ERROR_SUCCESS;
            const bool originalExists = QueryFileIdentityNoReparse(
                record.originalPath,
                originalIdentity,
                originalError);
            const bool parkedExists = QueryFileIdentityNoReparse(
                record.parkedPath,
                parkedIdentity,
                parkedError);
            bool machineWide = false;
            IsKnownStartupFolderFile(record.originalPath, &machineWide);
            DWORD reconciliationError = ERROR_SUCCESS;
            if (record.state == kBackupStatePrepared)
            {
                if (originalExists && !parkedExists
                    && (parkedError == ERROR_FILE_NOT_FOUND || parkedError == ERROR_PATH_NOT_FOUND))
                {
                    CleanupStartupFolderBackupArtifacts(record);
                    StartupFolderBackupRecord remainingRecord;
                    DWORD remainingError = ERROR_SUCCESS;
                    if (!ReadStartupFolderBackupById(
                            metadataHive,
                            backupId,
                            remainingRecord,
                            remainingError)
                        && remainingError == ERROR_FILE_NOT_FOUND)
                    {
                        continue;
                    }
                    reconciliationError = remainingError == ERROR_SUCCESS
                        ? ERROR_CANNOT_MAKE
                        : remainingError;
                }
                else if (!originalExists && parkedExists
                    && (originalError == ERROR_FILE_NOT_FOUND || originalError == ERROR_PATH_NOT_FOUND))
                {
                    reconciliationError = static_cast<DWORD>(
                        CommitMetadataStateById(
                            metadataHive,
                            kStartupFolderBackupRoot,
                            backupId,
                            kBackupStateDisabled));
                    if (reconciliationError == ERROR_SUCCESS)
                    {
                        record.state = kBackupStateDisabled;
                    }
                }
            }

            ks::startup::StartupEntry entry;
            entry.category = ks::startup::StartupCategory::Logon;
            entry.categoryText = ks::startup::CategoryToText(entry.category);
            entry.itemNameText = record.itemName.empty()
                ? FromWide(std::filesystem::path(record.originalPath).filename().wstring())
                : FromWide(record.itemName);
            entry.commandText = ToNativeSeparators(FromWide(record.originalPath));
            entry.imagePathText = ToNativeSeparators(FromWide(record.parkedPath));
            entry.publisherText = parkedExists
                ? ks::startup::QueryPublisherTextByPath(entry.imagePathText)
                : std::string();
            entry.locationText = ToNativeSeparators(FromWide(std::filesystem::path(record.originalPath).parent_path().wstring()));
            entry.userText = machineWide ? FromWide(L"\u672c\u673a") : FromWide(L"\u5f53\u524d\u7528\u6237");
            entry.sourceTypeText = "StartupFolder";
            entry.detailText =
                metadataScope + "|" + FromWide(L"KSword 暂存=") + FromWide(record.parkedPath);
            entry.enabled = false;
            entry.canOpenFileLocation = parkedExists;
            entry.canDelete = false;
            entry.imagePathExists = parkedExists;
            entry.uniqueIdText =
                "STARTUPFOLDER-RECOVERY|" + metadataScope + "|" + FromWide(backupId);
            entry.lastErrorCode = reconciliationError != ERROR_SUCCESS
                ? reconciliationError
                : (!originalExists && originalError != ERROR_FILE_NOT_FOUND
                    && originalError != ERROR_PATH_NOT_FOUND
                    ? originalError
                    : (!parkedExists && parkedError != ERROR_FILE_NOT_FOUND
                        && parkedError != ERROR_PATH_NOT_FOUND
                        ? parkedError
                        : ERROR_SUCCESS));
            std::string reasonCode = machineWide ? "machine_scope" : "backup_record";
            std::string reasonText;
            if (machineWide)
            {
                reasonText = FromWide(L"恢复公共启动文件夹中的文件需要管理员权限，并会影响所有用户。");
            }
            else if (record.state == kBackupStatePrepared && originalExists && !parkedExists)
            {
                reasonText = FromWide(L"Prepared 操作尚未发生，但安全清理暂存记录失败；记录保持可见。");
            }
            else if (record.state == kBackupStatePrepared && !originalExists && parkedExists)
            {
                reasonText = FromWide(L"Prepared 记录对应文件已被暂存，但提交 Disabled 状态失败；记录保持可见。");
            }
            else if (originalExists && parkedExists)
            {
                reasonText = FromWide(L"原位置与暂存位置同时存在文件；恢复操作会拒绝覆盖原位置文件。");
            }
            else if (originalExists)
            {
                reasonText = FromWide(L"原位置已存在文件；恢复操作会拒绝覆盖该文件。");
            }
            else if (!parkedExists)
            {
                reasonText = FromWide(L"原位置与暂存位置均无可验证普通文件；恢复操作预计会失败。");
            }
            else
            {
                reasonText = FromWide(L"暂存记录已完成对账；警告确认后可以将文件移回启动文件夹。");
            }
            if (record.state == kBackupStateDisabled)
            {
                entry.actionKind = ks::startup::StartupActionKind::StartupFolderFile;
                entry.actionLocator.originalFilePathText =
                    ToNativeSeparators(FromWide(record.originalPath));
                entry.actionLocator.parkedFilePathText =
                    ToNativeSeparators(FromWide(record.parkedPath));
                entry.actionLocator.backupIdText = FromWide(backupId);
                entry.canEnable = true;
                entry.canDisable = false;
                entry.riskLevel = machineWide
                    ? ks::startup::StartupRiskLevel::Critical
                    : ks::startup::StartupRiskLevel::Elevated;
                entry.riskReasonCode = reasonCode;
                entry.riskReasonText = reasonText;
            }
            else
            {
                MarkEntryActionUnavailable(
                    entry,
                    ks::startup::StartupRiskLevel::Critical,
                    reasonCode,
                    reasonText);
            }
            entries.push_back(std::move(entry));
            }
        }
    }
}

namespace
{
    std::wstring QuotePowerShellLiteral(const std::wstring& text)
    {
        std::wstring escaped;
        escaped.reserve(text.size() + 2);
        escaped.push_back(L'\'');
        for (const wchar_t ch : text)
        {
            escaped.push_back(ch);
            if (ch == L'\'')
            {
                escaped.push_back(L'\'');
            }
        }
        escaped.push_back(L'\'');
        return escaped;
    }

    bool IsValidScheduledTaskLocator(const std::wstring& taskPath, const std::wstring& taskName)
    {
        const auto containsWildcard = [](const std::wstring& text) {
            return text.find_first_of(L"*?[]") != std::wstring::npos;
        };
        return !taskPath.empty()
            && taskPath.front() == L'\\'
            && taskPath.back() == L'\\'
            && taskPath.find(L'\0') == std::wstring::npos
            && !containsWildcard(taskPath)
            && !taskName.empty()
            && taskName.find(L'\0') == std::wstring::npos
            && taskName.find(L'\\') == std::wstring::npos
            && !containsWildcard(taskName);
    }

    std::wstring TaskIdentityPowerShellFunction()
    {
        return LR"PS(
$ProgressPreference='SilentlyContinue'
function Get-KSwordTaskIdentityHash($task) {
  [xml]$document = [string](ScheduledTasks\Export-ScheduledTask -InputObject $task -ErrorAction Stop)
  $enabledNode = $document.SelectSingleNode("/*[local-name()='Task']/*[local-name()='Settings']/*[local-name()='Enabled']")
  if ($null -ne $enabledNode) { $null = $enabledNode.ParentNode.RemoveChild($enabledNode) }
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    return [BitConverter]::ToString(
      $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($document.OuterXml))
    ).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}
function Get-KSwordTaskEnabled($task) {
  if ($null -ne $task.Settings -and $null -ne $task.Settings.Enabled) {
    return [bool]$task.Settings.Enabled
  }
  return ([string]$task.State -ne 'Disabled')
}
function Test-KSwordBootOrLogon($task) {
  $kinds = @($task.Triggers | ForEach-Object { $_.CimClass.CimClassName })
  return @($kinds | Where-Object {
    $_ -eq 'MSFT_TaskBootTrigger' -or $_ -eq 'MSFT_TaskLogonTrigger'
  }).Count -gt 0
}
)PS";
    }

    std::wstring BuildSetTaskEnabledPowerShellScript(
        const std::wstring& taskPath,
        const std::wstring& taskName,
        const std::wstring& expectedHash,
        const bool enabled)
    {
        std::wstring script = LR"PS(
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
)PS";
        script += TaskIdentityPowerShellFunction();
        script += LR"PS(
$taskPath = )PS";
        script += QuotePowerShellLiteral(taskPath);
        script += L"\n$taskName = ";
        script += QuotePowerShellLiteral(taskName);
        script += L"\n$expectedHash = ";
        script += QuotePowerShellLiteral(expectedHash);
        script += L"\n$hasExpectedHash = -not [string]::IsNullOrWhiteSpace($expectedHash)";
        script += L"\n$desiredEnabled = ";
        script += enabled ? L"$true\n" : L"$false\n";
        script += LR"PS(
try {
$scheduledTasksModule = Join-Path $PSHOME 'Modules\ScheduledTasks\ScheduledTasks.psd1'
Microsoft.PowerShell.Core\Import-Module -Name $scheduledTasksModule -Force -ErrorAction Stop
$task = ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
if (-not (Test-KSwordBootOrLogon $task)) { 'KSWORD_UNSUPPORTED'; exit 12 }
if ($hasExpectedHash -and (Get-KSwordTaskIdentityHash $task) -ne $expectedHash) { 'KSWORD_STALE'; exit 13 }
$currentEnabled = Get-KSwordTaskEnabled $task
if ($currentEnabled -eq $desiredEnabled) { 'KSWORD_NO_CHANGE'; exit 0 }
if ($currentEnabled) { 'KSWORD_ORIGINAL_ENABLED' } else { 'KSWORD_ORIGINAL_DISABLED' }
'KSWORD_MUTATION_ATTEMPTED'
[Console]::Out.Flush()
if ($desiredEnabled) {
  ScheduledTasks\Enable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
} else {
  ScheduledTasks\Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
}
$verifyTask = ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
if (-not (Test-KSwordBootOrLogon $verifyTask)) { throw 'KSWORD_VERIFY_TRIGGER' }
if ($hasExpectedHash -and (Get-KSwordTaskIdentityHash $verifyTask) -ne $expectedHash) { throw 'KSWORD_VERIFY_HASH' }
if ((Get-KSwordTaskEnabled $verifyTask) -ne $desiredEnabled) { throw 'KSWORD_VERIFY_STATE' }
'KSWORD_CHANGED'
} catch {
  $hresult = [int]$_.Exception.HResult
  $accessDenied = ($_.Exception -is [System.UnauthorizedAccessException]) -or
    ($hresult -eq -2147024891) -or
    ([string]$_.FullyQualifiedErrorId -match 'AccessDenied|UnauthorizedAccess')
  if ($accessDenied) { 'KSWORD_ACCESS_DENIED'; exit 5 }
  'KSWORD_TASK_ERROR'
  exit 1
}
)PS";
        return script;
    }

    std::wstring BuildRecoverTaskStatePowerShellScript(
        const std::wstring& taskPath,
        const std::wstring& taskName,
        const std::wstring& expectedHash,
        const bool originalEnabled)
    {
        std::wstring script = LR"PS(
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
)PS";
        script += TaskIdentityPowerShellFunction();
        script += LR"PS(
$taskPath = )PS";
        script += QuotePowerShellLiteral(taskPath);
        script += L"\n$taskName = ";
        script += QuotePowerShellLiteral(taskName);
        script += L"\n$expectedHash = ";
        script += QuotePowerShellLiteral(expectedHash);
        script += L"\n$hasExpectedHash = -not [string]::IsNullOrWhiteSpace($expectedHash)";
        script += L"\n$originalEnabled = ";
        script += originalEnabled ? L"$true\n" : L"$false\n";
        script += LR"PS(
try {
  $scheduledTasksModule = Join-Path $PSHOME 'Modules\ScheduledTasks\ScheduledTasks.psd1'
  Microsoft.PowerShell.Core\Import-Module -Name $scheduledTasksModule -Force -ErrorAction Stop
  $task = ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
  if (-not (Test-KSwordBootOrLogon $task)) { 'KSWORD_ROLLBACK_BLOCKED'; exit 21 }
  if ($hasExpectedHash -and (Get-KSwordTaskIdentityHash $task) -ne $expectedHash) { 'KSWORD_ROLLBACK_BLOCKED'; exit 22 }
  if ((Get-KSwordTaskEnabled $task) -eq $originalEnabled) {
    'KSWORD_ROLLBACK_NOT_NEEDED'
    exit 0
  }
  if ($originalEnabled) {
    ScheduledTasks\Enable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
  } else {
    ScheduledTasks\Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
  }
  $verifyTask = ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
  if (-not (Test-KSwordBootOrLogon $verifyTask)) { throw 'KSWORD_ROLLBACK_TRIGGER' }
  if ($hasExpectedHash -and (Get-KSwordTaskIdentityHash $verifyTask) -ne $expectedHash) { throw 'KSWORD_ROLLBACK_HASH' }
  if ((Get-KSwordTaskEnabled $verifyTask) -ne $originalEnabled) { throw 'KSWORD_ROLLBACK_STATE' }
  'KSWORD_ROLLBACK_OK'
} catch {
  'KSWORD_ROLLBACK_FAILED'
  exit 23
}
)PS";
        return script;
    }

    std::wstring BuildDeleteTaskPowerShellScript(
        const std::wstring& taskPath,
        const std::wstring& taskName,
        const std::wstring& expectedHash)
    {
        std::wstring script = LR"PS(
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
)PS";
        script += TaskIdentityPowerShellFunction();
        script += LR"PS(
function Test-KSwordTaskNotFoundError($record) {
  $hresult = [int]$record.Exception.HResult
  $errorId = [string]$record.FullyQualifiedErrorId
  return ($hresult -eq -2147024894) -or
    ($hresult -eq -2147024893) -or
    ($errorId -match 'NoMatchingMSFT_Task|CmdletizationQuery_NotFound|ObjectNotFound')
}
$taskPath = )PS";
        script += QuotePowerShellLiteral(taskPath);
        script += L"\n$taskName = ";
        script += QuotePowerShellLiteral(taskName);
        script += L"\n$expectedHash = ";
        script += QuotePowerShellLiteral(expectedHash);
        script += LR"PS(
$hasExpectedHash = -not [string]::IsNullOrWhiteSpace($expectedHash)
try {
  $scheduledTasksModule = Join-Path $PSHOME 'Modules\ScheduledTasks\ScheduledTasks.psd1'
  Microsoft.PowerShell.Core\Import-Module -Name $scheduledTasksModule -Force -ErrorAction Stop
  try {
    $tasks = @(ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop)
  } catch {
    if (Test-KSwordTaskNotFoundError $_) { 'KSWORD_TASK_NOT_FOUND'; exit 0 }
    throw
  }
  if ($tasks.Count -eq 0) { 'KSWORD_TASK_NOT_FOUND'; exit 0 }
  if ($tasks.Count -ne 1) { 'KSWORD_TASK_AMBIGUOUS'; exit 14 }
  $task = $tasks[0]
  if (-not (Test-KSwordBootOrLogon $task)) { 'KSWORD_UNSUPPORTED'; exit 12 }
  if ($hasExpectedHash -and (Get-KSwordTaskIdentityHash $task) -ne $expectedHash) {
    'KSWORD_STALE'
    exit 13
  }
  ScheduledTasks\Unregister-ScheduledTask -InputObject $task -Confirm:$false -ErrorAction Stop
  try {
    $remaining = @(ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop)
  } catch {
    if (Test-KSwordTaskNotFoundError $_) { 'KSWORD_TASK_DELETED'; exit 0 }
    throw
  }
  if ($remaining.Count -eq 0) { 'KSWORD_TASK_DELETED'; exit 0 }
  throw 'KSWORD_TASK_VERIFY'
} catch {
  $hresult = [int]$_.Exception.HResult
  $accessDenied = ($_.Exception -is [System.UnauthorizedAccessException]) -or
    ($hresult -eq -2147024891) -or
    ([string]$_.FullyQualifiedErrorId -match 'AccessDenied|UnauthorizedAccess')
  if ($accessDenied) { 'KSWORD_ACCESS_DENIED'; exit 5 }
  'KSWORD_TASK_ERROR'
  exit 1
}
)PS";
        return script;
    }

    bool QueryScmStartType(SC_HANDLE serviceHandle, DWORD& startTypeOut)
    {
        startTypeOut = SERVICE_NO_CHANGE;
        DWORD requiredBytes = 0;
        ::QueryServiceConfigW(serviceHandle, nullptr, 0, &requiredBytes);
        if (requiredBytes == 0)
        {
            return false;
        }
        std::vector<std::uint8_t> buffer(requiredBytes);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
        if (::QueryServiceConfigW(serviceHandle, config, requiredBytes, &requiredBytes) == FALSE)
        {
            return false;
        }
        startTypeOut = config->dwStartType;
        return true;
    }

    ks::startup::ActionResult SetScmEntryEnabled(
        const ks::startup::StartupEntry& entry,
        const bool enabled)
    {
        const std::wstring serviceName = ToWide(entry.actionLocator.serviceNameText);
        if (serviceName.empty()
            || serviceName.find(L'\0') != std::wstring::npos
            || serviceName.find_first_of(L"\\/") != std::wstring::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"服务控制管理器定位器无效。"));
        }

        SC_HANDLE scmHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (scmHandle == nullptr)
        {
            const DWORD errorCode = ::GetLastError();
            return MakeActionResult(
                StatusFromWin32(errorCode, ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                errorCode,
                FromWide(L"无法打开服务控制管理器。"));
        }
        SC_HANDLE serviceHandle = ::OpenServiceW(
            scmHandle,
            serviceName.c_str(),
            SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);
        if (serviceHandle == nullptr)
        {
            const DWORD errorCode = ::GetLastError();
            ::CloseServiceHandle(scmHandle);
            return MakeActionResult(
                StatusFromWin32(errorCode, ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                errorCode,
                FromWide(L"无法打开目标服务或驱动。"));
        }

        DWORD currentStartType = SERVICE_NO_CHANGE;
        if (!QueryScmStartType(serviceHandle, currentStartType))
        {
            const DWORD errorCode = ::GetLastError();
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            return MakeActionResult(
                StatusFromWin32(errorCode, ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                errorCode,
                FromWide(L"无法读取当前服务启动类型。"));
        }
        if (currentStartType != entry.actionLocator.serviceStartType)
        {
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                FromWide(L"服务启动类型已在枚举后变化；请刷新后重试。"));
        }

        const DWORD desiredStartType = enabled
            ? (entry.actionLocator.serviceIsDriver ? SERVICE_SYSTEM_START : SERVICE_AUTO_START)
            : SERVICE_DISABLED;
        if (currentStartType == desiredStartType)
        {
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            return MakeActionResult(
                ks::startup::StartupActionStatus::NoChange,
                true,
                false,
                ERROR_SUCCESS,
                FromWide(L"服务启动类型已经处于请求的状态。"));
        }

        if (::ChangeServiceConfigW(
                serviceHandle,
                SERVICE_NO_CHANGE,
                desiredStartType,
                SERVICE_NO_CHANGE,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr) == FALSE)
        {
            const DWORD errorCode = ::GetLastError();
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            return MakeActionResult(
                StatusFromWin32(errorCode, ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                errorCode,
                FromWide(L"修改服务启动类型失败。"));
        }

        DWORD observedStartType = SERVICE_NO_CHANGE;
        const bool querySucceeded = QueryScmStartType(serviceHandle, observedStartType);
        const DWORD observedError = querySucceeded ? ERROR_INVALID_DATA : ::GetLastError();
        const bool verified = querySucceeded && observedStartType == desiredStartType;
        if (!verified)
        {
            const DWORD verificationError = observedError == ERROR_SUCCESS
                ? ERROR_INVALID_DATA
                : observedError;
            const bool rollbackSucceeded = ::ChangeServiceConfigW(
                serviceHandle,
                SERVICE_NO_CHANGE,
                currentStartType,
                SERVICE_NO_CHANGE,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr) != FALSE;
            const DWORD rollbackError = rollbackSucceeded ? ERROR_SUCCESS : ::GetLastError();
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            ks::startup::ActionResult failure = MakeActionResult(
                rollbackSucceeded
                    ? ks::startup::StartupActionStatus::VerificationFailed
                    : ks::startup::StartupActionStatus::RollbackFailed,
                false,
                !rollbackSucceeded,
                rollbackSucceeded ? verificationError : rollbackError,
                rollbackSucceeded
                    ? FromWide(L"服务启动类型验证失败；已恢复操作前配置。")
                    : FromWide(L"服务启动类型验证失败，且无法恢复操作前配置。"));
            failure.rollbackAttempted = true;
            failure.rollbackSucceeded = rollbackSucceeded;
            return failure;
        }

        ::CloseServiceHandle(serviceHandle);
        ::CloseServiceHandle(scmHandle);
        return MakeActionResult(
            ks::startup::StartupActionStatus::Success,
            true,
            true,
            ERROR_SUCCESS,
            FromWide(L"服务启动类型已变更并验证。"));
    }

    bool IsAllowedWmiClassName(const std::string& className)
    {
        static const std::array<const char*, 6> allowedClassNames{ {
            "CommandLineEventConsumer",
            "ActiveScriptEventConsumer",
            "LogFileEventConsumer",
            "NTEventLogEventConsumer",
            "__EventFilter",
            "__FilterToConsumerBinding"
        } };
        return std::any_of(
            allowedClassNames.begin(),
            allowedClassNames.end(),
            [&className](const char* allowedName) { return className == allowedName; });
    }

    std::wstring BuildRemoveWmiEntryPowerShellScript(
        const ks::startup::StartupActionLocator& locator)
    {
        std::wstring script = LR"PS(
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$cimCmdletsModule = Join-Path $PSHOME 'Modules\CimCmdlets\CimCmdlets.psd1'
Microsoft.PowerShell.Core\Import-Module -Name $cimCmdletsModule -Force -ErrorAction Stop
$className = )PS";
        script += QuotePowerShellLiteral(ToWide(locator.wmiClassNameText));
        script += L"\n$name = ";
        script += QuotePowerShellLiteral(ToWide(locator.wmiNameText));
        script += L"\n$filterPath = ";
        script += QuotePowerShellLiteral(ToWide(locator.wmiFilterText));
        script += L"\n$consumerPath = ";
        script += QuotePowerShellLiteral(ToWide(locator.wmiConsumerText));
        script += LR"PS(
try {
  $allItems = @(CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName $className -ErrorAction Stop)
  if ($className -eq '__FilterToConsumerBinding') {
    $matches = @($allItems | Where-Object {
      ([string]$_.Filter -eq $filterPath) -and ([string]$_.Consumer -eq $consumerPath)
    })
  } else {
    $matches = @($allItems | Where-Object { [string]$_.Name -eq $name })
  }
  if ($matches.Count -eq 0) { 'KSWORD_WMI_NO_CHANGE'; exit 0 }
  if ($matches.Count -ne 1) { 'KSWORD_WMI_AMBIGUOUS'; exit 14 }
  $matches[0] | CimCmdlets\Remove-CimInstance -ErrorAction Stop
  $verifyItems = @(CimCmdlets\Get-CimInstance -Namespace root/subscription -ClassName $className -ErrorAction Stop)
  if ($className -eq '__FilterToConsumerBinding') {
    $remaining = @($verifyItems | Where-Object {
      ([string]$_.Filter -eq $filterPath) -and ([string]$_.Consumer -eq $consumerPath)
    })
  } else {
    $remaining = @($verifyItems | Where-Object { [string]$_.Name -eq $name })
  }
  if ($remaining.Count -ne 0) { throw 'KSWORD_WMI_VERIFY' }
  'KSWORD_WMI_REMOVED'
} catch {
  $hresult = [int]$_.Exception.HResult
  $accessDenied = ($_.Exception -is [System.UnauthorizedAccessException]) -or
    ($hresult -eq -2147024891) -or
    ([string]$_.FullyQualifiedErrorId -match 'AccessDenied|UnauthorizedAccess')
  if ($accessDenied) { 'KSWORD_ACCESS_DENIED'; exit 5 }
  'KSWORD_WMI_ERROR'
  exit 1
}
)PS";
        return script;
    }

    ks::startup::ActionResult RemoveWmiEntry(
        const ks::startup::StartupEntry& entry,
        const bool enabled)
    {
        if (enabled)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::NotSupported,
                false,
                false,
                ERROR_NOT_SUPPORTED,
                FromWide(L"WMI 对象删除后无法由 KSword 自动重建。"));
        }
        if (!IsAllowedWmiClassName(entry.actionLocator.wmiClassNameText))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"WMI 修改定位器无效。"));
        }
        const ProcessOutput output = RunPowerShellScript(
            BuildRemoveWmiEntryPowerShellScript(entry.actionLocator),
            20000);
        const std::string stdoutText = StripUtf8Bom(ks::str::TrimCopy(output.stdoutText));
        if (output.started && output.finished && output.exitCode == 0
            && stdoutText.find("KSWORD_WMI_NO_CHANGE") != std::string::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::NoChange,
                true,
                false,
                ERROR_SUCCESS,
                FromWide(L"WMI 对象已经不存在。"));
        }
        if (output.started && output.finished && output.exitCode == 0
            && stdoutText.find("KSWORD_WMI_REMOVED") != std::string::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Success,
                true,
                true,
                ERROR_SUCCESS,
                FromWide(L"WMI 永久事件对象已删除并验证。"));
        }
        if (stdoutText.find("KSWORD_WMI_AMBIGUOUS") != std::string::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_DUP_NAME,
                FromWide(L"存在多个匹配的 WMI 对象；为避免误删，未执行修改。"));
        }
        const bool accessDenied =
            stdoutText.find("KSWORD_ACCESS_DENIED") != std::string::npos;
        const DWORD errorCode = accessDenied
            ? ERROR_ACCESS_DENIED
            : ProcessFailureCode(output);
        return MakeActionResult(
            accessDenied
                ? ks::startup::StartupActionStatus::AccessDenied
                : ks::startup::StartupActionStatus::ProcessFailed,
            false,
            false,
            errorCode,
            FromWide(L"删除 WMI 永久事件对象失败。"));
    }

    ks::startup::ActionResult SetScheduledTaskEnabled(
        const ks::startup::StartupEntry& entry,
        const bool enabled)
    {
        const std::wstring taskPath = ToWide(entry.actionLocator.taskPathText);
        const std::wstring taskName = ToWide(entry.actionLocator.taskNameText);
        const std::wstring expectedHash =
            ToWide(LowerAsciiCopy(entry.actionLocator.taskDefinitionSha256Text));
        const bool hashProvided = !expectedHash.empty();
        const bool validHash = expectedHash.size() == 64
            && std::all_of(expectedHash.begin(), expectedHash.end(), [](const wchar_t ch) {
                return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f');
            });
        if (!IsValidScheduledTaskLocator(taskPath, taskName) || (hashProvided && !validHash))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"计划任务定位器无效。"));
        }
        const ProcessOutput output = RunPowerShellScript(
            BuildSetTaskEnabledPowerShellScript(taskPath, taskName, expectedHash, enabled),
            20000);
        const std::string stdoutText = StripUtf8Bom(ks::str::TrimCopy(output.stdoutText));
        if (output.started && output.finished && output.exitCode == 0
            && stdoutText.find("KSWORD_NO_CHANGE") != std::string::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::NoChange,
                true,
                false,
                ERROR_SUCCESS,
                FromWide(L"计划任务已经处于请求的状态。"));
        }
        if (output.started && output.finished && output.exitCode == 0
            && stdoutText.find("KSWORD_CHANGED") != std::string::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Success,
                true,
                true,
                ERROR_SUCCESS,
                FromWide(L"Windows 任务计划程序已变更并校验任务状态。"));
        }
        if (stdoutText.find("KSWORD_STALE") != std::string::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                FromWide(L"计划任务定义已在枚举后变化；未修改陈旧对象。"));
        }
        if (stdoutText.find("KSWORD_UNSUPPORTED") != std::string::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_NOT_SUPPORTED,
                FromWide(L"计划任务已不再包含 Boot 或 Logon 触发器；请刷新启动项列表。"));
        }

        const bool accessDenied =
            stdoutText.find("KSWORD_ACCESS_DENIED") != std::string::npos;
        const DWORD errorCode = accessDenied
            ? ERROR_ACCESS_DENIED
            : ProcessFailureCode(output);
        ks::startup::ActionResult failure = MakeActionResult(
            accessDenied
                ? ks::startup::StartupActionStatus::AccessDenied
                : ks::startup::StartupActionStatus::ProcessFailed,
            false,
            false,
            errorCode,
            FromWide(L"计划任务状态变更失败。"));
        const bool mutationAttempted =
            stdoutText.find("KSWORD_MUTATION_ATTEMPTED") != std::string::npos;
        const bool originalEnabled =
            stdoutText.find("KSWORD_ORIGINAL_ENABLED") != std::string::npos;
        const bool originalDisabled =
            stdoutText.find("KSWORD_ORIGINAL_DISABLED") != std::string::npos;
        if (!mutationAttempted || originalEnabled == originalDisabled)
        {
            return failure;
        }

        const ProcessOutput recoveryOutput = RunPowerShellScript(
            BuildRecoverTaskStatePowerShellScript(
                taskPath,
                taskName,
                expectedHash,
                originalEnabled),
            20000);
        const std::string recoveryText =
            StripUtf8Bom(ks::str::TrimCopy(recoveryOutput.stdoutText));
        failure.messageText =
            FromWide(L"计划任务状态变更失败；后端已使用独立进程重查原状态。");
        if (recoveryOutput.started && recoveryOutput.finished
            && recoveryOutput.exitCode == 0
            && recoveryText.find("KSWORD_ROLLBACK_NOT_NEEDED") != std::string::npos)
        {
            return failure;
        }
        failure.rollbackAttempted = true;
        failure.rollbackSucceeded = recoveryOutput.started
            && recoveryOutput.finished
            && recoveryOutput.exitCode == 0
            && recoveryText.find("KSWORD_ROLLBACK_OK") != std::string::npos;
        if (!failure.rollbackSucceeded)
        {
            failure.status = ks::startup::StartupActionStatus::RollbackFailed;
            failure.changed = true;
            failure.errorCode = ProcessFailureCode(recoveryOutput);
            failure.messageText =
                FromWide(L"计划任务状态变更失败，且独立恢复无法确认已回到原状态。");
        }
        return failure;
    }

    bool IsMissingStartupSourceError(const DWORD errorCode)
    {
        return errorCode == ERROR_FILE_NOT_FOUND
            || errorCode == ERROR_PATH_NOT_FOUND
            || errorCode == ERROR_KEY_DELETED
            || errorCode == ERROR_SERVICE_DOES_NOT_EXIST;
    }

    ks::startup::ActionResult DeleteStartupFolderFile(
        const ks::startup::StartupEntry& entry)
    {
        const std::wstring pathText = ToWide(entry.actionLocator.originalFilePathText);
        if (pathText.empty()
            || !entry.actionLocator.parkedFilePathText.empty()
            || !IsKnownStartupFolderFile(pathText))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"启动文件删除定位器无效。"));
        }

        HANDLE fileHandle = ::CreateFileW(
            pathText.c_str(),
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            const DWORD errorCode = ::GetLastError();
            if (IsMissingStartupSourceError(errorCode))
            {
                return MakeActionResult(
                    ks::startup::StartupActionStatus::NoChange,
                    true,
                    false,
                    ERROR_SUCCESS,
                    FromWide(L"启动文件已经不存在。"));
            }
            return MakeActionResult(
                StatusFromWin32(errorCode, ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                errorCode,
                FromWide(L"无法打开要永久删除的启动文件。"));
        }

        BY_HANDLE_FILE_INFORMATION information{};
        if (::GetFileInformationByHandle(fileHandle, &information) == FALSE)
        {
            const DWORD errorCode = ::GetLastError();
            ::CloseHandle(fileHandle);
            return MakeActionResult(
                StatusFromWin32(errorCode, ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                errorCode,
                FromWide(L"无法读取启动文件身份。"));
        }
        if ((information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
            || (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            ::CloseHandle(fileHandle);
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_REPARSE_TAG_INVALID,
                FromWide(L"启动文件已变成目录或重解析点；未执行删除。"));
        }

        ULARGE_INTEGER fileIndex{};
        fileIndex.HighPart = information.nFileIndexHigh;
        fileIndex.LowPart = information.nFileIndexLow;
        ULARGE_INTEGER fileSize{};
        fileSize.HighPart = information.nFileSizeHigh;
        fileSize.LowPart = information.nFileSizeLow;
        ULARGE_INTEGER lastWriteTime{};
        lastWriteTime.HighPart = information.ftLastWriteTime.dwHighDateTime;
        lastWriteTime.LowPart = information.ftLastWriteTime.dwLowDateTime;
        if (entry.actionLocator.fileIdentitySnapshotValid
            && (entry.actionLocator.fileVolumeSerial != information.dwVolumeSerialNumber
                || entry.actionLocator.fileIndex != fileIndex.QuadPart
                || entry.actionLocator.fileSize != fileSize.QuadPart
                || entry.actionLocator.fileLastWriteTime != lastWriteTime.QuadPart))
        {
            ::CloseHandle(fileHandle);
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                FromWide(L"启动文件已在枚举后被替换或修改；请刷新后重试。"));
        }

        FILE_DISPOSITION_INFO disposition{};
        disposition.DeleteFile = TRUE;
        if (::SetFileInformationByHandle(
                fileHandle,
                FileDispositionInfo,
                &disposition,
                sizeof(disposition)) == FALSE)
        {
            const DWORD errorCode = ::GetLastError();
            ::CloseHandle(fileHandle);
            return MakeActionResult(
                StatusFromWin32(errorCode, ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                errorCode,
                FromWide(L"无法永久删除启动文件。"));
        }
        ::CloseHandle(fileHandle);

        FileIdentitySnapshot remainingIdentity;
        DWORD verifyError = ERROR_SUCCESS;
        if (!QueryFileIdentityNoReparse(pathText, remainingIdentity, verifyError)
            && IsMissingStartupSourceError(verifyError))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Success,
                true,
                true,
                ERROR_SUCCESS,
                FromWide(L"启动文件已按句柄永久删除并验证。"));
        }
        return MakeActionResult(
            ks::startup::StartupActionStatus::VerificationFailed,
            false,
            true,
            verifyError == ERROR_SUCCESS ? ERROR_ALREADY_EXISTS : verifyError,
            FromWide(L"已提交启动文件删除，但无法确认目标路径保持不存在。"));
    }

    ks::startup::ActionResult DeleteRegistryValueEntry(
        const ks::startup::StartupEntry& entry)
    {
        const HKEY rootKey = NativeRegistryRoot(entry.actionLocator.registryRoot);
        const std::wstring subKey = ToWide(entry.actionLocator.registrySubKeyText);
        const std::wstring valueName = ToWide(entry.actionLocator.registryValueNameText);
        if (rootKey == nullptr
            || !IsSupportedRunLocation(rootKey, subKey)
            || !entry.actionLocator.backupIdText.empty())
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"注册表删除定位器无效。"));
        }

        DWORD expectedType = entry.actionLocator.registryValueType;
        std::vector<std::uint8_t> expectedData = entry.actionLocator.registryRawData;
        if (!entry.actionLocator.registryValueSnapshotValid)
        {
            const LONG queryResult = QueryRegistryValueRaw(
                rootKey,
                subKey,
                valueName,
                expectedType,
                expectedData);
            if (IsMissingStartupSourceError(static_cast<DWORD>(queryResult)))
            {
                return MakeActionResult(
                    ks::startup::StartupActionStatus::NoChange,
                    true,
                    false,
                    ERROR_SUCCESS,
                    FromWide(L"注册表启动值已经不存在。"));
            }
            if (queryResult != ERROR_SUCCESS)
            {
                return MakeActionResult(
                    StatusFromWin32(
                        static_cast<DWORD>(queryResult),
                        ks::startup::StartupActionStatus::WriteFailed),
                    false,
                    false,
                    static_cast<DWORD>(queryResult),
                    FromWide(L"无法读取要永久删除的注册表值。"));
            }
        }

        const LONG deleteResult = DeleteRegistryValueIfExact(
            rootKey,
            subKey,
            valueName,
            expectedType,
            expectedData);
        if (deleteResult == ERROR_SUCCESS)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Success,
                true,
                true,
                ERROR_SUCCESS,
                FromWide(L"注册表启动值已按原始数据快照永久删除并验证。"));
        }
        if (IsMissingStartupSourceError(static_cast<DWORD>(deleteResult)))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::NoChange,
                true,
                false,
                ERROR_SUCCESS,
                FromWide(L"注册表启动值已经不存在。"));
        }
        if (deleteResult == ERROR_ALREADY_EXISTS)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                FromWide(L"注册表值已在枚举后变化；未删除陈旧目标。"));
        }
        return MakeActionResult(
            StatusFromWin32(
                static_cast<DWORD>(deleteResult),
                ks::startup::StartupActionStatus::WriteFailed),
            false,
            false,
            static_cast<DWORD>(deleteResult),
            FromWide(L"无法永久删除注册表启动值。"));
    }

    ks::startup::ActionResult DeleteRegistryTreeEntry(
        const ks::startup::StartupEntry& entry)
    {
        const HKEY rootKey = NativeRegistryRoot(entry.actionLocator.registryRoot);
        const std::wstring subKey = ToWide(entry.actionLocator.registrySubKeyText);
        if (rootKey == nullptr
            || !IsSupportedRunLocation(rootKey, subKey)
            || !entry.actionLocator.backupIdText.empty())
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"注册表子树删除定位器无效。"));
        }

        ks::startup::StartupActionLocator currentSnapshot;
        const LONG snapshotResult = QueryRegistryTreeSnapshot(rootKey, subKey, currentSnapshot);
        if (IsMissingStartupSourceError(static_cast<DWORD>(snapshotResult)))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::NoChange,
                true,
                false,
                ERROR_SUCCESS,
                FromWide(L"注册表子树已经不存在。"));
        }
        if (snapshotResult != ERROR_SUCCESS)
        {
            return MakeActionResult(
                StatusFromWin32(
                    static_cast<DWORD>(snapshotResult),
                    ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                static_cast<DWORD>(snapshotResult),
                FromWide(L"无法读取要永久删除的注册表子树快照。"));
        }
        if (entry.actionLocator.registryTreeSnapshotValid
            && (entry.actionLocator.registryTreeSubKeyCount
                    != currentSnapshot.registryTreeSubKeyCount
                || entry.actionLocator.registryTreeValueCount
                    != currentSnapshot.registryTreeValueCount
                || entry.actionLocator.registryTreeLastWriteTime
                    != currentSnapshot.registryTreeLastWriteTime))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                FromWide(L"注册表子树已在枚举后变化；未删除陈旧目标。"));
        }

        const LONG deleteResult = ::RegDeleteTreeW(rootKey, subKey.c_str());
        if (IsMissingStartupSourceError(static_cast<DWORD>(deleteResult)))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::NoChange,
                true,
                false,
                ERROR_SUCCESS,
                FromWide(L"注册表子树已经不存在。"));
        }
        if (deleteResult != ERROR_SUCCESS)
        {
            return MakeActionResult(
                StatusFromWin32(
                    static_cast<DWORD>(deleteResult),
                    ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                static_cast<DWORD>(deleteResult),
                FromWide(L"无法永久删除注册表子树。"));
        }

        HKEY verifyKey = nullptr;
        const LONG verifyResult = ::RegOpenKeyExW(
            rootKey,
            subKey.c_str(),
            0,
            KEY_QUERY_VALUE,
            &verifyKey);
        if (verifyKey != nullptr)
        {
            ::RegCloseKey(verifyKey);
        }
        if (IsMissingStartupSourceError(static_cast<DWORD>(verifyResult)))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Success,
                true,
                true,
                ERROR_SUCCESS,
                FromWide(L"注册表子树已按结构化定位器永久删除并验证。"));
        }
        return MakeActionResult(
            ks::startup::StartupActionStatus::VerificationFailed,
            false,
            true,
            verifyResult == ERROR_SUCCESS
                ? ERROR_ALREADY_EXISTS
                : static_cast<DWORD>(verifyResult),
            FromWide(L"已提交注册表子树删除，但无法确认目标保持不存在。"));
    }

    bool QueryScmConfigurationSnapshot(
        SC_HANDLE serviceHandle,
        DWORD& serviceTypeOut,
        DWORD& startTypeOut,
        std::string& binaryPathTextOut,
        DWORD& errorCodeOut)
    {
        serviceTypeOut = 0;
        startTypeOut = SERVICE_NO_CHANGE;
        binaryPathTextOut.clear();
        errorCodeOut = ERROR_SUCCESS;
        DWORD requiredBytes = 0;
        ::QueryServiceConfigW(serviceHandle, nullptr, 0, &requiredBytes);
        if (requiredBytes == 0)
        {
            errorCodeOut = ::GetLastError();
            return false;
        }
        std::vector<std::uint8_t> buffer(requiredBytes);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
        if (::QueryServiceConfigW(
                serviceHandle,
                config,
                requiredBytes,
                &requiredBytes) == FALSE)
        {
            errorCodeOut = ::GetLastError();
            return false;
        }
        serviceTypeOut = config->dwServiceType;
        startTypeOut = config->dwStartType;
        binaryPathTextOut = QueryServiceBinaryPathText(*config);
        return true;
    }

    ks::startup::ActionResult DeleteScmEntry(
        const ks::startup::StartupEntry& entry)
    {
        const std::wstring serviceName = ToWide(entry.actionLocator.serviceNameText);
        if (serviceName.empty()
            || serviceName.find(L'\0') != std::wstring::npos
            || serviceName.find_first_of(L"\\/") != std::wstring::npos
            || entry.actionLocator.serviceType == 0)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"服务删除定位器无效。"));
        }

        SC_HANDLE scmHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (scmHandle == nullptr)
        {
            const DWORD errorCode = ::GetLastError();
            return MakeActionResult(
                StatusFromWin32(errorCode, ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                errorCode,
                FromWide(L"无法打开服务控制管理器。"));
        }
        SC_HANDLE serviceHandle = ::OpenServiceW(
            scmHandle,
            serviceName.c_str(),
            SERVICE_QUERY_CONFIG | DELETE);
        if (serviceHandle == nullptr)
        {
            const DWORD errorCode = ::GetLastError();
            ::CloseServiceHandle(scmHandle);
            if (IsMissingStartupSourceError(errorCode)
                || errorCode == ERROR_SERVICE_MARKED_FOR_DELETE)
            {
                return MakeActionResult(
                    ks::startup::StartupActionStatus::NoChange,
                    true,
                    false,
                    ERROR_SUCCESS,
                    FromWide(L"服务或驱动已经不存在，或已标记为删除。"));
            }
            return MakeActionResult(
                StatusFromWin32(errorCode, ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                errorCode,
                FromWide(L"无法打开要永久删除的服务或驱动。"));
        }

        DWORD currentServiceType = 0;
        DWORD currentStartType = SERVICE_NO_CHANGE;
        DWORD queryError = ERROR_SUCCESS;
        std::string currentBinaryPathText;
        if (!QueryScmConfigurationSnapshot(
                serviceHandle,
                currentServiceType,
                currentStartType,
                currentBinaryPathText,
                queryError))
        {
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            return MakeActionResult(
                StatusFromWin32(queryError, ks::startup::StartupActionStatus::WriteFailed),
                false,
                false,
                queryError,
                FromWide(L"无法读取服务或驱动配置快照。"));
        }
        if (currentServiceType != entry.actionLocator.serviceType
            || currentStartType != entry.actionLocator.serviceStartType
            || !EqualWideI(
                ToWide(currentBinaryPathText),
                ToWide(entry.actionLocator.serviceBinaryPathText)))
        {
            ::CloseServiceHandle(serviceHandle);
            ::CloseServiceHandle(scmHandle);
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                FromWide(L"服务或驱动配置已在枚举后变化；未删除陈旧目标。"));
        }

        const BOOL deleteOk = ::DeleteService(serviceHandle);
        const DWORD deleteError = deleteOk == FALSE ? ::GetLastError() : ERROR_SUCCESS;
        ::CloseServiceHandle(serviceHandle);
        ::CloseServiceHandle(scmHandle);
        if (deleteOk != FALSE)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Success,
                true,
                true,
                ERROR_SUCCESS,
                FromWide(L"服务或驱动已由原始 SCM 句柄标记为永久删除。"));
        }
        if (deleteError == ERROR_SERVICE_MARKED_FOR_DELETE
            || IsMissingStartupSourceError(deleteError))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::NoChange,
                true,
                false,
                ERROR_SUCCESS,
                FromWide(L"服务或驱动已经不存在，或已标记为删除。"));
        }
        return MakeActionResult(
            StatusFromWin32(deleteError, ks::startup::StartupActionStatus::WriteFailed),
            false,
            false,
            deleteError,
            FromWide(L"无法永久删除服务或驱动。"));
    }

    ks::startup::ActionResult DeleteScheduledTaskEntry(
        const ks::startup::StartupEntry& entry)
    {
        const std::wstring taskPath = ToWide(entry.actionLocator.taskPathText);
        const std::wstring taskName = ToWide(entry.actionLocator.taskNameText);
        const std::wstring expectedHash =
            ToWide(LowerAsciiCopy(entry.actionLocator.taskDefinitionSha256Text));
        const bool hashProvided = !expectedHash.empty();
        const bool validHash = expectedHash.size() == 64
            && std::all_of(expectedHash.begin(), expectedHash.end(), [](const wchar_t ch) {
                return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f');
            });
        if (!IsValidScheduledTaskLocator(taskPath, taskName)
            || (hashProvided && !validHash))
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::InvalidEntry,
                false,
                false,
                ERROR_INVALID_PARAMETER,
                FromWide(L"计划任务删除定位器无效。"));
        }

        const ProcessOutput output = RunPowerShellScript(
            BuildDeleteTaskPowerShellScript(taskPath, taskName, expectedHash),
            20000);
        const std::string stdoutText =
            StripUtf8Bom(ks::str::TrimCopy(output.stdoutText));
        if (output.started && output.finished && output.exitCode == 0
            && stdoutText.find("KSWORD_TASK_NOT_FOUND") != std::string::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::NoChange,
                true,
                false,
                ERROR_SUCCESS,
                FromWide(L"计划任务已经不存在。"));
        }
        if (output.started && output.finished && output.exitCode == 0
            && stdoutText.find("KSWORD_TASK_DELETED") != std::string::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Success,
                true,
                true,
                ERROR_SUCCESS,
                FromWide(L"计划任务已按路径、名称和定义快照永久删除并验证。"));
        }
        if (stdoutText.find("KSWORD_STALE") != std::string::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_REVISION_MISMATCH,
                FromWide(L"计划任务定义已在枚举后变化；未删除陈旧目标。"));
        }
        if (stdoutText.find("KSWORD_UNSUPPORTED") != std::string::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_NOT_SUPPORTED,
                FromWide(L"计划任务已不再包含 Boot 或 Logon 触发器；请刷新启动项列表。"));
        }
        if (stdoutText.find("KSWORD_TASK_AMBIGUOUS") != std::string::npos)
        {
            return MakeActionResult(
                ks::startup::StartupActionStatus::Conflict,
                false,
                false,
                ERROR_DUP_NAME,
                FromWide(L"计划任务定位器匹配到多个对象；未执行删除。"));
        }

        const bool accessDenied =
            stdoutText.find("KSWORD_ACCESS_DENIED") != std::string::npos;
        const DWORD errorCode = accessDenied
            ? ERROR_ACCESS_DENIED
            : ProcessFailureCode(output);
        return MakeActionResult(
            accessDenied
                ? ks::startup::StartupActionStatus::AccessDenied
                : ks::startup::StartupActionStatus::ProcessFailed,
            false,
            false,
            errorCode,
            FromWide(L"永久删除计划任务失败。"));
    }
}

namespace ks::startup
{
    std::string CategoryToText(const StartupCategory category)
    {
        switch (category)
        {
        case StartupCategory::All:
            return FromWide(L"\u603b\u89c8");
        case StartupCategory::Logon:
            return FromWide(L"\u767b\u5f55");
        case StartupCategory::Services:
            return FromWide(L"\u670d\u52a1");
        case StartupCategory::Drivers:
            return FromWide(L"\u9a71\u52a8");
        case StartupCategory::Tasks:
            return FromWide(L"\u8ba1\u5212\u4efb\u52a1");
        case StartupCategory::ImageHijack:
            return FromWide(L"映像劫持");
        case StartupCategory::Registry:
            return FromWide(L"\u9ad8\u7ea7\u6ce8\u518c\u8868");
        case StartupCategory::Wmi:
            return "WMI";
        case StartupCategory::Hidden:
            return FromWide(L"隐藏项");
        default:
            return FromWide(L"\u672a\u77e5");
        }
    }

    std::string NormalizeFilePathText(const std::string& commandText)
    {
        std::wstring text = TrimWide(ToWide(commandText));
        if (text.empty())
        {
            return std::string();
        }
        text = ExpandEnvironmentWide(text);
        if (text.starts_with(L"\\??\\"))
        {
            text.erase(0, 4);
        }
        if (text.starts_with(L"\\SystemRoot\\"))
        {
            const std::wstring systemRoot = QueryEnvironmentWide(L"SystemRoot");
            if (!systemRoot.empty())
            {
                text = systemRoot + text.substr(std::wstring(L"\\SystemRoot").size());
            }
        }
        if (!text.empty() && text.front() == L'\"')
        {
            const std::size_t endQuote = text.find(L'\"', 1);
            if (endQuote != std::wstring::npos && endQuote > 1)
            {
                return ToNativeSeparators(FromWide(text.substr(1, endQuote - 1)));
            }
        }
        const std::wstring lowerText = LowerWideCopy(text);
        for (const std::wstring& extension : { L".exe", L".dll", L".sys" })
        {
            const std::size_t index = lowerText.find(extension);
            if (index != std::wstring::npos && index > 0)
            {
                return ToNativeSeparators(FromWide(text.substr(0, index + extension.size())));
            }
        }
        const std::size_t spaceIndex = text.find(L' ');
        if (spaceIndex != std::wstring::npos && spaceIndex > 0)
        {
            return ToNativeSeparators(FromWide(text.substr(0, spaceIndex)));
        }
        return ToNativeSeparators(FromWide(text));
    }

    std::string QueryPublisherTextByPath(const std::string& filePathText)
    {
        const std::string trimmedPath = ks::str::TrimCopy(filePathText);
        if (trimmedPath.empty() || !FileExists(trimmedPath))
        {
            return std::string();
        }
        const std::string companyName = QueryCompanyNameByVersion(trimmedPath);
        const bool trusted = IsFileTrustedByWindows(trimmedPath);
        if (!companyName.empty())
        {
            return companyName + (trusted ? " (Trusted)" : " (Untrusted)");
        }
        return trusted ? "Signed (Trusted)" : std::string();
    }

    std::string NormalizeRegistryLocationLine(const std::string& rawLineText)
    {
        std::string text = ks::str::TrimCopy(rawLineText);
        if (text.empty() || (!StartsWithI(text, "HKLM") && !StartsWithI(text, "HKCU") && !StartsWithI(text, "HKCR")))
        {
            return std::string();
        }
        std::replace(text.begin(), text.end(), '/', '\\');
        text = std::regex_replace(
            text,
            std::regex("^(HKLM|HKCU|HKCR)\\s+(SOFTWARE|SYSTEM|Software|System|Classes|Environment|Control Panel)", std::regex_constants::icase),
            "$1\\$2");
        text = std::regex_replace(text, std::regex("\\s*\\\\\\s*"), "\\");
        text = std::regex_replace(text, std::regex("\\\\{2,}"), "\\");
        const std::array<std::pair<const char*, const char*>, 28> replacements{ {
            { "HKLMSOFTWARE", "HKLM\\SOFTWARE" }, { "HKLMSoftware", "HKLM\\Software" }, { "HKLMSystem", "HKLM\\System" }, { "HKLMSYSTEM", "HKLM\\SYSTEM" },
            { "HKCU\\SOFTWAREClasses", "HKCU\\SOFTWARE\\Classes" }, { "HKCU\\SOFTWARE Classes", "HKCU\\SOFTWARE\\Classes" }, { "HKLM\\SOFTWAREWow6432Node", "HKLM\\SOFTWARE\\Wow6432Node" },
            { "SOFTWAREClasses", "SOFTWARE\\Classes" }, { "SOFTWARE Classes", "SOFTWARE\\Classes" }, { "ShelllconOverlayldentifiers", "ShellIconOverlayIdentifiers" },
            { "Catalog Entries64", "Catalog_Entries64" }, { "Folder ShellEx", "Folder\\ShellEx" }, { "Explorer ShellExecuteHooks", "Explorer\\ShellExecuteHooks" },
            { "Explorer ShellServiceObjects", "Explorer\\ShellServiceObjects" }, { "ShellExecute Hooks", "ShellExecuteHooks" }, { "Internet ExplorerExtensions", "Internet Explorer\\Extensions" },
            { "Intemet", "Internet" }, { "Interet", "Internet" }, { "Userlnit", "Userinit" }, { "Scmsave.exe", "Scrnsave.exe" }, { "AutoStartDisconnect", "AutoStartOnDisconnect" },
            { "Appinit Dlls", "AppInit_DLLs" }, { "Appinit_Dlls", "AppInit_DLLs" }, { "Session Manager\\SOInitialCommand", "Session Manager\\S0InitialCommand" },
            { "HKCU\\Software\\Classes\\M\\ShellEx\\ContextMenuHandlers", "HKCU\\Software\\Classes\\*\\ShellEx\\ContextMenuHandlers" },
            { "HKCU\\Software\\Classes\\\\ShellEx\\PropertySheetHandlers", "HKCU\\Software\\Classes\\*\\ShellEx\\PropertySheetHandlers" },
            { "HKLM\\Software\\Classes\\\\ShellEx\\PropertySheetHandlers", "HKLM\\Software\\Classes\\*\\ShellEx\\PropertySheetHandlers" },
            { "HKLM\\Software\\Wow6432Node\\Classes\\\\ShellEx\\PropertySheetHandlers", "HKLM\\Software\\Wow6432Node\\Classes\\*\\ShellEx\\PropertySheetHandlers" }
        } };
        for (const auto& rule : replacements)
        {
            ReplaceAllI(text, rule.first, rule.second);
        }
        text = std::regex_replace(
            text,
            std::regex("\\\\CLSID\\\\\\{?\\(?([0-9A-Fa-f\\-]{36})\\)?\\}?\\\\"),
            "\\\\CLSID\\\\{$1}\\\\");
        if ((StartsWithI(text, "HKLM") || StartsWithI(text, "HKCU") || StartsWithI(text, "HKCR")) && text.size() > 4 && text[4] != '\\')
        {
            text.insert(4, "\\");
        }
        text = std::regex_replace(text, std::regex("\\s*\\\\\\s*"), "\\");
        text = std::regex_replace(text, std::regex("\\\\{2,}"), "\\");
        text = ks::str::TrimCopy(text);
        if (!StartsWithI(text, "HKLM\\") && !StartsWithI(text, "HKCU\\") && !StartsWithI(text, "HKCR\\"))
        {
            return std::string();
        }
        text.replace(0, 4, LowerAsciiCopy(text.substr(0, 4)) == "hklm" ? "HKLM" : (LowerAsciiCopy(text.substr(0, 4)) == "hkcu" ? "HKCU" : "HKCR"));
        ReplaceAllI(text, "}\\)\\InProcServer32", "}\\InProcServer32");
        ReplaceAllI(text, "}\\)\\Instance", "}\\Instance");
        if (LowerAsciiCopy(text).ends_with("\\(default)"))
        {
            text.erase(text.size() - std::string("\\(Default)").size());
        }
        return text;
    }

    std::vector<std::string> BuildKnownStartupRegistryLocationList(const std::vector<std::string>& rawLineList)
    {
        std::vector<std::string> locations;
        std::vector<std::string> dedupeKeys;
        for (const std::string& rawLine : rawLineList)
        {
            const std::string normalized = NormalizeRegistryLocationLine(rawLine);
            if (normalized.empty())
            {
                continue;
            }
            const std::string key = LowerAsciiCopy(normalized);
            if (std::find(dedupeKeys.begin(), dedupeKeys.end(), key) != dedupeKeys.end())
            {
                continue;
            }
            dedupeKeys.push_back(key);
            locations.push_back(normalized);
        }
        return locations;
    }

    std::vector<StartupEntry> EnumerateLogonEntries()
    {
        std::vector<StartupEntry> entries;
        for (const RunKeySpec& spec : BuildRunKeySpecList())
        {
            const std::wstring subKeyText(spec.subKeyText);
            for (const RegistryValueRecord& valueRecord : EnumerateRegistryValues(spec.rootKey, subKeyText))
            {
                if (ks::str::TrimCopy(valueRecord.valueDataText).empty())
                {
                    continue;
                }
                if (EndsWithI(subKeyText, L"\\Windows"))
                {
                    const std::string lowerName = LowerAsciiCopy(ks::str::TrimCopy(valueRecord.valueNameText));
                    if (lowerName != "run" && lowerName != "load")
                    {
                        continue;
                    }
                }
                if (EndsWithI(subKeyText, L"Command Processor") && LowerAsciiCopy(valueRecord.valueNameText) != "autorun")
                {
                    continue;
                }
                AppendValueBasedLogonEntry(entries, spec, valueRecord);
            }
        }
        AppendRunOnceExEntries(entries);
        AppendStartupFolderEntries(entries);
        // Script and add-in files execute at logon without any registry pointer of their own.
        AppendScriptFileEntries(entries);
        AppendDisabledRegistryRunEntries(entries);
        AppendDisabledStartupFolderEntries(entries);
        return entries;
    }

    std::vector<StartupEntry> EnumerateServiceEntries()
    {
        return EnumerateScmEntries(false);
    }

    std::vector<StartupEntry> EnumerateDriverEntries()
    {
        return EnumerateScmEntries(true);
    }

    std::vector<StartupEntry> EnumerateTaskEntries()
    {
        std::vector<StartupEntry> entries;
        const ProcessOutput output = RunPowerShellScript(BuildTaskPowerShellScript(), 20000);
        if (!output.started || !output.finished || output.stdoutText.empty())
        {
            return entries;
        }
        bool parseOk = false;
        const std::vector<JsonValue> taskObjects = ParseJsonObjects(StripUtf8Bom(ks::str::TrimCopy(output.stdoutText)), &parseOk);
        if (!parseOk)
        {
            return entries;
        }
        for (const JsonValue& taskObject : taskObjects)
        {
            AppendScheduledTaskJsonObject(entries, taskObject);
        }
        return entries;
    }

    std::vector<StartupEntry> EnumerateImageHijackEntries()
    {
        std::vector<StartupEntry> entries;
        for (const IfeoRegistryViewSpec& viewSpec : BuildIfeoRegistryViewSpecList())
        {
            AppendIfeoViewEntries(entries, viewSpec);
        }
        AppendSilentProcessExitEntries(entries);
        return entries;
    }

    std::vector<StartupEntry> EnumerateAdvancedRegistryEntries()
    {
        std::vector<StartupEntry> entries;
        AppendSingleValueEntries(entries);
        AppendValueEnumEntries(entries);
        AppendSubKeyValueEntries(entries);
        // Policy scripts sit three levels deep, so they need their own walker.
        AppendGroupPolicyScriptEntries(entries);
        return entries;
    }

    std::vector<StartupEntry> EnumerateWinsockEntries()
    {
        std::vector<StartupEntry> entries;
        for (const WinsockKeySpec& spec : BuildWinsockKeySpecList())
        {
            const std::wstring rootSubKey(spec.subKeyText);
            const std::string groupLocationText = BuildRegistryLocationText(spec.rootKey, rootSubKey);
            for (const std::wstring& subKeyName : EnumerateRegistrySubKeys(spec.rootKey, rootSubKey))
            {
                const std::wstring itemSubKey = rootSubKey + L"\\" + subKeyName;
                const std::string subKeyNameText = FromWide(subKeyName);
                const std::vector<std::string> valueTexts = EnumerateRegistryValueTextList(spec.rootKey, itemSubKey);
                StartupEntry entry;
                entry.category = StartupCategory::Registry;
                entry.categoryText = CategoryToText(entry.category);
                entry.itemNameText = FromWide(L"Winsock \u9879 ") + subKeyNameText;
                entry.commandText = JoinStrings(valueTexts, FromWide(L"\uff1b"));
                entry.locationText = BuildRegistryLocationText(spec.rootKey, itemSubKey);
                entry.locationGroupText = groupLocationText;
                entry.userText = FromWide(spec.userText);
                entry.detailText = FromWide(spec.detailText) + FromWide(L"\uff1b\u952e\u503c\u6570\u91cf=") + std::to_string(valueTexts.size());
                entry.sourceTypeText = spec.sourceTypeText;
                entry.enabled = true;
                entry.canOpenFileLocation = false;
                entry.canOpenRegistryLocation = true;
                ConfigureRegistryTreeDeletion(entry, spec.rootKey, itemSubKey);
                entry.uniqueIdText = "WINSOCK|" + entry.locationText;
                entry.riskLevel = StartupRiskLevel::Critical;
                entry.riskReasonCode = "winsock";
                entry.riskReasonText = FromWide(L"该 Winsock 目录子键只能永久删除；错误修改可能导致网络协议栈或网络访问失效。");
                entries.push_back(std::move(entry));
            }
        }
        return entries;
    }

    std::vector<StartupEntry> EnumerateWmiEntries()
    {
        std::vector<StartupEntry> entries;
        const ProcessOutput output = RunPowerShellScript(BuildWmiPowerShellScript(), 15000);
        if (!output.started || !output.finished)
        {
            return entries;
        }
        const std::string stdoutText = StripUtf8Bom(ks::str::TrimCopy(output.stdoutText));
        if (stdoutText.empty())
        {
            return entries;
        }
        bool parseOk = false;
        const std::vector<JsonValue> wmiObjects = ParseJsonObjects(stdoutText, &parseOk);
        if (!parseOk)
        {
            StartupEntry errorEntry;
            errorEntry.category = StartupCategory::Wmi;
            errorEntry.categoryText = CategoryToText(errorEntry.category);
            errorEntry.itemNameText = FromWide(L"WMI \u679a\u4e3e\u89e3\u6790\u5931\u8d25");
            errorEntry.commandText = stdoutText;
            errorEntry.locationText = "root\\subscription";
            errorEntry.userText = FromWide(L"本机");
            errorEntry.detailText = FromWide(L"JSON \u89e3\u6790\u5931\u8d25");
            errorEntry.sourceTypeText = "WMI-ParseError";
            errorEntry.enabled = false;
            errorEntry.uniqueIdText = "WMI|ParseError";
            MarkEntryActionUnavailable(
                errorEntry,
                StartupRiskLevel::Critical,
                "wmi",
                FromWide(L"WMI 枚举失败；合成的错误记录不能修改。"));
            entries.push_back(std::move(errorEntry));
            return entries;
        }
        for (const JsonValue& wmiObject : wmiObjects)
        {
            AppendWmiJsonObject(entries, wmiObject);
        }
        return entries;
    }

    std::vector<StartupEntry> EnumerateAllStartupEntries()
    {
        return EnumerateAllStartupEntries(
            StartupEnumerationProgressCallback{},
            StartupEnumerationStageResultCallback{});
    }

    std::vector<StartupEntry> EnumerateAllStartupEntries(
        const StartupEnumerationProgressCallback& progressCallback)
    {
        return EnumerateAllStartupEntries(
            progressCallback,
            StartupEnumerationStageResultCallback{});
    }

    std::vector<StartupEntry> EnumerateAllStartupEntries(
        const StartupEnumerationProgressCallback& progressCallback,
        const StartupEnumerationStageResultCallback& stageResultCallback)
    {
        std::vector<StartupEntry> entries;
        constexpr std::size_t stageCount = 9U;
        auto append = [&entries, &progressCallback, &stageResultCallback, stageCount](
            const StartupEnumerationStage stage,
            const std::size_t stageIndex,
            auto&& enumerateStage)
        {
            if (progressCallback)
            {
                progressCallback(stage, stageIndex, stageCount);
            }
            std::vector<StartupEntry> part = enumerateStage();
            if (stageResultCallback)
            {
                stageResultCallback(stage, stageIndex, stageCount, part);
            }
            entries.insert(entries.end(), std::make_move_iterator(part.begin()), std::make_move_iterator(part.end()));
        };
        append(StartupEnumerationStage::Logon, 0U, []() { return EnumerateLogonEntries(); });
        append(StartupEnumerationStage::Services, 1U, []() { return EnumerateServiceEntries(); });
        append(StartupEnumerationStage::Drivers, 2U, []() { return EnumerateDriverEntries(); });
        append(StartupEnumerationStage::Tasks, 3U, []() { return EnumerateTaskEntries(); });
        append(StartupEnumerationStage::ImageHijack, 4U, []() { return EnumerateImageHijackEntries(); });
        append(StartupEnumerationStage::AdvancedRegistry, 5U, []() { return EnumerateAdvancedRegistryEntries(); });
        append(StartupEnumerationStage::Winsock, 6U, []() { return EnumerateWinsockEntries(); });
        append(StartupEnumerationStage::Wmi, 7U, []() { return EnumerateWmiEntries(); });
        // Hidden findings run last: they cross-check the same objects the enumerators above walked.
        append(StartupEnumerationStage::Hidden, 8U, []() { return EnumerateHiddenEntries(); });
        return entries;
    }

    ActionResult SetStartupEntryEnabled(const StartupEntry& entry, const bool enabled)
    {
        switch (entry.actionKind)
        {
        case StartupActionKind::RegistryRunValue:
            return enabled ? EnableRegistryRunEntry(entry) : DisableRegistryRunEntry(entry);
        case StartupActionKind::RegistryTree:
            break;
        case StartupActionKind::StartupFolderFile:
            return enabled ? EnableStartupFolderEntry(entry) : DisableStartupFolderEntry(entry);
        case StartupActionKind::ScheduledTask:
            return SetScheduledTaskEnabled(entry, enabled);
        case StartupActionKind::ScmStartType:
            return SetScmEntryEnabled(entry, enabled);
        case StartupActionKind::WmiEntryRemoval:
            return RemoveWmiEntry(entry, enabled);
        case StartupActionKind::None:
            break;
        }
        return MakeActionResult(
            StartupActionStatus::NotSupported,
            false,
            false,
            ERROR_NOT_SUPPORTED,
            FromWide(L"此启动项没有可逆的后端操作。"));
    }

    ActionResult DeleteStartupEntry(const StartupEntry& entry)
    {
        if (!entry.canDelete)
        {
            return MakeActionResult(
                StartupActionStatus::NotSupported,
                false,
                false,
                ERROR_NOT_SUPPORTED,
                FromWide(L"此启动项没有可用的永久删除操作。"));
        }
        if (entry.deleteRegistryTree)
        {
            return DeleteRegistryTreeEntry(entry);
        }

        switch (entry.actionKind)
        {
        case StartupActionKind::RegistryRunValue:
            return DeleteRegistryValueEntry(entry);
        case StartupActionKind::RegistryTree:
            return DeleteRegistryTreeEntry(entry);
        case StartupActionKind::StartupFolderFile:
            return DeleteStartupFolderFile(entry);
        case StartupActionKind::ScheduledTask:
            return DeleteScheduledTaskEntry(entry);
        case StartupActionKind::ScmStartType:
            return DeleteScmEntry(entry);
        case StartupActionKind::WmiEntryRemoval:
        case StartupActionKind::None:
            break;
        }
        return MakeActionResult(
            StartupActionStatus::NotSupported,
            false,
            false,
            ERROR_NOT_SUPPORTED,
            FromWide(L"此启动项来源不支持永久删除。"));
    }
}
