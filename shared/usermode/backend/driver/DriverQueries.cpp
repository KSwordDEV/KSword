#include "DriverQueries.h"
#include <algorithm>
#include <cwchar>
#include <cstring>
#include <memory>
#include <limits>
#include <sstream>
#include "DriverFormatting.h"
#pragma comment(lib,"Wintrust.lib")
#pragma comment(lib,"Version.lib")
#pragma comment(lib,"Psapi.lib")
namespace ks::r3::driver {
bool IsRetryStatus(LONG status) {
    return status == kStatusInfoLengthMismatch
        || status == kStatusBufferTooSmall
        || status == kStatusBufferOverflow;
}
std::wstring WideText(const UNICODE_STRING& value) {
    if (!value.Buffer || value.Length == 0) {
        return {};
    }
    return std::wstring(value.Buffer, value.Buffer + (value.Length / sizeof(wchar_t)));
}
std::wstring AnsiTextToWide(const char* text, std::size_t length) {
    if (!text || length == 0) {
        return {};
    }

    const int needed = ::MultiByteToWideChar(CP_ACP, 0, text, static_cast<int>(length), nullptr, 0);
    if (needed <= 0) {
        return {};
    }

    std::wstring wide(static_cast<std::size_t>(needed), L'\0');
    if (::MultiByteToWideChar(CP_ACP, 0, text, static_cast<int>(length), wide.data(), needed) <= 0) {
        return {};
    }
    return wide;
}
std::wstring AnsiPathFromModule(const KRTL_PROCESS_MODULE_INFORMATION& module) {
    std::size_t length = 0;
    while (length < sizeof(module.FullPathName) && module.FullPathName[length] != '\0') {
        ++length;
    }
    return AnsiTextToWide(reinterpret_cast<const char*>(module.FullPathName), length);
}
std::wstring CompactHex(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << value;
    return stream.str();
}
std::wstring NtStatusText(const long status) {
    return CompactHex(static_cast<std::uint32_t>(status));
}
std::wstring ResolveKernelImagePathForTrust(const std::wstring& path) {
    if (path.empty()) {
        return {};
    }

    constexpr wchar_t kSystemRootPrefix[] = L"\\SystemRoot";
    if (_wcsnicmp(path.c_str(), kSystemRootPrefix, _countof(kSystemRootPrefix) - 1) == 0) {
        wchar_t windowsDirectory[MAX_PATH]{};
        const UINT length = ::GetWindowsDirectoryW(windowsDirectory, static_cast<UINT>(_countof(windowsDirectory)));
        if (length == 0 || length >= _countof(windowsDirectory)) {
            return {};
        }
        return std::wstring(windowsDirectory) + path.substr(_countof(kSystemRootPrefix) - 1);
    }

    constexpr wchar_t kDosDevicePrefix[] = L"\\??\\";
    if (_wcsnicmp(path.c_str(), kDosDevicePrefix, _countof(kDosDevicePrefix) - 1) == 0) {
        return path.substr(_countof(kDosDevicePrefix) - 1);
    }

    if (path.size() >= 3 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) {
        return path;
    }

    return {};
}
std::wstring VerifyDriverImageSignature(const std::wstring& displayPath,DriverSignatureEvidence* evidence) {
    DriverSignatureEvidence local;if (!evidence) evidence = &local;*evidence = {};
    const std::wstring localPath = ResolveKernelImagePathForTrust(displayPath);
    if (localPath.empty()) {
        return L"未解析本地路径";
    }
    evidence->pathResolved = true;evidence->localPath = localPath;
    if (::GetFileAttributesW(localPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        evidence->fileError = ::GetLastError();
        return L"文件不可访问";
    }
    evidence->fileAccessible = true;

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = localPath.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = ::WinVerifyTrust(nullptr, &policy, &trustData);
    evidence->evaluated = true;evidence->trustStatus = status;
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)::WinVerifyTrust(nullptr, &policy, &trustData);

    if (status == ERROR_SUCCESS) {
        return L"签名有效";
    }
    if (status == TRUST_E_NOSIGNATURE) {
        return L"无嵌入签名";
    }
    if (status == CERT_E_EXPIRED) {
        return L"证书过期";
    }
    if (status == TRUST_E_BAD_DIGEST) {
        return L"摘要不匹配";
    }
    return L"签名失败 " + NtStatusText(status);
}
std::wstring LeafName(const std::wstring& text) {
    const std::size_t slash = text.find_last_of(L"\\/");
    if (slash == std::wstring::npos || slash + 1 >= text.size()) {
        return text;
    }
    return text.substr(slash + 1);
}
std::wstring JoinObjectPath(const std::wstring& root, const std::wstring& name) {
    if (root.empty()) {
        return name;
    }
    if (name.empty()) {
        return root;
    }
    if (root.back() == L'\\') {
        return root + name;
    }
    return root + L"\\" + name;
}
std::wstring StatusForObjectType(const std::wstring& typeName, bool querySucceeded, bool hasTarget) {
    if (!querySucceeded) {
        return L"对象信息有限，建议检查权限或对象类型";
    }
    if (typeName == L"Directory") {
        return L"目录，可继续枚举";
    }
    if (typeName == L"SymbolicLink") {
        return hasTarget ? L"符号链接，已解析目标" : L"符号链接，目标未解析";
    }
    return L"叶子对象，建议查属性";
}
std::wstring CapabilityForObjectType(const std::wstring& typeName, bool hasTarget) {
    if (typeName == L"Directory") {
        return L"可用目录递归继续展开";
    }
    if (typeName == L"SymbolicLink") {
        return hasTarget ? L"可解析符号链接，用于设备路径理解" : L"可尝试解析符号链接目标";
    }
    return L"叶子对象，建议查属性";
}
HANDLE OpenNtDirectory(const NtLibrary& library, const std::wstring& path) {
    if (!library.openDirectoryObject || path.empty()) {
        return nullptr;
    }

    UNICODE_STRING unicodePath{};
    unicodePath.Buffer = const_cast<PWSTR>(path.c_str());
    unicodePath.Length = static_cast<USHORT>(path.size() * sizeof(wchar_t));
    unicodePath.MaximumLength = static_cast<USHORT>(unicodePath.Length + sizeof(wchar_t));

    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = nullptr;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    attributes.ObjectName = &unicodePath;

    HANDLE handle = nullptr;
    const LONG status = library.openDirectoryObject(&handle, DIRECTORY_QUERY, &attributes);
    return status >= 0 ? handle : nullptr;
}
bool QueryBasicCounts(const NtLibrary& library, HANDLE handle, std::wstring& handleCountText, std::wstring& referenceCountText) {
    if (!library.queryObject || !handle) {
        return false;
    }

    KOBJECT_BASIC_INFORMATION basic{};
    ULONG returnLength = 0;
    const LONG status = library.queryObject(handle, 0, &basic, static_cast<ULONG>(sizeof(basic)), &returnLength);
    if (status < 0) {
        return false;
    }

    handleCountText = std::to_wstring(basic.HandleCount);
    referenceCountText = std::to_wstring(basic.PointerCount);
    return true;
}
std::wstring QuerySymbolicLinkTarget(const NtLibrary& library, HANDLE handle) {
    if (!library.querySymbolicLinkObject || !handle) {
        return {};
    }

    std::vector<wchar_t> buffer(1024, L'\0');
    UNICODE_STRING target{};
    target.Buffer = buffer.data();
    target.Length = 0;
    target.MaximumLength = static_cast<USHORT>(buffer.size() * sizeof(wchar_t));

    const LONG status = library.querySymbolicLinkObject(handle, &target, nullptr);
    if (status < 0) {
        return {};
    }

    if (!target.Buffer || target.Length == 0) {
        return {};
    }
    return std::wstring(target.Buffer, target.Buffer + (target.Length / sizeof(wchar_t)));
}
DriverObjectRow AppendDirectoryRow(const NtLibrary& library, const std::wstring& directoryPath, const std::wstring& name, const std::wstring& typeName) {
    DriverObjectRow row;
    row.directoryPathText = directoryPath;
    row.objectNameText = name;
    row.objectTypeText = typeName.empty() ? L"<unknown>" : typeName;
    row.fullPathText = JoinObjectPath(directoryPath, name);
    row.statusText = StatusForObjectType(row.objectTypeText, true, false);
    row.capabilityHint = CapabilityForObjectType(row.objectTypeText, false);
    row.querySucceeded = true;

        if (row.objectTypeText == L"Directory") {
            row.isDirectory = true;
            row.statusText = L"目录，可继续枚举";
            row.capabilityHint = L"可用目录递归继续展开";
            HANDLE handle = OpenNtDirectory(library, row.fullPathText);
            if (handle) {
            std::wstring handleCount;
            std::wstring referenceCount;
            if (QueryBasicCounts(library, handle, handleCount, referenceCount)) {
                row.handleCountText = handleCount;
                row.referenceCountText = referenceCount;
            }
            ::CloseHandle(handle);
        }
        } else if (row.objectTypeText == L"SymbolicLink") {
            row.isSymbolicLink = true;
            HANDLE handle = nullptr;
            if (library.openSymbolicLinkObject) {
            UNICODE_STRING unicodePath{};
            unicodePath.Buffer = const_cast<PWSTR>(row.fullPathText.c_str());
            unicodePath.Length = static_cast<USHORT>(row.fullPathText.size() * sizeof(wchar_t));
            unicodePath.MaximumLength = static_cast<USHORT>(unicodePath.Length + sizeof(wchar_t));

            OBJECT_ATTRIBUTES attributes{};
            attributes.Length = sizeof(attributes);
            attributes.RootDirectory = nullptr;
            attributes.Attributes = OBJ_CASE_INSENSITIVE;
            attributes.ObjectName = &unicodePath;

            const LONG status = library.openSymbolicLinkObject(&handle, SYMBOLIC_LINK_QUERY, &attributes);
            if (status >= 0 && handle) {
                std::wstring handleCount;
                std::wstring referenceCount;
                if (QueryBasicCounts(library, handle, handleCount, referenceCount)) {
                    row.handleCountText = handleCount;
                    row.referenceCountText = referenceCount;
                }
                row.targetPathText = QuerySymbolicLinkTarget(library, handle);
                ::CloseHandle(handle);
            }
        }
        row.statusText = StatusForObjectType(row.objectTypeText, true, !row.targetPathText.empty());
        row.capabilityHint = CapabilityForObjectType(row.objectTypeText, !row.targetPathText.empty());
    } else {
        row.statusText = L"叶子对象，建议查属性";
        row.capabilityHint = L"叶子对象，建议查属性";
    }

    if (row.referenceCountText.empty()) {
        row.referenceCountText = L"N/A";
    }
    if (row.handleCountText.empty()) {
        row.handleCountText = L"N/A";
    }
    return row;
}
bool QueryModuleInformation(std::vector<DriverOverviewRow>& rows, std::wstring& diagnosticText,DriverEnumerationEvidence* evidence,bool signature) {
    DriverEnumerationEvidence local;if (!evidence) evidence = &local;*evidence = {};
    ks::r3::common::NtApi api;
    if (!api.available()) {
        evidence->unsupported = true;
        diagnosticText = L"NtQuerySystemInformation 不可用，准备回退到 Psapi 枚举。";
        return false;
    }

    ULONG bufferSize = 1u << 20;
    std::vector<std::byte> buffer;
    LONG status = kStatusProcedureNotFound;
    ULONG actualLength = 0;
    for (int attempt = 0; attempt < 8; ++attempt) {
        buffer.assign(bufferSize, std::byte{});
        ULONG returnLength = 0;
        status = api.querySystemInformation(
            static_cast<ks::r3::common::SystemInformationClass>(11),
            buffer.data(),
            bufferSize,
            &returnLength);
        evidence->ntStatusKnown = true;evidence->ntStatus = status;actualLength = returnLength;
        if (status == kStatusSuccess) {
            break;
        }
        if (!IsRetryStatus(status)) {
            diagnosticText = L"NtQuerySystemInformation(SystemModuleInformation) 失败: 0x";
            wchar_t code[16]{};
            ::swprintf_s(code, L"%08lX", static_cast<unsigned long>(status));
            diagnosticText += code;
            return false;
        }
        const auto next = (std::max)(static_cast<std::uint64_t>(bufferSize)*2,static_cast<std::uint64_t>(returnLength)+0x10000);
        if (next > 128ull*1024*1024) {evidence->win32ErrorKnown = true;evidence->win32Error = ERROR_MORE_DATA;break;}
        bufferSize = static_cast<ULONG>(next);
    }

    if (status != kStatusSuccess) {
        diagnosticText = L"NtQuerySystemInformation(SystemModuleInformation) 重试失败。";
        return false;
    }

    const auto offset = offsetof(KRTL_PROCESS_MODULES,Modules);
    if (actualLength < offset || actualLength > buffer.size()) {
        evidence->malformed = true;diagnosticText = L"NtQuerySystemInformation(SystemModuleInformation) 重试失败。";return false;
    }
    const auto* modules = reinterpret_cast<const KRTL_PROCESS_MODULES*>(buffer.data());
    if (modules->NumberOfModules > (actualLength-offset)/sizeof(KRTL_PROCESS_MODULE_INFORMATION)) {
        evidence->malformed = true;diagnosticText = L"NtQuerySystemInformation(SystemModuleInformation) 重试失败。";return false;
    }
    evidence->reportedCount = modules->NumberOfModules;
    rows.reserve(modules->NumberOfModules);
    for (ULONG index = 0; index < modules->NumberOfModules; ++index) {
        const KRTL_PROCESS_MODULE_INFORMATION& module = modules->Modules[index];
        DriverOverviewRow row;
        row.driverName = AnsiPathFromModule(module);
        row.driverName = LeafName(row.driverName);
        const std::uint64_t baseAddress = reinterpret_cast<std::uint64_t>(module.ImageBase);
        row.baseAddress = baseAddress;row.baseKnown = baseAddress != 0;row.imageSize = module.ImageSize;row.sizeKnown = module.ImageSize != 0;
        row.flags = module.Flags;row.loadOrder = module.LoadOrderIndex;row.initOrder = module.InitOrderIndex;row.loadCount = module.LoadCount;
        row.rangeValid = baseAddress <= (std::numeric_limits<std::uint64_t>::max)()-module.ImageSize;
        if (!row.rangeValid) evidence->malformed = true;
        if (!row.baseKnown) evidence->redacted = true;
        const std::uint64_t endAddress = baseAddress + static_cast<std::uint64_t>(module.ImageSize);
        row.baseAddressText = FormatHexAddress(baseAddress);
        row.memoryRangeText = FormatHexAddress(baseAddress) + L"-" + FormatHexAddress(endAddress);
        row.sizeText = FormatByteSize(module.ImageSize);
        row.pathText = AnsiPathFromModule(module);
        row.pathKnown = std::memchr(module.FullPathName,0,sizeof(module.FullPathName)) != nullptr && !row.pathText.empty();
        row.nameKnown = row.pathKnown && !row.driverName.empty();
        if (signature) row.signatureText = VerifyDriverImageSignature(row.pathText,&row.signature);
        row.statusText = row.pathText.empty() ? L"已加载，路径不可用" : L"已加载";
        row.anomalyText = L"等待 R0 完整性证据";
        row.capabilityHint = L"可进一步按基址或路径追踪驱动模块";
        if (row.driverName.empty()) {
            row.driverName = L"<unknown>";
        }
        rows.push_back(std::move(row));
    }

    std::sort(rows.begin(), rows.end(), [](const DriverOverviewRow& left, const DriverOverviewRow& right) {
        return left.baseAddressText < right.baseAddressText;
    });

    diagnosticText = L"已通过 NtQuerySystemInformation 枚举驱动模块。";
    evidence->complete = true;
    return true;
}
bool QueryPsapiModules(std::vector<DriverOverviewRow>& rows, std::wstring& diagnosticText,DriverEnumerationEvidence* evidence,bool signature) {
    DriverEnumerationEvidence local;if (!evidence) evidence = &local;*evidence = {};
    std::vector<LPVOID> bases(2048);
    DWORD needed = 0;
    bool ready = false;
    for (int attempt = 0;attempt < 8;++attempt) {
        if (!::EnumDeviceDrivers(bases.data(), static_cast<DWORD>(bases.size() * sizeof(LPVOID)), &needed)) {
            evidence->win32ErrorKnown = true;evidence->win32Error = ::GetLastError();
            diagnosticText = std::wstring(L"EnumDeviceDrivers 失败，错误 ") + std::to_wstring(evidence->win32Error) + std::wstring(L"。建议以管理员身份运行。");
            return false;
        }
        if (needed%sizeof(LPVOID)) {evidence->malformed = true;return false;}
        if (needed <= bases.size()*sizeof(LPVOID)) {ready = true;break;}
        if (needed > 128u*1024*1024) break;
        bases.assign(needed/sizeof(LPVOID),nullptr);
    }
    if (!ready) {evidence->win32ErrorKnown = true;evidence->win32Error = ERROR_MORE_DATA;return false;}

    const std::size_t count = needed / sizeof(LPVOID);
    evidence->reportedCount = static_cast<DWORD>(count);
    rows.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        LPVOID base = bases[index];
        wchar_t nameBuffer[512]{};
        wchar_t pathBuffer[1024]{};
        DriverOverviewRow row;
        const DWORD nameLength = base ? ::GetDeviceDriverBaseNameW(base,nameBuffer,static_cast<DWORD>(_countof(nameBuffer))) : 0;
        if (base && !nameLength) row.nameError = ::GetLastError();
        row.nameKnown = nameLength > 0 && nameLength < _countof(nameBuffer) && nameBuffer[0] != L'\0';
        if (nameLength >= _countof(nameBuffer)) row.nameError = ERROR_INSUFFICIENT_BUFFER;
        const DWORD pathLength = base ? ::GetDeviceDriverFileNameW(base,pathBuffer,static_cast<DWORD>(_countof(pathBuffer))) : 0;
        if (base && !pathLength) row.pathError = ::GetLastError();
        row.pathKnown = pathLength > 0 && pathLength < _countof(pathBuffer) && pathBuffer[0] != L'\0';
        if (pathLength >= _countof(pathBuffer)) row.pathError = ERROR_INSUFFICIENT_BUFFER;
        nameBuffer[_countof(nameBuffer)-1] = L'\0';pathBuffer[_countof(pathBuffer)-1] = L'\0';
        if (!row.nameKnown) {
            std::wstring fallback = L"<unknown>";
            if (row.pathKnown) {
                fallback = LeafName(pathBuffer);
                row.nameKnown = !fallback.empty();
            }
            ::wcsncpy_s(nameBuffer, _countof(nameBuffer), fallback.c_str(), _TRUNCATE);
        }
        row.driverName = nameBuffer;
        const std::uint64_t baseAddress = reinterpret_cast<std::uint64_t>(base);
        row.baseAddress = baseAddress;row.baseKnown = base != nullptr;
        if (!base) evidence->redacted = true;
        row.baseAddressText = FormatHexAddress(baseAddress);
        row.memoryRangeText = FormatHexAddress(baseAddress) + L"-未知";
        row.sizeText = L"未知";
        row.pathText = pathBuffer;
        if (signature && row.pathKnown) row.signatureText = VerifyDriverImageSignature(row.pathText,&row.signature);
        row.statusText = L"已加载";
        row.anomalyText = L"Psapi 回退路径，等待 R0 完整性证据";
        row.capabilityHint = L"可进一步按基址或路径追踪驱动模块";
        rows.push_back(std::move(row));
    }

    std::sort(rows.begin(), rows.end(), [](const DriverOverviewRow& left, const DriverOverviewRow& right) {
        return left.baseAddressText < right.baseAddressText;
    });

    diagnosticText = L"已通过 Psapi 回退枚举驱动模块；大小信息不可用。";
    evidence->complete = true;
    return true;
}
void QueryObjectDirectory(
    const NtLibrary& library,
    const std::wstring& directoryPath,
    std::vector<DriverObjectRow>& rows,
    std::vector<std::wstring>& warnings) {
    HANDLE directory = OpenNtDirectory(library, directoryPath);
    if (!directory) {
        warnings.push_back(std::wstring(L"无法打开目录: ") + directoryPath + std::wstring(L"。"));
        return;
    }

    std::vector<std::byte> buffer(64 * 1024);
    ULONG context = 0;
    BOOLEAN restartScan = TRUE;
    for (;;) {
        ULONG returnLength = 0;
        const LONG status = library.queryDirectoryObject(
            directory,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            TRUE,
            restartScan,
            &context,
            &returnLength);
        restartScan = FALSE;

        if (status == kStatusNoMoreEntries) {
            break;
        }
        if (status < 0) {
            warnings.push_back(std::wstring(L"目录查询失败: ") + directoryPath + std::wstring(L" (0x") + [] (LONG s) {
                wchar_t code[16]{};
                ::swprintf_s(code, L"%08lX", static_cast<unsigned long>(s));
                return std::wstring(code);
            }(status) + L")。");
            break;
        }

        const auto* entry = reinterpret_cast<const KOBJECT_DIRECTORY_INFORMATION*>(buffer.data());
        if (!entry->Name.Buffer || entry->Name.Length == 0) {
            continue;
        }

        const std::wstring name = WideText(entry->Name);
        const std::wstring typeName = WideText(entry->TypeName);
        rows.push_back(AppendDirectoryRow(library, directoryPath, name, typeName));
    }

    ::CloseHandle(directory);
}
}
