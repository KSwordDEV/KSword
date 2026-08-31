#include "StartupEnumerator.h"

#include "../../Core/Common.h"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <shlobj.h>
#include <string>
#include <utility>
#include <vector>
#include <winsvc.h>

namespace Ksword::Features::Startup {
namespace {
constexpr wchar_t kRunKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRunOnceKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
constexpr wchar_t kDisabledRegistryBase[] = L"Software\\KswordARKLight\\DisabledStartup\\Registry";
constexpr wchar_t kDisabledStartupFolderBase[] = L"KswordARKLight\\DisabledStartup\\StartupFolder";
constexpr wchar_t kServicesRegistryRoot[] = L"SYSTEM\\CurrentControlSet\\Services";
constexpr DWORD kServiceUserServiceBit = 0x00000040U;
constexpr DWORD kServiceUserServiceInstanceBit = 0x00000080U;
constexpr DWORD kMaxServiceEnumerationPages = 4096;
constexpr DWORD kMaxServiceEnumerationPageBytes = 64U * 1024U;
constexpr DWORD kMaxServiceRegistryStringBytes = 1024U * 1024U;

// RegKey owns an HKEY opened by Win32 registry APIs. Inputs are HKEY handles;
// processing closes them at scope exit; get returns the raw handle without
// transferring ownership.
class RegKey final {
public:
    RegKey() : key_(nullptr) {}
    explicit RegKey(HKEY key) : key_(key) {}
    ~RegKey() { reset(); }

    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;

    void reset(HKEY key = nullptr) {
        if (key_) {
            ::RegCloseKey(key_);
        }
        key_ = key;
    }

    HKEY get() const { return key_; }
    bool valid() const { return key_ != nullptr; }

private:
    HKEY key_;
};

// ServiceHandle owns SC_HANDLE values from the service control manager. Inputs
// are handles from OpenSCManager/OpenService; processing closes them at scope
// exit; get returns the raw handle for Win32 calls.
class ServiceHandle final {
public:
    ServiceHandle() : handle_(nullptr) {}
    explicit ServiceHandle(SC_HANDLE handle) : handle_(handle) {}
    ~ServiceHandle() { reset(); }

    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;

    void reset(SC_HANDLE handle = nullptr) {
        if (handle_) {
            ::CloseServiceHandle(handle_);
        }
        handle_ = handle;
    }

    SC_HANDLE get() const { return handle_; }
    bool valid() const { return handle_ != nullptr; }

private:
    SC_HANDLE handle_;
};

// HKeyLabel returns a short root-key label. Input is an HKEY root; output is used
// in location text and disabled-storage subkeys.
std::wstring HKeyLabel(HKEY root) {
    if (root == HKEY_CURRENT_USER) {
        return L"HKCU";
    }
    if (root == HKEY_LOCAL_MACHINE) {
        return L"HKLM";
    }
    return L"HK";
}

// RegistryViewLabel formats a KEY_WOW64_* view flag. Input is a registry view;
// output is empty for the default native/current-user view.
std::wstring RegistryViewLabel(DWORD view) {
    if (view == KEY_WOW64_64KEY) {
        return L"64";
    }
    if (view == KEY_WOW64_32KEY) {
        return L"32";
    }
    return {};
}

// DisabledRegistrySubKey builds this module's parking key for a registry startup
// value. Inputs are target root, view and original subkey; output is a private
// subkey used only by StartupActions and StartupEnumerator.
std::wstring DisabledRegistrySubKey(HKEY root, DWORD view, const std::wstring& subKey) {
    std::wstring name = HKeyLabel(root) + L"_";
    if (subKey.find(L"RunOnce") != std::wstring::npos) {
        name += L"RunOnce";
    } else {
        name += L"Run";
    }
    const std::wstring viewText = RegistryViewLabel(view);
    if (!viewText.empty()) {
        name += L"_" + viewText;
    }
    return std::wstring(kDisabledRegistryBase) + L"\\" + name;
}

// RegistryLocationText formats one registry location. Inputs are root, subkey and
// view; output is a display string for the list/detail panes.
std::wstring RegistryLocationText(HKEY root, DWORD view, const std::wstring& subKey) {
    std::wstring text = HKeyLabel(root) + L"\\" + subKey;
    const std::wstring viewText = RegistryViewLabel(view);
    if (!viewText.empty()) {
        text += L" (" + viewText + L"-bit view)";
    }
    return text;
}

// RegValueToString converts a registry value buffer into display text. Inputs are
// type and raw bytes returned by RegEnumValueW; output is command text or a small
// compact binary-size description for unsupported value types.
std::wstring RegValueToString(DWORD type, const std::vector<BYTE>& data) {
    if (data.empty()) {
        return {};
    }
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        return std::wstring(reinterpret_cast<const wchar_t*>(data.data()));
    }
    if (type == REG_MULTI_SZ) {
        std::wstring output;
        const wchar_t* cursor = reinterpret_cast<const wchar_t*>(data.data());
        const wchar_t* end = reinterpret_cast<const wchar_t*>(data.data() + data.size());
        while (cursor < end && *cursor) {
            std::wstring part(cursor);
            if (!output.empty()) {
                output += L"; ";
            }
            output += part;
            cursor += part.size() + 1;
        }
        return output;
    }
    if ((type == REG_DWORD || type == REG_DWORD_LITTLE_ENDIAN) && data.size() >= sizeof(DWORD)) {
        DWORD value = 0;
        std::memcpy(&value, data.data(), sizeof(value));
        return std::to_wstring(value);
    }
    return L"(" + std::to_wstring(data.size()) + L" bytes)";
}

// OpenRegistryKey opens a startup or disabled-storage registry key. Inputs are
// root, subkey, access and view flag; output is an owning RegKey, empty on error.
RegKey OpenRegistryKey(HKEY root, const std::wstring& subKey, REGSAM access, DWORD view) {
    HKEY raw = nullptr;
    if (::RegOpenKeyExW(root, subKey.c_str(), 0, access | view, &raw) != ERROR_SUCCESS) {
        return RegKey();
    }
    return RegKey(raw);
}

// ReadRegistryDword reads one exact REG_DWORD value. Inputs are an already-open
// key and value name; output is false when the value is absent or has a different
// type, leaving value unchanged.
bool ReadRegistryDword(HKEY key, const wchar_t* valueName, DWORD& value) {
    DWORD type = 0;
    DWORD bytes = sizeof(value);
    DWORD candidate = 0;
    if (::RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<BYTE*>(&candidate), &bytes) != ERROR_SUCCESS ||
        type != REG_DWORD || bytes != sizeof(candidate)) {
        return false;
    }
    value = candidate;
    return true;
}

// ReadRegistryString reads one REG_SZ or REG_EXPAND_SZ value into an owned
// string. Inputs are an already-open key and value name; output is empty for a
// missing, non-string, or malformed value and never expands environment text.
std::wstring ReadRegistryString(HKEY key, const wchar_t* valueName) {
    DWORD type = 0;
    DWORD bytes = 0;
    if (::RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ) || bytes == 0 || bytes > kMaxServiceRegistryStringBytes) {
        return {};
    }
    std::vector<wchar_t> buffer((bytes / sizeof(wchar_t)) + 2, L'\0');
    DWORD queriedBytes = bytes;
    if (::RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<BYTE*>(buffer.data()), &queriedBytes) != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ)) {
        return {};
    }
    return std::wstring(buffer.data());
}

// AddProperty appends a detail property when the value exists. Inputs are entry,
// label and value; processing filters empty values; no return.
void AddProperty(StartupEntry& entry, const std::wstring& name, const std::wstring& value) {
    if (!value.empty()) {
        entry.properties.push_back({ name, value });
    }
}

// EnumerateRegistryKey appends Run/RunOnce rows from one registry key. Inputs are
// output vector and key metadata; processing reads every registry value; no
// return value is produced.
void EnumerateRegistryKey(std::vector<StartupEntry>& entries, HKEY root, StartupEntryScope scope,
    DWORD view, const std::wstring& subKey, StartupEntryKind kind) {
    RegKey key = OpenRegistryKey(root, subKey, KEY_QUERY_VALUE, view);
    if (!key.valid()) {
        return;
    }

    DWORD valueCount = 0;
    DWORD maxNameChars = 0;
    DWORD maxDataBytes = 0;
    if (::RegQueryInfoKeyW(key.get(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            &valueCount, &maxNameChars, &maxDataBytes, nullptr, nullptr) != ERROR_SUCCESS) {
        return;
    }

    std::vector<wchar_t> name(maxNameChars + 2, L'\0');
    std::vector<BYTE> data(maxDataBytes + sizeof(wchar_t) * 2, 0);
    for (DWORD index = 0; index < valueCount; ++index) {
        DWORD nameChars = static_cast<DWORD>(name.size());
        DWORD dataBytes = static_cast<DWORD>(data.size());
        DWORD type = 0;
        std::fill(name.begin(), name.end(), L'\0');
        std::fill(data.begin(), data.end(), 0);
        const LSTATUS status = ::RegEnumValueW(key.get(), index, name.data(), &nameChars,
            nullptr, &type, data.data(), &dataBytes);
        if (status != ERROR_SUCCESS) {
            continue;
        }

        StartupEntry entry;
        entry.kind = kind;
        entry.scope = scope;
        entry.state = StartupEntryState::Active;
        entry.name = nameChars > 0 ? std::wstring(name.data(), name.data() + nameChars) : L"(default)";
        entry.command = RegValueToString(type, std::vector<BYTE>(data.begin(), data.begin() + dataBytes));
        entry.location = RegistryLocationText(root, view, subKey);
        entry.registryRoot = root;
        entry.registryView = view;
        entry.registrySubKey = subKey;
        entry.registryValueName = entry.name == L"(default)" ? std::wstring() : entry.name;
        entry.disabledRegistrySubKey = DisabledRegistrySubKey(root, view, subKey);
        AddProperty(entry, L"Registry type", std::to_wstring(type));
        entries.push_back(std::move(entry));
    }
}

// EnumerateDisabledRegistryKey appends rows parked by StartupActions. Inputs are
// output vector and target metadata; processing reads private disabled-storage
// values; no return value is produced.
void EnumerateDisabledRegistryKey(std::vector<StartupEntry>& entries, HKEY root, StartupEntryScope scope,
    DWORD view, const std::wstring& subKey, StartupEntryKind kind) {
    const std::wstring disabledSubKey = DisabledRegistrySubKey(root, view, subKey);
    RegKey key = OpenRegistryKey(HKEY_CURRENT_USER, disabledSubKey, KEY_QUERY_VALUE, 0);
    if (!key.valid()) {
        return;
    }

    DWORD valueCount = 0;
    DWORD maxNameChars = 0;
    DWORD maxDataBytes = 0;
    if (::RegQueryInfoKeyW(key.get(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            &valueCount, &maxNameChars, &maxDataBytes, nullptr, nullptr) != ERROR_SUCCESS) {
        return;
    }

    std::vector<wchar_t> name(maxNameChars + 2, L'\0');
    std::vector<BYTE> data(maxDataBytes + sizeof(wchar_t) * 2, 0);
    for (DWORD index = 0; index < valueCount; ++index) {
        DWORD nameChars = static_cast<DWORD>(name.size());
        DWORD dataBytes = static_cast<DWORD>(data.size());
        DWORD type = 0;
        std::fill(name.begin(), name.end(), L'\0');
        std::fill(data.begin(), data.end(), 0);
        if (::RegEnumValueW(key.get(), index, name.data(), &nameChars, nullptr, &type, data.data(), &dataBytes) != ERROR_SUCCESS) {
            continue;
        }

        StartupEntry entry;
        entry.kind = kind;
        entry.scope = scope;
        entry.state = StartupEntryState::Disabled;
        entry.name = nameChars > 0 ? std::wstring(name.data(), name.data() + nameChars) : L"(default)";
        entry.command = RegValueToString(type, std::vector<BYTE>(data.begin(), data.begin() + dataBytes));
        entry.location = RegistryLocationText(root, view, subKey) + L" (disabled in HKCU\\" + disabledSubKey + L")";
        entry.registryRoot = root;
        entry.registryView = view;
        entry.registrySubKey = subKey;
        entry.registryValueName = entry.name == L"(default)" ? std::wstring() : entry.name;
        entry.disabledRegistrySubKey = disabledSubKey;
        AddProperty(entry, L"Disabled storage", L"HKCU\\" + disabledSubKey);
        entries.push_back(std::move(entry));
    }
}

// FolderPath returns a CSIDL folder path. Input is a CSIDL value; output is empty
// when Shell32 cannot resolve it for the current user/context.
std::wstring FolderPath(int csidl) {
    wchar_t path[MAX_PATH]{};
    if (FAILED(::SHGetFolderPathW(nullptr, csidl, nullptr, SHGFP_TYPE_CURRENT, path))) {
        return {};
    }
    return std::wstring(path);
}

// JoinPath concatenates two Win32 path segments. Inputs are base and leaf text;
// output contains exactly one backslash between non-empty segments.
std::wstring JoinPath(const std::wstring& base, const std::wstring& leaf) {
    if (base.empty()) {
        return leaf;
    }
    if (leaf.empty()) {
        return base;
    }
    if (base.back() == L'\\' || base.back() == L'/') {
        return base + leaf;
    }
    return base + L"\\" + leaf;
}

// LeafName extracts the last path segment. Input is a full path; output is the
// final file or directory name.
std::wstring LeafName(const std::wstring& path) {
    const std::size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

// DisabledStartupFolder returns this module's parking folder for Startup-folder
// entries. Input is a scope; output is a local appdata path, empty on failure.
std::wstring DisabledStartupFolder(StartupEntryScope scope) {
    const std::wstring localAppData = FolderPath(CSIDL_LOCAL_APPDATA);
    if (localAppData.empty()) {
        return {};
    }
    const wchar_t* scopeName = scope == StartupEntryScope::AllUsers ? L"AllUsers" : L"CurrentUser";
    return JoinPath(JoinPath(localAppData, kDisabledStartupFolderBase), scopeName);
}

// EnumerateStartupFolder appends entries from one Startup folder and its disabled
// parking folder. Inputs are output vector, scope and folder path; no return.
void EnumerateStartupFolder(std::vector<StartupEntry>& entries, StartupEntryScope scope, const std::wstring& folder) {
    if (folder.empty()) {
        return;
    }

    auto enumerateOneFolder = [&](const std::wstring& source, StartupEntryState state) {
        WIN32_FIND_DATAW data{};
        HANDLE find = ::FindFirstFileW(JoinPath(source, L"*").c_str(), &data);
        if (find == INVALID_HANDLE_VALUE) {
            return;
        }
        do {
            const std::wstring name(data.cFileName);
            if (name == L"." || name == L".." || (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                continue;
            }
            const std::wstring path = JoinPath(source, name);
            StartupEntry entry;
            entry.kind = StartupEntryKind::StartupFolder;
            entry.scope = scope;
            entry.state = state;
            entry.name = name;
            entry.command = path;
            entry.location = source;
            entry.filePath = state == StartupEntryState::Active ? path : JoinPath(folder, name);
            entry.disabledFilePath = state == StartupEntryState::Disabled ? path : JoinPath(DisabledStartupFolder(scope), name);
            AddProperty(entry, L"File attributes", std::to_wstring(data.dwFileAttributes));
            entries.push_back(std::move(entry));
        } while (::FindNextFileW(find, &data));
        ::FindClose(find);
    };

    enumerateOneFolder(folder, StartupEntryState::Active);
    const std::wstring disabled = DisabledStartupFolder(scope);
    if (!disabled.empty()) {
        enumerateOneFolder(disabled, StartupEntryState::Disabled);
    }
}

// ServiceStartState maps a service start type into StartupEntryState. Input is a
// SERVICE_*_START value; output is the state shown by the Startup page.
StartupEntryState ServiceStartState(DWORD startType) {
    if (startType == SERVICE_DISABLED) {
        return StartupEntryState::Disabled;
    }
    if (startType == SERVICE_DEMAND_START) {
        return StartupEntryState::Manual;
    }
    return StartupEntryState::Active;
}

// ServiceStartText formats a service start type. Input is a SERVICE_*_START value;
// output is a readable detail string.
std::wstring ServiceStartText(DWORD startType) {
    switch (startType) {
    case SERVICE_BOOT_START:
        return L"Boot";
    case SERVICE_SYSTEM_START:
        return L"System";
    case SERVICE_AUTO_START:
        return L"Automatic";
    case SERVICE_DEMAND_START:
        return L"Manual";
    case SERVICE_DISABLED:
        return L"Disabled";
    default:
        break;
    }
    return L"Unknown";
}

// ServiceCurrentStateText formats SCM's current runtime state. Input is one
// SERVICE_* state from ENUM_SERVICE_STATUS_PROCESSW; output is display-only and
// never drives an action.
std::wstring ServiceCurrentStateText(DWORD currentState) {
    switch (currentState) {
    case SERVICE_STOPPED:
        return L"Stopped";
    case SERVICE_START_PENDING:
        return L"Start pending";
    case SERVICE_STOP_PENDING:
        return L"Stop pending";
    case SERVICE_RUNNING:
        return L"Running";
    case SERVICE_CONTINUE_PENDING:
        return L"Continue pending";
    case SERVICE_PAUSE_PENDING:
        return L"Pause pending";
    case SERVICE_PAUSED:
        return L"Paused";
    default:
        break;
    }
    return L"Unknown";
}

// DriverServiceTypeText classifies the SCM service-type bits used for a driver
// row. Inputs are the existing enumeration status bits; output is informational
// only, so unknown combinations remain visible without any mutation path.
std::wstring DriverServiceTypeText(DWORD serviceType) {
    if ((serviceType & SERVICE_FILE_SYSTEM_DRIVER) != 0U) {
        return L"File system driver";
    }
    if ((serviceType & SERVICE_RECOGNIZER_DRIVER) != 0U) {
        return L"Recognizer driver";
    }
    if ((serviceType & SERVICE_KERNEL_DRIVER) != 0U) {
        return L"Kernel driver";
    }
    return L"Driver";
}

// AppendServiceRows adds one SCM enumeration page and records the service short
// names returned by that same page. Inputs are the already-filled SCM buffer and
// a query-only SCM handle; output rows retain the existing action boundaries.
void AppendServiceRows(std::vector<StartupEntry>& entries, const ENUM_SERVICE_STATUS_PROCESSW* services,
    DWORD servicesReturned, SC_HANDLE scm, std::vector<std::wstring>& scmServiceNames) {
    for (DWORD index = 0; index < servicesReturned; ++index) {
        const ENUM_SERVICE_STATUS_PROCESSW& service = services[index];
        if (!service.lpServiceName || !*service.lpServiceName) {
            continue;
        }
        const bool isDriver = (service.ServiceStatusProcess.dwServiceType & SERVICE_DRIVER) != 0U;
        ServiceHandle handle(::OpenServiceW(scm, service.lpServiceName, SERVICE_QUERY_CONFIG));
        DWORD startType = SERVICE_DEMAND_START;
        std::wstring binaryPath;
        std::wstring description;
        bool hasConfiguration = false;
        if (handle.valid()) {
            DWORD configBytes = 0;
            ::QueryServiceConfigW(handle.get(), nullptr, 0, &configBytes);
            if (configBytes > 0) {
                std::vector<BYTE> configBuffer(configBytes, 0);
                auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());
                if (::QueryServiceConfigW(handle.get(), config, configBytes, &configBytes)) {
                    hasConfiguration = true;
                    startType = config->dwStartType;
                    if (config->lpBinaryPathName) {
                        binaryPath = config->lpBinaryPathName;
                    }
                }
            }

            SERVICE_DESCRIPTIONW* desc = nullptr;
            DWORD descBytes = 0;
            ::QueryServiceConfig2W(handle.get(), SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &descBytes);
            if (descBytes > 0) {
                std::vector<BYTE> descBuffer(descBytes, 0);
                if (::QueryServiceConfig2W(handle.get(), SERVICE_CONFIG_DESCRIPTION, descBuffer.data(), descBytes, &descBytes)) {
                    desc = reinterpret_cast<SERVICE_DESCRIPTIONW*>(descBuffer.data());
                    if (desc->lpDescription) {
                        description = desc->lpDescription;
                    }
                }
            }
        }

        StartupEntry entry;
        entry.kind = isDriver ? StartupEntryKind::DriverService : StartupEntryKind::Service;
        entry.scope = StartupEntryScope::LocalMachine;
        entry.state = isDriver && !hasConfiguration ? StartupEntryState::Unknown : ServiceStartState(startType);
        entry.name = service.lpDisplayName && *service.lpDisplayName ? service.lpDisplayName : service.lpServiceName;
        entry.command = binaryPath;
        entry.location = L"Service Control Manager";
        entry.description = description;
        entry.serviceName = service.lpServiceName;
        entry.serviceStartType = startType;
        AddProperty(entry, L"Service name", entry.serviceName);
        if (isDriver) {
            AddProperty(entry, L"Driver type", DriverServiceTypeText(service.ServiceStatusProcess.dwServiceType));
            AddProperty(entry, L"Startup type", hasConfiguration ? ServiceStartText(startType) : L"Unavailable (configuration query failed)");
            AddProperty(entry, L"Image path", binaryPath.empty() ? L"Unavailable" : binaryPath);
            AddProperty(entry, L"Current status", ServiceCurrentStateText(service.ServiceStatusProcess.dwCurrentState));
            AddProperty(entry, L"Actions", L"Read-only SCM observation; enable, disable, delete, and open are unavailable.");
        } else {
            AddProperty(entry, L"Start type", ServiceStartText(startType));
            AddProperty(entry, L"Current state", std::to_wstring(service.ServiceStatusProcess.dwCurrentState));
        }
        scmServiceNames.push_back(entry.serviceName);
        entries.push_back(std::move(entry));
    }
}

// EnumerateServices appends every available SCM service/driver row while keeping
// an exact per-pass short-name set for later registry cross-checking. It uses only
// SC_MANAGER_ENUMERATE_SERVICE and SERVICE_QUERY_CONFIG; false means that the
// returned SCM pages are incomplete and must not be used for mismatch findings.
bool EnumerateServices(std::vector<StartupEntry>& entries, std::vector<std::wstring>& scmServiceNames) {
    ServiceHandle scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
    if (!scm.valid()) {
        StartupEntry error;
        error.kind = StartupEntryKind::Service;
        error.scope = StartupEntryScope::LocalMachine;
        error.state = StartupEntryState::Unknown;
        error.name = L"Service enumeration failed";
        error.description = Ksword::Core::LastErrorMessage();
        entries.push_back(std::move(error));
        return false;
    }

    DWORD resumeHandle = 0;
    for (DWORD page = 0; page < kMaxServiceEnumerationPages; ++page) {
        DWORD bytesNeeded = 0;
        DWORD servicesReturned = 0;
        // A zero-byte probe is only sizing. Keep the live resume handle intact
        // until the corresponding data-bearing call has consumed this page.
        DWORD probeResumeHandle = resumeHandle;
        if (::EnumServicesStatusExW(scm.get(), SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
                nullptr, 0, &bytesNeeded, &servicesReturned, &probeResumeHandle, nullptr)) {
            return true;
        }
        if (::GetLastError() != ERROR_MORE_DATA || bytesNeeded == 0) {
            return false;
        }

        const DWORD pageBytes = std::min(bytesNeeded, kMaxServiceEnumerationPageBytes);
        std::vector<BYTE> buffer(pageBytes, 0);
        servicesReturned = 0;
        const BOOL enumerated = ::EnumServicesStatusExW(scm.get(), SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);
        const DWORD error = enumerated ? ERROR_SUCCESS : ::GetLastError();
        if (!enumerated && error != ERROR_MORE_DATA) {
            return false;
        }
        AppendServiceRows(entries, reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data()), servicesReturned,
            scm.get(), scmServiceNames);
        if (enumerated) {
            return true;
        }
    }
    return false;
}

// ServiceNameWasReturned compares two SCM service short names case-insensitively.
// Inputs are one completed enumeration's names and one registry subkey name;
// output is true only when SCM actually returned that name in the same pass.
bool ServiceNameWasReturned(const std::vector<std::wstring>& scmServiceNames, const std::wstring& serviceName) {
    return std::any_of(scmServiceNames.cbegin(), scmServiceNames.cend(), [&serviceName](const std::wstring& candidate) {
        return ::_wcsicmp(candidate.c_str(), serviceName.c_str()) == 0;
    });
}

// IsUninstantiatedUserServiceTemplate excludes per-user service template records
// that do not represent a running instance. Input is the registry Type value;
// output follows the documented service type flags without calling SCM.
bool IsUninstantiatedUserServiceTemplate(DWORD serviceType) {
    return (serviceType & kServiceUserServiceBit) != 0U &&
        (serviceType & kServiceUserServiceInstanceBit) == 0U;
}

// AppendRegistryOnlyServices enumerates Services registry records that were not
// returned by a completed SCM pass. Inputs are the destination rows and SCM short
// names; output is false when the root scan is incomplete, so callers make no
// registry/SCM mismatch claim for that pass. All appended rows remain read-only.
bool AppendRegistryOnlyServices(std::vector<StartupEntry>& entries, const std::vector<std::wstring>& scmServiceNames) {
    RegKey servicesRoot = OpenRegistryKey(HKEY_LOCAL_MACHINE, kServicesRegistryRoot, KEY_READ, KEY_WOW64_64KEY);
    if (!servicesRoot.valid()) {
        return false;
    }

    std::vector<StartupEntry> registryOnlyEntries;
    std::vector<wchar_t> serviceNameBuffer(256, L'\0');
    for (DWORD index = 0;; ++index) {
        DWORD serviceNameLength = static_cast<DWORD>(serviceNameBuffer.size() - 1);
        FILETIME lastWriteTime{};
        LSTATUS status = ::RegEnumKeyExW(servicesRoot.get(), index, serviceNameBuffer.data(), &serviceNameLength,
            nullptr, nullptr, nullptr, &lastWriteTime);
        while (status == ERROR_MORE_DATA && serviceNameBuffer.size() < 32768) {
            serviceNameBuffer.resize(serviceNameBuffer.size() * 2, L'\0');
            serviceNameLength = static_cast<DWORD>(serviceNameBuffer.size() - 1);
            status = ::RegEnumKeyExW(servicesRoot.get(), index, serviceNameBuffer.data(), &serviceNameLength,
                nullptr, nullptr, nullptr, &lastWriteTime);
        }
        if (status == ERROR_NO_MORE_ITEMS) {
            for (StartupEntry& entry : registryOnlyEntries) {
                entries.push_back(std::move(entry));
            }
            return true;
        }
        if (status != ERROR_SUCCESS) {
            return false;
        }

        const std::wstring serviceName(serviceNameBuffer.data(), serviceNameLength);
        if (serviceName.empty() || ServiceNameWasReturned(scmServiceNames, serviceName)) {
            continue;
        }

        HKEY rawServiceKey = nullptr;
        if (::RegOpenKeyExW(servicesRoot.get(), serviceName.c_str(), 0, KEY_READ, &rawServiceKey) != ERROR_SUCCESS) {
            // Do not publish a partial cross-source result when an enumerated
            // child cannot be read; the caller discards this pass's local rows.
            return false;
        }
        RegKey serviceKey(rawServiceKey);
        DWORD serviceType = 0;
        if (!ReadRegistryDword(serviceKey.get(), L"Type", serviceType) ||
            (serviceType & (SERVICE_DRIVER | SERVICE_WIN32)) == 0U ||
            IsUninstantiatedUserServiceTemplate(serviceType)) {
            continue;
        }

        DWORD startType = 0;
        const bool hasStartType = ReadRegistryDword(serviceKey.get(), L"Start", startType);
        DWORD errorControl = 0;
        const bool hasErrorControl = ReadRegistryDword(serviceKey.get(), L"ErrorControl", errorControl);
        DWORD delayedAutoStart = 0;
        const bool hasDelayedAutoStart = ReadRegistryDword(serviceKey.get(), L"DelayedAutoStart", delayedAutoStart);
        const std::wstring imagePath = ReadRegistryString(serviceKey.get(), L"ImagePath");
        const std::wstring objectName = ReadRegistryString(serviceKey.get(), L"ObjectName");
        std::wstring serviceDll;
        HKEY rawParametersKey = nullptr;
        if (::RegOpenKeyExW(serviceKey.get(), L"Parameters", 0, KEY_READ, &rawParametersKey) == ERROR_SUCCESS) {
            RegKey parametersKey(rawParametersKey);
            serviceDll = ReadRegistryString(parametersKey.get(), L"ServiceDll");
        }

        StartupEntry entry;
        entry.kind = StartupEntryKind::RegistryOnlyService;
        entry.scope = StartupEntryScope::LocalMachine;
        entry.state = hasStartType ? ServiceStartState(startType) : StartupEntryState::Unknown;
        entry.name = serviceName;
        entry.command = imagePath;
        entry.location = RegistryLocationText(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY,
            std::wstring(kServicesRegistryRoot) + L"\\" + serviceName);
        entry.description = L"Registry record was not returned by this SCM enumeration; access filtering is possible and this is not a hidden-service verdict.";
        entry.serviceName = serviceName;
        entry.serviceStartType = startType;
        AddProperty(entry, L"Service name", entry.serviceName);
        AddProperty(entry, L"SCM observation", L"Present in Services registry; this SCM enumeration did not return it (access filtering is possible).");
        AddProperty(entry, L"Type", std::to_wstring(serviceType));
        if (hasStartType) {
            AddProperty(entry, L"Start", ServiceStartText(startType) + L" (" + std::to_wstring(startType) + L")");
        }
        if (hasErrorControl) {
            AddProperty(entry, L"Error control", std::to_wstring(errorControl));
        }
        if (hasDelayedAutoStart) {
            AddProperty(entry, L"Delayed auto-start", delayedAutoStart != 0U ? L"true" : L"false");
        }
        AddProperty(entry, L"Object name", objectName);
        AddProperty(entry, L"Service DLL", serviceDll);
        AddProperty(entry, L"Image path", imagePath);
        AddProperty(entry, L"Actions", L"Read-only source observation; enable, disable, delete, and open are unavailable.");
        registryOnlyEntries.push_back(std::move(entry));
    }
}

// WindowsDirectory returns the system Windows directory. There is no input;
// output is empty when GetWindowsDirectoryW fails.
std::wstring WindowsDirectory() {
    wchar_t path[MAX_PATH]{};
    const UINT chars = ::GetWindowsDirectoryW(path, MAX_PATH);
    if (chars == 0 || chars >= MAX_PATH) {
        return {};
    }
    return std::wstring(path);
}

// EnumerateTaskFilesRecursive appends scheduled-task rows by scanning the Task
// Scheduler file store. Inputs are output vector, root path, current folder and
// relative task path; processing is read-only during enumeration while actions
// later use Task Scheduler COM for enable/disable/delete; no return.
void EnumerateTaskFilesRecursive(std::vector<StartupEntry>& entries, const std::wstring& root,
    const std::wstring& folder, const std::wstring& relative) {
    WIN32_FIND_DATAW data{};
    HANDLE find = ::FindFirstFileW(JoinPath(folder, L"*").c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        const std::wstring name(data.cFileName);
        if (name == L"." || name == L"..") {
            continue;
        }
        const std::wstring fullPath = JoinPath(folder, name);
        const std::wstring taskRelative = relative.empty() ? name : JoinPath(relative, name);
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            EnumerateTaskFilesRecursive(entries, root, fullPath, taskRelative);
            continue;
        }

        StartupEntry entry;
        entry.kind = StartupEntryKind::ScheduledTaskFacade;
        entry.scope = StartupEntryScope::LocalMachine;
        entry.state = StartupEntryState::Unknown;
        entry.name = taskRelative;
        entry.location = fullPath;
        entry.taskPath = L"\\" + taskRelative;
        AddProperty(entry, L"Task Scheduler", L"File-store row; actions use Task Scheduler COM by task path.");
        AddProperty(entry, L"Task path", entry.taskPath);
        AddProperty(entry, L"File attributes", std::to_wstring(data.dwFileAttributes));
        entries.push_back(std::move(entry));
    } while (::FindNextFileW(find, &data));
    ::FindClose(find);
}

// EnumerateScheduledTaskFacade appends scheduled-task entry rows. Input is the
// output vector; processing scans the on-disk task store for fast display and
// records task paths that StartupActions resolves through Task Scheduler COM.
void EnumerateScheduledTaskFacade(std::vector<StartupEntry>& entries) {
    const std::wstring windows = WindowsDirectory();
    if (windows.empty()) {
        return;
    }
    const std::wstring tasksRoot = JoinPath(JoinPath(windows, L"System32"), L"Tasks");
    EnumerateTaskFilesRecursive(entries, tasksRoot, tasksRoot, L"");
}

} // namespace

StartupEnumerationResult EnumerateStartupEntries() {
    StartupEnumerationResult result;
    EnumerateRegistryKey(result.entries, HKEY_CURRENT_USER, StartupEntryScope::CurrentUser, 0, kRunKey, StartupEntryKind::RegistryRun);
    EnumerateRegistryKey(result.entries, HKEY_CURRENT_USER, StartupEntryScope::CurrentUser, 0, kRunOnceKey, StartupEntryKind::RegistryRunOnce);
    EnumerateRegistryKey(result.entries, HKEY_LOCAL_MACHINE, StartupEntryScope::LocalMachine, KEY_WOW64_64KEY, kRunKey, StartupEntryKind::RegistryRun);
    EnumerateRegistryKey(result.entries, HKEY_LOCAL_MACHINE, StartupEntryScope::LocalMachine, KEY_WOW64_64KEY, kRunOnceKey, StartupEntryKind::RegistryRunOnce);
    EnumerateRegistryKey(result.entries, HKEY_LOCAL_MACHINE, StartupEntryScope::LocalMachine, KEY_WOW64_32KEY, kRunKey, StartupEntryKind::RegistryRun);
    EnumerateRegistryKey(result.entries, HKEY_LOCAL_MACHINE, StartupEntryScope::LocalMachine, KEY_WOW64_32KEY, kRunOnceKey, StartupEntryKind::RegistryRunOnce);

    EnumerateDisabledRegistryKey(result.entries, HKEY_CURRENT_USER, StartupEntryScope::CurrentUser, 0, kRunKey, StartupEntryKind::RegistryRun);
    EnumerateDisabledRegistryKey(result.entries, HKEY_CURRENT_USER, StartupEntryScope::CurrentUser, 0, kRunOnceKey, StartupEntryKind::RegistryRunOnce);
    EnumerateDisabledRegistryKey(result.entries, HKEY_LOCAL_MACHINE, StartupEntryScope::LocalMachine, KEY_WOW64_64KEY, kRunKey, StartupEntryKind::RegistryRun);
    EnumerateDisabledRegistryKey(result.entries, HKEY_LOCAL_MACHINE, StartupEntryScope::LocalMachine, KEY_WOW64_64KEY, kRunOnceKey, StartupEntryKind::RegistryRunOnce);
    EnumerateDisabledRegistryKey(result.entries, HKEY_LOCAL_MACHINE, StartupEntryScope::LocalMachine, KEY_WOW64_32KEY, kRunKey, StartupEntryKind::RegistryRun);
    EnumerateDisabledRegistryKey(result.entries, HKEY_LOCAL_MACHINE, StartupEntryScope::LocalMachine, KEY_WOW64_32KEY, kRunOnceKey, StartupEntryKind::RegistryRunOnce);

    EnumerateStartupFolder(result.entries, StartupEntryScope::CurrentUser, FolderPath(CSIDL_STARTUP));
    EnumerateStartupFolder(result.entries, StartupEntryScope::AllUsers, FolderPath(CSIDL_COMMON_STARTUP));
    std::vector<std::wstring> scmServiceNames;
    if (!EnumerateServices(result.entries, scmServiceNames)) {
        result.diagnosticText = L"服务来源交叉验证不可用：SCM 服务枚举未完整完成。";
    } else if (!AppendRegistryOnlyServices(result.entries, scmServiceNames)) {
        result.diagnosticText = L"服务来源交叉验证不可用：Services 注册表读取未完整完成。";
    }
    EnumerateScheduledTaskFacade(result.entries);

    result.success = true;
    return result;
}

} // namespace Ksword::Features::Startup
