#include "ServiceEnumerator.h"

#include "../../../Ksword5.1/Ksword5.1/ksword/service/service.h"

#include <algorithm>
#include <cwctype>
#include <string>
#include <utility>

namespace Ksword::Features::Service {
namespace {

std::wstring WidenUtf8(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int required = ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (required <= 0) {
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(required), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), required);
    return wide;
}

std::wstring LowerText(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const wchar_t character) {
        return static_cast<wchar_t>(std::towlower(character));
    });
    return value;
}

std::wstring TrimText(std::wstring value) {
    const auto begin = std::find_if_not(value.begin(), value.end(), [](const wchar_t ch) { return std::iswspace(ch) != 0; });
    const auto end = std::find_if_not(value.rbegin(), value.rend(), [](const wchar_t ch) { return std::iswspace(ch) != 0; }).base();
    return begin >= end ? std::wstring{} : std::wstring(begin, end);
}

// ExpandDependencyList turns the SCM's double-null-terminated dependency block
// into one readable line. The reusable layer hands it over with the embedded
// nulls intact so callers can decide how to present it.
std::wstring ExpandDependencyList(const std::wstring& multiSz) {
    std::wstring text;
    std::size_t cursor = 0;
    while (cursor < multiSz.size()) {
        const std::size_t end = multiSz.find(L'\0', cursor);
        const std::wstring item = multiSz.substr(cursor, end == std::wstring::npos ? std::wstring::npos : end - cursor);
        if (!item.empty()) {
            if (!text.empty()) {
                text += L", ";
            }
            text += item;
        }
        if (end == std::wstring::npos) {
            break;
        }
        cursor = end + 1;
    }
    return text;
}

// SplitDependencyList preserves the SCM distinction between a service short
// name and a +load-order-group entry. The formatted dependency string remains
// useful for the existing list view, while these vectors let detail consumers
// export or render the two meanings without parsing presentation text.
void SplitDependencyList(const std::wstring& multiSz,
    std::vector<std::wstring>* serviceNames,
    std::vector<std::wstring>* loadOrderGroups) {
    if (!serviceNames || !loadOrderGroups) {
        return;
    }
    serviceNames->clear();
    loadOrderGroups->clear();
    std::size_t cursor = 0;
    while (cursor < multiSz.size()) {
        const std::size_t end = multiSz.find(L'\0', cursor);
        const std::wstring item = multiSz.substr(cursor, end == std::wstring::npos ? std::wstring::npos : end - cursor);
        if (!item.empty()) {
            if (item.front() == L'+' && item.size() > 1) {
                loadOrderGroups->push_back(item.substr(1));
            } else {
                serviceNames->push_back(item);
            }
        }
        if (end == std::wstring::npos) {
            break;
        }
        cursor = end + 1;
    }
}

std::wstring JoinNames(const std::vector<std::wstring>& names) {
    std::wstring text;
    for (const std::wstring& name : names) {
        if (name.empty()) {
            continue;
        }
        if (!text.empty()) {
            text += L", ";
        }
        text += name;
    }
    return text;
}

// ExecutablePathFromCommandLine extracts just the image path from a service's
// binary path. Quoted paths are taken verbatim; an unquoted one is cut at the
// first space that ends a token looking like an executable, since service
// command lines routinely carry arguments (-k netsvcs and friends).
std::wstring ExecutablePathFromCommandLine(const std::wstring& commandLine) {
    const std::wstring trimmed = TrimText(commandLine);
    if (trimmed.empty()) {
        return {};
    }
    if (trimmed.front() == L'"') {
        const std::size_t closing = trimmed.find(L'"', 1);
        return closing == std::wstring::npos ? trimmed.substr(1) : trimmed.substr(1, closing - 1);
    }
    // Driver paths often arrive in NT form; those have no arguments at all.
    const std::wstring lowered = LowerText(trimmed);
    const std::size_t extension = lowered.find(L".exe");
    if (extension != std::wstring::npos) {
        return trimmed.substr(0, extension + 4);
    }
    const std::size_t space = trimmed.find(L' ');
    return space == std::wstring::npos ? trimmed : trimmed.substr(0, space);
}

// ResolveImagePath maps a service image path onto something the filesystem can
// answer for. The SCM stores driver paths relative to the system root and in NT
// device form, neither of which GetFileAttributesW understands as-is.
std::wstring ResolveImagePath(const std::wstring& imagePath) {
    std::wstring path = TrimText(imagePath);
    if (path.empty()) {
        return {};
    }
    const std::wstring lowered = LowerText(path);
    if (lowered.rfind(L"\\systemroot\\", 0) == 0) {
        wchar_t systemRoot[MAX_PATH]{};
        if (::GetWindowsDirectoryW(systemRoot, MAX_PATH) > 0) {
            return std::wstring(systemRoot) + path.substr(11);
        }
        return {};
    }
    if (lowered.rfind(L"\\??\\", 0) == 0) {
        return path.substr(4);
    }
    if (lowered.rfind(L"system32\\", 0) == 0 || lowered.rfind(L"\\system32\\", 0) == 0) {
        wchar_t systemRoot[MAX_PATH]{};
        if (::GetWindowsDirectoryW(systemRoot, MAX_PATH) > 0) {
            const std::wstring suffix = path.front() == L'\\' ? path.substr(1) : path;
            return std::wstring(systemRoot) + L"\\" + suffix;
        }
        return {};
    }
    if (path.size() >= 2 && path[1] == L':') {
        return path;
    }
    return {};
}

bool FileExists(const std::wstring& path) {
    if (path.empty()) {
        return false;
    }
    const DWORD attributes = ::GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool IsUnderSystemDirectory(const std::wstring& resolvedPath) {
    if (resolvedPath.empty()) {
        return false;
    }
    wchar_t systemRoot[MAX_PATH]{};
    if (::GetWindowsDirectoryW(systemRoot, MAX_PATH) == 0) {
        return false;
    }
    const std::wstring lowered = LowerText(resolvedPath);
    const std::wstring loweredRoot = LowerText(std::wstring(systemRoot));
    return lowered.rfind(loweredRoot, 0) == 0;
}

bool IsSystemAccount(const std::wstring& accountName) {
    const std::wstring lowered = LowerText(accountName);
    return lowered == L"localsystem" ||
        lowered == L"nt authority\\system" ||
        lowered == L".\\localsystem";
}

// BuildRiskText flags the service configurations that matter in an audit. Every
// check below describes a concrete, verifiable property of the configuration --
// none of them is a verdict about whether the service is malicious, and the text
// is worded so the operator can go and check the same thing by hand.
std::wstring BuildRiskText(const ServiceEntry& entry) {
    std::vector<std::wstring> flags;

    const std::wstring imagePath = ExecutablePathFromCommandLine(entry.binaryPath);
    const std::wstring resolvedPath = ResolveImagePath(imagePath);

    // An unquoted path containing spaces lets Windows try C:\Program.exe before
    // the real target. It is a long-standing local privilege-escalation surface
    // and is trivially checkable, so it is worth naming precisely.
    const std::wstring trimmedCommand = TrimText(entry.binaryPath);
    if (!trimmedCommand.empty() && trimmedCommand.front() != L'"' &&
        imagePath.find(L' ') != std::wstring::npos) {
        flags.push_back(L"未加引号路径");
    }

    if (!resolvedPath.empty() && !FileExists(resolvedPath)) {
        flags.push_back(L"映像缺失");
    }

    if (IsSystemAccount(entry.accountName) && !resolvedPath.empty() && !IsUnderSystemDirectory(resolvedPath)) {
        flags.push_back(L"系统账户·非系统目录");
    }

    const bool isDriver = (entry.serviceType & (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER)) != 0;
    if (isDriver && (entry.startType == SERVICE_BOOT_START || entry.startType == SERVICE_SYSTEM_START ||
            entry.startType == SERVICE_AUTO_START)) {
        flags.push_back(L"驱动·自启");
    }

    std::wstring text;
    for (const std::wstring& flag : flags) {
        if (!text.empty()) {
            text += L" / ";
        }
        text += flag;
    }
    return text;
}

bool IsExplicitlyUnsupportedOptionalQueryError(const std::uint32_t win32Error) {
    switch (win32Error) {
    case ERROR_CALL_NOT_IMPLEMENTED:
    case ERROR_NOT_SUPPORTED:
    case ERROR_OLD_WIN_VERSION:
        return true;
    default:
        return false;
    }
}

ServiceDetailSection OptionalQueryFailure(const std::string& errorText, const std::uint32_t win32Error) {
    ServiceDetailSection section{};
    section.availability = IsExplicitlyUnsupportedOptionalQueryError(win32Error)
        ? ServiceDetailAvailability::Unsupported
        : ServiceDetailAvailability::Partial;
    const std::wstring detail = WidenUtf8(errorText);
    section.diagnosticText = ServiceDetailAvailabilityText(section.availability) + L"：";
    if (!detail.empty()) {
        section.diagnosticText += detail;
    } else if (win32Error != ERROR_SUCCESS) {
        section.diagnosticText += L"Win32 错误 " + std::to_wstring(win32Error);
    } else {
        section.diagnosticText += L"服务控制管理器未返回诊断。";
    }
    return section;
}

ServiceDetailSection OptionalQueryInvalidInput(const wchar_t* detail) {
    ServiceDetailSection section{};
    section.availability = ServiceDetailAvailability::Partial;
    section.diagnosticText = L"Partial：";
    section.diagnosticText += detail ? detail : L"查询输入无效。";
    return section;
}

std::wstring FailureActionText(const std::uint32_t actionType, const std::uint32_t delayMs) {
    std::wstring action;
    switch (actionType) {
    case SC_ACTION_NONE:
        action = L"不执行操作";
        break;
    case SC_ACTION_RESTART:
        action = L"重启服务";
        break;
    case SC_ACTION_REBOOT:
        action = L"重启计算机";
        break;
    case SC_ACTION_RUN_COMMAND:
        action = L"运行恢复命令";
        break;
    default:
        action = L"未知操作(" + std::to_wstring(actionType) + L")";
        break;
    }
    return action + L"（延迟 " + std::to_wstring(delayMs) + L" 毫秒）";
}

std::wstring SectionStatusValue(const ServiceDetailSection& section) {
    return section.diagnosticText.empty()
        ? ServiceDetailAvailabilityText(section.availability)
        : section.diagnosticText;
}

void AppendFailureSettingsProperties(std::vector<ServiceProperty>* properties,
    const ServiceFailureSettingsSnapshot& settings,
    const ServiceDetailSection& status) {
    if (!properties) {
        return;
    }
    properties->push_back({ L"恢复策略查询", SectionStatusValue(status) });
    if (status.availability != ServiceDetailAvailability::Available) {
        return;
    }

    properties->push_back({ L"故障恢复配置", settings.hasFailureActions ? L"已配置" : L"未配置" });
    properties->push_back({ L"恢复计数重置周期", settings.hasFailureActions
        ? std::to_wstring(settings.resetPeriodSeconds) + L" 秒"
        : L"-" });
    properties->push_back({ L"恢复重启消息", settings.hasFailureActions
        ? (settings.rebootMessage.empty() ? L"-" : settings.rebootMessage)
        : L"-" });
    properties->push_back({ L"恢复命令", settings.hasFailureActions
        ? (settings.command.empty() ? L"-" : settings.command)
        : L"-" });
    properties->push_back({ L"非崩溃失败也触发恢复", settings.hasFailureActionsFlag
        ? (settings.failureActionsOnNonCrash ? L"是" : L"否")
        : L"未报告" });
    for (std::size_t index = 0; index < settings.actions.size(); ++index) {
        const ServiceFailureActionSnapshot& action = settings.actions[index];
        properties->push_back({
            L"第 " + std::to_wstring(index + 1) + L" 次失败后的操作",
            action.actionText,
        });
    }
}

void AppendReverseDependencyProperties(std::vector<ServiceProperty>* properties,
    const ServiceDependencySnapshot& dependencies,
    const ServiceDetailSection& status) {
    if (!properties) {
        return;
    }
    properties->push_back({ L"反向依赖查询", SectionStatusValue(status) });
    if (status.availability == ServiceDetailAvailability::Available) {
        const std::wstring names = JoinNames(dependencies.directDependentServiceNames);
        properties->push_back({ L"直接反向依赖服务", names.empty() ? L"无" : names });
    }
}

ServiceEntry BuildEntry(const ks::service::ServiceRecord& record) {
    ServiceEntry entry{};
    entry.serviceName = record.serviceName;
    entry.displayName = record.displayName.empty() ? record.serviceName : record.displayName;
    entry.description = record.description;
    entry.hasStatus = record.hasStatus;
    entry.hasConfig = record.hasConfig;
    entry.hasDescription = record.hasDescription;

    if (record.hasStatus) {
        entry.serviceType = record.status.serviceType;
        entry.currentState = record.status.currentState;
        entry.controlsAccepted = record.status.controlsAccepted;
        entry.win32ExitCode = record.status.win32ExitCode;
        entry.serviceSpecificExitCode = record.status.serviceSpecificExitCode;
        entry.checkPoint = record.status.checkPoint;
        entry.waitHint = record.status.waitHint;
        entry.serviceFlags = record.status.serviceFlags;
        entry.processId = record.status.processId;
    }
    if (record.hasConfig) {
        // The config's service type is the configured one; the status block
        // reports what the SCM currently has loaded. They agree in practice, and
        // the configured value is the one that survives a stopped service.
        entry.serviceType = record.config.serviceType != 0 ? record.config.serviceType : entry.serviceType;
        entry.startType = record.config.startType;
        entry.errorControl = record.config.errorControl;
        entry.tagId = record.config.tagId;
        entry.binaryPath = record.config.binaryPath;
        entry.loadOrderGroup = record.config.loadOrderGroup;
        entry.dependencies = ExpandDependencyList(record.config.dependenciesMultiSz);
        SplitDependencyList(record.config.dependenciesMultiSz,
            &entry.dependencyServiceNames,
            &entry.dependencyLoadOrderGroups);
        entry.accountName = record.config.accountName;
        entry.delayedAutoStart = record.config.delayedAutoStart;
        if (entry.displayName.empty()) {
            entry.displayName = record.config.displayName;
        }
    }

    // A service whose status or config could not be read is kept in the table
    // with the reason attached. Silently dropping it would hide the services an
    // audit most wants to see, since an unreadable config usually means a
    // permission or tampering issue rather than an empty result.
    std::wstring diagnostic;
    if (!record.hasStatus && !record.statusErrorText.empty()) {
        diagnostic += L"状态读取失败：" + WidenUtf8(record.statusErrorText);
    }
    if (!record.hasConfig && !record.configErrorText.empty()) {
        if (!diagnostic.empty()) {
            diagnostic += L"；";
        }
        diagnostic += L"配置读取失败：" + WidenUtf8(record.configErrorText);
    }
    if (!record.hasDescription && !record.descriptionErrorText.empty()) {
        if (!diagnostic.empty()) {
            diagnostic += L"；";
        }
        diagnostic += L"描述读取失败：" + WidenUtf8(record.descriptionErrorText);
    }
    entry.diagnosticText = std::move(diagnostic);

    if (entry.accountName.empty()) {
        entry.accountName = entry.hasConfig ? L"-" : L"未知";
    }
    entry.riskText = BuildRiskText(entry);
    return entry;
}

} // namespace

std::wstring ServiceDetailAvailabilityText(const ServiceDetailAvailability availability) {
    switch (availability) {
    case ServiceDetailAvailability::Available:
        return L"Available";
    case ServiceDetailAvailability::Unsupported:
        return L"Unsupported";
    case ServiceDetailAvailability::Partial:
    default:
        return L"Partial";
    }
}

std::wstring ResolveServiceImagePathForBrowser(const std::wstring& binaryPath) {
    return ResolveImagePath(ExecutablePathFromCommandLine(binaryPath));
}

ServiceDetailSnapshot QueryServiceReadOnlyDetails(const ServiceEntry& entry) {
    ServiceDetailSnapshot snapshot{};
    snapshot.entry = entry;
    snapshot.properties = ServicePropertiesForEntry(entry);
    snapshot.dependencies.directServiceNames = entry.dependencyServiceNames;
    snapshot.dependencies.loadOrderGroups = entry.dependencyLoadOrderGroups;

    if (entry.serviceName.empty()) {
        snapshot.failureSettingsStatus = OptionalQueryInvalidInput(L"服务名为空，无法查询恢复策略。");
        snapshot.reverseDependenciesStatus = OptionalQueryInvalidInput(L"服务名为空，无法查询反向依赖。");
        AppendFailureSettingsProperties(&snapshot.properties, snapshot.failureSettings, snapshot.failureSettingsStatus);
        AppendReverseDependencyProperties(&snapshot.properties, snapshot.dependencies, snapshot.reverseDependenciesStatus);
        return snapshot;
    }

    ks::service::FailureSettings failureSettings;
    std::string failureErrorText;
    std::uint32_t failureWin32Error = ERROR_SUCCESS;
    if (ks::service::QueryServiceFailureSettings(
            entry.serviceName, &failureSettings, &failureErrorText, &failureWin32Error)) {
        snapshot.failureSettings.resetPeriodSeconds = failureSettings.resetPeriodSeconds;
        snapshot.failureSettings.rebootMessage = failureSettings.rebootMessage;
        snapshot.failureSettings.command = failureSettings.command;
        snapshot.failureSettings.failureActionsOnNonCrash = failureSettings.failureActionsOnNonCrash;
        snapshot.failureSettings.hasFailureActions = failureSettings.hasFailureActions;
        snapshot.failureSettings.hasFailureActionsFlag = failureSettings.hasFailureActionsFlag;
        snapshot.failureSettings.actions.reserve(failureSettings.actions.size());
        for (const ks::service::FailureAction& action : failureSettings.actions) {
            ServiceFailureActionSnapshot row{};
            row.actionType = action.type;
            row.delayMs = action.delayMs;
            row.actionText = FailureActionText(row.actionType, row.delayMs);
            snapshot.failureSettings.actions.push_back(std::move(row));
        }
    } else {
        snapshot.failureSettingsStatus = OptionalQueryFailure(failureErrorText, failureWin32Error);
    }

    std::vector<std::wstring> reverseDependencies;
    std::string reverseErrorText;
    std::uint32_t reverseWin32Error = ERROR_SUCCESS;
    if (ks::service::QueryDependentServiceNames(
            entry.serviceName, SERVICE_STATE_ALL, &reverseDependencies, &reverseErrorText, &reverseWin32Error)) {
        snapshot.dependencies.directDependentServiceNames = std::move(reverseDependencies);
    } else {
        snapshot.reverseDependenciesStatus = OptionalQueryFailure(reverseErrorText, reverseWin32Error);
    }

    AppendFailureSettingsProperties(&snapshot.properties, snapshot.failureSettings, snapshot.failureSettingsStatus);
    AppendReverseDependencyProperties(&snapshot.properties, snapshot.dependencies, snapshot.reverseDependenciesStatus);
    return snapshot;
}

ServiceEnumerationResult EnumerateServices() {
    ServiceEnumerationResult result{};

    std::vector<ks::service::ServiceRecord> records;
    std::string errorText;
    std::uint32_t win32Error = 0;
    // Drivers are enumerated alongside Win32 services on purpose: on an ARK page
    // the kernel and file-system driver services are the interesting half, and
    // splitting them into a separate view would only hide them.
    const std::uint32_t typeMask =
        SERVICE_WIN32 | SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_ADAPTER | SERVICE_RECOGNIZER_DRIVER;
    if (!ks::service::EnumerateServiceRecords(typeMask, SERVICE_STATE_ALL, &records, &errorText, &win32Error)) {
        result.success = false;
        result.diagnosticText = L"服务枚举失败：" + WidenUtf8(errorText);
        return result;
    }

    result.entries.reserve(records.size());
    for (const ks::service::ServiceRecord& record : records) {
        result.entries.push_back(BuildEntry(record));
    }
    result.success = true;
    return result;
}

ServiceEnumerationResult QuerySingleService(const std::wstring& serviceName) {
    ServiceEnumerationResult result{};
    if (serviceName.empty()) {
        result.diagnosticText = L"服务名为空，无法查询。";
        return result;
    }

    ks::service::ServiceRecord record;
    std::string errorText;
    std::uint32_t win32Error = 0;
    if (!ks::service::QueryServiceRecord(serviceName, &record, &errorText, &win32Error)) {
        result.diagnosticText = L"查询服务失败：" + WidenUtf8(errorText);
        return result;
    }
    result.entries.push_back(BuildEntry(record));
    result.success = true;
    return result;
}

} // namespace Ksword::Features::Service
