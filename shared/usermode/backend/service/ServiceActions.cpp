#include "ServiceActions.h"

#include "../../../../Ksword5.1/Ksword5.1/ksword/service/service.h"

#include <string>

namespace ks::r3::service {
namespace {

// kTransitionTimeoutMs bounds every wait. The SCM reports a service's own
// waitHint, but a service that ignores its hint would otherwise hang the worker
// thread indefinitely; 30 seconds matches what the Services MMC snap-in allows
// before it gives up and tells the user the request timed out.
constexpr std::uint32_t kTransitionTimeoutMs = 30000;

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

ServiceActionResult FinishTransition(
    const bool succeeded,
    const std::wstring& serviceName,
    const wchar_t* actionLabel,
    const ks::service::ServiceStatus& finalStatus,
    const std::string& errorText, const std::uint32_t win32Error) {
    ServiceActionResult result{};
    result.success = succeeded;
    result.win32Error = win32Error; result.finalState = finalStatus.currentState;
    if (succeeded) {
        result.message = std::wstring(L"服务 ") + serviceName + L" " + actionLabel + L"成功，当前状态：" +
            ServiceStateText(finalStatus.currentState) + L"。";
        return result;
    }
    result.message = std::wstring(L"服务 ") + serviceName + L" " + actionLabel + L"失败：" + WidenUtf8(errorText);
    return result;
}

} // namespace

ServiceActionResult StartServiceEntry(const std::wstring& serviceName) {
    ks::service::ServiceStatus finalStatus{};
    std::string errorText;
    std::uint32_t win32Error = 0;
    const bool succeeded = ks::service::StartServiceByName(
        serviceName, kTransitionTimeoutMs, SERVICE_RUNNING, &finalStatus, &errorText, &win32Error);
    return FinishTransition(succeeded, serviceName, L"启动", finalStatus, errorText, win32Error);
}

ServiceActionResult StopServiceEntry(const std::wstring& serviceName) {
    ks::service::ServiceStatus finalStatus{};
    std::string errorText;
    std::uint32_t win32Error = 0;
    const bool succeeded = ks::service::StopServiceByName(
        serviceName, kTransitionTimeoutMs, SERVICE_STOPPED, &finalStatus, &errorText, &win32Error);
    return FinishTransition(succeeded, serviceName, L"停止", finalStatus, errorText, win32Error);
}

ServiceActionResult PauseServiceEntry(const std::wstring& serviceName) {
    ks::service::ServiceStatus finalStatus{};
    std::string errorText;
    std::uint32_t win32Error = 0;
    const bool succeeded = ks::service::ControlServiceByName(
        serviceName,
        SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS,
        SERVICE_CONTROL_PAUSE,
        kTransitionTimeoutMs,
        SERVICE_PAUSED,
        &finalStatus,
        &errorText, &win32Error);
    return FinishTransition(succeeded, serviceName, L"暂停", finalStatus, errorText, win32Error);
}

ServiceActionResult ContinueServiceEntry(const std::wstring& serviceName) {
    ks::service::ServiceStatus finalStatus{};
    std::string errorText;
    std::uint32_t win32Error = 0;
    const bool succeeded = ks::service::ControlServiceByName(
        serviceName,
        SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS,
        SERVICE_CONTROL_CONTINUE,
        kTransitionTimeoutMs,
        SERVICE_RUNNING,
        &finalStatus,
        &errorText, &win32Error);
    return FinishTransition(succeeded, serviceName, L"继续", finalStatus, errorText, win32Error);
}

ServiceActionResult ApplyServiceStartType(const std::wstring& serviceName, const ServiceStartTypeChoice choice) {
    ServiceActionResult result{};
    if (serviceName.empty()) {
        result.message = L"未选择服务，无法修改启动类型。";
        return result;
    }

    ks::service::ServiceConfigUpdate update{};
    update.changeStartType = true;
    bool wantsDelayedAutoStart = false;
    const wchar_t* choiceLabel = L"";
    switch (choice) {
    case ServiceStartTypeChoice::Automatic:
        update.startType = SERVICE_AUTO_START;
        choiceLabel = L"自动";
        break;
    case ServiceStartTypeChoice::AutomaticDelayed:
        update.startType = SERVICE_AUTO_START;
        wantsDelayedAutoStart = true;
        choiceLabel = L"自动(延迟)";
        break;
    case ServiceStartTypeChoice::Manual:
        update.startType = SERVICE_DEMAND_START;
        choiceLabel = L"手动";
        break;
    case ServiceStartTypeChoice::Disabled:
        update.startType = SERVICE_DISABLED;
        choiceLabel = L"禁用";
        break;
    }

    std::string errorText;
    std::uint32_t win32Error = 0;
    if (!ks::service::ChangeServiceConfiguration(serviceName, update, &errorText, &win32Error)) {
        result.win32Error = win32Error;
        result.message = std::wstring(L"服务 ") + serviceName + L" 启动类型修改失败：" + WidenUtf8(errorText);
        return result;
    }

    // The delayed flag only has meaning for automatic start, and Windows keeps
    // it in a separate config block. It is written on both automatic choices so
    // switching away from delayed actually clears it.
    if (update.startType == SERVICE_AUTO_START) {
        std::string delayedErrorText;
        if (!ks::service::SetDelayedAutoStart(serviceName, wantsDelayedAutoStart, &delayedErrorText, &win32Error)) {
            result.success = false; result.partial = true; result.win32Error = win32Error;
            result.message = std::wstring(L"服务 ") + serviceName + L" 启动类型已改为自动，但延迟启动标志写入失败：" +
                WidenUtf8(delayedErrorText);
            return result;
        }
    }

    result.success = true;
    result.message = std::wstring(L"服务 ") + serviceName + L" 启动类型已改为" + choiceLabel + L"。";
    return result;
}

} // namespace ks::r3::service
