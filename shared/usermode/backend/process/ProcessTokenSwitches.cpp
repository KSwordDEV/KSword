#include "ProcessTokenSwitches.h"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <iterator>
namespace ks::r3::process_detail::token {
ProcessTokenSwitchSnapshot CollectTokenSwitchSnapshot(
    const DWORD processId,
    const ULONGLONG expectedProcessCreationTime100ns) {
    ProcessTokenSwitchSnapshot snapshot{};
    ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
    if (!process) {
        snapshot.win32ErrorKnown = true;snapshot.win32Error = ::GetLastError();
        snapshot.statusText = L"● 刷新失败：无法打开目标令牌";
        return snapshot;
    }
    std::wstring identityError;
    if (!VerifyProcessIdentity(process.get(), expectedProcessCreationTime100ns, identityError)) {
        snapshot.statusText = L"● 刷新已取消：" + identityError;
        return snapshot;
    }
    snapshot.identityMatched = true;

    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(process.get(), TOKEN_QUERY, &rawToken)) {
        snapshot.win32ErrorKnown = true;snapshot.win32Error = ::GetLastError();
        snapshot.statusText = L"● 刷新失败：无法打开目标令牌";
        return snapshot;
    }

    ScopedHandle token(rawToken);
    int success = 0;
    for (std::size_t index = 0; index < kTokenBooleanInformationClasses.size(); ++index) {
        ULONG value = 0;
        DWORD returned = 0;
        const bool ok = ::GetTokenInformation(
                token.get(),
                static_cast<TOKEN_INFORMATION_CLASS>(kTokenBooleanInformationClasses[index]),
                &value,
                sizeof(value),
                &returned) != FALSE;
        snapshot.returnLengths[index] = returned;
        // Some native boolean classes return a BOOLEAN even though the public
        // caller buffer is ULONG; the zero-initialized buffer handles both ABIs.
        const bool lengthOk = returned == sizeof(BOOLEAN) || returned == sizeof(value);
        snapshot.queryErrors[index] = ok ? lengthOk ? ERROR_SUCCESS : ERROR_INVALID_DATA : ::GetLastError();
        if (ok && lengthOk) {
            snapshot.values[index] = value != 0;
            snapshot.updated[index] = true;
            ++success;
        }
    }

    TOKEN_MANDATORY_POLICY policy{};
    DWORD returned = 0;
    const bool policyOk = ::GetTokenInformation(token.get(), TokenMandatoryPolicy, &policy, sizeof(policy), &returned) != FALSE;
    const DWORD policyError = policyOk ? returned == sizeof(policy) ? ERROR_SUCCESS : ERROR_INVALID_DATA : ::GetLastError();
    snapshot.queryErrors[10] = snapshot.queryErrors[11] = policyError;
    snapshot.returnLengths[10] = snapshot.returnLengths[11] = returned;
    if (policyOk && returned == sizeof(policy)) {
        snapshot.mandatoryPolicy = policy.Policy;snapshot.mandatoryPolicyKnown = true;
        snapshot.values[10] = (policy.Policy & 0x1U) != 0;
        snapshot.values[11] = (policy.Policy & 0x2U) != 0;
        snapshot.updated[10] = true;
        snapshot.updated[11] = true;
        ++success;
    }
    snapshot.succeeded = true;
    snapshot.statusText = L"● 刷新完成：" + std::to_wstring(success) + L" 项开关已同步";
    return snapshot;
}
ProcessDetailActionResult WriteTokenSwitches(DWORD processId, ULONGLONG expectedProcessCreationTime100ns, const std::array<bool, 12>& values) {

            ProcessDetailActionResult action{};
            const auto setInformation = reinterpret_cast<NtSetInformationTokenFn>(
                ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtSetInformationToken"));
            ks::r3::common::UniqueHandle verifiedProcess;
            std::wstring identityError;
            if (!OpenVerifiedProcessActionTarget(
                    processId,
                    expectedProcessCreationTime100ns,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    verifiedProcess,
                    identityError)) {
                action.statusText = L"● 应用失败：" + identityError;
                return action;
            }
            HANDLE rawToken = nullptr;
            if (!setInformation || !::OpenProcessToken(
                    verifiedProcess.get(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &rawToken)) {
                action.statusText = L"● 应用失败：无法获取 NtSetInformationToken/令牌写权限";
                return action;
            }

            ScopedHandle token(rawToken);
            int success = 0;
            int failed = 0;
            for (std::size_t index = 0; index < kTokenBooleanInformationClasses.size(); ++index) {
                ULONG value = values[index] ? 1UL : 0UL;
                const NTSTATUS status = setInformation(
                    token.get(),
                    static_cast<TOKEN_INFORMATION_CLASS>(kTokenBooleanInformationClasses[index]),
                    &value,
                    sizeof(value));
                status >= 0 ? ++success : ++failed;
            }
            TOKEN_MANDATORY_POLICY policy{};
            if (values[10]) { policy.Policy |= 0x1U; }
            if (values[11]) { policy.Policy |= 0x2U; }
            const NTSTATUS policyStatus = setInformation(token.get(), TokenMandatoryPolicy, &policy, sizeof(policy));
            policyStatus >= 0 ? ++success : ++failed;
            action.statusText =
                L"● 应用完成：成功" + std::to_wstring(success) + L"，失败" + std::to_wstring(failed);
            action.refreshTokenSwitches = true;
            action.refreshTokenReport = true;
            return action;

}
ProcessDetailActionResult WriteTokenSwitch(DWORD processId,ULONGLONG expectedCreationTime,std::size_t index,bool enabled) {
    ProcessDetailActionResult action;
    // Other fields in the original bulk UI setter are query-only native classes.
    if (index != 1 && index != 2 && index != 3 && index != 10 && index != 11) {action.unsupported = true;return action;}
    ks::r3::common::UniqueHandle process;std::wstring error;
    if (!OpenVerifiedProcessActionTarget(processId,expectedCreationTime,PROCESS_QUERY_LIMITED_INFORMATION,process,error)) {
        action.statusText = L"● 应用失败：" + error;return action;
    }
    action.identityMatched = true;
    const auto set = reinterpret_cast<NtSetInformationTokenFn>(::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"),"NtSetInformationToken"));
    HANDLE rawToken = nullptr;
    if (!set || !::OpenProcessToken(process.get(),TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,&rawToken)) {
        action.unsupported = !set;if (set) {action.win32ErrorKnown = true;action.win32Error = ::GetLastError();}
        action.statusText = L"● 应用失败：无法获取 NtSetInformationToken/令牌写权限";return action;
    }
    ScopedHandle token(rawToken);
    ULONG value = enabled ? 1UL : 0UL;
    const auto informationClass = index < 10 ? static_cast<TOKEN_INFORMATION_CLASS>(kTokenBooleanInformationClasses[index]) : TokenMandatoryPolicy;
    if (index >= 10) {
        TOKEN_MANDATORY_POLICY policy{};DWORD returned = 0;
        if (!::GetTokenInformation(token.get(),TokenMandatoryPolicy,&policy,sizeof(policy),&returned)) {
            action.win32ErrorKnown = true;action.win32Error = ::GetLastError();return action;
        }
        if (returned != sizeof(policy)) {action.win32ErrorKnown = true;action.win32Error = ERROR_INVALID_DATA;return action;}
        const ULONG mask = index == 10 ? 1UL : 2UL;
        value = enabled ? policy.Policy | mask : policy.Policy & ~mask;
    }
    action.writeAttempted = true;
    action.ntStatus = set(token.get(),informationClass,&value,sizeof(value));action.ntStatusKnown = true;
    action.requestSucceeded = action.ntStatus == 0;action.writeSucceeded = action.requestSucceeded;
    action.refreshTokenSwitches = action.refreshTokenReport = true;
    action.statusText = L"● 应用完成：成功" + std::to_wstring(action.requestSucceeded ? 1 : 0) + L"，失败" + std::to_wstring(action.requestSucceeded ? 0 : 1);
    return action;
}
}
