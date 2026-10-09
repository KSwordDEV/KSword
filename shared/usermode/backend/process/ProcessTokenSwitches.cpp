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
        snapshot.statusText = L"● 刷新失败：无法打开目标令牌";
        return snapshot;
    }

    ScopedHandle token(rawToken);
    int success = 0;
    for (std::size_t index = 0; index < kTokenBooleanInformationClasses.size(); ++index) {
        ULONG value = 0;
        DWORD returned = 0;
        if (::GetTokenInformation(
                token.get(),
                static_cast<TOKEN_INFORMATION_CLASS>(kTokenBooleanInformationClasses[index]),
                &value,
                sizeof(value),
                &returned)) {
            snapshot.values[index] = value != 0;
            snapshot.updated[index] = true;
            ++success;
        }
    }

    TOKEN_MANDATORY_POLICY policy{};
    DWORD returned = 0;
    if (::GetTokenInformation(token.get(), TokenMandatoryPolicy, &policy, sizeof(policy), &returned)) {
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
}
