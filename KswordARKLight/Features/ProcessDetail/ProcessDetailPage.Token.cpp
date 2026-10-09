#include "../../../shared/usermode/backend/process/ProcessToken.h"
#include "ProcessDetailPage.h"
#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::ProcessDetail {
namespace {
using namespace ks::r3::process_detail::token;









void AddComboText(HWND combo, const std::wstring& text, LPARAM data) {
    const LRESULT index = ::SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text.c_str()));
    if (index >= 0) {
        ::SendMessageW(combo, CB_SETITEMDATA, static_cast<WPARAM>(index), data);
    }
}







bool ParseUnsigned(const std::wstring& text, unsigned long long maximum, unsigned long long& value) {
    try {
        std::size_t consumed = 0;
        value = std::stoull(text, &consumed, 0);
        return consumed == text.size() && value <= maximum;
    } catch (...) {
        return false;
    }
}

bool IsChecked(HWND checkbox) {
    return checkbox && ::SendMessageW(checkbox, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void SetChecked(HWND checkbox, bool checked) {
    if (checkbox) {
        ::SendMessageW(checkbox, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
    }
}

// VerifyProcessIdentity keeps the caller-owned process handle in scope so the
// PID cannot be reused while the following token operations are collected.


constexpr std::array<int, 10> kTokenBooleanInformationClasses{
    15, 23, 24, 26, 21, 29, 40, 46, 47, 51
};

ProcessTokenReportSnapshot CollectTokenReportSnapshot(DWORD processId, ULONGLONG expectedProcessCreationTime100ns) {
    return ks::r3::process_detail::token::QueryTokenReportSnapshotR3(processId, expectedProcessCreationTime100ns,
        [processId, expectedProcessCreationTime100ns](ProcessTokenReportSnapshot& snapshot, DWORD error) {
        const ksword::ark::ProcessTokenPrivilegeResult r0 =
            ksword::ark::DriverClient().queryProcessTokenPrivileges(
                processId, expectedProcessCreationTime100ns);
        if (r0.io.ok &&
            (r0.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ||
                r0.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL)) {
            std::wostringstream report;
            report << L"[Token Privileges / R0 Fallback]\r\nPID: " << processId
                   << L"\r\nOpenProcessToken failed: " << error
                   << L"\r\nR0 PrivilegeCount: " << r0.entries.size() << L"\r\n";
            for (const ksword::ark::ProcessTokenPrivilegeEntry& entry : r0.entries) {
                LUID luid{};
                luid.LowPart = entry.luidLowPart;
                luid.HighPart = entry.luidHighPart;
                wchar_t name[256]{};
                DWORD length = static_cast<DWORD>(std::size(name));
                ::LookupPrivilegeNameW(nullptr, &luid, name, &length);
                report << L"  - " << (*name ? name : L"<unknown>") << L" ["
                       << ((entry.attributes & SE_PRIVILEGE_ENABLED) ? L"Enabled" : L"Disabled")
                       << L"]\r\n";
            }
            if (r0.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL) {
                report << L"R0 返回了部分特权结果。\r\n";
            }
            snapshot.reportText = report.str();
            snapshot.statusText = L"● R3 令牌不可访问，已通过 R0 读取特权列表。";
            snapshot.succeeded = true;
        } else {
            snapshot.statusText = L"● 刷新失败：R3 与 R0 均无法读取目标令牌特权";
            snapshot.reportText = L"OpenProcessToken failed: " + std::to_wstring(error) +
                L"\r\nR0 status: " + std::to_wstring(r0.status);
        }
        snapshot.editorStatusText = L"行:1 列:1 字符:" +
            std::to_wstring(snapshot.reportText.size()) +
            L" 文件:<未命名> 模式:只读 编码:UTF-16";

        });
}



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

} // namespace

bool ProcessDetailPage::CreateTokenTab() {
    const TabIndex tab = TabIndex::Token;
    AddButton(tab, TokenRefresh, L"刷新令牌", 6, 6, 92, 30);
    AddButton(tab, TokenCopy, L"复制", 106, 6, 64, 30);
    AddButton(tab, TokenFind, L"查找", 178, 6, 64, 30);
    AddButton(tab, TokenGoto, L"跳转行", 250, 6, 76, 30);
    AddButton(tab, TokenWrap, L"自动换行", 334, 6, 86, 30);
    AddLabel(tab, TokenStatus, L"● 尚未刷新", 430, 8, -6, 24);
    HWND privilegeName = AddEdit(tab, TokenPrivilegeName, L"", false, false, 6, 44, 196, 28);
    ::SendMessageW(privilegeName, EM_SETCUEBANNER, FALSE, reinterpret_cast<LPARAM>(L"SeDebugPrivilege"));
    HWND privilegeAction = AddCombo(tab, TokenPrivilegeAction, 210, 44, 116, 120);
    AddComboText(privilegeAction, L"启用", KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE);
    AddComboText(privilegeAction, L"禁用", KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE);
    ::SendMessageW(privilegeAction, CB_SETCURSEL, 0, 0);
    AddButton(tab, TokenPrivilegeApply, L"调整特权", 334, 44, 86, 28);
    AddLabel(tab, 0, L"优先使用 R3；令牌访问受限时按进程身份由 R0 兜底", 430, 48, -6, 24);
    AddEdit(tab, TokenOutput, L"令牌详细信息将在此处显示。", true, true, 6, 80, -6, -30);
    AddLabel(tab, TokenEditorStatus, L"行:1 列:1 字符:0 文件:<未命名> 模式:只读 编码:未知", 6, -24, -6, 20);
    return Control(tab, TokenRefresh) && Control(tab, TokenOutput);
}

bool ProcessDetailPage::CreateTokenSwitchTab() {
    const TabIndex tab = TabIndex::TokenSwitch;
    AddButton(tab, TokenSwitchRefresh, L"↻", 6, 6, 34, 34);
    AddButton(tab, TokenSwitchApply, L"▶", 46, 6, 34, 34);
    AddButton(tab, TokenSwitchRefreshAll, L"≡", 86, 6, 34, 34);
    AddLabel(tab, TokenSwitchStatus, L"● 尚未刷新令牌开关", 130, 10, -6, 24);

    AddGroup(tab, L"Token 快捷开关", 6, 48, -6, 116);
    AddCheck(tab, TokenSandboxInert, L"SandboxInert", 20, 72, 260, 24);
    AddCheck(tab, TokenVirtualizationAllowed, L"VirtualizationAllowed", 310, 72, 280, 24);
    AddCheck(tab, TokenVirtualizationEnabled, L"VirtualizationEnabled", 20, 100, 260, 24);
    AddCheck(tab, TokenUiAccess, L"UIAccess", 310, 100, 280, 24);
    AddCheck(tab, TokenMandatoryNoWriteUp, L"MandatoryPolicy.NoWriteUp", 20, 128, 260, 24);
    AddCheck(tab, TokenMandatoryNewProcessMin, L"MandatoryPolicy.NewProcessMin", 310, 128, 300, 24);

    AddGroup(tab, L"Token 常用信息类（布尔语义）", 6, 172, -6, 116);
    AddCheck(tab, TokenHasRestrictions, L"HasRestrictions", 20, 196, 260, 24);
    AddCheck(tab, TokenIsAppContainer, L"IsAppContainer", 310, 196, 280, 24);
    AddCheck(tab, TokenIsRestricted, L"IsRestricted", 20, 224, 260, 24);
    AddCheck(tab, TokenIsLessPrivilegedAppContainer, L"IsLessPrivilegedAppContainer", 310, 224, 300, 24);
    AddCheck(tab, TokenIsSandboxed, L"IsSandboxed", 20, 252, 260, 24);
    AddCheck(tab, TokenIsAppSilo, L"IsAppSilo", 310, 252, 280, 24);

    AddGroup(tab, L"原始 NtSetInformationToken（全部信息类）", 6, 296, -6, 140);
    AddLabel(tab, 0, L"信息类", 20, 322, 92, 26);
    HWND infoClass = AddCombo(tab, TokenRawInfoClass, 116, 320, -20, 360);
    for (int value = 1; value <= 80; ++value) {
        AddComboText(infoClass, L"[" + std::to_wstring(value) + L"] " + TokenClassName(value), value);
    }
    ::SendMessageW(infoClass, CB_SETCURSEL, 14, 0);
    AddLabel(tab, 0, L"输入模式", 20, 356, 92, 26);
    HWND mode = AddCombo(tab, TokenRawInputMode, 116, 354, -20, 180);
    AddComboText(mode, L"UInt32", 0);
    AddComboText(mode, L"UInt64", 1);
    AddComboText(mode, L"HexBytes", 2);
    ::SendMessageW(mode, CB_SETCURSEL, 0, 0);
    AddLabel(tab, 0, L"原始负载", 20, 390, 92, 26);
    HWND payload = AddEdit(tab, TokenRawPayload, L"", false, false, 116, 388, -64, 28);
    ::SendMessageW(payload, EM_SETCUEBANNER, FALSE,
        reinterpret_cast<LPARAM>(L"示例：UInt32=1；UInt64=0x10；HexBytes=01 00 00 00"));
    AddButton(tab, TokenRawApply, L"▶", -50, 386, 34, 34);
    AddLabel(tab, 0,
        L"提示：可先点“刷新全部令牌信息”查看所有 TokenInformationClass 的当前状态，再按快捷或原始模式应用。",
        10, 444, -10, 44);
    if (actionTask_ && actionTask_->running()) {
        SetBackgroundActionControlsEnabled(false);
    }
    return infoClass && mode && payload;
}

void ProcessDetailPage::PopulateTokenTab() {
    if (!tokenLoaded_) {
        SetControlText(TabIndex::Token, TokenOutput, L"令牌详细信息将在此处显示。");
    }
}

void ProcessDetailPage::PopulateTokenSwitchTab() {
    if (!tokenSwitchLoaded_) {
        SetPageStatus(TabIndex::TokenSwitch, TokenSwitchStatus, L"● 尚未刷新令牌开关");
    }
}

bool ProcessDetailPage::HandleTokenCommand(int controlId) {
    switch (controlId) {
    case TokenPrivilegeApply:
        ApplyTokenPrivilege();
        return true;
    case TokenRefresh:
        RefreshTokenReport();
        return true;
    case TokenCopy: {
        HWND output = Control(TabIndex::Token, TokenOutput);
        ::SendMessageW(output, EM_SETSEL, 0, -1);
        const std::wstring text = ReadWindowText(output);
        if (!text.empty()) {
            CopyText(hwnd_, text);
        } else {
            // Preserve the native edit-control behavior for an empty report.
            ::SendMessageW(output, WM_COPY, 0, 0);
        }
        return true;
    }
    case TokenFind:
        ::MessageBoxW(hwnd_, L"可使用 Ctrl+F 配合系统编辑控件查找；当前布局保留查找入口。", L"查找", MB_OK | MB_ICONINFORMATION);
        return true;
    case TokenGoto:
        ::SendMessageW(Control(TabIndex::Token, TokenOutput), EM_SETSEL, 0, 0);
        ::SetFocus(Control(TabIndex::Token, TokenOutput));
        return true;
    case TokenWrap: {
        HWND output = Control(TabIndex::Token, TokenOutput);
        const LONG_PTR style = ::GetWindowLongPtrW(output, GWL_STYLE);
        ::SetWindowLongPtrW(output, GWL_STYLE, style ^ ES_AUTOHSCROLL);
        ::SetWindowPos(output, nullptr, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
        return true;
    }
    default:
        return false;
    }
}

void ProcessDetailPage::ApplyTokenPrivilege() {
    const std::wstring name = ControlText(TabIndex::Token, TokenPrivilegeName);
    LUID luid{};
    if (name.empty() || !::LookupPrivilegeValueW(nullptr, name.c_str(), &luid)) {
        SetPageStatus(TabIndex::Token, TokenStatus, L"● 特权名称无效；请输入 SeDebugPrivilege 等完整名称。");
        return;
    }
    const int selected = static_cast<int>(::SendMessageW(
        Control(TabIndex::Token, TokenPrivilegeAction), CB_GETCURSEL, 0, 0));
    if (selected < 0 || expectedCreationTime100ns_ == 0) {
        SetPageStatus(TabIndex::Token, TokenStatus, L"● 缺少动作或进程创建时间，不能安全调整。");
        return;
    }
    const auto action = static_cast<std::uint32_t>(::SendMessageW(
        Control(TabIndex::Token, TokenPrivilegeAction), CB_GETITEMDATA, selected, 0));
    const std::wstring prompt = L"目标 PID " + std::to_wstring(processId_) + L" 的 " + name +
        (action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE ? L" 将被启用。" : L" 将被禁用。") +
        L"\nR3 调整失败时会按进程创建时间由 R0 兜底。确认继续？";
    if (::MessageBoxW(hwnd_, prompt.c_str(), L"调整目标进程特权",
            MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) != IDYES) {
        return;
    }
    const DWORD processId = processId_;
    const ULONGLONG expectedCreationTime = expectedCreationTime100ns_;
    ExecuteBackgroundAction(TabIndex::Token, TokenStatus, L"● 正在后台调整目标令牌特权…",
        [processId, expectedCreationTime, name, luid, action] {
            ProcessDetailActionResult result{};
            const auto observed = ksword::ark::DriverClient().queryProcessTokenPrivileges(
                processId, expectedCreationTime);
            if (!observed.io.ok ||
                observed.status != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ||
                observed.processCreateTime100ns != expectedCreationTime) {
                result.statusText = L"● R0 进程身份或令牌特权预检失败，请刷新进程列表。";
                return result;
            }
            Ksword::Core::UniqueHandle process;
            DWORD r3Error = ERROR_ACCESS_DENIED;
            result = ks::r3::process_detail::token::AdjustTokenPrivilegeR3(processId, expectedCreationTime, name, luid,
                action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE, process, r3Error);
            if (result.refreshTokenReport) { return result; }
            ksword::ark::ProcessTokenPrivilegeEntry edit{};
            edit.luidLowPart = luid.LowPart;
            edit.luidHighPart = luid.HighPart;
            edit.action = action;
            const auto r0 = ksword::ark::DriverClient().adjustProcessTokenPrivileges(
                processId, expectedCreationTime, { edit }, false);
            if (!r0.io.ok || r0.status != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ||
                r0.appliedCount != 1U) {
                result.statusText = L"● R3 调整失败（Win32 " + std::to_wstring(r3Error) +
                    L"）；R0 兜底失败（状态 " + std::to_wstring(r0.status) + L"）。";
                result.dialogTitle = L"调整令牌特权失败";
                result.dialogText = result.statusText + L"\n" +
                    std::wstring(r0.io.message.begin(), r0.io.message.end());
                result.dialogIcon = MB_ICONERROR;
                return result;
            }
            result.statusText = L"● R0 已调整 " + name + L"；R3 Win32=" + std::to_wstring(r3Error);
            result.refreshTokenReport = true;
            return result;
        });
}

bool ProcessDetailPage::HandleTokenSwitchCommand(int controlId) {
    switch (controlId) {
    case TokenSwitchRefresh: RefreshTokenSwitches(); return true;
    case TokenSwitchApply: ApplyTokenSwitches(); return true;
    case TokenSwitchRefreshAll: RefreshTokenReport(); return true;
    case TokenRawApply: ApplyRawTokenValue(); return true;
    default: return false;
    }
}

void ProcessDetailPage::RefreshTokenReport() {
    if (!tokenReportTask_) {
        SetPageStatus(TabIndex::Token, TokenStatus, L"● 令牌后台任务不可用。");
        return;
    }
    SetPageStatus(TabIndex::Token, TokenStatus, L"● 正在刷新令牌...");
    const DWORD processId = processId_;
    const ULONGLONG expectedProcessCreationTime100ns = expectedCreationTime100ns_;
    tokenReportTask_->request(
        [processId, expectedProcessCreationTime100ns] {
            return CollectTokenReportSnapshot(processId, expectedProcessCreationTime100ns);
        },
        [this](std::uint64_t, std::optional<ProcessTokenReportSnapshot>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                SetPageStatus(TabIndex::Token, TokenStatus, L"● 令牌后台查询异常结束。");
                return;
            }
            SetControlText(TabIndex::Token, TokenOutput, result->reportText);
            SetControlText(TabIndex::Token, TokenEditorStatus, result->editorStatusText);
            SetPageStatus(TabIndex::Token, TokenStatus, result->statusText);
            tokenLoaded_ = result->succeeded && result->identityMatched;
        });
}

void ProcessDetailPage::RefreshTokenSwitches() {
    if (!tokenSwitchTask_) {
        SetPageStatus(TabIndex::TokenSwitch, TokenSwitchStatus, L"● 令牌开关后台任务不可用。");
        return;
    }
    SetPageStatus(TabIndex::TokenSwitch, TokenSwitchStatus, L"● 正在读取令牌开关...");
    const DWORD processId = processId_;
    const ULONGLONG expectedProcessCreationTime100ns = expectedCreationTime100ns_;
    tokenSwitchTask_->request(
        [processId, expectedProcessCreationTime100ns] {
            return CollectTokenSwitchSnapshot(processId, expectedProcessCreationTime100ns);
        },
        [this](std::uint64_t, std::optional<ProcessTokenSwitchSnapshot>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                SetPageStatus(TabIndex::TokenSwitch, TokenSwitchStatus, L"● 令牌开关后台查询异常结束。");
                return;
            }
            constexpr std::array<int, 12> controls{
                TokenSandboxInert,
                TokenVirtualizationAllowed,
                TokenVirtualizationEnabled,
                TokenUiAccess,
                TokenHasRestrictions,
                TokenIsAppContainer,
                TokenIsRestricted,
                TokenIsLessPrivilegedAppContainer,
                TokenIsSandboxed,
                TokenIsAppSilo,
                TokenMandatoryNoWriteUp,
                TokenMandatoryNewProcessMin
            };
            for (std::size_t index = 0; index < controls.size(); ++index) {
                if (result->updated[index]) {
                    SetChecked(Control(TabIndex::TokenSwitch, controls[index]), result->values[index]);
                }
            }
            SetPageStatus(TabIndex::TokenSwitch, TokenSwitchStatus, result->statusText);
            tokenSwitchLoaded_ = result->succeeded && result->identityMatched;
        });
}

void ProcessDetailPage::ApplyTokenSwitches() {
    if (::MessageBoxW(hwnd_, L"将尝试写回目标进程令牌开关。部分信息类在当前系统上只读，是否继续？",
        L"令牌开关", MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) != IDYES) {
        return;
    }
    const std::array<bool, 12> values{
        IsChecked(Control(TabIndex::TokenSwitch, TokenSandboxInert)),
        IsChecked(Control(TabIndex::TokenSwitch, TokenVirtualizationAllowed)),
        IsChecked(Control(TabIndex::TokenSwitch, TokenVirtualizationEnabled)),
        IsChecked(Control(TabIndex::TokenSwitch, TokenUiAccess)),
        IsChecked(Control(TabIndex::TokenSwitch, TokenHasRestrictions)),
        IsChecked(Control(TabIndex::TokenSwitch, TokenIsAppContainer)),
        IsChecked(Control(TabIndex::TokenSwitch, TokenIsRestricted)),
        IsChecked(Control(TabIndex::TokenSwitch, TokenIsLessPrivilegedAppContainer)),
        IsChecked(Control(TabIndex::TokenSwitch, TokenIsSandboxed)),
        IsChecked(Control(TabIndex::TokenSwitch, TokenIsAppSilo)),
        IsChecked(Control(TabIndex::TokenSwitch, TokenMandatoryNoWriteUp)),
        IsChecked(Control(TabIndex::TokenSwitch, TokenMandatoryNewProcessMin))
    };
    const DWORD processId = processId_;
    const ULONGLONG expectedProcessCreationTime100ns = expectedCreationTime100ns_;
    ExecuteBackgroundAction(
        TabIndex::TokenSwitch,
        TokenSwitchStatus,
        L"● 正在后台写回令牌开关…",
        [processId, expectedProcessCreationTime100ns, values] {
            ProcessDetailActionResult action{};
            const auto setInformation = reinterpret_cast<NtSetInformationTokenFn>(
                ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtSetInformationToken"));
            Ksword::Core::UniqueHandle verifiedProcess;
            std::wstring identityError;
            if (!ProcessDetailPage::OpenVerifiedProcessActionTarget(
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
        });
}

void ProcessDetailPage::ApplyRawTokenValue() {
    HWND classCombo = Control(TabIndex::TokenSwitch, TokenRawInfoClass);
    HWND modeCombo = Control(TabIndex::TokenSwitch, TokenRawInputMode);
    const int classIndex = static_cast<int>(::SendMessageW(classCombo, CB_GETCURSEL, 0, 0));
    const int modeIndex = static_cast<int>(::SendMessageW(modeCombo, CB_GETCURSEL, 0, 0));
    if (classIndex < 0 || modeIndex < 0) {
        SetPageStatus(TabIndex::TokenSwitch, TokenSwitchStatus, L"● 原始设置失败：信息类或输入模式无效");
        return;
    }
    const int informationClass = static_cast<int>(::SendMessageW(classCombo, CB_GETITEMDATA, classIndex, 0));
    const std::wstring payloadText = ControlText(TabIndex::TokenSwitch, TokenRawPayload);
    std::vector<std::byte> payload;
    if (modeIndex <= 1) {
        unsigned long long value = 0;
        const unsigned long long maximum = modeIndex == 0 ? 0xFFFFFFFFULL : ~0ULL;
        if (!ParseUnsigned(payloadText, maximum, value)) {
            SetPageStatus(TabIndex::TokenSwitch, TokenSwitchStatus, L"● 原始设置失败：整数解析失败");
            return;
        }
        const std::size_t size = modeIndex == 0 ? sizeof(std::uint32_t) : sizeof(std::uint64_t);
        payload.resize(size);
        std::memcpy(payload.data(), &value, size);
    } else {
        std::wstring normalized = payloadText;
        std::replace(normalized.begin(), normalized.end(), L',', L' ');
        std::wistringstream stream(normalized);
        std::wstring item;
        while (stream >> item) {
            unsigned long long value = 0;
            const bool hasHexPrefix = item.size() >= 2 && item[0] == L'0' && std::towlower(item[1]) == L'x';
            if (!ParseUnsigned(hasHexPrefix ? item : L"0x" + item, 0xFF, value)) {
                SetPageStatus(TabIndex::TokenSwitch, TokenSwitchStatus, L"● 原始设置失败：非法字节 '" + item + L"'");
                return;
            }
            payload.push_back(static_cast<std::byte>(value));
        }
        if (payload.empty()) {
            SetPageStatus(TabIndex::TokenSwitch, TokenSwitchStatus, L"● 原始设置失败：没有字节");
            return;
        }
    }

    if (payload.size() > 16U * 1024U * 1024U) {
        SetPageStatus(TabIndex::TokenSwitch, TokenSwitchStatus, L"● 原始设置失败：负载超过16 MiB上限");
        return;
    }
    const DWORD processId = processId_;
    const ULONGLONG expectedProcessCreationTime100ns = expectedCreationTime100ns_;
    ExecuteBackgroundAction(
        TabIndex::TokenSwitch,
        TokenSwitchStatus,
        L"● 正在后台写入原始令牌信息…",
        [informationClass, processId, expectedProcessCreationTime100ns, payload = std::move(payload)]() mutable {
            return ks::r3::process_detail::token::WriteRawTokenValue(informationClass, processId, expectedProcessCreationTime100ns, std::move(payload));
        });
}

} // namespace Ksword::Features::ProcessDetail

namespace Ksword::Features::ProcessDetail { namespace {



}}
