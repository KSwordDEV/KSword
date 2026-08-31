#include "ProcessDetailPage.h"

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

using NtSetInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG);

class ScopedHandle final {
public:
    explicit ScopedHandle(HANDLE value = nullptr) : value_(value) {}
    ~ScopedHandle() { if (value_) { ::CloseHandle(value_); } }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ != nullptr; }
private:
    HANDLE value_ = nullptr;
};

constexpr std::array<const wchar_t*, 51> kTokenClassNames{
    L"TokenUser", L"TokenGroups", L"TokenPrivileges", L"TokenOwner", L"TokenPrimaryGroup",
    L"TokenDefaultDacl", L"TokenSource", L"TokenType", L"TokenImpersonationLevel", L"TokenStatistics",
    L"TokenRestrictedSids", L"TokenSessionId", L"TokenGroupsAndPrivileges", L"TokenSessionReference",
    L"TokenSandBoxInert", L"TokenAuditPolicy", L"TokenOrigin", L"TokenElevationType", L"TokenLinkedToken",
    L"TokenElevation", L"TokenHasRestrictions", L"TokenAccessInformation", L"TokenVirtualizationAllowed",
    L"TokenVirtualizationEnabled", L"TokenIntegrityLevel", L"TokenUIAccess", L"TokenMandatoryPolicy",
    L"TokenLogonSid", L"TokenIsAppContainer", L"TokenCapabilities", L"TokenAppContainerSid",
    L"TokenAppContainerNumber", L"TokenUserClaimAttributes", L"TokenDeviceClaimAttributes",
    L"TokenRestrictedUserClaimAttributes", L"TokenRestrictedDeviceClaimAttributes", L"TokenDeviceGroups",
    L"TokenRestrictedDeviceGroups", L"TokenSecurityAttributes", L"TokenIsRestricted", L"TokenProcessTrustLevel",
    L"TokenPrivateNameSpace", L"TokenSingletonAttributes", L"TokenBnoIsolation", L"TokenChildProcessFlags",
    L"TokenIsLessPrivilegedAppContainer", L"TokenIsSandboxed", L"TokenOriginatingProcessTrustLevel",
    L"TokenLoggingInformation", L"TokenLearningMode", L"TokenIsAppSilo"
};

std::wstring TokenClassName(int informationClass) {
    if (informationClass >= 1 && informationClass <= static_cast<int>(kTokenClassNames.size())) {
        return kTokenClassNames[static_cast<std::size_t>(informationClass - 1)];
    }
    return L"TokenClass" + std::to_wstring(informationClass);
}

void AddComboText(HWND combo, const std::wstring& text, LPARAM data) {
    const LRESULT index = ::SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text.c_str()));
    if (index >= 0) {
        ::SendMessageW(combo, CB_SETITEMDATA, static_cast<WPARAM>(index), data);
    }
}

std::wstring SidText(PSID sid) {
    if (!sid) {
        return L"<null sid>";
    }
    LPWSTR rawSid = nullptr;
    std::wstring sidValue;
    if (::ConvertSidToStringSidW(sid, &rawSid) && rawSid) {
        sidValue = rawSid;
        ::LocalFree(rawSid);
    }
    wchar_t name[256]{};
    wchar_t domain[256]{};
    DWORD nameLength = static_cast<DWORD>(std::size(name));
    DWORD domainLength = static_cast<DWORD>(std::size(domain));
    SID_NAME_USE use{};
    if (::LookupAccountSidW(nullptr, sid, name, &nameLength, domain, &domainLength, &use)) {
        std::wstring account;
        if (*domain) { account = std::wstring(domain) + L"\\"; }
        account += name;
        return account + L" (SID=" + sidValue + L")";
    }
    return L"SID=" + (sidValue.empty() ? std::wstring(L"<unavailable>") : sidValue);
}

bool QueryTokenBytes(HANDLE token, int informationClass, std::vector<std::byte>& bytes, DWORD& error) {
    DWORD required = 0;
    ::SetLastError(ERROR_SUCCESS);
    ::GetTokenInformation(token, static_cast<TOKEN_INFORMATION_CLASS>(informationClass), nullptr, 0, &required);
    error = ::GetLastError();
    if (required == 0 || required > 16 * 1024 * 1024) {
        return false;
    }
    bytes.resize(required);
    if (!::GetTokenInformation(
            token,
            static_cast<TOKEN_INFORMATION_CLASS>(informationClass),
            bytes.data(),
            required,
            &required)) {
        error = ::GetLastError();
        bytes.clear();
        return false;
    }
    bytes.resize(required);
    error = ERROR_SUCCESS;
    return true;
}

std::wstring RawPreview(const std::vector<std::byte>& bytes) {
    std::wostringstream text;
    text << std::uppercase << std::hex << std::setfill(L'0');
    const std::size_t count = std::min<std::size_t>(24, bytes.size());
    for (std::size_t index = 0; index < count; ++index) {
        if (index) { text << L' '; }
        text << std::setw(2) << std::to_integer<unsigned int>(bytes[index]);
    }
    if (bytes.size() > count) { text << L" ..."; }
    return text.str();
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
bool VerifyProcessIdentity(
    HANDLE process,
    ULONGLONG expectedProcessCreationTime100ns,
    std::wstring& errorText) {
    errorText.clear();
    if (!process || expectedProcessCreationTime100ns == 0U) {
        errorText = L"进程身份不可用。";
        return false;
    }
    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    if (!::GetProcessTimes(process, &creationTime, &exitTime, &kernelTime, &userTime)) {
        errorText = L"GetProcessTimes失败(" + std::to_wstring(::GetLastError()) + L")";
        return false;
    }
    const ULONGLONG actualProcessCreationTime100ns =
        (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
        static_cast<ULONGLONG>(creationTime.dwLowDateTime);
    if (actualProcessCreationTime100ns == 0U ||
        actualProcessCreationTime100ns != expectedProcessCreationTime100ns) {
        errorText = L"目标进程实例已变更（PID 已复用）。";
        return false;
    }
    return true;
}

constexpr std::array<int, 10> kTokenBooleanInformationClasses{
    15, 23, 24, 26, 21, 29, 40, 46, 47, 51
};

ProcessTokenReportSnapshot CollectTokenReportSnapshot(
    const DWORD processId,
    const ULONGLONG expectedProcessCreationTime100ns) {
    ProcessTokenReportSnapshot snapshot{};
    ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
    if (!process) {
        const DWORD error = ::GetLastError();
        snapshot.statusText = L"● 刷新失败：无法打开目标令牌";
        snapshot.reportText = L"OpenProcess failed: " + std::to_wstring(error);
        snapshot.editorStatusText = L"行:1 列:1 字符:0 文件:<未命名> 模式:只读 编码:UTF-16";
        return snapshot;
    }
    std::wstring identityError;
    if (!VerifyProcessIdentity(process.get(), expectedProcessCreationTime100ns, identityError)) {
        snapshot.statusText = L"● 刷新已取消：" + identityError;
        snapshot.reportText = L"Process identity verification failed: " + identityError;
        snapshot.editorStatusText = L"行:1 列:1 字符:0 文件:<未命名> 模式:只读 编码:UTF-16";
        return snapshot;
    }
    snapshot.identityMatched = true;

    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(process.get(), TOKEN_QUERY, &rawToken)) {
        const DWORD error = ::GetLastError();
        snapshot.statusText = L"● 刷新失败：无法打开目标令牌";
        snapshot.reportText = L"OpenProcessToken failed: " + std::to_wstring(error);
        snapshot.editorStatusText = L"行:1 列:1 字符:0 文件:<未命名> 模式:只读 编码:UTF-16";
        return snapshot;
    }

    ScopedHandle token(rawToken);
    std::wostringstream report;
    report << L"[Token / Security Information]\r\nPID: " << processId << L"\r\n";

    std::vector<std::byte> bytes;
    DWORD error = 0;
    if (QueryTokenBytes(token.get(), TokenUser, bytes, error)) {
        const auto* user = reinterpret_cast<const TOKEN_USER*>(bytes.data());
        report << L"User: " << SidText(user->User.Sid) << L"\r\n";
    }
    if (QueryTokenBytes(token.get(), TokenElevationType, bytes, error)) {
        const auto value = *reinterpret_cast<const TOKEN_ELEVATION_TYPE*>(bytes.data());
        report << L"ElevationType: " << (value == TokenElevationTypeFull ? L"Full" : value == TokenElevationTypeLimited ? L"Limited" : L"Default") << L"\r\n";
    }
    if (QueryTokenBytes(token.get(), TokenElevation, bytes, error)) {
        report << L"IsElevated: " << (reinterpret_cast<const TOKEN_ELEVATION*>(bytes.data())->TokenIsElevated ? L"true" : L"false") << L"\r\n";
    }
    if (QueryTokenBytes(token.get(), TokenGroups, bytes, error)) {
        const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(bytes.data());
        report << L"GroupCount: " << groups->GroupCount << L"\r\n";
        for (DWORD index = 0; index < std::min<DWORD>(groups->GroupCount, 16); ++index) {
            report << L"  - " << SidText(groups->Groups[index].Sid) << L"\r\n";
        }
    }
    if (QueryTokenBytes(token.get(), TokenPrivileges, bytes, error)) {
        const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(bytes.data());
        report << L"PrivilegeCount: " << privileges->PrivilegeCount << L"\r\n";
        for (DWORD index = 0; index < std::min<DWORD>(privileges->PrivilegeCount, 24); ++index) {
            wchar_t name[256]{};
            DWORD length = static_cast<DWORD>(std::size(name));
            ::LookupPrivilegeNameW(nullptr, const_cast<LUID*>(&privileges->Privileges[index].Luid), name, &length);
            report << L"  - " << (*name ? name : L"<unknown>") << L" ["
                   << ((privileges->Privileges[index].Attributes & SE_PRIVILEGE_ENABLED) ? L"Enabled" : L"Disabled")
                   << L"]\r\n";
        }
    }

    report << L"\r\n[All TokenInformationClass Snapshot]\r\n";
    for (int informationClass = 1; informationClass <= 80; ++informationClass) {
        if (QueryTokenBytes(token.get(), informationClass, bytes, error)) {
            report << L"  [" << informationClass << L"] " << TokenClassName(informationClass)
                   << L": size=" << bytes.size() << L", raw=" << RawPreview(bytes) << L"\r\n";
        } else {
            report << L"  [" << informationClass << L"] " << TokenClassName(informationClass)
                   << L": queryFailed(" << error << L")\r\n";
        }
    }
    DWORD sessionId = 0;
    DWORD returnLength = 0;
    if (::GetTokenInformation(token.get(), TokenSessionId, &sessionId, sizeof(sessionId), &returnLength)) {
        report << L"SessionId: " << sessionId << L"\r\n";
    }

    snapshot.succeeded = true;
    snapshot.reportText = report.str();
    snapshot.statusText = L"● 刷新完成";
    snapshot.editorStatusText =
        L"行:1 列:1 字符:" + std::to_wstring(snapshot.reportText.size()) + L" 文件:<未命名> 模式:只读 编码:UTF-16";
    return snapshot;
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
    AddEdit(tab, TokenOutput, L"令牌详细信息将在此处显示。", true, true, 6, 44, -6, -30);
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
                action.statusText = L"● 原始设置失败：" + identityError;
                return action;
            }
            HANDLE rawToken = nullptr;
            if (!setInformation || !::OpenProcessToken(
                    verifiedProcess.get(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &rawToken)) {
                action.statusText = L"● 原始设置失败：无法打开目标令牌";
                return action;
            }
            ScopedHandle token(rawToken);
            const NTSTATUS status = setInformation(
                token.get(),
                static_cast<TOKEN_INFORMATION_CLASS>(informationClass),
                payload.data(),
                static_cast<ULONG>(payload.size()));
            std::wostringstream message;
            message << (status >= 0 ? L"● 原始设置成功：" : L"● 原始设置失败：")
                    << L"[" << informationClass << L"] " << TokenClassName(informationClass)
                    << L", size=" << payload.size() << L", status=0x"
                    << std::uppercase << std::hex << static_cast<std::uint32_t>(status);
            action.statusText = message.str();
            action.refreshTokenSwitches = true;
            action.refreshTokenReport = true;
            return action;
        });
}

} // namespace Ksword::Features::ProcessDetail
