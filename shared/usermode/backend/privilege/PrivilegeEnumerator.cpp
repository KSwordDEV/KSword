#include "PrivilegeEnumerator.h"

#include <memory>
#include <string>
#include <vector>

#include <sddl.h>

namespace ks::r3::privilege {
namespace {

// TokenHandleGuard closes the process token on scope exit. The token is opened
// once per snapshot and every early return below has to release it.
class TokenHandleGuard final {
public:
    explicit TokenHandleGuard(HANDLE handle) noexcept : handle_(handle) {}
    ~TokenHandleGuard() {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(handle_);
        }
    }
    TokenHandleGuard(const TokenHandleGuard&) = delete;
    TokenHandleGuard& operator=(const TokenHandleGuard&) = delete;

    HANDLE get() const noexcept { return handle_; }

private:
    HANDLE handle_;
};

// QueryTokenInformationBlock reads a variable-size token information class. The
// two-call size probe is required because most classes have no fixed size and
// the required length is only known after the first rejected call.
std::vector<std::uint8_t> QueryTokenInformationBlock(HANDLE token, TOKEN_INFORMATION_CLASS infoClass) {
    DWORD required = 0;
    ::GetTokenInformation(token, infoClass, nullptr, 0, &required);
    if (required == 0) {
        return {};
    }
    std::vector<std::uint8_t> buffer(required, 0);
    if (!::GetTokenInformation(token, infoClass, buffer.data(), required, &required)) {
        return {};
    }
    buffer.resize(required);
    return buffer;
}

std::wstring FormatSid(PSID sid) {
    if (sid == nullptr || !::IsValidSid(sid)) {
        return {};
    }
    LPWSTR text = nullptr;
    if (!::ConvertSidToStringSidW(sid, &text) || text == nullptr) {
        return {};
    }
    std::wstring result(text);
    ::LocalFree(text);
    return result;
}

// AccountNameForSid resolves a SID to DOMAIN\Name. Unresolvable SIDs are normal
// (deleted accounts, SIDs from other machines), so failure yields the string
// form rather than an error.
std::wstring AccountNameForSid(PSID sid) {
    if (sid == nullptr || !::IsValidSid(sid)) {
        return {};
    }
    DWORD nameLength = 0;
    DWORD domainLength = 0;
    SID_NAME_USE use = SidTypeUnknown;
    ::LookupAccountSidW(nullptr, sid, nullptr, &nameLength, nullptr, &domainLength, &use);
    if (nameLength == 0) {
        return FormatSid(sid);
    }
    std::wstring name(nameLength, L'\0');
    std::wstring domain(domainLength == 0 ? 1 : domainLength, L'\0');
    if (!::LookupAccountSidW(nullptr, sid, name.data(), &nameLength, domain.data(), &domainLength, &use)) {
        return FormatSid(sid);
    }
    name.resize(nameLength);
    domain.resize(domainLength);
    return domain.empty() ? name : domain + L"\\" + name;
}

std::wstring IntegrityLevelText(HANDLE token) {
    const std::vector<std::uint8_t> buffer = QueryTokenInformationBlock(token, TokenIntegrityLevel);
    if (buffer.empty()) {
        return {};
    }
    const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data());
    if (label->Label.Sid == nullptr) {
        return {};
    }
    const PUCHAR count = ::GetSidSubAuthorityCount(label->Label.Sid);
    if (count == nullptr || *count == 0) {
        return {};
    }
    const DWORD rid = *::GetSidSubAuthority(label->Label.Sid, static_cast<DWORD>(*count - 1));
    if (rid >= SECURITY_MANDATORY_SYSTEM_RID) {
        return L"System";
    }
    if (rid >= SECURITY_MANDATORY_HIGH_RID) {
        return L"High";
    }
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID) {
        return L"Medium";
    }
    if (rid >= SECURITY_MANDATORY_LOW_RID) {
        return L"Low";
    }
    return L"Untrusted";
}

std::wstring PrivilegeNameForLuid(const LUID& luid) {
    LUID mutableLuid = luid;
    DWORD length = 0;
    ::LookupPrivilegeNameW(nullptr, &mutableLuid, nullptr, &length);
    if (length == 0) {
        return {};
    }
    std::wstring name(length, L'\0');
    if (!::LookupPrivilegeNameW(nullptr, &mutableLuid, name.data(), &length)) {
        return {};
    }
    name.resize(length);
    return name;
}

std::wstring PrivilegeDisplayNameFor(const std::wstring& privilegeName) {
    if (privilegeName.empty()) {
        return {};
    }
    DWORD length = 0;
    DWORD languageId = 0;
    ::LookupPrivilegeDisplayNameW(nullptr, privilegeName.c_str(), nullptr, &length, &languageId);
    if (length == 0) {
        return {};
    }
    std::wstring display(length + 1, L'\0');
    DWORD available = length + 1;
    if (!::LookupPrivilegeDisplayNameW(nullptr, privilegeName.c_str(), display.data(), &available, &languageId)) {
        return {};
    }
    display.resize(available);
    return display;
}

} // namespace

PrivilegeSnapshot EnumerateProcessPrivileges() {
    PrivilegeSnapshot snapshot{};

    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &rawToken)) {
        snapshot.diagnosticText = L"打开当前进程令牌失败，错误码 " + std::to_wstring(::GetLastError()) + L"。";
        return snapshot;
    }
    TokenHandleGuard token(rawToken);

    if (const std::vector<std::uint8_t> userBuffer = QueryTokenInformationBlock(token.get(), TokenUser);
        !userBuffer.empty()) {
        const auto* user = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
        snapshot.token.userSid = FormatSid(user->User.Sid);
        snapshot.token.userName = AccountNameForSid(user->User.Sid);
    }

    snapshot.token.integrityLevel = IntegrityLevelText(token.get());

    if (const std::vector<std::uint8_t> elevationBuffer = QueryTokenInformationBlock(token.get(), TokenElevation);
        elevationBuffer.size() >= sizeof(TOKEN_ELEVATION)) {
        const auto* elevation = reinterpret_cast<const TOKEN_ELEVATION*>(elevationBuffer.data());
        snapshot.token.elevated = elevation->TokenIsElevated != 0;
    }

    if (const std::vector<std::uint8_t> uiAccessBuffer = QueryTokenInformationBlock(token.get(), TokenUIAccess);
        uiAccessBuffer.size() >= sizeof(DWORD)) {
        snapshot.token.uiAccess = *reinterpret_cast<const DWORD*>(uiAccessBuffer.data()) != 0;
    }

    if (const std::vector<std::uint8_t> typeBuffer = QueryTokenInformationBlock(token.get(), TokenType);
        typeBuffer.size() >= sizeof(TOKEN_TYPE)) {
        const TOKEN_TYPE type = *reinterpret_cast<const TOKEN_TYPE*>(typeBuffer.data());
        snapshot.token.tokenType = type == TokenPrimary ? L"Primary" : L"Impersonation";
    }

    if (const std::vector<std::uint8_t> groupBuffer = QueryTokenInformationBlock(token.get(), TokenGroups);
        !groupBuffer.empty()) {
        const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(groupBuffer.data());
        snapshot.token.groups.reserve(groups->GroupCount);
        for (DWORD index = 0; index < groups->GroupCount; ++index) {
            const SID_AND_ATTRIBUTES& group = groups->Groups[index];
            // Deny-only and logon-id entries are filtered out: they are not
            // grants and listing them alongside real groups reads as if the
            // process had more membership than it does.
            if ((group.Attributes & SE_GROUP_LOGON_ID) != 0 || (group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0) {
                continue;
            }
            if ((group.Attributes & SE_GROUP_ENABLED) == 0) {
                continue;
            }
            std::wstring name = AccountNameForSid(group.Sid);
            if (!name.empty()) {
                snapshot.token.groups.push_back(std::move(name));
            }
        }
    }

    const std::vector<std::uint8_t> privilegeBuffer = QueryTokenInformationBlock(token.get(), TokenPrivileges);
    if (privilegeBuffer.empty()) {
        snapshot.diagnosticText = L"读取令牌权限数组失败，错误码 " + std::to_wstring(::GetLastError()) + L"。";
        return snapshot;
    }

    const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(privilegeBuffer.data());
    snapshot.privileges.reserve(privileges->PrivilegeCount);
    for (DWORD index = 0; index < privileges->PrivilegeCount; ++index) {
        const LUID_AND_ATTRIBUTES& raw = privileges->Privileges[index];
        PrivilegeEntry entry{};
        entry.luid = raw.Luid;
        entry.enabled = (raw.Attributes & SE_PRIVILEGE_ENABLED) != 0;
        entry.enabledByDefault = (raw.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
        entry.removed = (raw.Attributes & SE_PRIVILEGE_REMOVED) != 0;
        entry.name = PrivilegeNameForLuid(raw.Luid);
        entry.displayName = PrivilegeDisplayNameFor(entry.name);
        entry.description = DescribePrivilege(entry.name);
        entry.riskText = PrivilegeRiskText(entry.name);
        snapshot.privileges.push_back(std::move(entry));
    }

    snapshot.success = true;
    return snapshot;
}

} // namespace ks::r3::privilege
