#pragma once
#include "../Win32.h"
#include <string>
#include <vector>
namespace ks::r3::privilege {
struct PrivilegeProperty {
    std::wstring name;
    std::wstring value;
};
struct PrivilegeEntry {
    std::wstring name;          // Constant form, e.g. SeDebugPrivilege.
    std::wstring displayName;   // Localized name from LookupPrivilegeDisplayNameW.
    LUID luid{};
    bool enabled = false;
    bool enabledByDefault = false;
    bool removed = false;       // SE_PRIVILEGE_REMOVED: gone for this token's life.
    std::wstring description;   // What holding this privilege actually allows.
    std::wstring riskText;      // Non-empty for privileges that bypass access checks.
};
struct TokenSummary {
    std::wstring userName;
    std::wstring userSid;
    std::wstring integrityLevel;
    std::wstring tokenType;
    bool elevated = false;
    bool uiAccess = false;
    std::vector<std::wstring> groups;
};
struct PrivilegeSnapshot {
    bool success = false;
    std::wstring diagnosticText;
    TokenSummary token;
    std::vector<PrivilegeEntry> privileges;
};
std::wstring PrivilegeStateText(const PrivilegeEntry& entry);
std::wstring DescribePrivilege(const std::wstring& privilegeName);
std::wstring PrivilegeRiskText(const std::wstring& privilegeName);
}
