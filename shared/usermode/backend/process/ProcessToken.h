#pragma once
#include "../Common.h"
#include "ProcessDetailTypes.h"
#include "ThreadActions.h"
#include <sddl.h>
#include <winternl.h>
#include <array>
#include <functional>
#include <cstddef>
#include <vector>
#include <string>
namespace ks::r3::process_detail::token {
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
std::wstring TokenClassName(int informationClass);
std::wstring SidText(PSID sid);
bool QueryTokenBytes(HANDLE token, int informationClass, std::vector<std::byte>& bytes, DWORD& error,bool* malformed = nullptr);
struct TokenClassSnapshot {
    int informationClass = 0;
    bool available = false;
    bool malformed = false;
    DWORD win32Error = ERROR_SUCCESS;
    std::vector<std::byte> bytes;
};
struct TokenQuerySnapshot {
    bool tokenOpened = false, identityMatched = false;
    bool win32ErrorKnown = false;
    DWORD win32Error = ERROR_SUCCESS;
    std::vector<TokenClassSnapshot> classes;
};
TokenQuerySnapshot QueryTokenClasses(DWORD processId,ULONGLONG expectedCreationTime,const std::vector<int>& classes);
std::wstring RawPreview(const std::vector<std::byte>& bytes);
bool VerifyProcessIdentity(
    HANDLE process,
    ULONGLONG expectedProcessCreationTime100ns,
    std::wstring& errorText);
ProcessTokenReportSnapshot QueryTokenReportSnapshotR3(
    const DWORD processId,
    const ULONGLONG expectedProcessCreationTime100ns,
    const std::function<void(ProcessTokenReportSnapshot&, DWORD)>& fallback);
ProcessDetailActionResult AdjustTokenPrivilegeR3(DWORD processId, ULONGLONG expectedCreationTime, const std::wstring& name, LUID luid, bool enable, ks::r3::common::UniqueHandle& process, DWORD& r3Error);
ProcessDetailActionResult WriteRawTokenValue(int informationClass, DWORD processId, ULONGLONG expectedProcessCreationTime100ns, std::vector<std::byte> payload);
}
