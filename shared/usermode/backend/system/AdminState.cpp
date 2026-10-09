#include "AdminState.h"
#include <vector>
namespace ks::r3::common {
bool IsRunningAsAdmin() {
    BOOL elevated = FALSE;
    HANDLE rawToken = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &rawToken)) {
        UniqueHandle token(rawToken);
        TOKEN_ELEVATION elevation{};
        DWORD bytes = 0;
        if (::GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &bytes)) {
            elevated = elevation.TokenIsElevated != 0;
        }
    }
    if (elevated) {
        return true;
    }

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    if (!::AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators)) {
        return false;
    }
    BOOL isMember = FALSE;
    const BOOL ok = ::CheckTokenMembership(nullptr, administrators, &isMember);
    ::FreeSid(administrators);
    return ok && isMember;
}
}
