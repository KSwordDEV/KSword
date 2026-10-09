#include "ProcessDetailIdentity.h"

namespace ks::r3::process_detail::detail {
bool AcquireDetailIdentityLease(DWORD processId, ULONGLONG expectedCreationTime100ns, ks::r3::common::UniqueHandle& identityProcess, std::wstring& statusText) {
    const HANDLE rawIdentityProcess = ::OpenProcess(kProcessBasicAccess, FALSE, processId);
    const DWORD identityOpenError = rawIdentityProcess ? ERROR_SUCCESS : ::GetLastError();
    identityProcess.reset(rawIdentityProcess);
    if (!identityProcess.valid()) {
        statusText = Win32ErrorText(L"OpenProcess(identity)", identityOpenError);
        return false;
    }

    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    const BOOL identityTimeOk = ::GetProcessTimes(
        identityProcess.get(),
        &creationTime,
        &exitTime,
        &kernelTime,
        &userTime);
    const DWORD identityTimeError = identityTimeOk ? ERROR_SUCCESS : ::GetLastError();
    const ULONGLONG actualCreationTime100ns = identityTimeOk
        ? (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
            static_cast<ULONGLONG>(creationTime.dwLowDateTime)
        : 0U;
    if (!identityTimeOk || actualCreationTime100ns == 0U ||
        actualCreationTime100ns != expectedCreationTime100ns) {
        statusText = !identityTimeOk
            ? Win32ErrorText(L"GetProcessTimes(identity)", identityTimeError)
            : L"Process identity changed (PID was reused); detail refresh skipped.";
        return false;
    }


    return true;
}
}
