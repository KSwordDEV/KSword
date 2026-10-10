#include "ProcessNavigationIdentity.h"

namespace ks::r3::process {
ULONGLONG QueryProcessCreationTimeR3(DWORD processId, ULONGLONG expectedCreationTime100ns,ProcessIdentityEvidence* output) {
    ProcessIdentityEvidence local;auto& evidence=output?*output:local;evidence={};
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) {
        evidence.openError=::GetLastError();
        return 0U;
    }
    evidence.opened=true;struct Owner{HANDLE handle;ProcessIdentityEvidence& e;~Owner(){e.closeAttempted=true;::SetLastError(0);e.closed=::CloseHandle(handle)!=FALSE;e.closeError=e.closed?0: ::GetLastError();}} owner{process,evidence};
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    ULARGE_INTEGER value{};
    if (::GetProcessTimes(process, &creation, &exit, &kernel, &user)) {
        value.LowPart = creation.dwLowDateTime;
        value.HighPart = creation.dwHighDateTime;
        evidence.timeKnown=value.QuadPart!=0;evidence.creationTime=value.QuadPart;
    }else evidence.timeError=::GetLastError();
    evidence.matched=evidence.timeKnown&&(!expectedCreationTime100ns||value.QuadPart==expectedCreationTime100ns);
    if (expectedCreationTime100ns != 0U && value.QuadPart != expectedCreationTime100ns) {
        return 0U;
    }
    return value.QuadPart;

}
}
