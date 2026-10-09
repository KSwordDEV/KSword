#include "ProcessNavigationIdentity.h"

namespace ks::r3::process {
ULONGLONG QueryProcessCreationTimeR3(DWORD processId, ULONGLONG expectedCreationTime100ns) {
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) {
        return 0U;
    }
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    ULARGE_INTEGER value{};
    if (::GetProcessTimes(process, &creation, &exit, &kernel, &user)) {
        value.LowPart = creation.dwLowDateTime;
        value.HighPart = creation.dwHighDateTime;
    }
    ::CloseHandle(process);
    if (expectedCreationTime100ns != 0U && value.QuadPart != expectedCreationTime100ns) {
        return 0U;
    }
    return value.QuadPart;

}
}
