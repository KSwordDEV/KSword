#pragma once

#include <Windows.h>
#include "DwmZOrderProtocol.h"

namespace ks::dwm_order
{
    inline bool MatchesProcessIdentity(HANDLE process, const WindowIdentity& identity)
    {
        if (!process || process == INVALID_HANDLE_VALUE || !identity.processId
            || !identity.processCreated || GetProcessId(process) != identity.processId) return false;
        FILETIME created{}, exited{}, kernel{}, user{};
        DWORD code = 0;
        return GetProcessTimes(process, &created, &exited, &kernel, &user)
            && !exited.dwLowDateTime && !exited.dwHighDateTime
            && GetExitCodeProcess(process, &code) && code == STILL_ACTIVE
            && ((static_cast<std::uint64_t>(created.dwHighDateTime) << 32)
                | created.dwLowDateTime) == identity.processCreated;
    }
}
