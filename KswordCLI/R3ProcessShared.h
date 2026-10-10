#pragma once
#include "CommandRegistry.h"
#include "../shared/usermode/backend/Common.h"
#include <stdexcept>
namespace ks::cli::process {
struct Lease {
    ks::r3::common::UniqueHandle handle;
    DWORD pid = 0, error = ERROR_SUCCESS;
    std::uint64_t creationTime = 0;
    bool matches = false;
    Lease(const Args& args, DWORD access = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE) {
        pid = args.u32(L"--pid"); (void)args.require(L"--pid");
        if (args.has(L"--creation-time") && !args.integer(L"--creation-time")) throw std::invalid_argument("--creation-time must be positive");
        handle.reset(OpenProcess(access, FALSE, pid));
        if (!handle.valid()) { error = GetLastError(); return; }
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetProcessTimes(handle.get(), &created, &exited, &kernel, &user)) { error = GetLastError(); return; }
        creationTime = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        matches = !args.has(L"--creation-time") || creationTime == args.integer(L"--creation-time");
    }
    bool alive() const { return handle.valid() && WaitForSingleObject(handle.get(), 0) == WAIT_TIMEOUT; }
    Json json() const { return Json::object({{L"pid", Json::number(pid)}, {L"creationTime", creationTime ? Json::count(creationTime) : Json{}},
        {L"identityMatched", Json::boolean(matches)}, {L"win32Error", Json::number(error)}}); }
};
}
