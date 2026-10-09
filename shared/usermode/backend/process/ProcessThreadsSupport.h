#pragma once
#include "ProcessDetailTypes.h"
#include "ProcessBasicInfoSupport.h"
#include "../Common.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <limits>
namespace ks::r3::process_detail::detail {
constexpr DWORD kThreadQueryAccess = THREAD_QUERY_LIMITED_INFORMATION;
constexpr LONG kThreadQuerySetWin32StartAddressClass = 9;
using NtQueryInformationThreadFn = LONG(NTAPI*)(HANDLE, LONG, PVOID, ULONG, PULONG);
struct NtThreadApi {
    NtQueryInformationThreadFn queryInformationThread = nullptr;

    // available reports whether NtQueryInformationThread was resolved. There is
    // no input; processing checks the stored pointer; output is false when the
    // Threads page must fall back to Toolhelp-only metadata.
    bool available() const {
        return queryInformationThread != nullptr;
    }
};
template <typename Fn>
Fn ResolveProc(HMODULE module, const char* name) {
    return module ? reinterpret_cast<Fn>(::GetProcAddress(module, name)) : nullptr;
}
NtThreadApi LoadNtThreadApi();
std::vector<ProcessThreadInfo> CollectThreads(DWORD processId, bool& succeededOut, std::wstring& statusOut);
}
