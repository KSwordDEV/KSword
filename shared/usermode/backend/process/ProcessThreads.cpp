#include "ProcessThreadsSupport.h"
#include <algorithm>
#include <cstddef>
#include <cwchar>
#include <limits>
#include <sstream>
#include <utility>
#pragma comment(lib, "Psapi.lib")
namespace ks::r3::process_detail::detail {
NtThreadApi LoadNtThreadApi() {
    NtThreadApi api{};
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = ::LoadLibraryW(L"ntdll.dll");
    }
    api.queryInformationThread = ResolveProc<NtQueryInformationThreadFn>(ntdll, "NtQueryInformationThread");
    return api;
}
std::vector<ProcessThreadInfo> CollectThreads(DWORD processId, bool& succeededOut, std::wstring& statusOut) {
    succeededOut = false;
    statusOut.clear();
    std::vector<ProcessThreadInfo> rows;
    const NtThreadApi threadApi = LoadNtThreadApi();

    ks::r3::common::UniqueHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot.valid()) {
        statusOut = Win32ErrorText(L"CreateToolhelp32Snapshot(THREAD)", ::GetLastError());
        return rows;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!::Thread32First(snapshot.get(), &entry)) {
        statusOut = Win32ErrorText(L"Thread32First", ::GetLastError());
        return rows;
    }

    do {
        if (entry.th32OwnerProcessID != processId) {
            continue;
        }

        ProcessThreadInfo row{};
        row.threadId = entry.th32ThreadID;
        row.ownerProcessId = entry.th32OwnerProcessID;
        row.basePriority = entry.tpBasePri;
        row.deltaPriority = entry.tpDeltaPri;
        row.suspendCount = 0;

        ks::r3::common::UniqueHandle thread(::OpenThread(kThreadQueryAccess, FALSE, row.threadId));
        if (!thread.valid()) {
            row.statusText = L"OpenThread limited info failed: " + ks::r3::common::LastErrorMessage();
            rows.push_back(std::move(row));
            continue;
        }

        const DWORD actualOwnerProcessId = ::GetProcessIdOfThread(thread.get());
        if (actualOwnerProcessId == 0U || actualOwnerProcessId != processId) {
            // The Toolhelp entry became stale before OpenThread completed. Do not
            // retain a row that could later represent another process's thread.
            continue;
        }
        row.ownerProcessId = actualOwnerProcessId;

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL creationTimeOk = ::GetThreadTimes(
            thread.get(),
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);
        if (creationTimeOk) {
            row.creationTime100ns =
                (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
                static_cast<ULONGLONG>(creationTime.dwLowDateTime);
        } else {
            row.statusText = L"GetThreadTimes failed: " + ks::r3::common::LastErrorMessage();
        }

        if (threadApi.available()) {
            PVOID startAddress = nullptr;
            const LONG status = threadApi.queryInformationThread(
                thread.get(),
                kThreadQuerySetWin32StartAddressClass,
                &startAddress,
                sizeof(startAddress),
                nullptr);
            if (status >= 0) {
                row.startAddress = reinterpret_cast<std::uintptr_t>(startAddress);
                if (creationTimeOk) {
                    row.statusText = L"OK";
                }
            } else if (creationTimeOk) {
                row.statusText = L"NtQueryInformationThread failed";
            }
        } else if (creationTimeOk) {
            row.statusText = L"OK; NtQueryInformationThread unavailable";
        }
        rows.push_back(std::move(row));
    } while (::Thread32Next(snapshot.get(), &entry));

    succeededOut = true;
    statusOut = L"OK";
    std::sort(rows.begin(), rows.end(), [](const ProcessThreadInfo& left, const ProcessThreadInfo& right) {
        return left.threadId < right.threadId;
    });
    return rows;
}
}
