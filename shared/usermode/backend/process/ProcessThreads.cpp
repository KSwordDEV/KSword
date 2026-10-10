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
std::vector<ProcessThreadInfo> CollectThreads(DWORD processId, bool& succeededOut, std::wstring& statusOut, ThreadEnumerationEvidence* evidence) {
    ThreadEnumerationEvidence local;
    if (!evidence) evidence = &local;
    *evidence = {};
    succeededOut = false;
    statusOut.clear();
    std::vector<ProcessThreadInfo> rows;
    const NtThreadApi threadApi = LoadNtThreadApi();

    ks::r3::common::UniqueHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot.valid()) {
        evidence->win32Error = ::GetLastError();
        statusOut = Win32ErrorText(L"CreateToolhelp32Snapshot(THREAD)", evidence->win32Error);
        return rows;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!::Thread32First(snapshot.get(), &entry)) {
        evidence->win32Error = ::GetLastError();
        if (evidence->win32Error == ERROR_NO_MORE_FILES) {evidence->complete = true; succeededOut = true;}
        statusOut = Win32ErrorText(L"Thread32First", evidence->win32Error);
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

        // Class 9 requires QUERY_INFORMATION. Keep limited metadata available
        // when the target denies that stronger read permission.
        ks::r3::common::UniqueHandle thread(::OpenThread(kThreadQueryAccess | THREAD_QUERY_INFORMATION, FALSE, row.threadId));
        if (!thread.valid()) thread.reset(::OpenThread(kThreadQueryAccess, FALSE, row.threadId));
        if (!thread.valid()) {
            row.queryEvidence = {false,true,false,::GetLastError()};
            row.statusText = L"OpenThread limited info failed: " + ks::r3::common::LastErrorMessage(row.queryEvidence.win32Error);
            rows.push_back(std::move(row));
            continue;
        }

        const DWORD actualOwnerProcessId = ::GetProcessIdOfThread(thread.get());
        if (actualOwnerProcessId == 0U || actualOwnerProcessId != processId) {
            ++evidence->skippedCount;
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
            row.identityKnown = true; row.queryEvidence.available = true;
            row.creationTime100ns =
                (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
                static_cast<ULONGLONG>(creationTime.dwLowDateTime);
        } else {
            row.queryEvidence = {false,true,false,::GetLastError()};
            row.statusText = L"GetThreadTimes failed: " + ks::r3::common::LastErrorMessage(row.queryEvidence.win32Error);
        }

        if (threadApi.available()) {
            PVOID startAddress = nullptr;
            const LONG status = threadApi.queryInformationThread(
                thread.get(),
                kThreadQuerySetWin32StartAddressClass,
                &startAddress,
                sizeof(startAddress),
                nullptr);
            row.startEvidence = {status == 0,false,true,0,status};
            if (status == 0) {
                row.startAddress = reinterpret_cast<std::uintptr_t>(startAddress);
                row.startAddressKnown = true;
                if (creationTimeOk) {
                    row.statusText = L"OK";
                }
            } else if (creationTimeOk) {
                row.statusText = L"NtQueryInformationThread failed";
            }
            // ThreadSuspendCount (35), ULONG, since Windows 8.1; phnt ntpsapi.h.
            const LONG suspendStatus = threadApi.queryInformationThread(thread.get(),35,&row.suspendCount,sizeof(row.suspendCount),nullptr);
            row.suspendCountKnown = suspendStatus == 0;
            row.suspendEvidence = {suspendStatus == 0,false,true,0,suspendStatus};
        } else if (creationTimeOk) {
            row.startEvidence = {false,true,false,ERROR_PROC_NOT_FOUND};
            row.suspendEvidence = row.startEvidence;
            row.statusText = L"OK; NtQueryInformationThread unavailable";
        }
        rows.push_back(std::move(row));
    } while (::Thread32Next(snapshot.get(), &entry));
    evidence->win32Error = ::GetLastError();
    evidence->complete = evidence->win32Error == ERROR_NO_MORE_FILES;
    if (evidence->complete) evidence->win32Error = ERROR_SUCCESS;

    succeededOut = true;
    statusOut = L"OK";
    std::sort(rows.begin(), rows.end(), [](const ProcessThreadInfo& left, const ProcessThreadInfo& right) {
        return left.threadId < right.threadId;
    });
    return rows;
}
}
