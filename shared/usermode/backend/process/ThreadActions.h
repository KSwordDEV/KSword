#pragma once
#include "DetailActionTypes.h"
#include "../Common.h"
#include "ThreadActionSupport.h"
#include "../../../../shared/ThreadAffinityR3.h"
namespace ks::r3::process_detail {
bool OpenVerifiedProcessActionTarget(
    DWORD targetProcessId,
    ULONGLONG expectedProcessCreationTime100ns,
    DWORD requestedProcessAccess,
    ks::r3::common::UniqueHandle& processOut,
    std::wstring& errorText);
bool OpenVerifiedThreadActionTarget(
    DWORD targetProcessId,
    ULONGLONG expectedProcessCreationTime100ns,
    DWORD targetThreadId,
    ULONGLONG expectedThreadCreationTime100ns,
    DWORD requestedThreadAccess,
    ks::r3::common::UniqueHandle& processOut,
    ks::r3::common::UniqueHandle& threadOut,
    std::wstring& errorText);
ProcessDetailActionResult SuspendDetailThread(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns);
ProcessDetailActionResult ResumeDetailThread(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns);
ProcessDetailActionResult TerminateDetailThread(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns);
ProcessDetailActionResult SetDetailThreadAffinity(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns, const ksword::thread_affinity_r3::Rule& rule);
}
