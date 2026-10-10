#pragma once

#include "../Win32.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace ks::r3::process_detail {

struct ProcessQueryEvidence {
    bool available = false;
    bool win32ErrorKnown = false, ntStatusKnown = false;
    DWORD win32Error = ERROR_SUCCESS;
    LONG ntStatus = 0;
    bool emptyValue = false;
};

// ProcessBasicInfo carries the read-only fields shown by the Basic page.
// Inputs are collected from Win32 and ntdll process queries; processing converts
// native values into UI-ready strings; consumers only render the fields.
struct ProcessBasicInfo {
    DWORD processId = 0;
    DWORD parentProcessId = 0;
    DWORD sessionId = 0;
    DWORD handleCount = 0;
    DWORD threadCount = 0;
    ULONGLONG workingSetBytes = 0;
    ULONGLONG privateBytes = 0;
    ULONGLONG ioBytes = 0;
    std::uintptr_t pebAddress = 0;
    std::uint64_t affinityMask = 0;
    bool pebAddressKnown = false;
    bool affinityKnown = false;
    bool isAdmin = false;
    bool adminKnown = false;
    std::wstring processName;
    std::wstring parentProcessName;
    std::wstring imagePath;
    std::wstring commandLine;
    std::wstring startTimeText;
    std::wstring bitness;
    std::wstring userName;
    std::wstring integrityLevel;
    std::wstring priorityText;
    std::wstring statusText;
    ULONGLONG creationTime100ns = 0;
    DWORD priorityClass = 0;
    std::map<std::wstring, ProcessQueryEvidence> evidence;
};

// ProcessThreadInfo describes one thread row. Inputs come from Toolhelp thread
// snapshots and optional OpenThread queries; processing keeps metadata cheap and
// non-invasive; consumers display the row in the Threads tab.
struct ProcessThreadInfo {
    DWORD threadId = 0;
    DWORD ownerProcessId = 0;
    ULONGLONG creationTime100ns = 0;
    LONG basePriority = 0;
    LONG deltaPriority = 0;
    DWORD suspendCount = 0;
    std::uintptr_t startAddress = 0;
    std::wstring statusText;
};

// ProcessModuleInfo describes one module row. Inputs come from PSAPI module
// enumeration; processing resolves path/name/base/size where available;
// consumers display the row in the Modules tab.
struct ProcessModuleInfo {
    std::wstring moduleName;
    std::wstring modulePath;
    std::uintptr_t baseAddress = 0;
    DWORD imageSize = 0;
    DWORD representativeThreadId = 0;
    ULONGLONG representativeThreadCreationTime100ns = 0;
    std::wstring statusText;
};

// ProcessR0AuditInfo is one read-only R0 evidence row shown in the audit tab.
// Inputs come from ArkDriverClient cross-view wrappers; consumers only render
// the object/source/anomaly/status fields and must not treat addresses as
// writable operation handles.
struct ProcessR0AuditInfo {
    std::wstring scope;
    DWORD processId = 0;
    DWORD threadId = 0;
    std::uintptr_t objectAddress = 0;
    std::uintptr_t relatedObjectAddress = 0;
    std::uintptr_t startAddress = 0;
    ULONG sourceMask = 0;
    ULONG anomalyFlags = 0;
    ULONG confidence = 0;
    std::wstring sourceText;
    std::wstring anomalyText;
    std::wstring detailText;
};

// ProcessDetailSnapshot is a complete page refresh result. Input is a target
// PID; processing is performed by ProcessDetailCollector; output is copied into
// the page and remains valid without holding process handles.
struct ProcessDetailSnapshot {
    ProcessBasicInfo basic;
    std::vector<ProcessThreadInfo> threads;
    std::vector<ProcessModuleInfo> modules;
    std::vector<ProcessR0AuditInfo> r0AuditRows;
    std::wstring errorText;
    bool basicSucceeded = false;
    bool threadsSucceeded = false;
    bool modulesSucceeded = false;
    bool r0AuditSucceeded = false;
};

// ProcessTokenReportSnapshot contains the fully rendered, immutable token
// report collected away from the UI thread. The page only assigns these strings
// to controls when the newest request completes.
struct ProcessTokenReportSnapshot {
    bool succeeded = false;
    bool identityMatched = false;
    std::wstring statusText;
    std::wstring reportText;
    std::wstring editorStatusText;
};

// ProcessTokenSwitchSnapshot keeps the queried boolean token fields in their
// UI order: ten direct information classes followed by two mandatory-policy
// bits. It never owns a token handle or an HWND.
struct ProcessTokenSwitchSnapshot {
    bool succeeded = false;
    bool identityMatched = false;
    std::array<bool, 12> values{};
    std::array<bool, 12> updated{};
    std::wstring statusText;
};

// ProcessPebSnapshot is a read-only PEB and virtual-address-space result. The
// worker fills it without retaining remote-process handles; the UI applies it
// only after the latest request completes.
struct ProcessPebSnapshot {
    bool completed = false;
    bool identityMatched = false;
    bool affinityKnown = false;
    bool priorityKnown = false;
    bool selectedPebKnown = false;
    int priorityComboIndex = 0;
    std::wstring statusText;
    std::wstring reportText;
    std::wstring affinityText;
    std::wstring commandLine;
    std::wstring imagePath;
    std::wstring currentDirectory;
    std::wstring imageBase;
};

} // namespace ks::r3::process_detail
