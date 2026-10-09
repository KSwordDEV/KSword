#pragma once
#include "ProcessEnumerator.h"
#include "../Common.h"
#include <cstdint>
#include <string>
#include <vector>
namespace ks::r3::process {
enum class ProcessActionId {
    CopyCell,
    CopyRow,
    CopyVisibleResults,
    ExportVisibleResults,
    OpenDetails,
    OpenImageInFileModule,
    OpenNetworkForProcess,
    OpenHandlesForProcess,
    OpenEtwForProcess,
    OpenWindowsForProcess,
    TerminateProcessMultiMethod,
    TerminateProcess,
    TerminateProcessTree,
    R0TerminateProcess,
    R0TerminateProcessTree,
    R0SuspendProcess,
    R0ResumeProcess,
    R0HideUnlinkOnly,
    R0HidePatchPidOnly,
    R0HideLegacyBoth,
    R0UnhideProcess,
    R0ClearHiddenMarks,
    R0EnableBreakOnTermination,
    R0DisableBreakOnTermination,
    R0DisableApcInsertion,
    R0DkomRemoveFromCidTable,
    R0SetIntegrityUntrusted,
    R0SetIntegrityLow,
    R0SetIntegrityMedium,
    R0SetIntegrityMediumPlus,
    R0SetIntegrityHigh,
    R0SetIntegritySystem,
    R0InjectDll,
    R0InjectShellcode,
    RefreshPplProtectionLevel,
    SuspendProcess,
    ResumeProcess,
    EnableEfficiencyMode,
    DisableEfficiencyMode,
    SetCriticalProcess,
    ClearCriticalProcess,
    OpenFolder,
    OpenMemoryOperation,
    ScanHotkeys,
    SetPriorityIdle,
    SetPriorityBelowNormal,
    SetPriorityNormal,
    SetPriorityAboveNormal,
    SetPriorityHigh,
    SetPriorityRealtime,
    R0SetPplNone,
    R0SetPplAuthenticode,
    R0SetPplCodeGen,
    R0SetPplAntimalware,
    R0SetPplLsa,
    R0SetPplWindows,
    R0SetPplWinTcb,
    // 完整 PP（PsProtectedTypeProtected）。与上面的 PPL 共用同一个 IOCTL，
    // 只是 PS_PROTECTION 字节里的类型位从 1 变成 2。
    R0SetPpAuthenticode,
    R0SetPpCodeGen,
    R0SetPpAntimalware,
    R0SetPpLsa,
    R0SetPpWindows,
    R0SetPpWinTcb
};
struct ProcessActionResult {
    bool success = false;
    std::wstring title;
    std::wstring detail;
};
std::wstring Utf8ToWide(const std::string& text);
std::wstring PidListText(const std::vector<DWORD>& pids);
const ProcessSnapshotRow* FindRowByPid(const std::vector<ProcessSnapshotRow>& rows, DWORD pid);
std::vector<ProcessSnapshotRow> BuildProcessActionTargets(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows);
std::vector<DWORD> CollectR3ProcessTreePids(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows);
ProcessActionResult FailureResult(const wchar_t* title, const std::vector<DWORD>& pids, const wchar_t* reason);
std::wstring Win32ErrorText(const DWORD error);
std::wstring Hex32(const LONG status);
std::wstring Hex64(const std::uint64_t value);
std::wstring AsciiLiteralToWide(const char* text);
FARPROC NtProc(const char* name);
bool EnableCurrentProcessPrivilege(const wchar_t* privilegeName, std::wstring& detail);
void AppendIoLine(std::wstring& detail, DWORD pid, const wchar_t* operation, bool ok, const std::wstring& message);
void AppendIoLine(std::wstring& detail, const wchar_t* operation, bool ok, const std::wstring& message);
bool IsProtectedSystemPid(DWORD pid);
bool IsProcessPresentBySnapshot(DWORD pid, bool* queryOkOut);
ks::r3::common::UniqueHandle OpenProcessForAction(
    const DWORD pid,
    const ULONGLONG expectedCreationTime100ns,
    const DWORD access,
    std::wstring& errorText,
    const bool rejectProtected = true);
ProcessActionResult ExecuteMultiMethodTerminate(const std::vector<ProcessSnapshotRow>& actionTargets);
bool NtSuspendOrResumeProcess(DWORD pid, ULONGLONG expectedCreationTime100ns, bool resume, std::wstring& message);
bool SetCriticalFlagForPid(DWORD pid, ULONGLONG expectedCreationTime100ns, bool enable, std::wstring& message);
bool SetEfficiencyModeForPid(DWORD pid, ULONGLONG expectedCreationTime100ns, bool enable, std::wstring& message);
bool SetPriorityForPid(
    DWORD pid,
    ULONGLONG expectedCreationTime100ns,
    DWORD priorityClass,
    std::wstring& detail);
ProcessActionResult ExecuteLocalProcessAction(
    ProcessActionId actionId,
    const std::vector<ProcessSnapshotRow>& actionTargets);
DWORD PriorityClassForAction(ProcessActionId actionId);
ProcessActionResult TerminateProcesses(const std::vector<ProcessSnapshotRow>& actionTargets);
}
