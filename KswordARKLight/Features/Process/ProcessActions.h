#pragma once

#include "ProcessModel.h"

#include <string>
#include <vector>

namespace Ksword::Features::Process {

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

struct ProcessActionMenuItem {
    ProcessActionId id = ProcessActionId::OpenDetails;
    std::wstring text;
};

struct ProcessActionResult {
    bool success = false;
    std::wstring title;
    std::wstring detail;
};

// ExecuteProcessAction runs the Win32 layer for one context-menu command. Inputs
// are action id, selected PIDs, and current model snapshot for path lookup.
// Processing performs local Win32 actions and retained ArkDriverClient R0
// operations. Output is a result
// message that callers must surface to the user/status area.
ProcessActionResult ExecuteProcessAction(
    ProcessActionId actionId,
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows);

// PriorityClassForAction maps menu priority actions to Win32 priority classes.
// Input is a ProcessActionId; output is zero when the id is not a priority item.
DWORD PriorityClassForAction(ProcessActionId actionId);

// ExecuteR0ProcessDllInjection / ExecuteR0ProcessShellcodeInjection mirror the
// full Ksword5.1 ArkDriverClient process injection calls. Inputs are selected
// PIDs, their captured snapshot rows, and a user-picked payload path; processing
// holds each verified process instance through the R0 IOCTL; output is a
// display-ready operation result.
ProcessActionResult ExecuteR0ProcessDllInjection(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows,
    const std::wstring& dllPath);

ProcessActionResult ExecuteR0ProcessShellcodeInjection(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows,
    const std::wstring& shellcodePath);

} // namespace Ksword::Features::Process
