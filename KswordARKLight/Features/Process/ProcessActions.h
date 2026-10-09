#pragma once

#include "../../../shared/usermode/backend/process/ProcessControls.h"

#include "ProcessModel.h"

#include <string>
#include <vector>

namespace Ksword::Features::Process {
using ks::r3::process::ProcessActionId;
using ks::r3::process::ProcessActionResult;




struct ProcessActionMenuItem {
    ProcessActionId id = ProcessActionId::OpenDetails;
    std::wstring text;
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
using ks::r3::process::PriorityClassForAction;

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
