#pragma once
#include "../../shared/usermode/backend/system/AdminState.h"

#include "Win32Lean.h"

#include <string>
#include <vector>

namespace Ksword::Core {

// PrivilegeEnableResult records one startup AdjustTokenPrivileges attempt.
// Inputs are filled by EnableStartupPrivileges; processing code reads ok/error
// to summarize non-blocking startup privilege state; there is no behavior here.
struct PrivilegeEnableResult {
    std::wstring name;
    bool enabled = false;
    DWORD errorCode = ERROR_SUCCESS;
    std::wstring message;
};

// IsRunningAsAdmin checks the current token elevation/member state. There is no
// input; processing queries the process token and Administrators SID; output is
// true when elevated enough for SCM/driver operations.
using ks::r3::common::IsRunningAsAdmin;

// RelaunchElevated starts the same executable through ShellExecuteW("runas").
// Input is the current command tail; processing asks UAC for elevation; output
// is true when ShellExecute accepted the launch request.
bool RelaunchElevated(const std::wstring& commandLineTail = L"");

// IsUiAccessEnabled reports the current token UIAccess flag. There is no input;
// processing queries TokenUIAccess; output is false on failure or when disabled.
bool IsUiAccessEnabled();

// DescribePrivilegeState creates compact status text. There is no input;
// processing combines Admin/UIAccess state; output is suitable for logs/status.
std::wstring DescribePrivilegeState();

// EnableStartupPrivileges enables common process privileges after the shell is
// created. There is no input; processing opens the current token and applies
// AdjustTokenPrivileges one privilege at a time; output contains per-privilege
// status and never blocks startup because unavailable privileges are recorded.
std::vector<PrivilegeEnableResult> EnableStartupPrivileges();

// SummarizePrivilegeEnableResults creates a compact one-line status string.
// Input is the per-privilege result list; processing counts success/failure and
// names a few failures; output is suitable for status text or tooltip display.
std::wstring SummarizePrivilegeEnableResults(const std::vector<PrivilegeEnableResult>& results);

// LaunchSelfWithSystemUiAccessToken starts a new instance with a duplicated
// SYSTEM primary token whose TokenUIAccess flag is enabled. Input is an optional
// detail output string; processing follows the KswordARK SYSTEM TokenUIAccess
// fallback path; output is true when the replacement process is created.
bool LaunchSelfWithSystemUiAccessToken(std::wstring* detailTextOut = nullptr);

} // namespace Ksword::Core
