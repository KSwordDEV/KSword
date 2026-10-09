#pragma once
#include "../Common.h"
#include <string>
#include <vector>
#include <array>
namespace ks::r3::security {
struct MiscAuditRow {
    std::wstring category;
    std::wstring item;
    std::wstring state;
    std::wstring source;
    std::wstring risk;
    std::wstring detail;
};
struct CommandResult {
    bool started = false;
    DWORD exitCode = ERROR_PROCESS_ABORTED;
    DWORD win32Error = ERROR_SUCCESS;
    std::wstring output;
    std::wstring errorText;
};
std::wstring TrimCopy(const std::wstring& text);
std::wstring CollapseWhitespace(const std::wstring& text);
std::wstring QuotePowerShellCommand(const std::wstring& text);
std::wstring GetLastErrorText(const DWORD error);
void AppendRow(
    std::vector<MiscAuditRow>& rows,
    std::wstring category,
    std::wstring item,
    std::wstring state,
    std::wstring source,
    std::wstring risk,
    std::wstring detail);
CommandResult RunCaptureCommand(const std::wstring& commandLine, const DWORD timeoutMs = 12000);
std::wstring PowerShellCommand(const std::wstring& script);
CommandResult RunPowerShellScalar(const std::wstring& script, const DWORD timeoutMs = 12000);
void AddCommandRow(
    std::vector<MiscAuditRow>& rows,
    const std::wstring& category,
    const std::wstring& item,
    const std::wstring& source,
    const CommandResult& command,
    const std::wstring& cleanHint = L"已查询");
bool QueryRegistryValueString(const std::wstring& subKey, const std::wstring& valueName, std::wstring& valueOut, std::wstring& errorOut);
void AddRegistryRow(
    std::vector<MiscAuditRow>& rows,
    const std::wstring& category,
    const std::wstring& item,
    const std::wstring& subKey,
    const std::wstring& valueName);
bool QueryServiceStatusText(const std::wstring& serviceName, std::wstring& statusOut, std::wstring& errorOut);
void AddServiceRow(
    std::vector<MiscAuditRow>& rows,
    const std::wstring& category,
    const std::wstring& item,
    const std::wstring& serviceName);
void AppendCodeIntegrityR3(std::vector<MiscAuditRow>& rows);
}
