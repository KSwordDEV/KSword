#pragma once
#include "../Common.h"
#include <string>
#include <vector>
#include <array>
#include <functional>
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
    bool exitCodeKnown=false,waitCompleted=false,timedOut=false,cancelled=false,terminated=false,outputTruncated=false,decodeMalformed=false;
    DWORD outputError=0,terminationError=0,terminationWait=0,closeError=0;
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
CommandResult RunCaptureCommand(const std::wstring& commandLine, const DWORD timeoutMs = 12000,const std::function<bool()>& cancelled={});
CommandResult RunPowerShellJson(const std::wstring& body,DWORD timeoutMs=12000,const std::function<bool()>& cancelled={});
enum class SecurityProbeKind {Command,Registry,Service};
struct SecurityProbe {std::wstring id,source;SecurityProbeKind kind=SecurityProbeKind::Command;std::wstring body,path,name;};
struct SecurityRegistryEvidence {bool openAttempted=false,opened=false,queryAttempted=false,available=false,absent=false,limited=false,malformed=false,closeAttempted=false,closed=false;DWORD openError=0,queryError=0,closeError=0,type=0,reportedBytes=0;std::vector<std::uint8_t> bytes;};
struct SecurityServiceEvidence {bool scmOpened=false,opened=false,available=false,absent=false,serviceCloseAttempted=false,serviceClosed=false,scmCloseAttempted=false,scmClosed=false;DWORD error=0,closeError=0;SERVICE_STATUS_PROCESS status{};};
struct SecurityProbeResult {SecurityProbe probe;int code=5;CommandResult command;SecurityRegistryEvidence registry;SecurityServiceEvidence service;};
struct SecurityProbeOptions {DWORD durationMs=30000,timeoutMs=12000;std::function<bool()> cancelled;};
struct SecuritySnapshot {bool limited=false,cancelled=false;std::size_t requestedCount=0;std::vector<SecurityProbeResult> results;};
SecuritySnapshot CollectSecurityProbes(const std::vector<SecurityProbe>& probes,const SecurityProbeOptions& options={});
const std::vector<SecurityProbe>& CodeIntegrityProbes();
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
