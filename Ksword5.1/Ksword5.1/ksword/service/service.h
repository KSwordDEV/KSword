#pragma once

// ============================================================
// ksword/service/service.h
// Namespace: ks::service
// Purpose:
// - Provide reusable Win32 Service Control Manager helpers.
// - Keep UI code free of raw OpenSCManager/OpenService calls.
// - Expose only standard C++ strings, vectors, and integer values.
// ============================================================

#include <cstdint>
#include <string>
#include <vector>

namespace ks::service
{
    // ServiceStatus mirrors SERVICE_STATUS_PROCESS without exposing Win32 types.
    // Inputs: populated by query/enumeration functions from the SCM status block.
    // Processing: all fields are copied as unsigned 32-bit values.
    // Return behavior: plain data carrier; functions return it through output pointers.
    struct ServiceStatus
    {
        std::uint32_t serviceType = 0;
        std::uint32_t currentState = 0;
        std::uint32_t controlsAccepted = 0;
        std::uint32_t win32ExitCode = 0;
        std::uint32_t serviceSpecificExitCode = 0;
        std::uint32_t checkPoint = 0;
        std::uint32_t waitHint = 0;
        std::uint32_t processId = 0;
        std::uint32_t serviceFlags = 0;
    };

    // ServiceConfig mirrors QUERY_SERVICE_CONFIGW with UTF-16 strings.
    // Inputs: populated from QueryServiceConfigW and optional config2 calls.
    // Processing: pointer fields are copied into owned std::wstring members.
    // Return behavior: plain data carrier; empty strings represent missing fields.
    struct ServiceConfig
    {
        std::uint32_t serviceType = 0;
        std::uint32_t startType = 0;
        std::uint32_t errorControl = 0;
        std::wstring binaryPath;
        std::wstring loadOrderGroup;
        std::uint32_t tagId = 0;
        std::wstring dependenciesMultiSz;
        std::wstring accountName;
        std::wstring displayName;
        bool delayedAutoStart = false;
        bool hasDelayedAutoStart = false;
    };

    // ServiceRecord is the common enumeration/query result used by DriverDock and ServiceDock.
    // Inputs: serviceName/displayName come from EnumServicesStatusExW or OpenService query.
    // Processing: status/config/description are best-effort for enumeration and strict for single query.
    // Return behavior: has* flags describe which nested data was successfully filled.
    struct ServiceRecord
    {
        std::wstring serviceName;
        std::wstring displayName;
        std::wstring description;
        ServiceStatus status;
        ServiceConfig config;
        bool hasStatus = false;
        bool hasConfig = false;
        bool hasDescription = false;
        std::string statusErrorText;
        std::string configErrorText;
        std::string descriptionErrorText;
    };

    // KernelDriverServiceConfig describes CreateService/ChangeServiceConfig inputs for .sys services.
    // Inputs: caller supplies Win32-compatible numeric constants for startType/errorControl.
    // Processing: the implementation creates a missing service or updates an existing one.
    // Return behavior: CreateOrUpdateKernelDriverService returns true on create/update success.
    struct KernelDriverServiceConfig
    {
        std::wstring serviceName;
        std::wstring displayName;
        std::wstring binaryPath;
        std::wstring description;
        std::uint32_t startType = 3;     // SERVICE_DEMAND_START.
        std::uint32_t errorControl = 1;  // SERVICE_ERROR_NORMAL.
    };

    // ServiceConfigUpdate describes a partial ChangeServiceConfigW request.
    // Inputs: set a change* flag to true for each field that should be written.
    // Processing: fields without a change* flag are passed as SERVICE_NO_CHANGE or nullptr.
    // Return behavior: ChangeServiceConfiguration returns false and an error string on failure.
    struct ServiceConfigUpdate
    {
        bool changeServiceType = false;
        std::uint32_t serviceType = 0;

        bool changeStartType = false;
        std::uint32_t startType = 0;

        bool changeErrorControl = false;
        std::uint32_t errorControl = 0;

        bool changeBinaryPath = false;
        std::wstring binaryPath;

        bool changeLoadOrderGroup = false;
        std::wstring loadOrderGroup;

        bool changeDependencies = false;
        std::wstring dependenciesMultiSz;

        bool changeAccount = false;
        std::wstring accountName;

        bool changePassword = false;
        std::wstring password;

        bool changeDisplayName = false;
        std::wstring displayName;
    };

    // FailureAction mirrors SC_ACTION using numeric Win32 action types and delays.
    // Inputs: action type values are SC_ACTION_* constants expressed as uint32_t.
    // Processing: ApplyServiceFailureSettings converts each entry to SC_ACTION.
    // Return behavior: plain data carrier for query/apply functions.
    struct FailureAction
    {
        std::uint32_t type = 0;
        std::uint32_t delayMs = 0;
    };

    // FailureSettings stores SERVICE_FAILURE_ACTIONS and SERVICE_FAILURE_ACTIONS_FLAG.
    // Inputs: command/rebootMessage are UTF-16 because SCM APIs are wide-character.
    // Processing: query functions own-copy all returned strings and action rows.
    // Return behavior: has* flags indicate whether each optional config block existed.
    struct FailureSettings
    {
        std::uint32_t resetPeriodSeconds = 0;
        std::wstring rebootMessage;
        std::wstring command;
        std::vector<FailureAction> actions;
        bool failureActionsOnNonCrash = false;
        bool hasFailureActions = false;
        bool hasFailureActionsFlag = false;
    };

    // FormatWin32ErrorText converts a Win32 error code into UTF-8 text.
    // Inputs: errorCode is the Win32 GetLastError-compatible value.
    // Processing: FormatMessageW is used and the result is trimmed by the caller/UI if needed.
    // Return behavior: returns "<code>: <message>"; falls back to "unknown error".
    std::string FormatWin32ErrorText(std::uint32_t errorCode);

    // EnumerateServiceRecords lists services matching a service type/state mask.
    // Inputs: serviceTypeMask and serviceStateMask are Win32 SERVICE_* masks as uint32_t.
    // Processing: EnumServicesStatusExW is paged, then each item is enriched with config data.
    // Return behavior: true means enumeration completed; per-service config errors stay in records.
    bool EnumerateServiceRecords(
        std::uint32_t serviceTypeMask,
        std::uint32_t serviceStateMask,
        std::vector<ServiceRecord>* recordsOut,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // QueryServiceRecord reads status, config, and description for one service.
    // Inputs: serviceName is the SCM short name, encoded as UTF-16.
    // Processing: opens SCM/service once and queries status/config/config2 fields.
    // Return behavior: true only when status and base config are both available.
    bool QueryServiceRecord(
        const std::wstring& serviceName,
        ServiceRecord* recordOut,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // QueryServiceStatus reads SERVICE_STATUS_PROCESS for one service.
    // Inputs: serviceName is the SCM short name.
    // Processing: opens the service with SERVICE_QUERY_STATUS and copies status fields.
    // Return behavior: true on successful status query; false sets error outputs.
    bool QueryServiceStatus(
        const std::wstring& serviceName,
        ServiceStatus* statusOut,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // QueryServiceConfig reads QUERY_SERVICE_CONFIGW plus description/delayed-auto data.
    // Inputs: serviceName is the SCM short name.
    // Processing: opens with SERVICE_QUERY_CONFIG and copies all pointer data into strings.
    // Return behavior: true on base config success; optional fields may remain empty/default.
    bool QueryServiceConfig(
        const std::wstring& serviceName,
        ServiceConfig* configOut,
        std::wstring* descriptionOut = nullptr,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // QueryServiceDescription reads only SERVICE_CONFIG_DESCRIPTION.
    // Inputs: serviceName is the SCM short name.
    // Processing: opens with SERVICE_QUERY_CONFIG and handles missing descriptions as empty.
    // Return behavior: true on successful query path; false only for SCM/open/query failures.
    bool QueryServiceDescription(
        const std::wstring& serviceName,
        std::wstring* descriptionOut,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // QueryServiceConfig2Raw reads a variable-size QueryServiceConfig2W block.
    // Inputs: infoLevel is a SERVICE_CONFIG_* numeric value and serviceName is the SCM short name.
    // Processing: the reusable layer owns OpenService and the size-probe/query sequence.
    // Return behavior: true with raw bytes on success; false when the optional block is missing/unreadable.
    bool QueryServiceConfig2Raw(
        const std::wstring& serviceName,
        std::uint32_t infoLevel,
        std::vector<std::uint8_t>* dataOut,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // QueryDependentServiceNames reads services that depend on the target service.
    // Inputs: serviceName is the SCM short name and stateMask is a SERVICE_STATE_* mask.
    // Processing: EnumDependentServicesW results are copied into owned UTF-16 names.
    // Return behavior: true on API success; an empty vector means no dependents.
    bool QueryDependentServiceNames(
        const std::wstring& serviceName,
        std::uint32_t stateMask,
        std::vector<std::wstring>* namesOut,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // QueryServiceSecuritySddl reads a service security descriptor and converts it to SDDL.
    // Inputs: securityInformation is a SECURITY_INFORMATION bitmask as uint32_t.
    // Processing: QueryServiceObjectSecurity and SDDL conversion happen in the reusable layer.
    // Return behavior: true with SDDL text on success; false sets error outputs.
    bool QueryServiceSecuritySddl(
        const std::wstring& serviceName,
        std::uint32_t securityInformation,
        std::wstring* sddlOut,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // CanOpenServiceWithAccess checks whether OpenServiceW succeeds with desired access.
    // Inputs: desiredAccess is a SERVICE_* access mask and serviceName is the SCM short name.
    // Processing: only open/close is performed; no service state is changed.
    // Return behavior: true when the service can be opened with that access.
    bool CanOpenServiceWithAccess(
        const std::wstring& serviceName,
        std::uint32_t desiredAccess);

    // StartServiceByName starts a service and optionally waits for a state.
    // Inputs: serviceName, timeoutMs, and expectedState control the operation/wait behavior.
    // Processing: ERROR_SERVICE_ALREADY_RUNNING is treated as success for idempotent UI actions.
    // Return behavior: true when start dispatch succeeds; finalStatusOut contains the last observed state.
    bool StartServiceByName(
        const std::wstring& serviceName,
        std::uint32_t timeoutMs,
        std::uint32_t expectedState,
        ServiceStatus* finalStatusOut = nullptr,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // ControlServiceByName sends a control code such as stop/pause/continue.
    // Inputs: desiredAccess and controlCode are Win32 SERVICE_* and SERVICE_CONTROL_* values.
    // Processing: stop on an inactive service is treated as success for idempotent UI actions.
    // Return behavior: true when control dispatch succeeds; finalStatusOut contains the last observed state.
    bool ControlServiceByName(
        const std::wstring& serviceName,
        std::uint32_t desiredAccess,
        std::uint32_t controlCode,
        std::uint32_t timeoutMs,
        std::uint32_t expectedState,
        ServiceStatus* finalStatusOut = nullptr,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // StopServiceByName is a convenience wrapper around ControlServiceByName.
    // Inputs: serviceName, timeoutMs, and expectedState control the stop/wait behavior.
    // Processing: ERROR_SERVICE_NOT_ACTIVE is treated as success.
    // Return behavior: true when stop dispatch succeeds; finalStatusOut contains the last observed state.
    bool StopServiceByName(
        const std::wstring& serviceName,
        std::uint32_t timeoutMs,
        std::uint32_t expectedState,
        ServiceStatus* finalStatusOut = nullptr,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // DeleteServiceByName deletes a service, optionally stopping it first.
    // Inputs: stopFirst controls best-effort stop before DeleteServiceW.
    // Processing: ERROR_SERVICE_MARKED_FOR_DELETE is treated as success.
    // Return behavior: true when DeleteServiceW succeeds or reports already marked for delete.
    bool DeleteServiceByName(
        const std::wstring& serviceName,
        bool stopFirst,
        std::uint32_t stopTimeoutMs,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // CreateOrUpdateKernelDriverService creates or updates a kernel driver service.
    // Inputs: config carries SCM short name, display name, image path, description, start/error type.
    // Processing: existing services are opened and updated; missing services are created first.
    // Return behavior: true on success; createdOut reports whether CreateServiceW was used.
    bool CreateOrUpdateKernelDriverService(
        const KernelDriverServiceConfig& config,
        bool* createdOut = nullptr,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // ChangeServiceConfiguration applies a partial ChangeServiceConfigW request.
    // Inputs: update.change* flags decide which fields are modified.
    // Processing: opens with SERVICE_CHANGE_CONFIG and translates unchanged fields correctly.
    // Return behavior: true on ChangeServiceConfigW success; false sets error outputs.
    bool ChangeServiceConfiguration(
        const std::wstring& serviceName,
        const ServiceConfigUpdate& update,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // SetServiceDescription writes SERVICE_CONFIG_DESCRIPTION.
    // Inputs: description is UTF-16 and may be empty to clear the description.
    // Processing: opens with SERVICE_CHANGE_CONFIG and calls ChangeServiceConfig2W.
    // Return behavior: true on success; false sets error outputs.
    bool SetServiceDescription(
        const std::wstring& serviceName,
        const std::wstring& description,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // SetDelayedAutoStart writes SERVICE_CONFIG_DELAYED_AUTO_START_INFO.
    // Inputs: delayedAutoStart is the target flag.
    // Processing: opens with SERVICE_CHANGE_CONFIG and calls ChangeServiceConfig2W.
    // Return behavior: true on success; false sets error outputs.
    bool SetDelayedAutoStart(
        const std::wstring& serviceName,
        bool delayedAutoStart,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // QueryServiceFailureSettings reads SERVICE_FAILURE_ACTIONS and the non-crash flag.
    // Inputs: serviceName is the SCM short name.
    // Processing: missing optional blocks are not treated as hard failures.
    // Return behavior: true when SCM/open succeeded; has* flags describe found data.
    bool QueryServiceFailureSettings(
        const std::wstring& serviceName,
        FailureSettings* settingsOut,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);

    // ApplyServiceFailureSettings writes SERVICE_FAILURE_ACTIONS and the non-crash flag.
    // Inputs: settings carries reset period, command/reboot text, actions, and flag.
    // Processing: action rows are converted to SC_ACTION before ChangeServiceConfig2W.
    // Return behavior: true when both config blocks are written successfully.
    bool ApplyServiceFailureSettings(
        const std::wstring& serviceName,
        const FailureSettings& settings,
        std::string* errorTextOut = nullptr,
        std::uint32_t* win32ErrorOut = nullptr);
}
