/*++

Module Name:

    ioctl_registry.c

Abstract:

    Static IOCTL registry for the KswordARK dispatch path.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ioctl_registry.h"
#include "ark/ark_ioctl.h"
#include "driver/KswordArkMutationIoctl.h"
#include "driver/KswordArkDeviceAuditIoctl.h"
#include "driver/KswordArkPlatformAuditIoctl.h"
#include "driver/KswordArkI8042AuditIoctl.h"
#include "driver/KswordArkHwidIoctl.h"
#include "driver/KswordArkProcessProtectIoctl.h"
#include "driver/KswordArkCallbackMonitorIoctl.h"

// Feature handler declarations live here instead of in the central dispatch file.
NTSTATUS KswordARKKernelIoctlControlDriverDispatch(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlControlDriverImage(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlTerminate(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlSuspend(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlSetPplLevel(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlSetIntegrity(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlTokenPrivileges(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlQueryTokenPrivileges(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlAdjustTokenPrivilege(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlEnumProcess(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlSetVisibility(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlSetSpecialFlags(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlDkomProcess(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlInjectProcess(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKThreadIoctlSetSuspended(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKThreadIoctlControlDriverThread(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKWorkQueueIoctlEnum(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMemoryIoctlQueryVirtualMemory(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMemoryIoctlReadVirtualMemory(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMemoryIoctlWriteVirtualMemory(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMemoryIoctlReadPhysicalMemory(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMemoryIoctlWritePhysicalMemory(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMemoryIoctlTranslateVirtualAddress(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMemoryIoctlQueryPageTableEntry(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMemoryIoctlScanKernelExecutableMemory(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMemoryIoctlScanKernelMemoryEvidence(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKFileIoctlDeletePath(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKFileIoctlQueryFileInfo(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKFileIoctlEnumDirectory(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKFileIoctlSetIntegrity(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKFileIrpIoctlEnumDirectory(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKFileIrpIoctlSubmit(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKFileMonitorIoctlControl(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKFileMonitorIoctlDrain(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKFileMonitorIoctlQueryStatus(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlEnumSsdt(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlQueryDriverObject(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlControlIoTimer(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlEnumShadowSsdt(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlScanInlineHooks(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlPatchInlineHook(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlRestoreIdtBaseline(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlQueryPiDdb(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlDeletePiDdb(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKHvmIoctlQuery(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKHvmIoctlControl(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlQuerySlatIommuAudit(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKSystemTimeIoctlQuery(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKSystemTimeIoctlControl(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKHvmIoctlEptRule(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKHvmIoctlEvents(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlEnumIatEatHooks(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlForceUnloadDriver(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlControlDriverCommunication(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlQueryDriverIntegrity(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlQueryCpuHardware(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlQueryPhysicalMemoryLayout(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlQueryIoctlRegistry(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlEnumTimerDpc(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlExperimentalReturnToFirmware(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelIoctlQueryUnloadedDrivers(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackIoctlSetRulesHandler(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackIoctlGetRuntimeStateHandler(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackIoctlWaitEventHandler(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackIoctlAnswerEventHandler(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackIoctlCancelAllPendingHandler(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackIoctlRemoveExternalCallbackHandler(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKBugcheckIoctlConfigureDiagnostics(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackIoctlRemoveExternalCallbackExHandler(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackIoctlEnumCallbacksHandler(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackIoctlSetMinifilterBypassPidsHandler(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackIoctlQueryMinifilterBypassPidsHandler(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackMonitorIoctlControl(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackMonitorIoctlQuery(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCallbackMonitorIoctlRead(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessProtectIoctlSetConfigHandler(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessProtectIoctlQueryStateHandler(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDynDataIoctlQueryStatus(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDynDataIoctlQueryFields(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDynDataIoctlQueryCapabilities(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDynDataIoctlApplyProfile(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDynDataIoctlApplyProfileEx(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDynDataIoctlApplyProfileV4(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDynDataIoctlQueryV4Modules(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDynDataIoctlQueryV4CapabilityGroups(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDynDataIoctlQueryV4MissingItems(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDynDataIoctlQueryV4Items(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCapabilityIoctlQueryDriverCapabilities(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKThreadIoctlEnumThread(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKThreadIoctlTerminate(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlQueryCrossView(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKThreadIoctlQueryCrossView(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlQueryDetail(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKProcessIoctlQueryRuntimeFields(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKThreadIoctlQueryDetail(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKThreadIoctlQueryRuntimeFields(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKHandleIoctlEnumProcessHandles(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKHandleIoctlQueryHandleObject(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKAlpcIoctlQueryAlpcPort(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKSectionIoctlQueryProcessSection(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKSectionIoctlQueryFileSectionMappings(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKWslSiloIoctlQuery(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKTrustIoctlQueryImageTrust(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKTrustIoctlQueryImageSignature(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKSafetyIoctlQueryPolicy(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKSafetyIoctlSetPolicy(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKPreflightIoctlQuery(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRegistryIoctlReadValue(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRegistryIoctlEnumKey(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRegistryIoctlSetValue(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRegistryIoctlDeleteValue(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRegistryIoctlCreateKey(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRegistryIoctlDeleteKey(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRegistryIoctlRenameValue(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRegistryIoctlRenameKey(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRedirectIoctlSetRules(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRedirectIoctlQueryStatus(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKNetworkIoctlSetRules(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKNetworkIoctlQueryStatus(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKNetworkIoctlQueryTcpEndpoints(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKNetworkIoctlQueryUdpEndpoints(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKNetworkIoctlQueryWfpInventory(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKNetworkIoctlQueryWfpEvents(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKNetworkIoctlQueryTrafficPackets(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKNetworkIoctlControlTrafficCapture(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKNetworkIoctlQueryNdisChain(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKeyboardIoctlEnumHotkeys(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKeyboardIoctlEnumHooks(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKeyboardIoctlMutateHotkey(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMutationIoctlPrepare(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMutationIoctlCommit(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMutationIoctlRollback(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMutationIoctlQueryAudit(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKMinifilterIoctlQueryInventory(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelObjectIoctlEnumCidTable(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelObjectIoctlQueryObjectSummary(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelObjectIoctlEnumTypeTable(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKKernelObjectIoctlQueryIpcSummary(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKStorageIoctlQueryVolumeStackAudit(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKStorageIoctlQueryBitLockerFveAudit(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKStorageIoctlQueryMountMgrMappingAudit(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKStorageIoctlQueryFileSystemIntegrityAudit(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKStorageIoctlQueryRawDiskBackend(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKStorageIoctlReadRawDisk(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKStorageIoctlWriteRawDisk(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKSecurityAuditIoctlQuerySecurityStatus(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKSecurityAuditIoctlQueryDriverTrustView(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKSecurityAuditIoctlQueryHyperVSummary(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKSecurityAuditIoctlQueryAppControlStatus(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKWin32kIoctlQueryProfileStatus(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKWin32kIoctlQueryWindows(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKWin32kIoctlQueryGuiThreads(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKWin32kIoctlQueryHotkeysPdb(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKWin32kIoctlQueryHooksPdb(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKWin32kIoctlQueryWindowDetail(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKWin32kIoctlQueryTimers(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKWin32kIoctlQueryEventHooks(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDeviceAuditIoctlQueryDeviceStack(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDeviceAuditIoctlQueryInputStack(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDeviceAuditIoctlQueryUsbTopology(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDeviceAuditIoctlQueryGpuDisplayWatchdog(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKPlatformAuditIoctlQuery(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKPlatformAuditIoctlControl(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKI8042AuditIoctlQuery(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKHwidIoctlQueryDispatch(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKHwidIoctlControlDispatch(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCpuPowerIoctlQuery(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKCpuPowerIoctlControl(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKResearchIoctlQueryTopic(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDebugOutputIoctlControl(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKDebugOutputIoctlDrain(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKBugcheckIoctlSetBitmap(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKBugcheckIoctlSetVerdictResources(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKBugcheckGuardIoctlConfigure(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKBugcheckShieldIoctlConfigure(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKAntiBsodIoctlConfigure(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRxpfIoctlQuerySupport(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRxpfIoctlRegisterPage(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRxpfIoctlChangePage(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRxpfIoctlQueryPage(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRxpfIoctlWritePage(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRxpfIoctlSetEmulation(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRxpfIoctlQueryStats(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRxpfIoctlDrainEvents(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRxpfIoctlUnregisterPage(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);
NTSTATUS KswordARKRxpfIoctlRunSelfTest(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned);

static const KSWORD_ARK_IOCTL_ENTRY g_KswordArkIoctlTable[] = {
    { IOCTL_KSWORD_ARK_TERMINATE_PROCESS, KswordARKProcessIoctlTerminate, "IOCTL_KSWORD_ARK_TERMINATE_PROCESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SUSPEND_PROCESS, KswordARKProcessIoctlSuspend, "IOCTL_KSWORD_ARK_SUSPEND_PROCESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_PPL_LEVEL, KswordARKProcessIoctlSetPplLevel, "IOCTL_KSWORD_ARK_SET_PPL_LEVEL", KSW_CAP_PROCESS_PROTECTION_PATCH, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY, KswordARKProcessIoctlSetIntegrity, "IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES, KswordARKProcessIoctlTokenPrivileges, "IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES, KswordARKProcessIoctlQueryTokenPrivileges, "IOCTL_KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE, KswordARKProcessIoctlAdjustTokenPrivilege, "IOCTL_KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_PROCESS, KswordARKProcessIoctlEnumProcess, "IOCTL_KSWORD_ARK_ENUM_PROCESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY, KswordARKProcessIoctlSetVisibility, "IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS, KswordARKProcessIoctlSetSpecialFlags, "IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DKOM_PROCESS, KswordARKProcessIoctlDkomProcess, "IOCTL_KSWORD_ARK_DKOM_PROCESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_INJECT_PROCESS, KswordARKProcessIoctlInjectProcess, "IOCTL_KSWORD_ARK_INJECT_PROCESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY, KswordARKMemoryIoctlQueryVirtualMemory, "IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY, KswordARKMemoryIoctlReadVirtualMemory, "IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY, KswordARKMemoryIoctlWriteVirtualMemory, "IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY, KswordARKMemoryIoctlReadPhysicalMemory, "IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY, KswordARKMemoryIoctlWritePhysicalMemory, "IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS, KswordARKMemoryIoctlTranslateVirtualAddress, "IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY, KswordARKMemoryIoctlQueryPageTableEntry, "IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY, KswordARKMemoryIoctlScanKernelExecutableMemory, "IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE, KswordARKMemoryIoctlScanKernelMemoryEvidence, "IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DELETE_PATH, KswordARKFileIoctlDeletePath, "IOCTL_KSWORD_ARK_DELETE_PATH", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_FILE_INFO, KswordARKFileIoctlQueryFileInfo, "IOCTL_KSWORD_ARK_QUERY_FILE_INFO", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_DIRECTORY, KswordARKFileIoctlEnumDirectory, "IOCTL_KSWORD_ARK_ENUM_DIRECTORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY, KswordARKFileIoctlSetIntegrity, "IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY, KswordARKFileIrpIoctlEnumDirectory, "IOCTL_KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT, KswordARKFileIrpIoctlSubmit, "IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL, KswordARKFileMonitorIoctlControl, "IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN, KswordARKFileMonitorIoctlDrain, "IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS, KswordARKFileMonitorIoctlQueryStatus, "IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_SSDT, KswordARKKernelIoctlEnumSsdt, "IOCTL_KSWORD_ARK_ENUM_SSDT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT, KswordARKKernelIoctlQueryDriverObject, "IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_CONTROL_IO_TIMER, KswordARKKernelIoctlControlIoTimer, "IOCTL_KSWORD_ARK_CONTROL_IO_TIMER", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT, KswordARKKernelIoctlEnumShadowSsdt, "IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS, KswordARKKernelIoctlScanInlineHooks, "IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK, KswordARKKernelIoctlPatchInlineHook, "IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RESTORE_IDT_BASELINE, KswordARKKernelIoctlRestoreIdtBaseline, "IOCTL_KSWORD_ARK_RESTORE_IDT_BASELINE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_PIDDB, KswordARKKernelIoctlQueryPiDdb, "IOCTL_KSWORD_ARK_QUERY_PIDDB", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DELETE_PIDDB, KswordARKKernelIoctlDeletePiDdb, "IOCTL_KSWORD_ARK_DELETE_PIDDB", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_HVM, KswordARKHvmIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_HVM", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CONTROL_HVM, KswordARKHvmIoctlControl, "IOCTL_KSWORD_ARK_CONTROL_HVM", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT, KswordARKKernelIoctlQuerySlatIommuAudit, "IOCTL_KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME, KswordARKSystemTimeIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_CONTROL_SYSTEM_TIME, KswordARKSystemTimeIoctlControl, "IOCTL_KSWORD_ARK_CONTROL_SYSTEM_TIME", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_EPT_RULE, KswordARKHvmIoctlEptRule, "IOCTL_KSWORD_ARK_HVM_EPT_RULE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HVM_EVENTS, KswordARKHvmIoctlEvents, "IOCTL_KSWORD_ARK_HVM_EVENTS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS, KswordARKKernelIoctlEnumIatEatHooks, "IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER, KswordARKKernelIoctlForceUnloadDriver, "IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CONTROL_DRIVER_COMMUNICATION, KswordARKKernelIoctlControlDriverCommunication, "IOCTL_KSWORD_ARK_CONTROL_DRIVER_COMMUNICATION", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_CONTROL_DRIVER_DISPATCH, KswordARKKernelIoctlControlDriverDispatch, "IOCTL_KSWORD_ARK_CONTROL_DRIVER_DISPATCH", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CONTROL_DRIVER_IMAGE, KswordARKKernelIoctlControlDriverImage, "IOCTL_KSWORD_ARK_CONTROL_DRIVER_IMAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY, KswordARKKernelIoctlQueryDriverIntegrity, "IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE, KswordARKKernelIoctlQueryCpuHardware, "IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT, KswordARKKernelIoctlQueryPhysicalMemoryLayout, "IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY, KswordARKKernelIoctlQueryIoctlRegistry, "IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_ENUM_TIMER_DPC, KswordARKKernelIoctlEnumTimerDpc, "IOCTL_KSWORD_ARK_ENUM_TIMER_DPC", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_EXPERIMENTAL_RETURN_TO_FIRMWARE, KswordARKKernelIoctlExperimentalReturnToFirmware, "IOCTL_KSWORD_ARK_EXPERIMENTAL_RETURN_TO_FIRMWARE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // 三个来源各自报告 DynData/PDB 缺口，因此注册层允许降级响应通过。
    { IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS, KswordARKKernelIoctlQueryUnloadedDrivers, "IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_SET_CALLBACK_RULES, KswordARKCallbackIoctlSetRulesHandler, "IOCTL_KSWORD_ARK_SET_CALLBACK_RULES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_GET_CALLBACK_RUNTIME_STATE, KswordARKCallbackIoctlGetRuntimeStateHandler, "IOCTL_KSWORD_ARK_GET_CALLBACK_RUNTIME_STATE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_WAIT_CALLBACK_EVENT, KswordARKCallbackIoctlWaitEventHandler, "IOCTL_KSWORD_ARK_WAIT_CALLBACK_EVENT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT, KswordARKCallbackIoctlAnswerEventHandler, "IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS, KswordARKCallbackIoctlCancelAllPendingHandler, "IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK, KswordARKCallbackIoctlRemoveExternalCallbackHandler, "IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX, KswordARKCallbackIoctlRemoveExternalCallbackExHandler, "IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_CALLBACKS, KswordARKCallbackIoctlEnumCallbacksHandler, "IOCTL_KSWORD_ARK_ENUM_CALLBACKS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS, KswordARKCallbackIoctlSetMinifilterBypassPidsHandler, "IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_MINIFILTER_BYPASS_PIDS, KswordARKCallbackIoctlQueryMinifilterBypassPidsHandler, "IOCTL_KSWORD_ARK_QUERY_MINIFILTER_BYPASS_PIDS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL, KswordARKCallbackMonitorIoctlControl, "IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CALLBACK_MONITOR_QUERY, KswordARKCallbackMonitorIoctlQuery, "IOCTL_KSWORD_ARK_CALLBACK_MONITOR_QUERY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_CALLBACK_MONITOR_READ, KswordARKCallbackMonitorIoctlRead, "IOCTL_KSWORD_ARK_CALLBACK_MONITOR_READ", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    // 进程保护复用同一个对象回调，配置下发按"改变回调行为"处理，查询为只读。
    { IOCTL_KSWORD_ARK_SET_PROCESS_PROTECT_CONFIG, KswordARKProcessProtectIoctlSetConfigHandler, "IOCTL_KSWORD_ARK_SET_PROCESS_PROTECT_CONFIG", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE, KswordARKProcessProtectIoctlQueryStateHandler, "IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    // 知识中心只读证据编排：只查中央注册表并采集当前 WDF/WDM 上下文。
    { IOCTL_KSWORD_ARK_QUERY_RESEARCH_TOPIC, KswordARKResearchIoctlQueryTopic, "IOCTL_KSWORD_ARK_QUERY_RESEARCH_TOPIC", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_QUERY_DYN_STATUS, KswordARKDynDataIoctlQueryStatus, "IOCTL_KSWORD_ARK_QUERY_DYN_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS, KswordARKDynDataIoctlQueryFields, "IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_CAPABILITIES, KswordARKDynDataIoctlQueryCapabilities, "IOCTL_KSWORD_ARK_QUERY_CAPABILITIES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE, KswordARKDynDataIoctlApplyProfile, "IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX, KswordARKDynDataIoctlApplyProfileEx, "IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4, KswordARKDynDataIoctlApplyProfileV4, "IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES, KswordARKDynDataIoctlQueryV4Modules, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS, KswordARKDynDataIoctlQueryV4CapabilityGroups, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS, KswordARKDynDataIoctlQueryV4MissingItems, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS, KswordARKDynDataIoctlQueryV4Items, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES, KswordARKCapabilityIoctlQueryDriverCapabilities, "IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_THREAD, KswordARKThreadIoctlEnumThread, "IOCTL_KSWORD_ARK_ENUM_THREAD", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_TERMINATE_THREAD, KswordARKThreadIoctlTerminate, "IOCTL_KSWORD_ARK_TERMINATE_THREAD", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED, KswordARKThreadIoctlSetSuspended, "IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CONTROL_DRIVER_THREAD, KswordARKThreadIoctlControlDriverThread, "IOCTL_KSWORD_ARK_CONTROL_DRIVER_THREAD", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Work-queue enumeration is read-only and reports identity/layout gaps in its fixed response.
    { IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE, KswordARKWorkQueueIoctlEnum, "IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    // Process cross-view performs its own per-source capability checks, so dispatch must allow degraded read-only results.
    { IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW, KswordARKProcessIoctlQueryCrossView, "IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Thread cross-view performs its own per-source capability checks, so dispatch must allow degraded read-only results.
    { IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW, KswordARKThreadIoctlQueryCrossView, "IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Process detail is read-only and reports missing PDB/DynData fields inside the fixed response.
    { IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL, KswordARKProcessIoctlQueryDetail, "IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Process runtime field sample is read-only and samples only bounded fields from PsLookupProcessByProcessId.
    { IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS, KswordARKProcessIoctlQueryRuntimeFields, "IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Thread detail is read-only and reports missing PDB/DynData fields inside the fixed response.
    { IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL, KswordARKThreadIoctlQueryDetail, "IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Thread runtime field sample is read-only and samples only bounded fields from PsLookupThreadByThreadId.
    { IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS, KswordARKThreadIoctlQueryRuntimeFields, "IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Handle/object/ALPC queries own their public-API and runtime-signature fallback paths.
    // Handle occupancy scans issue these IOCTLs at process/handle granularity.
    // Their handlers keep validation and failure logs; dispatch success records
    // are redundant and can evict the real diagnostic lines from the log ring.
    { IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES, KswordARKHandleIoctlEnumProcessHandles, "IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS | KSWORD_ARK_IOCTL_FLAG_QUIET_INVALID_CID },
    { IOCTL_KSWORD_ARK_QUERY_HANDLE_OBJECT, KswordARKHandleIoctlQueryHandleObject, "IOCTL_KSWORD_ARK_QUERY_HANDLE_OBJECT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_QUERY_ALPC_PORT, KswordARKAlpcIoctlQueryAlpcPort, "IOCTL_KSWORD_ARK_QUERY_ALPC_PORT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Section queries return public FILE_OBJECT/ControlArea evidence even when private mapping offsets are absent.
    { IOCTL_KSWORD_ARK_QUERY_PROCESS_SECTION, KswordARKSectionIoctlQueryProcessSection, "IOCTL_KSWORD_ARK_QUERY_PROCESS_SECTION", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS, KswordARKSectionIoctlQueryFileSectionMappings, "IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WSL_SILO, KswordARKWslSiloIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_WSL_SILO", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_IMAGE_TRUST, KswordARKTrustIoctlQueryImageTrust, "IOCTL_KSWORD_ARK_QUERY_IMAGE_TRUST", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE, KswordARKTrustIoctlQueryImageSignature, "IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_SAFETY_POLICY, KswordARKSafetyIoctlQueryPolicy, "IOCTL_KSWORD_ARK_QUERY_SAFETY_POLICY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_SAFETY_POLICY, KswordARKSafetyIoctlSetPolicy, "IOCTL_KSWORD_ARK_SET_SAFETY_POLICY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_PREFLIGHT, KswordARKPreflightIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_PREFLIGHT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_READ_REGISTRY_VALUE, KswordARKRegistryIoctlReadValue, "IOCTL_KSWORD_ARK_READ_REGISTRY_VALUE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_REGISTRY_KEY, KswordARKRegistryIoctlEnumKey, "IOCTL_KSWORD_ARK_ENUM_REGISTRY_KEY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_REGISTRY_VALUE, KswordARKRegistryIoctlSetValue, "IOCTL_KSWORD_ARK_SET_REGISTRY_VALUE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DELETE_REGISTRY_VALUE, KswordARKRegistryIoctlDeleteValue, "IOCTL_KSWORD_ARK_DELETE_REGISTRY_VALUE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CREATE_REGISTRY_KEY, KswordARKRegistryIoctlCreateKey, "IOCTL_KSWORD_ARK_CREATE_REGISTRY_KEY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DELETE_REGISTRY_KEY, KswordARKRegistryIoctlDeleteKey, "IOCTL_KSWORD_ARK_DELETE_REGISTRY_KEY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RENAME_REGISTRY_VALUE, KswordARKRegistryIoctlRenameValue, "IOCTL_KSWORD_ARK_RENAME_REGISTRY_VALUE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RENAME_REGISTRY_KEY, KswordARKRegistryIoctlRenameKey, "IOCTL_KSWORD_ARK_RENAME_REGISTRY_KEY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_REDIRECT_SET_RULES, KswordARKRedirectIoctlSetRules, "IOCTL_KSWORD_ARK_REDIRECT_SET_RULES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_REDIRECT_QUERY_STATUS, KswordARKRedirectIoctlQueryStatus, "IOCTL_KSWORD_ARK_REDIRECT_QUERY_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_SET_RULES, KswordARKNetworkIoctlSetRules, "IOCTL_KSWORD_ARK_NETWORK_SET_RULES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS, KswordARKNetworkIoctlQueryStatus, "IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS, KswordARKNetworkIoctlQueryTcpEndpoints, "IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS, KswordARKNetworkIoctlQueryUdpEndpoints, "IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY, KswordARKNetworkIoctlQueryWfpInventory, "IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS, KswordARKNetworkIoctlQueryWfpEvents, "IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS, KswordARKNetworkIoctlQueryTrafficPackets, "IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_CONTROL_TRAFFIC_CAPTURE, KswordARKNetworkIoctlControlTrafficCapture, "IOCTL_KSWORD_ARK_NETWORK_CONTROL_TRAFFIC_CAPTURE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN, KswordARKNetworkIoctlQueryNdisChain, "IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS, KswordARKKeyboardIoctlEnumHotkeys, "IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOOKS, KswordARKKeyboardIoctlEnumHooks, "IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOOKS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY, KswordARKKeyboardIoctlMutateHotkey, "IOCTL_KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_MUTATION_PREPARE, KswordARKMutationIoctlPrepare, "IOCTL_KSWORD_ARK_MUTATION_PREPARE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_MUTATION_COMMIT, KswordARKMutationIoctlCommit, "IOCTL_KSWORD_ARK_MUTATION_COMMIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_MUTATION_ROLLBACK, KswordARKMutationIoctlRollback, "IOCTL_KSWORD_ARK_MUTATION_ROLLBACK", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT, KswordARKMutationIoctlQueryAudit, "IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY, KswordARKMinifilterIoctlQueryInventory, "IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_CID_TABLE, KswordARKKernelObjectIoctlEnumCidTable, "IOCTL_KSWORD_ARK_ENUM_CID_TABLE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY, KswordARKKernelObjectIoctlQueryObjectSummary, "IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE, KswordARKKernelObjectIoctlEnumTypeTable, "IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY, KswordARKKernelObjectIoctlQueryIpcSummary, "IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT, KswordARKStorageIoctlQueryVolumeStackAudit, "IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT, KswordARKStorageIoctlQueryBitLockerFveAudit, "IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT, KswordARKStorageIoctlQueryMountMgrMappingAudit, "IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT, KswordARKStorageIoctlQueryFileSystemIntegrityAudit, "IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_RAW_DISK_BACKEND, KswordARKStorageIoctlQueryRawDiskBackend, "IOCTL_KSWORD_ARK_QUERY_RAW_DISK_BACKEND", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_READ_RAW_DISK, KswordARKStorageIoctlReadRawDisk, "IOCTL_KSWORD_ARK_READ_RAW_DISK", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_WRITE_RAW_DISK, KswordARKStorageIoctlWriteRawDisk, "IOCTL_KSWORD_ARK_WRITE_RAW_DISK", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS, KswordARKSecurityAuditIoctlQuerySecurityStatus, "IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW, KswordARKSecurityAuditIoctlQueryDriverTrustView, "IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY, KswordARKSecurityAuditIoctlQueryHyperVSummary, "IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS, KswordARKSecurityAuditIoctlQueryAppControlStatus, "IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS, KswordARKWin32kIoctlQueryProfileStatus, "IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS, KswordARKWin32kIoctlQueryWindows, "IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS, KswordARKWin32kIoctlQueryGuiThreads, "IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB, KswordARKWin32kIoctlQueryHotkeysPdb, "IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB, KswordARKWin32kIoctlQueryHooksPdb, "IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL, KswordARKWin32kIoctlQueryWindowDetail, "IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS, KswordARKWin32kIoctlQueryTimers, "IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS, KswordARKWin32kIoctlQueryEventHooks, "IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT, KswordARKDeviceAuditIoctlQueryDeviceStack, "IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT, KswordARKDeviceAuditIoctlQueryInputStack, "IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT, KswordARKDeviceAuditIoctlQueryUsbTopology, "IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT, KswordARKDeviceAuditIoctlQueryGpuDisplayWatchdog, "IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // HAL/WDF 查询返回经导出、边界和结构签名验证的证据；HAL 编辑由
    // 独立 FILE_WRITE_ACCESS IOCTL 重新定位槽位并做快照 CAS。
    { IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT, KswordARKPlatformAuditIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_CONTROL_PLATFORM_AUDIT, KswordARKPlatformAuditIoctlControl, "IOCTL_KSWORD_ARK_CONTROL_PLATFORM_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // i8042prt 审计只在精确映像/描述符匹配后读取端点地址，不读取输入数据。
    { IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT, KswordARKI8042AuditIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // 调试输出轮询频率较高，成功路径静默，避免驱动自有日志被无意义放大。
    { IOCTL_KSWORD_ARK_DEBUG_OUTPUT_CONTROL, KswordARKDebugOutputIoctlControl, "IOCTL_KSWORD_ARK_DEBUG_OUTPUT_CONTROL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN, KswordARKDebugOutputIoctlDrain, "IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY, KswordARKHwidIoctlQueryDispatch, "IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL, KswordARKHwidIoctlControlDispatch, "IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_QUERY_CPU_POWER, KswordARKCpuPowerIoctlQuery, "IOCTL_KSWORD_ARK_QUERY_CPU_POWER", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_CONTROL_CPU_POWER, KswordARKCpuPowerIoctlControl, "IOCTL_KSWORD_ARK_CONTROL_CPU_POWER", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // BGP 扫描和 BugCheck 回调只有 R3 明确请求后才安装，避免普通驱动启动触发私有字段探测。
    { IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_DIAGNOSTICS, KswordARKBugcheckIoctlConfigureDiagnostics, "IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_DIAGNOSTICS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_SET_BUGCHECK_BITMAP, KswordARKBugcheckIoctlSetBitmap, "IOCTL_KSWORD_ARK_SET_BUGCHECK_BITMAP", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_COMPLETION },
    { IOCTL_KSWORD_ARK_SET_BUGCHECK_VERDICT_RESOURCES, KswordARKBugcheckIoctlSetVerdictResources, "IOCTL_KSWORD_ARK_SET_BUGCHECK_VERDICT_RESOURCES", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_COMPLETION },
    { IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_GUARD, KswordARKBugcheckGuardIoctlConfigure, "IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_GUARD", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Shield 只走公共 BugCheck 回调，绝不修改私有内核状态；enable 需要 UI 明确确认。
    { IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_SHIELD, KswordARKBugcheckShieldIoctlConfigure, "IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_SHIELD", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // Anti-BSOD 参考实现：编译默认关闭，即使打开也依赖空签名表 fail-closed；只做研究用途。
    { IOCTL_KSWORD_ARK_CONFIGURE_ANTIBSOD, KswordARKAntiBsodIoctlConfigure, "IOCTL_KSWORD_ARK_CONFIGURE_ANTIBSOD", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    // RXPF owns its exact-build, write-access, confirmation-token and safety-policy gates.
    { IOCTL_KSWORD_ARK_RXPF_QUERY_SUPPORT, KswordARKRxpfIoctlQuerySupport, "IOCTL_KSWORD_ARK_RXPF_QUERY_SUPPORT", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_REGISTER_PAGE, KswordARKRxpfIoctlRegisterPage, "IOCTL_KSWORD_ARK_RXPF_REGISTER_PAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_CHANGE_PAGE, KswordARKRxpfIoctlChangePage, "IOCTL_KSWORD_ARK_RXPF_CHANGE_PAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_QUERY_PAGE, KswordARKRxpfIoctlQueryPage, "IOCTL_KSWORD_ARK_RXPF_QUERY_PAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_WRITE_PAGE, KswordARKRxpfIoctlWritePage, "IOCTL_KSWORD_ARK_RXPF_WRITE_PAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_SET_EMULATION, KswordARKRxpfIoctlSetEmulation, "IOCTL_KSWORD_ARK_RXPF_SET_EMULATION", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_QUERY_STATS, KswordARKRxpfIoctlQueryStats, "IOCTL_KSWORD_ARK_RXPF_QUERY_STATS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_RXPF_DRAIN_EVENTS, KswordARKRxpfIoctlDrainEvents, "IOCTL_KSWORD_ARK_RXPF_DRAIN_EVENTS", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS },
    { IOCTL_KSWORD_ARK_RXPF_UNREGISTER_PAGE, KswordARKRxpfIoctlUnregisterPage, "IOCTL_KSWORD_ARK_RXPF_UNREGISTER_PAGE", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE },
    { IOCTL_KSWORD_ARK_RXPF_RUN_SELF_TEST, KswordARKRxpfIoctlRunSelfTest, "IOCTL_KSWORD_ARK_RXPF_RUN_SELF_TEST", KSWORD_ARK_IOCTL_CAPABILITY_NONE, KSWORD_ARK_IOCTL_FLAG_NONE }
};

_Must_inspect_result_
const KSWORD_ARK_IOCTL_ENTRY*
KswordARKLookupIoctlEntry(
    _In_ ULONG IoControlCode
    )
/*++

Routine Description:

    Locate the registered IOCTL entry for the supplied control code. The table is
    exact-match only so unsupported IOCTLs fail closed.

Arguments:

    IoControlCode - Control code received by the queue dispatch callback.

Return Value:

    Pointer to a registry entry when found; NULL when unsupported.

--*/
{
    ULONG entryIndex = 0;

    for (entryIndex = 0; entryIndex < (sizeof(g_KswordArkIoctlTable) / sizeof(g_KswordArkIoctlTable[0])); ++entryIndex) {
        if (g_KswordArkIoctlTable[entryIndex].IoControlCode == IoControlCode) {
            return &g_KswordArkIoctlTable[entryIndex];
        }
    }

    return NULL;
}

ULONG
KswordARKGetRegisteredIoctlCount(
    VOID
    )
/*++

Routine Description:

    返回当前 IOCTL 注册表项数量。中文说明：Phase-16 preflight 使用该值检查
    注册表是否可枚举，避免 R3 自己猜测驱动支持面。

Arguments:

    None.

Return Value:

    g_KswordArkIoctlTable 的元素数量。

--*/
{
    return (ULONG)(sizeof(g_KswordArkIoctlTable) / sizeof(g_KswordArkIoctlTable[0]));
}

ULONG
KswordARKGetDuplicateIoctlCount(
    VOID
    )
/*++

Routine Description:

    检查 IOCTL 注册表中重复 control code 的数量。中文说明：重复注册会导致
    后面的 handler 永远不可达，是发布前必须暴露的结构性问题。

Arguments:

    None.

Return Value:

    重复项数量；0 表示没有重复。

--*/
{
    ULONG duplicateCount = 0UL;
    ULONG outerIndex = 0UL;
    ULONG innerIndex = 0UL;
    const ULONG totalCount = KswordARKGetRegisteredIoctlCount();

    for (outerIndex = 0UL; outerIndex < totalCount; ++outerIndex) {
        for (innerIndex = outerIndex + 1UL; innerIndex < totalCount; ++innerIndex) {
            if (g_KswordArkIoctlTable[outerIndex].IoControlCode ==
                g_KswordArkIoctlTable[innerIndex].IoControlCode) {
                duplicateCount += 1UL;
            }
        }
    }

    return duplicateCount;
}

// 中文说明：按索引导出静态注册表项，越界时返回 NULL。
_Must_inspect_result_
const KSWORD_ARK_IOCTL_ENTRY*
KswordARKGetIoctlEntryByIndex(
    _In_ ULONG Index
    )
/*++

Routine Description:

    中文说明：只读返回注册表项，不复制或修改静态表。

Arguments:

    Index - 注册表数组索引。

Return Value:

    有效索引返回项地址，越界返回 NULL。

--*/
{
    // 中文说明：先取得固定数组长度，避免调用方越界访问。
    const ULONG totalCount = KswordARKGetRegisteredIoctlCount();

    // 中文说明：拒绝越界索引，保持注册表查询为只读安全操作。
    if (Index >= totalCount) {
        return NULL;
    }

    // 中文说明：返回静态数组中的只读项地址。
    return &g_KswordArkIoctlTable[Index];
}
