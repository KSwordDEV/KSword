#pragma once

// ============================================================
// KswordArkStartupProtocol.h
// Purpose:
// - Shared R0/R3 contract for KswordARK driver startup breadcrumbs.
// - R0 persists the last startup stage and the raw NTSTATUS under the driver
//   service Parameters key so a failed load can be diagnosed without a kernel
//   debugger. R3 reads the same values when StartService reports a failure.
// ============================================================

// Registry subkey created under the driver service key (Services\KswordARK).
#define KSWORD_ARK_STARTUP_PARAMETERS_SUBKEY L"Parameters"

// Full user-mode path of the breadcrumb key, used by R3 with RegOpenKeyExW.
#define KSWORD_ARK_STARTUP_PARAMETERS_PATH \
    L"SYSTEM\\CurrentControlSet\\Services\\KswordARK\\Parameters"

// REG_DWORD: last reached KSWORD_ARK_START_STAGE value.
#define KSWORD_ARK_STARTUP_VALUE_STAGE L"LastStartStage"

// REG_DWORD: raw NTSTATUS of the last startup attempt. STATUS_PENDING while
// DriverEntry is still running, STATUS_SUCCESS once the driver is fully up.
#define KSWORD_ARK_STARTUP_VALUE_STATUS L"LastStartStatus"

// REG_SZ: build identity of the .sys image that produced the record.
#define KSWORD_ARK_STARTUP_VALUE_BUILD L"LastStartBuild"

// REG_DWORD: OS build number observed by the driver during the attempt.
#define KSWORD_ARK_STARTUP_VALUE_OS_BUILD L"LastStartOsBuild"

// REG_DWORD: callback capability mask that survived degraded startup.
#define KSWORD_ARK_STARTUP_VALUE_CALLBACK_MASK L"LastStartCallbackMask"

// Lowest OS build declared by KswordARKDriver.inf. Older systems are rejected
// with STATUS_NOT_SUPPORTED instead of failing later inside callback setup.
#define KSWORD_ARK_MINIMUM_SUPPORTED_OS_BUILD 16299UL

// Highest OS build for which the checked-in DynData/runtime-offset set is
// supported. Newer or unknown builds keep the driver loadable for diagnostics,
// but all offset-dependent IOCTLs are rejected by the R0 dispatch gate.
#define KSWORD_ARK_MAXIMUM_SUPPORTED_OS_BUILD 26100UL

// Startup stages, ordered exactly like the DriverEntry call sequence. The
// numeric values are part of the R3 contract and must never be reordered.
typedef enum _KSWORD_ARK_START_STAGE
{
    KswordArkStartStageEnteredDriverEntry = 1,
    KswordArkStartStageOsVersionCheck = 2,
    KswordArkStartStageWdfDriverCreate = 3,
    KswordArkStartStageControlInitAllocate = 4,
    KswordArkStartStageDeviceAssignName = 5,
    KswordArkStartStageDeviceCreate = 6,
    KswordArkStartStageLogChannel = 7,
    KswordArkStartStageDebugOutput = 8,
    KswordArkStartStageSymbolicLink = 9,
    KswordArkStartStageDefaultQueue = 10,
    KswordArkStartStageCallbackRuntimeAllocate = 11,
    KswordArkStartStageCallbackWaitQueue = 12,
    KswordArkStartStageRegistryCallback = 13,
    KswordArkStartStageProcessCallback = 14,
    KswordArkStartStageThreadCallback = 15,
    KswordArkStartStageImageCallback = 16,
    KswordArkStartStageObjectCallback = 17,
    KswordArkStartStageControlDevicePublish = 18,
    KswordArkStartStageReady = 19
} KSWORD_ARK_START_STAGE;
