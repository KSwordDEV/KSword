#pragma once

#include <ntddk.h>

#include "driver/KswordArkKernelIoctl.h"
#include "driver/KswordArkDriverBlindIoctl.h"
#include "driver/KswordArkDriverDispatchIoctl.h"
#include "driver/KswordArkDriverImageEditorIoctl.h"
#include "driver/KswordArkSlatIommuAuditIoctl.h"

EXTERN_C_START

#define KSW_DRIVER_UNLOAD_DIAG_STAGE_REFERENCE KSWORD_ARK_UNLOAD_DIAG_REFERENCE
#define KSW_DRIVER_UNLOAD_DIAG_STAGE_PREFLIGHT KSWORD_ARK_UNLOAD_DIAG_PREFLIGHT
#define KSW_DRIVER_UNLOAD_DIAG_STAGE_ZW KSWORD_ARK_UNLOAD_DIAG_ZW
#define KSW_DRIVER_UNLOAD_DIAG_STAGE_ZW_VERIFY KSWORD_ARK_UNLOAD_DIAG_ZW_VERIFY
#define KSW_DRIVER_UNLOAD_DIAG_STAGE_DIRECT KSWORD_ARK_UNLOAD_DIAG_DIRECT
#define KSW_DRIVER_UNLOAD_DIAG_STAGE_DIRECT_VERIFY KSWORD_ARK_UNLOAD_DIAG_DIRECT_VERIFY

typedef struct _KSW_DRIVER_UNLOAD_DIAGNOSTICS
{
    ULONG stages;
    ULONG blockingFlags; // 分别记录三类尚未恢复的编辑记录，供日志与回执共享。
    ULONG requestedFlags;
    ULONG sanitizedFlags;
    ULONG finalFlags;
    NTSTATUS referenceStatus;
    NTSTATUS preflightBuildStatus;
    NTSTATUS preflightStatus;
    NTSTATUS preflightDenyStatus;
    NTSTATUS zwRunStatus;
    NTSTATUS zwWaitStatus;
    NTSTATUS zwUnloadStatus;
    NTSTATUS zwVerifyStatus;
    NTSTATUS directRunStatus;
    NTSTATUS directWaitStatus;
    NTSTATUS directUnloadStatus;
    NTSTATUS directCleanupStatus;
    NTSTATUS directVerifyStatus;
    BOOLEAN allowZwUnload;
    BOOLEAN allowDirectUnload;
    BOOLEAN allowDestructiveCleanup;
    BOOLEAN hasServiceRegistryPath;
    BOOLEAN hasDriverUnload;
    BOOLEAN hasValidDynData;
    BOOLEAN hasPdbBackedDynData;
    BOOLEAN hasValidDriverObjectOffsets;
    BOOLEAN hasValidLoaderEvidence;
    BOOLEAN hasDeviceChain;
    BOOLEAN hasCrossDriverAttach;
    BOOLEAN hasDeviceLoop;
    BOOLEAN hasAttachedDevice;
    BOOLEAN hasBusyDeviceReference;
    BOOLEAN hasThreadScan;
    BOOLEAN hasModuleResidentThreads;
    BOOLEAN hasCallbackScan;
    BOOLEAN hasModuleCallbacks;
    BOOLEAN hasNonRemovableModuleCallbacks;
    BOOLEAN hasLoaderLinkCheck;
    BOOLEAN hasLoaderLinkMismatch;
    BOOLEAN hasImageHeaderCheck;
    BOOLEAN hasInvalidImageHeader;
    BOOLEAN isCoreKernelModule;
    BOOLEAN isSelfModule;
    ULONGLONG driverStart;
    ULONGLONG loaderEntryAddress;
    ULONGLONG loaderDllBase;
    ULONG loaderSizeOfImage;
    ULONG scannedProcessCount;
    ULONG scannedThreadCount;
    ULONG moduleResidentThreadCount;
    NTSTATUS threadScanStatus;
    ULONG callbackEnumeratedCount;
    ULONG moduleCallbackCount;
    ULONG removableModuleCallbackCount;
    ULONG nonRemovableModuleCallbackCount;
    NTSTATUS callbackScanStatus;
    NTSTATUS loaderLinkStatus;
    NTSTATUS imageHeaderStatus;
    ULONG imageHeaderSizeOfImage;
    ULONG imageNtHeaderOffset;
} KSW_DRIVER_UNLOAD_DIAGNOSTICS, *PKSW_DRIVER_UNLOAD_DIAGNOSTICS;

NTSTATUS
KswordARKDriverCommunicationInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    );

VOID
KswordARKDriverCommunicationUninitialize(
    VOID
    );

NTSTATUS
KswordARKDriverControlCommunication(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* Response
    );

BOOLEAN
KswordARKDriverCommunicationHasBlockingRecord(
    _In_ PDRIVER_OBJECT TargetDriverObject,
    _In_ ULONGLONG OriginalRequestModuleBase
    );

NTSTATUS
KswordARKDriverDispatchInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    );

VOID
KswordARKDriverDispatchUninitialize(
    VOID
    );

// HAL 表编辑事务在驱动生命周期内记录首次原值；卸载时仅在槽仍等于
// 本功能最后发布值的情况下原子恢复，避免覆盖第三方并发修改。
VOID
KswordARKPlatformAuditInitialize(
    VOID
    );

VOID
KswordARKPlatformAuditUninitialize(
    VOID
    );

NTSTATUS
KswordARKDriverControlDispatch(
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* Response
    );

NTSTATUS
KswordARKSlatIommuAuditQuery(
    _In_ const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST* Request,
    _Out_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* Response
    );

BOOLEAN
KswordARKDriverDispatchHasBlockingRecord(
    _In_ PDRIVER_OBJECT TargetDriverObject,
    _In_ ULONGLONG OriginalRequestModuleBase
    );

NTSTATUS
KswordARKKernelIoctlControlDriverDispatch(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

NTSTATUS
KswordARKDriverImageInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    );

VOID
KswordARKDriverImageUninitialize(
    VOID
    );

NTSTATUS
KswordARKDriverControlImage(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* Response
    );

BOOLEAN
KswordARKDriverImageHasBlockingRecord(
    _In_ PDRIVER_OBJECT TargetDriverObject,
    _In_ ULONGLONG OriginalRequestModuleBase
    );

NTSTATUS
KswordARKKernelIoctlControlDriverImage(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

NTSTATUS
KswordARKDriverReferenceObjectByModuleBase(
    _In_ ULONGLONG TargetModuleBase,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut,
    _Out_writes_(NameChars) PWCHAR NormalizedNameOut,
    _In_ ULONG NameChars
    );

NTSTATUS
KswordARKKernelIoctlExperimentalReturnToFirmware(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

NTSTATUS
KswordARKDriverEnumerateSsdt(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_SSDT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
KswordARKDriverQueryDriverObject(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
KswordARKDriverQueryDriverIntegrity(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKDriverQueryCpuHardware(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKDriverQueryPhysicalMemoryLayout(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKDriverEnumerateTimerDpc(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_TIMER_DPC_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKDriverEnumerateShadowSsdt(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_SSDT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
KswordARKDriverScanInlineHooks(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKDriverPatchInlineHook(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_PATCH_INLINE_HOOK_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKDriverEnumerateIatEatHooks(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKDriverForceUnloadDriver(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut,
    _Out_opt_ KSW_DRIVER_UNLOAD_DIAGNOSTICS* Diagnostics
    );

EXTERN_C_END
