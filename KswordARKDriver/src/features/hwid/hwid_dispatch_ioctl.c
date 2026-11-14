/*++

Module Name:

    hwid_dispatch_ioctl.c

Abstract:

    IOCTL handlers for the dispatch-function HWID integration page.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_safety.h"
#include "../../dispatch/ioctl_validation.h"
#include "driver/KswordArkHwidIoctl.h"
#include "hwid_dispatch_hooks.h"

#include <ntstrsafe.h>
#include <stdarg.h>

NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
    );

extern POBJECT_TYPE* IoDriverObjectType;

typedef struct _KSW_HWID_DISPATCH_SLOT
{
    ULONG TargetFlag;
    PCWSTR DriverName;
    PDRIVER_OBJECT DriverObject;
    PDRIVER_DISPATCH OriginalDispatch;
    NTSTATUS LastStatus;
    BOOLEAN Active;
    /*
     * 中文说明：派遣帧和挂起完成例程分开计数。目标驱动同步完成 IRP 时完成例程
     * 会先于 passthrough 返回执行，只靠一个计数会让卸载路径提前放行仍在目标
     * 驱动栈里的派遣帧；两段计数都归零才允许释放引用和卸载映像。
     */
    volatile LONG DispatchInFlight;
    volatile LONG CompletionInFlight;
} KSW_HWID_DISPATCH_SLOT, *PKSW_HWID_DISPATCH_SLOT;

static FAST_MUTEX g_KswordHwidDispatchLock;
/* 中文说明：槽位发布和派遣路径的在途计数用自旋锁保护，派遣可在 DISPATCH_LEVEL 运行。 */
static KSPIN_LOCK g_KswordHwidDispatchSpinLock;
static volatile LONG g_KswordHwidDispatchInitialized = 0;
static ULONG g_KswordHwidDispatchGeneration = 1UL;
static KSWORD_ARK_HWID_DISPATCH_PROFILE g_KswordHwidActiveProfile;
static KSW_HWID_DISPATCH_SLOT g_KswordHwidSlots[KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT] = {
    { KSWORD_ARK_HWID_DISPATCH_TARGET_DISK, L"\\Driver\\Disk", NULL, NULL, STATUS_NOT_SUPPORTED, FALSE, 0L, 0L },
    { KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR, L"\\Driver\\partmgr", NULL, NULL, STATUS_NOT_SUPPORTED, FALSE, 0L, 0L },
    { KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR, L"\\Driver\\mountmgr", NULL, NULL, STATUS_NOT_SUPPORTED, FALSE, 0L, 0L },
    { KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA, L"\\Driver\\nvlddmkm", NULL, NULL, STATUS_NOT_SUPPORTED, FALSE, 0L, 0L },
    { KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY, L"\\Driver\\nsiproxy", NULL, NULL, STATUS_NOT_SUPPORTED, FALSE, 0L, 0L }
};

static VOID
KswordARKHwidLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), FormatText, arguments))) {
        (VOID)KswordARKDriverEnqueueLogFrame(Device, LevelText, logMessage);
    }
    va_end(arguments);
}

static VOID
KswordARKHwidEnsureInitialized(
    VOID
    )
{
    if (InterlockedCompareExchange(&g_KswordHwidDispatchInitialized, 1L, 0L) == 0L) {
        ExInitializeFastMutex(&g_KswordHwidDispatchLock);
        /* 中文说明：自旋锁必须先于任何槽位安装初始化，派遣路径拿锁时它已可用。 */
        KeInitializeSpinLock(&g_KswordHwidDispatchSpinLock);
        RtlZeroMemory(&g_KswordHwidActiveProfile, sizeof(g_KswordHwidActiveProfile));
        g_KswordHwidActiveProfile.size = sizeof(g_KswordHwidActiveProfile);
        g_KswordHwidActiveProfile.version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
        InterlockedExchange(&g_KswordHwidDispatchInitialized, 2L);
    }
    else {
        while (g_KswordHwidDispatchInitialized != 2L) {
            YieldProcessor();
        }
    }
}

static VOID
KswordARKHwidNormalizeProfile(
    _Out_ KSWORD_ARK_HWID_DISPATCH_PROFILE* Destination,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* Source
    );

static KSW_HWID_DISPATCH_SLOT*
KswordARKHwidFindSlotLocked(
    _In_opt_ PDRIVER_OBJECT DriverObject
    )
{
    ULONG slotIndex = 0UL;

    /* 中文说明：调用方必须持有 g_KswordHwidDispatchSpinLock，槽位字段才能与拆除路径互斥。 */
    if (DriverObject == NULL) {
        return NULL;
    }

    for (slotIndex = 0UL; slotIndex < KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT; ++slotIndex) {
        if (g_KswordHwidSlots[slotIndex].DriverObject == DriverObject &&
            g_KswordHwidSlots[slotIndex].OriginalDispatch != NULL) {
            return &g_KswordHwidSlots[slotIndex];
        }
    }

    return NULL;
}

static NTSTATUS
KswordARKHwidDispatchPassthrough(
    _In_ PDEVICE_OBJECT Device,
    _Inout_ PIRP Irp
    )
{
    PDRIVER_DISPATCH originalDispatch = NULL;
    KSW_HWID_DISPATCH_SLOT* targetSlot = NULL;
    PIO_STACK_LOCATION ioStack = NULL;
    KSWORD_ARK_HWID_DISPATCH_PROFILE activeProfile;
    NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
    KIRQL irql;

    RtlZeroMemory(&activeProfile, sizeof(activeProfile));
    /*
     * 中文说明：槽位查找与派遣帧登记必须在同一临界区完成。卸载路径先恢复全部
     * MajorFunction，再逐槽等待两段计数归零，因此登记成功即代表目标驱动对象
     * 引用在本次派遣和完成例程结束前不会被释放。
     */
    if (Device != NULL) {
        KeAcquireSpinLock(&g_KswordHwidDispatchSpinLock, &irql);
        targetSlot = KswordARKHwidFindSlotLocked(Device->DriverObject);
        if (targetSlot != NULL) {
            InterlockedIncrement(&targetSlot->DispatchInFlight);
            originalDispatch = targetSlot->OriginalDispatch;
        }
        KeReleaseSpinLock(&g_KswordHwidDispatchSpinLock, irql);
    }

    if (originalDispatch != NULL) {
        if (Irp != NULL) {
            ioStack = IoGetCurrentIrpStackLocation(Irp);
            KswordARKHwidNormalizeProfile(&activeProfile, &g_KswordHwidActiveProfile);
            /*
             * 中文说明：安装完成例程时同时登记完成段计数；目标驱动可能挂起
             * IRP，完成例程会晚于本函数返回才执行。
             */
            (VOID)KswordARKHwidPrepareDispatchCompletion(
                Irp,
                ioStack,
                targetSlot->TargetFlag,
                &activeProfile,
                &targetSlot->CompletionInFlight);
        }

        /*
         * 中文说明：派遣帧计数必须等目标驱动返回后再递减，同步完成路径下
         * 完成例程已经执行也不影响这里；否则卸载可能提前回到已释放的栈帧。
         */
        status = originalDispatch(Device, Irp);
        InterlockedDecrement(&targetSlot->DispatchInFlight);
        return status;
    }

    /* 中文说明：槽位已被拆除时不再转发，避免在卸载窗口调用目标驱动的旧派遣。 */
    if (Irp != NULL) {
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0U;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return status;
}

static NTSTATUS
KswordARKHwidReferenceDriverObject(
    _In_z_ PCWSTR DriverName,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut
    )
{
    UNICODE_STRING objectName;

    if (DriverObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DriverObjectOut = NULL;
    if (DriverName == NULL || IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&objectName, DriverName);
    return ObReferenceObjectByName(
        &objectName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)DriverObjectOut);
}

static VOID
KswordARKHwidCopyBoundedText(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_z_ PCWSTR Source
    )
{
    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }

    Destination[0] = L'\0';
    if (Source == NULL) {
        return;
    }

    (VOID)RtlStringCbCopyW(Destination, (SIZE_T)DestinationChars * sizeof(WCHAR), Source);
    Destination[DestinationChars - 1UL] = L'\0';
}

static VOID
KswordARKHwidNormalizeProfile(
    _Out_ KSWORD_ARK_HWID_DISPATCH_PROFILE* Destination,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* Source
    )
{
    if (Destination == NULL || Source == NULL) {
        return;
    }

    RtlCopyMemory(Destination, Source, sizeof(*Destination));
    Destination->size = sizeof(*Destination);
    Destination->version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
    Destination->diskSerial[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    Destination->diskProduct[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    Destination->diskRevision[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    Destination->gpuSerial[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    Destination->permanentMac[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
    Destination->currentMac[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS - 1U] = L'\0';
}

static NTSTATUS
KswordARKHwidInstallSlot(
    _Inout_ KSW_HWID_DISPATCH_SLOT* Slot,
    _In_ BOOLEAN DryRun
    )
{
    PDRIVER_OBJECT driverObject = NULL;
    PDRIVER_DISPATCH originalDispatch = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;

    if (Slot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Slot->Active != FALSE) {
        Slot->LastStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }

    status = KswordARKHwidReferenceDriverObject(Slot->DriverName, &driverObject);
    Slot->LastStatus = status;
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (DryRun != FALSE) {
        ObDereferenceObject(driverObject);
        Slot->LastStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }

    originalDispatch = driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    if (originalDispatch == NULL) {
        ObDereferenceObject(driverObject);
        Slot->OriginalDispatch = NULL;
        Slot->LastStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_INVALID_DEVICE_STATE;
    }

    /*
     * 中文说明：槽位发布和 MajorFunction 替换必须与派遣路径共用同一把自旋锁，
     * 否则并发的 passthrough 可能看到只写了一半的槽位。
     */
    KeAcquireSpinLock(&g_KswordHwidDispatchSpinLock, &irql);
    Slot->DriverObject = driverObject;
    Slot->OriginalDispatch = originalDispatch;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KswordARKHwidDispatchPassthrough;
    Slot->Active = TRUE;
    Slot->LastStatus = STATUS_SUCCESS;
    KeReleaseSpinLock(&g_KswordHwidDispatchSpinLock, irql);
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKHwidRemoveSlot(
    _Inout_ KSW_HWID_DISPATCH_SLOT* Slot,
    _Inout_ ULONG* ResponseFlags
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PDRIVER_OBJECT driverObject = NULL;
    PDRIVER_DISPATCH originalDispatch = NULL;
    KIRQL irql;

    if (Slot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Slot->Active == FALSE) {
        Slot->LastStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }

    /*
     * 中文说明：恢复入口和清空槽位在同一把自旋锁内完成，派遣路径不会再取到
     * 正在拆除的槽位；在途计数由卸载路径统一等待，拆除单个槽位不阻塞调用方。
     */
    KeAcquireSpinLock(&g_KswordHwidDispatchSpinLock, &irql);
    driverObject = Slot->DriverObject;
    originalDispatch = Slot->OriginalDispatch;
    if (driverObject == NULL || originalDispatch == NULL) {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else if (driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] == KswordARKHwidDispatchPassthrough) {
        driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = originalDispatch;
    }
    else {
        status = STATUS_OBJECT_TYPE_MISMATCH;
        if (ResponseFlags != NULL) {
            *ResponseFlags |= KSWORD_ARK_HWID_DISPATCH_RESPONSE_FLAG_FOREIGN_CHANGE;
        }
    }
    Slot->DriverObject = NULL;
    Slot->OriginalDispatch = NULL;
    Slot->Active = FALSE;
    Slot->LastStatus = status;
    KeReleaseSpinLock(&g_KswordHwidDispatchSpinLock, irql);

    /* 中文说明：无论入口是否被第三方改写，安装时取得的 DriverObject 引用都必须释放。 */
    if (driverObject != NULL) {
        ObDereferenceObject(driverObject);
    }
    return status;
}

static VOID
KswordARKHwidFillResponseLocked(
    _Out_ KSWORD_ARK_HWID_DISPATCH_RESPONSE* Response,
    _In_ ULONG RequestedTargetFlags,
    _In_ ULONG FailedTargetFlags,
    _In_ ULONG ExtraResponseFlags,
    _In_ NTSTATUS LastStatus
    )
{
    ULONG slotIndex = 0UL;
    ULONG activeFlags = 0UL;

    RtlZeroMemory(Response, sizeof(*Response));
    Response->size = sizeof(*Response);
    Response->version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
    Response->supportedTargetFlags = KSWORD_ARK_HWID_DISPATCH_TARGET_ALL;
    Response->requestedTargetFlags = RequestedTargetFlags;
    Response->failedTargetFlags = FailedTargetFlags;
    Response->generation = g_KswordHwidDispatchGeneration;
    Response->lastStatus = LastStatus;
    Response->responseFlags = ExtraResponseFlags;
    KswordARKHwidNormalizeProfile(&Response->activeProfile, &g_KswordHwidActiveProfile);

    for (slotIndex = 0UL; slotIndex < KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT; ++slotIndex) {
        KSWORD_ARK_HWID_DISPATCH_ENTRY* entry = &Response->entries[slotIndex];
        KSW_HWID_DISPATCH_SLOT* slot = &g_KswordHwidSlots[slotIndex];
        entry->size = sizeof(*entry);
        entry->targetFlag = slot->TargetFlag;
        entry->active = slot->Active != FALSE ? 1UL : 0UL;
        entry->lastStatus = slot->LastStatus;
        entry->driverObjectAddress = (ULONGLONG)(ULONG_PTR)slot->DriverObject;
        entry->originalDispatchAddress = (ULONGLONG)(ULONG_PTR)slot->OriginalDispatch;
        entry->currentDispatchAddress = slot->DriverObject != NULL ?
            (ULONGLONG)(ULONG_PTR)slot->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] : 0ULL;
        KswordARKHwidCopyBoundedText(entry->driverName, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS, slot->DriverName);
        if (slot->Active != FALSE) {
            activeFlags |= slot->TargetFlag;
        }
    }

    Response->activeTargetFlags = activeFlags;
    if (FailedTargetFlags != 0UL && activeFlags != 0UL) {
        Response->overallStatus = KSWORD_ARK_HWID_DISPATCH_STATUS_PARTIAL;
        Response->responseFlags |= KSWORD_ARK_HWID_DISPATCH_RESPONSE_FLAG_PARTIAL;
    }
    else if (FailedTargetFlags != 0UL) {
        Response->overallStatus = KSWORD_ARK_HWID_DISPATCH_STATUS_FAILED;
    }
    else if (activeFlags != 0UL) {
        Response->overallStatus = KSWORD_ARK_HWID_DISPATCH_STATUS_ACTIVE;
    }
    else {
        Response->overallStatus = KSWORD_ARK_HWID_DISPATCH_STATUS_READY;
    }
}

static NTSTATUS
KswordARKHwidControlLocked(
    _In_ const KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST* Request,
    _Out_ KSWORD_ARK_HWID_DISPATCH_RESPONSE* Response
    )
{
    ULONG slotIndex = 0UL;
    ULONG targetFlags = 0UL;
    ULONG failedFlags = 0UL;
    ULONG responseFlags = 0UL;
    NTSTATUS lastStatus = STATUS_SUCCESS;
    BOOLEAN dryRun = FALSE;

    targetFlags = Request->profile.targetFlags & KSWORD_ARK_HWID_DISPATCH_TARGET_ALL;
    dryRun = ((Request->requestFlags & KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_DRY_RUN) != 0UL) ? TRUE : FALSE;
    if (dryRun != FALSE) {
        responseFlags |= KSWORD_ARK_HWID_DISPATCH_RESPONSE_FLAG_DRY_RUN;
    }

    if (targetFlags == 0UL && Request->action != KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE_ALL) {
        KswordARKHwidFillResponseLocked(Response, Request->profile.targetFlags, Request->profile.targetFlags, responseFlags, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    if (Request->action == KSWORD_ARK_HWID_DISPATCH_ACTION_ENABLE && dryRun == FALSE) {
        KswordARKHwidNormalizeProfile(&g_KswordHwidActiveProfile, &Request->profile);
    }

    for (slotIndex = 0UL; slotIndex < KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT; ++slotIndex) {
        KSW_HWID_DISPATCH_SLOT* slot = &g_KswordHwidSlots[slotIndex];
        if (Request->action != KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE_ALL &&
            (slot->TargetFlag & targetFlags) == 0UL) {
            continue;
        }
        if (Request->action == KSWORD_ARK_HWID_DISPATCH_ACTION_ENABLE) {
            lastStatus = KswordARKHwidInstallSlot(slot, dryRun);
        }
        else if (Request->action == KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE ||
            Request->action == KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE_ALL) {
            lastStatus = dryRun != FALSE ? STATUS_SUCCESS : KswordARKHwidRemoveSlot(slot, &responseFlags);
        }
        else if (Request->action == KSWORD_ARK_HWID_DISPATCH_ACTION_QUERY) {
            lastStatus = STATUS_SUCCESS;
        }
        else {
            lastStatus = STATUS_INVALID_PARAMETER;
        }
        if (!NT_SUCCESS(lastStatus)) {
            failedFlags |= slot->TargetFlag;
        }
    }

    if (dryRun == FALSE && Request->action != KSWORD_ARK_HWID_DISPATCH_ACTION_QUERY) {
        ++g_KswordHwidDispatchGeneration;
    }

    KswordARKHwidFillResponseLocked(Response, targetFlags, failedFlags, responseFlags, lastStatus);
    return failedFlags == 0UL ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS
KswordARKHwidIoctlQueryDispatch(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_HWID_DISPATCH_RESPONSE* response = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    size_t actualOutputLength = 0U;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    KswordARKHwidEnsureInitialized();

    status = KswordARKRetrieveRequiredOutputBuffer(Request, sizeof(*response), (PVOID*)&response, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ExAcquireFastMutex(&g_KswordHwidDispatchLock);
    KswordARKHwidFillResponseLocked(response, 0UL, 0UL, 0UL, STATUS_SUCCESS);
    ExReleaseFastMutex(&g_KswordHwidDispatchLock);

    *BytesReturned = sizeof(*response);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHwidIoctlControlDispatch(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST* controlRequest = NULL;
    // requestSnapshot 在写响应前保存完整请求，响应与请求共用同一 SystemBuffer。
    KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST requestSnapshot;
    KSWORD_ARK_HWID_DISPATCH_RESPONSE* response = NULL;
    KSWORD_ARK_SAFETY_CONTEXT safetyContext;
    NTSTATUS status = STATUS_SUCCESS;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    static const WCHAR targetText[] = L"HWID dispatch MajorFunction hook";

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    KswordARKHwidEnsureInitialized();

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = KswordARKRetrieveRequiredInputBuffer(Request, sizeof(*controlRequest), (PVOID*)&controlRequest, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * METHOD_BUFFERED 的输入和输出是同一个 SystemBuffer；KswordARKHwidFillResponseLocked
     * 写完响应后本函数还要读 action 记日志，不做快照日志里就全是响应头字节。
     */
    RtlCopyMemory(&requestSnapshot, controlRequest, sizeof(requestSnapshot));
    controlRequest = &requestSnapshot;

    status = KswordARKRetrieveRequiredOutputBuffer(Request, sizeof(*response), (PVOID*)&response, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (controlRequest->size < sizeof(*controlRequest) ||
        controlRequest->version != KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION ||
        controlRequest->profile.size < sizeof(controlRequest->profile) ||
        controlRequest->profile.version != KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION) {
        ExAcquireFastMutex(&g_KswordHwidDispatchLock);
        KswordARKHwidFillResponseLocked(response, 0UL, 0UL, 0UL, STATUS_INVALID_PARAMETER);
        ExReleaseFastMutex(&g_KswordHwidDispatchLock);
        *BytesReturned = sizeof(*response);
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&safetyContext, sizeof(safetyContext));
    safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
    safetyContext.ContextFlags =
        ((controlRequest->requestFlags & KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_UI_CONFIRMED) != 0UL) ?
        KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED : 0UL;
    safetyContext.TargetText = targetText;
    safetyContext.TargetTextChars = (USHORT)(RTL_NUMBER_OF(targetText) - 1U);
    status = KswordARKSafetyEvaluate(Device, &safetyContext);
    if (!NT_SUCCESS(status)) {
        ExAcquireFastMutex(&g_KswordHwidDispatchLock);
        KswordARKHwidFillResponseLocked(response, controlRequest->profile.targetFlags, controlRequest->profile.targetFlags, 0UL, status);
        response->overallStatus = KSWORD_ARK_HWID_DISPATCH_STATUS_DENIED;
        ExReleaseFastMutex(&g_KswordHwidDispatchLock);
        *BytesReturned = sizeof(*response);
        KswordARKHwidLog(Device, "Warn", "R0 HWID dispatch denied by safety policy, status=0x%08X.", (unsigned int)status);
        return status;
    }

    ExAcquireFastMutex(&g_KswordHwidDispatchLock);
    status = KswordARKHwidControlLocked(controlRequest, response);
    ExReleaseFastMutex(&g_KswordHwidDispatchLock);

    *BytesReturned = sizeof(*response);
    KswordARKHwidLog(
        Device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "R0 HWID dispatch action=%lu status=0x%08X active=0x%08X failed=0x%08X.",
        (unsigned long)controlRequest->action,
        (unsigned int)status,
        (unsigned int)response->activeTargetFlags,
        (unsigned int)response->failedTargetFlags);
    return status;
}

static VOID
KswordARKHwidDrainCounter(
    _Inout_ volatile LONG* Counter
    )
{
    LARGE_INTEGER retryInterval;

    /* 中文说明：调用方处于 PASSIVE_LEVEL；1ms 相对等待避免卸载路径忙等。 */
    retryInterval.QuadPart = -10000LL;
    while (InterlockedCompareExchange(Counter, 0L, 0L) != 0L) {
        KeDelayExecutionThread(KernelMode, FALSE, &retryInterval);
    }
}

VOID
KswordARKHwidUninitialize(
    VOID
    )
{
    PDRIVER_OBJECT releaseObjects[KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT] = { NULL };
    ULONG releaseCount = 0UL;
    ULONG slotIndex = 0UL;
    KIRQL irql;

    /* 中文说明：从未处理过 HWID 请求时没有安装过 hook，直接返回。 */
    if (InterlockedCompareExchange(&g_KswordHwidDispatchInitialized, 0L, 0L) != 2L) {
        return;
    }

    ExAcquireFastMutex(&g_KswordHwidDispatchLock);
    for (slotIndex = 0UL; slotIndex < KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT; ++slotIndex) {
        KSW_HWID_DISPATCH_SLOT* slot = &g_KswordHwidSlots[slotIndex];
        PDRIVER_OBJECT driverObject = NULL;

        KeAcquireSpinLock(&g_KswordHwidDispatchSpinLock, &irql);
        driverObject = slot->DriverObject;
        /*
         * 中文说明：只恢复仍由本模块持有的入口；被第三方改写过的槽位保持现状，
         * 但安装时取得的 DriverObject 引用仍然必须释放。
         */
        if (driverObject != NULL &&
            slot->OriginalDispatch != NULL &&
            driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] == KswordARKHwidDispatchPassthrough) {
            driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = slot->OriginalDispatch;
        }
        slot->DriverObject = NULL;
        slot->OriginalDispatch = NULL;
        slot->Active = FALSE;
        KeReleaseSpinLock(&g_KswordHwidDispatchSpinLock, irql);

        if (driverObject != NULL) {
            releaseObjects[releaseCount] = driverObject;
            ++releaseCount;
        }
    }
    ++g_KswordHwidDispatchGeneration;
    ExReleaseFastMutex(&g_KswordHwidDispatchLock);

    /*
     * 中文说明：入口全部恢复后不会再有新的 passthrough 进入。先等所有派遣帧
     * 退出（此后不会再有新的完成例程被安装），再等挂起的完成例程退出。
     */
    for (slotIndex = 0UL; slotIndex < KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT; ++slotIndex) {
        KswordARKHwidDrainCounter(&g_KswordHwidSlots[slotIndex].DispatchInFlight);
    }
    for (slotIndex = 0UL; slotIndex < KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT; ++slotIndex) {
        KswordARKHwidDrainCounter(&g_KswordHwidSlots[slotIndex].CompletionInFlight);
    }

    for (slotIndex = 0UL; slotIndex < releaseCount; ++slotIndex) {
        ObDereferenceObject(releaseObjects[slotIndex]);
    }

    RtlZeroMemory(&g_KswordHwidActiveProfile, sizeof(g_KswordHwidActiveProfile));
    InterlockedExchange(&g_KswordHwidDispatchInitialized, 0L);
}
