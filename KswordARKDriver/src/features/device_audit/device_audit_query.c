/*++

Module Name:

    device_audit_query.c

Abstract:

    Read-only adapter from existing DriverObject integrity evidence to device audit rows.

Environment:

    Kernel-mode Driver Framework

--*/

#include "device_audit_internal.h"
#include "../../platform/pool_compat.h"

/*
 * A device-audit row is large, and the integrity backend has its own sizable
 * stack frame.  Keep the per-target conversion state adjacent to the dynamic
 * backend response so the complete synchronous query chain remains bounded.
 */
typedef struct _KSW_DEVICE_AUDIT_QUERY_WORKSPACE
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST IntegrityRequest;
    KSWORD_ARK_DEVICE_AUDIT_ENTRY AuditEntry;
} KSW_DEVICE_AUDIT_QUERY_WORKSPACE, *PKSW_DEVICE_AUDIT_QUERY_WORKSPACE;

static VOID
KswDeviceAuditFillSummaryEntry(
    _Out_ KSWORD_ARK_DEVICE_AUDIT_ENTRY* Entry,
    _In_ ULONG ProfileFlags,
    _In_ ULONG RoleHint,
    _In_z_ PCWSTR DriverName,
    _In_ const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* IntegrityResponse
    )
/*++

Routine Description:

    Build a driver-summary row from the integrity response header.  This row is
    emitted even when the DriverObject was absent so R3 can show a clean
    not-found/partial diagnostic instead of silently hiding the target.

Arguments:

    Entry - Output row to initialize.
    ProfileFlags - Audit profile represented by this target.
    RoleHint - Expected role for the target driver in the selected profile.
    DriverName - DriverObject name queried by the backend.
    IntegrityResponse - Response header returned by the existing integrity code.

Return Value:

    None.  Entry is fully initialized in-place.

--*/
{
    ULONG rowStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_OK;
    ULONG riskFlags = KSWORD_ARK_DEVICE_AUDIT_RISK_NONE;

    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->size = sizeof(*Entry);
    Entry->profileFlags = ProfileFlags;
    Entry->rowKind = KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DRIVER_SUMMARY;
    Entry->roleHint = RoleHint;
    Entry->confidence = 70UL;
    Entry->lastStatus = STATUS_SUCCESS;
    KswDeviceAuditCopyWide(Entry->driverName, RTL_NUMBER_OF(Entry->driverName), DriverName);
    KswDeviceAuditCopyServiceName(Entry->serviceName, RTL_NUMBER_OF(Entry->serviceName), DriverName);
    Entry->fieldFlags = KSWORD_ARK_DEVICE_AUDIT_FIELD_DRIVER_NAME_PRESENT |
        KSWORD_ARK_DEVICE_AUDIT_FIELD_SERVICE_NAME_PRESENT |
        KSWORD_ARK_DEVICE_AUDIT_FIELD_DETAIL_PRESENT;

    if (IntegrityResponse == NULL) {
        Entry->status = KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED;
        Entry->riskFlags = KSWORD_ARK_DEVICE_AUDIT_RISK_QUERY_FAILED;
        Entry->lastStatus = STATUS_UNSUCCESSFUL;
        KswDeviceAuditCopyWide(Entry->detail, RTL_NUMBER_OF(Entry->detail), L"Driver integrity backend returned no response header.");
        return;
    }

    if (IntegrityResponse->queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK &&
        (IntegrityResponse->statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL) == 0UL) {
        rowStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_OK;
    }
    else if (IntegrityResponse->queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_NOT_FOUND) {
        rowStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_NOT_FOUND;
        riskFlags |= KSWORD_ARK_DEVICE_AUDIT_RISK_UNAVAILABLE;
    }
    else if (IntegrityResponse->queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_QUERY_FAILED) {
        rowStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED;
        riskFlags |= KSWORD_ARK_DEVICE_AUDIT_RISK_QUERY_FAILED;
    }
    else {
        rowStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_PARTIAL;
        riskFlags |= KSWORD_ARK_DEVICE_AUDIT_RISK_INTEGRITY_PARTIAL;
    }

    if ((IntegrityResponse->statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_TRUNCATED) != 0UL) {
        riskFlags |= KSWORD_ARK_DEVICE_AUDIT_RISK_STACK_TRUNCATED;
    }
    Entry->status = rowStatus;
    Entry->riskFlags = riskFlags;
    Entry->lastStatus = IntegrityResponse->lastStatus;
    Entry->fieldFlags |= KSWORD_ARK_DEVICE_AUDIT_FIELD_INTEGRITY_SUMMARY_PRESENT;
    Entry->integrityStatus = IntegrityResponse->queryStatus;
    Entry->integrityReturnedCount = IntegrityResponse->returnedCount;
    Entry->integrityTotalCount = IntegrityResponse->totalCount;
    Entry->integrityModuleCount = IntegrityResponse->moduleCount;
    Entry->integrityStatusFlags = IntegrityResponse->statusFlags;
    KswDeviceAuditCopyWide(Entry->detail, RTL_NUMBER_OF(Entry->detail), L"Driver integrity summary is available as typed fields.");
}

static VOID
KswDeviceAuditFillDeviceEntry(
    _Out_ KSWORD_ARK_DEVICE_AUDIT_ENTRY* Entry,
    _In_ ULONG ProfileFlags,
    _In_ ULONG RoleHint,
    _In_z_ PCWSTR DriverName,
    _In_ const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* Evidence
    )
/*++

Routine Description:

    Convert one integrity device-chain evidence row into the new audit row shape.
    The conversion is read-only and copies only addresses, flags, names, and
    textual diagnostics already produced by the integrity backend.

Arguments:

    Entry - Output row to initialize.
    ProfileFlags - Audit profile represented by this target.
    RoleHint - Expected role for the target driver.
    DriverName - DriverObject name queried by the backend.
    Evidence - Integrity evidence row to convert.

Return Value:

    None.  Entry is fully initialized in-place.

--*/
{
    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->size = sizeof(*Entry);
    Entry->profileFlags = ProfileFlags;
    Entry->rowKind = KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DEVICE_ROW;
    Entry->roleHint = RoleHint;
    Entry->status = KswDeviceAuditMapStatus(Evidence->entryStatus, Evidence->riskFlags);
    Entry->riskFlags = KswDeviceAuditMapRiskFlags(Evidence->riskFlags);
    Entry->fieldFlags = KSWORD_ARK_DEVICE_AUDIT_FIELD_DRIVER_NAME_PRESENT |
        KSWORD_ARK_DEVICE_AUDIT_FIELD_SERVICE_NAME_PRESENT |
        KSWORD_ARK_DEVICE_AUDIT_FIELD_DETAIL_PRESENT;
    Entry->confidence = Evidence->confidence;
    Entry->relationDepth = Evidence->ordinal;
    Entry->attachedDepth = Evidence->ordinal;
    Entry->deviceType = Evidence->deviceType;
    Entry->characteristics = Evidence->deviceFlags;
    Entry->lastStatus = STATUS_SUCCESS;
    Entry->driverObjectAddress = Evidence->driverObjectAddress;
    Entry->deviceObjectAddress = Evidence->deviceObjectAddress;
    Entry->attachedDeviceAddress = Evidence->attachedDeviceObjectAddress;
    Entry->nextDeviceObjectAddress = Evidence->nextDeviceObjectAddress;
    if ((Evidence->fieldMask & KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DEVICE_OBJECT) != 0UL) {
        Entry->ownerDriverObjectAddress = Evidence->deviceDriverObjectAddress;
        Entry->fieldFlags |= KSWORD_ARK_DEVICE_AUDIT_FIELD_OWNER_DRIVER_PRESENT;
    }
    KswDeviceAuditCopyWide(Entry->driverName, RTL_NUMBER_OF(Entry->driverName), DriverName);
    KswDeviceAuditCopyServiceName(Entry->serviceName, RTL_NUMBER_OF(Entry->serviceName), DriverName);
    KswDeviceAuditCopyWide(Entry->detail, RTL_NUMBER_OF(Entry->detail), Evidence->detail);

    if (Evidence->deviceObjectAddress != 0ULL) {
        Entry->fieldFlags |= KSWORD_ARK_DEVICE_AUDIT_FIELD_DEVICE_NAME_PRESENT;
        (VOID)RtlStringCchPrintfW(Entry->deviceName, RTL_NUMBER_OF(Entry->deviceName), L"DeviceObject 0x%llX", Evidence->deviceObjectAddress);
    }
    if (Evidence->attachedDeviceObjectAddress != 0ULL) {
        Entry->fieldFlags |= KSWORD_ARK_DEVICE_AUDIT_FIELD_ATTACHED_PRESENT;
    }
    if (Evidence->nextDeviceObjectAddress != 0ULL) {
        Entry->fieldFlags |= KSWORD_ARK_DEVICE_AUDIT_FIELD_NEXT_PRESENT;
    }
}

static NTSTATUS
KswDeviceAuditQueryOneTarget(
    _Inout_ KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ const KSW_DEVICE_AUDIT_REQUEST_CONTEXT* Context,
    _In_z_ PCWSTR DriverName,
    _In_ ULONG ProfileFlags,
    _In_ ULONG RoleHint
    )
/*++

Routine Description:

    Query one target DriverObject through the existing integrity backend and
    append a summary row plus each returned device-chain row to the audit
    response.  The function does not dereference device links itself.

Arguments:

    Response - Initialized caller response that receives converted rows.
    Capacity - Physical row capacity of Response.
    Context - Validated request context containing row and depth limits.
    DriverName - DriverObject namespace name to query.
    ProfileFlags - Audit profile represented by DriverName.
    RoleHint - Expected role to attach to emitted rows.

Return Value:

    STATUS_SUCCESS when the target was queried and any rows were appended.
    Non-success status only represents local allocation/backend transport errors;
    missing drivers are converted to partial evidence rows.

--*/
{
    KSW_DEVICE_AUDIT_QUERY_WORKSPACE* workspace = NULL;
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST* integrityRequest = NULL;
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* integrityResponse = NULL;
    KSWORD_ARK_DEVICE_AUDIT_ENTRY* auditEntry = NULL;
    ULONG scratchRows = KSW_DEVICE_AUDIT_SCRATCH_ROW_LIMIT;
    size_t workspaceBytes = 0U;
    size_t scratchBytes = 0U;
    size_t allocationBytes = 0U;
    size_t bytesWritten = 0U;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Response == NULL || Context == NULL || DriverName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Context->MaxRows != 0UL && Context->MaxRows < scratchRows) {
        scratchRows = Context->MaxRows;
    }
    if (scratchRows == 0UL) {
        scratchRows = 1UL;
    }

    scratchBytes = KSW_DEVICE_AUDIT_INTEGRITY_RESPONSE_HEADER_SIZE +
        ((size_t)scratchRows * sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE));
    workspaceBytes = ALIGN_UP_BY(
        sizeof(*workspace),
        MEMORY_ALLOCATION_ALIGNMENT);
    if (scratchBytes > MAXULONG_PTR - workspaceBytes) {
        return STATUS_INTEGER_OVERFLOW;
    }
    allocationBytes = workspaceBytes + scratchBytes;
    workspace = (KSW_DEVICE_AUDIT_QUERY_WORKSPACE*)KswordARKAllocateNonPagedPool(
        allocationBytes,
        KSW_DEVICE_AUDIT_POOL_TAG);
    if (workspace == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(workspace, allocationBytes);
    integrityRequest = &workspace->IntegrityRequest;
    auditEntry = &workspace->AuditEntry;
    integrityResponse = (KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*)(
        (PUCHAR)workspace + workspaceBytes);

    integrityRequest->version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
    integrityRequest->flags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DRIVER_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_SERVICE;
    integrityRequest->maxRows = scratchRows;
    integrityRequest->maxDevices = Context->MaxRows;
    integrityRequest->maxAttachedDevices = Context->MaxAttachedDepth;
    integrityRequest->requestSize = sizeof(*integrityRequest);
    KswDeviceAuditCopyWide(
        integrityRequest->driverName,
        RTL_NUMBER_OF(integrityRequest->driverName),
        DriverName);

    status = KswordARKDriverQueryDriverIntegrity(
        integrityResponse,
        scratchBytes,
        integrityRequest,
        &bytesWritten);
    if (!NT_SUCCESS(status)) {
        KswDeviceAuditSetResponsePartial(Response, status);
        RtlZeroMemory(auditEntry, sizeof(*auditEntry));
        auditEntry->size = sizeof(*auditEntry);
        auditEntry->profileFlags = ProfileFlags;
        auditEntry->rowKind = KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DRIVER_SUMMARY;
        auditEntry->roleHint = RoleHint;
        auditEntry->status = KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED;
        auditEntry->riskFlags = KSWORD_ARK_DEVICE_AUDIT_RISK_QUERY_FAILED;
        auditEntry->confidence = 20UL;
        auditEntry->lastStatus = status;
        auditEntry->fieldFlags = KSWORD_ARK_DEVICE_AUDIT_FIELD_DRIVER_NAME_PRESENT |
            KSWORD_ARK_DEVICE_AUDIT_FIELD_SERVICE_NAME_PRESENT |
            KSWORD_ARK_DEVICE_AUDIT_FIELD_DETAIL_PRESENT;
        KswDeviceAuditCopyWide(
            auditEntry->driverName,
            RTL_NUMBER_OF(auditEntry->driverName),
            DriverName);
        KswDeviceAuditCopyServiceName(
            auditEntry->serviceName,
            RTL_NUMBER_OF(auditEntry->serviceName),
            DriverName);
        (VOID)RtlStringCchPrintfW(
            auditEntry->detail,
            RTL_NUMBER_OF(auditEntry->detail),
            L"Driver integrity backend failed, status=0x%08lX.",
            (ULONG)status);
        (VOID)KswDeviceAuditAppendEntry(
            Response,
            Capacity,
            Context->MaxRows,
            auditEntry);
        ExFreePoolWithTag(workspace, KSW_DEVICE_AUDIT_POOL_TAG);
        return STATUS_SUCCESS;
    }

    UNREFERENCED_PARAMETER(bytesWritten);

    KswDeviceAuditFillSummaryEntry(
        auditEntry,
        ProfileFlags,
        RoleHint,
        DriverName,
        integrityResponse);
    status = KswDeviceAuditAppendEntry(
        Response,
        Capacity,
        Context->MaxRows,
        auditEntry);
    if (!NT_SUCCESS(status)) {
        KswDeviceAuditSetResponsePartial(Response, status);
    }
    else {
        Response->driverCount += 1UL;
    }

    if (integrityResponse->queryStatus != KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK ||
        (integrityResponse->statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL) != 0UL) {
        KswDeviceAuditSetResponsePartial(Response, integrityResponse->lastStatus);
    }

    for (index = 0UL; index < integrityResponse->returnedCount; ++index) {
        const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* evidence = &integrityResponse->entries[index];
        if (evidence->evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN) {
            continue;
        }
        KswDeviceAuditFillDeviceEntry(
            auditEntry,
            ProfileFlags,
            RoleHint,
            DriverName,
            evidence);
        status = KswDeviceAuditAppendEntry(
            Response,
            Capacity,
            Context->MaxRows,
            auditEntry);
        if (!NT_SUCCESS(status)) {
            KswDeviceAuditSetResponsePartial(Response, status);
            break;
        }
        Response->deviceCount += 1UL;
    }

    ExFreePoolWithTag(workspace, KSW_DEVICE_AUDIT_POOL_TAG);
    return STATUS_SUCCESS;
}

static NTSTATUS
KswDeviceAuditQueryTargets(
    _Inout_ KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ const KSW_DEVICE_AUDIT_REQUEST_CONTEXT* Context,
    _In_reads_(TargetCount) const KSW_DEVICE_AUDIT_TARGET* Targets,
    _In_ ULONG TargetCount,
    _In_ ULONG ProfileFlags
    )
/*++

Routine Description:

    Query a static list of target drivers for one profile.  Each target is
    isolated so one absent Windows component does not fail the whole IOCTL.

Arguments:

    Response - Initialized output response.
    Capacity - Physical row capacity of Response.
    Context - Validated request context.
    Targets - Static target table for the selected profile.
    TargetCount - Number of entries in Targets.
    ProfileFlags - Profile bit attached to emitted rows.

Return Value:

    STATUS_SUCCESS after all targets are attempted.  Local allocation failures
    are represented as partial response state and do not stop later targets.

--*/
{
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Response == NULL || Context == NULL || Targets == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0UL; index < TargetCount; ++index) {
        NTSTATUS targetStatus = KswDeviceAuditQueryOneTarget(
            Response,
            Capacity,
            Context,
            Targets[index].DriverName,
            ProfileFlags,
            Targets[index].RoleHint);
        Response->targetCount += 1UL;
        if (!NT_SUCCESS(targetStatus)) {
            status = targetStatus;
            KswDeviceAuditSetResponsePartial(Response, targetStatus);
        }
    }
    return status;
}

static ULONG
KswDeviceAuditKnownProfileForHandler(
    _In_ ULONG HandlerProfile,
    _In_ ULONG RequestedProfile
    )
/*++

Routine Description:

    Select the profile flags to execute for one public IOCTL.  A zero request
    means the handler default; otherwise only the handler-owned bit is honored.

Arguments:

    HandlerProfile - Profile bit implied by the IOCTL control code.
    RequestedProfile - Caller supplied profile mask.

Return Value:

    Effective profile mask or zero when the caller requested an unsupported mask.

--*/
{
    if (RequestedProfile == 0UL) {
        return HandlerProfile;
    }
    if ((RequestedProfile & ~KSWORD_ARK_DEVICE_AUDIT_PROFILE_ALL) != 0UL) {
        return 0UL;
    }
    return RequestedProfile & HandlerProfile;
}

static NTSTATUS
KswDeviceAuditCaptureRequest(
    _In_opt_ const KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST* UserRequest,
    _In_ ULONG HandlerProfile,
    _Out_ KSW_DEVICE_AUDIT_REQUEST_CONTEXT* Context
    )
/*++

Routine Description:

    Validate and normalize the optional IOCTL request.  The function accepts a
    NULL request to support legacy callers that only provide an output buffer.

Arguments:

    UserRequest - Optional caller request already retrieved from WDF.
    HandlerProfile - Profile bit implied by the IOCTL handler.
    Context - Normalized request context returned to the handler.

Return Value:

    STATUS_SUCCESS on a usable request; STATUS_INVALID_PARAMETER when version,
    size, profile, or target string validation fails.

--*/
{
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(*Context));
    Context->Request.size = sizeof(Context->Request);
    Context->Request.version = KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION;
    Context->EffectiveProfile = HandlerProfile;
    Context->MaxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS;
    Context->MaxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH;

    if (UserRequest != NULL) {
        RtlCopyMemory(&Context->Request, UserRequest, sizeof(Context->Request));
        if (Context->Request.size < sizeof(Context->Request)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (Context->Request.version != KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION) {
            return STATUS_REVISION_MISMATCH;
        }
        Context->EffectiveProfile = KswDeviceAuditKnownProfileForHandler(HandlerProfile, Context->Request.profileFlags);
        if (Context->EffectiveProfile == 0UL) {
            return STATUS_INVALID_PARAMETER;
        }
        Context->MaxRows = KswDeviceAuditNormalizeMaxRows(Context->Request.maxRows);
        Context->MaxAttachedDepth = KswDeviceAuditNormalizeAttachedDepth(Context->Request.maxAttachedDepth);
        Context->HasSingleTarget = KswDeviceAuditStringPresent(Context->Request.targetName, RTL_NUMBER_OF(Context->Request.targetName));
        if (Context->Request.targetName[RTL_NUMBER_OF(Context->Request.targetName) - 1UL] != L'\0') {
            return STATUS_INVALID_PARAMETER;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswDeviceAuditExecute(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned,
    _In_ ULONG HandlerProfile,
    _In_z_ PCSTR LogName
    )
/*++

Routine Description:

    Shared implementation for the four read-only audit IOCTL handlers.  The
    routine validates buffers, normalizes the optional request, runs either a
    caller-specified target or the handler's static target list, and finalizes
    the response byte count.

Arguments:

    Device - WDF device used only for logging.
    Request - Current IOCTL request.
    InputBufferLength - Caller input byte count.
    OutputBufferLength - Caller output byte count; WDF performs concrete buffer validation.
    BytesReturned - Receives the number of bytes written to the output buffer.
    HandlerProfile - Profile bit represented by the public IOCTL.
    Targets - Static fallback target list for this handler.
    TargetCount - Number of entries in Targets.
    LogName - Short ANSI name used in diagnostic logs.

Return Value:

    STATUS_SUCCESS when a syntactically valid response is returned, even if the
    response contains per-target partial/not-found diagnostics.  Buffer or
    request validation failures are returned directly.

--*/
{
    const KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST* userRequest = NULL;
    KSW_DEVICE_AUDIT_REQUEST_CONTEXT context;
    KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE* response = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    ULONG capacity = 0UL;
    const KSW_DEVICE_AUDIT_TARGET* targets = NULL;
    ULONG targetCount = 0UL;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswDeviceAuditLog(Device, "Error", "%s input invalid: 0x%08X.", LogName, (unsigned int)status);
        return status;
    }
    UNREFERENCED_PARAMETER(actualInputLength);
    userRequest = hasInput ? (const KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST*)inputBuffer : NULL;

    if (HandlerProfile == KSWORD_ARK_DEVICE_AUDIT_PROFILE_DEVICE_STACK) {
        targets = g_KswDeviceAuditDeviceTargets;
        targetCount = g_KswDeviceAuditDeviceTargetCount;
    }
    else if (HandlerProfile == KSWORD_ARK_DEVICE_AUDIT_PROFILE_INPUT_STACK) {
        targets = g_KswDeviceAuditInputTargets;
        targetCount = g_KswDeviceAuditInputTargetCount;
    }
    else if (HandlerProfile == KSWORD_ARK_DEVICE_AUDIT_PROFILE_USB_TOPOLOGY) {
        targets = g_KswDeviceAuditUsbTargets;
        targetCount = g_KswDeviceAuditUsbTargetCount;
    }
    else if (HandlerProfile == KSWORD_ARK_DEVICE_AUDIT_PROFILE_GPU_DISPLAY_WATCHDOG) {
        targets = g_KswDeviceAuditGpuTargets;
        targetCount = g_KswDeviceAuditGpuTargetCount;
    }
    else {
        return STATUS_INVALID_PARAMETER;
    }

    status = KswDeviceAuditCaptureRequest(userRequest, HandlerProfile, &context);
    if (!NT_SUCCESS(status)) {
        KswDeviceAuditLog(Device, "Error", "%s request invalid: 0x%08X.", LogName, (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSW_DEVICE_AUDIT_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswDeviceAuditLog(Device, "Error", "%s output invalid: 0x%08X.", LogName, (unsigned int)status);
        return status;
    }

    capacity = KswDeviceAuditOutputCapacity(actualOutputLength);
    KswDeviceAuditZeroResponse(outputBuffer, actualOutputLength, context.EffectiveProfile);
    response = (KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE*)outputBuffer;

    if (context.HasSingleTarget) {
        status = KswDeviceAuditQueryOneTarget(
            response,
            capacity,
            &context,
            context.Request.targetName,
            context.EffectiveProfile,
            KSWORD_ARK_DEVICE_AUDIT_ROLE_UNKNOWN);
        response->targetCount += 1UL;
        if (!NT_SUCCESS(status)) {
            KswDeviceAuditSetResponsePartial(response, status);
        }
    }
    else {
        status = KswDeviceAuditQueryTargets(response, capacity, &context, targets, targetCount, HandlerProfile);
        if (!NT_SUCCESS(status)) {
            KswDeviceAuditSetResponsePartial(response, status);
        }
    }

    if (response->totalCount == 0UL) {
        response->responseFlags |= KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_EMPTY;
        response->queryStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_NOT_FOUND;
    }
    if ((response->responseFlags & KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_TRUNCATED) != 0UL) {
        response->queryStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_PARTIAL;
    }

    *BytesReturned = KSW_DEVICE_AUDIT_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_DEVICE_AUDIT_ENTRY));
    KswDeviceAuditLog(
        Device,
        (response->queryStatus == KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED) ? "Warn" : "Info",
        "%s completed: q=%lu flags=0x%08lX total=%lu returned=%lu devices=%lu targets=%lu bytes=%Iu.",
        LogName,
        response->queryStatus,
        response->responseFlags,
        response->totalCount,
        response->returnedCount,
        response->deviceCount,
        response->targetCount,
        *BytesReturned);
    return STATUS_SUCCESS;
}
