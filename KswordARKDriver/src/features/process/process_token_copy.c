// NTIFS supplies primary-token object references and security information queries.
#include "process_token_copy.h"
// Reuse the current kernel's DynData offsets and provenance.
#include "ark/ark_driver.h"
// Candidate private fields are read through the shared safe-memory reader.
#include "../../platform/runtime_signature_scan.h"

// Match the existing driver modules' declarations for process rundown protection.
NTKERNELAPI NTSTATUS NTAPI PsAcquireProcessExitSynchronization(_In_ PEPROCESS Process);
// Release exactly one successful process rundown acquisition.
NTKERNELAPI VOID NTAPI PsReleaseProcessExitSynchronization(_In_ PEPROCESS Process);

// A pointer-sized fast reference stores cached reference credits in its low bits.
#ifdef _WIN64
#define KSW_TOKEN_FAST_MASK ((ULONG_PTR)0xFUL)
#else
#define KSW_TOKEN_FAST_MASK ((ULONG_PTR)0x7UL)
#endif

// Accept the same token-offset provenance as the existing private integrity path.
static BOOLEAN KswTokenOffsetTrusted(_In_ ULONG Offset, _In_ ULONG Source)
{
    // Require an aligned in-object field with an identified, current-kernel source.
    return Offset != 0UL && Offset != KSW_DYN_OFFSET_UNAVAILABLE && Offset < 0x3000UL &&
        (Offset % sizeof(ULONG_PTR)) == 0UL &&
        (Source == KSW_DYN_FIELD_SOURCE_PDB_PROFILE || Source == KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN);
}

// Obtain a diagnostic TokenId from an already referenced token, without opening handles.
static NTSTATUS KswTokenId(_In_ PACCESS_TOKEN Token, _Out_ ULONGLONG* Id)
{
    // The security manager allocates the returned statistics record.
    TOKEN_STATISTICS* statistics = NULL;
    // Query does not duplicate or assign a token.
    NTSTATUS status = SeQueryInformationToken(Token, TokenStatistics, (PVOID*)&statistics);
    // Never consume an absent record as a successful observation.
    if (NT_SUCCESS(status) && statistics == NULL) {
        // Keep malformed observations distinct from zero-valued identities.
        return STATUS_DATA_ERROR;
    }
    // Publish an identity only after the security query succeeds.
    if (NT_SUCCESS(status)) {
        // Preserve the unsigned bit pattern of both halves of the LUID.
        *Id = ((ULONGLONG)(ULONG)statistics->TokenId.HighPart << 32) | statistics->TokenId.LowPart;
    }
    // The returned allocation belongs to this query caller.
    if (statistics != NULL) { ExFreePool(statistics); }
    // Preserve the security manager's failure status.
    return status;
}

// Reference one exact process and prevent its token teardown until cleanup.
static NTSTATUS KswTokenProcess(_In_ ULONG Pid, _In_ ULONGLONG Expected,
    _Out_ PEPROCESS* Process, _Out_ BOOLEAN* Protected, _Out_ ULONGLONG* Actual)
{
    // Resolve once so subsequent work cannot follow a reused PID.
    NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(Pid), Process);
    // Lookup failure owns no process reference.
    if (!NT_SUCCESS(status)) { return status; }
    // Freeze the creation identity on the referenced object.
    *Actual = (ULONGLONG)PsGetProcessCreateTimeQuadPart(*Process);
    // Reject a different process instance before acquiring its token.
    if (*Actual != Expected) { return STATUS_INVALID_CID; }
    // Rundown protection prevents process exit from deassigning its primary token.
    status = PsAcquireProcessExitSynchronization(*Process);
    // Record ownership so cleanup never releases an unacquired protection.
    *Protected = NT_SUCCESS(status) ? TRUE : FALSE;
    // Preserve the actual exit-synchronization failure.
    return status;
}

// Validate the private fast-reference field against a live, referenced token object.
static NTSTATUS KswTokenReadField(_In_ PEPROCESS Process, _In_ ULONG Offset,
    _In_ PACCESS_TOKEN Token, _Out_ ULONG_PTR* Value)
{
    // The candidate offset must be read without faulting on an invalid kernel address.
    NTSTATUS status = KswordARKRuntimeReadMemory((UCHAR*)Process + Offset, Value, sizeof(*Value))
        ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
    // Reject a different object rather than trusting only profile provenance.
    if (NT_SUCCESS(status) && (*Value & ~KSW_TOKEN_FAST_MASK) != (ULONG_PTR)Token) {
        // A concurrent replacement or incorrect layout must prevent writing.
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    // Return the safe-reader or object-comparison result.
    return status;
}

// Replace the EPROCESS.Token fast reference directly, without native token assignment.
NTSTATUS KswordARKProcessCopyToken(
    _In_ const KSWORD_ARK_COPY_PROCESS_TOKEN_REQUEST* Request,
    _Inout_ KSWORD_ARK_COPY_PROCESS_TOKEN_RESPONSE* Response)
{
    // Capture one consistent set of private offsets and their sources.
    KSW_DYN_STATE dyn;
    // Process references and rundown protections have independent ownership.
    PEPROCESS sourceProcess = NULL, targetProcess = NULL;
    // Both token snapshots retain real object references throughout the replacement.
    PACCESS_TOKEN sourceToken = NULL, beforeToken = NULL, afterToken = NULL;
    // This extra reference becomes the target field's ownership after a successful swap.
    BOOLEAN transferReference = FALSE;
    // Exit synchronization is released only when acquired successfully.
    BOOLEAN sourceProtected = FALSE, targetProtected = FALSE;
    // Validate both source and target fast-reference fields before a write.
    ULONG_PTR sourceValue = 0U, targetValue = 0U, displaced = 0U;
    // The process security lock serializes the replacement with slow token readers.
    EX_PUSH_LOCK* processLock = NULL;
    // CAS retries tolerate ordinary changes to the target's cached reference credits.
    ULONG attempt = 0UL, references = 0UL;
    // All failures converge on the same ownership-aware cleanup.
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    // Validate internal callers as well as the public IOCTL handler.
    if (Request->size != sizeof(*Request) || Request->version != KSWORD_ARK_PROCESS_TOKEN_COPY_VERSION ||
        Request->flags != KSWORD_ARK_PROCESS_TOKEN_COPY_CONFIRMED || Request->reserved != 0UL ||
        Request->sourceProcessId == 0UL || Request->targetProcessId <= 4UL ||
        Request->sourceProcessId == Request->targetProcessId ||
        Request->expectedSourceCreateTime100ns == 0ULL || Request->expectedTargetCreateTime100ns == 0ULL) {
        // No private memory is touched for an incomplete request.
        goto Cleanup;
    }
    // Token queries and process locks require a passive caller.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        // Do not acquire pageable process state at elevated IRQL.
        status = STATUS_INVALID_DEVICE_STATE;
        // Publish the refusal through normal cleanup.
        goto Cleanup;
    }
    // Initialize the DynData snapshot before reading its readiness and provenance.
    RtlZeroMemory(&dyn, sizeof(dyn));
    // Reuse the same offset source as the existing private integrity implementation.
    KswordARKDynDataSnapshot(&dyn);
    // A writable token field and the real process lock must both be identified.
    if (!KswTokenOffsetTrusted(dyn.Kernel.EpToken, dyn.KernelSources.EpToken) ||
        !KswTokenOffsetTrusted(dyn.Kernel.EpProcessLock, dyn.KernelSources.EpProcessLock) ||
        dyn.KernelSources.EpProcessLock != KSW_DYN_FIELD_SOURCE_PDB_PROFILE ||
        dyn.Kernel.EpToken == dyn.Kernel.EpProcessLock) {
        // Never use a guessed process-lock address for a token replacement.
        status = STATUS_NOT_SUPPORTED;
        // No token reference or write has occurred.
        goto Cleanup;
    }
    // Retain and validate the source before capturing its token snapshot.
    status = KswTokenProcess(Request->sourceProcessId, Request->expectedSourceCreateTime100ns,
        &sourceProcess, &sourceProtected, &Response->sourceCreateTime100ns);
    // Release partial ownership through the shared cleanup path.
    if (!NT_SUCCESS(status)) { goto Cleanup; }
    // Report that the kernel validated the selected source instance.
    Response->fieldFlags |= KSWORD_ARK_PROCESS_TOKEN_COPY_SOURCE_IDENTITY;
    // Retain and validate the target before reading its private token field.
    status = KswTokenProcess(Request->targetProcessId, Request->expectedTargetCreateTime100ns,
        &targetProcess, &targetProtected, &Response->targetCreateTime100ns);
    // A stale or exiting target must never receive a token write.
    if (!NT_SUCCESS(status)) { goto Cleanup; }
    // Report that the kernel validated the selected target instance.
    Response->fieldFlags |= KSWORD_ARK_PROCESS_TOKEN_COPY_TARGET_IDENTITY;
    // Take a stable source token reference; this does not duplicate the token object.
    sourceToken = PsReferencePrimaryToken(sourceProcess);
    // Retain the original target token until displaced fast-reference credits are retired.
    beforeToken = PsReferencePrimaryToken(targetProcess);
    // Refuse absent primary-token state before accessing private fields.
    if (sourceToken == NULL || beforeToken == NULL) {
        // Preserve a distinct missing-object diagnostic.
        status = STATUS_NOT_FOUND;
        // No field has been changed.
        goto Cleanup;
    }
    // Cross-check the profile offset against the real source token object.
    status = KswTokenReadField(sourceProcess, dyn.Kernel.EpToken, sourceToken, &sourceValue);
    // A wrong or concurrently changed source field prevents replacement.
    if (!NT_SUCCESS(status)) { goto Cleanup; }
    // Cross-check the target field before constructing its writable slot.
    status = KswTokenReadField(targetProcess, dyn.Kernel.EpToken, beforeToken, &targetValue);
    // Never write through an offset that failed the object comparison.
    if (!NT_SUCCESS(status)) { goto Cleanup; }
    // Capture the source identity for both the receipt and the final readback comparison.
    status = KswTokenId(sourceToken, &Response->sourceTokenId);
    // Diagnostic failure is resolved before any side effect.
    if (!NT_SUCCESS(status)) { goto Cleanup; }
    // Mark the source token identity as observed.
    Response->fieldFlags |= KSWORD_ARK_PROCESS_TOKEN_COPY_SOURCE_TOKEN;
    // Capture the original target token identity.
    status = KswTokenId(beforeToken, &Response->targetTokenIdBefore);
    // No write occurs unless the baseline can be returned.
    if (!NT_SUCCESS(status)) { goto Cleanup; }
    // Mark the baseline token identity as observed.
    Response->fieldFlags |= KSWORD_ARK_PROCESS_TOKEN_COPY_BEFORE_TOKEN;
    // This field now identifies the assigned shared token, not a duplicated token object.
    Response->assignedTokenId = Response->sourceTokenId;
    // Record availability of the token selected for assignment.
    Response->fieldFlags |= KSWORD_ARK_PROCESS_TOKEN_COPY_ASSIGNED_TOKEN;
    // Reserve one reference for the target field; its cached-credit bits start at zero.
    ObReferenceObject(sourceToken);
    // Retain ownership until a successful CAS transfers this reference into EPROCESS.Token.
    transferReference = TRUE;
    // Use only the identified target process lock; source capture needs no private lock.
    processLock = (EX_PUSH_LOCK*)((UCHAR*)targetProcess + dyn.Kernel.EpProcessLock);
    // Push locks require normal kernel APC delivery to remain disabled while held.
    KeEnterCriticalRegion();
    // Drain preexisting slow readers before replacing the fast-reference owner.
    ExAcquirePushLockExclusive(processLock);
    // Record that the actual assignment stage was reached.
    Response->fieldFlags |= KSWORD_ARK_PROCESS_TOKEN_COPY_ASSIGN_ATTEMPTED;
    // Exhausting retries reports a concurrent-state failure rather than spinning forever.
    status = STATUS_RETRY;
    // Fast readers may consume or replenish low-bit reference credits between comparisons.
    for (attempt = 0UL; attempt < 64UL; ++attempt) {
        // Check the full current word using the safe-reader path before the atomic write.
        status = KswTokenReadField(targetProcess, dyn.Kernel.EpToken, beforeToken, &targetValue);
        // An object change or invalid field ends the operation without overwriting it.
        if (!NT_SUCCESS(status)) { break; }
        // Publish only a referenced object pointer, never the source field's cached credits.
        displaced = (ULONG_PTR)InterlockedCompareExchangePointer(
            (PVOID volatile*)((UCHAR*)targetProcess + dyn.Kernel.EpToken), (PVOID)sourceToken, (PVOID)targetValue);
        // Only the exact compared word transfers ownership to the target field.
        if (displaced == targetValue) {
            // The field now owns the extra source-token reference.
            transferReference = FALSE;
            // Mutation succeeded independently of subsequent readback.
            Response->fieldFlags |= KSWORD_ARK_PROCESS_TOKEN_COPY_APPLIED;
            // Retire the old field owner's reference plus its unused cached reference credits.
            references = (ULONG)(displaced & KSW_TOKEN_FAST_MASK) + 1UL;
            // Stop once one atomic replacement has succeeded.
            status = STATUS_SUCCESS;
            // Never apply the same operation twice.
            break;
        }
        // A changed credit count can be retried without changing object ownership.
        status = STATUS_RETRY;
    }
    // Release the real process lock before dereferencing objects or querying token metadata.
    ExReleasePushLockExclusive(processLock);
    // Restore APC delivery after all private process-lock work completes.
    KeLeaveCriticalRegion();
    // Preserve assignment status separately from the final verification status.
    Response->assignStatus = status;
    // The original token remains held by beforeToken while its displaced credits are retired.
    while (references != 0UL) {
        // Each credit represented a real reference owned by the old fast-reference word.
        ObDereferenceObject(beforeToken);
        // Consume only the references captured by the successful atomic exchange.
        --references;
    }
    // Assignment rejection must not be masked by observing the old token afterwards.
    if (!NT_SUCCESS(status)) { goto Cleanup; }
    // Observe the current primary token through a fresh, lifetime-safe object reference.
    afterToken = PsReferencePrimaryToken(targetProcess);
    // A missing post-operation token leaves an applied but unverified receipt.
    status = afterToken != NULL ? KswTokenId(afterToken, &Response->targetTokenIdAfter) : STATUS_NOT_FOUND;
    // Publish successful observation independently of equality.
    if (NT_SUCCESS(status)) {
        // The after-token identifier was read successfully.
        Response->fieldFlags |= KSWORD_ARK_PROCESS_TOKEN_COPY_AFTER_TOKEN;
        // Verify both the object instance and its diagnostic token identity.
        if (afterToken != sourceToken || Response->targetTokenIdAfter != Response->sourceTokenId) {
            // Concurrent replacement must not be declared a verified copy.
            status = STATUS_UNSUCCESSFUL;
        }
    }
    // Keep readback failure distinguishable from assignment failure.
    Response->verifyStatus = status;
    // Only exact source/target equality proves the requested shared token was observed.
    if (NT_SUCCESS(status)) { Response->fieldFlags |= KSWORD_ARK_PROCESS_TOKEN_COPY_VERIFIED; }

Cleanup:
    // Failed CAS leaves the reserved target-field reference owned by this function.
    if (transferReference) { ObDereferenceObject(sourceToken); }
    // Release the final observation independently of the target's field ownership.
    if (afterToken != NULL) { PsDereferencePrimaryToken(afterToken); }
    // Release the original target snapshot after retiring its old field credits.
    if (beforeToken != NULL) { PsDereferencePrimaryToken(beforeToken); }
    // Release the source snapshot; the target retains its separate reference after success.
    if (sourceToken != NULL) { PsDereferencePrimaryToken(sourceToken); }
    // Allow target token teardown only after replacement and readback have completed.
    if (targetProtected) { PsReleaseProcessExitSynchronization(targetProcess); }
    // Release the source exit protection acquired during identity capture.
    if (sourceProtected) { PsReleaseProcessExitSynchronization(sourceProcess); }
    // Drop the explicit target process lookup reference.
    if (targetProcess != NULL) { ObDereferenceObject(targetProcess); }
    // Drop the explicit source process lookup reference.
    if (sourceProcess != NULL) { ObDereferenceObject(sourceProcess); }
    // Publish final operation status independently of IOCTL transport success.
    Response->lastStatus = status;
    // Internal callers receive the same operation status as the public receipt.
    return status;
}
