// Token object declarations precede the common driver header.
#include "process_token_copy.h"
// Reuse the centralized safety policy and WDF device definitions.
#include "ark/ark_driver.h"
// Keep buffer and access validation in the existing shared dispatch helpers.
#include "../../dispatch/ioctl_validation.h"

// Handle one explicitly confirmed primary-token copy with a fixed-size receipt.
NTSTATUS KswordARKProcessIoctlCopyToken(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned)
{
    // Snapshot METHOD_BUFFERED input before initializing its aliased output storage.
    KSWORD_ARK_COPY_PROCESS_TOKEN_REQUEST snapshot;
    // Output contains statuses and token identities, never kernel addresses or handles.
    KSWORD_ARK_COPY_PROCESS_TOKEN_RESPONSE* response = NULL;
    // Use the existing process-token mutation safety policy.
    KSWORD_ARK_SAFETY_CONTEXT safety = { 0 };
    // WDF retrieves the real buffer lengths independently of declared protocol sizes.
    PVOID input = NULL, output = NULL;
    // Keep input and output sizes separate because their buffers can alias.
    size_t inputLength = 0U, outputLength = 0U;
    // Transport errors are separate from operation statuses inside the response.
    NTSTATUS status = STATUS_SUCCESS;

    // A completion byte count is mandatory for this synchronous handler.
    if (BytesReturned == NULL) {
        // Do not dereference a missing completion output.
        return STATUS_INVALID_PARAMETER;
    }
    // All transport-failure paths return no response bytes.
    *BytesReturned = 0U;
    // Reject truncated declared buffers before any side effect.
    if (InputBufferLength < sizeof(snapshot) || OutputBufferLength < sizeof(*response)) {
        // The caller can allocate the exact shared protocol sizes and retry explicitly.
        return STATUS_BUFFER_TOO_SMALL;
    }
    // Enforce device write access in addition to the IOCTL's access bits.
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    // Do not inspect or mutate tokens for a read-only device handle.
    if (!NT_SUCCESS(status)) {
        // Preserve the access-check result as a transport failure.
        return status;
    }
    // Retrieve the shared fixed-size request.
    status = KswordARKRetrieveRequiredInputBuffer(Request, sizeof(snapshot), &input, &inputLength);
    // Failed input retrieval must not produce a synthetic operation receipt.
    if (!NT_SUCCESS(status)) {
        // Leave the byte count at zero.
        return status;
    }
    // The output buffer may point to this same METHOD_BUFFERED allocation.
    RtlCopyMemory(&snapshot, input, sizeof(snapshot));
    // Retrieve all output storage before the operation can change a token.
    status = KswordARKRetrieveRequiredOutputBuffer(Request, sizeof(*response), &output, &outputLength);
    // Avoid applying a mutation when its receipt cannot be returned.
    if (!NT_SUCCESS(status)) {
        // Report only the WDF failure.
        return status;
    }
    // Interpret the validated output allocation using the unique shared ABI.
    response = (KSWORD_ARK_COPY_PROCESS_TOKEN_RESPONSE*)output;
    // Clear all observation bits and identity fields before validation.
    RtlZeroMemory(response, sizeof(*response));
    // Publish the exact supported response size.
    response->size = sizeof(*response);
    // Publish the response ABI independently of the untrusted request version.
    response->version = KSWORD_ARK_PROCESS_TOKEN_COPY_VERSION;
    // Echo the source selection for response correlation.
    response->sourceProcessId = snapshot.sourceProcessId;
    // Echo the target selection for response correlation.
    response->targetProcessId = snapshot.targetProcessId;
    // Invalid requests have no implied success status.
    response->lastStatus = STATUS_INVALID_PARAMETER;
    // Assignment has not yet been attempted.
    response->assignStatus = STATUS_NOT_SUPPORTED;
    // Readback has not yet been attempted.
    response->verifyStatus = STATUS_NOT_SUPPORTED;
    // From this point semantic failures return a complete operation receipt.
    *BytesReturned = sizeof(*response);
    // Require exact protocol, confirmation, reserved fields and both process identities.
    if (snapshot.size != sizeof(snapshot) || snapshot.version != KSWORD_ARK_PROCESS_TOKEN_COPY_VERSION ||
        snapshot.flags != KSWORD_ARK_PROCESS_TOKEN_COPY_CONFIRMED || snapshot.reserved != 0UL ||
        snapshot.sourceProcessId == 0UL || snapshot.targetProcessId <= 4UL ||
        snapshot.sourceProcessId == snapshot.targetProcessId ||
        snapshot.expectedSourceCreateTime100ns == 0ULL || snapshot.expectedTargetCreateTime100ns == 0ULL) {
        // No backend operation runs with an incomplete identity or unknown flags.
        return STATUS_SUCCESS;
    }
    // Reuse the existing safety classification for primary-token privilege mutations.
    safety.Operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_SET_PROTECTION;
    // The target is the only process whose primary token is modified.
    safety.TargetProcessId = snapshot.targetProcessId;
    // Confirmation remains subject to the central safety policy.
    safety.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
    // Preserve existing global policy rather than inventing a second mutation gate.
    status = KswordARKSafetyEvaluate(Device, &safety);
    // Policy rejection is an operation failure with a valid receipt.
    if (!NT_SUCCESS(status)) {
        // Preserve the actual policy result for CLI diagnostics.
        response->lastStatus = status;
        // Transport completed successfully even though the mutation was rejected.
        return STATUS_SUCCESS;
    }
    // The backend owns field replacement, readback and complete object-reference cleanup.
    (void)KswordARKProcessCopyToken(&snapshot, response);
    // Replacement failure is represented in lastStatus, never hidden as operation success.
    return STATUS_SUCCESS;
}
