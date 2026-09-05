/*++

Module Name:

    hvm_ioctl.c

Abstract:

    WDF adapters for HVM capability queries and safety-gated lifecycle control.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_runtime.h"
#include "hvm_cr_policy.h"
#include "hvm_ept_view.h"
#include "hvm_memory.h"
#include "hvm_msr_policy.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

/* Tag the bounded request snapshot the shared SystemBuffer forces us to keep. */
#define KSWORD_ARK_HVM_MEMORY_IOCTL_POOL_TAG 'IvHK'
/* Tag the view request snapshot, which carries a full shadow page. */
#define KSWORD_ARK_HVM_VIEW_IOCTL_POOL_TAG 'VvHK'

NTSTATUS
KswordARKHvmIoctlQuery(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    const KSWORD_ARK_QUERY_HVM_REQUEST* queryRequest = NULL;

    /* The dispatcher requires an explicit completion size on every path. */
    UNREFERENCED_PARAMETER(Device);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    /* Retrieve and validate the versioned fixed query request. */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_HVM_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        InputBufferLength < sizeof(KSWORD_ARK_QUERY_HVM_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_QUERY_HVM_REQUEST)) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    queryRequest = (const KSWORD_ARK_QUERY_HVM_REQUEST*)inputBuffer;
    if (queryRequest->version != KSWORD_ARK_HVM_PROTOCOL_VERSION ||
        queryRequest->size != sizeof(*queryRequest)) {
        return STATUS_REVISION_MISMATCH;
    }
    /* Reject unknown query flags and reserved fields in this protocol version. */
    if (queryRequest->flags != 0UL ||
        queryRequest->reserved != 0UL) {
        /* Return the exact fixed-field contract failure. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Retrieve the complete fixed status response. */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_HVM_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        OutputBufferLength < sizeof(KSWORD_ARK_QUERY_HVM_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_QUERY_HVM_RESPONSE)) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }

    /* Snapshot the backend without changing VMX or EPT state. */
    status = KswordARKHvmQuery(
        (KSWORD_ARK_QUERY_HVM_RESPONSE*)outputBuffer);
    if (NT_SUCCESS(status)) {
        *BytesReturned = sizeof(KSWORD_ARK_QUERY_HVM_RESPONSE);
    }
    return status;
}

NTSTATUS
KswordARKHvmIoctlControl(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    KSWORD_ARK_CONTROL_HVM_REQUEST controlRequestSnapshot = { 0 };
    const KSWORD_ARK_CONTROL_HVM_REQUEST* controlRequest = NULL;
    KSWORD_ARK_CONTROL_HVM_RESPONSE* controlResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    /* Lifecycle mutations require a write-authorized device handle. */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Retrieve both fixed protocol buffers before evaluating policy. */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_CONTROL_HVM_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        InputBufferLength < sizeof(KSWORD_ARK_CONTROL_HVM_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_CONTROL_HVM_REQUEST)) {
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /* Preserve METHOD_BUFFERED input before output retrieval exposes the same system buffer. */
    RtlCopyMemory(
        &controlRequestSnapshot,
        inputBuffer,
        sizeof(controlRequestSnapshot));
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_CONTROL_HVM_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        OutputBufferLength < sizeof(KSWORD_ARK_CONTROL_HVM_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_CONTROL_HVM_RESPONSE)) {
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    controlRequest = &controlRequestSnapshot;
    controlResponse =
        (KSWORD_ARK_CONTROL_HVM_RESPONSE*)outputBuffer;

    /*
     * Preparing VMX pages is reversible allocation work.  VMX transitions and
     * guest entry both receive the central critical kernel-patch policy gate.
     */
    if (controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_SELF_TEST ||
        controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST ||
        controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_START_RESIDENT ||
        controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED ||
        controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_RESET_FAULT) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext = { 0 };

        /* Bind policy auditing to the exact high-risk operation class. */
        safetyContext.Operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.ContextFlags =
            (controlRequest->flags &
                KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe the exact privileged transition in the central audit gate. */
        if (controlRequest->command ==
                KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST) {
            safetyContext.TargetText =
                L"One-shot VT-x VMLAUNCH and VMCALL VM-exit test";
            safetyContext.TargetTextChars =
                (USHORT)(RTL_NUMBER_OF(
                    L"One-shot VT-x VMLAUNCH and VMCALL VM-exit test") - 1U);
        } else if (controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_SELF_TEST) {
            safetyContext.TargetText =
                L"Per-processor VT-x VMXON and VMXOFF self-test";
            safetyContext.TargetTextChars =
                (USHORT)(RTL_NUMBER_OF(
                    L"Per-processor VT-x VMXON and VMXOFF self-test") - 1U);
        } else if (controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_START_RESIDENT) {
            /* Describe all-processor resident VMX entry and rollback. */
            safetyContext.TargetText =
                L"Resident all-processor VT-x VMM and EPT activation";
            /* Publish the exact bounded target text length. */
            safetyContext.TargetTextChars =
                (USHORT)(RTL_NUMBER_OF(
                    L"Resident all-processor VT-x VMM and EPT activation") -
                    1U);
        } else if (controlRequest->command ==
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED) {
            /* Describe partial nested-VMX and eVMCS validation explicitly. */
            safetyContext.TargetText =
                L"Partial nested VMX dispatch and Hyper-V eVMCS validation";
            /* Publish the exact bounded target text length. */
            safetyContext.TargetTextChars =
                (USHORT)(RTL_NUMBER_OF(
                    L"Partial nested VMX dispatch and Hyper-V eVMCS validation") -
                    1U);
        } else {
            /* Describe recoverable HVM fault-state reset explicitly. */
            safetyContext.TargetText =
                L"Reset stopped HVM fault and rollback state";
            /* Publish the exact bounded target text length. */
            safetyContext.TargetTextChars =
                (USHORT)(RTL_NUMBER_OF(
                    L"Reset stopped HVM fault and rollback state") - 1U);
        }
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            RtlZeroMemory(controlResponse, sizeof(*controlResponse));
            controlResponse->version =
                KSWORD_ARK_HVM_PROTOCOL_VERSION;
            controlResponse->size = sizeof(*controlResponse);
            controlResponse->status =
                KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED;
            controlResponse->lastStatus = status;
            *BytesReturned = sizeof(*controlResponse);
            return status;
        }
    }

    /* Execute the versioned lifecycle command and return its stable summary. */
    status = KswordARKHvmControl(controlRequest, controlResponse);
    *BytesReturned = sizeof(*controlResponse);
    return status;
}

NTSTATUS
KswordARKHvmIoctlEptRule(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    const KSWORD_ARK_HVM_EPT_RULE_REQUEST* ruleRequest = NULL;
    /* requestSnapshot 在运行时清零共用 SystemBuffer 前保存完整请求。 */
    KSWORD_ARK_HVM_EPT_RULE_REQUEST requestSnapshot;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE* ruleResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (BytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Initialize the completion size on every path. */
    *BytesReturned = 0U;
    /* EPT rule control requires a write-authorized device handle. */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    /* Stop before buffer access when handle authorization fails. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact authorization failure. */
        return status;
    }
    /* Retrieve the complete fixed EPT rule request. */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_HVM_EPT_RULE_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        InputBufferLength <
            sizeof(KSWORD_ARK_HVM_EPT_RULE_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_HVM_EPT_RULE_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /* Retrieve the complete fixed EPT rule response. */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_HVM_EPT_RULE_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        OutputBufferLength <
            sizeof(KSWORD_ARK_HVM_EPT_RULE_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_HVM_EPT_RULE_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /*
     * METHOD_BUFFERED 的输入和输出是同一个 SystemBuffer；KswordARKHvmEptRuleControl
     * 会先 RtlZeroMemory 响应再读 operation/GPA/权限位，不做快照就会按响应头
     * 字节去改一条完全不相干的 EPT 规则。
     */
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    /* Bind fixed protocol views after both buffers are validated. */
    ruleRequest = &requestSnapshot;
    /* Bind the fixed protocol output view. */
    ruleResponse =
        (KSWORD_ARK_HVM_EPT_RULE_RESPONSE*)outputBuffer;
    /* Apply central high-risk policy to every mutating EPT rule operation. */
    if (ruleRequest->operation !=
        KSWORD_ARK_HVM_EPT_RULE_QUERY) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext = { 0 };

        /* Bind policy auditing to the kernel-patch operation class. */
        safetyContext.Operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* Preserve explicit UI confirmation in central policy evidence. */
        safetyContext.ContextFlags =
            (ruleRequest->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe the exact EPT permission mutation class. */
        safetyContext.TargetText =
            L"Resident EPT R/W/X rule and cross-processor invalidation";
        /* Publish the exact bounded target text length. */
        safetyContext.TargetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"Resident EPT R/W/X rule and cross-processor invalidation") -
                1U);
        /* Evaluate central policy without weakening protocol confirmation. */
        status = KswordARKSafetyEvaluate(
            Device,
            &safetyContext);
        /* Return a complete confirmation-required response on denial. */
        if (!NT_SUCCESS(status)) {
            /* Initialize the complete fixed response. */
            RtlZeroMemory(
                ruleResponse,
                sizeof(*ruleResponse));
            /* Publish the response protocol identity. */
            ruleResponse->version =
                KSWORD_ARK_HVM_PROTOCOL_VERSION;
            /* Publish the complete response size. */
            ruleResponse->size =
                sizeof(*ruleResponse);
            /* Publish stable confirmation-required status. */
            ruleResponse->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_CONFIRMATION_REQUIRED;
            /* Publish the authoritative policy failure. */
            ruleResponse->lastStatus = status;
            /* Publish the fixed completion size. */
            *BytesReturned =
                sizeof(*ruleResponse);
            /* Return the authoritative policy failure. */
            return status;
        }
    }
    /* Execute the serialized EPT rule operation. */
    status = KswordARKHvmEptRuleControl(
        ruleRequest,
        ruleResponse);
    /* Publish the fixed completion size on protocol-level results. */
    *BytesReturned = sizeof(*ruleResponse);
    /* Return the complete EPT rule operation result. */
    return status;
}

NTSTATUS
KswordARKHvmIoctlEvents(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    const KSWORD_ARK_HVM_EVENT_QUERY_REQUEST* eventRequest = NULL;

    /* Event queries do not use the device object directly. */
    UNREFERENCED_PARAMETER(Device);
    /* Reject an invalid completion contract before touching request buffers. */
    if (BytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Initialize the completion size on every path. */
    *BytesReturned = 0U;
    /* Retrieve the complete fixed event query request. */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_HVM_EVENT_QUERY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        InputBufferLength <
            sizeof(KSWORD_ARK_HVM_EVENT_QUERY_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_HVM_EVENT_QUERY_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /* Bind the fixed protocol request after length validation. */
    eventRequest =
        (const KSWORD_ARK_HVM_EVENT_QUERY_REQUEST*)inputBuffer;
    /* Require write authorization before clearing retained events. */
    if (eventRequest->operation ==
        KSWORD_ARK_HVM_EVENT_QUERY_CLEAR) {
        /* Validate write access on the current device handle. */
        status = KswordARKValidateDeviceIoControlWriteAccess(
            Request);
        /* Stop before response access when authorization fails. */
        if (!NT_SUCCESS(status)) {
            /* Return the exact authorization failure. */
            return status;
        }
    }
    /* Retrieve the complete fixed event query response. */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        OutputBufferLength <
            sizeof(KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /* Execute the read or stopped clear operation. */
    status = KswordARKHvmEventControl(
        eventRequest,
        (KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE*)outputBuffer);
    /* Publish the fixed completion size only on success. */
    if (NT_SUCCESS(status)) {
        /* Publish the complete fixed response size. */
        *BytesReturned =
            sizeof(KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE);
    }
    /* Return the complete event operation result. */
    return status;
}

NTSTATUS
KswordARKHvmIoctlMemory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /*
     * The request carries a full payload page, which is too large to snapshot
     * on the kernel stack, so it is copied into its own allocation instead.
     */
    KSWORD_ARK_HVM_MEMORY_REQUEST* requestSnapshot = NULL;
    KSWORD_ARK_HVM_MEMORY_RESPONSE* memoryResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (BytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Initialize the completion size on every path. */
    *BytesReturned = 0U;
    /* Every ring -1 memory operation requires a write-authorized handle. */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    /* Stop before buffer access when handle authorization fails. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact authorization failure. */
        return status;
    }
    /* Retrieve the complete fixed memory request. */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_HVM_MEMORY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        InputBufferLength < sizeof(KSWORD_ARK_HVM_MEMORY_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_HVM_MEMORY_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /* Retrieve the complete fixed memory response. */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_HVM_MEMORY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        OutputBufferLength < sizeof(KSWORD_ARK_HVM_MEMORY_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_HVM_MEMORY_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /* Reserve the snapshot before the shared buffer is written. */
    requestSnapshot = (KSWORD_ARK_HVM_MEMORY_REQUEST*)
        KswordARKAllocateNonPagedPool(
            sizeof(KSWORD_ARK_HVM_MEMORY_REQUEST),
            KSWORD_ARK_HVM_MEMORY_IOCTL_POOL_TAG);
    /* Fail before any buffer mutation when the snapshot cannot be reserved. */
    if (requestSnapshot == NULL) {
        /* Return the exact allocation failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * METHOD_BUFFERED shares one SystemBuffer between input and output, and
     * the executor zeroes the response before reading the operation, address
     * and payload.  Without this snapshot it would act on response header
     * bytes instead of the caller's request.
     */
    RtlCopyMemory(
        requestSnapshot,
        inputBuffer,
        sizeof(*requestSnapshot));
    /* Bind the fixed protocol output view. */
    memoryResponse = (KSWORD_ARK_HVM_MEMORY_RESPONSE*)outputBuffer;
    /* Apply central high-risk policy to every operation that writes memory. */
    if (requestSnapshot->operation ==
            KSWORD_ARK_HVM_MEMORY_OP_WRITE_PHYSICAL ||
        requestSnapshot->operation ==
            KSWORD_ARK_HVM_MEMORY_OP_WRITE_VIRTUAL) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext = { 0 };

        /* Bind policy auditing to the kernel-patch operation class. */
        safetyContext.Operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* Preserve explicit UI confirmation in central policy evidence. */
        safetyContext.ContextFlags =
            (requestSnapshot->flags &
                KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe the exact memory mutation class. */
        safetyContext.TargetText =
            L"Ring -1 physical memory write through a private page-table window";
        /* Publish the exact bounded target text length. */
        safetyContext.TargetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"Ring -1 physical memory write through a private page-table window") -
                1U);
        /* Evaluate central policy without weakening protocol confirmation. */
        status = KswordARKSafetyEvaluate(
            Device,
            &safetyContext);
        /* Return a complete confirmation-required response on denial. */
        if (!NT_SUCCESS(status)) {
            /* Initialize the complete fixed response. */
            RtlZeroMemory(
                memoryResponse,
                sizeof(*memoryResponse));
            /* Publish the response protocol identity. */
            memoryResponse->version =
                KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
            /* Publish the complete response size. */
            memoryResponse->size = sizeof(*memoryResponse);
            /* Publish stable confirmation-required status. */
            memoryResponse->status =
                KSWORD_ARK_HVM_MEMORY_STATUS_CONFIRMATION_REQUIRED;
            /* Publish the authoritative policy failure. */
            memoryResponse->ntStatus = status;
            /* Publish the fixed completion size. */
            *BytesReturned = sizeof(*memoryResponse);
            /* Release the snapshot before returning the policy failure. */
            ExFreePoolWithTag(
                requestSnapshot,
                KSWORD_ARK_HVM_MEMORY_IOCTL_POOL_TAG);
            /* Return the authoritative policy failure. */
            return status;
        }
    }
    /* Execute the versioned ring -1 memory operation. */
    status = KswordARKHvmMemoryExecute(
        requestSnapshot,
        memoryResponse);
    /* Release the snapshot as soon as the operation no longer needs it. */
    ExFreePoolWithTag(
        requestSnapshot,
        KSWORD_ARK_HVM_MEMORY_IOCTL_POOL_TAG);
    /* Publish the fixed completion size on protocol-level results. */
    *BytesReturned = sizeof(*memoryResponse);
    /* Return the complete ring -1 memory operation result. */
    return status;
}

NTSTATUS
KswordARKHvmIoctlView(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /* The request carries a full shadow page, too large for the kernel stack. */
    KSWORD_ARK_HVM_VIEW_REQUEST* requestSnapshot = NULL;
    KSWORD_ARK_HVM_VIEW_RESPONSE* viewResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (BytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Initialize the completion size on every path. */
    *BytesReturned = 0U;
    /* Redirecting real memory accesses requires a write-authorized handle. */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    /* Stop before buffer access when handle authorization fails. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact authorization failure. */
        return status;
    }
    /* Retrieve the complete fixed view request. */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_HVM_VIEW_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        InputBufferLength < sizeof(KSWORD_ARK_HVM_VIEW_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_HVM_VIEW_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /* Retrieve the complete fixed view response. */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_HVM_VIEW_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        OutputBufferLength < sizeof(KSWORD_ARK_HVM_VIEW_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_HVM_VIEW_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /* Reserve the snapshot before the shared buffer is written. */
    requestSnapshot = (KSWORD_ARK_HVM_VIEW_REQUEST*)
        KswordARKAllocateNonPagedPool(
            sizeof(KSWORD_ARK_HVM_VIEW_REQUEST),
            KSWORD_ARK_HVM_VIEW_IOCTL_POOL_TAG);
    /* Fail before any buffer mutation when the snapshot cannot be reserved. */
    if (requestSnapshot == NULL) {
        /* Return the exact allocation failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * METHOD_BUFFERED shares one SystemBuffer between input and output, and the
     * view backend zeroes the response before reading the operation, kind,
     * target page and shadow payload.  Without this snapshot it would install a
     * view described by response header bytes.
     */
    RtlCopyMemory(
        requestSnapshot,
        inputBuffer,
        sizeof(*requestSnapshot));
    /* Bind the fixed protocol output view. */
    viewResponse = (KSWORD_ARK_HVM_VIEW_RESPONSE*)outputBuffer;
    /* Apply central high-risk policy to every operation that installs a view. */
    if (requestSnapshot->operation != KSWORD_ARK_HVM_VIEW_OP_QUERY) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext = { 0 };

        /* Bind policy auditing to the kernel-patch operation class. */
        safetyContext.Operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* Preserve explicit UI confirmation in central policy evidence. */
        safetyContext.ContextFlags =
            (requestSnapshot->flags &
                KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe the exact memory redirection class. */
        safetyContext.TargetText =
            L"EPT split view redirecting execution or reads to a shadow page";
        /* Publish the exact bounded target text length. */
        safetyContext.TargetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"EPT split view redirecting execution or reads to a shadow page") -
                1U);
        /* Evaluate central policy without weakening protocol confirmation. */
        status = KswordARKSafetyEvaluate(
            Device,
            &safetyContext);
        /* Return a complete confirmation-required response on denial. */
        if (!NT_SUCCESS(status)) {
            /* Initialize the complete fixed response. */
            RtlZeroMemory(
                viewResponse,
                sizeof(*viewResponse));
            /* Publish the response protocol identity. */
            viewResponse->version =
                KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
            /* Publish the complete response size. */
            viewResponse->size = sizeof(*viewResponse);
            /* Publish stable confirmation-required status. */
            viewResponse->status =
                KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED;
            /* Publish the authoritative policy failure. */
            viewResponse->lastStatus = status;
            /* Publish the fixed completion size. */
            *BytesReturned = sizeof(*viewResponse);
            /* Release the snapshot before returning the policy failure. */
            ExFreePoolWithTag(
                requestSnapshot,
                KSWORD_ARK_HVM_VIEW_IOCTL_POOL_TAG);
            /* Return the authoritative policy failure. */
            return status;
        }
    }
    /* Execute the versioned EPT view operation. */
    status = KswordARKHvmEptViewControl(
        requestSnapshot,
        viewResponse);
    /* Release the snapshot as soon as the operation no longer needs it. */
    ExFreePoolWithTag(
        requestSnapshot,
        KSWORD_ARK_HVM_VIEW_IOCTL_POOL_TAG);
    /* Publish the fixed completion size on protocol-level results. */
    *BytesReturned = sizeof(*viewResponse);
    /* Return the complete EPT view operation result. */
    return status;
}

NTSTATUS
KswordARKHvmIoctlMsrPolicy(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /* The request is small enough to snapshot on the stack. */
    KSWORD_ARK_HVM_MSR_POLICY_REQUEST requestSnapshot = { 0 };
    KSWORD_ARK_HVM_MSR_POLICY_RESPONSE* policyResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (BytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Initialize the completion size on every path. */
    *BytesReturned = 0U;
    /* Changing what the guest sees in an MSR needs a write-authorized handle. */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    /* Stop before buffer access when handle authorization fails. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact authorization failure. */
        return status;
    }
    /* Retrieve the complete fixed policy request. */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_HVM_MSR_POLICY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        InputBufferLength <
            sizeof(KSWORD_ARK_HVM_MSR_POLICY_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_HVM_MSR_POLICY_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /*
     * METHOD_BUFFERED shares one SystemBuffer between input and output, and the
     * policy backend zeroes the response before reading the operation, index
     * and action.  Snapshot the request before that happens.
     */
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    /* Retrieve the complete fixed policy response. */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_HVM_MSR_POLICY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        OutputBufferLength <
            sizeof(KSWORD_ARK_HVM_MSR_POLICY_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_HVM_MSR_POLICY_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /* Bind the fixed protocol output view. */
    policyResponse =
        (KSWORD_ARK_HVM_MSR_POLICY_RESPONSE*)outputBuffer;
    /* Apply central high-risk policy to every mutating operation. */
    if (requestSnapshot.operation !=
        KSWORD_ARK_HVM_MSR_POLICY_OP_QUERY) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext = { 0 };

        /* Bind policy auditing to the kernel-patch operation class. */
        safetyContext.Operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* Preserve explicit UI confirmation in central policy evidence. */
        safetyContext.ContextFlags =
            (requestSnapshot.flags &
                KSWORD_ARK_HVM_MSR_POLICY_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe the exact interception class. */
        safetyContext.TargetText =
            L"Model-specific register interception with denial or faked values";
        /* Publish the exact bounded target text length. */
        safetyContext.TargetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"Model-specific register interception with denial or faked values") -
                1U);
        /* Evaluate central policy without weakening protocol confirmation. */
        status = KswordARKSafetyEvaluate(
            Device,
            &safetyContext);
        /* Return a complete confirmation-required response on denial. */
        if (!NT_SUCCESS(status)) {
            /* Initialize the complete fixed response. */
            RtlZeroMemory(
                policyResponse,
                sizeof(*policyResponse));
            /* Publish the response protocol identity. */
            policyResponse->version =
                KSWORD_ARK_HVM_MSR_POLICY_PROTOCOL_VERSION;
            /* Publish the complete response size. */
            policyResponse->size = sizeof(*policyResponse);
            /* Publish stable confirmation-required status. */
            policyResponse->status =
                KSWORD_ARK_HVM_MSR_POLICY_STATUS_CONFIRMATION_REQUIRED;
            /* Publish the authoritative policy failure. */
            policyResponse->lastStatus = status;
            /* Publish the fixed completion size. */
            *BytesReturned = sizeof(*policyResponse);
            /* Return the authoritative policy failure. */
            return status;
        }
    }
    /* Execute the versioned MSR policy operation. */
    status = KswordARKHvmMsrPolicyControl(
        &requestSnapshot,
        policyResponse);
    /* Publish the fixed completion size on protocol-level results. */
    *BytesReturned = sizeof(*policyResponse);
    /* Return the complete MSR policy operation result. */
    return status;
}

NTSTATUS
KswordARKHvmIoctlCrPolicy(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    /* The request is small enough to snapshot on the stack. */
    KSWORD_ARK_HVM_CR_POLICY_REQUEST requestSnapshot = { 0 };
    KSWORD_ARK_HVM_CR_POLICY_RESPONSE* policyResponse = NULL;

    /* Reject an invalid completion contract before touching request buffers. */
    if (BytesReturned == NULL) {
        /* Return the exact dispatcher-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Initialize the completion size on every path. */
    *BytesReturned = 0U;
    /* Pinning control-register bits needs a write-authorized handle. */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    /* Stop before buffer access when handle authorization fails. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact authorization failure. */
        return status;
    }
    /* Retrieve the complete fixed policy request. */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_HVM_CR_POLICY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* Reject truncated or unavailable input buffers. */
    if (!NT_SUCCESS(status) ||
        InputBufferLength <
            sizeof(KSWORD_ARK_HVM_CR_POLICY_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_HVM_CR_POLICY_REQUEST)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_INFO_LENGTH_MISMATCH
            : status;
    }
    /*
     * METHOD_BUFFERED shares one SystemBuffer between input and output, and the
     * policy backend zeroes the response before reading the masks.  Snapshot
     * the request before that happens.
     */
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    /* Retrieve the complete fixed policy response. */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_HVM_CR_POLICY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* Reject truncated or unavailable output buffers. */
    if (!NT_SUCCESS(status) ||
        OutputBufferLength <
            sizeof(KSWORD_ARK_HVM_CR_POLICY_RESPONSE) ||
        actualOutputLength <
            sizeof(KSWORD_ARK_HVM_CR_POLICY_RESPONSE)) {
        /* Return the exact WDF or fixed-size failure. */
        return NT_SUCCESS(status)
            ? STATUS_BUFFER_TOO_SMALL
            : status;
    }
    /* Bind the fixed protocol output view. */
    policyResponse =
        (KSWORD_ARK_HVM_CR_POLICY_RESPONSE*)outputBuffer;
    /* Apply central high-risk policy to every mutating operation. */
    if (requestSnapshot.operation !=
        KSWORD_ARK_HVM_CR_POLICY_OP_QUERY) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext = { 0 };

        /* Bind policy auditing to the kernel-patch operation class. */
        safetyContext.Operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* Preserve explicit UI confirmation in central policy evidence. */
        safetyContext.ContextFlags =
            (requestSnapshot.flags &
                KSWORD_ARK_HVM_CR_POLICY_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        /* Describe the exact interception class. */
        safetyContext.TargetText =
            L"Control-register pinning and address-space switch interception";
        /* Publish the exact bounded target text length. */
        safetyContext.TargetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"Control-register pinning and address-space switch interception") -
                1U);
        /* Evaluate central policy without weakening protocol confirmation. */
        status = KswordARKSafetyEvaluate(
            Device,
            &safetyContext);
        /* Return a complete confirmation-required response on denial. */
        if (!NT_SUCCESS(status)) {
            /* Initialize the complete fixed response. */
            RtlZeroMemory(
                policyResponse,
                sizeof(*policyResponse));
            /* Publish the response protocol identity. */
            policyResponse->version =
                KSWORD_ARK_HVM_CR_POLICY_PROTOCOL_VERSION;
            /* Publish the complete response size. */
            policyResponse->size = sizeof(*policyResponse);
            /* Publish stable confirmation-required status. */
            policyResponse->status =
                KSWORD_ARK_HVM_CR_POLICY_STATUS_CONFIRMATION_REQUIRED;
            /* Publish the authoritative policy failure. */
            policyResponse->lastStatus = status;
            /* Publish the fixed completion size. */
            *BytesReturned = sizeof(*policyResponse);
            /* Return the authoritative policy failure. */
            return status;
        }
    }
    /* Execute the versioned control-register policy operation. */
    status = KswordARKHvmCrPolicyControl(
        &requestSnapshot,
        policyResponse);
    /* Publish the fixed completion size on protocol-level results. */
    *BytesReturned = sizeof(*policyResponse);
    /* Return the complete control-register policy operation result. */
    return status;
}
