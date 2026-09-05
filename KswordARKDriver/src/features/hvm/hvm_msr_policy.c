/*++

Module Name:

    hvm_msr_policy.c

Abstract:

    MSR policies.

    The bitmap installed during preparation passes every MSR through natively,
    which is what lets residency survive at all.  A policy punches one hole in
    it: the named index starts exiting again and this module decides what the
    guest gets instead of the native access.

    Writes are deliberately weaker than reads.  Replaying an arbitrary WRMSR in
    VMX root would fault on the host IDT with no continuation available, so a
    write policy can only refuse the access or discard it.  Reads are replayed
    under structured exception handling and fall back to an injected #GP, which
    is what the guest would have taken had the index been undefined.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root dispatch.

--*/

#include "hvm_msr_policy.h"

#include "hvm_exit_emulate.h"

#if defined(_M_AMD64)
#include <intrin.h>
#endif

/* Name the last index covered by the low half of the architectural bitmap. */
#define KSW_HVM_MSR_LOW_LIMIT 0x00001FFFUL
/* Name the first index covered by the high half of the bitmap. */
#define KSW_HVM_MSR_HIGH_BASE 0xC0000000UL
/* Name the last index covered by the high half of the bitmap. */
#define KSW_HVM_MSR_HIGH_LIMIT 0xC0001FFFUL

/* Byte offset of the low-range read bitmap inside the page. */
#define KSW_HVM_MSR_READ_LOW_OFFSET 0x000U
/* Byte offset of the high-range read bitmap inside the page. */
#define KSW_HVM_MSR_READ_HIGH_OFFSET 0x400U
/* Byte offset of the low-range write bitmap inside the page. */
#define KSW_HVM_MSR_WRITE_LOW_OFFSET 0x800U
/* Byte offset of the high-range write bitmap inside the page. */
#define KSW_HVM_MSR_WRITE_HIGH_OFFSET 0xC00U

/* Return whether the architectural bitmap covers one MSR index. */
static BOOLEAN
KswordARKHvmMsrPolicyIsCovered(
    _In_ ULONG MsrIndex
    )
{
    /* Accept the low range the bitmap describes. */
    if (MsrIndex <= KSW_HVM_MSR_LOW_LIMIT) {
        /* Report a covered index. */
        return TRUE;
    }
    /* Accept the high range the bitmap describes. */
    return MsrIndex >= KSW_HVM_MSR_HIGH_BASE &&
        MsrIndex <= KSW_HVM_MSR_HIGH_LIMIT;
}

/*
 * Set or clear one bitmap bit.  A set bit makes the access exit; the zeroed
 * bitmap installed at preparation therefore passes everything through.
 */
static VOID
KswordARKHvmMsrPolicySetBit(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG MsrIndex,
    _In_ BOOLEAN IsWrite,
    _In_ BOOLEAN Intercept
    )
{
    UCHAR* bitmap = (UCHAR*)Runtime->MsrBitmapVirtual;
    ULONG base = 0UL;
    ULONG relative = 0UL;
    ULONG byteOffset = 0UL;
    UCHAR mask = 0U;

    /* Do nothing when the bitmap was never reserved. */
    if (bitmap == NULL) {
        /* Return without touching an absent bitmap. */
        return;
    }
    /* Select the half of the bitmap that describes this index. */
    if (MsrIndex <= KSW_HVM_MSR_LOW_LIMIT) {
        /* Low indices start at the beginning of each half. */
        base = IsWrite
            ? KSW_HVM_MSR_WRITE_LOW_OFFSET
            : KSW_HVM_MSR_READ_LOW_OFFSET;
        /* The low range is indexed directly. */
        relative = MsrIndex;
    } else {
        /* High indices are offset from the start of the high range. */
        base = IsWrite
            ? KSW_HVM_MSR_WRITE_HIGH_OFFSET
            : KSW_HVM_MSR_READ_HIGH_OFFSET;
        /* Rebase the index onto the high half. */
        relative = MsrIndex - KSW_HVM_MSR_HIGH_BASE;
    }
    /* Resolve the byte and bit describing this index. */
    byteOffset = base + (relative >> 3);
    mask = (UCHAR)(1U << (relative & 7U));
    /* Publish the requested interception state. */
    if (Intercept) {
        /* Make the access exit. */
        bitmap[byteOffset] |= mask;
    } else {
        /* Return the access to the native pass-through path. */
        bitmap[byteOffset] &= (UCHAR)~mask;
    }
}

/* Return the active policy covering one index and direction. */
static KSW_HVM_MSR_POLICY_SLOT*
KswordARKHvmMsrPolicyFind(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG MsrIndex,
    _In_ ULONG Access
    )
{
    ULONG index = 0UL;

    /* Search the bounded policy table without allocation. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_MSR_POLICIES;
         ++index) {
        KSW_HVM_MSR_POLICY_SLOT* policy = &Runtime->MsrPolicies[index];

        /* Match only installed policies for the exact index and direction. */
        if (policy->Active &&
            policy->MsrIndex == MsrIndex &&
            (policy->Access & Access) != 0UL) {
            /* Return the exact installed policy. */
            return policy;
        }
    }
    /* Report that no policy covers the access. */
    return NULL;
}

/* Close both bitmap holes one policy owns. */
static VOID
KswordARKHvmMsrPolicyReleaseLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_MSR_POLICY_SLOT* Policy
    )
{
    /* Return the read access to the native pass-through path. */
    if ((Policy->Access & KSWORD_ARK_HVM_MSR_ACCESS_READ) != 0UL) {
        /* Clear the read bit for this index. */
        KswordARKHvmMsrPolicySetBit(
            Runtime,
            Policy->MsrIndex,
            FALSE,
            FALSE);
    }
    /* Return the write access to the native pass-through path. */
    if ((Policy->Access & KSWORD_ARK_HVM_MSR_ACCESS_WRITE) != 0UL) {
        /* Clear the write bit for this index. */
        KswordARKHvmMsrPolicySetBit(
            Runtime,
            Policy->MsrIndex,
            TRUE,
            FALSE);
    }
    /* Clear the reusable slot completely. */
    RtlZeroMemory(Policy, sizeof(*Policy));
    /* Account the released policy. */
    if (Runtime->MsrPolicyCount != 0UL) {
        /* Keep the published count consistent with the table. */
        Runtime->MsrPolicyCount -= 1UL;
    }
}

VOID
KswordARKHvmMsrPolicyResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;

    /* Close every hole before the bitmap page is released. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_MSR_POLICIES;
         ++index) {
        /* Skip inactive records. */
        if (!Runtime->MsrPolicies[index].Active) {
            /* Continue to the next bounded record. */
            continue;
        }
        /* Close the holes and clear the record. */
        KswordARKHvmMsrPolicyReleaseLocked(
            Runtime,
            &Runtime->MsrPolicies[index]);
    }
    /* Leave the table and its counters deterministic. */
    RtlZeroMemory(
        Runtime->MsrPolicies,
        sizeof(Runtime->MsrPolicies));
    Runtime->MsrPolicyCount = 0UL;
}

/* Install one policy over an index no other policy already intercepts. */
static NTSTATUS
KswordARKHvmMsrPolicyAddLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_MSR_POLICY_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_MSR_POLICY_RESPONSE* Response
    )
{
    KSW_HVM_MSR_POLICY_SLOT* policy = NULL;
    ULONG index = 0UL;

    /* Reject an index the architectural bitmap does not describe. */
    if (!KswordARKHvmMsrPolicyIsCovered(Request->msrIndex)) {
        /* Publish the stable uncovered-index protocol status. */
        Response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_INDEX_UNCOVERED;
        /* Return the exact coverage failure. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Require at least one direction and reject unknown access bits. */
    if ((Request->access &
            (KSWORD_ARK_HVM_MSR_ACCESS_READ |
             KSWORD_ARK_HVM_MSR_ACCESS_WRITE)) == 0UL ||
        (Request->access &
            ~(KSWORD_ARK_HVM_MSR_ACCESS_READ |
              KSWORD_ARK_HVM_MSR_ACCESS_WRITE)) != 0UL) {
        /* Publish the stable invalid-request protocol status. */
        Response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_INVALID_REQUEST;
        /* Return the exact parameter failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Reject an action outside the defined vocabulary. */
    if (Request->action != KSWORD_ARK_HVM_MSR_ACTION_LOG &&
        Request->action != KSWORD_ARK_HVM_MSR_ACTION_DENY &&
        Request->action != KSWORD_ARK_HVM_MSR_ACTION_FAKE) {
        /* Publish the stable invalid-request protocol status. */
        Response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_INVALID_REQUEST;
        /* Return the exact parameter failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * A logged write would have to be replayed in VMX root, where an illegal
     * value faults with no continuation.  Refuse the combination instead of
     * offering an action that can bugcheck the machine.
     */
    if (Request->action == KSWORD_ARK_HVM_MSR_ACTION_LOG &&
        (Request->access & KSWORD_ARK_HVM_MSR_ACCESS_WRITE) != 0UL) {
        /* Publish the stable unsafe-combination protocol status. */
        Response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_WRITE_LOG_UNSAFE;
        /* Return the exact policy-contract failure. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Refuse a second policy over the same index and direction. */
    if (KswordARKHvmMsrPolicyFind(
            Runtime,
            Request->msrIndex,
            Request->access) != NULL) {
        /* Publish the stable duplicate protocol status. */
        Response->status = KSWORD_ARK_HVM_MSR_POLICY_STATUS_DUPLICATE;
        /* Return the exact ownership conflict. */
        return STATUS_OBJECT_NAME_COLLISION;
    }
    /* Reserve one bounded table slot. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_MSR_POLICIES;
         ++index) {
        /* Select the first inactive record. */
        if (!Runtime->MsrPolicies[index].Active) {
            /* Bind the reusable zeroed record. */
            policy = &Runtime->MsrPolicies[index];
            /* Stop after the first free slot. */
            break;
        }
    }
    /* Report bounded policy capacity exhaustion. */
    if (policy == NULL) {
        /* Publish the stable table-full protocol status. */
        Response->status = KSWORD_ARK_HVM_MSR_POLICY_STATUS_TABLE_FULL;
        /* Return the exact fixed-capacity failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Preserve every field before the bitmap starts exiting. */
    policy->MsrIndex = Request->msrIndex;
    /* Preserve the intercepted directions. */
    policy->Access = Request->access;
    /* Preserve the action applied to an intercepted access. */
    policy->Action = Request->action;
    /* Preserve the value returned by a faked read. */
    policy->FakeValue = Request->fakeValue;
    /* Assign the next stable protocol identifier. */
    Runtime->MsrPolicyNextId += 1UL;
    /* Publish the assigned identifier. */
    policy->PolicyId = Runtime->MsrPolicyNextId;
    /* Order every field before the record becomes reachable. */
    KeMemoryBarrier();
    /* Publish the installed policy record. */
    policy->Active = TRUE;
    /* Account the installed policy. */
    Runtime->MsrPolicyCount += 1UL;
    /* Open the read hole only after the record can service it. */
    if ((policy->Access & KSWORD_ARK_HVM_MSR_ACCESS_READ) != 0UL) {
        /* Make guest reads of this index exit. */
        KswordARKHvmMsrPolicySetBit(
            Runtime,
            policy->MsrIndex,
            FALSE,
            TRUE);
    }
    /* Open the write hole only after the record can service it. */
    if ((policy->Access & KSWORD_ARK_HVM_MSR_ACCESS_WRITE) != 0UL) {
        /* Make guest writes of this index exit. */
        KswordARKHvmMsrPolicySetBit(
            Runtime,
            policy->MsrIndex,
            TRUE,
            TRUE);
    }
    /* Publish the assigned identifier to the caller. */
    Response->policyId = policy->PolicyId;
    /* Publish the successful installation. */
    Response->status = KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK;
    /* Complete the installation successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmMsrPolicyControl(
    _In_ const KSWORD_ARK_HVM_MSR_POLICY_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_MSR_POLICY_RESPONSE* Response
    )
{
    KSW_HVM_RUNTIME* runtime = KswordARKHvmGetRuntime();
    BOOLEAN mutating = FALSE;
    ULONG index = 0UL;
    ULONG rows = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before acquiring the lock. */
    if (Request == NULL || Response == NULL || runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Start from a deterministic response for every failure path. */
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_HVM_MSR_POLICY_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    /* Validate the complete versioned request. */
    if (Request->version !=
            KSWORD_ARK_HVM_MSR_POLICY_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request)) {
        /* Publish the stable invalid-request protocol status. */
        Response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Classify the request before deciding which guards apply. */
    mutating = Request->operation != KSWORD_ARK_HVM_MSR_POLICY_OP_QUERY;
    /* Mutating operations redirect real MSR access and need confirmation. */
    if (mutating &&
        (Request->confirmationToken !=
                KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN ||
         (Request->flags &
                KSWORD_ARK_HVM_MSR_POLICY_FLAG_UI_CONFIRMED) == 0UL)) {
        /* Publish the stable confirmation-required protocol status. */
        Response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_CONFIRMATION_REQUIRED;
        Response->lastStatus = STATUS_ACCESS_DENIED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Serialize against every other lifecycle and EPT operation. */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&runtime->Lock);
    Response->generation = runtime->Generation;
    if (!runtime->Initialized ||
        (mutating && runtime->MsrBitmapVirtual == NULL)) {
        /* Publish the stable not-prepared protocol status. */
        Response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_NOT_PREPARED;
        Response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Select protocol-level success after writing the fixed response. */
        status = STATUS_SUCCESS;
    } else if (mutating &&
        InterlockedCompareExchange(
            &runtime->ResidentProcessorCount,
            0L,
            0L) != 0L) {
        /*
         * Resident VM exits read this table without taking the PASSIVE_LEVEL
         * lock, and the bitmap is live hardware state.  Keep both immutable
         * until every VCPU has committed its guest-stack return.
         */
        Response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_RESIDENT_BUSY;
        Response->lastStatus = STATUS_DEVICE_BUSY;
        /* No policy or bitmap bit was changed. */
        status = STATUS_SUCCESS;
    } else if (Request->operation ==
        KSWORD_ARK_HVM_MSR_POLICY_OP_QUERY) {
        /* Publish every installed policy row. */
        for (index = 0UL;
             index < KSWORD_ARK_HVM_MAX_MSR_POLICIES &&
                rows < KSWORD_ARK_HVM_MAX_MSR_POLICIES;
             ++index) {
            const KSW_HVM_MSR_POLICY_SLOT* policy =
                &runtime->MsrPolicies[index];

            /* Skip inactive records. */
            if (!policy->Active) {
                /* Continue to the next bounded record. */
                continue;
            }
            /* Publish the stable protocol identifier. */
            Response->rows[rows].policyId = policy->PolicyId;
            /* Publish the intercepted index. */
            Response->rows[rows].msrIndex = policy->MsrIndex;
            /* Publish the intercepted directions. */
            Response->rows[rows].access = policy->Access;
            /* Publish the configured action. */
            Response->rows[rows].action = policy->Action;
            /* Publish the faked read value. */
            Response->rows[rows].fakeValue = policy->FakeValue;
            /* Publish how often the policy has been applied. */
            Response->rows[rows].hitCount = (ULONGLONG)policy->HitCount;
            /* Account the published row. */
            rows += 1UL;
        }
        /* Publish the number of rows written. */
        Response->returnedRows = rows;
        /* Publish the successful query. */
        Response->status = KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK;
        /* Select protocol-level success. */
        status = STATUS_SUCCESS;
    } else if (Request->operation ==
        KSWORD_ARK_HVM_MSR_POLICY_OP_CLEAR) {
        /* Close every hole and clear the table. */
        KswordARKHvmMsrPolicyResetLocked(runtime);
        /* Publish the successful clear. */
        Response->status = KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK;
        /* Select protocol-level success. */
        status = STATUS_SUCCESS;
    } else if (Request->operation ==
        KSWORD_ARK_HVM_MSR_POLICY_OP_REMOVE) {
        KSW_HVM_MSR_POLICY_SLOT* policy = NULL;

        /* Locate the policy carrying the requested identifier. */
        for (index = 0UL;
             index < KSWORD_ARK_HVM_MAX_MSR_POLICIES;
             ++index) {
            /* Match only installed policies with the exact identifier. */
            if (runtime->MsrPolicies[index].Active &&
                runtime->MsrPolicies[index].PolicyId ==
                    Request->policyId) {
                /* Bind the exact installed policy. */
                policy = &runtime->MsrPolicies[index];
                /* Stop after the first match. */
                break;
            }
        }
        if (policy == NULL) {
            /* Publish the stable not-found protocol status. */
            Response->status =
                KSWORD_ARK_HVM_MSR_POLICY_STATUS_NOT_FOUND;
            Response->lastStatus = STATUS_NOT_FOUND;
        } else {
            /* Close the holes and clear the record. */
            KswordARKHvmMsrPolicyReleaseLocked(runtime, policy);
            /* Publish the successful removal. */
            Response->status = KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK;
        }
        /* Select protocol-level success. */
        status = STATUS_SUCCESS;
    } else if (Request->operation ==
        KSWORD_ARK_HVM_MSR_POLICY_OP_ADD) {
        /* Install the requested policy. */
        status = KswordARKHvmMsrPolicyAddLocked(
            runtime,
            Request,
            Response);
        /* Preserve the authoritative installation status. */
        Response->lastStatus = status;
        /* Return a protocol-level result successfully. */
        status = STATUS_SUCCESS;
    } else {
        /* Publish the stable invalid-request protocol status. */
        Response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Select protocol-level success after writing the fixed response. */
        status = STATUS_SUCCESS;
    }
    /* Publish the resulting count on every path. */
    Response->policyCount = runtime->MsrPolicyCount;
    /* Release exclusive lifecycle ownership. */
    ExReleasePushLockExclusive(&runtime->Lock);
    /* Leave the critical region after releasing the push lock. */
    KeLeaveCriticalRegion();
    /* Return the complete protocol operation result. */
    return status;
}

ULONG
KswordARKHvmMsrPolicyApply(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ BOOLEAN IsWrite
    )
{
#if defined(_M_AMD64)
    KSW_HVM_MSR_POLICY_SLOT* policy = NULL;
    ULONG msrIndex = 0UL;
    ULONGLONG value = 0ULL;
    BOOLEAN read = FALSE;

    /* Reject invalid fixed pointers in the nonblocking exit path. */
    if (Runtime == NULL || Frame == NULL) {
        /* Report no policy match. */
        return KSW_HVM_MSR_POLICY_RESULT_UNMATCHED;
    }
    /* The architectural MSR index always arrives in ECX. */
    msrIndex = (ULONG)Frame->Rcx;
    /* Locate the policy covering this index and direction. */
    policy = KswordARKHvmMsrPolicyFind(
        Runtime,
        msrIndex,
        IsWrite
            ? KSWORD_ARK_HVM_MSR_ACCESS_WRITE
            : KSWORD_ARK_HVM_MSR_ACCESS_READ);
    /* Leave an unmatched access to the caller's existing behavior. */
    if (policy == NULL) {
        /* Report no policy match. */
        return KSW_HVM_MSR_POLICY_RESULT_UNMATCHED;
    }
    /* Account the applied policy before choosing an outcome. */
    InterlockedIncrement64(&policy->HitCount);
    /* Refuse the access exactly as an undefined index would. */
    if (policy->Action == KSWORD_ARK_HVM_MSR_ACTION_DENY) {
        /* Report that the caller must inject the architectural fault. */
        return KSW_HVM_MSR_POLICY_RESULT_INJECT_FAULT;
    }
    if (IsWrite) {
        /*
         * The only remaining write action is FAKE, which discards the value.
         * LOG is refused at installation because replaying an arbitrary WRMSR
         * in root operation has no safe failure path.
         */
        return KSW_HVM_MSR_POLICY_RESULT_HANDLED;
    }
    /* Return the configured value without touching the real register. */
    if (policy->Action == KSWORD_ARK_HVM_MSR_ACTION_FAKE) {
        /* Publish the faked value in the architectural EDX:EAX pair. */
        Frame->Rax = (ULONGLONG)(ULONG)policy->FakeValue;
        Frame->Rdx = (ULONGLONG)(ULONG)(policy->FakeValue >> 32);
        /* Report a completely serviced access. */
        return KSW_HVM_MSR_POLICY_RESULT_HANDLED;
    }
    /*
     * LOG performs the native read after recording it.  The index was chosen
     * by an operator and may still be illegal on this part, so the read is
     * guarded and falls back to the fault the guest would have taken.
     */
    read = TRUE;
    __try {
        /* Perform the exact read the guest asked for. */
        value = __readmsr(msrIndex);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Record that no value was produced. */
        read = FALSE;
    }
    /* Deliver the architectural fault when the index turned out illegal. */
    if (!read) {
        /* Report that the caller must inject the architectural fault. */
        return KSW_HVM_MSR_POLICY_RESULT_INJECT_FAULT;
    }
    /* Publish the native value in the architectural EDX:EAX pair. */
    Frame->Rax = (ULONGLONG)(ULONG)value;
    Frame->Rdx = (ULONGLONG)(ULONG)(value >> 32);
    /* Report a completely serviced access. */
    return KSW_HVM_MSR_POLICY_RESULT_HANDLED;
#else
    UNREFERENCED_PARAMETER(Runtime);
    UNREFERENCED_PARAMETER(Frame);
    UNREFERENCED_PARAMETER(IsWrite);
    return KSW_HVM_MSR_POLICY_RESULT_UNMATCHED;
#endif
}
