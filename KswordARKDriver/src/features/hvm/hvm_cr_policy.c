/*++

Module Name:

    hvm_cr_policy.c

Abstract:

    Control- and debug-register policy.

    Pinning works through the VMCS guest/host masks.  A masked bit belongs to
    the hypervisor: the guest reads it from the shadow and any attempt to change
    it exits here, where the write is applied to every unpinned bit and refused
    for the pinned ones.  That is what keeps CR0.WP or CR4.SMEP set against code
    that would otherwise simply clear them.

    CR3-load exiting and MOV-DR exiting are plain observation.  The first is the
    most expensive control in this whole protocol - every address-space switch
    becomes a VM exit - so it is opt-in and the UI says what it costs.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root dispatch.

--*/

#include "hvm_cr_policy.h"
/* VMCS access goes through the seam in hvm_vmcs.h, never the raw intrinsic. */
#include "hvm_vmcs.h"

#if defined(_M_AMD64)
#include <intrin.h>

/* Name the VMCS guest CR0 field. */
#define KSW_VMCS_GUEST_CR0 0x6800UL
/* Name the VMCS guest CR3 field. */
#define KSW_VMCS_GUEST_CR3 0x6802UL
/* Name the VMCS guest CR4 field. */
#define KSW_VMCS_GUEST_CR4 0x6804UL
/* Name the VMCS CR0 read-shadow field. */
#define KSW_VMCS_CR0_READ_SHADOW 0x6004UL
/* Name the VMCS CR4 read-shadow field. */
#define KSW_VMCS_CR4_READ_SHADOW 0x6006UL

/* Decode the control register a MOV-CR exit touched. */
#define KSW_HVM_CR_QUAL_NUMBER(q) ((ULONG)((q) & 0xFULL))
/* Decode the access type of a MOV-CR exit. */
#define KSW_HVM_CR_QUAL_ACCESS(q) ((ULONG)(((q) >> 4) & 0x3ULL))
/* Decode the general-purpose register a MOV-CR exit used. */
#define KSW_HVM_CR_QUAL_GPR(q) ((ULONG)(((q) >> 8) & 0xFULL))

/* Identify a guest write to a control register. */
#define KSW_HVM_CR_ACCESS_TO_CR 0UL
/* Identify a guest read from a control register. */
#define KSW_HVM_CR_ACCESS_FROM_CR 1UL
/* Identify CLTS, which clears CR0.TS and nothing else. */
#define KSW_HVM_CR_ACCESS_CLTS 2UL
/* Identify LMSW, which writes only the low four bits of CR0. */
#define KSW_HVM_CR_ACCESS_LMSW 3UL

/* Decode the 16-bit source operand LMSW carries in the qualification. */
#define KSW_HVM_CR_QUAL_LMSW_SOURCE(q) ((ULONGLONG)(((q) >> 16) & 0xFFFFULL))

/* Identify CR0.PE, which LMSW may set but never clear. */
#define KSW_HVM_CR0_PE (1ULL << 0)
/* Identify CR0.TS, the only bit CLTS touches. */
#define KSW_HVM_CR0_TS (1ULL << 3)
/* Group the four bits LMSW is allowed to write. */
#define KSW_HVM_CR0_LMSW_MASK 0xFULL

/* Decode the debug register a MOV-DR exit touched. */
#define KSW_HVM_DR_QUAL_NUMBER(q) ((ULONG)((q) & 0x7ULL))
/* Decode the direction of a MOV-DR exit. */
#define KSW_HVM_DR_QUAL_DIRECTION(q) ((ULONG)(((q) >> 4) & 0x1ULL))
/* Decode the general-purpose register a MOV-DR exit used. */
#define KSW_HVM_DR_QUAL_GPR(q) ((ULONG)(((q) >> 8) & 0xFULL))

/* Identify a guest write to a debug register. */
#define KSW_HVM_DR_DIRECTION_TO_DR 0UL

/* Return the frame slot for one architectural general-purpose register. */
static ULONGLONG*
KswordARKHvmCrPolicyRegisterSlot(
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG RegisterNumber
    )
{
    switch (RegisterNumber) {
    case 0UL:
        /* Return the RAX slot. */
        return &Frame->Rax;
    case 1UL:
        /* Return the RCX slot. */
        return &Frame->Rcx;
    case 2UL:
        /* Return the RDX slot. */
        return &Frame->Rdx;
    case 3UL:
        /* Return the RBX slot. */
        return &Frame->Rbx;
    case 5UL:
        /* Return the RBP slot. */
        return &Frame->Rbp;
    case 6UL:
        /* Return the RSI slot. */
        return &Frame->Rsi;
    case 7UL:
        /* Return the RDI slot. */
        return &Frame->Rdi;
    case 8UL:
        /* Return the R8 slot. */
        return &Frame->R8;
    case 9UL:
        /* Return the R9 slot. */
        return &Frame->R9;
    case 10UL:
        /* Return the R10 slot. */
        return &Frame->R10;
    case 11UL:
        /* Return the R11 slot. */
        return &Frame->R11;
    case 12UL:
        /* Return the R12 slot. */
        return &Frame->R12;
    case 13UL:
        /* Return the R13 slot. */
        return &Frame->R13;
    case 14UL:
        /* Return the R14 slot. */
        return &Frame->R14;
    case 15UL:
        /* Return the R15 slot. */
        return &Frame->R15;
    default:
        /*
         * Register 4 is RSP, which the frame does not carry because the guest
         * stack pointer lives in the VMCS.  Refuse rather than guess.
         */
        break;
    }
    /* Report an unusable register selection. */
    return NULL;
}

BOOLEAN
KswordARKHvmCrPolicyHandleControlRegister(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONGLONG Qualification
    )
{
    const ULONG number = KSW_HVM_CR_QUAL_NUMBER(Qualification);
    const ULONG access = KSW_HVM_CR_QUAL_ACCESS(Qualification);
    ULONGLONG* slot = NULL;
    SIZE_T current = 0U;
    ULONGLONG pinnedMask = 0ULL;
    ULONGLONG pinnedValue = 0ULL;
    ULONG guestField = 0UL;
    ULONG shadowField = 0UL;
    ULONGLONG requested = 0ULL;
    ULONGLONG merged = 0ULL;

    /* Reject invalid fixed pointers in the nonblocking exit path. */
    if (Runtime == NULL || Frame == NULL) {
        /* Report an unhandled exit. */
        return FALSE;
    }
    /*
     * CR3 exits carry no pinning: they exist only to observe address-space
     * switches, so the value is replayed verbatim after being counted.
     */
    if (number == 3UL) {
        /* Resolve the register carrying or receiving the CR3 value. */
        slot = KswordARKHvmCrPolicyRegisterSlot(
            Frame,
            KSW_HVM_CR_QUAL_GPR(Qualification));
        /* Refuse a register selection the frame cannot express. */
        if (slot == NULL) {
            /* Report an unhandled exit. */
            return FALSE;
        }
        if (access == KSW_HVM_CR_ACCESS_TO_CR) {
            /* Account the observed address-space switch. */
            InterlockedIncrement64(&Runtime->CrPolicyCr3SwitchCount);
            /* Apply the exact value the guest asked for. */
            return KswordARKHvmVmcsFieldStore(
                KSW_VMCS_GUEST_CR3,
                (SIZE_T)*slot) == 0U;
        }
        if (access == KSW_HVM_CR_ACCESS_FROM_CR) {
            /* Publish the current guest CR3 into the selected register. */
            if (KswordARKHvmVmcsFieldLoad(
                    KSW_VMCS_GUEST_CR3,
                    &current) != 0U) {
                /* Report an unhandled exit. */
                return FALSE;
            }
            /* Return the exact architectural value. */
            *slot = (ULONGLONG)current;
            /* Report a completely serviced access. */
            return TRUE;
        }
        /* Report an unhandled access type. */
        return FALSE;
    }
    /* Select the pinning state for the touched register. */
    if (number == 0UL) {
        /* CR0 pinning state. */
        pinnedMask = Runtime->CrPolicyCr0PinnedMask;
        pinnedValue = Runtime->CrPolicyCr0PinnedValue;
        guestField = KSW_VMCS_GUEST_CR0;
        shadowField = KSW_VMCS_CR0_READ_SHADOW;
    } else if (number == 4UL) {
        /* CR4 pinning state. */
        pinnedMask = Runtime->CrPolicyCr4PinnedMask;
        pinnedValue = Runtime->CrPolicyCr4PinnedValue;
        guestField = KSW_VMCS_GUEST_CR4;
        shadowField = KSW_VMCS_CR4_READ_SHADOW;
    } else {
        /*
         * No other control register is masked by this policy, so an exit on
         * one means the VMCS does not match the configuration.  Fail closed.
         */
        return FALSE;
    }
    /*
     * CLTS and LMSW write CR0 without a source register, so they need their
     * own decoding.  They only reach here when a low CR0 bit is pinned, which
     * is unusual - but failing closed on them would tear down residency for an
     * instruction the guest is entitled to execute.
     */
    if (number == 0UL &&
        (access == KSW_HVM_CR_ACCESS_CLTS ||
         access == KSW_HVM_CR_ACCESS_LMSW)) {
        SIZE_T guestCr0 = 0U;
        ULONGLONG startingValue = 0ULL;

        /* Read the value the instruction is about to modify. */
        if (KswordARKHvmVmcsFieldLoad(
                KSW_VMCS_GUEST_CR0,
                &guestCr0) != 0U) {
            /* Report an unhandled exit. */
            return FALSE;
        }
        /* Preserve the exact architectural starting value. */
        startingValue = (ULONGLONG)guestCr0;
        if (access == KSW_HVM_CR_ACCESS_CLTS) {
            /* CLTS clears exactly one bit. */
            requested = startingValue & ~KSW_HVM_CR0_TS;
        } else {
            /*
             * LMSW writes the low four bits from its immediate source, and
             * architecturally cannot clear PE - once in protected mode the
             * guest stays there.
             */
            const ULONGLONG source =
                KSW_HVM_CR_QUAL_LMSW_SOURCE(Qualification);

            requested =
                (startingValue & ~KSW_HVM_CR0_LMSW_MASK) |
                (source & KSW_HVM_CR0_LMSW_MASK) |
                (startingValue & KSW_HVM_CR0_PE);
        }
        /* Apply the pinning exactly as an ordinary write would. */
        merged = (requested & ~pinnedMask) | (pinnedValue & pinnedMask);
        /* Account a refusal only when a pinned bit was actually targeted. */
        if ((requested & pinnedMask) != (pinnedValue & pinnedMask)) {
            /* Record the refused write for the protocol counters. */
            InterlockedIncrement64(&Runtime->CrPolicyRefusedWriteCount);
        }
        /* Install the merged value in the architectural register. */
        if (KswordARKHvmVmcsFieldStore(
                guestField,
                (SIZE_T)merged) != 0U) {
            /* Report an unhandled exit. */
            return FALSE;
        }
        /* Let the guest read back what it asked for. */
        return KswordARKHvmVmcsFieldStore(
            shadowField,
            (SIZE_T)requested) == 0U;
    }
    /* Only writes reach here: masked reads are served from the shadow. */
    if (access != KSW_HVM_CR_ACCESS_TO_CR) {
        /* Report an unhandled access type. */
        return FALSE;
    }
    /* Resolve the register carrying the requested value. */
    slot = KswordARKHvmCrPolicyRegisterSlot(
        Frame,
        KSW_HVM_CR_QUAL_GPR(Qualification));
    /* Refuse a register selection the frame cannot express. */
    if (slot == NULL) {
        /* Report an unhandled exit. */
        return FALSE;
    }
    /* Capture the value the guest wanted to install. */
    requested = *slot;
    /*
     * Apply every unpinned bit and keep the pinned ones at the value captured
     * when the policy was installed.  The guest's own view stays consistent
     * because the shadow reports what it asked for.
     */
    merged = (requested & ~pinnedMask) | (pinnedValue & pinnedMask);
    /* Account a refusal only when the guest actually tried to change a pin. */
    if ((requested & pinnedMask) != (pinnedValue & pinnedMask)) {
        /* Record the refused write for the protocol counters. */
        InterlockedIncrement64(&Runtime->CrPolicyRefusedWriteCount);
    }
    /* Install the merged value in the architectural register. */
    if (KswordARKHvmVmcsFieldStore(
            guestField,
            (SIZE_T)merged) != 0U) {
        /* Report an unhandled exit. */
        return FALSE;
    }
    /*
     * Publish the requested value in the shadow so the guest reads back what
     * it wrote.  Hiding the refusal is the point: code that checks whether its
     * write took effect sees success and does not escalate.
     */
    return KswordARKHvmVmcsFieldStore(
        shadowField,
        (SIZE_T)requested) == 0U;
}

BOOLEAN
KswordARKHvmCrPolicyHandleDebugRegister(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONGLONG Qualification
    )
{
    const ULONG number = KSW_HVM_DR_QUAL_NUMBER(Qualification);
    const ULONG direction = KSW_HVM_DR_QUAL_DIRECTION(Qualification);
    ULONGLONG* slot = NULL;

    /* Reject invalid fixed pointers in the nonblocking exit path. */
    if (Runtime == NULL || Frame == NULL) {
        /* Report an unhandled exit. */
        return FALSE;
    }
    /* Resolve the register carrying or receiving the debug value. */
    slot = KswordARKHvmCrPolicyRegisterSlot(
        Frame,
        KSW_HVM_DR_QUAL_GPR(Qualification));
    /* Refuse a register selection the frame cannot express. */
    if (slot == NULL) {
        /* Report an unhandled exit. */
        return FALSE;
    }
    /* Account the intercepted debug-register access. */
    InterlockedIncrement64(&Runtime->CrPolicyDebugAccessCount);
    /*
     * Interception here is observation only: the access is replayed so the
     * guest's debugging behavior is unchanged.  DR4 and DR5 alias DR6 and DR7
     * when CR4.DE is clear and fault when it is set, so they are refused
     * rather than replayed under a guess about CR4.
     */
    if (number > 3UL && number != 6UL && number != 7UL) {
        /* Report an unhandled register selection. */
        return FALSE;
    }
    if (direction == KSW_HVM_DR_DIRECTION_TO_DR) {
        /* Replay the exact write the guest issued. */
        switch (number) {
        case 0UL:
            /* Install DR0. */
            __writedr(0, *slot);
            break;
        case 1UL:
            /* Install DR1. */
            __writedr(1, *slot);
            break;
        case 2UL:
            /* Install DR2. */
            __writedr(2, *slot);
            break;
        case 3UL:
            /* Install DR3. */
            __writedr(3, *slot);
            break;
        case 6UL:
            /* Install DR6. */
            __writedr(6, *slot);
            break;
        default:
            /* Install DR7. */
            __writedr(7, *slot);
            break;
        }
        /* Report a completely serviced access. */
        return TRUE;
    }
    /* Replay the exact read the guest issued. */
    switch (number) {
    case 0UL:
        /* Return DR0. */
        *slot = __readdr(0);
        break;
    case 1UL:
        /* Return DR1. */
        *slot = __readdr(1);
        break;
    case 2UL:
        /* Return DR2. */
        *slot = __readdr(2);
        break;
    case 3UL:
        /* Return DR3. */
        *slot = __readdr(3);
        break;
    case 6UL:
        /* Return DR6. */
        *slot = __readdr(6);
        break;
    default:
        /* Return DR7. */
        *slot = __readdr(7);
        break;
    }
    /* Report a completely serviced access. */
    return TRUE;
}

#else

BOOLEAN
KswordARKHvmCrPolicyHandleControlRegister(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONGLONG Qualification
    )
{
    UNREFERENCED_PARAMETER(Runtime);
    UNREFERENCED_PARAMETER(Frame);
    UNREFERENCED_PARAMETER(Qualification);
    return FALSE;
}

BOOLEAN
KswordARKHvmCrPolicyHandleDebugRegister(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONGLONG Qualification
    )
{
    UNREFERENCED_PARAMETER(Runtime);
    UNREFERENCED_PARAMETER(Frame);
    UNREFERENCED_PARAMETER(Qualification);
    return FALSE;
}

#endif

VOID
KswordARKHvmCrPolicyResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    /* Clear the configuration so the next VMCS build masks nothing. */
    Runtime->CrPolicyFlags = 0UL;
    Runtime->CrPolicyCr0PinnedMask = 0ULL;
    Runtime->CrPolicyCr4PinnedMask = 0ULL;
    Runtime->CrPolicyCr0PinnedValue = 0ULL;
    Runtime->CrPolicyCr4PinnedValue = 0ULL;
    /* Clear the counters alongside the configuration they describe. */
    Runtime->CrPolicyRefusedWriteCount = 0LL;
    Runtime->CrPolicyCr3SwitchCount = 0LL;
    Runtime->CrPolicyDebugAccessCount = 0LL;
}

NTSTATUS
KswordARKHvmCrPolicyControl(
    _In_ const KSWORD_ARK_HVM_CR_POLICY_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_CR_POLICY_RESPONSE* Response
    )
{
    KSW_HVM_RUNTIME* runtime = KswordARKHvmGetRuntime();
    BOOLEAN mutating = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before acquiring the lock. */
    if (Request == NULL || Response == NULL || runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Start from a deterministic response for every failure path. */
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_HVM_CR_POLICY_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    /* Validate the complete versioned request. */
    if (Request->version !=
            KSWORD_ARK_HVM_CR_POLICY_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request)) {
        /* Publish the stable invalid-request protocol status. */
        Response->status =
            KSWORD_ARK_HVM_CR_POLICY_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Classify the request before deciding which guards apply. */
    mutating = Request->operation != KSWORD_ARK_HVM_CR_POLICY_OP_QUERY;
    /* Mutating operations change what the guest can do and need confirmation. */
    if (mutating &&
        (Request->confirmationToken !=
                KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN ||
         (Request->flags &
                KSWORD_ARK_HVM_CR_POLICY_FLAG_UI_CONFIRMED) == 0UL)) {
        /* Publish the stable confirmation-required protocol status. */
        Response->status =
            KSWORD_ARK_HVM_CR_POLICY_STATUS_CONFIRMATION_REQUIRED;
        Response->lastStatus = STATUS_ACCESS_DENIED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Serialize against every other lifecycle operation. */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&runtime->Lock);
    Response->generation = runtime->Generation;
    if (!runtime->Initialized) {
        /* Publish the stable not-prepared protocol status. */
        Response->status =
            KSWORD_ARK_HVM_CR_POLICY_STATUS_NOT_PREPARED;
        Response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Select protocol-level success after writing the fixed response. */
        status = STATUS_SUCCESS;
    } else if (mutating &&
        InterlockedCompareExchange(
            &runtime->ResidentProcessorCount,
            0L,
            0L) != 0L) {
        /*
         * The masks and exiting controls are VMCS fields written at launch, so
         * changing them while resident would silently do nothing.  Refuse
         * instead of accepting a configuration that has no effect.
         */
        Response->status =
            KSWORD_ARK_HVM_CR_POLICY_STATUS_RESIDENT_BUSY;
        Response->lastStatus = STATUS_DEVICE_BUSY;
        /* No configuration was changed. */
        status = STATUS_SUCCESS;
    } else if (Request->operation ==
        KSWORD_ARK_HVM_CR_POLICY_OP_CLEAR) {
        /* Drop the whole configuration and its counters. */
        KswordARKHvmCrPolicyResetLocked(runtime);
        /* Publish the successful clear. */
        Response->status = KSWORD_ARK_HVM_CR_POLICY_STATUS_OK;
        /* Select protocol-level success. */
        status = STATUS_SUCCESS;
    } else if (Request->operation ==
        KSWORD_ARK_HVM_CR_POLICY_OP_SET) {
#if defined(_M_AMD64)
        const ULONGLONG currentCr0 = (ULONGLONG)__readcr0();
        const ULONGLONG currentCr4 = (ULONGLONG)__readcr4();
#else
        const ULONGLONG currentCr0 = 0ULL;
        const ULONGLONG currentCr4 = 0ULL;
#endif

        /*
         * A bit can only be pinned if the fixed-bit MSRs let the guest hold it
         * at the captured value.  Pinning something the architecture forces the
         * other way would make every VM entry fail.
         */
        if ((Request->cr0PinnedMask &
                ~(runtime->Cr0Fixed1 & ~runtime->Cr0Fixed0)) != 0ULL &&
            (Request->cr0PinnedMask &
                (runtime->Cr0Fixed0 | ~runtime->Cr0Fixed1)) != 0ULL) {
            /* Publish the stable unpinnable-bit protocol status. */
            Response->status =
                KSWORD_ARK_HVM_CR_POLICY_STATUS_BIT_NOT_PINNABLE;
            Response->lastStatus = STATUS_INVALID_PARAMETER;
        } else if ((Request->cr4PinnedMask &
                ~(runtime->Cr4Fixed1 & ~runtime->Cr4Fixed0)) != 0ULL &&
            (Request->cr4PinnedMask &
                (runtime->Cr4Fixed0 | ~runtime->Cr4Fixed1)) != 0ULL) {
            /* Publish the stable unpinnable-bit protocol status. */
            Response->status =
                KSWORD_ARK_HVM_CR_POLICY_STATUS_BIT_NOT_PINNABLE;
            Response->lastStatus = STATUS_INVALID_PARAMETER;
        } else {
            /* Preserve only defined behavior flags. */
            runtime->CrPolicyFlags = Request->flags &
                (KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3 |
                 KSWORD_ARK_HVM_CR_POLICY_FLAG_INTERCEPT_DR |
                 KSWORD_ARK_HVM_CR_POLICY_FLAG_LOG);
            /* Preserve the requested masks. */
            runtime->CrPolicyCr0PinnedMask = Request->cr0PinnedMask;
            runtime->CrPolicyCr4PinnedMask = Request->cr4PinnedMask;
            /*
             * Capture the values now, on the configuring processor.  Pinning
             * means "keep what it is at this moment", so the snapshot has to
             * come from before residency starts.
             */
            runtime->CrPolicyCr0PinnedValue = currentCr0;
            runtime->CrPolicyCr4PinnedValue = currentCr4;
            /* Publish the successful configuration. */
            Response->status = KSWORD_ARK_HVM_CR_POLICY_STATUS_OK;
        }
        /* Select protocol-level success. */
        status = STATUS_SUCCESS;
    } else if (Request->operation ==
        KSWORD_ARK_HVM_CR_POLICY_OP_QUERY) {
        /* Publish the successful query. */
        Response->status = KSWORD_ARK_HVM_CR_POLICY_STATUS_OK;
        /* Select protocol-level success. */
        status = STATUS_SUCCESS;
    } else {
        /* Publish the stable invalid-request protocol status. */
        Response->status =
            KSWORD_ARK_HVM_CR_POLICY_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Select protocol-level success after writing the fixed response. */
        status = STATUS_SUCCESS;
    }
    /* Publish the resulting configuration on every path. */
    Response->flags = runtime->CrPolicyFlags;
    Response->cr0PinnedMask = runtime->CrPolicyCr0PinnedMask;
    Response->cr4PinnedMask = runtime->CrPolicyCr4PinnedMask;
    Response->cr0PinnedValue = runtime->CrPolicyCr0PinnedValue;
    Response->cr4PinnedValue = runtime->CrPolicyCr4PinnedValue;
    Response->refusedWriteCount =
        (ULONGLONG)runtime->CrPolicyRefusedWriteCount;
    Response->cr3SwitchCount =
        (ULONGLONG)runtime->CrPolicyCr3SwitchCount;
    Response->debugAccessCount =
        (ULONGLONG)runtime->CrPolicyDebugAccessCount;
    /* Release exclusive lifecycle ownership. */
    ExReleasePushLockExclusive(&runtime->Lock);
    /* Leave the critical region after releasing the push lock. */
    KeLeaveCriticalRegion();
    /* Return the complete protocol operation result. */
    return status;
}
