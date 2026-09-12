/*++

Module Name:

    hvm_nested_l2.c

Abstract:

    Implements vmcs02 construction, L2 entry, and L2 exit routing.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_nested_l2.h"
#include "hvm_nested_ept.h"
#include "hvm_resident.h"
#include "hvm_exit.h"
#include "hvm_vmcs.h"

#if defined(_M_AMD64)
#include <intrin.h>

/* Name the Intel VM-instruction errors this module reports to L1. */
#define KSW_L2_ERROR_VMLAUNCH_NONCLEAR_VMCS 4UL
#define KSW_L2_ERROR_VMRESUME_NONLAUNCHED_VMCS 5UL
#define KSW_L2_ERROR_INVALID_CONTROL_FIELDS 7UL
#define KSW_L2_ERROR_INVALID_HOST_STATE 8UL

/* Name the VMCS fields this module addresses by hand. */
#define KSW_L2_VMCS_LINK_POINTER 0x2800UL
#define KSW_L2_EPT_POINTER 0x201AUL
#define KSW_L2_PIN_CONTROLS 0x4000UL
#define KSW_L2_PRIMARY_CONTROLS 0x4002UL
#define KSW_L2_EXCEPTION_BITMAP 0x4004UL
#define KSW_L2_EXIT_CONTROLS 0x400CUL
#define KSW_L2_ENTRY_CONTROLS 0x4012UL
#define KSW_L2_SECONDARY_CONTROLS 0x401EUL
#define KSW_L2_EXIT_REASON 0x4402UL
#define KSW_L2_EXIT_INTR_INFO 0x4404UL
#define KSW_L2_EXIT_INTR_ERROR 0x4406UL
#define KSW_L2_IDT_VECTORING_INFO 0x4408UL
#define KSW_L2_IDT_VECTORING_ERROR 0x440AUL
#define KSW_L2_EXIT_INSTRUCTION_LENGTH 0x440CUL
#define KSW_L2_EXIT_INSTRUCTION_INFO 0x440EUL
#define KSW_L2_EXIT_QUALIFICATION 0x6400UL
#define KSW_L2_GUEST_LINEAR_ADDRESS 0x640AUL
#define KSW_L2_GUEST_PHYSICAL_ADDRESS 0x2400UL
#define KSW_L2_GUEST_RSP 0x681CUL
#define KSW_L2_GUEST_RIP 0x681EUL
#define KSW_L2_GUEST_RFLAGS 0x6820UL
#define KSW_L2_GUEST_CR0 0x6800UL
#define KSW_L2_GUEST_CR3 0x6802UL
#define KSW_L2_GUEST_CR4 0x6804UL
#define KSW_L2_GUEST_ACTIVITY_STATE 0x4826UL
#define KSW_L2_GUEST_INTERRUPTIBILITY 0x4824UL

/* Name the secondary control that turns on EPT for L2. */
#define KSW_L2_SECONDARY_ENABLE_EPT 0x00000002UL
/* Name the primary control that activates the secondary controls. */
#define KSW_L2_PRIMARY_ACTIVATE_SECONDARY 0x80000000UL

/*
 * Describe one field copied verbatim between vmcs12 and vmcs02.
 *
 * Guest state moves in both directions: into vmcs02 on entry so L2 runs with
 * the state L1 configured, and back into vmcs12 on reflection so L1 sees where
 * L2 got to.  One table serves both because the field list is identical.
 */
static const ULONG g_KswordL2GuestFields[] = {
    /* Segment selectors. */
    0x0800UL, 0x0802UL, 0x0804UL, 0x0806UL, 0x0808UL, 0x080AUL,
    0x080CUL, 0x080EUL,
    /* 64-bit guest state. */
    0x2802UL, 0x2804UL, 0x2806UL, 0x280AUL, 0x280CUL, 0x280EUL, 0x2810UL,
    /* Segment limits. */
    0x4800UL, 0x4802UL, 0x4804UL, 0x4806UL, 0x4808UL, 0x480AUL,
    0x480CUL, 0x480EUL, 0x4810UL, 0x4812UL,
    /* Access rights. */
    0x4814UL, 0x4816UL, 0x4818UL, 0x481AUL, 0x481CUL, 0x481EUL,
    0x4820UL, 0x4822UL,
    /* Interruptibility, activity state and SYSENTER selector. */
    0x4824UL, 0x4826UL, 0x482AUL,
    /* Control registers and segment bases. */
    0x6800UL, 0x6802UL, 0x6804UL, 0x6806UL, 0x6808UL, 0x680AUL,
    0x680CUL, 0x680EUL, 0x6810UL, 0x6812UL, 0x6814UL, 0x6816UL,
    0x6818UL, 0x681AUL, 0x681CUL, 0x681EUL, 0x6820UL, 0x6822UL,
    0x6824UL, 0x6826UL
};

/* Describe the host-state fields vmcs02 inherits from vmcs01 unchanged. */
static const ULONG g_KswordL2HostFields[] = {
    0x0C00UL, 0x0C02UL, 0x0C04UL, 0x0C06UL, 0x0C08UL, 0x0C0AUL, 0x0C0CUL,
    0x2C00UL, 0x2C02UL,
    0x4C00UL,
    0x6C00UL, 0x6C02UL, 0x6C04UL, 0x6C06UL, 0x6C08UL, 0x6C0AUL,
    0x6C0CUL, 0x6C0EUL, 0x6C10UL, 0x6C12UL, 0x6C14UL, 0x6C16UL
};

/*
 * Describe the control fields taken from vmcs12 without merging.
 *
 * These name behaviour that is entirely L1's business - which exceptions it
 * wants, what it injects, how it masks control-register bits - and none of
 * them can cause an exit to bypass us.  Controls that decide *whether we keep
 * control* are merged separately and never copied.
 */
static const ULONG g_KswordL2CopiedControlFields[] = {
    /* Exception bitmap and page-fault matching. */
    0x4004UL, 0x4006UL, 0x4008UL,
    /* Event injection. */
    0x4016UL, 0x4018UL, 0x401AUL,
    /* TPR threshold. */
    0x401CUL,
    /* TSC offset. */
    0x2010UL,
    /* Control-register masks and read shadows. */
    0x6000UL, 0x6002UL, 0x6004UL, 0x6006UL
};

/* Read one field of the currently loaded VMCS, or zero. */
static ULONGLONG
KswordARKHvmNestedL2Read(
    _In_ ULONG Field
    )
{
    SIZE_T value = 0U;

    /* Report zero for a field the processor refused to produce. */
    if (KswordARKHvmVmcsFieldLoad((SIZE_T)Field, &value) != 0U) {
        /* Return the deterministic value every failure path shares. */
        return 0ULL;
    }
    /* Return the exact field value. */
    return (ULONGLONG)value;
}

/* Write one field of the currently loaded VMCS, ignoring refusal. */
static VOID
KswordARKHvmNestedL2Write(
    _In_ ULONG Field,
    _In_ ULONGLONG Value
    )
{
    /*
     * A refused write is not escalated here.
     *
     * Fields differ across processor models, and vmcs02 is validated as a
     * whole by VM entry itself: if something essential did not land, VMLAUNCH
     * fails with an architectural error that goes straight back to L1.  That
     * is a better report than aborting the merge on the first optional field
     * this processor happens not to implement.
     */
    (void)KswordARKHvmVmcsFieldStore((SIZE_T)Field, (SIZE_T)Value);
}

/* Clamp one control field to what this processor actually permits. */
static ULONG
KswordARKHvmNestedL2ClampControl(
    _In_ ULONG Requested,
    _In_ ULONGLONG CapabilityMsr
    )
{
    const ULONG allowedZero = (ULONG)(CapabilityMsr & 0xFFFFFFFFULL);
    const ULONG allowedOne = (ULONG)(CapabilityMsr >> 32);

    /*
     * The low half forces bits on and the high half permits bits at all.
     *
     * Handing the hardware a control it does not support fails VM entry with
     * an error L1 cannot act on, because the control L1 asked for was legal on
     * L1's own view of the processor.  Clamping keeps the entry valid; the
     * caller separately refuses requests whose loss would change semantics.
     */
    return (Requested | allowedZero) & allowedOne;
}

ULONG
KswordARKHvmNestedL2Enter(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ BOOLEAN IsResume
    )
{
    KSW_HVM_NESTED_VCPU* nested = &Context->Nested;
    KSW_HVM_VMCS12_STATE* vmcs12 = &nested->Vmcs12;
    ULONGLONG hostFields[RTL_NUMBER_OF(g_KswordL2HostFields)] = { 0 };
    ULONGLONG vmcs01Physical = 0ULL;
    ULONGLONG vmcs02Physical = 0ULL;
    ULONGLONG value = 0ULL;
    ULONGLONG eptPointer = 0ULL;
    ULONG primary = 0UL;
    ULONG secondary = 0UL;
    ULONG index = 0UL;

    /* Refuse an entry whose launch state does not match the instruction. */
    if (IsResume && !vmcs12->Launched) {
        /* Return the exact resume-before-launch error. */
        return KSW_L2_ERROR_VMRESUME_NONLAUNCHED_VMCS;
    }
    if (!IsResume && vmcs12->Launched) {
        /* Return the exact launch-on-launched error. */
        return KSW_L2_ERROR_VMLAUNCH_NONCLEAR_VMCS;
    }
    /* Refuse without the resources L2 execution needs. */
    if (Context->Resource == NULL ||
        Context->Resource->Vmcs02Virtual == NULL ||
        Context->PhysWindow == NULL) {
        /* Return the exact unavailable-resource error. */
        return KSW_L2_ERROR_INVALID_CONTROL_FIELDS;
    }
    vmcs01Physical = (ULONGLONG)Context->Resource->VmcsPhysical.QuadPart;
    vmcs02Physical = (ULONGLONG)Context->Resource->Vmcs02Physical.QuadPart;
    (void)KswordARKHvmNestedVmcs12Read(vmcs12, KSW_L2_PRIMARY_CONTROLS, &value);
    primary = (ULONG)value;
    value = 0ULL;
    if ((primary & KSW_L2_PRIMARY_ACTIVATE_SECONDARY) != 0UL) {
        (void)KswordARKHvmNestedVmcs12Read(
            vmcs12,
            KSW_L2_SECONDARY_CONTROLS,
            &value);
        secondary = (ULONG)value;
    }
    /*
     * Arm the shadow hierarchy when L1 asked for EPT, and use our own when it
     * did not.
     *
     * Without EPT12, L2 physical addresses are L1 physical addresses, so our
     * own identity hierarchy already describes them correctly - composing a
     * shadow would produce the same mapping at the cost of a fault per page.
     */
    if ((secondary & KSW_L2_SECONDARY_ENABLE_EPT) != 0UL) {
        value = 0ULL;
        (void)KswordARKHvmNestedVmcs12Read(
            vmcs12,
            KSW_L2_EPT_POINTER,
            &value);
        if (!NT_SUCCESS(KswordARKHvmNestedEptSetL1Pointer(
                &nested->ShadowEpt,
                value))) {
            /* Return the exact unusable-EPT-pointer error. */
            return KSW_L2_ERROR_INVALID_CONTROL_FIELDS;
        }
        eptPointer = nested->ShadowEpt.ComposedEptPointer;
    } else {
        nested->ShadowEpt.Active = FALSE;
        eptPointer = (Context->EptLocal != NULL)
            ? Context->EptLocal->EptPointer
            : Context->Runtime->EptPointer;
    }
    /* Refuse rather than enter L2 without a hierarchy to run it under. */
    if (eptPointer == 0ULL) {
        /* Return the exact unusable-EPT-pointer error. */
        return KSW_L2_ERROR_INVALID_CONTROL_FIELDS;
    }
    /* Capture our host state while vmcs01 is still the loaded VMCS. */
    for (index = 0UL;
         index < RTL_NUMBER_OF(g_KswordL2HostFields);
         ++index) {
        hostFields[index] =
            KswordARKHvmNestedL2Read(g_KswordL2HostFields[index]);
    }
    /* Preserve where L1 must resume once L2 hands control back. */
    nested->L1ResumeRip =
        KswordARKHvmNestedL2Read(KSW_L2_GUEST_RIP) +
        KswordARKHvmNestedL2Read(KSW_L2_EXIT_INSTRUCTION_LENGTH);
    nested->L1ResumeRsp = KswordARKHvmNestedL2Read(KSW_L2_GUEST_RSP);
    nested->L1ResumeRflags = KswordARKHvmNestedL2Read(KSW_L2_GUEST_RFLAGS);
    nested->Vmcs01Physical = vmcs01Physical;
    /* Load vmcs02 and make every subsequent access address it. */
    if (__vmx_vmptrld(&vmcs02Physical) != 0) {
        /* Return the exact control-field error for an unusable vmcs02. */
        return KSW_L2_ERROR_INVALID_CONTROL_FIELDS;
    }
    /* Host state is always ours, never L1's. */
    for (index = 0UL;
         index < RTL_NUMBER_OF(g_KswordL2HostFields);
         ++index) {
        KswordARKHvmNestedL2Write(
            g_KswordL2HostFields[index],
            hostFields[index]);
    }
    /* Guest state is whatever L1 configured for L2. */
    for (index = 0UL;
         index < RTL_NUMBER_OF(g_KswordL2GuestFields);
         ++index) {
        value = 0ULL;
        (void)KswordARKHvmNestedVmcs12Read(
            vmcs12,
            g_KswordL2GuestFields[index],
            &value);
        KswordARKHvmNestedL2Write(g_KswordL2GuestFields[index], value);
    }
    /* Controls that cannot cost us control are L1's verbatim. */
    for (index = 0UL;
         index < RTL_NUMBER_OF(g_KswordL2CopiedControlFields);
         ++index) {
        value = 0ULL;
        (void)KswordARKHvmNestedVmcs12Read(
            vmcs12,
            g_KswordL2CopiedControlFields[index],
            &value);
        KswordARKHvmNestedL2Write(
            g_KswordL2CopiedControlFields[index],
            value);
    }
    /*
     * Controls that decide who keeps control are the union of both sides.
     *
     * Ours must all survive: an exit we rely on that L1 did not request still
     * has to reach us.  L1's must also survive: an exit L1 arranged for and
     * does not receive is a hypervisor silently losing its own guest.  The
     * union satisfies both, and the clamp keeps the result legal on this
     * processor.  Nothing here ever removes one of our bits.
     */
    value = 0ULL;
    (void)KswordARKHvmNestedVmcs12Read(vmcs12, KSW_L2_PIN_CONTROLS, &value);
    KswordARKHvmNestedL2Write(
        KSW_L2_PIN_CONTROLS,
        KswordARKHvmNestedL2ClampControl(
            (ULONG)value | Context->Runtime->ActiveControls.Pin,
            Context->Runtime->ActiveControls.PinCapability));
    KswordARKHvmNestedL2Write(
        KSW_L2_PRIMARY_CONTROLS,
        KswordARKHvmNestedL2ClampControl(
            primary | Context->Runtime->ActiveControls.Primary,
            Context->Runtime->ActiveControls.PrimaryCapability));
    KswordARKHvmNestedL2Write(
        KSW_L2_SECONDARY_CONTROLS,
        KswordARKHvmNestedL2ClampControl(
            secondary | Context->Runtime->ActiveControls.Secondary,
            Context->Runtime->ActiveControls.SecondaryCapability));
    value = 0ULL;
    (void)KswordARKHvmNestedVmcs12Read(vmcs12, KSW_L2_EXIT_CONTROLS, &value);
    KswordARKHvmNestedL2Write(
        KSW_L2_EXIT_CONTROLS,
        KswordARKHvmNestedL2ClampControl(
            (ULONG)value | Context->Runtime->ActiveControls.Exit,
            Context->Runtime->ActiveControls.ExitCapability));
    value = 0ULL;
    (void)KswordARKHvmNestedVmcs12Read(vmcs12, KSW_L2_ENTRY_CONTROLS, &value);
    KswordARKHvmNestedL2Write(
        KSW_L2_ENTRY_CONTROLS,
        KswordARKHvmNestedL2ClampControl(
            (ULONG)value | Context->Runtime->ActiveControls.Entry,
            Context->Runtime->ActiveControls.EntryCapability));
    /* The hierarchy is ours: either the composed shadow or our own. */
    KswordARKHvmNestedL2Write(KSW_L2_EPT_POINTER, eptPointer);
    /*
     * The link pointer is always the architectural empty value.
     *
     * L1 may have written its own; propagating it would tell the processor
     * that vmcs02 shadows a VMCS that does not exist from its point of view.
     */
    KswordARKHvmNestedL2Write(KSW_L2_VMCS_LINK_POINTER, ~0ULL);
    /* Publish that this processor is about to be running L2. */
    nested->InL2 = TRUE;
    nested->State = KSWORD_ARK_HVM_NESTED_STATE_L2_ACTIVE;
    nested->L2EntryCount += 1ULL;
    /*
     * Enter L2.  On success this does not return - the processor leaves for
     * L2 and comes back through the exit stub with vmcs02 loaded.
     */
    if (IsResume) {
        (void)__vmx_vmresume();
    } else {
        (void)__vmx_vmlaunch();
    }
    /* Entry failed, so nothing is running L2 and the claim must be undone. */
    nested->InL2 = FALSE;
    nested->State = KSWORD_ARK_HVM_NESTED_STATE_VMCS12_CURRENT;
    value = KswordARKHvmNestedL2Read(0x4400UL);
    (void)__vmx_vmptrld(&vmcs01Physical);
    /* Report whatever the processor said, or a generic control failure. */
    return (value != 0ULL)
        ? (ULONG)value
        : KSW_L2_ERROR_INVALID_HOST_STATE;
}

/*
 * Decide whether one L2 exit is L1's to receive.
 *
 * The question is ownership: did this exit happen because of a control *L1*
 * set, or only because of one we set?  Anything L1 asked for must reach L1,
 * and anything only we asked for must not - handing L1 an exit it never armed
 * makes it demultiplex an event it has no case for.
 */
static BOOLEAN
KswordARKHvmNestedL2ExitBelongsToL1(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ ULONG ExitReason
    )
{
    KSW_HVM_NESTED_VCPU* nested = &Context->Nested;

    switch (ExitReason) {
    case 48UL: {
        /*
         * An EPT violation is ours exactly when composing the leaf resolves
         * it.  A refusal means L1's own EPT12 denied the access, and that is
         * precisely the event L1 installed EPT to receive.
         */
        const ULONGLONG guestPhysical =
            KswordARKHvmNestedL2Read(KSW_L2_GUEST_PHYSICAL_ADDRESS);
        const ULONG access =
            (ULONG)(KswordARKHvmNestedL2Read(KSW_L2_EXIT_QUALIFICATION) &
                0x7ULL);

        if (!nested->ShadowEpt.Active) {
            /* Report our own hierarchy's violation as ours. */
            return FALSE;
        }
        if (KswordARKHvmNestedEptFill(
                Context->Runtime,
                &nested->ShadowEpt,
                Context->PhysWindow,
                guestPhysical,
                access)) {
            /* Report the satisfied violation as ours. */
            return FALSE;
        }
        /* Report the refused violation as L1's. */
        return TRUE;
    }
    case 18UL:
        /*
         * VMCALL from L2 is L1's.
         *
         * Our own hypercall surface belongs to the guest we host directly.  A
         * VMCALL two levels down is L1's guest talking to L1, and answering it
         * ourselves would impersonate L1 to its own guest.
         */
        return TRUE;
    default:
        break;
    }
    /*
     * Everything else goes to L1.
     *
     * The conservative direction is deliberate.  Handling an exit that was
     * L1's leaves L1 unaware that its guest did something it asked to see;
     * reflecting one that was ours costs L1 a spurious exit it will handle and
     * resume from.  The first is a silent correctness loss, the second is
     * overhead - so the default is to reflect.
     */
    return TRUE;
}

BOOLEAN
KswordARKHvmNestedL2Reflect(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ ULONG ExitReason
    )
{
    KSW_HVM_NESTED_VCPU* nested = &Context->Nested;
    KSW_HVM_VMCS12_STATE* vmcs12 = &nested->Vmcs12;
    ULONGLONG vmcs01Physical = nested->Vmcs01Physical;
    ULONG index = 0UL;

    /* Not an L2 exit at all, so there is nothing to route. */
    if (!nested->InL2) {
        /* Report that the caller owns this exit. */
        return FALSE;
    }
    /* Handle it ourselves on vmcs02 when it was never L1's. */
    if (!KswordARKHvmNestedL2ExitBelongsToL1(Context, ExitReason)) {
        /* Report that the caller owns this exit. */
        return FALSE;
    }
    /* Record where L2 got to so L1 can inspect and later resume it. */
    for (index = 0UL;
         index < RTL_NUMBER_OF(g_KswordL2GuestFields);
         ++index) {
        (void)KswordARKHvmNestedVmcs12Write(
            vmcs12,
            g_KswordL2GuestFields[index],
            KswordARKHvmNestedL2Read(g_KswordL2GuestFields[index]));
    }
    /* Record the exit itself in the fields L1 will read. */
    (void)KswordARKHvmNestedVmcs12Write(
        vmcs12,
        KSW_L2_EXIT_REASON,
        KswordARKHvmNestedL2Read(KSW_L2_EXIT_REASON));
    (void)KswordARKHvmNestedVmcs12Write(
        vmcs12,
        KSW_L2_EXIT_QUALIFICATION,
        KswordARKHvmNestedL2Read(KSW_L2_EXIT_QUALIFICATION));
    (void)KswordARKHvmNestedVmcs12Write(
        vmcs12,
        KSW_L2_EXIT_INTR_INFO,
        KswordARKHvmNestedL2Read(KSW_L2_EXIT_INTR_INFO));
    (void)KswordARKHvmNestedVmcs12Write(
        vmcs12,
        KSW_L2_EXIT_INTR_ERROR,
        KswordARKHvmNestedL2Read(KSW_L2_EXIT_INTR_ERROR));
    (void)KswordARKHvmNestedVmcs12Write(
        vmcs12,
        KSW_L2_IDT_VECTORING_INFO,
        KswordARKHvmNestedL2Read(KSW_L2_IDT_VECTORING_INFO));
    (void)KswordARKHvmNestedVmcs12Write(
        vmcs12,
        KSW_L2_IDT_VECTORING_ERROR,
        KswordARKHvmNestedL2Read(KSW_L2_IDT_VECTORING_ERROR));
    (void)KswordARKHvmNestedVmcs12Write(
        vmcs12,
        KSW_L2_EXIT_INSTRUCTION_LENGTH,
        KswordARKHvmNestedL2Read(KSW_L2_EXIT_INSTRUCTION_LENGTH));
    (void)KswordARKHvmNestedVmcs12Write(
        vmcs12,
        KSW_L2_EXIT_INSTRUCTION_INFO,
        KswordARKHvmNestedL2Read(KSW_L2_EXIT_INSTRUCTION_INFO));
    (void)KswordARKHvmNestedVmcs12Write(
        vmcs12,
        KSW_L2_GUEST_LINEAR_ADDRESS,
        KswordARKHvmNestedL2Read(KSW_L2_GUEST_LINEAR_ADDRESS));
    (void)KswordARKHvmNestedVmcs12Write(
        vmcs12,
        KSW_L2_GUEST_PHYSICAL_ADDRESS,
        KswordARKHvmNestedL2Read(KSW_L2_GUEST_PHYSICAL_ADDRESS));
    /* Go back to the VMCS that runs L1. */
    if (__vmx_vmptrld(&vmcs01Physical) != 0) {
        /*
         * Losing vmcs01 here is unrecoverable by design.
         *
         * There is no VMCS to resume and no state to report through, so the
         * only honest outcome is to stop claiming residency on this processor
         * rather than resume something undefined.
         */
        nested->InL2 = FALSE;
        /* Report the exit as consumed so the caller does not resume. */
        return FALSE;
    }
    /*
     * Put L1 at its own VM-exit handler.
     *
     * From L1's point of view its VMLAUNCH produced a VM exit, and a VM exit
     * loads the host state L1 wrote into vmcs12.  Resuming L1 at the
     * instruction after VMLAUNCH instead would be resuming it as though the
     * entry had failed, which is a different architectural event entirely.
     */
    {
        ULONGLONG hostRip = 0ULL;
        ULONGLONG hostRsp = 0ULL;
        ULONGLONG hostCr0 = 0ULL;
        ULONGLONG hostCr3 = 0ULL;
        ULONGLONG hostCr4 = 0ULL;

        (void)KswordARKHvmNestedVmcs12Read(vmcs12, 0x6C16UL, &hostRip);
        (void)KswordARKHvmNestedVmcs12Read(vmcs12, 0x6C14UL, &hostRsp);
        (void)KswordARKHvmNestedVmcs12Read(vmcs12, 0x6C00UL, &hostCr0);
        (void)KswordARKHvmNestedVmcs12Read(vmcs12, 0x6C02UL, &hostCr3);
        (void)KswordARKHvmNestedVmcs12Read(vmcs12, 0x6C04UL, &hostCr4);
        KswordARKHvmNestedL2Write(KSW_L2_GUEST_RIP, hostRip);
        KswordARKHvmNestedL2Write(KSW_L2_GUEST_RSP, hostRsp);
        KswordARKHvmNestedL2Write(KSW_L2_GUEST_CR0, hostCr0);
        KswordARKHvmNestedL2Write(KSW_L2_GUEST_CR3, hostCr3);
        KswordARKHvmNestedL2Write(KSW_L2_GUEST_CR4, hostCr4);
        /* A VM exit always lands with interrupts masked and no shadow. */
        KswordARKHvmNestedL2Write(KSW_L2_GUEST_RFLAGS, 0x2ULL);
        KswordARKHvmNestedL2Write(KSW_L2_GUEST_INTERRUPTIBILITY, 0ULL);
        KswordARKHvmNestedL2Write(KSW_L2_GUEST_ACTIVITY_STATE, 0ULL);
    }
    vmcs12->Launched = TRUE;
    nested->InL2 = FALSE;
    nested->State = KSWORD_ARK_HVM_NESTED_STATE_VMCS12_CURRENT;
    nested->L2ExitReflectedCount += 1ULL;
    /* Report that the exit was delivered and the caller must resume L1. */
    return TRUE;
}

#else

ULONG
KswordARKHvmNestedL2Enter(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ BOOLEAN IsResume
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(IsResume);
    /* Report the explicit unsupported-architecture control failure. */
    return 7UL;
}

BOOLEAN
KswordARKHvmNestedL2Reflect(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ ULONG ExitReason
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ExitReason);
    /* Report that the caller owns this exit. */
    return FALSE;
}

#endif
