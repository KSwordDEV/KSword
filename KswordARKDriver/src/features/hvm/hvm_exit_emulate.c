/*++

Module Name:

    hvm_exit_emulate.c

Abstract:

    Emulates the VM exits a resident guest cannot avoid.  Enabling the MSR
    bitmap removes the RDMSR/WRMSR exit storm, which leaves INVD, XSETBV and
    out-of-bitmap MSR access as the only unconditional exits the dispatcher
    must complete instead of devirtualizing.  Every routine here runs in VMX
    root on the processor-owned host stack: no allocation, no waiting, and no
    instruction that can fault without an architecturally verified operand.

Environment:

    Kernel-mode Driver Framework, VMX root operation.

--*/

#include "hvm_exit_emulate.h"
/* VMCS access goes through the seam in hvm_vmcs.h, never the raw intrinsic. */
#include "hvm_vmcs.h"

#include "driver/KswordArkHvmControls.h"

#if defined(_M_AMD64)
#include <intrin.h>

/* Name the VM-entry interruption-information field. */
#define KSW_VMCS_ENTRY_INTERRUPTION_INFO 0x4016UL
/* Name the VM-entry exception error-code field. */
#define KSW_VMCS_ENTRY_EXCEPTION_ERROR 0x4018UL
/* Name the VM-entry instruction-length field. */
#define KSW_VMCS_ENTRY_INSTRUCTION_LENGTH 0x401AUL

/* Mark an injected event as valid. */
#define KSW_HVM_INJECT_VALID (1UL << 31)
/* Select the hardware-exception interruption type. */
#define KSW_HVM_INJECT_HARDWARE_EXCEPTION (3UL << 8)
/* Mark that an error code accompanies the injected exception. */
#define KSW_HVM_INJECT_DELIVER_ERROR (1UL << 11)

/* Identify the invalid-opcode exception vector. */
#define KSW_HVM_VECTOR_UD 6UL
/* Identify the general-protection exception vector. */
#define KSW_HVM_VECTOR_GP 13UL
/* Identify the page-fault exception vector. */
#define KSW_HVM_VECTOR_PF 14UL

/* Mark the faulting page as present in the guest's own page tables. */
#define KSW_HVM_PF_PRESENT 0x1UL
/* Mark the denied access as a write. */
#define KSW_HVM_PF_WRITE 0x2UL
/* Mark the denied access as user-mode. */
#define KSW_HVM_PF_USER 0x4UL
/* Mark the denied access as an instruction fetch. */
#define KSW_HVM_PF_INSTRUCTION 0x10UL

/*
 * Bound the architectural MSR bitmap coverage.  A bitmap page describes
 * 0x00000000-0x00001FFF and 0xC0000000-0xC0001FFF only; every other index
 * exits unconditionally and reaches this module.
 */
#define KSW_HVM_MSR_LOW_LIMIT 0x00001FFFUL
/* Name the first index of the architectural high MSR bitmap range. */
#define KSW_HVM_MSR_HIGH_BASE 0xC0000000UL
/* Name the last index of the architectural high MSR bitmap range. */
#define KSW_HVM_MSR_HIGH_LIMIT 0xC0001FFFUL

/* Name the extended-state enumeration CPUID leaf. */
#define KSW_HVM_CPUID_XSTATE_LEAF 0x0DUL

/* Identify the x87 state bit that XCR0 must always keep set. */
#define KSW_XCR0_X87 (1ULL << 0)
/* Identify the SSE state bit required by every wider vector state. */
#define KSW_XCR0_SSE (1ULL << 1)
/* Identify the AVX state bit. */
#define KSW_XCR0_AVX (1ULL << 2)
/* Identify the AVX-512 opmask state bit. */
#define KSW_XCR0_OPMASK (1ULL << 5)
/* Identify the AVX-512 upper-256 state bit. */
#define KSW_XCR0_ZMM_HI256 (1ULL << 6)
/* Identify the AVX-512 high-register state bit. */
#define KSW_XCR0_HI16_ZMM (1ULL << 7)
/* Group every AVX-512 component that must move together. */
#define KSW_XCR0_AVX512 \
    (KSW_XCR0_OPMASK | KSW_XCR0_ZMM_HI256 | KSW_XCR0_HI16_ZMM)

BOOLEAN
KswordARKHvmExitInjectException(
    _In_ ULONG Vector,
    _In_ BOOLEAN DeliverErrorCode,
    _In_ ULONG ErrorCode
    )
{
    ULONG information =
        KSW_HVM_INJECT_VALID |
        KSW_HVM_INJECT_HARDWARE_EXCEPTION |
        (Vector & 0xFFUL);

    /* Attach the architectural error code only when the vector defines one. */
    if (DeliverErrorCode) {
        /* Mark the entry-interruption information as carrying an error code. */
        information |= KSW_HVM_INJECT_DELIVER_ERROR;
        /* Publish the exact error code consumed by VM entry. */
        if (KswordARKHvmVmcsFieldStore(
                KSW_VMCS_ENTRY_EXCEPTION_ERROR,
                (SIZE_T)ErrorCode) != 0U) {
            /* Report failure without leaving a half-written injection. */
            return FALSE;
        }
    }
    /*
     * A hardware exception restarts the faulting instruction, so the guest RIP
     * must stay where the exit left it and the instruction length must be zero.
     */
    if (KswordARKHvmVmcsFieldStore(
            KSW_VMCS_ENTRY_INSTRUCTION_LENGTH,
            0U) != 0U) {
        /* Report failure before arming the injection. */
        return FALSE;
    }
    /* Arm the injection consumed by the next VM entry. */
    return KswordARKHvmVmcsFieldStore(
        KSW_VMCS_ENTRY_INTERRUPTION_INFO,
        (SIZE_T)information) == 0U;
}

BOOLEAN
KswordARKHvmExitInjectUndefinedOpcode(
    VOID
    )
{
    /* Deliver #UD, which carries no architectural error code. */
    return KswordARKHvmExitInjectException(
        KSW_HVM_VECTOR_UD,
        FALSE,
        0UL);
}

BOOLEAN
KswordARKHvmExitInjectGeneralProtection(
    VOID
    )
{
    /* Deliver #GP with the zero selector error code used by MSR faults. */
    return KswordARKHvmExitInjectException(
        KSW_HVM_VECTOR_GP,
        TRUE,
        0UL);
}

BOOLEAN
KswordARKHvmExitInjectPageFault(
    _In_ ULONGLONG GuestLinearAddress,
    _In_ ULONG Access
    )
{
    /*
     * The page is present in the guest's own page tables - EPT is what refused
     * the access - so the fault must say present, or the guest handler would
     * try to fault the page in and loop.
     */
    ULONG errorCode = KSW_HVM_PF_PRESENT;

    /* Report a write fault when the denied access attempted to write. */
    if ((Access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
        /* Mark the architectural write bit. */
        errorCode |= KSW_HVM_PF_WRITE;
    }
    /* Report an instruction fetch when the denied access attempted to run. */
    if ((Access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL) {
        /* Mark the architectural instruction-fetch bit. */
        errorCode |= KSW_HVM_PF_INSTRUCTION;
    }
    /*
     * The canonical half of the address is the only privilege evidence
     * available here: an EPT violation reports no CPL.  Kernel addresses
     * therefore produce a supervisor fault and user addresses a user fault,
     * which is what the guest would have taken natively.
     */
    if ((GuestLinearAddress & 0x8000000000000000ULL) == 0ULL) {
        /* Mark the architectural user-mode bit. */
        errorCode |= KSW_HVM_PF_USER;
    }
    /*
     * CR2 is not a VMCS field: VM exit does not save it and VM entry does not
     * load it, so guest and host share the physical register.  Writing it here
     * is exactly what the guest's page-fault handler will read.
     */
    __writecr2((ULONG_PTR)GuestLinearAddress);
    /* Deliver the page fault with its complete architectural error code. */
    return KswordARKHvmExitInjectException(
        KSW_HVM_VECTOR_PF,
        TRUE,
        errorCode);
}

BOOLEAN
KswordARKHvmExitEmulateInvd(
    VOID
    )
{
    /*
     * INVD exits unconditionally and discards cache lines without writing
     * them back.  Replaying it in root operation would drop dirty lines that
     * belong to the host, so complete the guest's intent with WBINVD instead:
     * the caches end up clean either way and no modified data is lost.
     */
    __wbinvd();
    /* Report a completely emulated instruction. */
    return TRUE;
}

BOOLEAN
KswordARKHvmExitEmulateXsetbv(
    _In_ const KSW_HVM_GPR_FRAME* Frame,
    _Out_ BOOLEAN* InjectFault
    )
{
    int registers[4] = { 0 };
    ULONGLONG requested = 0ULL;
    ULONGLONG supported = 0ULL;

    /* Refuse to run without both the register frame and a fault channel. */
    if (Frame == NULL ||
        InjectFault == NULL) {
        /* Report an unusable emulation request. */
        return FALSE;
    }
    /* Start with no pending architectural fault. */
    *InjectFault = FALSE;
    /* Only XCR0 is architecturally defined; every other index faults. */
    if ((ULONG)Frame->Rcx != 0UL) {
        /* Request the architectural #GP for an undefined XCR index. */
        *InjectFault = TRUE;
        /* Report that no register state was changed. */
        return FALSE;
    }
    /* Rebuild the 64-bit value from the architectural EDX:EAX pair. */
    requested =
        ((ULONGLONG)(ULONG)Frame->Rdx << 32) |
        (ULONGLONG)(ULONG)Frame->Rax;
    /* Read the exact extended-state components this processor supports. */
    __cpuidex(
        registers,
        (int)KSW_HVM_CPUID_XSTATE_LEAF,
        0);
    /* Combine the reported low and high support masks. */
    supported =
        ((ULONGLONG)(ULONG)registers[3] << 32) |
        (ULONGLONG)(ULONG)registers[0];
    /*
     * Validate every architectural constraint before executing XSETBV in root
     * operation.  An unvalidated write faults on the host IDT inside VMX root,
     * which no continuation can recover.
     */
    if ((requested & ~supported) != 0ULL ||
        (requested & KSW_XCR0_X87) == 0ULL ||
        ((requested & KSW_XCR0_AVX) != 0ULL &&
            (requested & KSW_XCR0_SSE) == 0ULL) ||
        ((requested & KSW_XCR0_AVX512) != 0ULL &&
            ((requested & KSW_XCR0_AVX512) != KSW_XCR0_AVX512 ||
             (requested & KSW_XCR0_AVX) == 0ULL))) {
        /* Deliver the architectural #GP the guest would have received. */
        *InjectFault = TRUE;
        /* Report that no register state was changed. */
        return FALSE;
    }
    /* Apply the fully validated extended-state mask. */
    _xsetbv(0UL, requested);
    /* Report a completely emulated instruction. */
    return TRUE;
}

/*
 * Lowest index of the range architecturally reserved for hypervisor use.  The
 * whole 0x40000000-0x4FFFFFFF window belongs to whatever hypervisor is running
 * underneath - no physical MSR may live there - so an access that reaches this
 * routine with such an index was aimed at that hypervisor, not at us.
 */
#define KSW_HVM_HYPERVISOR_MSR_BASE  0x40000000UL
/* Highest index of that same reserved range. */
#define KSW_HVM_HYPERVISOR_MSR_LIMIT 0x4FFFFFFFUL

BOOLEAN
KswordARKHvmExitEmulateMsr(
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ BOOLEAN IsWrite,
    _In_ BOOLEAN HypervisorPresent,
    _Out_ BOOLEAN* InjectFault
    )
{
    ULONG index = 0UL;
    ULONGLONG value = 0ULL;

    /* Refuse to run without both the register frame and a fault channel. */
    if (Frame == NULL ||
        InjectFault == NULL) {
        /* Report an unusable emulation request. */
        return FALSE;
    }
    /* Start with no pending architectural fault. */
    *InjectFault = FALSE;
    /* The architectural MSR index always arrives in ECX. */
    index = (ULONG)Frame->Rcx;
    /*
     * Reaching this routine means the index fell outside both bitmap ranges,
     * because every in-range MSR is passed through natively.
     */
    if (KswordArkHvmMsrIndexIsCovered(index)) {
        /*
         * An in-range index can still arrive once a policy opens a bitmap
         * hole.  Until the policy engine owns those holes, treat the exit as
         * unhandled so the caller keeps its existing fail-closed behavior
         * instead of silently passing an intercepted access through.
         */
        return FALSE;
    }
    /*
     * The synthetic MSRs of the hypervisor beneath us live in the reserved
     * window and are unreachable through the bitmap, whose two halves only
     * describe 0x0-0x1FFF and 0xC0000000-0xC0001FFF, so every access to them
     * exits here.  Faulting them is what killed the resident guest: the
     * Windows we virtualize writes HV_X64_MSR_EOI on the way out of every
     * interrupt, and an unexpected #GP there is not survivable.
     *
     * Forwarding is a genuine relaxation and is deliberately narrow.  It is
     * confined to the reserved window, it requires an outer hypervisor to
     * actually be present - without one those indices really are undefined and
     * reading them in VMX root would fault on the host IDT with no
     * continuation - and every index outside the window keeps faulting exactly
     * as before.  Because the root context and the resident guest are the same
     * physical processor, executing the access here reaches the same synthetic
     * state the guest was addressing.
     */
    if (HypervisorPresent != FALSE &&
        index >= KSW_HVM_HYPERVISOR_MSR_BASE &&
        index <= KSW_HVM_HYPERVISOR_MSR_LIMIT) {
        __try {
            if (IsWrite != FALSE) {
                /* Rebuild the 64-bit operand from the architectural pair. */
                value = ((ULONGLONG)(ULONG)Frame->Rdx << 32) |
                        (ULONGLONG)(ULONG)Frame->Rax;
                /* Apply the guest write to the hypervisor beneath us. */
                __writemsr(index, value);
            } else {
                /* Read the value the guest asked the hypervisor for. */
                value = __readmsr(index);
                /* Publish the low half exactly as RDMSR would. */
                Frame->Rax = (ULONGLONG)(ULONG)value;
                /* Publish the high half exactly as RDMSR would. */
                Frame->Rdx = (ULONGLONG)(ULONG)(value >> 32);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /*
             * Best effort only.  A fault taken in VMX root operation dispatches
             * on the host IDT, and this driver already documents elsewhere that
             * such a fault has no reliable continuation - so this handler may
             * never run.  The actual protection is the narrowness of the gate
             * above it: an outer hypervisor must be present, and the index must
             * lie in the window reserved for that hypervisor, which is exactly
             * the set of indices it is obliged to implement for this processor.
             * The handler is kept because it costs nothing and converts the
             * recoverable subset into the architectural #GP.
             */
            *InjectFault = TRUE;
            /* Report that no register state was changed. */
            return FALSE;
        }
        /* Report a completely emulated instruction. */
        return TRUE;
    }
    /* Undefined MSR access faults identically for reads and writes. */
    UNREFERENCED_PARAMETER(HypervisorPresent);
    UNREFERENCED_PARAMETER(IsWrite);
    /* Request the architectural #GP for an undefined MSR index. */
    *InjectFault = TRUE;
    /* Report that no register state was changed. */
    return FALSE;
}

#else

BOOLEAN
KswordARKHvmExitInjectException(
    _In_ ULONG Vector,
    _In_ BOOLEAN DeliverErrorCode,
    _In_ ULONG ErrorCode
    )
{
    UNREFERENCED_PARAMETER(Vector);
    UNREFERENCED_PARAMETER(DeliverErrorCode);
    UNREFERENCED_PARAMETER(ErrorCode);
    return FALSE;
}

BOOLEAN
KswordARKHvmExitInjectUndefinedOpcode(
    VOID
    )
{
    return FALSE;
}

BOOLEAN
KswordARKHvmExitInjectGeneralProtection(
    VOID
    )
{
    return FALSE;
}

BOOLEAN
KswordARKHvmExitInjectPageFault(
    _In_ ULONGLONG GuestLinearAddress,
    _In_ ULONG Access
    )
{
    UNREFERENCED_PARAMETER(GuestLinearAddress);
    UNREFERENCED_PARAMETER(Access);
    return FALSE;
}

BOOLEAN
KswordARKHvmExitEmulateInvd(
    VOID
    )
{
    return FALSE;
}

BOOLEAN
KswordARKHvmExitEmulateXsetbv(
    _In_ const KSW_HVM_GPR_FRAME* Frame,
    _Out_ BOOLEAN* InjectFault
    )
{
    UNREFERENCED_PARAMETER(Frame);
    if (InjectFault != NULL) {
        *InjectFault = FALSE;
    }
    return FALSE;
}

BOOLEAN
KswordARKHvmExitEmulateMsr(
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ BOOLEAN IsWrite,
    _In_ BOOLEAN HypervisorPresent,
    _Out_ BOOLEAN* InjectFault
    )
{
    UNREFERENCED_PARAMETER(Frame);
    UNREFERENCED_PARAMETER(IsWrite);
    if (InjectFault != NULL) {
        *InjectFault = FALSE;
    }
    return FALSE;
}

#endif
