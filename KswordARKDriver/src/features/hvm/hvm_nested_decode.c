/*++

Module Name:

    hvm_nested_decode.c

Abstract:

    Implements VM-exit instruction-information decoding for nested VMX
    instruction dispatch.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_nested_decode.h"
#include "hvm_exit.h"
/* VMCS access goes through the seam in hvm_vmcs.h, never the raw intrinsic. */
#include "hvm_vmcs.h"

#if defined(_M_AMD64)

/* Name the VM-exit instruction-information field. */
#define KSW_VMCS_VMX_INSTRUCTION_INFORMATION 0x440EUL
/* Name the exit-qualification field, which carries the displacement. */
#define KSW_VMCS_EXIT_QUALIFICATION 0x6400UL
/* Name the VMCS guest stack pointer, which is not in the register frame. */
#define KSW_VMCS_GUEST_RSP 0x681CUL

/*
 * Name the guest segment base fields.
 *
 * They are consecutive at a stride of two starting from ES, so the segment
 * register number out of the instruction-information field indexes them
 * directly.  The stride is asserted below rather than assumed.
 */
#define KSW_VMCS_GUEST_ES_BASE 0x6806UL
#define KSW_VMCS_GUEST_SEGMENT_BASE_STRIDE 2UL
/* Name the highest segment register number Intel encodes (GS). */
#define KSW_VMCS_GUEST_SEGMENT_MAX 5UL

/* Name the architectural register number that denotes RSP. */
#define KSW_HVM_GPR_NUMBER_RSP 4UL
/* Name the count of architectural general-purpose registers. */
#define KSW_HVM_GPR_COUNT 16UL

UCHAR
KswordARKHvmNestedReadGpr(
    _In_ const struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG RegisterNumber,
    _Out_ ULONGLONG* Value
    )
{
    /* Reject an incomplete caller contract before touching any storage. */
    if (Frame == NULL || Value == NULL) {
        /* Return the explicit contract failure. */
        return 1U;
    }
    *Value = 0ULL;
    /* Reject register numbers Intel does not encode. */
    if (RegisterNumber >= KSW_HVM_GPR_COUNT) {
        /* Return the explicit range failure. */
        return 1U;
    }
    /*
     * RSP is the hole in the frame, and it is a silent one.
     *
     * Intel numbers registers RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8..R15.
     * The VM-exit stub does not push RSP - it cannot, because the value that
     * matters is the guest's, and by the time the stub runs the stack pointer
     * is the host's.  The guest value lives in the VMCS instead.
     *
     * So the frame holds fifteen registers where Intel numbers sixteen, and
     * every number above four is shifted by one relative to a naive index.
     * Treating the frame as an array would hand back RBP for RSP, RSI for RBP,
     * and so on for the rest - wrong values, no error, for every instruction
     * whose operand used one of those registers as a base or index.
     */
    if (RegisterNumber == KSW_HVM_GPR_NUMBER_RSP) {
        SIZE_T guestRsp = 0U;

        /* Read the guest stack pointer from the only place that holds it. */
        if (KswordARKHvmVmcsFieldLoad(KSW_VMCS_GUEST_RSP, &guestRsp) != 0U) {
            /* Return the explicit VMCS read failure. */
            return 1U;
        }
        *Value = (ULONGLONG)guestRsp;
        /* Return the complete guest stack pointer. */
        return 0U;
    }
    switch (RegisterNumber) {
    case 0UL:  *Value = Frame->Rax; break;
    case 1UL:  *Value = Frame->Rcx; break;
    case 2UL:  *Value = Frame->Rdx; break;
    case 3UL:  *Value = Frame->Rbx; break;
    /* Case four is RSP and was handled above. */
    case 5UL:  *Value = Frame->Rbp; break;
    case 6UL:  *Value = Frame->Rsi; break;
    case 7UL:  *Value = Frame->Rdi; break;
    case 8UL:  *Value = Frame->R8;  break;
    case 9UL:  *Value = Frame->R9;  break;
    case 10UL: *Value = Frame->R10; break;
    case 11UL: *Value = Frame->R11; break;
    case 12UL: *Value = Frame->R12; break;
    case 13UL: *Value = Frame->R13; break;
    case 14UL: *Value = Frame->R14; break;
    case 15UL: *Value = Frame->R15; break;
    default:
        /* Return the explicit unreachable-number failure. */
        return 1U;
    }
    /* Return the complete register value. */
    return 0U;
}

UCHAR
KswordARKHvmNestedWriteGpr(
    _Inout_ struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG RegisterNumber,
    _In_ ULONGLONG Value
    )
{
    /* Reject an incomplete caller contract before touching any storage. */
    if (Frame == NULL || RegisterNumber >= KSW_HVM_GPR_COUNT) {
        /* Return the explicit contract failure. */
        return 1U;
    }
    /* RSP is written back through the VMCS for the same reason it is read. */
    if (RegisterNumber == KSW_HVM_GPR_NUMBER_RSP) {
        /* Return whatever the VMCS write reported, unmodified. */
        return KswordARKHvmVmcsFieldStore(
            KSW_VMCS_GUEST_RSP,
            (SIZE_T)Value);
    }
    switch (RegisterNumber) {
    case 0UL:  Frame->Rax = Value; break;
    case 1UL:  Frame->Rcx = Value; break;
    case 2UL:  Frame->Rdx = Value; break;
    case 3UL:  Frame->Rbx = Value; break;
    /* Case four is RSP and was handled above. */
    case 5UL:  Frame->Rbp = Value; break;
    case 6UL:  Frame->Rsi = Value; break;
    case 7UL:  Frame->Rdi = Value; break;
    case 8UL:  Frame->R8  = Value; break;
    case 9UL:  Frame->R9  = Value; break;
    case 10UL: Frame->R10 = Value; break;
    case 11UL: Frame->R11 = Value; break;
    case 12UL: Frame->R12 = Value; break;
    case 13UL: Frame->R13 = Value; break;
    case 14UL: Frame->R14 = Value; break;
    case 15UL: Frame->R15 = Value; break;
    default:
        /* Return the explicit unreachable-number failure. */
        return 1U;
    }
    /* Return the complete register write. */
    return 0U;
}

/*
 * Name the lowest canonical kernel-half linear address.
 *
 * Only kernel addresses are accepted by the guest accessors below, and the
 * reason is not hygiene - it is correctness.  See the comment on the accessor.
 */
#define KSW_HVM_KERNEL_ADDRESS_FLOOR 0xFFFF800000000000ULL

/*
 * Check that one guest linear address may be accessed from the exit handler.
 *
 * Two conditions, both load-bearing:
 *
 * Kernel half.  HOST_CR3 names the System address space, while GUEST_CR3 names
 * whatever process was current when the instruction executed.  Windows maps the
 * kernel half identically in every address space, so a kernel address resolves
 * to the same physical page under either - but a *user* address resolves to a
 * different process's page, or to nothing.  Dereferencing one here would read
 * some unrelated process's memory and report it as the operand.  VMX
 * instructions require CPL 0, so a user-range operand is already malformed;
 * refusing it costs nothing and closes the hole.
 *
 * Eight-byte alignment.  A split access across a page boundary can have the
 * first page present and the second not, which turns one refusal into a fault
 * in root mode.
 *
 * What this does NOT establish is that the page is present.  There is no
 * VM-exit-safe way to ask.  The exposure is bounded: the guest that supplies
 * this address is already running in ring 0 underneath us, so it can halt the
 * machine by a hundred cheaper routes than aiming a VMPTRLD at a paged-out
 * address.  This is the same position HyperPlatform and kHypervisor take; the
 * difference is that it is written down here.
 */
static BOOLEAN
KswordARKHvmNestedIsGuestAccessAllowed(
    _In_ ULONGLONG LinearAddress
    )
{
    /* Reject the user half, which HOST_CR3 does not name. */
    if (LinearAddress < KSW_HVM_KERNEL_ADDRESS_FLOOR) {
        /* Report the address as not accessible from here. */
        return FALSE;
    }
    /* Reject an unaligned eight-byte access. */
    if ((LinearAddress & 0x7ULL) != 0ULL) {
        /* Report the address as not accessible from here. */
        return FALSE;
    }
    /* Report that the access may proceed. */
    return TRUE;
}

NTSTATUS
KswordARKHvmNestedReadGuestQword(
    _In_ ULONGLONG LinearAddress,
    _Out_ ULONGLONG* Value
    )
{
    /* Reject an incomplete caller contract before any dereference. */
    if (Value == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *Value = 0ULL;
    /* Refuse an address this context cannot resolve correctly. */
    if (!KswordARKHvmNestedIsGuestAccessAllowed(LinearAddress)) {
        /* Return the explicit access refusal. */
        return STATUS_ACCESS_VIOLATION;
    }
    *Value = *(volatile ULONGLONG*)(ULONG_PTR)LinearAddress;
    /* Return the complete guest read. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmNestedWriteGuestQword(
    _In_ ULONGLONG LinearAddress,
    _In_ ULONGLONG Value
    )
{
    /* Refuse an address this context cannot resolve correctly. */
    if (!KswordARKHvmNestedIsGuestAccessAllowed(LinearAddress)) {
        /* Return the explicit access refusal. */
        return STATUS_ACCESS_VIOLATION;
    }
    *(volatile ULONGLONG*)(ULONG_PTR)LinearAddress = Value;
    /* Return the complete guest write. */
    return STATUS_SUCCESS;
}

/* Translate the encoded address-size field into a width in bytes. */
static UCHAR
KswordARKHvmNestedAddressSizeBytes(
    _In_ ULONG Encoded
    )
{
    /* Select the two-byte width Intel encodes as zero. */
    if (Encoded == 0UL) {
        /* Return sixteen-bit addressing. */
        return 2U;
    }
    /* Select the four-byte width Intel encodes as one. */
    if (Encoded == 1UL) {
        /* Return thirty-two-bit addressing. */
        return 4U;
    }
    /* Return sixty-four-bit addressing for every remaining encoding. */
    return 8U;
}

/* Truncate one address to the operand address width. */
static ULONGLONG
KswordARKHvmNestedTruncateAddress(
    _In_ ULONGLONG Address,
    _In_ UCHAR AddressSizeBytes
    )
{
    /* Select sixteen-bit truncation. */
    if (AddressSizeBytes == 2U) {
        /* Return the low sixteen bits. */
        return Address & 0xFFFFULL;
    }
    /* Select thirty-two-bit truncation. */
    if (AddressSizeBytes == 4U) {
        /* Return the low thirty-two bits. */
        return Address & 0xFFFFFFFFULL;
    }
    /* Return the untruncated sixty-four-bit address. */
    return Address;
}

NTSTATUS
KswordARKHvmNestedDecodeOperand(
    _In_ const struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG Layout,
    _Out_ KSW_HVM_VMX_OPERAND* Operand
    )
{
    SIZE_T rawInformation = 0U;
    SIZE_T rawQualification = 0U;
    ULONG information = 0UL;
    ULONG scaling = 0UL;
    ULONG segment = 0UL;
    ULONG indexRegister = 0UL;
    ULONG baseRegister = 0UL;
    BOOLEAN indexValid = FALSE;
    BOOLEAN baseValid = FALSE;
    ULONGLONG effectiveAddress = 0ULL;
    ULONGLONG component = 0ULL;
    SIZE_T segmentBase = 0U;

    /* Reject an incomplete caller contract before reading any VMCS field. */
    if (Frame == NULL || Operand == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Operand, sizeof(*Operand));
    /* Read the instruction-information field that describes the operand. */
    if (KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_VMX_INSTRUCTION_INFORMATION,
            &rawInformation) != 0U) {
        /* Return the explicit VMCS read failure. */
        return STATUS_UNSUCCESSFUL;
    }
    information = (ULONG)rawInformation;
    /* Decode the address width, which both layouts place at bits 9:7. */
    Operand->AddressSizeBytes = KswordARKHvmNestedAddressSizeBytes(
        (information >> 7) & 0x7UL);
    /*
     * Decode the register form, which only VMREAD and VMWRITE can take.
     *
     * Bit 10 is cleared to zero for the memory-only instructions, so reading
     * it under either layout is safe; what is not safe is reading bits 6:3 or
     * 31:28 under the memory-only layout, where Intel leaves them undefined.
     */
    if (Layout == KSW_HVM_VMX_OPERAND_LAYOUT_VMREAD_WRITE) {
        Operand->PrimaryRegister = (UCHAR)((information >> 3) & 0xFUL);
        Operand->SecondaryRegister = (UCHAR)((information >> 28) & 0xFUL);
        if (((information >> 10) & 0x1UL) != 0UL) {
            Operand->IsRegister = TRUE;
            /* Return the complete register-form operand. */
            return STATUS_SUCCESS;
        }
    }
    /* Decode the memory form shared by both layouts. */
    scaling = information & 0x3UL;
    segment = (information >> 15) & 0x7UL;
    indexRegister = (information >> 18) & 0xFUL;
    /* Intel sets the invalid bits to one, so valid is the cleared state. */
    indexValid = (((information >> 22) & 0x1UL) == 0UL);
    baseRegister = (information >> 23) & 0xFUL;
    baseValid = (((information >> 27) & 0x1UL) == 0UL);
    /* Read the displacement, which the exit qualification carries whole. */
    if (KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_EXIT_QUALIFICATION,
            &rawQualification) != 0U) {
        /* Return the explicit VMCS read failure. */
        return STATUS_UNSUCCESSFUL;
    }
    effectiveAddress = (ULONGLONG)rawQualification;
    /* Add the base register when the instruction named one. */
    if (baseValid) {
        if (KswordARKHvmNestedReadGpr(
                Frame,
                baseRegister,
                &component) != 0U) {
            /* Return the explicit register read failure. */
            return STATUS_UNSUCCESSFUL;
        }
        effectiveAddress += component;
    }
    /* Add the scaled index register when the instruction named one. */
    if (indexValid) {
        if (KswordARKHvmNestedReadGpr(
                Frame,
                indexRegister,
                &component) != 0U) {
            /* Return the explicit register read failure. */
            return STATUS_UNSUCCESSFUL;
        }
        effectiveAddress += (component << scaling);
    }
    /*
     * Truncate before adding the segment base, not after.
     *
     * The address-size attribute bounds the effective address that the
     * addressing expression produces; the segment base is then added to form a
     * linear address that is not itself truncated to that width.  Doing it in
     * the other order would mask off the high half of a long-mode FS or GS
     * base on any instruction that happened to use 32-bit addressing.
     */
    effectiveAddress = KswordARKHvmNestedTruncateAddress(
        effectiveAddress,
        Operand->AddressSizeBytes);
    Operand->SegmentRegister = segment;
    /* Reject a segment number Intel does not encode rather than index past. */
    if (segment > KSW_VMCS_GUEST_SEGMENT_MAX) {
        /* Return the explicit encoding failure. */
        return STATUS_UNSUCCESSFUL;
    }
    /* Read the base of the segment the operand was relative to. */
    if (KswordARKHvmVmcsFieldLoad(
            (SIZE_T)(KSW_VMCS_GUEST_ES_BASE +
                (segment * KSW_VMCS_GUEST_SEGMENT_BASE_STRIDE)),
            &segmentBase) != 0U) {
        /* Return the explicit VMCS read failure. */
        return STATUS_UNSUCCESSFUL;
    }
    Operand->LinearAddress = effectiveAddress + (ULONGLONG)segmentBase;
    /* Return the complete memory-form operand. */
    return STATUS_SUCCESS;
}

#else

UCHAR
KswordARKHvmNestedReadGpr(
    _In_ const struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG RegisterNumber,
    _Out_ ULONGLONG* Value
    )
{
    UNREFERENCED_PARAMETER(Frame);
    UNREFERENCED_PARAMETER(RegisterNumber);
    /* Reject a missing output before reporting the architecture boundary. */
    if (Value != NULL) {
        *Value = 0ULL;
    }
    /* Return the explicit unsupported-architecture failure. */
    return 1U;
}

UCHAR
KswordARKHvmNestedWriteGpr(
    _Inout_ struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG RegisterNumber,
    _In_ ULONGLONG Value
    )
{
    UNREFERENCED_PARAMETER(Frame);
    UNREFERENCED_PARAMETER(RegisterNumber);
    UNREFERENCED_PARAMETER(Value);
    /* Return the explicit unsupported-architecture failure. */
    return 1U;
}

NTSTATUS
KswordARKHvmNestedReadGuestQword(
    _In_ ULONGLONG LinearAddress,
    _Out_ ULONGLONG* Value
    )
{
    UNREFERENCED_PARAMETER(LinearAddress);
    /* Zero the output so no caller reads uninitialized operand state. */
    if (Value != NULL) {
        *Value = 0ULL;
    }
    /* Return the explicit unsupported-architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
KswordARKHvmNestedWriteGuestQword(
    _In_ ULONGLONG LinearAddress,
    _In_ ULONGLONG Value
    )
{
    UNREFERENCED_PARAMETER(LinearAddress);
    UNREFERENCED_PARAMETER(Value);
    /* Return the explicit unsupported-architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
KswordARKHvmNestedDecodeOperand(
    _In_ const struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG Layout,
    _Out_ KSW_HVM_VMX_OPERAND* Operand
    )
{
    UNREFERENCED_PARAMETER(Frame);
    UNREFERENCED_PARAMETER(Layout);
    /* Zero the output so no caller reads uninitialized operand state. */
    if (Operand != NULL) {
        RtlZeroMemory(Operand, sizeof(*Operand));
    }
    /* Return the explicit unsupported-architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

#endif
