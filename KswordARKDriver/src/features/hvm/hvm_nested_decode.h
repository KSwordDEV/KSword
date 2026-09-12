/*++

Module Name:

    hvm_nested_decode.h

Abstract:

    Decodes the VM-exit instruction-information field into the operand that a
    VMX instruction named.  Every nested VMX instruction except VMXOFF,
    VMLAUNCH and VMRESUME carries an operand, so this decode is the shared
    prerequisite for all of them.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

/* Forward-declare the VM-exit register frame without creating include cycles. */
struct _KSW_HVM_GPR_FRAME;

/*
 * Name the two instruction-information layouts.
 *
 * Intel gives VMREAD and VMWRITE a different field layout from the rest: they
 * can name a register instead of memory, and they spend bits 6:3 and 31:28 on
 * the two register operands that the memory-only instructions leave undefined.
 * Decoding one with the other's layout reads undefined bits as if they meant
 * something, so the caller states which one it has.
 */
#define KSW_HVM_VMX_OPERAND_LAYOUT_MEMORY_ONLY 0UL
#define KSW_HVM_VMX_OPERAND_LAYOUT_VMREAD_WRITE 1UL

/* Preserve one decoded VMX instruction operand. */
typedef struct _KSW_HVM_VMX_OPERAND
{
    /* Record whether the instruction named a register instead of memory. */
    BOOLEAN IsRegister;
    /* Record the architectural register number when IsRegister is set. */
    UCHAR PrimaryRegister;
    /* Record the second register operand, used only by VMREAD and VMWRITE. */
    UCHAR SecondaryRegister;
    /* Record the operand address width in bytes: 2, 4 or 8. */
    UCHAR AddressSizeBytes;
    /* Record the segment register index the operand was relative to. */
    ULONG SegmentRegister;
    /* Record the computed guest linear address when IsRegister is clear. */
    ULONGLONG LinearAddress;
} KSW_HVM_VMX_OPERAND;

EXTERN_C_START

/*
 * Read one guest general-purpose register by its architectural number.
 *
 * Returns 0 on success, non-zero when the register could not be produced.
 *
 * This is exported rather than kept private because every nested instruction
 * that writes a result back to a register needs the same number-to-storage
 * mapping, and a second copy of that mapping is a second chance to get the
 * RSP hole wrong.
 */
UCHAR
KswordARKHvmNestedReadGpr(
    _In_ const struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG RegisterNumber,
    _Out_ ULONGLONG* Value
    );

/* Write one guest general-purpose register by its architectural number. */
UCHAR
KswordARKHvmNestedWriteGpr(
    _Inout_ struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG RegisterNumber,
    _In_ ULONGLONG Value
    );

/*
 * Read or write eight bytes of guest memory at a guest linear address.
 *
 * Returns STATUS_SUCCESS only when the access was actually performed.
 *
 * These are the VM-exit-safe accessors.  KswordARKHvmMemoryTranslate is not
 * one: it reads page-table entries through a shared window guarded by
 * KeAcquireSpinLock, and taking a spin lock in VMX root means either an IRQL
 * claim we cannot honour or a wait on a processor that may itself be in root
 * mode.  That module belongs to the IOCTL path.
 */
NTSTATUS
KswordARKHvmNestedReadGuestQword(
    _In_ ULONGLONG LinearAddress,
    _Out_ ULONGLONG* Value
    );

/* Write eight bytes of guest memory at a guest linear address. */
NTSTATUS
KswordARKHvmNestedWriteGuestQword(
    _In_ ULONGLONG LinearAddress,
    _In_ ULONGLONG Value
    );

/*
 * Decode the operand of the VMX instruction that caused the current exit.
 *
 * Reads the VM-exit instruction-information and exit-qualification fields of
 * the *current* VMCS, so it is only valid from inside a VM-exit handler.
 * Returns STATUS_SUCCESS only when every field it needed was actually read.
 */
NTSTATUS
KswordARKHvmNestedDecodeOperand(
    _In_ const struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG Layout,
    _Out_ KSW_HVM_VMX_OPERAND* Operand
    );

EXTERN_C_END
