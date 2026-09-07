#pragma once

#include "ark/ark_driver.h"

#define KSW_HVM_VMEXIT_REASON_BASIC_MASK 0x0000FFFFUL
#define KSW_HVM_VMEXIT_REASON_ENTRY_FAILURE 0x80000000UL
#define KSW_HVM_VMEXIT_REASON_VMCALL 18UL

#pragma pack(push, 1)
typedef struct _KSW_HVM_DESCRIPTOR_TABLE
{
    USHORT Limit;
    ULONGLONG Base;
} KSW_HVM_DESCRIPTOR_TABLE;

typedef struct _KSW_HVM_SEGMENT_SNAPSHOT
{
    KSW_HVM_DESCRIPTOR_TABLE Gdtr;
    KSW_HVM_DESCRIPTOR_TABLE Idtr;
    USHORT Es;
    USHORT Cs;
    USHORT Ss;
    USHORT Ds;
    USHORT Fs;
    USHORT Gs;
    USHORT Ldtr;
    USHORT Tr;
} KSW_HVM_SEGMENT_SNAPSHOT;
#pragma pack(pop)

typedef struct _KSW_HVM_VMCS_INPUT
{
    ULONGLONG VmxBasic;
    ULONGLONG Cr0Fixed0;
    ULONGLONG Cr0Fixed1;
    ULONGLONG Cr4Fixed0;
    ULONGLONG Cr4Fixed1;
    ULONGLONG EptPointer;
    ULONGLONG GuestStackPointer;
    ULONGLONG HostStackPointer;
    ULONGLONG GuestInstructionPointer;
    ULONGLONG HostInstructionPointer;
    ULONGLONG GuestRflags;
    /*
     * Page-directory base loaded into HOST_CR3 on every VM exit.  Must name an
     * address space that outlives residency - the System process one - not the
     * CR3 that happens to be current while the VMCS is written, which belongs
     * to whichever process asked for residency.  Zero is refused.
     */
    ULONGLONG HostCr3;
    ULONGLONG MsrBitmapPhysical;
    /*
     * Per-processor #VE information area.  Zero means the caller has none, in
     * which case the EPT-violation #VE control is never requested.
     */
    ULONGLONG VeInfoPhysical;
    /*
     * EPTP list published to VMFUNC.  Zero means the caller has none, in which
     * case VM functions are never requested.
     */
    ULONGLONG EptpListPhysical;
    /* CR0/CR4 bits owned by the hypervisor; the guest reads them from shadow. */
    ULONGLONG Cr0PinnedMask;
    ULONGLONG Cr4PinnedMask;
    /* Nonzero makes every address-space switch exit. Expensive by design. */
    UCHAR TrackCr3;
    /* Nonzero makes guest debug-register access exit. */
    UCHAR InterceptDr;
    UCHAR ResidentMode;
    UCHAR EnableNestedVmx;
    /*
     * Nonzero requests EPT-violation #VE.  This alone delivers nothing: a
     * violation still converts only on a leaf whose suppress-#VE bit is clear
     * (this driver sets it everywhere) and only when the information area is
     * not busy (allocation latches it busy).  Both must also be undone before
     * a single #VE can reach the guest.
     */
    UCHAR EnableVe;
    /*
     * Nonzero arms VM functions and EPTP switching.  VMFUNC performs no CPL
     * check, so arming this publishes every list entry to unprivileged guest
     * code.  Domains are forkable only in the narrowing direction, which is
     * what keeps that from being an escalation path.
     */
    UCHAR EnableVmFunctions;
    USHORT Reserved;
    /*
     * Interrupt descriptor table to install as HOST_IDTR_BASE, or zero to keep
     * using the guest's own.
     *
     * VMX root runs on whatever IDT this field names, and until now that was
     * the guest's - which is correct for everything the host does on purpose,
     * because the host raises no exceptions.  It stops being correct as soon
     * as something *sends* this processor an NMI: an NMI that lands while the
     * processor is in VMX root is not converted into a VM exit no matter what
     * the pin controls say, so it is delivered through this IDT, and the
     * guest's vector 2 belongs to Windows, which bugchecks 0x80 on an NMI it
     * cannot attribute.  Measured 2026-09-07 - that is exactly how the first
     * cross-processor flush attempt failed.
     *
     * A private IDT is therefore a precondition for sending NMIs at all, not
     * an optimization.  Zero keeps the previous behavior exactly.
     */
    ULONGLONG HostIdtBase;
} KSW_HVM_VMCS_INPUT;

typedef struct _KSW_HVM_VMEXIT_TELEMETRY
{
    ULONG Reason;
    ULONG InstructionLength;
    ULONG VmInstructionError;
    ULONG Reserved;
    ULONGLONG Qualification;
    ULONGLONG GuestRip;
    ULONGLONG GuestRsp;
} KSW_HVM_VMEXIT_TELEMETRY;

EXTERN_C_START

VOID
KswordARKHvmCaptureSegments(
    _Out_ KSW_HVM_SEGMENT_SNAPSHOT* Snapshot
    );

ULONGLONG
KswordARKHvmAsmReadSsp(
    VOID
    );

VOID
KswordARKHvmControlledGuestEntry(
    VOID
    );

VOID
KswordARKHvmVmExitEntry(
    VOID
    );

NTSTATUS
KswordARKHvmConfigureVmcs(
    _In_ const KSW_HVM_VMCS_INPUT* Input,
    _Out_ ULONG* VmInstructionError
    );

NTSTATUS
KswordARKHvmReadVmExitTelemetry(
    _Out_ KSW_HVM_VMEXIT_TELEMETRY* Telemetry
    );

EXTERN_C_END
