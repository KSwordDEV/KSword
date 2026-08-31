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
    UCHAR ResidentMode;
    UCHAR EnableNestedVmx;
    USHORT Reserved;
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
