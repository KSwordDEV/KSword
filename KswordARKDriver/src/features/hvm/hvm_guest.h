#pragma once

#include "ark/ark_driver.h"
#include "hvm_vmcs.h"

struct _KSW_HVM_RUNTIME;

typedef struct _KSW_HVM_GUEST_LAUNCH_INPUT
{
    USHORT ProcessorGroup;
    UCHAR ProcessorNumber;
    UCHAR NestedLaunch;
    PHYSICAL_ADDRESS VmxonPhysical;
    PHYSICAL_ADDRESS VmcsPhysical;
    ULONGLONG VmxBasic;
    ULONGLONG Cr0Fixed0;
    ULONGLONG Cr0Fixed1;
    ULONGLONG Cr4Fixed0;
    ULONGLONG Cr4Fixed1;
    ULONGLONG EptPointer;
    struct _KSW_HVM_RUNTIME* Runtime;
    LONG ExpectedPowerTransitionGeneration;
} KSW_HVM_GUEST_LAUNCH_INPUT;

typedef struct _KSW_HVM_GUEST_LAUNCH_RESULT
{
    NTSTATUS Status;
    UCHAR VmxInstructionResult;
    UCHAR VmcsLoaded;
    UCHAR GuestLaunched;
    UCHAR VmExitHandled;
    ULONG VmInstructionError;
    KSW_HVM_VMEXIT_TELEMETRY Exit;
} KSW_HVM_GUEST_LAUNCH_RESULT;

EXTERN_C_START

NTSTATUS
KswordARKHvmLaunchControlledGuest(
    _In_ const KSW_HVM_GUEST_LAUNCH_INPUT* Input,
    _Out_ KSW_HVM_GUEST_LAUNCH_RESULT* Result
    );

PVOID
KswordARKHvmVmExitDispatch(
    VOID
    );

UCHAR
KswordARKHvmAsmLaunch(
    _Inout_ PVOID Context
    );

EXTERN_C_END
