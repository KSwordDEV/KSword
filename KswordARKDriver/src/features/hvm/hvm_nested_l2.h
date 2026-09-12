/*++

Module Name:

    hvm_nested_l2.h

Abstract:

    Defines L2 entry from vmcs12 and the routing of L2 exits between us and L1.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"
#include "hvm_nested.h"

/* Forward-declare the per-processor resident context. */
struct _KSW_HVM_RESIDENT_VCPU;
/* Forward-declare the VM-exit register frame. */
struct _KSW_HVM_GPR_FRAME;

EXTERN_C_START

/*
 * Enter L2 from the current vmcs12.
 *
 * On success this does not return: the processor is running L2, and the next
 * thing that executes on this processor is the VM-exit stub.  On failure it
 * returns the Intel VM-instruction error L1 should observe, with vmcs01 loaded
 * again and nothing else disturbed.
 *
 * Returns zero only when a failure could not even be expressed, which the
 * caller reports as VMfailInvalid.
 */
ULONG
KswordARKHvmNestedL2Enter(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ BOOLEAN IsResume
    );

/*
 * Decide whether one L2 exit belongs to L1 and, when it does, deliver it.
 *
 * Returns TRUE when the exit was reflected: vmcs01 is loaded, L1's guest state
 * has been set to its own VM-exit handler, and the caller must resume.
 * Returns FALSE when the exit is ours to handle on vmcs02 as usual.
 */
BOOLEAN
KswordARKHvmNestedL2Reflect(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ ULONG ExitReason
    );

EXTERN_C_END
