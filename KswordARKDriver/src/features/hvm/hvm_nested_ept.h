/*++

Module Name:

    hvm_nested_ept.h

Abstract:

    Defines the shadow EPT that composes L1's EPT12 with our own EPT01 so the
    processor, which only walks one hierarchy, can run L2.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"
#include "hvm_phys_window.h"

/*
 * Bound the table pages one processor's shadow hierarchy may consume.
 *
 * Filling happens inside a VM exit, where allocation is not available, so
 * every table page has to exist before L2 starts.  The count covers a root
 * plus the interior tables an L2 working set touches; exhaustion is reported
 * as a denied violation rather than a crash, because the alternative to
 * "L2 cannot run this page" must not be "the host stops".
 */
#define KSW_HVM_NEPT_TABLE_PAGES 192UL

/* Preserve one processor's shadow-EPT composition state. */
typedef struct _KSW_HVM_SHADOW_EPT_STATE
{
    /* Record whether a composed hierarchy is armed for the current EPT12. */
    BOOLEAN Active;
    /* Record whether L1 supplied an EPT pointer at all. */
    BOOLEAN L1PointerValid;
    /* Keep the structure explicitly initialized across architectures. */
    USHORT Reserved0;
    /* Preserve the shadow-EPT generation. */
    ULONG Generation;
    /* Preserve the last invalidated generation. */
    ULONG InvalidationGeneration;
    /* Preserve the L1-provided EPT pointer exactly as L1 wrote it. */
    ULONGLONG L1EptPointer;
    /* Preserve KSword's own EPT pointer. */
    ULONGLONG L0EptPointer;
    /* Preserve the composed EPT pointer the processor loads for L2. */
    ULONGLONG ComposedEptPointer;
    /* Preserve the last composition status. */
    NTSTATUS LastStatus;
    /* Count leaves this hierarchy composed successfully. */
    ULONG FillCount;
    /* Count violations refused because L1's own mapping refused them. */
    ULONG DenyCount;
    /* Count violations refused because no table page remained. */
    ULONG ExhaustionCount;
    /* Retain the one nonpaged block every table page is carved from. */
    PVOID PageBlock;
    /* Retain how many pages the block holds. */
    ULONG PageTotal;
    /* Retain how many pages have been handed out. */
    ULONG PageUsed;
    /*
     * Retain each handed-out page's frame so an interior entry can be
     * navigated back to its table.
     *
     * MmGetVirtualForPhysical would answer the same question and is not
     * callable at the IRQL a VM exit runs at, so the answer is recorded when
     * it is cheap - at hand-out time - and looked up by a scan bounded to the
     * pages actually issued.
     */
    ULONGLONG PagePhysical[KSW_HVM_NEPT_TABLE_PAGES];
    /* Retain the composed hierarchy root. */
    PVOID RootVirtual;
    /* Retain the composed hierarchy root's physical address. */
    ULONGLONG RootPhysical;
} KSW_HVM_SHADOW_EPT_STATE;

EXTERN_C_START

/* Initialize explicit inactive shadow-EPT state. */
VOID
KswordARKHvmNestedEptInitialize(
    _Out_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L0EptPointer
    );

/* Reserve the table pages one processor's shadow needs.  PASSIVE_LEVEL. */
NTSTATUS
KswordARKHvmNestedEptPrepare(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    );

/* Release the reserved block.  Legal at DISPATCH_LEVEL. */
VOID
KswordARKHvmNestedEptRelease(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    );

/*
 * Record the EPT pointer L1 wrote into vmcs12 and arm composition.
 *
 * Changing the pointer drops every composed mapping: they described a
 * different EPT12 entirely, and keeping them would let L2 run on translations
 * the incoming hierarchy never authorized.
 */
NTSTATUS
KswordARKHvmNestedEptSetL1Pointer(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L1EptPointer
    );

/* Drop every composed mapping for one L1 invalidation request. */
VOID
KswordARKHvmNestedEptInvalidate(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    );

/*
 * Compose one leaf for an L2 guest physical address.  VM-exit safe.
 *
 * Returns TRUE when a mapping now exists and the faulting instruction may be
 * retried; FALSE when the violation belongs to L1 - either because EPT12 does
 * not permit the access or because no table page remained.
 */
BOOLEAN
KswordARKHvmNestedEptFill(
    _Inout_ struct _KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access
    );

EXTERN_C_END
