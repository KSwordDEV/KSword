/*++

Module Name:

    hvm_memory.h

Abstract:

    Declares ring -1 memory access: a private page-table window that reaches
    physical memory without calling the documented memory-manager routines.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL entry.

--*/

#pragma once

#include "hvm_runtime.h"

EXTERN_C_START

/*
 * Reserve the private window and discover the page-table self-map.  Failure is
 * not fatal: every access falls back to MmCopyMemory and reports that the
 * hook-free path was unavailable.
 */
VOID
KswordARKHvmMemoryInitialize(
    VOID
    );

/* Release the private window and restore its original page-table entry. */
VOID
KswordARKHvmMemoryShutdown(
    VOID
    );

/* Execute one versioned ring -1 memory request. */
NTSTATUS
KswordARKHvmMemoryExecute(
    _In_ const KSWORD_ARK_HVM_MEMORY_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_MEMORY_RESPONSE* Response
    );

EXTERN_C_END
