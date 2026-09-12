/*++

Module Name:

    hvm_phys_window.h

Abstract:

    Defines a per-processor window that maps one guest physical page into the
    VM-exit handler's address space without taking a lock or calling the memory
    manager.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

/* Name every outcome one window mapping can produce. */
#define KSW_HVM_PHYS_WINDOW_OK 0UL
/* Report that the window was never prepared, so no mapping exists. */
#define KSW_HVM_PHYS_WINDOW_NOT_PREPARED 1UL
/* Report that another mapping on this processor is still open. */
#define KSW_HVM_PHYS_WINDOW_BUSY 2UL
/* Report that the request would run past the end of one page. */
#define KSW_HVM_PHYS_WINDOW_CROSSES_PAGE 3UL
/* Report a physical address the architecture cannot encode. */
#define KSW_HVM_PHYS_WINDOW_BAD_ADDRESS 4UL
/* Report that the backing entry no longer maps the backing page. */
#define KSW_HVM_PHYS_WINDOW_ENTRY_DRIFTED 5UL

/*
 * Preserve one processor's physical mapping window.
 *
 * One window per processor, never shared.  Sharing would force a lock, and a
 * lock is exactly what this exists to avoid: the IOCTL-path window in
 * hvm_memory.c serializes with KeAcquireSpinLock, which in VMX root mode means
 * either an IRQL claim we cannot honour or a wait on a processor that may
 * itself be in root mode.
 */
typedef struct _KSW_HVM_PHYS_WINDOW
{
    /* Publish whether every field below is complete and verified. */
    BOOLEAN Prepared;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[3];
    /* Hold one at a time: set while a mapping is open, cleared on unmap. */
    volatile LONG Active;
    /* Preserve the reserved page this window rewrites the mapping of. */
    PVOID BackingVirtual;
    /* Preserve the reserved page's own frame for drift detection. */
    ULONGLONG BackingPhysical;
    /* Preserve the writable page-table entry that maps the reserved page. */
    volatile ULONGLONG* BackingEntry;
    /* Preserve the entry value to restore on every unmap. */
    ULONGLONG OriginalEntry;
    /* Preserve the last mapping outcome for post-mortem inspection. */
    ULONG LastResult;
    /* Preserve the last physical address this window was pointed at. */
    ULONGLONG LastPhysical;
} KSW_HVM_PHYS_WINDOW;

EXTERN_C_START

/*
 * Reserve one window per processor.  Driver initialization only.
 *
 * The lifetime is deliberately the driver's, not residency's.  Releasing a
 * window means MmFreeContiguousMemory, which requires PASSIVE_LEVEL, while the
 * residency teardown path can be reached from a power callback where that is
 * not guaranteed - the same constraint that already forces the host stacks to
 * come from the pool.  Binding these to driver load and unload keeps both ends
 * on paths where PASSIVE_LEVEL is certain, and residency only borrows them.
 *
 * Never fatal: a processor whose window fails verification simply has none,
 * and every caller must check.
 */
VOID
KswordARKHvmPhysWindowInitializeAll(
    VOID
    );

/* Restore every entry and release every reservation.  Driver unload only. */
VOID
KswordARKHvmPhysWindowShutdownAll(
    VOID
    );

/*
 * Return one processor's window, or NULL when that processor has none.
 *
 * The returned pointer is stable for the driver's lifetime, so a caller may
 * cache it - which is what the per-processor resident context does.
 */
KSW_HVM_PHYS_WINDOW*
KswordARKHvmPhysWindowForProcessor(
    _In_ ULONG ProcessorIndex
    );

/*
 * Point the window at one guest physical page and return a usable pointer.
 *
 * VM-exit safe: no allocation, no lock, no memory-manager call.  Returns one
 * of KSW_HVM_PHYS_WINDOW_*; the mapping exists only on OK, and every OK must
 * be paired with exactly one KswordARKHvmPhysWindowUnmap.
 */
ULONG
KswordARKHvmPhysWindowMap(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONG Bytes,
    _Outptr_result_maybenull_ volatile VOID** Mapped
    );

/* Restore the window's own mapping and release it for the next caller. */
VOID
KswordARKHvmPhysWindowUnmap(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window
    );

/* Read eight bytes of guest physical memory through the window. */
NTSTATUS
KswordARKHvmPhysWindowReadQword(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG PhysicalAddress,
    _Out_ ULONGLONG* Value
    );

/* Write eight bytes of guest physical memory through the window. */
NTSTATUS
KswordARKHvmPhysWindowWriteQword(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG Value
    );

EXTERN_C_END
