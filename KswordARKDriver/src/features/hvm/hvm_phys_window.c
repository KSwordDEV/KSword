/*++

Module Name:

    hvm_phys_window.c

Abstract:

    Implements the per-processor VM-exit-safe physical mapping window.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_phys_window.h"
#include "hvm_memory.h"
#include "driver/KswordArkHvmControls.h"

#if defined(_M_AMD64)
#include <intrin.h>

/* Name the present bit of a page-table entry. */
#define KSW_HVM_PHYS_WINDOW_PRESENT 0x1ULL
/* Name the frame field of a page-table entry. */
#define KSW_HVM_PHYS_WINDOW_FRAME_MASK 0x000FFFFFFFFFF000ULL
/* Name the page size this window maps. */
#define KSW_HVM_PHYS_WINDOW_PAGE_BYTES 4096ULL

/* Bound the per-processor window table without dynamic allocation. */
#define KSW_HVM_PHYS_WINDOW_MAX_PROCESSORS 256UL

/* Preserve one window per processor for the driver's lifetime. */
static KSW_HVM_PHYS_WINDOW g_KswordHvmPhysWindows[
    KSW_HVM_PHYS_WINDOW_MAX_PROCESSORS];

/* Preserve how many windows were actually reserved. */
static ULONG g_KswordHvmPhysWindowCount;

/* Name the patterns the preparation self-test moves through the window. */
#define KSW_HVM_PHYS_WINDOW_PROBE_PATTERN 0x4B53575744574E31ULL
#define KSW_HVM_PHYS_WINDOW_PROBE_WRITEBACK 0x0F1E2D3C4B5A6978ULL

/*
 * Demonstrate that one prepared window actually works.  PASSIVE_LEVEL only.
 *
 * Verifying the leaf entry's frame proves we resolved *an* entry that maps the
 * reservation.  It does not prove that rewriting it moves the mapping, that
 * the invalidation retires the old translation, or that unmapping puts the
 * original mapping back - and each of those failing produces a window that
 * looks prepared and silently reads or writes the wrong page.  So the window
 * moves a known pattern through itself in both directions before it is kept.
 */
static BOOLEAN
KswordARKHvmPhysWindowSelfTest(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window
    )
{
    PHYSICAL_ADDRESS lowest = { 0 };
    PHYSICAL_ADDRESS highest = { 0 };
    PHYSICAL_ADDRESS boundary = { 0 };
    PHYSICAL_ADDRESS probePhysical = { 0 };
    volatile ULONGLONG* probe = NULL;
    volatile VOID* mapped = NULL;
    BOOLEAN passed = FALSE;

    highest.QuadPart = MAXLONGLONG;
    probe = (volatile ULONGLONG*)MmAllocateContiguousMemorySpecifyCache(
        (SIZE_T)KSW_HVM_PHYS_WINDOW_PAGE_BYTES,
        lowest,
        highest,
        boundary,
        MmCached);
    /* Report failure rather than keep an undemonstrated window. */
    if (probe == NULL) {
        /* Report that the window could not be demonstrated. */
        return FALSE;
    }
    RtlZeroMemory(
        (PVOID)(ULONG_PTR)probe,
        (SIZE_T)KSW_HVM_PHYS_WINDOW_PAGE_BYTES);
    probe[0] = KSW_HVM_PHYS_WINDOW_PROBE_PATTERN;
    probePhysical = MmGetPhysicalAddress((PVOID)(ULONG_PTR)probe);
    if (KswordARKHvmPhysWindowMap(
            Window,
            (ULONGLONG)probePhysical.QuadPart,
            (ULONG)sizeof(ULONGLONG),
            &mapped) == KSW_HVM_PHYS_WINDOW_OK) {
        /* The read direction: the window must see the probe's content. */
        if (*(volatile ULONGLONG*)mapped ==
                KSW_HVM_PHYS_WINDOW_PROBE_PATTERN) {
            /* The write direction: the probe must see the window's write. */
            *(volatile ULONGLONG*)mapped =
                KSW_HVM_PHYS_WINDOW_PROBE_WRITEBACK;
            passed = (probe[0] == KSW_HVM_PHYS_WINDOW_PROBE_WRITEBACK);
        }
        KswordARKHvmPhysWindowUnmap(Window);
        /*
         * And the restore: after unmapping, the reservation must once again
         * read as itself.  It was zeroed at allocation and never written
         * through its own address, so anything non-zero here means the entry
         * did not go back - a window that would corrupt whatever page it was
         * last pointed at, on every subsequent use.
         */
        if (passed &&
            *(volatile ULONGLONG*)Window->BackingVirtual != 0ULL) {
            passed = FALSE;
        }
    }
    MmFreeContiguousMemory((PVOID)(ULONG_PTR)probe);
    /* Report whether the window demonstrated every direction. */
    return passed;
}

/* Reserve and verify one window.  PASSIVE_LEVEL only. */
static NTSTATUS
KswordARKHvmPhysWindowPrepare(
    _Out_ KSW_HVM_PHYS_WINDOW* Window
    )
{
    PHYSICAL_ADDRESS lowest = { 0 };
    PHYSICAL_ADDRESS highest = { 0 };
    PHYSICAL_ADDRESS boundary = { 0 };
    PHYSICAL_ADDRESS backingPhysical = { 0 };
    ULONGLONG selfMapBase = 0ULL;
    volatile ULONGLONG* entry = NULL;
    ULONGLONG entryValue = 0ULL;

    /* Reject an incomplete caller contract before reserving anything. */
    if (Window == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Start from a deterministic, unusable window. */
    RtlZeroMemory(Window, sizeof(*Window));
    Window->LastResult = KSW_HVM_PHYS_WINDOW_NOT_PREPARED;
    /*
     * Reuse the self-map base the memory module already discovered.
     *
     * If that module's own window never came up, this one must not come up
     * either: without the base there is no way to name the entry that maps the
     * reservation, and guessing at it edits an entry that maps something else.
     */
    if (!KswordARKHvmMemorySelfMapBase(&selfMapBase)) {
        /* Return the explicit unavailable-prerequisite failure. */
        return STATUS_NOT_SUPPORTED;
    }
    /*
     * Reserve one contiguous page.
     *
     * Contiguous rather than pool because the window must own one independent
     * 4-KiB entry: a pool block can share a large-page mapping with unrelated
     * allocations, and rewriting that entry would move every one of them.
     */
    highest.QuadPart = MAXLONGLONG;
    Window->BackingVirtual = MmAllocateContiguousMemorySpecifyCache(
        (SIZE_T)KSW_HVM_PHYS_WINDOW_PAGE_BYTES,
        lowest,
        highest,
        boundary,
        MmCached);
    /* Leave the window unprepared when the reservation fails. */
    if (Window->BackingVirtual == NULL) {
        /* Return the exact allocation failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(
        Window->BackingVirtual,
        (SIZE_T)KSW_HVM_PHYS_WINDOW_PAGE_BYTES);
    backingPhysical = MmGetPhysicalAddress(Window->BackingVirtual);
    Window->BackingPhysical = (ULONGLONG)backingPhysical.QuadPart;
    /* Derive the writable entry that maps the reservation. */
    entry = (volatile ULONGLONG*)(ULONG_PTR)
        KswordArkHvmSelfMapEntryAddress(
            selfMapBase,
            (ULONGLONG)(ULONG_PTR)Window->BackingVirtual);
    /*
     * Probe the derived address before dereferencing it.
     *
     * If the reservation landed inside a large-page mapping there is no
     * 4-KiB table for it, and the derived address names a page that need not
     * exist - reading it would fault right here.  MmIsAddressValid is only
     * acceptable because this is the one-time PASSIVE_LEVEL path; it must
     * never appear on the mapping path.
     */
    if (!MmIsAddressValid((PVOID)(ULONG_PTR)entry)) {
        /* Release the reservation that cannot be used as a window. */
        MmFreeContiguousMemory(Window->BackingVirtual);
        Window->BackingVirtual = NULL;
        Window->BackingPhysical = 0ULL;
        /* Return the explicit resolution failure. */
        return STATUS_NOT_MAPPED_DATA;
    }
    entryValue = *entry;
    /*
     * Verify the derived entry before trusting it, and refuse otherwise.
     *
     * This is the one check that separates "we resolved our own entry" from
     * "we resolved some other page's entry".  Getting it wrong does not fault
     * - it silently repoints a mapping we do not own, and the damage surfaces
     * somewhere else entirely.  A large-page mapping fails the same test,
     * which is the correct outcome: the window cannot own a shared leaf.
     */
    if ((entryValue & KSW_HVM_PHYS_WINDOW_PRESENT) == 0ULL ||
        (entryValue & KSW_HVM_PHYS_WINDOW_FRAME_MASK) !=
            (Window->BackingPhysical & KSW_HVM_PHYS_WINDOW_FRAME_MASK)) {
        /* Release the reservation that cannot be used as a window. */
        MmFreeContiguousMemory(Window->BackingVirtual);
        Window->BackingVirtual = NULL;
        Window->BackingPhysical = 0ULL;
        /* Return the explicit verification failure. */
        return STATUS_DATA_ERROR;
    }
    Window->BackingEntry = entry;
    Window->OriginalEntry = entryValue;
    Window->LastResult = KSW_HVM_PHYS_WINDOW_OK;
    /*
     * Publish before the self-test, because the self-test maps through the
     * window and mapping refuses an unpublished one.  The failure path below
     * unpublishes again, so nothing outside this function can observe a
     * window that has not passed.
     */
    Window->Prepared = TRUE;
    /* Refuse to keep a window that cannot demonstrate it works. */
    if (!KswordARKHvmPhysWindowSelfTest(Window)) {
        *entry = entryValue;
        __invlpg(Window->BackingVirtual);
        Window->Prepared = FALSE;
        Window->BackingEntry = NULL;
        MmFreeContiguousMemory(Window->BackingVirtual);
        Window->BackingVirtual = NULL;
        Window->BackingPhysical = 0ULL;
        /* Return the explicit self-test failure. */
        return STATUS_DATA_ERROR;
    }
    /* Return a complete, verified window. */
    return STATUS_SUCCESS;
}

/* Restore the entry and release one reservation.  PASSIVE_LEVEL only. */
static VOID
KswordARKHvmPhysWindowRelease(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window
    )
{
    /* Nothing to release on a window that was never prepared. */
    if (Window == NULL || Window->BackingVirtual == NULL) {
        /* Return without touching an absent reservation. */
        return;
    }
    /*
     * Restore the entry before freeing the page, never after.
     *
     * The other order leaves a kernel mapping pointing at a physical page the
     * memory manager has taken back and may already have handed to someone
     * else - a window onto an arbitrary page, with nothing left to notice it.
     */
    if (Window->BackingEntry != NULL) {
        *Window->BackingEntry = Window->OriginalEntry;
        __invlpg(Window->BackingVirtual);
        Window->BackingEntry = NULL;
    }
    MmFreeContiguousMemory(Window->BackingVirtual);
    Window->BackingVirtual = NULL;
    Window->BackingPhysical = 0ULL;
    Window->Prepared = FALSE;
    Window->LastResult = KSW_HVM_PHYS_WINDOW_NOT_PREPARED;
    InterlockedExchange(&Window->Active, 0L);
}

VOID
KswordARKHvmPhysWindowInitializeAll(
    VOID
    )
{
    ULONG count = (ULONG)KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    ULONG index = 0UL;

    /* Bound the table rather than trust an unexpected processor count. */
    if (count > KSW_HVM_PHYS_WINDOW_MAX_PROCESSORS) {
        count = KSW_HVM_PHYS_WINDOW_MAX_PROCESSORS;
    }
    for (index = 0UL; index < count; ++index) {
        /*
         * A window that fails to verify is left unprepared and the rest
         * continue.  One processor without a window costs the features that
         * need it on that processor; refusing them all would cost every
         * processor for one processor's unusual layout.
         */
        (void)KswordARKHvmPhysWindowPrepare(
            &g_KswordHvmPhysWindows[index]);
    }
    g_KswordHvmPhysWindowCount = count;
}

VOID
KswordARKHvmPhysWindowShutdownAll(
    VOID
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < g_KswordHvmPhysWindowCount; ++index) {
        KswordARKHvmPhysWindowRelease(
            &g_KswordHvmPhysWindows[index]);
    }
    g_KswordHvmPhysWindowCount = 0UL;
}

KSW_HVM_PHYS_WINDOW*
KswordARKHvmPhysWindowForProcessor(
    _In_ ULONG ProcessorIndex
    )
{
    /* Report no window for an index outside the reserved table. */
    if (ProcessorIndex >= g_KswordHvmPhysWindowCount) {
        /* Return the explicit absence. */
        return NULL;
    }
    /* Report no window for a processor whose reservation failed. */
    if (!g_KswordHvmPhysWindows[ProcessorIndex].Prepared) {
        /* Return the explicit absence. */
        return NULL;
    }
    /* Return this processor's stable window. */
    return &g_KswordHvmPhysWindows[ProcessorIndex];
}

ULONG
KswordARKHvmPhysWindowMap(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONG Bytes,
    _Outptr_result_maybenull_ volatile VOID** Mapped
    )
{
    ULONGLONG offset = 0ULL;
    ULONGLONG observed = 0ULL;
    ULONGLONG mappedEntry = 0ULL;

    /* Start from a deterministic result for every failure path. */
    if (Mapped != NULL) {
        *Mapped = NULL;
    }
    /* Refuse a window that is not complete, and refuse a broken contract. */
    if (Window == NULL || Mapped == NULL || !Window->Prepared ||
        Window->BackingEntry == NULL) {
        if (Window != NULL) {
            Window->LastResult = KSW_HVM_PHYS_WINDOW_NOT_PREPARED;
        }
        /* Report that no mapping exists. */
        return KSW_HVM_PHYS_WINDOW_NOT_PREPARED;
    }
    offset = PhysicalAddress & (KSW_HVM_PHYS_WINDOW_PAGE_BYTES - 1ULL);
    /*
     * One mapping covers one page, and a crossing request is refused rather
     * than split.  Splitting would mean two mappings with a window of time
     * between them, and only the caller knows whether the guest may observe
     * or change the second page in that gap.
     */
    if (Bytes == 0UL ||
        (ULONGLONG)Bytes > KSW_HVM_PHYS_WINDOW_PAGE_BYTES - offset) {
        Window->LastResult = KSW_HVM_PHYS_WINDOW_CROSSES_PAGE;
        /* Report the refused crossing request. */
        return KSW_HVM_PHYS_WINDOW_CROSSES_PAGE;
    }
    /* Refuse a physical address with bits the architecture does not encode. */
    if ((PhysicalAddress &
            ~(KSW_HVM_PHYS_WINDOW_FRAME_MASK |
                (KSW_HVM_PHYS_WINDOW_PAGE_BYTES - 1ULL))) != 0ULL) {
        Window->LastResult = KSW_HVM_PHYS_WINDOW_BAD_ADDRESS;
        /* Report the refused address. */
        return KSW_HVM_PHYS_WINDOW_BAD_ADDRESS;
    }
    /*
     * Claim the window without waiting.
     *
     * Failing instead of spinning is the whole point.  A spin here would
     * reintroduce exactly the hazard that rules out the IOCTL-path window:
     * waiting inside VMX root on a holder that may also be in root mode.  The
     * window is per-processor, so the only way this can be contended is a
     * nested map inside one exit - a coding error, which should surface at the
     * call site rather than deadlock the machine.
     */
    if (InterlockedCompareExchange(&Window->Active, 1L, 0L) != 0L) {
        Window->LastResult = KSW_HVM_PHYS_WINDOW_BUSY;
        /* Report the contended window. */
        return KSW_HVM_PHYS_WINDOW_BUSY;
    }
    observed = *Window->BackingEntry;
    /*
     * Re-verify the entry on every mapping, not only at preparation.
     *
     * Windows owns this entry and may have rewritten it since - a large-page
     * promotion, a relocation, anything.  Editing it anyway would repoint
     * whatever now lives there.  Checking costs one read; not checking costs a
     * corruption with no symptom at the site that caused it.
     */
    if ((observed & KSW_HVM_PHYS_WINDOW_PRESENT) == 0ULL ||
        (observed & KSW_HVM_PHYS_WINDOW_FRAME_MASK) !=
            (Window->BackingPhysical & KSW_HVM_PHYS_WINDOW_FRAME_MASK)) {
        Window->LastResult = KSW_HVM_PHYS_WINDOW_ENTRY_DRIFTED;
        InterlockedExchange(&Window->Active, 0L);
        /* Report that the backing entry no longer belongs to this window. */
        return KSW_HVM_PHYS_WINDOW_ENTRY_DRIFTED;
    }
    /* Keep the original attribute bits and swap only the frame. */
    mappedEntry = (observed & ~KSW_HVM_PHYS_WINDOW_FRAME_MASK) |
        (PhysicalAddress & KSW_HVM_PHYS_WINDOW_FRAME_MASK);
    *Window->BackingEntry = mappedEntry;
    /* Retire the stale translation before the mapping is used. */
    __invlpg(Window->BackingVirtual);
    Window->LastPhysical = PhysicalAddress;
    Window->LastResult = KSW_HVM_PHYS_WINDOW_OK;
    *Mapped = (volatile VOID*)(ULONG_PTR)
        ((ULONGLONG)(ULONG_PTR)Window->BackingVirtual + offset);
    /* Report a complete mapping. */
    return KSW_HVM_PHYS_WINDOW_OK;
}

VOID
KswordARKHvmPhysWindowUnmap(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window
    )
{
    /* Ignore an unmap on a window that holds no mapping. */
    if (Window == NULL || !Window->Prepared ||
        Window->BackingEntry == NULL) {
        /* Return without restoring an absent mapping. */
        return;
    }
    *Window->BackingEntry = Window->OriginalEntry;
    /* Retire the mapping before another processor can observe it. */
    __invlpg(Window->BackingVirtual);
    InterlockedExchange(&Window->Active, 0L);
}

NTSTATUS
KswordARKHvmPhysWindowReadQword(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG PhysicalAddress,
    _Out_ ULONGLONG* Value
    )
{
    volatile VOID* mapped = NULL;
    ULONG result = KSW_HVM_PHYS_WINDOW_NOT_PREPARED;

    /* Reject an incomplete caller contract before mapping anything. */
    if (Value == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *Value = 0ULL;
    /* Refuse an unaligned access rather than split it across two mappings. */
    if ((PhysicalAddress & 0x7ULL) != 0ULL) {
        /* Return the explicit alignment failure. */
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    result = KswordARKHvmPhysWindowMap(
        Window,
        PhysicalAddress,
        (ULONG)sizeof(*Value),
        &mapped);
    /* Return without reading when no mapping was produced. */
    if (result != KSW_HVM_PHYS_WINDOW_OK) {
        /* Return the explicit mapping failure. */
        return STATUS_UNSUCCESSFUL;
    }
    *Value = *(volatile ULONGLONG*)mapped;
    KswordARKHvmPhysWindowUnmap(Window);
    /* Return the complete read. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmPhysWindowWriteQword(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG Value
    )
{
    volatile VOID* mapped = NULL;
    ULONG result = KSW_HVM_PHYS_WINDOW_NOT_PREPARED;

    /* Refuse an unaligned access rather than split it across two mappings. */
    if ((PhysicalAddress & 0x7ULL) != 0ULL) {
        /* Return the explicit alignment failure. */
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    result = KswordARKHvmPhysWindowMap(
        Window,
        PhysicalAddress,
        (ULONG)sizeof(Value),
        &mapped);
    /* Return without writing when no mapping was produced. */
    if (result != KSW_HVM_PHYS_WINDOW_OK) {
        /* Return the explicit mapping failure. */
        return STATUS_UNSUCCESSFUL;
    }
    *(volatile ULONGLONG*)mapped = Value;
    KswordARKHvmPhysWindowUnmap(Window);
    /* Return the complete write. */
    return STATUS_SUCCESS;
}

#else

VOID
KswordARKHvmPhysWindowInitializeAll(
    VOID
    )
{
}

VOID
KswordARKHvmPhysWindowShutdownAll(
    VOID
    )
{
}

KSW_HVM_PHYS_WINDOW*
KswordARKHvmPhysWindowForProcessor(
    _In_ ULONG ProcessorIndex
    )
{
    UNREFERENCED_PARAMETER(ProcessorIndex);
    /* Return the explicit absence on every non-x64 build. */
    return NULL;
}

ULONG
KswordARKHvmPhysWindowMap(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONG Bytes,
    _Outptr_result_maybenull_ volatile VOID** Mapped
    )
{
    UNREFERENCED_PARAMETER(Window);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Bytes);
    /* Zero the output so no caller dereferences uninitialized storage. */
    if (Mapped != NULL) {
        *Mapped = NULL;
    }
    /* Report that no mapping exists. */
    return KSW_HVM_PHYS_WINDOW_NOT_PREPARED;
}

VOID
KswordARKHvmPhysWindowUnmap(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window
    )
{
    UNREFERENCED_PARAMETER(Window);
}

NTSTATUS
KswordARKHvmPhysWindowReadQword(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG PhysicalAddress,
    _Out_ ULONGLONG* Value
    )
{
    UNREFERENCED_PARAMETER(Window);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    /* Zero the output so no caller reads uninitialized storage. */
    if (Value != NULL) {
        *Value = 0ULL;
    }
    /* Return the explicit unsupported-architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
KswordARKHvmPhysWindowWriteQword(
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG Value
    )
{
    UNREFERENCED_PARAMETER(Window);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Value);
    /* Return the explicit unsupported-architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

#endif
