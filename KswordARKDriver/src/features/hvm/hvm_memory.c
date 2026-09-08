/*++

Module Name:

    hvm_memory.c

Abstract:

    Ring -1 memory access.

    The value here is not that the driver can read memory - it always could -
    but that it reaches memory without calling the documented memory-manager
    routines that another driver may have hooked.  One private page is reserved
    at load time; its page-table entry is rewritten to point at the target
    frame, the access is performed through that window, and the original entry
    is restored.

    Locating the window's own page-table entry requires the page-table self-map
    base, which recent Windows randomizes.  It is discovered once by scanning
    the 512 candidate PML4 slots for the one whose derived entry maps the
    window page itself.  When discovery fails - the window landed inside a
    large-page mapping, or the layout is unfamiliar - every access falls back to
    MmCopyMemory and the response says the hook-free path was not taken.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL entry.

--*/

#include "hvm_memory.h"

#include "driver/KswordArkHvmControls.h"

#include <intrin.h>

/*
 * Declared here rather than pulled in through ntifs.h, matching what
 * memory_pagetable.c already does in this driver: ntifs.h and ntddk.h do not
 * compose cleanly in a KMDF translation unit, and these three are the only
 * routines this file needs from it.  ApcState stays PVOID for the same reason
 * the existing declarations do - PRKAPC_STATE is not visible here.
 */
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID Process,
    _Out_ PVOID ApcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PVOID ApcState
    );

/* Name the architectural page size used by the window and its entries. */
#define KSW_HVM_MEMORY_PAGE_BYTES 0x1000ULL
/* Mask the canonical low 48 bits used to index the paging hierarchy. */
#define KSW_HVM_MEMORY_VA_INDEX_MASK 0x0000FFFFFFFFFFFFULL
/* Isolate the frame number inside a paging structure entry. */
#define KSW_HVM_MEMORY_ENTRY_FRAME_MASK 0x000FFFFFFFFFF000ULL
/* Identify the present bit of a paging structure entry. */
#define KSW_HVM_MEMORY_ENTRY_PRESENT 0x1ULL
/* Identify the writable bit of a paging structure entry. */
#define KSW_HVM_MEMORY_ENTRY_WRITABLE 0x2ULL
/* Identify the large-page bit shared by PDPT and PD entries. */
#define KSW_HVM_MEMORY_ENTRY_LARGE 0x80ULL
/* Identify the no-execute bit kept set on the data-only window. */
#define KSW_HVM_MEMORY_ENTRY_NO_EXECUTE 0x8000000000000000ULL
/*
 * Bound accepted physical addresses to the 52 bits current x64 paging encodes,
 * matching the limit the R0 physical-memory feature already enforces.
 */
#define KSW_HVM_MEMORY_PHYSICAL_MAX 0x000FFFFFFFFFFFFFULL
/* Tag the reserved window allocation for pool tracking. */
#define KSW_HVM_MEMORY_POOL_TAG 'MvHK'

/* Own the private window and the discovered self-map base. */
typedef struct _KSW_HVM_MEMORY_WINDOW
{
    /* Serialize every window rewrite; one page is shared by all callers. */
    KSPIN_LOCK Lock;
    /* Retain the reserved single-page virtual window. */
    PVOID WindowVirtual;
    /* Reference the writable page-table entry that maps the window. */
    volatile ULONGLONG* WindowEntry;
    /* Preserve the original entry restored at shutdown and after each use. */
    ULONGLONG OriginalEntry;
    /* Preserve the discovered page-table self-map base address. */
    ULONGLONG SelfMapBase;
    /* Publish whether the private window is usable. */
    BOOLEAN Ready;
    /* Keep the tail deterministic for crash-dump inspection. */
    UCHAR Reserved[7];
} KSW_HVM_MEMORY_WINDOW;

/* Own the single process-wide ring -1 memory window. */
static KSW_HVM_MEMORY_WINDOW g_KswordHvmMemory;

#if defined(_M_AMD64)

/* Derive the page-table entry address for one virtual address. */
static volatile ULONGLONG*
KswordARKHvmMemoryEntryAddress(
    _In_ ULONGLONG SelfMapBase,
    _In_ ULONGLONG VirtualAddress
    )
{
    /*
     * The arithmetic lives in KswordArkHvmControls.h so the host unit tests
     * cover the same code this file executes.  The step that matters is
     * masking off the sign extension before shifting: without it a kernel
     * address lands outside the self-map region, on an address that is often
     * still readable - so the mistake shows up as "the page table edit had no
     * effect" rather than as a fault.
     */
    return (volatile ULONGLONG*)(ULONG_PTR)
        KswordArkHvmSelfMapEntryAddress(SelfMapBase, VirtualAddress);
}

/*
 * Find the PML4 slot that maps the paging hierarchy onto itself.  Windows
 * randomizes it, so it is discovered rather than assumed: the correct slot is
 * the one whose derived leaf entry maps the probe page's own frame.
 */
static BOOLEAN
KswordARKHvmMemoryDiscoverSelfMap(
    _In_ PVOID Probe,
    _In_ ULONGLONG ProbeFrame,
    _Out_ ULONGLONG* SelfMapBase
    )
{
    ULONG index = 0UL;

    /* Start from a deterministic result for every failure path. */
    *SelfMapBase = 0ULL;
    for (index = 0UL; index < 512UL; ++index) {
        /* Build the self-map base implied by this candidate slot. */
        const ULONGLONG candidateBase =
            KswordArkHvmSelfMapBaseFromIndex(index);
        volatile ULONGLONG* entry = KswordARKHvmMemoryEntryAddress(
            candidateBase,
            (ULONGLONG)(ULONG_PTR)Probe);
        ULONGLONG value = 0ULL;

        /*
         * A wrong candidate usually points at unmapped memory, so the address
         * must be validated before it is dereferenced.  MmIsAddressValid is
         * only used during this one-time discovery, never on the access path.
         */
        if (!MmIsAddressValid((PVOID)(ULONG_PTR)entry)) {
            /* Continue with the next candidate slot. */
            continue;
        }
        /* Read the candidate leaf entry exactly once. */
        value = *entry;
        /* Reject entries that are not present. */
        if ((value & KSW_HVM_MEMORY_ENTRY_PRESENT) == 0ULL) {
            /* Continue with the next candidate slot. */
            continue;
        }
        /* Accept only the slot whose entry maps the probe page itself. */
        if (((value & KSW_HVM_MEMORY_ENTRY_FRAME_MASK) >> 12) != ProbeFrame) {
            /* Continue with the next candidate slot. */
            continue;
        }
        /* Publish the confirmed self-map base. */
        *SelfMapBase = candidateBase;
        /* Report a complete discovery. */
        return TRUE;
    }
    /* Report that no candidate slot mapped the probe page. */
    return FALSE;
}

/*
 * Copy one page-bounded span through the private window.  The caller owns the
 * spin lock, so the window cannot be repointed underneath this access.
 */
static NTSTATUS
KswordARKHvmMemoryCopyThroughWindow(
    _In_ ULONGLONG PhysicalAddress,
    _Inout_updates_bytes_(Length) VOID* Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN IsWrite
    )
{
    KSW_HVM_MEMORY_WINDOW* window = &g_KswordHvmMemory;
    const ULONGLONG frame = PhysicalAddress >> 12;
    const ULONG offset = (ULONG)(PhysicalAddress & 0xFFFULL);
    UCHAR* windowBytes = NULL;
    ULONGLONG entry = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Refuse a span that would cross the single mapped page. */
    if (Length == 0UL ||
        (ULONGLONG)offset + Length > KSW_HVM_MEMORY_PAGE_BYTES) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * Build the window entry from the original one so cache attributes and
     * ownership bits stay whatever the memory manager chose, and keep the page
     * writable and non-executable regardless of the direction of the access.
     */
    entry = (window->OriginalEntry & ~KSW_HVM_MEMORY_ENTRY_FRAME_MASK) |
        (frame << 12) |
        KSW_HVM_MEMORY_ENTRY_PRESENT |
        KSW_HVM_MEMORY_ENTRY_WRITABLE |
        KSW_HVM_MEMORY_ENTRY_NO_EXECUTE;
    /* Point the window at the target frame. */
    *window->WindowEntry = entry;
    /* Drop the stale translation for the window address on this processor. */
    __invlpg(window->WindowVirtual);
    /* Address the requested bytes inside the freshly mapped page. */
    windowBytes = (UCHAR*)window->WindowVirtual + offset;
    __try {
        if (IsWrite) {
            /* Publish caller bytes into the mapped physical page. */
            RtlCopyMemory(windowBytes, Buffer, Length);
        } else {
            /* Capture physical bytes into the caller buffer. */
            RtlCopyMemory(Buffer, windowBytes, Length);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Preserve the exact access failure. */
        status = GetExceptionCode();
    }
    /* Restore the original mapping before releasing the window. */
    *window->WindowEntry = window->OriginalEntry;
    /* Drop the target translation so no stale mapping survives the access. */
    __invlpg(window->WindowVirtual);
    /* Return the authoritative access result. */
    return status;
}

#endif

/* Copy one page-bounded span through the documented physical-copy path. */
static NTSTATUS
KswordARKHvmMemoryCopyFallback(
    _In_ ULONGLONG PhysicalAddress,
    _Out_writes_bytes_(Length) VOID* Buffer,
    _In_ ULONG Length
    )
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copied = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    /* Build the physical source descriptor. */
    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.PhysicalAddress.QuadPart = (LONGLONG)PhysicalAddress;
    __try {
        /* Read physical memory through the documented copy routine. */
        status = MmCopyMemory(
            Buffer,
            copyAddress,
            Length,
            MM_COPY_MEMORY_PHYSICAL,
            &copied);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Preserve the exact access failure. */
        status = GetExceptionCode();
        copied = 0U;
    }
    /* Reject a short read rather than returning partially filled bytes. */
    if (NT_SUCCESS(status) && copied != (SIZE_T)Length) {
        /* Report the incomplete transfer. */
        return STATUS_PARTIAL_COPY;
    }
    /* Return the authoritative access result. */
    return status;
}

/* Return whether one physical span stays inside the encodable address space. */
static BOOLEAN
KswordARKHvmMemoryIsPhysicalRangeValid(
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONG Length
    )
{
    /* Reject addresses beyond the architectural encoding limit. */
    if (PhysicalAddress > KSW_HVM_MEMORY_PHYSICAL_MAX) {
        /* Report an unusable span. */
        return FALSE;
    }
    /* Accept an empty span without further arithmetic. */
    if (Length == 0UL) {
        /* Report an acceptable empty span. */
        return TRUE;
    }
    /* Reject a span whose end would overflow the encoding limit. */
    if ((ULONGLONG)Length >
            KSW_HVM_MEMORY_PHYSICAL_MAX - PhysicalAddress + 1ULL) {
        /* Report an unusable span. */
        return FALSE;
    }
    /* Report an acceptable span. */
    return TRUE;
}

/*
 * Read eight bytes of physical memory for the page walk.  Paging structures
 * are read through the same window as everything else so the walk itself does
 * not depend on the routines this feature exists to avoid.
 */
static NTSTATUS
KswordARKHvmMemoryReadEntry(
    _In_ ULONGLONG PhysicalAddress,
    _Out_ ULONGLONG* Value
    )
{
#if defined(_M_AMD64)
    KSW_HVM_MEMORY_WINDOW* window = &g_KswordHvmMemory;
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Start from a deterministic value for every failure path. */
    *Value = 0ULL;
    /* Reject an entry address the architecture cannot encode. */
    if (!KswordARKHvmMemoryIsPhysicalRangeValid(
            PhysicalAddress,
            (ULONG)sizeof(*Value))) {
        /* Return the exact address-range failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Prefer the private window when it is available. */
    if (window->Ready) {
        /* Serialize the shared window against every other access. */
        KeAcquireSpinLock(&window->Lock, &oldIrql);
        /* Copy the eight-byte entry through the window. */
        status = KswordARKHvmMemoryCopyThroughWindow(
            PhysicalAddress,
            Value,
            (ULONG)sizeof(*Value),
            FALSE);
        /* Release the window for the next caller. */
        KeReleaseSpinLock(&window->Lock, oldIrql);
        /* Return the authoritative window result. */
        return status;
    }
    /* Fall back to the documented physical-copy path. */
    return KswordARKHvmMemoryCopyFallback(
        PhysicalAddress,
        Value,
        (ULONG)sizeof(*Value));
#else
    UNREFERENCED_PARAMETER(PhysicalAddress);
    *Value = 0ULL;
    return STATUS_NOT_SUPPORTED;
#endif
}

/*
 * Translate one virtual address using the supplied page-directory base.  Large
 * pages are resolved at the level that terminates the walk, so a 2 MiB or 1 GiB
 * mapping produces the same physical address the processor would use.
 */
NTSTATUS
KswordARKHvmMemoryTranslate(
    _In_ ULONGLONG DirectoryBase,
    _In_ ULONGLONG VirtualAddress,
    _Out_ ULONGLONG* PhysicalAddress,
    _Out_opt_ ULONGLONG* LeafEntry
    )
{
    ULONGLONG tableBase = DirectoryBase & KSW_HVM_MEMORY_ENTRY_FRAME_MASK;
    ULONGLONG entry = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG level = 0UL;
    /* Index shifts for PML4, PDPT, PD and PT in walk order. */
    static const ULONG shifts[4] = { 39UL, 30UL, 21UL, 12UL };

    /* Start from a deterministic value for every failure path. */
    *PhysicalAddress = 0ULL;
    if (LeafEntry != NULL) {
        *LeafEntry = 0ULL;
    }
    for (level = 0UL; level < 4UL; ++level) {
        /* Select this level's entry inside the current table. */
        const ULONGLONG index =
            (VirtualAddress >> shifts[level]) & 0x1FFULL;
        /* Read the exact entry that continues the walk. */
        status = KswordARKHvmMemoryReadEntry(
            tableBase + (index << 3),
            &entry);
        /* Stop as soon as one level cannot be read. */
        if (!NT_SUCCESS(status)) {
            /* Return the exact page-walk failure. */
            return status;
        }
        /* A not-present entry terminates the walk without a translation. */
        if ((entry & KSW_HVM_MEMORY_ENTRY_PRESENT) == 0ULL) {
            /* Report that the address is not mapped. */
            return STATUS_NOT_FOUND;
        }
        /* Resolve large pages at the level that terminates the walk. */
        if (level >= 1UL &&
            level <= 2UL &&
            (entry & KSW_HVM_MEMORY_ENTRY_LARGE) != 0ULL) {
            /* Keep only the offset bits this leaf size leaves unresolved. */
            const ULONGLONG offsetMask =
                (1ULL << shifts[level]) - 1ULL;

            /* Combine the leaf frame with the remaining offset bits. */
            *PhysicalAddress =
                ((entry & KSW_HVM_MEMORY_ENTRY_FRAME_MASK) & ~offsetMask) |
                (VirtualAddress & offsetMask);
            /* 把终止这次走表的那一项交出去，调用方据此判 NX / US。 */
            if (LeafEntry != NULL) {
                *LeafEntry = entry;
            }
            /* Report a complete large-page translation. */
            return STATUS_SUCCESS;
        }
        /* Descend into the next level of the hierarchy. */
        tableBase = entry & KSW_HVM_MEMORY_ENTRY_FRAME_MASK;
    }
    /* Combine the leaf frame with the four-KiB page offset. */
    *PhysicalAddress = tableBase | (VirtualAddress & 0xFFFULL);
    /* 四 KiB 路径上，循环结束时 entry 就是那一项。 */
    if (LeafEntry != NULL) {
        *LeafEntry = entry;
    }
    /* Report a complete four-KiB translation. */
    return STATUS_SUCCESS;
}

/* Copy one span of physical memory, splitting it at page boundaries. */
static NTSTATUS
KswordARKHvmMemoryCopyRange(
    _In_ ULONGLONG PhysicalAddress,
    _Inout_updates_bytes_(Length) UCHAR* Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN IsWrite,
    _Out_ ULONG* BytesTransferred,
    _Out_ BOOLEAN* UsedWindow
    )
{
#if defined(_M_AMD64)
    KSW_HVM_MEMORY_WINDOW* window = &g_KswordHvmMemory;
    ULONG completed = 0UL;
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Start from deterministic results for every failure path. */
    *BytesTransferred = 0UL;
    *UsedWindow = FALSE;
    /* Writes have no fallback: MmCopyMemory only reads physical memory. */
    if (IsWrite && !window->Ready) {
        /* Report that the only write path is unavailable. */
        return STATUS_NOT_SUPPORTED;
    }
    while (completed < Length) {
        /* Split the transfer at the next page boundary. */
        const ULONGLONG current = PhysicalAddress + completed;
        const ULONG pageRemainder =
            (ULONG)(KSW_HVM_MEMORY_PAGE_BYTES - (current & 0xFFFULL));
        const ULONG chunk = (Length - completed) < pageRemainder
            ? (Length - completed)
            : pageRemainder;

        if (window->Ready) {
            /* Serialize the shared window against every other access. */
            KeAcquireSpinLock(&window->Lock, &oldIrql);
            /* Copy this page-bounded chunk through the private window. */
            status = KswordARKHvmMemoryCopyThroughWindow(
                current,
                Buffer + completed,
                chunk,
                IsWrite);
            /* Release the window for the next caller. */
            KeReleaseSpinLock(&window->Lock, oldIrql);
            /* Record that the hook-free path carried this transfer. */
            *UsedWindow = TRUE;
        } else {
            /* Read this chunk through the documented physical-copy path. */
            status = KswordARKHvmMemoryCopyFallback(
                current,
                Buffer + completed,
                chunk);
        }
        /* Stop at the first chunk that could not be transferred. */
        if (!NT_SUCCESS(status)) {
            /* Publish exactly how many bytes completed before the failure. */
            *BytesTransferred = completed;
            /* Return the exact access failure. */
            return status;
        }
        /* Account the chunk that just completed. */
        completed += chunk;
    }
    /* Publish the fully completed transfer length. */
    *BytesTransferred = completed;
    /* Return the authoritative success result. */
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(IsWrite);
    *BytesTransferred = 0UL;
    *UsedWindow = FALSE;
    return STATUS_NOT_SUPPORTED;
#endif
}

VOID
KswordARKHvmMemoryInitialize(
    VOID
    )
{
#if defined(_M_AMD64)
    KSW_HVM_MEMORY_WINDOW* window = &g_KswordHvmMemory;
    PHYSICAL_ADDRESS lowest = { 0 };
    PHYSICAL_ADDRESS highest = { 0 };
    PHYSICAL_ADDRESS boundary = { 0 };
    PHYSICAL_ADDRESS windowPhysical = { 0 };
    ULONGLONG selfMapBase = 0ULL;
    volatile ULONGLONG* entry = NULL;

    /* Start from a deterministic, unusable window. */
    RtlZeroMemory(window, sizeof(*window));
    KeInitializeSpinLock(&window->Lock);
    /* Reserve one physically contiguous page to serve as the window. */
    highest.QuadPart = MAXLONGLONG;
    window->WindowVirtual = MmAllocateContiguousMemorySpecifyCache(
        (SIZE_T)KSW_HVM_MEMORY_PAGE_BYTES,
        lowest,
        highest,
        boundary,
        MmCached);
    /* Leave the window unavailable when the reservation fails. */
    if (window->WindowVirtual == NULL) {
        /* Every access will use the documented fallback path. */
        return;
    }
    /* Zero the reservation before its entry is ever rewritten. */
    RtlZeroMemory(
        window->WindowVirtual,
        (SIZE_T)KSW_HVM_MEMORY_PAGE_BYTES);
    /* Resolve the reservation's own frame for self-map discovery. */
    windowPhysical = MmGetPhysicalAddress(window->WindowVirtual);
    /*
     * Discover the self-map base once.  Failure means the reservation landed
     * inside a large-page mapping or the layout is unfamiliar; either way the
     * window stays unavailable rather than guessing at an entry address.
     */
    if (!KswordARKHvmMemoryDiscoverSelfMap(
            window->WindowVirtual,
            (ULONGLONG)windowPhysical.QuadPart >> 12,
            &selfMapBase)) {
        /* Release the reservation that cannot be used as a window. */
        MmFreeContiguousMemory(window->WindowVirtual);
        /* Leave the window unavailable. */
        window->WindowVirtual = NULL;
        /* Every access will use the documented fallback path. */
        return;
    }
    /* Resolve the writable entry that maps the reservation. */
    entry = KswordARKHvmMemoryEntryAddress(
        selfMapBase,
        (ULONGLONG)(ULONG_PTR)window->WindowVirtual);
    /* Preserve the original entry so every access can restore it. */
    window->OriginalEntry = *entry;
    /* Publish the discovered self-map base. */
    window->SelfMapBase = selfMapBase;
    /* Publish the writable window entry. */
    window->WindowEntry = entry;
    /* Publish the window only after every field is complete. */
    window->Ready = TRUE;
#endif
}

VOID
KswordARKHvmMemoryShutdown(
    VOID
    )
{
    KSW_HVM_MEMORY_WINDOW* window = &g_KswordHvmMemory;
    KIRQL oldIrql = PASSIVE_LEVEL;

    /* Nothing to release when the reservation never succeeded. */
    if (window->WindowVirtual == NULL) {
        /* Return without touching an absent reservation. */
        return;
    }
    /* Close the window against concurrent access before releasing it. */
    KeAcquireSpinLock(&window->Lock, &oldIrql);
    if (window->Ready) {
        /* Restore the exact entry captured at initialization. */
        *window->WindowEntry = window->OriginalEntry;
        /* Drop any translation left by the last access. */
        __invlpg(window->WindowVirtual);
        /* Refuse every further window access. */
        window->Ready = FALSE;
    }
    /* Release the window for the final free. */
    KeReleaseSpinLock(&window->Lock, oldIrql);
    /* Release the reservation itself. */
    MmFreeContiguousMemory(window->WindowVirtual);
    /* Leave no dangling reservation pointer behind. */
    window->WindowVirtual = NULL;
    /* Leave no dangling entry pointer behind. */
    window->WindowEntry = NULL;
}

/*
 * Resolve one process to the page-directory base its threads run on.
 *
 * Windows does not publish a stable EPROCESS DirectoryTableBase offset, and
 * hardcoding one is how a driver ends up reading the wrong field after a
 * Windows update - silently, because a wrong CR3 still walks and still
 * produces a physical address.  So this attaches to the process and reads the
 * register the hardware is actually using, exactly as the R0 page-table walker
 * already does.
 *
 * The base is used after detaching, which is sound: the walk that follows
 * reads physical memory through the private window, not virtual memory in the
 * target address space.
 */
NTSTATUS
KswordARKHvmMemoryResolveProcessDirectoryBase(
    _In_ ULONG ProcessId,
    _Out_ ULONGLONG* DirectoryBase
    )
{
#if defined(_M_AMD64)
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    PEPROCESS process = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before any lookup. */
    if (DirectoryBase == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *DirectoryBase = 0ULL;
    /* Refuse the idle process, whose identifier is never a valid target. */
    if (ProcessId == 0UL) {
        /* Return the exact target-selection failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Take a reference so the process cannot exit mid-attach. */
    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId,
        &process);
    /* Stop when the process has already gone. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact lookup failure. */
        return status;
    }
    RtlZeroMemory(attachState, sizeof(attachState));
    /* Attach only long enough to read the register. */
    KeStackAttachProcess((PVOID)process, (PVOID)attachState);
    *DirectoryBase = (ULONGLONG)__readcr3();
    KeUnstackDetachProcess((PVOID)attachState);
    ObDereferenceObject(process);
    /* Refuse a base the walker could not use anyway. */
    if (*DirectoryBase == 0ULL) {
        /* Return the exact unusable-state failure. */
        return STATUS_UNSUCCESSFUL;
    }
    /* Complete the resolution successfully. */
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(ProcessId);
    /* Report that no other architecture has this register. */
    if (DirectoryBase != NULL) {
        *DirectoryBase = 0ULL;
    }
    return STATUS_NOT_SUPPORTED;
#endif
}

NTSTATUS
KswordARKHvmMemoryExecute(
    _In_ const KSWORD_ARK_HVM_MEMORY_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_MEMORY_RESPONSE* Response
    )
{
    KSW_HVM_MEMORY_WINDOW* window = &g_KswordHvmMemory;
    ULONGLONG physicalAddress = 0ULL;
    ULONG transferred = 0UL;
    BOOLEAN usedWindow = FALSE;
    BOOLEAN isWrite = FALSE;
    BOOLEAN isVirtual = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before touching any state. */
    if (Request == NULL || Response == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Start from a deterministic response for every failure path. */
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    Response->windowReady = window->Ready ? 1U : 0U;
    /* Validate the complete versioned request. */
    if (Request->version != KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        Request->reserved0 != 0UL ||
        Request->length > KSWORD_ARK_HVM_MEMORY_MAX_BYTES) {
        /* Publish the stable invalid-request protocol status. */
        Response->status = KSWORD_ARK_HVM_MEMORY_STATUS_INVALID_REQUEST;
        Response->ntStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Answer window availability without touching memory. */
    if (Request->operation == KSWORD_ARK_HVM_MEMORY_OP_QUERY_WINDOW) {
        /* Publish the successful availability answer. */
        Response->status = KSWORD_ARK_HVM_MEMORY_STATUS_OK;
        /* Return the complete availability answer. */
        return STATUS_SUCCESS;
    }
    /*
     * Every remaining operation reaches memory outside the documented paths,
     * so all of them require the explicit confirmation token, not only writes.
     */
    if (Request->confirmationToken !=
            KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN ||
        (Request->flags &
            KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED) == 0UL) {
        /* Publish the stable confirmation-required protocol status. */
        Response->status =
            KSWORD_ARK_HVM_MEMORY_STATUS_CONFIRMATION_REQUIRED;
        Response->ntStatus = STATUS_ACCESS_DENIED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Classify the requested operation. */
    switch (Request->operation) {
    case KSWORD_ARK_HVM_MEMORY_OP_WRITE_PHYSICAL:
        /* Physical write through the private window. */
        isWrite = TRUE;
        break;
    case KSWORD_ARK_HVM_MEMORY_OP_READ_VIRTUAL:
        /* Virtual read after an independent page walk. */
        isVirtual = TRUE;
        break;
    case KSWORD_ARK_HVM_MEMORY_OP_WRITE_VIRTUAL:
        /* Virtual write after an independent page walk. */
        isWrite = TRUE;
        isVirtual = TRUE;
        break;
    case KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE:
        /* Translation only, no memory access. */
        isVirtual = TRUE;
        break;
    case KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL:
        /* Physical read through the private window or the fallback. */
        break;
    default:
        /* Publish the stable invalid-request protocol status. */
        Response->status = KSWORD_ARK_HVM_MEMORY_STATUS_INVALID_REQUEST;
        Response->ntStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Honor an explicit refusal to fall back to the documented path. */
    if (!window->Ready &&
        (Request->flags &
            KSWORD_ARK_HVM_MEMORY_FLAG_REQUIRE_WINDOW) != 0UL) {
        /* Publish the stable window-unavailable protocol status. */
        Response->status = KSWORD_ARK_HVM_MEMORY_STATUS_WINDOW_UNAVAILABLE;
        Response->ntStatus = STATUS_NOT_SUPPORTED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    if (isVirtual) {
        ULONGLONG directoryBase = 0ULL;

        if (Request->processId != 0UL) {
            /*
             * A named process wins over an explicit base.  Callers that know a
             * PID should not also have to know a CR3, and the driver never
             * hands one out, so this is the only way for them to reach another
             * address space.
             */
            status = KswordARKHvmMemoryResolveProcessDirectoryBase(
                Request->processId,
                &directoryBase);
            /* Stop before any walk when the process cannot be resolved. */
            if (!NT_SUCCESS(status)) {
                /* Publish the stable process-lookup protocol status. */
                Response->status =
                    KSWORD_ARK_HVM_MEMORY_STATUS_PROCESS_LOOKUP_FAILED;
                Response->ntStatus = status;
                /* Return the complete lookup failure. */
                return STATUS_SUCCESS;
            }
        } else if (Request->directoryBase != 0ULL) {
            /* Honor an explicitly supplied hierarchy. */
            directoryBase = Request->directoryBase;
        } else {
            /*
             * A zero directory base means the caller wants the address
             * resolved in the page tables the current thread already runs on.
             */
            directoryBase = (ULONGLONG)__readcr3();
        }

        /* Resolve the virtual address through an independent page walk. */
        status = KswordARKHvmMemoryTranslate(
            directoryBase,
            Request->address,
            &physicalAddress,
            NULL);
        /* Stop when the address is not mapped in that hierarchy. */
        if (!NT_SUCCESS(status)) {
            /* Publish the stable translation-failure protocol status. */
            Response->status =
                KSWORD_ARK_HVM_MEMORY_STATUS_TRANSLATION_FAILED;
            Response->ntStatus = status;
            /* Return the complete translation failure. */
            return STATUS_SUCCESS;
        }
        /* Publish the resolved physical address for every virtual operation. */
        Response->physicalAddress = physicalAddress;
        /* Translation requests are complete once the address is resolved. */
        if (Request->operation == KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE) {
            /* Publish the successful translation. */
            Response->status = KSWORD_ARK_HVM_MEMORY_STATUS_OK;
            /* Return the complete translation answer. */
            return STATUS_SUCCESS;
        }
    } else {
        /* Physical operations address the requested frame directly. */
        physicalAddress = Request->address;
        /* Publish the address the access will use. */
        Response->physicalAddress = physicalAddress;
    }
    /* Reject a span the architecture cannot encode. */
    if (Request->length == 0UL ||
        !KswordARKHvmMemoryIsPhysicalRangeValid(
            physicalAddress,
            Request->length)) {
        /* Publish the stable address-invalid protocol status. */
        Response->status = KSWORD_ARK_HVM_MEMORY_STATUS_ADDRESS_INVALID;
        Response->ntStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    if (isWrite) {
        /* Stage caller bytes in the response buffer before publishing them. */
        RtlCopyMemory(Response->data, Request->data, Request->length);
    }
    /* Perform the page-split transfer in the requested direction. */
    status = KswordARKHvmMemoryCopyRange(
        physicalAddress,
        Response->data,
        Request->length,
        isWrite,
        &transferred,
        &usedWindow);
    /* Publish exactly how many bytes moved. */
    Response->bytesTransferred = transferred;
    /* Publish whether the hook-free path carried the access. */
    Response->usedDirectWindow = usedWindow ? 1U : 0U;
    /* Preserve the authoritative access status. */
    Response->ntStatus = status;
    if (!NT_SUCCESS(status)) {
        /* Distinguish a partial transfer from a complete failure. */
        Response->status = transferred != 0UL
            ? KSWORD_ARK_HVM_MEMORY_STATUS_PARTIAL
            : KSWORD_ARK_HVM_MEMORY_STATUS_ACCESS_FAILED;
        /* Return the complete access failure. */
        return STATUS_SUCCESS;
    }
    /* A write leaves nothing to return, so do not echo the payload back. */
    if (isWrite) {
        /* Clear the staged payload from the response buffer. */
        RtlZeroMemory(Response->data, KSWORD_ARK_HVM_MEMORY_MAX_BYTES);
    }
    /* Publish the successful transfer. */
    Response->status = KSWORD_ARK_HVM_MEMORY_STATUS_OK;
    /* Return the complete access result. */
    return STATUS_SUCCESS;
}
