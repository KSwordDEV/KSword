/*++

Module Name:

    hvm_event.c

Abstract:

    Implements a fixed nonpaged HVM event ring with sequence-validated slots.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_event.h"

/* Bound retained VM-exit evidence without allocation in VMX root. */
#define KSW_HVM_EVENT_RING_CAPACITY 1024UL
/* Reserve the high state bit for one nonblocking writer ownership claim. */
#define KSW_HVM_EVENT_SLOT_BUSY 0x8000000000000000ULL
/* Keep completed public sequences separate from the writer ownership bit. */
#define KSW_HVM_EVENT_SEQUENCE_MASK 0x7FFFFFFFFFFFFFFFULL

/* Wrap one public row with an atomic busy-plus-sequence publication state. */
typedef struct _KSW_HVM_EVENT_SLOT
{
    /* Publish BUSY|sequence while owned and sequence alone when complete. */
    DECLSPEC_ALIGN(8) volatile LONG64 PublicationState;
    /* Retain the protocol-visible event payload. */
    KSWORD_ARK_HVM_EVENT_ROW Row;
} KSW_HVM_EVENT_SLOT;

/* Own the monotonic sequence and fixed nonpaged event slots. */
typedef struct _KSW_HVM_EVENT_RING
{
    /* Allocate the next protocol-visible event sequence atomically. */
    DECLSPEC_ALIGN(8) volatile LONG64 NextSequence;
    /* Count writers that could not claim their wrapped slot without waiting. */
    DECLSPEC_ALIGN(8) volatile LONG64 DroppedPublications;
    /* Retain every bounded ring slot in nonpaged driver storage. */
    KSW_HVM_EVENT_SLOT Slots[KSW_HVM_EVENT_RING_CAPACITY];
} KSW_HVM_EVENT_RING;

/* Require the 64-bit interlocked operands to remain naturally aligned. */
C_ASSERT(__alignof(KSW_HVM_EVENT_SLOT) >= 8);
C_ASSERT(__alignof(KSW_HVM_EVENT_RING) >= 8);
C_ASSERT((FIELD_OFFSET(
    KSW_HVM_EVENT_SLOT,
    PublicationState) & 0x7) == 0);
C_ASSERT((FIELD_OFFSET(
    KSW_HVM_EVENT_RING,
    DroppedPublications) & 0x7) == 0);

/* Store the process-wide nonpaged HVM event ring. */
static KSW_HVM_EVENT_RING g_KswordHvmEvents;

VOID
KswordARKHvmEventInitialize(
    VOID
    )
{
    /* Initialize the full event ring before HVM becomes observable. */
    RtlZeroMemory(
        &g_KswordHvmEvents,
        sizeof(g_KswordHvmEvents));
}

VOID
KswordARKHvmEventReset(
    VOID
    )
{
    /* Reset the full ring only after lifecycle serialization stops writers. */
    RtlZeroMemory(
        &g_KswordHvmEvents,
        sizeof(g_KswordHvmEvents));
}

VOID
KswordARKHvmEventPublish(
    _In_ const KSWORD_ARK_HVM_EVENT_ROW* Event
    )
{
    LONG64 sequence = 0;
    LONG64 observedState = 0;
    LONG64 busyState = 0;
    ULONGLONG observedBits = 0ULL;
    ULONG slotIndex = 0UL;
    KSW_HVM_EVENT_SLOT* slot = NULL;
    LARGE_INTEGER timestamp = { 0 };

    /* Reject a missing event without touching the ring. */
    if (Event == NULL) {
        /* Return immediately on an invalid VM-exit publication contract. */
        return;
    }
    /* Allocate one monotonic sequence with full interlocked ordering. */
    sequence = InterlockedIncrement64(
        &g_KswordHvmEvents.NextSequence);
    /*
     * The high bit belongs to slot ownership.  Refuse the theoretical signed
     * sequence rollover instead of aliasing a public sequence with BUSY.
     */
    if (sequence <= 0) {
        /* Account for the sequence that cannot be represented safely. */
        InterlockedIncrement64(
            &g_KswordHvmEvents.DroppedPublications);
        /* Return without indexing the ring with a wrapped value. */
        return;
    }
    /* Convert the positive sequence to a bounded ring slot. */
    slotIndex = (ULONG)(
        ((ULONGLONG)sequence - 1ULL) %
        KSW_HVM_EVENT_RING_CAPACITY);
    /* Select the exact slot owned by this sequence. */
    slot = &g_KswordHvmEvents.Slots[slotIndex];
    /* Snapshot the current slot owner or completed sequence. */
    observedState = InterlockedCompareExchange64(
        &slot->PublicationState,
        0,
        0);
    observedBits = (ULONGLONG)observedState;
    /*
     * Never wait in VMX root.  A busy slot means a wrapped writer caught an
     * earlier publisher in flight; a newer completed sequence means this
     * writer was delayed and must not overwrite newer evidence.
     */
    if ((observedBits & KSW_HVM_EVENT_SLOT_BUSY) != 0ULL ||
        (observedBits & KSW_HVM_EVENT_SEQUENCE_MASK) >=
            (ULONGLONG)sequence) {
        /* Account for the intentionally discarded publication. */
        InterlockedIncrement64(
            &g_KswordHvmEvents.DroppedPublications);
        /* Return without spinning or modifying another writer's slot. */
        return;
    }
    /* Encode this sequence as the single-writer ownership state. */
    busyState = (LONG64)(
        KSW_HVM_EVENT_SLOT_BUSY |
        (ULONGLONG)sequence);
    /* Claim the slot exactly once; a failed claim is a bounded drop. */
    if (InterlockedCompareExchange64(
            &slot->PublicationState,
            busyState,
            observedState) != observedState) {
        /* Account for the losing writer without retrying in VMX root. */
        InterlockedIncrement64(
            &g_KswordHvmEvents.DroppedPublications);
        /* Preserve the concurrent winner's publication. */
        return;
    }
    /* Copy the caller-provided fixed payload without allocation. */
    slot->Row = *Event;
    /* Publish the authoritative monotonic sequence in the payload. */
    slot->Row.sequence = (ULONGLONG)sequence;
    /* Capture one nonblocking interrupt-time timestamp when absent. */
    if (slot->Row.timestamp == 0ULL) {
        /* Read the monotonically increasing interrupt time. */
        timestamp = KeQueryPerformanceCounter(NULL);
        /* Preserve the performance-counter tick value. */
        slot->Row.timestamp =
            (ULONGLONG)timestamp.QuadPart;
    }
    /* Order the entire payload before the publication sequence. */
    KeMemoryBarrier();
    /* Publish the completed slot to concurrent readers. */
    InterlockedExchange64(
        &slot->PublicationState,
        sequence);
}

NTSTATUS
KswordARKHvmEventQuery(
    _In_ const KSWORD_ARK_HVM_EVENT_QUERY_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE* Response
    )
{
    ULONGLONG newest = 0ULL;
    ULONGLONG oldest = 0ULL;
    ULONGLONG next = 0ULL;
    ULONGLONG available = 0ULL;
    ULONG rowLimit = 0UL;

    /* Validate the complete versioned query contract. */
    if (Request == NULL ||
        Response == NULL ||
        Request->version != KSWORD_ARK_HVM_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        Request->operation != KSWORD_ARK_HVM_EVENT_QUERY_READ) {
        /* Return the exact fixed-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Initialize the complete response before reading concurrent slots. */
    RtlZeroMemory(Response, sizeof(*Response));
    /* Publish the protocol identity immediately. */
    Response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    /* Publish the complete fixed response size. */
    Response->size = sizeof(*Response);
    /* Bound the caller row request to the fixed response capacity. */
    rowLimit = Request->maxRows;
    /* Replace zero with the full fixed batch capacity. */
    if (rowLimit == 0UL ||
        rowLimit > KSWORD_ARK_HVM_MAX_EVENT_ROWS) {
        /* Clamp the row limit to the complete response array. */
        rowLimit = KSWORD_ARK_HVM_MAX_EVENT_ROWS;
    }
    /* Snapshot the newest assigned sequence with interlocked ordering. */
    newest = (ULONGLONG)InterlockedCompareExchange64(
        &g_KswordHvmEvents.NextSequence,
        0,
        0);
    /* Publish the newest sequence even when no row is retained. */
    Response->newestSequence = newest;
    /* Return an empty valid response before the first publication. */
    if (newest == 0ULL) {
        /* Complete the empty query successfully. */
        return STATUS_SUCCESS;
    }
    /* Compute the oldest sequence that can still occupy the fixed ring. */
    oldest = newest >= KSW_HVM_EVENT_RING_CAPACITY
        ? newest - KSW_HVM_EVENT_RING_CAPACITY + 1ULL
        : 1ULL;
    /* Start strictly after the caller-provided sequence. */
    next = Request->afterSequence + 1ULL;
    /* Detect caller sequence overflow explicitly. */
    if (next == 0ULL) {
        /* Return the exact sequence-overflow contract failure. */
        return STATUS_INTEGER_OVERFLOW;
    }
    /* Account for rows overwritten before the requested starting point. */
    if (next < oldest) {
        ULONGLONG overwritten = oldest - next;

        /* Saturate overwritten evidence at the protocol counter width. */
        Response->droppedRows = overwritten > MAXULONG
            ? MAXULONG
            : (ULONG)overwritten;
        /* Continue from the oldest sequence that remains readable. */
        next = oldest;
    }
    /* Compute the number of retained rows after the adjusted cursor. */
    available = next <= newest
        ? newest - next + 1ULL
        : 0ULL;
    /* Publish the bounded number available before the response row limit. */
    Response->availableRows = available > MAXULONG
        ? MAXULONG
        : (ULONG)available;
    /* Copy sequence-validated slots until the caller's row limit is reached. */
    while (next <= newest &&
           Response->returnedRows < rowLimit) {
        ULONG slotIndex = (ULONG)(
            ((next - 1ULL) %
                KSW_HVM_EVENT_RING_CAPACITY));
        KSW_HVM_EVENT_SLOT* slot =
            &g_KswordHvmEvents.Slots[slotIndex];
        LONG64 before = 0;
        KSWORD_ARK_HVM_EVENT_ROW row = { 0 };
        LONG64 after = 0;

        /* Snapshot the busy-plus-sequence state before copying the payload. */
        before = InterlockedCompareExchange64(
            &slot->PublicationState,
            0,
            0);
        /* Copy only a completed slot for the exact requested sequence. */
        if (((ULONGLONG)before &
                KSW_HVM_EVENT_SLOT_BUSY) == 0ULL &&
            ((ULONGLONG)before &
                KSW_HVM_EVENT_SEQUENCE_MASK) == next) {
            /* Copy the fixed payload optimistically. */
            row = slot->Row;
            /* Order the payload read before rechecking publication. */
            KeMemoryBarrier();
            /* Recheck that no concurrent writer replaced the slot. */
            after = InterlockedCompareExchange64(
                &slot->PublicationState,
                0,
                0);
            /* Publish only a stable two-phase slot snapshot. */
            if (before == after &&
                ((ULONGLONG)after &
                    KSW_HVM_EVENT_SLOT_BUSY) == 0ULL &&
                row.sequence == next) {
                /* Append the stable row to the fixed response batch. */
                Response->rows[Response->returnedRows] = row;
                /* Publish one additional returned row. */
                Response->returnedRows += 1UL;
            } else if (Response->droppedRows != MAXULONG) {
                /* Count a row unavailable in this concurrent snapshot. */
                Response->droppedRows += 1UL;
            }
        } else if (Response->droppedRows != MAXULONG) {
            /* Count an unclaimed, busy, stale, or wrapped slot as unavailable. */
            Response->droppedRows += 1UL;
        }
        /* Advance to the next monotonic event sequence. */
        next += 1ULL;
    }
    /* Complete the bounded snapshot successfully. */
    return STATUS_SUCCESS;
}

VOID
KswordARKHvmEventGetCounts(
    _Out_ ULONG* RetainedCount,
    _Out_ ULONG* PublicationDropCount,
    _Out_ ULONG* OverwrittenCount,
    _Out_ ULONGLONG* PublishedCount
    )
{
    ULONGLONG newest = 0ULL;
    ULONGLONG oldest = 0ULL;
    ULONGLONG retained = 0ULL;
    ULONGLONG overwritten = 0ULL;
    ULONGLONG publicationDrops = 0ULL;
    ULONG slotIndex = 0UL;

    /* Reject any missing fixed output pointer. */
    if (RetainedCount == NULL ||
        PublicationDropCount == NULL ||
        OverwrittenCount == NULL ||
        PublishedCount == NULL) {
        /* Return without publishing a partial count set. */
        return;
    }
    /* Snapshot the newest assigned sequence with interlocked ordering. */
    newest = (ULONGLONG)InterlockedCompareExchange64(
        &g_KswordHvmEvents.NextSequence,
        0,
        0);
    /* Snapshot exact failed ownership claims for a conservative loss floor. */
    publicationDrops = (ULONGLONG)InterlockedCompareExchange64(
        &g_KswordHvmEvents.DroppedPublications,
        0,
        0);
    /* Compute the oldest sequence that can still occupy the fixed ring. */
    oldest = newest >= KSW_HVM_EVENT_RING_CAPACITY
        ? newest - KSW_HVM_EVENT_RING_CAPACITY + 1ULL
        : 1ULL;
    /*
     * Count only completed states in the current retention window.  This
     * bounded scan avoids reporting assigned-but-dropped sequences as rows.
     */
    for (slotIndex = 0UL;
         slotIndex < KSW_HVM_EVENT_RING_CAPACITY;
         ++slotIndex) {
        LONG64 before = InterlockedCompareExchange64(
            &g_KswordHvmEvents.Slots[slotIndex].PublicationState,
            0,
            0);
        ULONGLONG sequence =
            (ULONGLONG)before &
            KSW_HVM_EVENT_SEQUENCE_MASK;

        /* Count only one completed sequence inside the current window. */
        if (((ULONGLONG)before &
                KSW_HVM_EVENT_SLOT_BUSY) == 0ULL &&
            sequence >= oldest &&
            sequence <= newest) {
            /* Publish one additional currently retained event. */
            retained += 1ULL;
        }
    }
    /*
     * Displacement by ring wrap is reported apart from publication loss.
     *
     * These two numbers answer different questions and were previously folded
     * together by a max(), which made the result unreadable: a 1024-slot ring
     * that has carried a million events reports "999k displaced" even when the
     * consumer read every one of them before it was overwritten.  Only the
     * publication drop count is evidence that an event was never written at
     * all, and only that number justifies changing the ring's structure.
     *
     * Whether displacement is an actual loss depends on the reader's polling
     * interval, which the driver cannot see - so the driver reports the raw
     * displacement and leaves that judgement to the caller.
     */
    overwritten = newest > retained
        ? newest - retained
        : 0ULL;
    /* Publish the retained count within protocol width. */
    *RetainedCount = retained > MAXULONG
        ? MAXULONG
        : (ULONG)retained;
    /* Publish exact failed nonblocking ownership claims within protocol width. */
    *PublicationDropCount = publicationDrops > MAXULONG
        ? MAXULONG
        : (ULONG)publicationDrops;
    /* Saturate the wrap-displaced sequence count within protocol width. */
    *OverwrittenCount = overwritten > MAXULONG
        ? MAXULONG
        : (ULONG)overwritten;
    /* Publish the full-width total so the two counters have a denominator. */
    *PublishedCount = newest;
}
