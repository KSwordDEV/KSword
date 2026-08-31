#include "ark/ark_driver.h"

/*++

Module Name:

    bugcheck_shield.c

Abstract:

    PatchGuard-safe bugcheck buffer backend.

    Motivation and design boundaries
    --------------------------------
    Publicly circulated reverse-engineering of private-slot
    "Disable-PatchGuard" style samples shows the same recipe: enumerate
    ntoskrnl by signature, overwrite undocumented function-pointer slots
    and permanently wait on an unsignaled event so the intercepted
    bug-check path never completes. That approach fails Windows kernel
    integrity checks (HVCI, PatchGuard, WHQL) and leaves the kernel in a
    non-recoverable state. It is presented as an example of what not to
    ship in a signed driver.

    The Shield keeps the "extend the window before the machine leaves the
    bug-check screen" observation from those samples but implements it
    only through documented callbacks:

      * KeRegisterBugCheckCallback for the earliest phase.
      * KeRegisterBugCheckReasonCallback for KbCallbackSecondaryDumpData,
        KbCallbackDumpIo and KbCallbackAddPages.

    Every callback performs a bounded KeStallExecutionProcessor loop that
    respects a global remaining-budget accumulator. The Shield never
    writes to ntoskrnl code, private KPCR/KPRCB/KTHREAD offsets, CR0, CR4,
    CR8, MSRs, SSDT, IDT or GDT. It never waits on an unsignaled event.
    It always yields back to Windows so the normal dump path can run.

    DriverEntry only initializes synchronization state. Callbacks are
    installed only after an IOCTL with the KSHL confirmation token and
    UI-confirmed flag arrives. Driver unload drains any in-flight
    callback invocations before deregistering the records.

Environment:

    Kernel-mode Driver Framework

--*/

// x64 only: the driver as a whole is x64-only; the Shield reuses the same
// gate so a mistaken 32-bit build does not silently link against the wrong
// ULONG_PTR/pointer semantics used inside the timeline ring.
#if !defined(_WIN64)
#error The bugcheck Shield only supports x64 builds.
#endif

// KSHL is derived from the shared header. Redefining it locally would allow
// R0 and R3 to drift; instead we assert the token matches at compile time so
// any accidental change trips the build before anyone reaches a real machine.
C_ASSERT(KSWORD_ARK_BUGCHECK_SHIELD_CONFIRMATION_TOKEN == 0x4C48534BUL);

// Fixed component name shown by the kernel when logging callback failures.
static UCHAR g_KswordArkBugcheckShieldComponent[] = "KswordBugcheckShield";

// State is fully static and lives in nonpaged BSS. The Shield never allocates
// at callback time; every field it touches on the crash path is a member of
// this structure.
typedef struct _KSWORD_ARK_BUGCHECK_SHIELD_STATE
{
    // ControlLock serializes IOCTL enable/disable transitions at
    // PASSIVE_LEVEL. It is never acquired by callback code, which can run at
    // HIGH_LEVEL on the crashing processor.
    FAST_MUTEX ControlLock;
    // Enabled is set to 1 after all requested reason callbacks registered
    // successfully. Callbacks bail out cheaply when Enabled is 0.
    volatile LONG Enabled;
    // Fired is set to 1 on the first callback observed after enable so R3
    // can distinguish "installed but never fired" from "actually invoked".
    volatile LONG Fired;
    // FireCount tracks how many callback executions have completed. It is
    // decremented after each callback returns so unload can drain safely.
    volatile LONG FireCount;
    // Executions counts nesting per callback entry; used to prevent unload
    // from deregistering while another CPU is inside a Shield callback.
    volatile LONG Executions;
    // TimelineNextIndex is monotonically incremented; entries beyond the
    // ring size are dropped to keep the response bounded.
    volatile LONG TimelineNextIndex;
    // TimelineCommittedCount is the visible size for R3 snapshots.
    volatile LONG TimelineCommittedCount;
    // RemainingBudgetMs is a global buffer budget shared across callbacks
    // so multiple stages cannot exceed TotalSeconds. It is set on enable
    // and drained by callbacks; it never goes negative.
    volatile LONG RemainingBudgetMs;
    // Configured knobs mirror the last successful enable request; used for
    // both response serialization and callback stall duration.
    ULONG ReasonMask;
    ULONG StageSeconds;
    ULONG TotalSeconds;
    // Registration bookkeeping for KeDeregister* on disable/unload.
    KBUGCHECK_CALLBACK_RECORD ClassicRecord;
    KBUGCHECK_REASON_CALLBACK_RECORD SecondaryRecord;
    KBUGCHECK_REASON_CALLBACK_RECORD DumpIoRecord;
    KBUGCHECK_REASON_CALLBACK_RECORD AddPagesRecord;
    // The kernel keeps a pointer to the callback buffer; we hand it a
    // ULONG per callback record. The value itself is not used by Windows,
    // it only needs to remain valid until the record is deregistered.
    ULONG ClassicBuffer;
    ULONG ReasonBuffer;
    BOOLEAN ClassicRegistered;
    BOOLEAN SecondaryRegistered;
    BOOLEAN DumpIoRegistered;
    BOOLEAN AddPagesRegistered;
    // Last kernel status reported to R3 for diagnostics.
    NTSTATUS LastStatus;
    // Timeline ring is fixed size; entries are visible only after they are
    // fully written and TimelineCommittedCount is bumped.
    KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRY
        Timeline[KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRIES];
} KSWORD_ARK_BUGCHECK_SHIELD_STATE;

// Single global state; the Shield is not per-device.
static KSWORD_ARK_BUGCHECK_SHIELD_STATE g_KswordArkBugcheckShield;

// Forward declarations for the four callback entry points.
static VOID
KswordARKBugcheckShieldClassicCallback(
    _In_ PVOID Buffer,
    _In_ ULONG Length
    );

static VOID
KswordARKBugcheckShieldReasonCallback(
    _In_ KBUGCHECK_CALLBACK_REASON Reason,
    _In_ struct _KBUGCHECK_REASON_CALLBACK_RECORD* Record,
    _In_ PVOID ReasonSpecificData,
    _In_ ULONG ReasonSpecificDataLength
    );

// KeQueryInterruptTime returns 100ns units. This helper converts a
// millisecond count to interrupt-time units so we can compare against a
// KeQueryInterruptTime baseline without integer overflow risk on the
// bug-check path.
static ULONGLONG
KswordARKBugcheckShieldMsToInterruptUnits(
    _In_ ULONG Milliseconds
    )
{
    // 10 000 100ns ticks per millisecond; guard against overflow by taking
    // ULONGLONG on both operands even though ULONG * 10000 fits in 64-bit.
    return (ULONGLONG)Milliseconds * 10000ULL;
}

// Compute how long this callback is allowed to stall. The per-stage cap is
// bounded by the global remaining budget; when the global budget is empty
// the callback returns immediately so downstream Windows work is not
// starved.
static ULONG
KswordARKBugcheckShieldClaimStallBudgetMs(
    _In_ ULONG StageSeconds
    )
{
    LONG desired;
    LONG remaining;
    LONG claim;
    LONG updated;

    // Convert stage seconds to milliseconds; the shared header caps the
    // value at KSWORD_ARK_BUGCHECK_SHIELD_STAGE_MAX_SECONDS so this cannot
    // wrap.
    desired = (LONG)(StageSeconds * 1000UL);
    for (;;) {
        // Read the current remaining budget. Loop until CAS succeeds so we
        // are correct even if multiple callbacks race on different CPUs.
        remaining = InterlockedCompareExchange(
            &g_KswordArkBugcheckShield.RemainingBudgetMs,
            0L,
            0L);
        if (remaining <= 0L) {
            // Global budget is exhausted; no further stall permitted.
            return 0UL;
        }
        claim = remaining < desired ? remaining : desired;
        // Publish the new remaining value only if nobody else changed it.
        updated = InterlockedCompareExchange(
            &g_KswordArkBugcheckShield.RemainingBudgetMs,
            remaining - claim,
            remaining);
        if (updated == remaining) {
            return (ULONG)claim;
        }
    }
}

// Stall the current processor for approximately the requested duration.
// The loop uses 50µs KeStallExecutionProcessor steps and re-checks elapsed
// time on every iteration so the stall never significantly overshoots.
static VOID
KswordARKBugcheckShieldStallMs(
    _In_ ULONG Milliseconds
    )
{
    ULONGLONG deadline;
    ULONGLONG now;

    if (Milliseconds == 0UL) {
        // Empty stall — fall through so the timeline still records the hit.
        return;
    }
    // KeQueryInterruptTime is callable at any IRQL and monotonic across
    // processors, which is the property we need on the crash path.
    now = KeQueryInterruptTime();
    deadline = now + KswordARKBugcheckShieldMsToInterruptUnits(Milliseconds);
    while (now < deadline) {
        // 50µs per step keeps the loop responsive without spinning too
        // tightly on the memory subsystem.
        KeStallExecutionProcessor(50UL);
        now = KeQueryInterruptTime();
    }
}

// Publish a timeline entry describing the callback that just ran. Called
// after the stall completes so the recorded duration is accurate.
static VOID
KswordARKBugcheckShieldRecordTimeline(
    _In_ ULONG Reason,
    _In_ ULONG StalledMilliseconds
    )
{
    LONG index;
    ULONG cpu;

    // Reserve the next ring slot; drop the entry when the ring is full so
    // the crash response never grows beyond its fixed layout.
    index = InterlockedIncrement(
        &g_KswordArkBugcheckShield.TimelineNextIndex) - 1L;
    if (index < 0L ||
        (ULONG)index >= KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRIES) {
        return;
    }
    // KeGetCurrentProcessorNumberEx is documented for any IRQL and returns
    // the processor that is actually running the callback.
    cpu = KeGetCurrentProcessorNumberEx(NULL);
    g_KswordArkBugcheckShield.Timeline[index].reason = Reason;
    // Bug-check code is not exposed to reason callbacks; leave it 0 so
    // R3 renders it as "unknown".  We keep the field for wire-format
    // compatibility if a future kernel exposes the value.
    g_KswordArkBugcheckShield.Timeline[index].bugcheckCode = 0UL;
    g_KswordArkBugcheckShield.Timeline[index].cpu = cpu;
    g_KswordArkBugcheckShield.Timeline[index].stalledMilliseconds =
        StalledMilliseconds;
    // Publish the entry only after all fields are written so a reader
    // observing TimelineCommittedCount can trust every visible slot.
    KeMemoryBarrier();
    InterlockedIncrement(&g_KswordArkBugcheckShield.TimelineCommittedCount);
}

// Core buffer body shared by every callback entry point. Handles the
// enable check, stall budget, timeline recording and bookkeeping so the
// callback shims can stay a couple of lines each.
static VOID
KswordARKBugcheckShieldOnCallback(
    _In_ ULONG Reason
    )
{
    ULONG stallMs;
    ULONG stageSeconds;

    // The Executions counter guards against unload deregistering the
    // record while a CPU is still inside this function.
    InterlockedIncrement(&g_KswordArkBugcheckShield.Executions);
    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckShield.Enabled,
            0L,
            0L) == 0L) {
        // Disabled after registration; still record the reason so R3 can
        // see a callback fired but no buffer was applied.
        KswordARKBugcheckShieldRecordTimeline(Reason, 0UL);
        InterlockedDecrement(&g_KswordArkBugcheckShield.Executions);
        return;
    }
    // Flag the first-ever invocation for R3 UI feedback. The order matters:
    // set Fired before consuming budget so a query racing the first hit
    // never sees "budget consumed, Fired = 0".
    InterlockedCompareExchange(&g_KswordArkBugcheckShield.Fired, 1L, 0L);
    InterlockedIncrement(&g_KswordArkBugcheckShield.FireCount);
    // Snapshot StageSeconds locally; the field itself is written only
    // under ControlLock at PASSIVE_LEVEL so a plain read is safe here.
    stageSeconds = g_KswordArkBugcheckShield.StageSeconds;
    stallMs = KswordARKBugcheckShieldClaimStallBudgetMs(stageSeconds);
    KswordARKBugcheckShieldStallMs(stallMs);
    KswordARKBugcheckShieldRecordTimeline(Reason, stallMs);
    InterlockedDecrement(&g_KswordArkBugcheckShield.Executions);
}

// Classic BugCheck callback: fires early during bug-check processing on the
// crashing processor before dump generation.
static VOID
KswordARKBugcheckShieldClassicCallback(
    _In_ PVOID Buffer,
    _In_ ULONG Length
    )
{
    // The buffer is our own ULONG scratch and is not used to communicate
    // state back to Windows; acknowledge the parameters and drop into the
    // shared body.
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Length);
    KswordARKBugcheckShieldOnCallback(
        KSWORD_ARK_BUGCHECK_SHIELD_REASON_CLASSIC);
}

// Reason callback: fires for SECONDARY_DUMP_DATA, DUMP_IO and ADD_PAGES.
// The Shield does not attempt to inject dump data or extra pages; we only
// stall for the buffer budget and return to let Windows continue.
static VOID
KswordARKBugcheckShieldReasonCallback(
    _In_ KBUGCHECK_CALLBACK_REASON Reason,
    _In_ struct _KBUGCHECK_REASON_CALLBACK_RECORD* Record,
    _In_ PVOID ReasonSpecificData,
    _In_ ULONG ReasonSpecificDataLength
    )
{
    ULONG reasonBit;

    UNREFERENCED_PARAMETER(Record);
    UNREFERENCED_PARAMETER(ReasonSpecificData);
    UNREFERENCED_PARAMETER(ReasonSpecificDataLength);
    // Map the kernel reason enum to the shared bitmask so R3 sees a
    // single, wire-stable value even if Windows renumbers the enum.
    switch (Reason) {
    case KbCallbackSecondaryDumpData:
        reasonBit = KSWORD_ARK_BUGCHECK_SHIELD_REASON_SECONDARY_DUMP_DATA;
        break;
    case KbCallbackDumpIo:
        reasonBit = KSWORD_ARK_BUGCHECK_SHIELD_REASON_DUMP_IO;
        break;
    case KbCallbackAddPages:
        reasonBit = KSWORD_ARK_BUGCHECK_SHIELD_REASON_ADD_PAGES;
        break;
    default:
        // The Shield only registers the three reasons above; any other
        // reason means the kernel invoked us for a callback we did not
        // subscribe to. Record and exit without stalling.
        reasonBit = 0UL;
        break;
    }
    if (reasonBit == 0UL) {
        // Skip the stall for reasons we did not request but still record
        // the invocation so anomalies are visible in the timeline.
        KswordARKBugcheckShieldRecordTimeline(0UL, 0UL);
        return;
    }
    KswordARKBugcheckShieldOnCallback(reasonBit);
}

// Assemble the current state bitmap for R3 responses. Runs at PASSIVE_LEVEL
// under ControlLock so registration state is a coherent snapshot.
static ULONG
KswordARKBugcheckShieldStateFlagsLocked(VOID)
{
    ULONG flags = 0UL;

    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckShield.Enabled,
            0L,
            0L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_SHIELD_STATE_ACTIVE;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckShield.Fired,
            0L,
            0L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_SHIELD_STATE_FIRED;
    }
    if (g_KswordArkBugcheckShield.ClassicRegistered) {
        flags |= KSWORD_ARK_BUGCHECK_SHIELD_STATE_CLASSIC_REGISTERED;
    }
    if (g_KswordArkBugcheckShield.SecondaryRegistered) {
        flags |= KSWORD_ARK_BUGCHECK_SHIELD_STATE_SECONDARY_REGISTERED;
    }
    if (g_KswordArkBugcheckShield.DumpIoRegistered) {
        flags |= KSWORD_ARK_BUGCHECK_SHIELD_STATE_DUMPIO_REGISTERED;
    }
    if (g_KswordArkBugcheckShield.AddPagesRegistered) {
        flags |= KSWORD_ARK_BUGCHECK_SHIELD_STATE_ADDPAGES_REGISTERED;
    }
    return flags;
}

// Deregister every previously registered callback record. Returns TRUE only
// when all records were successfully deregistered; a FALSE return means at
// least one callback was in flight and the caller must retry or refuse the
// disable so we do not free the record while Windows is calling us.
static BOOLEAN
KswordARKBugcheckShieldDeregisterAllLocked(VOID)
{
    BOOLEAN allDeregistered = TRUE;

    // Deregister the reason callbacks first so no additional executions
    // can enter after Enabled is dropped.
    if (g_KswordArkBugcheckShield.AddPagesRegistered) {
        if (KeDeregisterBugCheckReasonCallback(
                &g_KswordArkBugcheckShield.AddPagesRecord)) {
            g_KswordArkBugcheckShield.AddPagesRegistered = FALSE;
        }
        else {
            allDeregistered = FALSE;
        }
    }
    if (g_KswordArkBugcheckShield.DumpIoRegistered) {
        if (KeDeregisterBugCheckReasonCallback(
                &g_KswordArkBugcheckShield.DumpIoRecord)) {
            g_KswordArkBugcheckShield.DumpIoRegistered = FALSE;
        }
        else {
            allDeregistered = FALSE;
        }
    }
    if (g_KswordArkBugcheckShield.SecondaryRegistered) {
        if (KeDeregisterBugCheckReasonCallback(
                &g_KswordArkBugcheckShield.SecondaryRecord)) {
            g_KswordArkBugcheckShield.SecondaryRegistered = FALSE;
        }
        else {
            allDeregistered = FALSE;
        }
    }
    if (g_KswordArkBugcheckShield.ClassicRegistered) {
        if (KeDeregisterBugCheckCallback(
                &g_KswordArkBugcheckShield.ClassicRecord)) {
            g_KswordArkBugcheckShield.ClassicRegistered = FALSE;
        }
        else {
            allDeregistered = FALSE;
        }
    }
    return allDeregistered;
}

// Reset runtime accumulators back to their pre-enable defaults. Only called
// after all callback records are deregistered.
static VOID
KswordARKBugcheckShieldResetRuntimeLocked(VOID)
{
    InterlockedExchange(&g_KswordArkBugcheckShield.Enabled, 0L);
    InterlockedExchange(&g_KswordArkBugcheckShield.Fired, 0L);
    InterlockedExchange(&g_KswordArkBugcheckShield.FireCount, 0L);
    InterlockedExchange(&g_KswordArkBugcheckShield.TimelineNextIndex, 0L);
    InterlockedExchange(&g_KswordArkBugcheckShield.TimelineCommittedCount, 0L);
    InterlockedExchange(&g_KswordArkBugcheckShield.RemainingBudgetMs, 0L);
    g_KswordArkBugcheckShield.ReasonMask = 0UL;
    g_KswordArkBugcheckShield.StageSeconds = 0UL;
    g_KswordArkBugcheckShield.TotalSeconds = 0UL;
    // Zero the timeline ring so a subsequent enable presents a clean slate.
    RtlZeroMemory(
        g_KswordArkBugcheckShield.Timeline,
        sizeof(g_KswordArkBugcheckShield.Timeline));
}

// Try to deregister every record and reset runtime state. Returns success
// only when both the deregister and the drain succeed.
static NTSTATUS
KswordARKBugcheckShieldDisableLocked(VOID)
{
    // Flip Enabled off before touching the records so any concurrent
    // callback observes the drop immediately and skips further stalls.
    InterlockedExchange(&g_KswordArkBugcheckShield.Enabled, 0L);
    if (!KswordARKBugcheckShieldDeregisterAllLocked()) {
        // Restore Enabled=1 if any record could not be dropped; the driver
        // has not actually disabled and must reflect that to R3.
        InterlockedExchange(&g_KswordArkBugcheckShield.Enabled, 1L);
        return STATUS_DEVICE_BUSY;
    }
    // The kernel deregister APIs synchronize with in-flight callbacks on
    // the current CPU; verify Executions is 0 before publishing success.
    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckShield.Executions,
            0L,
            0L) != 0L) {
        return STATUS_DEVICE_BUSY;
    }
    KswordARKBugcheckShieldResetRuntimeLocked();
    return STATUS_SUCCESS;
}

// Register a single reason callback. The caller flips the matching
// registered flag in the state struct on success so the disable path
// knows which records to undo.
static NTSTATUS
KswordARKBugcheckShieldRegisterReasonLocked(
    _Inout_ PKBUGCHECK_REASON_CALLBACK_RECORD Record,
    _In_ KBUGCHECK_CALLBACK_REASON Reason
    )
{
    KeInitializeCallbackRecord(Record);
    if (!KeRegisterBugCheckReasonCallback(
            Record,
            KswordARKBugcheckShieldReasonCallback,
            Reason,
            g_KswordArkBugcheckShieldComponent)) {
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

// Register every requested reason atomically. If any registration fails we
// roll back the ones that already succeeded so the driver never presents a
// partial installation to Windows.
static NTSTATUS
KswordARKBugcheckShieldEnableLocked(
    _In_ ULONG ReasonMask,
    _In_ ULONG StageSeconds,
    _In_ ULONG TotalSeconds
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    // The enable path is only valid from a clean state. If a previous
    // enable is still active or draining we reject the request instead of
    // stacking registrations.
    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckShield.Enabled,
            0L,
            0L) != 0L ||
        g_KswordArkBugcheckShield.ClassicRegistered ||
        g_KswordArkBugcheckShield.SecondaryRegistered ||
        g_KswordArkBugcheckShield.DumpIoRegistered ||
        g_KswordArkBugcheckShield.AddPagesRegistered) {
        return STATUS_ALREADY_REGISTERED;
    }
    // Wipe accumulators so a re-enable presents a fresh timeline.
    KswordARKBugcheckShieldResetRuntimeLocked();
    g_KswordArkBugcheckShield.ReasonMask = ReasonMask;
    g_KswordArkBugcheckShield.StageSeconds = StageSeconds;
    g_KswordArkBugcheckShield.TotalSeconds = TotalSeconds;
    // Seed the global remaining budget for this enable so callbacks share
    // one bounded pool regardless of how many reasons were requested.
    InterlockedExchange(
        &g_KswordArkBugcheckShield.RemainingBudgetMs,
        (LONG)(TotalSeconds * 1000UL));
    if ((ReasonMask & KSWORD_ARK_BUGCHECK_SHIELD_REASON_CLASSIC) != 0UL) {
        // Classic callbacks use the legacy KeRegisterBugCheckCallback entry;
        // it is the earliest hook Windows offers to a driver during a bug
        // check and has been stable since Windows XP.
        KeInitializeCallbackRecord(&g_KswordArkBugcheckShield.ClassicRecord);
        if (!KeRegisterBugCheckCallback(
                &g_KswordArkBugcheckShield.ClassicRecord,
                KswordARKBugcheckShieldClassicCallback,
                &g_KswordArkBugcheckShield.ClassicBuffer,
                sizeof(g_KswordArkBugcheckShield.ClassicBuffer),
                g_KswordArkBugcheckShieldComponent)) {
            status = STATUS_UNSUCCESSFUL;
            goto Rollback;
        }
        g_KswordArkBugcheckShield.ClassicRegistered = TRUE;
    }
    if ((ReasonMask &
            KSWORD_ARK_BUGCHECK_SHIELD_REASON_SECONDARY_DUMP_DATA) != 0UL) {
        status = KswordARKBugcheckShieldRegisterReasonLocked(
            &g_KswordArkBugcheckShield.SecondaryRecord,
            KbCallbackSecondaryDumpData);
        if (!NT_SUCCESS(status)) {
            goto Rollback;
        }
        g_KswordArkBugcheckShield.SecondaryRegistered = TRUE;
    }
    if ((ReasonMask & KSWORD_ARK_BUGCHECK_SHIELD_REASON_DUMP_IO) != 0UL) {
        status = KswordARKBugcheckShieldRegisterReasonLocked(
            &g_KswordArkBugcheckShield.DumpIoRecord,
            KbCallbackDumpIo);
        if (!NT_SUCCESS(status)) {
            goto Rollback;
        }
        g_KswordArkBugcheckShield.DumpIoRegistered = TRUE;
    }
    if ((ReasonMask & KSWORD_ARK_BUGCHECK_SHIELD_REASON_ADD_PAGES) != 0UL) {
        // KbCallbackAddPages is supported from Windows 8; a failure here is
        // still fatal to enable so R3 sees an explicit reject rather than
        // a silently degraded set of registrations.
        status = KswordARKBugcheckShieldRegisterReasonLocked(
            &g_KswordArkBugcheckShield.AddPagesRecord,
            KbCallbackAddPages);
        if (!NT_SUCCESS(status)) {
            goto Rollback;
        }
        g_KswordArkBugcheckShield.AddPagesRegistered = TRUE;
    }
    // Publish Enabled last so a callback that fires the moment the final
    // record was registered still observes a fully installed Shield.
    InterlockedExchange(&g_KswordArkBugcheckShield.Enabled, 1L);
    return STATUS_SUCCESS;

Rollback:
    // Roll back every record that did register; the drain path is safe to
    // reuse because we never set Enabled=1 on this attempt.
    (VOID)KswordARKBugcheckShieldDeregisterAllLocked();
    KswordARKBugcheckShieldResetRuntimeLocked();
    return status;
}

// Validate the fixed-length request. Returns TRUE only when every field is
// well formed for the current protocol version. The caller guarantees the
// pointer is non-null because WdfRequestRetrieveInputBuffer succeeded.
static BOOLEAN
KswordARKBugcheckShieldRequestValid(
    _In_ const KSWORD_ARK_BUGCHECK_SHIELD_REQUEST* Request
    )
{
    if (Request->size != sizeof(*Request) ||
        Request->version != KSWORD_ARK_BUGCHECK_SHIELD_PROTOCOL_VERSION) {
        return FALSE;
    }
    // Reserved fields exist so future versions can repurpose them; refuse
    // any non-zero value so a v1 driver never accidentally interprets v2
    // request extensions as valid data.
    if (Request->reserved0 != 0UL || Request->reserved1 != 0UL) {
        return FALSE;
    }
    // Only the confirmed flag is defined today; reject unknown bits.
    if ((Request->flags & ~KSWORD_ARK_BUGCHECK_SHIELD_FLAG_UI_CONFIRMED) !=
            0UL) {
        return FALSE;
    }
    // Any of the three actions is acceptable.
    if (Request->action != KSWORD_ARK_BUGCHECK_SHIELD_ACTION_QUERY &&
        Request->action != KSWORD_ARK_BUGCHECK_SHIELD_ACTION_ENABLE &&
        Request->action != KSWORD_ARK_BUGCHECK_SHIELD_ACTION_DISABLE) {
        return FALSE;
    }
    return TRUE;
}

// Fill the fixed-length response, including the currently visible slice of
// the timeline ring.
static VOID
KswordARKBugcheckShieldFillResponseLocked(
    _Out_ KSWORD_ARK_BUGCHECK_SHIELD_RESPONSE* Response,
    _In_ ULONG ProtocolStatus
    )
{
    LONG committed;
    LONG index;

    // Zero the response first so failure paths never leak stale kernel
    // stack data back to R3.
    RtlZeroMemory(Response, sizeof(*Response));
    Response->size = sizeof(*Response);
    Response->version = KSWORD_ARK_BUGCHECK_SHIELD_PROTOCOL_VERSION;
    Response->status = ProtocolStatus;
    Response->stateFlags = KswordARKBugcheckShieldStateFlagsLocked();
    Response->reasonMask = g_KswordArkBugcheckShield.ReasonMask;
    Response->stageSeconds = g_KswordArkBugcheckShield.StageSeconds;
    Response->totalSeconds = g_KswordArkBugcheckShield.TotalSeconds;
    Response->fireCount = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBugcheckShield.FireCount, 0L, 0L);
    committed = InterlockedCompareExchange(
        &g_KswordArkBugcheckShield.TimelineCommittedCount, 0L, 0L);
    if (committed < 0L) {
        committed = 0L;
    }
    if ((ULONG)committed > KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRIES) {
        committed = (LONG)KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRIES;
    }
    Response->timelineCount = (ULONG)committed;
    Response->lastStatus = (LONG)g_KswordArkBugcheckShield.LastStatus;
    // Copy the committed prefix; the remainder was already zeroed above.
    for (index = 0; index < committed; ++index) {
        Response->timeline[index] =
            g_KswordArkBugcheckShield.Timeline[index];
    }
}

// Public initialization entry called from DriverEntry. It only prepares the
// synchronization primitives; no callback is registered until an IOCTL
// arrives with an explicit enable request.
VOID
KswordARKBugcheckShieldInitialize(
    VOID
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    // Diagnostics disabled at compile time: nothing to do.
    return;
#else
    // Zero the state so a fresh driver load starts with an inactive Shield.
    RtlZeroMemory(
        &g_KswordArkBugcheckShield,
        sizeof(g_KswordArkBugcheckShield));
    ExInitializeFastMutex(&g_KswordArkBugcheckShield.ControlLock);
    g_KswordArkBugcheckShield.LastStatus = STATUS_SUCCESS;
#endif
}

// Public uninitialize entry. Called from EvtDriverUnload after the control
// device becomes invisible to user space, so no additional IOCTLs can race.
VOID
KswordARKBugcheckShieldUninitialize(
    VOID
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    return;
#else
    NTSTATUS status;

    // ControlLock is the same one the IOCTL path uses; acquiring it here
    // guarantees the disable path serializes with any final query racing
    // driver unload from user space.
    ExAcquireFastMutex(&g_KswordArkBugcheckShield.ControlLock);
    status = KswordARKBugcheckShieldDisableLocked();
    g_KswordArkBugcheckShield.LastStatus = status;
    ExReleaseFastMutex(&g_KswordArkBugcheckShield.ControlLock);
#endif
}

// IOCTL configure entry point registered in ioctl_registry.c. All input and
// output are fixed-length METHOD_BUFFERED packets, so buffer retrieval and
// bounds checks are trivial and never dereference user-mode pointers
// directly.
NTSTATUS
KswordARKBugcheckShieldIoctlConfigure(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    // Fail closed when the entire diagnostics stack is disabled.
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned != NULL) {
        *BytesReturned = 0U;
    }
    return STATUS_NOT_SUPPORTED;
#else
    KSWORD_ARK_BUGCHECK_SHIELD_REQUEST* input = NULL;
    KSWORD_ARK_BUGCHECK_SHIELD_RESPONSE* output = NULL;
    NTSTATUS status;
    ULONG protocolStatus = KSWORD_ARK_BUGCHECK_SHIELD_STATUS_INVALID_REQUEST;
    ULONG stageSeconds;
    ULONG totalSeconds;

    UNREFERENCED_PARAMETER(Device);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    // Retrieve the fixed-length input buffer; the framework handles all
    // copy-in and access-mode checks for METHOD_BUFFERED.
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(*input),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || InputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    // Retrieve the fixed-length output buffer; refusing here keeps the
    // response layout stable and unambiguous for R3.
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(*output),
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || OutputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    // Serialize the transition. All state mutation happens under this lock
    // so a concurrent query cannot observe a torn snapshot.
    ExAcquireFastMutex(&g_KswordArkBugcheckShield.ControlLock);
    if (!KswordARKBugcheckShieldRequestValid(input)) {
        // Bad header: fail closed and expose the last kernel status so R3
        // can render a precise reason.
        g_KswordArkBugcheckShield.LastStatus = STATUS_INVALID_PARAMETER;
        protocolStatus = KSWORD_ARK_BUGCHECK_SHIELD_STATUS_INVALID_REQUEST;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_SHIELD_ACTION_QUERY) {
        // Query is idempotent and never touches the callback state.
        protocolStatus = InterlockedCompareExchange(
            &g_KswordArkBugcheckShield.Enabled,
            0L,
            0L) != 0L
            ? KSWORD_ARK_BUGCHECK_SHIELD_STATUS_ACTIVE
            : KSWORD_ARK_BUGCHECK_SHIELD_STATUS_INACTIVE;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_SHIELD_ACTION_DISABLE) {
        // Attempt to deregister every callback; the drain path may report
        // BUSY if a callback is still executing on another CPU.
        status = KswordARKBugcheckShieldDisableLocked();
        g_KswordArkBugcheckShield.LastStatus = status;
        protocolStatus = NT_SUCCESS(status)
            ? KSWORD_ARK_BUGCHECK_SHIELD_STATUS_INACTIVE
            : KSWORD_ARK_BUGCHECK_SHIELD_STATUS_BUSY;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_SHIELD_ACTION_ENABLE) {
        if ((input->flags &
                KSWORD_ARK_BUGCHECK_SHIELD_FLAG_UI_CONFIRMED) == 0UL ||
            input->confirmationToken !=
                KSWORD_ARK_BUGCHECK_SHIELD_CONFIRMATION_TOKEN) {
            // Enable requires the explicit UI-side confirmation contract.
            g_KswordArkBugcheckShield.LastStatus = STATUS_ACCESS_DENIED;
            protocolStatus =
                KSWORD_ARK_BUGCHECK_SHIELD_STATUS_CONFIRMATION_NEEDED;
        }
        else if ((input->reasonMask &
                    ~KSWORD_ARK_BUGCHECK_SHIELD_REASON_ALL) != 0UL ||
                 input->reasonMask == 0UL) {
            // Reason mask must select at least one supported reason and
            // must not include unknown bits.
            g_KswordArkBugcheckShield.LastStatus = STATUS_INVALID_PARAMETER;
            protocolStatus =
                KSWORD_ARK_BUGCHECK_SHIELD_STATUS_INVALID_REQUEST;
        }
        else {
            // Apply defaults for zero values so R3 can send a minimal
            // request; then clamp both knobs to the shared caps.
            stageSeconds = input->stageSeconds == 0UL
                ? KSWORD_ARK_BUGCHECK_SHIELD_DEFAULT_STAGE_SECONDS
                : input->stageSeconds;
            totalSeconds = input->totalSeconds == 0UL
                ? KSWORD_ARK_BUGCHECK_SHIELD_DEFAULT_TOTAL_SECONDS
                : input->totalSeconds;
            if (stageSeconds >
                    KSWORD_ARK_BUGCHECK_SHIELD_STAGE_MAX_SECONDS) {
                stageSeconds =
                    KSWORD_ARK_BUGCHECK_SHIELD_STAGE_MAX_SECONDS;
            }
            if (totalSeconds >
                    KSWORD_ARK_BUGCHECK_SHIELD_TOTAL_MAX_SECONDS) {
                totalSeconds =
                    KSWORD_ARK_BUGCHECK_SHIELD_TOTAL_MAX_SECONDS;
            }
            // Enforce total >= stage so at least one full stage fits.
            if (stageSeconds > totalSeconds) {
                stageSeconds = totalSeconds;
            }
            status = KswordARKBugcheckShieldEnableLocked(
                input->reasonMask,
                stageSeconds,
                totalSeconds);
            g_KswordArkBugcheckShield.LastStatus = status;
            if (status == STATUS_SUCCESS) {
                protocolStatus = KSWORD_ARK_BUGCHECK_SHIELD_STATUS_ACTIVE;
            }
            else if (status == STATUS_ALREADY_REGISTERED) {
                protocolStatus = KSWORD_ARK_BUGCHECK_SHIELD_STATUS_ACTIVE;
            }
            else if (status == STATUS_NOT_SUPPORTED) {
                protocolStatus =
                    KSWORD_ARK_BUGCHECK_SHIELD_STATUS_UNSUPPORTED;
            }
            else {
                protocolStatus =
                    KSWORD_ARK_BUGCHECK_SHIELD_STATUS_REGISTRATION_FAILED;
            }
        }
    }

    // Serialize the response snapshot under the same lock so state and
    // timeline agree with each other for this reply.
    KswordARKBugcheckShieldFillResponseLocked(output, protocolStatus);
    ExReleaseFastMutex(&g_KswordArkBugcheckShield.ControlLock);
    *BytesReturned = sizeof(*output);
    return STATUS_SUCCESS;
#endif
}
