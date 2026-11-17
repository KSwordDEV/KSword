#include <ntifs.h>
#include "process_crossview.h"
#include "../../platform/runtime_signature_scan.h"

NTKERNELAPI POBJECT_TYPE NTAPI ObGetObjectType(_In_ PVOID Object);
typedef BOOLEAN (NTAPI* KSW_CID_LOCKED_CALLBACK)(PVOID Table, PVOID Entry, HANDLE Id, PVOID Context);
NTKERNELAPI BOOLEAN NTAPI ExEnumHandleTable(PVOID Table, KSW_CID_LOCKED_CALLBACK Callback, PVOID Context, PHANDLE Id);
NTKERNELAPI VOID FASTCALL ExfUnblockPushLock(PEX_PUSH_LOCK Lock, PVOID WaitBlock);

typedef struct _KSW_CID_PROTECTED_CONTEXT {
    const KSW_DYN_STATE* Dyn; // Per-request validated field snapshot.
    POBJECT_TYPE Type; // Only referenced objects are inspected for this type.
    KSW_CROSSVIEW_CID_CALLBACK Callback; // Existing consumers retain balanced-reference ownership.
    PVOID Parameter; // Consumer's request-local state.
    ULONG Maximum; // Bound all occupied entries, regardless of type.
    ULONG Visited; // Count protected entries observed.
    NTSTATUS Status; // Any inability to reference an occupied slot makes the view incomplete.
} KSW_CID_PROTECTED_CONTEXT;

// CID values encode object bodies; calibrate against PID 4 before any header access.
static PVOID KswCidDecode(ULONGLONG Value)
{
    return (PVOID)(ULONG_PTR)(((ULONGLONG)((LONGLONG)Value >> 16)) & ~0xFULL); // Existing CID encoding, independently checked below.
}

static BOOLEAN NTAPI KswCidProtectedCallback(PVOID Table, PVOID Entry, HANDLE Id, PVOID Parameter)
{
    KSW_CID_PROTECTED_CONTEXT* ctx = (KSW_CID_PROTECTED_CONTEXT*)Parameter; // ExEnum owns the entry lock on entry.
    ULONGLONG low = 0ULL; // Copy the encoded slot before reference acquisition.
    PVOID object = NULL; // A decoded address is not yet safe to inspect.
    BOOLEAN referenced = FALSE; // Counts only successful ObReferenceObjectSafe.
    BOOLEAN stop = FALSE; // Always unlock, even when the budget is reached.
    ULONG_PTR contention = 0U; // Read the contention field through the safe reader.
    KSW_CROSSVIEW_CID_ENTRY result; // Same in-kernel payload as the existing walker.
    if (++ctx->Visited > ctx->Maximum) { // Occupied-entry budget is independent of returned row count.
        ctx->Status = STATUS_BUFFER_OVERFLOW; // Do not claim a complete source.
        stop = TRUE; // Release the lock before stopping enumeration.
    }
    else if (!KswordARKRuntimeReadMemory(Entry, &low, sizeof(low))) { // A protected entry still needs a complete read.
        ctx->Status = STATUS_PARTIAL_COPY; // Preserve incompleteness.
    }
    else {
        object = KswCidDecode(low); // System-slot calibration established the encoding.
        if (object != NULL && KswordARKCrossViewPointerAligned((ULONG_PTR)object)) { // Reject malformed slot values.
            referenced = ObReferenceObjectSafe(object); // Entry lock prevents normal CID removal/reclamation during acquisition.
            if (!referenced) { // Deleting objects cannot establish a complete type view.
                ctx->Status = STATUS_DELETE_PENDING; // Never interpret a failed reference as death.
            }
        }
        else { // An occupied but undecodable entry invalidates absence conclusions.
            ctx->Status = STATUS_DATA_ERROR; // Keep source failure separate from existing rows.
        }
    }
    InterlockedExchangeAdd64((volatile LONG64*)Entry, 1); // Release the entry lock exactly once, matching the existing handle enumerator.
    if (KswordARKRuntimeReadMemory((PUCHAR)Table + ctx->Dyn->Kernel.HtHandleContentionEvent, &contention, sizeof(contention)) && contention != 0U) { // Wake blocked table users only when needed.
        ExfUnblockPushLock((PEX_PUSH_LOCK)((PUCHAR)Table + ctx->Dyn->Kernel.HtHandleContentionEvent), NULL); // Same target-validated unlock protocol as handle_query.c.
    }
    if (referenced) { // All object-manager/type/accessor calls below own a reference.
        if (ObGetObjectType(object) == ctx->Type) { // Process and thread entries share the CID table.
            RtlZeroMemory(&result, sizeof(result)); // No uninitialized protocol evidence.
            result.Object = object; // The callback borrows this protected reference.
            result.ObjectAddress = (ULONG64)(ULONG_PTR)object; // Identity is independent of a modified PID field.
            result.CidValue = HandleToULong(Id); // Preserve the real table identity.
            result.Referenced = TRUE; // Consumers may safely inspect the object now.
            result.TypeMatched = TRUE; // Type confirmed only after acquisition.
            result.ReferenceStatus = STATUS_SUCCESS; // The acquisition succeeded.
            ctx->Callback(&result, ctx->Parameter); // Slow sampling runs after releasing the CID entry lock.
        }
        ObDereferenceObject(object); // Balance every reference regardless of type or consumer result.
    }
    return stop; // TRUE means the bounded enumeration must stop.
}

NTSTATUS KswordARKCrossViewWalkCidTableProtected(
    const KSW_DYN_STATE* Dyn, PVOID TableVariable, POBJECT_TYPE Type,
    ULONG Maximum, KSW_CROSSVIEW_CID_CALLBACK Callback, PVOID Parameter, ULONG* Visited)
{
    PVOID table = NULL; // The CID HANDLE_TABLE, never a user-supplied pointer.
    ULONGLONG code = 0ULL; // Read the root/level without touching an object header.
    ULONGLONG root; // Table root after stripping level bits.
    ULONGLONG low = 0ULL; // PID 4 slot encoding for anchor calibration.
    ULONG level; // Only verified modern x64 table levels are accepted.
    KSW_CID_PROTECTED_CONTEXT ctx; // No global mutable acquisition state.
    if (Dyn == NULL || Type == NULL || Callback == NULL || Maximum == 0UL || KeGetCurrentIrql() != PASSIVE_LEVEL ||
        Dyn->Kernel.HtTableCode == KSW_DYN_OFFSET_UNAVAILABLE || Dyn->Kernel.HtHandleContentionEvent == KSW_DYN_OFFSET_UNAVAILABLE ||
        Dyn->Kernel.HtHandleContentionEvent > 0x1000UL) { // Never guess an entry-unlock layout.
        return STATUS_NOT_SUPPORTED; // Caller may keep the existing lookup-backed evidence path.
    }
    if (!KswordARKRuntimeReadMemory(TableVariable, &table, sizeof(table)) || table == NULL ||
        !KswordARKRuntimeReadMemory((PUCHAR)table + Dyn->Kernel.HtTableCode, &code, sizeof(code))) { // Capture the actual CID table root safely.
        return STATUS_NOT_SUPPORTED; // No protected acquisition has started.
    }
    level = (ULONG)(code & 3ULL); // CID table level is part of the anchor-validated encoding.
    root = code & ~3ULL; // Root address is only used through safe reads.
    if (level > 2UL) { // Unknown layouts are not eligible for direct object referencing.
        return STATUS_NOT_SUPPORTED; // Preserve fallback behavior.
    }
    while (level-- != 0UL) { // PID 4 is in the first leaf at every supported level.
        if (!KswordARKRuntimeReadMemory((PVOID)(ULONG_PTR)root, &root, sizeof(root)) || root == 0ULL) { // Read each table pointer independently.
            return STATUS_NOT_SUPPORTED; // Calibration cannot complete.
        }
    }
    if (!KswordARKRuntimeReadMemory((PVOID)(ULONG_PTR)(root + 16ULL), &low, sizeof(low)) ||
        KswCidDecode(low) != PsInitialSystemProcess) { // Exact known object proves this is the expected CID-body encoding.
        return STATUS_NOT_SUPPORTED; // No speculative header references.
    }
    RtlZeroMemory(&ctx, sizeof(ctx)); // Initialize bounded walk bookkeeping.
    ctx.Dyn = Dyn; // Preserve the exact unlock-layout snapshot.
    ctx.Type = Type; // Restrict observations to the requested object kind.
    ctx.Callback = Callback; // Caller receives balanced borrowed references.
    ctx.Parameter = Parameter; // Request-local consumer state.
    ctx.Maximum = Maximum; // Stop cleanly after the caller's budget.
    ctx.Status = STATUS_SUCCESS; // Any callback failure can only downgrade this result.
    KeEnterCriticalRegion(); // Match handle-table enumeration's APC discipline.
    (VOID)ExEnumHandleTable(table, KswCidProtectedCallback, &ctx, NULL); // The kernel protects each slot while the reference is acquired.
    KeLeaveCriticalRegion(); // Always restore the caller's APC state.
    if (Visited != NULL) { // Optional diagnostics never change the outcome.
        *Visited = ctx.Visited; // Report the actual protected walk count.
    }
    return ctx.Status; // Complete or explicitly partial, never silently complete.
}
