#include <ntifs.h>
#include "process_lifetime.h"
#include "process_crossview.h"
#include "../../platform/runtime_signature_scan.h"

extern POBJECT_TYPE* PsThreadType; // Exported type is consulted only after a reference.
NTKERNELAPI LONGLONG NTAPI PsGetProcessCreateTimeQuadPart(_In_ PEPROCESS Process);
NTKERNELAPI PEPROCESS NTAPI PsGetThreadProcess(_In_ PETHREAD Thread);
typedef BOOLEAN (NTAPI* KSW_EXIT_CALLED)(_In_ PEPROCESS Process);

// Valid offsets come from the current, already validated DynData snapshot.
static BOOLEAN KswLifeRead(PVOID Object, ULONG Offset, PVOID Out, SIZE_T Bytes)
{
    if (Object == NULL || Offset == 0UL || Offset == KSW_DYN_OFFSET_UNAVAILABLE || Offset > 0x4000UL) { // Reject unavailable or implausible layouts.
        return FALSE; // Failure is unknown evidence, never a zero value.
    }
    return KswordARKRuntimeReadMemory((PUCHAR)Object + Offset, Out, Bytes); // No unguarded candidate access.
}

// A zero timeout polls the referenced dispatcher object without blocking.
static NTSTATUS KswLifePoll(PVOID Object)
{
    LARGE_INTEGER zero; // NULL would wait forever, so always supply this value.
    zero.QuadPart = 0; // No timed delay is introduced into enumeration.
    return KeWaitForSingleObject(Object, Executive, KernelMode, FALSE, &zero); // Preserve the exact status, including positive STATUS_TIMEOUT.
}

VOID KswordARKProcessSampleLifetime(KSWORD_ARK_PROCESS_ENTRY* Entry, PEPROCESS Process, const KSW_DYN_STATE* Dyn)
{
    UNICODE_STRING name; // Resolve an exported semantic accessor instead of guessing Flags bits.
    KSW_EXIT_CALLED exitCalled; // NULL leaves the corresponding evidence unavailable.
    ULONG active = MAXULONG; // Unknown is distinct from zero threads.
    PVOID table = NULL; // NULL counts only after a successful field read.
    LONGLONG exitTime = 0; // Zero remains an unproven exit timestamp.
    if (Entry == NULL || Process == NULL || Dyn == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) { // Wait/accessor preconditions.
        return; // Leave all evidence unset.
    }
    Entry->processObjectAddress = (ULONG64)(ULONG_PTR)Process; // Diagnostic identity, never an accepted R3 pointer.
    Entry->creationTime100ns = (ULONG64)PsGetProcessCreateTimeQuadPart(Process); // Same referenced object supplies creation identity.
    Entry->observedProcessId = HandleToULong(PsGetProcessId(Process)); // Preserve tampered PID fields separately from the CID.
    Entry->flags |= KSWORD_ARK_PROCESS_FLAG_OBJECT_REFERENCED; // Reference validity is independent of lifetime/source membership.
    Entry->exitEvidence = KSWORD_ARK_PROCESS_EXIT_REFERENCE; // Every other evidence starts unavailable.
    Entry->exitWaitStatus = KswLifePoll(Process); // Sample the actual process object.
    if (Entry->exitWaitStatus == STATUS_SUCCESS) { // Exact comparison avoids treating STATUS_TIMEOUT as death.
        Entry->exitEvidence |= KSWORD_ARK_PROCESS_EXIT_SIGNALED; // One evidence family only.
    }
    if (KswLifeRead(Process, Dyn->Kernel.EpExitTime, &exitTime, sizeof(exitTime)) &&
        exitTime > 0 && (ULONG64)exitTime >= Entry->creationTime100ns && Entry->creationTime100ns != 0ULL) { // Require a coherent nonzero timestamp.
        Entry->exitTime100ns = (ULONG64)exitTime; // Preserve the raw timestamp.
        Entry->exitEvidence |= KSWORD_ARK_PROCESS_EXIT_TIME_VALID; // Layout/read failures never pass.
    }
    RtlInitUnicodeString(&name, L"PsGetProcessExitProcessCalled"); // This accessor is independently resolved by the existing runtime layout code too.
    exitCalled = (KSW_EXIT_CALLED)MmGetSystemRoutineAddress(&name); // Missing exports are an explicit evidence gap.
    if (exitCalled != NULL && exitCalled(Process)) { // Sample verified object only.
        Entry->exitEvidence |= KSWORD_ARK_PROCESS_EXIT_CALLED; // Records completed entry into the exit path, not death alone.
    }
    if (KswLifeRead(Process, Dyn->Kernel.EpActiveThreads, &active, sizeof(active))) { // Use the current verified layout.
        Entry->activeThreadCount = active; // Preserve zero versus missing.
        if (active == 0UL) { // Thread count alone cannot exclude a candidate.
            Entry->exitEvidence |= KSWORD_ARK_PROCESS_EXIT_ZERO_THREADS; // Require independent thread views below.
        }
    }
    if (KswLifeRead(Process, Dyn->Kernel.EpObjectTable, &table, sizeof(table)) && table == NULL) { // Only successfully observed NULL counts.
        Entry->exitEvidence |= KSWORD_ARK_PROCESS_EXIT_NO_OBJECT_TABLE; // Resources have reached this teardown milestone.
    }
    if (KswLifePoll(Process) != Entry->exitWaitStatus) { // State changed during sampling: no coherent proof.
        Entry->exitEvidence &= ~KSWORD_ARK_PROCESS_EXIT_SIGNALED; // Keep the row anomalous for this sample.
    }
}

typedef struct _KSW_LIFE_CID_CONTEXT {
    KSWORD_ARK_ENUM_PROCESS_RESPONSE* Response; // Entries carry frozen process object identities.
} KSW_LIFE_CID_CONTEXT;

// All unfinished CID threads veto exclusion of their referenced owner object.
static VOID KswLifeCidThread(const KSW_CROSSVIEW_CID_ENTRY* Thread, PVOID Context)
{
    KSW_LIFE_CID_CONTEXT* ctx = (KSW_LIFE_CID_CONTEXT*)Context; // Caller owns response for the full scan.
    PEPROCESS owner; // Valid while the referenced ETHREAD is held.
    ULONG index; // No PID matching: the owner address is the identity.
    if (!Thread->Referenced || Thread->Object == NULL) { // Unknown thread evidence cannot prove a quiet view.
        for (index = 0UL; index < ctx->Response->returnedCount; ++index) { // Conservatively veto this incomplete view.
            if (Thread->ObservedOwnerAddress == 0ULL || ctx->Response->entries[index].processObjectAddress == Thread->ObservedOwnerAddress) { // A known owner's unfinished thread only vetoes that owner.
                ctx->Response->entries[index].exitEvidence &= ~KSWORD_ARK_PROCESS_EXIT_CID_THREADS_QUIET; // Unresolved ownership retains the global veto.
            }
        }
        return; // Never call accessors on unreferenced addresses.
    }
    if (KswLifePoll(Thread->Object) == STATUS_SUCCESS) { // Already terminated threads are legitimate retained objects.
        return; // No live-thread contradiction.
    }
    owner = PsGetThreadProcess((PETHREAD)Thread->Object); // Exact owner, independent of a modified PID field.
    for (index = 0UL; index < ctx->Response->returnedCount; ++index) { // Apply the veto to matching process objects.
        KSWORD_ARK_PROCESS_ENTRY* row = &ctx->Response->entries[index]; // A frozen evidence record only.
        if (row->processObjectAddress == (ULONG64)(ULONG_PTR)owner) { // Avoid PID reuse collisions.
            row->exitEvidence &= ~KSWORD_ARK_PROCESS_EXIT_CID_THREADS_QUIET; // Any unfinished thread wins over apparent death.
        }
    }
}

VOID KswordARKProcessFinalizeLifetime(KSWORD_ARK_ENUM_PROCESS_RESPONSE* Response, const KSW_DYN_STATE* Dyn)
{
    PVOID table = NULL; // Resolved kernel-owned CID table variable.
    ULONG64 missing = 0ULL; // Source availability remains explicit.
    BOOLEAN used = FALSE; // Resolver provenance output.
    ULONG visited = 0UL; // Bounded CID leaf scan count.
    ULONG index; // Iterate actual returned records only.
    ULONG attempt; // Bound re-collection when an unrelated CID is removed during a read-only walk.
    NTSTATUS status; // Any incomplete thread view vetoes exclusion.
    KSW_LIFE_CID_CONTEXT ctx; // Per-request, no shared mutable lifetime cache.
    if (PsThreadType == NULL || *PsThreadType == NULL) { // Missing type means unavailable thread cross-check.
        return; // All CID_THREAD evidence remains clear.
    }
    ctx.Response = Response; // Callback never outlives this request.
    for (index = 0UL; index < Response->returnedCount; ++index) { // Initialize provisional thread evidence.
        KSWORD_ARK_PROCESS_ENTRY* row = &Response->entries[index]; // Per-row reference evidence was already sampled.
        row->exitEvidence |= KSWORD_ARK_PROCESS_EXIT_CID_THREADS_QUIET; // Revoked by any unfinished thread or scan failure.
        if (row->observedProcessId != row->processId) { // Even known self-hidden PID changes stay anomalous.
            row->flags |= KSWORD_ARK_PROCESS_FLAG_PID_FIELD_MISMATCH; // Never conceal identity tampering as ordinary residue.
        }
    }
    status = KswordARKCrossViewResolvePspCidTableAddress(Dyn, NULL, &table, &missing, &used); // No source substitution on failure.
    if (NT_SUCCESS(status)) { // Walk only a successfully resolved table.
        for (attempt = 0UL; attempt < 3UL; ++attempt) { // A later complete view may finish resolving a concurrently removed slot.
            status = KswordARKCrossViewWalkCidTable(Dyn, table, *PsThreadType, 0x100000UL, KswLifeCidThread, &ctx, &visited); // Reuse protected acquisition or the existing exact-lookup fallback.
            if (status != STATUS_PARTIAL_COPY && status != STATUS_DELETE_PENDING) { // Permanent capability/read/budget failures are not retried.
                break; // Every positive unfinished-owner veto from every attempt remains cleared.
            }
        }
    }
    if (!NT_SUCCESS(status)) { // Truncation/read failures cannot establish absence.
        for (index = 0UL; index < Response->returnedCount; ++index) { // Preserve each candidate but invalidate this family.
            Response->entries[index].exitEvidence &= ~KSWORD_ARK_PROCESS_EXIT_CID_THREADS_QUIET; // Conservative evidence failure.
        }
    }
}
