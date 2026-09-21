/* Allocation-free per-CPU recorder: no guest memory reads, locks or architectural writes. */
#include "hvm_svm_flightrecorder.h"
#include <string.h>
/* Capture only caller-selected observations; normal exceptions never freeze the recorder. */
void KswSvmFlightRecord(KSWORD_HVM_FLIGHT_RECORDER* Flight, const KSW_SVM_VMCB* Current,
    unsigned Kind, unsigned Phase, unsigned Action, unsigned Generation,
    KSW_SVM_U64 Tsc, KSW_SVM_U64 OperandPa, KSW_SVM_U64 LeaseToken)
{
    /* The destination lives in preallocated processor-private storage. */
    KSWORD_HVM_FLIGHT_ROW* row;
    /* Preserve the first incident across all later entries, exits and stops. */
    if (!Flight || !Current || Flight->latched) { return; }
    /* Advance in bounded storage without allocating a temporary record on the root stack. */
    row = &Flight->rows[Flight->next];
    /* Saturation never wraps the lifetime identity to zero. */
    if (Flight->total != ~0ULL) { ++Flight->total; }
    /* Store the originating execution identity before interpretation changes ownership. */
    row->ordinal = Flight->total; row->tsc = Tsc; row->operandPa = OperandPa; row->leaseToken = LeaseToken;
    /* Label entry and raw-exit samples explicitly. */
    row->kind = Kind; row->phase = Phase; row->action = Action; row->generation = Generation;
    /* All reads use trusted owned VMCB pages. */
    row->exitCode = KswSvmRead64(Current, KSW_VMCB_EXITCODE);
    /* Preserve architecture-specific qualification without Intel index conversion. */
    row->info1 = KswSvmRead64(Current, KSW_VMCB_EXITINFO1); row->info2 = KswSvmRead64(Current, KSW_VMCB_EXITINFO2);
    /* These values describe the image at the named capture point. */
    row->rip = KswSvmRead64(Current, KSW_VMCB_RIP); row->rsp = KswSvmRead64(Current, KSW_VMCB_RSP);
    /* CR2 and CR3 aid distinguishing paging failures from event delivery failures. */
    row->cr2 = KswSvmRead64(Current, KSW_VMCB_CR2); row->cr3 = KswSvmRead64(Current, KSW_VMCB_CR3);
    /* Keep both pending injection and interrupted delivery, including valid/error-code bits. */
    row->event = KswSvmRead64(Current, KSW_VMCB_EVENT); row->exitIntInfo = KswSvmRead64(Current, KSW_VMCB_EXITINTINFO);
    /* NRIP is raw evidence, not an instruction-retirement decision. */
    row->nrip = KswSvmRead64(Current, KSW_VMCB_NRIP);
    /* Publish ring order within the caller's sequence-protected mutation. */
    Flight->next = (Flight->next + 1U) % KSW_HVM_FLIGHT_ROWS;
    /* Count never exceeds the fixed capacity. */
    if (Flight->count < KSW_HVM_FLIGHT_ROWS) { ++Flight->count; }
}
/* The first terminal observation wins; later routine activity cannot erase its pages. */
void KswSvmFlightLatch(KSWORD_HVM_FLIGHT_RECORDER* Flight, const KSW_SVM_VMCB* Current,
    const KSW_SVM_VMCB* Vmcb12, unsigned Reason, unsigned Timing)
{
    /* A missing current image must not produce a supposedly complete snapshot. */
    if (!Flight || !Current || Flight->latched || !Reason) { return; }
    /* Preserve the full hardware image before the caller performs any reflection when Timing=1. */
    memcpy(Flight->currentVmcb, Current, sizeof(Flight->currentVmcb));
    /* Only an active inner session gives the saved operand an attributable meaning. */
    if (Vmcb12) { memcpy(Flight->vmcb12, Vmcb12, sizeof(Flight->vmcb12)); }
    /* Explicit absence prevents stale operand bytes being mistaken for this incident. */
    else { memset(Flight->vmcb12, 0, sizeof(Flight->vmcb12)); }
    /* Timing two deliberately does not promise the pre-dispatch architectural state. */
    Flight->vmcb12Valid = Vmcb12 != NULL; Flight->reason = Reason; Flight->captureTiming = Timing;
    /* The platform wrapper release-publishes this immutable snapshot after this function returns. */
    Flight->latched = 1;
}
