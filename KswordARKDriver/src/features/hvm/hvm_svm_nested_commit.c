/* VMEXIT-safe output adapter; one processor-private mapping per VMCB writeback. */
#include "hvm_svm_nested_runtime.h"

/* The caller has already translated the operand with write permission through NPT01. */
int KswordSvmNestedCommitVmcb(void* Context, KSW_SVM_U64 HostPa,
    const KSW_SVM_VMCB* Image, unsigned int Operation, unsigned int NestedPaging,
    unsigned int* WordsWritten)
{
    /* No guest pointer is treated as a root virtual address. */
    KSW_SVM_NESTED* nested = Context;
    /* The mapping is held only while applying the bounded field whitelist. */
    volatile VOID* mapped = NULL;
    /* Each iteration handles one aligned word, preserving all unowned bits. */
    ULONG offset, attempt;
    /* A failure after progress is not equivalent to a rejected, untouched operand. */
    if (!WordsWritten) { return 0; }
    /* No write can precede publication of zero progress. */
    *WordsWritten = 0;
    /* Validate a complete RAM page before acquiring the mapping. */
    if (!Image || (HostPa & 4095ULL) || NestedPaging > 1U ||
        Operation < KSW_NSVM_SAVE_VMEXIT || Operation > KSW_NSVM_SAVE_VMSAVE ||
        !KswordSvmNestedRamRange(nested, HostPa, 4096) ||
        KswordARKHvmPhysWindowMap(nested->Window, HostPa, 4096, &mapped) != KSW_HVM_PHYS_WINDOW_OK) { return 0; }
    /* Fixed page size ensures no write can escape the validated mapping. */
    for (offset = 0; offset < 4096; offset += 8) {
        /* The driver, not the inner VMM, chooses the writable fields. */
        ULONGLONG mask = KswSvmNestedWritebackMask(offset, Operation, NestedPaging);
        /* Reserved fields and all hardware pointer controls are untouched. */
        if (mask) {
            /* Source is a CPU-owned byte image; the destination is a mapped aligned word. */
            ULONGLONG source = KswSvmRead64(Image, offset);
            /* Atomic masked replacement preserves unrelated control bits under contention. */
            volatile LONG64* slot = (volatile LONG64*)((volatile UCHAR*)mapped + offset);
            /* Capture the value for the first compare-exchange attempt. */
            LONG64 observed = *slot;
            /* A competing writer cannot force an unbounded root-mode spin. */
            for (attempt = 0; attempt < 64; ++attempt) {
                /* Replace only the architectural result subset of this word. */
                LONG64 desired = (LONG64)(((ULONGLONG)observed & ~mask) | (source & mask));
                /* The hardware instruction does not take a kernel lock or wait on another CPU. */
                LONG64 previous = InterlockedCompareExchange64(slot, desired, observed);
                /* Count complete stores, including idempotent values. */
                if (previous == observed) { ++*WordsWritten; break; }
                /* Retry from the observed competing value while retaining unrelated bits. */
                observed = previous;
            }
            /* A partially committed image requires diagnosis, never an automatic replay. */
            if (attempt == 64) { KswordARKHvmPhysWindowUnmap(nested->Window); return 0; }
        }
    }
    /* No physical mapping pointer survives this callback. */
    KswordARKHvmPhysWindowUnmap(nested->Window);
    /* All selected fields have been written before the virtual host may resume. */
    return 1;
}
