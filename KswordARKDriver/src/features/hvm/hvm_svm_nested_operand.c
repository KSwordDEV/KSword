/* Read-only operand capture. No direct guest PA casts or root-mode allocations. */
#include "hvm_svm_nested_operand.h"

/* Failure clears copied bytes so a partial image cannot be mistaken for an operand. */
static unsigned int KswNsvmOperandFail(unsigned char* Destination,
    KSW_NSVM_OPERAND_RESULT* Result, unsigned int Status)
{
    /* Only the supplied private destination is modified. */
    unsigned int index;
    /* Preserve the precise failure and amount of work for diagnosis. */
    if (Result) { Result->Status = Status; }
    /* Null destination is itself a caller error, not a reason to dereference it. */
    if (Destination) {
        /* Never expose a mixture of old bytes and a partially captured new page. */
        for (index = 0; index < 4096U; ++index) { Destination[index] = 0; }
    }
    /* The caller must not publish a ready VMCB/map following this return. */
    return Status;
}

/* Perform one bounded copy while the caller holds the prepared NPT01 lifetime. */
unsigned int KswSvmNestedReadOperandPage(const KSW_NSVM_OPERAND_IO* Io,
    KSW_SVM_U64 GuestPa, unsigned char* Destination, KSW_NSVM_OPERAND_RESULT* Result)
{
    /* Keep the source path for a final structural recheck after copying. */
    KSW_NNPT_WALK walk;
    /* Every physical callback returns one complete initialized word. */
    KSW_SVM_U64 value;
    /* Offset and recheck loops have fixed architecture bounds. */
    unsigned int offset, byte, status;
    /* Zero result fields even when the operand is rejected before its first read. */
    const KSW_NSVM_OPERAND_RESULT empty = {0};
    /* A missing result is a programming error; never return synthetic success. */
    if (!Result) { return KswNsvmOperandFail(Destination, Result, KSW_NNPT_UNSUPPORTED); }
    /* Preserve the submitted L1 physical address separately from its translation. */
    *Result = empty; Result->GuestPa = GuestPa;
    /* Full-page reads start at a page boundary; callers normalize map bases first. */
    if (!Io || !Io->Read || !Destination || (GuestPa & 4095ULL)) {
        /* Reject before looking up any untrusted memory. */
        return KswNsvmOperandFail(Destination, Result, KSW_NNPT_UNSUPPORTED);
    }
    /* Translate L1 GPA through L0's outer map, not through the L1-owned NPT12. */
    status = KswSvmNestedNptWalk(Io->Root, GuestPa, Io->PhysicalBits, Io->Page1Gb,
        Io->Nx, 0, Io->Read, Io->Context, &walk);
    /* A fault in NPT01 must never be reflected as a fabricated L2 NPF. */
    if (status != KSW_NNPT_OK) { return KswNsvmOperandFail(Destination, Result, status); }
    /* The existing physical RAM window uses WB; reject other PAT classifications. */
    if (((Io->Pat >> (8U * walk.PatIndex)) & 0xffULL) != 6ULL) {
        /* This API does not map MMIO or reinterpret UC/WC/WT memory as WB. */
        return KswNsvmOperandFail(Destination, Result, KSW_NNPT_UNSUPPORTED);
    }
    /* A 4-KiB aligned GPA remains aligned through supported 4K/2M/1G mappings. */
    Result->HostPa = walk.Address;
    /* Every read still passes the trusted RAM inventory check in the platform callback. */
    for (offset = 0; offset < 4096U; offset += 8U) {
        /* The current page's full physical range is within the successfully walked leaf. */
        if (!Io->Read(Io->Context, walk.Address + offset, &value)) {
            /* Preserve partial progress, but remove the partial data itself. */
            return KswNsvmOperandFail(Destination, Result, KSW_NNPT_UNREADABLE);
        }
        /* Byte stores support any private snapshot alignment without aliasing assumptions. */
        for (byte = 0; byte < 8U; ++byte) { Destination[offset + byte] = (unsigned char)(value >> (8U * byte)); }
        /* This count is evidence of completed reads, never a readiness flag. */
        ++Result->Words;
    }
    /* A concurrent structural remap invalidates this copy before publication. */
    for (offset = 0; offset < walk.Count; ++offset) {
        /* The callback again enforces physical RAM ownership on each source table. */
        if (!Io->Read(Io->Context, walk.EntryAddress[offset], &value)) {
            /* A disappearing table is a failed capture, not an empty permission map. */
            return KswNsvmOperandFail(Destination, Result, KSW_NNPT_UNREADABLE);
        }
        /* Hardware A/D updates alone do not change the mapped frame or permissions. */
        if ((value ^ walk.EntryValue[offset]) & ~0x60ULL) {
            /* Caller may retry at a later bounded entry attempt; this routine never spins. */
            return KswNsvmOperandFail(Destination, Result, KSW_NNPT_RETRY);
        }
    }
    /* The caller still owns data-page synchronization and executable publication. */
    Result->Status = KSW_NNPT_OK;
    /* This routine did not change page tables, TLB state, or any guest registers. */
    return KSW_NNPT_OK;
}
