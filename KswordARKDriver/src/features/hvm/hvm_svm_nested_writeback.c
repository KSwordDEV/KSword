/* Copy only hardware-owned output fields; never install a host pointer in VMCB12. */
#include "hvm_svm_nested_writeback.h"

/* All full-word ranges are aligned, with an exclusive upper bound. */
KSW_SVM_U64 KswSvmNestedWritebackMask(unsigned int Offset,
    unsigned int Operation, unsigned int NestedPaging)
{
    /* Unaligned/out-of-page requests are never authorized by this whitelist. */
    if ((Offset & 7U) || Offset >= 4096U || NestedPaging > 1U) { return 0; }
    /* VMSAVE cannot overwrite automatic VMRUN state or control pointers. */
    if (Operation == KSW_NSVM_SAVE_VMSAVE) {
        /* FS/GS, LDTR, TR and the syscall/system-entry register group. */
        return ((Offset >= 0x440U && Offset < 0x460U) ||
            (Offset >= 0x470U && Offset < 0x480U) ||
            (Offset >= 0x490U && Offset < 0x4a0U) ||
            (Offset >= 0x600U && Offset < 0x640U)) ? ~0ULL : 0;
    }
    /* Software admission failures do not save an unexecuted guest context. */
    if (Operation == KSW_NSVM_SAVE_INVALID) {
        /* INVALID and deterministic diagnostic operands are the only writes. */
        return Offset >= 0x070U && Offset < 0x090U ? ~0ULL : 0;
    }
    /* Unknown operations cannot accidentally become a whole-page memcpy. */
    if (Operation != KSW_NSVM_SAVE_VMEXIT) { return 0; }
    /* Preserve L1's interrupt policy while updating hardware V_IRQ/V_TPR. */
    if (Offset == 0x060U) { return 0x10fULL; }
    /* Only the implemented interrupt-shadow bit is hardware output here. */
    if (Offset == 0x068U) { return 1; }
    /* Full-width exit operands and NRIP are returned to the virtual VMM. */
    if ((Offset >= 0x070U && Offset < 0x090U) ||
        (Offset >= 0x0c8U && Offset < 0x0e0U)) { return ~0ULL; }
    /* CPL shares an aligned word with seven reserved bytes. */
    if (Offset == 0x4c8U) { return 0xffULL << 24; }
    /* Automatic ES/CS/SS/DS, GDTR, IDTR, EFER and general execution state. */
    if ((Offset >= 0x400U && Offset < 0x440U) ||
        (Offset >= 0x460U && Offset < 0x470U) ||
        (Offset >= 0x480U && Offset < 0x490U) || Offset == 0x4d0U ||
        (Offset >= 0x548U && Offset < 0x580U) ||
        (Offset >= 0x5d8U && Offset < 0x600U) || Offset == 0x640U) { return ~0ULL; }
    /* Guest PAT is automatic state only for nested paging. */
    return Offset == 0x668U && NestedPaging ? ~0ULL : 0;
}

/* Caller retains a structurally immutable NPT01 for the full capture/commit lifetime. */
unsigned int KswSvmNestedWriteback(const KSW_NSVM_OPERAND_IO* Io,
    KSW_SVM_U64 GuestPa, KSW_SVM_U64 ExpectedHostPa, const KSW_SVM_VMCB* Image,
    unsigned int Operation, unsigned int NestedPaging, KSW_NSVM_COMMIT_VMCB Commit,
    KSW_NSVM_OPERAND_RESULT* Result)
{
    /* A fresh write walk must authorize the output, not merely reuse read permission. */
    KSW_NNPT_WALK walk;
    /* Record zero writes on every rejection before the physical commit callback. */
    const KSW_NSVM_OPERAND_RESULT empty = {0};
    /* Source path revalidation uses one aligned physical word at a time. */
    KSW_SVM_U64 value;
    /* Bounded path length and status remain separate from write progress. */
    unsigned int index, status;
    /* A caller cannot omit partial-write diagnostics. */
    if (!Result) { return KSW_NNPT_UNSUPPORTED; }
    /* Input identity is retained even when no physical address was resolved. */
    *Result = empty; Result->GuestPa = GuestPa;
    /* Only fixed operations and complete page operands can reach physical RAM. */
    if (!Io || !Io->Read || !Commit || !Image || (GuestPa & 4095ULL) ||
        (ExpectedHostPa & 4095ULL) || NestedPaging > 1U ||
        Operation < KSW_NSVM_SAVE_VMEXIT || Operation > KSW_NSVM_SAVE_VMSAVE) {
        /* Publish a software-contract failure without any write. */
        Result->Status = KSW_NNPT_UNSUPPORTED; return Result->Status;
    }
    /* Source tables belong to the stable outer mapping, never VMCB12's NCR3. */
    status = KswSvmNestedNptWalk(Io->Root, GuestPa, Io->PhysicalBits, Io->Page1Gb,
        Io->Nx, KSW_NNPT_WRITE, Io->Read, Io->Context, &walk);
    /* A readonly NPT01 operand may be read but never written by this API. */
    if (status != KSW_NNPT_OK) { Result->Status = status; return status; }
    /* Preserve both levels' identities for post-failure diagnosis. */
    Result->HostPa = walk.Address;
    /* An operand remap cannot redirect a delayed virtual VMEXIT into a different page. */
    if (walk.Address != ExpectedHostPa) { Result->Status = KSW_NNPT_RETRY; return Result->Status; }
    /* The RAM window's cache mode must agree with the authoritative outer PAT. */
    if (((Io->Pat >> (8U * walk.PatIndex)) & 255ULL) != 6ULL) {
        /* Do not write MMIO through an assumed WB alias. */
        Result->Status = KSW_NNPT_UNSUPPORTED; return Result->Status;
    }
    /* Recheck the complete path before allowing the first write. */
    for (index = 0; index < walk.Count; ++index) {
        /* Read failures are distinct from architectural nested faults. */
        if (!Io->Read(Io->Context, walk.EntryAddress[index], &value)) {
            /* No commit occurred. */
            Result->Status = KSW_NNPT_UNREADABLE; return Result->Status;
        }
        /* Hardware A/D updates do not move or widen the operand mapping. */
        if ((value ^ walk.EntryValue[index]) & ~0x60ULL) {
            /* The outer owner must resolve structural drift before resuming. */
            Result->Status = KSW_NNPT_RETRY; return Result->Status;
        }
    }
    /* The platform callback maps/validates the whole page, then applies fixed masks. */
    if (!Commit(Io->Context, walk.Address, Image, Operation, NestedPaging, &Result->Words)) {
        /* Preserve partial writes; the caller must retain state and must not auto-retry. */
        Result->Status = KSW_NNPT_UNREADABLE; return Result->Status;
    }
    /* This publication follows complete architectural writeback. */
    Result->Status = KSW_NNPT_OK; return Result->Status;
}
