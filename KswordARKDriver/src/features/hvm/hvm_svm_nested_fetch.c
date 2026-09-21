/* Snapshot the exact exited instruction; remap/mismatch is a retained capture failure, not a guest #PF. */
#include "hvm_svm_nested_fetch.h"

/* Every physical word, including a guest page-table word, must first pass immutable NPT01. */
static unsigned KswNsvmFetchWord(const KSW_NSVM_OPERAND_IO* Io, KSW_SVM_U64 Gpa, KSW_SVM_U64* Value)
{
    /* A complete path permits a structural recheck after the physical read. */
    KSW_NNPT_WALK walk;
    /* Never publish bytes from a partially revalidated mapping. */
    KSW_SVM_U64 word, current;
    /* Each path is bounded by four levels. */
    unsigned status, index;
    /* The physical RAM reader accepts only aligned, complete words. */
    if (Gpa & 7ULL) { return KSW_NNPT_UNSUPPORTED; }
    /* Guest CR3 cannot bypass the same outer translation used for VMCB operands. */
    status = KswSvmNestedNptWalk(Io->Root, Gpa, Io->PhysicalBits, Io->Page1Gb, Io->Nx, 0, Io->Read, Io->Context, &walk);
    /* Translation and cache failures have no synthetic guest-side success representation. */
    if (status != KSW_NNPT_OK) { return status; }
    /* The platform RAM mapping has a WB contract; no instruction fetch may map MMIO as WB. */
    if (((Io->Pat >> (walk.PatIndex * 8U)) & 255ULL) != 6ULL) { return KSW_NNPT_UNSUPPORTED; }
    /* Read only after the complete physical translation succeeded. */
    if (!Io->Read(Io->Context, walk.Address, &word)) { return KSW_NNPT_UNREADABLE; }
    /* Recheck the source translation; ignore only independent hardware A/D updates. */
    for (index = 0; index < walk.Count; ++index) {
        /* Never retain a pointer into a temporary physical window. */
        if (!Io->Read(Io->Context, walk.EntryAddress[index], &current)) { return KSW_NNPT_UNREADABLE; }
        /* Structural changes invalidate this capture before publication. */
        if ((current ^ walk.EntryValue[index]) & ~0x60ULL) { return KSW_NNPT_RETRY; }
    }
    /* No guest memory or page-table A/D bit is modified by an observation of an already exited instruction. */
    *Value = word; return KSW_NNPT_OK;
}

/* This path is for the current long-mode Windows L1, including its compatibility-mode code. */
static unsigned KswNsvmFetchTranslate(const KSW_NSVM_OPERAND_IO* Io,
    const KSW_SVM_VMCB* Current, KSW_SVM_U64 Linear, KSW_NNPT_WALK* Walk)
{
    /* Guest linear width and physical width are deliberately separate. */
    KSW_SVM_U64 mask = KswNptAddressMask(Io->PhysicalBits), table, entry, offsetMask, reserved;
    /* Start with deterministic failure state and retained source path. */
    const KSW_NNPT_WALK empty = {0};
    /* The initial implementation does not advertise five-level paging. */
    unsigned level, shift, status, large;
    /* Reject a noncanonical current instruction rather than treating it as a physical address. */
    if (!mask || ((Linear >> 47) != 0 && (Linear >> 47) != 0x1ffffULL)) { return KSW_NNPT_UNSUPPORTED; }
    /* Long-mode paging is distinct from legacy PAE; never reinterpret a PDPT as a PML4. */
    if (!(KswSvmRead64(Current, KSW_VMCB_EFER) & (1ULL << 10)) ||
        !(KswSvmRead64(Current, KSW_VMCB_CR0) & (1ULL << 31)) ||
        !(KswSvmRead64(Current, KSW_VMCB_CR4) & (1ULL << 5)) ||
        (KswSvmRead64(Current, KSW_VMCB_CR4) & (1ULL << 12))) { return KSW_NNPT_UNSUPPORTED; }
    /* CR3 PCID/cache bits are not part of its page-frame address. */
    table = KswSvmRead64(Current, KSW_VMCB_CR3) & KSW_NNPT_FRAME;
    /* A reserved physical address cannot be truncated into another valid table. */
    if (table & ~mask) { return KSW_NNPT_UNSUPPORTED; }
    /* Snapshot the guest path so the final instruction copy can recheck it. */
    *Walk = empty; Walk->InputAddress = Linear; Walk->Root = table;
    /* Read at most four guest page-table entries, each through NPT01. */
    for (level = 0; level < 4; ++level) {
        /* 48-bit linear translation uses shifts 39, 30, 21 and 12. */
        shift = 39U - level * 9U;
        /* These addresses are L1 physical addresses, never host pointers. */
        Walk->EntryAddress[level] = table + (((Linear >> shift) & 511ULL) * 8ULL);
        /* Preserve the distinction between unreadable outer RAM and changed guest translation. */
        status = KswNsvmFetchWord(Io, Walk->EntryAddress[level], &entry);
        /* No guessed instruction bytes on a missing or unsupported physical mapping. */
        if (status != KSW_NNPT_OK) { return status; }
        /* Retain complete source entries for post-copy structural comparison. */
        Walk->EntryValue[level] = entry; Walk->Count = level + 1;
        /* Nonpresent/reserved source changes after VMEXIT are capture failures, not new guest exceptions. */
        if (!(entry & 1ULL) || (entry & KSW_NNPT_FRAME & ~mask)) { return KSW_NNPT_RETRY; }
        /* NX remains a reserved bit if the captured guest did not enable NXE. */
        if ((entry & KSW_NNPT_NX) && !(KswSvmRead64(Current, KSW_VMCB_EFER) & (1ULL << 11))) { return KSW_NNPT_RETRY; }
        /* A now non-executable path cannot authorize instruction emulation. */
        if (entry & KSW_NNPT_NX) { return KSW_NNPT_RETRY; }
        /* PML4 entries have no large-page form. */
        large = level < 3 && (entry & 128ULL) != 0;
        /* Page-size support matches the prepared CPU capability contract. */
        if (large && (!level || (level == 1 && !Io->Page1Gb))) { return KSW_NNPT_UNSUPPORTED; }
        /* A terminal PTE uses bit seven for PAT instead of page size. */
        if (large || level == 3) {
            /* Guest large-page PAT occupies bit twelve, not a physical address bit. */
            offsetMask = (1ULL << shift) - 1ULL; reserved = offsetMask & KSW_NNPT_FRAME;
            /* Bits below a large frame must be zero except for PAT. */
            if (large && (entry & (reserved & ~0x1000ULL))) { return KSW_NNPT_RETRY; }
            /* Preserve the original byte offset into the translated guest page. */
            Walk->Address = (entry & mask & ~offsetMask) | (Linear & offsetMask);
            /* No write or A/D update is authorized by this read-only capture descriptor. */
            Walk->LeafShift = shift; Walk->Complete = 1; return KSW_NNPT_OK;
        }
        /* The next guest physical table is still resolved through NPT01 on the next iteration. */
        table = entry & mask;
    }
    /* Every valid four-level path terminates above. */
    return KSW_NNPT_UNSUPPORTED;
}

/* Only bytes between the intercepted RIP and its hardware NRIP are sampled. */
unsigned KswSvmNestedFetchInstruction(const KSW_NSVM_OPERAND_IO* Io,
    const KSW_SVM_VMCB* Current, unsigned char Bytes[15], unsigned* Length)
{
    /* Guest paging paths and physical words never escape this CPU-private call. */
    KSW_NNPT_WALK walk;
    /* Segment offsets in compatibility mode must not be confused with long-mode linear RIP. */
    const KSW_SVM_SEGMENT* cs;
    /* Only initialized bytes are exposed when the entire capture succeeds. */
    unsigned char captured[15] = {0};
    /* Physical reads are word-sized while the capture itself is byte-exact. */
    KSW_SVM_U64 rip, next, linear, word, entry;
    /* At most fifteen byte observations and four path comparisons per byte. */
    unsigned count, index, path, status;
    /* Failure always leaves an unusable zero-length image. */
    if (!Length || !Bytes) { return KSW_NNPT_UNSUPPORTED; }
    /* Remove stale output before validating the current instruction. */
    *Length = 0; for (index = 0; index < 15; ++index) { Bytes[index] = 0; }
    /* All callbacks must have been bound before entering root. */
    if (!Io || !Io->Read || !Current) { return KSW_NNPT_UNSUPPORTED; }
    /* NRIP came from the current hardware exit, not a fixed assumed opcode length. */
    rip = KswSvmRead64(Current, KSW_VMCB_RIP); next = KswSvmRead64(Current, KSW_VMCB_NRIP);
    /* No backward/wrapping or overlength capture is permitted. */
    if (!KswSvmNextRipValid(rip, next)) { return KSW_NNPT_UNSUPPORTED; }
    /* The bounded delta is now representable without truncation. */
    count = (unsigned)(next - rip); cs = (const KSW_SVM_SEGMENT*)((const unsigned char*)Current + KSW_VMCB_CS);
    /* CS.L and CS.D cannot both be set. */
    if ((cs->attributes & 0x600U) == 0x600U) { return KSW_NNPT_UNSUPPORTED; }
    /* Long code ignores the cached segment base; compatibility code uses it and the limit. */
    linear = rip;
    /* A segment-limit change after the exit is not repaired by wrapping the address. */
    if (!(cs->attributes & 0x200U)) {
        /* Both start and final byte must remain inside the captured code segment. */
        if (rip > cs->limit || next - 1 > cs->limit || cs->base > ~0ULL - rip) { return KSW_NNPT_RETRY; }
        /* Segment addition precedes long-mode paging in compatibility mode. */
        linear += cs->base;
    }
    /* Reject arithmetic wrap before the per-byte walk. */
    if (linear > ~0ULL - (count - 1U)) { return KSW_NNPT_UNSUPPORTED; }
    /* Fetch only the exited instruction, including a genuine cross-page suffix. */
    for (index = 0; index < count; ++index) {
        /* Guest and outer translations are separate, bounded operations. */
        status = KswNsvmFetchTranslate(Io, Current, linear + index, &walk);
        /* No emulation after a partially captured instruction. */
        if (status != KSW_NNPT_OK) { return status; }
        /* A word-aligned read cannot straddle its physical page. */
        status = KswNsvmFetchWord(Io, walk.Address & ~7ULL, &word);
        /* Physical callback failure leaves the public image empty. */
        if (status != KSW_NNPT_OK) { return status; }
        /* Retain one byte in local storage until all source paths are rechecked. */
        captured[index] = (unsigned char)(word >> ((unsigned)(walk.Address & 7ULL) * 8U));
        /* Recheck guest page-table structure after reading its translated instruction byte. */
        for (path = 0; path < walk.Count; ++path) {
            /* Revalidation also crosses NPT01 rather than dereferencing a guest CR3 page. */
            status = KswNsvmFetchWord(Io, walk.EntryAddress[path], &entry);
            /* Hardware A/D changes alone do not invalidate a mapping. */
            if (status != KSW_NNPT_OK) { return status; }
            /* This detects remaps; it does not promise atomicity against guest self-modifying code. */
            if ((entry ^ walk.EntryValue[path]) & ~0x60ULL) { return KSW_NNPT_RETRY; }
        }
    }
    /* Publish the exact captured instruction only after the complete bounded observation. */
    for (index = 0; index < count; ++index) { Bytes[index] = captured[index]; }
    /* Consumers must also match the opcode to the independently observed exit. */
    *Length = count; return KSW_NNPT_OK;
}

/* Prefixes affect the implicit rAX address even though the instruction has no ordinary ModRM operand. */
unsigned KswSvmNestedDecodeSvmOperand(const unsigned char* Bytes, unsigned Length,
    KSW_SVM_U64 ExitCode, unsigned LongCode, unsigned Default32,
    KSW_SVM_U64 Accumulator, KSW_SVM_U64* Operand, unsigned* AddressBits)
{
    /* Presence, not repetition count, determines the address-size override. */
    unsigned index, override = 0, expected, bits;
    /* Decoding never modifies output on failure. */
    if (!Bytes || !Operand || !AddressBits || Length < 3 || Length > 15 || LongCode > 1 || Default32 > 1) { return KSW_NNPT_UNSUPPORTED; }
    /* Only instructions with an implicit address are accepted by this narrow decoder. */
    if (ExitCode == 0x80) { expected = 0xd8; }
    /* VMLOAD and VMSAVE share VMCB addressing but not their transfer direction. */
    else if (ExitCode == 0x82 || ExitCode == 0x83) { expected = (unsigned)ExitCode + 0x58U; }
    /* INVLPGA names a linear address using the same effective-address-size selection. */
    else if (ExitCode == KSW_SVM_EXIT_INVLPGA) { expected = 0xdf; }
    /* No unrelated exit can authorize this decoder's interpretation of rAX. */
    else { return KSW_NNPT_UNSUPPORTED; }
    /* No trailing bytes may be ignored when reconciling the sample with hardware NRIP. */
    if (Bytes[Length - 3] != 0x0f || Bytes[Length - 2] != 0x01 || Bytes[Length - 1] != expected) { return KSW_NNPT_RETRY; }
    /* Prefix validation is bounded by the architectural fifteen-byte instruction limit. */
    for (index = 0; index < Length - 3; ++index) {
        /* Multiple address overrides still select the alternate size once. */
        if (Bytes[index] == 0x67) { override = 1; }
        /* These accepted legacy prefixes do not change the implicit physical/linear address. */
        else if (Bytes[index] == 0x66 || Bytes[index] == 0xf2 || Bytes[index] == 0xf3 ||
            Bytes[index] == 0x26 || Bytes[index] == 0x2e || Bytes[index] == 0x36 || Bytes[index] == 0x3e ||
            Bytes[index] == 0x64 || Bytes[index] == 0x65) { continue; }
        /* REX is a prefix only in 64-bit code and never changes address size. */
        else if (LongCode && Bytes[index] >= 0x40 && Bytes[index] <= 0x4f) { continue; }
        /* LOCK and arbitrary opcode bytes cannot be accepted as harmless padding. */
        else { return KSW_NNPT_RETRY; }
    }
    /* Operand-size/REX.W do not select the effective address size. */
    bits = LongCode ? (override ? 32U : 64U) : ((Default32 != override) ? 32U : 16U);
    /* Avoid shifting a 64-bit mask by its own width. */
    *Operand = bits == 64 ? Accumulator : Accumulator & ((1ULL << bits) - 1ULL);
    /* Retain the decoded width for diagnostics independent of operand value. */
    *AddressBits = bits; return KSW_NNPT_OK;
}
