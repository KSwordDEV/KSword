/* AMD NPT composition. Hardware publication/ASID invalidation is a separate owner. */
#include "hvm_svm_nested_mmu.h"

typedef struct _KSW_NMMU_TABLE_CACHE {
    KSW_SVM_U64 InputBase, OutputBase, OffsetMask;
} KSW_NMMU_TABLE_CACHE;

/* Keep the walk adapter on the caller's nonpaged exit stack. */
typedef struct _KSW_NMMU_CONTEXT {
    /* Immutable roots, capability limits and PAT layouts. */
    const KSW_NMMU_CONFIG* Config;
    /* Host-physical accesses supplied by the per-CPU window. */
    const KSW_NMMU_IO* Io;
    /* Preserve failure provenance across boolean callback interfaces. */
    KSW_NMMU_RESULT* Result;
    /* Callback failures have more precise status than a generic unreadable slot. */
    unsigned int CallbackStatus;
    KSW_NMMU_TABLE_CACHE Tables[4];
    unsigned int TableCount;
} KSW_NMMU_CONTEXT;

/* Count actual reads; never infer success from an initialized output value. */
static int KswNmmuReadHost(void* Opaque, KSW_SVM_U64 Address, KSW_SVM_U64* Value)
{
    /* The context is processor-local and never shared with another exit handler. */
    KSW_NMMU_CONTEXT* context = (KSW_NMMU_CONTEXT*)Opaque;
    /* Operand words must be aligned, wholly within an admitted RAM page. */
    if ((Address & 7ULL) || !context->Io->Read(context->Io->Context, Address, Value)) {
        /* An inaccessible hardware operand is a host-side failure. */
        context->Result->FaultOwner = KSW_NMMU_PHYSICAL;
        /* Preserve the exact physical address that the adapter refused. */
        context->Result->FaultAddress = Address;
        /* A physical read failure cannot synthesize a not-present entry. */
        context->CallbackStatus = KSW_NNPT_UNREADABLE;
        /* Stop this walk immediately. */
        return 0;
    }
    /* Count only initialized source words. */
    ++context->Result->Reads;
    /* Return the caller-supplied word unchanged. */
    return 1;
}

/* Forward atomic updates without replacing guest-owned frame or permission bits. */
static int KswNmmuUpdateHost(void* Opaque, KSW_SVM_U64 Address,
    KSW_SVM_U64 Expected, KSW_SVM_U64 Bits)
{
    /* This callback shares the same window owner as the read callback. */
    KSW_NMMU_CONTEXT* context = (KSW_NMMU_CONTEXT*)Opaque;
    /* A refused physical write and a compare mismatch both require a new resolution. */
    return context->Io->CompareOr(context->Io->Context, Address, Expected, Bits);
}

/* Translate an NPT12 slot through NPT01; table fetches require nested-level writes. */
static unsigned int KswNmmuTableAddress(KSW_NMMU_CONTEXT* Context,
    KSW_SVM_U64 Address, KSW_SVM_U64* Physical)
{
    /* Retain the outer path long enough to commit its table-access A/D bits. */
    KSW_NNPT_WALK path;
    /* Alias the immutable owner configuration. */
    const KSW_NMMU_CONFIG* config = Context->Config;
    /* Never read a guest-physical table as if it were host physical. */
    unsigned int index, status;
    if (config->OuterImmutable) {
        for (index = 0; index < Context->TableCount; ++index) {
            const KSW_NMMU_TABLE_CACHE* cached = &Context->Tables[index];
            if ((Address & ~cached->OffsetMask) == cached->InputBase) {
                *Physical = cached->OutputBase | (Address & cached->OffsetMask);
                return KSW_NNPT_OK;
            }
        }
    }
    status = KswSvmNestedNptWalk(config->OuterRoot, Address,
        config->OuterBits, config->OuterPage1Gb, config->OuterNx, KSW_NNPT_WRITE,
        KswNmmuReadHost, Context, &path);
    /* Even an inner-table read is an outer user write (APM 15.25.5). */
    if (status == KSW_NNPT_OK) {
        /* Hardware would set outer A/D while resolving the inner page-table access. */
        status = KswSvmNestedNptCommitAd(&path, 1, KswNmmuReadHost, KswNmmuUpdateHost, Context);
    }
    /* Preserve which translation failed rather than reflecting every NPF inward. */
    if (status != KSW_NNPT_OK) {
        /* Physical callback failures already record their actual failing address. */
        if (Context->Result->FaultOwner != KSW_NMMU_PHYSICAL) {
            /* This failure belongs to the outer mapping of an inner table. */
            Context->Result->FaultOwner = KSW_NMMU_OUTER_TABLE;
            /* Record the L1 physical table slot that was being resolved. */
            Context->Result->FaultAddress = Address;
            /* Record architectural fault bits only when a real walk fault occurred. */
            Context->Result->FaultInfo = status == KSW_NNPT_FAULT ? path.Fault | KSW_NMMU_TABLE : 0;
        }
        /* Carry the precise outcome through the read/compare callback contract. */
        Context->CallbackStatus = status;
        /* Do not return an address from an incomplete walk. */
        return status;
    }
    /* This slot is writable RAM only if the host callback subsequently admits it. */
    *Physical = path.Address;
    if (config->OuterImmutable && Context->TableCount < 4U) {
        KSW_NMMU_TABLE_CACHE* cached = &Context->Tables[Context->TableCount++];
        cached->OffsetMask = (1ULL << path.LeafShift) - 1ULL;
        cached->InputBase = Address & ~cached->OffsetMask;
        cached->OutputBase = path.Address & ~cached->OffsetMask;
    }
    /* Let the caller perform exactly one word operation. */
    return KSW_NNPT_OK;
}

/* Adapter used by the NPT12 walker and its full-path A/D revalidation. */
static int KswNmmuReadInner(void* Opaque, KSW_SVM_U64 Address, KSW_SVM_U64* Value)
{
    /* Preserve a single window mapping at a time. */
    KSW_NMMU_CONTEXT* context = (KSW_NMMU_CONTEXT*)Opaque;
    /* A physical address is only usable after both mappings succeeded. */
    KSW_SVM_U64 physical = 0;
    /* Complete the outer walk before opening the final table slot. */
    if (KswNmmuTableAddress(context, Address, &physical) != KSW_NNPT_OK) { return 0; }
    /* Host RAM admission remains mandatory even for a valid guest PTE. */
    return KswNmmuReadHost(context, physical, Value);
}

/* Re-translate each source slot before atomic A/D modification. */
static int KswNmmuUpdateInner(void* Opaque, KSW_SVM_U64 Address,
    KSW_SVM_U64 Expected, KSW_SVM_U64 Bits)
{
    /* The same outer epoch must remain held by the caller throughout resolution. */
    KSW_NMMU_CONTEXT* context = (KSW_NMMU_CONTEXT*)Opaque;
    /* Never retain a physical-window pointer across another window operation. */
    KSW_SVM_U64 physical = 0;
    /* This also verifies that the table is still writable through NPT01. */
    if (KswNmmuTableAddress(context, Address, &physical) != KSW_NNPT_OK) { return 0; }
    /* CAS detects source mutation without overwriting a concurrent remap. */
    return KswNmmuUpdateHost(context, physical, Expected, Bits);
}

/* Resolve and commit one source translation; hardware installation is deliberately separate. */
unsigned int KswSvmNestedMmuResolve(const KSW_NMMU_CONFIG* Config,
    const KSW_NMMU_IO* Io, KSW_SVM_U64 Gpa, unsigned int Access,
    KSW_SVM_U64 FaultContext, KSW_NMMU_RESULT* Result)
{
    /* Deterministic output, including failure paths before any memory access. */
    const KSW_NMMU_RESULT empty = {0};
    /* Bound all state to this one synchronous resolution. */
    KSW_NMMU_CONTEXT context;
    /* A leaf remains private until both A/D paths commit. */
    KSW_SVM_U64 leaf = 0;
    /* Preserve the first failing stage. */
    unsigned int status;
    /* No caller may omit the evidence/output buffer. */
    if (!Result) { return KSW_NNPT_UNSUPPORTED; }
    /* Never leave a stale valid leaf on argument failure. */
    *Result = empty;
    /* Initialize status before any early return. */
    Result->Status = KSW_NNPT_UNSUPPORTED;
    /* Require one architectural NPF origin and an explicit invalidation epoch. */
    if (!Config || !Io || !Io->Read || !Io->CompareOr || !Config->Epoch ||
        (Access & ~(KSW_NNPT_WRITE | KSW_NNPT_EXECUTE)) ||
        (FaultContext != KSW_NMMU_FINAL && FaultContext != KSW_NMMU_TABLE)) { return Result->Status; }
    /* A page-table fetch is a nested user write, even for an instruction fetch. */
    if (FaultContext == KSW_NMMU_TABLE) { Access = KSW_NNPT_WRITE; }
    /* Bind the candidate leaf to its source address. */
    Result->Gpa = Gpa;
    /* This is a stamp, not a substitute for the caller holding the epoch stable. */
    Result->Epoch = Config->Epoch;
    /* Install immutable configuration for the callback adapters. */
    context.Config = Config;
    /* Preserve the actual physical-memory implementation. */
    context.Io = Io;
    /* Callbacks publish their fault ownership directly. */
    context.Result = Result;
    /* Zero means no callback has yet failed. */
    context.CallbackStatus = KSW_NNPT_OK;
    context.TableCount = 0;
    /* The first walk resolves L2 GPA to L1 GPA through translated table accesses. */
    status = KswSvmNestedNptWalk(Config->InnerRoot, Gpa, Config->InnerBits,
        Config->InnerPage1Gb, Config->InnerNx, Access, KswNmmuReadInner, &context, &Result->Inner);
    /* Only a genuine NPT12 fault is reflected to the inner hypervisor. */
    if (status == KSW_NNPT_FAULT) {
        /* Preserve the original L2 physical address, not an intermediate table PA. */
        Result->FaultAddress = Gpa;
        /* Retain the final/page-table context from the hardware fault. */
        Result->FaultInfo = Result->Inner.Fault | FaultContext;
        /* Name the owner explicitly. */
        Result->FaultOwner = KSW_NMMU_INNER;
    }
    /* Translate final L1 GPA through the real outer NPT. */
    if (status == KSW_NNPT_OK) {
        /* Use the same access permissions at both levels. */
        status = KswSvmNestedNptWalk(Config->OuterRoot, Result->Inner.Address,
            Config->OuterBits, Config->OuterPage1Gb, Config->OuterNx,
            Access, KswNmmuReadHost, &context, &Result->Outer);
        /* Preserve an outer failure separately from a guest-controlled NPT fault. */
        if (status != KSW_NNPT_OK && Result->FaultOwner != KSW_NMMU_PHYSICAL) {
            /* This address is the translated L1 GPA. */
            Result->FaultAddress = Result->Inner.Address;
            /* Only faults, not unsupported/read failures, have architectural error bits. */
            Result->FaultInfo = status == KSW_NNPT_FAULT ? Result->Outer.Fault | FaultContext : 0;
            /* The host must handle this instead of telling L1 its own map failed. */
            Result->FaultOwner = KSW_NMMU_OUTER_DATA;
        }
    }
    /* Cache policy validation precedes final source dirty-bit updates. */
    if (status == KSW_NNPT_OK) {
        /* WB/UC subset only; arbitrary three-stage PAT composition is not advertised. */
        status = KswSvmNestedNptCompose4k(&Result->Inner, &Result->Outer,
            Config->InnerPat, Config->OuterPat, Config->HardwarePat, &leaf);
    }
    /* Commit the final outer page, preserving concurrent table mutations via CAS. */
    if (status == KSW_NNPT_OK) {
        /* A writable hardware leaf requires source dirty accounting first. */
        status = KswSvmNestedNptCommitAd(&Result->Outer, Access & KSW_NNPT_WRITE,
            KswNmmuReadHost, KswNmmuUpdateHost, &context);
    }
    /* Commit the inner source path through the translated slot adapter. */
    if (status == KSW_NNPT_OK) {
        /* Failed commits never publish the private composed leaf. */
        status = KswSvmNestedNptCommitAd(&Result->Inner, Access & KSW_NNPT_WRITE,
            KswNmmuReadInner, KswNmmuUpdateInner, &context);
    }
    /* Recover a precise fault/retry that a boolean callback could not express. */
    if (context.CallbackStatus != KSW_NNPT_OK) { status = context.CallbackStatus; }
    /* Clean source leaves still fault on their first write; already dirty paths need no extra exit. */
    if (status == KSW_NNPT_OK) {
        /* Both final source entries were revalidated and retain their current dirty accounting. */
        unsigned int dirty = (Result->Inner.EntryValue[Result->Inner.Count - 1] &
            Result->Outer.EntryValue[Result->Outer.Count - 1] & 0x40ULL) != 0;
        /* Reuse only intersected permissions; a read-only source never becomes writable. */
        Result->Leaf = (leaf & (dirty ? ~0ULL : ~2ULL)) | 0x20ULL | (dirty ? 0x40ULL : 0ULL);
    }
    /* Never equate a usable candidate leaf with hardware entry success. */
    Result->Status = status;
    /* Return exactly the diagnostic result recorded above. */
    return status;
}
