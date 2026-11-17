/*++

Module Name:

    hvm_ept.c

Abstract:

    Implements bounded EPT large-leaf splitting, permission rules, and
    monitor-trap restoration without allocation in the VM-exit path.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_ept.h"
#include "hvm_resident.h"
/* 首次访问监视里没有诊断面的那几件事，与离线测试共用同一份实现。 */
#include "../../../../shared/driver/KswordArkHvmWatch.h"

/*
 * 位布局必须与共享头逐位一致，否则离线测试证明的是另一套算术。
 *
 * 钉在编译期而不是靠约定：这两组常量分属三个头文件（协议、驱动内部、共享纯
 * 模块），任何一边改一位都不会产生编译错误，只会让测试和内核开始各算各的。
 */
C_ASSERT(KSW_HVM_WATCH_ACCESS_READ == KSWORD_ARK_HVM_EPT_ACCESS_READ);
C_ASSERT(KSW_HVM_WATCH_ACCESS_WRITE == KSWORD_ARK_HVM_EPT_ACCESS_WRITE);
C_ASSERT(KSW_HVM_WATCH_ACCESS_EXECUTE == KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE);
C_ASSERT(KSW_HVM_WATCH_LEAF_READ == KSW_EPT_READ);
C_ASSERT(KSW_HVM_WATCH_LEAF_WRITE == KSW_EPT_WRITE);
C_ASSERT(KSW_HVM_WATCH_LEAF_EXECUTE == KSW_EPT_EXECUTE);
C_ASSERT(KSW_HVM_WATCH_STATE_ARMED == KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED);
C_ASSERT(KSW_HVM_WATCH_STATE_TRIGGERED ==
    KSWORD_ARK_HVM_EPT_WATCH_STATE_TRIGGERED);
C_ASSERT(KSW_HVM_WATCH_STATE_DISARMED ==
    KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED);
C_ASSERT(KSW_HVM_WATCH_STATE_INVALIDATED ==
    KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED);
C_ASSERT(KSW_HVM_WATCH_STATE_FAULTED ==
    KSWORD_ARK_HVM_EPT_WATCH_STATE_FAULTED);

/* Return the active split that owns one two-MiB physical range. */
static KSW_HVM_EPT_SPLIT*
KswordARKHvmEptFindSplit(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalBase
    )
{
    ULONG index = 0UL;

    /* Search the bounded split ledger without allocation. */
    for (index = 0UL;
         index < KSW_HVM_MAX_EPT_SPLITS;
         ++index) {
        /* Match only active records with the exact aligned base. */
        if (Runtime->EptSplits[index].Active &&
            Runtime->EptSplits[index].PhysicalBase ==
                PhysicalBase) {
            /* Return the exact active split record. */
            return &Runtime->EptSplits[index];
        }
    }
    /* Report that no existing four-KiB table owns the range. */
    return NULL;
}

/* Allocate one free split-ledger slot. */
static KSW_HVM_EPT_SPLIT*
KswordARKHvmEptFindFreeSplit(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;

    /* Search the bounded split ledger for one inactive record. */
    for (index = 0UL;
         index < KSW_HVM_MAX_EPT_SPLITS;
         ++index) {
        /* Return the first inactive split record. */
        if (!Runtime->EptSplits[index].Active) {
            /* Return the reusable zeroed split record. */
            return &Runtime->EptSplits[index];
        }
    }
    /* Report split-ledger exhaustion explicitly. */
    return NULL;
}

/* Resolve the parent PDE for one guest physical address. */
static volatile ULONGLONG*
KswordARKHvmEptFindParentEntry(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalAddress
    )
{
    ULONG pml4Index = 0UL;
    ULONG pdptIndex = 0UL;
    ULONG pdIndex = 0UL;
    ULONGLONG* pd = NULL;

    /* Reject physical addresses outside the explicit EPT mapping window. */
    if (PhysicalAddress >= KSW_HVM_MAX_MAPPED_PHYSICAL) {
        /* Report the address as unmapped. */
        return NULL;
    }
    /* Decode the EPT PML4 index from the guest physical address. */
    pml4Index =
        (ULONG)((PhysicalAddress >> 39) & 0x1FFULL);
    /* Decode the EPT PDPT index from the guest physical address. */
    pdptIndex =
        (ULONG)((PhysicalAddress >> 30) & 0x1FFULL);
    /* Decode the EPT page-directory index from the guest physical address. */
    pdIndex =
        (ULONG)((PhysicalAddress >> 21) & 0x1FFULL);
    /* Reject sparse hierarchy holes before dereferencing a page directory. */
    if (pml4Index >= KSW_HVM_MAX_PML4_ENTRIES ||
        Runtime->EptPd[pml4Index][pdptIndex] == NULL) {
        /* Report the address as unmapped. */
        return NULL;
    }
    /* Select the writable page-directory virtual address. */
    pd = (ULONGLONG*)Runtime->EptPd[pml4Index][pdptIndex];
    /* Return the exact writable parent PDE. */
    return &pd[pdIndex];
}

/* Split one two-MiB EPT identity leaf into 512 four-KiB entries. */
NTSTATUS
KswordARKHvmEptEnsureSplitLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalAddress,
    _Outptr_ KSW_HVM_EPT_SPLIT** Split
    )
{
    ULONGLONG physicalBase =
        PhysicalAddress &
        ~(KSW_HVM_LARGE_PAGE_BYTES - 1ULL);
    volatile ULONGLONG* parentEntry = NULL;
    KSW_HVM_EPT_SPLIT* split = NULL;
    PHYSICAL_ADDRESS pageTablePhysical = { 0 };
    ULONGLONG originalEntry = 0ULL;
    ULONGLONG leafFlags = 0ULL;
    ULONG pageIndex = 0UL;

    /* Reject a missing output before changing EPT state. */
    if (Split == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Reuse an existing split for the same two-MiB range. */
    split = KswordARKHvmEptFindSplit(
        Runtime,
        physicalBase);
    /* Return the existing split without rewriting its page table. */
    if (split != NULL) {
        /* Publish the exact reusable split. */
        *Split = split;
        /* Complete the idempotent split request. */
        return STATUS_SUCCESS;
    }
    /* Resolve the sparse parent PDE that currently owns the range. */
    parentEntry = KswordARKHvmEptFindParentEntry(
        Runtime,
        physicalBase);
    /* Reject holes and non-large parent entries explicitly. */
    if (parentEntry == NULL ||
        ((*parentEntry) & KSW_EPT_LARGE_PAGE) == 0ULL) {
        /* Report that the baseline identity leaf is unavailable. */
        return STATUS_NOT_FOUND;
    }
    /* Reserve one bounded split-ledger record before allocating a page. */
    split = KswordARKHvmEptFindFreeSplit(Runtime);
    /* Report bounded split capacity exhaustion. */
    if (split == NULL) {
        /* Return the exact fixed-capacity failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Preserve the original parent identity leaf before replacement. */
    originalEntry = *parentEntry;
    /*
     * Preserve permissions and memory type while dropping the large marker.
     * Suppress-#VE has to be carried across explicitly: this mask is what the
     * split leaves inherit, and a leaf that loses the bit silently becomes
     * convertible the moment #VE is ever enabled.
     */
    leafFlags = originalEntry &
        (KSW_EPT_READ |
         KSW_EPT_WRITE |
         KSW_EPT_EXECUTE |
         KSW_EPT_SUPPRESS_VE |
         (7ULL << KSW_EPT_MEMORY_TYPE_SHIFT));
    /* Guarantee the bit even if the parent leaf somehow lacked it. */
    leafFlags |= KSW_EPT_SUPPRESS_VE;
    /* Allocate one zeroed page table through the shared cleanup ledger. */
    split->PageTable = KswordARKHvmAllocateEptPageLocked(
        Runtime,
        &pageTablePhysical);
    /* Report allocation failure without publishing a partial parent entry. */
    if (split->PageTable == NULL) {
        /* Clear the reusable ledger record. */
        RtlZeroMemory(split, sizeof(*split));
        /* Return the exact resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Populate every four-KiB identity leaf before switching the parent PDE. */
    for (pageIndex = 0UL; pageIndex < 512UL; ++pageIndex) {
        /* Encode one physical page and the inherited permissions and type. */
        ((ULONGLONG*)split->PageTable)[pageIndex] =
            (physicalBase +
                ((ULONGLONG)pageIndex * KSW_HVM_PAGE_BYTES)) |
            leafFlags;
    }
    /* Preserve all split metadata before the parent entry becomes visible. */
    split->PhysicalBase = physicalBase;
    /* Preserve the page-table physical address for protocol cleanup. */
    split->PageTablePhysical = pageTablePhysical;
    /* Preserve the writable parent entry for reset. */
    split->ParentEntry = parentEntry;
    /* Preserve the original large leaf for reset. */
    split->OriginalEntry = originalEntry;
    /* Order the fully initialized page table before replacing its parent. */
    KeMemoryBarrier();
    /* Point the parent PDE at the new four-KiB page table. */
    *parentEntry =
        (pageTablePhysical.QuadPart &
            KSW_EPT_PHYSICAL_MASK) |
        KSW_EPT_READ |
        KSW_EPT_WRITE |
        KSW_EPT_EXECUTE;
    /* Publish the completed split record after the parent transition. */
    split->Active = TRUE;
    /* Publish the exact active split to the caller. */
    *Split = split;
    /* Complete the split operation successfully. */
    return STATUS_SUCCESS;
}

/* Return the writable four-KiB EPT entry for one split physical page. */
volatile ULONGLONG*
KswordARKHvmEptFindLeafEntry(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalAddress
    )
{
    ULONGLONG physicalBase =
        PhysicalAddress &
        ~(KSW_HVM_LARGE_PAGE_BYTES - 1ULL);
    ULONG pageIndex = (ULONG)(
        (PhysicalAddress - physicalBase) >>
        12);
    KSW_HVM_EPT_SPLIT* split =
        KswordARKHvmEptFindSplit(
            Runtime,
            physicalBase);

    /* Report an unsplit or unavailable page explicitly. */
    if (split == NULL ||
        split->PageTable == NULL) {
        /* Return no writable four-KiB entry. */
        return NULL;
    }
    /* Return the exact writable four-KiB identity leaf. */
    return &((ULONGLONG*)split->PageTable)[pageIndex];
}


BOOLEAN
KswordARKHvmEptReadLeaf(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalAddress,
    _Out_ ULONGLONG* Leaf,
    _Out_ ULONG* LeafShift
    )
{
    volatile ULONGLONG* entry = NULL;

    if (Leaf == NULL || LeafShift == NULL) { return FALSE; }
    *Leaf = 0ULL;
    *LeafShift = 0UL;
    if (Runtime == NULL ||
        PhysicalAddress >= Runtime->HighestMappedPhysicalAddress) {
        return FALSE;
    }
    entry = KswordARKHvmEptFindParentEntry(Runtime, PhysicalAddress);
    if (entry == NULL) { return FALSE; }
    if ((*entry & KSW_EPT_LARGE_PAGE) != 0ULL) {
        *Leaf = *entry;
        *LeafShift = 21UL;
        return TRUE;
    }
    entry = KswordARKHvmEptFindLeafEntry(Runtime, PhysicalAddress);
    if (entry == NULL) { return FALSE; }
    *Leaf = *entry;
    *LeafShift = 12UL;
    return TRUE;
}

/* Apply every active overlapping rule to one four-KiB EPT entry. */
static VOID
KswordARKHvmEptRecomputePageLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalAddress
    )
{
    volatile ULONGLONG* entry =
        KswordARKHvmEptFindLeafEntry(
            Runtime,
            PhysicalAddress);
    ULONGLONG value = 0ULL;
    ULONG ruleIndex = 0UL;

    /* Ignore pages whose split failed before recomputation. */
    if (entry == NULL) {
        /* Return without dereferencing an unavailable leaf. */
        return;
    }
    /* Restore baseline R/W/X before applying all active overlapping rules. */
    value = *entry |
        KSW_EPT_READ |
        KSW_EPT_WRITE |
        KSW_EPT_EXECUTE;
    /* Apply each bounded active rule that contains the physical page. */
    for (ruleIndex = 0UL;
         ruleIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++ruleIndex) {
        const KSW_HVM_EPT_RULE_SLOT* rule =
            &Runtime->EptRules[ruleIndex];
        ULONGLONG ruleBytes = 0ULL;
        ULONGLONG ruleEnd = 0ULL;

        /* Skip inactive rule records. */
        if (!rule->Active) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Convert the validated page count to bytes. */
        ruleBytes = rule->PageCount * KSW_HVM_PAGE_BYTES;
        /* Compute the validated exclusive rule end. */
        ruleEnd = rule->PhysicalAddress + ruleBytes;
        /* Skip rules that do not contain the target page. */
        if (PhysicalAddress < rule->PhysicalAddress ||
            PhysicalAddress >= ruleEnd) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Remove read permission requested by the overlapping rule. */
        if ((rule->DeniedAccess &
                KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL) {
            /* Clear the EPT read permission. */
            value &= ~KSW_EPT_READ;
        }
        /* Remove write permission requested by the overlapping rule. */
        if ((rule->DeniedAccess &
                KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
            /* Clear the EPT write permission. */
            value &= ~KSW_EPT_WRITE;
        }
        /* Remove execute permission requested by the overlapping rule. */
        if ((rule->DeniedAccess &
                KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL) {
            /* Clear the EPT execute permission. */
            value &= ~KSW_EPT_EXECUTE;
        }
    }
    /* Publish the recomputed permission value atomically on x64. */
    *entry = value;
}

/*
 * Compute what one page's leaf value becomes once a given rule stops denying.
 *
 * Deliberately not "read DeniedAccess after the winner cleared it": the
 * processor that loses the atomic transition can reach this point before the
 * winner's store is visible to it, and a recompute that still sees the denial
 * would restore the restricted value, resume, fault again, and keep doing that
 * until the store lands.  Excluding the rule by identity removes the ordering
 * question entirely - every processor computes the same final value no matter
 * when it arrives.
 *
 * VM-exit safe: it reads only the rule table and the split ledger, both of
 * which residency freezes, and it takes no lock.
 */
static ULONGLONG
KswordARKHvmEptComputeLeafExcluding(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG CurrentValue,
    _In_ const KSW_HVM_EPT_RULE_SLOT* Excluded
    )
{
    ULONGLONG value = KswordArkHvmWatchRestoreLeaf(CurrentValue);
    ULONG ruleIndex = 0UL;

    /* Apply each bounded active rule that still contains the physical page. */
    for (ruleIndex = 0UL;
         ruleIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++ruleIndex) {
        const KSW_HVM_EPT_RULE_SLOT* rule =
            &Runtime->EptRules[ruleIndex];
        ULONGLONG ruleBytes = 0ULL;
        ULONGLONG ruleEnd = 0ULL;

        /* Skip inactive rule records. */
        if (!rule->Active) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Skip the rule whose denial this computation is removing. */
        if (rule == Excluded) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Convert the validated page count to bytes. */
        ruleBytes = rule->PageCount * KSW_HVM_PAGE_BYTES;
        /* Compute the validated exclusive rule end. */
        ruleEnd = rule->PhysicalAddress + ruleBytes;
        /* Skip rules that do not contain the target page. */
        if (PhysicalAddress < rule->PhysicalAddress ||
            PhysicalAddress >= ruleEnd) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Remove exactly the permissions this overlapping rule denies. */
        value = KswordArkHvmWatchApplyDenial(
            value,
            rule->DeniedAccess);
    }
    /* Return the permission value the page settles on. */
    return value;
}

/* Recompute every page in one validated rule range. */
static VOID
KswordARKHvmEptRecomputeRangeLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG PageCount
    )
{
    ULONGLONG pageIndex = 0ULL;

    /* Recompute each bounded four-KiB page exactly once. */
    for (pageIndex = 0ULL;
         pageIndex < PageCount;
         ++pageIndex) {
        /* Recompute all overlapping rule permissions for one page. */
        KswordARKHvmEptRecomputePageLocked(
            Runtime,
            PhysicalAddress +
                (pageIndex * KSW_HVM_PAGE_BYTES));
    }
}

/* Validate one physical rule range without truncation. */
static BOOLEAN
KswordARKHvmEptValidateRuleRange(
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG PageCount
    )
{
    ULONGLONG byteCount = 0ULL;

    /* Require a nonempty page-aligned physical range. */
    if (PageCount == 0ULL ||
        (PhysicalAddress &
            (KSW_HVM_PAGE_BYTES - 1ULL)) != 0ULL) {
        /* Reject a malformed rule range. */
        return FALSE;
    }
    /* Reject multiplication overflow before converting pages to bytes. */
    if (PageCount >
        (MAXULONGLONG / KSW_HVM_PAGE_BYTES)) {
        /* Reject the overflowing rule range. */
        return FALSE;
    }
    /* Convert the validated page count to bytes. */
    byteCount = PageCount * KSW_HVM_PAGE_BYTES;
    /* Reject address addition overflow and the explicit mapping boundary. */
    if (PhysicalAddress > MAXULONGLONG - byteCount ||
        PhysicalAddress + byteCount >
            KSW_HVM_MAX_MAPPED_PHYSICAL) {
        /* Reject the out-of-window rule range. */
        return FALSE;
    }
    /* Accept the fully representable physical page range. */
    return TRUE;
}

VOID
KswordARKHvmEptResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;

    /* Reject a missing runtime during defensive teardown. */
    if (Runtime == NULL) {
        /* Return without dereferencing an invalid runtime. */
        return;
    }
    /* Restore every replaced two-MiB parent entry. */
    for (index = 0UL;
         index < KSW_HVM_MAX_EPT_SPLITS;
         ++index) {
        KSW_HVM_EPT_SPLIT* split =
            &Runtime->EptSplits[index];

        /* Skip inactive split records. */
        if (!split->Active ||
            split->ParentEntry == NULL) {
            /* Continue to the next bounded split record. */
            continue;
        }
        /* Restore the exact baseline two-MiB identity leaf. */
        *split->ParentEntry = split->OriginalEntry;
    }
    /* Clear every protocol-visible EPT rule. */
    RtlZeroMemory(
        Runtime->EptRules,
        sizeof(Runtime->EptRules));
    /* Clear every split ledger record after parent restoration. */
    RtlZeroMemory(
        Runtime->EptSplits,
        sizeof(Runtime->EptSplits));
    /* Publish zero active EPT rules. */
    Runtime->EptRuleCount = 0UL;
    /* Clear protocol-visible EPT-rule activity. */
    KswordARKHvmStateClear(Runtime, KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE);
}

/* Publish one watch slot as a protocol row. */
static VOID
KswordARKHvmEptFillWatchRow(
    _In_ const KSW_HVM_EPT_RULE_SLOT* Slot,
    _Out_ KSWORD_ARK_HVM_EPT_WATCH_ROW* Row
    )
{
    /* Initialize the complete row before publishing any field. */
    RtlZeroMemory(Row, sizeof(*Row));
    /* Publish the watch identity, which is the rule identity. */
    Row->watchId = Slot->RuleId;
    /* Publish the lifecycle state read once, not re-read per field. */
    Row->state = (ULONG)InterlockedCompareExchange(
        (volatile LONG*)&Slot->WatchState,
        0L,
        0L);
    /* Publish the requested and normalized access masks side by side. */
    Row->requestedAccess = Slot->WatchRequestedAccess;
    Row->effectiveAccess = Slot->WatchEffectiveAccess;
    Row->addressKind = Slot->WatchAddressKind;
    Row->hitCount = Slot->WatchHitCount;
    Row->lastHitSequence = Slot->WatchLastHitSequence;
    Row->lastHitStatus = Slot->WatchLastHitStatus;
    Row->armedGeneration = Slot->WatchArmedGeneration;
    /* Publish the requested target next to the page actually watched. */
    Row->requestedAddress = Slot->WatchRequestedAddress;
    Row->requestedLength = Slot->WatchRequestedLength;
    Row->physicalPage = Slot->PhysicalAddress;
    Row->pageCount = Slot->PageCount;
    /* Publish the recorded hit scene. */
    Row->lastHitRip = Slot->WatchLastHitRip;
    Row->lastHitGuestLinearAddress = Slot->WatchLastHitGuestLinearAddress;
    Row->lastHitGuestPhysicalAddress = Slot->WatchLastHitGuestPhysicalAddress;
    Row->lastHitCr3 = Slot->WatchLastHitCr3;
    Row->lastHitRsp = Slot->WatchLastHitRsp;
    Row->lastHitTimestamp = Slot->WatchLastHitTimestamp;
    Row->lastHitProcessorGroup = Slot->WatchLastHitProcessorGroup;
    Row->lastHitProcessorNumber = Slot->WatchLastHitProcessorNumber;
    Row->lastHitGuestLinearValid = Slot->WatchLastHitGuestLinearValid;
    Row->lastHitRangeMatch = Slot->WatchLastHitRangeMatch;
}

/*
 * Report whether any other EPT mechanism already owns one physical page.
 *
 * Refusing instead of merging is deliberate.  A view and a watch want opposite
 * values in the same leaf: the view keeps a restricted primary value in place
 * permanently, while the watch restores full permissions the first time it is
 * hit.  Whichever writes last wins, and it wins silently - the other feature
 * simply stops working with nothing anywhere reporting why.  One page, one
 * owner, and the conflict named in the response.
 */
static BOOLEAN
KswordARKHvmEptPageHasOwner(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalPage,
    _In_opt_ const KSW_HVM_EPT_RULE_SLOT* IgnoredRule,
    _Out_ ULONG* OwnerId,
    _Out_ ULONG* OwnerKind
    )
{
    ULONG index = 0UL;

    /* Publish no owner before the bounded scans. */
    *OwnerId = 0UL;
    *OwnerKind = KSWORD_ARK_HVM_WATCH_CONFLICT_NONE;
    /* Scan every installed split view. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_VIEWS;
         ++index) {
        const KSW_HVM_EPT_VIEW_SLOT* view =
            &Runtime->EptViews[index];

        /* Skip inactive or nonoverlapping views. */
        if (!view->Active ||
            view->PhysicalAddress != PhysicalPage) {
            /* Continue to the next bounded view record. */
            continue;
        }
        /* Publish the conflicting view identity. */
        *OwnerId = view->ViewId;
        *OwnerKind = KSWORD_ARK_HVM_WATCH_CONFLICT_VIEW;
        /* Report that the page already has an owner. */
        return TRUE;
    }
    /* Scan every active rule, including other watches. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++index) {
        const KSW_HVM_EPT_RULE_SLOT* rule =
            &Runtime->EptRules[index];
        ULONGLONG ruleEnd = 0ULL;

        /* Skip inactive slots and the caller's own record. */
        if (!rule->Active ||
            rule == IgnoredRule) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Compute the validated exclusive rule end. */
        ruleEnd = rule->PhysicalAddress +
            (rule->PageCount * KSW_HVM_PAGE_BYTES);
        /* Skip rules that do not contain the page. */
        if (PhysicalPage < rule->PhysicalAddress ||
            PhysicalPage >= ruleEnd) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Publish the conflicting rule identity and its kind. */
        *OwnerId = rule->RuleId;
        *OwnerKind = (rule->Flags &
            KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) != 0UL
            ? KSWORD_ARK_HVM_WATCH_CONFLICT_WATCH
            : KSWORD_ARK_HVM_WATCH_CONFLICT_RULE;
        /* Report that the page already has an owner. */
        return TRUE;
    }
    /* Report a page with exactly one prospective owner. */
    return FALSE;
}

/* Find one active watch by identifier. */
static KSW_HVM_EPT_RULE_SLOT*
KswordARKHvmEptFindWatch(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG WatchId
    )
{
    ULONG index = 0UL;

    /* Scan every bounded rule record for one active watch. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++index) {
        KSW_HVM_EPT_RULE_SLOT* rule =
            &Runtime->EptRules[index];

        /* Select the active watch whose identifier matches exactly. */
        if (rule->Active &&
            (rule->Flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) != 0UL &&
            rule->RuleId == WatchId) {
            /* Return the selected watch record. */
            return rule;
        }
    }
    /* Report that no active watch carries that identifier. */
    return NULL;
}

/*
 * Retire a watch whose hit path won the atomic transition but could not
 * finish restoring the page.
 *
 * Only the first-hit owner moved the lifecycle, so only it may move it again;
 * a loser that failed to repair its own view must not stomp on the winner's
 * record.  The three callers all return FALSE right after, which takes the
 * whole machine out of VMX non-root, so this is the last chance to leave the
 * record in a state that describes what happened.
 *
 * FAULTED rather than TRIGGERED: TRIGGERED is transient, and the stop path
 * only converts ARMED, so a record left there would stay "handling a hit"
 * forever.  FAULTED rather than DISARMED or INVALIDATED: no evidence was
 * recorded, and an access did happen - both of those would state something
 * that is not true.
 *
 * Parameters:
 *   Slot - the watch rule whose lifecycle this processor owns.
 *   Plan - the hit plan returned by the shared decision header.
 * Returns nothing; the caller reports the failure by its own return value.
 */
static VOID
KswordARKHvmEptFaultWatchAfterCas(
    _Inout_ KSW_HVM_EPT_RULE_SLOT* Slot,
    _In_ const KSW_HVM_WATCH_HIT_PLAN* Plan
    )
{
    /* Reject missing inputs on a path that must never dereference NULL. */
    if (Slot == NULL ||
        Plan == NULL) {
        /* Return without touching an invalid record. */
        return;
    }
    /* Only the owner of the first touch may move this lifecycle. */
    if (Plan->OwnsFirstHit == 0U) {
        /* Return: a loser must not overwrite the owner's state. */
        return;
    }
    /* Publish the terminal fault state for this watch. */
    InterlockedExchange(
        &Slot->WatchState,
        (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_FAULTED);
}

VOID
KswordARKHvmEptInvalidateWatchesLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;
    /* Records whether this pass actually restored any leaf permission. */
    BOOLEAN restored = FALSE;
    /* Lifecycle state read before this pass attempted to retire the watch. */
    LONG previousState = 0L;

    /* Reject a missing runtime during defensive teardown. */
    if (Runtime == NULL) {
        /* Return without dereferencing an invalid runtime. */
        return;
    }
    /* Retire every armed watch that this residency will stop observing. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++index) {
        KSW_HVM_EPT_RULE_SLOT* rule =
            &Runtime->EptRules[index];

        /* Skip inactive slots and every non-watch rule. */
        if (!rule->Active ||
            (rule->Flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) == 0UL) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /*
         * Only ARMED watches change lifecycle state.  A DISARMED one already
         * produced its evidence and that evidence stays true regardless of
         * what residency does next; overwriting it would erase a real
         * observation.
         */
        previousState = InterlockedCompareExchange(
            &rule->WatchState,
            (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED,
            (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED);
        /*
         * Two more states still need their page repaired even though their
         * lifecycle must not move.
         *
         * TRIGGERED means a hit is in flight; FAULTED means one won the
         * transition and then failed to restore the page.  Both can leave a
         * leaf that still denies access while no rule claims it any more, and
         * the next processor to touch that page aggregates to "unruled" -
         * the whole-machine fail-closed path.  Skipping them here is how that
         * leak survived teardown.
         */
        if (previousState != (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED &&
            previousState != (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_TRIGGERED &&
            previousState != (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_FAULTED) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Stop denying: the page must not stay restricted with nobody looking. */
        rule->DeniedAccess = 0UL;
        /* Restore the page against every rule that still denies it. */
        KswordARKHvmEptRecomputeRangeLocked(
            Runtime,
            rule->PhysicalAddress,
            rule->PageCount);
        /* Remember that a leaf changed so the flush below is not skipped. */
        restored = TRUE;
    }
    /*
     * Flush the stale restrictive translations this pass just removed.
     *
     * Every other path that recomputes a leaf (ADD, REARM, CLEAR) invalidates
     * right after; this one never did.  The caller runs it while processors
     * are still in VMX non-root - that placement is deliberate, precisely
     * "because the permissions have to be restored while the processors can
     * still be invalidated" - so without the flush a sibling processor keeps
     * using the old restricted translation and takes an EPT violation for a
     * page no rule claims any more.  That aggregates to "unruled", which is
     * the whole-machine fail-closed devirtualization path: a teardown would
     * end by faulting the machine it was trying to shut down cleanly.
     *
     * A failed flush is not escalated here.  This helper is on the teardown
     * path and has no way to report; the stop sequence that follows takes
     * every processor out of VMX non-root anyway, which retires the stale
     * translations along with the EPT pointer that produced them.
     */
    if (restored) {
        /* Drop stale translations on every processor still resident. */
        (VOID)KswordARKHvmResidentInvalidateEpt(Runtime->EptPointer);
    }
}

NTSTATUS
KswordARKHvmEptRuleControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_EPT_RULE_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_EPT_RULE_RESPONSE* Response,
    _In_ BOOLEAN DebuggerOwned
    )
{
    /* 独占不附加会话保留全部不可变根，外部仅允许查询。 */
    if (KswordARKNoAttachReserved() && Request != NULL && Request->operation != KSWORD_ARK_HVM_EPT_RULE_QUERY) { return STATUS_DEVICE_BUSY; }
    NTSTATUS status = STATUS_SUCCESS;
    ULONG slotIndex = 0UL;
    KSW_HVM_EPT_RULE_SLOT* slot = NULL;
    ULONG assignedRuleId = 0UL;
    ULONG effectiveDeniedAccess = 0UL;

    /* Validate the fixed pointers before initializing the response. */
    if (Runtime == NULL ||
        Request == NULL ||
        Response == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Initialize the complete protocol response. */
    RtlZeroMemory(Response, sizeof(*Response));
    /* Publish the response protocol version. */
    Response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    /* Publish the complete fixed response size. */
    Response->size = sizeof(*Response);
    /* Publish the current EPT implementation maturity. */
    Response->implementation = Runtime->EptImplementation;
    /* Require prepared EPT state for every rule operation. */
    if ((Runtime->StateFlags &
            KSWORD_ARK_HVM_STATE_EPT_READY) == 0UL) {
        /* Publish the stable not-prepared protocol status. */
        Response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_PREPARED;
        /* Publish the authoritative NTSTATUS. */
        Response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Return a query snapshot without mutating EPT state. */
    if (Request->operation == KSWORD_ARK_HVM_EPT_RULE_QUERY) {
        /* Search one exact requested rule identifier when provided. */
        for (slotIndex = 0UL;
             slotIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
             ++slotIndex) {
            /* Skip inactive or nonmatching rule records. */
            if (!Runtime->EptRules[slotIndex].Active ||
                (Request->ruleId != 0UL &&
                 Runtime->EptRules[slotIndex].RuleId !=
                    Request->ruleId)) {
                /* Continue to the next bounded rule record. */
                continue;
            }
            /* Select the first exact or first active rule. */
            slot = &Runtime->EptRules[slotIndex];
            /* Stop after one protocol-visible rule snapshot. */
            break;
        }
        /* Publish not-found only for a requested exact identifier. */
        if (slot == NULL &&
            Request->ruleId != 0UL) {
            /* Publish the stable not-found protocol status. */
            Response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND;
            /* Publish the authoritative NTSTATUS. */
            Response->lastStatus = STATUS_NOT_FOUND;
        } else {
            /* Publish a successful query snapshot. */
            Response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_OK;
            /* Publish the optional selected rule fields. */
            if (slot != NULL) {
                /* Publish the selected stable rule identifier. */
                Response->ruleId = slot->RuleId;
                /* Publish the selected denied-access mask. */
                Response->deniedAccess = slot->DeniedAccess;
                /* Publish the selected rule behavior flags. */
                Response->flags = slot->Flags;
                /* Publish the selected first physical page. */
                Response->physicalAddress =
                    slot->PhysicalAddress;
                /* Publish the selected page count. */
                Response->pageCount = slot->PageCount;
            }
            /* Publish the successful query NTSTATUS. */
            Response->lastStatus = STATUS_SUCCESS;
        }
        /* Publish the complete current rule count. */
        Response->ruleCount = Runtime->EptRuleCount;
        /* Publish the current lifecycle generation. */
        Response->generation = Runtime->Generation;
        /* Return the protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Return the whole watch table without mutating EPT state. */
    if (Request->operation ==
            KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY) {
        ULONG returned = 0UL;
        ULONG total = 0UL;

        /* Publish every active watch up to the bounded row capacity. */
        for (slotIndex = 0UL;
             slotIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
             ++slotIndex) {
            const KSW_HVM_EPT_RULE_SLOT* rule =
                &Runtime->EptRules[slotIndex];

            /* Skip inactive slots and every non-watch rule. */
            if (!rule->Active ||
                (rule->Flags &
                    KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) == 0UL) {
                /* Continue to the next bounded rule record. */
                continue;
            }
            /* Count every watch, including ones past the row capacity. */
            total += 1UL;
            /* Publish only as many rows as the fixed response can carry. */
            if (returned < KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS) {
                /* Publish one complete watch snapshot. */
                KswordARKHvmEptFillWatchRow(
                    rule,
                    &Response->watchRows[returned]);
                /* Advance the bounded published row count. */
                returned += 1UL;
            }
        }
        /* Publish the published and total counts separately. */
        Response->returnedWatchRows = returned;
        Response->watchRowCount = total;
        /* Publish the successful snapshot status. */
        Response->status = KSWORD_ARK_HVM_EPT_RULE_STATUS_OK;
        Response->lastStatus = STATUS_SUCCESS;
        /* Publish the complete current rule count. */
        Response->ruleCount = Runtime->EptRuleCount;
        /* Publish the current lifecycle generation. */
        Response->generation = Runtime->Generation;
        /* Return the protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* External rule edits cannot invalidate a debugger's pinned rule ownership. */
    if (!DebuggerOwned) {
        /* Scan the bounded debugger lease table while holding the runtime lock. */
        for (slotIndex = 0UL; slotIndex < KSWORD_ARK_HVM_DEBUG_MAX_SLOTS; ++slotIndex) {
            /* An ID retains ownership even after lifetime revocation disabled injection. */
            if (Runtime->DebugSlots[slotIndex].Id != 0UL) {
                /* Preserve the existing protocol's frozen-mutation outcome. */
                Response->status = KSWORD_ARK_HVM_EPT_RULE_STATUS_RESIDENT_FROZEN;
                /* Identify the active debugger ownership conflict. */
                Response->lastStatus = STATUS_DEVICE_BUSY;
                /* Complete the typed refusal without changing EPT. */
                return STATUS_SUCCESS;
            }
        }
    }
    /* Require typed UI confirmation for every EPT mutation. */
    if ((Request->flags &
            KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED) == 0UL ||
        Request->confirmationToken !=
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN) {
        /* Publish the stable confirmation-required protocol status. */
        Response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_CONFIRMATION_REQUIRED;
        /* Publish the authoritative access failure. */
        Response->lastStatus = STATUS_ACCESS_DENIED;
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Require a matching generation for every mutating EPT operation. */
    if (Request->expectedGeneration != 0UL &&
        Request->expectedGeneration != Runtime->Generation) {
        /* Publish the stable invalid-request protocol status. */
        Response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST;
        /* Publish the authoritative compare-before failure. */
        Response->lastStatus = STATUS_REVISION_MISMATCH;
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Re-arm one watch that already fired, keeping its identity and history. */
    if (Request->operation == KSWORD_ARK_HVM_EPT_RULE_REARM) {
        ULONG conflictOwnerId = 0UL;
        ULONG conflictOwnerKind = 0UL;

        /* Locate the exact active watch. */
        slot = KswordARKHvmEptFindWatch(
            Runtime,
            Request->ruleId);
        /* Report a missing watch explicitly. */
        if (slot == NULL) {
            /* Publish the stable not-found protocol status. */
            Response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND;
            /* Publish the authoritative NTSTATUS. */
            Response->lastStatus = STATUS_NOT_FOUND;
            /* Return a protocol-level result successfully. */
            return STATUS_SUCCESS;
        }
        /*
         * Re-arming, like arming, happens while residency is stopped: the
         * caller never reaches here otherwise, because the rule table is
         * frozen for the whole of residency.
         */
        /* Refuse to re-arm onto a page another mechanism has since claimed. */
        if (KswordARKHvmEptPageHasOwner(
                Runtime,
                slot->PhysicalAddress,
                slot,
                &conflictOwnerId,
                &conflictOwnerKind)) {
            /* Publish the stable leaf-conflict protocol status. */
            Response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT;
            /* Publish which mechanism owns the page instead. */
            Response->conflictOwnerId = conflictOwnerId;
            Response->conflictOwnerKind = conflictOwnerKind;
            /* Publish the authoritative conflict failure. */
            Response->lastStatus = STATUS_SHARING_VIOLATION;
            /* Return a protocol-level result successfully. */
            return STATUS_SUCCESS;
        }
        /* Restore the normalized tripwire mask this watch was installed with. */
        slot->DeniedAccess = slot->WatchEffectiveAccess;
        /* Advance the lifecycle generation before binding the watch to it. */
        Runtime->Generation += 1UL;
        /* Bind this armed round to the generation that will observe it. */
        slot->WatchArmedGeneration = Runtime->Generation;
        /* Order every field before the state becomes observable to VMX root. */
        KeMemoryBarrier();
        /* Publish the armed lifecycle state. */
        InterlockedExchange(
            &slot->WatchState,
            (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED);
        /* Apply the restored denial to every covered page. */
        KswordARKHvmEptRecomputeRangeLocked(
            Runtime,
            slot->PhysicalAddress,
            slot->PageCount);
        /* Invalidate resident EPT translations on every active processor. */
        status = KswordARKHvmResidentInvalidateEpt(
            Runtime->EptPointer);
        /* Publish success or an explicit partial invalidation result. */
        Response->status = NT_SUCCESS(status)
            ? KSWORD_ARK_HVM_EPT_RULE_STATUS_OK
            : KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL;
        /* Publish the re-armed watch identity and its complete snapshot. */
        Response->ruleId = slot->RuleId;
        Response->deniedAccess = slot->DeniedAccess;
        Response->flags = slot->Flags;
        Response->physicalAddress = slot->PhysicalAddress;
        Response->pageCount = slot->PageCount;
        Response->ruleCount = Runtime->EptRuleCount;
        Response->generation = Runtime->Generation;
        Response->lastStatus = status;
        KswordARKHvmEptFillWatchRow(slot, &Response->watch);
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Clear every rule and restore baseline permissions. */
    if (Request->operation == KSWORD_ARK_HVM_EPT_RULE_CLEAR) {
        /* Restore split leaves and clear all rule records. */
        KswordARKHvmEptResetLocked(Runtime);
        /* Advance the lifecycle generation after the mutation. */
        Runtime->Generation += 1UL;
        /* Invalidate resident EPT translations on every active processor. */
        status = KswordARKHvmResidentInvalidateEpt(
            Runtime->EptPointer);
        /* Publish success or an explicit partial invalidation result. */
        Response->status = NT_SUCCESS(status)
            ? KSWORD_ARK_HVM_EPT_RULE_STATUS_OK
            : KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL;
        /* Publish the authoritative invalidation status. */
        Response->lastStatus = status;
        /* Publish the advanced generation. */
        Response->generation = Runtime->Generation;
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Locate one exact active rule for removal. */
    if (Request->operation == KSWORD_ARK_HVM_EPT_RULE_REMOVE) {
        ULONGLONG removedAddress = 0ULL;
        ULONGLONG removedPageCount = 0ULL;

        /* Search the bounded rule table for the exact identifier. */
        for (slotIndex = 0UL;
             slotIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
             ++slotIndex) {
            /* Select only the exact active rule identifier. */
            if (Runtime->EptRules[slotIndex].Active &&
                Runtime->EptRules[slotIndex].RuleId ==
                    Request->ruleId) {
                /* Preserve the selected slot for removal. */
                slot = &Runtime->EptRules[slotIndex];
                /* Stop after the exact stable rule match. */
                break;
            }
        }
        /* Return an explicit not-found result for stale identifiers. */
        if (slot == NULL) {
            /* Publish the stable not-found protocol status. */
            Response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND;
            /* Publish the authoritative NTSTATUS. */
            Response->lastStatus = STATUS_NOT_FOUND;
            /* Publish the unchanged rule count. */
            Response->ruleCount = Runtime->EptRuleCount;
            /* Publish the unchanged generation. */
            Response->generation = Runtime->Generation;
            /* Return a protocol-level result successfully. */
            return STATUS_SUCCESS;
        }
        /* Preserve the removed range before clearing the slot. */
        removedAddress = slot->PhysicalAddress;
        /* Preserve the removed page count before clearing the slot. */
        removedPageCount = slot->PageCount;
        /* Clear the exact selected rule record. */
        RtlZeroMemory(slot, sizeof(*slot));
        /* Decrement the active rule count without underflow. */
        if (Runtime->EptRuleCount != 0UL) {
            /* Publish one fewer active EPT rule. */
            Runtime->EptRuleCount -= 1UL;
        }
        /* Recompute pages against every remaining overlapping rule. */
        KswordARKHvmEptRecomputeRangeLocked(
            Runtime,
            removedAddress,
            removedPageCount);
        /* Clear rule-active state after the final rule is removed. */
        if (Runtime->EptRuleCount == 0UL) {
            /* Clear protocol-visible EPT-rule activity. */
            KswordARKHvmStateClear(
                Runtime,
                KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE);
        }
    /* Validate and add one new physical-page rule. */
    } else if (Request->operation == KSWORD_ARK_HVM_EPT_RULE_ADD) {
        ULONGLONG pageIndex = 0ULL;

        /* Require one valid permission bit and no unknown access bits. */
        if ((Request->deniedAccess &
                (KSWORD_ARK_HVM_EPT_ACCESS_READ |
                 KSWORD_ARK_HVM_EPT_ACCESS_WRITE |
                 KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE)) == 0UL ||
            (Request->deniedAccess &
                ~(KSWORD_ARK_HVM_EPT_ACCESS_READ |
                  KSWORD_ARK_HVM_EPT_ACCESS_WRITE |
                  KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE)) != 0UL ||
            !KswordARKHvmEptValidateRuleRange(
                Request->physicalAddress,
                Request->pageCount)) {
            /* Publish the stable invalid-request protocol status. */
            Response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST;
            /* Publish the authoritative parameter failure. */
            Response->lastStatus = STATUS_INVALID_PARAMETER;
            /* Return a protocol-level result successfully. */
            return STATUS_SUCCESS;
        }
        /*
         * Traditional EPT never permits W=1 with R=0.  READ removal therefore
         * also removes WRITE.  When execute-only EPT is unavailable, remove
         * EXECUTE as well rather than publishing an illegal R=0/W=0/X=1 leaf.
         */
        /*
         * Normalization lives in the shared pure header so the offline suite
         * proves the same code the exit path runs.  Getting it wrong has no
         * diagnostic surface in either direction: too little and the leaf is
         * architecturally illegal (one anonymous exit reason 49), too much and
         * the watch silently covers more than the user asked for.
         */
        effectiveDeniedAccess = KswordArkHvmWatchNormalizeAccess(
            Request->deniedAccess,
            (Runtime->VmxEptVpidCapabilities &
                KSW_EPT_CAP_EXECUTE_ONLY) != 0ULL);
        /* Validate everything that is specific to a first-touch watch. */
        if ((Request->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) != 0UL) {
            ULONG conflictOwnerId = 0UL;
            ULONG conflictOwnerKind = 0UL;

            /*
             * A watch covers exactly one page.
             *
             * Not a limitation being papered over: the hit path restores
             * permissions from VMX root, and that work has to stay bounded by
             * a constant rather than by whatever range a caller asked for.
             * One page is also the honest unit - EPT permissions are page
             * granular, so a multi-page watch would be several independent
             * watches wearing one identifier, with one shared hit count that
             * could not say which page was touched.
             */
            if (Request->pageCount != 1ULL ||
                (Request->flags &
                    (KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE |
                     KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE)) != 0UL) {
                /* Publish the stable invalid-request protocol status. */
                Response->status =
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST;
                /* Publish the authoritative parameter failure. */
                Response->lastStatus = STATUS_INVALID_PARAMETER;
                /* Return a protocol-level result successfully. */
                return STATUS_SUCCESS;
            }
            /*
             * A watch is armed while residency is STOPPED, exactly like every
             * other EPT rule, and takes effect when residency starts.
             *
             * An earlier version refused a watch unless residency was already
             * running, reasoning that a tripwire nothing can trip is worse than
             * a refusal.  That reasoning produced a rule that could never be
             * installed at all: KswordARKHvmEptRuleControl deliberately freezes
             * the whole rule table while resident, because VM exits scan it
             * without taking the PASSIVE_LEVEL lock.  The two conditions were
             * mutually exclusive.
             *
             * The honest fix is not to weaken that freeze - it is a real
             * safety invariant - but to drop the extra gate and let the state
             * be visible instead: an armed watch with residency stopped reads
             * as exactly that, and the callers say so.
             */
            /* Refuse a page another EPT mechanism already owns. */
            if (KswordARKHvmEptPageHasOwner(
                    Runtime,
                    Request->physicalAddress,
                    NULL,
                    &conflictOwnerId,
                    &conflictOwnerKind)) {
                /* Publish the stable leaf-conflict protocol status. */
                Response->status =
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT;
                /* Publish which mechanism owns the page instead. */
                Response->conflictOwnerId = conflictOwnerId;
                Response->conflictOwnerKind = conflictOwnerKind;
                /* Publish the authoritative conflict failure. */
                Response->lastStatus = STATUS_SHARING_VIOLATION;
                /* Return a protocol-level result successfully. */
                return STATUS_SUCCESS;
            }
        } else {
            ULONGLONG ownedIndex = 0ULL;
            ULONG conflictOwnerId = 0UL;
            ULONG conflictOwnerKind = 0UL;

            /*
             * An ordinary rule must not land on a page a view or a watch owns.
             *
             * The ownership test used to run only for watches, which made the
             * "one page, one owner" rule enforceable from one side only: a
             * plain tripwire could be installed straight on top of a watched
             * page, and the GUI lets a user pick any physical address.  The
             * damage shows up later and far away - the hit path finds a watch
             * sharing its page with another rule, cannot resolve the watch,
             * and takes the whole machine out of VMX non-root, which is
             * exactly the outcome this feature exists to avoid.
             *
             * Rule-on-rule overlap stays allowed.  Two ordinary rules want the
             * same thing from the leaf (fewer permissions), so they compose;
             * it is the view and the watch that want opposite values, and they
             * are the only owners named here.
             */
            for (ownedIndex = 0ULL;
                 ownedIndex < Request->pageCount;
                 ++ownedIndex) {
                /* Test one page of the requested range for an owner. */
                if (!KswordARKHvmEptPageHasOwner(
                        Runtime,
                        Request->physicalAddress +
                            (ownedIndex * KSW_HVM_PAGE_BYTES),
                        NULL,
                        &conflictOwnerId,
                        &conflictOwnerKind)) {
                    /* Continue to the next bounded page of the range. */
                    continue;
                }
                /* Let another ordinary rule share the page as before. */
                if (conflictOwnerKind ==
                    KSWORD_ARK_HVM_WATCH_CONFLICT_RULE) {
                    /* Continue to the next bounded page of the range. */
                    continue;
                }
                /* Publish the stable leaf-conflict protocol status. */
                Response->status =
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT;
                /* Publish which mechanism owns the page instead. */
                Response->conflictOwnerId = conflictOwnerId;
                Response->conflictOwnerKind = conflictOwnerKind;
                /* Publish the authoritative conflict failure. */
                Response->lastStatus = STATUS_SHARING_VIOLATION;
                /* Return a protocol-level result successfully. */
                return STATUS_SUCCESS;
            }
        }
        /* Reserve one free bounded rule slot. */
        for (slotIndex = 0UL;
             slotIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
             ++slotIndex) {
            /* Select the first inactive rule record. */
            if (!Runtime->EptRules[slotIndex].Active) {
                /* Preserve the reusable rule slot. */
                slot = &Runtime->EptRules[slotIndex];
                /* Stop after selecting one bounded free slot. */
                break;
            }
        }
        /* Report fixed rule-table exhaustion explicitly. */
        if (slot == NULL) {
            /* Publish the stable table-full protocol status. */
            Response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_TABLE_FULL;
            /* Publish the authoritative resource failure. */
            Response->lastStatus =
                STATUS_INSUFFICIENT_RESOURCES;
            /* Return a protocol-level result successfully. */
            return STATUS_SUCCESS;
        }
        /*
         * An allow-once rule the private hierarchies could not mirror must be
         * refused here rather than at start.  Rules that only deny access
         * never flip a leaf, so they are exempt and this check skips them.
         */
        if ((Request->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE) != 0UL) {
            /*
             * Refuse a one-instruction grant this machine cannot serve.
             *
             * The runtime gate (the allAllowOnce branch further down) already
             * requires either a private hierarchy or exactly one processor,
             * and fails closed otherwise.  That gate is correct but it fires
             * too late: the rule installs, reports success, and only on some
             * later hit does the machine leave VMX - and since fail-closed
             * became a whole-machine stop, it takes every processor with it.
             * Nothing connects the install the user did to the moment
             * virtualization silently went away.
             *
             * Mirroring the runtime condition here, not a weaker proxy: the
             * latch is what admission below already consults, and a rule
             * added while stopped has no per-VCPU record to ask instead.
             * ENFORCE never reaches this branch - it is rejected earlier as
             * UNIMPLEMENTED, and storing it drops ALLOW_ONCE anyway.
             */
            if (Runtime->ProcessorCount != 1UL &&
                !Runtime->LocalEptArmed) {
                /* Publish the stable machine-capability refusal. */
                Response->status =
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_MULTIPROCESSOR_UNSAFE;
                /* Publish the authoritative capability failure. */
                Response->lastStatus = STATUS_NOT_SUPPORTED;
                /* Return a protocol-level result successfully. */
                return STATUS_SUCCESS;
            }
            status = KswordARKHvmEptLocalCheckAdmission(
                Runtime,
                Request->physicalAddress,
                (ULONGLONG)Request->pageCount * KSW_HVM_PAGE_BYTES);
            if (!NT_SUCCESS(status)) {
                /* Publish the stable table-full protocol status. */
                Response->status =
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_TABLE_FULL;
                /* Publish the authoritative admission failure. */
                Response->lastStatus = status;
                /* Return a protocol-level result successfully. */
                return STATUS_SUCCESS;
            }
        }
        /* Pre-split every covered two-MiB leaf before publishing the rule. */
        for (pageIndex = 0ULL;
             pageIndex < Request->pageCount;
             ++pageIndex) {
            KSW_HVM_EPT_SPLIT* split = NULL;

            /* Ensure one writable four-KiB page table covers this page. */
            status = KswordARKHvmEptEnsureSplitLocked(
                Runtime,
                Request->physicalAddress +
                    (pageIndex * KSW_HVM_PAGE_BYTES),
                &split);
            /* Stop before rule publication when any split fails. */
            if (!NT_SUCCESS(status)) {
                /* Publish the stable split-failed protocol status. */
                Response->status =
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_SPLIT_FAILED;
                /* Publish the authoritative split failure. */
                Response->lastStatus = status;
                /* Return a protocol-level result successfully. */
                return STATUS_SUCCESS;
            }
        }
        /* Allocate a nonzero identifier from generation and slot position. */
        assignedRuleId =
            ((Runtime->Generation & 0x00FFFFFFUL) << 8) |
            (slotIndex + 1UL);
        /* Replace an impossible wrapped zero identifier with the slot index. */
        if (assignedRuleId == 0UL) {
            /* Publish a stable nonzero identifier. */
            assignedRuleId = slotIndex + 1UL;
        }
        /* Publish the stable rule identifier. */
        slot->RuleId = assignedRuleId;
        /* Publish the denied-access mask. */
        slot->DeniedAccess = effectiveDeniedAccess;
        /* Preserve only defined behavior flags. */
        slot->Flags = Request->flags &
            (KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE);
        /* Initialize the complete watch record for every rule. */
        slot->WatchState = (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_NONE;
        slot->WatchRequestedAccess = 0UL;
        slot->WatchEffectiveAccess = 0UL;
        slot->WatchAddressKind = 0UL;
        slot->WatchHitCount = 0UL;
        slot->WatchLastHitStatus = KSWORD_ARK_HVM_EPT_WATCH_HIT_NONE;
        slot->WatchArmedGeneration = 0UL;
        slot->WatchRequestedAddress = 0ULL;
        slot->WatchRequestedLength = 0ULL;
        slot->WatchLastHitSequence = 0ULL;
        slot->WatchLastHitRip = 0ULL;
        slot->WatchLastHitGuestLinearAddress = 0ULL;
        slot->WatchLastHitGuestPhysicalAddress = 0ULL;
        slot->WatchLastHitCr3 = 0ULL;
        slot->WatchLastHitRsp = 0ULL;
        slot->WatchLastHitTimestamp = 0ULL;
        slot->WatchLastHitProcessorGroup = 0U;
        slot->WatchLastHitProcessorNumber = 0U;
        slot->WatchLastHitGuestLinearValid = 0U;
        slot->WatchLastHitRangeMatch = 0UL;
        /* Populate the watch record only for a first-touch watch. */
        if ((slot->Flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) != 0UL) {
            /*
             * Keep the user's request next to the mask actually installed.
             * They differ whenever architectural normalization widened the
             * request - and a UI that shows only one of them either rewrites
             * what the user asked for or understates what is being watched.
             */
            slot->WatchRequestedAccess = Request->deniedAccess;
            slot->WatchEffectiveAccess = effectiveDeniedAccess;
            slot->WatchAddressKind = Request->addressKind;
            /*
             * Default the requested range to the whole page when the caller
             * gave none, so range matching reports MATCH rather than a
             * silent miss for a caller that watched a page on purpose.
             */
            slot->WatchRequestedAddress =
                Request->requestedLength != 0ULL
                    ? Request->requestedAddress
                    : Request->physicalAddress;
            slot->WatchRequestedLength =
                Request->requestedLength != 0ULL
                    ? Request->requestedLength
                    : KSW_HVM_PAGE_BYTES;
            /* Bind this armed round to the generation advanced below. */
            slot->WatchArmedGeneration = Runtime->Generation + 1UL;
            /* Publish the armed lifecycle state. */
            slot->WatchState =
                (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED;
        }
        /*
         * Durable denial and a one-instruction grant are opposite outcomes for
         * the same access.  Let denial win rather than storing a rule whose
         * behavior would depend on aggregation order.
         */
        if ((slot->Flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE) != 0UL) {
            /* Drop the contradictory temporary grant. */
            slot->Flags &= ~KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE;
        }
        /* Publish the first page-aligned physical address. */
        slot->PhysicalAddress = Request->physicalAddress;
        /* Publish the complete validated page count. */
        slot->PageCount = Request->pageCount;
        /* Order every rule field before publishing the active marker. */
        KeMemoryBarrier();
        /* Publish the complete active rule. */
        slot->Active = TRUE;
        /* Publish one additional active EPT rule. */
        Runtime->EptRuleCount += 1UL;
        /* Recompute every covered page against all active rules. */
        KswordARKHvmEptRecomputeRangeLocked(
            Runtime,
            Request->physicalAddress,
            Request->pageCount);
        /* Publish protocol-visible EPT-rule activity. */
        KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE);
    } else {
        /* Publish the stable invalid-request protocol status. */
        Response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST;
        /* Publish the authoritative parameter failure. */
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Advance the lifecycle generation after an add or removal mutation. */
    Runtime->Generation += 1UL;
    /* Invalidate resident EPT translations on every active processor. */
    status = KswordARKHvmResidentInvalidateEpt(
        Runtime->EptPointer);
    /* Publish success or an explicit partial invalidation result. */
    Response->status = NT_SUCCESS(status)
        ? KSWORD_ARK_HVM_EPT_RULE_STATUS_OK
        : KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL;
    /* Publish the affected or removed rule identifier. */
    Response->ruleId = assignedRuleId != 0UL
        ? assignedRuleId
        : Request->ruleId;
    /* Publish the effective, architecturally legal permission-removal mask. */
    if (assignedRuleId != 0UL) {
        /* Return the normalized mask applied to the new rule. */
        Response->deniedAccess = effectiveDeniedAccess;
        /* Return the complete watch snapshot the caller will display. */
        if (slot != NULL &&
            (slot->Flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) != 0UL) {
            /* Publish one armed watch row. */
            KswordARKHvmEptFillWatchRow(slot, &Response->watch);
        }
    }
    /* Publish the current active rule count. */
    Response->ruleCount = Runtime->EptRuleCount;
    /* Publish the advanced lifecycle generation. */
    Response->generation = Runtime->Generation;
    /* Publish the authoritative invalidation status. */
    Response->lastStatus = status;
    /* Return the protocol-level result successfully. */
    return STATUS_SUCCESS;
}

BOOLEAN
KswordARKHvmEptRestoreTransient(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_EPT_TRANSIENT* Transient
    )
{
    /* Reject a malformed recovery record without discarding its evidence. */
    if (Runtime == NULL ||
        Transient == NULL) {
        /* Report that no safe restoration was proven. */
        return FALSE;
    }
    /* Treat an unarmed record as already restored. */
    if (!Transient->Armed) {
        /* Complete the idempotent restoration successfully. */
        return TRUE;
    }
    /* Preserve an armed malformed record for fail-closed devirtualization. */
    if (Transient->Entry == NULL ||
        Runtime->EptPointer == 0ULL) {
        /* Report that the pending grant cannot be safely restored. */
        return FALSE;
    }
    /* Restore the exact restricted four-KiB entry first. */
    *Transient->Entry = Transient->RestrictedValue;
    /* Order the restoration before invalidating the current EPT context. */
    KeMemoryBarrier();
    /*
     * Invalidate the hierarchy the grant was actually made in.  Single-context
     * INVEPT is scoped by the pointer it names, so naming the shared one here
     * would leave a private processor holding the widened translation.
     */
    if (KswordARKHvmAsmInveptSingle(
            Transient->EptPointer != 0ULL
                ? Transient->EptPointer
                : Runtime->EptPointer) != 0U) {
        /* Keep Armed and every recovery field for VMXOFF fail-closed cleanup. */
        return FALSE;
    }
    /* Clear the complete recovery record only after successful INVEPT. */
    Transient->Armed = FALSE;
    Transient->Reserved0[0] = 0U;
    Transient->Reserved0[1] = 0U;
    Transient->Reserved0[2] = 0U;
    Transient->RuleId = 0UL;
    Transient->Entry = NULL;
    Transient->RestrictedValue = 0ULL;
    Transient->EptPointer = 0ULL;
    /* Report a fully restored and invalidated EPT context. */
    return TRUE;
}

BOOLEAN
KswordARKHvmEptHandleViolation(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONGLONG GuestLinearAddress,
    _In_ ULONG Access,
    _In_ BOOLEAN GuestLinearAddressValid,
    _In_opt_ const KSW_HVM_EPT_LOCAL* Local,
    _Out_ KSW_HVM_EPT_TRANSIENT* Transient,
    _Out_ ULONG* RuleId,
    _Out_ ULONG* Disposition,
    _Out_ KSW_HVM_EPT_WATCH_HIT* WatchHit
    )
{
    ULONGLONG physicalPage =
        GuestPhysicalAddress &
        ~(KSW_HVM_PAGE_BYTES - 1ULL);
    ULONG index = 0UL;
    ULONG selectedRuleId = 0UL;
    BOOLEAN matched = FALSE;
    BOOLEAN allAllowOnce = TRUE;
    BOOLEAN enforceMatched = FALSE;
    /* Set by any non-watch rule, so a watch never shares a disposition. */
    BOOLEAN otherMatched = FALSE;
    KSW_HVM_EPT_RULE_SLOT* watchSlot = NULL;
    volatile ULONGLONG* entry = NULL;
    ULONGLONG grantedValue = 0ULL;

    /* Reject invalid fixed pointers in the nonblocking exit path. */
    if (Runtime == NULL ||
        Transient == NULL ||
        RuleId == NULL ||
        Disposition == NULL ||
        WatchHit == NULL) {
        /* Report an unhandled fatal EPT violation. */
        return FALSE;
    }
    /* Publish the fail-closed disposition before any rule is examined. */
    *Disposition = KSW_HVM_EPT_DISPOSITION_DEVIRTUALIZE;
    /* Publish no new rule match before the bounded rule scan. */
    *RuleId = 0UL;
    /* Publish an empty watch result before any rule is examined. */
    WatchHit->FirstHit = FALSE;
    WatchHit->RangeMatch = FALSE;
    WatchHit->Reserved0[0] = 0U;
    WatchHit->Reserved0[1] = 0U;
    WatchHit->WatchId = 0UL;
    /*
     * A second violation before MTF must restore the first grant and then
     * devirtualize.  Never overwrite the only recovery record.
     */
    if (Transient->Armed) {
        /* Preserve the first rule as the authoritative failure evidence. */
        *RuleId = Transient->RuleId;
        /* Attempt restoration; failure intentionally leaves the record armed. */
        (void)KswordARKHvmEptRestoreTransient(
            Runtime,
            Transient);
        /* Force fail-closed devirtualization after any overlapping transient. */
        return FALSE;
    }
    /* Clear stale unarmed fields without calling vectorized runtime helpers. */
    Transient->Reserved0[0] = 0U;
    Transient->Reserved0[1] = 0U;
    Transient->Reserved0[2] = 0U;
    Transient->RuleId = 0UL;
    Transient->Entry = NULL;
    Transient->RestrictedValue = 0ULL;
    Transient->EptPointer = 0ULL;
    /* Aggregate every active rule that covers this page and access type. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++index) {
        KSW_HVM_EPT_RULE_SLOT* rule =
            &Runtime->EptRules[index];
        ULONGLONG ruleBytes = 0ULL;
        ULONGLONG ruleEnd = 0ULL;

        /* Skip inactive rules. */
        if (!rule->Active) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Skip rules that did not remove the attempted access type. */
        if ((rule->DeniedAccess & Access) == 0UL) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Convert the validated page count to bytes. */
        ruleBytes = rule->PageCount * KSW_HVM_PAGE_BYTES;
        /* Compute the validated exclusive rule end. */
        ruleEnd = rule->PhysicalAddress + ruleBytes;
        /* Skip rules that do not contain the faulting page. */
        if (physicalPage < rule->PhysicalAddress ||
            physicalPage >= ruleEnd) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Preserve the first matching identifier for allow-once telemetry. */
        if (!matched) {
            /* Select the first complete overlapping rule. */
            selectedRuleId = rule->RuleId;
        }
        /* Publish that at least one rule covers this exact attempted access. */
        matched = TRUE;
        /*
         * A watch resolves on its own, after the scan, and never mixes with
         * the other three dispositions: installation already refuses a watch
         * on a page any of them owns, so seeing both here would mean the
         * table is inconsistent - and then the conservative outcome wins.
         */
        if ((rule->Flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) != 0UL) {
            /* Preserve the first watch as the authoritative hit owner. */
            if (watchSlot == NULL) {
                /* Select the watch this violation belongs to. */
                watchSlot = rule;
            }
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Publish that a non-watch rule also covers this access. */
        otherMatched = TRUE;
        /*
         * A durable denial neither grants a temporary permission nor tears
         * down residency, so it is tracked separately from the tripwire and
         * allow-once dispositions and resolved after the whole scan.
         */
        if ((rule->Flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE) != 0UL) {
            /* Preserve the first denying rule as authoritative evidence. */
            if (!enforceMatched) {
                /* Select the rule that will produce the injected fault. */
                selectedRuleId = rule->RuleId;
            }
            /* Publish that at least one rule denies this access durably. */
            enforceMatched = TRUE;
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Any strict tripwire dominates every overlapping allow-once rule. */
        if ((rule->Flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE) == 0UL) {
            /* Preserve the first strict rule as authoritative evidence. */
            if (allAllowOnce) {
                /* Select the rule that requires immediate devirtualization. */
                selectedRuleId = rule->RuleId;
            }
            /* Prevent any temporary grant for the aggregate rule set. */
            allAllowOnce = FALSE;
        }
    }
    /*
     * First-touch watch.
     *
     * Resolved before every other disposition and only when no other rule
     * covers the same access, because a watch means "let it through and tell
     * me who did it" while the others mean "stop", "deny" or "step".  Mixing
     * them would silently turn one into the other.
     */
    if (watchSlot != NULL &&
        !otherMatched) {
        LONG previousState = 0L;
        KSW_HVM_WATCH_HIT_PLAN plan = { 0 };
        volatile ULONGLONG* watchEntry = NULL;
        ULONGLONG restoredValue = 0ULL;
        ULONGLONG invalidatePointer = 0ULL;

        /* Publish the watch identity as the authoritative rule evidence. */
        selectedRuleId = watchSlot->RuleId;
        *RuleId = selectedRuleId;
        WatchHit->WatchId = selectedRuleId;
        /*
         * Decide the single owner of this first touch.
         *
         * Every processor that faults on the page still has to repair its own
         * view below - only the one that wins here records evidence and moves
         * the lifecycle.  Losers that merely resumed would fault again on the
         * same instruction until the winner's store reached them.
         */
        previousState = InterlockedCompareExchange(
            &watchSlot->WatchState,
            (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_TRIGGERED,
            (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED);
        /*
         * The decision itself lives in the shared pure header, exhaustively
         * tested offline.  Both ways of getting it wrong are silent: two
         * processors each believing they are the first touch produces two
         * contradictory "first" records, and a loser that resumes without
         * repairing its own view re-faults on the same instruction until the
         * winner's store reaches it - a livelock with no error code at all.
         */
        plan = KswordArkHvmWatchPlanHit((ULONG)previousState);
        /* Refuse to continue from a lifecycle state this path cannot explain. */
        if (!plan.Accepted) {
            /* Report that the dispatcher must leave EPT enforcement. */
            return FALSE;
        }
        /* Record which processor owns the one logical first touch. */
        WatchHit->FirstHit = plan.OwnsFirstHit != 0U;
        /* Stop denying before anything recomputes the page from the table. */
        if (WatchHit->FirstHit) {
            /*
             * Clearing the mask is the representation of "disarmed": both the
             * scan above and the recompute below read it, so one store retires
             * the tripwire everywhere without a second state to keep in sync.
             */
            watchSlot->DeniedAccess = 0UL;
            /* Order the retirement before any permission is restored. */
            KeMemoryBarrier();
        }
        /* Resolve the preallocated writable four-KiB leaf for this page. */
        watchEntry = KswordARKHvmEptFindLeafEntry(
            Runtime,
            physicalPage);
        /* Fail closed when split metadata is unexpectedly unavailable. */
        if (watchEntry == NULL) {
            /* Retire the lifecycle so it cannot stay in the transient state. */
            KswordARKHvmEptFaultWatchAfterCas(watchSlot, &plan);
            /* Report that the resident dispatcher must devirtualize. */
            return FALSE;
        }
        /* Compute the value the page settles on once this watch stops denying. */
        restoredValue = KswordARKHvmEptComputeLeafExcluding(
            Runtime,
            physicalPage,
            *watchEntry,
            watchSlot);
        /*
         * Publish into the shared table first so that a later passive-level
         * recompute agrees with what the processors are already using.
         */
        *watchEntry = restoredValue;
        /* Repair this processor's own mirror when it runs a private hierarchy. */
        if (Local != NULL) {
            volatile ULONGLONG* localEntry =
                KswordARKHvmEptLocalTranslate(Local, watchEntry);

            /* Fail closed rather than leave this processor still denied. */
            if (localEntry == NULL) {
                /* Retire the lifecycle so it cannot stay in the transient state. */
                KswordARKHvmEptFaultWatchAfterCas(watchSlot, &plan);
                /* Report that the resident dispatcher must devirtualize. */
                return FALSE;
            }
            /* Restore the permission in the hierarchy this processor walks. */
            *localEntry = restoredValue;
            /* Name the private hierarchy for the invalidation below. */
            invalidatePointer = Local->EptPointer;
        }
        /* Order the restoration before invalidating any translation. */
        KeMemoryBarrier();
        /* Discard translations built from the restricted leaf. */
        if (KswordARKHvmAsmInveptSingle(
                invalidatePointer != 0ULL
                    ? invalidatePointer
                    : Runtime->EptPointer) != 0U) {
            /* Retire the lifecycle so it cannot stay in the transient state. */
            KswordARKHvmEptFaultWatchAfterCas(watchSlot, &plan);
            /* Report that the resident dispatcher must devirtualize. */
            return FALSE;
        }
        /* Record the hit scene on the owning processor only. */
        if (WatchHit->FirstHit) {
            /*
             * Range match is an attribution refinement, never a filter: the
             * hit is reported either way, because the hardware watched the
             * whole page and saying otherwise would misdescribe what happened.
             */
            WatchHit->RangeMatch = KswordArkHvmWatchRangeMatch(
                GuestLinearAddressValid ? 1 : 0,
                GuestLinearAddress,
                watchSlot->WatchRequestedAddress,
                watchSlot->WatchRequestedLength) != 0;
            /* Preserve the scene the dispatcher will publish as evidence. */
            watchSlot->WatchLastHitGuestPhysicalAddress = GuestPhysicalAddress;
            watchSlot->WatchLastHitGuestLinearAddress = GuestLinearAddress;
            watchSlot->WatchLastHitGuestLinearValid =
                GuestLinearAddressValid ? 1U : 0U;
            watchSlot->WatchLastHitRangeMatch =
                WatchHit->RangeMatch ? 1UL : 0UL;
            watchSlot->WatchHitCount += 1UL;
            /*
             * Assume the evidence was lost until the ring says otherwise.
             *
             * The publish happens in the dispatcher, after this function
             * returns, and it can fail.  Starting from "lost" means a failed
             * publish needs no extra bookkeeping to be reported honestly,
             * while starting from "published" would quietly claim evidence
             * that does not exist.
             */
            watchSlot->WatchLastHitStatus =
                KSWORD_ARK_HVM_EPT_WATCH_HIT_EVENT_LOST;
            /* Order every recorded field before the terminal state. */
            KeMemoryBarrier();
            /* Publish the terminal lifecycle state for this armed round. */
            InterlockedExchange(
                &watchSlot->WatchState,
                (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED);
        }
        /* Request the resume that re-executes the original instruction. */
        *Disposition = KSW_HVM_EPT_DISPOSITION_WATCH_ONCE;
        /* Report a completely resolved violation with residency intact. */
        return TRUE;
    }
    /*
     * A watch that reached here shares its page with another rule, which
     * installation is supposed to make impossible.  Deny the one-instruction
     * grant so the aggregate falls through to fail-closed devirtualization
     * rather than resolving as whichever rule happened to be scanned first.
     */
    if (watchSlot != NULL) {
        /* Prevent any temporary grant for an inconsistent rule set. */
        allAllowOnce = FALSE;
    }
    /*
     * A durable denial outranks an overlapping allow-once grant: permitting
     * the access even once would defeat the rule that exists to refuse it.
     * A strict tripwire still dominates, because tearing down residency is
     * the most conservative outcome available.
     */
    if (enforceMatched && allAllowOnce) {
        /* Publish the aggregate rule identity before the disposition. */
        *RuleId = selectedRuleId;
        /*
         * Denial is expressed as a page fault, and a page fault without a
         * meaningful CR2 would send the guest handler to an arbitrary
         * address.  Without a reported guest-linear address, fall back to the
         * tripwire behavior rather than inventing one.
         */
        if (!GuestLinearAddressValid) {
            /* Report that the dispatcher must leave EPT enforcement. */
            return FALSE;
        }
        /* Request the injected fault that expresses durable denial. */
        *Disposition = KSW_HVM_EPT_DISPOSITION_INJECT_FAULT;
        /* Report a completely resolved violation. */
        return TRUE;
    }
    /* Publish the aggregate rule identity before choosing a disposition. */
    *RuleId = selectedRuleId;
    /* Unruled accesses and any strict overlapping rule devirtualize. */
    if (!matched ||
        !allAllowOnce) {
        /* Report that the resident dispatcher must leave EPT enforcement. */
        return FALSE;
    }
    /*
     * ALLOW_ONCE edits an EPT leaf.  On a SHARED hierarchy that is safe only
     * with exactly one resident VCPU, because every other one would see the
     * widened permission for the whole window.  With a private hierarchy the
     * leaf is this processor's alone, so the topology requirement drops out -
     * but the capability requirement below never does.
     */
    if ((Local == NULL &&
            (Runtime->ProcessorCount != 1UL ||
             InterlockedCompareExchange(
                 &Runtime->ResidentProcessorCount,
                 0L,
                 0L) != 1L)) ||
        (Runtime->FeatureFlags &
            (KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
             KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG)) !=
            (KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
             KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG)) {
        /* Reject a shared-leaf permission window that another VCPU could use. */
        return FALSE;
    }
    /* Resolve the preallocated writable four-KiB leaf after aggregation. */
    entry = KswordARKHvmEptFindLeafEntry(
        Runtime,
        physicalPage);
    /* Fail closed when split metadata is unexpectedly unavailable. */
    if (entry == NULL) {
        /* Report that the resident dispatcher must devirtualize. */
        return FALSE;
    }
    /*
     * Redirect the write to this processor's own copy of the leaf.  A leaf
     * that is flippable but has no mirror is a build error, and writing the
     * shared table instead would silently reintroduce exactly the hazard the
     * private hierarchy exists to remove - so it fails closed.
     */
    if (Local != NULL) {
        entry = KswordARKHvmEptLocalTranslate(Local, entry);
        if (entry == NULL) {
            /* Report that the resident dispatcher must devirtualize. */
            return FALSE;
        }
    }
    /* Preserve every recovery field before changing the leaf. */
    Transient->RestrictedValue = *entry;
    Transient->Entry = entry;
    Transient->RuleId = selectedRuleId;
    /* Record which hierarchy must be invalidated when this grant ends. */
    Transient->EptPointer = Local != NULL ? Local->EptPointer : 0ULL;
    /* Publish the armed recovery record before granting any permission. */
    KeMemoryBarrier();
    Transient->Armed = TRUE;
    /* Compute a temporary value that grants only the attempted permissions. */
    grantedValue = Transient->RestrictedValue;
    /* Temporarily grant attempted read permission. */
    if ((Access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL) {
        /* Add EPT read permission for one instruction. */
        grantedValue |= KSW_EPT_READ;
    }
    /* Temporarily grant attempted write permission. */
    if ((Access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
        /* EPT never permits W=1 with R=0, so grant the legal R/W pair. */
        grantedValue |= KSW_EPT_READ | KSW_EPT_WRITE;
    }
    /* Temporarily grant attempted execute permission. */
    if ((Access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL) {
        /* Add EPT execute permission for one instruction. */
        grantedValue |= KSW_EPT_EXECUTE;
        /* Add READ when the processor cannot encode execute-only EPT leaves. */
        if ((Runtime->VmxEptVpidCapabilities &
                KSW_EPT_CAP_EXECUTE_ONLY) == 0ULL) {
            /* Preserve an architecturally legal temporary execute leaf. */
            grantedValue |= KSW_EPT_READ;
        }
    }
    /* Publish the complete temporary permission value. */
    *entry = grantedValue;
    /* Order the permission grant before current-context invalidation. */
    KeMemoryBarrier();
    /* Invalidate the hierarchy the grant was made in, before VMRESUME. */
    if (KswordARKHvmAsmInveptSingle(
            Transient->EptPointer != 0ULL
                ? Transient->EptPointer
                : Runtime->EptPointer) != 0U) {
        /* Restore and invalidate; retain Armed if the restoration also fails. */
        (void)KswordARKHvmEptRestoreTransient(
            Runtime,
            Transient);
        /* Require immediate fail-closed devirtualization. */
        return FALSE;
    }
    /* Request the monitor-trap step that restores the temporary grant. */
    *Disposition = KSW_HVM_EPT_DISPOSITION_ALLOW_ONCE;
    /* Report a handled, single-VCPU allow-once EPT violation. */
    return TRUE;
}

BOOLEAN
KswordARKHvmEptHandleMonitorTrap(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_EPT_TRANSIENT* Transient
    )
{
    /* Restore and invalidate before monitor-trap can be disabled. */
    return KswordARKHvmEptRestoreTransient(
        Runtime,
        Transient);
}
