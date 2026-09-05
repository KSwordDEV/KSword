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
static NTSTATUS
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
    /* Preserve permissions and memory type while dropping the large marker. */
    leafFlags = originalEntry &
        (KSW_EPT_READ |
         KSW_EPT_WRITE |
         KSW_EPT_EXECUTE |
         (7ULL << KSW_EPT_MEMORY_TYPE_SHIFT));
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
static volatile ULONGLONG*
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
    Runtime->StateFlags &=
        ~KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE;
}

NTSTATUS
KswordARKHvmEptRuleControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_EPT_RULE_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_EPT_RULE_RESPONSE* Response
    )
{
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
            Runtime->StateFlags &=
                ~KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE;
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
        effectiveDeniedAccess = Request->deniedAccess;
        /* Normalize every read tripwire to a legal EPT permission tuple. */
        if ((effectiveDeniedAccess &
                KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL) {
            /* Prevent the architecturally invalid write-without-read state. */
            effectiveDeniedAccess |=
                KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
            /* Prevent execute-only leaves when the CPU does not support them. */
            if ((Runtime->VmxEptVpidCapabilities &
                    KSW_EPT_CAP_EXECUTE_ONLY) == 0ULL) {
                /* Fall back to a no-access tripwire on this processor. */
                effectiveDeniedAccess |=
                    KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE;
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
             KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE);
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
        Runtime->StateFlags |=
            KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE;
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
    /* Require current-context invalidation before forgetting the recovery. */
    if (KswordARKHvmAsmInveptSingle(
            Runtime->EptPointer) != 0U) {
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
    /* Report a fully restored and invalidated EPT context. */
    return TRUE;
}

BOOLEAN
KswordARKHvmEptHandleViolation(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access,
    _In_ BOOLEAN GuestLinearAddressValid,
    _Out_ KSW_HVM_EPT_TRANSIENT* Transient,
    _Out_ ULONG* RuleId,
    _Out_ ULONG* Disposition
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
    volatile ULONGLONG* entry = NULL;
    ULONGLONG grantedValue = 0ULL;

    /* Reject invalid fixed pointers in the nonblocking exit path. */
    if (Runtime == NULL ||
        Transient == NULL ||
        RuleId == NULL ||
        Disposition == NULL) {
        /* Report an unhandled fatal EPT violation. */
        return FALSE;
    }
    /* Publish the fail-closed disposition before any rule is examined. */
    *Disposition = KSW_HVM_EPT_DISPOSITION_DEVIRTUALIZE;
    /* Publish no new rule match before the bounded rule scan. */
    *RuleId = 0UL;
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
    /* Aggregate every active rule that covers this page and access type. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++index) {
        const KSW_HVM_EPT_RULE_SLOT* rule =
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
     * ALLOW_ONCE edits a shared EPT leaf.  It is safe only when exactly one
     * resident VCPU exists and the CPU supports both MTF and single INVEPT.
     */
    if (Runtime->ProcessorCount != 1UL ||
        InterlockedCompareExchange(
            &Runtime->ResidentProcessorCount,
            0L,
            0L) != 1L ||
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
    /* Preserve every recovery field before changing the shared leaf. */
    Transient->RestrictedValue = *entry;
    Transient->Entry = entry;
    Transient->RuleId = selectedRuleId;
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
    /* Invalidate the current EPT context before VMRESUME. */
    if (KswordARKHvmAsmInveptSingle(
            Runtime->EptPointer) != 0U) {
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
