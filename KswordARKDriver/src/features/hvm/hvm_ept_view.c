/*++

Module Name:

    hvm_ept_view.c

Abstract:

    EPT split views.

    A view gives one guest-physical page two backing frames and picks between
    them by access type.  CLOAK keeps execution on the real page and sends every
    read and write to a shadow, so code runs while memory scanners see the
    shadow's contents.  HOOK is the mirror: reads see the real page while
    execution runs from a shadow holding patched instructions, which is a
    breakpoint that byte comparison cannot find.

    The mechanism is the leaf flip.  The primary value denies exactly the access
    that must be redirected; the resulting EPT violation installs the secondary
    value, and the monitor-trap exit that follows restores the primary one.
    That reuses the allow-once transient machinery unchanged - a view flip is
    an allow-once grant whose restored value happens to point at a different
    frame.

    The consequence used to be inherited too: with one shared EPT hierarchy a
    second resident processor could execute through the secondary value during
    the one-instruction window, so views were refused unless exactly one VCPU
    was resident.

    hvm_ept_local.c removes that restriction where it is armed.  Each
    processor walks its own copy of the tables leading to a flippable leaf, so
    a flip reaches only the processor that took the exit.  The single-VCPU
    refusal therefore applies only when no private hierarchy was built.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root violations.

--*/

#include "hvm_ept_view.h"
#include "hvm_ept_switch.h"
/*
 * For KswordARKHvmResidentInvalidateEpt.  The view path must not issue INVEPT
 * itself: the instruction is #UD outside VMX operation, and both of the places
 * below run from the IOCTL path, where no processor need be in VMX operation at
 * all.  It is also per-logical-processor, so even when residency is up, issuing
 * it here would leave every other processor holding stale translations.
 */
#include "hvm_resident.h"

/* Return the active view that owns one page-aligned physical address. */
static KSW_HVM_EPT_VIEW_SLOT*
KswordARKHvmEptViewFind(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalPage
    )
{
    ULONG index = 0UL;

    /* Search the bounded view table without allocation. */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        /* Match only installed views covering the exact page. */
        if (Runtime->EptViews[index].Active &&
            Runtime->EptViews[index].PhysicalAddress == PhysicalPage) {
            /* Return the exact installed view. */
            return &Runtime->EptViews[index];
        }
    }
    /* Report that no view covers the page. */
    return NULL;
}

/* Return the active view carrying one protocol identifier. */
static KSW_HVM_EPT_VIEW_SLOT*
KswordARKHvmEptViewFindById(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG ViewId
    )
{
    ULONG index = 0UL;

    /* Search the bounded view table without allocation. */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        /* Match only installed views with the exact identifier. */
        if (Runtime->EptViews[index].Active &&
            Runtime->EptViews[index].ViewId == ViewId) {
            /* Return the exact installed view. */
            return &Runtime->EptViews[index];
        }
    }
    /* Report that no view carries the identifier. */
    return NULL;
}

/* Return whether any active EPT rule covers one page. */
static BOOLEAN
KswordARKHvmEptViewPageHasRule(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalPage
    )
{
    ULONG index = 0UL;

    /* Rules and views both own the leaf value; they cannot share a page. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++index) {
        const KSW_HVM_EPT_RULE_SLOT* rule = &Runtime->EptRules[index];
        ULONGLONG ruleEnd = 0ULL;

        /* Skip inactive rule records. */
        if (!rule->Active) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Compute the validated exclusive rule end. */
        ruleEnd = rule->PhysicalAddress +
            (rule->PageCount * KSW_HVM_PAGE_BYTES);
        /* Report the first rule that contains the page. */
        if (PhysicalPage >= rule->PhysicalAddress &&
            PhysicalPage < ruleEnd) {
            /* Report a leaf-ownership conflict. */
            return TRUE;
        }
    }
    /* Report that no rule owns the page. */
    return FALSE;
}

/*
 * Build the two leaf values one view alternates between.  Permissions come
 * from the kind; the memory type and every other attribute are inherited from
 * the identity leaf so a view never changes how the page is cached.
 */
static NTSTATUS
KswordARKHvmEptViewBuildEntries(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG Kind,
    _In_ ULONGLONG OriginalEntry,
    _In_ ULONGLONG ShadowPhysical,
    _Out_ ULONGLONG* PrimaryEntry,
    _Out_ ULONGLONG* SecondaryEntry
    )
{
    /* Preserve the memory type and non-permission attributes of the leaf. */
    const ULONGLONG attributes =
        OriginalEntry &
        ~(KSW_EPT_READ | KSW_EPT_WRITE | KSW_EPT_EXECUTE |
          KSW_EPT_PHYSICAL_MASK);
    /* Preserve the real frame the identity leaf already encodes. */
    const ULONGLONG realFrame = OriginalEntry & KSW_EPT_PHYSICAL_MASK;
    /* Encode the shadow frame that backs the redirected access. */
    const ULONGLONG shadowFrame = ShadowPhysical & KSW_EPT_PHYSICAL_MASK;
    /* Record whether the processor can encode execute-only leaves. */
    const BOOLEAN executeOnly =
        (Runtime->VmxEptVpidCapabilities & KSW_EPT_CAP_EXECUTE_ONLY) != 0ULL;

    if (Kind == KSWORD_ARK_HVM_VIEW_KIND_CLOAK) {
        /*
         * Execution must reach the real page while reads are redirected, which
         * requires an execute-only leaf.  Without that encoding the primary
         * value would have to grant read as well, and nothing would be hidden.
         */
        if (!executeOnly) {
            /* Report the missing architectural encoding. */
            return STATUS_NOT_SUPPORTED;
        }
        /* Primary: execute the real page, deny every read and write. */
        *PrimaryEntry = attributes | realFrame | KSW_EPT_EXECUTE;
        /* Secondary: read and write the shadow for one instruction. */
        *SecondaryEntry =
            attributes | shadowFrame | KSW_EPT_READ | KSW_EPT_WRITE;
        /* Report a complete pair. */
        return STATUS_SUCCESS;
    }
    if (Kind == KSWORD_ARK_HVM_VIEW_KIND_HOOK) {
        /* Primary: read and write the real page, deny execution. */
        *PrimaryEntry =
            attributes | realFrame | KSW_EPT_READ | KSW_EPT_WRITE;
        /*
         * Secondary: execute the shadow.  Read is added when execute-only is
         * unavailable, because EPT cannot encode X without R on those parts.
         * The window is one instruction, so a reader would have to land inside
         * it to observe the shadow at all.
         */
        *SecondaryEntry = attributes | shadowFrame | KSW_EPT_EXECUTE;
        if (!executeOnly) {
            /* Keep the secondary value architecturally legal. */
            *SecondaryEntry |= KSW_EPT_READ;
        }
        /* Report a complete pair. */
        return STATUS_SUCCESS;
    }
    /* Report an unknown view kind. */
    return STATUS_INVALID_PARAMETER;
}

/* Release one view's shadow page and restore the leaf it owned. */
static VOID
KswordARKHvmEptViewReleaseLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_EPT_VIEW_SLOT* View
    )
{
    /* Restore the leaf before the shadow frame becomes reusable. */
    if (View->Entry != NULL) {
        /* Publish the exact value captured before installation. */
        *View->Entry = View->OriginalEntry;
        /* Order the restoration before the context is invalidated. */
        KeMemoryBarrier();
        /*
         * Drop cached translations that still point at the shadow, on every
         * processor and only while some processor is actually in VMX
         * operation.  A bare INVEPT here would be #UD on exactly the path this
         * runs on most - releasing a view after residency has stopped.
         */
        (void)KswordARKHvmResidentInvalidateEpt(Runtime->EptPointer);
    }
    /*
     * Release this view's hierarchy before the record is cleared, while the
     * index is still readable.  Harmless when the view was served by the
     * default backend: the index is then 0, which names the base, and
     * releasing the base is defined as doing nothing.
     */
    KswordARKHvmEptSwitchReleaseLeaf(Runtime, View->EptSwitchIndex);
    /* Release the shadow page after no leaf can reach it. */
    if (View->ShadowVirtual != NULL) {
        /* Free the shadow allocation. */
        MmFreeContiguousMemory(View->ShadowVirtual);
    }
    /* Clear the reusable slot completely. */
    RtlZeroMemory(View, sizeof(*View));
    /* Account the released view. */
    if (Runtime->EptViewCount != 0UL) {
        /* Keep the published count consistent with the table. */
        Runtime->EptViewCount -= 1UL;
    }
}

/* Publish one view row into a protocol response. */
static VOID
KswordARKHvmEptViewFillRow(
    _In_ const KSW_HVM_EPT_VIEW_SLOT* View,
    _Out_ KSWORD_ARK_HVM_VIEW_ROW* Row
    )
{
    /* Publish the stable protocol identifier. */
    Row->viewId = View->ViewId;
    /* Publish the view kind. */
    Row->kind = View->Kind;
    /* Publish the behavior flags. */
    Row->flags = View->Flags;
    /* Keep the reserved field deterministic. */
    Row->reserved = 0UL;
    /* Publish the covered guest physical page. */
    Row->physicalAddress = View->PhysicalAddress;
    /* Publish the shadow frame backing the redirected access. */
    Row->shadowPhysicalAddress =
        (ULONGLONG)View->ShadowPhysical.QuadPart;
    /* Publish how often the leaf flipped since installation. */
    Row->flipCount = (ULONGLONG)View->FlipCount;
}

/* Install one new view over a page that no rule or view already owns. */
static NTSTATUS
KswordARKHvmEptViewAddLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_VIEW_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_VIEW_RESPONSE* Response
    )
{
    const ULONGLONG physicalPage =
        Request->physicalAddress & ~(KSW_HVM_PAGE_BYTES - 1ULL);
    PHYSICAL_ADDRESS lowest = { 0 };
    PHYSICAL_ADDRESS highest = { 0 };
    PHYSICAL_ADDRESS boundary = { 0 };
    KSW_HVM_EPT_VIEW_SLOT* view = NULL;
    KSW_HVM_EPT_SPLIT* split = NULL;
    volatile ULONGLONG* entry = NULL;
    ULONGLONG originalEntry = 0ULL;
    ULONGLONG primaryEntry = 0ULL;
    ULONGLONG secondaryEntry = 0ULL;
    ULONG index = 0UL;
    ULONG switchIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an unaligned or out-of-window target before allocating. */
    if (Request->physicalAddress != physicalPage ||
        physicalPage >= KSW_HVM_MAX_MAPPED_PHYSICAL) {
        /* Publish the stable invalid-request protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST;
        /* Return the exact parameter failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * A view the private hierarchies could not mirror must be refused here,
     * not at start.  Refusing at start would mean the caller learns a view
     * set is inadmissible only after every add already succeeded.
     */
    status = KswordARKHvmEptLocalCheckAdmission(
        Runtime,
        physicalPage,
        KSW_HVM_PAGE_BYTES);
    if (!NT_SUCCESS(status)) {
        /* Publish the stable table-full protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL;
        Response->lastStatus = status;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Refuse to share one leaf between a view and a rule or another view. */
    if (KswordARKHvmEptViewFind(Runtime, physicalPage) != NULL ||
        KswordARKHvmEptViewPageHasRule(Runtime, physicalPage)) {
        /* Publish the stable leaf-conflict protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_LEAF_CONFLICT;
        /* Return the exact ownership conflict. */
        return STATUS_OBJECT_NAME_COLLISION;
    }
    /* Reserve one bounded table slot before allocating a shadow. */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        /* Select the first inactive record. */
        if (!Runtime->EptViews[index].Active) {
            /* Bind the reusable zeroed record. */
            view = &Runtime->EptViews[index];
            /* Stop after the first free slot. */
            break;
        }
    }
    /* Report bounded view capacity exhaustion. */
    if (view == NULL) {
        /* Publish the stable table-full protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL;
        /* Return the exact fixed-capacity failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Split the covering two-MiB leaf so the view owns four-KiB granularity. */
    status = KswordARKHvmEptEnsureSplitLocked(
        Runtime,
        physicalPage,
        &split);
    /* Stop when the baseline identity leaf cannot be split. */
    if (!NT_SUCCESS(status)) {
        /* Publish the stable split-failure protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED;
        /* Return the exact split failure. */
        return status;
    }
    /* Resolve the writable four-KiB leaf the view will flip. */
    entry = KswordARKHvmEptFindLeafEntry(Runtime, physicalPage);
    /* Fail closed when split metadata is unexpectedly unavailable. */
    if (entry == NULL) {
        /* Publish the stable split-failure protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED;
        /* Return the exact lookup failure. */
        return STATUS_NOT_FOUND;
    }
    /* Preserve the exact value that existed before installation. */
    originalEntry = *entry;
    /* Allocate the shadow frame that backs the redirected access. */
    highest.QuadPart = MAXLONGLONG;
    view->ShadowVirtual = MmAllocateContiguousMemorySpecifyCache(
        (SIZE_T)KSW_HVM_PAGE_BYTES,
        lowest,
        highest,
        boundary,
        MmCached);
    /* Report allocation failure without publishing a partial view. */
    if (view->ShadowVirtual == NULL) {
        /* Clear the reusable record. */
        RtlZeroMemory(view, sizeof(*view));
        /* Publish the stable resource-failure protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED;
        /* Return the exact resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Resolve the shadow frame encoded into the secondary leaf value. */
    view->ShadowPhysical = MmGetPhysicalAddress(view->ShadowVirtual);
    /* Seed the shadow before any leaf can reach it. */
    if ((Request->flags &
            KSWORD_ARK_HVM_VIEW_FLAG_SEED_ZERO) != 0UL) {
        /* Present an empty page to whatever the view redirects. */
        RtlZeroMemory(
            view->ShadowVirtual,
            (SIZE_T)KSW_HVM_PAGE_BYTES);
    } else if ((Request->flags &
            KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET) != 0UL) {
        MM_COPY_ADDRESS copyAddress;
        SIZE_T copied = 0U;

        /* Freeze the page's current contents into the shadow. */
        RtlZeroMemory(&copyAddress, sizeof(copyAddress));
        copyAddress.PhysicalAddress.QuadPart = (LONGLONG)physicalPage;
        status = MmCopyMemory(
            view->ShadowVirtual,
            copyAddress,
            (SIZE_T)KSW_HVM_PAGE_BYTES,
            MM_COPY_MEMORY_PHYSICAL,
            &copied);
        /* Refuse to install a view over a page that cannot be captured. */
        if (!NT_SUCCESS(status) ||
            copied != (SIZE_T)KSW_HVM_PAGE_BYTES) {
            /* Release the shadow that will never be installed. */
            MmFreeContiguousMemory(view->ShadowVirtual);
            /* Clear the reusable record. */
            RtlZeroMemory(view, sizeof(*view));
            /* Publish the stable resource-failure protocol status. */
            Response->status = KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED;
            /* Return the exact capture failure. */
            return NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
        }
    } else {
        /* Publish the caller-supplied shadow contents. */
        RtlCopyMemory(
            view->ShadowVirtual,
            Request->shadow,
            (SIZE_T)KSW_HVM_PAGE_BYTES);
    }
    /* Build the two values the view alternates between. */
    status = KswordARKHvmEptViewBuildEntries(
        Runtime,
        Request->kind,
        originalEntry,
        (ULONGLONG)view->ShadowPhysical.QuadPart,
        &primaryEntry,
        &secondaryEntry);
    /* Stop when the requested kind cannot be encoded on this processor. */
    if (!NT_SUCCESS(status)) {
        /* Release the shadow that will never be installed. */
        MmFreeContiguousMemory(view->ShadowVirtual);
        /* Clear the reusable record. */
        RtlZeroMemory(view, sizeof(*view));
        /* Distinguish the missing encoding from a malformed request. */
        Response->status = status == STATUS_NOT_SUPPORTED
            ? KSWORD_ARK_HVM_VIEW_STATUS_EXECUTE_ONLY_UNSUPPORTED
            : KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST;
        /* Return the exact encoding failure. */
        return status;
    }
    /*
     * Build this view's own hierarchy before anything is published.
     *
     * Done here rather than at start for the same reason the private-EPT
     * admission check is: refusing at start would mean the caller learns a
     * view set is inadmissible only after every add already reported success.
     *
     * Verified immediately, and the verification walks the built tables the
     * way the processor would rather than re-reading what was just written.
     * Every error this can catch - an index off by one level, a parent
     * repointed to the wrong page - produces a hierarchy that is still
     * structurally valid, so there is no later symptom to catch it by.
     */
    if (Runtime->EptpSwitchArmed) {
        status = KswordARKHvmEptSwitchBuildLeaf(
            Runtime,
            physicalPage,
            primaryEntry,
            secondaryEntry,
            (const volatile ULONGLONG*)split->PageTable,
            &switchIndex);
        if (NT_SUCCESS(status)) {
            status = KswordARKHvmEptSwitchVerifyLeaf(
                Runtime,
                switchIndex);
            /* A hierarchy that does not verify must not stay in the ledger. */
            if (!NT_SUCCESS(status)) {
                KswordARKHvmEptSwitchReleaseLeaf(Runtime, switchIndex);
                switchIndex = 0UL;
            }
        }
        if (!NT_SUCCESS(status)) {
            /* Release the shadow that will never be installed. */
            MmFreeContiguousMemory(view->ShadowVirtual);
            /* Clear the reusable record. */
            RtlZeroMemory(view, sizeof(*view));
            /* Publish the stable resource-failure protocol status. */
            Response->status = KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED;
            Response->lastStatus = status;
            /* Return the exact hierarchy failure. */
            return status;
        }
    }
    /* Preserve every recovery field before the leaf changes. */
    view->PhysicalAddress = physicalPage;
    /* Preserve which hierarchy serves this view; 0 means the base. */
    view->EptSwitchIndex = switchIndex;
    /* Preserve the kind that selects the redirected access. */
    view->Kind = Request->kind;
    /* Preserve only defined behavior flags. */
    view->Flags = Request->flags &
        (KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET |
         KSWORD_ARK_HVM_VIEW_FLAG_SEED_ZERO |
         KSWORD_ARK_HVM_VIEW_FLAG_LOG);
    /* Preserve the writable leaf for flips and restoration. */
    view->Entry = entry;
    /* Preserve the exact pre-installation value. */
    view->OriginalEntry = originalEntry;
    /* Preserve the steady-state value. */
    view->PrimaryEntry = primaryEntry;
    /* Preserve the one-instruction redirection value. */
    view->SecondaryEntry = secondaryEntry;
    /* Assign the next stable protocol identifier. */
    Runtime->EptViewNextId += 1UL;
    /* Publish the assigned identifier. */
    view->ViewId = Runtime->EptViewNextId;
    /* Order every field before the record becomes reachable. */
    KeMemoryBarrier();
    /* Publish the installed view record. */
    view->Active = TRUE;
    /* Account the installed view. */
    Runtime->EptViewCount += 1UL;
    /* Install the steady-state value the view keeps. */
    *entry = primaryEntry;
    /* Order the leaf change before the context is invalidated. */
    KeMemoryBarrier();
    /*
     * Same reasoning as the release path, with a sharper edge: this runs after
     * Active, EptViewCount and the leaf value are already committed, so a #UD
     * here is not "installation failed" - it is "installation succeeded, then
     * the machine bugchecked".  That is why this call has to be the guarded,
     * all-processor one even though the leaf write above is local.
     */
    (void)KswordARKHvmResidentInvalidateEpt(Runtime->EptPointer);
    /* Publish the assigned identifier to the caller. */
    Response->viewId = view->ViewId;
    /* Publish the successful installation. */
    Response->status = KSWORD_ARK_HVM_VIEW_STATUS_OK;
    /* Complete the installation successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmEptViewControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_VIEW_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_VIEW_RESPONSE* Response
    )
{
    ULONG index = 0UL;
    ULONG rows = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before touching any state. */
    if (Runtime == NULL || Request == NULL || Response == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Start from a deterministic response for every failure path. */
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    Response->generation = Runtime->Generation;
    /* Validate the complete versioned request. */
    if (Request->version != KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request)) {
        /* Publish the stable invalid-request protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Answer read-only queries before any confirmation requirement. */
    if (Request->operation == KSWORD_ARK_HVM_VIEW_OP_QUERY) {
        /* Publish every installed view row. */
        for (index = 0UL;
             index < KSWORD_ARK_HVM_MAX_VIEWS &&
                rows < KSWORD_ARK_HVM_MAX_VIEWS;
             ++index) {
            /* Skip inactive records. */
            if (!Runtime->EptViews[index].Active) {
                /* Continue to the next bounded record. */
                continue;
            }
            /* Publish one complete row. */
            KswordARKHvmEptViewFillRow(
                &Runtime->EptViews[index],
                &Response->rows[rows]);
            /* Account the published row. */
            rows += 1UL;
        }
        /* Publish the number of rows written. */
        Response->returnedRows = rows;
        /* Publish the installed view count. */
        Response->viewCount = Runtime->EptViewCount;
        /* Publish the successful query. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_OK;
        /* Return the complete query answer. */
        return STATUS_SUCCESS;
    }
    /*
     * Every mutating operation redirects real memory accesses, so all of them
     * require the explicit confirmation token.
     */
    if (Request->confirmationToken !=
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN ||
        (Request->flags &
            KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED) == 0UL) {
        /* Publish the stable confirmation-required protocol status. */
        Response->status =
            KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED;
        Response->lastStatus = STATUS_ACCESS_DENIED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Honor a generation-bound request exactly as the control path does. */
    if (Request->expectedGeneration != 0UL &&
        Request->expectedGeneration != Runtime->Generation) {
        /* Publish the stable invalid-request protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_REVISION_MISMATCH;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Views need the split EPT hierarchy that preparation builds. */
    if ((Runtime->StateFlags &
            KSWORD_ARK_HVM_STATE_EPT_READY) == 0UL) {
        /* Publish the stable not-prepared protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED;
        Response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Release every installed view. */
    if (Request->operation == KSWORD_ARK_HVM_VIEW_OP_CLEAR) {
        /* Restore and release each record in turn. */
        for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
            /* Skip inactive records. */
            if (!Runtime->EptViews[index].Active) {
                /* Continue to the next bounded record. */
                continue;
            }
            /* Restore the leaf and free the shadow. */
            KswordARKHvmEptViewReleaseLocked(
                Runtime,
                &Runtime->EptViews[index]);
        }
        /* Publish the resulting count. */
        Response->viewCount = Runtime->EptViewCount;
        /* Publish the successful clear. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_OK;
        /* Return the complete clear result. */
        return STATUS_SUCCESS;
    }
    /* Release exactly one installed view. */
    if (Request->operation == KSWORD_ARK_HVM_VIEW_OP_REMOVE) {
        KSW_HVM_EPT_VIEW_SLOT* view =
            KswordARKHvmEptViewFindById(Runtime, Request->viewId);

        /* Report an unknown identifier without changing any leaf. */
        if (view == NULL) {
            /* Publish the stable not-found protocol status. */
            Response->status = KSWORD_ARK_HVM_VIEW_STATUS_NOT_FOUND;
            Response->lastStatus = STATUS_NOT_FOUND;
            /* Return the complete protocol-level rejection. */
            return STATUS_SUCCESS;
        }
        /* Restore the leaf and free the shadow. */
        KswordARKHvmEptViewReleaseLocked(Runtime, view);
        /* Publish the resulting count. */
        Response->viewCount = Runtime->EptViewCount;
        /* Publish the successful removal. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_OK;
        /* Return the complete removal result. */
        return STATUS_SUCCESS;
    }
    /* Reject every operation outside the defined vocabulary. */
    if (Request->operation != KSWORD_ARK_HVM_VIEW_OP_ADD) {
        /* Publish the stable invalid-request protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /*
     * A flip edits an EPT leaf for one instruction.  On a SHARED hierarchy
     * that window is visible to every other processor, so a view is only
     * safe on a single-processor topology - the same limit allow-once rules
     * already carry.
     *
     * hvm_ept_local.c lifts it by giving each processor its own copy of the
     * tables on the path to a flippable leaf, so the flip reaches only the
     * processor that took the exit.  The latch below is set at PREPARE time
     * from the capabilities that mechanism needs; residency additionally has
     * to be started with ENABLE_LOCAL_EPT, and a start that omits it is
     * refused while any view is installed on a multicore box.
     */
    /*
     * The EPTP-switching backend is the third way out, and it was being
     * refused here by a rule written for the other two.
     *
     * That backend never flips a leaf at run time: a violation on one of its
     * views returns from the handler having written nothing but this
     * processor's own EPT_POINTER, and the hierarchy index it selects is per
     * VCPU. There is no machine-wide window to protect against, which is why
     * the comment further down the resident start path already says a view
     * backed by it "needs no extra refusal here" - that comment described a
     * refusal that was removed, while this one stayed and kept refusing.
     *
     * The consequence was worse than a missing feature: the only backend that
     * works on a nested target was unreachable on any multicore box, and the
     * status it returned - MULTIPROCESSOR_UNSAFE - named a hazard that does
     * not apply to it. Measured 2026-09-07 on a 2 vCPU target: view-effect
     * reported "installed: false" while the backend was armed and capable.
     *
     * The predicate is the arm latch here, not the installed records, because
     * at this point the record for this view does not exist yet - the check
     * below is what decides whether it will be built with a hierarchy. The
     * resident start gate asks the records instead; see its own comment.
     */
    if (Runtime->ProcessorCount != 1UL &&
        !Runtime->LocalEptArmed &&
        !Runtime->EptpSwitchArmed) {
        /* Publish the stable multiprocessor-unsafe protocol status. */
        Response->status =
            KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE;
        Response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /*
     * Capability gate, one branch per backend.  The two do not need the same
     * controls, and conflating them is what made this look like "views need
     * the Monitor Trap Flag" - a statement that is only true of the default
     * backend.
     *
     *   write leaf + monitor-trap : INVEPT_SINGLE and MONITOR_TRAP_FLAG.
     *       The flip is bounded to one instruction by single-stepping, so the
     *       trap flag is not an optimisation - without it the leaf stays
     *       flipped forever and the shadow becomes permanent.
     *
     *   switch EPTP               : INVEPT_SINGLE only, plus the arm latch,
     *       which already proved execute-only leaves are encodable.  This
     *       backend never single-steps: it leaves the guest on a second
     *       hierarchy until an access of the opposite kind faults it back.
     *
     * INVEPT_SINGLE is common to both because either way the translations
     * built from the value being left have to be dropped.
     */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) == 0ULL ||
        (!Runtime->EptpSwitchArmed &&
         (Runtime->FeatureFlags &
             KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) == 0ULL)) {
        /* Publish the stable multiprocessor-unsafe protocol status. */
        Response->status =
            KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE;
        Response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Install the requested view. */
    status = KswordARKHvmEptViewAddLocked(
        Runtime,
        Request,
        Response);
    /* Publish the resulting count on every path. */
    Response->viewCount = Runtime->EptViewCount;
    /* Preserve the authoritative installation status. */
    Response->lastStatus = status;
    /* Return a protocol-level result successfully. */
    return STATUS_SUCCESS;
}

BOOLEAN
KswordARKHvmEptViewAllSwitchBackedLocked(
    _In_ const KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;

    /* Treat a missing runtime as "cannot prove it", never as safe. */
    if (Runtime == NULL) {
        /* Report the conservative answer. */
        return FALSE;
    }
    /* Inspect every bounded record, not just the first EptViewCount of them. */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        /* Skip records that hold no installed view. */
        if (!Runtime->EptViews[index].Active) {
            /* Continue to the next bounded record. */
            continue;
        }
        /*
         * Index zero means this view is served from the base hierarchy, and
         * that service is a leaf flip - the one thing the multicore gates
         * exist to refuse.
         */
        if (Runtime->EptViews[index].EptSwitchIndex == 0UL) {
            /* Report that at least one view would flip a shared leaf. */
            return FALSE;
        }
    }
    /* Report that no installed view flips a leaf; an empty table qualifies. */
    return TRUE;
}

VOID
KswordARKHvmEptViewResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;

    /* Restore and release every installed view before EPT pages are freed. */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        /* Skip inactive records. */
        if (!Runtime->EptViews[index].Active) {
            /* Continue to the next bounded record. */
            continue;
        }
        /* Restore the leaf and free the shadow. */
        KswordARKHvmEptViewReleaseLocked(
            Runtime,
            &Runtime->EptViews[index]);
    }
    /* Leave the table and its counters deterministic. */
    RtlZeroMemory(Runtime->EptViews, sizeof(Runtime->EptViews));
    Runtime->EptViewCount = 0UL;
}

BOOLEAN
KswordARKHvmEptViewHandleViolation(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access,
    _In_opt_ const KSW_HVM_EPT_LOCAL* Local,
    _Out_ KSW_HVM_EPT_TRANSIENT* Transient,
    _Out_ ULONG* ViewId,
    _Out_ KSW_HVM_EPT_VIEW_SWITCH* Switch
    )
{
    const ULONGLONG physicalPage =
        GuestPhysicalAddress & ~(KSW_HVM_PAGE_BYTES - 1ULL);
    KSW_HVM_EPT_VIEW_SLOT* view = NULL;
    /*
     * Declared here but assigned only after the view is known to exist.
     * Initializing it from view->Entry at the block top would dereference
     * NULL on every violation that no view covers, which is most of them.
     */
    volatile ULONGLONG* entry = NULL;

    /* Reject invalid fixed pointers in the nonblocking exit path. */
    if (Runtime == NULL ||
        Transient == NULL ||
        ViewId == NULL ||
        Switch == NULL) {
        /* Report an unhandled violation. */
        return FALSE;
    }
    /* Publish no view match before the bounded table scan. */
    *ViewId = 0UL;
    RtlZeroMemory(Switch, sizeof(*Switch));
    /* Locate the view that owns the faulting page. */
    view = KswordARKHvmEptViewFind(Runtime, physicalPage);
    /* Report that no view covers the page. */
    if (view == NULL) {
        /* Leave the violation to the rule backend. */
        return FALSE;
    }
    /* Publish the matched view identity. */
    *ViewId = view->ViewId;
    /*
     * Served by its own hierarchy: report and return without touching a leaf.
     *
     * Everything below this point - the armed-transient check, the access
     * direction check, the flip and its invalidation - exists to bound a leaf
     * write to one instruction.  This backend performs no leaf write at run
     * time, so none of it applies; the secondary value is already sitting in
     * that leaf's hierarchy and the caller only has to point the processor at
     * it.  Falling through would flip the shared leaf as well, which is both
     * unnecessary and visible to every other processor.
     *
     * The access direction is deliberately **not** checked here.  The switch
     * planner decides it from the permissions of both values, and it is the
     * one place that knows which hierarchy is currently loaded - a fact this
     * function cannot see.
     */
    if (view->EptSwitchIndex != 0UL) {
        Switch->Requested = TRUE;
        Switch->LeafSlot = view->EptSwitchIndex - 1UL;
        Switch->Kind = view->Kind;
        /* Report a handled violation with no transient armed. */
        return TRUE;
    }
    /*
     * An armed transient means a previous flip has not been restored yet.
     * Restoring and failing closed is the only safe outcome; overwriting the
     * record would lose the only way back to the primary value.
     */
    if (Transient->Armed) {
        /* Attempt restoration; failure intentionally leaves it armed. */
        (void)KswordARKHvmEptRestoreTransient(Runtime, Transient);
        /* Force fail-closed devirtualization after an overlapping flip. */
        return FALSE;
    }
    /*
     * Only the access the primary value denies belongs to the secondary one.
     * Anything else reaching here means the leaf does not match the view, so
     * failing closed is safer than flipping on an unexpected access.
     */
    if (view->Kind == KSWORD_ARK_HVM_VIEW_KIND_CLOAK) {
        /* CLOAK denies read and write; execution must never fault. */
        if ((Access &
                (KSWORD_ARK_HVM_EPT_ACCESS_READ |
                 KSWORD_ARK_HVM_EPT_ACCESS_WRITE)) == 0UL) {
            /* Report an unexpected access for this view. */
            return FALSE;
        }
    } else {
        /* HOOK denies execution; reads and writes must never fault. */
        if ((Access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL) {
            /* Report an unexpected access for this view. */
            return FALSE;
        }
    }
    /* Clear stale unarmed fields without calling vectorized helpers. */
    Transient->Reserved0[0] = 0U;
    Transient->Reserved0[1] = 0U;
    Transient->Reserved0[2] = 0U;
    /* Preserve the view identity for restoration telemetry. */
    Transient->RuleId = view->ViewId;
    /*
     * Redirect the flip to this processor's own copy of the leaf.  A view
     * whose leaf has no mirror is a build error, and flipping the shared
     * table instead would make the flip visible to every other processor -
     * the exact hazard the private hierarchy removes.
     */
    entry = view->Entry;
    if (Local != NULL) {
        entry = KswordARKHvmEptLocalTranslate(Local, entry);
        if (entry == NULL) {
            /* Require immediate fail-closed devirtualization. */
            return FALSE;
        }
    }
    /* Preserve the writable leaf. */
    Transient->Entry = entry;
    /* Restore to the steady-state value, not to the pre-install one. */
    Transient->RestrictedValue = view->PrimaryEntry;
    /* Record which hierarchy must be invalidated when this flip ends. */
    Transient->EptPointer = Local != NULL ? Local->EptPointer : 0ULL;
    /* Publish the armed recovery record before the leaf changes. */
    KeMemoryBarrier();
    Transient->Armed = TRUE;
    /* Redirect the access to the shadow for exactly one instruction. */
    *entry = view->SecondaryEntry;
    /* Order the flip before the context is invalidated. */
    KeMemoryBarrier();
    /* Drop cached translations built from the primary value. */
    if (KswordARKHvmAsmInveptSingle(
            Transient->EptPointer != 0ULL
                ? Transient->EptPointer
                : Runtime->EptPointer) != 0U) {
        /* Restore and invalidate; retain Armed if restoration also fails. */
        (void)KswordARKHvmEptRestoreTransient(Runtime, Transient);
        /* Require immediate fail-closed devirtualization. */
        return FALSE;
    }
    /* Account the completed flip. */
    InterlockedIncrement64(&view->FlipCount);
    /* Report a handled violation whose restoration monitor-trap will finish. */
    return TRUE;
}

NTSTATUS
KswordARKHvmEptViewControl(
    _In_ const KSWORD_ARK_HVM_VIEW_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_VIEW_RESPONSE* Response
    )
{
    KSW_HVM_RUNTIME* runtime = KswordARKHvmGetRuntime();
    BOOLEAN mutating = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before acquiring the lock. */
    if (Request == NULL || Response == NULL || runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Classify the request before deciding which guards apply. */
    mutating = Request->operation != KSWORD_ARK_HVM_VIEW_OP_QUERY;
    /* Serialize against every other lifecycle and EPT operation. */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&runtime->Lock);
    if (!runtime->Initialized) {
        /* Publish the fixed response identity for the rejection. */
        RtlZeroMemory(Response, sizeof(*Response));
        Response->version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        /* Publish the stable not-prepared protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED;
        Response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Select protocol-level success after writing the fixed response. */
        status = STATUS_SUCCESS;
    } else if (mutating && runtime->Busy) {
        /* Publish the fixed response identity for the rejection. */
        RtlZeroMemory(Response, sizeof(*Response));
        Response->version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        /* Reuse the resource status for a transient lifecycle conflict. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED;
        Response->lastStatus = STATUS_DEVICE_BUSY;
        /* No view, leaf or shadow was changed. */
        status = STATUS_SUCCESS;
    } else if (mutating &&
        InterlockedCompareExchange(
            &runtime->ResidentProcessorCount,
            0L,
            0L) != 0L) {
        /*
         * Resident VM exits read the view table without taking this
         * PASSIVE_LEVEL lock.  Keep the table, every leaf and every shadow
         * immutable until all VCPUs have committed their guest-stack return.
         */
        RtlZeroMemory(Response, sizeof(*Response));
        Response->version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        /* Publish the stable multiprocessor-unsafe protocol status. */
        Response->status =
            KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE;
        Response->lastStatus = STATUS_DEVICE_BUSY;
        /* No view, leaf or shadow was changed. */
        status = STATUS_SUCCESS;
    } else {
        /* Execute the bounded view operation under lifecycle ownership. */
        status = KswordARKHvmEptViewControlLocked(
            runtime,
            Request,
            Response);
    }
    /* Release exclusive lifecycle ownership. */
    ExReleasePushLockExclusive(&runtime->Lock);
    /* Leave the critical region after releasing the push lock. */
    KeLeaveCriticalRegion();
    /* Return the complete protocol operation result. */
    return status;
}

volatile UCHAR*
KswordARKHvmEptViewShadowForViewId(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG ViewId
    )
{
    ULONG index = 0UL;

    /* 拒绝不完整的调用契约与不可能命中的标识。 */
    if (Runtime == NULL || ViewId == 0UL) {
        /* 返回未命中。 */
        return NULL;
    }
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        const KSW_HVM_EPT_VIEW_SLOT* slot = &Runtime->EptViews[index];

        if (slot->Active &&
            slot->ViewId == ViewId &&
            slot->ShadowVirtual != NULL) {
            /* 返回这张视图的影子页。 */
            return (volatile UCHAR*)slot->ShadowVirtual;
        }
    }
    /* 返回未命中。 */
    return NULL;
}
