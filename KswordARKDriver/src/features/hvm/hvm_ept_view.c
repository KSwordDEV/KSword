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

    The consequence is inherited too: the leaf belongs to the shared EPT
    hierarchy, so a second resident processor could execute through the
    secondary value during the one-instruction window.  Views are therefore
    refused unless exactly one VCPU is resident.  Lifting that needs
    per-processor hierarchies, which this version does not build.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root violations.

--*/

#include "hvm_ept_view.h"

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
        /* Drop cached translations that still point at the shadow. */
        (void)KswordARKHvmAsmInveptSingle(Runtime->EptPointer);
    }
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
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an unaligned or out-of-window target before allocating. */
    if (Request->physicalAddress != physicalPage ||
        physicalPage >= KSW_HVM_MAX_MAPPED_PHYSICAL) {
        /* Publish the stable invalid-request protocol status. */
        Response->status = KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST;
        /* Return the exact parameter failure. */
        return STATUS_INVALID_PARAMETER;
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
    /* Preserve every recovery field before the leaf changes. */
    view->PhysicalAddress = physicalPage;
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
    /* Drop cached translations built from the previous leaf value. */
    (void)KswordARKHvmAsmInveptSingle(Runtime->EptPointer);
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
     * A flip edits the shared EPT leaf for one instruction.  On a second
     * processor that window is executable by someone else, so a view is only
     * safe on a single-processor topology - the same limit allow-once rules
     * already carry.  Lifting it needs per-processor EPT hierarchies.
     */
    if (Runtime->ProcessorCount != 1UL) {
        /* Publish the stable multiprocessor-unsafe protocol status. */
        Response->status =
            KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE;
        Response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Restoration after a flip depends on both of these controls. */
    if ((Runtime->FeatureFlags &
            (KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
             KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG)) !=
            (KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
             KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG)) {
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
    _Out_ KSW_HVM_EPT_TRANSIENT* Transient,
    _Out_ ULONG* ViewId
    )
{
    const ULONGLONG physicalPage =
        GuestPhysicalAddress & ~(KSW_HVM_PAGE_BYTES - 1ULL);
    KSW_HVM_EPT_VIEW_SLOT* view = NULL;

    /* Reject invalid fixed pointers in the nonblocking exit path. */
    if (Runtime == NULL ||
        Transient == NULL ||
        ViewId == NULL) {
        /* Report an unhandled violation. */
        return FALSE;
    }
    /* Publish no view match before the bounded table scan. */
    *ViewId = 0UL;
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
    /* Preserve the writable leaf. */
    Transient->Entry = view->Entry;
    /* Restore to the steady-state value, not to the pre-install one. */
    Transient->RestrictedValue = view->PrimaryEntry;
    /* Publish the armed recovery record before the leaf changes. */
    KeMemoryBarrier();
    Transient->Armed = TRUE;
    /* Redirect the access to the shadow for exactly one instruction. */
    *view->Entry = view->SecondaryEntry;
    /* Order the flip before the context is invalidated. */
    KeMemoryBarrier();
    /* Drop cached translations built from the primary value. */
    if (KswordARKHvmAsmInveptSingle(Runtime->EptPointer) != 0U) {
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
