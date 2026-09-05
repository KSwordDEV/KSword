/*++

Module Name:

    hvm_ept_domain.c

Abstract:

    Implements EPT execution domains and the EPTP list that publishes them to
    VMFUNC.  A domain is a fork of the default identity view whose permissions
    may only be narrower, never wider.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_ept_domain.h"
#include "hvm_ept.h"
#include "driver/KswordArkHvmControls.h"

/* Mark a private-table record as being the PDPT rather than a page directory. */
#define KSW_HVM_DOMAIN_PDPT_MARKER MAXULONG

/* Compose one EPT pointer from a root physical address. */
static ULONGLONG
KswordARKHvmEptDomainComposePointer(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _In_ PHYSICAL_ADDRESS RootPhysical
    )
{
    /* Encode write-back memory and the architectural four-level walk. */
    ULONGLONG pointer =
        ((ULONGLONG)RootPhysical.QuadPart & KSW_EPT_PHYSICAL_MASK) |
        6ULL |
        (3ULL << 3);

    /* Match the default view's accessed-and-dirty choice exactly. */
    if ((Runtime->FeatureFlags & KSWORD_ARK_HVM_FEATURE_EPT_AD) != 0ULL) {
        /* Set the architecturally defined EPTP accessed/dirty enable bit. */
        pointer |= (1ULL << 6);
    }
    /* Return the complete pointer for an EPTP list slot. */
    return pointer;
}

/* Find one domain's private table, or NULL when it has not forked yet. */
static KSW_HVM_DOMAIN_PRIVATE_TABLE*
KswordARKHvmEptDomainFindPrivate(
    _Inout_ KSW_HVM_EPT_DOMAIN* Domain,
    _In_ ULONG Pml4Index,
    _In_ ULONG PdptIndex
    )
{
    ULONG index = 0UL;

    /* Scan the bounded fork ledger for an exact position match. */
    for (index = 0UL; index < Domain->PrivateTableCount; ++index) {
        /* Compare both coordinates so a PDPT never matches a page directory. */
        if (Domain->PrivateTables[index].Pml4Index == Pml4Index &&
            Domain->PrivateTables[index].PdptIndex == PdptIndex) {
            /* Return the existing private table for in-place editing. */
            return &Domain->PrivateTables[index];
        }
    }
    /* Report that this position is still shared with the default view. */
    return NULL;
}

/* Fork one paging structure so this domain can diverge at that position. */
static NTSTATUS
KswordARKHvmEptDomainForkTable(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_EPT_DOMAIN* Domain,
    _In_ ULONG Pml4Index,
    _In_ ULONG PdptIndex,
    _In_ const VOID* SourceTable
    )
{
    PHYSICAL_ADDRESS physicalAddress = { 0 };
    KSW_HVM_DOMAIN_PRIVATE_TABLE* record = NULL;
    PVOID page = NULL;

    /* Reject a fork the bounded per-domain ledger cannot record. */
    if (Domain->PrivateTableCount >= KSW_HVM_MAX_DOMAIN_PRIVATE_TABLES) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Allocate one ledgered page; the allocator primes suppress-#VE. */
    page = KswordARKHvmAllocateEptPageLocked(Runtime, &physicalAddress);
    if (page == NULL) {
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * Copy the shared table wholesale.  The fork starts identical to the
     * default view by construction, which is what makes "narrower only" an
     * invariant rather than a hope: every later edit is a removal.
     */
    RtlCopyMemory(page, SourceTable, (SIZE_T)KSW_HVM_PAGE_BYTES);
    /* Record the fork so cleanup and later lookups can find it. */
    record = &Domain->PrivateTables[Domain->PrivateTableCount];
    record->Pml4Index = Pml4Index;
    record->PdptIndex = PdptIndex;
    record->Virtual = page;
    record->Physical = physicalAddress;
    Domain->PrivateTableCount += 1UL;
    /* Complete the fork successfully. */
    return STATUS_SUCCESS;
}

/* Ensure this domain owns a private page directory for one GiB window. */
static NTSTATUS
KswordARKHvmEptDomainEnsurePrivatePd(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_EPT_DOMAIN* Domain,
    _In_ ULONG Pml4Index,
    _In_ ULONG PdptIndex,
    _Outptr_ ULONGLONG** PdEntries
    )
{
    KSW_HVM_DOMAIN_PRIVATE_TABLE* record = NULL;
    ULONGLONG* pdptEntries = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Refuse positions the default view never mapped. */
    if (Pml4Index >= KSW_HVM_MAX_PML4_ENTRIES ||
        PdptIndex >= 512UL ||
        Runtime->EptPdpt[Pml4Index] == NULL ||
        Runtime->EptPd[Pml4Index][PdptIndex] == NULL ||
        Domain->Pml4Virtual == NULL) {
        /* Return the exact hierarchy-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Reuse an existing private page directory when one already exists. */
    record = KswordARKHvmEptDomainFindPrivate(Domain, Pml4Index, PdptIndex);
    if (record != NULL) {
        /* Return the previously forked page directory. */
        *PdEntries = (ULONGLONG*)record->Virtual;
        /* Complete without allocating a second copy. */
        return STATUS_SUCCESS;
    }
    /*
     * A private page directory needs a private PDPT to point at it, otherwise
     * publishing it would edit the table every other domain shares.
     */
    record = KswordARKHvmEptDomainFindPrivate(
        Domain,
        Pml4Index,
        KSW_HVM_DOMAIN_PDPT_MARKER);
    if (record == NULL) {
        /* Fork the PDPT before anything can point at a private directory. */
        status = KswordARKHvmEptDomainForkTable(
            Runtime,
            Domain,
            Pml4Index,
            KSW_HVM_DOMAIN_PDPT_MARKER,
            Runtime->EptPdpt[Pml4Index]);
        if (!NT_SUCCESS(status)) {
            /* Return before touching any published table. */
            return status;
        }
        record = KswordARKHvmEptDomainFindPrivate(
            Domain,
            Pml4Index,
            KSW_HVM_DOMAIN_PDPT_MARKER);
        if (record == NULL) {
            /* Return the exact internal-consistency failure. */
            return STATUS_INTERNAL_ERROR;
        }
        /* Point this domain's own root slot at the forked PDPT. */
        ((ULONGLONG*)Domain->Pml4Virtual)[Pml4Index] =
            ((ULONGLONG)record->Physical.QuadPart & KSW_EPT_PHYSICAL_MASK) |
            KSW_EPT_READ |
            KSW_EPT_WRITE |
            KSW_EPT_EXECUTE;
    }
    /* Bind the private PDPT that will own the forked page directory. */
    pdptEntries = (ULONGLONG*)record->Virtual;
    /* Fork the page directory that actually holds the target leaves. */
    status = KswordARKHvmEptDomainForkTable(
        Runtime,
        Domain,
        Pml4Index,
        PdptIndex,
        Runtime->EptPd[Pml4Index][PdptIndex]);
    if (!NT_SUCCESS(status)) {
        /* Return with the private PDPT retained for a later attempt. */
        return status;
    }
    record = KswordARKHvmEptDomainFindPrivate(Domain, Pml4Index, PdptIndex);
    if (record == NULL) {
        /* Return the exact internal-consistency failure. */
        return STATUS_INTERNAL_ERROR;
    }
    /* Publish the forked page directory inside this domain's PDPT only. */
    pdptEntries[PdptIndex] =
        ((ULONGLONG)record->Physical.QuadPart & KSW_EPT_PHYSICAL_MASK) |
        KSW_EPT_READ |
        KSW_EPT_WRITE |
        KSW_EPT_EXECUTE;
    /* Return the writable page directory for leaf edits. */
    *PdEntries = (ULONGLONG*)record->Virtual;
    /* Complete the copy-on-write path successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmEptDomainPrepareLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    PHYSICAL_ADDRESS physicalAddress = { 0 };
    ULONGLONG* entries = NULL;
    PVOID page = NULL;

    /* Report success when the list already exists for this runtime. */
    if (Runtime->EptpListVirtual != NULL) {
        /* Complete without allocating a second list. */
        return STATUS_SUCCESS;
    }
    /* Refuse to build a list before the default view exists. */
    if (Runtime->EptPointer == 0ULL ||
        Runtime->EptPml4 == NULL) {
        /* Return the exact ordering failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Allocate one ledgered page to hold 512 EPT pointers. */
    page = KswordARKHvmAllocateEptPageLocked(Runtime, &physicalAddress);
    if (page == NULL) {
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * Zero every slot.  A zero EPT pointer is architecturally invalid, so an
     * unused slot makes VMFUNC fail and exit rather than switch somewhere
     * unintended.  The page allocator primes EPT tables with suppress-#VE,
     * which is meaningless for a pointer list, so this zeroing is not
     * redundant with it.
     */
    RtlZeroMemory(page, (SIZE_T)KSW_HVM_PAGE_BYTES);
    entries = (ULONGLONG*)page;
    /* Publish the default view as entry zero so VMFUNC 0 always returns. */
    entries[0] = Runtime->EptPointer;
    Runtime->EptDomains[0].Active = TRUE;
    Runtime->EptDomains[0].EptPointer = Runtime->EptPointer;
    Runtime->EptDomains[0].Pml4Virtual = Runtime->EptPml4;
    Runtime->EptpListVirtual = page;
    Runtime->EptpListPhysical = physicalAddress;
    /* Publish list readiness for callers deciding whether to arm VMFUNC. */
    Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_EPTP_LIST_READY;
    /* Complete the list preparation successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmEptDomainCreateLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Out_ ULONG* DomainIndex
    )
{
    PHYSICAL_ADDRESS physicalAddress = { 0 };
    KSW_HVM_EPT_DOMAIN* domain = NULL;
    PVOID page = NULL;
    ULONG index = 0UL;
    ULONG selected = 0UL;

    /* Reject a request that cannot report which domain was created. */
    if (DomainIndex == NULL) {
        /* Return the exact contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *DomainIndex = 0UL;
    /* Refuse to fork before the list and the default view both exist. */
    if (Runtime->EptpListVirtual == NULL ||
        Runtime->EptPml4 == NULL) {
        /* Return the exact ordering failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Select the first free slot, never slot zero which is the default. */
    for (index = 1UL; index < KSW_HVM_MAX_EPT_DOMAINS; ++index) {
        if (!Runtime->EptDomains[index].Active) {
            /* Bind the free slot for this fork. */
            domain = &Runtime->EptDomains[index];
            selected = index;
            break;
        }
    }
    if (domain == NULL) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Allocate this domain's own root table. */
    page = KswordARKHvmAllocateEptPageLocked(Runtime, &physicalAddress);
    if (page == NULL) {
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * Copy the default root.  Every slot still points at the shared PDPTs, so
     * the new domain is byte-for-byte equivalent to the default view until a
     * restriction forks something.  An equivalent domain is the only safe
     * starting point, because it cannot grant anything the guest lacks.
     */
    RtlCopyMemory(page, Runtime->EptPml4, (SIZE_T)KSW_HVM_PAGE_BYTES);
    domain->Pml4Virtual = page;
    domain->Pml4Physical = physicalAddress;
    domain->PrivateTableCount = 0UL;
    domain->EptPointer =
        KswordARKHvmEptDomainComposePointer(Runtime, physicalAddress);
    domain->Active = TRUE;
    /* Publish the domain so guest VMFUNC can select it by index. */
    ((ULONGLONG*)Runtime->EptpListVirtual)[selected] = domain->EptPointer;
    *DomainIndex = selected;
    /* Complete the fork successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmEptDomainRestrictRangeLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG DomainIndex,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG ByteCount,
    _In_ ULONG DeniedAccess
    )
{
    KSW_HVM_EPT_DOMAIN* domain = NULL;
    ULONGLONG removedBits = 0ULL;
    ULONGLONG cursor = 0ULL;
    ULONGLONG end = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Refuse the default view: narrowing it would affect every domain. */
    if (DomainIndex == 0UL ||
        DomainIndex >= KSW_HVM_MAX_EPT_DOMAINS ||
        !Runtime->EptDomains[DomainIndex].Active) {
        /* Return the exact target-selection failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Refuse an empty or wrapping range before touching any table. */
    if (ByteCount == 0ULL ||
        PhysicalAddress > (MAXULONGLONG - ByteCount)) {
        /* Return the exact range-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Refuse ranges outside the window the default view actually maps. */
    if ((PhysicalAddress + ByteCount) >
            Runtime->HighestMappedPhysicalAddress) {
        /* Return the exact coverage failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Translate protocol access bits into the EPT permission bits to clear. */
    if ((DeniedAccess & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL) {
        removedBits |= KSW_EPT_READ;
    }
    if ((DeniedAccess & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
        removedBits |= KSW_EPT_WRITE;
    }
    if ((DeniedAccess & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL) {
        removedBits |= KSW_EPT_EXECUTE;
    }
    /* Refuse a request that would remove nothing. */
    if (removedBits == 0ULL) {
        /* Return the exact empty-policy failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * A leaf that denies read while keeping write or execute is
     * architecturally invalid unless the processor supports execute-only
     * translation, and an invalid leaf fails VM entry rather than the access.
     * Refuse the request instead of publishing a table that cannot launch.
     */
    if ((removedBits & KSW_EPT_READ) != 0ULL &&
        (Runtime->VmxEptVpidCapabilities &
            KSW_EPT_CAP_EXECUTE_ONLY) == 0ULL) {
        /* Return the exact unsupported-permission failure. */
        return STATUS_NOT_SUPPORTED;
    }
    domain = &Runtime->EptDomains[DomainIndex];
    /*
     * Walk whole two-MiB leaves so no partial leaf is ever left edited.  The
     * index arithmetic lives in KswordArkHvmControls.h so the host unit tests
     * exercise the same code the driver runs: getting it wrong does not fault,
     * it silently narrows an unrelated region.
     */
    cursor = KswordArkHvmEptLeafBase(PhysicalAddress);
    end = PhysicalAddress + ByteCount;
    while (cursor < end) {
        const ULONG pml4Index = KswordArkHvmEptPml4Index(cursor);
        const ULONG pdptIndex = KswordArkHvmEptPdptIndex(cursor);
        const ULONG pdIndex = KswordArkHvmEptPdIndex(cursor);
        ULONGLONG* pdEntries = NULL;

        /* Fork whatever this position still shares with the default view. */
        status = KswordARKHvmEptDomainEnsurePrivatePd(
            Runtime,
            domain,
            pml4Index,
            pdptIndex,
            &pdEntries);
        if (!NT_SUCCESS(status)) {
            /* Return with earlier leaves narrowed; the caller resets. */
            return status;
        }
        /*
         * Remove permissions only; this is what keeps a domain a subset.  The
         * helper cannot express "grant", so it cannot be called wrongly.
         */
        pdEntries[pdIndex] = KswordArkHvmEptApplyRestriction(
            pdEntries[pdIndex],
            removedBits);
        /* Advance to the next whole two-MiB leaf. */
        cursor += KSW_HVM_LARGE_PAGE_BYTES;
    }
    /* Complete the narrowing successfully. */
    return STATUS_SUCCESS;
}

VOID
KswordARKHvmEptDomainResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;

    /*
     * Unpublish before forgetting.  Every list slot is reachable by one guest
     * instruction, so a slot must stop naming a domain before that domain's
     * pages can be reused for anything else.
     */
    if (Runtime->EptpListVirtual != NULL) {
        RtlZeroMemory(
            Runtime->EptpListVirtual,
            (SIZE_T)KSW_HVM_PAGE_BYTES);
    }
    /*
     * Forget every domain.  The pages themselves belong to the shared EPT
     * allocation ledger and are freed with it, so this clears references
     * rather than memory; releasing them here would double-free.
     */
    for (index = 0UL; index < KSW_HVM_MAX_EPT_DOMAINS; ++index) {
        RtlZeroMemory(
            &Runtime->EptDomains[index],
            sizeof(Runtime->EptDomains[index]));
    }
    Runtime->EptpListVirtual = NULL;
    Runtime->EptpListPhysical.QuadPart = 0LL;
    /* Withdraw the readiness claim along with the list. */
    Runtime->FeatureFlags &= ~KSWORD_ARK_HVM_FEATURE_EPTP_LIST_READY;
}

/* Publish one domain slot as a protocol row. */
static VOID
KswordARKHvmEptDomainFillRow(
    _In_ const KSW_HVM_EPT_DOMAIN* Domain,
    _In_ ULONG DomainIndex,
    _Out_ KSWORD_ARK_HVM_DOMAIN_ROW* Row
    )
{
    /* Start from a deterministic row for every field. */
    RtlZeroMemory(Row, sizeof(*Row));
    /* Publish the index guest code would name in a VMFUNC. */
    Row->domainIndex = DomainIndex;
    /* Publish whether this slot currently holds a live domain. */
    Row->active = Domain->Active ? 1UL : 0UL;
    /* Publish how far this domain diverged from the shared hierarchy. */
    Row->privateTableCount = Domain->PrivateTableCount;
    /* Publish the pointer actually written into the list slot. */
    Row->eptPointer = Domain->EptPointer;
}

/* Execute one validated domain request with the runtime lock already held. */
static NTSTATUS
KswordARKHvmEptDomainControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_DOMAIN_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_DOMAIN_RESPONSE* Response
    )
{
    ULONG domainIndex = 0UL;
    ULONG index = 0UL;
    ULONG rows = 0UL;
    ULONG active = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before touching any state. */
    if (Runtime == NULL || Request == NULL || Response == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Start from a deterministic response for every failure path. */
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    Response->generation = Runtime->Generation;
    Response->featureFlags = Runtime->FeatureFlags;
    Response->stateFlags = Runtime->StateFlags;
    /* Validate the complete versioned request. */
    if (Request->version != KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request)) {
        /* Publish the stable invalid-request protocol status. */
        Response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Count live domains once for every operation that reports them. */
    for (index = 0UL; index < KSW_HVM_MAX_EPT_DOMAINS; ++index) {
        if (Runtime->EptDomains[index].Active) {
            /* Account one live domain. */
            active += 1UL;
        }
    }
    /* Answer read-only queries before any confirmation requirement. */
    if (Request->operation == KSWORD_ARK_HVM_DOMAIN_OP_QUERY) {
        /* Publish every slot, live or not, so gaps stay visible. */
        for (index = 0UL;
             index < KSW_HVM_MAX_EPT_DOMAINS &&
                rows < KSWORD_ARK_HVM_MAX_DOMAIN_ROWS;
             ++index) {
            /* Publish one complete row. */
            KswordARKHvmEptDomainFillRow(
                &Runtime->EptDomains[index],
                index,
                &Response->rows[rows]);
            /* Account the published row. */
            rows += 1UL;
        }
        /* Publish the number of rows written. */
        Response->returnedRows = rows;
        /* Publish the live domain count. */
        Response->domainCount = active;
        /* Publish the successful query. */
        Response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_OK;
        /* Return the complete query answer. */
        return STATUS_SUCCESS;
    }
    /*
     * Every mutating operation edits tables that guest code can reach with a
     * single instruction, so all of them require the confirmation token.
     */
    if (Request->confirmationToken !=
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN ||
        (Request->flags &
            KSWORD_ARK_HVM_DOMAIN_FLAG_UI_CONFIRMED) == 0UL) {
        /* Publish the stable confirmation-required protocol status. */
        Response->status =
            KSWORD_ARK_HVM_DOMAIN_STATUS_CONFIRMATION_REQUIRED;
        Response->lastStatus = STATUS_ACCESS_DENIED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Honor a generation-bound request exactly as the control path does. */
    if (Request->expectedGeneration != 0UL &&
        Request->expectedGeneration != Runtime->Generation) {
        /* Publish the stable invalid-request protocol status. */
        Response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_REVISION_MISMATCH;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Refuse every mutation on a processor that cannot switch pointers. */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_EPTP_SWITCHING) == 0ULL) {
        /* Publish the stable unsupported protocol status. */
        Response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_UNSUPPORTED;
        Response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Refuse mutation before the list that publishes domains exists. */
    if (Runtime->EptpListVirtual == NULL) {
        /* Publish the stable not-prepared protocol status. */
        Response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_PREPARED;
        Response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Dispatch the exact requested mutation. */
    if (Request->operation == KSWORD_ARK_HVM_DOMAIN_OP_CREATE) {
        /* Fork one domain equivalent to the default view. */
        status = KswordARKHvmEptDomainCreateLocked(
            Runtime,
            &domainIndex);
        /* Publish the created index for the caller to restrict later. */
        Response->domainIndex = domainIndex;
        /* Translate the exact backend failure into a protocol status. */
        Response->status = NT_SUCCESS(status)
            ? KSWORD_ARK_HVM_DOMAIN_STATUS_OK
            : (status == STATUS_INSUFFICIENT_RESOURCES
                ? KSWORD_ARK_HVM_DOMAIN_STATUS_TABLE_FULL
                : KSWORD_ARK_HVM_DOMAIN_STATUS_RESOURCE_FAILED);
    } else if (Request->operation == KSWORD_ARK_HVM_DOMAIN_OP_RESTRICT) {
        /* Remove the requested permissions from the named domain. */
        status = KswordARKHvmEptDomainRestrictRangeLocked(
            Runtime,
            Request->domainIndex,
            Request->physicalAddress,
            Request->byteCount,
            Request->deniedAccess);
        /* Echo the target so a caller can correlate the answer. */
        Response->domainIndex = Request->domainIndex;
        /* Translate the exact backend failure into a protocol status. */
        if (NT_SUCCESS(status)) {
            Response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_OK;
        } else if (status == STATUS_NOT_SUPPORTED) {
            Response->status =
                KSWORD_ARK_HVM_DOMAIN_STATUS_EXECUTE_ONLY_UNSUPPORTED;
        } else if (status == STATUS_INVALID_PARAMETER) {
            Response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_FOUND;
        } else if (status == STATUS_INSUFFICIENT_RESOURCES) {
            Response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_TABLE_FULL;
        } else {
            Response->status =
                KSWORD_ARK_HVM_DOMAIN_STATUS_RESOURCE_FAILED;
        }
    } else if (Request->operation == KSWORD_ARK_HVM_DOMAIN_OP_RESET) {
        /*
         * Reset drops the list too, so rebuild it immediately.  A runtime
         * holding a default view but no list would report EPTP_LIST_READY as
         * false and refuse a later start that asked for VMFUNC.
         */
        KswordARKHvmEptDomainResetLocked(Runtime);
        status = KswordARKHvmEptDomainPrepareLocked(Runtime);
        Response->status = NT_SUCCESS(status)
            ? KSWORD_ARK_HVM_DOMAIN_STATUS_OK
            : KSWORD_ARK_HVM_DOMAIN_STATUS_RESOURCE_FAILED;
    } else {
        /* Publish the stable invalid-request protocol status. */
        Response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_INVALID_REQUEST;
        status = STATUS_INVALID_PARAMETER;
    }
    /* Publish the authoritative backend result alongside the status. */
    Response->lastStatus = status;
    /* Recount and republish so the caller sees the post-operation shape. */
    active = 0UL;
    rows = 0UL;
    for (index = 0UL;
         index < KSW_HVM_MAX_EPT_DOMAINS &&
            rows < KSWORD_ARK_HVM_MAX_DOMAIN_ROWS;
         ++index) {
        if (Runtime->EptDomains[index].Active) {
            /* Account one live domain. */
            active += 1UL;
        }
        /* Publish one complete row. */
        KswordARKHvmEptDomainFillRow(
            &Runtime->EptDomains[index],
            index,
            &Response->rows[rows]);
        /* Account the published row. */
        rows += 1UL;
    }
    Response->returnedRows = rows;
    Response->domainCount = active;
    Response->featureFlags = Runtime->FeatureFlags;
    /* Report protocol-level success; the detail lives in the response. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmEptDomainControl(
    _In_ const KSWORD_ARK_HVM_DOMAIN_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_DOMAIN_RESPONSE* Response
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
    mutating = Request->operation != KSWORD_ARK_HVM_DOMAIN_OP_QUERY;
    /* Serialize against every other lifecycle and EPT operation. */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&runtime->Lock);
    if (!runtime->Initialized) {
        /* Publish the fixed response identity for the rejection. */
        RtlZeroMemory(Response, sizeof(*Response));
        Response->version = KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        /* Publish the stable not-prepared protocol status. */
        Response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_PREPARED;
        Response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Select protocol-level success after writing the fixed response. */
        status = STATUS_SUCCESS;
    } else if (mutating && runtime->Busy) {
        /* Publish the fixed response identity for the rejection. */
        RtlZeroMemory(Response, sizeof(*Response));
        Response->version = KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        /* Reuse the resource status for a transient lifecycle conflict. */
        Response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_RESOURCE_FAILED;
        Response->lastStatus = STATUS_DEVICE_BUSY;
        /* No domain, table or list slot was changed. */
        status = STATUS_SUCCESS;
    } else if (mutating &&
        InterlockedCompareExchange(
            &runtime->ResidentProcessorCount,
            0L,
            0L) != 0L) {
        /*
         * A resident processor may be executing inside one of these tables
         * right now, and guest code can switch between them without exiting.
         * Editing a live domain would change translations under a running
         * VCPU with no coherent way to invalidate, so refuse instead.
         */
        RtlZeroMemory(Response, sizeof(*Response));
        Response->version = KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        /* Publish the stable resident-active protocol status. */
        Response->status = KSWORD_ARK_HVM_DOMAIN_STATUS_RESIDENT_ACTIVE;
        Response->lastStatus = STATUS_DEVICE_BUSY;
        /* No domain, table or list slot was changed. */
        status = STATUS_SUCCESS;
    } else {
        /* Execute the bounded domain operation under lifecycle ownership. */
        status = KswordARKHvmEptDomainControlLocked(
            runtime,
            Request,
            Response);
    }
    ExReleasePushLockExclusive(&runtime->Lock);
    KeLeaveCriticalRegion();
    /* Return the complete domain operation result. */
    return status;
}
