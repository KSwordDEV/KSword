/*++

Module Name:

    kernel_object_type_table.c

Abstract:

    Enumerates the live ObTypeIndexTable as read-only R0 evidence. The table is
    recovered from bounded references rooted at Object Manager exports and is
    accepted only when several exported POBJECT_TYPE identities agree with the
    table slots. Optional DynData offsets add name and index cross-validation.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL read-only query path.

--*/

#include "kernel_object_type_table.h"
#include "driver_integrity.h"
#include "hook_scan_support.h"
#include "kernel_image_section_map.h"
#include "ark/ark_dyndata.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"
#include "../../platform/runtime_signature_scan.h"

#define KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE) - \
        sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY))
#define KSW_OBJECT_TYPE_MAX_REFERENCES 96UL
#define KSW_OBJECT_TYPE_SCAN_BYTES 0x500UL
#define KSW_OBJECT_TYPE_MAX_CALL_DEPTH 2UL
#define KSW_OBJECT_TYPE_MAX_STRUCT_OFFSET 0x1000UL
#define KSW_OBJECT_TYPE_FNV_OFFSET_BASIS 1469598103934665603ULL
#define KSW_OBJECT_TYPE_FNV_PRIME 1099511628211ULL
#define KSW_OBJECT_TYPE_NAME_POOL_TAG 'nTsK'
#define KSW_OBJECT_TYPE_WORKSPACE_POOL_TAG 'wOsK'

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

extern POBJECT_TYPE* PsProcessType;
extern POBJECT_TYPE* PsThreadType;
extern POBJECT_TYPE* IoDriverObjectType;
extern POBJECT_TYPE* IoFileObjectType;

NTKERNELAPI
NTSTATUS
ObQueryNameString(
    _In_ PVOID Object,
    _Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
    _In_ ULONG Length,
    _Out_ PULONG ReturnLength
    );

typedef struct _KSW_OBJECT_TYPE_TABLE_CANDIDATE
{
    ULONG_PTR Address;
    ULONG KnownMatchCount;
    ULONG NonNullCount;
    BOOLEAN Valid;
} KSW_OBJECT_TYPE_TABLE_CANDIDATE, *PKSW_OBJECT_TYPE_TABLE_CANDIDATE;

/*
 * DynData state, the parsed PE view, and signature references are all sizable.
 * They are live together while the nested scanner runs, so keep the complete
 * query workspace in bounded nonpaged pool instead of the kernel stack.
 */
typedef struct _KSW_OBJECT_TYPE_WORKSPACE
{
    KSW_DYN_STATE DynState;
    KSW_RUNTIME_IMAGE_VIEW NtosView;
    KSW_RUNTIME_DATA_REFERENCE References[KSW_OBJECT_TYPE_MAX_REFERENCES];
} KSW_OBJECT_TYPE_WORKSPACE, *PKSW_OBJECT_TYPE_WORKSPACE;

static BOOLEAN
KswordARKObjectTypeIsKernelPointer(
    _In_ ULONG_PTR Address
    )
/*++

Routine Description:

    Validates one aligned canonical kernel pointer.

Return Value:

    TRUE only for system-range aligned addresses.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (Address >> 48U) == 0xFFFFU &&
        (Address & (sizeof(PVOID) - 1U)) == 0U;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (Address & (sizeof(PVOID) - 1U)) == 0U;
#endif
}

static BOOLEAN
KswordARKObjectTypeOffsetPresent(
    _In_ ULONG Offset
    )
/*++

Routine Description:

    Rejects missing or implausibly large private structure offsets.

Return Value:

    TRUE for a bounded non-sentinel offset.

--*/
{
    return Offset != 0UL && Offset != 0xFFFFFFFFUL &&
        Offset < KSW_OBJECT_TYPE_MAX_STRUCT_OFFSET;
}

static ULONG64
KswordARKObjectTypeHashBytes(
    _In_ ULONG64 Hash,
    _In_reads_bytes_(ByteCount) const VOID* Data,
    _In_ SIZE_T ByteCount
    )
/*++

Routine Description:

    Extends a deterministic FNV-1a snapshot or row identity.

Return Value:

    Updated 64-bit hash.

--*/
{
    const UCHAR* bytes = (const UCHAR*)Data;
    SIZE_T index = 0U;

    for (index = 0U; index < ByteCount; ++index) {
        Hash ^= bytes[index];
        Hash *= KSW_OBJECT_TYPE_FNV_PRIME;
    }
    return Hash;
}

static BOOLEAN
KswordARKObjectTypeReadPointerSlot(
    _In_ ULONG_PTR TableAddress,
    _In_ ULONG SlotIndex,
    _Out_ ULONG_PTR* ObjectTypeAddressOut
    )
/*++

Routine Description:

    Reads one fixed ObTypeIndexTable pointer without dereferencing the object.

Return Value:

    TRUE when the slot was readable.

--*/
{
    if (ObjectTypeAddressOut == NULL ||
        SlotIndex >= KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS) {
        return FALSE;
    }
    *ObjectTypeAddressOut = 0U;
    return KswordARKRuntimeReadMemory(
        (const VOID*)(TableAddress + ((ULONG_PTR)SlotIndex * sizeof(PVOID))),
        ObjectTypeAddressOut,
        sizeof(*ObjectTypeAddressOut));
}

static ULONG
KswordARKObjectTypeKnownPointers(
    _Out_writes_(Capacity) ULONG_PTR* Pointers,
    _In_ ULONG Capacity
    )
/*++

Routine Description:

    Captures exported Object Manager type identities used only to authenticate
    a candidate table.

Return Value:

    Number of distinct non-null known POBJECT_TYPE values.

--*/
{
    POBJECT_TYPE* sources[] = {
        PsProcessType,
        PsThreadType,
        IoDriverObjectType,
        IoFileObjectType
    };
    ULONG sourceIndex = 0UL;
    ULONG count = 0UL;

    if (Pointers == NULL || Capacity == 0UL) {
        return 0UL;
    }
    for (sourceIndex = 0UL; sourceIndex < RTL_NUMBER_OF(sources); ++sourceIndex) {
        ULONG_PTR value = 0U;
        ULONG existingIndex = 0UL;
        BOOLEAN duplicate = FALSE;

        if (sources[sourceIndex] == NULL ||
            !KswordARKRuntimeReadMemory(
                sources[sourceIndex],
                &value,
                sizeof(value)) ||
            !KswordARKObjectTypeIsKernelPointer(value)) {
            continue;
        }
        for (existingIndex = 0UL; existingIndex < count; ++existingIndex) {
            if (Pointers[existingIndex] == value) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate && count < Capacity) {
            Pointers[count] = value;
            count += 1UL;
        }
    }
    return count;
}

static BOOLEAN
KswordARKObjectTypeValidateCandidate(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* NtosView,
    _In_ ULONG_PTR CandidateAddress,
    _In_reads_(KnownCount) const ULONG_PTR* KnownPointers,
    _In_ ULONG KnownCount,
    _Out_ KSW_OBJECT_TYPE_TABLE_CANDIDATE* CandidateOut
    )
/*++

Routine Description:

    Requires a complete writable 256-slot array, canonical non-null entries,
    and at least three exported type identities present in the same table.

Return Value:

    TRUE only for a strongly authenticated table candidate.

--*/
{
    ULONG slot = 0UL;
    ULONG knownIndex = 0UL;
    ULONG knownMatches = 0UL;
    ULONG nonNullCount = 0UL;
    BOOLEAN knownSeen[4];

    if (CandidateOut == NULL || KnownPointers == NULL || KnownCount < 3UL ||
        KnownCount > RTL_NUMBER_OF(knownSeen) ||
        !KswordARKRuntimeAddressIsWritableData(
            NtosView,
            CandidateAddress,
            KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS * sizeof(PVOID))) {
        return FALSE;
    }
    RtlZeroMemory(knownSeen, sizeof(knownSeen));
    for (slot = 0UL; slot < KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS; ++slot) {
        ULONG_PTR objectTypeAddress = 0U;

        if (!KswordARKObjectTypeReadPointerSlot(
                CandidateAddress,
                slot,
                &objectTypeAddress)) {
            return FALSE;
        }
        if (objectTypeAddress == 0U) {
            continue;
        }
        if (!KswordARKObjectTypeIsKernelPointer(objectTypeAddress)) {
            return FALSE;
        }
        nonNullCount += 1UL;
        for (knownIndex = 0UL; knownIndex < KnownCount; ++knownIndex) {
            if (!knownSeen[knownIndex] &&
                KnownPointers[knownIndex] == objectTypeAddress) {
                knownSeen[knownIndex] = TRUE;
                knownMatches += 1UL;
            }
        }
    }
    if (knownMatches < 3UL || nonNullCount < knownMatches) {
        return FALSE;
    }
    CandidateOut->Address = CandidateAddress;
    CandidateOut->KnownMatchCount = knownMatches;
    CandidateOut->NonNullCount = nonNullCount;
    CandidateOut->Valid = TRUE;
    return TRUE;
}

static NTSTATUS
KswordARKObjectTypeLocateTable(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* NtosView,
    _Out_writes_(ReferenceCapacity) KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG ReferenceCapacity,
    _Out_ ULONG_PTR* TableAddressOut
    )
/*++

Routine Description:

    Locates ObTypeIndexTable from bounded RIP-relative references rooted at
    Object Manager exports and rejects tied strongest candidates.

Return Value:

    STATUS_SUCCESS for one unique table, STATUS_OBJECT_NAME_COLLISION for an
    ambiguity, or STATUS_NOT_FOUND when no candidate validates.

--*/
{
    static PCSTR const anchors[] = {
        "ObGetObjectType",
        "ObReferenceObjectByHandle",
        "ObOpenObjectByPointer"
    };
    ULONG_PTR knownPointers[4];
    ULONG knownCount = 0UL;
    ULONG referenceCount = 0UL;
    ULONG referenceIndex = 0UL;
    KSW_OBJECT_TYPE_TABLE_CANDIDATE best;
    BOOLEAN ambiguous = FALSE;

    if (NtosView == NULL || References == NULL || ReferenceCapacity == 0UL ||
        ReferenceCapacity > KSW_OBJECT_TYPE_MAX_REFERENCES ||
        TableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *TableAddressOut = 0U;
    RtlZeroMemory(
        References,
        (SIZE_T)ReferenceCapacity * sizeof(*References));
    RtlZeroMemory(knownPointers, sizeof(knownPointers));
    RtlZeroMemory(&best, sizeof(best));
    knownCount = KswordARKObjectTypeKnownPointers(
        knownPointers,
        RTL_NUMBER_OF(knownPointers));
    if (knownCount < 3UL) {
        return STATUS_NOT_SUPPORTED;
    }
    referenceCount = KswordARKRuntimeCollectAnchoredDataReferences(
        NtosView,
        anchors,
        RTL_NUMBER_OF(anchors),
        KSW_OBJECT_TYPE_MAX_CALL_DEPTH,
        KSW_OBJECT_TYPE_SCAN_BYTES,
        References,
        ReferenceCapacity);
    for (referenceIndex = 0UL; referenceIndex < referenceCount; ++referenceIndex) {
        KSW_OBJECT_TYPE_TABLE_CANDIDATE candidate;

        RtlZeroMemory(&candidate, sizeof(candidate));
        if (!KswordARKObjectTypeValidateCandidate(
                NtosView,
                References[referenceIndex].Address,
                knownPointers,
                knownCount,
                &candidate)) {
            continue;
        }
        if (!best.Valid ||
            candidate.KnownMatchCount > best.KnownMatchCount) {
            best = candidate;
            ambiguous = FALSE;
        }
        else if (candidate.KnownMatchCount == best.KnownMatchCount &&
            candidate.Address != best.Address) {
            ambiguous = TRUE;
        }
    }
    if (!best.Valid) {
        return STATUS_NOT_FOUND;
    }
    if (ambiguous) {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    *TableAddressOut = best.Address;
    return STATUS_SUCCESS;
}

static BOOLEAN
KswordARKObjectTypeReadName(
    _In_ ULONG_PTR ObjectTypeAddress,
    _In_ ULONG NameOffset,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars
    )
/*++

Routine Description:

    Copies a DynData-gated _OBJECT_TYPE.Name into a fixed response buffer.

Return Value:

    TRUE only when the UNICODE_STRING and complete bounded payload are valid.

--*/
{
    UNICODE_STRING name;
    USHORT copyBytes = 0U;

    if (Destination == NULL || DestinationChars < 2UL ||
        !KswordARKObjectTypeOffsetPresent(NameOffset)) {
        return FALSE;
    }
    RtlZeroMemory(Destination, (SIZE_T)DestinationChars * sizeof(WCHAR));
    RtlZeroMemory(&name, sizeof(name));
    if (!KswordARKRuntimeReadMemory(
            (const VOID*)(ObjectTypeAddress + NameOffset),
            &name,
            sizeof(name)) ||
        name.Buffer == NULL || name.Length == 0U ||
        name.Length > name.MaximumLength ||
        (name.Length & (sizeof(WCHAR) - 1U)) != 0U ||
        !KswordARKObjectTypeIsKernelPointer((ULONG_PTR)name.Buffer)) {
        return FALSE;
    }
    copyBytes = (USHORT)min(
        name.Length,
        (USHORT)((DestinationChars - 1UL) * sizeof(WCHAR)));
    if (!KswordARKRuntimeReadMemory(name.Buffer, Destination, copyBytes)) {
        RtlZeroMemory(Destination, (SIZE_T)DestinationChars * sizeof(WCHAR));
        return FALSE;
    }
    Destination[copyBytes / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

static BOOLEAN
KswordARKObjectTypeReadNamespaceName(
    _In_ ULONG_PTR ObjectTypeAddress,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars
    )
/*++

Routine Description:

    Query the Object Manager name of an OBJECT_TYPE object and retain the last
    path component (for example, "Process" from "\ObjectTypes\Process").
    This provides names without the private _OBJECT_TYPE.Name member offset.

Return Value:

    TRUE only when a complete bounded name was copied.

--*/
{
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG requiredBytes = 0UL;
    ULONG allocationBytes = 0UL;
    ULONG sourceChars = 0UL;
    ULONG startChar = 0UL;
    ULONG copyChars = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (ObjectTypeAddress == 0U || Destination == NULL ||
        DestinationChars < 2UL) {
        return FALSE;
    }
    RtlZeroMemory(Destination, (SIZE_T)DestinationChars * sizeof(WCHAR));
    status = ObQueryNameString(
        (PVOID)ObjectTypeAddress,
        NULL,
        0UL,
        &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH &&
        status != STATUS_BUFFER_TOO_SMALL &&
        status != STATUS_BUFFER_OVERFLOW) {
        return FALSE;
    }
    allocationBytes = max(
        requiredBytes,
        (ULONG)(sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR)));
    if (allocationBytes > 64UL * 1024UL) {
        return FALSE;
    }
    nameInfo = (POBJECT_NAME_INFORMATION)KswordARKAllocateNonPagedPool(
        allocationBytes,
        KSW_OBJECT_TYPE_NAME_POOL_TAG);
    if (nameInfo == NULL) {
        return FALSE;
    }
    RtlZeroMemory(nameInfo, allocationBytes);
    status = ObQueryNameString(
        (PVOID)ObjectTypeAddress,
        nameInfo,
        allocationBytes,
        &requiredBytes);
    if (NT_SUCCESS(status) && nameInfo->Name.Buffer != NULL &&
        nameInfo->Name.Length != 0U &&
        nameInfo->Name.Length <= nameInfo->Name.MaximumLength &&
        (nameInfo->Name.Length & (sizeof(WCHAR) - 1U)) == 0U) {
        sourceChars = nameInfo->Name.Length / sizeof(WCHAR);
        for (index = 0UL; index < sourceChars; ++index) {
            if (nameInfo->Name.Buffer[index] == L'\\') {
                startChar = index + 1UL;
            }
        }
        if (startChar < sourceChars) {
            copyChars = min(sourceChars - startChar, DestinationChars - 1UL);
            RtlCopyMemory(
                Destination,
                &nameInfo->Name.Buffer[startChar],
                (SIZE_T)copyChars * sizeof(WCHAR));
            Destination[copyChars] = L'\0';
        }
    }
    ExFreePoolWithTag(nameInfo, KSW_OBJECT_TYPE_NAME_POOL_TAG);
    return copyChars != 0UL;
}

static BOOLEAN
KswordARKObjectTypeReadIndex(
    _In_ ULONG_PTR ObjectTypeAddress,
    _In_ ULONG IndexOffset,
    _Out_ UCHAR* TypeIndexOut
    )
/*++

Routine Description:

    Reads the DynData-gated _OBJECT_TYPE.Index byte.

Return Value:

    TRUE when the member is available and readable.

--*/
{
    if (TypeIndexOut == NULL ||
        !KswordARKObjectTypeOffsetPresent(IndexOffset)) {
        return FALSE;
    }
    *TypeIndexOut = 0U;
    return KswordARKRuntimeReadMemory(
        (const VOID*)(ObjectTypeAddress + IndexOffset),
        TypeIndexOut,
        sizeof(*TypeIndexOut));
}

static BOOLEAN
KswordARKObjectTypeIsKnown(
    _In_ ULONG_PTR ObjectTypeAddress
    )
/*++

Routine Description:

    Compares one row against exported process/thread/driver/file type objects.

Return Value:

    TRUE for an exported known identity.

--*/
{
    ULONG_PTR knownPointers[4];
    ULONG knownCount = 0UL;
    ULONG index = 0UL;

    RtlZeroMemory(knownPointers, sizeof(knownPointers));
    knownCount = KswordARKObjectTypeKnownPointers(
        knownPointers,
        RTL_NUMBER_OF(knownPointers));
    for (index = 0UL; index < knownCount; ++index) {
        if (knownPointers[index] == ObjectTypeAddress) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS
KswordARKObjectTypeBuildResponse(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Builds one paged, read-only Object Type Table response.

Return Value:

    STATUS_SUCCESS for a semantic response; malformed buffers return an error.

--*/
{
    KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE* response =
        (KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE*)OutputBuffer;
    KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY* rows = NULL;
    KSW_OBJECT_TYPE_WORKSPACE* workspace = NULL;
    KSW_DYN_STATE* dynState = NULL;
    KSW_RUNTIME_IMAGE_VIEW* ntosView = NULL;
    ULONG_PTR tableAddress = 0U;
    NTSTATUS locateStatus = STATUS_SUCCESS;
    ULONG capacity = 0UL;
    ULONG requestedMax = 0UL;
    ULONG startIndex = 0UL;
    ULONG slot = 0UL;
    ULONG nextIndex = KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS;
    BOOLEAN dynName = FALSE;
    BOOLEAN dynIndex = FALSE;
    BOOLEAN partial = FALSE;
    ULONG64 snapshotHash = KSW_OBJECT_TYPE_FNV_OFFSET_BASIS;

    if (OutputBuffer == NULL || Request == NULL || BytesWrittenOut == NULL ||
        OutputBufferLength < KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *BytesWrittenOut = 0U;
    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response->version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY);
    response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_UNAVAILABLE;
    response->nextIndex = KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS;

    workspace = (KSW_OBJECT_TYPE_WORKSPACE*)KswordARKAllocateNonPagedPool(
        sizeof(*workspace),
        KSW_OBJECT_TYPE_WORKSPACE_POOL_TAG);
    if (workspace == NULL) {
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        *BytesWrittenOut = KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(workspace, sizeof(*workspace));
    dynState = &workspace->DynState;
    ntosView = &workspace->NtosView;

    capacity = (ULONG)((OutputBufferLength - KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY));
    requestedMax = Request->maxEntries == 0UL
        ? KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS
        : min(Request->maxEntries, KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS);
    capacity = min(capacity, requestedMax);
    startIndex = min(Request->startIndex, KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS);
    rows = response->entries;

    KswordARKDynDataSnapshot(dynState);
    response->dynDataCapabilityMask = dynState->CapabilityMask;
    response->otNameOffset = dynState->Kernel.OtName;
    response->otIndexOffset = dynState->Kernel.OtIndex;
    dynName = KswordARKObjectTypeOffsetPresent(dynState->Kernel.OtName);
    dynIndex = KswordARKObjectTypeOffsetPresent(dynState->Kernel.OtIndex);
    if (dynName || dynIndex) {
        response->flags |=
            KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_DYNDATA_ACTIVE;
    }
    if (dynState->Ntoskrnl.present == 0UL ||
        !KswordARKRuntimeInitializeImageView(
            (PVOID)(ULONG_PTR)dynState->Ntoskrnl.imageBase,
            dynState->Ntoskrnl.sizeOfImage,
            ntosView)) {
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_TABLE_NOT_FOUND;
        response->lastStatus = STATUS_NOT_SUPPORTED;
        *BytesWrittenOut = KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE;
        ExFreePoolWithTag(workspace, KSW_OBJECT_TYPE_WORKSPACE_POOL_TAG);
        workspace = NULL;
        return STATUS_SUCCESS;
    }
    locateStatus = KswordARKObjectTypeLocateTable(
        ntosView,
        workspace->References,
        RTL_NUMBER_OF(workspace->References),
        &tableAddress);
    if (!NT_SUCCESS(locateStatus)) {
        response->status = (locateStatus == STATUS_OBJECT_NAME_COLLISION)
            ? KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_TABLE_AMBIGUOUS
            : KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_TABLE_NOT_FOUND;
        response->lastStatus = locateStatus;
        *BytesWrittenOut = KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE;
        ExFreePoolWithTag(workspace, KSW_OBJECT_TYPE_WORKSPACE_POOL_TAG);
        workspace = NULL;
        return STATUS_SUCCESS;
    }
    response->tableAddress = (ULONG64)tableAddress;
    response->flags |=
        KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_TABLE_VALIDATED;

    for (slot = 0UL; slot < KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS; ++slot) {
        ULONG_PTR objectTypeAddress = 0U;

        if (!KswordARKObjectTypeReadPointerSlot(
                tableAddress,
                slot,
                &objectTypeAddress)) {
            partial = TRUE;
            continue;
        }
        if (objectTypeAddress == 0U) {
            continue;
        }
        response->totalCount += 1UL;
        snapshotHash = KswordARKObjectTypeHashBytes(
            snapshotHash,
            &slot,
            sizeof(slot));
        snapshotHash = KswordARKObjectTypeHashBytes(
            snapshotHash,
            &objectTypeAddress,
            sizeof(objectTypeAddress));
        if (slot < startIndex || response->returnedCount >= capacity) {
            if (slot >= startIndex && nextIndex == KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS) {
                nextIndex = slot;
            }
            continue;
        }
        {
            KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY* entry =
                &rows[response->returnedCount];
            UCHAR observedIndex = 0U;
            BOOLEAN nameRead = FALSE;
            BOOLEAN indexRead = FALSE;

            entry->size = sizeof(*entry);
            entry->typeIndex = slot;
            entry->status = KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_OK;
            entry->fieldFlags = KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_ADDRESS;
            entry->objectTypeAddress = (ULONG64)objectTypeAddress;
            if (KswordARKObjectTypeIsKnown(objectTypeAddress)) {
                entry->fieldFlags |=
                    KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_KNOWN_TYPE;
            }
            if ((Request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_NAMES) != 0UL &&
                dynName) {
                nameRead = KswordARKObjectTypeReadName(
                    objectTypeAddress,
                    dynState->Kernel.OtName,
                    entry->typeName,
                    RTL_NUMBER_OF(entry->typeName));
                if (nameRead) {
                    entry->fieldFlags |=
                        KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_NAME;
                }
            }
            /*
             * ObQueryNameString consumes a live Object Manager object.  The
             * table entries above come from a private kernel table and are
             * only validated as readable pointer values; a stale entry must
             * never be passed to the Object Manager.  Keep the namespace
             * fallback limited to the four identities obtained from exported
             * POBJECT_TYPE globals, which are live object references.  All
             * other names are supplied by the DynData-gated, MmCopyMemory
             * based path above (or reported as unavailable).
             */
            if ((Request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_NAMES) != 0UL &&
                !nameRead &&
                KswordARKObjectTypeIsKnown(objectTypeAddress)) {
                nameRead = KswordARKObjectTypeReadNamespaceName(
                    objectTypeAddress,
                    entry->typeName,
                    RTL_NUMBER_OF(entry->typeName));
                if (nameRead) {
                    entry->fieldFlags |=
                        KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_NAME;
                    response->flags |=
                        KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_NAMESPACE_NAMES;
                }
            }
            if ((Request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_VALIDATE_INDEX) != 0UL &&
                dynIndex) {
                indexRead = KswordARKObjectTypeReadIndex(
                    objectTypeAddress,
                    dynState->Kernel.OtIndex,
                    &observedIndex);
                if (indexRead) {
                    entry->fieldFlags |=
                        KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_INDEX;
                    if ((ULONG)observedIndex == slot) {
                        entry->fieldFlags |=
                            KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_INDEX_MATCH;
                    }
                    else {
                        entry->status =
                            KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_INDEX_MISMATCH;
                        entry->lastStatus = STATUS_DATA_ERROR;
                        partial = TRUE;
                    }
                }
            }
            if (((Request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_NAMES) != 0UL &&
                    !nameRead) ||
                ((Request->flags &
                    KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_VALIDATE_INDEX) != 0UL &&
                    !indexRead)) {
                if (entry->status == KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_OK) {
                    entry->status = KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_PARTIAL;
                }
                partial = TRUE;
            }
            entry->identityHash = KswordARKObjectTypeHashBytes(
                KSW_OBJECT_TYPE_FNV_OFFSET_BASIS,
                &entry->typeIndex,
                sizeof(entry->typeIndex));
            entry->identityHash = KswordARKObjectTypeHashBytes(
                entry->identityHash,
                &entry->objectTypeAddress,
                sizeof(entry->objectTypeAddress));
            entry->fieldFlags |=
                KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_IDENTITY_HASH;
            response->returnedCount += 1UL;
        }
    }
    response->snapshotHash = snapshotHash;
    response->flags |=
        KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_SNAPSHOT_HASH_VALID;
    response->nextIndex = nextIndex;
    if (nextIndex < KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS) {
        response->flags |=
            KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_TRUNCATED;
        response->status =
            KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_BUFFER_TRUNCATED;
        response->lastStatus = STATUS_BUFFER_OVERFLOW;
    }
    else if (partial ||
        (((Request->flags &
            KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_VALIDATE_INDEX) != 0UL) &&
            !dynIndex)) {
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_PARTIAL;
        response->lastStatus = partial ? STATUS_PARTIAL_COPY : STATUS_NOT_SUPPORTED;
    }
    else {
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_OK;
        response->lastStatus = STATUS_SUCCESS;
    }
    *BytesWrittenOut = KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount *
            sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY));
    ExFreePoolWithTag(workspace, KSW_OBJECT_TYPE_WORKSPACE_POOL_TAG);
    workspace = NULL;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKernelObjectIoctlEnumTypeTable(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Validates and dispatches IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE.

Return Value:

    WDF buffer validation or response-builder status.

--*/
{
    KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_REQUEST* queryRequest = NULL;
    // requestSnapshot 在后端清零共用 SystemBuffer 前保存完整请求。
    KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_REQUEST requestSnapshot;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Device);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    if (InputBufferLength < sizeof(*queryRequest) ||
        OutputBufferLength < KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(*queryRequest),
        (PVOID*)&queryRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status) || actualInputLength < sizeof(*queryRequest)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    /*
     * METHOD_BUFFERED 的输入和输出是同一个 SystemBuffer；后端会先
     * RtlZeroMemory 输出再读 maxEntries 当作枚举上界，不做快照就是拿
     * 响应头字节当条目数用。
     */
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    if (queryRequest->version != KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION ||
        (queryRequest->flags &
            (~KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_ALL)) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSW_OBJECT_TYPE_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return KswordARKObjectTypeBuildResponse(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        BytesReturned);
}

/*
 * ============================================================
 * ObjectType 方法指针完整性（issue #200）。
 *
 * OBJECT_TYPE 内嵌的初始化器有八个方法指针（Dump/Open/Close/Delete/Parse/
 * Security/QueryName/OkayToClose）。改其中任一个就能截获该类型对象上的每一次
 * 打开/解析/关闭，而 ObTypeIndexTable 本身、类型对象地址都毫无变化，只核对
 * 一级地址的检测看不到它。
 *
 * 这些成员的偏移不在任何 DynData 表里（本机 ntoskrnl 也不在任何偏移表内），
 * 本文件也不假设它，更不依赖任何导出符号：方法指针块的起点在运行时自验证。
 *
 *   1. 读出 ObTypeIndexTable 里全部对象类型（约 70 个）各自的前 0x180 字节窗口；
 *   2. 锚点：SecurityProcedure。绝大多数类型共用同一个默认安全方法，所以在窗口的
 *      某个偏移上，"落在 ntoskrnl 可执行节里的同一个指针值"会被很多个类型共享。
 *      找出这个共享数量最多、且明显多于第二名（>= 2 倍）的偏移——没有唯一优势解
 *      就判 UNVERIFIED，绝不挑一个"看起来最像"的；
 *   3. 由锚点按成员顺序（Dump,Open,Close,Delete,Parse,Security,QueryName,OkayToClose，
 *      Security 是第 6 个）倒推块起点；
 *   4. 形状核对：八个槽位里，每一槽都要有 >= 95% 的类型"为空，或落在某个已加载模块的
 *      可执行节里"。核对用全体类型而不是四个核心类型，所以两三个被 Hook 的类型
 *      不会反过来遮蔽发现过程。
 *
 * 任何一步过不了就如实上报 UNVERIFIED 和原因，绝不在没把握时给出"被劫持"的结论。
 * ============================================================
 */

#define KSW_OBJTYPE_PROC_WINDOW_BYTES 0x180UL
#define KSW_OBJTYPE_PROC_WINDOW_QWORDS (KSW_OBJTYPE_PROC_WINDOW_BYTES / sizeof(ULONG_PTR))
#define KSW_OBJTYPE_PROC_MIN_TYPES 12UL
#define KSW_OBJTYPE_PROC_MIN_MODAL 6UL
#define KSW_OBJTYPE_PROC_SLOT_AGREE_PERCENT 95UL
#define KSW_OBJTYPE_PROC_CLASS_MEMO_SLOTS 512UL
#define KSW_OBJTYPE_PROC_DISCOVERY_POOL_TAG 'dOsK'
#define KSW_OBJTYPE_PROC_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_RESPONSE) - \
        sizeof(KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY))

typedef struct _KSW_OBJTYPE_PROC_CLASSIFICATION
{
    BOOLEAN IsNull;
    BOOLEAN Canonical;
    BOOLEAN InModule;
    BOOLEAN IsCoreModule;
    ULONG SectionResult;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module;
} KSW_OBJTYPE_PROC_CLASSIFICATION;

typedef struct _KSW_OBJTYPE_MEMO_ENTRY
{
    ULONGLONG Value;
    KSW_OBJTYPE_PROC_CLASSIFICATION Classification;
} KSW_OBJTYPE_MEMO_ENTRY;

/*
 * 对象类型清单：直接枚举 \ObjectTypes 命名空间目录，而不是依赖 ObTypeIndexTable 定位器。
 * 目录里的每个条目本身就是一个 OBJECT_TYPE 对象，并且自带类型名。2026-09 在 Win11 22621
 * 测试机上实测，既有的表定位器（r0 object-types）会判"多个候选并列"而一行都不返回，
 * 让整条 ObjectType 完整性检测无从谈起；命名空间枚举与那条链路没有任何共用部分。
 */
#define KSW_OBJTYPE_DIRECTORY_QUERY_BUFFER_BYTES (32UL * 1024UL)

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

typedef struct _KSW_OBJTYPE_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} KSW_OBJTYPE_DIRECTORY_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenDirectoryObject(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength
    );

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID Object
    );

NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
    );

// 一次查询所需的全部工作区（约 150 KB），放在非分页池里，不占内核栈。
typedef struct _KSW_OBJTYPE_DISCOVERY
{
    ULONG TypeCount;
    // 目录里有、但没能引用成类型对象（或超出容量）的条目数：非零表示清单不完整。
    ULONG SkippedCount;
    ULONG MemoCount;
    // 持有引用的类型对象（清理时逐个 ObDereferenceObject）。
    PVOID Object[KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS];
    ULONG_PTR TypeAddress[KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS];
    WCHAR Name[KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS][KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS];
    BOOLEAN WindowOk[KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS];
    ULONG_PTR Window[KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS][KSW_OBJTYPE_PROC_WINDOW_QWORDS];
    KSW_OBJTYPE_MEMO_ENTRY Memo[KSW_OBJTYPE_PROC_CLASS_MEMO_SLOTS];
} KSW_OBJTYPE_DISCOVERY;

typedef struct _KSW_OBJTYPE_LAYOUT_RESULT
{
    ULONG State;
    ULONG Reason;
    ULONG BlockOffset;
    ULONG TypesConsidered;
    ULONG ModalCount;
} KSW_OBJTYPE_LAYOUT_RESULT;

typedef struct _KSW_OBJTYPE_LAYOUT_CACHE
{
    volatile ULONG State;
    ULONG BlockOffset;
    ULONG TypesConsidered;
    ULONG ModalCount;
} KSW_OBJTYPE_LAYOUT_CACHE;

// 文件级一次性缓存：只缓存 VALIDATED 的偏移（缓存的是偏移，不是某次查询的结论）。
// UNVERIFIED 可能只是这一次没取到模块快照之类的瞬时原因，下次查询应当重新尝试。
static KSW_OBJTYPE_LAYOUT_CACHE g_KswordArkObjectTypeProcLayout;

static BOOLEAN
KswordARKObjectTypeIsCanonicalKernelAddress(
    _In_ ULONG_PTR Address
    )
/*++

Routine Description:

    判断一个值是不是规范的系统空间地址。不要求 8 字节对齐：函数入口并不保证对齐，
    把对齐当成"是指针"的条件会把合法的入口地址误判成垃圾值。

Return Value:

    TRUE 表示落在系统地址空间内的规范地址。

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    return Address >= (ULONG_PTR)MmSystemRangeStart && (Address >> 48U) == 0xFFFFU;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart;
#endif
}

static VOID
KswordARKObjectTypeClassifyPointer(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONGLONG Value,
    _Out_ KSW_OBJTYPE_PROC_CLASSIFICATION* Result
    )
/*++

Routine Description:

    把一个方法指针槽的原始值归类：空值、非规范值、落在某模块内与否、该模块是否
    核心内核、落在该模块的哪类节。只做地址分类，不对指针解引用。

Return Value:

    None. 结果写入 Result。

--*/
{
    RtlZeroMemory(Result, sizeof(*Result));
    if (Value == 0ULL) {
        Result->IsNull = TRUE;
        return;
    }
    if (!KswordARKObjectTypeIsCanonicalKernelAddress((ULONG_PTR)Value)) {
        return;
    }
    Result->Canonical = TRUE;
    Result->Module = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, Value);
    if (Result->Module == NULL) {
        return;
    }
    Result->InModule = TRUE;
    Result->IsCoreModule = KswordARKDriverIntegrityIsCoreKernelModule(Result->Module);
    Result->SectionResult = KswordARKImageClassifyAddress(
        Result->Module,
        Value,
        NULL,
        0UL,
        NULL);
}

static const KSW_OBJTYPE_PROC_CLASSIFICATION*
KswordARKObjectTypeClassifyMemoized(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _Inout_ KSW_OBJTYPE_DISCOVERY* Discovery,
    _In_ ULONGLONG Value,
    _Out_ KSW_OBJTYPE_PROC_CLASSIFICATION* Scratch
    )
/*++

Routine Description:

    带缓存的归类。同一个函数指针会被很多个类型共享（默认安全方法等），而每次归类都要
    线性扫模块表并解析 PE 节表头，所以按值缓存。缓存满了就退化成不缓存，结果不变。

Return Value:

    指向缓存项或 Scratch 的归类结果，恒非空。

--*/
{
    ULONG index = 0UL;

    if (Value == 0ULL || !KswordARKObjectTypeIsCanonicalKernelAddress((ULONG_PTR)Value)) {
        KswordARKObjectTypeClassifyPointer(ModuleInfo, Value, Scratch);
        return Scratch;
    }
    for (index = 0UL; index < Discovery->MemoCount; ++index) {
        if (Discovery->Memo[index].Value == Value) {
            return &Discovery->Memo[index].Classification;
        }
    }
    if (Discovery->MemoCount < KSW_OBJTYPE_PROC_CLASS_MEMO_SLOTS) {
        KSW_OBJTYPE_MEMO_ENTRY* entry = &Discovery->Memo[Discovery->MemoCount];

        entry->Value = Value;
        KswordARKObjectTypeClassifyPointer(ModuleInfo, Value, &entry->Classification);
        Discovery->MemoCount += 1UL;
        return &entry->Classification;
    }
    KswordARKObjectTypeClassifyPointer(ModuleInfo, Value, Scratch);
    return Scratch;
}

static BOOLEAN
KswordARKObjectTypeIsCoreExec(
    _In_ const KSW_OBJTYPE_PROC_CLASSIFICATION* Classification
    )
/*++

Return Value:

    TRUE 表示落在 ntoskrnl / hal 的可执行节内。

--*/
{
    return Classification->InModule && Classification->IsCoreModule &&
        Classification->SectionResult == KSW_IMAGE_SECTION_RESULT_EXECUTABLE;
}

static BOOLEAN
KswordARKObjectTypeAgreesWithBlockShape(
    _In_ const KSW_OBJTYPE_PROC_CLASSIFICATION* Classification
    )
/*++

Routine Description:

    形状核对用的"这个槽位像方法指针"判据：为空，或落在**任何**已加载模块的可执行节内。
    刻意不要求是核心模块——第三方自建的对象类型合法地落在自己的模块里；
    节归类不出来（PE 头读不到）时不当作反证，只是无法判断。

Return Value:

    TRUE 表示与"方法指针槽"的形状相符。

--*/
{
    if (Classification->IsNull) {
        return TRUE;
    }
    if (!Classification->InModule) {
        return FALSE;
    }
    return Classification->SectionResult == KSW_IMAGE_SECTION_RESULT_EXECUTABLE ||
        Classification->SectionResult == KSW_IMAGE_SECTION_RESULT_UNKNOWN;
}

static VOID
KswordARKObjectTypeDiscoverProcedureBlock(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _Inout_ KSW_OBJTYPE_DISCOVERY* Discovery,
    _Out_ KSW_OBJTYPE_LAYOUT_RESULT* Result
    )
/*++

Routine Description:

    发现方法指针块相对 OBJECT_TYPE 基址的偏移。调用方已填好 Discovery->TypeAddress 与
    TypeCount。结果只写进 Result（局部），是否缓存由调用方决定，避免并发查询互相覆盖状态。

Return Value:

    None.

--*/
{
    ULONG typeIndex = 0UL;
    ULONG usable = 0UL;
    ULONG qword = 0UL;
    ULONG bestQword = 0UL;
    ULONG bestModal = 0UL;
    ULONG secondModal = 0UL;
    ULONG blockFirst = 0UL;
    ULONG slotIndex = 0UL;
    ULONG modal[KSW_OBJTYPE_PROC_WINDOW_QWORDS];

    RtlZeroMemory(Result, sizeof(*Result));
    Result->State = KSWORD_ARK_OBJTYPE_LAYOUT_UNVERIFIED;
    if (ModuleInfo == NULL || ModuleInfo->NumberOfModules == 0UL) {
        Result->Reason = KSWORD_ARK_OBJTYPE_LAYOUT_REASON_NO_MODULE_SNAPSHOT;
        return;
    }
    for (typeIndex = 0UL; typeIndex < Discovery->TypeCount; ++typeIndex) {
        Discovery->WindowOk[typeIndex] = KswordARKRuntimeReadMemory(
            (const VOID*)Discovery->TypeAddress[typeIndex],
            Discovery->Window[typeIndex],
            KSW_OBJTYPE_PROC_WINDOW_BYTES);
        if (Discovery->WindowOk[typeIndex]) {
            usable += 1UL;
        }
    }
    Result->TypesConsidered = usable;
    if (usable < KSW_OBJTYPE_PROC_MIN_TYPES) {
        Result->Reason = KSWORD_ARK_OBJTYPE_LAYOUT_REASON_TOO_FEW_TYPES;
        return;
    }

    /* 锚点：每个偏移上"落在 ntoskrnl 可执行节内的同一个指针值"被最多多少个类型共享。 */
    RtlZeroMemory(modal, sizeof(modal));
    for (qword = 0UL; qword < KSW_OBJTYPE_PROC_WINDOW_QWORDS; ++qword) {
        for (typeIndex = 0UL; typeIndex < Discovery->TypeCount; ++typeIndex) {
            KSW_OBJTYPE_PROC_CLASSIFICATION scratch;
            const KSW_OBJTYPE_PROC_CLASSIFICATION* classification = NULL;
            ULONGLONG value = 0ULL;
            ULONG otherIndex = 0UL;
            ULONG sameCount = 0UL;

            if (!Discovery->WindowOk[typeIndex]) {
                continue;
            }
            value = Discovery->Window[typeIndex][qword];
            if (value == 0ULL) {
                continue;
            }
            classification = KswordARKObjectTypeClassifyMemoized(ModuleInfo, Discovery, value, &scratch);
            if (!KswordARKObjectTypeIsCoreExec(classification)) {
                continue;
            }
            for (otherIndex = 0UL; otherIndex < Discovery->TypeCount; ++otherIndex) {
                if (Discovery->WindowOk[otherIndex] && Discovery->Window[otherIndex][qword] == value) {
                    sameCount += 1UL;
                }
            }
            if (sameCount > modal[qword]) {
                modal[qword] = sameCount;
            }
        }
    }
    for (qword = 0UL; qword < KSW_OBJTYPE_PROC_WINDOW_QWORDS; ++qword) {
        if (modal[qword] > bestModal) {
            secondModal = bestModal;
            bestModal = modal[qword];
            bestQword = qword;
        }
        else if (modal[qword] > secondModal) {
            secondModal = modal[qword];
        }
    }
    Result->ModalCount = bestModal;
    /*
     * 块必须整个落在窗口里：Security 是第 6 个成员，所以锚点下标至少 5，
     * 且其后还要容得下 QueryName 与 OkayToClose 两个成员。
     */
    if (bestModal < KSW_OBJTYPE_PROC_MIN_MODAL ||
        (secondModal != 0UL && bestModal < secondModal * 2UL) ||
        bestQword < (ULONG)KSWORD_ARK_OBJTYPE_PROC_SECURITY ||
        bestQword - (ULONG)KSWORD_ARK_OBJTYPE_PROC_SECURITY + (ULONG)KSWORD_ARK_OBJTYPE_PROC_COUNT >
            KSW_OBJTYPE_PROC_WINDOW_QWORDS) {
        Result->Reason = KSWORD_ARK_OBJTYPE_LAYOUT_REASON_NO_DOMINANT_ANCHOR;
        return;
    }
    blockFirst = bestQword - (ULONG)KSWORD_ARK_OBJTYPE_PROC_SECURITY;

    /* 形状核对：八个槽位每一槽都要有 >= 95% 的可读类型与"方法指针槽"的形状相符。 */
    for (slotIndex = 0UL; slotIndex < (ULONG)KSWORD_ARK_OBJTYPE_PROC_COUNT; ++slotIndex) {
        ULONG agree = 0UL;

        for (typeIndex = 0UL; typeIndex < Discovery->TypeCount; ++typeIndex) {
            KSW_OBJTYPE_PROC_CLASSIFICATION scratch;
            const KSW_OBJTYPE_PROC_CLASSIFICATION* classification = NULL;

            if (!Discovery->WindowOk[typeIndex]) {
                continue;
            }
            classification = KswordARKObjectTypeClassifyMemoized(
                ModuleInfo,
                Discovery,
                Discovery->Window[typeIndex][blockFirst + slotIndex],
                &scratch);
            if (KswordARKObjectTypeAgreesWithBlockShape(classification)) {
                agree += 1UL;
            }
        }
        if (agree * 100UL < usable * KSW_OBJTYPE_PROC_SLOT_AGREE_PERCENT) {
            Result->Reason = KSWORD_ARK_OBJTYPE_LAYOUT_REASON_BLOCK_SHAPE_FAILED;
            return;
        }
    }
    Result->BlockOffset = blockFirst * (ULONG)sizeof(ULONG_PTR);
    Result->State = KSWORD_ARK_OBJTYPE_LAYOUT_VALIDATED;
    Result->Reason = KSWORD_ARK_OBJTYPE_LAYOUT_REASON_NONE;
}

static VOID
KswordARKObjectTypeReleaseList(
    _Inout_ KSW_OBJTYPE_DISCOVERY* Discovery
    )
/*++

Routine Description:

    归还清单里每个类型对象持有的引用。

Return Value:

    None.

--*/
{
    ULONG index = 0UL;

    for (index = 0UL; index < Discovery->TypeCount; ++index) {
        if (Discovery->Object[index] != NULL) {
            ObDereferenceObject(Discovery->Object[index]);
            Discovery->Object[index] = NULL;
        }
    }
    Discovery->TypeCount = 0UL;
}

static NTSTATUS
KswordARKObjectTypeEnumerateNamespace(
    _Inout_ KSW_OBJTYPE_DISCOVERY* Discovery
    )
/*++

Routine Description:

    枚举 \ObjectTypes 目录，把每个条目按全路径引用成 OBJECT_TYPE 对象并记下类型名。
    不依赖 ObTypeIndexTable，也不需要任何私有偏移。调用方负责在用完后调用
    KswordARKObjectTypeReleaseList 归还引用。

Return Value:

    STATUS_SUCCESS 表示枚举走到了结尾（清单可能为空）；其它值表示目录打不开或查询失败。

--*/
{
    UNICODE_STRING directoryName;
    OBJECT_ATTRIBUTES attributes;
    HANDLE directoryHandle = NULL;
    PUCHAR buffer = NULL;
    ULONG context = 0UL;
    BOOLEAN restart = TRUE;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG pageCount = 0UL;
    POBJECT_TYPE typeObjectType = NULL;

    Discovery->TypeCount = 0UL;
    Discovery->SkippedCount = 0UL;
    // ZwOpenDirectoryObject / ZwQueryDirectoryObject / ObReferenceObjectByName 都只能在
    // PASSIVE_LEVEL 调用（可能进入可分页系统服务）；这个 IOCTL 走 KMDF 并行队列，没有
    // PASSIVE 保证，必须自己门。与 KswordARKHookBuildModuleSnapshot 的既有惯例一致。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    /*
     * ObReferenceObjectByName 在 ObjectType 与 AccessState 都为 NULL 时，会拿
     * &ObjectType->TypeInfo.GenericMapping（即 0x4C）去建局部访问状态并直接读取它，
     * 2026-09 在 Win11 22621 靶机上实测为 SYSTEM_SERVICE_EXCEPTION（0x3B，读 0x4C）。
     * 所以必须给出真实的 ObjectType：类型对象本身的类型就是"Type"，
     * 用任一已导出类型对象（PsProcessType）经 ObGetObjectType 取得它。
     */
    if (PsProcessType == NULL || *PsProcessType == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    typeObjectType = ObGetObjectType((PVOID)*PsProcessType);
    if (typeObjectType == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    RtlInitUnicodeString(&directoryName, L"\\ObjectTypes");
    InitializeObjectAttributes(
        &attributes,
        &directoryName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    status = ZwOpenDirectoryObject(&directoryHandle, DIRECTORY_QUERY, &attributes);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    buffer = (PUCHAR)KswordARKAllocateNonPagedPool(
        KSW_OBJTYPE_DIRECTORY_QUERY_BUFFER_BYTES,
        KSW_OBJTYPE_PROC_DISCOVERY_POOL_TAG);
    if (buffer == NULL) {
        ZwClose(directoryHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (pageCount = 0UL; pageCount < 64UL; ++pageCount) {
        ULONG returned = 0UL;
        const KSW_OBJTYPE_DIRECTORY_INFORMATION* entry = NULL;
        const UCHAR* bufferEnd = buffer + KSW_OBJTYPE_DIRECTORY_QUERY_BUFFER_BYTES;

        RtlZeroMemory(buffer, KSW_OBJTYPE_DIRECTORY_QUERY_BUFFER_BYTES);
        status = ZwQueryDirectoryObject(
            directoryHandle,
            buffer,
            KSW_OBJTYPE_DIRECTORY_QUERY_BUFFER_BYTES,
            FALSE,
            restart,
            &context,
            &returned);
        restart = FALSE;
        if (status == STATUS_NO_MORE_ENTRIES) {
            status = STATUS_SUCCESS;
            break;
        }
        if (!NT_SUCCESS(status) && status != STATUS_MORE_ENTRIES) {
            break;
        }

        /* 条目数组以一个 Name.Buffer 为空的条目收尾；再叠一层边界检查，防坏数据。 */
        for (entry = (const KSW_OBJTYPE_DIRECTORY_INFORMATION*)buffer;
            (const UCHAR*)(entry + 1) <= bufferEnd && entry->Name.Buffer != NULL;
            ++entry) {
            WCHAR fullPath[13 + KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS + 1];
            UNICODE_STRING fullName;
            PVOID object = NULL;
            ULONG nameChars = entry->Name.Length / sizeof(WCHAR);
            NTSTATUS referenceStatus = STATUS_SUCCESS;

            if (Discovery->TypeCount >= KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS) {
                Discovery->SkippedCount += 1UL;
                continue;
            }
            if (nameChars == 0UL || nameChars >= KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS ||
                (const UCHAR*)entry->Name.Buffer < buffer ||
                (const UCHAR*)entry->Name.Buffer + entry->Name.Length > bufferEnd) {
                Discovery->SkippedCount += 1UL;
                continue;
            }
            RtlZeroMemory(fullPath, sizeof(fullPath));
            RtlCopyMemory(fullPath, L"\\ObjectTypes\\", 13 * sizeof(WCHAR));
            RtlCopyMemory(&fullPath[13], entry->Name.Buffer, entry->Name.Length);
            RtlInitUnicodeString(&fullName, fullPath);
            referenceStatus = ObReferenceObjectByName(
                &fullName,
                OBJ_CASE_INSENSITIVE,
                NULL,
                0,
                typeObjectType,
                KernelMode,
                NULL,
                &object);
            if (!NT_SUCCESS(referenceStatus) || object == NULL) {
                Discovery->SkippedCount += 1UL;
                continue;
            }
            Discovery->Object[Discovery->TypeCount] = object;
            Discovery->TypeAddress[Discovery->TypeCount] = (ULONG_PTR)object;
            RtlCopyMemory(
                Discovery->Name[Discovery->TypeCount],
                entry->Name.Buffer,
                entry->Name.Length);
            Discovery->Name[Discovery->TypeCount][nameChars] = L'\0';
            Discovery->TypeCount += 1UL;
        }
        if (status != STATUS_MORE_ENTRIES) {
            break;
        }
    }
    ExFreePoolWithTag(buffer, KSW_OBJTYPE_PROC_DISCOVERY_POOL_TAG);
    ZwClose(directoryHandle);
    return status == STATUS_MORE_ENTRIES ? STATUS_SUCCESS : status;
}

static VOID
KswordARKObjectTypeClassifyProcedureRow(
    _In_ BOOLEAN IsCoreType,
    _In_ const KSW_OBJTYPE_PROC_CLASSIFICATION* Classification,
    _Inout_ KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY* Entry
    )
/*++

Routine Description:

    给一行方法指针定风险位。原则：只在有**正面证据**时指控——解析出一个不是核心内核的模块、
    或落在可执行节之外；节归类不出来（PE 头读不到）只标"无法判断"，绝不当成劫持。

    核心类型（Process/Thread/Driver/File，其身份已由 ntoskrnl 导出的类型指针确认）的方法指针
    必须落在 ntoskrnl/hal 的可执行节里；偏离一律是"隐藏行为"：一级（类型表、类型对象地址）
    毫无变化，问题只藏在二级方法指针里。
    非核心类型可能是第三方驱动自建的 ObjectType，方法指针合法地落在它自己的模块里，
    所以只对"不在任何模块里"和"在模块里但不在可执行节里"给软性风险位。

Return Value:

    None.

--*/
{
    const BOOLEAN sectionKnown = Classification->SectionResult != KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    const BOOLEAN sectionNonExec = Classification->SectionResult == KSW_IMAGE_SECTION_RESULT_NON_EXECUTABLE ||
        Classification->SectionResult == KSW_IMAGE_SECTION_RESULT_OUTSIDE_SECTIONS;

    if (!Classification->Canonical || !Classification->InModule) {
        Entry->riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
        if (IsCoreType) {
            Entry->riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK;
        }
        return;
    }
    if (!sectionKnown) {
        Entry->riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE;
        if (IsCoreType && !Classification->IsCoreModule) {
            Entry->riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK |
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_OBJTYPE_PROC_NON_CORE;
        }
        return;
    }
    if (IsCoreType) {
        if (!Classification->IsCoreModule) {
            Entry->riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK |
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_OBJTYPE_PROC_NON_CORE;
        }
        else if (sectionNonExec) {
            Entry->riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK |
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_TARGET_NON_EXEC;
        }
        return;
    }
    if (sectionNonExec) {
        Entry->riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_TARGET_NON_EXEC;
    }
}

#define KSW_OBJTYPE_TYPE_CONSISTENCY_MIN_NT_SLOTS 3UL

static VOID
KswordARKObjectTypeApplyTypeConsistencyRule(
    _In_ BOOLEAN IsCoreType,
    _Inout_updates_(RowCount) KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY* Rows,
    _In_ ULONG RowCount
    )
/*++

Routine Description:

    issue #200 的正题：核心类型（Process/Thread/Driver/File）靠身份 + 地址范围就能下硬判据，
    但那只是 70 个对象类型里的 4 个——其余 66 个此前只有"不在任何模块里""在模块里但不在可执行
    节里"这两条软性风险位，一个方法指针被换成落在合法第三方驱动模块可执行节里的函数（完全符合
    "方法指针落在某模块可执行节"这条形状），riskFlags 恒为 0，是明确的漏检。

    这里补一条只看同一类型内部、不依赖外部基线的判据：非核心类型如果同时有
    >= KSW_OBJTYPE_TYPE_CONSISTENCY_MIN_NT_SLOTS 个方法指针落在 ntoskrnl/hal 可执行节里
    （"这个类型大体上用的是系统默认实现"）、又恰好只有 1 个方法指针落在别的模块里，那 1 个就是
    类型内部唯一的异常，判 HIDDEN_HOOK。多于 1 个第三方槽位是第三方驱动自建类型的正常形态
    （TmTm/PcwObject/Dxgk* 等在干净机器上都有 2-4 个），不能一概当成劫持——**但这不是充分证据**：
    一个第三方类型完全可以合法地只自建 1 个方法、其余 2 个以上留给系统共享默认实现（"该类型大体上
    用系统默认，只有一处自定义"本身就是正当形态，不能反过来当成"只有一处被劫持"）。没有干净基线
    做对照，这条判据分不清这两种情况；本版本把 nt 槽位门槛设到 3（而不是够用的 2）只是经验性地
    收窄误判面，不是结构性证明。这一处仍是本版本的已知局限，如实写进覆盖度语义里，不要在文档或
    UI 里把它包装成"确定性判据"。

    覆盖度标记（TYPE_JUDGED）：**必须与上面触发 HIDDEN_HOOK 的两个前提同时成立**——只在该类型
    当前 thirdPartyCount 恰好为 0（干净）且 nt 槽位 >= 3 时才标；只按 nt 槽位数判断而不管
    thirdPartyCount 会把"这个类型已经有 1 个第三方槽位、判据已经在吃它自己触发条件的老本"也标成
    "单槽劫持保证能抓到"，两者互相矛盾。用 2026-09-21 在 Win11 22621 靶机上的 70 个对象类型
    实测过：这条判据在干净机器上假阳性为 0。

Arguments:

    IsCoreType - 该类型是否已由身份判据（ntoskrnl 导出的类型指针）确认为核心类型。
    Rows - 该类型这一次查询产出的连续 KSWORD_ARK_OBJTYPE_PROC_COUNT 行。
    RowCount - Rows 的元素个数（正常总是 KSWORD_ARK_OBJTYPE_PROC_COUNT，防御性传参）。

Return Value:

    None. 就地修改 Rows[].riskFlags / Rows[].entryFlags。

--*/
{
    ULONG index = 0UL;
    ULONG thirdPartyCount = 0UL;
    ULONG ntCount = 0UL;
    ULONG thirdPartyRowIndex = RowCount;
    BOOLEAN anyReadFailed = FALSE;
    BOOLEAN typeJudged = FALSE;

    if (Rows == NULL || RowCount == 0UL) {
        return;
    }
    if (IsCoreType) {
        // 核心类型的每一行已经由 ClassifyProcedureRow 的地址范围判据覆盖过，这里只补标记。
        for (index = 0UL; index < RowCount; ++index) {
            Rows[index].entryFlags |= KSWORD_ARK_OBJTYPE_ENTRY_FLAG_TYPE_JUDGED;
        }
        return;
    }
    for (index = 0UL; index < RowCount; ++index) {
        const KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY* row = &Rows[index];

        if ((row->entryFlags & KSWORD_ARK_OBJTYPE_ENTRY_FLAG_READ_FAILED) != 0UL) {
            anyReadFailed = TRUE;
            continue;
        }
        if ((row->entryFlags & KSWORD_ARK_OBJTYPE_ENTRY_FLAG_IN_MODULE) == 0UL) {
            continue;
        }
        if ((row->entryFlags & KSWORD_ARK_OBJTYPE_ENTRY_FLAG_IN_CORE_KERNEL) != 0UL) {
            ntCount += 1UL;
        }
        else {
            thirdPartyCount += 1UL;
            thirdPartyRowIndex = index;
        }
    }
    if (anyReadFailed) {
        // 读取失败的槽位无法判断，缺一角的证据不足以支撑本条判据，宁可不判。
        return;
    }
    if (thirdPartyCount == 1UL &&
        ntCount >= KSW_OBJTYPE_TYPE_CONSISTENCY_MIN_NT_SLOTS &&
        thirdPartyRowIndex < RowCount) {
        Rows[thirdPartyRowIndex].riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK |
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_OBJTYPE_PROC_NON_CORE;
    }
    // 覆盖度承诺的是"下一次只坏一个槽也保证抓到"：当前必须已经零第三方槽位（thirdPartyCount==0），
    // 不然这个类型本身已经踩在触发条件的边缘上——它自己的第三方槽位已经用掉了判据里"恰好 1 个"
    // 的名额，再劫持任何一个 nt 槽位都不会让 thirdPartyCount 变成"恰好 1"，判据不会响。
    typeJudged = (thirdPartyCount == 0UL && ntCount >= KSW_OBJTYPE_TYPE_CONSISTENCY_MIN_NT_SLOTS);
    if (typeJudged) {
        for (index = 0UL; index < RowCount; ++index) {
            Rows[index].entryFlags |= KSWORD_ARK_OBJTYPE_ENTRY_FLAG_TYPE_JUDGED;
        }
    }
}

static NTSTATUS
KswordARKObjectTypeProceduresBuildResponse(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    构建一份只读的 ObjectType 方法指针完整性响应。布局没通过自验证、或者没取到模块快照
    （无法归属任何指针）时返回零条目并如实标注原因，绝不猜偏移、也绝不在缺证据时指控。

Return Value:

    STATUS_SUCCESS 承载语义化响应；缓冲区过小才返回错误状态。

--*/
{
    KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_RESPONSE* response =
        (KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_RESPONSE*)OutputBuffer;
    KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY* rows = NULL;
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    KSW_OBJTYPE_DISCOVERY* discovery = NULL;
    KSW_OBJTYPE_LAYOUT_RESULT layout;
    ULONG moduleInfoBytes = 0UL;
    NTSTATUS moduleStatus = STATUS_SUCCESS;
    NTSTATUS enumerateStatus = STATUS_SUCCESS;
    ULONG capacity = 0UL;
    ULONG maxTypes = 0UL;
    ULONG typesEmitted = 0UL;
    ULONG startIndex = 0UL;
    ULONG slot = 0UL;
    ULONG nextIndex = KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS;
    ULONG blockOffset = 0UL;
    BOOLEAN partial = FALSE;
    BOOLEAN truncated = FALSE;
    BOOLEAN skippedTypes = FALSE;

    if (OutputBuffer == NULL || Request == NULL || BytesWrittenOut == NULL ||
        OutputBufferLength < KSW_OBJTYPE_PROC_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *BytesWrittenOut = 0U;
    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    RtlZeroMemory(&layout, sizeof(layout));
    response->version = KSWORD_ARK_OBJECT_TYPE_PROCEDURES_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY);
    response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_UNAVAILABLE;
    response->nextIndex = KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS;
    response->layoutState = KSWORD_ARK_OBJTYPE_LAYOUT_UNAVAILABLE;

    rows = response->entries;
    discovery = (KSW_OBJTYPE_DISCOVERY*)KswordARKAllocateNonPagedPool(
        sizeof(*discovery),
        KSW_OBJTYPE_PROC_DISCOVERY_POOL_TAG);
    if (discovery == NULL) {
        response->layoutState = KSWORD_ARK_OBJTYPE_LAYOUT_UNVERIFIED;
        response->reserved0 = KSWORD_ARK_OBJTYPE_LAYOUT_REASON_OUT_OF_MEMORY;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        *BytesWrittenOut = KSW_OBJTYPE_PROC_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(discovery, sizeof(*discovery));

    /*
     * 对象类型清单来自 \ObjectTypes 命名空间。tableAddress 恒为 0：本查询不经过
     * ObTypeIndexTable，所以 typeIndex 是本次枚举里的序号而不是类型表槽位。
     */
    enumerateStatus = KswordARKObjectTypeEnumerateNamespace(discovery);
    if (!NT_SUCCESS(enumerateStatus)) {
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_TABLE_NOT_FOUND;
        response->lastStatus = enumerateStatus;
        *BytesWrittenOut = KSW_OBJTYPE_PROC_RESPONSE_HEADER_SIZE;
        goto Cleanup;
    }
    response->totalCount = discovery->TypeCount + discovery->SkippedCount;
    if (discovery->SkippedCount != 0UL) {
        partial = TRUE;
        skippedTypes = TRUE;
    }

    moduleStatus = KswordARKHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(moduleStatus) || moduleInfo == NULL || moduleInfo->NumberOfModules == 0UL) {
        /*
         * 没有模块快照就没法把任何指针归属到模块；这时再"分类"只会把每个非空指针都当成
         * "不在任何模块里"，在干净的机器上制造满屏的隐藏行为。宁可零条目并说明原因。
         */
        if (moduleInfo != NULL) {
            ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
            moduleInfo = NULL;
        }
        response->layoutState = KSWORD_ARK_OBJTYPE_LAYOUT_UNVERIFIED;
        response->reserved0 = KSWORD_ARK_OBJTYPE_LAYOUT_REASON_NO_MODULE_SNAPSHOT;
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_PARTIAL;
        response->lastStatus = NT_SUCCESS(moduleStatus) ? STATUS_NOT_SUPPORTED : moduleStatus;
        *BytesWrittenOut = KSW_OBJTYPE_PROC_RESPONSE_HEADER_SIZE;
        goto Cleanup;
    }

    if (g_KswordArkObjectTypeProcLayout.State == KSWORD_ARK_OBJTYPE_LAYOUT_VALIDATED) {
        // 只复用缓存的偏移（内核这次启动的二进制布局不会变）。参与统计的类型数与共享锚点的
        // 类型数是"这次查询看到了什么"的证据，每次都要用本次的 discovery 重新算——沿用缓存
        // 首次验证时的旧数字，会把上一次（可能命名空间还没完全建好）的统计当成这次的证据上报。
        KSW_OBJTYPE_LAYOUT_RESULT freshLayout;

        RtlZeroMemory(&freshLayout, sizeof(freshLayout));
        KswordARKObjectTypeDiscoverProcedureBlock(moduleInfo, discovery, &freshLayout);
        if (freshLayout.State == KSWORD_ARK_OBJTYPE_LAYOUT_VALIDATED &&
            freshLayout.BlockOffset == g_KswordArkObjectTypeProcLayout.BlockOffset) {
            layout.State = KSWORD_ARK_OBJTYPE_LAYOUT_VALIDATED;
            layout.BlockOffset = g_KswordArkObjectTypeProcLayout.BlockOffset;
            layout.TypesConsidered = freshLayout.TypesConsidered;
            layout.ModalCount = freshLayout.ModalCount;
        }
        else {
            // 本次重新验证跟缓存的偏移对不上、或本次干脆验证不过：缓存的前提可能已经不成立，
            // 别再沿用它，如实报 UNVERIFIED 并清掉缓存，逼下一次查询重新发现。
            layout.State = KSWORD_ARK_OBJTYPE_LAYOUT_UNVERIFIED;
            layout.Reason = freshLayout.Reason;
            InterlockedExchange(
                (volatile LONG*)&g_KswordArkObjectTypeProcLayout.State,
                (LONG)KSWORD_ARK_OBJTYPE_LAYOUT_UNAVAILABLE);
        }
    }
    else {
        KswordARKObjectTypeDiscoverProcedureBlock(moduleInfo, discovery, &layout);
        if (layout.State == KSWORD_ARK_OBJTYPE_LAYOUT_VALIDATED) {
            g_KswordArkObjectTypeProcLayout.BlockOffset = layout.BlockOffset;
            g_KswordArkObjectTypeProcLayout.TypesConsidered = layout.TypesConsidered;
            g_KswordArkObjectTypeProcLayout.ModalCount = layout.ModalCount;
            // State 最后写：并发读者先看 State 再取其它字段，所以用带栅栏的写。
            InterlockedExchange(
                (volatile LONG*)&g_KswordArkObjectTypeProcLayout.State,
                (LONG)KSWORD_ARK_OBJTYPE_LAYOUT_VALIDATED);
        }
    }
    response->layoutState = layout.State;
    response->layoutAnchorTypes = layout.TypesConsidered;
    response->layoutAnchorAgree = layout.ModalCount;
    response->reserved0 = layout.Reason;
    if (layout.State != KSWORD_ARK_OBJTYPE_LAYOUT_VALIDATED) {
        response->procedureBlockOffset = 0UL;
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_PARTIAL;
        response->lastStatus = STATUS_NOT_SUPPORTED;
        *BytesWrittenOut = KSW_OBJTYPE_PROC_RESPONSE_HEADER_SIZE;
        goto Cleanup;
    }
    blockOffset = layout.BlockOffset;
    response->procedureBlockOffset = blockOffset;

    capacity = (ULONG)((OutputBufferLength - KSW_OBJTYPE_PROC_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY));
    maxTypes = Request->maxEntries == 0UL
        ? KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS
        : min(Request->maxEntries, KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS);
    startIndex = min(Request->startIndex, KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS);

    for (slot = startIndex; slot < discovery->TypeCount; ++slot) {
        ULONG_PTR objectTypeAddress = discovery->TypeAddress[slot];
        BOOLEAN isCoreType = FALSE;
        const WCHAR* typeNameBuffer = discovery->Name[slot];
        ULONG procIndex = 0UL;
        ULONG typeRowStart = response->returnedCount;

        /* 停在"下一个还没输出的类型"，续读从 nextIndex 开始；maxEntries 数的是类型不是槽位。 */
        if (typesEmitted >= maxTypes ||
            response->returnedCount + (ULONG)KSWORD_ARK_OBJTYPE_PROC_COUNT > capacity) {
            nextIndex = slot;
            truncated = TRUE;
            break;
        }
        isCoreType = KswordARKObjectTypeIsKnown(objectTypeAddress);

        for (procIndex = 0UL; procIndex < (ULONG)KSWORD_ARK_OBJTYPE_PROC_COUNT; ++procIndex) {
            KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY* entry = &rows[response->returnedCount];
            ULONG_PTR slotAddress = objectTypeAddress +
                (ULONG_PTR)blockOffset + ((ULONG_PTR)procIndex * sizeof(PVOID));
            ULONGLONG value = 0ULL;
            KSW_OBJTYPE_PROC_CLASSIFICATION classification;

            RtlZeroMemory(entry, sizeof(*entry));
            entry->size = sizeof(*entry);
            entry->typeIndex = slot;
            entry->procedureKind = procIndex;
            entry->objectTypeAddress = (ULONG64)objectTypeAddress;
            entry->slotAddress = (ULONG64)slotAddress;
            RtlCopyMemory(
                entry->typeName,
                typeNameBuffer,
                min(sizeof(entry->typeName), sizeof(discovery->Name[slot])));
            if (isCoreType) {
                entry->entryFlags |= KSWORD_ARK_OBJTYPE_ENTRY_FLAG_CORE_TYPE;
            }

            if (!KswordARKRuntimeReadMemory((const VOID*)slotAddress, &value, sizeof(value))) {
                entry->entryFlags |= KSWORD_ARK_OBJTYPE_ENTRY_FLAG_READ_FAILED;
                entry->riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED;
                entry->lastStatus = STATUS_UNSUCCESSFUL;
                partial = TRUE;
                response->returnedCount += 1UL;
                continue;
            }
            entry->targetAddress = value;
            KswordARKObjectTypeClassifyPointer(moduleInfo, value, &classification);
            if (classification.IsNull) {
                entry->entryFlags |= KSWORD_ARK_OBJTYPE_ENTRY_FLAG_NULL_POINTER;
                response->returnedCount += 1UL;
                continue;
            }
            if (classification.InModule) {
                const UCHAR* fileName = NULL;
                ULONG fileNameBytes = 0UL;

                entry->entryFlags |= KSWORD_ARK_OBJTYPE_ENTRY_FLAG_IN_MODULE;
                entry->ownerModuleBase = (ULONG64)(ULONG_PTR)classification.Module->ImageBase;
                entry->ownerModuleSize = classification.Module->ImageSize;
                KswordARKHookGetModuleFileName(classification.Module, &fileName, &fileNameBytes);
                KswordARKHookCopyBoundedAnsiToWide(
                    fileName,
                    fileNameBytes,
                    entry->ownerModule,
                    RTL_NUMBER_OF(entry->ownerModule));
                KswordARKImageClassifyAddress(
                    classification.Module,
                    value,
                    entry->sectionName,
                    RTL_NUMBER_OF(entry->sectionName),
                    NULL);
                if (classification.IsCoreModule) {
                    entry->entryFlags |= KSWORD_ARK_OBJTYPE_ENTRY_FLAG_IN_CORE_KERNEL;
                }
                if (classification.SectionResult == KSW_IMAGE_SECTION_RESULT_EXECUTABLE) {
                    entry->entryFlags |= KSWORD_ARK_OBJTYPE_ENTRY_FLAG_EXEC_SECTION;
                }
            }
            KswordARKObjectTypeClassifyProcedureRow(isCoreType, &classification, entry);
            response->returnedCount += 1UL;
        }
        // 补一条只看这一个类型内部的判据（issue #200 的正题：66 个非核心类型此前完全没有
        // 硬判据）。必须等 8 个槽位都写完才有全貌，所以放在内层循环之后。
        KswordARKObjectTypeApplyTypeConsistencyRule(
            isCoreType,
            &rows[typeRowStart],
            response->returnedCount - typeRowStart);
        typesEmitted += 1UL;
    }
    response->nextIndex = nextIndex;
    if (skippedTypes) {
        response->flags |= KSWORD_ARK_OBJTYPE_RESPONSE_FLAG_SKIPPED_TYPES;
    }
    if (truncated) {
        response->flags |= KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_TRUNCATED;
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_BUFFER_TRUNCATED;
        response->lastStatus = STATUS_BUFFER_OVERFLOW;
    }
    else if (partial) {
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_PARTIAL;
        response->lastStatus = STATUS_PARTIAL_COPY;
    }
    else {
        response->status = KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_OK;
        response->lastStatus = STATUS_SUCCESS;
    }
    *BytesWrittenOut = KSW_OBJTYPE_PROC_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY));

Cleanup:
    if (discovery != NULL) {
        // 先归还类型对象引用，再释放工作区（引用清单就存在工作区里）。
        KswordARKObjectTypeReleaseList(discovery);
        ExFreePoolWithTag(discovery, KSW_OBJTYPE_PROC_DISCOVERY_POOL_TAG);
    }
    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKernelObjectIoctlEnumTypeProcedures(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    校验并派发 IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES。

Return Value:

    WDF 缓冲校验或响应构建状态。

--*/
{
    KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_REQUEST* queryRequest = NULL;
    // requestSnapshot 在后端清零共用 SystemBuffer 前保存完整请求。
    KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_REQUEST requestSnapshot;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Device);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    if (InputBufferLength < sizeof(*queryRequest) ||
        OutputBufferLength < KSW_OBJTYPE_PROC_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(*queryRequest),
        (PVOID*)&queryRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status) || actualInputLength < sizeof(*queryRequest)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    if (queryRequest->version != KSWORD_ARK_OBJECT_TYPE_PROCEDURES_PROTOCOL_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }
    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSW_OBJTYPE_PROC_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return KswordARKObjectTypeProceduresBuildResponse(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        BytesReturned);
}
