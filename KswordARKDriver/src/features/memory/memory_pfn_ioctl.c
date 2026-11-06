// Bounded read-only PFN evidence via the Memory Manager's identity query.
// No PFN database offsets, physical contents, private locks, or pointer chasing.
#include "ark/ark_driver.h"
#include "driver/KswordArkPfnIoctl.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"
#include "../../../../third_party/systeminformer_dyn/PfnNative.h"

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

// Check the x64 native ABI before passing any buffer to the kernel service.
C_ASSERT(sizeof(KSW_PF_IDENTITY) == 24);
C_ASSERT(FIELD_OFFSET(KSW_PF_QUERY, Pages) == 192);
C_ASSERT(sizeof(KSW_PF_PRIVATE_INFO) == 96);

// Query a fixed, internally selected class; never relay caller-controlled pointers.
static NTSTATUS KswPfnNative(ULONG InfoClass, PVOID Buffer, ULONG Length)
{
    KSW_PF_SUPERFETCH info = { 0 }; // Initialize padding and all optional fields.
    info.Version = 45UL; // Supported Superfetch ABI version.
    info.Magic = 0x6B756843UL; // Superfetch query signature.
    info.InfoClass = InfoClass; // Only read classes 6 and 8 are used below.
    info.Buffer = Buffer; // Kernel allocation owned by this request.
    info.Length = Length; // Checked and bounded allocation length.
    return ZwQuerySystemInformation(79UL, &info, sizeof(info), NULL); // Query only.
}

// Fill a caller-owned response from an immutable copy of the buffered request.
NTSTATUS KswordARKMemoryIoctlQueryPfnBatch(
    WDFDEVICE Device, WDFREQUEST Request, size_t InputBufferLength,
    size_t OutputBufferLength, size_t* BytesReturned)
{
    KSWORD_ARK_PFN_REQUEST request = { 0 }; // METHOD_BUFFERED input can alias output.
    KSWORD_ARK_PFN_RESPONSE* response = NULL; // WDF output is validated below.
    PVOID input = NULL; // WDF input, never dereferenced before retrieval succeeds.
    PVOID output = NULL; // WDF output, never dereferenced before retrieval succeeds.
    PVOID nativeBuffer = NULL; // Single bounded allocation freed on every path.
    PULONGLONG indices = NULL; // Optional arbitrary-PFN input, copied before output aliases it.
    size_t actual = 0; // Actual WDF buffer size.
    ULONG capacity = 0; // Maximum output records for the selected operation.
    ULONG elementBytes = 0; // Fixed protocol record width.
    ULONG nativeBytes = 0; // Bounded native request size.
    NTSTATUS status; // Preserve errors as explicit query evidence.
    UNREFERENCED_PARAMETER(Device); // No device-specific state is changed.
    if (BytesReturned == NULL) { // The dispatch layer supplies it today; keep the handler contract safe.
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0; // Failed packets expose no uninitialized output.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { // Native enumeration can block.
        return STATUS_INVALID_DEVICE_STATE; // Never issue this query at elevated IRQL.
    }
    if (InputBufferLength < sizeof(request)) { // Reject truncated protocol layouts.
        return STATUS_INFO_LENGTH_MISMATCH; // No partial input interpretation.
    }
    status = KswordARKValidateDeviceIoControlWriteAccess(Request); // Require authorized device access.
    if (!NT_SUCCESS(status)) { return status; } // Preserve access failure.
    status = KswordARKRetrieveRequiredInputBuffer(Request, sizeof(request), &input, &actual); // Validate input.
    if (!NT_SUCCESS(status)) { return status; } // No read on failed retrieval.
    RtlCopyMemory(&request, input, sizeof(request)); // Snapshot before zeroing aliased output.
    if (request.version != KSWORD_ARK_PFN_VERSION || request.reserved != 0UL) { // Validate protocol.
        return STATUS_INVALID_PARAMETER; // Fail closed on unknown flags/version.
    }
    if (request.operation == KSWORD_ARK_PFN_RANGES) { // Enumerate NT-managed RAM extents.
        capacity = KSWORD_ARK_PFN_MAX_RANGES; // Bound both enumeration and output.
        elementBytes = sizeof(KSWORD_ARK_PFN_RANGE); // Fixed range ABI.
    } else if (request.operation == KSWORD_ARK_PFN_PAGES || request.operation == KSWORD_ARK_PFN_IDENTITIES) { // Query bounded PFNs.
        if (request.count == 0 || request.count > KSWORD_ARK_PFN_MAX_PAGES ||
            request.firstPfn > ((1ULL << 40) - request.count)) { // Validate PFN arithmetic.
            return STATUS_INVALID_PARAMETER; // Reject overflow or unbounded work.
        }
        capacity = request.count; // One result per requested PFN.
        elementBytes = sizeof(KSWORD_ARK_PFN_IDENTITY); // Fixed identity ABI.
    } else if (request.operation == KSWORD_ARK_PFN_OWNERS) { // Resolve private-page process keys.
        capacity = KSWORD_ARK_PFN_MAX_OWNERS; // Cap native process enumeration.
        elementBytes = sizeof(KSWORD_ARK_PFN_OWNER); // Fixed owner ABI.
    } else { return STATUS_INVALID_PARAMETER; } // No setter or arbitrary native-class relay.
    if (InputBufferLength != sizeof(request) + (request.operation == KSWORD_ARK_PFN_IDENTITIES ? (size_t)capacity * sizeof(ULONGLONG) : 0)) {
        return STATUS_INFO_LENGTH_MISMATCH; // Reject truncated or surplus PFN arrays.
    }
    if (OutputBufferLength < sizeof(*response) + (size_t)capacity * elementBytes) { // Validate capacity.
        return STATUS_BUFFER_TOO_SMALL; // No truncation hidden as success.
    }
    status = KswordARKRetrieveRequiredOutputBuffer(Request,
        sizeof(*response) + (size_t)capacity * elementBytes, &output, &actual); // Retrieve validated output.
    if (!NT_SUCCESS(status)) { return status; } // Return retrieval error unchanged.
    if (request.operation == KSWORD_ARK_PFN_IDENTITIES) { // Preserve variable input before writing METHOD_BUFFERED output.
        indices = KswordARKAllocateNonPagedPool((size_t)capacity * sizeof(ULONGLONG), 'iPsK'); // Bounded 32 KiB maximum.
        if (indices == NULL) { return STATUS_INSUFFICIENT_RESOURCES; } // No aliasing fallback.
        RtlCopyMemory(indices, (PUCHAR)input + sizeof(request), (size_t)capacity * sizeof(ULONGLONG)); // Caller PFN values only.
    }
    RtlZeroMemory(output, sizeof(*response) + (size_t)capacity * elementBytes); // No kernel data leakage.
    response = (KSWORD_ARK_PFN_RESPONSE*)output; // Header precedes normalized payload.
    response->version = KSWORD_ARK_PFN_VERSION; // Identify the response ABI.
    response->operation = request.operation; // Caller can verify operation consistency.
    response->timestamp100ns = KeQueryInterruptTime(); // Per-batch timestamp, not an atomic system snapshot.
    if (request.operation == KSWORD_ARK_PFN_RANGES) { // Use the supported physical range enumerator.
        PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges(); // Allocated range array with terminator.
        KSWORD_ARK_PFN_RANGE* rows = (KSWORD_ARK_PFN_RANGE*)(response + 1); // Fixed output records.
        status = ranges != NULL ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES; // Preserve allocation failure.
        if (ranges != NULL) { // Read only the OS-owned range array.
            ULONG i; // Bounded enumeration cursor.
            for (i = 0; i < capacity && ranges[i].NumberOfBytes.QuadPart != 0; ++i) { // Stop at sentinel.
                rows[i].firstPfn = (ULONGLONG)ranges[i].BaseAddress.QuadPart >> PAGE_SHIFT; // PFN base.
                rows[i].pageCount = (ULONGLONG)ranges[i].NumberOfBytes.QuadPart >> PAGE_SHIFT; // PFN count.
            }
            response->count = i; // Publish only initialized records.
            if (i == capacity) { status = STATUS_BUFFER_OVERFLOW; } // Mark possible range truncation.
            ExFreePool(ranges); // Release the OS range allocation.
        }
    } else {
        nativeBytes = request.operation != KSWORD_ARK_PFN_OWNERS
            ? FIELD_OFFSET(KSW_PF_QUERY, Pages) + capacity * (ULONG)sizeof(KSW_PF_IDENTITY)
            : FIELD_OFFSET(KSW_PF_PRIVATE_QUERY, Sources) + capacity * (ULONG)sizeof(KSW_PF_PRIVATE_INFO); // Checked bounded sizes.
        nativeBuffer = KswordARKAllocateNonPagedPool(nativeBytes, 'fPsK'); // Private query scratch space.
        status = nativeBuffer != NULL ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES; // Allocation evidence.
        if (nativeBuffer != NULL) { // Initialize before entering native code.
            RtlZeroMemory(nativeBuffer, nativeBytes); // Deterministic optional fields.
            if (request.operation != KSWORD_ARK_PFN_OWNERS) { // Identity query.
                KSW_PF_QUERY* query = (KSW_PF_QUERY*)nativeBuffer; // Native layout checked above.
                query->Version = 1UL; // Native PFN ABI version.
                query->Count = capacity; // Native output is bounded by this count.
                for (ULONG i = 0; i < capacity; ++i) { // Initialize every requested identity.
                    query->Pages[i].Pfn = (ULONG_PTR)(indices != NULL ? indices[i] : request.firstPfn + i); // Initialized bounded input.
                    if (query->Pages[i].Pfn >= (1ULL << 40)) { status = STATUS_INVALID_PARAMETER; } // Check every arbitrary PFN.
                    query->Pages[i].Frame = ~0ULL; // Unwritten records stay invalid, not free/private pages.
                }
                if (NT_SUCCESS(status)) { status = KswPfnNative(6UL, query, nativeBytes); } // Read only validated PFNs.
                if (NT_SUCCESS(status) && query->Count == capacity) { // Validate returned record count.
                    RtlCopyMemory(response + 1, query->Pages, capacity * sizeof(KSW_PF_IDENTITY)); // Identical fixed-width ABI.
                    response->count = capacity; // Publish only after successful query.
                } else if (NT_SUCCESS(status)) { status = STATUS_DATA_ERROR; } // Reject malformed native output.
            } else { // Private source query.
                KSW_PF_PRIVATE_QUERY* query = (KSW_PF_PRIVATE_QUERY*)nativeBuffer; // Native owner layout.
                KSWORD_ARK_PFN_OWNER* rows = (KSWORD_ARK_PFN_OWNER*)(response + 1); // Normalized output.
                query->Version = 8UL; // Modern private-source ABI.
                query->Count = capacity; // Cap the source array.
                status = KswPfnNative(8UL, query, nativeBytes); // Read-only private-source enumeration.
                if (NT_SUCCESS(status) && query->Count <= capacity) { // Validate before indexing.
                    for (ULONG i = 0; i < query->Count; ++i) { // Only process sources have process ownership.
                        if (query->Sources[i].Source.Type == 2UL) { // PfsPrivateSourceProcess.
                            KSWORD_ARK_PFN_OWNER* row = &rows[response->count++]; // Bounded normalized record.
                            row->processKey = (ULONGLONG)(ULONG_PTR)query->Sources[i].EProcess & 0xFFFFFFFFFFFFULL; // 48-bit identity key.
                            row->processId = query->Sources[i].Source.ProcessId; // Native process identifier.
                            row->sessionId = query->Sources[i].SessionId; // Native session identifier.
                            RtlCopyMemory(row->imageName, query->Sources[i].ImageName, sizeof(row->imageName)); // Fixed bounded name.
                        }
                    }
                } else if (NT_SUCCESS(status)) { status = STATUS_DATA_ERROR; } // Reject out-of-bounds count.
            }
            ExFreePoolWithTag(nativeBuffer, 'fPsK'); // Release per-request scratch allocation.
        }
    }
    response->nativeStatus = status; // Query failure is visible even with a valid protocol header.
    if (indices != NULL) { ExFreePoolWithTag(indices, 'iPsK'); } // Release the optional immutable index list.
    if (!NT_SUCCESS(status)) { response->count = 0UL; } // Failed records must never be counted.
    *BytesReturned = sizeof(*response) + (size_t)response->count * elementBytes; // Exact initialized extent.
    return STATUS_SUCCESS; // The header reports the underlying query status separately.
}
