/*++

Module Name:

    memory_kernel_evidence.c

Abstract:

    Read-only kernel memory evidence collector for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_memory_evidence.h"
#include "memory_evidence_enrichment.h"
#include "memory_kernel_exec_scan_internal.h"

#include <ntimage.h>
#include <ntstrsafe.h>

#define KSW_MEMORY_EVIDENCE_TAG 'eKsK'
#define KSW_MEMORY_EVIDENCE_SYSTEM_BIG_POOL_INFORMATION_CLASS 0x42UL
#define KSW_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW))

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef struct _KSW_MEMORY_EVIDENCE_BIGPOOL_ENTRY
{
    union
    {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged;
    } Address;
    SIZE_T SizeInBytes;
    union
    {
        UCHAR TagChars[4];
        ULONG TagUlong;
    } Tag;
} KSW_MEMORY_EVIDENCE_BIGPOOL_ENTRY, *PKSW_MEMORY_EVIDENCE_BIGPOOL_ENTRY;

typedef struct _KSW_MEMORY_EVIDENCE_BIGPOOL_INFORMATION
{
    ULONG Count;
    KSW_MEMORY_EVIDENCE_BIGPOOL_ENTRY AllocatedInfo[1];
} KSW_MEMORY_EVIDENCE_BIGPOOL_INFORMATION, *PKSW_MEMORY_EVIDENCE_BIGPOOL_INFORMATION;

typedef struct _KSW_MEMORY_EVIDENCE_LIMITS
{
    ULONG EffectiveFlags;
    ULONG MaxRows;
    ULONG MaxBigPoolRows;
    ULONG SampleBytes;
    ULONG64 MaxBytes;
} KSW_MEMORY_EVIDENCE_LIMITS;

typedef struct _KSW_MEMORY_EVIDENCE_STATE
{
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE* Response;
    ULONG RowCapacity;
    ULONG ReturnedRows;
    ULONG64 BytesScanned;
    BOOLEAN Truncated;
    BOOLEAN BudgetExhausted;
} KSW_MEMORY_EVIDENCE_STATE;

static BOOLEAN
KswordARKMemoryEvidenceRangeIntersects(
    _In_ ULONG64 RangeStart,
    _In_ ULONG64 RangeEnd,
    _In_ const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* Request
    )
/*++

Routine Description:

    Test whether a half-open candidate range intersects the optional request range.

Arguments:

    RangeStart - Candidate range start address.
    RangeEnd - Candidate range end address.
    Request - Evidence request containing startAddress/endAddress filters.

Return Value:

    TRUE when the candidate must be considered; FALSE when it can be skipped.

--*/
{
    ULONG64 filterEnd = 0ULL;

    if (Request == NULL || RangeEnd <= RangeStart) {
        return FALSE;
    }
    if (Request->startAddress == 0ULL && Request->endAddress == 0ULL) {
        return TRUE;
    }

    filterEnd = (Request->endAddress == 0ULL) ? MAXULONGLONG : Request->endAddress;
    if (RangeEnd <= Request->startAddress || RangeStart >= filterEnd) {
        return FALSE;
    }
    return TRUE;
}

static NTSTATUS
KswordARKMemoryEvidenceValidateRequest(
    _In_ const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* Request,
    _Out_ KSW_MEMORY_EVIDENCE_LIMITS* LimitsOut
    )
/*++

Routine Description:

    Validate evidence scan flags, reserved fields, range bounds, and cost limits.

Arguments:

    Request - User-mode request copied from METHOD_BUFFERED input.
    LimitsOut - Receives effective bounded flags and scan limits.

Return Value:

    STATUS_SUCCESS when valid; STATUS_INVALID_PARAMETER for unknown flags, bad
    reserved fields, reversed ranges, missing non-module range, or excessive caps.

--*/
{
    KSW_MEMORY_EVIDENCE_LIMITS limits;

    if (Request == NULL || LimitsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&limits, sizeof(limits));

    if (Request->reserved0 != 0UL || Request->reserved1 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    limits.EffectiveFlags = Request->flags;
    if (limits.EffectiveFlags == 0UL) {
        limits.EffectiveFlags =
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES |
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;
    }
    if ((limits.EffectiveFlags & ~(KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_ALL |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_COMPARE_BIGPOOL_MODULES)) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((limits.EffectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_COMPARE_BIGPOOL_MODULES) != 0UL &&
        (limits.EffectiveFlags & (KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
         KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL)) == 0UL) {
        return STATUS_INVALID_PARAMETER; // 没有大池请求时无法应用这项模块归属比较。
    }

    if (Request->startAddress != 0ULL &&
        Request->endAddress != 0ULL &&
        Request->endAddress <= Request->startAddress) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((limits.EffectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES) != 0UL &&
        (Request->startAddress == 0ULL || Request->endAddress == 0ULL || Request->endAddress <= Request->startAddress)) {
        return STATUS_INVALID_PARAMETER;
    }

    limits.MaxRows = Request->maxRows;
    if (limits.MaxRows == 0UL) {
        limits.MaxRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS;
    }
    if (limits.MaxRows > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS) {
        return STATUS_INVALID_PARAMETER;
    }

    limits.MaxBigPoolRows = Request->maxBigPoolRows;
    if (limits.MaxBigPoolRows == 0UL) {
        limits.MaxBigPoolRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS;
    }
    if (limits.MaxBigPoolRows > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BIGPOOL_ROWS) {
        return STATUS_INVALID_PARAMETER;
    }

    limits.SampleBytes = Request->sampleBytes;
    if (limits.SampleBytes == 0UL) {
        limits.SampleBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES;
    }
    if (limits.SampleBytes > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_SAMPLE_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    limits.MaxBytes = Request->maxBytes;
    if (limits.MaxBytes == 0ULL) {
        limits.MaxBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES;
    }
    if (limits.MaxBytes > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    *LimitsOut = limits;
    return STATUS_SUCCESS;
}

static VOID
KswordARKMemoryEvidenceInitRow(
    _Out_ KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* Row,
    _In_ ULONG EvidenceKind,
    _In_ ULONG64 VirtualAddress,
    _In_ ULONG64 RegionSize,
    _In_ ULONG PageSize
    )
/*++

Routine Description:

    Initialize one evidence row with protocol defaults.

Arguments:

    Row - Row to initialize.
    EvidenceKind - Source/classification kind for the row.
    VirtualAddress - Region start address.
    RegionSize - Region size in bytes.
    PageSize - Observed page size, or PAGE_SIZE when unknown.

Return Value:

    None. The function writes only Row.

--*/
{
    if (Row == NULL) {
        return;
    }

    RtlZeroMemory(Row, sizeof(*Row));
    Row->rowSize = sizeof(*Row);
    Row->evidenceKind = EvidenceKind;
    Row->virtualAddress = VirtualAddress;
    Row->regionSize = RegionSize;
    Row->pageSize = PageSize;
    Row->ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_UNKNOWN;
    Row->confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_UNKNOWN;
    Row->backingKind = KSWORD_ARK_MEMORY_EVIDENCE_BACKING_UNKNOWN;
    Row->sectionHintStatus = KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_UNAVAILABLE;
    Row->lastStatus = STATUS_SUCCESS;
    Row->hashAlgorithm = KSWORD_ARK_MEMORY_EVIDENCE_HASH_NONE;
}

static VOID
KswordARKMemoryEvidenceCopyWideLiteral(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_z_ PCWSTR Source
    )
/*++

Routine Description:

    Copy a literal wide string into a bounded protocol field.

Arguments:

    Destination - Destination WCHAR buffer.
    DestinationChars - Destination capacity in WCHARs.
    Source - Optional source string.

Return Value:

    None. Destination is NUL-terminated when capacity is nonzero.

--*/
{
    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }
    Destination[0] = L'\0';
    if (Source != NULL) {
        (VOID)RtlStringCchCopyW(Destination, DestinationChars, Source);
    }
}

static VOID
KswordARKMemoryEvidenceCopyAnsiToWide(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_reads_bytes_(SourceBytes) const UCHAR* Source,
    _In_ ULONG SourceBytes
    )
/*++

Routine Description:

    Copy bounded ANSI module text into a WCHAR protocol field.

Arguments:

    Destination - Destination WCHAR buffer.
    DestinationChars - Destination capacity in WCHARs.
    Source - Bounded ANSI source bytes.
    SourceBytes - Source byte limit.

Return Value:

    None. Bytes are widened directly for display-only owner names.

--*/
{
    ULONG index = 0UL;

    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }
    Destination[0] = L'\0';
    if (Source == NULL || SourceBytes == 0UL) {
        return;
    }

    for (index = 0UL; index + 1UL < DestinationChars && index < SourceBytes; ++index) {
        if (Source[index] == '\0') {
            break;
        }
        Destination[index] = (WCHAR)Source[index];
    }
    Destination[index] = L'\0';
}

static VOID
KswordARKMemoryEvidenceCopySectionName(
    _Out_writes_bytes_(DestinationBytes) UCHAR* Destination,
    _In_ ULONG DestinationBytes,
    _In_reads_bytes_(SourceBytes) const UCHAR* Source,
    _In_ ULONG SourceBytes
    )
/*++

Routine Description:

    Copy an 8-byte PE section name into a row field.

Arguments:

    Destination - Destination byte array.
    DestinationBytes - Destination byte capacity.
    Source - Source bytes.
    SourceBytes - Source byte count.

Return Value:

    None. Destination is zero-filled before copying.

--*/
{
    ULONG index = 0UL;

    if (Destination == NULL || DestinationBytes == 0UL) {
        return;
    }
    RtlZeroMemory(Destination, DestinationBytes);
    if (Source == NULL || SourceBytes == 0UL) {
        return;
    }

    for (index = 0UL; index < DestinationBytes && index < SourceBytes; ++index) {
        Destination[index] = Source[index];
        if (Source[index] == '\0') {
            break;
        }
    }
}

static CHAR
KswordARKMemoryEvidenceLowerAnsi(
    _In_ CHAR Character
    )
/*++

Routine Description:

    Lowercase an ASCII byte for pool-tag heuristics.

Arguments:

    Character - Input byte.

Return Value:

    Lowercase ASCII byte or the original byte.

--*/
{
    if (Character >= 'A' && Character <= 'Z') {
        return (CHAR)(Character + ('a' - 'A'));
    }
    return Character;
}

static BOOLEAN
KswordARKMemoryEvidenceTagContains3(
    _In_reads_bytes_(4) const UCHAR TagChars[4],
    _In_ CHAR A,
    _In_ CHAR B,
    _In_ CHAR C
    )
/*++

Routine Description:

    Check whether a four-byte tag contains a case-insensitive three-byte token.

Arguments:

    TagChars - BigPool tag bytes.
    A - First token byte.
    B - Second token byte.
    C - Third token byte.

Return Value:

    TRUE when the token appears at tag offset 0 or 1; otherwise FALSE.

--*/
{
    ULONG index = 0UL;

    if (TagChars == NULL) {
        return FALSE;
    }
    for (index = 0UL; index <= 1UL; ++index) {
        if (KswordARKMemoryEvidenceLowerAnsi((CHAR)TagChars[index]) == KswordARKMemoryEvidenceLowerAnsi(A) &&
            KswordARKMemoryEvidenceLowerAnsi((CHAR)TagChars[index + 1UL]) == KswordARKMemoryEvidenceLowerAnsi(B) &&
            KswordARKMemoryEvidenceLowerAnsi((CHAR)TagChars[index + 2UL]) == KswordARKMemoryEvidenceLowerAnsi(C)) {
            return TRUE;
        }
    }
    return FALSE;
}

static ULONG64
KswordARKMemoryEvidenceFnv1a64(
    _In_reads_bytes_(BytesToHash) const UCHAR* Bytes,
    _In_ ULONG BytesToHash
    )
/*++

Routine Description:

    Compute an FNV-1a 64-bit hash over an already-local memory sample.

Arguments:

    Bytes - Sample bytes.
    BytesToHash - Sample length.

Return Value:

    Hash value, or zero when no bytes are supplied.

--*/
{
    ULONG index = 0UL;
    ULONG64 hash = 1469598103934665603ULL;

    if (Bytes == NULL || BytesToHash == 0UL) {
        return 0ULL;
    }
    for (index = 0UL; index < BytesToHash; ++index) {
        hash ^= (ULONG64)Bytes[index];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static BOOLEAN
KswordARKMemoryEvidenceReadVirtualSafe(
    _In_ ULONG64 VirtualAddress,
    _Out_writes_bytes_(BytesToRead) VOID* Destination,
    _In_ SIZE_T BytesToRead
    )
/*++

Routine Description:

    Copy kernel virtual memory into local storage with MmCopyMemory and SEH.

Arguments:

    VirtualAddress - Source virtual address.
    Destination - Destination buffer.
    BytesToRead - Bytes to copy.

Return Value:

    TRUE on an exact copy; FALSE on exception, failing status, or short copy.

--*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copiedBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (VirtualAddress == 0ULL || Destination == NULL || BytesToRead == 0U) {
        return FALSE;
    }
    RtlZeroMemory(Destination, BytesToRead);

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)(ULONG_PTR)VirtualAddress;
    __try {
        status = MmCopyMemory(
            Destination,
            copyAddress,
            BytesToRead,
            MM_COPY_MEMORY_VIRTUAL,
            &copiedBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(Destination, BytesToRead);
        return FALSE;
    }

    if (!NT_SUCCESS(status) || copiedBytes != BytesToRead) {
        RtlZeroMemory(Destination, BytesToRead);
        return FALSE;
    }
    return TRUE;
}

static VOID
KswordARKMemoryEvidencePermissionFromPage(
    _In_ const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* PageInfo,
    _Out_ ULONG* PermissionFlagsOut,
    _Out_ ULONG* RiskFlagsOut,
    _Out_ ULONG* ConfidenceOut
    )
/*++

Routine Description:

    Convert page-table effective flags to evidence permission/risk/confidence fields.

Arguments:

    PageInfo - Read-only page-table query result.
    PermissionFlagsOut - Receives P/R/W/X/NX/Large/Global/User bits.
    RiskFlagsOut - Receives page-level RWX and LargeExecutable risks.
    ConfidenceOut - Receives confidence score for the observation.

Return Value:

    None. Outputs are zeroed when input is invalid.

--*/
{
    ULONG permissionFlags = 0UL;
    ULONG riskFlags = 0UL;
    ULONG confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_UNKNOWN;

    if (PermissionFlagsOut != NULL) {
        *PermissionFlagsOut = 0UL;
    }
    if (RiskFlagsOut != NULL) {
        *RiskFlagsOut = 0UL;
    }
    if (ConfidenceOut != NULL) {
        *ConfidenceOut = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_UNKNOWN;
    }
    if (PageInfo == NULL) {
        return;
    }

    if ((PageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) != 0UL) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_PRESENT |
            KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_READ;
    }
    if ((PageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE) != 0UL) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE;
    }
    if ((PageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) != 0UL) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_NX;
    }
    else if ((PageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) != 0UL) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE;
    }
    if ((PageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE) != 0UL ||
        PageInfo->largePageType != KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_NONE) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_LARGE;
        riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE;
    }
    if ((PageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_GLOBAL) != 0UL) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_GLOBAL;
    }
    if ((PageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_USER) != 0UL) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_USER;
    }
    if ((permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) != 0UL &&
        (permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE) != 0UL) {
        riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX;
    }

    if (PageInfo->queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK && PageInfo->resolved != 0UL) {
        confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_HIGH;
    }
    else if (PageInfo->queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_NOT_PRESENT) {
        confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_LOW;
    }
    else {
        confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_MEDIUM;
    }

    if (PermissionFlagsOut != NULL) {
        *PermissionFlagsOut = permissionFlags;
    }
    if (RiskFlagsOut != NULL) {
        *RiskFlagsOut = riskFlags;
    }
    if (ConfidenceOut != NULL) {
        *ConfidenceOut = confidence;
    }
}

static BOOLEAN
KswordARKMemoryEvidenceSectionIsTextLike(
    _In_ const IMAGE_SECTION_HEADER* SectionHeader
    )
/*++

Routine Description:

    Classify a PE section as text/code-like.

Arguments:

    SectionHeader - Section header copied from kernel image memory.

Return Value:

    TRUE for IMAGE_SCN_CNT_CODE or .text-like names; otherwise FALSE.

--*/
{
    if (SectionHeader == NULL) {
        return FALSE;
    }
    if ((SectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) != 0UL) {
        return TRUE;
    }
    return SectionHeader->Name[0] == '.' &&
        (SectionHeader->Name[1] == 't' || SectionHeader->Name[1] == 'T') &&
        (SectionHeader->Name[2] == 'e' || SectionHeader->Name[2] == 'E') &&
        (SectionHeader->Name[3] == 'x' || SectionHeader->Name[3] == 'X') &&
        (SectionHeader->Name[4] == 't' || SectionHeader->Name[4] == 'T');
}

static BOOLEAN
KswordARKMemoryEvidenceReadSections(
    _In_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* ModuleEntry,
    _Out_writes_(KSWORD_ARK_KERNEL_EXEC_MAX_SECTION_HEADERS) IMAGE_SECTION_HEADER* SectionHeaders,
    _Out_ ULONG* SectionCountOut
    )
/*++

Routine Description:

    Copy a module PE section table into local storage using safe image reads.

Arguments:

    ModuleEntry - Loaded kernel module snapshot row.
    SectionHeaders - Caller-provided fixed section header array.
    SectionCountOut - Receives section count used by the scanner.

Return Value:

    TRUE when PE headers are readable and section count is within the hard cap.

--*/
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG sectionTableRva = 0UL;
    ULONG sectionCount = 0UL;
    ULONG sectionIndex = 0UL;

    if (ModuleEntry == NULL || SectionHeaders == NULL || SectionCountOut == NULL) {
        return FALSE;
    }
    *SectionCountOut = 0UL;
    RtlZeroMemory(&dosHeader, sizeof(dosHeader));
    RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
    RtlZeroMemory(SectionHeaders, sizeof(IMAGE_SECTION_HEADER) * KSWORD_ARK_KERNEL_EXEC_MAX_SECTION_HEADERS);

    if (!KswordARKHookReadImageBytes(ModuleEntry, 0UL, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0) {
        return FALSE;
    }
    if (!KswordARKHookReadImageNtHeaders(ModuleEntry, &ntHeaders)) {
        return FALSE;
    }
    if (ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > KSWORD_ARK_KERNEL_EXEC_MAX_SECTION_HEADERS) {
        return FALSE;
    }
    if ((ULONG)dosHeader.e_lfanew > MAXULONG - (ULONG)FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) ||
        (ULONG)dosHeader.e_lfanew + (ULONG)FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) >
            MAXULONG - (ULONG)ntHeaders.FileHeader.SizeOfOptionalHeader) {
        return FALSE;
    }

    sectionTableRva =
        (ULONG)dosHeader.e_lfanew +
        (ULONG)FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        (ULONG)ntHeaders.FileHeader.SizeOfOptionalHeader;
    sectionCount = (ULONG)ntHeaders.FileHeader.NumberOfSections;

    for (sectionIndex = 0UL; sectionIndex < sectionCount; ++sectionIndex) {
        ULONG sectionRva = 0UL;
        if (!KswordARKHookAddRvaOffset(
            sectionTableRva,
            sectionIndex,
            (ULONG)sizeof(IMAGE_SECTION_HEADER),
            &sectionRva)) {
            break;
        }
        (VOID)KswordARKHookReadImageBytes(
            ModuleEntry,
            sectionRva,
            &SectionHeaders[sectionIndex],
            sizeof(SectionHeaders[sectionIndex]));
    }

    *SectionCountOut = sectionCount;
    return TRUE;
}

static BOOLEAN
KswordARKMemoryEvidenceClassifyPageSection(
    _In_reads_(SectionCount) const IMAGE_SECTION_HEADER* SectionHeaders,
    _In_ ULONG SectionCount,
    _In_ ULONG64 ModuleBase,
    _In_ ULONG ModuleSize,
    _In_ ULONG64 PageAddress,
    _In_ ULONG PageSize,
    _Out_ BOOLEAN* IsTextLikeOut,
    _Out_ BOOLEAN* IsWritableOut,
    _Out_ ULONG* SectionRvaOut,
    _Out_ ULONG* SectionSizeOut,
    _Out_writes_bytes_(KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES) UCHAR* SectionNameOut
    )
/*++

Routine Description:

    Find sections overlapping a page and derive text/writable metadata.

Arguments:

    SectionHeaders - Local section header array.
    SectionCount - Number of entries.
    ModuleBase - Loaded image base.
    ModuleSize - Loaded image size.
    PageAddress - Page or large-page base address.
    PageSize - Page size from page-table walk.
    IsTextLikeOut - TRUE only when all overlapping sections are text-like.
    IsWritableOut - TRUE when any overlapping section is writable.
    SectionRvaOut - First overlapping section RVA.
    SectionSizeOut - First overlapping section size.
    SectionNameOut - First overlapping section name.

Return Value:

    TRUE when at least one valid section overlaps; otherwise FALSE.

--*/
{
    ULONG sectionIndex = 0UL;
    ULONG64 pageEnd = 0ULL;
    ULONG64 moduleEnd = 0ULL;
    BOOLEAN sawSection = FALSE;
    BOOLEAN sawText = FALSE;
    BOOLEAN sawNonText = FALSE;
    BOOLEAN sawWritable = FALSE;

    if (IsTextLikeOut != NULL) {
        *IsTextLikeOut = FALSE;
    }
    if (IsWritableOut != NULL) {
        *IsWritableOut = FALSE;
    }
    if (SectionRvaOut != NULL) {
        *SectionRvaOut = 0UL;
    }
    if (SectionSizeOut != NULL) {
        *SectionSizeOut = 0UL;
    }
    if (SectionNameOut != NULL) {
        RtlZeroMemory(SectionNameOut, KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES);
    }

    if (SectionHeaders == NULL || SectionCount == 0UL || ModuleSize == 0UL || PageSize == 0UL) {
        return FALSE;
    }
    if ((ULONG64)ModuleSize > MAXULONGLONG - ModuleBase) {
        return FALSE;
    }
    moduleEnd = ModuleBase + (ULONG64)ModuleSize;
    pageEnd = ((ULONG64)PageSize > MAXULONGLONG - PageAddress) ? MAXULONGLONG : PageAddress + (ULONG64)PageSize;

    for (sectionIndex = 0UL; sectionIndex < SectionCount; ++sectionIndex) {
        const IMAGE_SECTION_HEADER* sectionHeader = &SectionHeaders[sectionIndex];
        ULONG sectionSize = sectionHeader->Misc.VirtualSize;
        ULONG64 sectionStart = 0ULL;
        ULONG64 sectionEnd = 0ULL;

        if (sectionSize == 0UL) {
            sectionSize = sectionHeader->SizeOfRawData;
        }
        if (sectionSize == 0UL || sectionHeader->VirtualAddress >= ModuleSize) {
            continue;
        }
        if ((ULONG64)sectionHeader->VirtualAddress > MAXULONGLONG - ModuleBase) {
            continue;
        }

        sectionStart = ModuleBase + (ULONG64)sectionHeader->VirtualAddress;
        sectionEnd = ((ULONG64)sectionSize > MAXULONGLONG - sectionStart) ? moduleEnd : sectionStart + (ULONG64)sectionSize;
        if (sectionEnd > moduleEnd || sectionEnd < sectionStart) {
            sectionEnd = moduleEnd;
        }
        if (pageEnd <= sectionStart || PageAddress >= sectionEnd) {
            continue;
        }

        sawSection = TRUE;
        if (KswordARKMemoryEvidenceSectionIsTextLike(sectionHeader)) {
            sawText = TRUE;
        }
        else {
            sawNonText = TRUE;
        }
        if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) != 0UL) {
            sawWritable = TRUE;
        }
        if (SectionRvaOut != NULL && *SectionRvaOut == 0UL) {
            *SectionRvaOut = sectionHeader->VirtualAddress;
        }
        if (SectionSizeOut != NULL && *SectionSizeOut == 0UL) {
            *SectionSizeOut = sectionSize;
        }
        if (SectionNameOut != NULL && SectionNameOut[0] == '\0') {
            KswordARKMemoryEvidenceCopySectionName(
                SectionNameOut,
                KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES,
                sectionHeader->Name,
                KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES);
        }
    }

    if (IsTextLikeOut != NULL) {
        *IsTextLikeOut = (sawText && !sawNonText) ? TRUE : FALSE;
    }
    if (IsWritableOut != NULL) {
        *IsWritableOut = sawWritable;
    }
    return sawSection;
}

static BOOLEAN
KswordARKMemoryEvidenceConsumeBudget(
    _Inout_ KSW_MEMORY_EVIDENCE_STATE* State,
    _In_ ULONG64 Bytes
    )
/*++

Routine Description:

    Account scan cost against maxBytes before probing another page/range.

Arguments:

    State - Mutable evidence scan state.
    Bytes - Bytes represented by the next probe.

Return Value:

    TRUE when scanning may proceed; FALSE when the budget is exhausted.

--*/
{
    if (State == NULL || State->Response == NULL) {
        return FALSE;
    }
    if (State->BytesScanned >= State->Response->maxBytes ||
        Bytes > State->Response->maxBytes - State->BytesScanned) {
        State->BudgetExhausted = TRUE;
        State->Truncated = TRUE;
        State->BytesScanned = State->Response->maxBytes;
        return FALSE;
    }
    State->BytesScanned += Bytes;
    return TRUE;
}

static VOID
KswordARKMemoryEvidenceAppendRow(
    _Inout_ KSW_MEMORY_EVIDENCE_STATE* State,
    _In_ const KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* Row
    )
/*++

Routine Description:

    Append a row if row capacity remains while always counting totalRows.

Arguments:

    State - Mutable evidence scan state.
    Row - Candidate row.

Return Value:

    None. The function updates response counts and truncation state.

--*/
{
    if (State == NULL || State->Response == NULL || Row == NULL) {
        return;
    }

    State->Response->totalRows += 1UL;
    if (State->ReturnedRows >= State->RowCapacity) {
        State->Truncated = TRUE;
        return;
    }

    RtlCopyMemory(&State->Response->rows[State->ReturnedRows], Row, sizeof(*Row));
    ++State->ReturnedRows;
    State->Response->returnedRows = State->ReturnedRows;
}

static VOID
KswordARKMemoryEvidenceFillSample(
    _Inout_ KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* Row,
    _In_ ULONG64 VirtualAddress,
    _In_ ULONG SampleBytes
    )
/*++

Routine Description:

    Read a bounded memory sample and calculate its FNV-1a hash.

Arguments:

    Row - Row receiving sample metadata.
    VirtualAddress - Source memory address.
    SampleBytes - Requested sample length.

Return Value:

    None. Failed reads leave sampleSize zero and hashAlgorithm NONE.

--*/
{
    ULONG sampleLength = SampleBytes;

    if (Row == NULL || sampleLength == 0UL) {
        return;
    }
    if (sampleLength > KSWORD_ARK_MEMORY_EVIDENCE_SECTION_SAMPLE_BYTES) {
        sampleLength = KSWORD_ARK_MEMORY_EVIDENCE_SECTION_SAMPLE_BYTES;
    }
    if (!KswordARKMemoryEvidenceReadVirtualSafe(VirtualAddress, Row->sample, sampleLength)) {
        Row->sampleSize = 0UL;
        Row->hashAlgorithm = KSWORD_ARK_MEMORY_EVIDENCE_HASH_NONE;
        Row->contentHash = 0ULL;
        return;
    }

    Row->sampleSize = sampleLength;
    Row->hashAlgorithm = KSWORD_ARK_MEMORY_EVIDENCE_HASH_FNV1A64;
    Row->contentHash = KswordARKMemoryEvidenceFnv1a64(Row->sample, sampleLength);
}

static VOID
KswordARKMemoryEvidenceFillModuleRow(
    _Out_ KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* Row,
    _In_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* ModuleEntry,
    _In_ const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* PageInfo,
    _In_ ULONG64 PageAddress,
    _In_ BOOLEAN IsTextLike,
    _In_ BOOLEAN IsWritableSection,
    _In_ ULONG SectionRva,
    _In_ ULONG SectionSize,
    _In_reads_bytes_(KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES) const UCHAR* SectionName,
    _In_ ULONG SampleBytes
    )
/*++

Routine Description:

    Build one loaded-module executable/text evidence row.

Arguments:

    Row - Output row.
    ModuleEntry - Loaded module snapshot entry.
    PageInfo - Read-only page-table result.
    PageAddress - Page or large-page base address.
    IsTextLike - TRUE when PE section metadata is text/code-like.
    IsWritableSection - TRUE when PE section metadata is writable.
    SectionRva - First overlapping section RVA.
    SectionSize - First overlapping section size.
    SectionName - First overlapping section name.
    SampleBytes - Number of bytes to sample from memory.

Return Value:

    None. The function writes only Row.

--*/
{
    ULONG permissionFlags = 0UL;
    ULONG riskFlags = 0UL;
    ULONG confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_UNKNOWN;
    ULONG pageSize = (PageInfo != NULL && PageInfo->pageSize != 0UL) ? PageInfo->pageSize : PAGE_SIZE;

    KswordARKMemoryEvidenceInitRow(
        Row,
        IsTextLike ? KSWORD_ARK_MEMORY_EVIDENCE_KIND_TEXT_SECTION_MEMORY : KSWORD_ARK_MEMORY_EVIDENCE_KIND_EXECUTABLE_RANGE,
        PageAddress,
        (ULONG64)pageSize,
        pageSize);
    if (Row == NULL || ModuleEntry == NULL || PageInfo == NULL) {
        return;
    }

    KswordARKMemoryEvidencePermissionFromPage(PageInfo, &permissionFlags, &riskFlags, &confidence);
    Row->permissionFlags = permissionFlags;
    Row->ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_LOADED_MODULE;
    Row->riskFlags = riskFlags;
    Row->confidence = confidence;
    Row->backingKind = KSWORD_ARK_MEMORY_EVIDENCE_BACKING_LOADED_MODULE;
    Row->sectionHintStatus = KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_NOT_APPLICABLE;
    Row->moduleBase = (ULONG64)(ULONG_PTR)ModuleEntry->ImageBase;
    Row->moduleSize = ModuleEntry->ImageSize;
    Row->ownerAddress = Row->moduleBase;
    if (ModuleEntry->Section != NULL) {
        Row->sectionObjectAddress = (ULONG64)(ULONG_PTR)ModuleEntry->Section;
        Row->rowFlags |= KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_SECTION_OBJECT_PRESENT;
        Row->sectionHintStatus = KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_SECTION_PRESENT;
    }
    Row->lastStatus = PageInfo->walkStatus;
    Row->sectionRva = SectionRva;
    Row->sectionSize = SectionSize;
    KswordARKMemoryEvidenceCopySectionName(
        Row->sectionName,
        KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES,
        SectionName,
        KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES);
    KswordARKMemoryEvidenceCopyAnsiToWide(
        Row->ownerName,
        KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NAME_CHARS,
        ModuleEntry->FullPathName,
        (ULONG)sizeof(ModuleEntry->FullPathName));

    if (!IsTextLike) {
        Row->riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE;
    }
    if (IsWritableSection && (Row->permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) != 0UL) {
        Row->riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX;
    }

    KswordARKMemoryEvidenceFillSample(Row, PageAddress, SampleBytes);
    (VOID)RtlStringCchPrintfW(
        Row->detail,
        KSWORD_ARK_MEMORY_EVIDENCE_DETAIL_CHARS,
        L"module section text=%lu writableSection=%lu sectionRva=0x%lX sectionSize=0x%lX",
        IsTextLike ? 1UL : 0UL,
        IsWritableSection ? 1UL : 0UL,
        SectionRva,
        SectionSize);
}

static NTSTATUS
KswordARKMemoryEvidenceScanModule(
    _Inout_ KSW_MEMORY_EVIDENCE_STATE* State,
    _In_ const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* Request,
    _In_ const KSW_MEMORY_EVIDENCE_LIMITS* Limits,
    _In_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* ModuleEntry
    )
/*++

Routine Description:

    Scan one loaded module for executable text and non-text pages.

Arguments:

    State - Mutable response state.
    Request - Original request with range filter.
    Limits - Effective scan limits.
    ModuleEntry - Loaded module snapshot entry.

Return Value:

    STATUS_SUCCESS when processed or skipped; first page-query failure otherwise.

--*/
{
    IMAGE_SECTION_HEADER sectionHeaders[KSWORD_ARK_KERNEL_EXEC_MAX_SECTION_HEADERS];
    ULONG sectionCount = 0UL;
    ULONG64 moduleBase = 0ULL;
    ULONG64 moduleEnd = 0ULL;
    ULONG64 pageAddress = 0ULL;
    BOOLEAN includeLoaded = FALSE;
    BOOLEAN includeTextSamples = FALSE;
    NTSTATUS firstFailure = STATUS_SUCCESS;

    if (State == NULL || Request == NULL || Limits == NULL || ModuleEntry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    includeLoaded = (Limits->EffectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE) != 0UL;
    includeTextSamples = (Limits->EffectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES) != 0UL;
    if (!includeLoaded && !includeTextSamples) {
        return STATUS_SUCCESS;
    }
    if (!KswordARKKernelExecSafeModuleRange(ModuleEntry, &moduleBase, &moduleEnd)) {
        return STATUS_SUCCESS;
    }
    if (!KswordARKMemoryEvidenceRangeIntersects(moduleBase, moduleEnd, Request)) {
        return STATUS_SUCCESS;
    }
    if (!KswordARKMemoryEvidenceReadSections(ModuleEntry, sectionHeaders, &sectionCount)) {
        return STATUS_SUCCESS;
    }

    pageAddress = KswordARKKernelExecAlignDown(moduleBase, PAGE_SIZE);
    if (Request->startAddress != 0ULL && pageAddress < Request->startAddress) {
        pageAddress = KswordARKKernelExecAlignDown(Request->startAddress, PAGE_SIZE);
    }
    if (pageAddress < moduleBase) {
        pageAddress = moduleBase;
    }

    while (pageAddress < moduleEnd) {
        KSWORD_ARK_PAGE_TABLE_ENTRY_INFO pageInfo;
        KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW row;
        UCHAR sectionName[KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES];
        ULONG sectionRva = 0UL;
        ULONG sectionSize = 0UL;
        ULONG pageSize = PAGE_SIZE;
        ULONG64 nextAddress = 0ULL;
        BOOLEAN isTextLike = FALSE;
        BOOLEAN isWritableSection = FALSE;
        NTSTATUS status = STATUS_SUCCESS;

        if (Request->endAddress != 0ULL && pageAddress >= Request->endAddress) {
            break;
        }
        if (!KswordARKMemoryEvidenceConsumeBudget(State, PAGE_SIZE)) {
            break;
        }

        RtlZeroMemory(&pageInfo, sizeof(pageInfo));
        status = KswordARKKernelExecQueryPage(pageAddress, &pageInfo);
        if (!NT_SUCCESS(status)) {
            if (NT_SUCCESS(firstFailure)) {
                firstFailure = status;
            }
            pageAddress += PAGE_SIZE;
            continue;
        }
        if (pageInfo.queryStatus != KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK ||
            pageInfo.resolved == 0UL ||
            (pageInfo.effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) == 0UL) {
            pageAddress += PAGE_SIZE;
            continue;
        }

        pageSize = (pageInfo.pageSize != 0UL) ? pageInfo.pageSize : PAGE_SIZE;
        if (pageSize > PAGE_SIZE &&
            !KswordARKMemoryEvidenceConsumeBudget(State, (ULONG64)pageSize - (ULONG64)PAGE_SIZE)) {
            break;
        }
        nextAddress = pageAddress + (ULONG64)pageSize;
        if (nextAddress <= pageAddress) {
            break;
        }
        if ((pageInfo.effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) != 0UL) {
            pageAddress = nextAddress;
            continue;
        }

        RtlZeroMemory(sectionName, sizeof(sectionName));
        if (!KswordARKMemoryEvidenceClassifyPageSection(
            sectionHeaders,
            sectionCount,
            moduleBase,
            ModuleEntry->ImageSize,
            pageAddress,
            pageSize,
            &isTextLike,
            &isWritableSection,
            &sectionRva,
            &sectionSize,
            sectionName)) {
            pageAddress = nextAddress;
            continue;
        }
        if (isTextLike && !includeTextSamples && !includeLoaded) {
            pageAddress = nextAddress;
            continue;
        }
        if (!isTextLike && !includeLoaded) {
            pageAddress = nextAddress;
            continue;
        }

        KswordARKMemoryEvidenceFillModuleRow(
            &row,
            ModuleEntry,
            &pageInfo,
            pageAddress,
            isTextLike,
            isWritableSection,
            sectionRva,
            sectionSize,
            sectionName,
            Limits->SampleBytes);
        KswordARKMemoryEvidenceAppendRow(State, &row);
        if (State->Truncated) {
            break;
        }
        pageAddress = nextAddress;
    }

    return firstFailure;
}

static BOOLEAN
KswordARKMemoryEvidenceModuleRangesUsable(
    _In_reads_bytes_(Bytes) const KSW_HOOK_SYSTEM_MODULE_INFORMATION* Modules,
    _In_ ULONG Bytes)
{
    const ULONG header = FIELD_OFFSET(KSW_HOOK_SYSTEM_MODULE_INFORMATION, Modules); // 模块数组的真实起点。
    ULONG i = 0UL; // 只在完整的返回缓冲区内读取条目。
    if (Modules == NULL || Bytes < header || Modules->NumberOfModules == 0UL ||
        Modules->NumberOfModules > (Bytes - header) / sizeof(Modules->Modules[0])) {
        return FALSE; // 截断、空目录都不能作为未命中归属的证据。
    }
    for (i = 0; i < Modules->NumberOfModules; ++i) {
        const ULONG_PTR base = (ULONG_PTR)Modules->Modules[i].ImageBase; // 检查每个范围的半开区间。
        const ULONG size = Modules->Modules[i].ImageSize; // 内核模块实际报告的映像大小。
        if (base == 0U || size == 0UL || base > MAXULONG_PTR - size) {
            return FALSE; // 隐去或溢出的条目使目录无法证明“模块外”。
        }
    }
    return TRUE; // 只证明枚举时可用的加载模块视图。
}

static NTSTATUS
KswordARKMemoryEvidenceScanModules(
    _Inout_ KSW_MEMORY_EVIDENCE_STATE* State,
    _In_ const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* Request,
    _In_ const KSW_MEMORY_EVIDENCE_LIMITS* Limits,
    _Inout_opt_ KSW_HOOK_SYSTEM_MODULE_INFORMATION** ModuleInfoOut
    )
/*++

Routine Description:

    Query SystemModuleInformation and scan loaded module executable evidence.

Arguments:

    State - Mutable response state.
    Request - Original request.
    Limits - Effective scan limits.
    ModuleInfoOut - Optional snapshot returned to the caller for reuse.

Return Value:

    STATUS_SUCCESS or the first snapshot/page-query failure status.

--*/
{
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG moduleIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS firstFailure = STATUS_SUCCESS;

    if (State == NULL || State->Response == NULL || Request == NULL || Limits == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (ModuleInfoOut != NULL) {
        *ModuleInfoOut = NULL;
    }

    status = KswordARKHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    State->Response->lastStatus = status;
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!KswordARKMemoryEvidenceModuleRangesUsable(moduleInfo, moduleInfoBytes)) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG); // 不向后续采样移交无效的模块范围。
        return STATUS_DATA_ERROR; // 归属未核实，不能报告模块外页。
    }
    State->Response->moduleCount = moduleInfo->NumberOfModules;

    for (moduleIndex = 0UL; moduleIndex < moduleInfo->NumberOfModules; ++moduleIndex) {
        status = KswordARKMemoryEvidenceScanModule(State, Request, Limits, &moduleInfo->Modules[moduleIndex]);
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
        if (State->Truncated || State->BudgetExhausted) {
            break;
        }
    }

    if (ModuleInfoOut != NULL) {
        *ModuleInfoOut = moduleInfo;
    }
    else {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    return firstFailure;
}

static BOOLEAN
KswordARKMemoryEvidenceCanMergeNonModule(
    _In_ const KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* Left,
    _In_ const KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* Right
    )
/*++

Routine Description:

    Decide whether two non-module executable rows are contiguous and compatible.

Arguments:

    Left - Current aggregate row.
    Right - New candidate row.

Return Value:

    TRUE when Right can extend Left; otherwise FALSE.

--*/
{
    ULONG64 leftEnd = 0ULL;

    if (Left == NULL || Right == NULL || Left->pageSize == 0UL) {
        return FALSE;
    }
    if (Left->ownerKind != Right->ownerKind ||
        Left->permissionFlags != Right->permissionFlags ||
        Left->pageSize != Right->pageSize ||
        Left->riskFlags != Right->riskFlags ||
        Left->rowFlags != Right->rowFlags ||
        Left->backingKind != Right->backingKind ||
        Left->sectionHintStatus != Right->sectionHintStatus) {
        return FALSE;
    }
    if (Left->regionSize > MAXULONGLONG - Left->virtualAddress) {
        return FALSE;
    }
    leftEnd = Left->virtualAddress + Left->regionSize;
    return Right->virtualAddress == leftEnd;
}

static VOID
KswordARKMemoryEvidenceFillNonModuleRow(
    _Out_ KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* Row,
    _In_ ULONG64 PageAddress,
    _In_ const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* PageInfo,
    _In_ ULONG SampleBytes
    )
/*++

Routine Description:

    Build one executable page row for an address outside loaded module ranges.

Arguments:

    Row - Output evidence row.
    PageAddress - Page or large-page base address.
    PageInfo - Read-only page-table query result.
    SampleBytes - Number of bytes to sample.

Return Value:

    None. The function writes only Row.

--*/
{
    ULONG permissionFlags = 0UL;
    ULONG riskFlags = 0UL;
    ULONG confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_UNKNOWN;
    ULONG pageSize = (PageInfo != NULL && PageInfo->pageSize != 0UL) ? PageInfo->pageSize : PAGE_SIZE;

    KswordARKMemoryEvidenceInitRow(
        Row,
        KSWORD_ARK_MEMORY_EVIDENCE_KIND_EXECUTABLE_RANGE,
        PageAddress,
        (ULONG64)pageSize,
        pageSize);
    if (Row == NULL || PageInfo == NULL) {
        return;
    }

    KswordARKMemoryEvidencePermissionFromPage(PageInfo, &permissionFlags, &riskFlags, &confidence);
    Row->permissionFlags = permissionFlags;
    Row->ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NONMODULE;
    Row->backingKind = KSWORD_ARK_MEMORY_EVIDENCE_BACKING_PRIVATE;
    Row->rowFlags = KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_NONMODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_SECTION_HINT_UNAVAILABLE;
    Row->riskFlags = riskFlags |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING;
    if ((permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE) != 0UL &&
        (permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) != 0UL) {
        Row->rowFlags |= KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_RWX_PRIVATE;
    }
    else if ((permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) != 0UL) {
        Row->rowFlags |= KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_RX_PRIVATE;
        Row->riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_RX_PRIVATE;
    }
    Row->sectionHintStatus = KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_UNAVAILABLE;
    Row->confidence = confidence;
    Row->lastStatus = PageInfo->walkStatus;
    KswordARKMemoryEvidenceCopyWideLiteral(Row->ownerName, KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NAME_CHARS, L"NonModule");
    KswordARKMemoryEvidenceFillSample(Row, PageAddress, SampleBytes);
    KswordARKMemoryEvidenceApplyImageLikeHint(Row);
    (VOID)RtlStringCchCopyW(
        Row->detail,
        KSWORD_ARK_MEMORY_EVIDENCE_DETAIL_CHARS,
        L"bounded range executable private/non-module page; section hint unavailable");
}

static NTSTATUS
KswordARKMemoryEvidenceScanNonModuleRange(
    _Inout_ KSW_MEMORY_EVIDENCE_STATE* State,
    _In_ const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* Request,
    _In_ const KSW_MEMORY_EVIDENCE_LIMITS* Limits,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo
    )
/*++

Routine Description:

    Scan a caller-bounded range for executable pages outside loaded modules.

Arguments:

    State - Mutable response state.
    Request - Request with required startAddress/endAddress bounds.
    Limits - Effective scan limits.
    ModuleInfo - Reused loaded module snapshot.

Return Value:

    STATUS_SUCCESS or first page-query failure status.

--*/
{
    ULONG64 pageAddress = 0ULL;
    KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW aggregate;
    BOOLEAN haveAggregate = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS firstFailure = STATUS_SUCCESS;

    if (State == NULL || State->Response == NULL || Request == NULL || Limits == NULL || ModuleInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((Limits->EffectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES) == 0UL) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&aggregate, sizeof(aggregate));
    pageAddress = KswordARKKernelExecAlignDown(Request->startAddress, PAGE_SIZE);
    while (pageAddress < Request->endAddress) {
        KSWORD_ARK_PAGE_TABLE_ENTRY_INFO pageInfo;
        KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW row;
        ULONG pageSize = PAGE_SIZE;
        ULONG64 nextAddress = 0ULL;

        if (KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)pageAddress) != NULL) {
            pageAddress += PAGE_SIZE;
            continue;
        }
        if (!KswordARKMemoryEvidenceConsumeBudget(State, PAGE_SIZE)) {
            break;
        }

        RtlZeroMemory(&pageInfo, sizeof(pageInfo));
        status = KswordARKKernelExecQueryPage(pageAddress, &pageInfo);
        if (!NT_SUCCESS(status)) {
            if (NT_SUCCESS(firstFailure)) {
                firstFailure = status;
            }
            pageAddress += PAGE_SIZE;
            continue;
        }
        if (pageInfo.queryStatus != KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK ||
            pageInfo.resolved == 0UL ||
            (pageInfo.effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) == 0UL ||
            (pageInfo.effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) != 0UL) {
            pageAddress += PAGE_SIZE;
            continue;
        }

        pageSize = (pageInfo.pageSize != 0UL) ? pageInfo.pageSize : PAGE_SIZE;
        if (pageSize > PAGE_SIZE &&
            !KswordARKMemoryEvidenceConsumeBudget(State, (ULONG64)pageSize - (ULONG64)PAGE_SIZE)) {
            break;
        }
        nextAddress = pageAddress + (ULONG64)pageSize;
        if (nextAddress <= pageAddress) {
            break;
        }
        KswordARKMemoryEvidenceFillNonModuleRow(&row, pageAddress, &pageInfo, Limits->SampleBytes);

        if (haveAggregate && KswordARKMemoryEvidenceCanMergeNonModule(&aggregate, &row)) {
            aggregate.regionSize += row.regionSize;
            aggregate.contentHash ^= row.contentHash;
        }
        else {
            if (haveAggregate) {
                KswordARKMemoryEvidenceAppendRow(State, &aggregate);
                if (State->Truncated) {
                    break;
                }
            }
            aggregate = row;
            haveAggregate = TRUE;
        }
        pageAddress = nextAddress;
    }

    if (haveAggregate && !State->Truncated) {
        KswordARKMemoryEvidenceAppendRow(State, &aggregate);
    }
    return firstFailure;
}

static VOID
KswordARKMemoryEvidenceFillTagWide(
    _In_reads_bytes_(4) const UCHAR TagChars[4],
    _Out_writes_(5) WCHAR TagText[5]
    )
/*++

Routine Description:

    Convert a four-byte BigPool tag into printable WCHAR text.

Arguments:

    TagChars - Raw BigPool tag bytes.
    TagText - Five-WCHAR destination including terminator.

Return Value:

    None. NUL bytes are displayed as spaces.

--*/
{
    ULONG index = 0UL;

    if (TagText == NULL) {
        return;
    }
    for (index = 0UL; index < 4UL; ++index) {
        UCHAR ch = (TagChars != NULL) ? TagChars[index] : ' ';
        TagText[index] = (WCHAR)(ch == 0U ? ' ' : ch);
    }
    TagText[4] = L'\0';
}

static NTSTATUS
KswordARKMemoryEvidenceScanBigPool(
    _Inout_ KSW_MEMORY_EVIDENCE_STATE* State,
    _In_ const KSW_MEMORY_EVIDENCE_LIMITS* Limits,
    _In_opt_ KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo
    )
/*++

Routine Description:

    Query SystemBigPoolInformation and emit bounded BigPool evidence rows.

Arguments:

    State - Mutable response state.
    Limits - Effective BigPool and scan-cost limits.

Return Value:

    STATUS_SUCCESS or ZwQuerySystemInformation/allocation failure status.

--*/
{
    PVOID buffer = NULL;
    ULONG bufferBytes = 0UL;
    ULONG rowIndex = 0UL;
    ULONG count = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (State == NULL || State->Response == NULL || Limits == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((Limits->EffectiveFlags & (KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL)) == 0UL) {
        return STATUS_SUCCESS;
    }

    status = ZwQuerySystemInformation(
        KSW_MEMORY_EVIDENCE_SYSTEM_BIG_POOL_INFORMATION_CLASS,
        NULL,
        0UL,
        &bufferBytes);
    if (bufferBytes == 0UL) {
        State->Response->lastStatus = NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
        return State->Response->lastStatus;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    buffer = ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSW_MEMORY_EVIDENCE_TAG);
#pragma warning(pop)
    if (buffer == NULL) {
        State->Response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(
        KSW_MEMORY_EVIDENCE_SYSTEM_BIG_POOL_INFORMATION_CLASS,
        buffer,
        bufferBytes,
        &bufferBytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, KSW_MEMORY_EVIDENCE_TAG);
        State->Response->lastStatus = status;
        return status;
    }

    count = ((KSW_MEMORY_EVIDENCE_BIGPOOL_INFORMATION*)buffer)->Count;
    for (rowIndex = 0UL; rowIndex < count; ++rowIndex) {
        KSW_MEMORY_EVIDENCE_BIGPOOL_ENTRY* entry = NULL;
        KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW row;
        KSWORD_ARK_PAGE_TABLE_ENTRY_INFO pageInfo;
        WCHAR tagText[5];
        ULONG permissionFlags = 0UL;
        ULONG pageRiskFlags = 0UL;
        ULONG confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_LOW;
        ULONG bigPoolFlags = 0UL;
        ULONG ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_BIGPOOL;
        ULONG riskFlags = 0UL;
        ULONG64 rawAddress = 0ULL;
        ULONG64 address = 0ULL;
        ULONG64 size = 0ULL;
        BOOLEAN isExecutable = FALSE;
        BOOLEAN isSuspicious = FALSE;

        if (rowIndex >= Limits->MaxBigPoolRows) {
            State->Truncated = TRUE;
            State->Response->responseFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_FLAG_BIGPOOL_TRUNCATED;
            break;
        }
        entry = &((KSW_MEMORY_EVIDENCE_BIGPOOL_INFORMATION*)buffer)->AllocatedInfo[rowIndex];
        State->Response->bigPoolRowsSeen += 1UL;

        rawAddress = (ULONG64)entry->Address.NonPaged;
        address = rawAddress & ~(ULONG64)1ULL;
        size = (ULONG64)entry->SizeInBytes;
        if ((rawAddress & 1ULL) != 0ULL) {
            bigPoolFlags |= KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_NON_PAGED;
        }
        if (address == 0ULL || size == 0ULL) {
            continue;
        }

        if (KswordARKMemoryEvidenceTagContains3(entry->Tag.TagChars, 'P', 'T', 'E')) {
            ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_SYSTEM_PTE;
            bigPoolFlags |= KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_TAG_SYSTEM_PTE_LIKE;
        }
        if (KswordARKMemoryEvidenceTagContains3(entry->Tag.TagChars, 'M', 'D', 'L')) {
            ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_MDL_LIKE;
            bigPoolFlags |= KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_TAG_MDL_LIKE;
        }

        if (!KswordARKMemoryEvidenceConsumeBudget(State, PAGE_SIZE)) {
            break;
        }
        RtlZeroMemory(&pageInfo, sizeof(pageInfo));
        status = KswordARKKernelExecQueryPage(KswordARKKernelExecAlignDown(address, PAGE_SIZE), &pageInfo);
        if (NT_SUCCESS(status) && pageInfo.queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK) {
            KswordARKMemoryEvidencePermissionFromPage(&pageInfo, &permissionFlags, &pageRiskFlags, &confidence);
            if ((permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) != 0UL) {
                isExecutable = TRUE;
                bigPoolFlags |= KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_EXECUTABLE;
            }
        }

        isSuspicious = ((bigPoolFlags & KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_NON_PAGED) != 0UL &&
            (ownerKind == KSWORD_ARK_MEMORY_EVIDENCE_OWNER_SYSTEM_PTE ||
                ownerKind == KSWORD_ARK_MEMORY_EVIDENCE_OWNER_MDL_LIKE));
        if (isSuspicious) {
            bigPoolFlags |= KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_EXECUTABLE_SUSPECTED;
        }
        if (isExecutable || isSuspicious) {
            riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL;
        }
        riskFlags |= pageRiskFlags;

        if ((Limits->EffectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL) == 0UL &&
            (Limits->EffectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL) != 0UL &&
            !isExecutable && !isSuspicious) {
            continue;
        }

        KswordARKMemoryEvidenceInitRow(
            &row,
            KSWORD_ARK_MEMORY_EVIDENCE_KIND_BIGPOOL,
            address,
            size,
            (pageInfo.pageSize != 0UL) ? pageInfo.pageSize : PAGE_SIZE);
        row.permissionFlags = permissionFlags;
        row.ownerKind = ownerKind;
        row.riskFlags = riskFlags;
        // 只用实际页表的执行权限和已取得的模块清单确认模块外页面，忽略标签启发式。
        if (isExecutable && ModuleInfo != NULL && ModuleInfo->NumberOfModules != 0UL &&
            KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)address) == NULL) {
            row.riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE; // 首个采样页，不外推到整个分配。
        }
        row.confidence = confidence;
        row.backingKind = KSWORD_ARK_MEMORY_EVIDENCE_BACKING_BIGPOOL;
        row.sectionHintStatus = KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_NOT_APPLICABLE;
        row.ownerAddress = address;
        row.lastStatus = NT_SUCCESS(status) ? pageInfo.walkStatus : status;
        row.bigPoolTag = entry->Tag.TagUlong;
        row.bigPoolFlags = bigPoolFlags;
        KswordARKMemoryEvidenceCopyWideLiteral(row.ownerName, KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NAME_CHARS, L"BigPool");
        KswordARKMemoryEvidenceFillSample(&row, address, Limits->SampleBytes);
        KswordARKMemoryEvidenceApplyImageLikeHint(&row);
        KswordARKMemoryEvidenceFillTagWide(entry->Tag.TagChars, tagText);
        (VOID)RtlStringCchPrintfW(
            row.detail,
            KSWORD_ARK_MEMORY_EVIDENCE_DETAIL_CHARS,
            L"tag=%ws nonPaged=%lu executable=%lu suspected=%lu size=0x%I64X",
            tagText,
            (bigPoolFlags & KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_NON_PAGED) ? 1UL : 0UL,
            isExecutable ? 1UL : 0UL,
            isSuspicious ? 1UL : 0UL,
            size);

        KswordARKMemoryEvidenceAppendRow(State, &row);
        if (State->Truncated || State->BudgetExhausted) {
            break;
        }
    }

    ExFreePoolWithTag(buffer, KSW_MEMORY_EVIDENCE_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKDriverScanKernelMemoryEvidence(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Collect read-only kernel memory evidence rows for executable pages, BigPool,
    page-table permissions, and text-section memory samples. The routine rejects
    non-PASSIVE_LEVEL callers and never writes kernel memory, PTEs, or CR0.WP.

Arguments:

    OutputBuffer - METHOD_BUFFERED response buffer.
    OutputBufferLength - Response buffer length.
    Request - Evidence scan request with flags and cost limits.
    BytesWrittenOut - Receives response byte count.

Return Value:

    STATUS_SUCCESS when a response header is valid; response->status/lastStatus
    describe scan completeness. Parameter/buffer errors are returned directly.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE* response = NULL;
    KSW_MEMORY_EVIDENCE_LIMITS limits;
    KSW_MEMORY_EVIDENCE_STATE state;
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    size_t rowCapacitySize = 0U;
    ULONG rowCapacity = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS firstPartialStatus = STATUS_SUCCESS;

    if (OutputBuffer == NULL || Request == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;

    if (OutputBufferLength < KSW_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    rowCapacitySize = (OutputBufferLength - KSW_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW);
    rowCapacity = (rowCapacitySize > (size_t)KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS) ?
        KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS :
        (ULONG)rowCapacitySize;
    RtlZeroMemory(&limits, sizeof(limits));
    status = KswordARKMemoryEvidenceValidateRequest(Request, &limits);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (limits.MaxRows > rowCapacity) {
        limits.MaxRows = rowCapacity;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_MEMORY_EVIDENCE_STATUS_UNAVAILABLE;
    response->sourceFlags = limits.EffectiveFlags;
    response->rowSize = sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW);
    response->maxRows = limits.MaxRows;
    response->maxBytes = limits.MaxBytes;
    response->lastStatus = STATUS_SUCCESS;

    RtlZeroMemory(&state, sizeof(state));
    state.Response = response;
    state.RowCapacity = limits.MaxRows;

    if ((limits.EffectiveFlags & (
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES)) != 0UL) {
        status = KswordARKMemoryEvidenceScanModules(&state, Request, &limits, &moduleInfo);
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstPartialStatus)) {
            firstPartialStatus = status;
        }
    }

    if (!state.BudgetExhausted &&
        !state.Truncated &&
        moduleInfo != NULL &&
        (limits.EffectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES) != 0UL) {
        status = KswordARKMemoryEvidenceScanNonModuleRange(&state, Request, &limits, moduleInfo);
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstPartialStatus)) {
            firstPartialStatus = status;
        }
    }

    if (!state.BudgetExhausted && !state.Truncated) {
        if (moduleInfo == NULL && (limits.EffectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_COMPARE_BIGPOOL_MODULES) != 0UL) {
            ULONG moduleBytes = 0UL; // 只获取模块地址范围，不扫描任何已知映像的内容。
            status = KswordARKHookBuildModuleSnapshot(&moduleInfo, &moduleBytes); // 与本轮大池采样共享唯一快照。
            if (NT_SUCCESS(status) && KswordARKMemoryEvidenceModuleRangesUsable(moduleInfo, moduleBytes)) {
                response->moduleCount = moduleInfo->NumberOfModules; // 能力与实际来源完整性分开返回。
            } else {
                if (moduleInfo != NULL) {
                    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG); // 截断/隐去范围不得交给地址归属查询。
                    moduleInfo = NULL; // 后续大池行只能保留基本页表证据。
                }
                if (NT_SUCCESS(firstPartialStatus)) {
                    firstPartialStatus = NT_SUCCESS(status) ? STATUS_DATA_ERROR : status; // 清单无效与成功空扫描分开。
                }
            }
        }
        status = KswordARKMemoryEvidenceScanBigPool(&state, &limits, moduleInfo); // 大池首个执行页与本轮模块归属比对。
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstPartialStatus)) {
            firstPartialStatus = status;
        }
    }

    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG); // 最后一个消费者完成后释放模块清单。
    }
    response->returnedRows = state.ReturnedRows;
    response->bytesScanned = state.BytesScanned;
    if (state.Truncated) {
        response->responseFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_FLAG_TRUNCATED;
    }
    if (state.BudgetExhausted) {
        response->responseFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_FLAG_BUDGET_EXHAUSTED;
    }

    if (state.Truncated || state.BudgetExhausted || !NT_SUCCESS(firstPartialStatus)) {
        response->status = KSWORD_ARK_MEMORY_EVIDENCE_STATUS_PARTIAL;
        response->lastStatus = state.Truncated ? STATUS_BUFFER_TOO_SMALL : firstPartialStatus;
    }
    else {
        response->status = KSWORD_ARK_MEMORY_EVIDENCE_STATUS_OK;
        response->lastStatus = STATUS_SUCCESS;
    }

    *BytesWrittenOut = KSW_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedRows * sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW));
    return STATUS_SUCCESS;
}
