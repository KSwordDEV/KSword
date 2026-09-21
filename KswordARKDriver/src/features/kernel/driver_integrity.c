/*++
Module Name:
    driver_integrity.c
Abstract:
    Read-only DriverObject, module-view, service-key, and optional kernel-global
    evidence collection for DriverDock integrity diagnostics.
Environment:
    Kernel-mode Driver Framework
--*/
#include "driver_integrity.h"
#include "kernel_cpu_integrity.h"
#include <ntstrsafe.h>
#include <stdarg.h>
#define KSW_DRIVER_INTEGRITY_TAG 'iDsK'
#define KSW_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE))
#define KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FieldName) \
    { FIELD_OFFSET(FAST_IO_DISPATCH, FieldName), #FieldName }
#define KSW_DRIVER_INTEGRITY_DEVICE_VISIT_LIMIT 128UL
#define KSW_DRIVER_INTEGRITY_ATTACH_VISIT_LIMIT 32UL
#define KSW_DRIVER_INTEGRITY_UNLOADED_SCAN_LIMIT 50UL
#define KSW_DRIVER_INTEGRITY_RTL_AVL_TABLE_SIZE_LIMIT 0x400UL
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif
typedef PVOID
(NTAPI* KSW_DRIVER_INTEGRITY_EX_ALLOCATE_POOL2_FN)(
    _In_ POOL_FLAGS Flags,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    );
typedef NTSTATUS
(NTAPI* KSW_DRIVER_INTEGRITY_AUX_INITIALIZE_FN)(
    VOID
    );
typedef NTSTATUS
(NTAPI* KSW_DRIVER_INTEGRITY_AUX_QUERY_MODULES_FN)(
    _Inout_ PULONG BufferSize,
    _In_ ULONG ElementSize,
    _Out_writes_bytes_opt_(*BufferSize) PVOID QueryInfo
    );
typedef struct _KSW_DRIVER_INTEGRITY_AUX_MODULE_BASIC_INFO
{
    PVOID ImageBase;
} KSW_DRIVER_INTEGRITY_AUX_MODULE_BASIC_INFO, *PKSW_DRIVER_INTEGRITY_AUX_MODULE_BASIC_INFO;
typedef struct _KSW_DRIVER_INTEGRITY_AUX_MODULE_EXTENDED_INFO
{
    KSW_DRIVER_INTEGRITY_AUX_MODULE_BASIC_INFO BasicInfo;
    ULONG ImageSize;
    USHORT FileNameOffset;
    UCHAR FullPathName[256];
} KSW_DRIVER_INTEGRITY_AUX_MODULE_EXTENDED_INFO, *PKSW_DRIVER_INTEGRITY_AUX_MODULE_EXTENDED_INFO;
typedef struct _KSW_DRIVER_INTEGRITY_FAST_IO_FIELD
{
    ULONG Offset;
    PCSTR Name;
} KSW_DRIVER_INTEGRITY_FAST_IO_FIELD, *PKSW_DRIVER_INTEGRITY_FAST_IO_FIELD;
typedef struct _KSW_DRIVER_INTEGRITY_DEVICE_SNAPSHOT
{
    PDEVICE_OBJECT NextDevice;
    PDEVICE_OBJECT AttachedDevice;
    PDRIVER_OBJECT DriverObject;
    ULONG DeviceType;
    ULONG Flags;
} KSW_DRIVER_INTEGRITY_DEVICE_SNAPSHOT, *PKSW_DRIVER_INTEGRITY_DEVICE_SNAPSHOT;
typedef struct _KSW_DRIVER_INTEGRITY_PIDDB_AVL_SUMMARY
{
    ULONGLONG BalancedRootLeftChild;
    ULONGLONG BalancedRootRightChild;
    ULONGLONG BalancedRootParentValue;
    ULONGLONG OrderedPointer;
    ULONGLONG RestartKey;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    ULONG DepthOfTree;
    ULONG DeleteCount;
} KSW_DRIVER_INTEGRITY_PIDDB_AVL_SUMMARY, *PKSW_DRIVER_INTEGRITY_PIDDB_AVL_SUMMARY;
NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
    );
extern POBJECT_TYPE* IoDriverObjectType;
static const KSW_DRIVER_INTEGRITY_FAST_IO_FIELD g_KswordArkFastIoFields[] = {
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoCheckIfPossible),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoRead),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoWrite),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoQueryBasicInfo),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoQueryStandardInfo),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoLock),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoUnlockSingle),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoUnlockAll),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoUnlockAllByKey),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoDeviceControl),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(AcquireFileForNtCreateSection),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(ReleaseFileForNtCreateSection),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoDetachDevice),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoQueryNetworkOpenInfo),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(AcquireForModWrite),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(MdlRead),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(MdlReadComplete),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(PrepareMdlWrite),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(MdlWriteComplete),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoReadCompressed),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoWriteCompressed),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(MdlReadCompleteCompressed),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(MdlWriteCompleteCompressed),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(FastIoQueryOpen),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(ReleaseForModWrite),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(AcquireForCcFlush),
    KSW_DRIVER_INTEGRITY_FAST_IO_FIELD(ReleaseForCcFlush)
};
static PVOID
KswordARKDriverIntegrityAllocate(
    _In_ SIZE_T BufferBytes
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    static volatile LONG allocatorResolved = 0;
    static KSW_DRIVER_INTEGRITY_EX_ALLOCATE_POOL2_FN allocatePool2 = NULL;
    if (BufferBytes == 0U) {
        return NULL;
    }
    if (InterlockedCompareExchange(&allocatorResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        allocatePool2 = (KSW_DRIVER_INTEGRITY_EX_ALLOCATE_POOL2_FN)MmGetSystemRoutineAddress(&routineName);
    }
    if (allocatePool2 != NULL) {
        return allocatePool2(POOL_FLAG_NON_PAGED, BufferBytes, KSW_DRIVER_INTEGRITY_TAG);
    }
#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, BufferBytes, KSW_DRIVER_INTEGRITY_TAG);
#pragma warning(pop)
}
static VOID
KswordARKDriverIntegrityFormatDetail(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_z_ PCWSTR FormatText,
    ...
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    va_list arguments;
    if (Destination == NULL || DestinationChars == 0UL || FormatText == NULL) {
        return;
    }
    Destination[0] = L'\0';
    va_start(arguments, FormatText);
    (VOID)RtlStringCbVPrintfW(Destination, (SIZE_T)DestinationChars * sizeof(WCHAR), FormatText, arguments);
    va_end(arguments);
    Destination[DestinationChars - 1UL] = L'\0';
}
static VOID
KswordARKDriverIntegrityCopyUnicode(
    _In_opt_ PCUNICODE_STRING Source,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    ULONG charsToCopy = 0UL;
    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }
    Destination[0] = L'\0';
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0U) {
        return;
    }
    charsToCopy = (ULONG)(Source->Length / sizeof(WCHAR));
    if (charsToCopy >= DestinationChars) {
        charsToCopy = DestinationChars - 1UL;
    }
    RtlCopyMemory(Destination, Source->Buffer, (SIZE_T)charsToCopy * sizeof(WCHAR));
    Destination[charsToCopy] = L'\0';
}
static BOOLEAN
KswordARKDriverIntegrityDynOffsetPresent(
    _In_ ULONG Offset
    )

/* Read-only helper; returns TRUE only for explicit PDB/DynData offsets. */
{
    return (Offset != KSW_DYN_OFFSET_UNAVAILABLE && Offset != 0x0000FFFFUL) ? TRUE : FALSE;
}
static BOOLEAN
KswordARKDriverIntegrityReadUnloadedUnicodeName(
    _In_ ULONGLONG EntryAddress,
    _In_ ULONG NameOffset,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars
    )

/* Read-only helper; reads one _UNLOADED_DRIVERS.Name safely into a bounded text buffer. */
{
    UNICODE_STRING nameString;
    ULONG copyChars = 0UL;
    if (Destination == NULL || DestinationChars == 0UL) {
        return FALSE;
    }
    Destination[0] = L'\0';
    if (EntryAddress == 0ULL || !KswordARKDriverIntegrityDynOffsetPresent(NameOffset)) {
        return FALSE;
    }
    if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)(EntryAddress + (ULONGLONG)NameOffset), &nameString, sizeof(nameString))) {
        return FALSE;
    }
    if (nameString.Buffer == NULL || nameString.Length == 0U || nameString.Length > 512U || nameString.MaximumLength > 1024U) {
        return FALSE;
    }
    copyChars = (ULONG)(nameString.Length / sizeof(WCHAR));
    if (copyChars >= DestinationChars) {
        copyChars = DestinationChars - 1UL;
    }
    if (!KswordARKHookReadMemorySafe((const VOID*)nameString.Buffer, Destination, (SIZE_T)copyChars * sizeof(WCHAR))) {
        Destination[0] = L'\0';
        return FALSE;
    }
    Destination[copyChars] = L'\0';
    return TRUE;
}
static BOOLEAN
KswordARKDriverIntegrityReadUnloadedUlong64(
    _In_ ULONGLONG EntryAddress,
    _In_ ULONG FieldOffset,
    _Out_ ULONGLONG* ValueOut
    )

/* Read-only helper; reads one pointer-sized unloaded-driver field using PDB offset evidence. */
{
    if (ValueOut == NULL) {
        return FALSE;
    }
    *ValueOut = 0ULL;
    if (EntryAddress == 0ULL || !KswordARKDriverIntegrityDynOffsetPresent(FieldOffset)) {
        return FALSE;
    }
    return KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)(EntryAddress + (ULONGLONG)FieldOffset), ValueOut, sizeof(*ValueOut));
}
static BOOLEAN
KswordARKDriverIntegrityReadUlongByOffset(
    _In_ ULONGLONG BaseAddress,
    _In_ ULONG FieldOffset,
    _Out_ ULONG* ValueOut
    )

/* Read-only helper; reads one ULONG field from a PDB-gated structure offset. */
{
    if (ValueOut == NULL) {
        return FALSE;
    }
    *ValueOut = 0UL;
    if (BaseAddress == 0ULL || !KswordARKDriverIntegrityDynOffsetPresent(FieldOffset)) {
        return FALSE;
    }
    return KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)(BaseAddress + (ULONGLONG)FieldOffset), ValueOut, sizeof(*ValueOut));
}
static BOOLEAN
KswordARKDriverIntegrityReadPointerByOffset(
    _In_ ULONGLONG BaseAddress,
    _In_ ULONG FieldOffset,
    _Out_ ULONGLONG* ValueOut
    )

/* Read-only helper; reads one pointer-sized field from a PDB-gated structure offset. */
{
    PVOID pointerValue = NULL;
    if (ValueOut == NULL) {
        return FALSE;
    }
    *ValueOut = 0ULL;
    if (BaseAddress == 0ULL || !KswordARKDriverIntegrityDynOffsetPresent(FieldOffset)) {
        return FALSE;
    }
    if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)(BaseAddress + (ULONGLONG)FieldOffset), &pointerValue, sizeof(pointerValue))) {
        return FALSE;
    }
    *ValueOut = (ULONGLONG)(ULONG_PTR)pointerValue;
    return TRUE;
}
static BOOLEAN
KswordARKDriverIntegrityReadPointerAtOffset(
    _In_ ULONGLONG BaseAddress,
    _In_ ULONG FieldOffset,
    _Out_ ULONGLONG* ValueOut
    )

/* Read-only helper; reads one pointer-sized field where offset zero is valid. */
{
    PVOID pointerValue = NULL;
    if (ValueOut == NULL) {
        return FALSE;
    }
    *ValueOut = 0ULL;
    if (BaseAddress == 0ULL || FieldOffset == KSW_DYN_OFFSET_UNAVAILABLE || FieldOffset == 0x0000FFFFUL) {
        return FALSE;
    }
    if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)(BaseAddress + (ULONGLONG)FieldOffset), &pointerValue, sizeof(pointerValue))) {
        return FALSE;
    }
    *ValueOut = (ULONGLONG)(ULONG_PTR)pointerValue;
    return TRUE;
}
static NTSTATUS
KswordARKDriverIntegrityBuildDriverObjectName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* SourceName,
    _Out_writes_(DestinationChars) PWCHAR DestinationName,
    _In_ ULONG DestinationChars
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    ULONG inputChars = 0UL;
    if (SourceName == NULL || DestinationName == NULL || DestinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    DestinationName[0] = L'\0';
    while (inputChars < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS && SourceName[inputChars] != L'\0') {
        ++inputChars;
    }
    if (inputChars == 0UL || inputChars >= KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }
    if (SourceName[0] == L'\\') {
        return RtlStringCchCopyNW(DestinationName, DestinationChars, SourceName, inputChars);
    }
    return RtlStringCchPrintfW(DestinationName, DestinationChars, L"\\Driver\\%ws", SourceName);
}
static NTSTATUS
KswordARKDriverIntegrityExtractLeafName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* ObjectName,
    _Out_writes_(LeafChars) PWCHAR LeafName,
    _In_ ULONG LeafChars
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    ULONG index = 0UL;
    ULONG leafStart = 0UL;
    if (ObjectName == NULL || LeafName == NULL || LeafChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    LeafName[0] = L'\0';
    while (index < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS && ObjectName[index] != L'\0') {
        if (ObjectName[index] == L'\\') {
            leafStart = index + 1UL;
        }
        ++index;
    }
    if (index == 0UL || leafStart >= index) {
        return STATUS_INVALID_PARAMETER;
    }
    return RtlStringCchCopyW(LeafName, LeafChars, ObjectName + leafStart);
}
static BOOLEAN
KswordARKDriverIntegrityNameHasPrefix(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* ObjectName,
    _In_z_ const WCHAR* Prefix
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    ULONG index = 0UL;
    if (ObjectName == NULL || Prefix == NULL) {
        return FALSE;
    }
    while (Prefix[index] != L'\0') {
        WCHAR left = ObjectName[index];
        WCHAR right = Prefix[index];
        if (left >= L'a' && left <= L'z') {
            left = (WCHAR)(left - L'a' + L'A');
        }
        if (right >= L'a' && right <= L'z') {
            right = (WCHAR)(right - L'a' + L'A');
        }
        if (left != right) {
            return FALSE;
        }
        ++index;
    }
    return TRUE;
}
static NTSTATUS
KswordARKDriverIntegrityReferenceCandidateName(
    _In_z_ const WCHAR* CandidateName,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    UNICODE_STRING objectName;
    NTSTATUS status = STATUS_SUCCESS;
    if (CandidateName == NULL || DriverObjectOut == NULL || IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *DriverObjectOut = NULL;
    RtlInitUnicodeString(&objectName, CandidateName);
    status = ObReferenceObjectByName(&objectName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)DriverObjectOut);
    if (!NT_SUCCESS(status)) {
        *DriverObjectOut = NULL;
    }
    return status;
}
static NTSTATUS
KswordARKDriverIntegrityReferenceDriverObject(
    _In_ const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST* Request,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    WCHAR firstCandidate[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    WCHAR leafName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    WCHAR alternateName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    if (Request == NULL || DriverObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *DriverObjectOut = NULL;
    status = KswordARKDriverIntegrityBuildDriverObjectName(Request->driverName, firstCandidate, RTL_NUMBER_OF(firstCandidate));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KswordARKDriverIntegrityReferenceCandidateName(firstCandidate, DriverObjectOut);
    if (NT_SUCCESS(status) || (status != STATUS_OBJECT_NAME_NOT_FOUND && status != STATUS_OBJECT_PATH_NOT_FOUND && status != STATUS_NOT_FOUND)) {
        return status;
    }
    if (!NT_SUCCESS(KswordARKDriverIntegrityExtractLeafName(firstCandidate, leafName, RTL_NUMBER_OF(leafName)))) {
        return status;
    }
    if (!KswordARKDriverIntegrityNameHasPrefix(firstCandidate, L"\\FileSystem\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(alternateName, RTL_NUMBER_OF(alternateName), L"\\FileSystem\\%ws", leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = KswordARKDriverIntegrityReferenceCandidateName(alternateName, DriverObjectOut);
            if (NT_SUCCESS(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }
    if (!KswordARKDriverIntegrityNameHasPrefix(firstCandidate, L"\\FileSystem\\Filters\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(alternateName, RTL_NUMBER_OF(alternateName), L"\\FileSystem\\Filters\\%ws", leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = KswordARKDriverIntegrityReferenceCandidateName(alternateName, DriverObjectOut);
            if (NT_SUCCESS(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }
    return status;
}
static ULONG
KswordARKDriverIntegrityPointerRisk(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* DriverModule,
    _In_ ULONGLONG PointerValue
    )

/* Read-only helper; arguments and return behavior follow the SAL contract. */
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* ownerModule = NULL;
    ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    if (PointerValue == 0ULL) {
        return KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER;
    }
    ownerModule = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, PointerValue);
    if (ownerModule == NULL) {
        return KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
    }
    if (DriverModule != NULL && ownerModule->ImageBase != DriverModule->ImageBase) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH;
    }
    return riskFlags;
}
static KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE*
KswordARKDriverIntegrityLastEvidence(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_ ULONG EvidenceClass,
    _In_ ULONGLONG ObjectAddress,
    _In_ ULONGLONG TargetAddress
    )

/* Read-only helper; returns the last row when it matches the just-added evidence, otherwise NULL. */
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* response = NULL;
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
    if (Builder == NULL || Builder->Response == NULL || Builder->Response->returnedCount == 0UL) {
        return NULL;
    }
    response = Builder->Response;
    row = &response->entries[response->returnedCount - 1UL];
    if (row->evidenceClass != EvidenceClass || row->objectAddress != ObjectAddress || row->targetAddress != TargetAddress) {
        return NULL;
    }
    return row;
}
static ULONG
KswordARKDriverIntegrityRangeState(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* DriverModule,
    _In_ ULONGLONG Address
    )

/* Read-only helper; classifies an observed pointer into driver, other module, unresolved, or NULL range. */
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* ownerModule = NULL;
    if (Address == 0ULL) {
        return KSWORD_ARK_DRIVER_INTEGRITY_RANGE_NULL;
    }
    ownerModule = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, Address);
    if (ownerModule == NULL) {
        return KSWORD_ARK_DRIVER_INTEGRITY_RANGE_UNRESOLVED;
    }
    if (DriverModule != NULL && ownerModule->ImageBase == DriverModule->ImageBase) {
        return KSWORD_ARK_DRIVER_INTEGRITY_RANGE_IN_DRIVER;
    }
    return KSWORD_ARK_DRIVER_INTEGRITY_RANGE_IN_OTHER_MODULE;
}
static ULONG
KswordARKDriverIntegrityScoreRisk(
    _In_ ULONG RiskFlags
    )

/* Read-only helper; maps evidence bits to a bounded 0..100 score without changing system state. */
{
    ULONG score = 0UL;
    if ((RiskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED) != 0UL) {
        score += 25UL;
    }
    if ((RiskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE) != 0UL) {
        score += 20UL;
    }
    if ((RiskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED) != 0UL) {
        score += 35UL;
    }
    if ((RiskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH) != 0UL) {
        score += 45UL;
    }
    if ((RiskFlags & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH)) != 0UL) {
        score += 35UL;
    }
    if ((RiskFlags & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP | KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH)) != 0UL) {
        score += 30UL;
    }
    if ((RiskFlags & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD | KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER)) != 0UL) {
        score += 10UL;
    }
    if ((RiskFlags & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED)) != 0UL) {
        score += 50UL;
    }
    if ((RiskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID) != 0UL) {
        score += 50UL;
    }
    return (score > 100UL) ? 100UL : score;
}
static VOID
KswordARKDriverIntegrityFinalizeRows(
    _Inout_ KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* Response
    )

/* Read-only helper; fills common status, field masks, and scores after all collectors finish. */
{
    ULONG index = 0UL;
    if (Response == NULL) {
        return;
    }
    for (index = 0UL; index < Response->returnedCount; ++index) {
        KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = &Response->entries[index];
        row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_COMMON;
        if (row->ownerModuleBase != 0ULL) {
            row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_OWNER_MODULE;
        }
        if (row->processorGroup != ~0UL || row->processorNumber != ~0UL || row->vector != ~0UL) {
            row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_CPU_CONTEXT;
        }
        row->riskScore = KswordARKDriverIntegrityScoreRisk(row->riskFlags);
        row->entryStatus = (row->riskFlags == KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE) ? KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK : KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL;
        if ((row->riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED) != 0UL) {
            row->entryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_QUERY_FAILED;
        }
        if ((row->riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE) != 0UL) {
            row->entryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_UNAVAILABLE;
            row->statusFlags |= KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED;
        }
        if ((row->riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE) != 0UL) {
            row->statusFlags |= KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
        }
        if (row->riskFlags != KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE) {
            row->statusFlags |= KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL;
        }
        if ((row->statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL) != 0UL && row->entryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK) {
            row->entryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL;
        }
        Response->fieldFlags |= row->fieldMask;
        Response->statusFlags |= row->statusFlags;
    }
    if ((Response->flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED) != 0UL) {
        Response->statusFlags |= KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_TRUNCATED;
    }
}
static VOID
KswordARKDriverIntegrityAddSystemModuleRow(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ NTSTATUS ModuleStatus,
    _In_ ULONGLONG DriverStart
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* ownerModule = NULL;
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    if (!NT_SUCCESS(ModuleStatus) || ModuleInfo == NULL) {
        KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"SystemModuleInformation unavailable, status=0x%08lX.", (ULONG)ModuleStatus);
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, DriverStart,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED,
            KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, 20UL, ~0UL, ~0UL, ~0UL, NULL, detail);
        return;
    }
    ownerModule = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, DriverStart);
    if (ownerModule == NULL && DriverStart != 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
    }
    KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"SystemModuleInformation modules=%lu, target=0x%llX.", ModuleInfo->NumberOfModules, DriverStart);
    KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, DriverStart, riskFlags,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, (ownerModule != NULL) ? 95UL : 60UL, ~0UL, ~0UL, ~0UL, ownerModule, detail);
}
static VOID
KswordARKDriverIntegrityAddAuxKlibRow(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_ ULONGLONG DriverStart
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    UNICODE_STRING initName;
    UNICODE_STRING queryName;
    KSW_DRIVER_INTEGRITY_AUX_INITIALIZE_FN auxInitialize = NULL;
    KSW_DRIVER_INTEGRITY_AUX_QUERY_MODULES_FN auxQueryModules = NULL;
    KSW_DRIVER_INTEGRITY_AUX_MODULE_EXTENDED_INFO* modules = NULL;
    ULONG bufferBytes = 0UL;
    ULONG moduleCount = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    RtlInitUnicodeString(&initName, L"AuxKlibInitialize");
    RtlInitUnicodeString(&queryName, L"AuxKlibQueryModuleInformation");
    auxInitialize = (KSW_DRIVER_INTEGRITY_AUX_INITIALIZE_FN)MmGetSystemRoutineAddress(&initName);
    auxQueryModules = (KSW_DRIVER_INTEGRITY_AUX_QUERY_MODULES_FN)MmGetSystemRoutineAddress(&queryName);
    if (auxInitialize == NULL || auxQueryModules == NULL) {
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, DriverStart,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, 20UL,
            ~0UL, ~0UL, ~0UL, NULL, L"AuxKlib exports unavailable; SystemModuleInformation remains primary.");
        return;
    }
    status = auxInitialize();
    if (NT_SUCCESS(status)) {
        status = auxQueryModules(&bufferBytes, sizeof(KSW_DRIVER_INTEGRITY_AUX_MODULE_EXTENDED_INFO), NULL);
    }
    if (!(NT_SUCCESS(status) || status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH) || bufferBytes == 0UL) {
        KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"AuxKlib size query failed, status=0x%08lX.", (ULONG)status);
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, DriverStart,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, 30UL,
            ~0UL, ~0UL, ~0UL, NULL, detail);
        return;
    }
    modules = (KSW_DRIVER_INTEGRITY_AUX_MODULE_EXTENDED_INFO*)KswordARKDriverIntegrityAllocate(bufferBytes);
    if (modules == NULL) {
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, DriverStart,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, 30UL,
            ~0UL, ~0UL, ~0UL, NULL, L"AuxKlib buffer allocation failed.");
        return;
    }
    status = auxQueryModules(&bufferBytes, sizeof(KSW_DRIVER_INTEGRITY_AUX_MODULE_EXTENDED_INFO), modules);
    moduleCount = NT_SUCCESS(status) ? (bufferBytes / (ULONG)sizeof(KSW_DRIVER_INTEGRITY_AUX_MODULE_EXTENDED_INFO)) : 0UL;
    for (index = 0UL; index < moduleCount; ++index) {
        const ULONGLONG base = (ULONGLONG)(ULONG_PTR)modules[index].BasicInfo.ImageBase;
        const ULONGLONG end = base + (ULONGLONG)modules[index].ImageSize;
        if (DriverStart >= base && DriverStart < end) {
            KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"AuxKlib modules=%lu, matched base=0x%llX size=0x%lX.", moduleCount, base, modules[index].ImageSize);
            KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, DriverStart,
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, 90UL,
                ~0UL, ~0UL, ~0UL, NULL, detail);
            ExFreePoolWithTag(modules, KSW_DRIVER_INTEGRITY_TAG);
            return;
        }
    }
    KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"AuxKlib status=0x%08lX, modules=%lu, target not matched.", (ULONG)status, moduleCount);
    KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW, 0ULL, DriverStart,
        NT_SUCCESS(status) ? KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED : KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, NT_SUCCESS(status) ? 60UL : 30UL, ~0UL, ~0UL, ~0UL, NULL, detail);
    ExFreePoolWithTag(modules, KSW_DRIVER_INTEGRITY_TAG);
}
static VOID
KswordARKDriverIntegrityBuildUnloadedSummary(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ ULONGLONG MmUnloadedAddress,
    _In_ ULONGLONG MmLastUnloadedAddress,
    _Out_writes_(DetailChars) PWCHAR Detail,
    _In_ ULONG DetailChars,
    _Out_ ULONG* ConfidenceOut,
    _Out_ ULONG* StatusFlagsOut
    )

/* Read-only helper; summarizes bounded MmUnloadedDrivers entries when PDB offsets are present. */
{
    ULONG lastIndex = 0UL;
    ULONG scanIndex = 0UL;
    ULONG nonEmptyCount = 0UL;
    ULONGLONG newestStart = 0ULL;
    ULONGLONG newestEnd = 0ULL;
    ULONGLONG newestTime = 0ULL;
    ULONG entrySize = 0UL;
    ULONGLONG recordsAddress = 0ULL;
    WCHAR newestName[96] = { 0 };
    BOOLEAN offsetsPresent = FALSE;
    if (Detail == NULL || DetailChars == 0UL || ConfidenceOut == NULL || StatusFlagsOut == NULL) {
        return;
    }
    *ConfidenceOut = 45UL;
    *StatusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL;
    Detail[0] = L'\0';
    if (DynState == NULL || MmUnloadedAddress == 0ULL) {
        KswordARKDriverIntegrityFormatDetail(Detail, DetailChars, L"MmUnloadedDrivers global=0x%llX MmLastUnloadedDriver=0x%llX; global evidence incomplete.", MmUnloadedAddress, MmLastUnloadedAddress);
        *ConfidenceOut = 20UL;
        *StatusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED | KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
        return;
    }
    if (!KswordARKHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)MmUnloadedAddress,
            &recordsAddress,
            sizeof(recordsAddress)) ||
        recordsAddress == 0ULL) {
        KswordARKDriverIntegrityFormatDetail(Detail, DetailChars,
            L"MmUnloadedDrivers global=0x%llX; record array pointer is null or unreadable.",
            MmUnloadedAddress);
        *ConfidenceOut = 30UL;
        *StatusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL;
        return;
    }
    offsetsPresent =
        KswordARKDriverIntegrityDynOffsetPresent(DynState->Kernel.UldName) &&
        KswordARKDriverIntegrityDynOffsetPresent(DynState->Kernel.UldStartAddress) &&
        KswordARKDriverIntegrityDynOffsetPresent(DynState->Kernel.UldEndAddress) &&
        KswordARKDriverIntegrityDynOffsetPresent(DynState->Kernel.UldCurrentTime) &&
        KswordARKDriverIntegrityDynOffsetPresent(DynState->Kernel.UldTypeSize);
    if (!offsetsPresent) {
        KswordARKDriverIntegrityFormatDetail(Detail, DetailChars,
            L"MmUnloadedDrivers global=0x%llX MmLastUnloadedDriver=0x%llX; _UNLOADED_DRIVERS offsets/type-size missing.",
            MmUnloadedAddress, MmLastUnloadedAddress);
        *StatusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL | KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
        return;
    }
    entrySize = DynState->Kernel.UldTypeSize;
    if (entrySize < sizeof(UNICODE_STRING) || entrySize > 0x200UL) {
        KswordARKDriverIntegrityFormatDetail(Detail, DetailChars,
            L"MmUnloadedDrivers global=0x%llX MmLastUnloadedDriver=0x%llX; _UNLOADED_DRIVERS TypeSize invalid: %lu.",
            MmUnloadedAddress, MmLastUnloadedAddress, entrySize);
        *ConfidenceOut = 35UL;
        *StatusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL | KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
        return;
    }
    if (MmLastUnloadedAddress != 0ULL &&
        !KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)MmLastUnloadedAddress, &lastIndex, sizeof(lastIndex))) {
        KswordARKDriverIntegrityFormatDetail(Detail, DetailChars,
            L"MmUnloadedDrivers global=0x%llX MmLastUnloadedDriver=0x%llX; last index read failed.",
            MmUnloadedAddress, MmLastUnloadedAddress);
        *ConfidenceOut = 35UL;
        return;
    }
    for (scanIndex = 0UL; scanIndex < KSW_DRIVER_INTEGRITY_UNLOADED_SCAN_LIMIT; ++scanIndex) {
        const ULONGLONG entryAddress = recordsAddress + ((ULONGLONG)scanIndex * (ULONGLONG)entrySize);
        ULONGLONG startAddress = 0ULL;
        ULONGLONG endAddress = 0ULL;
        ULONGLONG timeValue = 0ULL;
        WCHAR nameText[96] = { 0 };
        if (!KswordARKDriverIntegrityReadUnloadedUlong64(entryAddress, DynState->Kernel.UldStartAddress, &startAddress) ||
            !KswordARKDriverIntegrityReadUnloadedUlong64(entryAddress, DynState->Kernel.UldEndAddress, &endAddress) ||
            !KswordARKDriverIntegrityReadUnloadedUlong64(entryAddress, DynState->Kernel.UldCurrentTime, &timeValue)) {
            continue;
        }
        if (startAddress == 0ULL && endAddress == 0ULL && timeValue == 0ULL) {
            continue;
        }
        nonEmptyCount += 1UL;
        if (timeValue >= newestTime) {
            newestTime = timeValue;
            newestStart = startAddress;
            newestEnd = endAddress;
            if (!KswordARKDriverIntegrityReadUnloadedUnicodeName(entryAddress, DynState->Kernel.UldName, nameText, RTL_NUMBER_OF(nameText))) {
                (VOID)RtlStringCchCopyW(nameText, RTL_NUMBER_OF(nameText), L"<name unread>");
            }
            (VOID)RtlStringCchCopyW(newestName, RTL_NUMBER_OF(newestName), nameText);
        }
    }
    KswordARKDriverIntegrityFormatDetail(Detail, DetailChars,
        L"MmUnloadedDrivers global=0x%llX records=0x%llX MmLastUnloadedDriver=0x%llX typeSize=%lu lastIndex=%lu scanned=%lu nonEmpty=%lu newest=%ws [0x%llX-0x%llX] time=0x%llX.",
        MmUnloadedAddress, recordsAddress, MmLastUnloadedAddress, entrySize, lastIndex, KSW_DRIVER_INTEGRITY_UNLOADED_SCAN_LIMIT,
        nonEmptyCount, newestName[0] != L'\0' ? newestName : L"<none>", newestStart, newestEnd, newestTime);
    *ConfidenceOut = (nonEmptyCount != 0UL) ? 70UL : 55UL;
    *StatusFlagsOut = (nonEmptyCount != 0UL) ? 0UL : KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL;
}
static VOID
KswordARKDriverIntegrityBuildPiDdbSummary(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ ULONGLONG PiDdbAddress,
    _Out_writes_(DetailChars) PWCHAR Detail,
    _In_ ULONG DetailChars,
    _Out_ ULONG* ConfidenceOut,
    _Out_ ULONG* StatusFlagsOut
    )

/* Read-only helper; summarizes the PDB-gated _RTL_AVL_TABLE header for PiDDBCacheTable. */
{
    ULONGLONG balancedRootAddress = 0ULL;
    ULONG avlTypeSize = 0UL;
    KSW_DRIVER_INTEGRITY_PIDDB_AVL_SUMMARY summary;
    BOOLEAN requiredOffsetsPresent = FALSE;
    RtlZeroMemory(&summary, sizeof(summary));
    if (Detail == NULL || DetailChars == 0UL || ConfidenceOut == NULL || StatusFlagsOut == NULL) {
        return;
    }
    *ConfidenceOut = 35UL;
    *StatusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL | KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
    Detail[0] = L'\0';
    if (DynState == NULL || PiDdbAddress == 0ULL) {
        KswordARKDriverIntegrityFormatDetail(Detail, DetailChars, L"PiDDBCacheTable global=0x%llX; global evidence incomplete.", PiDdbAddress);
        *ConfidenceOut = 20UL;
        *StatusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED | KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
        return;
    }
    requiredOffsetsPresent =
        DynState->Kernel.RtlAvlBalancedRoot != KSW_DYN_OFFSET_UNAVAILABLE &&
        DynState->Kernel.RtlAvlBalancedRoot != 0x0000FFFFUL &&
        KswordARKDriverIntegrityDynOffsetPresent(DynState->Kernel.RtlAvlNumberGenericTableElements) &&
        KswordARKDriverIntegrityDynOffsetPresent(DynState->Kernel.RtlAvlDepthOfTree) &&
        KswordARKDriverIntegrityDynOffsetPresent(DynState->Kernel.RtlAvlTypeSize);
    if (!requiredOffsetsPresent) {
        KswordARKDriverIntegrityFormatDetail(Detail, DetailChars,
            L"PiDDBCacheTable global=0x%llX; _RTL_AVL_TABLE offsets/type-size missing, entry walk disabled.",
            PiDdbAddress);
        return;
    }
    avlTypeSize = DynState->Kernel.RtlAvlTypeSize;
    if (avlTypeSize < (sizeof(PVOID) * 3U) || avlTypeSize > KSW_DRIVER_INTEGRITY_RTL_AVL_TABLE_SIZE_LIMIT) {
        KswordARKDriverIntegrityFormatDetail(Detail, DetailChars,
            L"PiDDBCacheTable global=0x%llX; _RTL_AVL_TABLE TypeSize invalid: %lu.",
            PiDdbAddress, avlTypeSize);
        return;
    }
    balancedRootAddress = PiDdbAddress + (ULONGLONG)DynState->Kernel.RtlAvlBalancedRoot;
    (VOID)KswordARKDriverIntegrityReadPointerAtOffset(balancedRootAddress, 0UL, &summary.BalancedRootLeftChild);
    (VOID)KswordARKDriverIntegrityReadPointerAtOffset(balancedRootAddress, (ULONG)sizeof(PVOID), &summary.BalancedRootRightChild);
    (VOID)KswordARKDriverIntegrityReadPointerAtOffset(balancedRootAddress, (ULONG)(sizeof(PVOID) * 2U), &summary.BalancedRootParentValue);
    (VOID)KswordARKDriverIntegrityReadPointerByOffset(PiDdbAddress, DynState->Kernel.RtlAvlOrderedPointer, &summary.OrderedPointer);
    (VOID)KswordARKDriverIntegrityReadPointerByOffset(PiDdbAddress, DynState->Kernel.RtlAvlRestartKey, &summary.RestartKey);
    (VOID)KswordARKDriverIntegrityReadUlongByOffset(PiDdbAddress, DynState->Kernel.RtlAvlWhichOrderedElement, &summary.WhichOrderedElement);
    if (!KswordARKDriverIntegrityReadUlongByOffset(PiDdbAddress, DynState->Kernel.RtlAvlNumberGenericTableElements, &summary.NumberGenericTableElements) ||
        !KswordARKDriverIntegrityReadUlongByOffset(PiDdbAddress, DynState->Kernel.RtlAvlDepthOfTree, &summary.DepthOfTree)) {
        KswordARKDriverIntegrityFormatDetail(Detail, DetailChars,
            L"PiDDBCacheTable global=0x%llX typeSize=%lu; AVL count/depth read failed.",
            PiDdbAddress, avlTypeSize);
        *ConfidenceOut = 40UL;
        return;
    }
    (VOID)KswordARKDriverIntegrityReadUlongByOffset(PiDdbAddress, DynState->Kernel.RtlAvlDeleteCount, &summary.DeleteCount);
    KswordARKDriverIntegrityFormatDetail(Detail, DetailChars,
        L"PiDDBCacheTable global=0x%llX typeSize=%lu count=%lu depth=%lu deleteCount=%lu balancedRoot=0x%llX left=0x%llX right=0x%llX parent=0x%llX ordered=0x%llX which=%lu restart=0x%llX; entry schema not yet consumed.",
        PiDdbAddress, avlTypeSize, summary.NumberGenericTableElements, summary.DepthOfTree, summary.DeleteCount,
        balancedRootAddress, summary.BalancedRootLeftChild, summary.BalancedRootRightChild,
        summary.BalancedRootParentValue, summary.OrderedPointer, summary.WhichOrderedElement, summary.RestartKey);
    *ConfidenceOut = 65UL;
    *StatusFlagsOut = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL;
}
static VOID
KswordARKDriverIntegrityAddDynRows(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_ const KSW_DYN_STATE* DynState,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONGLONG DriverSection,
    _In_ ULONGLONG DriverSize,
    _In_ ULONGLONG DriverStart,
    _In_ BOOLEAN IncludeOptionalGlobals
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    KSW_DRIVER_INTEGRITY_LDR_TARGET target;
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
    NTSTATUS ldrStatus = STATUS_SUCCESS;
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    RtlZeroMemory(&target, sizeof(target));
    ldrStatus = KswordARKDriverIntegrityFindLoadedModule(DynState, DriverStart, &target);
    if (NT_SUCCESS(ldrStatus) && target.Found) {
        const KSW_HOOK_SYSTEM_MODULE_ENTRY* ownerModule = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, target.DllBase);
        ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
        if (DriverSection != 0ULL && DriverSection != target.EntryAddress) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH;
        }
        if (DriverStart != target.DllBase || DriverSize != (ULONGLONG)target.SizeOfImage || target.SizeOfImage == 0UL) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH;
        }
        if (ModuleInfo != NULL && ownerModule == NULL) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
        }
        KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail),
            L"PsLoadedModuleList=0x%llX KLDR=0x%llX DllBase=0x%llX Size=0x%lX DriverSize=0x%llX BaseName=%ws.",
            target.ListHeadAddress, target.EntryAddress, target.DllBase, target.SizeOfImage, DriverSize,
            target.BaseDllName[0] != L'\0' ? target.BaseDllName : L"<unread>");
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES,
            DriverSection, target.DllBase, riskFlags,
            KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_PS_LOADED_MODULES | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE,
            90UL, ~0UL, ~0UL, ~0UL, ownerModule, detail);
        row = KswordARKDriverIntegrityLastEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES, DriverSection, target.DllBase); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_KLDR; row->kldrEntryAddress = target.EntryAddress; row->kldrListHeadAddress = target.ListHeadAddress; row->kldrDllBase = target.DllBase; row->kldrSizeOfImage = target.SizeOfImage; }
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION,
            DriverSection, target.EntryAddress, riskFlags,
            KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE,
            90UL, ~0UL, ~0UL, ~0UL, ownerModule, detail);
        row = KswordARKDriverIntegrityLastEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION, DriverSection, target.EntryAddress); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_KLDR; row->kldrEntryAddress = target.EntryAddress; row->kldrListHeadAddress = target.ListHeadAddress; row->kldrDllBase = target.DllBase; row->kldrSizeOfImage = target.SizeOfImage; }
    }
    else {
        KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail),
            L"PsLoadedModuleList unavailable or target not found, status=0x%08lX, listHead=0x%llX.",
            (ULONG)ldrStatus, target.ListHeadAddress);
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES, DriverSection, DriverStart,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE,
            KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_PS_LOADED_MODULES | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA, 25UL,
            ~0UL, ~0UL, ~0UL, NULL, detail);
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION, DriverSection, DriverStart,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE,
            KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA, 25UL,
            ~0UL, ~0UL, ~0UL, NULL, L"DriverSection captured; KLDR alignment unavailable or target not found through DynData.");
    }
    if (IncludeOptionalGlobals) {
        ULONGLONG mmUnloaded = KswordARKDriverIntegrityNtosAddressFromRva(DynState, DynState != NULL ? DynState->KernelGlobals.MmUnloadedDrivers : 0UL, sizeof(PVOID));
        ULONGLONG piDdb = KswordARKDriverIntegrityNtosAddressFromRva(DynState, DynState != NULL ? DynState->KernelGlobals.PiDDBCacheTable : 0UL, sizeof(PVOID));
        ULONGLONG mmLastUnloaded = KswordARKDriverIntegrityNtosAddressFromRva(DynState, DynState != NULL ? DynState->KernelGlobals.MmLastUnloadedDriver : 0UL, sizeof(ULONG));
        const KSW_HOOK_SYSTEM_MODULE_ENTRY* mmOwner = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, mmUnloaded);
        const KSW_HOOK_SYSTEM_MODULE_ENTRY* piOwner = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, piDdb);
        ULONG mmSource = KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA;
        ULONG piSource = KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA;
        ULONG mmConfidence = 45UL;
        ULONG mmStatusFlags = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL;
        ULONG piConfidence = 35UL;
        ULONG piStatusFlags = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL | KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED;
        if (mmUnloaded != 0ULL) {
            mmSource |= KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE;
        }
        if (piDdb != 0ULL) {
            piSource |= KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE;
        }
        KswordARKDriverIntegrityBuildUnloadedSummary(DynState, mmUnloaded, mmLastUnloaded, detail, RTL_NUMBER_OF(detail), &mmConfidence, &mmStatusFlags);
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL, mmUnloaded, 0ULL,
            (mmUnloaded == 0ULL) ? (KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE) : KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE,
            mmSource, (mmUnloaded == 0ULL) ? 15UL : mmConfidence, ~0UL, ~0UL, ~0UL, mmOwner, detail);
        row = KswordARKDriverIntegrityLastEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL, mmUnloaded, 0ULL); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_OPTIONAL_GLOBAL; row->statusFlags |= (mmUnloaded == 0ULL) ? KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED : mmStatusFlags; }
        KswordARKDriverIntegrityBuildPiDdbSummary(DynState, piDdb, detail, RTL_NUMBER_OF(detail), &piConfidence, &piStatusFlags);
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL, piDdb, 0ULL,
            (piDdb == 0ULL) ? (KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE) : KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE,
            piSource, (piDdb == 0ULL) ? 15UL : piConfidence, ~0UL, ~0UL, ~0UL, piOwner, detail);
        row = KswordARKDriverIntegrityLastEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL, piDdb, 0ULL); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_OPTIONAL_GLOBAL; row->statusFlags |= (piDdb == 0ULL) ? KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED : piStatusFlags; }
    }
}
static VOID
KswordARKDriverIntegrityAddDriverObjectRows(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_ PDRIVER_OBJECT DriverObject,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    const ULONGLONG driverStart = (ULONGLONG)(ULONG_PTR)DriverObject->DriverStart;
    const ULONGLONG driverSize = (ULONGLONG)DriverObject->DriverSize;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* driverModule = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, driverStart);
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
    ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    ULONG index = 0UL;
    if (driverStart == 0ULL || driverSize == 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER;
    }
    if (driverModule == NULL && driverStart != 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
    }
    if (driverModule != NULL) {
        const ULONGLONG moduleBase = (ULONGLONG)(ULONG_PTR)driverModule->ImageBase;
        const ULONGLONG moduleEnd = moduleBase + (ULONGLONG)driverModule->ImageSize;
        if (driverStart != moduleBase || driverStart + driverSize > moduleEnd || driverSize != (ULONGLONG)driverModule->ImageSize) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH;
        }
    }
    KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"DriverObject=0x%p DriverStart=0x%llX DriverSize=0x%llX DriverSection=0x%p DriverUnload=0x%p.",
        DriverObject, driverStart, driverSize, DriverObject->DriverSection, DriverObject->DriverUnload);
    KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT, (ULONGLONG)(ULONG_PTR)DriverObject, driverStart, riskFlags,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, (driverModule != NULL) ? 90UL : 55UL,
        ~0UL, ~0UL, ~0UL, driverModule, detail);
    row = KswordARKDriverIntegrityLastEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT, (ULONGLONG)(ULONG_PTR)DriverObject, driverStart); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DRIVER_OBJECT; row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)DriverObject; row->driverStart = driverStart; row->driverSize = driverSize; row->driverSection = (ULONGLONG)(ULONG_PTR)DriverObject->DriverSection; row->driverUnload = (ULONGLONG)(ULONG_PTR)DriverObject->DriverUnload; }
    KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION, (ULONGLONG)(ULONG_PTR)DriverObject->DriverSection, driverStart,
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION,
        70UL, ~0UL, ~0UL, ~0UL, driverModule, L"DriverSection captured read-only; KLDR alignment row follows when DynData is available.");
    if (DriverObject->DriverUnload == NULL) {
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT, (ULONGLONG)(ULONG_PTR)DriverObject, 0ULL,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 75UL,
            ~0UL, ~0UL, ~0UL, NULL, L"DriverObject->DriverUnload is NULL; no unload or repair attempted.");
    }
    for (index = 0UL; index < KSWORD_ARK_DRIVER_MAJOR_FUNCTION_COUNT; ++index) {
        const ULONGLONG address = (ULONGLONG)(ULONG_PTR)DriverObject->MajorFunction[index];
        KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"MajorFunction[%lu]=0x%llX.", index, address);
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION, (ULONGLONG)(ULONG_PTR)&DriverObject->MajorFunction[index], address,
            KswordARKDriverIntegrityPointerRisk(ModuleInfo, driverModule, address), KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE,
            85UL, ~0UL, ~0UL, ~0UL, KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, address), detail);
        row = KswordARKDriverIntegrityLastEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION, (ULONGLONG)(ULONG_PTR)&DriverObject->MajorFunction[index], address); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DISPATCH_TARGET | KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DRIVER_OBJECT; row->ordinal = index; row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)DriverObject; row->driverStart = driverStart; row->driverSize = driverSize; row->rangeState = KswordARKDriverIntegrityRangeState(ModuleInfo, driverModule, address); }
    }
    {
        /* DriverStartIo 三态：读取失败给出明确证据；空值属正常（多数驱动不用 StartIo 队列），不报风险；非空按指针风险归类。 */
        PVOID startIo = NULL;
        const ULONGLONG fieldAddress = (ULONGLONG)(ULONG_PTR)&DriverObject->DriverStartIo;
        if (!KswordARKHookReadMemorySafe(&DriverObject->DriverStartIo, &startIo, sizeof(startIo))) {
            KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_START_IO, fieldAddress, 0ULL,
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT,
                30UL, ~0UL, ~0UL, ~0UL, NULL, L"DriverObject->DriverStartIo read failed.");
        }
        else if (startIo == NULL) {
            KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_START_IO, fieldAddress, 0ULL,
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT,
                85UL, ~0UL, ~0UL, ~0UL, NULL, L"DriverObject->DriverStartIo is NULL.");
        }
        else {
            const ULONGLONG address = (ULONGLONG)(ULONG_PTR)startIo;
            KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"DriverStartIo=0x%llX.", address);
            KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_START_IO, fieldAddress, address,
                KswordARKDriverIntegrityPointerRisk(ModuleInfo, driverModule, address),
                KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE,
                85UL, ~0UL, ~0UL, ~0UL, KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, address), detail);
            row = KswordARKDriverIntegrityLastEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_START_IO, fieldAddress, address);
            if (row != NULL) {
                row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DISPATCH_TARGET | KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DRIVER_OBJECT;
                row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)DriverObject;
                row->driverStart = driverStart;
                row->driverSize = driverSize;
                row->rangeState = KswordARKDriverIntegrityRangeState(ModuleInfo, driverModule, address);
            }
        }
    }
    if (DriverObject->FastIoDispatch != NULL) {
        for (index = 0UL; index < RTL_NUMBER_OF(g_KswordArkFastIoFields); ++index) {
            const UCHAR* fieldAddress = (const UCHAR*)DriverObject->FastIoDispatch + g_KswordArkFastIoFields[index].Offset;
            PVOID routine = NULL;
            if (!KswordARKHookReadMemorySafe(fieldAddress, &routine, sizeof(routine)) || routine == NULL) {
                continue;
            }
            KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"FastIoDispatch.%S=0x%p.", g_KswordArkFastIoFields[index].Name, routine);
            KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO, (ULONGLONG)(ULONG_PTR)fieldAddress, (ULONGLONG)(ULONG_PTR)routine,
                KswordARKDriverIntegrityPointerRisk(ModuleInfo, driverModule, (ULONGLONG)(ULONG_PTR)routine),
                KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE,
                80UL, ~0UL, ~0UL, ~0UL, KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, (ULONGLONG)(ULONG_PTR)routine), detail);
            row = KswordARKDriverIntegrityLastEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO, (ULONGLONG)(ULONG_PTR)fieldAddress, (ULONGLONG)(ULONG_PTR)routine); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_FAST_IO_TARGET | KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DRIVER_OBJECT; row->ordinal = index; row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)DriverObject; row->driverStart = driverStart; row->driverSize = driverSize; row->rangeState = KswordARKDriverIntegrityRangeState(ModuleInfo, driverModule, (ULONGLONG)(ULONG_PTR)routine); }
        }
    }
}
static BOOLEAN
KswordARKDriverIntegrityReadDeviceSnapshot(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ KSW_DRIVER_INTEGRITY_DEVICE_SNAPSHOT* Snapshot
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    if (DeviceObject == NULL || Snapshot == NULL) {
        return FALSE;
    }
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    return KswordARKHookReadMemorySafe(&DeviceObject->NextDevice, &Snapshot->NextDevice, sizeof(Snapshot->NextDevice)) &&
        KswordARKHookReadMemorySafe(&DeviceObject->AttachedDevice, &Snapshot->AttachedDevice, sizeof(Snapshot->AttachedDevice)) &&
        KswordARKHookReadMemorySafe(&DeviceObject->DriverObject, &Snapshot->DriverObject, sizeof(Snapshot->DriverObject)) &&
        KswordARKHookReadMemorySafe(&DeviceObject->DeviceType, &Snapshot->DeviceType, sizeof(Snapshot->DeviceType)) &&
        KswordARKHookReadMemorySafe(&DeviceObject->Flags, &Snapshot->Flags, sizeof(Snapshot->Flags));
}
static BOOLEAN
KswordARKDriverIntegrityPointerVisited(
    _In_reads_(VisitedCount) PDEVICE_OBJECT const* Visited,
    _In_ ULONG VisitedCount,
    _In_opt_ PDEVICE_OBJECT Candidate
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    ULONG index = 0UL;
    if (Candidate == NULL) {
        return FALSE;
    }
    for (index = 0UL; index < VisitedCount; ++index) {
        if (Visited[index] == Candidate) {
            return TRUE;
        }
    }
    return FALSE;
}
static VOID
KswordARKDriverIntegrityAddDeviceRows(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ ULONG MaxDevices,
    _In_ ULONG MaxAttachedDevices
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    PDEVICE_OBJECT visitedRoots[KSW_DRIVER_INTEGRITY_DEVICE_VISIT_LIMIT] = { 0 };
    PDEVICE_OBJECT rootDevice = DriverObject->DeviceObject;
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
    ULONG rootCount = 0UL;
    if (MaxDevices == 0UL || MaxDevices > KSW_DRIVER_INTEGRITY_DEVICE_VISIT_LIMIT) {
        MaxDevices = KSW_DRIVER_INTEGRITY_DEVICE_VISIT_LIMIT;
    }
    if (MaxAttachedDevices == 0UL || MaxAttachedDevices > KSW_DRIVER_INTEGRITY_ATTACH_VISIT_LIMIT) {
        MaxAttachedDevices = KSW_DRIVER_INTEGRITY_ATTACH_VISIT_LIMIT;
    }
    while (rootDevice != NULL && rootCount < MaxDevices) {
        KSW_DRIVER_INTEGRITY_DEVICE_SNAPSHOT rootSnapshot;
        PDEVICE_OBJECT visitedAttached[KSW_DRIVER_INTEGRITY_ATTACH_VISIT_LIMIT] = { 0 };
        PDEVICE_OBJECT attachedDevice = NULL;
        ULONG attachedCount = 0UL;
        ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
        WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
        if (KswordARKDriverIntegrityPointerVisited(visitedRoots, rootCount, rootDevice)) {
            KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice, 0ULL,
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 90UL, ~0UL, ~0UL, ~0UL, NULL,
                L"DriverObject->DeviceObject/NextDevice chain loop detected.");
            break;
        }
        visitedRoots[rootCount++] = rootDevice;
        if (!KswordARKDriverIntegrityReadDeviceSnapshot(rootDevice, &rootSnapshot)) {
            KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice, 0ULL,
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 40UL, ~0UL, ~0UL, ~0UL, NULL,
                L"Failed to safely read root DeviceObject fields.");
            break;
        }
        if (rootSnapshot.DriverObject != DriverObject) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH;
        }
        KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"DeviceObject=0x%p Next=0x%p Attached=0x%p Type=0x%lX Flags=0x%lX.",
            rootDevice, rootSnapshot.NextDevice, rootSnapshot.AttachedDevice, rootSnapshot.DeviceType, rootSnapshot.Flags);
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice,
            (ULONGLONG)(ULONG_PTR)rootSnapshot.AttachedDevice, riskFlags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 80UL,
            ~0UL, ~0UL, ~0UL, NULL, detail);
        row = KswordARKDriverIntegrityLastEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice, (ULONGLONG)(ULONG_PTR)rootSnapshot.AttachedDevice); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DEVICE_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DRIVER_OBJECT; row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)DriverObject; row->deviceObjectAddress = (ULONGLONG)(ULONG_PTR)rootDevice; row->nextDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)rootSnapshot.NextDevice; row->attachedDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)rootSnapshot.AttachedDevice; row->deviceDriverObjectAddress = (ULONGLONG)(ULONG_PTR)rootSnapshot.DriverObject; row->deviceType = rootSnapshot.DeviceType; row->deviceFlags = rootSnapshot.Flags; }
        attachedDevice = rootSnapshot.AttachedDevice;
        while (attachedDevice != NULL && attachedCount < MaxAttachedDevices) {
            KSW_DRIVER_INTEGRITY_DEVICE_SNAPSHOT attachedSnapshot;
            ULONG attachedRisk = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
            if (KswordARKDriverIntegrityPointerVisited(visitedAttached, attachedCount, attachedDevice)) {
                KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice, (ULONGLONG)(ULONG_PTR)attachedDevice,
                    KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 90UL, ~0UL, ~0UL, ~0UL, NULL,
                    L"AttachedDevice chain loop detected.");
                break;
            }
            visitedAttached[attachedCount++] = attachedDevice;
            if (!KswordARKDriverIntegrityReadDeviceSnapshot(attachedDevice, &attachedSnapshot)) {
                break;
            }
            if (attachedSnapshot.DriverObject != DriverObject) {
                attachedRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH;
            }
            KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"AttachedDevice=0x%p OwnerDriver=0x%p NextAttached=0x%p.",
                attachedDevice, attachedSnapshot.DriverObject, attachedSnapshot.AttachedDevice);
            KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice,
                (ULONGLONG)(ULONG_PTR)attachedDevice, attachedRisk, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 75UL,
                ~0UL, ~0UL, ~0UL, NULL, detail);
            row = KswordARKDriverIntegrityLastEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN, (ULONGLONG)(ULONG_PTR)rootDevice, (ULONGLONG)(ULONG_PTR)attachedDevice); if (row != NULL) { row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DEVICE_OBJECT | KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DRIVER_OBJECT; row->ordinal = attachedCount; row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)DriverObject; row->deviceObjectAddress = (ULONGLONG)(ULONG_PTR)attachedDevice; row->nextDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)attachedSnapshot.NextDevice; row->attachedDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)attachedSnapshot.AttachedDevice; row->deviceDriverObjectAddress = (ULONGLONG)(ULONG_PTR)attachedSnapshot.DriverObject; row->deviceType = attachedSnapshot.DeviceType; row->deviceFlags = attachedSnapshot.Flags; }
            attachedDevice = attachedSnapshot.AttachedDevice;
        }
        rootDevice = rootSnapshot.NextDevice;
    }
}
static VOID
KswordARKDriverIntegrityAddServiceRow(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_opt_ PDRIVER_OBJECT DriverObject,
    _In_ const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST* Request
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    WCHAR serviceName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    WCHAR keyPath[KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS] = { 0 };
    UNICODE_STRING keyName;
    OBJECT_ATTRIBUTES attributes;
    HANDLE keyHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    if (DriverObject != NULL && DriverObject->DriverExtension != NULL) {
        KswordARKDriverIntegrityCopyUnicode(&DriverObject->DriverExtension->ServiceKeyName, serviceName, RTL_NUMBER_OF(serviceName));
    }
    if (serviceName[0] == L'\0') {
        WCHAR objectName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
        if (NT_SUCCESS(KswordARKDriverIntegrityBuildDriverObjectName(Request->driverName, objectName, RTL_NUMBER_OF(objectName)))) {
            (VOID)KswordARKDriverIntegrityExtractLeafName(objectName, serviceName, RTL_NUMBER_OF(serviceName));
        }
    }
    if (serviceName[0] == L'\0') {
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE, 0ULL, 0ULL,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY, 30UL,
            ~0UL, ~0UL, ~0UL, NULL, L"No service key name could be derived.");
        return;
    }
    status = RtlStringCchPrintfW(keyPath, RTL_NUMBER_OF(keyPath), L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%ws", serviceName);
    if (!NT_SUCCESS(status)) {
        return;
    }
    RtlInitUnicodeString(&keyName, keyPath);
    InitializeObjectAttributes(&attributes, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_READ, &attributes);
    if (!NT_SUCCESS(status)) {
        KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"Service key %ws open failed, status=0x%08lX.", serviceName, (ULONG)status);
        KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE, 0ULL, 0ULL,
            KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY, 45UL,
            ~0UL, ~0UL, ~0UL, NULL, detail);
        return;
    }
    KswordARKDriverIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"Service key %ws opened read-only.", serviceName);
    KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE, 0ULL, 0ULL,
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY, 80UL,
        ~0UL, ~0UL, ~0UL, NULL, detail);
    ZwClose(keyHandle);
}
NTSTATUS
KswordARKDriverQueryDriverIntegrity(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )

/* Read-only evidence collector; inputs, processing, and output are bounded by SAL and protocol fields. */
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST requestSnapshot;
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* response = NULL;
    KSW_DRIVER_INTEGRITY_BUILDER builder;
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    PDRIVER_OBJECT driverObject = NULL;
    KSW_DYN_STATE dynState;
    ULONG moduleInfoBytes = 0UL;
    ULONG capacity = 0UL;
    ULONG flags = 0UL;
    ULONG cpuCount = 0UL;
    ULONGLONG targetBase = 0ULL;
    NTSTATUS moduleStatus = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;
    if (OutputBuffer == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < KSW_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(&requestSnapshot, sizeof(requestSnapshot));
    if (Request != NULL) {
        RtlCopyMemory(&requestSnapshot, Request, sizeof(requestSnapshot));
    }
    flags = (requestSnapshot.flags == 0UL) ? KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT : requestSnapshot.flags;
    if (requestSnapshot.maxRows == 0UL || requestSnapshot.maxRows > KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS) {
        requestSnapshot.maxRows = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS;
    }
    capacity = (ULONG)((OutputBufferLength - KSW_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE));
    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
    response->queryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK;
    response->entrySize = sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE);
    response->lastStatus = STATUS_SUCCESS;
    RtlZeroMemory(&builder, sizeof(builder));
    RtlZeroMemory(&dynState, sizeof(dynState));
    builder.Response = response;
    builder.Capacity = capacity;
    builder.RowLimit = requestSnapshot.maxRows;
    moduleStatus = KswordARKHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    KswordARKDynDataSnapshot(&dynState);
    targetBase = requestSnapshot.targetModuleBase;
    if ((flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DRIVER_OBJECT) != 0UL) {
        status = KswordARKDriverIntegrityReferenceDriverObject(&requestSnapshot, &driverObject);
        response->lastStatus = status;
        if (NT_SUCCESS(status)) {
            targetBase = (ULONGLONG)(ULONG_PTR)driverObject->DriverStart;
        }
        else {
            response->queryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL;
            KswordARKDriverIntegrityAddEvidence(&builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT, 0ULL, targetBase,
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE | KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED,
                KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, 30UL, ~0UL, ~0UL, ~0UL, NULL,
                L"DriverObject reference failed; module and CPU evidence still collected.");
        }
    }
    KswordARKDriverIntegrityAddSystemModuleRow(&builder, moduleInfo, moduleStatus, targetBase);
    KswordARKDriverIntegrityAddAuxKlibRow(&builder, targetBase);
    if (driverObject != NULL) {
        KswordARKDriverIntegrityAddDriverObjectRows(&builder, driverObject, moduleInfo);
        KswordARKDriverIntegrityAddDeviceRows(&builder, driverObject, requestSnapshot.maxDevices, requestSnapshot.maxAttachedDevices);
    }
    if ((flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_SERVICE) != 0UL) {
        KswordARKDriverIntegrityAddServiceRow(&builder, driverObject, &requestSnapshot);
    }
    if (driverObject != NULL) {
        KswordARKDriverIntegrityAddDynRows(
            &builder,
            &dynState,
            moduleInfo,
            (ULONGLONG)(ULONG_PTR)driverObject->DriverSection,
            (ULONGLONG)driverObject->DriverSize,
            (ULONGLONG)(ULONG_PTR)driverObject->DriverStart,
            ((flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS) != 0UL) ? TRUE : FALSE);
    }
    else {
        KswordARKDriverIntegrityAddDynRows(&builder, &dynState, moduleInfo, 0ULL, 0ULL, targetBase,
            ((flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS) != 0UL) ? TRUE : FALSE);
    }
    if ((flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU) != 0UL) {
        status = KswordARKCpuIntegrityCollect(&builder, moduleInfo, flags, requestSnapshot.maxIdtVectorsPerCpu, &cpuCount);
        response->cpuCount = cpuCount;
        if (!NT_SUCCESS(status) && response->queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK) {
            response->queryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL;
            response->lastStatus = status;
        }
    }
    response->moduleCount = (moduleInfo != NULL) ? moduleInfo->NumberOfModules : 0UL;
    KswordARKDriverIntegrityFinalizeRows(response);
    if ((response->flags & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED | KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED | KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE)) != 0UL &&
        response->queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK) {
        response->queryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL;
    }
    *BytesWrittenOut = KSW_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE + ((size_t)response->returnedCount * sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE));
    if (driverObject != NULL) {
        ObDereferenceObject(driverObject);
    }
    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    return STATUS_SUCCESS;
}
