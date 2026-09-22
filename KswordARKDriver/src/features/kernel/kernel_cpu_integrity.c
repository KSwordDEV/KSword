/*++
Module Name:
    kernel_cpu_integrity.c
Abstract:
    Read-only per-CPU descriptor/MSR/control-register evidence collection for
    DriverDock integrity diagnostics.
Environment:
    Kernel-mode Driver Framework
--*/
#include "kernel_cpu_integrity.h"
#include "kernel_idt_baseline.h"
#include "kernel_idt_consistency.h"
#include "kernel_image_section_map.h"
#include "kernel_interrupt_object.h"
#include <intrin.h>
#include <ntstrsafe.h>
#include <stdarg.h>
#define KSW_CPU_INTEGRITY_MSR_EFER 0xC0000080UL
#define KSW_CPU_INTEGRITY_MSR_LSTAR 0xC0000082UL
#define KSW_CPU_INTEGRITY_MSR_SYSENTER_EIP 0x00000176UL
#define KSW_CPU_INTEGRITY_CR0_WP 0x0000000000010000ULL
#define KSW_CPU_INTEGRITY_CR4_SMEP 0x0000000000100000ULL
#define KSW_CPU_INTEGRITY_CR4_SMAP 0x0000000000200000ULL
#define KSW_CPU_INTEGRITY_EFER_NXE 0x0000000000000800ULL
#define KSW_CPU_INTEGRITY_IDT_ENTRY_BYTES 16UL
#define KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES 8UL
#define KSW_CPU_INTEGRITY_MAX_GDT_ENTRIES 256UL
#define KSW_DRIVER_INTEGRITY_LOADED_MODULE_LIMIT 512UL
#ifndef ALL_PROCESSOR_GROUPS
#define ALL_PROCESSOR_GROUPS 0xFFFFU
#endif
#if defined(_M_AMD64) || defined(_M_X64)
extern void _sgdt(void*);
#pragma intrinsic(_sgdt)
#define KswordARKCpuStoreGdtr _sgdt
#else
#define KswordARKCpuStoreGdtr(_Destination) UNREFERENCED_PARAMETER(_Destination)
#endif
#pragma pack(push, 1)
typedef struct _KSW_CPU_INTEGRITY_DESCRIPTOR_REGISTER
{
    USHORT Limit;
    ULONG_PTR Base;
} KSW_CPU_INTEGRITY_DESCRIPTOR_REGISTER, *PKSW_CPU_INTEGRITY_DESCRIPTOR_REGISTER;
typedef struct _KSW_CPU_INTEGRITY_IDT_ENTRY64
{
    USHORT OffsetLow;
    USHORT Selector;
    USHORT IstAndType;
    USHORT OffsetMiddle;
    ULONG OffsetHigh;
    ULONG Reserved;
} KSW_CPU_INTEGRITY_IDT_ENTRY64, *PKSW_CPU_INTEGRITY_IDT_ENTRY64;
#pragma pack(pop)
typedef struct _KSW_CPU_INTEGRITY_SAMPLE
{
    ULONG Group;
    ULONG Number;
    ULONG Captured;
    ULONGLONG Cr0;
    ULONGLONG Cr4;
    ULONGLONG Efer;
    ULONGLONG Lstar;
    ULONGLONG SysenterEip;
    // 该 CPU 的 KPRCB 地址。KeGetPcr() 只在绑定亲和性期间对得上，所以必须在绑定的那一段里取。
    ULONGLONG Prcb;
    KSW_CPU_INTEGRITY_DESCRIPTOR_REGISTER Idtr;
    KSW_CPU_INTEGRITY_DESCRIPTOR_REGISTER Gdtr;
} KSW_CPU_INTEGRITY_SAMPLE, *PKSW_CPU_INTEGRITY_SAMPLE;
static VOID
KswordARKCpuIntegrityFormatDetail(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_z_ PCWSTR FormatText,
    ...
    )
/*++
Routine Description:
    Format a bounded wide detail string for CPU evidence rows.
Arguments:
    Destination - Fixed output buffer.
    DestinationChars - Output capacity in WCHARs.
    FormatText - printf-style wide format.
    ... - Formatting arguments.
Return Value:
    None. Invalid output is ignored.
--*/
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
VOID
KswordARKDriverIntegrityCopyWide(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_z_ PCWSTR Source
    )
/*++
Routine Description:
    Copy a NUL-terminated wide string into a fixed protocol buffer.
Arguments:
    Destination - Fixed output buffer.
    DestinationChars - Output capacity in WCHARs.
    Source - Optional source string.
Return Value:
    None. Output is terminated when a buffer is supplied.
--*/
{
    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }
    Destination[0] = L'\0';
    if (Source == NULL) {
        return;
    }
    (VOID)RtlStringCchCopyNW(Destination, DestinationChars, Source, DestinationChars - 1UL);
    Destination[DestinationChars - 1UL] = L'\0';
}
const KSW_HOOK_SYSTEM_MODULE_ENTRY*
KswordARKDriverIntegrityFindModuleForAddress(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONGLONG Address
    )
/*++
Routine Description:
    Resolve a kernel virtual address to a loaded module snapshot row.
Arguments:
    ModuleInfo - Optional SystemModuleInformation snapshot.
    Address - Address to classify.
Return Value:
    Owning module row or NULL.
--*/
{
    if (Address == 0ULL || Address > (ULONGLONG)((ULONG_PTR)~((ULONG_PTR)0U))) {
        return NULL;
    }
    return KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)Address);
}
BOOLEAN
KswordARKDriverIntegrityIsCoreKernelModule(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* ModuleEntry
    )
/*++
Routine Description:
    Decide whether a module is one of the normal ntoskrnl/HAL entry owners.
Arguments:
    ModuleEntry - Optional loaded-module snapshot row.
Return Value:
    TRUE for nt kernel or HAL style filenames; otherwise FALSE.
--*/
{
    const UCHAR* fileName = NULL;
    ULONG fileNameBytes = 0UL;
    if (ModuleEntry == NULL) {
        return FALSE;
    }
    KswordARKHookGetModuleFileName(ModuleEntry, &fileName, &fileNameBytes);
    return KswordARKHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, "ntoskrnl.exe") ||
        KswordARKHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, "ntkrnlmp.exe") ||
        KswordARKHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, "ntkrnlpa.exe") ||
        KswordARKHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, "ntkrpamp.exe") ||
        KswordARKHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, "hal.dll");
}
KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE*
KswordARKDriverIntegrityAddEvidence(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_ ULONG EvidenceClass,
    _In_ ULONGLONG ObjectAddress,
    _In_ ULONGLONG TargetAddress,
    _In_ ULONG RiskFlags,
    _In_ ULONG SourceMask,
    _In_ ULONG Confidence,
    _In_ ULONG ProcessorGroup,
    _In_ ULONG ProcessorNumber,
    _In_ ULONG Vector,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* OwnerModule,
    _In_opt_z_ PCWSTR DetailText
    )
/*++
Routine Description:
    Append one variable evidence row and preserve total count on truncation.
Arguments:
    Builder - Response builder state.
    EvidenceClass - Evidence class identifier.
    ObjectAddress - Object or field address under inspection.
    TargetAddress - Observed target address.
    RiskFlags - Risk bits for the row.
    SourceMask - Evidence source mask for the row.
    Confidence - 0..100 row confidence.
    ProcessorGroup - CPU group or ULONG_MAX for non-CPU rows.
    ProcessorNumber - CPU number or ULONG_MAX for non-CPU rows.
    Vector - IDT vector or ULONG_MAX for non-vector rows.
    OwnerModule - Optional owner module for TargetAddress.
    DetailText - Optional detail string.
Return Value:
    Pointer to the appended row, or NULL when validation/capacity rejected it.
--*/
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* response = NULL;
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
    if (Builder == NULL || Builder->Response == NULL) {
        return NULL;
    }
    response = Builder->Response;
    response->totalCount += 1UL;
    response->sourceMask |= SourceMask;
    response->flags |= RiskFlags;
    if ((Builder->RowLimit != 0UL && response->returnedCount >= Builder->RowLimit) || response->returnedCount >= Builder->Capacity) {
        response->flags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED;
        return NULL;
    }
    row = &response->entries[response->returnedCount];
    RtlZeroMemory(row, sizeof(*row));
    row->evidenceClass = EvidenceClass;
    row->riskFlags = RiskFlags;
    row->sourceMask = SourceMask;
    row->confidence = Confidence;
    row->processorGroup = ProcessorGroup;
    row->processorNumber = ProcessorNumber;
    row->vector = Vector;
    row->objectAddress = ObjectAddress;
    row->targetAddress = TargetAddress;
    if (OwnerModule != NULL) {
        const UCHAR* fileName = NULL;
        ULONG fileNameBytes = 0UL;
        row->ownerModuleBase = (ULONGLONG)(ULONG_PTR)OwnerModule->ImageBase;
        row->ownerModuleSize = OwnerModule->ImageSize;
        KswordARKHookGetModuleFileName(OwnerModule, &fileName, &fileNameBytes);
        KswordARKHookCopyBoundedAnsiToWide(fileName, fileNameBytes, row->ownerModule, KSWORD_ARK_DRIVER_INTEGRITY_OWNER_CHARS);
    }
    KswordARKDriverIntegrityCopyWide(row->detail, KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS, DetailText);
    response->returnedCount += 1UL;
    return row;
}
BOOLEAN
KswordARKDriverIntegrityOffsetPresent(
    _In_ ULONG Offset
    )
/*++
Routine Description:
    Test whether a DynData offset is usable for read-only field access.
Arguments:
    Offset - Offset value from the active DynData snapshot.
Return Value:
    TRUE when the offset is not a sentinel.
--*/
{
    return Offset != KSW_DYN_OFFSET_UNAVAILABLE && Offset != 0x0000FFFFUL;
}
static BOOLEAN
KswordARKDriverIntegrityReadLoadedModuleRecord(
    _In_ ULONGLONG EntryAddress,
    _In_ const KSW_DYN_KERNEL_OFFSETS* Offsets,
    _Out_ KSW_DRIVER_INTEGRITY_LDR_TARGET* Record
    )
/*++
Routine Description:
    Read one KLDR entry using only DynData offsets and guarded memory copies.
Arguments:
    EntryAddress - Address of the KLDR_DATA_TABLE_ENTRY candidate.
    Offsets - Active DynData kernel offsets.
    Record - Receives the selected KLDR fields and a bounded basename.
Return Value:
    TRUE when the required fields were copied.
--*/
{
    UNICODE_STRING baseName;
    WCHAR baseNameBuffer[KSWORD_ARK_DRIVER_INTEGRITY_OWNER_CHARS] = { 0 };
    ULONG baseNameChars = 0UL;
    if (Record == NULL || Offsets == NULL || EntryAddress == 0ULL) {
        return FALSE;
    }
    if (!KswordARKDriverIntegrityOffsetPresent(Offsets->KldrInLoadOrderLinks) ||
        !KswordARKDriverIntegrityOffsetPresent(Offsets->KldrDllBase) ||
        !KswordARKDriverIntegrityOffsetPresent(Offsets->KldrSizeOfImage)) {
        return FALSE;
    }
    RtlZeroMemory(Record, sizeof(*Record));
    Record->Available = TRUE;
    Record->EntryAddress = EntryAddress;
    Record->LinkAddress = EntryAddress + (ULONGLONG)Offsets->KldrInLoadOrderLinks;
    if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)(EntryAddress + (ULONGLONG)Offsets->KldrDllBase), &Record->DllBase, sizeof(Record->DllBase)) ||
        !KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)(EntryAddress + (ULONGLONG)Offsets->KldrSizeOfImage), &Record->SizeOfImage, sizeof(Record->SizeOfImage))) {
        return FALSE;
    }
    if (KswordARKDriverIntegrityOffsetPresent(Offsets->KldrBaseDllName) &&
        KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)(EntryAddress + (ULONGLONG)Offsets->KldrBaseDllName), &baseName, sizeof(baseName)) &&
        baseName.Buffer != NULL &&
        baseName.Length != 0U) {
        baseNameChars = (ULONG)(baseName.Length / sizeof(WCHAR));
        if (baseNameChars >= RTL_NUMBER_OF(baseNameBuffer)) {
            baseNameChars = RTL_NUMBER_OF(baseNameBuffer) - 1UL;
        }
        if (baseNameChars != 0UL &&
            KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)baseName.Buffer, baseNameBuffer, (SIZE_T)baseNameChars * sizeof(WCHAR))) {
            baseNameBuffer[baseNameChars] = L'\0';
            baseName.Buffer = baseNameBuffer;
            baseName.Length = (USHORT)(baseNameChars * sizeof(WCHAR));
            baseName.MaximumLength = baseName.Length;
            KswordARKDriverIntegrityCopyWide(Record->BaseDllName, RTL_NUMBER_OF(Record->BaseDllName), baseNameBuffer);
        }
    }
    return TRUE;
}
ULONGLONG
KswordARKDriverIntegrityNtosAddressFromRva(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ ULONG Rva,
    _In_ SIZE_T ProbeBytes
    )
/*++
Routine Description:
    Convert a DynData ntoskrnl RVA to a readable kernel VA.
Arguments:
    DynState - Active DynData snapshot.
    Rva - Global RVA from the PDB profile.
    ProbeBytes - Optional bytes that must fit inside the image.
Return Value:
    Kernel VA, or zero when DynData is inactive/untrusted/unreadable.
--*/
{
    UCHAR probe[sizeof(LIST_ENTRY)] = { 0 };
    ULONGLONG address = 0ULL;
    if (DynState == NULL || !DynState->Initialized || !DynState->NtosActive ||
        DynState->Ntoskrnl.imageBase == 0ULL || DynState->Ntoskrnl.sizeOfImage == 0UL ||
        !KswordARKDriverIntegrityOffsetPresent(Rva)) {
        return 0ULL;
    }
    if (Rva >= DynState->Ntoskrnl.sizeOfImage ||
        ProbeBytes > sizeof(probe) ||
        (ProbeBytes != 0U && ((ULONGLONG)Rva + (ULONGLONG)ProbeBytes) > (ULONGLONG)DynState->Ntoskrnl.sizeOfImage) ||
        DynState->Ntoskrnl.imageBase > (((ULONGLONG)~0ULL) - (ULONGLONG)Rva)) {
        return 0ULL;
    }
    address = DynState->Ntoskrnl.imageBase + (ULONGLONG)Rva;
    if (ProbeBytes != 0U &&
        !KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)address, probe, ProbeBytes)) {
        return 0ULL;
    }
    return address;
}
NTSTATUS
KswordARKDriverIntegrityFindLoadedModule(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ ULONGLONG DriverStart,
    _Out_ KSW_DRIVER_INTEGRITY_LDR_TARGET* TargetOut
    )
/*++
Routine Description:
    Walk PsLoadedModuleList read-only with DynData KLDR offsets and find the target image.
Arguments:
    DynState - Query-time DynData snapshot.
    DriverStart - DriverObject->DriverStart or requested module base.
    TargetOut - Receives the matched target or list-head evidence.
Return Value:
    STATUS_SUCCESS when a target row is found, STATUS_NOT_FOUND for a valid
    walk without a target match, or an explanatory status for unavailable data.
--*/
{
    ULONGLONG listHead = 0ULL;
    LIST_ENTRY headLinks;
    ULONGLONG currentLink = 0ULL;
    ULONG visited = 0UL;
    if (TargetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(TargetOut, sizeof(*TargetOut));
    if (DynState == NULL ||
        !DynState->Initialized ||
        !DynState->NtosActive ||
        (DynState->CapabilityMask & KSW_CAP_KERNEL_MODULE_LIST_FIELDS) == 0ULL ||
        !KswordARKDriverIntegrityOffsetPresent(DynState->KernelGlobals.PsLoadedModuleList)) {
        return STATUS_NOT_SUPPORTED;
    }
    listHead = KswordARKDriverIntegrityNtosAddressFromRva(DynState, DynState->KernelGlobals.PsLoadedModuleList, sizeof(LIST_ENTRY));
    if (listHead == 0ULL) {
        return STATUS_NOT_FOUND;
    }
    if (!KswordARKDriverIntegrityOffsetPresent(DynState->Kernel.KldrInLoadOrderLinks) ||
        !KswordARKDriverIntegrityOffsetPresent(DynState->Kernel.KldrDllBase) ||
        !KswordARKDriverIntegrityOffsetPresent(DynState->Kernel.KldrSizeOfImage)) {
        return STATUS_NOT_SUPPORTED;
    }
    RtlZeroMemory(&headLinks, sizeof(headLinks));
    if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)listHead, &headLinks, sizeof(headLinks))) {
        return STATUS_ACCESS_VIOLATION;
    }
    TargetOut->Available = TRUE;
    TargetOut->ListHeadAddress = listHead;
    currentLink = (ULONGLONG)(ULONG_PTR)headLinks.Flink;
    while (currentLink != 0ULL && currentLink != listHead && visited < KSW_DRIVER_INTEGRITY_LOADED_MODULE_LIMIT) {
        KSW_DRIVER_INTEGRITY_LDR_TARGET record;
        ULONGLONG entryAddress = 0ULL;
        LIST_ENTRY links;
        if (currentLink < (ULONGLONG)DynState->Kernel.KldrInLoadOrderLinks) {
            return STATUS_ACCESS_VIOLATION;
        }
        entryAddress = currentLink - (ULONGLONG)DynState->Kernel.KldrInLoadOrderLinks;
        RtlZeroMemory(&record, sizeof(record));
        RtlZeroMemory(&links, sizeof(links));
        if (!KswordARKDriverIntegrityReadLoadedModuleRecord(entryAddress, &DynState->Kernel, &record)) {
            return STATUS_PARTIAL_COPY;
        }
        record.ListHeadAddress = listHead;
        if (DriverStart != 0ULL &&
            record.SizeOfImage != 0UL &&
            record.DllBase <= (((ULONGLONG)~0ULL) - (ULONGLONG)record.SizeOfImage) &&
            DriverStart >= record.DllBase &&
            DriverStart < (record.DllBase + (ULONGLONG)record.SizeOfImage)) {
            record.Found = TRUE;
            RtlCopyMemory(TargetOut, &record, sizeof(*TargetOut));
            return STATUS_SUCCESS;
        }
        if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)currentLink, &links, sizeof(links))) {
            return STATUS_PARTIAL_COPY;
        }
        currentLink = (ULONGLONG)(ULONG_PTR)links.Flink;
        ++visited;
    }
    return (visited >= KSW_DRIVER_INTEGRITY_LOADED_MODULE_LIMIT) ? STATUS_MORE_ENTRIES : STATUS_NOT_FOUND;
}
static ULONGLONG
KswordARKCpuIntegrityIdtHandler(
    _In_ const KSW_CPU_INTEGRITY_IDT_ENTRY64* Entry
    )
/*++
Routine Description:
    Decode one x64 IDT gate handler address from copied descriptor bytes.
Arguments:
    Entry - Copied IDT gate descriptor.
Return Value:
    Handler virtual address, or zero for invalid input.
--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    ULONGLONG high = 0ULL;
    ULONGLONG middle = 0ULL;
    ULONGLONG low = 0ULL;
    if (Entry == NULL) {
        return 0ULL;
    }
    low = (ULONGLONG)Entry->OffsetLow;
    middle = ((ULONGLONG)Entry->OffsetMiddle) << 16;
    high = ((ULONGLONG)Entry->OffsetHigh) << 32;
    return high | middle | low;
#else
    UNREFERENCED_PARAMETER(Entry);
    return 0ULL;
#endif
}

static BOOLEAN
KswordARKCpuIntegrityGdtDescriptorIsWide(
    _In_ ULONG Type,
    _In_ BOOLEAN UserSegment
    )
/*++
Routine Description:
    Decide whether one long-mode GDT system descriptor consumes two slots.
Arguments:
    Type - Four-bit architectural descriptor type.
    UserSegment - TRUE when the S bit marks a code/data descriptor.
Return Value:
    TRUE for LDT/TSS/call/interrupt/trap system descriptors; FALSE otherwise.
--*/
{
    if (UserSegment) {
        return FALSE;
    }
    return Type == 0x2UL || Type == 0x9UL || Type == 0xBUL ||
        Type == 0xCUL || Type == 0xEUL || Type == 0xFUL;
}

static VOID
KswordARKCpuIntegrityPopulateDescriptorFields(
    _Inout_opt_ KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* Row,
    _In_ ULONG Selector,
    _In_ ULONG Type,
    _In_ ULONG Dpl,
    _In_ ULONG Flags,
    _In_ ULONG DescriptorSize,
    _In_ ULONGLONG TableBase,
    _In_ ULONG TableLimit,
    _In_ ULONGLONG Base,
    _In_ ULONGLONG Limit,
    _In_ ULONGLONG RawLow,
    _In_ ULONGLONG RawHigh
    )
/*++
Routine Description:
    Fill the append-only v3 descriptor columns on one evidence row.
Arguments:
    Row - Row returned by the bounded evidence builder.
    Selector - IDT code selector or GDT selector.
    Type - Architectural gate/segment type.
    Dpl - Descriptor privilege level.
    Flags - KSWORD_ARK_DESCRIPTOR_FLAG_* bits.
    DescriptorSize - Descriptor byte width.
    TableBase - IDTR/GDTR base captured on the target CPU.
    TableLimit - IDTR/GDTR limit captured on the target CPU.
    Base - Handler or segment base decoded from the descriptor.
    Limit - Effective segment limit; zero for IDT gates.
    RawLow - First eight descriptor bytes.
    RawHigh - Second eight descriptor bytes when present.
Return Value:
    None.
--*/
{
    if (Row == NULL) {
        return;
    }
    Row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DESCRIPTOR;
    Row->descriptorSelector = Selector;
    Row->descriptorType = Type;
    Row->descriptorDpl = Dpl;
    Row->descriptorFlags = Flags;
    Row->descriptorSize = DescriptorSize;
    Row->descriptorTableBase = TableBase;
    Row->descriptorTableLimit = TableLimit;
    Row->descriptorBase = Base;
    Row->descriptorLimit = Limit;
    Row->descriptorRawLow = RawLow;
    Row->descriptorRawHigh = RawHigh;
}
static VOID
KswordARKCpuIntegrityCaptureCurrent(
    _Inout_ KSW_CPU_INTEGRITY_SAMPLE* Sample
    )
/*++
Routine Description:
    Capture only read-only CPU state on the current processor.
Arguments:
    Sample - Per-CPU sample to populate.
Return Value:
    None. Unsupported architectures mark Captured as zero.
--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    if (Sample == NULL) {
        return;
    }
    Sample->Cr0 = __readcr0();
    Sample->Cr4 = __readcr4();
    Sample->Efer = __readmsr(KSW_CPU_INTEGRITY_MSR_EFER);
    Sample->Lstar = __readmsr(KSW_CPU_INTEGRITY_MSR_LSTAR);
    Sample->SysenterEip = __readmsr(KSW_CPU_INTEGRITY_MSR_SYSENTER_EIP);
    __sidt(&Sample->Idtr);
    KswordARKCpuStoreGdtr(&Sample->Gdtr);
    // 调用方已把线程绑到目标 CPU，此刻 KeGetPcr()->CurrentPrcb 就是该 CPU 的 KPRCB。
    Sample->Prcb = (ULONGLONG)(ULONG_PTR)KeGetPcr()->CurrentPrcb;
    Sample->Captured = 1UL;
#else
    UNREFERENCED_PARAMETER(Sample);
#endif
}
static VOID
KswordARKCpuIntegrityEmitControlRows(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_ const KSW_CPU_INTEGRITY_SAMPLE* Sample,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_opt_ const KSW_IDT_CONSISTENCY_VIEW* ConsistencyView
    )
/*++
Routine Description:
    Emit CR0/CR4/EFER/LSTAR/SYSENTER and descriptor-table summary rows.
Arguments:
    Builder - Response builder.
    Sample - Captured CPU state.
    ModuleInfo - Optional module snapshot for MSR owner attribution.
    ConsistencyView - Optional cross-CPU IDTR view used to score the table row.
Return Value:
    None. Rows are appended to Builder.
--*/
{
    ULONG consistencyRisk = 0UL;
    ULONG tableRisk = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    ULONG lstarSection = KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    ULONG lstarRisk = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    ULONG sysenterRisk = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* lstarOwner = NULL;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* sysenterOwner = NULL;
    if (Builder == NULL || Sample == NULL || Sample->Captured == 0UL) {
        return;
    }
    if ((Sample->Cr0 & KSW_CPU_INTEGRITY_CR0_WP) == 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED;
    }
    if ((Sample->Cr4 & KSW_CPU_INTEGRITY_CR4_SMEP) == 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED;
    }
    if ((Sample->Cr4 & KSW_CPU_INTEGRITY_CR4_SMAP) == 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED;
    }
    if ((Sample->Efer & KSW_CPU_INTEGRITY_EFER_NXE) == 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED;
    }
    KswordARKCpuIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"CR0=0x%llX CR4=0x%llX EFER=0x%llX; WP/SMEP/SMAP/NXE read-only state.", Sample->Cr0, Sample->Cr4, Sample->Efer);
    KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_CPU_CONTROL, 0ULL, 0ULL, riskFlags,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_CPU_REGISTER | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR, 90UL, Sample->Group, Sample->Number, ~0UL, NULL, detail);
    lstarOwner = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, Sample->Lstar);
    sysenterOwner = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, Sample->SysenterEip);
    if (lstarOwner == NULL) {
        lstarRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
    }
    else {
        if (!KswordARKDriverIntegrityIsCoreKernelModule(lstarOwner)) {
            lstarRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER;
        }
        // syscall 入口同样必须落在归属模块的可执行节内。
        lstarSection = KswordARKImageClassifyAddress(lstarOwner, Sample->Lstar, NULL, 0UL, NULL);
        if (lstarSection == KSW_IMAGE_SECTION_RESULT_NON_EXECUTABLE ||
            lstarSection == KSW_IMAGE_SECTION_RESULT_OUTSIDE_SECTIONS) {
            lstarRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_TARGET_NON_EXEC;
        }
    }
    if (Sample->SysenterEip != 0ULL) {
        if (sysenterOwner == NULL) {
            sysenterRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
        }
        else if (!KswordARKDriverIntegrityIsCoreKernelModule(sysenterOwner)) {
            sysenterRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER;
        }
    }
    KswordARKCpuIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"MSR_LSTAR=0x%llX; SYSENTER_EIP=0x%llX.", Sample->Lstar, Sample->SysenterEip);
    KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY, 0ULL, Sample->Lstar,
        lstarRisk,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, 90UL, Sample->Group, Sample->Number, ~0UL, lstarOwner, detail);
    KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY, 0ULL, Sample->SysenterEip,
        sysenterRisk,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, 70UL, Sample->Group, Sample->Number, ~0UL, sysenterOwner, L"SYSENTER_EIP captured read-only; x64 systems may leave this path unused.");
    // 描述符表汇总行现在带上跨 CPU 一致性与启动期基线的判定结果。
    consistencyRisk = KswordARKIdtConsistencyClassify(ConsistencyView, Sample->Group, Sample->Number);
    if ((consistencyRisk & KSW_IDT_CONSISTENCY_RISK_DIVERGED) != 0UL) {
        tableRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_TABLE_DIVERGED;
    }
    if ((consistencyRisk & KSW_IDT_CONSISTENCY_RISK_RELOCATED) != 0UL) {
        tableRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_TABLE_RELOCATED;
    }
    KswordARKCpuIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail),
        L"IDTR base=0x%llX limit=0x%04X; GDTR base=0x%llX limit=0x%04X; majority IDT base=0x%llX limit=0x%04lX on %lu/%lu CPU.",
        (ULONGLONG)Sample->Idtr.Base, Sample->Idtr.Limit, (ULONGLONG)Sample->Gdtr.Base, Sample->Gdtr.Limit,
        (ConsistencyView != NULL) ? ConsistencyView->MajorityBase : 0ULL,
        (ConsistencyView != NULL) ? ConsistencyView->MajorityLimit : 0UL,
        (ConsistencyView != NULL) ? ConsistencyView->MajorityCount : 0UL,
        (ConsistencyView != NULL) ? ConsistencyView->CpuCount : 0UL);
    KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE, (ULONGLONG)Sample->Idtr.Base,
        (ULONGLONG)Sample->Gdtr.Base, tableRisk,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT, 90UL, Sample->Group, Sample->Number, ~0UL, NULL, detail);
}
static VOID
KswordARKCpuIntegrityEmitIdtRows(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_ const KSW_CPU_INTEGRITY_SAMPLE* Sample,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONG MaxVectors,
    _Inout_ KSW_INTERRUPT_OBJECT_CONTEXT* InterruptContext
    )
/*++
Routine Description:
    Read copied IDT entries and emit handler owner evidence rows. After each
    gate row, follow the vector to its interrupt object and emit the secondary
    ISR pointer evidence (class INTERRUPT_OBJECT).
Arguments:
    Builder - Response builder.
    Sample - Captured descriptor state for one CPU.
    ModuleInfo - Optional module snapshot for owner attribution.
    MaxVectors - Maximum vectors to emit for this CPU.
    InterruptContext - Per-query interrupt-object layout state shared across CPUs.
Return Value:
    None. IDT rows are appended to Builder.
--*/
{
    ULONG vector = 0UL;
    ULONG vectorCount = 0UL;
    KSW_INTERRUPT_OBJECT_CPU interruptCpu;
    if (Builder == NULL || Sample == NULL || Sample->Captured == 0UL || Sample->Idtr.Base == 0U) {
        return;
    }
    // KPRCB 地址取自绑定亲和性的那一段，这里只是把它连同 IDT 现场一起交给二级对象取证。
    RtlZeroMemory(&interruptCpu, sizeof(interruptCpu));
    interruptCpu.ProcessorGroup = Sample->Group;
    interruptCpu.ProcessorNumber = Sample->Number;
    interruptCpu.PrcbAddress = Sample->Prcb;
    interruptCpu.IdtBase = (ULONGLONG)Sample->Idtr.Base;
    interruptCpu.IdtLimit = (ULONG)Sample->Idtr.Limit;
    vectorCount = ((ULONG)Sample->Idtr.Limit + 1UL) / KSW_CPU_INTEGRITY_IDT_ENTRY_BYTES;
    if (vectorCount > 256UL) {
        vectorCount = 256UL;
    }
    if (MaxVectors != 0UL && vectorCount > MaxVectors) {
        vectorCount = MaxVectors;
    }
    for (vector = 0UL; vector < vectorCount; ++vector) {
        KSW_CPU_INTEGRITY_IDT_ENTRY64 entry;
        KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
        ULONGLONG entryAddress = (ULONGLONG)Sample->Idtr.Base + ((ULONGLONG)vector * KSW_CPU_INTEGRITY_IDT_ENTRY_BYTES);
        ULONGLONG handler = 0ULL;
        ULONGLONG rawLow = 0ULL;
        ULONGLONG rawHigh = 0ULL;
        ULONGLONG baselineTableBase = 0ULL;
        ULONGLONG baselineHandler = 0ULL;
        ULONGLONG baselineRawLow = 0ULL;
        ULONGLONG baselineRawHigh = 0ULL;
        ULONG baselineTableLimit = 0UL;
        ULONG baselineGeneration = 0UL;
        BOOLEAN baselineAvailable = FALSE;
        ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
        ULONG descriptorFlags = 0UL;
        ULONG descriptorType = 0UL;
        ULONG descriptorDpl = 0UL;
        const KSW_HOOK_SYSTEM_MODULE_ENTRY* owner = NULL;
        ULONG sectionResult = KSW_IMAGE_SECTION_RESULT_UNKNOWN;
        WCHAR sectionName[KSW_IMAGE_SECTION_NAME_CHARS] = { 0 };
        WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
        RtlZeroMemory(&entry, sizeof(entry));
        if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)entryAddress, &entry, sizeof(entry))) {
            riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED;
            row = KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER, entryAddress, 0ULL, riskFlags,
                KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT, 35UL, Sample->Group, Sample->Number, vector, NULL, L"IDT entry read failed.");
            KswordARKCpuIntegrityPopulateDescriptorFields(
                row, 0UL, 0UL, 0UL, KSWORD_ARK_DESCRIPTOR_FLAG_READ_FAILED,
                KSW_CPU_INTEGRITY_IDT_ENTRY_BYTES, (ULONGLONG)Sample->Idtr.Base,
                Sample->Idtr.Limit, 0ULL, 0ULL, 0ULL, 0ULL);
            continue;
        }
        RtlCopyMemory(&rawLow, &entry, sizeof(rawLow));
        RtlCopyMemory(&rawHigh, (const UCHAR*)&entry + sizeof(rawLow), sizeof(rawHigh));
        handler = KswordARKCpuIntegrityIdtHandler(&entry);
        descriptorType = ((ULONG)entry.IstAndType >> 8) & 0xFUL;
        descriptorDpl = ((ULONG)entry.IstAndType >> 13) & 0x3UL;
        if ((entry.IstAndType & 0x8000U) != 0U) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_PRESENT;
        }
        if ((descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_PRESENT) == 0UL ||
            entry.Selector == 0U || handler == 0ULL ||
            (descriptorType != 0xEUL && descriptorType != 0xFUL) || entry.Reserved != 0UL) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID;
        }
        owner = KswordARKDriverIntegrityFindModuleForAddress(ModuleInfo, handler);
        if (owner == NULL) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
        }
        else {
            if (!KswordARKDriverIntegrityIsCoreKernelModule(owner)) {
                riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER;
            }
            // 落在映像区间内还不够，handler 必须位于该模块的可执行节里。
            sectionResult = KswordARKImageClassifyAddress(
                owner, handler, sectionName, RTL_NUMBER_OF(sectionName), NULL);
            if (sectionResult == KSW_IMAGE_SECTION_RESULT_NON_EXECUTABLE ||
                sectionResult == KSW_IMAGE_SECTION_RESULT_OUTSIDE_SECTIONS) {
                riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_TARGET_NON_EXEC;
            }
        }
        baselineAvailable = KswordARKIdtBaselineQuery(
            (USHORT)Sample->Group,
            (UCHAR)Sample->Number,
            (UCHAR)vector,
            &baselineTableBase,
            &baselineTableLimit,
            NULL,
            &baselineRawLow,
            &baselineRawHigh,
            &baselineHandler,
            &baselineGeneration);
        if (baselineAvailable &&
            (baselineRawLow != rawLow ||
             baselineRawHigh != rawHigh)) {
            riskFlags |=
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_BASELINE_CHANGED;
        }
        KswordARKCpuIntegrityFormatDetail(
            detail,
            RTL_NUMBER_OF(detail),
            L"IDT[%lu] gate=0x%llX handler=0x%llX selector=0x%04X attr=0x%04X; section=%ls(%lu); baseline=%ls handler=0x%llX generation=%lu.",
            vector,
            entryAddress,
            handler,
            entry.Selector,
            entry.IstAndType,
            (sectionName[0] != L'\0') ? sectionName : L"n/a",
            sectionResult,
            baselineAvailable ? L"available" : L"unavailable",
            baselineHandler,
            baselineGeneration);
        row = KswordARKDriverIntegrityAddEvidence(Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER, entryAddress, handler, riskFlags,
            KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, 85UL, Sample->Group, Sample->Number, vector, owner, detail);
        KswordARKCpuIntegrityPopulateDescriptorFields(
            row, entry.Selector, descriptorType, descriptorDpl, descriptorFlags,
            KSW_CPU_INTEGRITY_IDT_ENTRY_BYTES, (ULONGLONG)Sample->Idtr.Base,
            Sample->Idtr.Limit, handler, 0ULL, rawLow, rawHigh);
        if (row != NULL && baselineAvailable) {
            row->fieldMask |=
                KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DESCRIPTOR_BASELINE;
            row->baselineDescriptorFlags =
                KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_AVAILABLE;
            if (baselineTableBase == (ULONGLONG)Sample->Idtr.Base &&
                baselineTableLimit == Sample->Idtr.Limit) {
                row->baselineDescriptorFlags |=
                    KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_SAME_TABLE;
            }
            if (baselineRawLow != rawLow ||
                baselineRawHigh != rawHigh) {
                row->baselineDescriptorFlags |=
                    KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_DIFFERS;
            }
            row->baselineGeneration = baselineGeneration;
            row->baselineDescriptorBase = baselineHandler;
            row->baselineDescriptorRawLow = baselineRawLow;
            row->baselineDescriptorRawHigh = baselineRawHigh;
        }
        // 网关行之后：沿该向量走到中断对象，核对网关之后的二级指针（只读，布局运行时自验证）。
        KswordARKInterruptObjectEmitForVector(Builder, InterruptContext, ModuleInfo, &interruptCpu, vector, handler, riskFlags);
    }
}

static VOID
KswordARKCpuIntegrityEmitGdtRows(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_ const KSW_CPU_INTEGRITY_SAMPLE* Sample
    )
/*++
Routine Description:
    Decode a bounded copy of each GDT slot and emit structured v3 evidence.
Arguments:
    Builder - Response builder.
    Sample - Captured GDTR state for one CPU.
Return Value:
    None. Every row remains read-only diagnostic evidence.
--*/
{
    ULONG slot = 0UL;
    ULONG slotCount = 0UL;
    if (Builder == NULL || Sample == NULL || Sample->Captured == 0UL || Sample->Gdtr.Base == 0U) {
        return;
    }
    slotCount = ((ULONG)Sample->Gdtr.Limit + 1UL) / KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES;
    if (slotCount > KSW_CPU_INTEGRITY_MAX_GDT_ENTRIES) {
        Builder->Response->flags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED;
        slotCount = KSW_CPU_INTEGRITY_MAX_GDT_ENTRIES;
    }
    for (slot = 0UL; slot < slotCount; ++slot) {
        KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
        const ULONGLONG entryAddress =
            (ULONGLONG)Sample->Gdtr.Base + ((ULONGLONG)slot * KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES);
        ULONGLONG rawLow = 0ULL;
        ULONGLONG rawHigh = 0ULL;
        ULONGLONG base = 0ULL;
        ULONGLONG limit = 0ULL;
        ULONG descriptorType = 0UL;
        ULONG descriptorDpl = 0UL;
        ULONG descriptorFlags = 0UL;
        ULONG descriptorSize = KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES;
        ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
        BOOLEAN userSegment = FALSE;
        BOOLEAN wideDescriptor = FALSE;
        WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };

        if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)entryAddress, &rawLow, sizeof(rawLow))) {
            row = KswordARKDriverIntegrityAddEvidence(
                Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_GDT_DESCRIPTOR,
                entryAddress, 0ULL, KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED,
                KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT, 35UL, Sample->Group,
                Sample->Number, slot, NULL, L"GDT descriptor read failed.");
            KswordARKCpuIntegrityPopulateDescriptorFields(
                row, slot * KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES, 0UL, 0UL,
                KSWORD_ARK_DESCRIPTOR_FLAG_READ_FAILED, descriptorSize,
                (ULONGLONG)Sample->Gdtr.Base, Sample->Gdtr.Limit,
                0ULL, 0ULL, 0ULL, 0ULL);
            continue;
        }

        descriptorType = (ULONG)((rawLow >> 40) & 0xFULL);
        userSegment = ((rawLow >> 44) & 0x1ULL) != 0ULL ? TRUE : FALSE;
        descriptorDpl = (ULONG)((rawLow >> 45) & 0x3ULL);
        if (((rawLow >> 47) & 0x1ULL) != 0ULL) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_PRESENT;
        }
        if (((rawLow >> 55) & 0x1ULL) != 0ULL) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_GRANULARITY_PAGE;
        }
        if (userSegment) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_USER_SEGMENT;
        }
        if (((rawLow >> 53) & 0x1ULL) != 0ULL) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_LONG_MODE;
        }
        if (((rawLow >> 54) & 0x1ULL) != 0ULL) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_DEFAULT_BIG;
        }
        if (!userSegment && descriptorType == 0x9UL) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_AVAILABLE;
        }

        base = ((rawLow >> 16) & 0xFFFFFFULL) | (((rawLow >> 56) & 0xFFULL) << 24);
        limit = (rawLow & 0xFFFFULL) | (((rawLow >> 48) & 0xFULL) << 16);
        wideDescriptor = KswordARKCpuIntegrityGdtDescriptorIsWide(descriptorType, userSegment);
        if (wideDescriptor) {
            descriptorSize = 2UL * KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES;
            if (slot + 1UL >= slotCount ||
                !KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)(entryAddress + KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES), &rawHigh, sizeof(rawHigh))) {
                riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED |
                    KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID;
                descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_READ_FAILED;
            }
            else {
                base |= (rawHigh & 0xFFFFFFFFULL) << 32;
                if ((rawHigh >> 32) != 0ULL) {
                    riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID;
                }
            }
        }
        if ((descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_GRANULARITY_PAGE) != 0UL) {
            limit = (limit << 12) | 0xFFFULL;
        }
        if ((descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_PRESENT) != 0UL) {
            if (descriptorType == 0UL ||
                (userSegment &&
                 (descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_LONG_MODE) != 0UL &&
                 (descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_DEFAULT_BIG) != 0UL)) {
                riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID;
            }
        }

        KswordARKCpuIntegrityFormatDetail(
            detail, RTL_NUMBER_OF(detail),
            L"GDT selector=0x%04lX entry=0x%llX base=0x%llX limit=0x%llX type=0x%lX DPL=%lu flags=0x%lX size=%lu.",
            slot * KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES, entryAddress, base, limit,
            descriptorType, descriptorDpl, descriptorFlags, descriptorSize);
        row = KswordARKDriverIntegrityAddEvidence(
            Builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_GDT_DESCRIPTOR,
            entryAddress, base, riskFlags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT,
            riskFlags == 0UL ? 90UL : 55UL, Sample->Group, Sample->Number,
            slot, NULL, detail);
        KswordARKCpuIntegrityPopulateDescriptorFields(
            row, slot * KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES, descriptorType,
            descriptorDpl, descriptorFlags, descriptorSize,
            (ULONGLONG)Sample->Gdtr.Base, Sample->Gdtr.Limit,
            base, limit, rawLow, rawHigh);
        if (wideDescriptor && slot + 1UL < slotCount) {
            // IA-32e system descriptors consume two adjacent GDT slots. The
            // upper half is raw continuation data, not an independent entry.
            ++slot;
        }
    }
}
NTSTATUS
KswordARKCpuIntegrityCollect(
    _Inout_ KSW_DRIVER_INTEGRITY_BUILDER* Builder,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONG Flags,
    _In_ ULONG MaxIdtVectorsPerCpu,
    _Out_ ULONG* CpuCountOut
    )
/*++
Routine Description:
    Sequentially switch to each active processor and collect read-only CPU entry evidence.
Arguments:
    Builder - Response builder.
    ModuleInfo - Optional module snapshot for owner attribution.
    Flags - Query flags controlling IDT expansion.
    MaxIdtVectorsPerCpu - Per-CPU IDT vector cap; zero selects protocol default.
    CpuCountOut - Receives number of active processors visited or attempted.
Return Value:
    STATUS_SUCCESS when at least the current architecture supports sampling.
--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    ULONG groupCount = 0UL;
    ULONG groupIndex = 0UL;
    ULONG totalCpus = 0UL;
    ULONG allActiveCount = 0UL;
    KSW_IDT_CONSISTENCY_VIEW* consistencyView = NULL;
    KSW_INTERRUPT_OBJECT_CONTEXT interruptContext;
    if (Builder == NULL || CpuCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CpuCountOut = 0UL;
    // 中断对象布局在整次查询内只解析一次；验证不过时只产出一行说明，其后静默。
    KswordARKInterruptObjectContextInitialize(&interruptContext);
    // 先做一轮只读的全机 IDTR 采样，后续每个 CPU 的证据行都能引用多数派结论。
    // 采集失败不影响其余证据，consistencyView 保持 NULL 即可。
    (VOID)KswordARKIdtConsistencyCollect(&consistencyView);
    if (MaxIdtVectorsPerCpu == 0UL || MaxIdtVectorsPerCpu > KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS) {
        MaxIdtVectorsPerCpu = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS;
    }
    groupCount = KeQueryActiveGroupCount();
    allActiveCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (groupIndex = 0UL; groupIndex < groupCount; ++groupIndex) {
        ULONG activeInGroup = KeQueryActiveProcessorCountEx((USHORT)groupIndex);
        ULONG visitedInGroup = 0UL;
        ULONG globalIndex = 0UL;
        for (globalIndex = 0UL; globalIndex < allActiveCount && visitedInGroup < activeInGroup; ++globalIndex) {
            GROUP_AFFINITY targetAffinity;
            GROUP_AFFINITY previousAffinity;
            PROCESSOR_NUMBER processorNumber;
            KSW_CPU_INTEGRITY_SAMPLE sample;
            KAFFINITY bit = 0U;
            RtlZeroMemory(&processorNumber, sizeof(processorNumber));
            if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(globalIndex, &processorNumber))) {
                break;
            }
            if (processorNumber.Group != (USHORT)groupIndex) {
                continue;
            }
            if (processorNumber.Number >= (sizeof(KAFFINITY) * 8UL)) {
                break;
            }
            bit = ((KAFFINITY)1) << processorNumber.Number;
            RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
            RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
            RtlZeroMemory(&sample, sizeof(sample));
            targetAffinity.Group = (USHORT)groupIndex;
            targetAffinity.Mask = bit;
            KeSetSystemGroupAffinityThread(&targetAffinity, &previousAffinity);
            sample.Group = groupIndex;
            sample.Number = processorNumber.Number;
            KswordARKCpuIntegrityCaptureCurrent(&sample);
            KeRevertToUserGroupAffinityThread(&previousAffinity);
            visitedInGroup += 1UL;
            totalCpus += 1UL;
            KswordARKCpuIntegrityEmitControlRows(Builder, &sample, ModuleInfo, consistencyView);
            if ((Flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES) != 0UL) {
                KswordARKCpuIntegrityEmitIdtRows(Builder, &sample, ModuleInfo, MaxIdtVectorsPerCpu, &interruptContext);
            }
            if ((Flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_GDT_ENTRIES) != 0UL) {
                KswordARKCpuIntegrityEmitGdtRows(Builder, &sample);
            }
        }
    }
    *CpuCountOut = totalCpus;
    // 中断对象二级核对的整次汇总：干净的部分只占这一行，异常行在逐向量处已经各自产出。
    KswordARKInterruptObjectEmitSummary(Builder, &interruptContext);
    // 一致性视图只在本次采集期间有效，归还它的非分页池。
    KswordARKIdtConsistencyRelease(consistencyView);
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Builder);
    UNREFERENCED_PARAMETER(ModuleInfo);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(MaxIdtVectorsPerCpu);
    if (CpuCountOut != NULL) {
        *CpuCountOut = 0UL;
    }
    return STATUS_NOT_SUPPORTED;
#endif
}
