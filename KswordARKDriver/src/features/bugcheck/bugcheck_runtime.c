/*++

Module Name:

    bugcheck_runtime.c

Abstract:

    Bugcheck callback registration and nonpaged diagnostic state for the
    fail-closed physical BGP panel.

--*/

#include "bugcheck_internal.h"
#include "bugcheck_decode.h"
#include "bugcheck_bgp.h"
#include "bugcheck_panel.h"
#include "bugcheck_preparation_log.h"
#include "../../platform/pool_compat.h"

#include <aux_klib.h>
#include <ntstrsafe.h>

#define KSWORD_ARK_BUGCHECK_POOL_TAG 'cbSK'
#define KSWORD_ARK_BUGCHECK_SECONDARY_SIGNATURE 0x4442534BUL /* 'KSBD' */

NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

typedef PEPROCESS
(NTAPI* KSWORD_ARK_BUGCHECK_PS_GET_NEXT_PROCESS)(
    _In_opt_ PEPROCESS Process
    );

typedef struct _KSWORD_ARK_BUGCHECK_SECONDARY_DATA
{
    ULONG Signature;
    ULONG Version;
    ULONG Size;
    ULONG Reserved;
    KSWORD_ARK_BUGCHECK_DIAGNOSTICS Diagnostics;
    KSWORD_ARK_BGP_DUMP_STATE BgpState;
} KSWORD_ARK_BUGCHECK_SECONDARY_DATA;

#define KSWORD_ARK_BUGCHECK_CALLBACK_CLASSIC   0x00000001UL
#define KSWORD_ARK_BUGCHECK_CALLBACK_SECONDARY 0x00000002UL
#define KSWORD_ARK_BUGCHECK_CALLBACK_DUMP_IO   0x00000004UL
#define KSWORD_ARK_BUGCHECK_CALLBACK_TRIAGE    0x00000008UL

KSWORD_ARK_BUGCHECK_STATE g_KswordArkBugcheckState;
UCHAR g_KswordArkBugcheckBitmapPixels[KSWORD_ARK_BUGCHECK_BITMAP_MAX_BYTES];

static UCHAR g_KswordArkBugcheckComponent[] = "KswordARK";
static KSWORD_ARK_BUGCHECK_SECONDARY_DATA g_KswordArkBugcheckSecondaryData;
static const GUID g_KswordArkBugcheckSecondaryGuid =
{ 0x956d0947, 0x326a, 0x4ba7, { 0x92, 0xf1, 0x4c, 0x8b, 0x5a, 0x5c, 0x71, 0x2d } };

static ULONG
KswordARKBugcheckCallbackMask(
    VOID
    )
{
    ULONG callbackMask;

    callbackMask = 0;
    if (g_KswordArkBugcheckState.ClassicRegistered) {
        callbackMask |= KSWORD_ARK_BUGCHECK_CALLBACK_CLASSIC;
    }
    if (g_KswordArkBugcheckState.SecondaryRegistered) {
        callbackMask |= KSWORD_ARK_BUGCHECK_CALLBACK_SECONDARY;
    }
    if (g_KswordArkBugcheckState.DumpIoRegistered) {
        callbackMask |= KSWORD_ARK_BUGCHECK_CALLBACK_DUMP_IO;
    }
    if (g_KswordArkBugcheckState.TriageRegistered) {
        callbackMask |= KSWORD_ARK_BUGCHECK_CALLBACK_TRIAGE;
    }
    return callbackMask;
}

static VOID
KswordARKBugcheckUpdateSecondaryData(
    VOID
    )
{
    g_KswordArkBugcheckSecondaryData.Signature =
        KSWORD_ARK_BUGCHECK_SECONDARY_SIGNATURE;
    g_KswordArkBugcheckSecondaryData.Version = 4UL;
    g_KswordArkBugcheckSecondaryData.Size =
        sizeof(g_KswordArkBugcheckSecondaryData);
    RtlCopyMemory(
        &g_KswordArkBugcheckSecondaryData.Diagnostics,
        &g_KswordArkBugcheckState.Diagnostics,
        sizeof(g_KswordArkBugcheckSecondaryData.Diagnostics));
    KswordARKBugcheckBgpSnapshot(
        &g_KswordArkBugcheckSecondaryData.BgpState);
}

static CHAR
KswordARKBugcheckLowerA(
    _In_ CHAR Value
    )
{
    return (Value >= 'A' && Value <= 'Z') ? (CHAR)(Value - 'A' + 'a') : Value;
}

static BOOLEAN
KswordARKBugcheckEqualsNoCaseA(
    _In_z_ PCSTR Left,
    _In_z_ PCSTR Right
    )
{
    if (Left == NULL || Right == NULL) {
        return FALSE;
    }

    while (*Left != '\0' && *Right != '\0') {
        if (KswordARKBugcheckLowerA(*Left) != KswordARKBugcheckLowerA(*Right)) {
            return FALSE;
        }
        ++Left;
        ++Right;
    }

    return (*Left == '\0' && *Right == '\0') ? TRUE : FALSE;
}

static BOOLEAN
KswordARKBugcheckStartsWithNoCaseA(
    _In_z_ PCSTR Text,
    _In_z_ PCSTR Prefix
    )
{
    if (Text == NULL || Prefix == NULL) {
        return FALSE;
    }

    while (*Prefix != '\0') {
        if (*Text == '\0' ||
            KswordARKBugcheckLowerA(*Text) != KswordARKBugcheckLowerA(*Prefix)) {
            return FALSE;
        }
        ++Text;
        ++Prefix;
    }
    return TRUE;
}

static BOOLEAN
KswordARKBugcheckContainsNoCaseA(
    _In_z_ PCSTR Text,
    _In_z_ PCSTR Needle
    )
{
    PCSTR cursor;

    if (Text == NULL || Needle == NULL || Needle[0] == '\0') {
        return FALSE;
    }

    for (cursor = Text; *cursor != '\0'; ++cursor) {
        if (KswordARKBugcheckStartsWithNoCaseA(cursor, Needle)) {
            return TRUE;
        }
    }
    return FALSE;
}

static ULONG
KswordARKBugcheckClassifyModuleName(
    _In_z_ PCSTR Name
    )
{
    static const PCSTR knownMicrosoftModules[] = {
        "ntoskrnl.exe", "hal.dll", "kdcom.dll", "bootvid.dll", "ci.dll",
        "clfs.sys", "cng.sys", "acpi.sys", "pci.sys", "partmgr.sys",
        "volmgr.sys", "volsnap.sys", "disk.sys", "classpnp.sys",
        "storport.sys", "stornvme.sys", "ntfs.sys", "fltmgr.sys",
        "ndis.sys", "tcpip.sys", "afd.sys", "wdf01000.sys",
        "watchdog.sys", "dxgkrnl.sys", "basicdisplay.sys",
        "basicrender.sys", "win32k.sys"
    };
    ULONG index;

    if (Name == NULL || Name[0] == '\0') {
        return KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN;
    }

    if (KswordARKBugcheckEqualsNoCaseA(Name, "KswordARK.sys") ||
        KswordARKBugcheckContainsNoCaseA(Name, "kswordark")) {
        return KSWORD_ARK_BUGCHECK_MODULE_OURS;
    }

    for (index = 0; index < RTL_NUMBER_OF(knownMicrosoftModules); ++index) {
        if (KswordARKBugcheckEqualsNoCaseA(Name, knownMicrosoftModules[index])) {
            return KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT;
        }
    }

    if (KswordARKBugcheckStartsWithNoCaseA(Name, "win32k") ||
        KswordARKBugcheckStartsWithNoCaseA(Name, "dxgmms") ||
        KswordARKBugcheckStartsWithNoCaseA(Name, "ksec") ||
        KswordARKBugcheckStartsWithNoCaseA(Name, "msrpc") ||
        KswordARKBugcheckStartsWithNoCaseA(Name, "netio") ||
        KswordARKBugcheckStartsWithNoCaseA(Name, "spaceport") ||
        KswordARKBugcheckStartsWithNoCaseA(Name, "iorate")) {
        return KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT;
    }

    return KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY;
}

static VOID
KswordARKBugcheckPublishModule(
    _In_ ULONG_PTR Base,
    _In_ ULONG Size,
    _In_z_ PCSTR Name
    )
{
    KIRQL oldIrql;
    ULONG index;
    ULONG targetIndex;
    PKSWORD_ARK_BUGCHECK_MODULE_ENTRY entry;

    if (Base < 0x10000ULL || Size == 0 || Name == NULL || Name[0] == '\0' ||
        InterlockedCompareExchange(
            &g_KswordArkBugcheckState.TrackingReady,
            1,
            1) == 0) {
        return;
    }

    KeAcquireSpinLock(&g_KswordArkBugcheckState.ModuleCacheLock, &oldIrql);
    targetIndex = MAXULONG;
    for (index = 0; index < KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT; ++index) {
        ULONG_PTR existingBase;
        ULONG_PTR existingEnd;
        ULONG_PTR newEnd;

        entry = &g_KswordArkBugcheckState.Modules[index];
        existingBase = entry->Base;
        if (existingBase == 0 || entry->Size == 0) {
            if (targetIndex == MAXULONG) {
                targetIndex = index;
            }
            continue;
        }
        existingEnd = existingBase + entry->Size;
        newEnd = Base + Size;
        if (existingBase == Base ||
            (Base < existingEnd && existingBase < newEnd)) {
            targetIndex = index;
            break;
        }
    }
    if (targetIndex == MAXULONG) {
        targetIndex = g_KswordArkBugcheckState.ModuleNextSlot %
            KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT;
        ++g_KswordArkBugcheckState.ModuleNextSlot;
    }

    entry = &g_KswordArkBugcheckState.Modules[targetIndex];
    if (entry->Base == 0 &&
        g_KswordArkBugcheckState.ModuleCount <
            KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT) {
        ++g_KswordArkBugcheckState.ModuleCount;
    }
    (VOID)InterlockedIncrement(&entry->Sequence);
    KeMemoryBarrier();
    entry->Base = Base;
    entry->Size = Size;
    entry->Classification = KswordARKBugcheckClassifyModuleName(Name);
    (VOID)RtlStringCbCopyA(entry->Name, sizeof(entry->Name), Name);
    entry->Name[KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS - 1UL] = '\0';
    KeMemoryBarrier();
    (VOID)InterlockedIncrement(&entry->Sequence);
    KeReleaseSpinLock(&g_KswordArkBugcheckState.ModuleCacheLock, oldIrql);
}

static BOOLEAN
KswordARKBugcheckCopyUnicodeBaseNameA(
    _In_opt_ PCUNICODE_STRING FullImageName,
    _Out_writes_z_(Capacity) PCHAR Name,
    _In_ ULONG Capacity
    )
{
    USHORT characterCount;
    USHORT start;
    USHORT index;
    ULONG copied;

    if (Name == NULL || Capacity == 0) {
        return FALSE;
    }
    Name[0] = '\0';
    if (FullImageName == NULL || FullImageName->Buffer == NULL ||
        FullImageName->Length < sizeof(WCHAR)) {
        return FALSE;
    }

    characterCount = FullImageName->Length / sizeof(WCHAR);
    start = 0;
    for (index = 0; index < characterCount; ++index) {
        if (FullImageName->Buffer[index] == L'\\' ||
            FullImageName->Buffer[index] == L'/') {
            start = (USHORT)(index + 1U);
        }
    }
    copied = 0;
    for (index = start;
         index < characterCount && copied + 1UL < Capacity;
         ++index) {
        WCHAR value;

        value = FullImageName->Buffer[index];
        Name[copied++] = value >= 0x20 && value <= 0x7E
            ? (CHAR)value
            : '?';
    }
    Name[copied] = '\0';
    return copied != 0 ? TRUE : FALSE;
}

VOID
KswordARKBugcheckTrackLoadedImage(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    CHAR name[KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS];

    UNREFERENCED_PARAMETER(ProcessId);
    if (ImageInfo == NULL || !ImageInfo->SystemModeImage ||
        ImageInfo->ImageBase == NULL || ImageInfo->ImageSize == 0 ||
        ImageInfo->ImageSize > MAXULONG ||
        !KswordARKBugcheckCopyUnicodeBaseNameA(
            FullImageName,
            name,
            (ULONG)RTL_NUMBER_OF(name))) {
        return;
    }
    KswordARKBugcheckPublishModule(
        (ULONG_PTR)ImageInfo->ImageBase,
        (ULONG)ImageInfo->ImageSize,
        name);
}

static VOID
KswordARKBugcheckPublishProcess(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Exiting
    )
{
    CHAR name[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS];
    PCSTR imageName;
    KIRQL oldIrql;
    ULONG index;
    ULONG targetIndex;
    ULONG exitingIndex;
    PKSWORD_ARK_BUGCHECK_PROCESS_ENTRY entry;

    if (Process == NULL ||
        InterlockedCompareExchange(
            &g_KswordArkBugcheckState.TrackingReady,
            1,
            1) == 0) {
        return;
    }
    RtlZeroMemory(name, sizeof(name));
    imageName = PsGetProcessImageFileName(Process);
    if (imageName != NULL) {
        (VOID)RtlStringCbCopyA(name, sizeof(name), imageName);
    }
    name[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS - 1UL] = '\0';

    KeAcquireSpinLock(&g_KswordArkBugcheckState.ProcessCacheLock, &oldIrql);
    targetIndex = MAXULONG;
    exitingIndex = MAXULONG;
    for (index = 0; index < KSWORD_ARK_BUGCHECK_PROCESS_CACHE_COUNT; ++index) {
        entry = &g_KswordArkBugcheckState.Processes[index];
        if (entry->Object == Process) {
            targetIndex = index;
            break;
        }
        if (entry->Object == NULL && targetIndex == MAXULONG) {
            targetIndex = index;
        } else if (entry->Exiting && exitingIndex == MAXULONG) {
            exitingIndex = index;
        }
    }
    if (targetIndex == MAXULONG) {
        targetIndex = exitingIndex != MAXULONG
            ? exitingIndex
            : g_KswordArkBugcheckState.ProcessNextSlot %
                KSWORD_ARK_BUGCHECK_PROCESS_CACHE_COUNT;
        ++g_KswordArkBugcheckState.ProcessNextSlot;
    }

    entry = &g_KswordArkBugcheckState.Processes[targetIndex];
    if (entry->Object == NULL &&
        g_KswordArkBugcheckState.ProcessCount <
            KSWORD_ARK_BUGCHECK_PROCESS_CACHE_COUNT) {
        ++g_KswordArkBugcheckState.ProcessCount;
    }
    (VOID)InterlockedIncrement(&entry->Sequence);
    KeMemoryBarrier();
    entry->Object = Process;
    entry->ProcessId = (ULONG_PTR)ProcessId;
    entry->Exiting = Exiting;
    if (name[0] != '\0' || entry->Name[0] == '\0') {
        (VOID)RtlStringCbCopyA(entry->Name, sizeof(entry->Name), name);
    }
    entry->Name[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS - 1UL] = '\0';
    KeMemoryBarrier();
    (VOID)InterlockedIncrement(&entry->Sequence);
    KeReleaseSpinLock(&g_KswordArkBugcheckState.ProcessCacheLock, oldIrql);
}

VOID
KswordARKBugcheckTrackProcess(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    KswordARKBugcheckPublishProcess(
        Process,
        ProcessId,
        CreateInfo == NULL ? TRUE : FALSE);
}

static VOID
KswordARKBugcheckRefreshProcessCache(
    VOID
    )
{
    UNICODE_STRING routineName;
    KSWORD_ARK_BUGCHECK_PS_GET_NEXT_PROCESS getNextProcess;
    PEPROCESS process;
    ULONG visited;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    getNextProcess = (KSWORD_ARK_BUGCHECK_PS_GET_NEXT_PROCESS)
        MmGetSystemRoutineAddress(&routineName);
    if (getNextProcess == NULL) {
        return;
    }

    visited = 0;
    process = getNextProcess(NULL);
    while (process != NULL && visited < 65536UL) {
        PEPROCESS nextProcess;

        if (!NT_SUCCESS(KswordARKBugcheckControlCheckAbort())) {
            break;
        }

        nextProcess = getNextProcess(process);
        KswordARKBugcheckPublishProcess(
            process,
            PsGetProcessId(process),
            FALSE);
        ObDereferenceObject(process);
        process = nextProcess;
        ++visited;
    }
    if (process != NULL) {
        ObDereferenceObject(process);
    }
}

PCSTR
KswordARKBugcheckName(
    _In_ ULONG BugCheckCode
    )
{
    switch (BugCheckCode) {
    case 0x0000000A: return "IRQL_NOT_LESS_OR_EQUAL";
    case 0x0000001A: return "MEMORY_MANAGEMENT";
    case 0x0000001E: return "KMODE_EXCEPTION_NOT_HANDLED";
    case 0x00000024: return "NTFS_FILE_SYSTEM";
    case 0x0000002E: return "DATA_BUS_ERROR";
    case 0x0000003B: return "SYSTEM_SERVICE_EXCEPTION";
    case 0x00000050: return "PAGE_FAULT_IN_NONPAGED_AREA";
    case 0x0000007E: return "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED";
    case 0x0000007F: return "UNEXPECTED_KERNEL_MODE_TRAP";
    case 0x0000009F: return "DRIVER_POWER_STATE_FAILURE";
    case 0x000000A0: return "INTERNAL_POWER_ERROR";
    case 0x000000BE: return "ATTEMPTED_WRITE_TO_READONLY_MEMORY";
    case 0x000000C2: return "BAD_POOL_CALLER";
    case 0x000000C4: return "DRIVER_VERIFIER_DETECTED_VIOLATION";
    case 0x000000C5: return "DRIVER_CORRUPTED_EXPOOL";
    case 0x000000C9: return "DRIVER_VERIFIER_IOMANAGER_VIOLATION";
    case 0x000000D1: return "DRIVER_IRQL_NOT_LESS_OR_EQUAL";
    case 0x000000D5: return "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL";
    case 0x000000EA: return "THREAD_STUCK_IN_DEVICE_DRIVER";
    case 0x000000EF: return "CRITICAL_PROCESS_DIED";
    case 0x000000F7: return "DRIVER_OVERRAN_STACK_BUFFER";
    case 0x00000109: return "CRITICAL_STRUCTURE_CORRUPTION";
    case 0x00000116: return "VIDEO_TDR_FAILURE";
    case 0x00000117: return "VIDEO_TDR_TIMEOUT_DETECTED";
    case 0x00000119: return "VIDEO_SCHEDULER_INTERNAL_ERROR";
    case 0x00000124: return "WHEA_UNCORRECTABLE_ERROR";
    case 0x00000133: return "DPC_WATCHDOG_VIOLATION";
    case 0x00000139: return "KERNEL_SECURITY_CHECK_FAILURE";
    case 0x0000013A: return "KERNEL_MODE_HEAP_CORRUPTION";
    default: return "UNKNOWN_BUGCHECK_CODE";
    }
}

PCSTR
KswordARKBugcheckModuleClassText(
    _In_ ULONG Classification
    )
{
    switch (Classification) {
    case KSWORD_ARK_BUGCHECK_MODULE_OURS: return "OUR_DRIVER";
    case KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT: return "MICROSOFT_KNOWN";
    case KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY: return "THIRD_PARTY";
    default: return "UNKNOWN";
    }
}

PCSTR
KswordARKBugcheckConfidenceText(
    _In_ ULONG Confidence
    )
{
    switch (Confidence) {
    case KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH: return "HIGH";
    case KSWORD_ARK_BUGCHECK_CONFIDENCE_MEDIUM: return "MEDIUM";
    case KSWORD_ARK_BUGCHECK_CONFIDENCE_LOW: return "LOW";
    default: return "NONE";
    }
}

PCSTR
KswordARKBugcheckVerdictText(
    _In_ ULONG Classification
    )
{
    switch (Classification) {
    case KSWORD_ARK_BUGCHECK_MODULE_OURS:
        return "KswordARK may be involved. Capture this page and attach the crash dump when reporting the issue.";
    case KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT:
        return "The available crash parameters point to a known Microsoft kernel component.";
    case KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY:
        return "The available crash parameters point to another third-party kernel component.";
    default:
        return "The faulting component is unknown. Capture this page and preserve the crash dump.";
    }
}

PCSTR
KswordARKBugcheckDumpTypeText(
    _In_ ULONG DumpType
    )
{
    switch (DumpType) {
    case KbDumpIoHeader: return "Header";
    case KbDumpIoBody: return "Body";
    case KbDumpIoSecondaryData: return "SecondaryData";
    case KbDumpIoComplete: return "Complete";
    default: return "Unknown";
    }
}

PCSTR
KswordARKBugcheckReasonText(
    _In_ ULONG Reason
    )
{
    switch (Reason) {
    case KbCallbackInvalid: return "Invalid";
    case KbCallbackSecondaryDumpData: return "SecondaryDumpData";
    case KbCallbackDumpIo: return "DumpIo";
    case KbCallbackAddPages: return "AddPages";
    case KbCallbackSecondaryMultiPartDumpData: return "SecondaryMultiPartDumpData";
    case KbCallbackRemovePages: return "RemovePages";
    case KbCallbackTriageDumpData: return "TriageDumpData";
    default: return "Unknown";
    }
}

static VOID
KswordARKBugcheckRefreshModuleCache(
    VOID
    )
{
    NTSTATUS status;
    ULONG bytes = 0;
    ULONG count;
    ULONG index;
    PAUX_MODULE_EXTENDED_INFO modules;
    PCSTR name;

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status)) {
        return;
    }

    status = AuxKlibQueryModuleInformation(
        &bytes,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        NULL);
    if (!NT_SUCCESS(status) || bytes == 0) {
        return;
    }

    modules = (PAUX_MODULE_EXTENDED_INFO)KswordARKAllocateNonPagedPool(
        bytes,
        KSWORD_ARK_BUGCHECK_POOL_TAG);
    if (modules == NULL) {
        return;
    }

    RtlZeroMemory(modules, bytes);
    status = AuxKlibQueryModuleInformation(
        &bytes,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        modules);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, KSWORD_ARK_BUGCHECK_POOL_TAG);
        return;
    }

    count = bytes / sizeof(AUX_MODULE_EXTENDED_INFO);
    for (index = 0; index < count; ++index) {
        if (!NT_SUCCESS(KswordARKBugcheckControlCheckAbort())) {
            break;
        }
        name = (PCSTR)modules[index].FullPathName;
        if (modules[index].FileNameOffset < AUX_KLIB_MODULE_PATH_LEN) {
            name = (PCSTR)&modules[index].FullPathName[modules[index].FileNameOffset];
        }

        KswordARKBugcheckPublishModule(
            (ULONG_PTR)modules[index].BasicInfo.ImageBase,
            modules[index].ImageSize,
            name);
    }
    ExFreePoolWithTag(modules, KSWORD_ARK_BUGCHECK_POOL_TAG);
}

static BOOLEAN
KswordARKBugcheckFindModuleForAddress(
    _In_ ULONG_PTR Address,
    _Out_ PKSWORD_ARK_BUGCHECK_MODULE_ENTRY Module
    )
{
    ULONG index;
    ULONG moduleCount;

    if (Address < 0x10000ULL || Module == NULL) {
        return FALSE;
    }
    RtlZeroMemory(Module, sizeof(*Module));
    moduleCount = g_KswordArkBugcheckState.ModuleCount;
    if (moduleCount > KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT) {
        moduleCount = KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT;
    }

    for (index = 0; index < moduleCount; ++index) {
        PKSWORD_ARK_BUGCHECK_MODULE_ENTRY entry;
        LONG sequenceBefore;
        LONG sequenceAfter;
        ULONG_PTR base;
        ULONG size;
        ULONG classification;
        CHAR name[KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS];

        entry = &g_KswordArkBugcheckState.Modules[index];
        sequenceBefore = InterlockedCompareExchange(&entry->Sequence, 0, 0);
        if ((sequenceBefore & 1L) != 0) {
            continue;
        }
        base = entry->Base;
        size = entry->Size;
        classification = entry->Classification;
        RtlCopyMemory(name, entry->Name, sizeof(name));
        name[KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS - 1UL] = '\0';
        KeMemoryBarrier();
        sequenceAfter = InterlockedCompareExchange(&entry->Sequence, 0, 0);
        if (sequenceBefore != sequenceAfter || (sequenceAfter & 1L) != 0) {
            continue;
        }
        if (base != 0 && size != 0 &&
            Address >= base && Address - base < size) {
            Module->Base = base;
            Module->Size = size;
            Module->Classification = classification;
            (VOID)RtlStringCbCopyA(Module->Name, sizeof(Module->Name), name);
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
KswordARKBugcheckFindProcessForObject(
    _In_ PVOID ProcessObject,
    _Out_ PULONG_PTR ProcessId,
    _Out_writes_z_(NameCapacity) PCHAR Name,
    _In_ ULONG NameCapacity
    )
{
    ULONG index;

    if (ProcessObject == NULL || ProcessId == NULL || Name == NULL ||
        NameCapacity == 0) {
        return FALSE;
    }
    *ProcessId = 0;
    Name[0] = '\0';

    for (index = 0; index < KSWORD_ARK_BUGCHECK_PROCESS_CACHE_COUNT; ++index) {
        PKSWORD_ARK_BUGCHECK_PROCESS_ENTRY entry;
        LONG sequenceBefore;
        LONG sequenceAfter;
        PVOID object;
        ULONG_PTR processId;
        CHAR processName[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS];

        entry = &g_KswordArkBugcheckState.Processes[index];
        sequenceBefore = InterlockedCompareExchange(&entry->Sequence, 0, 0);
        if ((sequenceBefore & 1L) != 0) {
            continue;
        }
        object = entry->Object;
        processId = entry->ProcessId;
        RtlCopyMemory(processName, entry->Name, sizeof(processName));
        processName[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS - 1UL] = '\0';
        KeMemoryBarrier();
        sequenceAfter = InterlockedCompareExchange(&entry->Sequence, 0, 0);
        if (sequenceBefore != sequenceAfter || (sequenceAfter & 1L) != 0 ||
            object != ProcessObject) {
            continue;
        }

        *ProcessId = processId;
        (VOID)RtlStringCbCopyA(Name, NameCapacity, processName);
        return processName[0] != '\0' ? TRUE : FALSE;
    }
    return FALSE;
}

static VOID
KswordARKBugcheckResolveProcessContext(
    _Inout_ PKSWORD_ARK_BUGCHECK_DIAGNOSTICS Diagnostics
    )
{
    PVOID processObject;

    Diagnostics->ProcessObject = 0;
    Diagnostics->ProcessId = 0;
    Diagnostics->ProcessSource = KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_NONE;
    Diagnostics->ProcessName[0] = '\0';
    if (Diagnostics->BugCheckCode == 0x000000EF &&
        Diagnostics->Parameter1 != 0) {
        processObject = (PVOID)Diagnostics->Parameter1;
        Diagnostics->ProcessSource =
            KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_CRITICAL;
    } else {
        processObject = PsGetCurrentProcess();
        Diagnostics->ProcessSource =
            KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_CONTEXT;
    }
    Diagnostics->ProcessObject = (ULONG_PTR)processObject;
    (VOID)KswordARKBugcheckFindProcessForObject(
        processObject,
        &Diagnostics->ProcessId,
        Diagnostics->ProcessName,
        (ULONG)sizeof(Diagnostics->ProcessName));
}

static VOID
KswordARKBugcheckSetCandidate(
    _Inout_ PKSWORD_ARK_BUGCHECK_DIAGNOSTICS Diagnostics,
    _In_ PKSWORD_ARK_BUGCHECK_MODULE_ENTRY Module,
    _In_ ULONG_PTR Address,
    _In_ ULONG Confidence,
    _In_ ULONG ParameterIndex,
    _In_z_ PCSTR Source
    )
{
    Diagnostics->CandidateAddress = Address;
    Diagnostics->CandidateModuleBase = Module->Base;
    Diagnostics->CandidateModuleSize = Module->Size;
    Diagnostics->CandidateModuleOffset = Address >= Module->Base
        ? Address - Module->Base
        : 0;
    Diagnostics->CandidateParameter = ParameterIndex;
    Diagnostics->CandidateClass = Module->Classification;
    Diagnostics->CandidateConfidence = Confidence;
    (VOID)RtlStringCbCopyA(
        Diagnostics->CandidateModule,
        sizeof(Diagnostics->CandidateModule),
        Module->Name);
    (VOID)RtlStringCbCopyA(
        Diagnostics->CandidateSource,
        sizeof(Diagnostics->CandidateSource),
        Source);
}

static VOID
KswordARKBugcheckResolveCandidate(
    _Inout_ PKSWORD_ARK_BUGCHECK_DIAGNOSTICS Diagnostics
    )
{
    ULONG_PTR primaryAddress;
    ULONG primaryParameter;
    ULONG primaryConfidence;
    KSWORD_ARK_BUGCHECK_MODULE_ENTRY module;

    Diagnostics->CandidateAddress = 0;
    Diagnostics->CandidateModuleBase = 0;
    Diagnostics->CandidateModuleOffset = 0;
    Diagnostics->CandidateModuleSize = 0;
    Diagnostics->CandidateParameter = 0;
    Diagnostics->CandidateClass = KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN;
    Diagnostics->CandidateConfidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_NONE;
    (VOID)RtlStringCbCopyA(
        Diagnostics->CandidateModule,
        sizeof(Diagnostics->CandidateModule),
        "(none)");
    (VOID)RtlStringCbCopyA(
        Diagnostics->CandidateSource,
        sizeof(Diagnostics->CandidateSource),
        "none");
    Diagnostics->FaultAddress = 0;
    Diagnostics->FaultParameter = 0;
    (VOID)RtlStringCbCopyA(
        Diagnostics->FaultMeaning,
        sizeof(Diagnostics->FaultMeaning),
        "not classified");

    if (KswordARKBugcheckDecodePrimaryAddress(
            Diagnostics,
            &primaryAddress,
            &primaryParameter,
            &primaryConfidence)) {
        if (KswordARKBugcheckFindModuleForAddress(primaryAddress, &module)) {
            KswordARKBugcheckSetCandidate(
                Diagnostics,
                &module,
                primaryAddress,
                primaryConfidence,
                primaryParameter,
                "bugcheck-specific address parameter");
            return;
        }
    }
}

static VOID
KswordARKBugcheckCaptureData(
    _In_opt_ PKBUGCHECK_TRIAGE_DUMP_DATA TriageData,
    _In_ ULONG Reason,
    _In_ ULONG DumpType,
    _In_ ULONG64 DumpOffset,
    _In_ ULONG DumpBufferLength
    )
{
    KBUGCHECK_DATA bugData;
    PKSWORD_ARK_BUGCHECK_DIAGNOSTICS diagnostics =
        &g_KswordArkBugcheckState.Diagnostics;

    RtlZeroMemory(&bugData, sizeof(bugData));
    bugData.BugCheckDataSize = sizeof(bugData);

    if (TriageData != NULL) {
        diagnostics->BugCheckCode = TriageData->BugCheckCode;
        diagnostics->Parameter1 = TriageData->BugCheckParameter1;
        diagnostics->Parameter2 = TriageData->BugCheckParameter2;
        diagnostics->Parameter3 = TriageData->BugCheckParameter3;
        diagnostics->Parameter4 = TriageData->BugCheckParameter4;
    } else if (NT_SUCCESS(AuxKlibGetBugCheckData(&bugData)) &&
               bugData.BugCheckDataSize >= sizeof(bugData)) {
        diagnostics->BugCheckCode = bugData.BugCheckCode;
        diagnostics->Parameter1 = bugData.Parameter1;
        diagnostics->Parameter2 = bugData.Parameter2;
        diagnostics->Parameter3 = bugData.Parameter3;
        diagnostics->Parameter4 = bugData.Parameter4;
    }

    diagnostics->LastReason = Reason;
    diagnostics->LastDumpType = DumpType;
    diagnostics->DumpOffset = DumpOffset;
    diagnostics->DumpBufferLength = DumpBufferLength;
    diagnostics->Irql = (ULONG)KeGetCurrentIrql();
    diagnostics->Cpu = KeGetCurrentProcessorNumber();
    diagnostics->PerfCounter = KeQueryPerformanceCounter(NULL);
    KswordARKBugcheckResolveProcessContext(diagnostics);
    KswordARKBugcheckResolveCandidate(diagnostics);
    InterlockedExchange(&diagnostics->Captured, 1);

    KswordARKBugcheckUpdateSecondaryData();
}

static VOID
KswordARKBugcheckClassicCallback(
    _In_ PVOID Buffer,
    _In_ ULONG Length
    )
{
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Length);

    // Windows can paint over the classic callback. The late dump-I/O callback
    // owns the actual panel draw, so this callback intentionally performs no I/O.
    (VOID)InterlockedCompareExchange(
        &g_KswordArkBugcheckState.ClassicDisplayStarted,
        1,
        0);
}

static VOID
KswordARKBugcheckReasonCallback(
    _In_ KBUGCHECK_CALLBACK_REASON Reason,
    _In_ PKBUGCHECK_REASON_CALLBACK_RECORD Record,
    _Inout_ PVOID ReasonSpecificData,
    _In_ ULONG ReasonSpecificDataLength
    )
{
    PKBUGCHECK_SECONDARY_DUMP_DATA secondaryData;
    PKBUGCHECK_DUMP_IO dumpIoData;
    PKBUGCHECK_TRIAGE_DUMP_DATA triageData;
    ULONG dumpLength;

    UNREFERENCED_PARAMETER(Record);

    if (ReasonSpecificData == NULL ||
        InterlockedCompareExchange(&g_KswordArkBugcheckState.Active, 1, 1) == 0) {
        return;
    }

    if (Reason == KbCallbackSecondaryDumpData) {
        if (ReasonSpecificDataLength < sizeof(KBUGCHECK_SECONDARY_DUMP_DATA)) {
            return;
        }
        KswordARKBugcheckUpdateSecondaryData();
        secondaryData = (PKBUGCHECK_SECONDARY_DUMP_DATA)ReasonSpecificData;
        dumpLength = sizeof(g_KswordArkBugcheckSecondaryData);
        if (dumpLength > secondaryData->MaximumAllowed) {
            dumpLength = secondaryData->MaximumAllowed;
        }
        secondaryData->Guid = g_KswordArkBugcheckSecondaryGuid;
        secondaryData->OutBuffer = &g_KswordArkBugcheckSecondaryData;
        secondaryData->OutBufferLength = dumpLength;
        return;
    }

    if (Reason == KbCallbackTriageDumpData) {
        if (ReasonSpecificDataLength < sizeof(KBUGCHECK_TRIAGE_DUMP_DATA)) {
            return;
        }
        triageData = (PKBUGCHECK_TRIAGE_DUMP_DATA)ReasonSpecificData;
        KswordARKBugcheckCaptureData(
            triageData,
            Reason,
            KbDumpIoInvalid,
            0,
            0);
        return;
    }

    if (Reason == KbCallbackDumpIo) {
        if (ReasonSpecificDataLength < sizeof(KBUGCHECK_DUMP_IO)) {
            return;
        }
        dumpIoData = (PKBUGCHECK_DUMP_IO)ReasonSpecificData;
        KswordARKBugcheckCaptureData(
            NULL,
            Reason,
            dumpIoData->Type,
            dumpIoData->Offset,
            dumpIoData->BufferLength);
        if ((dumpIoData->Type == KbDumpIoHeader ||
             dumpIoData->Type == KbDumpIoBody ||
             dumpIoData->Type == KbDumpIoSecondaryData) &&
            InterlockedCompareExchange(
                &g_KswordArkBugcheckState.DumpDisplayStarted,
                1,
                0) == 0) {
            (VOID)KswordARKBugcheckPanelDraw(
                &g_KswordArkBugcheckState.Diagnostics,
                KswordARKBugcheckCallbackMask(),
                g_KswordArkBugcheckState.ModuleCount);
        }
    }
}

NTSTATUS
KswordARKBugcheckInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ WDFDEVICE ControlDevice
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(ControlDevice);
    return STATUS_NOT_SUPPORTED;
#else
    NTSTATUS bgpStatus;
    NTSTATUS callbackStatus;
    NTSTATUS abortStatus;
    NTSTATUS logStatus;
    NTSTATUS panelStatus;

    if (DriverObject == NULL || ControlDevice == WDF_NO_HANDLE) {
        return STATUS_INVALID_PARAMETER;
    }
    abortStatus = KswordARKBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        return abortStatus;
    }

    RtlZeroMemory(&g_KswordArkBugcheckState, sizeof(g_KswordArkBugcheckState));
    RtlZeroMemory(
        &g_KswordArkBugcheckSecondaryData,
        sizeof(g_KswordArkBugcheckSecondaryData));
    g_KswordArkBugcheckState.DriverObject = DriverObject;
    g_KswordArkBugcheckState.DeviceObject =
        WdfDeviceWdmGetDeviceObject(ControlDevice);
    g_KswordArkBugcheckState.Bitmap.BrandColorRgb = 0x0078D4UL;
    KeInitializeSpinLock(&g_KswordArkBugcheckState.ModuleCacheLock);
    KeInitializeSpinLock(&g_KswordArkBugcheckState.ProcessCacheLock);
    InterlockedExchange(&g_KswordArkBugcheckState.TrackingReady, 1);

    panelStatus = STATUS_DEVICE_NOT_READY;
    bgpStatus = KswordARKBugcheckBgpInitialize();
    if (NT_SUCCESS(bgpStatus)) {
        panelStatus = KswordARKBugcheckPanelInitialize();
    } else {
        panelStatus = bgpStatus;
    }

    // 超时或卸载取消属于控制层终止，不得继续注册任何 BugCheck 回调。
    abortStatus = KswordARKBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        return abortStatus;
    }

    KswordARKBugcheckRefreshModuleCache();
    abortStatus = KswordARKBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        return abortStatus;
    }
    KswordARKBugcheckRefreshProcessCache();
    abortStatus = KswordARKBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        return abortStatus;
    }
    InterlockedExchange(&g_KswordArkBugcheckState.Active, 1);

    KeInitializeCallbackRecord(&g_KswordArkBugcheckState.ClassicRecord);
    g_KswordArkBugcheckState.ClassicRegistered =
        KeRegisterBugCheckCallback(
            &g_KswordArkBugcheckState.ClassicRecord,
            KswordARKBugcheckClassicCallback,
            &g_KswordArkBugcheckSecondaryData,
            sizeof(g_KswordArkBugcheckSecondaryData),
            g_KswordArkBugcheckComponent);

    KeInitializeCallbackRecord(&g_KswordArkBugcheckState.SecondaryRecord);
    g_KswordArkBugcheckState.SecondaryRegistered =
        KeRegisterBugCheckReasonCallback(
            &g_KswordArkBugcheckState.SecondaryRecord,
            KswordARKBugcheckReasonCallback,
            KbCallbackSecondaryDumpData,
            g_KswordArkBugcheckComponent);

    KeInitializeCallbackRecord(&g_KswordArkBugcheckState.DumpIoRecord);
    g_KswordArkBugcheckState.DumpIoRegistered =
        KeRegisterBugCheckReasonCallback(
            &g_KswordArkBugcheckState.DumpIoRecord,
            KswordARKBugcheckReasonCallback,
            KbCallbackDumpIo,
            g_KswordArkBugcheckComponent);

    KeInitializeCallbackRecord(&g_KswordArkBugcheckState.TriageRecord);
    g_KswordArkBugcheckState.TriageRegistered =
        KeRegisterBugCheckReasonCallback(
            &g_KswordArkBugcheckState.TriageRecord,
            KswordARKBugcheckReasonCallback,
            KbCallbackTriageDumpData,
            g_KswordArkBugcheckComponent);

    abortStatus = KswordARKBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        KswordARKBugcheckUninitialize();
        return abortStatus;
    }

    // Persist both successful and failed preparation results before a target
    // machine can be crashed for display testing.
    callbackStatus =
        g_KswordArkBugcheckState.ClassicRegistered &&
        g_KswordArkBugcheckState.SecondaryRegistered &&
        g_KswordArkBugcheckState.DumpIoRegistered &&
        g_KswordArkBugcheckState.TriageRegistered
            ? STATUS_SUCCESS
            : STATUS_UNSUCCESSFUL;
    logStatus = KswordARKBugcheckWritePreparationLog(
        bgpStatus,
        panelStatus,
        callbackStatus);
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        NT_SUCCESS(logStatus) ? DPFLTR_INFO_LEVEL : DPFLTR_ERROR_LEVEL,
        "KswordARK: BGP preparation=0x%08lX panel=0x%08lX "
        "callbacks=0x%08lX report=0x%08lX\n",
        (ULONG)bgpStatus,
        (ULONG)panelStatus,
        (ULONG)callbackStatus,
        (ULONG)logStatus);

    if (!g_KswordArkBugcheckState.ClassicRegistered ||
        !g_KswordArkBugcheckState.SecondaryRegistered ||
        !g_KswordArkBugcheckState.DumpIoRegistered ||
        !g_KswordArkBugcheckState.TriageRegistered) {
        KswordARKBugcheckUninitialize();
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
#endif
}

VOID
KswordARKBugcheckUninitialize(
    VOID
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    return;
#else
    InterlockedExchange(&g_KswordArkBugcheckState.TrackingReady, 0);
    KeMemoryBarrier();
    InterlockedExchange(&g_KswordArkBugcheckState.Active, 0);
    InterlockedExchange(&g_KswordArkBugcheckState.Bitmap.Valid, 0);

    if (g_KswordArkBugcheckState.TriageRegistered) {
        (VOID)KeDeregisterBugCheckReasonCallback(
            &g_KswordArkBugcheckState.TriageRecord);
        g_KswordArkBugcheckState.TriageRegistered = FALSE;
    }
    if (g_KswordArkBugcheckState.DumpIoRegistered) {
        (VOID)KeDeregisterBugCheckReasonCallback(
            &g_KswordArkBugcheckState.DumpIoRecord);
        g_KswordArkBugcheckState.DumpIoRegistered = FALSE;
    }
    if (g_KswordArkBugcheckState.SecondaryRegistered) {
        (VOID)KeDeregisterBugCheckReasonCallback(
            &g_KswordArkBugcheckState.SecondaryRecord);
        g_KswordArkBugcheckState.SecondaryRegistered = FALSE;
    }
    if (g_KswordArkBugcheckState.ClassicRegistered) {
        (VOID)KeDeregisterBugCheckCallback(
            &g_KswordArkBugcheckState.ClassicRecord);
        g_KswordArkBugcheckState.ClassicRegistered = FALSE;
    }

    KswordARKBugcheckPanelShutdown();
    KswordARKBugcheckBgpShutdown();
#endif
}
