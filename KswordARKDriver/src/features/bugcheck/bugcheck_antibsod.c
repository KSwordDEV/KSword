#include "ark/ark_driver.h"

/*++

Module Name:

    bugcheck_antibsod.c

Abstract:

    Faithful, algorithm-level reproduction of the Disable-PatchGuard-BSOD.sys
    sample described in the Anti-BSOD IDA analysis. This module exists so an
    operator working from the same report can inspect, single-step, and
    reason about the private-slot bugcheck-suppression pattern inside the
    KSword codebase without having to load or trust the original binary.

    What this file matches from the report
    --------------------------------------

      - Nine-slot, 0x4E0-byte per-build signature layout.
      - Five build ranges with per-build KTHREAD routine offsets (912, 1528,
        1104, 1248, 1248) and a legacy-build mode for pre-7602 systems.
      - Wildcard byte scan where 0x00 in the pattern matches any target byte.
      - RIP-relative displacement resolver.
      - ntoskrnl `.text` range located through ZwQuerySystemInformation
        SystemModuleInformation (class 11).
      - Stack-origin classifier reading up to 64 return addresses through
        RtlCaptureStackBackTrace and testing them against the resolved
        bugcheck code range.
      - Per-CPU KPCR/PRCB state capture broadcast by KeIpiGenericCall.
      - Two suppression hooks that overwrite the resolved private
        function-pointer slots, mutate private state, execute
        __writecr8(0), optionally call an undocumented KTHREAD routine,
        and permanently wait on a never-signaled NotificationEvent.

    What this file deliberately does not do
    ---------------------------------------

      - No ntoskrnl private signature bytes are shipped. Every pattern is
        zeroed with Length=0 so FindWildcardBytePattern returns 0 for
        every scan. Every downstream resolver returns 0 for zero inputs
        and Install fail-closes before touching a private slot. This is
        the same policy the analysis report followed: the pattern layout
        and offsets are public, the private kernel signature bytes are
        deliberately not.
      - The module is gated behind KSWORD_ARK_ANTIBSOD_REFERENCE_ENABLED
        which defaults to 0. When 0, every entry point in this file is a
        stub that returns STATUS_NOT_SUPPORTED. The shipping DriverEntry
        never wires this module active without an explicit rebuild.
      - Install adds the fail-closed pointer checks the analysis report
        identifies as missing from the sample. When any resolver returns
        0 the whole Install rolls back without writing any private slot.
      - This file is x64-only, kernel-mode, and uses only kernel primitives
        already imported by the KSword driver.

Environment:

    Kernel-mode Driver Framework

--*/

// The reference is x64-only. The KSword driver as a whole is x64-only,
// but restating the gate here makes the file portable when copied.
#if !defined(_WIN64)
#error KSword Anti-BSOD reference only supports x64 builds.
#endif

// Build gate. Default OFF: when 0 the module compiles to stubs that
// return STATUS_NOT_SUPPORTED and never touch kernel state. Turn on by
// setting KSWORD_ARK_ANTIBSOD_REFERENCE_ENABLED=1 in the compiler command
// line; note that turning it on without also filling in signatures still
// results in fail-closed Install, which is the design intent.
#ifndef KSWORD_ARK_ANTIBSOD_REFERENCE_ENABLED
#define KSWORD_ARK_ANTIBSOD_REFERENCE_ENABLED 0
#endif

// Wire the shared confirmation token to a compile-time check so the driver
// and any R3 caller cannot drift out of sync silently.
C_ASSERT(KSWORD_ARK_ANTIBSOD_CONFIRMATION_TOKEN == 0x424B414BUL);

#if !KSWORD_ARK_ANTIBSOD_REFERENCE_ENABLED

// Disabled build: keep the exported symbols so ioctl_registry.c and
// driver_entry.c can link, but return STATUS_NOT_SUPPORTED for every
// live operation.
VOID
KswordARKAntiBsodInitialize(
    VOID
    )
{
    // No state to initialize when the reference is disabled at build time.
}

VOID
KswordARKAntiBsodUninitialize(
    VOID
    )
{
    // Uninitialize is symmetric with Initialize: nothing to do when off.
}

NTSTATUS
KswordARKAntiBsodIoctlConfigure(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    // Explicitly acknowledge every parameter so /WX does not flag them.
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    // Zero BytesReturned so callers see a deterministic short reply.
    if (BytesReturned != NULL) {
        *BytesReturned = 0U;
    }
    return STATUS_NOT_SUPPORTED;
}

#else

// ============================================================================
// Section 1: signature slot and profile layout
// ============================================================================
//
// The Disable-PatchGuard-BSOD sample stores each build's signature set in
// a fixed 0x4E0-byte record. Slots are pattern arrays followed by scanner
// parameters. Three slot flavors exist:
//
//   ADD  = pattern + length + addOffset               (AddOffsetIfNonNull)
//   RIP  = pattern + length + dispOffset + trailing   (ResolveRipRelativeTarget)
//   READ = pattern + length + readOffset              (ReadUint32AtOffset)
//
// The composition is:
//   +0x000 Slot0 ADD  bugcheck-code anchor
//   +0x088 Slot1 RIP  bugcheck-code range start
//   +0x114 Slot2 ADD  bugcheck-code range end
//   +0x19C Slot3 RIP  private state DWORD pointer
//   +0x228 Slot4 READ PRCB bug-check state offset
//   +0x2B0 Slot5 READ KPCR secondary flag offset
//   +0x338 Slot6 RIP  bug-check-in-progress byte pointer
//   +0x3C4 Slot7 RIP  all-processors hook function slot
//   +0x450 Slot8 RIP  current-processor hook function slot
//   +0x4DC..0x4DF trailing padding
//
// All patterns are zeroed. Length=0 causes FindWildcardBytePattern to
// return 0 for every scan; Install treats each 0 result as fatal.

// ADD slot: 0x88 bytes total (128 pattern + 2 ULONG).
typedef struct _KSWORD_ARK_ANTIBSOD_SIG_ADD
{
    UCHAR Pattern[128];
    ULONG Length;
    ULONG AddOffset;
} KSWORD_ARK_ANTIBSOD_SIG_ADD;
C_ASSERT(sizeof(KSWORD_ARK_ANTIBSOD_SIG_ADD) == 0x88);

// RIP slot: 0x8C bytes total (128 pattern + 3 ULONG).
typedef struct _KSWORD_ARK_ANTIBSOD_SIG_RIP
{
    UCHAR Pattern[128];
    ULONG Length;
    ULONG DispOffset;
    ULONG TrailingAdjust;
} KSWORD_ARK_ANTIBSOD_SIG_RIP;
C_ASSERT(sizeof(KSWORD_ARK_ANTIBSOD_SIG_RIP) == 0x8C);

// READ slot: 0x88 bytes total (128 pattern + 2 ULONG).
typedef struct _KSWORD_ARK_ANTIBSOD_SIG_READ
{
    UCHAR Pattern[128];
    ULONG Length;
    ULONG ReadOffset;
} KSWORD_ARK_ANTIBSOD_SIG_READ;
C_ASSERT(sizeof(KSWORD_ARK_ANTIBSOD_SIG_READ) == 0x88);

// Full profile record. Nine slots + 4 bytes trailing padding = 0x4E0.
typedef struct _KSWORD_ARK_ANTIBSOD_PROFILE
{
    KSWORD_ARK_ANTIBSOD_SIG_ADD  Slot0BugcheckAnchor;
    KSWORD_ARK_ANTIBSOD_SIG_RIP  Slot1BugcheckCodeStart;
    KSWORD_ARK_ANTIBSOD_SIG_ADD  Slot2BugcheckCodeEnd;
    KSWORD_ARK_ANTIBSOD_SIG_RIP  Slot3StateFlagPtr;
    KSWORD_ARK_ANTIBSOD_SIG_READ Slot4KpcrStateOffset;
    KSWORD_ARK_ANTIBSOD_SIG_READ Slot5KpcrSecondaryOffset;
    KSWORD_ARK_ANTIBSOD_SIG_RIP  Slot6InProgressFlagPtr;
    KSWORD_ARK_ANTIBSOD_SIG_RIP  Slot7AllProcessorsHookSlot;
    KSWORD_ARK_ANTIBSOD_SIG_RIP  Slot8CurrentProcessorHookSlot;
    UCHAR TrailingPadding[4];
} KSWORD_ARK_ANTIBSOD_PROFILE;
C_ASSERT(sizeof(KSWORD_ARK_ANTIBSOD_PROFILE) == 0x4E0);

// Per-build metadata: build range, KTHREAD private routine offset, and
// the "legacy" bit for pre-7602 systems. Numbers come from the report.
typedef struct _KSWORD_ARK_ANTIBSOD_PROFILE_META
{
    ULONG MinBuild;
    ULONG MaxBuild;
    ULONG KthreadRoutineOffset;
    BOOLEAN LegacyBuildMode;
} KSWORD_ARK_ANTIBSOD_PROFILE_META;

// Five profiles. Add or trim entries only alongside a matching update to
// SelectWindowsBuildProfile.
#define KSWORD_ARK_ANTIBSOD_PROFILE_COUNT 5UL

static const KSWORD_ARK_ANTIBSOD_PROFILE_META
    g_KswordArkAntiBsodProfileMeta[KSWORD_ARK_ANTIBSOD_PROFILE_COUNT] = {
    {     0UL,  7601UL,  912UL, TRUE  }, // legacy Windows 7 / Server 2008 R2
    {  7602UL,  9600UL, 1528UL, FALSE }, // Windows 8 / 8.1 / Server 2012 (R2)
    {  9601UL, 20348UL, 1104UL, FALSE }, // Windows 10 through Server 2022
    { 20349UL, 26200UL, 1248UL, FALSE }, // Windows 11 21H2 through 24H2 era
    { 26201UL, 28000UL, 1248UL, FALSE }  // preview / Insider builds
};

// All-zero signature table. Filling in bytes here is the operator's own
// step and is not shipped with the driver. The table lives in .data so
// InstallSuppressionHooks can index it by the profile the OS build maps to.
static KSWORD_ARK_ANTIBSOD_PROFILE
    g_KswordArkAntiBsodProfiles[KSWORD_ARK_ANTIBSOD_PROFILE_COUNT];

// ============================================================================
// Section 2: SYSTEM_MODULE_INFORMATION mirror
// ============================================================================
//
// The sample enumerates loaded modules through ZwQuerySystemInformation
// class 11 (SystemModuleInformation) and walks the returned buffer with a
// fixed 296-byte stride. That layout matches the classic RTL_PROCESS_MODULES
// structure. We redeclare it locally so the file does not depend on
// non-WDK headers.

// A single module descriptor. Total size is 296 bytes.
typedef struct _KSWORD_ARK_ANTIBSOD_SYSTEM_MODULE
{
    HANDLE Section;           // +0x00
    PVOID  MappedBase;        // +0x08
    PVOID  ImageBase;         // +0x10
    ULONG  ImageSize;         // +0x18
    ULONG  Flags;             // +0x1C
    USHORT LoadOrderIndex;    // +0x20
    USHORT InitOrderIndex;    // +0x22
    USHORT LoadCount;         // +0x24
    USHORT OffsetToFileName;  // +0x26
    UCHAR  FullPathName[256]; // +0x28..+0x127
} KSWORD_ARK_ANTIBSOD_SYSTEM_MODULE;
C_ASSERT(sizeof(KSWORD_ARK_ANTIBSOD_SYSTEM_MODULE) == 296);

// Header + variable-length array.
typedef struct _KSWORD_ARK_ANTIBSOD_MODULE_LIST
{
    ULONG NumberOfModules;
    KSWORD_ARK_ANTIBSOD_SYSTEM_MODULE Modules[1];
} KSWORD_ARK_ANTIBSOD_MODULE_LIST;

// ZwQuerySystemInformation prototype (already used by bugcheck_guard.c;
// redeclared here so the file is self-contained).
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

// The classic SYSTEM_INFORMATION_CLASS value for SystemModuleInformation.
#define KSWORD_ARK_ANTIBSOD_SYSTEM_MODULE_INFORMATION_CLASS 11UL

// Pool tag used for the transient module-info allocation and per-CPU state
// arrays. Distinct from every other bugcheck-family tag so kernel triage
// pinpoints which module allocated a given block.
#define KSWORD_ARK_ANTIBSOD_POOL_TAG 'sbAK' /* 'KAbs' little-endian */

// ExAllocatePool2 is a Windows 10 20H1 addition. Older kernels do not
// export it and the driver has to run on both. Match the repository-wide
// convention: try to resolve ExAllocatePool2 dynamically, fall back to
// ExAllocatePoolWithTag with pragma-suppressed 4996 so /WX still succeeds.
typedef PVOID (NTAPI* KSWORD_ARK_ANTIBSOD_EX_ALLOCATE_POOL2_FN)(
    POOL_FLAGS Flags,
    SIZE_T NumberOfBytes,
    ULONG Tag);

static PVOID
KswordARKAntiBsodAllocateNonPaged(
    _In_ SIZE_T Bytes
    )
{
    // Cache the resolved routine across calls. LONG guard covers the
    // one-time resolve; subsequent callers hit the cached pointer.
    static volatile LONG resolved = 0L;
    static KSWORD_ARK_ANTIBSOD_EX_ALLOCATE_POOL2_FN allocatePool2 = NULL;
    UNICODE_STRING routineName;

    if (Bytes == 0U) {
        return NULL;
    }
    if (InterlockedCompareExchange(&resolved, 1L, 0L) == 0L) {
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        allocatePool2 = (KSWORD_ARK_ANTIBSOD_EX_ALLOCATE_POOL2_FN)
            MmGetSystemRoutineAddress(&routineName);
    }
    if (allocatePool2 != NULL) {
        // Modern path: NX non-paged pool through the documented flag API.
        return allocatePool2(
            POOL_FLAG_NON_PAGED,
            Bytes,
            KSWORD_ARK_ANTIBSOD_POOL_TAG);
    }
#pragma warning(push)
#pragma warning(disable:4996)
    // Legacy path: NonPagedPoolNx is the closest equivalent on down-level
    // Windows and the same choice the rest of the driver uses.
    return ExAllocatePoolWithTag(
        NonPagedPoolNx,
        Bytes,
        KSWORD_ARK_ANTIBSOD_POOL_TAG);
#pragma warning(pop)
}

// ============================================================================
// Section 3: runtime state
// ============================================================================

// KEVENT initializer type sentinel: NotificationEvent maps to 0 in the
// documented header, but we spell it out to keep the source explicit.
#define KSWORD_ARK_ANTIBSOD_EVENT_KIND NotificationEvent

typedef struct _KSWORD_ARK_ANTIBSOD_STATE
{
    // Serializes install/uninstall/query at PASSIVE_LEVEL. Callback code
    // never touches this lock: bugcheck path can run at HIGH_LEVEL where
    // FAST_MUTEX would deadlock.
    FAST_MUTEX ControlLock;

    // Set to 1 once InstallSuppressionHooks completes. Uninstall clears it.
    volatile LONG Installed;
    // Set to 1 once both hooks are live and the never-signaled event has
    // been initialized. Different from Installed so a partial install can
    // be observed by R3 for diagnostics.
    volatile LONG HooksActive;
    // Nesting counter incremented on hook entry and decremented on exit.
    // Uninstall refuses to release resources while this is nonzero.
    volatile LONG HookExecutions;
    // Bumped once per hook entry, never decremented. Reported to R3.
    volatile LONG HookInvocationCount;

    // Snapshot of the selected profile identity for diagnostics.
    ULONG WindowsBuildNumber;
    ULONG SelectedProfileIndex;
    ULONG KthreadRoutineOffset;
    BOOLEAN LegacyBuildMode;

    // Pointer to the selected profile inside g_KswordArkAntiBsodProfiles.
    const KSWORD_ARK_ANTIBSOD_PROFILE* Profile;

    // Resolved ntoskrnl module range and KeBugCheckEx anchor.
    ULONG_PTR NtTextStart;
    ULONG_PTR NtTextEnd;
    ULONG_PTR KeBugCheckExAddress;

    // Resolved private targets. Every one of these fields must be nonzero
    // before Install commits: this is the fail-closed check the analysis
    // report identifies as missing from the original sample.
    ULONG_PTR BugcheckScanBoundary;
    ULONG_PTR BugcheckCodeRangeStart;
    ULONG_PTR BugcheckCodeRangeEnd;
    ULONG_PTR BugcheckStateFlagPtr;
    ULONG     KpcrBugcheckStateOffset;
    ULONG     KpcrSecondaryFlagOffset;
    ULONG_PTR BugcheckInProgressFlagPtr;
    ULONG_PTR AllProcessorsHookSlot;
    ULONG_PTR CurrentProcessorHookSlot;

    // Function pointers we saved from the two hook slots before overwriting.
    PVOID OriginalAllProcessorsRoutine;
    PVOID OriginalCurrentProcessorRoutine;

    // Transparency masks published to R3. Bit N corresponds to slot N.
    //   SlotExpectedMask: profile has a nonzero pattern length for slot N.
    //   SlotHitMask: scan for slot N produced a nonzero resolved value.
    // Both are only meaningful after Install or Probe has run.
    volatile LONG SlotExpectedMask;
    volatile LONG SlotHitMask;
    // SupportSummary value from the shared header. Reset to UNKNOWN by
    // Uninitialize, updated by Install or Probe.
    volatile LONG SupportSummary;

    // Per-CPU state captured by the IPI broadcast.
    ULONG ActiveProcessorCount;
    ULONG_PTR* PerCpuPrcbArray;
    ULONG_PTR* PerCpuSecondaryStateArray;

    // Notification event that is created but never signaled. The hooks
    // wait on it forever. The analysis report identifies this as the
    // "permanent wait" that keeps the crashing CPU inside the driver.
    KEVENT NeverSignaledEvent;

    // Last kernel status surfaced to R3 for diagnostics.
    NTSTATUS LastStatus;
} KSWORD_ARK_ANTIBSOD_STATE;

// Single global state. The sample is not per-device; the reference matches.
static KSWORD_ARK_ANTIBSOD_STATE g_KswordArkAntiBsod;

// Forward declarations for the two suppression hooks. Signatures match
// the sample's __fastcall four-argument prototype so the resolved slot
// can be replaced without an intermediate trampoline.
typedef __int64 (__fastcall* KSWORD_ARK_ANTIBSOD_HOOK_FN)(
    __int64 arg1,
    __int64 arg2,
    __int64 arg3,
    __int64 arg4
    );

static __int64 __fastcall
KswordARKAntiBsodSuppressAllProcessorsHook(
    __int64 arg1,
    __int64 arg2,
    __int64 arg3,
    __int64 arg4
    );

static __int64 __fastcall
KswordARKAntiBsodSuppressCurrentProcessorHook(
    __int64 arg1,
    __int64 arg2,
    __int64 arg3,
    __int64 arg4
    );

// ============================================================================
// Section 4: scanning helpers (four pure functions from the report)
// ============================================================================

// FindWildcardBytePattern: linear scan across [RangeStart, RangeEnd) for a
// pattern whose 0x00 bytes are wildcards. Returns 0 when the pattern is
// empty, the length is zero, or the pattern is not found.
static ULONG_PTR
KswordARKAntiBsodFindWildcardBytePattern(
    _In_ ULONG_PTR RangeStart,
    _In_reads_bytes_opt_(PatternLength) const UCHAR* Pattern,
    _In_ ULONG_PTR RangeEnd,
    _In_ SIZE_T PatternLength
    )
{
    SIZE_T candidateOffset;
    SIZE_T patternIndex;
    SIZE_T spanBytes;
    UCHAR expected;
    UCHAR actual;

    // Guard against the two edge cases the sample also rejects up front.
    if (Pattern == NULL || PatternLength == 0) {
        return 0;
    }
    // Guard against RangeEnd < RangeStart to avoid an underflow when the
    // caller passed a bogus interval; the sample did not do this.
    if (RangeEnd < RangeStart) {
        return 0;
    }
    // Compute how many candidate positions exist. If the pattern is longer
    // than the range there is nothing to scan.
    spanBytes = (SIZE_T)(RangeEnd - RangeStart);
    if (spanBytes < PatternLength) {
        return 0;
    }
    // The sample iterates from 0 to spanBytes - PatternLength inclusive.
    for (candidateOffset = 0;
         candidateOffset <= spanBytes - PatternLength;
         ++candidateOffset) {
        // Test each byte, treating 0x00 in the pattern as a wildcard.
        for (patternIndex = 0; patternIndex < PatternLength; ++patternIndex) {
            expected = Pattern[patternIndex];
            actual = *(const UCHAR*)(RangeStart + patternIndex + candidateOffset);
            if (expected != 0 && actual != expected) {
                break;
            }
        }
        if (patternIndex == PatternLength) {
            return RangeStart + candidateOffset;
        }
    }
    return 0;
}

// ResolveRipRelativeTarget: given an instruction address and the byte
// offsets that identify the rel32 displacement field, resolve the absolute
// target of a x64 RIP-relative reference.
static ULONG_PTR
KswordARKAntiBsodResolveRipRelativeTarget(
    _In_ ULONG_PTR Instruction,
    _In_ ULONG DisplacementOffset,
    _In_ ULONG TrailingAdjustment
    )
{
    LONG displacement;

    // Sample returns 0 for a null instruction pointer, so do the same.
    if (Instruction == 0) {
        return 0;
    }
    // Signed 32-bit displacement stored at Instruction + DisplacementOffset.
    displacement = *(const LONG*)(Instruction + DisplacementOffset);
    // Absolute target = start of displacement + 4 (rel32 width) + trailing.
    return Instruction + DisplacementOffset + 4UL +
        TrailingAdjustment + (ULONG_PTR)(LONG_PTR)displacement;
}

// ReadUint32AtOffset: read a ULONG at Base + Offset when Base is nonzero.
// Used to extract KPCR/PRCB byte offsets encoded as immediates in a mov.
static ULONG
KswordARKAntiBsodReadUint32AtOffset(
    _In_ ULONG_PTR Base,
    _In_ ULONG Offset
    )
{
    if (Base == 0) {
        return 0;
    }
    return *(const ULONG*)(Base + Offset);
}

// AddOffsetIfNonNull: add Offset to Base when Base is nonzero.
static ULONG_PTR
KswordARKAntiBsodAddOffsetIfNonNull(
    _In_ ULONG_PTR Base,
    _In_ ULONG Offset
    )
{
    if (Base == 0) {
        return 0;
    }
    return Base + Offset;
}

// ============================================================================
// Section 5: Windows build profile selection
// ============================================================================

// SelectWindowsBuildProfile: read the current build number and pick the
// matching entry in g_KswordArkAntiBsodProfiles. Returns TRUE when a
// profile is selected. Unlike the sample, this refuses to continue when
// the build number is above every declared range.
static BOOLEAN
KswordARKAntiBsodSelectWindowsBuildProfile(VOID)
{
    RTL_OSVERSIONINFOW version;
    NTSTATUS status;
    ULONG i;

    // Zero the version struct so RtlGetVersion sees a fresh input.
    RtlZeroMemory(&version, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    status = RtlGetVersion(&version);
    if (!NT_SUCCESS(status)) {
        // Sample ignored this; the reference records and bails.
        g_KswordArkAntiBsod.LastStatus = status;
        return FALSE;
    }
    g_KswordArkAntiBsod.WindowsBuildNumber = version.dwBuildNumber;
    // Walk the metadata table looking for a match. Ranges are inclusive.
    for (i = 0; i < KSWORD_ARK_ANTIBSOD_PROFILE_COUNT; ++i) {
        if (version.dwBuildNumber >=
                g_KswordArkAntiBsodProfileMeta[i].MinBuild &&
            version.dwBuildNumber <=
                g_KswordArkAntiBsodProfileMeta[i].MaxBuild) {
            g_KswordArkAntiBsod.SelectedProfileIndex = i;
            g_KswordArkAntiBsod.KthreadRoutineOffset =
                g_KswordArkAntiBsodProfileMeta[i].KthreadRoutineOffset;
            g_KswordArkAntiBsod.LegacyBuildMode =
                g_KswordArkAntiBsodProfileMeta[i].LegacyBuildMode;
            g_KswordArkAntiBsod.Profile =
                &g_KswordArkAntiBsodProfiles[i];
            return TRUE;
        }
    }
    // No match: the sample fell through with a NULL profile; the reference
    // stops here so downstream resolvers do not dereference a null pointer.
    g_KswordArkAntiBsod.LastStatus = STATUS_NOT_SUPPORTED;
    return FALSE;
}

// ============================================================================
// Section 6: ntoskrnl .text range resolution
// ============================================================================

// FindLoadedModuleTextRange: resolve ntoskrnl.exe's .text bounds through
// ZwQuerySystemInformation. Returns TRUE only when the section is located
// and both endpoints are populated in the state struct.
static BOOLEAN
KswordARKAntiBsodFindNtoskrnlTextRange(VOID)
{
    // The routine name string is fixed at kernel-mode load time and does
    // not change across boots. Declared as a const-initialized buffer so
    // no runtime allocation is required.
    static const CHAR NtoskrnlName[] = "ntoskrnl.exe";
    static const CHAR TextSectionName[] = ".text";
    ULONG requiredBytes = 0UL;
    NTSTATUS status;
    PVOID moduleBuffer = NULL;
    KSWORD_ARK_ANTIBSOD_MODULE_LIST* list = NULL;
    KSWORD_ARK_ANTIBSOD_SYSTEM_MODULE* entry = NULL;
    ULONG moduleIndex;
    const CHAR* baseName;
    PVOID imageBase;
    ULONG_PTR ntHeaders;
    ULONG_PTR sectionTable;
    ULONG sectionIndex;
    ULONG sectionCount;
    BOOLEAN success = FALSE;

    // First call: size query. Windows returns STATUS_INFO_LENGTH_MISMATCH
    // and the required buffer size through the last parameter.
    status = ZwQuerySystemInformation(
        KSWORD_ARK_ANTIBSOD_SYSTEM_MODULE_INFORMATION_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    if (requiredBytes == 0UL) {
        // Sample skipped this check; the reference bails out cleanly.
        g_KswordArkAntiBsod.LastStatus = status;
        return FALSE;
    }
    // Allocate a non-paged buffer big enough for the full list. Reserve a
    // little slack in case the module count grows between calls.
    moduleBuffer = KswordARKAntiBsodAllocateNonPaged(
        (SIZE_T)requiredBytes + 4096U);
    if (moduleBuffer == NULL) {
        g_KswordArkAntiBsod.LastStatus = STATUS_INSUFFICIENT_RESOURCES;
        return FALSE;
    }
    // Second call: actually populate the buffer.
    status = ZwQuerySystemInformation(
        KSWORD_ARK_ANTIBSOD_SYSTEM_MODULE_INFORMATION_CLASS,
        moduleBuffer,
        requiredBytes + 4096UL,
        &requiredBytes);
    if (!NT_SUCCESS(status)) {
        g_KswordArkAntiBsod.LastStatus = status;
        ExFreePoolWithTag(moduleBuffer, KSWORD_ARK_ANTIBSOD_POOL_TAG);
        return FALSE;
    }
    list = (KSWORD_ARK_ANTIBSOD_MODULE_LIST*)moduleBuffer;
    // Walk entries looking for a matching basename. The kernel writes the
    // basename inside FullPathName at OffsetToFileName.
    for (moduleIndex = 0; moduleIndex < list->NumberOfModules; ++moduleIndex) {
        entry = &list->Modules[moduleIndex];
        // Guard OffsetToFileName so a malformed entry cannot walk past the
        // module's own buffer.
        if (entry->OffsetToFileName >= sizeof(entry->FullPathName)) {
            continue;
        }
        baseName = (const CHAR*)&entry->FullPathName[entry->OffsetToFileName];
        // Case-insensitive compare; ntoskrnl.exe on disk is lowercase but
        // the kernel path can vary in case across builds.
        if (_stricmp(baseName, NtoskrnlName) != 0) {
            continue;
        }
        imageBase = entry->ImageBase;
        if (imageBase == NULL) {
            break;
        }
        // Validate the DOS header magic before touching e_lfanew.
        if (*(const USHORT*)imageBase != IMAGE_DOS_SIGNATURE) {
            break;
        }
        ntHeaders = (ULONG_PTR)imageBase +
            ((const IMAGE_DOS_HEADER*)imageBase)->e_lfanew;
        // Validate the PE signature before touching FileHeader.
        if (*(const ULONG*)ntHeaders != IMAGE_NT_SIGNATURE) {
            break;
        }
        sectionCount =
            ((const IMAGE_NT_HEADERS64*)ntHeaders)->FileHeader.NumberOfSections;
        sectionTable = ntHeaders +
            FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
            ((const IMAGE_NT_HEADERS64*)ntHeaders)->
                FileHeader.SizeOfOptionalHeader;
        for (sectionIndex = 0; sectionIndex < sectionCount; ++sectionIndex) {
            const IMAGE_SECTION_HEADER* section =
                (const IMAGE_SECTION_HEADER*)
                    (sectionTable + sectionIndex * sizeof(IMAGE_SECTION_HEADER));
            // Sample compared the first five bytes of the section name;
            // do the same so we accept ".text" and reject anything else.
            if (RtlCompareMemory(
                    section->Name,
                    TextSectionName,
                    sizeof(TextSectionName) - 1U) == sizeof(TextSectionName) - 1U) {
                g_KswordArkAntiBsod.NtTextStart =
                    (ULONG_PTR)imageBase + section->VirtualAddress;
                g_KswordArkAntiBsod.NtTextEnd =
                    g_KswordArkAntiBsod.NtTextStart + section->Misc.VirtualSize;
                success = TRUE;
                break;
            }
        }
        break;
    }
    ExFreePoolWithTag(moduleBuffer, KSWORD_ARK_ANTIBSOD_POOL_TAG);
    if (!success) {
        g_KswordArkAntiBsod.LastStatus = STATUS_NOT_FOUND;
    }
    return success;
}

// ============================================================================
// Section 7: per-CPU state capture (IPI callback)
// ============================================================================

// Broadcast callback invoked on every active processor. Reads the KPCR
// derived state pointers the sample stores in two parallel arrays.
static ULONG_PTR
KswordARKAntiBsodCapturePerCpuBugcheckState(
    _In_ ULONG_PTR IgnoredArgument
    )
{
    ULONG cpuIndex;
    ULONG_PTR kpcr;

    UNREFERENCED_PARAMETER(IgnoredArgument);
    // Determine the executing CPU index. KeGetCurrentProcessorNumberEx
    // is documented callable at any IRQL, including HIGH_LEVEL.
    cpuIndex = KeGetCurrentProcessorNumberEx(NULL);
    // The KPCR self-pointer is exposed through KeGetPcr on x64. Even
    // though the sample read gs:[0x18] directly, the effect is identical.
    kpcr = (ULONG_PTR)KeGetPcr();
    // Guard against a null result before writing arrays; the sample did
    // not check but the reference does so a corrupt system does not
    // amplify into a per-CPU array overrun.
    if (g_KswordArkAntiBsod.PerCpuPrcbArray != NULL) {
        // Sample stored KPCR + 0x20 (NtTib.FiberData). Match that offset.
        g_KswordArkAntiBsod.PerCpuPrcbArray[cpuIndex] =
            *(ULONG_PTR*)(kpcr + 0x20);
    }
    if (g_KswordArkAntiBsod.PerCpuSecondaryStateArray != NULL) {
        // Sample stored KPCR + KpcrSecondaryFlagOffset as an address.
        g_KswordArkAntiBsod.PerCpuSecondaryStateArray[cpuIndex] =
            kpcr + g_KswordArkAntiBsod.KpcrSecondaryFlagOffset;
    }
    return 0;
}

// ============================================================================
// Section 8: stack-origin classification
// ============================================================================

// StackClass values match the sample: 0 = no frame lies in the bug-check
// code range, 1 = a frame is present with a captured continuation slot,
// 2 = a frame is present at the terminal boundary.
#define KSWORD_ARK_ANTIBSOD_STACK_NO_TARGET_FRAME      0
#define KSWORD_ARK_ANTIBSOD_STACK_WITH_CONTINUATION    1
#define KSWORD_ARK_ANTIBSOD_STACK_TERMINAL_BOUNDARY    2

// Buffer size for CaptureStackBackTrace. Sample used 64 frames.
#define KSWORD_ARK_ANTIBSOD_STACK_FRAME_COUNT 64

static ULONG
KswordARKAntiBsodClassifyBugcheckStackOrigin(VOID)
{
    PVOID frames[KSWORD_ARK_ANTIBSOD_STACK_FRAME_COUNT];
    ULONG captured;
    ULONG frameIndex;
    ULONG_PTR frameAddress;

    // Sample zeroes the buffer before the call; do the same so an early
    // exit does not observe stack garbage.
    RtlZeroMemory(frames, sizeof(frames));
    captured = RtlCaptureStackBackTrace(
        0UL,
        KSWORD_ARK_ANTIBSOD_STACK_FRAME_COUNT,
        frames,
        NULL);
    // Iterate the captured slots. A null slot marks the end of the trace.
    for (frameIndex = 0;
         frameIndex < KSWORD_ARK_ANTIBSOD_STACK_FRAME_COUNT;
         ++frameIndex) {
        if (frameIndex >= captured || frames[frameIndex] == NULL) {
            return KSWORD_ARK_ANTIBSOD_STACK_NO_TARGET_FRAME;
        }
        frameAddress = (ULONG_PTR)frames[frameIndex];
        if (frameAddress >= g_KswordArkAntiBsod.BugcheckCodeRangeStart &&
            frameAddress <= g_KswordArkAntiBsod.BugcheckCodeRangeEnd) {
            // A frame lies inside the resolved bug-check code range.
            // The sample distinguishes terminal-boundary from continuation
            // by whether the next captured slot is nonzero.
            if (frameIndex + 1UL < captured &&
                frames[frameIndex + 1UL] != NULL) {
                return KSWORD_ARK_ANTIBSOD_STACK_WITH_CONTINUATION;
            }
            return KSWORD_ARK_ANTIBSOD_STACK_TERMINAL_BOUNDARY;
        }
    }
    return KSWORD_ARK_ANTIBSOD_STACK_NO_TARGET_FRAME;
}

// ============================================================================
// Section 9: the two suppression hooks
// ============================================================================

// Waits forever on a NotificationEvent that is created but never signaled.
// The analysis report notes this is the point where the sample's design
// requires the crashing CPU to never return.
static VOID
KswordARKAntiBsodWaitForever(VOID)
{
    // Bounded loop is intentional: the sample loops so a spurious wake
    // (never expected in practice) does not fall through to the caller.
    while (TRUE) {
        (VOID)KeWaitForSingleObject(
            &g_KswordArkAntiBsod.NeverSignaledEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    }
}

// Invoke the KTHREAD private routine slot the sample transfers to at the
// terminal-boundary stack classification. We do not return from this.
static DECLSPEC_NORETURN VOID
KswordARKAntiBsodInvokeKthreadRoutine(VOID)
{
    PVOID kthread;
    PVOID routineSlot;
    typedef VOID (NTAPI* KSWORD_ARK_ANTIBSOD_THREAD_ROUTINE)(VOID);
    KSWORD_ARK_ANTIBSOD_THREAD_ROUTINE routine;

    // Match the sample: call IoGetInitialStack before transferring so any
    // subsequent unwinder that inspects the initial-stack field sees a
    // consistent value. Return value is discarded on purpose.
    (VOID)IoGetInitialStack();
    kthread = (PVOID)KeGetCurrentThread();
    routineSlot = (PVOID)((ULONG_PTR)kthread +
        g_KswordArkAntiBsod.KthreadRoutineOffset);
    routine = *(KSWORD_ARK_ANTIBSOD_THREAD_ROUTINE*)routineSlot;
    if (routine != NULL) {
        routine();
    }
    // Fall through into the never-signaled wait so we never return.
    KswordARKAntiBsodWaitForever();
}

// The "all processors" hook. Sample: mutate global state, walk every
// active CPU writing per-CPU state, drop CR8, optionally invoke KTHREAD
// routine, then wait forever.
static __int64 __fastcall
KswordARKAntiBsodSuppressAllProcessorsHook(
    __int64 arg1,
    __int64 arg2,
    __int64 arg3,
    __int64 arg4
    )
{
    ULONG stackClass;
    ULONG currentCpu;
    ULONG cpu;
    KSWORD_ARK_ANTIBSOD_HOOK_FN original;

    // Track re-entrancy so Uninstall can drain safely.
    InterlockedIncrement(&g_KswordArkAntiBsod.HookExecutions);
    InterlockedIncrement(&g_KswordArkAntiBsod.HookInvocationCount);
    // Classify the caller stack. Zero means "not from the tracked bug
    // check code range" and we transparently forward to the original.
    stackClass = KswordARKAntiBsodClassifyBugcheckStackOrigin();
    if (stackClass == KSWORD_ARK_ANTIBSOD_STACK_NO_TARGET_FRAME) {
        original = (KSWORD_ARK_ANTIBSOD_HOOK_FN)
            g_KswordArkAntiBsod.OriginalAllProcessorsRoutine;
        InterlockedDecrement(&g_KswordArkAntiBsod.HookExecutions);
        if (original == NULL) {
            // The reference refuses to forward through a null pointer.
            // The sample would have crashed; we return zero instead.
            return 0;
        }
        return original(arg1, arg2, arg3, arg4);
    }
    // Suppression path. Match the sample writes step by step.
    // 1. Clear the private state flag DWORD.
    if (g_KswordArkAntiBsod.BugcheckStateFlagPtr != 0) {
        *(volatile ULONG*)g_KswordArkAntiBsod.BugcheckStateFlagPtr = 0UL;
    }
    // 2. Set the bug-check-in-progress byte to 1.
    if (g_KswordArkAntiBsod.BugcheckInProgressFlagPtr != 0) {
        *(volatile UCHAR*)g_KswordArkAntiBsod.BugcheckInProgressFlagPtr = 1;
    }
    currentCpu = KeGetCurrentProcessorNumberEx(NULL);
    // 3. Walk every CPU. Current CPU and remote CPUs get different values.
    for (cpu = 0; cpu < g_KswordArkAntiBsod.ActiveProcessorCount; ++cpu) {
        ULONG_PTR prcbState = g_KswordArkAntiBsod.PerCpuPrcbArray[cpu];
        ULONG_PTR secondary =
            g_KswordArkAntiBsod.PerCpuSecondaryStateArray[cpu];
        if (cpu == currentCpu) {
            if (g_KswordArkAntiBsod.KpcrSecondaryFlagOffset != 0UL &&
                secondary != 0) {
                *(volatile UCHAR*)(*(ULONG_PTR*)secondary) = 0;
            }
            if (prcbState != 0) {
                *(volatile ULONG*)
                    (prcbState + g_KswordArkAntiBsod.KpcrBugcheckStateOffset) = 0UL;
            }
        }
        else {
            if (g_KswordArkAntiBsod.KpcrSecondaryFlagOffset != 0UL &&
                secondary != 0) {
                *(volatile UCHAR*)(*(ULONG_PTR*)secondary) = 1;
            }
            if (prcbState != 0) {
                *(volatile ULONG*)
                    (prcbState + g_KswordArkAntiBsod.KpcrBugcheckStateOffset) = 5UL;
            }
        }
    }
    // 4. Legacy build branch: stall then rewrite remote CPU states again.
    if (g_KswordArkAntiBsod.LegacyBuildMode) {
        KeStallExecutionProcessor(100000UL);
        for (cpu = 0; cpu < g_KswordArkAntiBsod.ActiveProcessorCount; ++cpu) {
            ULONG_PTR prcbState = g_KswordArkAntiBsod.PerCpuPrcbArray[cpu];
            if (cpu != currentCpu && prcbState != 0) {
                *(volatile ULONG*)
                    (prcbState + g_KswordArkAntiBsod.KpcrBugcheckStateOffset) = 34UL;
            }
        }
    }
    // 5. Drop CR8 so subsequent interrupts are eligible on the local CPU.
    __writecr8(0);
    // 6. Terminal boundary transfers to the KTHREAD private routine slot.
    if (stackClass == KSWORD_ARK_ANTIBSOD_STACK_TERMINAL_BOUNDARY) {
        InterlockedDecrement(&g_KswordArkAntiBsod.HookExecutions);
        KswordARKAntiBsodInvokeKthreadRoutine();
        // Not reached: KswordARKAntiBsodInvokeKthreadRoutine is __noreturn.
    }
    // 7. Otherwise wait forever on the never-signaled event.
    InterlockedDecrement(&g_KswordArkAntiBsod.HookExecutions);
    KswordARKAntiBsodWaitForever();
    return 0;
}

// The "current processor" hook. Same idea but only touches this CPU.
static __int64 __fastcall
KswordARKAntiBsodSuppressCurrentProcessorHook(
    __int64 arg1,
    __int64 arg2,
    __int64 arg3,
    __int64 arg4
    )
{
    ULONG stackClass;
    ULONG currentCpu;
    ULONG_PTR prcbState;
    ULONG_PTR secondary;
    KSWORD_ARK_ANTIBSOD_HOOK_FN original;

    InterlockedIncrement(&g_KswordArkAntiBsod.HookExecutions);
    InterlockedIncrement(&g_KswordArkAntiBsod.HookInvocationCount);
    stackClass = KswordARKAntiBsodClassifyBugcheckStackOrigin();
    if (stackClass == KSWORD_ARK_ANTIBSOD_STACK_NO_TARGET_FRAME) {
        original = (KSWORD_ARK_ANTIBSOD_HOOK_FN)
            g_KswordArkAntiBsod.OriginalCurrentProcessorRoutine;
        InterlockedDecrement(&g_KswordArkAntiBsod.HookExecutions);
        if (original == NULL) {
            return 0;
        }
        return original(arg1, arg2, arg3, arg4);
    }
    currentCpu = KeGetCurrentProcessorNumberEx(NULL);
    if (g_KswordArkAntiBsod.BugcheckStateFlagPtr != 0) {
        *(volatile ULONG*)g_KswordArkAntiBsod.BugcheckStateFlagPtr = 0UL;
    }
    if (g_KswordArkAntiBsod.BugcheckInProgressFlagPtr != 0) {
        *(volatile UCHAR*)g_KswordArkAntiBsod.BugcheckInProgressFlagPtr = 1;
    }
    prcbState = g_KswordArkAntiBsod.PerCpuPrcbArray[currentCpu];
    secondary = g_KswordArkAntiBsod.PerCpuSecondaryStateArray[currentCpu];
    if (g_KswordArkAntiBsod.KpcrSecondaryFlagOffset != 0UL &&
        secondary != 0) {
        *(volatile UCHAR*)(*(ULONG_PTR*)secondary) = 0;
    }
    if (prcbState != 0) {
        *(volatile ULONG*)
            (prcbState + g_KswordArkAntiBsod.KpcrBugcheckStateOffset) = 0UL;
    }
    __writecr8(0);
    if (stackClass == KSWORD_ARK_ANTIBSOD_STACK_TERMINAL_BOUNDARY) {
        InterlockedDecrement(&g_KswordArkAntiBsod.HookExecutions);
        KswordARKAntiBsodInvokeKthreadRoutine();
    }
    InterlockedDecrement(&g_KswordArkAntiBsod.HookExecutions);
    KswordARKAntiBsodWaitForever();
    return 0;
}

// ============================================================================
// Section 10: install / uninstall
// ============================================================================

// Free per-CPU arrays and reset counts. Safe to call multiple times.
static VOID
KswordARKAntiBsodReleasePerCpuArraysLocked(VOID)
{
    if (g_KswordArkAntiBsod.PerCpuPrcbArray != NULL) {
        ExFreePoolWithTag(
            g_KswordArkAntiBsod.PerCpuPrcbArray,
            KSWORD_ARK_ANTIBSOD_POOL_TAG);
        g_KswordArkAntiBsod.PerCpuPrcbArray = NULL;
    }
    if (g_KswordArkAntiBsod.PerCpuSecondaryStateArray != NULL) {
        ExFreePoolWithTag(
            g_KswordArkAntiBsod.PerCpuSecondaryStateArray,
            KSWORD_ARK_ANTIBSOD_POOL_TAG);
        g_KswordArkAntiBsod.PerCpuSecondaryStateArray = NULL;
    }
    g_KswordArkAntiBsod.ActiveProcessorCount = 0UL;
}

// Reset every resolved kernel address in the state struct so a failed
// or torn-down install cannot leak stale pointers to future queries.
static VOID
KswordARKAntiBsodResetResolvedTargetsLocked(VOID)
{
    g_KswordArkAntiBsod.NtTextStart = 0;
    g_KswordArkAntiBsod.NtTextEnd = 0;
    g_KswordArkAntiBsod.KeBugCheckExAddress = 0;
    g_KswordArkAntiBsod.BugcheckScanBoundary = 0;
    g_KswordArkAntiBsod.BugcheckCodeRangeStart = 0;
    g_KswordArkAntiBsod.BugcheckCodeRangeEnd = 0;
    g_KswordArkAntiBsod.BugcheckStateFlagPtr = 0;
    g_KswordArkAntiBsod.KpcrBugcheckStateOffset = 0UL;
    g_KswordArkAntiBsod.KpcrSecondaryFlagOffset = 0UL;
    g_KswordArkAntiBsod.BugcheckInProgressFlagPtr = 0;
    g_KswordArkAntiBsod.AllProcessorsHookSlot = 0;
    g_KswordArkAntiBsod.CurrentProcessorHookSlot = 0;
    g_KswordArkAntiBsod.OriginalAllProcessorsRoutine = NULL;
    g_KswordArkAntiBsod.OriginalCurrentProcessorRoutine = NULL;
    InterlockedExchange(&g_KswordArkAntiBsod.HookInvocationCount, 0L);
    InterlockedExchange(&g_KswordArkAntiBsod.SlotExpectedMask, 0L);
    InterlockedExchange(&g_KswordArkAntiBsod.SlotHitMask, 0L);
    InterlockedExchange(
        &g_KswordArkAntiBsod.SupportSummary,
        (LONG)KSWORD_ARK_ANTIBSOD_SUPPORT_UNKNOWN);
}

// Compute the two transparency masks from the currently selected profile
// and the resolved targets. Callers invoke this after the scan pipeline
// completes so R3 can render per-rule hit/miss.
static VOID
KswordARKAntiBsodComputeMasksLocked(VOID)
{
    ULONG expected = 0UL;
    ULONG hit = 0UL;
    const KSWORD_ARK_ANTIBSOD_PROFILE* profile = g_KswordArkAntiBsod.Profile;

    // Expected mask: which slots have a nonzero pattern length. This is
    // the operator-supplied part of the state, independent of the target
    // kernel image.
    if (profile != NULL) {
        if (profile->Slot0BugcheckAnchor.Length != 0UL) {
            expected |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_BUGCHECK_ANCHOR;
        }
        if (profile->Slot1BugcheckCodeStart.Length != 0UL) {
            expected |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_BUGCHECK_CODE_START;
        }
        if (profile->Slot2BugcheckCodeEnd.Length != 0UL) {
            expected |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_BUGCHECK_CODE_END;
        }
        if (profile->Slot3StateFlagPtr.Length != 0UL) {
            expected |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_STATE_FLAG_PTR;
        }
        if (profile->Slot4KpcrStateOffset.Length != 0UL) {
            expected |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_KPCR_STATE_OFFSET;
        }
        if (profile->Slot5KpcrSecondaryOffset.Length != 0UL) {
            expected |=
                1UL << KSWORD_ARK_ANTIBSOD_SLOT_KPCR_SECONDARY_OFFSET;
        }
        if (profile->Slot6InProgressFlagPtr.Length != 0UL) {
            expected |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_INPROGRESS_FLAG_PTR;
        }
        if (profile->Slot7AllProcessorsHookSlot.Length != 0UL) {
            expected |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_ALL_HOOK_SLOT;
        }
        if (profile->Slot8CurrentProcessorHookSlot.Length != 0UL) {
            expected |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_CURRENT_HOOK_SLOT;
        }
    }
    // Hit mask: which slots resolved to nonzero after the scan. Slot 4/5
    // are ULONG offsets, everything else is ULONG_PTR.
    if (g_KswordArkAntiBsod.BugcheckScanBoundary != 0) {
        hit |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_BUGCHECK_ANCHOR;
    }
    if (g_KswordArkAntiBsod.BugcheckCodeRangeStart != 0) {
        hit |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_BUGCHECK_CODE_START;
    }
    if (g_KswordArkAntiBsod.BugcheckCodeRangeEnd != 0) {
        hit |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_BUGCHECK_CODE_END;
    }
    if (g_KswordArkAntiBsod.BugcheckStateFlagPtr != 0) {
        hit |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_STATE_FLAG_PTR;
    }
    if (g_KswordArkAntiBsod.KpcrBugcheckStateOffset != 0UL) {
        hit |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_KPCR_STATE_OFFSET;
    }
    // KpcrSecondaryFlagOffset is legitimately zero on some builds; when
    // that is the case, treat the slot as "hit" so a build where the
    // sample intentionally omits this field is not misclassified.
    if (g_KswordArkAntiBsod.KpcrSecondaryFlagOffset != 0UL ||
        (g_KswordArkAntiBsod.Profile != NULL &&
         g_KswordArkAntiBsod.Profile->Slot5KpcrSecondaryOffset.Length ==
             0UL)) {
        hit |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_KPCR_SECONDARY_OFFSET;
    }
    if (g_KswordArkAntiBsod.BugcheckInProgressFlagPtr != 0) {
        hit |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_INPROGRESS_FLAG_PTR;
    }
    if (g_KswordArkAntiBsod.AllProcessorsHookSlot != 0) {
        hit |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_ALL_HOOK_SLOT;
    }
    if (g_KswordArkAntiBsod.CurrentProcessorHookSlot != 0) {
        hit |= 1UL << KSWORD_ARK_ANTIBSOD_SLOT_CURRENT_HOOK_SLOT;
    }
    InterlockedExchange(
        &g_KswordArkAntiBsod.SlotExpectedMask,
        (LONG)expected);
    InterlockedExchange(&g_KswordArkAntiBsod.SlotHitMask, (LONG)hit);
}

// Classify the outcome after a probe or install attempt. Ties expected
// vs hit mask + profile selection into a single enum for R3.
static VOID
KswordARKAntiBsodComputeSupportSummaryLocked(VOID)
{
    ULONG expected;
    ULONG hit;
    ULONG summary;

    if (g_KswordArkAntiBsod.Profile == NULL) {
        summary = KSWORD_ARK_ANTIBSOD_SUPPORT_UNSUPPORTED_BUILD;
    }
    else {
        expected = (ULONG)InterlockedCompareExchange(
            &g_KswordArkAntiBsod.SlotExpectedMask, 0L, 0L);
        hit = (ULONG)InterlockedCompareExchange(
            &g_KswordArkAntiBsod.SlotHitMask, 0L, 0L);
        if (expected == 0UL) {
            // Zero signatures loaded: this is the shipping default and
            // the strongest fail-closed guarantee.
            summary = KSWORD_ARK_ANTIBSOD_SUPPORT_SIGNATURES_EMPTY;
        }
        else if ((hit & expected) == expected) {
            summary = KSWORD_ARK_ANTIBSOD_SUPPORT_FULL_MATCH;
        }
        else {
            summary = KSWORD_ARK_ANTIBSOD_SUPPORT_PARTIAL_MATCH;
        }
    }
    InterlockedExchange(
        &g_KswordArkAntiBsod.SupportSummary,
        (LONG)summary);
}

// The whole install pipeline in one place. Fail-closed at every step.
static NTSTATUS
KswordARKAntiBsodInstallLocked(VOID)
{
    UNICODE_STRING routineName;
    const KSWORD_ARK_ANTIBSOD_PROFILE* profile;
    ULONG_PTR match;
    NTSTATUS status;
    ULONG activeCpus;

    // Reject re-install; caller must Uninstall first.
    if (InterlockedCompareExchange(
            &g_KswordArkAntiBsod.Installed, 0L, 0L) != 0L) {
        return STATUS_ALREADY_REGISTERED;
    }
    // Clean slate for resolved addresses and per-CPU arrays.
    KswordARKAntiBsodResetResolvedTargetsLocked();
    KswordARKAntiBsodReleasePerCpuArraysLocked();

    // Step 1: pick the build profile.
    if (!KswordARKAntiBsodSelectWindowsBuildProfile()) {
        return STATUS_NOT_SUPPORTED;
    }
    profile = g_KswordArkAntiBsod.Profile;
    if (profile == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    // Step 2: locate ntoskrnl .text.
    if (!KswordARKAntiBsodFindNtoskrnlTextRange()) {
        return STATUS_NOT_FOUND;
    }
    // Step 3: resolve KeBugCheckEx as the primary anchor.
    RtlInitUnicodeString(&routineName, L"KeBugCheckEx");
    g_KswordArkAntiBsod.KeBugCheckExAddress =
        (ULONG_PTR)MmGetSystemRoutineAddress(&routineName);
    if (g_KswordArkAntiBsod.KeBugCheckExAddress == 0) {
        return STATUS_NOT_FOUND;
    }
    // Step 4: scan the private targets in order, each stage feeding the
    // next range. This is the multi-level chained scan the sample uses.
    // Slot 0: anchor.
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.KeBugCheckExAddress,
        profile->Slot0BugcheckAnchor.Pattern,
        g_KswordArkAntiBsod.NtTextEnd,
        profile->Slot0BugcheckAnchor.Length);
    g_KswordArkAntiBsod.BugcheckScanBoundary =
        KswordARKAntiBsodAddOffsetIfNonNull(
            match,
            profile->Slot0BugcheckAnchor.AddOffset);
    // Slot 1: bug-check code range start.
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.KeBugCheckExAddress,
        profile->Slot1BugcheckCodeStart.Pattern,
        g_KswordArkAntiBsod.BugcheckScanBoundary,
        profile->Slot1BugcheckCodeStart.Length);
    g_KswordArkAntiBsod.BugcheckCodeRangeStart =
        KswordARKAntiBsodResolveRipRelativeTarget(
            match,
            profile->Slot1BugcheckCodeStart.DispOffset,
            profile->Slot1BugcheckCodeStart.TrailingAdjust);
    // Slot 2: bug-check code range end.
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.BugcheckCodeRangeStart,
        profile->Slot2BugcheckCodeEnd.Pattern,
        g_KswordArkAntiBsod.NtTextEnd,
        profile->Slot2BugcheckCodeEnd.Length);
    g_KswordArkAntiBsod.BugcheckCodeRangeEnd =
        KswordARKAntiBsodAddOffsetIfNonNull(
            match,
            profile->Slot2BugcheckCodeEnd.AddOffset);
    // Slot 3: private state flag pointer.
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.BugcheckCodeRangeStart,
        profile->Slot3StateFlagPtr.Pattern,
        g_KswordArkAntiBsod.BugcheckCodeRangeEnd,
        profile->Slot3StateFlagPtr.Length);
    g_KswordArkAntiBsod.BugcheckStateFlagPtr =
        KswordARKAntiBsodResolveRipRelativeTarget(
            match,
            profile->Slot3StateFlagPtr.DispOffset,
            profile->Slot3StateFlagPtr.TrailingAdjust);
    // Slot 4: PRCB state offset.
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.NtTextStart,
        profile->Slot4KpcrStateOffset.Pattern,
        g_KswordArkAntiBsod.NtTextEnd,
        profile->Slot4KpcrStateOffset.Length);
    g_KswordArkAntiBsod.KpcrBugcheckStateOffset =
        KswordARKAntiBsodReadUint32AtOffset(
            match,
            profile->Slot4KpcrStateOffset.ReadOffset);
    // Slot 5: KPCR secondary flag offset.
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.NtTextStart,
        profile->Slot5KpcrSecondaryOffset.Pattern,
        g_KswordArkAntiBsod.NtTextEnd,
        profile->Slot5KpcrSecondaryOffset.Length);
    g_KswordArkAntiBsod.KpcrSecondaryFlagOffset =
        KswordARKAntiBsodReadUint32AtOffset(
            match,
            profile->Slot5KpcrSecondaryOffset.ReadOffset);
    // Slot 6: bug-check-in-progress byte.
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.NtTextStart,
        profile->Slot6InProgressFlagPtr.Pattern,
        g_KswordArkAntiBsod.NtTextEnd,
        profile->Slot6InProgressFlagPtr.Length);
    g_KswordArkAntiBsod.BugcheckInProgressFlagPtr =
        KswordARKAntiBsodResolveRipRelativeTarget(
            match,
            profile->Slot6InProgressFlagPtr.DispOffset,
            profile->Slot6InProgressFlagPtr.TrailingAdjust);
    // Slot 7: all-processors hook slot.
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.BugcheckCodeRangeStart,
        profile->Slot7AllProcessorsHookSlot.Pattern,
        g_KswordArkAntiBsod.BugcheckCodeRangeEnd,
        profile->Slot7AllProcessorsHookSlot.Length);
    g_KswordArkAntiBsod.AllProcessorsHookSlot =
        KswordARKAntiBsodResolveRipRelativeTarget(
            match,
            profile->Slot7AllProcessorsHookSlot.DispOffset,
            profile->Slot7AllProcessorsHookSlot.TrailingAdjust);
    // Slot 8: current-processor hook slot.
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.NtTextStart,
        profile->Slot8CurrentProcessorHookSlot.Pattern,
        g_KswordArkAntiBsod.NtTextEnd,
        profile->Slot8CurrentProcessorHookSlot.Length);
    g_KswordArkAntiBsod.CurrentProcessorHookSlot =
        KswordARKAntiBsodResolveRipRelativeTarget(
            match,
            profile->Slot8CurrentProcessorHookSlot.DispOffset,
            profile->Slot8CurrentProcessorHookSlot.TrailingAdjust);
    // Publish the transparency masks and the support summary now that
    // every scan has run. R3 can observe them via QUERY even when Install
    // will fail-close below.
    KswordARKAntiBsodComputeMasksLocked();
    KswordARKAntiBsodComputeSupportSummaryLocked();
    // Step 5: fail-closed validation. This block is the safety hardening
    // the analysis report identifies as missing from the sample.
    if (g_KswordArkAntiBsod.BugcheckScanBoundary == 0 ||
        g_KswordArkAntiBsod.BugcheckCodeRangeStart == 0 ||
        g_KswordArkAntiBsod.BugcheckCodeRangeEnd == 0 ||
        g_KswordArkAntiBsod.BugcheckStateFlagPtr == 0 ||
        g_KswordArkAntiBsod.KpcrBugcheckStateOffset == 0UL ||
        g_KswordArkAntiBsod.BugcheckInProgressFlagPtr == 0 ||
        g_KswordArkAntiBsod.AllProcessorsHookSlot == 0 ||
        g_KswordArkAntiBsod.CurrentProcessorHookSlot == 0) {
        // Any zero here means an empty signature or an unmatched scan.
        // Refuse to write hook slots. This is the default state when
        // shipping without operator-supplied signature bytes.
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    // Step 6: allocate per-CPU arrays and capture state through IPI.
    activeCpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (activeCpus == 0UL || activeCpus > 2048UL) {
        // Refuse absurd counts before they overflow the allocations.
        return STATUS_INVALID_DEVICE_STATE;
    }
    g_KswordArkAntiBsod.ActiveProcessorCount = activeCpus;
    g_KswordArkAntiBsod.PerCpuPrcbArray = (ULONG_PTR*)
        KswordARKAntiBsodAllocateNonPaged(
            (SIZE_T)activeCpus * sizeof(ULONG_PTR));
    g_KswordArkAntiBsod.PerCpuSecondaryStateArray = (ULONG_PTR*)
        KswordARKAntiBsodAllocateNonPaged(
            (SIZE_T)activeCpus * sizeof(ULONG_PTR));
    // KswordARKAntiBsodAllocateNonPaged does not zero on the fallback path,
    // so wipe both arrays before the IPI can partially populate them.
    if (g_KswordArkAntiBsod.PerCpuPrcbArray != NULL) {
        RtlZeroMemory(
            g_KswordArkAntiBsod.PerCpuPrcbArray,
            (SIZE_T)activeCpus * sizeof(ULONG_PTR));
    }
    if (g_KswordArkAntiBsod.PerCpuSecondaryStateArray != NULL) {
        RtlZeroMemory(
            g_KswordArkAntiBsod.PerCpuSecondaryStateArray,
            (SIZE_T)activeCpus * sizeof(ULONG_PTR));
    }
    if (g_KswordArkAntiBsod.PerCpuPrcbArray == NULL ||
        g_KswordArkAntiBsod.PerCpuSecondaryStateArray == NULL) {
        KswordARKAntiBsodReleasePerCpuArraysLocked();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    (VOID)KeIpiGenericCall(
        (PKIPI_BROADCAST_WORKER)KswordARKAntiBsodCapturePerCpuBugcheckState,
        0);
    // Step 7: initialize the never-signaled event.
    KeInitializeEvent(
        &g_KswordArkAntiBsod.NeverSignaledEvent,
        KSWORD_ARK_ANTIBSOD_EVENT_KIND,
        FALSE);
    // Step 8: save the original targets, then overwrite the hook slots.
    // The sample uses an atomic pair of pointer stores; on x64 a naturally
    // aligned pointer write is atomic already.
    g_KswordArkAntiBsod.OriginalAllProcessorsRoutine =
        *(PVOID*)g_KswordArkAntiBsod.AllProcessorsHookSlot;
    g_KswordArkAntiBsod.OriginalCurrentProcessorRoutine =
        *(PVOID*)g_KswordArkAntiBsod.CurrentProcessorHookSlot;
    __try {
        // Wrap the two writes in SEH so a slot located in a read-only or
        // stale mapping does not immediately fault the driver. This is
        // not in the sample; the reference adds it as defense in depth.
        *(PVOID*)g_KswordArkAntiBsod.AllProcessorsHookSlot =
            (PVOID)(ULONG_PTR)KswordARKAntiBsodSuppressAllProcessorsHook;
        *(PVOID*)g_KswordArkAntiBsod.CurrentProcessorHookSlot =
            (PVOID)(ULONG_PTR)KswordARKAntiBsodSuppressCurrentProcessorHook;
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        // Roll back: the slot writes may have partially succeeded above.
        __try {
            if (g_KswordArkAntiBsod.OriginalAllProcessorsRoutine != NULL) {
                *(PVOID*)g_KswordArkAntiBsod.AllProcessorsHookSlot =
                    g_KswordArkAntiBsod.OriginalAllProcessorsRoutine;
            }
            if (g_KswordArkAntiBsod.OriginalCurrentProcessorRoutine != NULL) {
                *(PVOID*)g_KswordArkAntiBsod.CurrentProcessorHookSlot =
                    g_KswordArkAntiBsod.OriginalCurrentProcessorRoutine;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Best effort. Nothing else useful we can do here.
        }
        KswordARKAntiBsodReleasePerCpuArraysLocked();
        return status;
    }
    // All state is live now. Publish flags last.
    InterlockedExchange(&g_KswordArkAntiBsod.HooksActive, 1L);
    InterlockedExchange(&g_KswordArkAntiBsod.Installed, 1L);
    // Re-publish the summary now that hooks are actually live; this only
    // changes the reported hookInvocationCount when a real firing occurs
    // later, but the summary value stays FULL_MATCH for the R3 QUERY view.
    KswordARKAntiBsodComputeSupportSummaryLocked();
    return STATUS_SUCCESS;
}

// Run the entire scan pipeline read-only. No hook writes, no per-CPU
// allocation, no IPI. The response afterwards carries per-slot expected
// and hit masks plus the support summary so R3 can render "current rules
// hit / current system supported" without any side effect.
static NTSTATUS
KswordARKAntiBsodProbeLocked(VOID)
{
    UNICODE_STRING routineName;
    const KSWORD_ARK_ANTIBSOD_PROFILE* profile;
    ULONG_PTR match;

    // Probe requires no confirmation because it neither installs nor
    // dereferences any private slot. Do refuse while an install is live
    // so the observable state is not overwritten under a live hook.
    if (InterlockedCompareExchange(
            &g_KswordArkAntiBsod.Installed, 0L, 0L) != 0L) {
        return STATUS_ALREADY_REGISTERED;
    }
    // Start from a clean slate so a previous probe cannot pollute masks.
    KswordARKAntiBsodResetResolvedTargetsLocked();

    // Step 1: pick a profile.
    if (!KswordARKAntiBsodSelectWindowsBuildProfile()) {
        // No profile: report support summary immediately and leave the
        // rest of the state zero.
        KswordARKAntiBsodComputeMasksLocked();
        KswordARKAntiBsodComputeSupportSummaryLocked();
        return STATUS_NOT_SUPPORTED;
    }
    profile = g_KswordArkAntiBsod.Profile;
    // Step 2: resolve ntoskrnl.
    if (!KswordARKAntiBsodFindNtoskrnlTextRange()) {
        KswordARKAntiBsodComputeMasksLocked();
        KswordARKAntiBsodComputeSupportSummaryLocked();
        return STATUS_NOT_FOUND;
    }
    RtlInitUnicodeString(&routineName, L"KeBugCheckEx");
    g_KswordArkAntiBsod.KeBugCheckExAddress =
        (ULONG_PTR)MmGetSystemRoutineAddress(&routineName);
    if (g_KswordArkAntiBsod.KeBugCheckExAddress == 0) {
        KswordARKAntiBsodComputeMasksLocked();
        KswordARKAntiBsodComputeSupportSummaryLocked();
        return STATUS_NOT_FOUND;
    }
    // Step 3: run all 9 scans in the exact same order Install uses. The
    // wildcard scanner returns 0 when either the pattern or the length
    // is zero, so every empty slot cleanly ends up as a miss.
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.KeBugCheckExAddress,
        profile->Slot0BugcheckAnchor.Pattern,
        g_KswordArkAntiBsod.NtTextEnd,
        profile->Slot0BugcheckAnchor.Length);
    g_KswordArkAntiBsod.BugcheckScanBoundary =
        KswordARKAntiBsodAddOffsetIfNonNull(
            match, profile->Slot0BugcheckAnchor.AddOffset);
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.KeBugCheckExAddress,
        profile->Slot1BugcheckCodeStart.Pattern,
        g_KswordArkAntiBsod.BugcheckScanBoundary,
        profile->Slot1BugcheckCodeStart.Length);
    g_KswordArkAntiBsod.BugcheckCodeRangeStart =
        KswordARKAntiBsodResolveRipRelativeTarget(
            match,
            profile->Slot1BugcheckCodeStart.DispOffset,
            profile->Slot1BugcheckCodeStart.TrailingAdjust);
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.BugcheckCodeRangeStart,
        profile->Slot2BugcheckCodeEnd.Pattern,
        g_KswordArkAntiBsod.NtTextEnd,
        profile->Slot2BugcheckCodeEnd.Length);
    g_KswordArkAntiBsod.BugcheckCodeRangeEnd =
        KswordARKAntiBsodAddOffsetIfNonNull(
            match, profile->Slot2BugcheckCodeEnd.AddOffset);
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.BugcheckCodeRangeStart,
        profile->Slot3StateFlagPtr.Pattern,
        g_KswordArkAntiBsod.BugcheckCodeRangeEnd,
        profile->Slot3StateFlagPtr.Length);
    g_KswordArkAntiBsod.BugcheckStateFlagPtr =
        KswordARKAntiBsodResolveRipRelativeTarget(
            match,
            profile->Slot3StateFlagPtr.DispOffset,
            profile->Slot3StateFlagPtr.TrailingAdjust);
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.NtTextStart,
        profile->Slot4KpcrStateOffset.Pattern,
        g_KswordArkAntiBsod.NtTextEnd,
        profile->Slot4KpcrStateOffset.Length);
    g_KswordArkAntiBsod.KpcrBugcheckStateOffset =
        KswordARKAntiBsodReadUint32AtOffset(
            match, profile->Slot4KpcrStateOffset.ReadOffset);
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.NtTextStart,
        profile->Slot5KpcrSecondaryOffset.Pattern,
        g_KswordArkAntiBsod.NtTextEnd,
        profile->Slot5KpcrSecondaryOffset.Length);
    g_KswordArkAntiBsod.KpcrSecondaryFlagOffset =
        KswordARKAntiBsodReadUint32AtOffset(
            match, profile->Slot5KpcrSecondaryOffset.ReadOffset);
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.NtTextStart,
        profile->Slot6InProgressFlagPtr.Pattern,
        g_KswordArkAntiBsod.NtTextEnd,
        profile->Slot6InProgressFlagPtr.Length);
    g_KswordArkAntiBsod.BugcheckInProgressFlagPtr =
        KswordARKAntiBsodResolveRipRelativeTarget(
            match,
            profile->Slot6InProgressFlagPtr.DispOffset,
            profile->Slot6InProgressFlagPtr.TrailingAdjust);
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.BugcheckCodeRangeStart,
        profile->Slot7AllProcessorsHookSlot.Pattern,
        g_KswordArkAntiBsod.BugcheckCodeRangeEnd,
        profile->Slot7AllProcessorsHookSlot.Length);
    g_KswordArkAntiBsod.AllProcessorsHookSlot =
        KswordARKAntiBsodResolveRipRelativeTarget(
            match,
            profile->Slot7AllProcessorsHookSlot.DispOffset,
            profile->Slot7AllProcessorsHookSlot.TrailingAdjust);
    match = KswordARKAntiBsodFindWildcardBytePattern(
        g_KswordArkAntiBsod.NtTextStart,
        profile->Slot8CurrentProcessorHookSlot.Pattern,
        g_KswordArkAntiBsod.NtTextEnd,
        profile->Slot8CurrentProcessorHookSlot.Length);
    g_KswordArkAntiBsod.CurrentProcessorHookSlot =
        KswordARKAntiBsodResolveRipRelativeTarget(
            match,
            profile->Slot8CurrentProcessorHookSlot.DispOffset,
            profile->Slot8CurrentProcessorHookSlot.TrailingAdjust);
    // Publish the transparency masks and summary; Probe never writes a
    // private slot regardless of outcome.
    KswordARKAntiBsodComputeMasksLocked();
    KswordARKAntiBsodComputeSupportSummaryLocked();
    return STATUS_SUCCESS;
}

// Restore the two hook slots and free per-CPU arrays. Fails when a hook
// is still executing on another CPU: on modern Windows the hook path never
// returns, so this branch mostly serves as a diagnostic in a research VM.
static NTSTATUS
KswordARKAntiBsodUninstallLocked(VOID)
{
    // Refuse if never installed.
    if (InterlockedCompareExchange(
            &g_KswordArkAntiBsod.Installed, 0L, 0L) == 0L) {
        return STATUS_SUCCESS;
    }
    // Refuse if a hook is still in flight.
    if (InterlockedCompareExchange(
            &g_KswordArkAntiBsod.HookExecutions, 0L, 0L) != 0L) {
        return STATUS_DEVICE_BUSY;
    }
    InterlockedExchange(&g_KswordArkAntiBsod.HooksActive, 0L);
    __try {
        if (g_KswordArkAntiBsod.AllProcessorsHookSlot != 0 &&
            g_KswordArkAntiBsod.OriginalAllProcessorsRoutine != NULL) {
            *(PVOID*)g_KswordArkAntiBsod.AllProcessorsHookSlot =
                g_KswordArkAntiBsod.OriginalAllProcessorsRoutine;
        }
        if (g_KswordArkAntiBsod.CurrentProcessorHookSlot != 0 &&
            g_KswordArkAntiBsod.OriginalCurrentProcessorRoutine != NULL) {
            *(PVOID*)g_KswordArkAntiBsod.CurrentProcessorHookSlot =
                g_KswordArkAntiBsod.OriginalCurrentProcessorRoutine;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Ignore: if the slot itself is inaccessible we still want to
        // fall through and release our own allocations.
    }
    KswordARKAntiBsodReleasePerCpuArraysLocked();
    KswordARKAntiBsodResetResolvedTargetsLocked();
    InterlockedExchange(&g_KswordArkAntiBsod.Installed, 0L);
    return STATUS_SUCCESS;
}

// ============================================================================
// Section 11: response bookkeeping + IOCTL
// ============================================================================

static ULONG
KswordARKAntiBsodStateFlagsLocked(VOID)
{
    ULONG flags = 0UL;

    if (InterlockedCompareExchange(
            &g_KswordArkAntiBsod.Installed, 0L, 0L) != 0L) {
        flags |= KSWORD_ARK_ANTIBSOD_STATE_INSTALLED;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkAntiBsod.HooksActive, 0L, 0L) != 0L) {
        flags |= KSWORD_ARK_ANTIBSOD_STATE_HOOKS_ACTIVE;
    }
    if (g_KswordArkAntiBsod.LegacyBuildMode) {
        flags |= KSWORD_ARK_ANTIBSOD_STATE_LEGACY_BUILD;
    }
    if (g_KswordArkAntiBsod.Profile != NULL) {
        flags |= KSWORD_ARK_ANTIBSOD_STATE_PROFILE_SELECTED;
    }
    if (g_KswordArkAntiBsod.NtTextStart != 0 &&
        g_KswordArkAntiBsod.NtTextEnd != 0) {
        flags |= KSWORD_ARK_ANTIBSOD_STATE_MODULE_RANGE_RESOLVED;
    }
    if (g_KswordArkAntiBsod.AllProcessorsHookSlot != 0 &&
        g_KswordArkAntiBsod.CurrentProcessorHookSlot != 0) {
        flags |= KSWORD_ARK_ANTIBSOD_STATE_TARGETS_RESOLVED;
    }
    if (g_KswordArkAntiBsod.PerCpuPrcbArray != NULL &&
        g_KswordArkAntiBsod.PerCpuSecondaryStateArray != NULL) {
        flags |= KSWORD_ARK_ANTIBSOD_STATE_PER_CPU_STATE_CAPTURED;
    }
    // If Slot0's length is zero across all profiles the caller can see the
    // signature table is empty. Cheap to compute and useful for R3.
    if (g_KswordArkAntiBsod.Profile == NULL ||
        g_KswordArkAntiBsod.Profile->Slot0BugcheckAnchor.Length == 0UL) {
        flags |= KSWORD_ARK_ANTIBSOD_STATE_SIGNATURES_EMPTY;
    }
    return flags;
}

static VOID
KswordARKAntiBsodFillResponseLocked(
    _Out_ KSWORD_ARK_ANTIBSOD_RESPONSE* Response,
    _In_ ULONG ProtocolStatus
    )
{
    RtlZeroMemory(Response, sizeof(*Response));
    Response->size = sizeof(*Response);
    Response->version = KSWORD_ARK_ANTIBSOD_PROTOCOL_VERSION;
    Response->status = ProtocolStatus;
    Response->stateFlags = KswordARKAntiBsodStateFlagsLocked();
    Response->windowsBuildNumber = g_KswordArkAntiBsod.WindowsBuildNumber;
    Response->selectedProfileIndex = g_KswordArkAntiBsod.SelectedProfileIndex;
    Response->kthreadRoutineOffset = g_KswordArkAntiBsod.KthreadRoutineOffset;
    Response->activeProcessorCount = g_KswordArkAntiBsod.ActiveProcessorCount;
    Response->hookInvocationCount = (ULONG)InterlockedCompareExchange(
        &g_KswordArkAntiBsod.HookInvocationCount, 0L, 0L);
    Response->lastStatus = (LONG)g_KswordArkAntiBsod.LastStatus;
    Response->slotExpectedMask = (ULONG)InterlockedCompareExchange(
        &g_KswordArkAntiBsod.SlotExpectedMask, 0L, 0L);
    Response->slotHitMask = (ULONG)InterlockedCompareExchange(
        &g_KswordArkAntiBsod.SlotHitMask, 0L, 0L);
    Response->supportSummary = (ULONG)InterlockedCompareExchange(
        &g_KswordArkAntiBsod.SupportSummary, 0L, 0L);
}

VOID
KswordARKAntiBsodInitialize(
    VOID
    )
{
    // Zero the entire runtime; synchronization primitives live here too.
    RtlZeroMemory(&g_KswordArkAntiBsod, sizeof(g_KswordArkAntiBsod));
    ExInitializeFastMutex(&g_KswordArkAntiBsod.ControlLock);
    g_KswordArkAntiBsod.LastStatus = STATUS_SUCCESS;
    // Also zero the signature table so a reload cannot inherit stale
    // patterns from another instance loaded earlier in this boot.
    RtlZeroMemory(
        g_KswordArkAntiBsodProfiles,
        sizeof(g_KswordArkAntiBsodProfiles));
}

VOID
KswordARKAntiBsodUninitialize(
    VOID
    )
{
    NTSTATUS status;

    ExAcquireFastMutex(&g_KswordArkAntiBsod.ControlLock);
    status = KswordARKAntiBsodUninstallLocked();
    g_KswordArkAntiBsod.LastStatus = status;
    ExReleaseFastMutex(&g_KswordArkAntiBsod.ControlLock);
}

NTSTATUS
KswordARKAntiBsodIoctlConfigure(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_ANTIBSOD_REQUEST* input = NULL;
    KSWORD_ARK_ANTIBSOD_RESPONSE* output = NULL;
    NTSTATUS status;
    ULONG protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_INVALID_REQUEST;
    NTSTATUS installStatus;

    UNREFERENCED_PARAMETER(Device);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    status = WdfRequestRetrieveInputBuffer(
        Request, sizeof(*input), (PVOID*)&input, NULL);
    if (!NT_SUCCESS(status) || InputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    status = WdfRequestRetrieveOutputBuffer(
        Request, sizeof(*output), (PVOID*)&output, NULL);
    if (!NT_SUCCESS(status) || OutputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    ExAcquireFastMutex(&g_KswordArkAntiBsod.ControlLock);
    // Strict fixed-length validation of every reserved field.
    if (input->size != sizeof(*input) ||
        input->version != KSWORD_ARK_ANTIBSOD_PROTOCOL_VERSION ||
        (input->flags & ~KSWORD_ARK_ANTIBSOD_FLAG_UI_CONFIRMED) != 0UL ||
        input->reserved0 != 0UL ||
        input->reserved1 != 0UL ||
        input->reserved2 != 0UL) {
        g_KswordArkAntiBsod.LastStatus = STATUS_INVALID_PARAMETER;
        protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_INVALID_REQUEST;
    }
    else if (input->action == KSWORD_ARK_ANTIBSOD_ACTION_QUERY) {
        protocolStatus = InterlockedCompareExchange(
            &g_KswordArkAntiBsod.Installed, 0L, 0L) != 0L
            ? KSWORD_ARK_ANTIBSOD_STATUS_ACTIVE
            : KSWORD_ARK_ANTIBSOD_STATUS_INACTIVE;
    }
    else if (input->action == KSWORD_ARK_ANTIBSOD_ACTION_PROBE) {
        // PROBE runs the read-only scan pipeline and updates the masks
        // and support summary; it never writes any private slot.
        installStatus = KswordARKAntiBsodProbeLocked();
        g_KswordArkAntiBsod.LastStatus = installStatus;
        if (installStatus == STATUS_NOT_SUPPORTED) {
            protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_PROFILE_MISSING;
        }
        else if (installStatus == STATUS_NOT_FOUND) {
            protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_MODULE_NOT_FOUND;
        }
        else if (installStatus == STATUS_ALREADY_REGISTERED) {
            protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_ACTIVE;
        }
        else {
            // Probe succeeded structurally. The support summary decides
            // whether the current image is a full match, partial match,
            // or the shipping SIGNATURES_EMPTY default.
            protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_INACTIVE;
        }
    }
    else if (input->action == KSWORD_ARK_ANTIBSOD_ACTION_UNINSTALL) {
        installStatus = KswordARKAntiBsodUninstallLocked();
        g_KswordArkAntiBsod.LastStatus = installStatus;
        protocolStatus = NT_SUCCESS(installStatus)
            ? KSWORD_ARK_ANTIBSOD_STATUS_INACTIVE
            : KSWORD_ARK_ANTIBSOD_STATUS_BUSY;
    }
    else if (input->action == KSWORD_ARK_ANTIBSOD_ACTION_INSTALL) {
        if ((input->flags & KSWORD_ARK_ANTIBSOD_FLAG_UI_CONFIRMED) == 0UL ||
            input->confirmationToken !=
                KSWORD_ARK_ANTIBSOD_CONFIRMATION_TOKEN) {
            // Enable requires the explicit UI-side confirmation contract.
            g_KswordArkAntiBsod.LastStatus = STATUS_ACCESS_DENIED;
            protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_CONFIRMATION_NEEDED;
        }
        else {
            installStatus = KswordARKAntiBsodInstallLocked();
            g_KswordArkAntiBsod.LastStatus = installStatus;
            if (installStatus == STATUS_SUCCESS) {
                protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_ACTIVE;
            }
            else if (installStatus == STATUS_ALREADY_REGISTERED) {
                protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_ACTIVE;
            }
            else if (installStatus == STATUS_NOT_SUPPORTED) {
                protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_PROFILE_MISSING;
            }
            else if (installStatus == STATUS_NOT_FOUND) {
                protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_MODULE_NOT_FOUND;
            }
            else if (installStatus == STATUS_OBJECT_NAME_NOT_FOUND) {
                protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_SIGNATURE_NOT_FOUND;
            }
            else {
                protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_HOOK_INSTALL_FAILED;
            }
        }
    }
    else {
        g_KswordArkAntiBsod.LastStatus = STATUS_INVALID_PARAMETER;
        protocolStatus = KSWORD_ARK_ANTIBSOD_STATUS_INVALID_REQUEST;
    }
    KswordARKAntiBsodFillResponseLocked(output, protocolStatus);
    ExReleaseFastMutex(&g_KswordArkAntiBsod.ControlLock);
    *BytesReturned = sizeof(*output);
    return STATUS_SUCCESS;
}

#endif // KSWORD_ARK_ANTIBSOD_REFERENCE_ENABLED
