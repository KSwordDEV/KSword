#include "ark/ark_driver.h"

/*++

Module Name:

    bugcheck_guard.c

Abstract:

    Explicitly-confirmed KeBugCheckEx guard with persistent ignore mode.

--*/

#if !defined(_WIN64)
#error The bugcheck delay guard only supports x64 builds.
#endif

#define KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED 0L
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED   1L
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_RESTORING   2L
#define KSWORD_ARK_BUGCHECK_GUARD_SYSTEM_CODEINTEGRITY_INFORMATION 103UL

typedef VOID
(NTAPI* KSWORD_ARK_KE_BUGCHECK_EX_FN)(
    _In_ ULONG BugCheckCode,
    _In_ ULONG_PTR Parameter1,
    _In_ ULONG_PTR Parameter2,
    _In_ ULONG_PTR Parameter3,
    _In_ ULONG_PTR Parameter4
    );

typedef struct _KSWORD_ARK_BUGCHECK_GUARD_CODEINTEGRITY_INFORMATION
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
} KSWORD_ARK_BUGCHECK_GUARD_CODEINTEGRITY_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef struct _KSWORD_ARK_BUGCHECK_GUARD_STATE
{
    FAST_MUTEX ControlLock;
    volatile LONG HookState;
    volatile LONG Enabled;
    volatile LONG Fired;
    volatile LONG TryIgnoreError;
    volatile LONG ErrorIgnored;
    volatile LONG HookExecutions;
    volatile LONG HvciEnabled;
    volatile LONG CallbackRegistered;
    ULONG DelaySeconds;
    PVOID Target;
    PMDL TargetMdl;
    PVOID WritableAlias;
    KBUGCHECK_CALLBACK_RECORD CallbackRecord;
    ULONG CallbackBuffer;
    UCHAR OriginalBytes[KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES];
    UCHAR HookBytes[KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES];
    NTSTATUS LastStatus;
} KSWORD_ARK_BUGCHECK_GUARD_STATE;

static KSWORD_ARK_BUGCHECK_GUARD_STATE g_KswordArkBugcheckGuard;
static UCHAR g_KswordArkBugcheckGuardComponent[] = "KswordBugcheckGuard";

static VOID
NTAPI
KswordARKBugcheckGuardHook(
    _In_ ULONG BugCheckCode,
    _In_ ULONG_PTR Parameter1,
    _In_ ULONG_PTR Parameter2,
    _In_ ULONG_PTR Parameter3,
    _In_ ULONG_PTR Parameter4
    );

static VOID
KswordARKBugcheckGuardCallback(
    _In_ PVOID Buffer,
    _In_ ULONG Length
    );

static BOOLEAN
KswordARKBugcheckGuardLooksHooked(
    _In_reads_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) const UCHAR* Bytes
    )
{
    if (Bytes[0] == 0xE9U || Bytes[0] == 0xEBU || Bytes[0] == 0xCCU) {
        return TRUE;
    }

    if ((Bytes[0] == 0xFFU && Bytes[1] == 0x25U) ||
        (Bytes[0] == 0x48U && Bytes[1] == 0xB8U &&
         Bytes[10] == 0xFFU && Bytes[11] == 0xE0U)) {
        return TRUE;
    }

    return FALSE;
}

static VOID
KswordARKBugcheckGuardBuildHook(
    _Out_writes_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) UCHAR* Patch
    )
{
    PVOID hookTarget = (PVOID)(ULONG_PTR)KswordARKBugcheckGuardHook;
    RtlZeroMemory(Patch, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
    Patch[0] = 0x48U;
    Patch[1] = 0xB8U;
    RtlCopyMemory(Patch + 2U, &hookTarget, sizeof(hookTarget));
    Patch[10] = 0xFFU;
    Patch[11] = 0xE0U;
}

static BOOLEAN
KswordARKBugcheckGuardHvciEnabled(VOID)
{
    KSWORD_ARK_BUGCHECK_GUARD_CODEINTEGRITY_INFORMATION information;
    NTSTATUS status;

    RtlZeroMemory(&information, sizeof(information));
    information.Length = sizeof(information);
    status = ZwQuerySystemInformation(
        KSWORD_ARK_BUGCHECK_GUARD_SYSTEM_CODEINTEGRITY_INFORMATION,
        &information,
        sizeof(information),
        NULL);
    return NT_SUCCESS(status) &&
        (information.CodeIntegrityOptions &
            KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0UL;
}

static NTSTATUS
KswordARKBugcheckGuardTryWriteBytes(
    _Out_writes_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) PVOID Destination,
    _In_reads_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) const UCHAR* Source
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        RtlCopyMemory(
            Destination,
            Source,
            KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
        KeMemoryBarrier();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static NTSTATUS
KswordARKBugcheckGuardVerifyBytes(
    _In_reads_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) const VOID* Address,
    _In_reads_bytes_(KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) const UCHAR* Expected
    )
{
    SIZE_T matchingBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        matchingBytes = RtlCompareMemory(
            Address,
            Expected,
            KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (NT_SUCCESS(status) &&
        matchingBytes != KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES) {
        status = STATUS_DATA_ERROR;
    }
    return status;
}

static ULONG
KswordARKBugcheckGuardStateFlags(VOID)
{
    ULONG flags = 0UL;

    if (g_KswordArkBugcheckGuard.Target != NULL) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_TARGET_RESOLVED;
    }
    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.Enabled, 1L, 1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_ACTIVE;
    }
    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.HookState, 1L, 1L) == KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_PATCH_INSTALLED;
    }

    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.Fired, 1L, 1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_FIRED;
    }
    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.TryIgnoreError, 1L, 1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_TRY_IGNORE_ERROR;
    }
    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 1L, 1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_ERROR_IGNORED;
    }
    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.HookExecutions, 0L, 0L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_HOOK_EXECUTING;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckGuard.HvciEnabled,
            1L,
            1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_HVCI_ENABLED;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckGuard.CallbackRegistered,
            1L,
            1L) != 0L) {
        flags |= KSWORD_ARK_BUGCHECK_GUARD_STATE_CALLBACK_REGISTERED;
    }
    return flags;
}
static NTSTATUS
KswordARKBugcheckGuardRestoreFromCrashPath(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    LONG state = InterlockedCompareExchange(
        &g_KswordArkBugcheckGuard.HookState,
        KSWORD_ARK_BUGCHECK_GUARD_STATE_RESTORING,
        KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED);

    if (state == KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED) {
        if (g_KswordArkBugcheckGuard.WritableAlias == NULL ||
            g_KswordArkBugcheckGuard.Target == NULL) {
            status = STATUS_INVALID_DEVICE_STATE;
        }
        else {
            status = KswordARKBugcheckGuardVerifyBytes(
                g_KswordArkBugcheckGuard.WritableAlias,
                g_KswordArkBugcheckGuard.OriginalBytes);
            if (!NT_SUCCESS(status)) {
                status = KswordARKBugcheckGuardTryWriteBytes(
                    g_KswordArkBugcheckGuard.WritableAlias,
                    g_KswordArkBugcheckGuard.OriginalBytes);
                if (NT_SUCCESS(status)) {
                    status = KswordARKBugcheckGuardVerifyBytes(
                        g_KswordArkBugcheckGuard.WritableAlias,
                        g_KswordArkBugcheckGuard.OriginalBytes);
                }
            }
        }
        if (NT_SUCCESS(status)) {
            KeInvalidateRangeAllCaches(
                g_KswordArkBugcheckGuard.Target,
                KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
            InterlockedExchange(
                &g_KswordArkBugcheckGuard.HookState,
                KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED);
            return STATUS_SUCCESS;
        }
        g_KswordArkBugcheckGuard.LastStatus = status;
        InterlockedExchange(
            &g_KswordArkBugcheckGuard.HookState,
            KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED);
        return status;
    }

    while (state == KSWORD_ARK_BUGCHECK_GUARD_STATE_RESTORING) {
        KeStallExecutionProcessor(10UL);
        state = InterlockedCompareExchange(&g_KswordArkBugcheckGuard.HookState, 0L, 0L);
    }
    return state == KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED ?
        STATUS_SUCCESS : STATUS_DEVICE_BUSY;
}

static NTSTATUS
KswordARKBugcheckGuardReleaseMappingLocked(VOID)
{
    NTSTATUS status;

    InterlockedExchange(&g_KswordArkBugcheckGuard.Enabled, 0L);
    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckGuard.CallbackRegistered,
            0L,
            0L) != 0L) {
        if (InterlockedCompareExchange(
                &g_KswordArkBugcheckGuard.HookExecutions,
                0L,
                0L) != 0L ||
            !KeDeregisterBugCheckCallback(
                &g_KswordArkBugcheckGuard.CallbackRecord)) {
            return STATUS_DEVICE_BUSY;
        }
        InterlockedExchange(
            &g_KswordArkBugcheckGuard.CallbackRegistered,
            0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.Fired, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.TryIgnoreError, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 0L);
        g_KswordArkBugcheckGuard.DelaySeconds = 0UL;
        return STATUS_SUCCESS;
    }

    status = KswordARKBugcheckGuardRestoreFromCrashPath();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckGuard.HookExecutions,
            0L,
            0L) != 0L) {
        // A triggering CPU is still executing this driver. A later disable
        // request can release the mapping after the return attempt completes.
        return STATUS_DEVICE_BUSY;
    }
    InterlockedExchange(&g_KswordArkBugcheckGuard.Fired, 0L);
    InterlockedExchange(&g_KswordArkBugcheckGuard.TryIgnoreError, 0L);
    InterlockedExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 0L);
    if (g_KswordArkBugcheckGuard.WritableAlias != NULL) {
        MmUnmapLockedPages(g_KswordArkBugcheckGuard.WritableAlias, g_KswordArkBugcheckGuard.TargetMdl);
        g_KswordArkBugcheckGuard.WritableAlias = NULL;
    }
    if (g_KswordArkBugcheckGuard.TargetMdl != NULL) {
        MmUnlockPages(g_KswordArkBugcheckGuard.TargetMdl);
        IoFreeMdl(g_KswordArkBugcheckGuard.TargetMdl);
        g_KswordArkBugcheckGuard.TargetMdl = NULL;
    }
    g_KswordArkBugcheckGuard.Target = NULL;
    RtlZeroMemory(g_KswordArkBugcheckGuard.OriginalBytes, sizeof(g_KswordArkBugcheckGuard.OriginalBytes));
    RtlZeroMemory(g_KswordArkBugcheckGuard.HookBytes, sizeof(g_KswordArkBugcheckGuard.HookBytes));
    g_KswordArkBugcheckGuard.DelaySeconds = 0UL;
    return STATUS_SUCCESS;
}

static VOID
KswordARKBugcheckGuardDelay(
    _In_ ULONG DelaySeconds
    )
{
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    ULONG remainingSeconds;

    (void)KeQueryPerformanceCounter(&frequency);
    if (frequency.QuadPart <= 0) {
        for (remainingSeconds = DelaySeconds;
             remainingSeconds != 0UL;
             --remainingSeconds) {
            ULONG sliceIndex;

            for (sliceIndex = 0UL; sliceIndex < 20000UL; ++sliceIndex) {
                if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.Enabled, 0L, 0L) == 0L) { /* Let an explicit off request cancel the remaining delay. */
                    return; /* Leave crash forwarding or return handling to the caller. */
                }
                KeStallExecutionProcessor(50UL);
            }
        }
        return;
    }
    for (remainingSeconds = DelaySeconds;
         remainingSeconds != 0UL;
         --remainingSeconds) {
        start = KeQueryPerformanceCounter(NULL);
        while ((ULONGLONG)(
                KeQueryPerformanceCounter(NULL).QuadPart -
                start.QuadPart) < (ULONGLONG)frequency.QuadPart) {
            if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.Enabled, 0L, 0L) == 0L) { /* Observe switch-off without waiting for the full configured delay. */
                return; /* Do not acquire control locks in the crash path. */
            }
            KeStallExecutionProcessor(50UL);
        }
    }
}

static VOID
KswordARKBugcheckGuardCallback(
    _In_ PVOID Buffer,
    _In_ ULONG Length
    )
{
    BOOLEAN enabled; /* Snapshot the switch without consuming an activation. */

    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Length);

    InterlockedIncrement(&g_KswordArkBugcheckGuard.HookExecutions);
    enabled = InterlockedCompareExchange(&g_KswordArkBugcheckGuard.Enabled, 0L, 0L) != 0L; /* Read the persistent switch. */
    if (enabled) { /* Each callback keeps the registration active until disable. */
        InterlockedExchange(&g_KswordArkBugcheckGuard.Fired, 1L); /* Record history without disarming the guard. */
        KswordARKBugcheckGuardDelay(
            g_KswordArkBugcheckGuard.DelaySeconds);
    }
    InterlockedDecrement(&g_KswordArkBugcheckGuard.HookExecutions);
}

static VOID
NTAPI
KswordARKBugcheckGuardHook(
    _In_ ULONG BugCheckCode,
    _In_ ULONG_PTR Parameter1,
    _In_ ULONG_PTR Parameter2,
    _In_ ULONG_PTR Parameter3,
    _In_ ULONG_PTR Parameter4
    )
{
    KSWORD_ARK_KE_BUGCHECK_EX_FN target;
    BOOLEAN enabled; /* Preserve whether this invocation entered an enabled guard. */
    BOOLEAN tryIgnoreError;
    NTSTATUS restoreStatus;

    InterlockedIncrement(&g_KswordArkBugcheckGuard.HookExecutions);
    target =
        (KSWORD_ARK_KE_BUGCHECK_EX_FN)g_KswordArkBugcheckGuard.Target;
    enabled = InterlockedCompareExchange(&g_KswordArkBugcheckGuard.Enabled, 0L, 0L) != 0L; /* Read the switch without clearing it. */
    tryIgnoreError = InterlockedCompareExchange(
        &g_KswordArkBugcheckGuard.TryIgnoreError,
        1L,
        1L) != 0L;

    if (enabled) { /* Apply the configured delay on every intercepted call. */
        InterlockedExchange(&g_KswordArkBugcheckGuard.Fired, 1L); /* Fired is history, not an automatic off switch. */
        KswordARKBugcheckGuardDelay(g_KswordArkBugcheckGuard.DelaySeconds); /* Keep the entry installed throughout the delay. */
    }
    if (enabled && tryIgnoreError &&
        InterlockedCompareExchange(&g_KswordArkBugcheckGuard.Enabled, 0L, 0L) != 0L) { /* An explicit disable takes precedence over persistent interception. */
        // The entry remains installed for subsequent calls. A forced return still
        // does not repair the fault or supply a valid continuation for no-return callers.
        InterlockedExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 1L); /* Report a return attempt, not system recovery. */
        InterlockedDecrement(&g_KswordArkBugcheckGuard.HookExecutions); /* Release this invocation before returning. */
        return; /* Only explicit disable or the normal forwarding mode restores the entry. */
    }
    InterlockedExchange(&g_KswordArkBugcheckGuard.Enabled, 0L); /* Normal forwarding leaves interception before entering Windows bugcheck. */
    restoreStatus = KswordARKBugcheckGuardRestoreFromCrashPath(); /* Restore only when forwarding, never on a persistent ignore hit. */
    if (!NT_SUCCESS(restoreStatus)) {
        g_KswordArkBugcheckGuard.LastStatus = restoreStatus;
        InterlockedExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 1L);
        InterlockedDecrement(&g_KswordArkBugcheckGuard.HookExecutions);
        return;
    }
    InterlockedDecrement(&g_KswordArkBugcheckGuard.HookExecutions);
    if (target != NULL) {
        target(BugCheckCode, Parameter1, Parameter2, Parameter3, Parameter4);
    }
    KeBugCheckEx(BugCheckCode, Parameter1, Parameter2, Parameter3, Parameter4);
}

static NTSTATUS
KswordARKBugcheckGuardEnableCallbackLocked(
    _In_ ULONG DelaySeconds
    )
{
    BOOLEAN registered;

    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckGuard.HookState,
            0L,
            0L) != KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED ||
        InterlockedCompareExchange(
            &g_KswordArkBugcheckGuard.CallbackRegistered,
            0L,
            0L) != 0L ||
        InterlockedCompareExchange(
            &g_KswordArkBugcheckGuard.HookExecutions,
            0L,
            0L) != 0L ||
        g_KswordArkBugcheckGuard.Target != NULL ||
        g_KswordArkBugcheckGuard.TargetMdl != NULL ||
        g_KswordArkBugcheckGuard.WritableAlias != NULL) {
        return STATUS_DEVICE_BUSY;
    }

    g_KswordArkBugcheckGuard.DelaySeconds = DelaySeconds;
    g_KswordArkBugcheckGuard.CallbackBuffer = 0UL;
    InterlockedExchange(&g_KswordArkBugcheckGuard.Fired, 0L);
    InterlockedExchange(&g_KswordArkBugcheckGuard.TryIgnoreError, 0L);
    InterlockedExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 0L);
    InterlockedExchange(&g_KswordArkBugcheckGuard.HookExecutions, 0L);
    KeInitializeCallbackRecord(&g_KswordArkBugcheckGuard.CallbackRecord);
    registered = KeRegisterBugCheckCallback(
        &g_KswordArkBugcheckGuard.CallbackRecord,
        KswordARKBugcheckGuardCallback,
        &g_KswordArkBugcheckGuard.CallbackBuffer,
        sizeof(g_KswordArkBugcheckGuard.CallbackBuffer),
        g_KswordArkBugcheckGuardComponent);
    if (!registered) {
        g_KswordArkBugcheckGuard.DelaySeconds = 0UL;
        return STATUS_UNSUCCESSFUL;
    }
    InterlockedExchange(
        &g_KswordArkBugcheckGuard.CallbackRegistered,
        1L);
    InterlockedExchange(&g_KswordArkBugcheckGuard.Enabled, 1L);
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKBugcheckGuardEnableLocked(
    _In_ ULONG DelaySeconds,
    _In_ BOOLEAN TryIgnoreError
    )
{
    UNICODE_STRING routineName;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID target = NULL;
    PMDL mdl = NULL;
    PVOID writableAlias = NULL;
    BOOLEAN pagesLocked = FALSE;
    BOOLEAN canReleaseMapping = TRUE;

    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckGuard.HvciEnabled,
            1L,
            1L) != 0L) {
        return KswordARKBugcheckGuardEnableCallbackLocked(DelaySeconds);
    }
    if (InterlockedCompareExchange(&g_KswordArkBugcheckGuard.HookState, 0L, 0L) != KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED) {
        return InterlockedCompareExchange(&g_KswordArkBugcheckGuard.Enabled, 0L, 0L) != 0L
            ? STATUS_ALREADY_REGISTERED : STATUS_DEVICE_BUSY; /* A pending disable is not an active installation. */
    }
    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckGuard.HookExecutions,
            0L,
            0L) != 0L ||
        g_KswordArkBugcheckGuard.Target != NULL ||
        g_KswordArkBugcheckGuard.TargetMdl != NULL ||
        g_KswordArkBugcheckGuard.WritableAlias != NULL) {
        return STATUS_DEVICE_BUSY;
    }

    RtlInitUnicodeString(&routineName, L"KeBugCheckEx");
    target = MmGetSystemRoutineAddress(&routineName);
    if (target == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    mdl = IoAllocateMdl(target, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        // The original executable mapping is intentionally read-only. Probe
        // for read access, then apply PAGE_READWRITE only to the MDL alias.
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        pagesLocked = TRUE;
        writableAlias = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmCached,
            NULL,
            FALSE,
            NormalPagePriority | MdlMappingNoExecute);
        if (writableAlias == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }
        status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        RtlCopyMemory(g_KswordArkBugcheckGuard.OriginalBytes, writableAlias, KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
        if (KswordARKBugcheckGuardLooksHooked(g_KswordArkBugcheckGuard.OriginalBytes)) {
            status = STATUS_OBJECT_NAME_COLLISION;
            __leave;
        }
        KswordARKBugcheckGuardBuildHook(g_KswordArkBugcheckGuard.HookBytes);
        g_KswordArkBugcheckGuard.Target = target;
        g_KswordArkBugcheckGuard.TargetMdl = mdl;
        g_KswordArkBugcheckGuard.WritableAlias = writableAlias;
        g_KswordArkBugcheckGuard.DelaySeconds = DelaySeconds;
        InterlockedExchange(&g_KswordArkBugcheckGuard.Fired, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.TryIgnoreError, TryIgnoreError ? 1L : 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.HookExecutions, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.HookState, KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED);
        status = KswordARKBugcheckGuardTryWriteBytes(
            writableAlias,
            g_KswordArkBugcheckGuard.HookBytes);
        if (NT_SUCCESS(status)) {
            status = KswordARKBugcheckGuardVerifyBytes(
                writableAlias,
                g_KswordArkBugcheckGuard.HookBytes);
        }
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        KeInvalidateRangeAllCaches(
            target,
            KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES);
        InterlockedExchange(&g_KswordArkBugcheckGuard.Enabled, 1L);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        if (InterlockedCompareExchange(
                &g_KswordArkBugcheckGuard.HookState,
                0L,
                0L) == KSWORD_ARK_BUGCHECK_GUARD_STATE_INSTALLED) {
            NTSTATUS restoreStatus =
                KswordARKBugcheckGuardRestoreFromCrashPath();
            if (!NT_SUCCESS(restoreStatus)) {
                canReleaseMapping = FALSE;
            }
        }
        InterlockedExchange(&g_KswordArkBugcheckGuard.Enabled, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.TryIgnoreError, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.ErrorIgnored, 0L);
        InterlockedExchange(&g_KswordArkBugcheckGuard.HookExecutions, 0L);
        if (canReleaseMapping) {
            if (writableAlias != NULL) {
                MmUnmapLockedPages(writableAlias, mdl);
            }
            if (pagesLocked) {
                MmUnlockPages(mdl);
            }
            IoFreeMdl(mdl);
            g_KswordArkBugcheckGuard.Target = NULL;
            g_KswordArkBugcheckGuard.TargetMdl = NULL;
            g_KswordArkBugcheckGuard.WritableAlias = NULL;
            g_KswordArkBugcheckGuard.DelaySeconds = 0UL;
            RtlZeroMemory(g_KswordArkBugcheckGuard.OriginalBytes, sizeof(g_KswordArkBugcheckGuard.OriginalBytes));
            RtlZeroMemory(g_KswordArkBugcheckGuard.HookBytes, sizeof(g_KswordArkBugcheckGuard.HookBytes));
        }
    }
    return status;
}

static VOID
KswordARKBugcheckGuardFillResponse(
    _Out_ KSWORD_ARK_BUGCHECK_GUARD_RESPONSE* Response,
    _In_ ULONG Status
    )
{
    RtlZeroMemory(Response, sizeof(*Response));
    Response->size = sizeof(*Response);
    Response->version = KSWORD_ARK_BUGCHECK_GUARD_PROTOCOL_VERSION;
    Response->status = Status;
    Response->stateFlags = KswordARKBugcheckGuardStateFlags();
    Response->delaySeconds = g_KswordArkBugcheckGuard.DelaySeconds;
    Response->lastStatus = g_KswordArkBugcheckGuard.LastStatus;
    Response->targetAddress = (ULONGLONG)(ULONG_PTR)g_KswordArkBugcheckGuard.Target;
    RtlCopyMemory(Response->originalBytes, g_KswordArkBugcheckGuard.OriginalBytes, sizeof(Response->originalBytes));
    RtlCopyMemory(Response->hookBytes, g_KswordArkBugcheckGuard.HookBytes, sizeof(Response->hookBytes));
}

VOID
KswordARKBugcheckGuardInitialize(
    VOID
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    return;
#else
    RtlZeroMemory(&g_KswordArkBugcheckGuard, sizeof(g_KswordArkBugcheckGuard));
    ExInitializeFastMutex(&g_KswordArkBugcheckGuard.ControlLock);
    InterlockedExchange(
        &g_KswordArkBugcheckGuard.HvciEnabled,
        KswordARKBugcheckGuardHvciEnabled() ? 1L : 0L);
    g_KswordArkBugcheckGuard.LastStatus = STATUS_SUCCESS;
#endif
}

VOID
KswordARKBugcheckGuardUninitialize(
    VOID
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    return;
#else
    NTSTATUS status;

    ExAcquireFastMutex(&g_KswordArkBugcheckGuard.ControlLock);
    status = KswordARKBugcheckGuardReleaseMappingLocked();
    g_KswordArkBugcheckGuard.LastStatus = status;
    ExReleaseFastMutex(&g_KswordArkBugcheckGuard.ControlLock);
#endif
}

NTSTATUS
KswordARKBugcheckGuardIoctlConfigure(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned != NULL) {
        *BytesReturned = 0;
    }
    return STATUS_NOT_SUPPORTED;
#else
    KSWORD_ARK_BUGCHECK_GUARD_REQUEST* input = NULL;
    KSWORD_ARK_BUGCHECK_GUARD_RESPONSE* output = NULL;
    NTSTATUS status;
    ULONG protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST;

    UNREFERENCED_PARAMETER(Device);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(*input),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || InputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(*output),
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || OutputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    ExAcquireFastMutex(&g_KswordArkBugcheckGuard.ControlLock);
    if (input->size != sizeof(*input) ||
        input->version != KSWORD_ARK_BUGCHECK_GUARD_PROTOCOL_VERSION ||
        input->reserved0 != 0UL ||
        input->reserved1 != 0UL ||
        (input->flags & ~(KSWORD_ARK_BUGCHECK_GUARD_FLAG_UI_CONFIRMED | KSWORD_ARK_BUGCHECK_GUARD_FLAG_TRY_IGNORE_ERROR)) != 0UL) {
        g_KswordArkBugcheckGuard.LastStatus = STATUS_INVALID_PARAMETER;
        protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_GUARD_ACTION_QUERY) {
        if (InterlockedCompareExchange(
                &g_KswordArkBugcheckGuard.Enabled,
                0L,
                0L) != 0L) {
            protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE;
        }
        else if (InterlockedCompareExchange(
                    &g_KswordArkBugcheckGuard.HookState,
                    0L,
                    0L) != KSWORD_ARK_BUGCHECK_GUARD_STATE_UNINSTALLED ||
                 InterlockedCompareExchange(
                    &g_KswordArkBugcheckGuard.HookExecutions,
                    0L,
                    0L) != 0L) {
            protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_BUSY;
        }
        else {
            protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INACTIVE;
        }
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_GUARD_ACTION_DISABLE) {
        status = KswordARKBugcheckGuardReleaseMappingLocked();
        g_KswordArkBugcheckGuard.LastStatus = status;
        protocolStatus = NT_SUCCESS(status)
            ? KSWORD_ARK_BUGCHECK_GUARD_STATUS_INACTIVE
            : KSWORD_ARK_BUGCHECK_GUARD_STATUS_BUSY;
    }
    else if (input->action == KSWORD_ARK_BUGCHECK_GUARD_ACTION_ENABLE) {
        if ((input->flags & KSWORD_ARK_BUGCHECK_GUARD_FLAG_UI_CONFIRMED) == 0UL ||
            input->confirmationToken != KSWORD_ARK_BUGCHECK_GUARD_CONFIRMATION_TOKEN) {
            g_KswordArkBugcheckGuard.LastStatus = STATUS_ACCESS_DENIED;
            protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFIRMATION_NEEDED;
        }
        else if (input->delaySeconds <
                    KSWORD_ARK_BUGCHECK_GUARD_MIN_DELAY_SECONDS) {
            g_KswordArkBugcheckGuard.LastStatus = STATUS_INVALID_PARAMETER;
            protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST;
        }
        else {
            status = KswordARKBugcheckGuardEnableLocked(
                input->delaySeconds,
                (input->flags & KSWORD_ARK_BUGCHECK_GUARD_FLAG_TRY_IGNORE_ERROR) != 0UL);
            g_KswordArkBugcheckGuard.LastStatus = status;
            if (status == STATUS_SUCCESS) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE;
            }
            else if (status == STATUS_ALREADY_REGISTERED) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE;
            }
            else if (status == STATUS_NOT_SUPPORTED) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_UNSUPPORTED;
            }
            else if (status == STATUS_OBJECT_NAME_COLLISION) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFLICT;
            }
            else if (status == STATUS_DEVICE_BUSY) {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_BUSY;
            }
            else {
                protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_PATCH_FAILED;
            }
        }
    }
    else {
        g_KswordArkBugcheckGuard.LastStatus = STATUS_INVALID_PARAMETER;
        protocolStatus = KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST;
    }

    KswordARKBugcheckGuardFillResponse(output, protocolStatus);
    ExReleaseFastMutex(&g_KswordArkBugcheckGuard.ControlLock);
    *BytesReturned = sizeof(*output);
    return STATUS_SUCCESS;
#endif
}
