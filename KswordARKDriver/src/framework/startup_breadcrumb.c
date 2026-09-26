/*++

Module Name:

    startup_breadcrumb.c

Abstract:

    Persists the DriverEntry startup stage and the raw NTSTATUS of a failed
    load into the driver service Parameters key. Without this record the only
    user-visible evidence of a failed load is the SCM Win32 code (31), which
    cannot distinguish a WDF queue failure from a kernel callback registration
    failure.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_startup.h"

#include <ntimage.h>
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, KswordArkStartupBreadcrumbInitialize)
#pragma alloc_text (PAGE, KswordArkStartupStage)
#pragma alloc_text (PAGE, KswordArkStartupFailure)
#pragma alloc_text (PAGE, KswordArkStartupNoteCallbackMask)
#pragma alloc_text (PAGE, KswordArkStartupReady)
#pragma alloc_text (PAGE, KswordArkStartupGetOsBuildNumber)
#endif

// 构建身份，用于确认用户实际加载的就是本次分发的二进制。驱动构建是确定性的，
// __DATE__/__TIME__ 不可用，因此改用自身映像的 PE 链接时间戳与校验和：这两个
// 值可以直接和分发出去的 .sys 对照。
static WCHAR g_KswordArkStartupBuildText[64] = { 0 };

// 服务 Parameters 键的内核对象路径，在 DriverEntry 入口一次性拼好。
static WCHAR g_KswordArkStartupParametersPath[512] = { 0 };

// 路径不可用时所有持久化调用静默跳过，绝不影响真正的启动返回值。
static BOOLEAN g_KswordArkStartupPathReady = FALSE;

// 当前已经登记的阶段号，失败路径没有显式传阶段时作为兜底。
static ULONG g_KswordArkStartupCurrentStage = 0UL;

// 降级启动后仍然可用的回调能力掩码。
static ULONG g_KswordArkStartupCallbackMask = 0UL;

// 本次启动观察到的系统内部版本号。
static ULONG g_KswordArkStartupOsBuildNumber = 0UL;
static volatile LONG g_KswordArkStartupOsBuildSupported = 0L;

static VOID
KswordArkStartupCaptureBuildIdentity(
    _In_opt_ PDRIVER_OBJECT DriverObject
    )
/*++

Routine Description:

    Derive the build identity from the loaded image headers. Persisting this
    lets a user report be matched against the exact .sys that was shipped, which
    is the only way to rule out "the running binary is not the one we built".

Arguments:

    DriverObject - Driver object supplied to DriverEntry.

Return Value:

    VOID

--*/
{
    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS ntHeaders = NULL;

    PAGED_CODE();

    // 读不到映像头时保留一个明确的占位值，而不是留空。
    (VOID)RtlStringCchCopyW(
        g_KswordArkStartupBuildText,
        RTL_NUMBER_OF(g_KswordArkStartupBuildText),
        L"unknown");

    if (DriverObject == NULL ||
        DriverObject->DriverStart == NULL ||
        DriverObject->DriverSize < (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))) {
        return;
    }

    __try {
        dosHeader = (PIMAGE_DOS_HEADER)DriverObject->DriverStart;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return;
        }
        if (dosHeader->e_lfanew <= 0 ||
            (ULONG)dosHeader->e_lfanew > (DriverObject->DriverSize - sizeof(IMAGE_NT_HEADERS))) {
            return;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)DriverObject->DriverStart + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return;
        }

        // 链接时间戳与校验和一起唯一标识本次链接产物。
        (VOID)RtlStringCchPrintfW(
            g_KswordArkStartupBuildText,
            RTL_NUMBER_OF(g_KswordArkStartupBuildText),
            L"pe:%08lX/%08lX",
            (ULONG)ntHeaders->FileHeader.TimeDateStamp,
            (ULONG)ntHeaders->OptionalHeader.CheckSum);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 读自身映像头本不应失败；万一失败就保留占位值。
        NOTHING;
    }
}

static VOID
KswordArkStartupWriteDwordValue(
    _In_ HANDLE ParametersKey,
    _In_z_ PCWSTR ValueName,
    _In_ ULONG ValueData
    )
/*++

Routine Description:

    Write one REG_DWORD breadcrumb value. Failures are swallowed because the
    breadcrumb must never change the startup result it is describing.

Arguments:

    ParametersKey - Open handle to the service Parameters key.
    ValueName - Registry value name from the shared startup protocol.
    ValueData - Value payload.

Return Value:

    VOID

--*/
{
    UNICODE_STRING valueNameText;

    PAGED_CODE();

    // 内核注册表 API 只接受 UNICODE_STRING 形式的值名。
    RtlInitUnicodeString(&valueNameText, ValueName);
    (VOID)ZwSetValueKey(
        ParametersKey,
        &valueNameText,
        0UL,
        REG_DWORD,
        &ValueData,
        (ULONG)sizeof(ValueData));
}

static VOID
KswordArkStartupWriteStringValue(
    _In_ HANDLE ParametersKey,
    _In_z_ PCWSTR ValueName,
    _In_z_ PCWSTR ValueText
    )
/*++

Routine Description:

    Write one REG_SZ breadcrumb value, including the terminating NUL so the
    R3 reader can consume it directly.

Arguments:

    ParametersKey - Open handle to the service Parameters key.
    ValueName - Registry value name from the shared startup protocol.
    ValueText - NUL terminated payload.

Return Value:

    VOID

--*/
{
    UNICODE_STRING valueNameText;
    size_t textChars = 0U;

    PAGED_CODE();

    // 长度异常时直接放弃这一条 breadcrumb，不做任何截断猜测。
    if (!NT_SUCCESS(RtlStringCchLengthW(ValueText, NTSTRSAFE_MAX_CCH, &textChars))) {
        return;
    }

    RtlInitUnicodeString(&valueNameText, ValueName);
    (VOID)ZwSetValueKey(
        ParametersKey,
        &valueNameText,
        0UL,
        REG_SZ,
        (PVOID)ValueText,
        (ULONG)((textChars + 1U) * sizeof(WCHAR)));
}

static VOID
KswordArkStartupPersist(
    _In_ ULONG Stage,
    _In_ NTSTATUS Status
    )
/*++

Routine Description:

    Create (or open) the service Parameters key and publish the full startup
    record: stage, raw NTSTATUS, build identity, OS build and the callback
    capability mask that survived a degraded start.

Arguments:

    Stage - KSWORD_ARK_START_STAGE value reached by this attempt.
    Status - Raw NTSTATUS to persist. STATUS_PENDING marks a start still in
        progress; STATUS_SUCCESS marks a completed start.

Return Value:

    VOID

--*/
{
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING parametersPath;
    HANDLE parametersKey = NULL;
    ULONG dispositionValue = 0UL;
    NTSTATUS createStatus = STATUS_SUCCESS;

    PAGED_CODE();

    // 没有解析出服务路径时不做任何注册表访问。
    if (!g_KswordArkStartupPathReady) {
        return;
    }

    RtlInitUnicodeString(&parametersPath, g_KswordArkStartupParametersPath);
    InitializeObjectAttributes(
        &objectAttributes,
        &parametersPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    // Parameters 子键在首次启动时并不存在，因此使用 create 语义。
    createStatus = ZwCreateKey(
        &parametersKey,
        KEY_SET_VALUE,
        &objectAttributes,
        0UL,
        NULL,
        REG_OPTION_NON_VOLATILE,
        &dispositionValue);
    if (!NT_SUCCESS(createStatus)) {
        return;
    }

    KswordArkStartupWriteDwordValue(parametersKey, KSWORD_ARK_STARTUP_VALUE_STAGE, Stage);
    KswordArkStartupWriteDwordValue(parametersKey, KSWORD_ARK_STARTUP_VALUE_STATUS, (ULONG)Status);
    KswordArkStartupWriteStringValue(
        parametersKey,
        KSWORD_ARK_STARTUP_VALUE_BUILD,
        g_KswordArkStartupBuildText);
    KswordArkStartupWriteDwordValue(
        parametersKey,
        KSWORD_ARK_STARTUP_VALUE_OS_BUILD,
        g_KswordArkStartupOsBuildNumber);
    KswordArkStartupWriteDwordValue(
        parametersKey,
        KSWORD_ARK_STARTUP_VALUE_CALLBACK_MASK,
        g_KswordArkStartupCallbackMask);

    (VOID)ZwClose(parametersKey);
}

ULONG
KswordArkStartupGetOsBuildNumber(
    VOID
    )
/*++

Routine Description:

    Return the running OS build number, caching the first successful query.

Arguments:

    None.

Return Value:

    OS build number, or zero when the version could not be queried.

--*/
{
    RTL_OSVERSIONINFOW versionInfo;

    PAGED_CODE();

    // 版本号在一次加载期间不变，查询成功后直接复用缓存。
    if (g_KswordArkStartupOsBuildNumber != 0UL) {
        return g_KswordArkStartupOsBuildNumber;
    }

    RtlZeroMemory(&versionInfo, sizeof(versionInfo));
    versionInfo.dwOSVersionInfoSize = (ULONG)sizeof(versionInfo);
    if (!NT_SUCCESS(RtlGetVersion(&versionInfo))) {
        return 0UL;
    }

    g_KswordArkStartupOsBuildNumber = versionInfo.dwBuildNumber;
    InterlockedExchange(
        &g_KswordArkStartupOsBuildSupported,
        (versionInfo.dwBuildNumber >= KSWORD_ARK_MINIMUM_SUPPORTED_OS_BUILD &&
         versionInfo.dwBuildNumber <= KSWORD_ARK_MAXIMUM_SUPPORTED_OS_BUILD) ?
            1L : 0L);
    return g_KswordArkStartupOsBuildNumber;
}

BOOLEAN
KswordArkStartupIsOsBuildSupported(
    VOID
    )
{
    return InterlockedCompareExchange(
        &g_KswordArkStartupOsBuildSupported,
        0L,
        0L) != 0L;
}

VOID
KswordArkStartupBreadcrumbInitialize(
    _In_opt_ PDRIVER_OBJECT DriverObject,
    _In_opt_ PCUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    Capture the service registry path handed to DriverEntry, then publish the
    first breadcrumb. A machine whose service key holds no LastStartStage after
    a failed start never reached DriverEntry at all, which separates signing /
    Code Integrity / import failures from in-driver initialization failures.

Arguments:

    DriverObject - Driver object used to read the loaded image identity.
    RegistryPath - Service key path supplied by the I/O manager.

Return Value:

    VOID

--*/
{
    NTSTATUS copyStatus = STATUS_SUCCESS;

    PAGED_CODE();

    // 重新初始化时先复位状态，避免沿用上一次加载的路径。
    g_KswordArkStartupPathReady = FALSE;
    g_KswordArkStartupCurrentStage = (ULONG)KswordArkStartStageEnteredDriverEntry;
    g_KswordArkStartupCallbackMask = 0UL;
    g_KswordArkStartupParametersPath[0] = L'\0';

    // 先取映像身份，后续每一条 breadcrumb 都带上它。
    KswordArkStartupCaptureBuildIdentity(DriverObject);

    // 提前读一次系统版本，后续所有 breadcrumb 都带上它。
    (VOID)KswordArkStartupGetOsBuildNumber();

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL || RegistryPath->Length == 0U) {
        return;
    }

    // RegistryPath 未必以 NUL 结尾，必须按 Length 精确复制。
    copyStatus = RtlStringCchCopyNW(
        g_KswordArkStartupParametersPath,
        RTL_NUMBER_OF(g_KswordArkStartupParametersPath),
        RegistryPath->Buffer,
        RegistryPath->Length / sizeof(WCHAR));
    if (!NT_SUCCESS(copyStatus)) {
        return;
    }

    // 服务键本身由 SCM 拥有，breadcrumb 统一写在其 Parameters 子键下。
    copyStatus = RtlStringCchCatW(
        g_KswordArkStartupParametersPath,
        RTL_NUMBER_OF(g_KswordArkStartupParametersPath),
        L"\\" KSWORD_ARK_STARTUP_PARAMETERS_SUBKEY);
    if (!NT_SUCCESS(copyStatus)) {
        return;
    }

    g_KswordArkStartupPathReady = TRUE;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[KswordARK] startup stage=%lu build=%ws osBuild=%lu\n",
        g_KswordArkStartupCurrentStage,
        g_KswordArkStartupBuildText,
        g_KswordArkStartupOsBuildNumber);

    // 入口记录用 STATUS_PENDING 表示"已进入 DriverEntry 但尚未定论"。
    KswordArkStartupPersist(g_KswordArkStartupCurrentStage, STATUS_PENDING);
}

VOID
KswordArkStartupStage(
    _In_ KSWORD_ARK_START_STAGE Stage
    )
/*++

Routine Description:

    Record the stage that is about to run. Only memory state and the debugger
    trace are updated here; the registry is written on failure or on success so
    a normal start does not pay for seventeen registry transactions.

Arguments:

    Stage - Stage about to be attempted.

Return Value:

    VOID

--*/
{
    PAGED_CODE();

    g_KswordArkStartupCurrentStage = (ULONG)Stage;
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[KswordARK] startup stage=%lu\n",
        g_KswordArkStartupCurrentStage);
}

NTSTATUS
KswordArkStartupFailure(
    _In_ KSWORD_ARK_START_STAGE Stage,
    _In_ NTSTATUS Status
    )
/*++

Routine Description:

    Persist a fatal startup failure and return the original NTSTATUS unchanged
    so the caller can hand it straight back to the I/O manager.

Arguments:

    Stage - Stage that failed.
    Status - Raw NTSTATUS returned by the failing API.

Return Value:

    The Status argument, unmodified.

--*/
{
    PAGED_CODE();

    g_KswordArkStartupCurrentStage = (ULONG)Stage;
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[KswordARK] startup failure: stage=%lu status=0x%08lX\n",
        g_KswordArkStartupCurrentStage,
        (ULONG)Status);

    // 持久化失败本身不得改变返回值，因此忽略其结果。
    KswordArkStartupPersist(g_KswordArkStartupCurrentStage, Status);
    return Status;
}

VOID
KswordArkStartupNoteCallbackMask(
    _In_ ULONG CallbackMask
    )
/*++

Routine Description:

    Remember which callback capabilities survived a degraded start so the final
    breadcrumb explains why some features are missing on this machine.

Arguments:

    CallbackMask - KSWORD_ARK_CALLBACK_REGISTERED_* bitmask.

Return Value:

    VOID

--*/
{
    PAGED_CODE();

    g_KswordArkStartupCallbackMask = CallbackMask;
}

VOID
KswordArkStartupReady(
    VOID
    )
/*++

Routine Description:

    Publish the terminal success record. A stale failure record from a previous
    boot is therefore always overwritten by the next successful start.

Arguments:

    None.

Return Value:

    VOID

--*/
{
    PAGED_CODE();

    g_KswordArkStartupCurrentStage = (ULONG)KswordArkStartStageReady;
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[KswordARK] startup ready, callbackMask=0x%08lX\n",
        g_KswordArkStartupCallbackMask);

    KswordArkStartupPersist(g_KswordArkStartupCurrentStage, STATUS_SUCCESS);
}
