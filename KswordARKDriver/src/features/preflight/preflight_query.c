/*++

Module Name:

    preflight_query.c

Abstract:

    Phase-16 release preflight diagnostics.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_registry.h"

#include <ntstrsafe.h>

#define KSWORD_ARK_PREFLIGHT_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE) - sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY))

typedef struct _KSWORD_ARK_PREFLIGHT_BUILDER
{
    KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE* Response;
    ULONG Capacity;
    ULONG Returned;
    ULONG Total;
    ULONG WorstStatus;
} KSWORD_ARK_PREFLIGHT_BUILDER;

static ULONG
KswordARKPreflightBuildConfiguration(
    VOID
    )
/*++

Routine Description:

    返回当前驱动编译配置。中文说明：Debug/Release 由预处理宏判断，供发布前
    诊断确认当前加载的不是错误配置。

Arguments:

    None.

Return Value:

    KSWORD_ARK_PREFLIGHT_BUILD_*。

--*/
{
#if DBG
    return KSWORD_ARK_PREFLIGHT_BUILD_DEBUG;
#else
    return KSWORD_ARK_PREFLIGHT_BUILD_RELEASE;
#endif
}

static ULONG
KswordARKPreflightTargetArchitecture(
    VOID
    )
/*++

Routine Description:

    返回当前目标架构。中文说明：Phase-16 要求 x64 Debug/Release 无警告，
    ARM64 项目保留但当前验收以 x64 为主。

Arguments:

    None.

Return Value:

    KSWORD_ARK_PREFLIGHT_ARCH_*。

--*/
{
#if defined(_M_AMD64) || defined(_AMD64_)
    return KSWORD_ARK_PREFLIGHT_ARCH_X64;
#elif defined(_M_ARM64) || defined(_ARM64_)
    return KSWORD_ARK_PREFLIGHT_ARCH_ARM64;
#else
    return KSWORD_ARK_PREFLIGHT_ARCH_UNKNOWN;
#endif
}

static VOID
KswordARKPreflightCopyAnsi(
    _Out_writes_bytes_(DestinationBytes) CHAR* Destination,
    _In_ size_t DestinationBytes,
    _In_opt_z_ PCSTR Source
    )
/*++

Routine Description:

    复制 preflight 诊断文本。中文说明：固定 ANSI 字段总是 NUL 结尾，避免 R3
    诊断报告拼接时读越界。

Arguments:

    Destination - 目标缓冲。
    DestinationBytes - 缓冲字节数。
    Source - 可选来源字符串。

Return Value:

    None. 本函数没有返回值。

--*/
{
    if (Destination == NULL || DestinationBytes == 0U) {
        return;
    }

    Destination[0] = '\0';
    if (Source == NULL) {
        return;
    }

    (VOID)RtlStringCbCopyNA(Destination, DestinationBytes, Source, DestinationBytes - 1U);
    Destination[DestinationBytes - 1U] = '\0';
}

static VOID
KswordARKPreflightAddCheck(
    _Inout_ KSWORD_ARK_PREFLIGHT_BUILDER* Builder,
    _In_ ULONG CheckId,
    _In_ ULONG Status,
    _In_ NTSTATUS NtStatus,
    _In_z_ PCSTR CheckName,
    _In_z_ PCSTR DetailText
    )
/*++

Routine Description:

    添加一条 preflight check。中文说明：输出缓冲容量不足时仍增加 totalCount，
    R3 可据此扩容重试。

Arguments:

    Builder - 构造器。
    CheckId - 检查项 ID。
    Status - PASS/WARN/FAIL/NOT_RUN。
    NtStatus - 相关 NTSTATUS。
    CheckName - 检查名称。
    DetailText - 诊断说明。

Return Value:

    None. 本函数没有返回值。

--*/
{
    if (Builder == NULL) {
        return;
    }

    Builder->Total += 1UL;
    if (Status > Builder->WorstStatus && Status != KSWORD_ARK_PREFLIGHT_STATUS_NOT_RUN) {
        Builder->WorstStatus = Status;
    }

    if (Builder->Response == NULL || Builder->Returned >= Builder->Capacity) {
        return;
    }

    {
        KSWORD_ARK_PREFLIGHT_CHECK_ENTRY* entry = &Builder->Response->checks[Builder->Returned];
        RtlZeroMemory(entry, sizeof(*entry));
        entry->checkId = CheckId;
        entry->status = Status;
        entry->ntstatus = NtStatus;
        KswordARKPreflightCopyAnsi(entry->checkName, sizeof(entry->checkName), CheckName);
        KswordARKPreflightCopyAnsi(entry->detail, sizeof(entry->detail), DetailText);
        Builder->Returned += 1UL;
    }
}

static VOID
KswordARKPreflightAddExternalGateChecks(
    _Inout_ KSWORD_ARK_PREFLIGHT_BUILDER* Builder
    )
/*++

Routine Description:

    添加需要人工或外部环境执行的发布门槛。中文说明：驱动内无法运行 Driver
    Verifier、跨系统兼容性矩阵和 R3 UI 验收，因此明确标记 NotRun。

Arguments:

    Builder - 构造器。

Return Value:

    None. 本函数没有返回值。

--*/
{
    KswordARKPreflightAddCheck(
        Builder,
        KSWORD_ARK_PREFLIGHT_CHECK_DRIVER_VERIFIER,
        KSWORD_ARK_PREFLIGHT_STATUS_NOT_RUN,
        STATUS_NOT_SUPPORTED,
        "Driver Verifier",
        "External test required; driver reports NotRun instead of assuming pass.");
    KswordARKPreflightAddCheck(
        Builder,
        KSWORD_ARK_PREFLIGHT_CHECK_LOAD_UNLOAD,
        KSWORD_ARK_PREFLIGHT_STATUS_NOT_RUN,
        STATUS_NOT_SUPPORTED,
        "Load/unload loop",
        "External SCM/load test required for repeated load, unload and UI open/close.");
    KswordARKPreflightAddCheck(
        Builder,
        KSWORD_ARK_PREFLIGHT_CHECK_R3_DEGRADED_UI,
        KSWORD_ARK_PREFLIGHT_STATUS_NOT_RUN,
        STATUS_NOT_SUPPORTED,
        "R3 degraded UI",
        "R3 build is intentionally skipped in current unattended driver-only pass.");
}

NTSTATUS
KswordARKPreflightQuery(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_QUERY_PREFLIGHT_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    构造发布前驱动自检响应。中文说明：该响应只报告驱动内可观察状态；不能在
    内核中验证的发布门槛显式返回 NotRun，避免误导发布流程。

Arguments:

    OutputBuffer - 输出缓冲。
    OutputBufferLength - 输出缓冲长度。
    Request - 可选请求。
    BytesWrittenOut - 接收写入字节数。

Return Value:

    STATUS_SUCCESS 或缓冲/参数错误。

--*/
{
    KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE* response = NULL;
    KSWORD_ARK_PREFLIGHT_BUILDER builder;
    KSW_DYN_STATE dynState;
    KSWORD_ARK_QUERY_SAFETY_POLICY_RESPONSE safetyState;
    KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE monitorState;
    KSWORD_ARK_QUERY_IMAGE_TRUST_REQUEST trustRequest;
    KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE trustState;
    size_t bytesWritten = 0U;
    ULONG requestFlags = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (OutputBuffer == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < KSWORD_ARK_PREFLIGHT_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (Request != NULL &&
        Request->size != 0UL &&
        (Request->size < sizeof(KSWORD_ARK_QUERY_PREFLIGHT_REQUEST) ||
         Request->version != KSWORD_ARK_PREFLIGHT_PROTOCOL_VERSION)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    RtlZeroMemory(&builder, sizeof(builder));
    RtlZeroMemory(&dynState, sizeof(dynState));
    RtlZeroMemory(&safetyState, sizeof(safetyState));
    RtlZeroMemory(&monitorState, sizeof(monitorState));
    RtlZeroMemory(&trustRequest, sizeof(trustRequest));
    RtlZeroMemory(&trustState, sizeof(trustState));

    response = (KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE*)OutputBuffer;
    response->size = (ULONG)KSWORD_ARK_PREFLIGHT_RESPONSE_HEADER_SIZE;
    response->version = KSWORD_ARK_PREFLIGHT_PROTOCOL_VERSION;
    response->overallStatus = KSWORD_ARK_PREFLIGHT_STATUS_UNKNOWN;
    response->entrySize = sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY);
    response->buildConfiguration = KswordARKPreflightBuildConfiguration();
    response->targetArchitecture = KswordARKPreflightTargetArchitecture();
    response->ioctlRegistryCount = KswordARKGetRegisteredIoctlCount();
    response->ioctlDuplicateCount = KswordARKGetDuplicateIoctlCount();

    builder.Response = response;
    builder.Capacity = (ULONG)((OutputBufferLength - KSWORD_ARK_PREFLIGHT_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY));
    builder.WorstStatus = KSWORD_ARK_PREFLIGHT_STATUS_PASS;

    KswordARKPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_DRIVER_BUILD,
        (response->targetArchitecture == KSWORD_ARK_PREFLIGHT_ARCH_X64) ? KSWORD_ARK_PREFLIGHT_STATUS_PASS : KSWORD_ARK_PREFLIGHT_STATUS_WARN,
        STATUS_SUCCESS,
        "Driver build",
#if DBG
        "Debug driver build is loaded; Release is required for public release.");
#else
        "Release driver build is loaded.");
#endif

    KswordARKPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_OS_BUILD_SUPPORT,
        KswordArkStartupIsOsBuildSupported()
            ? KSWORD_ARK_PREFLIGHT_STATUS_PASS
            : KSWORD_ARK_PREFLIGHT_STATUS_FAIL,
        KswordArkStartupIsOsBuildSupported()
            ? STATUS_SUCCESS
            : STATUS_NOT_SUPPORTED,
        "OS build support",
        KswordArkStartupIsOsBuildSupported()
            ? "OS build is inside the validated DynData range."
            : "OS build is outside the validated DynData range; offset-dependent IOCTLs are disabled.");

    KswordARKDynDataSnapshot(&dynState);
    response->dynDataCapabilityMask = dynState.CapabilityMask;
    response->dynDataLastStatus = dynState.LastStatus;
    response->dynDataStatusFlags = 0UL;
    if (dynState.Initialized) {
        response->dynDataStatusFlags |= KSW_DYN_STATUS_FLAG_INITIALIZED;
    }
    if (dynState.NtosActive) {
        response->dynDataStatusFlags |= KSW_DYN_STATUS_FLAG_NTOS_ACTIVE;
    }
    if (dynState.LxcoreActive) {
        response->dynDataStatusFlags |= KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE;
    }
    if (dynState.ExtraActive) {
        response->dynDataStatusFlags |= KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE;
    }
    if (dynState.PdbProfileActive) {
        response->dynDataStatusFlags |= KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE;
    }
    response->fieldFlags |= KSWORD_ARK_PREFLIGHT_FIELD_DYNDATA_PRESENT;
    KswordARKPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_DYNDATA_TOLERANCE,
        dynState.Initialized ? (dynState.NtosActive ? KSWORD_ARK_PREFLIGHT_STATUS_PASS : KSWORD_ARK_PREFLIGHT_STATUS_WARN) : KSWORD_ARK_PREFLIGHT_STATUS_FAIL,
        dynState.LastStatus,
        "DynData tolerance",
        dynState.NtosActive ? "DynData ntos profile active." : "Driver must still load when DynData profile is missing.");

    response->fieldFlags |= KSWORD_ARK_PREFLIGHT_FIELD_IOCTL_REGISTRY;
    KswordARKPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_IOCTL_REGISTRY,
        (response->ioctlRegistryCount != 0UL && response->ioctlDuplicateCount == 0UL) ? KSWORD_ARK_PREFLIGHT_STATUS_PASS : KSWORD_ARK_PREFLIGHT_STATUS_FAIL,
        (response->ioctlDuplicateCount == 0UL) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_COLLISION,
        "IOCTL registry",
        "Central registry is enumerable and duplicate control codes are checked.");

    status = KswordARKSafetyQueryPolicy(&safetyState, sizeof(safetyState), &bytesWritten);
    if (NT_SUCCESS(status) && bytesWritten >= sizeof(safetyState)) {
        response->fieldFlags |= KSWORD_ARK_PREFLIGHT_FIELD_SAFETY_POLICY;
        response->safetyPolicyFlags = safetyState.policyFlags;
        response->safetyPolicyGeneration = safetyState.policyGeneration;
    }
    KswordARKPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_SAFETY_POLICY,
        (NT_SUCCESS(status) &&
            (safetyState.policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_ACTIVE) != 0UL &&
            (safetyState.policyFlags & KSWORD_ARK_SAFETY_POLICY_FLAG_DENY_CRITICAL_PROCESS) != 0UL) ?
            KSWORD_ARK_PREFLIGHT_STATUS_PASS : KSWORD_ARK_PREFLIGHT_STATUS_FAIL,
        status,
        "Safety policy",
        "Dangerous operations are routed through central policy with critical PID denial.");

    status = KswordARKFileMonitorQueryStatus(&monitorState, sizeof(monitorState), &bytesWritten);
    if (NT_SUCCESS(status) && bytesWritten >= sizeof(monitorState)) {
        response->fieldFlags |= KSWORD_ARK_PREFLIGHT_FIELD_FILE_MONITOR;
        response->fileMonitorRuntimeFlags = monitorState.runtimeFlags;
        response->fileMonitorQueuedCount = monitorState.queuedCount;
        response->fileMonitorDroppedCount = monitorState.droppedCount;
        response->fileMonitorRegisterStatus = monitorState.registerStatus;
        response->fileMonitorStartStatus = monitorState.startStatus;
    }
    KswordARKPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_FILE_MONITOR,
        (NT_SUCCESS(status) && NT_SUCCESS(monitorState.registerStatus)) ? KSWORD_ARK_PREFLIGHT_STATUS_PASS : KSWORD_ARK_PREFLIGHT_STATUS_WARN,
        NT_SUCCESS(status) ? monitorState.registerStatus : status,
        "File monitor",
        "Minifilter registration status is reported; StartFiltering is intentionally IOCTL-controlled.");

    trustRequest.flags = KSWORD_ARK_TRUST_QUERY_FLAG_INCLUDE_GLOBAL_CI;
    status = KswordARKDriverQueryImageTrust(&trustState, sizeof(trustState), &trustRequest, &bytesWritten);
    if (NT_SUCCESS(status) && bytesWritten >= sizeof(trustState)) {
        response->fieldFlags |= KSWORD_ARK_PREFLIGHT_FIELD_TRUST_CI;
        response->trustFieldFlags = trustState.fieldFlags;
        response->codeIntegrityOptions = trustState.codeIntegrityOptions;
        response->codeIntegrityStatus = trustState.codeIntegrityStatus;
        response->secureBootEnabled = trustState.secureBootEnabled;
        response->secureBootCapable = trustState.secureBootCapable;
    }
    KswordARKPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_CODE_INTEGRITY,
        ((trustState.fieldFlags & KSWORD_ARK_TRUST_FIELD_GLOBAL_CI_PRESENT) != 0UL) ? KSWORD_ARK_PREFLIGHT_STATUS_PASS : KSWORD_ARK_PREFLIGHT_STATUS_WARN,
        NT_SUCCESS(status) ? trustState.codeIntegrityStatus : status,
        "Code Integrity",
        "Global Code Integrity options are exposed for release diagnostics.");
    KswordARKPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_SIGNING_PIPELINE,
        KSWORD_ARK_PREFLIGHT_STATUS_NOT_RUN,
        STATUS_NOT_SUPPORTED,
        "Signing pipeline",
        "Build can skip signing here; final Visual Studio/signing pipeline must sign the driver.");

    requestFlags = (Request == NULL || Request->flags == 0UL) ? 0UL : Request->flags;
    if ((requestFlags & KSWORD_ARK_PREFLIGHT_QUERY_FLAG_INCLUDE_EXTERNAL_GATES) != 0UL) {
        response->fieldFlags |= KSWORD_ARK_PREFLIGHT_FIELD_EXTERNAL_GATES;
        KswordARKPreflightAddExternalGateChecks(&builder);
    }

    KswordARKPreflightAddCheck(
        &builder,
        KSWORD_ARK_PREFLIGHT_CHECK_OBJECT_LIFETIME,
        KSWORD_ARK_PREFLIGHT_STATUS_PASS,
        STATUS_SUCCESS,
        "Object lifetime",
        "Preflight confirms modules expose explicit cleanup paths; static review still required before release.");

    response->totalCheckCount = builder.Total;
    response->returnedCheckCount = builder.Returned;
    response->overallStatus = builder.WorstStatus;
    response->size = (ULONG)(KSWORD_ARK_PREFLIGHT_RESPONSE_HEADER_SIZE + ((size_t)builder.Returned * sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY)));
    *BytesWrittenOut = response->size;
    return STATUS_SUCCESS;
}
