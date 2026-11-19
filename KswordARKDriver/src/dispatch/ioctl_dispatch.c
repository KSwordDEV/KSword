/*++

Module Name:

    ioctl_dispatch.c

Abstract:

    Thin IOCTL dispatch for the default queue. Business behavior is implemented
    in feature-owned handler files registered through ioctl_registry.c.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ioctl_registry.h"
#include "ark/ark_storage_controller.h"
#include "../features/bugcheck/bugcheck_evidence.h" // 统一记录最近真实 IOCTL 事件，不访问普通日志 ring。
#include "ioctl_dispatch.tmh"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
KswordARKDispatchLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one dispatch-level log line. Feature-specific details are
    logged in each handler; dispatch logs routing and unsupported-control cases.

Arguments:

    Device - WDF device that owns the log channel.
    LevelText - Log level string.
    FormatText - printf-style ANSI message template.
    ... - Template arguments.

Return Value:

    None. Formatting or enqueue failures are ignored so completion still occurs.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), FormatText, arguments))) {
        (void)KswordARKDriverEnqueueLogFrame(Device, LevelText, logMessage);
    }
    va_end(arguments);
}

// OS build 上限白名单防护已停用；连同辅助函数注释，避免未引用函数告警。
// static BOOLEAN
// KswordARKIsSafeOnUnsupportedOsBuild(
//     _In_ ULONG IoControlCode
//     )
// {
//     switch (IoControlCode) {
//     case IOCTL_KSWORD_ARK_QUERY_PREFLIGHT:
//     case IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY:
//         return TRUE;
//     default:
//         return FALSE;
//     }
// }

VOID
KswordARKDriverDispatchDeviceControl(
    _In_ WDFDEVICE Device,
    _In_opt_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
/*++

Routine Description:

    Route IRP_MJ_DEVICE_CONTROL requests to a registered feature handler. The
    dispatch layer owns lookup, completion, and common tracing only.

Arguments:

    Queue - Handle to the queue object.
    Request - Handle to a framework request object.
    OutputBufferLength - Size of output buffer in bytes.
    InputBufferLength - Size of input buffer in bytes.
    IoControlCode - I/O control code.

Return Value:

    None. The request is completed unless a handler returns STATUS_PENDING.

--*/
{
    const KSWORD_ARK_IOCTL_ENTRY* ioctlEntry = NULL;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t completeBytes = 0;

    /* Resolve the endpoint role before anything can read the primary context.
     * Controller FDOs own independent queues, resources, and audit records. */
    ioctlEntry = KswordARKLookupIoctlEntry(IoControlCode);
    if (KswordARKStorageControllerIsDevice(Device)) {
        if (ioctlEntry == NULL || ioctlEntry->Handler == NULL ||
            (ioctlEntry->Flags & KSWORD_ARK_IOCTL_FLAG_CONTROLLER_ONLY) == 0UL) {
            WdfRequestCompleteWithInformation(Request, STATUS_INVALID_DEVICE_REQUEST, 0U);
            return;
        }
        status = ioctlEntry->Handler(Device, Request, InputBufferLength,
            OutputBufferLength, &completeBytes);
        if (status != STATUS_PENDING) {
            WdfRequestCompleteWithInformation(Request, status, completeBytes);
        }
        return;
    }
    if (ioctlEntry != NULL &&
        (ioctlEntry->Flags & KSWORD_ARK_IOCTL_FLAG_CONTROLLER_ONLY) != 0UL) {
        WdfRequestCompleteWithInformation(Request, STATUS_INVALID_DEVICE_REQUEST, 0U);
        return;
    }
    if (!KswordARKDriverCoreEnterRequest()) {
        WdfRequestCompleteWithInformation(Request, STATUS_DELETE_PENDING, 0U);
        return;
    }

    TraceEvents(
        TRACE_LEVEL_INFORMATION,
        TRACE_QUEUE,
        "%!FUNC! Queue 0x%p, Request 0x%p OutputBufferLength %d InputBufferLength %d IoControlCode %d",
        Queue,
        Request,
        (int)OutputBufferLength,
        (int)InputBufferLength,
        IoControlCode);

    /*
     * Previous build-envelope policy (disabled below):
     * The client is not a trust boundary.  On a build outside the validated
     * DynData envelope, do not let any caller reach an offset-dependent
     * handler.  Keep only the static registry and preflight evidence paths
     * available so the caller can diagnose why the rest is unavailable.
     */
    // OS build 上限分发防护已停用；继续执行下方逐功能能力检查。
    // if (!KswordArkStartupIsOsBuildSupported() &&
    //     !KswordARKIsSafeOnUnsupportedOsBuild(IoControlCode)) {
    //     KswordARKDispatchLog(
    //         Device,
    //         "Warn",
    //         "IOCTL denied: OS build is outside supported range, code=0x%08X, status=0x%08X.",
    //         (unsigned int)IoControlCode,
    //         (unsigned int)STATUS_NOT_SUPPORTED);
    //     KswordARKCapabilityRecordLastError(
    //         STATUS_NOT_SUPPORTED,
    //         "ioctl_dispatch",
    //         "OS build is outside the validated DynData range; offset-dependent IOCTLs are disabled.");
    //     WdfRequestCompleteWithInformation(
    //         Request,
    //         STATUS_NOT_SUPPORTED,
    //         0U);
    //     return;
    // }

    if (ioctlEntry == NULL || ioctlEntry->Handler == NULL) {
        KswordARKDispatchLog(Device, "Warn", "Unsupported ioctl=0x%08X.", (unsigned int)IoControlCode);
        WdfRequestCompleteWithInformation(Request, status, completeBytes);
        KswordARKDriverCoreLeaveRequest();
        return;
    }

    if (!KswordARKCapabilityIsIoctlAllowed(ioctlEntry->RequiredCapability, &status)) {
        KswordARKDispatchLog(
            Device,
            "Warn",
            "IOCTL denied by capability gate: name=%s, code=0x%08X, required=0x%I64X, status=0x%08X.",
            ioctlEntry->Name != NULL ? ioctlEntry->Name : "<unnamed>",
            (unsigned int)ioctlEntry->IoControlCode,
            ioctlEntry->RequiredCapability,
            (unsigned int)status);
        KswordARKCapabilityRecordLastError(status, "ioctl_dispatch", "IOCTL denied by DynData capability gate.");
        WdfRequestCompleteWithInformation(Request, status, completeBytes);
        KswordARKDriverCoreLeaveRequest();
        return;
    }

    KswordARKBugcheckTraceRecord( // 先提交 BEGIN，handler 或后续上下文采集内部崩溃也保留操作身份。
        KSWORD_BUGCHECK_TRACE_KIND_IOCTL_BEGIN, // 区分请求开始与实际 handler 返回。
        IoControlCode, // 保留注册表实际请求编号。
        STATUS_PENDING, // 开始阶段尚无返回值，trace 模块会标记 STATUS_UNAVAILABLE。
        ioctlEntry->Name, // 注册表名称为只读内核文本，NULL 仍保留其他字段。
        KSWORD_BUGCHECK_EVIDENCE_EVENT_TEXT); // 只允许读取最多 64 字节摘要。
    KswordARKBugcheckContextOperation(); // 仅在正常 PASSIVE 上下文采集最近操作栈，崩溃端只读缓存。
    status = ioctlEntry->Handler(Device, Request, InputBufferLength, OutputBufferLength, &completeBytes);
    if (!NT_SUCCESS(status) || // 失败的返回始终保留，不由普通日志开关决定。
        (ioctlEntry->Flags & (KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS | KSWORD_ARK_IOCTL_FLAG_QUIET_COMPLETION)) == 0UL) { // 安静轮询只省略成功返回。
        KswordARKBugcheckTraceRecord( // END 表示 handler 返回；STATUS_PENDING 不等同异步完成。
            KSWORD_BUGCHECK_TRACE_KIND_IOCTL_END, // 明确保存返回类别。
            IoControlCode, // 与 BEGIN 共用真实请求编号。
            status, // 原样保存 handler NTSTATUS，不从文字推断失败。
            ioctlEntry->Name, // 保存与开始一致的有界请求名称。
            KSWORD_BUGCHECK_EVIDENCE_EVENT_TEXT); // 摘要由固定非分页 ring 截断并标记。
    } // 最近事件镜像结束，继续既有日志与 WDF 完成路径。
    if ((ioctlEntry->Flags & KSWORD_ARK_IOCTL_FLAG_QUIET_COMPLETION) == 0UL &&
        !((ioctlEntry->Flags & KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS) != 0UL &&
        (NT_SUCCESS(status) || status == STATUS_PENDING)) &&
        !((ioctlEntry->Flags & KSWORD_ARK_IOCTL_FLAG_QUIET_INVALID_CID) != 0UL &&
        status == STATUS_INVALID_CID)) {
        KswordARKDispatchLog(
            Device,
            NT_SUCCESS(status) || status == STATUS_PENDING ? "Info" : "Warn",
            "IOCTL complete: name=%s, code=0x%08X, status=0x%08X, in=%Iu, out=%Iu, bytes=%Iu.",
            ioctlEntry->Name != NULL ? ioctlEntry->Name : "<unnamed>",
            (unsigned int)ioctlEntry->IoControlCode,
            (unsigned int)status,
            InputBufferLength,
            OutputBufferLength,
            completeBytes);
    }

    if (status != STATUS_PENDING) {
        WdfRequestCompleteWithInformation(Request, status, completeBytes);
    }
    KswordARKDriverCoreLeaveRequest();
}

VOID
KswordARKDriverEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    KswordARKDriverDispatchDeviceControl(
        WdfIoQueueGetDevice(Queue),
        Queue,
        Request,
        OutputBufferLength,
        InputBufferLength,
        IoControlCode);
}
