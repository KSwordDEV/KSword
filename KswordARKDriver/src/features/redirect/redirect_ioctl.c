/*++

Module Name:

    redirect_ioctl.c

Abstract:

    IOCTL handlers for KswordARK file and registry redirection rules.

Environment:

    Kernel-mode Driver Framework

--*/

#include "redirect_internal.h" // 文件规则需要按本次请求进程的 DOS namespace 解析盘符。
#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h" // 大型固定规则请求的快照必须离开有限的内核栈。

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_REDIRECT_IOCTL_TAG_SNAPSHOT 0x7352734BUL // sRsK：规则请求快照的独立池标签。

static VOID
KswordARKRedirectIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    输出重定向 IOCTL 日志。中文说明：只记录规则数量和状态码，不记录完整路径，
    避免敏感路径进入日志通道。

Arguments:

    Device - WDF 设备对象。
    LevelText - 日志级别。
    FormatText - printf 风格格式串。
    ... - 格式化参数。

Return Value:

    None. 本函数没有返回值。

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), FormatText, arguments))) {
        (VOID)KswordARKDriverEnqueueLogFrame(Device, LevelText, logMessage);
    }
    va_end(arguments);
}

NTSTATUS
KswordARKRedirectIoctlSetRules(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_REDIRECT_SET_RULES。中文说明：规则修改需要写权限，后端
    完成完整校验与快照替换。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 WDF 请求。
    InputBufferLength - 输入长度。
    OutputBufferLength - 输出长度。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from validation or backend.

--*/
{
    KSWORD_ARK_REDIRECT_SET_RULES_REQUEST* setRequest = NULL;
    // 完整请求超过 33KB；快照放在非分页池，不能作为 IOCTL 线程的局部栈结构。
    KSWORD_ARK_REDIRECT_SET_RULES_REQUEST* requestSnapshot = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        KswordARKRedirectIoctlLog(Device, "Warn", "R0 redirect set-rules denied, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_REDIRECT_SET_RULES_REQUEST),
        (PVOID*)&setRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKRedirectIoctlLog(Device, "Error", "R0 redirect set-rules input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED 的输入和输出是同一个 SystemBuffer；后端会先
     * RtlZeroMemory 输出再按 ruleCount 遍历并拷贝 rules[]，不做快照就会
     * 把响应头字节当规则数和重定向路径装进运行时表。
     */
    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKRedirectIoctlLog(Device, "Error", "R0 redirect set-rules output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    requestSnapshot = (KSWORD_ARK_REDIRECT_SET_RULES_REQUEST*)KswordARKAllocateNonPagedPool(
        sizeof(*requestSnapshot), KSWORD_ARK_REDIRECT_IOCTL_TAG_SNAPSHOT); // 完整 METHOD_BUFFERED 请求以池副本保持稳定。
    if (requestSnapshot == NULL) { // 不能建立独立快照时不得进入会改配置或清零共用输入的后端。
        return STATUS_INSUFFICIENT_RESOURCES; // 旧规则和完成字节数保持不变。
    }
    RtlCopyMemory(requestSnapshot, setRequest, sizeof(*requestSnapshot)); // 输出尚未写入，先复制全部已验证容量的输入。
    if (requestSnapshot->action == KSWORD_ARK_REDIRECT_ACTION_REPLACE &&
        requestSnapshot->ruleCount <= KSWORD_ARK_REDIRECT_MAX_RULES) { // 仅处理完整容量内的启用文件规则。
        ULONG index; // 本次规则下标。
        for (index = 0UL; index < requestSnapshot->ruleCount; ++index) { // 先解析全部名字再交给原子发布后端。
            KSWORD_ARK_REDIRECT_RULE* rule = &requestSnapshot->rules[index]; // 固定池快照中规则。
            if (rule->type != KSWORD_ARK_REDIRECT_TYPE_FILE ||
                (rule->flags & KSWORD_ARK_REDIRECT_RULE_FLAG_ENABLED) == 0UL) continue; // 不改变注册表路径。
            status = KswordARKRedirectNormalizeFilePath(rule->sourcePath); // DOS source 转为设备全名。
            if (NT_SUCCESS(status)) status = KswordARKRedirectNormalizeFilePath(rule->targetPath); // 目标使用同一 namespace。
            if (!NT_SUCCESS(status)) { // 解析失败保持原有规则，不发布部分新表。
                ExFreePoolWithTag(requestSnapshot, KSWORD_ARK_REDIRECT_IOCTL_TAG_SNAPSHOT); // 释放独立输入快照。
                return status; // 返回确切名字解析失败。
            }
        }
    }
    setRequest = requestSnapshot; // 后端与响应日志期间均使用独立且不可被 SystemBuffer 覆盖的快照。

    status = KswordARKRedirectSetRules(
        setRequest,
        outputBuffer,
        actualOutputLength,
        BytesReturned);
    if (NT_SUCCESS(status) && *BytesReturned >= sizeof(KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE)) {
        KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE* response =
            (KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE*)outputBuffer;
        KswordARKRedirectIoctlLog(
            Device,
            response->status == KSWORD_ARK_REDIRECT_STATUS_APPLIED ? "Info" : "Warn",
            "R0 redirect set-rules status=%lu file=%lu registry=%lu last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->fileRuleCount,
            (unsigned long)response->registryRuleCount,
            (unsigned int)response->lastStatus);
    }

    ExFreePoolWithTag(requestSnapshot, KSWORD_ARK_REDIRECT_IOCTL_TAG_SNAPSHOT); // 所有后端成功/失败结果都归还唯一池快照。
    return status;
}

NTSTATUS
KswordARKRedirectIoctlQueryStatus(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_REDIRECT_QUERY_STATUS。中文说明：返回当前规则快照、命中
    计数和 registry callback 注册状态。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 WDF 请求。
    InputBufferLength - 输入长度。
    OutputBufferLength - 输出长度。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from output retrieval or backend.

--*/
{
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_REDIRECT_STATUS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKRedirectIoctlLog(Device, "Error", "R0 redirect status output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKRedirectQueryStatus(
        outputBuffer,
        actualOutputLength,
        BytesReturned);
    if (NT_SUCCESS(status) && *BytesReturned >= sizeof(KSWORD_ARK_REDIRECT_STATUS_RESPONSE)) {
        KSWORD_ARK_REDIRECT_STATUS_RESPONSE* response =
            (KSWORD_ARK_REDIRECT_STATUS_RESPONSE*)outputBuffer;
        KswordARKRedirectIoctlLog(
            Device,
            "Info",
            "R0 redirect status flags=0x%08X file=%lu registry=%lu.",
            (unsigned int)response->runtimeFlags,
            (unsigned long)response->fileRuleCount,
            (unsigned long)response->registryRuleCount);
    }

    return status;
}
