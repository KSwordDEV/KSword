#include "kernel_noattach.h"
#include <ntstrsafe.h>
#include "ark/ark_log.h"
/* 发起者取自原始 IRP，不是派发工作线程。 */
NTKERNELAPI ULONG IoGetRequestorProcessId(PIRP Irp);
/* 同一份 R0/R3 布局必须保持定宽。 */
C_ASSERT(sizeof(KSWORD_ARK_KERNEL_NOATTACH_REQUEST) == 232);
/* 完整停止文档不允许截断。 */
C_ASSERT(sizeof(KSWORD_ARK_KERNEL_NOATTACH_RESPONSE) == 480);

NTSTATUS KswordARKKernelIoctlNoAttach(WDFDEVICE Device, WDFREQUEST Request, size_t InputBufferLength,
                                    size_t OutputBufferLength, size_t *BytesReturned)
{
    /* BUFFERED 输入输出共享内存，先保存请求。 */
    KSWORD_ARK_KERNEL_NOATTACH_REQUEST copy;
    /* 只使用 WDF 验证的地址。 */
    PVOID input = NULL, output = NULL;
    /* 框架和派发器长度分别核对。 */
    size_t inputBytes = 0U, outputBytes = 0U;
    /* 保留每一步真实错误。 */
    NTSTATUS status;
    /* 没有完成计数不能进入业务。 */
    if (BytesReturned == NULL) { return STATUS_INVALID_PARAMETER; }
    /* 所有拒绝默认零字节。 */
    *BytesReturned = 0U;
    /* 帧绑定、引用与上下文只从普通用户请求进入。 */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || WdfRequestGetRequestorMode(Request) != UserMode)
    { return STATUS_ACCESS_DENIED; }
    /* 只允许主控制设备有确切 Cleanup 语义的文件。 */
    if (WdfRequestGetFileObject(Request) == WDF_NO_HANDLE ||
        KswordARKHvmNoAttachFileContext(WdfRequestGetFileObject(Request)) == NULL) { return STATUS_INVALID_HANDLE; }
    /* 先取完整输入。 */
    status = WdfRequestRetrieveInputBuffer(Request, sizeof(copy), &input, &inputBytes);
    /* 不访问截断成员。 */
    if (!NT_SUCCESS(status)) { return status; }
    /* 拒绝未知尾部或错误 ABI。 */
    if (InputBufferLength != sizeof(copy) || inputBytes < sizeof(copy)) { return STATUS_INFO_LENGTH_MISMATCH; }
    /* 响应清零不会覆盖输入身份。 */
    RtlCopyMemory(&copy, input, sizeof(copy));
    /* 取完整固定响应。 */
    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(KSWORD_ARK_KERNEL_NOATTACH_RESPONSE), &output, &outputBytes);
    /* 不把缓冲失败改成业务成功。 */
    if (!NT_SUCCESS(status)) { return status; }
    /* 停止文档一次完整返回。 */
    if (OutputBufferLength < sizeof(KSWORD_ARK_KERNEL_NOATTACH_RESPONSE) || outputBytes < sizeof(KSWORD_ARK_KERNEL_NOATTACH_RESPONSE))
    { return STATUS_BUFFER_TOO_SMALL; }
    /* 安装内核异常消费者使用现有的内核补丁策略。 */
    if (copy.operation == KSWORD_ARK_HVM_NOATTACH_OPEN)
    {
        /* 策略上下文明确说明本次修改。 */
        KSWORD_ARK_SAFETY_CONTEXT safety = {0};
        /* 不伪装成只读内存操作。 */
        safety.Operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        /* 确认必须属于本次 OPEN。 */
        safety.ContextFlags = (copy.flags & KSWORD_ARK_HVM_NOATTACH_CONFIRMED) != 0UL ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED : 0UL;
        /* 文本是固定生命周期审计说明。 */
        safety.TargetText = L"Version-bound kernel exception consumer and boot-resident bridge";
        /* 长度不包括终止符。 */
        safety.TargetTextChars = (USHORT)(RTL_NUMBER_OF(L"Version-bound kernel exception consumer and boot-resident bridge") - 1U);
        /* 拒绝时不运行任何内核代码修改。 */
        status = KswordARKSafetyEvaluate(Device, &safety);
        /* 原样保留策略拒绝。 */
        if (!NT_SUCCESS(status)) { return status; }
    }
    /* 固定协议转交独立普通驱动实现。 */
    status = KswordARKKernelNoAttachControl(&copy, (KSWORD_ARK_KERNEL_NOATTACH_RESPONSE *)output,
        IoGetRequestorProcessId(WdfRequestWdmGetIrp(Request)), WdfRequestGetFileObject(Request));
    /* 关闭后的诊断在请求线程中格式化，不能增加目标异常路径的锁与分配。 */
    if (copy.operation == KSWORD_ARK_HVM_NOATTACH_CLOSE)
    {
        /* 不包含目标代码或用户数据，只记录消费判断的实际字段。 */
        CHAR message[256];
        /* 观察计数和状态分别呈现，不能把进入转接器当成停止完成。 */
        if (NT_SUCCESS(RtlStringCbPrintfA(message, sizeof(message),
            "Kernel no-attach trace: events=%ld code=%08lX mode=%lu first=%lu irql=%lu hardwareDr6=%I64X frameDr6=%I64X flags=%I64X",
            g_Kna.TargetEvents, g_Kna.LastCode, g_Kna.LastMode, g_Kna.LastChance, g_Kna.LastIrql,
            g_Kna.LastHardwareDr6, g_Kna.LastFrameDr6, g_Kna.LastFlags)))
        {
            /* 诊断失败不影响真实关闭结果。 */
            (void)KswordARKDriverEnqueueLogFrame(Device, "Info", message);
        }
    }
    /* 只在控制请求返回后记录失败，异常消费者不做格式化或日志分配。 */
    if (NT_SUCCESS(status) && !NT_SUCCESS(((KSWORD_ARK_KERNEL_NOATTACH_RESPONSE *)output)->status))
    {
        /* 固定长度日志不包含目标内存或不受限的调用方文本。 */
        CHAR message[192];
        /* 同一状态码必须附上实际原生阶段和冻结的目标身份。 */
        if (NT_SUCCESS(RtlStringCbPrintfA(message, sizeof(message),
            "Kernel no-attach op=%lu pid=%lu tid=%lu phase=%s status=0x%08lX ownSuspend=%u ownTf=%u",
            copy.operation, copy.processId, copy.threadId, g_Kna.NativePhase != NULL ? g_Kna.NativePhase : "preflight",
            (ULONG)((KSWORD_ARK_KERNEL_NOATTACH_RESPONSE *)output)->status,
            (unsigned int)g_Kna.OwnSuspend, (unsigned int)g_Kna.OwnTf)))
        {
            /* 审计日志失败不能改写原控制请求的真实结果。 */
            (void)KswordARKDriverEnqueueLogFrame(Device, "Warn", message);
        }
    }
    /* 传输成功后语义结果位于固定响应内。 */
    if (NT_SUCCESS(status)) { *BytesReturned = sizeof(KSWORD_ARK_KERNEL_NOATTACH_RESPONSE); }
    /* 统一派发器完成请求。 */
    return status;
}
