#include "hvm_noattach.h"
#include <ntstrsafe.h>
#include "ark/ark_log.h"
/* 用户态和内核态的固定宽度 ABI 必须一致。 */
C_ASSERT(sizeof(KSWORD_ARK_HVM_NOATTACH_REQUEST) == 232);
/* 完整停止现场及八条配置不能被编译选项改变。 */
C_ASSERT(sizeof(KSWORD_ARK_HVM_NOATTACH_RESPONSE) == 480);

/* wdm.h 内联声明可能因 include 顺序不可见，同 debugger_ioctl.c。 */
NTKERNELAPI ULONG IoGetRequestorProcessId(_In_ PIRP Irp);

/* 唯一 WDF 入口只转交固定协议，所有执行语义由独立模块拥有。 */
NTSTATUS KswordARKHvmIoctlNoAttach(WDFDEVICE Device, WDFREQUEST Request, size_t InputBufferLength,
                                   size_t OutputBufferLength, size_t *BytesReturned)
{
    /* METHOD_BUFFERED 输入输出共享 SystemBuffer，必须先复制固定请求。 */
    KSWORD_ARK_HVM_NOATTACH_REQUEST copy;
    /* 由 KMDF 验证完整输入地址。 */
    PVOID input = NULL, output = NULL;
    /* 同时核对派发器长度和框架实际长度。 */
    size_t inputBytes = 0U, outputBytes = 0U;
    /* 保留每一步框架错误。 */
    NTSTATUS status;
    /* IRP 保留真实发起者，不能使用派发线程当前所在的进程。 */
    PIRP irp = WdfRequestWdmGetIrp(Request);
    /* 控制面不借用设备的业务上下文。 */
    UNREFERENCED_PARAMETER(Device);
    /* 每个拒绝路径都报告零完成字节。 */
    if (BytesReturned == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* 初始化唯一完成计数。 */
    *BytesReturned = 0U;
    /* 身份引用、控制锁与生命周期工作只能从普通 PASSIVE_LEVEL 请求进入。 */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* 新执行后端只接受普通用户调用者，不接收伪造 kernel 请求身份。 */
    if (WdfRequestGetRequestorMode(Request) != UserMode)
    {
        return STATUS_ACCESS_DENIED;
    }
    /* 没有文件对象就没有可撤销的会话所有者。 */
    if (WdfRequestGetFileObject(Request) == WDF_NO_HANDLE)
    {
        return STATUS_INVALID_HANDLE;
    }
    /* 其它 FDO 没有本通道的 Closing 上下文，不得从共享注册表误接此会话。 */
    if (KswordARKHvmNoAttachFileContext(WdfRequestGetFileObject(Request)) == NULL)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    /* 无原始请求身份时不得建立会话。 */
    if (irp == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* 取回固定宽度输入。 */
    status = WdfRequestRetrieveInputBuffer(Request, sizeof(copy), &input, &inputBytes);
    /* 拒绝截断协议以后才读任何成员。 */
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* 输入长度必须完整。 */
    if (InputBufferLength != sizeof(copy) || inputBytes < sizeof(copy))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    /* 后续清响应不会覆盖本次操作身份。 */
    RtlCopyMemory(&copy, input, sizeof(copy));
    /* 取回完整固定响应。 */
    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(KSWORD_ARK_HVM_NOATTACH_RESPONSE), &output,
                                            &outputBytes);
    /* 保留框架缓冲区错误。 */
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* 不允许截断停止现场。 */
    if (OutputBufferLength < sizeof(KSWORD_ARK_HVM_NOATTACH_RESPONSE) ||
        outputBytes < sizeof(KSWORD_ARK_HVM_NOATTACH_RESPONSE))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    /* owner 来自 WDF requestor，而不是输入的 PID。 */
    status = KswordARKHvmNoAttachControl(&copy, (KSWORD_ARK_HVM_NOATTACH_RESPONSE *)output,
                                         IoGetRequestorProcessId(irp), WdfRequestGetFileObject(Request));
    /* 仅普通控制面格式化最后的真实 TF 边界诊断，root 不调用日志通道。 */
    if (copy.operation == KSWORD_ARK_HVM_NOATTACH_CLOSE && g_KswordNoAttach.UseTf)
    {
        /* 固定预算不包含任何目标用户数据。 */
        CHAR message[384];
        /* 所有值均来自本会话的实际 VMCS 读取，而非停止快照推导。 */
        if (NT_SUCCESS(RtlStringCbPrintfA(message, sizeof(message),
            "HVM no-attach TF trace: arm=%lu pre=%lu exit=%lu retries=%lu qual=%I64X info=%I64X pin=%I64X exits=%I64X entry=%I64X vector=%I64X pending=%I64X block=%I64X flags=%I64X dr7=%I64X debug=%I64X",
            g_KswordNoAttach.TfArmStage, g_KswordNoAttach.TfPrecheckReject, g_KswordNoAttach.TfExitReason,
            g_KswordNoAttach.TfRetryCount,
            g_KswordNoAttach.TfExitQualification, g_KswordNoAttach.TfExitInfo,
            g_KswordNoAttach.TfBoundary[0], g_KswordNoAttach.TfBoundary[1], g_KswordNoAttach.TfBoundary[2],
            g_KswordNoAttach.TfBoundary[3], g_KswordNoAttach.TfBoundary[4], g_KswordNoAttach.TfBoundary[5],
            g_KswordNoAttach.TfBoundary[6], g_KswordNoAttach.TfBoundary[7], g_KswordNoAttach.TfBoundary[8])))
        {
            /* 诊断日志失败不改变已确认的关闭结果。 */
            (void)KswordARKDriverEnqueueLogFrame(Device, "Info", message);
        }
    }
    /* 通信成功时返回完整固定文档，语义 NTSTATUS 留在响应内。 */
    if (NT_SUCCESS(status))
    {
        *BytesReturned = sizeof(KSWORD_ARK_HVM_NOATTACH_RESPONSE);
    }
    /* 派发器统一完成请求。 */
    return status;
}
