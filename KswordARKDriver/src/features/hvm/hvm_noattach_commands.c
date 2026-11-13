#include "hvm_noattach.h"

NTSTATUS KswordARKHvmNoAttachEditStopped(const KSWORD_ARK_HVM_NOATTACH_REQUEST *Request)
{
    /* 普通控制锁已经串行化所有命令，CAS 另防根模式更新停点。 */
    NTSTATUS status;
    /* 修改必须消费确切的当前停止身份。 */
    if (Request->stopId == 0ULL ||
        InterlockedCompareExchange(&g_KswordNoAttach.State, KSW_NOATTACH_COMMAND_RESERVING,
                                   KSWORD_ARK_HVM_NOATTACH_STOPPED) != KSWORD_ARK_HVM_NOATTACH_STOPPED)
    { return STATUS_INVALID_DEVICE_STATE; }
    /* 占用以后再检查 ID，不能出现 STOPPED 状态的 ABA。 */
    if (Request->stopId != g_KswordNoAttach.Snapshot.stopId)
    {
        /* 退出通知如果已经撤销，不得恢复旧 STOPPED。 */
        (void)InterlockedCompareExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_STOPPED,
                                         KSW_NOATTACH_COMMAND_RESERVING);
        /* 明确拒绝旧停止授权。 */
        return STATUS_REVISION_MISMATCH;
    }
    /* 寄存器编辑不借用 Windows 的运行中线程上下文。 */
    if (Request->operation == KSWORD_ARK_HVM_NOATTACH_SET_GPR)
    {
        /* 只支持完整声明的整数寄存器，不接收 flags/DR/SIMD。 */
        if (Request->registerMask == 0ULL ||
            (Request->registerMask & ~KSWORD_ARK_HVM_NOATTACH_GPR_MASK) != 0ULL ||
            ((Request->registerMask & (1ULL << 15)) != 0ULL &&
             (Request->registers.rip == 0ULL || Request->registers.rip > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress)) ||
            ((Request->registerMask & (1ULL << 16)) != 0ULL &&
             (Request->registers.rsp == 0ULL || Request->registers.rsp > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress)))
        {
            /* 验证失败保持原停点与全部原寄存器。 */
            status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            /* 发布前完全复制请求，根模式不再访问 IOCTL 缓冲区。 */
            g_KswordNoAttach.PendingRegisters = Request->registers;
            /* mask 与寄存器属于同一份待提交命令。 */
            g_KswordNoAttach.PendingRegisterMask = Request->registerMask;
            /* 发布 CAS 是根模式读取值的 acquire/release 屏障。 */
            if (InterlockedCompareExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING,
                                           KSW_NOATTACH_COMMAND_RESERVING) != KSW_NOATTACH_COMMAND_RESERVING)
            { return STATUS_CANCELLED; }
            /* 只有匹配的真实取指才能报告 CONTEXT 停止；ACK 不代表已提交。 */
            return KswordARKHvmNoAttachRendezvous(KswordARKHvmGetRuntime());
        }
    }
    else
    {
        /* 双 bank 原子安装完整配置，旧 bank 仅在全核屏障后重用。 */
        status = KswordARKHvmNoAttachEditBreakpoint(Request);
        /* RUN_TO 只有安装成功才消费停点，安装失败仍停在原现场。 */
        if (NT_SUCCESS(status) && Request->operation == KSWORD_ARK_HVM_NOATTACH_RUN_TO)
        {
            /* 异步退出撤销不能被继续命令覆盖。 */
            if (InterlockedCompareExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_CONTINUE_PENDING,
                                           KSW_NOATTACH_COMMAND_RESERVING) != KSW_NOATTACH_COMMAND_RESERVING)
            { return STATUS_CANCELLED; }
            /* 继续仍要在下一次目标取指复核原停止上下文。 */
            return KswordARKHvmNoAttachRendezvous(KswordARKHvmGetRuntime());
        }
    }
    /* 仅非执行编辑保留当前停点，恢复失败状态不会被覆盖。 */
    (void)InterlockedCompareExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_STOPPED,
                                     KSW_NOATTACH_COMMAND_RESERVING);
    /* 返回真实配置/参数验证结果。 */
    return status;
}
