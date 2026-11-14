#include "kernel_noattach.h"

/* 六个 Windows 调试字段在本目标 ABI 中连续，但写入地址槽仍逐个选择。 */
C_ASSERT(FIELD_OFFSET(CONTEXT, Dr7) - FIELD_OFFSET(CONTEXT, Dr0) == 5 * sizeof(ULONGLONG));

/* 公共文档只发布明确支持的整数寄存器。 */
VOID KnaPublish(PCONTEXT Context, ULONG Reason, ULONG BreakpointId)
{
    /* 调用者持 StateLock，当前线程仍处于真实异常处理者中。 */
    KSWORD_ARK_KERNEL_NOATTACH_RESPONSE *s = &g_Kna.Snapshot;
    /* 零始终表示没有可消费的停点。 */
    if (++g_Kna.StopCounter == 0ULL) { ++g_Kna.StopCounter; }
    /* 新代次与完整上下文作为一个停止发布。 */
    s->stopId = g_Kna.StopCounter;
    /* 原因区分主动暂停、TF、DR 与修改提交。 */
    s->stopReason = Reason;
    /* 命中 ID 不复用旧列表行身份。 */
    s->breakpointId = BreakpointId;
    /* 控制字段来自当前用户上下文。 */
    s->rip = Context->Rip; s->rsp = Context->Rsp; s->rflags = Context->EFlags;
    /* 该普通后端不伪造 VMCS/CR3 现场。 */
    s->cr3 = 0ULL;
    /* 显式映射避免 CONTEXT 中 RSP 插在通用寄存器之间造成错位。 */
    s->rax = Context->Rax; s->rcx = Context->Rcx; s->rdx = Context->Rdx; s->rbx = Context->Rbx;
    /* 完整保存其余非易失和易失整数寄存器。 */
    s->rbp = Context->Rbp; s->rsi = Context->Rsi; s->rdi = Context->Rdi;
    /* 不以界面指针宽度裁剪数值。 */
    s->r8 = Context->R8; s->r9 = Context->R9; s->r10 = Context->R10; s->r11 = Context->R11;
    /* 这些值仍来自同一次真实异常。 */
    s->r12 = Context->R12; s->r13 = Context->R13; s->r14 = Context->R14; s->r15 = Context->R15;
    /* 寄存器写完后才公开停止状态。 */
    g_Kna.State = KSWORD_ARK_HVM_NOATTACH_STOPPED;
    /* 每次真实停点都给控制器足够租约；Query 可续期。 */
    g_Kna.LeaseDeadline = KeQueryInterruptTime() + 300000000ULL;
}

NTSTATUS KnaRequestPause(VOID)
{
    /* Native API 不在 StateLock 内调用。 */
    ULONG previous = 0UL;
    /* 状态、挂起和上下文失败分别返回。 */
    NTSTATUS status;
    /* 短锁只决定能否接受新的请求。 */
    KIRQL irql;
    /* 驱动自己只增加一次挂起计数。 */
    KeAcquireSpinLock(&g_Kna.StateLock, &irql);
    /* 已有真实停点或已排队暂停保持幂等。 */
    if (g_Kna.State == KSWORD_ARK_HVM_NOATTACH_STOPPED || g_Kna.State == KSWORD_ARK_HVM_NOATTACH_PAUSE_PENDING)
    { KeReleaseSpinLock(&g_Kna.StateLock, irql); return STATUS_SUCCESS; }
    /* 不把运行中的另一命令替换为新的暂停。 */
    if (g_Kna.State != KSWORD_ARK_HVM_NOATTACH_RUNNING && g_Kna.State != KSWORD_ARK_HVM_NOATTACH_INTERRUPTED)
    { KeReleaseSpinLock(&g_Kna.StateLock, irql); return STATUS_INVALID_DEVICE_STATE; }
    /* 在挂起前声明短暂预约，真实 #DB 到达后才会 STOPPED。 */
    g_Kna.State = KNA_ARMING;
    /* 允许异常处理者并行完成已发生的硬件命中。 */
    KeReleaseSpinLock(&g_Kna.StateLock, irql);
    /* 此函数的 PETHREAD ABI 已按目标内核核对。 */
    g_Kna.NativePhase = "suspend";
    /* 阶段身份先于实际调用，便于区分相同的原生错误。 */
    status = g_Kna.Suspend(g_Kna.Thread, &previous);
    /* 失败不会制造自有挂起。 */
    if (!NT_SUCCESS(status)) { goto Failed; }
    /* 从这里起 Close 必须配平这一次计数。 */
    g_Kna.OwnSuspend = TRUE;
    /* 不能接管其它工具已经暂停的线程。 */
    if (previous != 0UL) { status = STATUS_DEVICE_BUSY; goto Resume; }
    /* 上下文缓冲区在 OPEN 时对齐分配。 */
    RtlZeroMemory(g_Kna.Capture, sizeof(*g_Kna.Capture));
    /* 只请求实际要核对的控制和调试字段。 */
    g_Kna.Capture->ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    /* 捕获前已经取得自己的挂起计数。 */
    g_Kna.NativePhase = "get-context";
    /* 捕获失败保留该阶段供控制面审计。 */
    status = g_Kna.GetContext(g_Kna.Thread, g_Kna.Capture, KernelMode);
    /* API 失败保留真实错误。 */
    if (!NT_SUCCESS(status)) { goto Resume; }
    /* 不把 WOW64、内核现场或已有 TF 解释为自己的用户单步。 */
    if ((g_Kna.Capture->SegCs & 3U) != 3U || g_Kna.Capture->Rip > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress ||
        (g_Kna.Capture->EFlags & 0x100UL) != 0UL)
    { status = STATUS_NOT_SUPPORTED; goto Resume; }
    /* 首次暂停前保留所有原始调试槽；不抢占外部调试器。 */
    if (!g_Kna.BaselineValid)
    {
        /* GD 和任何已启用的地址槽都不属于本会话。 */
        if ((g_Kna.Capture->Dr7 & 0x20FFULL) != 0ULL) { status = STATUS_DEVICE_BUSY; goto Resume; }
        /* Windows CONTEXT 的六个调试字段由同一 ABI 定义。 */
        RtlCopyMemory(g_Kna.BaselineDr, &g_Kna.Capture->Dr0, sizeof(g_Kna.BaselineDr));
        /* 只有完整捕获才公开基线。 */
        g_Kna.BaselineValid = TRUE;
    }
    /* 与已经到达的硬件停点或关闭请求重新核对。 */
    KeAcquireSpinLock(&g_Kna.StateLock, &irql);
    /* 已经停止时不用再设置一次 TF。 */
    if (g_Kna.State != KNA_ARMING || g_Kna.Closing)
    { KeReleaseSpinLock(&g_Kna.StateLock, irql); status = g_Kna.Closing ? STATUS_CANCELLED : STATUS_SUCCESS; goto Resume; }
    /* 在放行之前先建立明确的异常消费所有权。 */
    g_Kna.OwnTf = TRUE;
    /* 用户看到的是等待，不能提前发布寄存器停点。 */
    g_Kna.State = KSWORD_ARK_HVM_NOATTACH_PAUSE_PENDING;
    /* 解除短锁后调用可能等待 APC 的原生 API。 */
    KeReleaseSpinLock(&g_Kna.StateLock, irql);
    /* 设置 TF 仅是触发条件，真正消费者是已安装的异常后端。 */
    g_Kna.Capture->EFlags |= 0x100UL;
    /* 初始暂停不重写捕获到的 DR，避免扩大本次修改范围。 */
    g_Kna.Capture->ContextFlags = CONTEXT_CONTROL;
    /* 不写入目标代码或注册目标内 VEH。 */
    g_Kna.NativePhase = "set-initial-tf";
    /* 不把原生设置失败误报为挂起失败。 */
    status = g_Kna.SetContext(g_Kna.Thread, g_Kna.Capture, KernelMode);
    /* 设置失败时撤销自己的期待，不把旧现场当成新停点。 */
    if (!NT_SUCCESS(status)) { g_Kna.OwnTf = FALSE; goto Resume; }
    /* 关闭若在设置期间到来，在线程仍暂停时回滚本次 TF。 */
    if (g_Kna.Closing)
    {
        /* 这里只归还本次加入的 TF，原基线已确认 TF=0。 */
        g_Kna.Capture->EFlags &= ~0x100UL;
        /* 恢复失败保留自有挂起与会话，供 Close 重试。 */
        g_Kna.NativePhase = "rollback-initial-tf";
        /* 回滚失败必须与首次设置失败分别呈现。 */
        status = g_Kna.SetContext(g_Kna.Thread, g_Kna.Capture, KernelMode);
        /* 不能在未知 TF 状态下放弃所有权。 */
        if (!NT_SUCCESS(status)) { return status; }
        /* 已完成原位回滚。 */
        g_Kna.OwnTf = FALSE;
    }
Resume:
    /* 只恢复自己取得的一次计数。 */
    if (g_Kna.OwnSuspend)
    {
        /* 返回的旧计数用于核对实际恢复。 */
        ULONG count = 0UL;
        /* 保留 Resume 的真实结果。 */
        NTSTATUS resumed = g_Kna.Resume(g_Kna.Thread, &count);
        /* 失败绝不丢弃尚需恢复的责任。 */
        if (!NT_SUCCESS(resumed) || count == 0UL)
        { g_Kna.NativePhase = "resume"; return NT_SUCCESS(resumed) ? STATUS_INVALID_DEVICE_STATE : resumed; }
        /* 精确归还完毕后才清理计数。 */
        g_Kna.OwnSuspend = FALSE;
    }
Failed:
    /* 未安排成功的请求不能留在无限等待状态。 */
    if (!NT_SUCCESS(status))
    {
        /* 与真实异常停点竞争时保留停点。 */
        KeAcquireSpinLock(&g_Kna.StateLock, &irql);
        /* 只退休仍由本次请求占用的状态。 */
        if (g_Kna.State == KNA_ARMING || (g_Kna.State == KSWORD_ARK_HVM_NOATTACH_PAUSE_PENDING && !g_Kna.OwnTf))
        { g_Kna.State = KSWORD_ARK_HVM_NOATTACH_RUNNING; }
        /* 恢复普通 IRQL。 */
        KeReleaseSpinLock(&g_Kna.StateLock, irql);
    }
    /* 请求接受与停止完成仍是两件事。 */
    return status;
}

NTSTATUS KnaRestoreThread(VOID)
{
    /* 退出线程不会再次执行用户代码，不对已退出对象排 APC。 */
    if (PsIsThreadTerminating(g_Kna.Thread)) { g_Kna.OwnTf = FALSE; g_Kna.OwnSuspend = FALSE; return STATUS_SUCCESS; }
    /* 在途自有 TF 由关闭态异常消费者清理，不能丢失旧 #DB。 */
    if (g_Kna.OwnTf || g_Kna.Observer) { return STATUS_PENDING; }
    /* 没有基线和自有暂停意味着从未改变目标状态。 */
    if (!g_Kna.BaselineValid && !g_Kna.OwnSuspend) { return STATUS_SUCCESS; }
    /* 普通 API 不在自旋锁内运行。 */
    ULONG previous = 0UL;
    /* 每个恢复阶段保留单独结果。 */
    NTSTATUS status = STATUS_SUCCESS;
    /* 只在没有异常处理者持有目标时短暂停止读取。 */
    if (!g_Kna.OwnSuspend)
    {
        /* 增加一次计数，原有外部挂起仍保留。 */
        status = g_Kna.Suspend(g_Kna.Thread, &previous);
        /* 失败不会伪报恢复。 */
        if (!NT_SUCCESS(status)) { return status; }
        /* 明确记录自己的恢复责任。 */
        g_Kna.OwnSuspend = TRUE;
    }
    /* 捕获最新控制/调试状态，不覆盖其它工具的普通寄存器。 */
    RtlZeroMemory(g_Kna.Capture, sizeof(*g_Kna.Capture));
    /* 不请求或改写 GPR/SIMD。 */
    g_Kna.Capture->ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    /* 当前线程已由自己的计数保证不执行用户指令。 */
    status = g_Kna.GetContext(g_Kna.Thread, g_Kna.Capture, KernelMode);
    /* 只清理仍由自己拥有的调试字段。 */
    if (NT_SUCCESS(status))
    {
        /* 已发生而未进入消费者的 DR 命中先放行到关闭态消费者。 */
        if (KnaHit(g_Kna.Capture) != 0UL) { status = STATUS_PENDING; }
        else
        {
            /* 并发外部改动不被无条件写回旧基线。 */
            KnaApplyDebug(g_Kna.Capture, TRUE);
            /* 只提交调试组，保留最新的 RIP/RSP 和外部控制状态。 */
            g_Kna.Capture->ContextFlags = CONTEXT_DEBUG_REGISTERS;
            /* 真实恢复失败时保留会话引用供重试。 */
            status = g_Kna.SetContext(g_Kna.Thread, g_Kna.Capture, KernelMode);
        }
    }
    /* 只归还本次增加的计数，不能清空外部暂停。 */
    if (NT_SUCCESS(status) || status == STATUS_PENDING)
    {
        /* 每次精确恢复都有可核对的旧计数。 */
        ULONG count = 0UL;
        /* 不能忽略恢复失败。 */
        NTSTATUS resumed = g_Kna.Resume(g_Kna.Thread, &count);
        /* 计数未配平时保留责任。 */
        if (!NT_SUCCESS(resumed) || count == 0UL) { return NT_SUCCESS(resumed) ? STATUS_INVALID_DEVICE_STATE : resumed; }
        /* 恢复成功才释放自有计数。 */
        g_Kna.OwnSuspend = FALSE;
    }
    /* PENDING 表示还必须等真实消费者确认，不等于已经关闭。 */
    return status;
}
