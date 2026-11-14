#include "kernel_noattach.h"

/* 当前观察者归还以后，控制面才能释放会话的帧缓冲区。 */
static VOID KnaLeaveObserver(VOID)
{
    /* 帧写入先于完成发布。 */
    KeMemoryBarrier();
    /* 一个目标线程在同一时间只有一个权威异常现场。 */
    InterlockedExchange(&g_Kna.Observer, 0L);
    /* 等待者按实际完成信号恢复，不依赖固定宽限期。 */
    KeSetEvent(&g_Kna.ObserverIdle, IO_NO_INCREMENT, FALSE);
}

/* 寄存器位顺序只在这里与规范请求映射一次。 */
static VOID KnaEditRegisters(PCONTEXT Context, const KSWORD_ARK_KERNEL_NOATTACH_REQUEST *Request)
{
    /* 普通整数寄存器不通过跨结构指针运算访问。 */
#define KNA_SET(bit, lower, upper) /* 只写请求明确选择的字段。 */ \
    if ((Request->registerMask & (1ULL << (bit))) != 0ULL) { Context->upper = Request->registers.lower; }
    /* 前十五位与公共保存帧相同。 */
    KNA_SET(0, rax, Rax); KNA_SET(1, rcx, Rcx); KNA_SET(2, rdx, Rdx); KNA_SET(3, rbx, Rbx);
    /* 非易失寄存器同样保留完整位宽。 */
    KNA_SET(4, rbp, Rbp); KNA_SET(5, rsi, Rsi); KNA_SET(6, rdi, Rdi);
    /* 不截断高位整数寄存器。 */
    KNA_SET(7, r8, R8); KNA_SET(8, r9, R9); KNA_SET(9, r10, R10); KNA_SET(10, r11, R11);
    /* 与 Windows CONTEXT 布局无关的显式投影。 */
    KNA_SET(11, r12, R12); KNA_SET(12, r13, R13); KNA_SET(13, r14, R14); KNA_SET(14, r15, R15);
    /* 控制地址在控制面已经限定为用户空间。 */
    KNA_SET(15, rip, Rip); KNA_SET(16, rsp, Rsp);
    /* 页面不能借此编辑 TF、DR 或 XSTATE。 */
#undef KNA_SET
}

BOOLEAN KnaObserve(PEXCEPTION_RECORD Record, PVOID Exception, PVOID Trap, KPROCESSOR_MODE Mode, BOOLEAN FirstChance)
{
    /* 高于 DISPATCH_LEVEL 不做帧转换、加锁或任何等待。 */
    KIRQL entryIrql = KeGetCurrentIrql();
    /* 捕获与关闭共享短锁，不跨等待持有。 */
    KIRQL irql;
    /* TF 与硬件断点原因分别核对。 */
    BOOLEAN ownTf, handled = FALSE;
    /* 公开原因只来自真实捕获。 */
    ULONG hit, reason, id = 0UL;
    /* 当前会话的唯一活动上下文。 */
    PCONTEXT context;
    /* 未初始化、无会话或不支持的异常阶段保持原分发。 */
    if (g_Kna.Initialized != 2L || !FirstChance || entryIrql > DISPATCH_LEVEL || Record == NULL)
    { return FALSE; }
    /* 只以强对象身份判断线程，不比较可能复用的 CPU/PID。 */
    KeAcquireSpinLock(&g_Kna.StateLock, &irql);
    /* 普通目标异常只有自有 TF 尚未完成时才需要取消步进。 */
    if (!g_Kna.Owned || g_Kna.Thread != PsGetCurrentThread() || g_Kna.Observer != 0L ||
        (Record->ExceptionCode != STATUS_SINGLE_STEP && !g_Kna.OwnTf))
    { KeReleaseSpinLock(&g_Kna.StateLock, irql); return FALSE; }
    /* 从这里到 LeaveObserver，Close 不得释放 Context。 */
    InterlockedExchange(&g_Kna.Observer, 1L);
    /* 完成事件直到这次处理真正离开才重新置位。 */
    KeClearEvent(&g_Kna.ObserverIdle);
    /* 同一个缓冲区只由这个目标线程写入。 */
    context = g_Kna.Context;
    /* 普通上下文 API 使用另一份 Capture，不覆盖这里。 */
    KeReleaseSpinLock(&g_Kna.StateLock, irql);
    /* 仅请求当前实现保证的整数、控制和调试组。 */
    RtlZeroMemory(context, sizeof(*context));
    /* 不要求未提供的 SIMD/XSTATE 扩展区。 */
    context->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    /* 由当前内核自己的帧转换处理非易失寄存器。 */
    KnaReadFrames(Trap, Exception, context);
    /* 真实 DR 原因和私有 TF 所有权在短锁内一起核对。 */
    KeAcquireSpinLock(&g_Kna.StateLock, &irql);
    /* BS 是单步原因，不是任意 #DB 都属于本会话。 */
    ownTf = g_Kna.OwnTf && (context->Dr6 & 0x4000ULL) != 0ULL;
    /* 精确 RIP、DR6 和地址槽必须同时匹配。 */
    hit = KnaHit(context);
    /* 同时发生的外部 DR/GD 原因必须保留原异常分发。 */
    {
        /* 本方地址槽只按真实记录和当前地址值认定。 */
        ULONGLONG ownedMask = 0ULL;
        /* 固定四槽，不查询其它线程。 */
        const ULONGLONG addresses[4] = {context->Dr0, context->Dr1, context->Dr2, context->Dr3};
        /* 未由本方占用的原因不能随 TF 一起吞掉。 */
        for (ULONG i = 0UL; i < 4UL; ++i)
        { if (g_Kna.Rows[i].id != 0UL && addresses[i] == g_Kna.Rows[i].address) { ownedMask |= 1ULL << i; } }
        /* 只在真实单步异常上核对混合来源。 */
        if (Record->ExceptionCode == STATUS_SINGLE_STEP && ((context->Dr6 & (0xFULL & ~ownedMask)) != 0ULL ||
            (context->Dr6 & 0x2000ULL) != 0ULL))
        {
            /* 退休本方的 TF，但保留其它硬件原因。 */
            if (ownTf) { context->EFlags &= ~0x100UL; context->Dr6 = (context->Dr6 & ~0x4000ULL) | (g_Kna.BaselineDr[4] & 0x4000ULL); g_Kna.OwnTf = FALSE; }
            /* 不报告单步完成。 */
            g_Kna.State = KSWORD_ARK_HVM_NOATTACH_INTERRUPTED;
            /* 转换不能在自旋锁内调用。 */
            KeReleaseSpinLock(&g_Kna.StateLock, irql);
            /* 当前线程提交自己所做的清理。 */
            KnaWriteFrames(Trap, Exception, context, CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS, Mode);
            /* 恢复原事件链。 */
            KnaLeaveObserver();
            /* 原分发器仍会处理外部异常。 */
            return FALSE;
        }
    }
    /* 其它真实异常不能被当作一次单步完成。 */
    if (Record->ExceptionCode != STATUS_SINGLE_STEP)
    {
        /* 只撤销本方安排的 TF，让原异常继续由 Windows 处理。 */
        if (g_Kna.OwnTf) { context->EFlags &= ~0x100UL; g_Kna.OwnTf = FALSE; g_Kna.State = KSWORD_ARK_HVM_NOATTACH_INTERRUPTED; }
        /* 不消费 AV、断点或任何非本方异常。 */
        KeReleaseSpinLock(&g_Kna.StateLock, irql);
        /* 修改发生在当前线程，不能从控制工作线程写错 DebugActive。 */
        KnaWriteFrames(Trap, Exception, context, CONTEXT_CONTROL, Mode);
        /* 原异常将由原始分发器继续执行。 */
        KnaLeaveObserver();
        /* FALSE 要求保持原异常链。 */
        return FALSE;
    }
    /* 既不属于自有 TF 也不属于自己的 DR 槽时完全转发。 */
    if (!ownTf && hit == 0UL)
    { KeReleaseSpinLock(&g_Kna.StateLock, irql); KnaLeaveObserver(); return FALSE; }
    /* 清除的只是本方生成的 TF/BS，不修改原生 debug port。 */
    if (ownTf)
    {
        /* 原始 TF 在首次捕获时已确认未设置。 */
        context->EFlags &= ~0x100UL;
        /* 恢复基线原有的 BS 状态，不抹掉其它真实原因。 */
        context->Dr6 = (context->Dr6 & ~0x4000ULL) | (g_Kna.BaselineDr[4] & 0x4000ULL);
        /* 该次期待只消费一次。 */
        g_Kna.OwnTf = FALSE;
    }
    /* 本后端只发布用户态线程停止；内核边界只取消自己的步进。 */
    if (Mode != UserMode || entryIrql > APC_LEVEL || g_Kna.Closing)
    {
        /* 关闭必须恢复自己的 DR，内核步进中断不伪造用户停点。 */
        if (g_Kna.Closing) { KnaApplyDebug(context, TRUE); }
        /* 没有停止身份就不能宣称一次用户单步完成。 */
        g_Kna.State = g_Kna.Closing ? KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED : KSWORD_ARK_HVM_NOATTACH_INTERRUPTED;
        /* 在调用帧转换前恢复原 IRQL。 */
        KeReleaseSpinLock(&g_Kna.StateLock, irql);
        /* 只消费确实属于本会话的原因。 */
        KnaWriteFrames(Trap, Exception, context, CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS, Mode);
        /* 真正回写完成才允许收尾。 */
        KnaLeaveObserver();
        /* 关闭完成是一次真实进展，可以唤醒已经超时的收尾。 */
        if (g_Kna.Closing) { KnaRevoke(); }
        /* 本方生成的异常不继续抛给未附加的用户程序。 */
        return TRUE;
    }
    /* 带栈深过滤的命中只在对应调用层级停止。 */
    if (!ownTf && hit != 0UL && (g_Kna.Rows[hit - 1UL].flags & KSWORD_ARK_HVM_NOATTACH_BP_STACK_FILTER) != 0UL &&
        context->Rsp < g_Kna.Rows[hit - 1UL].minimumRsp)
    {
        /* RF 只跳过当前执行比较，不占另一地址槽或修改代码。 */
        context->EFlags |= 0x10000UL;
        /* 不把过滤掉的地址报告成停点。 */
        KeReleaseSpinLock(&g_Kna.StateLock, irql);
        /* 当前线程自己提交恢复状态。 */
        KnaWriteFrames(Trap, Exception, context, CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS, Mode);
        /* 没有生成停止文档。 */
        KnaLeaveObserver();
        /* 精确属于本方的 DR 事件由本方消费。 */
        return TRUE;
    }
    /* 硬件命中优先保留实际断点身份。 */
    reason = hit != 0UL ? KSWORD_ARK_HVM_NOATTACH_STOP_BREAKPOINT :
        (g_Kna.State == KSWORD_ARK_HVM_NOATTACH_PAUSE_PENDING || g_Kna.State == KNA_ARMING
            ? KSWORD_ARK_HVM_NOATTACH_STOP_FETCH : KSWORD_ARK_HVM_NOATTACH_STOP_STEP);
    /* 一次性消费不删除另一个地址的断点。 */
    if (hit != 0UL)
    {
        /* 保存真实公开 ID。 */
        id = g_Kna.Rows[hit - 1UL].id;
        /* 一次性资格在实际命中时才消费。 */
        if ((g_Kna.Rows[hit - 1UL].flags & KSWORD_ARK_HVM_NOATTACH_BP_ONESHOT) != 0UL)
        { g_Kna.Rows[hit - 1UL].flags |= KSWORD_ARK_HVM_NOATTACH_BP_CONSUMED; }
    }
    /* 目标暂停期间没有控制命令残留。 */
    g_Kna.Action = 0UL;
    /* 在发布前清理上一次唤醒信号，快速新命令不会被随后清掉。 */
    KeClearEvent(&g_Kna.ContinueEvent);
    /* 一次性禁用等调试状态先由当前线程实际提交。 */
    KnaApplyDebug(context, FALSE);
    /* 帧转换不在自旋锁内做。 */
    KeReleaseSpinLock(&g_Kna.StateLock, irql);
    /* 当前线程的 DebugActive 只能由它自己的转换路径更新。 */
    KnaWriteFrames(Trap, Exception, context, CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS, Mode);
    /* 完整现场回写之后才发布可消费 stopId。 */
    KeAcquireSpinLock(&g_Kna.StateLock, &irql);
    /* 关闭与发布竞争时关闭优先。 */
    if (!g_Kna.Closing) { KnaPublish(context, reason, id); }
    /* 所有者/租约收尾仍能唤醒目标。 */
    KeReleaseSpinLock(&g_Kna.StateLock, irql);
    /* 非 alertable 的内核等待，不停止整个系统。 */
    for (;;)
    {
        /* 短超时用于检查租约和退出，不做忙轮询。 */
        LARGE_INTEGER timeout;
        /* 在短锁内冻结一次明确命令。 */
        ULONG action;
        /* 命令数据在接收时已经完整复制。 */
        KSWORD_ARK_KERNEL_NOATTACH_REQUEST command;
        /* 检查关闭和租约，不等待前端无限维持失联停点。 */
        KeAcquireSpinLock(&g_Kna.StateLock, &irql);
        /* 失联自动归还本会话状态。 */
        if (!g_Kna.Closing && KeQueryInterruptTime() > g_Kna.LeaseDeadline) { InterlockedExchange(&g_Kna.Closing, 1L); }
        /* 关闭始终优先于尚未提交的执行命令。 */
        action = g_Kna.Closing ? KSWORD_ARK_HVM_NOATTACH_CLOSE : g_Kna.Action;
        /* 原子消费一次命令。 */
        g_Kna.Action = 0UL;
        /* 当前已冻结的值不访问调用方缓冲区。 */
        command = g_Kna.Pending;
        /* 等待期间不持有自旋锁。 */
        KeReleaseSpinLock(&g_Kna.StateLock, irql);
        /* 没有命令时系统和其它线程继续执行。 */
        if (action == 0UL)
        {
            /* 百毫秒级唤醒只是租约检查，不是模拟单步。 */
            timeout.QuadPart = -1000000LL;
            /* 快速命令的事件信号会保持到本次等待消费。 */
            (void)KeWaitForSingleObject(&g_Kna.ContinueEvent, Executive, KernelMode, FALSE, &timeout);
            /* 回到真实命令检查。 */
            continue;
        }
        /* 关闭不让目标带着本会话的 TF/DR 返回。 */
        if (action == KSWORD_ARK_HVM_NOATTACH_CLOSE)
        {
            /* 恢复基线不会覆盖已由外部工具改变的其它槽。 */
            KnaApplyDebug(context, TRUE);
            /* 本方 TF 在入口已经消费。 */
            context->EFlags &= ~0x100UL;
            /* 在原异常线程实际回写。 */
            KnaWriteFrames(Trap, Exception, context, CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS, Mode);
            /* 文件失联和租约到期都安排同一条异步清理。 */
            KnaRevoke();
            /* 归还当前异常现场。 */
            handled = TRUE;
            /* 离开等待，不假造成功的单步。 */
            break;
        }
        /* 整数写入不能改变 TF/DR/XSTATE。 */
        if (action == KSWORD_ARK_HVM_NOATTACH_SET_GPR) { KnaEditRegisters(context, &command); }
        /* 行配置从同一份权威记录产生真实 DR 状态。 */
        KnaApplyDebug(context, FALSE);
        /* 配置或 GPR 修改后继续保持真实停止。 */
        if (action == KSWORD_ARK_HVM_NOATTACH_ADD_BREAKPOINT || action == KSWORD_ARK_HVM_NOATTACH_REMOVE_BREAKPOINT ||
            action == KSWORD_ARK_HVM_NOATTACH_SET_GPR)
        {
            /* 修改完成由目标线程自己回写。 */
            KnaWriteFrames(Trap, Exception, context, CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS, Mode);
            /* 新文档与配置提交在同一个短锁内完成。 */
            KeAcquireSpinLock(&g_Kna.StateLock, &irql);
            /* 实际提交后才去掉 Pending，并退休已删除 ID。 */
            for (ULONG i = 0UL; i < 4UL; ++i)
            {
                /* 不把已接受配置冒充已安装。 */
                g_Kna.Rows[i].flags &= ~KSWORD_ARK_KERNEL_NOATTACH_BP_PENDING;
                /* 删除只退休确切 ID，一次性历史仍可查看。 */
                if (action == KSWORD_ARK_HVM_NOATTACH_REMOVE_BREAKPOINT && g_Kna.Rows[i].id == command.breakpointId)
                { RtlZeroMemory(&g_Kna.Rows[i], sizeof(g_Kna.Rows[i])); }
            }
            /* 先清旧信号，再发布新 stopId，避免丢掉快速 Continue。 */
            KeClearEvent(&g_Kna.ContinueEvent);
            /* 关闭竞争不能复活 STOPPED。 */
            if (!g_Kna.Closing) { KnaPublish(context, KSWORD_ARK_HVM_NOATTACH_STOP_CONTEXT, 0UL); }
            /* 调度和等待不持自旋锁。 */
            KeReleaseSpinLock(&g_Kna.StateLock, irql);
            /* 回到同一真实异常持有者的等待。 */
            continue;
        }
        /* 执行类动作只恢复当前匹配停点。 */
        KeAcquireSpinLock(&g_Kna.StateLock, &irql);
        /* 命中地址需要 RF 跳过一次当前执行比较。 */
        for (ULONG i = 0UL; i < 4UL; ++i)
        {
            /* 同一地址的下一次真实到达仍会命中。 */
            if (g_Kna.Rows[i].id != 0UL && g_Kna.Rows[i].address == context->Rip) { context->EFlags |= 0x10000UL; }
            /* RUN_TO 配置在放行前已经实际武装。 */
            g_Kna.Rows[i].flags &= ~KSWORD_ARK_KERNEL_NOATTACH_BP_PENDING;
        }
        /* TF 只在显式 STEP 请求下设置。 */
        if (action == KSWORD_ARK_HVM_NOATTACH_STEP) { context->EFlags |= 0x100UL; g_Kna.OwnTf = TRUE; g_Kna.State = KSWORD_ARK_HVM_NOATTACH_STEP_PENDING; }
        /* Continue/RunTo 不使用伪造的 Windows 调试事件。 */
        else { context->EFlags &= ~0x100UL; g_Kna.State = KSWORD_ARK_HVM_NOATTACH_RUNNING; }
        /* 解除短锁后提交当前线程的完整整数现场。 */
        KeReleaseSpinLock(&g_Kna.StateLock, irql);
        /* 真实恢复后才结束此次异常处理。 */
        KnaWriteFrames(Trap, Exception, context, CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS, Mode);
        /* 已经由本方完整处理的 #DB。 */
        handled = TRUE;
        /* 单步完成会由下一次真实异常报告。 */
        break;
    }
    /* 目标上下文已经回写，控制面现在才能退休引用。 */
    KnaLeaveObserver();
    /* TRUE 只用于确实消费的自有调试异常。 */
    return handled;
}
