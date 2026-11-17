#include "hvm_noattach.h"
#include "hvm_vmcs.h"

/* 绝不使用调用方控制的配置位构造 EPT 指针。 */
#define KSW_NA_FRAME 0x000FFFFFFFFFF000ULL
/* MTF 属于主要处理器控制，独立于来宾 RFLAGS.TF。 */
#define KSW_NA_MTF (1UL << 27)

/* 读取一个体系结构字段，不查询 Windows 状态。 */
static BOOLEAN NaRead(ULONG Field, ULONGLONG *Value)
{
    /* 既有 VMCS 抽象按原生指针宽度执行 VMREAD。 */
    SIZE_T result = 0U;
    /* 字段读取失败时，绝不发布未初始化的值。 */
    if (KswordARKHvmVmcsFieldLoad(Field, &result) != 0U)
    {
        return FALSE;
    }
    /* 仅在成功后完成定宽转换。 */
    *Value = (ULONGLONG)result;
    /* 报告完整的体系结构读取。 */
    return TRUE;
}

/* 在不可变根表间切换；缓存转换仍绑定各自 EPTP。 */
static BOOLEAN NaRoot(ULONGLONG Eptp)
{
    /* 现有指针已指向所需根表时保持不变。 */
    ULONGLONG current = 0ULL;
    /* 零根表不可能是安全的 VM-entry 目标。 */
    if (Eptp == 0ULL || !NaRead(0x201AUL, &current))
    {
        return FALSE;
    }
    /* 重复停止取指时，避免对相同值重复执行 VMWRITE。 */
    if (current == Eptp)
    {
        return TRUE;
    }
    /* 每个根表都在常驻前完成构建与核对。 */
    return KswordARKHvmVmcsFieldStore(0x201AUL, (SIZE_T)Eptp) == 0U;
}

/* MTF 仍保留原行为；显式 TF 备用路径单独管理临时状态。 */
static BOOLEAN NaMtf(KSW_HVM_RESIDENT_VCPU *Context, BOOLEAN Enable)
{
    /* 缺少 MTF 的来宾使用明确报告的 VMX TF 边界。 */
    if (g_KswordNoAttach.UseTf) { return KswordARKHvmNoAttachTfEnable(Context, Enable); }
    /* 保留所有无关的主要处理器控制。 */
    ULONGLONG controls = 0ULL;
    /* 拒绝不完整的控制读取。 */
    if (!NaRead(0x4002UL, &controls))
    {
        return FALSE;
    }
    /* 只清除或设置 MTF 位。 */
    controls = Enable ? (controls | KSW_NA_MTF) : (controls & ~(ULONGLONG)KSW_NA_MTF);
    /* 完整控制更新成功后才允许 VM-entry。 */
    return KswordARKHvmVmcsFieldStore(0x4002UL, (SIZE_T)controls) == 0U;
}

/* 事件投递边界或既有来宾调试状态都不能算作普通单步。 */
static BOOLEAN NaStepBoundarySafe(VOID)
{
    /* 必须取得用于拒绝模糊完成边界的全部体系结构字段。 */
    ULONGLONG entry = 0ULL, vectoring = 0ULL, pending = 0ULL;
    /* 保留既有中断屏蔽窗口和来宾调试请求的语义。 */
    ULONGLONG blocking = 0ULL, flags = 0ULL, dr7 = 0ULL;
    /* 不能将读取失败解释为没有待处理事件。 */
    if (!NaRead(0x4016UL, &entry) || !NaRead(0x4408UL, &vectoring) || !NaRead(0x6822UL, &pending) ||
        !NaRead(0x4824UL, &blocking) || !NaRead(0x6820UL, &flags) || !NaRead(0x681AUL, &dr7))
    {
        return FALSE;
    }
    /* 不消费或覆盖来宾的异常与调试状态。 */
    BOOLEAN safe = (entry & 0x80000000ULL) == 0ULL && (vectoring & 0x80000000ULL) == 0ULL && pending == 0ULL &&
           blocking == 0ULL && (flags & 0x100ULL) == 0ULL && (dr7 & 0xFFULL) == 0ULL;
    /* 拒绝原因由实际字段说明，日志仍只在普通控制面输出。 */
    if (!safe && g_KswordNoAttach.UseTf)
    {
        /* 次数不作为完成或失败授权。 */
        ++g_KswordNoAttach.TfPrecheckReject;
        /* 与 TF 武装记录使用相同字段位置。 */
        g_KswordNoAttach.TfBoundary[2] = entry; g_KswordNoAttach.TfBoundary[3] = vectoring;
        /* 分别保留阻塞与调试状态。 */
        g_KswordNoAttach.TfBoundary[4] = pending; g_KswordNoAttach.TfBoundary[5] = blocking;
        /* 不从快照猜当前 flags/DR7。 */
        g_KswordNoAttach.TfBoundary[6] = flags; g_KswordNoAttach.TfBoundary[7] = dr7;
    }
    /* 原有安全条件保持不变。 */
    return safe;
}

/* 此支持任意 IRQL 的非分页身份叶函数，是根模式唯一调用的 Windows 例程。 */
static BOOLEAN NaTargetUserThread(VOID)
{
    /* 宿主 GS 指向 VMCS 配置时捕获的同一处理器内核 KPCR。 */
    ULONGLONG gs = 0ULL, cs = 0ULL;
    /* 退出通知必须在该线程 TEB 可复用前撤销发布。 */
    if (InterlockedCompareExchange(&g_KswordNoAttach.Enabled, 0L, 0L) == 0L)
    {
        return FALSE;
    }
    /* 直接比较已引用的不透明 ETHREAD，不读取线程私有字段。 */
    if ((PETHREAD)KeGetCurrentThread() != g_KswordNoAttach.Thread)
    {
        return FALSE;
    }
    /* TEB 和特权级是独立的体系结构交叉判据。 */
    if (!NaRead(0x6810UL, &gs) || !NaRead(0x0802UL, &cs))
    {
        return FALSE;
    }
    /* 不能仅因属于同一线程就停止内核执行。 */
    return (cs & 3ULL) == 3ULL && gs == g_KswordNoAttach.Teb;
}

/* 内核 APC、外部上下文修改或调度返回都可能使旧停止现场过期。 */
static BOOLEAN NaSameStop(KSW_HVM_GPR_FRAME *Frame)
{
    /* 不读取目标页，仅比较当前 VMCS 和当前退出保存帧。 */
    ULONGLONG rip = 0ULL, rsp = 0ULL, flags = 0ULL, cr3 = 0ULL;
    /* 固定十五个寄存器，循环不会追踪用户指针。 */
    ULONG index;
    /* 与协议的 GPR 顺序由结构大小断言固定。 */
    const ULONGLONG *actual = (const ULONGLONG *)Frame;
    /* 当前文档在 STOPPED/STEP_PENDING 状态没有其它写者。 */
    const ULONGLONG *saved = &g_KswordNoAttach.Snapshot.rax;
    /* 不能核对完整现场时不能继续使用旧 stopId。 */
    if (!NaRead(0x681EUL, &rip) || !NaRead(0x681CUL, &rsp) || !NaRead(0x6820UL, &flags) ||
        !NaRead(0x6802UL, &cr3))
    {
        return FALSE;
    }
    /* 地址空间与控制寄存器同样属于这次停止身份。 */
    if (rip != g_KswordNoAttach.Snapshot.rip || rsp != g_KswordNoAttach.Snapshot.rsp ||
        ((flags ^ g_KswordNoAttach.Snapshot.rflags) & ~0x10000ULL) != 0ULL ||
        cr3 != g_KswordNoAttach.Snapshot.cr3)
    {
        return FALSE;
    }
    /* RF 会由 EPT fault/retry 和中断返回改变，不表示用户指令或普通现场变化。 */
    /* 普通循环避免额外的 Windows 内核内存比较调用。 */
    for (index = 0UL; index < 15UL; ++index)
    {
        /* 任意寄存器变化都必须形成新停止，而非悄悄迁移旧动作授权。 */
        if (actual[index] != saved[index])
        {
            return FALSE;
        }
    }
    /* 相同重复 fetch 保持原 stopId，不制造事件风暴。 */
    return TRUE;
}

/* 调用方赢得状态转换后，才发布一份当前快照。 */
static NTSTATUS NaPublish(KSW_HVM_GPR_FRAME *Frame, ULONG Reason, ULONG BreakpointId)
{
    /* 先在本地构建文档，VMREAD 失败时保留原停止现场。 */
    KSWORD_ARK_HVM_NOATTACH_RESPONSE copy = g_KswordNoAttach.Snapshot;
    /* 绝不从历史遥测推断停止指令指针。 */
    if (!NaRead(0x681EUL, &copy.rip) || !NaRead(0x681CUL, &copy.rsp) || !NaRead(0x6820UL, &copy.rflags) ||
        !NaRead(0x6802UL, &copy.cr3))
    {
        return STATUS_HV_OPERATION_FAILED;
    }
    /* 汇编保存帧与协议按完全相同顺序存放十五个 GPR。 */
    RtlCopyMemory(&copy.rax, Frame, sizeof(*Frame));
    /* 每次真实停止发布只推进一次停止身份。 */
    copy.stopId += 1ULL;
    /* 零表示该会话尚未发生停止。 */
    if (copy.stopId == 0ULL)
    {
        copy.stopId = 1ULL;
    }
    /* 标识当前停止的真实来源。 */
    copy.stopReason = Reason;
    /* 当前命中身份与本次现场一起由序列锁发布。 */
    copy.breakpointId = BreakpointId;
    /* 已完成停止与已接受命令是不同状态。 */
    copy.state = KSWORD_ARK_HVM_NOATTACH_STOPPED;
    /* 字段读取成功后，才确立此快照的语义结果。 */
    copy.status = STATUS_SUCCESS;
    /* 新的可消费停止退休之前的在途重试，不能将其交给另一请求。 */
    InterlockedExchange(&g_KswordNoAttach.TfRetryAfterInterrupt, 0L);
    /* 奇数序号阻止 PASSIVE_LEVEL 读者接受撕裂副本。 */
    InterlockedIncrement(&g_KswordNoAttach.SnapshotSequence);
    /* 替换完整的定长文档。 */
    g_KswordNoAttach.Snapshot = copy;
    /* 确保全部寄存器写入先于偶数序号发布。 */
    KeMemoryBarrier();
    /* 完成序列锁发布。 */
    InterlockedIncrement(&g_KswordNoAttach.SnapshotSequence);
    /* 并发生命周期撤销绝不能被 STOPPED 覆盖。 */
    if (InterlockedCompareExchange(&g_KswordNoAttach.Enabled, 0L, 0L) == 0L)
    {
        return STATUS_CANCELLED;
    }
    /* 仅从该确切写者已占用的状态发布。 */
    return InterlockedCompareExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_STOPPED,
                                      KSW_NOATTACH_PUBLISHING) == KSW_NOATTACH_PUBLISHING
               ? STATUS_SUCCESS
               : STATUS_CANCELLED;
}

/* 取消属于正常生命周期清理，不是体系结构回滚故障。 */
static BOOLEAN NaPublishResult(KSW_HVM_RESIDENT_VCPU *Context, KSW_HVM_GPR_FRAME *Frame, ULONG Reason,
                               ULONG BreakpointId, ULONG *Action);

/* 失败先归还执行控制，实际 VMXOFF 由 PASSIVE_LEVEL 内核屏障完成。 */
static BOOLEAN NaFail(KSW_HVM_RESIDENT_VCPU *Context, ULONG *Action)
{
    /* 请求回滚前先停止发布执行控制。 */
    InterlockedExchange(&g_KswordNoAttach.Enabled, 0L);
    /* 确认全部处理器退出 VMX 前，保留所有资源。 */
    InterlockedExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED);
    /* 用户态 RSP 不能被 CPL0 的 native-return 汇编当作内核栈写入。 */
    Context->NoAttachBypass = FALSE;
    /* 在途单步不再具备发布完成的资格。 */
    InterlockedExchange(&g_KswordNoAttach.StepProcessor, -1L);
    /* 恢复成功仍保留全部 VMX 资源和会话身份，供控制面显式 Close。 */
    *Action = KswordARKHvmNoAttachTfDisarm(Context) && NaRoot(g_KswordNoAttach.NormalEptp)
        ? KSW_HVM_EXIT_ACTION_RESUME : KSW_HVM_EXIT_ACTION_FATAL;
    /* 此失败完整认领本次退出，其它规则不得放宽权限。 */
    return TRUE;
}

/* 区分真实 VMCS 失败与并发的所有者或目标撤销。 */
static BOOLEAN NaPublishResult(KSW_HVM_RESIDENT_VCPU *Context, KSW_HVM_GPR_FRAME *Frame, ULONG Reason,
                               ULONG BreakpointId, ULONG *Action)
{
    /* 全部体系结构读取成功后，快照发布仍可能被取消。 */
    NTSTATUS status = NaPublish(Frame, Reason, BreakpointId);
    /* 已撤销停止应恢复普通根表，并由所有者完成退休。 */
    if (status == STATUS_CANCELLED)
    {
        /* 绝不将正常关闭或目标退出误变为 RecoveryRequired。 */
        return NaRoot(g_KswordNoAttach.NormalEptp) ? TRUE : NaFail(Context, Action);
    }
    /* 只有体系结构读取失败才请求已核对的 VMXOFF 故障路径。 */
    return NT_SUCCESS(status) ? TRUE : NaFail(Context, Action);
}

/* 放行只改变当前 CPU 的 EPTP，其他核继续使用不可变的受限视图。 */
static BOOLEAN NaBypass(KSW_HVM_RESIDENT_VCPU *Context, ULONG *Action)
{
    /* 必须先登记恢复责任，任意下一退出都会收回权限。 */
    Context->NoAttachBypass = TRUE;
    /* 不修改代码、DR 或共享叶子；只有明确选择的备用模式临时设置 TF。 */
    return NaRoot(g_KswordNoAttach.NormalEptp) && NaMtf(Context, TRUE) ? TRUE : NaFail(Context, Action);
}

/* 在已复核的原停点提交整数寄存器，不执行任何用户指令。 */
static BOOLEAN NaApplyRegisters(KSW_HVM_RESIDENT_VCPU *Context, KSW_HVM_GPR_FRAME *Frame, ULONG *Action)
{
    /* 普通控制面发布状态之前已冻结完整的值请求。 */
    const KSWORD_ARK_HVM_NOATTACH_GPR *requested = &g_KswordNoAttach.PendingRegisters;
    /* 位顺序与汇编保存帧相同。 */
    ULONGLONG *actual = (ULONGLONG *)Frame;
    /* 请求指针只指向固定非分页存储。 */
    const ULONGLONG *values = &requested->rax;
    /* RFLAGS 保留原值，不能借寄存器编辑设置 TF。 */
    ULONGLONG mask = g_KswordNoAttach.PendingRegisterMask;
    /* 仅遍历有限的十五个整数寄存器。 */
    ULONG i;
    /* 两个 VMCS 写入均完成前不修改通用寄存器保存帧。 */
    if (((mask & (1ULL << 15)) != 0ULL && KswordARKHvmVmcsFieldStore(0x681EUL, (SIZE_T)requested->rip) != 0U) ||
        ((mask & (1ULL << 16)) != 0ULL && KswordARKHvmVmcsFieldStore(0x681CUL, (SIZE_T)requested->rsp) != 0U))
    {
        /* 恢复原控制寄存器，不能带着半份修改返回用户代码。 */
        if (KswordARKHvmVmcsFieldStore(0x681EUL, (SIZE_T)g_KswordNoAttach.Snapshot.rip) != 0U ||
            KswordARKHvmVmcsFieldStore(0x681CUL, (SIZE_T)g_KswordNoAttach.Snapshot.rsp) != 0U)
        {
            /* 无法保证原现场时不允许不完整的继续。 */
            *Action = KSW_HVM_EXIT_ACTION_FATAL;
            /* 由既有致命错误路径处理硬件故障。 */
            return TRUE;
        }
        /* 完整回滚后沿用现有 VMXOFF 恢复机制。 */
        return NaFail(Context, Action);
    }
    /* 只改请求明确选择的位，未选择的寄存器完全保留。 */
    for (i = 0UL; i < 15UL; ++i)
    {
        /* 不修改任何 SIMD/扩展状态。 */
        if ((mask & (1ULL << i)) != 0ULL) { actual[i] = values[i]; }
    }
    /* 提交后的新停点不冒充 MTF 完成。 */
    return NaPublishResult(Context, Frame, KSWORD_ARK_HVM_NOATTACH_STOP_CONTEXT, 0UL, Action);
}

BOOLEAN KswordARKHvmNoAttachHandleExit(KSW_HVM_RESIDENT_VCPU *Context, KSW_HVM_GPR_FRAME *Frame, ULONG Reason,
                                       ULONGLONG Qualification, ULONG *Action)
{
    /* 功能关闭路径不执行任何 VMCS 写入。 */
    LONG state;
    /* 当前 EPTP 标识哪种模式门禁产生了取指违规。 */
    ULONGLONG eptp = 0ULL;
    /* active bank 在全核屏障前不可重建，单次退出始终使用同一份。 */
    KSW_NA_BANK *bank;
    /* 实际异常重新投递以后，不再落入通用 bitmap=0 分支。 */
    BOOLEAN forwarded = FALSE;
    /* 全部不可变根表构建完成前，不认领执行控制。 */
    if (!KswordARKHvmNoAttachOwned() || g_KswordNoAttach.NormalEptp == 0ULL)
    {
        return FALSE;
    }
    /* 每次成功拦截都从同一条体系结构指令继续。 */
    *Action = KSW_HVM_EXIT_ACTION_RESUME;
    /* 任意退出先归还本方 TF，再允许其它派发或停止发布。 */
    if (!KswordARKHvmNoAttachTfRetire(Context, &Reason, Qualification, &forwarded)) { return NaFail(Context, Action); }
    /* 索引的原子读取与完整表发布配对。 */
    bank = &g_KswordNoAttach.Banks[InterlockedCompareExchange(&g_KswordNoAttach.ActiveBank, 0L, 0L)];
    /* 同一 bank 根物理地址重用后逐核失效，不能依赖 VMXON 清缓存。 */
    if (Context->NoAttachWatchGeneration != bank->Generation)
    {
        /* 初次和每次配置代次变化都在使用前失效。 */
        if (bank->Eptp == 0ULL || KswordARKHvmAsmInveptSingle(bank->Eptp) != 0U) { return NaFail(Context, Action); }
        /* 此代次已经在当前 CPU 完成硬件失效。 */
        Context->NoAttachWatchGeneration = bank->Generation;
    }
    /* 不匹配 RIP/线程的页命中及 Continue 的临时放行均在任何退出收回。 */
    if (Context->NoAttachBypass)
    {
        /* 先退休本 CPU 的恢复责任。 */
        Context->NoAttachBypass = FALSE;
        /* 不将该 MTF 当作用户单步完成事件。 */
        if (!NaMtf(Context, FALSE) || !NaRoot(g_KswordNoAttach.UserGateEptp)) { return NaFail(Context, Action); }
        /* 私有 MTF 必须完全消费，不能落入原有 guest #DB 通道。 */
        if (Reason == 37UL) { return TRUE; }
    }
    /* 派发任何其它退出前，先收回这一次处理器本地放行。 */
    if (InterlockedCompareExchange(&g_KswordNoAttach.StepProcessor, -1L, -1L) ==
        (LONG)Context->ProcessorIndex)
    {
        /* 被中断、被模拟或内核态指令都不得保留普通执行放行。 */
        if (!NaMtf(Context, FALSE) || !NaRoot(g_KswordNoAttach.UserGateEptp))
        {
            return NaFail(Context, Action);
        }
        /* 撤销该处理器的完成所有权。 */
        InterlockedExchange(&g_KswordNoAttach.StepProcessor, -1L);
        /* 只有明确属于目标用户线程的 MTF 边界才完成单步。 */
        if (Reason == 37UL && NaTargetUserThread() && NaStepBoundarySafe() &&
            InterlockedCompareExchange(&g_KswordNoAttach.State, KSW_NOATTACH_PUBLISHING,
                                       KSWORD_ARK_HVM_NOATTACH_STEPPING) == KSWORD_ARK_HVM_NOATTACH_STEPPING)
        {
            /* 保持下一次取指停止前，先发布真实 VMCS 和寄存器证据。 */
            return NaPublishResult(Context, Frame, KSWORD_ARK_HVM_NOATTACH_STOP_STEP, 0UL, Action);
        }
        else
        {
            /* IRQ 优先于尚未执行的指令时，恢复 TF 后允许原中断正常投递。 */
            if (g_KswordNoAttach.UseTf && Reason == 1UL && forwarded && NaTargetUserThread() &&
                g_KswordNoAttach.TfRetryCount < 64UL && NaSameStop(Frame))
            {
                /* RIP、RSP、全部 GPR 和其它 flags 不变，RF 允许在中断返回时由硬件退休。 */
                ++g_KswordNoAttach.TfRetryCount;
                /* 仍属于已经消费的同一个 STEP，不给新现场补授旧 stopId。 */
                InterlockedExchange(&g_KswordNoAttach.TfRetryAfterInterrupt, 1L);
                /* 下次匹配用户取指才重新武装，内核中断处理者绝不带本方 TF。 */
                (void)InterlockedCompareExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_STEP_PENDING,
                                                 KSWORD_ARK_HVM_NOATTACH_STEPPING);
            }
            else
            {
                /* 已执行、外部上下文变化、其它退出或预算耗尽均不报告 STEP 完成。 */
                (void)InterlockedCompareExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_INTERRUPTED,
                                                 KSWORD_ARK_HVM_NOATTACH_STEPPING);
            }
        }
        /* 本方拥有的 MTF 退出不得落入附加调试器的 #DB 路径。 */
        if (Reason == 37UL)
        {
            return TRUE;
        }
    }
    /* 真实异常或未 ACK 的中断已保留投递，不能误判成不支持的退出。 */
    if (forwarded) { return TRUE; }
    /* 撤销和普通运行状态不承担模式门禁退出开销。 */
    state = InterlockedCompareExchange(&g_KswordNoAttach.State, 0L, 0L);
    /* 发布关闭后，始终解除该处理器的不可变门禁。 */
    if (InterlockedCompareExchange(&g_KswordNoAttach.Enabled, 0L, 0L) == 0L ||
        state == KSWORD_ARK_HVM_NOATTACH_RUNNING)
    {
        /* 在继续或撤销前已发生的门禁违规，仍由本模块认领。 */
        BOOLEAN gateFetch =
            Reason == 48UL && (Qualification & 4ULL) != 0ULL && NaRead(0x201AUL, &eptp) &&
            (eptp == g_KswordNoAttach.UserGateEptp || eptp == g_KswordNoAttach.KernelGateEptp ||
             eptp == g_KswordNoAttach.Banks[0].Eptp || eptp == g_KswordNoAttach.Banks[1].Eptp);
        /* 活动执行断点从 EPT 页事件核对精确线程、RIP 与 backing。 */
        if (gateFetch && state == KSWORD_ARK_HVM_NOATTACH_RUNNING &&
            InterlockedCompareExchange(&g_KswordNoAttach.Enabled, 0L, 0L) != 0L && eptp == bank->Eptp)
        {
            /* 仅在架构保证有效的 EPT 退出读取 GPA。 */
            ULONGLONG physical = 0ULL, rip = 0ULL, rsp = 0ULL;
            /* 对页面命中作有限精确筛选。 */
            ULONG i;
            /* 无法读取真实地址时不能放行不明事件。 */
            if (!NaRead(0x2400UL, &physical) || !NaRead(0x681EUL, &rip) || !NaRead(0x681CUL, &rsp))
            { return NaFail(Context, Action); }
            /* 不同线程、同页其他指令或物理别名只放行当前 CPU 一条指令。 */
            if (NaTargetUserThread())
            {
                /* 多个地址可以共用同一受限物理页。 */
                for (i = 0UL; i < bank->Count; ++i)
                {
                    /* 过滤条件全部来自不可变活动配置。 */
                    const KSWORD_ARK_HVM_NOATTACH_BREAKPOINT *row = &bank->Rows[i];
                    /* 不把页粒度事件冒充任意字节地址命中。 */
                    if ((bank->Disabled & (1L << i)) != 0L || row->address != rip ||
                        row->physicalPage != (physical & ~0xFFFULL) ||
                        ((row->flags & KSWORD_ARK_HVM_NOATTACH_BP_STACK_FILTER) != 0UL && rsp < row->minimumRsp))
                    { continue; }
                    /* 只有唯一的停点发布者能消费一次性资格。 */
                    if (InterlockedCompareExchange(&g_KswordNoAttach.State, KSW_NOATTACH_PUBLISHING,
                                                   KSWORD_ARK_HVM_NOATTACH_RUNNING) == KSWORD_ARK_HVM_NOATTACH_RUNNING)
                    {
                        /* 保持原指令未执行，并允许系统内核继续调度。 */
                        if (!NaRoot(g_KswordNoAttach.UserGateEptp)) { return NaFail(Context, Action); }
                        /* 一次性断点只撤销自身精确地址资格，不放宽共享页权限。 */
                        if ((row->flags & KSWORD_ARK_HVM_NOATTACH_BP_ONESHOT) != 0UL)
                        { InterlockedOr(&bank->Disabled, 1L << i); }
                        /* 当前停止来自真实 EPT 执行事件。 */
                        return NaPublishResult(Context, Frame, KSWORD_ARK_HVM_NOATTACH_STOP_BREAKPOINT, row->id, Action);
                    }
                    /* 与暂停或退出竞争失败仍由新的状态保留门禁。 */
                    return NaRoot(g_KswordNoAttach.UserGateEptp) ? TRUE : NaFail(Context, Action);
                }
            }
            /* 无关页内取指不触发调试回调。 */
            return NaBypass(Context, Action);
        }
        /* 既有派发继续前，先恢复普通映射。 */
        if (!NaRoot(InterlockedCompareExchange(&g_KswordNoAttach.Enabled, 0L, 0L) != 0L &&
                    state == KSWORD_ARK_HVM_NOATTACH_RUNNING && bank->Count != 0UL
                        ? bank->Eptp : g_KswordNoAttach.NormalEptp))
        {
            return NaFail(Context, Action);
        }
        /* 其它体系结构退出仍交给既有处理例程。 */
        return gateFetch;
    }
    /* 只有指令取指 EPT 违规属于此模式门禁机制。 */
    if (Reason == 48UL && (Qualification & 4ULL) != 0ULL)
    {
        /* 读取实际加载的根表，不从全局状态推断。 */
        if (!NaRead(0x201AUL, &eptp))
        {
            return NaFail(Context, Action);
        }
        /* PAUSE/新配置期间的旧 watch 事件先切到门禁，不能交给 #DB 处理。 */
        if (eptp == g_KswordNoAttach.Banks[0].Eptp || eptp == g_KswordNoAttach.Banks[1].Eptp)
        {
            /* 同一 RIP 会在目标门禁中重新核对。 */
            return NaRoot(g_KswordNoAttach.UserGateEptp) ? TRUE : NaFail(Context, Action);
        }
        /* 每次首个监督态取指都恢复用户入口门禁。 */
        if (eptp == g_KswordNoAttach.KernelGateEptp)
        {
            /* 无需修改 RIP、写目标内存或注入异常。 */
            return NaRoot(g_KswordNoAttach.UserGateEptp) ? TRUE : NaFail(Context, Action);
        }
        /* 在选定用户线程的下一条指令退休前拦截。 */
        if (eptp == g_KswordNoAttach.UserGateEptp)
        {
            /* 其它线程保持可运行，并截获下一次特权级转换。 */
            if (!NaTargetUserThread())
            {
                /* 内核入口门禁也可捕获同一地址空间内的线程调度。 */
                return NaRoot(g_KswordNoAttach.KernelGateEptp) ? TRUE : NaFail(Context, Action);
            }
            /* 旧 stopId 不能授权内核返回后已经改变的另一份用户上下文。 */
            if ((state == KSWORD_ARK_HVM_NOATTACH_STOPPED || state == KSWORD_ARK_HVM_NOATTACH_STEP_PENDING ||
                 state == KSWORD_ARK_HVM_NOATTACH_CONTINUE_PENDING ||
                 state == KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING) &&
                !NaSameStop(Frame))
            {
                /* 先退休旧停止/动作，再发布确实截获的新取指现场。 */
                if (InterlockedCompareExchange(&g_KswordNoAttach.State, KSW_NOATTACH_PUBLISHING, state) ==
                    state)
                {
                    /* 新 stopReason 是 FETCH，不能冒充旧 STEP 已完成。 */
                    return NaPublishResult(Context, Frame, KSWORD_ARK_HVM_NOATTACH_STOP_FETCH, 0UL, Action);
                }
                /* 与命令占用或退出竞争失败时仍保持门禁。 */
                return TRUE;
            }
            /* 编辑只在原现场完全一致时提交，随后仍保持停止。 */
            if (state == KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING)
            {
                /* 与退出竞争失败不修改任何寄存器。 */
                if (InterlockedCompareExchange(&g_KswordNoAttach.State, KSW_NOATTACH_PUBLISHING, state) == state)
                { return NaApplyRegisters(Context, Frame, Action); }
                /* 已撤销的命令保持门禁直到普通生命周期收尾。 */
                return TRUE;
            }
            /* 继续动作也只在同一份真实停止现场上解除门禁。 */
            if (state == KSWORD_ARK_HVM_NOATTACH_CONTINUE_PENDING)
            {
                /* 与退出通知竞争失败时不能复活 Running。 */
                if (InterlockedCompareExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_RUNNING,
                                               state) == state)
                {
                    /* 只有当前取指确实落在受限物理页时，才需要逐指令临时放行。 */
                    ULONGLONG physical = 0ULL;
                    /* 原暂停点可能在 ntdll 的系统调用处，与断点页完全无关。 */
                    if (bank->Count != 0UL)
                    {
                        /* 当前退出是架构定义 GPA 有效的执行违规。 */
                        if (!NaRead(0x2400UL, &physical)) { return NaFail(Context, Action); }
                        /* 行即使已消费也可能仍保留受限 EPT 页，必须按实际表视图判断。 */
                        for (ULONG i = 0UL; i < bank->Count; ++i)
                        {
                            /* 同页放行只改变本 CPU，不能放宽共享 EPT 叶子。 */
                            if (bank->Rows[i].physicalPage == (physical & ~0xFFFULL)) { return NaBypass(Context, Action); }
                        }
                    }
                    /* 不相关代码直接进入正常监视根，不武装 TF/MTF。 */
                    return NaRoot(bank->Count != 0UL ? bank->Eptp : g_KswordNoAttach.NormalEptp)
                        ? TRUE : NaFail(Context, Action);
                }
                /* 已撤销或其它状态仍由下一次退出处理其恢复映射。 */
                return TRUE;
            }
            /* 待处理暂停或被中断单步在此成为真实当前停止。 */
            if (state == KSWORD_ARK_HVM_NOATTACH_PAUSE_PENDING ||
                state == KSWORD_ARK_HVM_NOATTACH_INTERRUPTED)
            {
                /* 生命周期回调或其它写者可能已撤销请求。 */
                if (InterlockedCompareExchange(&g_KswordNoAttach.State, KSW_NOATTACH_PUBLISHING, state) ==
                    state)
                {
                    /* 仅发布真实停止目标的当前体系结构状态。 */
                    return NaPublishResult(Context, Frame, KSWORD_ARK_HVM_NOATTACH_STOP_FETCH, 0UL, Action);
                }
                /* 重试被拒绝的取指，使停止指令保持未执行。 */
                return TRUE;
            }
            /* 已消费的停止只排入一次目标线程执行放行。 */
            if (state == KSWORD_ARK_HVM_NOATTACH_STEP_PENDING)
            {
                /* 武装前就检查事件投递，不能只在收到 MTF 后检查。 */
                if (!NaStepBoundarySafe())
                {
                    /* 初始边界不明确时，不执行任何指令。 */
                    (void)InterlockedCompareExchange(&g_KswordNoAttach.State,
                                                     KSWORD_ARK_HVM_NOATTACH_INTERRUPTED, state);
                    /* 保留门禁并等待新的真实停止。 */
                    return TRUE;
                }
                /* 修改处理器控制前，先认领唯一在途指令。 */
                if (InterlockedCompareExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_STEPPING,
                                               state) == state)
                {
                    /* 放行可见前，先记录完成所有权。 */
                    InterlockedExchange(&g_KswordNoAttach.StepProcessor, (LONG)Context->ProcessorIndex);
                    /* 下一次 VM-exit 在所有路径都恢复门禁。 */
                    if (!NaRoot(g_KswordNoAttach.NormalEptp) || !NaMtf(Context, TRUE))
                    {
                        /* 保守指令/事件边界拒绝没有执行指令，继续保留用户入口门禁。 */
                        if (g_KswordNoAttach.UseTf && Context->LastStatus == STATUS_NOT_SUPPORTED &&
                            KswordARKHvmNoAttachTfDisarm(Context) && NaRoot(g_KswordNoAttach.UserGateEptp))
                        {
                            /* 拒绝不能伪造 STEP 完成；下一次真实取指给出新的 FETCH 停止。 */
                            InterlockedExchange(&g_KswordNoAttach.StepProcessor, -1L);
                            /* 生命周期撤销若已到达，不恢复旧状态。 */
                            (void)InterlockedCompareExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_INTERRUPTED,
                                                             KSWORD_ARK_HVM_NOATTACH_STEPPING);
                            /* 当前指令保持未执行。 */
                            return TRUE;
                        }
                        return NaFail(Context, Action);
                    }
                }
                /* VMRESUME 执行真实指令；MTF 与明确报告的 TF 边界分别恢复。 */
                return TRUE;
            }
            /* 已保持的停止稳定不变，重复取指不推进其身份。 */
            return TRUE;
        }
    }
    /* 其它体系结构退出后重新建立用户入口拦截。 */
    if (!NaRoot(g_KswordNoAttach.UserGateEptp))
    {
        return NaFail(Context, Action);
    }
    /* 既有处理例程继续模拟 CPUID、超调用和真实来宾故障。 */
    return FALSE;
}

NTSTATUS KswordARKHvmNoAttachBuildRootsLocked(KSW_HVM_RUNTIME *Runtime)
{
    /* 所有表分配都在没有常驻处理器时执行。 */
    PHYSICAL_ADDRESS userPhysical, kernelPhysical;
    /* 两个不可变根表共用已准备的下级 EPT 表。 */
    ULONGLONG *userRoot;
    /* 普通根表仍使用运行时既有 EPT 指针。 */
    ULONGLONG *kernelRoot;
    /* 边界取自已准备的 EPT 分配台账。 */
    ULONG page, index, count = Runtime->EptPageCount;
    /* 仅在本模块独占模式中，MBEC 才改变第十位的含义。 */
    ULONGLONG controls = __readmsr(KSW_IA32_VMX_PROCBASED_CTLS2);
    /* 启用控制或进入 VMX 前，先拒绝能力缺失。 */
    if (((controls >> 32) & KSW_NOATTACH_MBEC_CONTROL) == 0ULL ||
        (Runtime->FeatureFlags & KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) == 0ULL ||
        ((Runtime->FeatureFlags & KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) == 0ULL &&
            !KswordARKHvmNoAttachTfAvailable()))
    {
        return STATUS_NOT_SUPPORTED;
    }
    /* 此独立模式不包含可变规则、视图、本地或切换层次。 */
    if (Runtime->EptRuleCount != 0UL || Runtime->LocalEptArmed || Runtime->EptpSwitchArmed ||
        Runtime->ProcessDispositionCount != 0UL)
    {
        return STATUS_DEVICE_BUSY;
    }
    /* 启用 MBEC 后，每个既有可执行条目也必须允许用户执行。 */
    for (page = 0UL; page < count; ++page)
    {
        /* 运行时台账包含完整的已准备基础分页层次。 */
        ULONGLONG *table = (ULONGLONG *)Runtime->EptPages[page].VirtualAddress;
        /* 分配台账不完整时绝不激活。 */
        if (table == NULL)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }
        /* 覆盖全部有效 PML4、PDPT、PD、PT 条目，包括大页叶子。 */
        for (index = 0UL; index < 512UL; ++index)
        {
            /* 保留普通执行限制，不额外授予隐藏访问权限。 */
            if ((table[index] & KSW_EPT_EXECUTE) != 0ULL)
            {
                table[index] |= KSW_NOATTACH_USER_EXECUTE;
            }
        }
    }
    /* 将两个页面都记入既有全处理器拆卸台账。 */
    userRoot = (ULONGLONG *)KswordARKHvmAllocateEptPageLocked(Runtime, &userPhysical);
    /* 分配失败时拒绝发布任何 EPT 指针。 */
    if (userRoot == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* 修改第一个根表权限前，先分配第二个根表。 */
    kernelRoot = (ULONGLONG *)KswordARKHvmAllocateEptPageLocked(Runtime, &kernelPhysical);
    /* 运行时负责准备失败时清理这两个台账条目。 */
    if (kernelRoot == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* 保留全部原物理映射及 EPT 权限依赖。 */
    RtlCopyMemory(userRoot, Runtime->EptPml4, PAGE_SIZE);
    /* 内核入口门禁共用完全相同的下级表。 */
    RtlCopyMemory(kernelRoot, Runtime->EptPml4, PAGE_SIZE);
    /* 仅修改有效根表条目，绝不给空洞创建映射。 */
    for (index = 0UL; index < 512UL; ++index)
    {
        /* MBEC 允许独立设置监督态和用户态执行权限。 */
        userRoot[index] &= ~KSW_NOATTACH_USER_EXECUTE;
        /* 禁止监督态执行可截获下一次系统调用、中断或调度入口。 */
        kernelRoot[index] &= ~KSW_EPT_EXECUTE;
    }
    /* 启动任何常驻处理器前，先发布完整不可变根表。 */
    g_KswordNoAttach.NormalEptp = Runtime->EptPointer;
    /* 内存类型、遍历层数与 A/D 配置均与基础根表一致。 */
    g_KswordNoAttach.UserGateEptp = (Runtime->EptPointer & ~KSW_NA_FRAME) | (ULONGLONG)userPhysical.QuadPart;
    /* 三种执行模式之间仅根表物理地址不同。 */
    g_KswordNoAttach.KernelGateEptp =
        (Runtime->EptPointer & ~KSW_NA_FRAME) | (ULONGLONG)kernelPhysical.QuadPart;
    /* VMCS 配置读取根表指针前，完成全部表写入。 */
    KeMemoryBarrier();
    /* 此准备例程不执行任何 VMX 指令。 */
    return KswordARKHvmNoAttachPrepareBanks(Runtime);
}

NTSTATUS KswordARKHvmNoAttachInvalidateRootsForEntry(KSW_HVM_RUNTIME *Runtime)
{
    /* 根表物理页可能来自旧会话；VMXON/VMXOFF 不保证清除其 EPT 缓存。 */
    if (Runtime == NULL || !KswordARKHvmNoAttachOwned() ||
        g_KswordNoAttach.NormalEptp == 0ULL ||
        g_KswordNoAttach.NormalEptp != Runtime->EptPointer ||
        g_KswordNoAttach.UserGateEptp == 0ULL || g_KswordNoAttach.KernelGateEptp == 0ULL)
    {
        /* 台账不完整时不能启动任何依赖此门禁的处理器。 */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* 基础根由既有入口失效；两个不可变专用根必须在当前处理器分别失效。 */
    if (KswordARKHvmAsmInveptSingle(g_KswordNoAttach.UserGateEptp) != 0U ||
        KswordARKHvmAsmInveptSingle(g_KswordNoAttach.KernelGateEptp) != 0U)
    {
        /* 不将失效失败降级为成功启动，沿用既有准入回滚路径。 */
        return STATUS_HV_OPERATION_FAILED;
    }
    /* 只有当前处理器的两个新根都完成失效后才允许首次使用。 */
    return STATUS_SUCCESS;
}

VOID KswordARKHvmNoAttachResetRootsLocked(KSW_HVM_RUNTIME *Runtime)
{
    /* 全处理器停止失败时，保留全部映射与身份引用。 */
    if (InterlockedCompareExchange(&Runtime->ResidentProcessorCount, 0L, 0L) != 0L)
    {
        return;
    }
    /* 运行时分配台账随后释放实际表页面。 */
    g_KswordNoAttach.NormalEptp = 0ULL;
    /* 拆卸成功后，已停止读者不得再保留任一模式门禁。 */
    g_KswordNoAttach.UserGateEptp = 0ULL;
    /* 对称清除第二个不可变根表。 */
    g_KswordNoAttach.KernelGateEptp = 0ULL;
}

NTSTATUS KswordARKHvmNoAttachRendezvous(KSW_HVM_RUNTIME *Runtime)
{
    /* 既有全处理器 INVEPT 超调用也会观察新的模式请求。 */
    return KswordARKHvmResidentInvalidateEpt(Runtime->EptPointer);
}
