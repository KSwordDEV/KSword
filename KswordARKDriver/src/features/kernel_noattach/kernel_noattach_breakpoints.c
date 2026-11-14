#include "kernel_noattach.h"

/* 四个真实地址槽，不能当成任意数量的页观察点。 */
static PULONGLONG KnaDr(PCONTEXT Context, ULONG Index)
{
    /* 调用方的索引均受固定容量限制。 */
    switch (Index) { case 0UL: return &Context->Dr0; case 1UL: return &Context->Dr1;
                    case 2UL: return &Context->Dr2; default: return &Context->Dr3; }
}

VOID KnaApplyDebug(PCONTEXT Context, BOOLEAN Restore)
{
    /* 调用者已经确保行配置不会在提交期间改变。 */
    ULONG i;
    /* 精确恢复或武装每个本会话槽位。 */
    for (i = 0UL; i < 4UL; ++i)
    {
        /* 空槽不赋予本会话覆盖外部状态的资格。 */
        KSWORD_ARK_HVM_NOATTACH_BREAKPOINT *row = &g_Kna.Rows[i];
        /* 每槽的启用位与类型/长度字段。 */
        ULONGLONG mask = (3ULL << (i * 2UL)) | (15ULL << (16UL + i * 4UL));
        /* 没有本方记录就保留外部槽。 */
        if (row->id == 0UL) { continue; }
        /* 关闭和一次性消费都只撤销自己的执行断点。 */
        if (Restore || (row->flags & KSWORD_ARK_HVM_NOATTACH_BP_CONSUMED) != 0UL)
        {
            /* 外部把同槽改成另一地址或访问类型时不盲目覆盖。 */
            if (*KnaDr(Context, i) == row->address && ((Context->Dr7 >> (16UL + i * 4UL)) & 15ULL) == 0ULL)
            {
                /* 恢复安装前的该地址值。 */
                *KnaDr(Context, i) = g_Kna.BaselineDr[i];
                /* 未由本方拥有的其它字段保持当前值。 */
                Context->Dr7 = (Context->Dr7 & ~mask) | (g_Kna.BaselineDr[5] & mask);
                /* 只退休该槽的自有命中位。 */
                Context->Dr6 = (Context->Dr6 & ~(1ULL << i)) | (g_Kna.BaselineDr[4] & (1ULL << i));
            }
        }
        else
        {
            /* 执行断点固定为一字节地址比较，RW/LEN=0。 */
            *KnaDr(Context, i) = row->address;
            /* 只占本会话自己的本地槽位。 */
            Context->Dr7 = (Context->Dr7 & ~mask) | (1ULL << (i * 2UL)) | 0x400ULL;
            /* 旧的同槽命中不能伪造下一次真实命中。 */
            Context->Dr6 = (Context->Dr6 & ~(1ULL << i)) | (g_Kna.BaselineDr[4] & (1ULL << i));
        }
    }
}

ULONG KnaHit(PCONTEXT Context)
{
    /* 仅返回本会话精确地址和真实 DR6 命中同时匹配的槽位。 */
    ULONG i;
    /* 不把第一个列表行状态代表整个集合。 */
    for (i = 0UL; i < 4UL; ++i)
    {
        /* 已消费的一次性地址不会再次停止。 */
        const KSWORD_ARK_HVM_NOATTACH_BREAKPOINT *row = &g_Kna.Rows[i];
        /* RF 抑制窗口由 CPU 处理，不模拟不存在的命中。 */
        if (row->id != 0UL && (row->flags & KSWORD_ARK_HVM_NOATTACH_BP_CONSUMED) == 0UL &&
            (Context->Dr6 & (1ULL << i)) != 0ULL && *KnaDr(Context, i) == row->address && Context->Rip == row->address)
        { return i + 1UL; }
    }
    /* 零意味着不是本会话的执行断点。 */
    return 0UL;
}

NTSTATUS KnaEditBreakpoint(const KSWORD_ARK_KERNEL_NOATTACH_REQUEST *Request)
{
    /* 调用方持 StateLock 且已核对当前 stopId。 */
    ULONG i, freeSlot = 4UL;
    /* 删除按真实 ID 定位，不接受前端硬件槽号伪装身份。 */
    if (Request->operation == KSWORD_ARK_HVM_NOATTACH_REMOVE_BREAKPOINT)
    {
        /* 有限遍历不会访问目标内存。 */
        for (i = 0UL; i < 4UL; ++i)
        {
            /* 仅修改自己的确切记录。 */
            if (g_Kna.Rows[i].id == Request->breakpointId && Request->breakpointId != 0UL)
            {
                /* 由目标线程提交恢复，然后才退休 ID。 */
                g_Kna.Rows[i].flags |= KSWORD_ARK_HVM_NOATTACH_BP_CONSUMED;
                /* 保留原 ID 到配置恢复完成。 */
                return STATUS_SUCCESS;
            }
        }
        /* 不存在的 ID 不冒充删除成功。 */
        return STATUS_NOT_FOUND;
    }
    /* 只接受当前实现支持的用户态执行断点与栈过滤。 */
    if (Request->address == 0ULL || Request->address > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress ||
        (Request->breakpointFlags & ~(KSWORD_ARK_HVM_NOATTACH_BP_ONESHOT | KSWORD_ARK_HVM_NOATTACH_BP_STACK_FILTER)) != 0UL ||
        ((Request->breakpointFlags & KSWORD_ARK_HVM_NOATTACH_BP_STACK_FILTER) != 0UL &&
         (Request->minimumRsp == 0ULL || Request->minimumRsp > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress)))
    { return STATUS_INVALID_PARAMETER; }
    /* 四槽容量与重复地址分别核对。 */
    for (i = 0UL; i < 4UL; ++i)
    {
        /* 相同地址不能悄悄换成另一种语义。 */
        if (g_Kna.Rows[i].id != 0UL && g_Kna.Rows[i].address == Request->address &&
            (g_Kna.Rows[i].flags & KSWORD_ARK_HVM_NOATTACH_BP_CONSUMED) == 0UL)
        { return STATUS_OBJECT_NAME_COLLISION; }
        /* 已由目标线程完成退休的空槽可以复用。 */
        if (g_Kna.Rows[i].id == 0UL && freeSlot == 4UL) { freeSlot = i; }
    }
    /* 容量不足时保留全部旧配置和原停点。 */
    if (freeSlot == 4UL) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* 非零 ID 在同一会话内不复用。 */
    if (++g_Kna.NextId == 0UL) { ++g_Kna.NextId; }
    /* 此后目标线程才会真正武装上下文。 */
    g_Kna.Rows[freeSlot].id = g_Kna.NextId;
    /* DR 使用虚拟地址，自然跟随该线程的地址翻译。 */
    g_Kna.Rows[freeSlot].address = Request->address;
    /* 不把虚拟地址冒充锁定的 EPT 物理页。 */
    g_Kna.Rows[freeSlot].physicalPage = 0ULL;
    /* RUN_TO 的一次性语义由驱动强制。 */
    g_Kna.Rows[freeSlot].flags = Request->breakpointFlags |
        KSWORD_ARK_KERNEL_NOATTACH_BP_PENDING |
        (Request->operation == KSWORD_ARK_HVM_NOATTACH_RUN_TO ? KSWORD_ARK_HVM_NOATTACH_BP_ONESHOT : 0UL);
    /* 明确保存请求时的栈深条件。 */
    g_Kna.Rows[freeSlot].minimumRsp = Request->minimumRsp;
    /* 实际提交由真实停止线程完成。 */
    return STATUS_SUCCESS;
}
