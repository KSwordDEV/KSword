#include "kernel_noattach.h"

/* 四个真实地址槽，不能当成任意数量的页观察点。 */
static PULONGLONG KnaDr(PCONTEXT Context, ULONG Index)
{
    /* 调用方的索引均受固定容量限制。 */
    switch (Index) { case 0UL: return &Context->Dr0; case 1UL: return &Context->Dr1;
                    case 2UL: return &Context->Dr2; default: return &Context->Dr3; }
}

/* 根据行配置算出该槽的 DR7 R/W 与 LEN 四位字段。 */
static ULONGLONG KnaRwLenBits(const KSWORD_ARK_HVM_NOATTACH_BREAKPOINT *Row)
{
    /* 读取请求时已经由 KnaEditBreakpoint 核对过组合合法性。 */
    ULONGLONG rw = 0ULL, len = 0ULL;
    /* 写观察 = 01，读写观察 = 11，执行 = 00。 */
    if ((Row->flags & KSWORD_ARK_HVM_NOATTACH_BP_WATCH_WRITE) != 0UL) { rw = 1ULL; }
    else if ((Row->flags & KSWORD_ARK_HVM_NOATTACH_BP_WATCH_READWRITE) != 0UL) { rw = 3ULL; }
    /* LEN 位：1B=00（默认），2B=01，8B=10，4B=11。 */
    if ((Row->flags & KSWORD_ARK_HVM_NOATTACH_BP_SIZE_2) != 0UL) { len = 1ULL; }
    else if ((Row->flags & KSWORD_ARK_HVM_NOATTACH_BP_SIZE_8) != 0UL) { len = 2ULL; }
    else if ((Row->flags & KSWORD_ARK_HVM_NOATTACH_BP_SIZE_4) != 0UL) { len = 3ULL; }
    /* 高位先 LEN、低位先 R/W，汇合成 4 位 DR7 字段。 */
    return rw | (len << 2);
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
        /* 关闭和一次性消费都只撤销自己的执行或观察断点。 */
        if (Restore || (row->flags & KSWORD_ARK_HVM_NOATTACH_BP_CONSUMED) != 0UL)
        {
            /* 外部把同槽改成另一地址或类型/长度时不盲目覆盖。 */
            ULONGLONG expected = KnaRwLenBits(row) << (16UL + i * 4UL);
            if (*KnaDr(Context, i) == row->address &&
                (Context->Dr7 & (15ULL << (16UL + i * 4UL))) == expected)
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
            /* 执行断点为 R/W=0 LEN=0；观察点由行 flags 推导。 */
            ULONGLONG rwLen = KnaRwLenBits(row);
            /* 真实地址写入对应 DR0..DR3。 */
            *KnaDr(Context, i) = row->address;
            /* 只占本会话自己的本地槽位，按需携带 R/W+LEN。 */
            Context->Dr7 = (Context->Dr7 & ~mask) | (1ULL << (i * 2UL)) |
                           (rwLen << (16UL + i * 4UL)) | 0x400ULL;
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
        if (row->id == 0UL || (row->flags & KSWORD_ARK_HVM_NOATTACH_BP_CONSUMED) != 0UL) { continue; }
        /* 共用条件：该槽实际命中且地址未被外部改写。 */
        if ((Context->Dr6 & (1ULL << i)) == 0ULL || *KnaDr(Context, i) != row->address) { continue; }
        /* 执行断点必须停在目标指令首字节；观察点触发时 RIP 指向访问指令末尾。 */
        if ((row->flags & KSWORD_ARK_HVM_NOATTACH_BP_WATCH_MASK) == 0UL && Context->Rip != row->address)
        { continue; }
        /* 该槽确实是本会话产生的真实停点。 */
        return i + 1UL;
    }
    /* 零意味着不是本会话的执行或观察断点。 */
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
        /* 内存观察不占 DR，可直接在控制路径清理；目标线程不需要参与提交。 */
        for (i = 0UL; i < 4UL; ++i)
        {
            if (g_Kna.MemoryWatches[i].id == Request->breakpointId && Request->breakpointId != 0UL)
            {
                /* 清空槽即时可用；R3 另行恢复页面保护。 */
                RtlZeroMemory(&g_Kna.MemoryWatches[i], sizeof(g_Kna.MemoryWatches[i]));
                return STATUS_SUCCESS;
            }
        }
        /* 不存在的 ID 不冒充删除成功。 */
        return STATUS_NOT_FOUND;
    }
    /* 内存观察走独立的存储和校验路径。 */
    if ((Request->breakpointFlags & KSWORD_ARK_HVM_NOATTACH_BP_MEMORY_WATCH) != 0UL)
    {
        const ULONG memoryAccepted = KSWORD_ARK_HVM_NOATTACH_BP_MEMORY_WATCH |
                                     KSWORD_ARK_HVM_NOATTACH_BP_MEMORY_TYPE_MASK;
        const ULONG types = Request->breakpointFlags & KSWORD_ARK_HVM_NOATTACH_BP_MEMORY_TYPE_MASK;
        /* 至多一位访问类型，未设任何位表示任意访问。 */
        const BOOLEAN typeConflict = types != 0UL && (types & (types - 1UL)) != 0UL;
        /* 一次性运行到地址不属于内存观察语义。 */
        if (Request->operation == KSWORD_ARK_HVM_NOATTACH_RUN_TO ||
            (Request->breakpointFlags & ~memoryAccepted) != 0UL || typeConflict ||
            Request->address == 0ULL || Request->minimumRsp == 0ULL ||
            Request->address > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress ||
            Request->minimumRsp > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress ||
            Request->address + Request->minimumRsp < Request->address ||
            Request->address + Request->minimumRsp - 1ULL > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress)
        { return STATUS_INVALID_PARAMETER; }
        /* 四条内存观察容量和与其它观察的重叠分别核对。 */
        for (i = 0UL; i < 4UL; ++i)
        {
            if (g_Kna.MemoryWatches[i].id != 0UL)
            {
                const ULONGLONG aStart = g_Kna.MemoryWatches[i].address;
                const ULONGLONG aEnd = aStart + g_Kna.MemoryWatches[i].minimumRsp;
                const ULONGLONG bStart = Request->address;
                const ULONGLONG bEnd = bStart + Request->minimumRsp;
                /* 重叠区间不允许静默覆盖旧配置。 */
                if (aStart < bEnd && bStart < aEnd) { return STATUS_OBJECT_NAME_COLLISION; }
            }
            if (g_Kna.MemoryWatches[i].id == 0UL && freeSlot == 4UL) { freeSlot = i; }
        }
        /* 容量不足保留旧配置。 */
        if (freeSlot == 4UL) { return STATUS_INSUFFICIENT_RESOURCES; }
        /* 非零 ID，不复用。 */
        if (++g_Kna.NextId == 0UL) { ++g_Kna.NextId; }
        g_Kna.MemoryWatches[freeSlot].id = g_Kna.NextId;
        /* 仅保存请求的 flags 组合；未设任何类型位表示任意访问。 */
        g_Kna.MemoryWatches[freeSlot].flags = Request->breakpointFlags;
        g_Kna.MemoryWatches[freeSlot].address = Request->address;
        /* 内存观察不固定物理页。 */
        g_Kna.MemoryWatches[freeSlot].physicalPage = 0ULL;
        /* 复用 minimumRsp 字段存储观察范围长度。 */
        g_Kna.MemoryWatches[freeSlot].minimumRsp = Request->minimumRsp;
        return STATUS_SUCCESS;
    }
    /* 允许的位集合：执行断点语义 + 观察点类型 + 观察点宽度。 */
    const ULONG accepted = KSWORD_ARK_HVM_NOATTACH_BP_ONESHOT |
                           KSWORD_ARK_HVM_NOATTACH_BP_STACK_FILTER |
                           KSWORD_ARK_HVM_NOATTACH_BP_WATCH_MASK |
                           KSWORD_ARK_HVM_NOATTACH_BP_SIZE_MASK;
    /* WATCH_WRITE 与 WATCH_READWRITE 互斥。 */
    const BOOLEAN watchConflict =
        (Request->breakpointFlags & KSWORD_ARK_HVM_NOATTACH_BP_WATCH_WRITE) != 0UL &&
        (Request->breakpointFlags & KSWORD_ARK_HVM_NOATTACH_BP_WATCH_READWRITE) != 0UL;
    /* 单一观察点宽度；至多一位。 */
    const ULONG sizeBits = Request->breakpointFlags & KSWORD_ARK_HVM_NOATTACH_BP_SIZE_MASK;
    const BOOLEAN sizeConflict = sizeBits != 0UL && (sizeBits & (sizeBits - 1UL)) != 0UL;
    /* 宽度仅对观察点有意义；执行断点必须保持 LEN=0 以仅比较指令地址。 */
    const BOOLEAN sizeWithoutWatch = sizeBits != 0UL &&
        (Request->breakpointFlags & KSWORD_ARK_HVM_NOATTACH_BP_WATCH_MASK) == 0UL;
    /* 栈过滤只对执行断点有意义。 */
    const BOOLEAN stackWithWatch =
        (Request->breakpointFlags & KSWORD_ARK_HVM_NOATTACH_BP_STACK_FILTER) != 0UL &&
        (Request->breakpointFlags & KSWORD_ARK_HVM_NOATTACH_BP_WATCH_MASK) != 0UL;
    /* 只接受当前实现支持的用户态执行断点与观察点；所有组合限制在 pin 之前核对。 */
    if (Request->address == 0ULL || Request->address > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress ||
        (Request->breakpointFlags & ~accepted) != 0UL ||
        watchConflict || sizeConflict || sizeWithoutWatch || stackWithWatch ||
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
