#include "hvm_noattach.h"

/* 普通地址空间切换不创建 Windows 调试关系。 */
NTKERNELAPI VOID KeStackAttachProcess(PVOID Process, PVOID ApcState);
/* 与上面的不透明 attach state 成对归还。 */
NTKERNELAPI VOID KeUnstackDetachProcess(PVOID ApcState);
/* 所有 EPT 物理表指针必须来自分配台账。 */
#define NA_PHYSICAL 0x000FFFFFFFFFF000ULL

/* 只在普通控制面解析已知 EPT 表，绝不映射任意用户物理地址。 */
static ULONGLONG *NaTable(KSW_HVM_RUNTIME *Runtime, ULONGLONG Physical)
{
    /* 页台账在此会话常驻期间固定。 */
    ULONG i;
    /* 查询有界台账，不递归遍历映射。 */
    for (i = 0UL; i < Runtime->EptPageCount; ++i)
    {
        /* 只接受完整对齐的已分配表页。 */
        if ((ULONGLONG)Runtime->EptPages[i].PhysicalAddress.QuadPart == (Physical & NA_PHYSICAL))
        {
            /* 该指针的生命周期覆盖全部 resident CPU。 */
            return (ULONGLONG *)Runtime->EptPages[i].VirtualAddress;
        }
    }
    /* 台账以外的表绝不被猜测解引用。 */
    return NULL;
}

/* 在 inactive bank 复制一条路径；普通根和另一个 bank 始终不变。 */
static NTSTATUS NaRestrictPage(KSW_HVM_RUNTIME *Runtime, KSW_NA_BANK *Bank, ULONGLONG Physical)
{
    /* 所有地址最多经过四层固定循环。 */
    ULONGLONG *table = (ULONGLONG *)Bank->Pages[0].VirtualAddress;
    /* level 3/2/1 分别索引 PML4/PDPT/PD。 */
    LONG level;
    /* 不接受基础 EPT 窗口外的 backing。 */
    if (Physical >= Runtime->HighestMappedPhysicalAddress) { return STATUS_NOT_SUPPORTED; }
    /* 每层最多创建一个已预分配的子表。 */
    for (level = 3L; level > 0L; --level)
    {
        /* 单个 GPA 对应的索引来自体系结构位段。 */
        ULONG slot = (ULONG)((Physical >> (12L + 9L * level)) & 511ULL);
        /* 保存未变更的原权限和地址。 */
        ULONGLONG entry = table[slot];
        /* 子表若已属于此 bank，后续地址可复用它。 */
        ULONGLONG *child = NULL;
        /* 有界检查 bank 私有页归属。 */
        ULONG i;
        /* 空洞及原本禁止用户执行的页不能作为执行断点。 */
        if ((entry & (KSW_EPT_READ | KSW_NOATTACH_USER_EXECUTE)) !=
            (KSW_EPT_READ | KSW_NOATTACH_USER_EXECUTE)) { return STATUS_NOT_SUPPORTED; }
        /* 大页并非下一层表，不得当作指针。 */
        if ((entry & 0x80ULL) == 0ULL)
        {
            /* 只在当前已用页集合中查找。 */
            for (i = 1UL; i < Bank->Used; ++i)
            {
                /* 同一分支上的多个断点共享一份私有子表。 */
                if ((ULONGLONG)Bank->Pages[i].PhysicalAddress.QuadPart == (entry & NA_PHYSICAL))
                {
                    /* 不再复制已经私有化的路径。 */
                    child = (ULONGLONG *)Bank->Pages[i].VirtualAddress;
                    /* 查找结束。 */
                    break;
                }
            }
        }
        /* 首次分叉必须保留所有相邻 GPA 的原语义。 */
        if (child == NULL)
        {
            /* 资源在 OPEN 前就预留，实时变更不分配 EPT 页。 */
            KSW_HVM_EPT_PAGE *page;
            /* 拒绝无法完整表示的新配置。 */
            if (Bank->Used >= KSW_NA_BANK_PAGES) { return STATUS_INSUFFICIENT_RESOURCES; }
            /* 取得一个仅 inactive bank 可以写的页面。 */
            page = &Bank->Pages[Bank->Used++];
            /* 页指针已经由普通准备路径验证。 */
            child = (ULONGLONG *)page->VirtualAddress;
            /* 1 GiB/2 MiB 叶子要先拆分，内存类型与其余权限保持不变。 */
            if ((entry & 0x80ULL) != 0ULL)
            {
                /* PML4 不允许大页编码。 */
                ULONG shift = (ULONG)(12L + 9L * (level - 1L));
                /* 除物理基址和大页标志外完整继承叶子属性。 */
                ULONGLONG flags = entry & ~(NA_PHYSICAL | 0x80ULL);
                /* 非法层级不能被修补为普通映射。 */
                if (level == 3L) { return STATUS_INVALID_DEVICE_STATE; }
                /* PDPT 的 1 GiB 叶子拆成 2 MiB 大页。 */
                if (level == 2L) { flags |= 0x80ULL; }
                /* 每个相邻叶子仍指向原有物理页。 */
                for (i = 0UL; i < 512UL; ++i)
                {
                    /* 不改变 MTRR 内存类型、A/D 或 suppress-VE 属性。 */
                    child[i] = ((entry & NA_PHYSICAL) + ((ULONGLONG)i << shift)) | flags;
                }
            }
            else
            {
                /* 基础映射中的非叶子表只能经台账解析。 */
                ULONGLONG *source = NaTable(Runtime, entry);
                /* 未知表拒绝安装。 */
                if (source == NULL) { return STATUS_INVALID_DEVICE_STATE; }
                /* 普通根表的并发硬件 A/D 仅为遥测，不作为授权判断。 */
                RtlCopyMemory(child, source, PAGE_SIZE);
            }
            /* 父指针只保留合法非叶子位，不携带大页内存类型。 */
            table[slot] = (ULONGLONG)page->PhysicalAddress.QuadPart |
                          (entry & (7ULL | KSW_NOATTACH_USER_EXECUTE | (1ULL << 8) | (1ULL << 63)));
        }
        /* 继续处理此 GPA 的下一层索引。 */
        table = child;
    }
    /* 仅禁止该物理页的用户执行，读写与 supervisor 执行保持原样。 */
    table[(Physical >> 12) & 511ULL] &= ~KSW_NOATTACH_USER_EXECUTE;
    /* 全部修改发生在尚未发布的 bank。 */
    return STATUS_SUCCESS;
}

NTSTATUS KswordARKHvmNoAttachPrepareBanks(KSW_HVM_RUNTIME *Runtime)
{
    /* 本函数只在没有 resident CPU 的准备阶段调用。 */
    ULONG bank, page;
    /* 每次新会话以全新 CPU context 观察新的代次。 */
    g_KswordNoAttach.BankGeneration = 1ULL;
    /* 两套预分配表可在停点之间交替重建。 */
    for (bank = 0UL; bank < 2UL; ++bank)
    {
        /* 旧会话元数据已经在全核退出后失效。 */
        KSW_NA_BANK *view = &g_KswordNoAttach.Banks[bank];
        /* 不保留上一次生命周期的表指针。 */
        RtlZeroMemory(view, sizeof(*view));
        /* 分配由统一 EPT 台账拥有的全部私有页面。 */
        for (page = 0UL; page < KSW_NA_BANK_PAGES; ++page)
        {
            /* 任何分配失败都由原有准备失败路径统一退休。 */
            view->Pages[page].VirtualAddress =
                KswordARKHvmAllocateEptPageLocked(Runtime, &view->Pages[page].PhysicalAddress);
            /* 不发布不完整的 bank。 */
            if (view->Pages[page].VirtualAddress == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
        }
        /* 初始配置没有断点，因此完整继承普通映射。 */
        RtlCopyMemory(view->Pages[0].VirtualAddress, Runtime->EptPml4, PAGE_SIZE);
        /* 即使空 bank，根页仍计入私有路径。 */
        view->Used = 1UL;
        /* 新 CPU 首次使用前须分别核对该配置代次。 */
        view->Generation = 1ULL;
        /* 沿用基础 EPTP 的内存类型、walk 长度与 A/D 选项。 */
        view->Eptp = (Runtime->EptPointer & ~NA_PHYSICAL) |
                     (ULONGLONG)view->Pages[0].PhysicalAddress.QuadPart;
    }
    /* 只有完整的双 bank 才能进入常驻。 */
    InterlockedExchange(&g_KswordNoAttach.ActiveBank, 0L);
    /* 源码准备成功不代表硬件运行验收。 */
    return STATUS_SUCCESS;
}

/* pin 只读原 backing，不写入目标代码或触发主动 COW。 */
static NTSTATUS NaProbe(ULONGLONG Address, PMDL *Descriptor, ULONGLONG *Physical)
{
    /* 用同一 MDL 同时证明驻留和 backing 身份。 */
    PMDL mdl;
    /* 不依赖 KAPC_STATE 的私有布局。 */
    DECLSPEC_ALIGN(16) UCHAR attach[128];
    /* 异常路径只解除成功取得的锁。 */
    NTSTATUS status = STATUS_SUCCESS;
    /* 单字节 pin 不会跨页。 */
    mdl = IoAllocateMdl((PVOID)(ULONG_PTR)Address, 1UL, FALSE, FALSE, NULL);
    /* 页描述符分配失败无副作用。 */
    if (mdl == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* 将地址解释限定为已引用的目标进程。 */
    KeStackAttachProcess(g_KswordNoAttach.Process, attach);
    /* 用户探测异常不能越过 attach 的归还。 */
    __try
    {
        /* 只取得读权限；断点不修改用户页权限。 */
        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        /* 保留探测失败的真实 NTSTATUS。 */
        status = GetExceptionCode();
    }
    /* 无论探测结果如何都恢复调用者地址空间。 */
    KeUnstackDetachProcess(attach);
    /* 失败的探测不拥有锁页引用。 */
    if (!NT_SUCCESS(status)) { IoFreeMdl(mdl); return status; }
    /* MDL 页数组提供此次 pin 的权威 PFN。 */
    *Physical = ((ULONGLONG)MmGetMdlPfnArray(mdl)[0]) << PAGE_SHIFT;
    /* 调用者明确持有或对称释放此次成功的锁页引用。 */
    *Descriptor = mdl;
    /* 不保留目标地址空间切换。 */
    return STATUS_SUCCESS;
}

/* 新增断点保留 backing pin 到整个硬件生命周期结束。 */
static NTSTATUS NaPin(ULONGLONG Address, ULONGLONG *Physical)
{
    /* 此路径从不读取尚未初始化的 MDL。 */
    PMDL mdl = NULL;
    /* pin 资源总量单独受会话容量约束。 */
    NTSTATUS status;
    /* 旧物理页不能为了新安装提前释放。 */
    if (g_KswordNoAttach.PinCount >= KSW_NA_MAX_PINS) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* 锁定与读取 PFN 由同一份 MDL 完成。 */
    status = NaProbe(Address, &mdl, Physical);
    /* 失败不保留任何未取得的引用。 */
    if (!NT_SUCCESS(status)) { return status; }
    /* 新引用在完整硬件退出后统一清理。 */
    g_KswordNoAttach.Pins[g_KswordNoAttach.PinCount].Mdl = mdl;
    /* 保存页面粒度的映射身份。 */
    g_KswordNoAttach.Pins[g_KswordNoAttach.PinCount].Address = Address & ~0xFFFULL;
    /* 保存锁定 backing。 */
    g_KswordNoAttach.Pins[g_KswordNoAttach.PinCount].Physical = *Physical;
    /* 最后发布已拥有引用数量。 */
    ++g_KswordNoAttach.PinCount;
    /* 实际有效性仍在查询和命中处分别复核。 */
    return STATUS_SUCCESS;
}

NTSTATUS KswordARKHvmNoAttachEditBreakpoint(const KSWORD_ARK_HVM_NOATTACH_REQUEST *Request)
{
    /* 控制锁确保前一次发布的全核屏障已经完成。 */
    LONG current = InterlockedCompareExchange(&g_KswordNoAttach.ActiveBank, 0L, 0L);
    /* 活动配置不可原地编辑。 */
    KSW_NA_BANK *old = &g_KswordNoAttach.Banks[current];
    /* 仅重建已确认没有任何 CPU 使用的 bank。 */
    KSW_NA_BANK *next = &g_KswordNoAttach.Banks[1L - current];
    /* 普通运行时页台账保持固定。 */
    KSW_HVM_RUNTIME *runtime = KswordARKHvmGetRuntime();
    /* 删除按 ID 核对，不存在不能冒充成功。 */
    BOOLEAN found = FALSE;
    /* 保留每个地址/资源错误。 */
    NTSTATUS status;
    /* 所有遍历均受公开容量限制。 */
    ULONG i;
    /* 未使用的新根不能带上旧配置状态。 */
    next->Count = 0UL;
    /* 整个 inactive bank 从普通映射重新构造。 */
    next->Used = 1UL;
    /* 旧行消费位仅属于上一代配置。 */
    next->Disabled = next->Stale = 0L;
    /* 复制正常映射不会放宽任何活动处理器的权限。 */
    RtlCopyMemory(next->Pages[0].VirtualAddress, runtime->EptPml4, PAGE_SIZE);
    /* 保留所有未删除且未被一次性消费的有效断点。 */
    for (i = 0UL; i < old->Count; ++i)
    {
        /* 删除只能指定确切的驱动分配 ID。 */
        if (Request->operation == KSWORD_ARK_HVM_NOATTACH_REMOVE_BREAKPOINT &&
            old->Rows[i].id == Request->breakpointId) { found = TRUE; continue; }
        /* 一次性消费和失效行在下一次编辑时退休。 */
        if ((old->Disabled & (1L << i)) != 0L) { continue; }
        /* 复制完整不可变过滤条件。 */
        next->Rows[next->Count++] = old->Rows[i];
    }
    /* 不存在的 ID 不产生配置发布。 */
    if (Request->operation == KSWORD_ARK_HVM_NOATTACH_REMOVE_BREAKPOINT && !found)
    { return STATUS_NOT_FOUND; }
    /* 其它编辑操作均为新增或一次性运行。 */
    if (Request->operation != KSWORD_ARK_HVM_NOATTACH_REMOVE_BREAKPOINT)
    {
        /* 当前 x64 版本只接受用户空间精确执行地址。 */
        KSWORD_ARK_HVM_NOATTACH_BREAKPOINT *row;
        /* 地址、容量和所有保留位必须在 pin 之前核对。 */
        if (Request->address == 0ULL || Request->address > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress ||
            (Request->breakpointFlags & ~(KSWORD_ARK_HVM_NOATTACH_BP_ONESHOT |
                                         KSWORD_ARK_HVM_NOATTACH_BP_STACK_FILTER)) != 0UL ||
            next->Count >= KSWORD_ARK_HVM_NOATTACH_MAX_BREAKPOINTS)
        { return STATUS_INVALID_PARAMETER; }
        /* 相同地址不能悄悄叠加另一套一次性/永久语义。 */
        for (i = 0UL; i < next->Count; ++i)
        {
            /* 明确要求先删除旧地址断点。 */
            if (next->Rows[i].address == Request->address) { return STATUS_OBJECT_NAME_COLLISION; }
        }
        /* 在尚未发布的行中建立 backing。 */
        row = &next->Rows[next->Count];
        /* 读取并固定真实物理页，不依赖历史页表缓存。 */
        status = NaPin(Request->address, &row->physicalPage);
        /* pin 失败不影响旧 bank。 */
        if (!NT_SUCCESS(status)) { return status; }
        /* ID 不复用，旧删除命令不能删除新记录。 */
        row->id = ++g_KswordNoAttach.NextBreakpointId;
        /* 零作为无命中的唯一哨兵。 */
        if (row->id == 0UL) { row->id = ++g_KswordNoAttach.NextBreakpointId; }
        /* 保留请求时冻结的虚拟地址。 */
        row->address = Request->address;
        /* RUN_TO 的一次性语义由驱动强制，不能由前端漏传。 */
        row->flags = Request->breakpointFlags |
                     (Request->operation == KSWORD_ARK_HVM_NOATTACH_RUN_TO ? KSWORD_ARK_HVM_NOATTACH_BP_ONESHOT : 0UL);
        /* 栈过滤只在显式请求时有效。 */
        row->minimumRsp = Request->minimumRsp;
        /* 最后才计入完整配置。 */
        ++next->Count;
    }
    /* 为每个活动页构造独立的执行权限路径。 */
    for (i = 0UL; i < next->Count; ++i)
    {
        /* 相邻页和普通根不接受任何原地修改。 */
        status = NaRestrictPage(runtime, next, next->Rows[i].physicalPage);
        /* 一条路径失败就保留原活动配置。 */
        if (!NT_SUCCESS(status)) { return status; }
    }
    /* 新代次保证重用同一物理根时逐核失效旧缓存。 */
    next->Generation = ++g_KswordNoAttach.BankGeneration;
    /* 发布索引前确保表和过滤行全部可见。 */
    KeMemoryBarrier();
    /* 原子切换到完整配置。 */
    InterlockedExchange(&g_KswordNoAttach.ActiveBank, 1L - current);
    /* 全部 CPU 观察新 bank 后旧 bank 才能在下一次编辑中重用。 */
    status = KswordARKHvmNoAttachRendezvous(runtime);
    /* 屏障失败时不能继续重用表页或伪称修改成功。 */
    if (!NT_SUCCESS(status))
    {
        /* 立即撤销执行控制，保留全部资源供 CLOSE 恢复。 */
        InterlockedExchange(&g_KswordNoAttach.Enabled, 0L);
        /* 不覆盖为普通运行状态。 */
        InterlockedExchange(&g_KswordNoAttach.State, KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED);
    }
    /* 返回实际全核传播结果。 */
    return status;
}

VOID KswordARKHvmNoAttachQueryBreakpoints(KSWORD_ARK_HVM_NOATTACH_RESPONSE *Response)
{
    /* 控制锁阻止此读取期间 bank 复用。 */
    KSW_NA_BANK *bank = &g_KswordNoAttach.Banks[InterlockedCompareExchange(&g_KswordNoAttach.ActiveBank, 0L, 0L)];
    /* 同一活动 bank 的 disabled 位可能由根模式撤销。 */
    ULONG i;
    /* 返回完整配置，区分已消费和仍有效记录。 */
    Response->breakpointCount = bank->Count;
    /* 每次查询重新核对 VA/PFN，映射变化绝不默默绑定到新代码。 */
    for (i = 0UL; i < bank->Count; ++i)
    {
        /* 只对仍有效的行进行普通内核查询。 */
        if ((bank->Disabled & (1L << i)) == 0L)
        {
            /* 用户 VA 可能已解除映射，必须由可捕获异常的探测取得真实 PFN。 */
            PMDL current = NULL;
            /* 临时 MDL 提供这次查询的权威 backing。 */
            ULONGLONG physical = 0ULL;
            /* 普通控制路径只读探测，不写代码或页面保护。 */
            NTSTATUS status = NaProbe(bank->Rows[i].address, &current, &physical);
            /* 不在查询间累计临时页面锁。 */
            if (NT_SUCCESS(status)) { MmUnlockPages(current); IoFreeMdl(current); }
            /* 缺页/解除映射/重新映射都不能悄悄授权新物理页。 */
            if (!NT_SUCCESS(status) || physical != bank->Rows[i].physicalPage)
            {
                /* 先标记失效原因，随后撤销命中资格。 */
                InterlockedOr(&bank->Stale, 1L << i);
                /* 旧物理页仍保留 pin，直到完整全核退出。 */
                InterlockedOr(&bank->Disabled, 1L << i);
            }
        }
        /* 所有前端消费相同的配置文档。 */
        Response->breakpoints[i] = bank->Rows[i];
        /* 消费位不伪装成断点已被物理删除。 */
        if ((bank->Disabled & (1L << i)) != 0L)
        {
            /* 失效与一次性命中有不同恢复方式。 */
            Response->breakpoints[i].flags |= (bank->Stale & (1L << i)) != 0L
                ? KSWORD_ARK_HVM_NOATTACH_BP_STALE : KSWORD_ARK_HVM_NOATTACH_BP_CONSUMED;
        }
    }
}

VOID KswordARKHvmNoAttachReleasePins(VOID)
{
    /* 本函数只能在完整 VMXOFF 后调用。 */
    ULONG i;
    /* 统一退休此会话累计的页面锁。 */
    for (i = 0UL; i < g_KswordNoAttach.PinCount; ++i)
    {
        /* 每条记录只保存成功取得的锁。 */
        MmUnlockPages(g_KswordNoAttach.Pins[i].Mdl);
        /* 对称释放描述符。 */
        IoFreeMdl(g_KswordNoAttach.Pins[i].Mdl);
    }
    /* 不让新会话沿用旧页面身份。 */
    RtlZeroMemory(g_KswordNoAttach.Pins, sizeof(g_KswordNoAttach.Pins));
    /* 全部引用已释放。 */
    g_KswordNoAttach.PinCount = 0UL;
}
