/*
 * hvm_ept_switch.c
 *
 * 「切 EPTP」分离视图后端的**带副作用**的一半：页池、台账、释放。
 *
 * 纯算术住在 shared/driver/KswordArkHvmEptSwitch.h，与宿主机单测共用同一份
 * 实现。本文件刻意不重算任何一个位域 —— 一旦这里自己算一遍，两份算术就会
 * 各自漂移，而这一类错误没有诊断面（叶项保留位没清干净只表现为一次 exit
 * reason 49，索引差一格只表现为某一页永久停在影子上而所有自检全绿）。
 */

#include "hvm_ept_switch.h"

#include "driver/KswordArkHvmEptSwitch.h"

#include "../../platform/pool_compat.h"

#define KSW_HVM_EPTSW_POOL_TAG 'SvHK'

/*
 * 页池上限。
 *
 * 共享基座模式下总开销与处理器数**无关**：32 叶 × 4 页 = 128 页 = 512 KiB，
 * 不管机器有 1 个核还是 256 个核。这个上限留了一倍余量，纯粹是为了让「有人把
 * 基座数改成按核计费」这种改动在小机器上就撞墙，而不是等到大机器上才拒绝启动。
 */
#define KSW_HVM_EPTSW_MAX_PAGES 256ULL

/*
 * 每一张已安装的视图恰好占用一个层次索引，所以这两个上限**必须相等**。
 *
 * 不相等时两个方向都没有诊断面：视图表更大 ⇒ 存在装得上却切不过去的视图，
 * 那一页毫无保护而自检全绿；层次表更大 ⇒ 白占页。
 *
 * hvm_ept_local.h 的 KSW_HVM_MAX_LOCAL_LEAVES(8) **不参与**这里的取小：
 * 那是每处理器私有层次的预算，而两套机制在协议层就互斥，永不共存。
 */
C_ASSERT(KSWORD_ARK_HVM_EPTSW_MAX_LEAVES == KSWORD_ARK_HVM_MAX_VIEWS);
/*
 * hvm_internal.h 把路径页数写成字面量以避免把整个算术头拉进每个 TU。
 * 这一条就是那个字面量与共享头之间的唯一纽带 —— 任一侧改动都会断构建，
 * 而不是安静地各算各的。
 */
C_ASSERT(KSW_HVM_EPTSW_PATH_PAGES == KSWORD_ARK_HVM_EPTSW_PATH_PAGES);
/* 台账数组必须放得下「基座 + 每叶一套」里的每叶一套。 */
C_ASSERT(RTL_NUMBER_OF(((KSW_HVM_EPTSW*)0)->Hierarchies) ==
         KSWORD_ARK_HVM_EPTSW_MAX_LEAVES);
/* 扁平 EPTP 表必须正好是「基座 + 每叶一套」，切换规划器会核这个长度。 */
C_ASSERT(RTL_NUMBER_OF(((KSW_HVM_EPTSW*)0)->Eptp) ==
         KSWORD_ARK_HVM_EPTSW_MAX_LEAVES + 1UL);

/*
 * 共享算术头点名要求集成方补的五条镜像断言（KswordArkHvmEptSwitch.h:1371）。
 *
 * 两套常量今天数值相同，但它们**来自不同的头、由不同的理由维护**。任一侧改了
 * 而另一侧没跟，切换规划器就会拿「读」的判据去服务一次写，或者拿 CLOAK 的
 * 权限去服务一张 HOOK 页 —— 挑中错误的层次，而那没有任何症状：视图还在、
 * 驱动还在跑、自检全绿，只是被保护的那一页对某一类访问永远给错内容。
 */
C_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_READ ==
         KSWORD_ARK_HVM_EPT_ACCESS_READ);
C_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE ==
         KSWORD_ARK_HVM_EPT_ACCESS_WRITE);
C_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE ==
         KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE);
C_ASSERT(KSWORD_ARK_HVM_EPTSW_KIND_CLOAK ==
         KSWORD_ARK_HVM_VIEW_KIND_CLOAK);
C_ASSERT(KSWORD_ARK_HVM_EPTSW_KIND_HOOK ==
         KSWORD_ARK_HVM_VIEW_KIND_HOOK);

/*
 * 本机物理地址位宽。
 *
 * 良构判据要用它算页帧的合法掩码。照 hvm_ept_builder.c:222-232 的同一套读法与
 * 同一组边界，不另立一套 —— 两处对「多少位算合法」的看法一旦分叉，表现是某台
 * 机器上建出来的层次自己认为合法而处理器判它误配。
 * 读不到就返回 0，调用方据此拒绝，而不是拿一个猜的宽度继续。
 */
static ULONG
KswordARKHvmEptSwitchPhysicalAddressBits(VOID)
{
    int cpuInfo[4] = { 0 };
    ULONG bits = 0UL;

    __cpuid(cpuInfo, (int)0x80000000UL);
    /* Refuse when the extended leaf carrying the width does not exist. */
    if ((ULONG)cpuInfo[0] < 0x80000008UL) {
        /* Return zero so the caller refuses rather than guesses. */
        return 0UL;
    }
    __cpuid(cpuInfo, (int)0x80000008UL);
    bits = (ULONG)cpuInfo[0] & 0xFFUL;
    /* Refuse a width no real processor reports. */
    if (bits < 32UL || bits > 52UL) {
        /* Return zero so the caller refuses rather than guesses. */
        return 0UL;
    }
    return bits;
}

/*
 * 取记录 i 的第 level 页。
 *
 * 固定切片而不是游标：一条视图可以被任意顺序装卸，游标下的释放要么泄漏那四页、
 * 要么把池打碎。切片让释放精确、复用免费，代价是一次性把池占满 —— 而那是
 * 512 KiB 且与处理器数无关。
 */
static PVOID
KswordARKHvmEptSwitchPage(
    _In_ const KSW_HVM_EPTSW* State,
    _In_ ULONG Record,
    _In_ ULONG Level,
    _Out_ PHYSICAL_ADDRESS* PhysicalAddress
    )
{
    ULONG page = 0UL;
    PVOID virtualAddress = NULL;

    PhysicalAddress->QuadPart = 0LL;
    /* Refuse an index the pool cannot back rather than running past it. */
    if (State->PageBlock == NULL ||
        Record >= State->LeafCapacity ||
        Level >= KSW_HVM_EPTSW_PATH_PAGES) {
        /* Return no page for an inadmissible request. */
        return NULL;
    }
    page = (Record * KSW_HVM_EPTSW_PATH_PAGES) + Level;
    if (page >= State->PageCount) {
        /* Return no page rather than running past the block. */
        return NULL;
    }
    virtualAddress = State->PageBlock + ((SIZE_T)page * (SIZE_T)PAGE_SIZE);
    *PhysicalAddress = MmGetPhysicalAddress(virtualAddress);
    /* Refuse a page whose physical address could not be resolved. */
    if (PhysicalAddress->QuadPart == 0LL) {
        /* Return no page rather than publishing address zero. */
        return NULL;
    }
    /* Return the page for the caller to fill. */
    return virtualAddress;
}

NTSTATUS
KswordARKHvmEptSwitchBuildLeaf(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG LeafPhysical,
    _In_ ULONGLONG PrimaryEntry,
    _In_ ULONGLONG SecondaryEntry,
    _In_ const volatile ULONGLONG* SharedPageTable,
    _Out_ ULONG* HierarchyIndex
    )
{
    KSW_HVM_EPTSW* state = NULL;
    KSW_HVM_EPTSW_HIERARCHY* record = NULL;
    PHYSICAL_ADDRESS physical[KSW_HVM_EPTSW_PATH_PAGES];
    PVOID level[KSW_HVM_EPTSW_PATH_PAGES];
    ULONGLONG* table = NULL;
    const ULONGLONG* sharedPml4 = NULL;
    const ULONGLONG* sharedPdpt = NULL;
    const ULONGLONG* sharedPd = NULL;
    ULONG pml4Index = 0UL;
    ULONG pdptIndex = 0UL;
    ULONG pdIndex = 0UL;
    ULONG ptIndex = 0UL;
    ULONG slot = 0UL;
    ULONG walk = 0UL;
    ULONG physicalBits = 0UL;

    /* Reject an incomplete caller contract before touching the pool. */
    if (Runtime == NULL ||
        HierarchyIndex == NULL ||
        SharedPageTable == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *HierarchyIndex = KSWORD_ARK_HVM_EPTSW_INDEX_BASE;
    state = &Runtime->EptSwitch;
    /* Only a reserved pool has anything to build into. */
    if (!state->Active || state->PageBlock == NULL) {
        /* Return the exact state-contract failure. */
        return STATUS_DEVICE_NOT_READY;
    }
    RtlZeroMemory(physical, sizeof(physical));
    RtlZeroMemory(level, sizeof(level));
    pml4Index = KswordArkHvmEptSwPml4Index(LeafPhysical);
    pdptIndex = KswordArkHvmEptSwPdptIndex(LeafPhysical);
    pdIndex = KswordArkHvmEptSwPdIndex(LeafPhysical);
    ptIndex = KswordArkHvmEptSwPtIndex(LeafPhysical);
    /*
     * Refuse a target the base hierarchy never populated.  Building a path
     * onto absent tables would produce a hierarchy that walks into zero
     * entries - an EPT misconfiguration whose exit tells you a bit is wrong
     * without telling you which.
     */
    if (pml4Index >= KSW_HVM_MAX_PML4_ENTRIES ||
        pdptIndex >= 512UL ||
        Runtime->EptPml4 == NULL ||
        Runtime->EptPdpt[pml4Index] == NULL ||
        Runtime->EptPd[pml4Index][pdptIndex] == NULL) {
        /* Return the exact hierarchy-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Take the first free record; its pages are implied by its index. */
    for (slot = 0UL; slot < state->LeafCapacity; ++slot) {
        if (!state->Hierarchies[slot].Active) {
            record = &state->Hierarchies[slot];
            break;
        }
    }
    /* Report bounded capacity exhaustion. */
    if (record == NULL) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Resolve every page of this record's slice before writing any of them. */
    for (walk = 0UL; walk < KSW_HVM_EPTSW_PATH_PAGES; ++walk) {
        level[walk] = KswordARKHvmEptSwitchPage(
            state,
            slot,
            walk,
            &physical[walk]);
        if (level[walk] == NULL) {
            /* Return the exact bounded-resource failure. */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    sharedPml4 = (const ULONGLONG*)Runtime->EptPml4;
    sharedPdpt = (const ULONGLONG*)Runtime->EptPdpt[pml4Index];
    sharedPd = (const ULONGLONG*)Runtime->EptPd[pml4Index][pdptIndex];
    /*
     * Copy each table wholesale, then repoint only the one entry on the path.
     * Everything the copies do not name stays shared with the base, which is
     * what keeps the cost four pages instead of a second full hierarchy - and
     * what makes "only this leaf differs" true by construction rather than by
     * an invariant somebody has to maintain.
     */
    RtlCopyMemory(level[0], sharedPml4, (SIZE_T)PAGE_SIZE);
    RtlCopyMemory(level[1], sharedPdpt, (SIZE_T)PAGE_SIZE);
    RtlCopyMemory(level[2], sharedPd, (SIZE_T)PAGE_SIZE);
    RtlCopyMemory(level[3], (const void*)SharedPageTable, (SIZE_T)PAGE_SIZE);
    /* Write the leaf first so no parent ever points at an unfinished table. */
    table = (ULONGLONG*)level[3];
    table[ptIndex] = SecondaryEntry;
    /* Repoint the copied parents child-first, for the same reason. */
    table = (ULONGLONG*)level[2];
    table[pdIndex] = KswordArkHvmEptRebaseEntry(
        sharedPd[pdIndex],
        (ULONGLONG)physical[3].QuadPart);
    table = (ULONGLONG*)level[1];
    table[pdptIndex] = KswordArkHvmEptRebaseEntry(
        sharedPdpt[pdptIndex],
        (ULONGLONG)physical[2].QuadPart);
    table = (ULONGLONG*)level[0];
    table[pml4Index] = KswordArkHvmEptRebaseEntry(
        sharedPml4[pml4Index],
        (ULONGLONG)physical[1].QuadPart);
    /*
     * Derive the pointer from the base rather than composing it.  Composing
     * would give the memory type, the walk length and the accessed/dirty bit
     * a second source of truth; derived this way it is accepted by VM entry
     * exactly when the base pointer is, and an INVEPT descriptor built from
     * it matches the field the processor was loaded with.
     */
    record->EptPointer = KswordArkHvmEptSwRebaseEptp(
        Runtime->EptPointer,
        (ULONGLONG)physical[0].QuadPart);
    /* Refuse a pointer the architecture would reject at VM entry. */
    physicalBits = KswordARKHvmEptSwitchPhysicalAddressBits();
    if (physicalBits == 0UL ||
        KswordArkHvmEptSwEptpIsWellFormed(
            record->EptPointer,
            Runtime->VmxEptVpidCapabilities,
            physicalBits) != KSWORD_ARK_HVM_EPTSW_EPTP_OK) {
        RtlZeroMemory(record, sizeof(*record));
        /* Return the exact encoding failure. */
        return STATUS_INVALID_PARAMETER;
    }
    record->LeafPhysical = LeafPhysical;
    record->PrimaryEntry = PrimaryEntry;
    record->SecondaryEntry = SecondaryEntry;
    for (walk = 0UL; walk < KSW_HVM_EPTSW_PATH_PAGES; ++walk) {
        record->Level[walk] = level[walk];
    }
    /* Publish into the flat ledger the switch planner indexes. */
    state->Eptp[slot + 1UL] = record->EptPointer;
    /* Published last, for the same reason as the pool's own Active flag. */
    record->Active = TRUE;
    state->BuiltCount += 1UL;
    /* Array index k-1 is hierarchy index k; index 0 is the base. */
    *HierarchyIndex = slot + 1UL;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmEptSwitchVerifyLeaf(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG HierarchyIndex
    )
{
    const KSW_HVM_EPTSW* state = NULL;
    const KSW_HVM_EPTSW_HIERARCHY* record = NULL;
    const ULONGLONG* table = NULL;
    ULONG slot = 0UL;
    ULONG physicalBits = 0UL;

    /* Reject an incomplete caller contract. */
    if (Runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    state = &Runtime->EptSwitch;
    /* The base is not a built hierarchy and has nothing to verify. */
    if (KswordArkHvmEptSwIndexIsBase(HierarchyIndex) ||
        HierarchyIndex > state->LeafCapacity) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    slot = HierarchyIndex - 1UL;
    record = &state->Hierarchies[slot];
    if (!record->Active) {
        /* Return the exact state-contract failure. */
        return STATUS_NOT_FOUND;
    }
    /*
     * Walk the built hierarchy the way the processor would and require the
     * target leaf to read back as the secondary value.
     *
     * This is not a tautology: the write above went through level[3], while
     * this walk starts at level[0] and follows the rebased parent entries.
     * An index computed one level off, or a parent rebased to the wrong page,
     * produces a walk that lands somewhere else - and that failure has no
     * other symptom, because the hierarchy is still structurally valid and
     * the processor would happily use it.
     */
    /*
     * 每一步一个**不同**的返回码。
     *
     * 五个检查共用一个码时，一次失败只告诉你「复核没过」，而定位它要么加日志
     * 要么上调试器 —— 而这是一条只在真机上、只在装视图那一刻走到的路径。
     * 这些码在这里纯作判别用，含义由这段注释规定，不要按它们的字面语义解读。
     */
    /*
     * 用掩码取地址，**不要**用 KswordArkHvmEptTablePointer ——
     * 那是个**构造器**（拿物理地址造出「地址 | RWX」的非叶项），不是提取器。
     * 拿它当提取器用，比较的左边永远多带 RWX 三位，于是这一条永远不成立，
     * 表现是「构造出来的层次一律复核不过」而构造本身其实是对的。已犯过一次。
     */
    table = (const ULONGLONG*)record->Level[0];
    if ((table[KswordArkHvmEptSwPml4Index(record->LeafPhysical)] &
            KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) !=
        ((ULONGLONG)MmGetPhysicalAddress(record->Level[1]).QuadPart &
            KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK)) {
        /* PML4 项没有指向本记录的 PDPT 副本。 */
        return STATUS_INVALID_ADDRESS;
    }
    table = (const ULONGLONG*)record->Level[1];
    if ((table[KswordArkHvmEptSwPdptIndex(record->LeafPhysical)] &
            KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) !=
        ((ULONGLONG)MmGetPhysicalAddress(record->Level[2]).QuadPart &
            KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK)) {
        /* PDPT 项没有指向本记录的 PD 副本。 */
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }
    table = (const ULONGLONG*)record->Level[2];
    if ((table[KswordArkHvmEptSwPdIndex(record->LeafPhysical)] &
            KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) !=
        ((ULONGLONG)MmGetPhysicalAddress(record->Level[3]).QuadPart &
            KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK)) {
        /* PD 项没有指向本记录的 PT 副本。 */
        return STATUS_INVALID_ADDRESS_WILDCARD;
    }
    table = (const ULONGLONG*)record->Level[3];
    if (table[KswordArkHvmEptSwPtIndex(record->LeafPhysical)] !=
        record->SecondaryEntry) {
        /* 叶项不是写进去的次值。 */
        return STATUS_DATA_ERROR;
    }
    /*
     * Refuse a leaf the architecture would reject as a misconfiguration.
     *
     * Not a large page: this backend only ever relaxes a four-KiB leaf, which
     * is why the caller had to split the covering two-MiB entry first.
     * Execute-only support is passed from the measured capability rather than
     * assumed - it is the whole premise of the backend, and a leaf that drops
     * READ without it is exactly the encoding the processor refuses.
     */
    physicalBits = KswordARKHvmEptSwitchPhysicalAddressBits();
    if (physicalBits == 0UL ||
        KswordArkHvmEptSwLeafIsWellFormed(
            record->SecondaryEntry,
            0,
            physicalBits,
            (Runtime->VmxEptVpidCapabilities &
                KSW_EPT_CAP_EXECUTE_ONLY) != 0ULL ? 1 : 0) !=
            KSWORD_ARK_HVM_EPTSW_LEAF_OK) {
        /* Return the exact encoding failure. */
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    return STATUS_SUCCESS;
}

VOID
KswordARKHvmEptSwitchReleaseLeaf(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG HierarchyIndex
    )
{
    KSW_HVM_EPTSW* state = NULL;
    KSW_HVM_EPTSW_HIERARCHY* record = NULL;

    /* Tolerate a missing runtime so every failure path can call this. */
    if (Runtime == NULL) {
        /* Return without touching anything. */
        return;
    }
    state = &Runtime->EptSwitch;
    /* Ignore the base and any index the ledger cannot name. */
    if (KswordArkHvmEptSwIndexIsBase(HierarchyIndex) ||
        HierarchyIndex > state->LeafCapacity) {
        /* Return without touching anything. */
        return;
    }
    record = &state->Hierarchies[HierarchyIndex - 1UL];
    if (!record->Active) {
        /* Return without double-counting a record already released. */
        return;
    }
    /*
     * The pages stay in the pool - this record owns a fixed slice of it - so
     * only the ledger is cleared.  Zeroed rather than flag-cleared: a stale
     * EptPointer would name a hierarchy nobody maintains any more, and the
     * one thing that must never happen is loading it.
     */
    RtlZeroMemory(record, sizeof(*record));
    /*
     * Clear the ledger slot in the same breath.  A pointer left here would
     * name a hierarchy whose record is gone, and the one thing that must
     * never happen is the processor being loaded with it.
     */
    state->Eptp[HierarchyIndex] = 0ULL;
    if (state->BuiltCount != 0UL) {
        state->BuiltCount -= 1UL;
    }
}

NTSTATUS
KswordARKHvmEptSwitchPlanViolation(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSWORD_ARK_HVM_EPTSW_PROGRESS* Progress,
    _In_ ULONG ActiveIndex,
    _In_ ULONG LeafSlot,
    _In_ ULONG Access,
    _In_ ULONG Kind,
    _In_ ULONGLONG GuestRip,
    _In_ ULONGLONG GuestPhysical,
    _Out_ ULONG* NextIndex,
    _Out_ ULONGLONG* TargetEptp
    )
{
    const KSW_HVM_EPTSW* state = NULL;
    KSWORD_ARK_HVM_EPTSW_TRANSITION transition;
    int executeOnly = 0;

    /* Reject an incomplete caller contract before deciding anything. */
    if (Runtime == NULL ||
        Progress == NULL ||
        NextIndex == NULL ||
        TargetEptp == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *NextIndex = KSWORD_ARK_HVM_EPTSW_INDEX_BASE;
    *TargetEptp = 0ULL;
    state = &Runtime->EptSwitch;
    /* Only a reserved runtime has a ledger to plan against. */
    if (!state->Active) {
        /* Return the exact state-contract failure. */
        return STATUS_DEVICE_NOT_READY;
    }
    RtlZeroMemory(&transition, sizeof(transition));
    executeOnly =
        (Runtime->VmxEptVpidCapabilities & KSW_EPT_CAP_EXECUTE_ONLY) != 0ULL
            ? 1
            : 0;
    /*
     * Decide and resolve in one shared-header call.  Nothing here re-derives
     * a permission or an index: the whole point of that header is that this
     * arithmetic has exactly one implementation, shared with the offline
     * tests, because every way of getting it wrong is symptomless at run time.
     */
    if (KswordArkHvmEptSwPlanSwitch(
            state->Eptp,
            state->HierarchyCount,
            ActiveIndex,
            LeafSlot,
            state->LeafCapacity,
            Access,
            Kind,
            executeOnly,
            &transition) != KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH) {
        /*
         * Refused.  Every refusal reason names a case that would otherwise be
         * a silent hang or a silent leak, so the caller must fail closed -
         * the same path a failed leaf flip takes today - rather than switch
         * anyway and hope the next exit resolves it.
         */
        return STATUS_NOT_SUPPORTED;
    }
    /*
     * Forward progress is a **precondition of the write**, stated as such by
     * the planner's contract.  It cannot be folded into the planner: that is
     * a pure function seeing one violation, and the combination that hangs -
     * an instruction whose fetch needs one leaf's secondary value while its
     * operand needs another's - has two halves that are each perfectly
     * serviceable.  The planner would return SWITCH forever while RIP never
     * advances, and the machine would stop with no bugcheck, no event and no
     * log.
     */
    if (!KswordArkHvmEptSwProgressAdmit(
            Progress,
            GuestRip,
            GuestPhysical,
            transition.NextIndex)) {
        /* Return the exact non-progress failure. */
        return STATUS_POSSIBLE_DEADLOCK;
    }
    *NextIndex = transition.NextIndex;
    *TargetEptp = transition.TargetEptp;
    return STATUS_SUCCESS;
}

VOID
KswordARKHvmEptSwitchRelease(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    KSW_HVM_EPTSW* state = NULL;

    /* Tolerate a missing runtime so teardown paths need no extra guard. */
    if (Runtime == NULL) {
        /* Return without touching anything. */
        return;
    }
    state = &Runtime->EptSwitch;
    /*
     * One allocation backs every hierarchy, so one free releases all of them.
     * ExFreePool is legal at DISPATCH_LEVEL, which matters because this runs
     * from a teardown path a power callback can reach.
     */
    if (state->PageBlock != NULL) {
        ExFreePool(state->PageBlock);
    }
    /*
     * Zero the whole record rather than clearing selected members.  A stale
     * EptPointer left behind here would be loaded by a later residency and
     * would name freed memory - a fault with no error path, because the
     * processor takes it during VM entry.
     */
    RtlZeroMemory(state, sizeof(*state));
}

NTSTATUS
KswordARKHvmEptSwitchReserve(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    KSW_HVM_EPTSW* state = NULL;
    ULONG leafCapacity = 0UL;
    ULONG hierarchyCount = 0UL;
    ULONG baseCount = 0UL;
    ULONGLONG pageCost = 0ULL;

    /* Reject an incomplete caller contract before allocating anything. */
    if (Runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    state = &Runtime->EptSwitch;
    /*
     * Refuse a second reservation rather than leaking the first.  The caller
     * is prepare, which already refuses to run while RESOURCES_READY is set,
     * so reaching here twice means an ordering bug worth surfacing.
     */
    if (state->Active) {
        /* Return the exact state-contract failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Only an armed runtime has anything to reserve. */
    if (!Runtime->EptpSwitchArmed) {
        /* Return the exact state-contract failure. */
        return STATUS_NOT_SUPPORTED;
    }
    /*
     * The base hierarchy must exist first: every secondary hierarchy is a
     * copy of one path through it, and its pointer is derived from the base
     * pointer rather than composed from constants.
     */
    if (Runtime->EptPointer == 0ULL || Runtime->EptPml4 == NULL) {
        /* Return the exact state-contract failure. */
        return STATUS_DEVICE_NOT_READY;
    }
    leafCapacity = KSWORD_ARK_HVM_EPTSW_MAX_LEAVES;
    /*
     * Shared base, so exactly one - and therefore the whole cost is
     * independent of the processor count.  Passed explicitly rather than
     * hard-coded to 1 so the composed case has one place to change if the
     * mutual exclusion with per-processor EPT is ever lifted.
     */
    baseCount = KswordArkHvmEptSwBaseCount(
        0,
        Runtime->ProcessorCount);
    hierarchyCount = KswordArkHvmEptSwHierarchyCount(leafCapacity);
    pageCost = KswordArkHvmEptSwSecondaryPageCost(
        baseCount,
        leafCapacity);
    /*
     * Both helpers report an inadmissible request as zero, which is why they
     * are checked before the budget rather than folded into it: zero fits any
     * budget, so a folded check would accept exactly the cases meant to be
     * refused.
     */
    if (hierarchyCount == 0UL || pageCost == 0ULL) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordArkHvmEptSwFitsBudget(
            pageCost,
            KSW_HVM_EPTSW_MAX_PAGES)) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Refuse a cost that cannot be expressed in the cursor's width. */
    if (pageCost > (ULONGLONG)MAXULONG) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* One allocation for every hierarchy, for the reason in the header. */
    state->PageBlock = (PUCHAR)KswordARKAllocateNonPagedPool(
        (SIZE_T)pageCost * (SIZE_T)PAGE_SIZE,
        KSW_HVM_EPTSW_POOL_TAG);
    if (state->PageBlock == NULL) {
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(
        state->PageBlock,
        (SIZE_T)pageCost * (SIZE_T)PAGE_SIZE);
    state->PageCount = (ULONG)pageCost;
    state->Reserved2 = 0UL;
    state->LeafCapacity = leafCapacity;
    state->HierarchyCount = hierarchyCount;
    state->BuiltCount = 0UL;
    /*
     * Slot 0 is the base, and it is the pointer the processor is already
     * running on.  Published here rather than at the first switch so the
     * ledger is complete the moment it exists: a planner that finds slot 0
     * empty would have to invent a "return to base" target, and inventing it
     * is exactly how the base and the VMCS come to disagree.
     */
    state->Eptp[KSWORD_ARK_HVM_EPTSW_INDEX_BASE] = Runtime->EptPointer;
    /*
     * Published last.  Every reader treats Active as "the page pool exists
     * and the ledger is consistent", so setting it before the fields above
     * would let a concurrent teardown free a block the ledger still counts.
     */
    state->Active = TRUE;
    return STATUS_SUCCESS;
}
