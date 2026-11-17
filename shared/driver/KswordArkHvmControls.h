/*
 * KswordArkHvmControls.h
 *
 * HVM 里那些"算错了不会报错、只会安静地做错事"的纯算术，集中放在这里。
 *
 * 为什么要单独拆出来：这些逻辑原本埋在依赖 WDK 的 .c 文件里，只能靠加载驱动
 * 才能验证——而加载驱动需要签名、需要一台没开 HVCI 的机器，出错的表现是蓝屏。
 * 把它们做成不依赖任何内核头的内联函数之后，驱动与 host 单测引用的是同一份
 * 实现（不是抄一遍，所以不会漂移），于是这部分正确性可以在编译机上直接证明。
 *
 * 收录标准只有一条：纯输入到输出、无副作用、算错了很难当场发现。
 * 例如 MSR 位图的四段偏移算错，策略就会打在另一个 MSR 上；自映射公式算错，
 * 就会去改一个不相干的页表项。这两种都不会立刻报错。
 *
 * 这个头文件同时被内核态 C 与用户态 C++ 包含，因此只使用固定宽度基本类型，
 * 不引用 WDK、CRT 或 Windows 头。
 */

#pragma once

/* ------------------------------------------------------------------ */
/* VMX 控制位夹取                                                       */
/* ------------------------------------------------------------------ */

/*
 * 按能力 MSR 夹取一组控制位。
 *
 * 能力 MSR 的低 32 位是 allowed-0（这些位必须为 1），高 32 位是 allowed-1
 * （只有这些位允许为 1）。所以正确做法永远是"先或上必须位，再与上允许位"，
 * 而不是直接写自己想要的值。
 *
 * 这在嵌套下尤其要命：外层 hypervisor 暴露给我们的能力面比裸硬件窄，任何被
 * 硬置的控制位都会让 VM entry 直接失败，而失败信息只有一个错误码。
 */
static __inline unsigned long
KswordArkHvmAdjustControls(
    unsigned long Desired,
    unsigned long long Capability
    )
{
    /* 低 32 位：必须置 1 的位。 */
    const unsigned long mustBeOne =
        (unsigned long)(Capability & 0xFFFFFFFFULL);
    /* 高 32 位：允许置 1 的位。 */
    const unsigned long mayBeOne =
        (unsigned long)(Capability >> 32);

    /* 保留必须位，剔除硬件不支持的请求位。 */
    return (Desired | mustBeOne) & mayBeOne;
}

/* ------------------------------------------------------------------ */
/* MSR 位图寻址                                                         */
/* ------------------------------------------------------------------ */

/* 位图页覆盖的低段最后一个索引。 */
#define KSWORD_ARK_HVM_MSR_LOW_LIMIT 0x00001FFFUL
/* 位图页覆盖的高段起始索引。 */
#define KSWORD_ARK_HVM_MSR_HIGH_BASE 0xC0000000UL
/* 位图页覆盖的高段最后一个索引。 */
#define KSWORD_ARK_HVM_MSR_HIGH_LIMIT 0xC0001FFFUL

/* 四个 1KiB 区在页内的字节偏移。 */
#define KSWORD_ARK_HVM_MSR_READ_LOW_OFFSET   0x000U
#define KSWORD_ARK_HVM_MSR_READ_HIGH_OFFSET  0x400U
#define KSWORD_ARK_HVM_MSR_WRITE_LOW_OFFSET  0x800U
#define KSWORD_ARK_HVM_MSR_WRITE_HIGH_OFFSET 0xC00U

/* 位图页大小，用于越界断言。 */
#define KSWORD_ARK_HVM_MSR_BITMAP_BYTES 0x1000U

/*
 * 判断某个 MSR 索引是否落在位图描述的两段范围内。
 * 范围外的索引无条件退出，不受位图控制，因此也不能给它设策略。
 */
static __inline int
KswordArkHvmMsrIndexIsCovered(
    unsigned long MsrIndex
    )
{
    if (MsrIndex <= KSWORD_ARK_HVM_MSR_LOW_LIMIT) {
        return 1;
    }
    return (MsrIndex >= KSWORD_ARK_HVM_MSR_HIGH_BASE &&
            MsrIndex <= KSWORD_ARK_HVM_MSR_HIGH_LIMIT) ? 1 : 0;
}

/*
 * 计算某个 MSR 在位图中的字节偏移与位掩码。
 *
 * 位图页分四个 1KiB 区，顺序是：低段读、高段读、低段写、高段写。
 * 高段索引要先减去 0xC0000000 再定位，这一步漏掉的话，写 IA32_LSTAR
 * (0xC0000082) 的策略会落到低段第 0x82 个 MSR 上——两个都存在，都不会报错。
 *
 * 返回 0 表示索引不在覆盖范围内，此时两个输出不被写入。
 */
static __inline int
KswordArkHvmMsrBitmapLocate(
    unsigned long MsrIndex,
    int IsWrite,
    unsigned long* ByteOffset,
    unsigned char* BitMask
    )
{
    unsigned long base = 0UL;
    unsigned long relative = 0UL;

    if (!KswordArkHvmMsrIndexIsCovered(MsrIndex)) {
        return 0;
    }
    if (MsrIndex <= KSWORD_ARK_HVM_MSR_LOW_LIMIT) {
        base = IsWrite
            ? KSWORD_ARK_HVM_MSR_WRITE_LOW_OFFSET
            : KSWORD_ARK_HVM_MSR_READ_LOW_OFFSET;
        relative = MsrIndex;
    } else {
        base = IsWrite
            ? KSWORD_ARK_HVM_MSR_WRITE_HIGH_OFFSET
            : KSWORD_ARK_HVM_MSR_READ_HIGH_OFFSET;
        relative = MsrIndex - KSWORD_ARK_HVM_MSR_HIGH_BASE;
    }
    *ByteOffset = base + (relative >> 3);
    *BitMask = (unsigned char)(1U << (relative & 7U));
    return 1;
}

/* ------------------------------------------------------------------ */
/* 页表自映射寻址                                                       */
/* ------------------------------------------------------------------ */

/* 规范地址里真正参与索引的低 48 位。 */
#define KSWORD_ARK_HVM_VA_INDEX_MASK 0x0000FFFFFFFFFFFFULL

/*
 * 由自映射基址推出某个虚拟地址的叶页表项地址。
 *
 * 必须先掩掉符号扩展的高 16 位再移位：内核地址的高位全 1，直接
 * (va >> 12) << 3 会把结果推出自映射区，落到一个不相干的地址上——
 * 而那个地址往往仍然可读，于是错误表现为"改了页表却没生效"。
 */
static __inline unsigned long long
KswordArkHvmSelfMapEntryAddress(
    unsigned long long SelfMapBase,
    unsigned long long VirtualAddress
    )
{
    const unsigned long long offset =
        ((VirtualAddress & KSWORD_ARK_HVM_VA_INDEX_MASK) >> 12) << 3;

    return SelfMapBase + offset;
}

/* 由 PML4 槽位号构造自映射基址。 */
static __inline unsigned long long
KswordArkHvmSelfMapBaseFromIndex(
    unsigned long Pml4Index
    )
{
    return 0xFFFF000000000000ULL |
        ((unsigned long long)(Pml4Index & 0x1FFUL) << 39);
}

/* ------------------------------------------------------------------ */
/* EPTP 校验                                                            */
/* ------------------------------------------------------------------ */

/* IA32_VMX_EPT_VPID_CAP 里与 EPTP 字段合法性相关的位。 */
#define KSWORD_ARK_HVM_EPT_CAP_PAGE_WALK_4   (1ULL << 6)
#define KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_UC (1ULL << 8)
#define KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_WB (1ULL << 14)
#define KSWORD_ARK_HVM_EPT_CAP_ACCESSED_DIRTY (1ULL << 21)

/* EPTP 字段布局。 */
#define KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_MASK 0x7ULL
#define KSWORD_ARK_HVM_EPTP_WALK_LENGTH_SHIFT 3
#define KSWORD_ARK_HVM_EPTP_WALK_LENGTH_MASK 0x7ULL
#define KSWORD_ARK_HVM_EPTP_ACCESSED_DIRTY (1ULL << 6)
/* bits 11:7 保留（bit 7 在新版 SDM 用于 supervisor shadow stack）。 */
#define KSWORD_ARK_HVM_EPTP_RESERVED_LOW 0x0F80ULL

/* 架构定义的两种可用内存类型。 */
#define KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_UC 0ULL
#define KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_WB 6ULL

/*
 * 按 SDM 判据校验一个 EPTP 值。
 *
 * 这套判据同时服务于两处：VM entry 前自检 EPT pointer 字段，以及 EPTP list
 * 里每一项的合法性——VMFUNC 用非法项切换时只会得到一次 exit reason 59，
 * 没有任何附加信息说明是哪一项错、错在哪，所以必须在写进 list 之前就自检。
 *
 * 特别注意：全 0 的项永远非法（页遍历级数为 0），所以 list 里未使用的槽不能
 * 留空，要填成与当前 EPTP 相同的合法值。
 *
 * MaxPhysicalAddressBits 来自 CPUID.80000008H:EAX[7:0]。
 * 返回非零表示该值可以被硬件接受。
 */
static __inline int
KswordArkHvmEptpIsValid(
    unsigned long long Eptp,
    unsigned long long EptVpidCapability,
    unsigned long MaxPhysicalAddressBits
    )
{
    const unsigned long long memoryType =
        Eptp & KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_MASK;
    const unsigned long long walkLength =
        (Eptp >> KSWORD_ARK_HVM_EPTP_WALK_LENGTH_SHIFT) &
        KSWORD_ARK_HVM_EPTP_WALK_LENGTH_MASK;
    unsigned long long physicalMask = 0ULL;

    /* 内存类型必须是硬件报告支持的那一种。 */
    if (memoryType == KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_UC) {
        if ((EptVpidCapability &
                KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_UC) == 0ULL) {
            return 0;
        }
    } else if (memoryType == KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_WB) {
        if ((EptVpidCapability &
                KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_WB) == 0ULL) {
            return 0;
        }
    } else {
        /* 其余编码架构上未定义。 */
        return 0;
    }
    /* 页遍历级数字段存的是"级数减一"，四级 walk 因此是 3。 */
    if (walkLength != 3ULL) {
        return 0;
    }
    if ((EptVpidCapability &
            KSWORD_ARK_HVM_EPT_CAP_PAGE_WALK_4) == 0ULL) {
        return 0;
    }
    /* 只有硬件支持时才允许开启 accessed/dirty。 */
    if ((Eptp & KSWORD_ARK_HVM_EPTP_ACCESSED_DIRTY) != 0ULL &&
        (EptVpidCapability &
            KSWORD_ARK_HVM_EPT_CAP_ACCESSED_DIRTY) == 0ULL) {
        return 0;
    }
    /* 低位保留域必须为零。 */
    if ((Eptp & KSWORD_ARK_HVM_EPTP_RESERVED_LOW) != 0ULL) {
        return 0;
    }
    /* 超出物理地址宽度的高位必须为零。 */
    if (MaxPhysicalAddressBits == 0UL ||
        MaxPhysicalAddressBits >= 64UL) {
        return 0;
    }
    physicalMask =
        ~((1ULL << MaxPhysicalAddressBits) - 1ULL);
    if ((Eptp & physicalMask) != 0ULL) {
        return 0;
    }
    return 1;
}

/*
 * EPT hierarchy index decomposition.
 *
 * Shared with the domain backend so the walk it performs can be checked on the
 * host.  A wrong index here does not fault - it silently edits the permissions
 * of an unrelated two-MiB region, which is exactly the class of bug that is
 * invisible until something far away misbehaves.
 */
/* EPT leaf permission bits, mirrored from the driver-private header. */
#define KSWORD_ARK_HVM_EPT_READ 0x1ULL
#define KSWORD_ARK_HVM_EPT_WRITE 0x2ULL
#define KSWORD_ARK_HVM_EPT_EXECUTE 0x4ULL

#define KSWORD_ARK_HVM_ONE_GIB 0x40000000ULL
#define KSWORD_ARK_HVM_ONE_512_GIB 0x8000000000ULL
#define KSWORD_ARK_HVM_LARGE_PAGE_BYTES 0x200000ULL
#define KSWORD_ARK_HVM_PAGE_BYTES 0x1000ULL

/* Select the PML4 slot covering one guest-physical address. */
static __inline unsigned long
KswordArkHvmEptPml4Index(
    unsigned long long PhysicalAddress)
{
    return (unsigned long)(PhysicalAddress / KSWORD_ARK_HVM_ONE_512_GIB);
}

/* Select the PDPT slot, that is the one-GiB window inside the PML4 slot. */
static __inline unsigned long
KswordArkHvmEptPdptIndex(
    unsigned long long PhysicalAddress)
{
    return (unsigned long)(
        (PhysicalAddress % KSWORD_ARK_HVM_ONE_512_GIB) /
        KSWORD_ARK_HVM_ONE_GIB);
}

/* Select the page-directory slot, that is the two-MiB leaf. */
static __inline unsigned long
KswordArkHvmEptPdIndex(
    unsigned long long PhysicalAddress)
{
    return (unsigned long)(
        (PhysicalAddress % KSWORD_ARK_HVM_ONE_GIB) /
        KSWORD_ARK_HVM_LARGE_PAGE_BYTES);
}

/* Round one address down to the two-MiB leaf that contains it. */
static __inline unsigned long long
KswordArkHvmEptLeafBase(
    unsigned long long PhysicalAddress)
{
    return PhysicalAddress & ~(KSWORD_ARK_HVM_LARGE_PAGE_BYTES - 1ULL);
}

/*
 * Apply one domain restriction to one leaf.
 *
 * Domains may only lose permissions, and this is where that rule lives.  It is
 * expressed as a mask-and rather than as a validated assignment on purpose: a
 * function that cannot express "grant" cannot be called wrongly to grant.
 */
static __inline unsigned long long
KswordArkHvmEptApplyRestriction(
    unsigned long long LeafEntry,
    unsigned long long RemovedBits)
{
    return LeafEntry & ~RemovedBits;
}

/*
 * Per-processor private EPT hierarchies (P4.1).
 *
 * A private hierarchy is the shared one with a handful of tables replaced by
 * private copies, so that flipping a leaf touches only the processor walking
 * it.  Every table on a private path is byte-for-byte its shared counterpart
 * except for the addresses that had to point somewhere else.  The arithmetic
 * that does the replacing lives here so the host tests can prove it, because
 * a wrong address in a paging structure does not fault - it silently walks to
 * the wrong page.
 */

/* Mask the physical-address field of an EPT entry or pointer. */
#define KSWORD_ARK_HVM_EPT_PHYSICAL_MASK 0x000FFFFFFFFFF000ULL
/* Mask the byte offset within one paging structure. */
#define KSWORD_ARK_HVM_EPT_ENTRY_OFFSET_MASK 0xFFFULL

/* Select the page-table slot, that is the four-KiB leaf inside a split. */
static __inline unsigned long
KswordArkHvmEptPtIndex(
    unsigned long long PhysicalAddress)
{
    return (unsigned long)(
        (PhysicalAddress % KSWORD_ARK_HVM_LARGE_PAGE_BYTES) /
        KSWORD_ARK_HVM_PAGE_BYTES);
}

/*
 * Encode one non-leaf entry pointing at a paging structure.
 *
 * Non-leaf entries carry no memory type, no large-page bit and no
 * suppress-#VE: those are leaf-only fields, and the permissions are the
 * permissive union so the leaves below decide the effective access.
 */
static __inline unsigned long long
KswordArkHvmEptTablePointer(
    unsigned long long TablePhysical)
{
    return (TablePhysical & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) |
        KSWORD_ARK_HVM_EPT_READ |
        KSWORD_ARK_HVM_EPT_WRITE |
        KSWORD_ARK_HVM_EPT_EXECUTE;
}

/*
 * Replace the address in an entry or pointer, keeping every other bit.
 *
 * This is the only operation that builds a private path, and it is used for
 * the EPT pointer itself as well as for table entries.  Composing a private
 * EPT pointer from constants instead would be a second source of truth for
 * the memory type, the walk length and the accessed/dirty bit: a private
 * pointer built this way is accepted by VM entry exactly when the shared one
 * is, and INVEPT sees the same descriptor the VMCS carries.
 */
static __inline unsigned long long
KswordArkHvmEptRebaseEntry(
    unsigned long long SharedEntry,
    unsigned long long PrivatePhysical)
{
    return (PrivatePhysical & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) |
        (SharedEntry & ~KSWORD_ARK_HVM_EPT_PHYSICAL_MASK);
}

/* Recover the paging structure that contains one entry address. */
static __inline unsigned long long
KswordArkHvmEptEntryTableBase(
    unsigned long long EntryAddress)
{
    return EntryAddress & ~KSWORD_ARK_HVM_EPT_ENTRY_OFFSET_MASK;
}

/* Recover the byte offset of one entry inside its paging structure. */
static __inline unsigned long long
KswordArkHvmEptEntryByteOffset(
    unsigned long long EntryAddress)
{
    return EntryAddress & KSWORD_ARK_HVM_EPT_ENTRY_OFFSET_MASK;
}

/*
 * Count the pages one private hierarchy set costs.
 *
 * Per processor: one private root, one private PDPT for each distinct PML4
 * slot the flippable leaves fall under, one private page directory for each
 * distinct one-GiB window, and one private page table per flippable leaf.
 * Everything else stays shared, which is what keeps this affordable.
 */
static __inline unsigned long long
KswordArkHvmEptLocalPageCost(
    unsigned long ProcessorCount,
    unsigned long DistinctPml4Slots,
    unsigned long DistinctGibWindows,
    unsigned long LeafCount)
{
    const unsigned long long perProcessor =
        1ULL +
        (unsigned long long)DistinctPml4Slots +
        (unsigned long long)DistinctGibWindows +
        (unsigned long long)LeafCount;

    return (unsigned long long)ProcessorCount * perProcessor;
}

/* Report whether a computed page cost fits the ledger reserved for it. */
static __inline int
KswordArkHvmEptLocalFitsBudget(
    unsigned long long PageCost,
    unsigned long long Cap)
{
    return PageCost != 0ULL && PageCost <= Cap ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* VMX 能力 MSR 过滤                                                    */
/* ------------------------------------------------------------------ */

/*
 * 我们**宣告**支持什么，必须等于我们**实现**了什么。
 *
 * L1 打开一个 VMX 特性之前，只会读这几个 MSR。不过滤的话它读到的是宿主的真实
 * 能力，于是它会去开 VPID、unrestricted guest、VMFUNC、posted interrupt 这些我们
 * 根本没有把字段拷进 vmcs02 的东西 —— 它设了控制位，我们不写配套字段，处理器
 * 按 vmcs02 里那个陈旧值（通常是 0）去做。整条路上没有任何一处会报错。
 *
 * 这跟 MSR 位图那个缺陷是同一族：**控制位与配套字段分家**。区别只在于那次是
 * 我们自己漏拷，这次是我们主动答应了做不到的事。
 *
 * 所以这里是一份**白名单**：只有明确列出的位才允许被宣告，其余一律清掉。新的
 * Intel 特性默认落到"不宣告"一侧 —— 反过来（黑名单）意味着每出一个新特性我们
 * 就默认答应一次，而且没人会注意到。
 */

/* 能力 MSR 的索引区间，全都是只读的。 */
#define KSWORD_ARK_HVM_VMX_MSR_BASIC            0x480UL
#define KSWORD_ARK_HVM_VMX_MSR_PINBASED         0x481UL
#define KSWORD_ARK_HVM_VMX_MSR_PROCBASED        0x482UL
#define KSWORD_ARK_HVM_VMX_MSR_EXIT_CTLS        0x483UL
#define KSWORD_ARK_HVM_VMX_MSR_ENTRY_CTLS       0x484UL
#define KSWORD_ARK_HVM_VMX_MSR_MISC             0x485UL
#define KSWORD_ARK_HVM_VMX_MSR_CR0_FIXED0       0x486UL
#define KSWORD_ARK_HVM_VMX_MSR_CR0_FIXED1       0x487UL
#define KSWORD_ARK_HVM_VMX_MSR_CR4_FIXED0       0x488UL
#define KSWORD_ARK_HVM_VMX_MSR_CR4_FIXED1       0x489UL
#define KSWORD_ARK_HVM_VMX_MSR_VMCS_ENUM        0x48AUL
#define KSWORD_ARK_HVM_VMX_MSR_PROCBASED2       0x48BUL
#define KSWORD_ARK_HVM_VMX_MSR_EPT_VPID_CAP     0x48CUL
#define KSWORD_ARK_HVM_VMX_MSR_TRUE_PINBASED    0x48DUL
#define KSWORD_ARK_HVM_VMX_MSR_TRUE_PROCBASED   0x48EUL
#define KSWORD_ARK_HVM_VMX_MSR_TRUE_EXIT_CTLS   0x48FUL
#define KSWORD_ARK_HVM_VMX_MSR_TRUE_ENTRY_CTLS  0x490UL
#define KSWORD_ARK_HVM_VMX_MSR_VMFUNC           0x491UL

/* 判断一个索引是不是 VMX 能力 MSR。 */
static __inline int
KswordArkHvmIsVmxCapabilityMsr(
    unsigned long MsrIndex
    )
{
    return (MsrIndex >= KSWORD_ARK_HVM_VMX_MSR_BASIC &&
            MsrIndex <= KSWORD_ARK_HVM_VMX_MSR_VMFUNC) ? 1 : 0;
}

/*
 * pin-based 控制里允许宣告的位。
 *
 * bit 0 外部中断退出 / bit 3 NMI 退出 / bit 5 虚拟 NMI：只是控制位，合并时并进
 * vmcs02，没有配套地址字段。
 * 清掉 bit 6（VMX 抢占计时器，要 0x482E 与退出控制 22）与 bit 7（posted
 * interrupt，要 0x2016 描述符地址 + 通知向量），两者的字段我们都不拷。
 */
/*
 * 2026-09-14：bit 6 曾被临时加进这张表，想看看"宣告了抢占计时器，VMware 会不会
 * 去配一个真的监控器定时器"。**那次实验是空操作，什么都没验到。**
 *
 * 这张表是白名单，下面的过滤器做的是 `高半部 &= 本表`——它只能收窄。宿主
 * （Hyper-V）的 pin allowed-1 是 0x3F，bit 6 本来就不在里面，所以无论这里写
 * 0x29 还是 0x69，交给来宾的都是同一个 0x3F，VMware 的能力转储照旧是
 * `Activate VMX-preemption timer { 0 }`。
 *
 * **判据：想让 L1 看见一个新能力，改白名单不够，得让过滤器去合成它**——那就
 * 不再是过滤而是伪造，必须连同字段（0x482E）与退出语义（原因 52）一起实现。
 * 在这之前，这里只放我们真的会往 vmcs02 里合并的位。
 */
#define KSWORD_ARK_HVM_VMX_PIN_ALLOWED 0x00000029UL

/*
 * primary processor-based 控制里允许宣告的位。
 *
 * 清掉的几个都是"要一个配套地址字段而我们不写"的：
 *   bit 27 monitor trap flag -> 我们没为 L2 实现 MTF
 *
 * bit 21（use TPR shadow）曾在这一行里，理由正是"要 0x2012 而我们不写"。现在写了：
 * 0x2012 与 0x401C 一起进了 hvm_nested_l2.c 的被拷控制字段表，进入前还会校验这一页
 * 的地址非零且页对齐。加它是因为 VMware Workstation 17.6 点名要它
 * （`True Primary Processor-Based VM-Execution Controls: Use TPR shadow`）。
 * 注意它与 secondary 的 virtualize-APIC-accesses（bit 0）是两件事，后者仍然不宣告。
 * 保留 bit 25 使用 I/O 位图与 bit 28 使用 MSR 位图（这两条路已经端到端验过），
 * 以及 bit 31 激活 secondary。
 *
 * bit 3（TSC offsetting）曾被清掉，那是个错误：0x2010 一直在
 * g_KswordL2CopiedControlFields 里拷着，我却按"它没被拷"把它停止宣告了 ——
 * 一次自己造出来的倒退。判断一位该不该留，**去 hvm_nested_l2.c 的字段表里查，
 * 不要 grep 宏名**：那三张表是循环应用的，表里的字段一个宏都没有。
 */
#define KSWORD_ARK_HVM_VMX_PROC_ALLOWED 0xF3F99E8CUL

/*
 * secondary 控制里允许宣告的位：EPT 与 unrestricted guest。
 *
 * 其余每一位都要一个我们没拷进 vmcs02 的字段：VPID 要 VPID 字段与 INVVPID 处理、
 * VMFUNC 要 0x2018、VMCS shadowing 要 0x2026/0x2028、PML 要 0x200E、#VE 要
 * 0x202A、EPTP 切换要 0x2024、TSC scaling 要 0x2032。
 *
 * bit 7（unrestricted guest）**不需要任何新字段**，这是它与上面那些的根本区别：
 * 它只是放宽处理器对来宾 CR0.PE/PG 的要求，让 L2 可以跑在实模式或未分页保护模式。
 * 来宾 CR0、段属性、CR0 掩码与读影子本来就逐字段从 vmcs12 拷过来，进入路径也没有
 * 任何一处校验 CR0.PE —— 也就是说这一位所需要的东西**全都已经在了**。
 *
 * 加它是因为真机上量到的需求：VMware Workstation 17.6 在自己的日志里点名
 * `The Intel "VMX Unrestricted Guest" feature is necessary to run this virtual
 * machine` —— 它的来宾从**实模式**启动，没有这一位一定起不来。这是四项缺件里
 * 唯一无法绕开的一项（另外三项是 TPR shadow、ack-interrupt-on-exit、INVVPID）。
 *
 * 依赖关系必须由代码保证而不是靠 L1 自觉：Intel 规定 unrestricted guest = 1 时
 * enable EPT 也必须为 1，否则 VM entry 失败。合并 vmcs02 控制时会把 EPT 关着的
 * unrestricted guest 位丢掉 —— 与 pin 控制里"虚拟 NMI 不能没有 NMI 退出"同一种
 * 处理，理由也一样：**不把一对没验过的控制送进 VMLAUNCH**。
 *
 * 后果仍然要说清楚：这份能力依旧很窄，很多 hypervisor 会直接拒绝启动。那正是想要
 * 的结果 —— 干净地拒绝，好过答应了再静默地做不到。
 */
#define KSWORD_ARK_HVM_VMX_PROC2_ALLOWED 0x00000082UL

/*
 * VM-exit 控制里允许宣告的位。
 *
 * 留的每一位都能在 hvm_nested_l2.c 的字段表里指出它依赖的那个字段：
 *   bit 2  保存调试控制  -> guest IA32_DEBUGCTL(0x2802) 与 DR7(0x681A) 在双向表里
 *   bit 9  host 地址空间 -> x64 上本来就是强制位
 *   bit 18 保存 guest PAT  -> 0x2804 在双向表里，反射时写回 vmcs12
 *   bit 19 装载 host PAT   -> 0x2C00 在 host 表里（继承自 vmcs01）
 *   bit 20 保存 guest EFER -> 0x2806 同上
 *   bit 21 装载 host EFER  -> 0x2C02 同上
 * 清掉的：12 PERF_GLOBAL_CTRL（0x2808 **不在**任何表里）、22 抢占计时器
 * （0x482E 同样不在）。
 *
 * bit 15（退出时应答中断）：置位时处理器**自己**去应答中断控制器并把向量写进
 * 0x4404，而 0x4404 与 0x4406 在反射时本来就逐字段写进 vmcs12。
 * VMware Workstation 17.6 点名要它（`True VM-Exit Controls: Acknowledge interrupt
 * on exit`），是它四项缺件里的最后一项。
 *
 * 这一位的危险不在语义而在**路由**：被应答的中断已经从控制器上取走了，谁都不再会
 * 重新投递它，所以这个退出**必须**到达 L1。保证它的是三件事，缺一不可：
 *   1. 我们自己从不请求外部中断退出，所以 reason 1 只可能因为 L1 要了才发生；
 *   2. 我们自己的退出控制里没有 bit 15，vmcs02 里的这一位只会来自 vmcs12；
 *   3. 退出归属里 reason 1 被**显式**判给 L1（不是靠 default 兜底）——
 *      见 hvm_nested_l2.c，那里写明了为什么这一条不能跟着默认走。
 * 三条里任何一条被后来的改动破坏，症状都是丢中断导致的静默挂死。
 *
 * **两次实测确认这一位既扣不下、也不能在合并时剥掉**（2026-09-14）：
 *   - 从这张表里去掉它是空操作。过滤器只能在宿主给的范围内收窄，而且
 *     `high |= low` 会把每个"必须为一"的位加回来，bit 15 正是其中之一 ——
 *     去掉之后来宾读到的 vmcs12 里它照旧置位。
 *   - 在合并进 vmcs02 时剥掉它，VMware 的监控器当场倒下：
 *     `MONITOR PANIC: VERIFY vmcore/monitor/common/platform/common/x86/irq.c:111`。
 *     L1 一旦要了这一位就会无条件去读那个向量，读到无效值就触发它自己的断言。
 * **L1 设了的控制位不能悄悄扣下**，要么它根本不该能设，要么就得如实兑现。
 */
#define KSWORD_ARK_HVM_VMX_EXIT_ALLOWED 0x003C8204UL

/*
 * VM-entry 控制里允许宣告的位。
 *
 *   bit 2  装载调试控制 -> guest IA32_DEBUGCTL(0x2802)、DR7 在双向表里
 *   bit 9  IA-32e 模式来宾 -> 不留的话 64 位 L2 根本进不去
 *   bit 14 装载 guest PAT  -> 0x2804 在双向表里
 *   bit 15 装载 guest EFER -> 0x2806 在双向表里
 * 清掉 13（PERF_GLOBAL_CTRL，0x2808 不拷）与 16/17/18/20/21/22
 * （BNDCFGS、PT、RTIT、CET、LBR、PKRS，字段一个都不拷）。
 *
 * 这一组曾经只留 bit 9，是我按"这些字段没拷"写的，而那个前提是错的 —— 那三张
 * 批量表一直在拷。**过窄的宣告和过宽的宣告一样有害**：过宽是答应做不到的事，
 * 过窄是让一个本可以跑起来的 hypervisor 干净地拒绝启动，而且两者都不报错。
 * 所以这份表的每一位现在都写明它依赖哪个字段编码，改之前先去表里查。
 */
#define KSWORD_ARK_HVM_VMX_ENTRY_ALLOWED 0x0000C204UL

/*
 * EPT/VPID 能力里允许宣告的位。
 *
 * 留下的是影子 EPT 真的走过的那些：4 级页表走、UC/WB 内存类型、2 MiB 与 1 GiB
 * 叶、INVEPT 及其两种上下文，外加 bit 21 accessed/dirty —— A/D 是这条线上唯一
 * 一个已经实测折回过 L1 表的能力位。
 *
 * VPID 那一族只宣告 **bit 32（支持 INVVPID）与 bit 40/41/42（类型 0/1/2）**，
 * 恰好是 VMware Workstation 17.6 在自己日志里点名要的那四位。注意它要的是**指令
 * 能力**，不是 secondary 里的 enable-VPID 控制位（那一位仍然不宣告，见
 * KSWORD_ARK_HVM_VMX_PROC2_ALLOWED）—— 这两件事在架构上本来就是分开的。
 *
 * 我们**不开 VPID**，所以 vmcs02 里 L2 用的是 VPID 0000H，而处理器在每一次 VM entry
 * 与 VM exit 上都会失效 VPID 0000H 的线性映射。也就是说 L1 想让 INVVPID 去掉的那些
 * 翻译，到下一次进出之前必然已经没了 —— 服务这条指令的正确动作是**什么都不做**，
 * 不是去刷影子 EPT（那是 INVEPT 的事，而且每次 INVVPID 重建一遍影子会很贵）。
 *
 * bit 43（类型 3，单上下文保留全局）不宣告：VMware 没要，我们也没有理由去承诺一个
 * 更精细的粒度。
 *
 * bit 0 execute-only 也清掉 —— 影子合成是否逐位保留 execute-only 没有验过，
 * 没验过的位不宣告。
 *
 * **这份白名单必须是我们自己在来宾里用到的位的超集。**
 *
 * 容易漏的一点：驱动自己也是这些 MSR 的读者，而常驻起来之后驱动就跑在来宾里，
 * 于是我们读到的是自己过滤后的值。今天有两个这样的读者：
 *   hvm_nested_ept.c  查 bit 21 决定要不要维护 A/D
 *   hvm_nested_probe.c 查 bit 17 决定 EPT12 能不能用 1 GiB 叶搭
 * bit 17 起初不在这份表里，那会让探针的 EPT12 装不起来、整行判 FAIL —— 故障现象
 * 跟"嵌套坏了"一模一样，而真因是我们把自己要用的能力给自己屏蔽了。
 */
#define KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED 0x0000070106334140ULL

/* MISC 里 CR3-target 个数字段的位置；我们不拷 CR3-target 字段，所以必须报 0。 */
#define KSWORD_ARK_HVM_VMX_MISC_CR3_TARGET_MASK 0x01FF0000ULL

/*
 * 把一个成对格式的控制能力 MSR 收窄。
 *
 * 低 32 位是 allowed-0（置 1 表示"必须为 1"），高 32 位是 allowed-1（置 1 表示
 * "可以为 1"）。收窄只动高半部。
 *
 * `| low` 这一步不能省：硬件强制为 1 的位必然也是允许为 1 的，把它从高半部清掉
 * 会造出一个自相矛盾的 MSR —— L1 照着它算出来的控制值会被处理器判非法，而报出
 * 来的错误指向 L1 自己的计算，不指向我们。宁可宣告一个我们没实现但被强制打开
 * 的位，也不能给出一份不自洽的能力。
 */
static __inline unsigned long long
KswordArkHvmFilterPairedControlMsr(
    unsigned long long HostValue,
    unsigned long AllowedHigh
    )
{
    unsigned long long low = HostValue & 0xFFFFFFFFULL;
    unsigned long long high = (HostValue >> 32) & 0xFFFFFFFFULL;

    high &= (unsigned long long)AllowedHigh;
    high |= low;
    return (high << 32) | low;
}

/*
 * 按索引收窄一个能力 MSR。返回要交给来宾的值。
 *
 * 不在过滤范围内的索引原样返回 —— 调用方已经用 KswordArkHvmIsVmxCapabilityMsr
 * 把范围框住了，这里再判一次是为了让这个函数单独拿出来也是对的。
 */
static __inline unsigned long long
KswordArkHvmFilterVmxCapabilityMsr(
    unsigned long MsrIndex,
    unsigned long long HostValue
    )
{
    switch (MsrIndex) {
    case KSWORD_ARK_HVM_VMX_MSR_PINBASED:
    case KSWORD_ARK_HVM_VMX_MSR_TRUE_PINBASED:
        return KswordArkHvmFilterPairedControlMsr(
            HostValue, KSWORD_ARK_HVM_VMX_PIN_ALLOWED);
    case KSWORD_ARK_HVM_VMX_MSR_PROCBASED:
    case KSWORD_ARK_HVM_VMX_MSR_TRUE_PROCBASED:
        return KswordArkHvmFilterPairedControlMsr(
            HostValue, KSWORD_ARK_HVM_VMX_PROC_ALLOWED);
    case KSWORD_ARK_HVM_VMX_MSR_EXIT_CTLS:
    case KSWORD_ARK_HVM_VMX_MSR_TRUE_EXIT_CTLS:
        return KswordArkHvmFilterPairedControlMsr(
            HostValue, KSWORD_ARK_HVM_VMX_EXIT_ALLOWED);
    case KSWORD_ARK_HVM_VMX_MSR_ENTRY_CTLS:
    case KSWORD_ARK_HVM_VMX_MSR_TRUE_ENTRY_CTLS:
        return KswordArkHvmFilterPairedControlMsr(
            HostValue, KSWORD_ARK_HVM_VMX_ENTRY_ALLOWED);
    case KSWORD_ARK_HVM_VMX_MSR_PROCBASED2:
        return KswordArkHvmFilterPairedControlMsr(
            HostValue, KSWORD_ARK_HVM_VMX_PROC2_ALLOWED);
    case KSWORD_ARK_HVM_VMX_MSR_EPT_VPID_CAP:
        /* 单值格式，不是成对的：直接与白名单相与。 */
        return HostValue & KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED;
    case KSWORD_ARK_HVM_VMX_MSR_VMFUNC:
        /*
         * secondary 里 VMFUNC 已经清了，这里把功能位也清空。
         *
         * 两处都清是故意的：L1 若只读这一个 MSR 就去用 VMFUNC，得到的是"一个
         * 功能都没有"，而不是"有功能但激活位打不开"。后者会让它以为是配置问题
         * 而重试。
         */
        return 0ULL;
    case KSWORD_ARK_HVM_VMX_MSR_MISC:
        /*
         * 只清 CR3-target 个数。
         *
         * 这个字段是个**承诺**：报 N 就是说 vmcs 里有 N 个 CR3-target 值可用，
         * 而我们一个都不往 vmcs02 里拷。其余各位是描述性的（活动状态、MSEG
         * 版本、抢占计时器频率），不构成我们必须兑现的功能。
         */
        return HostValue & ~KSWORD_ARK_HVM_VMX_MISC_CR3_TARGET_MASK;
    default:
        /*
         * BASIC / CR0 与 CR4 的固定位 / VMCS_ENUM 原样透传。
         *
         * BASIC 尤其不能动：低 31 位是 VMCS 修订号，改了它，来宾按新号去建
         * VMCS 区域，VMXON 与 VMPTRLD 会因为区域头部对不上而失败 —— 那是一个
         * 跟能力毫无关系的故障，却会被当成嵌套坏了。
         */
        return HostValue;
    }
}


/* ------------------------------------------------------------------ */
/* Detection-surface MSR filter: close CPUID.1 hide 的配套洞。          */
/* CPUID.1:ECX[5] (VMX) 被 handler 清 0 后, FEATURE_CONTROL (0x3A)      */
/* bit 2 (ENABLE_VMXON_OUTSIDE_SMX) 读物理值还是 1 (KSword 做了 VMXON), */
/* 一行 rdmsr 直接对 CPUID 形成矛盾 —— 可靠 hypervisor tell。           */
/* 下面的 filter 把 FEATURE_CONTROL 的 VMXON 使能位清掉, 保留 LOCK;     */
/* PERF_CAPABILITIES 零化 PEBS/LBR format 位防 PMU 侧探测。             */
/* ------------------------------------------------------------------ */

/* IA32_FEATURE_CONTROL (0x3A): BIOS/firmware 锁定 VMX 启动门。 */
#define KSWORD_ARK_HVM_DETECTION_MSR_FEATURE_CONTROL 0x3AUL

/* IA32_PERF_CAPABILITIES (0x345): PEBS/LBR/PT 格式位对外可见。 */
#define KSWORD_ARK_HVM_DETECTION_MSR_PERF_CAPABILITIES 0x345UL

/* FEATURE_CONTROL bit 0: LOCK 位, 需保留以让 Windows 内核仍能识别锁定。 */
#define KSWORD_ARK_HVM_FEATURE_CONTROL_LOCK (1ULL << 0)

/* FEATURE_CONTROL bit 1 + bit 2: VMXON 使能位, 对 CPL=3 必须清为 0 保一致性。 */
#define KSWORD_ARK_HVM_FEATURE_CONTROL_VMXON_MASK ((1ULL << 1) | (1ULL << 2))

/* 判断索引是否属于本 detection MSR 过滤器覆盖的范围。 */
static __inline int
KswordArkHvmIsDetectionMsr(
    unsigned long MsrIndex
    )
{
    /* 当前覆盖两个 MSR, 直接比较两个常量更短且无分支成本。 */
    return (MsrIndex == KSWORD_ARK_HVM_DETECTION_MSR_FEATURE_CONTROL ||
            MsrIndex == KSWORD_ARK_HVM_DETECTION_MSR_PERF_CAPABILITIES) ? 1 : 0;
}

/* 把物理 MSR 读回值缩小成来宾应观察到的值。 */
/* 保留的位: FEATURE_CONTROL.LOCK (bit 0) — 防 Windows 把未锁 flag 当异常。 */
/* 清掉的位: FEATURE_CONTROL VMXON 使能 (bits 1-2) — 与 CPUID.1 的 VMX 隐藏配平。*/
/* PERF_CAPABILITIES: 整体零化, 不宣布任何 PMU 高阶能力避免行为联动不一致。 */
static __inline unsigned long long
KswordArkHvmFilterDetectionMsr(
    unsigned long MsrIndex,
    unsigned long long HostValue
    )
{
    switch (MsrIndex) {
    case KSWORD_ARK_HVM_DETECTION_MSR_FEATURE_CONTROL:
        /* LOCK 必须按物理锁状态透传; 其余 VMX 使能位全部清 0。 */
        return HostValue & KSWORD_ARK_HVM_FEATURE_CONTROL_LOCK;
    case KSWORD_ARK_HVM_DETECTION_MSR_PERF_CAPABILITIES:
        /* 整体零化, 与 "无 PMU 扩展" 的最朴素形态保持一致。 */
        (void)HostValue;
        return 0ULL;
    default:
        /* 不在覆盖范围的索引不应该走到这里, 保守返回原值。 */
        return HostValue;
    }
}


/* ------------------------------------------------------------------ */
/* Nested EPT: L2 GPA -> L1 GPA -> KSword backing page.                 */
/* Return ownership separately: an outer denial is not an L1 fault.    */
/* ------------------------------------------------------------------ */
#define KSWORD_ARK_HVM_NEPT_COMPOSE_OK 0UL
#define KSWORD_ARK_HVM_NEPT_COMPOSE_L1_DENIED 1UL
#define KSWORD_ARK_HVM_NEPT_COMPOSE_OUTER_DENIED 2UL
#define KSWORD_ARK_HVM_NEPT_COMPOSE_INVALID 3UL

static __inline unsigned long
KswordArkHvmNestedEptComposeLeaf(
    unsigned long long L1Physical,
    unsigned long long L1Leaf,
    unsigned long long OuterLeaf,
    unsigned long OuterShift,
    unsigned long Access,
    unsigned long long* Composed)
{
    unsigned long long offsetMask;
    unsigned long long permissions;
    unsigned long innerType;
    unsigned long outerType;
    unsigned long memoryType;

    if (Composed == 0) { return KSWORD_ARK_HVM_NEPT_COMPOSE_INVALID; }
    *Composed = 0ULL;
    if (Access == 0UL || (Access & ~7UL) != 0UL) {
        return KSWORD_ARK_HVM_NEPT_COMPOSE_INVALID;
    }
    if ((L1Leaf & Access) != Access) {
        return KSWORD_ARK_HVM_NEPT_COMPOSE_L1_DENIED;
    }
    if (OuterShift != 12UL && OuterShift != 21UL && OuterShift != 30UL) {
        return KSWORD_ARK_HVM_NEPT_COMPOSE_INVALID;
    }
    offsetMask = (1ULL << OuterShift) - 1ULL;
    if ((L1Physical & ~(KSWORD_ARK_HVM_EPT_PHYSICAL_MASK | 0xFFFULL)) != 0ULL ||
        (OuterLeaf & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK & offsetMask) != 0ULL ||
        (((OuterLeaf & 0x80ULL) != 0ULL) != (OuterShift != 12UL)) ||
        ((OuterLeaf & 3ULL) == 2ULL) || ((L1Leaf & 3ULL) == 2ULL)) {
        return KSWORD_ARK_HVM_NEPT_COMPOSE_INVALID;
    }
    permissions = L1Leaf & OuterLeaf & 7ULL;
    if ((permissions & Access) != Access) {
        return KSWORD_ARK_HVM_NEPT_COMPOSE_OUTER_DENIED;
    }
    innerType = (unsigned long)((L1Leaf >> 3) & 7ULL);
    outerType = (unsigned long)((OuterLeaf >> 3) & 7ULL);
    if (innerType == 2UL || innerType == 3UL || innerType == 7UL ||
        outerType == 2UL || outerType == 3UL || outerType == 7UL) {
        return KSWORD_ARK_HVM_NEPT_COMPOSE_INVALID;
    }
    /* UC wins; unlike non-WB types use conservative UC, never forced WB. */
    memoryType = innerType == outerType ? innerType :
        (innerType == 6UL ? outerType : (outerType == 6UL ? innerType : 0UL));
    *Composed = (OuterLeaf & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) |
        (L1Physical & offsetMask & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) |
        permissions | ((unsigned long long)memoryType << 3) |
        (L1Leaf & 0x40ULL) | 0x8000000000000000ULL;
    /* A/D starts clear; the shadow's existing accounting owns these bits. */
    return KSWORD_ARK_HVM_NEPT_COMPOSE_OK;
}
