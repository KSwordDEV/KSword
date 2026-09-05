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
