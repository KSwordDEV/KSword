/*
 * hvm_unit_tests - KswordArkHvmControls.h 的宿主机单元测试
 *
 * 这些逻辑在驱动里只有加载后才会被执行，而加载需要签名、需要一台没开 HVCI 的
 * 机器，出错的表现是蓝屏。它们本身却是纯算术——把它们抽进共享头之后，正确性
 * 可以在编译机上直接证明，不需要任何虚拟化环境。
 *
 * 测试用的是不变量而不只是手算值：手算值只能覆盖我算过的那几个点，而不变量
 * （同页同项、相邻页差 8 字节、结果不越出自映射区）能覆盖我推导时最容易错的
 * 那一步——符号扩展没掩掉。
 *
 * 编译：
 *   cl /nologo /O2 /MT /W4 hvm_unit_tests.c /Fe:hvm_unit_tests.exe
 */

#include <stdio.h>

#include "../../shared/driver/KswordArkHvmControls.h"

static int g_checks = 0;
static int g_failures = 0;
static const char* g_group = "";

static void
Group(const char* name)
{
    g_group = name;
    printf("\n[%s]\n", name);
}

static void
Check(int condition, const char* what)
{
    g_checks += 1;
    if (condition) {
        printf("  ok    %s\n", what);
    } else {
        g_failures += 1;
        printf("  FAIL  %s\n", what);
    }
}

static void
CheckEqU64(unsigned long long actual,
           unsigned long long expected,
           const char* what)
{
    g_checks += 1;
    if (actual == expected) {
        printf("  ok    %s\n", what);
    } else {
        g_failures += 1;
        printf("  FAIL  %s\n        expected 0x%016llX got 0x%016llX\n",
               what, expected, actual);
    }
}

/* ------------------------------------------------------------------ */

static void
TestAdjustControls(void)
{
    unsigned long long capability = 0ULL;
    unsigned long result = 0UL;

    Group("VMX 控制位夹取");

    /*
     * 能力 MSR：低 32 位 = 必须为 1，高 32 位 = 允许为 1。
     * 构造一个"bit0 必须置位，bit0..bit3 允许置位"的能力面。
     */
    capability = 0x0000000FULL << 32 | 0x00000001ULL;

    /* 一个都不要，也必须拿回必须位。 */
    result = KswordArkHvmAdjustControls(0UL, capability);
    CheckEqU64(result, 0x1UL, "不请求任何位时仍保留 allowed-0 必须位");

    /* 请求一个被允许的位。 */
    result = KswordArkHvmAdjustControls(0x4UL, capability);
    CheckEqU64(result, 0x5UL, "被允许的请求位保留，必须位一并保留");

    /* 请求一个不被允许的位——这是嵌套下最常见的失败原因。 */
    result = KswordArkHvmAdjustControls(0x10UL, capability);
    CheckEqU64(result, 0x1UL, "硬件不允许的请求位被剔除，不会带进 VMCS");

    /*
     * 嵌套典型能力面之一：外层不给 secondary controls。
     * 我们请求 bit31（activate secondary controls），必须被剔除，
     * 否则 VM entry 会直接失败且只返回一个错误码。
     */
    capability = 0x7FFFFFFFULL << 32 | 0x00000016ULL;
    result = KswordArkHvmAdjustControls(0x80000000UL, capability);
    Check((result & 0x80000000UL) == 0UL,
          "外层不暴露 secondary controls 时该位被剔除");
    CheckEqU64(result & 0x16UL, 0x16UL, "同时必须位仍然完整保留");

    /* 全允许的能力面下，请求什么就得到什么（加上必须位）。 */
    capability = 0xFFFFFFFFULL << 32 | 0x00000000ULL;
    result = KswordArkHvmAdjustControls(0xDEADBEEFUL, capability);
    CheckEqU64(result, 0xDEADBEEFUL, "全允许时请求原样通过");

    /* 全不允许的能力面下，结果必然为零。 */
    capability = 0x00000000ULL << 32 | 0x00000000ULL;
    result = KswordArkHvmAdjustControls(0xFFFFFFFFUL, capability);
    CheckEqU64(result, 0UL, "全不允许时结果为零");
}

/* ------------------------------------------------------------------ */

static void
TestMsrBitmap(void)
{
    unsigned long offset = 0UL;
    unsigned char mask = 0U;
    int covered = 0;

    Group("MSR 位图寻址");

    /* 低段第 0 个 MSR 的读位：页首字节的 bit0。 */
    covered = KswordArkHvmMsrBitmapLocate(0UL, 0, &offset, &mask);
    Check(covered != 0, "索引 0 在覆盖范围内");
    CheckEqU64(offset, 0x000U, "低段读位图从页首开始");
    CheckEqU64(mask, 0x01U, "索引 0 对应 bit0");

    /* 低段写位图起始于 0x800。 */
    covered = KswordArkHvmMsrBitmapLocate(0UL, 1, &offset, &mask);
    CheckEqU64(offset, 0x800U, "低段写位图从 0x800 开始");

    /*
     * 高段必须先减去 0xC0000000 再定位。漏掉这一步的话，
     * IA32_LSTAR (0xC0000082) 会落到低段第 0x82 个 MSR 上——
     * 那个位置也是合法的，不会报错，只是拦错了对象。
     */
    covered = KswordArkHvmMsrBitmapLocate(0xC0000082UL, 0, &offset, &mask);
    Check(covered != 0, "IA32_LSTAR 在覆盖范围内");
    CheckEqU64(offset, 0x400U + (0x82U >> 3), "高段读位图先减基址再定位");
    CheckEqU64(mask, (unsigned char)(1U << (0x82U & 7U)),
               "IA32_LSTAR 的位掩码按相对索引算");

    /* 同一个索引的读与写必须落在不同的区。 */
    {
        unsigned long readOffset = 0UL;
        unsigned long writeOffset = 0UL;
        unsigned char ignored = 0U;

        KswordArkHvmMsrBitmapLocate(0xC0000082UL, 0, &readOffset, &ignored);
        KswordArkHvmMsrBitmapLocate(0xC0000082UL, 1, &writeOffset, &ignored);
        Check(readOffset != writeOffset, "同一 MSR 的读写位于不同区");
        CheckEqU64(writeOffset - readOffset, 0x800U,
                   "读区与写区相距正好 0x800");
    }

    /* 每一段的最后一个索引都必须仍落在页内。 */
    covered = KswordArkHvmMsrBitmapLocate(
        KSWORD_ARK_HVM_MSR_LOW_LIMIT, 1, &offset, &mask);
    Check(covered != 0, "低段末尾索引仍在覆盖范围内");
    Check(offset < KSWORD_ARK_HVM_MSR_BITMAP_BYTES,
          "低段末尾的写偏移不越出位图页");
    CheckEqU64(offset, 0x800U + 0x3FFU, "低段末尾正好落在写区最后一字节");

    covered = KswordArkHvmMsrBitmapLocate(
        KSWORD_ARK_HVM_MSR_HIGH_LIMIT, 1, &offset, &mask);
    Check(covered != 0, "高段末尾索引仍在覆盖范围内");
    CheckEqU64(offset, 0xC00U + 0x3FFU, "高段末尾正好落在页的最后一字节");

    /* 范围外的索引必须被拒绝，而不是算出一个看似合理的偏移。 */
    Check(KswordArkHvmMsrBitmapLocate(0x2000UL, 0, &offset, &mask) == 0,
          "低段之上的索引被拒绝");
    Check(KswordArkHvmMsrBitmapLocate(0xBFFFFFFFUL, 0, &offset, &mask) == 0,
          "高段之下的索引被拒绝");
    Check(KswordArkHvmMsrBitmapLocate(0xC0002000UL, 0, &offset, &mask) == 0,
          "高段之上的索引被拒绝");

    /* 遍历两段全部索引，确认没有任何一个越界。 */
    {
        unsigned long index = 0UL;
        int allInside = 1;

        for (index = 0UL; index <= KSWORD_ARK_HVM_MSR_LOW_LIMIT; ++index) {
            if (!KswordArkHvmMsrBitmapLocate(index, 1, &offset, &mask) ||
                offset >= KSWORD_ARK_HVM_MSR_BITMAP_BYTES) {
                allInside = 0;
                break;
            }
        }
        for (index = KSWORD_ARK_HVM_MSR_HIGH_BASE;
             index <= KSWORD_ARK_HVM_MSR_HIGH_LIMIT;
             ++index) {
            if (!KswordArkHvmMsrBitmapLocate(index, 1, &offset, &mask) ||
                offset >= KSWORD_ARK_HVM_MSR_BITMAP_BYTES) {
                allInside = 0;
                break;
            }
        }
        Check(allInside, "两段全部 16384 个索引的偏移都在页内");
    }
}

/* ------------------------------------------------------------------ */

static void
TestSelfMap(void)
{
    /* 历史上固定的自映射槽位，用作一组已知值。 */
    const unsigned long long base =
        KswordArkHvmSelfMapBaseFromIndex(0x1EDUL);
    const unsigned long long kernelVa = 0xFFFFF80000000000ULL;
    const unsigned long long userVa = 0x00007FF000000000ULL;

    Group("页表自映射寻址");

    CheckEqU64(base, 0xFFFFF68000000000ULL,
               "槽位 0x1ED 推出的自映射基址与历史固定值一致");

    /*
     * 这是整个公式里唯一容易错的地方：内核地址高 16 位全是 1，
     * 不掩掉就会把结果推出自映射区。掩掉之后必须仍落在 [base, base+512GiB)。
     */
    {
        const unsigned long long entry =
            KswordArkHvmSelfMapEntryAddress(base, kernelVa);

        /*
         * 逐步验算：va & 0x0000FFFFFFFFFFFF = 0xF8 << 40，
         * >> 12 得 0xF8 << 28，<< 3 得 0xF8 << 31 = 0x7C00000000，
         * 加基址 0xFFFFF68000000000 得 0xFFFFF6FC00000000。
         */
        CheckEqU64(entry, 0xFFFFF6FC00000000ULL,
                   "内核地址的叶项地址与逐步验算一致");
        /*
         * 区间判断一律写成 entry - base < 2^39。写成 entry < base + 2^39
         * 会在高槽位上溢出回绕：槽位 511 的 base + 2^39 正好是 0。
         */
        Check(entry - base < (1ULL << 39),
              "内核地址的叶项落在自映射区内");
    }
    {
        const unsigned long long entry =
            KswordArkHvmSelfMapEntryAddress(base, userVa);

        Check(entry - base < (1ULL << 39),
              "用户地址的叶项落在自映射区内");
    }

    /* 同一页内的任何地址必须给出同一个叶项。 */
    {
        const unsigned long long a =
            KswordArkHvmSelfMapEntryAddress(base, kernelVa);
        const unsigned long long b =
            KswordArkHvmSelfMapEntryAddress(base, kernelVa + 0xFFFULL);

        CheckEqU64(b, a, "同一页内的地址映射到同一个叶项");
    }

    /* 相邻页的叶项必须正好相差一个表项（8 字节）。 */
    {
        const unsigned long long a =
            KswordArkHvmSelfMapEntryAddress(base, kernelVa);
        const unsigned long long b =
            KswordArkHvmSelfMapEntryAddress(base, kernelVa + 0x1000ULL);

        CheckEqU64(b - a, 8ULL, "相邻页的叶项相差 8 字节");
    }

    /* 遍历全部 512 个槽位，确认没有一个会越出自身的自映射区。 */
    {
        unsigned long slot = 0UL;
        int allInside = 1;

        for (slot = 0UL; slot < 512UL; ++slot) {
            const unsigned long long slotBase =
                KswordArkHvmSelfMapBaseFromIndex(slot);
            const unsigned long long entry =
                KswordArkHvmSelfMapEntryAddress(slotBase, kernelVa);

            if (entry - slotBase >= (1ULL << 39)) {
                allInside = 0;
                break;
            }
        }
        Check(allInside, "512 个候选槽位的叶项都落在各自的自映射区内");
    }
}

/* ------------------------------------------------------------------ */

static void
TestEptpValidation(void)
{
    /* 一台典型机器：支持 WB、四级 walk、A/D。 */
    const unsigned long long caps =
        KSWORD_ARK_HVM_EPT_CAP_PAGE_WALK_4 |
        KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_WB |
        KSWORD_ARK_HVM_EPT_CAP_ACCESSED_DIRTY;
    const unsigned long maxPa = 39UL;
    /* WB + 四级 walk + 一个合法的页帧。 */
    const unsigned long long goodEptp = 0x0000000012345000ULL | 6ULL | (3ULL << 3);

    Group("EPTP 校验");

    Check(KswordArkHvmEptpIsValid(goodEptp, caps, maxPa),
          "典型合法 EPTP 被接受");

    /*
     * 全零项永远非法：页遍历级数字段为 0 意味着"一级"，架构不支持。
     * 这条直接决定 EPTP list 里未使用的槽不能留空。
     */
    Check(!KswordArkHvmEptpIsValid(0ULL, caps, maxPa),
          "全零 EPTP 被拒绝——list 的空槽不能留零");

    /* 内存类型必须是硬件报告支持的。 */
    Check(!KswordArkHvmEptpIsValid(
              (goodEptp & ~7ULL) | 5ULL, caps, maxPa),
          "未定义的内存类型编码被拒绝");
    Check(!KswordArkHvmEptpIsValid(
              (goodEptp & ~7ULL) | 0ULL, caps, maxPa),
          "硬件未报告支持 UC 时 UC 被拒绝");

    /* 页遍历级数必须正好是 3（四级）。 */
    Check(!KswordArkHvmEptpIsValid(
              (goodEptp & ~(7ULL << 3)) | (2ULL << 3), caps, maxPa),
          "三级页遍历被拒绝");

    /* 硬件不支持 A/D 时不得开启。 */
    Check(!KswordArkHvmEptpIsValid(
              goodEptp | KSWORD_ARK_HVM_EPTP_ACCESSED_DIRTY,
              caps & ~KSWORD_ARK_HVM_EPT_CAP_ACCESSED_DIRTY,
              maxPa),
          "硬件不支持时开启 accessed/dirty 被拒绝");
    Check(KswordArkHvmEptpIsValid(
              goodEptp | KSWORD_ARK_HVM_EPTP_ACCESSED_DIRTY, caps, maxPa),
          "硬件支持时开启 accessed/dirty 被接受");

    /* 保留位必须为零。 */
    Check(!KswordArkHvmEptpIsValid(goodEptp | (1ULL << 8), caps, maxPa),
          "低位保留域非零被拒绝");

    /* 超出物理地址宽度的高位必须为零。 */
    Check(!KswordArkHvmEptpIsValid(
              goodEptp | (1ULL << 40), caps, maxPa),
          "超出 MAXPHYADDR 的页帧位被拒绝");
    Check(KswordArkHvmEptpIsValid(
              goodEptp | (1ULL << 38), caps, maxPa),
          "MAXPHYADDR 之内的高位页帧被接受");

    /* 缺少四级 walk 能力时一律拒绝。 */
    Check(!KswordArkHvmEptpIsValid(
              goodEptp,
              caps & ~KSWORD_ARK_HVM_EPT_CAP_PAGE_WALK_4,
              maxPa),
          "硬件不支持四级页遍历时被拒绝");
}

/* ------------------------------------------------------------------ */

/*
 * EPT 层次索引分解。
 *
 * 这段算术在驱动里决定「收紧哪一个 2MiB 叶项」。算错不会 fault，只会安静地
 * 改掉另一块无关内存的权限——症状出现在离现场很远的地方。所以这里既验手算
 * 点，也验不变量：同一叶项内任意地址索引相同、跨叶项恰好进位一格。
 */
static void
TestEptIndices(void)
{
    unsigned long long address = 0ULL;
    unsigned long index = 0UL;

    Group("EPT 层次索引分解");

    /* 零地址落在每一级的 0 号槽。 */
    Check(KswordArkHvmEptPml4Index(0ULL) == 0UL &&
          KswordArkHvmEptPdptIndex(0ULL) == 0UL &&
          KswordArkHvmEptPdIndex(0ULL) == 0UL,
          "物理地址 0 落在三级 0 号槽");

    /* 第二个 2MiB 叶项只推进 PD 索引。 */
    address = KSWORD_ARK_HVM_LARGE_PAGE_BYTES;
    Check(KswordArkHvmEptPml4Index(address) == 0UL &&
          KswordArkHvmEptPdptIndex(address) == 0UL &&
          KswordArkHvmEptPdIndex(address) == 1UL,
          "跨一个 2MiB 只推进 PD 索引");

    /* 一 GiB 边界推进 PDPT 并把 PD 归零。 */
    address = KSWORD_ARK_HVM_ONE_GIB;
    Check(KswordArkHvmEptPml4Index(address) == 0UL &&
          KswordArkHvmEptPdptIndex(address) == 1UL &&
          KswordArkHvmEptPdIndex(address) == 0UL,
          "1 GiB 边界推进 PDPT 且 PD 归零");

    /* 512 GiB 边界推进 PML4 并把下两级归零。 */
    address = KSWORD_ARK_HVM_ONE_512_GIB;
    Check(KswordArkHvmEptPml4Index(address) == 1UL &&
          KswordArkHvmEptPdptIndex(address) == 0UL &&
          KswordArkHvmEptPdIndex(address) == 0UL,
          "512 GiB 边界推进 PML4 且下两级归零");

    /* 每一级的最后一个槽都恰好是 511，不是 512。 */
    address = KSWORD_ARK_HVM_ONE_512_GIB - 1ULL;
    Check(KswordArkHvmEptPdptIndex(address) == 511UL &&
          KswordArkHvmEptPdIndex(address) == 511UL,
          "512 GiB 前最后一字节落在 511/511 槽");

    /*
     * 不变量：一个 2MiB 叶项内部的任意偏移，三级索引必须完全相同。
     * 这一条覆盖的是取模写错成取整（或反过来）的情形。
     */
    for (index = 0UL; index < 64UL; ++index) {
        const unsigned long long base = 0x1C0000000ULL;
        const unsigned long long probe =
            base + (index * (KSWORD_ARK_HVM_LARGE_PAGE_BYTES / 64ULL));

        if (KswordArkHvmEptPml4Index(probe) !=
                KswordArkHvmEptPml4Index(base) ||
            KswordArkHvmEptPdptIndex(probe) !=
                KswordArkHvmEptPdptIndex(base) ||
            KswordArkHvmEptPdIndex(probe) !=
                KswordArkHvmEptPdIndex(base)) {
            break;
        }
    }
    Check(index == 64UL, "同一 2MiB 叶项内所有偏移索引相同");

    /* 不变量：向下取整到叶项基址后，索引不变且基址已对齐。 */
    address = 0x1C012345ULL;
    Check(KswordArkHvmEptLeafBase(address) ==
              (address & ~(KSWORD_ARK_HVM_LARGE_PAGE_BYTES - 1ULL)) &&
          (KswordArkHvmEptLeafBase(address) %
              KSWORD_ARK_HVM_LARGE_PAGE_BYTES) == 0ULL &&
          KswordArkHvmEptPdIndex(KswordArkHvmEptLeafBase(address)) ==
              KswordArkHvmEptPdIndex(address),
          "取整到叶项基址后对齐且索引不变");

    /* 已对齐的地址取整后不动。 */
    Check(KswordArkHvmEptLeafBase(KSWORD_ARK_HVM_ONE_GIB) ==
              KSWORD_ARK_HVM_ONE_GIB,
          "已对齐地址取整后不变");
}

/*
 * 域限制只能减权限。
 *
 * 这是 VMFUNC 安全性的全部依据：VMFUNC 不做 CPL 检查，任何 ring 3 线程都能切
 * 进域。只要域永远不可能比默认视图更宽松，切过去就拿不到新的访问权。
 */
static void
TestDomainRestriction(void)
{
    const unsigned long long rwx =
        KSWORD_ARK_HVM_EPT_READ |
        KSWORD_ARK_HVM_EPT_WRITE |
        KSWORD_ARK_HVM_EPT_EXECUTE;
    unsigned long long leaf = 0ULL;
    unsigned long long once = 0ULL;
    unsigned long long twice = 0ULL;
    unsigned long bits = 0UL;

    Group("域限制只减不增");

    /* 拿掉写权限后只剩读与执行。 */
    leaf = KswordArkHvmEptApplyRestriction(
        rwx, KSWORD_ARK_HVM_EPT_WRITE);
    CheckEqU64(leaf,
               KSWORD_ARK_HVM_EPT_READ | KSWORD_ARK_HVM_EPT_EXECUTE,
               "拿掉写权限后剩读与执行");

    /* 幂等：同一限制施加两次与一次结果相同。 */
    once = KswordArkHvmEptApplyRestriction(
        rwx, KSWORD_ARK_HVM_EPT_EXECUTE);
    twice = KswordArkHvmEptApplyRestriction(
        once, KSWORD_ARK_HVM_EPT_EXECUTE);
    CheckEqU64(twice, once, "同一限制重复施加是幂等的");

    /* 保留位不被限制影响：suppress-#VE 与内存类型必须活下来。 */
    leaf = KswordArkHvmEptApplyRestriction(
        rwx | (1ULL << 63) | (6ULL << 3),
        KSWORD_ARK_HVM_EPT_WRITE);
    Check((leaf & (1ULL << 63)) != 0ULL &&
          ((leaf >> 3) & 7ULL) == 6ULL,
          "限制不影响 suppress-#VE 与内存类型");

    /*
     * 核心不变量：穷举全部 8 种权限组合与 8 种移除集合，结果的权限位永远是
     * 原权限位的子集。这一条直接对应「域不可能比默认视图更宽松」。
     */
    for (bits = 0UL; bits < 64UL; ++bits) {
        const unsigned long long original = (unsigned long long)(bits & 7UL);
        const unsigned long long removed =
            (unsigned long long)((bits >> 3) & 7UL);
        const unsigned long long result =
            KswordArkHvmEptApplyRestriction(original, removed);

        if ((result & ~original) != 0ULL) {
            break;
        }
    }
    Check(bits == 64UL, "任意组合下结果权限都是原权限的子集");
}

/* ------------------------------------------------------------------ */

int
main(void)
{
    printf("hvm_unit_tests - KswordArkHvmControls.h\n");
    printf("================================================\n");

    TestAdjustControls();
    TestMsrBitmap();
    TestSelfMap();
    TestEptpValidation();
    TestEptIndices();
    TestDomainRestriction();

    printf("\n================================================\n");
    printf("%d 项检查，%d 项失败\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
