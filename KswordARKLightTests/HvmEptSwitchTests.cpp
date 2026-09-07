// EPTP 切换后端（shared/driver/KswordArkHvmEptSwitch.h）的离线自动测试。
//
// 被测的东西有一个共同特征：**算错了不会报错**。叶项保留位没清干净只会变成一次
// exit reason 49；EPTP 的级数字段写成 4 只会让 VM entry 返回一个数字；层次索引
// 差一格会让一个页永久停在影子上而所有自检全绿；状态机错一个分支的结局是整机
// 静默死锁。这些都不是「装上去跑一次就知道」的错误，所以它们必须在编译机上被
// 证明。
//
// 断言原则（与 CrossViewTests.cpp 一致）：
//   * 期望值一律**独立手算写死**，绝不从被测函数反算 —— 拿被测代码算期望值
//     的测试只能证明它自己等于自己；
//   * 良构判据断言**具体的失败项**而不是「非零」，否则「错了另一项」的回归会
//     整类逃逸；
//   * 状态机做**穷举**：(当前层次 × 访问类型 × 视图种类) 全组合逐一钉死结局、
//     目标索引与拒绝原因，不该发生的转移必须被显式拒绝；
//   * 边界两侧都测（最大物理地址、级数编码的合法与非法、索引 511 与 512、
//     预算刚好与刚好超），只测一侧的边界测试等于没测边界。

#include "TestSupport.h"

#include "../shared/driver/KswordArkHvmEptSwitch.h"

#include <cstdint>

namespace {

// ---------------------------------------------------------------------------
// 手算出来的样本值。每一个都在注释里写清它的位是怎么来的，
// 这样将来有人改了布局，对不上的是注释里的算式而不是一个魔数。
// ---------------------------------------------------------------------------

// 2MiB 恒等叶：帧 = 1GiB(0x40000000)，RWX(0x7)，WB(6<<3 = 0x30)，
// 大页(0x80)，suppress-#VE(bit 63)。低字节 = 0x7|0x30|0x80 = 0xB7。
constexpr std::uint64_t kLargeLeaf = 0x80000000400000B7ULL;
// 同一张叶的属性部分：去掉 RWX 与页帧，剩 suppress-#VE | 0xB0。
constexpr std::uint64_t kLargeAttributes = 0x80000000000000B0ULL;

// 4KiB 叶：帧 0x12345000，RWX，WB，无大页位。低字节 = 0x7|0x30 = 0x37。
constexpr std::uint64_t kSmallLeaf = 0x8000000012345037ULL;
// 4KiB 叶的属性部分：suppress-#VE | WB(0x30)。
constexpr std::uint64_t kSmallAttributes = 0x8000000000000030ULL;
constexpr std::uint64_t kSmallFrame = 0x0000000012345000ULL;

// 典型的实现物理宽度。39 位足够让「bit 40 的帧」成为一个越界样本。
constexpr std::uint32_t kPhysBits39 = 39U;

// 基座 EPTP：根 0x01000000，WB(6)，四级 walk(3<<3 = 0x18)。0x6|0x18 = 0x1E。
constexpr std::uint64_t kBaseEptp = 0x0100001EULL;
// 同一个基座打开 A/D（bit 6 = 0x40）。
constexpr std::uint64_t kBaseEptpAd = 0x0100005EULL;

// EPT/VPID 能力：四级 walk(bit 6) + WB(bit 14) + A/D(bit 21)。
constexpr std::uint64_t kCapWb = 0x0000000000204040ULL;
// 再加上 UC(bit 8)。
constexpr std::uint64_t kCapWbUc = 0x0000000000204140ULL;
// INVEPT(bit 20) + single(bit 25) + all(bit 26)。
constexpr std::uint64_t kCapInvept = 0x0000000006100000ULL;

// ---------------------------------------------------------------------------
// 叶项的解析与合成
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 架构常量的数值
// ---------------------------------------------------------------------------

// 这一节存在的唯一理由是:**符号化引用抓不到重新编号**。
//
// 上一轮评审注入了六条「把某个架构常量挪到另一位」的变异,344 条断言一条都没响,
// 因为每一条断言都写成 f(SYMBOL) == SYMBOL —— 两边一起变,等式恒成立。
// 具体存活的是:INVEPT 的 1/2 对调、叶的 accessed/dirty 对调、ignore-PAT 挪到
// bit 5、user-execute 挪到 bit 11、EPT 能力位 execute-only 挪离 bit 0、
// 以及协议镜像 CLOAK/HOOK 与 READ/WRITE 的对调。
//
// 所以下面每一条都把**字面量**写在等号右边,并在注释里写清这个数出自 SDM 的
// 哪一处、以及写错之后机器会怎样安静地做错事。
// 头文件里另有一组同样的编译期断言:那一组保护驱动的编译,这一组保护单测本身。

void TestArchitecturalConstants(KswordTests::Suite& s) {
    // --- EPT 叶项:SDM Vol.3C, Table 29-6 ---
    // 权限位错位 = CLOAK 的「不可读」变成「不可写」,影子页对所有读者永久暴露。
    s.expect(KSWORD_ARK_HVM_EPTSW_READ == 0x1ULL,
             L"the EPT read bit is bit 0");
    s.expect(KSWORD_ARK_HVM_EPTSW_WRITE == 0x2ULL,
             L"the EPT write bit is bit 1");
    s.expect(KSWORD_ARK_HVM_EPTSW_EXECUTE == 0x4ULL,
             L"the EPT execute bit is bit 2");
    s.expect(KSWORD_ARK_HVM_EPTSW_PERM_MASK == 0x7ULL,
             L"the permission mask is exactly bits 2:0");
    // 内存类型域挪一位 = MMIO 页从 UC 变成 WB,设备行为随机出错,没人会怀疑 EPT。
    s.expect(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_SHIFT == 3,
             L"the leaf memory type field starts at bit 3");
    s.expect(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_MASK == 0x7ULL,
             L"the leaf memory type field is three bits wide");
    // ignore-PAT 挪到 bit 5 就落进内存类型域:一个 WB 页会被读成 WP 页。
    s.expect(KSWORD_ARK_HVM_EPTSW_IGNORE_PAT == 0x40ULL,
             L"ignore-PAT is bit 6, not anywhere inside the memory type field");
    // 大页位挪一位 = 处理器把 2MiB 叶当成指向下一级表的指针,去走页内容。
    s.expect(KSWORD_ARK_HVM_EPTSW_LARGE_PAGE == 0x80ULL,
             L"the large-page bit is bit 7");
    // A/D 对调 = 「这一页被写过」被读成「这一页被访问过」,取证结论正好反过来。
    s.expect(KSWORD_ARK_HVM_EPTSW_ACCESSED == 0x100ULL,
             L"the accessed bit is bit 8");
    s.expect(KSWORD_ARK_HVM_EPTSW_DIRTY == 0x200ULL,
             L"the dirty bit is bit 9");
    s.expect(KSWORD_ARK_HVM_EPTSW_USER_EXECUTE == 0x400ULL,
             L"user-mode execute is bit 10");
    // suppress-#VE 掉位 = #VE 打开后一次访问就 #GP -> #DF -> triple fault。
    s.expect(KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE == 0x8000000000000000ULL,
             L"suppress-#VE is bit 63");
    s.expect(KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK == 0x000FFFFFFFFFF000ULL,
             L"the physical address field is bits 51:12");
    s.expect(KSWORD_ARK_HVM_EPTSW_LARGE_FRAME_MASK == 0x000FFFFFFFE00000ULL,
             L"the two-MiB frame field is bits 51:21");
    s.expect(KSWORD_ARK_HVM_EPTSW_PAGE_BYTES == 0x1000ULL &&
                 KSWORD_ARK_HVM_EPTSW_LARGE_BYTES == 0x200000ULL &&
                 KSWORD_ARK_HVM_EPTSW_TABLE_ENTRIES == 512U &&
                 KSWORD_ARK_HVM_EPTSW_ENTRY_BYTES == 8ULL,
             L"page geometry is four KiB, two MiB, 512 entries of eight bytes");
    // 五种合法内存类型的编码,2/3/7 保留。
    s.expect(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_UC == 0ULL &&
                 KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WC == 1ULL &&
                 KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WT == 4ULL &&
                 KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WP == 5ULL &&
                 KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WB == 6ULL,
             L"the five architectural EPT memory type encodings are 0, 1, 4, 5 and 6");

    // --- EPTP 字段:SDM Vol.3C, Table 25-9 ---
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_MEMORY_TYPE_MASK == 0x7ULL,
             L"the EPTP memory type field is bits 2:0");
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_WALK_SHIFT == 3,
             L"the EPTP walk-length field starts at bit 3");
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_WALK_MASK == 0x7ULL,
             L"the EPTP walk-length field is three bits wide");
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_ACCESSED_DIRTY == 0x40ULL,
             L"the EPTP accessed/dirty enable is bit 6");
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_LOW == 0xF80ULL,
             L"EPTP bits 11:7 are reserved");
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_WALK_LEVELS == 4U,
             L"this driver uses a four-level walk, which the field encodes as three");

    // --- IA32_VMX_EPT_VPID_CAP:SDM Vol.3D, Appendix A.10 ---
    // execute-only 那一位读错的后果不对称:判成「支持」而硬件不支持,
    // 写下去的 --x 叶就是一次 EPT misconfiguration。
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_EXECUTE_ONLY == 0x1ULL,
             L"execute-only support is capability bit 0");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_PAGE_WALK_4 == 0x40ULL,
             L"four-level page walk support is capability bit 6");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_UC == 0x100ULL,
             L"UC EPTP support is capability bit 8");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_WB == 0x4000ULL,
             L"WB EPTP support is capability bit 14");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_INVEPT == 0x100000ULL,
             L"the INVEPT instruction itself is capability bit 20");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_ACCESSED_DIRTY == 0x200000ULL,
             L"accessed/dirty support is capability bit 21");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_SINGLE == 0x2000000ULL,
             L"single-context INVEPT support is capability bit 25");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_ALL == 0x4000000ULL,
             L"all-context INVEPT support is capability bit 26");

    // --- INVEPT 类型:SDM Vol.3C, 30.3 ---
    // 这两个数会被原样装进寄存器交给 INVEPT。对调之后请求 all 会发出一次
    // descriptor 全零的 single —— 那一次失效什么都没刷掉,没有任何症状。
    s.expect(KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE == 1U,
             L"INVEPT type one is single-context");
    s.expect(KSWORD_ARK_HVM_EPTSW_INVEPT_ALL == 2U,
             L"INVEPT type two is all-context");

    // --- 协议镜像:KswordArkHvmIoctl.h:336-338 与 :754/756 ---
    // 本地这一份的数值由下面钉死;对面那一份由驱动 .c 里的 C_ASSERT 钉死
    // (头文件注释里逐行列出了要写的五条)。
    s.expect(KSWORD_ARK_HVM_EPTSW_ACCESS_READ == 1U,
             L"protocol access read is bit 0, mirroring KSWORD_ARK_HVM_EPT_ACCESS_READ");
    s.expect(KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE == 2U,
             L"protocol access write is bit 1, mirroring KSWORD_ARK_HVM_EPT_ACCESS_WRITE");
    s.expect(KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE == 4U,
             L"protocol access execute is bit 2, mirroring KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE");
    s.expect(KSWORD_ARK_HVM_EPTSW_ACCESS_MASK == 7U,
             L"the protocol access mask is exactly the three defined bits");
    // KIND 对调 = IOCTL 送进来的 CLOAK 被服务成 HOOK 的权限对,主值变成 rw- 的
    // 真帧,那一页对所有读者永远可读 —— 隐藏变成暴露,而一切看起来正常。
    s.expect(KSWORD_ARK_HVM_EPTSW_KIND_CLOAK == 1U,
             L"view kind CLOAK is one, mirroring KSWORD_ARK_HVM_VIEW_KIND_CLOAK");
    s.expect(KSWORD_ARK_HVM_EPTSW_KIND_HOOK == 2U,
             L"view kind HOOK is two, mirroring KSWORD_ARK_HVM_VIEW_KIND_HOOK");

    // --- 规模上限 ---
    s.expect(KSWORD_ARK_HVM_EPTSW_MAX_LEAVES == 32U,
             L"the leaf limit mirrors KSWORD_ARK_HVM_MAX_VIEWS, which is thirty-two");
    s.expect(KSWORD_ARK_HVM_EPTSW_PATH_PAGES == 4ULL,
             L"one private path is root plus PDPT plus PD plus PT");
    s.expect(KSWORD_ARK_HVM_EPTSW_MAX_SAME_RIP_SWITCHES == 8U,
             L"eight is twice the largest number of legitimate faults one instruction can take");

    // --- 与 KswordArkHvmControls.h 的跨头一致性 ---
    // 别名过去的常量必须仍然等于同族头里的那一个:这两组只要哪天分叉,
    // 同一个驱动里就会有两套位布局,而硬件不会告诉你用错了哪一套。
    s.expect(KSWORD_ARK_HVM_EPTSW_READ == KSWORD_ARK_HVM_EPT_READ &&
                 KSWORD_ARK_HVM_EPTSW_WRITE == KSWORD_ARK_HVM_EPT_WRITE &&
                 KSWORD_ARK_HVM_EPTSW_EXECUTE == KSWORD_ARK_HVM_EPT_EXECUTE,
             L"the permission bits are the same objects the shared controls header defines");
    s.expect(KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK == KSWORD_ARK_HVM_EPT_PHYSICAL_MASK,
             L"the physical mask agrees with the shared controls header");
    s.expect(KSWORD_ARK_HVM_EPTSW_PAGE_BYTES == KSWORD_ARK_HVM_PAGE_BYTES &&
                 KSWORD_ARK_HVM_EPTSW_LARGE_BYTES == KSWORD_ARK_HVM_LARGE_PAGE_BYTES,
             L"page geometry agrees with the shared controls header");
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_MEMORY_TYPE_MASK ==
                     KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_MASK &&
                 KSWORD_ARK_HVM_EPTSW_EPTP_WALK_SHIFT ==
                     KSWORD_ARK_HVM_EPTP_WALK_LENGTH_SHIFT &&
                 KSWORD_ARK_HVM_EPTSW_EPTP_WALK_MASK ==
                     KSWORD_ARK_HVM_EPTP_WALK_LENGTH_MASK &&
                 KSWORD_ARK_HVM_EPTSW_EPTP_ACCESSED_DIRTY ==
                     KSWORD_ARK_HVM_EPTP_ACCESSED_DIRTY &&
                 KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_LOW ==
                     KSWORD_ARK_HVM_EPTP_RESERVED_LOW,
             L"every EPTP field agrees with the shared controls header");
    s.expect(KSWORD_ARK_HVM_EPTSW_CAP_PAGE_WALK_4 == KSWORD_ARK_HVM_EPT_CAP_PAGE_WALK_4 &&
                 KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_UC ==
                     KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_UC &&
                 KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_WB ==
                     KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_WB &&
                 KSWORD_ARK_HVM_EPTSW_CAP_ACCESSED_DIRTY ==
                     KSWORD_ARK_HVM_EPT_CAP_ACCESSED_DIRTY,
             L"every capability bit agrees with the shared controls header");
    // 索引分解:本文件用移位加九位掩码,Controls.h 用除法取模。两者在 48 位以内
    // 必须逐值相同 —— 那是唯一一段两套公式都能表示的范围;超过 48 位 Controls
    // 那条会长出大于 511 的 PML4 号,所以只在可表示区间内断言,不放宽任何一边。
    {
        bool decompositionAgrees = true;
        const std::uint64_t probes[] = {
            0ULL, 0x1000ULL, 0x200000ULL, 0x40000000ULL,
            0x000002CB02390123ULL, 0x0000123456789ABCULL,
            0x0000FFFFFFFFFFFFULL,
        };
        for (const std::uint64_t probe : probes) {
            if (KswordArkHvmEptSwPml4Index(probe) != KswordArkHvmEptPml4Index(probe) ||
                KswordArkHvmEptSwPdptIndex(probe) != KswordArkHvmEptPdptIndex(probe) ||
                KswordArkHvmEptSwPdIndex(probe) != KswordArkHvmEptPdIndex(probe) ||
                KswordArkHvmEptSwPtIndex(probe) != KswordArkHvmEptPtIndex(probe)) {
                decompositionAgrees = false;
            }
        }
        s.expect(decompositionAgrees,
                 L"index decomposition agrees with the shared controls header below 2^48");
    }
    // 重定基址是同一个公式,所以直接断言同一个结果,而不是各写一遍表达式。
    s.expect(KswordArkHvmEptSwRebaseEptp(kBaseEptpAd, 0x02000000ULL) ==
                 KswordArkHvmEptRebaseEntry(kBaseEptpAd, 0x02000000ULL),
             L"rebasing an EPT pointer is the shared rebase, not a second copy of it");
}

void TestExecuteOnlyCapability(KswordTests::Suite& s) {
    // 上一版 CAP_EXECUTE_ONLY 定义了却没有任何函数读它,于是它可以被挪到任何一位
    // 而单测毫无反应。现在它有唯一一个读者,这几条断言就是那个读者的判据。
    s.expect(KswordArkHvmEptSwExecuteOnlySupported(0x1ULL) == 1,
             L"bit 0 alone reports execute-only support");
    s.expect(KswordArkHvmEptSwExecuteOnlySupported(0ULL) == 0,
             L"an all-zero capability reports no execute-only support");
    // 除 bit 0 以外的每一位都不得被误读成 execute-only。
    {
        bool onlyBitZero = true;
        for (std::uint32_t bit = 1U; bit < 64U; ++bit) {
            if (KswordArkHvmEptSwExecuteOnlySupported(1ULL << bit) != 0) {
                onlyBitZero = false;
            }
        }
        s.expect(onlyBitZero,
                 L"no capability bit other than bit zero is read as execute-only");
    }
    // 真实的能力面:kCapInvept 没有 bit 0,kCapWb 也没有。
    s.expect(KswordArkHvmEptSwExecuteOnlySupported(kCapWb) == 0 &&
                 KswordArkHvmEptSwExecuteOnlySupported(kCapInvept) == 0,
             L"the sample capability masks in this file advertise no execute-only");
    s.expect(KswordArkHvmEptSwExecuteOnlySupported(kCapWb | 0x1ULL) == 1,
             L"adding bit zero to a real capability mask turns execute-only on");
}

void TestLeafDecomposition(KswordTests::Suite& s) {
    s.expect(KswordArkHvmEptSwLeafPermissions(kLargeLeaf) == 0x7ULL,
             L"leaf permissions are bits 2:0");
    s.expect(KswordArkHvmEptSwLeafFrame(kLargeLeaf) == 0x40000000ULL,
             L"leaf frame is bits 51:12");
    s.expect(KswordArkHvmEptSwLeafMemoryType(kLargeLeaf) == 6ULL,
             L"leaf memory type is bits 5:3 and decodes to write-back");
    // 属性必须带走 suppress-#VE：掉了这一位，#VE 打开后这一页的违规会被反射进
    // Windows 没有准备的 IDT[20]，而安装期毫无异常。
    s.expect(KswordArkHvmEptSwLeafAttributes(kLargeLeaf) == kLargeAttributes,
             L"leaf attributes keep suppress-#VE, memory type and the large-page bit");
    s.expect((KswordArkHvmEptSwLeafAttributes(kLargeLeaf) &
              KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE) != 0ULL,
             L"leaf attributes never drop suppress-#VE");
    s.expect((KswordArkHvmEptSwLeafAttributes(kLargeLeaf) & 0x7ULL) == 0ULL,
             L"leaf attributes carry no permission bits");
    s.expect((KswordArkHvmEptSwLeafAttributes(kLargeLeaf) &
              KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) == 0ULL,
             L"leaf attributes carry no page frame");

    s.expect(KswordArkHvmEptSwLeafMemoryType(kSmallLeaf) == 6ULL,
             L"four-KiB leaf memory type decodes to write-back");
    s.expect(KswordArkHvmEptSwLeafAttributes(kSmallLeaf) == kSmallAttributes,
             L"four-KiB leaf attributes are suppress-#VE plus write-back");
}

void TestLeafComposition(KswordTests::Suite& s) {
    // 0x80000000000000B0 | 0x0000007654321000 | 0x3 = 0x80000076543210B3。
    constexpr std::uint64_t kExpected = 0x80000076543210B3ULL;
    s.expect(KswordArkHvmEptSwComposeLeaf(
                 kLargeAttributes, 0x0000007654321000ULL, 0x3ULL) == kExpected,
             L"composing a leaf ors attributes, frame and permissions");
    // 未对齐的影子帧必须被掩掉，否则低 12 位会泼进权限位与内存类型域 ——
    // 得到一个权限更宽、缓存类型被改掉的叶，而它看上去完全正常。
    s.expect(KswordArkHvmEptSwComposeLeaf(
                 kLargeAttributes, 0x0000007654321FFFULL, 0x3ULL) == kExpected,
             L"an unaligned frame cannot bleed into the permission or memory-type field");
    // 协议访问掩码里多出来的位同样不许落到内存类型上。
    s.expect(KswordArkHvmEptSwComposeLeaf(
                 kLargeAttributes, 0x0000007654321000ULL, 0xF3ULL) == kExpected,
             L"permission bits outside 2:0 cannot bleed into the memory-type field");
    // 调用方误传一个完整的原始叶项当属性时，旧页帧不能与新页帧或在一起 ——
    // 那会指向一个既不是真页也不是影子页的地方，而 CLOAK 主值指错帧意味着
    // 执行的就是错的字节。
    s.expect(KswordArkHvmEptSwComposeLeaf(
                 kLargeLeaf, 0x0000007654321000ULL, 0x3ULL) == kExpected,
             L"a full entry passed as attributes cannot leak its old frame or permissions");

    // 视图的两个值：属性逐位继承，只有帧与权限不同。
    const std::uint64_t cloakPrimary = KswordArkHvmEptSwComposeLeaf(
        kSmallAttributes, kSmallFrame, KSWORD_ARK_HVM_EPTSW_EXECUTE);
    const std::uint64_t cloakSecondary = KswordArkHvmEptSwComposeLeaf(
        kSmallAttributes, 0x0000000099999000ULL,
        KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE);
    s.expect(cloakPrimary == 0x8000000012345034ULL,
             L"CLOAK primary is execute-only on the real frame");
    s.expect(cloakSecondary == 0x8000000099999033ULL,
             L"CLOAK secondary is read-write on the shadow frame");
    s.expect(KswordArkHvmEptSwLeafMemoryType(cloakPrimary) ==
                 KswordArkHvmEptSwLeafMemoryType(cloakSecondary),
             L"both view values keep the identity leaf's memory type");
    s.expect((cloakPrimary & KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE) != 0ULL &&
                 (cloakSecondary & KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE) != 0ULL,
             L"both view values keep suppress-#VE");
    s.expect(KswordArkHvmEptSwLeafFrame(cloakPrimary) == kSmallFrame,
             L"CLOAK primary points at the real frame, not the shadow");
    s.expect(KswordArkHvmEptSwLeafFrame(cloakSecondary) == 0x0000000099999000ULL,
             L"CLOAK secondary points at the shadow frame, not the real page");
}

// ---------------------------------------------------------------------------
// 叶项良构判据
// ---------------------------------------------------------------------------

void TestPermissionLegality(KswordTests::Suite& s) {
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x1ULL, 1) == 1,
             L"read-only is legal");
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x3ULL, 1) == 1,
             L"read-write is legal");
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x5ULL, 1) == 1,
             L"read-execute is legal");
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x7ULL, 1) == 1,
             L"read-write-execute is legal");
    // 写不带读在 EPT 里没有编码，写进叶就是 misconfiguration。
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x2ULL, 1) == 0,
             L"write without read is refused");
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x6ULL, 1) == 0,
             L"write-execute without read is refused");
    // execute-only 只在硬件报告时合法。
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x4ULL, 1) == 1,
             L"execute-only is legal when the processor advertises it");
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x4ULL, 0) == 0,
             L"execute-only is refused when the processor cannot encode it");
    // 权限全零在本机制下永远找不到能服务它的层次 —— 那是一个不前进的环。
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0x0ULL, 1) == 0,
             L"an all-zero permission leaf is refused because no hierarchy can serve it");
    // 权限域之外的位不参与判断。
    s.expect(KswordArkHvmEptSwPermissionsAreLegal(0xF3ULL, 1) == 1,
             L"only bits 2:0 take part in the permission judgement");
}

void TestMemoryTypeLegality(KswordTests::Suite& s) {
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(0ULL) == 1, L"UC is a legal leaf memory type");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(1ULL) == 1, L"WC is a legal leaf memory type");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(4ULL) == 1, L"WT is a legal leaf memory type");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(5ULL) == 1, L"WP is a legal leaf memory type");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(6ULL) == 1, L"WB is a legal leaf memory type");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(2ULL) == 0, L"encoding 2 is reserved");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(3ULL) == 0, L"encoding 3 is reserved");
    s.expect(KswordArkHvmEptSwMemoryTypeIsLegal(7ULL) == 0, L"encoding 7 is reserved");
}

void TestFrameAlignment(KswordTests::Suite& s) {
    s.expect(KswordArkHvmEptSwFrameIsAligned(0x40000000ULL, 1) == 1,
             L"a two-MiB aligned frame fits a large leaf");
    // 只按 4KiB 对齐的影子帧写进 2MiB 叶：安装期一切正常，第一次访问 misconfig。
    s.expect(KswordArkHvmEptSwFrameIsAligned(0x40100000ULL, 1) == 0,
             L"a merely page-aligned frame does not fit a large leaf");
    s.expect(KswordArkHvmEptSwFrameIsAligned(0x40001000ULL, 1) == 0,
             L"bits 20:12 must be zero in a large leaf frame");
    s.expect(KswordArkHvmEptSwFrameIsAligned(0x40100000ULL, 0) == 1,
             L"the same frame is fine for a four-KiB leaf");
    s.expect(KswordArkHvmEptSwFrameIsAligned(0x40000FFFULL, 0) == 0,
             L"a sub-page offset is not a legal four-KiB frame");
}

void TestLeafWellFormed(KswordTests::Suite& s) {
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kLargeLeaf, 1, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"the identity two-MiB leaf is well formed");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kSmallLeaf, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"the four-KiB leaf is well formed");

    // 大页位与层级不一致的两个方向都要被抓住：该置不置会让处理器把页内容当页表
    // 走，不该置却置了会把一个页表项当成 2MiB 叶。
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kLargeLeaf, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_LARGE_BIT,
             L"a large-page bit on a four-KiB leaf is refused");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kSmallLeaf, 1, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_LARGE_BIT,
             L"a missing large-page bit on a two-MiB leaf is refused");

    // 权限：写不带读 / 全零 / 缺 execute-only。
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000012345032ULL, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PERMISSIONS,
             L"a write-without-read leaf is refused");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000012345030ULL, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PERMISSIONS,
             L"a leaf granting nothing is refused");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000012345034ULL, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"an execute-only leaf is accepted where the encoding exists");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000012345034ULL, 0, kPhysBits39, 0) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PERMISSIONS,
             L"an execute-only leaf is refused where the encoding does not exist");

    // 内存类型：0x10 = (2<<3)，0x38 = (7<<3)。
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000012345017ULL, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_MEMORY_TYPE,
             L"leaf memory type 2 is refused");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x800000001234503FULL, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_MEMORY_TYPE,
             L"leaf memory type 7 is refused");

    // 对齐：0x80000000401000B7 的帧是 0x40100000，只按 1MiB 对齐。
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x80000000401000B7ULL, 1, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_ALIGNMENT,
             L"a two-MiB leaf whose frame is not two-MiB aligned is refused");

    // 物理宽度：帧 0x10000000000 是 bit 40。
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000010000000037ULL, 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PHYS_WIDTH,
             L"a frame bit above MAXPHYADDR is refused");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000010000000037ULL, 0, 41U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"the same frame is accepted on a wider implementation");

    // 最大物理地址两侧：0x000FFFFFFFFFF000 是 52 位实现下最高的 4KiB 帧。
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x800FFFFFFFFFF037ULL, 0, 52U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"the highest four-KiB frame is accepted at 52 physical bits");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x800FFFFFFFFFF037ULL, 0, 51U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PHYS_WIDTH,
             L"the same frame is refused at 51 physical bits");

    // 本驱动从不使用的 bits 62:52 段（这里放 bit 57）。
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 kSmallLeaf | (1ULL << 57), 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_RESERVED,
             L"a bit in the unused 62:52 range is refused");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 kSmallLeaf | (1ULL << 52), 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_RESERVED,
             L"bit 52 is inside the refused range");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 kSmallLeaf | (1ULL << 62), 0, kPhysBits39, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_RESERVED,
             L"bit 62 is inside the refused range");
    // bit 63 是 suppress-#VE，必须仍然被接受。
    s.expect((kSmallLeaf & (1ULL << 63)) != 0ULL &&
                 KswordArkHvmEptSwLeafIsWellFormed(
                     kSmallLeaf, 0, kPhysBits39, 1) ==
                     KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"bit 63 is suppress-#VE and stays outside the refused range");

    // 不可能来自 CPUID 的物理宽度。
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kSmallLeaf, 0, 0U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PARAMETER,
             L"a zero physical width is a parameter error");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kSmallLeaf, 0, 31U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PARAMETER,
             L"a physical width below the architectural floor is a parameter error");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kSmallLeaf, 0, 53U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PARAMETER,
             L"a physical width above 52 is a parameter error");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(kSmallLeaf, 0, 32U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"32 physical bits is the architectural floor and is a legal width");
    // 32 位实现的两侧：bit 32 的帧刚好越界，33 位实现下同一个帧合法。
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000100000037ULL, 0, 32U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PHYS_WIDTH,
             L"a frame needing bit 32 is refused on a 32-bit implementation");
    s.expect(KswordArkHvmEptSwLeafIsWellFormed(
                 0x8000000100000037ULL, 0, 33U, 1) ==
                 KSWORD_ARK_HVM_EPTSW_LEAF_OK,
             L"the same frame is accepted once the implementation has 33 bits");
}

// ---------------------------------------------------------------------------
// EPTP 字段
// ---------------------------------------------------------------------------

void TestEptpComposition(KswordTests::Suite& s) {
    // 0x01000000 | 6 | (3 << 3) = 0x0100001E。
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 6ULL, 4U, 0) == kBaseEptp,
             L"a four-level write-back EPTP encodes walk length three");
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 6ULL, 4U, 1) == kBaseEptpAd,
             L"the accessed/dirty enable is bit 6");
    // 级数字段存的是级数减一：写 4 会得到 0x20 而不是 0x18。
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 6ULL, 5U, 0) == 0x01000026ULL,
             L"five levels encode as field value four");
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 6ULL, 0U, 0) == 0ULL,
             L"zero levels cannot be encoded and returns the never-legal value zero");
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 6ULL, 9U, 0) == 0ULL,
             L"nine levels exceed the three-bit field and are refused");
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 6ULL, 8U, 0) == 0x0100003EULL,
             L"eight levels is the largest encodable value");
    // 未对齐的根会把低位泼进内存类型与级数字段。
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000FFFULL, 6ULL, 4U, 0) == kBaseEptp,
             L"an unaligned root cannot corrupt the memory type or walk length");
    // 内存类型只有三位：0xFF 的低三位是 7，0xF6 的低三位是 6（等于基座）。
    // 多出来的高位必须被掩掉，否则它们会落到级数字段与 A/D 位上。
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 0xFFULL, 4U, 0) == 0x0100001FULL,
             L"only bits 2:0 of the memory type reach the pointer");
    s.expect(KswordArkHvmEptSwComposeEptp(0x01000000ULL, 0xF6ULL, 4U, 0) == kBaseEptp,
             L"memory type bits above 2:0 cannot reach the walk-length field or the A/D bit");
}

void TestEptpDecomposition(KswordTests::Suite& s) {
    s.expect(KswordArkHvmEptSwEptpRoot(kBaseEptpAd) == 0x01000000ULL,
             L"the EPTP root is bits 51:12");
    s.expect(KswordArkHvmEptSwEptpMemoryType(kBaseEptpAd) == 6ULL,
             L"the EPTP memory type is bits 2:0");
    // 解析时忘记加一与合成时忘记减一是同一个错误的两面。
    s.expect(KswordArkHvmEptSwEptpWalkLevels(kBaseEptp) == 4U,
             L"walk field three decodes back to four levels");
    s.expect(KswordArkHvmEptSwEptpWalkLevels(0x01000026ULL) == 5U,
             L"walk field four decodes back to five levels");
    s.expect(KswordArkHvmEptSwEptpWalkLevels(0x01000006ULL) == 1U,
             L"walk field zero decodes back to one level, never to zero");
    s.expect(KswordArkHvmEptSwEptpHasAccessedDirty(kBaseEptpAd) == 1,
             L"accessed/dirty is reported when bit 6 is set");
    s.expect(KswordArkHvmEptSwEptpHasAccessedDirty(kBaseEptp) == 0,
             L"accessed/dirty is not reported when bit 6 is clear");
    s.expect(KswordArkHvmEptSwEp4ta(kBaseEptpAd) == 0x01000000ULL,
             L"EP4TA is the root address and ignores the control bits");
}

void TestEptpWellFormed(KswordTests::Suite& s) {
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kBaseEptp, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_OK,
             L"the base pointer is accepted on a write-back four-level machine");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kBaseEptpAd, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_OK,
             L"accessed/dirty is accepted when the capability advertises it");
    // A/D 没有能力支持却置位 —— VM entry 会失败，且只给一个错误码。
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 kBaseEptpAd, kCapWb & ~0x0000000000200000ULL, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_AD,
             L"accessed/dirty without the capability is refused");
    // UC 在没有 UC 能力位时不可用。
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x01000018ULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE,
             L"an uncacheable EPTP is refused without the UC capability");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x01000018ULL, kCapWbUc, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_OK,
             L"an uncacheable EPTP is accepted with the UC capability");
    // EPTP 只承认 UC 与 WB，与叶项的五种编码不是同一套。
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x0100001CULL, kCapWbUc, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE,
             L"write-through is a legal leaf type but never a legal EPTP type");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x0100001BULL, kCapWbUc, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE,
             L"EPTP memory type three is reserved");
    // 级数。
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x01000026ULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_WALK,
             L"a five-level walk is refused");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 kBaseEptp, kCapWb & ~0x0000000000000040ULL, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_WALK,
             L"a four-level walk is refused when the capability does not advertise it");
    // 保留低位 bits 11:7。
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kBaseEptp | 0x80ULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED,
             L"bit 7 is reserved in the EPT pointer");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kBaseEptp | 0x800ULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED,
             L"bit 11 is reserved in the EPT pointer");
    // 根为零：字段判据管不到，但它只可能来自「槽位忘了填」。
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x0000001EULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_ROOT,
             L"a pointer whose root is zero is refused rather than walked");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(0ULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_ROOT,
             L"an all-zero EPT pointer is never legal");
    // 物理宽度。
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 0x000001000000001EULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PHYS_WIDTH,
             L"a root bit above MAXPHYADDR is refused");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 0x000001000000001EULL, kCapWb, 41U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_OK,
             L"the same root is accepted on a wider implementation");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kBaseEptp, kCapWb, 0U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PARAMETER,
             L"a zero physical width is a parameter error for the pointer too");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(kBaseEptp, kCapWb, 53U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PARAMETER,
             L"a physical width above 52 is a parameter error for the pointer too");

    // --- bits 63:52 是架构保留必须为零，与本机实现宽度无关 ---
    // 这一段上一版没有独立判据,只被 widthMask 的副作用兜住;而叶那条路径用的是
    // 更窄的 PHYSICAL_MASK & ~(...) 加一条独立检查。两条路径形状不同,谁把 EPTP
    // 这条「统一」成叶那种写法,63:52 就彻底无人检查,而后果是 VM entry 直接失败,
    // 只给一个错误码。所以这里在**最宽的机器**(MAXPHYADDR = 52)上钉死每一位:
    // 52 位机器的 widthMask 恰好等于 0xFFF0000000000000,如果判据只剩宽度掩码,
    // 下面三条会返回 BAD_PHYS_WIDTH 而不是 BAD_RESERVED_HIGH —— 而一旦有人把
    // 宽度掩码收窄成叶那种形状,它们会直接返回 EPTP_OK。
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 kBaseEptp | 0x0010000000000000ULL, kCapWb, 52U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH,
             L"bit 52 of an EPT pointer is reserved on a 52-bit machine");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 kBaseEptp | 0x0080000000000000ULL, kCapWb, 52U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH,
             L"bit 55 of an EPT pointer is reserved on a 52-bit machine");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 kBaseEptp | 0x8000000000000000ULL, kCapWb, 52U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH,
             L"bit 63 of an EPT pointer is reserved even though it is legal in a leaf");
    // 窄机器上同样是保留位判据先响,而不是宽度判据 —— 两条判据的顺序被钉死,
    // 否则「错了另一项」的回归会整类逃逸。
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 kBaseEptp | 0x8000000000000000ULL, kCapWb, kPhysBits39) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH,
             L"the reserved-high verdict wins over the width verdict on a narrow machine");
    // 保留高位与合法根地址不重叠:52 位机器上 bit 51 的根仍然合法。
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                 0x0008000000000000ULL | 0x1EULL, kCapWb, 52U) ==
                 KSWORD_ARK_HVM_EPTSW_EPTP_OK,
             L"bit 51 is the top of the root field and stays legal on a 52-bit machine");
    // 掩码本身的数值:bits 63:52 = 0xFFF0000000000000,一位不多一位不少。
    s.expect(KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_HIGH == 0xFFF0000000000000ULL,
             L"the EPTP reserved-high mask is exactly bits 63:52");
    s.expect(KSWORD_ARK_HVM_EPTSW_RESERVED_HIGH == 0x7FF0000000000000ULL,
             L"the leaf reserved-high mask is bits 62:52 because bit 63 is suppress-#VE");

    // --- 与 KswordArkHvmControls.h 的判据关系(跨头一致性,finding 8) ---
    // 同一个 EPTP 在一个驱动里绝不能因为调到哪个 helper 而得到两个答案。
    // 本文件的判据是**严格更强**的那一个,所以要钉死的是蕴含方向:
    // EptSw 说 OK => Controls 说合法。反向不成立,那正是本文件多挡的三类值。
    {
        const std::uint64_t implicationSamples[] = {
            kBaseEptp,                       // 典型基座
            kBaseEptpAd,                     // 开 A/D
            0x01000018ULL,                   // UC 类型
            0x000001000000001EULL,           // 宽机器上合法的高位根
            0x0008000000000000ULL | 0x1EULL, // bit 51 的根
        };
        bool implicationHolds = true;
        for (const std::uint64_t sample : implicationSamples) {
            for (std::uint32_t bits = 32U; bits <= 52U; ++bits) {
                if (KswordArkHvmEptSwEptpIsWellFormed(sample, kCapWbUc, bits) ==
                        KSWORD_ARK_HVM_EPTSW_EPTP_OK &&
                    KswordArkHvmEptpIsValid(sample, kCapWbUc, bits) == 0) {
                    implicationHolds = false;
                }
            }
        }
        s.expect(implicationHolds,
                 L"every pointer this file accepts is also accepted by the shared validator");
        // 反向的三类差异各钉一条,免得哪天有人把本文件「简化」成 Controls 那条。
        s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x0000001EULL, kCapWb, 39U) ==
                     KSWORD_ARK_HVM_EPTSW_EPTP_BAD_ROOT &&
                     KswordArkHvmEptpIsValid(0x0000001EULL, kCapWb, 39UL) != 0,
                 L"a zero root is refused here although the shared validator accepts it");
        // 根 0xFF000 塞得进 20 位,所以 Controls 那条会接受;本文件按 CPUID 的
        // 架构下界 32 拒绝 —— 一个 20 位的 MAXPHYADDR 只可能来自读错了寄存器。
        s.expect(KswordArkHvmEptSwEptpIsWellFormed(0x000FF01EULL, kCapWb, 20U) ==
                     KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PARAMETER &&
                     KswordArkHvmEptpIsValid(0x000FF01EULL, kCapWb, 20UL) != 0,
                 L"a physical width below 32 is refused here although the shared one allows it");
        s.expect(KswordArkHvmEptSwEptpIsWellFormed(
                     kBaseEptp | 0x8000000000000000ULL, kCapWb, 52U) ==
                     KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH,
                 L"bit 63 is refused here by a dedicated verdict, not by a side effect");
    }
}

void TestEptpRebase(KswordTests::Suite& s) {
    // 0x02000000 | (0x0100005E & ~PHYS) = 0x0200005E。
    const std::uint64_t derived =
        KswordArkHvmEptSwRebaseEptp(kBaseEptpAd, 0x02000000ULL);
    s.expect(derived == 0x0200005EULL,
             L"rebasing replaces only the root address");
    // 派生而不是合成：控制位必须与基座逐位相同，否则内存类型 / 级数 / A/D
    // 就有了第二个真值来源，而 VM entry 只返回一个错误码。
    s.expect((derived & ~KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) ==
                 (kBaseEptpAd & ~KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK),
             L"a derived pointer keeps every control bit of its source");
    s.expect(KswordArkHvmEptSwEptpMemoryType(derived) ==
                 KswordArkHvmEptSwEptpMemoryType(kBaseEptpAd) &&
                 KswordArkHvmEptSwEptpWalkLevels(derived) ==
                     KswordArkHvmEptSwEptpWalkLevels(kBaseEptpAd) &&
                 KswordArkHvmEptSwEptpHasAccessedDirty(derived) ==
                     KswordArkHvmEptSwEptpHasAccessedDirty(kBaseEptpAd),
             L"memory type, walk length and accessed/dirty survive the rebase");
    s.expect(KswordArkHvmEptSwEptpIsWellFormed(derived, kCapWb, kPhysBits39) ==
                 KswordArkHvmEptSwEptpIsWellFormed(kBaseEptpAd, kCapWb, kPhysBits39),
             L"a derived pointer is accepted exactly when its source is");
    s.expect(KswordArkHvmEptSwRebaseEptp(kBaseEptpAd, 0x02000FFFULL) == derived,
             L"an unaligned new root cannot corrupt the control bits");
    s.expect(KswordArkHvmEptSwEptpRoot(derived) == 0x02000000ULL,
             L"the derived pointer walks the new root");
}

void TestSwitchInvalidation(KswordTests::Suite& s) {
    const std::uint64_t secondary =
        KswordArkHvmEptSwRebaseEptp(kBaseEptp, 0x02000000ULL);
    // 换根即换 EP4TA，缓存条目互不别名 —— 这就是「切 EPTP 之后不发 INVEPT」
    // 的全部依据。
    s.expect(KswordArkHvmEptSwSwitchNeedsInvalidation(kBaseEptp, secondary) == 0,
             L"switching between two roots needs no explicit invalidation");
    s.expect(KswordArkHvmEptSwSwitchNeedsInvalidation(secondary, kBaseEptp) == 0,
             L"the reverse switch needs no explicit invalidation either");
    // 同一个根：切换在硬件上是空操作，同一条指令会永远重新违规。
    s.expect(KswordArkHvmEptSwSwitchNeedsInvalidation(kBaseEptp, kBaseEptp) == 1,
             L"switching to the same root changes no tag and is flagged");
    // 只翻转 A/D 造出来的「次层次」共享标签 —— 这是最像样却完全无效的构造错误。
    s.expect(KswordArkHvmEptSwSwitchNeedsInvalidation(kBaseEptp, kBaseEptpAd) == 1,
             L"two pointers differing only in control bits share a tag and are flagged");
}

// ---------------------------------------------------------------------------
// INVEPT descriptor
// ---------------------------------------------------------------------------

void TestInveptTypeSupport(KswordTests::Suite& s) {
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE, kCapInvept) == 1,
             L"single-context INVEPT is reported when bits 20 and 25 are set");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_ALL, kCapInvept) == 1,
             L"all-context INVEPT is reported when bits 20 and 26 are set");
    // 没有 INVEPT 指令本身，谈类型没有意义。
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE,
                 kCapInvept & ~0x0000000000100000ULL) == 0,
             L"no type is supported without the INVEPT instruction bit");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE,
                 kCapInvept & ~0x0000000002000000ULL) == 0,
             L"single-context is refused when only all-context is advertised");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_ALL,
                 kCapInvept & ~0x0000000002000000ULL) == 1,
             L"all-context still works when single-context is missing");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(0U, kCapInvept) == 0,
             L"type zero is reserved");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(3U, kCapInvept) == 0,
             L"type three is reserved");

    // 同样的判据,类型号写成**字面量**。上面那几条全部用符号,于是把
    // INVEPT_SINGLE 与 INVEPT_ALL 的值对调之后它们照样全过 —— 包括那条名字叫
    // 「只广告 all-context 时拒绝 single-context」的。这里的 1 与 2 是要装进
    // 寄存器交给 INVEPT 的数,不是本文件的内部编号。
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 1U, kCapInvept & ~0x0000000002000000ULL) == 0,
             L"type one is refused when capability bit 25 (single-context) is clear");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 2U, kCapInvept & ~0x0000000002000000ULL) == 1,
             L"type two still works when capability bit 25 is clear");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 2U, kCapInvept & ~0x0000000004000000ULL) == 0,
             L"type two is refused when capability bit 26 (all-context) is clear");
    s.expect(KswordArkHvmEptSwInveptTypeSupported(
                 1U, kCapInvept & ~0x0000000004000000ULL) == 1,
             L"type one still works when capability bit 26 is clear");
}

void TestInveptDescriptor(KswordTests::Suite& s) {
    KSWORD_ARK_HVM_EPTSW_INVEPT_DESCRIPTOR descriptor;

    descriptor.Eptp = 0xDEADBEEFDEADBEEFULL;
    descriptor.Reserved = 0xDEADBEEFDEADBEEFULL;
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE, kBaseEptp,
                 kCapInvept, &descriptor) == 1,
             L"a single-context descriptor is built for a real hierarchy");
    // qword 0 是**完整的** EPT pointer，不是根地址。掩掉低位「也能用」直到
    // 某天不能用，而那时的表现是失效没生效、guest 读到过期翻译。
    s.expect(descriptor.Eptp == kBaseEptp,
             L"the descriptor carries the full EPT pointer, not just the root");
    s.expect(descriptor.Eptp != KswordArkHvmEptSwEptpRoot(kBaseEptp),
             L"the descriptor is distinguishable from a root-only encoding");
    s.expect(descriptor.Reserved == 0ULL,
             L"descriptor qword one is architecturally zero");

    descriptor.Eptp = 0xDEADBEEFDEADBEEFULL;
    descriptor.Reserved = 0xDEADBEEFDEADBEEFULL;
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_ALL, kBaseEptp,
                 kCapInvept, &descriptor) == 1,
             L"an all-context descriptor is built");
    s.expect(descriptor.Eptp == 0ULL && descriptor.Reserved == 0ULL,
             L"an all-context descriptor is fully zeroed rather than left misleading");

    // 失败必须清零：忽略返回值的调用方如果就地执行 INVEPT，栈上的残留会被
    // 当成一个真的 EPTP 去失效，而那可能是任意一套层次。
    descriptor.Eptp = 0xDEADBEEFDEADBEEFULL;
    descriptor.Reserved = 0xDEADBEEFDEADBEEFULL;
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 3U, kBaseEptp, kCapInvept, &descriptor) == 0,
             L"a reserved INVEPT type is refused");
    s.expect(descriptor.Eptp == 0ULL && descriptor.Reserved == 0ULL,
             L"a refused build leaves no executable residue in the descriptor");

    descriptor.Eptp = 0xDEADBEEFDEADBEEFULL;
    descriptor.Reserved = 0xDEADBEEFDEADBEEFULL;
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE, 0ULL,
                 kCapInvept, &descriptor) == 0,
             L"single-context with an all-zero pointer is refused");
    s.expect(descriptor.Eptp == 0ULL,
             L"the refused zero-pointer build also clears the descriptor");
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE, 0x0000001EULL,
                 kCapInvept, &descriptor) == 0,
             L"single-context with a rootless pointer is refused");
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE, kBaseEptp,
                 kCapInvept & ~0x0000000000100000ULL, &descriptor) == 0,
             L"a descriptor is refused when INVEPT is not advertised");
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE, kBaseEptp,
                 kCapInvept, nullptr) == 0,
             L"a null descriptor pointer is refused rather than dereferenced");

    // 用字面量类型号复述两条最要命的差异:类型 1 必须填 EPTP,类型 2 必须全零。
    // 两个数对调之后,请求 all-context 会发出一次 descriptor 全零的 single ——
    // 那一次失效什么都没刷掉,guest 继续用过期翻译,没有任何症状。
    descriptor.Eptp = 0xDEADBEEFDEADBEEFULL;
    descriptor.Reserved = 0xDEADBEEFDEADBEEFULL;
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 1U, kBaseEptp, kCapInvept, &descriptor) == 1 &&
                 descriptor.Eptp == kBaseEptp,
             L"INVEPT type one fills the descriptor with the full pointer");
    descriptor.Eptp = 0xDEADBEEFDEADBEEFULL;
    descriptor.Reserved = 0xDEADBEEFDEADBEEFULL;
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 2U, kBaseEptp, kCapInvept, &descriptor) == 1 &&
                 descriptor.Eptp == 0ULL && descriptor.Reserved == 0ULL,
             L"INVEPT type two leaves the descriptor fully zeroed");
    // 类型 1 对一个根为零的指针必须拒绝;类型 2 不看指针,照样成功。
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 1U, 0ULL, kCapInvept, &descriptor) == 0,
             L"INVEPT type one refuses a pointer that names no hierarchy");
    s.expect(KswordArkHvmEptSwBuildInveptDescriptor(
                 2U, 0ULL, kCapInvept, &descriptor) == 1,
             L"INVEPT type two ignores the pointer because it invalidates everything");
}

void TestPreEntryInvalidation(KswordTests::Suite& s) {
    // 每套次层次都是回收来的非分页内存，可能带着上一次驻留的过期标签，而这一次
    // 驻留期间永远不会再发 INVEPT —— 进入前这一次是它唯一的机会。
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(8U, 1) == 8U,
             L"eight leaves need eight pre-entry invalidations when the base is already live");
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(8U, 0) == 9U,
             L"a base that is not already live adds one more");
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(1U, 1) == 1U,
             L"one leaf needs one pre-entry invalidation");
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(0U, 1) == 0U,
             L"no leaves means no secondary hierarchies and nothing to invalidate");
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(0U, 0) == 0U,
             L"the feature-off path issues no invalidation at all");
    // 协议上限两侧。32 叶合法 -> 32（基座已在跑）或 33（基座也要刷）。
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(32U, 1) == 32ULL,
             L"a full leaf set at the protocol limit is counted, not refused");
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(32U, 0) == 33ULL,
             L"a full leaf set plus a cold base is thirty-three invalidations");
    // 33 叶越界：与 SecondaryPageCost / HierarchyCount / IndexFromLeaf / Decide
    // 同样拒绝，否则同一个上限就多了一个缺口。
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(33U, 1) == 0ULL,
             L"a leaf count above the protocol limit is refused here as everywhere else");
    // **0xFFFFFFFF 必须返回 0 是因为被拒绝，不是因为回绕。** 上一版的
    // LeafCount + 1 在 uint32 里回绕成 0，而 0 恰好是「没有次层次要刷」的合法
    // 答案：调用方于是带着每一套回收内存里的过期 EP4TA 标签进 guest。
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(0xFFFFFFFFU, 0) == 0ULL,
             L"a wildly out-of-range leaf count is refused instead of wrapping to zero");
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(0xFFFFFFFFU, 1) == 0ULL,
             L"the same holds when the base is already live");
    // 返回类型必须宽于 32 位，否则上面那条回绕随时可以回来。
    s.expect(sizeof(KswordArkHvmEptSwPreEntryInvalidationCount(1U, 0)) >= 8U,
             L"the count is carried in a 64-bit type so the sum cannot wrap");
    // 与 HierarchyCount 的关系是手算的恒等式，不是从实现反推：
    // 基座未就绪时要刷的套数 = 层次总数 = 1 + 叶数。
    s.expect(KswordArkHvmEptSwPreEntryInvalidationCount(8U, 0) ==
                 (unsigned long long)KswordArkHvmEptSwHierarchyCount(8U),
             L"a cold base needs exactly one invalidation per hierarchy");
}

// ---------------------------------------------------------------------------
// 索引算术
// ---------------------------------------------------------------------------

void TestIndexArithmetic(KswordTests::Suite& s) {
    // 由选定的四级索引手工合成：
    //   5   << 39 = 0x00028000000000
    //   300 << 30 = 0x000004B00000000
    //   17  << 21 = 0x00000002200000
    //   400 << 12 = 0x00000000190000
    //   偏移        0x00000000000123
    constexpr std::uint64_t kGpa = 0x000002CB02390123ULL;

    s.expect(KswordArkHvmEptSwPml4Index(kGpa) == 5U,
             L"bits 47:39 select the PML4 slot");
    s.expect(KswordArkHvmEptSwPdptIndex(kGpa) == 300U,
             L"bits 38:30 select the one-GiB window");
    s.expect(KswordArkHvmEptSwPdIndex(kGpa) == 17U,
             L"bits 29:21 select the two-MiB leaf");
    s.expect(KswordArkHvmEptSwPtIndex(kGpa) == 400U,
             L"bits 20:12 select the four-KiB page inside a split");
    s.expect(KswordArkHvmEptSwLeafBase(kGpa) == 0x000002CB02200000ULL,
             L"the two-MiB leaf base clears bits 20:0");
    s.expect(KswordArkHvmEptSwPageBase(kGpa) == 0x000002CB02390000ULL,
             L"the page base clears bits 11:0");
    // 分解与还原互为逆运算：这是「复制哪张叶表」与「改哪一格」自洽的唯一证据。
    s.expect(KswordArkHvmEptSwComposeGuestPhysical(5U, 300U, 17U, 400U) ==
                 0x000002CB02390000ULL,
             L"the four indices recompose the page base");
    s.expect(KswordArkHvmEptSwComposeGuestPhysical(
                 KswordArkHvmEptSwPml4Index(kGpa),
                 KswordArkHvmEptSwPdptIndex(kGpa),
                 KswordArkHvmEptSwPdIndex(kGpa),
                 KswordArkHvmEptSwPtIndex(kGpa)) ==
                 KswordArkHvmEptSwPageBase(kGpa),
             L"decomposition and recomposition are inverse on the four-KiB grid");

    // 全 1：不掩九位的话 PML4 索引会长成一个巨大的数并越过表尾。
    s.expect(KswordArkHvmEptSwPml4Index(0xFFFFFFFFFFFFFFFFULL) == 511U &&
                 KswordArkHvmEptSwPdptIndex(0xFFFFFFFFFFFFFFFFULL) == 511U &&
                 KswordArkHvmEptSwPdIndex(0xFFFFFFFFFFFFFFFFULL) == 511U &&
                 KswordArkHvmEptSwPtIndex(0xFFFFFFFFFFFFFFFFULL) == 511U,
             L"every index is masked to nine bits even for an all-ones address");
    // 52 位物理地址上界。
    s.expect(KswordArkHvmEptSwPml4Index(0x000FFFFFFFFFFFFFULL) == 511U &&
                 KswordArkHvmEptSwPtIndex(0x000FFFFFFFFFFFFFULL) == 511U,
             L"the highest 52-bit address decomposes to the last slots");
    // 零与第一个 2MiB 边界。
    s.expect(KswordArkHvmEptSwPml4Index(0ULL) == 0U &&
                 KswordArkHvmEptSwPdptIndex(0ULL) == 0U &&
                 KswordArkHvmEptSwPdIndex(0ULL) == 0U &&
                 KswordArkHvmEptSwPtIndex(0ULL) == 0U,
             L"address zero decomposes to slot zero at every level");
    s.expect(KswordArkHvmEptSwPdIndex(0x1FFFFFULL) == 0U &&
                 KswordArkHvmEptSwPdIndex(0x200000ULL) == 1U,
             L"the two-MiB index steps exactly at the leaf boundary");
    s.expect(KswordArkHvmEptSwPtIndex(0xFFFULL) == 0U &&
                 KswordArkHvmEptSwPtIndex(0x1000ULL) == 1U,
             L"the four-KiB index steps exactly at the page boundary");
    s.expect(KswordArkHvmEptSwLeafBase(0x1FFFFFULL) == 0ULL &&
                 KswordArkHvmEptSwLeafBase(0x200000ULL) == 0x200000ULL,
             L"the leaf base rounds down on both sides of the boundary");
}

void TestEntryAddress(KswordTests::Suite& s) {
    // 511 * 8 = 4088 = 0xFF8：表内最后一格。
    s.expect(KswordArkHvmEptSwEntryAddress(0x23456000ULL, 511U) == 0x23456FF8ULL,
             L"entry 511 is the last eight bytes of the table page");
    s.expect(KswordArkHvmEptSwEntryAddress(0x23456000ULL, 0U) == 0x23456000ULL,
             L"entry zero is the table base");
    s.expect(KswordArkHvmEptSwEntryAddress(0x23456000ULL, 1U) == 0x23456008ULL,
             L"entries are eight bytes apart");
    // 512 号格子落在下一页的第 0 格上，那一页可能是另一张表 —— 回绕不会报错。
    s.expect(KswordArkHvmEptSwEntryAddress(0x23456000ULL, 512U) == 0ULL,
             L"entry 512 is refused instead of wrapping into the next table");
    s.expect(KswordArkHvmEptSwEntryAddress(0x23456000ULL, 0xFFFFFFFFU) == 0ULL,
             L"a wildly out-of-range index is refused");
    // 调用方常常拿到的是带字段位的条目值而不是干净的地址。低位字段位。
    s.expect(KswordArkHvmEptSwEntryAddress(0x23456037ULL, 3U) == 0x23456018ULL,
             L"the table base is masked so low entry bits cannot become address bits");
    // **高位字段位同样必须被掩掉。** 本文件构造的每一个叶项都带 bit 63 的
    // suppress-#VE，而这个函数的文档说调用方可以直接把条目值传进来；上一版
    // 用 ~(PAGE_BYTES-1) 只清了 bits 11:0，于是 bit 63 原样留在「物理地址」里，
    // 驱动拿它去写表就是往一个天文数字的物理地址上写。
    // 手算：0x8000000023456007 的页帧域 = 0x0000000023456000，
    //       3 号格偏移 = 3 * 8 = 24 = 0x18，和 = 0x23456018。
    s.expect(KswordArkHvmEptSwEntryAddress(0x8000000023456007ULL, 3U) ==
                 0x0000000023456018ULL,
             L"suppress-#VE in bit 63 of an entry value never leaks into the address");
    // bits 62:52 同理：0x00A0000000000000 落在保留高位段里。
    // 手算：0x00A0000023456037 的页帧域 = 0x0000000023456000，1 号格 = +8。
    s.expect(KswordArkHvmEptSwEntryAddress(0x00A0000023456037ULL, 1U) ==
                 0x0000000023456008ULL,
             L"reserved bits 62:52 of an entry value never leak into the address either");
    // 全 1：页帧域是 bits 51:12，所以只剩 0x000FFFFFFFFFF000，511 号格 = +0xFF8。
    s.expect(KswordArkHvmEptSwEntryAddress(0xFFFFFFFFFFFFFFFFULL, 511U) ==
                 0x000FFFFFFFFFFFF8ULL,
             L"an all-ones entry value still yields an address inside the physical field");
    // 拒绝仍然优先于掩码：越界索引返回 0，而不是一个「掩干净了的」错地址。
    s.expect(KswordArkHvmEptSwEntryAddress(0x8000000023456007ULL, 512U) == 0ULL,
             L"the out-of-range refusal still wins over the masking");
}

// ---------------------------------------------------------------------------
// 层次集合的规模与页开销
// ---------------------------------------------------------------------------

void TestPageCost(KswordTests::Suite& s) {
    s.expect(KSWORD_ARK_HVM_EPTSW_PATH_PAGES == 4ULL,
             L"one secondary hierarchy is root plus PDPT plus PD plus PT");
    // 共享基座模式：8 叶 = 8 套次层次 x 4 页 = 32 页 = 128 KiB。
    s.expect(KswordArkHvmEptSwSecondaryPageCost(1U, 8U) == 32ULL,
             L"eight leaves on a shared base cost thirty-two pages");
    s.expect(KswordArkHvmEptSwSecondaryPageCost(1U, 1U) == 4ULL,
             L"one leaf on a shared base costs four pages");
    s.expect(KswordArkHvmEptSwSecondaryPageCost(1U, 32U) == 128ULL,
             L"the protocol maximum of thirty-two leaves costs 128 pages");
    // 复合私有基座：128 核 x 8 叶 x 4 页 = 4096 页（不含基座本身）。
    s.expect(KswordArkHvmEptSwSecondaryPageCost(128U, 8U) == 4096ULL,
             L"a private base per processor multiplies the secondary cost by the core count");
    // 越界与零都在分配之前拒绝。
    s.expect(KswordArkHvmEptSwSecondaryPageCost(1U, 33U) == 0ULL,
             L"more leaves than the protocol allows is refused before any allocation");
    s.expect(KswordArkHvmEptSwSecondaryPageCost(1U, 0U) == 0ULL,
             L"zero leaves costs nothing and is reported as a refusal");
    s.expect(KswordArkHvmEptSwSecondaryPageCost(0U, 8U) == 0ULL,
             L"zero bases is refused");

    // 基座套数：这是整套方案经济性的开关。
    s.expect(KswordArkHvmEptSwBaseCount(0, 1U) == 1U &&
                 KswordArkHvmEptSwBaseCount(0, 256U) == 1U,
             L"the shared base is one hierarchy no matter how many processors exist");
    s.expect(KswordArkHvmEptSwBaseCount(1, 128U) == 128U,
             L"a private base is one hierarchy per processor");
    s.expect(KswordArkHvmEptSwBaseCount(1, 0U) == 0U,
             L"a private base on zero processors is zero hierarchies");

    // 显式钉死「共享基座下总页数与处理器数无关」这条不变量:一旦有人把它改成
    // 按核计费,功能一切正常,只是 256 核机器上要 32 页变成 8192 页而没人发现。
    const std::uint32_t processorCounts[] = { 1U, 2U, 4U, 16U, 64U, 128U, 256U };
    for (const std::uint32_t processorCount : processorCounts) {
        s.expect(KswordArkHvmEptSwSecondaryPageCost(
                     KswordArkHvmEptSwBaseCount(0, processorCount), 8U) == 32ULL,
                 L"the shared-base cost is independent of the processor count");
    }

    // 层次台账长度：短一格,运行期就会按索引读出界。
    s.expect(KswordArkHvmEptSwHierarchyCount(8U) == 9U,
             L"eight leaves need nine hierarchies counting the base");
    s.expect(KswordArkHvmEptSwHierarchyCount(1U) == 2U,
             L"one leaf needs the base plus one");
    s.expect(KswordArkHvmEptSwHierarchyCount(32U) == 33U,
             L"the protocol maximum needs thirty-three hierarchies");
    s.expect(KswordArkHvmEptSwHierarchyCount(0U) == 0U,
             L"no leaves means no hierarchy set is built at all");
    s.expect(KswordArkHvmEptSwHierarchyCount(33U) == 0U,
             L"more leaves than the protocol allows builds nothing");

    // 预算边界两侧。
    s.expect(KswordArkHvmEptSwFitsBudget(32ULL, 2048ULL) == 1,
             L"the shared-base cost fits the ledger with room to spare");
    s.expect(KswordArkHvmEptSwFitsBudget(2048ULL, 2048ULL) == 1,
             L"a cost exactly equal to the cap fits");
    s.expect(KswordArkHvmEptSwFitsBudget(2049ULL, 2048ULL) == 0,
             L"one page over the cap does not fit");
    s.expect(KswordArkHvmEptSwFitsBudget(0ULL, 2048ULL) == 0,
             L"a zero cost is a refusal, not a free fit");
    // 复合模式在 2048 页预算下大约 47 核开始拒绝 —— 那正是应该拒绝的地方。
    s.expect(KswordArkHvmEptSwFitsBudget(
                 KswordArkHvmEptSwSecondaryPageCost(64U, 8U), 2048ULL) == 1,
             L"64 processors with a private base still fits at 2048 pages");
    s.expect(KswordArkHvmEptSwFitsBudget(
                 KswordArkHvmEptSwSecondaryPageCost(65U, 8U), 2048ULL) == 0,
             L"65 processors with a private base is refused at 2048 pages");
}

// ---------------------------------------------------------------------------
// 层次索引与叶号的编码
// ---------------------------------------------------------------------------

void TestIndexEncoding(KswordTests::Suite& s) {
    // 输出参数的类型跟头文件走(unsigned long),不是 std::uint32_t:
    // 本族三个 HVM 共享头统一用基本类型,不引用 <stdint.h>。
    unsigned long index = 0xFFFFFFFFUL;
    unsigned long leaf = 0xFFFFFFFFUL;

    s.expect(KswordArkHvmEptSwIndexIsBase(0U) == 1,
             L"index zero is the base hierarchy");
    s.expect(KswordArkHvmEptSwIndexIsBase(1U) == 0,
             L"index one is already a secondary hierarchy");

    // 必须整体加一：令索引等于叶号会让「第 0 叶正取次值」与「什么都没放宽」
    // 变成同一个值,于是第 0 叶切进去就再也切不回来 —— 而没有任何报错。
    s.expect(KswordArkHvmEptSwIndexFromLeaf(0U, 8U, &index) == 1 && index == 1U,
             L"leaf zero maps to index one, never to the base index");
    s.expect(KswordArkHvmEptSwIndexFromLeaf(7U, 8U, &index) == 1 && index == 8U,
             L"the last leaf maps to the last index");
    s.expect(KswordArkHvmEptSwIndexFromLeaf(8U, 8U, &index) == 0,
             L"a leaf index equal to the count is refused");
    s.expect(KswordArkHvmEptSwIndexFromLeaf(0U, 0U, &index) == 0,
             L"a zero leaf count has no encodable index");
    s.expect(KswordArkHvmEptSwIndexFromLeaf(0U, 33U, &index) == 0,
             L"a leaf count above the protocol maximum is refused");
    s.expect(KswordArkHvmEptSwIndexFromLeaf(0U, 8U, nullptr) == 0,
             L"a null output pointer is refused rather than dereferenced");

    // 反解差一格会把恢复判据作用在一个无关的页上。
    s.expect(KswordArkHvmEptSwLeafFromIndex(1U, 8U, &leaf) == 1 && leaf == 0U,
             L"index one decodes back to leaf zero");
    s.expect(KswordArkHvmEptSwLeafFromIndex(8U, 8U, &leaf) == 1 && leaf == 7U,
             L"the last index decodes back to the last leaf");
    s.expect(KswordArkHvmEptSwLeafFromIndex(0U, 8U, &leaf) == 0,
             L"the base index has no leaf and is refused rather than given a sentinel");
    s.expect(KswordArkHvmEptSwLeafFromIndex(9U, 8U, &leaf) == 0,
             L"an index past the hierarchy set is refused");
    s.expect(KswordArkHvmEptSwLeafFromIndex(1U, 0U, &leaf) == 0,
             L"a zero leaf count has no decodable index");
    s.expect(KswordArkHvmEptSwLeafFromIndex(1U, 8U, nullptr) == 0,
             L"a null output pointer is refused on the decode side too");

    // 全量往返。
    bool roundTripHolds = true;
    for (std::uint32_t candidate = 0U; candidate < 32U; ++candidate) {
        unsigned long encoded = 0UL;
        unsigned long decoded = 0xFFFFFFFFUL;
        if (KswordArkHvmEptSwIndexFromLeaf(candidate, 32U, &encoded) != 1 ||
            encoded != candidate + 1U ||
            KswordArkHvmEptSwIndexIsBase(encoded) != 0 ||
            KswordArkHvmEptSwLeafFromIndex(encoded, 32U, &decoded) != 1 ||
            decoded != candidate) {
            roundTripHolds = false;
        }
    }
    s.expect(roundTripHolds,
             L"every leaf round-trips through a non-base index for the full protocol range");
}

// ---------------------------------------------------------------------------
// 访问位、权限对、授予判据
// ---------------------------------------------------------------------------

void TestAccessMapping(KswordTests::Suite& s) {
    // 两组常量目前数值相同,而这正是危险所在:直接赋值不会报错,直到有一侧
    // 被重新编号。
    s.expect(KswordArkHvmEptSwAccessToLeafBits(
                 KSWORD_ARK_HVM_EPTSW_ACCESS_READ) == KSWORD_ARK_HVM_EPTSW_READ,
             L"protocol read maps to the leaf read bit");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(
                 KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE) == KSWORD_ARK_HVM_EPTSW_WRITE,
             L"protocol write maps to the leaf write bit");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(
                 KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE) == KSWORD_ARK_HVM_EPTSW_EXECUTE,
             L"protocol execute maps to the leaf execute bit");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x3U) == 0x3ULL,
             L"read plus write maps to both leaf bits");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x7U) == 0x7ULL,
             L"all three access classes map to all three leaf bits");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0U) == 0ULL,
             L"an empty access mask needs no leaf bits");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x8U) == 0ULL,
             L"an undefined access bit contributes no leaf permission");

    // 上面几条全部写成 f(SYMBOL) == SYMBOL,两边一起被重新编号时等式恒成立 ——
    // 把 ACCESS_READ 与 ACCESS_WRITE 对调之后它们一条都不响。下面把两侧都写成
    // 字面量:协议 bit 0 必须映射到叶 bit 0,协议 bit 1 必须映射到叶 bit 1。
    // 对调的后果不是「读写混了」那么无害:CLOAK 的次值是 rw-,HOOK 的主值也是
    // rw-,R 与 W 在状态机里恰好对称,所以任何行为断言都看不见这个错误,
    // 只有数值断言看得见。
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x1U) == 0x1ULL,
             L"protocol bit 0 maps to leaf bit 0 by value, not merely by symbol");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x2U) == 0x2ULL,
             L"protocol bit 1 maps to leaf bit 1 by value");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x4U) == 0x4ULL,
             L"protocol bit 2 maps to leaf bit 2 by value");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x5U) == 0x5ULL,
             L"a read-execute request maps to leaf bits 0 and 2 by value");
    s.expect(KswordArkHvmEptSwAccessToLeafBits(0x6U) == 0x6ULL,
             L"a write-execute request maps to leaf bits 1 and 2 by value");
    // 授予判据同样用字面量:一个只可读的叶授予读、不授予写。
    s.expect(KswordArkHvmEptSwGrants(0x1ULL, 0x1U) == 1 &&
                 KswordArkHvmEptSwGrants(0x1ULL, 0x2U) == 0,
             L"a read-only leaf grants access bit 0 and refuses access bit 1");
    s.expect(KswordArkHvmEptSwGrants(0x2ULL, 0x2U) == 1 &&
                 KswordArkHvmEptSwGrants(0x2ULL, 0x1U) == 0,
             L"a write-only leaf grants access bit 1 and refuses access bit 0");

    // 空需求永远不算被满足 —— 否则那次违规会被当成「当前层次够用」而放行,
    // 一次 VMRESUME 之后再次违规,一个不报错的死循环。
    s.expect(KswordArkHvmEptSwGrants(0x7ULL, 0U) == 0,
             L"a fully permissive leaf still does not grant an empty access");
    s.expect(KswordArkHvmEptSwGrants(0x3ULL, 0x1U) == 1,
             L"read-write grants a read");
    s.expect(KswordArkHvmEptSwGrants(0x3ULL, 0x2U) == 1,
             L"read-write grants a write");
    s.expect(KswordArkHvmEptSwGrants(0x3ULL, 0x4U) == 0,
             L"read-write does not grant an execute");
    s.expect(KswordArkHvmEptSwGrants(0x3ULL, 0x3U) == 1,
             L"read-write grants a combined read and write");
    // 必须**全部**位都被授予:部分满足仍然会再次违规。
    s.expect(KswordArkHvmEptSwGrants(0x3ULL, 0x7U) == 0,
             L"a partially satisfying leaf does not grant a combined access");
    s.expect(KswordArkHvmEptSwGrants(0x4ULL, 0x4U) == 1,
             L"execute-only grants an execute");
    s.expect(KswordArkHvmEptSwGrants(0x4ULL, 0x1U) == 0,
             L"execute-only does not grant a read");
    s.expect(KswordArkHvmEptSwGrants(0x4ULL, 0x5U) == 0,
             L"execute-only does not grant a combined read and execute");
    s.expect(KswordArkHvmEptSwGrants(0ULL, 0x1U) == 0,
             L"a leaf granting nothing grants nothing");
}

void TestKindPermissions(KswordTests::Suite& s) {
    std::uint64_t primary = 0ULL;
    std::uint64_t secondary = 0ULL;

    s.expect(KswordArkHvmEptSwKindPermissions(
                 KSWORD_ARK_HVM_EPTSW_KIND_CLOAK, 1, &primary, &secondary) == 1 &&
                 primary == KSWORD_ARK_HVM_EPTSW_EXECUTE &&
                 secondary == (KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE),
             L"CLOAK executes the real page and redirects reads and writes");
    s.expect(KswordArkHvmEptSwKindPermissions(
                 KSWORD_ARK_HVM_EPTSW_KIND_HOOK, 1, &primary, &secondary) == 1 &&
                 primary == (KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE) &&
                 secondary == KSWORD_ARK_HVM_EPTSW_EXECUTE,
             L"HOOK reads the real page and redirects execution");
    // 与今天的 MTF 路径不同:那里缺 execute-only 时 HOOK 的次值退化成 r-x,
    // 论证是「窗口只有一条指令」。EPTP 切换没有 MTF,次层次一直生效到反向访问
    // 为止,r-x 等于把补丁字节公开 —— 而 hook 照常工作,没有任何症状。
    s.expect(KswordArkHvmEptSwKindPermissions(
                 KSWORD_ARK_HVM_EPTSW_KIND_HOOK, 0, &primary, &secondary) == 0,
             L"HOOK is refused without execute-only because r-x would publish the patch");
    s.expect(KswordArkHvmEptSwKindPermissions(
                 KSWORD_ARK_HVM_EPTSW_KIND_CLOAK, 0, &primary, &secondary) == 0,
             L"CLOAK is refused without execute-only because nothing would be hidden");
    s.expect(KswordArkHvmEptSwKindPermissions(0U, 1, &primary, &secondary) == 0,
             L"view kind zero is unknown");
    s.expect(KswordArkHvmEptSwKindPermissions(3U, 1, &primary, &secondary) == 0,
             L"view kind three is unknown");

    // 上面两条用的是 KIND_CLOAK / KIND_HOOK 符号,所以把两个值对调之后照样全过。
    // 这里把 kind 号与权限值**两侧都写成字面量**:协议里的 1 是 CLOAK,而 CLOAK
    // 的主值必须是 --x(0x4)。对调之后 kind = 1 会被服务成 rw- 的真帧,
    // 那一页对所有读者永远可读 —— 隐藏变成暴露,而 hook 与视图列表毫无异常。
    primary = 0ULL;
    secondary = 0ULL;
    s.expect(KswordArkHvmEptSwKindPermissions(1U, 1, &primary, &secondary) == 1 &&
                 primary == 0x4ULL && secondary == 0x3ULL,
             L"protocol kind one is CLOAK: primary --x on the real frame, secondary rw-");
    primary = 0ULL;
    secondary = 0ULL;
    s.expect(KswordArkHvmEptSwKindPermissions(2U, 1, &primary, &secondary) == 1 &&
                 primary == 0x3ULL && secondary == 0x4ULL,
             L"protocol kind two is HOOK: primary rw- on the real frame, secondary --x");
    s.expect(KswordArkHvmEptSwKindPermissions(
                 KSWORD_ARK_HVM_EPTSW_KIND_CLOAK, 1, nullptr, &secondary) == 0 &&
                 KswordArkHvmEptSwKindPermissions(
                     KSWORD_ARK_HVM_EPTSW_KIND_CLOAK, 1, &primary, nullptr) == 0,
             L"a null output pointer is refused rather than dereferenced");

    // 并集必须覆盖三种访问,否则某种访问永远找不到可切的目标 —— 而那只会在
    // 目标机器上跑了几小时之后才暴露成一次退虚拟化。
    s.expect(KswordArkHvmEptSwPairIsTotal(
                 KSWORD_ARK_HVM_EPTSW_EXECUTE,
                 KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE) == 1,
             L"the CLOAK pair covers read, write and execute");
    s.expect(KswordArkHvmEptSwPairIsTotal(
                 KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE,
                 KSWORD_ARK_HVM_EPTSW_EXECUTE) == 1,
             L"the HOOK pair covers read, write and execute");
    s.expect(KswordArkHvmEptSwPairIsTotal(0x3ULL, 0x3ULL) == 0,
             L"a pair that never grants execute is not total");
    s.expect(KswordArkHvmEptSwPairIsTotal(0x4ULL, 0x4ULL) == 0,
             L"a pair that never grants read or write is not total");
    s.expect(KswordArkHvmEptSwPairIsTotal(0x1ULL, 0x6ULL) == 1,
             L"totality only asks for the union, not for either side alone");
}

// ---------------------------------------------------------------------------
// 状态机穷举
// ---------------------------------------------------------------------------

// 穷举里三种「当前层次」。对本叶而言 base 与 other 是同一种状态(本叶取主值),
// 但目标不同 —— 从 other 切到本叶会顺带把那一叶收回主值,这正是「任何时刻至多
// 一叶被放宽」的来源,所以两者必须分开断言。
enum class ActiveKind { Base, ThisLeaf, OtherLeaf };

struct ExhaustiveCase {
    ActiveKind active;
    std::uint32_t viewKind;
    std::uint32_t access;
    std::uint32_t expectedOutcome;
    std::uint32_t expectedNextIndex;   // 仅在 SWITCH 时有意义
    std::uint32_t expectedReason;      // 仅在 REFUSE 时有意义
    const wchar_t* label;
};

constexpr std::uint32_t kLeafCount = 4U;
constexpr std::uint32_t kFaultLeaf = 1U;
constexpr std::uint32_t kFaultIndex = 2U;   // kFaultLeaf + 1
constexpr std::uint32_t kOtherIndex = 3U;   // 另一叶的层次,合法且不等于 kFaultIndex

constexpr std::uint32_t kR = 0x1U;
constexpr std::uint32_t kW = 0x2U;
constexpr std::uint32_t kX = 0x4U;
constexpr std::uint32_t kSwitch = KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
constexpr std::uint32_t kRefuse = KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
constexpr std::uint32_t kSpurious = KSWORD_ARK_HVM_EPTSW_REASON_SPURIOUS;
constexpr std::uint32_t kUnrep = KSWORD_ARK_HVM_EPTSW_REASON_UNREPRESENTABLE;
constexpr std::uint32_t kNone = KSWORD_ARK_HVM_EPTSW_REASON_NONE;
constexpr std::uint32_t kCloak = KSWORD_ARK_HVM_EPTSW_KIND_CLOAK;
constexpr std::uint32_t kHook = KSWORD_ARK_HVM_EPTSW_KIND_HOOK;

// 期望值全部独立手算:
//   CLOAK 主值 = --x (0x4)，次值 = rw- (0x3)
//   HOOK  主值 = rw- (0x3)，次值 = --x (0x4)
// 本叶取主值时(base / other):主值授予 -> SPURIOUS;次值不授予 -> UNREPRESENTABLE;
// 否则切到本叶索引。本叶取次值时:次值授予 -> SPURIOUS;主值不授予 -> UNREPRESENTABLE;
// 否则回基座。
const ExhaustiveCase kExhaustive[] = {
    // --- 基座,CLOAK ---
    { ActiveKind::Base, kCloak, kR,           kSwitch, kFaultIndex, kNone,
      L"base + CLOAK + read switches to the leaf hierarchy" },
    { ActiveKind::Base, kCloak, kW,           kSwitch, kFaultIndex, kNone,
      L"base + CLOAK + write switches to the leaf hierarchy" },
    { ActiveKind::Base, kCloak, kX,           kRefuse, 0U,          kSpurious,
      L"base + CLOAK + execute cannot fault because the primary grants X" },
    { ActiveKind::Base, kCloak, kR | kW,      kSwitch, kFaultIndex, kNone,
      L"base + CLOAK + read-write switches once for both" },
    { ActiveKind::Base, kCloak, kR | kX,      kRefuse, 0U,          kUnrep,
      L"base + CLOAK + read-execute is unrepresentable in any single hierarchy" },
    { ActiveKind::Base, kCloak, kW | kX,      kRefuse, 0U,          kUnrep,
      L"base + CLOAK + write-execute is unrepresentable" },
    { ActiveKind::Base, kCloak, kR | kW | kX, kRefuse, 0U,          kUnrep,
      L"base + CLOAK + read-write-execute is unrepresentable" },
    // --- 基座,HOOK ---
    { ActiveKind::Base, kHook,  kR,           kRefuse, 0U,          kSpurious,
      L"base + HOOK + read cannot fault because the primary grants R" },
    { ActiveKind::Base, kHook,  kW,           kRefuse, 0U,          kSpurious,
      L"base + HOOK + write cannot fault because the primary grants W" },
    { ActiveKind::Base, kHook,  kX,           kSwitch, kFaultIndex, kNone,
      L"base + HOOK + execute switches to the leaf hierarchy" },
    { ActiveKind::Base, kHook,  kR | kW,      kRefuse, 0U,          kSpurious,
      L"base + HOOK + read-write cannot fault" },
    { ActiveKind::Base, kHook,  kR | kX,      kRefuse, 0U,          kUnrep,
      L"base + HOOK + read-execute is unrepresentable" },
    { ActiveKind::Base, kHook,  kW | kX,      kRefuse, 0U,          kUnrep,
      L"base + HOOK + write-execute is unrepresentable" },
    { ActiveKind::Base, kHook,  kR | kW | kX, kRefuse, 0U,          kUnrep,
      L"base + HOOK + read-write-execute is unrepresentable" },
    // --- 本叶层次,CLOAK ---
    { ActiveKind::ThisLeaf, kCloak, kR,           kRefuse, 0U, kSpurious,
      L"leaf hierarchy + CLOAK + read no longer faults, so a fault here is spurious" },
    { ActiveKind::ThisLeaf, kCloak, kW,           kRefuse, 0U, kSpurious,
      L"leaf hierarchy + CLOAK + write is spurious" },
    { ActiveKind::ThisLeaf, kCloak, kX,           kSwitch, 0U, kNone,
      L"leaf hierarchy + CLOAK + execute returns to the base" },
    { ActiveKind::ThisLeaf, kCloak, kR | kW,      kRefuse, 0U, kSpurious,
      L"leaf hierarchy + CLOAK + read-write is spurious" },
    { ActiveKind::ThisLeaf, kCloak, kR | kX,      kRefuse, 0U, kUnrep,
      L"leaf hierarchy + CLOAK + read-execute is unrepresentable" },
    { ActiveKind::ThisLeaf, kCloak, kW | kX,      kRefuse, 0U, kUnrep,
      L"leaf hierarchy + CLOAK + write-execute is unrepresentable" },
    { ActiveKind::ThisLeaf, kCloak, kR | kW | kX, kRefuse, 0U, kUnrep,
      L"leaf hierarchy + CLOAK + read-write-execute is unrepresentable" },
    // --- 本叶层次,HOOK ---
    { ActiveKind::ThisLeaf, kHook,  kR,           kSwitch, 0U, kNone,
      L"leaf hierarchy + HOOK + read returns to the base so the reader sees the real page" },
    { ActiveKind::ThisLeaf, kHook,  kW,           kSwitch, 0U, kNone,
      L"leaf hierarchy + HOOK + write returns to the base so the write lands on the real page" },
    { ActiveKind::ThisLeaf, kHook,  kX,           kRefuse, 0U, kSpurious,
      L"leaf hierarchy + HOOK + execute no longer faults, so a fault here is spurious" },
    { ActiveKind::ThisLeaf, kHook,  kR | kW,      kSwitch, 0U, kNone,
      L"leaf hierarchy + HOOK + read-write returns to the base" },
    { ActiveKind::ThisLeaf, kHook,  kR | kX,      kRefuse, 0U, kUnrep,
      L"leaf hierarchy + HOOK + read-execute is unrepresentable" },
    { ActiveKind::ThisLeaf, kHook,  kW | kX,      kRefuse, 0U, kUnrep,
      L"leaf hierarchy + HOOK + write-execute is unrepresentable" },
    { ActiveKind::ThisLeaf, kHook,  kR | kW | kX, kRefuse, 0U, kUnrep,
      L"leaf hierarchy + HOOK + read-write-execute is unrepresentable" },
    // --- 别的叶的层次,CLOAK ---
    { ActiveKind::OtherLeaf, kCloak, kR,           kSwitch, kFaultIndex, kNone,
      L"another leaf's hierarchy + CLOAK + read switches over and retightens that leaf" },
    { ActiveKind::OtherLeaf, kCloak, kW,           kSwitch, kFaultIndex, kNone,
      L"another leaf's hierarchy + CLOAK + write switches over" },
    { ActiveKind::OtherLeaf, kCloak, kX,           kRefuse, 0U,          kSpurious,
      L"another leaf's hierarchy + CLOAK + execute cannot fault on this leaf" },
    { ActiveKind::OtherLeaf, kCloak, kR | kW,      kSwitch, kFaultIndex, kNone,
      L"another leaf's hierarchy + CLOAK + read-write switches over" },
    { ActiveKind::OtherLeaf, kCloak, kR | kX,      kRefuse, 0U,          kUnrep,
      L"another leaf's hierarchy + CLOAK + read-execute is unrepresentable" },
    { ActiveKind::OtherLeaf, kCloak, kW | kX,      kRefuse, 0U,          kUnrep,
      L"another leaf's hierarchy + CLOAK + write-execute is unrepresentable" },
    { ActiveKind::OtherLeaf, kCloak, kR | kW | kX, kRefuse, 0U,          kUnrep,
      L"another leaf's hierarchy + CLOAK + read-write-execute is unrepresentable" },
    // --- 别的叶的层次,HOOK ---
    { ActiveKind::OtherLeaf, kHook,  kR,           kRefuse, 0U,          kSpurious,
      L"another leaf's hierarchy + HOOK + read cannot fault on this leaf" },
    { ActiveKind::OtherLeaf, kHook,  kW,           kRefuse, 0U,          kSpurious,
      L"another leaf's hierarchy + HOOK + write cannot fault on this leaf" },
    { ActiveKind::OtherLeaf, kHook,  kX,           kSwitch, kFaultIndex, kNone,
      L"another leaf's hierarchy + HOOK + execute switches over and retightens that leaf" },
    { ActiveKind::OtherLeaf, kHook,  kR | kW,      kRefuse, 0U,          kSpurious,
      L"another leaf's hierarchy + HOOK + read-write cannot fault on this leaf" },
    { ActiveKind::OtherLeaf, kHook,  kR | kX,      kRefuse, 0U,          kUnrep,
      L"another leaf's hierarchy + HOOK + read-execute is unrepresentable" },
    { ActiveKind::OtherLeaf, kHook,  kW | kX,      kRefuse, 0U,          kUnrep,
      L"another leaf's hierarchy + HOOK + write-execute is unrepresentable" },
    { ActiveKind::OtherLeaf, kHook,  kR | kW | kX, kRefuse, 0U,          kUnrep,
      L"another leaf's hierarchy + HOOK + read-write-execute is unrepresentable" },
};

std::uint32_t ActiveIndexOf(ActiveKind kind) {
    switch (kind) {
    case ActiveKind::Base:
        return 0U;
    case ActiveKind::ThisLeaf:
        return kFaultIndex;
    default:
        return kOtherIndex;
    }
}

void TestDecideExhaustive(KswordTests::Suite& s) {
    // 3 种当前层次 x 2 种视图 x 7 种非空访问 = 42 组,一组不缺。
    s.expect(sizeof(kExhaustive) / sizeof(kExhaustive[0]) == 42U,
             L"the exhaustive table covers all three-by-two-by-seven combinations");

    for (const ExhaustiveCase& item : kExhaustive) {
        KSWORD_ARK_HVM_EPTSW_TRANSITION transition;
        const std::uint32_t outcome = KswordArkHvmEptSwDecide(
            ActiveIndexOf(item.active),
            kFaultLeaf,
            kLeafCount,
            item.access,
            item.viewKind,
            1,
            &transition);
        const bool outcomeMatches =
            outcome == item.expectedOutcome &&
            transition.Outcome == item.expectedOutcome;
        const bool detailMatches =
            item.expectedOutcome == kSwitch
                ? (transition.NextIndex == item.expectedNextIndex &&
                   transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_NONE)
                : (transition.Reason == item.expectedReason &&
                   transition.NextIndex == 0U &&
                   transition.TargetEptp == 0ULL);
        s.expect(outcomeMatches, item.label);
        s.expect(detailMatches, item.label);
    }
}

void TestDecideRejections(KswordTests::Suite& s) {
    KSWORD_ARK_HVM_EPTSW_TRANSITION transition;

    // 越界:叶数为零 / 超上限 / 叶号越界 / 当前索引越界。
    s.expect(KswordArkHvmEptSwDecide(0U, 0U, 0U, kR, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS,
             L"a zero leaf count is refused as out of bounds");
    s.expect(KswordArkHvmEptSwDecide(0U, 0U, 33U, kR, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS,
             L"a leaf count above the protocol maximum is refused");
    s.expect(KswordArkHvmEptSwDecide(0U, 4U, 4U, kR, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS,
             L"a fault leaf equal to the leaf count is refused");
    // 当前索引的上界正好是叶数:索引 4 在 4 叶时合法(第 3 叶的层次),5 不合法。
    s.expect(KswordArkHvmEptSwDecide(4U, 1U, 4U, kR, kCloak, 1, &transition) == kSwitch,
             L"an active index equal to the leaf count is the last legal hierarchy");
    s.expect(KswordArkHvmEptSwDecide(5U, 1U, 4U, kR, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS,
             L"an active index past the hierarchy set means the ledger already disagrees");

    // 空访问与未知访问位。
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, 0U, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_EMPTY_ACCESS,
             L"an empty access mask is refused instead of resuming into a loop");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, 0x8U, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_UNKNOWN_ACCESS,
             L"an access bit the protocol does not define is refused, not treated as a read");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, 0x9U, kCloak, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_UNKNOWN_ACCESS,
             L"an undefined bit alongside a defined one is still refused");

    // 能力与种类。缺 execute-only 的判断排在种类之前,所以两者同时为假时
    // 报告的是能力缺失 —— 那才是调用方要拿去做降级决定的信息。
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, kCloak, 0, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_NO_EXECUTE_ONLY,
             L"without execute-only the mechanism refuses before looking at the kind");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, 3U, 0, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_NO_EXECUTE_ONLY,
             L"the capability failure is reported ahead of an unknown kind");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, 3U, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_KIND,
             L"an unknown view kind is refused");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, 0U, 1, &transition) == kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_KIND,
             L"view kind zero is refused");

    // 空指针。
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, kCloak, 1, nullptr) == kRefuse,
             L"a null transition pointer is refused rather than dereferenced");

    // 拒绝时结果结构必须整体清空:调用方即使忽略返回值,也不能读到一个看着
    // 像成功的目标。
    transition.TargetEptp = 0xDEADBEEFULL;
    transition.NextIndex = 7U;
    transition.Reason = 0xEEU;
    (void)KswordArkHvmEptSwDecide(0U, 1U, 4U, 0U, kCloak, 1, &transition);
    s.expect(transition.TargetEptp == 0ULL && transition.NextIndex == 0U &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_EMPTY_ACCESS,
             L"a refusal clears the target and the next index and states its reason");

    // 单叶集合:唯一的叶只有索引 1,基座与它之间来回。
    s.expect(KswordArkHvmEptSwDecide(0U, 0U, 1U, kR, kCloak, 1, &transition) == kSwitch &&
                 transition.NextIndex == 1U,
             L"the only leaf of a single-leaf set is index one, not index zero");
    s.expect(KswordArkHvmEptSwDecide(1U, 0U, 1U, kX, kCloak, 1, &transition) == kSwitch &&
                 transition.NextIndex == 0U,
             L"a single-leaf set returns to the base on the reverse access");

    // 协议上限处的叶集合。
    s.expect(KswordArkHvmEptSwDecide(0U, 31U, 32U, kX, kHook, 1, &transition) == kSwitch &&
                 transition.NextIndex == 32U,
             L"the last leaf of a full set maps to the last hierarchy index");

    // 种类号写成字面量的两条不对称结局。穷举表里每一格都用 kCloak / kHook 符号,
    // 所以两个种类对调之后整张表照样全过 —— 因为对调之后它只是「另一张同样
    // 自洽的表」。这两条钉的是协议数字与语义的绑定:
    //   kind = 1 (CLOAK) 在基座上遇到取指**不该**切,因为 --x 已经授予;
    //   kind = 2 (HOOK)  在基座上遇到取指**必须**切,因为 rw- 不授予 X。
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kX, 1U, 1, &transition) == kRefuse &&
                 transition.Reason == kSpurious,
             L"protocol kind one on a base execute fault is spurious, because CLOAK grants X");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kX, 2U, 1, &transition) == kSwitch &&
                 transition.NextIndex == 2U,
             L"protocol kind two on a base execute fault switches, because HOOK denies X");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, 1U, 1, &transition) == kSwitch &&
                 transition.NextIndex == 2U,
             L"protocol kind one on a base read fault switches, because CLOAK denies R");
    s.expect(KswordArkHvmEptSwDecide(0U, 1U, 4U, kR, 2U, 1, &transition) == kRefuse &&
                 transition.Reason == kSpurious,
             L"protocol kind two on a base read fault is spurious, because HOOK grants R");
}

// ---------------------------------------------------------------------------
// 台账查表
// ---------------------------------------------------------------------------

void TestPlanSwitch(KswordTests::Suite& s) {
    // 台账:索引 0 是基座,索引 k 由基座派生,根 = 0x02000000 + k * 0x1000。
    std::uint64_t table[5];
    table[0] = kBaseEptp;
    for (std::uint32_t index = 1U; index < 5U; ++index) {
        table[index] = KswordArkHvmEptSwRebaseEptp(
            kBaseEptp, 0x02000000ULL + (std::uint64_t)index * 0x1000ULL);
    }
    // 手算:根 0x02002000 | 0x1E。
    s.expect(table[2] == 0x0200201EULL,
             L"the ledger entry for leaf one is the base pointer rebased onto its own root");

    KSWORD_ARK_HVM_EPTSW_TRANSITION transition;
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 5U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, &transition) ==
                 kSwitch &&
                 transition.NextIndex == kFaultIndex &&
                 transition.TargetEptp == 0x0200201EULL,
             L"a planned switch hands back the exact EPT pointer to write into the VMCS");
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 5U, kFaultIndex, kFaultLeaf, kLeafCount, kX, kCloak, 1,
                 &transition) == kSwitch &&
                 transition.NextIndex == 0U &&
                 transition.TargetEptp == kBaseEptp,
             L"the reverse plan hands back the base pointer");

    // 台账长度必须正好是 1 + 叶数:短一格就会按索引读出界,而读到的可能是一个
    // 看着合法的旧指针。
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 4U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, &transition) ==
                 kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_LEDGER,
             L"a ledger shorter than one plus the leaf count is refused");
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 6U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, &transition) ==
                 kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_LEDGER,
             L"a ledger longer than one plus the leaf count is refused too");
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 nullptr, 5U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, &transition) ==
                 kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_LEDGER,
             L"a null ledger is refused");

    // 槽位没填。
    {
        std::uint64_t holed[5];
        for (std::uint32_t index = 0U; index < 5U; ++index) {
            holed[index] = table[index];
        }
        holed[kFaultIndex] = 0ULL;
        s.expect(KswordArkHvmEptSwPlanSwitch(
                     holed, 5U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, &transition) ==
                     kRefuse &&
                     transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_LEDGER,
                 L"an unfilled target slot is refused rather than walked from physical zero");
        holed[kFaultIndex] = table[kFaultIndex];
        holed[0] = 0ULL;
        s.expect(KswordArkHvmEptSwPlanSwitch(
                     holed, 5U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, &transition) ==
                     kRefuse &&
                     transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_LEDGER,
                 L"an unfilled source slot is refused as well");
    }

    // 共享 EP4TA:切换在硬件上是空操作,同一条指令会永远重新违规 —— 这是本方案
    // 里唯一会变成整机静默死锁的构造错误。
    {
        std::uint64_t aliased[5];
        for (std::uint32_t index = 0U; index < 5U; ++index) {
            aliased[index] = table[index];
        }
        aliased[kFaultIndex] = kBaseEptpAd;   // 与基座同根,只有 A/D 不同
        s.expect(KswordArkHvmEptSwPlanSwitch(
                     aliased, 5U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1,
                     &transition) == kRefuse &&
                     transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_ALIASED,
                 L"a target sharing the source's EP4TA is refused instead of looping forever");
    }

    // 决策层的拒绝必须原样透传,而不是被台账检查覆盖成 LEDGER。
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 5U, 0U, kFaultLeaf, kLeafCount, kX, kCloak, 1, &transition) ==
                 kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_SPURIOUS &&
                 transition.TargetEptp == 0ULL,
             L"a decision-level refusal keeps its own reason and hands back no pointer");
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 5U, 0U, kFaultLeaf, kLeafCount, kR | kX, kCloak, 1, &transition) ==
                 kRefuse &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_UNREPRESENTABLE,
             L"an unrepresentable access keeps its reason through the ledger stage");
    s.expect(KswordArkHvmEptSwPlanSwitch(
                 table, 5U, 0U, kFaultLeaf, kLeafCount, kR, kCloak, 1, nullptr) == kRefuse,
             L"a null transition pointer is refused by the planner too");

    // 每一套次层次都必须与基座同样被 VM entry 接受,并且互不共享标签。
    bool ledgerHealthy = true;
    for (std::uint32_t index = 0U; index < 5U; ++index) {
        if (KswordArkHvmEptSwEptpIsWellFormed(table[index], kCapWb, kPhysBits39) !=
            KSWORD_ARK_HVM_EPTSW_EPTP_OK) {
            ledgerHealthy = false;
        }
        for (std::uint32_t other = 0U; other < 5U; ++other) {
            if (other != index &&
                KswordArkHvmEptSwSwitchNeedsInvalidation(table[index], table[other]) != 0) {
                ledgerHealthy = false;
            }
        }
    }
    s.expect(ledgerHealthy,
             L"every derived hierarchy is VM-entry legal and carries its own cache tag");
}

// ---------------------------------------------------------------------------
// 拒绝构造器本身
// ---------------------------------------------------------------------------

void TestRefuseHelper(KswordTests::Suite& s) {
    KSWORD_ARK_HVM_EPTSW_TRANSITION transition;

    transition.TargetEptp = 0xDEADBEEFULL;
    transition.Outcome = KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
    transition.NextIndex = 7U;
    transition.Reason = 0xEEU;
    s.expect(KswordArkHvmEptSwRefuse(
                 &transition, KSWORD_ARK_HVM_EPTSW_REASON_ALIASED) ==
                 KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE,
             L"the refusal helper reports a refusal");
    s.expect(transition.TargetEptp == 0ULL &&
                 transition.Outcome == KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE &&
                 transition.NextIndex == 0U &&
                 transition.Reason == KSWORD_ARK_HVM_EPTSW_REASON_ALIASED,
             L"the refusal helper clears the target and index and keeps the reason");
    // 这是一个公开的 static __inline,驱动侧会直接调它来构造一次拒绝,而它跑在
    // DISPATCH_LEVEL 的 VM-exit 路径上 —— 那里一次空解引用就是一次蓝屏,
    // 现场还离「谁没填 Transition」很远。文件里其它每个取指针的函数都检查了,
    // 上一版唯独这个没有。
    s.expect(KswordArkHvmEptSwRefuse(
                 nullptr, KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS) ==
                 KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE,
             L"a null transition is refused rather than dereferenced by the helper");
}

// ---------------------------------------------------------------------------
// 前进性台账(从已删除的 KswordArkHvmEptpSwitch.h 合并过来的那一节)
// ---------------------------------------------------------------------------

void TestProgressLedger(KswordTests::Suite& s) {
    KSWORD_ARK_HVM_EPTSW_PROGRESS progress;

    // 手算的现场值。RIP 与页地址只要互不相同即可,取值本身不参与任何算术。
    constexpr std::uint64_t kRipA = 0xFFFFF80100001000ULL;
    constexpr std::uint64_t kRipB = 0xFFFFF80100001007ULL;
    constexpr std::uint64_t kPageCloak = 0x0000000012340000ULL;
    constexpr std::uint64_t kPageHook = 0x0000000056780000ULL;

    // 复位之后台账必须是「还没有切换过」:不复位的话,上一批视图留下的
    // (RIP, 页, 目标) 会把新一批的第一次合法切换判成环,表现是刚装上视图
    // 就 fail-closed 退虚拟化。
    progress.LastRip = 0x1111ULL;
    progress.LastGuestPhysical = 0x2222ULL;
    progress.PreviousRip = 0x3333ULL;
    progress.PreviousGuestPhysical = 0x4444ULL;
    progress.LastTarget = 5U;
    progress.PreviousTarget = 6U;
    progress.SameRipSwitches = 7U;
    progress.Reserved0 = 8U;
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(progress.LastRip == 0ULL && progress.LastGuestPhysical == 0ULL &&
                 progress.PreviousRip == 0ULL &&
                 progress.PreviousGuestPhysical == 0ULL &&
                 progress.LastTarget == 0U && progress.PreviousTarget == 0U &&
                 progress.SameRipSwitches == 0U && progress.Reserved0 == 0U,
             L"a reset ledger records no history and points at the base hierarchy");
    // 空台账两条:重置忽略它,准入按「无法证明前进」拒绝。没有台账就没有证据,
    // 而这条路径的默认必须是 fail-closed。
    KswordArkHvmEptSwProgressReset(nullptr);
    s.expect(KswordArkHvmEptSwProgressAdmit(nullptr, kRipA, kPageCloak, 1U) == 0,
             L"a null ledger cannot prove progress and therefore admits nothing");

    // --- 正常前进 ---
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 1,
             L"the first switch of an instruction is always progress");
    s.expect(progress.LastRip == kRipA && progress.LastGuestPhysical == kPageCloak &&
                 progress.LastTarget == 1U && progress.SameRipSwitches == 1U,
             L"the accepted switch is recorded as this instruction's first");
    // 同一条指令的第二次违规(取指一次、操作数一次)是合法的,只要不重复。
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageHook, 2U) == 1,
             L"a second fault of the same instruction on another page is still progress");
    s.expect(progress.SameRipSwitches == 2U &&
                 progress.PreviousGuestPhysical == kPageCloak &&
                 progress.PreviousTarget == 1U,
             L"the previous generation is what the earlier switch left behind");

    // --- 周期 1:同一条指令、同一页、同一目标又来一次 ---
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 1,
             L"the first switch is admitted before the period-one probe");
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 0,
             L"switching to the same target for the same page and RIP is not progress");
    // 被拒绝时台账不更新:这一次退出的结局是退虚拟化,保留现场对事后判读更有用。
    s.expect(progress.SameRipSwitches == 1U && progress.PreviousRip == 0ULL,
             L"a refused switch leaves the ledger exactly as it was");

    // --- 周期 2:这就是文件开头那个「跨叶不可表示」的组合 ---
    // 取指落在 HOOK 页(要 HOOK 那一叶的次层次)、同一条指令的操作数读落在
    // CLOAK 页(要 CLOAK 那一叶的次层次)。每套层次只放宽一叶,所以没有任何
    // 单套层次能同时服务两半。KswordArkHvmEptSwDecide 对此无能为力 ——
    // 它一次只看到一次违规,每一半单独看都可服务 —— 所以它会诚实地一直返回
    // SWITCH,RIP 一步不动。台账是唯一能识别它的东西。
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageHook, 2U) == 1,
             L"the cross-leaf livelock's first switch looks perfectly normal");
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 1,
             L"its second switch also looks perfectly normal on its own");
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageHook, 2U) == 0,
             L"the third exit repeats generation two and is caught as a two-cycle");

    // --- 长环兜底:同一个 RIP 上切太多次 ---
    // 每一次的 (页, 目标) 都不同,所以周期 1 与周期 2 都不会响;只有计数会。
    // 手算:第一次把计数置 1,之后每次自增,第九次进来时计数已经是 8,触发上限。
    KswordArkHvmEptSwProgressReset(&progress);
    {
        bool firstEightAdmitted = true;
        for (std::uint32_t step = 0U; step < 8U; ++step) {
            if (KswordArkHvmEptSwProgressAdmit(
                    &progress, kRipA,
                    kPageCloak + ((std::uint64_t)step << 12),
                    step + 1U) != 1) {
                firstEightAdmitted = false;
            }
        }
        s.expect(firstEightAdmitted,
                 L"eight distinct switches at one RIP are all admitted");
        s.expect(progress.SameRipSwitches == 8U,
                 L"the counter reaches exactly the limit after eight switches");
        s.expect(KswordArkHvmEptSwProgressAdmit(
                     &progress, kRipA, kPageCloak + 0x8000ULL, 9U) == 0,
                 L"the ninth distinct switch at one RIP is refused by the long-cycle bound");
    }

    // --- RIP 变了就重新计数 ---
    // RIP 变了说明上一条指令退休了,也就是上一次切换确实起了作用。
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 1 &&
                 KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 0,
             L"the same instruction repeating itself is refused");
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipB, kPageCloak, 1U) == 1 &&
                 progress.SameRipSwitches == 1U,
             L"the next instruction starts a fresh count even on the same page and target");
    // 反过来:同一 RIP 并不必然是环,同一页并不必然是环,同一目标也不是 ——
    // 只有三者与前两代之一完全重合才是。这三条各放宽一格,都必须被接受。
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 1 &&
                 KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 2U) == 1,
             L"the same page with a different target is progress");
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageCloak, 1U) == 1 &&
                 KswordArkHvmEptSwProgressAdmit(&progress, kRipA, kPageHook, 1U) == 1,
             L"the same target on a different page is progress");

    // --- 与状态机串起来:文件开头那个组合走完整条路径 ---
    // 叶 0 = CLOAK 页,叶 1 = HOOK 页,同一条指令取指落在叶 1、操作数读落在叶 0。
    // Decide 三次全部诚实地返回 SWITCH(它看不到跨叶这件事),台账在第三次拒绝。
    // 这就是「Decide 拒绝不了、必须由台账兜住」这条前置条件的可执行证据。
    {
        KSWORD_ARK_HVM_EPTSW_TRANSITION transition;
        std::uint32_t active = 0U;
        std::uint32_t outcomes[3] = { 0U, 0U, 0U };
        std::uint32_t targets[3] = { 0U, 0U, 0U };
        int admitted[3] = { 0, 0, 0 };
        const std::uint32_t faultLeaf[3] = { 1U, 0U, 1U };
        const std::uint32_t faultKind[3] = { kHook, kCloak, kHook };
        const std::uint32_t faultAccess[3] = { kX, kR, kX };
        const std::uint64_t faultPage[3] = { kPageHook, kPageCloak, kPageHook };

        KswordArkHvmEptSwProgressReset(&progress);
        for (std::uint32_t step = 0U; step < 3U; ++step) {
            outcomes[step] = KswordArkHvmEptSwDecide(
                active, faultLeaf[step], 2U, faultAccess[step], faultKind[step],
                1, &transition);
            targets[step] = transition.NextIndex;
            admitted[step] = KswordArkHvmEptSwProgressAdmit(
                &progress, kRipA, faultPage[step], transition.NextIndex);
            if (admitted[step] != 0) {
                active = transition.NextIndex;
            }
        }
        // 三次决策全是 SWITCH,目标索引 2 -> 1 -> 2,RIP 一步没动。
        s.expect(outcomes[0] == kSwitch && outcomes[1] == kSwitch &&
                     outcomes[2] == kSwitch,
                 L"the decision function never refuses the cross-leaf combination");
        s.expect(targets[0] == 2U && targets[1] == 1U && targets[2] == 2U,
                 L"the targets alternate between the two leaf hierarchies");
        // 台账在第三次退出上把这个环打断,调用方据此 fail-closed。
        s.expect(admitted[0] == 1 && admitted[1] == 1 && admitted[2] == 0,
                 L"the ledger, not the decision function, is what stops the livelock");
    }

    // --- 台账的边界:全零现场 ---
    // 复位之后 LastRip 与 LastGuestPhysical 都是 0,目标是基座 0。一个 RIP 为 0、
    // 页为 0、目标为基座的「切换」因此与复位态完全重合,按周期 1 拒绝。
    // 这是保守方向:guest 内核代码不会跑在 RIP 0 上,而拒绝的代价只是一次
    // fail-closed,远小于放过一个环。
    KswordArkHvmEptSwProgressReset(&progress);
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, 0ULL, 0ULL, 0U) == 0,
             L"an all-zero switch coincides with the reset state and is refused");
    s.expect(KswordArkHvmEptSwProgressAdmit(&progress, 0ULL, 0ULL, 1U) == 1,
             L"the same all-zero site switching to a real hierarchy is still progress");
}

} // namespace

int RunHvmEptSwitchTests() {
    KswordTests::Suite suite(L"HVM ept switch");
    TestArchitecturalConstants(suite);
    TestExecuteOnlyCapability(suite);
    TestLeafDecomposition(suite);
    TestLeafComposition(suite);
    TestPermissionLegality(suite);
    TestMemoryTypeLegality(suite);
    TestFrameAlignment(suite);
    TestLeafWellFormed(suite);
    TestEptpComposition(suite);
    TestEptpDecomposition(suite);
    TestEptpWellFormed(suite);
    TestEptpRebase(suite);
    TestSwitchInvalidation(suite);
    TestInveptTypeSupport(suite);
    TestInveptDescriptor(suite);
    TestPreEntryInvalidation(suite);
    TestIndexArithmetic(suite);
    TestEntryAddress(suite);
    TestPageCost(suite);
    TestIndexEncoding(suite);
    TestAccessMapping(suite);
    TestKindPermissions(suite);
    TestDecideExhaustive(suite);
    TestDecideRejections(suite);
    TestRefuseHelper(suite);
    TestPlanSwitch(suite);
    TestProgressLedger(suite);
    suite.report();
    return suite.failures();
}
