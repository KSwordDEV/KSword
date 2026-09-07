// M 模块（内存证据与地址翻译深化）的离线自动测试。
//
// 覆盖编号：M-01 M-02 M-03 M-04 M-05 M-07 M-09 M-10（以及 F-05 / F-06 的账目要求）。
//
// 页表夹具完全由本文件用代码构造：一块 256 KiB 的模拟"物理内存"，PML4/PDPT/PD/PT
// 表项逐个手工填写，PhysicalReader 从这块内存读。所有期望的物理地址都是在注释里
// 手算出来的常量，不调用被测代码去算 —— 否则测试只是在给实现盖章。

#include "TestSupport.h"

#include "../shared/evidence/MemoryRegionEvidence.h"
#include "../shared/evidence/PageTableWalk.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using namespace Ksword::Evidence;

// ---------------------------------------------------------------------------
// 离线页表夹具
// ---------------------------------------------------------------------------
//
// 模拟物理内存覆盖 [0x00000000, 0x00040000)，共 64 个 4KiB 页。布局：
//   0x1000 PML4-A   0x2000 PDPT-A   0x3000 PD-A   0x4000 PT-A    帧 0x00010000
//   0x5000 PML4-B   0x6000 PDPT-B   0x7000 PD-B   0x8000 PT-B    帧 0x00011000
//   0x9000 PML4-C   0xA000 PDPT-C   0xB000 PD-C(PS=1，2MiB)      帧 0x00C00000
//   0xC000 PML4-D   0xD000 PDPT-D(PS=1，1GiB)                    帧 0x180000000
//
// 被翻译的虚拟地址固定为 kVa，它的四级索引是 1 / 2 / 3 / 4：
//   kVa = (1<<39) | (2<<30) | (3<<21) | (4<<12) | 0x678 = 0x0000008080604678
// 手算的页内偏移：
//   4KiB -> kVa & 0x00000FFF = 0x678
//   2MiB -> kVa & 0x001FFFFF = 0x4678        （3<<21 属于 PD 索引，不在偏移里）
//   1GiB -> kVa & 0x3FFFFFFF = 0x604678      （2<<30 属于 PDPT 索引，不在偏移里）

constexpr std::uint64_t kVa = 0x0000008080604678ULL;

constexpr std::uint64_t kRootA = 0x1000ULL;
constexpr std::uint64_t kRootB = 0x5000ULL;
constexpr std::uint64_t kRootC = 0x9000ULL;
constexpr std::uint64_t kRootD = 0xC000ULL;

// 逐层表项所在的物理地址：表基址 + 索引 * 8。
constexpr std::uint64_t kEntryPml4A = 0x1000ULL + 1ULL * 8ULL;   // 0x1008
constexpr std::uint64_t kEntryPdptA = 0x2000ULL + 2ULL * 8ULL;   // 0x2010
constexpr std::uint64_t kEntryPdA   = 0x3000ULL + 3ULL * 8ULL;   // 0x3018
constexpr std::uint64_t kEntryPtA   = 0x4000ULL + 4ULL * 8ULL;   // 0x4020
constexpr std::uint64_t kEntryPml4B = 0x5000ULL + 1ULL * 8ULL;   // 0x5008
constexpr std::uint64_t kEntryPdptB = 0x6000ULL + 2ULL * 8ULL;   // 0x6010
constexpr std::uint64_t kEntryPdB   = 0x7000ULL + 3ULL * 8ULL;   // 0x7018
constexpr std::uint64_t kEntryPtB   = 0x8000ULL + 4ULL * 8ULL;   // 0x8020
constexpr std::uint64_t kEntryPml4C = 0x9000ULL + 1ULL * 8ULL;   // 0x9008
constexpr std::uint64_t kEntryPdptC = 0xA000ULL + 2ULL * 8ULL;   // 0xA010
constexpr std::uint64_t kEntryPdC   = 0xB000ULL + 3ULL * 8ULL;   // 0xB018
constexpr std::uint64_t kEntryPml4D = 0xC000ULL + 1ULL * 8ULL;   // 0xC008
constexpr std::uint64_t kEntryPdptD = 0xD000ULL + 2ULL * 8ULL;   // 0xD010

// P|RW|US = 0x7；PS 位是 0x80。
constexpr std::uint64_t kLeafA = 0x00010007ULL;   // 帧 0x00010000
constexpr std::uint64_t kLeafB = 0x00011007ULL;   // 帧 0x00011000
constexpr std::uint64_t kLeaf2M = 0x00C00087ULL;  // 帧 0x00C00000，PS=1
constexpr std::uint64_t kLeaf1G = 0x180000087ULL; // 帧 0x180000000，PS=1

// 手算的最终物理地址。
constexpr std::uint64_t kExpectedPaA = 0x00010678ULL;   // 0x00010000 | 0x678
constexpr std::uint64_t kExpectedPaB = 0x00011678ULL;   // 0x00011000 | 0x678
constexpr std::uint64_t kExpectedPa2M = 0x00C04678ULL;  // 0x00C00000 | 0x4678
constexpr std::uint64_t kExpectedPa1G = 0x180604678ULL; // 0x180000000 | 0x604678

// M-04：MAXPHYADDR 不再有"看起来像在检查、其实不检查"的默认值。TranslateOptions
// 默认 0 = 调用方没提供 = 该项检查明确不生效，所以测试统一显式传一个真实宽度。
// 48 位是常见桌面 CPU 的值，夹具里所有表项都落在 48 位以内，因此它不会误伤。
constexpr std::uint32_t kMaxPhys = 48U;

// 默认选项：四级分页 + MAXPHYADDR=48 + **不支持 1GiB 大页**。
// 1GiB 默认关闭是硬规则：Intel SDM 规定 CPUID.80000001H:EDX.Page1GB==0 时
// PDPTE 的 bit7 是保留位，置位会触发 reserved-bit #PF。
TranslateOptions MakeOptions() {
    TranslateOptions options;
    options.mode = PagingMode::LongMode4Level;
    options.maxPhysAddrBits = kMaxPhys;
    options.supports1GiBPages = false;
    return options;
}

// 只有在真的确认了 CPUID.80000001H:EDX[26] 之后才允许用这一份。
TranslateOptions MakeOptions1GiB() {
    TranslateOptions options = MakeOptions();
    options.supports1GiBPages = true;
    return options;
}

using PhysMemory = std::vector<std::uint8_t>;

void PutEntry(PhysMemory& memory, std::uint64_t physicalAddress, std::uint64_t value) {
    for (std::size_t i = 0; i < 8U; ++i) {
        memory[static_cast<std::size_t>(physicalAddress) + i] =
            static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFULL);
    }
}

PhysMemory BuildFixture() {
    PhysMemory memory(0x40000U, 0U);
    // 根 A：普通 4KiB 映射。
    PutEntry(memory, kEntryPml4A, 0x2007ULL);
    PutEntry(memory, kEntryPdptA, 0x3007ULL);
    PutEntry(memory, kEntryPdA, 0x4007ULL);
    PutEntry(memory, kEntryPtA, kLeafA);
    // 根 B：同一个 VA，另一套页表，另一个帧。
    PutEntry(memory, kEntryPml4B, 0x6007ULL);
    PutEntry(memory, kEntryPdptB, 0x7007ULL);
    PutEntry(memory, kEntryPdB, 0x8007ULL);
    PutEntry(memory, kEntryPtB, kLeafB);
    // 根 C：PDE.PS=1，2MiB 大页。
    PutEntry(memory, kEntryPml4C, 0xA007ULL);
    PutEntry(memory, kEntryPdptC, 0xB007ULL);
    PutEntry(memory, kEntryPdC, kLeaf2M);
    // 根 D：PDPTE.PS=1，1GiB 大页。
    PutEntry(memory, kEntryPml4D, 0xD007ULL);
    PutEntry(memory, kEntryPdptD, kLeaf1G);
    return memory;
}

// 夹具读取回调：越界即读不到，正好模拟真实驱动"这页读不了"的情况。
PhysicalReader MakeReader(const PhysMemory& memory) {
    return [&memory](std::uint64_t physAddr, std::uint8_t* out, std::size_t bytes) -> bool {
        const std::uint64_t size = static_cast<std::uint64_t>(memory.size());
        if (physAddr >= size || static_cast<std::uint64_t>(bytes) > size - physAddr) {
            return false;
        }
        for (std::size_t i = 0; i < bytes; ++i) {
            out[i] = memory[static_cast<std::size_t>(physAddr) + i];
        }
        return true;
    };
}

bool NoPhysicalAddress(const TranslateResult& result) {
    return !result.physicalAddress.present && !result.pageFrameBase.present;
}

// ---------------------------------------------------------------------------
// M-04：4KiB 逐层索引与最终物理地址
// ---------------------------------------------------------------------------
void TestFourKiBTranslation(KswordTests::Suite& s) {
    const PhysMemory memory = BuildFixture();
    const TranslateResult result =
        TranslateVirtualAddress(kVa, kRootA, MakeReader(memory), MakeOptions());

    s.expect(result.status == TranslationStatus::Translated,
             L"M-04 a fully mapped 4KiB address translates");
    s.expect(result.pageSize == PageSizeClass::Size4KiB, L"M-04 the page size class is 4KiB");
    s.expect(result.levels.size() == 4U, L"M-04 all four levels are kept as evidence");
    if (result.levels.size() == 4U) {
        s.expect(result.levels[0].level == PageTableLevel::Pml4 && result.levels[0].index == 1U &&
                     result.levels[0].entryPhysicalAddress == kEntryPml4A &&
                     result.levels[0].rawValue == 0x2007ULL,
                 L"M-04 PML4E index, entry address and raw value are recorded");
        s.expect(result.levels[1].level == PageTableLevel::Pdpt && result.levels[1].index == 2U &&
                     result.levels[1].entryPhysicalAddress == kEntryPdptA &&
                     result.levels[1].rawValue == 0x3007ULL,
                 L"M-04 PDPTE index, entry address and raw value are recorded");
        s.expect(result.levels[2].level == PageTableLevel::Pd && result.levels[2].index == 3U &&
                     result.levels[2].entryPhysicalAddress == kEntryPdA &&
                     result.levels[2].rawValue == 0x4007ULL,
                 L"M-04 PDE index, entry address and raw value are recorded");
        s.expect(result.levels[3].level == PageTableLevel::Pt && result.levels[3].index == 4U &&
                     result.levels[3].entryPhysicalAddress == kEntryPtA &&
                     result.levels[3].rawValue == kLeafA,
                 L"M-04 PTE index, entry address and raw value are recorded");
    }
    s.expect(result.physicalAddress == OptionalU64::of(kExpectedPaA),
             L"M-04 the 4KiB physical address matches the hand-computed value");
    s.expect(result.pageOffset == OptionalU64::of(0x678ULL),
             L"M-04 the 4KiB page offset is 12 bits wide");
    s.expect(result.permissions.writable && result.permissions.userAccessible &&
                 !result.permissions.executeDisable,
             L"M-04 effective permissions are merged across levels");
    // 判据本身要能被复核：结果必须说出这次用的是哪个 MAXPHYADDR。
    s.expect(result.effectiveMaxPhysAddrBits == OptionalU64::of(kMaxPhys),
             L"M-04 the MAXPHYADDR that was actually in effect travels with the result");
}

// ---------------------------------------------------------------------------
// M-04：大页的偏移位宽，以及 1GiB 的硬件能力前提
// ---------------------------------------------------------------------------
void TestLargePages(KswordTests::Suite& s) {
    const PhysMemory memory = BuildFixture();
    const PhysicalReader reader = MakeReader(memory);

    // 2MiB 页在 IA-32e 下没有额外的 CPUID 前提，用默认选项即可。
    const TranslateResult twoMiB = TranslateVirtualAddress(kVa, kRootC, reader, MakeOptions());
    s.expect(twoMiB.status == TranslationStatus::Translated && twoMiB.levels.size() == 3U,
             L"M-04 a PDE with PS=1 stops the walk after three levels");
    s.expect(twoMiB.pageSize == PageSizeClass::Size2MiB,
             L"M-04 the 2MiB page size class is reported");
    s.expect(!twoMiB.levels.empty() && twoMiB.levels.back().largePage,
             L"M-04 the PDE is flagged as a large page");
    s.expect(twoMiB.pageOffset == OptionalU64::of(0x4678ULL),
             L"M-04 the 2MiB page offset is 21 bits wide");
    s.expect(twoMiB.physicalAddress == OptionalU64::of(kExpectedPa2M),
             L"M-04 the 2MiB physical address matches the hand-computed value");

    // 1GiB 需要 CPUID.80000001H:EDX.Page1GB。确认支持之后才允许翻译出物理地址。
    const TranslateResult oneGiB = TranslateVirtualAddress(kVa, kRootD, reader, MakeOptions1GiB());
    s.expect(oneGiB.status == TranslationStatus::Translated && oneGiB.levels.size() == 2U,
             L"M-04 a PDPTE with PS=1 stops the walk after two levels when 1GiB pages are supported");
    s.expect(oneGiB.pageSize == PageSizeClass::Size1GiB,
             L"M-04 the 1GiB page size class is reported");
    s.expect(oneGiB.pageOffset == OptionalU64::of(0x604678ULL),
             L"M-04 the 1GiB page offset is 30 bits wide");
    s.expect(oneGiB.physicalAddress == OptionalU64::of(kExpectedPa1G),
             L"M-04 the 1GiB physical address matches the hand-computed value");
    s.expect(oneGiB.supports1GiBPages,
             L"M-04 the result records that it interpreted PDPTE.bit7 as a 1GiB page size bit");

    // 负向：同一份夹具，机器不支持 1GiB。此时 PDPTE 的 bit7 是保留位，置位的表项
    // 在硬件上会触发 reserved-bit #PF —— 所以这里必须是 ReservedBitSet 而不是翻译，
    // 否则我们会为一个硬件根本不接受的表项造出物理地址。
    const TranslateResult noOneGiB = TranslateVirtualAddress(kVa, kRootD, reader, MakeOptions());
    s.expect(noOneGiB.status == TranslationStatus::ReservedBitSet &&
                 noOneGiB.failedLevel == PageTableLevel::Pdpt,
             L"M-04 without the Page1GB capability a PDPTE with PS=1 is a reserved-bit violation");
    s.expect(noOneGiB.reservedBitsSet == (1ULL << 7U),
             L"M-04 the offending bit is exactly PDPTE bit7, the PS bit that is reserved here");
    s.expect(NoPhysicalAddress(noOneGiB),
             L"M-04 a 1GiB entry on a machine without 1GiB pages never yields a physical address");
}

// ---------------------------------------------------------------------------
// M-04：非 canonical、缺项、不支持的模式
// ---------------------------------------------------------------------------
void TestRejectedAddresses(KswordTests::Suite& s) {
    PhysMemory memory = BuildFixture();
    const PhysicalReader reader = MakeReader(memory);

    const TranslateResult nonCanonical =
        TranslateVirtualAddress(0x0000800000000000ULL, kRootA, reader, MakeOptions());
    s.expect(nonCanonical.status == TranslationStatus::NotCanonical,
             L"M-04 a non-canonical address is rejected before any table read");
    s.expect(nonCanonical.levels.empty() && NoPhysicalAddress(nonCanonical),
             L"M-04 a rejected address produces no physical address at all");

    // 0xFFFF800000000000 是合法的内核侧 canonical 地址，PML4 索引 256 在夹具里是空项。
    const TranslateResult emptyEntry =
        TranslateVirtualAddress(0xFFFF800000000000ULL, kRootA, reader, MakeOptions());
    s.expect(emptyEntry.status == TranslationStatus::EntryNotPresent &&
                 emptyEntry.failedLevel == PageTableLevel::Pml4,
             L"M-04 a canonical kernel address with an empty PML4E stops at PML4");
    s.expect(NoPhysicalAddress(emptyEntry),
             L"M-04 a missing PML4E never yields a physical address");

    // 把 PD-A 的 present 位清掉：缺项必须停在 PDE 这一级。
    PutEntry(memory, kEntryPdA, 0x4007ULL & ~1ULL);
    const TranslateResult missingPde =
        TranslateVirtualAddress(kVa, kRootA, MakeReader(memory), MakeOptions());
    s.expect(missingPde.status == TranslationStatus::EntryNotPresent &&
                 missingPde.failedLevel == PageTableLevel::Pd,
             L"M-04 a PDE with P=0 reports EntryNotPresent at the PDE level");
    s.expect(missingPde.levels.size() == 3U && NoPhysicalAddress(missingPde),
             L"M-04 a missing PDE keeps three levels of evidence and no physical address");

    TranslateOptions unsupported = MakeOptions();
    unsupported.mode = PagingMode::Unsupported;
    const TranslateResult la57 =
        TranslateVirtualAddress(kVa, kRootA, MakeReader(memory), unsupported);
    s.expect(la57.status == TranslationStatus::UnsupportedMode && NoPhysicalAddress(la57),
             L"M-04 an unsupported paging mode is refused instead of guessed");

    // 根落在夹具之外：第一层就读不到，且 PML4E 的地址与索引仍然保留。
    const TranslateResult readFail =
        TranslateVirtualAddress(kVa, 0x100000ULL, MakeReader(memory), MakeOptions());
    s.expect(readFail.status == TranslationStatus::PhysicalReadFailed &&
                 readFail.failedLevel == PageTableLevel::Pml4,
             L"M-04 an unreadable table page reports PhysicalReadFailed at that level");
    s.expect(readFail.levels.size() == 1U && !readFail.levels[0].read &&
                 readFail.levels[0].entryPhysicalAddress == 0x100008ULL,
             L"M-04 the unreadable level still records its entry address and index");
    s.expect(NoPhysicalAddress(readFail),
             L"M-04 a read failure never yields a physical address");
}

// ---------------------------------------------------------------------------
// M-04：保留位异常
// ---------------------------------------------------------------------------
void TestReservedBits(KswordTests::Suite& s) {
    // 2MiB 项的 bit13 是保留位（bit13..20 必须为 0）。
    PhysMemory twoMiB = BuildFixture();
    PutEntry(twoMiB, kEntryPdC, kLeaf2M | (1ULL << 13U));
    const TranslateResult bad2M =
        TranslateVirtualAddress(kVa, kRootC, MakeReader(twoMiB), MakeOptions());
    s.expect(bad2M.status == TranslationStatus::ReservedBitSet &&
                 bad2M.failedLevel == PageTableLevel::Pd,
             L"M-04 a reserved low bit in a 2MiB PDE is reported at the PDE level");
    s.expect(bad2M.reservedBitsSet == (1ULL << 13U),
             L"M-04 the offending reserved bits are reported exactly");
    s.expect(NoPhysicalAddress(bad2M),
             L"M-04 a reserved-bit violation never yields a physical address");

    // 1GiB 项的 bit20 同样落在 bit13..29 的保留区间里。这条判据只有在机器**支持**
    // 1GiB 时才有意义 —— 不支持时 bit7 本身就先被判成保留位了（见 TestLargePages）。
    PhysMemory oneGiB = BuildFixture();
    PutEntry(oneGiB, kEntryPdptD, kLeaf1G | (1ULL << 20U));
    const TranslateResult bad1G =
        TranslateVirtualAddress(kVa, kRootD, MakeReader(oneGiB), MakeOptions1GiB());
    s.expect(bad1G.status == TranslationStatus::ReservedBitSet &&
                 bad1G.failedLevel == PageTableLevel::Pdpt &&
                 bad1G.reservedBitsSet == (1ULL << 20U),
             L"M-04 a reserved low bit in a 1GiB PDPTE is reported at the PDPTE level");
    s.expect(NoPhysicalAddress(bad1G),
             L"M-04 a bad 1GiB entry produces no physical address");

    // MAXPHYADDR=40 时 bit44 是超出物理地址宽度的保留位。
    TranslateOptions narrow = MakeOptions();
    narrow.maxPhysAddrBits = 40U;
    const PhysMemory clean = BuildFixture();
    const TranslateResult stillOk = TranslateVirtualAddress(kVa, kRootA, MakeReader(clean), narrow);
    s.expect(stillOk.status == TranslationStatus::Translated &&
                 stillOk.physicalAddress == OptionalU64::of(kExpectedPaA),
             L"M-04 a narrow MAXPHYADDR does not reject legitimate entries");

    PhysMemory wide = BuildFixture();
    PutEntry(wide, kEntryPtA, kLeafA | (1ULL << 44U));
    const TranslateResult tooWide = TranslateVirtualAddress(kVa, kRootA, MakeReader(wide), narrow);
    s.expect(tooWide.status == TranslationStatus::ReservedBitSet &&
                 tooWide.failedLevel == PageTableLevel::Pt &&
                 tooWide.reservedBitsSet == (1ULL << 44U),
             L"M-04 an address bit above MAXPHYADDR is a reserved-bit violation");
    s.expect(NoPhysicalAddress(tooWide),
             L"M-04 an over-wide physical address is never emitted");
    s.expect(tooWide.effectiveMaxPhysAddrBits == OptionalU64::of(40U),
             L"M-04 the MAXPHYADDR that produced the rejection is carried in the result");

    // 同一位在 MAXPHYADDR=52 下不是保留位 —— 判据随参数走，不是写死的。
    TranslateOptions archMax = MakeOptions();
    archMax.maxPhysAddrBits = 52U;
    const TranslateResult wideOk = TranslateVirtualAddress(kVa, kRootA, MakeReader(wide), archMax);
    s.expect(wideOk.status == TranslationStatus::Translated,
             L"M-04 the same bit is legal when MAXPHYADDR allows it");

    // MAXPHYADDR 根本没提供（默认 0）：该项检查不生效，而且结果里必须**明说**它没
    // 生效。以前默认 52 时它同样不生效，却看不出来 —— 那是一条隐形失效的判据。
    const TranslateResult noMaxPhys = TranslateVirtualAddress(kVa, kRootA, MakeReader(wide));
    s.expect(noMaxPhys.status == TranslationStatus::Translated,
             L"M-04 an unsupplied MAXPHYADDR reserves no bits");
    s.expect(!noMaxPhys.effectiveMaxPhysAddrBits.present,
             L"M-04 an unsupplied MAXPHYADDR is reported as an inactive check, not as a silent pass");
    s.expect(!noMaxPhys.supports1GiBPages,
             L"M-04 the 1GiB capability defaults to absent, so PDPTE.bit7 defaults to reserved");
}

// ---------------------------------------------------------------------------
// M-05：非驻留项的软件 PTE 解码
// ---------------------------------------------------------------------------
void TestSoftwarePte(KswordTests::Suite& s) {
    struct Case final {
        std::uint64_t entry;
        SoftwarePteKind expected;
        const wchar_t* label;
    };
    // bit0=0 一律非驻留；bit11=Transition，bit10=Prototype；剩下的按 PageFileHigh
    // (bit32..63) 是否非零，分成"真的在分页文件里"和"从未触碰的 demand-zero"。
    const Case cases[] = {
        {0x00010800ULL, SoftwarePteKind::Transition, L"M-05 a transition PTE is recognised"},
        {0x0000ABCD00000400ULL, SoftwarePteKind::Prototype, L"M-05 a prototype PTE is recognised"},
        {0x0000123400000006ULL, SoftwarePteKind::PageFile, L"M-05 a page-file PTE is recognised"},
        {0x0000000000000020ULL, SoftwarePteKind::DemandZero,
         L"M-05 a software PTE with only protection bits set is demand-zero, not a page-file PTE"},
        {0x0000000000000000ULL, SoftwarePteKind::Zero, L"M-05 an all-zero PTE is not a page-file PTE"},
    };

    for (const Case& item : cases) {
        PhysMemory memory = BuildFixture();
        PutEntry(memory, kEntryPtA, item.entry);
        const TranslateResult result =
            TranslateVirtualAddress(kVa, kRootA, MakeReader(memory), MakeOptions());
        s.expect(result.status == TranslationStatus::EntryNotPresent &&
                     result.failedLevel == PageTableLevel::Pt && result.softwarePteDecoded &&
                     result.softwarePte.kind == item.expected,
                 item.label);
        s.expect(NoPhysicalAddress(result),
                 L"M-05 a non-resident PTE never yields a physical address");
    }

    const SoftwarePteDecode pageFile = DecodeSoftwarePte(0x0000123400000006ULL);
    s.expect(pageFile.pageFileNumber == OptionalU64::of(3ULL),
             L"M-05 the page file number is decoded from bits 1..4");
    s.expect(pageFile.pageFileOffset == OptionalU64::of(0x1234ULL),
             L"M-05 the page file offset is decoded from bits 32..63");

    // 负向：entry=0x20 只置了 MMPTE_SOFTWARE 的 Protection 字段（bit5..9），
    // PageFileHigh(bit32..63) 是 0 —— 这是一个已提交但从未被触碰的页，它在分页
    // 文件里根本没有位置。判成 PageFile 并填 present=1 value=0 的号码与偏移，
    // 就是凭空造出一个分页文件位置（M-05 明令禁止）。
    const SoftwarePteDecode demandZero = DecodeSoftwarePte(0x20ULL);
    s.expect(demandZero.kind == SoftwarePteKind::DemandZero,
             L"M-05 an entry whose PageFileHigh is zero is classified as demand-zero");
    s.expect(!demandZero.pageFileNumber.present && !demandZero.pageFileOffset.present,
             L"M-05 a demand-zero PTE fabricates neither a page file number nor an offset");
    s.expect(!demandZero.transitionBit && !demandZero.prototypeBit,
             L"M-05 the demand-zero classification is not driven by the transition or prototype bit");

    const SoftwarePteDecode transition = DecodeSoftwarePte(0x00010800ULL);
    s.expect(transition.transitionBit && !transition.prototypeBit,
             L"M-05 the transition bit is reported separately from the classification");
    s.expect(!transition.pageFileNumber.present && !transition.pageFileOffset.present,
             L"M-05 a transition PTE carries no page file location either");

    // 两个互斥编码位同时置位：不硬套分类。
    const SoftwarePteDecode ambiguous = DecodeSoftwarePte(0x0000000000000C00ULL);
    s.expect(ambiguous.kind == SoftwarePteKind::Unknown,
             L"M-05 an unrecognised software PTE encoding stays Unknown");
}

// ---------------------------------------------------------------------------
// M-03：翻译上下文
// ---------------------------------------------------------------------------
ProcessInstanceId MakeProcess(std::uint64_t pid, std::uint64_t createTime) {
    ProcessInstanceId id;
    id.bootId = "boot-M";
    id.pid = OptionalU64::of(pid);
    id.createTime100ns = OptionalU64::of(createTime);
    id.imageName = "target.exe";
    return id;
}

TranslationContext MakeContext(const ProcessInstanceId& process, std::uint64_t root) {
    TranslationContext context;
    context.process = process;
    context.pageTableRootPhysical = OptionalU64::of(root);
    context.observedUtc100ns = OptionalU64::of(133000000000000000ULL);
    context.mode = PagingMode::LongMode4Level;
    context.rootSource = "KPROCESS.DirectoryTableBase";
    return context;
}

void TestTranslationContext(KswordTests::Suite& s) {
    const PhysMemory memory = BuildFixture();
    const PhysicalReader reader = MakeReader(memory);

    const ProcessInstanceId procA = MakeProcess(4321ULL, 133000000000000000ULL);
    const ProcessInstanceId procB = MakeProcess(5555ULL, 133000000000900000ULL);
    const TranslationContext ctxA = MakeContext(procA, kRootA);
    const TranslationContext ctxB = MakeContext(procB, kRootB);

    LiveResolution liveA;
    liveA.found = true;
    liveA.liveProcess = procA;
    LiveResolution liveB;
    liveB.found = true;
    liveB.liveProcess = procB;

    const ContextValidity validA = CheckContextUsable(ctxA, liveA);
    const ContextValidity validB = CheckContextUsable(ctxB, liveB);
    s.expect(validA == ContextValidity::Usable && validB == ContextValidity::Usable,
             L"M-03 a live, identity-confirmed context is usable");

    TranslateResult resultA;
    TranslateResult resultB;
    const bool okA = TranslateUsingContext(ctxA, validA, kVa, reader, MakeOptions(), resultA);
    const bool okB = TranslateUsingContext(ctxB, validB, kVa, reader, MakeOptions(), resultB);
    s.expect(okA && okB, L"M-03 both usable contexts are allowed to translate");
    s.expect(resultA.physicalAddress == OptionalU64::of(kExpectedPaA) &&
                 resultB.physicalAddress == OptionalU64::of(kExpectedPaB),
             L"M-03 the same VA under two page table roots yields two different physical addresses");
    s.expect(resultA.physicalAddress != resultB.physicalAddress,
             L"M-03 translation contexts are not mixed up between processes");

    // 进程已退出：上下文失效，只能作为历史观测展示。
    LiveResolution exited;
    exited.found = false;
    const ContextValidity afterExit = CheckContextUsable(ctxA, exited);
    s.expect(afterExit == ContextValidity::RejectProcessExited,
             L"M-03 a context whose process exited is rejected");
    s.expect(!ContextAllowsLiveReuse(afterExit),
             L"M-03 an invalid context may not be reused for a live translation");
    TranslateResult stale;
    const bool refused = TranslateUsingContext(ctxA, afterExit, kVa, reader, MakeOptions(), stale);
    s.expect(!refused && !stale.physicalAddress.present,
             L"M-03 a refused translation produces no physical address");
    // 拒绝理由必须是真实理由。以前这里让结果保持默认值，而默认状态是 UnsupportedMode，
    // 于是"进程已退出"会被 UI 渲染成"分页模式不支持"。
    s.expect(stale.status == TranslationStatus::ContextRejected,
             L"M-03 a context refusal is its own status, not the unsupported-paging-mode default");
    s.expect(stale.contextRefusal == ContextValidity::RejectProcessExited,
             L"M-03 the refusal reason handed to the UI is exactly RejectProcessExited");

    // 另一种拒绝理由同样原样带出来，两种拒绝在结果里可区分。
    TranslationContext noRootCtx = ctxA;
    noRootCtx.pageTableRootPhysical = OptionalU64::unset();
    const ContextValidity noRootValidity = CheckContextUsable(noRootCtx, liveA);
    TranslateResult noRootResult;
    const bool noRootRefused =
        TranslateUsingContext(noRootCtx, noRootValidity, kVa, reader, MakeOptions(), noRootResult);
    s.expect(!noRootRefused &&
                 noRootResult.contextRefusal == ContextValidity::RejectNoPageTableRoot &&
                 noRootResult.contextRefusal != stale.contextRefusal,
             L"M-03 two different refusal reasons stay distinguishable in the result");

    // PID 复用：同 PID 不同创建时间。
    LiveResolution reused;
    reused.found = true;
    reused.liveProcess = MakeProcess(4321ULL, 133000000000777000ULL);
    s.expect(CheckContextUsable(ctxA, reused) == ContextValidity::RejectIdentityMismatch,
             L"M-03 a reused PID is an identity mismatch, not the same context");

    // 身份不足：保存下来的创建时间缺失。
    TranslationContext weak = ctxA;
    weak.process.createTime100ns = OptionalU64::unset();
    LiveResolution weakLive;
    weakLive.found = true;
    weakLive.liveProcess = procA;
    weakLive.liveProcess.createTime100ns = OptionalU64::unset();
    s.expect(CheckContextUsable(weak, weakLive) == ContextValidity::RejectIdentityUnverifiable,
             L"M-03 an unverifiable identity is not silently upgraded to usable");

    s.expect(noRootValidity == ContextValidity::RejectNoPageTableRoot,
             L"M-03 a context without a page table root is rejected");

    TranslationContext badMode = ctxA;
    badMode.mode = PagingMode::Unsupported;
    s.expect(CheckContextUsable(badMode, liveA) == ContextValidity::RejectUnsupportedMode,
             L"M-03 a context with an unsupported paging mode is rejected");
}

// ---------------------------------------------------------------------------
// M-02：跨页边界的部分读取
// ---------------------------------------------------------------------------
void TestPartialRead(KswordTests::Suite& s) {
    // 0x1000..0x1FFF 可读，0x2000 起完全读不到。字节值固定为地址低 8 位。
    // 读不到时把驱动自己的 NTSTATUS 交回来（F-05）。
    const ChunkReader reader = [](std::uint64_t address, std::uint8_t* out, std::size_t bytes,
                                  ChunkReadResult& outcome) {
        const std::uint64_t available = (address < 0x2000ULL) ? (0x2000ULL - address) : 0ULL;
        const std::size_t count = (static_cast<std::uint64_t>(bytes) < available)
                                      ? bytes
                                      : static_cast<std::size_t>(available);
        for (std::size_t i = 0; i < count; ++i) {
            out[i] = static_cast<std::uint8_t>((address + i) & 0xFFULL);
        }
        outcome.copied = count;
        if (count == bytes) {
            outcome.status = CollectionStatus::Success;
            return;
        }
        outcome.status = (count == 0U) ? CollectionStatus::AccessDenied : CollectionStatus::Partial;
        outcome.nativeCodeDomain = "NTSTATUS";
        outcome.nativeCode = OptionalU64::of((count == 0U) ? 0xC0000022ULL : 0x8000000DULL);
        outcome.message = (count == 0U) ? "STATUS_ACCESS_DENIED" : "STATUS_PARTIAL_COPY";
    };

    BoundedReadRequest request;
    request.requested.begin = 0x1FF0ULL;
    request.requested.length = 0x20ULL;   // 跨过 0x2000 这个页边界
    request.budget.maxBytes = OptionalU64::of(0x1000ULL);
    request.chunkSize = 0x1000ULL;

    const BoundedReadResult result = ReadRangeBounded(request, reader);
    s.expect(result.validation == RangeValidation::Ok &&
                 result.rejection == BoundedReadRejection::None &&
                 result.stop == BudgetStop::Continue,
             L"M-02 a legal cross-page range runs to completion without hitting a budget");
    s.expect(result.span.outcome.status == CollectionStatus::Partial,
             L"M-02 a read with holes is Partial, never Success");
    s.expect(result.span.presentCount() == 16ULL,
             L"M-02 exactly the readable half of the range is marked present");

    bool firstPageExact = true;
    for (std::uint64_t address = 0x1FF0ULL; address < 0x2000ULL; ++address) {
        std::uint8_t value = 0U;
        if (!ByteAt(result.span, address, value) ||
            value != static_cast<std::uint8_t>(address & 0xFFULL)) {
            firstPageExact = false;
        }
    }
    s.expect(firstPageExact, L"M-02 every byte of the readable page matches the source exactly");

    bool secondPageIsHole = true;
    for (std::uint64_t address = 0x2000ULL; address < 0x2010ULL; ++address) {
        std::uint8_t value = 0U;
        if (ByteAt(result.span, address, value)) {
            secondPageIsHole = false;
        }
    }
    s.expect(secondPageIsHole, L"M-02 the unreadable page stays a hole and yields no bytes");

    const std::vector<AddressRange> holes = DescribeHoles(result.span);
    s.expect(holes.size() == 1U && holes[0].begin == 0x2000ULL && holes[0].length == 0x10ULL,
             L"M-02 the hole range is reported exactly");
    s.expect(result.coverage.succeeded == 16ULL && result.coverage.failed == 16ULL &&
                 result.coverage.truncated == 0ULL,
             L"M-02 the coverage account separates read bytes from unreadable bytes");
    s.expect(!result.coverage.fullyCovered(),
             L"M-02 a range with holes is never reported as fully covered");
    s.expect(result.span.outcome.nativeCode == OptionalU64::of(0xC0000022ULL) &&
                 result.span.outcome.nativeCodeDomain == "NTSTATUS" &&
                 result.span.outcome.message == "STATUS_ACCESS_DENIED",
             L"F-05 the first underlying failure's own status code and text survive into the result");

    // 全部可读的范围才允许 Success。
    BoundedReadRequest whole = request;
    whole.requested.begin = 0x1000ULL;
    whole.requested.length = 0x10ULL;
    const BoundedReadResult full = ReadRangeBounded(whole, reader);
    s.expect(full.span.outcome.status == CollectionStatus::Success && !full.span.hasHole() &&
                 DescribeHoles(full.span).empty(),
             L"M-02 a fully readable range is Success with no holes");
    s.expect(full.coverage.fullyCovered(),
             L"M-02 a fully readable range reports full coverage");
    s.expect(!full.span.outcome.nativeCode.present,
             L"F-05 a fully successful read leaves the native code unset instead of writing 0");

    // M-02：真实驱动最常见的一条路径是"一个块里前半段拷到了、后半段没拷到"
    // （0 < copied < length）。上面两个用例的块要么满读要么零读，走不到它。
    // chunkSize=0x4000 时 0x1000 % 0x4000 = 0x1000，所以整段请求恰好落在同一个块里：
    // 回调被要求 0x1010 字节，而它只拷得动前 0x1000 字节（0x2000 起读不到）。
    BoundedReadRequest straddling;
    straddling.requested.begin = 0x1000ULL;
    straddling.requested.length = 0x1010ULL;
    straddling.chunkSize = 0x4000ULL;
    straddling.budget.maxItems = OptionalU64::of(4ULL);
    int straddleCalls = 0;
    std::size_t straddleAsked = 0U;
    const ChunkReader straddleReader = [&straddleCalls, &straddleAsked](
                                           std::uint64_t address, std::uint8_t* out,
                                           std::size_t bytes, ChunkReadResult& outcome) {
        ++straddleCalls;
        straddleAsked = bytes;
        const std::uint64_t available = (address < 0x2000ULL) ? (0x2000ULL - address) : 0ULL;
        const std::size_t count = (static_cast<std::uint64_t>(bytes) < available)
                                      ? bytes
                                      : static_cast<std::size_t>(available);
        for (std::size_t i = 0; i < count; ++i) {
            out[i] = static_cast<std::uint8_t>((address + i) & 0xFFULL);
        }
        outcome.copied = count;
        outcome.status = (count == bytes) ? CollectionStatus::Success : CollectionStatus::Partial;
        if (count < bytes) {
            outcome.nativeCodeDomain = "NTSTATUS";
            outcome.nativeCode = OptionalU64::of(0x8000000DULL);  // STATUS_PARTIAL_COPY
            outcome.message = "STATUS_PARTIAL_COPY";
        }
    };
    const BoundedReadResult straddled = ReadRangeBounded(straddling, straddleReader);
    s.expect(straddleCalls == 1 && straddleAsked == static_cast<std::size_t>(0x1010),
             L"M-02 the whole request lands in one chunk, so the reader sees a single 0x1010-byte call");
    s.expect(straddled.span.presentCount() == 0x1000ULL,
             L"M-02 a chunk reporting 0 < copied < length marks exactly the copied bytes present");

    bool straddlePrefixExact = true;
    for (std::uint64_t address = 0x1000ULL; address < 0x2000ULL; ++address) {
        std::uint8_t value = 0U;
        if (!ByteAt(straddled.span, address, value) ||
            value != static_cast<std::uint8_t>(address & 0xFFULL)) {
            straddlePrefixExact = false;
        }
    }
    s.expect(straddlePrefixExact,
             L"M-02 the copied prefix of a partially copied chunk is byte-exact");
    bool straddleTailIsHole = true;
    for (std::uint64_t address = 0x2000ULL; address < 0x2010ULL; ++address) {
        std::uint8_t value = 0U;
        if (ByteAt(straddled.span, address, value)) {
            straddleTailIsHole = false;
        }
    }
    s.expect(straddleTailIsHole,
             L"M-02 the uncopied tail of a partially copied chunk stays a hole");
    const std::vector<AddressRange> straddleHoles = DescribeHoles(straddled.span);
    s.expect(straddleHoles.size() == 1U && straddleHoles[0].begin == 0x2000ULL &&
                 straddleHoles[0].length == 0x10ULL,
             L"M-02 DescribeHoles reports the uncopied tail of the chunk as exactly [0x2000,0x2010)");
    s.expect(straddled.span.outcome.status == CollectionStatus::Partial &&
                 straddled.span.outcome.nativeCode == OptionalU64::of(0x8000000DULL),
             L"M-02 a partial copy is Partial and keeps the driver's own partial-copy status");
    s.expect(straddled.coverage.succeeded == 0x1000ULL && straddled.coverage.failed == 0x10ULL &&
                 straddled.coverage.truncated == 0ULL,
             L"M-02 a partial copy is accounted as copied bytes plus a hole, not as truncation");
}

// ---------------------------------------------------------------------------
// M-02 / M-05：合并多次读取
// ---------------------------------------------------------------------------

// 两个采集时刻，相差 5 分钟（3e9 个 100ns）。M-05 的判据是时刻，所以夹具必须
// 能造出"同一时刻"和"不同时刻"两种输入。
constexpr std::uint64_t kObserveT0 = 133000000000000000ULL;
constexpr std::uint64_t kObserveT1 = 133000003000000000ULL;

ReadSpan MakeFilledSpan(std::uint64_t begin,
                        std::size_t length,
                        std::uint8_t seed,
                        const OptionalU64& observedUtc100ns) {
    AddressRange range;
    range.begin = begin;
    range.length = static_cast<std::uint64_t>(length);
    ReadSpan span = MakeEmptyReadSpan(range);
    std::vector<std::uint8_t> data(length, 0U);
    for (std::size_t i = 0; i < length; ++i) {
        data[i] = static_cast<std::uint8_t>(seed + static_cast<std::uint8_t>(i));
    }
    (void)ApplyReadChunk(span, begin, data.data(), data.size());
    span.outcome.status = CollectionStatus::Success;
    span.observedUtc100ns = observedUtc100ns;
    return span;
}

void TestMergeReadSpans(KswordTests::Suite& s) {
    const OptionalU64 t0 = OptionalU64::of(kObserveT0);
    const OptionalU64 t1 = OptionalU64::of(kObserveT1);

    const ReadSpan first = MakeFilledSpan(0x1000ULL, 16U, 0U, t0);
    const ReadSpan second = MakeFilledSpan(0x1010ULL, 16U, 0x80U, t0);
    const MergedReadSpan merged = MergeReadSpans({first, second});
    s.expect(merged.span.range.begin == 0x1000ULL && merged.span.range.length == 32ULL,
             L"M-02 adjacent spans merge into one contiguous range");
    s.expect(merged.timing == MergeObservationTiming::SingleObservation &&
                 merged.conflictingRanges.empty() &&
                 merged.span.outcome.status == CollectionStatus::Success,
             L"M-02 a gap-free merge of spans that carry the same recorded instant is Success");
    std::uint8_t value = 0U;
    s.expect(ByteAt(merged.span, 0x1010ULL, value) && value == 0x80U,
             L"M-02 the merged buffer keeps each span's own bytes");
    s.expect(merged.byteObservedUtc100ns.size() == 32U && merged.byteObservedUtc100ns[0] == t0 &&
                 merged.byteObservedUtc100ns[31] == t0,
             L"M-05 every merged byte keeps the instant its source span was observed at");

    // M-05 的通过条件是"不会把两次不同时间的观测包装成一个原子快照"。判据必须是
    // 采集时刻，不是字节值：把同一段原样当成 5 分钟后的第二次观测（字节完全相同），
    // 也必须降级 —— 字节相同只说明这段没被改过，不说明两次读取发生在同一时刻。
    const ReadSpan sameBytesLater = MakeFilledSpan(0x1000ULL, 16U, 0U, t1);
    const MergedReadSpan twoTimes = MergeReadSpans({first, sameBytesLater});
    s.expect(twoTimes.timing == MergeObservationTiming::MultipleObservations,
             L"M-05 two spans carrying different observation instants are flagged as multi-time");
    s.expect(twoTimes.span.outcome.status != CollectionStatus::Success,
             L"M-05 a merge spanning two instants is never Success, even when the bytes are identical");
    s.expect(twoTimes.conflictingRanges.empty(),
             L"M-05 identical bytes yield no byte conflict - the downgrade comes from the timing alone");
    s.expect(twoTimes.byteObservedUtc100ns.size() == 16U &&
                 twoTimes.byteObservedUtc100ns[0] == t1,
             L"M-05 the later observation's instant is kept for the bytes it supplied");
    s.expect(!twoTimes.span.observedUtc100ns.present,
             L"M-05 a multi-time merge has no single observation instant to claim");

    // 时刻根本没记录：多段输入之间无法证明同时，同样不许 Success。
    const ReadSpan untimedA = MakeFilledSpan(0x1000ULL, 16U, 0U, OptionalU64::unset());
    const ReadSpan untimedB = MakeFilledSpan(0x1010ULL, 16U, 0x80U, OptionalU64::unset());
    const MergedReadSpan untimed = MergeReadSpans({untimedA, untimedB});
    s.expect(untimed.timing == MergeObservationTiming::ObservationTimeUnknown &&
                 untimed.span.outcome.status != CollectionStatus::Success,
             L"M-05 spans without a recorded instant cannot be claimed to be one atomic snapshot");

    // 同一地址两次读到不同值：既是时刻不同，也是内容冲突，两条理由都要报。
    ReadSpan conflicting = MakeFilledSpan(0x1000ULL, 16U, 0U, t1);
    conflicting.bytes[5] = 0xAAU;
    const MergedReadSpan conflicted = MergeReadSpans({first, conflicting});
    s.expect(conflicted.conflictingRanges.size() == 1U &&
                 conflicted.conflictingRanges[0].begin == 0x1005ULL &&
                 conflicted.conflictingRanges[0].length == 1ULL,
             L"M-02 a byte that changed between reads is reported as a conflicting range");
    s.expect(conflicted.span.outcome.status == CollectionStatus::Partial,
             L"M-05 two observations taken at different times are not packaged as one snapshot");

    // BLOCKER 负向：一个 begin+length 溢出 64 位的 span —— consistent() 为真，
    // endAddress() 为假。第一趟循环把它排除掉了，第二趟必须用完全相同的判据；
    // 否则 base = begin - lowest 会算出一个巨大值，present[target] / bytes[target]
    // 就是越界读写。
    ReadSpan overflowing;
    overflowing.range.begin = 0xFFFFFFFFFFFFFFF0ULL;
    overflowing.range.length = 32ULL;
    overflowing.bytes.assign(32U, 0xEEU);
    overflowing.present.assign(32U, true);
    overflowing.outcome.status = CollectionStatus::Success;
    overflowing.observedUtc100ns = t0;
    std::uint64_t unusedEnd = 0ULL;
    s.expect(overflowing.consistent() && !overflowing.range.endAddress(unusedEnd),
             L"M-02 the hostile fixture really is self-consistent and really does overflow its end address");

    const MergedReadSpan guarded = MergeReadSpans({first, overflowing, second});
    s.expect(guarded.span.range.begin == 0x1000ULL && guarded.span.range.length == 32ULL,
             L"M-02 an overflowing span is excluded from the merged range instead of widening it");
    s.expect(guarded.span.presentCount() == 32ULL,
             L"M-02 the merge still completes over the two well-formed spans");
    bool noStrayBytes = true;
    for (std::uint64_t address = 0x1000ULL; address < 0x1020ULL; ++address) {
        const std::uint64_t offset = address - 0x1000ULL;
        // 手算：前 16 字节来自 seed=0 的段（0x00..0x0F），后 16 来自 seed=0x80 的段
        // （0x80..0x8F）。被排除的溢出段填的是 0xEE，一个都不该出现。
        const std::uint8_t expected =
            (offset < 16ULL) ? static_cast<std::uint8_t>(offset)
                             : static_cast<std::uint8_t>(0x80ULL + (offset - 16ULL));
        std::uint8_t byte = 0U;
        if (!ByteAt(guarded.span, address, byte) || byte != expected) {
            noStrayBytes = false;
        }
    }
    s.expect(noStrayBytes,
             L"M-02 not one byte of the excluded overflowing span leaks into the merged buffer");
}

// ---------------------------------------------------------------------------
// M-10：范围校验与扫描预算
// ---------------------------------------------------------------------------
void TestScanBudget(KswordTests::Suite& s) {
    int readerCalls = 0;
    const ChunkReader counting = [&readerCalls](std::uint64_t address, std::uint8_t* out,
                                                std::size_t bytes, ChunkReadResult& outcome) {
        ++readerCalls;
        for (std::size_t i = 0; i < bytes; ++i) {
            out[i] = static_cast<std::uint8_t>((address + i) & 0xFFULL);
        }
        outcome.copied = bytes;
        outcome.status = CollectionStatus::Success;
    };

    // 空范围、溢出范围、越出已批准范围：一个字节都不读。
    // 三个请求都带上预算，好让每条用例只检验一件事。
    BoundedReadRequest empty;
    empty.requested.begin = 0x1000ULL;
    empty.requested.length = 0ULL;
    empty.budget.maxBytes = OptionalU64::of(0x1000ULL);
    const BoundedReadResult emptyResult = ReadRangeBounded(empty, counting);
    s.expect(emptyResult.validation == RangeValidation::EmptyRange &&
                 emptyResult.rejection == BoundedReadRejection::InvalidRange &&
                 emptyResult.span.outcome.status == CollectionStatus::Error,
             L"M-10 an empty range is rejected");

    BoundedReadRequest overflow;
    overflow.requested.begin = 0xFFFFFFFFFFFFFFF0ULL;
    overflow.requested.length = 0x100ULL;
    overflow.budget.maxBytes = OptionalU64::of(0x1000ULL);
    const BoundedReadResult overflowResult = ReadRangeBounded(overflow, counting);
    s.expect(overflowResult.validation == RangeValidation::Overflow &&
                 overflowResult.rejection == BoundedReadRejection::InvalidRange &&
                 overflowResult.span.outcome.status == CollectionStatus::Error,
             L"M-10 a range that overflows 64 bits is rejected");

    BoundedReadRequest outside;
    outside.requested.begin = 0x1000ULL;
    outside.requested.length = 0x4000ULL;
    outside.approved.begin = 0x1000ULL;
    outside.approved.length = 0x1000ULL;
    outside.budget.maxBytes = OptionalU64::of(0x4000ULL);
    const BoundedReadResult outsideResult = ReadRangeBounded(outside, counting);
    s.expect(outsideResult.validation == RangeValidation::ExceedsApproved &&
                 outsideResult.rejection == BoundedReadRejection::InvalidRange,
             L"M-10 a range outside the approved window is rejected");

    // M-10：没有任何预算的请求。判据不能只在"设了预算"时生效 —— 忘了设预算的
    // 调用点否则能一次读走 kMaxReadSpanBytes 的内核内存。
    BoundedReadRequest unbounded;
    unbounded.requested.begin = 0x1000ULL;
    unbounded.requested.length = 0x1000ULL;
    s.expect(!unbounded.budget.bounded(),
             L"M-10 the no-budget fixture really does carry no limit at all");
    const BoundedReadResult unboundedResult = ReadRangeBounded(unbounded, counting);
    s.expect(unboundedResult.rejection == BoundedReadRejection::NoBudget &&
                 unboundedResult.span.outcome.status == CollectionStatus::Error,
             L"M-10 a request with no budget at all is refused outright");
    s.expect(unboundedResult.span.presentCount() == 0ULL &&
                 unboundedResult.span.range.length == 0ULL,
             L"M-10 a request with no budget produces no span content whatsoever");

    // M-10：超过单次跨度上限。以前这里 validation=Ok、stop=Continue、coverage 全零，
    // 调用方会把它读成"合法范围、没命中预算、正常跑完，只是什么都没有"。
    BoundedReadRequest tooBig;
    tooBig.requested.begin = 0x10000ULL;
    tooBig.requested.length = kMaxReadSpanBytes + 1ULL;
    tooBig.budget.maxBytes = OptionalU64::of(kMaxReadSpanBytes + 1ULL);
    const BoundedReadResult tooBigResult = ReadRangeBounded(tooBig, counting);
    s.expect(tooBigResult.rejection == BoundedReadRejection::ExceedsMaxSpan &&
                 tooBigResult.span.outcome.status == CollectionStatus::Error,
             L"M-10 a span above kMaxReadSpanBytes is an explicit refusal, not a quiet empty success");
    s.expect(tooBigResult.coverage.requestedEnd ==
                     OptionalU64::of(0x10000ULL + kMaxReadSpanBytes + 1ULL) &&
                 tooBigResult.coverage.truncated == kMaxReadSpanBytes + 1ULL,
             L"F-06 a refused over-sized span still reports the requested end and the whole length as untouched");

    // M-10：逆序范围。AddressRange 用 (begin,length) 表达，endAddress() 成功后 end
    // 必然 >= begin，所以这条判据在那种表示里不可达 —— 只有接受 end 的入口能测到。
    BoundedReadRequest endpointTemplate;
    endpointTemplate.budget.maxBytes = OptionalU64::of(0x1000ULL);
    const BoundedReadResult reversedResult =
        ReadRangeBoundedFromEndpoints(0x4000ULL, 0x1000ULL, endpointTemplate, counting);
    s.expect(reversedResult.rejection == BoundedReadRejection::ReversedRange &&
                 reversedResult.validation == RangeValidation::Reversed,
             L"M-10 an end < begin range is refused as a reversed range");
    s.expect(reversedResult.span.presentCount() == 0ULL &&
                 reversedResult.span.outcome.status == CollectionStatus::Error,
             L"M-10 a reversed range produces no span content");

    s.expect(readerCalls == 0,
             L"M-10 no bytes are read at all for any of the five refusal cases");

    // 同一个入口的正向用例，证明拒绝不是靠"这个入口什么都不做"实现的。
    const BoundedReadResult forwardResult =
        ReadRangeBoundedFromEndpoints(0x1000ULL, 0x1010ULL, endpointTemplate, counting);
    s.expect(forwardResult.rejection == BoundedReadRejection::None &&
                 forwardResult.span.range.length == 0x10ULL &&
                 forwardResult.span.presentCount() == 0x10ULL,
             L"M-10 the (begin,end) entry point reads the whole range when end > begin");

    // 很小的字节预算：按上限精确停止，保留已完成部分。
    BoundedReadRequest budgeted;
    budgeted.requested.begin = 0x1000ULL;
    budgeted.requested.length = 0x3000ULL;
    budgeted.budget.maxBytes = OptionalU64::of(16ULL);
    budgeted.chunkSize = 0x1000ULL;
    const BoundedReadResult budgetResult = ReadRangeBounded(budgeted, counting);
    s.expect(budgetResult.stop == BudgetStop::BytesExhausted,
             L"M-10 the byte budget stops the scan");
    s.expect(budgetResult.span.presentCount() == 16ULL,
             L"M-10 the scan stops exactly at the byte budget rather than finishing the chunk");
    s.expect(budgetResult.span.outcome.status == CollectionStatus::Partial &&
                 budgetResult.coverage.limitHit &&
                 budgetResult.coverage.limit == OptionalU64::of(16ULL),
             L"M-10 hitting a limit yields a partial result with the limit recorded");
    s.expect(budgetResult.coverage.truncated == 0x3000ULL - 16ULL &&
                 budgetResult.coverage.failed == 0ULL,
             L"M-10 untouched bytes are truncated, not counted as failed reads");

    // 中途取消。
    BoundedReadRequest cancelled = budgeted;
    cancelled.budget.maxBytes = OptionalU64::of(0x3000ULL);
    cancelled.cancelRequested = []() -> bool { return true; };
    const BoundedReadResult cancelResult = ReadRangeBounded(cancelled, counting);
    s.expect(cancelResult.stop == BudgetStop::Cancelled &&
                 cancelResult.span.outcome.status == CollectionStatus::Partial,
             L"M-10 a cancelled scan reports Cancelled and keeps a partial result");
    s.expect(cancelResult.coverage.truncated == 0x3000ULL,
             L"M-10 a scan cancelled before the first chunk truncates the whole range");

    // 页预算与条目预算：三条上限各自独立生效。
    BoundedReadRequest paged = budgeted;
    paged.budget.maxBytes = OptionalU64::unset();
    paged.budget.maxPages = OptionalU64::of(2ULL);
    const BoundedReadResult pageResult = ReadRangeBounded(paged, counting);
    s.expect(pageResult.stop == BudgetStop::PagesExhausted &&
                 pageResult.span.presentCount() == 0x2000ULL &&
                 pageResult.coverage.truncated == 0x1000ULL,
             L"M-10 the page budget stops after the allowed number of pages");

    BoundedReadRequest itemised = budgeted;
    itemised.budget.maxBytes = OptionalU64::unset();
    itemised.budget.maxItems = OptionalU64::of(1ULL);
    const BoundedReadResult itemResult = ReadRangeBounded(itemised, counting);
    s.expect(itemResult.stop == BudgetStop::ItemsExhausted &&
                 itemResult.coverage.truncated == 0x2000ULL,
             L"M-10 the item budget stops after the allowed number of chunks");

    // 时间预算。
    BoundedReadRequest timed = budgeted;
    timed.budget.maxBytes = OptionalU64::of(0x3000ULL);
    timed.budget.maxDurationNanos = OptionalU64::of(1000ULL);
    timed.elapsedNanos = []() -> std::uint64_t { return 5000ULL; };
    const BoundedReadResult timedResult = ReadRangeBounded(timed, counting);
    s.expect(timedResult.stop == BudgetStop::TimeExhausted,
             L"M-10 the time budget stops the scan");
}

// ---------------------------------------------------------------------------
// F-05：不同的读取失败必须在结果里长得不一样
// ---------------------------------------------------------------------------
void TestReadFailureCodes(KswordTests::Suite& s) {
    auto makeFailingReader = [](CollectionStatus status, std::uint64_t code,
                                const char* text) -> ChunkReader {
        return [status, code, text](std::uint64_t, std::uint8_t*, std::size_t,
                                    ChunkReadResult& outcome) {
            outcome.copied = 0U;
            outcome.status = status;
            outcome.nativeCodeDomain = "NTSTATUS";
            outcome.nativeCode = OptionalU64::of(code);
            outcome.message = text;
        };
    };

    BoundedReadRequest failing;
    failing.requested.begin = 0x1000ULL;
    failing.requested.length = 0x1000ULL;
    failing.budget.maxBytes = OptionalU64::of(0x1000ULL);

    // 同一段范围、同样一个字节都没读到 —— 只有底层原因不同。
    const BoundedReadResult denied = ReadRangeBounded(
        failing,
        makeFailingReader(CollectionStatus::AccessDenied, 0xC0000022ULL, "STATUS_ACCESS_DENIED"));
    const BoundedReadResult terminating = ReadRangeBounded(
        failing,
        makeFailingReader(CollectionStatus::Error, 0xC000010AULL, "STATUS_PROCESS_IS_TERMINATING"));

    s.expect(denied.span.outcome.status == CollectionStatus::AccessDenied &&
                 denied.span.outcome.nativeCode == OptionalU64::of(0xC0000022ULL) &&
                 denied.span.outcome.nativeCodeDomain == "NTSTATUS" &&
                 denied.span.outcome.message == "STATUS_ACCESS_DENIED",
             L"F-05 a denied read keeps its own NTSTATUS, its domain and the source's own text");
    s.expect(terminating.span.outcome.nativeCode == OptionalU64::of(0xC000010AULL) &&
                 terminating.span.outcome.message == "STATUS_PROCESS_IS_TERMINATING",
             L"F-05 a read against an exiting process keeps its own NTSTATUS, not a generic error");
    s.expect(denied.span.outcome.nativeCode != terminating.span.outcome.nativeCode &&
                 denied.span.outcome.status != terminating.span.outcome.status &&
                 denied.span.outcome.message != terminating.span.outcome.message,
             L"F-05 two different underlying failures stay distinguishable in the result");
    s.expect(denied.span.presentCount() == 0ULL && terminating.span.presentCount() == 0ULL,
             L"M-02 a read that copied nothing marks nothing present");

    // 回调根本没给：同样必须是明确的错误，不是"空但成功"。
    const BoundedReadResult noReader = ReadRangeBounded(failing, ChunkReader{});
    s.expect(noReader.span.outcome.status == CollectionStatus::Error &&
                 !noReader.span.outcome.message.empty(),
             L"F-05 a missing chunk reader is an error with a stated reason, not an empty success");
}

// ---------------------------------------------------------------------------
// M-01：区域信息语义
// ---------------------------------------------------------------------------
RegionRecord MakeRegion(RegionEvidenceSource source, RegionType type) {
    RegionRecord record;
    record.base = OptionalU64::of(0x00000001A0000000ULL);
    record.size = OptionalU64::of(0x10000ULL);
    record.state = RegionState::Commit;
    record.type = type;
    record.protection.readable = true;
    record.protection.executable = true;
    record.protection.rawValue = OptionalU64::of(0x20ULL);  // PAGE_EXECUTE_READ
    record.allocationBase = OptionalU64::of(0x00000001A0000000ULL);
    record.allocationProtect.readable = true;
    record.allocationProtect.writable = true;
    record.source = source;
    record.owner = MakeProcess(4321ULL, 133000000000000000ULL);
    return record;
}

VadEvidence MakeVad(bool verified) {
    VadEvidence vad;
    vad.vadNodeAddress = OptionalU64::of(0xFFFFA00012345678ULL);
    vad.startingVpn = OptionalU64::of(0x1A0000ULL);
    vad.endingVpn = OptionalU64::of(0x1A000FULL);
    vad.vadFlagsRaw = OptionalU64::of(0x7ULL);
    vad.profileId = "ntoskrnl-10.0.26300.9022";
    vad.profileVerified = verified;
    return vad;
}

void TestRegionSemantics(KswordTests::Suite& s) {
    // R3 来源即使被填上 VAD 字段，也不允许显示"VAD 已验证"。
    RegionRecord fromR3 = MakeRegion(RegionEvidenceSource::R3VirtualQuery, RegionType::Private);
    fromR3.vad = MakeVad(true);
    s.expect(!VadVerified(fromR3),
             L"M-01 a region that came from VirtualQuery is never marked VAD-verified");

    RegionRecord fromVad = MakeRegion(RegionEvidenceSource::R0VadWalk, RegionType::Private);
    fromVad.vad = MakeVad(true);
    s.expect(VadVerified(fromVad),
             L"M-01 a complete VAD walk with a verified profile is marked VAD-verified");

    RegionRecord unverifiedProfile = fromVad;
    unverifiedProfile.vad.profileVerified = false;
    s.expect(!VadVerified(unverifiedProfile),
             L"M-01 an unverified profile does not produce VAD-verified");

    RegionRecord brokenInterval = fromVad;
    brokenInterval.vad.endingVpn = OptionalU64::of(0x100000ULL);  // 结束早于起始
    s.expect(!VadVerified(brokenInterval),
             L"M-01 an inverted VAD interval is treated as broken data, not as evidence");

    RegionRecord offline = MakeRegion(RegionEvidenceSource::OfflineSnapshot, RegionType::Image);
    offline.vad = MakeVad(true);
    s.expect(!VadVerified(offline),
             L"M-01 an offline snapshot row is not itself a VAD walk");

    AddressRange range;
    s.expect(RegionRange(fromR3, range) && range.begin == 0x00000001A0000000ULL &&
                 range.length == 0x10000ULL,
             L"M-01 a region with base and size yields its address range");
    RegionRecord noSize = fromR3;
    noSize.size = OptionalU64::unset();
    s.expect(!RegionRange(noSize, range),
             L"M-01 a region without a size does not fall back to zero");
}

// ---------------------------------------------------------------------------
// M-01：Commit 之外的三种状态与两种映射类型
// 只测 Commit 等于只测了一条路径：Reserved / Free / Mapped / Image 各有自己的
// 字段语义，尤其是"来源没给的字段必须 unset，不能补 0"。
// ---------------------------------------------------------------------------
void TestRegionStateVariants(KswordTests::Suite& s) {
    // Reserved：只占住了地址空间，页还没提交。VirtualQuery 在 MEM_RESERVE 上不给
    // Protect，所以 protection.rawValue 必须保持 unset —— 填 0 会被下游读成
    // "我们查过了，保护值就是 0"，那是一个凭空造出来的观测。
    RegionRecord reserved;
    reserved.base = OptionalU64::of(0x00000001B0000000ULL);
    reserved.size = OptionalU64::of(0x100000ULL);
    reserved.state = RegionState::Reserved;
    reserved.type = RegionType::Private;
    reserved.allocationBase = OptionalU64::of(0x00000001B0000000ULL);
    reserved.allocationProtect.rawValue = OptionalU64::of(0x04ULL);  // PAGE_READWRITE
    reserved.source = RegionEvidenceSource::R3VirtualQuery;
    s.expect(reserved.state == RegionState::Reserved &&
                 std::string(RegionStateName(reserved.state)) == "Reserved",
             L"M-01 a reserved region keeps the Reserved state instead of being folded into Commit");
    s.expect(!reserved.protection.rawValue.present && !reserved.protection.readable &&
                 !reserved.protection.writable && !reserved.protection.executable,
             L"M-01 a reserved region has no current page protection - rawValue stays unset, not 0");
    s.expect(reserved.allocationProtect.rawValue == OptionalU64::of(0x04ULL),
             L"M-01 the allocation protection is a field of its own, separate from the current one");
    AddressRange reservedRange;
    s.expect(RegionRange(reserved, reservedRange) &&
                 reservedRange.begin == 0x00000001B0000000ULL &&
                 reservedRange.length == 0x100000ULL,
             L"M-01 a reserved region still has a real address range");

    // Free：地址空间里的空洞。没有类型、没有分配基址、没有保护，也没有映射路径。
    RegionRecord freeRegion;
    freeRegion.base = OptionalU64::of(0x00000001C0000000ULL);
    freeRegion.size = OptionalU64::of(0x10000ULL);
    freeRegion.state = RegionState::Free;
    freeRegion.type = RegionType::Unknown;
    freeRegion.source = RegionEvidenceSource::R3VirtualQuery;
    s.expect(freeRegion.state == RegionState::Free &&
                 freeRegion.type == RegionType::Unknown &&
                 std::string(RegionTypeName(freeRegion.type)) == "Unknown",
             L"M-01 a free region has no memory type and the unknown type is spelled out as such");
    s.expect(!freeRegion.allocationBase.present && !freeRegion.protection.rawValue.present,
             L"M-01 a free region fakes neither an allocation base nor a protection value");
    s.expect(freeRegion.mappedPath.empty() && !VadVerified(freeRegion),
             L"M-01 a free region carries no mapping path and is never VAD-verified");

    // Mapped：文件映射（非映像）。路径来自 section 对象，来源是 R0 的 VAD 遍历，
    // profile 已验证 —— 只有这一整套齐全时才允许显示"VAD 已验证"。
    RegionRecord mapped;
    mapped.base = OptionalU64::of(0x00000001D0000000ULL);
    mapped.size = OptionalU64::of(0x8000ULL);
    mapped.state = RegionState::Commit;
    mapped.type = RegionType::Mapped;
    mapped.protection.readable = true;
    mapped.protection.rawValue = OptionalU64::of(0x02ULL);  // PAGE_READONLY
    mapped.allocationBase = OptionalU64::of(0x00000001D0000000ULL);
    mapped.mappedPath = "\\Device\\HarddiskVolume3\\data\\catalog.bin";
    mapped.source = RegionEvidenceSource::R0VadWalk;
    // 手算：VPN = base >> 12 = 0x1D0000；0x8000 字节 = 8 页，末页 VPN = 0x1D0007。
    mapped.vad.vadNodeAddress = OptionalU64::of(0xFFFFA000ABCDEF00ULL);
    mapped.vad.startingVpn = OptionalU64::of(0x1D0000ULL);
    mapped.vad.endingVpn = OptionalU64::of(0x1D0007ULL);
    mapped.vad.vadFlagsRaw = OptionalU64::of(0x1ULL);
    mapped.vad.profileId = "ntoskrnl-10.0.26300.9022";
    mapped.vad.profileVerified = true;
    s.expect(mapped.type == RegionType::Mapped &&
                 std::string(RegionTypeName(mapped.type)) == "Mapped",
             L"M-01 a mapped file region reports the Mapped type, distinct from Image and Private");
    s.expect(!mapped.mappedPath.empty() && mapped.protection.readable &&
                 !mapped.protection.executable &&
                 mapped.protection.rawValue == OptionalU64::of(0x02ULL),
             L"M-01 the mapped region's decoded flags agree with the raw PAGE_* value they came from");
    s.expect(VadVerified(mapped) &&
                 std::string(RegionEvidenceSourceName(mapped.source)) == "R0VadWalk",
             L"M-01 only a VAD walk with a verified profile and a complete interval is VAD-verified");

    // Image：映像映射。同样的字段，但来源是离线快照 —— 快照行不是一次 VAD 遍历。
    RegionRecord image;
    image.base = OptionalU64::of(0x00007FFAB0000000ULL);
    image.size = OptionalU64::of(0x1F0000ULL);
    image.state = RegionState::Commit;
    image.type = RegionType::Image;
    image.protection.readable = true;
    image.protection.executable = true;
    image.protection.rawValue = OptionalU64::of(0x20ULL);  // PAGE_EXECUTE_READ
    image.allocationBase = OptionalU64::of(0x00007FFAB0000000ULL);
    image.mappedPath = "\\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll";
    image.source = RegionEvidenceSource::OfflineSnapshot;
    image.vad = MakeVad(true);
    s.expect(image.type == RegionType::Image && std::string(RegionTypeName(image.type)) == "Image",
             L"M-01 an image region reports the Image type");
    s.expect(!VadVerified(image) &&
                 std::string(RegionEvidenceSourceName(image.source)) == "OfflineSnapshot",
             L"M-01 an offline snapshot row keeps its own source and is never VAD-verified");
    s.expect(image.protection.executable && image.protection.rawValue == OptionalU64::of(0x20ULL),
             L"M-01 the image region's executable flag matches the raw PAGE_EXECUTE_READ it came from");

    // base + size 回绕 64 位：没有可用的地址范围。手算：
    // 0xFFFFFFFFFFFF0000 + 0x20000 = 0x1_0000_0000_0000_0000，超出 64 位。
    RegionRecord wrapping;
    wrapping.base = OptionalU64::of(0xFFFFFFFFFFFF0000ULL);
    wrapping.size = OptionalU64::of(0x20000ULL);
    wrapping.state = RegionState::Commit;
    wrapping.type = RegionType::Private;
    AddressRange wrapped;
    s.expect(!RegionRange(wrapping, wrapped),
             L"M-01 a region whose base plus size overflows 64 bits yields no address range at all");
}

// ---------------------------------------------------------------------------
// M-07：可执行区域线索
// ---------------------------------------------------------------------------
const ExecutableRegionFinding* FindRule(const ExecutableRegionReport& report, const char* ruleId) {
    for (const ExecutableRegionFinding& finding : report.findings) {
        if (finding.ruleId == ruleId) {
            return &finding;
        }
    }
    return nullptr;
}

bool HasFact(const ExecutableRegionFinding& finding, const std::string& fact) {
    return std::find(finding.facts.begin(), finding.facts.end(), fact) != finding.facts.end();
}

bool HasOwner(const ExecutableRegionFinding& finding, const std::string& owner) {
    return std::find(finding.candidateOwners.begin(), finding.candidateOwners.end(), owner) !=
           finding.candidateOwners.end();
}

void TestExecutableRegionRules(KswordTests::Suite& s) {
    const std::string kNtdll = "\\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll";
    const std::string kKernelBase = "\\Device\\HarddiskVolume3\\Windows\\System32\\kernelbase.dll";

    // 自有 JIT 风格：private RX，没有映射路径，也没做任何比对。
    ExecutableRegionInput jit;
    jit.region = MakeRegion(RegionEvidenceSource::R3VirtualQuery, RegionType::Private);
    const ExecutableRegionReport jitReport = EvaluateExecutableRegion(jit);
    const ExecutableRegionFinding* privateRule = FindRule(jitReport, kRuleIdPrivateExecutable);
    s.expect(privateRule != nullptr, L"M-07 a private executable region produces a private-exec clue");
    if (privateRule != nullptr) {
        s.expect(!privateRule->facts.empty(),
                 L"M-07 the rule lists the facts it relied on");
        s.expect(HasFact(*privateRule, "vadVerified=false") &&
                     HasFact(*privateRule, "region.type=Private") &&
                     HasFact(*privateRule, "region.mappedPath=unknown"),
                 L"M-07 the facts include source, type and the missing mapping path");
        s.expect(privateRule->attribution == OwnerAttribution::Unknown &&
                     privateRule->candidateOwners.empty(),
                 L"M-07 an unknown owner stays unknown for a private region");
    }
    s.expect(jitReport.conclusion == AnalysisConclusion::Indeterminate,
             L"M-07 RX plus private alone is a clue, never a difference or a verdict");
    s.expect(jitReport.attribution == OwnerAttribution::Unknown,
             L"M-07 the report-level attribution is unknown without mapping evidence");

    // 已知改写的 image 区域：精确差异。
    ExecutableRegionInput tampered;
    tampered.region = MakeRegion(RegionEvidenceSource::R0VadWalk, RegionType::Image);
    tampered.region.mappedPath = kNtdll;
    tampered.region.vad = MakeVad(true);
    tampered.regionOwnerKnown = true;
    tampered.imageComparison.compared = true;
    tampered.imageComparison.outcome = CollectionOutcome::success();
    tampered.imageComparison.onDiskPath = "C:\\Windows\\System32\\ntdll.dll";
    tampered.imageComparison.relocationsApplied = true;
    AddressRange diff;
    diff.begin = 0x00007FFAB0001000ULL;
    diff.length = 0x20ULL;
    tampered.imageComparison.differingRanges.push_back(diff);

    const ExecutableRegionReport tamperReport = EvaluateExecutableRegion(tampered);
    const ExecutableRegionFinding* imageRule = FindRule(tamperReport, kRuleIdImageBytesDiffer);
    s.expect(imageRule != nullptr, L"M-07 a differing image region produces an image-diff clue");
    if (imageRule != nullptr) {
        s.expect(HasFact(*imageRule, "image.differingRange=0x00007FFAB0001000+32"),
                 L"M-07 the differing range is reported precisely");
        s.expect(HasFact(*imageRule, "image.differingRangeCount=1"),
                 L"M-07 the number of differing ranges is a listed fact");
        s.expect(imageRule->attribution == OwnerAttribution::DirectEvidence,
                 L"M-09 a mapped image with a known owner is direct evidence");
    }
    s.expect(tamperReport.conclusion == AnalysisConclusion::DifferenceObserved,
             L"M-07 a normalised byte difference against disk is a difference observed");

    // 比对做了但没差异。
    ExecutableRegionInput clean = tampered;
    clean.imageComparison.differingRanges.clear();
    s.expect(EvaluateExecutableRegion(clean).conclusion == AnalysisConclusion::NoDifferenceObserved,
             L"M-07 a completed comparison without differences is NoDifferenceObserved");

    // 差异存在但没做重定位归一化：只能是线索。
    ExecutableRegionInput unnormalised = tampered;
    unnormalised.imageComparison.relocationsApplied = false;
    s.expect(EvaluateExecutableRegion(unnormalised).conclusion == AnalysisConclusion::Indeterminate,
             L"M-07 differences without relocation normalisation stay indeterminate");

    // 比对根本没做：不能拿"没差异"顶替。
    ExecutableRegionInput notCompared;
    notCompared.region = MakeRegion(RegionEvidenceSource::R0VadWalk, RegionType::Image);
    notCompared.region.mappedPath = kNtdll;
    const ExecutableRegionReport notComparedReport = EvaluateExecutableRegion(notCompared);
    s.expect(notComparedReport.conclusion == AnalysisConclusion::NoEvidence,
             L"M-07 a comparison that never ran does not become NoDifferenceObserved");

    // 线程起始地址落在私有区域内，且归属未知。
    ExecutableRegionInput threadCase;
    threadCase.region = MakeRegion(RegionEvidenceSource::R3VirtualQuery, RegionType::Private);
    ThreadStartFact thread;
    thread.thread.process = MakeProcess(4321ULL, 133000000000000000ULL);
    thread.thread.tid = OptionalU64::of(8888ULL);
    thread.thread.createTime100ns = OptionalU64::of(133000000000100000ULL);
    thread.startAddress = OptionalU64::of(0x00000001A0001000ULL);
    thread.startAddressInsideRegion = true;
    threadCase.threads.push_back(thread);
    const ExecutableRegionReport threadReport = EvaluateExecutableRegion(threadCase);
    const ExecutableRegionFinding* threadRule = FindRule(threadReport, kRuleIdThreadOriginMismatch);
    s.expect(threadRule != nullptr,
             L"M-07 a thread starting inside an unbacked region produces a clue");
    if (threadRule != nullptr) {
        s.expect(threadRule->attribution == OwnerAttribution::Unknown &&
                     HasFact(*threadRule, "thread.startMappedPath=unknown"),
                 L"M-07 an unmapped thread start address keeps the owner unknown");
        s.expect(HasFact(*threadRule, "thread.startAddress=0x00000001A0001000"),
                 L"M-07 the thread start address is reported losslessly");
    }
    s.expect(threadReport.findings.size() == 2U,
             L"M-07 each rule contributes its own finding rather than one merged verdict");

    // M-07 分支：线程起始地址落在与区域**同一个**映射里 —— 归属一致，没有可报的事实。
    ExecutableRegionInput sameOrigin;
    sameOrigin.region = MakeRegion(RegionEvidenceSource::R0VadWalk, RegionType::Image);
    sameOrigin.region.mappedPath = kNtdll;
    sameOrigin.region.vad = MakeVad(true);
    ThreadStartFact insider;
    insider.thread.process = MakeProcess(4321ULL, 133000000000000000ULL);
    insider.thread.tid = OptionalU64::of(7777ULL);
    insider.thread.createTime100ns = OptionalU64::of(133000000000200000ULL);
    insider.startAddress = OptionalU64::of(0x00000001A0002000ULL);
    insider.startAddressInsideRegion = true;
    insider.startAddressMappedPath = kNtdll;
    sameOrigin.threads.push_back(insider);
    const ExecutableRegionReport sameOriginReport = EvaluateExecutableRegion(sameOrigin);
    s.expect(FindRule(sameOriginReport, kRuleIdThreadOriginMismatch) == nullptr,
             L"M-07 a thread whose start address maps to the same module as the region raises no mismatch clue");
    s.expect(sameOriginReport.findings.empty() &&
                 sameOriginReport.conclusion == AnalysisConclusion::NoEvidence,
             L"M-07 an agreeing thread origin leaves no finding and no conclusion to draw");

    // M-07 分支：两条路径都非空且不同 —— 哪一边才是真正的归属没有证据可判，
    // 所以是 Candidate，而且两边都必须列进候选，不能只留线程那一侧。
    ExecutableRegionInput crossModule = sameOrigin;
    crossModule.threads[0].startAddressMappedPath = kKernelBase;
    const ExecutableRegionReport crossReport = EvaluateExecutableRegion(crossModule);
    const ExecutableRegionFinding* crossRule = FindRule(crossReport, kRuleIdThreadOriginMismatch);
    s.expect(crossRule != nullptr,
             L"M-07 a thread starting in a different module than the region produces a mismatch clue");
    if (crossRule != nullptr) {
        s.expect(crossRule->attribution == OwnerAttribution::Candidate,
                 L"M-09 a start address mapped to another module is a candidate attribution, never direct");
        s.expect(crossRule->candidateOwners.size() == 2U && HasOwner(*crossRule, kKernelBase) &&
                     HasOwner(*crossRule, kNtdll),
                 L"M-09 both the thread's module and the region's module are listed as candidates");
        s.expect(HasFact(*crossRule, "thread.startMappedPath=" + kKernelBase) &&
                     HasFact(*crossRule, "region.mappedPath=" + kNtdll),
                 L"M-07 both mapping paths are listed as facts so a reader can recheck the mismatch");
    }

    // 起始地址拿不到就是拿不到 —— 而且那是"没有观测"，不是"归属不一致"。
    ExecutableRegionInput unknownStart;
    unknownStart.region = MakeRegion(RegionEvidenceSource::R3VirtualQuery, RegionType::Mapped);
    unknownStart.region.protection.executable = false;
    ThreadStartFact blind;
    blind.thread.process = MakeProcess(4321ULL, 133000000000000000ULL);
    blind.thread.tid = OptionalU64::of(9999ULL);
    unknownStart.threads.push_back(blind);
    const ExecutableRegionReport blindReport = EvaluateExecutableRegion(unknownStart);
    const ExecutableRegionFinding* blindRule = FindRule(blindReport, kRuleIdThreadOriginUnknown);
    s.expect(blindRule != nullptr && blindRule->attribution == OwnerAttribution::Unknown &&
                 HasFact(*blindRule, "thread.startAddress=unknown"),
             L"M-07 a missing thread start address is reported as unknown, not as the region base");
    s.expect(FindRule(blindReport, kRuleIdThreadOriginMismatch) == nullptr,
             L"M-07 a start address that was never collected is not reported as an origin mismatch");
    s.expect(blindRule != nullptr &&
                 blindRule->inputOutcome.status == CollectionStatus::NotCollected,
             L"F-05 the not-collected input status travels with the finding");
    s.expect(blindReport.conclusion == AnalysisConclusion::NoEvidence,
             L"F-05 findings built only on not-collected inputs leave the conclusion at NoEvidence, not Indeterminate");
}

// ---------------------------------------------------------------------------
// M-09：pool 归因三档
// ---------------------------------------------------------------------------
void TestPoolAttribution(KswordTests::Suite& s) {
    std::vector<PoolTagOwnerEntry> table;
    table.push_back({"Ntfx", "\\SystemRoot\\System32\\drivers\\ntfs.sys", "kb-2026.01"});
    table.push_back({"Ntfx", "\\SystemRoot\\System32\\drivers\\thirdparty.sys", "kb-2026.01"});
    table.push_back({"Ntfx", "\\SystemRoot\\System32\\drivers\\another.sys", "kb-2026.01"});
    table.push_back({"Solo", "\\SystemRoot\\System32\\drivers\\solo.sys", "kb-2026.01"});

    const PoolAttributionResult shared = AttributeByTag("Ntfx", table);
    s.expect(shared.attribution == OwnerAttribution::Candidate,
             L"M-09 a tag shared by several components is only a candidate");
    s.expect(shared.candidateOwners.size() == 3U,
             L"M-09 every candidate owner is listed, not just the first one");
    s.expect(!shared.allocationStackAvailable,
             L"M-09 tag attribution never claims an allocation stack");

    const PoolAttributionResult single = AttributeByTag("Solo", table);
    s.expect(single.attribution == OwnerAttribution::Candidate &&
                 single.candidateOwners.size() == 1U,
             L"M-09 a tag with one known owner is still only a candidate");

    const PoolAttributionResult noTag = AttributeByTag("", table);
    s.expect(noTag.attribution == OwnerAttribution::Unknown && noTag.candidateOwners.empty(),
             L"M-09 an allocation without a tag stays unknown");

    const PoolAttributionResult unknownTag = AttributeByTag("Zzzz", table);
    s.expect(unknownTag.attribution == OwnerAttribution::Unknown &&
                 unknownTag.candidateOwners.empty(),
             L"M-09 a tag that is not in the table stays unknown");

    PoolAllocationEvent absent;
    absent.captured = false;
    const PoolAttributionResult withoutEvent = AttributeByAllocationEvent(absent, shared);
    s.expect(withoutEvent.attribution == OwnerAttribution::Candidate &&
                 !withoutEvent.allocationStackAvailable,
             L"M-09 without a pre-captured allocation event the answer falls back to candidate");

    PoolAllocationEvent captured;
    captured.captured = true;
    captured.allocator.bootId = "boot-M";
    captured.allocator.imagePath = "\\SystemRoot\\System32\\drivers\\ntfs.sys";
    captured.allocator.pdbSignature = "RSDS-1111-2222-1";
    captured.eventUtc100ns = OptionalU64::of(133000000000500000ULL);
    captured.eventSourceId = "etw.pool.alloc";
    const PoolAttributionResult withEvent = AttributeByAllocationEvent(captured, shared);
    s.expect(withEvent.attribution == OwnerAttribution::DirectEvidence,
             L"M-09 a pre-captured allocation event with a strong identity is direct evidence");
    s.expect(withEvent.candidateOwners.size() == 1U,
             L"M-09 direct evidence names exactly the allocator it observed");

    PoolAllocationEvent weakAllocator = captured;
    weakAllocator.allocator.pdbSignature.clear();
    weakAllocator.allocator.imagePath = "unknown.sys";
    weakAllocator.allocator.timeDateStamp = OptionalU64::unset();
    weakAllocator.allocator.imageSize = OptionalU64::unset();
    const PoolAttributionResult weakEvent = AttributeByAllocationEvent(weakAllocator, shared);
    s.expect(weakEvent.attribution == OwnerAttribution::Candidate,
             L"M-09 an event whose allocator identity is too weak is not upgraded to direct evidence");
}

} // namespace

int RunMemoryEvidenceTests() {
    KswordTests::Suite suite(L"M memory evidence");
    TestFourKiBTranslation(suite);
    TestLargePages(suite);
    TestRejectedAddresses(suite);
    TestReservedBits(suite);
    TestSoftwarePte(suite);
    TestTranslationContext(suite);
    TestPartialRead(suite);
    TestMergeReadSpans(suite);
    TestScanBudget(suite);
    TestReadFailureCodes(suite);
    TestRegionSemantics(suite);
    TestRegionStateVariants(suite);
    TestExecutableRegionRules(suite);
    TestPoolAttribution(suite);
    suite.report();
    return suite.failures();
}
