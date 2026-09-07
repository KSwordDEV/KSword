// HOOK 补丁页构造层（shared/evidence/HookPatchCompose.h）的离线自动测试。
//
// 被测的四个函数有一个共同特征：**算错了不会报错**。成品页少抄一个字节，装上去
// 只表现为"某个时刻机器行为怪了一下"；rel32 的位移基准少算 5，跳转会落在目标前
// 五个字节处，那里往往仍是合法指令；FF25 的 ModRM 写成别的值，指令照样能译码，
// 只是去一个凭空的地址取跳转目标；越界判定用 32 位相加，一个越界四十亿字节的请求
// 会被判成合法。这些都不是"装上去跑一次就知道"的错误，所以必须在编译机上被证明。
//
// 断言原则（与 HvmEptSwitchTests.cpp 一致）：
//   * 期望值一律**独立手算写死**，绝不从被测函数反算 —— 拿被测代码算期望值的测试
//     只能证明它自己等于自己；
//   * 架构常量写**字面量**，不写符号：f(SYMBOL) == SYMBOL 这种等式在有人把常量
//     改成另一个数时两边一起变，恒成立，一条都不会响；
//   * 边界两侧都测（恰好 4096 与 4097、+0x7FFFFFFF 与 +0x80000000、-0x80000000 与
//     -0x80000001），只测一侧的边界测试等于没测边界；
//   * 检查顺序也是判据：多个理由同时成立时返回哪一个被逐条钉死，否则将来有人调换
//     两个 if 不会有任何东西响。

#include "TestSupport.h"

#include "../shared/evidence/HookPatchCompose.h"

#include <array>
#include <cstdint>
#include <string_view>

namespace {

using namespace Ksword::Evidence;

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

using Page = std::array<std::uint8_t, 4096>;

// 原页的字节由一个与被测代码无关的算式生成，测试里重算同一个算式来对期望值。
// 步长 31 与 256 互质，所以整页 4096 个字节里没有任何一段是常量，"少抄一段"或
// "抄错了偏移"都改得动结果。
Page MakeOriginal(const std::uint8_t seed) {
    Page page{};
    for (std::uint32_t i = 0U; i < 4096U; ++i) {
        page[i] = static_cast<std::uint8_t>((i * 31U + 17U + seed) & 0xFFU);
    }
    return page;
}

std::uint8_t OriginalByte(const std::uint32_t index, const std::uint8_t seed) {
    return static_cast<std::uint8_t>((index * 31U + 17U + seed) & 0xFFU);
}

// 补丁区间以外逐字节与原页相同 —— 这就是"影子页 = 原页 + 补丁"那条不变式。
bool OutsidePatchMatchesOriginal(const ComposedPage& composed,
                                 const Page& original,
                                 const std::uint32_t offset,
                                 const std::uint32_t length) {
    for (std::uint32_t i = 0U; i < 4096U; ++i) {
        if (i >= offset && i < offset + length) {
            continue;
        }
        if (composed.bytes[i] != original[i]) {
            return false;
        }
    }
    return true;
}

bool PatchLanded(const ComposedPage& composed,
                 const std::uint8_t* patch,
                 const std::uint32_t offset,
                 const std::uint32_t length) {
    for (std::uint32_t i = 0U; i < length; ++i) {
        if (composed.bytes[offset + i] != patch[i]) {
            return false;
        }
    }
    return true;
}

bool AllZero(const std::uint8_t* bytes, const std::uint32_t length) {
    for (std::uint32_t i = 0U; i < length; ++i) {
        if (bytes[i] != 0U) {
            return false;
        }
    }
    return true;
}

// 把编码出来的 4 字节位移按小端读回一个有符号数。测试自己实现这一步，不借用被测
// 代码的任何东西，否则"编码错了、解码也照着错"会一起通过。
std::int32_t ReadDisplacement(const std::array<std::uint8_t, 5>& bytes) {
    const std::uint32_t raw = static_cast<std::uint32_t>(bytes[1]) |
                              (static_cast<std::uint32_t>(bytes[2]) << 8U) |
                              (static_cast<std::uint32_t>(bytes[3]) << 16U) |
                              (static_cast<std::uint32_t>(bytes[4]) << 24U);
    return static_cast<std::int32_t>(raw);
}

std::uint64_t ReadAbsoluteTarget(const std::array<std::uint8_t, 14>& bytes) {
    std::uint64_t value = 0ULL;
    for (std::uint32_t i = 0U; i < 8U; ++i) {
        value |= static_cast<std::uint64_t>(bytes[6U + i]) << (i * 8U);
    }
    return value;
}

// 给定位移反推目标：target = src + 5 + delta（模 2^64）。夹具用它构造样本，
// 被测函数用减法走回来，两条路互不借用。
std::uint64_t TargetForDisplacement(const std::uint64_t srcVa, const std::int64_t delta) {
    return srcVa + 5ULL + static_cast<std::uint64_t>(delta);
}

// ---------------------------------------------------------------------------
// 架构常量与协议常量：写字面量，不写符号
// ---------------------------------------------------------------------------
void TestArchitecturalLiterals(KswordTests::Suite& s) {
    // 一条视图恰好覆盖一页。这个数同时也是 addView 在 Explicit 种子下要求的影子
    // 字节数（KvmControl.cpp:1142-1150），改小一位会让每一次安装都被驱动拒绝。
    s.expect(kPatchPageBytes == 4096U, L"the patch page is exactly 4096 bytes");
    // E9 rel32 的指令长度。写成 4 会让位移基准整体前移一个字节，跳转落到目标之前
    // 一字节处 —— 那里通常仍能译码，机器不会当场报错。
    s.expect(kRel32JumpLength == 5U, L"a near jump is exactly 5 bytes");
    // FF /4 + ModRM + disp32 + 8 字节目标 = 14。
    s.expect(kAbsoluteJumpLength == 14U, L"an absolute jump is exactly 14 bytes");

    // 变量不叫 near / far：Windows 头里那两个名字仍是空宏，将来谁在这条链路上多
    // include 一个头，这个文件就会莫名其妙编不过。
    const Rel32Jump shortJump = EncodeRel32Jump(0x1000ULL, 0x1005ULL);
    // JMP rel32 的主操作码就是 0xE9（SDM Vol.2A, JMP）。0xEB 是 rel8，编码长度不同。
    s.expect(shortJump.bytes[0] == 0xE9U, L"the near jump opcode is literally 0xE9");

    const auto longJump = EncodeAbsoluteJump(0ULL);
    // FF /4 是 JMP r/m64。
    s.expect(longJump[0] == 0xFFU, L"the absolute jump opcode is literally 0xFF");
    // ModRM 0x25 = mod 00 / reg 100 / rm 101。64 位模式下 mod=00 且 rm=101 表示
    // RIP 相对寻址；写成 0x24（rm=100）会变成 SIB 寻址，写成 0x2C 会换掉 reg 域
    // 从而不再是 JMP —— 三种写法都仍是合法指令。
    s.expect(longJump[1] == 0x25U, L"the absolute jump ModRM byte is literally 0x25");

    s.expect(ComposedPage{}.bytes.size() == 4096U, L"the composed page array holds 4096 bytes");
    s.expect(Rel32Jump{}.bytes.size() == 5U, L"the near jump array holds 5 bytes");
    s.expect(longJump.size() == 14U, L"the absolute jump array holds 14 bytes");
}

// ---------------------------------------------------------------------------
// 状态名
// ---------------------------------------------------------------------------
void TestStatusNames(KswordTests::Suite& s) {
    using SV = std::string_view;
    s.expect(SV(PatchComposeStatusName(PatchComposeStatus::Ok)) == "Ok",
             L"compose status Ok has its own name");
    s.expect(SV(PatchComposeStatusName(PatchComposeStatus::OriginalMissing)) == "OriginalMissing",
             L"compose status OriginalMissing has its own name");
    s.expect(SV(PatchComposeStatusName(PatchComposeStatus::PatchMissing)) == "PatchMissing",
             L"compose status PatchMissing has its own name");
    s.expect(SV(PatchComposeStatusName(PatchComposeStatus::CrossesPageBoundary)) == "CrossesPageBoundary",
             L"compose status CrossesPageBoundary has its own name");
    s.expect(SV(PatchComposeStatusName(PatchComposeStatus::EmptyPatch)) == "EmptyPatch",
             L"compose status EmptyPatch has its own name");
    s.expect(SV(JumpEncodeStatusName(JumpEncodeStatus::Ok)) == "Ok",
             L"jump status Ok has its own name");
    s.expect(SV(JumpEncodeStatusName(JumpEncodeStatus::DisplacementOutOfRange)) == "DisplacementOutOfRange",
             L"jump status DisplacementOutOfRange has its own name");
    s.expect(SV(CrossPageClassificationName(CrossPageClassification::InPage)) == "InPage",
             L"classification InPage has its own name");
    s.expect(SV(CrossPageClassificationName(CrossPageClassification::CrossesPage)) == "CrossesPage",
             L"classification CrossesPage has its own name");

    // 名字两两不同。合并成一个名字的拒绝理由等于没有理由：UI 会把两种完全不同的
    // 错误显示成同一句话。
    const PatchComposeStatus all[] = {
        PatchComposeStatus::Ok,
        PatchComposeStatus::OriginalMissing,
        PatchComposeStatus::PatchMissing,
        PatchComposeStatus::CrossesPageBoundary,
        PatchComposeStatus::EmptyPatch,
    };
    bool distinct = true;
    for (std::uint32_t i = 0U; i < 5U; ++i) {
        for (std::uint32_t j = i + 1U; j < 5U; ++j) {
            if (SV(PatchComposeStatusName(all[i])) == SV(PatchComposeStatusName(all[j]))) {
                distinct = false;
            }
        }
    }
    s.expect(distinct, L"every compose status renders a distinct name");
}

// ---------------------------------------------------------------------------
// 几何：ClassifyCrossPage
// ---------------------------------------------------------------------------
void TestCrossPageGeometry(KswordTests::Suite& s) {
    s.expect(ClassifyCrossPage(0U, 4096U) == CrossPageClassification::InPage,
             L"a full-page patch at offset zero is in page");
    s.expect(ClassifyCrossPage(0U, 4097U) == CrossPageClassification::CrossesPage,
             L"one byte past a full page crosses");
    s.expect(ClassifyCrossPage(4095U, 1U) == CrossPageClassification::InPage,
             L"the last byte of the page is in page");
    s.expect(ClassifyCrossPage(4095U, 2U) == CrossPageClassification::CrossesPage,
             L"two bytes at the last offset cross");
    s.expect(ClassifyCrossPage(4096U, 0U) == CrossPageClassification::InPage,
             L"an empty span ending exactly at the page end is in page");
    s.expect(ClassifyCrossPage(4096U, 1U) == CrossPageClassification::CrossesPage,
             L"one byte starting at the page end crosses");
    s.expect(ClassifyCrossPage(1U, 4095U) == CrossPageClassification::InPage,
             L"a patch ending exactly at the page end is in page");
    s.expect(ClassifyCrossPage(1U, 4096U) == CrossPageClassification::CrossesPage,
             L"a full-page patch at offset one crosses");
    s.expect(ClassifyCrossPage(0U, 0U) == CrossPageClassification::InPage,
             L"an empty span at offset zero is in page");
    s.expect(ClassifyCrossPage(2048U, 2048U) == CrossPageClassification::InPage,
             L"a half page starting mid page is in page");
    s.expect(ClassifyCrossPage(2048U, 2049U) == CrossPageClassification::CrossesPage,
             L"one byte past the middle-start half page crosses");
    s.expect(ClassifyCrossPage(4097U, 0U) == CrossPageClassification::CrossesPage,
             L"an empty span starting past the page end still crosses");
    s.expect(ClassifyCrossPage(5000U, 0U) == CrossPageClassification::CrossesPage,
             L"an offset far past the page end crosses even with no bytes");

    // 32 位回绕陷阱：0xFFFFFFFF + 2 在 32 位里是 1，那会把这三条全判成 InPage。
    s.expect(ClassifyCrossPage(0xFFFFFFFFU, 2U) == CrossPageClassification::CrossesPage,
             L"a wrapping offset plus length does not fold back into the page");
    s.expect(ClassifyCrossPage(2U, 0xFFFFFFFFU) == CrossPageClassification::CrossesPage,
             L"a wrapping length does not fold back into the page");
    s.expect(ClassifyCrossPage(0xFFFFFFFFU, 0xFFFFFFFFU) == CrossPageClassification::CrossesPage,
             L"both operands at the 32-bit maximum still cross");

    // 整页扫一遍：每个起点上"恰好铺满"合法、"多一个字节"越界。
    bool exactFitAllInPage = true;
    bool oneMoreAllCrosses = true;
    bool emptyAllInPage = true;
    for (std::uint32_t offset = 0U; offset <= 4096U; ++offset) {
        if (ClassifyCrossPage(offset, 4096U - offset) != CrossPageClassification::InPage) {
            exactFitAllInPage = false;
        }
        if (ClassifyCrossPage(offset, 4096U - offset + 1U) != CrossPageClassification::CrossesPage) {
            oneMoreAllCrosses = false;
        }
        if (ClassifyCrossPage(offset, 0U) != CrossPageClassification::InPage) {
            emptyAllInPage = false;
        }
    }
    s.expect(exactFitAllInPage, L"every offset accepts the length that exactly fills the page");
    s.expect(oneMoreAllCrosses, L"every offset rejects one byte more than fills the page");
    s.expect(emptyAllInPage, L"an empty span is in page at every offset up to the page end");
}

// ---------------------------------------------------------------------------
// ComposePage 的几何与检查顺序
// ---------------------------------------------------------------------------
void TestComposeGeometryAndOrder(KswordTests::Suite& s) {
    const Page original = MakeOriginal(0U);
    const Page patch = MakeOriginal(0x5AU);
    const auto statusAt = [&](const std::uint32_t offset, const std::uint32_t length) {
        return ComposePage(original.data(), offset, patch.data(), length).status;
    };

    s.expect(statusAt(0U, 4096U) == PatchComposeStatus::Ok,
             L"a patch that exactly fills the page is accepted");
    s.expect(statusAt(0U, 4097U) == PatchComposeStatus::CrossesPageBoundary,
             L"4097 bytes at offset zero is refused");
    s.expect(statusAt(4095U, 1U) == PatchComposeStatus::Ok,
             L"a single byte at the last offset is accepted");
    s.expect(statusAt(4095U, 2U) == PatchComposeStatus::CrossesPageBoundary,
             L"two bytes at the last offset are refused");
    s.expect(statusAt(4096U, 1U) == PatchComposeStatus::CrossesPageBoundary,
             L"a patch starting at the page end is refused");
    s.expect(statusAt(0xFFFFFFFFU, 2U) == PatchComposeStatus::CrossesPageBoundary,
             L"compose refuses the 32-bit wrapping request the same way the classifier does");

    // --- 检查顺序 ---
    // 四个理由同时成立时返回哪一个是判据的一部分。没有这几条，将来有人调换两个 if
    // 不会有任何东西响，而 UI 会开始给出一个不解释真正问题的拒绝理由。
    s.expect(ComposePage(nullptr, 0U, patch.data(), 16U).status == PatchComposeStatus::OriginalMissing,
             L"a null original page is refused");
    s.expect(ComposePage(nullptr, 5000U, nullptr, 0U).status == PatchComposeStatus::OriginalMissing,
             L"the null original is reported ahead of every other defect");
    s.expect(ComposePage(original.data(), 0U, nullptr, 8U).status == PatchComposeStatus::PatchMissing,
             L"a null patch with a non-zero length is refused");
    s.expect(ComposePage(original.data(), 5000U, nullptr, 8U).status == PatchComposeStatus::PatchMissing,
             L"the null patch is reported ahead of the geometry");
    s.expect(ComposePage(original.data(), 100U, nullptr, 0U).status == PatchComposeStatus::EmptyPatch,
             L"a null patch of length zero is an empty patch rather than a missing one");
    s.expect(statusAt(100U, 0U) == PatchComposeStatus::EmptyPatch,
             L"an empty patch is refused instead of producing a page equal to the original");
    s.expect(statusAt(4096U, 0U) == PatchComposeStatus::EmptyPatch,
             L"an empty patch at the page end passes the geometry and is refused as empty");
    s.expect(statusAt(5000U, 0U) == PatchComposeStatus::CrossesPageBoundary,
             L"the geometry is reported ahead of the emptiness so both functions agree");

    // --- 回显与失败态 ---
    const ComposedPage accepted = ComposePage(original.data(), 1234U, patch.data(), 56U);
    const ComposedPage refused = ComposePage(original.data(), 4090U, patch.data(), 16U);
    s.expect(accepted.ok() && accepted.patchOffset == 1234U && accepted.patchLength == 56U,
             L"an accepted result echoes the request it was given");
    s.expect(!refused.ok() && refused.patchOffset == 4090U && refused.patchLength == 16U,
             L"a refused result echoes the request so the reason can name it");
    s.expect(refused.status == PatchComposeStatus::CrossesPageBoundary,
             L"sixteen bytes at offset 4090 cross the page end");
    s.expect(AllZero(refused.bytes.data(), 4096U),
             L"a refused compose leaves the page all zero rather than a half-built one");
    s.expect(AllZero(ComposePage(nullptr, 0U, nullptr, 0U).bytes.data(), 4096U),
             L"a refused compose with no inputs at all still leaves the page all zero");
    const ComposedPage defaulted{};
    s.expect(!defaulted.ok() && AllZero(defaulted.bytes.data(), 4096U),
             L"a default-constructed result is a failure carrying an all-zero page");
    s.expect(defaulted.status == PatchComposeStatus::OriginalMissing,
             L"the default state is a named failure rather than a silent Ok");

    // 每一条拒绝路径都必须留下一页零，尤其是 EmptyPatch：如果它退而产出一页等于
    // 原页的字节，一个忘了看 status 的调用点就会装上一条"什么都不改"的 HOOK 视图，
    // 而那条视图在稳态下不产生任何 violation，谁都看不出补丁其实没上。
    const ComposedPage empty = ComposePage(original.data(), 100U, patch.data(), 0U);
    const ComposedPage missing = ComposePage(original.data(), 100U, nullptr, 8U);
    const ComposedPage noOriginal = ComposePage(nullptr, 100U, patch.data(), 8U);
    s.expect(AllZero(empty.bytes.data(), 4096U),
             L"an empty patch leaves an all-zero page rather than a copy of the original");
    s.expect(AllZero(missing.bytes.data(), 4096U),
             L"a missing patch pointer leaves an all-zero page");
    s.expect(empty.patchOffset == 100U && empty.patchLength == 0U,
             L"the empty-patch refusal still echoes the request");
    s.expect(noOriginal.patchOffset == 100U && noOriginal.patchLength == 8U,
             L"the missing-original refusal still echoes the request");
    s.expect(!empty.ok() && !missing.ok() && !noOriginal.ok() && !refused.ok(),
             L"none of the four refusal statuses reports itself as ok");

    // 两个函数对同一组参数必须永远给出一致的结论。
    const std::uint32_t offsets[] = { 0U, 1U, 4090U, 4095U, 4096U, 4097U, 5000U, 0xFFFFFFFFU };
    const std::uint32_t lengths[] = { 0U, 1U, 2U, 5U, 14U, 4096U, 0xFFFFFFFFU };
    bool agree = true;
    for (const std::uint32_t offset : offsets) {
        for (const std::uint32_t length : lengths) {
            const bool crosses =
                ClassifyCrossPage(offset, length) == CrossPageClassification::CrossesPage;
            const bool refusedHere =
                statusAt(offset, length) == PatchComposeStatus::CrossesPageBoundary;
            if (crosses != refusedHere) {
                agree = false;
            }
        }
    }
    s.expect(agree, L"compose refuses exactly the spans the classifier calls crossing");
}

// ---------------------------------------------------------------------------
// 每一种真实补丁长度的"恰好装下"边界
// ---------------------------------------------------------------------------
void TestExactFitLengths(KswordTests::Suite& s) {
    const Page original = MakeOriginal(0U);
    const Page patch = MakeOriginal(0xA5U);
    const auto fitsOnlyAt = [&](const std::uint32_t length) {
        const std::uint32_t lastOffset = 4096U - length;
        const bool fits =
            ComposePage(original.data(), lastOffset, patch.data(), length).status ==
            PatchComposeStatus::Ok;
        const bool oneMore =
            ComposePage(original.data(), lastOffset + 1U, patch.data(), length).status ==
            PatchComposeStatus::CrossesPageBoundary;
        return fits && oneMore;
    };

    // 这张表不是随便挑的长度：1/2/4/8 是数据补丁，5 是 E9 近跳，14 是 FF25 远跳，
    // 其余是常见的函数头覆盖尺寸。每一条都钉死"最后一个合法起点"与"再往后一个字节"。
    s.expect(fitsOnlyAt(1U), L"a 1-byte patch fits only up to offset 4095");
    s.expect(fitsOnlyAt(2U), L"a 2-byte patch fits only up to offset 4094");
    s.expect(fitsOnlyAt(4U), L"a 4-byte patch fits only up to offset 4092");
    s.expect(fitsOnlyAt(5U), L"a 5-byte near jump fits only up to offset 4091");
    s.expect(fitsOnlyAt(8U), L"an 8-byte patch fits only up to offset 4088");
    s.expect(fitsOnlyAt(14U), L"a 14-byte absolute jump fits only up to offset 4082");
    s.expect(fitsOnlyAt(16U), L"a 16-byte patch fits only up to offset 4080");
    s.expect(fitsOnlyAt(32U), L"a 32-byte patch fits only up to offset 4064");
    s.expect(fitsOnlyAt(64U), L"a 64-byte patch fits only up to offset 4032");
    s.expect(fitsOnlyAt(128U), L"a 128-byte patch fits only up to offset 3968");
    s.expect(fitsOnlyAt(256U), L"a 256-byte patch fits only up to offset 3840");
    s.expect(fitsOnlyAt(512U), L"a 512-byte patch fits only up to offset 3584");
    s.expect(fitsOnlyAt(1024U), L"a 1024-byte patch fits only up to offset 3072");
    s.expect(fitsOnlyAt(2048U), L"a 2048-byte patch fits only up to offset 2048");
    s.expect(fitsOnlyAt(4095U), L"a 4095-byte patch fits only at offset 0 and 1");
    s.expect(fitsOnlyAt(4096U), L"a full-page patch fits only at offset 0");
}

// ---------------------------------------------------------------------------
// 成品页的字节
// ---------------------------------------------------------------------------
void TestComposedBytes(KswordTests::Suite& s) {
    const Page original = MakeOriginal(0U);
    const std::array<std::uint8_t, 5> patch = { 0xE9U, 0x11U, 0x22U, 0x33U, 0x44U };

    const ComposedPage mid = ComposePage(original.data(), 0x100U, patch.data(), 5U);
    s.expect(mid.ok() && mid.bytes.size() == 4096U,
             L"an accepted page is always exactly one page long");
    s.expect(PatchLanded(mid, patch.data(), 0x100U, 5U),
             L"the patch bytes land at the requested offset");
    s.expect(OutsidePatchMatchesOriginal(mid, original, 0x100U, 5U),
             L"every byte outside the patch equals the original page");
    // 期望值独立重算：偏移 0x100 之前那一个字节应当仍是原页的值。
    s.expect(mid.bytes[0xFFU] == OriginalByte(0xFFU, 0U) &&
                 mid.bytes[0x105U] == OriginalByte(0x105U, 0U),
             L"the bytes immediately around the patch are untouched");

    const ComposedPage head = ComposePage(original.data(), 0U, patch.data(), 5U);
    s.expect(head.ok() && PatchLanded(head, patch.data(), 0U, 5U),
             L"a patch at offset zero lands at the start of the page");
    s.expect(OutsidePatchMatchesOriginal(head, original, 0U, 5U),
             L"the rest of the page survives a patch at offset zero");

    const ComposedPage tail = ComposePage(original.data(), 4091U, patch.data(), 5U);
    s.expect(tail.ok() && PatchLanded(tail, patch.data(), 4091U, 5U),
             L"a patch ending exactly at the page end lands there");
    s.expect(OutsidePatchMatchesOriginal(tail, original, 4091U, 5U),
             L"the prefix survives a patch that ends at the page end");
    s.expect(tail.bytes[4095U] == 0x44U && tail.bytes[4090U] == OriginalByte(4090U, 0U),
             L"the last page byte is the patch tail and the byte before it is original");

    const Page fullPatch = MakeOriginal(0x33U);
    const ComposedPage full = ComposePage(original.data(), 0U, fullPatch.data(), 4096U);
    s.expect(full.ok() && full.bytes == fullPatch,
             L"a full-page patch replaces the page entirely");
    // 同一条全页补丁盖在另一张原页上必须得到同一页字节：这才证明"没有任何原页字节
    // 幸存"，而拿 full.bytes 与 fullPatch 再比一次只是把上一条断言换个写法。
    const Page otherBase = MakeOriginal(0x77U);
    const ComposedPage fullOverOther = ComposePage(otherBase.data(), 0U, fullPatch.data(), 4096U);
    s.expect(fullOverOther.ok() && fullOverOther.bytes == full.bytes,
             L"a full-page patch makes the result independent of the page underneath");

    // 全部 256 个字节值。uint8_t 与 char 混用的实现会在 0x80..0xFF 上出符号问题。
    std::array<std::uint8_t, 256> everyValue{};
    for (std::uint32_t i = 0U; i < 256U; ++i) {
        everyValue[i] = static_cast<std::uint8_t>(i);
    }
    const ComposedPage spread = ComposePage(original.data(), 1000U, everyValue.data(), 256U);
    s.expect(spread.ok() && PatchLanded(spread, everyValue.data(), 1000U, 256U),
             L"all 256 byte values survive the copy unchanged");
    s.expect(spread.bytes[1000U + 0x80U] == 0x80U,
             L"a high-bit byte is not sign extended on the way in");
    s.expect(spread.bytes[1000U + 0xFFU] == 0xFFU,
             L"the 0xFF byte lands as 0xFF");
    s.expect(OutsidePatchMatchesOriginal(spread, original, 1000U, 256U),
             L"a 256-byte patch leaves the remaining 3840 bytes alone");

    // 正中间：一半原页一半补丁，任何"抄了半页就停"的实现都会在这里露馅。
    const Page halfPatch = MakeOriginal(0x0FU);
    const ComposedPage half = ComposePage(original.data(), 2048U, halfPatch.data(), 2048U);
    s.expect(half.ok() && PatchLanded(half, halfPatch.data(), 2048U, 2048U),
             L"a half-page patch starting at the midpoint lands in full");
    s.expect(OutsidePatchMatchesOriginal(half, original, 2048U, 2048U),
             L"the first half of the page survives a half-page patch");
    const std::array<std::uint8_t, 2> straddle = { 0xAAU, 0xBBU };
    const ComposedPage midpoint = ComposePage(original.data(), 2047U, straddle.data(), 2U);
    s.expect(midpoint.ok() && midpoint.bytes[2047U] == 0xAAU && midpoint.bytes[2048U] == 0xBBU,
             L"a patch straddling the midpoint writes both halves");

    // 补丁字节恰好等于原页字节：这是合法输入，产出一页与原页相同的成品。它与
    // EmptyPatch 是两回事 —— 后者是"根本没给补丁"。
    std::array<std::uint8_t, 5> identity{};
    for (std::uint32_t i = 0U; i < 5U; ++i) {
        identity[i] = OriginalByte(2000U + i, 0U);
    }
    const ComposedPage same = ComposePage(original.data(), 2000U, identity.data(), 5U);
    s.expect(same.ok() && same.bytes == original,
             L"a patch equal to the original bytes yields a page equal to the original");

    // 逐偏移扫一遍单字节补丁：每一处都必须只改动那一个字节。
    const std::uint8_t single = 0xCCU;
    bool everyOffsetOk = true;
    bool everyOffsetLands = true;
    bool everyOffsetPreservesRest = true;
    for (std::uint32_t offset = 0U; offset < 4096U; ++offset) {
        const ComposedPage one = ComposePage(original.data(), offset, &single, 1U);
        if (!one.ok()) {
            everyOffsetOk = false;
        }
        if (one.bytes[offset] != single) {
            everyOffsetLands = false;
        }
        if (!OutsidePatchMatchesOriginal(one, original, offset, 1U)) {
            everyOffsetPreservesRest = false;
        }
    }
    s.expect(everyOffsetOk, L"a single-byte patch is accepted at every offset in the page");
    s.expect(everyOffsetLands, L"a single-byte patch lands at every offset in the page");
    s.expect(everyOffsetPreservesRest, L"a single-byte patch changes nothing else at any offset");

    // 决定性与无副作用。
    const Page originalCopy = original;
    const std::array<std::uint8_t, 5> patchCopy = patch;
    const ComposedPage again = ComposePage(original.data(), 0x100U, patch.data(), 5U);
    s.expect(again.bytes == mid.bytes, L"composing the same request twice yields the same page");
    s.expect(original == originalCopy, L"compose does not write through the original pointer");
    s.expect(patch == patchCopy, L"compose does not write through the patch pointer");

    // 两个只差一个种子的原页：成品页之间的差异必须与原页之间的差异完全一致。
    const Page other = MakeOriginal(1U);
    const ComposedPage fromOther = ComposePage(other.data(), 0x100U, patch.data(), 5U);
    bool differsExactlyWhereOriginalsDiffer = true;
    for (std::uint32_t i = 0U; i < 4096U; ++i) {
        if (i >= 0x100U && i < 0x105U) {
            continue;
        }
        if ((mid.bytes[i] != fromOther.bytes[i]) != (original[i] != other[i])) {
            differsExactlyWhereOriginalsDiffer = false;
        }
    }
    s.expect(differsExactlyWhereOriginalsDiffer,
             L"outside the patch the composed pages differ exactly where the originals differ");
    s.expect(PatchLanded(fromOther, patch.data(), 0x100U, 5U),
             L"the same patch lands identically on a different original page");
}

// ---------------------------------------------------------------------------
// rel32 近跳
// ---------------------------------------------------------------------------
void TestRel32Encoding(KswordTests::Suite& s) {
    // 位移 0：目标就是这条跳转之后的下一条指令。
    const Rel32Jump zero = EncodeRel32Jump(0x1000ULL, 0x1005ULL);
    const std::array<std::uint8_t, 5> zeroWant = { 0xE9U, 0x00U, 0x00U, 0x00U, 0x00U };
    s.expect(zero.ok(), L"a jump to the following instruction encodes");
    s.expect(zero.displacement == 0, L"a jump to the following instruction has displacement zero");
    s.expect(zero.bytes == zeroWant, L"a zero displacement encodes as E9 00 00 00 00");

    // 手算：next = 0xFFFFF80000001005，target - next = 0x2000 - 0x1005 = 0xFFB = 4091。
    const Rel32Jump forward = EncodeRel32Jump(0xFFFFF80000001000ULL, 0xFFFFF80000002000ULL);
    const std::array<std::uint8_t, 5> forwardWant = { 0xE9U, 0xFBU, 0x0FU, 0x00U, 0x00U };
    s.expect(forward.ok() && forward.displacement == 4091,
             L"a forward jump displacement is measured from the next instruction");
    s.expect(forward.bytes == forwardWant, L"a forward displacement of 4091 encodes as FB 0F 00 00");

    // 手算：next = 0xFFFFF80000002005，target - next = 0x1000 - 0x2005 = -0x1005 = -4101。
    // -4101 的 32 位补码是 0xFFFFEFFB，小端 FB EF FF FF。
    const Rel32Jump backward = EncodeRel32Jump(0xFFFFF80000002000ULL, 0xFFFFF80000001000ULL);
    const std::array<std::uint8_t, 5> backwardWant = { 0xE9U, 0xFBU, 0xEFU, 0xFFU, 0xFFU };
    s.expect(backward.ok() && backward.displacement == -4101,
             L"a backward jump displacement is negative and includes the instruction length");
    s.expect(backward.bytes == backwardWant, L"a displacement of -4101 encodes as FB EF FF FF");

    // 跳到自己：位移 = -5，恰好是"指令长度"这一项单独现身的地方。少算这 5 会让这
    // 条断言变成 0，而一个位移为 0 的跳转是往下走而不是原地转圈。
    const Rel32Jump selfJump = EncodeRel32Jump(0xFFFFF80000003000ULL, 0xFFFFF80000003000ULL);
    const std::array<std::uint8_t, 5> selfWant = { 0xE9U, 0xFBU, 0xFFU, 0xFFU, 0xFFU };
    s.expect(selfJump.ok() && selfJump.displacement == -5,
             L"a jump to its own address has displacement minus the instruction length");
    s.expect(selfJump.bytes == selfWant, L"a displacement of -5 encodes as FB FF FF FF");

    // ±1：符号处理最容易在这两处一起写错。
    const std::uint64_t unitSrc = 0xFFFFF80000004000ULL;
    const Rel32Jump plusOne = EncodeRel32Jump(unitSrc, unitSrc + 6ULL);
    const Rel32Jump minusOne = EncodeRel32Jump(unitSrc, unitSrc + 4ULL);
    const std::array<std::uint8_t, 5> plusOneWant = { 0xE9U, 0x01U, 0x00U, 0x00U, 0x00U };
    const std::array<std::uint8_t, 5> minusOneWant = { 0xE9U, 0xFFU, 0xFFU, 0xFFU, 0xFFU };
    s.expect(plusOne.ok() && plusOne.displacement == 1 && plusOne.bytes == plusOneWant,
             L"a displacement of +1 encodes as 01 00 00 00");
    s.expect(minusOne.ok() && minusOne.displacement == -1 && minusOne.bytes == minusOneWant,
             L"a displacement of -1 encodes as FF FF FF FF");

    // 四个字节全不相同的位移，逐字节钉死小端顺序。
    const Rel32Jump ordered = EncodeRel32Jump(0x0000000000100000ULL, 0x000000001244567DULL);
    s.expect(ordered.ok() && ordered.displacement == 0x12345678,
             L"the sample chosen for byte order really has displacement 0x12345678");
    s.expect(ordered.bytes[1] == 0x78U && ordered.bytes[2] == 0x56U &&
                 ordered.bytes[3] == 0x34U && ordered.bytes[4] == 0x12U,
             L"the displacement is stored little endian");
    // -0x12345678 的 32 位补码是 0xEDCBA988，小端 88 A9 CB ED。
    const Rel32Jump orderedNegative = EncodeRel32Jump(0x0000000020000000ULL, 0x000000000DCBA98DULL);
    s.expect(orderedNegative.ok() && orderedNegative.displacement == -0x12345678,
             L"the negative byte-order sample really has displacement -0x12345678");
    s.expect(orderedNegative.bytes[1] == 0x88U && orderedNegative.bytes[2] == 0xA9U &&
                 orderedNegative.bytes[3] == 0xCBU && orderedNegative.bytes[4] == 0xEDU,
             L"a negative displacement is stored little endian in two's complement");

    // --- 正边界 ---
    const Rel32Jump maxPositive = EncodeRel32Jump(0x0000000000010000ULL, 0x0000000080010004ULL);
    const std::array<std::uint8_t, 5> maxPositiveWant = { 0xE9U, 0xFFU, 0xFFU, 0xFFU, 0x7FU };
    s.expect(maxPositive.ok(), L"a displacement of +0x7FFFFFFF is inside the encodable range");
    s.expect(maxPositive.displacement == 0x7FFFFFFF,
             L"the positive boundary sample really has displacement +0x7FFFFFFF");
    s.expect(maxPositive.bytes == maxPositiveWant,
             L"the maximum positive displacement encodes as FF FF FF 7F");

    const Rel32Jump overPositive = EncodeRel32Jump(0x0000000000010000ULL, 0x0000000080010005ULL);
    s.expect(!overPositive.ok() &&
                 overPositive.status == JumpEncodeStatus::DisplacementOutOfRange,
             L"one byte past +0x7FFFFFFF is refused");
    s.expect(overPositive.displacement == 0x80000000LL,
             L"the refused positive displacement is reported so the reason can name it");
    s.expect(AllZero(overPositive.bytes.data(), 5U),
             L"a refused near jump leaves all five bytes zero rather than a truncated jump");

    // --- 负边界 ---
    const Rel32Jump maxNegative = EncodeRel32Jump(0x0000000100000000ULL, 0x0000000080000005ULL);
    const std::array<std::uint8_t, 5> maxNegativeWant = { 0xE9U, 0x00U, 0x00U, 0x00U, 0x80U };
    s.expect(maxNegative.ok(), L"a displacement of -0x80000000 is inside the encodable range");
    s.expect(maxNegative.displacement == -0x80000000LL,
             L"the negative boundary sample really has displacement -0x80000000");
    s.expect(maxNegative.bytes == maxNegativeWant,
             L"the most negative displacement encodes as 00 00 00 80");

    const Rel32Jump overNegative = EncodeRel32Jump(0x0000000100000000ULL, 0x0000000080000004ULL);
    s.expect(!overNegative.ok(), L"one byte past -0x80000000 is refused");
    s.expect(overNegative.displacement == -0x80000001LL,
             L"the refused negative displacement is reported exactly");
    s.expect(AllZero(overNegative.bytes.data(), 5U),
             L"a refused negative near jump also leaves all five bytes zero");

    // 模 2^64：src + 5 恰好回绕到 0，目标 0x10 的位移就是 0x10。
    const Rel32Jump wrapped = EncodeRel32Jump(0xFFFFFFFFFFFFFFFBULL, 0x0000000000000010ULL);
    const std::array<std::uint8_t, 5> wrappedWant = { 0xE9U, 0x10U, 0x00U, 0x00U, 0x00U };
    s.expect(wrapped.ok() && wrapped.bytes == wrappedWant,
             L"address arithmetic wraps modulo 2^64 exactly like the hardware does");

    // 跨越非 canonical 空洞的一对地址：位移是 0xFFFF000000000FFB，如实拒绝。
    const Rel32Jump acrossHole = EncodeRel32Jump(0x00007FFFFFFFF000ULL, 0xFFFF800000000000ULL);
    s.expect(!acrossHole.ok(),
             L"a user-to-kernel pair is refused instead of folding into a small displacement");

    const Rel32Jump defaulted{};
    s.expect(!defaulted.ok() && AllZero(defaulted.bytes.data(), 5U),
             L"a default-constructed near jump is a failure carrying zero bytes");

    // 合法位移扫一遍：编码再解码回来必须逐位相等。
    const std::int64_t legal[] = {
        0, 1, -1, 2, -2, 0x7F, -0x80, 0x100, -0x100, 0x7FFF, -0x8000,
        0x40000000LL, -0x40000000LL, 0x7FFFFFFELL, -0x7FFFFFFFLL,
        0x7FFFFFFFLL, -0x80000000LL, 0x12345678LL, -0x12345678LL,
    };
    const std::uint64_t src = 0xFFFFF80000100000ULL;
    bool allLegalOk = true;
    bool allRoundTrip = true;
    bool allOpcodes = true;
    for (const std::int64_t delta : legal) {
        const Rel32Jump jump = EncodeRel32Jump(src, TargetForDisplacement(src, delta));
        if (!jump.ok()) {
            allLegalOk = false;
        }
        if (static_cast<std::int64_t>(ReadDisplacement(jump.bytes)) != delta ||
            jump.displacement != delta) {
            allRoundTrip = false;
        }
        if (jump.bytes[0] != 0xE9U) {
            allOpcodes = false;
        }
    }
    s.expect(allLegalOk, L"every displacement inside the int32 range encodes");
    s.expect(allRoundTrip, L"every encoded displacement reads back bit for bit");
    s.expect(allOpcodes, L"every encoded near jump starts with the E9 opcode");

    // 越界位移扫一遍：全部拒绝，全部不留字节。
    const std::int64_t illegal[] = {
        0x80000000LL, 0x80000001LL, 0xFFFFFFFFLL, 0x100000000LL, 0x123456789LL,
        -0x80000001LL, -0x80000002LL, -0x100000000LL, -0x123456789LL,
    };
    bool allIllegalRefused = true;
    bool allIllegalZeroed = true;
    bool allIllegalReported = true;
    for (const std::int64_t delta : illegal) {
        const Rel32Jump jump = EncodeRel32Jump(src, TargetForDisplacement(src, delta));
        if (jump.ok() || jump.status != JumpEncodeStatus::DisplacementOutOfRange) {
            allIllegalRefused = false;
        }
        if (!AllZero(jump.bytes.data(), 5U)) {
            allIllegalZeroed = false;
        }
        if (jump.displacement != delta) {
            allIllegalReported = false;
        }
    }
    s.expect(allIllegalRefused, L"every displacement outside the int32 range is refused");
    s.expect(allIllegalZeroed, L"no refused displacement leaves any byte behind");
    s.expect(allIllegalReported, L"every refused displacement is reported at its true value");
}

// ---------------------------------------------------------------------------
// FF25 远跳
// ---------------------------------------------------------------------------
void TestAbsoluteJumpEncoding(KswordTests::Suite& s) {
    // 八个字节全不相同的目标，逐字节钉死顺序。
    const auto jump = EncodeAbsoluteJump(0x0123456789ABCDEFULL);
    s.expect(jump.size() == 14U, L"an absolute jump occupies fourteen bytes");
    s.expect(jump[0] == 0xFFU, L"byte 0 is the FF opcode");
    s.expect(jump[1] == 0x25U, L"byte 1 is the RIP-relative ModRM byte");
    s.expect(jump[2] == 0x00U, L"disp32 byte 0 is zero");
    s.expect(jump[3] == 0x00U, L"disp32 byte 1 is zero");
    s.expect(jump[4] == 0x00U, L"disp32 byte 2 is zero");
    s.expect(jump[5] == 0x00U, L"disp32 byte 3 is zero");
    s.expect(jump[6] == 0xEFU, L"target byte 0 is the least significant byte");
    s.expect(jump[7] == 0xCDU, L"target byte 1 follows in little-endian order");
    s.expect(jump[8] == 0xABU, L"target byte 2 follows in little-endian order");
    s.expect(jump[9] == 0x89U, L"target byte 3 follows in little-endian order");
    s.expect(jump[10] == 0x67U, L"target byte 4 follows in little-endian order");
    s.expect(jump[11] == 0x45U, L"target byte 5 follows in little-endian order");
    s.expect(jump[12] == 0x23U, L"target byte 6 follows in little-endian order");
    s.expect(jump[13] == 0x01U, L"target byte 7 is the most significant byte");

    // disp32 必须是 0：操作数就是紧随其后的 8 字节。任何非零值都会去别处取目标。
    s.expect(AllZero(jump.data() + 2U, 4U),
             L"the RIP-relative displacement is zero so the operand is the trailing eight bytes");

    const auto zeroTarget = EncodeAbsoluteJump(0ULL);
    const std::array<std::uint8_t, 14> zeroWant = {
        0xFFU, 0x25U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    };
    s.expect(zeroTarget == zeroWant, L"a zero target encodes as FF 25 and eight zero bytes");

    const auto allOnes = EncodeAbsoluteJump(0xFFFFFFFFFFFFFFFFULL);
    const std::array<std::uint8_t, 14> allOnesWant = {
        0xFFU, 0x25U, 0x00U, 0x00U, 0x00U, 0x00U,
        0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    };
    s.expect(allOnes == allOnesWant, L"an all-ones target fills only the trailing eight bytes");

    // 只有最高位的目标：只有第 13 字节是 0x80，其余七个地址字节全零。移位写成
    // 32 位就会在这里把高半边整个丢掉。
    const auto highBit = EncodeAbsoluteJump(0x8000000000000000ULL);
    s.expect(highBit[13] == 0x80U && AllZero(highBit.data() + 6U, 7U),
             L"a target with only the top bit set survives the full 64-bit shift");
    // 只有低 32 位的目标：高四个地址字节必须是零，不能被符号扩展成 FF。
    const auto lowHalf = EncodeAbsoluteJump(0x00000000FFFFFFFFULL);
    s.expect(lowHalf[6] == 0xFFU && lowHalf[7] == 0xFFU && lowHalf[8] == 0xFFU &&
                 lowHalf[9] == 0xFFU && AllZero(lowHalf.data() + 10U, 4U),
             L"a 32-bit target is zero extended rather than sign extended");

    // 一个真实形状的内核地址：0xFFFFF80312345678 小端是 78 56 34 12 03 F8 FF FF。
    const auto kernel = EncodeAbsoluteJump(0xFFFFF80312345678ULL);
    const std::array<std::uint8_t, 14> kernelWant = {
        0xFFU, 0x25U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x78U, 0x56U, 0x34U, 0x12U, 0x03U, 0xF8U, 0xFFU, 0xFFU,
    };
    s.expect(kernel == kernelWant, L"a kernel-shaped target encodes little endian in full");
    s.expect(ReadAbsoluteTarget(kernel) == 0xFFFFF80312345678ULL,
             L"the encoded kernel target reads back bit for bit");

    // 目标扫一遍：前六字节恒定，后八字节精确还原。
    const std::uint64_t targets[] = {
        0ULL, 1ULL, 0xFFULL, 0x100ULL, 0x80000000ULL, 0x100000000ULL,
        0x00007FFFFFFFF000ULL, 0xFFFF800000000000ULL, 0xFFFFF80000001000ULL,
        0xFFFFFFFFFFFFFFFFULL, 0x8000000000000000ULL, 0x0123456789ABCDEFULL,
    };
    bool prefixStable = true;
    bool targetsRoundTrip = true;
    for (const std::uint64_t target : targets) {
        const auto encoded = EncodeAbsoluteJump(target);
        if (encoded[0] != 0xFFU || encoded[1] != 0x25U || !AllZero(encoded.data() + 2U, 4U)) {
            prefixStable = false;
        }
        if (ReadAbsoluteTarget(encoded) != target) {
            targetsRoundTrip = false;
        }
    }
    s.expect(prefixStable, L"the six-byte prefix never depends on the target");
    s.expect(targetsRoundTrip, L"every target reads back bit for bit");

    // 两个不同目标只在后八字节上不同。
    const auto a = EncodeAbsoluteJump(0xFFFFF80000001000ULL);
    const auto b = EncodeAbsoluteJump(0xFFFFF80000002000ULL);
    bool differsOnlyInTarget = true;
    for (std::uint32_t i = 0U; i < 6U; ++i) {
        if (a[i] != b[i]) {
            differsOnlyInTarget = false;
        }
    }
    s.expect(differsOnlyInTarget && a != b,
             L"two different targets differ only in the trailing eight bytes");
}

// ---------------------------------------------------------------------------
// 两层合起来：把编码好的跳转装进一页
// ---------------------------------------------------------------------------
void TestJumpPatchesInPage(KswordTests::Suite& s) {
    const Page original = MakeOriginal(0U);
    const std::uint64_t pageVa = 0xFFFFF80000010000ULL;

    // 远跳装在最后一个合法起点上。
    const auto farJump = EncodeAbsoluteJump(0xFFFFF80312345678ULL);
    const ComposedPage farAtLast = ComposePage(original.data(), 4082U, farJump.data(), 14U);
    const ComposedPage farPastEnd = ComposePage(original.data(), 4083U, farJump.data(), 14U);
    s.expect(farAtLast.ok(), L"a 14-byte absolute jump is accepted at offset 4082");
    s.expect(PatchLanded(farAtLast, farJump.data(), 4082U, 14U),
             L"the absolute jump bytes land unchanged inside the page");
    s.expect(OutsidePatchMatchesOriginal(farAtLast, original, 4082U, 14U),
             L"the shadow page equals the original outside the absolute jump");
    s.expect(farPastEnd.status == PatchComposeStatus::CrossesPageBoundary,
             L"the same absolute jump one byte later is refused rather than split in two views");

    // 近跳：src 是补丁在页里的虚拟地址，target 在同一页之后 0x100 字节处。
    const std::uint64_t srcVa = pageVa + 4091ULL;
    const std::uint64_t targetVa = pageVa + 0x10000ULL;
    // 手算：next = pageVa + 4096 = pageVa + 0x1000，位移 = 0x10000 - 0x1000 = 0xF000。
    const Rel32Jump nearJump = EncodeRel32Jump(srcVa, targetVa);
    s.expect(nearJump.ok() && nearJump.displacement == 0xF000,
             L"a near jump from the page tail measures from the first byte of the next page");
    const ComposedPage nearAtLast = ComposePage(original.data(), 4091U, nearJump.bytes.data(), 5U);
    const ComposedPage nearPastEnd = ComposePage(original.data(), 4092U, nearJump.bytes.data(), 5U);
    s.expect(nearAtLast.ok() && PatchLanded(nearAtLast, nearJump.bytes.data(), 4091U, 5U),
             L"a 5-byte near jump is accepted at offset 4091 and lands there");
    s.expect(OutsidePatchMatchesOriginal(nearAtLast, original, 4091U, 5U),
             L"the shadow page equals the original outside the near jump");
    s.expect(nearPastEnd.status == PatchComposeStatus::CrossesPageBoundary,
             L"the same near jump one byte later is refused");

    // 影子页的不变式：与原页不同的字节数不超过补丁长度。
    std::uint32_t differing = 0U;
    for (std::uint32_t i = 0U; i < 4096U; ++i) {
        if (farAtLast.bytes[i] != original[i]) {
            ++differing;
        }
    }
    s.expect(differing <= 14U,
             L"a shadow page differs from the original in at most the patched bytes");

    // 远跳存在的理由：模块间距超过 ±2 GiB 时近跳直接没有出路。
    const std::uint64_t farTarget = pageVa + (8ULL << 30U);  // 8 GiB 之外
    const Rel32Jump tooFar = EncodeRel32Jump(srcVa, farTarget);
    const auto reachable = EncodeAbsoluteJump(farTarget);
    s.expect(!tooFar.ok(), L"a target 8 GiB away has no near-jump encoding");
    s.expect(ReadAbsoluteTarget(reachable) == farTarget,
             L"the absolute form reaches the same target the near jump could not");
    s.expect(ComposePage(original.data(), 4082U, reachable.data(), 14U).ok(),
             L"the absolute form still fits in the page it patches");

    // 近跳够得着的目标上，两种形式都可用 —— 这是上层选择的前提，不是二选一。
    const std::uint64_t nearTarget = pageVa + 0x1000ULL;
    s.expect(EncodeRel32Jump(srcVa, nearTarget).ok() &&
                 ReadAbsoluteTarget(EncodeAbsoluteJump(nearTarget)) == nearTarget,
             L"a nearby target encodes both ways so the caller really has a choice");
}

} // namespace

int RunHookPatchComposeTests() {
    KswordTests::Suite suite(L"HOOK patch compose");
    TestArchitecturalLiterals(suite);
    TestStatusNames(suite);
    TestCrossPageGeometry(suite);
    TestComposeGeometryAndOrder(suite);
    TestExactFitLengths(suite);
    TestComposedBytes(suite);
    TestRel32Encoding(suite);
    TestAbsoluteJumpEncoding(suite);
    TestJumpPatchesInPage(suite);
    suite.report();
    return suite.failures();
}
