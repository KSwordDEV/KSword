#include "HookPatchCompose.h"

namespace Ksword::Evidence {

const char* CrossPageClassificationName(CrossPageClassification classification) noexcept {
    switch (classification) {
    case CrossPageClassification::InPage:      return "InPage";
    case CrossPageClassification::CrossesPage: return "CrossesPage";
    }
    // 保守方向：认不出来的取值一律当成越界，宁可多拒绝一条补丁。
    return "CrossesPage";
}

CrossPageClassification ClassifyCrossPage(std::uint32_t pageOffset,
                                          std::uint32_t patchLen) noexcept {
    // 先各自升到 64 位再加。0xFFFFFFFF + 2 在 32 位里回绕成 1，那会把一个越界了
    // 四十亿字节的请求判成 InPage。
    const std::uint64_t end =
        static_cast<std::uint64_t>(pageOffset) + static_cast<std::uint64_t>(patchLen);
    if (end > static_cast<std::uint64_t>(kPatchPageBytes)) {
        return CrossPageClassification::CrossesPage;
    }
    return CrossPageClassification::InPage;
}

const char* PatchComposeStatusName(PatchComposeStatus status) noexcept {
    switch (status) {
    case PatchComposeStatus::Ok:                  return "Ok";
    case PatchComposeStatus::OriginalMissing:     return "OriginalMissing";
    case PatchComposeStatus::PatchMissing:        return "PatchMissing";
    case PatchComposeStatus::CrossesPageBoundary: return "CrossesPageBoundary";
    case PatchComposeStatus::EmptyPatch:          return "EmptyPatch";
    }
    return "OriginalMissing";
}

ComposedPage ComposePage(const std::uint8_t* original,
                         std::uint32_t pageOffset,
                         const std::uint8_t* patch,
                         std::uint32_t patchLen) noexcept {
    ComposedPage result;
    // 回显放在最前面：下面每一条拒绝路径都要带着请求参数出去。
    result.patchOffset = pageOffset;
    result.patchLength = patchLen;

    if (original == nullptr) {
        result.status = PatchComposeStatus::OriginalMissing;
        return result;
    }
    // patchLen == 0 时空指针不算错 —— 那是"没有补丁"，由下面的 EmptyPatch 说明。
    if (patch == nullptr && patchLen != 0U) {
        result.status = PatchComposeStatus::PatchMissing;
        return result;
    }
    if (ClassifyCrossPage(pageOffset, patchLen) == CrossPageClassification::CrossesPage) {
        result.status = PatchComposeStatus::CrossesPageBoundary;
        return result;
    }
    if (patchLen == 0U) {
        result.status = PatchComposeStatus::EmptyPatch;
        return result;
    }

    // 先整页照抄原字节，再覆盖补丁区间。顺序反过来（先写补丁再抄原页）会把补丁盖掉，
    // 而那种错误产出的仍是一页"看起来像原页"的合法数据，装上去只会表现为补丁没生效。
    for (std::uint32_t i = 0U; i < kPatchPageBytes; ++i) {
        result.bytes[i] = original[i];
    }
    for (std::uint32_t i = 0U; i < patchLen; ++i) {
        result.bytes[pageOffset + i] = patch[i];
    }
    result.status = PatchComposeStatus::Ok;
    return result;
}

const char* JumpEncodeStatusName(JumpEncodeStatus status) noexcept {
    switch (status) {
    case JumpEncodeStatus::Ok:                     return "Ok";
    case JumpEncodeStatus::DisplacementOutOfRange: return "DisplacementOutOfRange";
    }
    return "DisplacementOutOfRange";
}

Rel32Jump EncodeRel32Jump(std::uint64_t srcVa, std::uint64_t targetVa) noexcept {
    Rel32Jump result;

    // 与硬件一致地按模 2^64 做：srcVa + 5 允许回绕，两个地址相减也允许回绕。
    const std::uint64_t nextVa = srcVa + static_cast<std::uint64_t>(kRel32JumpLength);
    const std::uint64_t delta = targetVa - nextVa;
    // C++20 起无符号到有符号的转换就是二进制补码的位模式重解释，没有实现定义行为。
    result.displacement = static_cast<std::int64_t>(delta);

    // 可编码的充要条件：delta 的低 32 位符号扩展回去等于 delta 本身。写成两段区间是
    // 因为这样两侧边界都摆在明处：+0x7FFFFFFF 与 -0x80000000 都是**合法**的。
    constexpr std::uint64_t kPositiveLimit = 0x000000007FFFFFFFULL;
    constexpr std::uint64_t kNegativeLimit = 0xFFFFFFFF80000000ULL;
    if (delta > kPositiveLimit && delta < kNegativeLimit) {
        result.status = JumpEncodeStatus::DisplacementOutOfRange;
        return result;  // bytes 保持全零，不产出一条位移被截断的跳转
    }

    const std::uint32_t encoded = static_cast<std::uint32_t>(delta & 0xFFFFFFFFULL);
    result.bytes[0] = 0xE9U;  // JMP rel32
    result.bytes[1] = static_cast<std::uint8_t>(encoded & 0xFFU);
    result.bytes[2] = static_cast<std::uint8_t>((encoded >> 8U) & 0xFFU);
    result.bytes[3] = static_cast<std::uint8_t>((encoded >> 16U) & 0xFFU);
    result.bytes[4] = static_cast<std::uint8_t>((encoded >> 24U) & 0xFFU);
    result.status = JumpEncodeStatus::Ok;
    return result;
}

std::array<std::uint8_t, kAbsoluteJumpLength> EncodeAbsoluteJump(std::uint64_t targetVa) noexcept {
    std::array<std::uint8_t, kAbsoluteJumpLength> bytes{};
    bytes[0] = 0xFFU;  // JMP r/m64（/4）
    // ModRM = 0x25：mod=00、reg=100（/4 选中 JMP）、rm=101。在 64 位模式下 mod=00
    // 且 rm=101 的含义是 RIP 相对寻址，而不是"绝对地址 disp32"——这一条写错的话
    // 指令仍然合法，只是会去一个 32 位地址取跳转目标，跳到哪里全凭运气。
    bytes[1] = 0x25U;
    // disp32 = 0：操作数就是紧跟在这 6 字节后面的 8 字节，地址常量因此与跳转同页。
    bytes[2] = 0x00U;
    bytes[3] = 0x00U;
    bytes[4] = 0x00U;
    bytes[5] = 0x00U;
    for (std::uint32_t i = 0U; i < 8U; ++i) {
        bytes[6U + i] = static_cast<std::uint8_t>((targetVa >> (i * 8U)) & 0xFFULL);
    }
    return bytes;
}

} // namespace Ksword::Evidence
