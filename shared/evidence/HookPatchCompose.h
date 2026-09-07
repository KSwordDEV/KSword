#pragma once

// HOOK 视图的补丁页构造 —— 纯算术层。
//
// 这一层不认识驱动、不认识 Qt、不发 IOCTL，只回答四个能在编译机上被证明的问题：
// 一页成品影子字节该长什么样、一条近跳该编码成哪五个字节、一条远跳该编码成哪
// 十四个字节、一段补丁装不装得进这一页。装视图、判前置、翻译地址那些事都在上
// 面几层，错了会有别的判据接住；这四件事错了不会报错，只会让被执行的那一页悄悄
// 变成垃圾，所以它们必须在编译机上被钉死。
//
// 为什么"成品页"必须是完整的一页：
//   驱动侧 HOOK 的**影子页才是被执行的那一份**。稳态下 primary 叶 = 真页 | R | W
//   （不给 X），翻转态 secondary 叶 = 影子页 | X（缺 execute-only 能力时静默补 R）。
//   出处 KswordARKDriver/src/features/hvm/hvm_ept_view.c:177-192。
//   所以影子页不是"补丁片段"，而是"原页字节 + 补丁"整整 4096 字节：补丁区间以外
//   每一个字节都要与原页逐位相同，否则处理器被重定向过去执行的是一页垃圾。
//
// 为什么跨页在**本版本**直接拒绝：
//   协议里一条视图恰好覆盖一页，没有 PageCount。在当前的翻转设计下把一个跨页补丁
//   拆成两条视图意味着两页的翻转彼此独立 —— 中间任何一次退出都可能让 guest 执行到
//   半条指令，两种后端下都是 fail-closed。所以越界在这一层就报出来。
//
//   **但这不是结构性不可能，别把它读成一堵墙。** 2026-09-07 对照外部实现时确认了
//   三条出路，都不在本版本里：
//     (a) 换更短的补丁形式。DdiMon 只写 1 字节 0xCC，跨页在最常用的场景下自然消失；
//         代价是要拦 #BP，而我们的异常位图恒为 0（hvm_vmcs.c:1078）。
//     (b) 把补丁点前移到上一条指令边界，让补丁整体落回同一页。
//     (c) 在调用方拆成两条单页视图成对安装/摘除。hyper-reV 就是这么做的，
//         **不需要改协议**；上面那条"两页翻转彼此独立"的反对意见在稳态泊影子侧
//         （不再每次执行都翻转）之后大部分失效。
//   要放开跨页时从 (a) 开始评估，不要从 (c) 开始。
//
// 这一层不做指令边界判定：x86 是变长指令，从一个任意偏移向前线性解码只能是启发式，
// 仓库里的 InstructionDecoder 也只有正向能力。"补丁是不是切断了一条指令"因此不在
// 这里回答，也不假装回答。
//
// 最后一条，写给任何拿它做文案的人：CLOAK/HOOK 不是安全边界。这一层只保证字节算术
// 正确，对"补丁能不能防住一个有权限的对手"不做任何承诺。

#include <array>
#include <cstdint>

namespace Ksword::Evidence {

// 一条视图恰好覆盖一页，页大小是协议常量而不是可调参数。
inline constexpr std::uint32_t kPatchPageBytes = 4096U;

// ---------------------------------------------------------------------------
// 几何：这段补丁装得进这一页吗
// ---------------------------------------------------------------------------
enum class CrossPageClassification {
    InPage,       // [pageOffset, pageOffset + patchLen) 完全落在这一页里
    CrossesPage,  // 越过页尾（或起点本身就不在页内）—— 上层必须拒绝，不许拆成两条视图
};

const char* CrossPageClassificationName(CrossPageClassification classification) noexcept;

// 纯几何判定，不看补丁内容、不看补丁是否为空。pageOffset 与 patchLen 都升到 64 位
// 再相加：两个 32 位量相加会回绕，回绕之后的小和会把一个明显越界的请求判成 InPage。
CrossPageClassification ClassifyCrossPage(std::uint32_t pageOffset,
                                          std::uint32_t patchLen) noexcept;

// ---------------------------------------------------------------------------
// 成品页
// ---------------------------------------------------------------------------
enum class PatchComposeStatus {
    Ok,
    OriginalMissing,      // 原页指针为空
    PatchMissing,         // patchLen > 0 却没给补丁指针
    CrossesPageBoundary,  // 几何越界；ClassifyCrossPage 已经给出同样的结论
    // 空补丁产出的影子页与原页逐位相同。那样一条 HOOK 视图在稳态下什么都不改变，
    // 却会让上层以为补丁装上了 —— 这是调用点的错误，不是一个合法的"恒等补丁"。
    EmptyPatch,
};

const char* PatchComposeStatusName(PatchComposeStatus status) noexcept;

struct ComposedPage final {
    // 默认是失败态，且 bytes 全零：忘了看 status 的调用点拿到的是一页明显不对的
    // 零字节，而不是一页看起来合法、实际没经过任何构造的数据。
    PatchComposeStatus status = PatchComposeStatus::OriginalMissing;
    std::array<std::uint8_t, kPatchPageBytes> bytes{};

    // 原样回显请求，拒绝时也回显 —— 上层要把"你给的是 offset X 长度 Y"写进拒绝
    // 理由里，不能反过来去问调用点自己记得的值。
    std::uint32_t patchOffset = 0;
    std::uint32_t patchLength = 0;

    bool ok() const noexcept { return status == PatchComposeStatus::Ok; }
};

// original 必须指向 kPatchPageBytes 个可读字节 —— 这是调用方的契约，本函数只能查空
// 指针，查不了长度。上层从 R-1 通道分片拼出一页之后，必须先自己确认拼够了 4096 字节。
//
// 检查顺序是固定的，并且被单测钉死：原页指针 -> 补丁指针 -> 几何 -> 空补丁。
// 几何排在空补丁之前，是为了让 ComposePage 与 ClassifyCrossPage 对同一组参数永远
// 给出一致的结论（例如 offset 5000、长度 0 两边都说越界）。
// 任何非 Ok 的返回里 bytes 保持全零，不产出"差不多能用"的半成品页。
ComposedPage ComposePage(const std::uint8_t* original,
                         std::uint32_t pageOffset,
                         const std::uint8_t* patch,
                         std::uint32_t patchLen) noexcept;

// ---------------------------------------------------------------------------
// 跳转编码
// ---------------------------------------------------------------------------
inline constexpr std::uint32_t kRel32JumpLength = 5U;      // E9 + int32
inline constexpr std::uint32_t kAbsoluteJumpLength = 14U;  // FF 25 + disp32 + 目标 8 字节

enum class JumpEncodeStatus {
    Ok,
    DisplacementOutOfRange,  // 位移装不进 int32
};

const char* JumpEncodeStatusName(JumpEncodeStatus status) noexcept;

struct Rel32Jump final {
    JumpEncodeStatus status = JumpEncodeStatus::DisplacementOutOfRange;
    std::array<std::uint8_t, kRel32JumpLength> bytes{};

    // target - (src + 5)，按模 2^64 的有符号读法。越界时也填 —— 上层要在拒绝理由里
    // 写出"位移是多少"，才能解释清楚"所以请改用 14 字节的绝对跳"。
    std::int64_t displacement = 0;

    bool ok() const noexcept { return status == JumpEncodeStatus::Ok; }
};

// 位移的基准是**下一条指令**：E9 自身占 5 字节，处理器取完整条指令之后才加位移。
// 地址算术按模 2^64 做，和硬件一致；跨越非 canonical 空洞的一对地址因此会得到一个
// 巨大的位移并被如实拒绝，而不是被折算成一个看似合理的小数字。
Rel32Jump EncodeRel32Jump(std::uint64_t srcVa, std::uint64_t targetVa) noexcept;

// FF 25 00000000 + 小端 8 字节绝对地址：RIP 相对的间接跳，disp32 为 0 表示取的就是
// 紧跟在这条指令后面的那 8 字节，因此地址常量与跳转本身同处一页，补丁不需要在别处
// 再找一块可写空间。
//
// 为什么必须提供它：内核模块之间的间距经常超过 ±2 GiB，只给近跳会让最常用的补丁
// 形式频繁失败，而失败的形式会诱使人去改别的地方绕过去。
//
// 这个编码不会失败，所以没有状态位。目标是不是 canonical、是不是可执行，都不是编码
// 器能回答的问题，上层在装之前自己判。
std::array<std::uint8_t, kAbsoluteJumpLength> EncodeAbsoluteJump(std::uint64_t targetVa) noexcept;

} // namespace Ksword::Evidence
