#include "PageTableWalk.h"

namespace Ksword::Evidence {
namespace {

// x64 四级分页每级 9 位索引。
constexpr std::uint64_t kIndexMask = 0x1FFULL;
constexpr std::uint32_t kShiftPml4 = 39U;
constexpr std::uint32_t kShiftPdpt = 30U;
constexpr std::uint32_t kShiftPd = 21U;
constexpr std::uint32_t kShiftPt = 12U;

constexpr std::uint64_t kEntryBytes = 8ULL;

constexpr std::uint64_t kBitPresent = 1ULL << 0;
constexpr std::uint64_t kBitWritable = 1ULL << 1;
constexpr std::uint64_t kBitUser = 1ULL << 2;
constexpr std::uint64_t kBitLargePage = 1ULL << 7;   // PS
constexpr std::uint64_t kBitPrototype = 1ULL << 10;  // 软件 PTE：Prototype
constexpr std::uint64_t kBitTransition = 1ULL << 11; // 软件 PTE：Transition
constexpr std::uint64_t kBitExecuteDisable = 1ULL << 63;

// 各页大小对应的物理基址掩码（bit12/21/30 起，到 bit51 止）。
constexpr std::uint64_t kFrameMask4KiB = 0x000FFFFFFFFFF000ULL;
constexpr std::uint64_t kFrameMask2MiB = 0x000FFFFFFFE00000ULL;
constexpr std::uint64_t kFrameMask1GiB = 0x000FFFFFC0000000ULL;

// PS=1 时，页帧字段以下、PAT(bit12) 以上的位是保留位，硬件要求为 0。
// 1GiB 项：bit13..29；2MiB 项：bit13..20。
constexpr std::uint64_t kReservedLow1GiB = 0x000000003FFFE000ULL;
constexpr std::uint64_t kReservedLow2MiB = 0x00000000001FE000ULL;

// 架构上物理地址字段的最高位。bit52..62 是 ignored/protection key，不在此列。
constexpr std::uint64_t kArchAddressMask = 0x000FFFFFFFFFFFFFULL;

std::uint32_t ExtractIndex(std::uint64_t virtualAddress, std::uint32_t shift) noexcept {
    return static_cast<std::uint32_t>((virtualAddress >> shift) & kIndexMask);
}

// MAXPHYADDR 以上、bit51 以下的位掩码。
// 0 表示调用方没提供 MAXPHYADDR —— 该项检查明确不生效（结果里也会如实标成 unset），
// 而不是悄悄按某个默认值放行。>=52 时架构上本来就没有位被保留。
std::uint64_t AddressReservedMask(std::uint32_t maxPhysAddrBits) noexcept {
    if (maxPhysAddrBits == 0U) {
        return 0ULL;
    }
    std::uint32_t bits = maxPhysAddrBits;
    if (bits < 12U) {
        bits = 12U;  // 低于页大小的 MAXPHYADDR 在架构上不存在，按下限钳制
    }
    if (bits >= 52U) {
        return 0ULL;
    }
    const std::uint64_t low = (1ULL << bits) - 1ULL;
    return kArchAddressMask & ~low;
}

// 只对 present=1 的表项有意义：present=0 时其余位由 OS 自定义（M-05）。
std::uint64_t ReservedMaskForEntry(PageTableLevel level,
                                   bool largePage,
                                   const TranslateOptions& options) noexcept {
    std::uint64_t mask = AddressReservedMask(options.maxPhysAddrBits);
    switch (level) {
    case PageTableLevel::Pml4:
        // 四级分页里 PML4E 没有大页形态，bit7 是保留位。
        mask |= kBitLargePage;
        break;
    case PageTableLevel::Pdpt:
        if (!options.supports1GiBPages) {
            // Intel SDM：CPUID.80000001H:EDX.Page1GB == 0 时 PDPTE 的 bit7 是保留位，
            // 置位会触发 reserved-bit #PF。没有这条判据，解析不支持 1GiB 的机器时
            // 我们会为一个硬件根本不会接受的表项翻译出物理地址（M-04）。
            mask |= kBitLargePage;
        } else if (largePage) {
            mask |= kReservedLow1GiB;
        }
        break;
    case PageTableLevel::Pd:
        if (largePage) {
            mask |= kReservedLow2MiB;
        }
        break;
    case PageTableLevel::Pt:
        // PTE 的 bit7 是 PAT，不是 PS，不做大页判断也不算保留位。
        break;
    case PageTableLevel::None:
        break;
    }
    return mask;
}

bool ReadEntry(const PhysicalReader& reader,
               std::uint64_t physicalAddress,
               std::uint64_t& out) {
    if (!reader) {
        return false;
    }
    std::uint8_t buffer[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    if (!reader(physicalAddress, buffer, sizeof(buffer))) {
        return false;
    }
    std::uint64_t value = 0ULL;
    for (std::size_t i = 0; i < sizeof(buffer); ++i) {
        value |= static_cast<std::uint64_t>(buffer[i]) << (8U * i);
    }
    out = value;
    return true;
}

void MergePermissions(EffectivePermissions& permissions,
                      std::uint64_t entry,
                      bool first) noexcept {
    const bool writable = (entry & kBitWritable) != 0ULL;
    const bool user = (entry & kBitUser) != 0ULL;
    const bool nx = (entry & kBitExecuteDisable) != 0ULL;
    if (first) {
        permissions.writable = writable;
        permissions.userAccessible = user;
        permissions.executeDisable = nx;
        return;
    }
    // 写权限与用户可访问是逐级"与"，NX 是逐级"或" —— 与硬件一致。
    permissions.writable = permissions.writable && writable;
    permissions.userAccessible = permissions.userAccessible && user;
    permissions.executeDisable = permissions.executeDisable || nx;
}

// 走到某一级失败时的统一收尾：绝不填 physicalAddress。
void FailAt(TranslateResult& result,
            TranslationStatus status,
            PageTableLevel level,
            std::uint64_t reservedBits) {
    result.status = status;
    result.failedLevel = level;
    result.reservedBitsSet = reservedBits;
    result.physicalAddress = OptionalU64::unset();
    result.pageFrameBase = OptionalU64::unset();
    result.pageOffset = OptionalU64::unset();
}

} // namespace

const char* PagingModeName(PagingMode mode) noexcept {
    switch (mode) {
    case PagingMode::LongMode4Level: return "LongMode4Level";
    case PagingMode::Unsupported:    return "Unsupported";
    }
    return "Unsupported";
}

const char* PageTableLevelName(PageTableLevel level) noexcept {
    switch (level) {
    case PageTableLevel::None: return "None";
    case PageTableLevel::Pml4: return "PML4E";
    case PageTableLevel::Pdpt: return "PDPTE";
    case PageTableLevel::Pd:   return "PDE";
    case PageTableLevel::Pt:   return "PTE";
    }
    return "None";
}

const char* TranslationStatusName(TranslationStatus status) noexcept {
    switch (status) {
    case TranslationStatus::Translated:         return "Translated";
    case TranslationStatus::NotCanonical:       return "NotCanonical";
    case TranslationStatus::EntryNotPresent:    return "EntryNotPresent";
    case TranslationStatus::ReservedBitSet:     return "ReservedBitSet";
    case TranslationStatus::PhysicalReadFailed: return "PhysicalReadFailed";
    case TranslationStatus::UnsupportedMode:    return "UnsupportedMode";
    case TranslationStatus::ContextRejected:    return "ContextRejected";
    }
    return "UnsupportedMode";
}

const char* SoftwarePteKindName(SoftwarePteKind kind) noexcept {
    switch (kind) {
    case SoftwarePteKind::Transition: return "Transition";
    case SoftwarePteKind::Prototype:  return "Prototype";
    case SoftwarePteKind::PageFile:   return "PageFile";
    case SoftwarePteKind::DemandZero: return "DemandZero";
    case SoftwarePteKind::Zero:       return "Zero";
    case SoftwarePteKind::Unknown:    return "Unknown";
    }
    return "Unknown";
}

const char* PageSizeClassName(PageSizeClass size) noexcept {
    switch (size) {
    case PageSizeClass::Size4KiB: return "4KiB";
    case PageSizeClass::Size2MiB: return "2MiB";
    case PageSizeClass::Size1GiB: return "1GiB";
    }
    return "4KiB";
}

std::uint64_t PageSizeBytes(PageSizeClass size) noexcept {
    switch (size) {
    case PageSizeClass::Size4KiB: return 0x1000ULL;
    case PageSizeClass::Size2MiB: return 0x200000ULL;
    case PageSizeClass::Size1GiB: return 0x40000000ULL;
    }
    return 0x1000ULL;
}

bool IsCanonicalAddress48(std::uint64_t virtualAddress) noexcept {
    // 四级分页只使用低 48 位；bit47 必须符号扩展到 bit63。
    const std::uint64_t upper = virtualAddress & 0xFFFF000000000000ULL;
    if ((virtualAddress & 0x0000800000000000ULL) != 0ULL) {
        return upper == 0xFFFF000000000000ULL;
    }
    return upper == 0ULL;
}

SoftwarePteDecode DecodeSoftwarePte(std::uint64_t rawEntry) noexcept {
    SoftwarePteDecode decode;
    decode.transitionBit = (rawEntry & kBitTransition) != 0ULL;
    decode.prototypeBit = (rawEntry & kBitPrototype) != 0ULL;

    if (rawEntry == 0ULL) {
        // 全零项：从未建立过映射。它不是"页被换出"，UI 不能混用同一个文案。
        decode.kind = SoftwarePteKind::Zero;
        return decode;
    }
    if (decode.transitionBit && decode.prototypeBit) {
        // 两个编码位在已公开的软件 PTE 布局里互斥；同时置位说明我们不认识这个
        // 编码，标 Unknown 而不是硬挑一个。
        decode.kind = SoftwarePteKind::Unknown;
        return decode;
    }
    if (decode.transitionBit) {
        decode.kind = SoftwarePteKind::Transition;
        return decode;
    }
    if (decode.prototypeBit) {
        decode.kind = SoftwarePteKind::Prototype;
        return decode;
    }
    // MMPTE_SOFTWARE 里 PageFileHigh 占 bit32..63，它才是"页在分页文件里的位置"。
    // 为 0 说明这一项根本没有分页文件位置：典型的是已提交但从未触碰的 demand-zero
    // 页（例如 entry=0x20，只置了 Protection 字段 bit5..9）。以前这里把"非零且两个
    // 编码位都不置"一律判成 PageFile 并**无条件**填 pageFileNumber/pageFileOffset，
    // 等于凭空造出一个分页文件位置 —— M-05 明令禁止（不伪造观测）。
    const std::uint64_t pageFileHigh = rawEntry >> 32U;
    if (pageFileHigh == 0ULL) {
        decode.kind = SoftwarePteKind::DemandZero;
        return decode;  // 两个 OptionalU64 保持 unset
    }
    decode.kind = SoftwarePteKind::PageFile;
    decode.pageFileNumber = OptionalU64::of((rawEntry >> 1U) & 0xFULL);
    decode.pageFileOffset = OptionalU64::of(pageFileHigh);
    return decode;
}

TranslateResult TranslateVirtualAddress(std::uint64_t virtualAddress,
                                        std::uint64_t pageTableRootPhysical,
                                        const PhysicalReader& reader,
                                        const TranslateOptions& options) {
    TranslateResult result;
    result.virtualAddress = virtualAddress;
    result.mode = options.mode;
    result.supports1GiBPages = options.supports1GiBPages;
    if (options.maxPhysAddrBits != 0U) {
        // 只有调用方真的提供了 MAXPHYADDR，这项检查才算生效并被记进结果里。
        result.effectiveMaxPhysAddrBits = OptionalU64::of(options.maxPhysAddrBits);
    }

    if (options.mode != PagingMode::LongMode4Level) {
        // M-04：不支持的模式明确拒绝。LA57 五级分页本实现没有做，因此它落在这里，
        // 绝不按四级去猜 —— 猜出来的物理地址是伪造的。
        FailAt(result, TranslationStatus::UnsupportedMode, PageTableLevel::None, 0ULL);
        return result;
    }
    if (!IsCanonicalAddress48(virtualAddress)) {
        FailAt(result, TranslationStatus::NotCanonical, PageTableLevel::None, 0ULL);
        return result;
    }

    const std::uint64_t addressReserved = AddressReservedMask(options.maxPhysAddrBits);
    // 根的低 12 位在 CR3 里是 PCID/PWT/PCD，不是地址位，按架构掩掉而不是当成错误；
    // 但 MAXPHYADDR 以上的地址位置位说明这个根本身就不可能是硬件给的值。
    if ((pageTableRootPhysical & addressReserved) != 0ULL) {
        // 根不合法时一层都不该走 —— failedLevel 保持 None 表示"还没进到 PML4E"。
        FailAt(result,
               TranslationStatus::ReservedBitSet,
               PageTableLevel::None,
               pageTableRootPhysical & addressReserved);
        result.pageTableRootPhysical = OptionalU64::of(pageTableRootPhysical);
        return result;
    }
    result.pageTableRootPhysical = OptionalU64::of(pageTableRootPhysical);

    struct LevelPlan final {
        PageTableLevel level;
        std::uint32_t shift;
    };
    const LevelPlan plan[4] = {
        {PageTableLevel::Pml4, kShiftPml4},
        {PageTableLevel::Pdpt, kShiftPdpt},
        {PageTableLevel::Pd, kShiftPd},
        {PageTableLevel::Pt, kShiftPt},
    };

    std::uint64_t tableBase = pageTableRootPhysical & kFrameMask4KiB;
    bool firstLevel = true;

    for (const LevelPlan& step : plan) {
        PageTableEntryEvidence evidence;
        evidence.level = step.level;
        evidence.index = ExtractIndex(virtualAddress, step.shift);
        evidence.entryPhysicalAddress =
            tableBase + (static_cast<std::uint64_t>(evidence.index) * kEntryBytes);

        std::uint64_t raw = 0ULL;
        if (!ReadEntry(reader, evidence.entryPhysicalAddress, raw)) {
            // 读不到就是读不到。表项物理地址和索引仍然保留，UI 据此说明卡在哪一层。
            result.levels.push_back(evidence);
            FailAt(result, TranslationStatus::PhysicalReadFailed, step.level, 0ULL);
            return result;
        }
        evidence.read = true;
        evidence.rawValue = raw;
        evidence.present = (raw & kBitPresent) != 0ULL;
        // PS 位只在 PDPTE/PDE 上按大页解释；PTE 的同一位是 PAT。
        evidence.largePage = (step.level == PageTableLevel::Pdpt || step.level == PageTableLevel::Pd)
                                 ? ((raw & kBitLargePage) != 0ULL)
                                 : false;

        if (!evidence.present) {
            // M-05：非驻留项一律不产出物理地址，只解码软件 PTE 说明"为什么没有"。
            result.levels.push_back(evidence);
            result.softwarePteDecoded = true;
            result.softwarePte = DecodeSoftwarePte(raw);
            FailAt(result, TranslationStatus::EntryNotPresent, step.level, 0ULL);
            return result;
        }

        const std::uint64_t reservedMask =
            ReservedMaskForEntry(step.level, evidence.largePage, options);
        const std::uint64_t violated = raw & reservedMask;
        if (violated != 0ULL) {
            // M-04：保留位异常不是"正常映射"。此前 R0 只判 P 位，会把它当成有效映射。
            evidence.reservedBitsSet = violated;
            result.levels.push_back(evidence);
            FailAt(result, TranslationStatus::ReservedBitSet, step.level, violated);
            return result;
        }

        MergePermissions(result.permissions, raw, firstLevel);
        firstLevel = false;
        result.levels.push_back(evidence);

        if (evidence.largePage) {
            const PageSizeClass sizeClass = (step.level == PageTableLevel::Pdpt)
                                                ? PageSizeClass::Size1GiB
                                                : PageSizeClass::Size2MiB;
            if (sizeClass == PageSizeClass::Size1GiB && !options.supports1GiBPages) {
                // 双保险。上面的保留位掩码已经把这种项拦成 ReservedBitSet 了，
                // 这里再拦一次：没有 1GiB 能力就绝不产出 1GiB 物理地址，将来谁放宽
                // 了掩码也不至于让伪造的物理地址漏出去（M-04）。
                FailAt(result, TranslationStatus::ReservedBitSet, step.level, kBitLargePage);
                return result;
            }
            const std::uint64_t frameMask =
                (sizeClass == PageSizeClass::Size1GiB) ? kFrameMask1GiB : kFrameMask2MiB;
            const std::uint64_t frame = raw & frameMask;
            const std::uint64_t offset = virtualAddress & (PageSizeBytes(sizeClass) - 1ULL);
            result.pageSize = sizeClass;
            result.pageFrameBase = OptionalU64::of(frame);
            result.pageOffset = OptionalU64::of(offset);
            result.physicalAddress = OptionalU64::of(frame | offset);
            result.status = TranslationStatus::Translated;
            result.failedLevel = PageTableLevel::None;
            return result;
        }

        tableBase = raw & kFrameMask4KiB;
    }

    // 四级走完且最后一级是普通 PTE。
    const std::uint64_t frame = result.levels.back().rawValue & kFrameMask4KiB;
    const std::uint64_t offset = virtualAddress & (PageSizeBytes(PageSizeClass::Size4KiB) - 1ULL);
    result.pageSize = PageSizeClass::Size4KiB;
    result.pageFrameBase = OptionalU64::of(frame);
    result.pageOffset = OptionalU64::of(offset);
    result.physicalAddress = OptionalU64::of(frame | offset);
    result.status = TranslationStatus::Translated;
    result.failedLevel = PageTableLevel::None;
    return result;
}

// ---------------------------------------------------------------------------
// M-03 上下文
// ---------------------------------------------------------------------------

const char* ContextValidityName(ContextValidity validity) noexcept {
    switch (validity) {
    case ContextValidity::Usable:                     return "Usable";
    case ContextValidity::RejectProcessExited:        return "RejectProcessExited";
    case ContextValidity::RejectIdentityMismatch:     return "RejectIdentityMismatch";
    case ContextValidity::RejectIdentityUnverifiable: return "RejectIdentityUnverifiable";
    case ContextValidity::RejectNoPageTableRoot:      return "RejectNoPageTableRoot";
    case ContextValidity::RejectUnsupportedMode:      return "RejectUnsupportedMode";
    }
    return "RejectIdentityUnverifiable";
}

ContextValidity CheckContextUsable(const TranslationContext& saved,
                                   const LiveResolution& live) noexcept {
    // 先问身份：进程退出 / PID 复用是最主要的失效原因，也是 UI 最需要的理由。
    switch (ResolveProcessNavigation(saved.process, live)) {
    case LiveNavigationDecision::RejectObjectExited:
        return ContextValidity::RejectProcessExited;
    case LiveNavigationDecision::RejectIdentityMismatch:
        return ContextValidity::RejectIdentityMismatch;
    case LiveNavigationDecision::RejectIdentityUnverifiable:
        return ContextValidity::RejectIdentityUnverifiable;
    case LiveNavigationDecision::Allow:
        break;
    }
    if (saved.mode != PagingMode::LongMode4Level) {
        return ContextValidity::RejectUnsupportedMode;
    }
    if (!saved.pageTableRootPhysical.present) {
        // 没有页表根就没有地址空间。这里绝不回退到"用当前进程的 CR3 试试"。
        return ContextValidity::RejectNoPageTableRoot;
    }
    return ContextValidity::Usable;
}

bool ContextAllowsLiveReuse(ContextValidity validity) noexcept {
    return validity == ContextValidity::Usable;
}

bool TranslateUsingContext(const TranslationContext& context,
                           ContextValidity validity,
                           std::uint64_t virtualAddress,
                           const PhysicalReader& reader,
                           const TranslateOptions& options,
                           TranslateResult& out) {
    out = TranslateResult{};
    if (!ContextAllowsLiveReuse(validity)) {
        // 失效上下文禁止复用（M-03）。以前这里让 out 保持默认值，而默认 status 是
        // UnsupportedMode —— 于是"进程已退出"会被 UI 渲染成"分页模式不支持"，
        // 用户拿到的是一个假的拒绝理由。现在状态与理由都原样写进去。
        out.status = TranslationStatus::ContextRejected;
        out.contextRefusal = validity;
        out.virtualAddress = virtualAddress;
        out.mode = context.mode;
        // 保存下来的根照实带出去：它是历史观测的一部分，不是本次翻译的结果。
        out.pageTableRootPhysical = context.pageTableRootPhysical;
        return false;
    }
    TranslateOptions effective = options;
    effective.mode = context.mode;  // 分页模式以上下文为准，不接受调用方另给一个
    out = TranslateVirtualAddress(virtualAddress,
                                  context.pageTableRootPhysical.value,
                                  reader,
                                  effective);
    return true;
}

} // namespace Ksword::Evidence
