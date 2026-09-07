#pragma once

// M 模块：离线可测的 x64 四级页表解析核。
//
// 这一层不认识 Windows、不认识驱动，只认识"给我一个物理页读取回调，我按 Intel
// SDM 的 4 级分页规则逐层解析"。同一份判据因此既能被离线夹具驱动（用一块
// std::vector<uint8_t> 冒充物理内存），也能被真实 R0 读取路径驱动。
//
// 对应验收：
//   M-03 VA 翻译上下文（进程实例 + 页表根来源 + 时间 + 分页模式；失效上下文禁用）
//   M-04 分页边界与大页（4KiB / 2MiB / 1GiB、canonical、缺项、保留位异常）
//   M-05 非驻留与观测副作用（过渡态 / 原型 / PageFile 软件 PTE 区分）
//
// 硬规则，任何时候都不放宽：
//   * 非 canonical、缺项、保留位异常、读失败 —— 一律不产出物理地址。
//     "不伪造物理地址"（M-04）意味着 physicalAddress 保持 unset，而不是填 0。
//   * present=0 的表项其余位是软件自定义的，不能按硬件字段解读，因此保留位
//     校验只对 present=1 的项做。
//   * 五级分页（LA57）本实现不支持。不支持就是 UnsupportedMode，绝不退化成
//     "按四级猜一下"（M-04：不支持模式明确拒绝）。

#include "LiveNavigation.h"
#include "LosslessValue.h"
#include "ObjectIdentity.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace Ksword::Evidence {

// 物理内存读取回调。返回 false 表示该物理地址读不到（未映射 / 越界 / 拒绝）。
// 离线夹具与真实驱动共用这一个签名，解析核因此不需要知道自己跑在哪一侧。
using PhysicalReader =
    std::function<bool(std::uint64_t physAddr, std::uint8_t* out, std::size_t bytes)>;

// ---------------------------------------------------------------------------
// M-04：分页模式。只声明支持 x64 四级分页。
// ---------------------------------------------------------------------------
enum class PagingMode {
    LongMode4Level,  // IA-32e 4 级分页（PML4 -> PDPT -> PD -> PT）
    Unsupported,     // 其它一切：LA57 五级、PAE、32 位非 PAE、未知硬件
};

const char* PagingModeName(PagingMode mode) noexcept;

enum class PageTableLevel {
    None,   // 还没进到任何一级（非 canonical / 模式不支持 / 根本身非法）
    Pml4,
    Pdpt,
    Pd,
    Pt,
};

const char* PageTableLevelName(PageTableLevel level) noexcept;

enum class TranslationStatus {
    Translated,          // 逐层走通，physicalAddress 有效
    NotCanonical,        // VA 不满足 48 位符号扩展规则
    EntryNotPresent,     // 某一级 P=0；failedLevel 指出是哪一级
    ReservedBitSet,      // 某一级 present 项置了保留位；reservedBitsSet 给出具体位
    PhysicalReadFailed,  // 某一级的表项物理地址读不到
    UnsupportedMode,     // 分页模式不是 LongMode4Level
    // M-03：上下文失效，根本没发起翻译。真实理由在 TranslateResult::contextRefusal。
    // 这一档必须和 UnsupportedMode 分开：把"进程已退出"渲染成"分页模式不支持"，
    // 是在给用户一个假的拒绝理由。
    ContextRejected,
};

const char* TranslationStatusName(TranslationStatus status) noexcept;

// M-05：present=0 时表项的其余位由操作系统自定义。这里按 Windows 软件 PTE 的
// 公开编码给出分类；分不出来就是 Unknown，不猜。
enum class SoftwarePteKind {
    Transition,  // bit11=1 且 bit10=0：页仍在过渡链表（standby/modified），未被回收
    Prototype,   // bit10=1：指向 prototype PTE
    // 上面两位都不置、且 PageFileHigh(bit32..63) 非零：页确实在分页文件里，
    // 此时才按页文件号(bit1..4)+页内偏移(bit32..63)解读。
    PageFile,
    // 非全零、上面两位都不置、但 PageFileHigh==0：MMPTE_SOFTWARE 里只填了
    // Protection 一类字段（例如 entry=0x20），是已提交但从未触碰的 demand-zero 页。
    // 它在分页文件里根本没有位置 —— 绝不为它编造页文件号/偏移（M-05）。
    DemandZero,
    Zero,        // 表项全零：从未建立过映射（未提交）
    Unknown,     // 编码互斥位同时置位一类的情况；不硬套一个分类
};

const char* SoftwarePteKindName(SoftwarePteKind kind) noexcept;

enum class PageSizeClass {
    Size4KiB,
    Size2MiB,  // PDE.PS=1
    Size1GiB,  // PDPTE.PS=1
};

const char* PageSizeClassName(PageSizeClass size) noexcept;
std::uint64_t PageSizeBytes(PageSizeClass size) noexcept;

// ---------------------------------------------------------------------------
// 逐层证据。UI 要能展开"这一级读的是哪个物理地址、读到了什么、用的哪个索引"，
// 所以三样都必须保留，不能只留最终结果。
// ---------------------------------------------------------------------------
struct PageTableEntryEvidence final {
    PageTableLevel level = PageTableLevel::None;
    std::uint32_t index = 0;                    // 该级的 9 位索引（0..511）
    std::uint64_t entryPhysicalAddress = 0;     // 表项自身所在的物理地址
    std::uint64_t rawValue = 0;                 // 原始 64 位值；仅当 read 为真时有意义
    bool read = false;                          // 是否真的读到了 rawValue
    bool present = false;                       // bit0
    bool largePage = false;                     // bit7（只在 PDPTE/PDE 上按大页解释）
    std::uint64_t reservedBitsSet = 0;          // 违反保留位规则的位掩码，0 表示无
};

// M-05：非驻留项的解码结果。任何字段都不产出物理地址。
struct SoftwarePteDecode final {
    SoftwarePteKind kind = SoftwarePteKind::Unknown;
    bool transitionBit = false;     // bit11
    bool prototypeBit = false;      // bit10
    // 只有 PageFile 分类下才有值。其余分类一律保持 unset —— 填 present=1 value=0
    // 等于凭空造出一个"分页文件位置"，M-05 明令禁止。
    OptionalU64 pageFileNumber;     // bit1..4
    OptionalU64 pageFileOffset;     // bit32..63，单位为页
};

// 逐层与运算后的有效权限。只有 Translated 时才有意义。
struct EffectivePermissions final {
    bool writable = false;        // 各级 bit1 的与
    bool userAccessible = false;  // 各级 bit2 的与
    bool executeDisable = false;  // 各级 bit63 的或
};

struct TranslateOptions final {
    PagingMode mode = PagingMode::LongMode4Level;
    // MAXPHYADDR（CPUID.80000008H:EAX[7:0]）。硬件上物理地址字段以上、bit51 以下的
    // 位必须为 0，超出即保留位异常。
    // 0 表示"调用方没提供"：该项检查明确不生效，并在 TranslateResult 里如实标成
    // unset。以前默认 52，而 52 的保留掩码恰好是 0 —— 于是默认配置下这条判据悄悄
    // 失效，结果里却看不出它没跑过。默认改成"未知"，不再假装做过检查。
    std::uint32_t maxPhysAddrBits = 0;
    // CPUID.80000001H:EDX[26]（Page1GB）。为 false 时 PDPTE 的 bit7 是**保留位**，
    // 置位会触发 reserved-bit #PF。所以解析不支持 1GiB 的机器（或其离线转储）时，
    // 绝不能把该位当大页解释并翻译出物理地址（M-04）。默认 false：宁可多拒绝。
    bool supports1GiBPages = false;
};

// ---------------------------------------------------------------------------
// M-03：上下文有效性。
// TranslateResult 要把"上下文为什么被拒"原样带出去，所以这一组判据必须定义在
// TranslateResult 之前；真正的上下文结构在本文件末尾的 M-03 小节。
// ---------------------------------------------------------------------------
enum class ContextValidity {
    Usable,                      // 现场身份确认一致，可以继续翻译
    RejectProcessExited,         // 进程已退出：只能看历史观测
    RejectIdentityMismatch,      // 同 PID 不同实例（PID 复用）
    RejectIdentityUnverifiable,  // 身份信息不足以确认，不允许当成同一个进程
    RejectNoPageTableRoot,       // 上下文里没有页表根
    RejectUnsupportedMode,       // 分页模式不是本实现支持的四级
};

const char* ContextValidityName(ContextValidity validity) noexcept;

struct TranslateResult final {
    TranslationStatus status = TranslationStatus::UnsupportedMode;
    PagingMode mode = PagingMode::Unsupported;
    std::uint64_t virtualAddress = 0;
    OptionalU64 pageTableRootPhysical;

    // 按 PML4E -> PDPTE -> PDE -> PTE 顺序，只包含实际走到的层级。
    std::vector<PageTableEntryEvidence> levels;

    PageTableLevel failedLevel = PageTableLevel::None;
    std::uint64_t reservedBitsSet = 0;   // status==ReservedBitSet 时的具体位

    PageSizeClass pageSize = PageSizeClass::Size4KiB;
    OptionalU64 pageFrameBase;   // 页帧物理基址；只有 Translated 才 present
    OptionalU64 pageOffset;      // 页内偏移；位宽随页大小变化
    OptionalU64 physicalAddress; // 只有 Translated 才 present —— 其余状态一律 unset

    bool softwarePteDecoded = false;  // status==EntryNotPresent 时为真
    SoftwarePteDecode softwarePte;

    EffectivePermissions permissions;

    // 本次实际生效的 MAXPHYADDR。unset 表示调用方没提供，该项保留位检查**未生效**。
    // 导出与复核据此知道"这条判据这次没跑"，而不是以为它跑过并且通过了（M-04）。
    OptionalU64 effectiveMaxPhysAddrBits;
    // 本次按哪种 1GiB 能力解释 PDPTE.bit7。false 时该位被当成保留位。
    bool supports1GiBPages = false;

    // status==ContextRejected 时的真实拒绝理由（M-03）；其余情况保持 Usable。
    ContextValidity contextRefusal = ContextValidity::Usable;
};

// 核心入口。reader 为空、根地址非法、任一级失败都会得到明确状态而不是猜测结果。
TranslateResult TranslateVirtualAddress(std::uint64_t virtualAddress,
                                        std::uint64_t pageTableRootPhysical,
                                        const PhysicalReader& reader,
                                        const TranslateOptions& options = TranslateOptions{});

// 48 位 canonical 判据，单独暴露供 UI 在发起翻译前先给出理由。
bool IsCanonicalAddress48(std::uint64_t virtualAddress) noexcept;

// M-05：单独解码一个 present=0 的表项。UI 在展示"为什么没有物理地址"时直接用它。
SoftwarePteDecode DecodeSoftwarePte(std::uint64_t rawEntry) noexcept;

// ---------------------------------------------------------------------------
// M-03：翻译上下文。
// 一次翻译的结果只在"同一个进程实例 + 同一个页表根 + 同一种分页模式"下有意义。
// 进程退出或 PID 被复用之后，保存下来的上下文只能作为历史观测展示。
// ---------------------------------------------------------------------------
struct TranslationContext final {
    ProcessInstanceId process;
    OptionalU64 pageTableRootPhysical;  // CR3 / DirectoryTableBase / dump 头
    OptionalU64 observedUtc100ns;       // 采集时刻；缺失即 unset，不补当前时间
    PagingMode mode = PagingMode::Unsupported;
    std::string rootSource;             // 根从哪来，例如 "KPROCESS.DirectoryTableBase"
};

// 复用 LiveNavigation 的进程身份判据，不另造一套 PID 比对。
ContextValidity CheckContextUsable(const TranslationContext& saved,
                                   const LiveResolution& live) noexcept;

// 只有 Usable 才允许把上下文用于新的现场翻译。
bool ContextAllowsLiveReuse(ContextValidity validity) noexcept;

// M-03：上下文失效时禁止翻译。返回 false 时 out.status = ContextRejected、
// out.contextRefusal = 真实理由、没有任何物理地址，调用方只能把保存下来的旧结果
// 标成历史观测。options.mode 由 context.mode 覆盖，其余选项（MAXPHYADDR、1GiB
// 能力）照用调用方给的值。
bool TranslateUsingContext(const TranslationContext& context,
                           ContextValidity validity,
                           std::uint64_t virtualAddress,
                           const PhysicalReader& reader,
                           const TranslateOptions& options,
                           TranslateResult& out);

} // namespace Ksword::Evidence
