#pragma once

// I 模块唯一的 PE 归一化核 —— I-02（文件到映像的正确映射）与 I-03（重定位与加载变更）。
//
// 输入是磁盘文件的原始字节 + 目标加载基址，输出是映像布局、可比较区间集合和归一化
// 后的映像字节。仓库此前有两套并行实现（KernelCleanImageBaseline.cpp 的 mapPeImage
// 与 KernelDock.KernelHooks.cpp 的 kernelHookReadPeBytesAtRva），后者完全不做重定位；
// I 模块的硬约束是"不能再引入第二套 PE 解析器"，因此两处都应改为调用本文件。
//
// 设计要点（为什么这样判）：
//   * 所有偏移在使用前先做边界校验；任何越界一律落成状态码，绝不读越界。
//   * 畸形处理有粒度：只有"整份文件都无法解析"才拒绝；单个节畸形时该节标
//     SectionMapStatus::NotComparable 并跳过，其余节继续映射 —— 否则一个坏节就会
//     让整个模块失去比较能力，等于把证据丢掉。
//   * 不支持的重定位类型同理：只把受影响的字节范围标成不可比较，不让整映像失败。
//   * RVA 落在"零填充区"（在 VirtualSize 内但超出 SizeOfRawData）是一种明确状态，
//     不是"文件里没有" —— 这两者对差异解释的意义完全不同。
//   * DVRT（Windows 10+ 动态重定位表）描述的位点由加载器在启动期改写，磁盘上
//     根本不存在改写后的字节。它们既不能"归一化"也不能当成干净基线，只能标
//     不可比较 —— 这正是 ntoskrnl 上大量假"未解释差异"的来源（I-03）。
//
// 本文件是 C++20、Qt-free、Win32-free：PE 结构按偏移手工解析，不依赖 <Windows.h>。

#include "EvidenceEnvelope.h"
#include "LosslessValue.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Evidence {

// ---------------------------------------------------------------------------
// RVA 区间与区间集合运算
// ---------------------------------------------------------------------------

// RVA 区间。长度为 0 表示空区间，不参与任何集合运算。
struct RvaRange final {
    std::uint32_t rva = 0;
    std::uint32_t length = 0;

    // 用 64 位返回上界，避免 rva + length 在 32 位里回绕。
    constexpr std::uint64_t endExclusive() const noexcept {
        return static_cast<std::uint64_t>(rva) + static_cast<std::uint64_t>(length);
    }

    constexpr bool empty() const noexcept { return length == 0U; }

    constexpr bool contains(std::uint32_t probe) const noexcept {
        return length != 0U && probe >= rva && static_cast<std::uint64_t>(probe) < endExclusive();
    }

    // 完全包含另一个区间（空区间不被任何区间"包含"，避免空集合误判为已解释）。
    constexpr bool containsRange(const RvaRange& other) const noexcept {
        return !other.empty() && !empty() && other.rva >= rva &&
               other.endExclusive() <= endExclusive();
    }

    constexpr bool overlaps(const RvaRange& other) const noexcept {
        return !empty() && !other.empty() && rva < other.endExclusive() &&
               other.rva < endExclusive();
    }

    friend constexpr bool operator==(const RvaRange& a, const RvaRange& b) noexcept {
        return a.rva == b.rva && a.length == b.length;
    }

    friend constexpr bool operator!=(const RvaRange& a, const RvaRange& b) noexcept {
        return !(a == b);
    }
};

// 排序并合并重叠/相邻区间。空区间被丢弃。
std::vector<RvaRange> NormalizeRvaRanges(std::vector<RvaRange> ranges);

// base 减去 cut，结果已归一化。两侧都不要求预先排序。
std::vector<RvaRange> SubtractRvaRanges(const std::vector<RvaRange>& base,
                                        const std::vector<RvaRange>& cut);

// base 与 mask 的交集，结果已归一化。
std::vector<RvaRange> IntersectRvaRanges(const std::vector<RvaRange>& base,
                                         const std::vector<RvaRange>& mask);

std::uint64_t RvaRangesTotalBytes(const std::vector<RvaRange>& ranges) noexcept;

bool RvaRangesContain(const std::vector<RvaRange>& ranges, std::uint32_t rva) noexcept;

// ---------------------------------------------------------------------------
// 解析状态
// ---------------------------------------------------------------------------

// 只有这些情况才是"整份文件不可解析"，其余畸形都按节/按范围降级。
enum class PeParseStatus {
    Ok,
    EmptyInput,
    TruncatedDosHeader,
    BadDosSignature,
    BadNtHeaderOffset,           // e_lfanew 越界或未对齐
    TruncatedNtHeaders,
    BadNtSignature,
    UnsupportedOptionalMagic,    // 不是 PE32+
    TruncatedOptionalHeader,
    InvalidSectionCount,         // 0 个或超过上限
    TruncatedSectionTable,       // 节表被文件尾截断
    SectionTableExceedsHeaders,  // I-02：节表条目数与 SizeOfHeaders 不一致
    InvalidSizeOfImage,          // 为 0、小于 SizeOfHeaders 或超过取证上限
    InvalidAlignment,            // SectionAlignment / FileAlignment 非法
};

const char* PeParseStatusName(PeParseStatus status) noexcept;

// ---------------------------------------------------------------------------
// 节
// ---------------------------------------------------------------------------

enum class SectionMapStatus {
    Mapped,         // 边界校验通过，已映射，可参与比较
    NotComparable,  // 该节畸形，已跳过；它覆盖的 RVA 范围不给出任何比较结论
};

const char* SectionMapStatusName(SectionMapStatus status) noexcept;

// 单个节被判为不可比较的具体原因。给 UI 和报告用，不做二值遮盖。
enum class SectionDefectReason {
    None,
    ZeroVirtualExtent,        // VirtualSize 与 SizeOfRawData 同时为 0
    VirtualRangeOutOfImage,   // VirtualAddress + VirtualSize 越过 SizeOfImage
    VirtualRangeOverflow,     // VirtualAddress + VirtualSize 32 位回绕
    RawDataOutOfFile,         // PointerToRawData + SizeOfRawData 越过文件尾
    RawRangeOverflow,         // PointerToRawData + SizeOfRawData 32 位回绕
    // I-02：与前面已接受的节区间重叠，**或**与 PE 头区间 [0, SizeOfHeaders) 重叠。
    // 头部先于任何节被放进映像，节再盖上去就会让同一个 RVA 有两个来源；这两种
    // 重叠是同一类缺陷，共用一个原因码。
    OverlapsEarlierSection,
};

const char* SectionDefectReasonName(SectionDefectReason reason) noexcept;

struct SectionMap final {
    std::string name;                 // 最多 8 字节，去掉尾部 NUL；不保证唯一
    std::uint32_t virtualAddress = 0;
    std::uint32_t virtualSize = 0;    // 头里的原值，可能为 0
    std::uint32_t pointerToRawData = 0;
    std::uint32_t sizeOfRawData = 0;
    std::uint32_t characteristics = 0;

    // 实际生效的虚拟长度：VirtualSize 为 0 时退回 SizeOfRawData（老链接器写法）。
    std::uint32_t effectiveVirtualSize = 0;
    // 真正从文件复制进映像的字节数 = min(SizeOfRawData, effectiveVirtualSize)。
    // raw > virtual 的尾部填充不进映像，也就不进比较。
    std::uint32_t rawBackedBytes = 0;
    // 零填充长度 = effectiveVirtualSize - rawBackedBytes。这些字节在映像里确实是 0，
    // 但"文件里没有对应字节"，所以和 rawBacked 区分开。
    // 契约：归一化过程**绝不**往零填充区写字节 —— 目标落在这里的重定位一律拒绝
    // 应用并标不可比较，否则 zeroFillRanges 会一边宣称"这里是 0"一边藏着非 0 值。
    std::uint32_t zeroFillBytes = 0;

    SectionMapStatus status = SectionMapStatus::NotComparable;
    SectionDefectReason defect = SectionDefectReason::None;

    bool executable() const noexcept;   // IMAGE_SCN_MEM_EXECUTE 或 CNT_CODE
    bool writable() const noexcept;     // IMAGE_SCN_MEM_WRITE

    RvaRange virtualRange() const noexcept;    // [VA, VA + effectiveVirtualSize)
    RvaRange rawBackedRange() const noexcept;  // [VA, VA + rawBackedBytes)
    RvaRange zeroFillRange() const noexcept;   // [VA + rawBackedBytes, VA + effVSize)
};

// ---------------------------------------------------------------------------
// 头部事实
// ---------------------------------------------------------------------------
struct PeHeaderFacts final {
    std::uint16_t machine = 0;
    std::uint16_t sectionCount = 0;
    std::uint16_t fileCharacteristics = 0;
    std::uint32_t timeDateStamp = 0;
    std::uint32_t checkSum = 0;
    std::uint64_t preferredImageBase = 0;
    std::uint32_t sizeOfImage = 0;
    std::uint32_t sizeOfHeaders = 0;
    std::uint32_t sectionAlignment = 0;
    std::uint32_t fileAlignment = 0;
    std::uint32_t entryPointRva = 0;
    std::uint32_t numberOfRvaAndSizes = 0;   // 头里的原值，未必可信
    // I-02：真正落在可选头范围内、因而可以被解析的数据目录条目数 =
    // min(NumberOfRvaAndSizes, 16, (SizeOfOptionalHeader - 112) / 8)。
    // 超出这个数的目录项其实位于**节表字节**里，不是目录 —— 一律忽略。
    std::uint32_t dataDirectoryCount = 0;
    std::uint32_t exportDirectoryRva = 0;
    std::uint32_t exportDirectorySize = 0;
    std::uint32_t relocationDirectoryRva = 0;
    std::uint32_t relocationDirectorySize = 0;
    // I-03：DVRT 的入口在 LoadConfig 目录（数据目录 10）里。目录条目数不足 11 时
    // 这两个字段恒为 0，且那是**正面证据**："这份 PE 根本没有 LoadConfig 目录"。
    std::uint32_t loadConfigDirectoryRva = 0;
    std::uint32_t loadConfigDirectorySize = 0;
    std::uint64_t ntHeadersFileOffset = 0;
    std::uint64_t sectionTableFileOffset = 0;

    bool relocationsStripped() const noexcept;  // IMAGE_FILE_RELOCS_STRIPPED
};

// ---------------------------------------------------------------------------
// I-03 重定位
// ---------------------------------------------------------------------------

enum class RelocationStatus {
    NotNeeded,               // delta == 0，无需归一化
    Applied,                 // 全部条目按支持的类型应用完毕
    AppliedWithUnsupported,  // 部分类型不支持，对应字节范围已标不可比较，其余已归一化
    DirectoryMissing,        // 需要重定位但目录不存在/长度不足
    DirectoryUnbacked,       // 目录 RVA 不落在有文件字节支撑的范围里，内容不可信
    DirectoryMalformed,      // 块头/条目被截断；剩余部分停止
    Stripped,                // 映像声明 RELOCS_STRIPPED 却需要改基址
};

const char* RelocationStatusName(RelocationStatus status) noexcept;

// I-03：delta != 0 时，只有这三种状态说明"映像已经按目标基址归一化"。其余四种
// 说明归一化根本没做成，此时 map.image 仍停留在首选基址的字节上，拿它当磁盘参考
// 去比较必然在每个重定位点上凭空报差异 —— 所以这些状态一律把整份映像标不可比较。
bool RelocationNormalizationSucceeded(RelocationStatus status) noexcept;

// 记录不支持的重定位类型及其影响到的字节范围，供 UI 说明"为什么这段不可比较"。
struct UnsupportedRelocation final {
    std::uint16_t type = 0;
    RvaRange range;
};

struct RelocationReport final {
    RelocationStatus status = RelocationStatus::NotNeeded;
    std::uint64_t delta = 0;              // loadedBase - preferredImageBase（无符号回绕）
    // 真正是"重定位条目"的 WORD 数。HIGHADJ 后面那个参数字**不算**条目：它不描述
    // 任何重定位目标，把它计进来会让 succeeded + failed 永远小于 totalKnown，
    // 于是只要映像里有一个 HIGHADJ，重定位覆盖率就永远不可能完整（I-03 / F-06）。
    std::uint64_t entriesTotal = 0;
    std::uint64_t entriesApplied = 0;     // 真正改写了字节的条目
    std::uint64_t entriesAbsolute = 0;    // ABSOLUTE 对齐填充，按"跳过"记账
    std::uint64_t entriesUnsupported = 0; // 类型不支持
    std::uint64_t entriesOutOfRange = 0;  // 目标越过映像，未改写任何字节
    // 目标跨度不完全落在有文件字节支撑的范围内（落进零填充区或跨越 raw/零填充
    // 边界）。这类条目**拒绝应用**：加载器会写这些字节，但我们手里的磁盘参考在
    // 那里只有伪造的 0，改写它既会破坏 zeroFillRanges 的契约，也会把无中生有的
    // 值当成"磁盘上本来的样子"。范围一律标不可比较（I-02）。
    std::uint64_t entriesUnbackedTarget = 0;
    // HIGHADJ 的参数字，按"跳过的参数"单独记账，不进 entriesTotal（I-03 / F-06）。
    std::uint64_t entriesSkippedParameter = 0;
    std::uint32_t blocksProcessed = 0;

    // 被重定位改写过的字节集合。差异引擎可以据此排除（例如在无法精确归一化时）。
    std::vector<RvaRange> touchedRanges;
    std::vector<UnsupportedRelocation> unsupported;
    // 被拒绝应用的无文件支撑目标范围，与 unsupported 分开：类型是支持的，
    // 问题出在目标位置上。
    std::vector<RvaRange> unbackedTargetRanges;

    // I-03：delta != 0 却没能完成归一化时为 true，此时整份映像已进
    // notComparableRanges。调用方据此知道"这次比较根本没有可用的磁盘参考"。
    bool imageNotNormalized = false;

    // I-09：把 applied / unsupported 喂进统一账目。
    CoverageAccount coverage;
};

// ---------------------------------------------------------------------------
// I-03 DVRT：Windows 10+ 的 IMAGE_DYNAMIC_RELOCATION_TABLE
// ---------------------------------------------------------------------------
//
// DVRT 与 .reloc 是两件不同的事，不要混起来看：
//   * .reloc 描述"把首选基址换成实际基址"，delta 已知，因此**可以**从磁盘字节
//     算出加载后的字节 —— 这是归一化。
//   * DVRT 描述"加载器按当前系统状态改写这条指令"（import optimization 把经
//     IAT 的间接调用改成直接调用；retpoline 把间接跳转改写成 thunk 调用）。
//     改写结果取决于运行期才知道的 IAT 内容与 CPU 缓解策略开关，磁盘上**不存在**
//     改写后的字节。因此 DVRT 位点既不能归一化也不能当干净基线，只能标不可比较。
// 不标它的后果是确定的：ntoskrnl 的每一个被改写的调用点都会变成一条"未解释的
// 代码差异"，正是 I-01 明令禁止的批量误报。

// 已知的动态重定位符号编号（winnt.h 的 IMAGE_DYNAMIC_RELOCATION_* 常量）。
inline constexpr std::uint64_t kDvrtSymbolGuardRfPrologue = 1U;
inline constexpr std::uint64_t kDvrtSymbolGuardRfEpilogue = 2U;
inline constexpr std::uint64_t kDvrtSymbolImportControlTransfer = 3U;
inline constexpr std::uint64_t kDvrtSymbolIndirControlTransfer = 4U;
inline constexpr std::uint64_t kDvrtSymbolSwitchtableBranch = 5U;

// 一个位点最多覆盖的字节数。x64 上被改写的是一条 call/jmp，取 8 字节留出前缀与
// ModRM 的余量。宁可多标一点不可比较，也不要漏标而把被改写的字节报成"干净差异"。
inline constexpr std::uint32_t kDvrtSiteSpan = 8U;

// IMAGE_BASE_RELOCATION 块描述的页大小。DVRT 沿用同一种块容器。
inline constexpr std::uint32_t kRelocationPageBytes = 0x1000U;

enum class DvrtStatus {
    // 正面证据：这份 PE 确实没有 DVRT（没有 LoadConfig 目录 / LoadConfig 结构
    // 早于 DVRT 字段 / 表偏移为 0）。只有这一种"没有"是可以采信的。
    NotPresent,
    Parsed,                  // 表走完，所有符号都已按位点解码
    ParsedWithUnknownSymbol, // 表走完，但有符号解不开；其影响范围按块的页粒度界定
    LoadConfigUnusable,      // LoadConfig 目录越界 / 无文件字节支撑 / 宿主节不可用
    TableUnbacked,           // 表所在范围没有文件字节支撑，读到的是伪造的 0
    UnsupportedVersion,      // 表版本不是 1，字段含义未知
    Malformed,               // size 越界 / 块长度非法 / 条目头被截断
};

const char* DvrtStatusName(DvrtStatus status) noexcept;

// 只有这三种状态说明"DVRT 会改写哪些字节"已经被完整界定。其余状态下我们知道
// DVRT 可能存在却划不出边界，此时整份映像进 notComparableRanges —— 划不出边界
// 就没有资格对任何一个字节说"这里没有差异"。
bool DvrtExtentFullyBounded(DvrtStatus status) noexcept;

// 一个符号段（IMAGE_DYNAMIC_RELOCATION64 + 其后的基址重定位块）的账目。
struct DvrtSymbolGroup final {
    std::uint64_t symbol = 0;
    std::uint32_t payloadBytes = 0;        // BaseRelocSize
    // 每条记录的字节宽度；0 表示本层不认识这个符号，位点无法解码。
    std::uint32_t entryStride = 0;
    std::uint64_t blocksWalked = 0;
    std::uint64_t sitesDecoded = 0;
    std::uint64_t sitesOutsideImage = 0;   // 位点越过 SizeOfImage，未标任何范围
    // 容器（块头序列）是否走通。走通了即使符号不认识，也能按页界定影响范围。
    bool containerWalked = false;
    // 位点级解码是否完成 = 符号已知且容器走通。
    bool decoded = false;
};

struct DynamicRelocationReport final {
    DvrtStatus status = DvrtStatus::NotPresent;

    // 全部用 OptionalU64：没读到就是 unset，绝不用 0 冒充"读到了 0"。
    OptionalU64 loadConfigRva;
    OptionalU64 loadConfigDeclaredSize;   // 数据目录里声明的长度
    OptionalU64 loadConfigStructSize;     // 结构体自己的 Size 字段
    OptionalU64 tableRva;
    OptionalU64 tableVersion;
    OptionalU64 tableSize;

    std::uint64_t groupsTotal = 0;
    std::uint64_t groupsDecoded = 0;        // 符号已知且容器走通
    std::uint64_t groupsUnknownSymbol = 0;  // 符号不认识，只按页界定
    std::uint64_t sitesDecoded = 0;
    std::uint64_t sitesOutsideImage = 0;
    std::vector<DvrtSymbolGroup> groups;

    // 已解码位点覆盖的字节范围（每个位点 kDvrtSiteSpan 字节，按 SizeOfImage 截断）。
    // 这是"独立可导出的 RVA 范围集合"：差异引擎可以拿它排除或标注差异。
    std::vector<RvaRange> siteRanges;
    // 符号不认识但容器走通时，块所描述的整页范围。粒度比 siteRanges 粗，但仍是
    // 可证明的上界 —— 加载器只会在这些页里改字节。
    std::vector<RvaRange> unknownSymbolRanges;

    // status 不在 DvrtExtentFullyBounded 里时为 true，此时整份映像已进
    // notComparableRanges。
    bool extentUnknown = false;

    // I-09：以符号段为单位的账目。
    CoverageAccount coverage;

    // siteRanges ∪ unknownSymbolRanges，已归一化。给差异引擎的单一入口。
    std::vector<RvaRange> affectedRanges() const;
};

// ---------------------------------------------------------------------------
// RVA <-> 文件偏移
// ---------------------------------------------------------------------------

inline constexpr std::size_t kInvalidSectionIndex = static_cast<std::size_t>(-1);

enum class RvaKind {
    OutsideImage,      // RVA >= SizeOfImage
    Header,            // 落在 SizeOfHeaders 之内
    SectionRawBacked,  // 节内且有文件字节支撑
    SectionZeroFill,   // 节内但超出 SizeOfRawData —— 映像里是 0，文件里没有
    SectionGap,        // 在 SizeOfImage 内但不属于任何已映射节（对齐间隙）
    NotComparable,     // 落在被判为畸形的节里
};

const char* RvaKindName(RvaKind kind) noexcept;

struct RvaTranslation final {
    RvaKind kind = RvaKind::OutsideImage;
    // 只有 Header 与 SectionRawBacked 才 present；零填充/间隙没有文件偏移，
    // 这里保持 unset 而不是填 0，否则调用方会去读文件头当成节内容。
    OptionalU64 fileOffset;
    std::size_t sectionIndex = kInvalidSectionIndex;
};

enum class FileOffsetKind {
    OutsideFile,            // 超过文件长度
    Header,                 // 落在 SizeOfHeaders 之内
    SectionRawData,         // 落在某个已映射节的 raw 区
    NotMappedByAnySection,  // 文件里有，但没有任何节把它映射进映像（覆盖数据/证书）
    NotComparable,          // 落在被判为畸形的节的 raw 区
};

const char* FileOffsetKindName(FileOffsetKind kind) noexcept;

struct FileOffsetTranslation final {
    FileOffsetKind kind = FileOffsetKind::OutsideFile;
    OptionalU64 rva;
    std::size_t sectionIndex = kInvalidSectionIndex;
};

// ---------------------------------------------------------------------------
// 映射结果
// ---------------------------------------------------------------------------

struct PeMapOptions final {
    // 取证上限：超过就不再分配缓冲，避免畸形 SizeOfImage 撑爆内存。
    std::uint32_t maxImageBytes = 512U * 1024U * 1024U;
    std::uint16_t maxSectionCount = 96U;
    bool applyRelocations = true;
};

struct PeImageMap final {
    PeParseStatus status = PeParseStatus::EmptyInput;
    std::string errorDetail;            // 仅 status != Ok 时非空，是 i18n 键而非成句文案

    PeHeaderFacts header;
    std::vector<SectionMap> sections;

    std::uint64_t loadedBase = 0;       // 归一化到的目标基址
    std::uint64_t fileSize = 0;

    // 归一化后的映像字节，大小恒等于 SizeOfImage（status == Ok 时）。
    std::vector<std::uint8_t> image;

    RvaRange headerRange;                        // [0, min(SizeOfHeaders, SizeOfImage))
    // 有文件字节支撑的全部范围：头 + 各已映射节的 raw 支撑区。这是"本来打算比较的
    // 范围"，差异引擎用它当请求集合，才能把不可比较的部分记成"已排除"而不是从未请求。
    std::vector<RvaRange> rawBackedRanges;
    std::vector<RvaRange> zeroFillRanges;        // 各已映射节的零填充区
    // 畸形节 + 不支持的重定位目标 + 无文件支撑的重定位目标 + DVRT 位点；delta != 0
    // 却无法完成归一化时（Stripped / DirectoryMissing / DirectoryUnbacked /
    // DirectoryMalformed），或 DVRT 影响范围划不出边界时，这里是**整个映像范围**
    // —— 见 RelocationNormalizationSucceeded 与 DvrtExtentFullyBounded 的说明。
    std::vector<RvaRange> notComparableRanges;
    // 便利视图：rawBackedRanges 减去 notComparableRanges。
    std::vector<RvaRange> comparableRanges;

    RelocationReport relocation;
    DynamicRelocationReport dynamicRelocation;

    // I-09：节一级的尝试/成功/失败账目。
    CoverageAccount sectionCoverage;

    bool valid() const noexcept { return status == PeParseStatus::Ok; }

    // 已映射节里带可执行属性的 raw 支撑区。inline hook 基线只需要这部分。
    // 与 rawBackedRanges 同口径：**不**预先减去 notComparableRanges，交给差异引擎
    // 去减并记账，否则被排除的字节会静默消失在覆盖率里。
    std::vector<RvaRange> executableRawBackedRanges() const;

    const SectionMap* sectionAt(std::size_t index) const noexcept;
};

// 主入口。fileBytes 可以为 nullptr（此时 fileSize 必须为 0），返回 EmptyInput。
PeImageMap BuildPeImageMap(const std::uint8_t* fileBytes,
                           std::size_t fileSize,
                           std::uint64_t loadedBase,
                           const PeMapOptions& options = PeMapOptions{});

PeImageMap BuildPeImageMap(const std::vector<std::uint8_t>& fileBytes,
                           std::uint64_t loadedBase,
                           const PeMapOptions& options = PeMapOptions{});

RvaTranslation TranslateRva(const PeImageMap& map, std::uint32_t rva) noexcept;
FileOffsetTranslation TranslateFileOffset(const PeImageMap& map, std::uint64_t fileOffset) noexcept;

// 找出包含该 RVA 的已映射节；找不到返回 kInvalidSectionIndex。
std::size_t SectionIndexForRva(const PeImageMap& map, std::uint32_t rva) noexcept;

// 该 RVA 所属节名；落在头里返回 "(headers)"，落在间隙返回空串。
std::string SectionNameForRva(const PeImageMap& map, std::uint32_t rva);

// 从归一化映像里取一段字节。这是一个"磁盘参考窗口"接口，因此判据只有一条：
// 请求跨度必须完整落在 comparableRanges（= 有文件字节支撑、且未被标不可比较的
// 范围）内。越界、落进不可比较范围（畸形节 / 不支持的重定位 / DVRT 位点 /
// 未归一化的映像）、落进零填充区、落进节间隙一律返回 false 且不写 out ——
// 零填充与间隙在映像里是 0，但文件里根本没有对应字节，返回"成功 + 一片 0"
// 会让调用方把伪造的 0 当成磁盘上的真实内容（I-05：读不到就是缺失，绝不补 00）。
// 返回 false **不是**"没有差异"，调用方必须把该处表述成"不可比较"。
bool ReadNormalizedBytes(const PeImageMap& map,
                         std::uint32_t rva,
                         std::uint32_t length,
                         std::vector<std::uint8_t>& out);

} // namespace Ksword::Evidence
