#pragma once

// I 模块差异引擎 —— I-04（热补丁与未知合法变化）、I-05（差异定位和上下文）、
// I-06（跳转目标和所有者）、I-09（扫描覆盖和竞态）、I-10（磁盘参考的可信度）。
//
// 输入是 PeImageMap 产出的"归一化后的磁盘映像"和现场读到的映像字节，输出是逐条
// 可回溯的差异事实。设计上刻意不提供的东西，同样是判据的一部分：
//   * 没有 isMalicious / isSuspicious 之类的字段。跨模块跳转、RWX、微软签名都不是
//     结论，只是事实；结论层只有 AnalysisConclusion 四态。
//   * 没有"按模块整体豁免"的入口。ExplanationRule 只能作用在具体 RVA 范围上，
//     且命中时必须记下 ruleId + ruleVersion，否则一次签名校验就能让整份驱动永久放行。
//   * 读不到的字节永远是缺失标记，不补 00 后参与比较 —— 补 0 会把"没读到"伪装成
//     "读到了 0"，进而变成一条凭空的差异或一次凭空的"一致"。
//
// C++20、Qt-free、Win32-free。

#include "EvidenceEnvelope.h"
#include "LosslessValue.h"
#include "ObjectIdentity.h"
#include "PeImageMap.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace Ksword::Evidence {

// ---------------------------------------------------------------------------
// I-05：现场字节与读取状态
// ---------------------------------------------------------------------------

// 三态而不是 optional：读不到和没去读是两回事，前者是失败证据，后者是覆盖缺口。
enum class ByteReadStatus {
    Read,
    Unreadable,
    NotCollected,
};

const char* ByteReadStatusName(ByteReadStatus status) noexcept;

// 现场读到的一段映像字节。status 与 bytes 平行等长；status != Read 时 bytes 的值
// 无意义，调用方必须先看 status。窗口之外一律 NotCollected。
struct LiveImageBytes final {
    std::uint32_t baseRva = 0;
    std::vector<std::uint8_t> bytes;
    std::vector<ByteReadStatus> status;

    bool wellFormed() const noexcept { return bytes.size() == status.size(); }
    RvaRange window() const noexcept;

    ByteReadStatus statusAt(std::uint32_t rva) const noexcept;
    // 只有 status == Read 才返回 true 并写 out；其余情况 out 不被修改。
    bool byteAt(std::uint32_t rva, std::uint8_t& out) const noexcept;

    // 构造辅助：整段按 Read 填入。
    static LiveImageBytes fromBytes(std::uint32_t baseRva, std::vector<std::uint8_t> data);
    // 把一段标成不可读/未采集。范围超出窗口的部分被忽略。
    void markRange(const RvaRange& range, ByteReadStatus newStatus) noexcept;
};

// ---------------------------------------------------------------------------
// I-04：解释规则
// ---------------------------------------------------------------------------

// I-04：一条解释规则的最大跨度。热补丁、已发布补丁、跳板这类"有具体依据"的改动
// 都是指令级的，64 KiB 已经远超真实需要。设这条与参考映像无关的硬上限，是为了让
// 无映像上下文的 API（usable()）也无法被一条 range={0,0xFFFFFFFF} 的规则绕过 ——
// 那等于给整份驱动永久放行，正是 I-04 通过条件明令禁止的。
inline constexpr std::uint32_t kExplanationRuleMaxSpanBytes = 0x10000U;

// 一条解释规则只覆盖一个具体 RVA 范围。没有"整模块"重载，也不打算有。
struct ExplanationRule final {
    std::string ruleId;
    std::uint32_t ruleVersion = 0;
    RvaRange range;
    std::string evidenceText;   // 依据来源（例如某个已发布补丁的编号），不是结论

    // 结构性判据，不看参考映像。真正生效的是 AdmitExplanationRule —— 它还要求
    // 范围落在参考映像的某一个节（或 PE 头）里面。
    bool usable() const noexcept {
        return !ruleId.empty() && !range.empty() && range.length <= kExplanationRuleMaxSpanBytes;
    }
};

// 规则准入结论。拒绝原因分开列，UI 才能说清"这条规则为什么没生效"。
enum class RuleAdmission {
    Accepted,
    Unusable,               // ruleId 为空 / 范围为空 / 跨度超过硬上限
    CoversWholeImage,       // 覆盖或超过整个参考映像 —— 整模块豁免
    NotScopedToOneSection,  // 范围没有完整落在某一个已映射节或 PE 头区间内
};

const char* RuleAdmissionName(RuleAdmission admission) noexcept;

// I-04：豁免必须精确到范围。一条规则要生效，必须整段落在参考映像的某一个已映射
// 节（或 PE 头）之内 —— 跨节的"依据"没有可核对的对象，覆盖整份映像的规则更是
// 直接的整模块放行。被拒的规则不参与匹配，并在报告里留下限制键。
RuleAdmission AdmitExplanationRule(const PeImageMap& reference,
                                   const ExplanationRule& rule) noexcept;

// 只有当规则范围**完全包含**待判范围、且该规则通过了 AdmitExplanationRule 时才算
// 命中。部分覆盖不算 —— 否则一条覆盖一个字节的规则就能解释掉一整段改写。
const ExplanationRule* FindExplanationRule(const PeImageMap& reference,
                                           const std::vector<ExplanationRule>& rules,
                                           const RvaRange& span) noexcept;

enum class DiffExplanation {
    Unexplained,  // 默认状态。没有具体依据就停在这里
    Explained,    // 命中了某条规则的具体 RVA 范围
};

const char* DiffExplanationName(DiffExplanation explanation) noexcept;

// ---------------------------------------------------------------------------
// I-05：差异条目
// ---------------------------------------------------------------------------

enum class DiffKind {
    ByteDifference,    // 双方都可读且字节不同
    MissingLiveBytes,  // 现场读不到 —— 既不是差异也不是"相同"
};

const char* DiffKindName(DiffKind kind) noexcept;

// 折叠前的原始子范围。折叠只是显示层的合并，原始范围必须能展开。
struct DiffSubRange final {
    std::uint32_t rva = 0;
    std::uint32_t length = 0;
    std::vector<std::uint8_t> referenceBytes;
    std::vector<std::uint8_t> liveBytes;  // readStatus != Read 时为空，绝不补 00
};

// I-05 要求每条差异带"前后少量反汇编"。本层是 Qt-free / Win32-free 的纯字节层，
// 不含解码器，因此 decoded 恒为 false，文本由上层填。结构上必须能区分：
//   * 没尝试解码（attempted == false）—— 覆盖缺口；
//   * 尝试过但解不出来（attempted && !decoded）—— 失败证据，必须带原因键。
// 两者塌成同一个空串就等于把"没查"伪装成"查了没有"。
struct DisassemblyContext final {
    bool attempted = false;
    bool decoded = false;
    std::string beforeText;   // 仅 decoded 时有意义
    std::string afterText;    // 仅 decoded 时有意义
    // attempted 且未解码时必须非空的 i18n 键。缺失是显式状态，不是空串。
    std::string unavailableReasonKey;

    bool notAttempted() const noexcept { return !attempted; }
    bool attemptedButUndecoded() const noexcept { return attempted && !decoded; }
};

// 本层唯一能给出的"尝试过但解不出来"原因：这一层根本没有解码器。
inline constexpr const char* kDisassemblyUnavailableNoDecoder =
    "integrity.disassembly.noDecoderInThisLayer";

struct ImageDiffEntry final {
    DiffKind kind = DiffKind::ByteDifference;
    // I-05：这条差异属于哪一个模块实例。同名不同版本、同路径重载都靠它区分；
    // 空身份意味着调用方没提供，不代表"就是当前模块"。
    DriverInstanceId module;
    std::string sectionName;                       // 头部为 "(headers)"，间隙为空串
    std::size_t sectionIndex = kInvalidSectionIndex;
    std::uint32_t rva = 0;
    std::uint64_t va = 0;                          // reference.loadedBase + rva
    std::uint32_t length = 0;
    ByteReadStatus readStatus = ByteReadStatus::Read;
    DiffExplanation explanation = DiffExplanation::Unexplained;
    std::string ruleId;                            // 仅 Explained 时非空
    std::uint32_t ruleVersion = 0;
    std::string ruleEvidence;
    std::string evidenceSource;                    // 这条差异的证据来源串

    std::vector<std::uint8_t> referenceBytes;
    std::vector<std::uint8_t> liveBytes;
    bool byteEvidenceTruncated = false;            // 超过 maxBytesPerEntry 时为 true

    // I-05：反汇编上下文。它的状态**绝不**影响上面的原始字节证据 —— 解不出指令
    // 不代表读不到字节。
    DisassemblyContext disassembly;

    std::vector<DiffSubRange> subRanges;           // 未折叠的原始子范围
    bool collapsed = false;                        // 由多个子范围折叠而来
};

// ---------------------------------------------------------------------------
// I-09：覆盖统计与模块身份复核
// ---------------------------------------------------------------------------

struct CountTriplet final {
    std::uint64_t attempted = 0;
    std::uint64_t succeeded = 0;
    std::uint64_t failed = 0;
    std::uint64_t excluded = 0;
    // 命中上限而**从未被扫描**的部分。它既不是"尝试过失败了"，也不是"被判为
    // 不可比较排除掉了"，混进任何一个桶都会让账目对不上（F-06）。
    std::uint64_t notAttempted = 0;
};

struct ScanCoverageStats final {
    CountTriplet modules;
    CountTriplet bytes;
    CountTriplet pages;
    std::uint32_t pageSize = 4096;
};

void AccumulateStats(ScanCoverageStats& accumulator, const ScanCoverageStats& one) noexcept;

enum class ModuleStalenessVerdict {
    Same,          // 读前读后身份确认一致
    Stale,         // 已卸载 / 换版 / 换基址 —— 旧地址不得继续用于解释
    Unverifiable,  // 身份信息不足，既不能确认也不能否定
};

const char* ModuleStalenessVerdictName(ModuleStalenessVerdict verdict) noexcept;

// 复用 ObjectIdentity 的 MatchDriverInstance，并额外加两条本模块专有的判据：
//   * 读后拿不到任何可用身份 -> Stale。读到一半模块消失时保守判过期，方向上安全。
//   * 同一启动周期内基址变化 -> Stale。同基址重载的反面，旧 RVA→VA 映射已失效。
ModuleStalenessVerdict CheckModuleStillSame(const DriverInstanceId& before,
                                            const DriverInstanceId& after) noexcept;

// ---------------------------------------------------------------------------
// I-10：比较依据
// ---------------------------------------------------------------------------

enum class ReferenceSourceKind {
    LocalDisk,          // 本机磁盘上的同名文件
    UserSelectedImage,  // 用户显式选择的参考映像
    SavedSnapshot,      // 已保存的会话快照
};

const char* ReferenceSourceKindName(ReferenceSourceKind kind) noexcept;

struct ReferenceSource final {
    ReferenceSourceKind kind = ReferenceSourceKind::LocalDisk;
    std::string description;  // 路径 / 快照 id 等可核对的标识
    FileIdentity identity;    // 可用时填；空身份意味着"同名不等于同版本"
};

// 返回 i18n 键。三种来源的键集合各不相同，但**都不包含**"与磁盘一致所以安全"这类
// 结论 —— 字节一致只说明与该参考一致，参考本身可能已被篡改。
std::vector<std::string> BuildTrustNotes(const ReferenceSource& source);

// ---------------------------------------------------------------------------
// 差异引擎
// ---------------------------------------------------------------------------

struct ImageDiffOptions final {
    // 空表示使用 reference.rawBackedRanges（头 + 各已映射节的 raw 支撑区，尚未减去
    // 不可比较范围）。引擎随后减去排除集合并把差额记入 coverage.skipped。
    std::vector<RvaRange> compareRanges;
    // 调用方额外排除的范围。典型用法：重定位无法精确应用时传
    // PeImageMap::relocation.touchedRanges。
    std::vector<RvaRange> excludedRanges;
    std::vector<ExplanationRule> rules;
    ReferenceSource reference;
    std::string evidenceSource;
    // I-05：写进每条差异的模块实例。留空表示调用方没提供身份。
    DriverInstanceId module;
    // I-05：是否请求反汇编上下文。本层没有解码器，置 true 只会得到
    // attempted && !decoded + 一个明确的原因键 —— 这正是要能表达的状态。
    bool attemptDisassembly = false;

    // I-05 折叠：间隔不超过该值的同属性差异合并成一条，子范围仍完整保留。
    std::uint32_t collapseGapBytes = 0;
    std::size_t maxEntries = 4096;
    std::uint32_t maxBytesPerEntry = 256;
    std::uint32_t pageSize = 4096;
    ModuleStalenessVerdict staleness = ModuleStalenessVerdict::Same;
};

struct ImageDiffReport final {
    std::vector<ImageDiffEntry> entries;

    // 被判为不可比较而排除的范围（畸形节 + 不支持的重定位 + 调用方指定）。
    std::vector<RvaRange> excludedRanges;

    std::size_t byteDifferenceEntries = 0;
    std::size_t explainedEntries = 0;
    std::size_t unexplainedEntries = 0;
    std::size_t missingEntries = 0;

    std::uint64_t comparedBytes = 0;     // 双方都可读并真正比较过的字节
    std::uint64_t differingBytes = 0;
    std::uint64_t unreadableBytes = 0;
    std::uint64_t notCollectedBytes = 0;
    std::uint64_t excludedBytes = 0;
    // 有效比较集合里因为命中上限而从未被扫描的字节。恒等式：
    //   comparedBytes + unreadableBytes + notCollectedBytes + notAttemptedBytes
    //     + excludedBytes == 请求集合的字节总数
    std::uint64_t notAttemptedBytes = 0;

    // F-06：真正生效的两个上限都要暴露。停住扫描的是片段数上限（pieceLimit），
    // 条目数上限（entryLimit）只决定折叠后保留多少条 —— 报告里只写后者会让
    // 调用方以为约束是 maxEntries。
    std::uint64_t entryLimit = 0;
    std::uint64_t pieceLimit = 0;
    bool scanStoppedAtPieceLimit = false;

    CollectionOutcome outcome;
    CoverageAccount coverage;
    ScanCoverageStats stats;
    AnalysisConclusion conclusion = AnalysisConclusion::NoEvidence;

    ReferenceSource reference;
    std::vector<std::string> trustNotes;      // 只由 reference 决定
    std::vector<std::string> limitationKeys;  // 覆盖缺口 / 过期 / 重定位 / 规则被拒
    // I-04：被 AdmitExplanationRule 拒掉的规则数。丢弃必须可见，否则调用方会
    // 以为豁免生效了。
    std::size_t rejectedRuleCount = 0;
    bool limitHit = false;
    ModuleStalenessVerdict staleness = ModuleStalenessVerdict::Same;
};

ImageDiffReport CompareImage(const PeImageMap& reference,
                             const LiveImageBytes& live,
                             const ImageDiffOptions& options);

// ---------------------------------------------------------------------------
// I-06：跳转目标与所有者
// ---------------------------------------------------------------------------

struct ModuleRange final {
    std::string name;
    std::uint64_t base = 0;
    std::uint64_t size = 0;

    bool contains(std::uint64_t address) const noexcept {
        return size != 0U && address >= base && (address - base) < size;
    }
};

enum class TargetOwnerKind {
    InsideModule,
    OutsideKnownModules,  // 不在任何已知模块区间内。这是事实，不是"恶意"
};

const char* TargetOwnerKindName(TargetOwnerKind kind) noexcept;

struct TargetOwner final {
    TargetOwnerKind kind = TargetOwnerKind::OutsideKnownModules;
    std::string moduleName;
    OptionalU64 moduleBase;
    OptionalU64 offset;
};

TargetOwner ResolveTargetOwner(std::uint64_t address,
                               const std::vector<ModuleRange>& modules);

// 调用方在某个地址上看到的东西。离线测试直接给夹具，现场由反汇编/读内存填。
enum class FollowStepKind {
    ResolvedCode,        // 普通代码，跟随到此为止
    DirectBranch,        // 目标已确定的直接跳转/调用，继续跟随
    IndirectUnresolved,  // 间接跳转，目标指针取不到
    ExportForwarder,     // 导出转发（"DLL.Export"），与上一条是两码事
    TargetUnreadable,    // 该地址的字节读不出来
};

const char* FollowStepKindName(FollowStepKind kind) noexcept;

struct BranchStep final {
    FollowStepKind kind = FollowStepKind::TargetUnreadable;
    std::uint64_t target = 0;         // 仅 DirectBranch 有效
    std::uint32_t bytesConsumed = 0;  // 解码消耗的字节，计入 maxBytes 预算
    std::string forwarderText;        // 仅 ExportForwarder 有效
};

using BranchResolver = std::function<BranchStep(std::uint64_t address)>;

// 每种终止原因单独一个值。导出转发与未解析间接目标刻意不合并 —— 前者是已知的
// 正常机制，后者是"我们没查出来"，混在一起会让覆盖率虚高。
enum class FollowTermination {
    Resolved,
    DepthExhausted,
    ByteBudgetExhausted,
    CycleDetected,
    TargetUnreadable,
    OutsideKnownModules,
    IndirectUnresolved,
    ExportForwarder,
};

const char* FollowTerminationName(FollowTermination termination) noexcept;

struct FollowNode final {
    std::uint64_t address = 0;
    TargetOwner owner;
    FollowStepKind step = FollowStepKind::TargetUnreadable;
    std::string forwarderText;
};

struct FollowOptions final {
    std::uint32_t maxDepth = 8;
    std::uint64_t maxBytes = 256;
};

struct FollowResult final {
    FollowTermination termination = FollowTermination::TargetUnreadable;
    std::vector<FollowNode> path;
    std::uint32_t depthUsed = 0;
    std::uint64_t bytesUsed = 0;
    // 只陈述事实：路径上出现过模块归属变化。跨模块本身不等于恶意。
    bool crossedModuleBoundary = false;
};

FollowResult FollowBranchTarget(std::uint64_t startAddress,
                                const std::vector<ModuleRange>& modules,
                                const BranchResolver& resolver,
                                const FollowOptions& options = FollowOptions{});

} // namespace Ksword::Evidence
