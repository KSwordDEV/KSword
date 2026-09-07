#pragma once

// C 模块（离线崩溃转储分析，P2）的纯事实模型与安全边界。
//
// 覆盖编号：C-02 C-03 C-04 C-05 C-06 C-07 C-08 C-09 C-10。
// C-01（DbgEng 探测）与"与真实 dump 对照"不在本文件范围：那需要真实样本与调试引擎，
// 本文件只做能被构造字节完整离线验证的部分。
//
// 本文件不碰磁盘、不调 DbgEng、不含 Qt/Win32。输入是调用方已经读进内存的字节，
// 输出是可被 UI/报告直接消费的事实结构。引擎承载在既有 MinidumpDock 里。
//
// 三条贯穿全文件的红线（上一轮对抗性评审实测抓到的作弊模式）：
//   1. 缺失永远是独立状态。任何"没读到"都不许退化成 0、空串或"正常"
//      （C-03 点名的陷阱）。
//   2. 默认构造不许是"完整""可信""安全"。DumpRecognition 默认 NotADump，
//      StackFrame 默认 TruncatedNoData，SymbolMatch 默认 NotAttempted，
//      ContentPresence 默认 Unknown，SymbolServerPolicy 默认不联网。
//   3. 没有 malicious / threat / isRootkit / suspicious / riskScore / rootCause /
//      责任百分比这类越权判定字段。C-06 只产出"线索够不够立案"，不产出判决。

#include "EvidenceEnvelope.h"
#include "LosslessValue.h"
#include "ScanBudget.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Ksword::Evidence {

// ---------------------------------------------------------------------------
// 字节读取。所有按偏移的访问都经过这里，越界返回 false 而不是读到垃圾。
// 显式小端组装，不做结构体 memcpy —— 避免对齐与填充假设。
// ---------------------------------------------------------------------------
bool ReadLittleEndianU32(std::span<const std::uint8_t> bytes,
                         std::size_t offset,
                         std::uint32_t& out) noexcept;

bool ReadLittleEndianU64(std::span<const std::uint8_t> bytes,
                         std::size_t offset,
                         std::uint64_t& out) noexcept;

// ---------------------------------------------------------------------------
// C-02 文件识别与支持范围
// ---------------------------------------------------------------------------

// DumpKind：本轮的支持范围。只有 KernelSmall/KernelMemory 允许取崩溃事实。
enum class DumpKind {
    NotADump,      // 字节里没有任何已知转储签名
    Unsupported,   // 认出了签名家族，但本轮不解析（32 位内核转储 / 非 x64 / 头被截断）
    UserMinidump,  // 'MDMP' 用户态小型转储。红线：绝不当成内核 dump
    KernelSmall,   // PAGEDU64 且 DumpType ∈ {3 仅头, 4 triage}
    KernelMemory,  // PAGEDU64 且 DumpType ∈ {1,2,5,6,7}
};

const char* DumpKindName(DumpKind kind) noexcept;

// 只有这两类才谈得上 bugcheck 事实。其余一律不解析，也不冒充解析成功。
bool DumpKindCarriesKernelFacts(DumpKind kind) noexcept;

// SignatureFamily 与 DumpKind 是两件事，不能塌成一个字段：
// 头被截断时家族仍然可信（例如"确定是 MDMP，所以确定不是内核 dump"），
// 但 kind 收敛不到 KernelSmall/KernelMemory。DumpKind 只有规范给定的五个值，
// 因此这种"认得出但读不全"的情况 kind=Unsupported + reason=TruncatedHeader，
// 家族由本字段单独承载。
enum class SignatureFamily {
    None,
    Mdmp,          // 'MDMP'
    KernelPage64,  // 'PAGE' + 'DU64'
    KernelPage32,  // 'PAGE' + 'DUMP'
};

const char* SignatureFamilyName(SignatureFamily family) noexcept;

// RecognitionReason：为什么得到这个 kind。失败语义不许塌成一个（评审模式 4）：
// 空文件 / 太短 / 截断 / 未知签名 / 位宽不支持 / 架构不支持 / DumpType 不支持
// 是七种不同的事，报告与 UI 必须能分开表述。
enum class RecognitionReason {
    Recognized,
    EmptyFile,                 // 0 字节
    TooSmallForSignature,      // 有字节但不足 8 字节，连签名都读不出
    TruncatedHeader,           // 签名成立，但可读字节不足该格式的头长度
    UnknownSignature,          // 前 8 字节不匹配任何已知签名
    UnsupportedKernelBitness,  // 'PAGE'+'DUMP'：32 位内核转储，本轮不支持
    UnsupportedArchitecture,   // 内核转储但 MachineImageType 不是 x64
    UnsupportedDumpType,       // DumpType 字段不是已知取值（含 PAGE 填充）
};

const char* RecognitionReasonName(RecognitionReason reason) noexcept;

// C-02：目标架构分类。原始机器类型另存，分类不吃掉原值。
enum class TargetArchitecture {
    Unknown,  // 没读到可信的机器类型
    X86,
    X64,
    Arm,
    Arm64,
    Other,    // 读到了但不在已知表里 —— 原值在 rawMachineType
};

const char* TargetArchitectureName(TargetArchitecture architecture) noexcept;

struct DumpRecognition final {
    DumpKind kind = DumpKind::NotADump;
    SignatureFamily family = SignatureFamily::None;
    RecognitionReason reason = RecognitionReason::UnknownSignature;
    TargetArchitecture architecture = TargetArchitecture::Unknown;

    OptionalU64 rawSignature;    // 前 4 字节原值，未读到即 unset
    OptionalU64 rawValidDump;    // 次 4 字节原值
    OptionalU64 rawMachineType;  // PE 机器类型原值
    OptionalU64 rawDumpType;     // DUMP_HEADER64.DumpType 原值
    OptionalU64 fileSize;        // 调用方声明的文件大小
    OptionalU64 bytesProvided;   // 调用方实际给了多少字节
    OptionalU64 headerBytesRequired;  // 该家族需要的最小头长度

    // C-02："不冒充解析成功"。只有真的按格式读过字段才为真。
    bool parseAttempted = false;

    CollectionOutcome outcome;   // 失败时保留原因码（domain = "KSWORD_DUMPRECOGNITION"）
};

// C-02 主入口。只看字节，不看扩展名、不看路径。
// headBytes 至少给到文件头（内核转储要 0x2000 字节才能读全 DumpType 之后的字段）；
// totalFileSize 未知时按 headBytes.size() 当作全文件。
//
// **不是 noexcept**，而且不许改回去：每一条失败路径都要构造 CollectionOutcome，
// 里面的 domain 字符串 "KSWORD_DUMPRECOGNITION" 有 22 字节，超过 MSVC std::string
// 的 15 字节 SSO 上限，必然堆分配。声明成 noexcept 只会让一次内存不足从
// bad_alloc 变成 std::terminate —— 主程序直接消失，正是 C-01 要避免的那一条。
// 真正不许分配的是判据函数（见 .cpp 里 AsciiEqualsIgnoreCase 一节），它们仍是 noexcept。
DumpRecognition RecognizeDump(std::span<const std::uint8_t> headBytes,
                              const OptionalU64& totalFileSize);

// "文件坏了"与"格式不支持"都会落到 kind=Unsupported，但它们是两件事。
// UI 文案必须靠这个函数分开，不能只看 kind。
bool RecognitionIsDamagedRatherThanUnsupported(const DumpRecognition& recognition) noexcept;

// ---------------------------------------------------------------------------
// C-03 崩溃事实
// ---------------------------------------------------------------------------

// DumpFieldAvailability：字段级三态。C-03 点名的陷阱就是把 NotRecorded/NotParsed
// 压成 Present(0)。三者在这里永远分开。
enum class DumpFieldAvailability {
    NotParsed,    // 本轮没读到（窗口不够 / 文件截断 / 格式不解析）—— 不知道有没有
    NotRecorded,  // 转储里就没写（PAGE 填充 / 该格式不含此字段）—— 知道没有
    Present,      // 读到了真实值
};

const char* DumpFieldAvailabilityName(DumpFieldAvailability availability) noexcept;

struct DumpField final {
    DumpFieldAvailability availability = DumpFieldAvailability::NotParsed;
    OptionalU64 value;

    static DumpField present(std::uint64_t v) noexcept;
    static DumpField notRecorded() noexcept;
    static DumpField notParsed() noexcept;

    // 不变式：Present ⇔ value.present。任一侧单独成立都是构造 bug。
    bool consistent() const noexcept;

    friend bool operator==(const DumpField& a, const DumpField& b) noexcept {
        return a.availability == b.availability && a.value == b.value;
    }
    friend bool operator!=(const DumpField& a, const DumpField& b) noexcept { return !(a == b); }
};

struct BugCheckFacts final {
    DumpKind dumpKind = DumpKind::NotADump;

    DumpField code;                        // DUMP_HEADER64.BugCheckCode
    std::array<DumpField, 4> parameters{}; // BugCheckParameter[0..3]
    DumpField targetOsMajor;               // MajorVersion
    DumpField targetOsBuild;               // MinorVersion（内核构建号）
    DumpField processorCount;
    DumpField crashTimeUtc100ns;           // SystemTime（FILETIME）
    DumpField uptime100ns;                 // SystemUpTime
    DumpField writerStatus;                // 0 是有意义的取值，不当缺失
    DumpField directoryTableBase;          // 崩溃时的 CR3

    // C-03 + 评审模式 4：NotParsed 有两种来源，报告要能分开说。
    OptionalU64 bytesProvided;
    OptionalU64 fileSizeDeclared;
    bool windowShorterThanFile = false;

    CollectionOutcome outcome;

    // 至少有一个字段真的读到了值。全 false 时不允许渲染成"崩溃信息"。
    bool hasAnyFact() const noexcept;
    std::size_t presentFieldCount() const noexcept;
    std::size_t notRecordedFieldCount() const noexcept;
    std::size_t notParsedFieldCount() const noexcept;
    std::size_t fieldCount() const noexcept;
};

// C-03 主入口。recognition.kind 决定解析与否：
//   NotADump                 -> outcome=NotCollected，全部 NotParsed
//   Unsupported              -> outcome=Unsupported，全部 NotParsed
//   UserMinidump             -> outcome=Unsupported，全部 NotRecorded（该格式不含这些字段）
//   KernelSmall/KernelMemory -> 逐字段读，读不到的按上面三态如实标注
BugCheckFacts ExtractBugCheckFacts(const DumpRecognition& recognition,
                                   std::span<const std::uint8_t> headBytes);

// ---------------------------------------------------------------------------
// C-04 符号精确匹配
// ---------------------------------------------------------------------------

enum class SymbolMatch {
    NotAttempted,  // 默认：没试过。不是"没有符号"
    Absent,        // 试过了，找不到 PDB
    WrongVersion,  // 找到了 PDB 但 GUID/Age 不符 —— 红线：不得用于函数名/行号
    Matched,
};

const char* SymbolMatchName(SymbolMatch match) noexcept;

enum class SymbolCacheSource {
    Unknown,
    NotLoaded,
    LocalDirectory,  // 转储同目录 / 用户显式指定的本地目录
    LocalCache,      // 本地符号缓存（downstream store）
    SymbolServer,    // 网络符号服务器
    DumpEmbedded,    // 转储自带（极少）
};

const char* SymbolCacheSourceName(SymbolCacheSource source) noexcept;

// PdbIdentity：GUID 按 16 字节原样存，不先转字符串再比 —— 大小写与花括号写法
// 差异会让"错版"看起来像"匹配"。present 默认 false：没有标识绝不等于匹配。
struct PdbIdentity final {
    std::array<std::uint8_t, 16> guid{};
    std::uint32_t age = 0;
    bool present = false;
    std::string pdbName;  // 外来文本，进报告前必须过 EscapeForReport
};

// 任一侧 present==false 即返回 false。两个空标识不算"相同"。
bool SamePdbIdentity(const PdbIdentity& a, const PdbIdentity& b) noexcept;

enum class SymbolLoadAttempt {
    NotAttempted,
    FileNotFound,
    LoadFailed,   // 找到文件但打不开/格式坏
    FileLoaded,
};

const char* SymbolLoadAttemptName(SymbolLoadAttempt attempt) noexcept;

// C-04 判定：加载结果 + 两侧标识 -> 匹配三态。
// 默认构造（NotAttempted + 两个空标识）必须返回 NotAttempted，绝不返回 Matched。
SymbolMatch DeriveSymbolMatch(SymbolLoadAttempt attempt,
                              const PdbIdentity& wanted,
                              const PdbIdentity& loaded) noexcept;

struct ModuleSymbolState final {
    std::string moduleName;  // 外来文本
    PdbIdentity wanted;      // 转储里 CodeView 记录声明的
    PdbIdentity loaded;      // 实际加载到的
    SymbolMatch match = SymbolMatch::NotAttempted;
    // attempt 与 match 都要留：SymbolMatch 只有规范给的四个值，
    // "没找到文件" 与 "找到了但装不进来" 都会落到 Absent，两者的区别只能靠 attempt
    // 与 outcome 保留（评审模式 4：失败语义不许塌成一个）。
    SymbolLoadAttempt attempt = SymbolLoadAttempt::NotAttempted;
    SymbolCacheSource cacheSource = SymbolCacheSource::Unknown;
    CollectionOutcome outcome;  // 加载失败保留原始错误码
};

// C-04 红线：只有 Matched 才允许给出确定的函数名与行号。
bool MayReportFunctionName(const ModuleSymbolState& state) noexcept;
bool MayReportSourceLine(const ModuleSymbolState& state) noexcept;

// 允许的归因层级。WrongVersion/Absent 最多到"模块+偏移"。
enum class SymbolAttribution {
    ModuleOnly,             // 连基址都没有，只能说模块
    ModulePlusOffset,       // "模块+0x偏移"
    FunctionPlusOffset,     // "模块!函数+0x偏移"
    FunctionAndSourceLine,  // 再加"源文件:行号"
};

const char* SymbolAttributionName(SymbolAttribution attribution) noexcept;

SymbolAttribution AllowedAttribution(const ModuleSymbolState& state,
                                     bool moduleBaseKnown) noexcept;

// C-04：网络符号下载必须"用户启用 + 可取消 + 有限时"。默认三样都没有。
struct SymbolServerPolicy final {
    bool userEnabled = false;
    bool cancellable = false;
    ScanBudget budget;  // 必须含 maxDurationNanos，否则"有限时"无从谈起
};

enum class SymbolServerDecision {
    Allow,
    RejectNotEnabled,      // 用户没开
    RejectNotCancellable,  // 没有取消通路
    RejectNoTimeBudget,    // 没有时间预算
};

const char* SymbolServerDecisionName(SymbolServerDecision decision) noexcept;

// 默认构造的策略必须被拒。判定顺序：开关 -> 取消 -> 时限。
SymbolServerDecision DecideSymbolServerFetch(const SymbolServerPolicy& policy) noexcept;

// ---------------------------------------------------------------------------
// C-05 栈与模块
// ---------------------------------------------------------------------------

enum class UnwindState {
    TruncatedNoData,  // 默认：没有 unwind 数据或转储不含该栈内存，到此为止
    TruncatedCorrupt, // 数据自相矛盾（栈指针倒退/越界），到此为止
    Guessed,          // 栈扫描出来的候选，不是展开结果
    Unwound,          // 用 unwind 数据正常展开
};

const char* UnwindStateName(UnwindState state) noexcept;

// 截断态之后不允许再有帧 —— 否则就是"拼接猜测帧"。
bool UnwindStateIsTerminal(UnwindState state) noexcept;

// 只有 Unwound 是可信帧。Guessed 不是。
bool UnwindStateIsTrustworthy(UnwindState state) noexcept;

struct StackFrame final {
    OptionalU64 address;
    OptionalU64 stackPointer;

    std::string moduleName;  // 外来文本
    OptionalU64 moduleBase;
    OptionalU64 offsetInModule;

    SymbolMatch symbolMatch = SymbolMatch::NotAttempted;
    std::string functionName;  // 只有 symbolMatch==Matched 才允许非空
    OptionalU64 functionOffset;
    std::string sourceFile;  // 同上
    OptionalU64 sourceLine;

    UnwindState unwindState = UnwindState::TruncatedNoData;

    // C-05：参数逐个三态。取不到的参数保留 unset，绝不填 0。
    std::vector<OptionalU64> availableArgs;
    bool argsComplete = false;

    // C-05：优化/内联导致的归因歧义要保留而不是抹平。
    // attributionAmbiguous 为真时 candidateFunctions 必须留下 >= 2 个候选。
    bool attributionAmbiguous = false;
    std::vector<std::string> candidateFunctions;
};

struct StackTrace final {
    std::vector<StackFrame> frames;
    CollectionOutcome outcome;
    CoverageAccount coverage;

    std::size_t unwoundCount() const noexcept;
    std::size_t guessedCount() const noexcept;
    std::size_t truncatedCount() const noexcept;
};

// ValidateStackTrace：拒绝不合法的栈，而不是"修正"它。
// 检查顺序固定（先边界后逐帧），返回第一条违规。
enum class StackValidation {
    Ok,
    FramesAfterTruncation,              // 截断帧后面还有帧 = 拼接了猜测帧
    // 没有匹配符号却给了函数名 —— 函数内偏移（functionOffset）同样算：没有解析出
    // 函数就没有"函数内偏移"这回事，那个数只能是拿错版 PDB 或猜出来的。
    FunctionNameWithoutMatchedSymbols,
    SourceLineWithoutMatchedSymbols,    // 没有匹配符号却给了行号
    // 没有匹配符号却给了候选函数名。候选同样会被渲染到 UI，只是从单数变复数：
    // 错版 PDB 解出来的名字挂上"候选"两个字并不会因此变成可用的信息（C-04 红线）。
    CandidatesWithoutMatchedSymbols,
    AmbiguityCollapsed,                 // 标了歧义却只留一个候选 = 抹平了歧义
    IncompleteArgumentsClaimedComplete, // 声称参数齐全但里面有未知
};

const char* StackValidationName(StackValidation validation) noexcept;

StackValidation ValidateStackTrace(const StackTrace& trace) noexcept;

// ---------------------------------------------------------------------------
// C-06 可疑模块解释
// ---------------------------------------------------------------------------

// 三种证据分开表达。它们的强度完全不同，合并即失真。
enum class ModuleEvidenceKind {
    OnStack,           // 模块出现在栈上（可能只是被调用者）
    FaultingIpModule,  // 故障 IP 落在该模块
    VerifierReported,  // Driver Verifier 明确点名
};

const char* ModuleEvidenceKindName(ModuleEvidenceKind kind) noexcept;

struct ModuleEvidenceItem final {
    ModuleEvidenceKind kind = ModuleEvidenceKind::OnStack;
    std::string moduleName;  // 外来文本

    // 这条证据自己的前提：来自哪一帧、那一帧是怎么来的。
    UnwindState frameUnwindState = UnwindState::TruncatedNoData;
    OptionalU64 frameIndex;

    // 故障 IP 是不是直接来自 trap frame / context record，而不是某个展开帧的返回地址。
    // 默认 false —— 默认不许免检。FaultingIpModule 证据只有在这一位为真、或者它所在
    // 的那一帧本身可信（Unwound）时才够格当"可查线索"：一帧已经被判定为
    // TruncatedCorrupt（数据自相矛盾）却仍据此点名某个第三方驱动，就是越权判定。
    bool ipFromContextRecord = false;

    std::string detail;  // 外来文本，原样保存
};

struct ModuleEvidenceGroup final {
    std::string moduleName;  // 首次出现时的原始写法（展示用）
    std::string moduleKey;   // ASCII 小写的分组键（不跨大小写以外做归一化）

    std::vector<ModuleEvidenceItem> onStack;
    std::vector<ModuleEvidenceItem> faultingIp;
    std::vector<ModuleEvidenceItem> verifier;

    bool isWellKnownSystemModule = false;

    std::size_t evidenceCount() const noexcept;
};

// 已知系统模块名单（写死在实现里，不从转储读）。命中只降低"线索"资格，不是判决。
bool IsWellKnownSystemModuleName(std::string_view moduleName) noexcept;

// C-06：不给根因，只给"这条线索够不够立案"。没有任何百分比。
enum class InvestigationLead {
    Undetermined,          // 默认：证据不足，无法确定
    SystemModuleOnly,      // 只有系统模块（ntoskrnl/hal/...）的栈或 IP 证据：不构成线索
    StackPresenceOnly,     // 只在可信帧的栈上出现：弱线索
    FaultingIpAttributed,  // 故障 IP 归属到该模块：可查线索
    VerifierNamed,         // Verifier 点名：最强的可查线索，仍然不是根因
};

const char* InvestigationLeadName(InvestigationLead lead) noexcept;

// 每一条证据自己的前提也要成立，否则不许升级线索等级：
//   * group.moduleKey 为空 = 这一组根本没有身份（GroupModuleEvidence 对空模块名就会
//     产出这样一组）。没有名字的模块拿不到任何线索，一律 Undetermined。
//   * faultingIp 证据需要 ipFromContextRecord 或该帧 Unwound，见 ModuleEvidenceItem。
//   * onStack 证据需要该帧 Unwound。
InvestigationLead ClassifyLead(const ModuleEvidenceGroup& group) noexcept;

// 按模块分组。O(n log n)：一次 stable_sort + 一趟扫描，不做两两比较。
std::vector<ModuleEvidenceGroup> GroupModuleEvidence(std::vector<ModuleEvidenceItem> items);

struct SuspectLead final {
    ModuleEvidenceGroup group;
    InvestigationLead lead = InvestigationLead::Undetermined;
};

struct SuspectReport final {
    std::vector<SuspectLead> leads;
    AnalysisConclusion conclusion = AnalysisConclusion::NoEvidence;
    std::vector<std::string> limitationKeys;  // i18n 键，UI 负责翻译
};

// stackOutcome 决定有没有观测。没有观测就是 NoEvidence，绝不是"未发现问题"。
// 本函数永不返回 NoDifferenceObserved：一份转储的前提就是确实崩了，
// "未发现差异"在这里是没有意义的结论。
SuspectReport BuildSuspectReport(std::vector<ModuleEvidenceGroup> groups,
                                 const CollectionOutcome& stackOutcome);

// ---------------------------------------------------------------------------
// C-07 缺失内存的边界
// ---------------------------------------------------------------------------

enum class ContentCategory {
    IrpObjects,
    LockObjects,       // ERESOURCE / 自旋锁
    FullProcessSpace,  // 完整进程地址空间
    PoolMemory,
    KernelModuleList,
    ThreadStacks,
    PhysicalMemory,
};

inline constexpr std::size_t kContentCategoryCount = 7;

const char* ContentCategoryName(ContentCategory category) noexcept;

enum class ContentPresence {
    Unknown,      // 默认：还没判定。红线：不许当成"没有"，更不许当成"有"
    NotIncluded,  // 转储格式/本文件不含 —— "转储未包含"
    NotParsable,  // 含但当前解析不了 —— "当前无法解析"
    Included,     // 含且可解析
};

const char* ContentPresenceName(ContentPresence presence) noexcept;

struct DumpContentAvailability final {
    // 值初始化即全 Unknown（Unknown 是第一个枚举量）。默认不是"包含"。
    std::array<ContentPresence, kContentCategoryCount> presence{};

    ContentPresence presenceOf(ContentCategory category) const noexcept;
    void set(ContentCategory category, ContentPresence value) noexcept;
};

// 由转储类型推出的**上界**，不是"确认包含"。
// 只有格式上确定不含的才写 NotIncluded；可能含的一律 Unknown，要靠实际解析确认。
DumpContentAvailability DeriveAvailabilityFromKind(DumpKind kind) noexcept;

enum class ContentQueryResult {
    Available,            // 可以去解析
    NotIncludedInDump,    // "转储未包含"
    NotParsableHere,      // "当前无法解析"
    UnknownAvailability,  // 还没判定 —— 不许当成"没有"
};

const char* ContentQueryResultName(ContentQueryResult result) noexcept;

// C-07 红线：任何一种非 Available 的结果都不许返回空对象冒充真实数据。
ContentQueryResult QueryContent(const DumpContentAvailability& availability,
                               ContentCategory category) noexcept;

// C-07：从转储以外补齐的数据必须单独标记来源并在报告里写明，
// 不得与转储内数据合并计数。
struct ExternalSupplement final {
    bool used = false;
    SourceRef source;         // used 时 origin 必须是 ExternalFile
    std::string disclosureKey;  // 报告里必须出现的说明键
};

bool SupplementDisclosed(const ExternalSupplement& supplement) noexcept;

// ---------------------------------------------------------------------------
// C-08 超时、取消与隔离
// ---------------------------------------------------------------------------

enum class HelperState {
    NotStarted,
    Starting,
    Ready,
    Busy,
    Stalled,       // 超出预算仍无响应
    Disconnected,  // 通信断了
    Cancelling,    // 已请求取消，仍在收尾（不得伪报已清理）
    Exited,
    Failed,
};

const char* HelperStateName(HelperState state) noexcept;
bool HelperStateIsTerminal(HelperState state) noexcept;

// "这一轮到底结算了没有"。只有 Ready（起好了、该给的都给了）与 Exited（正常退出）
// 算已结算；NotStarted/Starting/Busy/Cancelling 表示这一轮还没跑完，
// Stalled/Disconnected/Failed 表示跑坏了。
// 与 HelperStateIsTerminal 是两件事：Terminal 说的是"进程还在不在"，
// 这里说的是"这批结果算不算数"。一个 Busy 的 helper 进程活得好好的，
// 但它手上的结果集合天生不完整 —— 据此报"成功且未发现差异"就是"从没采到推出正常"。
bool HelperStateSettled(HelperState state) noexcept;

// C-08 红线：只允许结束**本模块拥有的** helper。
struct HelperOwnership final {
    std::string ownerModuleId;  // 谁启动的
    std::string helperId;       // helper 实例 id
    OptionalU64 processId;
    bool startedByThisModule = false;  // 默认 false —— 默认不许结束
};

enum class TerminateDecision {
    Allow,
    RejectNotOwned,          // 不是本模块启动的
    RejectOwnerMismatch,     // owner id 与请求方对不上
    RejectNoHelperIdentity,  // 连 helperId 都没有，无从确认要结束谁
};

const char* TerminateDecisionName(TerminateDecision decision) noexcept;

TerminateDecision DecideHelperTermination(const HelperOwnership& helper,
                                          std::string_view requestingModuleId) noexcept;

// C-08：卡住/断连/取消都要保留部分结果并明确标注中断原因。
struct InterruptedResult final {
    BudgetStop stop = BudgetStop::Continue;
    HelperState helperState = HelperState::NotStarted;
    CollectionOutcome outcome;
    CoverageAccount coverage;
    bool partialResultsRetained = false;
    std::vector<std::string> interruptionKeys;  // i18n 键
};

// haveAnyResult 为 false 时结果绝不会是 Partial：一次"什么都没采到"的中断
// 若报成 Partial，StatusCarriesObservation 就会放行，下游据此推出正向结论 ——
// 这正是"从没采到推出正常"。此时按停止原因落到 NotCollected/Timeout/Error。
//
// helperState 是**独立的第二维**，不许只看 stop：stop==Continue 只说明"预算没用完"，
// 它对"helper 到底跑没跑"一无所知。helper 没结算（HelperStateSettled 为假）时，
// Success 一律降级 —— 有结果降到 Partial，没结果降到 NotCollected。已经是
// Timeout/Error/NotCollected 的更严重结论保持不动，本函数只降级不升级。
InterruptedResult BuildInterruptedResult(BudgetStop stop,
                                         HelperState helperState,
                                         const ScanBudget& budget,
                                         CoverageAccount coverage,
                                         bool haveAnyResult);

// ---------------------------------------------------------------------------
// C-09 不可信路径与输出
// ---------------------------------------------------------------------------

// EscapeForReport：外来文本（模块名 / 文件路径 / 符号名 / 转储自带字符串）进
// HTML 报告前的唯一出口。
//   & < > " ' -> 实体引用
//   C0 控制字符与 0x7F -> "&#65533;"（U+FFFD 的十进制数字引用，纯 ASCII 输出）
//   >= 0x80 的字节原样透传，不破坏 UTF-8
// 换行/制表也被替换：这些字段里出现换行本身就是异常，报告自己的换行不经过本函数。
std::string EscapeForReport(std::string_view untrusted);

// 纯文本（.txt / TSV）报告字段的消毒：只把会打乱行列结构的控制字符换成 '?'，
// 不做 HTML 转义。与 EscapeForReport 是两条不同出口，不许互相替代。
std::string SanitizeForPlainTextField(std::string_view untrusted);

// C-09：只允许实现内固定的白名单命令。没有任何"拼参数"入口 —— 本文件不提供
// 命令构造函数，白名单是完整命令字符串，逐字节全等才通过。
std::span<const std::string_view> AllowedAnalysisCommands() noexcept;

bool IsSafeAnalysisCommand(std::string_view command) noexcept;

enum class CommandRejection {
    Accepted,
    Empty,
    TooLong,
    ContainsControlCharacter,
    ContainsShellMetacharacter,
    NotInWhitelist,
};

const char* CommandRejectionName(CommandRejection rejection) noexcept;

// 判定顺序固定：空 -> 过长 -> 控制字符 -> shell 元字符 -> 白名单。
CommandRejection ClassifyCommandRequest(std::string_view request) noexcept;

// C-09：路径按数据处理。返回值只用于**判定**，本函数绝不重写路径。
enum class PathRisk {
    Ok,
    Empty,
    TooLong,
    ControlCharacter,
    WildCard,             // * 或 ?
    ParentTraversal,      // 存在等于 ".." 的路径段
    AlternateDataStream,  // 驱动器冒号以外的 ':'
    // 保留设备名（CON/PRN/AUX/NUL/COM1-9/LPT1-9）**或** DOS 设备命名空间前缀
    // \\.\ / //./（\\.\PhysicalDrive0、\\.\pipe\x、\\?\GLOBALROOT\Device\...）。
    // 后者既不是远程路径也不是文件：允许打开就等于允许把裸盘或命名管道当转储喂进来，
    // 那是一条无限长、可变、由本地攻击者控制的字节流。
    DeviceName,
    // 段尾有 '.' 或 ' '。Windows 打开时会把它们剥掉，于是"被判定的字符串"与
    // "真正被打开的文件"不是同一个 —— 判定结果因此不可信，直接拒绝。
    TrailingDotOrSpace,
    UncOrRemote,          // \\server\share 或 //server/share（含 \\?\UNC\ 长路径写法）
};

const char* PathRiskName(PathRisk risk) noexcept;

// Win32 长路径前缀 \\?\（以及 \\?\UNC\）先被剥掉再判定：它是打开超过 MAX_PATH 的
// 转储文件的唯一写法，本身无害。不剥掉的话，前缀里的 '?' 会被通配符扫描一刀切成
// WildCard —— 合法的长路径转储永远打不开，而且 UI 给出的理由（"含通配符"）是错的，
// 用户无从修。剥掉之后 \\?\UNC\server\share\x 仍然是 UncOrRemote。
PathRisk ClassifyDumpPath(std::string_view path) noexcept;

// 只有 Ok 与 UncOrRemote 可以打开；UncOrRemote 还需要用户显式确认。
bool PathAcceptableForOpen(PathRisk risk) noexcept;
bool PathNeedsExplicitConfirmation(PathRisk risk) noexcept;

// C-09 纵深防御：对**已经生成的**报告片段做出口检查。即使某处忘了转义，
// 这一层也能在写文件前拦下。
enum class ReportOutputRisk {
    Ok,
    RawControlCharacter,   // \t \n \r 以外的控制字符
    // 需要用户点一下才会走出去：href/action/formaction/cite/content 指向
    // http(s)/ftp/file/UNC。
    ExternalLink,
    // 打开报告就**自动**发出去的外部请求。两类都算，因为后果一样：
    //   * 标签：img/iframe/object/embed/video/audio/source/link/base/meta/style
    //   * 属性：src/srcset/background/poster/data/style 里出现外部 URL、
    //     CSS 的 url(...) 或 @import —— 即使标签名本身人畜无害
    //     （<div style="background:url(https://…)">、<table background="//…">）。
    ExternalResourceTag,
    DebuggerMarkupLink,    // DML：<exec cmd="..."> / <link cmd="...">
    // <script> / on*= / javascript: / vbscript: / data:。
    // 判定前先把属性区里的字符引用折掉：浏览器解析 URL **之前**先解实体，
    // 所以 "&#106;avascript:" 对它来说就是 "javascript:"。
    ScriptOrEventHandler,
};

const char* ReportOutputRiskName(ReportOutputRisk risk) noexcept;

// 一趟扫描，取最高危的一项。优先级：
// 控制字符 > 脚本 > DML > 外部资源（标签或自动加载属性）> 外部链接 > Ok。
ReportOutputRisk ClassifyReportFragment(std::string_view fragment) noexcept;

// ---------------------------------------------------------------------------
// C-10 报告出处
// ---------------------------------------------------------------------------

struct EngineIdentity final {
    std::string engineId;       // "ksword.dumpfacts" / "dbgeng"
    std::string engineVersion;  // 空 = 未知。红线：不许写 "0.0" 冒充
    bool engineAvailable = false;
};

struct DumpInputIdentity final {
    std::string filePath;  // 原始路径（外来文本，进报告前过 EscapeForReport）
    OptionalU64 fileSize;
    std::string sha256Hex;  // 64 位十六进制小写；空 = 未计算，不是 "0"
    bool hashComputed = false;
    OptionalU64 lastModifiedUtc100ns;
};

struct DumpReportProvenance final {
    EngineIdentity engine;
    DumpInputIdentity input;
    SourceRef source;               // origin 必须是 OfflineSample
    CaptureWindow window;           // 分析发生的时刻
    CoverageAccount analysisScope;  // 分析范围
    std::vector<ModuleSymbolState> symbolStates;
    DumpContentAvailability availability;
    ExternalSupplement supplement;
};

// C-10：缺什么就报什么，而不是一个 bool "ok"。
enum class ProvenanceGap {
    MissingEngineIdentity,
    MissingEngineVersion,
    MissingInputPath,
    MissingInputSize,
    MissingInputHash,
    MissingAnalysisWindow,
    MissingSymbolStates,
    UnstatedAnalysisScope,
    WrongSourceOrigin,
    UndisclosedExternalSupplement,  // 用了转储外的数据却没写说明
};

const char* ProvenanceGapName(ProvenanceGap gap) noexcept;

std::vector<ProvenanceGap> AuditProvenance(const DumpReportProvenance& provenance);

// 默认构造的 provenance 必然返回 false（评审模式 3）。
bool ProvenanceReviewable(const DumpReportProvenance& provenance);

struct ReportField final {
    std::string key;    // ASCII i18n 键
    std::string value;  // 已经过 EscapeForReport 的值
};

// C-09 + C-10：报告头字段的唯一生成入口。所有外来文本在这里统一转义，
// 缺失值输出固定的 "dump.value.unknown" 键而不是 "0"/空串。
std::vector<ReportField> BuildProvenanceFields(const DumpReportProvenance& provenance);

// 缺失值在报告里的占位键。调用方按 i18n 翻译，不要自己拼中文。
inline constexpr std::string_view kUnknownValueKey = "dump.value.unknown";

} // namespace Ksword::Evidence
