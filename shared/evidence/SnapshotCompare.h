#pragma once

// D 模块：快照比较与变化解释。
//
// 这是**实体级**比较，不是文本行 diff。两份快照按实体身份配对，字段逐项给出
// 旧值/新值/来源/时间/证据引用；地址与排序不参与"有没有这个对象"的判断。
//
// 贯穿全模块的硬规则（为什么这样判，见各处 D-xx 注释）：
//   * D-01：选择范围不同**不是**对象被删除。删除结论只有在"新快照的选择范围
//     完全盖住旧快照的选择范围"时才成立；新增结论反过来。范围未声明即未知。
//   * D-02：身份走 ObjectIdentity。进程/线程/句柄/连接是实例，跨启动周期一律
//     不硬配；驱动/模块/服务/文件按逻辑身份可跨启动比较。无法稳定匹配时标
//     MatchConfidence::Uncertain，绝不落成一对假增删。
//   * D-03：内核地址先归一化成"匹配的映像身份 + RVA"，且**只有确认两侧映像可比
//     较时才归一化**。同映像不同装载基址无差异；不同版本相同 RVA 不是相同代码；
//     模块缺失一律不归一化。
//   * D-04：旧快照有数据而新快照来源失败/不支持/截断时，结论是 NotComparable 或
//     InsufficientCoverage，永远不是"全部对象已移除"。同一次比较里已成功覆盖的
//     分区照常比较，不被别的分区连坐。
//   * D-05：变化事实与复核解释是两个字段。本层的 ReviewNote 只承载调用方声明的
//     复核优先级与依据键，API 里没有 malicious / threat / risk / suspicious。
//   * D-06：持久化带 schema 与主/次版本。未知可选字段保留并原样回写，未知**主**
//     版本明确拒绝。读取器是纯函数，不碰任何文件，源数据不会被就地"修好"。
//   * D-07：脱敏在同一次导出内对同一原值使用同一替换值，不同原值不撞；被替换和
//     被删除的内容都会列进清单；源快照是 const 输入，不被覆盖。**未知可选字段
//     （D-06 承诺原样回写的那些）同样要脱敏**——否则敏感原值正好躲在它们里面
//     被原样导出，这是 D-07 点名禁止的"藏在原始字段里"。
//
// 本文件是 C++20、Qt-free、Win32-free，只用标准库。

#include "EvidenceEnvelope.h"
#include "EvidenceJson.h"
#include "ObjectIdentity.h"
#include "PeImageMap.h"  // 只读复用 RvaRange 与其区间判定

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace Ksword::Evidence {

// ---------------------------------------------------------------------------
// D-02：配置类对象的逻辑身份
//
// 服务、规则、设备名这类对象持久存在于注册表/磁盘上，重启后仍是同一个逻辑对象，
// 因此它们的身份里**没有** bootId —— 这正是与 ProcessInstanceId 相反的一面。
// ---------------------------------------------------------------------------
struct LogicalObjectId final {
    std::string domain;    // "service" / "rule" / "device" …；空即身份不成立
    std::string name;      // 域内唯一名
    std::string scopeKey;  // 可选的所属范围（策略集 / SID / 卷），缺失只降级不致错

    IdentityStrength strength() const noexcept;

    // D-02：键在这里对 name/scopeKey 做大小写折叠。服务名、注册表键名、SID 文本在
    // Windows 上都是大小写不敏感的，两个 collector（SCM 与注册表枚举）给出的大小写
    // 常常不同 —— 那是**表示**变化，不是对象变化。不折叠会让两侧落进不同的桶，
    // 直接造出一对假增删（D-02 明令禁止）。折叠只影响分桶，不代表"确认是同一个"：
    // 仅大小写不同的两条记录在 MatchLogicalObject 里最高只给 Candidate。
    std::string crossSessionKey() const;
};

// domain/name 任一为空 -> Candidate（身份不足，统一门槛压顶）。
// name/scopeKey 折叠后不同 -> NoMatch（同名不同作用域是两个对象）。
// 折叠后相同但原文大小写不同 -> Candidate：可能是同一个，但两侧表示不一致，
// 不足以"确认"，也绝不允许据此产出增删。
MatchResult MatchLogicalObject(const LogicalObjectId& a, const LogicalObjectId& b) noexcept;

// D-02：驱动/模块在快照层的身份键。
// 它在 DriverInstanceId::crossSessionKey() 之上再把 imagePath 折叠成大小写与分隔符
// 归一化的形式：PsLoadedModuleList、SCM 与磁盘枚举给出的内核模块路径在大小写和
// "\SystemRoot\" 前缀写法上本来就会不同，不折叠同样会造出假增删。
// 与逻辑身份同理，折叠只影响分桶：路径原文不同的两条记录在 MatchDriverInstance 里
// 仍然只能是 Candidate。
std::string SnapshotDriverKey(const DriverInstanceId& id);

// D-02：该实体类型能否跨启动周期比较。
// 实例对象（进程/线程/句柄/连接/设备对象）为 false —— 跨启动的"缺席"不是"被删除"。
bool KindComparableAcrossBoot(ObjectKind kind) noexcept;

// ---------------------------------------------------------------------------
// D-01：快照的选择范围
// ---------------------------------------------------------------------------
struct SnapshotScope final {
    std::string scopeId;                 // 域标识，例如 "services"；两侧不同即无交集
    bool declared = false;               // 是否声明过选择范围。未声明一律按未知处理
    bool wholeDomain = false;            // 声称覆盖整个域
    std::vector<std::string> selectors;  // 非全域时的具体筛选项（已归一化的键）
};

// 两份快照选择范围之间的关系。命名一律以"谁是子集"表述，避免宽窄词歧义。
enum class ScopeComparability {
    Unknown,               // 至少一侧未声明范围 —— 增删都不可推断
    Identical,             // 两侧范围一致
    EarlierSubsetOfLater,  // 旧 ⊂ 新：新快照看得更全，可判删除，不可判新增
    LaterSubsetOfEarlier,  // 新 ⊂ 旧：可判新增，不可判删除
    PartialOverlap,        // 互有独有项 —— 增删都不可推断
    Disjoint,              // 无交集
};

const char* ScopeComparabilityName(ScopeComparability value) noexcept;

ScopeComparability CompareScopes(const SnapshotScope& earlier, const SnapshotScope& later);

// D-01 的核心判据：只有新范围盖住旧范围时，"旧有新无"才允许被解释成移除。
bool RemovalInferable(ScopeComparability value) noexcept;
// 对称：只有旧范围盖住新范围时，"新有旧无"才允许被解释成新增。
bool AdditionInferable(ScopeComparability value) noexcept;

// D-02：两份快照的启动周期关系。
enum class CrossBootComparability {
    UnknownBoot,    // 至少一侧没有 bootId —— 无法证明同一次启动
    SameBoot,
    DifferentBoot,
};

const char* CrossBootComparabilityName(CrossBootComparability value) noexcept;

// ---------------------------------------------------------------------------
// 字段
// ---------------------------------------------------------------------------

// D-07：字段承载的敏感类别，供脱敏声明使用（值本身不因此改变比较语义）。
enum class RedactionClass {
    None,
    UserName,
    Hostname,
    FilePath,
    AccountSid,
};

const char* RedactionClassName(RedactionClass value) noexcept;
bool ParseRedactionClassName(std::string_view text, RedactionClass& out) noexcept;

// D-03：字段的比较语义。地址类字段绝不按原值比。
enum class FieldSemantics {
    Opaque,           // 按值比较（文本或整数）
    LoadBaseAddress,  // 映像装载基址：同映像不同基址不是差异
    KernelAddress,    // 内核绝对地址：归一化成"映像身份 + RVA"后再比
};

const char* FieldSemanticsName(FieldSemantics value) noexcept;
bool ParseFieldSemanticsName(std::string_view text, FieldSemantics& out) noexcept;

// Absent 是独立状态：它既不是空串也不是 0，比较时只会产出"未知"。
enum class FieldValueKind {
    Absent,
    Text,
    Number,
};

const char* FieldValueKindName(FieldValueKind value) noexcept;
bool ParseFieldValueKindName(std::string_view text, FieldValueKind& out) noexcept;

struct EntityField final {
    std::string name;
    FieldSemantics semantics = FieldSemantics::Opaque;
    FieldValueKind kind = FieldValueKind::Absent;
    std::string text;                              // kind == Text
    OptionalU64 number;                            // kind == Number
    U64Format numberFormat = U64Format::Decimal;   // 仅决定展示与持久化写法
    RedactionClass redaction = RedactionClass::None;
};

// ---------------------------------------------------------------------------
// D-03：地址归一化材料
// ---------------------------------------------------------------------------
struct SnapshotModule final {
    std::string moduleId;        // 快照内引用用的稳定 id
    DriverInstanceId identity;   // 映像身份：pdbSignature 或 timeDateStamp+imageSize+path
    OptionalU64 imageBase;
    OptionalU64 imageSize;

    // 该模块覆盖的 RVA 区间（复用 PeImageMap 的区间类型）。尺寸未知或越过 32 位
    // 时返回空区间 —— 空区间不 contains 任何 RVA，于是地址一律解析不到，不会被
    // 硬当成"落在本模块内"。
    RvaRange rvaExtent() const noexcept;
};

// 地址归一化的判定结果。每一档都必须能单独展示 —— 把它们塌成一个 bool 正是
// D-03 想禁止的（"不同版本的相同 RVA"会被当成"相同代码"）。
enum class AddressNormalizationState {
    NotApplicable,        // 该字段不是地址语义
    ValueMissing,         // 至少一侧地址未知
    ModuleNotFound,       // 至少一侧地址不落在任何已知模块内 -> 不归一化
    ImageIdentityWeak,    // 两侧映像只能候选匹配 -> 不确认可比，不归一化
    ImageVersionDiffers,  // 同一路径的两个不同版本 -> 相同 RVA 不是相同代码
    DifferentModule,      // 两侧解析到不同映像
    Normalized,           // 确认可比，已按 RVA 比较
};

const char* AddressNormalizationStateName(AddressNormalizationState value) noexcept;

struct AddressNormalization final {
    AddressNormalizationState state = AddressNormalizationState::NotApplicable;
    std::string earlierModuleId;
    std::string laterModuleId;
    OptionalU64 earlierRva;
    OptionalU64 laterRva;
};

// ---------------------------------------------------------------------------
// 快照
// ---------------------------------------------------------------------------

// D-01/D-04：一个采集分区（通常一个 collector 一个），自带来源、状态与覆盖账目。
// 分区是 D-04 "已成功覆盖部分仍可单独比较"的粒度：某个分区失败不牵连别的分区。
struct SnapshotPartition final {
    std::string partitionId;
    ObjectKind kind = ObjectKind::Unknown;
    EvidenceEnvelope envelope;
    bool coversScope = false;  // 该分区是否声称覆盖了本快照声明的选择范围
};

struct SnapshotEntity final {
    std::string partitionId;
    ObjectKind kind = ObjectKind::Unknown;

    // 身份载荷按 kind 取用。Handle/Connection/Device/Service/Unknown 在快照层用
    // 逻辑身份表达（句柄与连接的实例身份属于 X 模块的跨视图分析，不在 D 的语义里）。
    ProcessInstanceId process;
    ThreadInstanceId thread;
    DriverInstanceId driver;
    FileIdentity file;
    LogicalObjectId logical;

    std::string rawRecordId;      // D-05：回到源记录
    std::size_t displayOrder = 0; // D-02：仅用于证明"排序变了但对象没变"
    std::vector<EntityField> fields;

    // D-06：读入时遇到的未知可选字段原样保留，回写时原样吐出。
    JsonObject unknownFields;

    // 稳定身份键；身份不足时为空。D-02：驱动/模块与逻辑对象的键会先做表示归一化
    // （路径与名字的大小写、路径分隔符），见 SnapshotDriverKey / LogicalObjectId。
    std::string identityKey() const;
    std::string candidateKey() const;  // 弱身份去重键，只在本次比较内有效
    IdentityStrength strength() const noexcept;
    std::string displayText() const;
};

struct Snapshot final {
    std::string snapshotId;
    EvidenceEnvelope envelope;   // D-01：系统/启动标识、collector 版本、采集区间
    SnapshotScope scope;
    std::vector<SnapshotPartition> partitions;
    std::vector<SnapshotModule> modules;
    std::vector<SnapshotEntity> entities;

    JsonObject unknownFields;  // D-06：顶层未知可选字段

    const SnapshotPartition* findPartition(std::string_view partitionId) const noexcept;
    const SnapshotModule* findModule(std::string_view moduleId) const noexcept;
};

// ---------------------------------------------------------------------------
// 比较结果
// ---------------------------------------------------------------------------

// 某一侧对某个实体的"在场情况"。各种未知彼此可分 —— 塌成一个"没有"正是 D-04 的红线，
// 而把"来源失败"塞进"覆盖不足"同样是 D-04 禁止的混淆（两者的处置完全不同）。
enum class EntitySideState {
    Present,              // 该侧列出了这个实体
    AbsentCovered,        // 该侧采集成功、账目正面证明完整、范围也覆盖它 —— 确实没有
    AbsentOutOfScope,     // 该侧的选择范围不覆盖它 —— 不是"没有"
    UnknownSourceFailed,  // 该侧分区未采集/失败/不支持/拒绝访问
    UnknownCoverage,      // 该侧成功但被截断或账目不足以证明完整
    UnknownCrossBoot,     // D-02：该类实体不跨启动周期比较
    // D-02：该侧存在同一稳定键的多条记录，无法确定这一条对应哪一条。既不是"没有"，
    // 也不能说"在"——"在"会让 UI 读成两侧配上了。
    UnknownAmbiguousIdentity,
};

const char* EntitySideStateName(EntitySideState value) noexcept;

// D-02：配对置信度。Uncertain 表示"可能是同一个，但身份不足以确认"。
enum class MatchConfidence {
    NoMatch,     // 没有配上，且身份足够强，缺席本身有意义
    Uncertain,   // 身份不足或只有候选证据 —— 不得据此宣称同一对象或宣称增删
    Confirmed,   // 稳定身份配对
};

const char* MatchConfidenceName(MatchConfidence value) noexcept;

enum class EntityChange {
    Unchanged,             // 两侧都在，所有可比较字段一致，且没有不可比较字段
    PartiallyComparable,   // 两侧都在，已比较的字段一致，但有字段无法比较
    Modified,              // 两侧都在且至少一个字段确实变了
    Added,                 // 只在新快照出现，且范围与覆盖都支持"新增"结论
    Removed,               // 只在旧快照出现，且范围与覆盖都支持"移除"结论
    NotComparable,         // D-04：至少一侧未知/跨启动/范围外 —— 不给增删结论
    InsufficientCoverage,  // D-04：该侧采到了但覆盖不足以判定
};

const char* EntityChangeName(EntityChange value) noexcept;

enum class FieldChange {
    Unchanged,
    NormalizedUnchanged,  // D-03：原值不同但归一化后相同（同映像不同基址）
    Changed,
    Unknown,              // 至少一侧未知 —— 不得当成变化
    NotComparable,        // D-03：映像不可比 / 模块缺失 / 值表示形式不同
};

const char* FieldChangeName(FieldChange value) noexcept;

// D-05：一条字段变化的完整说明。旧值、新值、来源、时间、证据引用都在这里。
struct FieldDelta final {
    std::string name;
    FieldSemantics semantics = FieldSemantics::Opaque;
    FieldChange change = FieldChange::Unknown;

    bool earlierKnown = false;
    std::string earlierText;   // 展示串；earlierKnown 为 false 时恒为空
    bool laterKnown = false;
    std::string laterText;

    std::string earlierCollectorId;
    std::string laterCollectorId;
    OptionalU64 earlierObservedUtc100ns;
    OptionalU64 laterObservedUtc100ns;
    std::string earlierEvidenceId;
    std::string laterEvidenceId;

    AddressNormalization normalization;
};

// D-05：复核解释。与变化事实分开存放，默认 NotAssessed —— 引擎自己不发明优先级，
// 只执行调用方声明的规则。这里没有、也不会有 malicious / risk / threat 字段。
enum class ReviewPriority {
    NotAssessed,
    Informational,
    NeedsReview,   // 需要人来看一眼，不是"恶意"
};

const char* ReviewPriorityName(ReviewPriority value) noexcept;

struct ReviewNote final {
    ReviewPriority priority = ReviewPriority::NotAssessed;
    std::vector<std::string> reasonKeys;  // i18n 键；UI 负责翻译
};

struct EntityDelta final {
    std::string partitionId;
    ObjectKind kind = ObjectKind::Unknown;
    std::string identityKey;   // 空表示身份不足（此时 candidateKey 非空）
    std::string candidateKey;
    IdentityStrength strength = IdentityStrength::Unusable;
    std::string displayText;

    EntitySideState earlierState = EntitySideState::UnknownSourceFailed;
    EntitySideState laterState = EntitySideState::UnknownSourceFailed;
    MatchConfidence matchConfidence = MatchConfidence::NoMatch;
    EntityChange change = EntityChange::NotComparable;

    std::vector<FieldDelta> fields;           // 有话可说的字段（变化/未知/不可比较）
    std::vector<std::string> limitationKeys;  // 为什么不可比较

    std::string earlierRawRecordId;
    std::string laterRawRecordId;
    std::string earlierEvidenceId;
    std::string laterEvidenceId;
    OptionalU64 earlierObservedUtc100ns;
    OptionalU64 laterObservedUtc100ns;

    std::size_t earlierDisplayOrder = 0;
    std::size_t laterDisplayOrder = 0;
    bool displayOrderChanged = false;  // D-02：排序变化被单独记录，不生成增删

    ReviewNote review;  // D-05：与上面的事实字段互不推导
};

// D-01/D-04：逐分区账目。分区在某一侧缺席时会被显式记成 NotCollected 并计入，
// 绝不"整轮缺席就当没发生过"。
struct PartitionAccount final {
    std::string partitionId;
    ObjectKind kind = ObjectKind::Unknown;
    bool earlierPresent = false;
    bool laterPresent = false;
    CollectionStatus earlierStatus = CollectionStatus::NotCollected;
    CollectionStatus laterStatus = CollectionStatus::NotCollected;
    bool earlierUsableForAbsence = false;  // 该侧是否有资格支撑"确实没有"
    bool laterUsableForAbsence = false;
    bool comparable = false;               // 两侧都携带观测
    AnalysisConclusion conclusion = AnalysisConclusion::NoEvidence;
    std::size_t entitiesCompared = 0;
    std::size_t entitiesNotComparable = 0;
    std::vector<std::string> limitationKeys;
};

struct SnapshotComparison final {
    ScopeComparability scope = ScopeComparability::Unknown;
    CrossBootComparability boot = CrossBootComparability::UnknownBoot;

    std::vector<EntityDelta> deltas;         // 按 (partitionId, 键) 稳定排序
    std::vector<PartitionAccount> partitions;
    TrustStatement trust;
    AnalysisConclusion conclusion = AnalysisConclusion::NoEvidence;

    std::size_t unchangedCount = 0;
    std::size_t partiallyComparableCount = 0;
    std::size_t modifiedCount = 0;
    std::size_t addedCount = 0;
    std::size_t removedCount = 0;
    std::size_t notComparableCount = 0;
    std::size_t insufficientCoverageCount = 0;

    // 内部一致性自检。false 说明计数口径与逐条结论对不上，UI 必须降级展示。
    // 判据见 CheckComparisonSelfConsistency —— 它只读本结构体已发布的字段，
    // 不复用产生这些字段的中间变量，否则"自检"只是把同一个变量抄一遍。
    bool selfCheckPassed = true;

    std::vector<std::string> limitationKeys;
};

// 对一份**已经产出**的比较结果做独立复核：逐条重算计数、核对每条增删所依据的分区
// 账目、核对每条结论与其字段清单相容。CompareSnapshots 用它填 selfCheckPassed，
// 调用方也可以对反序列化或跨进程传回来的结果再核一次。
//
// 之所以是公开函数而不是内联在 CompareSnapshots 里：判据必须能被独立构造的反例
// 打成 false，否则这个不变式永远无法被测试证伪（旧实现就是这样）。
bool CheckComparisonSelfConsistency(const SnapshotComparison& comparison);

// D-05：调用方声明的复核规则。partitionId/fieldName 为空表示"任意"。
struct ReviewRule final {
    std::string partitionId;
    std::string fieldName;
    ReviewPriority priority = ReviewPriority::Informational;
    std::string reasonKey;
};

struct SnapshotCompareOptions final {
    std::vector<ReviewRule> reviewRules;
    bool emitUnchanged = true;  // false 时结果里不保留 Unchanged 条目（计数仍然准）
};

SnapshotComparison CompareSnapshots(const Snapshot& earlier,
                                    const Snapshot& later,
                                    const SnapshotCompareOptions& options = SnapshotCompareOptions{});

// ---------------------------------------------------------------------------
// D-08：预期变化清单核对（离线这一半）
//
// 目标环境实测负责"只改自有对象、采前后快照、再清理"；本层只负责核对结果是否
// 恰好包含预先声明的变化。未声明的变化只被列出来，不做任何归因。
// ---------------------------------------------------------------------------
struct ExpectedChange final {
    std::string partitionId;
    // 二选一：强身份用 identityKey（= EntityDelta::identityKey）；弱身份对象没有
    // 跨会话主键，只能用本次比较内的 candidateKey（= EntityDelta::candidateKey）。
    // 两个都空的声明**没有指向任何对象**，会被记进 invalid 而不是被随便配上一条。
    std::string identityKey;
    std::string candidateKey;
    EntityChange change = EntityChange::Modified;
    std::vector<std::string> fieldNames;
};

// D-08：核对结论。三态而不是一个 bool —— "什么都没声明"与"声明的都观察到了"
// 绝不能是同一个值，否则一份忘了填清单的验收报告会自动变成绿的。
enum class ExpectationOutcome {
    NotAssessed,  // 没有声明，或这份比较根本没有可用证据 —— 无从核对
    Satisfied,    // 每一条声明都在有证据的比较里被观察到
    Violated,     // 至少一条声明没被观察到，或声明本身不可核对
};

const char* ExpectationOutcomeName(ExpectationOutcome value) noexcept;

struct ExpectationCheck final {
    ExpectationOutcome outcome = ExpectationOutcome::NotAssessed;
    std::vector<std::string> satisfied;
    std::vector<std::string> missing;         // 声明了却没观察到
    std::vector<std::string> unexpectedKeys;  // 观察到但未声明 —— 只记录
    // 声明本身不可核对：身份键为空，或它指向的分区在本次比较里不可比较。
    // 元素是该声明的 partitionId + '/' + 身份键（键为空时是 "<no-identity>"）。
    std::vector<std::string> invalid;
    // 恒等于 outcome == Satisfied。NotAssessed 也是 false —— 无从核对不是通过。
    bool allSatisfied = false;
};

ExpectationCheck CheckExpectedChanges(const SnapshotComparison& comparison,
                                      const std::vector<ExpectedChange>& expected);

// ---------------------------------------------------------------------------
// D-06：持久化
// ---------------------------------------------------------------------------
inline constexpr const char* kSnapshotSchemaId = "ksword.snapshot";
inline constexpr std::uint32_t kSnapshotSchemaMajor = 1;
inline constexpr std::uint32_t kSnapshotSchemaMinor = 0;

enum class SnapshotLoadStatus {
    Ok,
    OkWithUnknownFields,      // 有未知可选字段，已原样保留
    EmptyInput,
    MalformedJson,
    MissingSchema,
    WrongSchemaId,
    UnsupportedMajorVersion,  // 明确拒绝，不做"尽力而为"的解析
    MissingRequiredField,
    InvalidFieldValue,        // 含未知枚举名 —— 不静默回落到默认值
    // 文档本身合法，只是超过了本次调用给的解析上限（字节 / 节点 / 深度）。
    // 它必须与 MalformedJson 分开：一份合法的大快照和一份损坏文件对使用者的
    // 处置完全不同（抬高上限 vs. 这份文件坏了），D-06 要求错误状态明确。
    LimitExceeded,
};

const char* SnapshotLoadStatusName(SnapshotLoadStatus value) noexcept;

// D-06 + 7.2：快照持久化用的解析上限。
//
// JsonLimits 的默认值是给**不可信输入**用的（32 MiB / 524,288 节点 / 64 MiB 节点
// 预算），而 7.2 规定的 L1 负载是 100,000 条实体记录 —— 本模块自己写出来的合法
// 文档在那个规模下有约 100 MiB、数百万节点，用通用默认值一律读不回来。快照文件
// 是本机刚写出的会话数据，因此这里给一份显式的持久化档位；需要处理外来文件的
// 调用方仍可传自己的 JsonLimits。
JsonLimits SnapshotJsonLimits() noexcept;

struct SnapshotLoadResult final {
    SnapshotLoadStatus status = SnapshotLoadStatus::EmptyInput;
    Snapshot snapshot;
    std::uint32_t versionMajor = 0;
    std::uint32_t versionMinor = 0;
    std::vector<std::string> unknownFieldPaths;  // 保留下来的未知可选字段位置
    std::string errorDetail;                     // 原始错误说明，不猜、不美化
    std::size_t errorOffset = 0;

    bool ok() const noexcept {
        return status == SnapshotLoadStatus::Ok || status == SnapshotLoadStatus::OkWithUnknownFields;
    }
};

std::string WriteSnapshotJson(const Snapshot& snapshot, unsigned indent = 0);

// 纯函数：只读文本，不打开也不写任何文件。失败时 snapshot 保持默认构造 ——
// 不留半个解析到一半的对象，调用方就无从"顺手存回去"覆盖源数据（D-06）。
SnapshotLoadResult ReadSnapshotJson(std::string_view text);
SnapshotLoadResult ReadSnapshotJson(std::string_view text, const JsonLimits& limits);

// ---------------------------------------------------------------------------
// D-07：脱敏
// ---------------------------------------------------------------------------
struct RedactionOptions final {
    bool redactUserNames = true;
    bool redactHostnames = true;
    bool redactSids = true;
    // 采集器原始错误文本经常带完整路径。true 时整段删除并登记在 removedFieldPaths，
    // false 时按其它规则替换。删除与替换必须能被分辨，所以是两个清单。
    bool dropCollectorMessages = false;
};

struct RedactionMapping final {
    RedactionClass cls = RedactionClass::None;
    std::string original;     // 仅存在于内存，供一致性核对；绝不写进导出
    std::string replacement;  // "<user-1>" 之类的稳定占位符
};

struct RedactionReport final {
    std::vector<RedactionMapping> mappings;
    std::vector<std::string> replacedFieldPaths;  // 被替换的字段位置
    std::vector<std::string> removedFieldPaths;   // 被整体删除的字段位置
    std::size_t replacementCount = 0;

    // 7.3：本次脱敏被调用方取消。此时 redact 的输出被清空 —— 半脱敏的快照比不
    // 脱敏更危险（看着像已处理，实际还带着原值），所以取消一律不交付部分结果。
    bool cancelled = false;

    // 7.3 的可核查性：实际做过的"候选串比较"次数。朴素实现是
    //   文本长度 × 不同占位名数量，而占位名是从数据里自动收割的，会随快照增长。
    // 这个计数让"扫描代价与占位名数量无关"成为可断言的事实，而不是靠计时。
    std::size_t needleComparisons = 0;
};

// 同一个 session 内的多次 redact 共享映射表 —— 这正是"同一导出内一致映射"。
// 源快照是 const 输入，任何情况下都不会被修改。
class RedactionSession final {
public:
    // 7.3：本地可中断工作必须有取消点。返回 true 表示调用方要求停止。
    using CancelHook = std::function<bool()>;

    RedactionSession() = default;
    explicit RedactionSession(RedactionOptions options) : options_(std::move(options)) {}

    // 先学习再改写：free-text 字段里可能出现只在别处路径里露过面的用户名。
    // 需要跨多份快照完全一致时，调用方可以先对全部快照 learn 一遍再逐份 redact。
    void learn(const Snapshot& source);

    // 取消时 out 被置回默认构造，report().cancelled 为 true。
    void redact(const Snapshot& source, Snapshot& out);

    void setCancelHook(CancelHook hook) { cancel_ = std::move(hook); }

    const RedactionReport& report() const noexcept { return report_; }
    const RedactionOptions& options() const noexcept { return options_; }

    // 查询某个原值当前的占位符；未登记时返回空串。给测试与一致性核对用。
    std::string replacementFor(RedactionClass cls, std::string_view original) const;

private:
    std::string assign(RedactionClass cls, const std::string& original);

    RedactionOptions options_;
    RedactionReport report_;
    CancelHook cancel_;
    std::map<std::string, std::string> map_;  // 键 = 类别 + '\x1F' + 小写原值
    std::size_t userCount_ = 0;
    std::size_t hostCount_ = 0;
    std::size_t sidCount_ = 0;
};

void RedactSnapshot(const Snapshot& source,
                    const RedactionOptions& options,
                    Snapshot& out,
                    RedactionReport& report);

} // namespace Ksword::Evidence
