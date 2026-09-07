#pragma once

// M 模块：区域证据模型、部分读取账目、可执行区域线索与 pool 归因边界。
//
// 对应验收：
//   M-01 区域信息语义（字段按来源分开；未走 VAD 不得显示"VAD 已验证"）
//   M-02 安全读取与部分结果（孔洞必须是孔洞；完整成功与部分成功不混用）
//   M-07 可执行区域线索（规则逐条列出事实，不靠单个属性判恶意）
//   M-09 内核 pool 归因边界（直接证据/候选/未知三档；不生成调用栈）
//   M-10 扫描预算（范围校验与预算停止复用 ScanBudget.h，不另造判据）
//
// 这一层没有 malicious/threat/score 字段，也没有 callStack 字段 —— 不是忘了加，
// 是规范禁止：单个属性只能产出线索，没有事先采集的分配栈就必须是未知。

#include "EvidenceEnvelope.h"
#include "LosslessValue.h"
#include "ObjectIdentity.h"
#include "ScanBudget.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace Ksword::Evidence {

// ---------------------------------------------------------------------------
// M-01：区域信息语义
// ---------------------------------------------------------------------------
enum class RegionState {
    Unknown,
    Free,
    Reserved,
    Commit,
};

const char* RegionStateName(RegionState state) noexcept;

enum class RegionType {
    Unknown,
    Private,
    Mapped,
    Image,
};

const char* RegionTypeName(RegionType type) noexcept;

// 区域记录的来源。R3 的 VirtualQuery 与 R0 的 VAD 遍历是两条独立证据，
// 必须在同一张表里区分开，不能合并成一个"内存区域"就完事。
enum class RegionEvidenceSource {
    R3VirtualQuery,   // 用户态查询：可用但看不到 VAD 层事实
    R0VadWalk,        // 内核 VAD 遍历：需要已验证的 profile
    OfflineSnapshot,  // 已保存会话/转储里的区域记录
};

const char* RegionEvidenceSourceName(RegionEvidenceSource source) noexcept;

struct RegionProtection final {
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool copyOnWrite = false;
    bool guard = false;
    bool noAccess = false;
    OptionalU64 rawValue;  // 原始 PAGE_* 值；来源没给就是 unset，不补 0
};

// VAD 侧事实。只有真的走了 VAD 才允许填，且必须记录用的哪个 profile（M-06 边界）。
struct VadEvidence final {
    OptionalU64 vadNodeAddress;
    OptionalU64 startingVpn;
    OptionalU64 endingVpn;
    OptionalU64 vadFlagsRaw;
    std::string profileId;          // 空表示没有可验证的 profile
    bool profileVerified = false;   // profile 与当前内核匹配且已校验

    // 四个关键字段齐全 + profile 已验证才算"这条 VAD 证据可用"。
    bool complete() const noexcept;
};

struct RegionRecord final {
    OptionalU64 base;
    OptionalU64 size;
    RegionState state = RegionState::Unknown;
    RegionType type = RegionType::Unknown;
    RegionProtection protection;
    OptionalU64 allocationBase;
    RegionProtection allocationProtect;
    std::string mappedPath;         // 空表示"来源没给"，不等于"是私有内存"
    RegionEvidenceSource source = RegionEvidenceSource::R3VirtualQuery;

    VadEvidence vad;
    ProcessInstanceId owner;
    std::string evidenceId;         // 指回产生该行的 envelope
};

// M-01 硬规则：没有走 VAD 就绝不允许输出"VAD 已验证"。
// 光有 vad 字段不够 —— 来源必须是 R0VadWalk，且 profile 经过验证。
bool VadVerified(const RegionRecord& record) noexcept;

// 区域的地址范围。base/size 缺一即返回 false（不拿 0 冒充）。
bool RegionRange(const RegionRecord& record, AddressRange& out) noexcept;

// ---------------------------------------------------------------------------
// M-02：安全读取与部分结果
// ---------------------------------------------------------------------------

// 单次读取的最大跨度。超过就拒绝分配，避免"为了完成进度条"而吞掉整块 RAM（M-10）。
constexpr std::uint64_t kMaxReadSpanBytes = 64ULL * 1024ULL * 1024ULL;

// ReadSpan 把"读到的字节"和"哪些位置根本没读到"分成两个数组。
// present 为 false 的位置 bytes 里的值没有意义，任何调用方都不得把它当数据 ——
// 补 0 后当数据正是 M-02 明令禁止的行为。
struct ReadSpan final {
    AddressRange range;
    std::vector<std::uint8_t> bytes;
    std::vector<bool> present;
    CollectionOutcome outcome;
    // M-05：这一段字节是"什么时候"读到的。unset 表示来源没记录时刻 —— 那就无法
    // 证明它和别的段属于同一次原子观测，合并时只能降级，不许默认当成同一时刻。
    OptionalU64 observedUtc100ns;

    bool consistent() const noexcept;          // 三者长度自洽
    std::uint64_t presentCount() const noexcept;
    bool hasHole() const noexcept;
};

// 按范围建一个全孔洞的空 span。长度为 0 或超过 kMaxReadSpanBytes 时返回
// outcome=Error 的空 span，不做分配。
ReadSpan MakeEmptyReadSpan(const AddressRange& range);

// 把一段实际读到的字节写进 span 并标为 present。越界返回 false 且不写入。
bool ApplyReadChunk(ReadSpan& span,
                    std::uint64_t address,
                    const std::uint8_t* data,
                    std::size_t length);

// 取单个字节。孔洞返回 false —— 调用方拿不到"0"，因此不会误当数据。
bool ByteAt(const ReadSpan& span, std::uint64_t address, std::uint8_t& out) noexcept;

// M-02：孔洞的精确范围（极大连续段）。全部可读时返回空。
std::vector<AddressRange> DescribeHoles(const ReadSpan& span);

// 依据孔洞情况给出采集状态：全读到 = Success，有孔洞 = Partial，一个都没读到
// 且没有更具体的错误 = Error。完整成功与部分成功因此不会混用。
CollectionStatus ClassifyReadSpan(const ReadSpan& span) noexcept;

// F-06 账目：请求范围、成功/失败字节数。孔洞进 failed，不进 succeeded。
CoverageAccount BuildReadCoverage(const ReadSpan& span);

// M-05：多段观测之间的时刻关系。只有"能证明来自同一次观测"才允许 Success。
enum class MergeObservationTiming {
    SingleObservation,       // 只有一段输入，或全部输入带同一个已记录的采集时刻
    MultipleObservations,    // 输入来自两个及以上不同的采集时刻
    ObservationTimeUnknown,  // 多段输入里至少一段没记录时刻，无法证明它们同时
};

const char* MergeObservationTimingName(MergeObservationTiming timing) noexcept;

// 合并多个 span。M-05 的通过条件是"不会把两次不同时间的观测包装成原子快照"，
// 所以判据是**采集时刻**，不是字节值：两段字节恰好相同不能证明它们同时被读到。
struct MergedReadSpan final {
    ReadSpan span;
    std::vector<AddressRange> conflictingRanges;
    // 每个字节的来源采集时刻，与 span.bytes 等长；孔洞、或来源未记时刻处为 unset。
    // M-05 要求"分时记录"，所以来源时刻必须逐段保留，而不是合并后就丢掉。
    std::vector<OptionalU64> byteObservedUtc100ns;
    MergeObservationTiming timing = MergeObservationTiming::SingleObservation;
};

// spans 按读取顺序传入；冲突字节保留最后一次（较新）的值，同时记入 conflictingRanges。
// 只要 timing 不是 SingleObservation，结果一律不是 Success —— 哪怕一个字节都没冲突。
MergedReadSpan MergeReadSpans(const std::vector<ReadSpan>& spans);

// ---------------------------------------------------------------------------
// M-02 + M-10：有界读取
// ---------------------------------------------------------------------------

// 一次分块读取的结果。F-05：失败必须把原始错误码交回来 —— 只有一个"拷了几个
// 字节"的返回值时，STATUS_ACCESS_DENIED、目标进程已退出、页不可读长得一模一样。
struct ChunkReadResult final {
    std::size_t copied = 0;   // 实际拷贝的字节数；0 < copied < bytes 是合法且常见的
    CollectionStatus status = CollectionStatus::NotCollected;
    OptionalU64 nativeCode;         // NTSTATUS / Win32 / HRESULT 原值，未知即 unset
    std::string nativeCodeDomain;   // "NTSTATUS" / "WIN32" / "HRESULT" / ""
    std::string message;            // 来源给的原文，不是我们编的解释
};

// 分块读取回调。copied 表达真实驱动的"部分复制"语义（不是只有成功/失败两态），
// 其余字段把失败原因原样交回来，供 ReadRangeBounded 写进 outcome。
using ChunkReader = std::function<void(std::uint64_t address,
                                       std::uint8_t* out,
                                       std::size_t bytes,
                                       ChunkReadResult& result)>;

struct BoundedReadRequest final {
    AddressRange requested;
    AddressRange approved;             // 用户已批准范围；length==0 表示未限定
    ScanBudget budget;
    std::uint64_t chunkSize = 0x1000;  // 按页切块，页边界因此必然被覆盖到
    OptionalU64 observedUtc100ns;      // 本次采集时刻，原样写进 span（M-05）

    // 可选：把"已耗时"和"是否取消"交给调用方注入，避免这一层依赖时钟或线程，
    // 也让离线测试能确定性地触发时间预算与取消。
    std::function<std::uint64_t()> elapsedNanos;
    std::function<bool()> cancelRequested;
};

// M-10：ReadRangeBounded 自己的拒绝档位。RangeValidation 定义在 ScanBudget.h，
// 里面没有"超过单次跨度上限"和"没有预算"这两档；把它们判成 Ok 会让调用方以为
// "合法范围、没命中预算、正常跑完"。所以这两档在本模块自己的返回结构上表达。
enum class BoundedReadRejection {
    None,
    InvalidRange,     // ValidateRange 拒绝；具体原因见 BoundedReadResult::validation
    ReversedRange,    // (begin,end) 入口里 end < begin
    ExceedsMaxSpan,   // 请求跨度超过 kMaxReadSpanBytes
    NoBudget,         // request.budget 一条上限都没设
};

const char* BoundedReadRejectionName(BoundedReadRejection rejection) noexcept;

struct BoundedReadResult final {
    ReadSpan span;
    CoverageAccount coverage;
    RangeValidation validation = RangeValidation::Ok;
    // rejection != None 时一个字节都没读；此时 stop 保持 Continue 没有任何含义，
    // 调用方必须先看 rejection 再看 stop。
    BoundedReadRejection rejection = BoundedReadRejection::None;
    BudgetStop stop = BudgetStop::Continue;
};

// 非法范围、超跨度上限、无预算一律拒绝，一个字节都不读；
// 合法范围按预算停止并保留已完成部分。
BoundedReadResult ReadRangeBounded(const BoundedReadRequest& request, const ChunkReader& reader);

// M-10：(begin,end) 形式的入口。AddressRange 用 (begin,length) 表达，逆序范围在
// 那种表示里根本无法出现 —— 所以"逆序"只能在这个接受 end 的入口里判。这里判，
// 并明确拒绝。request.requested 被 begin/end 覆盖，其余字段（预算、块大小、回调）照用。
BoundedReadResult ReadRangeBoundedFromEndpoints(std::uint64_t begin,
                                                std::uint64_t end,
                                                const BoundedReadRequest& request,
                                                const ChunkReader& reader);

// ---------------------------------------------------------------------------
// M-09：归因三档。M-07 的归属字段也用同一套。
// ---------------------------------------------------------------------------
enum class OwnerAttribution {
    DirectEvidence,  // 有事先采集的分配事件/映射对象等直接证据
    Candidate,       // 只有标签、范围命中一类的间接线索
    Unknown,         // 没有可用依据 —— 就是未知，不许降格成"系统"或"未知驱动"
};

const char* OwnerAttributionName(OwnerAttribution attribution) noexcept;

// pool tag -> 已知使用者。同一个 tag 被多个组件使用是常态，所以这是一张多值表。
struct PoolTagOwnerEntry final {
    std::string tag;
    std::string ownerId;      // 归一化的驱动/组件标识
    std::string sourceNote;   // 这条映射本身从哪来（知识库版本 / 本机符号）
};

struct PoolAttributionResult final {
    OwnerAttribution attribution = OwnerAttribution::Unknown;
    std::vector<std::string> candidateOwners;  // Candidate 时列出全部候选，不只留一个
    std::vector<std::string> facts;            // 逐条依据，可回源
    // 分配栈只有事先采集才可能有。这里永远只是一个"有没有"的事实位，
    // 本模块不提供任何生成调用栈的入口（M-09）。
    bool allocationStackAvailable = false;
};

// M-09 硬规则：标签命中**只能**是 Candidate，哪怕表里只有一个 owner。
PoolAttributionResult AttributeByTag(const std::string& tag,
                                     const std::vector<PoolTagOwnerEntry>& knownTagOwners);

// 事先采集到的分配事件。captured 为假就是没有，绝不构造。
struct PoolAllocationEvent final {
    bool captured = false;
    DriverInstanceId allocator;
    OptionalU64 eventUtc100ns;
    std::string eventSourceId;  // 采集器 id，例如 "etw.pool.alloc"
};

// 只有带上事先采集的分配事件才可能到 DirectEvidence；否则退回 tag 那一档。
PoolAttributionResult AttributeByAllocationEvent(const PoolAllocationEvent& event,
                                                 const PoolAttributionResult& tagFallback);

// ---------------------------------------------------------------------------
// M-07：可执行区域线索
// ---------------------------------------------------------------------------

// 与磁盘映像的字节比对结果。没做比对就是没做，不能用"没差异"顶替。
struct ImageBytesComparison final {
    bool compared = false;
    CollectionOutcome outcome;
    std::string onDiskPath;
    std::vector<AddressRange> differingRanges;  // 精确差异范围（虚拟地址）
    // 未做重定位/导入表/热补丁归一化时，差异里混着正常改动，只能算线索。
    bool relocationsApplied = false;
};

// 线程起始地址事实。startAddress 未知就是 unset。
struct ThreadStartFact final {
    ThreadInstanceId thread;
    OptionalU64 startAddress;
    bool startAddressInsideRegion = false;
    std::string startAddressMappedPath;  // 空表示归属未知，不是"没有归属"
};

struct ExecutableRegionInput final {
    RegionRecord region;
    ImageBytesComparison imageComparison;
    std::vector<ThreadStartFact> threads;
    // 是否拿到了区域归属的直接证据（section 对象 / 映射文件句柄等）。
    bool regionOwnerKnown = false;
};

// 一条规则的输出。注意这里没有 malicious/score 字段：规则只交事实。
struct ExecutableRegionFinding final {
    std::string ruleId;
    std::uint32_t ruleVersion = 0;
    std::vector<std::string> facts;   // 该规则实际依据的事实，key=value，可回源
    OwnerAttribution attribution = OwnerAttribution::Unknown;
    std::vector<std::string> candidateOwners;
    CollectionOutcome inputOutcome;   // 该规则依赖输入的采集状态
};

struct ExecutableRegionReport final {
    std::uint32_t ruleSetVersion = 1;
    std::vector<ExecutableRegionFinding> findings;
    OwnerAttribution attribution = OwnerAttribution::Unknown;
    // 只在"做过比对且比对完整"时才可能是 DifferenceObserved / NoDifferenceObserved；
    // 单纯的 private RX 只到 Indeterminate（有线索，不足以判定）。
    AnalysisConclusion conclusion = AnalysisConclusion::NoEvidence;
};

// 规则 id 常量，供 UI 与导出稳定引用。
extern const char* const kRuleIdPrivateExecutable;      // mem.exec.private
extern const char* const kRuleIdImageBytesDiffer;       // mem.exec.image-bytes-differ
extern const char* const kRuleIdThreadOriginMismatch;   // mem.exec.thread-origin-mismatch
// F-05：起始地址根本没采集到，是"没有观测"，不是"归属不一致"。两者混用同一个
// ruleId 会让一条零观测的 finding 把结论从 NoEvidence 抬成 Indeterminate。
extern const char* const kRuleIdThreadOriginUnknown;    // mem.exec.thread-origin-unknown

ExecutableRegionReport EvaluateExecutableRegion(const ExecutableRegionInput& input);

} // namespace Ksword::Evidence
