#pragma once

// 证据 envelope —— F-04 来源和时间、F-05 可用性与结论分离、F-06 不完整采集的账目、
// F-11 来源可信度边界。
//
// 这一层只描述"采集这件事本身"，不描述采集到的对象。任何模块（I/X/M/T/N/S/D/C/G）
// 产出结果时都带一份 envelope，UI、导出和报告据此区分"采集失败"、"分析无法判断"
// 和"正确的空集合"。

#include "LosslessValue.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Evidence {

// ---------------------------------------------------------------------------
// F-05：采集状态。与分析结论是两个字段，任何一方都不能推出另一方。
// ---------------------------------------------------------------------------
enum class CollectionStatus {
    NotCollected,  // 根本没跑
    Success,       // 跑完且覆盖了请求范围（可以是正确的空集合）
    Partial,       // 跑了但没覆盖全部请求范围
    Unsupported,   // 当前驱动/OS/硬件不提供该能力
    AccessDenied,  // 权限不足
    Timeout,       // 超时
    Error,         // 其它失败
};

const char* CollectionStatusName(CollectionStatus status) noexcept;

// 只有 Success/Partial 才携带真实观测；其余状态下的"空"不是"不存在"。
bool StatusCarriesObservation(CollectionStatus status) noexcept;

// F-05：失败必须保留原始错误码及说明，不得用默认 0/空串/"正常"补齐。
struct CollectionOutcome final {
    CollectionStatus status = CollectionStatus::NotCollected;
    OptionalU64 nativeCode;  // NTSTATUS / Win32 / HRESULT 原值，未知即 unset
    std::string nativeCodeDomain;  // "NTSTATUS" / "WIN32" / "HRESULT" / ""
    std::string message;           // 来源给的原文，不是我们编的解释

    static CollectionOutcome success() noexcept;
    static CollectionOutcome notCollected() noexcept;
    static CollectionOutcome failure(CollectionStatus status,
                                     std::string domain,
                                     std::uint64_t code,
                                     std::string message);
};

// ---------------------------------------------------------------------------
// F-05：分析结论。没有证据时不能生成"正常"。
// ---------------------------------------------------------------------------
enum class AnalysisConclusion {
    NoEvidence,             // 没有可用观测 —— 不是"正常"
    NoDifferenceObserved,   // 有覆盖足够的观测且未发现矛盾 —— 不是"系统安全"
    DifferenceObserved,     // 观测到差异
    Indeterminate,          // 有观测但不足以判断
};

const char* AnalysisConclusionName(AnalysisConclusion conclusion) noexcept;

// ---------------------------------------------------------------------------
// F-06：不完整采集的账目。
// ---------------------------------------------------------------------------
struct CoverageAccount final {
    OptionalU64 requestedBegin;  // 请求范围（地址/序号/时间，由调用方定义单位）
    OptionalU64 requestedEnd;
    OptionalU64 processedBegin;  // 实际处理到的范围
    OptionalU64 processedEnd;

    std::uint64_t succeeded = 0;
    std::uint64_t failed = 0;
    std::uint64_t skipped = 0;
    std::uint64_t truncated = 0;

    bool limitHit = false;          // 命中上限而提前停止
    OptionalU64 limit;              // 生效的上限值
    // F-06：用户主动取消与"命中上限"是两个不同的停止原因，不能共用 limitHit —— 否则
    // 一次取消会在账目里被表述成"命中了一个不知道是多少的上限"，"原因"这一维就丢了。
    bool cancelled = false;
    // F-06：上面四个计数器是裸 u64，没有"未知"这一态。有些来源只报总数不报明细
    // （例如 ETW 只给 EventsLost 总计），此时把未知项按 0 汇总进 failed/skipped，
    // 等于把"不知道丢了多少"写成"一条都没丢"。置这一位表示**至少有一项计数来源
    // 未知**，账目里的数字只是下界，不是全貌。
    bool countsIncomplete = false;
    OptionalU64 totalKnown;         // 对象总数。未知就是 unset，不能拿已返回数冒充

    // F-06：完整覆盖需要**正面证据**，空账目不是完整覆盖。
    // 判定：先看否定项（命中上限 / 被取消 / 有失败、跳过、截断），再要求下面两条
    // 正面证据至少成立一条：
    //   (a) 范围口径：requested/processed 四个端点**同时**在场，且处理范围完全盖住
    //       请求范围。少一个端点就无从校验边界，不算数。
    //   (b) 数量口径：声明了 totalKnown，且 succeeded 已经不少于它。
    // 两条都缺 —— 即"什么都没填" —— 返回 false：未知覆盖 ≠ 完整覆盖。
    // 不变式：fullyCovered() 为真时 describeRemaining() 绝不返回 "remaining:unknown"。
    bool fullyCovered() const noexcept;

    // UI/报告用的剩余量说明；无法判断时返回明确的"未知"文案键而不是 0。
    // F-06 要求"剩余范围及原因可见"，因此停止原因（cancelled / limit-hit / truncated）
    // 优先于纯数量表述输出。
    std::string describeRemaining() const;
};

// ---------------------------------------------------------------------------
// F-11：来源可信度边界。
// ---------------------------------------------------------------------------
enum class SourceOrigin {
    Unknown,
    LiveKernel,    // 同一台正在运行的 Windows 内核
    LiveUserMode,  // 同一台机器的 R3 接口
    ExternalFile,  // 磁盘上的外部文件（映像、策略、配置）
    OfflineSample, // 已保存的会话/快照/转储
};

const char* SourceOriginName(SourceOrigin origin) noexcept;

// F-04 + X-01：collector 身份。sourceGroup 表示"底层证据来源"，同一个 collector
// 的两层包装必须共用同一个 sourceGroup，否则会被当成两个独立来源。
struct SourceRef final {
    std::string collectorId;              // 稳定标识，例如 "r0.process.enum"
    std::uint32_t collectorVersion = 0;   // 该 collector 的解析/协议版本
    std::string sourceGroup;              // 独立来源分组键
    SourceOrigin origin = SourceOrigin::Unknown;
    std::string dependsOn;                // 依赖链描述，例如 "ArkDriverClient/IOCTL 0x..."
};

enum class CaptureMode {
    Unknown,
    Snapshot,   // 一次性快照
    Streaming,  // 持续采集
    Replay,     // 从已保存数据重放
};

const char* CaptureModeName(CaptureMode mode) noexcept;

// F-04：UTC 与单调时钟分别使用。跨启动周期禁止直接比较单调值。
struct CaptureWindow final {
    OptionalU64 startUtc100ns;
    OptionalU64 endUtc100ns;
    OptionalU64 startMonotonic;   // QPC ticks，只在同一 bootId 内可比
    OptionalU64 endMonotonic;
    OptionalU64 monotonicFrequency;

    std::string machineId;
    std::string bootId;    // 启动周期标识；跨 bootId 的单调值不可相减
    std::string sessionId; // 本次采集会话
    CaptureMode mode = CaptureMode::Unknown;
};

// F-04：两个单调时间戳只有在同一启动周期内才可相减。
bool MonotonicComparable(const CaptureWindow& a, const CaptureWindow& b) noexcept;

// 返回 false 表示不可比较（不同 boot / 缺频率 / 缺值），out 不被修改。
bool MonotonicDeltaNanos(const CaptureWindow& window,
                         std::uint64_t earlierTicks,
                         std::uint64_t laterTicks,
                         std::int64_t& outNanos) noexcept;

// ---------------------------------------------------------------------------
// 组合体
// ---------------------------------------------------------------------------
struct EvidenceEnvelope final {
    SourceRef source;
    CaptureWindow window;
    CollectionOutcome outcome;
    CoverageAccount coverage;
    std::string evidenceId;  // 本批结果的稳定 id，供导航与报告引用（F-12）

    // F-05 核心约束：没有观测就不能得出"未发现差异"。
    // differenceFound 只在 StatusCarriesObservation 为真时才被采纳。
    AnalysisConclusion deriveConclusion(bool differenceFound) const noexcept;
};

// F-11：多个视图一致只说明这些视图未发现矛盾。该函数产出的是覆盖与信任说明的
// 结构化事实，调用方据此渲染；它绝不产出"系统安全"/"不存在 rootkit"结论。
struct TrustStatement final {
    std::size_t viewCount = 0;
    std::size_t independentSourceGroupCount = 0;
    bool allFromSameLiveKernel = false;
    bool anyIncompleteCoverage = false;

    // F-11 要求区分"同一台正在运行的 Windows 内核 / 外部文件 / 离线样本"三类来源。
    // 单个 allFromSameLiveKernel 只表达得出"是不是全部来自本机内核"，它为 false 时
    // 没有任何字段能说明另一半来自哪里，因此按 SourceOrigin 逐类计数。
    std::size_t unknownOriginViewCount = 0;
    std::size_t liveKernelViewCount = 0;
    std::size_t liveUserModeViewCount = 0;
    std::size_t externalFileViewCount = 0;
    std::size_t offlineSampleViewCount = 0;
    std::size_t distinctOriginCount = 0;   // 参与本次结论的来源类别数

    std::vector<std::string> limitationKeys;  // i18n 键，UI 负责翻译

    // 便捷读取：某一类来源出现过几次。UI 渲染"这份结论有多少来自离线样本"用。
    std::size_t originViewCount(SourceOrigin origin) const noexcept;
};

TrustStatement BuildTrustStatement(const std::vector<EvidenceEnvelope>& envelopes);

} // namespace Ksword::Evidence
