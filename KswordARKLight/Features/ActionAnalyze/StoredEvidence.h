#pragma once

#include "../../Core/Win32Lean.h"
#include "../../../KswordCLI/ActionAnalyze/Archive/NetworkEvidenceArchive.h"
#include "../../../shared/evidence/ApiMonitorClue.h"
#include "../../../shared/evidence/ApiInjectionFields.h"
#include "../../../shared/evidence/ApiApcFields.h"
#include "../../../shared/evidence/ApiContextFields.h"
#include "../../../shared/evidence/ApiSectionMapFields.h"
#include "../../../shared/evidence/ApiMemoryLifecycleFields.h"
#include "../../../shared/evidence/ApiTransferCandidateWindow.h"
#include "../../../shared/evidence/ApiNativeExecutionProjection.h"
#include "../../../KswordCLI/ActionAnalyze/Rules/ApiBehaviorObservation.h"
#include "../../../shared/evidence/ArchivedEtwObservation.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ks::cli::action_analyze::archive {
struct BlockInfo;
struct RawRecordV1;
}

namespace Ksword::Features::ActionAnalyze {

struct SegmentIdentity {
    std::string projectId;
    std::string sampleId;
    std::uint32_t streamKind = 0;
    std::uint64_t ordinal = 0;
    bool operator==(const SegmentIdentity&) const = default;
};

struct CallbackReplayObservation {
    std::uint64_t sourceSequence = 0; // 原生回调序号，不是 Stored 序号。
    std::uint64_t inlineOffset = 0; // 原包首字节与记录头位置不同。
    std::uint32_t inlineBytes = 0;
    std::uint32_t contextPid = 0, contextTid = 0;
    std::uint32_t targetPid = 0, targetTid = 0; // 仅为 PID/TID 提示，不是对象身份。
    std::int64_t sourceUtc100ns = 0; // 不作为接收 QPC。
};

struct EvidenceRecord {
    std::uint64_t segmentOrdinal = 0; // 此行文件内偏移所属的段。
    std::uint64_t offset = 0;
    std::uint64_t blockOrdinal = 0;
    std::uint64_t sequence = 0;
    std::uint16_t type = 0;
    std::uint16_t schemaVersion = 0;
    std::uint32_t flags = 0;
    std::uint32_t payloadBytes = 0;
    std::optional<std::uint64_t> eventOrdinal;
    std::optional<std::uint64_t> sourceDictionaryId;
    std::optional<std::uint64_t> epochDictionaryId;
    std::optional<std::uint64_t> receiveQpc;
    std::optional<std::uint64_t> rawSequence;
    std::optional<std::uint64_t> actorObjectId;
    std::optional<std::uint64_t> targetObjectId;
    std::optional<std::uint64_t> threadObjectId;
    std::optional<std::uint32_t> headerPid;
    std::optional<std::uint32_t> headerTid;
    std::uint16_t category = 0;
    std::uint32_t eventKind = 0;
    std::optional<Ksword::Evidence::ArchivedEtwObservation> etw; // 归档声明的 ETW 记录上下文。
    std::optional<ks::cli::action_analyze::archive::NetworkStoredFlowPreview> network; // CRC 与正文均通过的网络流。
    std::optional<CallbackReplayObservation> callback; // 仅在项目单批回读完整核验后有值。
    std::wstring apiClue; // 已核验的归档 API 导出名，非空表示线索行。
    std::wstring apiFamily; // 共用分类器返回的线索类别。
    std::uint64_t apiSourceSequence = 0; // JSONL 行号或合作流水号；零表示非 API 线索。
    std::optional<Ksword::Evidence::ApiMonitorArchiveSource> apiArchiveSource; // 来自核验通过的导入尾记或检查点计划。
    std::optional<Ksword::Evidence::ApiMonitorMemoryWriteReturn> memoryWriteReturn; // 同一原包报告的显式返回值。
    std::optional<Ksword::Evidence::ApiInjectionFieldsV1> apiTransfer; // 源端结构化目标身份与实际写入字段。
    Ksword::Evidence::ApiInjectionOutcome apiTransferOutcome = Ksword::Evidence::ApiInjectionOutcome::Unknown; // 不以请求值替代成功结果。
    std::optional<Ksword::Evidence::ApiApcFieldsV1> apiApc; // 当前行显式 AAAP1 参数，不从摘要猜测。
    Ksword::Evidence::ApiApcQueueOutcome apcOutcome = Ksword::Evidence::ApiApcQueueOutcome::Unknown; // 入队接受不证明执行。
    std::optional<Ksword::Evidence::ApiContextFieldsV1> apiContext; // 当前行 AACT1 上下文请求，独立于规范对象引用。
    Ksword::Evidence::ApiContextOutcome contextOutcome = Ksword::Evidence::ApiContextOutcome::Unknown; // 仅解释原上下文调用结果。
    std::optional<Ksword::Evidence::ApiSectionMapFieldsV1> apiSectionMap; // 当前行 AASM1 请求及实际返回范围。
    Ksword::Evidence::ApiSectionMapOutcome sectionMapOutcome = Ksword::Evidence::ApiSectionMapOutcome::Unknown; // 仅解释原节映射调用结果。
    std::optional<Ksword::Evidence::ApiMemoryLifecycleFieldsV1> apiMemoryLifecycle; // 当前原包AAIM1字段。
    std::uint64_t memorySourceSession = 0; // 同一packet来源会话，不授予控制资格。
    std::optional<Ksword::ActionAnalyze::Rules::ApiBehaviorObservation> behaviorObservation; // 独立普通调用参数与返回。
    std::wstring preview;
    bool mixedEtwLane = false; // 混采项目中的 raw-etw；独立段及旧项目仍使用原坐标。
};

struct SegmentEvidence {
    std::optional<SegmentIdentity> identity;
    std::uint64_t createdUtc100ns = 0;
    std::uint64_t fileBytes = 0;
    std::uint64_t framedBytes = 0;
    std::uint64_t decodedPrefixBytes = 0;
    std::optional<std::uint64_t> lastBlockOrdinal; // 最后一个完整解码块的序号。
    std::optional<std::uint64_t> lastSequence; // 最后一个完整解码块的末记录序号。
    std::uint64_t failureOffset = 0;
    std::size_t blocks = 0;
    std::size_t records = 0;
    std::size_t opaqueOptionalRecords = 0;
    std::size_t opaqueRequiredRecords = 0;
    std::uint64_t apiClues = 0; // 已验导入尾记或已提交连续前缀内的线索总数。
    bool continuousEtwPlan = false; // 首条记录声明持续采集，项目回放须等待检查点。
    std::optional<bool> apiFollowRequiresCheckpoint; // 只在识别首条 API 跟随计划时有值。
    std::string diagnostic;
    std::uint32_t systemError = 0;
    std::wstring fileIdentity;
    std::vector<EvidenceRecord> rows;
    std::vector<Ksword::Evidence::ApiTransferCandidateRows<EvidenceRecord>> transferCandidates; // 后台核验的最近双方详情。
    std::uint64_t transferCandidateCount = 0; // 已核验范围的全部候选数，含最近窗口之外。
    std::vector<Ksword::Evidence::ApiApcCandidateRows<EvidenceRecord>> apcTransferCandidates; // 最近 128 对 APC 双方值副本。
    std::uint64_t apcTransferCandidateCount = 0; // 已核验前缀的 APC 候选累计数。
    std::vector<Ksword::Evidence::ApiContextCandidateRows<EvidenceRecord>> contextTransferCandidates; // 最近 128 对 write/context 原行。
    std::uint64_t contextTransferCandidateCount = 0; // 已核验前缀累计数，不随裁剪回退。
    std::uint64_t evictedTransferWrites = 0; // 共享 1024 写入窗口淘汰数。
    std::vector<Ksword::Evidence::ApiSectionMapCandidateRow<EvidenceRecord>> sectionMapRequests; // 独立映射原行窗口。
    std::uint64_t evictedSectionMaps = 0; // 映射输入裁剪数。
    Ksword::Evidence::ApiNativeExecutionProjection<EvidenceRecord> nativeExecution; // 同采样执行候选及独立读取状态。
};

inline constexpr std::size_t kEvidenceRows = 4096;
inline constexpr std::uint64_t kEvidenceScanBytes = 64ULL * 1024 * 1024;
inline constexpr auto kUnsupportedRawSource = "unsupported/rawSource";
inline constexpr auto kCallbackProjectRequired = "raw.callbackProjectRequired";
inline constexpr auto kCallbackProjectOnly = "raw.callbackProjectOnly";
enum class StoredReadMode { Default, KeepLatest, LegacyProject }; // 项目回退识别专用段首计划后交给对应读取器。

// The caller supplies one immutable byte extent and an exact sequential reader.
// Return a nonzero native error if the span cannot be filled.
using ReadExact = std::function<std::uint32_t(std::span<std::uint8_t>)>;
SegmentEvidence ReadStoredEvidence(std::uint64_t size, const ReadExact& read,
    const SegmentIdentity* expected = nullptr, StoredReadMode mode = StoredReadMode::Default);

SegmentEvidence OpenStoredEvidence(const std::wstring& path);

// 读取调用方持有的同步只读句柄。可选端点限定本次投影，fileBytes 仍表示物理长度。
SegmentEvidence ReadOpenStoredEvidence(HANDLE file, std::optional<std::uint64_t> endOffset,
    const SegmentIdentity* expected = nullptr, StoredReadMode mode = StoredReadMode::Default);

// 在共享 API 检查点回调内构造暂存行。整段成功后才能发布。
EvidenceRecord PreviewCommittedApiRecord(const ks::cli::action_analyze::archive::BlockInfo& block,
    const ks::cli::action_analyze::archive::DecodedRecord& record,
    const ks::cli::action_analyze::archive::RawRecordV1& raw, std::uint64_t segmentOrdinal);
// 整段核验通过后，为线索详情应用计划声明的来源及序号口径。
void ApplyCommittedApiClueSource(EvidenceRecord& row, Ksword::Evidence::ApiMonitorArchiveSource source);

} // namespace Ksword::Features::ActionAnalyze
