#pragma once

#include "ProjectRawEvidence.h"
#include "../../../shared/driver/KswordArkCallbackMonitorIoctl.h"

#include <string_view>

namespace Ksword::ActionAnalyze {

inline constexpr char kProjectCallbackSourceId[] = "kswordark.callback";
inline constexpr char kProjectCallbackPlanKind[] = "kswordark-callback-thread-create-plan-v1";

// 只描述一次成功回读的游标状态，不是采集覆盖结论。失败/未读不能归档为空样本。
enum class CallbackBatchState { NotRead, CaughtUp, MoreAvailable, SnapshotRace };

// 将已读取的状态转为归档和 CLI 共用的协议标签，未读状态返回空。
std::string_view CallbackBatchStateName(CallbackBatchState state) noexcept;

struct ProjectCallbackEvidencePlan {
    std::string sourceEpoch; // 调用方为同一连续回调源登记的规范 UUID；游标重置不能沿用。
    std::uint64_t afterSequence = 0; // 原生请求游标，不含该序号。
    std::uint32_t maxRecords = KSWORD_ARK_CALLBACK_MONITOR_MAX_READ_RECORDS; // 本次实际读额度。
};

struct ProjectCallbackEvidenceEnd {
    CallbackBatchState state = CallbackBatchState::NotRead;
    std::uint64_t nextSequence = 0; // 原生响应游标，包含已读或覆盖而跳过的前缀。
    std::uint64_t latestSequence = 0; // 该响应快照的源上界，不是采样停止水位。
    std::uint32_t returnedCount = 0; // 原生返回数，含未归档的非线程创建行。
    std::optional<std::uint64_t> lostBeforeFirst; // 原生报告的覆盖数；无报告与已知 0 分开。
    std::optional<std::uint64_t> droppedCount; // 环的全局累计快照，不是本批丢失增量；空表示未知。
};

struct ProjectCallbackEvidenceRecord {
    KSWORD_ARK_CALLBACK_MONITOR_EVENT event{}; // 原生序号及 PID/TID 均为来源字段。
    std::uint64_t rawSequence = 0; // 段内 Stored 记录号，不是 event.sequence。
    std::uint64_t rawOffset = 0; // 文件中的 Stored 记录头位置。
    std::uint64_t inlineOffset = 0; // 文件中的原始事件字节位置；长度为 sizeof(event)。
};

// 只有核验成功才发布。即使读至游标末尾且报告 0 丢失，线程创建采集覆盖仍未知。
struct ProjectCallbackEvidenceReceipt {
    std::string projectId, sampleId, descriptionHash;
    ProjectCallbackEvidencePlan plan;
    ProjectCallbackEvidenceEnd end;
    std::uint64_t segmentOrdinal = 0; // 成功时为专用 raw/1。
    ks::cli::action_analyze::archive::RawEvidenceBoundary boundary;
    std::string prefixSha256;
    std::vector<ProjectCallbackEvidenceRecord> records;
};

// 调用方串行持有可写项目、已登记的专用采样及同一代次核验过的单批源回执；records 是该批
// 线程创建子集，按原生序号递增。只写新 raw/1；返回刷盘后完整回读的结果，失败清空 out。
ProjectResult WriteInitialCallbackEvidence(ProjectDocument& project, std::string_view sampleId,
    const ProjectCallbackEvidencePlan& plan, const ProjectCallbackEvidenceEnd& end,
    std::span<const KSWORD_ARK_CALLBACK_MONITOR_EVENT> records, ProjectCallbackEvidenceReceipt& out);

// 用已登记采样打开 raw/1；完整空批次有计划、终态和有效坐标；缺失或坏尾返回错误，不发布部分结果。
ProjectResult ReadInitialCallbackEvidence(const ProjectDocument& project, std::string_view sampleId,
    ProjectCallbackEvidenceReceipt& out);

} // namespace Ksword::ActionAnalyze
