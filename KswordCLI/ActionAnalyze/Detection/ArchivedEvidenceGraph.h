#pragma once

#include "CrossProcessEvidenceGraph.h"
#include "ApiTransferChain.h"
#include "../Project/ProjectCallbackEvidence.h"
#include "../../../shared/evidence/ApiContextFields.h"
#include "../../../shared/evidence/ApiSectionMapFields.h"
#include "../../../shared/evidence/ApiMemoryLifecycleFields.h"

namespace Ksword::ActionAnalyze::Detection {

// 页及扫描容量由读取适配器统一限制，避免读段后才裁剪图输入。
inline constexpr std::size_t kArchivedGraphMaxRows = 4096;
inline constexpr std::size_t kArchivedGraphDefaultRows = 100;
inline constexpr std::uint64_t kArchivedGraphMaxApiSegments = 128; // 与 CLI 历史查询的链核验预算一致。

enum class ArchivedGraphSource { ImportedApi, CommittedEtw, CommittedApiFollow, CallbackBatch };

// 已核验历史 API 的来源坐标不声明机器/启动身份；不能调用强对象证据的 machine/boot 门禁。
// 输入项目采样范围和原包引用，输出能否在该范围内精确回查；不授予来源认证或因果结论。
inline bool HasArchivedApiLocation(const SampleScope& scope, const EvidenceRef& evidence) noexcept
{
    return !scope.projectId.empty() && !scope.sampleId.empty() &&
        evidence.projectId == scope.projectId && evidence.sampleId == scope.sampleId &&
        !evidence.sourceId.empty() && !evidence.sourceEpoch.empty() && evidence.raw &&
        evidence.raw->segmentOrdinal != 0 && evidence.raw->sequence != 0;
}

// 游标使用本段的 raw 记录序号，有效观察序号为正数，首次读取传 0。
// 恢复页时可传上次回执的散列复核同一前缀。
struct ArchivedGraphRequest {
    std::string_view sampleId; // 目录中的规范采样 UUID。
    std::uint64_t segmentOrdinal = 0; // 明确选择的段号，从 1 开始。
    std::uint64_t afterSequence = 0; // 只返回大于此原始记录序号的观察。
    std::size_t limit = kArchivedGraphDefaultRows; // 本页保留的观察数上限。
    std::string_view expectedSha256; // 可选的既有 raw 前缀散列。
    ProjectEvidenceLane lane = ProjectEvidenceLane::Primary;
};

// 回调 v1 通知中的弱角色提示，不能作为进程或线程实例使用。
struct ArchivedCallbackHints {
    std::optional<std::uint32_t> originPid, originTid; // 零表示来源没有该提示。
    std::uint32_t targetPid, targetTid; // 线程创建正文要求目标编号非零。
    std::optional<std::uint64_t> notificationUtc100ns; // 回调采时，不是线程创建时间；非正值作未知。
};

// 同一已核验读批的游标及计数。续页和完整空批也返回同一份回执。
struct ArchivedCallbackBatch {
    ProjectCallbackEvidencePlan plan;
    ProjectCallbackEvidenceEnd end;
};

// 从原始段扫描器复制实际坐标。行号与图 observations 下标逐项对应。
struct ArchivedGraphRecord {
    std::uint64_t segmentOrdinal = 0; // 核验过的 raw 段号。
    std::uint64_t recordSequence = 0; // 原始记录封装的序号。
    std::uint64_t recordOffset = 0; // 记录头的文件字节偏移。
    std::uint64_t blockOrdinal = 0; // 所属完整 Stored 块号。
    std::uint64_t inlineOffset = 0; // 原始字节的文件偏移，包含空载荷时的位置。
    std::uint32_t inlineBytes = 0; // 核验过的内联字节数。
    std::string operation; // 精确导出名或 ETW 上下文类别。
    std::optional<std::uint32_t> headerPid, headerTid; // 仅来源提示。
    std::string_view apiFamily; // 共用目录的稳定线索类别。视图指向静态文本，ETW 为空。
    std::string_view apiCategory; // 原包核对后的业务分类 memory 或 thread。视图指向静态文本，ETW 为空。
    std::optional<ArchivedCallbackHints> callbackHints; // 仅自有回调批次提供。
    std::optional<Evidence::ApiInjectionFieldsV1> apiInjection; // 显式版本化 API 字段，仍按来源声明展示。
    Evidence::ApiInjectionOutcome apiOutcome = Evidence::ApiInjectionOutcome::Unknown; // 按精确返回约定解码。
    std::optional<Evidence::ApiApcFieldsV1> apiApc; // 独立AAAP1返回字段，不与AAIP1入口字段混用。
    Evidence::ApiApcQueueOutcome apcOutcome = Evidence::ApiApcQueueOutcome::Unknown; // 仅队列接受状态。
    std::optional<Evidence::ApiContextFieldsV1> apiContext; // 原上下文请求，不作为实际寄存器现场。
    Evidence::ApiContextOutcome contextOutcome = Evidence::ApiContextOutcome::Unknown; // 原接口是否接受请求。
    std::optional<Evidence::ApiSectionMapFieldsV1> apiSectionMap; // 原映射请求和可读的成功输出。
    Evidence::ApiSectionMapOutcome sectionMapOutcome = Evidence::ApiSectionMapOutcome::Unknown; // 仅映射调用返回。
    std::optional<Evidence::ApiMemoryLifecycleFieldsV1> apiMemoryLifecycle; // AAIM1原请求/成功输出，非执行或region代次。
    std::optional<std::uint64_t> apiSourceSession; // 生命周期原包声明的会话，不补造认证身份。
};

struct ArchivedApiGraphCheckpoint {
    std::uint64_t previousSourceSequence; // 本段之前最后提交的源序号。
    std::uint64_t lastSourceSequence; // 本段提交后的源序号，包含未分类包。
};

struct ArchivedGraphPage {
    ArchivedGraphSource source = ArchivedGraphSource::ImportedApi; // 实际通过核验的归档类型。
    EvidenceGraph graph; // 同一采样中本页的证据观察及关系。
    std::vector<ArchivedGraphRecord> records; // 同一索引的原始坐标与来源分类。
    std::uint64_t segmentOrdinal = 0; // 已验证的 raw 段号，空观察页仍保留。
    std::string descriptionHash; // 已登记的冻结采样描述散列。
    std::string sha256; // 同一实际读取句柄上核验的 raw 前缀摘要。
    ks::cli::action_analyze::archive::RawEvidenceBoundary end; // 本段已核验的完整块端点。
    std::uint64_t observationCount = 0; // 整个已核验段中的来源观察总数。
    std::optional<std::uint64_t> nextAfterSequence; // 仍有下一页时为本页最后一条坐标。
    std::optional<bool> etwFinalSegment; // ETW 检查点是否报告本段为终段。
    std::optional<bool> apiFinalSegment; // 已验证的 API 跟随检查点是否报告本段为终段。
    std::optional<ArchivedApiGraphCheckpoint> apiCheckpoint; // 本次已从首段连续验证的 API 水位。
    std::string_view apiInputKind; // API 输入方式及源序号口径，引用静态文本；非 API 页为空。
    std::optional<ArchivedCallbackBatch> callbackBatch; // 仅回调档提供，不代表整次采样覆盖。
    std::vector<ApiTransferLink> transferCandidates; // 当前页创建操作与先前实际写入的区间候选，非执行确认。
    std::uint64_t transferCandidateCount = 0; // 当前页创建操作的候选总数，超过候选容量时仍计数。
    std::uint64_t evictedTransferWrites = 0; // 链路状态达到容量后淘汰的旧写入数。
    std::vector<ApiApcTransferLink> apcTransferCandidates; // 当前页队列请求与先前写入的范围候选。
    std::uint64_t apcTransferCandidateCount = 0; // 独立于线程创建候选的完整页内计数。
    std::vector<ApiContextTransferLink> contextTransferCandidates; // 本页上下文请求与先前实际写入。
    std::uint64_t contextTransferCandidateCount = 0; // 独立上下文候选总数，不占用APC/创建窗口。
};

// 从已登记的 raw 段读取一页。支持完整 API 导入、已提交的 API 跟随和 ETW、完整自有回调批次。
// 适配期间只读取档案。失败不替换 out，成功时 records 与 graph.observations 等长。
[[nodiscard]] ProjectResult ReadArchivedEvidenceGraph(const ProjectDocument& project,
    const ArchivedGraphRequest& request, ArchivedGraphPage& out);

} // namespace Ksword::ActionAnalyze::Detection
