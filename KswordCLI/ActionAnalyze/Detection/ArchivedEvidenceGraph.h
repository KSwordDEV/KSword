#pragma once

#include "CrossProcessEvidenceGraph.h"
#include "../Project/ProjectRawEvidence.h"

namespace Ksword::ActionAnalyze::Detection {

// 页及扫描容量由读取适配器统一限制，避免读段后才裁剪图输入。
inline constexpr std::size_t kArchivedGraphMaxRows = 4096;
inline constexpr std::size_t kArchivedGraphDefaultRows = 100;
inline constexpr std::uint64_t kArchivedGraphMaxApiSegments = 128; // 与 CLI 历史查询的链核验预算一致。

enum class ArchivedGraphSource { ImportedApi, CommittedEtw, CommittedApiFollow };

// 游标使用本段的 raw 记录序号，有效观察序号为正数，首次读取传 0。
// 恢复页时可传上次回执的散列复核同一前缀。
struct ArchivedGraphRequest {
    std::string_view sampleId; // 目录中的规范采样 UUID。
    std::uint64_t segmentOrdinal = 0; // 明确选择的段号，从 1 开始。
    std::uint64_t afterSequence = 0; // 只返回大于此原始记录序号的观察。
    std::size_t limit = kArchivedGraphDefaultRows; // 本页保留的观察数上限。
    std::string_view expectedSha256; // 可选的既有 raw 前缀散列。
    ProjectEvidenceLane lane = ProjectEvidenceLane::Primary; // 游标仅在本流内有效。
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
};

struct ArchivedApiGraphCheckpoint {
    std::uint64_t previousSourceSequence; // 本段之前最后提交的源行号。
    std::uint64_t lastSourceSequence; // 本段提交后最后提交的源行号，包含未分类包。
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
};

// 从已登记的 raw 段读取一页。支持完整 API 导入、已提交的 API 跟随和已提交的 ETW。
// 适配期间只读取档案。失败不替换 out，成功时 records 与 graph.observations 等长。
[[nodiscard]] ProjectResult ReadArchivedEvidenceGraph(const ProjectDocument& project,
    const ArchivedGraphRequest& request, ArchivedGraphPage& out);

} // namespace Ksword::ActionAnalyze::Detection
