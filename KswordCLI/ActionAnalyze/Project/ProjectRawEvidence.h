#pragma once

#include "ProjectDocument.h"
#include "../Archive/RawEvidenceArchive.h"

namespace Ksword::ActionAnalyze {

// 调用方在项目归档工作线程为已登记采样保留新的 raw 段号和前序。
// 后续段要求前段存在完整前缀且末序号经回读匹配。
struct ProjectRawEvidenceWrite {
    std::string_view projectId;
    std::string_view sampleId;
    std::uint64_t ordinal = 1;
    std::optional<std::uint64_t> previousSequence;
    // 回调期间借用写入器，按报告顺序写块。回调不得操作同一项目文档或保留写入器。
    // 对每次 Append 的失败，回调负责停止或按原错误纠正后重试。
    // 返回后同步收尾并刷盘。回调错误和刷盘回执同时返回，便于保留部分结果。
    std::function<ProjectResult(ks::cli::action_analyze::archive::RawEvidenceArchive&)> append;
    ProjectEvidenceLane lane = ProjectEvidenceLane::Primary;
};

// 指定段的扫描通过项目目录、固定路径和段头复核采样身份。
struct ProjectRawEvidenceRead {
    std::string_view projectId;
    std::string_view sampleId;
    std::uint64_t ordinal = 1;
    std::optional<std::uint64_t> endOffset; // 可传运行期持有的刷盘字节端点。
    std::optional<std::uint64_t> previousSequence;
    ks::cli::action_analyze::archive::SegmentBodyVisitor visitor;
    std::optional<std::uint64_t> maxFileBytes = std::nullopt; // 整段读取可附加文件大小上限。
    ProjectEvidenceLane lane = ProjectEvidenceLane::Primary;
};

} // namespace Ksword::ActionAnalyze
