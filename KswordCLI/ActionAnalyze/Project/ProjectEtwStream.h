#pragma once

#include "ProjectEtwEvidence.h"

namespace Ksword::ActionAnalyze {

// 原项目worker持有的分段游标；不拥有来源、线程或第二份项目写租约。
struct ProjectEtwStream {
    std::uint64_t ordinal = 0; // 最后成功发布检查点的独立ETW段号。
    std::uint64_t observations = 0; // 已发布段中的累计观察数。
    std::uint64_t planRawSequence = 0; // 最近已发布段的首条计划记录序号，不与API主流混用。
    std::string rawSha256; // 最近成功发布检查点核验的原始段摘要；失败不覆盖旧身份。
    ks::cli::action_analyze::archive::RawEvidenceReceipt raw; // 最近已发布段的刷盘边界。
    ProjectResult archiveStatus; // 首个原始段失败，失败后不再追加。
    ProjectResult checkpointStatus; // 原有覆盖与检查点发布结果。
    bool finalized = false; // 已发布唯一终段，不再消费来源。

    // 输入本游标实际写入的流，返回最近已发布段的无损定位文档；尚未发布时返回null，不读盘。
    Evidence::JsonValue PublishedJson(ProjectEvidenceLane lane) const;

    // 每次移出至多512条，复用原Stored writer与ETW检查点。
    // final只在来源停止且队列已完全排空的最后一段发布；失败后保留已提交前缀，不跳段。
    bool Flush(ProjectDocument& project, std::string_view sampleId, ProjectEvidenceLane lane,
        const Evidence::JsonValue& plan, std::string_view reason,
        ks::r3::monitor::PassiveEtwSource& source, bool final);
};

} // namespace Ksword::ActionAnalyze
