#pragma once

#include "ProjectRawEvidence.h"
#include "../Control/NativeExecutionEvidence.h"
#include "../../../shared/evidence/EvidenceJson.h"

namespace Ksword::ActionAnalyze {

struct ProjectNativeExecutionReceipt {
    ks::cli::action_analyze::archive::RawEvidenceReceipt raw;
    std::uint64_t ordinal = 0;
    std::string sha256;
    bool verified = false;
};

struct ArchivedNativeExecution {
    // 历史文档只供证据回查，不解码成可调用 Continue 的活控制对象。
    Evidence::JsonValue document;
    ks::cli::action_analyze::archive::RawEvidenceBoundary end;
    std::string sha256;
};

// 调用者持项目写租约，在原生会话的串行控制线程显式保存当前停点。
// state 必须直接来自该活 owner，不接受外来 JSON 或历史停点反序列化。
ProjectResult WriteNativeExecution(ProjectDocument& project,
    const ks::cli::action_analyze::control::OwnerIdentity& owner, std::uint64_t ordinal,
    std::optional<std::uint64_t> previousSequence,
    const ks::cli::action_analyze::control::NativeControlResult& state,
    ProjectNativeExecutionReceipt& out);

// 只发布完整封段、严格元数据和散列核验后的历史证据；不认证外来文件生产者。
ProjectResult ReadNativeExecution(const ProjectDocument& project, std::string_view sampleId,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence, ArchivedNativeExecution& out);

} // namespace Ksword::ActionAnalyze
