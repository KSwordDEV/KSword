#pragma once

#include "ProjectRawEvidence.h"
#include "../Memory/SelectedMemorySnapshot.h"

namespace ks::cli::action_analyze::control { struct ProcessMemorySnapshotResult; }

namespace Ksword::ActionAnalyze {

struct ProjectMemorySnapshotReceipt {
    ks::cli::action_analyze::archive::RawEvidenceReceipt raw; // 写入和刷盘独立回执，失败时仍保留实际端点。
    std::string sha256; // 同一核验读句柄上的整个已提交段散列。
    std::uint64_t ordinal = 0; // raw-memory 段号，由本采样串行写入者保留。
    std::uint64_t capturedBytes = 0; // 实际归档的完整成功子范围字节，不含任何填零缺口。
    std::uint64_t unavailablePages = 0; // 已访问但未形成完整字节样本的页数。
    bool completeRange = false; // 仅本次显式范围全读成功，不表示原子进程 Dump。
    bool verified = false; // 元数据、原字节、段端点及散列均已同步回读。
};

// 将显式单轮快照写到采样专属 raw-memory/N，避免占用 API/ETW 的活采单写者。
// 调用者持项目写租约，并为每轮快照保留新段号和前序；旧停点不是本接口的执行凭据。
// 未实际访问任何页的拒绝/取消结果不创建段；实际失败页保留原诊断，允许没有成功字节。
ProjectResult WriteSelectedMemorySnapshot(ProjectDocument& project, std::string_view sampleId,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence,
    const ks::cli::action_analyze::memory::SelectedMemorySnapshot& snapshot,
    ProjectMemorySnapshotReceipt& out);

// 保存集合调查的原读取模式和读前/读后停点。内存读取成功不替代停点保持的独立结论。
ProjectResult WriteProcessGroupMemorySnapshot(ProjectDocument& project, std::string_view sampleId,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence,
    const ks::cli::action_analyze::control::ProcessMemorySnapshotResult& capture,
    ProjectMemorySnapshotReceipt& out);

} // namespace Ksword::ActionAnalyze
