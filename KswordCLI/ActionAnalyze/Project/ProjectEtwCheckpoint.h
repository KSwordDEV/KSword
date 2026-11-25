#pragma once

#include "../Archive/RawEvidenceArchive.h"

namespace Ksword::ActionAnalyze {

// 每个检查点提交同序号 raw 和 records 的已刷前缀。
struct EtwCheckpointPrefix {
    ks::cli::action_analyze::archive::RawEvidenceBoundary end;
    std::string sha256;
};

struct ProjectEtwCheckpoint {
    EtwCheckpointPrefix raw;
    EtwCheckpointPrefix records;
    std::uint64_t planRawSequence = 0; // 本段第一条原始记录的流内序号。
    bool finalSegment = true; // 旧单段记录视为终段，连续段以实际尾记录为准。
};

} // namespace Ksword::ActionAnalyze
