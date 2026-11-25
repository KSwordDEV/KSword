#pragma once

#include "../Archive/RawEvidenceArchive.h"

namespace Ksword::ActionAnalyze {

// 此版本在被动 ETW 清退后一次提交 raw/1 和 records/1 的已刷前缀。
struct EtwCheckpointPrefix {
    ks::cli::action_analyze::archive::RawEvidenceBoundary end;
    std::string sha256;
};

struct ProjectEtwCheckpoint {
    EtwCheckpointPrefix raw;
    EtwCheckpointPrefix records;
};

} // namespace Ksword::ActionAnalyze
