#pragma once

#include "Protocol.h"
#include "../Project/ProjectDocument.h"

namespace ks::cli::action_analyze {

// 从已打开项目的采样校验指定 ETW 段，返回只读采集摘要及核验状态。
JsonValue ReadArchivedCapture(const Ksword::ActionAnalyze::ProjectDocument& project,
                              const Ksword::ActionAnalyze::SampleRecord& sample, std::uint64_t ordinal = 1);

} // namespace ks::cli::action_analyze
