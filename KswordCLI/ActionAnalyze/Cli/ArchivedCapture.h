#pragma once

#include "Protocol.h"
#include "../Project/ProjectDocument.h"

namespace ks::cli::action_analyze {

// 从已打开项目的指定采样读取首个 ETW 原始段，返回只读采集摘要及读取状态。
JsonValue ReadArchivedCapture(const Ksword::ActionAnalyze::ProjectDocument& project,
                              const Ksword::ActionAnalyze::SampleRecord& sample);

} // namespace ks::cli::action_analyze
