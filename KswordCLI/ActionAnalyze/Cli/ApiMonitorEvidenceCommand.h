#pragma once
#include "../../CommandRegistry.h"

namespace ks::cli::action_analyze {

// 登记既有 API Monitor 归档的导入和只读回放命令，无参数或返回值。
void RegisterApiMonitorEvidenceCommands();
// Shared receipt/readback projection; attachment admission stays in its own product wrapper.
Result RunAttachedApiEvidence(const Args& args);

} // namespace ks::cli::action_analyze
