#pragma once

#include "../../../KswordCLI/ActionAnalyze/Archive/NetworkEvidenceArchive.h"

namespace Ksword::Features::ActionAnalyze {

// 将通过核验的网络流转换为虚拟列表摘要与可复制的只读正文。
std::wstring NetworkReplaySummary(const ks::cli::action_analyze::archive::NetworkStoredFlowPreview& record);
std::wstring NetworkReplayDetails(const ks::cli::action_analyze::archive::NetworkStoredFlowPreview& record);

} // namespace Ksword::Features::ActionAnalyze
