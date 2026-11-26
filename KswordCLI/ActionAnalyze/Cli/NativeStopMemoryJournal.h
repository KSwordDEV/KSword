#pragma once

#include "Protocol.h"
#include "../Control/ProcessGroupMemorySnapshot.h"
#include "../Project/ProjectDocument.h"

namespace ks::cli::action_analyze {

struct NativeStopMemoryReply {
    bool ok = false;
    JsonValue result;
};

// 共用固定原生会话证据目录的完整段号检查；不创建或持有第二个项目写者。
Ksword::ActionAnalyze::ProjectResult InspectNativeJournalLane(const std::wstring& path,
    std::string_view sample, std::wstring_view lane, std::uint64_t& count);

class NativeStopMemoryJournal final {
public:
    Ksword::ActionAnalyze::ProjectResult Open(Ksword::ActionAnalyze::ProjectDocument& project,
        const std::wstring& path, std::string_view sample);
    JsonValue Describe() const;
    NativeStopMemoryReply Capture(const Request& request, bool jsonl,
        const control::OwnerIdentity& identity, control::NativeDebugOwner& owner);

private:
    Ksword::ActionAnalyze::ProjectDocument* project_ = nullptr; // 借用原会话独占写租约。
    std::string sampleId_;
    std::uint64_t nextOrdinal_ = 1;
    std::optional<std::uint64_t> previousSequence_ = 0;
    std::optional<JsonValue> failedWrite_; // 只阻断 raw-memory，原生执行 lane 独立。
};

} // namespace ks::cli::action_analyze
