#pragma once

#include "Protocol.h"
#include "NativeStopMemoryJournal.h"
#include "NativeSessionApiCapture.h"
#include "../Project/ProjectNativeExecution.h"

#include <map>

namespace ks::cli::action_analyze {

inline constexpr std::uint64_t kNativeExecutionSessionSaveLimit = 4096;

struct NativeExecutionSaveReply {
    bool ok = false;
    JsonValue result;
};

// 持项目独占写租约至会话结束；只在同一 CLI 控制线程调用。
class NativeExecutionJournal final {
public:
    Ksword::ActionAnalyze::ProjectResult Open(const std::wstring& path, std::string_view sampleId);
    const std::string& SampleId() const noexcept { return sampleId_; }
    JsonValue Describe() const;
    // 输入原采样冻结定义ID及所选绝对模块，输出匹配的非零RVA；不使用项目后来修订或历史停止票据。
    Ksword::ActionAnalyze::ProjectResult ResolveImageDefinition(std::string_view definitionId,
        const std::wstring& modulePath, std::uint32_t& rva);
    NativeExecutionSaveReply Save(const Request& request, bool jsonl,
        const control::OwnerIdentity& identity, control::NativeDebugOwner& owner);
    NativeStopMemoryReply CaptureMemory(const Request& request, bool jsonl,
        const control::OwnerIdentity& identity, control::NativeDebugOwner& owner)
    { return memory_.Capture(request, jsonl, identity, owner); }
    NativeSessionApiReply CaptureApi(const Request& request, bool jsonl,
        const control::OwnerIdentity& identity, control::NativeDebugOwner& owner);

private:
    Ksword::ActionAnalyze::ProjectDocument project_;
    std::string sampleId_;
    std::string definitionId_; // 本轮由冻结采样配置解析的定义来源，只有成功解析才登记。
    std::uint64_t nextOrdinal_ = 1;
    std::optional<std::uint64_t> previousSequence_ = 0;
    std::map<std::uint64_t, JsonValue> saved_;
    std::optional<JsonValue> failedWrite_;
    NativeStopMemoryJournal memory_;
};

// 只产出历史文档，依次核验前段，不构造活控制请求。
Ksword::ActionAnalyze::ProjectResult ReadNativeExecutionChain(
    const Ksword::ActionAnalyze::ProjectDocument& project, std::string_view sample,
    std::uint64_t ordinal, Ksword::ActionAnalyze::ArchivedNativeExecution& out);

} // namespace ks::cli::action_analyze
