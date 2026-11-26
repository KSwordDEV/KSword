#pragma once

#include "../../Core/Win32Lean.h"
#include "../../../KswordCLI/ActionAnalyze/Control/OwnedExecutionGroup.h"
#include <memory>

namespace Ksword::Features::ActionAnalyze {
namespace execution_native = ks::cli::action_analyze::control;

enum class LightExecutionGroupCommand { Start, Query, Pause, Continue, Step, CancelStep, Identify };

// 点击时按值冻结；不借用窗口、列表索引或稍后可能改变的参数。
struct LightExecutionGroupRequest {
    LightExecutionGroupCommand command = LightExecutionGroupCommand::Query;
    std::vector<execution_native::ExecutionGroupSite> sites;
    std::vector<execution_native::ExecutionGroupSessionEntry> sessions; // 混合Pause/Continue逐成员冻结原owner和完整control。
    std::vector<execution_native::NativeControlResult> stops;
    execution_native::NativeStepMode stepMode = execution_native::NativeStepMode::Into;
    bool authorized = false;
    bool all = false;
    std::uint32_t identityPid = 0;
};

struct LightExecutionGroupSnapshot {
    execution_native::ExecutionGroupResult result;
    std::uint64_t revision = 0;
    std::uint64_t observedFileTime = 0;
    std::uint64_t operationFileTime = 0;
    bool active = false;
    bool busy = false;
    bool closing = false;
    bool closedClean = true;
    bool canStart = true;
    std::wstring diagnostic;
    std::uint32_t identityPid = 0;
    std::uint64_t identityCreation = 0;
    std::uint64_t identityRevision = 0;
    DWORD identityError = 0;
};

// 一个页面只登记一个串行worker；所有原生创建、查询、操作和销毁都在该线程。
class LightExecutionGroupSession final {
public:
    LightExecutionGroupSession() = default;
    ~LightExecutionGroupSession();
    LightExecutionGroupSession(const LightExecutionGroupSession&) = delete;
    LightExecutionGroupSession& operator=(const LightExecutionGroupSession&) = delete;
    DWORD StartWorker();
    bool Submit(LightExecutionGroupRequest request);
    void Close();
    void BeginRetirement();
    void CancelRetirement();
    bool Ready() const;
    LightExecutionGroupSnapshot ReadStatus() const;
private:
    struct Shared;
    std::shared_ptr<Shared> shared_;
    bool retiring_ = false;
};
}
