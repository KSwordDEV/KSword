#pragma once

#include "../../Core/Win32Lean.h"
#include "../../../KswordCLI/ActionAnalyze/Control/OwnedExecutionGroup.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ExecutionGroupArchive.h"
#include <memory>

namespace Ksword::Features::ActionAnalyze {
namespace execution_native = ks::cli::action_analyze::control;

enum class LightExecutionGroupCommand { Start, Query, Pause, Continue, Step, CancelStep, Identify, AddRange, SaveExecution, CaptureApi, ReadMemory, SaveMemory, AppendMembers };

// 点击时按值冻结；不借用窗口、列表索引或稍后可能改变的参数。
struct LightExecutionGroupRequest {
    LightExecutionGroupCommand command = LightExecutionGroupCommand::Query;
    std::vector<execution_native::ExecutionGroupSite> sites;
    std::string collectionId; // 显式追加冻结原集合身份，不能作用于下一轮集合。
    std::vector<execution_native::ExecutionGroupSessionEntry> sessions; // 混合Pause/Continue逐成员冻结原owner和完整control。
    std::vector<execution_native::NativeControlResult> stops;
    execution_native::NativeStepMode stepMode = execution_native::NativeStepMode::Into;
    bool authorized = false;
    bool all = false;
    std::uint32_t identityPid = 0;
    std::uint64_t address = 0; // AddRange点击时的手工范围草稿，不改写Start站点。
    std::uint64_t bytes = 0;
    std::wstring projectDirectory; // Start冻结的可选项目路径，空值只控制不归档。
    bool openExistingProject = false; // 明确打开已有项目，仍新建一轮sample。
    bool holdPeersOnHit = false; // 本次Start冻结的联停策略，追加成员不更换策略。
    Ksword::ActionAnalyze::NativeBoundApiRequest api; // CaptureApi冻结的另一明确来源，原worker复用同采样writer。
    std::shared_ptr<const execution_native::ProcessMemorySnapshotResult> memorySource; // 保存时冻结已读字节，不以当前选区重读。
};

struct LightExecutionGroupSnapshot {
    execution_native::ExecutionGroupResult result;
    Ksword::ActionAnalyze::ExecutionGroupArchiveView archive; // 原worker公布的归档身份及独立存储结果。
    std::shared_ptr<const Ksword::ActionAnalyze::NativeBoundApiProgress> apiStartup; // 原展示周期读取的不可变启动快照。
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
