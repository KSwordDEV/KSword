#pragma once

#include "LightProcessGroupMemory.h"
#include "../../../KswordCLI/ActionAnalyze/Control/OwnedDataWatchSession.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectNativeExecution.h"
#include "../../../KswordCLI/ActionAnalyze/Project/NativeBoundApiCapture.h"
#include "LightPrivateExecutionCandidatesFields.h"
#include <optional>
#include <string>
#include <unordered_map>

namespace Ksword::Features::ActionAnalyze {

// 原session工作线程发布的执行流回执；不携带活原生控制权。
struct LightNativeExecutionView {
    project::ProjectResult result; // 原项目写入或核验结论。
    std::optional<project::ProjectNativeExecutionReceipt> receipt; // 段号、原坐标和散列。
    std::optional<process_group_native::NativeExecutionEvidence> observation; // 原保存事件快照，只有证据语义没有活控制权。
    bool blocked = false; // 失败后只阻止本流追加，仍允许清退。
    bool duplicate = false; // 同事件复用旧坐标，不再次写段。
    std::shared_ptr<const LightNativeExecutionView> blockedFailure; // 历史重放时仍展示首次坏尾原因。
};

// Light写入/步进页的独立项目绑定，所有方法由持原session的同一worker串行调用。
class LightNativeStopArchive final {
public:
    // Start前明确新建或打开原项目，每次登记新sample；新建模式空目录仅显式读取。
    bool Prepare(const std::wstring& directory, bool openExisting = false);
    // 在本轮真实sample冻结配置核验定义；成功才允许原owner附加，手工无ID时直接通过。
    bool ValidateImageDefinition(std::string_view definitionId, std::string_view definitionProjectId,
        const std::wstring& modulePath, std::optional<std::uint32_t> draftRva,
        std::wstring& conditionSource, project::Rules::PreparedPredicate& condition);
    // 同一worker读取本轮sample核验成功后冻结的可选散列；只传给原生映像准入，不在UI计算。
    const std::optional<std::string>& ImageSha256() const;
    // 返回Start实际使用的sample；不得在采集后修改旧Plan来源。
    const std::string& SampleId() const;
    // 原session确认clean后由同一worker调用；释放项目租约，保留冻结回执供查看。
    void CloseProject();
    // 在原session读取当前显示停点，不调用Query条件路径或第二owner。
    void Capture(process_group_native::OwnedDataWatchSession& session,
        const process_group_native::NativeControlResult& stop,
        const ks::cli::action_analyze::memory::Plan& plan);
    // 保存同一不可变结果到原sample，完整保留readContext和实际成功页。
    void SaveMemory(const std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult>& shown);
    // 保存真实执行事件；同事件去重，raw-native与raw-memory完全独立。
    void SaveExecution(process_group_native::OwnedDataWatchSession& session,
        const process_group_native::NativeControlResult& stop);
    // 发布纯值项目和执行结果；调用者在自身锁内复制到UI快照。
    LightProcessGroupMemoryProjectView ProjectView() const;
    LightNativeExecutionView ExecutionView() const;
    // 同一worker输入明确来源和刚回读的原native目标；只使用私有原document与SampleId。
    // cancel借用原会话关闭标记，只触发API原清退，不继续或关闭native目标。
    void CaptureApi(const project::NativeBoundApiRequest& request, const project::NativeBoundApiTarget& nativeTarget,
        const std::atomic_bool& cancel, const project::NativeBoundApiStartup& onStartup = {});
    // 无输入，返回最近API请求的不可变完整回执；未请求时为空，不要求UI读取文件。
    std::shared_ptr<const project::NativeBoundApiResult> ApiView() const;
    std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> Latest() const;
    // 在原document/sample只读核验明确前缀；失败保留最近成功目录，不另开项目。
    void ReadExecutionCandidates(const LightPrivateExecutionCandidatesRequest& request);
    std::shared_ptr<const LightPrivateExecutionCandidatesView> CandidateView() const;
    std::string ProjectId() const; // 原已打开项目的纯身份，UI不触及document。

private:
    std::optional<project::ProjectDocument> project_; // 本worker独占的项目写租约。
    std::optional<std::string> imageSha256_; // 仅属于最近成功核验的sample定义，手工位置不沿用旧值。
    std::shared_ptr<const project::NativeBoundApiResult> api_; // API与内存/执行归档分开保存结果。
    std::shared_ptr<const LightPrivateExecutionCandidatesView> candidates_;
    LightProcessGroupMemoryProjectView view_; // 内存流身份与坏尾回执。
    LightNativeExecutionView execution_; // 最近显式执行保存结果。
    bool executionBlocked_ = false; // 流级阻断不被历史去重回执覆盖。
    std::shared_ptr<const LightNativeExecutionView> executionFailure_; // 首次失败快照，不持自身引用。
    std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> memory_; // 实际读取的完整capture。
    std::uint64_t memoryOrdinal_ = 1, executionOrdinal_ = 1; // 两条独立lane各自起段。
    std::optional<std::uint64_t> memoryPrevious_ = 0, executionPrevious_ = 0; // 各流真实末序号。
    std::unordered_map<std::string, LightNativeExecutionView> journal_; // 原session内backend/serial去重。
};

// 纯值格式化执行观测和归档坐标，供共享文本外壳搜索、复制和导出。
std::wstring FormatLightNativeExecution(const LightNativeExecutionView& view);
}
