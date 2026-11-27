#pragma once

#include "../../Core/Win32Lean.h"
#include "../../../KswordCLI/ActionAnalyze/Control/OwnedDataWatchSession.h"
#include "LightNativeStopArchive.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace Ksword::Features::ActionAnalyze {

struct LightDataWatchRequest {
    std::wstring executable;
    std::string exportName;
    std::uint32_t bytes = 0;
    std::wstring condition; // 本次启动时的表达式原文，用于回执而非重新求值。
    bool indirect = false; // 指针导出选择私有区间；缺省仍是旧映像数据绑定。
    std::wstring projectDirectory; // Start前冻结的新建目录或原项目路径；仅新建模式空路径可不归档。
    bool openExistingProject = false; // Start前明确冻结打开原项目；成功后总是创建本轮新采样。
    bool privateExecution = false; // 显式私有执行模式；缺省保持现有两种写入绑定兼容。
    std::uint32_t targetPid = 0; // 已有实例的PID；与创建时间及私有绝对地址一起冻结。
    std::uint64_t targetCreationFileTime = 0; // 原实例创建FILETIME，不由后来同PID的进程替代。
    std::uint64_t privateAddress = 0; // 非零表示直接附加私有地址；执行时bytes为0。
    std::uint64_t privateRangeBytes = 0; // 0为原单地址模式；1..64个4KiB页为显式私有执行范围。
    bool imageExecutionAttachment = false; // 已有实例的普通模块执行；不启动合作目标，也不借用私有地址。
    bool suspendedImageLaunch = false; // 普通EXE原始挂起期间由原owner先布置入口断点。
    std::optional<std::uint32_t> imageRva; // 非零模块RVA与精确PE导出二选一，均在Start前冻结。
    std::string definitionId; // 从项目定义载入的来源ID；仅冻结来源，不作为原生控制令牌。
    std::string definitionProjectId; // 定义入口选择的原项目，由archive在真实sample解析前再次匹配。
};

enum class LightDataWatchState { Idle, Starting, Armed, Held, Stepping, Closing, Closed, Exited, Failed, RecoveryRequired, Cancelled };

struct LightDataWatchHit {
    std::wstring token;
    std::uint32_t tid = 0;
    std::uint64_t threadCreation = 0;
    std::uint32_t changedByteMask = 0;
    std::uint64_t enrolledAfterStop = 0;
    bool execution = false; // 执行进入尝试不携带有效数据变化掩码。
    std::uint64_t address = 0; // 原生命中的真实执行或数据地址。
};

struct LightDataWatchSnapshot {
    std::shared_ptr<const std::uint8_t> sessionIdentity; // 每次Start独有的纯值代次，确认后不能串到后来会话。
    LightDataWatchState state = LightDataWatchState::Idle;
    LightDataWatchRequest request;
    std::uint32_t pid = 0;
    std::uint64_t creation = 0;
    std::optional<std::size_t> enrolledThreads;
    std::optional<ks::cli::action_analyze::control::NativeBreakpointBinding> binding; // 当前实际地址及私有区域回读。
    std::optional<LightDataWatchHit> lastHit;
    std::optional<ks::cli::action_analyze::control::SuspendedImageLaunchReceipt> launch; // 与控制同回合发布的实际启动阶段。
    std::shared_ptr<const ks::cli::action_analyze::control::NativeControlResult> displayedStop;
    std::shared_ptr<const ks::cli::action_analyze::control::NativeControlResult> lastDisplayedStop; // 最近显示停点的只读快照；继续/清退后仍保留，不授控制权。
    std::wstring diagnostic;
    ks::cli::action_analyze::control::DataWatchConditionReport condition; // 与当前控制状态来自同一工作回合。
    bool active = false;
    bool continuing = false;
    std::optional<ks::cli::action_analyze::control::NativeStepReceipt> step; // 当前原生步进回执，独立于最近写入事件。
    LightProcessGroupMemoryProjectView memoryProject; // 原worker独占项目的纯值回执。
    std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> memory; // 完整冻结capture含readContext。
    LightNativeExecutionView execution; // 独立raw-native流的最近保存回执。
    std::optional<ks::cli::action_analyze::control::NativeExecutionFollowReceipt> executionFollow; // 转换不改变源写入证据。
    std::string nativeStage; // 最近原生控制回执的真实阶段，页推进限制不由页面猜测。
    std::wstring memoryDumpDiagnostic; // 相机读取及保存的本次结果，不把旧memory当作新转储。
    std::optional<ks::cli::action_analyze::control::NativeExecutionRangeReceipt> executionRange;
    Ksword::ActionAnalyze::NativeBoundApiTarget nativeTarget; // 原worker最近真实回读的目标，区别于API来源草稿。
    std::shared_ptr<const Ksword::ActionAnalyze::NativeBoundApiResult> api;
    std::shared_ptr<const Ksword::ActionAnalyze::NativeBoundApiProgress> apiStartup; // 当前在途API的原启动阶段。
    std::shared_ptr<const Ksword::ActionAnalyze::ProjectApiCheckpoint> apiCheckpoint; // 同一writer已提交的最新水位。
    std::shared_ptr<const Ksword::ActionAnalyze::CooperativeApiRuleReceipt> apiRules; // 同一已提交前缀的规则回执。
    std::shared_ptr<const Ksword::ActionAnalyze::CooperativeApiTransferReceipt> apiTransfers; // 同一已提交前缀的转移快照。
    std::wstring apiDiagnostic;
    std::shared_ptr<const ks::cli::action_analyze::control::NativeControlResult> displayedSession; // 可暂停的原Armed副本；相同绑定轮询保持身份。
    ks::cli::action_analyze::control::NativeStopReason stopReason = ks::cli::action_analyze::control::NativeStopReason::None;
    std::optional<ks::cli::action_analyze::control::NativeArmedPauseReceipt> armedPause; // 与真实hit及清退回执独立。
    bool nativeClean = true; // 仅原native回读可确认清退，不由暂停receipt推导。
    std::optional<ks::cli::action_analyze::control::NativeRecoveryFailure> firstRecoveryFailure;
    std::optional<ks::cli::action_analyze::control::NativeRetirementReceipt> retirement;
    std::string projectId; // 原archive实际打开身份，不以路径相等代替。
    std::shared_ptr<const LightPrivateExecutionCandidatesView> candidates;
    std::wstring candidatesDiagnostic;
    std::shared_ptr<const private_execution::PrivateExecutionRangeDraft> executionRangeOrigin; // 本次显式纳入的历史来源。
};

// The page reads values and submits commands. Native handles stay on the worker.
class LightDataWatchSession final {
public:
    LightDataWatchSession() = default;
    ~LightDataWatchSession();
    LightDataWatchSession(const LightDataWatchSession&) = delete;
    LightDataWatchSession& operator=(const LightDataWatchSession&) = delete;

    // 接受页面冻结的参数与已校验谓词。返回异步工作入队结果。
    DWORD Start(LightDataWatchRequest request, Ksword::ActionAnalyze::Rules::PreparedPredicate condition);
    // 输入页面展示的原Armed副本；原worker调用原backend->Pause，不ApplyCondition或新建owner。
    bool Pause(const std::shared_ptr<const ks::cli::action_analyze::control::NativeControlResult>& displayedSession);
    bool Continue(const std::shared_ptr<const ks::cli::action_analyze::control::NativeControlResult>& displayedStop);
    // 输入显示的完整私有写入停点，在原worker切换同址DR0类型；不Continue、不创建新owner。
    bool FollowPrivateExecution(const std::shared_ptr<const ks::cli::action_analyze::control::NativeControlResult>& displayedStop);
    // 点击时冻结的停止快照与模式入队，工作线程复用原会话执行。
    bool Step(const std::shared_ptr<const ks::cli::action_analyze::control::NativeControlResult>& displayedStop,
        ks::cli::action_analyze::control::NativeStepMode mode);
    // 只取消页面所显示的当前请求，不因一次迟到点击中止新的步进。
    bool CancelStep(const ks::cli::action_analyze::control::NativeStepReceipt& displayedStep);
    // 点击时冻结原停点和Plan，在原串行worker读取；失败不回退Live。
    bool ReadMemory(const std::shared_ptr<const process_group_native::NativeControlResult>& displayedStop,
        const ks::cli::action_analyze::memory::Plan& plan);
    // 相机以一个命令冻结stop/Plan，同worker先Capture再保存这次完整结果；不复用旧memory。
    bool DumpMemory(const std::shared_ptr<const process_group_native::NativeControlResult>& displayedStop,
        const ks::cli::action_analyze::memory::Plan& plan);
    // 冻结原NX停点及新增范围，沿原worker纳入；不Continue、不触发ApplyCondition。
    bool AddPrivateExecutionRange(const std::shared_ptr<const process_group_native::NativeControlResult>& displayedStop,
        std::uint64_t address, std::uint64_t bytes,
        std::shared_ptr<const private_execution::PrivateExecutionRangeDraft> origin = {});
    // 与所有控制/归档共用原worker；只读原项目明确前缀，不Query/ApplyCondition。
    bool ReadExecutionCandidates(const std::shared_ptr<const std::uint8_t>& sessionIdentity,
        const LightPrivateExecutionCandidatesRequest& request);
    // 确认前的会话/采样/目标与当前发布值一致才入原命令槽，worker再Query真实目标。
    bool CaptureApi(const LightDataWatchSnapshot& confirmedSession, const Ksword::ActionAnalyze::NativeBoundApiRequest& request);
    // 保存当前实际显示的完整capture，不借用后来选择或创建新sample。
    bool SaveMemory(const std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult>& displayed);
    // 仅对真实可提取执行事件入队，普通写入停点不启用。
    bool SaveExecution(const std::shared_ptr<const process_group_native::NativeControlResult>& displayedStop);
    void Close();
    void BeginRetirement();
    bool Ready() const;
    void CancelRetirement();
    LightDataWatchSnapshot ReadStatus() const;

private:
    struct Shared;
    std::shared_ptr<Shared> session_;
    bool retiring_ = false;
};

} // namespace Ksword::Features::ActionAnalyze
