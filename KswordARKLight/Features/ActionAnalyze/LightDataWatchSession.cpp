#include "LightDataWatchSession.h"

#include "../../Ui/BackgroundWork.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <utility>

namespace Ksword::Features::ActionAnalyze {
namespace {

using namespace ks::cli::action_analyze::control;
using NativeStopSnapshot = std::shared_ptr<const NativeControlResult>;
namespace rules = Ksword::ActionAnalyze::Rules;

std::wstring Widen(std::string_view text) { return {text.begin(), text.end()}; }

const EventResponsibility* WritableStop(const NativeControlResult& result) {
    const auto& group = result.group;
    const auto& event = result.pending;
    const auto& responsibility = result.responsibility;
    if (!result.attached || !group || group->historical || !group->origin ||
        group->origin->phase != StopPhase::DataWriteObserved || !result.breakpointHit || !result.breakpointHit->dataChange ||
        !event || !event->ledgerOwned || event->continuationIndeterminate || !responsibility ||
        (responsibility->state != EventState::Held && responsibility->state != EventState::Retryable) ||
        responsibility->event != event->event || responsibility->groupId != group->groupId) return nullptr;
    return &*responsibility;
}

// 输入当前原生事件与已核对责任，输出写入或执行命中的冻结身份；不读取新的线程列表。
LightDataWatchHit DescribeHit(const NativeControlResult& result, const EventResponsibility& stop) {
    const auto& change = result.breakpointHit->dataChange; // 执行入口保留空值，不冒充写入变化。
    const auto origin = std::find_if(result.frozenThreads.begin(), result.frozenThreads.end(), [&](const auto& thread) {
        return thread.identity == stop.actualEventThread && thread.tid == result.pending->tid;
    });
    return {Widen(stop.stopId) + L" · 修订 " + std::to_wstring(result.group->stateRevision) + L"\r\n停止组 " +
        Widen(stop.groupId) + L"\r\n原生事件 " + Widen(stop.event.backendInstanceId) + L" / " + std::to_wstring(stop.event.serial),
        result.pending->tid, origin == result.frozenThreads.end() ? 0 : origin->creationTime,
        change ? change->changedByteMask : 0, change ? change->enrolledAfterStop : 0,
        !change.has_value(), result.breakpointHit->address};
}

bool Terminal(const NativeControlResult& result) {
    if (!result.clean || result.attached) return false;
    return result.status == NativeControlStatus::Rejected || result.status == NativeControlStatus::Closed ||
        result.status == NativeControlStatus::Detached || result.status == NativeControlStatus::Ended ||
        result.status == NativeControlStatus::Idle;
}

} // namespace

struct LightDataWatchSession::Shared {
    struct Command {
        NativeStopSnapshot pauseSession; // 原Armed显示副本，与继续/相机/API共用唯一命令槽。
        NativeStopSnapshot continueStop;
        std::optional<NativeStepMode> stepMode; // 非空表示按此模式释放同一个停止事件。
        NativeStopSnapshot cancelStep; // 仅携带待取消的冻结步进身份。
        NativeStopSnapshot memoryStop; // 显式读取或执行保存的原完整停点。
        std::optional<ks::cli::action_analyze::memory::Plan> memoryPlan; // 点击时范围草稿。
        std::shared_ptr<const ProcessMemorySnapshotResult> saveMemory; // 点击时不可变capture。
        bool saveExecution = false; // 不与普通条件Query混用。
        bool followExecution = false; // 独立转换动作借用continueStop授权，但不执行Continue。
        bool dumpMemory = false; // 相机读取和保存属于同一串行命令，中间不插入Continue或Query。
        std::optional<std::pair<std::uint64_t, std::uint64_t>> addRange; // 起点/字节随continueStop冻结，只借用命令槽。
        std::optional<Ksword::ActionAnalyze::NativeBoundApiRequest> api;
        Ksword::ActionAnalyze::NativeBoundApiTarget apiTarget;
        std::string apiSample;
        std::optional<LightPrivateExecutionCandidatesRequest> candidates;
        std::shared_ptr<const private_execution::PrivateExecutionRangeDraft> rangeOrigin;
        std::uint64_t closeAttempt = 0;
    };

    mutable std::mutex mutex;
    std::condition_variable changed;
    LightDataWatchSnapshot status;
    Command queued;
    std::uint64_t requestedClose = 0;
    std::uint64_t failedClose = 0;
    bool closeRequested = false;
    std::weak_ptr<Ui::BackgroundCleanup> retirement; // Registration ownership stays with the registry.

    // 线程仅接收本次启动的冻结参数和表达式；完成后发布实际清退结果。
    void Run(const LightDataWatchRequest& request, rules::PreparedPredicate condition);

    Command TakeCommand() {
        using namespace std::chrono_literals;
        std::unique_lock lock(mutex);
        changed.wait_for(lock, 100ms, [&] { return queued.closeAttempt || queued.pauseSession || queued.continueStop || queued.cancelStep ||
            queued.memoryStop || queued.saveMemory || queued.api || queued.candidates; });
        return std::exchange(queued, {});
    }

    void RecordCleanupFailure(std::uint64_t attempt) {
        {
            std::lock_guard lock(mutex);
            failedClose = attempt;
        }
        changed.notify_all();
    }

    bool Retire() {
        std::unique_lock lock(mutex);
        if (!status.active) return true;
        const auto attempt = ++requestedClose;
        queued.closeAttempt = attempt;
        status.state = LightDataWatchState::Closing;
        changed.notify_all();
        changed.wait(lock, [&] { return !status.active || failedClose >= attempt; });
        return !status.active;
    }

    // 调用者已持mutex，同本轮归档值一起原子发布；只为确切可继续事件生成UI令牌。
    void Publish(NativeControlResult result, const DataWatchConditionReport& condition,
        bool terminal, bool commandCompleted, bool cleanupFailed, bool withoutCondition = false) {
        if (!status.pid && result.pid && result.processCreationTime) {
            status.pid = result.pid;
            status.creation = result.processCreationTime;
        }
        if (result.breakpoint) status.enrolledThreads = result.breakpoint->enrolledThreads;
        status.binding = result.breakpoint;
        status.nativeTarget = {result.pid, result.processCreationTime, result.attached};
        status.stopReason = result.stopReason;
        status.nativeClean = result.clean;
        if (result.firstRecoveryFailure) status.firstRecoveryFailure = result.firstRecoveryFailure;
        if (result.retirement) status.retirement = result.retirement;
        if (result.armedPause) status.armedPause = result.armedPause; // 普通回读/命令拒绝不擦除独立暂停回执。
        const auto& armed = status.displayedSession;
        if (!closeRequested && CanPauseDataWatchSession(result)) {
            if (!armed || armed->pid != result.pid || armed->processCreationTime != result.processCreationTime ||
                armed->processInstanceId != result.processInstanceId || armed->breakpoint->requestId != result.breakpoint->requestId ||
                (armed->armedPause ? armed->armedPause->request.requestId : std::string{}) !=
                    (result.armedPause ? result.armedPause->request.requestId : std::string{})) {
                status.displayedSession = std::make_shared<const NativeControlResult>(result);
            }
        } else status.displayedSession.reset();
        status.condition = condition;
        status.step = result.step;
        status.nativeStage = result.stage; // 保留实际后端stage，成功和受限推进均有来源。
        status.executionFollow = result.executionFollow; // 只增加操作回执，不改写lastHit中的原写入事实。
        if (result.executionRange) status.executionRange = result.executionRange; // 普通轮询不擦掉最近范围事务回执。
        const auto* stop = DataWatchHeldStop(result); // 写入、执行、步进及精确ManualPause共用原owner停止资格。
        if (stop && !withoutCondition && result.stopReason != NativeStopReason::ManualPause && !IsDataWatchStepStop(result) && !status.request.condition.empty() &&
            (!condition.last || condition.last->event != stop->event ||
                condition.last->evaluation.truth != rules::Truth::True)) {
            stop = nullptr;
        }
        const auto& prior = status.displayedStop;
        const bool newStop = stop && !closeRequested && (!prior || prior->responsibility->event != stop->event ||
                prior->responsibility->stopId != stop->stopId || prior->responsibility->groupId != stop->groupId ||
                prior->group->stateRevision != result.group->stateRevision ||
                (prior->breakpoint && result.breakpoint &&
                    (prior->breakpoint->writeWatchBytes != result.breakpoint->writeWatchBytes ||
                        prior->breakpoint->executionRanges != result.breakpoint->executionRanges)));
        if (newStop) {
            if (result.stopReason != NativeStopReason::ManualPause &&
                (WritableStop(result) || (!IsDataWatchStepStop(result) && result.breakpointHit))) {
                status.lastHit = DescribeHit(result, *stop); // 写入与执行分别标记，普通step不伪造进入尝试。
            }
            status.displayedStop = std::make_shared<NativeControlResult>(result);
            status.lastDisplayedStop = status.displayedStop; // 同一事件的寄存器与完整停点一起保留，不另行Query。
        } else if (!stop || closeRequested) {
            status.displayedStop.reset();
        }
        if (commandCompleted) status.continuing = false;

        if (result.win32Error || cleanupFailed) {
            status.diagnostic = Widen(result.stage);
            if (result.win32Error) status.diagnostic += L" · Win32 " + std::to_wstring(result.win32Error);
        } else if (commandCompleted || terminal || newStop) {
            status.diagnostic.clear();
        }

        if (terminal) {
            switch (result.status) {
            case NativeControlStatus::Closed:
            case NativeControlStatus::Detached: status.state = LightDataWatchState::Closed; break;
            case NativeControlStatus::Ended: status.state = LightDataWatchState::Exited; break;
            case NativeControlStatus::Idle: status.state = closeRequested ? LightDataWatchState::Cancelled : LightDataWatchState::Failed; break;
            default: status.state = LightDataWatchState::Failed; break;
            }
        } else if (cleanupFailed || (failedClose && failedClose == requestedClose) ||
            result.status == NativeControlStatus::RecoveryRequired) {
            status.state = LightDataWatchState::RecoveryRequired;
        } else if (closeRequested || result.status == NativeControlStatus::ClosePending) {
            status.state = LightDataWatchState::Closing;
        } else if (stop) {
            status.state = LightDataWatchState::Held;
        } else if (result.step && result.step->state == NativeStepState::Running) {
            status.state = LightDataWatchState::Stepping;
        } else if (result.breakpoint && result.breakpoint->state == NativeBreakpointState::Armed) {
            status.state = LightDataWatchState::Armed;
        }
    }
};

void LightDataWatchSession::Shared::Run(const LightDataWatchRequest& request, rules::PreparedPredicate condition) {
    std::optional<OwnedDataWatchSession> backend; // 初始化失败尚无原生责任，必须在线程内发布失败。
    try {
        backend.emplace();
    } catch (...) {
        std::lock_guard lock(mutex);
        status.state = LightDataWatchState::Failed;
        status.diagnostic = L"本端会话初始化失败，未启动目标。";
        status.active = false;
        changed.notify_all();
        return;
    }
    LightNativeStopArchive archive; // 与原session同一串行worker持有，清退后释放项目租约。
    NativeControlResult currentState; // 保存内存时沿用最近控制快照，不能用默认Idle冒充清退。
    std::uint64_t closeAttempt = 0;
    bool start = true;
    while (backend) {
        const auto command = start ? Command{} : TakeCommand();
        try {
            NativeControlResult result;
            std::wstring dumpDiagnostic; // 与本轮capture/归档值一起发布，避免新回执配上旧memory。
            std::shared_ptr<const Ksword::ActionAnalyze::NativeBoundApiResult> apiResult;
            if (std::exchange(start, false)) {
                bool cancelled = false;
                {
                    std::lock_guard lock(mutex);
                    cancelled = closeRequested;
                }
                if (!cancelled) {
                    if (archive.Prepare(request.projectDirectory, request.openExistingProject) &&
                        archive.ValidateImageDefinition(request.definitionId, request.definitionProjectId, request.executable, request.imageRva)) {
                        // 模块附加优先于旧启动分支，沿用本worker、项目采样及唯一原生所有者。
                        result = request.imageExecutionAttachment
                            ? backend->AttachImageExecution(request.targetPid, request.targetCreationFileTime,
                                request.executable, request.imageRva, request.exportName, std::move(condition),
                                archive.SampleId(), archive.ImageSha256()) // 原生按真实调试事件文件核对冻结散列后武装。
                            : request.privateAddress
                            ? backend->AttachPrivateAddress(request.targetPid, request.targetCreationFileTime,
                                request.privateAddress, request.bytes, std::move(condition), archive.SampleId(), request.privateRangeBytes)
                            : request.privateExecution
                            ? backend->StartPrivateExecution(request.executable, request.exportName,
                                std::move(condition), archive.SampleId())
                            : backend->Start(request.executable, request.exportName, request.bytes,
                                std::move(condition), request.indirect, archive.SampleId());
                    } else {
                        result.status = NativeControlStatus::Rejected;
                        result.stage = "light-data-watch-project-failed";
                        result.win32Error = archive.ProjectView().projectResult.nativeError;
                    }
                }
            } else if (command.closeAttempt) {
                closeAttempt = command.closeAttempt;
                result = backend->Close();
            } else if (command.pauseSession) {
                result = backend->Pause(*command.pauseSession); // 原owner主动下断，不Continue、不打开合作Gate。
            } else if (command.continueStop) {
                result = command.addRange ? backend->AddPrivateExecutionRange(*command.continueStop, command.addRange->first, command.addRange->second)
                    : command.followExecution ? backend->FollowPrivateExecution(*command.continueStop)
                    : command.stepMode ? backend->Step(*command.continueStop, *command.stepMode)
                    : backend->Continue(*command.continueStop);
            } else if (command.cancelStep) {
                result = backend->CancelStep(*command.cancelStep);
            } else if (command.candidates) {
                archive.ReadExecutionCandidates(*command.candidates); // 原writer/document/sample的只读投影，不生成新租约。
                result = currentState; // 候选读取本身不触发条件自动继续或其它控制。
            } else if (command.api) {
                result = backend->QueryWithoutCondition(); // 真实目标回读不ApplyCondition、不开Gate、不自动Continue。
                const Ksword::ActionAnalyze::NativeBoundApiTarget target{result.pid, result.processCreationTime, result.attached};
                if (archive.SampleId() != command.apiSample || !target.attached || target.pid != command.apiTarget.pid ||
                    target.creationFileTime != command.apiTarget.creationFileTime) {
                    Ksword::ActionAnalyze::NativeBoundApiResult rejected;
                    rejected.request = *command.api;
                    rejected.nativeTarget = target;
                    rejected.sampleId = command.apiSample;
                    rejected.rejection = Ksword::ActionAnalyze::NativeBoundApiRejection::NativeUnavailable;
                    rejected.admission = {Ksword::ActionAnalyze::ProjectError::InvalidArgument, 0, "lightNativeApiSessionChanged"};
                    apiResult = std::make_shared<const Ksword::ActionAnalyze::NativeBoundApiResult>(std::move(rejected));
                } else {
                    archive.CaptureApi(*command.api, target); // 原archive/writer/sample，不调用Continue/Close。
                    apiResult = archive.ApiView();
                    result = backend->QueryWithoutCondition(); // 采集期间可能真实命中；回投实际native状态，不ApplyCondition/自动Continue。
                }
            } else if (command.memoryStop) {
                if (command.saveExecution) {
                    archive.SaveExecution(*backend, *command.memoryStop);
                } else if (command.memoryPlan) {
                    const auto previous = archive.Latest(); // 冻结旧结果身份，读取失败绝不保存它。
                    archive.Capture(*backend, *command.memoryStop, *command.memoryPlan);
                    if (command.dumpMemory) {
                        const auto captured = archive.Latest(); // 只取得紧接Capture生成的完整capture。
                        if (!captured || captured == previous || !captured->snapshot || !captured->snapshot->round ||
                            captured->snapshot->round->pages.empty()) {
                            dumpDiagnostic = L"本次相机转储未取得可保存的读取结果；未保存此前内存快照。";
                        } else {
                            archive.SaveMemory(captured); // 保留读前/读后停点及缺页，不要求completeRange为真。
                            const auto view = archive.ProjectView();
                            dumpDiagnostic = view.projectResult && view.archive && view.archive->verified && view.archiveSource == captured
                                ? L"本次相机读取结果已保存到本会话项目。" : L"本次相机读取已完成，保存未确认；请核对内存归档回执。";
                        }
                        if (captured && captured != previous) {
                            dumpDiagnostic += L"\r\n相机读取阶段：" + Widen(captured->stage) + L" · Win32 " + std::to_wstring(captured->win32Error);
                        }
                    }
                }
                result = *command.memoryStop; // 不经ApplyCondition或Continue，原stop仅供显示。
            } else if (command.saveMemory) {
                archive.SaveMemory(command.saveMemory);
                result = currentState; // 即使目标已继续运行，也不产生额外Query条件副作用。
            } else {
                result = backend->Query();
            }

            const bool terminal = Terminal(result);
            currentState = result;
            const bool cleanupFailed = closeAttempt && !terminal && result.status != NativeControlStatus::ClosePending;
            {
                std::lock_guard lock(mutex); // 读取及保存完成后同回合发布不可变capture。
                status.memoryProject = archive.ProjectView();
                status.projectId = archive.ProjectId();
                status.candidates = archive.CandidateView();
                if (command.candidates) status.candidatesDiagnostic.clear();
                if (command.addRange) status.executionRangeOrigin = command.rangeOrigin;
                status.memory = archive.Latest();
                status.execution = archive.ExecutionView();
                if (command.dumpMemory) status.memoryDumpDiagnostic = std::move(dumpDiagnostic);
                if (command.api) {
                    status.api = std::move(apiResult);
                    status.apiDiagnostic = status.api ? L"" : L"本次API采集未返回回执，不能视为完成。";
                }
                Publish(std::move(result), backend->ConditionReport(), terminal,
                    command.pauseSession != nullptr || command.continueStop != nullptr || command.cancelStep != nullptr || command.memoryStop != nullptr ||
                        command.saveMemory != nullptr || command.api.has_value() || command.candidates.has_value(), cleanupFailed, command.api.has_value());
            }
            if (terminal) backend.reset(); // The terminal value proves native obligations are clear.
            if (cleanupFailed) RecordCleanupFailure(std::exchange(closeAttempt, 0));
        } catch (...) {
            {
                std::lock_guard lock(mutex);
                status.continuing = false;
                status.displayedStop.reset();
                status.displayedSession.reset();
                status.state = LightDataWatchState::RecoveryRequired;
                status.diagnostic = L"后台操作失败，请关闭监视并核对清退回执。";
                if (command.pauseSession) status.diagnostic = L"主动暂停操作发生异常，未确认新停止；原owner继续承担清退责任，请关闭监视并核对回执。";
                if (command.dumpMemory) status.memoryDumpDiagnostic = L"本次相机转储发生异常，未改为保存此前内存快照；请核对归档及恢复回执。";
                if (command.api) status.apiDiagnostic = L"本次API操作发生异常，采集、清退和归档均未获完整确认；此前回执保留。";
                if (command.candidates) status.candidatesDiagnostic = L"本次候选读取发生异常，旧目录及其来源身份保留，未视为空成功。";
            }
            if (closeAttempt) RecordCleanupFailure(std::exchange(closeAttempt, 0));
        }
    }
    archive.CloseProject(); // 同worker先释放writer，再向GUI与清退登记发布可重新启动。
    {
        std::lock_guard lock(mutex);
        status.active = false;
    }
    changed.notify_all();
}

LightDataWatchSession::~LightDataWatchSession() {
    BeginRetirement();
}

DWORD LightDataWatchSession::Start(LightDataWatchRequest request, rules::PreparedPredicate condition) {
    if (retiring_ || !Ready()) return ERROR_BUSY;
    if (request.imageExecutionAttachment) {
        // 仅接受完整实例及一种模块内位置；隐藏的私有/合作草稿不能污染附加请求。
        const bool asciiExport = !request.exportName.empty() && request.exportName.size() <= 255 &&
            std::all_of(request.exportName.begin(), request.exportName.end(),
            [](unsigned char character) { return character >= 33 && character <= 126; });
        if (!request.targetPid || !request.targetCreationFileTime || request.executable.empty() || request.bytes ||
            request.indirect || request.privateExecution || request.privateAddress || request.privateRangeBytes ||
            (request.imageRva ? !*request.imageRva || !request.exportName.empty() : !asciiExport)) {
            return ERROR_INVALID_PARAMETER;
        }
    } else if (request.imageRva) {
        return ERROR_INVALID_PARAMETER; // 模块RVA只能交给显式模块附加，不静默落入合作启动。
    } else if (request.targetPid || request.targetCreationFileTime || request.privateAddress || request.privateRangeBytes) {
        const bool writeWidth = request.bytes == 1 || request.bytes == 2 || request.bytes == 4 || request.bytes == 8;
        if (!request.targetPid || !request.targetCreationFileTime || !request.privateAddress ||
            !request.executable.empty() || !request.exportName.empty() || request.indirect ||
            (request.privateExecution ? request.bytes != 0 : !writeWidth) ||
            (request.privateRangeBytes && (request.privateRangeBytes > 64 * 4096 || request.privateRangeBytes % 4096 || !request.privateExecution ||
                request.privateAddress % 4096 != 0))) {
            return ERROR_INVALID_PARAMETER; // 拒绝不完整身份或混用导出草稿，不回退为启动新程序。
        }
    }
    try {
        auto lease = Ui::TryAcceptBackgroundWork();
        if (!lease) return ERROR_OPERATION_ABORTED;
        auto next = std::make_shared<Shared>();
        next->status.sessionIdentity = std::make_shared<const std::uint8_t>(0);
        next->status.request = request;
        next->status.active = true;
        next->status.state = LightDataWatchState::Starting;
        std::thread([next, lease = std::move(lease), request = std::move(request), condition = std::move(condition)]() mutable {
            next->Run(request, std::move(condition));
        }).detach();
        session_ = std::move(next);
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return ERROR_SUCCESS;
}

bool LightDataWatchSession::Pause(const NativeStopSnapshot& displayedSession) {
    if (!session_ || retiring_) return false;
    {
        std::lock_guard lock(session_->mutex);
        auto& status = session_->status;
        if (!displayedSession || !status.active || session_->closeRequested || status.continuing ||
            status.state != LightDataWatchState::Armed || status.displayedSession != displayedSession ||
            !CanPauseDataWatchSession(*displayedSession)) return false;
        session_->queued.pauseSession = displayedSession;
        status.continuing = true;
    }
    session_->changed.notify_all();
    return true;
}

bool LightDataWatchSession::Continue(const NativeStopSnapshot& displayedStop) {
    if (!session_ || retiring_) return false;
    {
        std::lock_guard lock(session_->mutex);
        auto& status = session_->status;
        if (!displayedStop || !status.active || session_->closeRequested || status.continuing ||
            status.displayedStop != displayedStop) return false;
        session_->queued.continueStop = displayedStop;
        status.continuing = true;
    }
    session_->changed.notify_all();
    return true;
}

bool LightDataWatchSession::FollowPrivateExecution(const NativeStopSnapshot& displayedStop)
{
    if (!session_ || retiring_)
    {
        return false;
    }
    {
        std::lock_guard lock(session_->mutex); // 转换与原Continue/Step/Close使用唯一命令槽。
        auto& status = session_->status; // 只访问已发布值，不在UI线程读目标上下文。
        if (!displayedStop || !status.active || session_->closeRequested || status.continuing ||
            status.displayedStop != displayedStop || !CanFollowDataWatchPrivateExecution(*displayedStop))
        {
            return false;
        }
        session_->queued.continueStop = displayedStop;
        session_->queued.followExecution = true;
        status.continuing = true;
    }
    session_->changed.notify_all();
    return true;
}

bool LightDataWatchSession::Step(const NativeStopSnapshot& displayedStop, NativeStepMode mode) {
    if (!session_ || retiring_) return false;
    {
        std::lock_guard lock(session_->mutex); // 与 Continue 使用相同入队槽及显示身份检查。
        auto& status = session_->status; // 不访问工作线程持有的原生句柄。
        if (!displayedStop || !status.active || session_->closeRequested || status.continuing ||
            status.displayedStop != displayedStop || displayedStop->stopReason == NativeStopReason::ManualPause) return false;
        session_->queued.continueStop = displayedStop;
        session_->queued.stepMode = mode;
        status.continuing = true;
    }
    session_->changed.notify_all();
    return true;
}

bool LightDataWatchSession::CancelStep(const NativeStepReceipt& displayedStep) {
    if (!session_ || retiring_) return false;
    {
        std::lock_guard lock(session_->mutex); // 当前请求完成或被替换后不再接受旧取消。
        auto& status = session_->status; // 回执按值发布，不重新查询目标。
        if (!status.active || session_->closeRequested || status.continuing || !status.step ||
            status.step->state != NativeStepState::Running || status.step->request != displayedStep.request) return false;
        auto frozen = std::make_shared<NativeControlResult>(); // 后端取消仅使用该冻结请求身份。
        frozen->step = displayedStep;
        session_->queued.cancelStep = std::move(frozen);
        status.continuing = true;
    }
    session_->changed.notify_all();
    return true;
}

bool LightDataWatchSession::ReadMemory(const NativeStopSnapshot& displayedStop,
    const ks::cli::action_analyze::memory::Plan& plan)
{
    if (!session_ || retiring_) {
        return false;
    }
    {
        std::lock_guard lock(session_->mutex); // 与Continue/Step使用同一入队互斥和忙状态。
        auto& status = session_->status;
        if (!displayedStop || !status.active || session_->closeRequested || status.continuing ||
            status.displayedStop != displayedStop) {
            return false;
        }
        session_->queued.memoryStop = displayedStop;
        session_->queued.memoryPlan = plan;
        status.continuing = true;
    }
    session_->changed.notify_all();
    return true;
}

bool LightDataWatchSession::DumpMemory(const NativeStopSnapshot& displayedStop,
    const ks::cli::action_analyze::memory::Plan& plan)
{
    if (!session_ || retiring_) return false;
    {
        std::lock_guard lock(session_->mutex); // 本次完整停点、原sample及范围一次入队，不拆成两个UI动作。
        auto& status = session_->status;
        if (!displayedStop || !status.active || session_->closeRequested || status.continuing ||
            status.displayedStop != displayedStop || !displayedStop->group || displayedStop->group->historical ||
            displayedStop->group->state != GroupState::HeldComplete || !DataWatchHeldStop(*displayedStop) ||
            status.memoryProject.sampleId.empty() || status.memoryProject.archiveBlocked ||
            plan.sampleId != status.memoryProject.sampleId || plan.sampleId != displayedStop->group->sampleId) {
            return false;
        }
        session_->queued.memoryStop = displayedStop;
        session_->queued.memoryPlan = plan;
        session_->queued.dumpMemory = true;
        status.memoryDumpDiagnostic = L"正在读取并保存本次停点内存；范围及停点已冻结。";
        status.continuing = true;
    }
    session_->changed.notify_all();
    return true;
}

bool LightDataWatchSession::AddPrivateExecutionRange(const NativeStopSnapshot& displayedStop,
    std::uint64_t address, std::uint64_t bytes, std::shared_ptr<const private_execution::PrivateExecutionRangeDraft> origin)
{
    if (!session_ || retiring_ || !address || address % 4096 || !bytes || bytes % 4096 || bytes > 64 * 4096 ||
        address > UINT64_MAX - bytes) return false;
    {
        std::lock_guard lock(session_->mutex); // 与相机/继续共用唯一槽，后端再核验事件、重叠及allocation。
        auto& status = session_->status;
        if (!displayedStop || !status.active || session_->closeRequested || status.continuing ||
            status.displayedStop != displayedStop || !displayedStop->group || displayedStop->group->historical ||
            displayedStop->group->state != GroupState::HeldComplete || !DataWatchHeldStop(*displayedStop) ||
            !displayedStop->breakpoint || !displayedStop->breakpoint->rangeBytes || displayedStop->breakpoint->writeWatchBytes ||
            displayedStop->breakpoint->state != NativeBreakpointState::Held) return false;
        if (origin && (origin->projectId != status.projectId || origin->sampleId != status.memoryProject.sampleId ||
            origin->targetPid != status.nativeTarget.pid || origin->targetCreationFileTime != status.nativeTarget.creationFileTime ||
            origin->address != address || origin->bytes != bytes)) return false;
        session_->queued.continueStop = displayedStop;
        session_->queued.addRange = std::make_pair(address, bytes);
        session_->queued.rangeOrigin = std::move(origin);
        status.continuing = true;
    }
    session_->changed.notify_all();
    return true;
}

bool LightDataWatchSession::ReadExecutionCandidates(const std::shared_ptr<const std::uint8_t>& identity,
    const LightPrivateExecutionCandidatesRequest& request) {
    if (!session_ || retiring_ || !request.throughOrdinal || request.throughOrdinal > 128) return false;
    {
        std::lock_guard lock(session_->mutex);
        auto& status = session_->status;
        if (!identity || identity != status.sessionIdentity || !status.active || session_->closeRequested || status.continuing ||
            status.state == LightDataWatchState::RecoveryRequired || request.projectId.empty() || request.projectId != status.projectId ||
            request.sampleId.empty() || request.sampleId != status.memoryProject.sampleId ||
            request.after.has_value() != !request.expectedSnapshot.empty()) return false;
        if (request.after && (!status.candidates || !status.candidates->page ||
            status.candidates->page->snapshot != request.expectedSnapshot || status.candidates->page->nextAfter != request.after ||
            status.candidates->page->throughOrdinal != request.throughOrdinal)) return false;
        session_->queued.candidates = request;
        status.continuing = true;
        status.candidatesDiagnostic = L"正在由原worker核验明确API前缀；旧目录保留，范围草稿不变。";
    }
    session_->changed.notify_all();
    return true;
}

bool LightDataWatchSession::CaptureApi(const LightDataWatchSnapshot& confirmedSession,
    const Ksword::ActionAnalyze::NativeBoundApiRequest& request)
{
    if (!session_ || retiring_ || !request.confirmed) return false;
    {
        std::lock_guard lock(session_->mutex);
        auto& status = session_->status;
        if (!status.active || status.continuing || session_->closeRequested || !confirmedSession.sessionIdentity ||
            status.sessionIdentity != confirmedSession.sessionIdentity || status.memoryProject.sampleId.empty() ||
            status.memoryProject.projectDirectory.empty() || status.memoryProject.sampleId != confirmedSession.memoryProject.sampleId ||
            status.nativeTarget.pid != confirmedSession.nativeTarget.pid ||
            status.nativeTarget.creationFileTime != confirmedSession.nativeTarget.creationFileTime ||
            Ksword::ActionAnalyze::ValidateNativeBoundApiRequest(request, status.nativeTarget) != Ksword::ActionAnalyze::NativeBoundApiRejection::None) return false;
        session_->queued.api = request;
        session_->queued.apiSample = status.memoryProject.sampleId;
        session_->queued.apiTarget = status.nativeTarget;
        status.apiDiagnostic = L"正在由原worker附加明确API来源并采集有限区间；关闭和其它命令等待本轮结算。";
        status.continuing = true;
    }
    session_->changed.notify_all();
    return true;
}

bool LightDataWatchSession::SaveMemory(const std::shared_ptr<const ProcessMemorySnapshotResult>& displayed)
{
    if (!session_ || retiring_) {
        return false;
    }
    {
        std::lock_guard lock(session_->mutex); // 保存同一个实际显示的capture，不重读地址控件。
        auto& status = session_->status;
        if (!status.active || session_->closeRequested || status.continuing || !displayed ||
            status.memory != displayed || status.memoryProject.sampleId.empty() || status.memoryProject.archiveBlocked) {
            return false;
        }
        session_->queued.saveMemory = displayed;
        status.continuing = true;
    }
    session_->changed.notify_all();
    return true;
}

bool LightDataWatchSession::SaveExecution(const NativeStopSnapshot& displayedStop)
{
    if (!session_ || retiring_) {
        return false;
    }
    {
        std::lock_guard lock(session_->mutex); // 原事件身份、项目资格和入队动作一次冻结。
        auto& status = session_->status;
        if (!displayedStop || !status.active || session_->closeRequested || status.continuing ||
            status.displayedStop != displayedStop || status.memoryProject.sampleId.empty() ||
            status.execution.blocked || displayedStop->stopReason == NativeStopReason::ManualPause ||
            !NativeExecutionFromOwnedStop(*displayedStop)) {
            return false;
        }
        session_->queued.memoryStop = displayedStop;
        session_->queued.saveExecution = true;
        status.continuing = true;
    }
    session_->changed.notify_all();
    return true;
}

void LightDataWatchSession::Close() {
    const auto owner = session_;
    if (!owner) return;
    {
        std::lock_guard lock(owner->mutex);
        if (!owner->status.active) return;
        owner->closeRequested = true;
        owner->queued.pauseSession.reset(); // 已派发的暂停及恢复责任仍交原worker的Close结算。
        owner->queued.continueStop.reset();
        owner->queued.stepMode.reset();
        owner->queued.followExecution = false; // 取消未派发转换，已在途回合由原worker结算。
        owner->queued.addRange.reset();
        owner->queued.rangeOrigin.reset();
        owner->queued.candidates.reset();
        owner->queued.cancelStep.reset();
        owner->queued.memoryStop.reset(); // 只取消未派发请求，在途读取由同worker结算后清退。
        owner->queued.memoryPlan.reset();
        owner->queued.saveMemory.reset();
        owner->queued.saveExecution = false;
        owner->queued.dumpMemory = false;
        owner->queued.api.reset(); // 取消未派发API；在途有限采集仍由同worker完成清退再关闭native。
        owner->status.displayedStop.reset();
        owner->status.displayedSession.reset();
        owner->status.continuing = false;
        owner->status.state = LightDataWatchState::Closing;
    }
    if (!owner->retirement.expired()) {
        Ui::BackgroundWorkRegistry::global().retry(true);
    } else {
        owner->retirement = Ui::RunBackgroundRetirement([owner] { return owner->Retire(); });
    }
}

void LightDataWatchSession::BeginRetirement() {
    retiring_ = true;
    Close();
}

bool LightDataWatchSession::Ready() const {
    if (!session_) return true;
    std::lock_guard lock(session_->mutex);
    return !session_->status.active;
}

void LightDataWatchSession::CancelRetirement() {
    retiring_ = false;
}

LightDataWatchSnapshot LightDataWatchSession::ReadStatus() const {
    if (!session_) return {};
    if (const auto cleanup = session_->retirement.lock(); cleanup &&
        cleanup->failure() == Ui::BackgroundWorkRegistry::Failure::ThreadCreation) {
        Ui::BackgroundWorkRegistry::global().retry();
    }
    std::lock_guard lock(session_->mutex);
    return session_->status;
}

} // namespace Ksword::Features::ActionAnalyze
