#include "OwnedDataWatchSession.h"

#include "../Project/ProjectNativeExecution.h"
#include "../Project/ProjectStorage.h"

#include <utility>

namespace ks::cli::action_analyze::control {

ProcessMemorySnapshotResult OwnedDataWatchSession::CaptureMemory(const NativeControlResult& displayedStop,
    const memory::Plan& plan, const std::atomic_bool* cancel)
{
    ProcessMemorySnapshotRequest request;
    request.plan = plan;
    request.source = ProcessMemorySource::HeldEvent;
    const auto* stop = DataWatchHeldStop(displayedStop);
    if (stop && displayedStop.group) {
        request.stop = ProcessGroupStop{{displayedStop.pid, displayedStop.processCreationTime}, stop->groupId,
            stop->stopId, stop->event, displayedStop.group->stateRevision};
    }
    if (!owner_ || closing_ || !stop || !displayedStop.group ||
        displayedStop.group->sampleId != identity_.sampleId || displayedStop.group->sessionId != identity_.sessionId ||
        displayedStop.group->epoch != identity_.epoch || stop->event.backendInstanceId != identity_.backendInstanceId) {
        ProcessMemorySnapshotResult result;
        result.request = std::move(request);
        result.stage = "data-watch-memory-stale-stop";
        result.win32Error = ERROR_INVALID_STATE;
        return result;
    }
    // 不调用 ApplyCondition/Query：读取请求本身不会触发条件的自动继续。
    return CaptureNativeStopMemory(*owner_, identity_, request, cancel);
}

// 调查与项目写入单独编译，纯会话消费者仍只链接原有控制依赖。
Ksword::ActionAnalyze::ProjectResult OwnedDataWatchSession::SaveExecution(Ksword::ActionAnalyze::ProjectDocument& project,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence,
    const NativeControlResult& displayedStop, Ksword::ActionAnalyze::ProjectNativeExecutionReceipt& receipt)
{
    namespace storage = Ksword::ActionAnalyze::ProjectStorage;
    receipt = {};
    receipt.ordinal = ordinal;
    if (!owner_ || closing_) {
        return storage::Failure(Ksword::ActionAnalyze::ProjectError::InvalidArgument, "dataWatchExecutionUnavailable");
    }
    const auto current = QueryWithoutCondition(); // 保留会话既有恢复失败；不运行条件，不申请继续。
    if (!MatchesDisplayedStop(displayedStop, current) || !NativeExecutionFromOwnedStop(current)) {
        return storage::Failure(Ksword::ActionAnalyze::ProjectError::InvalidArgument, "dataWatchExecutionStaleStop");
    }
    return Ksword::ActionAnalyze::WriteNativeExecution(project, identity_, ordinal, previousSequence, current, receipt);
}

} // namespace ks::cli::action_analyze::control
