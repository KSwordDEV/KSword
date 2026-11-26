#include "LightNativeStopArchive.h"
#include "../../../KswordCLI/ActionAnalyze/Project/SampleImageDefinition.h"
#include <utility>

namespace Ksword::Features::ActionAnalyze {

bool LightNativeStopArchive::Prepare(const std::wstring& directory, bool openExisting)
{
    imageSha256_.reset(); // 新一轮sample不得继承上次定义的映像约束。
    if (directory.empty()) {
        if (openExisting) {
            view_.projectResult = {project::ProjectError::InvalidArgument, 0, "lightNativeExistingProjectRequired"};
            return false;
        }
        return true; // 无项目时读取仍走原owner，保存保持禁用。
    }
    view_.projectDirectory = directory; // 失败也保留用户请求路径。
    try {
        project_.emplace();
        view_.projectResult = openExisting
            ? project_->Open(directory, project::ProjectAccess::ReadWrite)
            : project_->Create(directory, {"Native stop observations", "Explicit memory and execution observations"});
        if (view_.projectResult) {
            project::SampleInfo sample; // 必须早于Start和任何读取生成真实采样。
            const auto revision = project_->Info()->revisionId; // 明确冻结当前已提交配置，不沿用历史sample或stop。
            view_.projectResult = project_->CreateSample("Native stop observations", sample, revision);
            if (view_.projectResult) {
                view_.sampleId = sample.sampleId;
            }
        }
    } catch (...) {
        view_.projectResult = {project::ProjectError::IoError, 0, "lightNativeStopProjectException"};
    }
    if (!view_.projectResult && project_) {
        project_->Close(); // 未Start前释放半创建项目租约，保留路径和失败回执。
    }
    return static_cast<bool>(view_.projectResult);
}

const std::string& LightNativeStopArchive::SampleId() const
{
    return view_.sampleId;
}

bool LightNativeStopArchive::ValidateImageDefinition(std::string_view definitionId, std::string_view definitionProjectId,
    const std::wstring& modulePath, std::optional<std::uint32_t> draftRva)
{
    imageSha256_.reset(); // 手工定义和核验失败都不得留下此前成功定义的散列。
    if (definitionId.empty()) {
        return true; // 手工输入模块位置不借用历史定义权限。
    }
    if (!project_ || !project_->Info() || SampleId().empty() || !draftRva || !*draftRva ||
        definitionProjectId.empty() || definitionProjectId != ProjectId()) {
        view_.projectResult = {project::ProjectError::InvalidArgument, 0, "lightNativeSampleDefinitionProject"};
        return false;
    }
    try {
        std::uint32_t frozenRva = 0; // 仅采用本轮sample的共享解析结果，不以UI旧值代替。
        std::optional<std::string> frozenImageSha256;
        view_.projectResult = project::ResolveSampleImageDefinition(*project_, SampleId(), definitionId,
            modulePath, frozenRva, &frozenImageSha256);
        if (view_.projectResult && frozenRva != *draftRva) {
            view_.projectResult = {project::ProjectError::StaleRevision, 0, "lightNativeSampleDefinitionRva"};
        }
        if (view_.projectResult)
        {
            imageSha256_ = std::move(frozenImageSha256); // 项目身份、冻结定义和RVA全部通过后才发布。
        }
    } catch (...) {
        view_.projectResult = {project::ProjectError::IoError, 0, "lightNativeSampleDefinitionException"};
    }
    return static_cast<bool>(view_.projectResult);
}

const std::optional<std::string>& LightNativeStopArchive::ImageSha256() const
{
    return imageSha256_;
}

std::string LightNativeStopArchive::ProjectId() const {
    return project_ && project_->Info() ? project_->Info()->projectId : std::string{};
}

void LightNativeStopArchive::ReadExecutionCandidates(const LightPrivateExecutionCandidatesRequest& request) {
    LightPrivateExecutionCandidatesView next;
    next.request = request;
    next.projectDirectory = view_.projectDirectory;
    if (candidates_) {
        next.page = candidates_->page;
        next.pageProjectDirectory = candidates_->pageProjectDirectory;
    }
    if (!project_ || !project_->Info() || request.projectId != project_->Info()->projectId ||
        request.sampleId != SampleId() || request.sampleId.empty()) {
        next.result = {project::ProjectError::InvalidArgument, 0, "lightPrivateCandidatesOriginalProjectSample"};
    } else if (!request.throughOrdinal || request.throughOrdinal > 128 ||
        request.after.has_value() != !request.expectedSnapshot.empty() ||
        (request.after && (!candidates_ || !candidates_->page ||
            candidates_->page->scope.projectId != request.projectId || candidates_->page->scope.sampleId != request.sampleId ||
            candidates_->page->throughOrdinal != request.throughOrdinal || candidates_->page->snapshot != request.expectedSnapshot ||
            candidates_->page->nextAfter != request.after))) {
        next.result = {project::ProjectError::StaleRevision, 0, "lightPrivateCandidatesCursorSnapshot"};
    } else {
        try {
            private_execution::PrivateExecutionCandidatesPage page;
            next.result = private_execution::ReadPrivateExecutionCandidates(*project_,
                {request.sampleId, request.throughOrdinal, request.after, private_execution::kPrivateCandidateMaxPage, request.expectedSnapshot}, page);
            if (next.result) {
                next.page = std::make_shared<const private_execution::PrivateExecutionCandidatesPage>(std::move(page));
                next.pageProjectDirectory = view_.projectDirectory;
            }
        } catch (...) {
            next.result = {project::ProjectError::IoError, 0, "lightPrivateCandidatesReadException"};
        }
    }
    candidates_ = std::make_shared<const LightPrivateExecutionCandidatesView>(std::move(next));
}

std::shared_ptr<const LightPrivateExecutionCandidatesView> LightNativeStopArchive::CandidateView() const {
    return candidates_;
}

void LightNativeStopArchive::CloseProject()
{
    if (project_) {
        project_->Close(); // 结束状态发布前归还本端writer，下一轮Start不会碰到旧租约。
    }
}

void LightNativeStopArchive::Capture(process_group_native::OwnedDataWatchSession& session,
    const process_group_native::NativeControlResult& stop,
    const ks::cli::action_analyze::memory::Plan& plan)
{
    memory_ = std::make_shared<const process_group_native::ProcessMemorySnapshotResult>(
        session.CaptureMemory(stop, plan)); // 原owner前后回读及完整sample/session/epoch核对。
    if (!view_.archiveBlocked) {
        view_.archive.reset(); // 新结果不抹掉旧坏尾回执。
        view_.archiveSource.reset();
    }
}

void LightNativeStopArchive::SaveMemory(
    const std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult>& shown)
{
    if (view_.archiveBlocked) {
        return; // 保留首次失败的真实回执，不越过坏尾。
    }
    if (!project_ || !project_->Info() || !shown || shown != memory_ || !shown->snapshot ||
        !shown->snapshot->round || shown->snapshot->round->pages.empty() ||
        shown->request.plan.sampleId != view_.sampleId) {
        view_.projectResult = {project::ProjectError::InvalidArgument, 0, "lightNativeMemorySelection"};
        return;
    }
    project::ProjectMemorySnapshotReceipt receipt; // 异常路径仍保留已知端点。
    view_.archiveSource = shown;
    try {
        view_.projectResult = project::WriteProcessGroupMemorySnapshot(*project_, view_.sampleId,
            memoryOrdinal_, memoryPrevious_, *shown, receipt);
        if (view_.projectResult && receipt.verified && receipt.raw.flushed) {
            memoryPrevious_ = receipt.raw.flushed->lastSequence;
            ++memoryOrdinal_;
        } else {
            view_.archiveBlocked = true;
        }
    } catch (...) {
        view_.archiveBlocked = true; // 无法确认尾段时禁止覆盖或跳段。
        view_.projectResult = {project::ProjectError::RecoveryRequired, 0, "lightNativeMemoryWrite"};
    }
    view_.archive = std::move(receipt);
}

void LightNativeStopArchive::SaveExecution(process_group_native::OwnedDataWatchSession& session,
    const process_group_native::NativeControlResult& stop)
{
    const auto observed = process_group_native::NativeExecutionFromOwnedStop(stop); // 不把普通dataWrite提升成执行。
    if (!project_ || !project_->Info() || !observed || session.Identity().sampleId != view_.sampleId ||
        observed->event.backendInstanceId != session.Identity().backendInstanceId) {
        if (executionBlocked_) return; // 后续无效请求不能覆盖首次坏尾现场。
        execution_ = {};
        execution_.result = {project::ProjectError::InvalidArgument, 0, "lightNativeExecutionOwner"};
        return;
    }
    const auto key = observed->event.backendInstanceId + "/" + std::to_string(observed->event.serial);
    if (const auto found = journal_.find(key); found != journal_.end()) {
        execution_ = found->second; // 原坐标重放不改变流级坏尾状态。
        execution_.duplicate = true;
        execution_.blocked = executionBlocked_;
        execution_.blockedFailure = executionFailure_;
        return;
    }
    if (executionBlocked_) {
        return;
    }
    if (journal_.size() >= 4096) {
        execution_ = {};
        execution_.result = {project::ProjectError::LimitExceeded, 0, "lightNativeExecutionSaveLimit"};
        return; // 显式会话保存预算有界，不影响原控制和清退。
    }
    project::ProjectNativeExecutionReceipt receipt; // 所有落盘结果均保留原坐标。
    execution_.observation = observed;
    try {
        execution_.result = session.SaveExecution(*project_, executionOrdinal_, executionPrevious_, stop, receipt);
        if (execution_.result && receipt.verified && receipt.raw.flushed) {
            executionPrevious_ = receipt.raw.flushed->lastSequence; // 新建sample空链为0，后续O(1)推进。
            ++executionOrdinal_;
        } else {
            executionBlocked_ = true;
        }
    } catch (...) {
        executionBlocked_ = true;
        execution_.result = {project::ProjectError::RecoveryRequired, 0, "lightNativeExecutionWrite"};
    }
    execution_.receipt = std::move(receipt);
    execution_.blocked = executionBlocked_;
    execution_.duplicate = false;
    if (executionBlocked_) {
        executionFailure_ = std::make_shared<const LightNativeExecutionView>(execution_);
        execution_.blockedFailure = executionFailure_; // 独立失败快照留给历史重放，不形成引用环。
    }
    journal_.emplace(key, execution_); // 同事件返回原结果，失败不重复写。
}

LightProcessGroupMemoryProjectView LightNativeStopArchive::ProjectView() const
{
    return view_;
}

LightNativeExecutionView LightNativeStopArchive::ExecutionView() const
{
    return execution_;
}

std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> LightNativeStopArchive::Latest() const
{
    return memory_;
}

// 原串行worker调用；API停止与清退不接触原native owner及事件责任。
void LightNativeStopArchive::CaptureApi(const project::NativeBoundApiRequest& request,
    const project::NativeBoundApiTarget& nativeTarget, const std::atomic_bool& cancel,
    const project::NativeBoundApiStartup& onStartup)
{
    // 原会话关闭可提前结束有限区间，采集器仍负责停钩和排空后返回本worker。
    if (project_)
    {
        api_ = std::make_shared<const project::NativeBoundApiResult>(
            project::CaptureNativeBoundApi(*project_, SampleId(), request, nativeTarget, cancel, onStartup));
        return;
    }
    project::NativeBoundApiResult rejected; // 无项目失败保留本次请求，禁止新开采样。
    rejected.request = request;
    rejected.nativeTarget = nativeTarget;
    rejected.sampleId = SampleId();
    rejected.rejection = project::NativeBoundApiRejection::ProjectUnavailable;
    rejected.admission = {project::ProjectError::NotOpen, 0, "nativeBoundApiWriter"};
    api_ = std::make_shared<const project::NativeBoundApiResult>(std::move(rejected));
}

// UI仅复制本值快照，无归档读取、控制权或后台查询。
std::shared_ptr<const project::NativeBoundApiResult> LightNativeStopArchive::ApiView() const
{
    return api_;
}

std::wstring FormatLightNativeExecution(const LightNativeExecutionView& view)
{
    if (!view.receipt && view.result) {
        return {}; // 尚未保存与成功空结果分开。
    }
    const std::string_view detail(view.result.detail); // 稳定ASCII诊断不翻译为成功。
    std::wstring text = L"\r\n执行观测归档回执\r\n诊断：" + std::wstring(detail.begin(), detail.end());
    text += L"\r\nWin32：" + std::to_wstring(view.result.nativeError);
    text += view.blocked ? L"\r\n执行流停止追加：是" : L"\r\n执行流停止追加：否";
    text += view.duplicate ? L"\r\n同事件原坐标：是" : L"\r\n同事件原坐标：否";
    if (view.duplicate && view.blockedFailure) {
        const auto& failure = *view.blockedFailure; // 旧成功坐标不能遮蔽后来停止追加的真实原因。
        const std::string_view reason(failure.result.detail);
        text += L"\r\n首次执行流阻断：" + std::wstring(reason.begin(), reason.end()) +
            L" / Win32 " + std::to_wstring(failure.result.nativeError);
        if (failure.receipt) {
            text += L"\r\n阻断段号：" + std::to_wstring(failure.receipt->ordinal);
            for (const auto* boundary : {&failure.receipt->raw.written, &failure.receipt->raw.flushed}) {
                text += boundary == &failure.receipt->raw.written ? L"\r\n阻断写入坐标：" : L"\r\n阻断刷盘坐标：";
                text += *boundary ? std::to_wstring((*boundary)->byteOffset) + L" / " +
                    std::to_wstring((*boundary)->blockOrdinal) + L" / " + std::to_wstring((*boundary)->lastSequence) : L"未取得";
            }
        }
    }
    if (view.observation) {
        const auto& event = *view.observation; // 当前UI停点可改变，归档来源仍绑定原事件。
        text += L"\r\n原生事件：" + std::wstring(event.event.backendInstanceId.begin(), event.event.backendInstanceId.end()) +
            L" / " + std::to_wstring(event.event.serial);
        text += L"\r\n目标 PID：" + std::to_wstring(event.pid) + L" / " + std::to_wstring(event.processCreationFileTime);
        text += L"\r\n执行线程 TID：" + std::to_wstring(event.thread.tid) + L" / " + std::to_wstring(event.thread.creationTime);
        text += event.kind == process_group_native::NativeExecutionKind::InstructionCompleted
            ? L"\r\n观测：单指令已完成" : L"\r\n观测：执行入口尝试";
        text += L"\r\n指令地址：" + std::to_wstring(event.instructionAddress);
    }
    if (view.receipt) {
        const auto& receipt = *view.receipt; // 写入/刷盘/核验分别呈现。
        text += L"\r\nraw-native 段号：" + std::to_wstring(receipt.ordinal);
        text += receipt.verified ? L"\r\n同步回读核验：是" : L"\r\n同步回读核验：否";
        text += L"\r\nSHA-256：" + std::wstring(receipt.sha256.begin(), receipt.sha256.end());
        for (const auto* boundary : {&receipt.raw.written, &receipt.raw.flushed}) {
            text += boundary == &receipt.raw.written ? L"\r\n写入坐标：" : L"\r\n刷盘坐标：";
            text += *boundary ? std::to_wstring((*boundary)->byteOffset) + L" / " +
                std::to_wstring((*boundary)->blockOrdinal) + L" / " + std::to_wstring((*boundary)->lastSequence) : L"未取得";
        }
    }
    return text;
}
}
