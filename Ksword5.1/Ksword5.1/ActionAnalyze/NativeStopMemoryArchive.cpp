#include "../Framework.h"
#include "NativeStopMemoryArchive.h"
#include "../../../KswordCLI/ActionAnalyze/Project/SampleImageDefinition.h"
#include <utility>

namespace ks::action_analyze
{
    // 目录方式由用户在启动时冻结，打开已有项目也总是创建独立新采样。
    bool NativeStopMemoryArchive::PrepareProject(const std::wstring& directory, bool openExisting)
    {
        if (directory.empty())
        {
            if (openExisting)
            {
                m_view.projectResult = {Ksword::ActionAnalyze::ProjectError::InvalidArgument, 0, "nativeStopExistingProjectDirectoryRequired"};
                return false;
            }
            return true; // 无归档请求仍允许显式读取，不借用其他页面的writer。
        }
        m_view.projectDirectory = directory; // 即使创建失败也保留用户请求的实际路径。
        try
        {
            m_project.emplace();
            m_view.projectResult = openExisting
                ? m_project->Open(directory, Ksword::ActionAnalyze::ProjectAccess::ReadWrite)
                : m_project->Create(directory, {"Native stop observations", "Explicit memory and execution observations"});
            if (m_view.projectResult)
            {
                Ksword::ActionAnalyze::SampleInfo sample; // 在任何Start或读取前登记的真实采样。
                m_view.projectResult = m_project->CreateSample("Native stop observations", sample);
                if (m_view.projectResult)
                {
                    m_view.sampleId = sample.sampleId; // 每次启动创建新sample，不沿用历史lane、句柄或stop。
                }
            }
        }
        catch (...)
        {
            m_view.projectResult = {Ksword::ActionAnalyze::ProjectError::IoError, 0, "nativeStopProjectException"};
        }
        if (!m_view.projectResult && m_project)
        {
            m_project->Close(); // 启动前失败没有原生责任；保留实际路径与失败，不占用writer。
        }
        return static_cast<bool>(m_view.projectResult);
    }

    // 输入所选定义及实际模块位置，核验原sample身份后才允许向原生owner提交。
    bool NativeStopMemoryArchive::ValidateImageDefinition(std::string_view definitionId,
        const std::wstring& modulePath, std::uint32_t rva)
    {
        if (definitionId.empty())
        {
            return true; // 手工位置不声明来自已保存的项目定义。
        }
        std::uint32_t resolved = 0; // 由当前sample冻结配置解析出的唯一RVA。
        m_view.projectResult = m_project
            ? Ksword::ActionAnalyze::ResolveSampleImageDefinition(*m_project, m_view.sampleId, definitionId, modulePath, resolved)
            : Ksword::ActionAnalyze::ProjectResult{Ksword::ActionAnalyze::ProjectError::NotOpen, 0, "sampleBreakpointProjectRequired"};
        if (m_view.projectResult && resolved != rva)
        {
            m_view.projectResult = {Ksword::ActionAnalyze::ProjectError::InvalidArgument, 0, "sampleBreakpointRvaMismatch"};
        }
        return static_cast<bool>(m_view.projectResult);
    }

    const std::string& NativeStopMemoryArchive::SampleId() const
    {
        return m_view.sampleId;
    }

    void NativeStopMemoryArchive::Capture(process_group_native::OwnedDataWatchSession& session,
        const process_group_native::NativeControlResult& displayed,
        const ks::cli::action_analyze::memory::Plan& plan)
    {
        // CaptureMemory自行核对原owner/sample/session/epoch及前后停点，不经条件自动继续入口。
        m_view.memory = std::make_shared<process_group_native::ProcessMemorySnapshotResult>(
            session.CaptureMemory(displayed, plan));
        if (!m_view.memoryArchiveBlocked)
        {
            m_view.memoryArchive.reset();
            m_view.memoryArchiveSource.reset();
        }
    }

    void NativeStopMemoryArchive::Save(
        const std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult>& displayed)
    {
        if (m_view.memoryArchiveBlocked)
        {
            return; // 首次坏尾回执保持原样，后续点击不得覆盖其诊断。
        }
        if (!m_project || !m_project->Info() || !displayed || displayed != m_view.memory ||
            !displayed->snapshot || !displayed->snapshot->round || displayed->snapshot->round->pages.empty() ||
            displayed->request.plan.sampleId != m_view.sampleId)
        {
            m_view.projectResult = {Ksword::ActionAnalyze::ProjectError::InvalidArgument, 0, "memorySnapshotSelection"};
            return;
        }
        Ksword::ActionAnalyze::ProjectMemorySnapshotReceipt receipt; // 异常路径也保留已产生的写入与刷盘坐标。
        m_view.memoryArchiveSource = displayed;
        try
        {
            m_view.projectResult = Ksword::ActionAnalyze::WriteProcessGroupMemorySnapshot(*m_project,
                m_view.sampleId, m_ordinal, m_previous, *displayed, receipt);
            if (m_view.projectResult && receipt.verified && receipt.raw.flushed)
            {
                m_previous = receipt.raw.flushed->lastSequence;
                ++m_ordinal;
            }
            else
            {
                m_view.memoryArchiveBlocked = true; // 保留可能已写入的原段，不覆盖或跳段。
            }
            m_view.memoryArchive = std::move(receipt);
        }
        catch (...)
        {
            m_view.memoryArchiveBlocked = true; // 落盘状态未知时仍保留writer，等待显式清退。
            m_view.memoryArchive = std::move(receipt);
            m_view.projectResult = {Ksword::ActionAnalyze::ProjectError::RecoveryRequired, 0, "memorySnapshotSelection"};
        }
    }

    ProcessGroupSessionSnapshot NativeStopMemoryArchive::View() const
    {
        return m_view;
    }

    void NativeStopMemoryArchive::SaveExecution(process_group_native::OwnedDataWatchSession& session,
        const process_group_native::NativeControlResult& displayed)
    {
        const auto observed = process_group_native::NativeExecutionFromOwnedStop(displayed); // 只接受真实Into完成或执行入口。
        if (!m_project || !m_project->Info() || !observed || m_view.sampleId != session.Identity().sampleId ||
            observed->event.backendInstanceId != session.Identity().backendInstanceId)
        {
            if (m_executionBlocked) return; // 无效后续点击也不能覆盖首次坏尾诊断。
            m_execution = {};
            m_execution.result = {Ksword::ActionAnalyze::ProjectError::InvalidArgument, 0, "nativeExecutionActiveOwner"};
            return;
        }
        const auto key = observed->event.backendInstanceId + "/" + std::to_string(observed->event.serial); // 同session内唯一原生事件。
        if (const auto found = m_executionJournal.find(key); found != m_executionJournal.end())
        {
            m_execution = found->second;
            m_execution.duplicate = true;
            m_execution.blocked = m_executionBlocked;
            m_execution.blockedFailure = m_executionFailure;
            return;
        }
        if (m_executionBlocked)
        {
            return; // 未知坏尾不能由另一次点击越过，保留原失败回执。
        }
        if (m_executionJournal.size() >= 4096)
        {
            m_execution = {};
            m_execution.result = {Ksword::ActionAnalyze::ProjectError::LimitExceeded, 0, "nativeExecutionSaveLimit"};
            return;
        }
        Ksword::ActionAnalyze::ProjectNativeExecutionReceipt receipt; // 原SaveExecution异常也保留已得到的真实端点。
        m_execution.observation = observed;
        try
        {
            m_execution.result = session.SaveExecution(*m_project, m_executionOrdinal,
                m_executionPrevious, displayed, receipt);
            if (m_execution.result && receipt.verified && receipt.raw.flushed)
            {
                m_executionPrevious = receipt.raw.flushed->lastSequence;
                ++m_executionOrdinal;
            }
            else
            {
                m_executionBlocked = true;
            }
        }
        catch (...)
        {
            m_executionBlocked = true;
            m_execution.result = {Ksword::ActionAnalyze::ProjectError::RecoveryRequired, 0, "nativeExecutionWrite"};
        }
        m_execution.receipt = std::move(receipt);
        m_execution.blocked = m_executionBlocked;
        m_execution.duplicate = false;
        if (m_executionBlocked)
        {
            m_executionFailure = std::make_shared<const NativeExecutionArchiveView>(m_execution);
            m_execution.blockedFailure = m_executionFailure; // 首次失败独立保存，不因历史重放丢失。
        }
        m_executionJournal.emplace(key, m_execution); // 后续同事件返原坐标，包括失败现场。
    }

    NativeExecutionArchiveView NativeStopMemoryArchive::ExecutionView() const
    {
        return m_execution;
    }

    // 参数均为点击冻结值；方法只在持原native会话的串行worker内调用。
    void NativeStopMemoryArchive::CaptureApi(const Ksword::ActionAnalyze::NativeBoundApiRequest& request,
        const Ksword::ActionAnalyze::NativeBoundApiTarget& nativeTarget)
    {
        const std::atomic_bool cancel{false}; // 本入口采用固定有限区间，不操作原session控制。
        if (m_project)
        {
            m_api = std::make_shared<const Ksword::ActionAnalyze::NativeBoundApiResult>(
                Ksword::ActionAnalyze::CaptureNativeBoundApi(*m_project, SampleId(), request, nativeTarget, cancel));
            return;
        }
        Ksword::ActionAnalyze::NativeBoundApiResult rejected; // 无项目时保留本次来源和目标，不能另建writer。
        rejected.request = request;
        rejected.nativeTarget = nativeTarget;
        rejected.sampleId = SampleId();
        rejected.rejection = Ksword::ActionAnalyze::NativeBoundApiRejection::ProjectUnavailable;
        rejected.admission = {Ksword::ActionAnalyze::ProjectError::NotOpen, 0, "nativeBoundApiWriter"};
        m_api = std::make_shared<const Ksword::ActionAnalyze::NativeBoundApiResult>(std::move(rejected));
    }

    // 无输入，返回可跨UI线程复制的不可变值；不授予项目或原生所有权。
    std::shared_ptr<const Ksword::ActionAnalyze::NativeBoundApiResult> NativeStopMemoryArchive::ApiView() const
    {
        return m_api;
    }

    void NativeStopMemoryArchive::CloseProject()
    {
        if (m_project)
        {
            m_project->Close(); // clean后释放本端写租约，不影响冻结结果和归档坐标。
        }
    }
}
