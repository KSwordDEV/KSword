#include "ProcessGroupSession.h"
#include "../UI/AsyncCleanupRegistry.h"

#include <Windows.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <optional>
#include <thread>

namespace ks::action_analyze
{
    namespace native = process_group_native;

    namespace
    {
        // 返回真实UTC FILETIME，供结果来源时间显示；不使用UI刷新时间冒充采样。
        std::uint64_t NowFileTime()
        {
            FILETIME now{}; // 操作系统当前UTC。
            ::GetSystemTimeAsFileTime(&now);
            return (static_cast<std::uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
        }

        // 复核输入身份，并从同一个句柄读取路径；失败保留原始错误，不猜测映像。
        ProcessGroupIdentityReadback ReadIdentity(native::ProcessGroupTarget target)
        {
            ProcessGroupIdentityReadback result; // 返回本次输入对应的真实读取结果。
            result.target = target;
            const std::unique_ptr<void, decltype(&::CloseHandle)> process(
                ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target.pid), &::CloseHandle); // 路径分配异常也释放原身份句柄。
            if (!process)
            {
                result.error = ::GetLastError();
                return result;
            }
            FILETIME creation{}, exit{}, kernel{}, user{}; // 同一进程对象的创建和CPU时间。
            if (!::GetProcessTimes(process.get(), &creation, &exit, &kernel, &user))
            {
                result.error = ::GetLastError();
            }
            else
            {
                const auto actual = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
                if (actual != target.creationFileTime)
                {
                    result.error = ERROR_INVALID_PARAMETER;
                }
                else
                {
                    std::wstring path(32768, L'\0'); // 系统允许的长路径缓冲。
                    DWORD count = static_cast<DWORD>(path.size()); // QueryFullProcessImageNameW的字符数。
                    if (::QueryFullProcessImageNameW(process.get(), 0, path.data(), &count))
                    {
                        path.resize(count);
                        result.imagePath = std::move(path);
                    }
                    else
                    {
                        result.error = ::GetLastError();
                    }
                }
            }
            return result;
        }
    }

    struct ProcessGroupSession::Shared
    {
        mutable std::mutex access; // GUI快照和命令队列的唯一锁。
        std::condition_variable changed; // 显式操作唤醒后台，不依赖Qt事件循环。
        std::optional<ProcessGroupRequest> pending; // 最多一项，不覆盖已接纳副作用。
        ProcessGroupSessionSnapshot snapshot; // 只按完整工作回合发布。
        native::OwnerIdentity identity; // 同一集合始终使用相同owner身份。
        bool closeRequested = false; // 销毁或显式关闭均走原Close路径。
        bool ended = false; // 已确认清退后后台退出。

        // 调用者只持共享值；原生group在该专用线程上构建、调用及清理。
        void Run()
        {
            std::optional<Ksword::ActionAnalyze::ProjectDocument> project; // 初始化成功后由本线程独占项目写租约。
            native::OwnerIdentity groupIdentity; // 配置前可绑定显式创建的真实采样，之后不改变。
            std::string sampleId; // 读取Plan必须与原生组的sample一致。
            std::wstring projectDirectory; // 已创建项目的真实目录。
            Ksword::ActionAnalyze::ProjectResult projectResult; // 最近项目操作回执。
            std::shared_ptr<const native::ProcessMemorySnapshotResult> lastMemory; // 原字节只由显式读生成。
            std::optional<Ksword::ActionAnalyze::ProjectMemorySnapshotReceipt> memoryArchive; // 最近保存回执。
            std::shared_ptr<const native::ProcessMemorySnapshotResult> memoryArchiveSource; // 本段实际保存的capture来源。
            std::uint64_t nextMemoryOrdinal = 1; // 独立raw-memory lane，不占API/ETW段号。
            std::optional<std::uint64_t> previousMemorySequence = 0; // 新sample空链为0；前段使用真实flushed末序号。
            bool memoryArchiveBlocked = false; // 坏尾不能通过跳段或覆盖文件规避。
            std::unique_ptr<native::OwnedProcessGroup> group; // 初始化阶段尚未取得任何目标控制责任。
            try
            {
                project.emplace();
                groupIdentity = identity;
                sampleId = identity.sampleId;
                group = std::make_unique<native::OwnedProcessGroup>(identity);
            }
            catch (...)
            {
                const auto failure = std::current_exception(); // 在改写状态前保留本次初始化异常。
                // 初始化失败尚未配置或附加，不让异常逃出线程触发整个程序terminate。
                std::lock_guard lock(access);
                snapshot.workerDiagnostic = "process-group-initialization-exception";
                try
                {
                    std::rethrow_exception(failure);
                }
                catch (const std::exception& error)
                {
                    snapshot.workerDiagnostic = std::string(error.what()).substr(0, 512); // 有界摘要不作为系统错误码。
                }
                catch (...)
                {
                    // 未知异常保留稳定阶段，不能编造错误原因。
                }
                snapshot.failed = true;
                snapshot.retired = true;
                snapshot.busy = false;
                ++snapshot.revision;
                ended = true;
                return;
            }
            for (;;)
            {
                ProcessGroupRequest request; // 本轮冻结的命令，离开锁后执行。
                bool closing = false; // 本轮是否执行原所有者清退。
                {
                    std::unique_lock lock(access); // 等待命令或下一轮真实状态回读。
                    changed.wait_for(lock, std::chrono::milliseconds(250), [this] {
                        return pending.has_value() || closeRequested;
                    });
                    closing = closeRequested;
                    if (pending)
                    {
                        request = std::move(*pending);
                        pending.reset();
                    }
                    else if (closing)
                    {
                        request.command = ProcessGroupCommand::Close;
                    }
                    snapshot.busy = true;
                }

                try
                {
                    native::ProcessGroupResult result; // 原生完整结果，不由首成员推断汇总。
                    std::vector<ProcessGroupIdentityReadback> identities; // Configure才重新读取身份来源。
                    switch (request.command)
                    {
                    case ProcessGroupCommand::Configure:
                        projectDirectory = request.newProjectDirectory; // 半创建失败也保留实际请求目录供恢复。
                        if (!request.newProjectDirectory.empty())
                        {
                            // 用户显式选择全新目录；Create拒绝已有项目，绝不抢别页活动writer。
                            projectResult = project->Create(request.newProjectDirectory,
                                {"Process group memory snapshots", "Explicit read-only selected ranges"});
                            Ksword::ActionAnalyze::SampleInfo sample; // 本端真实采样的冻结身份。
                            if (projectResult)
                            {
                                projectResult = project->CreateSample("Selected process memory", sample);
                            }
                            if (!projectResult)
                            {
                                project->Close(); // 尚未配置原生组，释放半创建项目租约但不删除现场目录。
                                result = group->Query();
                                result.stage = "process-group-memory-project-failed";
                                result.win32Error = projectResult.nativeError ? projectResult.nativeError : ERROR_INVALID_DATA;
                                break; // 未配置和附加任何进程；保留错误供用户清退后重试。
                            }
                            sampleId = sample.sampleId;
                            projectDirectory = request.newProjectDirectory;
                            groupIdentity.sampleId = sampleId;
                            group = std::make_unique<native::OwnedProcessGroup>(groupIdentity);
                        }
                        for (const auto& target : request.targets)
                        {
                            identities.push_back(ReadIdentity(target));
                        }
                        result = group->Configure(std::move(request.targets), request.authorized,
                            native::NativeTargetDisposition::ResumeAndDetach);
                        break;
                    case ProcessGroupCommand::Pause:
                        result = group->Pause(request.requestId, request.targets);
                        break;
                    case ProcessGroupCommand::Continue:
                        result = group->Continue(request.requestId, request.stops);
                        break;
                    case ProcessGroupCommand::Recover:
                        result = group->Recover(request.requestId);
                        break;
                    case ProcessGroupCommand::Close:
                        result = group->Close();
                        break;
                    case ProcessGroupCommand::Query:
                        result = group->Query();
                        break;
                    case ProcessGroupCommand::ReadMemory:
                        if (request.memory)
                        {
                            // 和Continue/Close处于同一串行线程，Held失败不回退Live。
                            lastMemory = std::make_shared<native::ProcessMemorySnapshotResult>(
                                native::CaptureProcessGroupMemory(*group, *request.memory));
                            if (!memoryArchiveBlocked)
                            {
                                memoryArchive.reset(); // 坏尾回执持续保留，新读取不能抹掉失败段身份。
                                memoryArchiveSource.reset();
                            }
                        }
                        result = group->Query();
                        break;
                    case ProcessGroupCommand::SaveMemory:
                        if (memoryArchiveBlocked)
                        {
                            result = group->Query(); // 保留首次失败回执，不接受新段越过坏尾。
                            break;
                        }
                        if (!project->Info() || !lastMemory || request.memoryToSave != lastMemory ||
                            !lastMemory->snapshot || !lastMemory->snapshot->round ||
                            lastMemory->snapshot->round->pages.empty() || lastMemory->request.plan.sampleId != sampleId)
                        {
                            projectResult = {Ksword::ActionAnalyze::ProjectError::InvalidArgument, 0, "memorySnapshotSelection"};
                        }
                        else
                        {
                            memoryArchive.emplace(); // writer异常时同样保留已经写入/刷盘的原坐标。
                            memoryArchiveSource = lastMemory;
                            auto& receipt = *memoryArchive;
                            const auto ordinal = nextMemoryOrdinal; // 仅前段核验成功后推进段号与前序。
                            projectResult = Ksword::ActionAnalyze::WriteProcessGroupMemorySnapshot(*project, sampleId,
                                ordinal, previousMemorySequence, *lastMemory, receipt); // 原样保存source、前后停点和真实读取回执。
                            if (projectResult && receipt.verified && receipt.raw.flushed)
                            {
                                previousMemorySequence = receipt.raw.flushed->lastSequence;
                                ++nextMemoryOrdinal;
                            }
                            else
                            {
                                memoryArchiveBlocked = true; // 保留失败段和原回执，新项目才能开始独立lane。
                            }
                        }
                        result = group->Query();
                        break;
                    }

                    // 同一锁发布状态、成员、票据和实际来源；UI不能读到半份回执。
                    const bool cleanClose = closing && request.command == ProcessGroupCommand::Close && result.clean;
                    if (cleanClose)
                    {
                        project->Close(); // 先归还原worker的写租约，再发布retired；新集合不能撞上旧writer。
                    }
                    {
                        std::lock_guard lock(access); // 短时复制回执，不在锁内调用原生系统接口。
                        snapshot.result = std::move(result);
                        if (request.command != ProcessGroupCommand::Query)
                        {
                            snapshot.lastCommandResult = snapshot.result; // 保存真实操作回执，Query只更新现态。
                        }
                        snapshot.sampleId = sampleId;
                        snapshot.projectDirectory = projectDirectory;
                        snapshot.projectResult = projectResult;
                        snapshot.memory = lastMemory;
                        snapshot.memoryArchive = memoryArchive;
                        snapshot.memoryArchiveSource = memoryArchiveSource;
                        snapshot.memoryArchiveBlocked = memoryArchiveBlocked;
                        if (request.command == ProcessGroupCommand::Configure)
                        {
                            snapshot.identities = std::move(identities);
                        }
                        if (snapshot.result.operation)
                        {
                            const auto& operation = *snapshot.result.operation; // 原生原票据或精确重放。
                            const auto found = std::find_if(snapshot.history.begin(), snapshot.history.end(), [&](const auto& item) {
                                return item.requestId == operation.requestId;
                            });
                            if (found == snapshot.history.end())
                            {
                                snapshot.history.push_back(operation);
                                if (snapshot.history.size() > 128)
                                {
                                    snapshot.history.erase(snapshot.history.begin());
                                }
                            }
                        }
                        snapshot.observedFileTime = NowFileTime();
                        snapshot.busy = false;
                        snapshot.closing = closeRequested;
                        snapshot.retired = cleanClose;
                        if (request.command != ProcessGroupCommand::Query)
                        {
                            snapshot.failed = false;
                            snapshot.workerDiagnostic.clear(); // 自动只读刷新不能抹去上一笔异常原因。
                        }
                        ++snapshot.revision;
                        ended = cleanClose;
                    }
                    if (cleanClose)
                    {
                        return; // 只有确认clean的原生group才允许析构。
                    }
                }
                catch (...)
                {
                    const auto failure = std::current_exception(); // 保存回合异常，不丢弃最后已发布原生状态。
                    std::lock_guard lock(access); // 异常不销毁可能仍持有事件的group。
                    snapshot.workerDiagnostic = "process-group-worker-exception";
                    try
                    {
                        std::rethrow_exception(failure);
                    }
                    catch (const std::exception& error)
                    {
                        snapshot.workerDiagnostic = std::string(error.what()).substr(0, 512);
                    }
                    catch (...)
                    {
                        // 非标准异常只保留稳定阶段，不生成成功或清退结论。
                    }
                    snapshot.projectDirectory = projectDirectory; // Create或采样登记抛异常也保留真实请求来源。
                    snapshot.sampleId = sampleId;
                    if (request.command == ProcessGroupCommand::Configure)
                    {
                        projectResult = {Ksword::ActionAnalyze::ProjectError::RecoveryRequired, 0,
                            "processGroupConfigureException"}; // 原生配置状态未知，须通过原Close确认后释放项目。
                        snapshot.projectResult = projectResult;
                    }
                    if (request.command == ProcessGroupCommand::SaveMemory)
                    {
                        memoryArchiveBlocked = true; // 写入是否落盘未知时不得覆盖重试或越过尾段。
                        snapshot.memoryArchiveBlocked = true;
                        snapshot.memoryArchive = memoryArchive;
                        snapshot.memoryArchiveSource = memoryArchiveSource;
                        projectResult = {Ksword::ActionAnalyze::ProjectError::RecoveryRequired, 0, "memorySnapshotSelection"};
                        snapshot.projectResult = projectResult;
                    }
                    snapshot.failed = true;
                    snapshot.busy = false;
                    ++snapshot.revision;
                }

                // Close未决时避免忙循环；仍保留原owner和原票据，不伪造恢复成功。
                if (closing)
                {
                    std::unique_lock lock(access);
                    changed.wait_for(lock, std::chrono::milliseconds(500));
                }
            }
        }
    };

    ProcessGroupSession::ProcessGroupSession(native::OwnerIdentity identity)
        : m_shared(std::make_shared<Shared>())
    {
        m_shared->identity = std::move(identity);
        try
        {
            const std::weak_ptr<Shared> weakOwner = m_shared; // 退出回调不强持有同时承担租约的会话。
            auto cleanup = ks::ui::AsyncCleanupRegistry::global().acquire([weakOwner] {
                if (const auto owner = weakOwner.lock())
                {
                    std::lock_guard lock(owner->access); // 只请求STOP，不在关闭事件中做原生调用。
                    owner->closeRequested = true;
                    owner->snapshot.closing = true;
                    owner->changed.notify_one();
                }
            });
            if (!cleanup)
            {
                m_shared->snapshot.failed = true;
                m_shared->snapshot.retired = true;
                m_shared->ended = true; // 主窗口已进入退出流程，不接纳新的本端会话。
                return;
            }
            std::thread([owner = m_shared, cleanup = std::move(cleanup)]() mutable {
                owner->Run(); // 仍由同一串行线程保留group，直到Close真正clean。
                cleanup.reset(); // Run局部group及项目租约已析构后才解除主窗口退出等待。
            }).detach();
        }
        catch (...)
        {
            m_shared->snapshot.failed = true;
            m_shared->snapshot.retired = true; // 启动失败没有原生责任，允许显式新集合。
            m_shared->ended = true; // 线程未创建，没有原生副作用。
        }
    }

    ProcessGroupSession::~ProcessGroupSession()
    {
        Close(); // GUI不join可能未决的调试线程。
    }

    bool ProcessGroupSession::Submit(ProcessGroupRequest request)
    {
        std::lock_guard lock(m_shared->access); // 忙时明确拒绝，调用方保留输入草稿。
        const bool recovery = request.command == ProcessGroupCommand::Recover; // Closing期间仍接受原票据恢复。
        if (m_shared->ended || (m_shared->closeRequested && !recovery) || m_shared->pending || m_shared->snapshot.busy)
        {
            return false;
        }
        m_shared->pending = std::move(request);
        m_shared->snapshot.busy = true;
        m_shared->changed.notify_one();
        return true;
    }

    ProcessGroupSessionSnapshot ProcessGroupSession::Read() const
    {
        std::lock_guard lock(m_shared->access); // 管理器和GUI只取得已公布值。
        return m_shared->snapshot;
    }

    void ProcessGroupSession::Close()
    {
        std::lock_guard lock(m_shared->access); // 不取消已经接受的副作用请求。
        m_shared->closeRequested = true;
        m_shared->snapshot.closing = true;
        m_shared->changed.notify_one();
    }
}
