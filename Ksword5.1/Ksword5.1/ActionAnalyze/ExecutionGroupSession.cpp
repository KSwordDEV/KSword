#include "../Framework.h"
#include "ExecutionGroupSession.h"
#include "../UI/AsyncCleanupRegistry.h"

#include <chrono>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>

namespace ks::action_analyze
{
    namespace native = execution_group_native;

    struct ExecutionGroupSession::Shared
    {
        mutable std::mutex access; // 仅保护请求与公布快照，不在锁内执行调试调用。
        std::condition_variable changed; // 显式动作或关闭请求唤醒后台。
        std::optional<ExecutionGroupRequest> pending; // 最多一个已受理的值请求。
        ExecutionGroupSessionSnapshot snapshot; // GUI和后台管理器共同读取的完整值。
        ks::ui::TaskCpuToken cpu; // 原任务管理器的纯值计量令牌，后台只读取本轮副本。
        bool closeRequested = false; // 一经设置不再接纳新操作。
        bool ended = false; // 原组已clean或线程创建前失败。
        std::atomic_bool apiCancel = false; // 关闭准入时立即取消在途API，原调试清退仍由同一worker串行执行。

        // 异常只影响本轮任务；原owner始终留在同一worker，下一轮进入清退。
        void Fail(const std::exception_ptr& failure)
        {
            std::string message = "execution-group-worker-exception"; // 未知异常使用稳定诊断。
            try
            {
                std::rethrow_exception(failure);
            }
            catch (const std::exception& error)
            {
                message = std::string(error.what()).substr(0, 512);
            }
            catch (...)
            {
                // 非标准异常不推测Win32原因，也不发布虚假的clean。
            }
            std::lock_guard lock(access); // 原结果仍可供用户查看，不用空状态覆盖。
            snapshot.failed = true;
            snapshot.diagnostic = std::move(message);
            snapshot.busy = false;
            snapshot.closing = true;
            closeRequested = true;
            apiCancel.store(true);
            ++snapshot.revision;
        }

        // 只有此函数访问集合。250ms后台回读不生成kPro任务，隐藏页面也不停止条件处理。
        void Run()
        {
            std::unique_ptr<native::OwnedExecutionGroup> group; // 原集合仅在专用线程中构造和释放。
            Ksword::ActionAnalyze::ExecutionGroupArchive archive; // 唯一writer与原生操作同线程串行。
            try
            {
                group = std::make_unique<native::OwnedExecutionGroup>();
            }
            catch (...)
            {
                Fail(std::current_exception());
                std::lock_guard lock(access);
                snapshot.retired = true;
                ended = true; // 尚未创建任何owner，没有原生责任。
                return;
            }

            bool started = false; // 未提交Start时只等待显式请求，不轮询系统。
            for (;;)
            {
                ExecutionGroupRequest request; // 离开锁后使用本轮冻结副本。
                ks::ui::TaskCpuToken cpuToken; // 计量仅包围一轮原生工作，不包括等待或整条线程。
                bool closing = false; // Close优先阻止尚未执行的新请求。
                {
                    std::unique_lock lock(access);
                    if (started || closeRequested)
                    {
                        changed.wait_for(lock, std::chrono::milliseconds(250), [this] {
                            return pending.has_value() || closeRequested;
                        });
                    }
                    else
                    {
                        changed.wait(lock, [this] { return pending.has_value() || closeRequested; });
                    }
                    closing = closeRequested;
                    if (!closing && pending)
                    {
                        request = std::move(*pending);
                    }
                    pending.reset(); // 清退取消尚未执行的队列，不产生迟到Start。
                    snapshot.busy = true;
                    cpuToken = cpu;
                }

                try
                {
                    ks::ui::TaskCpuScope cpuScope(std::move(cpuToken), ks::ui::TaskCpuPhase::Worker); // 关闭计量时不读取时钟。
                    native::ExecutionGroupResult result; // 全部字段来自同一个原集合调用。
                    if (closing)
                    {
                        result = group->Close();
                    }
                    else
                    {
                        switch (request.command)
                        {
                        case ExecutionGroupCommand::Start:
                            started = true;
                            if (archive.Prepare(request.projectDirectory, request.openExistingProject) && archive.ResolveSites(request.sites))
                            {
                                // 先创建本轮采样，再给全部原成员同一真实sample；失败不附加任何目标。
                                result = group->Start(std::move(request.sites), request.authorized,
                                    native::NativeTargetDisposition::ResumeAndDetach,
                                    archive.View().sampleId.empty() ? request.sampleId : archive.View().sampleId,
                                    request.holdPeersOnHit); // 原Query执行联停，不新增后台任务或owner。
                            }
                            else
                            {
                                result = group->QueryWithoutCondition(); // 详情保留项目失败，不伪报原生Start成功。
                            }
                            break;
                        case ExecutionGroupCommand::Query:
                            result = group->Query();
                            break;
                        case ExecutionGroupCommand::AppendMembers:
                            result = archive.AppendMembers(*group, std::move(request.sites), request.authorized,
                                request.collectionId); // 沿同一worker、writer和sample追加，不重新启动原成员。
                            break;
                        case ExecutionGroupCommand::Continue:
                            result = group->Continue(request.sessions, request.all);
                            break;
                        case ExecutionGroupCommand::Pause:
                            result = group->Pause(request.sessions, request.all);
                            break;
                        case ExecutionGroupCommand::Step:
                            result = request.stops.size() == 1 ? group->Step(request.stops.front(), request.mode) : group->Query();
                            break;
                        case ExecutionGroupCommand::CancelStep:
                            result = request.stops.size() == 1 ? group->CancelStep(request.stops.front()) : group->Query();
                            break;
                        case ExecutionGroupCommand::AddRange:
                            if (request.stops.size() == 1)
                            {
                                result = group->AddRange(request.stops.front(), request.rangeAddress, request.rangeBytes);
                            }
                            break;
                        case ExecutionGroupCommand::SaveExecution:
                            if (request.sessions.size() == 1)
                            {
                                archive.Save(*group, request.sessions.front()); // 完整原owner/control，不执行条件或Continue。
                            }
                            result = group->QueryWithoutCondition();
                            break;
                        case ExecutionGroupCommand::CaptureApi:
                            if (request.sessions.size() == 1)
                            {
                                archive.CaptureApi(*group, request.sessions.front(), request.api, apiCancel,
                                    [this](const Ksword::ActionAnalyze::NativeBoundApiProgress& progress) {
                                        auto value = std::make_shared<const Ksword::ActionAnalyze::NativeBoundApiProgress>(progress); // 不可变进度只含纯值。
                                        std::lock_guard lock(access); // 不持此锁执行采集或调试调用。
                                        snapshot.apiStartup = std::move(value);
                                        ++snapshot.revision;
                                    });
                            }
                            result = group->QueryWithoutCondition(); // API结束不求同伴条件，不自动Continue。
                            break;
                        case ExecutionGroupCommand::ReadMemory:
                            if (request.sessions.size() == 1)
                            {
                                archive.CaptureMemory(*group, request.sessions.front(), request.rangeAddress, request.rangeBytes, &apiCancel); // 同一关闭取消位，原worker串行读取。
                            }
                            result = group->QueryWithoutCondition();
                            break;
                        case ExecutionGroupCommand::SaveMemory:
                            archive.SaveMemory(request.memorySource); // 显式保存旧读取，不以当前行或参数改写其身份。
                            result = group->QueryWithoutCondition();
                            break;
                        }
                    }

                    FILETIME observed{}; // 真实回读完成时间，未声称跨进程同时采样。
                    ::GetSystemTimeAsFileTime(&observed);
                    const bool retired = closing && result.clean;
                    if (retired)
                    {
                        archive.Close(); // 归还writer前必须由原集合确认全体clean。
                    }
                    {
                        std::lock_guard lock(access); // 一次发布成员、操作回执及观察时间。
                        snapshot.result = std::move(result);
                        snapshot.archive = archive.View(); // 保存与控制在同一修订公布，不从GUI读取项目。
                        snapshot.observedFileTime = (static_cast<std::uint64_t>(observed.dwHighDateTime) << 32) | observed.dwLowDateTime;
                        snapshot.busy = false;
                        snapshot.closing = closeRequested;
                        snapshot.retired = retired;
                        ++snapshot.revision;
                        ended = retired;
                    }
                    if (retired)
                    {
                        return; // Run返回时先析构已clean集合，外层随后归还退出租约。
                    }
                }
                catch (...)
                {
                    {
                        std::lock_guard lock(access); // 写入异常也发布原始失败和实际writer状态，不能留下旧成功。
                        snapshot.archive = archive.View();
                    }
                    Fail(std::current_exception()); // 不允许异常销毁持有原生责任的集合。
                }

                if (closing)
                {
                    std::unique_lock lock(access); // 未清退时等待，避免Close重试忙循环。
                    changed.wait_for(lock, std::chrono::milliseconds(250));
                }
            }
        }
    };

    ExecutionGroupSession::ExecutionGroupSession()
        : m_shared(std::make_shared<Shared>())
    {
        try
        {
            const std::weak_ptr<Shared> weak = m_shared; // 退出回调不与lease形成引用环。
            auto lease = ks::ui::AsyncCleanupRegistry::global().acquire([weak] {
                if (const auto owner = weak.lock())
                {
                    std::lock_guard lock(owner->access); // 退出只请求关闭，不在GUI线程调原生API。
                    owner->closeRequested = true;
                    owner->apiCancel.store(true); // 程序退出和用户关闭使用同一个在途取消位。
                    owner->snapshot.closing = true;
                    owner->changed.notify_one();
                }
            });
            if (!lease)
            {
                throw std::runtime_error("execution-group-shutdown-in-progress");
            }
            std::thread([owner = m_shared, lease = std::move(lease)]() mutable {
                owner->Run(); // 页面销毁后仍持同一组，直到所有原owner真实clean。
                lease.reset();
            }).detach();
        }
        catch (...)
        {
            std::lock_guard lock(m_shared->access); // 线程尚未启动，不存在目标控制副作用。
            m_shared->snapshot.failed = true;
            m_shared->snapshot.retired = true;
            m_shared->snapshot.diagnostic = "execution-group-worker-unavailable";
            m_shared->ended = true;
            ++m_shared->snapshot.revision;
        }
    }

    ExecutionGroupSession::~ExecutionGroupSession()
    {
        Close(); // 不在GUI join原生调试线程，清退租约继续保活。
    }

    bool ExecutionGroupSession::Submit(ExecutionGroupRequest request)
    {
        std::lock_guard lock(m_shared->access); // 单个在途请求不能被新参数覆盖。
        if (m_shared->ended || m_shared->closeRequested || m_shared->pending || m_shared->snapshot.busy)
        {
            return false;
        }
        if (request.command == ExecutionGroupCommand::CaptureApi || request.command == ExecutionGroupCommand::ReadMemory)
        {
            m_shared->apiCancel.store(false); // 在关闭检查之后清零，仅属于本次已受理请求。
            m_shared->snapshot.apiStartup.reset();
        }
        m_shared->pending = std::move(request);
        m_shared->snapshot.busy = true;
        m_shared->changed.notify_one();
        return true;
    }

    ExecutionGroupSessionSnapshot ExecutionGroupSession::Read() const
    {
        std::lock_guard lock(m_shared->access); // 只读取已公布值，不执行查询或枚举。
        return m_shared->snapshot;
    }

    void ExecutionGroupSession::Close()
    {
        std::lock_guard lock(m_shared->access); // 关闭请求可以在任何显式操作在途时提交。
        m_shared->closeRequested = true;
        m_shared->apiCancel.store(true); // 不等待采集线程持锁，附加/排空按共享服务取消语义收尾。
        m_shared->snapshot.closing = true;
        m_shared->changed.notify_one();
    }

    void ExecutionGroupSession::SetCpuToken(ks::ui::TaskCpuToken token)
    {
        std::lock_guard lock(m_shared->access); // 同一查询在途时只更新下一轮身份，不重建业务会话。
        m_shared->cpu = std::move(token);
    }
}
