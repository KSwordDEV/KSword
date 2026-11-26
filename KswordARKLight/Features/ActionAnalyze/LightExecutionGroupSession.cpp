#include "LightExecutionGroupSession.h"
#include "../../Ui/BackgroundWork.h"
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <thread>

namespace Ksword::Features::ActionAnalyze {
namespace {
std::uint64_t NowFileTime()
{
    FILETIME time{};
    ::GetSystemTimeAsFileTime(&time);
    return (std::uint64_t{time.dwHighDateTime} << 32) | time.dwLowDateTime;
}
}

struct LightExecutionGroupSession::Shared {
    std::mutex mutex;
    std::condition_variable changed;
    LightExecutionGroupSnapshot status;
    std::optional<LightExecutionGroupRequest> pending;
    std::weak_ptr<Ui::BackgroundCleanup> retirement;
    std::uint64_t closeRequested = 0, closeTaken = 0, closeConclusions = 0;
    bool released = true;
    bool stopping = false;

    void Publish(execution_native::ExecutionGroupResult result, bool explicitOperation = false,
        const Ksword::ActionAnalyze::ExecutionGroupArchiveView* archive = nullptr)
    {
        std::lock_guard lock(mutex);
        status.result = std::move(result);
        if (archive) status.archive = *archive; // 本轮控制及存储值原子发布，不查询另一个writer。
        status.observedFileTime = NowFileTime();
        if (explicitOperation) status.operationFileTime = status.observedFileTime;
        status.diagnostic.clear();
        ++status.revision;
    }

    // 清退登记只发请求并等待本次结论；原生Close仍由原worker执行。
    bool Retire()
    {
        std::unique_lock lock(mutex);
        if (released) return true;
        const auto baseline = closeConclusions;
        ++closeRequested;
        status.closing = true;
        changed.notify_all();
        changed.wait(lock, [&] { return released || closeConclusions > baseline || !status.active; });
        return released;
    }

    void Run()
    {
        std::unique_ptr<execution_native::OwnedExecutionGroup> group;
        std::unique_ptr<Ksword::ActionAnalyze::ExecutionGroupArchive> archive; // 每次显式Start新建，clean之前不替换。
        for (;;) {
            std::optional<LightExecutionGroupRequest> request;
            bool close = false;
            {
                std::unique_lock lock(mutex);
                changed.wait_for(lock, std::chrono::milliseconds(250), [&] {
                    return pending.has_value() || closeRequested > closeTaken || (stopping && released);
                });
                if (pending) {
                    request = std::move(pending);
                    pending.reset();
                } else if (closeRequested > closeTaken) {
                    close = true;
                    closeTaken = closeRequested;
                } else if (stopping && released) {
                    // 已确认clean的集合也只在原worker上析构。
                    group.reset();
                    status.active = false;
                    changed.notify_all();
                    return;
                }
                status.busy = request.has_value() || close || group != nullptr;
            }
            try {
                if (close) {
                    const auto result = group ? group->Close() : execution_native::ExecutionGroupResult{};
                    if (result.clean && archive) archive->Close(); // 原生全清退后才归还写租约，保留回执。
                    Publish(result, true, archive ? &archive->View() : nullptr);
                    if (result.clean) group.reset();
                    std::lock_guard lock(mutex);
                    released = result.clean;
                    status.closedClean = result.clean;
                    status.canStart = result.clean;
                    status.closing = !result.clean;
                } else if (request) {
                    switch (request->command) {
                    case LightExecutionGroupCommand::Start: {
                        // 只有显式清退确认后才能替换；部分Start失败不会重建成功owner。
                        if (!group) {
                            group = std::make_unique<execution_native::OwnedExecutionGroup>();
                            archive = std::make_unique<Ksword::ActionAnalyze::ExecutionGroupArchive>();
                            if (archive->Prepare(request->projectDirectory, request->openExistingProject) && archive->ResolveSites(request->sites))
                            {
                                // 真实sample在附加前创建，全部成员共享身份而不共享调试owner。
                                Publish(group->Start(std::move(request->sites), request->authorized,
                                    execution_native::NativeTargetDisposition::ResumeAndDetach, archive->View().sampleId),
                                    true, &archive->View());
                            }
                            else
                            {
                                Publish(group->QueryWithoutCondition(), true, &archive->View());
                            }
                        }
                        break;
                    }
                    case LightExecutionGroupCommand::Query:
                        if (group) Publish(group->Query());
                        break;
                    case LightExecutionGroupCommand::Continue:
                        // 保留Held与已运行成员的原owner/control，原group整批核对后决定实际释放。
                        if (group) Publish(group->Continue(request->sessions, request->all), true);
                        break;
                    case LightExecutionGroupCommand::Pause:
                        // 原group核对整批owner/PIDcreation，已Held成员原样进入already-held回执。
                        if (group) Publish(group->Pause(request->sessions, request->all), true);
                        break;
                    case LightExecutionGroupCommand::Step:
                        if (group && request->stops.size() == 1)
                            Publish(group->Step(request->stops.front(), request->stepMode), true);
                        break;
                    case LightExecutionGroupCommand::CancelStep:
                        if (group && request->stops.size() == 1)
                            Publish(group->CancelStep(request->stops.front()), true);
                        break;
                    case LightExecutionGroupCommand::AddRange:
                        // 只调用原集合、原成员；追加不Continue，也不创建新的调试owner。
                        if (group && request->stops.size() == 1)
                            Publish(group->AddRange(request->stops.front(), request->address, request->bytes), true);
                        break;
                    case LightExecutionGroupCommand::SaveExecution:
                        if (group && archive && request->sessions.size() == 1)
                        {
                            archive->Save(*group, request->sessions.front()); // 不解析PID草稿，不求条件或释放同伴。
                            Publish(group->QueryWithoutCondition(), true, &archive->View());
                        }
                        break;
                    case LightExecutionGroupCommand::Identify: {
                        FILETIME created{}, exited{}, kernel{}, user{};
                        std::uint64_t creation = 0;
                        DWORD error = ERROR_SUCCESS;
                        const HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, request->identityPid);
                        if (!process) error = ::GetLastError();
                        else {
                            if (::GetProcessTimes(process, &created, &exited, &kernel, &user))
                                creation = (std::uint64_t{created.dwHighDateTime} << 32) | created.dwLowDateTime;
                            else error = ::GetLastError();
                            ::CloseHandle(process);
                        }
                        std::lock_guard lock(mutex);
                        status.identityPid = request->identityPid;
                        status.identityCreation = creation;
                        status.identityError = error;
                        ++status.identityRevision;
                        ++status.revision;
                        break;
                    }
                    }
                } else if (group) {
                    // 事件推进复用同一worker，不新增定时查询任务或目标所有者。
                    Publish(group->Query());
                }
            } catch (...) {
                std::lock_guard lock(mutex);
                if (archive) status.archive = archive->View(); // 写入异常保留中断段及阻止追加状态，旧成功不覆盖。
                status.diagnostic = L"后台操作异常；原集合及未决清退责任仍保留，请刷新或再次清退。";
                ++status.revision;
            }
            {
                std::lock_guard lock(mutex);
                if (close) ++closeConclusions;
                status.busy = false;
            }
            changed.notify_all();
        }
    }
};

LightExecutionGroupSession::~LightExecutionGroupSession()
{
    BeginRetirement();
    if (shared_) {
        std::lock_guard lock(shared_->mutex);
        shared_->stopping = true;
        shared_->changed.notify_all();
    }
}

DWORD LightExecutionGroupSession::StartWorker()
{
    if (shared_ || retiring_) return ERROR_BUSY;
    try {
        auto lease = Ui::TryAcceptBackgroundWork();
        if (!lease) return ERROR_OPERATION_ABORTED;
        auto state = std::make_shared<Shared>();
        state->status.active = true;
        std::thread([state, lease = std::move(lease)] { state->Run(); }).detach();
        shared_ = std::move(state);
        return ERROR_SUCCESS;
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

bool LightExecutionGroupSession::Submit(LightExecutionGroupRequest request)
{
    if (!shared_ || retiring_) return false;
    std::lock_guard lock(shared_->mutex);
    if (!shared_->status.active || shared_->status.busy || shared_->pending ||
        (shared_->status.closing && request.command != LightExecutionGroupCommand::Query)) return false;
    if (request.command == LightExecutionGroupCommand::Start) {
        if (!shared_->status.canStart) return false;
        if (const auto cleanup = shared_->retirement.lock(); cleanup && !cleanup->complete()) return false;
        shared_->released = false;
        shared_->status.closedClean = false;
        shared_->status.canStart = false;
    }
    shared_->pending = std::move(request);
    shared_->status.busy = true;
    shared_->changed.notify_all();
    return true;
}

void LightExecutionGroupSession::Close()
{
    if (!shared_) return;
    const auto state = shared_;
    {
        std::lock_guard lock(state->mutex);
        if (state->released) return;
        state->status.closing = true;
    }
    // 失败登记保留原state；再次清退重试同一登记，不转移或丢弃owner。
    const auto previous = state->retirement.lock();
    if (!previous || previous->complete())
        state->retirement = Ui::RunBackgroundRetirement([state] { return state->Retire(); });
    else Ui::BackgroundWorkRegistry::global().retry(true);
}

void LightExecutionGroupSession::BeginRetirement()
{
    retiring_ = true;
    Close();
    if (shared_) {
        std::lock_guard lock(shared_->mutex);
        // shell先等后台登记归零再销毁页面；结清后让唯一worker归还登记。
        shared_->stopping = true;
        shared_->changed.notify_all();
    }
}

void LightExecutionGroupSession::CancelRetirement()
{
    retiring_ = false;
    if (!shared_) return;
    bool restart = false;
    {
        std::lock_guard lock(shared_->mutex);
        shared_->stopping = false;
        restart = !shared_->status.active;
    }
    if (restart) {
        // 只有旧worker已clean退出才允许新worker；保留原结果用于查看。
        const auto previous = ReadStatus();
        shared_.reset();
        if (StartWorker() == ERROR_SUCCESS) {
            std::lock_guard lock(shared_->mutex);
            shared_->status.result = previous.result;
            shared_->status.archive = previous.archive; // 重建已clean的展示worker也保留历史保存坐标。
            shared_->status.observedFileTime = previous.observedFileTime;
            shared_->status.operationFileTime = previous.operationFileTime;
            shared_->status.revision = previous.revision + 1;
        }
    }
}

bool LightExecutionGroupSession::Ready() const
{
    if (!shared_) return true;
    std::lock_guard lock(shared_->mutex);
    return shared_->released;
}

LightExecutionGroupSnapshot LightExecutionGroupSession::ReadStatus() const
{
    if (!shared_) return {};
    if (const auto cleanup = shared_->retirement.lock(); cleanup &&
        cleanup->failure() == Ui::BackgroundWorkRegistry::Failure::ThreadCreation)
        Ui::BackgroundWorkRegistry::global().retry();
    std::lock_guard lock(shared_->mutex);
    auto snapshot = shared_->status;
    if (const auto cleanup = shared_->retirement.lock(); cleanup && !cleanup->complete()) snapshot.canStart = false;
    return snapshot;
}
}
