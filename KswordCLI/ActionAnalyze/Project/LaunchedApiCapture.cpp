#include "LaunchedApiCapture.h"
#include "../Control/OwnedDataWatchSession.h"
#include "ProjectStorage.h"

#include <algorithm>
#include <stdexcept>

namespace Ksword::ActionAnalyze {
namespace {
namespace Native = ks::cli::action_analyze::control;
using Json = Evidence::JsonValue;

// 将Windows时间转换为原生身份使用的无符号100ns时间，不接受日期文本。
std::uint64_t FileTimeValue(const FILETIME& value)
{
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

// 仅将已冻结的本地路径投影成UTF-8；不解析命令行或重新查询目标文件。
std::string ExecutableText(std::wstring_view value)
{
    const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr); // 原路径的UTF-8字节数。
    if (count <= 0)
    {
        return {};
    }
    std::string text(static_cast<std::size_t>(count), '\0'); // 单一JSON文档持有路径副本。
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        text.data(), count, nullptr, nullptr))
    {
        return {};
    }
    return text;
}

// 同一worker持有原debug会话、精确创建对象和独立主线程挂起；失败清退完成前不交还调用方。
class EntryBootstrap final {
public:
    // 回执和回调均由CaptureLaunchedApi栈持有，整个交接在调用端原worker同步执行。
    EntryBootstrap(LaunchedApiReceipt& receipt, const LaunchedApiLaunchProgress& progress)
        : out_(receipt), progress_(progress)
    {
    }

    // 异常退出仍必须终止本次自有对象并排空owner；不能把未clean局部对象交给析构等待。
    ~EntryBootstrap()
    {
        if (started_ && !finished_)
        {
            Cleanup(true);
        }
    }

    // 发布已完成事实；显示回调失败不能打断恢复账。回调不访问项目写者。
    void Publish(const char* stage) noexcept
    {
        out_.stage = stage;
        try
        {
            if (progress_)
            {
                progress_(out_);
            }
        }
        catch (...)
        {
            // GUI值回投异常不转移进程、线程及owner责任。
        }
    }

    // 保留首个实际故障，后续清退事实独立报告，不用成功脱离覆盖启动失败原因。
    void Fail(const char* stage, DWORD error) noexcept
    {
        if (!out_.error)
        {
            out_.error = error ? error : ERROR_GEN_FAILURE;
            Publish(stage);
        }
    }

    // 原会话创建并武装入口；等待确切主线程命中后，在OS debug事件仍被持有时额外挂起一次。
    bool Start(const LaunchedApiRequest& request, const std::atomic_bool& cancel)
    {
        started_ = true;
        Publish("launched-api-creating-suspended-image");
        state_ = session_.StartSuspendedImage(request.exe, request.optionalRva);
        out_.launch = session_.LaunchReceipt();
        process_ = session_.LaunchedProcessHandle(); // 原始CreateProcess对象，不按PID再次打开。
        Publish("launched-api-wait-entry");
        if (!out_.launch || !out_.launch->initialSuspendReleased || !process_)
        {
            Fail("launched-api-create-or-arm", state_.win32Error ? state_.win32Error : ERROR_INVALID_STATE);
            return false;
        }
        FILETIME creation{}, exited{}, kernel{}, user{}; // 从仍保留的创建对象读取实例身份。
        if (!GetProcessTimes(process_, &creation, &exited, &kernel, &user))
        {
            Fail("launched-api-query-process-identity", GetLastError());
            return false;
        }
        if (GetProcessId(process_) != out_.launch->pid || FileTimeValue(creation) != out_.launch->creationFileTime)
        {
            Fail("launched-api-process-identity", ERROR_INVALID_DATA);
            return false;
        }
        const auto deadline = GetTickCount64() + 30000; // TLS/loader可能耗时，超时只终止本次自有启动。
        while (!cancel.load())
        {
            state_ = session_.QueryWithoutCondition();
            if (ExactEntry())
            {
                out_.entryHeld = true; // 入口命中是独立事实，不等到后续Suspend成功才报告。
                Publish("launched-api-entry-held");
                break;
            }
            const auto processWait = WaitForSingleObject(process_, 0); // 退出、等待失败与启动超时分别保留原生原因。
            const auto waitError = processWait == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
            if (state_.status == Native::NativeControlStatus::Rejected ||
                state_.status == Native::NativeControlStatus::RecoveryRequired ||
                processWait != WAIT_TIMEOUT || GetTickCount64() >= deadline)
            {
                Fail("launched-api-entry-not-held", state_.win32Error ? state_.win32Error : waitError ? waitError :
                    processWait == WAIT_OBJECT_0 ? ERROR_PROCESS_ABORTED : ERROR_TIMEOUT);
                return false;
            }
            Sleep(10); // 原worker限速回读，不在GUI线程枚举或等待。
        }
        if (cancel.load())
        {
            Fail("launched-api-cancelled", ERROR_CANCELLED);
            return false;
        }
        const auto tid = out_.launch->initialThreadId; // 只接受CREATE_PROCESS核验过的原始主线程。
        const auto frozen = std::find_if(state_.frozenThreads.begin(), state_.frozenThreads.end(), [&](const auto& item) {
            return item.tid == tid && item.identity == state_.responsibility->actualEventThread;
        });
        const auto openedThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            FALSE, tid); // OpenThread失败返回null，不能当作存储层的有效句柄。
        if (!openedThread)
        {
            Fail("launched-api-open-main-thread", GetLastError());
            return false;
        }
        thread_ = ProjectStorage::Handle(openedThread);
        if (!GetThreadTimes(thread_.get(), &creation, &exited, &kernel, &user))
        {
            Fail("launched-api-query-main-thread-identity", GetLastError());
            return false;
        }
        if (frozen == state_.frozenThreads.end() || !frozen->creationTime ||
            GetProcessIdOfThread(thread_.get()) != out_.launch->pid ||
            FileTimeValue(creation) != frozen->creationTime || WaitForSingleObject(thread_.get(), 0) != WAIT_TIMEOUT)
        {
            Fail("launched-api-main-thread-identity", ERROR_INVALID_DATA);
            return false;
        }
        const auto previous = SuspendThread(thread_.get()); // OS事件不计入显式挂起计数，预期原值0。
        mainHold_ = previous != static_cast<DWORD>(-1); // 即使原计数冲突，本次取得的责任也不能丢失。
        if (!mainHold_ || previous != 0)
        {
            Fail("launched-api-main-suspend-conflict", mainHold_ ? ERROR_INVALID_STATE : GetLastError());
            return false;
        }
        Publish("launched-api-entry-held-main-suspended");
        state_ = session_.Close(); // 原owner先恢复DR0及账本，再脱离；主线程仍持独立一次挂起。
        while (!state_.clean || state_.attached)
        {
            if (cancel.load() || state_.status == Native::NativeControlStatus::RecoveryRequired || GetTickCount64() >= deadline)
            {
                Fail("launched-api-bootstrap-detach", state_.win32Error ? state_.win32Error :
                    cancel.load() ? ERROR_CANCELLED : ERROR_TIMEOUT);
                return false;
            }
            Sleep(10);
            state_ = session_.QueryWithoutCondition();
        }
        out_.bootstrapClean = true;
        Publish("launched-api-bootstrap-clean-main-suspended");
        return true;
    }

    // 只有原控制器已核验的Ready、会话和有效覆盖全部成立，才归还交接所持的一次主线程挂起。
    bool ResumeMain(std::uint64_t session, std::uint64_t revision,
        const std::optional<ks::winapi_monitor::CaptureStartupProgress>& startup, const std::atomic_bool& cancel)
    {
        if (cancel.load() || !mainHold_ || !out_.bootstrapClean || !session || !revision || !startup ||
            startup->stage != ks::winapi_monitor::CaptureStartupStage::Ready || startup->session != session ||
            startup->coverageRevision != revision || startup->pid != out_.launch->pid ||
            startup->creationFileTime != out_.launch->creationFileTime)
        {
            Fail("launched-api-ready-handoff-rejected", cancel.load() ? ERROR_CANCELLED : ERROR_INVALID_STATE);
            return false;
        }
        out_.agentReadyBeforeMainResume = true;
        out_.launch->apiAgentReady = true; // 仅此真实Ready回调改变API字段，TLS覆盖始终为false。
        Publish("launched-api-agent-ready-main-suspended");
        if (cancel.load())
        {
            Fail("launched-api-cancelled-before-main-resume", ERROR_CANCELLED);
            return false;
        }
        const auto previous = ResumeThread(thread_.get()); // 不Resume到零，只归还自己取得的一次。
        if (previous != static_cast<DWORD>(-1) && previous > 0)
        {
            mainHold_ = false;
            out_.initialMainSuspendReleased = true;
        }
        if (previous != 1)
        {
            Fail("launched-api-main-resume-conflict", previous == static_cast<DWORD>(-1) ? GetLastError() : ERROR_INVALID_STATE);
            return false;
        }
        Publish("launched-api-main-resumed");
        return true;
    }

    // 非Ready、取消或启动失败只终止创建对象。清退失败保留worker并重试，绝不局部析构遗留挂起。
    void Cleanup(bool terminate) noexcept
    {
        bool firstClose = true; // 首轮先请求原owner恢复，随后才终止精确自有对象。
        while (true)
        {
            try
            {
                process_ = session_.LaunchedProcessHandle();
                if (firstClose)
                {
                    state_ = session_.Close();
                    firstClose = false;
                }
                const bool exited = !process_ || WaitForSingleObject(process_, 0) == WAIT_OBJECT_0;
                if (terminate && !exited)
                {
                    if (!TerminateProcess(process_, ERROR_PROCESS_ABORTED))
                    {
                        Fail("launched-api-termination-pending", GetLastError());
                    }
                }
                if (state_.clean && !state_.attached && (!terminate || exited))
                {
                    mainHold_ = false; // 正常路径已Resume；异常路径以精确对象退出结清挂起责任。
                    out_.bootstrapClean = true;
                    finished_ = true;
                    if (!out_.error)
                    {
                        Publish("launched-api-bootstrap-complete"); // 只报告交接已结清，API成功仍看原完整回执。
                    }
                    else
                    {
                        Publish(out_.stage); // 终态重新发布clean事实，保留首错stage。
                    }
                    return;
                }
                state_ = session_.Close();
            }
            catch (...)
            {
                terminate = true; // 原owner仍在本对象中，异常只切换自有启动的撤销策略。
                Fail("launched-api-cleanup-pending", ERROR_GEN_FAILURE);
            }
            Sleep(100); // 没有恢复证据就保持原worker活着；循环重试不递归积累栈。
        }
    }

private:
    // 快照必须证明同一请求、精确地址、原主线程与完整OS停止；普通Pause或旧命中不能充当入口。
    bool ExactEntry() const
    {
        return state_.status == Native::NativeControlStatus::Held && state_.attached &&
            state_.pid == out_.launch->pid && state_.processCreationTime == out_.launch->creationFileTime &&
            state_.breakpoint && state_.breakpoint->state == Native::NativeBreakpointState::Held &&
            state_.breakpoint->rva == out_.launch->entryRva &&
            state_.breakpointHit && state_.breakpointHit->requestId == state_.breakpoint->requestId &&
            state_.breakpointHit->address == state_.breakpoint->address && state_.registers &&
            state_.registers->rip == state_.breakpoint->address && state_.pending && state_.pending->ledgerOwned &&
            state_.pending->pid == out_.launch->pid && state_.pending->tid == out_.launch->initialThreadId && state_.responsibility &&
            state_.responsibility->state == Native::EventState::Held &&
            state_.responsibility->event == state_.pending->event && state_.group &&
            !state_.group->historical && state_.group->state == Native::GroupState::HeldComplete &&
            state_.registers->thread == state_.responsibility->actualEventThread &&
            state_.stopReason == Native::NativeStopReason::Breakpoint;
    }

    LaunchedApiReceipt& out_; // 本次原worker的值回执。
    const LaunchedApiLaunchProgress& progress_; // 不持有UI或另一个项目写者。
    Native::OwnedDataWatchSession session_; // 复用原owner及其调试事件恢复账。
    Native::NativeControlResult state_; // 最近一次真实回读。
    HANDLE process_ = nullptr; // 借用session保留的CreateProcess原始句柄。
    ProjectStorage::Handle thread_; // 经冻结线程创建时间核验后的原始主线程对象。
    bool mainHold_ = false; // 独立于debug owner的一次Suspend责任。
    bool started_ = false; // 区分尚未创建与需要清退的启动。
    bool finished_ = false; // 确认owner清退且挂起责任已经结束。
};
} // namespace

// 所有启动事实由同一文档投影；uint64身份使用无损十进制字符串，不查询现场。
Evidence::JsonValue LaunchedApiProgressJson(const LaunchedApiProgress& progress)
{
    const auto* launch = progress.launch ? &*progress.launch : nullptr; // 失败在创建前时身份保持null。
    return Json::makeObject({
        {"pid", launch ? Json::makeUInt(launch->pid) : Json::makeNull()},
        {"executable", launch ? Json::makeString(ExecutableText(launch->executable)) : Json::makeNull()},
        {"creationFileTime", launch ? Json::makeString(std::to_string(launch->creationFileTime)) : Json::makeNull()},
        {"initialThreadId", launch ? Json::makeUInt(launch->initialThreadId) : Json::makeNull()},
        {"entryRva", launch ? Json::makeUInt(launch->entryRva) : Json::makeNull()},
        {"launchStage", launch ? Json::makeString(launch->stage) : Json::makeNull()},
        {"launchError", launch ? Json::makeUInt(launch->win32Error) : Json::makeNull()},
        {"createdSuspended", Json::makeBool(launch && launch->createdSuspended)},
        {"ownerAttachedBeforeResume", Json::makeBool(launch && launch->ownerAttachedBeforeResume)},
        {"breakpointArmedBeforeResume", Json::makeBool(launch && launch->breakpointArmedBeforeResume)},
        {"initialSuspendReleased", Json::makeBool(launch && launch->initialSuspendReleased)},
        {"earliestTlsCovered", Json::makeBool(false)},
        {"apiAgentReady", launch && launch->apiAgentReady ? Json::makeBool(*launch->apiAgentReady) : Json::makeNull()},
        {"entryHeld", Json::makeBool(progress.entryHeld)},
        {"agentReadyBeforeMainResume", Json::makeBool(progress.agentReadyBeforeMainResume)},
        {"initialMainSuspendReleased", Json::makeBool(progress.initialMainSuspendReleased)},
        {"bootstrapClean", Json::makeBool(progress.bootstrapClean)},
        {"stage", Json::makeString(progress.stage)},
        {"error", Json::makeUInt(progress.error)}
    });
}

// 在原writer线程串行推进入口debug交接和原API采集；全部回调保持现有签名及同步时序。
LaunchedApiReceipt CaptureLaunchedApi(ProjectDocument& document, const LaunchedApiRequest& request,
    const std::atomic_bool& cancel, const CooperativeApiReady& onReady, const CooperativeApiCommitted& onCommitted,
    const CooperativeApiTransferCommitted& onTransfers, const CooperativeApiStartup& onStartup,
    const LaunchedApiLaunchProgress& onLaunchProgress)
{
    LaunchedApiReceipt out; // 启动、管道和归档结果保持独立。
    EntryBootstrap bootstrap(out, onLaunchProgress); // 析构前必须实际结清入口恢复责任。
    try
    {
        if (!document.Info() || document.Info()->access != ProjectAccess::ReadWrite || request.title.empty() ||
            request.exe.empty() || (request.optionalRva && !*request.optionalRva) ||
            (!request.revisionId.empty() && document.Info()->revisionId != request.revisionId) ||
            (request.durationMs && (request.durationMs < 1000 || request.durationMs > 120000)))
        {
            bootstrap.Fail("launched-api-invalid-request", ERROR_INVALID_PARAMETER);
            out.api.sampleStatus = {ProjectError::InvalidArgument, out.error, out.stage};
            return out;
        }
        if (cancel.load() || !bootstrap.Start(request, cancel))
        {
            bootstrap.Fail("launched-api-cancelled", ERROR_CANCELLED);
            bootstrap.Cleanup(true);
            out.api.sampleStatus = {ProjectError::IoError, out.error, out.stage}; // API未启动，不能沿用默认成功状态。
            return out;
        }
        std::optional<ks::winapi_monitor::CaptureStartupProgress> startup; // 保存控制器实际Ready阶段用于交接核验。
        out.api = CaptureCooperativeApi(document,
            {out.launch->pid, out.launch->creationFileTime, request.durationMs, request.title, request.revisionId,
                request.captureAgentEtw, ApiCaptureMode::ExplicitAttachment, {}, request.autoTransfer, request.networkTraffic}, cancel,
            [&](std::uint64_t session, std::uint64_t revision) {
                if (!bootstrap.ResumeMain(session, revision, startup, cancel))
                {
                    bootstrap.Cleanup(true);
                    throw std::runtime_error("launched-api-ready-handoff"); // 原采集器捕获后沿既有管道清退。
                }
                if (onReady)
                {
                    onReady(session, revision);
                }
            }, onCommitted, onTransfers, [&](const ks::winapi_monitor::CaptureStartupProgress& progress) {
                startup = progress;
                if (onStartup)
                {
                    onStartup(progress);
                }
            });
        if (!out.initialMainSuspendReleased || !out.agentReadyBeforeMainResume || cancel.load())
        {
            bootstrap.Fail(cancel.load() ? "launched-api-cancelled" : "launched-api-agent-not-ready",
                cancel.load() ? ERROR_CANCELLED : ERROR_NOT_READY);
        }
        bootstrap.Cleanup(out.error != ERROR_SUCCESS);
    }
    catch (...)
    {
        bootstrap.Fail("launched-api-worker-exception", ERROR_GEN_FAILURE);
        bootstrap.Cleanup(true);
        if (out.api.sample.sampleId.empty())
        {
            out.api.sampleStatus = {ProjectError::IoError, out.error, out.stage};
        }
    }
    return out;
}

} // namespace Ksword::ActionAnalyze
