#include "LightProcessGroupSession.h"

#include "../../Ui/BackgroundWork.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>

namespace Ksword::Features::ActionAnalyze {
namespace {

namespace storage = Ksword::ActionAnalyze::ProjectStorage;

// 原生账本与界面历史都保留最近 128 项票据。
constexpr std::size_t kHistoryLimit = 128;

// 空闲时的只读回读间隔。回读只问原所有者，不产生新的原生副作用。
constexpr int kIdleQueryMs = 250;

// 真实的 UTC FILETIME，用于回执来源时间显示；不使用界面刷新时间冒充采样。
std::uint64_t NowFileTime() {
    FILETIME now{};
    ::GetSystemTimeAsFileTime(&now);
    return (static_cast<std::uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
}

// 读取一个进程实例的身份。创建时间与映像路径来自同一个句柄，失败保留真实 Win32 错误。
// 用户填写的创建时间只作为核对基准；不一致时仍回报真实创建时间，便于修正草稿。
LightProcessGroupIdentity ReadIdentity(const LightProcessGroupRequest& request) {
    LightProcessGroupIdentity identity; // 本次读取的真实结果。
    identity.target.pid = request.identityPid;
    identity.expectedCreation = request.identityCreation;
    identity.observedFileTime = NowFileTime();
    const std::unique_ptr<void, decltype(&::CloseHandle)> process(
        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, request.identityPid), &::CloseHandle); // 异常路径也释放身份句柄。
    if (!process) {
        identity.error = ::GetLastError();
        return identity;
    }
    FILETIME creation{}, exited{}, kernel{}, user{}; // 同一进程对象的创建与累计时间。
    if (!::GetProcessTimes(process.get(), &creation, &exited, &kernel, &user)) {
        identity.error = ::GetLastError();
    } else {
        identity.target.creationFileTime =
            (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
        identity.creationMatched = !request.identityCreation ||
            *request.identityCreation == identity.target.creationFileTime;
        if (!identity.creationMatched) identity.error = ERROR_INVALID_PARAMETER;
        std::wstring path(32768, L'\0'); // 系统允许的长路径缓冲。
        DWORD length = static_cast<DWORD>(path.size());
        if (::QueryFullProcessImageNameW(process.get(), 0, path.data(), &length)) {
            path.resize(length);
            identity.imagePath = std::move(path);
        } else if (!identity.error) {
            identity.error = ::GetLastError();
        }
    }
    return identity;
}

// 成员回执里界面真正展示的字段。用于判断一次回读是否带来可观察的变化。
struct MemberSignature {
    std::uint32_t pid = 0;
    std::uint64_t creation = 0;
    int status = 0;
    std::uint32_t win32Error = 0;
    std::string stage;
    bool attached = false;
    bool clean = true;
    bool hasStop = false;
    std::string stopId;
    std::string groupId;
    std::uint64_t eventSerial = 0; // 新停点不能仅凭stopId比较，必须覆盖真实事件与修订。
    std::uint64_t stateRevision = 0;
    std::string backendInstanceId;
    bool operator==(const MemberSignature&) const = default;
};

// 一次回读的界面可见签名。相同签名不推进发布代次，界面不会无变化重绘。
struct ResultSignature {
    int state = 0;
    bool clean = true;
    std::uint32_t win32Error = 0;
    std::string stage;
    int ledger = 0;
    std::vector<MemberSignature> members;
    bool operator==(const ResultSignature&) const = default;
};

ResultSignature SignatureOf(const group_native::ProcessGroupResult& result) {
    ResultSignature signature; // 界面可见字段的摘要。
    signature.state = static_cast<int>(result.state);
    signature.clean = result.clean;
    signature.win32Error = result.win32Error;
    signature.stage = result.stage ? result.stage : "";
    signature.ledger = static_cast<int>(result.ledgerResult);
    for (const auto& member : result.members) {
        MemberSignature entry; // 单个成员的真实回执摘要。
        entry.pid = member.target.pid;
        entry.creation = member.target.creationFileTime;
        entry.clean = member.clean;
        entry.hasStop = member.stop.has_value();
        if (member.stop) {
            entry.stopId = member.stop->stopId;
            entry.groupId = member.stop->groupId;
            entry.eventSerial = member.stop->event.serial;
            entry.stateRevision = member.stop->stateRevision;
            entry.backendInstanceId = member.stop->event.backendInstanceId;
        }
        if (member.control) {
            entry.status = static_cast<int>(member.control->status);
            entry.win32Error = member.control->win32Error;
            entry.stage = member.control->stage ? member.control->stage : "";
            entry.attached = member.control->attached;
        }
        signature.members.push_back(std::move(entry));
    }
    return signature;
}

} // namespace

struct LightProcessGroupSession::Shared {
    // 一次排队动作。界面动作在点击时按值冻结，工作线程不借用任何控件。
    struct Command {
        LightProcessGroupRequest request;
    };

    mutable std::mutex mutex;
    std::condition_variable changed;
    LightProcessGroupSnapshot status;
    std::optional<Command> pending;   // 单在途：同一时刻只有一个界面动作在队列里。
    std::uint64_t nextRequest = 0;     // 严格递增的 group/N 序号。
    std::uint64_t closeRequested = 0; // 已请求的清退尝试号。
    std::uint64_t closeTaken = 0;      // 已被工作线程取走的清退尝试号。
    std::uint64_t closeConclusions = 0;// 已有结论的清退次数，用于等待一次新结论。
    bool stopping = false;             // 页面正在退役，责任结清后工作线程才退出。
    bool released = false;             // 当前原生集合已确认清退并释放。
    ResultSignature lastSignature;
    std::optional<LightProcessGroupMemoryState> memory{std::in_place}; // 原group同线程独占；显式新集合重置归档身份。
    std::weak_ptr<Ui::BackgroundCleanup> retirement;

    // 由Start的唯一后台线程调用；输入为冻结队列，输出为锁内值快照，clean前不释放owner。
    void Run();

    // 发布一次完整回读。签名未变时不推进代次，界面不会无变化重绘。
    void Publish(const group_native::ProcessGroupResult& result,
        std::optional<LightProcessGroupCommand> completed = {}) {
        const auto signature = SignatureOf(result);
        std::lock_guard lock(mutex);
        const bool changedState = !(signature == lastSignature);
        lastSignature = signature;
        status.result = result;
        status.memoryProject = memory->ProjectView(); // 项目及capture与该控制回合同时发布。
        status.memory = memory->LatestRead();
        if (completed) {
            status.completedCommand = completed;
            if (*completed == LightProcessGroupCommand::Configure) {
                status.history.clear(); // 新集合发布时不把旧集合票据当作本轮恢复入口。
            }
            if (*completed != LightProcessGroupCommand::Query) {
                status.lastCommandResult = result; // 原operation三字段不被后续只读查询抹除。
                status.failed = false;
                status.diagnostic.clear(); // 只读Query不抹去先前后台异常。
            }
            ++status.revision;
        }
        if (changedState) {
            status.observedFileTime = NowFileTime();
            ++status.revision;
        }
        if (status.result.operation) {
            const auto& operation = *status.result.operation;
            const auto known = std::any_of(status.history.begin(), status.history.end(),
                [&](const group_native::ProcessGroupOperation& item) {
                    return item.requestId == operation.requestId && item.action == operation.action;
                });
            if (!known) {
                status.history.push_back(operation);
                if (status.history.size() > kHistoryLimit) status.history.erase(status.history.begin());
            }
        }
    }

    void PublishIdentity(const LightProcessGroupIdentity& identity) {
        std::lock_guard lock(mutex);
        status.identity = identity;
        status.completedCommand = LightProcessGroupCommand::Identify;
        status.failed = false; // 新显式身份查询完成后解除上一笔后台异常，真实系统错误仍在identity内。
        status.diagnostic.clear();
        status.observedFileTime = identity.observedFileTime;
        ++status.revision;
    }

    // 清退登记驱动的清退：请求一次新的尝试并等待这一次的结论。
    // 已确认清退时直接返回成功；未结清时返回失败，由登记处重试。
    // 同一 owner 在等待期间保持存活，不会被析构。
    bool Retire() {
        std::unique_lock lock(mutex);
        if (released) return true;
        const auto baseline = closeConclusions;
        ++closeRequested;             // 请求一次新的清退尝试。
        status.closing = true;
        changed.notify_all();
        changed.wait(lock, [this, baseline] {
            return released || closeConclusions > baseline || !status.active;
        });
        return released;
    }
};

// 本端唯一的工作线程：原生集合与调试所有者都只在这里创建、驱动和释放。
void LightProcessGroupSession::Shared::Run() {
    // 原生集合只存在于本线程。界面永远拿不到它，也不会在未决清退时把它析构。
    // 原生集合不可移动，用独占指针表达本线程独占的所有权。
    std::unique_ptr<group_native::OwnedProcessGroup> group;
    for (;;) {
        std::optional<LightProcessGroupRequest> request;
        bool close = false;
        {
            std::unique_lock lock(mutex);
            changed.wait_for(lock, std::chrono::milliseconds(kIdleQueryMs), [this] {
                return pending.has_value() || closeRequested > closeTaken;
            });
            if (pending) {
                // 已接纳的界面动作优先；清退不会覆盖它。
                request = std::move(pending->request);
                pending.reset();
                status.busy = true;
            } else if (closeRequested > closeTaken) {
                close = true;
                closeTaken = closeRequested;
                status.busy = true;
            } else if (group) {
                status.busy = true; // 自动Query也占用同一在途槽，不能让界面排入第二笔查询。
            }
        }
        try {
            if (!request && !close) {
                // 没有用户动作时只做一次只读回读，让界面看到成员的真实状态变化。
                if (group) Publish(group->Query());
                bool stop = false; // 无group或已经clean时才允许退役结束本线程。
                {
                    std::lock_guard lock(mutex);
                    stop = stopping && (!group || released);
                    status.busy = false;
                }
                if (stop) {
                    memory->CloseProject(); // 无group的初始化/半创建路径也先归还writer。
                    {
                        std::lock_guard lock(mutex);
                        status.active = false;
                        released = true;
                        status.closedClean = true;
                        status.memoryProject = memory->ProjectView();
                    }
                    changed.notify_all();
                    return;
                }
                continue;
            }

            if (close) {
                if (!group) {
                    memory->CloseProject(); // 半创建失败或从未配置时也归还原项目租约。
                    // 没有集合可清退：直接确认为已释放。
                    std::lock_guard lock(mutex);
                    released = true;
                    status.closedClean = true;
                    status.closing = false;
                    status.busy = false;
                    status.memoryProject = memory->ProjectView();
                    ++status.revision;
                } else {
                    const auto result = group->Close();
                    Publish(result);
                    if (result.clean) {
                        // 只有确认没有未决责任时才释放原生集合和调试所有者。
                        group.reset();
                        memory->CloseProject(); // 发布closedClean前释放writer，不与下一集合争用。
                        std::lock_guard lock(mutex);
                        released = true;
                        status.closedClean = true;
                        status.closing = false;
                        status.busy = false;
                        status.memoryProject = memory->ProjectView();
                        ++status.revision;
                    } else {
                        // 未结清：保留同一所有者，原会话仍可查询、按原票据恢复或再次清退。
                        std::lock_guard lock(mutex);
                        status.closing = true;
                        status.busy = false;
                        ++status.revision;
                    }
                }
                {
                    std::lock_guard lock(mutex);
                    ++closeConclusions; // 本次清退已有结论，唤醒等待中的登记。
                }
                changed.notify_all();
                continue;
            }

            switch (request->command) {
            case LightProcessGroupCommand::Identify: {
                PublishIdentity(ReadIdentity(*request));
                break;
            }
            case LightProcessGroupCommand::Configure: {
                if (!group) {
                    {
                        std::lock_guard lock(mutex);
                        released = false; // 接纳新集合后，旧clean标志不授予新的清退资格。
                        status.closedClean = false;
                        status.result = {}; // 显式开始下一配置后，旧集合令牌不再作为本轮成员投影。
                        status.result.stage = "light-process-group-configuring";
                        status.lastCommandResult.reset();
                        status.completedCommand.reset();
                        status.history.clear(); // 即使新配置异常，也不能恢复旧集合的Continue票据。
                        ++status.revision;
                    }
                    memory.emplace(); // 原group已clean释放；显式新配置才清空旧归档投影与段号。
                    // 每次新配置使用新的所有者身份；已冻结的集合不会被替换。
                    group_native::OwnerIdentity identity;
                    if (!storage::NewId(identity.sampleId) || !storage::NewId(identity.sessionId) ||
                        !storage::NewId(identity.epoch) || !storage::NewId(identity.backendInstanceId)) {
                        throw std::runtime_error("lightProcessGroupIdentity"); // UUID生成失败不能伪装配置成功。
                    }
                    if (!request->newProjectDirectory.empty()) {
                        const auto prepared = memory->CreateNewProject(request->newProjectDirectory, identity);
                        if (!prepared) {
                            group_native::ProcessGroupResult rejected; // 未建立group也保留真实项目错误与路径。
                            rejected.stage = "light-process-group-project-failed";
                            rejected.win32Error = prepared.nativeError;
                            Publish(rejected, request->command);
                            break;
                        }
                    }
                    group = std::make_unique<group_native::OwnedProcessGroup>(std::move(identity));
                    std::lock_guard lock(mutex);
                    released = false;             // 新集合尚未结清任何原生责任。
                    status.closedClean = false;
                }
                Publish(group->Configure(request->targets, request->authorized,
                    group_native::NativeTargetDisposition::ResumeAndDetach), request->command);
                break;
            }
            case LightProcessGroupCommand::Pause: {
                if (!group) break;
                Publish(group->Pause(request->requestId, request->targets), request->command);
                break;
            }
            case LightProcessGroupCommand::Continue: {
                if (!group) break;
                Publish(group->Continue(request->requestId, request->stops), request->command);
                break;
            }
            case LightProcessGroupCommand::Recover: {
                if (!group) break;
                Publish(group->Recover(request->requestId), request->command);
                break;
            }
            case LightProcessGroupCommand::Query: {
                if (!group) break;
                Publish(group->Query(), request->command);
                break;
            }
            case LightProcessGroupCommand::ReadMemory: {
                if (!group || !request->memory) break;
                memory->Read(*group, *request->memory); // 内部只做Held前后Query，不触发条件或Continue。
                Publish(group->Query(), request->command);
                break;
            }
            case LightProcessGroupCommand::SaveMemory: {
                if (!group) break;
                memory->Save(request->memoryToSave); // 独立raw-memory lane保留完整readContext。
                Publish(group->Query(), request->command);
                break;
            }
            }
        } catch (...) {
            const auto failure = std::current_exception(); // 自动Query异常也保留同group，不逃出线程析构owner。
            std::lock_guard lock(mutex);
            status.busy = false;
            status.failed = true;
            status.diagnostic = L"后台操作失败；原生未决状态与最后回执仍保留。";
            try {
                std::rethrow_exception(failure);
            } catch (const std::exception& error) {
                const std::string_view detail(error.what()); // 有界摘要不冒充Win32原生错误。
                status.diagnostic += L" / " + std::wstring(detail.begin(), detail.begin() +
                    (std::min)(detail.size(), std::size_t{512}));
            } catch (...) {
                // 非标准异常保留稳定说明，不编造具体原因。
            }
            status.memoryProject = memory->ProjectView();
            status.memory = memory->LatestRead();
            if (request) status.completedCommand = request->command;
            if (close) ++closeConclusions; // 失败也要唤醒原清退登记，保留owner等待重试。
            ++status.revision;
            changed.notify_all();
        }
        {
            std::lock_guard lock(mutex);
            status.busy = false;
        }
        changed.notify_all(); // 本回合结束后唤醒原等待者，不另派控制线程。
    }
}

LightProcessGroupSession::~LightProcessGroupSession() {
    BeginRetirement();
    if (session_) {
        std::lock_guard lock(session_->mutex); // 页面真正销毁后才结束clean worker，退出取消可以继续使用同一会话。
        session_->stopping = true;
        session_->changed.notify_all();
    }
}

DWORD LightProcessGroupSession::Start() {
    if (retiring_ || session_) return ERROR_BUSY; // 同页面只启动一个串行worker，新集合沿原worker显式配置。
    try {
        auto lease = Ui::TryAcceptBackgroundWork();
        if (!lease) return ERROR_OPERATION_ABORTED;
        auto next = std::make_shared<Shared>();
        next->status.active = true;
        std::thread([next, lease = std::move(lease)]() mutable {
            next->Run();
        }).detach();
        session_ = std::move(next);
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return ERROR_SUCCESS;
}

bool LightProcessGroupSession::Submit(LightProcessGroupRequest request) {
    if (!session_ || retiring_) return false;
    {
        std::lock_guard lock(session_->mutex);
        // 单在途：已有动作排队或执行时拒绝新动作，调用方保留自己的输入草稿。
        const bool recovering = request.command == LightProcessGroupCommand::Recover ||
            request.command == LightProcessGroupCommand::Query; // 清退中只接原票据恢复与只读回查。
        if (!session_->status.active || session_->status.busy || session_->pending ||
            (session_->status.closing && !recovering)) return false;
        session_->pending = Shared::Command{std::move(request)};
        if (session_->pending->request.command == LightProcessGroupCommand::Configure) {
            session_->released = false; // 排队配置已有新责任，旧clean不能让同时到来的Retire提前返回。
            session_->status.closedClean = false;
            session_->status.completedCommand.reset(); // 不把上一轮Configure结论误认为本次已经完成。
        }
        session_->status.busy = true; // 入队即发布忙态，防止UI在worker取走前重复点击。
    }
    session_->changed.notify_all();
    return true;
}

std::string LightProcessGroupSession::NextRequestId() {
    if (!session_) return {};
    std::lock_guard lock(session_->mutex);
    // 组层票据共用一个严格递增的命名空间；恢复动作复用原继续票据，不占用新号。
    return "group/" + std::to_string(++session_->nextRequest);
}

void LightProcessGroupSession::Close() {
    const auto owner = session_;
    if (!owner) return;
    {
        std::lock_guard lock(owner->mutex);
        if (!owner->status.active) return;
        owner->status.closing = true;
    }
    owner->changed.notify_all();
    // 清退登记保证页面关闭后同一 owner 继续存活；未结清时由登记处重试。
    if (!owner->retirement.expired()) {
        Ui::BackgroundWorkRegistry::global().retry(true);
    } else {
        owner->retirement = Ui::RunBackgroundRetirement([owner] { return owner->Retire(); });
    }
}

void LightProcessGroupSession::BeginRetirement() {
    retiring_ = true;
    if (!session_) return;
    // 退出准入只请求原owner清退，页面尚存时保留空闲worker，允许用户取消程序退出。
    // 真正销毁由析构设置stopping；未clean仍由相同登记与worker继续负责。
    Close();
}

bool LightProcessGroupSession::Ready() const {
    if (!session_) return true;
    std::lock_guard lock(session_->mutex);
    // 原生责任结清之前不允许页面消失；未结清时同一 owner 继续存活。
    return session_->released || !session_->status.active;
}

void LightProcessGroupSession::CancelRetirement() {
    retiring_ = false;
    if (!session_) return;
    std::lock_guard lock(session_->mutex);
    // 退出被取消：工作线程继续服务本会话，责任未结清时仍保留同一 owner。
    session_->stopping = false;
}

LightProcessGroupSnapshot LightProcessGroupSession::ReadStatus() const {
    if (!session_) return {};
    if (const auto cleanup = session_->retirement.lock(); cleanup &&
        cleanup->failure() == Ui::BackgroundWorkRegistry::Failure::ThreadCreation) {
        Ui::BackgroundWorkRegistry::global().retry();
    }
    std::lock_guard lock(session_->mutex);
    return session_->status;
}

} // namespace Ksword::Features::ActionAnalyze
