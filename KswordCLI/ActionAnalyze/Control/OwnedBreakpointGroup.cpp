#include "OwnedBreakpointGroup.h"

#include "../Project/ProjectStorage.h"
#include "../../../Ksword5.1/Ksword5.1/ksword/file/pe_analyzer.h"
#include "../../../shared/usermode/backend/Common.h"

#include <algorithm>
#include <limits>
#include <utility>
#include <vector>

namespace ks::cli::action_analyze::control {
namespace {

namespace storage = Ksword::ActionAnalyze::ProjectStorage;
using ks::r3::common::UniqueHandle;

constexpr DWORD kReadyTimeoutMs = 5000; // 两个主动就绪声明共用一个等待上限。

struct Failure {
    const char* stage = "idle"; // 失败发生的阶段；静态字面量便于直接投影给调用方。
    DWORD error = ERROR_SUCCESS; // 对应的系统错误。
    explicit operator bool() const noexcept { return error != ERROR_SUCCESS; }
};

// 在失败调用后立即读取系统错误，并与当前阶段一同返回。
Failure WinError(const char* stage) noexcept
{
    const auto code = GetLastError();
    return {stage, code ? code : ERROR_GEN_FAILURE};
}

// 验证普通 DOS 路径与 ASCII 导出名的形状，实际文件和映像在启动前另行核对。
bool ValidStart(std::wstring_view path, std::string_view name)
{
    return path.size() > 7 && path.size() < MAX_PATH &&
        ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' && path[2] == L'\\' && path.find_last_of(L'\\') > 2 && path.find(L'\0') == path.npos &&
        path.find_first_of(L"\"\r\n:/", 2) == path.npos &&
        CompareStringOrdinal(path.data() + path.size() - 4, 4, L".exe", 4, TRUE) == CSTR_EQUAL &&
        !name.empty() && name.size() <= 255 &&
        std::all_of(name.begin(), name.end(), [](char c) { return c >= 0x21 && c <= 0x7e; });
}

// 从现有进程对象核对架构，查询失败与仿真进程均不准入。
bool NativeAmd64(HANDLE process)
{
    USHORT machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native = IMAGE_FILE_MACHINE_UNKNOWN;
    return IsWow64Process2(process, &machine, &native) && machine == IMAGE_FILE_MACHINE_UNKNOWN &&
        native == IMAGE_FILE_MACHINE_AMD64;
}

struct Child {
    OwnerIdentity identity; // 共享会话身份，每个成员有不同的原生后端身份。
    NativeBreakpointRequest request; // 启动时锁定的执行导出和进程实例。
    UniqueHandle process; // 创建所得句柄；持有期间不会将 PID 认作另一实例。
    UniqueHandle ready; // 宿主等待的私有事件；子进程只继承置位权限。
    UniqueHandle gate; // 宿主持有唯一写端；关闭使尚未获准启动的目标收到 EOF。
    std::unique_ptr<NativeDebugOwner> owner; // 先于句柄销毁，避免本端销毁时抢跑取消。
    OwnedBreakpointGroupMember observed; // 最近一次实读状态。
};

struct LaunchAttributes {
    std::vector<std::uintptr_t> storage; // Windows 属性列表的对齐存储。
    LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr; // 只销毁已初始化的列表。
    ~LaunchAttributes()
    {
        if (list) DeleteProcThreadAttributeList(list);
    }

    // 分配用于精确继承清单的一项属性空间。
    bool Initialize()
    {
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        if (!bytes) return false;
        storage.resize((bytes + sizeof(std::uintptr_t) - 1) / sizeof(std::uintptr_t));
        const auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) return false;
        list = attributes;
        return true;
    }
};

// 启动已固定映像，只继承本成员的两个合作句柄；返回创建句柄核验阶段的错误。
Failure Launch(Child& child, const std::wstring& path)
{
    child.ready.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!child.ready.valid()) return WinError("create-cooperative-ready");
    HANDLE inheritedReady = nullptr; // 交给子进程的只写事件副本。
    const auto self = GetCurrentProcess();
    if (!DuplicateHandle(self, child.ready.get(), self, &inheritedReady, EVENT_MODIFY_STATE, TRUE, 0)) {
        return WinError("duplicate-cooperative-ready");
    }
    const UniqueHandle readyToSignal(inheritedReady);
    HANDLE readGate = nullptr; // 由子进程等待启动字节或 EOF。
    HANDLE writeGate = nullptr; // 只由宿主持有，避免子进程自身引入第二个写端。
    if (!CreatePipe(&readGate, &writeGate, nullptr, 1)) return WinError("create-cooperative-gate");
    const UniqueHandle gateToRead(readGate);
    child.gate.reset(writeGate);
    if (!SetHandleInformation(readGate, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        return WinError("mark-cooperative-gate-inheritable");
    }
    LaunchAttributes attributes;
    HANDLE inherited[]{readyToSignal.get(), gateToRead.get()};
    if (!attributes.Initialize() || !UpdateProcThreadAttribute(attributes.list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited, sizeof(inherited), nullptr, nullptr)) {
        return WinError("set-cooperative-child-handles");
    }
    // 除固定合作参数外不传入动态命令行；应用名明确使用已固定的本机映像。
    auto line = L"\"" + path + L"\" --ksword-breakpoint-ready " +
        std::to_wstring(reinterpret_cast<std::uintptr_t>(inherited[0])) + L" --ksword-breakpoint-gate " +
        std::to_wstring(reinterpret_cast<std::uintptr_t>(inherited[1]));
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes.list;
    PROCESS_INFORMATION created{};
    if (!CreateProcessW(path.c_str(), line.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            nullptr, nullptr, &startup.StartupInfo, &created)) {
        return WinError("launch-cooperative-child");
    }
    child.process.reset(created.hProcess);
    const UniqueHandle initialThread(created.hThread);
    child.observed.pid = created.dwProcessId;

    // 从创建所得的同一进程对象读回映像路径与时间；不另外按 PID 查当前对象。
    wchar_t observedPath[MAX_PATH]{};
    DWORD length = MAX_PATH;
    if (!QueryFullProcessImageNameW(child.process.get(), 0, observedPath, &length)) {
        return WinError("query-cooperative-child-image");
    }
    if (GetProcessId(child.process.get()) != created.dwProcessId || !NativeAmd64(child.process.get()) ||
        CompareStringOrdinal(observedPath, static_cast<int>(length), path.data(), static_cast<int>(path.size()), TRUE) !=
            CSTR_EQUAL) {
        return {"cooperative-child-identity-mismatch", ERROR_INVALID_DATA};
    }
    FILETIME start{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(child.process.get(), &start, &exit, &kernel, &user)) return WinError("query-cooperative-child-time");
    const auto creationTime = (static_cast<std::uint64_t>(start.dwHighDateTime) << 32) | start.dwLowDateTime;
    if (!creationTime) return {"missing-cooperative-child-time", ERROR_INVALID_DATA};
    child.observed.creationFileTime = creationTime;
    child.request.target.pid = created.dwProcessId;
    child.request.target.processCreationTime = creationTime;
    return {};
}

// 同时观察退出与就绪，进程先退出时不能用旧信号完成准入。
Failure AwaitReady(Child& child, ULONGLONG deadline)
{
    const auto now = GetTickCount64();
    const HANDLE handles[]{child.process.get(), child.ready.get()};
    const auto wait = WaitForMultipleObjects(2, handles, FALSE, now < deadline ? static_cast<DWORD>(deadline - now) : 0);
    if (wait == WAIT_FAILED) return WinError("wait-for-cooperative-ready");
    if (wait == WAIT_OBJECT_0) return {"child-exited-before-cooperative-ready", ERROR_PROCESS_ABORTED};
    if (wait != WAIT_OBJECT_0 + 1) return {"cooperative-ready-timeout", ERROR_TIMEOUT};
    child.observed.ready = true;
    child.ready.reset();
    return {};
}

// 只有属于该成员且仍由原生账本确切持有的事件，才能形成组继续令牌。
bool Held(const Child& child)
{
    const auto& state = child.observed.control;
    return state && state->status == NativeControlStatus::Held && state->attached &&
        state->pid == child.observed.pid && state->processCreationTime == child.observed.creationFileTime &&
        state->breakpointHit && state->group && !state->group->historical &&
        state->pending && state->pending->pid == child.observed.pid && state->pending->ledgerOwned &&
        !state->pending->continuationIndeterminate &&
        state->responsibility && state->responsibility->state == EventState::Held &&
        state->responsibility->groupId == state->group->groupId &&
        state->pending->event == state->responsibility->event &&
        state->pending->event.backendInstanceId == child.identity.backendInstanceId;
}

// 根据本次提交的 ID 与组确认原生回执，不能用 Close 或历史回执替代。
bool ConfirmedContinue(const NativeControlResult& result, const ReleaseRequest& request)
{
    return result.ledgerResult == LedgerResult::Applied && result.status == NativeControlStatus::Released &&
        result.releaseRequestId == request.requestId && result.group && result.group->groupId == request.groupId &&
        result.group->nativeEventState == EventState::Released && result.release && result.release->receipt &&
        result.release->receipt->result == ReleaseResult::Continued;
}

} // namespace

class OwnedBreakpointGroup::Impl final {
public:
    explicit Impl(OwnerIdentity identity) : identity_(std::move(identity)) {}
    ~Impl()
    {
        Drain();
    }

    OwnedBreakpointGroupResult Start(const std::wstring&, const std::string&);
    OwnedBreakpointGroupResult Query();
    OwnedBreakpointGroupResult Continue(const OwnedBreakpointGroupToken&);
    OwnedBreakpointGroupResult Close();

private:
    using Ending = OwnedBreakpointGroupEndReason;

    struct HeldPair {
        OwnedBreakpointGroupToken token; // 对外只暴露组标识和修订。
        std::array<ReleaseRequest, kOwnedBreakpointGroupSize> releases; // 冻结的真实原生继续请求。
    };

    OwnedBreakpointGroupResult Snapshot(LedgerResult = LedgerResult::Applied) const;
    void BeginEnding(Ending ending, Failure outcome, std::optional<std::size_t> member = {});
    void Drain();
    void Refresh();
    void CaptureStop();
    static void CloseLaunchGate(Child& child);
    static void ObserveChildExit(Child& child);

    const OwnerIdentity identity_; // 双成员共用的采样、会话与代次。
    std::array<Child, kOwnedBreakpointGroupSize> children_; // 固定成员，不按命中顺序重排。
    std::optional<HeldPair> held_; // 双方确实持有时冻结的当轮继续凭据。
    std::optional<OwnedBreakpointGroupRelease> lastRelease_; // 最近的显式提交及原始结果。
    std::uint64_t revision_ = 0; // 组修订与原生继续序号都不复用。
    Failure outcome_; // 发起清退时冻结的原因。
    std::optional<std::size_t> outcomeMember_; // 有责任成员时记录其下标。
    std::optional<Ending> ending_;
    bool started_ = false; // 已消费一次性启动请求。
    bool frozen_ = false; // 两个确认就绪的子进程已构成固定范围。
};

OwnedBreakpointGroupResult OwnedBreakpointGroup::Impl::Start(const std::wstring& exePath, const std::string& exportName)
{
    if (started_ || ending_) return Snapshot(LedgerResult::InvalidTransition);
    started_ = true;
    const auto fail = [this](Failure failure, std::optional<std::size_t> member = {}) {
        BeginEnding(Ending::Failed, failure, member);
        return Snapshot();
    };
    if (!ValidStart(exePath, exportName) || !storage::IsUuid(identity_.sampleId) ||
        !storage::IsUuid(identity_.sessionId) || !storage::IsUuid(identity_.epoch) ||
        !storage::IsUuid(identity_.backendInstanceId)) {
        return fail({"cooperative-pair-invalid-start", ERROR_INVALID_PARAMETER});
    }
    if (!NativeAmd64(GetCurrentProcess())) return fail({"cooperative-pair-native-amd64-required", ERROR_NOT_SUPPORTED});

    const auto separator = exePath.find_last_of(L'\\');
    const auto name = std::wstring_view(exePath).substr(separator + 1);
    storage::Directory directory;
    storage::Handle executable;
    auto pinned = storage::OpenRoot(exePath.substr(0, separator), false, false, directory);
    if (pinned) pinned = storage::OpenFile(directory, name, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, executable);
    if (!pinned) return fail({"pin-cooperative-child-image", pinned.nativeError ? pinned.nativeError : ERROR_BAD_PATHNAME});

    const auto path = directory.path.substr(4) + L"\\" + std::wstring(name);
    if (path.size() >= MAX_PATH) return fail({"cooperative-child-image-path-too-long", ERROR_FILENAME_EXCED_RANGE});
    const auto image = ks::file::AnalyzePeFileShared(path, false);
    if (!image || !image->success || !image->isPe64 || image->machine != IMAGE_FILE_MACHINE_AMD64 ||
        image->subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI) {
        return fail({"cooperative-child-requires-amd64-console", ERROR_BAD_EXE_FORMAT});
    }

    for (auto& child : children_) {
        child.identity = identity_;
        if (!storage::NewId(child.identity.backendInstanceId) || !storage::NewId(child.request.target.requestId)) {
            return fail({"allocate-cooperative-member-identities", ERROR_GEN_FAILURE});
        }
        child.request.target.explicitlyAuthorized = true;
        child.request.target.disposition = NativeTargetDisposition::ResumeAndDetach;
        child.request.modulePath = path;
        child.request.exportName = exportName;
    }

    // 所有成员先完成身份与就绪核对，再尝试附加其中任何一个。
    for (std::size_t i = 0; i < children_.size(); ++i) {
        if (auto failure = Launch(children_[i], path)) return fail(failure, i);
    }
    const auto deadline = GetTickCount64() + kReadyTimeoutMs;
    for (std::size_t i = 0; i < children_.size(); ++i) {
        if (auto failure = AwaitReady(children_[i], deadline)) return fail(failure, i);
    }
    for (std::size_t i = 0; i < children_.size(); ++i) {
        const auto life = WaitForSingleObject(children_[i].process.get(), 0);
        if (life == WAIT_FAILED) return fail(WinError("verify-cooperative-child-lifetime"), i);
        if (life != WAIT_TIMEOUT) return fail({"cooperative-child-exited-before-admission", ERROR_PROCESS_ABORTED}, i);
    }
    frozen_ = true;
    for (std::size_t i = 0; i < children_.size(); ++i) {
        auto& child = children_[i];
        child.owner = std::make_unique<NativeDebugOwner>(child.identity);
        child.observed.control = child.owner->ArmBreakpoint(child.request);
        const auto& state = *child.observed.control;
        if (state.status != NativeControlStatus::Accepted) {
            return fail({state.stage, state.win32Error ? state.win32Error : ERROR_GEN_FAILURE}, i);
        }
    }
    return Snapshot();
}

// 合并组状态，但按启动顺序保留每份原生快照和最近的原始继续回执。
OwnedBreakpointGroupResult OwnedBreakpointGroup::Impl::Snapshot(LedgerResult ledger) const
{
    OwnedBreakpointGroupResult result;
    result.frozen = frozen_;
    result.ledgerResult = ledger;
    result.lastRelease = lastRelease_;
    result.endReason = ending_;
    bool recovery = false;
    bool allGatesOpened = true;
    bool someHeld = false;
    for (std::size_t i = 0; i < children_.size(); ++i) {
        const auto& child = children_[i];
        auto& member = result.members[i];
        member = child.observed;
        member.held = Held(child);
        someHeld |= member.held;
        allGatesOpened &= member.gateOpened;
        result.clean &= !child.gate.valid() && (!member.control || member.control->clean);
        recovery |= member.control && !member.control->clean && member.control->status == NativeControlStatus::RecoveryRequired;
    }
    result.stage = outcome_.stage;
    result.win32Error = outcome_.error;
    result.outcomeMember = outcomeMember_;
    using enum OwnedBreakpointGroupState;
    if (recovery) {
        result.state = RecoveryRequired;
    } else if (ending_ && !result.clean) {
        result.state = Closing;
    } else if (ending_ == Ending::Failed) {
        result.state = Failed;
    } else if (ending_ == Ending::MemberEnded) {
        result.state = Ended;
    } else if (ending_ == Ending::Requested) {
        result.state = Closed;
    } else if (held_) {
        result.state = HeldComplete;
        result.stop = held_->token;
        result.stage = "cooperative-pair-held";
    } else if (someHeld) {
        result.state = HeldPartial;
        result.stage = "cooperative-pair-partially-held";
    } else if (allGatesOpened) {
        result.state = Running;
        result.stage = "cooperative-pair-running";
    } else if (started_) {
        result.state = Starting;
        result.stage = "arming-cooperative-pair";
    }
    return result;
}

// 只清退本会话的成员；未确认退役的所有者及其句柄继续保留。
void OwnedBreakpointGroup::Impl::Drain()
{
    held_.reset();
    for (auto& child : children_) {
        if (child.owner && (!child.observed.control || !child.observed.control->clean)) {
            child.observed.control = child.owner->Close();
        }
        CloseLaunchGate(child);
        ObserveChildExit(child);
    }
}

// 未接管的启动直接收到 EOF；已接管的等真实清退后再让孩子退出等待。
void OwnedBreakpointGroup::Impl::CloseLaunchGate(Child& child)
{
    if (child.observed.control && !child.observed.control->clean) return;
    child.gate.reset();
    child.ready.reset();
}

void OwnedBreakpointGroup::Impl::ObserveChildExit(Child& child)
{
    if (!child.process.valid()) return;
    if (!child.observed.exitCode && WaitForSingleObject(child.process.get(), 0) == WAIT_OBJECT_0) {
        DWORD exitCode = 0;
        if (GetExitCodeProcess(child.process.get(), &exitCode)) child.observed.exitCode = exitCode;
    }
    if (child.observed.exitCode && (!child.observed.control || child.observed.control->clean)) child.process.reset();
}

// 冻结清退原因后撤销当轮令牌，由每个拥有者单独归还真实责任。
void OwnedBreakpointGroup::Impl::BeginEnding(Ending ending, Failure outcome, std::optional<std::size_t> member)
{
    ending_ = ending;
    outcome_ = outcome;
    outcomeMember_ = member;
    Drain();
}

void OwnedBreakpointGroup::Impl::CaptureStop()
{
    if (held_ || !std::all_of(children_.begin(), children_.end(), Held)) return;
    HeldPair pair;
    if (revision_ == std::numeric_limits<std::uint64_t>::max() || !storage::NewId(pair.token.stopId)) {
        BeginEnding(Ending::Failed, {"allocate-cooperative-pair-stop", ERROR_GEN_FAILURE});
        return;
    }
    // 在发布令牌前同时冻结两份释放请求，后续查询不会重新拼接已发布的凭据。
    pair.token.stateRevision = ++revision_;
    const auto requestId = std::string(kSequencedReleasePrefix) + std::to_string(revision_);
    for (std::size_t i = 0; i < children_.size(); ++i) {
        const auto& child = children_[i];
        const auto& state = *child.observed.control;
        pair.releases[i] = {child.identity, state.group->groupId, state.responsibility->stopId,
            state.responsibility->event, requestId, state.group->stateRevision};
    }
    held_ = std::move(pair);
}

// 逐一读回 OS 责任；两端实际武装后打开启动门，运行时跟踪停点与退出。
void OwnedBreakpointGroup::Impl::Refresh()
{
    for (auto& child : children_) {
        if (child.owner && (!child.observed.control || !child.observed.control->clean)) {
            child.observed.control = child.owner->Query();
        }
        if (ending_) CloseLaunchGate(child);
        ObserveChildExit(child);
    }
    if (ending_ || !frozen_) return;

    for (std::size_t i = 0; i < children_.size(); ++i) {
        const auto& state = *children_[i].observed.control;
        if (state.status == NativeControlStatus::Ended) {
            if (children_[i].observed.gateOpened) {
                BeginEnding(Ending::MemberEnded, {state.stage, state.win32Error}, i);
            } else {
                BeginEnding(Ending::Failed, {"cooperative-child-exited-before-gate", ERROR_PROCESS_ABORTED}, i);
            }
            return;
        }
        if (state.status == NativeControlStatus::Rejected || state.status == NativeControlStatus::RecoveryRequired || state.clean) {
            BeginEnding(Ending::Failed, {state.stage, state.win32Error ? state.win32Error : ERROR_GEN_FAILURE}, i);
            return;
        }
    }

    if (!children_.front().observed.gateOpened) {
        if (!std::all_of(children_.begin(), children_.end(), [](const Child& child) {
            const auto& binding = child.observed.control->breakpoint;
            return binding && binding->state == NativeBreakpointState::Armed;
        })) return;

        for (std::size_t i = 0; i < children_.size(); ++i) {
            auto& child = children_[i];
            constexpr char go = '1';
            DWORD written = 0;
            if (!WriteFile(child.gate.get(), &go, sizeof(go), &written, nullptr)) {
                BeginEnding(Ending::Failed, WinError("open-cooperative-child-gate"), i);
                return;
            }
            if (written != sizeof(go)) {
                BeginEnding(Ending::Failed, {"open-cooperative-child-gate", ERROR_WRITE_FAULT}, i);
                return;
            }
            child.observed.gateOpened = true;
            child.gate.reset();
        }
    }
    if (!std::all_of(children_.begin(), children_.end(), Held)) held_.reset();
    CaptureStop();
}

OwnedBreakpointGroupResult OwnedBreakpointGroup::Impl::Query()
{
    Refresh();
    return Snapshot();
}

OwnedBreakpointGroupResult OwnedBreakpointGroup::Impl::Continue(const OwnedBreakpointGroupToken& stop)
{
    // 拒绝与重放保持只读，不借这些请求推进任何成员的清退。
    if (lastRelease_ && lastRelease_->stop == stop) return Snapshot(LedgerResult::Duplicate);
    if (!held_ || held_->token != stop) return Snapshot(LedgerResult::StaleRevision);
    Refresh();
    if (!held_ || held_->token != stop) return Snapshot(LedgerResult::StaleRevision);

    auto pair = std::move(*held_);
    held_.reset();
    lastRelease_.emplace();
    lastRelease_->stop = std::move(pair.token);
    std::optional<std::size_t> firstFailure;
    for (std::size_t i = 0; i < children_.size(); ++i) {
        auto& child = children_[i];
        auto& receipt = lastRelease_->members[i];
        receipt = child.owner->Continue(pair.releases[i]);
        child.observed.control = receipt;
        if (!ConfirmedContinue(receipt, pair.releases[i]) && !firstFailure) firstFailure = i;
    }
    lastRelease_->continued = !firstFailure;
    if (firstFailure) {
        const auto& failure = lastRelease_->members[*firstFailure];
        BeginEnding(Ending::Failed, {failure.stage, failure.win32Error ? failure.win32Error : ERROR_GEN_FAILURE}, firstFailure);
    }
    return Snapshot();
}

OwnedBreakpointGroupResult OwnedBreakpointGroup::Impl::Close()
{
    if (!ending_) {
        BeginEnding(Ending::Requested, {"cooperative-pair-close-requested", ERROR_SUCCESS});
    } else {
        Drain();
    }
    return Snapshot();
}

OwnedBreakpointGroup::OwnedBreakpointGroup(OwnerIdentity identity)
    : impl_(std::make_unique<Impl>(std::move(identity)))
{
}
OwnedBreakpointGroup::~OwnedBreakpointGroup() = default;

OwnedBreakpointGroupResult OwnedBreakpointGroup::Start(const std::wstring& exePath, const std::string& exportName)
{
    return impl_->Start(exePath, exportName);
}

OwnedBreakpointGroupResult OwnedBreakpointGroup::Query()
{
    return impl_->Query();
}

OwnedBreakpointGroupResult OwnedBreakpointGroup::Continue(const OwnedBreakpointGroupToken& stop)
{
    return impl_->Continue(stop);
}

OwnedBreakpointGroupResult OwnedBreakpointGroup::Close()
{
    return impl_->Close();
}

} // namespace ks::cli::action_analyze::control
