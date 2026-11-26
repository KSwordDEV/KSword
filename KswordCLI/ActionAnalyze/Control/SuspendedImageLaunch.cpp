#include "SuspendedImageLaunch.h"
#include "../Project/ProjectStorage.h"
#include "../../../Ksword5.1/Ksword5.1/ksword/file/pe_analyzer.h"

#include <algorithm>
#include <utility>

namespace ks::cli::action_analyze::control {
namespace {
namespace storage = Ksword::ActionAnalyze::ProjectStorage;

// 输入原生回执及启动故障，保留调试恢复责任和精确实例，不伪造clean成功。
NativeControlResult Failed(NativeControlResult state, const char* stage, DWORD error)
{
    state.stage = stage;
    state.win32Error = error;
    if (state.status != NativeControlStatus::RecoveryRequired)
    {
        state.status = NativeControlStatus::Rejected; // 原owner已有恢复失败时保留恢复状态。
    }
    state.ledgerResult = LedgerResult::InvalidEvidence;
    return state;
}

// 只接受本地绝对DOS EXE；不解释shell、URL、命令行或相对工作目录。
bool LocalExecutable(const std::wstring& path)
{
    return path.size() > 7 && path.size() < MAX_PATH &&
        ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' && path[2] == L'\\' && path.find_last_of(L'\\') > 2 &&
        path.find(L'\0') == path.npos && path.find_first_of(L"\"\r\n:/", 2) == path.npos &&
        CompareStringOrdinal(path.data() + path.size() - 4, 4, L".exe", 4, TRUE) == CSTR_EQUAL;
}
} // namespace

struct SuspendedImageLaunch::Impl {
    storage::Handle process; // 创建返回的精确子进程对象，失败不通过PID重新打开。
    storage::Handle thread; // 只归还原始主线程的一次挂起，不Resume到零。
    SuspendedImageLaunchReceipt receipt; // 原worker发布的启动里程碑。
    bool aborting = false; // 首次失败后只执行退出确认，不重复开始启动。
    DWORD abortError = ERROR_SUCCESS; // 终止请求失败的原始错误。

    // 初始挂起未释放时撤销本次新建目标，返回后仍由Observe确认对象退出。
    void Cancel() noexcept
    {
        if (!process || receipt.initialSuspendReleased)
        {
            return;
        }
        aborting = true;
        if (WaitForSingleObject(process.get(), 0) != WAIT_OBJECT_0 &&
            !TerminateProcess(process.get(), ERROR_PROCESS_ABORTED))
        {
            abortError = GetLastError();
        }
    }
};

// 构造时仅分配本地责任对象，实际进程创建必须显式调用Start。
SuspendedImageLaunch::SuspendedImageLaunch() : impl_(std::make_unique<Impl>())
{
}

// 正常调用方先沿原Close确认clean；异常析构仍撤销尚未释放初始挂起的自有子进程。
SuspendedImageLaunch::~SuspendedImageLaunch()
{
    impl_->Cancel();
}

// 原worker只读回执，不查询进程或将Armed推断为API就绪。
const SuspendedImageLaunchReceipt& SuspendedImageLaunch::Receipt() const noexcept
{
    return impl_->receipt;
}

// 返回CreateProcess原始对象，避免交接失败时按PID重新打开错误实例。
HANDLE SuspendedImageLaunch::ProcessHandle() const noexcept
{
    return impl_->process ? impl_->process.get() : nullptr; // 空存储句柄为INVALID_HANDLE_VALUE，借用接口统一返回null。
}

// 原会话关闭时调用；已释放初始挂起的目标继续交由原owner脱离。
void SuspendedImageLaunch::CancelUnreleased() noexcept
{
    impl_->Cancel();
}

NativeControlResult SuspendedImageLaunch::Start(NativeDebugOwner& owner, NativeBreakpointRequest request,
    const std::wstring& requestedPath)
{
    auto& launch = *impl_; // 仅由原调用方worker访问，不依赖UI消息循环。
    auto& receipt = launch.receipt; // 保存本轮启动边界，不复用API采集的Ready字段。
    const auto reject = [&](const char* stage, DWORD error) {
        receipt.stage = stage; // 创建前失败同样发布实际阶段，不能仍显示idle。
        receipt.win32Error = error;
        return Failed({}, stage, error);
    };
    if (receipt.createdSuspended || request.target.pid || request.privateAddress || request.writeWatchBytes ||
        request.writeWatchPointerExport || request.executePointerExport || request.waitForModule)
    {
        return reject("image-launch-invalid-request", ERROR_INVALID_PARAMETER);
    }
    auto path = requestedPath; // 文件选择器路径先标准化，再固定父目录和文件对象。
    std::replace(path.begin(), path.end(), L'/', L'\\');
    if (!LocalExecutable(path))
    {
        return reject("image-launch-absolute-exe-required", ERROR_BAD_PATHNAME);
    }
    const auto separator = path.find_last_of(L'\\'); // 目录链和文件固定句柄覆盖解析及创建。
    storage::Directory directory; // 固定整个父目录链，拒绝解析期间的目录替换。
    storage::Handle executable; // 固定实际EXE，覆盖解析和创建期间的文件身份。
    auto pinned = storage::OpenRoot(path.substr(0, separator), false, false, directory);
    if (pinned)
    {
        pinned = storage::OpenFile(directory, std::wstring_view(path).substr(separator + 1), GENERIC_READ,
            FILE_SHARE_READ, OPEN_EXISTING, executable);
    }
    if (!pinned)
    {
        return reject("image-launch-pin-image", pinned.nativeError);
    }
    path = directory.path.substr(4) + L"\\" + path.substr(separator + 1);
    const auto image = ks::file::AnalyzePeFileShared(path, false); // 无合作标记要求，也不解析PDB。
    if (!image || !image->success || !image->isPe64 || image->machine != IMAGE_FILE_MACHINE_AMD64 ||
        (image->subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI && image->subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI))
    {
        return reject("image-launch-amd64-exe-required", ERROR_BAD_EXE_FORMAT);
    }
    if (!request.rva && request.exportName.empty())
    {
        request.rva = image->entryPointRva; // 默认真实PE AddressOfEntryPoint，ASLR基址由owner回读。
    }
    if (request.rva && (!*request.rva || *request.rva >= image->sizeOfImage))
    {
        return reject("image-launch-entry-rva-required", ERROR_INVALID_ADDRESS);
    }
    receipt.executable = path;
    receipt.entryRva = request.rva.value_or(0);
    STARTUPINFOW startup{}; // 不继承任何控制管道或合作Ready/Gate句柄。
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION created{}; // 失败前不发布任何目标身份。
    auto command = L"\"" + path + L"\""; // 只有经过固定验证的映像路径，不解释其它命令参数。
    const auto workingDirectory = directory.path.substr(4); // CreateProcess使用同一固定目录的普通DOS路径。
    if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | DETACHED_PROCESS, nullptr, workingDirectory.c_str(), &startup, &created))
    {
        return reject("image-launch-create-suspended", GetLastError());
    }
    launch.process = storage::Handle(created.hProcess);
    launch.thread = storage::Handle(created.hThread);
    receipt.createdSuspended = true;
    receipt.pid = created.dwProcessId;
    receipt.initialThreadId = created.dwThreadId;
    // 从此任何失败都保留启动恢复责任；先撤销子进程，再让原owner排空事件。
    const auto abort = [&](NativeControlResult state, const char* stage, DWORD error) {
        receipt.stage = stage;
        receipt.win32Error = error;
        launch.Cancel();
        return Observe(Failed(std::move(state), stage, error));
    };
    FILETIME start{}, exit{}, kernel{}, user{}; // 原创建句柄提供强实例时间。
    if (!GetProcessTimes(launch.process.get(), &start, &exit, &kernel, &user))
    {
        return abort({}, "image-launch-query-creation", GetLastError());
    }
    receipt.creationFileTime = (static_cast<std::uint64_t>(start.dwHighDateTime) << 32) | start.dwLowDateTime;
    wchar_t observedPath[MAX_PATH]{}; // 用创建句柄核对实际映像，避免只凭磁盘解析或PID认为已绑定。
    DWORD observedLength = MAX_PATH;
    if (!QueryFullProcessImageNameW(launch.process.get(), 0, observedPath, &observedLength))
    {
        return abort({}, "image-launch-query-child-image", GetLastError());
    }
    if (GetProcessId(launch.process.get()) != receipt.pid ||
        CompareStringOrdinal(observedPath, static_cast<int>(observedLength), path.data(), static_cast<int>(path.size()), TRUE) != CSTR_EQUAL)
    {
        return abort({}, "image-launch-child-identity-mismatch", ERROR_INVALID_DATA);
    }
    request.target.pid = receipt.pid;
    request.target.processCreationTime = receipt.creationFileTime;
    request.modulePath = path;
    request.explicitImageAttachment = true;
    request.initialThreadId = receipt.initialThreadId; // owner须在CREATE_PROCESS事件先装DR0，不能等loader助手。
    auto state = owner.ArmBreakpoint(request);
    const auto deadline = GetTickCount64() + 5000; // 有限等待原调试线程；初始主线程始终保持挂起。
    while (state.status != NativeControlStatus::Rejected && state.status != NativeControlStatus::RecoveryRequired &&
        (!state.attached || !state.breakpoint || state.breakpoint->state == NativeBreakpointState::Installing) &&
        GetTickCount64() < deadline)
    {
        Sleep(10);
        state = owner.Query();
    }
    if (!state.attached || state.pid != receipt.pid || state.processCreationTime != receipt.creationFileTime ||
        !state.breakpoint || state.breakpoint->requestId != request.target.requestId || state.breakpoint->state != NativeBreakpointState::Armed ||
        !state.breakpoint->address || !state.breakpoint->enrolledThreads || state.win32Error ||
        state.status == NativeControlStatus::RecoveryRequired || state.status == NativeControlStatus::Rejected)
    {
        const auto error = state.win32Error ? state.win32Error : ERROR_TIMEOUT; // 移动原快照前冻结诊断。
        return abort(std::move(state), "image-launch-arm-before-resume-failed", error);
    }
    receipt.ownerAttachedBeforeResume = true;
    receipt.breakpointArmedBeforeResume = true;
    receipt.entryRva = state.breakpoint->rva;
    const auto previous = ResumeThread(launch.thread.get()); // 仅释放创建时取得的一次责任。
    if (previous == static_cast<DWORD>(-1) || previous != 1)
    {
        return abort(std::move(state), "image-launch-initial-suspend-conflict",
            previous == static_cast<DWORD>(-1) ? GetLastError() : ERROR_INVALID_STATE);
    }
    receipt.initialSuspendReleased = true;
    receipt.stage = "image-launch-entry-armed-initial-suspend-released";
    launch.thread.reset(); // 后续暂停/继续/步进只交给原NativeDebugOwner。
    return Observe(owner.Query());
}

NativeControlResult SuspendedImageLaunch::Observe(NativeControlResult state)
{
    auto& launch = *impl_; // 每次原worker查询都确认未完成启动的真实退出状态。
    if (!state.pid)
    {
        state.pid = launch.receipt.pid;
        state.processCreationTime = launch.receipt.creationFileTime;
    }
    if (!launch.aborting)
    {
        return state;
    }
    const auto exited = WaitForSingleObject(launch.process.get(), 0); // signaled才证明自有目标已退出。
    const auto waitError = exited == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS; // 读取失败不能当作正常等待。
    state.stage = launch.receipt.stage;
    state.win32Error = launch.receipt.win32Error;
    if (exited != WAIT_OBJECT_0)
    {
        state.clean = false;
        state.status = launch.abortError || waitError ? NativeControlStatus::RecoveryRequired : NativeControlStatus::ClosePending;
        if (launch.abortError || waitError)
        {
            state.stage = "image-launch-abort-failed";
            state.win32Error = launch.abortError ? launch.abortError : waitError;
        }
    }
    else if (state.clean && !state.attached)
    {
        state.status = NativeControlStatus::Rejected;
    }
    return state;
}

} // namespace ks::cli::action_analyze::control
