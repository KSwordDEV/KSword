#include "CooperativeBreakpointGate.h"

#include "../../../shared/usermode/backend/Common.h"

#include <vector>

namespace ks::cli::action_analyze::control {
namespace {
using ks::r3::common::UniqueHandle;

// 在失败的 Win32 调用之后立即保留原错误，防止零值被当作成功。
DWORD LastFailure()
{
    const auto error = GetLastError(); // 刚发生的原生错误。
    return error ? error : ERROR_GEN_FAILURE;
}
} // namespace

struct CooperativeBreakpointGate::Impl {
    UniqueHandle ready; // 宿主只等待，不向目标继承完整访问权。
    UniqueHandle signal; // 子进程继承的置位副本。
    UniqueHandle reader; // 子进程继承的管道读端。
    UniqueHandle writer; // 宿主的唯一管道写端，关闭时目标可观察 EOF。
    std::vector<std::uintptr_t> storage; // 启动属性列表的对齐存储。
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = nullptr; // 仅对成功初始化的列表调用销毁。
    bool prepared = false; // 单个 Gate 仅准备一次。
    bool waiting = false; // 已 Ready 且尚未发出业务启动字节。

    ~Impl()
    {
        if (attributes) {
            DeleteProcThreadAttributeList(attributes);
        }
    }
};

CooperativeBreakpointGate::CooperativeBreakpointGate() : impl_(std::make_unique<Impl>()) {}
CooperativeBreakpointGate::~CooperativeBreakpointGate() = default;

DWORD CooperativeBreakpointGate::Prepare(STARTUPINFOEXW& startup, std::wstring& commandLine)
{
    auto& gate = *impl_; // 当前一次性准备状态。
    if (gate.prepared) {
        return ERROR_INVALID_STATE;
    }
    gate.prepared = true;
    gate.ready.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!gate.ready.valid()) {
        return LastFailure();
    }
    HANDLE signal = nullptr; // 仅允许目标 SetEvent 的继承副本。
    const auto self = GetCurrentProcess(); // DuplicateHandle 的源和目标都是本宿主。
    if (!DuplicateHandle(self, gate.ready.get(), self, &signal, EVENT_MODIFY_STATE, TRUE, 0)) {
        return LastFailure();
    }
    gate.signal.reset(signal);
    HANDLE reader = nullptr; // CreatePipe 返回的读端。
    HANDLE writer = nullptr; // CreatePipe 返回的唯一写端。
    if (!CreatePipe(&reader, &writer, nullptr, 1)) {
        return LastFailure();
    }
    gate.reader.reset(reader);
    gate.writer.reset(writer);
    if (!SetHandleInformation(reader, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        return LastFailure();
    }

    // 白名单只含这两个句柄；不能继承宿主控制流或另一个管道写端。
    SIZE_T bytes = 0; // Windows 要求的属性存储大小。
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    if (!bytes) {
        return LastFailure();
    }
    gate.storage.resize((bytes + sizeof(std::uintptr_t) - 1) / sizeof(std::uintptr_t));
    const auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(gate.storage.data()); // 待初始化的对齐地址。
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) {
        return LastFailure();
    }
    gate.attributes = attributes;
    const HANDLE inherited[]{signal, reader}; // 唯一可继承的两个目标端句柄。
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            const_cast<HANDLE*>(inherited), sizeof(inherited), nullptr, nullptr)) {
        return LastFailure();
    }
    startup = {};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes;
    commandLine += L" --ksword-breakpoint-ready " + std::to_wstring(reinterpret_cast<std::uintptr_t>(signal)) +
        L" --ksword-breakpoint-gate " + std::to_wstring(reinterpret_cast<std::uintptr_t>(reader));
    return ERROR_SUCCESS;
}

DWORD CooperativeBreakpointGate::AwaitReady(HANDLE process)
{
    auto& gate = *impl_; // 创建结束，目标已有继承副本，关闭宿主多余的目标端。
    gate.signal.reset();
    gate.reader.reset();
    if (!gate.ready.valid() || !gate.writer.valid()) {
        return ERROR_INVALID_STATE;
    }
    const HANDLE handles[]{process, gate.ready.get()}; // 退出优先于 Ready，避免旧信号准入。
    const auto wait = WaitForMultipleObjects(2, handles, FALSE, 5000); // 合作启动的固定等待上限。
    gate.ready.reset();
    if (wait != WAIT_OBJECT_0 + 1) {
        const auto error = wait == WAIT_FAILED ? LastFailure() :
            wait == WAIT_OBJECT_0 ? ERROR_PROCESS_ABORTED : ERROR_TIMEOUT; // 保存等待的实际结果。
        Close();
        return error;
    }
    gate.waiting = true;
    return ERROR_SUCCESS;
}

DWORD CooperativeBreakpointGate::Observe(const NativeControlResult& control)
{
    auto& gate = *impl_; // 只在同一会话的串行查询链路中处理启动许可。
    if (!gate.waiting) {
        return ERROR_SUCCESS;
    }
    if (!control.attached || control.win32Error || !control.breakpoint ||
        control.breakpoint->state == NativeBreakpointState::Retiring ||
        control.breakpoint->state == NativeBreakpointState::Retired ||
        control.breakpoint->state == NativeBreakpointState::RecoveryRequired) {
        Close();
        return ERROR_SUCCESS;
    }
    if (control.breakpoint->state != NativeBreakpointState::Armed) {
        return ERROR_SUCCESS;
    }
    const char allowed = '1'; // 与现有合作双目标使用相同的一个字节许可。
    DWORD written = 0; // 系统实际提交的字节数。
    const auto ok = WriteFile(gate.writer.get(), &allowed, 1, &written, nullptr); // 管道为空且唯一一次写入。
    const auto error = ok ? (written == 1 ? ERROR_SUCCESS : ERROR_WRITE_FAULT) : LastFailure();
    Close();
    return error;
}

bool CooperativeBreakpointGate::Waiting() const noexcept
{
    return impl_->waiting;
}

void CooperativeBreakpointGate::Close() noexcept
{
    impl_->waiting = false;
    impl_->writer.reset();
    impl_->reader.reset();
    impl_->signal.reset();
    impl_->ready.reset();
}

} // namespace ks::cli::action_analyze::control
