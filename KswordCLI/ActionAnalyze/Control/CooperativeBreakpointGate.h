#pragma once

#include "NativeDebugOwner.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <memory>

namespace ks::cli::action_analyze::control {

// 私有内存由合作目标初始化后发布，宿主确认硬件停点武装才允许业务继续。
// 复用双目标的 Ready/Gate 参数；目标仅继承置位事件与管道读端，宿主退出时读到 EOF。
class CooperativeBreakpointGate final {
public:
    CooperativeBreakpointGate();
    ~CooperativeBreakpointGate();
    CooperativeBreakpointGate(const CooperativeBreakpointGate&) = delete;
    CooperativeBreakpointGate& operator=(const CooperativeBreakpointGate&) = delete;

    // 在创建子进程前调用，填入精确句柄白名单并将两项固定参数附到已有命令行。
    // startup 和命令行供同次 CreateProcessW 使用，必须指定继承及 EXTENDED_STARTUPINFO_PRESENT。
    [[nodiscard]] DWORD Prepare(STARTUPINFOEXW& startup, std::wstring& commandLine);
    // 创建成功后，按原进程句柄等待 Ready 或退出，最长 5 秒；不猜测初始化耗时。
    [[nodiscard]] DWORD AwaitReady(HANDLE process);
    // 串行会话每轮查询调用。仅确实 Armed 时写入启动字节，失败或结束关闭管道。
    [[nodiscard]] DWORD Observe(const NativeControlResult& control);
    [[nodiscard]] bool Waiting() const noexcept;
    // 取消尚未通过的启动：关闭宿主唯一写端，目标按合作协议由 EOF 正常退出。
    void Close() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_; // 私有句柄和启动属性只在本端串行控制线程访问。
};

} // namespace ks::cli::action_analyze::control
