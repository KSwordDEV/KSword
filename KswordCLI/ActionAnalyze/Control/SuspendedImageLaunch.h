#pragma once

#include "NativeDebugOwner.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <memory>

namespace ks::cli::action_analyze::control {

// 普通EXE启动的真实里程碑；不把入口DR0武装当作TLS或API Agent就绪。
struct SuspendedImageLaunchReceipt {
    std::wstring executable; // 本次固定文件身份后的绝对路径。
    std::uint32_t pid = 0; // CreateProcess返回的精确进程对象对应PID。
    std::uint64_t creationFileTime = 0; // 由创建句柄取得的实例身份。
    std::uint32_t initialThreadId = 0; // 原始主线程，供owner核对CREATE_PROCESS事件。
    std::uint32_t entryRva = 0; // 实际选择的PE入口或显式RVA；非PDB地址。
    bool createdSuspended = false; // 创建成功时原始挂起尚未归还。
    bool ownerAttachedBeforeResume = false; // 原owner回读确认先于首次Resume。
    bool breakpointArmedBeforeResume = false; // DR0及线程登记均由原owner确认。
    bool initialSuspendReleased = false; // 仅归还本次创建带来的一次挂起。
    bool earliestTlsCovered = false; // 本路径只设模块入口，不覆盖此前TLS/loader。
    std::optional<bool> apiAgentReady; // 本模块不部署Agent，保持未知。
    const char* stage = "image-launch-idle"; // 稳定诊断，由三端原状态通道展示。
    std::uint32_t win32Error = 0; // 启动或归还初始挂起的原始错误。
};

// 在调用方原串行worker使用；原NativeDebugOwner始终拥有调试事件及DR0恢复账。
// 失败启动只撤销本模块创建的子进程；初始挂起从不脱离这个对象的恢复责任。
class SuspendedImageLaunch final {
public:
    SuspendedImageLaunch();
    ~SuspendedImageLaunch();
    SuspendedImageLaunch(const SuspendedImageLaunch&) = delete;
    SuspendedImageLaunch& operator=(const SuspendedImageLaunch&) = delete;

    // 输入普通EXE及可选位置；两者省略时读取PE AddressOfEntryPoint。
    // request须已有owner身份、授权及requestId。成功才释放初始挂起，随后停点沿原owner控制。
    [[nodiscard]] NativeControlResult Start(NativeDebugOwner& owner, NativeBreakpointRequest request,
        const std::wstring& executable);
    // 原owner查询结果附带启动失败恢复状态；不重复Resume或重新附加。
    [[nodiscard]] NativeControlResult Observe(NativeControlResult state);
    // 关闭前先撤销尚未完成启动的自有子进程；已释放初始挂起时由原owner正常脱离。
    void CancelUnreleased() noexcept;
    [[nodiscard]] const SuspendedImageLaunchReceipt& Receipt() const noexcept;
    // 仅原worker在本对象存活期借用创建句柄；用于入口到Agent交接，调用方不得关闭或跨线程传递。
    [[nodiscard]] HANDLE ProcessHandle() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_; // 原始创建句柄及初始挂起责任均留在本对象。
};

} // namespace ks::cli::action_analyze::control
