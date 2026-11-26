#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include "NativeDebugOwner.h"
#include "NativeWriteExecutionTransition.h"

#include <utility>
#include <map>
#include <string>
#include <vector>

namespace ks::cli::action_analyze::control { class NativePrivateExecutionPage; }

namespace ks::cli::action_analyze::control::native_owner_detail {

// 原owner与准入共用的精确句柄RAII；不转移或释放任何目标状态责任。
class NativeDebugHandle {
public:
    explicit NativeDebugHandle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~NativeDebugHandle() { Reset(); }
    NativeDebugHandle(NativeDebugHandle&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    NativeDebugHandle& operator=(NativeDebugHandle&& other) noexcept { Reset(std::exchange(other.value_, nullptr)); return *this; }
    HANDLE Get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }
    void Reset(HANDLE value = nullptr) noexcept { if (*this) CloseHandle(value_); value_ = value; }
private:
    HANDLE value_;
};

struct NativeDebugError {
    const char* stage = "idle";
    DWORD code = ERROR_SUCCESS;
    explicit operator bool() const noexcept { return code != ERROR_SUCCESS; }
};

struct NativeDebugSlot {
    NativeDebugHandle thread;
    DWORD64 originalAddress;
    DWORD64 originalControl;
    std::uint64_t enrolledAfterStop;
    NativeFollowSlotState followState;
};
using NativeDebugSlots = std::map<DWORD, NativeDebugSlot>;
// 句柄及恢复账由原owner持有；仅在其原debug事件内登记/恢复，不创建新所有者。
[[nodiscard]] NativeDebugError EnrollNativeBreakpointThread(NativeDebugSlots& slots, DWORD pid, DWORD tid,
    HANDLE eventThread, std::uint64_t address, DWORD64 control, std::uint64_t revision, bool pageMode);
[[nodiscard]] NativeDebugError RestoreNativeBreakpointThreads(NativeDebugSlots& slots, std::uint64_t address);
[[nodiscard]] NativeDebugError CaptureNativeInterruptThread(NativeDebugHandle& heldThread, const DEBUG_EVENT& event);

[[nodiscard]] NativeDebugError CheckProcessIdentity(HANDLE process, const NativePauseRequest& request);
[[nodiscard]] NativeDebugError CheckAdmission(HANDLE process, const NativePauseRequest& request);
[[nodiscard]] NativeDebugError CheckOwnedChild(const NativePauseRequest& request);
[[nodiscard]] std::optional<DWORD64> DebugControl(std::uint32_t dataBytes) noexcept;
[[nodiscard]] std::uintptr_t InstructionPointer(const CONTEXT& context) noexcept;
[[nodiscard]] std::uint64_t FileTime(FILETIME value) noexcept;
[[nodiscard]] std::optional<std::uint64_t> ReadQpc() noexcept;
[[nodiscard]] bool AbsoluteModulePath(std::wstring_view path);
[[nodiscard]] bool IsNativeRequestedInterrupt(HANDLE process, HANDLE thread, const DEBUG_EVENT& event,
    std::uint64_t breakpointAddress);
// 准入及停止组共同使用的强线程集合；仅采集身份，不获取目标运行控制权。
struct NativeDebugFrozenThread {
    NativeDebugHandle handle;
    NativeFrozenThread member;
};
using NativeDebugThreadIds = std::map<std::pair<DWORD, std::uint64_t>, std::string>;
[[nodiscard]] std::string NewId();
[[nodiscard]] std::string BreakpointId(std::string_view backend, std::uint64_t revision, bool stop);
[[nodiscard]] std::string MembershipHash(const std::vector<ThreadIdentity>& ordered);
[[nodiscard]] NativeDebugError CaptureThreads(DWORD pid, const std::string& processInstanceId,
    const NativeDebugThreadIds& priorIds, std::vector<NativeDebugFrozenThread>& threads);

// 原owner持有的独立range/N票据窗口；验证及事务均在原debug线程，绝不Continue。
class NativeExecutionRangeHistory final {
public:
    [[nodiscard]] NativeControlResult Apply(const OwnerIdentity& owner, const NativeExecutionRangeRequest& request,
        NativeControlResult current, NativePrivateExecutionPage* page, HANDLE process);
    [[nodiscard]] const std::optional<NativeExecutionRangeReceipt>& Last() const noexcept { return last_; }
private:
    std::map<std::uint64_t, std::pair<NativeExecutionRangeRequest, NativeControlResult>> history_;
    std::uint64_t sequence_ = 0;
    std::optional<NativeExecutionRangeReceipt> last_;
};

// 保存独立pause/N回执，活动请求完成后仍保留幂等结果；不拥有调试附加或目标句柄。
class NativeArmedPauseHistory final {
public:
    [[nodiscard]] NativeControlResult Begin(const OwnerIdentity& owner, const OwnerIdentity& requestedOwner,
        const NativePauseRequest& request, const NativeControlResult& current, bool available, bool& issue);
    [[nodiscard]] std::optional<NativeArmedPauseReceipt> Find(std::string_view id) const;
    [[nodiscard]] const std::optional<NativeArmedPauseReceipt>& Last() const noexcept { return last_; }
    [[nodiscard]] bool Pending() const noexcept { return pending_.has_value(); }
    void Complete(NativeArmedPauseState state, const char* stage, DWORD error,
        std::optional<std::string> group = {}, std::optional<NativeEventKey> event = {});
private:
    std::map<std::uint64_t, NativeArmedPauseReceipt> history_;
    std::uint64_t sequence_ = 0;
    std::optional<std::uint64_t> pending_;
    std::optional<NativeArmedPauseReceipt> last_;
};

} // namespace ks::cli::action_analyze::control::native_owner_detail
