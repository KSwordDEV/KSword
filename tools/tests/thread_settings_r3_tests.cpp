// 独立 HostX64 测试：与 ThreadSettingsR3.cpp 一起编译，链接 Advapi32.lib。
// 所有 PID/TID 都来自当前测试进程；仅对本测试创建的等待线程提交有效编辑。
#include "../../Ksword5.1/Ksword5.1/ProcessDock/ThreadSettingsR3.h"

#include <Windows.h>
#include <sddl.h>

#include <cstdio>
#include <memory>

namespace {

using namespace ks::threadsettings;

struct CloseFixtureHandle
{
    // 离开测试范围时关闭所传入的自有句柄。
    void operator()(HANDLE handle) const noexcept
    {
        ::CloseHandle(handle);
    }
};

using Handle = std::unique_ptr<void, CloseFixtureHandle>;

struct Checks
{
    int count = 0; // 已执行的断言数。
    int failures = 0; // 失败的断言数。

    // 记录断言结果和短名称；返回断言条件，便于在前置条件不满足时停止。
    bool expect(bool result, const char* name)
    {
        ++count;
        if (!result)
        {
            ++failures;
            std::fprintf(stderr, "FAIL: %s\n", name);
        }
        return result;
    }
};

// 直接从原始句柄获得 FILETIME，作为与被测后端独立的身份来源。
std::uint64_t fileTime(const FILETIME& time)
{
    ULARGE_INTEGER packed{}; // 两个半字组成 Windows 原始时间值。
    packed.LowPart = time.dwLowDateTime;
    packed.HighPart = time.dwHighDateTime;
    return packed.QuadPart;
}

// 用测试自有进程/线程的原始句柄采集身份；返回是否取得完整创建时间。
bool readIdentity(HANDLE thread, DWORD tid, Identity& identity)
{
    FILETIME process{}, created{}, exited{}, kernel{}, user{}; // Get*Times 的输出。
    if (!::GetProcessTimes(::GetCurrentProcess(), &process, &exited, &kernel, &user) ||
        !::GetThreadTimes(thread, &created, &exited, &kernel, &user))
    {
        return false;
    }
    identity = {::GetCurrentProcessId(), tid, fileTime(process), fileTime(created)};
    return identity.processCreationTime100ns != 0 && identity.threadCreationTime100ns != 0;
}

// 测试线程只等待退出事件；超时后自行结束，返回失败以避免掩盖异常退出。
DWORD WINAPI waitForStop(void* stop)
{
    return ::WaitForSingleObject(stop, 30000) == WAIT_OBJECT_0 ? 0 : 1;
}

// 与原始句柄上的 Win32 结果交叉核验提升开关，确认布尔方向没有颠倒。
bool rawBoostEquals(HANDLE thread, int enabled)
{
    BOOL disabled = FALSE; // Win32 真值表示禁用，与被测接口相反。
    return ::GetThreadPriorityBoost(thread, &disabled) && (disabled != FALSE) == (enabled == 0);
}

// 对给定自有线程验证写入、回读、字段隔离及冲突检测。
void exerciseEdits(Checks& checks, HANDLE thread, const Identity& identity)
{
    const Snapshot start = Query(identity); // 创建后的真实初始配置。
    if (!checks.expect(start.identityError == 0 && start.priority.value && start.priorityBoost.value &&
            start.priority.writable && start.priorityBoost.writable, "read both settings with normal write access"))
    {
        return;
    }
    int currentPriority = *start.priority.value; // 每步用上一步已确认的真实值作为基线。
    const int originalBoost = *start.priorityBoost.value; // 优先级循环中不应被改变的提升开关。
    checks.expect(::GetThreadPriority(thread) == currentPriority && rawBoostEquals(thread, originalBoost),
        "initial settings match the original Win32 handle");

    // 覆盖可设档位和两种提升值，其中一部分操作没有提供进程创建时间。
    Identity withoutProcessTime = identity; // 保留必需的 PID/TID/线程创建时间。
    withoutProcessTime.processCreationTime100ns = 0;
    constexpr int priorities[] = {THREAD_PRIORITY_IDLE, THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_BELOW_NORMAL,
        THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_HIGHEST, THREAD_PRIORITY_NORMAL}; // 合法档位。
    for (const int desired : priorities) // 每一步只设置线程的相对优先级。
    {
        const Receipt receipt = Apply({identity, Field::Priority, currentPriority, desired}); // 实际回读回执。
        if (!checks.expect(receipt.status == Status::Applied && receipt.error == 0 &&
                receipt.snapshot.priority.value == desired && ::GetThreadPriority(thread) == desired,
                "relative priority set and verified"))
        {
            return;
        }
        checks.expect(receipt.snapshot.priorityBoost.value == originalBoost && rawBoostEquals(thread, originalBoost),
            "priority write leaves boost unchanged");
        currentPriority = desired;
    }

    const int flippedBoost = 1 - originalBoost; // 先翻转，再恢复初始开关值。
    const Receipt boost = Apply({withoutProcessTime, Field::PriorityBoost, originalBoost, flippedBoost});
    checks.expect(boost.status == Status::Applied && boost.snapshot.priorityBoost.value == flippedBoost &&
        rawBoostEquals(thread, flippedBoost), "boost write works without process creation time and has correct polarity");
    checks.expect(boost.snapshot.priority.value == currentPriority && ::GetThreadPriority(thread) == currentPriority,
        "boost write leaves priority unchanged");
    const Receipt restored = Apply({identity, Field::PriorityBoost, flippedBoost, originalBoost}); // 恢复提升开关。
    checks.expect(restored.status == Status::Applied && restored.snapshot.priorityBoost.value == originalBoost &&
        rawBoostEquals(thread, originalBoost), "boost restore has correct polarity");

    // 过期草稿不得被当作成功，读回应反映当前值，且不会写入 desired。
    const Receipt conflict = Apply({identity, Field::Priority, THREAD_PRIORITY_IDLE, THREAD_PRIORITY_LOWEST});
    checks.expect(conflict.status == Status::Conflict && conflict.snapshot.priority.value == currentPriority &&
        ::GetThreadPriority(thread) == currentPriority, "stale priority baseline does not write");
    const Receipt boostConflict = Apply({identity, Field::PriorityBoost, flippedBoost, flippedBoost}); // 错误的提升基线。
    checks.expect(boostConflict.status == Status::Conflict && boostConflict.snapshot.priorityBoost.value == originalBoost &&
        rawBoostEquals(thread, originalBoost), "stale boost baseline does not write");

    // 验证拒绝高风险/非相对档位；不在夹具中调用 Win32 设置这些值。
    for (const int invalid : {THREAD_PRIORITY_TIME_CRITICAL, THREAD_MODE_BACKGROUND_BEGIN, 3})
    {
        const Receipt rejected = Apply({identity, Field::Priority, currentPriority, invalid}); // 非法设置回执。
        checks.expect(rejected.status == Status::Failed && rejected.error == ERROR_INVALID_PARAMETER &&
            ::GetThreadPriority(thread) == currentPriority, "reject disallowed desired priority");
    }
    const Receipt invalidBoost = Apply({identity, Field::PriorityBoost, originalBoost, 2}); // 非布尔参数。
    checks.expect(invalidBoost.status == Status::Failed && invalidBoost.error == ERROR_INVALID_PARAMETER &&
        rawBoostEquals(thread, originalBoost), "reject non-boolean desired boost");
}

// 变动一个身份字段，验证两个入口都不返回数据，提交不会触及实际目标。
void exerciseBadIdentity(Checks& checks, const Identity& invalid, const char* name)
{
    const Snapshot snapshot = Query(invalid); // 错误身份不得产生貌似有效的字段。
    const Receipt edit = Apply({invalid, Field::Priority, THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_LOWEST});
    checks.expect(snapshot.identityError != 0 && !snapshot.priority.value && !snapshot.priorityBoost.value &&
        !snapshot.priority.writable && !snapshot.priorityBoost.writable && edit.status == Status::Unavailable &&
        edit.error == snapshot.identityError && edit.snapshot.identityError == snapshot.identityError, name);
}

// 使用只授予查询和等待权的自有线程对象验证真实权限失败与只读回退。
void exerciseReadOnly(Checks& checks, HANDLE stop)
{
    PSECURITY_DESCRIPTOR descriptor = nullptr; // 仅本次创建的线程使用；不是进程或系统 ACL。
    // 0x00100800 = SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION；不授予 SET。
    if (!checks.expect(::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;0x00100800;;;WD)", SDDL_REVISION_1, &descriptor, nullptr) != FALSE, "build read-only thread DACL"))
    {
        return;
    }
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE}; // 禁止继承夹具句柄。
    DWORD tid = 0; // 新建线程的 ID。
    const Handle thread(::CreateThread(&attributes, 0, waitForStop, stop, 0, &tid)); // 等待同一退出事件。
    ::LocalFree(descriptor);
    Identity identity{}; // 只读 DACL 线程的冻结身份。
    if (!checks.expect(thread && readIdentity(thread.get(), tid, identity), "create and identify read-only thread"))
    {
        return;
    }

    const Snapshot snapshot = Query(identity); // 拒写不应丢弃合法读值或产生读取错误。
    checks.expect(snapshot.identityError == 0 && snapshot.priority.value == THREAD_PRIORITY_NORMAL &&
        snapshot.priorityBoost.value && snapshot.priority.error == 0 && snapshot.priorityBoost.error == 0 &&
        !snapshot.priority.writable && !snapshot.priorityBoost.writable, "read-only thread still yields settings");
    const Receipt receipt = Apply({identity, Field::Priority, THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_LOWEST});
    checks.expect(receipt.status == Status::Unavailable && receipt.error == ERROR_ACCESS_DENIED &&
        receipt.snapshot.priority.value == THREAD_PRIORITY_NORMAL && ::GetThreadPriority(thread.get()) == THREAD_PRIORITY_NORMAL,
        "read-only edit is denied without changing priority");
    checks.expect(::SetEvent(stop) && ::WaitForSingleObject(thread.get(), 5000) == WAIT_OBJECT_0,
        "read-only worker shuts down cooperatively");
}

} // namespace

// 无参数独立测试入口；所有夹具线程结束后返回成功或失败退出码。
int main()
{
    Checks checks; // 累计断言和失败。
    const Handle stop(::CreateEventW(nullptr, TRUE, FALSE, nullptr)); // 用于正常回收两个自有线程。
    DWORD tid = 0; // 主夹具线程的 ID。
    const Handle thread(stop ? ::CreateThread(nullptr, 0, waitForStop, stop.get(), 0, &tid) : nullptr);
    Identity identity{}; // 主夹具线程的冻结身份。
    if (checks.expect(thread && readIdentity(thread.get(), tid, identity), "create and identify owned worker"))
    {
        exerciseEdits(checks, thread.get(), identity);

        // 构造每种错误身份时只改一项，验证拒绝原因不是依赖其它不匹配字段。
        Identity invalid = identity;
        invalid.processCreationTime100ns += 1;
        exerciseBadIdentity(checks, invalid, "wrong process creation time");
        invalid = identity;
        invalid.threadCreationTime100ns += 1;
        exerciseBadIdentity(checks, invalid, "wrong thread creation time");
        invalid.threadCreationTime100ns = 0;
        exerciseBadIdentity(checks, invalid, "missing mandatory thread creation time");
        invalid = identity;
        invalid.processCreationTime100ns = 0;
        invalid.processId ^= 0x80000000u; // 不会打开其它进程：仅在自有线程句柄上比较 PID。
        exerciseBadIdentity(checks, invalid, "wrong owner PID without process time");
        checks.expect(::GetThreadPriority(thread.get()) == THREAD_PRIORITY_NORMAL, "invalid identities did not write");

        exerciseReadOnly(checks, stop.get());
        DWORD exitCode = 1; // 主夹具线程的真实退出码。
        if (checks.expect(::SetEvent(stop.get()) && ::WaitForSingleObject(thread.get(), 5000) == WAIT_OBJECT_0 &&
                ::GetExitCodeThread(thread.get(), &exitCode) && exitCode == 0, "owned worker shuts down cooperatively"))
        {
            // 保持原句柄打开，验收仍可打开或已无法打开的已退出对象均不会通过。
            exerciseBadIdentity(checks, identity, "exited worker cannot be queried or edited");
        }
    }
    else if (stop && thread)
    {
        // 身份采集失败也先发出停止信号，再在有界时间内等待回收。
        ::SetEvent(stop.get());
        ::WaitForSingleObject(thread.get(), 5000);
    }
    std::printf("Thread settings R3: %d checks, %d failures\n", checks.count, checks.failures);
    return checks.failures == 0 ? 0 : 1;
}
