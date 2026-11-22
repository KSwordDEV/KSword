#include "ThreadSettingsR3.h"

#include <Windows.h>
#include <memory>

namespace ks::threadsettings {
namespace {

struct CloseObject
{
    // 由唯一所有权包装调用，关闭通过 OpenProcess/OpenThread 获取的句柄。
    void operator()(HANDLE object) const noexcept
    {
        ::CloseHandle(object);
    }
};

using ObjectHandle = std::unique_ptr<void, CloseObject>;

struct Target
{
    ObjectHandle process; // 只有指定了进程创建时间才打开，保留到操作结束。
    ObjectHandle thread; // 已选线程对象，用同一份句柄读、写、回读。
    bool writable = false; // 打开的线程句柄是否同时拥有写权限。
    DWORD writeOpenError = ERROR_SUCCESS; // 未能获取读写句柄的原因。
};

// 将公开 API 返回的两个 FILETIME 半字合为身份记录使用的原始时间值。
std::uint64_t toFileTime100ns(const FILETIME& time)
{
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32U) | time.dwLowDateTime;
}

// 不阻塞地检查给定对象是否仍存活；返回零或可用于回执的 Win32 错误码。
DWORD checkAlive(HANDLE object)
{
    const DWORD wait = ::WaitForSingleObject(object, 0); // 线程/进程退出后将有信号。
    if (wait == WAIT_TIMEOUT)
    {
        return ERROR_SUCCESS;
    }
    return wait == WAIT_FAILED ? ::GetLastError() : ERROR_OPERATION_ABORTED;
}

// 检查已经打开的对象；不重新通过 PID/TID 查找对象。
DWORD checkTargetAlive(const Target& target)
{
    if (target.process)
    {
        const DWORD processError = checkAlive(target.process.get()); // 进程存活结果。
        if (processError != ERROR_SUCCESS)
        {
            return processError;
        }
    }
    return checkAlive(target.thread.get());
}

// 打开并核验冻结身份，成功时将对象句柄保留在 target，失败则返回错误码。
DWORD openTarget(const Identity& identity, Target& target)
{
    if (!identity.processId || !identity.threadId || !identity.threadCreationTime100ns)
    {
        return ERROR_INVALID_PARAMETER;
    }

    // 仅在有进程创建时间可比对时打开进程；缺失时仍须核验线程归属 PID。
    FILETIME created{}, exited{}, kernel{}, user{}; // Get*Times 要求的四项输出；只比对创建时间。
    if (identity.processCreationTime100ns)
    {
        target.process.reset(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, identity.processId));
        if (!target.process || !::GetProcessTimes(target.process.get(), &created, &exited, &kernel, &user))
        {
            return ::GetLastError();
        }
        if (toFileTime100ns(created) != identity.processCreationTime100ns)
        {
            return ERROR_NOT_FOUND;
        }
    }

    // 仅请求文档所需的有限读写权限和存活检查权限；不更改令牌权限。
    constexpr DWORD readAccess = THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
    target.thread.reset(::OpenThread(readAccess | THREAD_SET_LIMITED_INFORMATION, FALSE, identity.threadId));
    target.writable = static_cast<bool>(target.thread);
    if (!target.writable)
    {
        target.writeOpenError = ::GetLastError();
        target.thread.reset(::OpenThread(readAccess, FALSE, identity.threadId));
        if (!target.thread)
        {
            return ::GetLastError();
        }
    }

    // 即使只读打开成功，也在实际拿到的同一个对象上复核归属和创建时间。
    const DWORD owner = ::GetProcessIdOfThread(target.thread.get()); // Win32 报告的所属 PID。
    if (!owner)
    {
        return ::GetLastError();
    }
    if (owner != identity.processId)
    {
        return ERROR_NOT_FOUND;
    }
    if (!::GetThreadTimes(target.thread.get(), &created, &exited, &kernel, &user))
    {
        return ::GetLastError();
    }
    if (toFileTime100ns(created) != identity.threadCreationTime100ns)
    {
        return ERROR_NOT_FOUND;
    }
    return checkTargetAlive(target);
}

// 将身份/存活失败传播到两个字段，不返回可能已过期的值或写权限。
Snapshot identityFailure(DWORD error)
{
    return {{std::nullopt, error, false}, {std::nullopt, error, false}, error};
}

// 读取已核验线程的一个设置；返回值与字段错误互斥，提升开关采用正逻辑。
Value readSetting(const Target& target, Field field)
{
    if (field == Field::Priority)
    {
        const int priority = ::GetThreadPriority(target.thread.get()); // Windows 相对优先级。
        if (priority == THREAD_PRIORITY_ERROR_RETURN)
        {
            return {std::nullopt, ::GetLastError(), false};
        }
        return {priority, ERROR_SUCCESS, target.writable};
    }

    BOOL disabled = FALSE; // Windows 返回的是“禁用优先级提升”，须取反。
    if (!::GetThreadPriorityBoost(target.thread.get(), &disabled))
    {
        return {std::nullopt, ::GetLastError(), false};
    }
    return {disabled ? 0 : 1, ERROR_SUCCESS, target.writable};
}

// 读取两个字段并检查对象未退出；受编辑的字段放在最后，缩短到设置调用的间隔。
Snapshot readSnapshot(const Target& target, Field lastField)
{
    Snapshot snapshot; // 两次独立读取，不是原子快照。
    if (lastField == Field::Priority)
    {
        snapshot.priorityBoost = readSetting(target, Field::PriorityBoost);
        snapshot.priority = readSetting(target, Field::Priority);
    }
    else
    {
        snapshot.priority = readSetting(target, Field::Priority);
        snapshot.priorityBoost = readSetting(target, Field::PriorityBoost);
    }

    const DWORD identityError = checkTargetAlive(target); // 读取结束后的存活判断。
    return identityError == ERROR_SUCCESS ? snapshot : identityFailure(identityError);
}

// 校验编辑参数；基线还需与真实读值比较。拒绝进入后台模式或设为 Time Critical。
bool validEdit(const Edit& edit)
{
    switch (edit.field)
    {
    case Field::PriorityBoost:
        return (edit.expected == 0 || edit.expected == 1) && (edit.desired == 0 || edit.desired == 1);
    case Field::Priority:
        // 可接受实际读取的其它基线（如实时进程的扩展值），但只允许设为下列相对档位。
        switch (edit.desired)
        {
        case THREAD_PRIORITY_IDLE:
        case THREAD_PRIORITY_LOWEST:
        case THREAD_PRIORITY_BELOW_NORMAL:
        case THREAD_PRIORITY_NORMAL:
        case THREAD_PRIORITY_ABOVE_NORMAL:
        case THREAD_PRIORITY_HIGHEST:
            return edit.expected != THREAD_PRIORITY_ERROR_RETURN;
        default:
            return false;
        }
    default:
        return false;
    }
}

} // namespace

Snapshot Query(const Identity& identity)
{
    Target target; // 本次查询持有的对象和读写能力。
    const DWORD error = openTarget(identity, target); // 身份或打开失败的错误。
    return error == ERROR_SUCCESS ? readSnapshot(target, Field::PriorityBoost) : identityFailure(error);
}

Receipt Apply(const Edit& edit)
{
    if (!validEdit(edit))
    {
        return {Status::Failed, {}, ERROR_INVALID_PARAMETER};
    }

    Target target; // 读、设、回读全部绑定这里持有的对象，不重新打开。
    const DWORD identityError = openTarget(edit.identity, target); // 写前的身份及存活复核结果。
    if (identityError != ERROR_SUCCESS)
    {
        return {Status::Unavailable, identityFailure(identityError), identityError};
    }

    const bool isPriority = edit.field == Field::Priority; // 否则为提升开关。
    const Snapshot before = readSnapshot(target, edit.field); // 写前真实读值。
    const Value& current = isPriority ? before.priority : before.priorityBoost; // 仅对目标字段比对。
    if (!current.value)
    {
        return {Status::Unavailable, before, current.error};
    }
    if (*current.value != edit.expected)
    {
        return {Status::Conflict, before, ERROR_RETRY};
    }
    if (!current.writable)
    {
        return {Status::Unavailable, before, target.writeOpenError};
    }

    // 公开的设置 API 和写前比较并不原子；不要因回执失配重试或覆盖其它写入。
    const BOOL didSet = isPriority
        ? ::SetThreadPriority(target.thread.get(), edit.desired)
        : ::SetThreadPriorityBoost(target.thread.get(), edit.desired == 0 ? TRUE : FALSE);
    const DWORD setError = didSet ? ERROR_SUCCESS : ::GetLastError(); // 先留存错误，再执行回读。
    const Snapshot after = readSnapshot(target, edit.field); // 设置失败也尝试在原句柄上回读。
    if (!didSet)
    {
        return {Status::Failed, after, setError};
    }

    const Value& verified = isPriority ? after.priority : after.priorityBoost; // 设置后的验证值。
    if (!verified.value)
    {
        return {Status::Unverified, after, verified.error};
    }
    if (*verified.value != edit.desired)
    {
        return {Status::Unverified, after, ERROR_RETRY};
    }
    return {Status::Applied, after, ERROR_SUCCESS};
}

} // namespace ks::threadsettings
