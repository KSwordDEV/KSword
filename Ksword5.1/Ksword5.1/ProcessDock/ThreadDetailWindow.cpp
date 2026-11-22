#include "ThreadDetailWindow.h"
#include "ThreadStackWindow.h"
#include "../ArkDriverClient/ArkDriverClient.h"

namespace
{
    // 将 Windows 创建时间转为列表缓存使用的 FILETIME 整数。
    std::uint64_t asFileTime(const FILETIME& value)
    {
        return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32U) | value.dwLowDateTime;
    }

    // 输入持有的进程、线程句柄；只有两个等待均超时才认为对象仍存活。
    bool objectsStillRunning(const ksword::ark::DriverHandle& process, const ksword::ark::DriverHandle& thread)
    {
        return ::WaitForSingleObject(process.native(), 0) == WAIT_TIMEOUT &&
            ::WaitForSingleObject(thread.native(), 0) == WAIT_TIMEOUT;
    }
}

VerifiedThreadDetail QueryVerifiedThreadDetail(const ThreadStackTarget& target, const unsigned long flags)
{
    VerifiedThreadDetail result{}; // 尚未通过身份复核的回执。
    const ksword::ark::DriverHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, target.processId)); // 原进程对象。
    const ksword::ark::DriverHandle thread(::OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, target.threadId)); // 原线程对象。
    FILETIME processCreated{}, threadCreated{}, exited{}, kernel{}, user{}; // 两种对象的独立创建时间。
    if (!process.isValid() || !thread.isValid() || ::GetProcessIdOfThread(thread.native()) != target.processId ||
        !::GetProcessTimes(process.native(), &processCreated, &exited, &kernel, &user) ||
        !::GetThreadTimes(thread.native(), &threadCreated, &exited, &kernel, &user) ||
        target.threadCreationTime100ns == 0 || target.threadCreationTime100ns != asFileTime(threadCreated) ||
        (target.processCreationTime100ns != 0 && target.processCreationTime100ns != asFileTime(processCreated)) ||
        !objectsStillRunning(process, thread))
    {
        result.diagnostic = QStringLiteral("R0: 无法复核线程身份，未执行查询。");
        return result;
    }

    // 被动探测缺失时不请求自动加载；失败仍可展示冻结的列表身份。
    const ksword::ark::DriverClient driver; // 统一的只读 R0 请求入口。
    const auto connection = driver.openSilently(); // 先检查驱动是否可用。
    if (!connection.isValid())
    {
        result.diagnostic = QStringLiteral("R0: 驱动设备不可用或拒绝访问。");
        return result;
    }
    const auto detail = driver.queryThreadRuntimeDetail(target.threadId, target.processId,
        flags | KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_IDENTITY); // 请求对应目标和字段组。
    result.response = detail.response;
    // 回执缺少创建时间；通过查询前后仍存活的原对象夹住查询区间。
    if (!detail.io.ok)
    {
        result.diagnostic = QString::fromStdString(detail.io.message);
    }
    else if (!objectsStillRunning(process, thread))
    {
        result.diagnostic = QStringLiteral("R0: 目标已退出或无法复核存活状态，未采用本次回执。");
    }
    else if (result.response.version != KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION ||
        result.response.threadId != target.threadId || result.response.processId != target.processId ||
        (result.response.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_PUBLIC_IDENTITY) == 0)
    {
        result.diagnostic = QStringLiteral("R0: 响应身份或版本不匹配。");
    }
    else
    {
        result.verified = true;
    }
    return result;
}
