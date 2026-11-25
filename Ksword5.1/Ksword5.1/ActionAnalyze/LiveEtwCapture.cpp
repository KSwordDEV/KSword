#include "LiveEtwCapture.h"
#include "../UI/AsyncOperation.h"

#include <chrono>
#include <objbase.h>

namespace ks::action_analyze
{
namespace
{
    using namespace std::chrono_literals;
    constexpr qsizetype kLiveRows = 4096; // 与归档预览采用同一行数预算。
    constexpr auto kDuration = 120s; // 有界采样，避免打开后忘记结束。
    constexpr quint64 kProcessIntervalMs = 1000; // 预设活动分析的最短区间。
    constexpr qsizetype kEtwRows = kLiveRows - kDuration.count(); // 为每个活动区间预留一行。

    // 把系统 FILETIME 作为无符号刻度读回，保持原始 100ns 精度。
    quint64 FileTicks(const FILETIME& value)
    {
        return (static_cast<quint64>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
    }

    // 函数作用域内保留目标进程身份。析构只关闭自己的查询句柄。
    struct TargetHandle
    {
        HANDLE value = nullptr; // 仅查询和等待，不改变目标状态。
        ~TargetHandle()
        {
            if (value)
            {
                CloseHandle(value);
            }
        }
    };

    // 工作线程读到的累计计数，采样间以单调时间而不是系统 UTC 相减。
    struct ProcessCounters
    {
        quint64 tickMs = 0; // 读取完成时的单调毫秒。
        quint64 cpu100ns = 0; // 用户态及内核态累计 CPU 时间。
        std::optional<IO_COUNTERS> io; // 原生累计 I/O；读取失败保持未知。
    };

    // 从原进程句柄读取计数并复核创建时间，返回 Win32 错误或零。
    DWORD ReadCounters(HANDLE target, quint64 expectedCreation, ProcessCounters& counters)
    {
        FILETIME created{}, exited{}, kernel{}, user{}; // 进程身份和 CPU 计数。
        if (!GetProcessTimes(target, &created, &exited, &kernel, &user))
        {
            return GetLastError();
        }
        if (FileTicks(created) != expectedCreation)
        {
            return ERROR_INVALID_PARAMETER;
        }
        IO_COUNTERS io{}; // 与 CPU 同轮读取的累计 I/O。
        if (GetProcessIoCounters(target, &io))
        {
            counters.io = io;
        }
        counters.cpu100ns = FileTicks(kernel) + FileTicks(user);
        counters.tickMs = GetTickCount64();
        return ERROR_SUCCESS;
    }

    // 比较两个同实例快照。系统异常回退的计数不填成零。
    LiveProcessObservation AnalyzeInterval(quint64 creation, const ProcessCounters& prev, const ProcessCounters& next)
    {
        LiveProcessObservation result; // 界面显示的区间及证据。
        result.creationTime = creation;
        result.elapsedMs = next.tickMs - prev.tickMs;
        result.cpu100ns = next.cpu100ns - prev.cpu100ns;
        if (prev.io && next.io)
        {
            if (next.io->ReadTransferCount >= prev.io->ReadTransferCount)
            {
                result.readBytes = next.io->ReadTransferCount - prev.io->ReadTransferCount;
            }
            if (next.io->WriteTransferCount >= prev.io->WriteTransferCount)
            {
                result.writeBytes = next.io->WriteTransferCount - prev.io->WriteTransferCount;
            }
        }
        return result;
    }
}

LiveEtwCapture::LiveEtwCapture(QString project, quint32 pid, QUuid provider)
    : m_pid(pid), m_provider(provider.isNull() ? QString() : provider.toString().toUpper())
{
    // 已打开项目只作为采样上下文。此处没有写入项目目录。
    m_snapshot.projectId = std::move(project);
    m_snapshot.sampleId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_snapshot.live = true;
    m_snapshot.end = SegmentEnd::Complete;
}

LiveEtwReceipt LiveEtwCapture::collect(const ks::ui::AsyncOperationToken& token)
{
    // 打开指定对象并保留句柄，目标退出时结束采集，防止按同 PID 续采。
    const auto target = std::shared_ptr<TargetHandle>(new TargetHandle{
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, m_pid)}); // 回调保留同一实例句柄。
    FILETIME created{}, exited{}, kernel{}, user{}; // 只使用创建时间作为进程身份。
    if (!target->value || !GetProcessTimes(target->value, &created, &exited, &kernel, &user))
    {
        return {false, false, QStringLiteral("OpenProcess/GetProcessTimes: %1").arg(GetLastError())};
    }
    m_created = FileTicks(created);
    FILETIME start{}; // 回调会丢弃采样边界之前的事件。
    GetSystemTimePreciseAsFileTime(&start);
    m_started = FileTicks(start);
    if (WaitForSingleObject(target->value, 0) != WAIT_TIMEOUT)
    {
        return {false, false, QStringLiteral("WaitForSingleObject: %1").arg(ERROR_PROCESS_ABORTED)};
    }

    ProcessCounters previous; // 第一份成功读取的同实例基线。
    m_processError = ReadCounters(target->value, m_created, previous);
    if (m_processError != ERROR_SUCCESS)
    {
        return {false, false, QStringLiteral("GetProcessTimes: %1").arg(m_processError)};
    }

    if (token.isCanceled() || m_stop.load())
    {
        LiveEtwReceipt canceled; // 尚未启用来源，也没有待清退的原生会话。
        canceled.end = CaptureEnd::Requested;
        return canceled;
    }
    m_collecting.store(true);
    m_ready.store(true);
    // 同一次启动可启用明确选择的辅助来源。独立报告 ETW 失败。
    if (!m_provider.isEmpty())
    {
        GUID guid{}; // 由已校验的 QUuid 生成的标准 ETW provider 身份。
        const auto provider = m_provider.toStdWString(); // Windows 使用的原生字符串。
        if (CLSIDFromString(provider.c_str(), &guid) == S_OK)
        {
            ks::r3::monitor::EtwFilterState filter; // 冻结本次采集选择。
            filter.processId = m_pid;
            filter.minimumLevel = 5;
            filter.providers = {{provider, guid, true, 5, 0}};
            m_controller.setEventCallback([this, target](const ks::r3::monitor::EtwEvent& event) {
                const auto wait = WaitForSingleObject(target->value, 0); // 原句柄是否仍指向活目标。
                if (wait == WAIT_TIMEOUT)
                {
                    append(event);
                }
                else if (wait == WAIT_OBJECT_0)
                {
                    FILETIME created{}, exited{}, kernel{}, user{}; // 排空期间只接收旧实例的时段。
                    if (GetProcessTimes(target->value, &created, &exited, &kernel, &user) && event.timestamp < FileTicks(exited))
                    {
                        append(event);
                    }
                }
            });
            (void)m_controller.start(filter);
        }
    }
    const auto deadline = std::chrono::steady_clock::now() + kDuration; // 不受系统时钟调整影响。
    m_end = CaptureEnd::Requested;
    while (!token.isCanceled() && !m_stop.load())
    {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            m_end = CaptureEnd::TimeLimit;
            break;
        }
        const auto wait = WaitForSingleObject(target->value, 25); // 保留目标退出和系统错误的区别。
        if (wait != WAIT_TIMEOUT)
        {
            m_end = wait == WAIT_OBJECT_0 ? CaptureEnd::TargetExited : CaptureEnd::ProcessError;
            m_processError = wait == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
            break;
        }
        if (GetTickCount64() - previous.tickMs < kProcessIntervalMs)
        {
            continue;
        }
        ProcessCounters current; // 同一进程实例的下一份累计计数。
        m_processError = ReadCounters(target->value, m_created, current);
        if (m_processError != ERROR_SUCCESS || current.cpu100ns < previous.cpu100ns)
        {
            if (m_processError == ERROR_SUCCESS)
            {
                m_processError = ERROR_INVALID_DATA;
            }
            m_end = CaptureEnd::ProcessError;
            break;
        }
        appendProcess(AnalyzeInterval(m_created, previous, current));
        previous = current;
    }
    // 冻结终态前完成真正的 STOP、消费排空与句柄关闭。
    return recover(); // 快速退出也要保存已消费的真实记录。
}

// 用与实时 ETW 相同的行序号和时间域发布一个真实计数区间。
void LiveEtwCapture::appendProcess(const LiveProcessObservation& observation)
{
    const std::lock_guard lock(m_mutex); // 序号与 ETW 消费回调共享。
    if (m_snapshot.rows.size() >= kLiveRows)
    {
        ++m_omitted;
        return;
    }
    SegmentRow row; // 预设分析记录无 ETW 原始报头和归档偏移。
    row.sequence = static_cast<quint64>(m_snapshot.rows.size()) + 1;
    row.pid = m_pid;
    row.liveProcess = observation;
    LARGE_INTEGER qpc{}; // 区间提交时使用同一个本机接收时钟。
    if (QueryPerformanceCounter(&qpc))
    {
        row.receiveQpc = static_cast<quint64>(qpc.QuadPart);
    }
    m_snapshot.rows.append(std::move(row));
}

void LiveEtwCapture::append(const ks::r3::monitor::EtwEvent& event)
{
    // 相关 PID 只表示记录上下文。核对退出时间，排除新实例的迟到报头。
    if (event.processId != m_pid || event.timestamp < m_created || event.timestamp < m_started ||
        QString::fromStdWString(event.providerText).compare(m_provider, Qt::CaseInsensitive) != 0)
    {
        return;
    }
    const std::lock_guard lock(m_mutex); // 写入和快照发布不能交叉修改列表。
    if (m_etwRows >= kEtwRows)
    {
        ++m_omitted;
        return;
    }
    LARGE_INTEGER qpc{}; // 本端收到事件时的单调时钟。
    SegmentRow row; // 同一总览模型中的直接来源行。
    row.sequence = static_cast<quint64>(m_snapshot.rows.size()) + 1;
    if (QueryPerformanceCounter(&qpc))
    {
        row.receiveQpc = static_cast<quint64>(qpc.QuadPart);
    }
    row.pid = event.processId;
    row.tid = event.threadId;
    row.liveEtw = LiveEtwHeader{m_provider, event.timestamp, event.eventId, event.version, event.opcode};
    m_snapshot.rows.append(std::move(row));
    ++m_etwRows;
}

EtwCoverage LiveEtwCapture::coverage() const
{
    if (m_provider.isEmpty())
    {
        return EtwCoverage::Disabled;
    }
    // 结合控制器及消费者的状态，区分启动中、真正可用及失败。
    const auto state = m_controller.evidence(); // Windows 分阶段回执。
    if ((state.startAttempted && state.startStatus != ERROR_SUCCESS) || state.threadStartFailed ||
        (state.openAttempted && state.openStatus != ERROR_SUCCESS) || state.callbackFailed || state.processCompleted ||
        (!state.providers.empty() && state.providers.front().status != ERROR_SUCCESS))
    {
        return EtwCoverage::Unavailable;
    }
    return state.processAttempted ? EtwCoverage::Active : EtwCoverage::Starting;
}

std::optional<SegmentSnapshot> LiveEtwCapture::preview(const QString& displayedSample, qsizetype displayedRows) const
{
    const std::lock_guard lock(m_mutex); // 返回共享的 Qt 值，不借用回调线程内存。
    if (!m_ready.load() || (m_snapshot.rows.isEmpty() && displayedRows >= 0) ||
        (displayedSample == m_snapshot.sampleId && displayedRows == m_snapshot.rows.size()))
    {
        return std::nullopt;
    }
    return m_snapshot;
}

LiveEtwReceipt LiveEtwCapture::recover()
{
    const bool stopped = m_controller.stopChecked(); // 原生所有者负责清退同一会话。
    m_collecting.store(false);
    return receipt(stopped);
}

LiveEtwReceipt LiveEtwCapture::receipt(bool stopped) const
{
    const auto state = m_controller.evidence(); // 真实 provider、消费与收尾回执。
    LiveEtwReceipt result; // 由工作线程一次性发布给总览。
    result.ready = m_ready.load();
    result.processError = m_processError;
    result.end = m_end;
    result.recovery = !stopped;
    if (state.statisticsKnown)
    {
        result.loss = state.eventsLost;
    }
    if (!m_provider.isEmpty() && (!state.startSucceeded || state.threadStartFailed || !state.processAttempted ||
        state.callbackFailed || !stopped ||
        (state.processCompleted && state.processStatus != ERROR_SUCCESS && state.processStatus != ERROR_CANCELLED)))
    {
        // stopChecked 会更新普通状态，原生错误从结构回执读取。
        const auto provider = state.providers.empty() ? ERROR_SUCCESS : state.providers.front().status;
        const auto stopError = state.stopStatuses.empty() ? ERROR_SUCCESS : state.stopStatuses.back();
        result.etwIssue = QStringLiteral("StartTrace=%1, EnableTrace=%2, OpenTrace=%3, ProcessTrace=%4, Stop=%5, CloseTrace=%6")
            .arg(state.startStatus).arg(provider).arg(state.openStatus).arg(state.processStatus)
            .arg(stopError).arg(state.closeStatus);
        if (!stopped)
        {
            result.error = result.etwIssue;
        }
    }
    const std::lock_guard lock(m_mutex); // 同时返回最终的行预算回执。
    result.omitted = m_omitted;
    result.hasRows = !m_snapshot.rows.isEmpty();
    return result;
}
}
