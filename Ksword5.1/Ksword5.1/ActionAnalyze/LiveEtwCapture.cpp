#include "LiveEtwCapture.h"
#include "../UI/AsyncOperation.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <algorithm>
#include <iterator>
#include <objbase.h>

namespace ks::action_analyze
{
namespace
{
    constexpr std::size_t kProcessRows = 120; // 保留最近约两分钟的活动区间，不限采集时长。
    constexpr std::size_t kEtwRows = 4096 - kProcessRows; // 预览总预算与离线视图一致。
    constexpr quint64 kProcessIntervalMs = 1000; // 预设活动分析的最短区间。
    constexpr quint64 kArchiveIntervalMs = 5000; // 周期刷盘，也限制常驻的段创建频率。
    constexpr qsizetype kArchiveBatch = 256; // 单段最多含这些观察，收尾记录独立写入。
    constexpr qsizetype kArchiveQueue = 4096; // 慢磁盘不阻塞 ETW 回调；队列满显式计数。

    // 常驻采集仍使用共享投递门禁，但长时间等待不占用短任务的并发名额。
    struct PoolCapacityLease
    {
        QThreadPool* pool = QThreadPool::globalInstance(); // 与 AsyncOperation 的实际派发池一致。
        PoolCapacityLease() { pool->releaseThread(); }
        ~PoolCapacityLease() { pool->reserveThread(); }
    };

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

LiveEtwCapture::LiveEtwCapture(LiveArchiveProject project, quint32 pid, QUuid provider)
    : m_pid(pid), m_provider(provider.isNull() ? QString() : provider.toString().toUpper()), m_project(std::move(project))
{
    // 无项目时只使用内存 UUID；正式项目登记后以磁盘采样身份为准。
    m_snapshot.projectId = m_project.projectId;
    m_snapshot.sampleId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_snapshot.live = true;
    m_snapshot.end = SegmentEnd::Complete;
}

LiveEtwReceipt LiveEtwCapture::collect(const ks::ui::AsyncOperationToken& token)
{
    const PoolCapacityLease releaseCapacity; // 从实际执行线程释放共享池的计数名额，结束时成对恢复。
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

    if (!m_project.manifest.isEmpty())
    {
        auto sample = m_writer.open(m_project, m_pid); // 目标资格核实后登记，返回提交身份。
        const std::lock_guard lock(m_mutex); // 只发布值，不在锁内做磁盘 I/O。
        if (!sample)
        {
            m_archive = m_writer.status();
            LiveEtwReceipt failed;
            failed.error = m_archive.error;
            failed.archive = m_archive;
            return failed;
        }
        m_snapshot.sampleId = sample->sample.id;
        m_registeredSample = std::move(sample);
        m_acceptArchive = true;
    }
    m_end = CaptureEnd::Requested;
    if (token.isCanceled() || m_stop.load())
    {
        return recover(); // 已登记的采样需要独立的真实结束记录。
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
    quint64 lastArchive = GetTickCount64(); // 单调节拍，档案写入不会以预览容量为界。
    while (!token.isCanceled() && !m_stop.load())
    {
        const auto wait = WaitForSingleObject(target->value, 100); // 目标退出立即唤醒，停止请求最多等待一个周期。
        if (wait != WAIT_TIMEOUT)
        {
            m_end = wait == WAIT_OBJECT_0 ? CaptureEnd::TargetExited : CaptureEnd::ProcessError;
            m_processError = wait == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
            break;
        }
        const auto now = GetTickCount64(); // 同轮使用一份时间判断值。
        if (now - lastArchive >= kArchiveIntervalMs)
        {
            flushArchive(false);
            lastArchive = now;
        }
        if (now - previous.tickMs < kProcessIntervalMs)
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
    SegmentRow row; // 预设分析记录无 ETW 原始报头和归档偏移。
    row.pid = m_pid;
    row.liveProcess = observation;
    LARGE_INTEGER qpc{}; // 区间提交时使用同一个本机接收时钟。
    if (QueryPerformanceCounter(&qpc))
    {
        row.receiveQpc = static_cast<quint64>(qpc.QuadPart);
    }
    appendRow(std::move(row), m_processRows, kProcessRows);
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
    LARGE_INTEGER qpc{}; // 本端收到事件时的单调时钟。
    SegmentRow row; // 同一总览模型中的直接来源行。
    if (QueryPerformanceCounter(&qpc))
    {
        row.receiveQpc = static_cast<quint64>(qpc.QuadPart);
    }
    row.pid = event.processId;
    row.tid = event.threadId;
    row.liveEtw = LiveEtwHeader{m_provider, event.timestamp, event.eventId, event.version, event.opcode};
    appendRow(std::move(row), m_etwRows, kEtwRows);
}

// 滚动淘汰只影响未来的视图快照；序号不复用，也不改变当前采集状态。
void LiveEtwCapture::appendRow(SegmentRow row, std::deque<SegmentRow>& window, std::size_t limit)
{
    row.sequence = ++m_snapshot.liveRevision;
    if (m_acceptArchive)
    {
        if (m_archiveQueue.size() < kArchiveQueue)
        {
            m_archiveQueue.append(row);
        }
        else
        {
            ++m_archive.dropped;
        }
    }
    window.push_back(std::move(row));
    if (window.size() > limit)
    {
        window.pop_front();
        ++m_evicted;
    }
}

// 从 GUI 回读归档状态值，互斥只覆盖短的队列交换和回执发布。
LiveArchiveStatus LiveEtwCapture::archiveStatus() const
{
    const std::lock_guard lock(m_mutex); // 读取已发布状态。
    return m_archive;
}

// 给目录刷新和工具条返回同一份冻结的采样身份。未登记时返回空值。
std::optional<SampleRequest> LiveEtwCapture::registeredSample() const
{
    const std::lock_guard lock(m_mutex); // 采样身份冻结后的本地副本。
    return m_registeredSample;
}

// 只回读当前采样 ID，供工具条区分临时窗口和其他采样的旧结果。
QString LiveEtwCapture::sampleId() const
{
    const std::lock_guard lock(m_mutex); // 与项目登记时的身份切换串行。
    return m_snapshot.sampleId;
}

// 收尾先排空已接纳的观察，只有原生停止成功后才写最终记录。
void LiveEtwCapture::flushArchive(bool final)
{
    QList<SegmentRow> pending; // 此次交给磁盘线程的冻结队列。
    quint64 dropped = 0; // 完成时实际归档队列丢失数。
    quint64 observed = 0; // 全程实际接纳的预览观测数。
    {
        const std::lock_guard lock(m_mutex); // 交换队列后立即放开供消费者继续入队。
        if (!m_acceptArchive)
        {
            return;
        }
        pending.swap(m_archiveQueue);
        dropped = m_archive.dropped;
        observed = m_snapshot.liveRevision;
        if (final)
        {
            m_acceptArchive = false;
        }
    }

    qsizetype next = 0; // 已确认的本批前缀；失败批次不纳入已确认。
    while (next < pending.size())
    {
        const auto size = (std::min)(kArchiveBatch, pending.size() - next); // 有界段正文。
        if (!m_writer.write(pending.mid(next, size)))
        {
            break;
        }
        next += size;
    }
    if (final && next == pending.size() && m_writer.status().error.isEmpty())
    {
        const auto native = m_controller.evidence(); // 终态只使用实际清退回执。
        const auto reason = m_end == CaptureEnd::TargetExited ? QStringLiteral("target-exited")
            : m_end == CaptureEnd::ProcessError ? QStringLiteral("process-error") : QStringLiteral("requested");
        const auto end = QJsonDocument(QJsonObject{{QStringLiteral("kind"), QStringLiteral("qt-live-end-v1")},
            {QStringLiteral("reason"), reason}, {QStringLiteral("observed"), QString::number(observed)},
            {QStringLiteral("headerPid"), QString::number(m_pid)},
            {QStringLiteral("creationFileTime"), QString::number(m_created)},
            {QStringLiteral("provider"), m_provider.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(m_provider)},
            {QStringLiteral("archiveQueueDropped"), QString::number(dropped)},
            {QStringLiteral("nativeTailUnconfirmed"), native.tailDeliveryUnconfirmed},
            {QStringLiteral("eventsLost"), native.statisticsKnown ? QJsonValue(QString::number(native.eventsLost)) : QJsonValue(QJsonValue::Null)}})
            .toJson(QJsonDocument::Compact).toStdString(); // 用正式封装写入终态元数据。
        m_writer.write({}, end);
    }
    const auto& written = m_writer.status(); // 工作线程实际刷盘并回读的前缀。
    const bool failed = !written.error.isEmpty(); // 失败后不跳写破损段之后的文件。
    if (final || failed)
    {
        m_writer.close();
    }
    const std::lock_guard lock(m_mutex); // 向界面发布，保留同时增加的丢失数。
    m_archive.verifiedSegments = written.verifiedSegments;
    m_archive.finished = written.finished;
    m_archive.error = written.error;
    if (failed)
    {
        m_archive.dropped += static_cast<quint64>(pending.size() - next + m_archiveQueue.size());
        m_archiveQueue.clear();
        m_acceptArchive = false;
    }
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

std::optional<SegmentSnapshot> LiveEtwCapture::preview(const QString& displayedSample, quint64 displayedRevision,
    bool keepExistingEvidence) const
{
    const std::lock_guard lock(m_mutex); // 在同一修订复制两个窗口，不借用回调缓冲。
    if (!m_ready.load() || (keepExistingEvidence && !m_snapshot.liveRevision) ||
        (displayedSample == m_snapshot.sampleId && displayedRevision == m_snapshot.liveRevision))
    {
        return std::nullopt;
    }
    auto snapshot = m_snapshot; // 保留当时实际的项目、采样和累计修订。
    snapshot.rows.reserve(static_cast<qsizetype>(m_processRows.size() + m_etwRows.size()));
    std::merge(m_processRows.cbegin(), m_processRows.cend(), m_etwRows.cbegin(), m_etwRows.cend(),
        std::back_inserter(snapshot.rows), [](const SegmentRow& left, const SegmentRow& right) {
            return left.sequence < right.sequence;
        });
    return snapshot;
}

LiveEtwReceipt LiveEtwCapture::recover()
{
    const bool stopped = m_controller.stopChecked(); // 原生所有者负责清退同一会话。
    flushArchive(stopped);
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
        state.callbackFailed || !stopped || state.tailDeliveryUnconfirmed ||
        (!state.providers.empty() && state.providers.front().status != ERROR_SUCCESS) ||
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
    result.evicted = m_evicted;
    result.hasRows = m_snapshot.liveRevision != 0;
    result.archive = m_archive;
    return result;
}
}
