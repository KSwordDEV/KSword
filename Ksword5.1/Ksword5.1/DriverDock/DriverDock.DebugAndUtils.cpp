#include "../UI/CodeEditorWidget.h"
#include "DriverDock.Internal.h"
#include "../UI/AsyncCleanupRegistry.h"

#include <QEvent>
#include <QTimer>
#include <QScrollBar>
#include <QStringList>

#include <condition_variable>
#include <functional>
#include <stdexcept>
#include <utility>

// 说明：由原聚合式实现迁移为独立 .cpp，成员函数实现保持原样。
using namespace ksword::driver_dock_internal;

bool DriverDock::DebugOutputBuffer::append(std::vector<DebugOutputLineRecord> records)
{
    if (records.empty()) return false;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (DebugOutputLineRecord& record : records)
    {
        record.sequence = m_nextSequence++;
        m_records.push_back(std::move(record));
        if (m_records.size() > 2000U) m_records.pop_front();
    }
    if (!m_visible || m_wakePending) return false;
    m_wakePending = true;
    return true;
}

void DriverDock::DebugOutputBuffer::setVisible(bool visible)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_visible = visible;
}

void DriverDock::DebugOutputBuffer::deliveryDropped(bool projectionWake)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (projectionWake) m_wakePending = false;
    m_deliveryDropped = true;
}

bool DriverDock::DebugOutputBuffer::takeDroppedDelivery()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return std::exchange(m_deliveryDropped, false);
}

DriverDock::DebugOutputSnapshot DriverDock::DebugOutputBuffer::snapshot(
    std::uint64_t afterSequence, bool force, bool clearWake)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (clearWake) m_wakePending = false;
    DebugOutputSnapshot result;
    result.lastSequence = m_nextSequence - 1U;
    result.visible = m_visible;
    if (!m_visible) return result;
    result.replace = force || afterSequence > result.lastSequence ||
        (!m_records.empty() && m_records.front().sequence > afterSequence &&
            m_records.front().sequence - afterSequence > 1U);
    for (const DebugOutputLineRecord& record : m_records)
    {
        if (result.replace || record.sequence > afterSequence) result.records.push_back(record);
    }
    return result;
}

std::uint64_t DriverDock::DebugOutputBuffer::clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_records.clear();
    return m_nextSequence - 1U;
}

void DriverDock::scheduleDebugOutputFlush()
{
    if (m_debugOutputFlushScheduled) return;
    m_debugOutputFlushScheduled = true;
    QTimer::singleShot(50, this, [this]() { m_debugOutputFlushScheduled = false; flushDebugOutputLines(); });
}

void DriverDock::enqueueDebugOutputLines(std::vector<DebugOutputLineRecord> records)
{
    if (!m_debugOutputBuffer->append(std::move(records))) return;
    // 与会话共用门禁合并正常唤醒；取消时只补投一次恢复，不递归重试。
    const auto source = m_debugOutputBuffer;
    const auto gateway = m_debugCaptureDispatcher;
    const auto wake = [this]() { scheduleDebugOutputFlush(); };
    try { gateway->post(wake, [source,gateway,wake]() {
        source->deliveryDropped(true);
        try { gateway->post(wake); } catch (...) {} // One recovery post without recursive cancellation.
    }); }
    catch (...) { source->deliveryDropped(true); try { gateway->post(wake); } catch (...) {} }
}

bool DriverDock::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == m_debugOutputEdit)
    {
        if (event->type() == QEvent::Show)
        {
            m_debugOutputBuffer->setVisible(true);
            // 首次绘制前补齐隐藏期数据；保留已排队唤醒，避免重复投递。
            flushDebugOutputLines(false);
            reconcileDebugOutputDelivery();
        }
        else if (event->type() == QEvent::Hide)
        {
            m_debugOutputBuffer->setVisible(false);
        }
    }
    return QWidget::eventFilter(watched, event);
}

// 此对象独立于 QWidget 生存。工作线程只捕获 session；回投只能经共享门禁执行。
struct DriverDock::DebugCaptureSession final : std::enable_shared_from_this<DebugCaptureSession>
{
    std::shared_ptr<DebugOutputBuffer> buffer;
    std::shared_ptr<ks::ui::AsyncUiDispatcher> dispatcher;
    std::function<void()> projectionWake;
    std::function<void()> stateChanged;
    ksword::ark::DriverClient driverClient;
    ksword::ark::DriverHandle driverHandle;
    std::atomic_bool stopRequested{ false };
    std::atomic_bool finished{ false };
    std::mutex waitMutex;
    std::condition_variable waitChanged;
    std::shared_ptr<ks::ui::AsyncCleanupRegistry::Lease> cleanupLease;
    bool stopRequired = false; // 仅工作线程读写。

    // 跨 DriverDock 销毁/重建也不能让新 START 与旧 STOP 竞争。
    static std::shared_ptr<std::mutex> captureGate()
    {
        static const auto gate = std::make_shared<std::mutex>();
        return gate;
    }
    const std::shared_ptr<std::mutex> gate = captureGate();

    void start()
    {
        // 退出冻结新工作前登记；弱回调只置停止标志，不等待驱动或形成引用环。
        const std::weak_ptr<DebugCaptureSession> weakSession(shared_from_this());
        cleanupLease = ks::ui::AsyncCleanupRegistry::global().acquire([weakSession]()
            {
                if (const auto session = weakSession.lock()) session->requestStop();
            });
        if (cleanupLease == nullptr) throw std::runtime_error("shutdown gate closed");
        std::thread([session = shared_from_this()]() { session->run(); }).detach();
    }

    void requestStop()
    {
        {
            // 与 wait 的谓词检查同锁，避免检查后、真正睡眠前丢失 notify。
            std::lock_guard<std::mutex> lock(waitMutex);
            stopRequested.store(true);
        }
        waitChanged.notify_all();
    }

    void waitForStop(std::chrono::milliseconds interval)
    {
        std::unique_lock<std::mutex> lock(waitMutex);
        waitChanged.wait_for(lock, interval, [this]() { return stopRequested.load(); });
    }

    void append(std::vector<DebugOutputLineRecord> records)
    {
        if (!buffer->append(std::move(records))) return;
        const auto source = buffer;
        const auto gateway = dispatcher;
        try { gateway->post(projectionWake, [source,gateway,wake=projectionWake]() {
            source->deliveryDropped(true);
            try { gateway->post(wake); } catch (...) {}
        }); }
        catch (...) { source->deliveryDropped(true); try { gateway->post(projectionWake); } catch (...) {} }
    }

    void postStateChanged() noexcept
    {
        const auto source = buffer;
        const auto gateway = dispatcher;
        try { gateway->post(stateChanged, [source,gateway,wake=stateChanged]() {
            source->deliveryDropped(false);
            try { gateway->post(wake); } catch (...) {}
        }); }
        catch (...) { source->deliveryDropped(false); try { gateway->post(stateChanged); } catch (...) {} }
    }

    void appendLocalizedDebugOutputLine(const QString& sourceText)
    {
        DebugOutputLineRecord record;
        record.timePrefix = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
        record.sourceText = sourceText;
        record.translateSourceText = true;
        append({ std::move(record) });
    }

    void run() noexcept
    {
        {
            std::unique_lock<std::mutex> lease(*gate);
            try
            {
                // 等旧会话清理期间停止时，不再打开设备或注册新回调。
                if (!stopRequested.load()) capture();
            }
            catch (...)
            {
                try
                {
                    appendLocalizedDebugOutputLine(QStringLiteral("读取 R0 调试输出失败：%1")
                        .arg(QString::number(ERROR_UNHANDLED_EXCEPTION)));
                }
                catch (...) {}
            }
            requestStop();
            postStateChanged();
            if (stopRequired)
            {
                // 不因宿主销毁或 drain 出错省略 STOP；只由本会话执行一次。
                bool stopped = false;
                try
                {
                    const auto result = driverClient.controlDebugOutput(
                        driverHandle, KSWORD_ARK_DEBUG_OUTPUT_ACTION_STOP);
                    stopped = result.io.ok;
                }
                catch (...) {}
                try
                {
                    appendLocalizedDebugOutputLine(stopped
                        ? QStringLiteral("R0 调试输出回调已停止。")
                        : QStringLiteral("捕获线程已退出，但 R0 回调注销返回失败。"));
                }
                catch (...) {}
                stopRequired = false;
            }
            driverHandle.reset();
        }
        // 只有 STOP 与句柄关闭之后才允许最终退出/下一次启动。
        cleanupLease.reset();
        finished.store(true);
        postStateChanged();
    }

    void capture()
    {
        driverHandle = driverClient.open();
        if (!driverHandle.isValid())
        {
            const unsigned long openError = ::GetLastError();
            appendLocalizedDebugOutputLine(
                QStringLiteral("启动失败：无法打开 KswordARK 控制设备（Win32=%1）。").arg(openError));
            return;
        }
        stopRequired = true; // START 已执行但客户端后处理抛异常时也必须尝试 STOP。
        const ksword::ark::DebugOutputControlResult startResult = driverClient.controlDebugOutput(
            driverHandle, KSWORD_ARK_DEBUG_OUTPUT_ACTION_START);
        if (!startResult.io.ok)
        {
            stopRequired = false;
            appendLocalizedDebugOutputLine(startResult.unsupported
                ? QStringLiteral("启动失败：当前 KswordARK 驱动版本不支持内核调试输出 IOCTL。")
                : QStringLiteral("启动失败：R0 调试输出回调注册失败：%1")
                    .arg(QString::fromStdString(startResult.io.message)));
            return;
        }
        appendLocalizedDebugOutputLine(
            QStringLiteral("R0 内核调试输出回调已启动，等待 DbgPrint/DbgPrintEx/KdPrintEx 消息..."));

        std::uint64_t nextSequence = 0;
        std::uint64_t reportedDroppedCount = 0;
        while (!stopRequested.load())
        {
            const ksword::ark::DebugOutputDrainResult drainResult = driverClient.drainDebugOutput(
                driverHandle, nextSequence, KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS);
            if (!drainResult.io.ok)
            {
                appendLocalizedDebugOutputLine(QStringLiteral("读取 R0 调试输出失败：%1")
                    .arg(QString::fromStdString(drainResult.io.message)));
                break;
            }
            nextSequence = drainResult.nextSequence;
            if ((drainResult.responseFlags & KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_OVERFLOW) != 0U &&
                drainResult.lostBeforeFirst != 0U)
            {
                appendLocalizedDebugOutputLine(
                    QStringLiteral("警告：读取游标落后，已有 %1 条内核调试消息被环形缓冲区覆盖。")
                        .arg(static_cast<qulonglong>(drainResult.lostBeforeFirst)));
            }
            if (drainResult.droppedCount > reportedDroppedCount)
            {
                const qulonglong droppedDelta = static_cast<qulonglong>(
                    drainResult.droppedCount - reportedDroppedCount);
                reportedDroppedCount = drainResult.droppedCount;
                appendLocalizedDebugOutputLine(
                    QStringLiteral("警告：高 IRQL 并发写入期间丢弃了 %1 条内核调试消息。")
                        .arg(droppedDelta));
            }
            std::vector<DebugOutputLineRecord> outputLines;
            outputLines.reserve(drainResult.records.size());
            const QString timePrefix = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
            for (const ksword::ark::DebugOutputRecord& record : drainResult.records)
            {
                QString messageText = QString::fromUtf8(
                    record.text.data(), static_cast<int>(record.text.size())).trimmed();
                if (messageText.isEmpty()) continue;
                const QString componentText = QString::number(record.componentId, 16)
                    .toUpper().rightJustified(8, QLatin1Char('0'));
                const QString levelText = QString::number(record.level, 16)
                    .toUpper().rightJustified(8, QLatin1Char('0'));
                DebugOutputLineRecord line;
                line.timePrefix = timePrefix;
                line.sourceText = QStringLiteral("[Seq=%1][Component=0x%2][Level=0x%3] %4")
                    .arg(static_cast<qulonglong>(record.sequence))
                    .arg(componentText, levelText, messageText);
                if ((record.flags & KSWORD_ARK_DEBUG_OUTPUT_RECORD_FLAG_TEXT_TRUNCATED) != 0U)
                    line.localizedSuffixSource = QStringLiteral(" [已截断]");
                outputLines.push_back(std::move(line));
            }
            append(std::move(outputLines));
            // 有更多记录时立即继续读取；空闲等待可被停止请求立即唤醒。
            if ((drainResult.responseFlags & KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_MORE_AVAILABLE) == 0U)
                waitForStop(std::chrono::milliseconds(100));
        }
    }
};

void DriverDock::reconcileDebugOutputDelivery()
{
    if (!m_debugOutputBuffer->takeDroppedDelivery()) return;
    if (m_debugCaptureSession && m_debugCaptureSession->finished.load()) m_debugCaptureSession.reset();
    updateDebugCaptureButtonState();
    flushDebugOutputLines(false); // Does not steal a newer accepted wake that arrived after cancellation.
}

void DriverDock::startDebugOutputCapture()
{
    reconcileDebugOutputDelivery();
    if (m_debugCaptureSession != nullptr)
    {
        appendLocalizedDebugOutputLine(QStringLiteral("捕获线程已在运行。"));
        return;
    }
    appendLocalizedDebugOutputLine(QStringLiteral("正在注册 R0 内核调试输出回调..."));
    try
    {
        auto session = std::make_shared<DebugCaptureSession>();
        session->buffer = m_debugOutputBuffer;
        session->dispatcher = m_debugCaptureDispatcher;
        session->projectionWake = [this]() { scheduleDebugOutputFlush(); };
        const std::weak_ptr<DebugCaptureSession> weakSession(session);
        session->stateChanged = [this, weakSession]()
        {
            const auto completed = weakSession.lock();
            if (completed == nullptr || completed != m_debugCaptureSession) return;
            if (completed->finished.load()) m_debugCaptureSession.reset();
            updateDebugCaptureButtonState();
        };
        m_debugCaptureSession = std::move(session);
        m_debugCaptureSession->start();
    }
    catch (...)
    {
        m_debugCaptureSession.reset();
        appendLocalizedDebugOutputLine(QStringLiteral("启动失败：无法创建后台线程。"));
    }
    updateDebugCaptureButtonState();
}

void DriverDock::stopDebugOutputCapture()
{
    reconcileDebugOutputDelivery();
    if (m_debugCaptureSession != nullptr) m_debugCaptureSession->requestStop();
    updateDebugCaptureButtonState();
}

void DriverDock::releaseDebugOutputCapture()
{
    if (m_debugCaptureSession != nullptr) m_debugCaptureSession->requestStop();
    m_debugCaptureSession.reset();
}

void DriverDock::updateDebugCaptureButtonState()
{
    const bool active = m_debugCaptureSession != nullptr;
    const bool stopping = active && m_debugCaptureSession->stopRequested.load();
    if (m_startCaptureButton != nullptr) m_startCaptureButton->setEnabled(!active);
    if (m_stopCaptureButton != nullptr) m_stopCaptureButton->setEnabled(active && !stopping);
    if (m_debugCaptureStatusLabel != nullptr)
    {
        m_debugCaptureStatusLabel->setText(stopping
            ? driverText("driver.service.state.stop_pending", QStringLiteral("停止中"))
            : active
                ? driverText("driver.debug.status.running", QStringLiteral("状态：捕获运行中"))
                : driverText("driver.debug.status.not_started", QStringLiteral("状态：未启动")));
    }
}

void DriverDock::appendOperateLogLine(const QString& logText)
{
    if (m_operateLogOutput == nullptr)
    {
        return;
    }

    const QString timePrefix = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    m_operateLogOutput->appendRawText(QStringLiteral("[%1] %2").arg(timePrefix, logText));
}

void DriverDock::appendDebugOutputLine(
    const QString& debugText,
    const QString& localizedSuffixSource)
{
    DebugOutputLineRecord record;
    record.timePrefix = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    record.sourceText = debugText;
    record.localizedSuffixSource = localizedSuffixSource;
    enqueueDebugOutputLines({ std::move(record) });
}

void DriverDock::appendLocalizedDebugOutputLine(const QString& sourceText)
{
    DebugOutputLineRecord record;
    record.timePrefix = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    record.sourceText = sourceText;
    record.translateSourceText = true;
    enqueueDebugOutputLines({ std::move(record) });
}

void DriverDock::flushDebugOutputLines(bool clearWake)
{
    const DebugOutputSnapshot snapshot = m_debugOutputBuffer->snapshot(
        m_debugOutputRenderedSequence, m_debugOutputTranslationDirty, clearWake);
    if (!snapshot.visible || m_debugOutputEdit == nullptr) return;
    if (!snapshot.replace && snapshot.records.empty()) return;
    QStringList renderedLines;
    renderedLines.reserve(static_cast<int>(snapshot.records.size()));
    for (const DebugOutputLineRecord& record : snapshot.records)
    {
        const QString lineText = record.translateSourceText
            ? ks::i18n::displayText(record.sourceText) : record.sourceText;
        renderedLines.push_back(QStringLiteral("[%1] %2%3")
            .arg(record.timePrefix, lineText, ks::i18n::displayText(record.localizedSuffixSource)));
    }
    const QString rendered = renderedLines.join(QLatin1Char('\n'));
    const QPointer<DriverDock> guardThis(this);
    if (snapshot.replace)
        m_debugOutputEdit->replaceRawText(rendered);
    else
        m_debugOutputEdit->appendRawText(rendered);
    if (guardThis == nullptr) return;
    m_debugOutputRenderedSequence = snapshot.lastSequence;
    m_debugOutputTranslationDirty = false;
}

void DriverDock::refreshDebugOutputLines()
{
    reconcileDebugOutputDelivery();
    m_debugOutputTranslationDirty = true;
    flushDebugOutputLines(false);
}

void DriverDock::clearDebugOutputLines()
{
    reconcileDebugOutputDelivery();
    m_debugOutputRenderedSequence = m_debugOutputBuffer->clear();
    m_debugOutputTranslationDirty = false;
    if (m_debugOutputEdit != nullptr) m_debugOutputEdit->clear();
}

bool DriverDock::queryDriverServiceRecords(
    std::vector<DriverServiceRecord>& recordListOut,
    std::string* errorTextOut)
{
    // DriverDock now delegates raw SCM enumeration/config reads to ks::service:
    // - input: no UI widgets are passed into the reusable layer;
    // - processing: this wrapper only converts std::wstring records into QString rows;
    // - return: true when SCM enumeration completed, false with UTF-8 error text.
    recordListOut.clear();
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }

    std::vector<ks::service::ServiceRecord> serviceRecordList;
    if (!ks::service::EnumerateServiceRecords(
        SERVICE_DRIVER,
        SERVICE_STATE_ALL,
        &serviceRecordList,
        errorTextOut))
    {
        return false;
    }

    recordListOut.reserve(serviceRecordList.size());
    for (const ks::service::ServiceRecord& serviceRecord : serviceRecordList)
    {
        DriverServiceRecord driverRecord;
        driverRecord.serviceName = QString::fromStdWString(serviceRecord.serviceName);
        driverRecord.displayName = QString::fromStdWString(serviceRecord.displayName);
        driverRecord.currentState = serviceRecord.status.currentState;
        driverRecord.serviceType = serviceRecord.status.serviceType;
        if (serviceRecord.hasConfig)
        {
            driverRecord.startType = serviceRecord.config.startType;
            driverRecord.errorControl = serviceRecord.config.errorControl;
            driverRecord.binaryPath = QString::fromStdWString(serviceRecord.config.binaryPath);
            if (driverRecord.displayName.trimmed().isEmpty())
            {
                driverRecord.displayName = QString::fromStdWString(serviceRecord.config.displayName);
            }
        }
        driverRecord.description = QString::fromStdWString(serviceRecord.description);
        recordListOut.push_back(std::move(driverRecord));
    }

    std::sort(
        recordListOut.begin(),
        recordListOut.end(),
        [](const DriverServiceRecord& left, const DriverServiceRecord& right)
        {
            return left.serviceName.compare(right.serviceName, Qt::CaseInsensitive) < 0;
        });
    return true;
}

bool DriverDock::queryLoadedKernelModuleRecords(
    std::vector<LoadedKernelModuleRecord>& recordListOut,
    std::string* errorTextOut)
{
    recordListOut.clear();
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }

    // 动态扩容驱动基址数组，避免在驱动数量较多时被固定 1024 截断。
    std::vector<LPVOID> moduleBaseList(1024, nullptr);
    DWORD bytesNeeded = 0;
    while (true)
    {
        if (!::EnumDeviceDrivers(
            moduleBaseList.data(),
            static_cast<DWORD>(moduleBaseList.size() * sizeof(LPVOID)),
            &bytesNeeded))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("EnumDeviceDrivers failed: %1")
                    .arg(formatWin32ErrorText(::GetLastError()))
                    .toStdString();
            }
            return false;
        }

        const std::size_t currentCapacityBytes = moduleBaseList.size() * sizeof(LPVOID);
        if (bytesNeeded <= currentCapacityBytes)
        {
            break;
        }

        const std::size_t requiredCount =
            (static_cast<std::size_t>(bytesNeeded) + sizeof(LPVOID) - 1) / sizeof(LPVOID);
        moduleBaseList.assign(requiredCount + 128, nullptr);
    }

    const std::size_t moduleCount = static_cast<std::size_t>(bytesNeeded / sizeof(LPVOID));
    recordListOut.reserve(moduleCount);
    for (std::size_t index = 0; index < moduleCount; ++index)
    {
        LPVOID moduleBase = moduleBaseList[index];
        if (moduleBase == nullptr)
        {
            continue;
        }

        std::array<wchar_t, MAX_PATH> moduleNameBuffer{};
        std::array<wchar_t, 1024> modulePathBuffer{};
        const DWORD nameLength = ::GetDeviceDriverBaseNameW(
            moduleBase,
            moduleNameBuffer.data(),
            static_cast<DWORD>(moduleNameBuffer.size()));
        const DWORD pathLength = ::GetDeviceDriverFileNameW(
            moduleBase,
            modulePathBuffer.data(),
            static_cast<DWORD>(modulePathBuffer.size()));

        LoadedKernelModuleRecord moduleRecord;
        moduleRecord.moduleName = (nameLength == 0)
            ? QStringLiteral("<unknown>")
            : QString::fromWCharArray(moduleNameBuffer.data());
        moduleRecord.imagePath = (pathLength == 0)
            ? QStringLiteral("<unknown>")
            : QString::fromWCharArray(modulePathBuffer.data());
        moduleRecord.baseAddress = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(moduleBase));
        recordListOut.push_back(std::move(moduleRecord));
    }

    std::sort(
        recordListOut.begin(),
        recordListOut.end(),
        [](const LoadedKernelModuleRecord& left, const LoadedKernelModuleRecord& right)
        {
            return left.moduleName.compare(right.moduleName, Qt::CaseInsensitive) < 0;
        });
    return true;
}

QString DriverDock::serviceStateToText(const std::uint32_t stateValue)
{
    switch (stateValue)
    {
    case SERVICE_STOPPED:
        return driverText("driver.service.state.stopped", QStringLiteral("已停止"));
    case SERVICE_START_PENDING:
        return driverText("driver.service.state.start_pending", QStringLiteral("启动中"));
    case SERVICE_STOP_PENDING:
        return driverText("driver.service.state.stop_pending", QStringLiteral("停止中"));
    case SERVICE_RUNNING:
        return driverText("driver.service.state.running", QStringLiteral("运行中"));
    case SERVICE_CONTINUE_PENDING:
        return driverText("driver.service.state.continue_pending", QStringLiteral("继续中"));
    case SERVICE_PAUSE_PENDING:
        return driverText("driver.service.state.pause_pending", QStringLiteral("暂停中"));
    case SERVICE_PAUSED:
        return driverText("driver.service.state.paused", QStringLiteral("已暂停"));
    default:
        return driverText("driver.service.state.unknown", QStringLiteral("未知状态(%1)"))
            .arg(stateValue);
    }
}

QString DriverDock::startTypeToText(const std::uint32_t startTypeValue)
{
    switch (startTypeValue)
    {
    case SERVICE_BOOT_START:   return QStringLiteral("BOOT");
    case SERVICE_SYSTEM_START: return QStringLiteral("SYSTEM");
    case SERVICE_AUTO_START:   return QStringLiteral("AUTO");
    case SERVICE_DEMAND_START: return QStringLiteral("DEMAND");
    case SERVICE_DISABLED:     return QStringLiteral("DISABLED");
    default:                   return QStringLiteral("UNKNOWN(%1)").arg(startTypeValue);
    }
}

QString DriverDock::errorControlToText(const std::uint32_t errorControlValue)
{
    switch (errorControlValue)
    {
    case SERVICE_ERROR_IGNORE:   return QStringLiteral("IGNORE");
    case SERVICE_ERROR_NORMAL:   return QStringLiteral("NORMAL");
    case SERVICE_ERROR_SEVERE:   return QStringLiteral("SEVERE");
    case SERVICE_ERROR_CRITICAL: return QStringLiteral("CRITICAL");
    default:                     return QStringLiteral("UNKNOWN(%1)").arg(errorControlValue);
    }
}

QString DriverDock::formatWin32ErrorText(const std::uint32_t win32ErrorCode)
{
    // Keep DriverDock formatting as a UI adapter only:
    // - input: raw Win32 error code;
    // - processing: ks::service owns FormatMessageW and UTF-8 formatting;
    // - return: QString text suitable for existing log lines.
    return QString::fromUtf8(ks::service::FormatWin32ErrorText(win32ErrorCode).c_str());
}

QString DriverDock::trimQuotedText(const QString& textValue)
{
    QString normalizedText = textValue.trimmed();
    if (normalizedText.startsWith('"') && normalizedText.endsWith('"') && normalizedText.size() >= 2)
    {
        normalizedText = normalizedText.mid(1, normalizedText.size() - 2);
    }
    return normalizedText.trimmed();
}
