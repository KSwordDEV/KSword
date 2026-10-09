#include "../UI/CodeEditorWidget.h"
#include "DriverDock.Internal.h"

#include <QScrollBar>
#include <QStringList>

// 说明：由原聚合式实现迁移为独立 .cpp，成员函数实现保持原样。
using namespace ksword::driver_dock_internal;

void DriverDock::startDebugOutputCapture()
{
    if (m_kernelDebugCaptureRunning.exchange(true))
    {
        appendLocalizedDebugOutputLine(QStringLiteral("捕获线程已在运行。"));
        return;
    }

    // 上一轮线程可能已自行退出；重新启动前必须回收 joinable 对象。
    if (m_kernelDebugCaptureThread != nullptr && m_kernelDebugCaptureThread->joinable())
    {
        m_kernelDebugCaptureThread->join();
    }
    m_kernelDebugCaptureThread.reset();

    appendLocalizedDebugOutputLine(QStringLiteral("正在注册 R0 内核调试输出回调..."));
    try
    {
        m_kernelDebugCaptureThread = std::make_unique<std::thread>([this]()
            {
                runKernelDebugOutputCaptureLoop();
            });
    }
    catch (...)
    {
        m_kernelDebugCaptureRunning.store(false);
        m_kernelDebugCaptureThread.reset();
        appendLocalizedDebugOutputLine(QStringLiteral("启动失败：无法创建后台线程。"));
    }

    updateDebugCaptureButtonState();
}

void DriverDock::stopDebugOutputCapture()
{
    m_kernelDebugCaptureRunning.store(false);
    if (m_kernelDebugCaptureThread != nullptr && m_kernelDebugCaptureThread->joinable())
    {
        m_kernelDebugCaptureThread->join();
    }
    m_kernelDebugCaptureThread.reset();
    updateDebugCaptureButtonState();
}

void DriverDock::runKernelDebugOutputCaptureLoop()
{
    // guardThis 用途：回投 UI 更新时判空，避免析构后访问悬空对象。
    QPointer<DriverDock> guardThis(this);
    ksword::ark::DriverClient driverClient;
    ksword::ark::DriverHandle driverHandle = driverClient.open();
    if (!driverHandle.isValid())
    {
        const unsigned long openError = ::GetLastError();
        m_kernelDebugCaptureRunning.store(false);
        QMetaObject::invokeMethod(this, [guardThis, openError]()
            {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->appendLocalizedDebugOutputLine(
                    QStringLiteral("启动失败：无法打开 KswordARK 控制设备（Win32=%1）。")
                        .arg(openError));
                guardThis->updateDebugCaptureButtonState();
            }, Qt::QueuedConnection);
        return;
    }

    const ksword::ark::DebugOutputControlResult startResult = driverClient.controlDebugOutput(
        driverHandle,
        KSWORD_ARK_DEBUG_OUTPUT_ACTION_START);
    if (!startResult.io.ok)
    {
        const QString errorDetail = QString::fromStdString(startResult.io.message);
        const bool unsupported = startResult.unsupported;
        m_kernelDebugCaptureRunning.store(false);
        QMetaObject::invokeMethod(this, [guardThis, errorDetail, unsupported]()
            {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->appendLocalizedDebugOutputLine(
                    unsupported
                        ? QStringLiteral("启动失败：当前 KswordARK 驱动版本不支持内核调试输出 IOCTL。")
                        : QStringLiteral("启动失败：R0 调试输出回调注册失败：%1")
                            .arg(errorDetail));
                guardThis->updateDebugCaptureButtonState();
            }, Qt::QueuedConnection);
        return;
    }

    QMetaObject::invokeMethod(this, [guardThis]()
        {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->appendLocalizedDebugOutputLine(
                QStringLiteral("R0 内核调试输出回调已启动，等待 DbgPrint/DbgPrintEx/KdPrintEx 消息..."));
            guardThis->updateDebugCaptureButtonState();
        }, Qt::QueuedConnection);

    std::uint64_t nextSequence = 0;
    std::uint64_t reportedDroppedCount = 0;
    while (m_kernelDebugCaptureRunning.load())
    {
        const ksword::ark::DebugOutputDrainResult drainResult = driverClient.drainDebugOutput(
            driverHandle,
            nextSequence,
            KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS);
        if (!drainResult.io.ok)
        {
            const QString errorDetail = QString::fromStdString(drainResult.io.message);
            QMetaObject::invokeMethod(this, [guardThis, errorDetail]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->appendLocalizedDebugOutputLine(
                        QStringLiteral("读取 R0 调试输出失败：%1")
                        .arg(errorDetail));
                }, Qt::QueuedConnection);
            break;
        }

        nextSequence = drainResult.nextSequence;
        if ((drainResult.responseFlags & KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_OVERFLOW) != 0U &&
            drainResult.lostBeforeFirst != 0U)
        {
            const qulonglong lostCount = static_cast<qulonglong>(drainResult.lostBeforeFirst);
            QMetaObject::invokeMethod(this, [guardThis, lostCount]()
                {
                    if (guardThis != nullptr)
                    {
                        guardThis->appendLocalizedDebugOutputLine(
                            QStringLiteral("警告：读取游标落后，已有 %1 条内核调试消息被环形缓冲区覆盖。")
                            .arg(lostCount));
                    }
                }, Qt::QueuedConnection);
        }
        if (drainResult.droppedCount > reportedDroppedCount)
        {
            const qulonglong droppedDelta = static_cast<qulonglong>(
                drainResult.droppedCount - reportedDroppedCount);
            reportedDroppedCount = drainResult.droppedCount;
            QMetaObject::invokeMethod(this, [guardThis, droppedDelta]()
                {
                    if (guardThis != nullptr)
                    {
                        guardThis->appendLocalizedDebugOutputLine(
                            QStringLiteral("警告：高 IRQL 并发写入期间丢弃了 %1 条内核调试消息。")
                            .arg(droppedDelta));
                    }
                }, Qt::QueuedConnection);
        }

        for (const ksword::ark::DebugOutputRecord& record : drainResult.records)
        {
            QString messageText = QString::fromUtf8(
                record.text.data(),
                static_cast<int>(record.text.size())).trimmed();
            if (messageText.isEmpty())
            {
                continue;
            }
            const bool textTruncated =
                (record.flags & KSWORD_ARK_DEBUG_OUTPUT_RECORD_FLAG_TEXT_TRUNCATED) != 0U;
            const QString componentText = QString::number(record.componentId, 16)
                .toUpper()
                .rightJustified(8, QLatin1Char('0'));
            const QString levelText = QString::number(record.level, 16)
                .toUpper()
                .rightJustified(8, QLatin1Char('0'));
            const QString outputLine = QStringLiteral("[Seq=%1][Component=0x%2][Level=0x%3] %4")
                .arg(static_cast<qulonglong>(record.sequence))
                .arg(componentText, levelText, messageText);
            QMetaObject::invokeMethod(this, [guardThis, outputLine, textTruncated]()
                {
                    if (guardThis != nullptr)
                    {
                        guardThis->appendDebugOutputLine(
                            outputLine,
                            textTruncated ? QStringLiteral(" [已截断]") : QString());
                    }
                }, Qt::QueuedConnection);
        }

        // 有更多记录时立即继续读取，否则短暂休眠以降低空轮询开销。
        if ((drainResult.responseFlags & KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_MORE_AVAILABLE) == 0U)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    const ksword::ark::DebugOutputControlResult stopResult = driverClient.controlDebugOutput(
        driverHandle,
        KSWORD_ARK_DEBUG_OUTPUT_ACTION_STOP);
    m_kernelDebugCaptureRunning.store(false);
    QMetaObject::invokeMethod(this, [guardThis, stopOk = stopResult.io.ok]()
        {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->appendLocalizedDebugOutputLine(
                stopOk
                    ? QStringLiteral("R0 调试输出回调已停止。")
                    : QStringLiteral("捕获线程已退出，但 R0 回调注销返回失败。"));
            guardThis->updateDebugCaptureButtonState();
        }, Qt::QueuedConnection);
}

void DriverDock::updateDebugCaptureButtonState()
{
    const bool running = m_kernelDebugCaptureRunning.load();
    if (m_startCaptureButton != nullptr)
    {
        m_startCaptureButton->setEnabled(!running);
    }
    if (m_stopCaptureButton != nullptr)
    {
        m_stopCaptureButton->setEnabled(running);
    }
    if (m_debugCaptureStatusLabel != nullptr)
    {
        m_debugCaptureStatusLabel->setText(
            running
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
    if (m_debugOutputEdit == nullptr)
    {
        return;
    }

    constexpr std::size_t kMaximumDebugOutputLines = 2000U;
    if (m_debugOutputLines.size() >= kMaximumDebugOutputLines)
    {
        m_debugOutputLines.erase(m_debugOutputLines.begin());
    }

    DebugOutputLineRecord record;
    record.timePrefix = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    record.sourceText = debugText;
    record.localizedSuffixSource = localizedSuffixSource;
    record.translateSourceText = false;
    m_debugOutputLines.push_back(record);

    m_debugOutputEdit->appendRawText(QStringLiteral("[%1] %2%3")
        .arg(record.timePrefix, record.sourceText, ks::i18n::displayText(record.localizedSuffixSource)));
}

void DriverDock::appendLocalizedDebugOutputLine(const QString& sourceText)
{
    if (m_debugOutputEdit == nullptr)
    {
        return;
    }

    constexpr std::size_t kMaximumDebugOutputLines = 2000U;
    if (m_debugOutputLines.size() >= kMaximumDebugOutputLines)
    {
        m_debugOutputLines.erase(m_debugOutputLines.begin());
    }

    DebugOutputLineRecord record;
    record.timePrefix = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    record.sourceText = sourceText;
    record.translateSourceText = true;
    m_debugOutputLines.push_back(record);
    m_debugOutputEdit->appendRawText(QStringLiteral("[%1] %2")
        .arg(record.timePrefix, ks::i18n::displayText(record.sourceText)));
}

void DriverDock::refreshDebugOutputLines()
{
    if (m_debugOutputEdit == nullptr)
    {
        return;
    }

    QStringList renderedLines;
    renderedLines.reserve(static_cast<int>(m_debugOutputLines.size()));
    for (const DebugOutputLineRecord& record : m_debugOutputLines)
    {
        const QString lineText = record.translateSourceText
            ? ks::i18n::displayText(record.sourceText)
            : record.sourceText;
        renderedLines.push_back(QStringLiteral("[%1] %2%3")
            .arg(
                record.timePrefix,
                lineText,
                ks::i18n::displayText(record.localizedSuffixSource)));
    }
    // 重建本地化提示时保留阅读位置，原来跟随尾部才继续跟随。
    m_debugOutputEdit->replaceRawText(renderedLines.join(QLatin1Char('\n')));
}

void DriverDock::clearDebugOutputLines()
{
    m_debugOutputLines.clear();
    if (m_debugOutputEdit != nullptr)
    {
        m_debugOutputEdit->clear();
    }
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

QString DriverDock::normalizeDriverBinaryPath(const QString& pathText)
{
    QString normalizedPath = pathText.trimmed();
    if (normalizedPath.isEmpty())
    {
        return normalizedPath;
    }

    const bool quoted =
        normalizedPath.startsWith('"') &&
        normalizedPath.endsWith('"') &&
        normalizedPath.size() >= 2;
    if (!quoted && normalizedPath.contains(' '))
    {
        normalizedPath = QStringLiteral("\"%1\"").arg(normalizedPath);
    }
    return normalizedPath;
}
