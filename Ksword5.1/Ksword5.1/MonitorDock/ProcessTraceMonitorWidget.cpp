#include "ProcessTraceMonitorWidget.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ThemeStatusRole.h"

// ============================================================
// ProcessTraceMonitorWidget.cpp
// 作用：
// 1) 承载进程定向监控控件的公共样式与基础工具函数；
// 2) 提供构造、析构与状态文本刷新等轻量逻辑；
// 3) 避免把 UI、动作、采集实现继续堆进同一个大文件。
// ============================================================

#include "../theme.h"

#include <QDateTime>
#include <QEvent>
#include <QLabel>
#include <QList>
#include <QPushButton>
#include <QRegularExpression>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QToolButton>
#include <QTimer>
#include <QWidget>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Objbase.h>
#include <evntcons.h>
#include <tdh.h>

#pragma comment(lib, "Tdh.lib")

ProcessTraceMonitorWidget::ProcessTraceMonitorWidget(QWidget* parent)
    : QWidget(parent)
    , m_uiDispatcher(std::make_shared<ks::ui::AsyncUiDispatcher>(this))
{
    // initEvent：构造阶段统一复用同一个日志事件，便于串起整个初始化链路。
    kLogEvent initEvent;
    info << initEvent << "[ProcessTraceMonitorWidget] 开始初始化进程定向监控页。" << eol;

    initializeUi();
    initializeConnections();
    refreshAvailableProcessListAsync();
    updateActionState();
    updateStatusLabel();

    info << initEvent << "[ProcessTraceMonitorWidget] 进程定向监控页初始化完成。" << eol;
}

ProcessTraceMonitorWidget::~ProcessTraceMonitorWidget()
{
    m_uiDispatcher->close();
    // 析构阶段同步停止后台线程，避免对象释放后回调仍访问成员。
    stopMonitoringInternal(true);

    if (m_uiUpdateTimer != nullptr)
    {
        m_uiUpdateTimer->stop();
    }

    if (m_eventFilterDebounceTimer != nullptr)
    {
        m_eventFilterDebounceTimer->stop();
    }

    if (m_runtimeRefreshTimer != nullptr)
    {
        m_runtimeRefreshTimer->stop();
    }

    kLogEvent destroyEvent;
    info << destroyEvent << "[ProcessTraceMonitorWidget] 进程定向监控页已析构。" << eol;
}

bool ProcessTraceMonitorWidget::event(QEvent* eventPointer)
{
    // handled：
    // - 先保留 QWidget 原始事件处理结果，避免主题刷新逻辑吞掉其它输入/布局事件；
    // - 后续只在样式相关事件上补刷 Collapse 动态样式。
    const bool handled = QWidget::event(eventPointer);
    if (eventPointer != nullptr
        && (eventPointer->type() == QEvent::PaletteChange
            || eventPointer->type() == QEvent::ApplicationPaletteChange
            || eventPointer->type() == QEvent::StyleChange))
    {
        refreshCollapseTheme(this);
    }
    return handled;
}

QString ProcessTraceMonitorWidget::blueButtonStyle()
{
    return KswordTheme::ThemedButtonStyle();
}

QString ProcessTraceMonitorWidget::blueInputStyle()
{
    return QStringLiteral(
        "QLineEdit{border:1px solid %2;border-radius:5px;background:%3;color:%4;padding:2px 8px;}"
        "QTableWidget{border:1px solid %2;border-radius:3px;background:transparent;background-color:transparent;color:%4;padding:2px 6px;gridline-color:%2;alternate-background-color:transparent;}"
        "QTableWidget::viewport{background:transparent;background-color:transparent;}"
        "QLineEdit:focus{border:1px solid %1;}")
        .arg(KswordTheme::PrimaryBlueHex)
        .arg(KswordTheme::BorderHex())
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::TextPrimaryHex())
        + KswordTheme::ThemedComboBoxStyle();
}

QString ProcessTraceMonitorWidget::blueHeaderStyle()
{
    return QStringLiteral(
        "QHeaderView::section{color:%1;background:%2;border:0;border-bottom:1px solid %3;padding:4px 8px;font-weight:600;}")
        .arg(KswordTheme::TextPrimaryHex())
        .arg(KswordTheme::SurfaceAltHex())
        .arg(KswordTheme::BorderHex());
}

QString ProcessTraceMonitorWidget::collapsePanelStyle()
{
    // 样式复用 MonitorDock 已有独立 Collapse 约定：
    // - 外层使用 kswordCollapsePanel 标记，显示统一边框和圆角；
    // - 内容宿主使用 kswordCollapseContent 标记，避免嵌套区域重复描边。
    return QStringLiteral(
        "QWidget[kswordCollapsePanel=\"true\"]{"
        "  background:%1;"
        "  color:%2;"
        "  border:1px solid %3;"
        "  border-radius:5px;"
        "}"
        "QWidget[kswordCollapseContent=\"true\"]{"
        "  background:transparent;"
        "  background-color:transparent;"
        "  color:%2;"
        "  border:none;"
        "}")
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::TextPrimaryHex())
        .arg(KswordTheme::BorderHex());
}

QString ProcessTraceMonitorWidget::collapseHeaderButtonStyle()
{
    // 纯色主题只接管颜色；保留本页按钮尺寸和业务选中状态。
    return ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Neutral)
        + QStringLiteral("QToolButton{border-radius:5px;padding:5px 8px;font-weight:600;text-align:left;}");

}

void ProcessTraceMonitorWidget::refreshCollapseTheme(QWidget* rootWidget)
{
    // 空根直接返回，便于 event() 在极早期初始化阶段安全调用。
    if (rootWidget == nullptr)
    {
        return;
    }

    // 面板样式按属性刷新：
    // - palette()/主题函数值会随深浅主题改变；
    // - 重新 setStyleSheet 可强制 Qt 重新解析动态颜色。
    const QList<QWidget*> widgetList = rootWidget->findChildren<QWidget*>();
    for (QWidget* widgetPointer : widgetList)
    {
        if (widgetPointer == nullptr)
        {
            continue;
        }

        if (widgetPointer->property("kswordCollapsePanel").toString() == QStringLiteral("true")
            || widgetPointer->property("kswordCollapseContent").toString() == QStringLiteral("true"))
        {
            widgetPointer->setStyleSheet(collapsePanelStyle());
        }
    }

    // 头部按钮单独刷新：
    // - 只匹配折叠段外层下的 QToolButton，避免误改普通工具按钮；
    // - 返回值为空，本函数只负责主题同步副作用。
    const QList<QToolButton*> headerButtonList = rootWidget->findChildren<QToolButton*>();
    for (QToolButton* buttonPointer : headerButtonList)
    {
        if (buttonPointer != nullptr
            && buttonPointer->parentWidget() != nullptr
            && buttonPointer->parentWidget()->property("kswordCollapsePanel").toString() == QStringLiteral("true"))
        {
            buttonPointer->setStyleSheet(collapseHeaderButtonStyle());
        }
    }
}

QString ProcessTraceMonitorWidget::providerTypeFromName(const QString& providerNameText)
{
    const QString nameText = providerNameText.trimmed();
    if (nameText.contains(QStringLiteral("Kernel-Process"), Qt::CaseInsensitive))
    {
        return QStringLiteral("进程");
    }
    if (nameText.contains(QStringLiteral("Kernel-Thread"), Qt::CaseInsensitive))
    {
        return QStringLiteral("线程");
    }
    if (nameText.contains(QStringLiteral("Kernel-Image"), Qt::CaseInsensitive))
    {
        return QStringLiteral("镜像");
    }
    if (nameText.contains(QStringLiteral("Kernel-File"), Qt::CaseInsensitive))
    {
        return QStringLiteral("文件");
    }
    if (nameText.contains(QStringLiteral("Kernel-Registry"), Qt::CaseInsensitive))
    {
        return QStringLiteral("注册表");
    }
    if (nameText.contains(QStringLiteral("DNS-Client"), Qt::CaseInsensitive))
    {
        return QStringLiteral("DNS");
    }
    if (nameText.contains(QStringLiteral("TCPIP"), Qt::CaseInsensitive)
        || nameText.contains(QStringLiteral("AFD"), Qt::CaseInsensitive))
    {
        return QStringLiteral("网络");
    }
    if (nameText.contains(QStringLiteral("PowerShell"), Qt::CaseInsensitive))
    {
        return QStringLiteral("PowerShell");
    }
    if (nameText.contains(QStringLiteral("WMI-Activity"), Qt::CaseInsensitive))
    {
        return QStringLiteral("WMI");
    }
    if (nameText.contains(QStringLiteral("TaskScheduler"), Qt::CaseInsensitive))
    {
        return QStringLiteral("计划任务");
    }
    if (nameText.contains(QStringLiteral("Security-Auditing"), Qt::CaseInsensitive))
    {
        return QStringLiteral("安全审计");
    }
    if (nameText.contains(QStringLiteral("Defender"), Qt::CaseInsensitive))
    {
        return QStringLiteral("Defender");
    }
    return QStringLiteral("其他");
}

QString ProcessTraceMonitorWidget::now100nsText()
{
    return QString::number(static_cast<qulonglong>(currentSystemTime100ns()));
}

std::uint64_t ProcessTraceMonitorWidget::currentSystemTime100ns()
{
    FILETIME fileTimeValue{};
    ::GetSystemTimeAsFileTime(&fileTimeValue);

    ULARGE_INTEGER largeValue{};
    largeValue.LowPart = fileTimeValue.dwLowDateTime;
    largeValue.HighPart = fileTimeValue.dwHighDateTime;
    return static_cast<std::uint64_t>(largeValue.QuadPart);
}

QString ProcessTraceMonitorWidget::guidToText(const GUID& guidValue)
{
    wchar_t guidBuffer[64] = {};
    if (::StringFromGUID2(guidValue, guidBuffer, static_cast<int>(std::size(guidBuffer))) <= 0)
    {
        return QStringLiteral("{00000000-0000-0000-0000-000000000000}");
    }
    return QString::fromWCharArray(guidBuffer);
}

QString ProcessTraceMonitorWidget::queryEtwEventName(const struct _EVENT_RECORD* eventRecordPtr)
{
    const auto textAtOffset = [](const unsigned char* bufferPointer, const ULONG offsetValue) -> QString {
        if (bufferPointer == nullptr || offsetValue == 0)
        {
            return QString();
        }

        const wchar_t* textPointer = reinterpret_cast<const wchar_t*>(bufferPointer + offsetValue);
        if (textPointer == nullptr || *textPointer == L'\0')
        {
            return QString();
        }
        return QString::fromWCharArray(textPointer).trimmed();
    };

    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr)
    {
        return QString();
    }

    DWORD bufferSize = 0;
    ULONG status = ::TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(eventRecord),
        0,
        nullptr,
        nullptr,
        &bufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0)
    {
        return QString();
    }

    std::vector<unsigned char> infoBuffer(bufferSize, 0);
    auto* eventInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
    status = ::TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(eventRecord),
        0,
        nullptr,
        eventInfo,
        &bufferSize);
    if (status != ERROR_SUCCESS || eventInfo == nullptr)
    {
        return QString();
    }

    const unsigned char* infoBufferPointer = infoBuffer.data();
    const QString eventNameText = textAtOffset(infoBufferPointer, eventInfo->EventNameOffset);
    if (!eventNameText.isEmpty())
    {
        return eventNameText;
    }

    const QString taskNameText = textAtOffset(infoBufferPointer, eventInfo->TaskNameOffset);
    if (!taskNameText.isEmpty())
    {
        return taskNameText;
    }

    return textAtOffset(infoBufferPointer, eventInfo->OpcodeNameOffset);
}

bool ProcessTraceMonitorWidget::textMatch(
    const QString& sourceText,
    const QString& patternText,
    const bool useRegex,
    const Qt::CaseSensitivity caseSensitivity)
{
    if (patternText.trimmed().isEmpty())
    {
        return true;
    }

    if (!useRegex)
    {
        return sourceText.contains(patternText, caseSensitivity);
    }

    QRegularExpression::PatternOptions options = QRegularExpression::NoPatternOption;
    if (caseSensitivity == Qt::CaseInsensitive)
    {
        options |= QRegularExpression::CaseInsensitiveOption;
    }

    const QRegularExpression regex(patternText, options);
    if (!regex.isValid())
    {
        return false;
    }
    return regex.match(sourceText).hasMatch();
}

bool ProcessTraceMonitorWidget::tryParseUint32Text(const QString& textValue, std::uint32_t* valueOut)
{
    if (valueOut == nullptr)
    {
        return false;
    }

    bool parseOk = false;
    QString normalizedText = textValue.trimmed();
    if (normalizedText.isEmpty())
    {
        return false;
    }

    std::uint32_t parsedValue = 0;
    if (normalizedText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        parsedValue = normalizedText.mid(2).toUInt(&parseOk, 16);
    }
    else
    {
        parsedValue = normalizedText.toUInt(&parseOk, 10);
        if (!parseOk)
        {
            parsedValue = normalizedText.toUInt(&parseOk, 16);
        }
    }

    if (!parseOk || parsedValue == 0)
    {
        return false;
    }

    *valueOut = parsedValue;
    return true;
}

QTableWidgetItem* ProcessTraceMonitorWidget::createReadOnlyItem(const QString& textValue)
{
    QTableWidgetItem* itemPointer = new QTableWidgetItem(textValue);
    itemPointer->setFlags(itemPointer->flags() & ~Qt::ItemIsEditable);
    itemPointer->setToolTip(textValue);
    return itemPointer;
}

void ProcessTraceMonitorWidget::updateActionState()
{
    const bool hasTargets = !m_targetProcessList.empty();
    const bool running = m_captureRunning.load();
    const bool paused = m_capturePaused.load();

    if (m_availableRefreshButton != nullptr)
    {
        m_availableRefreshButton->setEnabled(!running && !m_availableRefreshPending.load());
    }
    if (m_createTargetButton != nullptr)
    {
        m_createTargetButton->setEnabled(!running);
    }
    if (m_addSelectedButton != nullptr)
    {
        m_addSelectedButton->setEnabled(!running && m_availableTable != nullptr && m_availableTable->selectedItems().size() > 0);
    }
    if (m_addManualPidButton != nullptr)
    {
        m_addManualPidButton->setEnabled(!running);
    }
    if (m_removeTargetButton != nullptr)
    {
        m_removeTargetButton->setEnabled(!running && m_targetTable != nullptr && m_targetTable->selectedItems().size() > 0);
    }
    if (m_clearTargetButton != nullptr)
    {
        m_clearTargetButton->setEnabled(!running && hasTargets);
    }
    if (m_startButton != nullptr)
    {
        m_startButton->setEnabled((!running && hasTargets) || (running && paused));
        m_startButton->setIcon(QIcon(paused
            ? QStringLiteral(":/Icon/process_resume.svg")
            : QStringLiteral(":/Icon/process_start.svg")));
        m_startButton->setToolTip(paused
            ? QStringLiteral("继续处理与目标进程相关的事件")
            : QStringLiteral("开始监控已选择的目标进程"));
    }
    if (m_stopButton != nullptr)
    {
        m_stopButton->setEnabled(running);
    }
    if (m_pauseButton != nullptr)
    {
        m_pauseButton->setEnabled(running && !paused);
        m_pauseButton->setIcon(QIcon(QStringLiteral(":/Icon/process_pause.svg")));
        m_pauseButton->setToolTip(QStringLiteral("暂停处理与目标进程相关的事件"));
    }
    if (m_exportButton != nullptr)
    {
        m_exportButton->setEnabled(m_eventTable != nullptr && m_eventTable->rowCount() > 0);
    }
}

void ProcessTraceMonitorWidget::updateStatusLabel()
{
    if (m_statusLabel == nullptr)
    {
        return;
    }

    std::size_t trackedCount = 0;
    {
        std::lock_guard<std::mutex> lock(m_runtimeMutex);
        trackedCount = m_trackedProcessMap.size();
    }

    const int eventCount = (m_eventTable != nullptr) ? m_eventTable->rowCount() : 0;
    const QString summaryText = QStringLiteral("目标=%1 | 进程树=%2 | 事件=%3")
        .arg(m_targetProcessList.size())
        .arg(static_cast<qulonglong>(trackedCount))
        .arg(eventCount);

    if (m_captureRunning.load())
    {
        if (m_capturePaused.load())
        {
            m_statusLabel->setText(QStringLiteral("● 已暂停  %1").arg(summaryText));
            ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Warning);
        }
        else
        {
            m_statusLabel->setText(QStringLiteral("● 监听中  %1").arg(summaryText));
            ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Info);
        }
    }
    else
    {
        m_statusLabel->setText(QStringLiteral("● 空闲  %1").arg(summaryText));
        ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Idle);
    }
}
