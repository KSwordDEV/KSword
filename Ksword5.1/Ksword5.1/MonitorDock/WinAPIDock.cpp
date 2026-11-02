#include "MonitorCanonicalExport.h"
#include "WinAPIDock.h"
#include "WinAPIEventTableModel.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ThemeItemForeground.h"

// ============================================================
// WinAPIDock.cpp
// 作用：
// 1) 放置 WinAPI Dock 的基础样式、构造析构和轻量工具函数；
// 2) 把与 UI 结构无关的通用逻辑集中起来；
// 3) 避免把初始化、动作和管道代码堆进同一个实现文件。
// ============================================================

#include "../theme.h"

#include <QCoreApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QEvent>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>

WinAPIDock::WinAPIDock(QWidget* parent)
    : QWidget(parent)
{
    // initEvent：
    // - 作用：串起整个 Dock 初始化链路；
    // - 约束：初始化阶段统一使用同一个 kLogEvent。
    kLogEvent initEvent;
    info << initEvent << "[WinAPIDock] 开始初始化 WinAPI 监控页。" << eol;

    m_sessionOperation = new ks::ui::AsyncOperation(this);
    m_eventRules = std::make_shared<ks::monitor::WinAPIFilterRules>(QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("config/winapi-filter.cfg")));
    m_eventRulesValid = m_eventRules->load();
    initializeUi();
    initializeEventProjection();
    initializeConnections();
    updateActionState();
    updateStatusLabel();

    info << initEvent << "[WinAPIDock] WinAPI 监控页初始化完成。" << eol;
}

void WinAPIDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr || (event->type() != QEvent::PaletteChange
        && event->type() != QEvent::ApplicationPaletteChange) || m_itemThemeRefreshScheduled)
    {
        return;
    }
    // 已有事件只按 Info/Error 角色重新求色；保留排序、隐藏行、选择和监控代次。
    m_itemThemeRefreshScheduled = true;
    QTimer::singleShot(0, this, [this]() {
        ks::ui::RefreshThemeItemForegrounds(m_eventTable);
        m_itemThemeRefreshScheduled = false;
    });
}

WinAPIDock::~WinAPIDock()
{
    if (m_eventExport) m_eventExport->close();
    if (m_eventModel) m_eventModel->close();
    if (m_sessionOperation) m_sessionOperation->close();
    if (m_coverageDispatcher) m_coverageDispatcher->close();
    ++m_coverageFilterTicket;
    stopMonitoringInternal(true);

    if (m_uiFlushTimer != nullptr)
    {
        m_uiFlushTimer->stop();
    }

    kLogEvent destroyEvent;
    info << destroyEvent << "[WinAPIDock] WinAPI 监控页已析构。" << eol;
}

void WinAPIDock::notifyPageActivated()
{
    // 首次进入页签时立即刷新；之后 5 秒内重复切换不再重复扫进程，避免无意义抖动。
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    const bool shouldRefresh = !m_hasActivatedOnce
        || (m_lastProcessRefreshMs <= 0)
        || ((nowMs - m_lastProcessRefreshMs) >= 5000);

    m_hasActivatedOnce = true;
    if (m_coverageDirty) QTimer::singleShot(0, this, [this]() { updateCoverageView(); });
    if (shouldRefresh)
    {
        refreshProcessListAsync();
    }
}

QString WinAPIDock::blueButtonStyle()
{
    return KswordTheme::ThemedButtonStyle();
}

QString WinAPIDock::blueInputStyle()
{
    return QStringLiteral(
        "QLineEdit{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
        "QPlainTextEdit{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:4px 6px;}"
        "QTableWidget{border:1px solid %2;border-radius:3px;background:transparent;background-color:transparent;color:%4;padding:2px 6px;gridline-color:%2;alternate-background-color:transparent;}"
        "QTableWidget::viewport{background:transparent;background-color:transparent;}"
        "QLineEdit:focus,QPlainTextEdit:focus{border:1px solid %1;}")
        .arg(KswordTheme::PrimaryBlueHex)
        .arg(KswordTheme::BorderHex())
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::TextPrimaryHex());
}

QString WinAPIDock::blueHeaderStyle()
{
    return QStringLiteral(
        "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;padding:4px;font-weight:600;}")
        .arg(KswordTheme::PrimaryBlueHex)
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::BorderHex());
}

QString WinAPIDock::eventCategoryText(const std::uint32_t categoryValue)
{
    return QString::fromStdWString(
        ks::winapi_monitor::eventCategoryToText(
            static_cast<ks::winapi_monitor::EventCategory>(categoryValue)));
}

QString WinAPIDock::defaultDllPathHint()
{
    const QDir appDir(QCoreApplication::applicationDirPath());
    const QStringList candidatePathList{
        appDir.filePath(QStringLiteral("APIMonitor_x64.dll")),
        appDir.filePath(QStringLiteral("../APIMonitor_x64.dll")),
        appDir.filePath(QStringLiteral("../../APIMonitor_x64.dll")),
        appDir.filePath(QStringLiteral("../../../../APIMonitor_x64/x64/Debug/APIMonitor_x64.dll")),
        appDir.filePath(QStringLiteral("../../../../APIMonitor_x64/x64/Release/APIMonitor_x64.dll"))
    };

    for (const QString& candidatePath : candidatePathList)
    {
        const QFileInfo fileInfo(candidatePath);
        if (fileInfo.exists() && fileInfo.isFile())
        {
            return QDir::cleanPath(fileInfo.absoluteFilePath());
        }
    }

    return QDir::cleanPath(candidatePathList.front());
}

QString WinAPIDock::defaultRawHookModulesText()
{
    // defaultRawHookModulesText：
    // - 输入：无；
    // - 处理：从共享协议常量读取 Raw Fallback 默认模块目录；
    // - 返回：分号分隔文本，供 UI 编辑框展示和会话 INI 写入。
    return QString::fromWCharArray(ks::winapi_monitor::kDefaultRawHookModules);
}

QString WinAPIDock::defaultRawHookDenyListText()
{
    // defaultRawHookDenyListText：
    // - 输入：无；
    // - 处理：从共享协议常量读取 Raw Fallback 内置默认黑名单；
    // - 返回：分号分隔文本，主要供 tooltip/说明展示；用户额外黑名单不应默认填入该值。
    return QString::fromWCharArray(ks::winapi_monitor::kDefaultRawHookDenyList);
}

QString WinAPIDock::resultCodeText(const std::int32_t resultCodeValue)
{
    if (resultCodeValue == 0)
    {
        return QStringLiteral("OK");
    }
    return QStringLiteral("%1 (0x%2)")
        .arg(resultCodeValue)
        .arg(QString::number(static_cast<quint32>(resultCodeValue), 16).toUpper());
}

QString WinAPIDock::now100nsText()
{
    FILETIME fileTimeValue{};
    ::GetSystemTimeAsFileTime(&fileTimeValue);

    ULARGE_INTEGER largeValue{};
    largeValue.LowPart = fileTimeValue.dwLowDateTime;
    largeValue.HighPart = fileTimeValue.dwHighDateTime;
    return QString::number(static_cast<qulonglong>(largeValue.QuadPart));
}

bool WinAPIDock::tryParseUint32Text(const QString& textValue, std::uint32_t* valueOut)
{
    if (valueOut == nullptr)
    {
        return false;
    }

    bool parseOk = false;
    const QString normalizedText = textValue.trimmed();
    if (normalizedText.isEmpty())
    {
        return false;
    }

    const std::uint32_t parsedValue = normalizedText.toUInt(&parseOk, 10);
    if (!parseOk || parsedValue == 0)
    {
        return false;
    }

    *valueOut = parsedValue;
    return true;
}

QTableWidgetItem* WinAPIDock::createReadOnlyItem(const QString& textValue)
{
    QTableWidgetItem* itemPointer = new QTableWidgetItem(textValue);
    itemPointer->setFlags(itemPointer->flags() & ~Qt::ItemIsEditable);
    itemPointer->setToolTip(textValue);
    return itemPointer;
}

void WinAPIDock::updateActionState()
{
    std::uint32_t currentPidValue = 0;
    const bool hasPid = currentSelectedPid(&currentPidValue);
    const bool running = m_pipeRunning.load() || (m_sessionOperation && m_sessionOperation->isBusy());
    for (QCheckBox* check : {m_hookFileCheck, m_hookRegistryCheck, m_hookNetworkCheck,
            m_hookProcessCheck, m_hookLoaderCheck, m_hookClipboardCheck, m_autoInjectChildCheck})
        if (check) check->setEnabled(!running);
    const bool hasEvents = m_eventArchive.size() > 0;

    if (m_processRefreshButton != nullptr)
    {
        m_processRefreshButton->setEnabled(!m_processRefreshPending.load() && !running);
    }
    if (m_processCombo != nullptr)
    {
        m_processCombo->setEnabled(!running);
    }
    if (m_browseAgentDllButton != nullptr)
    {
        m_browseAgentDllButton->setEnabled(!running);
    }
    if (m_manualPidEdit != nullptr)
    {
        m_manualPidEdit->setEnabled(!running);
    }
    if (m_agentDllPathEdit != nullptr)
    {
        m_agentDllPathEdit->setEnabled(!running);
    }
    if (m_rawFallbackCheck != nullptr)
    {
        m_rawFallbackCheck->setEnabled(!running);
    }
    if (m_rawDefaultDenyListCheck != nullptr)
    {
        m_rawDefaultDenyListCheck->setEnabled(!running && m_rawFallbackCheck != nullptr && m_rawFallbackCheck->isChecked());
    }
    if (m_rawModuleListEdit != nullptr)
    {
        m_rawModuleListEdit->setEnabled(!running && m_rawFallbackCheck != nullptr && m_rawFallbackCheck->isChecked());
    }
    if (m_rawDenyListEdit != nullptr)
    {
        m_rawDenyListEdit->setEnabled(!running && m_rawFallbackCheck != nullptr && m_rawFallbackCheck->isChecked());
    }
    if (m_fakeModuleEdit != nullptr)
    {
        m_fakeModuleEdit->setEnabled(!running);
    }
    if (m_fakeApiEdit != nullptr)
    {
        m_fakeApiEdit->setEnabled(!running);
    }
    if (m_fakeReturnTypeCombo != nullptr)
    {
        m_fakeReturnTypeCombo->setEnabled(!running);
    }
    if (m_fakeReturnValueEdit != nullptr)
    {
        m_fakeReturnValueEdit->setEnabled(!running);
    }
    if (m_fakeLastErrorKindCombo != nullptr)
    {
        m_fakeLastErrorKindCombo->setEnabled(!running);
    }
    if (m_fakeLastErrorValueEdit != nullptr)
    {
        m_fakeLastErrorValueEdit->setEnabled(!running);
    }
    if (m_fakeX86StackBytesEdit != nullptr) m_fakeX86StackBytesEdit->setEnabled(!running);
    if (m_fakeRawFallbackCheck != nullptr)
    {
        m_fakeRawFallbackCheck->setEnabled(!running);
    }
    if (m_fakeAddRuleButton != nullptr)
    {
        m_fakeAddRuleButton->setEnabled(!running);
    }
    if (m_fakeRemoveRuleButton != nullptr)
    {
        m_fakeRemoveRuleButton->setEnabled(
            !running
            && m_fakeRuleTable != nullptr
            && !m_fakeRuleTable->selectedItems().isEmpty());
    }
    if (m_fakeApplyRuleButton != nullptr)
    {
        m_fakeApplyRuleButton->setEnabled(
            !running
            && hasPid
            && m_agentDllPathEdit != nullptr
            && !m_agentDllPathEdit->text().trimmed().isEmpty());
    }
    if (m_fakeStopRuleButton != nullptr)
    {
        m_fakeStopRuleButton->setEnabled(running);
    }
    if (m_fakeRuleTable != nullptr)
    {
        m_fakeRuleTable->setEnabled(!running);
    }
    if (m_startButton != nullptr)
    {
        m_startButton->setEnabled(
            !running
            && hasPid
            && m_agentDllPathEdit != nullptr
            && !m_agentDllPathEdit->text().trimmed().isEmpty());
    }
    if (m_stopButton != nullptr)
    {
        m_stopButton->setEnabled(running);
    }
    if (m_terminateHookButton != nullptr)
    {
        m_terminateHookButton->setEnabled(hasPid && (!running || currentPidValue == m_currentSessionPid));
    }
    updateEventExportAction();
    if (m_clearEventButton != nullptr)
    {
        m_clearEventButton->setEnabled(hasEvents && !running);
    }
}

void WinAPIDock::updateStatusLabel()
{
    if (m_sessionStatusLabel == nullptr)
    {
        return;
    }

    const int eventCount = static_cast<int>(m_eventArchive.size());
    const QString pidText = m_currentSessionPid == 0
        ? QStringLiteral("-")
        : QString::number(m_currentSessionPid);

    if (m_pipeRunning.load())
    {
        if (m_stopping)
        {
            m_sessionStatusLabel->setText(QStringLiteral("停止监控"));
            ks::ui::ApplyStatusRole(m_sessionStatusLabel, ks::ui::StatusRole::Warning);
        }
        else if (m_pipeConnected.load())
        {
            QString text;
            ks::ui::StatusRole role = ks::ui::StatusRole::Warning;
            switch (m_hookState)
            {
            case HookState::Active:
                text = QStringLiteral("● 监控中  PID=%1 | 事件=%2");
                role = ks::ui::StatusRole::Info;
                break;
            case HookState::Partial:
                text = QStringLiteral("● 部分 Hook 生效  PID=%1 | 事件=%2");
                break;
            case HookState::Failed:
                text = QStringLiteral("● Hook 安装失败  PID=%1 | 事件=%2");
                role = ks::ui::StatusRole::Error;
                break;
            case HookState::Removed:
                text = QStringLiteral("● Hook 已移除  PID=%1 | 事件=%2");
                break;
            default:
                text = QStringLiteral("● Agent 已连接，正在安装 Hook  PID=%1 | 事件=%2");
                break;
            }
            m_sessionStatusLabel->setText(text.arg(pidText).arg(eventCount));
            ks::ui::ApplyStatusRole(m_sessionStatusLabel, role);
        }
        else
        {
            m_sessionStatusLabel->setText(
                QStringLiteral("● 等待 Agent 连接  PID=%1 | 事件=%2").arg(pidText).arg(eventCount));
            ks::ui::ApplyStatusRole(m_sessionStatusLabel, ks::ui::StatusRole::Warning);
        }
    }
    else
    {
        m_sessionStatusLabel->setText(
            QStringLiteral("● 空闲  PID=%1 | 事件=%2").arg(pidText).arg(eventCount));
        ks::ui::ApplyStatusRole(m_sessionStatusLabel, ks::ui::StatusRole::Idle);
    }
    m_sessionStatusLabel->setText(m_sessionStatusLabel->text() + eventLossSummary());
    if (m_definitionMismatch)
    {
        m_sessionStatusLabel->setText(m_sessionStatusLabel->text() + QStringLiteral(" | API 定义不匹配或缺失"));
        ks::ui::ApplyStatusRole(m_sessionStatusLabel, ks::ui::StatusRole::Warning);
    }
}

QString WinAPIDock::eventLossSummary()
{
    std::lock_guard<std::mutex> lock(m_pendingMutex);
    std::uint64_t agentDropped = 0;
    for (const auto& entry : m_agentDroppedRows) agentDropped += entry.second;
    return QStringLiteral(" | Agent 丢失=%1，UI 丢失=%2，已移出表格=%3，待显示=%4")
        .arg(static_cast<qulonglong>(agentDropped)).arg(static_cast<qulonglong>(m_pendingDroppedRows))
        .arg(static_cast<qulonglong>(m_evictedRows)).arg(static_cast<qulonglong>(m_pendingRows.size()));
}
