#include "KernelDock.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/FlatButtonTheme.h"
#include "KernelDock.CallbackPromptManager.h"

#include "../theme.h"

#include <Windows.h>

#include <QApplication>
#include <QCloseEvent>
#include <QDateTime>
#include <QEvent>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFontMetrics>
#include <QGuiApplication>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QMetaObject>
#include <QPalette>
#include <QPushButton>
#include <QPixmap>
#include <QRegularExpression>
#include <QScreen>
#include <QTimer>
#include <QtGlobal>
#include <QVBoxLayout>
#include <QWindow>

#include <chrono>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    constexpr int kWaitWorkerCount = 3;
    constexpr int kWaitRetrySleepMs = 350;
    constexpr int kPollTickMs = 200;

    std::mutex g_callbackPromptManagerMutex;
    CallbackPromptManager* g_callbackPromptManager = nullptr;

    QString fromWideBuffer(const wchar_t* wideText)
    {
        if (wideText == nullptr)
        {
            return QString();
        }
        return QString::fromWCharArray(wideText).trimmed();
    }

    QString operationToDisplayText(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(eventPacket.operationType), 8, 16, QChar('0'))
            .toUpper();
    }

    QString queryProcessImagePathByPid(const quint32 processId)
    {
        if (processId == 0)
        {
            return QString();
        }

        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (processHandle == nullptr)
        {
            return QString();
        }

        wchar_t imagePathBuffer[MAX_PATH * 4] = {};
        DWORD imagePathLength = static_cast<DWORD>(sizeof(imagePathBuffer) / sizeof(imagePathBuffer[0]));
        const BOOL queryOk = ::QueryFullProcessImageNameW(
            processHandle,
            0,
            imagePathBuffer,
            &imagePathLength);
        ::CloseHandle(processHandle);
        if (queryOk == FALSE || imagePathLength == 0)
        {
            return QString();
        }

        return QString::fromWCharArray(imagePathBuffer, static_cast<int>(imagePathLength)).trimmed();
    }

    QIcon resolveInitiatorProcessIcon(const quint32 processId, const QString& fallbackPath)
    {
        static QFileIconProvider iconProvider;

        const auto iconByPath = [](const QString& pathText) -> QIcon {
            const QString normalizedPath = pathText.trimmed();
            if (normalizedPath.isEmpty())
            {
                return QIcon();
            }
            const QFileInfo fileInfo(normalizedPath);
            if (!fileInfo.exists())
            {
                return QIcon();
            }
            return iconProvider.icon(fileInfo);
        };

        const QString resolvedPath = queryProcessImagePathByPid(processId);
        QIcon processIcon = iconByPath(resolvedPath);
        if (processIcon.isNull())
        {
            processIcon = iconByPath(fallbackPath);
        }
        if (processIcon.isNull())
        {
            processIcon = QIcon(QStringLiteral(":/Icon/process_main.svg"));
        }
        return processIcon;
    }

    QColor resolveCurrentAccentColor()
    {
        if (qApp != nullptr)
        {
            const QColor highlightColor =
                qApp->palette().color(QPalette::Active, QPalette::Highlight);
            if (highlightColor.isValid())
            {
                return highlightColor;
            }
        }
        return KswordTheme::PrimaryBlueColor;
    }

    QString currentAccentColorHex()
    {
        return resolveCurrentAccentColor().name(QColor::HexRgb);
    }

    QString buildPopupThemeStyleSheet()
    {
        // 弹窗面板和标题仍保留原主题层级，按钮颜色交给逐项语义绑定。
        return QStringLiteral(
            "QDialog#KswordCallbackDecisionPopup{background-color:palette(window);"
            "color:palette(text);border:1px solid %1;border-radius:10px;}"
            "QDialog#KswordCallbackDecisionPopup QLabel{color:palette(text);}"
            "QDialog#KswordCallbackDecisionPopup QLabel#KswordCallbackTitleLabel{"
            "color:%1;font-size:15px;font-weight:800;}"
            "QDialog#KswordCallbackDecisionPopup QLabel#KswordCallbackSectionLabel{color:%1;font-weight:700;}"
            "QDialog#KswordCallbackDecisionPopup QLabel#KswordCallbackInitiatorLink{color:%1;}"
            "QDialog#KswordCallbackDecisionPopup QPushButton{border-radius:2px;padding:6px 14px;min-height:30px;}")
            .arg(currentAccentColorHex());
    }

    QString buildDecisionButtonText(
        const quint32 buttonDecision,
        const quint32 defaultDecision,
        const qint64 remainingTimeoutMs)
    {
        const QString baseText = (buttonDecision == KSWORD_ARK_DECISION_DENY)
            ? kernelText("kernel.callback.prompt.decision.deny", QStringLiteral("拒绝"))
            : kernelText("kernel.callback.prompt.decision.allow", QStringLiteral("允许"));
        if (buttonDecision != defaultDecision)
        {
            return baseText;
        }

        const qint64 remainingSeconds = qMax<qint64>(0, (remainingTimeoutMs + 999LL) / 1000LL);
        return kernelText("kernel.callback.prompt.decision.countdown", QStringLiteral("%1（%2）"))
            .arg(baseText)
            .arg(remainingSeconds);
    }
}

CallbackPromptManager* CallbackPromptManager::ensureGlobalManager(QWidget* hostWindow)
{
    std::lock_guard<std::mutex> lockGuard(g_callbackPromptManagerMutex);
    if (g_callbackPromptManager == nullptr)
    {
        g_callbackPromptManager = new CallbackPromptManager(hostWindow, qApp);
    }
    if (hostWindow != nullptr)
    {
        g_callbackPromptManager->setHostWindow(hostWindow);
    }
    return g_callbackPromptManager;
}

CallbackPromptManager* CallbackPromptManager::globalManager()
{
    std::lock_guard<std::mutex> lockGuard(g_callbackPromptManagerMutex);
    return g_callbackPromptManager;
}

void CallbackPromptManager::shutdownGlobalManager()
{
    CallbackPromptManager* manager = nullptr;
    {
        std::lock_guard<std::mutex> lockGuard(g_callbackPromptManagerMutex);
        manager = g_callbackPromptManager;
        g_callbackPromptManager = nullptr;
    }

    if (manager != nullptr)
    {
        manager->stop();
        delete manager;
    }
}

CallbackPromptManager::DecisionPopupDialog::DecisionPopupDialog(
    CallbackPromptManager* owner,
    QWidget* parent)
    : QDialog(parent)
    , m_owner(owner)
{
}

void CallbackPromptManager::DecisionPopupDialog::closeEvent(QCloseEvent* event)
{
    // 关闭事件来源：Alt+F4、系统菜单关闭或窗口管理器关闭都会进入这里。
    // 处理逻辑：驱动回调决策必须由“允许/拒绝”按钮或超时路径完成，关闭请求不触发默认决策。
    // 返回行为：忽略本次关闭事件，Qt 会继续保留当前待决策弹窗。
    if (event != nullptr)
    {
        event->ignore();
    }
}

CallbackPromptManager::CallbackPromptManager(QWidget* hostWindow, QObject* parent)
    : QObject(parent)
    , m_hostWindow(hostWindow)
{
    initializePopupUi();
    initializePopupConnections();
    if (qApp != nullptr)
    {
        qApp->installEventFilter(this);
    }
}

CallbackPromptManager::~CallbackPromptManager()
{
    if (qApp != nullptr)
    {
        qApp->removeEventFilter(this);
    }
    stop();
}

bool CallbackPromptManager::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == qApp && event != nullptr)
    {
        const QEvent::Type eventType = event->type();
        if (eventType == QEvent::ApplicationPaletteChange ||
            eventType == QEvent::PaletteChange ||
            eventType == QEvent::StyleChange)
        {
            applyPopupTheme();
            if (m_hasCurrentEvent)
            {
                updatePopupContent(m_currentEvent);
            }
        }
    }
    return QObject::eventFilter(watched, event);
}

void CallbackPromptManager::applyPopupTheme()
{
    if (m_popupDialog.isNull())
    {
        return;
    }
    m_popupDialog->setStyleSheet(buildPopupThemeStyleSheet());
}

void CallbackPromptManager::setHostWindow(QWidget* hostWindow)
{
    m_hostWindow = hostWindow;
    movePopupToBottomRight();
}

void CallbackPromptManager::start()
{
    if (m_running.exchange(true))
    {
        return;
    }

    appendManagerLog(kernelText("kernel.callback.prompt.log.manager_started", QStringLiteral("驱动回调全局弹窗管理器已启动。")));
    startWorkersIfNeeded();
}

void CallbackPromptManager::stop()
{
    if (!m_running.exchange(false))
    {
        return;
    }

    stopWorkersIfNeeded();
    cancelAllPendingDecisionsBestEffort();

    {
        std::lock_guard<std::mutex> queueLock(m_queueMutex);
        m_eventQueue.clear();
        m_hasCurrentEvent = false;
        RtlZeroMemory(&m_currentEvent, sizeof(m_currentEvent));
        m_remainingTimeoutMs = 0;
    }

    if (m_countdownTimer != nullptr)
    {
        m_countdownTimer->stop();
    }
    if (!m_popupDialog.isNull())
    {
        m_popupDialog->hide();
    }

    appendManagerLog(kernelText("kernel.callback.prompt.log.manager_stopped", QStringLiteral("驱动回调全局弹窗管理器已停止。")));
}

void CallbackPromptManager::initializePopupUi()
{
    auto* popupDialog = new DecisionPopupDialog(this);
    popupDialog->setObjectName(QStringLiteral("KswordCallbackDecisionPopup"));
    popupDialog->setWindowFlags(
        Qt::Tool |
        Qt::FramelessWindowHint |
        Qt::WindowStaysOnTopHint |
        Qt::NoDropShadowWindowHint);
    popupDialog->setModal(false);
    popupDialog->setAttribute(Qt::WA_ShowWithoutActivating, true);

    auto* rootLayout = new QVBoxLayout(popupDialog);
    rootLayout->setContentsMargins(14, 12, 14, 12);
    rootLayout->setSpacing(10);

    auto* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);

    auto* logoLabel = new QLabel(popupDialog);
    logoLabel->setFixedSize(100, 28);
    logoLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    const QPixmap mainLogoPixmap(QStringLiteral(":/Image/Resource/Logo/MainLogo.png"));
    if (!mainLogoPixmap.isNull())
    {
        logoLabel->setPixmap(mainLogoPixmap.scaled(
            logoLabel->size(),
            Qt::KeepAspectRatio,
            Qt::SmoothTransformation));
    }

    auto* titleLabel = new QLabel(kernelText("kernel.callback.prompt.title", QStringLiteral("驱动回调决策")), popupDialog);
    titleLabel->setObjectName(QStringLiteral("KswordCallbackTitleLabel"));

    headerLayout->addWidget(logoLabel, 0, Qt::AlignVCenter);
    headerLayout->addWidget(titleLabel, 0, Qt::AlignVCenter);
    headerLayout->addStretch(1);
    rootLayout->addLayout(headerLayout, 0);

    auto* detailGrid = new QGridLayout();
    detailGrid->setHorizontalSpacing(8);
    detailGrid->setVerticalSpacing(6);

    int rowIndex = 0;
    auto appendRow = [popupDialog, detailGrid, &rowIndex](const QString& nameText, QLabel** valueLabelOut) {
        auto* nameLabel = new QLabel(nameText, popupDialog);
        nameLabel->setObjectName(QStringLiteral("KswordCallbackSectionLabel"));
        auto* valueLabel = new QLabel(QStringLiteral("-"), popupDialog);
        valueLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        valueLabel->setWordWrap(true);
        detailGrid->addWidget(nameLabel, rowIndex, 0, 1, 1);
        detailGrid->addWidget(valueLabel, rowIndex, 1, 1, 1);
        if (valueLabelOut != nullptr)
        {
            *valueLabelOut = valueLabel;
        }
        ++rowIndex;
    };

    appendRow(kernelText("kernel.callback.prompt.label.event_guid", QStringLiteral("事件GUID")), &m_eventGuidValueLabel);
    appendRow(kernelText("kernel.callback.prompt.label.callback_type", QStringLiteral("回调类型")), &m_callbackTypeValueLabel);
    appendRow(kernelText("kernel.callback.prompt.label.operation_type", QStringLiteral("操作类型")), &m_operationValueLabel);
    appendRow(kernelText("kernel.callback.prompt.label.target", QStringLiteral("目标")), &m_targetValueLabel);

    auto* initiatorNameLabel = new QLabel(kernelText("kernel.callback.prompt.label.initiator", QStringLiteral("发起进程")), popupDialog);
    initiatorNameLabel->setObjectName(QStringLiteral("KswordCallbackSectionLabel"));
    auto* initiatorRowWidget = new QWidget(popupDialog);
    auto* initiatorRowLayout = new QHBoxLayout(initiatorRowWidget);
    initiatorRowLayout->setContentsMargins(0, 0, 0, 0);
    initiatorRowLayout->setSpacing(6);
    m_initiatorIconLabel = new QLabel(initiatorRowWidget);
    m_initiatorIconLabel->setFixedSize(18, 18);
    m_initiatorIconLabel->setScaledContents(false);
    m_initiatorValueLabel = new QLabel(QStringLiteral("-"), initiatorRowWidget);
    m_initiatorValueLabel->setObjectName(QStringLiteral("KswordCallbackInitiatorLink"));
    m_initiatorValueLabel->setTextFormat(Qt::RichText);
    m_initiatorValueLabel->setTextInteractionFlags(Qt::LinksAccessibleByMouse);
    m_initiatorValueLabel->setOpenExternalLinks(false);
    m_initiatorValueLabel->setWordWrap(false);
    m_initiatorValueLabel->setCursor(Qt::PointingHandCursor);
    m_initiatorValueLabel->setToolTip(kernelText("kernel.callback.prompt.initiator.tooltip", QStringLiteral("点击发起进程文本可打开进程详细信息")));
    initiatorRowLayout->addWidget(m_initiatorIconLabel, 0, Qt::AlignVCenter);
    initiatorRowLayout->addWidget(m_initiatorValueLabel, 1, Qt::AlignVCenter);
    detailGrid->addWidget(initiatorNameLabel, rowIndex, 0, 1, 1);
    detailGrid->addWidget(initiatorRowWidget, rowIndex, 1, 1, 1);
    ++rowIndex;

    appendRow(kernelText("kernel.callback.prompt.label.session_id", QStringLiteral("会话ID")), &m_sessionIdValueLabel);
    appendRow(kernelText("kernel.callback.prompt.label.rule", QStringLiteral("规则")), &m_ruleValueLabel);
    detailGrid->setColumnStretch(0, 0);
    detailGrid->setColumnStretch(1, 1);
    rootLayout->addLayout(detailGrid, 1);

    auto* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 2, 0, 0);
    actionLayout->setSpacing(8);

    m_allowButton = new QPushButton(kernelText("kernel.callback.prompt.decision.allow", QStringLiteral("允许")), popupDialog);
    m_allowButton->setObjectName(QStringLiteral("KswordCallbackAllowButton"));
    m_denyButton = new QPushButton(kernelText("kernel.callback.prompt.decision.deny", QStringLiteral("拒绝")), popupDialog);
    m_denyButton->setObjectName(QStringLiteral("KswordCallbackDenyButton"));
    m_detailButton = new QPushButton(kernelText("kernel.callback.prompt.button.details", QStringLiteral("查看详情")), popupDialog);
    m_detailButton->setObjectName(QStringLiteral("KswordCallbackDetailButton"));
    // 允许为主要操作，拒绝保持危险语义，详情为中性；不改变倒计时或默认决策。
    ks::ui::ApplyFlatButtonTheme(m_allowButton, ks::ui::FlatButtonTone::Accent);
    ks::ui::ApplyFlatButtonTheme(m_denyButton, ks::ui::FlatButtonTone::Danger);
    ks::ui::ApplyFlatButtonTheme(m_detailButton, ks::ui::FlatButtonTone::Neutral);

    actionLayout->addStretch(1);
    actionLayout->addWidget(m_allowButton, 0);
    actionLayout->addWidget(m_denyButton, 0);
    actionLayout->addWidget(m_detailButton, 0);
    ks::ui::NormalizeToolbarRow(actionLayout);
    rootLayout->addLayout(actionLayout, 0);

    m_popupDialog = popupDialog;
    applyPopupTheme();

    m_countdownTimer = new QTimer(this);
    m_countdownTimer->setInterval(kPollTickMs);
}

void CallbackPromptManager::initializePopupConnections()
{
    if (m_countdownTimer != nullptr)
    {
        connect(m_countdownTimer, &QTimer::timeout, this, [this]() {
            updateCountdownLabel();
        });
    }

    if (m_allowButton != nullptr)
    {
        connect(m_allowButton, &QPushButton::clicked, this, [this]() {
            finishCurrentEventWithDecision(KSWORD_ARK_DECISION_ALLOW, false);
        });
    }

    if (m_denyButton != nullptr)
    {
        connect(m_denyButton, &QPushButton::clicked, this, [this]() {
            finishCurrentEventWithDecision(KSWORD_ARK_DECISION_DENY, false);
        });
    }

    if (m_initiatorValueLabel != nullptr)
    {
        connect(m_initiatorValueLabel, &QLabel::linkActivated, this, [this](const QString&) {
            if (!m_hasCurrentEvent || m_currentEvent.originatingPid == 0)
            {
                return;
            }
            QWidget* invokeTarget = m_hostWindow;
            if (invokeTarget == nullptr)
            {
                invokeTarget = qobject_cast<QWidget*>(qApp != nullptr ? qApp->activeWindow() : nullptr);
            }
            if (invokeTarget == nullptr)
            {
                appendManagerLog(kernelText("kernel.callback.prompt.log.process_detail_no_window", QStringLiteral("无法打开进程详情：主窗口对象为空。")));
                return;
            }

            const bool invokeOk = QMetaObject::invokeMethod(
                invokeTarget,
                "openProcessDetailByPid",
                Qt::QueuedConnection,
                Q_ARG(quint32, m_currentEvent.originatingPid));
            appendManagerLog(
                kernelText("kernel.callback.prompt.log.process_link_clicked", QStringLiteral("发起进程超链接被点击: pid=%1, 跳转=%2。"))
                .arg(m_currentEvent.originatingPid)
                .arg(invokeOk
                    ? kernelText("kernel.callback.prompt.result.success", QStringLiteral("成功"))
                    : kernelText("kernel.callback.prompt.result.failure", QStringLiteral("失败"))));
        });
    }

    if (m_detailButton != nullptr)
    {
        connect(m_detailButton, &QPushButton::clicked, this, [this]() {
            if (!m_hasCurrentEvent)
            {
                return;
            }

            const QString detailText = kernelText("kernel.callback.prompt.detail.full", QStringLiteral(
                "事件GUID: %1\n"
                "回调类型: %2\n"
                "操作类型: %3\n"
                "动作: %4\n"
                "匹配模式: %5\n"
                "发起进程: %6\n"
                "目标: %7\n"
                "PID: %8\n"
                "TID: %9\n"
                "会话ID: %10\n"
                "规则组: [%11] %12\n"
                "规则: [%13] %14\n"
                "规则发起匹配: %15\n"
                "规则目标匹配: %16\n"
                "默认决策: %17\n"
                "超时毫秒: %18"))
                .arg(callbackGuidToString(m_currentEvent.eventGuid))
                .arg(callbackTypeToDisplayText(m_currentEvent.callbackType))
                .arg(operationToDisplayText(m_currentEvent))
                .arg(callbackActionToDisplayText(m_currentEvent.action))
                .arg(callbackMatchModeToDisplayText(m_currentEvent.matchMode))
                .arg(fromWideBuffer(m_currentEvent.initiatorPath))
                .arg(fromWideBuffer(m_currentEvent.targetPath))
                .arg(m_currentEvent.originatingPid)
                .arg(m_currentEvent.originatingTid)
                .arg(m_currentEvent.sessionId)
                .arg(m_currentEvent.groupId)
                .arg(fromWideBuffer(m_currentEvent.groupName))
                .arg(m_currentEvent.ruleId)
                .arg(fromWideBuffer(m_currentEvent.ruleName))
                .arg(fromWideBuffer(m_currentEvent.ruleInitiatorPattern))
                .arg(fromWideBuffer(m_currentEvent.ruleTargetPattern))
                .arg(callbackDecisionToDisplayText(m_currentEvent.defaultDecision))
                .arg(m_currentEvent.timeoutMs);

            QMessageBox::information(
                m_popupDialog,
                kernelText("kernel.callback.prompt.detail.title", QStringLiteral("驱动回调详情")),
                detailText);
        });
    }
}

void CallbackPromptManager::appendManagerLog(const QString& logText)
{
    const QString lineText = QStringLiteral("[%1] %2")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")))
        .arg(logText);
    emit logLineGenerated(lineText);
}

void CallbackPromptManager::startWorkersIfNeeded()
{
    if (!m_workerList.empty())
    {
        return;
    }

    m_workerList.reserve(kWaitWorkerCount);
    for (int workerIndex = 0; workerIndex < kWaitWorkerCount; ++workerIndex)
    {
        auto workerContext = std::make_unique<WaitWorkerContext>();
        workerContext->workerTag = workerIndex + 1;
        workerContext->running.store(true);
        workerContext->thread = std::make_unique<std::thread>(
            [this, tag = workerContext->workerTag]() {
                runWaitWorkerLoop(tag);
            });
        m_workerList.push_back(std::move(workerContext));
    }
}

void CallbackPromptManager::stopWorkersIfNeeded()
{
    for (const std::unique_ptr<WaitWorkerContext>& workerContext : m_workerList)
    {
        if (workerContext == nullptr)
        {
            continue;
        }

        workerContext->running.store(false);
        std::lock_guard<std::mutex> handleLock(workerContext->ioMutex);
        if (workerContext->deviceHandle.isValid())
        {
            (void)::CancelIoEx(workerContext->deviceHandle.native(), nullptr);
        }
    }

    for (const std::unique_ptr<WaitWorkerContext>& workerContext : m_workerList)
    {
        if (workerContext == nullptr || workerContext->thread == nullptr)
        {
            continue;
        }
        if (workerContext->thread->joinable())
        {
            workerContext->thread->join();
        }
    }

    for (const std::unique_ptr<WaitWorkerContext>& workerContext : m_workerList)
    {
        if (workerContext == nullptr)
        {
            continue;
        }
        std::lock_guard<std::mutex> handleLock(workerContext->ioMutex);
        workerContext->deviceHandle.reset();
    }

    m_workerList.clear();
}

void CallbackPromptManager::runWaitWorkerLoop(int workerTag)
{
    WaitWorkerContext* workerContext = nullptr;
    for (const std::unique_ptr<WaitWorkerContext>& currentWorker : m_workerList)
    {
        if (currentWorker != nullptr && currentWorker->workerTag == workerTag)
        {
            workerContext = currentWorker.get();
            break;
        }
    }
    if (workerContext == nullptr)
    {
        return;
    }

    auto resetDeviceHandle = [workerContext]() {
        std::lock_guard<std::mutex> handleLock(workerContext->ioMutex);
        workerContext->deviceHandle.reset();
    };

    while (workerContext->running.load())
    {
        HANDLE waitHandle = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> handleLock(workerContext->ioMutex);
            waitHandle = workerContext->deviceHandle.native();
        }

        if (waitHandle == nullptr || waitHandle == INVALID_HANDLE_VALUE)
        {
            ksword::ark::DriverClient driverClient;
            ksword::ark::DriverHandle newHandle = driverClient.openOverlapped();
            if (!newHandle.isValid())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(kWaitRetrySleepMs));
                continue;
            }

            {
                std::lock_guard<std::mutex> handleLock(workerContext->ioMutex);
                workerContext->deviceHandle = std::move(newHandle);
                waitHandle = workerContext->deviceHandle.native();
            }
        }

        KSWORD_ARK_CALLBACK_WAIT_REQUEST waitRequest{};
        waitRequest.size = sizeof(waitRequest);
        waitRequest.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
        waitRequest.waiterTag = static_cast<unsigned long>(workerTag);

        KSWORD_ARK_CALLBACK_EVENT_PACKET eventPacket{};
        OVERLAPPED waitOverlapped{};
        waitOverlapped.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (waitOverlapped.hEvent == nullptr)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(kWaitRetrySleepMs));
            continue;
        }

        DWORD bytesReturned = 0;
        ksword::ark::DriverClient driverClient;
        const ksword::ark::AsyncIoResult waitIssueResult = driverClient.waitCallbackEventAsync(
            workerContext->deviceHandle,
            waitRequest,
            eventPacket,
            &waitOverlapped);
        bytesReturned = waitIssueResult.bytesReturned;

        if (!waitIssueResult.issued)
        {
            const DWORD waitError = waitIssueResult.win32Error;
            if (waitError == ERROR_IO_PENDING)
            {
                bool needCancel = false;
                while (workerContext->running.load())
                {
                    const DWORD waitResult = ::WaitForSingleObject(waitOverlapped.hEvent, kPollTickMs);
                    if (waitResult == WAIT_OBJECT_0)
                    {
                        break;
                    }
                    if (waitResult == WAIT_FAILED)
                    {
                        needCancel = true;
                        break;
                    }
                }

                if (!workerContext->running.load() || needCancel)
                {
                    (void)::CancelIoEx(waitHandle, &waitOverlapped);
                    // Cancellation is asynchronous: keep the stack-backed OVERLAPPED and
                    // output packet alive until the pending DeviceIoControl has completed.
                    (void)::GetOverlappedResult(
                        waitHandle,
                        &waitOverlapped,
                        &bytesReturned,
                        TRUE);
                }

                if (::GetOverlappedResult(waitHandle, &waitOverlapped, &bytesReturned, FALSE) == FALSE)
                {
                    const DWORD overlappedError = ::GetLastError();
                    ::CloseHandle(waitOverlapped.hEvent);

                    if (!workerContext->running.load())
                    {
                        break;
                    }

                    if (overlappedError == ERROR_OPERATION_ABORTED ||
                        overlappedError == ERROR_INVALID_HANDLE ||
                        overlappedError == ERROR_DEVICE_NOT_CONNECTED ||
                        overlappedError == ERROR_FILE_NOT_FOUND)
                    {
                        resetDeviceHandle();
                    }

                    std::this_thread::sleep_for(std::chrono::milliseconds(kWaitRetrySleepMs));
                    continue;
                }
            }
            else
            {
                ::CloseHandle(waitOverlapped.hEvent);
                if (!workerContext->running.load())
                {
                    break;
                }

                if (waitError == ERROR_INVALID_HANDLE ||
                    waitError == ERROR_DEVICE_NOT_CONNECTED ||
                    waitError == ERROR_FILE_NOT_FOUND)
                {
                    resetDeviceHandle();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(kWaitRetrySleepMs));
                continue;
            }
        }

        ::CloseHandle(waitOverlapped.hEvent);

        if (!workerContext->running.load())
        {
            break;
        }

        if (bytesReturned < sizeof(KSWORD_ARK_CALLBACK_EVENT_PACKET))
        {
            continue;
        }
        if (eventPacket.size < sizeof(KSWORD_ARK_CALLBACK_EVENT_PACKET) ||
            eventPacket.version != KSWORD_ARK_CALLBACK_PROTOCOL_VERSION)
        {
            continue;
        }

        QMetaObject::invokeMethod(this, [this, eventPacket]() {
            onEventArrivedOnUiThread(eventPacket);
        }, Qt::QueuedConnection);
    }

    resetDeviceHandle();
}

void CallbackPromptManager::onEventArrivedOnUiThread(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket)
{
    if (!m_running.load())
    {
        return;
    }

    if (shouldAutoAllowByRegex(eventPacket))
    {
        const bool answerOk = sendAnswerToDriver(eventPacket.eventGuid, KSWORD_ARK_DECISION_ALLOW);
        appendManagerLog(
            kernelText("kernel.callback.prompt.log.regex_auto_allow", QStringLiteral("事件 %1 触发 Regex 二次确认自动放行（%2）。"))
            .arg(callbackGuidToString(eventPacket.eventGuid))
            .arg(answerOk
                ? kernelText("kernel.callback.prompt.result.reply_success", QStringLiteral("回传成功"))
                : kernelText("kernel.callback.prompt.result.reply_failure", QStringLiteral("回传失败"))));
        return;
    }

    enqueueEvent(eventPacket);
}

void CallbackPromptManager::enqueueEvent(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket)
{
    {
        std::lock_guard<std::mutex> queueLock(m_queueMutex);
        m_eventQueue.push_back(eventPacket);
    }

    appendManagerLog(
        kernelText("kernel.callback.prompt.log.event_queued", QStringLiteral("收到待决策事件 %1，当前队列长度=%2。"))
        .arg(callbackGuidToString(eventPacket.eventGuid))
        .arg(static_cast<int>(m_eventQueue.size())));
    tryShowNextEvent();
}

bool CallbackPromptManager::shouldAutoAllowByRegex(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket) const
{
    // R0 的 Regex 热路径只做粗命中，真正的正则确认在 R3 完成。
    // 注册表和文件系统微过滤器都复用该策略：未匹配或表达式无效时自动放行。
    if ((eventPacket.callbackType != KSWORD_ARK_CALLBACK_TYPE_REGISTRY &&
        eventPacket.callbackType != KSWORD_ARK_CALLBACK_TYPE_MINIFILTER) ||
        eventPacket.action != KSWORD_ARK_RULE_ACTION_ASK_USER ||
        eventPacket.matchMode != KSWORD_ARK_MATCH_MODE_REGEX)
    {
        return false;
    }

    const QString initiatorPattern = fromWideBuffer(eventPacket.ruleInitiatorPattern);
    const QString targetPattern = fromWideBuffer(eventPacket.ruleTargetPattern);
    const QString initiatorPath = fromWideBuffer(eventPacket.initiatorPath);
    const QString targetPath = fromWideBuffer(eventPacket.targetPath);

    auto isMatched = [](const QString& patternText, const QString& sourceText, bool* validOut) -> bool {
        if (validOut != nullptr)
        {
            *validOut = true;
        }
        if (patternText.trimmed().isEmpty())
        {
            return true;
        }

        const QRegularExpression regexPattern(patternText);
        if (!regexPattern.isValid())
        {
            if (validOut != nullptr)
            {
                *validOut = false;
            }
            return false;
        }
        return regexPattern.match(sourceText).hasMatch();
    };

    bool initiatorValid = true;
    const bool initiatorMatched = isMatched(initiatorPattern, initiatorPath, &initiatorValid);
    bool targetValid = true;
    const bool targetMatched = isMatched(targetPattern, targetPath, &targetValid);

    if (!initiatorValid || !targetValid)
    {
        return true;
    }
    if (!initiatorMatched || !targetMatched)
    {
        return true;
    }
    return false;
}

void CallbackPromptManager::tryShowNextEvent()
{
    if (!m_running.load())
    {
        return;
    }
    if (m_hasCurrentEvent)
    {
        return;
    }
    if (m_popupDialog.isNull())
    {
        return;
    }

    KSWORD_ARK_CALLBACK_EVENT_PACKET nextEvent{};
    bool hasEvent = false;
    {
        std::lock_guard<std::mutex> queueLock(m_queueMutex);
        if (!m_eventQueue.empty())
        {
            nextEvent = m_eventQueue.front();
            m_eventQueue.pop_front();
            hasEvent = true;
        }
    }

    if (!hasEvent)
    {
        return;
    }

    m_currentEvent = nextEvent;
    m_hasCurrentEvent = true;
    m_remainingTimeoutMs = static_cast<qint64>(m_currentEvent.timeoutMs);
    if (m_remainingTimeoutMs <= 0)
    {
        m_remainingTimeoutMs = 5000;
    }

    applyPopupTheme();
    movePopupToBottomRight();

    m_popupDialog->show();
    m_popupDialog->raise();
    m_popupDialog->activateWindow();

    updatePopupContent(m_currentEvent);

    if (m_countdownTimer != nullptr)
    {
        m_countdownTimer->start();
    }
    updateCountdownLabel();
}

void CallbackPromptManager::updatePopupContent(const KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket)
{
    if (m_eventGuidValueLabel != nullptr)
    {
        m_eventGuidValueLabel->setText(callbackGuidToString(eventPacket.eventGuid));
    }
    if (m_callbackTypeValueLabel != nullptr)
    {
        m_callbackTypeValueLabel->setText(callbackTypeToDisplayText(eventPacket.callbackType));
    }
    if (m_operationValueLabel != nullptr)
    {
        m_operationValueLabel->setText(operationToDisplayText(eventPacket));
    }
    if (m_targetValueLabel != nullptr)
    {
        m_targetValueLabel->setText(fromWideBuffer(eventPacket.targetPath));
    }

    const QString initiatorPathText = fromWideBuffer(eventPacket.initiatorPath);
    const QString initiatorLineText = QStringLiteral("[%1]%2;")
        .arg(eventPacket.originatingPid)
        .arg(initiatorPathText.isEmpty() ? QStringLiteral("-") : initiatorPathText);
    if (m_initiatorValueLabel != nullptr)
    {
        int availableWidth = m_initiatorValueLabel->width();
        if (availableWidth <= 24 && !m_popupDialog.isNull())
        {
            availableWidth = qMax(180, m_popupDialog->width() - 300);
        }
        if (availableWidth <= 24)
        {
            availableWidth = 280;
        }

        const QFontMetrics fontMetrics(m_initiatorValueLabel->font());
        const QString elidedText = fontMetrics.elidedText(
            initiatorLineText,
            Qt::ElideMiddle,
            availableWidth);

        m_initiatorValueLabel->setToolTip(initiatorLineText);
        m_initiatorValueLabel->setText(
            QStringLiteral("<a href=\"pid:%1\" style=\"color:%2;text-decoration:underline;\">%3</a>")
            .arg(eventPacket.originatingPid)
            .arg(currentAccentColorHex())
            .arg(elidedText.toHtmlEscaped()));
    }
    if (m_initiatorIconLabel != nullptr)
    {
        const QIcon processIcon = resolveInitiatorProcessIcon(
            eventPacket.originatingPid,
            initiatorPathText);
        m_initiatorIconLabel->setPixmap(processIcon.pixmap(16, 16));
    }

    if (m_sessionIdValueLabel != nullptr)
    {
        m_sessionIdValueLabel->setText(QString::number(eventPacket.sessionId));
    }
    if (m_ruleValueLabel != nullptr)
    {
        m_ruleValueLabel->setText(
            QStringLiteral("[%1] %2 / [%3] %4")
            .arg(eventPacket.groupId)
            .arg(fromWideBuffer(eventPacket.groupName))
            .arg(eventPacket.ruleId)
            .arg(fromWideBuffer(eventPacket.ruleName)));
    }
}

void CallbackPromptManager::updateCountdownLabel()
{
    if (!m_hasCurrentEvent)
    {
        return;
    }

    qint64 remainingMs = m_remainingTimeoutMs;
    if (m_currentEvent.deadlineUtc100ns > 0ULL)
    {
        const qint64 deadline100ns = static_cast<qint64>(m_currentEvent.deadlineUtc100ns);
        const qint64 now100ns = static_cast<qint64>(currentUtc100ns());
        remainingMs = (deadline100ns - now100ns) / 10000LL;
    }
    if (remainingMs < 0)
    {
        remainingMs = 0;
    }
    m_remainingTimeoutMs = remainingMs;

    const quint32 defaultDecision =
        (m_currentEvent.defaultDecision == KSWORD_ARK_DECISION_DENY)
        ? KSWORD_ARK_DECISION_DENY
        : KSWORD_ARK_DECISION_ALLOW;
    if (m_allowButton != nullptr)
    {
        m_allowButton->setText(buildDecisionButtonText(
            KSWORD_ARK_DECISION_ALLOW,
            defaultDecision,
            m_remainingTimeoutMs));
    }
    if (m_denyButton != nullptr)
    {
        m_denyButton->setText(buildDecisionButtonText(
            KSWORD_ARK_DECISION_DENY,
            defaultDecision,
            m_remainingTimeoutMs));
    }

    if (m_remainingTimeoutMs <= 0)
    {
        finishCurrentEventWithDecision(defaultDecision, true);
    }
}

void CallbackPromptManager::finishCurrentEventWithDecision(quint32 decision, bool fromTimeoutOrClose)
{
    if (!m_hasCurrentEvent)
    {
        return;
    }

    if (m_countdownTimer != nullptr)
    {
        m_countdownTimer->stop();
    }

    quint32 finalDecision = decision;
    if (finalDecision != KSWORD_ARK_DECISION_ALLOW &&
        finalDecision != KSWORD_ARK_DECISION_DENY)
    {
        finalDecision =
            (m_currentEvent.defaultDecision == KSWORD_ARK_DECISION_DENY)
            ? KSWORD_ARK_DECISION_DENY
            : KSWORD_ARK_DECISION_ALLOW;
    }

    const bool answerOk = sendAnswerToDriver(m_currentEvent.eventGuid, finalDecision);
    appendManagerLog(
        kernelText("kernel.callback.prompt.log.event_decided", QStringLiteral("事件 %1 已决策为“%2”（来源=%3，回传=%4）。"))
        .arg(callbackGuidToString(m_currentEvent.eventGuid))
        .arg(callbackDecisionToDisplayText(finalDecision))
        .arg(fromTimeoutOrClose
            ? kernelText("kernel.callback.prompt.result.timeout_or_close", QStringLiteral("超时/关闭"))
            : kernelText("kernel.callback.prompt.result.user_click", QStringLiteral("用户点击")))
        .arg(answerOk
            ? kernelText("kernel.callback.prompt.result.success", QStringLiteral("成功"))
            : kernelText("kernel.callback.prompt.result.failure", QStringLiteral("失败"))));

    m_hasCurrentEvent = false;
    m_remainingTimeoutMs = 0;
    RtlZeroMemory(&m_currentEvent, sizeof(m_currentEvent));

    if (!m_popupDialog.isNull())
    {
        m_popupDialog->hide();
    }

    QTimer::singleShot(0, this, [this]() {
        tryShowNextEvent();
    });
}

void CallbackPromptManager::onPopupClosedByUser()
{
    if (!m_hasCurrentEvent)
    {
        if (!m_popupDialog.isNull())
        {
            m_popupDialog->hide();
        }
        return;
    }

    const quint32 fallbackDecision =
        (m_currentEvent.defaultDecision == KSWORD_ARK_DECISION_DENY)
        ? KSWORD_ARK_DECISION_DENY
        : KSWORD_ARK_DECISION_ALLOW;
    finishCurrentEventWithDecision(fallbackDecision, true);
}

bool CallbackPromptManager::sendAnswerToDriver(const KSWORD_ARK_GUID128& eventGuid, quint32 decision)
{
    KSWORD_ARK_CALLBACK_ANSWER_REQUEST answerRequest{};
    answerRequest.size = sizeof(answerRequest);
    answerRequest.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
    answerRequest.eventGuid = eventGuid;
    answerRequest.decision =
        (decision == KSWORD_ARK_DECISION_DENY)
        ? KSWORD_ARK_DECISION_DENY
        : KSWORD_ARK_DECISION_ALLOW;
    answerRequest.sourceSessionId = currentSessionId();
    answerRequest.answeredAtUtc100ns = currentUtc100ns();

    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.answerCallbackEvent(answerRequest);
    return result.ok;
}

void CallbackPromptManager::cancelAllPendingDecisionsBestEffort()
{
    const ksword::ark::DriverClient driverClient;
    (void)driverClient.cancelAllPendingCallbackDecisions();
}

quint64 CallbackPromptManager::currentUtc100ns() const
{
    FILETIME utcFileTime{};
    ::GetSystemTimePreciseAsFileTime(&utcFileTime);

    ULARGE_INTEGER utcValue{};
    utcValue.HighPart = utcFileTime.dwHighDateTime;
    utcValue.LowPart = utcFileTime.dwLowDateTime;
    return utcValue.QuadPart;
}

quint32 CallbackPromptManager::currentSessionId() const
{
    DWORD sessionId = 0;
    if (::ProcessIdToSessionId(::GetCurrentProcessId(), &sessionId) == FALSE)
    {
        return 0;
    }
    return static_cast<quint32>(sessionId);
}

void CallbackPromptManager::movePopupToBottomRight()
{
    if (m_popupDialog.isNull())
    {
        return;
    }

    QScreen* targetScreen = nullptr;
    if (m_hostWindow != nullptr &&
        m_hostWindow->windowHandle() != nullptr &&
        m_hostWindow->windowHandle()->screen() != nullptr)
    {
        targetScreen = m_hostWindow->windowHandle()->screen();
    }
    if (targetScreen == nullptr)
    {
        targetScreen = QGuiApplication::primaryScreen();
    }
    if (targetScreen == nullptr)
    {
        return;
    }

    const QRect availableRect = targetScreen->availableGeometry();
    const QSize popupSize = m_popupDialog->sizeHint().expandedTo(QSize(680, 360));
    const int popupX = availableRect.right() - popupSize.width() - 12;
    const int popupY = availableRect.bottom() - popupSize.height() - 12;
    m_popupDialog->resize(popupSize);
    m_popupDialog->move(popupX, popupY);
}
