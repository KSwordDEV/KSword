#include "BugcheckGuardPage.h"

#include "../../ArkDriverClient/ArkDriverClient.h"
#include "../../Internationalization/LanguageManager.h"
#include "../../theme.h"

#include <QCheckBox>
#include <QEvent>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QShowEvent>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>

#include <Windows.h>

#include <limits>

namespace
{
    bool sendWinPrintScreen()
    {
        INPUT inputs[4]{};
        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].ki.wVk = VK_LWIN;
        inputs[1].type = INPUT_KEYBOARD;
        inputs[1].ki.wVk = VK_SNAPSHOT;
        inputs[2].type = INPUT_KEYBOARD;
        inputs[2].ki.wVk = VK_SNAPSHOT;
        inputs[2].ki.dwFlags = KEYEVENTF_KEYUP;
        inputs[3].type = INPUT_KEYBOARD;
        inputs[3].ki.wVk = VK_LWIN;
        inputs[3].ki.dwFlags = KEYEVENTF_KEYUP;

        const UINT sent = SendInput(4U, inputs, sizeof(INPUT));
        if (sent != 4U) {
            INPUT releases[2]{};
            releases[0].type = INPUT_KEYBOARD;
            releases[0].ki.wVk = VK_SNAPSHOT;
            releases[0].ki.dwFlags = KEYEVENTF_KEYUP;
            releases[1].type = INPUT_KEYBOARD;
            releases[1].ki.wVk = VK_LWIN;
            releases[1].ki.dwFlags = KEYEVENTF_KEYUP;
            (void)SendInput(2U, releases, sizeof(INPUT));
        }
        return sent == 4U;
    }

    QString bugcheckGuardStatusText(
        const unsigned long status,
        const long lastStatus,
        const unsigned long stateFlags)
    {
        QString reason;
        const bool hvciEnabled =
            (stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_HVCI_ENABLED) != 0UL;
        const bool callbackRegistered =
            (stateFlags &
                KSWORD_ARK_BUGCHECK_GUARD_STATE_CALLBACK_REGISTERED) != 0UL;
        switch (status) {
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE:
            reason = callbackRegistered
                ? ks::i18n::text(
                    QStringLiteral(
                        "misc.experimental.bugcheck.status.active_callback"),
                    QStringLiteral(
                        "已启用：蓝屏前会暂停几秒，之后仍会蓝屏"))
                : ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.status.active"),
                    QStringLiteral("拦截已开启，等待蓝屏触发"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_INACTIVE:
            reason = hvciEnabled
                ? ks::i18n::text(
                    QStringLiteral(
                        "misc.experimental.bugcheck.status.inactive_hvci"),
                    QStringLiteral(
                        "内存完整性（HVCI）已开启：可以暂停，但不能忽略蓝屏"))
                : ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.status.inactive"),
                    QStringLiteral("未启用"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFIRMATION_NEEDED:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.confirm"),
                QStringLiteral("请先勾选“我已保存工作”"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_UNSUPPORTED:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.unsupported"),
                QStringLiteral("当前系统无法启用这个功能"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFLICT:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.conflict"),
                QStringLiteral("检测到其他内核修改，为避免冲突没有启用"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_PATCH_FAILED:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.patch_failed"),
                QStringLiteral("启用失败"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_BUSY:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.busy"),
                QStringLiteral("上一次操作还没结束，请先关闭后重试"));
            break;
        default:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.invalid"),
                QStringLiteral("无法读取状态"));
            break;
        }
        if (lastStatus == 0L) {
            return reason;
        }
        const QString errorCode = QStringLiteral("%1")
            .arg(
                static_cast<unsigned long>(lastStatus),
                8,
                16,
                QLatin1Char('0'))
            .toUpper();
        return QStringLiteral("%1（错误代码：0x%2）")
            .arg(reason, errorCode);
    }

    void showOpaqueMessage(
        QWidget* parent,
        const QMessageBox::Icon icon,
        const QString& title,
        const QString& message)
    {
        QMessageBox dialog(parent);
        dialog.setObjectName(QStringLiteral("ksBugcheckGuardMessageBox"));
        dialog.setStyleSheet(
            KswordTheme::OpaqueDialogStyle(dialog.objectName()));
        dialog.setIcon(icon);
        dialog.setWindowTitle(title);
        dialog.setText(message);
        dialog.setStandardButtons(QMessageBox::Ok);
        dialog.exec();
    }
}

namespace ks::misc
{
    BugcheckGuardPage::BugcheckGuardPage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
    }

    void BugcheckGuardPage::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        refreshStatus();
    }

    void BugcheckGuardPage::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event == nullptr)
        {
            return;
        }
        if (event->type() == QEvent::ApplicationPaletteChange
            || event->type() == QEvent::PaletteChange)
        {
            applyWarningBannerStyle();
        }
    }

    // applyWarningBannerStyle 作用：
    // - 输入：无，读取当前主题的语义色；
    // - 处理：下发风险横幅样式，构造期与主题切换后走同一条路径；
    // - 返回：无，横幅尚未创建时静默跳过。
    void BugcheckGuardPage::applyWarningBannerStyle()
    {
        if (m_warningLabel == nullptr)
        {
            return;
        }
        m_warningLabel->setStyleSheet(
            QStringLiteral(
                "QLabel{padding:10px;border:1px solid %1;border-radius:5px;"
                "background:%2;color:%3;font-weight:650;}")
                .arg(KswordTheme::ErrorHex())
                .arg(KswordTheme::ThemeColorName(
                    KswordTheme::WarningBackgroundColor()))
                .arg(KswordTheme::TextPrimaryHex()));
    }

    void BugcheckGuardPage::initializeUi()
    {
        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(12, 12, 12, 12);
        rootLayout->setSpacing(10);

        auto& language = ks::i18n::LanguageManager::instance();
        m_warningLabel = new QLabel(this);
        m_warningLabel->setWordWrap(true);
        applyWarningBannerStyle();
        language.bindText(
            m_warningLabel,
            QStringLiteral("misc.experimental.bugcheck.warning"),
            QStringLiteral(
                "⚠ 这个功能不能修好蓝屏，只能在蓝屏前暂停几秒。"
                "开启“内存完整性（HVCI）”时只能暂停，不能忽略。"
                "要尝试继续运行，必须先关闭“内存完整性”并重启；"
                "即使如此，电脑仍可能马上蓝屏、死机或丢失数据。只在测试机上使用。"));
        rootLayout->addWidget(m_warningLabel);

        m_persistenceLabel = new QLabel(this);
        m_persistenceLabel->setWordWrap(true);
        m_persistenceLabel->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(KswordTheme::TextSecondaryHex()));
        language.bindText(
            m_persistenceLabel,
            QStringLiteral("misc.experimental.bugcheck.persistence"),
            QStringLiteral(
                "开启后持续拦截：尝试继续运行时保留 Hook，后续触发仍会拦截，直到手动关闭。仅暂停模式仍会在暂停后进入蓝屏。"));
        rootLayout->addWidget(m_persistenceLabel);

        auto* controlGroup = new QGroupBox(this);
        language.bindText(
            controlGroup,
            QStringLiteral("misc.experimental.bugcheck.control.title"),
            QStringLiteral("实验性控制"));
        auto* controlLayout = new QVBoxLayout(controlGroup);
        auto* delayLayout = new QHBoxLayout();
        m_delayLabel = new QLabel(controlGroup);
        language.bindText(
            m_delayLabel,
            QStringLiteral("misc.experimental.bugcheck.delay"),
            QStringLiteral("蓝屏前暂停："));
        m_delaySpin = new QSpinBox(controlGroup);
        m_delaySpin->setRange(
            static_cast<int>(KSWORD_ARK_BUGCHECK_GUARD_MIN_DELAY_SECONDS),
            std::numeric_limits<int>::max());
        m_delaySpin->setValue(10);
        language.bindSuffix(
            m_delaySpin,
            QStringLiteral("misc.experimental.bugcheck.delay.suffix"),
            QStringLiteral(" 秒"));
        m_delaySpin->setToolTip(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.delay.tooltip"),
                QStringLiteral(
                    "没有 30 秒上限。时间设得很长时，电脑会一直卡在蓝屏流程里。")));
        delayLayout->addWidget(m_delayLabel);
        delayLayout->addWidget(m_delaySpin);
        delayLayout->addStretch(1);
        controlLayout->addLayout(delayLayout);

        m_acknowledgeCheck = new QCheckBox(controlGroup);
        language.bindText(
            m_acknowledgeCheck,
            QStringLiteral("misc.experimental.bugcheck.ack"),
            QStringLiteral(
                "我已保存工作，并知道电脑仍可能立即蓝屏或丢失数据"));
        controlLayout->addWidget(m_acknowledgeCheck);

        m_tryIgnoreErrorCheck = new QCheckBox(controlGroup);
        m_tryIgnoreErrorCheck->setChecked(true);
        language.bindText(
            m_tryIgnoreErrorCheck,
            QStringLiteral("misc.experimental.bugcheck.try_ignore"),
            QStringLiteral(
                "暂停后尝试继续运行（仅关闭 HVCI 时可用，极危险）"));
        m_tryIgnoreErrorCheck->setToolTip(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.try_ignore.tooltip"),
                QStringLiteral(
                    "开启“内存完整性（HVCI）”时不可用。关闭后强行继续也可能马上再次蓝屏、"
                    "死机或损坏数据。")));
        controlLayout->addWidget(m_tryIgnoreErrorCheck);

        m_screenshotOnTriggerCheck = new QCheckBox(controlGroup);
        language.bindText(
            m_screenshotOnTriggerCheck,
            QStringLiteral("misc.experimental.bugcheck.screenshot"),
            QStringLiteral("蓝屏前尝试截图（仅关闭 HVCI 时可用）"));
        m_screenshotOnTriggerCheck->setToolTip(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.screenshot.tooltip"),
                QStringLiteral(
                    "这里只是模拟 Win+PrintScreen。系统已经卡住时不会成功，"
                    "也无法确认截图是否保存。")));
        controlLayout->addWidget(m_screenshotOnTriggerCheck);

        m_screenshotPollTimer = new QTimer(this);
        m_screenshotPollTimer->setInterval(10);
        m_screenshotPollTimer->setTimerType(Qt::PreciseTimer);

        auto* actionLayout = new QHBoxLayout();
        m_refreshButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
            QString(),
            controlGroup);
        m_enableButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_start.svg")),
            QString(),
            controlGroup);
        m_enableButton->setCheckable(true);
        language.bindText(
            m_refreshButton,
            QStringLiteral("misc.experimental.bugcheck.refresh"),
            QStringLiteral("刷新状态"));
        language.bindText(
            m_enableButton,
            QStringLiteral("misc.experimental.bugcheck.switch"),
            QStringLiteral("拦截开关"));
        for (QPushButton* button :
             { m_refreshButton, m_enableButton }) {
            button->setStyleSheet(KswordTheme::ThemedButtonStyle());
        }
        actionLayout->addWidget(m_refreshButton);
        actionLayout->addWidget(m_enableButton);
        actionLayout->addStretch(1);
        controlLayout->addLayout(actionLayout);
        rootLayout->addWidget(controlGroup);

        auto* statusGroup = new QGroupBox(this);
        language.bindText(
            statusGroup,
            QStringLiteral("misc.experimental.bugcheck.status.title"),
            QStringLiteral("当前状态"));
        auto* statusLayout = new QVBoxLayout(statusGroup);
        m_statusLabel = new QLabel(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.waiting"),
                QStringLiteral("正在读取状态…")),
            statusGroup);
        m_statusLabel->setWordWrap(true);
        m_statusLabel->setStyleSheet(
            QStringLiteral("font-size:15px;font-weight:650;color:%1;")
                .arg(KswordTheme::TextPrimaryHex()));
        m_detailLabel = new QLabel(statusGroup);
        m_detailLabel->setWordWrap(true);
        m_detailLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        statusLayout->addWidget(m_statusLabel);
        statusLayout->addWidget(m_detailLabel);
        rootLayout->addWidget(statusGroup);
        rootLayout->addStretch(1);

        connect(
            m_refreshButton,
            &QPushButton::clicked,
            this,
            [this]() { refreshStatus(); });
        connect(
            m_enableButton,
            &QPushButton::clicked,
            this,
            [this]() {
                if (m_active || m_triggered) {
                    disableGuard();
                }
                else {
                    enableGuard();
                }
            });
        connect(
            m_acknowledgeCheck,
            &QCheckBox::toggled,
            this,
            [this](const bool) { updateButtons(); });
        connect(
            m_screenshotPollTimer,
            &QTimer::timeout,
            this,
            [this]() { pollForScreenshot(); });
        updateButtons();
    }

    void BugcheckGuardPage::refreshStatus()
    {
        if (m_busy) {
            return;
        }
        setBusy(true);
        ksword::ark::DriverClient client;
        const auto result = client.configureBugcheckGuard(
            KSWORD_ARK_BUGCHECK_GUARD_ACTION_QUERY);
        setBusy(false);
        if (!result.io.ok) {
            m_supported = false;
            m_active = false;
            m_hvciEnabled = false;
            m_callbackBackend = false;
            m_statusLabel->setText(
                result.unsupported
                    ? ks::i18n::text(
                        QStringLiteral("misc.experimental.bugcheck.driver_old"),
                        QStringLiteral("当前 R0 驱动不支持蓝屏缓冲，请更新驱动"))
                    : ks::i18n::text(
                        QStringLiteral("misc.experimental.bugcheck.query_failed"),
                        QStringLiteral("无法读取 R0 蓝屏缓冲状态")));
            m_detailLabel->setText(
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.detail.io"),
                    QStringLiteral("Win32=%1；%2"))
                    .arg(result.io.win32Error)
                    .arg(QString::fromStdString(result.io.message)));
            updateButtons();
            return;
        }
        m_supported = true;
        updateFromResponse(result.response);
    }

    void BugcheckGuardPage::enableGuard()
    {
        if (m_busy || !m_acknowledgeCheck->isChecked()) {
            showOpaqueMessage(
                this,
                QMessageBox::Warning,
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.title"),
                    QStringLiteral("蓝屏缓冲（实验性）")),
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.ack_required"),
                    QStringLiteral("请先保存工作并勾选风险确认。")));
            return;
        }
        m_screenshotPollTimer->stop();
        m_screenshotDriverHandle.reset();
        m_screenshotWatcherArmed = false;
        setBusy(true);
        ksword::ark::DriverClient client;
        const auto result = client.configureBugcheckGuard(
            KSWORD_ARK_BUGCHECK_GUARD_ACTION_ENABLE,
            static_cast<unsigned long>(m_delaySpin->value()),
            true,
            m_tryIgnoreErrorCheck->isChecked());
        setBusy(false);
        if (result.io.ok &&
            result.response.status ==
                KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE) {
            const bool callbackBackend =
                (result.response.stateFlags &
                    KSWORD_ARK_BUGCHECK_GUARD_STATE_CALLBACK_REGISTERED) != 0UL;
            m_screenshotWatcherArmed =
                !callbackBackend && m_screenshotOnTriggerCheck->isChecked();
            m_screenshotAttempted = false;
            m_screenshotInputAccepted = false;
            if (m_screenshotWatcherArmed) {
                m_screenshotDriverHandle = client.open();
                m_screenshotPollTimer->start();
            }
        }
        if (!result.io.ok ||
            result.response.status != KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE) {
            showOpaqueMessage(
                this,
                QMessageBox::Critical,
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.title"),
                    QStringLiteral("蓝屏缓冲（实验性）")),
                result.io.ok
                    ? bugcheckGuardStatusText(
                        result.response.status,
                        result.response.lastStatus,
                        result.response.stateFlags)
                    : QString::fromStdString(result.io.message));
        }
        refreshStatus();
    }

    void BugcheckGuardPage::disableGuard()
    {
        if (m_busy) {
            return;
        }
        setBusy(true);
        ksword::ark::DriverClient client;
        const auto result = client.configureBugcheckGuard(
            KSWORD_ARK_BUGCHECK_GUARD_ACTION_DISABLE);
        setBusy(false);
        if (!result.io.ok || result.response.status != KSWORD_ARK_BUGCHECK_GUARD_STATUS_INACTIVE) {
            showOpaqueMessage(
                this,
                QMessageBox::Critical,
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.title"),
                    QStringLiteral("蓝屏缓冲（实验性）")),
                result.io.ok
                    ? bugcheckGuardStatusText(result.response.status, result.response.lastStatus, result.response.stateFlags)
                    : QString::fromStdString(result.io.message));
        }
        refreshStatus();
    }

    void BugcheckGuardPage::pollForScreenshot()
    {
        if (!m_screenshotWatcherArmed || m_screenshotAttempted) {
            m_screenshotPollTimer->stop();
            m_screenshotDriverHandle.reset();
            return;
        }

        ksword::ark::DriverClient client;
        if (!m_screenshotDriverHandle.isValid()) {
            m_screenshotDriverHandle = client.open();
        }
        if (!m_screenshotDriverHandle.isValid()) {
            return;
        }
        const auto result = client.configureBugcheckGuard(
            KSWORD_ARK_BUGCHECK_GUARD_ACTION_QUERY,
            0UL,
            false,
            false,
            &m_screenshotDriverHandle);
        if (!result.io.ok) {
            m_screenshotDriverHandle.reset();
            return;
        }

        const bool fired =
            (result.response.stateFlags &
             KSWORD_ARK_BUGCHECK_GUARD_STATE_FIRED) != 0UL;
        if (fired) {
            attemptScreenshot();
            updateFromResponse(result.response);
            return;
        }

        const bool active =
            (result.response.stateFlags &
             KSWORD_ARK_BUGCHECK_GUARD_STATE_ACTIVE) != 0UL;
        if (!active) {
            m_screenshotPollTimer->stop();
            m_screenshotDriverHandle.reset();
            m_screenshotWatcherArmed = false;
        }
    }

    void BugcheckGuardPage::attemptScreenshot()
    {
        if (!m_screenshotWatcherArmed || m_screenshotAttempted) {
            return;
        }
        m_screenshotAttempted = true;
        m_screenshotInputAccepted = sendWinPrintScreen();
        m_screenshotPollTimer->stop();
        m_screenshotDriverHandle.reset();
    }

    void BugcheckGuardPage::updateFromResponse(
        const KSWORD_ARK_BUGCHECK_GUARD_RESPONSE& response)
    {
        const bool fired =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_FIRED) != 0UL;
        const bool ignored =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_ERROR_IGNORED) != 0UL;
        const bool executing =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_HOOK_EXECUTING) != 0UL;
        const bool tryIgnore =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_TRY_IGNORE_ERROR) != 0UL;
        m_hvciEnabled =
            (response.stateFlags &
                KSWORD_ARK_BUGCHECK_GUARD_STATE_HVCI_ENABLED) != 0UL;
        m_callbackBackend =
            (response.stateFlags &
                KSWORD_ARK_BUGCHECK_GUARD_STATE_CALLBACK_REGISTERED) != 0UL;
        if (m_hvciEnabled) {
            m_tryIgnoreErrorCheck->setChecked(false);
            m_screenshotOnTriggerCheck->setChecked(false);
        }
        m_active =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_ACTIVE) != 0UL;
        if (m_active || fired) {
            const unsigned long maximumUiDelay =
                static_cast<unsigned long>(std::numeric_limits<int>::max());
            m_delaySpin->setValue(
                response.delaySeconds > maximumUiDelay
                    ? std::numeric_limits<int>::max()
                    : static_cast<int>(response.delaySeconds));
            m_tryIgnoreErrorCheck->setChecked(tryIgnore || ignored);
        }
        m_triggered = fired || ignored || executing;
        if (fired) {
            attemptScreenshot();
        }
        if (m_screenshotWatcherArmed &&
            !m_screenshotAttempted &&
            m_active) {
            m_screenshotPollTimer->start();
        }
        else if (m_screenshotAttempted ||
                 (!m_active && !fired && !executing)) {
            m_screenshotPollTimer->stop();
        }
        if (!m_active && !fired && !executing) {
            m_screenshotDriverHandle.reset();
            m_screenshotWatcherArmed = false;
        }

        if (ignored) {
            m_statusLabel->setText(
                m_active
                    ? ks::i18n::text(
                        QStringLiteral("misc.experimental.bugcheck.status.ignored_active"),
                        QStringLiteral("已尝试继续运行，拦截仍保持开启；这不代表故障已恢复。"))
                    : ks::i18n::text(
                        QStringLiteral("misc.experimental.bugcheck.status.ignored"),
                        QStringLiteral("已尝试继续运行。请立即保存文件并重启，系统可能随时再次崩溃。")));
        }
        else if (executing) {
            m_statusLabel->setText(
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.status.executing"),
                    QStringLiteral("正在处理蓝屏，系统可能随时崩溃。")));
        }
        else if (fired) {
            m_statusLabel->setText(
                m_callbackBackend
                    ? ks::i18n::text(
                        QStringLiteral(
                            "misc.experimental.bugcheck.status.fired_callback"),
                        QStringLiteral(
                            "暂停已结束，Windows 会继续蓝屏。"))
                    : ks::i18n::text(
                        QStringLiteral("misc.experimental.bugcheck.status.fired"),
                        QStringLiteral("已触发拦截；当前开关状态以驱动回读为准。")));
        }
        else {
            m_statusLabel->setText(
                bugcheckGuardStatusText(
                    response.status,
                    response.lastStatus,
                    response.stateFlags));
        }
        if (m_screenshotWatcherArmed) {
            const QString screenshotStatus = m_screenshotAttempted
                ? m_screenshotInputAccepted
                    ? ks::i18n::text(
                        QStringLiteral(
                            "misc.experimental.bugcheck.screenshot.status.sent"),
                        QStringLiteral(
                            "已发送 Win+PrintScreen；Windows 是否真正保存截图无法确认。"))
                    : ks::i18n::text(
                        QStringLiteral(
                            "misc.experimental.bugcheck.screenshot.status.failed"),
                        QStringLiteral(
                            "发送 Win+PrintScreen 失败；系统可能已无法处理用户态输入。"))
                : ks::i18n::text(
                    QStringLiteral(
                        "misc.experimental.bugcheck.screenshot.status.waiting"),
                    QStringLiteral("截屏监视已就绪，等待 Hook 命中。"));
            m_statusLabel->setText(
                QStringLiteral("%1\n%2")
                    .arg(m_statusLabel->text(), screenshotStatus));
        }
        m_statusLabel->setStyleSheet(
            QStringLiteral("font-size:15px;font-weight:650;color:%1;")
                .arg(ignored || executing
                    ? KswordTheme::ErrorHex()
                    : m_active
                        ? KswordTheme::WarningHex()
                        : KswordTheme::SuccessHex()));
        const QString backendText = m_callbackBackend || m_hvciEnabled
            ? ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.backend.callback"),
                QStringLiteral("HVCI 安全延时（不能忽略）"))
            : ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.backend.hook"),
                QStringLiteral("实验拦截（可尝试继续）"));
        m_detailLabel->setText(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.detail.state"),
                QStringLiteral(
                    "工作方式：%1；暂停：%4 秒；结束后：%5\n"
                    "技术信息：KeBugCheckEx=0x%2，状态位=0x%3，NTSTATUS=0x%6"))
                .arg(backendText)
                .arg(response.targetAddress, 16, 16, QLatin1Char('0'))
                .arg(response.stateFlags, 8, 16, QLatin1Char('0'))
                .arg(response.delaySeconds)
                .arg(
                    tryIgnore || ignored
                        ? ks::i18n::text(
                            QStringLiteral("misc.experimental.bugcheck.mode.ignore"),
                            QStringLiteral("尝试继续运行"))
                        : ks::i18n::text(
                            QStringLiteral("misc.experimental.bugcheck.mode.normal"),
                            QStringLiteral("继续蓝屏")))
                .arg(
                    static_cast<unsigned long>(response.lastStatus),
                    8,
                    16,
                    QLatin1Char('0')));
        updateButtons();
    }

    void BugcheckGuardPage::updateButtons()
    {
        m_refreshButton->setEnabled(!m_busy);
        m_enableButton->setEnabled(
            !m_busy && m_supported &&
            (m_active || m_triggered || m_acknowledgeCheck->isChecked()));
        m_enableButton->setChecked(m_active || m_triggered);
        m_delaySpin->setEnabled(!m_busy && !m_active && !m_triggered);
        m_acknowledgeCheck->setEnabled(!m_busy && !m_active && !m_triggered);
        m_tryIgnoreErrorCheck->setEnabled(
            !m_busy && !m_active && !m_triggered && !m_hvciEnabled);
        m_screenshotOnTriggerCheck->setEnabled(
            !m_busy && !m_active && !m_triggered && !m_hvciEnabled);
    }

    void BugcheckGuardPage::setBusy(const bool busy)
    {
        m_busy = busy;
        updateButtons();
    }
}
