#include "SystemTimePage.h"
#include "../../UI/ToolbarMetrics.h"

#include "../../ArkDriverClient/ArkDriverClient.h"
#include "../../Internationalization/LanguageManager.h"
#include "../../theme.h"

#include <QCheckBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHideEvent>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QRadioButton>
#include <QShowEvent>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>

namespace
{
    constexpr int kStatusRefreshIntervalMs = 2000;
    constexpr int kClockRefreshIntervalMs = 250;
    constexpr int kTimeSyncTimeoutMs = 15000;

    // addressText：把 R0 诊断地址转换为固定宽度十六进制文本。
    QString addressText(const unsigned long long address)
    {
        return address == 0ULL
            ? ks::i18n::sourceText(QStringLiteral("不可用"))
            : QStringLiteral("0x%1")
                .arg(address, 16, 16, QLatin1Char('0'))
                .toUpper();
    }

    // hexValueText：显示允许为零的 Hyper-V 锁、倍率或偏置值。
    QString hexValueText(const unsigned long long value)
    {
        return QStringLiteral("0x%1")
            .arg(value, 16, 16, QLatin1Char('0'))
            .toUpper();
    }
    // operationStatusText：把稳定协议状态码转换为场景化错误提示。
    QString operationStatusText(
        const unsigned long status,
        const long lastStatus)
    {
        QString reason;
        switch (status)
        {
        case KSWORD_ARK_SYSTEM_TIME_STATUS_OK:
            reason = QStringLiteral("操作成功");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_CONFIRMATION_REQUIRED:
            reason = QStringLiteral("安全策略要求重新确认");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_UNSUPPORTED_BUILD:
        case KSWORD_ARK_SYSTEM_TIME_STATUS_RESOLVE_FAILED:
            reason = QStringLiteral("当前 Windows 构建无法安全解析计时器");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_PATCH_FAILED:
            reason = QStringLiteral("计时器接管失败，已回滚");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT:
            reason = QStringLiteral("检测到其它计时器钩子，已失败关闭");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_STALE_GENERATION:
            reason = QStringLiteral("状态已被其它控制者更新，请刷新后重试");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_NOT_PRESENT:
            reason = QStringLiteral("未检测到 Microsoft Hyper-V，未启用变速");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_PAGE_UNAVAILABLE:
            reason = QStringLiteral("Hyper-V 共享 QPC 页不可用，未启用变速");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_VALIDATION_FAILED:
            reason = QStringLiteral("Hyper-V 共享 QPC 页校验冲突，已失败关闭");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_WRITE_FAILED:
            reason = QStringLiteral("Hyper-V 共享 QPC 页写入失败，已回滚");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST:
            reason = QStringLiteral("倍率或控制参数无效");
            break;
        default:
            reason = QStringLiteral("系统变速状态不可用");
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("%1；NTSTATUS=0x%2"))
            .arg(ks::i18n::sourceText(reason))
            .arg(
                static_cast<unsigned long>(lastStatus),
                8,
                16,
                QLatin1Char('0'))
            .toUpper();
    }

    // showOpaqueMessage：为高风险页面的消息框显式设置不透明主题背景。
    void showOpaqueMessage(
        QWidget* parent,
        const QMessageBox::Icon icon,
        const QString& title,
        const QString& text)
    {
        QMessageBox messageBox(parent);
        messageBox.setObjectName(
            QStringLiteral("ksSystemTimeMessageBox"));
        messageBox.setStyleSheet(
            KswordTheme::OpaqueDialogStyle(
                messageBox.objectName()));
        messageBox.setIcon(icon);
        messageBox.setWindowTitle(title);
        messageBox.setText(text);
        messageBox.setStandardButtons(QMessageBox::Ok);
        messageBox.exec();
    }
}

namespace ks::misc
{
    SystemTimePage::SystemTimePage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
        initializeConnections();
    }

    void SystemTimePage::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        refreshStatus();
        m_refreshTimer->start();
        updateCalibratedTimeDisplay();
        m_clockTimer->start();
    }

    void SystemTimePage::hideEvent(QHideEvent* event)
    {
        m_refreshTimer->stop();
        m_clockTimer->stop();
        QWidget::hideEvent(event);
    }

    void SystemTimePage::changeEvent(QEvent* event)
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
    // - 处理：下发永久警告横幅样式，构造期与主题切换后走同一条路径；
    // - 返回：无，横幅尚未创建时静默跳过。
    void SystemTimePage::applyWarningBannerStyle()
    {
        if (m_warningLabel == nullptr)
        {
            return;
        }
        m_warningLabel->setStyleSheet(
            QStringLiteral(
                "QLabel{padding:10px;border:1px solid %1;border-radius:5px;"
                "background:%2;color:%3;font-weight:600;}")
                .arg(KswordTheme::WarningHex())
                .arg(KswordTheme::ThemeColorName(
                    KswordTheme::WarningBackgroundColor()))
                .arg(KswordTheme::TextPrimaryHex()));
    }

    void SystemTimePage::initializeUi()
    {
        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(12, 12, 12, 12);
        rootLayout->setSpacing(10);

        // 永久警告不随确认消失，确保活动状态下始终能看到风险边界。
        m_warningLabel = new QLabel(
            QStringLiteral(
                "⚠ 系统全局变速会接管内核性能计数器；Hyper-V 后端还会改写"
                "当前 Windows 分区的共享 QPC 倍率与偏置。它可能导致动画、超时、"
                "音视频、网络协议、游戏和安全软件异常，"
                "严重时会造成冻结或蓝屏。请先保存工作，强烈建议仅在虚拟机中使用。"),
            this);
        m_warningLabel->setWordWrap(true);
        applyWarningBannerStyle();
        rootLayout->addWidget(m_warningLabel);

        m_persistenceLabel = new QLabel(
            QStringLiteral(
                "关闭页面不会自动恢复速度；请使用“恢复 1x”。"
                "恢复 1x 会保留连续计数接管以避免回跳；驱动卸载时才恢复原始路径。"),
            this);
        m_persistenceLabel->setWordWrap(true);
        m_persistenceLabel->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(KswordTheme::TextSecondaryHex()));
        rootLayout->addWidget(m_persistenceLabel);

        // 后端组要求用户明确选择 Hyper-V 共享页或原 HAL 兼容路径。
        auto* backendGroup = new QGroupBox(
            QStringLiteral("计时后端"),
            this);
        auto* backendLayout = new QVBoxLayout(backendGroup);
        m_hypervBackendRadio = new QRadioButton(
            QStringLiteral("Hyper-V 共享 QPC（推荐）"),
            backendGroup);
        m_hypervBackendRadio->setToolTip(
            QStringLiteral(
                "保留用户态 QPC 快速路径，接管 Hyper-V 共享倍率与偏置，并同步内核 HAL 计数器"));
        auto* hypervDescription = new QLabel(
            QStringLiteral(
                "要求 Microsoft Hyper-V 与共享 QPC 页均可用。用户态通过共享页变速，"
                "内核态通过 HAL 计数器钩子同步；任一校验失败都不会静默切到其它后端。"),
            backendGroup);
        hypervDescription->setWordWrap(true);
        hypervDescription->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(KswordTheme::TextSecondaryHex()));

        m_halBackendRadio = new QRadioButton(
            QStringLiteral("HAL 兼容后端（显式回退）"),
            backendGroup);
        m_halBackendRadio->setToolTip(
            QStringLiteral(
                "关闭用户态 QPC 快速旁路，并使用原有 HAL 计数器接管路径"));
        auto* halDescription = new QLabel(
            QStringLiteral(
                "保留原有实现：关闭用户态快速旁路，使用户态和内核态都进入 HAL 计数器钩子。"
                "仅在你明确选择后启用，不会由 Hyper-V 后端自动降级。"),
            backendGroup);
        halDescription->setWordWrap(true);
        halDescription->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(KswordTheme::TextSecondaryHex()));
        m_hypervBackendRadio->setChecked(true);
        backendLayout->addWidget(m_hypervBackendRadio);
        backendLayout->addWidget(hypervDescription);
        backendLayout->addWidget(m_halBackendRadio);
        backendLayout->addWidget(halDescription);
        rootLayout->addWidget(backendGroup);
        // 模式组明确区分兼容定位和写入前增强校验定位。
        auto* schemeGroup = new QGroupBox(
            QStringLiteral("实现模式"),
            this);
        auto* schemeLayout = new QVBoxLayout(schemeGroup);
        m_compatRadio = new QRadioButton(
            QStringLiteral("兼容模式（默认）"),
            schemeGroup);
        m_compatRadio->setToolTip(
            QStringLiteral(
                "按当前系统版本特征定位并接管 HAL 计数器函数指针"));
        auto* compatDescription = new QLabel(
            QStringLiteral(
                "使用基于系统版本特征的 HAL 计数器函数指针接管路径，"
                "兼容性最高；仍保留 KSword 的恢复与冲突监控。"),
            schemeGroup);
        compatDescription->setWordWrap(true);
        compatDescription->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(KswordTheme::TextSecondaryHex()));

        m_guardedResolutionRadio = new QRadioButton(
            QStringLiteral("安全模式（即使安全一些但是仍然可能导致严重后果）"),
            schemeGroup);
        m_guardedResolutionRadio->setToolTip(
            QStringLiteral(
                "使用相同接管原理，但在写入前验证描述符、函数槽和处理器表"));
        auto* guardedDescription = new QLabel(
            QStringLiteral(
                "使用相同接管原理，但在写入前额外验证描述符、函数槽和处理器表；"
                "校验不通过时拒绝启用。该模式只能降低部分风险，仍可能冻结或蓝屏。"),
            schemeGroup);
        guardedDescription->setWordWrap(true);
        guardedDescription->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(KswordTheme::TextSecondaryHex()));
        m_compatRadio->setChecked(true);
        schemeLayout->addWidget(m_compatRadio);
        schemeLayout->addWidget(compatDescription);
        schemeLayout->addWidget(m_guardedResolutionRadio);
        schemeLayout->addWidget(guardedDescription);
        rootLayout->addWidget(schemeGroup);

        // 倍率组只提供同一原理下的 N 倍加速和 1/N 减速。
        auto* controlGroup = new QGroupBox(
            QStringLiteral("计时倍率"),
            this);
        auto* controlLayout = new QVBoxLayout(controlGroup);
        auto* modeLayout = new QHBoxLayout();
        m_speedUpRadio = new QRadioButton(
            QStringLiteral("加速 N 倍"),
            controlGroup);
        m_slowDownRadio = new QRadioButton(
            QStringLiteral("减速到 1/N"),
            controlGroup);
        m_speedUpRadio->setChecked(true);
        m_factorSpin = new QSpinBox(controlGroup);
        m_factorSpin->setRange(
            static_cast<int>(KSWORD_ARK_SYSTEM_TIME_MIN_FACTOR),
            static_cast<int>(KSWORD_ARK_SYSTEM_TIME_MAX_FACTOR));
        m_factorSpin->setValue(2);
        m_factorSpin->setSuffix(QStringLiteral(" ×"));
        m_factorSpin->setToolTip(
            QStringLiteral("设置 2 到 64 的整数倍率"));
        modeLayout->addWidget(m_speedUpRadio);
        modeLayout->addWidget(m_slowDownRadio);
        // 单行参数的组间距由共享工具条统一提供。
        modeLayout->addWidget(new QLabel(
            QStringLiteral("倍率："),
            controlGroup));
        modeLayout->addWidget(m_factorSpin);
        modeLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(modeLayout);
        controlLayout->addLayout(modeLayout);

        m_acknowledgeCheck = new QCheckBox(
            QStringLiteral(
                "我已保存工作，并理解该功能可能使系统不稳定"),
            controlGroup);
        controlLayout->addWidget(m_acknowledgeCheck);

        auto* buttonLayout = new QHBoxLayout();
        m_refreshButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
            QStringLiteral("刷新状态"),
            controlGroup);
        m_timeSyncButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
            QStringLiteral("从时间服务器更新时间"),
            controlGroup);
        m_applyButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_start.svg")),
            QStringLiteral("应用变速"),
            controlGroup);
        m_resetButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
            QStringLiteral("恢复 1x"),
            controlGroup);
        m_refreshButton->setToolTip(
            QStringLiteral("重新查询 R0 计时器接管状态"));
        m_timeSyncButton->setToolTip(
            QStringLiteral("调用 Windows 时间服务，从已配置的时间服务器立即同步系统时间"));
        m_applyButton->setToolTip(
            QStringLiteral("经过双重确认后应用当前模式和倍率"));
        m_resetButton->setToolTip(
            QStringLiteral("立即停止变速并以连续计数保持 1x"));
        for (QPushButton* button :
             { m_refreshButton, m_timeSyncButton, m_applyButton, m_resetButton })
        {
            button->setStyleSheet(
                KswordTheme::ThemedButtonStyle());
        }
        buttonLayout->addWidget(m_refreshButton);
        buttonLayout->addWidget(m_timeSyncButton);
        buttonLayout->addWidget(m_applyButton);
        buttonLayout->addWidget(m_resetButton);
        buttonLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(buttonLayout);
        controlLayout->addLayout(buttonLayout);
        rootLayout->addWidget(controlGroup);

        // 状态组同时显示用户结论与可核对的解析证据。
        auto* statusGroup = new QGroupBox(
            QStringLiteral("当前状态"),
            this);
        auto* statusLayout = new QVBoxLayout(statusGroup);
        m_calibratedTimeLabel = new QLabel(
            QStringLiteral("校准后时间：等待倍率状态"),
            statusGroup);
        m_calibratedTimeLabel->setStyleSheet(
            QStringLiteral("font-size:15px;font-weight:650;color:%1;")
                .arg(KswordTheme::PrimaryBlueHex));
        m_currentModeLabel = new QLabel(
            QStringLiteral("当前：等待查询"),
            statusGroup);
        m_currentModeLabel->setStyleSheet(
            QStringLiteral("font-size:16px;font-weight:700;color:%1;")
                .arg(KswordTheme::TextPrimaryHex()));
        m_backendLabel = new QLabel(statusGroup);
        m_backendLabel->setWordWrap(true);
        m_diagnosticLabel = new QLabel(statusGroup);
        m_diagnosticLabel->setWordWrap(true);
        m_diagnosticLabel->setTextInteractionFlags(
            Qt::TextSelectableByMouse);
        m_operationLabel = new QLabel(
            QStringLiteral("尚未查询 R0 状态"),
            statusGroup);
        m_operationLabel->setWordWrap(true);
        statusLayout->addWidget(m_calibratedTimeLabel);
        statusLayout->addWidget(m_currentModeLabel);
        statusLayout->addWidget(m_backendLabel);
        statusLayout->addWidget(m_diagnosticLabel);
        statusLayout->addWidget(m_operationLabel);
        rootLayout->addWidget(statusGroup);
        rootLayout->addStretch(1);

        m_refreshTimer = new QTimer(this);
        m_refreshTimer->setInterval(
            kStatusRefreshIntervalMs);
        m_clockTimer = new QTimer(this);
        m_clockTimer->setInterval(kClockRefreshIntervalMs);
        resetCalibratedClock();
        updateButtons();
    }

    void SystemTimePage::initializeConnections()
    {
        connect(
            m_timeSyncButton,
            &QPushButton::clicked,
            this,
            [this]() { synchronizeFromTimeServer(); });
        connect(
            m_refreshButton,
            &QPushButton::clicked,
            this,
            [this]() { refreshStatus(); });
        connect(
            m_applyButton,
            &QPushButton::clicked,
            this,
            [this]() { applyRequestedMode(); });
        connect(
            m_resetButton,
            &QPushButton::clicked,
            this,
            [this]() { resetSystemTime(); });
        connect(
            m_acknowledgeCheck,
            &QCheckBox::toggled,
            this,
            [this](const bool) { updateButtons(); });
        connect(
            m_hypervBackendRadio,
            &QRadioButton::toggled,
            this,
            [this](const bool) { updateButtons(); });
        connect(
            m_refreshTimer,
            &QTimer::timeout,
            this,
            [this]() { refreshStatus(); });
        connect(
            m_clockTimer,
            &QTimer::timeout,
            this,
            [this]() { updateCalibratedTimeDisplay(); });
    }

    void SystemTimePage::refreshStatus()
    {
        if (m_busy)
        {
            return;
        }
        setBusy(true);
        ksword::ark::DriverClient client;
        const auto result = client.querySystemTime();
        setBusy(false);

        if (!result.io.ok)
        {
            m_supported = false;
            m_hypervAvailable = false;
            m_operationLabel->setText(
                result.unsupported
                    ? ks::i18n::sourceText(QStringLiteral(
                        "当前 KswordARK 驱动不支持系统全局变速，请更新 R0。"))
                    : ks::i18n::sourceText(QStringLiteral("R0 查询失败：%1"))
                        .arg(QString::fromStdString(
                            result.io.message)));
            updateButtons();
            return;
        }

        m_generation = result.response.generation;
        m_supported =
            (result.response.stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_SUPPORTED) != 0UL;
        updateStatusDisplay(
            result.response.status,
            result.response.stateFlags,
            result.response.generation,
            result.response.command,
            result.response.factor,
            result.response.osBuildNumber,
            result.response.lastStatus,
            result.response.resolutionMode,
            result.response.backend,
            result.response.counterSourceAddress,
            result.response.primarySlotAddress,
            result.response.secondarySlotAddress,
            result.response.hypervisorSharedPageAddress,
            result.response.hypervisorTimeUpdateLock,
            result.response.hypervisorOriginalMultiplier,
            result.response.hypervisorOriginalBias,
            result.response.hypervisorCurrentMultiplier,
            result.response.hypervisorCurrentBias);
        updateButtons();
    }

    void SystemTimePage::applyRequestedMode()
    {
        const unsigned long factor =
            static_cast<unsigned long>(m_factorSpin->value());
        const unsigned long command =
            m_speedUpRadio->isChecked()
            ? KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP
            : KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN;
        const QString modeText = ks::i18n::sourceText(
            m_speedUpRadio->isChecked()
            ? QStringLiteral("加速")
            : QStringLiteral("减速"));
        const unsigned long backend =
            m_hypervBackendRadio->isChecked()
            ? KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC
            : KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT;
        const QString backendText = ks::i18n::sourceText(
            m_hypervBackendRadio->isChecked()
            ? QStringLiteral("Hyper-V 共享 QPC")
            : QStringLiteral("HAL 兼容后端"));
        const unsigned long resolutionMode =
            m_compatRadio->isChecked()
            ? KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT
            : KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED;
        const QString schemeText = ks::i18n::sourceText(
            m_compatRadio->isChecked()
            ? QStringLiteral("兼容模式")
            : QStringLiteral("安全模式"));

        if (!m_acknowledgeCheck->isChecked() ||
            !confirmHighRisk(
                modeText,
                backendText,
                schemeText,
                factor))
        {
            return;
        }

        setBusy(true);
        kLogEvent controlEvent;
        ksword::ark::DriverClient client;
        const auto freshStatus = client.querySystemTime();
        if (!freshStatus.io.ok)
        {
            setBusy(false);
            warn << controlEvent
                << "[SystemTimePage] 控制前状态查询失败: "
                << freshStatus.io.message << eol;
            showOpaqueMessage(
                this,
                QMessageBox::Critical,
                ks::i18n::sourceText(QStringLiteral("系统全局变速")),
                ks::i18n::sourceText(
                    QStringLiteral("控制前无法读取 R0 状态，未执行任何修改。")));
            return;
        }

        const auto result = client.controlSystemTime(
            command,
            factor,
            backend,
            resolutionMode,
            freshStatus.response.generation,
            true);
        setBusy(false);
        if (!result.io.ok ||
            result.response.status !=
                KSWORD_ARK_SYSTEM_TIME_STATUS_OK)
        {
            warn << controlEvent
                << "[SystemTimePage] 系统变速失败: "
                << result.io.message << eol;
            showOpaqueMessage(
                this,
                QMessageBox::Critical,
                ks::i18n::sourceText(QStringLiteral("系统全局变速")),
                result.io.ok
                    ? operationStatusText(
                        result.response.status,
                        result.response.lastStatus)
                    : ks::i18n::sourceText(QStringLiteral("R0 控制失败：%1"))
                        .arg(QString::fromStdString(
                            result.io.message)));
            refreshStatus();
            return;
        }

        info << controlEvent
            << "[SystemTimePage] 系统变速已应用, mode="
            << modeText.toStdString()
            << ", backend=" << backendText.toStdString()
            << ", scheme=" << schemeText.toStdString()
            << ", factor=" << factor << eol;
        m_operationLabel->setText(
            ks::i18n::sourceText(QStringLiteral("已应用：%1；%2；%3 %4 倍"))
                .arg(backendText)
                .arg(schemeText)
                .arg(modeText)
                .arg(factor));
        refreshStatus();
    }

    void SystemTimePage::resetSystemTime()
    {
        setBusy(true);
        kLogEvent resetEvent;
        ksword::ark::DriverClient client;
        const auto result = client.controlSystemTime(
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET,
            1UL,
            m_currentBackend,
            m_compatRadio->isChecked()
                ? KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT
                : KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED,
            m_generation,
            false);
        setBusy(false);

        if (!result.io.ok ||
            result.response.status !=
                KSWORD_ARK_SYSTEM_TIME_STATUS_OK)
        {
            warn << resetEvent
                << "[SystemTimePage] 恢复 1x 失败: "
                << result.io.message << eol;
            showOpaqueMessage(
                this,
                QMessageBox::Critical,
                ks::i18n::sourceText(QStringLiteral("恢复系统计时")),
                result.io.ok
                    ? operationStatusText(
                        result.response.status,
                        result.response.lastStatus)
                    : ks::i18n::sourceText(QStringLiteral("R0 控制失败：%1"))
                        .arg(QString::fromStdString(
                            result.io.message)));
            refreshStatus();
            return;
        }

        info << resetEvent
            << "[SystemTimePage] 已停止变速并切换到连续 1x 计时。" << eol;
        m_operationLabel->setText(ks::i18n::sourceText(
            QStringLiteral("已停止变速，当前以连续计数保持 1x")));
        m_acknowledgeCheck->setChecked(false);
        refreshStatus();
    }

    void SystemTimePage::synchronizeFromTimeServer()
    {
        if (m_busy || m_timeSyncProcess != nullptr)
        {
            return;
        }

        setBusy(true);
        m_operationLabel->setText(ks::i18n::sourceText(
            QStringLiteral("正在请求 Windows 时间服务器同步...")));

        auto* process = new QProcess(this);
        m_timeSyncProcess = process;
        process->setProcessChannelMode(QProcess::MergedChannels);
        process->setProgram(QStringLiteral("w32tm.exe"));
        process->setArguments({
            QStringLiteral("/resync"),
            QStringLiteral("/rediscover") });

        auto* timeoutTimer = new QTimer(process);
        timeoutTimer->setSingleShot(true);
        timeoutTimer->setInterval(kTimeSyncTimeoutMs);
        connect(
            timeoutTimer,
            &QTimer::timeout,
            process,
            [this, process]()
            {
                if (m_timeSyncProcess != process)
                {
                    return;
                }
                process->setProperty("ksTimeSyncTimedOut", true);
                process->kill();
            });
        connect(
            process,
            &QProcess::errorOccurred,
            this,
            [this, process](const QProcess::ProcessError error)
            {
                if (error != QProcess::FailedToStart ||
                    m_timeSyncProcess != process)
                {
                    return;
                }
                completeTimeSynchronization(
                    process,
                    false,
                    ks::i18n::sourceText(
                        QStringLiteral("无法启动 Windows 时间服务命令 w32tm.exe")));
            });
        connect(
            process,
            qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this,
            [this, process](
                const int exitCode,
                const QProcess::ExitStatus exitStatus)
            {
                if (m_timeSyncProcess != process)
                {
                    return;
                }
                const bool timedOut =
                    process->property("ksTimeSyncTimedOut").toBool();
                const QString output = QString::fromLocal8Bit(
                    process->readAll()).trimmed();
                completeTimeSynchronization(
                    process,
                    !timedOut &&
                        exitStatus == QProcess::NormalExit &&
                        exitCode == 0,
                    timedOut
                        ? ks::i18n::sourceText(
                            QStringLiteral("等待时间服务器响应超时（15 秒）"))
                        : output);
            });

        timeoutTimer->start();
        process->start();
    }

    void SystemTimePage::completeTimeSynchronization(
        QProcess* process,
        const bool success,
        const QString& detailText)
    {
        if (process == nullptr || m_timeSyncProcess != process)
        {
            return;
        }

        m_timeSyncProcess = nullptr;
        process->deleteLater();
        setBusy(false);

        kLogEvent timeSyncEvent;
        if (success)
        {
            resetCalibratedClock();
            m_operationLabel->setText(ks::i18n::sourceText(
                QStringLiteral("已从 Windows 时间服务器同步系统时间")));
            info << timeSyncEvent
                << "[SystemTimePage] Windows 时间服务器同步成功。"
                << eol;
            return;
        }

        const QString failureDetail = detailText.trimmed().isEmpty()
            ? ks::i18n::sourceText(
                QStringLiteral("Windows 时间服务未返回详细错误"))
            : detailText.trimmed();
        warn << timeSyncEvent
            << "[SystemTimePage] Windows 时间服务器同步失败: "
            << failureDetail.toStdString() << eol;
        m_operationLabel->setText(
            ks::i18n::sourceText(QStringLiteral("时间服务器同步失败：%1"))
                .arg(failureDetail));
        showOpaqueMessage(
            this,
            QMessageBox::Warning,
            ks::i18n::sourceText(QStringLiteral("更新时间失败")),
            ks::i18n::sourceText(QStringLiteral(
                "未能从 Windows 已配置的时间服务器更新时间。\n\n%1\n\n"
                "请确认 Windows Time 服务正在运行，并以管理员身份重试。"))
                .arg(failureDetail));
    }

    void SystemTimePage::resetCalibratedClock()
    {
        m_calibratedAnchorEpochMs =
            QDateTime::currentMSecsSinceEpoch();
        m_calibratedElapsedTimer.start();
        updateCalibratedTimeDisplay();
    }

    void SystemTimePage::updateCalibratedTimeDisplay()
    {
        if (m_calibratedTimeLabel == nullptr)
        {
            return;
        }
        if (!m_calibratedElapsedTimer.isValid())
        {
            m_calibratedAnchorEpochMs =
                QDateTime::currentMSecsSinceEpoch();
            m_calibratedElapsedTimer.start();
        }

        const qint64 measuredElapsedMs =
            std::max<qint64>(0, m_calibratedElapsedTimer.elapsed());
        qint64 calibratedElapsedMs = measuredElapsedMs;
        QString calibrationMode = ks::i18n::sourceText(
            QStringLiteral("原始速度 1x"));
        if (m_active &&
            m_currentCommand ==
                KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP &&
            m_currentFactor > 1UL)
        {
            calibratedElapsedMs /=
                static_cast<qint64>(m_currentFactor);
            calibrationMode = ks::i18n::sourceText(
                QStringLiteral("加速 %1 倍"))
                .arg(m_currentFactor);
        }
        else if (m_active &&
                 m_currentCommand ==
                    KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN &&
                 m_currentFactor > 1UL)
        {
            const qint64 factor =
                static_cast<qint64>(m_currentFactor);
            calibratedElapsedMs = measuredElapsedMs >
                std::numeric_limits<qint64>::max() / factor
                ? std::numeric_limits<qint64>::max()
                : measuredElapsedMs * factor;
            calibrationMode = ks::i18n::sourceText(
                QStringLiteral("减速到 1/%1"))
                .arg(m_currentFactor);
        }

        const qint64 maximumAddition =
            std::numeric_limits<qint64>::max() -
            m_calibratedAnchorEpochMs;
        const qint64 calibratedEpochMs =
            m_calibratedAnchorEpochMs +
            std::min(calibratedElapsedMs, maximumAddition);
        const QString calibratedTimeText =
            QDateTime::fromMSecsSinceEpoch(calibratedEpochMs)
                .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
        m_calibratedTimeLabel->setText(
            ks::i18n::sourceText(
                QStringLiteral("校准后时间：%1（按当前 %2 校准）"))
                .arg(calibratedTimeText, calibrationMode));
    }

    bool SystemTimePage::confirmHighRisk(
        const QString& modeText,
        const QString& backendText,
        const QString& schemeText,
        const unsigned long factor)
    {
        QMessageBox warningBox(this);
        warningBox.setObjectName(
            QStringLiteral("ksSystemTimeRiskDialog"));
        warningBox.setStyleSheet(
            KswordTheme::OpaqueDialogStyle(
                warningBox.objectName()));
        warningBox.setIcon(QMessageBox::Warning);
        warningBox.setWindowTitle(ks::i18n::sourceText(
            QStringLiteral("系统全局变速风险确认")));
        warningBox.setText(
            ks::i18n::sourceText(QStringLiteral(
                "即将使用“%1”后端与“%2”，对整个系统%3 %4 倍。\n\n"
                "此操作会改变全局性能计数器的时间流速，"
                "可能破坏超时、同步、网络、音视频和安全软件行为。\n"
                "请确认已保存工作，并准备在异常时立即恢复 1x。"))
                .arg(backendText)
                .arg(schemeText)
                .arg(modeText)
                .arg(factor));
        warningBox.setStandardButtons(
            QMessageBox::Ok | QMessageBox::Cancel);
        warningBox.setDefaultButton(QMessageBox::Cancel);
        if (warningBox.exec() != QMessageBox::Ok)
        {
            return false;
        }

        // 最终确认改为直接点击：不再要求输入确认短语，默认聚焦“否”避免误触。
        QMessageBox finalBox(this);
        finalBox.setIcon(QMessageBox::Warning);
        finalBox.setWindowTitle(ks::i18n::sourceText(QStringLiteral("最终确认")));
        finalBox.setText(ks::i18n::sourceText(
            QStringLiteral("确认修改系统时间相关设置？该操作会影响全局时间行为。")));
        finalBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        finalBox.setDefaultButton(QMessageBox::No);
        return finalBox.exec() == QMessageBox::Yes;
    }

    void SystemTimePage::updateStatusDisplay(
        const unsigned long status,
        const unsigned long stateFlags,
        const unsigned long generation,
        const unsigned long command,
        const unsigned long factor,
        const unsigned long osBuildNumber,
        const long lastStatus,
        const unsigned long resolutionMode,
        const unsigned long backend,
        const unsigned long long counterSourceAddress,
        const unsigned long long primarySlotAddress,
        const unsigned long long secondarySlotAddress,
        const unsigned long long hypervisorSharedPageAddress,
        const unsigned long long hypervisorTimeUpdateLock,
        const unsigned long long hypervisorOriginalMultiplier,
        const unsigned long long hypervisorOriginalBias,
        const unsigned long long hypervisorCurrentMultiplier,
        const unsigned long long hypervisorCurrentBias)
    {
        const bool active =
            (stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_ACTIVE) != 0UL;
        const bool conflict =
            (stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_CONFLICT) != 0UL;
        const bool hypervPresent =
            (stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_PRESENT) != 0UL;
        const bool hypervSharedPage =
            (stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_SHARED_PAGE) != 0UL;
        const bool hypervActive =
            (stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_ACTIVE) != 0UL;
        const bool calibrationChanged =
            !m_calibratedElapsedTimer.isValid() ||
            m_calibrationGeneration != generation ||
            m_active != active ||
            m_currentCommand != command ||
            m_currentFactor != factor ||
            m_currentBackend != backend;
        const QString schemeText = ks::i18n::sourceText(
            resolutionMode ==
                KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED
            ? QStringLiteral("安全模式")
            : resolutionMode ==
                KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT
                ? QStringLiteral("兼容模式")
                : QStringLiteral("未知"));
        const QString backendText = ks::i18n::sourceText(
            backend ==
                KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC
            ? QStringLiteral("Hyper-V 共享 QPC")
            : backend ==
                KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT
                ? QStringLiteral("HAL 兼容后端")
                : QStringLiteral("未知"));
        const QString hypervStateText = ks::i18n::sourceText(hypervActive
            ? QStringLiteral("共享页已接管")
            : hypervSharedPage
                ? QStringLiteral("共享页可用")
                : hypervPresent
                    ? QStringLiteral("已检测，但共享页不可用")
                    : QStringLiteral("未检测到 Microsoft Hyper-V"));
        const QString kernelPathText = ks::i18n::sourceText(
            (stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_HANDLER_TABLE) != 0UL
            ? QStringLiteral("HAL 处理器表")
            : QStringLiteral("HAL 计数器槽"));

        m_hypervAvailable = hypervPresent && hypervSharedPage;
        m_active = active;
        m_currentCommand = active
            ? command
            : KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
        m_currentFactor = active
            ? std::max(1UL, factor)
            : 1UL;
        m_currentBackend = backend;
        m_calibrationGeneration = generation;
        if (calibrationChanged)
        {
            resetCalibratedClock();
        }
        else
        {
            updateCalibratedTimeDisplay();
        }
        if (active)
        {
            m_hypervBackendRadio->setChecked(
                backend ==
                    KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC);
            m_halBackendRadio->setChecked(
                backend ==
                    KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT);
            m_compatRadio->setChecked(
                resolutionMode ==
                    KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT);
            m_guardedResolutionRadio->setChecked(
                resolutionMode ==
                    KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED);
        }
        else if (!m_hypervAvailable &&
                 m_hypervBackendRadio->isChecked())
        {
            m_halBackendRadio->setChecked(true);
        }

        if (active &&
            command == KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP)
        {
            m_currentModeLabel->setText(
                ks::i18n::sourceText(QStringLiteral("当前：全局加速 %1 倍"))
                    .arg(factor));
        }
        else if (active &&
                 command ==
                    KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN)
        {
            m_currentModeLabel->setText(
                ks::i18n::sourceText(QStringLiteral("当前：全局减速到 1/%1"))
                    .arg(factor));
        }
        else
        {
            m_currentModeLabel->setText(ks::i18n::sourceText(
                QStringLiteral("当前：原始速度 1x")));
        }

        m_currentModeLabel->setStyleSheet(
            QStringLiteral("font-size:16px;font-weight:700;color:%1;")
                .arg(conflict
                    ? KswordTheme::ErrorHex()
                    : active
                        ? KswordTheme::WarningHex()
                        : KswordTheme::SuccessHex()));
        m_backendLabel->setText(
            ks::i18n::sourceText(QStringLiteral(
                "Windows 构建：%1；后端：%2；实现模式：%3；"
                "内核计时路径：%4；Hyper-V：%5；状态代次：%6"))
                .arg(osBuildNumber)
                .arg(backendText)
                .arg(schemeText)
                .arg(kernelPathText)
                .arg(hypervStateText)
                .arg(generation));
        if (hypervSharedPage)
        {
            m_diagnosticLabel->setText(
                ks::i18n::sourceText(QStringLiteral(
                    "计时描述符：%1；主槽：%2；辅助槽：%3；"
                    "Hyper-V 共享页：%4；更新锁：%5；"
                    "原倍率：%6；当前倍率：%7；原偏置：%8；当前偏置：%9"))
                    .arg(addressText(counterSourceAddress))
                    .arg(addressText(primarySlotAddress))
                    .arg(addressText(secondarySlotAddress))
                    .arg(addressText(hypervisorSharedPageAddress))
                    .arg(hexValueText(hypervisorTimeUpdateLock))
                    .arg(hexValueText(hypervisorOriginalMultiplier))
                    .arg(hexValueText(hypervisorCurrentMultiplier))
                    .arg(hexValueText(hypervisorOriginalBias))
                    .arg(hexValueText(hypervisorCurrentBias)));
        }
        else
        {
            m_diagnosticLabel->setText(
                ks::i18n::sourceText(QStringLiteral(
                    "计时描述符：%1；主槽：%2；辅助槽：%3；"
                    "Hyper-V 共享页：不可用"))
                    .arg(addressText(counterSourceAddress))
                    .arg(addressText(primarySlotAddress))
                    .arg(addressText(secondarySlotAddress)));
        }
        m_operationLabel->setText(
            operationStatusText(status, lastStatus));
    }

    void SystemTimePage::updateButtons()
    {
        m_refreshButton->setEnabled(!m_busy);
        m_timeSyncButton->setEnabled(
            !m_busy && m_timeSyncProcess == nullptr);
        m_applyButton->setEnabled(
            !m_busy &&
            m_supported &&
            m_acknowledgeCheck->isChecked() &&
            (!m_hypervBackendRadio->isChecked() ||
                m_hypervAvailable));
        m_resetButton->setEnabled(
            !m_busy &&
            m_supported);
        m_factorSpin->setEnabled(!m_busy);
        m_speedUpRadio->setEnabled(!m_busy);
        m_slowDownRadio->setEnabled(!m_busy);
        m_hypervBackendRadio->setEnabled(
            !m_busy && !m_active && m_hypervAvailable);
        m_halBackendRadio->setEnabled(
            !m_busy && !m_active);
        m_compatRadio->setEnabled(
            !m_busy && !m_active);
        m_guardedResolutionRadio->setEnabled(
            !m_busy && !m_active);
        m_acknowledgeCheck->setEnabled(!m_busy);
    }

    void SystemTimePage::setBusy(const bool busy)
    {
        m_busy = busy;
        updateButtons();
    }
}
