#include "NotificationCardManager.h"
#include "TaskSnapshotFeed.h"

#include "../Framework.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QFontMetrics>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPointer>
#include <QProgressBar>
#include <QPropertyAnimation>
#include <QRegion>
#include <QScreen>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <QWindow>

#include <algorithm>
#include <cmath>
#include <functional>
#include <utility>

namespace
{
    constexpr int kCardWidth = 400;
    constexpr int kScreenMargin = 12;
    constexpr int kCardSpacing = 8;
    constexpr int kAnimationDurationMs = 150;
    constexpr int kCardBackgroundAlpha = 191; // 75%

    QPointer<ks::ui::NotificationCardManager> g_notificationCardManager;

    QString toUiText(const std::string& utf8Text)
    {
        return QString::fromUtf8(utf8Text.data(), static_cast<int>(utf8Text.size()));
    }

    // localizedBackendText 作用：
    // - 日志与进度文本由后端以源语言（中文）写入 std::string，显示时才翻译；
    // - 与 DriverDock 的调试输出同一做法：按行 displayText，避免多行内容整体失配；
    // - 未登记的文本原样返回，不会丢内容。
    QString localizedBackendText(const std::string& utf8Text)
    {
        const QString rawText = toUiText(utf8Text);
        if (rawText.isEmpty())
        {
            return rawText;
        }
        if (!rawText.contains(QChar(u'\n')))
        {
            return ks::i18n::displayText(rawText);
        }

        QStringList localizedLines;
        const QStringList rawLines = rawText.split(QChar(u'\n'));
        localizedLines.reserve(rawLines.size());
        for (const QString& rawLine : rawLines)
        {
            localizedLines.append(ks::i18n::displayText(rawLine));
        }
        return localizedLines.join(QChar(u'\n'));
    }

    QColor levelColor(const kLogLevel level)
    {
        switch (level)
        {
        // 等级配色与日志面板 LogDockWidget::getLevelColor 保持同一套主题语义色。
        case kLogLevel::Debug: return KswordTheme::AccentColor(KswordTheme::AccentRole::Blue, -12, -38);
        case kLogLevel::Info: return KswordTheme::SuccessColor();
        case kLogLevel::Warn: return KswordTheme::WarningColor();
        case kLogLevel::Error: return KswordTheme::ErrorColor();
        case kLogLevel::Fatal: return KswordTheme::AccentTextColor(KswordTheme::AccentRole::Red, KswordTheme::BlackColor());
        // PrimaryBlueHex 是 "palette(highlight)" 样式表占位符，QColor 解析不出颜色；
        // 绘制路径必须取真实强调色。
        default: return KswordTheme::PrimaryAccentColor();
        }
    }

    QString logCopyText(const kEvent& eventItem)
    {
        return ks::i18n::contextText(
                QStringLiteral("notification.copy.log_template"),
                QStringLiteral("%1\n%2\n%3\n文件：%4\n函数：%5\nGUID：%6"))
            .arg(QString::fromStdString(LogLevelToString(eventItem.level)))
            .arg(QString::fromStdString(FormatTimeToString(eventItem.timestamp)).right(8))
            .arg(localizedBackendText(eventItem.content))
            .arg(toUiText(eventItem.fileLocation))
            .arg(toUiText(eventItem.functionName))
            .arg(QString::fromStdString(GuidToString(eventItem.guid)));
    }

    QString progressCopyText(const kProgressTask& taskItem)
    {
        const int percent = std::clamp(static_cast<int>(std::lround(taskItem.progress * 100.0f)), 0, 100);
        return QStringLiteral("%1\n%2\n%3%")
            .arg(localizedBackendText(taskItem.taskName))
            .arg(localizedBackendText(taskItem.stepName))
            .arg(percent);
    }

    QRect resolveScreenBounds(QWidget* const hostWindow)
    {
        QScreen* targetScreen = nullptr;
        if (hostWindow != nullptr)
        {
            targetScreen = QGuiApplication::screenAt(hostWindow->frameGeometry().center());
            if (targetScreen == nullptr && hostWindow->windowHandle() != nullptr)
            {
                targetScreen = hostWindow->windowHandle()->screen();
            }
        }
        if (targetScreen == nullptr)
        {
            targetScreen = QGuiApplication::primaryScreen();
        }
        return targetScreen != nullptr ? targetScreen->availableGeometry() : QRect(0, 0, 1920, 1080);
    }
}

namespace ks::ui
{
    // 卡片本体整体输入透明；独立的按钮窗口只保留两个按钮的窗口区域。
    // HTTRANSPARENT 只能继续命中同线程窗口，无法替代跨进程穿透。
    class NotificationControlsWindow final : public QWidget
    {
    public:
        explicit NotificationControlsWindow(QWidget* const owner)
            : QWidget(owner, Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint
                | Qt::WindowDoesNotAcceptFocus | Qt::NoDropShadowWindowHint)
        {
            setAttribute(Qt::WA_TranslucentBackground, true);
            setAttribute(Qt::WA_ShowWithoutActivating, true);
            setFocusPolicy(Qt::NoFocus);
        }

    protected:
        void paintEvent(QPaintEvent*) override
        {
            // 分层窗口的零 alpha 像素也会穿透。保留最低 alpha，让按钮空白处可点。
            QPainter painter(this);
            painter.fillRect(rect(), QColor(0, 0, 0, 1));
        }
    };

    class NotificationCard final : public QWidget
    {
    public:
        enum class Kind
        {
            Log,
            Progress
        };

        explicit NotificationCard(const Kind kind, std::function<void()> layoutChangedCallback = {})
            : QWidget(nullptr)
            , m_kind(kind)
            , m_layoutChangedCallback(std::move(layoutChangedCallback))
        {
            setAttribute(Qt::WA_TranslucentBackground, true);
            setAttribute(Qt::WA_ShowWithoutActivating, true);
            setWindowFlags(
                Qt::Tool |
                Qt::FramelessWindowHint |
                Qt::WindowStaysOnTopHint |
                Qt::WindowDoesNotAcceptFocus |
                Qt::WindowTransparentForInput);
            setFocusPolicy(Qt::NoFocus);
            setFixedWidth(kCardWidth);

            m_frame = new QWidget(this);
            m_frame->setObjectName(QStringLiteral("ksNotificationCardFrame"));
            QVBoxLayout* rootLayout = new QVBoxLayout(this);
            rootLayout->setContentsMargins(0, 0, 0, 0);
            rootLayout->addWidget(m_frame);

            QVBoxLayout* frameLayout = new QVBoxLayout(m_frame);
            frameLayout->setContentsMargins(14, 10, 10, 12);
            frameLayout->setSpacing(7);

            QHBoxLayout* titleLayout = new QHBoxLayout();
            titleLayout->setSpacing(6);
            m_titleLabel = new QLabel(m_frame);
            m_titleLabel->setObjectName(QStringLiteral("ksNotificationCardTitle"));
            m_titleLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
            titleLayout->addWidget(m_titleLabel, 1);
            m_controlsWindow = new NotificationControlsWindow(this);
            m_copyButton = new QToolButton(m_controlsWindow);
            m_copyButton->setObjectName(QStringLiteral("ksNotificationCardCopy"));
            m_copyButton->setText(ks::i18n::text(QStringLiteral("notification.copy"), QStringLiteral("复制")));
            m_copyButton->setToolTip(ks::i18n::text(QStringLiteral("notification.copy.tooltip"), QStringLiteral("复制卡片内容到剪贴板")));
            m_copyButton->setAutoRaise(true);
            m_copyButton->setFocusPolicy(Qt::NoFocus);
            m_copySlot = new QWidget(m_frame);
            titleLayout->addWidget(m_copySlot, 0, Qt::AlignTop);
            m_expandButton = new QToolButton(m_controlsWindow);
            m_expandButton->setObjectName(QStringLiteral("ksNotificationCardExpand"));
            m_expandButton->setArrowType(Qt::DownArrow);
            m_expandButton->setToolTip(ks::i18n::text(QStringLiteral("notification.expand"), QStringLiteral("展开完整日志")));
            m_expandButton->setAutoRaise(true);
            m_expandButton->setFocusPolicy(Qt::NoFocus);
            m_expandButton->hide();
            m_expandSlot = new QWidget(m_frame);
            m_expandSlot->hide();
            titleLayout->addWidget(m_expandSlot, 0, Qt::AlignTop);
            frameLayout->addLayout(titleLayout);

            m_bodyLabel = new QLabel(m_frame);
            m_bodyLabel->setObjectName(QStringLiteral("ksNotificationCardBody"));
            m_bodyLabel->setWordWrap(true);
            m_bodyLabel->setTextInteractionFlags(Qt::NoTextInteraction);
            frameLayout->addWidget(m_bodyLabel);

            if (m_kind == Kind::Progress)
            {
                m_progressBar = new QProgressBar(m_frame);
                m_progressBar->setObjectName(QStringLiteral("ksNotificationCardProgress"));
                m_progressBar->setRange(0, 100);
                m_progressBar->setTextVisible(true);
                frameLayout->addWidget(m_progressBar);
            }

            connect(m_copyButton, &QToolButton::clicked, this, [this]() {
                if (QClipboard* clipboard = QApplication::clipboard())
                {
                    // 先读取系统主剪贴板的当前文本：
                    // - 内容不同才重新写入，避免对已复制内容产生重复写入；
                    // - 每次点击仍会检查，卡片内容更新或剪贴板被其它程序改写后可自动补复制。
                    if (clipboard->text(QClipboard::Clipboard) != m_copyText)
                    {
                        clipboard->setText(m_copyText, QClipboard::Clipboard);
                    }
                    m_copyButton->setText(
                        ks::i18n::text(QStringLiteral("notification.copy.done"), QStringLiteral("已复制")));
                    updateLogHeightLimit();
                }
            });
            connect(m_expandButton, &QToolButton::clicked, this, [this]() {
                m_logExpanded = !m_logExpanded;
                updateLogHeightLimit();
                if (m_layoutChangedCallback)
                {
                    m_layoutChangedCallback();
                }
            });

            m_copySlot->installEventFilter(this);
            m_expandSlot->installEventFilter(this);
            refreshVisuals();
        }

        void setLogEvent(
            const kEvent& eventItem,
            const bool heightLimitEnabled,
            const int maximumLines)
        {
            m_titleLabel->setText(
                QStringLiteral("%1  %2")
                .arg(QString::fromStdString(LogLevelToString(eventItem.level)))
                .arg(QString::fromStdString(FormatTimeToString(eventItem.timestamp)).right(8)));
            m_bodyLabel->setText(localizedBackendText(eventItem.content));
            m_copyText = logCopyText(eventItem);
            m_logLevel = eventItem.level;
            m_logHeightLimitEnabled = heightLimitEnabled;
            m_logMaximumLines = std::max(1, maximumLines);
            m_logExpanded = false;
            refreshVisuals();
            adjustToContent();
        }

        void setLogHeightLimit(const bool heightLimitEnabled, const int maximumLines)
        {
            if (m_kind != Kind::Log)
            {
                return;
            }
            m_logHeightLimitEnabled = heightLimitEnabled;
            m_logMaximumLines = std::max(1, maximumLines);
            if (!m_logHeightLimitEnabled)
            {
                m_logExpanded = false;
            }
            updateLogHeightLimit();
        }

        void setProgressTask(const kProgressTask& taskItem)
        {
            // 保存源记录用于原位语言/主题刷新；任务身份不随展示文案改变。
            m_progressTask = taskItem;
            setObjectName(QStringLiteral("task_notification"));
            setProperty("task_pid", taskItem.pid);
            setProperty("task_state", static_cast<int>(taskItem.state));
            setProperty("task_generation", static_cast<qulonglong>(taskItem.generation));
            m_titleLabel->setText(localizedBackendText(taskItem.taskName)
                + QStringLiteral("  ·  ") + TaskStateText(taskItem.state));
            m_bodyLabel->setText(localizedBackendText(taskItem.stepName));
            if (m_progressBar != nullptr)
            {
                m_progressBar->setValue(std::clamp(static_cast<int>(std::lround(taskItem.progress * 100.0f)), 0, 100));
                m_progressBar->setVisible(!taskItem.hideProgressBarTemporarily && !IsProgressTerminal(taskItem.state));
            }
            m_copyText = progressCopyText(taskItem);
            refreshVisuals();
            adjustToContent();
        }

        void refreshVisuals()
        {
            QColor backgroundColor = KswordTheme::SurfaceColor();
            backgroundColor.setAlpha(kCardBackgroundAlpha);
            // 保存通知语义而不是创建时的像素色，连续切主题也从当前种子求色。
            const QColor accent = m_kind == Kind::Log
                ? levelColor(m_logLevel)
                : TaskStateColor(m_progressTask.state);
            const QColor hoverBackground = KswordTheme::BlendColors(KswordTheme::SurfaceColor(), accent, 36);
            const QString accentText = KswordTheme::ThemeColorName(
                KswordTheme::EnsureTextContrast(accent, KswordTheme::SurfaceColor()));
            const QString hoverText = KswordTheme::ThemeColorName(
                KswordTheme::EnsureTextContrast(accent, hoverBackground));
            m_frame->setStyleSheet(QStringLiteral(
                "#ksNotificationCardFrame{"
                "background-color:%1;border:1px solid %2;border-left:4px solid %3;border-radius:8px;"
                "}"
                "#ksNotificationCardTitle{color:%4;font-weight:600;}"
                "#ksNotificationCardBody{color:%4;}"
                "#ksNotificationCardCopy{color:%7;border:1px solid transparent;border-radius:4px;padding:2px 5px;}"
                "#ksNotificationCardCopy:hover{background:%5;border-color:%3;color:%8;}"
                "#ksNotificationCardExpand{color:%7;border:1px solid transparent;border-radius:4px;padding:2px;}"
                "#ksNotificationCardExpand:hover{background:%5;border-color:%3;color:%8;}"
                "#ksNotificationCardProgress{border:1px solid %2;border-radius:4px;text-align:center;color:%4;background:%6;height:16px;}"
                "#ksNotificationCardProgress::chunk{background:%3;border-radius:3px;}")
                .arg(backgroundColor.name(QColor::HexArgb))
                .arg(KswordTheme::BorderColorHex())
                .arg(accent.name())
                .arg(KswordTheme::TextPrimaryColorHex())
                .arg(KswordTheme::RgbaColorName(accent, 36))
                .arg(KswordTheme::SurfaceMutedColorHex())
                .arg(accentText)
                .arg(hoverText));
            m_controlsWindow->setStyleSheet(m_frame->styleSheet());
            updateControlSizes();
        }

        void animateTo(const QPoint& targetPosition, const bool animate)
        {
            if (!isVisible())
            {
                move(targetPosition);
                setWindowOpacity(0.0);
                m_controlsWindow->setWindowOpacity(0.0);
                show();
                QPropertyAnimation* fadeIn = new QPropertyAnimation(this, "windowOpacity", this);
                fadeIn->setDuration(kAnimationDurationMs);
                fadeIn->setStartValue(0.0);
                fadeIn->setEndValue(1.0);
                connect(fadeIn, &QPropertyAnimation::valueChanged, m_controlsWindow,
                    [this](const QVariant& value) { m_controlsWindow->setWindowOpacity(value.toReal()); });
                fadeIn->start(QAbstractAnimation::DeleteWhenStopped);
                return;
            }

            if (!animate || pos() == targetPosition)
            {
                move(targetPosition);
                return;
            }
            QPropertyAnimation* moveAnimation = new QPropertyAnimation(this, "pos", this);
            moveAnimation->setDuration(kAnimationDurationMs);
            moveAnimation->setEasingCurve(QEasingCurve::OutCubic);
            moveAnimation->setStartValue(pos());
            moveAnimation->setEndValue(targetPosition);
            moveAnimation->start(QAbstractAnimation::DeleteWhenStopped);
        }

        void dismiss(const bool animate)
        {
            if (!animate)
            {
                hide();
                deleteLater();
                return;
            }
            QPropertyAnimation* fadeOut = new QPropertyAnimation(this, "windowOpacity", this);
            fadeOut->setDuration(kAnimationDurationMs);
            fadeOut->setStartValue(windowOpacity());
            fadeOut->setEndValue(0.0);
            connect(fadeOut, &QPropertyAnimation::valueChanged, m_controlsWindow,
                [this](const QVariant& value) { m_controlsWindow->setWindowOpacity(value.toReal()); });
            connect(fadeOut, &QPropertyAnimation::finished, this, [this]() {
                hide();
                deleteLater();
            });
            fadeOut->start(QAbstractAnimation::DeleteWhenStopped);
        }

    protected:
        void changeEvent(QEvent* event) override
        {
            QWidget::changeEvent(event);
            // 语言变化必须从保留的源记录重新生成正文，不能依赖翻译合成标题。
            if (m_kind == Kind::Progress && m_titleLabel != nullptr && event != nullptr &&
                event->type() == QEvent::LanguageChange)
            {
                setProgressTask(m_progressTask);
            }
        }

        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if ((watched == m_copySlot || watched == m_expandSlot)
                && (event->type() == QEvent::Move || event->type() == QEvent::Resize
                    || event->type() == QEvent::Show || event->type() == QEvent::Hide))
            {
                syncControlsWindow();
            }
            return QWidget::eventFilter(watched, event);
        }

        void moveEvent(QMoveEvent* event) override
        {
            QWidget::moveEvent(event);
            syncControlsWindow();
        }

        void resizeEvent(QResizeEvent* event) override
        {
            QWidget::resizeEvent(event);
            syncControlsWindow();
        }

        void showEvent(QShowEvent* event) override
        {
            QWidget::showEvent(event);
            syncControlsWindow();
        }

        void hideEvent(QHideEvent* event) override
        {
            m_controlsWindow->hide();
            QWidget::hideEvent(event);
        }

    private:
        void updateControlSizes()
        {
            m_copySlot->setFixedSize(m_copyButton->sizeHint());
            m_expandSlot->setFixedSize(m_expandButton->sizeHint());
        }

        void syncControlsWindow()
        {
            if (m_controlsWindow == nullptr || m_copySlot == nullptr || m_expandSlot == nullptr)
            {
                return;
            }
            m_controlsWindow->setGeometry(QRect(mapToGlobal(QPoint(0, 0)), size()));
            const QRect copyRect(m_copySlot->mapTo(this, QPoint(0, 0)), m_copySlot->size());
            m_copyButton->setGeometry(copyRect);
            QRegion inputRegion(copyRect);
            const bool expandVisible = !m_expandSlot->isHidden();
            m_expandButton->setVisible(expandVisible);
            if (expandVisible)
            {
                const QRect expandRect(m_expandSlot->mapTo(this, QPoint(0, 0)), m_expandSlot->size());
                m_expandButton->setGeometry(expandRect);
                inputRegion += expandRect;
            }
            // 原生窗口区域排除正文、标题和按钮之间的空隙，穿透不依赖命中消息转发。
            m_controlsWindow->setMask(inputRegion);
            if (isVisible() && !m_controlsWindow->isVisible())
            {
                m_controlsWindow->show();
                m_controlsWindow->raise();
            }
        }

        void adjustToContent()
        {
            const int bodyWidth = kCardWidth - 42;
            m_bodyLabel->setMaximumWidth(bodyWidth);
            updateLogHeightLimit();
            setFixedWidth(kCardWidth);
        }

        void updateLogHeightLimit()
        {
            m_bodyLabel->setMaximumHeight(QWIDGETSIZE_MAX);
            m_bodyLabel->adjustSize();
            const int naturalHeight = m_bodyLabel->sizeHint().height();
            const int maximumHeight = QFontMetrics(m_bodyLabel->font()).lineSpacing()
                * std::max(1, m_logMaximumLines);
            const bool canExpand = m_kind == Kind::Log
                && m_logHeightLimitEnabled
                && naturalHeight > maximumHeight;
            m_expandSlot->setVisible(canExpand);
            if (canExpand && !m_logExpanded)
            {
                m_bodyLabel->setMaximumHeight(maximumHeight);
            }
            m_expandButton->setArrowType(m_logExpanded ? Qt::UpArrow : Qt::DownArrow);
            m_expandButton->setToolTip(ks::i18n::text(
                m_logExpanded ? QStringLiteral("notification.collapse") : QStringLiteral("notification.expand"),
                m_logExpanded ? QStringLiteral("收起日志") : QStringLiteral("展开完整日志")));
            updateControlSizes();
            layout()->activate();
            m_frame->layout()->activate();
            adjustSize();
            syncControlsWindow();
        }

        Kind m_kind;
        QWidget* m_frame = nullptr;
        QLabel* m_titleLabel = nullptr;
        QLabel* m_bodyLabel = nullptr;
        QProgressBar* m_progressBar = nullptr;
        NotificationControlsWindow* m_controlsWindow = nullptr;
        QWidget* m_copySlot = nullptr;
        QWidget* m_expandSlot = nullptr;
        QToolButton* m_copyButton = nullptr;
        QToolButton* m_expandButton = nullptr;
        kLogLevel m_logLevel = kLogLevel::Info;
        kProgressTask m_progressTask; // 原始任务状态，主题/语言更新保持同一张卡片。
        QString m_copyText;
        std::function<void()> m_layoutChangedCallback;
        bool m_logHeightLimitEnabled = true;
        int m_logMaximumLines = 5;
        bool m_logExpanded = false;
    };

    struct NotificationCardRecord
    {
        NotificationCard::Kind kind = NotificationCard::Kind::Log;
        QPointer<NotificationCard> card;
        int progressPid = 0;
        kProgressTask task; // 上次已呈现数据，只刷新发生变化的任务卡片。
        qint64 expiresAtMs = 0;
    };

    NotificationCardManager::NotificationCardManager(
        QWidget* const mainWindow,
        QWidget* const clientAnchor,
        QObject* const parent)
        : QObject(parent)
        , m_mainWindow(mainWindow)
        , m_clientAnchor(clientAnchor)
    {
        g_notificationCardManager = this;
        m_lastLogRevision = KswordARKEventEntry.Revision();
        m_knownLogCount = KswordARKEventEntry.Snapshot().size();
        m_lastProgressRevision = 0;

        m_refreshTimer = new QTimer(this);
        m_refreshTimer->setInterval(100);
        connect(m_refreshTimer, &QTimer::timeout, this, [this]() { refreshFromManagers(); });
        m_refreshTimer->start();
        // 任务读取集中到 feed，通知计时器只处理日志过期和原有溢出布局。
        TaskSnapshotFeed::instance().subscribe(this,
            [this](const std::shared_ptr<const kProgressSnapshot>& snapshot)
            {
                refreshProgressCards(snapshot);
            });
    }

    NotificationCardManager::~NotificationCardManager()
    {
        if (g_notificationCardManager == this)
        {
            g_notificationCardManager = nullptr;
        }
        clearCards();
    }

    void NotificationCardManager::applySettings(const ks::settings::AppearanceSettings& settings)
    {
        const bool wasEnabled = m_settings.notificationCardsEnabled;
        m_settings = settings;
        if (!m_settings.notificationCardsEnabled)
        {
            clearCards();
            return;
        }
        if (!wasEnabled)
        {
            m_lastLogRevision = KswordARKEventEntry.Revision();
            m_knownLogCount = KswordARKEventEntry.Snapshot().size();
            m_lastProgressRevision = 0;
        }
        for (const std::unique_ptr<NotificationCardRecord>& record : m_cards)
        {
            if (record != nullptr && record->kind == NotificationCard::Kind::Log && record->card != nullptr)
            {
                record->card->setLogHeightLimit(
                    m_settings.notificationLogHeightLimitEnabled,
                    m_settings.notificationLogMaximumLines);
            }
        }
        trimLogCardsToMaximum(true);
        refreshProgressCards(TaskSnapshotFeed::instance().current(), true);
        reflowCards(true);
    }

    void NotificationCardManager::refreshVisuals()
    {
        for (const std::unique_ptr<NotificationCardRecord>& record : m_cards)
        {
            if (record != nullptr && record->card != nullptr)
            {
                record->card->refreshVisuals();
            }
        }
        reflowCards(false);
    }

    void NotificationCardManager::onHostGeometryChanged()
    {
        reflowCards(true);
    }

    void NotificationCardManager::clearCards()
    {
        for (const std::unique_ptr<NotificationCardRecord>& record : m_cards)
        {
            if (record != nullptr && record->card != nullptr)
            {
                record->card->dismiss(false);
            }
        }
        m_cards.clear();
        m_overflowProgressTaskIds.clear();
    }

    bool NotificationCardManager::isProgressTaskOverflowed(const int pid) const
    {
        return std::find(m_overflowProgressTaskIds.cbegin(), m_overflowProgressTaskIds.cend(), pid)
            != m_overflowProgressTaskIds.cend();
    }

    QWidget* NotificationCardManager::hostWindow() const
    {
        return m_mainWindow;
    }

    void NotificationCardManager::refreshFromManagers()
    {
        if (!m_settings.notificationCardsEnabled)
        {
            return;
        }
        refreshLogCards();
        removeExpiredLogCards();
        reflowCards(true);
    }

    void NotificationCardManager::refreshLogCards()
    {
        const std::size_t revision = KswordARKEventEntry.Revision();
        if (revision == m_lastLogRevision)
        {
            return;
        }
        const std::vector<kEvent> snapshot = KswordARKEventEntry.Snapshot();
        if (snapshot.size() < m_knownLogCount)
        {
            // 日志被清空后不补发清空前后的历史记录，下一条新日志再正常显示。
            m_knownLogCount = snapshot.size();
            m_lastLogRevision = revision;
            return;
        }
        for (std::size_t index = m_knownLogCount; index < snapshot.size(); ++index)
        {
            if (static_cast<int>(snapshot[index].level) >= m_settings.notificationMinimumLevel)
            {
                appendLogCard(snapshot[index]);
            }
        }
        m_knownLogCount = snapshot.size();
        m_lastLogRevision = revision;
    }

    void NotificationCardManager::refreshProgressCards(
        const std::shared_ptr<const kProgressSnapshot>& snapshot, const bool force)
    {
        if (!m_settings.notificationCardsEnabled || !snapshot || snapshot->revision < m_lastProgressRevision ||
            (!force && snapshot->revision == m_lastProgressRevision))
        {
            return;
        }
        std::vector<int> activeTaskIds;
        activeTaskIds.reserve(snapshot->tasks.size());
        for (const kProgressTask& taskItem : snapshot->tasks)
        {
            if (taskItem.hiddenInList)
            {
                continue;
            }
            activeTaskIds.push_back(taskItem.pid);
            auto existingIterator = std::find_if(
                m_cards.begin(),
                m_cards.end(),
                [&taskItem](const std::unique_ptr<NotificationCardRecord>& record) {
                    return record != nullptr
                        && record->kind == NotificationCard::Kind::Progress
                        && record->progressPid == taskItem.pid;
                });
            if (existingIterator == m_cards.end())
            {
                appendProgressCard(taskItem);
            }
            else if ((*existingIterator)->card != nullptr)
            {
                // 其他任务更新不会重复刷新这张卡片；强制主题/语言刷新仍复用旧控件。
                const kProgressTask& previous = (*existingIterator)->task;
                if (force || previous.state != taskItem.state || previous.progress != taskItem.progress ||
                    previous.taskName != taskItem.taskName || previous.stepName != taskItem.stepName ||
                    previous.generation != taskItem.generation ||
                    previous.hideProgressBarTemporarily != taskItem.hideProgressBarTemporarily)
                {
                    (*existingIterator)->card->setProgressTask(taskItem);
                    (*existingIterator)->task = taskItem;
                }
            }
        }

        for (std::size_t index = 0; index < m_cards.size();)
        {
            const std::unique_ptr<NotificationCardRecord>& record = m_cards[index];
            if (record != nullptr
                && record->kind == NotificationCard::Kind::Progress
                && std::find(activeTaskIds.cbegin(), activeTaskIds.cend(), record->progressPid) == activeTaskIds.cend())
            {
                removeRecordAt(index, false);
                continue;
            }
            ++index;
        }
        m_lastProgressRevision = snapshot->revision;
        setProperty("task_snapshot_revision", static_cast<qulonglong>(snapshot->revision));
        reflowCards(true);
    }

    void NotificationCardManager::removeExpiredLogCards()
    {
        const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
        for (std::size_t index = 0; index < m_cards.size();)
        {
            const std::unique_ptr<NotificationCardRecord>& record = m_cards[index];
            if (record != nullptr
                && record->kind == NotificationCard::Kind::Log
                && record->expiresAtMs > 0
                && record->expiresAtMs <= nowMs)
            {
                removeRecordAt(index, true);
                continue;
            }
            ++index;
        }
    }

    void NotificationCardManager::appendLogCard(const kEvent& eventItem)
    {
        auto record = std::make_unique<NotificationCardRecord>();
        record->kind = NotificationCard::Kind::Log;
        const QPointer<NotificationCardManager> managerGuard(this);
        record->card = new NotificationCard(NotificationCard::Kind::Log, [managerGuard]() {
            if (managerGuard != nullptr)
            {
                managerGuard->reflowCards(true);
            }
        });
        record->card->setLogEvent(
            eventItem,
            m_settings.notificationLogHeightLimitEnabled,
            m_settings.notificationLogMaximumLines);
        if (m_settings.notificationLogDisplaySeconds > 0)
        {
            record->expiresAtMs = QDateTime::currentMSecsSinceEpoch()
                + static_cast<qint64>(m_settings.notificationLogDisplaySeconds) * 1000;
        }
        m_cards.push_back(std::move(record));
        trimLogCardsToMaximum(true);
    }

    void NotificationCardManager::appendProgressCard(const kProgressTask& taskItem)
    {
        auto record = std::make_unique<NotificationCardRecord>();
        record->kind = NotificationCard::Kind::Progress;
        record->progressPid = taskItem.pid;
        record->task = taskItem;
        record->card = new NotificationCard(NotificationCard::Kind::Progress);
        record->card->setProgressTask(taskItem);
        m_cards.push_back(std::move(record));
    }

    void NotificationCardManager::removeRecordAt(const std::size_t index, const bool animate)
    {
        if (index >= m_cards.size())
        {
            return;
        }
        if (m_cards[index] != nullptr && m_cards[index]->card != nullptr)
        {
            m_cards[index]->card->dismiss(animate);
        }
        m_cards.erase(m_cards.begin() + static_cast<std::ptrdiff_t>(index));
    }

    void NotificationCardManager::trimLogCardsToMaximum(const bool animate)
    {
        const int maximumLogCards = m_settings.notificationMaximumVisibleLogCards;
        if (maximumLogCards <= 0)
        {
            return;
        }
        int logCardCount = 0;
        for (const std::unique_ptr<NotificationCardRecord>& record : m_cards)
        {
            if (record != nullptr && record->kind == NotificationCard::Kind::Log)
            {
                ++logCardCount;
            }
        }
        while (logCardCount > maximumLogCards)
        {
            const auto oldestLogIterator = std::find_if(
                m_cards.cbegin(),
                m_cards.cend(),
                [](const std::unique_ptr<NotificationCardRecord>& record) {
                    return record != nullptr && record->kind == NotificationCard::Kind::Log;
                });
            if (oldestLogIterator == m_cards.cend())
            {
                return;
            }
            removeRecordAt(
                static_cast<std::size_t>(std::distance(m_cards.cbegin(), oldestLogIterator)),
                animate);
            --logCardCount;
        }
    }

    void NotificationCardManager::reflowCards(const bool animate)
    {
        if (!m_settings.notificationCardsEnabled || m_cards.empty())
        {
            m_overflowProgressTaskIds.clear();
            return;
        }

        QRect targetBounds;
        const bool useMainWindowClientArea =
            m_settings.notificationDisplayPlacement == ks::settings::NotificationDisplayPlacement::MainWindow
            && m_mainWindow != nullptr
            && !m_mainWindow->isMinimized()
            && m_clientAnchor != nullptr
            && m_clientAnchor->isVisible();
        if (useMainWindowClientArea)
        {
            targetBounds = QRect(m_clientAnchor->mapToGlobal(QPoint(0, 0)), m_clientAnchor->size());
        }
        else
        {
            targetBounds = resolveScreenBounds(m_mainWindow);
        }
        if (targetBounds.width() <= 0 || targetBounds.height() <= 0)
        {
            return;
        }

        // 日志优先让位：当混合堆叠超过可用高度时，持续注销最旧日志。
        const auto occupiedHeight = [this]() {
            int total = 0;
            int count = 0;
            for (const std::unique_ptr<NotificationCardRecord>& record : m_cards)
            {
                if (record != nullptr && record->card != nullptr)
                {
                    total += record->card->sizeHint().height();
                    ++count;
                }
            }
            return total + std::max(0, count - 1) * kCardSpacing;
        };
        const int usableHeight = std::max(1, targetBounds.height() - 2 * kScreenMargin);
        while (occupiedHeight() > usableHeight)
        {
            const auto oldestLogIterator = std::find_if(
                m_cards.cbegin(),
                m_cards.cend(),
                [](const std::unique_ptr<NotificationCardRecord>& record) {
                    return record != nullptr && record->kind == NotificationCard::Kind::Log;
                });
            if (oldestLogIterator == m_cards.cend())
            {
                break;
            }
            const std::size_t index = static_cast<std::size_t>(std::distance(m_cards.cbegin(), oldestLogIterator));
            removeRecordAt(index, true);
        }

        m_overflowProgressTaskIds.clear();
        const int xPosition = targetBounds.right() - kScreenMargin - kCardWidth + 1;
        int cursorY = m_settings.notificationStackDirection == ks::settings::NotificationStackDirection::BottomUp
            ? targetBounds.bottom() - kScreenMargin + 1
            : targetBounds.top() + kScreenMargin;

        // 新卡片靠近堆叠起点，符合右下或右上通知对最新事件的预期。
        for (auto iterator = m_cards.rbegin(); iterator != m_cards.rend(); ++iterator)
        {
            const std::unique_ptr<NotificationCardRecord>& record = *iterator;
            if (record == nullptr || record->card == nullptr)
            {
                continue;
            }
            const int cardHeight = std::max(record->card->sizeHint().height(), record->card->height());
            int yPosition = cursorY;
            if (m_settings.notificationStackDirection == ks::settings::NotificationStackDirection::BottomUp)
            {
                yPosition = cursorY - cardHeight;
                cursorY = yPosition - kCardSpacing;
            }
            else
            {
                cursorY += cardHeight + kCardSpacing;
            }
            const QRect cardRect(xPosition, yPosition, kCardWidth, cardHeight);
            if (record->kind == NotificationCard::Kind::Progress
                && !targetBounds.adjusted(kScreenMargin, kScreenMargin, -kScreenMargin, -kScreenMargin).contains(cardRect))
            {
                m_overflowProgressTaskIds.push_back(record->progressPid);
            }
            record->card->animateTo(cardRect.topLeft(), animate);
        }
    }

    bool isProgressTaskNotificationOverflowed(const int pid)
    {
        return g_notificationCardManager != nullptr
            && g_notificationCardManager->isProgressTaskOverflowed(pid);
    }

    QWidget* notificationCardHostWindow()
    {
        return g_notificationCardManager != nullptr
            ? g_notificationCardManager->hostWindow()
            : nullptr;
    }
}
