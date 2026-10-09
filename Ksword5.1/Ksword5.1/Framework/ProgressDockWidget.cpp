#include "ProgressDockWidget.h"
#include "TaskSnapshotFeed.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QEvent>
#include <QFrame>        // 任务卡片容器
#include <QLabel>        // 任务与步骤文本
#include <QProgressBar>  // 进度条显示
#include <QScrollArea>   // 列表滚动容器
#include <QTimer>        // 周期刷新
#include <QVBoxLayout>   // 纵向布局
#include <QSet>          // 当前快照保留的卡片 PID。

ProgressDockWidget::ProgressDockWidget(QWidget* parent)
    : QWidget(parent)
{
    // 构造时完成 UI 与定时器初始化，并先做一次首刷。
    initializeUi();
    initializeSnapshotFeed();
    refreshTaskCards(true);
}

void ProgressDockWidget::initializeUi()
{
    // 根布局：填满整个 Dock，可自适应大小变化。
    setObjectName(QStringLiteral("ksProgressDockRoot"));
    setAutoFillBackground(false);
    setAttribute(Qt::WA_StyledBackground, true);

    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(0, 0, 0, 0);
    m_rootLayout->setSpacing(0);

    // 滚动区域：用于容纳可增长的任务卡片列表。
    m_scrollArea = new QScrollArea(this);
    m_scrollArea->setObjectName(QStringLiteral("ksProgressDockScrollArea"));
    m_scrollArea->setWidgetResizable(true);
    m_scrollArea->setFrameShape(QFrame::NoFrame);
    m_scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_scrollArea->setAutoFillBackground(false);
    m_scrollArea->setAttribute(Qt::WA_StyledBackground, true);

    // viewport 单独命名并强制透明，避免 QAbstractScrollArea 默认底色露出。
    m_scrollArea->viewport()->setObjectName(QStringLiteral("ksProgressDockViewport"));
    m_scrollArea->viewport()->setAutoFillBackground(false);
    m_scrollArea->viewport()->setAttribute(Qt::WA_StyledBackground, true);

    // 滚动内容控件：真正承载卡片布局的中间层。
    m_scrollContent = new QWidget(m_scrollArea);
    m_scrollContent->setObjectName(QStringLiteral("ksProgressDockScrollContent"));
    m_scrollContent->setAutoFillBackground(false);
    m_scrollContent->setAttribute(Qt::WA_StyledBackground, true);
    m_cardLayout = new QVBoxLayout(m_scrollContent);
    m_cardLayout->setContentsMargins(8, 8, 8, 8);
    m_cardLayout->setSpacing(8);

    // 统一透明策略：让 Dock 背景透出，只保留任务内容本身。
    applyTransparentBackgroundPolicy();

    // 空列表提示：无任务时展示，提升可读性。
    m_emptyTipLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("progress.empty"),
            QStringLiteral("当前没有进行中的任务。")),
        m_scrollContent);
    m_emptyTipLabel->setAlignment(Qt::AlignCenter);
    m_emptyTipLabel->setStyleSheet(
        QStringLiteral("color:%1; font-size:13px; background:transparent;")
        .arg(buildHighContrastTextHex()));
    m_cardLayout->addWidget(m_emptyTipLabel);
    m_cardLayout->addStretch(1);

    // 把内容控件挂到滚动区域，再挂到根布局。
    m_scrollArea->setWidget(m_scrollContent);
    m_rootLayout->addWidget(m_scrollArea);
}

void ProgressDockWidget::applyTransparentBackgroundPolicy()
{
    // 透明样式作用范围：
    // - 根控件；
    // - QScrollArea；
    // - viewport；
    // - 承载卡片的滚动内容层。
    setStyleSheet(
        QStringLiteral(
        "#ksProgressDockRoot,"
        "#ksProgressDockScrollArea,"
        "#ksProgressDockViewport,"
        "#ksProgressDockScrollContent{"
        "  background:transparent;"
        "  background-color:transparent;"
        "  color:%1;"
        "  border:none;"
        "}"
        "#ksProgressDockRoot QLabel{"
        "  color:%1;"
        "  background:transparent;"
        "}"
        "#ksProgressDockRoot QProgressBar{"
        "  color:%1;"
        "}")
        .arg(buildHighContrastTextHex()));
}

void ProgressDockWidget::initializeSnapshotFeed()
{
    // 当前操作和角落通知订阅唯一发布器；每轮只读取一次核心快照。
    ks::ui::TaskSnapshotFeed::instance().subscribe(this,
        [this](const std::shared_ptr<const kProgressSnapshot>& snapshot)
        {
            applyTaskSnapshot(snapshot, false);
        });
}

void ProgressDockWidget::refreshThemeVisuals()
{
    // 主题刷新原位重绘任务卡片；不重建 QWidget，不改变滚动条位置。
    applyTransparentBackgroundPolicy();
    if (m_emptyTipLabel != nullptr)
    {
        m_emptyTipLabel->setStyleSheet(
            QStringLiteral("color:%1; font-size:13px; background:transparent;")
            .arg(buildHighContrastTextHex()));
    }
    refreshTaskCards(true);
}

void ProgressDockWidget::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
    else if (event != nullptr && event->type() == QEvent::ApplicationPaletteChange)
    {
        refreshThemeVisuals();
    }
}

void ProgressDockWidget::retranslateUi()
{
    if (m_emptyTipLabel != nullptr)
    {
        m_emptyTipLabel->setText(ks::i18n::contextText(
            QStringLiteral("progress.empty"),
            QStringLiteral("当前没有进行中的任务。")));
    }
    refreshTaskCards(true);
}

void ProgressDockWidget::refreshTaskCards(const bool forceRefresh)
{
    ks::ui::TaskSnapshotFeed::instance().refreshNow();
    applyTaskSnapshot(ks::ui::TaskSnapshotFeed::instance().current(), forceRefresh);
}

void ProgressDockWidget::applyTaskSnapshot(
    const std::shared_ptr<const kProgressSnapshot>& snapshot, const bool forceRefresh)
{
    if (!snapshot || snapshot->revision < m_lastRevision ||
        (!forceRefresh && snapshot->revision == m_lastRevision))
    {
        return;
    }
    m_lastRevision = snapshot->revision;
    setProperty("task_snapshot_revision", static_cast<qulonglong>(snapshot->revision));

    // 先同步差量数据，再只调整现有卡片的布局顺序，保证同 PID 控件始终复用。
    QSet<int> activeIds;
    int visibleIndex = 0;
    for (const kProgressTask& taskItem : snapshot->tasks)
    {
        if (taskItem.hiddenInList)
        {
            continue;
        }

        activeIds.insert(taskItem.pid);
        QWidget* cardWidget = m_cards.value(taskItem.pid, nullptr);
        const bool newlyCreated = cardWidget == nullptr;
        if (newlyCreated)
        {
            cardWidget = createTaskCardWidget(taskItem);
            m_cards.insert(taskItem.pid, cardWidget);
        }
        const kProgressTask previous = m_renderedTasks.value(taskItem.pid);
        if (newlyCreated || forceRefresh || previous.state != taskItem.state ||
            previous.progress != taskItem.progress || previous.taskName != taskItem.taskName ||
            previous.stepName != taskItem.stepName || previous.generation != taskItem.generation ||
            previous.hideProgressBarTemporarily != taskItem.hideProgressBarTemporarily)
        {
            updateTaskCardWidget(cardWidget, taskItem);
            m_renderedTasks.insert(taskItem.pid, taskItem);
        }
        if (m_cardLayout->indexOf(cardWidget) != visibleIndex)
        {
            m_cardLayout->removeWidget(cardWidget);
            m_cardLayout->insertWidget(visibleIndex, cardWidget);
        }
        ++visibleIndex;
    }
    for (auto iterator = m_cards.begin(); iterator != m_cards.end();)
    {
        if (!activeIds.contains(iterator.key()))
        {
            m_cardLayout->removeWidget(iterator.value());
            iterator.value()->hide();
            iterator.value()->deleteLater();
            m_renderedTasks.remove(iterator.key());
            iterator = m_cards.erase(iterator);
        }
        else
        {
            ++iterator;
        }
    }
    m_emptyTipLabel->setVisible(activeIds.isEmpty());
}

QWidget* ProgressDockWidget::createTaskCardWidget(const kProgressTask& taskItem) const
{
    // 卡片容器：取消边框，仅保留轻量半透明底色，避免“框线感”。
    QFrame* cardFrame = new QFrame();
    cardFrame->setObjectName(QStringLiteral("task_card"));
    cardFrame->setProperty("task_pid", taskItem.pid);
    cardFrame->setFrameShape(QFrame::NoFrame);
    cardFrame->setStyleSheet(
        QStringLiteral(
        "QFrame {"
        "  border:none;"
        "  border-radius:4px;"
        "  background:%1;"
        "}")
        .arg(buildCardBackgroundHex()));

    // 卡片内部布局：任务标题、步骤、进度条依次排列。
    QVBoxLayout* cardLayout = new QVBoxLayout(cardFrame);
    cardLayout->setContentsMargins(10, 8, 10, 8);
    cardLayout->setSpacing(6);

    // 顶部标题：展示任务名与 PID，便于排查/定位。
    const QString translatedTaskName = ks::i18n::sourceText(
        QString::fromUtf8(taskItem.taskName.c_str()));
    QLabel* titleLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("progress.task.title"),
            QStringLiteral("%1  (PID:%2)"))
        .arg(translatedTaskName)
        .arg(taskItem.pid),
        cardFrame);
    titleLabel->setObjectName(QStringLiteral("task_title"));
    titleLabel->setStyleSheet(
        QStringLiteral("font-weight:600; color:%1; background:transparent;")
        .arg(buildHighContrastTextHex()));
    cardLayout->addWidget(titleLabel);

    // 第二行：步骤文本改为与标题同级的高对比颜色，避免灰字看不清。
    const QString translatedStepName = ks::i18n::sourceText(
        QString::fromUtf8(taskItem.stepName.c_str()));
    QLabel* stepLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("progress.task.step"),
            QStringLiteral("步骤：%1"))
        .arg(translatedStepName),
        cardFrame);
    stepLabel->setObjectName(QStringLiteral("task_step"));
    stepLabel->setStyleSheet(
        QStringLiteral("color:%1; background:transparent;")
        .arg(buildHighContrastTextHex()));
    cardLayout->addWidget(stepLabel);

    // 进度条：保留蓝色进度块，并同步设置高对比文字与无边框底轨。
    QProgressBar* progressBar = new QProgressBar(cardFrame);
    progressBar->setObjectName(QStringLiteral("task_progress"));
    progressBar->setRange(0, 100);
    progressBar->setValue(static_cast<int>(taskItem.progress * 100.0f + 0.5f));
    progressBar->setFormat(QStringLiteral("%p%"));
    progressBar->setVisible(!taskItem.hideProgressBarTemporarily);
    progressBar->setTextVisible(true);
    progressBar->setStyleSheet(buildProgressBarStyleSheet());
    cardLayout->addWidget(progressBar);

    return cardFrame;
}

void ProgressDockWidget::updateTaskCardWidget(QWidget* const card, const kProgressTask& taskItem) const
{
    // 复用卡片只改正文、状态与主题；成员查找使用稳定 objectName，不跨事件保存内部指针。
    auto* title = card->findChild<QLabel*>(QStringLiteral("task_title"));
    auto* step = card->findChild<QLabel*>(QStringLiteral("task_step"));
    auto* progress = card->findChild<QProgressBar*>(QStringLiteral("task_progress"));
    card->setProperty("task_state", static_cast<int>(taskItem.state));
    card->setProperty("task_generation", static_cast<qulonglong>(taskItem.generation));
    const QString stateText = ks::ui::TaskStateText(taskItem.state);
    title->setText(ks::i18n::contextText(QStringLiteral("progress.task.title"), QStringLiteral("%1  (PID:%2)"))
        .arg(ks::i18n::sourceText(QString::fromUtf8(taskItem.taskName.c_str())))
        .arg(taskItem.pid) + QStringLiteral("  ·  ") + stateText);
    title->setStyleSheet(QStringLiteral("font-weight:600; color:%1; background:transparent;")
        .arg(KswordTheme::ThemeColorName(KswordTheme::EnsureTextContrast(
            ks::ui::TaskStateColor(taskItem.state), KswordTheme::SurfaceColor()))));
    step->setText(ks::i18n::contextText(QStringLiteral("progress.task.step"), QStringLiteral("步骤：%1"))
        .arg(ks::i18n::sourceText(QString::fromUtf8(taskItem.stepName.c_str()))));
    step->setStyleSheet(QStringLiteral("color:%1; background:transparent;").arg(buildHighContrastTextHex()));
    progress->setValue(static_cast<int>(taskItem.progress * 100.0f + 0.5f));
    progress->setVisible(!taskItem.hideProgressBarTemporarily && !IsProgressTerminal(taskItem.state));
    progress->setStyleSheet(buildProgressBarStyleSheet());
    card->setStyleSheet(QStringLiteral("QFrame {border:none;border-radius:4px;background:%1;}")
        .arg(buildCardBackgroundHex()));
}

QString ProgressDockWidget::buildHighContrastTextHex() const
{
    // 高对比前景策略：
    // - 深色主题使用项目主文本白蓝色；
    // - 浅色主题使用深墨色；
    // 避免透明背景叠加后 palette(mid) 灰字对比不足。
    return KswordTheme::TextPrimaryColorHex();
}

QString ProgressDockWidget::buildCardBackgroundHex() const
{
    // 卡片底色策略：
    // - 仅保留轻微半透明底色提升可读性；
    // - 不绘制任何边框，满足“取消框线”的要求。
    return KswordTheme::RgbaColorName(
        KswordTheme::IsDarkModeEnabled()
            ? KswordTheme::BlackColor()
            : KswordTheme::WhiteColor(),
        KswordTheme::IsDarkModeEnabled() ? 96 : 176);
}

QString ProgressDockWidget::buildProgressBarStyleSheet() const
{
    // 进度条样式策略：
    // - 底轨不画边框；
    // - 文本颜色与主题一致；
    // - 蓝色进度块维持全局主色一致性。
    const QString progressTrackColor = KswordTheme::RgbaColorName(
        KswordTheme::IsDarkModeEnabled()
            ? KswordTheme::WhiteColor()
            : KswordTheme::BlackColor(),
        KswordTheme::IsDarkModeEnabled() ? 48 : 28);

    return QStringLiteral(
        "QProgressBar{"
        "  border:none;"
        "  border-radius:3px;"
        "  background:%1;"
        "  color:%2;"
        "  text-align:center;"
        "  min-height:16px;"
        "}"
        "QProgressBar::chunk{"
        "  border:none;"
        "  border-radius:3px;"
        "  background:%3;"
        "}")
        .arg(progressTrackColor)
        .arg(buildHighContrastTextHex())
        .arg(KswordTheme::PrimaryBlueHex);
}
