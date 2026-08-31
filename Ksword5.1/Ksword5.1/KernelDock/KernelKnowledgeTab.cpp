#include "KernelKnowledgeTab.h"

#include "KernelKnowledgeCatalog.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFont>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QList>
#include <QMetaObject>
#include <QPointer>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStringList>
#include <QTextBrowser>
#include <QTextEdit>
#include <QTextCursor>
#include <QTextDocument>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QTreeWidgetItemIterator>
#include <QUrl>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <thread>
#include <utility>

namespace
{
    constexpr int kTopicIndexRole = Qt::UserRole + 201;
    constexpr int kAllCoverageData = -1;

    // uiText 作用：读取知识中心的通用界面文案。
    // 输入 keySuffix；返回本地化文本，缺键时保留完整键以便校验定位。
    QString uiText(const char* keySuffix)
    {
        const QString key = QStringLiteral("kernel.knowledge.ui.%1")
            .arg(QString::fromLatin1(keySuffix));
        return ks::i18n::text(key);
    }

    // badgeStyle 作用：生成紧凑状态徽标样式，不向全局 QSS 注入几何规则。
    // 输入文字颜色；返回仅供知识页 QLabel 使用的局部样式。
    QString badgeStyle(const QString& textColor)
    {
        return QStringLiteral(
            "QLabel{padding:3px 8px;border:1px solid %1;border-radius:9px;"
            "background:%2;color:%3;font-weight:600;}")
            .arg(
                KswordTheme::BorderColorHex(),
                KswordTheme::SurfaceAltColorHex(),
                textColor);
    }

    // coverageColor 作用：为底层能力覆盖标签选择语义颜色。
    // 输入 coverage；返回当前主题下有可读对比度的文字颜色。
    QString coverageColor(const ks::kernel_knowledge::Coverage coverage)
    {
        using ks::kernel_knowledge::Coverage;
        switch (coverage)
        {
        case Coverage::Available:
            return KswordTheme::SuccessHex();
        case Coverage::AvailableNeedsExplanation:
            return KswordTheme::InfoHex();
        case Coverage::Partial:
            return KswordTheme::WarningHex();
        case Coverage::Planned:
            return KswordTheme::TextSecondaryColorHex();
        }
        return KswordTheme::TextSecondaryColorHex();
    }
}

KernelKnowledgeTab::KernelKnowledgeTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    retranslateUi();
    applyTheme();
}

void KernelKnowledgeTab::setRouteHandler(RouteHandler handler)
{
    m_routeHandler = std::move(handler);
    if (m_routeButton != nullptr)
    {
        m_routeButton->setEnabled(
            static_cast<bool>(m_routeHandler) && !m_currentRouteId.isEmpty());
    }
}

void KernelKnowledgeTab::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr)
    {
        return;
    }

    if (event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
    else if (event->type() == QEvent::PaletteChange ||
             event->type() == QEvent::ApplicationPaletteChange)
    {
        applyTheme();
        if (m_currentTopicIndex >= 0)
        {
            showTopic(m_currentTopicIndex);
        }
    }
}

void KernelKnowledgeTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* mainSplitter = new QSplitter(Qt::Horizontal, this);
    mainSplitter->setChildrenCollapsible(false);
    rootLayout->addWidget(mainSplitter, 1);

    // 左侧只承担筛选与目录，设置合理最小宽度但允许用户自由拖动分隔线。
    auto* directoryPanel = new QWidget(mainSplitter);
    auto* directoryLayout = new QVBoxLayout(directoryPanel);
    directoryLayout->setContentsMargins(0, 0, 0, 0);
    directoryLayout->setSpacing(6);

    m_searchEdit = new QLineEdit(directoryPanel);
    m_searchEdit->setClearButtonEnabled(true);
    directoryLayout->addWidget(m_searchEdit, 0);

    auto* filterLayout = new QHBoxLayout();
    filterLayout->setContentsMargins(0, 0, 0, 0);
    filterLayout->setSpacing(6);
    m_coverageCombo = new QComboBox(directoryPanel);
    m_resultCountLabel = new QLabel(directoryPanel);
    m_resultCountLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    filterLayout->addWidget(m_coverageCombo, 1);
    filterLayout->addWidget(m_resultCountLabel, 0);
    directoryLayout->addLayout(filterLayout);

    m_topicTree = new QTreeWidget(directoryPanel);
    m_topicTree->setColumnCount(2);
    m_topicTree->setRootIsDecorated(true);
    m_topicTree->setUniformRowHeights(true);
    m_topicTree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_topicTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_topicTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_topicTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    directoryLayout->addWidget(m_topicTree, 1);

    // 右侧文章是语义化 Markdown（标题、代码块关系图和外部参考链接），
    // QTextBrowser 比代码编辑器更适合这类不可编辑的富文本教学材料。
    auto* articlePanel = new QWidget(mainSplitter);
    auto* articleLayout = new QVBoxLayout(articlePanel);
    articleLayout->setContentsMargins(0, 0, 0, 0);
    articleLayout->setSpacing(6);

    m_titleLabel = new QLabel(articlePanel);
    m_titleLabel->setWordWrap(true);
    m_titleLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    articleLayout->addWidget(m_titleLabel, 0);

    m_summaryLabel = new QLabel(articlePanel);
    m_summaryLabel->setWordWrap(true);
    m_summaryLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    articleLayout->addWidget(m_summaryLabel, 0);

    auto* articleToolLayout = new QHBoxLayout();
    articleToolLayout->setContentsMargins(0, 0, 0, 0);
    articleToolLayout->setSpacing(6);
    m_coverageBadge = new QLabel(articlePanel);
    m_knowledgeBadge = new QLabel(articlePanel);
    articleToolLayout->addWidget(m_coverageBadge, 0);
    articleToolLayout->addWidget(m_knowledgeBadge, 0);
    articleToolLayout->addStretch(1);

    m_previousButton = new QToolButton(articlePanel);
    m_previousButton->setIcon(QIcon(QStringLiteral(":/Icon/file_nav_back.svg")));
    m_nextButton = new QToolButton(articlePanel);
    m_nextButton->setIcon(QIcon(QStringLiteral(":/Icon/file_nav_forward.svg")));
    m_copyButton = new QToolButton(articlePanel);
    m_copyButton->setIcon(QIcon(QStringLiteral(":/Icon/codeeditor_copy.svg")));
    m_evidenceButton = new QToolButton(articlePanel);
    m_evidenceButton->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    m_routeButton = new QToolButton(articlePanel);
    m_routeButton->setIcon(QIcon(QStringLiteral(":/Icon/process_details.svg")));
    m_referenceButton = new QToolButton(articlePanel);
    m_referenceButton->setIcon(QIcon(QStringLiteral(":/Icon/codeeditor_open.svg")));

    // 所有简单动作保持纯图标；按钮尺寸统一使用全局紧凑工具栏 token。
    const QList<QToolButton*> actionButtons{
        m_previousButton,
        m_nextButton,
        m_copyButton,
        m_evidenceButton,
        m_routeButton,
        m_referenceButton
    };
    for (QToolButton* button : actionButtons)
    {
        button->setAutoRaise(true);
        KswordTheme::ApplyCompactIconButtonMetrics(button);
        articleToolLayout->addWidget(button, 0);
    }
    articleLayout->addLayout(articleToolLayout);

    m_articleView = new QTextBrowser(articlePanel);
    m_articleView->setOpenExternalLinks(false);
    m_articleView->setReadOnly(true);
    m_articleView->setTextInteractionFlags(
        Qt::TextBrowserInteraction | Qt::TextSelectableByKeyboard);
    articleLayout->addWidget(m_articleView, 1);

    mainSplitter->addWidget(directoryPanel);
    mainSplitter->addWidget(articlePanel);
    mainSplitter->setStretchFactor(0, 1);
    mainSplitter->setStretchFactor(1, 3);
    mainSplitter->setSizes({ 330, 990 });

    // 筛选、目录选择和工具按钮全部同步更新同一份当前专题状态。
    connect(m_searchEdit, &QLineEdit::textChanged, this, [this]() {
        const QString currentId = m_currentTopicIndex >= 0
            ? QString::fromLatin1(
                ks::kernel_knowledge::topics()[static_cast<std::size_t>(m_currentTopicIndex)].id)
            : QString();
        rebuildTree(currentId);
    });
    connect(
        m_coverageCombo,
        qOverload<int>(&QComboBox::currentIndexChanged),
        this,
        [this]()
        {
            const QString currentId = m_currentTopicIndex >= 0
                ? QString::fromLatin1(
                    ks::kernel_knowledge::topics()[static_cast<std::size_t>(m_currentTopicIndex)].id)
                : QString();
            rebuildTree(currentId);
        });
    connect(
        m_topicTree,
        &QTreeWidget::currentItemChanged,
        this,
        [this](QTreeWidgetItem* currentItem, QTreeWidgetItem*)
        {
            if (currentItem == nullptr)
            {
                return;
            }
            const QVariant indexValue = currentItem->data(0, kTopicIndexRole);
            if (indexValue.isValid())
            {
                showTopic(indexValue.toInt());
            }
        });
    connect(m_previousButton, &QToolButton::clicked, this, [this]() {
        navigateRelative(-1);
    });
    connect(m_nextButton, &QToolButton::clicked, this, [this]() {
        navigateRelative(1);
    });
    connect(m_copyButton, &QToolButton::clicked, this, [this]() {
        copyCurrentTopic();
    });
    connect(m_evidenceButton, &QToolButton::clicked, this, [this]() {
        collectCurrentEvidence();
    });
    connect(m_routeButton, &QToolButton::clicked, this, [this]() {
        openCurrentRoute();
    });
    connect(m_referenceButton, &QToolButton::clicked, this, [this]() {
        openCurrentReference();
    });
    connect(m_articleView, &QTextBrowser::anchorClicked, this, [](const QUrl& url) {
        // 文章正文来自可替换语言包；只允许打开目录声明的 Microsoft Learn 域名。
        if (url.scheme() == QStringLiteral("https") &&
            url.host().compare(QStringLiteral("learn.microsoft.com"), Qt::CaseInsensitive) == 0)
        {
            QDesktopServices::openUrl(url);
        }
    });
}

void KernelKnowledgeTab::retranslateUi()
{
    const QString currentTopicId = m_currentTopicIndex >= 0
        ? QString::fromLatin1(
            ks::kernel_knowledge::topics()[static_cast<std::size_t>(m_currentTopicIndex)].id)
        : QString();
    const int selectedCoverage = m_coverageCombo->currentData().isValid()
        ? m_coverageCombo->currentData().toInt()
        : kAllCoverageData;

    m_searchEdit->setPlaceholderText(uiText("search.placeholder"));
    m_searchEdit->setToolTip(uiText("search.tooltip"));
    m_coverageCombo->setToolTip(uiText("coverage.tooltip"));

    // 重建下拉项时阻断 currentIndexChanged，避免语言切换触发两次目录重建。
    {
        const QSignalBlocker blocker(m_coverageCombo);
        m_coverageCombo->clear();
        m_coverageCombo->addItem(uiText("coverage.all"), kAllCoverageData);
        const auto addCoverageWhenPresent = [this](
            const ks::kernel_knowledge::Coverage coverage)
        {
            const auto& catalog = ks::kernel_knowledge::topics();
            const bool present = std::any_of(
                catalog.cbegin(),
                catalog.cend(),
                [coverage](const ks::kernel_knowledge::TopicDefinition& topic)
                {
                    return topic.coverage == coverage;
                });
            if (present)
            {
                m_coverageCombo->addItem(
                    ks::kernel_knowledge::coverageText(coverage),
                    static_cast<int>(coverage));
            }
        };
        addCoverageWhenPresent(ks::kernel_knowledge::Coverage::Available);
        addCoverageWhenPresent(
            ks::kernel_knowledge::Coverage::AvailableNeedsExplanation);
        addCoverageWhenPresent(ks::kernel_knowledge::Coverage::Partial);
        addCoverageWhenPresent(ks::kernel_knowledge::Coverage::Planned);
        const int restoredIndex = m_coverageCombo->findData(selectedCoverage);
        m_coverageCombo->setCurrentIndex(restoredIndex >= 0 ? restoredIndex : 0);
    }

    m_previousButton->setToolTip(uiText("action.previous.tooltip"));
    m_nextButton->setToolTip(uiText("action.next.tooltip"));
    m_copyButton->setToolTip(uiText("action.copy.tooltip"));
    m_evidenceButton->setToolTip(uiText("action.evidence.tooltip"));
    m_routeButton->setToolTip(uiText("action.route.tooltip"));
    m_referenceButton->setToolTip(uiText("action.reference.tooltip"));
    m_previousButton->setAccessibleName(m_previousButton->toolTip());
    m_nextButton->setAccessibleName(m_nextButton->toolTip());
    m_copyButton->setAccessibleName(m_copyButton->toolTip());
    m_evidenceButton->setAccessibleName(m_evidenceButton->toolTip());
    m_routeButton->setAccessibleName(m_routeButton->toolTip());
    m_referenceButton->setAccessibleName(m_referenceButton->toolTip());

    rebuildTree(currentTopicId);
}

void KernelKnowledgeTab::applyTheme()
{
    m_titleLabel->setStyleSheet(QStringLiteral(
        "QLabel{color:%1;font-size:18px;font-weight:700;padding:2px 0;}")
        .arg(KswordTheme::TextPrimaryHex()));
    m_summaryLabel->setStyleSheet(QStringLiteral(
        "QLabel{color:%1;padding:0 0 4px 0;}")
        .arg(KswordTheme::TextSecondaryHex()));
    m_resultCountLabel->setStyleSheet(QStringLiteral("color:%1;")
        .arg(KswordTheme::TextSecondaryHex()));
    m_knowledgeBadge->setStyleSheet(badgeStyle(KswordTheme::SuccessHex()));

    m_topicTree->setStyleSheet(QStringLiteral(
        "QTreeWidget{background:%1;color:%2;border:1px solid %3;border-radius:4px;}"
        "QTreeWidget::item:selected{background:%4;color:%5;}")
        .arg(
            KswordTheme::SurfaceHex(),
            KswordTheme::TextPrimaryHex(),
            KswordTheme::BorderHex(),
            KswordTheme::PrimaryBlueHex,
            KswordTheme::OnAccentDynamicHex()));
    m_articleView->setStyleSheet(QStringLiteral(
        "QTextBrowser{background:%1;color:%2;border:1px solid %3;"
        "border-radius:4px;padding:8px;}")
        .arg(
            KswordTheme::SurfaceHex(),
            KswordTheme::TextPrimaryHex(),
            KswordTheme::BorderHex()));

    // QTextDocument 使用实色而非 palette()，确保 Markdown 标题、代码块和链接随主题可读。
    m_articleView->document()->setDefaultStyleSheet(QStringLiteral(
        "body{color:%1;font-size:14px;line-height:1.45;}"
        "h3{color:%2;margin-top:16px;margin-bottom:6px;}"
        "pre{background:%3;border:1px solid %4;border-radius:4px;padding:8px;}"
        "code{font-family:Consolas,'Cascadia Mono',monospace;}"
        "a{color:%2;text-decoration:none;}"
        "hr{color:%4;}")
        .arg(
            KswordTheme::TextPrimaryColorHex(),
            KswordTheme::ControlAccentHex(),
            KswordTheme::SurfaceAltColorHex(),
            KswordTheme::BorderColorHex()));
}

void KernelKnowledgeTab::rebuildTree(const QString& preferredTopicId)
{
    using namespace ks::kernel_knowledge;

    const QStringList searchTerms = m_searchEdit->text()
        .simplified()
        .toCaseFolded()
        .split(QLatin1Char(' '), Qt::SkipEmptyParts);
    const int coverageFilter = m_coverageCombo->currentData().isValid()
        ? m_coverageCombo->currentData().toInt()
        : kAllCoverageData;
    const auto& topicCatalog = topics();

    m_visibleTopicIndexes.clear();
    {
        // clear() 会触发 currentItemChanged；阻断信号，等完整树建好后一次性恢复选择。
        const QSignalBlocker blocker(m_topicTree);
        m_topicTree->clear();
        m_topicTree->setHeaderLabels({
            uiText("tree.header.topic"),
            uiText("tree.header.coverage")
        });

        for (const CategoryDefinition& category : categories())
        {
            QTreeWidgetItem* categoryItem = nullptr;
            for (std::size_t topicOffset = 0; topicOffset < topicCatalog.size(); ++topicOffset)
            {
                const TopicDefinition& topic = topicCatalog[topicOffset];
                if (QString::fromLatin1(topic.categoryId) != QString::fromLatin1(category.id))
                {
                    continue;
                }
                if (coverageFilter != kAllCoverageData &&
                    coverageFilter != static_cast<int>(topic.coverage))
                {
                    continue;
                }

                // 搜索同时覆盖正文，读者可直接按 API、结构名、限制或 Ksword 字段定位。
                QString searchableText = QStringLiteral("%1 %2 %3 %4")
                    .arg(
                        QString::fromLatin1(topic.id),
                        topicText(topic, "title"),
                        topicText(topic, "summary"),
                        topicText(topic, "body"))
                    .toCaseFolded();
                const bool matchesSearch = std::all_of(
                    searchTerms.cbegin(),
                    searchTerms.cend(),
                    [&searchableText](const QString& term)
                    {
                        return searchableText.contains(term);
                    });
                if (!matchesSearch)
                {
                    continue;
                }

                if (categoryItem == nullptr)
                {
                    categoryItem = new QTreeWidgetItem(m_topicTree);
                    categoryItem->setText(0, categoryText(category));
                    categoryItem->setFirstColumnSpanned(true);
                    QFont categoryFont = categoryItem->font(0);
                    categoryFont.setBold(true);
                    categoryItem->setFont(0, categoryFont);
                }

                auto* topicItem = new QTreeWidgetItem(categoryItem);
                topicItem->setText(0, topicText(topic, "title"));
                topicItem->setText(1, coverageText(topic.coverage));
                topicItem->setToolTip(0, topicText(topic, "summary"));
                topicItem->setData(
                    0,
                    kTopicIndexRole,
                    static_cast<int>(topicOffset));
                m_visibleTopicIndexes.push_back(static_cast<int>(topicOffset));
            }

            if (categoryItem != nullptr)
            {
                categoryItem->setExpanded(true);
            }
        }
    }

    m_resultCountLabel->setText(
        uiText("result_count")
            .arg(static_cast<qulonglong>(m_visibleTopicIndexes.size()))
            .arg(static_cast<qulonglong>(topicCatalog.size())));

    int targetIndex = findTopicIndex(preferredTopicId);
    if (std::find(
            m_visibleTopicIndexes.cbegin(),
            m_visibleTopicIndexes.cend(),
            targetIndex) == m_visibleTopicIndexes.cend())
    {
        targetIndex = m_visibleTopicIndexes.empty() ? -1 : m_visibleTopicIndexes.front();
    }

    if (targetIndex >= 0)
    {
        selectTopic(targetIndex);
        showTopic(targetIndex);
    }
    else
    {
        showTopic(-1);
    }
}

void KernelKnowledgeTab::showTopic(const int topicIndex)
{
    using namespace ks::kernel_knowledge;
    const auto& topicCatalog = topics();
    if (topicIndex < 0 || topicIndex >= static_cast<int>(topicCatalog.size()))
    {
        ++m_evidenceGeneration;
        m_currentTopicIndex = -1;
        m_currentRouteId.clear();
        m_currentReferenceUrl.clear();
        m_titleLabel->setText(uiText("empty.title"));
        m_summaryLabel->setText(uiText("empty.summary"));
        m_coverageBadge->clear();
        m_knowledgeBadge->clear();
        m_articleView->clear();
        m_previousButton->setEnabled(false);
        m_nextButton->setEnabled(false);
        m_copyButton->setEnabled(false);
        m_evidenceButton->setEnabled(false);
        m_routeButton->setEnabled(false);
        m_referenceButton->setEnabled(false);
        return;
    }

    if (m_currentTopicIndex != topicIndex)
    {
        ++m_evidenceGeneration;
    }
    m_currentTopicIndex = topicIndex;
    const TopicDefinition& topic = topicCatalog[static_cast<std::size_t>(topicIndex)];
    const CategoryDefinition* category = categoryForTopic(topic);
    m_currentRouteId = QString::fromLatin1(topic.routeId != nullptr ? topic.routeId : "");
    m_currentReferenceUrl = category != nullptr && category->referenceUrl != nullptr
        ? QString::fromLatin1(category->referenceUrl)
        : QString();

    m_titleLabel->setText(topicText(topic, "title"));
    m_summaryLabel->setText(topicText(topic, "summary"));
    m_coverageBadge->setText(
        uiText("badge.coverage").arg(coverageText(topic.coverage)));
    m_coverageBadge->setStyleSheet(badgeStyle(coverageColor(topic.coverage)));
    m_knowledgeBadge->setText(uiText("badge.knowledge_complete"));

    QString articleMarkdown = topicText(topic, "body");
    if (!m_currentReferenceUrl.isEmpty())
    {
        articleMarkdown += QStringLiteral("\n\n---\n\n[%1](%2)")
            .arg(uiText("reference.microsoft"), m_currentReferenceUrl);
    }
    const QTextDocument::MarkdownFeatures markdownFeatures =
        QTextDocument::MarkdownFeatures(QTextDocument::MarkdownDialectGitHub) |
        QTextDocument::MarkdownNoHTML;
    m_articleView->document()->setMarkdown(articleMarkdown, markdownFeatures);
    QTextCursor topCursor = m_articleView->textCursor();
    topCursor.movePosition(QTextCursor::Start);
    m_articleView->setTextCursor(topCursor);
    m_articleView->verticalScrollBar()->setValue(0);

    const auto visiblePosition = std::find(
        m_visibleTopicIndexes.cbegin(),
        m_visibleTopicIndexes.cend(),
        topicIndex);
    const int position = visiblePosition != m_visibleTopicIndexes.cend()
        ? static_cast<int>(std::distance(m_visibleTopicIndexes.cbegin(), visiblePosition))
        : -1;
    m_previousButton->setEnabled(position > 0);
    m_nextButton->setEnabled(
        position >= 0 && position + 1 < static_cast<int>(m_visibleTopicIndexes.size()));
    m_copyButton->setEnabled(true);
    m_evidenceButton->setToolTip(uiText("action.evidence.tooltip"));
    m_evidenceButton->setEnabled(true);
    m_routeButton->setEnabled(
        static_cast<bool>(m_routeHandler) && !m_currentRouteId.isEmpty());
    m_referenceButton->setEnabled(!m_currentReferenceUrl.isEmpty());
}

bool KernelKnowledgeTab::selectTopic(const int topicIndex)
{
    QTreeWidgetItemIterator iterator(m_topicTree);
    while (*iterator != nullptr)
    {
        QTreeWidgetItem* item = *iterator;
        const QVariant indexValue = item->data(0, kTopicIndexRole);
        if (indexValue.isValid() && indexValue.toInt() == topicIndex)
        {
            m_topicTree->setCurrentItem(item);
            m_topicTree->scrollToItem(item, QAbstractItemView::PositionAtCenter);
            return true;
        }
        ++iterator;
    }
    return false;
}

int KernelKnowledgeTab::findTopicIndex(const QString& topicId) const
{
    if (topicId.isEmpty())
    {
        return -1;
    }

    const auto& topicCatalog = ks::kernel_knowledge::topics();
    for (std::size_t topicIndex = 0; topicIndex < topicCatalog.size(); ++topicIndex)
    {
        if (QString::fromLatin1(topicCatalog[topicIndex].id) == topicId)
        {
            return static_cast<int>(topicIndex);
        }
    }
    return -1;
}

void KernelKnowledgeTab::navigateRelative(const int delta)
{
    const auto currentPosition = std::find(
        m_visibleTopicIndexes.cbegin(),
        m_visibleTopicIndexes.cend(),
        m_currentTopicIndex);
    if (currentPosition == m_visibleTopicIndexes.cend())
    {
        return;
    }

    const int sourcePosition = static_cast<int>(
        std::distance(m_visibleTopicIndexes.cbegin(), currentPosition));
    const int targetPosition = sourcePosition + delta;
    if (targetPosition < 0 ||
        targetPosition >= static_cast<int>(m_visibleTopicIndexes.size()))
    {
        return;
    }

    const int targetTopicIndex = m_visibleTopicIndexes[static_cast<std::size_t>(targetPosition)];
    selectTopic(targetTopicIndex);
    showTopic(targetTopicIndex);
}

void KernelKnowledgeTab::copyCurrentTopic() const
{
    if (m_currentTopicIndex < 0)
    {
        return;
    }

    const auto& topic = ks::kernel_knowledge::topics()[
        static_cast<std::size_t>(m_currentTopicIndex)];
    QString copyText = QStringLiteral("# %1\n\n%2\n\n%3")
        .arg(
            ks::kernel_knowledge::topicText(topic, "title"),
            ks::kernel_knowledge::topicText(topic, "summary"),
            ks::kernel_knowledge::topicText(topic, "body"));
    if (!m_currentReferenceUrl.isEmpty())
    {
        copyText += QStringLiteral("\n\n%1: %2")
            .arg(uiText("reference.microsoft"), m_currentReferenceUrl);
    }
    QApplication::clipboard()->setText(copyText);
}

void KernelKnowledgeTab::openCurrentRoute() const
{
    if (m_routeHandler && !m_currentRouteId.isEmpty())
    {
        m_routeHandler(m_currentRouteId);
    }
}

void KernelKnowledgeTab::openCurrentReference() const
{
    if (!m_currentReferenceUrl.isEmpty())
    {
        QDesktopServices::openUrl(QUrl(m_currentReferenceUrl));
    }
}

void KernelKnowledgeTab::collectCurrentEvidence()
{
    if (m_currentTopicIndex < 0 || m_evidenceButton == nullptr)
    {
        return;
    }

    const unsigned long topicId = static_cast<unsigned long>(m_currentTopicIndex + 1);
    const QString topicTitle = m_titleLabel->text();
    const std::uint64_t generation = ++m_evidenceGeneration;
    m_evidenceButton->setEnabled(false);
    m_evidenceButton->setToolTip(uiText("evidence.collecting"));

    QPointer<KernelKnowledgeTab> guard(this);
    std::thread([guard, generation, topicId, topicTitle]() mutable
    {
        auto result = ksword::ark::DriverClient().queryResearchTopic(topicId);
        if (guard.isNull())
        {
            return;
        }
        QMetaObject::invokeMethod(
            guard.data(),
            [guard, generation, topicId, topicTitle, result = std::move(result)]() mutable
            {
                if (guard.isNull() || guard->m_evidenceGeneration != generation)
                {
                    return;
                }

                guard->m_evidenceButton->setEnabled(true);
                guard->m_evidenceButton->setToolTip(uiText("action.evidence.tooltip"));

                auto* dialog = new QDialog(guard.data());
                dialog->setAttribute(Qt::WA_DeleteOnClose, true);
                dialog->setWindowTitle(
                    uiText("evidence.dialog.title").arg(topicTitle));
                dialog->resize(900, 620);

                auto* layout = new QVBoxLayout(dialog);
                layout->setContentsMargins(10, 10, 10, 10);
                layout->setSpacing(8);
                auto* editor = new QTextEdit(dialog);
                editor->setReadOnly(true);
                editor->setLineWrapMode(QTextEdit::NoWrap);
                editor->setFont(QFont(QStringLiteral("Consolas"), 10));
                editor->setStyleSheet(QStringLiteral(
                    "QTextEdit{background:%1;color:%2;border:1px solid %3;"
                    "border-radius:4px;padding:6px;}")
                    .arg(
                        KswordTheme::SurfaceHex(),
                        KswordTheme::TextPrimaryHex(),
                        KswordTheme::BorderHex()));
                layout->addWidget(editor, 1);

                auto* buttons = new QDialogButtonBox(
                    QDialogButtonBox::Close,
                    dialog);
                QObject::connect(
                    buttons,
                    &QDialogButtonBox::rejected,
                    dialog,
                    &QDialog::reject);
                layout->addWidget(buttons, 0);

                QString report;
                if (!result.io.ok)
                {
                    report = uiText("evidence.unavailable")
                        .arg(topicId)
                        .arg(result.io.win32Error)
                        .arg(QString::fromStdString(result.io.message));
                }
                else
                {
                    const auto& response = result.response;
                    report += uiText("evidence.summary")
                        .arg(topicId)
                        .arg(response.queryStatus)
                        .arg(QString::number(response.responseFlags, 16).toUpper())
                        .arg(response.returnedCount)
                        .arg(response.totalCount)
                        .arg(response.registeredIoctlCount)
                        .arg(response.duplicateIoctlCount);
                    report += QLatin1Char('\n');
                    report += uiText("evidence.context")
                        .arg(response.requestorProcessId)
                        .arg(response.requestorThreadId)
                        .arg(response.currentIrql)
                        .arg(response.processorGroup)
                        .arg(response.processorNumber)
                        .arg(response.activeGroupCount)
                        .arg(response.activeProcessorCount)
                        .arg(QString::number(response.systemTime100ns))
                        .arg(QString::number(response.performanceCounter));
                    report += QStringLiteral("\n\n");

                    for (std::size_t index = 0U; index < result.entries.size(); ++index)
                    {
                        const auto& row = result.entries[index];
                        const QString state = row.state ==
                                KSWORD_ARK_RESEARCH_EVIDENCE_AVAILABLE
                            ? uiText("evidence.state.available")
                            : uiText("evidence.state.unavailable");
                        report += uiText("evidence.row")
                            .arg(static_cast<qulonglong>(index + 1U))
                            .arg(QString::fromLatin1(row.name))
                            .arg(row.kind)
                            .arg(state)
                            .arg(row.confidence)
                            .arg(QString::number(row.sourceMask, 16).toUpper())
                            .arg(QString::number(row.ioControlCode, 16).toUpper())
                            .arg(QString::number(
                                static_cast<unsigned long>(row.lastStatus),
                                16).toUpper())
                            .arg(QString::number(row.value0, 16).toUpper())
                            .arg(QString::number(row.value1, 16).toUpper())
                            .arg(QString::number(row.value2, 16).toUpper())
                            .arg(QString::number(row.value3, 16).toUpper());
                        report += QLatin1Char('\n');
                    }
                    report += QStringLiteral("\n");
                    report += uiText("evidence.boundary");
                }

                editor->setPlainText(report);
                dialog->show();
            },
            Qt::QueuedConnection);
    }).detach();
}
