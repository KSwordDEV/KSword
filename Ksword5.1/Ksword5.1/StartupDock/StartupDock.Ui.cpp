#include "StartupDock.Internal.h"

#include <QElapsedTimer>
#include <QThreadPool>
#include "../UI/VisibleTableWidget.h"
#include "../UI/ThemeBinding.h"
#include "../UI/AsyncOperation.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/PageControlStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ToolbarMetrics.h"
#include "../Internationalization/LanguageManager.h"

#include <QColor>
#include <QPair>

namespace {
const ks::ui::PageNavigationTabDefinition kStartupDockNavigation[] = {
    {"startup.tab.overview", "", "startup.tab.overview", "总览", true},
    {"startup.tab.logon", "", "startup.tab.logon", "登录", false},
    {"startup.tab.services", "", "startup.tab.services", "服务", false},
    {"startup.tab.drivers", "", "startup.tab.drivers", "驱动", false},
    {"startup.tab.tasks", "", "startup.tab.tasks", "计划任务", false},
    {"startup.tab.image_hijack", "", "startup.tab.image_hijack", "映像劫持", false},
    {"startup.tab.registry", "", "startup.tab.registry", "高级注册表", false},
    {"startup.tab.wmi", "", "startup.tab.wmi", "WMI", false},
    {"startup.tab.hidden", "", "startup.tab.hidden", "隐藏项", false}
};
}
using namespace startup_dock_detail;

namespace startup_dock_detail
{
    QString startupText(const char* const key, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    }

    QStringList startupTableHeaders()
    {
        return {
            startupText("startup.header.name", QStringLiteral("名称")),
            startupText("startup.header.publisher", QStringLiteral("发布者")),
            startupText("startup.header.image_path", QStringLiteral("映像路径")),
            startupText("startup.header.command", QStringLiteral("命令")),
            startupText("startup.header.location", QStringLiteral("来源位置")),
            startupText("startup.header.user", QStringLiteral("用户")),
            startupText("startup.header.status", QStringLiteral("状态")),
            startupText("startup.header.type", QStringLiteral("类型")),
            startupText("startup.header.detail", QStringLiteral("详情"))
        };
    }
}

namespace
{
    // kToolbarIconSize 作用：
    // - 统一启动项页顶部图标按钮尺寸。
    constexpr QSize kToolbarIconSize(16, 16);

    // kUntrustedRowHighlightColor 作用：
    // - 定义不受信任启动项整行背景色；
    // - 采用半透明红色，确保风险可见且不遮挡文本。
    const QColor kUntrustedRowHighlightColor(255, 64, 64, 76);

    // isUntrustedStartupEntry 作用：
    // - 判断某条启动项是否属于不受信任目标；
    // - 调用方法：在行渲染前传入 StartupEntry；
    // - 传入参数 entry：当前待渲染的启动项数据；
    // - 返回值 true：需要按风险项做红色高亮，false：保持普通样式。
    bool isUntrustedStartupEntry(const StartupDock::StartupEntry& entry)
    {
        return entry.publisherText.contains(QStringLiteral("(Untrusted)"), Qt::CaseInsensitive)
            || (entry.category == StartupDock::StartupCategory::ImageHijack
                && entry.backendEntry.riskLevel == ks::startup::StartupRiskLevel::Critical);
    }

    // createStartupTable 作用：
    // - 创建统一列结构的启动项表格；
    // - 供六个分类页复用。
    QTableWidget* createStartupTable(QWidget* parentWidget)
    {
        QTableWidget* tableWidget = new ks::ui::VisibleTableWidget(parentWidget);
        // 启动项清单支持前后快照排查，保留完整操作栏。
        ks::ui::SetTableActionBarMode(tableWidget, ks::ui::TableActionBarMode::Full);
        tableWidget->setColumnCount(StartupDock::toStartupColumn(StartupDock::StartupColumn::Count));
        tableWidget->setHorizontalHeaderLabels(startupTableHeaders());
        tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableWidget->setSelectionMode(QAbstractItemView::ExtendedSelection);
        tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        tableWidget->setWordWrap(false);
        tableWidget->verticalHeader()->setVisible(false);
        tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        tableWidget->horizontalHeader()->setSectionResizeMode(
            StartupDock::toStartupColumn(StartupDock::StartupColumn::Detail),
            QHeaderView::Stretch);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::Name), 180);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::Publisher), 170);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::ImagePath), 260);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::Command), 300);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::Location), 260);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::User), 120);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::Enabled), 70);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::Type), 110);
        return tableWidget;
    }

    // createSingleTablePage 作用：
    // - 创建只承载单张表格的标签页容器。
    QWidget* createSingleTablePage(QTableWidget** tableOut, QWidget* parentWidget)
    {
        QWidget* pageWidget = new QWidget(parentWidget);
        QVBoxLayout* pageLayout = new QVBoxLayout(pageWidget);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(4);
        QTableWidget* tableWidget = createStartupTable(pageWidget);
        pageLayout->addWidget(tableWidget, 1);
        if (tableOut != nullptr)
        {
            *tableOut = tableWidget;
        }
        return pageWidget;
    }

    // createStartupTree 作用：
    // - 创建高级注册表页专用树控件；
    // - 一级节点对应注册表位置，二级节点对应具体启动项。
    QTreeWidget* createStartupTree(QWidget* parentWidget)
    {
        QTreeWidget* treeWidget = new QTreeWidget(parentWidget);
        treeWidget->setColumnCount(StartupDock::toStartupColumn(StartupDock::StartupColumn::Count));
        treeWidget->setHeaderLabels(startupTableHeaders());
        treeWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        treeWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        treeWidget->setWordWrap(false);
        treeWidget->setRootIsDecorated(true);
        treeWidget->setAlternatingRowColors(true);
        treeWidget->setUniformRowHeights(true);
        treeWidget->header()->setSectionResizeMode(QHeaderView::Interactive);
        treeWidget->header()->setSectionResizeMode(
            StartupDock::toStartupColumn(StartupDock::StartupColumn::Detail),
            QHeaderView::Stretch);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::Name), 260);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::Publisher), 170);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::ImagePath), 260);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::Command), 280);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::Location), 280);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::User), 120);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::Enabled), 70);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::Type), 130);
        return treeWidget;
    }

    // createRegistryTreePage 作用：
    // - 创建高级注册表页；
    // - 页内唯一主控件为按注册表位置分组的树。
    QWidget* createRegistryTreePage(QTreeWidget** treeOut, QWidget* parentWidget)
    {
        QWidget* pageWidget = new QWidget(parentWidget);
        QVBoxLayout* pageLayout = new QVBoxLayout(pageWidget);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(4);
        QTreeWidget* treeWidget = createStartupTree(pageWidget);
        pageLayout->addWidget(treeWidget, 1);
        if (treeOut != nullptr)
        {
            *treeOut = treeWidget;
        }
        return pageWidget;
    }
}

void StartupDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(4, 4, 4, 4);
    m_rootLayout->setSpacing(6);

    initializeToolbar();
    initializeTabs();

    m_tableRebuildTimer = new QTimer(this);
    m_tableRebuildTimer->setSingleShot(true);
    connect(
        m_tableRebuildTimer,
        &QTimer::timeout,
        this,
        &StartupDock::continueIncrementalTableRebuild);

    m_filterRefreshTimer = new QTimer(this);
    m_filterRefreshTimer->setSingleShot(true);
    m_filterRefreshTimer->setInterval(120);
    connect(m_filterRefreshTimer, &QTimer::timeout, this, &StartupDock::applyFilterAndRefresh);
    connect(m_sideTabWidget, &QTabWidget::currentChanged, this, [this](int) {
        ensureCurrentCategoryProjection();
    });

    m_rootLayout->addWidget(m_toolbarWidget, 0);
    m_rootLayout->addWidget(m_sideTabWidget, 1);
    // 工具条和分类Tab共同组成整页，外角放在页根并沿用原四边4px。
    ks::ui::StyleWorkspaceContentFrame(this, 4);
}

void StartupDock::initializeToolbar()
{
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    m_toolbarWidget = new QWidget(this);
    m_toolbarLayout = new QHBoxLayout(m_toolbarWidget);
    m_toolbarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolbarLayout->setSpacing(6);

    m_refreshButton = new QPushButton(m_toolbarWidget);
    m_refreshButton->setIcon(createBlueIcon(":/Icon/process_refresh.svg", kToolbarIconSize));
    languageManager.bindToolTip(
        m_refreshButton,
        QStringLiteral("startup.toolbar.refresh.tooltip"),
        QStringLiteral("刷新当前启动项视图"));
    m_refreshButton->setFixedSize(28, 28);

    m_exportButton = new QPushButton(m_toolbarWidget);
    m_exportButton->setIcon(createBlueIcon(":/Icon/log_export.svg", kToolbarIconSize));
    languageManager.bindToolTip(
        m_exportButton,
        QStringLiteral("startup.toolbar.export.tooltip"),
        QStringLiteral("导出当前视图为制表符文本"));
    m_exportButton->setFixedSize(28, 28);

    m_copyButton = new QPushButton(m_toolbarWidget);
    m_copyButton->setIcon(createBlueIcon(":/Icon/log_copy.svg", kToolbarIconSize));
    languageManager.bindToolTip(
        m_copyButton,
        QStringLiteral("startup.toolbar.copy.tooltip"),
        QStringLiteral("复制当前选中启动项"));
    m_copyButton->setFixedSize(28, 28);

    m_filterEdit = new QLineEdit(m_toolbarWidget);
    // 启动项树保留既有双语提示与分批结果过滤，只补搜索面板颜色。
    ks::ui::StyleSearchField(m_filterEdit);
    languageManager.bindPlaceholder(
        m_filterEdit,
        QStringLiteral("startup.toolbar.filter.placeholder"),
        QStringLiteral("过滤名称/发布者/路径/位置"));
    languageManager.bindToolTip(
        m_filterEdit,
        QStringLiteral("startup.toolbar.filter.tooltip"),
        QStringLiteral("按名称、发布者、路径、位置和类型做模糊筛选。"));

    m_hideMicrosoftCheck = new QCheckBox(
        startupText("startup.toolbar.hide_microsoft", QStringLiteral("隐藏微软项")),
        m_toolbarWidget);
    languageManager.bindText(
        m_hideMicrosoftCheck,
        QStringLiteral("startup.toolbar.hide_microsoft"),
        QStringLiteral("隐藏微软项"));
    languageManager.bindToolTip(
        m_hideMicrosoftCheck,
        QStringLiteral("startup.toolbar.hide_microsoft.tooltip"),
        QStringLiteral("隐藏发布者包含 Microsoft/Windows 的条目。"));

    m_hideEmptyPathCheck = new QCheckBox(
        startupText("startup.toolbar.hide_empty_path", QStringLiteral("隐藏空路径")),
        m_toolbarWidget);
    languageManager.bindText(
        m_hideEmptyPathCheck,
        QStringLiteral("startup.toolbar.hide_empty_path"),
        QStringLiteral("隐藏空路径"));
    languageManager.bindToolTip(
        m_hideEmptyPathCheck,
        QStringLiteral("startup.toolbar.hide_empty_path.tooltip"),
        QStringLiteral("在高级注册表树中隐藏当前没有任何条目的注册表位置。"));

    m_statusLabel = new QLabel(
        startupText("startup.status.initial", QStringLiteral("状态：首次打开该页时加载启动项")),
        m_toolbarWidget);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    m_toolbarLayout->addWidget(m_refreshButton);
    m_toolbarLayout->addWidget(m_exportButton);
    m_toolbarLayout->addWidget(m_copyButton);
    m_toolbarLayout->addWidget(m_filterEdit, 1);
    m_toolbarLayout->addWidget(m_hideMicrosoftCheck);
    m_toolbarLayout->addWidget(m_hideEmptyPathCheck);
    m_toolbarLayout->addWidget(m_statusLabel, 1);
    // 所有按钮与搜索、筛选控件共用等高和 8px 间距。
    m_toolbarLayout->setSpacing(8);
    ks::ui::NormalizeToolbarRow(m_toolbarLayout);
    // 只给已有操作带增加分界，保持分类表格的可用空间和风险行语义。
    ks::ui::StylePrimaryToolbar(m_toolbarWidget);
    m_toolbarLayout->setContentsMargins(6, 3, 6, 3);
    for (QPushButton* button : {m_refreshButton, m_exportButton, m_copyButton})
    {
        ks::ui::ApplyFlatButtonTheme(button, ks::ui::FlatButtonTone::Neutral,
            ks::ui::FlatButtonAppearance::Solid);
    }
}

void StartupDock::initializeTabs()
{
    m_sideTabWidget = new QTabWidget(this);
    m_sideTabWidget->setTabPosition(QTabWidget::West);
    ks::ui::StylePageTabsContentFrame(m_sideTabWidget);

    m_allPage = createSingleTablePage(&m_allTable, m_sideTabWidget);
    m_logonPage = createSingleTablePage(&m_logonTable, m_sideTabWidget);
    m_servicesPage = createSingleTablePage(&m_servicesTable, m_sideTabWidget);
    m_driversPage = createSingleTablePage(&m_driversTable, m_sideTabWidget);
    m_tasksPage = createSingleTablePage(&m_tasksTable, m_sideTabWidget);
    m_imageHijackPage = createSingleTablePage(&m_imageHijackTable, m_sideTabWidget);
    m_registryPage = createRegistryTreePage(&m_registryTree, m_sideTabWidget);
    m_wmiPage = createSingleTablePage(&m_wmiTable, m_sideTabWidget);
    m_hiddenPage = createSingleTablePage(&m_hiddenTable, m_sideTabWidget);

    m_navigationTabs.add(kStartupDockNavigation[0], m_sideTabWidget, m_allPage, QIcon(":/Icon/process_list.svg"));
    m_navigationTabs.add(kStartupDockNavigation[1], m_sideTabWidget, m_logonPage, QIcon(":/Icon/process_main.svg"));
    m_navigationTabs.add(kStartupDockNavigation[2], m_sideTabWidget, m_servicesPage, QIcon(":/Icon/process_start.svg"));
    m_navigationTabs.add(kStartupDockNavigation[3], m_sideTabWidget, m_driversPage, QIcon(":/Icon/process_details.svg"));
    m_navigationTabs.add(kStartupDockNavigation[4], m_sideTabWidget, m_tasksPage, QIcon(":/Icon/process_refresh.svg"));
    m_navigationTabs.add(kStartupDockNavigation[5], m_sideTabWidget, m_imageHijackPage, QIcon(":/Icon/startup_image_hijack.svg"));
    m_navigationTabs.add(kStartupDockNavigation[6], m_sideTabWidget, m_registryPage, QIcon(":/Icon/file_find.svg"));
    m_navigationTabs.add(kStartupDockNavigation[7], m_sideTabWidget, m_wmiPage, QIcon(":/Icon/process_tree.svg"));
    m_navigationTabs.add(kStartupDockNavigation[8], m_sideTabWidget, m_hiddenPage, QIcon(":/Icon/startup_hidden.svg"));
}

void StartupDock::applyTranslatedHeaders()
{
    const QStringList headerList = startup_dock_detail::startupTableHeaders();
    const QList<QTableWidget*> tableList{
        m_allTable,
        m_logonTable,
        m_servicesTable,
        m_driversTable,
        m_tasksTable,
        m_imageHijackTable,
        m_wmiTable,
        m_hiddenTable
    };
    for (QTableWidget* tableWidget : tableList)
    {
        if (tableWidget != nullptr)
        {
            tableWidget->setHorizontalHeaderLabels(headerList);
        }
    }
    if (m_registryTree != nullptr)
    {
        m_registryTree->setHeaderLabels(headerList);
    }
}

void StartupDock::rebuildAllTables(const bool processesRefreshStage, const bool invalidateProjection, const int appendFrom)
{
    if (m_tableRebuildTimer == nullptr || m_destroying.load())
    {
        return;
    }

    const auto categoryIndex = static_cast<std::size_t>(currentCategory());
    QTableWidget* const visibleTable = currentCategoryTable();
    const bool appendCurrentTable = processesRefreshStage && appendFrom >= 0
        && !m_projectionInvalidationPending && !m_filterRefreshPending && !m_tableRebuildInProgress
        && currentCategory() != StartupCategory::Registry && visibleTable
        && m_renderedProjectionRevision[categoryIndex] == m_projectionRevision
        && m_renderedCanonicalCounts[categoryIndex] == static_cast<std::size_t>(appendFrom)
        && visibleTable->rowCount() == m_renderedRowCounts[categoryIndex];
    const bool appendRegistry = processesRefreshStage && appendFrom >= 0
        && !m_projectionInvalidationPending && !m_filterRefreshPending && !m_tableRebuildInProgress
        && currentCategory() == StartupCategory::Registry && m_registryTree
        && m_renderedProjectionRevision[categoryIndex] == m_projectionRevision
        && m_renderedCanonicalCounts[categoryIndex] == static_cast<std::size_t>(appendFrom)
        && m_registryTree->topLevelItemCount() == m_renderedRegistryGroupCount
        && m_registryProjectionGroups.size() == m_renderedRegistryGroupCount;
    m_projectionInvalidationPending = m_projectionInvalidationPending || invalidateProjection;
    m_tableRebuildProcessesRefreshStage = m_tableRebuildProcessesRefreshStage || processesRefreshStage;
    const QList<QAbstractItemView*> startupViews = {
        m_allTable, m_logonTable, m_servicesTable, m_driversTable, m_tasksTable,
        m_imageHijackTable, m_wmiTable, m_hiddenTable, m_registryTree
    };
    const QPointer<StartupDock> guarded(this);
    if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(this,
        QStringLiteral("startup-current-projection-rebuild"), startupViews,
        [guarded, processesRefreshStage, invalidateProjection, appendFrom]() {
            if (guarded) guarded->rebuildAllTables(processesRefreshStage, invalidateProjection, appendFrom);
        })) return;

    m_filterRefreshTimer->stop();
    if (m_projectionInvalidationPending)
    {
        m_projectionInvalidationPending = false;
        ++m_projectionRevision;
        m_filterRefreshPending = false;
    }
    m_projectionBuildActive = false;
    m_projectionBuildCategory = currentCategory();
    m_projectionBuildRevision = m_projectionRevision;
    // Retain hidden projections as disabled, stale views of the canonical snapshot.
    // They are rebuilt only when selected; no hidden row/tree allocation here.
    for (QAbstractItemView* view : startupViews) if (view) view->setEnabled(false);

    m_tableRebuildTimer->stop();
    m_tableRebuildProcessesRefreshStage =
        m_tableRebuildProcessesRefreshStage || processesRefreshStage;
    m_tableRebuildInProgress = true;
    retireProjectionIndices();
    m_tableRebuildTargetIndex = 0;
    m_registryRebuildTargetIndex = 0;
    m_tableRebuildCompletedUnits = 0;
    m_tableRebuildTotalUnits = 0;
    m_lastTableRebuildProgressPercent = -1;
    m_rebuildRegistryFirst = currentCategory() == StartupCategory::Registry;
    m_appendRegistryProjection = appendRegistry;
    if (m_rebuildRegistryFirst && !appendRegistry)
    {
        auto oldGroups = std::move(m_registryProjectionGroups);
        auto oldOrder = std::move(m_registryProjectionGroupOrder);
        m_registryProjectionNextOrder = 0;
        QThreadPool::globalInstance()->start([groups = std::move(oldGroups), order = std::move(oldOrder)]() {});
    }

    if (m_exportButton != nullptr)
    {
        m_exportButton->setEnabled(false);
    }
    if (m_copyButton != nullptr)
    {
        m_copyButton->setEnabled(false);
    }

    if (!isVisible() || m_renderedProjectionRevision[static_cast<std::size_t>(currentCategory())] == m_projectionRevision)
    {
        finishIncrementalTableRebuild();
        return;
    }
    m_projectionBuildActive = true;

    const std::array<std::pair<StartupCategory, QTableWidget*>, 8> allTableTargets{
        std::pair{ StartupCategory::All, m_allTable },
        std::pair{ StartupCategory::Logon, m_logonTable },
        std::pair{ StartupCategory::Services, m_servicesTable },
        std::pair{ StartupCategory::Drivers, m_driversTable },
        std::pair{ StartupCategory::Tasks, m_tasksTable },
        std::pair{ StartupCategory::ImageHijack, m_imageHijackTable },
        std::pair{ StartupCategory::Wmi, m_wmiTable },
        std::pair{ StartupCategory::Hidden, m_hiddenTable }
    };
    const StartupCategory visibleCategory = currentCategory();
    for (const auto& [category, tableWidget] : allTableTargets)
    {
        if (category == visibleCategory && tableWidget)
        {
            TableRebuildTarget target;
            target.category = category;
            target.tableWidget = tableWidget;
            target.baseRow = appendCurrentTable ? tableWidget->rowCount() : 0;
            m_tableRebuildTargets.push_back(std::move(target));
            break;
        }
    }
    m_projectionPreparation = std::make_shared<ProjectionPreparation>();
    m_projectionPreparation->hideEmptyPaths = m_hideEmptyPathCheck && m_hideEmptyPathCheck->isChecked();
    if (appendCurrentTable || appendRegistry)
    {
        // Previous rows/identities stay in place; scan/format only this stage's tail.
        m_projectionPreparation->phase = ProjectionPreparation::Phase::Scan;
        m_projectionPreparation->nextEntry = static_cast<std::size_t>(appendFrom);
    }

    if (m_statusLabel != nullptr)
    {
        if (m_tableRebuildProcessesRefreshStage)
        {
            m_statusLabel->setText(refreshStatusText(
                startupText(
                    "startup.status.applying_stage_results",
                    QStringLiteral("状态：正在添加第 %1/%2 阶段结果，本阶段 %3 条..."))
                    .arg(m_activeRefreshStageIndex + 1U)
                    .arg(m_activeRefreshStageCount)
                    .arg(m_activeRefreshStageEntryCount)));
        }
        else if (m_refreshInProgress.load())
        {
            m_statusLabel->setText(refreshStatusText(
                startupText(
                    "startup.status.refreshing",
                    QStringLiteral("状态：后台正在枚举启动项..."))));
        }
        else
        {
            m_statusLabel->setText(refreshStatusText(
                startupText(
                    "startup.status.rebuilding_view",
                    QStringLiteral("状态：正在分批更新当前启动项视图..."))));
        }
    }

    m_tableRebuildTimer->start(0);
}

void StartupDock::retireProjectionIndices()
{
    if (m_tableRebuildTargets.empty() && m_registryRebuildTargets.empty() && !m_projectionPreparation) return;
    // Only value index buffers move to the pool. Nonowning view/item pointers are never accessed there.
    auto preparation = std::move(m_projectionPreparation);
    auto tables = std::make_shared<std::vector<TableRebuildTarget>>(std::move(m_tableRebuildTargets));
    auto registry = std::make_shared<std::deque<RegistryGroupRebuildTarget>>(std::move(m_registryRebuildTargets));
    QThreadPool::globalInstance()->start([preparation = std::move(preparation), tables, registry]() {});
}

bool StartupDock::continueProjectionPreparation()
{
    if (!m_projectionPreparation) return false;
    ProjectionPreparation& preparation = *m_projectionPreparation;
    while (true)
    {
        switch (preparation.phase)
        {
        case ProjectionPreparation::Phase::Clear:
            if (m_projectionBuildCategory == StartupCategory::Registry)
            {
                if (m_registryTree && m_registryTree->topLevelItemCount() > 0)
                {
                    const int last = m_registryTree->topLevelItemCount() - 1;
                    QTreeWidgetItem* group = m_registryTree->topLevelItem(last);
                    if (group->childCount() > 0) delete group->takeChild(group->childCount() - 1);
                    else delete m_registryTree->takeTopLevelItem(last);
                    return true;
                }
                // This project resource catalog is fixed; variable entry/group work stays sliced below.
                preparation.catalog = buildKnownStartupRegistryLocationList();
                preparation.phase = ProjectionPreparation::Phase::Catalog;
            }
            else
            {
                if (!m_tableRebuildTargets.empty())
                {
                    QTableWidget* table = m_tableRebuildTargets.front().tableWidget;
                    if (table && table->rowCount() > 0)
                    {
                        table->setRowCount(table->rowCount() - 1);
                        return true;
                    }
                }
                preparation.phase = ProjectionPreparation::Phase::Scan;
            }
            break;
        case ProjectionPreparation::Phase::Catalog:
            if (preparation.nextCatalog < preparation.catalog.size())
            {
                const QString location = preparation.catalog[preparation.nextCatalog++];
                if (!preparation.knownLocations.contains(location))
                {
                    preparation.knownLocations.insert(location);
                    preparation.locations.push_back(location);
                    m_registryProjectionGroupOrder.insert(location, m_registryProjectionNextOrder++);
                }
                return true;
            }
            preparation.phase = ProjectionPreparation::Phase::Scan;
            break;
        case ProjectionPreparation::Phase::Scan:
            if (preparation.nextEntry < static_cast<std::size_t>(m_entryList.size()))
            {
                const int entryIndex = static_cast<int>(preparation.nextEntry++);
                const StartupEntry& entry = m_entryList.at(static_cast<std::size_t>(entryIndex));
                if (m_projectionBuildCategory == StartupCategory::Registry)
                {
                    if (isRegistryBackedStartupEntry(entry))
                    {
                        const QString location = entry.locationGroupText.trimmed().isEmpty()
                            ? entry.locationText : entry.locationGroupText;
                        preparation.total[location].push_back(entryIndex);
                        if (!m_registryProjectionGroupOrder.contains(location))
                            m_registryProjectionGroupOrder.insert(location, m_registryProjectionNextOrder++);
                        if (!preparation.knownLocations.contains(location))
                        {
                            preparation.knownLocations.insert(location);
                            preparation.locations.push_back(location);
                        }
                        if (entryMatchesCurrentFilter(entry)) preparation.visible[location].push_back(entryIndex);
                    }
                }
                else if (!m_tableRebuildTargets.empty()
                    && (m_projectionBuildCategory == StartupCategory::All || entry.category == m_projectionBuildCategory)
                    && entryMatchesCurrentFilter(entry))
                {
                    m_tableRebuildTargets.front().visibleEntryIndexList.push_back(entryIndex);
                    ++m_tableRebuildTotalUnits;
                }
                return true;
            }
            preparation.phase = m_projectionBuildCategory == StartupCategory::Registry
                ? ProjectionPreparation::Phase::Groups : ProjectionPreparation::Phase::Ready;
            break;
        case ProjectionPreparation::Phase::Groups:
            if (preparation.nextGroup < preparation.locations.size())
            {
                RegistryGroupRebuildTarget target;
                target.locationText = preparation.locations[preparation.nextGroup++];
                auto total = preparation.total.find(target.locationText);
                if (total != preparation.total.end())
                {
                    target.totalEntryIndexList = std::move(total.value());
                    preparation.total.erase(total);
                }
                auto visible = preparation.visible.find(target.locationText);
                if (visible != preparation.visible.end())
                {
                    target.visibleEntryIndexList = std::move(visible.value());
                    preparation.visible.erase(visible);
                }
                if (!preparation.hideEmptyPaths || !target.totalEntryIndexList.empty())
                {
                    m_tableRebuildTotalUnits += 1U + target.visibleEntryIndexList.size();
                    m_registryRebuildTargets.push_back(std::move(target));
                }
                return true;
            }
            preparation.phase = ProjectionPreparation::Phase::Ready;
            break;
        case ProjectionPreparation::Phase::Ready:
            return false;
        }
    }
}

void StartupDock::continueIncrementalTableRebuild()
{
    if (!m_tableRebuildInProgress || m_destroying.load())
    {
        return;
    }

    QElapsedTimer sliceTimer;
    sliceTimer.start();
    constexpr qint64 sliceBudgetMilliseconds = 7;
    constexpr std::size_t maximumUnitsPerSlice = 24U;
    std::size_t sliceUnitCount = 0;

    const auto processOneTableUnit = [this]() -> bool
    {
        while (m_tableRebuildTargetIndex < m_tableRebuildTargets.size())
        {
            TableRebuildTarget& target = m_tableRebuildTargets[m_tableRebuildTargetIndex];
            if (target.nextRowIndex >= target.visibleEntryIndexList.size())
            {
                if (target.tableWidget != nullptr)
                {
                    target.tableWidget->setEnabled(true);
                }
                ++m_tableRebuildTargetIndex;
                continue;
            }

            const int entryIndex = target.visibleEntryIndexList[target.nextRowIndex];
            if (target.tableWidget != nullptr
                && entryIndex >= 0
                && entryIndex < static_cast<int>(m_entryList.size()))
            {
                target.tableWidget->setRowCount(target.baseRow + static_cast<int>(target.nextRowIndex) + 1);
                appendEntryRow(
                    target.tableWidget,
                    target.baseRow + static_cast<int>(target.nextRowIndex),
                    m_entryList.at(static_cast<std::size_t>(entryIndex)),
                    entryIndex);
            }
            ++target.nextRowIndex;
            ++m_tableRebuildCompletedUnits;
            if (target.nextRowIndex >= target.visibleEntryIndexList.size())
            {
                if (target.tableWidget != nullptr)
                {
                    target.tableWidget->setEnabled(true);
                }
                ++m_tableRebuildTargetIndex;
            }
            return true;
        }
        return false;
    };

    const auto processOneRegistryUnit = [this]() -> bool
    {
        while (m_registryRebuildTargetIndex < m_registryRebuildTargets.size())
        {
            RegistryGroupRebuildTarget& target = m_registryRebuildTargets[m_registryRebuildTargetIndex];
            if (!target.initialized)
            {
                initializeRegistryTreeGroup(&target);
                ++m_tableRebuildCompletedUnits;
                if (target.visibleEntryIndexList.empty())
                {
                    ++m_registryRebuildTargetIndex;
                }
                return true;
            }
            if (target.nextEntryIndex >= target.visibleEntryIndexList.size())
            {
                ++m_registryRebuildTargetIndex;
                continue;
            }

            const int entryIndex = target.visibleEntryIndexList[target.nextEntryIndex];
            if (target.groupItem != nullptr
                && entryIndex >= 0
                && entryIndex < static_cast<int>(m_entryList.size()))
            {
                appendRegistryTreeLeaf(
                    target.groupItem,
                    m_entryList.at(static_cast<std::size_t>(entryIndex)),
                    entryIndex);
            }
            ++target.nextEntryIndex;
            ++m_tableRebuildCompletedUnits;
            if (target.nextEntryIndex >= target.visibleEntryIndexList.size())
            {
                ++m_registryRebuildTargetIndex;
            }
            return true;
        }
        if (m_registryTree != nullptr)
        {
            m_registryTree->setEnabled(true);
        }
        return false;
    };

    while (sliceUnitCount < maximumUnitsPerSlice
        && (sliceUnitCount == 0U || sliceTimer.elapsed() < sliceBudgetMilliseconds))
    {
        bool processedUnit = continueProjectionPreparation();
        if (!processedUnit && m_rebuildRegistryFirst)
        {
            processedUnit = processOneRegistryUnit();
            if (!processedUnit)
            {
                m_rebuildRegistryFirst = false;
            }
        }
        if (!processedUnit)
        {
            processedUnit = processOneTableUnit();
        }
        if (!processedUnit)
        {
            processedUnit = processOneRegistryUnit();
        }
        if (!processedUnit)
        {
            break;
        }
        ++sliceUnitCount;
    }

    const bool preparationCompleted = !m_projectionPreparation
        || m_projectionPreparation->phase == ProjectionPreparation::Phase::Ready;
    if (preparationCompleted && m_tableRebuildProcessesRefreshStage
        && m_backendEnumerationCompleted
        && m_progressPid != 0
        && m_activeRefreshStageCount != 0U)
    {
        const double stageCompletedRatio = static_cast<double>(m_tableRebuildCompletedUnits)
            / static_cast<double>(std::max<std::size_t>(1U, m_tableRebuildTotalUnits));
        const double allStagesCompletedRatio =
            (static_cast<double>(m_activeRefreshStageIndex) + stageCompletedRatio)
            / static_cast<double>(m_activeRefreshStageCount);
        const int progressPercent = std::clamp(
            94 + static_cast<int>(allStagesCompletedRatio * 5.0),
            94,
            99);
        if (progressPercent != m_lastTableRebuildProgressPercent)
        {
            m_lastTableRebuildProgressPercent = progressPercent;
            kPro.set(
                m_progressPid,
                startupText(
                    "startup.progress.apply_stage_results",
                    QStringLiteral("正在添加第 %1/%2 阶段结果（%3/%4）"))
                    .arg(m_activeRefreshStageIndex + 1U)
                    .arg(m_activeRefreshStageCount)
                    .arg(m_tableRebuildCompletedUnits)
                    .arg(m_tableRebuildTotalUnits)
                    .toStdString(),
                0,
                static_cast<float>(progressPercent));
        }
    }

    const bool tablesCompleted = m_tableRebuildTargetIndex >= m_tableRebuildTargets.size();
    const bool registryCompleted = m_registryRebuildTargetIndex >= m_registryRebuildTargets.size();
    if (preparationCompleted && tablesCompleted && registryCompleted)
    {
        finishIncrementalTableRebuild();
        return;
    }
    m_tableRebuildTimer->start(0);
}

void StartupDock::finishIncrementalTableRebuild()
{
    const bool processesRefreshStage = m_tableRebuildProcessesRefreshStage;
    m_tableRebuildInProgress = false;
    if (m_projectionBuildActive && m_projectionBuildRevision == m_projectionRevision)
    {
        const auto index = static_cast<std::size_t>(m_projectionBuildCategory);
        m_renderedProjectionRevision[index] = m_projectionRevision;
        m_renderedCanonicalCounts[index] = m_entryList.size();
        if (m_projectionBuildCategory == StartupCategory::Registry)
            m_renderedRegistryGroupCount = m_registryTree ? m_registryTree->topLevelItemCount() : 0;
        else
        {
            for (const auto& target : m_tableRebuildTargets)
                if (target.category == m_projectionBuildCategory && target.tableWidget)
                    m_renderedRowCounts[index] = target.tableWidget->rowCount();
        }
    }
    m_projectionBuildActive = false;
    m_tableRebuildProcessesRefreshStage = false;
    m_rebuildRegistryFirst = false;
    retireProjectionIndices();

    const std::array<std::pair<StartupCategory, QTableWidget*>, 8> tableList{
        std::pair{StartupCategory::All, m_allTable}, std::pair{StartupCategory::Logon, m_logonTable},
        std::pair{StartupCategory::Services, m_servicesTable}, std::pair{StartupCategory::Drivers, m_driversTable},
        std::pair{StartupCategory::Tasks, m_tasksTable}, std::pair{StartupCategory::ImageHijack, m_imageHijackTable},
        std::pair{StartupCategory::Wmi, m_wmiTable}, std::pair{StartupCategory::Hidden, m_hiddenTable}
    };
    for (const auto& [category, tableWidget] : tableList)
        if (tableWidget) tableWidget->setEnabled(isCategoryProjectionReady(category));
    if (m_registryTree) m_registryTree->setEnabled(isCategoryProjectionReady(StartupCategory::Registry));
    const bool ready = isCategoryProjectionReady(currentCategory());
    if (m_exportButton) m_exportButton->setEnabled(ready && !m_exportOperation->isInFlight());
    if (m_copyButton) m_copyButton->setEnabled(ready);

    if (processesRefreshStage)
    {
        m_appliedRefreshStageCount = std::max(
            m_appliedRefreshStageCount,
            m_activeRefreshStageIndex + 1U);
        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(refreshStatusText(
                startupText(
                    "startup.status.stage_results_applied",
                    QStringLiteral("状态：已添加 %1/%2 阶段，共 %3 条"))
                    .arg(m_appliedRefreshStageCount)
                    .arg(m_activeRefreshStageCount)
                    .arg(m_entryList.size())));
        }
        QTimer::singleShot(0, this, [this]()
            {
                processNextRefreshStageResult();
            });
        return;
    }
    if (m_refreshInProgress.load())
    {
        QTimer::singleShot(0, this, [this]()
            {
                processNextRefreshStageResult();
            });
        return;
    }
    if (!m_refreshInProgress.load() && m_statusLabel != nullptr)
    {
        m_statusLabel->setText(refreshSummaryText());
    }
}

void StartupDock::appendEntryRow(
    QTableWidget* tableWidget,
    const int rowIndex,
    const StartupEntry& entry,
    const int entryIndex)
{
    if (tableWidget == nullptr || rowIndex < 0)
    {
        return;
    }

    QTableWidgetItem* nameItem = createReadOnlyItem(entry.itemNameText);
    nameItem->setData(Qt::UserRole, entryIndex);
    nameItem->setIcon(resolveEntryIcon(entry));
    tableWidget->setItem(rowIndex, toStartupColumn(StartupColumn::Name), nameItem);
    trackEntryIcon(entry, tableWidget->model()->index(rowIndex, toStartupColumn(StartupColumn::Name)));
    tableWidget->setItem(rowIndex, toStartupColumn(StartupColumn::Publisher), createReadOnlyItem(entry.publisherText));
    tableWidget->setItem(rowIndex, toStartupColumn(StartupColumn::ImagePath), createReadOnlyItem(entry.imagePathText));
    tableWidget->setItem(rowIndex, toStartupColumn(StartupColumn::Command), createReadOnlyItem(entry.commandText));
    tableWidget->setItem(rowIndex, toStartupColumn(StartupColumn::Location), createReadOnlyItem(entry.locationText));
    tableWidget->setItem(
        rowIndex,
        toStartupColumn(StartupColumn::User),
        createReadOnlyItem(ks::i18n::sourceText(entry.userText)));
    tableWidget->setItem(
        rowIndex,
        toStartupColumn(StartupColumn::Enabled),
        createReadOnlyItem(buildStatusText(entry.backendEntry)));
    tableWidget->setItem(
        rowIndex,
        toStartupColumn(StartupColumn::Type),
        createReadOnlyItem(ks::i18n::sourceText(entry.sourceTypeText)));
    tableWidget->setItem(
        rowIndex,
        toStartupColumn(StartupColumn::Detail),
        createReadOnlyItem(startupLocalizedDetailText(entry.detailText)));

    // shouldHighlightUntrusted 用途：记录当前条目是否命中不受信任高亮条件。
    const bool shouldHighlightUntrusted = isUntrustedStartupEntry(entry);
    if (shouldHighlightUntrusted)
    {
        for (int columnIndex = 0; columnIndex < toStartupColumn(StartupColumn::Count); ++columnIndex)
        {
            // currentItem 用途：定位当前行每一列单元格并统一套用半透明红底。
            QTableWidgetItem* currentItem = tableWidget->item(rowIndex, columnIndex);
            if (currentItem != nullptr)
            {
                currentItem->setBackground(kUntrustedRowHighlightColor);
            }
        }
    }
}

void StartupDock::appendRegistryTreeLeaf(
    QTreeWidgetItem* parentItem,
    const StartupEntry& entry,
    const int entryIndex)
{
    if (parentItem == nullptr)
    {
        return;
    }

    QTreeWidgetItem* entryItem = new QTreeWidgetItem(parentItem);
    entryItem->setData(0, kStartupEntryIndexRole, entryIndex);
    entryItem->setData(0, kStartupTreeNodeKindRole, static_cast<int>(StartupTreeNodeKind::Entry));
    entryItem->setData(0, kStartupTreeLocationRole, entry.locationText);
    entryItem->setText(toStartupColumn(StartupColumn::Name), entry.itemNameText);
    entryItem->setText(toStartupColumn(StartupColumn::Publisher), entry.publisherText);
    entryItem->setText(toStartupColumn(StartupColumn::ImagePath), entry.imagePathText);
    entryItem->setText(toStartupColumn(StartupColumn::Command), entry.commandText);
    entryItem->setText(toStartupColumn(StartupColumn::Location), entry.locationText);
    entryItem->setText(toStartupColumn(StartupColumn::User), ks::i18n::sourceText(entry.userText));
    entryItem->setText(
        toStartupColumn(StartupColumn::Enabled),
        buildStatusText(entry.backendEntry));
    entryItem->setText(toStartupColumn(StartupColumn::Type), ks::i18n::sourceText(entry.sourceTypeText));
    entryItem->setText(toStartupColumn(StartupColumn::Detail), startupLocalizedDetailText(entry.detailText));
    entryItem->setIcon(toStartupColumn(StartupColumn::Name), resolveEntryIcon(entry));
    trackEntryIcon(entry, m_registryTree->indexFromItem(entryItem, toStartupColumn(StartupColumn::Name)));

    // shouldHighlightUntrusted 用途：树节点模式下沿用表格相同的不受信任着色规则。
    const bool shouldHighlightUntrusted = isUntrustedStartupEntry(entry);
    if (shouldHighlightUntrusted)
    {
        for (int columnIndex = 0; columnIndex < toStartupColumn(StartupColumn::Count); ++columnIndex)
        {
            entryItem->setBackground(columnIndex, kUntrustedRowHighlightColor);
        }
    }

    for (int columnIndex = 0; columnIndex < toStartupColumn(StartupColumn::Count); ++columnIndex)
    {
        entryItem->setToolTip(columnIndex, entryItem->text(columnIndex));
    }
}

bool StartupDock::isRegistryBackedStartupEntry(const StartupEntry& entry) const
{
    return entry.canOpenRegistryLocation
        && !entry.locationText.trimmed().isEmpty()
        && (entry.category == StartupCategory::Logon || entry.category == StartupCategory::Registry);
}

int StartupDock::findEntryIndexByRegistryTreeItem(const QTreeWidgetItem* treeItem) const
{
    if (treeItem == nullptr || !isCategoryProjectionReady(StartupCategory::Registry))
    {
        return -1;
    }

    const StartupTreeNodeKind nodeKind = static_cast<StartupTreeNodeKind>(
        treeItem->data(0, kStartupTreeNodeKindRole).toInt());
    if (nodeKind != StartupTreeNodeKind::Entry)
    {
        return -1;
    }
    return treeItem->data(0, kStartupEntryIndexRole).toInt();
}

void StartupDock::initializeRegistryTreeGroup(RegistryGroupRebuildTarget* const target)
{
    if (target == nullptr || target->initialized || m_registryTree == nullptr)
    {
        return;
    }
    target->initialized = true;

    const auto previous = m_registryProjectionGroups.value(target->locationText);
    const bool reused = m_appendRegistryProjection && previous.item;
    QTreeWidgetItem* groupItem = reused ? previous.item : new QTreeWidgetItem();
    if (!reused)
    {
        // Preserve fixed catalog/first-discovered order, including a newly nonempty known path.
        const qsizetype order = m_registryProjectionGroupOrder.value(target->locationText);
        int first = 0, last = m_registryTree->topLevelItemCount();
        while (first < last)
        {
            const int middle = first + (last - first) / 2;
            const QString existing = m_registryTree->topLevelItem(middle)->data(0, kStartupTreeLocationRole).toString();
            if (m_registryProjectionGroupOrder.value(existing) < order) first = middle + 1;
            else last = middle;
        }
        m_registryTree->insertTopLevelItem(first, groupItem);
    }
    else if (previous.visible == 0)
        qDeleteAll(groupItem->takeChildren()); // At most the existing single no-match placeholder.
    const std::size_t totalCount = (reused ? previous.total : 0U) + target->totalEntryIndexList.size();
    const std::size_t visibleCount = (reused ? previous.visible : 0U) + target->visibleEntryIndexList.size();
    m_registryProjectionGroups.insert(target->locationText, {groupItem, totalCount, visibleCount});
    target->groupItem = groupItem;
    groupItem->setData(0, kStartupEntryIndexRole, -1);
    groupItem->setData(0, kStartupTreeNodeKindRole, static_cast<int>(StartupTreeNodeKind::Group));
    groupItem->setData(0, kStartupTreeLocationRole, target->locationText);
    groupItem->setFirstColumnSpanned(true);
    groupItem->setIcon(toStartupColumn(StartupColumn::Name), createBlueIcon(":/Icon/file_find.svg"));

    if (visibleCount != 0U)
    {
        groupItem->setText(
            toStartupColumn(StartupColumn::Name),
            startupText("startup.registry.group.match_summary", QStringLiteral("%1    匹配 %2 项 / 总计 %3 项"))
                .arg(target->locationText)
                .arg(visibleCount)
                .arg(totalCount));
    }
    else
    {
        groupItem->setText(
            toStartupColumn(StartupColumn::Name),
            totalCount == 0U
                ? startupText("startup.registry.group.no_entries", QStringLiteral("%1    无条目"))
                    .arg(target->locationText)
                : startupText(
                    "startup.registry.group.no_filter_matches",
                    QStringLiteral("%1    当前过滤下无匹配项（总计 %2 项）"))
                    .arg(target->locationText)
                    .arg(totalCount));

        QTreeWidgetItem* placeholderItem = new QTreeWidgetItem(groupItem);
        placeholderItem->setData(0, kStartupEntryIndexRole, -1);
        placeholderItem->setData(0, kStartupTreeNodeKindRole, static_cast<int>(StartupTreeNodeKind::Placeholder));
        placeholderItem->setData(0, kStartupTreeLocationRole, target->locationText);
        placeholderItem->setText(
            toStartupColumn(StartupColumn::Name),
            totalCount == 0U
                ? startupText("startup.registry.placeholder.no_entries", QStringLiteral("(无条目)"))
                : startupText("startup.registry.placeholder.no_matches", QStringLiteral("(无匹配项)")));
        placeholderItem->setText(
            toStartupColumn(StartupColumn::Detail),
            totalCount == 0U
                ? startupText(
                    "startup.registry.placeholder.not_found",
                    QStringLiteral("该位置当前未发现启动项"))
                : startupText(
                    "startup.registry.placeholder.filtered",
                    QStringLiteral("存在条目，但被当前过滤条件隐藏")));
    }

    if (!reused) groupItem->setExpanded(true);
}

ks::ui::PageNavigationCatalog StartupDock::navigationCatalog(const StartupDock* existing)
{
    ks::ui::PageNavigationCatalog schema;
    for (const auto& definition : kStartupDockNavigation)
        schema.append(ks::ui::PageNavigationTabDescriptor(definition));
    return existing ? existing->m_navigationTabs.describe(std::move(schema)) : schema;
}
QWidget* StartupDock::activateNavigationDescriptor(const QString& id)
{
    return m_navigationTabs.activate(id, navigationCatalog(this));
}
namespace { const bool kStartupDockNavigationRegistered =
    ks::ui::RegisterTypedPageNavigationCatalog<StartupDock>(QStringLiteral("startup")); }
