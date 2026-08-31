#include "StartupDock.Internal.h"

#include <QElapsedTimer>
#include "../UI/VisibleTableWidget.h"
#include "../Internationalization/LanguageManager.h"

#include <QColor>
#include <QPair>

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

    m_rootLayout->addWidget(m_toolbarWidget, 0);
    m_rootLayout->addWidget(m_sideTabWidget, 1);
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
}

void StartupDock::initializeTabs()
{
    m_sideTabWidget = new QTabWidget(this);
    m_sideTabWidget->setTabPosition(QTabWidget::West);

    m_allPage = createSingleTablePage(&m_allTable, m_sideTabWidget);
    m_logonPage = createSingleTablePage(&m_logonTable, m_sideTabWidget);
    m_servicesPage = createSingleTablePage(&m_servicesTable, m_sideTabWidget);
    m_driversPage = createSingleTablePage(&m_driversTable, m_sideTabWidget);
    m_tasksPage = createSingleTablePage(&m_tasksTable, m_sideTabWidget);
    m_imageHijackPage = createSingleTablePage(&m_imageHijackTable, m_sideTabWidget);
    m_registryPage = createRegistryTreePage(&m_registryTree, m_sideTabWidget);
    m_wmiPage = createSingleTablePage(&m_wmiTable, m_sideTabWidget);
    m_hiddenPage = createSingleTablePage(&m_hiddenTable, m_sideTabWidget);

    m_sideTabWidget->addTab(
        m_allPage,
        QIcon(":/Icon/process_list.svg"),
        startupText("startup.tab.overview", QStringLiteral("总览")));
    m_sideTabWidget->addTab(
        m_logonPage,
        QIcon(":/Icon/process_main.svg"),
        startupText("startup.tab.logon", QStringLiteral("登录")));
    m_sideTabWidget->addTab(
        m_servicesPage,
        QIcon(":/Icon/process_start.svg"),
        startupText("startup.tab.services", QStringLiteral("服务")));
    m_sideTabWidget->addTab(
        m_driversPage,
        QIcon(":/Icon/process_details.svg"),
        startupText("startup.tab.drivers", QStringLiteral("驱动")));
    m_sideTabWidget->addTab(
        m_tasksPage,
        QIcon(":/Icon/process_refresh.svg"),
        startupText("startup.tab.tasks", QStringLiteral("计划任务")));
    m_sideTabWidget->addTab(
        m_imageHijackPage,
        QIcon(":/Icon/startup_image_hijack.svg"),
        startupText("startup.tab.image_hijack", QStringLiteral("映像劫持")));
    m_sideTabWidget->addTab(
        m_registryPage,
        QIcon(":/Icon/file_find.svg"),
        startupText("startup.tab.registry", QStringLiteral("高级注册表")));
    m_sideTabWidget->addTab(
        m_wmiPage,
        QIcon(":/Icon/process_tree.svg"),
        startupText("startup.tab.wmi", QStringLiteral("WMI")));
    m_sideTabWidget->addTab(
        m_hiddenPage,
        QIcon(":/Icon/startup_hidden.svg"),
        startupText("startup.tab.hidden", QStringLiteral("隐藏项")));
    const QList<QPair<QWidget*, QPair<QString, QString>>> tabTranslations{
        {m_allPage, {QStringLiteral("startup.tab.overview"), QStringLiteral("总览")}},
        {m_logonPage, {QStringLiteral("startup.tab.logon"), QStringLiteral("登录")}},
        {m_servicesPage, {QStringLiteral("startup.tab.services"), QStringLiteral("服务")}},
        {m_driversPage, {QStringLiteral("startup.tab.drivers"), QStringLiteral("驱动")}},
        {m_tasksPage, {QStringLiteral("startup.tab.tasks"), QStringLiteral("计划任务")}},
        {m_imageHijackPage, {QStringLiteral("startup.tab.image_hijack"), QStringLiteral("映像劫持")}},
        {m_registryPage, {QStringLiteral("startup.tab.registry"), QStringLiteral("高级注册表")}},
        {m_wmiPage, {QStringLiteral("startup.tab.wmi"), QStringLiteral("WMI")}},
        {m_hiddenPage, {QStringLiteral("startup.tab.hidden"), QStringLiteral("隐藏项")}}
    };
    for (const auto& tabTranslation : tabTranslations)
    {
        ks::i18n::LanguageManager::instance().bindTab(
            m_sideTabWidget,
            tabTranslation.first,
            tabTranslation.second.first,
            tabTranslation.second.second);
    }
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

void StartupDock::rebuildAllTables(const bool processesRefreshStage)
{
    if (m_tableRebuildTimer == nullptr || m_destroying.load())
    {
        return;
    }

    // 结果对象只能在 UI 线程创建，但不能再用一个长循环独占事件循环。
    // 每次过滤、语言切换或新快照到达都会重建工作队列；零间隔单次定时器
    // 让主窗口在两个短时间片之间继续处理绘制、拖动和 Dock 切换。
    m_tableRebuildTimer->stop();
    m_tableRebuildProcessesRefreshStage =
        m_tableRebuildProcessesRefreshStage || processesRefreshStage;
    m_tableRebuildInProgress = true;
    m_tableRebuildTargets.clear();
    m_registryRebuildTargets.clear();
    m_tableRebuildTargetIndex = 0;
    m_registryRebuildTargetIndex = 0;
    m_tableRebuildCompletedUnits = 0;
    m_tableRebuildTotalUnits = 0;
    m_lastTableRebuildProgressPercent = -1;
    m_rebuildRegistryFirst = currentCategory() == StartupCategory::Registry;

    if (m_exportButton != nullptr)
    {
        m_exportButton->setEnabled(false);
    }
    if (m_copyButton != nullptr)
    {
        m_copyButton->setEnabled(false);
    }

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
    const auto appendTableTarget = [this](
        const StartupCategory category,
        QTableWidget* const tableWidget)
    {
        if (tableWidget == nullptr)
        {
            return;
        }
        const auto duplicateIt = std::find_if(
            m_tableRebuildTargets.cbegin(),
            m_tableRebuildTargets.cend(),
            [tableWidget](const TableRebuildTarget& target)
            {
                return target.tableWidget == tableWidget;
            });
        if (duplicateIt != m_tableRebuildTargets.cend())
        {
            return;
        }

        TableRebuildTarget target;
        target.category = category;
        target.tableWidget = tableWidget;
        target.visibleEntryIndexList.reserve(m_entryList.size());
        for (int entryIndex = 0; entryIndex < static_cast<int>(m_entryList.size()); ++entryIndex)
        {
            const StartupEntry& entry = m_entryList[static_cast<std::size_t>(entryIndex)];
            if (category != StartupCategory::All && entry.category != category)
            {
                continue;
            }
            if (entryMatchesCurrentFilter(entry))
            {
                target.visibleEntryIndexList.push_back(entryIndex);
            }
        }

        tableWidget->setEnabled(false);
        tableWidget->setRowCount(0);
        tableWidget->setRowCount(static_cast<int>(target.visibleEntryIndexList.size()));
        m_tableRebuildTotalUnits += target.visibleEntryIndexList.size();
        m_tableRebuildTargets.push_back(std::move(target));
    };

    // 先填充用户当前看见的分类；剩余分类继续在后续时间片中完成。
    for (const auto& [category, tableWidget] : allTableTargets)
    {
        if (category == visibleCategory)
        {
            appendTableTarget(category, tableWidget);
            break;
        }
    }
    for (const auto& [category, tableWidget] : allTableTargets)
    {
        appendTableTarget(category, tableWidget);
    }

    if (m_registryTree != nullptr)
    {
        m_registryTree->setEnabled(false);
        m_registryTree->clear();

        QStringList knownLocationList = buildKnownStartupRegistryLocationList();
        const bool hideEmptyPath = (m_hideEmptyPathCheck != nullptr) && m_hideEmptyPathCheck->isChecked();
        QHash<QString, std::vector<int>> totalEntryIndexMap;
        QHash<QString, std::vector<int>> visibleEntryIndexMap;
        for (int entryIndex = 0; entryIndex < static_cast<int>(m_entryList.size()); ++entryIndex)
        {
            const StartupEntry& entry = m_entryList[static_cast<std::size_t>(entryIndex)];
            if (!isRegistryBackedStartupEntry(entry))
            {
                continue;
            }
            const QString groupLocationText = entry.locationGroupText.trimmed().isEmpty()
                ? entry.locationText
                : entry.locationGroupText;
            totalEntryIndexMap[groupLocationText].push_back(entryIndex);
            if (!knownLocationList.contains(groupLocationText))
            {
                knownLocationList.push_back(groupLocationText);
            }
            if (entryMatchesCurrentFilter(entry))
            {
                visibleEntryIndexMap[groupLocationText].push_back(entryIndex);
            }
        }

        m_registryRebuildTargets.reserve(static_cast<std::size_t>(knownLocationList.size()));
        for (const QString& groupLocationText : knownLocationList)
        {
            RegistryGroupRebuildTarget target;
            target.locationText = groupLocationText;
            target.totalEntryIndexList = totalEntryIndexMap.value(groupLocationText);
            target.visibleEntryIndexList = visibleEntryIndexMap.value(groupLocationText);
            if (hideEmptyPath && target.totalEntryIndexList.empty())
            {
                continue;
            }
            m_tableRebuildTotalUnits += 1U + target.visibleEntryIndexList.size();
            m_registryRebuildTargets.push_back(std::move(target));
        }
    }

    if (m_statusLabel != nullptr)
    {
        if (m_tableRebuildProcessesRefreshStage)
        {
            m_statusLabel->setText(
                startupText(
                    "startup.status.applying_stage_results",
                    QStringLiteral("状态：正在添加第 %1/%2 阶段结果，本阶段 %3 条..."))
                    .arg(m_activeRefreshStageIndex + 1U)
                    .arg(m_activeRefreshStageCount)
                    .arg(m_activeRefreshStageEntryCount));
        }
        else if (m_refreshInProgress.load())
        {
            m_statusLabel->setText(
                startupText(
                    "startup.status.refreshing",
                    QStringLiteral("状态：后台正在枚举启动项...")));
        }
        else
        {
            m_statusLabel->setText(
                startupText(
                    "startup.status.rebuilding_view",
                    QStringLiteral("状态：正在分批更新当前启动项视图...")));
        }
    }

    if (m_tableRebuildTotalUnits == 0U)
    {
        finishIncrementalTableRebuild();
        return;
    }
    m_tableRebuildTimer->start(0);
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
                appendEntryRow(
                    target.tableWidget,
                    static_cast<int>(target.nextRowIndex),
                    m_entryList[static_cast<std::size_t>(entryIndex)],
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
                    m_entryList[static_cast<std::size_t>(entryIndex)],
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
        bool processedUnit = false;
        if (m_rebuildRegistryFirst)
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

    if (m_tableRebuildProcessesRefreshStage
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
    if (tablesCompleted && registryCompleted)
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
    m_tableRebuildProcessesRefreshStage = false;
    m_rebuildRegistryFirst = false;
    m_tableRebuildTargets.clear();
    m_registryRebuildTargets.clear();

    const std::array<QTableWidget*, 8> tableList{
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
            tableWidget->setEnabled(true);
        }
    }
    if (m_registryTree != nullptr)
    {
        m_registryTree->setEnabled(true);
    }
    if (m_exportButton != nullptr)
    {
        m_exportButton->setEnabled(true);
    }
    if (m_copyButton != nullptr)
    {
        m_copyButton->setEnabled(true);
    }

    if (processesRefreshStage)
    {
        m_appliedRefreshStageCount = std::max(
            m_appliedRefreshStageCount,
            m_activeRefreshStageIndex + 1U);
        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(
                startupText(
                    "startup.status.stage_results_applied",
                    QStringLiteral("状态：已添加 %1/%2 阶段，共 %3 条"))
                    .arg(m_appliedRefreshStageCount)
                    .arg(m_activeRefreshStageCount)
                    .arg(m_entryList.size()));
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
        m_statusLabel->setText(
            startupText("startup.status.summary", QStringLiteral("状态：共 %1 条，当前分类 %2"))
                .arg(m_entryList.size())
                .arg(categoryToText(currentCategory())));
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
    if (treeItem == nullptr)
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

    QTreeWidgetItem* groupItem = new QTreeWidgetItem(m_registryTree);
    target->groupItem = groupItem;
    groupItem->setData(0, kStartupEntryIndexRole, -1);
    groupItem->setData(0, kStartupTreeNodeKindRole, static_cast<int>(StartupTreeNodeKind::Group));
    groupItem->setData(0, kStartupTreeLocationRole, target->locationText);
    groupItem->setFirstColumnSpanned(true);
    groupItem->setIcon(toStartupColumn(StartupColumn::Name), createBlueIcon(":/Icon/file_find.svg"));

    if (!target->visibleEntryIndexList.empty())
    {
        groupItem->setText(
            toStartupColumn(StartupColumn::Name),
            startupText("startup.registry.group.match_summary", QStringLiteral("%1    匹配 %2 项 / 总计 %3 项"))
                .arg(target->locationText)
                .arg(target->visibleEntryIndexList.size())
                .arg(target->totalEntryIndexList.size()));
    }
    else
    {
        groupItem->setText(
            toStartupColumn(StartupColumn::Name),
            target->totalEntryIndexList.empty()
                ? startupText("startup.registry.group.no_entries", QStringLiteral("%1    无条目"))
                    .arg(target->locationText)
                : startupText(
                    "startup.registry.group.no_filter_matches",
                    QStringLiteral("%1    当前过滤下无匹配项（总计 %2 项）"))
                    .arg(target->locationText)
                    .arg(target->totalEntryIndexList.size()));

        QTreeWidgetItem* placeholderItem = new QTreeWidgetItem(groupItem);
        placeholderItem->setData(0, kStartupEntryIndexRole, -1);
        placeholderItem->setData(0, kStartupTreeNodeKindRole, static_cast<int>(StartupTreeNodeKind::Placeholder));
        placeholderItem->setData(0, kStartupTreeLocationRole, target->locationText);
        placeholderItem->setText(
            toStartupColumn(StartupColumn::Name),
            target->totalEntryIndexList.empty()
                ? startupText("startup.registry.placeholder.no_entries", QStringLiteral("(无条目)"))
                : startupText("startup.registry.placeholder.no_matches", QStringLiteral("(无匹配项)")));
        placeholderItem->setText(
            toStartupColumn(StartupColumn::Detail),
            target->totalEntryIndexList.empty()
                ? startupText(
                    "startup.registry.placeholder.not_found",
                    QStringLiteral("该位置当前未发现启动项"))
                : startupText(
                    "startup.registry.placeholder.filtered",
                    QStringLiteral("存在条目，但被当前过滤条件隐藏")));
    }

    groupItem->setExpanded(true);
}
