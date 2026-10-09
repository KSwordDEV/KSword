#include "../UI/StructuredFieldView.h"
#include "ServiceDock.Internal.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

using namespace service_dock_detail;

namespace
{
    // createServiceTable 作用：创建服务主列表控件并配置列结构。
    QTableWidget* createServiceTable(QWidget* parentWidget)
    {
        QTableWidget* tableWidget = new ks::ui::VisibleTableWidget(parentWidget);
        tableWidget->setColumnCount(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::Count));
        tableWidget->setHorizontalHeaderLabels({
            QStringLiteral("服务名"),
            QStringLiteral("显示名"),
            QStringLiteral("状态"),
            QStringLiteral("启动类型"),
            QStringLiteral("PID"),
            QStringLiteral("账户"),
            QStringLiteral("风险")
            });
        tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        tableWidget->setAlternatingRowColors(true);
        tableWidget->setWordWrap(false);
        tableWidget->verticalHeader()->setVisible(false);
        tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        tableWidget->horizontalHeader()->setSectionResizeMode(
            ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::Risk),
            QHeaderView::Stretch);
        tableWidget->setColumnWidth(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::Name), 180);
        tableWidget->setColumnWidth(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::DisplayName), 220);
        tableWidget->setColumnWidth(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::State), 100);
        tableWidget->setColumnWidth(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::StartType), 120);
        tableWidget->setColumnWidth(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::Pid), 80);
        tableWidget->setColumnWidth(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::Account), 190);
        return tableWidget;
    }

    // createReadOnlyEditorPage 作用：创建“只读文本编辑器页签”。


    // makeVerticalSeparator 作用：生成工具栏纵向分隔线，提升视觉层次。
    QWidget* makeVerticalSeparator(QWidget* parentWidget)
    {
        QWidget* separatorWidget = new QWidget(parentWidget);
        separatorWidget->setFixedSize(1, 20);
        // 分隔线用动态 token 取色，主题切换时无需重新下发样式。
        separatorWidget->setStyleSheet(
            QStringLiteral("background-color:%1;").arg(KswordTheme::BorderHex()));
        return separatorWidget;
    }

    // buildDetailSectionText 作用：用统一标题包裹一段详情文本，便于合并多个主题块。

}

int ServiceDock::toServiceColumn(const ServiceColumn column)
{
    return static_cast<int>(column);
}

void ServiceDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(6);

    initializeToolbar();
    initializeContent();

    m_rootLayout->addWidget(m_toolbarWidget, 0);
    m_rootLayout->addWidget(m_contentSplitter, 1);
}

void ServiceDock::initializeToolbar()
{
    m_toolbarWidget = new QWidget(this);
    m_toolbarLayout = new QHBoxLayout(m_toolbarWidget);
    m_toolbarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolbarLayout->setSpacing(6);

    // 基础刷新按钮组：
    // - 全量刷新与当前服务刷新拆分，避免误触全局重扫。
    m_refreshAllButton = new QToolButton(m_toolbarWidget);
    m_refreshAllButton->setIcon(createBlueIcon(":/Icon/process_refresh.svg", KswordTheme::CompactIconSize()));
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshAllButton);
    m_refreshAllButton->setToolTip(QStringLiteral("刷新全部服务列表"));

    m_refreshCurrentButton = new QToolButton(m_toolbarWidget);
    m_refreshCurrentButton->setIcon(createBlueIcon(":/Icon/process_details.svg", KswordTheme::CompactIconSize()));
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshCurrentButton);
    m_refreshCurrentButton->setToolTip(QStringLiteral("刷新当前选中服务详情"));

    // 服务控制按钮组：
    // - 全部使用图标按钮；
    // - 具体释义通过 tooltip 提示。
    m_startButton = new QToolButton(m_toolbarWidget);
    m_startButton->setIcon(createBlueIcon(":/Icon/process_start.svg", KswordTheme::CompactIconSize()));
    KswordTheme::ApplyCompactIconButtonMetrics(m_startButton);
    m_startButton->setToolTip(QStringLiteral("启动当前服务"));

    m_stopButton = new QToolButton(m_toolbarWidget);
    m_stopButton->setIcon(createBlueIcon(":/Icon/process_terminate.svg", KswordTheme::CompactIconSize()));
    KswordTheme::ApplyCompactIconButtonMetrics(m_stopButton);
    m_stopButton->setToolTip(QStringLiteral("停止当前服务（高风险动作）"));

    m_pauseButton = new QToolButton(m_toolbarWidget);
    m_pauseButton->setIcon(createBlueIcon(":/Icon/process_pause.svg", KswordTheme::CompactIconSize()));
    KswordTheme::ApplyCompactIconButtonMetrics(m_pauseButton);
    m_pauseButton->setToolTip(QStringLiteral("暂停当前服务"));

    m_continueButton = new QToolButton(m_toolbarWidget);
    m_continueButton->setIcon(createBlueIcon(":/Icon/process_resume.svg", KswordTheme::CompactIconSize()));
    KswordTheme::ApplyCompactIconButtonMetrics(m_continueButton);
    m_continueButton->setToolTip(QStringLiteral("继续当前服务"));

    // 快捷筛选按钮组：
    // - 使用短文本筛选片，避免把“启动/停止服务”的动作图标复用成筛选含义；
    // - checkable 形式可直观看到过滤状态。
    m_runningOnlyButton = new QToolButton(m_toolbarWidget);
    m_runningOnlyButton->setCheckable(true);
    m_runningOnlyButton->setText(QStringLiteral("运行中"));
    m_runningOnlyButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
    m_runningOnlyButton->setFixedHeight(28);
    m_runningOnlyButton->setToolTip(QStringLiteral("仅显示运行中服务"));

    m_autoStartOnlyButton = new QToolButton(m_toolbarWidget);
    m_autoStartOnlyButton->setCheckable(true);
    m_autoStartOnlyButton->setText(QStringLiteral("自动启动"));
    m_autoStartOnlyButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
    m_autoStartOnlyButton->setFixedHeight(28);
    m_autoStartOnlyButton->setToolTip(QStringLiteral("仅显示自动启动服务"));

    m_riskOnlyButton = new QToolButton(m_toolbarWidget);
    m_riskOnlyButton->setCheckable(true);
    m_riskOnlyButton->setText(QStringLiteral("风险"));
    m_riskOnlyButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
    m_riskOnlyButton->setFixedHeight(28);
    m_riskOnlyButton->setToolTip(QStringLiteral("仅显示带风险标签的服务"));

    // 文本过滤与排序：
    // - 关键词覆盖服务名/显示名/描述/路径/账户；
    // - 排序模式用于快速调整关注视角。
    m_filterEdit = new QLineEdit(m_toolbarWidget);
    m_filterEdit->setPlaceholderText(QStringLiteral("过滤：服务名/显示名/描述/路径/账户"));
    m_filterEdit->setToolTip(QStringLiteral("支持关键字模糊匹配"));

    m_sortCombo = new QComboBox(m_toolbarWidget);
    m_sortCombo->addItem(QStringLiteral("名称升序"), static_cast<int>(SortMode::NameAsc));
    m_sortCombo->addItem(QStringLiteral("运行中优先"), static_cast<int>(SortMode::StatePriority));
    m_sortCombo->addItem(QStringLiteral("自动启动优先"), static_cast<int>(SortMode::StartTypePriority));
    m_sortCombo->setToolTip(QStringLiteral("切换服务列表排序方式"));

    // 启动类型修改控件：
    // - 通过下拉选择目标类型；
    // - 右侧图标按钮执行变更。
    m_startTypeCombo = new QComboBox(m_toolbarWidget);
    m_startTypeCombo->setToolTip(QStringLiteral("选择要应用到当前服务的启动类型"));
    m_startTypeCombo->addItem(QStringLiteral("自动"));
    m_startTypeCombo->setItemData(0, static_cast<qulonglong>(SERVICE_AUTO_START), Qt::UserRole);
    m_startTypeCombo->setItemData(0, false, Qt::UserRole + 1);
    m_startTypeCombo->addItem(QStringLiteral("自动(延迟)"));
    m_startTypeCombo->setItemData(1, static_cast<qulonglong>(SERVICE_AUTO_START), Qt::UserRole);
    m_startTypeCombo->setItemData(1, true, Qt::UserRole + 1);
    m_startTypeCombo->addItem(QStringLiteral("手动"));
    m_startTypeCombo->setItemData(2, static_cast<qulonglong>(SERVICE_DEMAND_START), Qt::UserRole);
    m_startTypeCombo->setItemData(2, false, Qt::UserRole + 1);
    m_startTypeCombo->addItem(QStringLiteral("禁用"));
    m_startTypeCombo->setItemData(3, static_cast<qulonglong>(SERVICE_DISABLED), Qt::UserRole);
    m_startTypeCombo->setItemData(3, false, Qt::UserRole + 1);

    m_applyStartTypeButton = new QToolButton(m_toolbarWidget);
    m_applyStartTypeButton->setIcon(createBlueIcon(":/Icon/service_apply.svg", KswordTheme::CompactIconSize()));
    KswordTheme::ApplyCompactIconButtonMetrics(m_applyStartTypeButton);
    m_applyStartTypeButton->setToolTip(QStringLiteral("应用当前启动类型修改"));

    m_summaryLabel = new QLabel(QStringLiteral("状态：等待首次刷新"), m_toolbarWidget);
    m_summaryLabel->setWordWrap(true);
    m_summaryLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    m_toolbarLayout->addWidget(m_refreshAllButton);
    m_toolbarLayout->addWidget(m_refreshCurrentButton);
    m_toolbarLayout->addWidget(makeVerticalSeparator(m_toolbarWidget));
    m_toolbarLayout->addWidget(m_startButton);
    m_toolbarLayout->addWidget(m_stopButton);
    m_toolbarLayout->addWidget(m_pauseButton);
    m_toolbarLayout->addWidget(m_continueButton);
    m_toolbarLayout->addWidget(makeVerticalSeparator(m_toolbarWidget));
    m_toolbarLayout->addWidget(m_runningOnlyButton);
    m_toolbarLayout->addWidget(m_autoStartOnlyButton);
    m_toolbarLayout->addWidget(m_riskOnlyButton);
    m_toolbarLayout->addWidget(m_filterEdit, 1);
    m_toolbarLayout->addWidget(m_sortCombo);
    m_toolbarLayout->addWidget(m_startTypeCombo);
    m_toolbarLayout->addWidget(m_applyStartTypeButton);
    m_toolbarLayout->addWidget(m_summaryLabel, 1);
}

void ServiceDock::initializeContent()
{
    m_contentSplitter = new QSplitter(Qt::Horizontal, this);
    m_contentSplitter->setChildrenCollapsible(false);

    QWidget* leftPanelWidget = new QWidget(m_contentSplitter);
    QVBoxLayout* leftPanelLayout = new QVBoxLayout(leftPanelWidget);
    leftPanelLayout->setContentsMargins(0, 0, 0, 0);
    leftPanelLayout->setSpacing(4);

    m_serviceTable = createServiceTable(leftPanelWidget);
    leftPanelLayout->addWidget(m_serviceTable, 1);

    QWidget* rightPanelWidget = new QWidget(m_contentSplitter);
    QVBoxLayout* rightPanelLayout = new QVBoxLayout(rightPanelWidget);
    rightPanelLayout->setContentsMargins(0, 0, 0, 0);
    rightPanelLayout->setSpacing(4);

    m_detailTabWidget = new QTabWidget(rightPanelWidget);
    initializeDetailTabs();
    rightPanelLayout->addWidget(m_detailTabWidget, 1);

    m_contentSplitter->addWidget(leftPanelWidget);
    m_contentSplitter->addWidget(rightPanelWidget);
    m_contentSplitter->setStretchFactor(0, 3);
    m_contentSplitter->setStretchFactor(1, 2);
}

void ServiceDock::initializeConnections()
{
    connect(m_refreshAllButton, &QToolButton::clicked, this, [this]()
        {
            requestAsyncRefresh(true);
        });
    connect(m_refreshCurrentButton, &QToolButton::clicked, this, [this]()
        {
            refreshSelectedService();
        });

    connect(m_startButton, &QToolButton::clicked, this, [this]()
        {
            startSelectedService();
        });
    connect(m_stopButton, &QToolButton::clicked, this, [this]()
        {
            stopSelectedService();
        });
    connect(m_pauseButton, &QToolButton::clicked, this, [this]()
        {
            pauseSelectedService();
        });
    connect(m_continueButton, &QToolButton::clicked, this, [this]()
        {
            continueSelectedService();
        });
    connect(m_applyStartTypeButton, &QToolButton::clicked, this, [this]()
        {
            applySelectedStartType();
        });

    connect(m_filterEdit, &QLineEdit::textChanged, this, [this](const QString&)
        {
            rebuildServiceTable();
        });
    connect(m_sortCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](const int)
        {
            rebuildServiceTable();
        });
    connect(m_runningOnlyButton, &QToolButton::toggled, this, [this](const bool)
        {
            rebuildServiceTable();
        });
    connect(m_autoStartOnlyButton, &QToolButton::toggled, this, [this](const bool)
        {
            rebuildServiceTable();
        });
    connect(m_riskOnlyButton, &QToolButton::toggled, this, [this](const bool)
        {
            rebuildServiceTable();
        });

    connect(m_serviceTable, &QWidget::customContextMenuRequested, this, [this](const QPoint& localPos)
        {
            showServiceContextMenu(localPos);
        });
    connect(m_serviceTable, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            onServiceSelectionChanged();
        });
    connect(m_serviceTable, &QTableWidget::cellDoubleClicked, this, [this](const int row, const int)
        {
            if (row >= 0)
            {
                refreshSelectedService();
            }
        });

}

void ServiceDock::rebuildServiceTable()
{
    if (m_serviceTable == nullptr)
    {
        return;
    }

    // 先记录旧选择，重建后按服务短名恢复选择，避免刷新导致用户焦点丢失。
    const QString previousSelectedServiceName = selectedServiceName();

    std::vector<int> visibleIndexList;
    visibleIndexList.reserve(m_serviceList.size());
    for (int index = 0; index < static_cast<int>(m_serviceList.size()); ++index)
    {
        const ServiceEntry& entry = m_serviceList[static_cast<std::size_t>(index)];
        if (!entryMatchesCurrentFilter(entry))
        {
            continue;
        }
        visibleIndexList.push_back(index);
    }

    std::sort(
        visibleIndexList.begin(),
        visibleIndexList.end(),
        [this](const int leftIndex, const int rightIndex)
        {
            const ServiceEntry& leftEntry = m_serviceList[static_cast<std::size_t>(leftIndex)];
            const ServiceEntry& rightEntry = m_serviceList[static_cast<std::size_t>(rightIndex)];
            return serviceLessThan(leftEntry, rightEntry);
        });

    m_serviceTable->setRowCount(static_cast<int>(visibleIndexList.size()));
    for (int rowIndex = 0; rowIndex < static_cast<int>(visibleIndexList.size()); ++rowIndex)
    {
        const ServiceEntry& entry = m_serviceList[static_cast<std::size_t>(visibleIndexList[static_cast<std::size_t>(rowIndex)])];

        QTableWidgetItem* nameItem = createReadOnlyItem(entry.serviceNameText);
        nameItem->setData(kServiceNameRole, entry.serviceNameText);
        nameItem->setIcon(entry.currentState == SERVICE_RUNNING
            ? createBlueIcon(":/Icon/process_start.svg")
            : createBlueIcon(":/Icon/process_pause.svg"));

        QTableWidgetItem* displayNameItem = createReadOnlyItem(entry.displayNameText);
        QTableWidgetItem* stateItem = createReadOnlyItem(entry.stateText);
        QTableWidgetItem* startTypeItem = createReadOnlyItem(entry.startTypeText);
        QTableWidgetItem* pidItem = createReadOnlyItem(entry.processId == 0
            ? QStringLiteral("-")
            : QString::number(entry.processId));
        QTableWidgetItem* accountItem = createReadOnlyItem(entry.accountText);
        QTableWidgetItem* riskItem = createReadOnlyItem(entry.riskSummaryText);

        m_serviceTable->setItem(rowIndex, toServiceColumn(ServiceColumn::Name), nameItem);
        m_serviceTable->setItem(rowIndex, toServiceColumn(ServiceColumn::DisplayName), displayNameItem);
        m_serviceTable->setItem(rowIndex, toServiceColumn(ServiceColumn::State), stateItem);
        m_serviceTable->setItem(rowIndex, toServiceColumn(ServiceColumn::StartType), startTypeItem);
        m_serviceTable->setItem(rowIndex, toServiceColumn(ServiceColumn::Pid), pidItem);
        m_serviceTable->setItem(rowIndex, toServiceColumn(ServiceColumn::Account), accountItem);
        m_serviceTable->setItem(rowIndex, toServiceColumn(ServiceColumn::Risk), riskItem);

        // 基础高亮策略：
        // - 运行中：绿色弱高亮；
        // - 自动启动：蓝色弱高亮；
        // - Pending：橙色弱高亮。
        QColor rowColor;
        if (entry.currentState == SERVICE_RUNNING)
        {
            rowColor = KswordTheme::WithAlpha(KswordTheme::SuccessColor(), 70);
        }
        else if (isServiceStatePending(entry.currentState))
        {
            rowColor = KswordTheme::WithAlpha(KswordTheme::WarningColor(), 70);
        }
        else if (entry.startTypeValue == SERVICE_AUTO_START)
        {
            rowColor = KswordTheme::WithAlpha(
                KswordTheme::AccentColor(KswordTheme::AccentRole::Blue), 45);
        }
        if (entry.hasRisk)
        {
            rowColor = KswordTheme::WithAlpha(KswordTheme::ErrorColor(), 68);
        }

        if (rowColor.isValid())
        {
            for (int columnIndex = 0; columnIndex < toServiceColumn(ServiceColumn::Count); ++columnIndex)
            {
                QTableWidgetItem* rowItem = m_serviceTable->item(rowIndex, columnIndex);
                if (rowItem != nullptr)
                {
                    rowItem->setBackground(rowColor);
                }
            }
        }
    }

    // 重建后恢复选择：
    // - 优先恢复旧服务；
    // - 若旧服务不存在则选第一行。
    bool restoredSelection = false;
    if (!previousSelectedServiceName.isEmpty())
    {
        for (int rowIndex = 0; rowIndex < m_serviceTable->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* nameItem = m_serviceTable->item(rowIndex, toServiceColumn(ServiceColumn::Name));
            if (nameItem == nullptr)
            {
                continue;
            }

            const QString rowServiceName = nameItem->data(kServiceNameRole).toString();
            if (QString::compare(rowServiceName, previousSelectedServiceName, Qt::CaseInsensitive) == 0)
            {
                m_serviceTable->selectRow(rowIndex);
                restoredSelection = true;
                break;
            }
        }
    }
    if (!restoredSelection && m_serviceTable->rowCount() > 0)
    {
        m_serviceTable->selectRow(0);
    }

    updateSummaryText();
    syncToolbarStateWithSelection();
    updateDetailViewsFromSelection();
}

bool ServiceDock::entryMatchesCurrentFilter(const ServiceEntry& entry) const
{
    if ((m_runningOnlyButton != nullptr)
        && m_runningOnlyButton->isChecked()
        && entry.currentState != SERVICE_RUNNING)
    {
        return false;
    }

    if ((m_autoStartOnlyButton != nullptr)
        && m_autoStartOnlyButton->isChecked()
        && entry.startTypeValue != SERVICE_AUTO_START)
    {
        return false;
    }

    if ((m_riskOnlyButton != nullptr)
        && m_riskOnlyButton->isChecked()
        && !entry.hasRisk)
    {
        return false;
    }

    const QString keywordText = (m_filterEdit != nullptr) ? m_filterEdit->text().trimmed() : QString();
    if (keywordText.isEmpty())
    {
        return true;
    }

    const QString haystackText =
        entry.serviceNameText + QLatin1Char('\n')
        + entry.displayNameText + QLatin1Char('\n')
        + entry.descriptionText + QLatin1Char('\n')
        + entry.imagePathText + QLatin1Char('\n')
        + entry.commandLineText + QLatin1Char('\n')
        + entry.accountText + QLatin1Char('\n')
        + entry.sourceStatusText + QLatin1Char('\n')
        + entry.riskSummaryText;
    return haystackText.contains(keywordText, Qt::CaseInsensitive);
}

bool ServiceDock::serviceLessThan(const ServiceEntry& left, const ServiceEntry& right) const
{
    const SortMode sortMode = (m_sortCombo == nullptr)
        ? SortMode::NameAsc
        : static_cast<SortMode>(m_sortCombo->currentData().toInt());

    if (sortMode == SortMode::StatePriority)
    {
        const bool leftRunning = left.currentState == SERVICE_RUNNING;
        const bool rightRunning = right.currentState == SERVICE_RUNNING;
        if (leftRunning != rightRunning)
        {
            return leftRunning;
        }

        const bool leftPending = isServiceStatePending(left.currentState);
        const bool rightPending = isServiceStatePending(right.currentState);
        if (leftPending != rightPending)
        {
            return leftPending;
        }
    }
    else if (sortMode == SortMode::StartTypePriority)
    {
        const bool leftAuto = left.startTypeValue == SERVICE_AUTO_START;
        const bool rightAuto = right.startTypeValue == SERVICE_AUTO_START;
        if (leftAuto != rightAuto)
        {
            return leftAuto;
        }

        if (left.startTypeValue != right.startTypeValue)
        {
            return left.startTypeValue < right.startTypeValue;
        }
    }

    const int displayCompareResult = QString::compare(left.displayNameText, right.displayNameText, Qt::CaseInsensitive);
    if (displayCompareResult != 0)
    {
        return displayCompareResult < 0;
    }

    return QString::compare(left.serviceNameText, right.serviceNameText, Qt::CaseInsensitive) < 0;
}

void ServiceDock::updateSummaryText()
{
    if (m_summaryLabel == nullptr)
    {
        return;
    }

    int runningCount = 0;
    int autoStartCount = 0;
    int riskCount = 0;
    int registryOnlyCount = 0;
    int scmOnlyCount = 0;
    for (const ServiceEntry& entry : m_serviceList)
    {
        if (entry.currentState == SERVICE_RUNNING)
        {
            ++runningCount;
        }
        if (entry.startTypeValue == SERVICE_AUTO_START)
        {
            ++autoStartCount;
        }
        if (entry.hasRisk)
        {
            ++riskCount;
        }
        if (entry.registryScanCompleted
            && !entry.scmRecordPresent
            && entry.registryKeyPresent)
        {
            ++registryOnlyCount;
        }
        if (entry.registryScanCompleted
            && entry.scmRecordPresent
            && !entry.registryKeyPresent)
        {
            ++scmOnlyCount;
        }
    }

    const int visibleCount = (m_serviceTable == nullptr) ? 0 : m_serviceTable->rowCount();
    m_summaryLabel->setText(
        QStringLiteral("状态：总计 %1，运行中 %2，自动启动 %3，风险 %4，幽灵 %5，SCM 异常 %6，当前可见 %7")
        .arg(m_serviceList.size())
        .arg(runningCount)
        .arg(autoStartCount)
        .arg(riskCount)
        .arg(registryOnlyCount)
        .arg(scmOnlyCount)
        .arg(visibleCount));
}

QString ServiceDock::selectedServiceName() const
{
    if (m_serviceTable == nullptr)
    {
        return QString();
    }

    const int currentRow = m_serviceTable->currentRow();
    if (currentRow < 0)
    {
        return QString();
    }

    QTableWidgetItem* nameItem = m_serviceTable->item(currentRow, toServiceColumn(ServiceColumn::Name));
    if (nameItem == nullptr)
    {
        return QString();
    }

    return nameItem->data(kServiceNameRole).toString().trimmed();
}

void ServiceDock::syncToolbarStateWithSelection()
{
    const int selectedIndex = findServiceIndexByName(selectedServiceName());
    const bool hasSelection = selectedIndex >= 0 && selectedIndex < static_cast<int>(m_serviceList.size());

    if (!hasSelection)
    {
        m_refreshCurrentButton->setEnabled(false);
        m_startButton->setEnabled(false);
        m_stopButton->setEnabled(false);
        m_pauseButton->setEnabled(false);
        m_continueButton->setEnabled(false);
        m_applyStartTypeButton->setEnabled(false);
        m_startTypeCombo->setEnabled(false);
        if (m_generalStartButton != nullptr) { m_generalStartButton->setEnabled(false); }
        if (m_generalStopButton != nullptr) { m_generalStopButton->setEnabled(false); }
        if (m_generalPauseButton != nullptr) { m_generalPauseButton->setEnabled(false); }
        if (m_generalContinueButton != nullptr) { m_generalContinueButton->setEnabled(false); }
        // 未选中服务时同样要说明原因，避免用户对着一排灰按钮猜。
        const QString noSelectionText = QStringLiteral("请先在列表中选择一个服务");
        m_startButton->setToolTip(noSelectionText);
        m_stopButton->setToolTip(noSelectionText);
        m_pauseButton->setToolTip(noSelectionText);
        m_continueButton->setToolTip(noSelectionText);
        m_applyStartTypeButton->setToolTip(noSelectionText);
        return;
    }

    const ServiceEntry& selectedEntry = m_serviceList[static_cast<std::size_t>(selectedIndex)];
    const bool scmRecordPresent = selectedEntry.scmRecordPresent;
    const bool pendingState = scmRecordPresent
        && isServiceStatePending(selectedEntry.currentState);
    const bool canPauseContinue = (selectedEntry.controlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) != 0;

    m_refreshCurrentButton->setEnabled(true);
    m_startButton->setEnabled(scmRecordPresent
        && !pendingState
        && (selectedEntry.currentState == SERVICE_STOPPED || selectedEntry.currentState == SERVICE_PAUSED));
    m_stopButton->setEnabled(scmRecordPresent
        && !pendingState
        && (selectedEntry.currentState == SERVICE_RUNNING || selectedEntry.currentState == SERVICE_PAUSED));

    // 选中服务后恢复常规 tooltip；过渡态则说明正在切换，
    // 否则未选中分支写入的“请先选择一个服务”会一直残留。
    if (!scmRecordPresent)
    {
        const QString unavailableText = QStringLiteral("该条目未出现在 SCM 枚举中，仅提供注册表取证与删除操作");
        m_startButton->setToolTip(unavailableText);
        m_stopButton->setToolTip(unavailableText);
        m_applyStartTypeButton->setToolTip(unavailableText);
    }
    else if (pendingState)
    {
        const QString pendingText = QStringLiteral("服务正在切换状态，请等待完成");
        m_startButton->setToolTip(pendingText);
        m_stopButton->setToolTip(pendingText);
        m_applyStartTypeButton->setToolTip(pendingText);
    }
    else
    {
        m_startButton->setToolTip(m_startButton->isEnabled()
            ? QStringLiteral("启动当前服务")
            : QStringLiteral("仅在服务已停止或已暂停时可启动"));
        m_stopButton->setToolTip(m_stopButton->isEnabled()
            ? QStringLiteral("停止当前服务（高风险动作）")
            : QStringLiteral("仅在服务正在运行或已暂停时可停止"));
        m_applyStartTypeButton->setToolTip(QStringLiteral("应用当前启动类型修改"));
    }
    m_pauseButton->setEnabled(scmRecordPresent
        && !pendingState
        && selectedEntry.currentState == SERVICE_RUNNING
        && canPauseContinue);
    m_continueButton->setEnabled(scmRecordPresent
        && !pendingState
        && selectedEntry.currentState == SERVICE_PAUSED
        && canPauseContinue);

    // 置灰必须说明原因：这两个按钮有三个互相独立的置灰来源
    //（服务不支持暂停/继续、正处于过渡态、当前状态不符），
    // 而 tooltip 此前恒为“暂停当前服务”。用户只看到灰按钮，
    // 会反复换选服务、反复等待，却永远等不到它可用。
    if (!scmRecordPresent)
    {
        const QString unavailableText = QStringLiteral("该条目未出现在 SCM 枚举中，无法执行服务控制");
        m_pauseButton->setToolTip(unavailableText);
        m_continueButton->setToolTip(unavailableText);
    }
    else if (!canPauseContinue)
    {
        const QString unsupportedText = QStringLiteral("该服务不支持暂停/继续");
        m_pauseButton->setToolTip(unsupportedText);
        m_continueButton->setToolTip(unsupportedText);
    }
    else if (pendingState)
    {
        const QString pendingText = QStringLiteral("服务正在切换状态，请等待完成");
        m_pauseButton->setToolTip(pendingText);
        m_continueButton->setToolTip(pendingText);
    }
    else
    {
        m_pauseButton->setToolTip(m_pauseButton->isEnabled()
            ? QStringLiteral("暂停当前服务")
            : QStringLiteral("仅在服务正在运行时可暂停"));
        m_continueButton->setToolTip(m_continueButton->isEnabled()
            ? QStringLiteral("继续当前服务")
            : QStringLiteral("仅在服务已暂停时可继续"));
    }
    m_applyStartTypeButton->setEnabled(scmRecordPresent && !pendingState);
    m_startTypeCombo->setEnabled(scmRecordPresent && !pendingState);
    if (m_generalStartButton != nullptr) { m_generalStartButton->setEnabled(m_startButton->isEnabled()); }
    if (m_generalStopButton != nullptr) { m_generalStopButton->setEnabled(m_stopButton->isEnabled()); }
    if (m_generalPauseButton != nullptr) { m_generalPauseButton->setEnabled(m_pauseButton->isEnabled()); }
    if (m_generalContinueButton != nullptr) { m_generalContinueButton->setEnabled(m_continueButton->isEnabled()); }

    if (!m_detailUiSyncInProgress && m_generalStartTypeCombo != nullptr)
    {
        const QSignalBlocker blocker(m_generalStartTypeCombo);
        const int generalStartTypeIndex = m_generalStartTypeCombo->findData(static_cast<qulonglong>(selectedEntry.startTypeValue));
        if (generalStartTypeIndex >= 0)
        {
            m_generalStartTypeCombo->setCurrentIndex(generalStartTypeIndex);
        }
    }

    const QSignalBlocker startTypeBlocker(m_startTypeCombo);
    const int toolbarStartTypeIndex = m_startTypeCombo->findData(static_cast<qulonglong>(selectedEntry.startTypeValue), Qt::UserRole);
    if (toolbarStartTypeIndex >= 0)
    {
        m_startTypeCombo->setCurrentIndex(toolbarStartTypeIndex);
    }
}

int ServiceDock::findServiceIndexByName(const QString& serviceNameText) const
{
    if (serviceNameText.trimmed().isEmpty())
    {
        return -1;
    }

    for (int index = 0; index < static_cast<int>(m_serviceList.size()); ++index)
    {
        const ServiceEntry& entry = m_serviceList[static_cast<std::size_t>(index)];
        if (QString::compare(entry.serviceNameText, serviceNameText, Qt::CaseInsensitive) == 0)
        {
            return index;
        }
    }
    return -1;
}

void ServiceDock::onServiceSelectionChanged()
{
    updateDetailViewsFromSelection();
    syncToolbarStateWithSelection();
}

ks::ui::FieldDocument ServiceDock::buildAuditTabText(const ServiceEntry& entry) const
{
    ks::ui::FieldDocument document;
    document.section(QStringLiteral("独立来源"));
    document.field(QStringLiteral("交叉比对"), entry.sourceStatusText, true);
    document.field(QStringLiteral("SCM 枚举"), entry.scmRecordPresent ? QStringLiteral("存在") : QStringLiteral("未发现"), true);
    document.field(QStringLiteral("注册表键"), entry.registryKeyPresent ? QStringLiteral("存在") : QStringLiteral("未发现"), true);
    const auto appendSection = [&document](const QString& title, const ks::ui::FieldDocument& content) {
        ks::ui::FieldNode section;
        section.kind = ks::ui::FieldNode::Kind::Section;
        section.name = title;
        section.children = content.nodes;
        document.nodes.append(std::move(section));
    };
    appendSection(QStringLiteral("触发器"), buildTriggerDetailText(entry));
    appendSection(QStringLiteral("安全"), buildSecurityDetailText(entry));
    appendSection(QStringLiteral("风险"), buildRiskDetailText(entry));
    appendSection(QStringLiteral("导出"), buildExportDetailText(entry));
    return document;
}

QString ServiceDock::buildBasicInfoText(const ServiceEntry& entry) const
{
    QString detailText;
    detailText += QStringLiteral("服务名：%1\n").arg(entry.serviceNameText);
    detailText += QStringLiteral("来源交叉验证：%1\n").arg(entry.sourceStatusText);
    detailText += QStringLiteral("显示名：%1\n").arg(entry.displayNameText);
    detailText += QStringLiteral("状态：%1\n").arg(entry.stateText);
    detailText += QStringLiteral("PID：%1\n").arg(entry.processId == 0 ? QStringLiteral("-") : QString::number(entry.processId));
    detailText += QStringLiteral("启动类型：%1\n").arg(entry.startTypeText);
    detailText += QStringLiteral("延迟自动启动：%1\n").arg(entry.delayedAutoStart ? QStringLiteral("是") : QStringLiteral("否"));
    detailText += QStringLiteral("服务类型：%1\n").arg(entry.serviceTypeText);
    detailText += QStringLiteral("错误控制：%1\n").arg(entry.errorControlText);
    detailText += QStringLiteral("启动账户：%1\n").arg(entry.accountText);
    detailText += QStringLiteral("镜像路径：%1\n").arg(entry.imagePathText);
    detailText += QStringLiteral("ServiceDll：%1\n").arg(entry.serviceDllPathText.isEmpty() ? QStringLiteral("未配置") : entry.serviceDllPathText);
    detailText += QStringLiteral("BinaryPath：%1\n").arg(entry.commandLineText);
    detailText += QStringLiteral("描述：%1\n").arg(entry.descriptionText);
    detailText += QStringLiteral("风险摘要：%1\n").arg(entry.riskSummaryText);
    return detailText;
}

QString ServiceDock::buildConfigInfoText(const ServiceEntry& entry) const
{
    QString detailText;
    detailText += QStringLiteral("dwStartType：%1\n").arg(entry.startTypeValue);
    detailText += QStringLiteral("dwServiceType：%1\n").arg(entry.serviceTypeValue);
    detailText += QStringLiteral("dwErrorControl：%1\n").arg(entry.errorControlValue);
    detailText += QStringLiteral("当前状态值：%1\n").arg(entry.currentState);
    detailText += QStringLiteral("可接受控制位：%1\n").arg(entry.controlsAccepted);
    detailText += QStringLiteral("启动类型文本：%1\n").arg(entry.startTypeText);
    detailText += QStringLiteral("服务类型文本：%1\n").arg(entry.serviceTypeText);
    detailText += QStringLiteral("错误控制文本：%1\n").arg(entry.errorControlText);
    detailText += QStringLiteral("账户：%1\n").arg(entry.accountText);
    detailText += QStringLiteral("描述：%1\n").arg(entry.descriptionText);
    return detailText;
}
