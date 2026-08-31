#include "NetworkDock.InternalCommon.h"
#include "NetworkFirewallPage.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/TableInteractionSupport.h"

#include "../OnlineScan/SandboxUploadActions.h"
#include "../theme.h"

#include <QApplication>
#include <QBrush>

using namespace network_dock_detail;

namespace
{
    // nidsSeverityText：把 NIDS 等级转为界面文本。
    QString nidsSeverityText(const ks::network::NidsAlertSeverity severity)
    {
        switch (severity)
        {
        case ks::network::NidsAlertSeverity::Low:
            return QStringLiteral("低");
        case ks::network::NidsAlertSeverity::Medium:
            return QStringLiteral("中");
        case ks::network::NidsAlertSeverity::High:
            return QStringLiteral("高");
        case ks::network::NidsAlertSeverity::Critical:
            return QStringLiteral("严重");
        default:
            return QStringLiteral("未知");
        }
    }

    // nidsSeverityColor：按等级返回表格强调色。
    QColor nidsSeverityColor(const ks::network::NidsAlertSeverity severity)
    {
        switch (severity)
        {
        case ks::network::NidsAlertSeverity::Low:
            return KswordTheme::TextSecondaryColor();
        case ks::network::NidsAlertSeverity::Medium:
            return KswordTheme::WarningColor();
        case ks::network::NidsAlertSeverity::High:
            return KswordTheme::ErrorColor();
        case ks::network::NidsAlertSeverity::Critical:
            return KswordTheme::AccentColor(KswordTheme::AccentRole::Purple);
        default:
            return KswordTheme::TextSecondaryColor();
        }
    }

    // createNidsCell：创建统一的只读 NIDS 表格单元格。
    QTableWidgetItem* createNidsCell(const QString& cellText)
    {
        QTableWidgetItem* tableItem = new QTableWidgetItem(cellText);
        tableItem->setFlags(tableItem->flags() & ~Qt::ItemIsEditable);
        return tableItem;
    }

    // nidsSeverityIndex：等级转 int，用于过滤和排序。
    int nidsSeverityIndex(const ks::network::NidsAlertSeverity severity)
    {
        return static_cast<int>(severity);
    }

    // nidsTableRowText：
    // - 输入：NIDS 表格指针和行号；
    // - 处理：按当前列顺序读取整行，使用 TSV 拼接；
    // - 返回：可直接复制到剪贴板或表格工具的文本。
    QString nidsTableRowText(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return QString();
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        return fields.join(QLatin1Char('\t'));
    }

    // nidsSelectedRows：
    // - 输入：NIDS 表格指针；
    // - 处理：收集选择模型中的行号并去重排序，空选择时回退当前行；
    // - 返回：需要复制的行号列表。
    std::vector<int> nidsSelectedRows(QTableWidget* table)
    {
        std::set<int> rowSet;
        if (table != nullptr)
        {
            for (const QModelIndex& index : table->selectionModel()->selectedRows())
            {
                rowSet.insert(index.row());
            }
            if (rowSet.empty() && table->currentRow() >= 0)
            {
                rowSet.insert(table->currentRow());
            }
        }
        return std::vector<int>(rowSet.begin(), rowSet.end());
    }

    // copyNidsRowsToClipboard：
    // - 输入：NIDS 表格和待复制行号；
    // - 处理：逐行生成 TSV，多行使用换行分隔；
    // - 返回：无，复制失败时静默保持 UI 稳定。
    void copyNidsRowsToClipboard(QTableWidget* table, const std::vector<int>& rowList)
    {
        if (table == nullptr || QApplication::clipboard() == nullptr || rowList.empty())
        {
            return;
        }

        QStringList rowTexts;
        rowTexts.reserve(static_cast<int>(rowList.size()));
        for (const int rowIndex : rowList)
        {
            const QString rowText = nidsTableRowText(table, rowIndex);
            if (!rowText.isEmpty())
            {
                rowTexts.push_back(rowText);
            }
        }
        if (!rowTexts.isEmpty())
        {
            QApplication::clipboard()->setText(rowTexts.join(QChar('\n')));
        }
    }

    // nidsAlertSequenceForRow：
    // - 输入：NIDS 表格指针、目标行号和时间列索引（列枚举是 NetworkDock 的类内成员，
    //   匿名命名空间取不到，故由调用方换算好列号传入）；
    // - 处理：从时间列的 Qt::UserRole 取出该告警关联的报文序号；
    // - 返回：取到非零序号时为 true，行号越界、单元格缺失或序号无效时为 false。
    bool nidsAlertSequenceForRow(
        QTableWidget* table,
        const int row,
        const int timeColumn,
        std::uint64_t& sequenceIdOut)
    {
        if (table == nullptr || row < 0 || row >= table->rowCount())
        {
            return false;
        }

        const QTableWidgetItem* timeItem = table->item(row, timeColumn);
        if (timeItem == nullptr)
        {
            return false;
        }

        const QVariant sequenceVariant = timeItem->data(Qt::UserRole);
        if (!sequenceVariant.isValid())
        {
            return false;
        }
        sequenceIdOut = static_cast<std::uint64_t>(sequenceVariant.toULongLong());
        return sequenceIdOut != 0;
    }

    // captureNidsProcessIdentity：
    // - 作用：在 NIDS 告警生成的同一时段冻结应用级处置所需的进程身份；
    // - 处理：创建时间前后各读取一次，只有两次一致且镜像路径可得才接受快照；
    // - 返回：失败时保持字段为空，后续只能生成端点级阻断规则。
    void captureNidsProcessIdentity(ks::network::NidsAlert& alertRecord)
    {
        if (alertRecord.processId == 0U)
        {
            return;
        }

        std::uint64_t creationTimeBefore = 0U;
        if (!ks::process::QueryProcessCreationTimeByPid(
                alertRecord.processId,
                &creationTimeBefore,
                nullptr) ||
            creationTimeBefore == 0U)
        {
            return;
        }

        const std::string imagePath = ks::process::QueryProcessPathByPid(alertRecord.processId);
        if (imagePath.empty())
        {
            return;
        }

        std::uint64_t creationTimeAfter = 0U;
        if (!ks::process::QueryProcessCreationTimeByPid(
                alertRecord.processId,
                &creationTimeAfter,
                nullptr) ||
            creationTimeAfter != creationTimeBefore)
        {
            return;
        }

        alertRecord.processCreationTime100ns = creationTimeAfter;
        alertRecord.processImagePath = imagePath;
    }
}

void NetworkDock::initializeNidsTab()
{
    m_nidsPage = new QWidget(this);
    m_nidsLayout = new QVBoxLayout(m_nidsPage);
    m_nidsLayout->setContentsMargins(6, 6, 6, 6);
    m_nidsLayout->setSpacing(6);

    m_nidsControlLayout = new QHBoxLayout();
    m_nidsControlLayout->setSpacing(6);

    m_nidsEnableCheck = new QCheckBox(QStringLiteral("实时检测"), m_nidsPage);
    m_nidsEnableCheck->setChecked(true);
    m_nidsEnableCheck->setToolTip(QStringLiteral("启用或暂停 NIDS 实时报文检测"));

    QLabel* severityFilterLabel = new QLabel(QStringLiteral("等级:"), m_nidsPage);
    m_nidsSeverityFilterCombo = new QComboBox(m_nidsPage);
    m_nidsSeverityFilterCombo->addItem(QStringLiteral("全部"), static_cast<int>(ks::network::NidsAlertSeverity::Low));
    m_nidsSeverityFilterCombo->addItem(QStringLiteral("中危+"), static_cast<int>(ks::network::NidsAlertSeverity::Medium));
    m_nidsSeverityFilterCombo->addItem(QStringLiteral("高危+"), static_cast<int>(ks::network::NidsAlertSeverity::High));
    m_nidsSeverityFilterCombo->addItem(QStringLiteral("严重"), static_cast<int>(ks::network::NidsAlertSeverity::Critical));
    m_nidsSeverityFilterCombo->setToolTip(QStringLiteral("按最低告警等级过滤表格"));
    m_nidsSeverityFilterCombo->setMaximumWidth(120);

    m_nidsClearButton = new QPushButton(m_nidsPage);
    m_nidsClearButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_nidsClearButton->setToolTip(QStringLiteral("清空 NIDS 告警和检测窗口"));

    m_nidsStatusLabel = new QLabel(m_nidsPage);
    m_nidsStatusLabel->setWordWrap(true);
    m_nidsStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    m_nidsControlLayout->addWidget(m_nidsEnableCheck);
    m_nidsControlLayout->addWidget(severityFilterLabel);
    m_nidsControlLayout->addWidget(m_nidsSeverityFilterCombo);
    m_nidsControlLayout->addWidget(m_nidsClearButton);
    m_nidsControlLayout->addWidget(m_nidsStatusLabel, 1);
    m_nidsLayout->addLayout(m_nidsControlLayout);

    m_nidsAlertTable = new ks::ui::VisibleTableWidget(m_nidsPage);
    m_nidsAlertTable->setColumnCount(toNidsAlertColumn(NidsAlertTableColumn::Count));
    m_nidsAlertTable->setHorizontalHeaderLabels({
        QStringLiteral("时间"),
        QStringLiteral("等级"),
        QStringLiteral("分类"),
        QStringLiteral("规则"),
        QStringLiteral("协议"),
        QStringLiteral("方向"),
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("本地端点"),
        QStringLiteral("远端端点"),
        QStringLiteral("详情")
        });
    m_nidsAlertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_nidsAlertTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_nidsAlertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_nidsAlertTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_nidsAlertTable->verticalHeader()->setVisible(false);
    m_nidsAlertTable->horizontalHeader()->setStretchLastSection(true);
    m_nidsAlertTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_nidsLayout->addWidget(m_nidsAlertTable, 1);

    connect(m_nidsAlertTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
    {
        // 右键菜单：
        // - 输入：用户在 NIDS 告警表中的点击位置；
        // - 处理：定位当前行，提供关联报文详情，以及单元格/当前行/多选行复制；
        // - 返回：无，菜单只查看和复制审计证据，不修改规则或连接。
        // 唯一性说明：本表的右键菜单只在这里注册。initializeConnections() 曾重复注册过一份
        // “详情类”菜单，两个槽各自 exec() 会让一次右键先后弹出两个内容不同的菜单。
        if (m_nidsAlertTable == nullptr)
        {
            return;
        }

        const QModelIndex clickedIndex = m_nidsAlertTable->indexAt(localPosition);
        if (clickedIndex.isValid())
        {
            m_nidsAlertTable->setCurrentCell(clickedIndex.row(), clickedIndex.column());
        }

        QMenu menu(m_nidsAlertTable);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        // 关联报文详情：告警行在时间列的 UserRole 里记录了触发它的报文序号。
        std::uint64_t relatedPacketSequenceId = 0;
        const bool hasRelatedPacket = nidsAlertSequenceForRow(
            m_nidsAlertTable,
            m_nidsAlertTable->currentRow(),
            toNidsAlertColumn(NidsAlertTableColumn::Time),
            relatedPacketSequenceId);
        QAction* viewPacketDetailAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QStringLiteral("查看关联报文详情"));
        viewPacketDetailAction->setEnabled(hasRelatedPacket);
        menu.addSeparator();
        QAction* copyCellAction = menu.addAction(QIcon(QStringLiteral(":/Icon/log_copy.svg")), QStringLiteral("复制单元格"));
        QAction* copyRowAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制当前行"));
        QAction* copySelectedRowsAction = menu.addAction(QIcon(QStringLiteral(":/Icon/log_clipboard.svg")), QStringLiteral("复制选中行"));
        const int currentRow = m_nidsAlertTable->currentRow();
        const QTableWidgetItem* processIdItem = currentRow >= 0
            ? m_nidsAlertTable->item(currentRow, toNidsAlertColumn(NidsAlertTableColumn::Pid))
            : nullptr;
        std::uint32_t processId = 0;
        const bool hasProcessId = processIdItem != nullptr &&
            ks::online_scan::tryParsePidFromText(processIdItem->text(), &processId) &&
            processId != 0U;
        QAction* openProcessDetailAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QStringLiteral("转到进程详细信息"));
        openProcessDetailAction->setEnabled(hasProcessId);
        QAction* addBlockRuleAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
            QStringLiteral("预填阻断规则"));
        addBlockRuleAction->setEnabled(hasRelatedPacket && m_firewallPage != nullptr);
        menu.addSeparator();
        QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
            &menu,
            this,
            [this]() -> ks::online_scan::SandboxUploadTarget
            {
                // 输入：NIDS 告警表当前行。
                // 处理：读取 PID 列并解析发起进程 EXE 路径。
                // 返回：待上传路径和来源说明；PID 缺失或进程已退出时返回 errorText。
                ks::online_scan::SandboxUploadTarget uploadTarget;
                const int rowIndex = m_nidsAlertTable != nullptr ? m_nidsAlertTable->currentRow() : -1;
                const QTableWidgetItem* pidItem =
                    (m_nidsAlertTable != nullptr && rowIndex >= 0)
                    ? m_nidsAlertTable->item(rowIndex, toNidsAlertColumn(NidsAlertTableColumn::Pid))
                    : nullptr;
                std::uint32_t targetPid = 0;
                if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &targetPid))
                {
                    uploadTarget.errorText = QStringLiteral("当前 NIDS 告警没有可解析 PID。");
                    return uploadTarget;
                }

                uploadTarget.filePath = QString::fromStdString(ks::process::QueryProcessPathByPid(targetPid));
                uploadTarget.sourceText = QStringLiteral("NIDS 告警 PID=%1").arg(targetPid);
                return uploadTarget;
            });
        const bool hasCurrentCell = m_nidsAlertTable->currentRow() >= 0 && m_nidsAlertTable->currentColumn() >= 0;
        const bool hasCurrentRow = m_nidsAlertTable->currentRow() >= 0;
        copyCellAction->setEnabled(hasCurrentCell);
        copyRowAction->setEnabled(hasCurrentRow);
        copySelectedRowsAction->setEnabled(!nidsSelectedRows(m_nidsAlertTable).empty());
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(hasCurrentRow);
        }

        const QAction* selectedAction = menu.exec(m_nidsAlertTable->viewport()->mapToGlobal(localPosition));
        if (selectedAction == viewPacketDetailAction)
        {
            openPacketDetailWindowBySequenceId(relatedPacketSequenceId);
        }
        else if (selectedAction == addBlockRuleAction)
        {
            const auto alertIt = std::find_if(
                m_nidsAlertList.cbegin(),
                m_nidsAlertList.cend(),
                [relatedPacketSequenceId](const ks::network::NidsAlert& alertRecord)
                {
                    return alertRecord.sequenceId == relatedPacketSequenceId;
                });
            if (alertIt != m_nidsAlertList.cend() && m_firewallPage != nullptr)
            {
                m_firewallPage->addBlockRuleFromEvidence(
                    QString::fromUtf8(alertIt->remoteAddress.c_str()),
                    QString::number(alertIt->remotePort),
                    toQString(ks::network::PacketProtocolToString(alertIt->protocol)),
                    alertIt->direction == ks::network::PacketDirection::Inbound
                        ? QStringLiteral("Inbound") : QStringLiteral("Outbound"),
                    QStringLiteral("NIDS"),
                    alertIt->processId,
                    alertIt->processCreationTime100ns,
                    QString::fromUtf8(alertIt->processImagePath.c_str()));
            }
        }
        else if (selectedAction == copyCellAction)
        {
            const QTableWidgetItem* item = m_nidsAlertTable->item(
                m_nidsAlertTable->currentRow(),
                m_nidsAlertTable->currentColumn());
            if (item != nullptr && QApplication::clipboard() != nullptr)
            {
                QApplication::clipboard()->setText(item->text());
            }
        }
        else if (selectedAction == copyRowAction)
        {
            copyNidsRowsToClipboard(m_nidsAlertTable, std::vector<int>{ m_nidsAlertTable->currentRow() });
        }
        else if (selectedAction == copySelectedRowsAction)
        {
            copyNidsRowsToClipboard(m_nidsAlertTable, nidsSelectedRows(m_nidsAlertTable));
        }
        else if (selectedAction == openProcessDetailAction)
        {
            ks::ui::OpenProcessDetailByPid(processId);
        }
        else if (selectedAction == uploadVirusTotalAction)
        {
            return;
        }
    });

    updateNidsStatusLabel();
    m_sideTabWidget->addTab(m_nidsPage, QIcon(":/Icon/process_critical.svg"), QStringLiteral("NIDS"));

    kLogEvent initNidsEvent;
    info << initNidsEvent << "[NetworkDock] NIDS 页初始化完成。" << eol;
}

void NetworkDock::processNidsPacket(const ks::network::PacketRecord& packetRecord)
{
    if (m_nidsEnableCheck != nullptr && !m_nidsEnableCheck->isChecked())
    {
        return;
    }

    ++m_nidsAnalyzedPacketCount;

    std::vector<ks::network::NidsAlert> alertList = m_nidsEngine.AnalyzePacket(packetRecord);
    if (alertList.empty())
    {
        if ((m_nidsAnalyzedPacketCount % 256) == 0)
        {
            updateNidsStatusLabel();
        }
        return;
    }

    bool trimmed = false;
    for (ks::network::NidsAlert& alertRecord : alertList)
    {
        captureNidsProcessIdentity(alertRecord);
        m_nidsAlertList.push_back(alertRecord);
        ++m_nidsTotalAlertCount;
        while (m_nidsAlertList.size() > kMaxNidsAlertCount)
        {
            m_nidsAlertList.pop_front();
            trimmed = true;
        }

        if (!trimmed && nidsAlertPassesFilter(alertRecord))
        {
            appendNidsAlertRow(alertRecord);
        }

        kLogEvent nidsAlertEvent;
        warn << nidsAlertEvent
            << "[NetworkDock] NIDS 告警, severity="
            << ks::network::NidsAlertSeverityToString(alertRecord.severity)
            << ", rule=" << alertRecord.ruleId
            << ", pid=" << alertRecord.processId
            << ", detail=" << alertRecord.detail
            << eol;
    }

    if (trimmed)
    {
        rebuildNidsAlertTable();
    }
    else if (m_nidsAlertTable != nullptr && m_nidsAlertTable->rowCount() > 0)
    {
        m_nidsAlertTable->scrollToBottom();
    }

    updateNidsStatusLabel();
}

void NetworkDock::appendNidsAlertRow(const ks::network::NidsAlert& alertRecord)
{
    if (m_nidsAlertTable == nullptr)
    {
        return;
    }

    const int newRow = m_nidsAlertTable->rowCount();
    m_nidsAlertTable->setRowCount(newRow + 1);

    const QString timeText = toQString(ks::network::FormatUnixTimestampMs(alertRecord.timestampMs, false));
    const QString severityText = nidsSeverityText(alertRecord.severity);
    const QString protocolText = toQString(ks::network::PacketProtocolToString(alertRecord.protocol));
    const QString directionText = toQString(ks::network::PacketDirectionToString(alertRecord.direction));
    const QString pidText = QString::number(alertRecord.processId);
    const QString processNameText = toQString(alertRecord.processName);
    const QString localEndpointText = formatEndpointText(alertRecord.localAddress, alertRecord.localPort);
    const QString remoteEndpointText = formatEndpointText(alertRecord.remoteAddress, alertRecord.remotePort);
    const QString detailText = QStringLiteral("%1：%2")
        .arg(toQString(alertRecord.title))
        .arg(toQString(alertRecord.detail));

    QTableWidgetItem* timeItem = createNidsCell(timeText);
    timeItem->setData(Qt::UserRole, static_cast<qulonglong>(alertRecord.sequenceId));
    m_nidsAlertTable->setItem(newRow, toNidsAlertColumn(NidsAlertTableColumn::Time), timeItem);

    QTableWidgetItem* severityItem = createNidsCell(severityText);
    severityItem->setForeground(QBrush(nidsSeverityColor(alertRecord.severity)));
    severityItem->setData(Qt::UserRole, nidsSeverityIndex(alertRecord.severity));
    m_nidsAlertTable->setItem(newRow, toNidsAlertColumn(NidsAlertTableColumn::Severity), severityItem);

    m_nidsAlertTable->setItem(newRow, toNidsAlertColumn(NidsAlertTableColumn::Category), createNidsCell(toQString(alertRecord.category)));
    m_nidsAlertTable->setItem(newRow, toNidsAlertColumn(NidsAlertTableColumn::Rule), createNidsCell(toQString(alertRecord.ruleId)));
    m_nidsAlertTable->setItem(newRow, toNidsAlertColumn(NidsAlertTableColumn::Protocol), createNidsCell(protocolText));
    m_nidsAlertTable->setItem(newRow, toNidsAlertColumn(NidsAlertTableColumn::Direction), createNidsCell(directionText));
    m_nidsAlertTable->setItem(newRow, toNidsAlertColumn(NidsAlertTableColumn::Pid), createNidsCell(pidText));

    QTableWidgetItem* processNameItem = createNidsCell(processNameText);
    processNameItem->setIcon(resolveProcessIconByPid(alertRecord.processId, alertRecord.processName));
    m_nidsAlertTable->setItem(newRow, toNidsAlertColumn(NidsAlertTableColumn::ProcessName), processNameItem);

    m_nidsAlertTable->setItem(newRow, toNidsAlertColumn(NidsAlertTableColumn::LocalEndpoint), createNidsCell(localEndpointText));
    m_nidsAlertTable->setItem(newRow, toNidsAlertColumn(NidsAlertTableColumn::RemoteEndpoint), createNidsCell(remoteEndpointText));
    m_nidsAlertTable->setItem(newRow, toNidsAlertColumn(NidsAlertTableColumn::Detail), createNidsCell(detailText));
}

void NetworkDock::rebuildNidsAlertTable()
{
    if (m_nidsAlertTable == nullptr)
    {
        return;
    }

    const QPointer<NetworkDock> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-nids-filter-rebuild"),
        {m_nidsAlertTable},
        [safeThis]()
        {
            if (!safeThis.isNull())
            {
                safeThis->rebuildNidsAlertTable();
            }
        }))
    {
        return;
    }

    m_nidsAlertTable->setUpdatesEnabled(false);
    m_nidsAlertTable->setRowCount(0);
    for (const ks::network::NidsAlert& alertRecord : m_nidsAlertList)
    {
        if (!nidsAlertPassesFilter(alertRecord))
        {
            continue;
        }
        appendNidsAlertRow(alertRecord);
    }
    m_nidsAlertTable->setUpdatesEnabled(true);
    if (m_nidsAlertTable->rowCount() > 0)
    {
        m_nidsAlertTable->scrollToBottom();
    }
}

void NetworkDock::clearNidsAlerts()
{
    const QPointer<NetworkDock> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-nids-clear"),
        {m_nidsAlertTable},
        [safeThis]()
        {
            if (!safeThis.isNull())
            {
                safeThis->clearNidsAlerts();
            }
        }))
    {
        return;
    }

    m_nidsEngine.Reset();
    m_nidsAlertList.clear();
    m_nidsAnalyzedPacketCount = 0;
    m_nidsTotalAlertCount = 0;
    if (m_nidsAlertTable != nullptr)
    {
        m_nidsAlertTable->setRowCount(0);
    }
    updateNidsStatusLabel();

    kLogEvent clearNidsEvent;
    info << clearNidsEvent << "[NetworkDock] NIDS 告警与检测窗口已清空。" << eol;
}

void NetworkDock::updateNidsStatusLabel()
{
    if (m_nidsStatusLabel == nullptr)
    {
        return;
    }

    std::size_t lowCount = 0;
    std::size_t mediumCount = 0;
    std::size_t highCount = 0;
    std::size_t criticalCount = 0;
    for (const ks::network::NidsAlert& alertRecord : m_nidsAlertList)
    {
        switch (alertRecord.severity)
        {
        case ks::network::NidsAlertSeverity::Low:
            ++lowCount;
            break;
        case ks::network::NidsAlertSeverity::Medium:
            ++mediumCount;
            break;
        case ks::network::NidsAlertSeverity::High:
            ++highCount;
            break;
        case ks::network::NidsAlertSeverity::Critical:
            ++criticalCount;
            break;
        default:
            break;
        }
    }

    const bool enabled = (m_nidsEnableCheck == nullptr || m_nidsEnableCheck->isChecked());
    m_nidsStatusLabel->setText(QStringLiteral("状态：%1 | 已分析 %2 包 | 告警 %3（低 %4 / 中 %5 / 高 %6 / 严重 %7）")
        .arg(enabled ? QStringLiteral("实时检测中") : QStringLiteral("已暂停"))
        .arg(static_cast<qulonglong>(m_nidsAnalyzedPacketCount))
        .arg(static_cast<qulonglong>(m_nidsAlertList.size()))
        .arg(static_cast<qulonglong>(lowCount))
        .arg(static_cast<qulonglong>(mediumCount))
        .arg(static_cast<qulonglong>(highCount))
        .arg(static_cast<qulonglong>(criticalCount)));
}

bool NetworkDock::nidsAlertPassesFilter(const ks::network::NidsAlert& alertRecord) const
{
    if (m_nidsSeverityFilterCombo == nullptr)
    {
        return true;
    }

    const int minSeverity = m_nidsSeverityFilterCombo->currentData().toInt();
    return nidsSeverityIndex(alertRecord.severity) >= minSeverity;
}
