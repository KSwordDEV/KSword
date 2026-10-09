#include "ProcessDock.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/VisibleTableWidget.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../UI/DetailLayoutHost.h"
#include "../UI/TableColumnAutoFit.h"
#include "../UI/TableInteractionSupport.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QCheckBox>
#include <QClipboard>
#include <QGuiApplication>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSplitter>
#include <QTabWidget>
#include <QSize>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QVBoxLayout>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <sstream>

namespace
{
    enum class CrossViewColumn : int
    {
        Id = 0,
        Object,
        Process,
        Public,
        ActiveOrThreadList,
        Anomaly,
        Confidence,
        Detail,
        Count
    };

    int columnIndex(const CrossViewColumn column)
    {
        // 输入：Cross-View 表格列枚举。
        // 处理：转换为 Qt 表格列索引。
        // 返回：列号。
        return static_cast<int>(column);
    }

    QString hex64(const std::uint64_t value)
    {
        // 输入：地址或 capability 值。
        // 处理：格式化为 0x 前缀大写十六进制。
        // 返回：展示文本。
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString sourceYesNo(const std::uint32_t sourceMask, const std::uint32_t bit)
    {
        // 输入：来源矩阵 sourceMask 和目标 bit。
        // 处理：映射为勾选文本。
        // 返回：是/否。
        return (sourceMask & bit) ? QStringLiteral("是") : QStringLiteral("-");
    }

    QString anomalyText(const std::uint32_t flags)
    {
        // 输入：KSWORD_ARK_CROSSVIEW_ANOMALY_* 位集合。
        // 处理：转换为短标签，便于 ProcessDock/MonitorDock 使用一致语义。
        // 返回：异常文本；无异常返回“正常”。
        if (flags == 0U)
        {
            return QStringLiteral("正常");
        }
        QStringList parts;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY) parts << QStringLiteral("仅单源");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY) parts << QStringLiteral("Active-only");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST) parts << QStringLiteral("缺活跃源");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE) parts << QStringLiteral("缺辅助源");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN) parts << QStringLiteral("孤儿线程");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST) parts << QStringLiteral("线程进程缺失");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE) parts << QStringLiteral("入口出模块");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT) parts << QStringLiteral("悬空对象");
        return parts.join(QStringLiteral(" | "));
    }

    // friendlyDriverDetail：
    // - 输入 rawDetail：R0 返回的原始 detail 字段；
    // - 处理：把常见协议/IO 字符串转换成人类可读说明；
    // - 返回：表格末列可直接展示的短说明。
    QString friendlyDriverDetail(const QString& rawDetail)
    {
        const QString trimmedText = rawDetail.trimmed();
        if (trimmedText.isEmpty())
        {
            return QStringLiteral("驱动未返回额外说明");
        }
        if (trimmedText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动调用失败或协议版本不匹配");
        }
        if (trimmedText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            trimmedText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动不支持该 cross-view 查询");
        }
        if (trimmedText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            trimmedText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return QStringLiteral("动态偏移能力未完全满足，请查看详情区的 capability/DynData 信息");
        }
        return trimmedText.left(180);
    }

    // crossViewTableDetail：
    // - 输入 isThread/sourceMask/anomalyFlags/confidence/rawDetail：当前 cross-view 行关键信息；
    // - 处理：生成表格末列摘要，避免直接把原始 R0 字符串塞进表格；
    // - 返回：一行中文说明，原始 detail 仍在详情区完整展示。
    QString crossViewTableDetail(
        const bool isThread,
        const std::uint32_t sourceMask,
        const std::uint32_t anomalyFlags,
        const std::uint32_t confidence,
        const QString& rawDetail)
    {
        const std::uint32_t listBit = isThread
            ? KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST
            : KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST;
        const QString objectKindText = isThread ? QStringLiteral("线程") : QStringLiteral("进程");
        const QString sourceText = QStringLiteral("PublicWalk=%1，%2=%3")
            .arg(sourceYesNo(sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK))
            .arg(isThread ? QStringLiteral("ThreadList") : QStringLiteral("ActiveList"))
            .arg(sourceYesNo(sourceMask, listBit));
        const QString anomalySummaryText = anomalyFlags == 0U
            ? QStringLiteral("未发现 cross-view 异常")
            : QStringLiteral("异常：%1").arg(anomalyText(anomalyFlags));

        return QStringLiteral("%1；%2；%3；置信度 %4；%5")
            .arg(objectKindText)
            .arg(sourceText)
            .arg(anomalySummaryText)
            .arg(confidence)
            .arg(friendlyDriverDetail(rawDetail));
    }

    QString narrowToQString(const std::string& value)
    {
        // 输入：ArkDriverClient 的窄字符串。
        // 处理：按 UTF-8 转换，失败场景 Qt 会保留可显示替代字符。
        // 返回：QString。
        return QString::fromStdString(value);
    }

    class NumericItem final : public QTableWidgetItem
    {
    public:
        NumericItem(const QString& text, const qulonglong value)
            : QTableWidgetItem(text)
        {
            // 输入：显示文本和排序数值。
            // 处理：数值写入 UserRole，保留文本原样。
            // 返回：构造函数无返回值。
            setData(Qt::UserRole, QVariant::fromValue<qulonglong>(value));
            setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        }

        bool operator<(const QTableWidgetItem& other) const override
        {
            // 输入：另一单元格。
            // 处理：优先按 UserRole 数值排序。
            // 返回：true 表示当前项更小。
            bool leftOk = false;
            bool rightOk = false;
            const qulonglong leftValue = data(Qt::UserRole).toULongLong(&leftOk);
            const qulonglong rightValue = other.data(Qt::UserRole).toULongLong(&rightOk);
            if (leftOk && rightOk)
            {
                return leftValue < rightValue;
            }
            return QTableWidgetItem::operator<(other);
        }
    };

    QTableWidgetItem* textItem(const QString& value)
    {
        // 输入：展示文本。
        // 处理：创建只读单元格项。
        // 返回：交给 QTableWidget 接管生命周期的 item。
        QTableWidgetItem* item = new QTableWidgetItem(value);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QTableWidgetItem* numericItem(const QString& text, const qulonglong value)
    {
        // 输入：展示文本和排序数值。
        // 处理：创建可数值排序单元格。
        // 返回：交给 QTableWidget 接管生命周期的 item。
        return new NumericItem(text, value);
    }

    QString crossViewTableCellText(QTableWidget* table, const int rowIndex, const int columnIndex)
    {
        // crossViewTableCellText：
        // - 输入：Cross-View 表格、行号、列号；
        // - 处理：安全读取单元格文本；
        // - 返回：单元格不存在时返回空字符串。
        if (table == nullptr)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
        return item != nullptr ? item->text() : QString();
    }

    QString crossViewEmptyStateDetail(
        const QString& titleText,
        const bool ioOk,
        const bool unsupported,
        const std::size_t cacheCount,
        const std::uint32_t returnedCount,
        const std::uint32_t totalCount,
        const std::uint64_t missingCapabilityMask,
        const QString& rawMessageText)
    {
        // crossViewEmptyStateDetail：
        // - 输入：单个 cross-view wrapper 的 IO 状态、计数和原始消息；
        // - 处理：生成表格空状态诊断行的完整说明；
        // - 返回：可放入详情区或表格末列的人读文本。
        if (cacheCount > 0U)
        {
            return QStringLiteral("%1：当前过滤条件隐藏了全部 %2 条缓存记录；请清空过滤或关闭“仅异常”。")
                .arg(titleText)
                .arg(static_cast<qulonglong>(cacheCount));
        }

        QString stateText;
        if (ioOk)
        {
            stateText = QStringLiteral("驱动接口可用，但本次没有返回结构化行");
        }
        else if (unsupported)
        {
            stateText = QStringLiteral("当前驱动/协议暂不支持该 Cross-View 查询");
        }
        else
        {
            stateText = QStringLiteral("驱动查询暂不可用");
        }

        return QStringLiteral("%1：%2；驱动报告 %3/%4 行；missingCapability=%5；说明=%6")
            .arg(titleText)
            .arg(stateText)
            .arg(returnedCount)
            .arg(totalCount)
            .arg(hex64(missingCapabilityMask))
            .arg(friendlyDriverDetail(rawMessageText));
    }

    void setCrossViewDiagnosticRow(
        QTableWidget* table,
        const QString& idText,
        const QString& anomalyText,
        const QString& detailText)
    {
        // setCrossViewDiagnosticRow：
        // - 输入：目标表格、首列提示、异常列提示和详情文本；
        // - 处理：写入一行不可编辑诊断，UserRole+2 保存完整详情；
        // - 返回：无。用于避免 R0 空结果/过滤空结果导致表格完全空白。
        if (table == nullptr)
        {
            return;
        }

        table->setRowCount(1);
        QTableWidgetItem* idItem = textItem(idText);
        idItem->setData(Qt::UserRole + 2, detailText);
        table->setItem(0, columnIndex(CrossViewColumn::Id), idItem);
        table->setItem(0, columnIndex(CrossViewColumn::Object), textItem(QStringLiteral("N/A")));
        table->setItem(0, columnIndex(CrossViewColumn::Process), textItem(QStringLiteral("N/A")));
        table->setItem(0, columnIndex(CrossViewColumn::Public), textItem(QStringLiteral("-")));
        table->setItem(0, columnIndex(CrossViewColumn::ActiveOrThreadList), textItem(QStringLiteral("-")));
        table->setItem(0, columnIndex(CrossViewColumn::Anomaly), textItem(anomalyText));
        table->setItem(0, columnIndex(CrossViewColumn::Confidence), numericItem(QStringLiteral("0"), 0));
        table->setItem(0, columnIndex(CrossViewColumn::Detail), textItem(detailText));
        table->setCurrentCell(0, columnIndex(CrossViewColumn::Id));
    }

    void copyCrossViewCurrentRow(QTableWidget* table)
    {
        // copyCrossViewCurrentRow：
        // - 输入：Process/Thread Cross-View 表；
        // - 处理：复制当前行 TSV；
        // - 返回：无，只写剪贴板，不触发任何 R0 操作。
        if (table == nullptr || QGuiApplication::clipboard() == nullptr)
        {
            return;
        }

        const int rowIndex = table->currentRow();
        if (rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            fields.push_back(crossViewTableCellText(table, rowIndex, columnIndex));
        }
        QGuiApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }

    void installCrossViewContextMenu(
        QTableWidget* table,
        const std::function<quint32(const QTableWidget*, int)>& processIdForRow)
    {
        // installCrossViewContextMenu：
        // - 输入：Cross-View 表；
        // - 处理：安装复制当前行和按表格明确 PID 来源跳转详情的右键菜单；
        // - 返回：无。
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table, processIdForRow](const QPoint& localPosition) {
            const QModelIndex clickedIndex = table->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                table->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            }

            QMenu contextMenu(table);
            contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            const quint32 processId = processIdForRow != nullptr
                ? processIdForRow(table, table->currentRow())
                : 0U;
            QAction* openProcessAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_details.svg")),
                QStringLiteral("转到进程详细信息"));
            openProcessAction->setEnabled(processId != 0U);

            QAction* selectedAction = contextMenu.exec(table->viewport()->mapToGlobal(localPosition));
            if (selectedAction == copyRowAction)
            {
                copyCrossViewCurrentRow(table);
            }
            else if (selectedAction == openProcessAction)
            {
                ks::ui::OpenProcessDetailByPid(processId);
            }
        });
    }

    bool textContainsFilter(const QStringList& fields, const QString& filter)
    {
        // 输入：待匹配字段集合和过滤文本。
        // 处理：大小写不敏感 contains。
        // 返回：true 表示命中过滤。
        if (filter.isEmpty())
        {
            return true;
        }
        for (const QString& field : fields)
        {
            if (field.contains(filter, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    ks::ui::FieldDocument offsetsDocument(const ksword::ark::CrossViewFieldOffsets& offsets)
    {
        // 输入：R0 返回的 DynData offset 快照。
        // 处理：直接生成偏移结构字段。
        // 返回：可复制的偏移说明。
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("DynData Offsets"));
        document.field(QStringLiteral("EPROCESS.UniqueProcessId"), QStringLiteral("0x%1").arg(offsets.epUniqueProcessId, 8, 16, QChar('0')));
        document.field(QStringLiteral("EPROCESS.ActiveProcessLinks"), QStringLiteral("0x%1").arg(offsets.epActiveProcessLinks, 8, 16, QChar('0')));
        document.field(QStringLiteral("EPROCESS.ThreadListHead"), QStringLiteral("0x%1").arg(offsets.epThreadListHead, 8, 16, QChar('0')));
        document.field(QStringLiteral("EPROCESS.ImageFileName"), QStringLiteral("0x%1").arg(offsets.epImageFileName, 8, 16, QChar('0')));
        document.field(QStringLiteral("ETHREAD.ThreadListEntry"), QStringLiteral("0x%1").arg(offsets.etThreadListEntry, 8, 16, QChar('0')));
        document.field(QStringLiteral("ETHREAD.StartAddress"), QStringLiteral("0x%1").arg(offsets.etStartAddress, 8, 16, QChar('0')));
        document.field(QStringLiteral("KTHREAD.Process"), QStringLiteral("0x%1").arg(offsets.ktProcess, 8, 16, QChar('0')));
        return document;
    }
}

void ProcessDock::initializeCrossViewPage()
{
    // 输入：无，由 initializeUi 调用。
    // 处理：创建 Cross-View 页，展示进程和线程来源矩阵。
    // 返回：无。
    m_crossViewPage = new QWidget(this);
    m_crossViewPageLayout = new QVBoxLayout(m_crossViewPage);
    m_crossViewPageLayout->setContentsMargins(6, 6, 6, 6);
    m_crossViewPageLayout->setSpacing(6);

    m_crossViewTopLayout = new QHBoxLayout();
    m_crossViewTopLayout->setContentsMargins(0, 0, 0, 0);
    m_crossViewTopLayout->setSpacing(8);

    m_crossViewRefreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), m_crossViewPage);
    KswordTheme::ApplyStandardIconButtonMetrics(m_crossViewRefreshButton);
    m_crossViewRefreshButton->setToolTip(QStringLiteral("查询 R0 Process/Thread Cross-View 证据"));

    m_crossViewSearchEdit = new QLineEdit(m_crossViewPage);
    m_crossViewSearchEdit->setClearButtonEnabled(true);
    m_crossViewSearchEdit->setPlaceholderText(QStringLiteral("过滤 PID/TID/进程名/异常/详情"));

    m_crossViewAnomalyOnlyCheck = new QCheckBox(QStringLiteral("仅异常"), m_crossViewPage);
    m_crossViewAnomalyOnlyCheck->setChecked(true);

    m_crossViewStatusLabel = new QLabel(QStringLiteral("状态：等待刷新"), m_crossViewPage);
    m_crossViewStatusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_crossViewStatusLabel->setStyleSheet(QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::TextSecondaryHex()));

    m_crossViewTopLayout->addWidget(m_crossViewRefreshButton);
    m_crossViewTopLayout->addWidget(m_crossViewAnomalyOnlyCheck);
    m_crossViewTopLayout->addWidget(m_crossViewSearchEdit, 1);
    m_crossViewTopLayout->addWidget(m_crossViewStatusLabel);
    m_crossViewPageLayout->addLayout(m_crossViewTopLayout);

    QSplitter* splitter = new QSplitter(Qt::Vertical, m_crossViewPage);
    m_crossViewPageLayout->addWidget(splitter, 1);

    QTabWidget* innerTabs = new QTabWidget(splitter);
    m_processCrossViewTable = new ks::ui::VisibleTableWidget(innerTabs);
    m_threadCrossViewTable = new ks::ui::VisibleTableWidget(innerTabs);
    for (QTableWidget* table : { m_processCrossViewTable, m_threadCrossViewTable })
    {
        table->setColumnCount(columnIndex(CrossViewColumn::Count));
        table->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("ID"),
            QStringLiteral("对象"),
            QStringLiteral("进程"),
            QStringLiteral("PublicWalk"),
            QStringLiteral("Active/ThreadList"),
            QStringLiteral("异常"),
            QStringLiteral("置信度"),
            QStringLiteral("说明")
            });
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(columnIndex(CrossViewColumn::Detail), QHeaderView::Stretch);
    }
    installCrossViewContextMenu(
        m_processCrossViewTable,
        [](const QTableWidget* table, const int rowIndex)
        {
            const QTableWidgetItem* processIdItem = table != nullptr
                ? table->item(rowIndex, columnIndex(CrossViewColumn::Id))
                : nullptr;
            bool ok = false;
            const qulonglong processId = processIdItem != nullptr
                ? processIdItem->data(Qt::UserRole).toULongLong(&ok)
                : 0ULL;
            return ok && processId <= std::numeric_limits<quint32>::max()
                ? static_cast<quint32>(processId)
                : 0U;
        });
    installCrossViewContextMenu(
        m_threadCrossViewTable,
        [this](const QTableWidget* table, const int rowIndex)
        {
            const QTableWidgetItem* threadIdItem = table != nullptr
                ? table->item(rowIndex, columnIndex(CrossViewColumn::Id))
                : nullptr;
            bool ok = false;
            const qulonglong cacheIndex = threadIdItem != nullptr
                ? threadIdItem->data(Qt::UserRole + 1).toULongLong(&ok)
                : 0ULL;
            if (!ok || cacheIndex >= static_cast<qulonglong>(m_threadCrossViewCache.size()))
            {
                return 0U;
            }
            return static_cast<quint32>(m_threadCrossViewCache[static_cast<std::size_t>(cacheIndex)].processId);
        });
    innerTabs->addTab(m_processCrossViewTable, QStringLiteral("Process Cross-View"));
    innerTabs->addTab(m_threadCrossViewTable, QStringLiteral("Thread Cross-View"));
    ks::i18n::LanguageManager::instance().bindTab(
        innerTabs,
        m_processCrossViewTable,
        QStringLiteral("process.cross_view.process_tab"),
        QStringLiteral("Process Cross-View"));
    ks::i18n::LanguageManager::instance().bindTab(
        innerTabs,
        m_threadCrossViewTable,
        QStringLiteral("process.cross_view.thread_tab"),
        QStringLiteral("Thread Cross-View"));
    splitter->addWidget(innerTabs);

    // Cross-View 详情区直接接受结构字段，保留查找、复制与全部详情布局。
    m_crossViewDetailEdit = new ks::ui::StructuredFieldView(splitter);
    m_crossViewDetailEdit->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("选择一条记录查看进程来源、异常标记和内核详情。")));
    splitter->addWidget(m_crossViewDetailEdit);
    auto* detailHost = ks::ui::DetailLayoutRegistry::registerStructuredHost(
        m_processCrossViewTable, m_crossViewDetailEdit, m_crossViewPage, splitter, innerTabs, m_crossViewDetailEdit);
    const QPointer<ks::ui::DetailLayoutHost> hostGuard(detailHost);
    connect(innerTabs, &QTabWidget::currentChanged, m_crossViewPage, [this, hostGuard](int index) {
        m_crossViewDetailEdit->setProperty("ks_cross_view_thread_selected", index == 1);
        if (!hostGuard.isNull()) hostGuard->setTableView(index == 1 ? m_threadCrossViewTable : m_processCrossViewTable);
        showCrossViewDetailForCurrentRow(index == 1);
    });
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    m_sideTabWidget->addTab(m_crossViewPage, blueTintedIcon(":/Icon/process_tree.svg"), QStringLiteral("Process Cross-View"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget,
        m_crossViewPage,
        QStringLiteral("process.tab.cross_view"),
        QStringLiteral("Process Cross-View"));
}

void ProcessDock::initializeCrossViewConnections()
{
    // 输入：无，由 initializeConnections 调用。
    // 处理：连接刷新、过滤和选择变化。
    // 返回：无。
    connect(m_crossViewRefreshButton, &QPushButton::clicked, this, [this]() {
        refreshCrossViewAsync();
    });
    connect(m_crossViewSearchEdit, &QLineEdit::textChanged, this, [this]() {
        rebuildCrossViewTables();
    });
    connect(m_crossViewAnomalyOnlyCheck, &QCheckBox::toggled, this, [this]() {
        rebuildCrossViewTables();
    });
    connect(m_processCrossViewTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showCrossViewDetailForCurrentRow(false);
    });
    connect(m_threadCrossViewTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showCrossViewDetailForCurrentRow(true);
    });
}

void ProcessDock::refreshCrossViewAsync()
{
    // 输入：用户刷新动作。
    // 处理：后台同时请求进程和线程 cross-view，主线程回填缓存。
    // 返回：无。
    if (m_crossViewRefreshInProgress)
    {
        return;
    }
    m_crossViewRefreshInProgress = true;
    const std::uint64_t ticket = ++m_crossViewRefreshTicket;
    if (m_crossViewRefreshButton != nullptr)
    {
        m_crossViewRefreshButton->setEnabled(false);
    }
    if (m_crossViewStatusLabel != nullptr)
    {
        m_crossViewStatusLabel->setText(QStringLiteral("状态：查询中..."));
        m_crossViewStatusLabel->setStyleSheet(QStringLiteral("color:%1; font-weight:700;").arg(KswordTheme::PrimaryBlueHex));
    }

    QPointer<ProcessDock> guardThis(this);
    QRunnable* task = QRunnable::create([guardThis, ticket]() {
        const ksword::ark::DriverClient client;
        ksword::ark::ProcessCrossViewResult processResult = client.queryProcessCrossView();
        ksword::ark::ThreadCrossViewResult threadResult = client.queryThreadCrossView();

        QMetaObject::invokeMethod(qApp, [guardThis, ticket, processResult = std::move(processResult), threadResult = std::move(threadResult)]() mutable {
            if (guardThis == nullptr || guardThis->m_crossViewRefreshTicket != ticket)
            {
                return;
            }
            auto applySnapshot = [
                guardThis,
                ticket,
                processSnapshot = std::move(processResult),
                threadSnapshot = std::move(threadResult)]() mutable
            {
                if (guardThis == nullptr || guardThis->m_crossViewRefreshTicket != ticket)
                {
                    return;
                }

                guardThis->m_crossViewRefreshInProgress = false;
                if (guardThis->m_crossViewRefreshButton != nullptr)
                {
                    guardThis->m_crossViewRefreshButton->setEnabled(true);
                }

                guardThis->m_lastProcessCrossViewResult = processSnapshot;
                guardThis->m_lastThreadCrossViewResult = threadSnapshot;
                guardThis->m_processCrossViewCache = processSnapshot.entries;
                guardThis->m_threadCrossViewCache = threadSnapshot.entries;
                guardThis->rebuildCrossViewTables();

                QString statusText;
                if (!processSnapshot.io.ok || !threadSnapshot.io.ok)
                {
                    // 将底层 IO 诊断转换为用户可读说明：
                    // - 输入：ArkDriverClient 的 unsupported 标记和 io.message；
                    // - 处理：保留“未集成/驱动过旧”的明确语义，其余交给 friendlyDriverDetail 归一化；
                    // - 返回：状态栏短文本，不直接暴露 DeviceIoControl 等底层字符串。
                    const QString processMessageText = processSnapshot.unsupported
                        ? QStringLiteral("进程未集成/驱动过旧")
                        : friendlyDriverDetail(narrowToQString(processSnapshot.io.message));
                    const QString threadMessageText = threadSnapshot.unsupported
                        ? QStringLiteral("线程未集成/驱动过旧")
                        : friendlyDriverDetail(narrowToQString(threadSnapshot.io.message));
                    statusText = QStringLiteral("状态：%1 / %2")
                        .arg(processMessageText)
                        .arg(threadMessageText);
                    guardThis->m_crossViewStatusLabel->setStyleSheet(
                        QStringLiteral("color:%1; font-weight:700;")
                            .arg(KswordTheme::ErrorColor().name(QColor::HexRgb)));
                }
                else
                {
                    statusText = QStringLiteral("状态：进程 %1/%2，线程 %3/%4，missingCaps=0x%5/0x%6")
                        .arg(processSnapshot.entries.size())
                        .arg(processSnapshot.totalCount)
                        .arg(threadSnapshot.entries.size())
                        .arg(threadSnapshot.totalCount)
                        .arg(static_cast<qulonglong>(processSnapshot.missingCapabilityMask), 0, 16)
                        .arg(static_cast<qulonglong>(threadSnapshot.missingCapabilityMask), 0, 16);
                    guardThis->m_crossViewStatusLabel->setStyleSheet(
                        QStringLiteral("color:%1; font-weight:700;")
                            .arg(KswordTheme::SuccessColor().name(QColor::HexRgb)));
                }
                guardThis->m_crossViewStatusLabel->setText(statusText);
                guardThis->showCrossViewDetailForCurrentRow(guardThis->m_crossViewDetailEdit != nullptr
                    && guardThis->m_crossViewDetailEdit->property("ks_cross_view_thread_selected").toBool());
            };

            if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                    guardThis.data(),
                    QStringLiteral("process-cross-view-snapshot-apply"),
                    {guardThis->m_processCrossViewTable, guardThis->m_threadCrossViewTable},
                    applySnapshot))
            {
                return;
            }
            applySnapshot();
        }, Qt::QueuedConnection);
    });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void ProcessDock::rebuildCrossViewTables()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_crossViewDetailEdit);
    const QPointer<ProcessDock> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("process-cross-view-tables-rebuild"),
        {m_processCrossViewTable, m_threadCrossViewTable},
        [safeThis]()
        {
            if (!safeThis.isNull())
            {
                safeThis->rebuildCrossViewTables();
            }
        }))
    {
        return;
    }

    // 输入：无，读取 cross-view 缓存和过滤控件。
    // 处理：分别重绘进程/线程来源矩阵。
    // 返回：无。
    const QString filter = m_crossViewSearchEdit != nullptr ? m_crossViewSearchEdit->text().trimmed() : QString();
    const bool anomalyOnly = m_crossViewAnomalyOnlyCheck != nullptr && m_crossViewAnomalyOnlyCheck->isChecked();

    if (m_processCrossViewTable != nullptr)
    {
        QSignalBlocker blocker(m_processCrossViewTable);
        m_processCrossViewTable->setSortingEnabled(false);
        std::vector<std::size_t> indexes;
        for (std::size_t index = 0; index < m_processCrossViewCache.size(); ++index)
        {
            const auto& row = m_processCrossViewCache[index];
            if (anomalyOnly && row.anomalyFlags == 0U)
            {
                continue;
            }
            if (!textContainsFilter({
                QString::number(row.processId),
                narrowToQString(row.imageName),
                hex64(row.objectAddress),
                anomalyText(row.anomalyFlags),
                narrowToQString(row.detail)
                }, filter))
            {
                continue;
            }
            indexes.push_back(index);
        }
        m_processCrossViewTable->setRowCount(static_cast<int>(indexes.size()));
        for (int tableRow = 0; tableRow < static_cast<int>(indexes.size()); ++tableRow)
        {
            const std::size_t cacheIndex = indexes[static_cast<std::size_t>(tableRow)];
            const auto& row = m_processCrossViewCache[cacheIndex];
            QTableWidgetItem* idItem = numericItem(QString::number(row.processId), row.processId);
            idItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(cacheIndex)));
            m_processCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::Id), idItem);
            m_processCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::Object), numericItem(hex64(row.objectAddress), row.objectAddress));
            m_processCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::Process), textItem(narrowToQString(row.imageName)));
            m_processCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::Public), textItem(sourceYesNo(row.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK)));
            m_processCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::ActiveOrThreadList), textItem(sourceYesNo(row.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST)));
            m_processCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::Anomaly), textItem(anomalyText(row.anomalyFlags)));
            m_processCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::Confidence), numericItem(QString::number(row.confidence), row.confidence));
            m_processCrossViewTable->setItem(
                tableRow,
                columnIndex(CrossViewColumn::Detail),
                textItem(crossViewTableDetail(false, row.sourceMask, row.anomalyFlags, row.confidence, narrowToQString(row.detail))));
        }
        if (m_processCrossViewTable->rowCount() > 0 && m_processCrossViewTable->currentRow() < 0)
        {
            m_processCrossViewTable->setCurrentCell(0, columnIndex(CrossViewColumn::Id));
        }
        if (m_processCrossViewTable->rowCount() == 0)
        {
            const QString detailText = crossViewEmptyStateDetail(
                QStringLiteral("进程 Cross-View"),
                m_lastProcessCrossViewResult.io.ok,
                m_lastProcessCrossViewResult.unsupported,
                m_processCrossViewCache.size(),
                m_lastProcessCrossViewResult.returnedCount,
                m_lastProcessCrossViewResult.totalCount,
                m_lastProcessCrossViewResult.missingCapabilityMask,
                narrowToQString(m_lastProcessCrossViewResult.io.message));
            setCrossViewDiagnosticRow(
                m_processCrossViewTable,
                QStringLiteral("<无进程证据>"),
                QStringLiteral("诊断"),
                detailText);
        }
        m_processCrossViewTable->setSortingEnabled(true);
        ks::ui::RequestTableColumnAutoFit(m_processCrossViewTable);
    }

    if (m_threadCrossViewTable != nullptr)
    {
        QSignalBlocker blocker(m_threadCrossViewTable);
        m_threadCrossViewTable->setSortingEnabled(false);
        std::vector<std::size_t> indexes;
        for (std::size_t index = 0; index < m_threadCrossViewCache.size(); ++index)
        {
            const auto& row = m_threadCrossViewCache[index];
            if (anomalyOnly && row.anomalyFlags == 0U)
            {
                continue;
            }
            if (!textContainsFilter({
                QString::number(row.threadId),
                QString::number(row.processId),
                narrowToQString(row.imageName),
                hex64(row.objectAddress),
                anomalyText(row.anomalyFlags),
                narrowToQString(row.detail)
                }, filter))
            {
                continue;
            }
            indexes.push_back(index);
        }
        m_threadCrossViewTable->setRowCount(static_cast<int>(indexes.size()));
        for (int tableRow = 0; tableRow < static_cast<int>(indexes.size()); ++tableRow)
        {
            const std::size_t cacheIndex = indexes[static_cast<std::size_t>(tableRow)];
            const auto& row = m_threadCrossViewCache[cacheIndex];
            QTableWidgetItem* idItem = numericItem(QString::number(row.threadId), row.threadId);
            idItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(cacheIndex)));
            m_threadCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::Id), idItem);
            m_threadCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::Object), numericItem(hex64(row.objectAddress), row.objectAddress));
            m_threadCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::Process), textItem(QStringLiteral("%1 %2").arg(row.processId).arg(narrowToQString(row.imageName))));
            m_threadCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::Public), textItem(sourceYesNo(row.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK)));
            m_threadCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::ActiveOrThreadList), textItem(sourceYesNo(row.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST)));
            m_threadCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::Anomaly), textItem(anomalyText(row.anomalyFlags)));
            m_threadCrossViewTable->setItem(tableRow, columnIndex(CrossViewColumn::Confidence), numericItem(QString::number(row.confidence), row.confidence));
            m_threadCrossViewTable->setItem(
                tableRow,
                columnIndex(CrossViewColumn::Detail),
                textItem(crossViewTableDetail(true, row.sourceMask, row.anomalyFlags, row.confidence, narrowToQString(row.detail))));
        }
        if (m_threadCrossViewTable->rowCount() > 0 && m_threadCrossViewTable->currentRow() < 0)
        {
            m_threadCrossViewTable->setCurrentCell(0, columnIndex(CrossViewColumn::Id));
        }
        if (m_threadCrossViewTable->rowCount() == 0)
        {
            const QString detailText = crossViewEmptyStateDetail(
                QStringLiteral("线程 Cross-View"),
                m_lastThreadCrossViewResult.io.ok,
                m_lastThreadCrossViewResult.unsupported,
                m_threadCrossViewCache.size(),
                m_lastThreadCrossViewResult.returnedCount,
                m_lastThreadCrossViewResult.totalCount,
                m_lastThreadCrossViewResult.missingCapabilityMask,
                narrowToQString(m_lastThreadCrossViewResult.io.message));
            setCrossViewDiagnosticRow(
                m_threadCrossViewTable,
                QStringLiteral("<无线程证据>"),
                QStringLiteral("诊断"),
                detailText);
        }
        m_threadCrossViewTable->setSortingEnabled(true);
        ks::ui::RequestTableColumnAutoFit(m_threadCrossViewTable);
    }
}

void ProcessDock::showCrossViewDetailForCurrentRow(const bool preferThreadTable)
{
    // 输入：preferThreadTable 指示优先读取线程表还是进程表。
    // 处理：展开当前行 source/anomaly/DynData 细节到只读文本框。
    // 返回：无。
    if (m_crossViewDetailEdit == nullptr)
    {
        return;
    }

    if (preferThreadTable && m_threadCrossViewTable != nullptr && m_threadCrossViewTable->currentRow() >= 0)
    {
        const QTableWidgetItem* item = m_threadCrossViewTable->item(m_threadCrossViewTable->currentRow(), columnIndex(CrossViewColumn::Id));
        const QString diagnosticText = item != nullptr
            ? item->data(Qt::UserRole + 2).toString()
            : QString();
        if (!diagnosticText.isEmpty())
        {
            m_crossViewDetailEdit->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("线程 Cross-View 诊断\n%1").arg(diagnosticText)));
            return;
        }

        bool ok = false;
        const qulonglong cacheIndex = item != nullptr ? item->data(Qt::UserRole + 1).toULongLong(&ok) : 0ULL;
        if (ok && cacheIndex < static_cast<qulonglong>(m_threadCrossViewCache.size()))
        {
            const auto& row = m_threadCrossViewCache[static_cast<std::size_t>(cacheIndex)];
            const QString rawDetailText = narrowToQString(row.detail);
            const QString readableDetailText = friendlyDriverDetail(rawDetailText);
            ks::ui::FieldDocument document;
            document.section(QStringLiteral("线程 Cross-View 详情"));
            document.field(QStringLiteral("TID"), QString::number(row.threadId));
            document.field(QStringLiteral("PID"), QString::number(row.processId));
            document.field(QStringLiteral("Image"), narrowToQString(row.imageName));
            document.field(QStringLiteral("ThreadObject"), hex64(row.objectAddress));
            document.field(QStringLiteral("ProcessObject"), hex64(row.processObjectAddress));
            document.field(QStringLiteral("StartAddress"), hex64(row.startAddress));
            document.field(QStringLiteral("SourceMask"), QStringLiteral("0x%1").arg(row.sourceMask, 8, 16, QChar('0')));
            document.field(QStringLiteral("AnomalyFlags"), QStringLiteral("%1 (0x%2)").arg(anomalyText(row.anomalyFlags)).arg(row.anomalyFlags, 8, 16, QChar('0')), true);
            document.field(QStringLiteral("DynDataCapabilityMask"), hex64(row.dynDataCapabilityMask));
            document.nodes += offsetsDocument(row.fieldOffsets).nodes;
            document.section(QStringLiteral("诊断"));
            document.field(QStringLiteral("LastStatus"), QStringLiteral("0x%1").arg(static_cast<qulonglong>(static_cast<unsigned long>(row.lastStatus)), 8, 16, QChar('0')));
            document.field(QStringLiteral("Confidence"), QString::number(row.confidence));
            document.field(QStringLiteral("驱动说明"), readableDetailText, true);
            document.field(QStringLiteral("驱动原始说明"), rawDetailText);
            m_crossViewDetailEdit->setDocument(document);
            return;
        }
    }

    if (preferThreadTable)
    { m_crossViewDetailEdit->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请选择一条 Cross-View 记录查看详情。"))); return; }
    if (m_processCrossViewTable != nullptr && m_processCrossViewTable->currentRow() >= 0)
    {
        const QTableWidgetItem* item = m_processCrossViewTable->item(m_processCrossViewTable->currentRow(), columnIndex(CrossViewColumn::Id));
        const QString diagnosticText = item != nullptr
            ? item->data(Qt::UserRole + 2).toString()
            : QString();
        if (!diagnosticText.isEmpty())
        {
            m_crossViewDetailEdit->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("进程 Cross-View 诊断\n%1").arg(diagnosticText)));
            return;
        }

        bool ok = false;
        const qulonglong cacheIndex = item != nullptr ? item->data(Qt::UserRole + 1).toULongLong(&ok) : 0ULL;
        if (ok && cacheIndex < static_cast<qulonglong>(m_processCrossViewCache.size()))
        {
            const auto& row = m_processCrossViewCache[static_cast<std::size_t>(cacheIndex)];
            const QString rawDetailText = narrowToQString(row.detail);
            const QString readableDetailText = friendlyDriverDetail(rawDetailText);
            ks::ui::FieldDocument document;
            document.section(QStringLiteral("进程 Cross-View 详情"));
            document.field(QStringLiteral("PID"), QString::number(row.processId));
            document.field(QStringLiteral("PPID"), QString::number(row.parentProcessId));
            document.field(QStringLiteral("Image"), narrowToQString(row.imageName));
            document.field(QStringLiteral("ProcessObject"), hex64(row.objectAddress));
            document.field(QStringLiteral("StartAddress"), hex64(row.startAddress));
            document.field(QStringLiteral("SourceMask"), QStringLiteral("0x%1").arg(row.sourceMask, 8, 16, QChar('0')));
            document.field(QStringLiteral("AnomalyFlags"), QStringLiteral("%1 (0x%2)").arg(anomalyText(row.anomalyFlags)).arg(row.anomalyFlags, 8, 16, QChar('0')), true);
            document.field(QStringLiteral("DynDataCapabilityMask"), hex64(row.dynDataCapabilityMask));
            document.nodes += offsetsDocument(row.fieldOffsets).nodes;
            document.section(QStringLiteral("诊断"));
            document.field(QStringLiteral("LastStatus"), QStringLiteral("0x%1").arg(static_cast<qulonglong>(static_cast<unsigned long>(row.lastStatus)), 8, 16, QChar('0')));
            document.field(QStringLiteral("Confidence"), QString::number(row.confidence));
            document.field(QStringLiteral("驱动说明"), readableDetailText, true);
            document.field(QStringLiteral("驱动原始说明"), rawDetailText);
            m_crossViewDetailEdit->setDocument(document);
            return;
        }
    }

    m_crossViewDetailEdit->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请选择一条 Cross-View 记录查看详情。")));
}
