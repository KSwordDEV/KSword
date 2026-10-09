#include "KernelThreadAuditTab.h"
#include "../UI/FlatButtonTheme.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../UI/TableInteractionSupport.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QCoreApplication>
#include <QEvent>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <utility>

namespace
{
    // threadAuditText：
    // - 输入 key：语言包稳定键；fallbackText：中文回退文本；
    // - 处理：统一走 LanguageManager 上下文翻译；
    // - 返回：当前语言下的页面文本。
    QString threadAuditText(const char* key, const QString& fallbackText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), fallbackText);
    }

    constexpr std::uint32_t kWaitReasonQueue = 15U; // KWAIT_REASON::WrQueue。

    // menuStyle：
    // - 返回不透明 QMenu 主题；
    // - 解决浅色模式下透明菜单导致的黑底黑字问题。
    QString menuStyle()
    {
        return QStringLiteral(
            "QMenu{background:%1;color:%2;border:1px solid %3;padding:4px;}"
            "QMenu::item{padding:5px 24px 5px 8px;}"
            "QMenu::item:selected{background:%4;color:%5;}"
            "QMenu::item:disabled{color:%6;}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::OnAccentHex())
            .arg(KswordTheme::TextSecondaryHex());
    }

    // messageBoxStyle：
    // - 为本页危险操作确认框显式设置不透明背景；
    // - 保证浅色和深色主题均可读取风险文本。
    QString messageBoxStyle()
    {
        return QStringLiteral(
            "QMessageBox{background:%1;color:%2;}"
            "QMessageBox QLabel{background:transparent;color:%2;min-width:440px;}"
            "QMessageBox QPushButton{min-width:90px;padding:6px 12px;}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    // showConfirmation：
    // - 输入 parent/title/body：确认框宿主与文本；
    // - 处理：显式主题、Yes/No、默认 No；
    // - 返回：用户明确选择 Yes 时为 true。
    bool showConfirmation(QWidget* parent, const QString& titleText, const QString& bodyText)
    {
        QMessageBox confirmationBox(QMessageBox::Warning, titleText, bodyText, QMessageBox::NoButton, parent);
        confirmationBox.setStyleSheet(messageBoxStyle());
        confirmationBox.setTextFormat(Qt::PlainText);
        QPushButton* yesButton = confirmationBox.addButton(QMessageBox::Yes);
        QPushButton* noButton = confirmationBox.addButton(QMessageBox::No);
        confirmationBox.setDefaultButton(noButton);
        confirmationBox.setEscapeButton(noButton);
        confirmationBox.exec();
        return confirmationBox.clickedButton() == yesButton;
    }

    // showResultMessage：
    // - 输入 success：决定信息或警告图标；
    // - 处理：显示带不透明主题的结果弹窗；
    // - 返回：无。
    void showResultMessage(
        QWidget* parent,
        const bool success,
        const QString& titleText,
        const QString& bodyText)
    {
        QMessageBox resultBox(
            success ? QMessageBox::Information : QMessageBox::Warning,
            titleText,
            bodyText,
            QMessageBox::Ok,
            parent);
        resultBox.setStyleSheet(messageBoxStyle());
        resultBox.setTextFormat(Qt::PlainText);
        resultBox.exec();
    }

}

KernelThreadAuditTab::KernelThreadAuditTab(const Mode mode, QWidget* parent)
    : QWidget(parent),
      m_mode(mode)
{
    initializeUi();
    applyTranslatedText();

    // 首次刷新延后到事件循环，避免 Dock 构造阶段同步查询系统信息。
    QTimer::singleShot(0, this, [this]() {
        requestRefresh();
    });
}

void KernelThreadAuditTab::initializeUi()
{
    // 根布局：工具栏、表格和详情垂直排列。
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    // 工具栏按钮使用图标和 tooltip；工作队列线程页直接展示完整证据列。
    auto* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(4);

    m_refreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), this);
    m_suspendButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_pause.svg")), QString(), this);
    m_resumeButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_resume.svg")), QString(), this);
    m_terminateButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_terminate.svg")), QString(), this);
    for (QPushButton* actionButton : { m_refreshButton, m_suspendButton, m_resumeButton, m_terminateButton })
    {
        KswordTheme::ApplyCompactIconButtonMetrics(actionButton);
    }
    const bool managementVisible = m_mode == Mode::SystemThreads;
    m_suspendButton->setVisible(managementVisible);
    m_resumeButton->setVisible(managementVisible);
    m_terminateButton->setVisible(managementVisible);

    m_overviewButton = new QPushButton(QStringLiteral("A"), this);
    m_evidenceButton = new QPushButton(QStringLiteral("B"), this);
    m_overviewButton->setFixedSize(28, 28);
    m_evidenceButton->setFixedSize(28, 28);
    m_overviewButton->setVisible(m_mode != Mode::WorkQueueThreads);
    m_evidenceButton->setVisible(m_mode != Mode::WorkQueueThreads);

    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setClearButtonEnabled(true);
    m_statusLabel = new QLabel(this);
    m_statusLabel->setStyleSheet(QStringLiteral("QLabel{color:%1;}").arg(KswordTheme::TextSecondaryHex()));

    toolLayout->addWidget(m_refreshButton);
    toolLayout->addSpacing(3);
    toolLayout->addWidget(m_suspendButton);
    toolLayout->addWidget(m_resumeButton);
    toolLayout->addWidget(m_terminateButton);
    toolLayout->addSpacing(7);
    toolLayout->addWidget(m_overviewButton);
    toolLayout->addWidget(m_evidenceButton);
    toolLayout->addWidget(m_filterEdit, 1);
    toolLayout->addWidget(m_statusLabel);
    rootLayout->addLayout(toolLayout);

    // 表格与 ks::ui::StructuredFieldView 由纵向 splitter 组织，详情窗口保持项目统一编辑器。
    auto* splitter = new QSplitter(Qt::Vertical, this);
    m_table = new QTableWidget(splitter);
    m_table->setColumnCount(static_cast<int>(Column::Count));
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);

    m_detailEditor = new ks::ui::StructuredFieldView(splitter);

    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 2);
    rootLayout->addWidget(splitter, 1);

    ks::ui::DetailLayoutRegistry::registerStructuredHost(m_table, m_detailEditor, this);

    // 连接：刷新、筛选、选择、视图预设、表头菜单和行操作菜单。
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { requestRefresh(); });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this]() { rebuildTable(); });
    connect(m_table, &QTableWidget::itemSelectionChanged, this, [this]() { updateDetail(); });
    connect(m_overviewButton, &QPushButton::clicked, this, [this]() {
        applyColumnPreset(ViewPreset::Overview);
    });
    connect(m_evidenceButton, &QPushButton::clicked, this, [this]() {
        applyColumnPreset(ViewPreset::Evidence);
    });
    connect(m_table->horizontalHeader(), &QHeaderView::customContextMenuRequested, this,
        [this](const QPoint& localPosition) { showHeaderMenu(localPosition); });
    connect(m_table, &QTableWidget::customContextMenuRequested, this,
        [this](const QPoint& localPosition) { showRowMenu(localPosition); });
    connect(m_suspendButton, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND);
    });
    connect(m_resumeButton, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME);
    });
    connect(m_terminateButton, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE);
    });

    applyColumnPreset(m_mode == Mode::WorkQueueThreads
        ? ViewPreset::Evidence
        : ViewPreset::Overview);
}

void KernelThreadAuditTab::applyTranslatedText()
{
    // 图标按钮只通过 tooltip 表达动作含义。
    m_refreshButton->setToolTip(threadAuditText("thread_audit.tooltip.refresh", QStringLiteral("刷新线程审计快照")));
    m_suspendButton->setToolTip(threadAuditText("thread_audit.tooltip.suspend", QStringLiteral("挂起选中的系统线程")));
    m_resumeButton->setToolTip(threadAuditText("thread_audit.tooltip.resume", QStringLiteral("恢复选中的系统线程")));
    m_terminateButton->setToolTip(threadAuditText("thread_audit.tooltip.terminate", QStringLiteral("终止选中的系统线程（高风险）")));
    m_overviewButton->setToolTip(threadAuditText("thread_audit.tooltip.view_a", QStringLiteral("A：调度与队列概览")));
    m_evidenceButton->setToolTip(threadAuditText("thread_audit.tooltip.view_b", QStringLiteral("B：入口地址与模块归属证据")));
    m_filterEdit->setPlaceholderText(threadAuditText("thread_audit.filter.placeholder", QStringLiteral("按 TID、状态、队列或模块筛选")));
    m_filterEdit->setToolTip(threadAuditText("thread_audit.filter.tooltip", QStringLiteral("输入关键字后实时过滤当前线程快照")));

    // 表头按固定 Column 顺序翻译；预设只控制可见性，不改变数据列。
    m_table->setHorizontalHeaderLabels(QStringList{
        threadAuditText("thread_audit.header.tid", QStringLiteral("线程ID")),
        threadAuditText("thread_audit.header.ethread", QStringLiteral("EThread")),
        threadAuditText("thread_audit.header.category", QStringLiteral("类别")),
        threadAuditText("thread_audit.header.queue_type", QStringLiteral("队列类型")),
        threadAuditText("thread_audit.header.node_priority", QStringLiteral("Node/Priority")),
        threadAuditText("thread_audit.header.work_queue", QStringLiteral("EX_WORK_QUEUE")),
        threadAuditText("thread_audit.header.state", QStringLiteral("线程状态")),
        threadAuditText("thread_audit.header.wait_reason", QStringLiteral("等待原因")),
        threadAuditText("thread_audit.header.routine", QStringLiteral("例程入口")),
        threadAuditText("thread_audit.header.parameter", QStringLiteral("参数")),
        threadAuditText("thread_audit.header.module", QStringLiteral("入口模块")),
        threadAuditText("thread_audit.header.module_base", QStringLiteral("模块基址")),
        threadAuditText("thread_audit.header.module_path", QStringLiteral("模块路径")),
        threadAuditText("thread_audit.header.r0_status", QStringLiteral("R0状态")),
        threadAuditText("thread_audit.header.protection", QStringLiteral("管理保护"))
    });

    if (m_rows.empty() && !m_refreshRunning)
    {
        m_statusLabel->setText(threadAuditText("thread_audit.status.waiting", QStringLiteral("状态：等待刷新")));
        m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(threadAuditText("thread_audit.detail.initial", QStringLiteral("请选择一条线程记录查看证据与安全边界。"))));
    }
    updatePresetButtons();
}

void KernelThreadAuditTab::requestRefresh()
{
    if (m_refreshRunning)
    {
        return;
    }

    m_refreshRunning = true;
    const std::uint64_t refreshTicket = ++m_refreshTicket;
    m_refreshButton->setEnabled(false);
    m_statusLabel->setText(threadAuditText("thread_audit.status.refreshing", QStringLiteral("状态：正在采集线程与模块证据...")));

    // 后台只构造值类型 Snapshot；UI 控件仅在主线程回调中访问。
    QPointer<KernelThreadAuditTab> guardThis(this);
    const Mode requestedMode = m_mode;
    QThreadPool::globalInstance()->start([guardThis, refreshTicket, requestedMode]() {
        auto snapshot = std::make_shared<Snapshot>(collectSnapshot(requestedMode));
        QMetaObject::invokeMethod(
            QCoreApplication::instance(),
            [guardThis, refreshTicket, snapshot]() {
                if (guardThis == nullptr || refreshTicket != guardThis->m_refreshTicket)
                {
                    return;
                }
                guardThis->applySnapshot(*snapshot);
            },
            Qt::QueuedConnection);
    });
}

void KernelThreadAuditTab::applySnapshot(const Snapshot& snapshot)
{
    const QPointer<KernelThreadAuditTab> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-thread-audit-snapshot"),
        { m_table },
        [safeThis, snapshot]()
        {
            if (!safeThis.isNull())
            {
                safeThis->applySnapshot(snapshot);
            }
        }))
    {
        return;
    }

    m_rows = snapshot.rows;
    m_refreshRunning = false;
    m_refreshButton->setEnabled(true);
    rebuildTable();

    const QString diagnosticText = snapshotDiagnosticText(snapshot, m_mode);
    if (m_mode == Mode::WorkQueueThreads)
    {
        m_statusLabel->setText(
            threadAuditText(
                "thread_audit.status.work_queue_completed",
                QStringLiteral("状态：%1 条；队列=%2；节点=%3；查询=%4；%5"))
                .arg(static_cast<qulonglong>(m_rows.size()))
                .arg(snapshot.workQueueQueuesVisited)
                .arg(snapshot.workQueueNodeCount)
                .arg(snapshot.workQueueQueryStatus)
                .arg(diagnosticText));
    }
    else
    {
        m_statusLabel->setText(
            threadAuditText(
                "thread_audit.status.completed",
                QStringLiteral("状态：%1 条；R3=%2；R0=%3；%4"))
                .arg(static_cast<qulonglong>(m_rows.size()))
                .arg(snapshot.usedNtQuery ? QStringLiteral("NtQuery") : QStringLiteral("Toolhelp"))
                .arg(snapshot.r0Available ? QStringLiteral("OK") : QStringLiteral("Unavailable"))
                .arg(diagnosticText));
    }
}

void KernelThreadAuditTab::rebuildTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_detailEditor);
    const QString filterText = m_filterEdit->text().trimmed();
    m_table->setSortingEnabled(false);
    m_table->setRowCount(0);

    for (std::size_t sourceIndex = 0; sourceIndex < m_rows.size(); ++sourceIndex)
    {
        const ThreadRow& row = m_rows[sourceIndex];
        const bool workItem =
            row.workQueueRowKind == KSWORD_ARK_WORK_QUEUE_ROW_WORK_ITEM;
        const bool workerThread =
            row.workQueueRowKind == KSWORD_ARK_WORK_QUEUE_ROW_WORKER_THREAD;
        const QString categoryText = workItem
            ? threadAuditText("thread_audit.category.work_item", QStringLiteral("工作项"))
            : (workerThread
                ? threadAuditText("thread_audit.category.worker", QStringLiteral("关联工作线程"))
                : threadAuditText("thread_audit.category.system", QStringLiteral("系统线程")));
        const QString queueText = m_mode == Mode::WorkQueueThreads
            ? queueTypeText(row.queueType)
            : threadAuditText("thread_audit.value.not_applicable", QStringLiteral("不适用"));
        const QString parameterText = workItem
            ? pointerText(row.parameterAddress)
            : threadAuditText("thread_audit.value.not_applicable", QStringLiteral("不适用"));
        const QString moduleText = row.moduleResolved
            ? row.module.name
            : threadAuditText("thread_audit.module.unknown", QStringLiteral("<未知归属>"));
        const QString protectionText = row.protectedTarget
            ? threadAuditText("thread_audit.protection.blocked", QStringLiteral("已保护：%1"))
                .arg(protectionReasonText(row.protectionKind))
            : threadAuditText("thread_audit.protection.allowed", QStringLiteral("可操作（需确认）"));
        const QString stateValue = m_mode == Mode::WorkQueueThreads
            ? threadAuditText("thread_audit.value.not_applicable", QStringLiteral("不适用"))
            : stateText(row.state);
        const QString waitValue = m_mode == Mode::WorkQueueThreads
            ? threadAuditText("thread_audit.value.not_applicable", QStringLiteral("不适用"))
            : waitReasonText(row.waitReason);
        const QString r0Value = m_mode == Mode::WorkQueueThreads
            ? workQueueEntryStatusText(row.workQueueStatus)
            : r0StatusText(row.r0Status);
        const QString nodePriorityText = QStringLiteral("%1/%2")
            .arg(row.nodeIndex)
            .arg(row.queuePriorityIndex);

        const QStringList cellTexts{
            QString::number(row.threadId),
            addressText(row.threadObject),
            categoryText,
            queueText,
            nodePriorityText,
            addressText(row.queueAddress),
            stateValue,
            waitValue,
            addressText(row.startAddress),
            parameterText,
            moduleText,
            addressText(row.module.baseAddress),
            row.module.path,
            r0Value,
            protectionText
        };
        if (!filterText.isEmpty() &&
            !cellTexts.join(QLatin1Char(' ')).contains(filterText, Qt::CaseInsensitive))
        {
            continue;
        }

        const int targetRow = m_table->rowCount();
        m_table->insertRow(targetRow);
        for (int columnIndex = 0; columnIndex < static_cast<int>(Column::Count); ++columnIndex)
        {
            auto* item = new QTableWidgetItem(cellTexts.value(columnIndex));
            item->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
            if (columnIndex == static_cast<int>(Column::ThreadId))
            {
                item->setData(Qt::DisplayRole, static_cast<qulonglong>(row.threadId));
            }
            m_table->setItem(targetRow, columnIndex, item);
        }
    }

    m_table->setSortingEnabled(true);
    m_table->resizeColumnsToContents();
    updateDetail();
}

void KernelThreadAuditTab::updateDetail()
{
    const ThreadRow* selected = selectedRow();
    if (selected == nullptr)
    {
        m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(threadAuditText("thread_audit.detail.initial", QStringLiteral("请选择一条线程记录查看证据与安全边界。"))));
        m_suspendButton->setEnabled(false);
        m_resumeButton->setEnabled(false);
        m_terminateButton->setEnabled(false);
        return;
    }
    const ThreadRow row = *selected;

    const bool actionAllowed =
        m_mode == Mode::SystemThreads &&
        row.threadId != 0U;
    m_suspendButton->setEnabled(actionAllowed);
    m_resumeButton->setEnabled(actionAllowed);
    m_terminateButton->setEnabled(actionAllowed);

    ks::ui::FieldDocument detailLines;
    detailLines.section(QStringLiteral("线程身份"));
    if (m_mode == Mode::WorkQueueThreads)
    {
        detailLines.field(QStringLiteral("RowKind"), QStringLiteral("%1").arg(row.workQueueRowKind == KSWORD_ARK_WORK_QUEUE_ROW_WORK_ITEM
                    ? threadAuditText("thread_audit.category.work_item", QStringLiteral("工作项"))
                    : threadAuditText("thread_audit.category.worker", QStringLiteral("关联工作线程"))));
        detailLines.field(QStringLiteral("TID"), QStringLiteral("%1").arg(row.threadId));
        detailLines.field(QStringLiteral("ETHREAD"), QStringLiteral("%1").arg(addressText(row.threadObject)));
        detailLines.field(QStringLiteral("CreateTime100ns"), QStringLiteral("%1").arg(static_cast<qulonglong>(row.createTime100ns)));

        detailLines.section(QStringLiteral("工作队列证据"));
        detailLines.field(QStringLiteral("QueueType"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(queueTypeText(row.queueType))).arg(QStringLiteral("%1").arg(row.queueType)));
        detailLines.field(QStringLiteral("Node/Priority"), QStringLiteral("%1/%2").arg(QStringLiteral("%1").arg(row.nodeIndex)).arg(QStringLiteral("%1").arg(row.queuePriorityIndex)));
        detailLines.field(QStringLiteral("EX_WORK_QUEUE"), QStringLiteral("%1").arg(addressText(row.queueAddress)));
        detailLines.field(QStringLiteral("WORK_QUEUE_ITEM"), QStringLiteral("%1").arg(addressText(row.workItemAddress)));
        detailLines.field(QStringLiteral("WorkerRoutine"), QStringLiteral("%1").arg(addressText(row.startAddress)));
        detailLines.field(QStringLiteral("Parameter"), QStringLiteral("%1").arg(pointerText(row.parameterAddress)));
        detailLines.field(QStringLiteral("EvidenceFlags"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(row.workQueueFlags, 0, 16)));
        detailLines.field(QStringLiteral("EntryStatus"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(workQueueEntryStatusText(row.workQueueStatus))).arg(QStringLiteral("%1").arg(row.workQueueStatus)));
        detailLines.note(QStringLiteral("证据来自当前构建精确匹配的 PDB/DynData 结构描述"));
        detailLines.note(QStringLiteral("未知字段、身份不匹配、链表损坏或读取失败均显式降级。"));
    }
    else
    {
        detailLines.field(QStringLiteral("TID"), QStringLiteral("%1").arg(row.threadId));
        detailLines.field(QStringLiteral("CreateTime100ns"), QStringLiteral("%1").arg(static_cast<qulonglong>(row.createTime100ns)));
        detailLines.field(QStringLiteral("Priority/BasePriority"), QStringLiteral("%1/%2").arg(QStringLiteral("%1").arg(row.priority)).arg(QStringLiteral("%1").arg(row.basePriority)));
        detailLines.field(QStringLiteral("State"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(stateText(row.state))).arg(QStringLiteral("%1").arg(row.state)));
        detailLines.field(QStringLiteral("WaitReason"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(waitReasonText(row.waitReason))).arg(QStringLiteral("%1").arg(row.waitReason)));

        detailLines.section(QStringLiteral("调度证据"));
        detailLines.field(QStringLiteral("ActiveExWorkerKnown"), QStringLiteral("%1").arg(row.workerKnown ? QStringLiteral("true") : QStringLiteral("false")));
        detailLines.field(QStringLiteral("ActiveExWorker"), QStringLiteral("%1").arg(row.activeWorker ? QStringLiteral("true") : QStringLiteral("false")));
        detailLines.note(QStringLiteral("队列归属不适用于系统线程管理视图"));
        detailLines.note(QStringLiteral("请在只读工作队列页查看精确队列与工作项证据。"));
    }

    detailLines.section(QStringLiteral("入口与模块归属"));
    detailLines.field(QStringLiteral("StartRoutine"), QStringLiteral("%1").arg(addressText(row.startAddress)));
    detailLines.field(QStringLiteral("Module"), QStringLiteral("%1").arg(row.moduleResolved ? row.module.name : QStringLiteral("<unresolved>")));
    detailLines.field(QStringLiteral("ModuleBase/Size"), QStringLiteral("%1 / 0x%2").arg(QStringLiteral("%1").arg(addressText(row.module.baseAddress))).arg(QStringLiteral("%1").arg(row.module.imageSize, 0, 16)));
    detailLines.field(QStringLiteral("ModulePath"), QStringLiteral("%1").arg(row.module.path));

    detailLines.section(QStringLiteral("管理确认"));
    detailLines.note(QStringLiteral("危险操作仅限系统线程页"));
    detailLines.note(QStringLiteral("R0 始终复核 TID，并在启动地址或创建时间可用时同步复核对应字段。"));
    m_detailEditor->setDocument(detailLines);
}

void KernelThreadAuditTab::applyColumnPreset(const ViewPreset preset)
{
    m_viewPreset = preset;

    // A：调度/队列概览；B：地址/模块/R0 证据。两组均保持精简。
    std::vector<Column> visibleColumns;
    if (m_mode == Mode::WorkQueueThreads)
    {
        visibleColumns = {
            Column::ThreadId,
            Column::EThread,
            Column::StartRoutine,
            Column::Parameter,
            Column::NodePriority,
            Column::WorkQueueAddress,
            Column::Module,
            Column::ModuleBase,
            Column::ModulePath,
            Column::R0Status };
    }
    else if (preset == ViewPreset::Evidence)
    {
        visibleColumns = {
            Column::ThreadId,
            Column::StartRoutine,
            Column::Parameter,
            Column::Module,
            Column::ModuleBase,
            Column::ModulePath,
            Column::R0Status,
            Column::Protection };
    }
    else
    {
        visibleColumns = {
            Column::ThreadId,
            Column::Category,
            Column::QueueType,
            Column::State,
            Column::WaitReason,
            Column::Module,
            Column::Protection };
    }

    for (int columnIndex = 0; columnIndex < static_cast<int>(Column::Count); ++columnIndex)
    {
        const Column column = static_cast<Column>(columnIndex);
        const bool visible = std::find(visibleColumns.begin(), visibleColumns.end(), column) != visibleColumns.end();
        m_table->setColumnHidden(columnIndex, !visible);
    }
    updatePresetButtons();
}

void KernelThreadAuditTab::updatePresetButtons()
{
    // 选中态前景走 palette(highlighted-text)，与 palette(highlight) 底色配对；
    // 用户把系统强调色改成浅色时也不会出现白底白字。
    const QString activeStyle = ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Accent)
        + QStringLiteral("QPushButton{border-radius:3px;font-weight:600;}");
    const QString inactiveStyle = ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Neutral)
        + QStringLiteral("QPushButton{border-radius:3px;}");

    m_overviewButton->setStyleSheet(m_viewPreset == ViewPreset::Overview ? activeStyle : inactiveStyle);
    m_evidenceButton->setStyleSheet(m_viewPreset == ViewPreset::Evidence ? activeStyle : inactiveStyle);
}

void KernelThreadAuditTab::showHeaderMenu(const QPoint& localPosition)
{
    QMenu columnMenu(this);
    columnMenu.setStyleSheet(menuStyle());

    // 表头菜单允许逐列勾选；手工改变后预设按钮取消着色，表示 Custom。
    for (int columnIndex = 0; columnIndex < static_cast<int>(Column::Count); ++columnIndex)
    {
        const Column column = static_cast<Column>(columnIndex);
        const bool workQueueOnlyColumn =
            column == Column::EThread ||
            column == Column::NodePriority ||
            column == Column::WorkQueueAddress;
        if ((m_mode == Mode::WorkQueueThreads && column == Column::Protection) ||
            (m_mode != Mode::WorkQueueThreads && workQueueOnlyColumn))
        {
            continue;
        }

        const QString headerText = m_table->horizontalHeaderItem(columnIndex) != nullptr
            ? m_table->horizontalHeaderItem(columnIndex)->text()
            : QString::number(columnIndex);
        QAction* columnAction = columnMenu.addAction(headerText);
        columnAction->setCheckable(true);
        columnAction->setChecked(!m_table->isColumnHidden(columnIndex));
        connect(columnAction, &QAction::toggled, this, [this, columnIndex](const bool visible) {
            m_table->setColumnHidden(columnIndex, !visible);
            m_viewPreset = ViewPreset::Custom;
            updatePresetButtons();
        });
    }
    columnMenu.exec(m_table->horizontalHeader()->mapToGlobal(localPosition));
}

void KernelThreadAuditTab::showRowMenu(const QPoint& localPosition)
{
    if (m_table->itemAt(localPosition) != nullptr)
    {
        m_table->selectRow(m_table->itemAt(localPosition)->row());
    }
    if (m_mode != Mode::SystemThreads)
    {
        return;
    }

    std::optional<ThreadRow> rowCopy;
    if (const ThreadRow* const selected = selectedRow(); selected != nullptr)
    {
        rowCopy = *selected;
    }
    QMenu actionMenu(this);
    actionMenu.setStyleSheet(menuStyle());
    QAction* suspendAction = actionMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_pause.svg")),
        threadAuditText("thread_audit.menu.suspend", QStringLiteral("挂起系统线程")));
    QAction* resumeAction = actionMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_resume.svg")),
        threadAuditText("thread_audit.menu.resume", QStringLiteral("恢复系统线程")));
    QAction* terminateAction = actionMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
        threadAuditText("thread_audit.menu.terminate", QStringLiteral("终止系统线程（高风险）")));

    const bool actionAllowed =
        m_mode == Mode::SystemThreads &&
        rowCopy.has_value() &&
        rowCopy->threadId != 0U;
    suspendAction->setEnabled(actionAllowed);
    resumeAction->setEnabled(actionAllowed);
    terminateAction->setEnabled(actionAllowed);
    QAction* selectedAction = actionMenu.exec(m_table->viewport()->mapToGlobal(localPosition));
    if (!rowCopy.has_value())
    {
        return;
    }
    if (selectedAction == suspendAction)
    {
        runControlAction(*rowCopy, KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND);
    }
    else if (selectedAction == resumeAction)
    {
        runControlAction(*rowCopy, KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME);
    }
    else if (selectedAction == terminateAction)
    {
        runControlAction(*rowCopy, KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE);
    }
}

void KernelThreadAuditTab::runControlAction(const unsigned long action)
{
    const ThreadRow* const selected = selectedRow();
    if (selected == nullptr)
    {
        return;
    }
    const ThreadRow row = *selected;
    runControlAction(row, action);
}

void KernelThreadAuditTab::runControlAction(
    const ThreadRow& row,
    const unsigned long action)
{
    if (m_mode != Mode::SystemThreads ||
        row.threadId == 0U)
    {
        showResultMessage(
            this,
            false,
            threadAuditText("thread_audit.dialog.blocked.title", QStringLiteral("系统线程操作已阻止")),
            threadAuditText("thread_audit.dialog.blocked.body", QStringLiteral("当前记录没有可用于执行操作的线程 ID。")));
        return;
    }

    const QString targetText = QStringLiteral(
        "TID=%1\nStart=%2\nCreateTime100ns=%3\nModule=%4")
        .arg(row.threadId)
        .arg(addressText(row.startAddress))
        .arg(static_cast<qulonglong>(row.createTime100ns))
        .arg(row.module.name);
    const bool terminating = action == KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE;
    const QString actionTitle = terminating
        ? threadAuditText("thread_audit.dialog.terminate.title", QStringLiteral("终止系统线程"))
        : (action == KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND
            ? threadAuditText("thread_audit.dialog.suspend.title", QStringLiteral("挂起系统线程"))
            : threadAuditText("thread_audit.dialog.resume.title", QStringLiteral("恢复系统线程")));
    const QString firstWarning = terminating
        ? threadAuditText(
            "thread_audit.dialog.terminate.warning",
            QStringLiteral("高风险：终止驱动系统线程可能造成设备失效、数据丢失或系统崩溃。\n\n%1\n\n确认继续？")).arg(targetText)
        : threadAuditText(
            "thread_audit.dialog.control.warning",
            QStringLiteral("改变驱动系统线程调度状态可能造成设备失效或系统卡死。\n\n%1\n\n确认继续？")).arg(targetText);
    if (!showConfirmation(this, actionTitle, firstWarning))
    {
        return;
    }

    // 终止动作执行第二次独立确认；恢复/挂起保持一次确认。
    if (terminating &&
        !showConfirmation(
            this,
            threadAuditText("thread_audit.dialog.terminate.second.title", QStringLiteral("最终终止确认")),
            threadAuditText(
                "thread_audit.dialog.terminate.second.body",
                QStringLiteral("这是不可逆操作。R0 会再次校验当前可用的线程身份字段，但无法保证目标驱动可以安全恢复。\n\n再次确认终止 TID %1？"))
                .arg(row.threadId)))
    {
        return;
    }

    const unsigned long terminateMethod = terminating
        ? KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC
        : KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE;
    const bool uiConfirmed = action != KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.controlDriverThread(
        row.threadId,
        row.startAddress,
        row.createTime100ns,
        action,
        terminateMethod,
        uiConfirmed);

    kLogEvent controlEvent;
    if (result.ok)
    {
        info << controlEvent
            << "[KernelThreadAuditTab] 系统线程控制完成, tid="
            << row.threadId
            << ", action="
            << action
            << eol;
    }
    else
    {
        err << controlEvent
            << "[KernelThreadAuditTab] 系统线程控制失败, tid="
            << row.threadId
            << ", action="
            << action
            << ", detail="
            << result.message
            << eol;
    }

    const QString resultDetail = QString::fromStdString(result.message);
    showResultMessage(
        this,
        result.ok,
        actionTitle,
        result.ok
            ? threadAuditText("thread_audit.dialog.result.success", QStringLiteral("操作已由 R0 完成。\n%1")).arg(resultDetail)
            : threadAuditText("thread_audit.dialog.result.failure", QStringLiteral("R0 拒绝或执行失败。\n%1")).arg(resultDetail));
    requestRefresh();
}

const KernelThreadAuditTab::ThreadRow* KernelThreadAuditTab::selectedRow() const
{
    const int sourceIndex = selectedSourceIndex();
    if (sourceIndex < 0 || static_cast<std::size_t>(sourceIndex) >= m_rows.size())
    {
        return nullptr;
    }
    return &m_rows[static_cast<std::size_t>(sourceIndex)];
}

int KernelThreadAuditTab::selectedSourceIndex() const
{
    const QList<QTableWidgetItem*> selectedItems = m_table->selectedItems();
    if (selectedItems.isEmpty())
    {
        return -1;
    }
    const qulonglong sourceIndex = selectedItems.first()->data(Qt::UserRole).toULongLong();
    if (sourceIndex > static_cast<qulonglong>((std::numeric_limits<int>::max)()))
    {
        return -1;
    }
    return static_cast<int>(sourceIndex);
}

// collectSnapshot 的实现位于 KernelThreadAuditTab.Snapshot.cpp。

// queryKernelModules 的实现位于 KernelThreadAuditTab.Snapshot.cpp。

// findOwnerModule 的实现位于 KernelThreadAuditTab.Snapshot.cpp。

QString KernelThreadAuditTab::stateText(const std::uint32_t stateValue)
{
    switch (stateValue)
    {
    case 0U: return threadAuditText("thread_audit.state.initialized", QStringLiteral("已初始化"));
    case 1U: return threadAuditText("thread_audit.state.ready", QStringLiteral("就绪"));
    case 2U: return threadAuditText("thread_audit.state.running", QStringLiteral("运行中"));
    case 3U: return threadAuditText("thread_audit.state.standby", QStringLiteral("待运行"));
    case 4U: return threadAuditText("thread_audit.state.terminated", QStringLiteral("已终止"));
    case 5U: return threadAuditText("thread_audit.state.waiting", QStringLiteral("等待中"));
    case 6U: return threadAuditText("thread_audit.state.transition", QStringLiteral("转换中"));
    case 7U: return threadAuditText("thread_audit.state.deferred_ready", QStringLiteral("延迟就绪"));
    default: return QStringLiteral("Unknown(%1)").arg(stateValue);
    }
}

QString KernelThreadAuditTab::waitReasonText(const std::uint32_t waitReasonValue)
{
    switch (waitReasonValue)
    {
    case 0U: return QStringLiteral("Executive");
    case 4U: return QStringLiteral("DelayExecution");
    case 5U: return QStringLiteral("Suspended");
    case 6U: return QStringLiteral("UserRequest");
    case 7U: return QStringLiteral("WrExecutive");
    case 11U: return QStringLiteral("WrDelayExecution");
    case 12U: return QStringLiteral("WrSuspended");
    case 13U: return QStringLiteral("WrUserRequest");
    case kWaitReasonQueue: return QStringLiteral("WrQueue");
    case 16U: return QStringLiteral("WrLpcReceive");
    case 17U: return QStringLiteral("WrLpcReply");
    case 25U: return QStringLiteral("WrCalloutStack");
    case 26U: return QStringLiteral("WrKernel");
    case 27U: return QStringLiteral("WrResource");
    case 28U: return QStringLiteral("WrPushLock");
    case 29U: return QStringLiteral("WrMutex");
    default: return QStringLiteral("Reason(%1)").arg(waitReasonValue);
    }
}

QString KernelThreadAuditTab::r0StatusText(const std::uint32_t statusValue)
{
    switch (statusValue)
    {
    case KSWORD_ARK_THREAD_R0_STATUS_OK: return QStringLiteral("OK");
    case KSWORD_ARK_THREAD_R0_STATUS_PARTIAL: return QStringLiteral("Partial");
    case KSWORD_ARK_THREAD_R0_STATUS_DYNDATA_MISSING: return QStringLiteral("DynData missing");
    case KSWORD_ARK_THREAD_R0_STATUS_READ_FAILED: return QStringLiteral("Read failed");
    default: return QStringLiteral("Unavailable");
    }
}

QString KernelThreadAuditTab::addressText(const std::uint64_t addressValue)
{
    if (addressValue == 0U)
    {
        return QStringLiteral("Unavailable");
    }
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(addressValue), 0, 16)
        .toUpper();
}

QString KernelThreadAuditTab::pointerText(const std::uint64_t addressValue)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(addressValue), 0, 16)
        .toUpper();
}

QString KernelThreadAuditTab::protectionReasonText(
    const ProtectionKind protectionKind)
{
    switch (protectionKind)
    {
    case ProtectionKind::UnknownModule:
        return threadAuditText(
            "thread_audit.protection.unknown",
            QStringLiteral("启动入口归属未知"));
    case ProtectionKind::KernelImage:
        return threadAuditText(
            "thread_audit.protection.kernel",
            QStringLiteral("Windows 内核线程"));
    case ProtectionKind::MissingThreadIdentity:
        return threadAuditText(
            "thread_audit.protection.identity_missing",
            QStringLiteral("启动地址或创建时间缺失，危险操作已关闭"));
    case ProtectionKind::BestEffortR0Recheck:
        return threadAuditText(
            "thread_audit.protection.r0_recheck",
            QStringLiteral("操作时由 R0 复核当前可用身份"));
    case ProtectionKind::ReadOnlyWorkQueueEvidence:
        return threadAuditText(
            "thread_audit.protection.read_only",
            QStringLiteral("只读工作队列证据，不提供管理动作"));
    default:
        return threadAuditText(
            "thread_audit.protection.unknown",
            QStringLiteral("启动入口归属未知"));
    }
}

QString KernelThreadAuditTab::queueTypeText(const std::uint32_t queueType)
{
    switch (queueType)
    {
    case KSWORD_ARK_WORK_QUEUE_TYPE_CRITICAL:
        return threadAuditText(
            "thread_audit.queue.critical",
            QStringLiteral("Critical"));
    case KSWORD_ARK_WORK_QUEUE_TYPE_DELAYED:
        return threadAuditText(
            "thread_audit.queue.delayed",
            QStringLiteral("Delayed"));
    case KSWORD_ARK_WORK_QUEUE_TYPE_HYPERCRITICAL:
        return threadAuditText(
            "thread_audit.queue.hypercritical",
            QStringLiteral("HyperCritical"));
    case KSWORD_ARK_WORK_QUEUE_TYPE_SHARED_WORKER:
        return threadAuditText(
            "thread_audit.queue.shared_worker",
            QStringLiteral("关联工作线程"));
    default:
        return QStringLiteral("Unknown(%1)").arg(queueType);
    }
}

QString KernelThreadAuditTab::workQueueEntryStatusText(
    const std::uint32_t status)
{
    switch (status)
    {
    case KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_OK:
        return QStringLiteral("OK");
    case KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_READ_FAILED:
        return threadAuditText(
            "thread_audit.work_queue.entry.read_failed",
            QStringLiteral("读取失败"));
    case KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_ROUTINE_UNRESOLVED:
        return threadAuditText(
            "thread_audit.work_queue.entry.module_unresolved",
            QStringLiteral("例程模块未解析"));
    case KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_ROUTINE_NOT_EXECUTABLE:
        return threadAuditText(
            "thread_audit.work_queue.entry.not_executable",
            QStringLiteral("例程不在可执行节"));
    case KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_THREAD_REFERENCE_FAILED:
        return threadAuditText(
            "thread_audit.work_queue.entry.reference_failed",
            QStringLiteral("线程对象引用失败"));
    case KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_THREAD_IDENTITY_FAILED:
        return threadAuditText(
            "thread_audit.work_queue.entry.identity_failed",
            QStringLiteral("线程身份验证失败"));
    default:
        return QStringLiteral("Unknown(%1)").arg(status);
    }
}

QString KernelThreadAuditTab::snapshotDiagnosticText(
    const Snapshot& snapshot,
    const Mode mode)
{
    QStringList diagnostics;
    if (mode == Mode::WorkQueueThreads)
    {
        // IOCTL 没送达时 workQueueQueryStatus 仍是 R3 结构体默认值(UNSUPPORTED)，
        // 把它当成 R0 的布局结论上报会把“没有驱动”误报成“布局定位失败”。
        if ((snapshot.diagnosticFlags & DiagnosticWorkQueueTransportFailed) != 0U)
        {
            diagnostics <<
                ((snapshot.diagnosticFlags & DiagnosticWorkQueueUnsupported) != 0U
                ? threadAuditText(
                    "thread_audit.work_queue.transport.unsupported",
                    QStringLiteral("驱动不识别工作队列 IOCTL，驱动版本过旧"))
                : threadAuditText(
                    "thread_audit.work_queue.transport.unavailable",
                    QStringLiteral("驱动未加载或未连接，本次查询 R0 未参与")));
            diagnostics << QStringLiteral("Win32=%1").arg(snapshot.r0Win32Error);
            return diagnostics.join(QStringLiteral(" | "));
        }
        switch (snapshot.workQueueQueryStatus)
        {
        case KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK:
            diagnostics << threadAuditText(
                "thread_audit.work_queue.query.ok",
                QStringLiteral("精确身份与布局已验证"));
            break;
        case KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED:
            diagnostics << threadAuditText(
                "thread_audit.work_queue.query.unsupported",
                QStringLiteral("PDB Profile 与运行期签名回退都未能定位工作队列布局；枚举已关闭"));
            break;
        case KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL:
            diagnostics << threadAuditText(
                "thread_audit.work_queue.query.partial",
                QStringLiteral("快照部分完成，异常已计数"));
            break;
        case KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_INVALID_LAYOUT:
            diagnostics << threadAuditText(
                "thread_audit.work_queue.query.invalid_layout",
                QStringLiteral("结构描述边界无效，已关闭枚举"));
            break;
        case KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_IDENTITY_MISMATCH:
            diagnostics << threadAuditText(
                "thread_audit.work_queue.query.identity_mismatch",
                QStringLiteral("PE/PDB 身份不匹配，已关闭枚举"));
            break;
        case KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_READ_FAILED:
            diagnostics << threadAuditText(
                "thread_audit.work_queue.query.read_failed",
                QStringLiteral("内核证据读取失败"));
            break;
        default:
            diagnostics << QStringLiteral("QueryStatus=%1")
                .arg(snapshot.workQueueQueryStatus);
            break;
        }
        // 任何非 OK 结论都附上 NTSTATUS，否则 UNSUPPORTED 只剩一句结论，
        // 无法区分是布局搜索失败、映像不可用还是读取失败。
        if ((snapshot.diagnosticFlags & DiagnosticWorkQueuePartial) != 0U ||
            snapshot.workQueueQueryStatus != KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK)
        {
            diagnostics << QStringLiteral(
                "corrupt=%1, read=%2, reference=%3, NTSTATUS=0x%4")
                .arg(snapshot.workQueueCorruptCount)
                .arg(snapshot.workQueueReadFailureCount)
                .arg(snapshot.workQueueReferenceFailureCount)
                .arg(static_cast<unsigned long>(snapshot.workQueueLastStatus), 8, 16, QLatin1Char('0'));
        }
    }
    else
    {
        if ((snapshot.diagnosticFlags & DiagnosticR3EnumerationEmpty) != 0U)
        {
            diagnostics << threadAuditText(
                "thread_audit.diagnostic.r3_empty",
                QStringLiteral("R3 未返回 System 线程"));
        }
        if ((snapshot.diagnosticFlags & DiagnosticR0ThreadUnavailable) != 0U)
        {
            diagnostics << QStringLiteral("R0 Win32=%1").arg(snapshot.r0Win32Error);
        }
        if ((snapshot.diagnosticFlags & DiagnosticModuleUnavailable) != 0U)
        {
            diagnostics << QStringLiteral("ModuleStatus=%1, NTSTATUS=0x%2, bytes=%3")
                .arg(static_cast<std::uint32_t>(snapshot.moduleQueryStatus))
                .arg(static_cast<unsigned long>(snapshot.moduleNativeStatus), 8, 16, QLatin1Char('0'))
                .arg(snapshot.moduleRequiredBytes);
        }
        if (diagnostics.isEmpty())
        {
            diagnostics << threadAuditText(
                "thread_audit.diagnostic.complete",
                QStringLiteral("身份与模块证据完整"));
        }
    }
    return diagnostics.join(QStringLiteral(" | "));
}

void KernelThreadAuditTab::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        applyTranslatedText();
        rebuildTable();
    }
}
