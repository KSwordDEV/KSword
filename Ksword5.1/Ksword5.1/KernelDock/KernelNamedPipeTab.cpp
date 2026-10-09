#include "KernelNamedPipeTab.h"
#include "KernelDock.h"
#include "../UI/TableInteractionSupport.h"

#include <memory>

// ============================================================
// KernelNamedPipeTab.cpp
// 作用说明：
// 1) 展示 R3 Named Pipe NPFS 目录枚举结果；
// 2) 支持刷新、过滤、复制当前行和详情查看；
// 3) 本文件不负责挂入 KernelDock，由集成会话处理项目文件和 Tab 注册。
// ============================================================

#include "../theme.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/DetailLayoutRegistry.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QSplitter>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QResizeEvent>
#include <QSize>
#include <QStringList>
#include <QThreadPool>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    QString tableColumnText(const KernelNamedPipeEntry& row, const KernelNamedPipeTab::TableColumn column)
    {
        switch (column)
        {
        case KernelNamedPipeTab::TableColumn::PipeName:
            return row.pipeName;
        case KernelNamedPipeTab::TableColumn::NtPath:
            return row.ntPath;
        case KernelNamedPipeTab::TableColumn::Attributes:
            return row.attributesText;
        case KernelNamedPipeTab::TableColumn::LastWriteTime:
            return row.lastWriteTimeText;
        case KernelNamedPipeTab::TableColumn::Status:
            return row.statusText;
        case KernelNamedPipeTab::TableColumn::SourceDirectory:
            return row.sourceDirectory;
        default:
            return QString();
        }
    }

    QString buildDirectoryStatusText(const KernelNamedPipeSnapshot& snapshot)
    {
        QStringList lines;
        lines << kernelText("kernel.named_pipe.detail.directory_status_heading", QStringLiteral("[路径候选状态]"));
        for (const KernelNamedPipeDirectoryStatus& status : snapshot.directories)
        {
            lines << QStringLiteral("- %1 | open=%2 | query=%3 | rows=%4 | status=%5")
                .arg(status.candidatePath)
                .arg(status.openSucceeded ? QStringLiteral("yes") : QStringLiteral("no"))
                .arg(status.querySucceeded ? QStringLiteral("yes") : QStringLiteral("no"))
                .arg(static_cast<qulonglong>(status.returnedRows))
                .arg(status.statusText);
        }
        return lines.join('\n');
    }

    QString buildSelectedRowDetailText(const KernelNamedPipeEntry* row)
    {
        if (row == nullptr)
        {
            return kernelText("kernel.named_pipe.detail.no_selection", QStringLiteral("[当前行]\n<未选择>"));
        }

        QStringList lines;
        lines << kernelText("kernel.named_pipe.detail.current_row_heading", QStringLiteral("[当前行]"));
        lines << QStringLiteral("Pipe Name: %1").arg(row->pipeName);
        lines << QStringLiteral("NT Path: %1").arg(row->ntPath);
        lines << QStringLiteral("Source Directory: %1").arg(row->sourceDirectory);
        lines << QStringLiteral("Query Succeeded: %1").arg(row->querySucceeded ? QStringLiteral("true") : QStringLiteral("false"));
        lines << QStringLiteral("Attributes: %1").arg(row->attributesText);
        lines << QStringLiteral("LastWriteTime: %1").arg(row->lastWriteTimeText);
        lines << QStringLiteral("LastWriteTimeRaw: %1").arg(static_cast<qlonglong>(row->lastWriteTime));
        lines << QStringLiteral("Status: %1").arg(row->statusText);
        return lines.join('\n');
    }
}

KernelNamedPipeTab::KernelNamedPipeTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();

    QMetaObject::invokeMethod(
        this,
        [this]()
        {
            requestRefresh(false);
        },
        Qt::QueuedConnection);
}

void KernelNamedPipeTab::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(8, 8, 8, 8);
    m_rootLayout->setSpacing(6);

    m_toolbarLayout = new QHBoxLayout();
    m_toolbarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolbarLayout->setSpacing(6);

    m_refreshButton = new QPushButton(this);
    m_refreshButton->setIcon(QIcon(":/Icon/handle_refresh.svg"));
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshButton);
    m_refreshButton->setToolTip(kernelText("kernel.named_pipe.toolbar.refresh.tooltip", QStringLiteral("刷新命名管道列表")));
    m_refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());

    m_copyButton = new QPushButton(this);
    m_copyButton->setIcon(QIcon(":/Icon/handle_copy_row.svg"));
    KswordTheme::ApplyCompactIconButtonMetrics(m_copyButton);
    m_copyButton->setToolTip(kernelText("kernel.named_pipe.toolbar.copy.tooltip", QStringLiteral("复制当前行")));
    m_copyButton->setStyleSheet(KswordTheme::ThemedButtonStyle());

    m_detailButton = new QPushButton(this);
    m_detailButton->setIcon(QIcon(":/Icon/process_details.svg"));
    KswordTheme::ApplyCompactIconButtonMetrics(m_detailButton);
    m_detailButton->setToolTip(kernelText("kernel.named_pipe.toolbar.detail.tooltip", QStringLiteral("刷新详情面板")));
    m_detailButton->setStyleSheet(KswordTheme::ThemedButtonStyle());

    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setPlaceholderText(kernelText("kernel.named_pipe.toolbar.filter.placeholder", QStringLiteral("过滤管道名、NT路径、状态")));
    m_filterEdit->setClearButtonEnabled(true);

    m_statusLabel = new QLabel(kernelText("kernel.named_pipe.status.waiting", QStringLiteral("● 等待刷新")), this);
    m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));

    m_toolbarLayout->addWidget(m_refreshButton);
    m_toolbarLayout->addWidget(m_copyButton);
    m_toolbarLayout->addWidget(m_detailButton);
    m_toolbarLayout->addWidget(m_filterEdit, 1);
    m_rootLayout->addLayout(m_toolbarLayout);
    m_rootLayout->addWidget(m_statusLabel);

    m_resultTable = new QTreeWidget(this);
    m_resultTable->setColumnCount(static_cast<int>(TableColumn::Count));
    m_resultTable->setHeaderLabels(QStringList{
        QStringLiteral("Pipe Name"),
        QStringLiteral("NT Path"),
        QStringLiteral("Attributes"),
        QStringLiteral("LastWriteTime"),
        QStringLiteral("Status"),
        QStringLiteral("Source")
        });
    m_resultTable->setRootIsDecorated(false);
    m_resultTable->setItemsExpandable(false);
    m_resultTable->setAlternatingRowColors(true);
    m_resultTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_resultTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_resultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_resultTable->setSortingEnabled(true);
    m_resultTable->setContextMenuPolicy(Qt::CustomContextMenu);
    if (m_resultTable->header() != nullptr)
    {
        m_resultTable->header()->setSectionResizeMode(QHeaderView::Interactive);
        m_resultTable->header()->setStretchLastSection(false);
    }

    // m_detailEdit 使用项目内置 CodeEditorWidget：
    // - 输入：NPFS 枚举说明、候选路径状态和当前行详情；
    // - 处理：以只读代码/日志视图展示多行文本；
    // - 返回：无，控件由 Qt 父子关系释放。
    m_detailEdit = new CodeEditorWidget(this);
    m_detailEdit->setReadOnly(true);
    m_detailEdit->setMinimumHeight(150);
    m_detailEdit->setText(kernelText(
        "kernel.named_pipe.detail.intro",
        QStringLiteral(
            "说明：命名管道属于 NPFS 文件系统目录枚举，本页使用 NtOpenFile + NtQueryDirectoryFile 读取 \\Device\\NamedPipe。"
            "\n这不是 NtQueryDirectoryObject 下钻，也不是系统句柄表枚举。")));

    // 页面显式拥有两面板的布局，详情宿主不再从 m_rootLayout 推断并重挂载。
    auto* const detailSplitter = new QSplitter(Qt::Vertical, this);
    detailSplitter->setChildrenCollapsible(false);
    detailSplitter->addWidget(m_resultTable);
    detailSplitter->addWidget(m_detailEdit);
    m_rootLayout->addWidget(detailSplitter, 1);
    ks::ui::DetailLayoutRegistry::registerHost(
        m_resultTable, m_detailEdit, this, detailSplitter, m_resultTable, m_detailEdit);
    applyAdaptiveColumnWidths();
}

void KernelNamedPipeTab::initializeConnections()
{
    connect(m_refreshButton, &QPushButton::clicked, this, [this]()
        {
            requestRefresh(true);
        });
    connect(m_copyButton, &QPushButton::clicked, this, [this]()
        {
            copyCurrentRow();
        });
    connect(m_detailButton, &QPushButton::clicked, this, [this]()
        {
            updateDetailPanel();
        });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this]()
        {
            applyFilter();
        });
    connect(m_resultTable, &QTreeWidget::itemSelectionChanged, this, [this]()
        {
            updateDetailPanel();
        });
    connect(m_resultTable, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            showContextMenu(localPosition);
        });
}

void KernelNamedPipeTab::requestRefresh(const bool forceRefresh)
{
    if (m_refreshInProgress)
    {
        if (forceRefresh)
        {
            m_refreshPending = true;
        }
        return;
    }

    const std::uint64_t currentTicket = ++m_refreshTicket;
    m_refreshInProgress = true;
    m_refreshButton->setEnabled(false);
    m_statusLabel->setText(kernelText("kernel.named_pipe.status.enumerating", QStringLiteral("● 正在枚举 NPFS Named Pipe 目录...")));
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:700;").arg(KswordTheme::PrimaryBlueHex));

    QPointer<KernelNamedPipeTab> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, currentTicket]()
        {
            const KernelNamedPipeSnapshot snapshot = runKernelNamedPipeSnapshotTask();
            if (guardThis == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, currentTicket, snapshot]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->applySnapshot(currentTicket, snapshot);
                },
                Qt::QueuedConnection);
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void KernelNamedPipeTab::applySnapshot(
    const std::uint64_t refreshTicket,
    const KernelNamedPipeSnapshot& snapshot)
{
    if (refreshTicket < m_refreshTicket)
    {
        return;
    }

    const QPointer<KernelNamedPipeTab> guardThis(this);
    const auto deferredSnapshot =
        std::make_shared<KernelNamedPipeSnapshot>(snapshot);
    if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-named-pipe-snapshot-apply"),
        { m_resultTable },
        [guardThis, refreshTicket, deferredSnapshot]()
        {
            if (!guardThis.isNull())
            {
                guardThis->applySnapshot(refreshTicket, *deferredSnapshot);
            }
        }))
    {
        return;
    }

    m_lastSnapshot = snapshot;
    m_rows = snapshot.rows;
    rebuildTable();
    applyFilter();
    updateDetailPanel();

    m_refreshInProgress = false;
    m_refreshButton->setEnabled(true);

    QString statusText = snapshot.taskSucceeded
        ? kernelText("kernel.named_pipe.status.completed", QStringLiteral("● 刷新完成 | %1")).arg(snapshot.summaryText)
        : kernelText("kernel.named_pipe.status.failed", QStringLiteral("● 刷新失败 | %1")).arg(snapshot.errorText);
    if (!snapshot.errorText.trimmed().isEmpty() && snapshot.taskSucceeded)
    {
        statusText += kernelText("kernel.named_pipe.status.additional_error", QStringLiteral(" | %1")).arg(snapshot.errorText);
    }
    m_statusLabel->setText(statusText);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
        .arg(snapshot.anyQuerySucceeded ? KswordTheme::SuccessHex() : KswordTheme::WarningHex()));

    if (m_refreshPending)
    {
        m_refreshPending = false;
        QMetaObject::invokeMethod(
            this,
            [this]()
            {
                requestRefresh(true);
            },
            Qt::QueuedConnection);
    }
}

void KernelNamedPipeTab::rebuildTable()
{
    if (m_resultTable == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_detailEdit);

    m_resultTable->setSortingEnabled(false);
    m_resultTable->clear();

    for (std::size_t rowIndex = 0; rowIndex < m_rows.size(); ++rowIndex)
    {
        const KernelNamedPipeEntry& row = m_rows[rowIndex];
        auto* item = new QTreeWidgetItem();
        for (int column = 0; column < static_cast<int>(TableColumn::Count); ++column)
        {
            item->setText(column, tableColumnText(row, static_cast<TableColumn>(column)));
        }
        item->setData(static_cast<int>(TableColumn::PipeName), Qt::UserRole, static_cast<qulonglong>(rowIndex));
        m_resultTable->addTopLevelItem(item);
    }

    if (m_resultTable->topLevelItemCount() > 0)
    {
        m_resultTable->setCurrentItem(m_resultTable->topLevelItem(0));
    }

    applyAdaptiveColumnWidths();
    m_resultTable->setSortingEnabled(true);
}

void KernelNamedPipeTab::applyFilter()
{
    if (m_resultTable == nullptr || m_filterEdit == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_detailEdit);

    const QString filterText = m_filterEdit->text().trimmed().toCaseFolded();
    for (int rowIndex = 0; rowIndex < m_resultTable->topLevelItemCount(); ++rowIndex)
    {
        QTreeWidgetItem* item = m_resultTable->topLevelItem(rowIndex);
        if (item == nullptr)
        {
            continue;
        }

        bool matched = filterText.isEmpty();
        for (int column = 0; !matched && column < static_cast<int>(TableColumn::Count); ++column)
        {
            matched = item->text(column).toCaseFolded().contains(filterText);
        }
        item->setHidden(!matched);
    }
}

void KernelNamedPipeTab::updateDetailPanel()
{
    if (m_detailEdit == nullptr)
    {
        return;
    }

    QStringList detailLines;
    detailLines << kernelText("kernel.named_pipe.detail.explanation_heading", QStringLiteral("[说明]"));
    detailLines << kernelText("kernel.named_pipe.detail.explanation.enumeration", QStringLiteral("命名管道属于 NPFS 文件系统目录枚举，本页使用 NtOpenFile + NtQueryDirectoryFile 读取 \\Device\\NamedPipe 或等价路径。"));
    detailLines << kernelText("kernel.named_pipe.detail.explanation.scope", QStringLiteral("这不是 NtQueryDirectoryObject 下钻，也不是系统句柄表枚举；因此不会列出持有管道句柄的进程。"));
    detailLines << QString();
    detailLines << buildDirectoryStatusText(m_lastSnapshot);
    detailLines << QString();
    detailLines << buildSelectedRowDetailText(selectedRow());
    m_detailEdit->setText(detailLines.join('\n'));
}

void KernelNamedPipeTab::copyCurrentRow()
{
    if (m_resultTable == nullptr || m_resultTable->currentItem() == nullptr)
    {
        return;
    }

    QStringList fields;
    for (int column = 0; column < static_cast<int>(TableColumn::Count); ++column)
    {
        fields.push_back(m_resultTable->currentItem()->text(column));
    }
    QApplication::clipboard()->setText(fields.join('\t'));
}

void KernelNamedPipeTab::showContextMenu(const QPoint& localPosition)
{
    if (m_resultTable == nullptr)
    {
        return;
    }

    QTreeWidgetItem* clickedItem = m_resultTable->itemAt(localPosition);
    if (clickedItem == nullptr)
    {
        return;
    }
    m_resultTable->setCurrentItem(clickedItem);

    QMenu menu(this);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* copyRowAction = menu.addAction(QIcon(":/Icon/handle_copy_row.svg"), kernelText("kernel.named_pipe.menu.copy_row", QStringLiteral("复制当前行")));
    QAction* detailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), kernelText("kernel.named_pipe.menu.refresh_detail", QStringLiteral("刷新详情")));

    QAction* selectedAction = menu.exec(m_resultTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copyCurrentRow();
        return;
    }
    if (selectedAction == detailAction)
    {
        updateDetailPanel();
    }
}

const KernelNamedPipeEntry* KernelNamedPipeTab::selectedRow() const
{
    if (m_resultTable == nullptr || m_resultTable->currentItem() == nullptr)
    {
        return nullptr;
    }

    const QVariant rowIndexValue =
        m_resultTable->currentItem()->data(static_cast<int>(TableColumn::PipeName), Qt::UserRole);
    if (!rowIndexValue.isValid())
    {
        return nullptr;
    }

    const std::size_t rowIndex = static_cast<std::size_t>(rowIndexValue.toULongLong());
    if (rowIndex >= m_rows.size())
    {
        return nullptr;
    }
    return &m_rows[rowIndex];
}

void KernelNamedPipeTab::applyAdaptiveColumnWidths()
{
    if (m_resultTable == nullptr || m_resultTable->header() == nullptr)
    {
        return;
    }

    QHeaderView* header = m_resultTable->header();
    header->setSectionResizeMode(QHeaderView::Interactive);

    const int viewportWidth = m_resultTable->viewport()->width();
    if (viewportWidth <= 0)
    {
        return;
    }

    const int nameWidth = 220;
    const int attributesWidth = 180;
    const int timeWidth = 190;
    const int statusWidth = 220;
    const int sourceWidth = 160;
    const int pathWidth = std::max(320, viewportWidth - nameWidth - attributesWidth - timeWidth - statusWidth - sourceWidth - 24);

    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::PipeName), nameWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::NtPath), pathWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::Attributes), attributesWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::LastWriteTime), timeWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::Status), statusWidth);
    m_resultTable->setColumnWidth(static_cast<int>(TableColumn::SourceDirectory), sourceWidth);
}

void KernelNamedPipeTab::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    applyAdaptiveColumnWidths();
}
