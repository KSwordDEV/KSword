#include "../UI/StructuredFieldView.h"
#include "KernelDock.h"
#include "../UI/TableInteractionSupport.h"

#include <memory>
#include "../UI/VisibleTableWidget.h"

#include "KernelDockSsdtWorker.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/DetailLayoutRegistry.h"
/* 统一入口：这一页不需要知道 GPA、EPT 叶或 ruleId。 */
#include "../UI/HvmWatchDialog.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QInputDialog>
#include <QMessageBox>
#include <QMetaObject>
#include <QMenu>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QStringList>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <thread>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    QString blueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:2px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    QString headerStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::BorderHex());
    }

    QString itemSelectionStyle()
    {
        return QString();
    }

    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    // ssdtContextMenuStyle：
    // - 输入：无，由全局主题读取菜单背景、文字、边框与选中颜色；
    // - 处理：统一返回非透明 QMenu 样式，避免深色主题/系统主题下右键菜单不可读；
    // - 返回：可直接传给 QMenu::setStyleSheet 的样式文本。
    QString ssdtContextMenuStyle()
    {
        return KswordTheme::ContextMenuStyle();
    }

    QString safeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString safeText(const QString& valueText)
    {
        return safeText(valueText, kernelText("kernel.ssdt.placeholder.empty", QStringLiteral("<空>")));
    }

    QString emptyText()
    {
        return kernelText("kernel.ssdt.placeholder.empty", QStringLiteral("<空>"));
    }

    QString formatAddressHex(const std::uint64_t addressValue)
    {
        return QStringLiteral("0x%1")
            .arg(addressValue, 16, 16, QChar('0'))
            .toUpper();
    }

    // tableRowAsTsv：
    // - 输入：SSDT 表指针与可视行号；
    // - 处理：按当前表格列顺序读取可见文本，空单元格使用占位符，字段间使用 Tab；
    // - 返回：适合复制到剪贴板/表格软件的 TSV 文本；输入无效时返回空字符串。
    QString tableRowAsTsv(const QTableWidget* tableWidget, const int rowIndex)
    {
        if (tableWidget == nullptr || rowIndex < 0 || rowIndex >= tableWidget->rowCount())
        {
            return QString();
        }

        QStringList fieldList;
        fieldList.reserve(tableWidget->columnCount());
        for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* cellItem = tableWidget->item(rowIndex, columnIndex);
            fieldList.push_back(cellItem != nullptr ? safeText(cellItem->text()) : emptyText());
        }
        return fieldList.join('\t');
    }

    enum class SsdtColumn : int
    {
        Index = 0,
        ServiceName,
        ZwAddress,
        ServiceAddress,
        SlotAddress,
        Module,
        Count
    };
}

void KernelDock::initializeSsdtTab()
{
    if (m_ssdtPage == nullptr || m_ssdtLayout != nullptr)
    {
        return;
    }

    m_ssdtLayout = new QVBoxLayout(m_ssdtPage);
    m_ssdtLayout->setContentsMargins(4, 4, 4, 4);
    m_ssdtLayout->setSpacing(6);

    m_ssdtToolLayout = new QHBoxLayout();
    m_ssdtToolLayout->setContentsMargins(0, 0, 0, 0);
    m_ssdtToolLayout->setSpacing(6);

    m_refreshSsdtButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_ssdtPage);
    m_refreshSsdtButton->setToolTip(kernelText("kernel.ssdt.toolbar.refresh.tooltip", QStringLiteral("刷新 SSDT 遍历结果")));
    m_refreshSsdtButton->setStyleSheet(blueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshSsdtButton);

    m_restoreSsdtButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
        kernelText(
            "kernel.ssdt.toolbar.restore",
            QStringLiteral("恢复选中槽位")),
        m_ssdtPage);
    m_restoreSsdtButton->setToolTip(kernelText(
        "kernel.ssdt.toolbar.restore.tooltip",
        QStringLiteral(
            "仅当磁盘映像身份完全匹配且槽值存在差异时，按当前值比较后恢复")));
    m_restoreSsdtButton->setStyleSheet(blueButtonStyle());
    m_restoreSsdtButton->setEnabled(false);

    m_ssdtFilterEdit = new QLineEdit(m_ssdtPage);
    m_ssdtFilterEdit->setPlaceholderText(kernelText("kernel.ssdt.toolbar.filter.placeholder", QStringLiteral("按索引/服务名/地址/模块筛选")));
    m_ssdtFilterEdit->setToolTip(kernelText("kernel.ssdt.toolbar.filter.tooltip", QStringLiteral("输入关键字后实时过滤 SSDT 结果")));
    m_ssdtFilterEdit->setClearButtonEnabled(true);
    m_ssdtFilterEdit->setStyleSheet(blueInputStyle());

    m_ssdtStatusLabel = new QLabel(kernelText("kernel.ssdt.status.waiting", QStringLiteral("状态：等待刷新")), m_ssdtPage);
    m_ssdtStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::TextSecondaryHex()));

    m_ssdtToolLayout->addWidget(m_refreshSsdtButton, 0);
    m_ssdtToolLayout->addWidget(m_restoreSsdtButton, 0);
    m_ssdtToolLayout->addWidget(m_ssdtFilterEdit, 1);
    m_ssdtToolLayout->addWidget(m_ssdtStatusLabel, 0);
    m_ssdtLayout->addLayout(m_ssdtToolLayout);

    QSplitter* splitter = new QSplitter(Qt::Vertical, m_ssdtPage);
    m_ssdtLayout->addWidget(splitter, 1);

    m_ssdtTable = new ks::ui::VisibleTableWidget(splitter);
    m_ssdtTable->setColumnCount(static_cast<int>(SsdtColumn::Count));
    m_ssdtTable->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.ssdt.header.index", QStringLiteral("索引")),
        kernelText("kernel.ssdt.header.service_name", QStringLiteral("服务名")),
        kernelText("kernel.ssdt.header.zw_address", QStringLiteral("Zw导出地址")),
        kernelText("kernel.ssdt.header.service_address", QStringLiteral("服务例程")),
        kernelText("kernel.ssdt.header.slot_address", QStringLiteral("槽位地址")),
        kernelText("kernel.ssdt.header.module", QStringLiteral("模块"))
        });
    m_ssdtTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_ssdtTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_ssdtTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_ssdtTable->setAlternatingRowColors(true);
    m_ssdtTable->setStyleSheet(itemSelectionStyle());
    m_ssdtTable->setCornerButtonEnabled(false);
    m_ssdtTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_ssdtTable->verticalHeader()->setVisible(false);
    m_ssdtTable->horizontalHeader()->setStyleSheet(headerStyle());
    m_ssdtTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_ssdtTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(SsdtColumn::ServiceName), QHeaderView::Stretch);
    m_ssdtTable->setColumnWidth(static_cast<int>(SsdtColumn::Index), 90);
    m_ssdtTable->setColumnWidth(static_cast<int>(SsdtColumn::ZwAddress), 180);
    m_ssdtTable->setColumnWidth(static_cast<int>(SsdtColumn::ServiceAddress), 180);
    m_ssdtTable->setColumnWidth(static_cast<int>(SsdtColumn::SlotAddress), 180);
    m_ssdtTable->setColumnWidth(static_cast<int>(SsdtColumn::Module), 150);

    m_ssdtDetailEditor = new ks::ui::StructuredFieldView(splitter);

    m_ssdtDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.ssdt.detail.initial", QStringLiteral("请选择一条 SSDT 记录查看详情。"))));

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerStructuredHost(
        m_ssdtTable, m_ssdtDetailEditor, m_ssdtPage);

    connect(m_refreshSsdtButton, &QPushButton::clicked, this, [this]() {
        refreshSsdtAsync();
    });
    connect(m_restoreSsdtButton, &QPushButton::clicked, this, [this]() {
        restoreSelectedSsdtBaseline();
    });
    connect(m_ssdtFilterEdit, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildSsdtTable(filterText.trimmed());
    });
    connect(m_ssdtTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showSsdtDetailByCurrentRow();
        const KernelSsdtEntry* entry = currentSsdtEntry();
        m_restoreSsdtButton->setEnabled(
            entry != nullptr
            && entry->cleanBaselineAvailable
            && entry->cleanBaselineDiffers
            && entry->tableEntryAddress != 0U
            && !m_ssdtRefreshRunning.load());
    });
    connect(m_ssdtTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        if (m_ssdtTable == nullptr)
        {
            return;
        }

        const QModelIndex clickedIndex = m_ssdtTable->indexAt(localPosition);
        if (clickedIndex.isValid())
        {
            m_ssdtTable->setCurrentCell(clickedIndex.row(), clickedIndex.column());
        }

        const int currentRow = m_ssdtTable->currentRow();
        QMenu contextMenu(m_ssdtTable);
        contextMenu.setStyleSheet(ssdtContextMenuStyle());

        QAction* copyRowAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
            kernelText("kernel.ssdt.menu.copy_row", QStringLiteral("复制当前行")));
        copyRowAction->setEnabled(currentRow >= 0);

        /*
         * 监视这一项**槽位本身**的写入，不是它指向的服务例程。
         *
         * 改 SSDT 就是改槽位里那个编码值；例程被改是另一回事（那是 inline hook，
         * 该去反汇编页盯）。监视错了对象的后果不是报错，是永远等不到命中。
         */
        const KernelSsdtEntry* const watchEntry = currentSsdtEntry();
        QAction* watchAction = contextMenu.addAction(
            kernelText("kernel.ssdt.menu.hvm_watch",
                       QStringLiteral("HVM 监视：下一次写入这一槽位")));
        watchAction->setEnabled(
            watchEntry != nullptr && watchEntry->tableEntryAddress != 0U);
        watchAction->setToolTip(kernelText(
            "kernel.ssdt.menu.hvm_watch.tip",
            QStringLiteral("装一条首次访问监视，等下一次有人写这一槽位时记下访问者的 RIP、模块与地址空间。命中不阻止写入，也不会让常驻退出。")));

        /*
         * 再给一条：谁改了这张表所在页的**映射**。
         *
         * 与上一条问的不是一件事。上一条盯槽位内容，回答"谁改了这一项"；
         * 这一条盯指向 SSDT 那一页的 PTE，回答"谁把整张表重映射到别处了"——
         * 后者发生时表里一个字节都不用动，上一条永远不会响。
         */
        QAction* watchPteAction = contextMenu.addAction(
            kernelText("kernel.ssdt.menu.hvm_watch_pte",
                       QStringLiteral("HVM 监视：下一次写入这张表所在页的页表项")));
        watchPteAction->setEnabled(
            watchEntry != nullptr && watchEntry->tableEntryAddress != 0U);
        watchPteAction->setToolTip(kernelText(
            "kernel.ssdt.menu.hvm_watch_pte.tip",
            QStringLiteral("盯的不是表内容，而是指向这一页的那一项页表项。整张表被重映射走时表内容不变，只有这一项会被改。")));
        // 地址在弹菜单之前取好：exec 是嵌套事件循环，表可以在这期间被刷新掉。
        const unsigned long long ssdtEntryAddress = watchEntry != nullptr
            ? watchEntry->tableEntryAddress
            : 0ULL;
        const QString ssdtPteLabel = watchEntry != nullptr
            ? kernelText("kernel.ssdt.menu.hvm_watch_pte.label",
                         QStringLiteral("SSDT 槽位 #%1 %2 所在的表页"))
                  .arg(watchEntry->serviceIndex)
                  .arg(watchEntry->serviceNameText)
            : QString();

        QAction* selectedAction = contextMenu.exec(m_ssdtTable->viewport()->mapToGlobal(localPosition));
        if (selectedAction == watchPteAction && ssdtEntryAddress != 0ULL)
        {
            ks::ui::openHvmWatchOnPte(this, ssdtEntryAddress, ssdtPteLabel);
            return;
        }
        if (selectedAction == watchAction && watchEntry != nullptr)
        {
            ks::ui::HvmWatchRequest request;
            request.virtualAddress = true;
            request.address = watchEntry->tableEntryAddress;
            // 槽宽由驱动回报（x64 上是 4 字节的编码偏移），不要写死。
            request.length = watchEntry->tableEntrySize != 0U
                ? watchEntry->tableEntrySize
                : sizeof(std::uint32_t);
            request.access = KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
            request.label = kernelText(
                "kernel.ssdt.menu.hvm_watch.label",
                QStringLiteral("SSDT 槽位 #%1 %2"))
                .arg(watchEntry->serviceIndex)
                .arg(watchEntry->serviceNameText);
            ks::ui::openHvmWatch(this, request);
            return;
        }
        if (selectedAction != copyRowAction || currentRow < 0)
        {
            return;
        }

        const QString rowText = tableRowAsTsv(m_ssdtTable, currentRow);
        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard != nullptr && !rowText.isEmpty())
        {
            clipboard->setText(rowText);
        }
    });
}

void KernelDock::refreshSsdtAsync()
{
    if (m_ssdtRefreshRunning.exchange(true))
    {
        kLogEvent skipEvent;
        dbg << skipEvent << "[KernelDock] SSDT 刷新被忽略：已有任务运行。" << eol;
        return;
    }

    m_refreshSsdtButton->setEnabled(false);
    m_ssdtStatusLabel->setText(kernelText("kernel.ssdt.status.refreshing", QStringLiteral("状态：刷新中...")));
    m_ssdtStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::PrimaryBlueHex));

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelSsdtEntry> resultRows;
        QString errorText;
        const bool success = runSsdtSnapshotTask(resultRows, errorText);

        QMetaObject::invokeMethod(guardThis, [guardThis, success, errorText, resultRows = std::move(resultRows)]() mutable {
            const auto deferredRows =
                std::make_shared<std::vector<KernelSsdtEntry>>(std::move(resultRows));
            auto commitResult = [guardThis, success, errorText, deferredRows]() mutable
            {
            std::vector<KernelSsdtEntry>& resultRows = *deferredRows;
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->m_ssdtRefreshRunning.store(false);
            guardThis->m_refreshSsdtButton->setEnabled(true);

            if (!success)
            {
                guardThis->m_ssdtStatusLabel->setText(kernelText("kernel.ssdt.status.failed", QStringLiteral("状态：刷新失败")));
                guardThis->m_ssdtStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::ErrorHex()));
                guardThis->m_ssdtDetailEditor->setDocument(ks::ui::FieldDocument{}.note(errorText));
                return;
            }

            guardThis->m_ssdtRows = std::move(resultRows);
            guardThis->rebuildSsdtTable(guardThis->m_ssdtFilterEdit->text().trimmed());

            std::size_t unresolvedCount = 0U;
            for (const KernelSsdtEntry& entry : guardThis->m_ssdtRows)
            {
                if (!entry.indexResolved)
                {
                    ++unresolvedCount;
                }
            }

            guardThis->m_ssdtStatusLabel->setText(
                kernelText("kernel.ssdt.status.summary", QStringLiteral("状态：已刷新 %1 项，未解析索引 %2 项"))
                .arg(guardThis->m_ssdtRows.size())
                .arg(unresolvedCount));
            guardThis->m_ssdtStatusLabel->setStyleSheet(
                statusLabelStyle(unresolvedCount == 0U ? KswordTheme::SuccessHex() : KswordTheme::WarningHex()));

            if (guardThis->m_ssdtTable->rowCount() > 0)
            {
                guardThis->m_ssdtTable->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->m_ssdtDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.ssdt.empty", QStringLiteral("当前环境未返回可见 SSDT 条目。"))));
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-ssdt-snapshot-apply"),
                { guardThis->m_ssdtTable },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::rebuildSsdtTable(const QString& filterKeyword)
{
    if (m_ssdtTable == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_ssdtDetailEditor);

    m_ssdtTable->setSortingEnabled(false);
    m_ssdtTable->setRowCount(0);

    for (std::size_t sourceIndex = 0; sourceIndex < m_ssdtRows.size(); ++sourceIndex)
    {
        const KernelSsdtEntry& entry = m_ssdtRows[sourceIndex];
        const QString indexText = entry.indexResolved
            ? QString::number(entry.serviceIndex)
            : kernelText("kernel.ssdt.placeholder.unknown", QStringLiteral("<未知>"));
        const QString zwAddressText = formatAddressHex(entry.zwRoutineAddress);
        const QString serviceAddressText = formatAddressHex(entry.serviceRoutineAddress);
        const QString slotAddressText =
            formatAddressHex(entry.tableEntryAddress);

        const bool matched = filterKeyword.isEmpty()
            || indexText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.serviceNameText.contains(filterKeyword, Qt::CaseInsensitive)
            || zwAddressText.contains(filterKeyword, Qt::CaseInsensitive)
            || serviceAddressText.contains(filterKeyword, Qt::CaseInsensitive)
            || slotAddressText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.moduleNameText.contains(filterKeyword, Qt::CaseInsensitive);
        if (!matched)
        {
            continue;
        }

        const int rowIndex = m_ssdtTable->rowCount();
        m_ssdtTable->insertRow(rowIndex);

        auto* indexItem = new QTableWidgetItem(indexText);
        indexItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        auto* serviceNameItem = new QTableWidgetItem(safeText(entry.serviceNameText));
        auto* zwAddressItem = new QTableWidgetItem(zwAddressText);
        auto* serviceAddressItem = new QTableWidgetItem(serviceAddressText);
        auto* slotAddressItem = new QTableWidgetItem(slotAddressText);
        auto* moduleItem = new QTableWidgetItem(safeText(entry.moduleNameText));

        indexItem->setFlags(indexItem->flags() & ~Qt::ItemIsEditable);
        serviceNameItem->setFlags(serviceNameItem->flags() & ~Qt::ItemIsEditable);
        zwAddressItem->setFlags(zwAddressItem->flags() & ~Qt::ItemIsEditable);
        serviceAddressItem->setFlags(serviceAddressItem->flags() & ~Qt::ItemIsEditable);
        slotAddressItem->setFlags(slotAddressItem->flags() & ~Qt::ItemIsEditable);
        moduleItem->setFlags(moduleItem->flags() & ~Qt::ItemIsEditable);

        m_ssdtTable->setItem(rowIndex, static_cast<int>(SsdtColumn::Index), indexItem);
        m_ssdtTable->setItem(rowIndex, static_cast<int>(SsdtColumn::ServiceName), serviceNameItem);
        m_ssdtTable->setItem(rowIndex, static_cast<int>(SsdtColumn::ZwAddress), zwAddressItem);
        m_ssdtTable->setItem(rowIndex, static_cast<int>(SsdtColumn::ServiceAddress), serviceAddressItem);
        m_ssdtTable->setItem(rowIndex, static_cast<int>(SsdtColumn::SlotAddress), slotAddressItem);
        m_ssdtTable->setItem(rowIndex, static_cast<int>(SsdtColumn::Module), moduleItem);
    }

    m_ssdtTable->setSortingEnabled(true);
}

void KernelDock::restoreSelectedSsdtBaseline()
{
    const KernelSsdtEntry* selected = currentSsdtEntry();
    if (selected == nullptr
        || !selected->cleanBaselineAvailable
        || !selected->cleanBaselineDiffers
        || selected->tableEntryAddress == 0U
        || selected->tableEntrySize == 0U
        || selected->currentTableBytes.size() != selected->tableEntrySize
        || selected->cleanTableBytes.size() != selected->tableEntrySize)
    {
        QMessageBox::information(
            this,
            kernelText(
                "kernel.ssdt.restore.title",
                QStringLiteral("SSDT 槽位恢复")),
            kernelText(
                "kernel.ssdt.restore.unavailable",
                QStringLiteral(
                    "当前行没有通过映像身份校验的差异基线，不能恢复。")));
        return;
    }

    const KernelSsdtEntry snapshot = *selected;
    const ksword::ark::DriverClient client;
    const ksword::ark::KernelInlinePatchResult preflight =
        client.patchInlineHook(
            snapshot.tableEntryAddress,
            KSWORD_ARK_INLINE_PATCH_MODE_RESTORE_BYTES,
            snapshot.tableEntrySize,
            snapshot.currentTableBytes,
            snapshot.cleanTableBytes,
            0UL);
    if (!preflight.io.ok
        || preflight.status
            != KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED)
    {
        QMessageBox::critical(
            this,
            kernelText(
                "kernel.ssdt.restore.title",
                QStringLiteral("SSDT 槽位恢复")),
            kernelText(
                "kernel.ssdt.restore.preflight_failed",
                QStringLiteral(
                    "R0 恢复预检失败，未写入任何内容。\nWin32=%1\n状态=%2\nNT=0x%3"))
                .arg(preflight.io.win32Error)
                .arg(preflight.status)
                .arg(static_cast<unsigned long>(preflight.lastStatus),
                    8,
                    16,
                    QChar('0')));
        return;
    }

    const QMessageBox::StandardButton warning =
        QMessageBox::warning(
            this,
            kernelText(
                "kernel.ssdt.restore.warning.title",
                QStringLiteral("高风险内核表项恢复")),
            kernelText(
                "kernel.ssdt.restore.warning.body",
                QStringLiteral(
                    "即将把 SSDT[%1] 槽位从当前编码值 0x%2 恢复为磁盘基线 0x%3。\n\n"
                    "R0 会在写入前再次逐字节比较当前值；任何并发变化都会使操作失败。"
                    "错误恢复可能立即导致系统崩溃。\n\n映像：%4"))
                .arg(snapshot.serviceIndex)
                .arg(static_cast<qulonglong>(snapshot.currentTableValue),
                    0,
                    16)
                .arg(static_cast<qulonglong>(snapshot.cleanTableValue),
                    0,
                    16)
                .arg(snapshot.cleanBaselinePath),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
    if (warning != QMessageBox::Yes)
    {
        return;
    }

    // 最终确认改为直接点击：不再要求输入确认短语，默认聚焦“否”避免误触。
    const auto confirmation = QMessageBox::warning(
        this,
        kernelText(
            "kernel.ssdt.restore.confirm.title",
            QStringLiteral("最终确认")),
        kernelText(
            "kernel.ssdt.restore.confirm.final",
            QStringLiteral("确认按基线恢复该 SSDT 表项？该操作会改写内核数据。")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmation != QMessageBox::Yes)
    {
        return;
    }

    m_restoreSsdtButton->setEnabled(false);
    const ksword::ark::KernelInlinePatchResult applied =
        client.patchInlineHook(
            snapshot.tableEntryAddress,
            KSWORD_ARK_INLINE_PATCH_MODE_RESTORE_BYTES,
            snapshot.tableEntrySize,
            snapshot.currentTableBytes,
            snapshot.cleanTableBytes,
            KSWORD_ARK_KERNEL_PATCH_FLAG_FORCE);
    if (!applied.io.ok
        || applied.status != KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED
        || applied.bytesPatched != snapshot.tableEntrySize)
    {
        QMessageBox::critical(
            this,
            kernelText(
                "kernel.ssdt.restore.title",
                QStringLiteral("SSDT 槽位恢复")),
            kernelText(
                "kernel.ssdt.restore.failed",
                QStringLiteral(
                    "恢复失败或当前槽值已变化。\nWin32=%1\n状态=%2\nNT=0x%3\n写入=%4"))
                .arg(applied.io.win32Error)
                .arg(applied.status)
                .arg(static_cast<unsigned long>(applied.lastStatus),
                    8,
                    16,
                    QChar('0'))
                .arg(applied.bytesPatched));
        refreshSsdtAsync();
        return;
    }

    QMessageBox::information(
        this,
        kernelText(
            "kernel.ssdt.restore.title",
            QStringLiteral("SSDT 槽位恢复")),
        kernelText(
            "kernel.ssdt.restore.success",
            QStringLiteral(
                "槽位已按验证基线恢复，并已触发重新扫描。")));
    refreshSsdtAsync();
}

bool KernelDock::currentSsdtSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0U;

    if (m_ssdtTable == nullptr)
    {
        return false;
    }

    const int currentRow = m_ssdtTable->currentRow();
    if (currentRow < 0)
    {
        return false;
    }

    QTableWidgetItem* indexItem = m_ssdtTable->item(currentRow, static_cast<int>(SsdtColumn::Index));
    if (indexItem == nullptr)
    {
        return false;
    }

    sourceIndexOut = static_cast<std::size_t>(indexItem->data(Qt::UserRole).toULongLong());
    return sourceIndexOut < m_ssdtRows.size();
}

const KernelSsdtEntry* KernelDock::currentSsdtEntry() const
{
    std::size_t sourceIndex = 0U;
    if (!currentSsdtSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &m_ssdtRows[sourceIndex];
}

void KernelDock::showSsdtDetailByCurrentRow()
{
    if (m_ssdtDetailEditor == nullptr)
    {
        return;
    }

    const KernelSsdtEntry* entry = currentSsdtEntry();
    if (entry == nullptr)
    {
        m_ssdtDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.ssdt.detail.initial", QStringLiteral("请选择一条 SSDT 记录查看详情。"))));
        return;
    }

    ks::ui::FieldDocument detailText;
    detailText.field(QStringLiteral("服务索引"), QStringLiteral("%1").arg(entry->indexResolved ? QString::number(entry->serviceIndex) : kernelText("kernel.ssdt.placeholder.unknown", QStringLiteral("<未知>"))));
    detailText.field(QStringLiteral("服务名"), QStringLiteral("%1").arg(safeText(entry->serviceNameText)));
    detailText.field(QStringLiteral("模块"), QStringLiteral("%1").arg(safeText(entry->moduleNameText)));
    detailText.field(QStringLiteral("Zw导出地址"), QStringLiteral("%1").arg(formatAddressHex(entry->zwRoutineAddress)));
    detailText.field(QStringLiteral("服务表基址"), QStringLiteral("%1").arg(formatAddressHex(entry->serviceTableBase)));
    detailText.field(QStringLiteral("表项服务地址"), QStringLiteral("%1").arg(formatAddressHex(entry->serviceRoutineAddress)));
    detailText.field(QStringLiteral("槽位地址"), QStringLiteral("%1").arg(formatAddressHex(entry->tableEntryAddress)));
    detailText.field(QStringLiteral("当前编码值"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(entry->currentTableValue), 0, 16)));
    detailText.field(QStringLiteral("磁盘基线值"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(entry->cleanTableValue), 0, 16)));
    detailText.field(QStringLiteral("基线状态"), QStringLiteral("%1").arg(safeText(entry->cleanBaselineStatus)));
    detailText.field(QStringLiteral("状态"), QStringLiteral("%1").arg(safeText(entry->statusText)));
    detailText.field(QStringLiteral("标志"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<unsigned int>(entry->flags), 8, 16, QChar('0'))));
    detailText.section(QStringLiteral("Worker详情"));
    detailText.nodes.last().children = entry->detailDocument.nodes;

    m_ssdtDetailEditor->setDocument(detailText);
}
