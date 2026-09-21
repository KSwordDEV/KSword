#include "KernelDriverStartIoTab.h"

#include "KernelDeviceDriverObjectsWorker.h"
#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QSet>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    QString buttonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    QString headerStyle()
    {
        return QStringLiteral("QHeaderView::section{color:%1;background:transparent;border:1px solid %2;font-weight:600;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex());
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }
}

KernelDriverStartIoTab::KernelDriverStartIoTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelDriverStartIoTab::requestInitialRefresh()
{
    if (m_initialRefreshRequested)
    {
        return;
    }

    m_initialRefreshRequested = true;
    refreshAsync();
}

void KernelDriverStartIoTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        kernelText("kernel.start_io.refresh", QStringLiteral("刷新 StartIo")),
        this);
    m_refreshButton->setStyleSheet(buttonStyle());
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setPlaceholderText(kernelText(
        "kernel.start_io.filter.placeholder",
        QStringLiteral("筛选驱动、模块或地址...")));
    m_filterEdit->setMinimumWidth(280);
    m_clearFilterButton = new QPushButton(
        kernelText("kernel.start_io.filter.clear", QStringLiteral("清除筛选")),
        this);
    m_clearFilterButton->setStyleSheet(buttonStyle());
    m_statusLabel = new QLabel(
        kernelText("kernel.start_io.loading", QStringLiteral("等待查询 DriverObject->DriverStartIo。")),
        this);
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_filterEdit);
    toolbar->addWidget(m_clearFilterButton);
    toolbar->addWidget(m_statusLabel, 1);
    rootLayout->addLayout(toolbar);

    m_table = new ks::ui::VisibleTableWidget(this);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->setStyleSheet(QStringLiteral("QTableWidget{background:transparent;color:%1;}").arg(KswordTheme::TextPrimaryHex()));
    m_table->horizontalHeader()->setStyleSheet(headerStyle());
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->setColumnCount(8);
    m_table->setHorizontalHeaderLabels({
        kernelText("kernel.start_io.header.driver", QStringLiteral("DriverObject")),
        kernelText("kernel.start_io.header.object_address", QStringLiteral("对象地址")),
        kernelText("kernel.start_io.header.state", QStringLiteral("状态")),
        kernelText("kernel.start_io.header.address", QStringLiteral("StartIo 地址")),
        kernelText("kernel.start_io.header.module_base", QStringLiteral("模块基址")),
        kernelText("kernel.start_io.header.module", QStringLiteral("归属模块")),
        kernelText("kernel.start_io.header.image_path", QStringLiteral("镜像路径")),
        QStringLiteral("NTSTATUS")});
    rootLayout->addWidget(m_table, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this](const QString&) { applyFilter(); });
    connect(m_clearFilterButton, &QPushButton::clicked, this, [this]() {
        if (m_filterEdit != nullptr)
        {
            m_filterEdit->clear();
        }
    });
    connect(m_table, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showCopyMenu(position);
    });
}

void KernelDriverStartIoTab::refreshAsync()
{
    if (m_refreshRunning)
    {
        return;
    }
    m_refreshRunning = true;
    m_refreshButton->setEnabled(false);
    m_statusLabel->setText(kernelText(
        "kernel.start_io.refreshing",
        QStringLiteral("正在枚举 DriverObject 并读取 DriverStartIo...")));
    QPointer<KernelDriverStartIoTab> safeThis(this);
    std::thread([safeThis]() {
        Snapshot snapshot;
        std::vector<KernelDeviceDriverObjectEntry> objectRows;
        QString workerError;
        const bool workerOk = runKernelDeviceDriverObjectsSnapshotTask(objectRows, workerError);
        if (!workerOk)
        {
            snapshot.errorText = workerError;
        }

        ksword::ark::DriverClient client;
        if (workerOk)
        {
            QSet<QString> seenDriverNames;
            for (const KernelDeviceDriverObjectEntry& objectRow : objectRows)
            {
                if (objectRow.isScopeEntry ||
                    objectRow.objectTypeText.compare(QStringLiteral("Driver"), Qt::CaseInsensitive) != 0)
                {
                    continue;
                }
                const QString driverPath = objectRow.fullPathText.trimmed();
                const QString normalizedDriverPath = driverPath.toCaseFolded();
                if (driverPath.isEmpty() || seenDriverNames.contains(normalizedDriverPath))
                {
                    continue;
                }
                seenDriverNames.insert(normalizedDriverPath);

                StartIoRow row;
                row.driverName = driverPath;
                const ksword::ark::DriverObjectQueryResult query =
                    client.queryDriverObject(driverPath.toStdWString());
                row.lastStatus = static_cast<std::int32_t>(query.lastStatus);
                if (!query.io.ok)
                {
                    ++snapshot.queryFailureCount;
                    row.queryError = query.io.message.empty()
                        ? QStringLiteral("DriverObject 查询失败")
                        : QString::fromStdString(query.io.message);
                    snapshot.rows.push_back(std::move(row));
                    continue;
                }

                row.driverObjectAddress = query.driverObjectAddress;
                row.imagePath = QString::fromStdWString(query.imagePath);
                row.state = query.startIo.state;
                row.startIoAddress = query.startIo.address;
                row.moduleBase = query.startIo.moduleBase;
                row.moduleName = QString::fromStdWString(query.startIo.moduleName);
                row.flags = query.startIo.flags;
                switch (row.state)
                {
                case KSWORD_ARK_DRIVER_START_IO_STATE_PRESENT:
                    ++snapshot.presentCount;
                    break;
                case KSWORD_ARK_DRIVER_START_IO_STATE_NULL:
                    ++snapshot.nullCount;
                    break;
                case KSWORD_ARK_DRIVER_START_IO_STATE_READ_FAILED:
                    ++snapshot.readFailedCount;
                    break;
                default:
                    ++snapshot.notQueriedCount;
                    break;
                }
                snapshot.rows.push_back(std::move(row));
            }
        }

        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(safeThis, [safeThis, snapshot = std::move(snapshot)]() mutable {
            if (safeThis != nullptr)
            {
                safeThis->applySnapshot(std::move(snapshot));
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDriverStartIoTab::applySnapshot(Snapshot snapshot)
{
    const QPointer<KernelDriverStartIoTab> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-driver-start-io-snapshot"),
        { m_table },
        [safeThis, snapshot]() mutable
        {
            if (!safeThis.isNull())
            {
                safeThis->applySnapshot(std::move(snapshot));
            }
        }))
    {
        return;
    }

    m_refreshRunning = false;
    m_refreshButton->setEnabled(true);
    m_rows = std::move(snapshot.rows);
    m_presentCount = snapshot.presentCount;
    m_nullCount = snapshot.nullCount;
    m_readFailedCount = snapshot.readFailedCount;
    m_queryFailureCount = snapshot.queryFailureCount;
    m_notQueriedCount = snapshot.notQueriedCount;
    m_errorText = std::move(snapshot.errorText);
    populateTable();
}

QString KernelDriverStartIoTab::hex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0'));
}

QString KernelDriverStartIoTab::hex32(const std::uint32_t value)
{
    return QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0'));
}

QString KernelDriverStartIoTab::stateText(const StartIoRow& row) const
{
    if (!row.queryError.isEmpty())
    {
        return kernelText("kernel.start_io.state.query_failed", QStringLiteral("查询失败：%1")).arg(row.queryError);
    }
    switch (row.state)
    {
    case KSWORD_ARK_DRIVER_START_IO_STATE_PRESENT:
        return (row.flags & KSWORD_ARK_DRIVER_START_IO_FLAG_OWN_IMAGE) != 0U
            ? kernelText("kernel.start_io.state.own_image", QStringLiteral("非空 · 本驱动镜像"))
            : ((row.flags & KSWORD_ARK_DRIVER_START_IO_FLAG_MODULE_RESOLVED) != 0U
                ? kernelText("kernel.start_io.state.external_module", QStringLiteral("非空 · 外部模块"))
                : kernelText("kernel.start_io.state.unresolved", QStringLiteral("非空 · 模块未解析")));
    case KSWORD_ARK_DRIVER_START_IO_STATE_NULL:
        return kernelText("kernel.start_io.state.null", QStringLiteral("空值"));
    case KSWORD_ARK_DRIVER_START_IO_STATE_READ_FAILED:
        return kernelText("kernel.start_io.state.read_failed", QStringLiteral("读取失败"));
    default:
        return kernelText("kernel.start_io.state.not_queried", QStringLiteral("未查询（驱动协议较旧）"));
    }
}

void KernelDriverStartIoTab::populateTable()
{
    m_table->setRowCount(0);
    for (const StartIoRow& row : m_rows)
    {
        // 空值与读取失败都没有地址可展示，统一渲染成 "-"；
        // 两者的区别只由状态列承担，绝不用 0 地址冒充空值。
        const bool hasAddress = row.queryError.isEmpty() &&
            row.state == KSWORD_ARK_DRIVER_START_IO_STATE_PRESENT;
        const int tableRow = m_table->rowCount();
        m_table->insertRow(tableRow);
        m_table->setItem(tableRow, 0, readOnlyItem(row.driverName));
        m_table->setItem(tableRow, 1, readOnlyItem(hex64(row.driverObjectAddress)));
        m_table->setItem(tableRow, 2, readOnlyItem(stateText(row)));
        m_table->setItem(tableRow, 3, readOnlyItem(hasAddress ? hex64(row.startIoAddress) : QStringLiteral("-")));
        m_table->setItem(tableRow, 4, readOnlyItem(hasAddress ? hex64(row.moduleBase) : QStringLiteral("-")));
        m_table->setItem(tableRow, 5, readOnlyItem(row.moduleName.isEmpty() ? QStringLiteral("-") : row.moduleName));
        m_table->setItem(tableRow, 6, readOnlyItem(row.imagePath.isEmpty() ? QStringLiteral("-") : row.imagePath));
        m_table->setItem(tableRow, 7, readOnlyItem(hex32(static_cast<std::uint32_t>(row.lastStatus))));
    }
    m_table->resizeColumnsToContents();
    applyFilter();

    const QString summary = kernelText(
        "kernel.start_io.summary",
        QStringLiteral("驱动 %1 个：非空 %2，空值 %3，读取失败 %4，查询失败 %5，未查询 %6。"))
        .arg(static_cast<qulonglong>(m_rows.size()))
        .arg(m_presentCount)
        .arg(m_nullCount)
        .arg(m_readFailedCount)
        .arg(m_queryFailureCount)
        .arg(m_notQueriedCount);
    m_statusLabel->setText(m_errorText.isEmpty() ? summary : summary + QStringLiteral(" ") + m_errorText);
}

void KernelDriverStartIoTab::applyFilter()
{
    const QString filterText = m_filterEdit == nullptr ? QString() : m_filterEdit->text().trimmed();
    const bool hasFilter = !filterText.isEmpty();
    if (m_table != nullptr)
    {
        for (int row = 0; row < m_table->rowCount(); ++row)
        {
            bool matched = !hasFilter;
            for (int column = 0; !matched && column < m_table->columnCount(); ++column)
            {
                const QTableWidgetItem* item = m_table->item(row, column);
                matched = item != nullptr && item->text().contains(filterText, Qt::CaseInsensitive);
            }
            m_table->setRowHidden(row, !matched);
        }
    }
    if (m_clearFilterButton != nullptr)
    {
        m_clearFilterButton->setEnabled(hasFilter);
    }
}

QString KernelDriverStartIoTab::tableRowText(QTableWidget* table, const int row, const bool includeHeader)
{
    if (table == nullptr || row < 0 || row >= table->rowCount())
    {
        return {};
    }
    QStringList values;
    if (includeHeader)
    {
        for (int column = 0; column < table->columnCount(); ++column)
        {
            values << table->horizontalHeaderItem(column)->text();
        }
    }
    QStringList rowValues;
    for (int column = 0; column < table->columnCount(); ++column)
    {
        rowValues << (table->item(row, column) == nullptr ? QString() : table->item(row, column)->text());
    }
    values << rowValues.join(QLatin1Char('\t'));
    return values.join(QLatin1Char('\n'));
}

void KernelDriverStartIoTab::showCopyMenu(const QPoint& position)
{
    if (m_table == nullptr)
    {
        return;
    }
    const QModelIndex index = m_table->indexAt(position);
    const int row = index.isValid() ? index.row() : -1;
    QMenu menu(this);
    QAction* copyRow = menu.addAction(kernelText("kernel.start_io.copy_row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(kernelText("kernel.start_io.copy_all", QStringLiteral("复制全部行")));
    copyRow->setEnabled(row >= 0);
    copyAll->setEnabled(m_table->rowCount() > 0);
    QAction* selected = menu.exec(m_table->viewport()->mapToGlobal(position));
    if (selected == copyRow)
    {
        QApplication::clipboard()->setText(tableRowText(m_table, row, true));
    }
    else if (selected == copyAll)
    {
        QStringList lines;
        for (int rowIndex = 0; rowIndex < m_table->rowCount(); ++rowIndex)
        {
            lines << tableRowText(m_table, rowIndex, rowIndex == 0);
        }
        QApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
    }
}
