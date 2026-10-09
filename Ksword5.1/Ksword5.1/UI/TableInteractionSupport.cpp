#include "TableInteractionSupport.h"

#include "../Internationalization/LanguageManager.h"
#include "../theme.h"
#include "TableFreezeSupport.h"
#include "TableHeaderSortingSupport.h"
#include "TableSnapshotCompare.h"
#include "TableSearchSupport.h"
#include "VisibleTableWidget.h"
#include "ResultTableHost.h"
#include "UiCommitCoordinator.h"
#include "TablePresentation.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QDateTime>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QHash>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QTreeView>
#include <QIcon>
#include <QItemSelectionModel>
#include <QKeyEvent>
#include <QKeySequence>
#include <QLabel>
#include <QComboBox>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPalette>
#include <QPointer>
#include <QPushButton>
#include <QSaveFile>
#include <QScrollArea>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QSpinBox>
#include <QStringConverter>
#include <QTableView>
#include <QTextStream>
#include <QTimer>
#include <QToolButton>
#include <QVariant>
#include <QVector>
#include <QWheelEvent>
#include <QWidget>
#include <QWidgetAction>

#include <algorithm>
#include <utility>

namespace
{
    using ks::ui::TableComparisonModel;
    using ks::ui::TableComparisonResult;
    using ks::ui::TableFrozenPaneController;
    using ks::ui::TablePausedSnapshotModel;
    using ks::ui::TableSnapshot;
    using ks::ui::TableSnapshotCaptureLimits;
    using ks::ui::TableSnapshotColumn;
    using ks::ui::TableSnapshotCompareEngine;
    using ks::ui::TableSnapshotComparisonLimits;
    using ks::ui::TableSnapshotRetentionLimits;
    using ks::ui::TableSnapshotRetentionResult;
    using ks::ui::TableActionBarMode;

    constexpr char kInstalledProperty[] = "KSWORD_TABLE_INTERACTION_SUPPORT_INSTALLED";
    constexpr char kActionBarProperty[] = "KSWORD_TABLE_INTERACTION_ACTION_BAR";
    constexpr char kStandardContextMenuProperty[] = "KSWORD_TABLE_INTERACTION_STANDARD_CONTEXT_MENU";
    constexpr char kContextActionsInstalledProperty[] = "KSWORD_TABLE_INTERACTION_CONTEXT_ACTIONS_INSTALLED";
    constexpr char kComparisonActiveProperty[] = "KSWORD_TABLE_INTERACTION_COMPARISON_ACTIVE";
    constexpr int kActionBarHeight = 32;
    constexpr quint64 kBytesPerMiB = 1024ULL * 1024ULL;
    constexpr TableSnapshotCaptureLimits kSnapshotCaptureLimits{};
    constexpr TableSnapshotComparisonLimits kSnapshotComparisonLimits{};
    constexpr TableSnapshotRetentionLimits kSnapshotRetentionLimits{};

    // 菜单来源仍由表格过滤器识别，状态和异步提交队列统一交给协调器。
    void beginItemViewContextMenu(QAbstractItemView* itemView)
    {
        if (auto* const coordinator = ks::ui::UiCommitCoordinator::forApplication())
        {
            coordinator->beginContextMenu(itemView);
        }
    }

    void endItemViewContextMenu(QAbstractItemView* itemView)
    {
        if (auto* const coordinator = ks::ui::UiCommitCoordinator::forApplication())
        {
            coordinator->endContextMenu(itemView);
        }
    }

    QString localizedSourceText(const char* sourceText)
    {
        return ks::i18n::sourceText(QString::fromUtf8(sourceText));
    }

    QTableView* tableForEventObject(QObject* watchedObject)
    {
        if (QTableView* tableView = qobject_cast<QTableView*>(watchedObject))
        {
            return tableView;
        }

        QTableView* tableView = qobject_cast<QTableView*>(watchedObject != nullptr
            ? watchedObject->parent()
            : nullptr);
        if (tableView != nullptr && watchedObject == tableView->viewport())
        {
            return tableView;
        }
        return nullptr;
    }

    // itemViewForEventObject 作用：
    // - 把 QTableView/QTreeView 本体、viewport 或其 QHeaderView 统一还原为业务视图；
    // - 仅用于菜单生命周期屏障，不改变全局表格操作栏的适用范围。
    QAbstractItemView* itemViewForEventObject(QObject* watchedObject)
    {
        QHeaderView* headerView = qobject_cast<QHeaderView*>(watchedObject);
        if (headerView == nullptr)
        {
            QHeaderView* parentHeader = qobject_cast<QHeaderView*>(
                watchedObject != nullptr ? watchedObject->parent() : nullptr);
            if (parentHeader != nullptr && watchedObject == parentHeader->viewport())
            {
                headerView = parentHeader;
            }
        }
        if (headerView != nullptr)
        {
            if (QAbstractItemView* parentItemView =
                    qobject_cast<QAbstractItemView*>(headerView->parent()))
            {
                return parentItemView;
            }
        }

        if (QAbstractItemView* itemView = qobject_cast<QAbstractItemView*>(watchedObject))
        {
            return itemView;
        }

        QAbstractItemView* itemView = qobject_cast<QAbstractItemView*>(
            watchedObject != nullptr ? watchedObject->parent() : nullptr);
        if (itemView != nullptr && watchedObject == itemView->viewport())
        {
            return itemView;
        }
        return nullptr;
    }

    QString normalizedTsvField(const QVariant& value)
    {
        QString text = value.toString();
        text.replace(QLatin1Char('\t'), QLatin1Char(' '));
        text.replace(QLatin1Char('\r'), QLatin1Char(' '));
        text.replace(QLatin1Char('\n'), QLatin1Char(' '));
        return text;
    }

    /*
     * 复制、导出、快照比对都只取"可见"行列，而冻结是靠 setRowHidden/setColumnHidden
     * 实现的，与筛选共用同一个状态位。若不区分，用户特意钉住的行列反而会从导出的
     * 取证数据里消失，且没有任何提示。这里只把真正被筛掉的算作不可见。
     */
    bool isRowHiddenByFilter(const QTableView* tableView, const int row)
    {
        if (tableView == nullptr)
        {
            return false;
        }
        return tableView->isRowHidden(row) && !ks::ui::isRowHiddenByFreeze(tableView, row);
    }

    bool isColumnHiddenByFilter(const QTableView* tableView, const int column)
    {
        if (tableView == nullptr)
        {
            return false;
        }
        return tableView->isColumnHidden(column) && !ks::ui::isColumnHiddenByFreeze(tableView, column);
    }

    QVector<int> selectedVisibleRows(QTableView* tableView, const bool includeCurrentFallback)
    {
        QVector<int> rowList;
        if (tableView == nullptr || tableView->model() == nullptr || tableView->selectionModel() == nullptr)
        {
            return rowList;
        }

        const QModelIndexList selectedIndexList = tableView->selectionModel()->selectedIndexes();
        rowList.reserve(selectedIndexList.size());
        for (const QModelIndex& index : selectedIndexList)
        {
            if (index.isValid() && !isRowHiddenByFilter(tableView, index.row()))
            {
                rowList.push_back(index.row());
            }
        }

        std::sort(rowList.begin(), rowList.end());
        rowList.erase(std::unique(rowList.begin(), rowList.end()), rowList.end());

        if (rowList.isEmpty() && includeCurrentFallback)
        {
            const QModelIndex currentIndex = tableView->currentIndex();
            if (currentIndex.isValid() && !isRowHiddenByFilter(tableView, currentIndex.row()))
            {
                rowList.push_back(currentIndex.row());
            }
        }
        return rowList;
    }

    QVector<int> allVisibleRows(QTableView* tableView)
    {
        QVector<int> rowList;
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return rowList;
        }

        const int rowCount = tableView->model()->rowCount();
        rowList.reserve(rowCount);
        for (int row = 0; row < rowCount; ++row)
        {
            if (!isRowHiddenByFilter(tableView, row))
            {
                rowList.push_back(row);
            }
        }
        return rowList;
    }

    QVector<int> visibleColumns(const QTableView* tableView)
    {
        QVector<int> columnList;
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return columnList;
        }

        const int columnCount = tableView->model()->columnCount();
        columnList.reserve(columnCount);
        for (int column = 0; column < columnCount; ++column)
        {
            if (!isColumnHiddenByFilter(tableView, column))
            {
                columnList.push_back(column);
            }
        }
        return columnList;
    }

    QString tableRowsToTsv(
        QTableView* tableView,
        const QVector<int>& rowList,
        const bool includeHeader)
    {
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return {};
        }

        QAbstractItemModel* modelObject = tableView->model();
        const QVector<int> columnList = visibleColumns(tableView);
        if (rowList.isEmpty() || columnList.isEmpty())
        {
            return {};
        }

        QStringList lineList;
        lineList.reserve(rowList.size() + (includeHeader ? 1 : 0));
        if (includeHeader)
        {
            QStringList headerList;
            headerList.reserve(columnList.size());
            for (const int column : columnList)
            {
                headerList.push_back(normalizedTsvField(
                    modelObject->headerData(column, Qt::Horizontal, Qt::DisplayRole)));
            }
            lineList.push_back(headerList.join(QLatin1Char('\t')));
        }

        for (const int row : rowList)
        {
            if (row < 0 || row >= modelObject->rowCount() || isRowHiddenByFilter(tableView, row))
            {
                continue;
            }

            QStringList valueList;
            valueList.reserve(columnList.size());
            for (const int column : columnList)
            {
                valueList.push_back(normalizedTsvField(
                    modelObject->data(modelObject->index(row, column), Qt::DisplayRole)));
            }
            lineList.push_back(valueList.join(QLatin1Char('\t')));
        }

        return lineList.join(QLatin1Char('\n'));
    }

    void copyRowsToClipboard(QTableView* tableView, const QVector<int>& rowList)
    {
        if (QClipboard* clipboardObject = QApplication::clipboard())
        {
            const QString text = tableRowsToTsv(tableView, rowList, false);
            if (!text.isEmpty())
            {
                clipboardObject->setText(text);
            }
        }
    }

    void copySelectedRowsToClipboard(QTableView* tableView)
    {
        copyRowsToClipboard(tableView, selectedVisibleRows(tableView, true));
    }

    void copyVisibleRowsToClipboard(QTableView* tableView)
    {
        copyRowsToClipboard(tableView, allVisibleRows(tableView));
    }

    // copySelectedTreeRowsToClipboard 作用：
    // - 给 QTreeView/QTreeWidget 这类层级视图补上 Ctrl+C；
    // - 上面那条表格路径按“扁平行号”工作，对树没有意义（不同父节点下 row 会重复），
    //   所以这里改走 QModelIndex：用 indexBelow() 沿视觉顺序遍历，命中选中行就取一行；
    //   折叠起来的子节点会被 indexBelow 自然跳过，复制结果与用户看到的完全一致；
    // - 没有选中项时回落到当前行，与表格路径的 includeCurrentFallback 语义保持一致；
    // - 列按表头视觉顺序输出并跳过隐藏列，用户拖动过列序时复制结果跟着走。
    // 入参 treeView：目标树视图；为空或无模型时忽略。
    // 返回：无；结果写入系统剪贴板。
    void copySelectedTreeRowsToClipboard(QTreeView* treeView)
    {
        if (treeView == nullptr || treeView->model() == nullptr)
        {
            return;
        }

        QItemSelectionModel* selectionModel = treeView->selectionModel();
        QAbstractItemModel* modelObject = treeView->model();
        if (selectionModel == nullptr)
        {
            return;
        }

        // 列序：优先按表头当前视觉顺序，没有表头时退回逻辑顺序。
        QVector<int> columnList;
        const int columnCount = modelObject->columnCount(treeView->rootIndex());
        columnList.reserve(columnCount);
        QHeaderView* headerView = treeView->header();
        for (int position = 0; position < columnCount; ++position)
        {
            const int logicalColumn = headerView != nullptr
                ? headerView->logicalIndex(position)
                : position;
            if (logicalColumn >= 0 && !treeView->isColumnHidden(logicalColumn))
            {
                columnList.push_back(logicalColumn);
            }
        }
        if (columnList.isEmpty())
        {
            return;
        }

        QStringList lineList;
        for (QModelIndex walkIndex = modelObject->index(0, 0, treeView->rootIndex());
            walkIndex.isValid();
            walkIndex = treeView->indexBelow(walkIndex))
        {
            // 用 isSelected(列 0) 判定整行：这些树一律是 SelectRows，选中即整行选中。
            // 不用 isRowSelected(row, parent) 是因为它自 Qt 6.4 起已标记废弃。
            if (!selectionModel->isSelected(walkIndex))
            {
                continue;
            }

            QStringList valueList;
            valueList.reserve(columnList.size());
            for (const int column : columnList)
            {
                valueList.push_back(normalizedTsvField(
                    modelObject->data(walkIndex.sibling(walkIndex.row(), column), Qt::DisplayRole)));
            }
            lineList.push_back(valueList.join(QLatin1Char('\t')));
        }

        if (lineList.isEmpty())
        {
            const QModelIndex currentIndex = selectionModel->currentIndex();
            if (!currentIndex.isValid())
            {
                return;
            }

            QStringList valueList;
            valueList.reserve(columnList.size());
            for (const int column : columnList)
            {
                valueList.push_back(normalizedTsvField(
                    modelObject->data(currentIndex.sibling(currentIndex.row(), column), Qt::DisplayRole)));
            }
            lineList.push_back(valueList.join(QLatin1Char('\t')));
        }

        if (QClipboard* clipboardObject = QApplication::clipboard())
        {
            clipboardObject->setText(lineList.join(QLatin1Char('\n')));
        }
    }

    // exportRowsToTsv 作用：
    // - 将指定的可见表格行连同表头保存为 UTF-8 TSV 文件；
    // - 输入为表格对象、待导出行号及默认文件名前缀；
    // - 行集合为空或写入失败时展示提示，成功时由 QSaveFile 原子提交文件。
    void exportRowsToTsv(
        QTableView* tableView,
        const QVector<int>& rowList,
        const QString& defaultFileNamePrefix)
    {
        // tableText 用途：保存已按当前可见列序列化的 TSV 正文。
        const QString tableText = tableRowsToTsv(tableView, rowList, true);
        if (tableText.isEmpty())
        {
            QMessageBox::information(
                tableView,
                localizedSourceText("导出 TSV"),
                localizedSourceText("没有可导出的行。"));
            return;
        }

        // outputPath 用途：保存用户确认后的目标文件完整路径。
        QString outputPath = QFileDialog::getSaveFileName(
            tableView,
            localizedSourceText("导出 TSV"),
            defaultFileNamePrefix
                + QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))
                + QStringLiteral(".tsv"),
            localizedSourceText("TSV 文件 (*.tsv)"));
        if (outputPath.trimmed().isEmpty())
        {
            return;
        }
        if (QFileInfo(outputPath).suffix().isEmpty())
        {
            outputPath += QStringLiteral(".tsv");
        }

        // fileObject 用途：以原子替换方式写入用户选择的 TSV 文件。
        QSaveFile fileObject(outputPath);
        if (!fileObject.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            QMessageBox::warning(
                tableView,
                localizedSourceText("导出 TSV"),
                localizedSourceText("导出失败：%1").arg(fileObject.errorString()));
            return;
        }

        // outputStream 用途：以 UTF-8 编码将 TSV 正文写入临时文件。
        QTextStream outputStream(&fileObject);
        outputStream.setEncoding(QStringConverter::Utf8);
        outputStream << tableText << Qt::endl;
        if (outputStream.status() != QTextStream::Ok || !fileObject.commit())
        {
            QMessageBox::warning(
                tableView,
                localizedSourceText("导出 TSV"),
                localizedSourceText("导出失败：%1").arg(fileObject.errorString()));
        }
    }

    // exportTableToTsv 作用：导出当前表格全部可见行，供顶部全量导出按钮使用。
    void exportTableToTsv(QTableView* tableView)
    {
        exportRowsToTsv(tableView, allVisibleRows(tableView), QStringLiteral("table_export_"));
    }

    // exportSelectedRowsToTsv 作用：导出当前选中行，未选中时回退到当前焦点行。
    void exportSelectedRowsToTsv(QTableView* tableView)
    {
        exportRowsToTsv(
            tableView,
            selectedVisibleRows(tableView, true),
            QStringLiteral("table_selected_export_"));
    }

    // ComparisonTableView 同时用于比对视图和冻结视图。它继承表格外框宿主，
    // 因此冻结视图期间同样能像实时表一样预留冻结窗格所需的视口空间。
    class ComparisonTableView final
        : public ks::ui::visible_table_detail::TableChromeHostView<QTableView>
    {
    public:
        using TableChromeHostView<QTableView>::TableChromeHostView;

    protected:
        void wheelEvent(QWheelEvent* eventObject) override
        {
            if (eventObject == nullptr)
            {
                return;
            }

            const QPoint pixelDeltaPoint = eventObject->pixelDelta();
            const QPoint angleDeltaPoint = eventObject->angleDelta();
            const bool horizontal = eventObject->modifiers().testFlag(Qt::ShiftModifier) ||
                std::abs(pixelDeltaPoint.x()) > std::abs(pixelDeltaPoint.y()) ||
                std::abs(angleDeltaPoint.x()) > std::abs(angleDeltaPoint.y());
            QScrollBar* scrollBar = horizontal ? horizontalScrollBar() : verticalScrollBar();
            if (scrollBar == nullptr || scrollBar->minimum() == scrollBar->maximum())
            {
                QTableView::wheelEvent(eventObject);
                return;
            }

            const int pixelDelta = horizontal
                ? (pixelDeltaPoint.x() != 0 ? pixelDeltaPoint.x() : pixelDeltaPoint.y())
                : (pixelDeltaPoint.y() != 0 ? pixelDeltaPoint.y() : pixelDeltaPoint.x());
            if (pixelDelta != 0)
            {
                scrollBar->setValue(std::clamp(
                    scrollBar->value() - pixelDelta,
                    scrollBar->minimum(),
                    scrollBar->maximum()));
                eventObject->accept();
                return;
            }

            const int angleDelta = horizontal
                ? (angleDeltaPoint.x() != 0 ? angleDeltaPoint.x() : angleDeltaPoint.y())
                : (angleDeltaPoint.y() != 0 ? angleDeltaPoint.y() : angleDeltaPoint.x());
            if (angleDelta == 0)
            {
                QTableView::wheelEvent(eventObject);
                return;
            }

            const int wheelSteps = angleDelta / 120 != 0
                ? angleDelta / 120
                : (angleDelta > 0 ? 1 : -1);
            const int distance = std::max(24, scrollBar->singleStep() * 3);
            scrollBar->setValue(std::clamp(
                scrollBar->value() - wheelSteps * distance,
                scrollBar->minimum(),
                scrollBar->maximum()));
            eventObject->accept();
        }

    };

    class TableActionBar final : public QFrame
    {
    public:
        explicit TableActionBar(QTableView* tableView, const TableActionBarMode mode)
            : QFrame(tableView)
            , m_table(tableView)
            , m_mode(mode)
        {
            setObjectName(QString::fromLatin1(kActionBarProperty));
            setFrameShape(QFrame::NoFrame);
            setFixedHeight(kActionBarHeight);
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

            // 表格操作条会同时出现在 Dock 与普通 QDialog 中，不能继续继承宿主的
            // QPushButton/QToolButton 几何样式。普通弹窗主题会为按钮增加较大的
            // padding 和粗体，曾导致插件管理页的同一套操作按钮明显大于进程页，
            // 甚至挤压 32px 高的操作条。这里用 palette 角色建立自包含的紧凑基线，
            // 保证换肤仍然生效，同时让所有 TableActionBarHost 的外观完全一致。
            setStyleSheet(QStringLiteral(
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR{"
                "  background-color:palette(base);"
                "  border:none;"
                "}"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QToolButton{"
                "  min-height:20px;"
                "  padding:2px 7px;"
                "  color:palette(text) !important;"
                "  background-color:transparent !important;"
                "  border:1px solid transparent !important;"
                "  border-radius:3px;"
                "  font-weight:400;"
                "}"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QToolButton:hover{"
                "  background-color:palette(alternate-base) !important;"
                "  border-color:transparent !important;"
                "}"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QToolButton:pressed,"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QToolButton:checked{"
                "  background-color:palette(highlight) !important;"
                "  color:palette(highlighted-text) !important;"
                "  border-color:palette(highlight) !important;"
                "}"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QToolButton:disabled{"
                "  color:palette(placeholder-text) !important;"
                "  background-color:transparent !important;"
                "  border-color:transparent !important;"
                "}"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QScrollArea,"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QScrollArea::viewport{"
                "  background-color:transparent !important;"
                "  border:none !important;"
                "}"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QCheckBox{"
                "  background-color:transparent !important;"
                "  font-weight:400;"
                "}"));

            auto* layout = new QHBoxLayout(this);
            layout->setContentsMargins(4, 2, 4, 2);
            layout->setSpacing(4);

            m_copyAllButton = createButton("复制全表", QStringLiteral(":/Icon/log_copy.svg"));
            m_exportButton = createButton("导出", QStringLiteral(":/Icon/log_export.svg"));
            m_freezePaneButton = createButton("冻结");
            m_freezePaneButton->setObjectName(QStringLiteral("ksword_table_freeze_button"));
            m_freezePaneButton->setMinimumSize(68, 28);
            m_freezePaneButton->setToolTip(localizedSourceText(
                "冻结选中的行或列：行会钉在列标题正下方，列会固定在行表头右侧；支持一次冻结多选行"));
            m_pauseRefreshButton = createButton("冻结视图");
            m_pauseRefreshButton->setCheckable(true);
            layout->addWidget(m_copyAllButton);
            layout->addWidget(m_exportButton);
            layout->addWidget(m_freezePaneButton);
            layout->addWidget(m_pauseRefreshButton);

            m_frozenPaneController = new TableFrozenPaneController(this);
            m_frozenPaneController->setTargetTable(m_table.data());

            m_freezePaneMenu = new QMenu(m_freezePaneButton);
            m_freezePaneMenu->setStyleSheet(KswordTheme::ContextMenuStyle());
            auto* freezeCountsWidget = new QWidget(m_freezePaneMenu);
            auto* freezeCountsLayout = new QGridLayout(freezeCountsWidget);
            freezeCountsLayout->setContentsMargins(10, 8, 10, 8);
            freezeCountsLayout->setHorizontalSpacing(10);
            freezeCountsLayout->setVerticalSpacing(6);
            m_freezeRowsLabel = new QLabel(localizedSourceText("前面的行"), freezeCountsWidget);
            m_freezeColumnsLabel = new QLabel(localizedSourceText("前面的列"), freezeCountsWidget);
            m_freezeRowsSpin = new QSpinBox(freezeCountsWidget);
            m_freezeColumnsSpin = new QSpinBox(freezeCountsWidget);
            m_freezeRowsSpin->setObjectName(QStringLiteral("ksword_table_freeze_row_count"));
            m_freezeColumnsSpin->setObjectName(QStringLiteral("ksword_table_freeze_column_count"));
            for (QSpinBox* spin : {m_freezeRowsSpin, m_freezeColumnsSpin})
            {
                spin->setRange(0, 0);
                spin->setMinimumSize(72, 28);
                spin->setToolTip(localizedSourceText("数量按照当前可见顺序；冻结区域最多占用视口的一半。"));
            }
            m_freezeRowsLabel->setBuddy(m_freezeRowsSpin);
            m_freezeColumnsLabel->setBuddy(m_freezeColumnsSpin);
            m_applyFreezeCountsButton = new QPushButton(localizedSourceText("应用冻结"), freezeCountsWidget);
            m_applyFreezeCountsButton->setObjectName(QStringLiteral("ksword_table_apply_freeze_counts"));
            m_applyFreezeCountsButton->setMinimumHeight(28);
            freezeCountsLayout->addWidget(m_freezeRowsLabel, 0, 0);
            freezeCountsLayout->addWidget(m_freezeRowsSpin, 0, 1);
            freezeCountsLayout->addWidget(m_freezeColumnsLabel, 1, 0);
            freezeCountsLayout->addWidget(m_freezeColumnsSpin, 1, 1);
            freezeCountsLayout->addWidget(m_applyFreezeCountsButton, 2, 0, 1, 2);
            auto* freezeCountsAction = new QWidgetAction(m_freezePaneMenu);
            freezeCountsAction->setDefaultWidget(freezeCountsWidget);
            m_freezePaneMenu->addAction(freezeCountsAction);
            m_freezePaneMenu->addSeparator();
            m_freezeCurrentRowAction = m_freezePaneMenu->addAction(
                localizedSourceText("冻结选中行"));
            m_freezeCurrentColumnAction = m_freezePaneMenu->addAction(
                localizedSourceText("冻结选中列"));
            m_freezeCurrentCellAction = m_freezePaneMenu->addAction(
                localizedSourceText("冻结选中行列"));
            m_freezePaneMenu->addSeparator();
            m_unfreezeRowsAction = m_freezePaneMenu->addAction(
                localizedSourceText("取消冻结行"));
            m_unfreezeColumnsAction = m_freezePaneMenu->addAction(
                localizedSourceText("取消冻结列"));
            m_unfreezeAllAction = m_freezePaneMenu->addAction(
                localizedSourceText("取消全部冻结"));
            m_freezePaneButton->setMenu(m_freezePaneMenu);
            m_freezePaneButton->setPopupMode(QToolButton::InstantPopup);

            m_snapshotScrollArea = new QScrollArea(this);
            m_snapshotScrollArea->setFrameShape(QFrame::NoFrame);
            m_snapshotScrollArea->setWidgetResizable(false);
            m_snapshotScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
            m_snapshotScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            m_snapshotScrollArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            m_snapshotScrollArea->setMinimumWidth(96);
            m_snapshotScrollArea->setFixedHeight(kActionBarHeight - 4);
            m_snapshotContent = new QWidget(m_snapshotScrollArea);
            m_snapshotLayout = new QHBoxLayout(m_snapshotContent);
            m_snapshotLayout->setContentsMargins(0, 0, 0, 0);
            m_snapshotLayout->setSpacing(2);
            m_snapshotScrollArea->setWidget(m_snapshotContent);
            layout->addWidget(m_snapshotScrollArea, 1);
            connect(m_snapshotScrollArea->horizontalScrollBar(), &QScrollBar::rangeChanged,
                this, [this]() { scheduleSnapshotLayout(); });

            m_addSnapshotButton = createButton("增加快照");
            m_cleanupButton = createButton("清理");
            m_doneCleanupButton = createButton("完成");
            m_deleteSelectedButton = createButton("清理选中");
            m_clearAllButton = createButton("清除全部");
            layout->addWidget(m_addSnapshotButton);
            layout->addWidget(m_cleanupButton);
            layout->addWidget(m_doneCleanupButton);
            layout->addWidget(m_deleteSelectedButton);
            layout->addWidget(m_clearAllButton);

            m_differenceOnlyCheckBox = new QCheckBox(localizedSourceText("只显示差异项"), this);
            m_differenceOnlyCheckBox->setChecked(true);
            m_ignoreColumnsButton = createButton("忽略列");
            layout->addWidget(m_differenceOnlyCheckBox);
            layout->addWidget(m_ignoreColumnsButton);

            m_currentViewButton = createButton("当前视图");
            m_currentViewButton->setCheckable(true);
            m_compareViewButton = createButton("比对视图");
            m_compareViewButton->setCheckable(true);
            layout->addWidget(m_currentViewButton);
            layout->addWidget(m_compareViewButton);

            connect(m_copyAllButton, &QToolButton::clicked, this, [this]()
                {
                    copyVisibleRowsToClipboard(activeTableView());
                });
            connect(m_exportButton, &QToolButton::clicked, this, [this]()
                {
                    exportTableToTsv(activeTableView());
                });
            connect(m_freezePaneMenu, &QMenu::aboutToShow, this, [this]()
                {
                    // ContextMenuStyle includes sampled theme colors. Refresh before
                    // native Show begins, never from a Show/Resize event filter.
                    const QString menuStyle = KswordTheme::ContextMenuStyle();
                    if (m_freezePaneMenu->styleSheet() != menuStyle) m_freezePaneMenu->setStyleSheet(menuStyle);
                    if (!m_freezeMenuBarrierActive)
                    {
                        m_freezeMenuBarrierActive = true;
                        m_freezeMenuSource = m_table;
                        beginItemViewContextMenu(m_freezeMenuSource.data());
                    }
                    updateFreezePaneMenu();
                });
            connect(m_freezePaneMenu, &QMenu::aboutToHide, this, [this]()
                {
                    closeFreezeMenuBarrier();
                });
            connect(m_applyFreezeCountsButton, &QPushButton::clicked, this, [this]()
                {
                    applyFreezeCounts();
                    m_freezePaneMenu->hide();
                });
            connect(m_freezeCurrentRowAction, &QAction::triggered, this, [this]()
                {
                    freezeToCurrentIndex(true, false);
                });
            connect(m_freezeCurrentColumnAction, &QAction::triggered, this, [this]()
                {
                    freezeToCurrentIndex(false, true);
                });
            connect(m_freezeCurrentCellAction, &QAction::triggered, this, [this]()
                {
                    freezeToCurrentIndex(true, true);
                });
            connect(m_unfreezeRowsAction, &QAction::triggered, this, [this]()
                {
                    m_frozenPaneController->clearFrozenRows();
                    updatePosition();
                    updateControls();
                });
            connect(m_unfreezeColumnsAction, &QAction::triggered, this, [this]()
                {
                    m_frozenPaneController->clearFrozenColumns();
                    updatePosition();
                    updateControls();
                });
            connect(m_unfreezeAllAction, &QAction::triggered, this, [this]()
                {
                    m_frozenPaneController->clearFrozenPanes();
                    updatePosition();
                    updateControls();
                });
            connect(m_pauseRefreshButton, &QToolButton::toggled, this, [this](const bool checked)
                {
                    setRefreshPaused(checked);
                });
            connect(m_addSnapshotButton, &QToolButton::clicked, this, [this]()
                {
                    addSnapshot();
                });
            connect(m_cleanupButton, &QToolButton::clicked, this, [this]()
                {
                    enterCleanupMode();
                });
            connect(m_doneCleanupButton, &QToolButton::clicked, this, [this]()
                {
                    leaveCleanupMode();
                });
            connect(m_deleteSelectedButton, &QToolButton::clicked, this, [this]()
                {
                    deleteSelectedSnapshots();
                });
            connect(m_clearAllButton, &QToolButton::clicked, this, [this]()
                {
                    clearAllSnapshots();
                });
            connect(m_differenceOnlyCheckBox, &QCheckBox::toggled, this, [this](const bool checked)
                {
                    if (!m_comparisonModel.isNull())
                    {
                        m_comparisonModel->setShowDifferencesOnly(checked);
                    }
                });
            connect(m_ignoreColumnsButton, &QToolButton::clicked, this, [this]()
                {
                    showIgnoredColumnsMenu();
                });
            connect(m_currentViewButton, &QToolButton::clicked, this, [this]()
                {
                    showCurrentView();
                });
            connect(m_compareViewButton, &QToolButton::clicked, this, [this]()
                {
                    showComparisonView();
                });

            m_table->installEventFilter(this);
            rebuildSnapshotControls();
            updateControls();
        }

        ~TableActionBar() override
        {
            closeFreezeMenuBarrier();
        }

    protected:
        bool eventFilter(QObject* source, QEvent* event) override
        {
            // Frozen sections are already published by the controller after model
            // resets/inserts/removes. Observe that state without polling or repolishing.
            if (source == m_table && event != nullptr && event->type() == QEvent::DynamicPropertyChange)
                updateFreezeButton();
            return QFrame::eventFilter(source, event);
        }

        void changeEvent(QEvent* eventObject) override
        {
            QFrame::changeEvent(eventObject);
            if (eventObject != nullptr && m_snapshotScrollArea != nullptr
                && (eventObject->type() == QEvent::FontChange || eventObject->type() == QEvent::StyleChange))
                scheduleSnapshotLayout();
            if (eventObject == nullptr || eventObject->type() != QEvent::LanguageChange)
            {
                return;
            }

            m_copyAllButton->setText(localizedSourceText("复制全表"));
            m_exportButton->setText(localizedSourceText("导出"));
            m_freezeRowsLabel->setText(localizedSourceText("前面的行"));
            m_freezeColumnsLabel->setText(localizedSourceText("前面的列"));
            m_applyFreezeCountsButton->setText(localizedSourceText("应用冻结"));
            for (QSpinBox* spin : {m_freezeRowsSpin, m_freezeColumnsSpin})
                spin->setToolTip(localizedSourceText("数量按照当前可见顺序；冻结区域最多占用视口的一半。"));
            m_freezePaneButton->setToolTip(localizedSourceText(
                "冻结选中的行或列：行会钉在列标题正下方，列会固定在行表头右侧；支持一次冻结多选行"));
            m_freezeCurrentRowAction->setText(localizedSourceText("冻结选中行"));
            m_freezeCurrentColumnAction->setText(localizedSourceText("冻结选中列"));
            m_freezeCurrentCellAction->setText(localizedSourceText("冻结选中行列"));
            m_unfreezeRowsAction->setText(localizedSourceText("取消冻结行"));
            m_unfreezeColumnsAction->setText(localizedSourceText("取消冻结列"));
            m_unfreezeAllAction->setText(localizedSourceText("取消全部冻结"));
            m_cleanupButton->setText(localizedSourceText("清理"));
            m_doneCleanupButton->setText(localizedSourceText("完成"));
            m_deleteSelectedButton->setText(localizedSourceText("清理选中"));
            m_clearAllButton->setText(localizedSourceText("清除全部"));
            m_differenceOnlyCheckBox->setText(localizedSourceText("只显示差异项"));
            m_ignoreColumnsButton->setText(localizedSourceText("忽略列"));
            m_currentViewButton->setText(localizedSourceText("当前视图"));
            m_compareViewButton->setText(localizedSourceText("比对视图"));
            updateControls();
        }

    public:
        void setMode(const TableActionBarMode mode)
        {
            if (m_mode == mode)
            {
                applyModeVisibility();
                return;
            }

            m_mode = mode;
            updateControls();
            updatePosition();
        }

        void updatePosition()
        {
            if (m_table.isNull())
            {
                return;
            }

            updateSnapshotContentSize();
            const bool actionBarVisible = m_mode != TableActionBarMode::None;
            auto* host = ks::ui::TableActionBarHostFor(m_table.data());
            if (host != nullptr) host->setTopActionBarHeight(actionBarVisible ? height() : 0);
            // 冻结窗格会改变视口边距，操作条位置依赖那个结果，所以必须先刷新冻结窗格。
            if (m_frozenPaneController != nullptr)
            {
                m_frozenPaneController->refreshGeometry();
            }
            if (host != nullptr)
            {
                setVisible(actionBarVisible);
                if (actionBarVisible)
                {
                    setGeometry(host->topActionBarGeometry());
                    raise();
                }
            }
            hideSourceViewportWidgets();
            updateComparisonOverlayGeometry();
        }

    private:
        QToolButton* createButton(const char* text, const QString& iconPath = QString())
        {
            auto* button = new QToolButton(this);
            button->setText(localizedSourceText(text));
            button->setAutoRaise(true);
            button->setToolButtonStyle(Qt::ToolButtonTextOnly);
            if (!iconPath.isEmpty())
            {
                button->setIcon(QIcon(iconPath));
            }
            return button;
        }

        QToolButton* createSnapshotButton(const TableSnapshot& snapshot, const bool checked)
        {
            auto* button = new QToolButton(m_snapshotContent);
            button->setText(snapshot.label + (snapshot.isTruncated() ? QStringLiteral("*") : QString()));
            button->setCheckable(true);
            button->setChecked(checked);
            button->setAutoRaise(false);
            button->setMinimumWidth(28);
            QString tooltip = localizedSourceText("快照 %1：保留 %2 行，估算 %3 MiB。")
                .arg(snapshot.label)
                .arg(snapshot.rows.size())
                .arg(QString::number(
                    static_cast<double>(snapshot.estimatedBytes) / kBytesPerMiB,
                    'f',
                    2));
            if (snapshot.isTruncated())
            {
                tooltip += QLatin1Char('\n')
                    + localizedSourceText("该快照仅覆盖源表前 %1 个扫描行；保留部分仍可用于比较，未覆盖行不会参与结果。")
                        .arg(snapshot.visitedSourceRows);
            }
            button->setToolTip(tooltip);
            button->setStyleSheet(QStringLiteral(
                "QToolButton {"
                "  padding: 2px 7px;"
                "  border: 1px solid palette(mid);"
                "  border-radius: 3px;"
                "  background-color: transparent;"
                "  color: palette(button-text);"
                "}"
                "QToolButton:hover {"
                "  border-color: palette(highlight);"
                "}"
                "QToolButton:checked {"
                "  background-color: palette(highlight);"
                "  border-color: palette(highlight);"
                "  color: palette(highlighted-text);"
                "}"));
            return button;
        }

        QTableView* activeTableView() const
        {
            if (!m_comparisonOverlay.isNull())
            {
                return m_comparisonOverlay.data();
            }
            return m_pauseOverlay.isNull() ? m_table.data() : m_pauseOverlay.data();
        }

        void updateFreezePaneMenu()
        {
            QTableView* tableView = activeTableView();
            const QModelIndex currentIndex =
                tableView != nullptr ? tableView->currentIndex() : QModelIndex();
            if (tableView != nullptr && m_frozenPaneController->targetTable() != tableView)
            {
                m_frozenPaneController->setTargetTable(tableView);
            }
            const bool currentAvailable =
                !m_inComparison &&
                !m_pauseCaptureInProgress &&
                m_frozenPaneController->canFreeze() &&
                currentIndex.isValid();

            const bool countsAvailable = !m_inComparison && !m_pauseCaptureInProgress
                && !m_snapshotCaptureInProgress && !m_comparisonInProgress
                && tableView != nullptr && tableView->model() != nullptr
                && m_frozenPaneController->canFreeze();
            const QSignalBlocker rowsBlocker(m_freezeRowsSpin);
            const QSignalBlocker columnsBlocker(m_freezeColumnsSpin);
            m_freezeRowsSpin->setRange(0, countsAvailable ? tableView->model()->rowCount() : 0);
            m_freezeColumnsSpin->setRange(0, countsAvailable ? tableView->model()->columnCount() : 0);
            m_freezeRowsSpin->setValue(m_frozenPaneController->frozenRowCount());
            m_freezeColumnsSpin->setValue(m_frozenPaneController->frozenColumnCount());
            m_freezeRowsSpin->setEnabled(countsAvailable);
            m_freezeColumnsSpin->setEnabled(countsAvailable);
            m_applyFreezeCountsButton->setEnabled(countsAvailable);

            m_freezeCurrentRowAction->setEnabled(currentAvailable);
            m_freezeCurrentColumnAction->setEnabled(currentAvailable);
            m_freezeCurrentCellAction->setEnabled(currentAvailable);
            m_unfreezeRowsAction->setEnabled(m_frozenPaneController->frozenRowCount() > 0);
            m_unfreezeColumnsAction->setEnabled(m_frozenPaneController->frozenColumnCount() > 0);
            m_unfreezeAllAction->setEnabled(
                m_frozenPaneController->frozenRowCount() > 0 ||
                m_frozenPaneController->frozenColumnCount() > 0);
            updateFreezeButton();
        }

        void closeFreezeMenuBarrier()
        {
            if (!m_freezeMenuBarrierActive) return;
            m_freezeMenuBarrierActive = false;
            endItemViewContextMenu(m_freezeMenuSource.data());
            m_freezeMenuSource.clear();
        }

        void updateFreezeButton()
        {
            if (m_freezePaneButton == nullptr || m_frozenPaneController == nullptr) return;
            const int rows = m_frozenPaneController->frozenRowCount();
            const int columns = m_frozenPaneController->frozenColumnCount();
            m_freezePaneButton->setText(rows == 0 && columns == 0
                ? localizedSourceText("冻结")
                : localizedSourceText("冻结（%1 行 / %2 列）").arg(rows).arg(columns));
            m_freezePaneButton->setProperty("ksword_frozen_rows", rows);
            m_freezePaneButton->setProperty("ksword_frozen_columns", columns);
        }

        void applyFreezeCounts()
        {
            QTableView* tableView = activeTableView();
            if (m_inComparison || m_pauseCaptureInProgress || m_snapshotCaptureInProgress || m_comparisonInProgress
                || tableView == nullptr || tableView->model() == nullptr) return;
            if (m_frozenPaneController->targetTable() != tableView)
                m_frozenPaneController->setTargetTable(tableView);
            if (!m_frozenPaneController->canFreeze()) return;
            // Keep business-hidden sections hidden. Existing frozen sections remain
            // eligible when changing the counts; visual order follows the current headers.
            QList<int> rows;
            QList<int> columns;
            const int requestedRows = m_freezeRowsSpin->value();
            const int requestedColumns = m_freezeColumnsSpin->value();
            for (int visual = 0; visual < tableView->verticalHeader()->count() && rows.size() < requestedRows; ++visual)
            {
                const int logical = tableView->verticalHeader()->logicalIndex(visual);
                if (logical >= 0 && !isRowHiddenByFilter(tableView, logical)) rows.append(logical);
            }
            for (int visual = 0; visual < tableView->horizontalHeader()->count() && columns.size() < requestedColumns; ++visual)
            {
                const int logical = tableView->horizontalHeader()->logicalIndex(visual);
                if (logical >= 0 && !isColumnHiddenByFilter(tableView, logical)) columns.append(logical);
            }
            m_frozenPaneController->clearFrozenPanes();
            m_frozenPaneController->freezeRows(rows);
            m_frozenPaneController->freezeColumns(columns);
            updatePosition();
            updateControls();
        }

        // freezeToCurrentIndex 作用：
        // - 行方向：把选中的行（多选全部生效，未选中回落到当前行）钉到列表头正下方；
        // - 列方向：把当前单元格所在列固定到行表头右侧；
        // - 只冻结选中的行列本身；其余内容——包括它们上方/左侧的行列——照常滚动；
        // - freezeRows/freezeColumns 控制本次只修改哪一个方向。
        void freezeToCurrentIndex(const bool freezeRows, const bool freezeColumns)
        {
            QTableView* tableView = activeTableView();
            if (m_inComparison || tableView == nullptr || tableView->model() == nullptr ||
                !tableView->currentIndex().isValid())
            {
                return;
            }

            if (m_frozenPaneController->targetTable() != tableView)
            {
                m_frozenPaneController->setTargetTable(tableView);
            }
            if (!m_frozenPaneController->canFreeze())
            {
                return;
            }

            const QModelIndex currentIndex = tableView->currentIndex();
            if (freezeRows)
            {
                const QVector<int> selectedRows = selectedVisibleRows(tableView, true);
                m_frozenPaneController->freezeRows(
                    QList<int>(selectedRows.cbegin(), selectedRows.cend()));
            }
            if (freezeColumns)
            {
                m_frozenPaneController->freezeColumns({ currentIndex.column() });
            }
            updatePosition();
            updateControls();
        }

        void configurePausedOverlay(
            ComparisonTableView* pausedView,
            const TableSnapshot& snapshot)
        {
            if (pausedView == nullptr || m_table.isNull() || m_pauseModel.isNull())
            {
                return;
            }

            QTableView* sourceTable = m_table.data();
            pausedView->setModel(m_pauseModel);
            pausedView->setSelectionMode(QAbstractItemView::ExtendedSelection);
            pausedView->setSelectionBehavior(sourceTable->selectionBehavior());
            pausedView->setEditTriggers(QAbstractItemView::NoEditTriggers);
            pausedView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
            pausedView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
            pausedView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
            pausedView->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
            pausedView->verticalScrollBar()->setSingleStep(
                std::max(20, sourceTable->verticalScrollBar()->singleStep()));
            pausedView->horizontalScrollBar()->setSingleStep(
                std::max(20, sourceTable->horizontalScrollBar()->singleStep()));
            pausedView->setAlternatingRowColors(sourceTable->alternatingRowColors());
            pausedView->setShowGrid(sourceTable->showGrid());
            pausedView->setGridStyle(sourceTable->gridStyle());
            pausedView->setTextElideMode(sourceTable->textElideMode());
            pausedView->setWordWrap(false);
            pausedView->setSortingEnabled(false);
            pausedView->setFrameShape(QFrame::NoFrame);
            pausedView->setFocusPolicy(Qt::StrongFocus);
            pausedView->setFont(sourceTable->font());
            pausedView->setPalette(sourceTable->palette());
            pausedView->setAutoFillBackground(true);
            pausedView->viewport()->setAutoFillBackground(true);
            pausedView->viewport()->setPalette(sourceTable->viewport()->palette());

            pausedView->verticalHeader()->setVisible(
                !sourceTable->verticalHeader()->isHidden());
            pausedView->verticalHeader()->setMinimumSectionSize(
                sourceTable->verticalHeader()->minimumSectionSize());
            pausedView->verticalHeader()->setDefaultSectionSize(
                sourceTable->verticalHeader()->defaultSectionSize());
            pausedView->horizontalHeader()->setSectionsMovable(false);
            pausedView->horizontalHeader()->setSectionsClickable(false);
            pausedView->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
            pausedView->horizontalHeader()->setStretchLastSection(
                sourceTable->horizontalHeader()->stretchLastSection());
            ks::ui::CopyTablePresentation(sourceTable, pausedView);

            for (int columnIndex = 0; columnIndex < snapshot.visibleColumns.size(); ++columnIndex)
            {
                const int sourceColumn = snapshot.visibleColumns.at(columnIndex).sourceColumn;
                const int sourceWidth =
                    sourceColumn >= 0 &&
                    sourceTable->model() != nullptr &&
                    sourceColumn < sourceTable->model()->columnCount()
                    ? sourceTable->columnWidth(sourceColumn)
                    : sourceTable->horizontalHeader()->defaultSectionSize();
                pausedView->setColumnWidth(columnIndex, std::max(32, sourceWidth));
            }

            const QModelIndex sourceCurrentIndex = sourceTable->currentIndex();
            if (sourceCurrentIndex.isValid())
            {
                int pausedRow = -1;
                int pausedColumn = -1;
                for (int rowIndex = 0; rowIndex < snapshot.rows.size(); ++rowIndex)
                {
                    if (snapshot.rows.at(rowIndex).sourceRow == sourceCurrentIndex.row())
                    {
                        pausedRow = rowIndex;
                        break;
                    }
                }
                for (int columnIndex = 0;
                    columnIndex < snapshot.visibleColumns.size();
                    ++columnIndex)
                {
                    if (snapshot.visibleColumns.at(columnIndex).sourceColumn ==
                        sourceCurrentIndex.column())
                    {
                        pausedColumn = columnIndex;
                        break;
                    }
                }
                if (pausedRow >= 0 && pausedColumn >= 0)
                {
                    pausedView->setCurrentIndex(m_pauseModel->index(pausedRow, pausedColumn));
                }
            }
        }

        bool pauseRefresh()
        {
            if (m_refreshPaused)
            {
                return true;
            }
            if (m_table.isNull() || m_table->model() == nullptr ||
                m_inComparison || m_pauseCaptureInProgress)
            {
                return false;
            }

            const QPointer<TableActionBar> actionBarGuard(this);
            const QPointer<QTableView> tableGuard(m_table);
            const QPointer<QAbstractItemModel> modelGuard(m_table->model());
            m_pauseCaptureInProgress = true;
            updateControls();
            const TableSnapshot snapshot = TableSnapshotCompareEngine::capture(
                m_table.data(),
                localizedSourceText("视图已冻结"),
                0,
                kSnapshotCaptureLimits);
            if (actionBarGuard.isNull())
            {
                return false;
            }
            m_pauseCaptureInProgress = false;
            if (tableGuard.isNull() || modelGuard.isNull() ||
                m_table != tableGuard || tableGuard->model() != modelGuard ||
                snapshot.sourceInvalidated)
            {
                QMessageBox::warning(
                    this,
                    localizedSourceText("冻结视图失败"),
                    localizedSourceText("表格在捕获期间已重建，请重试。"));
                updateControls();
                return false;
            }

            if (snapshot.isTruncated())
            {
                QMessageBox::warning(
                    this,
                    localizedSourceText("冻结视图已截断"),
                    localizedSourceText(
                        "表格规模超过冻结视图快照的安全上限，当前冻结视图保留 %1/%2 行和 %3/%4 列；恢复实时视图后可回到完整实时表格。")
                        .arg(snapshot.rows.size())
                        .arg(snapshot.sourceRowCount)
                        .arg(snapshot.visibleColumns.size())
                        .arg(snapshot.sourceColumnCount));
                if (actionBarGuard.isNull() || tableGuard.isNull() ||
                    modelGuard.isNull() || m_table != tableGuard ||
                    tableGuard->model() != modelGuard)
                {
                    updateControls();
                    return false;
                }
            }

            m_pauseModel = new TablePausedSnapshotModel(snapshot, this);
            auto* pausedView = new ComparisonTableView(m_table.data());
            m_pauseOverlay = pausedView;
            configurePausedOverlay(pausedView, snapshot);

            m_frozenPaneController->setTargetTable(nullptr);
            suspendOriginalTablePainting();
            m_refreshPaused = true;
            pausedView->show();
            updatePosition();
            pausedView->raise();
            pausedView->setFocus(Qt::OtherFocusReason);
            m_frozenPaneController->setTargetTable(pausedView);
            updateControls();
            return true;
        }

        void resumeRefresh()
        {
            if (!m_refreshPaused && m_pauseOverlay.isNull())
            {
                return;
            }

            m_frozenPaneController->setTargetTable(nullptr);
            if (!m_pauseOverlay.isNull())
            {
                m_pauseOverlay->hide();
                m_pauseOverlay->deleteLater();
                m_pauseOverlay.clear();
            }
            resumeOriginalTablePainting();
            if (!m_pauseModel.isNull())
            {
                m_pauseModel->deleteLater();
                m_pauseModel.clear();
            }

            m_refreshPaused = false;
            m_frozenPaneController->setTargetTable(m_table.data());
            {
                const QSignalBlocker blocker(m_pauseRefreshButton);
                m_pauseRefreshButton->setChecked(false);
            }
            updatePosition();
            updateControls();
        }

        void setRefreshPaused(const bool paused)
        {
            if (paused)
            {
                if (!pauseRefresh())
                {
                    const QSignalBlocker blocker(m_pauseRefreshButton);
                    m_pauseRefreshButton->setChecked(false);
                    updateControls();
                }
                return;
            }
            resumeRefresh();
        }

        const TableSnapshot* snapshotForSequence(const quint64 sequence) const
        {
            const auto iterator = std::find_if(
                m_snapshots.cbegin(),
                m_snapshots.cend(),
                [sequence](const TableSnapshot& snapshot)
                {
                    return snapshot.sequence == sequence;
                });
            return iterator == m_snapshots.cend() ? nullptr : &*iterator;
        }

        QVector<const TableSnapshot*> selectedSnapshots() const
        {
            QVector<const TableSnapshot*> result;
            result.reserve(m_selectedSnapshotSequences.size());
            for (const quint64 sequence : m_selectedSnapshotSequences)
            {
                if (const TableSnapshot* snapshot = snapshotForSequence(sequence))
                {
                    result.push_back(snapshot);
                }
            }
            return result;
        }

        void addSnapshot()
        {
            if (m_table.isNull() ||
                m_inComparison ||
                m_snapshotCaptureInProgress ||
                m_table->model() == nullptr)
            {
                return;
            }

            const quint64 sequence = m_nextSnapshotOrdinal++;
            const QString label = TableSnapshotCompareEngine::snapshotLabelForOrdinal(sequence);
            m_snapshotCaptureInProgress = true;
            updateControls();

            QPointer<TableActionBar> actionBarGuard(this);
            TableSnapshot snapshot = TableSnapshotCompareEngine::capture(
                m_table.data(),
                label,
                sequence,
                kSnapshotCaptureLimits);
            if (actionBarGuard.isNull())
            {
                return;
            }
            m_snapshotCaptureInProgress = false;
            if (snapshot.sourceInvalidated)
            {
                updateControls();
                QMessageBox::warning(
                    this,
                    localizedSourceText("快照采集限制"),
                    localizedSourceText("采集期间源表已关闭，或其数据、布局、表头可见状态发生变化。本次快照已整份丢弃；请在源表稳定后重试。"));
                return;
            }

            m_snapshots.push_back(std::move(snapshot));
            const TableSnapshot& retainedSnapshot = m_snapshots.back();

            QStringList limitMessages;
            bool retainedPartialSnapshot = false;
            if (retainedSnapshot.truncatedByRowLimit)
            {
                retainedPartialSnapshot = true;
                limitMessages.push_back(
                    localizedSourceText("快照 %1 已截断：源表共 %2 行，仅访问 %3 行并保留 %4 行。")
                        .arg(retainedSnapshot.label)
                        .arg(retainedSnapshot.sourceRowCount)
                        .arg(retainedSnapshot.visitedSourceRows)
                        .arg(retainedSnapshot.rows.size()));
                limitMessages.push_back(
                    localizedSourceText("已达到单份快照的 %1 行硬上限。")
                        .arg(kSnapshotCaptureLimits.maximumRows));
            }
            if (retainedSnapshot.truncatedByColumnLimit)
            {
                retainedPartialSnapshot = true;
                limitMessages.push_back(
                    localizedSourceText("快照 %1 仅扫描源表前 %2/%3 列，并保留其中 %4 个可见列。")
                        .arg(retainedSnapshot.label)
                        .arg(retainedSnapshot.visitedSourceColumns)
                        .arg(retainedSnapshot.sourceColumnCount)
                        .arg(retainedSnapshot.visibleColumns.size()));
                limitMessages.push_back(
                    localizedSourceText("已达到单份快照的 %1 列硬上限。")
                        .arg(kSnapshotCaptureLimits.maximumColumns));
            }
            if (retainedSnapshot.truncatedByByteLimit)
            {
                retainedPartialSnapshot = true;
                limitMessages.push_back(
                    localizedSourceText("已达到单份快照的 %1 MiB 估算内存硬上限。")
                        .arg(kSnapshotCaptureLimits.maximumEstimatedBytes / kBytesPerMiB));
            }
            if (retainedSnapshot.truncatedByValueLimit)
            {
                retainedPartialSnapshot = true;
                limitMessages.push_back(
                    localizedSourceText("快照 %1 中有 %2 个表头值和 %3 个单元格值超过单值上限，另有 %4 个不支持的显示值类型；相关值已截断或留空。")
                        .arg(retainedSnapshot.label)
                        .arg(retainedSnapshot.truncatedHeaderValueCount)
                        .arg(retainedSnapshot.truncatedCellValueCount)
                        .arg(retainedSnapshot.unsupportedDisplayValueCount));
                limitMessages.push_back(
                    localizedSourceText("单个表头最多保留 %1 个字符，单个单元格最多保留 %2 个字符。")
                        .arg(kSnapshotCaptureLimits.maximumHeaderCharacters)
                        .arg(kSnapshotCaptureLimits.maximumCellCharacters));
            }

            const TableSnapshotRetentionResult retention =
                TableSnapshotCompareEngine::enforceRetentionLimits(
                    m_snapshots,
                    kSnapshotRetentionLimits);
            if (!retention.evictedLabels.isEmpty())
            {
                limitMessages.push_back(
                    localizedSourceText("为满足最多 %1 份快照、总估算内存不超过 %2 MiB 的硬上限，已淘汰最旧的 %3 份快照：%4。")
                        .arg(kSnapshotRetentionLimits.maximumSnapshots)
                        .arg(kSnapshotRetentionLimits.maximumEstimatedBytes / kBytesPerMiB)
                        .arg(retention.evictedLabels.size())
                        .arg(retention.evictedLabels.join(QStringLiteral(", "))));
            }
            if (retainedPartialSnapshot)
            {
                limitMessages.push_back(
                    localizedSourceText("已保留的部分仍可继续参与快照比较。"));
            }

            pruneSnapshotSelections();
            rebuildSnapshotControls();
            updateControls();
            if (!limitMessages.isEmpty())
            {
                QMessageBox::information(
                    this,
                    localizedSourceText("快照采集限制"),
                    limitMessages.join(QStringLiteral("\n\n")));
            }
        }

        void enterCleanupMode()
        {
            showCurrentView();
            m_cleanupMode = true;
            m_cleanupSelections.clear();
            rebuildSnapshotControls();
            updateControls();
        }

        void leaveCleanupMode()
        {
            m_cleanupMode = false;
            m_cleanupSelections.clear();
            rebuildSnapshotControls();
            updateControls();
        }

        void deleteSelectedSnapshots()
        {
            if (m_cleanupSelections.isEmpty())
            {
                QMessageBox::information(
                    this,
                    localizedSourceText("清理快照"),
                    localizedSourceText("没有选中的快照。"));
                return;
            }

            const int count = m_cleanupSelections.size();
            if (QMessageBox::question(
                    this,
                    localizedSourceText("清理快照"),
                    localizedSourceText("确定清理选中的 %1 份快照吗？").arg(count),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No) != QMessageBox::Yes)
            {
                return;
            }

            m_snapshots.erase(
                std::remove_if(
                    m_snapshots.begin(),
                    m_snapshots.end(),
                    [this](const TableSnapshot& snapshot)
                    {
                        return m_cleanupSelections.contains(snapshot.sequence);
                    }),
                m_snapshots.end());
            pruneSnapshotSelections();
            m_cleanupSelections.clear();
            rebuildSnapshotControls();
            updateControls();
        }

        void clearAllSnapshots()
        {
            if (m_snapshots.isEmpty())
            {
                return;
            }

            const int count = m_snapshots.size();
            if (QMessageBox::question(
                    this,
                    localizedSourceText("清理快照"),
                    localizedSourceText("确定清除该表的全部 %1 份快照吗？").arg(count),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No) != QMessageBox::Yes)
            {
                return;
            }

            showCurrentView();
            m_snapshots.clear();
            m_selectedSnapshotSequences.clear();
            m_cleanupSelections.clear();
            rebuildSnapshotControls();
            updateControls();
        }

        void pruneSnapshotSelections()
        {
            m_selectedSnapshotSequences.erase(
                std::remove_if(
                    m_selectedSnapshotSequences.begin(),
                    m_selectedSnapshotSequences.end(),
                    [this](const quint64 sequence)
                    {
                        return snapshotForSequence(sequence) == nullptr;
                    }),
                m_selectedSnapshotSequences.end());
        }

        void rebuildSnapshotControls()
        {
            while (QLayoutItem* item = m_snapshotLayout->takeAt(0))
            {
                delete item->widget();
                delete item;
            }
            m_snapshotButtons.clear();

            for (const TableSnapshot& snapshot : m_snapshots)
            {
                QToolButton* button = createSnapshotButton(
                    snapshot,
                    m_cleanupMode
                        ? m_cleanupSelections.contains(snapshot.sequence)
                        : m_selectedSnapshotSequences.contains(snapshot.sequence));
                if (m_cleanupMode)
                {
                    connect(button, &QToolButton::toggled, this, [this, sequence = snapshot.sequence](const bool checked)
                        {
                            if (checked)
                            {
                                m_cleanupSelections.insert(sequence);
                            }
                            else
                            {
                                m_cleanupSelections.remove(sequence);
                            }
                            updateControls();
                        });
                }
                else
                {
                    connect(button, &QToolButton::toggled, this, [this, sequence = snapshot.sequence](const bool checked)
                        {
                            selectSnapshot(sequence, checked);
                        });
                }
                m_snapshotLayout->addWidget(button);
                m_snapshotButtons.insert(snapshot.sequence, button);
            }
            m_snapshotLayout->addStretch(1);
            updateSnapshotContentSize();
            scheduleSnapshotLayout();
        }

        void scheduleSnapshotLayout()
        {
            if (m_snapshotLayoutPending) return;
            m_snapshotLayoutPending = true;
            QTimer::singleShot(0, this, [this]()
                {
                    m_snapshotLayoutPending = false;
                    updatePosition();
                });
        }

        void updateSnapshotContentSize()
        {
            if (m_snapshotContent == nullptr || m_snapshotLayout == nullptr ||
                m_snapshotScrollArea == nullptr)
            {
                return;
            }

            m_snapshotLayout->invalidate();
            m_snapshotLayout->activate();
            QSize desiredSize = m_snapshotLayout->sizeHint().expandedTo(
                m_snapshotLayout->minimumSize());
            desiredSize.setWidth(std::max(1, desiredSize.width()));
            const bool needsHorizontalBar = m_mode == TableActionBarMode::Full
                && !m_snapshotButtons.isEmpty()
                && desiredSize.width() > m_snapshotScrollArea->viewport()->width();
            const int horizontalBarHeight = needsHorizontalBar
                ? std::max(0, m_snapshotScrollArea->horizontalScrollBar()->sizeHint().height()) : 0;
            const int frameHeight = m_snapshotScrollArea->frameWidth() * 2;
            const int stripHeight = std::max(kActionBarHeight - 4,
                desiredSize.height() + horizontalBarHeight + frameHeight);
            if (m_snapshotScrollArea->height() != stripHeight) m_snapshotScrollArea->setFixedHeight(stripHeight);
            const QMargins margins = layout()->contentsMargins();
            const int barHeight = m_mode == TableActionBarMode::Full
                ? std::max(kActionBarHeight, stripHeight + margins.top() + margins.bottom()) : kActionBarHeight;
            if (height() != barHeight) setFixedHeight(barHeight);
            desiredSize.setHeight(std::max(
                desiredSize.height(),
                stripHeight - horizontalBarHeight - frameHeight));
            if (m_snapshotContent->minimumSize() != desiredSize) m_snapshotContent->setMinimumSize(desiredSize);
            if (m_snapshotContent->size() != desiredSize) m_snapshotContent->resize(desiredSize);
        }

        void selectSnapshot(const quint64 sequence, const bool checked)
        {
            if (m_inComparison)
            {
                showCurrentView();
            }

            if (checked)
            {
                if (!m_selectedSnapshotSequences.contains(sequence))
                {
                    m_selectedSnapshotSequences.push_back(sequence);
                }
                if (m_selectedSnapshotSequences.size() > 2)
                {
                    m_selectedSnapshotSequences = { sequence };
                }
            }
            else
            {
                m_selectedSnapshotSequences.removeAll(sequence);
            }

            for (auto iterator = m_snapshotButtons.begin(); iterator != m_snapshotButtons.end(); ++iterator)
            {
                if (iterator.value() != nullptr)
                {
                    const QSignalBlocker blocker(iterator.value());
                    iterator.value()->setChecked(m_selectedSnapshotSequences.contains(iterator.key()));
                }
            }
            updateControls();
        }

        void hideSourceViewportWidgets()
        {
            if (!m_originalTablePaintingSuspended || m_table.isNull() ||
                m_table->viewport() == nullptr)
            {
                return;
            }

            for (QWidget* childWidget : m_table->viewport()->findChildren<QWidget*>(
                    QString(),
                    Qt::FindDirectChildrenOnly))
            {
                if (childWidget != nullptr && !childWidget->isHidden())
                {
                    childWidget->hide();
                    const bool alreadyTracked = std::any_of(
                        m_hiddenSourceViewportWidgets.cbegin(),
                        m_hiddenSourceViewportWidgets.cend(),
                        [childWidget](const QPointer<QWidget>& guardedWidget)
                        {
                            return guardedWidget.data() == childWidget;
                        });
                    if (!alreadyTracked)
                    {
                        m_hiddenSourceViewportWidgets.push_back(childWidget);
                    }
                }
            }
        }

        void suspendOriginalTablePainting()
        {
            if (m_table.isNull() || m_originalTablePaintingSuspended)
            {
                return;
            }

            QTableView* tableView = m_table.data();
            m_originalTablePaintingSuspended = true;
            m_originalHorizontalHeaderHidden = tableView->horizontalHeader()->isHidden();
            m_originalVerticalHeaderHidden = tableView->verticalHeader()->isHidden();
            m_originalHorizontalScrollBarPolicy = tableView->horizontalScrollBarPolicy();
            m_originalVerticalScrollBarPolicy = tableView->verticalScrollBarPolicy();
            m_originalViewportOpaquePaint = tableView->viewport()->testAttribute(Qt::WA_OpaquePaintEvent);
            m_hiddenSourceViewportWidgets.clear();

            tableView->setProperty(
                ks::ui::visible_table_detail::ComparisonSourceActiveProperty,
                true);
            tableView->viewport()->setAttribute(Qt::WA_OpaquePaintEvent, false);
            hideSourceViewportWidgets();
            tableView->horizontalHeader()->hide();
            tableView->verticalHeader()->hide();
            tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            tableView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            tableView->viewport()->update();
        }

        void resumeOriginalTablePainting()
        {
            if (!m_originalTablePaintingSuspended)
            {
                return;
            }

            if (!m_table.isNull())
            {
                QTableView* tableView = m_table.data();
                tableView->setProperty(
                    ks::ui::visible_table_detail::ComparisonSourceActiveProperty,
                    false);
                tableView->setHorizontalScrollBarPolicy(m_originalHorizontalScrollBarPolicy);
                tableView->setVerticalScrollBarPolicy(m_originalVerticalScrollBarPolicy);
                tableView->horizontalHeader()->setHidden(m_originalHorizontalHeaderHidden);
                tableView->verticalHeader()->setHidden(m_originalVerticalHeaderHidden);
                tableView->viewport()->setAttribute(
                    Qt::WA_OpaquePaintEvent,
                    m_originalViewportOpaquePaint);
                for (const QPointer<QWidget>& guardedWidget : m_hiddenSourceViewportWidgets)
                {
                    if (!guardedWidget.isNull())
                    {
                        guardedWidget->show();
                    }
                }
                tableView->doItemsLayout();
                tableView->viewport()->update();
            }

            m_hiddenSourceViewportWidgets.clear();
            m_originalTablePaintingSuspended = false;
        }

        void configureComparisonOverlay(
            ComparisonTableView* comparisonView,
            const TableComparisonResult& comparison)
        {
            if (comparisonView == nullptr || m_table.isNull())
            {
                return;
            }

            QTableView* sourceTable = m_table.data();
            comparisonView->setModel(m_comparisonModel);
            comparisonView->setSelectionMode(QAbstractItemView::ExtendedSelection);
            comparisonView->setSelectionBehavior(QAbstractItemView::SelectRows);
            comparisonView->setEditTriggers(QAbstractItemView::NoEditTriggers);
            comparisonView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
            comparisonView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
            comparisonView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
            comparisonView->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
            comparisonView->verticalScrollBar()->setSingleStep(std::max(20, sourceTable->verticalScrollBar()->singleStep()));
            comparisonView->horizontalScrollBar()->setSingleStep(std::max(20, sourceTable->horizontalScrollBar()->singleStep()));
            comparisonView->setAlternatingRowColors(sourceTable->alternatingRowColors());
            comparisonView->setShowGrid(sourceTable->showGrid());
            comparisonView->setGridStyle(sourceTable->gridStyle());
            comparisonView->setTextElideMode(sourceTable->textElideMode());
            comparisonView->setWordWrap(false);
            comparisonView->setSortingEnabled(false);
            comparisonView->setFrameShape(QFrame::NoFrame);
            comparisonView->setFocusPolicy(Qt::StrongFocus);
            comparisonView->setFont(sourceTable->font());
            comparisonView->setAutoFillBackground(false);
            comparisonView->setPalette(sourceTable->palette());
            if (comparisonView->viewport() != nullptr)
            {
                comparisonView->viewport()->setAutoFillBackground(false);
                comparisonView->viewport()->setPalette(sourceTable->viewport()->palette());
            }

            comparisonView->verticalHeader()->hide();
            const int readableRowHeight = std::max(
                sourceTable->verticalHeader()->defaultSectionSize(),
                comparisonView->fontMetrics().lineSpacing() + 8);
            comparisonView->verticalHeader()->setMinimumSectionSize(readableRowHeight);
            comparisonView->verticalHeader()->setDefaultSectionSize(readableRowHeight);
            comparisonView->horizontalHeader()->setSectionsMovable(false);
            comparisonView->horizontalHeader()->setSectionsClickable(false);
            comparisonView->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
            comparisonView->horizontalHeader()->setStretchLastSection(
                sourceTable->horizontalHeader()->stretchLastSection());
            ks::ui::CopyTablePresentation(sourceTable, comparisonView);

            comparisonView->setColumnWidth(0, 56);
            for (int columnIndex = 0; columnIndex < comparison.columns.size(); ++columnIndex)
            {
                const int sourceColumn = comparison.columns.at(columnIndex).sourceColumn;
                const int sourceWidth = sourceColumn >= 0 && sourceColumn < sourceTable->model()->columnCount()
                    ? sourceTable->columnWidth(sourceColumn)
                    : sourceTable->horizontalHeader()->defaultSectionSize();
                comparisonView->setColumnWidth(columnIndex + 1, std::max(48, sourceWidth));
            }
        }

        void showComparisonLimitWarning(const TableComparisonResult& comparison)
        {
            if (!comparison.isTruncated() || comparison.cancelled)
            {
                return;
            }

            QStringList reasons;
            if (comparison.truncatedByResultByteLimit)
            {
                reasons.push_back(
                    localizedSourceText("比较结果达到 %1 MiB 独立估算内存硬上限。")
                        .arg(kSnapshotComparisonLimits.maximumEstimatedBytes / kBytesPerMiB));
            }
            if (comparison.truncatedByTemporaryByteLimit)
            {
                reasons.push_back(
                    localizedSourceText("比较临时索引达到 %1 MiB 估算内存硬上限。")
                        .arg(kSnapshotComparisonLimits.maximumTemporaryEstimatedBytes / kBytesPerMiB));
            }
            if (comparison.truncatedByWorkLimit)
            {
                reasons.push_back(
                    localizedSourceText("比较达到 %1 个单元工作量硬上限。")
                        .arg(kSnapshotComparisonLimits.maximumWorkUnits));
            }

            QMessageBox::warning(
                this,
                localizedSourceText("快照比较限制"),
                localizedSourceText("比较已按硬预算提前停止；当前视图仅包含停止前生成的部分结果。")
                    + QStringLiteral("\n\n")
                    + reasons.join(QLatin1Char('\n')));
        }

        void showComparisonView()
        {
            if (m_table.isNull() ||
                m_cleanupMode ||
                m_comparisonInProgress ||
                m_selectedSnapshotSequences.size() != 2)
            {
                return;
            }

            const QPointer<TableActionBar> actionBarGuard(this);
            const QPointer<QTableView> tableGuard(m_table);
            const QPointer<QAbstractItemModel> modelGuard(m_table->model());
            const auto sourceStillValid = [actionBarGuard, tableGuard, modelGuard]()
            {
                return !actionBarGuard.isNull() &&
                    !tableGuard.isNull() &&
                    !modelGuard.isNull() &&
                    actionBarGuard->m_table == tableGuard &&
                    tableGuard->model() == modelGuard;
            };

            QVector<const TableSnapshot*> snapshots = selectedSnapshots();
            if (snapshots.size() != 2)
            {
                pruneSnapshotSelections();
                updateControls();
                return;
            }

            const TableSnapshot* earlier = snapshots.at(0);
            const TableSnapshot* later = snapshots.at(1);
            if (earlier->sequence > later->sequence)
            {
                std::swap(earlier, later);
            }

            if (earlier->isTruncated() || later->isTruncated())
            {
                QStringList snapshotCoverage;
                for (const TableSnapshot* snapshot : { earlier, later })
                {
                    if (snapshot != nullptr && snapshot->isTruncated())
                    {
                        snapshotCoverage.push_back(
                            localizedSourceText("快照 %1：扫描源表前 %2/%3 行，保留 %4 行；扫描前 %5/%6 列，保留 %7 个可见列。")
                                .arg(snapshot->label)
                                .arg(snapshot->visitedSourceRows)
                                .arg(snapshot->sourceRowCount)
                                .arg(snapshot->rows.size())
                                .arg(snapshot->visitedSourceColumns)
                                .arg(snapshot->sourceColumnCount)
                                .arg(snapshot->visibleColumns.size()));
                    }
                }
                QMessageBox::warning(
                    this,
                    localizedSourceText("截断快照比较"),
                    localizedSourceText("所选快照包含截断数据。比对仅覆盖各快照已扫描并保留的行与列；未覆盖内容不会出现在结果中。")
                        + QStringLiteral("\n\n")
                        + snapshotCoverage.join(QLatin1Char('\n')));
                if (!sourceStillValid())
                {
                    return;
                }

                // The nested modal event loop may have changed the snapshot store
                // without destroying the table. Re-resolve both selections before
                // using their addresses again.
                snapshots = selectedSnapshots();
                if (snapshots.size() != 2)
                {
                    pruneSnapshotSelections();
                    updateControls();
                    return;
                }
                earlier = snapshots.at(0);
                later = snapshots.at(1);
                if (earlier->sequence > later->sequence)
                {
                    std::swap(earlier, later);
                }
            }

            if (m_inComparison)
            {
                showCurrentView();
            }

            m_ignoredSourceColumns = TableSnapshotCompareEngine::defaultIgnoredColumnIndexes(*earlier);
            m_ignoredSourceColumns.unite(TableSnapshotCompareEngine::defaultIgnoredColumnIndexes(*later));
            m_comparisonInProgress = true;
            updateControls();
            const TableComparisonResult comparison = TableSnapshotCompareEngine::compare(
                *earlier,
                *later,
                m_ignoredSourceColumns,
                QVector<int>(),
                kSnapshotComparisonLimits,
                [sourceStillValid]()
                {
                    return !sourceStillValid();
                });
            if (actionBarGuard.isNull())
            {
                return;
            }
            m_comparisonInProgress = false;
            if (!sourceStillValid() || comparison.cancelled)
            {
                updateControls();
                return;
            }
            showComparisonLimitWarning(comparison);
            if (actionBarGuard.isNull())
            {
                return;
            }
            if (!sourceStillValid())
            {
                updateControls();
                return;
            }
            m_comparisonModel = new TableComparisonModel(comparison, this);
            m_comparisonModel->setShowDifferencesOnly(m_differenceOnlyCheckBox->isChecked());

            auto* comparisonView = new ComparisonTableView(m_table.data());
            m_comparisonOverlay = comparisonView;
            configureComparisonOverlay(comparisonView, comparison);
            comparisonView->setProperty(kComparisonActiveProperty, true);

            m_frozenPaneController->setTargetTable(nullptr);
            suspendOriginalTablePainting();
            m_inComparison = true;
            comparisonView->show();
            updatePosition();
            comparisonView->raise();
            comparisonView->setFocus(Qt::OtherFocusReason);
            updateControls();
        }

        void showCurrentView()
        {
            if (!m_inComparison)
            {
                return;
            }

            if (!m_comparisonOverlay.isNull())
            {
                m_comparisonOverlay->setProperty(kComparisonActiveProperty, false);
                m_comparisonOverlay->hide();
                m_comparisonOverlay->deleteLater();
                m_comparisonOverlay.clear();
            }
            resumeOriginalTablePainting();
            if (!m_comparisonModel.isNull())
            {
                m_comparisonModel->deleteLater();
                m_comparisonModel.clear();
            }

            m_inComparison = false;
            m_frozenPaneController->setTargetTable(m_table.data());
            updatePosition();
            updateControls();
        }

        void refreshComparison()
        {
            if (!m_inComparison ||
                m_comparisonInProgress ||
                m_comparisonModel.isNull() ||
                m_selectedSnapshotSequences.size() != 2)
            {
                return;
            }
            const QVector<const TableSnapshot*> snapshots = selectedSnapshots();
            if (snapshots.size() != 2)
            {
                return;
            }
            const TableSnapshot* earlier = snapshots.at(0);
            const TableSnapshot* later = snapshots.at(1);
            if (earlier->sequence > later->sequence)
            {
                std::swap(earlier, later);
            }
            m_comparisonInProgress = true;
            updateControls();
            const QPointer<TableActionBar> actionBarGuard(this);
            const TableComparisonResult comparison = TableSnapshotCompareEngine::compare(
                *earlier,
                *later,
                m_ignoredSourceColumns,
                QVector<int>(),
                kSnapshotComparisonLimits,
                [actionBarGuard]()
                {
                    return actionBarGuard.isNull() || actionBarGuard->m_table.isNull();
                });
            if (actionBarGuard.isNull())
            {
                return;
            }
            m_comparisonInProgress = false;
            if (comparison.cancelled || m_table.isNull() || m_comparisonModel.isNull())
            {
                updateControls();
                return;
            }
            showComparisonLimitWarning(comparison);
            if (actionBarGuard.isNull())
            {
                return;
            }
            if (m_table.isNull() || m_comparisonModel.isNull())
            {
                updateControls();
                return;
            }
            m_comparisonModel->setComparison(comparison);
            m_comparisonModel->setShowDifferencesOnly(m_differenceOnlyCheckBox->isChecked());
            updateControls();
        }

        void showIgnoredColumnsMenu()
        {
            if (!m_inComparison || m_comparisonModel.isNull())
            {
                return;
            }

            QMenu menu(this);
            menu.addSection(localizedSourceText("当前比对的忽略列"));
            const QStringList keywords = TableSnapshotCompareEngine::defaultIgnoredColumnKeywords();
            const TableComparisonResult& comparison = m_comparisonModel->comparison();
            QHash<QAction*, int> columnActions;
            for (const TableSnapshotColumn& column : comparison.columns)
            {
                QStringList matchedKeywords;
                for (const QString& keyword : keywords)
                {
                    if (column.headerText.contains(keyword, Qt::CaseInsensitive))
                    {
                        matchedKeywords.push_back(keyword);
                    }
                }

                QString title = column.headerText.isEmpty()
                    ? localizedSourceText("列 %1").arg(column.sourceColumn + 1)
                    : column.headerText;
                if (!matchedKeywords.isEmpty())
                {
                    title += QStringLiteral("  ")
                        + localizedSourceText("自动匹配：%1").arg(matchedKeywords.join(QStringLiteral(", ")));
                }
                QAction* action = menu.addAction(title);
                action->setCheckable(true);
                action->setChecked(m_ignoredSourceColumns.contains(column.sourceColumn));
                columnActions.insert(action, column.sourceColumn);
            }

            QAction* selectedAction = menu.exec(m_ignoreColumnsButton->mapToGlobal(
                QPoint(0, m_ignoreColumnsButton->height())));
            if (selectedAction == nullptr || !columnActions.contains(selectedAction))
            {
                return;
            }

            const int sourceColumn = columnActions.value(selectedAction);
            if (selectedAction->isChecked())
            {
                m_ignoredSourceColumns.insert(sourceColumn);
            }
            else
            {
                m_ignoredSourceColumns.remove(sourceColumn);
            }
            refreshComparison();
        }

        void updateComparisonOverlayGeometry()
        {
            if (m_table.isNull() ||
                (m_comparisonOverlay.isNull() && m_pauseOverlay.isNull()))
            {
                return;
            }

            const int frameWidth = m_table->frameWidth();
            const int top = std::max(frameWidth, geometry().bottom() + 1);
            QTableView* overlayView = !m_comparisonOverlay.isNull()
                ? m_comparisonOverlay.data()
                : m_pauseOverlay.data();
            overlayView->setGeometry(
                frameWidth,
                top,
                std::max(0, m_table->width() - frameWidth * 2),
                std::max(0, m_table->height() - top - frameWidth));
            overlayView->raise();
            raise();
        }

        void applyModeVisibility()
        {
            const bool actionBarVisible = m_mode != TableActionBarMode::None;
            const bool fullMode = m_mode == TableActionBarMode::Full;
            m_copyAllButton->setVisible(actionBarVisible);
            m_exportButton->setVisible(actionBarVisible);
            m_freezePaneButton->setVisible(fullMode);
            m_pauseRefreshButton->setVisible(fullMode);
            m_snapshotScrollArea->setVisible(fullMode);
            m_addSnapshotButton->setVisible(fullMode);
            m_cleanupButton->setVisible(fullMode && !m_cleanupMode);
            m_doneCleanupButton->setVisible(fullMode && m_cleanupMode);
            m_deleteSelectedButton->setVisible(fullMode && m_cleanupMode);
            m_clearAllButton->setVisible(fullMode && m_cleanupMode);
            m_differenceOnlyCheckBox->setVisible(fullMode && m_inComparison);
            m_ignoreColumnsButton->setVisible(fullMode && m_inComparison);
            m_currentViewButton->setVisible(fullMode);
            m_compareViewButton->setVisible(fullMode);
        }

        void updateControls()
        {
            const bool hasSnapshots = !m_snapshots.isEmpty();
            const bool exactlyTwoSnapshotsSelected = m_selectedSnapshotSequences.size() == 2;
            QTableView* activeTable = activeTableView();
            const bool hasVisibleRows = activeTable != nullptr &&
                activeTable->model() != nullptr &&
                activeTable->model()->rowCount() > 0 &&
                activeTable->model()->columnCount() > 0;
            const bool controlsAvailable =
                !m_snapshotCaptureInProgress &&
                !m_comparisonInProgress &&
                !m_pauseCaptureInProgress;
            m_copyAllButton->setEnabled(controlsAvailable && hasVisibleRows);
            m_exportButton->setEnabled(controlsAvailable && hasVisibleRows);
            m_freezePaneButton->setEnabled(
                controlsAvailable &&
                !m_inComparison &&
                activeTable != nullptr &&
                activeTable->model() != nullptr);
            updateFreezeButton();
            m_pauseRefreshButton->setText(localizedSourceText(
                m_pauseCaptureInProgress
                    ? "正在冻结…"
                    : (m_refreshPaused ? "恢复实时视图" : "冻结视图")));
            m_pauseRefreshButton->setToolTip(localizedSourceText(
                m_refreshPaused
                    ? "恢复实时视图并显示后台更新后的最新结果"
                    : "冻结当前表格内容；后台采集继续运行，恢复后显示最新结果"));
            {
                const QSignalBlocker blocker(m_pauseRefreshButton);
                m_pauseRefreshButton->setChecked(
                    m_refreshPaused || m_pauseCaptureInProgress);
            }
            m_pauseRefreshButton->setEnabled(
                !m_pauseCaptureInProgress &&
                !m_snapshotCaptureInProgress &&
                !m_comparisonInProgress &&
                !m_cleanupMode &&
                !m_inComparison &&
                m_table != nullptr &&
                m_table->model() != nullptr);
            m_addSnapshotButton->setText(localizedSourceText(
                m_snapshotCaptureInProgress ? "正在采集…" : "增加快照"));
            m_addSnapshotButton->setEnabled(
                controlsAvailable &&
                !m_cleanupMode &&
                !m_inComparison &&
                !m_refreshPaused &&
                m_table != nullptr &&
                m_table->model() != nullptr);
            m_cleanupButton->setVisible(!m_cleanupMode);
            m_cleanupButton->setEnabled(controlsAvailable && hasSnapshots && !m_inComparison);
            m_doneCleanupButton->setVisible(m_cleanupMode);
            m_doneCleanupButton->setEnabled(controlsAvailable);
            m_deleteSelectedButton->setVisible(m_cleanupMode);
            m_deleteSelectedButton->setEnabled(
                controlsAvailable &&
                m_cleanupMode &&
                !m_cleanupSelections.isEmpty());
            m_clearAllButton->setVisible(m_cleanupMode);
            m_clearAllButton->setEnabled(controlsAvailable && m_cleanupMode && hasSnapshots);
            m_differenceOnlyCheckBox->setVisible(m_inComparison);
            m_differenceOnlyCheckBox->setEnabled(controlsAvailable);
            m_ignoreColumnsButton->setVisible(m_inComparison);
            m_ignoreColumnsButton->setEnabled(controlsAvailable);
            m_currentViewButton->setEnabled(controlsAvailable && m_inComparison);
            m_currentViewButton->setChecked(!m_inComparison);
            m_compareViewButton->setEnabled(
                controlsAvailable &&
                !m_cleanupMode &&
                !m_refreshPaused &&
                exactlyTwoSnapshotsSelected);
            m_compareViewButton->setChecked(m_inComparison);
            for (QToolButton* snapshotButton : std::as_const(m_snapshotButtons))
            {
                if (snapshotButton != nullptr)
                {
                    snapshotButton->setEnabled(controlsAvailable);
                }
            }
            applyModeVisibility();
        }

        QPointer<QTableView> m_table;
        QPointer<QTableView> m_comparisonOverlay;
        QPointer<TableComparisonModel> m_comparisonModel;
        QPointer<QTableView> m_pauseOverlay;
        QPointer<TablePausedSnapshotModel> m_pauseModel;
        TableFrozenPaneController* m_frozenPaneController = nullptr;
        QVector<TableSnapshot> m_snapshots;
        QVector<quint64> m_selectedSnapshotSequences;
        QSet<quint64> m_cleanupSelections;
        QSet<int> m_ignoredSourceColumns;
        QHash<quint64, QToolButton*> m_snapshotButtons;
        QVector<QPointer<QWidget>> m_hiddenSourceViewportWidgets;
        quint64 m_nextSnapshotOrdinal = 0;
        Qt::ScrollBarPolicy m_originalHorizontalScrollBarPolicy = Qt::ScrollBarAsNeeded;
        Qt::ScrollBarPolicy m_originalVerticalScrollBarPolicy = Qt::ScrollBarAsNeeded;
        bool m_originalTablePaintingSuspended = false;
        bool m_originalHorizontalHeaderHidden = false;
        bool m_originalVerticalHeaderHidden = false;
        bool m_originalViewportOpaquePaint = false;
        bool m_cleanupMode = false;
        bool m_inComparison = false;
        bool m_refreshPaused = false;
        bool m_snapshotCaptureInProgress = false;
        bool m_comparisonInProgress = false;
        bool m_pauseCaptureInProgress = false;
        bool m_snapshotLayoutPending = false;
        TableActionBarMode m_mode = TableActionBarMode::Full;
        QToolButton* m_copyAllButton = nullptr;
        QToolButton* m_exportButton = nullptr;
        QToolButton* m_freezePaneButton = nullptr;
        QToolButton* m_pauseRefreshButton = nullptr;
        QMenu* m_freezePaneMenu = nullptr;
        QPointer<QAbstractItemView> m_freezeMenuSource;
        bool m_freezeMenuBarrierActive = false;
        QLabel* m_freezeRowsLabel = nullptr;
        QLabel* m_freezeColumnsLabel = nullptr;
        QSpinBox* m_freezeRowsSpin = nullptr;
        QSpinBox* m_freezeColumnsSpin = nullptr;
        QPushButton* m_applyFreezeCountsButton = nullptr;
        QAction* m_freezeCurrentRowAction = nullptr;
        QAction* m_freezeCurrentColumnAction = nullptr;
        QAction* m_freezeCurrentCellAction = nullptr;
        QAction* m_unfreezeRowsAction = nullptr;
        QAction* m_unfreezeColumnsAction = nullptr;
        QAction* m_unfreezeAllAction = nullptr;
        QToolButton* m_addSnapshotButton = nullptr;
        QToolButton* m_cleanupButton = nullptr;
        QToolButton* m_doneCleanupButton = nullptr;
        QToolButton* m_deleteSelectedButton = nullptr;
        QToolButton* m_clearAllButton = nullptr;
        QToolButton* m_ignoreColumnsButton = nullptr;
        QToolButton* m_currentViewButton = nullptr;
        QToolButton* m_compareViewButton = nullptr;
        QCheckBox* m_differenceOnlyCheckBox = nullptr;
        QScrollArea* m_snapshotScrollArea = nullptr;
        QWidget* m_snapshotContent = nullptr;
        QHBoxLayout* m_snapshotLayout = nullptr;
    };

    TableActionBar* actionBarForTable(QTableView* tableView)
    {
        if (tableView == nullptr)
        {
            return nullptr;
        }
        return dynamic_cast<TableActionBar*>(tableView->findChild<QObject*>(
            QString::fromLatin1(kActionBarProperty),
            Qt::FindDirectChildrenOnly));
    }

    void installActionBar(QTableView* tableView)
    {
        if (tableView == nullptr || ks::ui::TableActionBarHostFor(tableView) == nullptr)
        {
            return;
        }
        const TableActionBarMode mode = ks::ui::EffectiveTableActionBarMode(tableView);
        TableActionBar* actionBar = actionBarForTable(tableView);
        if (actionBar == nullptr)
        {
            if (mode == TableActionBarMode::None)
            {
                ks::ui::TableActionBarHostFor(tableView)->setTopActionBarHeight(0);
                return;
            }
            actionBar = new TableActionBar(tableView, mode);
        }
        actionBar->setMode(mode);
        actionBar->updatePosition();
    }

    // applyContextMenuStyle 作用：为全局创建或扩展的菜单补齐不透明主题样式。
    void applyContextMenuStyle(QMenu* menu)
    {
        if (menu != nullptr && menu->styleSheet().trimmed().isEmpty())
        {
            menu->setStyleSheet(KswordTheme::ContextMenuStyle());
        }
    }

    // showStandardTableContextMenu 作用：显示无业务右键表格使用的复制和导出菜单。
    void showStandardTableContextMenu(QTableView* tableView, const QPoint& globalPosition)
    {
        if (tableView == nullptr)
        {
            return;
        }

        QMenu menu(tableView);
        menu.setProperty(kStandardContextMenuProperty, true);
        applyContextMenuStyle(&menu);
        QAction* copyAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/log_copy.svg")),
            localizedSourceText("复制选中行（TSV）"));
        QAction* exportAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/log_export.svg")),
            localizedSourceText("导出选中行（TSV）"));

        copyAction->setEnabled(!selectedVisibleRows(tableView, true).isEmpty());
        exportAction->setEnabled(!selectedVisibleRows(tableView, true).isEmpty());

        QAction* selectedAction = menu.exec(globalPosition);
        if (selectedAction == copyAction)
        {
            copySelectedRowsToClipboard(tableView);
        }
        else if (selectedAction == exportAction)
        {
            exportSelectedRowsToTsv(tableView);
        }
    }

    // appendTableContextActions 作用：向业务右键菜单追加选中行复制和导出动作。
    void appendTableContextActions(QMenu* menu, QTableView* contextTableView = nullptr)
    {
        if (menu == nullptr ||
            menu->property(kStandardContextMenuProperty).toBool() ||
            menu->property(kContextActionsInstalledProperty).toBool())
        {
            return;
        }

        // tableView 用途：保存本次菜单对应的表格，优先使用右键事件来源。
        QTableView* tableView = contextTableView;
        if (tableView == nullptr)
        {
            tableView = qobject_cast<QTableView*>(menu->parent());
        }
        if (tableView == nullptr)
        {
            return;
        }

        // 已存在业务菜单项后再添加分隔线，使全局动作保持在菜单末尾。
        menu->setProperty(kContextActionsInstalledProperty, true);
        if (!menu->actions().isEmpty())
        {
            menu->addSeparator();
        }
        applyContextMenuStyle(menu);
        QAction* copyAction = menu->addAction(
            QIcon(QStringLiteral(":/Icon/log_copy.svg")),
            localizedSourceText("复制选中行（TSV）"));
        QAction* exportAction = menu->addAction(
            QIcon(QStringLiteral(":/Icon/log_export.svg")),
            localizedSourceText("导出选中行（TSV）"));

        // guardedTable 用途：在菜单存续期间安全引用其来源表格。
        const QPointer<QTableView> guardedTable(tableView);
        copyAction->setEnabled(!selectedVisibleRows(tableView, true).isEmpty());
        exportAction->setEnabled(!selectedVisibleRows(tableView, true).isEmpty());
        QObject::connect(copyAction, &QAction::triggered, menu, [guardedTable]()
            {
                if (!guardedTable.isNull())
                {
                    copySelectedRowsToClipboard(guardedTable.data());
                }
            });
        QObject::connect(exportAction, &QAction::triggered, menu, [guardedTable]()
            {
                if (!guardedTable.isNull())
                {
                    exportSelectedRowsToTsv(guardedTable.data());
                }
            });
    }

    void selectContextRow(QTableView* tableView, const QModelIndex& clickedIndex)
    {
        if (tableView == nullptr || !clickedIndex.isValid() || tableView->selectionModel() == nullptr)
        {
            return;
        }

        const QVector<int> selectedRowList = selectedVisibleRows(tableView, false);
        if (std::find(selectedRowList.cbegin(), selectedRowList.cend(), clickedIndex.row()) != selectedRowList.cend())
        {
            tableView->selectionModel()->setCurrentIndex(clickedIndex, QItemSelectionModel::NoUpdate);
            return;
        }

        tableView->selectionModel()->setCurrentIndex(
            clickedIndex,
            QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    }

    // 全局发现只是兼容适配层；实际模型、列能力由每张表的宿主维护。
    void configureTable(QTableView* tableView)
    {
        if (auto* const host = ks::ui::ResultTableHost::ensure(tableView))
        {
            host->refresh();
        }
    }

    // Coalesce discovery and resize work outside QWidget's Show/repolish recursion.
    void scheduleTableConfiguration(QTableView* tableView)
    {
        constexpr char pending[] = "ksword_table_interaction_configuration_pending";
        if (tableView == nullptr || tableView->property(pending).toBool()) return;
        tableView->setProperty(pending, true);
        const QPointer<QTableView> guardedTable(tableView);
        QTimer::singleShot(0, tableView, [guardedTable]()
        {
            if (guardedTable.isNull()) return;
            guardedTable->setProperty("ksword_table_interaction_configuration_pending", false);
            configureTable(guardedTable.data());
        });
    }

    class GlobalTableInteractionSupportFilter final : public QObject
    {
    public:
        explicit GlobalTableInteractionSupportFilter(QObject* parentObject)
            : QObject(parentObject)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (eventObject->type() == QEvent::Show)
            {
                // shownMenu 用途：识别业务代码刚刚显示的右键菜单。
                QMenu* shownMenu = qobject_cast<QMenu*>(watchedObject);
                if (shownMenu != nullptr)
                {
                    // contextItemView 用途：绑定当前菜单到最近一次表格或树右键来源。
                    QAbstractItemView* contextItemView = m_pendingContextItemView.data();
                    QTableView* contextTableView =
                        qobject_cast<QTableView*>(contextItemView);
                    appendTableContextActions(shownMenu, contextTableView);
                    if (contextItemView != nullptr)
                    {
                        // 同一个菜单对象一次显示只登记一次；Hide/销毁都会解除刷新屏障。
                        if (!m_openContextMenuItemViews.contains(shownMenu))
                        {
                            m_openContextMenuItemViews.insert(shownMenu, contextItemView);
                            beginItemViewContextMenu(contextItemView);

                            // 菜单可被不同视图复用；销毁时读取当下映射，避免旧连接解除新视图深度。
                            QObject::connect(
                                shownMenu,
                                &QObject::destroyed,
                                this,
                                [this, shownMenu]()
                                {
                                    const auto menuIterator =
                                        m_openContextMenuItemViews.find(shownMenu);
                                    if (menuIterator != m_openContextMenuItemViews.end())
                                    {
                                        const QPointer<QAbstractItemView> guardedItemView =
                                            menuIterator.value();
                                        m_openContextMenuItemViews.erase(menuIterator);
                                        endItemViewContextMenu(guardedItemView.data());
                                    }
                                });
                        }
                        m_pendingContextItemView.clear();
                        ++m_pendingContextSequence;
                    }
                }
            }
            else if (eventObject->type() == QEvent::Hide)
            {
                // hiddenMenu 用途：业务菜单退出嵌套事件循环后释放对应表格的 UI 提交屏障。
                QMenu* hiddenMenu = qobject_cast<QMenu*>(watchedObject);
                if (hiddenMenu != nullptr)
                {
                    const auto menuIterator = m_openContextMenuItemViews.find(hiddenMenu);
                    if (menuIterator != m_openContextMenuItemViews.end())
                    {
                        const QPointer<QAbstractItemView> guardedItemView = menuIterator.value();
                        m_openContextMenuItemViews.erase(menuIterator);
                        endItemViewContextMenu(guardedItemView.data());
                    }
                }
            }

            const QEvent::Type eventType = eventObject->type();
            QAbstractItemView* contextItemView = itemViewForEventObject(watchedObject);
            if (contextItemView != nullptr && eventType == QEvent::ContextMenu)
            {
                // 业务菜单显示前记录来源；QTableView 与 QTreeView 共用同一生命周期屏障。
                m_pendingContextItemView = contextItemView;
                ++m_pendingContextSequence;
                const unsigned long long pendingContextSequence = m_pendingContextSequence;
                QTimer::singleShot(0, this, [this, pendingContextSequence]()
                    {
                        if (m_pendingContextSequence == pendingContextSequence)
                        {
                            m_pendingContextItemView.clear();
                        }
                    });
            }

            QTableView* tableView = tableForEventObject(watchedObject);
            if (tableView == nullptr)
            {
                // 树形视图不适用下面那条按扁平行号工作的表格路径，但 Ctrl+C 不该因此变成死键。
                // 全局表格设施此前只认 QTableView，于是句柄树、设备树、内核对象树、文件占用树等
                // 一大批列表按 Ctrl+C 毫无反应——用户对着一张能多选的列表复制不出任何东西。
                if (eventType == QEvent::KeyPress)
                {
                    auto* treeKeyEvent = static_cast<QKeyEvent*>(eventObject);
                    if (treeKeyEvent->matches(QKeySequence::Copy))
                    {
                        if (QTreeView* treeView =
                                qobject_cast<QTreeView*>(itemViewForEventObject(watchedObject)))
                        {
                            copySelectedTreeRowsToClipboard(treeView);
                            treeKeyEvent->accept();
                            return true;
                        }
                    }
                }
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const bool comparisonActive = tableView->property(kComparisonActiveProperty).toBool();
            if (tableView->property(
                    ks::ui::visible_table_detail::ComparisonSourceActiveProperty).toBool() &&
                watchedObject == tableView->viewport() &&
                (eventType == QEvent::Paint || eventType == QEvent::UpdateRequest))
            {
                if (TableActionBar* actionBar = actionBarForTable(tableView))
                {
                    actionBar->updatePosition();
                }
            }
            if (comparisonActive && eventType == QEvent::ContextMenu)
            {
                auto* contextMenuEvent = static_cast<QContextMenuEvent*>(eventObject);
                const QPoint viewportPosition = watchedObject == tableView
                    ? tableView->viewport()->mapFrom(tableView, contextMenuEvent->pos())
                    : contextMenuEvent->pos();
                selectContextRow(tableView, tableView->indexAt(viewportPosition));
                showStandardTableContextMenu(tableView, contextMenuEvent->globalPos());
                contextMenuEvent->accept();
                return true;
            }
            if (eventType == QEvent::Show ||
                eventType == QEvent::Polish ||
                eventType == QEvent::LayoutRequest ||
                eventType == QEvent::StyleChange ||
                eventType == QEvent::Resize)
            {
                scheduleTableConfiguration(tableView);
            }
            else if (eventType == QEvent::KeyPress)
            {
                auto* keyEvent = static_cast<QKeyEvent*>(eventObject);
                if (keyEvent->matches(QKeySequence::Copy))
                {
                    copySelectedRowsToClipboard(tableView);
                    keyEvent->accept();
                    return true;
                }
                if (comparisonActive &&
                    (keyEvent->key() == Qt::Key_Return ||
                        keyEvent->key() == Qt::Key_Enter ||
                        keyEvent->key() == Qt::Key_Space))
                {
                    keyEvent->accept();
                    return true;
                }
            }
            else if (eventType == QEvent::ContextMenu)
            {
                auto* contextMenuEvent = static_cast<QContextMenuEvent*>(eventObject);
                const QPoint viewportPosition = watchedObject == tableView
                    ? tableView->viewport()->mapFrom(tableView, contextMenuEvent->pos())
                    : contextMenuEvent->pos();
                const QModelIndex clickedIndex = tableView->indexAt(viewportPosition);
                selectContextRow(tableView, clickedIndex);

                // 在事件发生时判断当前策略，不能在构造期把 Default 改成 Custom
                // 并接上通用菜单：页面随后接入的业务菜单会被先弹出的复制菜单遮住。
                if (tableView->contextMenuPolicy() == Qt::DefaultContextMenu)
                {
                    showStandardTableContextMenu(tableView, contextMenuEvent->globalPos());
                    contextMenuEvent->accept();
                    return true;
                }
            }

            return QObject::eventFilter(watchedObject, eventObject);
        }

    private:
        // m_pendingContextItemView 用途：保存当前业务右键菜单应绑定的表格或树来源。
        QPointer<QAbstractItemView> m_pendingContextItemView;
        // m_pendingContextSequence 用途：区分连续右键事件，保证延迟清理仅影响同一次事件。
        unsigned long long m_pendingContextSequence = 0ULL;
        // m_openContextMenuItemViews 用途：把当前可见业务菜单绑定到触发它的表格或树。
        QHash<QMenu*, QPointer<QAbstractItemView>> m_openContextMenuItemViews;
    };
}

namespace ks::ui
{
    // 宿主复用原有功能实现，避免迁移时丢失冻结、暂停、快照比较或搜索能力。
    void ConfigureResultTableInteractions(
        QTableView* tableView,
        const ResultTableCapabilities& capabilities)
    {
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }
        ApplyTablePresentation(tableView, capabilities.normalizeHeader);
        auto* const tableWidget = qobject_cast<QTableWidget*>(tableView);
        if (capabilities.headerClickSorting.has_value())
        {
            SetTableHeaderClickSortingEnabled(tableWidget, *capabilities.headerClickSorting);
        }
        InstallTableHeaderClickSorting(tableWidget);
        if (capabilities.actionBar.has_value())
        {
            SetTableActionBarMode(tableView, *capabilities.actionBar);
        }
        installActionBar(tableView);
        InstallTableSearchSupport(tableView);
        RefreshTableSearchSupport(tableView);
    }

    void OpenProcessDetailByPid(const quint32 pid)
    {
        if (pid == 0U)
        {
            return;
        }

        for (QWidget* topLevelWidget : QApplication::topLevelWidgets())
        {
            if (topLevelWidget != nullptr &&
                QMetaObject::invokeMethod(
                    topLevelWidget,
                    "openProcessDetailByPid",
                    Qt::QueuedConnection,
                    Q_ARG(quint32, pid)))
            {
                return;
            }
        }
    }

    void OpenProcessDetailByIdentity(
        const quint32 pid,
        const quint64 creationTime100ns)
    {
        // 历史记录不得静默退化为纯 PID，否则 PID 复用后可能打开无关进程。
        if (pid == 0U || creationTime100ns == 0U)
        {
            return;
        }

        // topLevelWidget：逐个寻找拥有 identity-aware 槽的主窗口实例。
        for (QWidget* topLevelWidget : QApplication::topLevelWidgets())
        {
            if (topLevelWidget != nullptr &&
                QMetaObject::invokeMethod(
                    topLevelWidget,
                    "openProcessDetailByIdentity",
                    Qt::QueuedConnection,
                    Q_ARG(quint32, pid),
                    Q_ARG(quint64, creationTime100ns)))
            {
                return;
            }
        }
    }

    void InstallGlobalTableInteractionSupport(QApplication* appInstance)
    {
        if (appInstance == nullptr || appInstance->property(kInstalledProperty).toBool())
        {
            return;
        }

        ks::ui::UiCommitCoordinator::forApplication(appInstance);
        InstallGlobalTablePresentation(appInstance);
        auto* filter = new GlobalTableInteractionSupportFilter(appInstance);
        appInstance->installEventFilter(filter);
        appInstance->setProperty(kInstalledProperty, true);

        for (QWidget* widget : appInstance->allWidgets())
        {
            scheduleTableConfiguration(qobject_cast<QTableView*>(widget));
        }
    }

    bool DeferTableUiCommitIfContextMenuOpen(
        QObject* owner,
        const QString& commitKey,
        const QList<QTableView*>& tableList,
        std::function<void()> commitAction)
    {
        QList<QAbstractItemView*> itemViewList;
        itemViewList.reserve(tableList.size());
        for (QTableView* tableView : tableList)
        {
            itemViewList.push_back(tableView);
        }
        UiCommitCoordinator* const coordinator = UiCommitCoordinator::forApplication();
        return coordinator != nullptr && coordinator->deferIfBlocked(
            owner, commitKey, itemViewList, std::move(commitAction));
    }

    bool IsTableUiCommitBlockedByContextMenu(
        const QList<QTableView*>& tableList)
    {
        QList<QAbstractItemView*> itemViewList;
        itemViewList.reserve(tableList.size());
        for (QTableView* tableView : tableList)
        {
            itemViewList.push_back(tableView);
        }
        return IsItemViewUiCommitBlockedByContextMenu(itemViewList);
    }

    bool DeferItemViewUiCommitIfContextMenuOpen(
        QObject* owner,
        const QString& commitKey,
        const QList<QAbstractItemView*>& itemViewList,
        std::function<void()> commitAction)
    {
        UiCommitCoordinator* const coordinator = UiCommitCoordinator::forApplication();
        return coordinator != nullptr && coordinator->deferIfBlocked(
            owner, commitKey, itemViewList, std::move(commitAction));
    }

    bool DeferUiCommitIfComboBoxPopupOpen(
        QObject* owner,
        const QString& commitKey,
        std::function<void()> commitAction)
    {
        // 视图集合留空：该入口不重建表格，屏障只由下拉框弹层和左 Ctrl 决定。
        UiCommitCoordinator* const coordinator = UiCommitCoordinator::forApplication();
        return coordinator != nullptr && coordinator->deferIfBlocked(
            owner, commitKey, {}, std::move(commitAction));
    }

    bool IsItemViewUiCommitBlockedByContextMenu(
        const QList<QAbstractItemView*>& itemViewList)
    {
        UiCommitCoordinator* const coordinator = UiCommitCoordinator::forApplication();
        return coordinator != nullptr && coordinator->isBlocked(itemViewList);
    }
}
