#include "TableFreezeSupport.h"

#include "VisibleTableWidget.h"
#include "TablePresentation.h"

#include <QAbstractItemDelegate>
#include <QAbstractItemView>
#include <QCoreApplication>
#include <QEvent>
#include <QHash>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QMouseEvent>
#include <QPalette>
#include <QScrollBar>
#include <QSet>
#include <QSize>
#include <QTableView>
#include <QTimer>
#include <QVariant>
#include <QWheelEvent>

#include <algorithm>
#include <utility>

namespace
{
    constexpr char kFrozenPaneAuxiliaryProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_PANE_AUXILIARY";
    constexpr char kFrozenPaneSourceProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_PANE_SOURCE";

    /*
     * 冻结靠 setRowHidden/setColumnHidden 把行列从主表挪走，这与"被筛选掉"在
     * QTableView 上是同一个状态位。复制、导出、快照比对都按"可见行/可见列"取数，
     * 若不加区分，用户特意钉住的行列反而不会进导出结果。这里把冻结集发布到
     * 表格属性上，让取数侧只排除真正被筛掉的行列。
     */
    constexpr char kFrozenHiddenRowsProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_HIDDEN_ROWS";
    constexpr char kFrozenHiddenColumnsProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_HIDDEN_COLUMNS";

    // 冻结区最多吃掉可用尺寸的一半。没有这条上限，把大量行一次冻结就会把整屏钉死，
    // 滚动区高度归零，表格看上去彻底不动了。
    constexpr int kFrozenBandBudgetDivisor = 2;

    // 主表滚动位置随可视行高刷新而抖动时，多镜像几行以免冻结列窗格底部露白。
    constexpr int kMirrorRowMargin = 3;

    // FrozenPaneTableView 作用：
    // - 冻结区用的只读附属视图，与主表共享模型与选择模型；
    // - 自身不接受滚轮与滚动，一切滚动交还主表，再由控制器把窗格对齐回去。
    class FrozenPaneTableView final : public QTableView
    {
    public:
        explicit FrozenPaneTableView(QTableView* sourceTable, QWidget* parent)
            : QTableView(parent)
            , m_sourceTable(sourceTable)
        {
        }

    protected:
        void wheelEvent(QWheelEvent* eventObject) override
        {
            if (eventObject == nullptr || m_sourceTable.isNull() ||
                m_sourceTable->viewport() == nullptr)
            {
                QTableView::wheelEvent(eventObject);
                return;
            }

            // 冻结区域自身不滚动；把滚轮输入交还主表，随后由控制器同步窗格。
            QCoreApplication::sendEvent(m_sourceTable->viewport(), eventObject);
        }

        void mousePressEvent(QMouseEvent* eventObject) override
        {
            const QPoint restorePoint = sourceScrollPoint();
            QTableView::mousePressEvent(eventObject);
            restoreSourceScroll(restorePoint);
        }

        void mouseDoubleClickEvent(QMouseEvent* eventObject) override
        {
            const QPoint restorePoint = sourceScrollPoint();
            QTableView::mouseDoubleClickEvent(eventObject);
            restoreSourceScroll(restorePoint);
        }

    private:
        // sourceScrollPoint / restoreSourceScroll 作用：
        // - 冻结区与主表共用选择模型，点中的行在主表里是隐藏的；
        // - QAbstractItemView 在 currentChanged 里会 scrollTo(current)，不还原就会整表乱跳。
        QPoint sourceScrollPoint() const
        {
            if (m_sourceTable.isNull())
            {
                return QPoint(-1, -1);
            }
            return QPoint(
                m_sourceTable->horizontalScrollBar()->value(),
                m_sourceTable->verticalScrollBar()->value());
        }

        void restoreSourceScroll(const QPoint& restorePoint)
        {
            if (m_sourceTable.isNull() || restorePoint.x() < 0)
            {
                return;
            }
            if (m_sourceTable->horizontalScrollBar()->value() != restorePoint.x())
            {
                m_sourceTable->horizontalScrollBar()->setValue(restorePoint.x());
            }
            if (m_sourceTable->verticalScrollBar()->value() != restorePoint.y())
            {
                m_sourceTable->verticalScrollBar()->setValue(restorePoint.y());
            }
        }

        QPointer<QTableView> m_sourceTable;
    };

    int headerBandHeight(const QTableView* tableView)
    {
        const QHeaderView* header = tableView != nullptr ? tableView->horizontalHeader() : nullptr;
        return header != nullptr && !header->isHidden() ? header->height() : 0;
    }

    int headerBandWidth(const QTableView* tableView)
    {
        const QHeaderView* header = tableView != nullptr ? tableView->verticalHeader() : nullptr;
        return header != nullptr && !header->isHidden() ? header->width() : 0;
    }

    // setPaneScrollValue 作用：
    // - 窗格滚动条完全由控制器驱动，QTableView 自己算出的范围可能不覆盖目标偏移；
    // - 直接扩展范围后再赋值，避免被 clamp 成错位的一格。
    void setPaneScrollValue(QScrollBar* scrollBar, const int value)
    {
        if (scrollBar == nullptr)
        {
            return;
        }
        if (scrollBar->minimum() > value)
        {
            scrollBar->setMinimum(value);
        }
        if (scrollBar->maximum() < value)
        {
            scrollBar->setMaximum(value);
        }
        if (scrollBar->value() != value)
        {
            scrollBar->setValue(value);
        }
    }
}

namespace ks::ui
{
    TablePausedSnapshotModel::TablePausedSnapshotModel(
        TableSnapshot snapshot,
        QObject* parent)
        : QAbstractTableModel(parent)
        , m_snapshot(std::move(snapshot))
    {
    }

    const TableSnapshot& TablePausedSnapshotModel::snapshot() const
    {
        return m_snapshot;
    }

    int TablePausedSnapshotModel::rowCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : m_snapshot.rows.size();
    }

    int TablePausedSnapshotModel::columnCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : m_snapshot.visibleColumns.size();
    }

    QVariant TablePausedSnapshotModel::data(const QModelIndex& index, const int role) const
    {
        if (!index.isValid() ||
            index.row() < 0 ||
            index.row() >= m_snapshot.rows.size() ||
            index.column() < 0 ||
            index.column() >= m_snapshot.visibleColumns.size())
        {
            return QVariant();
        }

        const TableSnapshotRow& row = m_snapshot.rows.at(index.row());
        if (index.column() >= row.values.size())
        {
            return QVariant();
        }
        if (role == Qt::DisplayRole || role == Qt::EditRole || role == Qt::ToolTipRole)
        {
            return row.values.at(index.column());
        }
        return QVariant();
    }

    QVariant TablePausedSnapshotModel::headerData(
        const int section,
        const Qt::Orientation orientation,
        const int role) const
    {
        if (role != Qt::DisplayRole || section < 0)
        {
            return QVariant();
        }
        if (orientation == Qt::Horizontal)
        {
            return section < m_snapshot.visibleColumns.size()
                ? m_snapshot.visibleColumns.at(section).headerText
                : QVariant();
        }
        if (section >= m_snapshot.rows.size())
        {
            return QVariant();
        }
        const int sourceRow = m_snapshot.rows.at(section).sourceRow;
        return sourceRow >= 0 ? QVariant(sourceRow + 1) : QVariant(section + 1);
    }

    Qt::ItemFlags TablePausedSnapshotModel::flags(const QModelIndex& index) const
    {
        return index.isValid()
            ? Qt::ItemIsEnabled | Qt::ItemIsSelectable
            : Qt::NoItemFlags;
    }

    TableFrozenPaneController::TableFrozenPaneController(QObject* parent)
        : QObject(parent)
    {
    }

    TableFrozenPaneController::~TableFrozenPaneController()
    {
        // The production controller is owned by TableActionBar, which in turn is a
        // direct child of the target table. QWidget destroys its children while the
        // target table's most-derived C++ object is already gone, but QPointer is not
        // cleared until QObject's destructor runs. Calling releaseTarget() here can
        // therefore dispatch virtual table methods through a partially destroyed
        // object. QObject already disconnects every connection owned by this
        // controller, and the target table owns the auxiliary panes, so destruction
        // only needs to let the guarded members tear down locally. Explicit target
        // changes still use setTargetTable()/releaseTarget() while both objects live.
    }

    void TableFrozenPaneController::setTargetTable(QTableView* tableView)
    {
        if (m_targetTable == tableView)
        {
            refreshGeometry();
            return;
        }

        // 换目标表格时先把旧表的冻结行列还原为可见，再清空状态。
        releaseTarget();
        m_targetTable = tableView;
        m_targetModel = tableView != nullptr ? tableView->model() : nullptr;
        connectTarget();
        refreshGeometry();
    }

    QTableView* TableFrozenPaneController::targetTable() const
    {
        return m_targetTable.data();
    }

    bool TableFrozenPaneController::canFreeze() const
    {
        return !m_targetTable.isNull() &&
            m_targetTable->model() != nullptr &&
            m_targetTable->viewport() != nullptr &&
            TableActionBarHostFor(m_targetTable.data()) != nullptr;
    }

    int TableFrozenPaneController::freezeRows(const QList<int>& logicalRows)
    {
        if (!canFreeze() || m_targetTable->verticalHeader() == nullptr)
        {
            return 0;
        }

        QTableView* tableView = m_targetTable.data();
        QHeaderView* header = tableView->verticalHeader();
        QAbstractItemModel* model = tableView->model();
        const int rowCount = model->rowCount();

        QSet<int> alreadyFrozen;
        for (const FrozenLine& line : m_frozenRowLines)
        {
            if (line.index.isValid())
            {
                alreadyFrozen.insert(line.index.row());
            }
        }

        // 候选按可视顺序排序：多选不连续行时冻结区内保持屏幕上原来的相对顺序。
        QList<QPair<int, int>> candidateList; // (可视行, 逻辑行)
        QSet<int> seenRows;
        for (const int logicalRow : logicalRows)
        {
            if (logicalRow < 0 || logicalRow >= rowCount ||
                seenRows.contains(logicalRow) ||
                alreadyFrozen.contains(logicalRow) ||
                tableView->isRowHidden(logicalRow))
            {
                continue;
            }
            seenRows.insert(logicalRow);
            const int visualRow = header->visualIndex(logicalRow);
            if (visualRow >= 0)
            {
                candidateList.push_back({ visualRow, logicalRow });
            }
        }
        std::sort(candidateList.begin(), candidateList.end());

        const int budget = frozenRowsBudget();
        int usedHeight = totalFrozenRowsHeight();
        int addedCount = 0;
        for (const auto& [visualRow, logicalRow] : candidateList)
        {
            const int rowHeight = header->sectionSize(logicalRow);
            if (rowHeight <= 0)
            {
                continue;
            }
            if (usedHeight + rowHeight > budget)
            {
                break;
            }
            m_frozenRowLines.push_back(
                { QPersistentModelIndex(model->index(logicalRow, 0)), rowHeight, logicalRow });
            tableView->setRowHidden(logicalRow, true);
            usedHeight += rowHeight;
            ++addedCount;
        }

        if (addedCount > 0)
        {
            refreshGeometry();
        }
        return addedCount;
    }

    int TableFrozenPaneController::freezeColumns(const QList<int>& logicalColumns)
    {
        if (!canFreeze() || m_targetTable->horizontalHeader() == nullptr)
        {
            return 0;
        }

        QTableView* tableView = m_targetTable.data();
        QHeaderView* header = tableView->horizontalHeader();
        QAbstractItemModel* model = tableView->model();
        const int columnCount = model->columnCount();

        QSet<int> alreadyFrozen;
        for (const FrozenLine& line : m_frozenColumnLines)
        {
            if (line.index.isValid())
            {
                alreadyFrozen.insert(line.index.column());
            }
        }

        QList<QPair<int, int>> candidateList; // (可视列, 逻辑列)
        QSet<int> seenColumns;
        for (const int logicalColumn : logicalColumns)
        {
            if (logicalColumn < 0 || logicalColumn >= columnCount ||
                seenColumns.contains(logicalColumn) ||
                alreadyFrozen.contains(logicalColumn) ||
                tableView->isColumnHidden(logicalColumn))
            {
                continue;
            }
            seenColumns.insert(logicalColumn);
            const int visualColumn = header->visualIndex(logicalColumn);
            if (visualColumn >= 0)
            {
                candidateList.push_back({ visualColumn, logicalColumn });
            }
        }
        std::sort(candidateList.begin(), candidateList.end());

        const int budget = frozenColumnsBudget();
        int usedWidth = totalFrozenColumnsWidth();
        int addedCount = 0;
        for (const auto& [visualColumn, logicalColumn] : candidateList)
        {
            const int columnWidth = header->sectionSize(logicalColumn);
            if (columnWidth <= 0)
            {
                continue;
            }
            if (usedWidth + columnWidth > budget)
            {
                break;
            }
            m_frozenColumnLines.push_back(
                { QPersistentModelIndex(model->index(0, logicalColumn)), columnWidth, logicalColumn });
            tableView->setColumnHidden(logicalColumn, true);
            usedWidth += columnWidth;
            ++addedCount;
        }

        if (addedCount > 0)
        {
            refreshGeometry();
        }
        return addedCount;
    }

    void TableFrozenPaneController::clearFrozenRows()
    {
        if (m_frozenRowLines.isEmpty())
        {
            return;
        }
        unfreezeAllRows();
        refreshGeometry();
    }

    void TableFrozenPaneController::clearFrozenColumns()
    {
        if (m_frozenColumnLines.isEmpty())
        {
            return;
        }
        unfreezeAllColumns();
        refreshGeometry();
    }

    void TableFrozenPaneController::clearFrozenPanes()
    {
        if (m_frozenRowLines.isEmpty() && m_frozenColumnLines.isEmpty())
        {
            return;
        }
        unfreezeAllRows();
        unfreezeAllColumns();
        refreshGeometry();
    }

    int TableFrozenPaneController::frozenRowCount() const
    {
        return m_frozenRowLines.size();
    }

    int TableFrozenPaneController::frozenColumnCount() const
    {
        return m_frozenColumnLines.size();
    }

    void TableFrozenPaneController::unfreezeAllRows()
    {
        if (!m_targetTable.isNull() && m_targetTable->model() != nullptr)
        {
            for (const FrozenLine& line : m_frozenRowLines)
            {
                if (line.index.isValid())
                {
                    m_targetTable->setRowHidden(line.index.row(), false);
                }
            }
        }
        m_frozenRowLines.clear();
        publishFrozenSections();
    }

    void TableFrozenPaneController::unfreezeAllColumns()
    {
        if (!m_targetTable.isNull() && m_targetTable->model() != nullptr)
        {
            const int columnCount = m_targetTable->model()->columnCount();
            for (const FrozenLine& line : m_frozenColumnLines)
            {
                // 索引失效时按 section 还原，否则「取消全部冻结」救不回被隐藏的列。
                const int column = line.index.isValid() ? line.index.column() : line.section;
                if (column >= 0 && column < columnCount)
                {
                    m_targetTable->setColumnHidden(column, false);
                }
            }
        }
        m_frozenColumnLines.clear();
        publishFrozenSections();
    }

    bool TableFrozenPaneController::eventFilter(QObject* watchedObject, QEvent* eventObject)
    {
        if (eventObject != nullptr &&
            (eventObject->type() == QEvent::Resize ||
                eventObject->type() == QEvent::Show ||
                eventObject->type() == QEvent::LayoutRequest ||
                eventObject->type() == QEvent::StyleChange))
        {
            scheduleRefresh();
        }
        return QObject::eventFilter(watchedObject, eventObject);
    }

    void TableFrozenPaneController::disconnectTarget()
    {
        if (!m_targetTable.isNull())
        {
            QObject::disconnect(m_targetTable, nullptr, this, nullptr);
            if (QHeaderView* header = m_targetTable->horizontalHeader())
            {
                QObject::disconnect(header, nullptr, this, nullptr);
            }
            if (QHeaderView* header = m_targetTable->verticalHeader())
            {
                QObject::disconnect(header, nullptr, this, nullptr);
            }
            if (QScrollBar* scrollBar = m_targetTable->horizontalScrollBar())
            {
                QObject::disconnect(scrollBar, nullptr, this, nullptr);
            }
            if (QScrollBar* scrollBar = m_targetTable->verticalScrollBar())
            {
                QObject::disconnect(scrollBar, nullptr, this, nullptr);
            }
            m_targetTable->removeEventFilter(this);
            if (m_targetTable->viewport() != nullptr)
            {
                m_targetTable->viewport()->removeEventFilter(this);
            }
        }
        if (!m_targetModel.isNull())
        {
            QObject::disconnect(m_targetModel, nullptr, this, nullptr);
        }
    }

    void TableFrozenPaneController::connectTarget()
    {
        if (m_targetTable.isNull())
        {
            return;
        }

        const auto onScrolled = [this]()
        {
            if (m_refreshing)
            {
                return;
            }
            m_refreshing = true;
            syncPanes();
            m_refreshing = false;
        };
        const auto onSectionChanged = [this]()
        {
            if (!m_mirroringSections && !m_refreshing)
            {
                scheduleRefresh();
            }
        };

        connect(m_targetTable->horizontalScrollBar(), &QScrollBar::valueChanged, this, onScrolled);
        connect(m_targetTable->verticalScrollBar(), &QScrollBar::valueChanged, this, onScrolled);
        connect(m_targetTable->horizontalScrollBar(), &QScrollBar::rangeChanged, this, onScrolled);
        connect(m_targetTable->verticalScrollBar(), &QScrollBar::rangeChanged, this, onScrolled);
        connect(
            m_targetTable->horizontalHeader(),
            &QHeaderView::sectionResized,
            this,
            onSectionChanged);
        connect(
            m_targetTable->verticalHeader(),
            &QHeaderView::sectionResized,
            this,
            onSectionChanged);
        connect(
            m_targetTable->horizontalHeader(),
            &QHeaderView::sectionMoved,
            this,
            onSectionChanged);
        connect(
            m_targetTable->horizontalHeader(),
            &QHeaderView::sortIndicatorChanged,
            this,
            onSectionChanged);
        m_targetTable->installEventFilter(this);
        if (m_targetTable->viewport() != nullptr)
        {
            m_targetTable->viewport()->installEventFilter(this);
        }

        if (!m_targetModel.isNull())
        {
            // 行列增删和排序由 FrozenLine 里的持久索引自动平移，这里只需触发一次
            // 延迟刷新，让 enforceFrozenState 丢弃失效项并重新校正隐藏状态。
            const auto onModelChanged = [this]() { scheduleRefresh(); };
            connect(m_targetModel, &QAbstractItemModel::modelReset, this, onModelChanged);
            connect(m_targetModel, &QAbstractItemModel::rowsInserted, this, onModelChanged);
            connect(m_targetModel, &QAbstractItemModel::rowsRemoved, this, onModelChanged);
            connect(m_targetModel, &QAbstractItemModel::columnsInserted, this, onModelChanged);
            connect(m_targetModel, &QAbstractItemModel::columnsRemoved, this, onModelChanged);
            connect(m_targetModel, &QAbstractItemModel::layoutChanged, this, onModelChanged);
        }
    }

    void TableFrozenPaneController::scheduleRefresh()
    {
        if (m_refreshScheduled)
        {
            return;
        }
        // 没有任何冻结时无事可做。进程表这类每秒重建内容的表格挂着大量这种信号，
        // 白跑一轮虽然便宜，但没必要。
        if (m_frozenRowLines.isEmpty() &&
            m_frozenColumnLines.isEmpty() &&
            m_topPane.isNull() &&
            m_leftPane.isNull() &&
            m_cornerPane.isNull() &&
            m_appliedFrozenWidth == 0 &&
            m_appliedFrozenHeight == 0)
        {
            return;
        }
        m_refreshScheduled = true;
        QTimer::singleShot(0, this, [this]()
            {
                m_refreshScheduled = false;
                refreshGeometry();
            });
    }

    void TableFrozenPaneController::releaseTarget()
    {
        unfreezeAllRows();
        unfreezeAllColumns();
        destroyPanes();
        if (!m_targetTable.isNull())
        {
            if (TableActionBarHost* host = TableActionBarHostFor(m_targetTable.data()))
            {
                host->setFrozenPaneReservation(0, 0);
            }
        }
        disconnectTarget();
        m_targetTable.clear();
        m_targetModel.clear();
        m_appliedFrozenWidth = 0;
        m_appliedFrozenHeight = 0;
    }

    void TableFrozenPaneController::destroyPanes()
    {
        for (QPointer<QTableView>* guardedPane : { &m_topPane, &m_leftPane, &m_cornerPane })
        {
            if (!guardedPane->isNull())
            {
                guardedPane->data()->hide();
                guardedPane->data()->deleteLater();
                guardedPane->clear();
            }
        }
    }

    QTableView* TableFrozenPaneController::createPane(QPointer<QTableView>& guardedPane)
    {
        if (guardedPane.isNull())
        {
            guardedPane = new FrozenPaneTableView(m_targetTable.data(), m_targetTable.data());
        }
        return guardedPane.data();
    }

    void TableFrozenPaneController::ensurePanes()
    {
        const bool rowsFrozen = !m_frozenRowLines.isEmpty() && m_appliedFrozenHeight > 0;
        const bool columnsFrozen = !m_frozenColumnLines.isEmpty() && m_appliedFrozenWidth > 0;
        if (!rowsFrozen && !columnsFrozen)
        {
            destroyPanes();
            return;
        }

        QTableView* tableView = m_targetTable.data();
        const int headerHeight = headerBandHeight(tableView);
        const int headerWidth = headerBandWidth(tableView);
        // 交叉窗格同时承担三件事：冻结行的行号、冻结列的列标题、以及两者相交的单元格。
        const bool cornerNeeded =
            (m_appliedFrozenWidth + headerWidth) > 0 &&
            (m_appliedFrozenHeight + headerHeight) > 0;

        if (rowsFrozen)
        {
            configurePane(createPane(m_topPane), false, false);
        }
        else if (!m_topPane.isNull())
        {
            m_topPane->hide();
            m_topPane->deleteLater();
            m_topPane.clear();
        }

        if (columnsFrozen)
        {
            configurePane(createPane(m_leftPane), false, false);
        }
        else if (!m_leftPane.isNull())
        {
            m_leftPane->hide();
            m_leftPane->deleteLater();
            m_leftPane.clear();
        }

        if (cornerNeeded)
        {
            configurePane(createPane(m_cornerPane), headerHeight > 0, headerWidth > 0);
        }
        else if (!m_cornerPane.isNull())
        {
            m_cornerPane->hide();
            m_cornerPane->deleteLater();
            m_cornerPane.clear();
        }
    }

    void TableFrozenPaneController::configurePane(
        QTableView* pane,
        const bool showHorizontalHeader,
        const bool showVerticalHeader)
    {
        if (pane == nullptr || m_targetTable.isNull() || m_targetTable->model() == nullptr)
        {
            return;
        }

        QTableView* sourceTable = m_targetTable.data();
        pane->setProperty(kFrozenPaneAuxiliaryProperty, true);
        pane->setProperty(
            kFrozenPaneSourceProperty,
            QVariant::fromValue(static_cast<QObject*>(sourceTable)));

        // setModel 会重建列宽与选择模型，只在真的换了模型时才做。
        if (pane->model() != sourceTable->model())
        {
            pane->setModel(sourceTable->model());
        }
        if (sourceTable->selectionModel() != nullptr &&
            pane->selectionModel() != sourceTable->selectionModel())
        {
            pane->setSelectionModel(sourceTable->selectionModel());
        }
        if (pane->itemDelegate() != sourceTable->itemDelegate())
        {
            pane->setItemDelegate(sourceTable->itemDelegate());
        }
        const int columnCount = sourceTable->model()->columnCount();
        for (int column = 0; column < columnCount; ++column)
        {
            QAbstractItemDelegate* columnDelegate = sourceTable->itemDelegateForColumn(column);
            if (columnDelegate != pane->itemDelegateForColumn(column))
            {
                pane->setItemDelegateForColumn(column, columnDelegate);
            }
        }

        pane->setSelectionMode(sourceTable->selectionMode());
        pane->setSelectionBehavior(sourceTable->selectionBehavior());
        pane->setEditTriggers(QAbstractItemView::NoEditTriggers);
        // 偏移完全由控制器按像素计算，窗格必须固定在按像素滚动模式。
        pane->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
        pane->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        pane->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        pane->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        pane->setAlternatingRowColors(sourceTable->alternatingRowColors());
        pane->setShowGrid(sourceTable->showGrid());
        pane->setGridStyle(sourceTable->gridStyle());
        pane->setTextElideMode(sourceTable->textElideMode());
        pane->setWordWrap(sourceTable->wordWrap());
        pane->setSortingEnabled(false);
        pane->setFrameShape(QFrame::NoFrame);
        // 键盘焦点留在主表，否则方向键会在冻结区里移动当前项。
        pane->setFocusPolicy(Qt::NoFocus);
        pane->setFont(sourceTable->font());
        pane->setPalette(sourceTable->palette());
        pane->setAutoFillBackground(true);
        pane->viewport()->setAutoFillBackground(true);
        pane->viewport()->setPalette(sourceTable->viewport()->palette());
        pane->setCornerButtonEnabled(
            showHorizontalHeader && showVerticalHeader && sourceTable->isCornerButtonEnabled());
        CopyTablePresentation(sourceTable, pane);

        QHeaderView* sourceHorizontalHeader = sourceTable->horizontalHeader();
        QHeaderView* paneHorizontalHeader = pane->horizontalHeader();
        paneHorizontalHeader->setVisible(showHorizontalHeader);
        if (showHorizontalHeader && sourceHorizontalHeader != nullptr)
        {
            paneHorizontalHeader->setFixedHeight(sourceHorizontalHeader->height());
            paneHorizontalHeader->setDefaultAlignment(
                sourceHorizontalHeader->defaultAlignment());
            paneHorizontalHeader->setHighlightSections(
                sourceHorizontalHeader->highlightSections());
            paneHorizontalHeader->setSectionsClickable(
                sourceHorizontalHeader->sectionsClickable());
            paneHorizontalHeader->setSectionsMovable(false);
            paneHorizontalHeader->setStretchLastSection(false);
            paneHorizontalHeader->setSortIndicatorShown(
                sourceHorizontalHeader->isSortIndicatorShown());
            paneHorizontalHeader->setFont(sourceHorizontalHeader->font());
            paneHorizontalHeader->setPalette(sourceHorizontalHeader->palette());
            if (!pane->property("kswordFrozenHeaderBridged").toBool())
            {
                pane->setProperty("kswordFrozenHeaderBridged", true);
                bridgeFrozenHeader(pane);
            }
        }

        QHeaderView* sourceVerticalHeader = sourceTable->verticalHeader();
        QHeaderView* paneVerticalHeader = pane->verticalHeader();
        paneVerticalHeader->setVisible(showVerticalHeader);
        if (showVerticalHeader && sourceVerticalHeader != nullptr)
        {
            paneVerticalHeader->setFixedWidth(sourceVerticalHeader->width());
            paneVerticalHeader->setDefaultAlignment(sourceVerticalHeader->defaultAlignment());
            paneVerticalHeader->setSectionsClickable(false);
            paneVerticalHeader->setFont(sourceVerticalHeader->font());
            paneVerticalHeader->setPalette(sourceVerticalHeader->palette());
        }
    }

    void TableFrozenPaneController::bridgeFrozenHeader(QTableView* pane)
    {
        if (pane == nullptr || pane->horizontalHeader() == nullptr)
        {
            return;
        }

        QHeaderView* paneHeader = pane->horizontalHeader();
        // 冻结列的列标题由交叉窗格绘制，点击排序、拖拽列宽都要转交主表处理，
        // 否则冻结之后这几列的表头就变成了死区。
        connect(
            paneHeader,
            &QHeaderView::sectionClicked,
            this,
            [this](const int logicalIndex)
            {
                if (m_targetTable.isNull() ||
                    !m_targetTable->isSortingEnabled() ||
                    m_targetTable->horizontalHeader() == nullptr)
                {
                    return;
                }
                QHeaderView* sourceHeader = m_targetTable->horizontalHeader();
                const Qt::SortOrder nextOrder =
                    sourceHeader->sortIndicatorSection() == logicalIndex &&
                        sourceHeader->sortIndicatorOrder() == Qt::AscendingOrder
                    ? Qt::DescendingOrder
                    : Qt::AscendingOrder;
                m_targetTable->sortByColumn(logicalIndex, nextOrder);
            });
        connect(
            paneHeader,
            &QHeaderView::sectionResized,
            this,
            [this](const int logicalIndex, int, const int newSize)
            {
                if (m_mirroringSections || m_targetTable.isNull())
                {
                    return;
                }
                m_targetTable->setColumnWidth(logicalIndex, newSize);
            });
    }

    void TableFrozenPaneController::mirrorColumnLayout(QTableView* pane)
    {
        if (pane == nullptr || m_targetTable.isNull())
        {
            return;
        }

        QHeaderView* sourceHeader = m_targetTable->horizontalHeader();
        QHeaderView* paneHeader = pane->horizontalHeader();
        if (sourceHeader == nullptr || paneHeader == nullptr)
        {
            return;
        }

        m_mirroringSections = true;
        paneHeader->setDefaultSectionSize(sourceHeader->defaultSectionSize());
        const int sectionCount = std::min(sourceHeader->count(), paneHeader->count());
        for (int visualIndex = 0; visualIndex < sectionCount; ++visualIndex)
        {
            const int logicalIndex = sourceHeader->logicalIndex(visualIndex);
            if (logicalIndex < 0)
            {
                continue;
            }
            const int paneVisualIndex = paneHeader->visualIndex(logicalIndex);
            if (paneVisualIndex >= 0 && paneVisualIndex != visualIndex)
            {
                paneHeader->moveSection(paneVisualIndex, visualIndex);
            }
        }
        for (int logicalIndex = 0; logicalIndex < sectionCount; ++logicalIndex)
        {
            const bool hidden = sourceHeader->isSectionHidden(logicalIndex);
            if (paneHeader->isSectionHidden(logicalIndex) != hidden)
            {
                paneHeader->setSectionHidden(logicalIndex, hidden);
            }
            if (!hidden)
            {
                paneHeader->resizeSection(logicalIndex, sourceHeader->sectionSize(logicalIndex));
            }
        }
        if (paneHeader->isSortIndicatorShown())
        {
            paneHeader->setSortIndicator(
                sourceHeader->sortIndicatorSection(),
                sourceHeader->sortIndicatorOrder());
        }
        m_mirroringSections = false;
    }

    void TableFrozenPaneController::mirrorRowLayout(
        QTableView* pane,
        const int firstLogicalRow,
        const int lastLogicalRow)
    {
        if (pane == nullptr || m_targetTable.isNull())
        {
            return;
        }

        QHeaderView* sourceHeader = m_targetTable->verticalHeader();
        QHeaderView* paneHeader = pane->verticalHeader();
        if (sourceHeader == nullptr || paneHeader == nullptr)
        {
            return;
        }

        m_mirroringSections = true;
        paneHeader->setDefaultSectionSize(sourceHeader->defaultSectionSize());
        const int sectionCount = std::min(sourceHeader->count(), paneHeader->count());
        const int firstRow = std::max(0, firstLogicalRow);
        const int lastRow = std::min(sectionCount - 1, lastLogicalRow);
        for (int logicalRow = firstRow; logicalRow <= lastRow; ++logicalRow)
        {
            const bool hidden = sourceHeader->isSectionHidden(logicalRow);
            if (paneHeader->isSectionHidden(logicalRow) != hidden)
            {
                paneHeader->setSectionHidden(logicalRow, hidden);
            }
            if (!hidden)
            {
                paneHeader->resizeSection(logicalRow, sourceHeader->sectionSize(logicalRow));
            }
        }
        m_mirroringSections = false;
    }

    void TableFrozenPaneController::mirrorVisibleRowLayout(QTableView* pane)
    {
        QTableView* tableView = m_targetTable.data();
        if (pane == nullptr || tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        const int rowCount = tableView->model()->rowCount();
        if (rowCount <= 0)
        {
            return;
        }

        int firstRow = tableView->rowAt(0);
        if (firstRow < 0)
        {
            firstRow = 0;
        }
        int lastRow = tableView->rowAt(std::max(0, tableView->viewport()->height() - 1));
        if (lastRow < 0)
        {
            lastRow = rowCount - 1;
        }
        if (lastRow < firstRow)
        {
            std::swap(firstRow, lastRow);
        }
        mirrorRowLayout(
            pane,
            std::max(0, firstRow - 1),
            std::min(rowCount - 1, lastRow + kMirrorRowMargin));
    }

    void TableFrozenPaneController::applyFrozenRowFilter(QTableView* pane)
    {
        QTableView* tableView = m_targetTable.data();
        if (pane == nullptr || tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        QHash<int, int> frozenRowHeights;
        for (const FrozenLine& line : m_frozenRowLines)
        {
            if (line.index.isValid())
            {
                frozenRowHeights.insert(line.index.row(), line.extent);
            }
        }

        m_mirroringSections = true;
        const int rowCount = tableView->model()->rowCount();
        for (int row = 0; row < rowCount; ++row)
        {
            const auto heightIterator = frozenRowHeights.constFind(row);
            const bool frozen = heightIterator != frozenRowHeights.cend();
            if (pane->isRowHidden(row) == frozen)
            {
                pane->setRowHidden(row, !frozen);
            }
            if (frozen && pane->rowHeight(row) != heightIterator.value())
            {
                pane->setRowHeight(row, heightIterator.value());
            }
        }
        m_mirroringSections = false;
    }

    void TableFrozenPaneController::applyFrozenColumnFilter(QTableView* pane)
    {
        QTableView* tableView = m_targetTable.data();
        if (pane == nullptr || tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        QHash<int, int> frozenColumnWidths;
        for (const FrozenLine& line : m_frozenColumnLines)
        {
            if (line.index.isValid())
            {
                frozenColumnWidths.insert(line.index.column(), line.extent);
            }
        }

        m_mirroringSections = true;
        const int columnCount = tableView->model()->columnCount();
        for (int column = 0; column < columnCount; ++column)
        {
            const auto widthIterator = frozenColumnWidths.constFind(column);
            const bool frozen = widthIterator != frozenColumnWidths.cend();
            if (pane->isColumnHidden(column) == frozen)
            {
                pane->setColumnHidden(column, !frozen);
            }
            if (frozen && pane->columnWidth(column) != widthIterator.value())
            {
                pane->setColumnWidth(column, widthIterator.value());
            }
        }
        m_mirroringSections = false;
    }

    // enforceFrozenState 作用：
    // - 丢弃已被模型删除的冻结项（持久索引失效）；
    // - 业务刷新把我们隐藏的行列重新显示时，重新捕获尺寸并再次隐藏；
    // - 视口缩小后冻结区超出预算时，从末尾开始解冻直到回到预算之内。
    void TableFrozenPaneController::enforceFrozenState()
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            m_frozenRowLines.clear();
            m_frozenColumnLines.clear();
            return;
        }

        for (int i = m_frozenRowLines.size() - 1; i >= 0; --i)
        {
            FrozenLine& line = m_frozenRowLines[i];
            if (!line.index.isValid())
            {
                m_frozenRowLines.removeAt(i);
                continue;
            }
            const int row = line.index.row();
            if (!tableView->isRowHidden(row))
            {
                const int rowHeight = tableView->verticalHeader() != nullptr
                    ? tableView->verticalHeader()->sectionSize(row)
                    : 0;
                if (rowHeight > 0)
                {
                    line.extent = rowHeight;
                }
                tableView->setRowHidden(row, true);
            }
        }
        const int rowBudget = frozenRowsBudget();
        while (!m_frozenRowLines.isEmpty() && totalFrozenRowsHeight() > rowBudget)
        {
            const FrozenLine line = m_frozenRowLines.takeLast();
            if (line.index.isValid())
            {
                tableView->setRowHidden(line.index.row(), false);
            }
        }

        const int columnCount = tableView->model()->columnCount();
        const int rowCount = tableView->model()->rowCount();
        for (int i = m_frozenColumnLines.size() - 1; i >= 0; --i)
        {
            FrozenLine& line = m_frozenColumnLines[i];
            if (!line.index.isValid())
            {
                /*
                 * 持久索引锚在第 0 行单元格上，业务刷新常见的 setRowCount(0) 会让它失效，
                 * 而列的隐藏位不随 section 清除。此处若直接丢弃条目，该列就永久隐藏且
                 * UI 再也解不开——取消冻结按钮会因计数归零而置灰。
                 */
                if (line.section < 0 || line.section >= columnCount)
                {
                    // 列本身没了：还原显示再丢弃，不留下解不开的隐藏列。
                    if (line.section >= 0)
                    {
                        tableView->setColumnHidden(line.section, false);
                    }
                    m_frozenColumnLines.removeAt(i);
                    continue;
                }
                if (rowCount <= 0)
                {
                    // 表格正在重填（行已清空、还没填回来）。保留冻结状态原样，
                    // 等重填后的这一轮再把持久索引锚回去。
                    continue;
                }
                line.index = QPersistentModelIndex(tableView->model()->index(0, line.section));
                if (!line.index.isValid())
                {
                    tableView->setColumnHidden(line.section, false);
                    m_frozenColumnLines.removeAt(i);
                    continue;
                }
            }
            const int column = line.index.column();
            line.section = column;
            if (!tableView->isColumnHidden(column))
            {
                const int columnWidth = tableView->horizontalHeader() != nullptr
                    ? tableView->horizontalHeader()->sectionSize(column)
                    : 0;
                if (columnWidth > 0)
                {
                    line.extent = columnWidth;
                }
                tableView->setColumnHidden(column, true);
            }
        }
        const int columnBudget = frozenColumnsBudget();
        while (!m_frozenColumnLines.isEmpty() && totalFrozenColumnsWidth() > columnBudget)
        {
            const FrozenLine line = m_frozenColumnLines.takeLast();
            // 持久索引可能已失效，此时只有 section 能定位到要还原的列。
            const int column = line.index.isValid() ? line.index.column() : line.section;
            if (column >= 0 && column < columnCount)
            {
                tableView->setColumnHidden(column, false);
            }
        }

        // 冻结集在本轮可能被重锚或裁剪过，发布出去供取数侧区分冻结与筛选。
        publishFrozenSections();
    }

    void TableFrozenPaneController::layoutPanes()
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->viewport() == nullptr)
        {
            return;
        }

        const QRect viewportGeometry = tableView->viewport()->geometry();
        const int frozenWidth = m_appliedFrozenWidth;
        const int frozenHeight = m_appliedFrozenHeight;
        const int headerHeight = headerBandHeight(tableView);
        const int headerWidth = headerBandWidth(tableView);
        const bool rightToLeft = tableView->isRightToLeft();
        const int bandLeft = rightToLeft
            ? viewportGeometry.right() + 1
            : viewportGeometry.left() - frozenWidth;
        const int cornerLeft = rightToLeft ? bandLeft : bandLeft - headerWidth;

        if (!m_topPane.isNull())
        {
            mirrorColumnLayout(m_topPane.data());
            applyFrozenRowFilter(m_topPane.data());
            m_topPane->setGeometry(
                viewportGeometry.left(),
                viewportGeometry.top() - frozenHeight,
                viewportGeometry.width(),
                frozenHeight);
            m_topPane->setVisible(frozenHeight > 0 && viewportGeometry.width() > 0);
            m_topPane->raise();
        }
        if (!m_leftPane.isNull())
        {
            applyFrozenColumnFilter(m_leftPane.data());
            mirrorVisibleRowLayout(m_leftPane.data());
            m_leftPane->setGeometry(
                bandLeft,
                viewportGeometry.top(),
                frozenWidth,
                viewportGeometry.height());
            m_leftPane->setVisible(frozenWidth > 0 && viewportGeometry.height() > 0);
            m_leftPane->raise();
        }
        if (!m_cornerPane.isNull())
        {
            applyFrozenRowFilter(m_cornerPane.data());
            applyFrozenColumnFilter(m_cornerPane.data());
            m_cornerPane->setGeometry(
                cornerLeft,
                viewportGeometry.top() - frozenHeight - headerHeight,
                frozenWidth + headerWidth,
                frozenHeight + headerHeight);
            m_cornerPane->setVisible(
                (frozenWidth + headerWidth) > 0 && (frozenHeight + headerHeight) > 0);
            m_cornerPane->raise();
        }
    }

    void TableFrozenPaneController::syncPanes()
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        if (!m_topPane.isNull())
        {
            // 非冻结行全部隐藏，内容顶端就是第一条冻结行，纵向锁死在 0。
            setPaneScrollValue(m_topPane->verticalScrollBar(), 0);
            setPaneHorizontalToSource(m_topPane.data());
        }
        if (!m_leftPane.isNull())
        {
            mirrorVisibleRowLayout(m_leftPane.data());
            setPaneVerticalToSource(m_leftPane.data());
            setPaneScrollValue(m_leftPane->horizontalScrollBar(), 0);
        }
        if (!m_cornerPane.isNull())
        {
            setPaneScrollValue(m_cornerPane->verticalScrollBar(), 0);
            setPaneScrollValue(m_cornerPane->horizontalScrollBar(), 0);
        }
    }

    void TableFrozenPaneController::setPaneVerticalToSource(QTableView* pane)
    {
        QTableView* tableView = m_targetTable.data();
        if (pane == nullptr || tableView == nullptr || pane->verticalHeader() == nullptr)
        {
            return;
        }

        // 主表可能按整行滚动，滚动条数值并非像素；统一按“视口顶行的像素落点”对齐，
        // 这样两种滚动模式下冻结列都不会与主表错行。
        const int firstRow = tableView->rowAt(0);
        if (firstRow < 0)
        {
            setPaneScrollValue(pane->verticalScrollBar(), 0);
            return;
        }
        const int sectionPosition = pane->verticalHeader()->sectionPosition(firstRow);
        if (sectionPosition < 0)
        {
            return;
        }
        setPaneScrollValue(
            pane->verticalScrollBar(),
            std::max(0, sectionPosition - tableView->rowViewportPosition(firstRow)));
    }

    void TableFrozenPaneController::setPaneHorizontalToSource(QTableView* pane)
    {
        QTableView* tableView = m_targetTable.data();
        if (pane == nullptr || tableView == nullptr || pane->horizontalHeader() == nullptr)
        {
            return;
        }

        const int firstColumn = tableView->columnAt(0);
        if (firstColumn < 0)
        {
            setPaneScrollValue(pane->horizontalScrollBar(), 0);
            return;
        }
        const int sectionPosition = pane->horizontalHeader()->sectionPosition(firstColumn);
        if (sectionPosition < 0)
        {
            return;
        }
        setPaneScrollValue(
            pane->horizontalScrollBar(),
            std::max(0, sectionPosition - tableView->columnViewportPosition(firstColumn)));
    }

    void TableFrozenPaneController::refreshGeometry()
    {
        if (m_refreshing)
        {
            return;
        }
        if (m_targetTable.isNull() ||
            m_targetTable->viewport() == nullptr ||
            m_targetTable->model() == nullptr)
        {
            destroyPanes();
            m_appliedFrozenWidth = 0;
            m_appliedFrozenHeight = 0;
            return;
        }

        // 未冻结时的快速通道：updatePosition 在 Resize/Show 等高频路径上会直接调进来。
        if (m_frozenRowLines.isEmpty() &&
            m_frozenColumnLines.isEmpty() &&
            m_topPane.isNull() &&
            m_leftPane.isNull() &&
            m_cornerPane.isNull() &&
            m_appliedFrozenWidth == 0 &&
            m_appliedFrozenHeight == 0 &&
            m_targetModel == m_targetTable->model())
        {
            return;
        }

        m_refreshing = true;

        if (m_targetModel != m_targetTable->model())
        {
            // 业务代码整体换掉模型后，旧模型上的持久索引已经失效，直接解除全部冻结。
            disconnectTarget();
            destroyPanes();
            m_frozenRowLines.clear();
            m_frozenColumnLines.clear();
            m_targetModel = m_targetTable->model();
            connectTarget();
        }

        enforceFrozenState();

        if (TableActionBarHost* host = TableActionBarHostFor(m_targetTable.data()))
        {
            host->setFrozenPaneReservation(
                totalFrozenColumnsWidth(),
                totalFrozenRowsHeight());
            const QSize reservation = host->frozenPaneReservation();
            m_appliedFrozenWidth = reservation.width();
            m_appliedFrozenHeight = reservation.height();
        }
        else
        {
            // 普通 QTableView 无法预留视口，强行叠加只会遮住数据，这里直接放弃冻结。
            unfreezeAllRows();
            unfreezeAllColumns();
            m_appliedFrozenWidth = 0;
            m_appliedFrozenHeight = 0;
        }

        ensurePanes();
        layoutPanes();
        syncPanes();
        m_refreshing = false;
    }

    int TableFrozenPaneController::totalFrozenRowsHeight() const
    {
        int height = 0;
        for (const FrozenLine& line : m_frozenRowLines)
        {
            if (line.index.isValid())
            {
                height += line.extent;
            }
        }
        return height;
    }

    int TableFrozenPaneController::totalFrozenColumnsWidth() const
    {
        int width = 0;
        for (const FrozenLine& line : m_frozenColumnLines)
        {
            if (line.index.isValid())
            {
                width += line.extent;
            }
        }
        return width;
    }

    int TableFrozenPaneController::frozenRowsBudget() const
    {
        if (m_targetTable.isNull() || m_targetTable->viewport() == nullptr)
        {
            return 0;
        }
        return std::max(
            0,
            (m_targetTable->viewport()->height() + m_appliedFrozenHeight) /
                kFrozenBandBudgetDivisor);
    }

    int TableFrozenPaneController::frozenColumnsBudget() const
    {
        if (m_targetTable.isNull() || m_targetTable->viewport() == nullptr)
        {
            return 0;
        }
        return std::max(
            0,
            (m_targetTable->viewport()->width() + m_appliedFrozenWidth) /
                kFrozenBandBudgetDivisor);
    }

    void TableFrozenPaneController::publishFrozenSections()
    {
        QTableView* tableView = m_targetTable.data();
        if (tableView == nullptr)
        {
            return;
        }

        QVariantList frozenRows;
        frozenRows.reserve(m_frozenRowLines.size());
        for (const FrozenLine& line : m_frozenRowLines)
        {
            const int row = line.index.isValid() ? line.index.row() : line.section;
            if (row >= 0)
            {
                frozenRows.push_back(row);
            }
        }

        QVariantList frozenColumns;
        frozenColumns.reserve(m_frozenColumnLines.size());
        for (const FrozenLine& line : m_frozenColumnLines)
        {
            const int column = line.index.isValid() ? line.index.column() : line.section;
            if (column >= 0)
            {
                frozenColumns.push_back(column);
            }
        }

        tableView->setProperty(kFrozenHiddenRowsProperty, frozenRows);
        tableView->setProperty(kFrozenHiddenColumnsProperty, frozenColumns);
    }

    namespace
    {
        bool sectionListContains(
            const QTableView* tableView,
            const char* propertyName,
            const int section)
        {
            if (tableView == nullptr || section < 0)
            {
                return false;
            }
            const QVariant stored = tableView->property(propertyName);
            if (!stored.isValid())
            {
                return false;
            }
            const QVariantList sectionList = stored.toList();
            for (const QVariant& entry : sectionList)
            {
                bool converted = false;
                if (entry.toInt(&converted) == section && converted)
                {
                    return true;
                }
            }
            return false;
        }
    }

    bool isRowHiddenByFreeze(const QTableView* tableView, const int row)
    {
        return sectionListContains(tableView, kFrozenHiddenRowsProperty, row);
    }

    bool isColumnHiddenByFreeze(const QTableView* tableView, const int column)
    {
        return sectionListContains(tableView, kFrozenHiddenColumnsProperty, column);
    }
}
