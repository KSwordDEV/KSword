#pragma once

class QApplication;
class QAbstractItemView;
class QTableView;
class QWidget;
class QString;

namespace ks::ui
{
    enum class TablePresentationDensity
    {
        Comfortable,
        Compact
    };

    // Shared view chrome only: no model/delegate/selection/sort/row-height changes.
    // Existing local QSS outside the marked presentation block remains intact.
    // Geometry belongs to this widget-level block, never the application baseline.
    void ApplyTablePresentation(QAbstractItemView* view, bool normalizeHeader = true);
    void SetTablePresentationDensity(QAbstractItemView* view, TablePresentationDensity density);
    // Frozen panes, paused snapshots and comparison overlays mirror their source chrome.
    void CopyTablePresentation(const QAbstractItemView* source, QAbstractItemView* target);

    // Explicit opt-out for HEX grids and other purpose-built visualizations.
    // Set before the first presentation application; changing it later removes the block.
    void SetPreserveCustomTablePresentation(QAbstractItemView* view, bool preserve);
    bool PreservesCustomTablePresentation(const QAbstractItemView* view);

    // Queued, lifetime-guarded discovery of QTableView/QTreeView and their widget variants.
    // Show/StyleChange never repolish synchronously, including newly built dialog subtrees.
    void InstallGlobalTablePresentation(QApplication* appInstance);

    // 为多表页面建立明确标题区；只重新挂接原表格，不替换模型、动作条或选区。
    QWidget* CreateTitledTablePanel(QTableView* table, const QString& title, QWidget* parent = nullptr);
}
