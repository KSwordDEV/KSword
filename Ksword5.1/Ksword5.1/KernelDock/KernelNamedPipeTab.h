#pragma once

// ============================================================
// KernelNamedPipeTab.h
// 作用说明：
// 1) 提供独立 Named Pipe 枚举 Widget；
// 2) 只依赖 R3 worker，不需要 KernelDock.h 集成；
// 3) 留给集成会话挂入 KernelDock 二级 Tab。
// ============================================================

#include "KernelNamedPipeWorker.h"

#include <QWidget>

#include <cstdint>
#include <vector>

class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
#include "../UI/StructuredFieldView.h"
class QResizeEvent;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;
class QHBoxLayout;

class KernelNamedPipeTab final : public QWidget
{
public:
    // 构造函数：
    // - 输入 parent：Qt 父对象；
    // - 处理逻辑：创建工具栏、过滤框、结果表和详情面板；
    // - 返回结果：无，构造后会排队发起首次刷新。
    explicit KernelNamedPipeTab(QWidget* parent = nullptr);

    enum class TableColumn : int
    {
        PipeName = 0,
        NtPath,
        Attributes,
        LastWriteTime,
        Status,
        SourceDirectory,
        Count
    };

private:
    // initializeUi：
    // - 输入：无；
    // - 处理逻辑：创建按钮、过滤输入、表格和详情框；
    // - 返回结果：无。
    void initializeUi();

    // initializeConnections：
    // - 输入：无；
    // - 处理逻辑：绑定刷新、过滤、复制、详情和右键菜单动作；
    // - 返回结果：无。
    void initializeConnections();

    // requestRefresh：
    // - 输入 forceRefresh：true 表示正在刷新时排队再刷一次；
    // - 处理逻辑：后台运行 runKernelNamedPipeSnapshotTask；
    // - 返回结果：无，结果通过 applySnapshot 回填。
    void requestRefresh(bool forceRefresh);

    // applySnapshot：
    // - 输入 refreshTicket：刷新序号；snapshot：worker 返回结果；
    // - 处理逻辑：丢弃过期结果，重建表格和详情面板；
    // - 返回结果：无。
    void applySnapshot(std::uint64_t refreshTicket, const KernelNamedPipeSnapshot& snapshot);

    // rebuildTable：
    // - 输入：无；
    // - 处理逻辑：把 m_rows 映射为 QTreeWidget 行；
    // - 返回结果：无。
    void rebuildTable();

    // applyFilter：
    // - 输入：无，读取 m_filterEdit；
    // - 处理逻辑：按名称、路径、状态和来源目录隐藏不匹配行；
    // - 返回结果：无。
    void applyFilter();

    // updateDetailPanel：
    // - 输入：无，读取当前选中行和 m_lastSnapshot；
    // - 处理逻辑：展示 NPFS 枚举说明、候选路径状态和当前行详情；
    // - 返回结果：无。
    void updateDetailPanel();

    // copyCurrentRow：
    // - 输入：无；
    // - 处理逻辑：复制当前行可见列，字段用 Tab 分隔；
    // - 返回结果：无。
    void copyCurrentRow();

    // showContextMenu：
    // - 输入 localPosition：表格视口内坐标；
    // - 处理逻辑：弹出复制/详情菜单；
    // - 返回结果：无。
    void showContextMenu(const QPoint& localPosition);

    // selectedRow：
    // - 输入：无；
    // - 处理逻辑：通过 UserRole 中的 row index 查找 m_rows；
    // - 返回结果：当前行指针；无选中或索引失效时返回 nullptr。
    const KernelNamedPipeEntry* selectedRow() const;

    // applyAdaptiveColumnWidths：
    // - 输入：无；
    // - 处理逻辑：按当前视口宽度设置常用列宽；
    // - 返回结果：无。
    void applyAdaptiveColumnWidths();

    void resizeEvent(QResizeEvent* event) override;

private:
    QVBoxLayout* m_rootLayout = nullptr;
    QHBoxLayout* m_toolbarLayout = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QPushButton* m_copyButton = nullptr;
    QPushButton* m_detailButton = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTreeWidget* m_resultTable = nullptr;
    ks::ui::StructuredFieldView* m_detailEdit = nullptr;

    std::vector<KernelNamedPipeEntry> m_rows;
    KernelNamedPipeSnapshot m_lastSnapshot;
    bool m_refreshInProgress = false;
    bool m_refreshPending = false;
    std::uint64_t m_refreshTicket = 0;
};
