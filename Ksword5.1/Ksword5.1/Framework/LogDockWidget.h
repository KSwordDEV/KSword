#pragma once

// LogDockWidget 是“日志输出”Dock 中的可视化日志面板。
// 该控件负责：
// 1) 展示日志表格（等级/时间/内容/文件/函数）；
// 2) 提供等级筛选、事件追踪、复制与导出能力；
// 3) 从全局日志管理器 KswordARKEventEntry 周期刷新数据。

#include "../Framework.h"

#include <QColor>
#include <QIcon>
#include <QPoint>
#include <QString>
#include <QVariant>
#include <QWidget>

#include <vector>

// 前置声明：减少头文件依赖体积，提升编译速度。
class QCheckBox;
class QHBoxLayout;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QShowEvent;
class QTableView;
class QTimer;
class QVBoxLayout;

namespace ks::ui
{
    template<typename RowT>
    class FlatTableModel;
}

class LogDockWidget final : public QWidget
{
public:
    // 构造函数作用：
    // - 初始化全部 UI 控件；
    // - 建立信号连接；
    // - 启动定时刷新。
    // 参数 parent：Qt 父对象指针。
    explicit LogDockWidget(QWidget* parent = nullptr);

    // refreshNow：独立日志窗口重新显示时强制同步最新日志快照。
    void refreshNow();

protected:
    void changeEvent(QEvent* event) override;
    // 隐藏时不重建表格，重新显示前读取日志管理器保存的最新完整历史。
    void showEvent(QShowEvent* event) override;

private:
    // initializeUi 作用：
    // - 创建布局、筛选区、按钮区、日志表格；
    // - 设置不可编辑与列宽策略。
    void initializeUi();

    // initializeConnections 作用：
    // - 连接复选框、按钮、右键菜单、定时器等交互逻辑。
    void initializeConnections();

    // initializeRefreshTimer 作用：
    // - 创建并启动刷新定时器；
    // - 使用 Revision() 做轻量级变更检测。
    void initializeRefreshTimer();

    // refreshTableFromManager 作用：
    // - 从日志管理器读取快照；
    // - 应用等级筛选/追踪筛选；
    // - 仅把最近 N 条筛选命中的日志交给表格模型，内部日志仍由 KswordARKEventEntry 保留全量；
    // - 重建表格并在需要时滚动到底部。
    // 参数 forceRefresh：
    // - true  强制刷新（用于用户主动操作）；
    // - false 仅在 revision 变化时刷新（用于定时器）。
    void refreshTableFromManager(bool forceRefresh);

    // rebuildTable 作用：
    // - 用 filteredEvents 一次性替换轻量表格模型的数据快照；
    // - 不再为每个单元格创建 QTableWidgetItem，减少刷新时的堆分配与析构压力。
    // 参数 filteredEvents：已筛选后的可见日志集合。
    void rebuildTable(std::vector<kEvent> filteredEvents);

    // visibleLogLimit 作用：
    // - 读取“最近日志条数”数字框当前值；
    // - 在 UI 尚未初始化或控件异常时回退到默认显示条数。
    // 参数：无。
    // 返回值：当前界面允许展示的最大日志行数，不影响内部全量日志存储。
    int visibleLogLimit() const;

    // applyDetailColumnVisibility 作用：
    // - 根据“详细信息”复选框状态切换文件列与函数列；
    // - 让日志表格在简洁模式和详细模式之间切换。
    void applyDetailColumnVisibility();

    // resolveLogTableData 作用：
    // - 为 FlatTableModel 统一解析 Display/Decoration/ToolTip/Foreground/Background 等 role；
    // - 把原先分散在 QTableWidgetItem 上的文本、图标和行着色逻辑集中到模型层。
    // 参数 logItem：目标行日志对象；column：目标列；role：Qt 数据角色。
    // 返回值：对应 role 的 QVariant；不支持或越界时返回空 QVariant。
    QVariant resolveLogTableData(const kEvent& logItem, int column, int role) const;

    // getRowHighlightBrush 作用：
    // - 根据日志等级返回整行背景/前景高亮色；
    // - 只对 Error/Fatal 返回有效颜色，其它等级保持当前主题默认表格配色。
    // 参数 logItem：目标日志对象；role：Qt::BackgroundRole 或 Qt::ForegroundRole。
    // 返回值：有效 QBrush 包装在 QVariant 中；无特殊样式时返回空 QVariant。
    QVariant getRowHighlightBrush(const kEvent& logItem, int role) const;

    // makeLevelSquareIcon 作用：
    // - 生成一个纯色小方块图标，放在“等级”列。
    // 参数 color：方块颜色。
    // 返回值：生成后的 QIcon。
    QIcon makeLevelSquareIcon(const QColor& color) const;

    // getLevelColor 作用：返回等级对应颜色。
    QColor getLevelColor(kLogLevel level) const;

    // getLevelText 作用：返回等级字符串（DEBUG/INFO/...）。
    QString getLevelText(kLogLevel level) const;

    // isLevelEnabledByCheckbox 作用：
    // - 根据复选框状态判断某等级是否应展示。
    bool isLevelEnabledByCheckbox(kLogLevel level) const;

    // showTableContextMenu 作用：
    // - 在表格单元格右键时弹出菜单；
    // - 提供复制单元格/复制行/跟踪或取消追踪。
    // 参数 position：右键点在表格视口坐标系中的位置。
    void showTableContextMenu(const QPoint& position);

    // copySingleCell 作用：复制指定单元格文本到剪贴板。
    // 参数 row/column：目标行列索引。
    void copySingleCell(int row, int column);

    // copySingleRow 作用：复制指定整行（制表符分隔）到剪贴板。
    // 参数 row：目标行索引。
    void copySingleRow(int row);

    // copySelectedRows 作用：
    // - 复制当前表格中选中的全部日志行；
    // - 多选行右键菜单只调用该入口，保证一次性复制所有选中行。
    // 参数：无，函数内部读取表格选择模型。
    // 返回值：无，复制文本直接写入系统剪贴板。
    void copySelectedRows();

    // copyVisibleRows 作用：
    // - 把当前表格可见内容全部复制到剪贴板；
    // - 适配事件追踪过滤后的可见子集。
    void copyVisibleRows();

    // visibleEvents 作用：
    // - 返回轻量模型当前保存的可见日志快照；
    // - 复制、追踪、右键菜单统一读取该快照，避免 Dock 再维护第二份平行缓存。
    // 参数：无。
    // 返回值：模型内行数组的只读引用；模型未创建时返回空数组引用。
    const std::vector<kEvent>& visibleEvents() const;

    // visibleEventAt 作用：
    // - 按表格行号安全读取当前可见日志；
    // - 集中处理模型未创建和行号越界场景。
    // 参数 row：表格行号。
    // 返回值：有效时返回日志对象指针；无效时返回 nullptr。
    const kEvent* visibleEventAt(int row) const;

    // collectSelectedRowIndexes 作用：
    // - 从 QTableView 的选择模型中收集当前被选中的行号；
    // - 自动排序并去重，避免同一行被多个单元格重复计入。
    // 参数：无。
    // 返回值：合法行号列表，顺序与界面从上到下保持一致。
    std::vector<int> collectSelectedRowIndexes() const;

    // buildVisibleRowText 作用：
    // - 按当前可见列拼接一行日志文本；
    // - 供“复制行/复制可见”复用，确保复制结果与界面一致。
    QString buildVisibleRowText(const kEvent& logItem) const;

    // startTrackingByRow 作用：
    // - 读取某行的 GUID；
    // - 进入“仅显示同 GUID 日志”模式。
    // 参数 row：触发追踪的行索引。
    void startTrackingByRow(int row);

    // cancelTracking 作用：退出事件追踪模式并恢复常规过滤。
    void cancelTracking();

    // exportAllLogs 作用：
    // - 弹出保存对话框；
    // - 调用 KswordARKEventEntry.Save 导出全部日志。
    void exportAllLogs();

    // chooseExportPath 作用：
    // - Windows 上优先调用原生 shell 保存对话框；
    // - shell 调用失败时回退为手动输入路径。
    // 返回值：
    // - 非空：用户确认后的目标路径；
    // - 空串：用户取消。
    QString chooseExportPath();

    // clearAllLogsWithDoubleConfirm 作用：
    // - 两次确认后清空日志管理器；
    // - 刷新表格。
    void clearAllLogsWithDoubleConfirm();

private:
    // ======== 主布局与控件 ========
    QVBoxLayout* m_rootLayout = nullptr;      // 根布局：纵向堆叠“单行工具栏/表格”。
    QHBoxLayout* m_filterLayout = nullptr;    // m_filterLayout：保留成员位，当前未单独挂入布局。
    QHBoxLayout* m_actionLayout = nullptr;    // 动作布局：图标按钮 + 全部复选框。

    QCheckBox* m_debugCheck = nullptr;        // Debug 级别显示开关。
    QCheckBox* m_infoCheck = nullptr;         // Info 级别显示开关。
    QCheckBox* m_warnCheck = nullptr;         // Warn 级别显示开关。
    QCheckBox* m_errorCheck = nullptr;        // Error 级别显示开关。
    QCheckBox* m_fatalCheck = nullptr;        // Fatal 级别显示开关。
    QCheckBox* m_detailCheck = nullptr;       // “详细信息”开关：控制文件/函数列显示。
    QCheckBox* m_autoScrollCheck = nullptr;   // “保持滚动到最底端”开关。
    QSpinBox* m_visibleLimitSpin = nullptr;   // “最近日志条数”输入：只限制界面渲染行数，不截断内部日志。
    QLineEdit* m_textFilterEdit = nullptr;    // 文本过滤框：匹配日志内容、文件和函数字段。

    QPushButton* m_exportButton = nullptr;       // 导出日志按钮。
    QPushButton* m_clearButton = nullptr;        // 清空日志按钮。
    QPushButton* m_copyVisibleButton = nullptr;  // 复制可见按钮。

    QTableView* m_logTable = nullptr;                         // 核心日志表格视图。
    ks::ui::FlatTableModel<kEvent>* m_logModel = nullptr;     // 核心日志表格轻量数据模型。
    QTimer* m_refreshTimer = nullptr;                         // 定时刷新器。

    // ======== 刷新与过滤状态 ========
    ks::log::RecentSnapshotToken m_recentSnapshotToken; // Query identity and last matching record.
    std::size_t m_lastRevision = 0;           // 上次渲染时的日志 revision。

    bool m_isTracking = false;                // 当前是否处于“按 GUID 追踪”模式。
    GUID m_trackingGuid{};                    // 追踪模式下使用的目标 GUID。
};
