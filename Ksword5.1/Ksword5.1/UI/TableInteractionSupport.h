#pragma once

class QApplication;
class QAbstractItemView;
class QObject;
class QTableView;

#include <QList>
#include <QString>
#include <QTableWidgetItem>
#include <QTreeWidget>
#include <QVariant>
#include <QtGlobal>

#include <functional>

namespace ks::ui
{
    struct ResultTableCapabilities;

    // 由 ResultTableHost 复用现有排序、冻结、搜索和快照条实现；页面不直接调用。
    void ConfigureResultTableInteractions(
        QTableView* tableView,
        const ResultTableCapabilities& capabilities);

    // NumericSortRole 作用：
    // - 存放“这一格用于排序的真实数值”，与 DisplayRole 的可读文本彻底分家；
    // - 表格默认按 DisplayRole 的字符串比大小，于是 PID 排成 1/10/100/11/2、
    //   512 KB 排在 2.50 MB 后面、不补零的十六进制地址完全乱序——这类问题在本仓
    //   已经被四处 copy-paste 的私有 NumericItem 各修一遍，此处统一收口；
    // - 不能用 Qt::UserRole：句柄页等已用它存行索引，会互相覆盖。
    constexpr int NumericSortRole = Qt::UserRole + 900;

    // NumericTableItem 作用：
    // - 供 QTableWidget 使用的数值排序单元格：显示文本随便写（十六进制、KB/MB、带单位），
    //   排序一律读 NumericSortRole；
    // - 该角色缺失时回落到基类的字符串比较，混用不会崩。
    class NumericTableItem final : public QTableWidgetItem
    {
    public:
        // 构造函数：displayText 为界面文本，sortValue 为参与排序的真实数值。
        NumericTableItem(const QString& displayText, const qulonglong sortValue)
            : QTableWidgetItem(displayText)
        {
            setData(NumericSortRole, QVariant::fromValue<qulonglong>(sortValue));
        }

        // 构造函数重载：带符号数值（如可正可负的偏移、差值）。
        NumericTableItem(const QString& displayText, const qlonglong sortValue)
            : QTableWidgetItem(displayText)
        {
            setData(NumericSortRole, QVariant::fromValue<qlonglong>(sortValue));
        }

        bool operator<(const QTableWidgetItem& otherItem) const override
        {
            const QVariant leftValue = data(NumericSortRole);
            const QVariant rightValue = otherItem.data(NumericSortRole);
            if (!leftValue.isValid() || !rightValue.isValid())
            {
                return QTableWidgetItem::operator<(otherItem);
            }
            return leftValue.toDouble() < rightValue.toDouble();
        }
    };

    // NumericTreeItem 作用：
    // - QTreeWidget 版本；每列可各自带一个 NumericSortRole，未带该角色的列按原字符串比较。
    class NumericTreeItem : public QTreeWidgetItem
    {
    public:
        using QTreeWidgetItem::QTreeWidgetItem;

        // setNumericCell 作用：一次写入某列的显示文本与排序数值。
        void setNumericCell(const int column, const QString& displayText, const qulonglong sortValue)
        {
            setText(column, displayText);
            setData(column, NumericSortRole, QVariant::fromValue<qulonglong>(sortValue));
        }

        bool operator<(const QTreeWidgetItem& otherItem) const override
        {
            const QTreeWidget* ownerTree = treeWidget();
            const int sortedColumn = ownerTree != nullptr ? ownerTree->sortColumn() : 0;
            const QVariant leftValue = data(sortedColumn, NumericSortRole);
            const QVariant rightValue = otherItem.data(sortedColumn, NumericSortRole);
            if (!leftValue.isValid() || !rightValue.isValid())
            {
                return QTreeWidgetItem::operator<(otherItem);
            }
            return leftValue.toDouble() < rightValue.toDouble();
        }
    };

    // InstallGlobalTableInteractionSupport 作用：
    // - 为应用内所有 QTableView/QTableWidget 统一提供 Ctrl 多选、Ctrl+C 复制和 TSV 导出；
    // - 未开启持续排序的 QTableWidget 可点击表头执行一次性排序，刷新填表时不会发生行错位；
    // - 保留业务表格的原有右键菜单，并在其末尾追加复制选中行和导出选中行；
    // - 每张表顶部预留紧凑操作区并放置导出按钮，动态创建的表格也会自动接入。
    void InstallGlobalTableInteractionSupport(QApplication* appInstance);

    // OpenProcessDetailByPid 作用：请求主窗口打开指定 PID 的进程详细信息。
    // - 由各业务表的右键菜单显式调用，不负责自动为表格添加菜单项；
    // - pid 为 0 或主窗口尚未创建时不执行操作。
    void OpenProcessDetailByPid(quint32 pid);

    // OpenProcessDetailByIdentity 作用：
    // - 按 PID 与捕获时创建时间请求打开历史进程详情；
    // - 调用方式：持有历史事件 identity 的业务表右键菜单调用；
    // - 入参 pid：历史事件中的进程 PID；
    // - 入参 creationTime100ns：历史事件捕获时的进程创建时间；
    // - 返回：无；identity 缺失时不降级为纯 PID 跳转。
    void OpenProcessDetailByIdentity(
        quint32 pid,
        quint64 creationTime100ns);

    // IsTableUiCommitBlockedByContextMenu 作用：
    // - 输入：一次 UI 提交会修改的全部表格；
    // - 返回：任一表格的右键菜单仍打开，或用户仍按住左 Ctrl 多选时为 true（Issue #149）；
    // - 供携带大型可移动快照的刷新入口先判断，避免正常刷新为延迟回调复制整份数据。
    bool IsTableUiCommitBlockedByContextMenu(
        const QList<QTableView*>& tableList);

    // IsItemViewUiCommitBlockedByContextMenu 作用：
    // - 与表格版本相同，但同时支持 QTreeView/QTreeWidget；
    // - 用于设备树、句柄树等带业务右键菜单的异步重建入口；
    // - 左 Ctrl 多选进行中时对所有视图统一返回 true（Issue #149）。
    bool IsItemViewUiCommitBlockedByContextMenu(
        const QList<QAbstractItemView*>& itemViewList);

    // DeferTableUiCommitIfContextMenuOpen 作用：
    // - 输入：提交任务所有者、稳定去重键、会被重建的表格集合和 UI 提交函数；
    // - 处理：任一表格右键菜单打开或左 Ctrl 多选进行中时只保留同 owner/key 的最新提交，
    //   菜单关闭且左 Ctrl 松开后回投（Issue #149）；
    // - 返回：true 表示本次提交已延后，false 表示无需缓存，调用方应立即提交。
    // 调用方法：刷新函数在修改模型前调用；返回 true 时立即结束本轮刷新。
    bool DeferTableUiCommitIfContextMenuOpen(
        QObject* owner,
        const QString& commitKey,
        const QList<QTableView*>& tableList,
        std::function<void()> commitAction);

    // DeferItemViewUiCommitIfContextMenuOpen 作用：
    // - 为 QTableView 与 QTreeView 提供同一菜单/左 Ctrl 屏障与 owner/key latest-wins 语义；
    // - 刷新函数必须在清空缓存、模型或 item 前调用，返回 true 时立即结束。
    bool DeferItemViewUiCommitIfContextMenuOpen(
        QObject* owner,
        const QString& commitKey,
        const QList<QAbstractItemView*>& itemViewList,
        std::function<void()> commitAction);

    // DeferUiCommitIfComboBoxPopupOpen 作用：
    // - 输入：提交任务所有者、稳定去重键和 UI 提交函数；
    // - 处理：任意 QComboBox 弹层展开时只保留同 owner/key 的最新提交，弹层收起后回投；
    // - 返回：true 表示本次提交已延后，false 表示可以立即提交。
    // 调用方法：不重建表格、只重建下拉框内容的异步回填入口在改动控件前调用。
    // Why：弹层是抓着鼠标键盘的独立顶层窗口，展开期间被清空重填后会继续抓着输入但内容失效，
    //      用户看到的就是“点开下拉框之后整个界面点不动”。
    bool DeferUiCommitIfComboBoxPopupOpen(
        QObject* owner,
        const QString& commitKey,
        std::function<void()> commitAction);
}
