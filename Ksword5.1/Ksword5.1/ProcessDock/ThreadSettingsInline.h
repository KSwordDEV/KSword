#pragma once

class QSortFilterProxyModel;
class QStandardItemModel;
class QToolButton;
class QTreeView;
struct ThreadStackTarget;

// GUI 线程调用：将公开 Win32 设置挂到五列树，返回独立的 R3 刷新按钮（视图拥有控制器）。
// model/proxy 是现有树的源模型/搜索代理；target 是冻结的线程身份。不会请求驱动。
QToolButton* AddInlineThreadSettings(QTreeView& view, QStandardItemModel& model,
    QSortFilterProxyModel& proxy, const ThreadStackTarget& target);
