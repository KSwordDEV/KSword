#pragma once

// 字段呈现是展示策略：调用方仍负责 R0、JSON、XML 或报告的数据和准确来源。
// 本模块统一列宽、主题、字体和复制，不把 typed 字段重新导出再解析。
#include <QFont>
#include <QModelIndex>
#include <QPoint>
#include <QString>

class QAbstractItemView;
class QColor;
class QTreeWidget;
class QTreeWidgetItem;

namespace ks::ui
{
    // 统一字段字号；baseFont 必须是未放大的应用字体，返回 1.6 倍展示字号。
    QFont ScaledReportFont(const QFont& baseFont);
    // 地址、哈希和状态外观只影响展示，不参与值解码或业务判定。
    bool FieldValueLooksMonospace(const QString& value);
    bool FieldValueStatusColor(const QString& value, QColor* colorOut);

    // 初始化两列只读字段树，并安装随应用字体/主题变化的安全刷新控制器。
    // showBranches 控制树形箭头；已有分组和字段数据不变。
    void ConfigureFieldTree(QTreeWidget* tree, bool showBranches);
    // 根据全部字段名及层次测量名称列，长说明跨列行不挤占值列。
    void RefreshFieldTree(QTreeWidget* tree);
    // 添加明确的分组或字段；note 是跨列说明，decorateValue 是已知报告值的外观提示。
    // 返回由 Qt 树拥有的节点；调用方不得跨嵌套事件循环保存该裸指针。
    QTreeWidgetItem* AppendFieldGroup(QTreeWidget* tree, const QString& title);
    QTreeWidgetItem* AppendFieldRow(QTreeWidget* tree, QTreeWidgetItem* parent,
        const QString& name, const QString& value, bool note = false, bool decorateValue = true);
    // 已有 typed 节点亦可采用相同呈现；group/note/decorateValue 不改变字段和值。
    void SetFieldItemPresentation(QTreeWidgetItem* item, bool group, bool note, bool decorateValue);
    // 导出树内完整字段；分组保留 [标题]，字段统一使用“名称: 值”。
    QString FieldTreeToPlainText(const QTreeWidget* tree);

    // 可在不写真实剪贴板的回归中检查菜单打开前冻结的内容。
    struct StructuredCopySnapshot
    {
        QString value;  // 当前单元格（字段树固定取值列）。
        QString row;    // 当前完整行，两列统一为“名称: 值”。
        QString all;    // 菜单打开前的全部呈现字段。
        bool hasRow = false;
    };
    StructuredCopySnapshot CaptureStructuredCopy(const QAbstractItemView* view, const QModelIndex& clicked);
    // 工具栏和键盘共同使用；多选按模型先后顺序复制，不读取剪贴板。
    QString StructuredSelectionText(const QAbstractItemView* view);
    // 宿主提供准确原文作为无选区及“复制全部”的权威载荷，不从呈现节点重新猜测数据。
    // standalone 树没有原文宿主时仍可导出其自身字段，调用方可随报告刷新更新原文。
    void SetStructuredCopyFallback(QAbstractItemView* view, const QString& authoritativeText);
    // 键盘、工具栏和菜单共用：选区优先，无选区使用宿主原文或完整字段。
    QString StructuredCopyText(const QAbstractItemView* view);
    // 嵌套菜单只处理冻结字符串；树刷新不再访问旧节点，宿主被销毁则返回空串。
    QString ExecStructuredCopyMenu(QAbstractItemView* view, const QPoint& localPosition);
    // 安装通用主题菜单和 Ctrl+C；写剪贴板仅发生在用户主动复制且宿主仍存活时。
    void InstallStructuredCopyMenu(QAbstractItemView* view);
}
