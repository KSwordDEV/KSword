#pragma once

// ============================================================
// TableSearchSupport.h
// 作用：
// 1) 为所有 QTableView/QTableWidget 自动安装表格搜索入口；
// 2) 只在内容超过一屏且页面没有专属搜索框时显示；
// 3) 仅显示搜索按钮，点击后激活标题栏搜索框；空间不足时隐藏；
// 4) 支持“仅显示搜索结果”，并精确恢复启用前的行隐藏状态；
// 5) 提供表格名称解析、模型匹配与结果定位，供顶部搜索复用。
// ============================================================

#include <QPersistentModelIndex>
#include <QPointer>
#include <QString>
#include <QVector>

class QTableView;

namespace ks::ui
{
    // TableCellSearchMatch：保存一次表格单元格搜索命中及其稳定模型索引。
    struct TableCellSearchMatch
    {
        QPointer<QTableView> tableView;       // tableView：命中所属表格。
        QPersistentModelIndex modelIndex;     // modelIndex：命中单元格，模型重置后自动失效。
        QString matchedText;                  // matchedText：单元格展示文本。
        QString locationText;                 // locationText：表格名、行号与列名组成的位置说明。
        int matchRank = 2;                    // matchRank：0=完全匹配，1=前缀，2=包含。
    };

    // InstallTableSearchSupport：给表格安装一次搜索按钮入口，重复调用安全。
    void InstallTableSearchSupport(QTableView* tableView);

    // RefreshTableSearchSupport：重新判断滚动状态、专属搜索框和可用空间。
    void RefreshTableSearchSupport(QTableView* tableView);

    // IsGenericTableSearchEligible：仅允许没有遗留外部搜索框的表格使用通用过滤。
    bool IsGenericTableSearchEligible(QTableView* tableView);

    // ApplyTableSearchResultFilter：隐藏不匹配行并保留原始行隐藏快照，成功时返回 true。
    bool ApplyTableSearchResultFilter(
        QTableView* tableView,
        const QString& queryText);

    // ClearTableSearchResultFilter：撤销通用过滤并恢复启用前的行隐藏状态。
    void ClearTableSearchResultFilter(QTableView* tableView);


    // ResolveTableSearchDisplayName：从显式属性、分组标题、页签和对象名解析表格名。
    QString ResolveTableSearchDisplayName(const QTableView* tableView);

    // CollectTableCellSearchMatches：在表格模型中查找展示文本，最多返回 maxHitCount 项。
    QVector<TableCellSearchMatch> CollectTableCellSearchMatches(
        QTableView* tableView,
        const QString& queryText,
        int maxHitCount);

    // RevealTableCellSearchMatch：滚动、选中并聚焦命中的表格单元格。
    void RevealTableCellSearchMatch(const TableCellSearchMatch& searchMatch);
}
