#pragma once

#include "ExecutionGroupSession.h"
#include "../UI/StructuredFieldView.h"
#include <QAbstractTableModel>

namespace ks::action_analyze
{
    // 四列管理表只放实例、站点、状态和原生诊断；完整身份及票据保留在统一字段文档。
    class ExecutionGroupMemberModel final : public QAbstractTableModel
    {
    public:
        using QAbstractTableModel::QAbstractTableModel;
        int rowCount(const QModelIndex& parent = {}) const override; // 输入父节点，返回平表成员数。
        int columnCount(const QModelIndex& parent = {}) const override; // 平表固定四列，避免密集扩展视图。
        QVariant data(const QModelIndex& index, int role) const override; // 只从当前草稿或实际回读投影。
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override; // 动态双语表头。
        void Replace(std::vector<execution_group_native::ExecutionGroupSite> sites); // 显式修改草稿目录，重置旧结果。
        void Apply(const execution_group_native::ExecutionGroupResult& result); // 更新固定成员值，保留多选和行身份。
        void Relocalize(); // 通知表头和已显示值重译，不改变目录或令牌。

        std::vector<execution_group_native::ExecutionGroupSite> sites; // 已加入的草稿或Start冻结目录。
        execution_group_native::ExecutionGroupResult result; // 最近一次公布的真实成员及操作回执。
    };

    QString ExecutionGroupStateText(execution_group_native::ExecutionGroupState state); // 原集合汇总状态的双语显示。
    bool ExecutionGroupCanRelease(const execution_group_native::ExecutionGroupMember& member); // 仅提示资格，实际由backend复核。
    ks::ui::FieldDocument ExecutionGroupDocument(const ExecutionGroupSessionSnapshot& snapshot,
        const std::vector<execution_group_native::ExecutionGroupSite>& sites, const std::vector<int>& selected); // 统一字段、复制和导出源。
}
