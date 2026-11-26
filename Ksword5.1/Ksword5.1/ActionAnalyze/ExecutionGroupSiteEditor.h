#pragma once

#include "ExecutionGroupSession.h"
#include <QWidget>

class QComboBox;
class QFormLayout;
class QLineEdit;

namespace ks::action_analyze
{
    class PrivateAddressWatchFields;

    // 自然高度的单站点草稿；仅解析显式输入，不枚举、附加或改写活集合。
    class ExecutionGroupSiteEditor final : public QWidget
    {
    public:
        explicit ExecutionGroupSiteEditor(QWidget* parent); // 在父参数正文创建共享身份输入及模块选择。
        bool Prepare(execution_group_native::ExecutionGroupSite& site, QString& error) const; // 成功才提交完整站点。
        void LoadDraft(const execution_group_native::ExecutionGroupSite& site); // 显式载入完整成员草稿，不读取实际绑定或附加目标。

    private:
        void UpdateMode(); // 切换参数可见行，保留各模式已有草稿。
        PrivateAddressWatchFields* m_identity = nullptr; // 复用PID、创建时间和私有地址/页数解析。
        QComboBox* m_kind = nullptr; // 导出、RVA、私有地址、私有页范围四种明确机制。
        QFormLayout* m_form = nullptr; // 自然高度模块及条件表单，窄窗允许折行。
        QLineEdit* m_module = nullptr; // 用户明确选择的绝对DOS模块路径。
        QLineEdit* m_location = nullptr; // 区分大小写导出或非零RVA草稿。
        QLineEdit* m_imageSha256 = nullptr; // 用户显式期望散列；私有模式隐藏并保留，不随请求发送。
        QLineEdit* m_condition = nullptr; // 当前单成员条件原文，与活集合分离。
        QWidget* m_moduleRow = nullptr; // 文件选择器与模块输入共用一行。
    };
}
