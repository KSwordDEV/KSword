#pragma once

#include "ProcessGroupSession.h"
#include <QWidget>
#include <functional>

class QLineEdit;
class QLabel;
class QPushButton;
class QLayout;
class QComboBox;
namespace ks::ui { struct FieldDocument; }

namespace ks::action_analyze
{
    // 只管理内存范围草稿和显式动作，不持原生group；执行仍交原页面串行session。
    class ProcessGroupMemoryPane final : public QWidget
    {
    public:
        // nativeStop用于原写入/步进单会话文案，默认仍为集合选中成员。
        explicit ProcessGroupMemoryPane(QWidget* parent, bool nativeStop = false);
        std::function<void(bool save)> execute; // 点击读/保存，由父页冻结当前精确成员。
        std::wstring ProjectDirectory() const; // Configure点击时冻结的可选新项目目录。
        bool OpenExistingProject() const; // 原生控制页显式选择已有项目，新建采样而不复用历史停止令牌。
        bool Prepare(const ProcessGroupSessionSnapshot& shown,
            const process_group_native::ProcessGroupTarget& target, ProcessGroupRequest& request);
        // 写入／步进页复用相同范围草稿，输入原控制回执，仅构造值请求不访问原owner。
        bool PrepareNative(const process_group_native::NativeControlResult& displayed, ProcessGroupRequest& request);
        // 将读/保存动作移入页面固定动作栏，参数正文滚动时仍可执行；布局由调用者共享Flow拥有。
        void MoveExecutionActions(QLayout* actions);
        void Update(const ProcessGroupSessionSnapshot& shown, bool oneSelected, bool configured);
        static void Append(ks::ui::FieldDocument& document, const ProcessGroupSessionSnapshot& shown);
    private:
        QLineEdit* m_directory = nullptr; // 全新项目路径，空表示仅读取、不保存。
        QComboBox* m_projectMode = nullptr; // 原生页的新建/打开草稿；集合旧入口保持只新建。
        QLineEdit* m_base = nullptr; // 明确0x十六进制或十进制起点草稿。
        QLineEdit* m_bytes = nullptr; // 所选范围十进制字节长度，不是整个进程dump。
        QLabel* m_error = nullptr; // 范围输入错误，不覆盖原内存结果。
        QPushButton* m_read = nullptr; // Held模式只读当前精确停点。
        QPushButton* m_save = nullptr; // 将显示的实际成功页提交raw-memory lane。
        QPushButton* m_browse = nullptr; // 仅选择新项目路径，不立即写入。
    };
}
