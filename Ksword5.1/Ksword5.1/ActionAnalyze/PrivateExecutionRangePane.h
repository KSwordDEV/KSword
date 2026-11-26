#pragma once

#include <QWidget>
#include <cstdint>
#include <functional>

class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;

namespace ks::action_analyze
{
    // 行为分析执行页内的追加范围草稿，不拥有调试会话，也不枚举目标内存。
    class PrivateExecutionRangePane final : public QWidget
    {
    public:
        // parent为ParameterWorkspace参数正文；创建自然高度分区，保留宿主唯一滚动区。
        explicit PrivateExecutionRangePane(QWidget* parent);

        // 输入当前完整Held资格与不可用原因；只控制动作，不清空用户草稿。
        void SetAvailable(bool available, const QString& reason);
        // 输入已核验的历史范围草稿及来源说明，只填参数；替换已有草稿须确认，绝不提交控制。
        bool SetDraft(std::uint64_t address, std::uint64_t bytes, const QString& origin,
            const std::function<bool()>& stillCurrent = {});

        // 点击时传出已校验且冻结的起点和字节数，由原worker再次核验当前停点。
        std::function<void(std::uint64_t, std::uint64_t)> addRange;

    private:
        // 从当前草稿解析范围；失败更新原位提示，成功时调用原页面纯值端口。
        void SubmitRange();

        QLineEdit* m_address = nullptr; // 新范围起点，不对输入地址隐式向下取整。
        QSpinBox* m_pages = nullptr; // 新增1..64页；与已有范围合计上限由原生owner核对。
        QPushButton* m_add = nullptr; // 显式追加范围动作，不能隐式Continue。
        QLabel* m_status = nullptr; // 输入错误及当前动作不可用原因。
        QLabel* m_origin = nullptr; // 仅记录当前草稿的原API坐标，手工编辑后清除。
        bool m_available = false; // 当前页面发布的可提交资格，不授予原生控制权。
    };
}
