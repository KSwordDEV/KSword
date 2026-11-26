#pragma once

#include <QWidget>
#include <cstdint>
#include <functional>
#include <optional>

class QLineEdit;
class QSpinBox;

namespace ks::action_analyze
{
    // 启动点击时冻结的实例与地址；不包含任何进程或线程控制句柄。
    struct PrivateAddressWatchTarget
    {
        std::uint32_t pid = 0; // 用户明确选择的进程编号。
        std::uint64_t creation = 0; // 进程创建FILETIME，防止PID复用。
        std::uint64_t address = 0; // 本轮选择的单个私有关注地址。
        std::uint64_t rangeBytes = 0; // 零为单地址DR0；非零为明确选择的1..64页NX范围。
    };

    // 写入停点页的已有实例参数行；分区和滚动由宿主ParameterWorkspace拥有。
    class PrivateAddressWatchFields final : public QWidget
    {
    public:
        explicit PrivateAddressWatchFields(QWidget* parent);
        // 仅解析草稿；成功返回冻结值，失败返回false，不查询或附加进程。
        bool Prepare(PrivateAddressWatchTarget& target, bool pageExecution = false, bool requireAddress = true) const;
        // 切换地址提示，不改写地址草稿；整页模式明确要求4KiB对齐并说明保护变化。
        void SetPageExecutionMode(bool pageExecution, bool imageExecution = false);
        void SetActive(bool active); // 活会话只读，保留下一轮之前的原始输入。
        void LoadDraft(const PrivateAddressWatchTarget& target); // 显式回填保存的实例与范围草稿，不查询系统。
        std::function<void()> changed; // 草稿变化通知宿主页重算启动资格。

    private:
        QLineEdit* m_pid = nullptr; // 十进制PID输入。
        QLineEdit* m_creation = nullptr; // 十进制创建时间输入。
        QLineEdit* m_address = nullptr; // 十进制或0x十六进制地址输入。
        QSpinBox* m_pageCount = nullptr; // 显式NX范围页数，默认1，不自动扩大目标范围。
    };

    // 解析模块RVA草稿，接受十进制或0x前缀十六进制；失败为空，不访问映像或目标进程。
    std::optional<std::uint32_t> ParseImageExecutionRva(const QString& text);
}
