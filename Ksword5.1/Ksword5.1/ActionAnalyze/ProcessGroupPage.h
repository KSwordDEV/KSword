#pragma once

#include <QString>
#include <array>
#include <functional>
#include <memory>

class QWidget;

namespace ks::action_analyze
{
    // 工具条的全局范围是本端已经核验的显式集合，选中范围来自该集合表。
    enum class ProcessGroupToolbarAction { PauseAll, ContinueAll, PauseSelected, ContinueSelected, Recover, Close };
    struct ProcessGroupToolbarState
    {
        QString target; // 实际采样与冻结成员身份摘要。
        QString selected; // 原集合表当前选中的实例，独立于总览历史选区。
        std::array<bool, 6> enabled{}; // 按上述动作顺序复制原按钮资格。
        bool operator==(const ProcessGroupToolbarState&) const = default;
    };
    struct ProcessGroupToolbarPort
    {
        ProcessGroupToolbarState state; // 原页面回投的值快照，无现场查询。
        std::function<void(ProcessGroupToolbarAction)> execute; // 仅转交原页显式动作。
        std::function<void()> changed; // 回投通知，不创建另一轮询。
    };

    // 创建本端进程集合工作页；父工作台提供导航和外层边界。
    QWidget* CreateProcessGroupPage(QWidget* parent, std::shared_ptr<ProcessGroupToolbarPort> toolbar = {});
}
