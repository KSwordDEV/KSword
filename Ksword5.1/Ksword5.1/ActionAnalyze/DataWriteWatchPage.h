#pragma once

#include <QString>
#include <cstdint>
#include <functional>
#include <memory>

class QWidget;

namespace ks::action_analyze
{
    // 工具条只转交动作意图；原页面在点击时冻结实际停止令牌并提交同一个owner。
    enum class DataWatchToolbarAction { Continue, Into, OverCall, Out, CancelStep, DumpMemory, Close, Pause };

    struct DataWatchToolbarState
    {
        QString target; // 本轮实际PID和创建时间，不采用总览当前选区。
        bool canContinue = false; // 来自原控制按钮的当前资格。
        bool canPause = false; // 原执行owner仍在运行，可请求主动中断，不创建另一个暂停owner。
        bool canStep = false; // 三种步进共用当前冻结线程资格。
        bool canCancel = false; // 当前原生步进存在且可请求取消。
        bool canDump = false; // 原会话完整Held且有可保存的项目采样。
        bool canClose = false; // 原owner仍有控制或恢复责任。
        bool operator==(const DataWatchToolbarState&) const = default;
    };

    struct DataWatchToolbarPort
    {
        DataWatchToolbarState state; // 原页面发布的UI值快照，无现场查询。
        std::function<void(DataWatchToolbarAction)> execute; // 调用原页面执行路径。
        std::function<void()> changed; // 原页面回投时更新工具条，无新增轮询。
        // 输入已选模块绝对路径、非零RVA和定义ID；只准备草稿，实际附加仍须显式开始。
        std::function<bool(const QString&, std::uint32_t, const QString&)> prepareImageRva;
    };

    // 创建行为分析的写入/私有执行停点页；输入父宿主，返回复用参数工作区的页面。
    // 页面持有本端同一会话及冻结结果，父窗口负责生命周期。
    QWidget* CreateDataWriteWatchPage(QWidget* parent, std::shared_ptr<DataWatchToolbarPort> toolbar = {});
}
