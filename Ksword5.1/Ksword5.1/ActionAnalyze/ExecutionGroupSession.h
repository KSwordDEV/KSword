#pragma once

#include "../../../KswordCLI/ActionAnalyze/Control/OwnedExecutionGroup.h"
#include "../Framework/TaskCpuMeasurement.h"

#include <memory>
#include <string>

namespace ks::action_analyze
{
    namespace execution_group_native = ks::cli::action_analyze::control;

    // 请求完全按值进入原串行线程，界面行索引和控件不进入后台。
    enum class ExecutionGroupCommand { Start, Query, Pause, Continue, Step, CancelStep };

    struct ExecutionGroupRequest
    {
        ExecutionGroupCommand command = ExecutionGroupCommand::Query; // 显式动作类型。
        std::vector<execution_group_native::ExecutionGroupSite> sites; // Start冻结的唯一站点目录。
        std::vector<execution_group_native::NativeControlResult> stops; // 点击时复制的完整原生票据；Pause使用活绑定，不要求旧stop。
        std::vector<execution_group_native::ExecutionGroupSessionEntry> sessions; // 混合Pause/Continue携带每项完整原owner与显示快照。
        execution_group_native::NativeStepMode mode = execution_group_native::NativeStepMode::Into; // 单成员步进模式。
        std::string sampleId; // 可选共享采样UUID；空值交给原会话分配。
        bool all = false; // Pause/Continue显式区分固定全集与所选子集。
        bool authorized = false; // Start时冻结的用户授权。
    };

    struct ExecutionGroupSessionSnapshot
    {
        execution_group_native::ExecutionGroupResult result; // 本次逐成员真实回读。
        std::uint64_t revision = 0; // 供UI避免重复投影。
        std::uint64_t observedFileTime = 0; // 完成本轮查询的UTC时间，不是同时冻结时间。
        bool busy = false; // 单项显式操作或查询在途。
        bool closing = false; // 已关闭新控制准入，保留原owner清退。
        bool retired = false; // 仅原集合Close确认clean后发布。
        bool failed = false; // 后台异常与原生诊断分列。
        std::string diagnostic; // 有界异常摘要，不冒充成员错误码。
    };

    // 每页一个worker，原集合在同一线程创建、查询、操作和销毁，不创建项目writer。
    class ExecutionGroupSession final
    {
    public:
        ExecutionGroupSession(); // 登记退出租约并创建专用后台线程，尚不附加目标。
        ~ExecutionGroupSession(); // 非阻塞请求Close，未clean的worker由租约保活。
        ExecutionGroupSession(const ExecutionGroupSession&) = delete;
        ExecutionGroupSession& operator=(const ExecutionGroupSession&) = delete;

        bool Submit(ExecutionGroupRequest request); // 忙或关闭中明确拒绝；不会覆盖原请求。
        ExecutionGroupSessionSnapshot Read() const; // 只复制已公布值，不执行任何原生查询。
        void SetCpuToken(ks::ui::TaskCpuToken token); // GUI传入原后台任务的本轮计量身份，worker不查询QObject。
        void Close(); // 关闭准入并唤醒原worker，直到全部原owner清退。

    private:
        struct Shared;
        std::shared_ptr<Shared> m_shared; // 与worker共享纯值状态，不包含QObject。
    };
}
