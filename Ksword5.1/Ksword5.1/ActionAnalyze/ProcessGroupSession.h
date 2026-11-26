#pragma once

#include "../../../KswordCLI/ActionAnalyze/Control/OwnedProcessGroup.h"
#include "../../../KswordCLI/ActionAnalyze/Control/ProcessGroupMemorySnapshot.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectMemorySnapshot.h"

#include <memory>
#include <string>

namespace ks::action_analyze
{
    namespace process_group_native = ks::cli::action_analyze::control;

    // 页面提交值请求；完整停止令牌在点击时复制，工作线程不借用任何控件。
    enum class ProcessGroupCommand { Configure, Pause, Continue, Recover, Query, Close, ReadMemory, SaveMemory };

    struct ProcessGroupRequest
    {
        ProcessGroupCommand command = ProcessGroupCommand::Query; // 本轮显式动作。
        std::string requestId; // 暂停/继续的新票据，恢复使用原继续票据。
        std::vector<process_group_native::ProcessGroupTarget> targets; // 精确冻结目标或子集。
        std::vector<process_group_native::ProcessGroupStop> stops; // 界面实际显示的全部精确令牌。
        bool authorized = false; // 配置时用户明确勾选的授权。
        std::wstring newProjectDirectory; // 可选新项目，Configure时由本端独占创建写租约。
        std::optional<process_group_native::ProcessMemorySnapshotRequest> memory; // 点击时冻结的范围和完整令牌。
        std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> memoryToSave; // 保存点击时实际显示的不可变结果。
    };

    struct ProcessGroupIdentityReadback
    {
        process_group_native::ProcessGroupTarget target; // 手工输入后由操作系统重新核对的身份。
        std::wstring imagePath; // 同一个进程句柄读取的完整映像路径。
        std::uint32_t error = 0; // 路径/身份读取的实际 Win32 错误。
    };

    struct ProcessGroupSessionSnapshot
    {
        process_group_native::ProcessGroupResult result; // 最新一轮原所有者回读。
        std::optional<process_group_native::ProcessGroupResult> lastCommandResult; // 自动Query不能抹掉上次显式失败。
        std::vector<ProcessGroupIdentityReadback> identities; // 本次 Configure 的身份与路径来源。
        std::vector<process_group_native::ProcessGroupOperation> history; // 原票据及不可变成员回执，最多128条。
        std::uint64_t revision = 0; // UI 只在发布代次变化时重投影。
        std::uint64_t observedFileTime = 0; // 本轮实际回读时间，不随输入草稿变化。
        bool busy = false; // 单个命令执行中或已入队。
        bool closing = false; // 清退已请求，仍由原控制器保留责任。
        bool retired = false; // Close真实返回clean后本端线程已结算；不改写原生Idle/Closed状态。
        bool failed = false; // 工作异常；原生未决状态与最后回执仍保留。
        std::string workerDiagnostic; // 仅后台异常摘要，不冒充原生stage或Win32错误。
        std::string sampleId; // 实际项目采样ID；无项目时为本端控制会话采样标签。
        std::wstring projectDirectory; // 本端显式新建项目，不借用其他页writer。
        Ksword::ActionAnalyze::ProjectResult projectResult; // 项目创建或内存归档的真实结果。
        std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> memory; // 最近显式范围读取，不随查询重做。
        std::optional<Ksword::ActionAnalyze::ProjectMemorySnapshotReceipt> memoryArchive; // 成功页原字节归档及回读结果。
        std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> memoryArchiveSource; // 原保存capture，不随新读取替换。
        bool memoryArchiveBlocked = false; // 写入/回读失败后不越过坏尾或覆盖原段。
    };

    // 每个Qt页面持有自己的串行会话。关闭请求不等待原生清退，未clean时线程保活。
    class ProcessGroupSession final
    {
    public:
        explicit ProcessGroupSession(process_group_native::OwnerIdentity identity);
        ~ProcessGroupSession();
        ProcessGroupSession(const ProcessGroupSession&) = delete;
        ProcessGroupSession& operator=(const ProcessGroupSession&) = delete;

        // 输入值请求；忙、关闭中或线程创建失败返回false，不产生副作用。
        bool Submit(ProcessGroupRequest request);
        // 仅复制本地快照，不执行系统查询，允许GUI定时读取。
        ProcessGroupSessionSnapshot Read() const;
        // 请求原所有者清退；页面销毁后仍保留未完成责任并继续回读。
        void Close();

    private:
        struct Shared;
        std::shared_ptr<Shared> m_shared; // 线程和页面共享的值状态，不含QObject。
    };
}
