#pragma once

#include "../../Core/Win32Lean.h"
#include "LightProcessGroupMemory.h"
#include "../../../KswordCLI/ActionAnalyze/Control/OwnedProcessGroup.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Ksword::Features::ActionAnalyze {

namespace group_native = ks::cli::action_analyze::control;

// 本端会话执行的显式动作。全部动作在同一个工作线程上串行完成，界面只提交按值冻结的副本。
enum class LightProcessGroupCommand {
    Identify,   // 只读身份核对：不附加调试器，不改变集合。
    Configure,  // 冻结并核对集合身份；只核对，不暂停。
    Pause,      // 按全集或明确子集请求暂停。
    Continue,   // 用点击时复制的完整停止令牌请求继续。
    Recover,    // 用原继续票据请求恢复。
    Query,      // 回读全部成员的真实状态。
    ReadMemory, // 在原集合串行worker读取单个完整Held停点的显式范围。
    SaveMemory, // 保存点击时显示的完整capture，不重读当前参数。
};

// 一次显式动作的完整输入。停止令牌与请求号都在点击时按值复制，工作线程不借用任何控件。
struct LightProcessGroupRequest {
    LightProcessGroupCommand command = LightProcessGroupCommand::Query;
    std::string requestId;                                 // 暂停与继续的新票据；恢复使用原继续票据。
    std::vector<group_native::ProcessGroupTarget> targets;  // 精确冻结目标或明确子集。
    std::vector<group_native::ProcessGroupStop> stops;      // 点击时显示的完整停止令牌副本。
    bool authorized = false;                                // 配置时的显式授权。
    std::uint32_t identityPid = 0;                          // 身份读取使用的进程号。
    std::optional<std::uint64_t> identityCreation;          // 身份读取时的期望创建时间；可空表示不核对。
    std::wstring newProjectDirectory; // Configure前冻结的新项目目录；空表示只读不归档。
    std::optional<group_native::ProcessMemorySnapshotRequest> memory; // 显式读取的完整停点及范围。
    std::shared_ptr<const group_native::ProcessMemorySnapshotResult> memoryToSave; // 保存原capture唯一身份。
};

// 一次身份读取的真实结果。创建时间来自同一进程句柄，失败保留真实 Win32 错误。
struct LightProcessGroupIdentity {
    group_native::ProcessGroupTarget target;      // 系统回读的真实身份。
    std::optional<std::uint64_t> expectedCreation; // 用户草稿中的创建时间；可空。
    bool creationMatched = false;                  // 期望创建时间与真实值是否一致。
    std::wstring imagePath;                        // 同一句柄读取的完整映像路径。
    std::uint32_t error = 0;                       // 身份读取的实际 Win32 错误。
    std::uint64_t observedFileTime = 0;            // 本次回读的真实 UTC FILETIME。
};

// 界面可见的完整快照。成员、票据与诊断来自同一轮回读，不从首行推断全组。
struct LightProcessGroupSnapshot {
    group_native::ProcessGroupResult result;         // 最新一轮原所有者回读。
    std::optional<group_native::ProcessGroupResult> lastCommandResult; // 自动Query不能覆盖原操作拒绝与Duplicate。
    std::optional<LightProcessGroupCommand> completedCommand; // 最近完成的显式动作；用于区分配置失败与等待。
    LightProcessGroupMemoryProjectView memoryProject; // 原项目、采样与独立归档来源。
    std::shared_ptr<const group_native::ProcessMemorySnapshotResult> memory; // 最新显式读取的完整结果。
    std::optional<LightProcessGroupIdentity> identity; // 最近一次身份读取结果。
    std::vector<group_native::ProcessGroupOperation> history; // 原票据，最多 128 项。
    std::uint64_t revision = 0;                      // 发布代次，界面只在变化时重投影。
    std::uint64_t observedFileTime = 0;              // 最近一次状态变化的真实回读时间。
    std::wstring diagnostic;                         // 工作线程异常时的中文提示。
    bool active = true;                              // 工作线程仍在运行。
    bool busy = false;                               // 单个显式动作执行中或已入队。
    bool closing = false;                            // 清退未确认，原所有者责任仍未结清。
    bool closedClean = false;                        // 原生集合已确认清退并释放。
    bool failed = false;                             // 工作异常；原生未决状态与最后回执仍保留。
};

// 本端唯一的进程集合会话。原生集合与所有者只存在于工作线程；界面只读快照并提交冻结副本。
// 未确认清退时同一 owner 保持存活，不会因为界面关闭而被析构。
class LightProcessGroupSession final {
public:
    LightProcessGroupSession() = default;
    ~LightProcessGroupSession();
    LightProcessGroupSession(const LightProcessGroupSession&) = delete;
    LightProcessGroupSession& operator=(const LightProcessGroupSession&) = delete;

    // 启动本端工作线程。成功返回 ERROR_SUCCESS；线程创建失败时返回真实错误码且不产生副作用。
    DWORD Start();
    // 提交一个显式动作。已有动作在途或会话已结束时返回 false，调用方保留输入草稿。
    bool Submit(LightProcessGroupRequest request);
    // 分配下一个严格递增的 group/N 票据。页面在点击时按值复制进请求。
    std::string NextRequestId();
    // 请求原所有者清退。未确认清退时保留同一 owner 存活并继续接受查询与恢复。
    void Close();
    // 页面退役入口：与 Close 相同，但通过清退登记保活，未结清时由登记处重试。
    void BeginRetirement();
    // 原生责任已结清时为真。未结清时页面不得销毁，同一 owner 继续存活。
    bool Ready() const;
    void CancelRetirement();
    // 只复制本地快照，不执行任何系统查询，允许界面定时读取。
    LightProcessGroupSnapshot ReadStatus() const;

private:
    struct Shared;
    std::shared_ptr<Shared> session_; // 线程与界面共享的值状态，不含窗口句柄。
    bool retiring_ = false;            // 当前页面的关闭准入状态。
};

} // namespace Ksword::Features::ActionAnalyze
