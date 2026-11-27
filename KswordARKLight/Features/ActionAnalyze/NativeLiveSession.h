#pragma once

#include "LiveCapture.h"
#include "StoredEvidence.h"
#include "../../Ui/VirtualListView.h"
#include "../../../shared/ApiMonitorCapture.h"
#include "../../../KswordCLI/ActionAnalyze/Project/NetworkTrafficCapture.h"

namespace Ksword::Features::ActionAnalyze {

inline constexpr DWORD kCooperativeApiDurationMs = 0; // 活采默认持续；请求可冻结有限时长，保留启动及清退超时。

struct NativeLiveProject {
    std::wstring manifestPath; // 正在查看的本地项目清单。
    std::string projectId; // 从已验证历史回放中取得的项目 UUID。
    std::string revisionId; // 目录读取时核验的项目修订。
};

struct NativeLiveApiSource {
    std::wstring path;
    std::uint64_t sessionIdentity = 0;
    std::uint64_t creationFileTime = 0;
    bool cooperative = false;
    bool explicitAttachment = false; // 普通目标的显式 R3 附加，与合作模式互斥。
    bool attachmentConfirmed = false; // 针对冻结 PID 与创建 FILETIME 的本轮确认。
    DWORD durationMs = kCooperativeApiDurationMs; // Ready后采集时限，零持续，不由UI计时。
    bool autoTransfer = false; // 启动冻结的API调用前跨进程私有执行接管策略。
    bool launched = false; // 第四来源：入口停止后自动附加API Agent。
    std::wstring executable; // 普通EXE独立路径，不借用JSONL草稿。
    std::optional<std::uint32_t> entryRva; // 空值使用PE AddressOfEntryPoint。
    std::optional<Ksword::ActionAnalyze::NetworkTrafficBackend> networkTraffic; // 冻结同采样网络源，自动接管追加目标，空值关闭。
    bool captureAgentEtw = false; // 开始时冻结的配套ETW策略；JSONL模式只保留页面草稿。
};

struct NativeLiveRequest {
    DWORD pid = 0; // 用户明确输入的十进制 PID。
    std::optional<GUID> provider; // 空值只查询进程活动。
    std::optional<NativeLiveProject> project;
    std::optional<NativeLiveApiSource> api; // 本地文件、合作 Agent 或显式附加，与 ETW 互斥。
};

struct NativeLiveProjection {
    SegmentEvidence evidence; // 同一快照中的最近实时观察。
    std::shared_ptr<const std::vector<Ui::VirtualListRow>> presentation; // 后台准备的虚拟表行。
};

struct NativeLiveApiReceipt {
    std::wstring manifestPath;
    std::wstring sourcePath; // 冻结来源，不随下一轮文件选择改变。
    std::uint64_t sourceSessionId = 0;
    std::string sampleDescriptionHash;
    std::wstring details; // 后台从共享报告投影的来源、水位、规则回执。
    bool cooperative = false;
    std::optional<std::uint64_t> readyCoverageRevision; // 合作 Agent 就绪时核验的覆盖修订。
    bool explicitAttachment = false; // 回执绑定本轮准入方式，不根据模块或文件存在推断。
    bool attachmentIdentityVerified = false; // 控制器已固定并核验目标实例。
    bool agentLoadAttempted = false; // 本轮实际尝试装载，与模块存在或 Ready 独立。
    bool agentModuleVerified = false; // 产品 Agent 模块核验通过，不代表 Hook 就绪。
    DWORD durationMs = 0; // 结果所属请求的冻结时限，不随下一轮草稿变化。
    bool agentReady = false; // 原控制器启动屏障，独立于三个附加事实及模块存在。
    std::optional<ks::winapi_monitor::CaptureStartupProgress> startup; // 原worker最后确认的启动阶段，清退和失败不重置。
    bool launched = false; // 本轮真实来源，显示不依赖当前草稿选择。
    std::wstring executable; // 冻结的EXE路径，保留结果来源。
    std::wstring launchProgress; // 共享LaunchedApiProgressJson规范投影。
    std::wstring networkTraffic; // 原worker返回的ApiCaptureNetworkJson全文，与API状态独立保留。
    bool captureAgentEtw = false; // 本轮已受理请求的ETW开关，不随下轮草稿修改。
    std::wstring agentEtw; // Close后保留原ETW来源全文与独立阶段回执，沿既有详情展示。
};

struct NativeLiveSnapshot {
    LiveCaptureStatus capture; // 目标、来源、清退和归档回执。
    std::uint64_t previewEvicted = 0; // 只从预览中移出的行。
    bool active = false; // 后台线程尚未完成与本次会话有关的操作。
    bool cleanupPending = false; // 已真实尝试清退，等待显式重试。
    DWORD projectionError = ERROR_SUCCESS; // 后台投影准备失败。
    std::optional<NativeLiveApiReceipt> api;
};

// 页面只在 GUI 线程调用。采集句柄、项目和有界投影属于后台线程。
class NativeLiveSession final {
public:
    NativeLiveSession() = default;
    ~NativeLiveSession();
    NativeLiveSession(const NativeLiveSession&) = delete;
    NativeLiveSession& operator=(const NativeLiveSession&) = delete;

    // 冻结页面请求并申请一个后台会话。返回立即可知的启动错误。
    DWORD Start(NativeLiveRequest request);
    // 发出协作停止意图，或通过 Light 原生任务登记重试现有清退。
    void Stop();
    // 提交退出意图。Ready 用于主窗口轮询，无须等待原生线程。
    void BeginRetirement();
    bool Ready() const;
    // 恢复新会话准入。之前已提交的停止仍继续完成。
    void CancelRetirement();

    // 请求后台准备最近窗口。页面离开实时视图时可暂停请求。
    void RequestProjection();
    std::optional<NativeLiveProjection> TakeProjection();
    NativeLiveSnapshot ReadStatus() const;

private:
    struct Shared;
    std::shared_ptr<Shared> session_; // GUI 可脱离，后台保留自己的所有权。
    bool retiring_ = false; // 当前页面的关闭准入状态。
};

// 将只读采集现状转换为页面状态栏的原生文本。
std::wstring FormatLiveStatus(const NativeLiveSnapshot& status);

} // namespace Ksword::Features::ActionAnalyze
