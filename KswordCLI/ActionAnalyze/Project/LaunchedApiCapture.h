#pragma once

#include "CooperativeApiCapture.h"
#include "../Control/SuspendedImageLaunch.h"
#include <atomic>
#include <string>

namespace Ksword::ActionAnalyze {

// 调用端原worker冻结的普通EXE启动请求；不接受手填PID或自定义注入器。
struct LaunchedApiRequest {
    std::wstring exe; // 已选择的本地AMD64 EXE绝对路径。
    std::optional<std::uint32_t> optionalRva; // 空值使用PE AddressOfEntryPoint。
    DWORD durationMs = 0; // Ready后时长，零表示持续到停止或目标退出。
    std::string_view title; // 调用期间有效的采样标题。
    std::string_view revisionId; // 原项目写者冻结的配置修订。
    bool autoTransfer = false; // 同一采样的自动跨进程接管策略。
    std::optional<NetworkTrafficBackend> networkTraffic; // 入口Ready前启用原网络源，自动接管追加同采样目标。
    bool captureAgentEtw = false; // 入口Ready前启动自有ETW来源，后续目标沿同一来源追加。
};

// 原生入口到Agent的事实快照；不包含句柄、owner或ProjectDocument。
struct LaunchedApiProgress {
    std::optional<ks::cli::action_analyze::control::SuspendedImageLaunchReceipt> launch; // 实际创建及入口武装回执。
    bool entryHeld = false; // 原主线程已在精确入口断点保持。
    bool agentReadyBeforeMainResume = false; // 真实Ready且有效覆盖先于归还交接挂起。
    bool initialMainSuspendReleased = false; // 仅归还本次入口交接另取的一次挂起。
    bool bootstrapClean = false; // 原debug owner已清退，不代表Agent管道清退。
    const char* stage = "launched-api-idle"; // 稳定阶段，失败保留实际原因。
    DWORD error = ERROR_SUCCESS; // 原生错误；零不替代各里程碑布尔值。
};

// 最终回执复用原API完整结果，并保留启动和入口交接的独立事实。
struct LaunchedApiReceipt : LaunchedApiProgress {
    CooperativeApiReceipt api; // 真实管道、归档、规则与自动接管回执。
};

// 原worker同步发布每个完成事实；参数只在回调内借用，不允许向项目开启第二写者。
using LaunchedApiLaunchProgress = std::function<void(const LaunchedApiProgress&)>;
// 输入冻结事实，返回两端相同的规范JSON，供原字段/文本详情搜索复制导出。
Evidence::JsonValue LaunchedApiProgressJson(const LaunchedApiProgress& progress);
// 调用方持有唯一项目写租约并在原worker执行；非Ready、取消或故障只终止本次自有进程。
// onReady/onCommitted/onTransfers/onStartup沿原签名，新增onLaunchProgress发布实际实例和交接事实。
LaunchedApiReceipt CaptureLaunchedApi(ProjectDocument& document, const LaunchedApiRequest& request,
    const std::atomic_bool& cancel, const CooperativeApiReady& onReady = {},
    const CooperativeApiCommitted& onCommitted = {}, const CooperativeApiTransferCommitted& onTransfers = {},
    const CooperativeApiStartup& onStartup = {}, const LaunchedApiLaunchProgress& onLaunchProgress = {});

} // namespace Ksword::ActionAnalyze
