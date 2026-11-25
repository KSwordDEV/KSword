#pragma once

#include "LiveCapture.h"
#include "StoredEvidence.h"
#include "../../Ui/VirtualListView.h"

namespace Ksword::Features::ActionAnalyze {

struct NativeLiveProject {
    std::wstring manifestPath; // 正在查看的本地项目清单。
    std::string projectId; // 从已验证历史回放中取得的项目 UUID。
};

struct NativeLiveRequest {
    DWORD pid = 0; // 用户明确输入的十进制 PID。
    std::optional<GUID> provider; // 空值只查询进程活动。
    std::optional<NativeLiveProject> project; // 显式启用后将 ETW 提交到当前项目。
};

struct NativeLiveProjection {
    SegmentEvidence evidence; // 同一快照中的最近实时观察。
    std::shared_ptr<const std::vector<Ui::VirtualListRow>> presentation; // 后台准备的虚拟表行。
};

struct NativeLiveSnapshot {
    LiveCaptureStatus capture; // 目标、来源、清退和归档回执。
    std::uint64_t previewEvicted = 0; // 只从预览中移出的行。
    bool active = false; // 后台线程尚未完成与本次会话有关的操作。
    bool cleanupPending = false; // 已真实尝试清退，等待显式重试。
    DWORD projectionError = ERROR_SUCCESS; // 后台投影准备失败。
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
