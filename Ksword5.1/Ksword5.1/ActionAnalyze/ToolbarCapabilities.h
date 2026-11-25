#pragma once

#include <QString>
#include <optional>

namespace ks::action_analyze
{
    // 供工具提示、键盘可达状态和点击守卫共用。由调用页面负责翻译。
    enum class ToolbarDisabledReason
    {
        None,
        CaptureUnavailable,
        CaptureAlreadyInProgress,
        CaptureStopping,
        CaptureCleanupPending,
        CaptureOwnerMissing,
        NoActiveCapture,
        CaptureProjectMissing,
        CaptureArchiveUnverified,
        ArchiveReadInProgress,
        ProjectMissing,
        SampleNotSelected,
        SampleReadInProgress,
        SampleReadFailed,
        SampleUnverified,
        SampleSelectionChanged,
        PreviewUnavailable,
        AlreadyFollowing,
        FollowingAwaitingPreview,
        BreakpointPageUnavailable
    };

    // 一次只读资格判定，供界面更新和实际点击入口重新求值。
    struct ToolbarActionEligibility
    {
        ToolbarDisabledReason reason = ToolbarDisabledReason::None; // None 表示当前可用。

        // 返回动作当前是否可用，无状态修改。
        [[nodiscard]] bool enabled() const noexcept;
    };

    // 活动阶段由采集所有者及其回执提供，历史和归档视图单独描述。
    enum class ToolbarCapturePhase { Idle, Starting, Capturing, Stopping, CleanupPending, Ended };
    enum class ToolbarViewSource { None, Live, Archive };

    // 采样身份由已有值快照提供，临时实时采样可没有项目 ID。
    struct ToolbarSampleIdentity
    {
        QString projectId; // 实际归属项目，空值表示未绑定项目。
        QString sampleId; // 采样 UUID，尚未取得时留空。
    };

    // 总览按同一时刻的采集所有者和视图值构建输入。
    struct ToolbarOverviewState
    {
        ToolbarCapturePhase capturePhase = ToolbarCapturePhase::Idle; // 采集状态，独立于当前查看位置。
        bool captureRegistered = false; // 能否发起本端原采集入口。
        bool hasCaptureOwner = false; // 是否仍持有当前或最近一次采集的实际所有者。
        bool captureHasPreviewRows = false; // 当前所有者结束后仍有可回看的实时记录。
        ToolbarSampleIdentity captureSample; // 从当前所有者或其同代次快照取得。
        bool verifiedCaptureArchive = false; // 当前所有者完成了至少一段刷盘和回读。
        bool readingArchive = false; // 总览正在读归档，暂不能切回实时投影或启动新采样。
        ToolbarViewSource viewSource = ToolbarViewSource::None; // 当前已发布视图的数据来源。
        ToolbarSampleIdentity viewSample; // 当前可见结果的身份，可能是历史采样。
        bool livePreviewEnabled = false; // 已允许实时窗口接收后续发布。
        bool followingLive = true; // 用户是否在跟随时间窗口。
        bool breakpointPageAvailable = false; // 同一工作台有实际的断点页导航回调。
    };

    // 总览的现有按钮共用一次求值。停止监控含清退原会话的重试。
    struct ToolbarOverviewCapabilities
    {
        ToolbarActionEligibility startCapture; // 开始监控及采集参数可编辑性。
        ToolbarActionEligibility stopCapture; // 停止监控或按原路径重试清退。
        ToolbarActionEligibility followLive; // 切回实时或恢复跟随。
        ToolbarActionEligibility openBreakpointDefinitions; // 打开断点草稿页。
        ToolbarActionEligibility openCaptureArchive; // 重开本次采样自己的归档前缀。
    };

    // 记录已选目录行的身份及用于校验其冻结描述的散列。
    struct ToolbarArchiveSample
    {
        ToolbarSampleIdentity identity; // 已发表的项目和采样身份。
        QString descriptionHash; // 此目录行预期的采样描述散列。
    };

    // 项目目录提供只读输入，归档能否打开仍由原异步读取路径核验。
    struct ToolbarArchiveState
    {
        QString manifestPath; // 当前已显示项目的清单路径。
        ToolbarArchiveSample selection; // 当前选中的目录行。
        std::optional<ToolbarArchiveSample> verifiedSample; // 最近验证成功的读取请求身份。
        bool readingSample = false; // 当前选择的冻结描述仍在读取。
        bool sampleReadFailed = false; // 当前选择的最近读取已失败。
    };

    // 输入总览状态，返回四个已有按钮的资格和禁用原因。
    [[nodiscard]] ToolbarOverviewCapabilities EvaluateToolbarOverview(const ToolbarOverviewState& state);

    // 输入目录选区和核验回执，返回定位该采样归档的资格和禁用原因。
    [[nodiscard]] ToolbarActionEligibility EvaluateToolbarArchiveLocation(const ToolbarArchiveState& state);
}
