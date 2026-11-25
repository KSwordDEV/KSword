#include "ToolbarCapabilities.h"

namespace ks::action_analyze
{
    namespace
    {
        // 两份值已由各自所有者核验。仅接受同一采样和实际项目的精确身份。
        bool SameSample(const ToolbarSampleIdentity& left, const ToolbarSampleIdentity& right)
        {
            return !left.sampleId.isEmpty() && left.sampleId == right.sampleId && left.projectId == right.projectId;
        }

        // 从总览的注册状态和会话阶段计算开始监控的禁用原因。
        ToolbarDisabledReason StartDisabledReason(const ToolbarOverviewState& state)
        {
            if (!state.captureRegistered)
            {
                return ToolbarDisabledReason::CaptureUnavailable;
            }
            switch (state.capturePhase)
            {
            case ToolbarCapturePhase::Starting:
            case ToolbarCapturePhase::Capturing:
                return ToolbarDisabledReason::CaptureAlreadyInProgress;
            case ToolbarCapturePhase::Stopping:
                return ToolbarDisabledReason::CaptureStopping;
            case ToolbarCapturePhase::CleanupPending:
                return ToolbarDisabledReason::CaptureCleanupPending;
            case ToolbarCapturePhase::Idle:
            case ToolbarCapturePhase::Ended:
                return state.readingArchive ? ToolbarDisabledReason::ArchiveReadInProgress : ToolbarDisabledReason::None;
            }
            return ToolbarDisabledReason::CaptureUnavailable;
        }

        // 从原采集所有者及其阶段计算停止或重试清退的资格。
        ToolbarDisabledReason StopDisabledReason(const ToolbarOverviewState& state)
        {
            switch (state.capturePhase)
            {
            case ToolbarCapturePhase::Starting:
            case ToolbarCapturePhase::Capturing:
            case ToolbarCapturePhase::CleanupPending:
                return state.hasCaptureOwner ? ToolbarDisabledReason::None : ToolbarDisabledReason::CaptureOwnerMissing;
            case ToolbarCapturePhase::Stopping:
                return ToolbarDisabledReason::CaptureStopping;
            case ToolbarCapturePhase::Idle:
            case ToolbarCapturePhase::Ended:
                return ToolbarDisabledReason::NoActiveCapture;
            }
            return ToolbarDisabledReason::NoActiveCapture;
        }

        // 区分可回看的最近会话、正在读档和已经跟随同一个窗口的状态。
        ToolbarDisabledReason FollowDisabledReason(const ToolbarOverviewState& state)
        {
            if (state.readingArchive)
            {
                return ToolbarDisabledReason::ArchiveReadInProgress;
            }
            const bool expectingPreview = state.capturePhase == ToolbarCapturePhase::Starting ||
                state.capturePhase == ToolbarCapturePhase::Capturing ||
                state.capturePhase == ToolbarCapturePhase::Stopping; // 监控仍可发布窗口。
            if (!state.hasCaptureOwner || (!expectingPreview && !state.captureHasPreviewRows))
            {
                return ToolbarDisabledReason::PreviewUnavailable;
            }
            if (state.livePreviewEnabled && state.followingLive)
            {
                const bool showingCapture = state.viewSource == ToolbarViewSource::Live &&
                    SameSample(state.viewSample, state.captureSample); // 旧实时窗口和历史视图都不能冒充当前窗口。
                return showingCapture ? ToolbarDisabledReason::AlreadyFollowing : ToolbarDisabledReason::FollowingAwaitingPreview;
            }
            return ToolbarDisabledReason::None;
        }
    }

    // 仅无禁用原因时开放入口。
    bool ToolbarActionEligibility::enabled() const noexcept
    {
        return reason == ToolbarDisabledReason::None;
    }

    // 总览按钮从同一份输入快照计算，导航只检查真实页签入口。
    ToolbarOverviewCapabilities EvaluateToolbarOverview(const ToolbarOverviewState& state)
    {
        // 本次归档有独立回执，只有采样所属项目存在并已核验首段时才能打开。
        auto captureArchive = ToolbarDisabledReason::None; // 默认表示归档具备读入资格。
        if (!state.hasCaptureOwner || state.captureSample.projectId.isEmpty())
        {
            captureArchive = ToolbarDisabledReason::CaptureProjectMissing;
        }
        else if (state.readingArchive)
        {
            captureArchive = ToolbarDisabledReason::ArchiveReadInProgress;
        }
        else if (!state.verifiedCaptureArchive)
        {
            captureArchive = ToolbarDisabledReason::CaptureArchiveUnverified;
        }
        return {
            {StartDisabledReason(state)},
            {StopDisabledReason(state)},
            {FollowDisabledReason(state)},
            {state.breakpointPageAvailable ? ToolbarDisabledReason::None : ToolbarDisabledReason::BreakpointPageUnavailable},
            {captureArchive}
        };
    }

    // 按当前选择和已验证的描述判定，历史目录可在活动监控期间独立使用。
    ToolbarActionEligibility EvaluateToolbarArchiveLocation(const ToolbarArchiveState& state)
    {
        if (state.manifestPath.isEmpty() || state.selection.identity.projectId.isEmpty())
        {
            return {ToolbarDisabledReason::ProjectMissing};
        }
        if (state.selection.identity.sampleId.isEmpty())
        {
            return {ToolbarDisabledReason::SampleNotSelected};
        }
        if (state.readingSample)
        {
            return {ToolbarDisabledReason::SampleReadInProgress};
        }
        if (state.sampleReadFailed)
        {
            return {ToolbarDisabledReason::SampleReadFailed};
        }
        // 旧的成功回执仅可用于同一项目、同一采样、同一冻结描述。
        if (!state.verifiedSample || state.verifiedSample->descriptionHash.isEmpty())
        {
            return {ToolbarDisabledReason::SampleUnverified};
        }
        if (!SameSample(state.selection.identity, state.verifiedSample->identity) ||
            state.selection.descriptionHash != state.verifiedSample->descriptionHash)
        {
            return {ToolbarDisabledReason::SampleSelectionChanged};
        }
        return {};
    }
}
