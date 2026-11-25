#pragma once

#include "OfflineSegmentReader.h"
#include "../../../shared/usermode/backend/monitor/EtwSessionController.h"
#include <QUuid>

namespace ks::ui { class AsyncOperationToken; }

namespace ks::action_analyze
{
    // 监控停止的触发原因，清退成败使用独立字段。
    enum class CaptureEnd { None, Requested, TimeLimit, TargetExited, ProcessError };
    enum class EtwCoverage { Disabled, Starting, Active, Unavailable };

    // Qt 实时会话的只读回执。会话资源由异步工作线程持有。
    struct LiveEtwReceipt
    {
        bool ready = false; // 已建立进程实例与活动基线。
        bool recovery = false; // 原会话尚未完全清退。
        QString error; // 真实系统操作错误或目标资格错误。
        std::optional<quint64> loss; // 结束后才得到的 ETW 丢失数。
        quint64 omitted = 0; // 预览缓冲超限丢弃的记录数。
        quint32 processError = 0; // 采样途中首个进程计数读取错误。
        QString etwIssue; // ETW 的独立回执，不掩盖进程活动结果。
        CaptureEnd end = CaptureEnd::None; // 启动失败时还没有进入采样循环。
        bool hasRows = false; // 新采样实际产生了可回看的记录。
    };

    // 一次有限时长、单进程的直接 ETW 采集。每次启动使用新的采样 ID。
    class LiveEtwCapture final
    {
    public:
        // 绑定项目、PID 和可选 ETW 来源。空 UUID 表示只监控进程活动。
        LiveEtwCapture(QString project, quint32 pid, QUuid provider);

        // 从工作线程开始采集，结束时返回收尾回执；界面销毁通过令牌退出。
        LiveEtwReceipt collect(const ks::ui::AsyncOperationToken& token);
        // 从工作线程重试原会话清退，返回当前回执。
        LiveEtwReceipt recover();
        // 请求结束本会话，实际结果由 collect 返回。
        void requestStop() { m_stop.store(true); }
        // 回读是否正处于实际采集阶段，供任务中心展示。
        bool running() const { return m_collecting.load(); }
        // 回读 ETW 单独的覆盖状态，避免把进程就绪当成 ETW 就绪。
        EtwCoverage coverage() const;
        // 仅在记录数变化或首次启动时返回新的只读投影。
        std::optional<SegmentSnapshot> preview(const QString& displayedSample, qsizetype displayedRows) const;

    private:
        // 回调线程只拷贝来源证据，目标实例与时间范围必须匹配。
        void append(const ks::r3::monitor::EtwEvent& event);
        // 采样工作线程追加已比较的进程活动区间，返回无。
        void appendProcess(const LiveProcessObservation& observation);
        // 使用真实结束回执填充损失、错误和待恢复状态。
        LiveEtwReceipt receipt(bool stopped) const;

        quint32 m_pid; // 采样请求冻结的目标 PID。
        QString m_provider; // Windows 格式的 provider GUID。
        quint64 m_created = 0; // 打开进程句柄时核验的创建 FILETIME。
        quint64 m_started = 0; // 进入本次采集生命周期的 FILETIME。
        mutable std::mutex m_mutex; // 保护已投影的行和截断计数。
        SegmentSnapshot m_snapshot; // 采样内实时行，不伪造归档偏移。
        qsizetype m_etwRows = 0; // 辅助来源单独限额，给进程活动分析留出容量。
        quint64 m_omitted = 0; // 缓冲到达上限后没有进入视图的行。
        quint32 m_processError = 0; // 仅采集或清退工作线程访问。
        CaptureEnd m_end = CaptureEnd::None; // 采集工作线程确定的结束原因。
        std::atomic_bool m_stop{false}; // 从界面发往采集所有者。
        std::atomic_bool m_ready{false}; // 进程活动来源已建立身份和基线。
        std::atomic_bool m_collecting{false}; // 实际采集或清退正在运行。
        ks::r3::monitor::EtwSessionController m_controller; // 最先析构，回调使用的成员仍存活。
    };
}
