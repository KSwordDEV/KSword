#pragma once

#include "LiveSampleArchive.h"
#include "../../../shared/usermode/backend/monitor/EtwSessionController.h"
#include <QUuid>
#include <deque>

namespace ks::ui { class AsyncOperationToken; }

namespace ks::action_analyze
{
    // 监控停止的触发原因，清退成败使用独立字段。
    enum class CaptureEnd { None, Requested, TargetExited, ProcessError };
    enum class EtwCoverage { Disabled, Starting, Active, Unavailable };

    // Qt 实时会话的只读回执。会话资源由异步工作线程持有。
    struct LiveEtwReceipt
    {
        bool ready = false; // 已建立进程实例与活动基线。
        bool recovery = false; // 原会话尚未完全清退。
        QString error; // 真实系统操作错误或目标资格错误。
        std::optional<quint64> loss; // 结束后才得到的 ETW 丢失数。
        quint64 evicted = 0; // 实时预览滚动淘汰的记录数，不等于来源丢失。
        quint32 processError = 0; // 采样途中首个进程计数读取错误。
        QString etwIssue; // ETW 的独立回执，不掩盖进程活动结果。
        CaptureEnd end = CaptureEnd::None; // 启动失败时还没有进入采样循环。
        bool hasRows = false; // 新采样实际产生了可回看的记录。
        LiveArchiveStatus archive; // 归档进度与采集是否正常清退彼此独立。
    };

    // 一次常驻单进程活动采集，可选直接 ETW。每次启动使用独立采样 ID。
    class LiveEtwCapture final
    {
    public:
        // 冻结项目、PID 和可选 ETW 来源。空 UUID 表示只监控进程活动。
        LiveEtwCapture(LiveArchiveProject project, quint32 pid, QUuid provider);

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
        // GUI 只读取归档积压与回执，不访问文件系统或工作线程的项目文档。
        LiveArchiveStatus archiveStatus() const;
        // GUI 回读本次已登记采样的冻结身份。无项目或登记未完成时返回空值。
        std::optional<SampleRequest> registeredSample() const;
        // 返回当前采样 ID，项目登记前为临时 UUID。调用不读取文件或构造视图。
        QString sampleId() const;
        // 按采样和修订识别新投影，滚动窗口满后也能持续发布。
        std::optional<SegmentSnapshot> preview(const QString& displayedSample, quint64 displayedRevision,
            bool keepExistingEvidence) const;

    private:
        // 回调线程只拷贝来源证据，目标实例与时间范围必须匹配。
        void append(const ks::r3::monitor::EtwEvent& event);
        // 采样工作线程追加已比较的进程活动区间，返回无。
        void appendProcess(const LiveProcessObservation& observation);
        // 已持锁时接纳一条记录，淘汰目标来源最旧的记录并分配稳定序号。
        void appendRow(SegmentRow row, std::deque<SegmentRow>& window, std::size_t limit);
        // 单个工作线程逐批刷盘；final 为真时先排空再追加真实收尾记录。
        void flushArchive(bool final);
        // 使用真实结束回执填充损失、错误和待恢复状态。
        LiveEtwReceipt receipt(bool stopped) const;

        quint32 m_pid; // 采样请求冻结的目标 PID。
        QString m_provider; // Windows 格式的 provider GUID。
        const LiveArchiveProject m_project; // 启动瞬间绑定的项目，不随界面切换。
        quint64 m_created = 0; // 打开进程句柄时核验的创建 FILETIME。
        quint64 m_started = 0; // 进入本次采集生命周期的 FILETIME。
        mutable std::mutex m_mutex; // 保护已投影的行和截断计数。
        SegmentSnapshot m_snapshot; // 冻结采样身份和当前修订，不持有历史行。
        std::deque<SegmentRow> m_processRows; // 进程活动滚动缓存，不被高频 ETW 挤出。
        std::deque<SegmentRow> m_etwRows; // 辅助 ETW 滚动缓存。
        quint64 m_evicted = 0; // 实时预览淘汰的旧行累计数。
        LiveSampleArchive m_writer; // 只有采集工作线程调用，磁盘操作不持有视图锁。
        QList<SegmentRow> m_archiveQueue; // 回调与采集线程间的有界归档交接。
        LiveArchiveStatus m_archive; // 锁内发布的归档状态，不代理原生资源。
        bool m_acceptArchive = false; // 仅项目登记成功且尚可写入时接纳。
        std::optional<SampleRequest> m_registeredSample; // 已登记的冻结目录行，和实时行共用锁。
        quint32 m_processError = 0; // 仅采集或清退工作线程访问。
        CaptureEnd m_end = CaptureEnd::None; // 采集工作线程确定的结束原因。
        std::atomic_bool m_stop{false}; // 从界面发往采集所有者。
        std::atomic_bool m_ready{false}; // 进程活动来源已建立身份和基线。
        std::atomic_bool m_collecting{false}; // 实际采集或清退正在运行。
        ks::r3::monitor::EtwSessionController m_controller; // 最先析构，回调使用的成员仍存活。
    };
}
