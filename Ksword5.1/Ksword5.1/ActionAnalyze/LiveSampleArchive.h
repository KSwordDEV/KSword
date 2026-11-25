#pragma once

#include "OfflineSegmentReader.h"
#include "../../../KswordCLI/ActionAnalyze/Archive/SegmentBodies.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h"

namespace ks::action_analyze
{
    // 开始按钮冻结的项目身份；空路径表示只采集到内存。修订用于拒绝陈旧项目草稿。
    struct LiveArchiveProject
    {
        QString manifest; // 项目清单的实际绝对路径。
        QString projectId; // 工作区最后验证的项目 UUID。
        QString revisionId; // 工作区最后验证的配置修订。
    };

    // 回读限于本端已刷盘并核验的 raw 段，不推断成 ETW 双流检查点。
    struct LiveArchiveStatus
    {
        quint64 verifiedSegments = 0; // 本会话已逐段回读验证的连续前缀。
        quint64 dropped = 0; // 归档等待队列已满而未接纳的记录数。
        bool finished = false; // 最终收尾记录所在段已回读验证。
        QString error; // 写入或回读失败的第一条诊断；后续不跨过坏段。
    };

    // 仅由 Qt 采集工作线程持有，使用正式项目 API 写入；不借用任何 QWidget。
    class LiveSampleArchive final
    {
    public:
        // 以冻结项目和目标 PID 登记采样，返回可用于独立回读的目录身份。失败返回空值。
        std::optional<SampleRequest> open(const LiveArchiveProject& frozen, quint32 pid);
        // 将待写行和可选终态分段提交并核验。返回值为仍可继续归档的状态。
        bool write(const QList<SegmentRow>& rows, const std::string& terminal = {});
        // 释放写租约，保留传给界面的回执。
        void close() { m_project.Close(); }
        // 返回当前工作线程内的归档回执。
        const LiveArchiveStatus& status() const { return m_status; }

    private:
        Ksword::ActionAnalyze::ProjectDocument m_project; // 仅此采集线程访问的项目写租约。
        std::string m_sample; // 正式登记的采样 UUID。
        std::optional<std::uint64_t> m_previous; // 前一段最后一次核验成功的真实封装序号。
        LiveArchiveStatus m_status; // 首次失败与连续已核验前缀。
    };

    enum class QtLiveRecordKind { Other, Invalid, Observation, Terminal };

    struct QtLiveTerminal
    {
        quint64 observed = 0; // 终止时实时源实际给出的累计观测数。
        quint64 dropped = 0; // 归档队列未接纳的观测数。
    };

    // 正文通过 RawRecord 外层校验后，识别 Qt 记录并将有效观测或终止计数写入输出。
    QtLiveRecordKind ProjectQtLiveMetadata(const ks::cli::action_analyze::archive::RawRecordV1& raw,
        SegmentRow& row, QtLiveTerminal& terminal);
}
