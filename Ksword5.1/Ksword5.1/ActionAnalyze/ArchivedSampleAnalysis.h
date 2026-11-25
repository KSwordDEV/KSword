#pragma once

#include "OfflineSegmentReader.h"

#include <array>

namespace ks::ui { struct FieldDocument; }

namespace ks::action_analyze
{
    enum class SensitiveApiFamily { MemoryWrite, SectionMap, ThreadCreate, ThreadContext, ApcQueue, Count };

    // 每条线索保留原始行号和实际归档位置，报头 PID 不用于推断目标。
    struct SampleSensitiveClue
    {
        QString api; // 已核验原包的导出名。
        SensitiveApiFamily family{}; // 共用来源分类器返回的类别。
        quint64 segment = 0; // 采样内的 raw 段号。
        quint64 sequence = 0; // Stored 记录序号。
        quint64 sourceSequence = 0; // 源文件行号。
        bool operator==(const SampleSensitiveClue&) const = default;
    };

    // 采样自动预览的结果。完整性和结果数量分别呈现。
    struct ArchivedSampleAnalysis
    {
        SegmentEnd end = SegmentEnd::Unavailable; // 原读侧报告的终止原因。
        bool verified = false; // 存在可发布的已核验窗口，空窗口也可为真。
        bool legacyUnpublished = false; // 旧 API 跟随档没有持久提交标记。
        quint64 archiveRows = 0; // 扫描器确认的记录数，可能含封装元数据。
        quint64 lastSegment = 0; // 连续核验到的段号。
        quint64 failedSegment = 0; // 已识别的失败段号。
        qsizetype windowRows = 0; // 参与本轮分析的归档窗口行数。
        qsizetype etwRows = 0; // 已识别的 ETW 头数。
        qsizetype networkRows = 0; // 已识别的网络观测数。
        qsizetype processRows = 0; // 已识别的进程区间数。
        std::array<qsizetype, static_cast<std::size_t>(SensitiveApiFamily::Count)> familyCounts{}; // 窗口内逐类计数。
        QList<SampleSensitiveClue> recentClues; // 有界的最近线索，顺序与原归档一致。
    };

    // 对已冻结的目录行读取本地归档，返回可复制的分类摘要。由现有后台任务调用。
    ArchivedSampleAnalysis ReadArchivedSampleAnalysis(const SampleRequest& request, const CancelCheck& isCanceled);

    // 将相同的结果追加到采样字段文档，使视觉、搜索、复制及导出共用数据。
    void AppendArchivedSampleAnalysis(ks::ui::FieldDocument& document, const ArchivedSampleAnalysis& analysis);
    // 单独追加最近失败或部分读取状态，用于继续展示同一样本的上次分类。
    void AppendArchivedSampleAnalysisStatus(ks::ui::FieldDocument& document, const ArchivedSampleAnalysis& analysis);
    // 根据已核验线索生成当前语言的选择器标签，保留原 API 名称与记录坐标。
    QString ArchivedClueLabel(const SampleSensitiveClue& clue);
}
