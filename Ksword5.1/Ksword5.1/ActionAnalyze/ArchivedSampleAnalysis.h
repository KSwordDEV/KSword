#pragma once

#include "OfflineSegmentReader.h"

#include <array>

namespace ks::ui { struct FieldDocument; }

namespace ks::action_analyze
{
    // 既有值保持顺序；新增类别只追加，用于同一原包的详情计数与定位。
    enum class SensitiveApiFamily
    {
        MemoryWrite, // 内存写入调用。
        SectionMap, // 节映射调用。
        ThreadCreate, // 线程创建请求。
        ThreadContext, // 线程上下文请求。
        ApcQueue, // APC入队请求。
        MemoryAllocate, // 私有内存分配请求与返回。
        MemoryProtect, // 内存保护变更请求与返回。
        MemoryFreeRequest, // 释放请求，不等于已知释放范围。
        RegistryQuery, // 注册表打开与查询。
        RegistryWrite, // 注册表值写入。
        ProcessEnumeration, // 单次进程枚举步骤。
        ModuleQuery, // 模块名称查询或枚举步骤。
        SystemQuery, // 系统信息查询。
        ProcessStart, // 进程创建请求与返回。
        FileOpen, // 文件句柄打开。
        FileCopy, // 文件复制请求与返回。
        FileWrite, // 文件写入请求与返回。
        ServiceControl, // 服务管理调用。
        NetworkNameQuery, // 名称解析调用。
        NetworkSession, // 网络会话句柄调用。
        NetworkRequest, // HTTP 请求构造或发送。
        Count // 分类计数数组的容量。
    };

    // 每条线索保留原始序号、序号口径和实际归档位置，报头 PID 不用于推断目标。
    struct SampleSensitiveClue
    {
        QString api; // 已核验原包的导出名。
        SensitiveApiFamily family{}; // 共用来源分类器返回的类别。
        quint64 segment = 0; // 采样内的 raw 段号。
        quint64 sequence = 0; // Stored 记录序号。
        quint64 sourceSequence = 0; // JSONL 行号或合作来源流水号。
        std::optional<Ksword::Evidence::ApiMonitorArchiveSource> archiveSource{}; // 归档尾记声明的输入方式。
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
        std::optional<SegmentCallbackBatch> callbackBatch; // 有值即整批已核验，观测数取窗口行数。
        std::optional<MixedArchiveReadback> mixed; // 同一采样的独立 ETW 通道与 API 回放状态。
        std::array<qsizetype, static_cast<std::size_t>(SensitiveApiFamily::Count)> familyCounts{}; // 窗口内逐类计数。
        QList<SampleSensitiveClue> recentClues; // 有界的最近线索，顺序与原归档一致。
    };

    // 对已冻结的目录行读取本地归档，返回可复制的分类摘要。由现有后台任务调用。
    ArchivedSampleAnalysis ReadArchivedSampleAnalysis(const SampleRequest& request, const CancelCheck& isCanceled);

    // 将相同的结果追加到采样字段文档，使视觉、搜索、复制及导出共用数据。
    void AppendArchivedSampleAnalysis(ks::ui::FieldDocument& document, const ArchivedSampleAnalysis& analysis);
    // 单独追加最近失败或部分读取状态，用于继续展示同一样本的上次分类。
    void AppendArchivedSampleAnalysisStatus(ks::ui::FieldDocument& document, const ArchivedSampleAnalysis& analysis);
    // 将两路终态及段号格式化为同一文本，供总览状态和采样详情使用。
    QString MixedArchiveStatus(const MixedArchiveReadback& mixed, quint64 apiLast, quint64 apiFailed);
    // 根据已核验线索生成当前语言的选择器标签，保留原 API 名称与记录坐标。
    QString ArchivedClueLabel(const SampleSensitiveClue& clue);
}
