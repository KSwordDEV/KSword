#include "ArchivedSampleAnalysis.h"
#include "CallbackArchivePresentation.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/StructuredFieldView.h"

#include <optional>

namespace ks::action_analyze
{
namespace
{
    using ks::i18n::sourceText;
    constexpr qsizetype kCluePreview = 32; // 字段详情最多展示最近 32 条，计数覆盖本次整个窗口。
    constexpr quint64 kAutomaticSegments = 32; // 自动读取的连续段预算，显式归档仍读完整范围。

    struct Category
    {
        const char* key; // 来自已核验 API 线索的稳定类别。
        QString name; // 字段文档使用的本地化源标签。
    };

    // 目录顺序与内部枚举、计数数组一致，返回静态只读投影。
    const auto& Categories()
    {
        static const std::array<Category, static_cast<std::size_t>(SensitiveApiFamily::Count)> categories{{
            {"memory-write", QStringLiteral("内存写入操作")},
            {"section-map", QStringLiteral("节映射")},
            {"thread-create", QStringLiteral("线程创建")},
            {"thread-context", QStringLiteral("线程上下文修改")},
            {"apc-queue", QStringLiteral("APC 入队")},
            {"memory-allocation", QStringLiteral("内存分配")},
            {"memory-protection", QStringLiteral("内存保护变更")},
            {"memory-free-request", QStringLiteral("内存释放请求")},
            // 与正式分类器的新增类别逐项一致；只表示 API 观察，不推断业务效果。
            {"registry-query", QStringLiteral("注册表查询")},
            {"registry-write", QStringLiteral("注册表值写入")},
            {"process-enumeration", QStringLiteral("进程枚举")},
            {"module-query", QStringLiteral("模块查询")},
            {"system-query", QStringLiteral("系统信息查询")},
            {"process-start", QStringLiteral("进程创建请求")},
            {"file-open", QStringLiteral("文件句柄打开")},
            {"file-copy", QStringLiteral("文件复制")},
            {"file-write", QStringLiteral("文件写入")},
            {"service-control", QStringLiteral("服务管理调用")},
            {"network-name-query", QStringLiteral("名称解析调用")},
            {"network-session", QStringLiteral("网络会话句柄")},
            {"network-request", QStringLiteral("HTTP 请求调用")},
        }};
        return categories;
    }

    // 把分类器 ID 转成显示枚举。未来新增的类别没有对应文案时保持未知。
    std::optional<std::size_t> CategoryIndex(const QString& key)
    {
        const auto& categories = Categories(); // 与枚举同序的已知API类别，包含生命周期请求。
        for (std::size_t index = 0; index < categories.size(); ++index)
        {
            if (key == QLatin1StringView(categories[index].key))
            {
                return index;
            }
        }
        return std::nullopt;
    }

    // 按单一通道格式化已验边界，无终段和坏段分别报告。
    QString LaneStatus(SegmentEnd end, quint64 last, quint64 failed)
    {
        QString status; // 当前通道可核对的回执。
        switch (end)
        {
        case SegmentEnd::Complete:
            status = sourceText(QStringLiteral("已核验终段。"));
            break;
        case SegmentEnd::IncompleteSample:
            status = sourceText(QStringLiteral("归档尚未发布有效终段。"));
            break;
        case SegmentEnd::PreviewLimit:
            status = sourceText(QStringLiteral("已达到离线预览上限。"));
            break;
        default:
            status = sourceText(QStringLiteral("无法验证项目检查点或其引用的归档数据。"));
            break;
        }
        if (last)
        {
            status += u' ' + sourceText(QStringLiteral("已验证至第 %1 段。")).arg(last);
        }
        if (failed)
        {
            status += u' ' + sourceText(QStringLiteral("第 %1 段校验失败。")).arg(failed);
        }
        return status;
    }
}

// 以物理目录区分两通道，让每个终态、水位及坏段均能追溯。
QString MixedArchiveStatus(const MixedArchiveReadback& mixed, quint64 apiLast, quint64 apiFailed)
{
    auto etw = LaneStatus(mixed.etwEnd, mixed.etwLastOrdinal, mixed.etwFailedOrdinal); // ETW 自有检查点回执。
    if (mixed.etwFailureOffset)
    {
        etw += u' ' + sourceText(QStringLiteral("停止位置：%1 字节。")).arg(mixed.etwFailureOffset);
    }
    return sourceText(QStringLiteral("API (raw)：%1\nETW (raw-etw)：%2"))
        .arg(LaneStatus(mixed.apiEnd, apiLast, apiFailed), etw);
}

// 附带终止原因及失败段，区分没有证据、未读取和读取失败。
void AppendArchivedSampleAnalysisStatus(ks::ui::FieldDocument& document, const ArchivedSampleAnalysis& analysis)
{
    if (analysis.mixed)
    {
        document.note(MixedArchiveStatus(*analysis.mixed, analysis.lastSegment, analysis.failedSegment));
        return;
    }
    if (analysis.legacyUnpublished)
    {
        document.note(QStringLiteral("旧 API 跟随归档没有持久提交标记。"));
    }
    else if (analysis.end == SegmentEnd::PreviewLimit)
    {
        document.note(QStringLiteral("已达到自动分析的读取上限。打开采样归档可查看其余记录。"));
    }
    else if (analysis.end == SegmentEnd::IncompleteSample)
    {
        document.note(QStringLiteral("采样尚未发布终段。可重新读取采样以更新结果。"));
    }
    else if (analysis.end == SegmentEnd::Unavailable)
    {
        document.note(QStringLiteral("此采样暂无可读取的归档。"));
    }
    else if (analysis.end == SegmentEnd::InvalidCallbackBatch)
    {
        document.note(QStringLiteral("KSwordARK 回调归档读取或核验失败。"));
    }
    else if (analysis.end != SegmentEnd::Complete)
    {
        document.note(QStringLiteral("归档读取或核验失败。可重新读取采样。"));
    }
    if (analysis.failedSegment)
    {
        document.field(QStringLiteral("失败段号"), QString::number(analysis.failedSegment));
    }
}

// 返回可辨识的类别、API 名称和 raw 坐标，供下拉选项使用。
QString ArchivedClueLabel(const SampleSensitiveClue& clue)
{
    const auto& family = Categories()[static_cast<std::size_t>(clue.family)]; // 由归档分类器核对的类别。
    return QStringLiteral("%1 · %2 · raw/%3 #%4")
        .arg(ks::i18n::sourceText(family.name), clue.api).arg(clue.segment).arg(clue.sequence);
}

// 工作线程复用正式回放的格式、身份和完整性验证，再从同一窗口提取证据。
ArchivedSampleAnalysis ReadArchivedSampleAnalysis(const SampleRequest& request, const CancelCheck& isCanceled)
{
    const auto path = SampleRawSegmentPath(request); // 目录身份约束的规范入口，不从界面取任意路径。
    const auto snapshot = ReadOfflineSegment(path, isCanceled, &request, kAutomaticSegments); // 同一采样的已验证窗口。
    ArchivedSampleAnalysis analysis; // 仅保存分类、段水位及少量锚点。
    analysis.end = snapshot.end;
    analysis.failedSegment = snapshot.failedOrdinal;
    analysis.mixed = snapshot.mixed;
    analysis.legacyUnpublished = snapshot.checkpoint == SegmentCheckpoint::ApiLegacyUnpublished;
    // 只接受已有尾记、检查点或正常扫描完的同一采样，拒绝未经发布的部分单段。
    analysis.verified = snapshot.projectId == request.projectId && snapshot.sampleId == request.sample.id &&
        (snapshot.end == SegmentEnd::Complete || snapshot.lastVerifiedOrdinal != 0 ||
            (snapshot.mixed && snapshot.mixed->etwLastOrdinal != 0));
    if (!analysis.verified)
    {
        return analysis;
    }

    analysis.lastSegment = snapshot.mixed || snapshot.lastVerifiedOrdinal ? snapshot.lastVerifiedOrdinal : snapshot.ordinal;
    analysis.windowRows = snapshot.rows.size();
    analysis.archiveRows = snapshot.mixed || snapshot.verifiedRows
        ? snapshot.verifiedRows : static_cast<quint64>(analysis.windowRows);
    // 回调专用段没有 API 分类。回传核验过的批次与实际完整观测数。
    if (snapshot.callbackBatch)
    {
        analysis.callbackBatch = snapshot.callbackBatch;
        return analysis;
    }
    for (const auto& row : snapshot.rows)
    {
        analysis.etwRows += row.liveEtw.has_value();
        analysis.networkRows += row.network.has_value();
        analysis.processRows += row.liveProcess.has_value();
        if (!row.archivedApi)
        {
            continue;
        }
        // 分类取自经导入尾记或发布检查点核验的实际原包。
        const auto& clue = *row.archivedApi;
        const auto index = CategoryIndex(clue.family); // 查找已有预置支持的类别。
        if (index)
        {
            ++analysis.familyCounts[*index];
            if (analysis.recentClues.size() == kCluePreview)
            {
                analysis.recentClues.removeFirst();
            }
            analysis.recentClues.append(SampleSensitiveClue{clue.api, static_cast<SensitiveApiFamily>(*index),
                row.segmentOrdinal, row.sequence, clue.sourceSequence, clue.archiveSource});
        }
    }
    return analysis;
}

// 将样本、归档来源和类别显示在同一份字段报告中。每个分支仅表示分类路径。
void AppendArchivedSampleAnalysis(ks::ui::FieldDocument& document, const ArchivedSampleAnalysis& analysis)
{
    document.section(QStringLiteral("采样分析"));
    AppendArchivedSampleAnalysisStatus(document, analysis);
    if (!analysis.verified)
    {
        return;
    }

    if (analysis.mixed)
    {
        // 水位已按通道列在回执中；归档数也分别显示，不把 UI 窗口当作源记录数。
        document.field(QStringLiteral("API 归档记录数"), QString::number(analysis.archiveRows));
        document.field(QStringLiteral("ETW 归档记录数"), QString::number(analysis.mixed->etwVerifiedRows));
    }
    else
    {
        document.field(QStringLiteral("已核验末段"), QString::number(analysis.lastSegment));
        document.field(QStringLiteral("归档记录数"), QString::number(analysis.archiveRows));
    }
    if (analysis.callbackBatch)
    {
        document.note(CallbackArchiveStatus(analysis.windowRows));
        AppendCallbackBatchFields(document, *analysis.callbackBatch);
        document.field(QStringLiteral("归档线程创建观测数"), QString::number(analysis.windowRows));
        return;
    }
    document.field(QStringLiteral("分析窗口行数"), QString::number(analysis.windowRows));
    document.note(QStringLiteral("跨进程因果关系缺少已核验的执行方、目标及操作结果。"));

    document.section(QStringLiteral("归档分类流程"));
    document.field(QStringLiteral("采样 → ETW 报头"), QString::number(analysis.etwRows));
    document.field(QStringLiteral("采样 → 网络观测"), QString::number(analysis.networkRows));
    document.field(QStringLiteral("采样 → 进程区间"), QString::number(analysis.processRows));
    const auto& categories = Categories(); // 界面使用相同顺序显示全部已知类别。
    for (std::size_t index = 0; index < categories.size(); ++index)
    {
        document.field(categories[index].name, QString::number(analysis.familyCounts[index]));
    }

    document.section(QStringLiteral("敏感 API 线索"));
    if (analysis.recentClues.isEmpty())
    {
        document.note(QStringLiteral("当前窗口没有匹配这五类的 API 观测。"));
        return;
    }
    // 只有静态模板参与本地化，导出名及原始坐标保留原样。
    document.note(QStringLiteral("按原始顺序列出最近最多 32 条线索。API 线索的实际效果仍待核验。"));
    for (const auto& clue : analysis.recentClues)
    {
        const auto family = categories[static_cast<std::size_t>(clue.family)].name; // 稳定类别对应的文案。
        // 缺尾记声明的旧导入只显示原始序号；无导入尾记的跟随档仍为 JSONL 读回。
        using Ksword::Evidence::ApiMonitorArchiveSource;
        QString sourceLabel = QStringLiteral("events.jsonl #"); // 关闭的 JSONL 或被动跟随的原坐标。
        if (clue.archiveSource == ApiMonitorArchiveSource::CooperativePipe)
        {
            sourceLabel = ks::i18n::sourceText(QStringLiteral("合作流水号（非 JSONL 行号）")) + QLatin1Char(' ');
        }
        else if (clue.archiveSource == ApiMonitorArchiveSource::LegacyUnspecified)
        {
            sourceLabel = ks::i18n::sourceText(QStringLiteral("原始序号（输入类型未声明）")) + QLatin1Char(' ');
        }
        const auto location = QStringLiteral("raw/%1 #%2 · %3%4") // Stored 坐标与源坐标分别呈现。
            .arg(clue.segment).arg(clue.sequence).arg(sourceLabel).arg(clue.sourceSequence);
        document.field(clue.api, location + QStringLiteral(" · ") + ks::i18n::sourceText(family));
        document.nodes.last().children.last().translateName = false;
    }
}
}
