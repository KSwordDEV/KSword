#include "ArchivedSampleAnalysis.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/StructuredFieldView.h"

#include <optional>

namespace ks::action_analyze
{
namespace
{
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
        }};
        return categories;
    }

    // 把分类器 ID 转成显示枚举。未来新增的类别没有对应文案时保持未知。
    std::optional<std::size_t> CategoryIndex(const QString& key)
    {
        const auto& categories = Categories(); // 已支持的五个已知类别。
        for (std::size_t index = 0; index < categories.size(); ++index)
        {
            if (key == QLatin1StringView(categories[index].key))
            {
                return index;
            }
        }
        return std::nullopt;
    }

}

// 附带终止原因及失败段，区分没有证据、未读取和读取失败。
void AppendArchivedSampleAnalysisStatus(ks::ui::FieldDocument& document, const ArchivedSampleAnalysis& analysis)
{
    if (analysis.end == SegmentEnd::PreviewLimit)
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
    // 只接受已有尾记、检查点或正常扫描完的同一采样，拒绝未经发布的部分单段。
    analysis.verified = snapshot.projectId == request.projectId && snapshot.sampleId == request.sample.id &&
        (snapshot.end == SegmentEnd::Complete || snapshot.lastVerifiedOrdinal != 0);
    if (!analysis.verified)
    {
        return analysis;
    }

    analysis.lastSegment = snapshot.lastVerifiedOrdinal ? snapshot.lastVerifiedOrdinal : snapshot.ordinal;
    analysis.windowRows = snapshot.rows.size();
    analysis.archiveRows = snapshot.verifiedRows ? snapshot.verifiedRows : static_cast<quint64>(analysis.windowRows);
    for (const auto& row : snapshot.rows)
    {
        analysis.etwRows += row.liveEtw.has_value();
        analysis.networkRows += row.network.has_value();
        analysis.processRows += row.liveProcess.has_value();
        if (!row.archivedApi)
        {
            continue;
        }
        // 分类取自实际原包，只有通过导入尾记的窗口才会包含此字段。
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
                row.segmentOrdinal, row.sequence, clue.sourceSequence});
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

    document.field(QStringLiteral("已核验末段"), QString::number(analysis.lastSegment));
    document.field(QStringLiteral("归档记录数"), QString::number(analysis.archiveRows));
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
        const QString location = QStringLiteral("raw/%1 #%2 · events.jsonl #%3")
            .arg(clue.segment).arg(clue.sequence).arg(clue.sourceSequence); // 可回查的两套序号。
        document.field(clue.api, location + QStringLiteral(" · ") + ks::i18n::sourceText(family));
        document.nodes.last().children.last().translateName = false;
    }
}
}
