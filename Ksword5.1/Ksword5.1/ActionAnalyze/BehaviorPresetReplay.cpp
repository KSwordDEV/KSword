#include "BehaviorPresetReplay.h"
#include "../Internationalization/LanguageManager.h"

#include <QDateTime>
#include <QStringList>
#include <QTimeZone>
#include <unordered_map>
#include <utility>

namespace ks::action_analyze
{
namespace
{
    using ks::i18n::sourceText;
    namespace rule = Ksword::ActionAnalyze::Rules;
    constexpr qint64 kFiletimeEpochOffsetMs = 11644473600000; // FILETIME 与 Unix 各自纪元的毫秒差。

    // 按 UTF-8 解释规则引擎回执中的名称或 ID，返回给只读文本视口。
    QString DisplayUtf8(std::string_view bytes)
    {
        return QString::fromUtf8(bytes.data(), static_cast<qsizetype>(bytes.size()));
    }

    // 用当前配置的真实定义组织计数；即使窗口无命中也保留零条计数与规则顺序。
    std::vector<PresetReplayCount> CountPresetMatches(const rule::ApiPresetDatabase& database,
        rule::ApiPresetProfile profile, const rule::ApiPresetReport& report)
    {
        std::unordered_map<std::string_view, quint64> matchesById; // 仅在本函数借用回执的 ID。
        for (const auto& hit : report.matches)
        {
            ++matchesById[hit.ruleId];
        }
        const auto definitions = rule::ApiClassificationPresets(database, profile); // 本轮已验证的规则定义。
        std::vector<PresetReplayCount> counts; // 返回拥有文本的界面快照。
        counts.reserve(definitions.size());
        for (const auto& definition : definitions)
        {
            const auto& text = definition.description; // 同一个规则的双语释义和 ID。
            counts.push_back({DisplayUtf8(text.summary.empty() ? text.ruleId : text.summary),
                DisplayUtf8(text.summaryZh), matchesById[text.ruleId]});
        }
        return counts;
    }

    // 通过同一格式呈现任意规则数量；语言切换仅重排已冻结的结果。
    QString FormatPresetCounts(const std::vector<PresetReplayCount>& counts, bool useChinese)
    {
        const auto countFormat = sourceText(QStringLiteral("%1 %2 条")); // 每条规则及其命中数量。
        QStringList entries; // 规则定义顺序与本次求值一致。
        for (const auto& entry : counts)
        {
            const auto& label = useChinese && !entry.labelZh.isEmpty() ? entry.labelZh : entry.label;
            entries << countFormat.arg(label, QString::number(entry.matches));
        }
        return entries.join(QStringLiteral(" · "));
    }

    // 把读侧终态映射到稳定回执码，保留独立导入段的既有诊断。
    QString ArchiveEndCode(SegmentEnd end)
    {
        switch (end)
        {
        case SegmentEnd::Complete: return {};
        case SegmentEnd::Unavailable: return QStringLiteral("archive-unavailable");
        case SegmentEnd::Truncated: return QStringLiteral("archive-truncated");
        case SegmentEnd::Invalid: return QStringLiteral("archive-invalid");
        case SegmentEnd::Unsupported: return QStringLiteral("archive-unsupported");
        case SegmentEnd::PreviewLimit: return QStringLiteral("archive-preview-limit");
        case SegmentEnd::Canceled: return QStringLiteral("archive-canceled");
        case SegmentEnd::WrongSample: return QStringLiteral("archive-wrong-sample");
        case SegmentEnd::InvalidCheckpoint: return QStringLiteral("archive-invalid-checkpoint");
        default: return QStringLiteral("archive-incomplete");
        }
    }
}

// 使用同一个读端核对冻结身份、导入尾记和发布检查点，再执行纯值预置。
PresetReplayResult ReadBehaviorPresets(const PresetReplayRequest& request, const CancelCheck& isCanceled)
{
    const auto* sample = request.sample ? &*request.sample : nullptr; // 仅项目模式绑定目录身份。
    constexpr quint64 kRuleReplaySegments = 128; // 交互式规则回放的段数配额。
    const auto segment = sample
        ? ReadOfflineSegment(SampleRawSegmentPath(*sample), isCanceled, sample, kRuleReplaySegments,
            SegmentProjection::ApiClues)
        : ReadOfflineSegment(request.path, isCanceled, nullptr, 0, SegmentProjection::ApiClues); // 本入口自行求值，不额外生成总览行为窗口。
    PresetReplayResult result; // 只保留已核验证据和读取边界。
    result.end = segment.end;
    const bool verifiedFollow = sample && segment.checkpoint == SegmentCheckpoint::ApiRawVerified &&
        segment.lastVerifiedOrdinal != 0; // 已核验的跟随前缀可以是空线索。
    if (segment.end != SegmentEnd::Complete && !verifiedFollow)
    {
        result.error = segment.checkpoint == SegmentCheckpoint::ApiLegacyUnpublished
            ? QStringLiteral("archive-unpublished-api-follow") : ArchiveEndCode(segment.end);
        result.firstUnverifiedSegment = segment.failedOrdinal;
        return result;
    }

    // 非 API 段与有效的零线索采样区分。独立段仅接受原有首段导入格式。
    if ((!segment.hasArchivedApi && !verifiedFollow) || segment.ordinal != 1 ||
        segment.projectId.isEmpty() || segment.sampleId.isEmpty())
    {
        result.error = QStringLiteral("archive-not-api-monitor-import");
        return result;
    }
    result.projectId = segment.projectId;
    result.sampleId = segment.sampleId;
    if (verifiedFollow)
    {
        // 检查点计划标识来源，线索窗口为空时也能确认输入类型。
        result.archiveSource = segment.apiArchiveSource;
        result.recordedRuleSourceSha256 = segment.recordedRuleSourceSha256;
    }
    if (sample)
    {
        result.sampleCreatedUtc = sample->sample.createdUtc;
        result.verifiedSegments = verifiedFollow ? segment.lastVerifiedOrdinal : segment.ordinal;
        if (segment.end != SegmentEnd::Complete)
        {
            result.firstUnverifiedSegment = segment.failedOrdinal ? segment.failedOrdinal : result.verifiedSegments + 1;
        }
    }

    // 转码后的字符串在同步规则解释器返回前保持稳定，归档段号不进入求值器。
    std::vector<std::pair<QByteArray, QByteArray>> text; // 每行拥有导出名与分类的 UTF-8 字节。
    std::vector<rule::ArchivedApiObservation> observations; // 只读借用上方稳定存储。
    const auto rowCount = static_cast<std::size_t>(segment.rows.size()); // 本次规则输入窗口的大小。
    text.reserve(rowCount);
    observations.reserve(rowCount);
    result.matchSegments.reserve(rowCount);
    for (const auto& row : segment.rows)
    {
        if (isCanceled() || !row.archivedApi)
        {
            result.error = isCanceled() ? QStringLiteral("archive-canceled") : QStringLiteral("archive-missing-api-row");
            return result;
        }
        // 原始两套序号可跨段跳号。随同一行保存段号，避免按窗口位置重建证据坐标。
        const auto& clue = *row.archivedApi; // 读侧已对照原包核验的分类线索。
        if (observations.empty() && !verifiedFollow)
        {
            result.archiveSource = clue.archiveSource; // 旧单段导入的来源由已核验的整段尾记声明。
        }
        const auto& [api, family] = text.emplace_back(clue.api.toUtf8(), clue.family.toUtf8()); // 解释器借用的字节。
        std::optional<rule::ArchivedApiMemoryWriteReturn> returned; // 缺显式返回证据时仅提交原有分类。
        if (clue.memoryWriteReturn)
        {
            returned = rule::ArchivedApiMemoryWriteReturn{
                clue.memoryWriteReturn->returned, clue.memoryWriteReturn->statusCode};
        }
        observations.push_back({row.sequence, clue.sourceSequence,
            {api.constData(), static_cast<std::size_t>(api.size())},
            {family.constData(), static_cast<std::size_t>(family.size())}, returned});
        // 只复用读侧已经从同一原包解码的字段，不访问摘要、目标内存或候选目录。
        auto& evidence = observations.back().evidence;
        evidence.actorPid = row.pid.value_or(0);
        evidence.memory = clue.apiMemoryLifecycle;
        evidence.apc = clue.apiApc;
        evidence.apcOutcome = clue.apcOutcome;
        evidence.context = clue.apiContext;
        evidence.contextOutcome = clue.contextOutcome;
        evidence.map = clue.apiSectionMap;
        evidence.mapOutcome = clue.sectionMapOutcome;
        evidence.behavior = clue.behaviorObservation; // 文本归独立观察所有，求值期间保持稳定。
        result.matchSegments.push_back(row.segmentOrdinal);
    }
    if (isCanceled())
    {
        result.error = QStringLiteral("archive-canceled");
        return result;
    }

    const auto database = rule::LoadApiPresetDatabase(); // 本次回放的两个配置共用同一份外置规则。
    if (!database.error.empty())
    {
        result.error = QStringLiteral("archive-preset-invalid");
        result.configError = DisplayUtf8(database.error);
        return result;
    }
    // 项目档允许跳号，旧的独立导入段保持原有连续性验证。
    const auto analyze = [&](rule::ApiPresetProfile profile)
    {
        return sample ? rule::AnalyzeVerifiedApiPresetPage(database, observations, segment.verifiedApiClueRows, profile)
            : rule::AnalyzeArchivedApiPresets(database, observations, segment.verifiedRows, profile);
    };
    const auto grouped = analyze(rule::ApiPresetProfile::Grouped); // 按真实汇总配置求值。
    result.report = analyze(rule::ApiPresetProfile::ByCategory);
    if (grouped.error != rule::ApiPresetError::None || result.report.error != rule::ApiPresetError::None)
    {
        result.error = grouped.error == rule::ApiPresetError::InvalidPreset || result.report.error == rule::ApiPresetError::InvalidPreset
            ? QStringLiteral("archive-preset-invalid") : QStringLiteral("archive-projection-invalid");
        return result;
    }
    if (grouped.matches.size() != rowCount || result.report.matches.size() != rowCount)
    {
        result.error = QStringLiteral("archive-preset-invalid");
        return result;
    }
    // 两种分类都按相同的原始序号关联，避免将汇总 ID 或证据误挂到另一原包。
    result.groupRuleIds.reserve(rowCount);
    for (std::size_t position = 0; position < rowCount; ++position)
    {
        const auto& group = grouped.matches[position]; // 本条观测的汇总命中。
        const auto& category = result.report.matches[position]; // 本条观测的细分命中。
        const auto& observation = observations[position]; // 此处对应 matchSegments 中的段号。
        if (group.rawSequence != observation.rawSequence || group.sourceSequence != observation.sourceSequence ||
            category.rawSequence != observation.rawSequence || category.sourceSequence != observation.sourceSequence)
        {
            result.error = QStringLiteral("archive-projection-invalid");
            return result;
        }
        result.groupRuleIds.push_back(DisplayUtf8(group.ruleId));
    }
    result.presetSet = DisplayUtf8(database.presetSet);
    result.ruleSourceSha256 = DisplayUtf8(database.sourceSha256); // 与本轮已准备的谓词来自同一份文件。
    result.groupedCounts = CountPresetMatches(database, rule::ApiPresetProfile::Grouped, grouped);
    result.categoryCounts = CountPresetMatches(database, rule::ApiPresetProfile::ByCategory, result.report);
    return result;
}

// 返回已核验范围和第一处未覆盖的段，原状态码可用于关联 CLI 诊断。
QString FormatPresetVerifiedPrefix(const PresetReplayResult& result)
{
    return sourceText(QStringLiteral("仅回放已核验前缀。末段 raw/%1，首个未核验段 raw/%2（%3）。"))
        .arg(result.verifiedSegments).arg(result.firstUnverifiedSegment).arg(ArchiveEndCode(result.end));
}

// 生成由 CodeEditorWidget 显示、查找及导出的单一文本回执。
QString FormatBehaviorPresets(const PresetReplayResult& result)
{
    const bool useChinese = ks::i18n::LanguageManager::instance().currentLanguageId()
        .compare(QStringLiteral("zh-CN"), Qt::CaseInsensitive) == 0; // 语料仓的简体中文释义。
    QStringList evidenceLines; // 每条命中继承原始顺序和归档坐标。
    const bool cooperative = result.archiveSource == Ksword::Evidence::ApiMonitorArchiveSource::CooperativePipe;
    for (std::size_t pos = 0; pos < result.report.matches.size(); ++pos)
    {
        const auto& hit = result.report.matches[pos]; // 与输入线索一一对应的规则命中。
        const auto ruleIds = result.groupRuleIds[pos] + QStringLiteral(" · ") + DisplayUtf8(hit.ruleId); // 同一原包的两层命中。
        QString evidenceLine; // 本条原始坐标、分类和可选行为证据共用一行。
        if (result.verifiedSegments)
        {
            const auto format = cooperative ? sourceText(QStringLiteral("raw/%1 #%2 · 合作流水号 %3 · %4 · %5"))
                : sourceText(QStringLiteral("raw/%1 #%2 · 源行 %3 · %4 · %5"));
            evidenceLine = format
                .arg(result.matchSegments[pos]).arg(hit.rawSequence).arg(hit.sourceSequence)
                .arg(DisplayUtf8(hit.api), ruleIds);
        }
        else
        {
            const auto format = cooperative ? sourceText(QStringLiteral("段内序号 %1 · 合作流水号 %2 · %3 · %4"))
                : sourceText(QStringLiteral("段内序号 %1 · 源行 %2 · %3 · %4"));
            evidenceLine = format
                .arg(hit.rawSequence).arg(hit.sourceSequence).arg(DisplayUtf8(hit.api), ruleIds);
        }
        // 展示规则引擎回执中的实际 ID、证据级别和同一原包携带的释义。
        if (const auto& behavior = hit.behavior)
        {
            evidenceLine += QStringLiteral(" · %1 · %2").arg(DisplayUtf8(behavior->ruleId), DisplayUtf8(behavior->evidence));
            const auto& summary = useChinese && !behavior->summaryZh.empty() ? behavior->summaryZh : behavior->summary;
            if (!summary.empty())
            {
                evidenceLine += QStringLiteral(" · ") + DisplayUtf8(summary);
            }
        }
        evidenceLines << evidenceLine;
    }

    QStringList lines; // 固定报告身份、验证状态、规则汇总、原始坐标。
    lines << sourceText(QStringLiteral("项目 %1 · 采样 %2")).arg(result.projectId, result.sampleId);
    if (result.sampleCreatedUtc)
    {
        // 时间取冻结目录行，报告生成时间由页面独立呈现。
        const auto created = QDateTime::fromMSecsSinceEpoch(
            static_cast<qint64>(*result.sampleCreatedUtc / 10000) - kFiletimeEpochOffsetMs, QTimeZone::utc());
        lines << sourceText(QStringLiteral("采样创建时间 (UTC)：%1")).arg(created.toString(Qt::ISODateWithMs));
    }
    if (result.verifiedSegments)
    {
        lines << (result.firstUnverifiedSegment ? FormatPresetVerifiedPrefix(result)
            : sourceText(QStringLiteral("已核验采样归档至终段 raw/%1。")).arg(result.verifiedSegments));
    }
    lines << sourceText(QStringLiteral("已分析最近 %1 条，共验证 %2 条归档线索。命中 %3 条。"))
        .arg(qulonglong(result.report.analyzedRows)).arg(result.report.importedRows).arg(qulonglong(result.report.matches.size()));
    lines << sourceText(QStringLiteral("%1\nSHA-256：%2")).arg(
        sourceText(QStringLiteral("规则集：%1")).arg(result.presetSet), result.ruleSourceSha256);
    if (!result.recordedRuleSourceSha256.isEmpty())
    {
        // 两份摘要分别来自采集计划和当前规则文件，旧档不补造采集时的内容身份。
        lines << sourceText(QStringLiteral("采集规则 SHA-256：%1")).arg(result.recordedRuleSourceSha256);
    }
    lines << sourceText(QStringLiteral("汇总：%1")).arg(FormatPresetCounts(result.groupedCounts, useChinese));
    lines << sourceText(QStringLiteral("细分：%1")).arg(FormatPresetCounts(result.categoryCounts, useChinese));
    lines << sourceText(QStringLiteral("以下为 API 观测。目标身份、调用效果和采集覆盖未知。"));
    lines.append(evidenceLines);
    return lines.join(QLatin1Char('\n'));
}
}
