#include "OfflineSegmentBehaviorPresentation.h"
#include "OfflineSegmentReader.h"
#include "OfflineSegmentBehavior.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/StructuredFieldView.h"

#include <algorithm>

namespace ks::action_analyze
{
using ks::i18n::sourceText;

// 输入冻结的双语释义，按 GUI 当前语言取值；缺中文时沿用规则默认释义。
QString SegmentBehaviorSummary(const SegmentBehaviorMatch& match)
{
    const bool chinese = ks::i18n::LanguageManager::instance().currentLanguageId()
        .compare(QStringLiteral("zh-CN"), Qt::CaseInsensitive) == 0; // 只读 GUI 当前语言。
    const auto& summary = chinese && !match.behavior.summaryZh.empty()
        ? match.behavior.summaryZh : match.behavior.summary; // 同一规则结果中的当前语言文本。
    return QString::fromStdString(summary);
}

// 状态明确限定当前窗口，加载失败与成功零命中有不同文字和原始诊断。
QString SegmentBehaviorStatus(const SegmentBehaviorProjection& projection)
{
    if (projection.state == SegmentBehaviorState::Failed)
    {
        return sourceText(QStringLiteral("行为规则不可用：%1")).arg(projection.error);
    }
    return sourceText(QStringLiteral("行为命中（当前窗口 %1 / 已分析 API %2）"))
        .arg(projection.matches.size()).arg(projection.analyzedRows);
}

// 叶项同时保留原段、Stored 序号、来源序号、规则 ID、证据级别和当前语言释义。
QString SegmentBehaviorRowText(const SegmentBehaviorMatch& match)
{
    return sourceText(QStringLiteral("raw/%1 #%2 · 来源序号 %3 · %4 · %5 · %6"))
        .arg(match.segment).arg(match.rawSequence).arg(match.sourceSequence)
        .arg(QString::fromStdString(match.behavior.ruleId), QString::fromStdString(match.behavior.evidence),
            SegmentBehaviorSummary(match));
}

// 原详情文档按实际原包坐标关联；输入显示复用生产投影，命中说明只用冻结结果。
void AppendSegmentBehaviorFields(ks::ui::FieldDocument& document,
    const SegmentSnapshot& snapshot, const SegmentRow& row)
{
    const auto found = std::find_if(snapshot.behavior.matches.cbegin(), snapshot.behavior.matches.cend(),
        [&](const SegmentBehaviorMatch& match) {
            return row.archivedApi && row.evidenceLane == Ksword::ActionAnalyze::ProjectEvidenceLane::Primary &&
                match.segment == row.segmentOrdinal && match.rawSequence == row.sequence &&
                match.sourceSequence == row.archivedApi->sourceSequence;
        }); // 不用窗口下标或同 PID 替代原坐标。

    // 当前规则求值成功时，命中与未命中的 API 行都展示同一实际 Known 字段投影。
    if (snapshot.behavior.state == SegmentBehaviorState::Ready && row.archivedApi &&
        row.evidenceLane == Ksword::ActionAnalyze::ProjectEvidenceLane::Primary)
    {
        const auto inputs = OfflineSegmentBehaviorInputs(row); // 不重新读取原包或当前系统。
        document.section(QStringLiteral("规则求值输入字段"))
            .field(QStringLiteral("已知字段（缺失字段未输出）"), inputs);
    }
    if (found == snapshot.behavior.matches.cend())
    {
        return;
    }
    document.section(QStringLiteral("行为规则命中（当前窗口）"))
        .field(QStringLiteral("行为规则 ID"), QString::fromStdString(found->behavior.ruleId))
        .field(QStringLiteral("证据级别"), QString::fromStdString(found->behavior.evidence))
        .field(QStringLiteral("行为释义"), SegmentBehaviorSummary(*found))
        .field(QStringLiteral("规则集"), snapshot.behavior.presetSet)
        .field(QStringLiteral("规则 SHA-256"), snapshot.behavior.sourceSha256);
}
}
