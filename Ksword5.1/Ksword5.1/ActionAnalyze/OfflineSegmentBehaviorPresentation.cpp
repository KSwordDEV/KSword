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
    const bool primaryApiRow = row.archivedApi &&
        row.evidenceLane == Ksword::ActionAnalyze::ProjectEvidenceLane::Primary; // 只对同一快照中的生产 API 原行投影字段。
    const auto found = std::find_if(snapshot.behavior.matches.cbegin(), snapshot.behavior.matches.cend(),
        [&](const SegmentBehaviorMatch& match) {
            return primaryApiRow && match.segment == row.segmentOrdinal && match.rawSequence == row.sequence &&
                match.sourceSequence == row.archivedApi->sourceSequence;
        }); // 不用窗口下标或同 PID 替代原坐标。

    // 不论规则成功、失败还是加载失败，都从真实原行生成同一份生产 Known 字段投影。
    if (primaryApiRow)
    {
        const auto inputs = OfflineSegmentBehaviorInputs(row); // 不重新读取原包或当前系统。
        document.section(QStringLiteral("规则求值输入字段"))
            .field(QStringLiteral("已知字段（缺失字段未输出）"), inputs);

        // 规则身份和诊断绑定当前快照；这里不重读规则文件，也不重新执行规则求值。
        QString status; // 当前快照的规则状态文本，供详情字段和导出共用。
        bool translateStatus = true; // 只有原始语言键需要交给字段文档翻译。
        switch (snapshot.behavior.state)
        {
        case SegmentBehaviorState::Failed:
            status = QStringLiteral("规则求值失败");
            break;
        case SegmentBehaviorState::Ready:
            status = SegmentBehaviorStatus(snapshot.behavior);
            translateStatus = false;
            break;
        case SegmentBehaviorState::NotRequested:
            status = QStringLiteral("行为规则未请求");
            break;
        }
        document.section(QStringLiteral("API 规则回执"))
            .field(QStringLiteral("规则状态"), status, translateStatus);
        if (!snapshot.behavior.presetSet.isEmpty())
        {
            document.field(QStringLiteral("规则集"), snapshot.behavior.presetSet);
        }
        if (!snapshot.behavior.sourceSha256.isEmpty())
        {
            document.field(QStringLiteral("规则 SHA-256"), snapshot.behavior.sourceSha256);
        }
        const auto& recordedSha = snapshot.recordedRuleSourceSha256; // 已核验计划中的采集规则内容摘要。
        document.field(QStringLiteral("采集规则 SHA-256"), recordedSha.isEmpty()
            ? sourceText(QStringLiteral("未记录")) : recordedSha);
        QString identityMatch = sourceText(QStringLiteral("未知")); // 任一侧缺少真实摘要时不推断相同或不同。
        if (!recordedSha.isEmpty() && !snapshot.behavior.sourceSha256.isEmpty())
        {
            identityMatch = sourceText(recordedSha == snapshot.behavior.sourceSha256
                ? QStringLiteral("一致") : QStringLiteral("不一致"));
        }
        document.field(QStringLiteral("规则内容一致性"), identityMatch);
        if (!snapshot.behavior.error.isEmpty())
        {
            document.field(QStringLiteral("规则库诊断"), snapshot.behavior.error);
        }
    }
    if (found == snapshot.behavior.matches.cend())
    {
        return;
    }
    document.section(QStringLiteral("行为规则命中（当前窗口）"))
        .field(QStringLiteral("行为规则 ID"), QString::fromStdString(found->behavior.ruleId))
        .field(QStringLiteral("证据级别"), QString::fromStdString(found->behavior.evidence))
        .field(QStringLiteral("行为释义"), SegmentBehaviorSummary(*found));
}
}
