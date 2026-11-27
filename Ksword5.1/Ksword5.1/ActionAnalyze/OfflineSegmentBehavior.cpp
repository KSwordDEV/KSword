#include "OfflineSegmentBehavior.h"
#include "OfflineSegmentReader.h"

#include <utility>

namespace ks::action_analyze
{
namespace
{
    namespace rule = Ksword::ActionAnalyze::Rules;

    // 输入当前已解码 API 行和稳定的 UTF-8 文本，返回同一原包的规则输入值。
    rule::ArchivedApiObservation BehaviorInput(const SegmentRow& row, const QByteArray& api, const QByteArray& family)
    {
        const auto& clue = *row.archivedApi; // 读取器已从完整原包独立解码的字段。
        rule::ArchivedApiObservation observation{row.sequence, clue.sourceSequence,
            {api.constData(), static_cast<std::size_t>(api.size())},
            {family.constData(), static_cast<std::size_t>(family.size())}}; // 求值期间借用调用方文本。
        if (clue.memoryWriteReturn)
        {
            observation.memoryWriteReturn = rule::ArchivedApiMemoryWriteReturn{
                clue.memoryWriteReturn->returned, clue.memoryWriteReturn->statusCode};
        }

        // 与预置回放共用原包字段；不从分类摘要、当前目标或候选链推断行为。
        auto& evidence = observation.evidence; // 当前原包专属的可空证据。
        evidence.actorPid = row.pid.value_or(0);
        evidence.memory = clue.apiMemoryLifecycle;
        evidence.apc = clue.apiApc;
        evidence.apcOutcome = clue.apcOutcome;
        evidence.context = clue.apiContext;
        evidence.contextOutcome = clue.contextOutcome;
        evidence.map = clue.apiSectionMap;
        evidence.mapOutcome = clue.sectionMapOutcome;
        evidence.behavior = clue.behaviorObservation;
        return observation;
    }
}

// 在原后台读取的最终行窗口上投影一次，所有输出均由该快照拥有。
void ProjectOfflineSegmentBehavior(SegmentSnapshot& snapshot, const CancelCheck& isCanceled)
{
    const bool verifiedFollow = snapshot.checkpoint == SegmentCheckpoint::ApiRawVerified &&
        snapshot.lastVerifiedOrdinal != 0; // 零条 API 线索的已核验前缀也有规则状态。
    if (snapshot.live || isCanceled() || (!verifiedFollow &&
        (!snapshot.hasArchivedApi || snapshot.end != SegmentEnd::Complete)))
    {
        return;
    }

    SegmentBehaviorProjection projection; // 失败时不发布任何部分命中。
    projection.state = SegmentBehaviorState::Failed;
    std::vector<std::pair<QByteArray, QByteArray>> text; // 每行的精确导出名与分类 UTF-8 存储。
    std::vector<rule::ArchivedApiObservation> observations; // 求值器借用稳定文本，字段值归自身所有。
    QList<qsizetype> rowOffsets; // 将引擎返回顺序映射回同一快照的原始行。
    text.reserve(static_cast<std::size_t>(snapshot.rows.size()));
    observations.reserve(static_cast<std::size_t>(snapshot.rows.size()));
    for (qsizetype offset = 0; offset < snapshot.rows.size(); ++offset)
    {
        if (isCanceled())
        {
            return;
        }
        const auto& row = snapshot.rows.at(offset); // 混采中忽略非 API 原行，不改变其坐标。
        if (!row.archivedApi)
        {
            continue;
        }
        const auto& clue = *row.archivedApi; // 同一已核验原包的规则输入。
        const auto& [api, family] = text.emplace_back(clue.api.toUtf8(), clue.family.toUtf8());
        observations.push_back(BehaviorInput(row, api, family));
        rowOffsets.append(offset);
    }

    // 仅规则文件在这里加载一次；归档沿用原读取结果，不调用 ReadBehaviorPresets 再读档。
    const auto database = rule::LoadApiPresetDatabase(); // 本轮唯一的已准备规则数据库。
    projection.presetSet = QString::fromStdString(database.presetSet);
    projection.sourceSha256 = QString::fromStdString(database.sourceSha256);
    if (!database.error.empty())
    {
        projection.error = QString::fromStdString(database.error);
        snapshot.behavior = std::move(projection);
        return;
    }
    if (isCanceled())
    {
        return;
    }
    const auto report = rule::AnalyzeVerifiedApiPresetPage(database, observations,
        snapshot.verifiedApiClueRows, rule::ApiPresetProfile::ByCategory); // 当前有界窗口允许原始序号跳号。
    if (report.error != rule::ApiPresetError::None || report.matches.size() != observations.size())
    {
        projection.error = QStringLiteral("archive-projection-invalid");
        snapshot.behavior = std::move(projection);
        return;
    }

    // 逐条核对引擎返回的双坐标；普通分类没有 behavior 时不会产生行为树叶项。
    projection.analyzedRows = static_cast<qsizetype>(report.analyzedRows);
    for (std::size_t position = 0; position < report.matches.size(); ++position)
    {
        if (isCanceled())
        {
            return;
        }
        const auto& hit = report.matches[position]; // 本次求值拥有的真实匹配结果。
        const auto& row = snapshot.rows.at(rowOffsets.at(static_cast<qsizetype>(position))); // 原段和原包坐标。
        if (hit.rawSequence != row.sequence || hit.sourceSequence != row.archivedApi->sourceSequence)
        {
            projection.matches.clear();
            projection.error = QStringLiteral("archive-projection-invalid");
            snapshot.behavior = std::move(projection);
            return;
        }
        if (hit.behavior)
        {
            projection.matches.append({rowOffsets.at(static_cast<qsizetype>(position)), row.segmentOrdinal,
                hit.rawSequence, hit.sourceSequence, *hit.behavior});
        }
    }
    projection.state = SegmentBehaviorState::Ready;
    snapshot.behavior = std::move(projection);
}

}
