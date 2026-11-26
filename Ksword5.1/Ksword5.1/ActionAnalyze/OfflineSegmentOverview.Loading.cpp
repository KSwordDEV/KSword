#include "OfflineSegmentOverview.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/ResultTableHost.h"

#include <QFileDialog>
#include <QLineEdit>
#include <QMetaObject>
#include <QPushButton>
#include <QSignalBlocker>
#include <algorithm>

namespace ks::action_analyze
{
// 打开系统文件选择器。取消对话框时不触碰当前证据。
void OfflineSegmentOverview::chooseSegment()
{
    using ks::i18n::sourceText;
    const auto path = QFileDialog::getOpenFileName(this, sourceText(QStringLiteral("打开归档段")),
        m_lastPath, sourceText(QStringLiteral("行为分析归档段 (*.ksaseg)")), nullptr, QFileDialog::ReadOnly);
    openSegment(path);
}

// 用目录的稳定 ID 构造首个 raw 段路径。最终文件身份由后台读取器核对。
bool OfflineSegmentOverview::openSampleArchive(const SampleRequest& sample, const SampleSensitiveClue* clue)
{
    return openSegment(SampleRawSegmentPath(sample), sample, clue);
}

// 冻结路径与目录身份后交给后台。只有仍有效的请求可以切换证据来源。
bool OfflineSegmentOverview::openSegment(const QString& path, std::optional<SampleRequest> sample,
    const SampleSensitiveClue* clue, bool followPrefix)
{
    if (path.isEmpty())
    {
        return false;
    }
    if (!followPrefix)
    {
        m_apiPrefixAttempt = 0;
        m_allowApiPrefixFollow = sample.has_value();
    }
    struct Request
    {
        QString path; // 明确选择的归档文件路径。
        std::optional<SampleRequest> sample; // 可选项目约束，和路径一起冻结。
    };
    m_lastPath = path;
    m_lastSampleRequest = sample;
    m_lastClue = clue ? std::optional<SampleSensitiveClue>(*clue) : std::nullopt;
    m_clueMissing = false;
    m_reading = true;
    updateText();
    const auto anchor = m_lastClue; // 冻结锚点，排队回执独立于后续请求。
    const auto accepted = m_read->submit<Request, SegmentSnapshot>({path, std::move(sample)}, // 实际读取任务代次，零表示未受理。
        [](const Request& requested, const ks::ui::AsyncOperationToken& token) {
            return ReadOfflineSegment(requested.path, [&token]() {
                return token.isCanceled();
            }, requested.sample ? &*requested.sample : nullptr);
        },
        [this, anchor](const SegmentSnapshot& segment, quint64 generation) {
            // 表格操作暂时锁定更新时，推迟结果并在提交时复查代次。
            const auto commit = ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("action_analyze_segment"),
                {m_host}, [this, segment, generation, anchor]() {
                    if (m_read->isCurrent(generation))
                    {
                        publish(segment);
                        // 同时核对采样、段、记录和原包分类坐标，避免跳到回读时已更新的行。
                        if (anchor && anchor == m_lastClue)
                        {
                            const auto row = m_latestPublished ? std::find_if(segment.rows.cbegin(), segment.rows.cend(), [&](const SegmentRow& candidate) {
                                return RowAnchor(candidate) == SegmentRowAnchor{Ksword::ActionAnalyze::ProjectEvidenceLane::Primary,
                                        anchor->segment, anchor->sequence} &&
                                    candidate.archivedApi && candidate.archivedApi->sourceSequence == anchor->sourceSequence &&
                                    candidate.archivedApi->archiveSource == anchor->archiveSource && candidate.archivedApi->api == anchor->api;
                            }) : segment.rows.cend(); // 未发布的回读不能提供定位目标。
                            if (row != segment.rows.cend())
                            {
                                // 已定位后，普通重读沿用总览当前选择，允许用户自由查看别的记录。
                                m_lastClue.reset();
                                selectRecord(RowAnchor(*row), true);
                            }
                            else
                            {
                                m_clueMissing = true;
                                updateText();
                            }
                        }
                    }
                    m_read->completeDeferred(generation);
                });
            if (commit == ks::ui::UiCommitSubmission::Rejected)
            {
                publish({});
            }
            return commit != ks::ui::UiCommitSubmission::Deferred;
        },
        [this](std::exception_ptr) {
            publish({});
        });
    if (!accepted)
    {
        publish({});
    }
    else
    {
        // 唯一的归档入口回到原证据视图，API 源读端不受影响。
        m_apiCaptureToggle->setChecked(false);
    }
    return accepted != 0;
}

// 取消按钮与异步门禁同步，已排队的旧提交不能改写视图。
void OfflineSegmentOverview::cancelRead()
{
    if (m_reading)
    {
        m_allowApiPrefixFollow = false;
        m_read->cancel();
        SegmentSnapshot canceled; // 独立回执，不携带待发布行。
        canceled.end = SegmentEnd::Canceled;
        publish(canceled);
    }
}

// 发布完整段或有真实记录的已验证前缀。失败保留原段及详情。
void OfflineSegmentOverview::publish(const SegmentSnapshot& result)
{
    m_reading = false;
    m_latestEnd = result.end;
    m_latestLegacyApi = result.checkpoint == SegmentCheckpoint::ApiLegacyUnpublished;
    m_latestOffset = result.failureOffset;
    m_latestVerifiedOrdinal = result.lastVerifiedOrdinal;
    m_latestFailedOrdinal = result.failedOrdinal;
    m_latestMixed = result.mixed;
    // 现有读取槽空闲后再补读在途期间到达的新段，避免嵌套提交覆盖当前代次。
    if (m_allowApiPrefixFollow)
    {
        QMetaObject::invokeMethod(this, [this]() { followCommittedApiPrefix(); }, Qt::QueuedConnection);
    }
    // 重读同一文件失败时，旧结果保留原范围并附加本次失败回执。
    const bool keepComplete = m_snapshot && m_snapshot->path == result.path
        && m_snapshot->end == SegmentEnd::Complete && result.end != SegmentEnd::Complete;
    m_latestPublished = result.end == SegmentEnd::Complete ||
        (!keepComplete && result.end != SegmentEnd::Canceled && result.ordinal &&
            (!result.rows.isEmpty() || result.nativeHistoryOnly)); // 原生链达到上限时仍可浏览已核验历史。
    if (!m_latestPublished)
    {
        updateText();
        return;
    }

    m_livePreviewEnabled = false;
    setActiveSnapshot(result);
}

// 在同一模型发布实时或档案快照。同源增量沿用已提交的筛选和选择。
void OfflineSegmentOverview::setActiveSnapshot(const SegmentSnapshot& result)
{
    // 回调段若已被替换，同一个 Stored 序号可能指向不同的原包。
    const bool sameCallbackBatch = m_snapshot && (result.callbackBatch
        ? m_snapshot->callbackBatch && m_snapshot->callbackBatch->sha256 == result.callbackBatch->sha256
        : !m_snapshot->callbackBatch); // 核验同路径回调的实际文件内容。
    const bool same = sameCallbackBatch && m_snapshot->live == result.live && m_snapshot->path == result.path
        && m_snapshot->projectId == result.projectId && m_snapshot->sampleId == result.sampleId
        && m_snapshot->sampleDescriptionHash == result.sampleDescriptionHash
        && m_snapshot->stream == result.stream && m_snapshot->ordinal == result.ordinal; // 是否保留原选择和筛选。
    m_snapshot = std::make_shared<const SegmentSnapshot>(result);
    if (!same)
    {
        const QSignalBlocker guard(m_keyword); // 新段重置关键字，不提交临时模型。
        m_keyword->clear();
        m_selection.reset();
        m_selectedLiveRow.reset();
        m_lower.reset();
        m_upper.reset();
        m_start->clear();
        m_end->clear();
        m_invalidRange = false;
        m_filterCategories.clear();
        m_objectFilter.reset();
        m_viewedObject.reset();
    }
    updateArchiveRelations(same);
    fillCategories(same);
    applyFilters();
}
}
