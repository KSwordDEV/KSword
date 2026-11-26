#pragma once

#include <QString>

namespace ks::ui { struct FieldDocument; }

namespace ks::action_analyze
{
    struct SegmentCallbackBatch;
    struct SegmentRow;

    // 表与来源上下文叶项使用同一个本地化观测名称。
    QString CallbackArchiveRowLabel();
    // 根据已验证的观测数量生成整批状态；零行也明确显示覆盖未知。
    QString CallbackArchiveStatus(qsizetype observationCount);
    // 用同一回执向采样和事件详情追加源代次、游标及可空计数。
    void AppendCallbackBatchFields(ks::ui::FieldDocument& document, const SegmentCallbackBatch& batch);
    // 将已核验的回调行以纯字段形式加入规范文档，使用该快照实际的采样 ID。
    void AppendCallbackObservation(ks::ui::FieldDocument& document, const QString& sampleId, const SegmentRow& row);
    // 在回调原生序号和上下文 PID/TID 提示中匹配关键字。
    bool MatchesCallbackKeyword(const SegmentRow& row, const QString& keyword);
}
