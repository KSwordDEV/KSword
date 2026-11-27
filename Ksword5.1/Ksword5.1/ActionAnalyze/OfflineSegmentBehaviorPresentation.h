#pragma once

#include "OfflineSegmentBehavior.h"

namespace ks::ui
{
    struct FieldDocument;
}

namespace ks::action_analyze
{
    struct SegmentRow;

    // 输入后台冻结结果，输出当前语言文案；不加载规则、不重新求值。
    QString SegmentBehaviorSummary(const SegmentBehaviorMatch& match);
    QString SegmentBehaviorStatus(const SegmentBehaviorProjection& projection);
    QString SegmentBehaviorRowText(const SegmentBehaviorMatch& match);

    // 将原包对应的行为字段追加到共享规范文档，原详情、搜索、复制和导出共用。
    void AppendSegmentBehaviorFields(ks::ui::FieldDocument& document,
        const SegmentSnapshot& snapshot, const SegmentRow& row);
}
