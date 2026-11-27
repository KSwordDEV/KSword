#pragma once

#include "OfflineProjectReader.h"
#include "../../../KswordCLI/ActionAnalyze/Rules/BehaviorPresets.h"

namespace ks::action_analyze
{
    struct SegmentSnapshot;
    struct SegmentRow;

    // 总览只发布当前窗口的行为命中；没有请求、成功空结果与规则失败分别保留。
    enum class SegmentBehaviorState { NotRequested, Ready, Failed };

    struct SegmentBehaviorMatch
    {
        qsizetype rowOffset = 0; // 同一不可变快照中的原始 API 行下标。
        quint64 segment = 0; // 原包所在 raw 段，独立于求值窗口位置。
        quint64 rawSequence = 0; // Stored 原记录序号，不重新编号。
        quint64 sourceSequence = 0; // 原 API 来源行号或合作流水号。
        Ksword::ActionAnalyze::Rules::ApiPresetBehavior behavior; // 同次求值拥有的 ID、证据与双语释义。
    };

    struct SegmentBehaviorProjection
    {
        SegmentBehaviorState state = SegmentBehaviorState::NotRequested; // 本快照的规则请求状态。
        QString error; // 规则加载或求值失败的原始诊断。
        QString presetSet; // 本次实际加载的规则集标识。
        QString sourceSha256; // 本次规则文件内容身份，不冒充采集时的规则。
        qsizetype analyzedRows = 0; // 当前窗口中实际提交求值的 API 观测数。
        QList<SegmentBehaviorMatch> matches; // 只保留 behavior 存在的真实命中。
    };

    // 原 ReadOfflineSegment 工作线程在最终窗口形成后调用一次；只使用已解码原包，不读归档。
    // snapshot 原位接收规则状态和命中，isCanceled 沿用原任务取消条件。
    void ProjectOfflineSegmentBehavior(SegmentSnapshot& snapshot, const CancelCheck& isCanceled);
    // 将一条原始行重建为与规则求值相同的字段投影，仅用于原详情显示，不重新加载规则库。
    QString OfflineSegmentBehaviorInputs(const SegmentRow& row);

}
