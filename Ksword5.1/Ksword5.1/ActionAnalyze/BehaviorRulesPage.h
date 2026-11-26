#pragma once

#include <functional>

class QWidget;

namespace ks::action_analyze
{
    struct SampleRequest;
    using ReplaySamplePresets = std::function<bool(const SampleRequest&)>; // 提交冻结采样，返回是否受理。

    // 创建规则子页，向同一工作台提供采样提交入口并通知在途状态变化。
    QWidget* CreateBehaviorRulesPage(QWidget* parent, ReplaySamplePresets& replay, std::function<void(bool)> busyChanged);
}
