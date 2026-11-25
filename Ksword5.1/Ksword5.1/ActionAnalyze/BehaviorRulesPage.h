#pragma once

class QWidget;

namespace ks::action_analyze
{
    // 由行为分析工作台创建自有子页。parent 为 Qt 宿主，返回挂载后的规则编辑页。
    QWidget* CreateBehaviorRulesPage(QWidget* parent);
}
