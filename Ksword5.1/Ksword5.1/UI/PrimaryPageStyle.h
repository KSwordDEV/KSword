#pragma once

class QComboBox;
class QGroupBox;
class QLabel;
class QWidget;

namespace ks::ui
{
    // 页面显式登记组合框，完整维护中性底、文字、箭头与交互态；不改变选项或业务信号。
    void StylePrimaryCombo(QComboBox* combo);

    // 已有功能分组保留完整细边界，只统一底面和标题，不创建卡片或改变内部布局。
    void StylePrimaryGroup(QGroupBox* group);

    // toolbar 是页面明确建立的操作区；轻底面和下分界区分操作与结果，不遍历子控件。
    void StylePrimaryToolbar(QWidget* toolbar);

    // 只为页面标题绑定可读次级颜色与字重，不接管状态提示或模型项的数据语义色。
    void StylePrimarySectionTitle(QLabel* title);
}
