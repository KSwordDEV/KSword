#pragma once

#include <functional>

class QWidget;
class QAbstractSpinBox;

namespace ks::ui
{
    // 独立窗口可明确保留自身 palette；普通控件允许主题函数更新其主题角色。
    enum class ThemePalettePolicy
    {
        FollowApplication,
        PreserveLocal
    };

    // BindWidgetTheme：登记控件完整的主题角色刷新函数；同一控件再次登记会替换旧函数。
    // widget 管理绑定生命周期，refresh 必须使用明确的主题角色，并完整刷新自身局部样式。
    // 首次及主题变化均延迟到下一轮 GUI 事件循环，避免在 Popup Show/Resize 中重入 polish。
    // 返回 false 表示空参数、没有 QApplication 或调用线程不属于 GUI 线程。
    // PreserveLocal 会在重建 QSS 后恢复调用前的局部 palette，防止 Qt repolish 丢失独立底色。
    bool BindWidgetTheme(QWidget* widget, std::function<void()> refresh,
        ThemePalettePolicy palettePolicy = ThemePalettePolicy::FollowApplication);

    // 为数值控件及其内部编辑器显式绑定可读主题色，避免父级 QSS 把数字染成底色。
    // 仅接管文字与表面色，保留 value/suffix、尺寸、步进按钮、验证器与编辑状态。
    bool BindSpinBoxTheme(QAbstractSpinBox* spinBox);

    // HasWidgetThemeBinding：只判断该控件自身是否声明完整主题刷新，不跨到其未登记子控件。
    // 旧色值补偿据此跳过明确绑定的控件；其余存量控件仍沿用原有兼容路径。
    bool HasWidgetThemeBinding(const QWidget* widget);

    // RefreshWidgetThemeBindings：合并调度所有已登记控件，供主题种子更新完成后调用。
    // 不枚举 QApplication::allWidgets，不同步调用控件刷新，不改变全局或独立窗口 palette。
    void RefreshWidgetThemeBindings();
}
