#pragma once

#include <QString>
#include <QIcon>
#include <QColor>
#include <QPalette>

class QAbstractButton;
class QApplication;
class QColor;

namespace ks::ui
{
    // 语义色由页面明确选择，不从按钮文字猜测危险/成功动作。
    enum class FlatButtonTone
    {
        Neutral,
        Accent,
        Danger,
        Success
    };

    // 外观由页面明确选择；Auto 将普通工具按钮视为透明工具，将普通操作按钮保留实底。
    enum class FlatButtonAppearance
    {
        Auto,
        Solid,
        Flat,
        Navigation // 详情导航使用稍柔和的选中底面，图标按同一实际底色校准。
    };
    enum class FlatButtonState
    {
        Normal,
        Hover,
        Pressed,
        Checked,
        Disabled
    };
    struct FlatButtonStateColors
    {
        QColor background; // 透明常态返回实际露出的表面色，供文字/图标校准。
        QColor foreground; // 对实际底色校准后的文字色。
        bool transparent = false; // 自绘控件据此跳过底色填充。
    };

    // 自绘与 QSS 共用状态配方；纯自绘控件应明确传 Solid 或 Flat。
    FlatButtonStateColors FlatButtonColorsForState(const QPalette& palette, FlatButtonTone tone,
        FlatButtonAppearance appearance, FlatButtonState state);

    // 返回仅针对 QPushButton/QToolButton 的纯色无线框主题规则；不改变尺寸或业务状态。
    // 页面可继续追加自身 padding/圆角/字号；普通与强调态使用 palette 动态颜色。
    QString BuildFlatButtonStyle(FlatButtonTone tone = FlatButtonTone::Neutral,
        FlatButtonAppearance appearance = FlatButtonAppearance::Auto);

    // 安装仅发现明确样式标记的热主题绑定，不遍历改写未审核页面的任意本地 QSS。
    void InstallGlobalFlatButtonTheme(QApplication* app);

    // 为一个已核对的按钮绑定热主题刷新，保留现有样式中的几何与其他控件规则。
    // 输入按钮与语义色；只接管该按钮的颜色/边框，不修改 enabled/checked/图标或信号。
    void ApplyFlatButtonTheme(QAbstractButton* button,
        FlatButtonTone tone = FlatButtonTone::Neutral,
        FlatButtonAppearance appearance = FlatButtonAppearance::Auto);

    // 为已审核的共享按钮图标查询实际状态底色；未知页面本地样式返回 false。
    // mode/state 同时兼容 Qt 请求的 Active/On，不能只用普通模式猜悬停与选中底。
    bool TryGetFlatButtonBackground(const QAbstractButton* button,
        QIcon::Mode mode, QIcon::State state, QColor* background);
    bool IsFlatButtonBackgroundTransparent(const QAbstractButton* button,
        QIcon::Mode mode = QIcon::Normal, QIcon::State state = QIcon::Off);
}
