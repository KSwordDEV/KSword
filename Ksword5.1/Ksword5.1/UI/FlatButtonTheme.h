#pragma once

#include <QString>
#include <QIcon>

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

    // 返回仅针对 QPushButton/QToolButton 的纯色无线框主题规则；不改变尺寸或业务状态。
    // 页面可继续追加自身 padding/圆角/字号；普通与强调态使用 palette 动态颜色。
    QString BuildFlatButtonStyle(FlatButtonTone tone = FlatButtonTone::Neutral);

    // 安装仅发现明确样式标记的热主题绑定，不遍历改写未审核页面的任意本地 QSS。
    void InstallGlobalFlatButtonTheme(QApplication* app);

    // 为一个已核对的按钮绑定热主题刷新，保留现有样式中的几何与其他控件规则。
    // 输入按钮与语义色；只接管该按钮的颜色/边框，不修改 enabled/checked/图标或信号。
    void ApplyFlatButtonTheme(QAbstractButton* button,
        FlatButtonTone tone = FlatButtonTone::Neutral);

    // 为已审核的共享按钮图标查询实际状态底色；未知页面本地样式返回 false。
    // mode/state 同时兼容 Qt 请求的 Active/On，不能只用普通模式猜悬停与选中底。
    bool TryGetFlatButtonBackground(const QAbstractButton* button,
        QIcon::Mode mode, QIcon::State state, QColor* background);
}
