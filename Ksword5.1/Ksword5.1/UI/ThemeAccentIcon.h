#pragma once

#include <QIcon>
#include <QColor>

class QAbstractButton;

namespace ks::ui
{
    // MakeThemeAccentIcon：为应用内单色源图建立绘制时读取主题强调色的图标。
    // sourceIcon 必须保留固定默认色轮廓；只用于自制图标，不用于 Shell/进程多色图标。
    // 返回拥有独立 QIconEngine 的图标；空源图原样返回，主题变化无需重建模型项。
    QIcon MakeThemeAccentIcon(const QIcon& sourceIcon);

    // fixedAccent 为通用图标管理器收到的主体色快照；底色仍在绘制时读取当前主题。
    // Normal覆盖中性表面，Active覆盖按钮强调底，Selected/On覆盖选中底；自管图标不走此入口。
    QIcon MakeThemeAccentIcon(const QIcon& sourceIcon, const QColor& fixedAccent);

    // MakeThemeButtonAccentIcon：仅为已判定为单色主题候选的 push/tool 按钮建立独立图标。
    // button 为真实绘制上下文，绘制时读取共享实心按钮的 tone、父 palette 和当前状态。
    // 使用 QPointer 跟踪按钮寿命，不共享跨按钮结果；未知本地样式沿用通用状态语义。
    // sourceIcon 必须为未包装的原图，fixedAccent 为管理器本轮主题色；空源图原样返回。
    QIcon MakeThemeButtonAccentIcon(const QIcon& sourceIcon,
        const QColor& fixedAccent, QAbstractButton* button);
}
