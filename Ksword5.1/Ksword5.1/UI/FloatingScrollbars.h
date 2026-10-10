#pragma once

#include <QMargins>
#include <QtGlobal>

class QApplication;
class QAbstractScrollArea;

namespace ks::ui
{
    // 安装主程序悬浮条发现器；延迟处理新建滚动区域，不改页面滚轮算法。
    void InstallGlobalFloatingScrollbars(QApplication* application);

    // 给滚动区域安装视觉滑块；原生条对象、策略、数值和业务信号均保留。
    // 滚动或接近边缘时出现，悬停和拖动时保持；闲置后淡出并让鼠标穿透。
    // 设置 ksword_preserve_native_scrollbars=true 可显式恢复原生条外观。
    void InstallFloatingScrollbars(QAbstractScrollArea* area);

    // 页面更换视口、调整滚动策略或完成比较态切换后，可主动刷新绑定和几何。
    void RefreshFloatingScrollbars(QAbstractScrollArea* area);

    // 设置浮窗内容倍率；输入钳制到 0.25–3.0，影响滑块和鼠标命中带。
    void SetFloatingScrollbarScale(QAbstractScrollArea* area, qreal scale);

    // 设置 viewport 内侧避让距离，例如保护十六进制属性行右缘的复制动作。
    // 不修改 viewportMargins，也不向页面布局添加任何空间。
    void SetFloatingScrollbarInsets(QAbstractScrollArea* area, const QMargins& insets);

    // 查询该区域是否已安装并启用悬浮外观；不表示当前内容一定溢出。
    bool HasFloatingScrollbars(const QAbstractScrollArea* area);
}
